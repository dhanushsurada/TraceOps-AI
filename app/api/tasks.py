"""
Task API with Tenant Isolation & Execution Graph Integration

POST /task/start  — begin a task (scoped to authenticated user & optional project)
POST /task/end    — complete a task, trigger scoring, loop detection, and graph reconciliation
GET  /task/{id}   — get task details (tenant isolated)
GET  /task/       — list tasks for authenticated user
"""
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user
from app.core.database import get_db
from app.models.models import Event, Score, Task, User, Project
from app.services.loop_detection import detect_all_loops
from app.services.scoring import score_from_task_data

router = APIRouter(prefix="/task", tags=["Tasks"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class TaskStartRequest(BaseModel):
    goal: str = Field(..., min_length=3, max_length=500)
    target_level: int = Field(..., ge=0, le=5)
    project_id: Optional[str] = None


class TaskEndRequest(BaseModel):
    task_id: str
    final_level: int = Field(..., ge=0, le=5)


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/start", status_code=201)
async def start_task(
    req: TaskStartRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start a new task. Mandatory authentication scoped to the current user."""
    user_id = current_user.id

    # If project_id provided, verify ownership
    if req.project_id:
        p_res = await db.execute(select(Project).where(Project.id == req.project_id, Project.user_id == user_id))
        if not p_res.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found or access denied.")

    task = Task(
        user_id=user_id,
        goal=req.goal,
        target_level=req.target_level,
        project_id=req.project_id,
        status="active",
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return {
        "task_id": task.id,
        "user_id": task.user_id,
        "goal": task.goal,
        "target_level": task.target_level,
        "started_at": task.started_at,
        "status": task.status,
        "instructions": (
            f"Add [TRO-{task.id}] to your git commits. "
            f"Send task_id='{task.id}' with all AI proxy requests."
        ),
    }


@router.post("/end")
async def end_task(
    req: TaskEndRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Mark task as complete, compute score, run loop detection.
    Strictly enforces task ownership: User A cannot complete User B's task.
    """
    result = await db.execute(select(Task).where(Task.id == req.task_id, Task.user_id == current_user.id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or access denied.")
    if task.status == "completed":
        raise HTTPException(status_code=409, detail="Task already completed.")

    task.final_level = req.final_level
    task.ended_at = datetime.utcnow()
    task.status = "completed"
    await db.flush()

    # Fetch associated events
    ev_result = await db.execute(select(Event).where(Event.task_id == req.task_id))
    events = ev_result.scalars().all()
    events_dicts = [
        {
            "event_type": e.event_type,
            "timestamp": e.timestamp,
            "metadata": e.metadata_ or {},
        }
        for e in events
    ]

    # Loop detection
    prompts = [
        e.metadata_.get("prompt_snippet", "") for e in events
        if e.event_type == "ai" and e.metadata_
    ]
    error_logs = [
        e.metadata_.get("message", "") for e in events
        if e.event_type == "error" and e.metadata_
    ]
    loop_res = detect_all_loops(prompts, error_logs, [])

    # Scoring v3
    task_data = {
        "target_level": task.target_level,
        "final_level": task.final_level,
        "started_at": task.started_at,
        "ended_at": task.ended_at,
    }
    score_breakdown = score_from_task_data(task_data, events_dicts)

    # Persist score
    score = Score(
        task_id=task.id,
        level=score_breakdown.level,
        velocity=score_breakdown.velocity,
        stability_penalty=score_breakdown.stability_penalty,
        ai_penalty=score_breakdown.ai_penalty,
        final_score=score_breakdown.final_score,
    )
    db.add(score)
    await db.commit()

    return {
        "task_id": task.id,
        "goal": task.goal,
        "target_level": task.target_level,
        "final_level": task.final_level,
        "status": task.status,
        "score": score_breakdown.final_score,
        "breakdown": {
            "outcome_score": score_breakdown.outcome_score,
            "velocity": score_breakdown.velocity,
            "stability_penalty": score_breakdown.stability_penalty,
            "ai_penalty": score_breakdown.ai_penalty,
            "final_score": score_breakdown.final_score,
            "details": score_breakdown.details,
        },
        "loops_detected": [
            {
                "type": loop_res.loop_type,
                "severity": loop_res.severity,
                "confidence": loop_res.loop_confidence,
                "evidence": loop_res.evidence,
            }
        ] if loop_res.loop_detected else [],
    }


@router.get("/{task_id}")
async def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve task details, events, and score with strict tenant authorization."""
    result = await db.execute(select(Task).where(Task.id == task_id, Task.user_id == current_user.id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or access denied.")

    # Score
    sc_result = await db.execute(select(Score).where(Score.task_id == task_id))
    score = sc_result.scalar_one_or_none()

    # Events count
    ev_result = await db.execute(select(Event).where(Event.task_id == task_id))
    events = ev_result.scalars().all()

    return {
        "task_id": task.id,
        "user_id": task.user_id,
        "project_id": task.project_id,
        "goal": task.goal,
        "target_level": task.target_level,
        "final_level": task.final_level,
        "status": task.status,
        "started_at": task.started_at,
        "ended_at": task.ended_at,
        "event_count": len(events),
        "score": score.final_score if score else None,
    }


@router.get("/")
async def list_tasks(
    status: Optional[str] = Query(None, description="active|completed"),
    project_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List tasks scoped strictly to the authenticated tenant."""
    stmt = select(Task).where(Task.user_id == current_user.id)
    if status:
        stmt = stmt.where(Task.status == status)
    if project_id:
        stmt = stmt.where(Task.project_id == project_id)

    stmt = stmt.order_by(Task.started_at.desc()).limit(limit)
    result = await db.execute(stmt)
    tasks = result.scalars().all()

    return [
        {
            "task_id": t.id,
            "goal": t.goal,
            "target_level": t.target_level,
            "final_level": t.final_level,
            "status": t.status,
            "started_at": t.started_at,
            "ended_at": t.ended_at,
            "project_id": t.project_id,
        }
        for t in tasks
    ]
