"""
Report API with Strict Tenant Isolation

GET  /report/daily       — get today's report (scoped to authenticated user)
GET  /report/{date}      — get report for specific date (YYYY-MM-DD, user-scoped)
POST /report/generate    — force-generate report for today (user-scoped)
POST /report/validate    — run deployment validation on a URL
"""
from datetime import date as dt_date, datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user, get_optional_user
from app.core.database import get_db
from app.models.models import Event, Report, Score, Task, User
from app.services.deployment import validate_deployment
from app.services.llm_analyzer import run_analysis
from app.services.loop_detection import detect_all_loops
from app.services.report_gen import build_report, report_to_markdown
from app.services.scoring import score_from_task_data

router = APIRouter(prefix="/report", tags=["Reports"])


class ValidateRequest(BaseModel):
    url: str
    functional_path: str = "/health"
    functional_expected_status: int = 200
    functional_expected_keys: Optional[list[str]] = None


# ── Core: build today's report data scoped to user ───────────────────────────

async def _generate_report_for_date(target_date: dt_date, user_id: str, db: AsyncSession) -> dict:
    # Fetch all tasks for the date strictly scoped to this user
    task_result = await db.execute(
        select(Task).where(Task.task_date == target_date, Task.user_id == user_id)
    )
    tasks = task_result.scalars().all()
    if not tasks:
        return {
            "meta": {"date": target_date.isoformat(), "user_id": user_id},
            "summary": {"total_tasks": 0, "completed_tasks": 0, "average_score": 0, "score_grade": "N/A"},
            "tasks": [],
            "scores": [],
            "loop_detection": [],
            "deployment_validation": [],
            "analysis": {"bottlenecks": [], "root_cause": "No tasks recorded for today.", "corrective_actions": []},
        }

    task_ids = [t.id for t in tasks]

    # Fetch events for user's tasks
    ev_result = await db.execute(
        select(Event).where(Event.task_id.in_(task_ids))
    )
    all_events = ev_result.scalars().all()

    # Fetch existing scores
    sc_result = await db.execute(
        select(Score).where(Score.task_id.in_(task_ids))
    )
    scores = sc_result.scalars().all()

    # Loop detection per task
    loop_results = []
    for task in tasks:
        task_events = [e for e in all_events if e.task_id == task.id]
        prompts = [
            e.metadata_.get("prompt_snippet", "") for e in task_events
            if e.event_type == "ai" and e.metadata_
        ]
        error_logs = [
            e.metadata_.get("message", "") for e in task_events
            if e.event_type == "error" and e.metadata_
        ]
        lr = detect_all_loops(prompts=prompts, error_logs=error_logs, task_attempts=[])
        loop_results.append({
            "task_id": task.id,
            "loop_detected": lr.loop_detected,
            "loop_type": lr.loop_type,
            "severity": lr.severity,
            "evidence": lr.evidence[:3],
        })

    # Scores as dicts
    scores_dicts = [
        {
            "task_id": s.task_id,
            "level": s.level,
            "velocity": s.velocity,
            "stability_penalty": s.stability_penalty,
            "ai_penalty": s.ai_penalty,
            "final_score": s.final_score,
            "outcome_score": s.level * 10,
        }
        for s in scores
    ]

    # Missing scores computation
    scored_task_ids = {s.task_id for s in scores}
    for task in tasks:
        if task.id not in scored_task_ids and task.status == "completed":
            task_events = [e for e in all_events if e.task_id == task.id]
            ev_dicts = [
                {"event_type": e.event_type, "timestamp": e.timestamp, "metadata": e.metadata_ or {}}
                for e in task_events
            ]
            bd = score_from_task_data(
                {
                    "target_level": task.target_level,
                    "final_level": task.final_level or task.target_level,
                    "started_at": task.started_at,
                    "ended_at": task.ended_at,
                },
                ev_dicts,
            )
            scores_dicts.append({
                "task_id": task.id,
                "level": bd.level,
                "velocity": bd.velocity,
                "stability_penalty": bd.stability_penalty,
                "ai_penalty": bd.ai_penalty,
                "final_score": bd.final_score,
                "outcome_score": bd.outcome_score,
            })

    # Task dicts
    tasks_dicts = [
        {
            "id": t.id,
            "goal": t.goal,
            "target_level": t.target_level,
            "final_level": t.final_level,
            "status": t.status,
            "started_at": t.started_at.isoformat() if t.started_at else None,
            "ended_at": t.ended_at.isoformat() if t.ended_at else None,
        }
        for t in tasks
    ]

    # LLM Bottleneck analysis
    analysis = None
    if tasks:
        lead_task = tasks[0]
        lead_score = next((s for s in scores_dicts if s["task_id"] == lead_task.id), {})
        lead_events = [
            {"event_type": e.event_type, "timestamp": e.timestamp.isoformat() if e.timestamp else None, "metadata": e.metadata_ or {}}
            for e in all_events if e.task_id == lead_task.id
        ]
        try:
            analysis = await run_analysis(
                task_data={"goal": lead_task.goal, "target_level": lead_task.target_level, "final_level": lead_task.final_level},
                events=lead_events,
                score=lead_score,
            )
        except Exception:
            analysis = None

    return build_report(
        target_date=target_date,
        tasks=tasks_dicts,
        scores=scores_dicts,
        analysis=analysis,
        loop_results=loop_results,
        deploy_results=[],
    )


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/daily")
async def get_daily_report(
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Return today's report from DB for authenticated user, or generate if missing."""
    today = dt_date.today()
    user_id = current_user.id if current_user else "default_user"

    result = await db.execute(
        select(Report)
        .where(Report.report_date == today, Report.user_id == user_id)
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    existing = result.scalar_one_or_none()
    if existing:
        return existing.content

    # Generate fresh
    content = await _generate_report_for_date(today, user_id, db)
    report_row = Report(user_id=user_id, report_date=today, content=content)
    db.add(report_row)
    await db.commit()
    return content


@router.get("/daily/markdown")
async def get_daily_report_markdown(
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Return today's report as a Markdown string."""
    from fastapi.responses import PlainTextResponse
    today = dt_date.today()
    user_id = current_user.id if current_user else "default_user"
    content = await _generate_report_for_date(today, user_id, db)
    return PlainTextResponse(report_to_markdown(content), media_type="text/markdown")


@router.get("/{report_date}")
async def get_report_by_date(
    report_date: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        d = dt_date.fromisoformat(report_date)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    user_id = current_user.id if current_user else "default_user"
    result = await db.execute(
        select(Report)
        .where(Report.report_date == d, Report.user_id == user_id)
        .order_by(Report.created_at.desc())
        .limit(1)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail=f"No report for {report_date}.")
    return report.content


@router.post("/generate", status_code=201)
async def force_generate_report(
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Force-generate and store today's report for current user."""
    today = dt_date.today()
    user_id = current_user.id if current_user else "default_user"
    content = await _generate_report_for_date(today, user_id, db)
    report_row = Report(user_id=user_id, report_date=today, content=content)
    db.add(report_row)
    await db.commit()
    return {"message": "Report generated.", "date": today.isoformat(), "report": content}


@router.post("/validate")
async def run_validation(req: ValidateRequest):
    """Validate a deployed service's health and functional endpoints."""
    result = await validate_deployment(
        base_url=req.url,
        functional_path=req.functional_path,
        functional_expected_status=req.functional_expected_status,
        functional_expected_keys=req.functional_expected_keys,
    )
    return {
        "url": req.url,
        "status": result.status,
        "score": result.score,
        "summary": result.summary,
        "checks": [
            {
                "url": c.url,
                "status_code": c.status_code,
                "latency_ms": c.latency_ms,
                "success": c.success,
                "error": c.error,
            }
            for c in result.checks
        ],
    }
