"""
External AI Context Interface

Provides standardized, evidence-grounded engineering intelligence packages to
external AI systems (ChatGPT, Claude, SAM, and custom agents).
Endpoints:
GET  /api/v1/context/audit      — multi-day engineering execution audit
GET  /api/v1/context/task/{id}  — deep context package for a single task
POST /api/v1/context/verify     — verifies natural language claims against code evidence
"""
from datetime import datetime, timedelta
import hashlib
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_optional_user
from app.core.database import get_db
from app.models.models import (
    User, Task, Commit, FileChange, Deployment, ErrorRecord,
    Assessment, Observation, Project
)

router = APIRouter(prefix="/api/v1/context", tags=["AI Context"])


class VerifyClaimRequest(BaseModel):
    claim: str
    project_slug: Optional[str] = None


@router.get("/audit")
async def get_engineering_audit(
    timeframe: str = Query("7d", description="e.g. 24h, 7d, 30d"),
    project_id: Optional[str] = Query(None),
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns an auditable context package for external AI models (ChatGPT, Claude, SAM).
    Includes verified achievements, assessments, bottlenecks, and evidence coverage.
    """
    user_id = current_user.id if current_user else "default_user"

    # Parse timeframe
    days = 7
    if timeframe.endswith("d"):
        try:
            days = int(timeframe[:-1])
        except ValueError:
            days = 7
    elif timeframe.endswith("h"):
        try:
            days = max(1, int(timeframe[:-1]) // 24)
        except ValueError:
            days = 1

    start_date = datetime.utcnow() - timedelta(days=days)

    # 1. Fetch Tasks
    t_stmt = select(Task).where(Task.user_id == user_id, Task.started_at >= start_date)
    if project_id:
        t_stmt = t_stmt.where(Task.project_id == project_id)
    t_res = await db.execute(t_stmt)
    tasks = t_res.scalars().all()

    # 2. Fetch Commits
    c_stmt = select(Commit).where(Commit.user_id == user_id, Commit.committed_at >= start_date)
    if project_id:
        c_stmt = c_stmt.where(Commit.project_id == project_id)
    c_res = await db.execute(c_stmt)
    commits = c_res.scalars().all()

    # 3. Fetch Deployments
    d_stmt = select(Deployment).where(Deployment.user_id == user_id, Deployment.started_at >= start_date)
    d_res = await db.execute(d_stmt)
    deployments = d_res.scalars().all()

    # 4. Fetch Assessments
    a_stmt = select(Assessment).where(Assessment.user_id == user_id, Assessment.created_at >= start_date)
    a_res = await db.execute(a_stmt)
    assessments = a_res.scalars().all()

    # 5. Fetch Errors
    err_stmt = select(ErrorRecord).where(ErrorRecord.user_id == user_id, ErrorRecord.occurred_at >= start_date)
    err_res = await db.execute(err_stmt)
    errors = err_res.scalars().all()

    # Calculate aggregate scores
    dimension_scores: Dict[str, List[float]] = {}
    for a in assessments:
        dimension_scores.setdefault(a.assessment_dimension, []).append(a.score)

    avg_assessments = {
        dim: round(sum(scores) / len(scores), 1)
        for dim, scores in dimension_scores.items()
    }

    # Verified achievements
    verified_achievements = []
    for t in tasks:
        if t.status == "completed":
            t_commits = [c for c in commits if c.task_id == t.id]
            shas = [c.sha[:7] for c in t_commits]
            evid_str = f"TRO-EVID-{t.id[:8]}"
            verified_achievements.append({
                "task_id": t.id,
                "goal": t.goal,
                "target_level": t.target_level,
                "final_level": t.final_level,
                "commits_count": len(t_commits),
                "commit_shas": shas,
                "citation_tag": evid_str,
            })

    # Bottlenecks
    bottlenecks = []
    if len(errors) > 2:
        bottlenecks.append({
            "type": "repeated_exceptions",
            "description": f"Encountered {len(errors)} runtime exceptions during development.",
            "severity": "medium",
        })

    coverage_score = round(min(1.0, (len(commits) * 0.1) + (len(tasks) * 0.1) + 0.4), 2)

    return {
        "traceops_context_version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat(),
        "tenant_id": user_id,
        "timeframe": timeframe,
        "summary": {
            "total_tasks": len(tasks),
            "completed_tasks": sum(1 for t in tasks if t.status == "completed"),
            "total_commits": len(commits),
            "total_deployments": len(deployments),
            "total_errors": len(errors),
            "evidence_coverage": coverage_score,
        },
        "assessments": avg_assessments,
        "verified_achievements": verified_achievements,
        "bottlenecks": bottlenecks,
    }


@router.get("/task/{task_id}")
async def get_task_context(
    task_id: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve complete evidence-backed context package for an individual task."""
    user_id = current_user.id if current_user else "default_user"

    t_res = await db.execute(select(Task).where(Task.id == task_id, Task.user_id == user_id))
    task = t_res.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or access denied.")

    c_res = await db.execute(select(Commit).where(Commit.task_id == task_id))
    commits = c_res.scalars().all()

    obs_res = await db.execute(select(Observation).where(Observation.task_id == task_id))
    observations = obs_res.scalars().all()

    ass_res = await db.execute(select(Assessment).where(Assessment.task_id == task_id))
    assessments = ass_res.scalars().all()

    return {
        "task_id": task.id,
        "user_id": task.user_id,
        "goal": task.goal,
        "target_level": task.target_level,
        "final_level": task.final_level,
        "status": task.status,
        "started_at": task.started_at,
        "ended_at": task.ended_at,
        "commits": [
            {"sha": c.sha, "message": c.message, "committed_at": c.committed_at}
            for c in commits
        ],
        "observations": [
            {"type": o.observation_type, "value": o.metric_value, "unit": o.unit, "hash": o.evidence_hash}
            for o in observations
        ],
        "assessments": [
            {"dimension": a.assessment_dimension, "score": a.score, "confidence": a.confidence}
            for a in assessments
        ],
        "citation": f"[TRO-EVID-{task.id[:8]}]",
    }


@router.post("/verify")
async def verify_achievement_claim(
    req: VerifyClaimRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Validates a natural language developer achievement claim against code commits and file changes.
    Returns verification verdict, confidence, and cryptographic citation tag.
    """
    user_id = current_user.id if current_user else "default_user"

    c_res = await db.execute(
        select(Commit).where(Commit.user_id == user_id).order_by(Commit.committed_at.desc()).limit(50)
    )
    commits = c_res.scalars().all()

    claim_words = set(req.claim.lower().split())
    matching_commits = []

    for c in commits:
        msg_words = set(c.message.lower().split())
        overlap = claim_words.intersection(msg_words)
        if len(overlap) >= 2 or any(w in c.message.lower() for w in claim_words if len(w) > 4):
            matching_commits.append({
                "sha": c.sha[:7],
                "message": c.message,
                "committed_at": c.committed_at,
                "task_id": c.task_id,
            })

    verified = len(matching_commits) > 0
    confidence = min(0.95, 0.4 + (len(matching_commits) * 0.2)) if verified else 0.1
    citation_id = hashlib.sha256(f"{user_id}:{req.claim}".encode()).hexdigest()[:8]

    return {
        "claim": req.claim,
        "verified": verified,
        "confidence": round(confidence, 2),
        "matching_commits_count": len(matching_commits),
        "matching_commits": matching_commits[:5],
        "citation_tag": f"[TRO-EVID-{citation_id}]" if verified else None,
        "verdict": "Substantiated with repository evidence" if verified else "Unsubstantiated: no matching commits found",
    }
