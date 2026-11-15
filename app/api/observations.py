"""
Deterministic Observations API

GET  /observations/task/{task_id}         — list observations with evidence hashes
POST /observations/task/{task_id}/compute — compute & persist observations
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user
from app.core.database import get_db
from app.models.models import Observation, User, Task
from app.services.observation_engine import ObservationEngine

router = APIRouter(prefix="/observations", tags=["Observations"])


@router.get("/task/{task_id}")
async def get_task_observations(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify task ownership
    t_res = await db.execute(select(Task).where(Task.id == task_id, Task.user_id == current_user.id))
    if not t_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Task not found or access denied.")

    res = await db.execute(
        select(Observation).where(Observation.task_id == task_id, Observation.user_id == current_user.id)
    )
    obs = res.scalars().all()
    return [
        {
            "id": o.id,
            "type": o.observation_type,
            "metric_value": o.metric_value,
            "unit": o.unit,
            "window_start": o.window_start,
            "window_end": o.window_end,
            "evidence_hash": o.evidence_hash,
            "supporting_evidence": o.supporting_evidence,
            "computed_at": o.computed_at,
        }
        for o in obs
    ]


@router.post("/task/{task_id}/compute", status_code=201)
async def compute_task_observations(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify task ownership
    t_res = await db.execute(select(Task).where(Task.id == task_id, Task.user_id == current_user.id))
    if not t_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Task not found or access denied.")

    engine = ObservationEngine(db)
    obs = await engine.compute_task_observations(user_id=current_user.id, task_id=task_id)
    return {
        "task_id": task_id,
        "observations_computed": len(obs),
        "results": [
            {"type": o.observation_type, "value": o.metric_value, "unit": o.unit, "hash": o.evidence_hash}
            for o in obs
        ],
    }
