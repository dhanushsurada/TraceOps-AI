"""
Deterministic Observations API

GET  /observations/task/{task_id}         — list observations with evidence hashes
POST /observations/task/{task_id}/compute — compute & persist observations
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_optional_user
from app.core.database import get_db
from app.models.models import Observation, User
from app.services.observation_engine import ObservationEngine

router = APIRouter(prefix="/observations", tags=["Observations"])


@router.get("/task/{task_id}")
async def get_task_observations(
    task_id: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    res = await db.execute(
        select(Observation).where(Observation.task_id == task_id, Observation.user_id == user_id)
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
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    engine = ObservationEngine(db)
    obs = await engine.compute_task_observations(user_id=user_id, task_id=task_id)
    return {
        "task_id": task_id,
        "observations_computed": len(obs),
        "results": [
            {"type": o.observation_type, "value": o.metric_value, "unit": o.unit, "hash": o.evidence_hash}
            for o in obs
        ],
    }
