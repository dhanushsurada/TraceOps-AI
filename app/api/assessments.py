"""
Versioned Assessments API

GET  /assessments/task/{task_id}          — list versioned assessments for task
POST /assessments/task/{task_id}/evaluate — evaluate assessments from observations
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_optional_user
from app.core.database import get_db
from app.models.models import Assessment, User
from app.services.assessment_engine import AssessmentEngine

router = APIRouter(prefix="/assessments", tags=["Assessments"])


@router.get("/task/{task_id}")
async def get_task_assessments(
    task_id: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    res = await db.execute(
        select(Assessment).where(Assessment.task_id == task_id, Assessment.user_id == user_id)
    )
    assessments = res.scalars().all()
    return [
        {
            "id": a.id,
            "dimension": a.assessment_dimension,
            "algorithm_version": a.algorithm_version,
            "score": a.score,
            "confidence": a.confidence,
            "breakdown": a.breakdown,
            "limitations": a.limitations,
            "input_observation_ids": a.input_observation_ids,
            "created_at": a.created_at,
        }
        for a in assessments
    ]


@router.post("/task/{task_id}/evaluate", status_code=201)
async def evaluate_task_assessments(
    task_id: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    engine = AssessmentEngine(db)
    assessments = await engine.generate_task_assessments(user_id=user_id, task_id=task_id)
    return {
        "task_id": task_id,
        "assessments_generated": len(assessments),
        "assessments": [
            {
                "dimension": a.assessment_dimension,
                "score": a.score,
                "confidence": a.confidence,
                "version": a.algorithm_version,
            }
            for a in assessments
        ],
    }
