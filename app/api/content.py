"""
Evidence-Backed Content Generation API

POST /content/linkedin  — generate verified LinkedIn progress post
POST /content/resume    — generate quantified resume bullets with evidence hashes
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_optional_user
from app.core.database import get_db
from app.models.models import User
from app.services.content_generator import ContentGenerator

router = APIRouter(prefix="/content", tags=["Evidence-Backed Content"])


class ResumeBulletRequest(BaseModel):
    task_id: str


@router.post("/linkedin")
async def generate_linkedin_content(
    days: int = Query(7, ge=1, le=90),
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    generator = ContentGenerator(db)
    result = await generator.generate_linkedin_update(user_id=user_id, days=days)
    return result


@router.post("/resume")
async def generate_resume_content(
    req: ResumeBulletRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    generator = ContentGenerator(db)
    result = await generator.generate_resume_bullet(user_id=user_id, task_id=req.task_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail="Task not found or access denied.")
    return result
