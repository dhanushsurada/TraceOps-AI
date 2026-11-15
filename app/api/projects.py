"""
Projects API

Manages software repositories and engineering products in TraceOps.
GET  /projects        — list user projects
POST /projects        — register a new project
GET  /projects/{id}   — get project details and recent activity
DELETE /projects/{id} — remove project
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_optional_user
from app.core.database import get_db
from app.models.models import Project, Task, Commit, User

router = APIRouter(prefix="/projects", tags=["Projects"])


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    default_branch: str = "main"
    visibility: str = "private"
    repository_url: Optional[str] = None


@router.get("/")
async def list_projects(
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    result = await db.execute(select(Project).where(Project.user_id == user_id).order_by(Project.name.asc()))
    projects = result.scalars().all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "slug": p.slug,
            "description": p.description,
            "default_branch": p.default_branch,
            "visibility": p.visibility,
            "repository_url": p.repository_url,
            "created_at": p.created_at,
        }
        for p in projects
    ]


@router.post("/", status_code=201)
async def create_project(
    req: CreateProjectRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"

    # Check unique slug per user
    existing = await db.execute(
        select(Project).where(Project.user_id == user_id, Project.slug == req.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Project with slug '{req.slug}' already exists.")

    project = Project(
        user_id=user_id,
        name=req.name,
        slug=req.slug,
        description=req.description,
        default_branch=req.default_branch,
        visibility=req.visibility,
        repository_url=req.repository_url,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return {
        "id": project.id,
        "name": project.name,
        "slug": project.slug,
        "repository_url": project.repository_url,
        "default_branch": project.default_branch,
    }


@router.get("/{project_id}")
async def get_project(
    project_id: str,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = current_user.id if current_user else "default_user"
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found.")

    # Count tasks and commits
    tasks_res = await db.execute(select(Task).where(Task.project_id == project_id))
    tasks = tasks_res.scalars().all()

    commits_res = await db.execute(select(Commit).where(Commit.project_id == project_id))
    commits = commits_res.scalars().all()

    return {
        "id": project.id,
        "name": project.name,
        "slug": project.slug,
        "description": project.description,
        "default_branch": project.default_branch,
        "visibility": project.visibility,
        "repository_url": project.repository_url,
        "task_count": len(tasks),
        "commit_count": len(commits),
    }
