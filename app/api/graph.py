"""
Execution Graph API

Endpoints:
GET  /graph/task/{task_id}    — returns execution DAG for a task
GET  /graph/project/{proj_id} — returns project DAG
POST /graph/edge              — manual or automated edge creation
"""
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user
from app.core.database import get_db
from app.models.models import User, Task, Project, GraphEdge
from app.services.graph_engine import GraphEngine

router = APIRouter(prefix="/graph", tags=["Execution Graph"])


class CreateEdgeRequest(BaseModel):
    source_type: str
    source_id: str
    edge_type: str
    target_type: str
    target_id: str
    confidence: float = 1.0
    evidence_source: str = "manual_override"


@router.get("/task/{task_id}")
async def get_task_graph(
    task_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve full execution DAG and timeline for a task (strictly tenant isolated)."""
    engine = GraphEngine(db)
    graph = await engine.get_task_graph(user_id=current_user.id, task_id=task_id)
    if "error" in graph:
        raise HTTPException(status_code=404, detail="Task not found or access denied.")
    return graph


@router.post("/edge", status_code=201)
async def create_graph_edge(
    req: CreateEdgeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a verified causal or associative edge between engineering artifacts."""
    engine = GraphEngine(db)
    edge = await engine.add_edge(
        user_id=current_user.id,
        source_type=req.source_type,
        source_id=req.source_id,
        edge_type=req.edge_type,
        target_type=req.target_type,
        target_id=req.target_id,
        confidence=req.confidence,
        evidence_source=req.evidence_source,
    )
    await db.commit()
    return {
        "edge_id": edge.id,
        "source": f"{edge.source_type}:{edge.source_id}",
        "edge_type": edge.edge_type,
        "target": f"{edge.target_type}:{edge.target_id}",
        "confidence": edge.confidence,
    }
