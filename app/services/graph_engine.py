"""
Execution Graph Engine

Builds, persists, and traverses the directed acyclic graph (DAG) of software execution:
- Nodes: Task, Commit, FileChange, PullRequest, Build, Deployment, ErrorRecord, AISession, Decision
- Edges: CONTRIBUTES_TO, MODIFIES, RELEASES, ASSISTS, CAUSES, RESOLVES, PRECEDES
- Multi-signal correlation waterfall (Tier 1-4)
- Graph traversal and timeline replay
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    GraphEdge, Task, Commit, FileChange, PullRequest,
    Deployment, ErrorRecord, AISession, Event, Project
)
from app.services.loop_detection import _cosine_similarity, _get_model


class GraphEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_edge(
        self,
        user_id: str,
        source_type: str,
        source_id: str,
        edge_type: str,
        target_type: str,
        target_id: str,
        confidence: float = 1.0,
        evidence_source: str = "explicit_tag",
    ) -> GraphEdge:
        """Create or update a typed, confidence-weighted edge in the Execution Graph."""
        stmt = select(GraphEdge).where(
            GraphEdge.user_id == user_id,
            GraphEdge.source_type == source_type,
            GraphEdge.source_id == source_id,
            GraphEdge.edge_type == edge_type,
            GraphEdge.target_type == target_type,
            GraphEdge.target_id == target_id,
        )
        res = await self.db.execute(stmt)
        edge = res.scalar_one_or_none()
        if edge:
            edge.confidence = max(edge.confidence, confidence)
            edge.evidence_source = evidence_source
            return edge

        edge = GraphEdge(
            user_id=user_id,
            source_type=source_type,
            source_id=source_id,
            edge_type=edge_type,
            target_type=target_type,
            target_id=target_id,
            confidence=confidence,
            evidence_source=evidence_source,
        )
        self.db.add(edge)
        return edge

    async def correlate_commit_to_task(
        self,
        user_id: str,
        commit_id: str,
        commit_sha: str,
        commit_msg: str,
        committed_at: datetime,
        files_modified: List[str],
    ) -> Optional[Tuple[str, float, str]]:
        """
        4-Tier correlation waterfall matching commit to task:
        Tier 1: Explicit [TRO-<UUID>]
        Tier 2: Active session window
        Tier 3: File overlap
        Tier 4: Semantic embedding similarity
        """
        import re

        # Tier 1: Explicit tag
        match = re.search(r'\[TRO-([0-9a-fA-F-]+)\]', commit_msg)
        if match:
            tid = match.group(1)
            t_res = await self.db.execute(select(Task).where(Task.id == tid, Task.user_id == user_id))
            if t_res.scalar_one_or_none():
                await self.add_edge(user_id, "Commit", commit_id, "CONTRIBUTES_TO", "Task", tid, 1.0, "explicit_tag")
                return (tid, 1.0, "explicit_tag")

        # Fetch in-flight or recent tasks for user
        active_res = await self.db.execute(
            select(Task).where(
                Task.user_id == user_id,
                Task.started_at <= committed_at,
                or_(Task.ended_at.is_(None), Task.ended_at >= committed_at - timedelta(hours=2))
            )
        )
        candidate_tasks = active_res.scalars().all()

        # Tier 2: Single active task during commit window
        if len(candidate_tasks) == 1:
            task = candidate_tasks[0]
            await self.add_edge(user_id, "Commit", commit_id, "CONTRIBUTES_TO", "Task", task.id, 0.85, "time_window")
            return (task.id, 0.85, "time_window")

        if not candidate_tasks:
            return None

        # Tier 3: File overlap with previous commits
        if files_modified:
            for task in candidate_tasks:
                fc_res = await self.db.execute(
                    select(FileChange.file_path)
                    .join(Commit, FileChange.commit_id == Commit.id)
                    .where(Commit.task_id == task.id)
                )
                prev_files = set(fc_res.scalars().all())
                overlap = prev_files.intersection(set(files_modified))
                if overlap:
                    await self.add_edge(user_id, "Commit", commit_id, "CONTRIBUTES_TO", "Task", task.id, 0.70, "file_overlap")
                    return (task.id, 0.70, "file_overlap")

        # Tier 4: Semantic similarity between commit message and task goals
        try:
            texts = [commit_msg] + [t.goal for t in candidate_tasks]
            embs = _get_model().encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            commit_emb = embs[0]
            best_sim = -1.0
            best_task = None
            for idx, task in enumerate(candidate_tasks):
                sim = _cosine_similarity(commit_emb, embs[idx + 1])
                if sim > best_sim:
                    best_sim = sim
                    best_task = task
            if best_sim >= 0.70 and best_task:
                await self.add_edge(user_id, "Commit", commit_id, "CONTRIBUTES_TO", "Task", best_task.id, round(float(best_sim), 2), "semantic")
                return (best_task.id, round(float(best_sim), 2), "semantic")
        except Exception:
            pass

        return None

    async def get_task_graph(self, user_id: str, task_id: str) -> Dict[str, Any]:
        """
        Extract complete execution DAG for a task, returning nodes and directed edges.
        """
        # Verify task ownership
        t_res = await self.db.execute(select(Task).where(Task.id == task_id, Task.user_id == user_id))
        task = t_res.scalar_one_or_none()
        if not task:
            return {"error": "Task not found"}

        nodes: List[Dict[str, Any]] = [
            {
                "id": task.id,
                "type": "Task",
                "label": task.goal[:60],
                "status": task.status,
                "target_level": task.target_level,
                "final_level": task.final_level,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "ended_at": task.ended_at.isoformat() if task.ended_at else None,
            }
        ]

        # Fetch commits
        c_res = await self.db.execute(select(Commit).where(Commit.task_id == task_id))
        commits = c_res.scalars().all()
        for c in commits:
            nodes.append({
                "id": c.id,
                "type": "Commit",
                "sha": c.sha[:7],
                "label": c.message[:60],
                "author": c.author_name,
                "committed_at": c.committed_at.isoformat() if c.committed_at else None,
            })

        # Fetch AI Sessions
        ai_res = await self.db.execute(select(AISession).where(AISession.task_id == task_id))
        sessions = ai_res.scalars().all()
        for s in sessions:
            nodes.append({
                "id": s.id,
                "type": "AISession",
                "label": s.session_name or "AI Assistant Session",
                "started_at": s.started_at.isoformat() if s.started_at else None,
            })

        # Fetch Errors
        err_res = await self.db.execute(select(ErrorRecord).where(ErrorRecord.task_id == task_id))
        errors = err_res.scalars().all()
        for err in errors:
            nodes.append({
                "id": err.id,
                "type": "Error",
                "label": f"{err.exception_type}: {err.message[:50]}",
                "severity": err.severity,
                "occurred_at": err.occurred_at.isoformat() if err.occurred_at else None,
            })

        # Fetch Graph Edges
        edge_res = await self.db.execute(
            select(GraphEdge).where(
                GraphEdge.user_id == user_id,
                or_(
                    and_(GraphEdge.source_type == "Task", GraphEdge.source_id == task_id),
                    and_(GraphEdge.target_type == "Task", GraphEdge.target_id == task_id),
                    GraphEdge.source_id.in_([n["id"] for n in nodes]),
                    GraphEdge.target_id.in_([n["id"] for n in nodes]),
                )
            )
        )
        edges = edge_res.scalars().all()

        return {
            "task_id": task_id,
            "goal": task.goal,
            "status": task.status,
            "nodes": nodes,
            "edges": [
                {
                    "source": e.source_id,
                    "source_type": e.source_type,
                    "target": e.target_id,
                    "target_type": e.target_type,
                    "edge_type": e.edge_type,
                    "confidence": e.confidence,
                    "evidence_source": e.evidence_source,
                }
                for e in edges
            ],
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
