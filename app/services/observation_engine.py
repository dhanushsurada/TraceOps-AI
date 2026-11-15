"""
Deterministic Observation Engine

Computes mathematical, verifiable facts from the Execution Graph and persists
them as `Observation` records with SHA-256 evidence hashes.
No subjective interpretations; strictly empirical measurements.
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Observation, Task, Commit, Event, ErrorRecord, Deployment, AISession, AIPrompt
)
from app.services.scoring import compute_active_time_hours


def compute_evidence_hash(evidence_ids: List[str]) -> str:
    """Produce deterministic SHA-256 hash over sorted supporting evidence IDs."""
    sorted_ids = sorted(str(i) for i in evidence_ids)
    joined = "|".join(sorted_ids)
    return hashlib.sha256(joined.encode()).hexdigest()


class ObservationEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def compute_task_observations(self, user_id: str, task_id: str) -> List[Observation]:
        """Compute all deterministic observations for a task and persist to database."""
        # 1. Fetch Task
        t_res = await self.db.execute(select(Task).where(Task.id == task_id, Task.user_id == user_id))
        task = t_res.scalar_one_or_none()
        if not task:
            return []

        start_time = task.started_at or datetime.utcnow()
        end_time = task.ended_at or datetime.utcnow()

        # 2. Fetch Commits
        c_res = await self.db.execute(select(Commit).where(Commit.task_id == task_id))
        commits = c_res.scalars().all()

        # 3. Fetch Events
        ev_res = await self.db.execute(select(Event).where(Event.task_id == task_id))
        events = ev_res.scalars().all()
        event_ts = [e.timestamp for e in events if e.timestamp]

        # 4. Fetch AI Prompts
        p_res = await self.db.execute(
            select(AIPrompt)
            .join(AISession, AIPrompt.session_id == AISession.id)
            .where(AISession.task_id == task_id)
        )
        prompts = p_res.scalars().all()

        # 5. Fetch Errors
        err_res = await self.db.execute(select(ErrorRecord).where(ErrorRecord.task_id == task_id))
        errors = err_res.scalars().all()

        # 6. Fetch Deployments
        dep_res = await self.db.execute(
            select(Deployment).where(Deployment.commit_sha.in_([c.sha for c in commits]))
        )
        deployments = dep_res.scalars().all()

        observations: List[Observation] = []

        # ── Observation: active_work_seconds ──
        active_hours = compute_active_time_hours(event_ts, start_time, end_time)
        active_secs = active_hours * 3600.0
        ev_ids = [str(e.id) for e in events]
        observations.append(Observation(
            user_id=user_id,
            task_id=task_id,
            project_id=task.project_id,
            window_start=start_time,
            window_end=end_time,
            observation_type="active_work_seconds",
            metric_value=round(active_secs, 2),
            unit="seconds",
            supporting_evidence={"event_count": len(events), "event_ids": ev_ids[:20]},
            evidence_hash=compute_evidence_hash(ev_ids),
        ))

        # ── Observation: commit_count ──
        commit_shas = [c.sha for c in commits]
        observations.append(Observation(
            user_id=user_id,
            task_id=task_id,
            project_id=task.project_id,
            window_start=start_time,
            window_end=end_time,
            observation_type="commit_count",
            metric_value=float(len(commits)),
            unit="commits",
            supporting_evidence={"commit_shas": commit_shas},
            evidence_hash=compute_evidence_hash(commit_shas),
        ))

        # ── Observation: code_churn_ratio ──
        total_added = sum(c.lines_added for c in commits)
        total_deleted = sum(c.lines_deleted for c in commits)
        total_loc = total_added + total_deleted
        churn = round(total_deleted / total_loc, 4) if total_loc > 0 else 0.0
        observations.append(Observation(
            user_id=user_id,
            task_id=task_id,
            project_id=task.project_id,
            window_start=start_time,
            window_end=end_time,
            observation_type="code_churn_ratio",
            metric_value=churn,
            unit="ratio",
            supporting_evidence={"lines_added": total_added, "lines_deleted": total_deleted},
            evidence_hash=compute_evidence_hash(commit_shas),
        ))

        # ── Observation: ai_prompt_intensity ──
        prompt_ids = [p.id for p in prompts]
        intensity = round(len(prompts) / max(0.5, active_hours), 2)
        observations.append(Observation(
            user_id=user_id,
            task_id=task_id,
            project_id=task.project_id,
            window_start=start_time,
            window_end=end_time,
            observation_type="ai_prompt_intensity",
            metric_value=intensity,
            unit="prompts/hour",
            supporting_evidence={"prompt_count": len(prompts), "prompt_ids": prompt_ids[:20]},
            evidence_hash=compute_evidence_hash(prompt_ids),
        ))

        # ── Observation: defect_density ──
        err_ids = [err.id for err in errors]
        failed_deploys = [d for d in deployments if d.status == "failed"]
        defect_count = len(errors) + len(failed_deploys)
        observations.append(Observation(
            user_id=user_id,
            task_id=task_id,
            project_id=task.project_id,
            window_start=start_time,
            window_end=end_time,
            observation_type="defect_density",
            metric_value=float(defect_count),
            unit="defects",
            supporting_evidence={"errors": len(errors), "failed_deployments": len(failed_deploys)},
            evidence_hash=compute_evidence_hash(err_ids + [d.id for d in failed_deploys]),
        ))

        for obs in observations:
            self.db.add(obs)
        await self.db.commit()

        return observations
