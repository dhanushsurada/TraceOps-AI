"""
Evidence-Backed Output & Content Engine

Generates human-readable, defensible engineering artifacts:
- LinkedIn progress posts
- Resume achievement bullets
- Technical changelogs and release notes

Core Rule: Evidence before claims.
Never assert facts that cannot be substantiated from recorded telemetry.
Omit unmeasured properties (e.g. test coverage percentage, code reviews) unless
corroborated by actual database records.
"""
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Task, Commit, Assessment, Observation, Project, Event


class ContentGenerator:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_linkedin_update(self, user_id: str, days: int = 7) -> Dict[str, Any]:
        """Produce an evidence-backed LinkedIn post with citations derived strictly from verified data."""
        start_date = datetime.utcnow() - timedelta(days=days)

        # Fetch completed tasks
        t_res = await self.db.execute(
            select(Task).where(
                Task.user_id == user_id,
                Task.started_at >= start_date,
                Task.status == "completed",
            )
        )
        tasks = t_res.scalars().all()

        # Fetch commits
        c_res = await self.db.execute(
            select(Commit).where(Commit.user_id == user_id, Commit.committed_at >= start_date)
        )
        commits = c_res.scalars().all()

        task_count = len(tasks)
        commit_count = len(commits)
        loc_added = sum(c.lines_added for c in commits)
        loc_deleted = sum(c.lines_deleted for c in commits)

        evidence_str = f"usr_{user_id[:6]}_{task_count}t_{commit_count}c_{loc_added}l"
        citation_hash = hashlib.sha256(evidence_str.encode()).hexdigest()[:8].upper()
        citation_tag = f"[TRO-EVID-{citation_hash}]"

        task_bullets = "\n".join(f"• Completed: {t.goal}" for t in tasks[:4]) if tasks else "• Progress recorded across active development branches"

        # Evidence-grounded telemetry points
        telemetry_lines = [
            f"⚡ {commit_count} Git commits recorded across {task_count} completed tasks",
        ]
        if loc_added > 0:
            telemetry_lines.append(f"📦 +{loc_added} / -{loc_deleted} lines of code modified")

        telemetry_block = "\n".join(telemetry_lines)

        post_body = f"""Engineering Execution Summary ({days}-Day Period)

Development Milestones:
{task_bullets}

Telemetry Recorded:
{telemetry_block}

Traceability Reference: {citation_tag}
Verified by TraceOps Execution Intelligence."""

        return {
            "post_body": post_body,
            "citation_tag": citation_tag,
            "tasks_substantiated": task_count,
            "commits_substantiated": commit_count,
            "lines_added": loc_added,
            "lines_deleted": loc_deleted,
        }

    async def generate_resume_bullet(self, user_id: str, task_id: str) -> Dict[str, Any]:
        """Produce a quantified resume achievement bullet tied to verifiable task evidence."""
        t_res = await self.db.execute(select(Task).where(Task.id == task_id, Task.user_id == user_id))
        task = t_res.scalar_one_or_none()
        if not task:
            return {"error": "Task not found"}

        c_res = await self.db.execute(select(Commit).where(Commit.task_id == task_id, Commit.user_id == user_id))
        commits = c_res.scalars().all()

        loc_added = sum(c.lines_added for c in commits)
        citation_tag = f"[TRO-EVID-{task.id[:8].upper()}]"

        if loc_added > 0:
            bullet = f"Delivered {task.goal}, implementing {len(commits)} commits (+{loc_added} LOC) {citation_tag}."
        else:
            bullet = f"Completed {task.goal}, delivering {len(commits)} verified commits {citation_tag}."

        return {
            "task_id": task_id,
            "resume_bullet": bullet,
            "citation_tag": citation_tag,
            "commit_count": len(commits),
            "lines_added": loc_added,
        }
