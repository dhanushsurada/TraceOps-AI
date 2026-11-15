"""
Versioned Assessment Engine (v4.0.0)

Generates auditable, multi-dimensional execution assessments derived from
deterministic observations:
- delivery_velocity
- execution_efficiency
- stability_and_reliability
- ai_leverage_effectiveness
- evidence_confidence_score

Every assessment records its input observation IDs, confidence bounds, and algorithm version.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Assessment, Observation, Task


ALGORITHM_VERSION = "v4.0.0"


class AssessmentEngine:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_task_assessments(self, user_id: str, task_id: str) -> List[Assessment]:
        """Compute versioned v4.0.0 assessments for a task from its recorded observations."""
        # Fetch observations for this task
        obs_res = await self.db.execute(
            select(Observation).where(Observation.task_id == task_id, Observation.user_id == user_id)
        )
        observations = obs_res.scalars().all()
        if not observations:
            return []

        obs_map = {o.observation_type: o for o in observations}
        input_ids = [str(o.id) for o in observations]

        window_start = min(o.window_start for o in observations)
        window_end = max(o.window_end for o in observations)
        project_id = observations[0].project_id

        # ── 1. Delivery Velocity ──
        active_secs = obs_map.get("active_work_seconds", None)
        commits_obs = obs_map.get("commit_count", None)

        active_hours = (active_secs.metric_value / 3600.0) if active_secs else 1.0
        commit_count = commits_obs.metric_value if commits_obs else 0.0

        # Velocity: commits per active hour normalized to 100
        raw_velocity = min(100.0, (commit_count / max(0.5, active_hours)) * 25.0)

        # ── 2. Execution Efficiency ──
        churn_obs = obs_map.get("code_churn_ratio", None)
        churn_ratio = churn_obs.metric_value if churn_obs else 0.0
        defects_obs = obs_map.get("defect_density", None)
        defects = defects_obs.metric_value if defects_obs else 0.0

        churn_penalty = min(40.0, churn_ratio * 50.0)
        defect_penalty = min(40.0, defects * 10.0)
        efficiency = max(0.0, min(100.0, 100.0 - churn_penalty - defect_penalty))

        # ── 3. Stability & Reliability ──
        stability = max(0.0, min(100.0, 100.0 - (defects * 15.0)))

        # ── 4. AI Leverage Effectiveness ──
        intensity_obs = obs_map.get("ai_prompt_intensity", None)
        intensity = intensity_obs.metric_value if intensity_obs else 0.0

        if intensity == 0:
            ai_effectiveness = 100.0
        else:
            # High commit output with moderate AI prompts yields high leverage
            ai_effectiveness = min(100.0, max(20.0, (commit_count / max(1.0, intensity)) * 50.0))

        # ── 5. Evidence Confidence Score ──
        # Higher confidence when multiple telemetry streams are present
        coverage_factors = [
            active_secs is not None,
            commits_obs is not None and commit_count > 0,
            churn_obs is not None,
            defects_obs is not None,
        ]
        confidence = round(sum(1.0 for f in coverage_factors if f) / len(coverage_factors), 2)

        assessments: List[Assessment] = [
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="delivery_velocity",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(raw_velocity, 2),
                confidence=confidence,
                input_observation_ids=input_ids,
                breakdown={"active_hours": active_hours, "commit_count": commit_count},
                limitations={"telemetry": "Active hours estimated from event stream"},
            ),
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="execution_efficiency",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(efficiency, 2),
                confidence=confidence,
                input_observation_ids=input_ids,
                breakdown={"churn_penalty": churn_penalty, "defect_penalty": defect_penalty},
                limitations={},
            ),
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="stability_and_reliability",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(stability, 2),
                confidence=confidence,
                input_observation_ids=input_ids,
                breakdown={"defects_recorded": defects},
                limitations={},
            ),
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="ai_leverage_effectiveness",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(ai_effectiveness, 2),
                confidence=confidence,
                input_observation_ids=input_ids,
                breakdown={"ai_intensity": intensity, "commits": commit_count},
                limitations={},
            ),
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="evidence_confidence_score",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(confidence * 100.0, 2),
                confidence=1.0,
                input_observation_ids=input_ids,
                breakdown={"coverage_factors_present": sum(1 for f in coverage_factors if f)},
                limitations={},
            ),
        ]

        for a in assessments:
            self.db.add(a)
        await self.db.commit()

        return assessments
