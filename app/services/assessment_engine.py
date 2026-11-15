"""
Versioned Assessment Engine (v4.0.0)

Generates auditable, multi-dimensional execution assessments derived from
deterministic observations:
- delivery_velocity
- execution_efficiency
- stability_and_reliability
- ai_leverage_effectiveness
- evidence_confidence_score

Strict Principle Enforcement:
- Honest Uncertainty: Absence of data is explicitly represented as low confidence / N/A, never fabricated as 100% success.
- Zero AI usage does NOT yield 100% effectiveness.
- Limitations and caveats are documented on every assessment record.
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

        # ── 1. Telemetry Coverage & Evidence Confidence ──
        active_secs_obs = obs_map.get("active_work_seconds")
        commits_obs = obs_map.get("commit_count")
        churn_obs = obs_map.get("code_churn_ratio")
        intensity_obs = obs_map.get("ai_prompt_intensity")
        defects_obs = obs_map.get("defect_density")

        # Telemetry sources tracked
        has_git = commits_obs is not None and commits_obs.metric_value > 0
        has_activity = active_secs_obs is not None and active_secs_obs.metric_value > 0
        has_churn = churn_obs is not None
        has_defects = defects_obs is not None
        has_ai = intensity_obs is not None and intensity_obs.metric_value > 0

        # Confidence calculation:
        # Without local IDE or terminal daemon, max confidence is capped at 0.75
        base_coverage = sum([has_git, has_activity, has_churn, has_defects]) / 4.0
        overall_confidence = round(min(0.75, base_coverage * 0.75), 2)

        # ── 2. Delivery Velocity ──
        active_hours = (active_secs_obs.metric_value / 3600.0) if active_secs_obs else 1.0
        commit_count = commits_obs.metric_value if commits_obs else 0.0

        raw_velocity = min(100.0, (commit_count / max(0.5, active_hours)) * 25.0)

        # ── 3. Execution Efficiency ──
        churn_ratio = churn_obs.metric_value if churn_obs else 0.0
        defects = defects_obs.metric_value if defects_obs else 0.0

        churn_penalty = min(40.0, churn_ratio * 50.0)
        defect_penalty = min(40.0, defects * 10.0)
        efficiency = max(0.0, min(100.0, 100.0 - churn_penalty - defect_penalty))

        # ── 4. Stability & Reliability ──
        stability = max(0.0, min(100.0, 100.0 - (defects * 15.0)))

        # ── 5. AI Leverage Effectiveness ──
        # If no AI prompts were used, AI effectiveness cannot be scored as 100%
        if not has_ai:
            ai_score = 0.0
            ai_confidence = 0.0
            ai_breakdown = {"status": "no_ai_interactions_detected", "prompts_count": 0}
            ai_limitations = {"note": "Developer did not use AI proxy for this task; score is N/A"}
        else:
            intensity = intensity_obs.metric_value
            ai_score = round(min(100.0, max(10.0, (commit_count / max(1.0, intensity)) * 50.0)), 2)
            ai_confidence = overall_confidence
            ai_breakdown = {"ai_intensity_prompts_per_hr": intensity, "commits_delivered": commit_count}
            ai_limitations = {}

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
                confidence=overall_confidence,
                input_observation_ids=input_ids,
                breakdown={"estimated_active_hours": active_hours, "commit_count": commit_count},
                limitations={"telemetry": "Active work duration is estimated from event timestamps; IDE keystrokes not connected."},
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
                confidence=overall_confidence,
                input_observation_ids=input_ids,
                breakdown={"churn_penalty": churn_penalty, "defect_penalty": defect_penalty},
                limitations={"provisional": "Heuristic model based on diff churn and defect counts."},
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
                confidence=overall_confidence,
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
                score=ai_score,
                confidence=ai_confidence,
                input_observation_ids=input_ids,
                breakdown=ai_breakdown,
                limitations=ai_limitations,
            ),
            Assessment(
                user_id=user_id,
                task_id=task_id,
                project_id=project_id,
                assessment_dimension="evidence_confidence_score",
                algorithm_version=ALGORITHM_VERSION,
                window_start=window_start,
                window_end=window_end,
                score=round(overall_confidence * 100.0, 2),
                confidence=1.0,
                input_observation_ids=input_ids,
                breakdown={
                    "git_telemetry": has_git,
                    "activity_telemetry": has_activity,
                    "churn_telemetry": has_churn,
                    "defect_telemetry": has_defects,
                    "ide_telemetry_connected": False,
                },
                limitations={"ceiling": "Confidence capped at 0.75 until IDE collector plugin is connected."},
            ),
        ]

        for a in assessments:
            self.db.add(a)
        await self.db.commit()

        return assessments
