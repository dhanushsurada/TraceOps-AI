"""
Event Ingestion API with Webhook Durability, Deduplication & Tenant Isolation

POST /event          — ingest a single normalized event
POST /event/github   — receive GitHub webhook (with signature verification & durability)
POST /event/deploy   — ingest deploy log
POST /event/error    — ingest error log
GET  /event/         — list recent events (user scoped)
"""
from typing import Optional, List
import hmac
import hashlib

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user, get_optional_user
from app.core.config import settings
from app.core.database import get_db
from app.models.models import Event, User, Commit, Project
from app.services.normalizer import (
    normalize_deploy_event,
    normalize_error_event,
    normalize_event,
    normalize_github_commit,
)
from app.services.task_enforcement import enforce_task_id
from app.services.webhook_durability import (
    store_webhook,
    mark_processed,
    mark_failed,
)

router = APIRouter(prefix="/event", tags=["Events"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class EventRequest(BaseModel):
    task_id: Optional[str] = None
    event_type: str
    metadata: dict = {}
    source: Optional[str] = None
    timestamp: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _persist_event(db: AsyncSession, normalized: dict, user_id: Optional[str] = None) -> Event:
    event = Event(
        user_id=user_id or normalized.get("user_id"),
        task_id=normalized.get("task_id"),
        event_type=normalized["event_type"],
        source=normalized.get("source"),
        raw_data=normalized,
        metadata_=normalized.get("metadata"),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/", status_code=201)
async def ingest_event(
    req: EventRequest,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Generic event ingestion. Normalizes, enforces TASK_ID, and stores."""
    user_id = current_user.id if current_user else None
    raw = {
        "user_id": user_id,
        "task_id": req.task_id,
        "event_type": req.event_type,
        "source": req.source or "api",
        "timestamp": req.timestamp,
        "metadata": req.metadata,
    }
    normalized = normalize_event(raw)
    normalized = await enforce_task_id(normalized, db)
    event = await _persist_event(db, normalized, user_id=user_id)
    return {"event_id": event.id, "task_id": event.task_id, "event_type": event.event_type}


@router.post("/github", status_code=201)
async def ingest_github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
):
    """
    Receive GitHub push webhook with HMAC-SHA256 signature validation and idempotency.
    """
    body_bytes = await request.body()

    # Optional signature check if secret is configured
    if settings.SECRET_KEY and x_hub_signature_256:
        expected = "sha256=" + hmac.new(settings.SECRET_KEY.encode(), body_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")

    payload = await request.json()
    event_type = x_github_event or "push"

    if event_type not in ("push", "pull_request"):
        return {"skipped": True, "reason": f"Unhandled event type: {event_type}"}

    # Idempotency check via payload hash & durable storage
    webhook_row, is_dup = await store_webhook(db, "github", event_type, payload)
    if is_dup:
        return {"skipped": True, "reason": "Duplicate webhook event already processed."}

    try:
        normalized_list = normalize_github_commit(payload)
        if isinstance(normalized_list, dict):
            normalized_list = [normalized_list]

        created_ids = []
        for normalized in normalized_list:
            event = await _persist_event(db, normalized)
            created_ids.append(event.id)

        if webhook_row:
            await mark_processed(webhook_row.id, db)

        return {"created": len(created_ids), "event_ids": created_ids}
    except Exception as e:
        if webhook_row:
            await mark_failed(webhook_row.id, str(e), db)
        raise


@router.post("/deploy", status_code=201)
async def ingest_deploy_event(
    payload: dict,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a deployment log event from CI/CD."""
    user_id = current_user.id if current_user else None
    normalized = normalize_deploy_event(payload)
    event = await _persist_event(db, normalized, user_id=user_id)
    return {
        "event_id": event.id,
        "task_id": event.task_id,
        "status": normalized.get("metadata", {}).get("status"),
        "commit_sha": normalized.get("metadata", {}).get("commit_sha"),
    }


@router.post("/error", status_code=201)
async def ingest_error_event(
    payload: dict,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest an error or exception log."""
    user_id = current_user.id if current_user else None
    normalized = normalize_error_event(payload)
    event = await _persist_event(db, normalized, user_id=user_id)
    return {
        "event_id": event.id,
        "task_id": event.task_id,
        "error_hash": normalized.get("metadata", {}).get("error_hash"),
        "normalized": normalized.get("metadata", {}).get("message", "")[:100],
    }


@router.get("/")
async def list_events(
    task_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 50,
    current_user: Optional[User] = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
):
    """List events with tenant isolation."""
    user_id = current_user.id if current_user else None
    q = select(Event).order_by(Event.timestamp.desc()).limit(min(limit, 200))
    if user_id:
        q = q.where(Event.user_id == user_id)
    if task_id:
        q = q.where(Event.task_id == task_id)
    if event_type:
        q = q.where(Event.event_type == event_type)
    result = await db.execute(q)
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "task_id": e.task_id,
            "user_id": e.user_id,
            "event_type": e.event_type,
            "source": e.source,
            "timestamp": e.timestamp,
            "metadata": e.metadata_,
        }
        for e in events
    ]
