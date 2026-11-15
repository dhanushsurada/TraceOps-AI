"""
Event Ingestion API with Mandatory Authentication & Strict Webhook Verification

POST /event          — ingest a single normalized event (requires authentication)
POST /event/github   — receive GitHub webhook (mandatory HMAC-SHA256 signature verification)
POST /event/deploy   — ingest deploy log (requires authentication)
POST /event/error    — ingest error log (requires authentication)
GET  /event/         — list recent events (strictly scoped to authenticated user)
"""
from typing import Optional, List
import hmac
import hashlib

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth.deps import get_current_user
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

async def _persist_event(db: AsyncSession, normalized: dict, user_id: str) -> Event:
    event = Event(
        user_id=user_id,
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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generic event ingestion. Mandatory authentication; strictly scoped to current tenant."""
    raw = {
        "user_id": current_user.id,
        "task_id": req.task_id,
        "event_type": req.event_type,
        "source": req.source or "api",
        "timestamp": req.timestamp,
        "metadata": req.metadata,
    }
    normalized = normalize_event(raw)
    normalized = await enforce_task_id(normalized, db)
    event = await _persist_event(db, normalized, user_id=current_user.id)
    return {"event_id": event.id, "task_id": event.task_id, "event_type": event.event_type}


@router.post("/github", status_code=201)
async def ingest_github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    x_traceops_tenant_id: Optional[str] = Header(None, alias="X-TraceOps-Tenant-ID"),
):
    """
    Receive GitHub push webhook with mandatory HMAC-SHA256 signature validation and deterministic tenant mapping.
    - Dedicated Secret: GITHUB_WEBHOOK_SECRET is mandatory; fallback to SECRET_KEY is forbidden.
    - Deterministic Mapping: Resolves to exactly one verified tenant; collisions/ambiguity are rejected.
    """
    body_bytes = await request.body()
    webhook_secret = settings.GITHUB_WEBHOOK_SECRET

    if not webhook_secret or not webhook_secret.strip():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: GITHUB_WEBHOOK_SECRET is mandatory for webhook ingestion. Falling back to SECRET_KEY is forbidden.",
        )

    if not x_hub_signature_256:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing mandatory X-Hub-Signature-256 header. Unsigned webhooks are rejected.",
        )

    expected = "sha256=" + hmac.new(webhook_secret.encode(), body_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid GitHub webhook signature.",
        )

    payload = await request.json()
    event_type = x_github_event or "push"

    if event_type not in ("push", "pull_request"):
        return {"skipped": True, "reason": f"Unhandled event type: {event_type}"}

    repo_slug = payload.get("repository", {}).get("full_name")
    if not repo_slug:
        return {"skipped": True, "reason": "No repository.full_name in payload"}

    # Deterministic Tenant Mapping Policy
    user_id: Optional[str] = None
    proj_stmt = select(Project).where(Project.slug == repo_slug)
    matching_projects = (await db.execute(proj_stmt)).scalars().all()

    if x_traceops_tenant_id:
        # Explicit tenant specified in webhook header
        tenant_match = [p for p in matching_projects if p.user_id == x_traceops_tenant_id]
        if tenant_match:
            user_id = tenant_match[0].user_id
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specified tenant '{x_traceops_tenant_id}' does not own registered repository '{repo_slug}'.",
            )
    elif len(matching_projects) == 1:
        # Unambiguous single project registered
        user_id = matching_projects[0].user_id
    elif len(matching_projects) > 1:
        # Collision: multiple tenants registered the same repo slug.
        # Disambiguate strictly via verified sender identity
        sender_gh_id = str(payload.get("sender", {}).get("id", ""))
        sender_login = payload.get("sender", {}).get("login", "")
        candidate_user_ids = {p.user_id for p in matching_projects}

        u_stmt = select(User).where(
            User.id.in_(candidate_user_ids),
            (User.github_id == sender_gh_id) | (User.github_username == sender_login)
        )
        resolved_users = (await db.execute(u_stmt)).scalars().all()

        if len(resolved_users) == 1:
            user_id = resolved_users[0].id
        else:
            # Cannot be deterministically disambiguated — reject to prevent cross-tenant pollution
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ambiguous tenant mapping for repository '{repo_slug}'. Multiple tenants match. Disambiguate via X-TraceOps-Tenant-ID header.",
            )
    else:
        # No project registered; check for unambiguous registered user by github_id
        sender_gh_id = str(payload.get("sender", {}).get("id", ""))
        if sender_gh_id:
            users = (await db.execute(select(User).where(User.github_id == sender_gh_id))).scalars().all()
            if len(users) == 1:
                user_id = users[0].id

    if not user_id:
        return {"skipped": True, "reason": f"No registered TraceOps tenant found for repository '{repo_slug}'."}

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
            event = await _persist_event(db, normalized, user_id=user_id)
            created_ids.append(event.id)

        if webhook_row:
            await mark_processed(db, webhook_row.id)

        return {"created": len(created_ids), "event_ids": created_ids}
    except Exception as e:
        if webhook_row:
            await mark_failed(db, webhook_row.id, str(e))
        raise


@router.post("/deploy", status_code=201)
async def ingest_deploy_event(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest a deployment log event from CI/CD. Requires authentication."""
    normalized = normalize_deploy_event(payload)
    event = await _persist_event(db, normalized, user_id=current_user.id)
    return {
        "event_id": event.id,
        "task_id": event.task_id,
        "status": normalized.get("metadata", {}).get("status"),
        "commit_sha": normalized.get("metadata", {}).get("commit_sha"),
    }


@router.post("/error", status_code=201)
async def ingest_error_event(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest an error or exception log. Requires authentication."""
    normalized = normalize_error_event(payload)
    event = await _persist_event(db, normalized, user_id=current_user.id)
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
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List events strictly scoped to the authenticated user."""
    q = select(Event).where(Event.user_id == current_user.id).order_by(Event.timestamp.desc()).limit(min(limit, 200))
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
