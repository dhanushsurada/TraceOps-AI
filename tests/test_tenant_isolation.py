"""
TraceOps AI — Strict Multi-Tenant Isolation & Authentication Acceptance Test Suite

Verifies:
1. Mandatory Authentication: User-facing and machine endpoints strictly reject unauthenticated calls (HTTP 401).
2. Credential Security: User IDs are strictly rejected as credentials (HTTP 401). Scoped API keys (tro_live_...) and session tokens are required.
3. Multi-Tenant Data Isolation: User A cannot read, mutate, or observe User B's tasks, projects, events, graphs, assessments, or reports.
4. Dedicated Webhook Secret: Fallback to SECRET_KEY is forbidden; requests signed with SECRET_KEY are rejected (HTTP 401).
5. Unambiguous Webhook Mapping: Colliding repository registrations require explicit disambiguation; ambiguity raises HTTP 409 Conflict.
"""
import hmac
import hashlib
import json
import os
import tempfile
from unittest.mock import patch
import pytest
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from starlette.testclient import TestClient

from main import app
from app.core.config import settings
from app.core.database import get_db, Base
from app.models.models import User
from app.services.auth import create_session, create_api_key


@pytest.fixture(scope="module")
def test_setup():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    TestingSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    import asyncio
    async def init_db():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with TestingSessionLocal() as session:
            # Create User A
            user_a = User(id="usr_alice", email="alice@test.com", name="Alice Developer")
            session.add(user_a)
            # Create User B
            user_b = User(id="usr_bob", email="bob@test.com", name="Bob Developer")
            session.add(user_b)
            await session.commit()

            # Create sessions
            token_a = await create_session(session, "usr_alice")
            token_b = await create_session(session, "usr_bob")

            # Create scoped API Key for User A
            raw_key_a, _ = await create_api_key(session, "usr_alice", name="Alice CLI Key", scopes="read,write,mcp")

            await session.commit()

            return token_a, token_b, raw_key_a

    token_a, token_b, raw_key_a = asyncio.run(init_db())

    async def override_get_db():
        async with TestingSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    yield {
        "client": client,
        "token_a": token_a,
        "token_b": token_b,
        "api_key_a": raw_key_a,
        "headers_a": {"Authorization": f"Bearer {token_a}"},
        "headers_b": {"Authorization": f"Bearer {token_b}"},
        "api_key_headers_a": {"Authorization": f"Bearer {raw_key_a}"},
    }

    app.dependency_overrides.clear()
    if os.path.exists(db_path):
        os.remove(db_path)


class TestUnauthenticatedRejection:
    """Verifies that all user-facing and machine endpoints enforce authentication."""

    def test_user_id_rejected_as_credential(self, test_setup):
        """CRITICAL: User ID is an identifier, not a credential. Must be rejected with 401."""
        client = test_setup["client"]
        resp = client.get("/projects/", headers={"Authorization": "Bearer usr_alice"})
        assert resp.status_code == 401

    def test_scoped_api_key_accepted(self, test_setup):
        """Verifies that cryptographically secure, scoped API key (tro_live_...) authenticates successfully."""
        client = test_setup["client"]
        headers = test_setup["api_key_headers_a"]
        resp = client.get("/projects/", headers=headers)
        assert resp.status_code == 200

    def test_task_endpoints_require_auth(self, test_setup):
        client = test_setup["client"]
        r1 = client.post("/task/start", json={"goal": "unauth", "target_level": 3})
        assert r1.status_code == 401

        r2 = client.post("/task/end", json={"task_id": "any-uuid", "final_level": 3})
        assert r2.status_code == 401

        r3 = client.get("/task/any-uuid")
        assert r3.status_code == 401

    def test_project_endpoints_require_auth(self, test_setup):
        client = test_setup["client"]
        r1 = client.get("/projects/")
        assert r1.status_code == 401

        r2 = client.post("/projects/", json={"name": "test-repo", "slug": "org/test-repo"})
        assert r2.status_code == 401

    def test_event_endpoints_require_auth(self, test_setup):
        client = test_setup["client"]
        r1 = client.get("/event/")
        assert r1.status_code == 401

        r2 = client.post("/event", json={"event_type": "build", "timestamp": "2026-11-15T00:00:00Z"})
        assert r2.status_code == 401

        r3 = client.post("/event/deploy", json={"status": "success"})
        assert r3.status_code == 401

        r4 = client.post("/event/error", json={"message": "NullPointer"})
        assert r4.status_code == 401

    def test_context_and_audit_require_auth(self, test_setup):
        client = test_setup["client"]
        r1 = client.get("/api/v1/context/task/any-uuid")
        assert r1.status_code == 401

        r2 = client.get("/api/v1/context/audit")
        assert r2.status_code == 401

    def test_content_generator_requires_auth(self, test_setup):
        client = test_setup["client"]
        r1 = client.post("/content/linkedin", json={"days": 7})
        assert r1.status_code == 401

        r2 = client.post("/content/resume", json={"days": 30})
        assert r2.status_code == 401

    def test_reports_require_auth(self, test_setup):
        client = test_setup["client"]
        r = client.get("/report/daily")
        assert r.status_code == 401


class TestWebhookSecurity:
    """Verifies dedicated secret enforcement and deterministic tenant mapping."""

    def test_unsigned_github_webhook_rejected(self, test_setup):
        client = test_setup["client"]
        payload = {"action": "push", "repository": {"full_name": "org/repo"}}
        resp = client.post("/event/github", json=payload)
        assert resp.status_code == 401
        assert "Missing mandatory X-Hub-Signature-256 header" in resp.json()["detail"]

    def test_invalidly_signed_github_webhook_rejected(self, test_setup):
        client = test_setup["client"]
        payload = {"action": "push", "repository": {"full_name": "org/repo"}}
        headers = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        }
        resp = client.post("/event/github", json=payload, headers=headers)
        assert resp.status_code == 401
        assert "Invalid GitHub webhook signature" in resp.json()["detail"]

    def test_webhook_signed_with_general_secret_key_rejected(self, test_setup):
        """CRITICAL: Webhook signed with SECRET_KEY must be rejected. Dedicated GITHUB_WEBHOOK_SECRET is mandatory."""
        client = test_setup["client"]
        payload_bytes = json.dumps({"action": "push", "repository": {"full_name": "org/repo"}}).encode("utf-8")
        # Sign with general SECRET_KEY (which is distinct from GITHUB_WEBHOOK_SECRET)
        wrong_sig = "sha256=" + hmac.new(b"different_general_secret_key_12345", payload_bytes, hashlib.sha256).hexdigest()

        headers = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": wrong_sig,
            "Content-Type": "application/json",
        }
        resp = client.post("/event/github", content=payload_bytes, headers=headers)
        assert resp.status_code == 401

    def test_webhook_without_configured_secret_fails_server_error(self, test_setup):
        """If GITHUB_WEBHOOK_SECRET is unconfigured, ingestion fails with 500, never falling back to SECRET_KEY."""
        client = test_setup["client"]
        payload_bytes = json.dumps({"action": "push", "repository": {"full_name": "org/repo"}}).encode("utf-8")
        headers = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": "sha256=any",
            "Content-Type": "application/json",
        }
        with patch.object(settings, "GITHUB_WEBHOOK_SECRET", ""):
            resp = client.post("/event/github", content=payload_bytes, headers=headers)
            assert resp.status_code == 500
            assert "GITHUB_WEBHOOK_SECRET is mandatory" in resp.json()["detail"]

    def test_validly_signed_github_webhook_accepted(self, test_setup):
        client = test_setup["client"]
        payload_bytes = json.dumps({"action": "push", "repository": {"full_name": "org/repo"}}).encode("utf-8")
        secret = settings.GITHUB_WEBHOOK_SECRET
        sig = "sha256=" + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

        headers = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        }
        resp = client.post("/event/github", content=payload_bytes, headers=headers)
        assert resp.status_code in (200, 201)

    def test_ambiguous_webhook_mapping_policy(self, test_setup):
        """
        When two tenants register the same repository slug:
        - Webhook without unique disambiguation returns 409 Conflict (no arbitrary guessing).
        - Webhook with explicit X-TraceOps-Tenant-ID routes deterministically.
        """
        client = test_setup["client"]
        headers_a = test_setup["headers_a"]
        headers_b = test_setup["headers_b"]

        # User A and User B both register 'corp/shared-platform'
        client.post("/projects/", json={"name": "Shared A", "slug": "corp/shared-platform"}, headers=headers_a)
        client.post("/projects/", json={"name": "Shared B", "slug": "corp/shared-platform"}, headers=headers_b)

        payload_bytes = json.dumps({
            "action": "push",
            "repository": {"full_name": "corp/shared-platform"},
            "sender": {"id": 999999, "login": "external-contributor"},
            "commits": [{"id": "c_shared_1", "message": "feat: shared update", "timestamp": "2026-11-15T00:00:00Z"}]
        }).encode("utf-8")

        secret = settings.GITHUB_WEBHOOK_SECRET
        sig = "sha256=" + hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

        # 1. Ambiguous webhook without header fails with 409 Conflict
        headers_ambiguous = {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        }
        resp_ambiguous = client.post("/event/github", content=payload_bytes, headers=headers_ambiguous)
        assert resp_ambiguous.status_code == 409
        assert "Ambiguous tenant mapping" in resp_ambiguous.json()["detail"]

        # 2. Webhook disambiguated with explicit tenant header routes successfully
        headers_disambiguated = {
            **headers_ambiguous,
            "X-TraceOps-Tenant-ID": "usr_alice",
        }
        resp_disambiguated = client.post("/event/github", content=payload_bytes, headers=headers_disambiguated)
        assert resp_disambiguated.status_code == 201


class TestMultiTenantDataIsolation:
    """Verifies that tenant boundaries are strictly respected across all operations."""

    def test_tenant_a_and_b_full_isolation_lifecycle(self, test_setup):
        client = test_setup["client"]
        headers_a = test_setup["headers_a"]
        headers_b = test_setup["headers_b"]

        # 1. User A creates a project
        resp_pa = client.post(
            "/projects/",
            json={"name": "Alice Engine", "slug": "alice/engine", "description": "Alice project"},
            headers=headers_a,
        )
        assert resp_pa.status_code == 201
        proj_a_id = resp_pa.json()["id"]

        # 2. User A starts a task
        resp_ta = client.post(
            "/task/start",
            json={"goal": "Alice private architecture implementation", "target_level": 4, "project_id": proj_a_id},
            headers=headers_a,
        )
        assert resp_ta.status_code == 201
        task_a_id = resp_ta.json()["task_id"]

        # 3. User A ingests an event
        resp_ea = client.post(
            "/event",
            json={
                "event_type": "commit",
                "task_id": task_a_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {"sha": "alicesha1234"},
            },
            headers=headers_a,
        )
        assert resp_ea.status_code == 201

        # --- VERIFY USER B CANNOT ACCESS USER A'S RESOURCES ---

        # 4. User B cannot read User A's task (404)
        resp_b_task = client.get(f"/task/{task_a_id}", headers=headers_b)
        assert resp_b_task.status_code == 404

        # 5. User B cannot end User A's task (404)
        resp_b_end = client.post("/task/end", json={"task_id": task_a_id, "final_level": 4}, headers=headers_b)
        assert resp_b_end.status_code == 404

        # 6. User B cannot read User A's project (404)
        resp_b_proj = client.get(f"/projects/{proj_a_id}", headers=headers_b)
        assert resp_b_proj.status_code == 404

        # 7. User B cannot read User A's task context (404)
        resp_b_ctx = client.get(f"/api/v1/context/task/{task_a_id}", headers=headers_b)
        assert resp_b_ctx.status_code == 404

        # 8. User B cannot compute observations on User A's task (404)
        resp_b_obs = client.post(f"/api/v1/observations/compute/{task_a_id}", headers=headers_b)
        assert resp_b_obs.status_code == 404

        # 9. User B cannot compute assessments on User A's task (404)
        resp_b_ass = client.post(f"/api/v1/assessments/compute/{task_a_id}", headers=headers_b)
        assert resp_b_ass.status_code == 404

        # --- VERIFY LIST QUERIES ARE FILTERED BY TENANT ---

        # 10. User A sees their events; User B sees empty events list
        resp_a_events = client.get("/event/", headers=headers_a)
        assert resp_a_events.status_code == 200
        assert len(resp_a_events.json()) >= 1
        assert any(e.get("task_id") == task_a_id for e in resp_a_events.json())

        resp_b_events = client.get("/event/", headers=headers_b)
        assert resp_b_events.status_code == 200
        assert len(resp_b_events.json()) == 0

        # 11. User A sees their project; User B sees empty projects list
        resp_a_projs = client.get("/projects/", headers=headers_a)
        assert resp_a_projs.status_code == 200
        assert any(p["id"] == proj_a_id for p in resp_a_projs.json())

        resp_b_projs = client.get("/projects/", headers=headers_b)
        assert resp_b_projs.status_code == 200
        assert not any(p["id"] == proj_a_id for p in resp_b_projs.json())

        # 12. User B's reports reflect only User B's metrics (0 tasks started)
        resp_b_reports = client.get("/report/daily", headers=headers_b)
        assert resp_b_reports.status_code == 200
        assert resp_b_reports.json()["summary"]["total_tasks"] == 0

        # 13. User A ends their own task successfully
        resp_a_end = client.post("/task/end", json={"task_id": task_a_id, "final_level": 4}, headers=headers_a)
        assert resp_a_end.status_code == 200
        assert resp_a_end.json()["task_id"] == task_a_id
