"""
Comprehensive End-to-End Test Suite for TraceOps Core Platform Features

Tests:
1. Credential Encryption, Versioned Envelopes (v1:), Key Rotation & Strict Error Handling
2. Deterministic Observation Engine & Evidence Hashes
3. Execution Graph Multi-Signal Correlation & Traversal
4. Versioned Assessment Engine (v4.0.0) with Telemetry-Grounded Scoring
5. Evidence-Backed Content Generator (Grounded Claims Only)
6. MCP Server Tools Dispatch & Tenant Authorization
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from cryptography.fernet import Fernet

from app.core.config import settings
from app.models.models import User, Task, Commit, Event, GraphEdge, Project, Observation, Assessment
from app.services.crypto import encrypt_secret, decrypt_secret, rotate_secret, DecryptionError
from app.services.graph_engine import GraphEngine
from app.services.observation_engine import ObservationEngine, compute_evidence_hash
from app.services.assessment_engine import AssessmentEngine
from app.services.content_generator import ContentGenerator
from app.mcp.server import handle_tool_call


class TestCredentialEncryption:
    def test_encrypt_and_decrypt(self):
        secret = "ghp_super_secret_github_access_token_12345"
        cipher = encrypt_secret(secret)
        assert cipher != secret
        assert cipher.startswith("v1:")
        assert len(cipher) > len(secret)
        decrypted = decrypt_secret(cipher)
        assert decrypted == secret

    def test_empty_or_none(self):
        assert encrypt_secret(None) is None
        assert decrypt_secret(None) is None
        assert encrypt_secret("") == ""
        assert decrypt_secret("") == ""

    def test_corrupt_ciphertext_raises_decryption_error(self):
        with pytest.raises(DecryptionError):
            decrypt_secret("v1:totally_corrupted_ciphertext_that_cannot_be_decrypted")

    def test_legacy_plaintext_token_passthrough(self):
        legacy = "ghp_legacy_personal_access_token_1234"
        assert decrypt_secret(legacy) == legacy

    def test_key_rotation_and_multikey(self):
        old_key = Fernet.generate_key().decode()
        new_key = Fernet.generate_key().decode()

        # Encrypt with old_key
        with patch.object(settings, "ENCRYPTION_KEY", old_key), \
             patch.object(settings, "PREVIOUS_ENCRYPTION_KEYS", None):
            cipher_old = encrypt_secret("database_password_999")
            assert cipher_old.startswith("v1:")

        # Decrypt with new_key as primary and old_key in PREVIOUS_ENCRYPTION_KEYS
        with patch.object(settings, "ENCRYPTION_KEY", new_key), \
             patch.object(settings, "PREVIOUS_ENCRYPTION_KEYS", old_key):
            decrypted = decrypt_secret(cipher_old)
            assert decrypted == "database_password_999"

            # Re-encrypt (rotate) to new_key
            rotated = rotate_secret(cipher_old)
            assert rotated != cipher_old

        # Verify rotated ciphertext decrypts with new_key alone
        with patch.object(settings, "ENCRYPTION_KEY", new_key), \
             patch.object(settings, "PREVIOUS_ENCRYPTION_KEYS", None):
            assert decrypt_secret(rotated) == "database_password_999"


class TestEvidenceHash:
    def test_deterministic_hash(self):
        ids_1 = ["c_123", "c_456", "c_789"]
        ids_2 = ["c_789", "c_123", "c_456"]  # different order
        h1 = compute_evidence_hash(ids_1)
        h2 = compute_evidence_hash(ids_2)
        assert h1 == h2
        assert len(h1) == 64  # sha256 hex


@pytest.mark.asyncio
async def test_graph_and_correlation_logic():
    db = AsyncMock()
    db.add = MagicMock()
    engine = GraphEngine(db)
    user_id = "usr_alice"
    commit_id = "cm_001"
    commit_sha = "a1b2c3d4e5"
    commit_msg = "[TRO-11111111-2222-3333-4444-555555555555] feat: initial graph support"
    committed_at = datetime.utcnow()

    # Mock Task query to simulate explicit tag match
    mock_task = Task(id="11111111-2222-3333-4444-555555555555", user_id=user_id, goal="Build graph", target_level=3)
    mock_scalar = MagicMock()
    mock_scalar.scalar_one_or_none.return_value = mock_task

    mock_edge_scalar = MagicMock()
    mock_edge_scalar.scalar_one_or_none.return_value = None

    db.execute.side_effect = [mock_scalar, mock_edge_scalar]

    res = await engine.correlate_commit_to_task(
        user_id=user_id,
        commit_id=commit_id,
        commit_sha=commit_sha,
        commit_msg=commit_msg,
        committed_at=committed_at,
        files_modified=["app/services/graph_engine.py"],
    )

    assert res is not None
    task_id, confidence, source = res
    assert task_id == "11111111-2222-3333-4444-555555555555"
    assert confidence == 1.0
    assert source == "explicit_tag"


@pytest.mark.asyncio
async def test_assessment_engine_v4():
    db = AsyncMock()
    db.add = MagicMock()
    engine = AssessmentEngine(db)
    user_id = "usr_bob"
    task_id = "tsk_99"

    obs1 = Observation(
        id="obs_1",
        user_id=user_id,
        task_id=task_id,
        project_id="prj_1",
        window_start=datetime.utcnow() - timedelta(hours=2),
        window_end=datetime.utcnow(),
        observation_type="active_work_seconds",
        metric_value=7200.0,
        unit="seconds",
        supporting_evidence={},
        evidence_hash="hash_1",
    )
    obs2 = Observation(
        id="obs_2",
        user_id=user_id,
        task_id=task_id,
        project_id="prj_1",
        window_start=datetime.utcnow() - timedelta(hours=2),
        window_end=datetime.utcnow(),
        observation_type="commit_count",
        metric_value=4.0,
        unit="commits",
        supporting_evidence={},
        evidence_hash="hash_2",
    )
    obs3 = Observation(
        id="obs_3",
        user_id=user_id,
        task_id=task_id,
        project_id="prj_1",
        window_start=datetime.utcnow() - timedelta(hours=2),
        window_end=datetime.utcnow(),
        observation_type="code_churn_ratio",
        metric_value=0.15,
        unit="ratio",
        supporting_evidence={},
        evidence_hash="hash_3",
    )

    mock_obs = MagicMock()
    mock_obs.scalars.return_value.all.return_value = [obs1, obs2, obs3]
    db.execute.return_value = mock_obs

    assessments = await engine.generate_task_assessments(user_id=user_id, task_id=task_id)

    assert len(assessments) == 5
    dims = {a.assessment_dimension: a for a in assessments}
    assert "delivery_velocity" in dims
    assert "execution_efficiency" in dims
    assert "stability_and_reliability" in dims
    assert "ai_leverage_effectiveness" in dims
    assert "evidence_confidence_score" in dims

    for a in assessments:
        assert a.algorithm_version == "v4.0.0"
        assert 0.0 <= a.score <= 100.0
        assert 0.0 <= a.confidence <= 1.0

    # Test telemetry-grounded validation:
    # 1. Zero AI prompts should result in score 0.0 with "no_ai_interactions_detected", not 100.0
    ai_dim = dims["ai_leverage_effectiveness"]
    assert ai_dim.score == 0.0
    assert ai_dim.breakdown.get("status") == "no_ai_interactions_detected"

    # 2. Evidence confidence without IDE telemetry should be capped at 0.75
    conf_dim = dims["evidence_confidence_score"]
    assert conf_dim.score <= 75.0


@pytest.mark.asyncio
async def test_content_generator_grounded_claims():
    db = AsyncMock()
    user_id = "usr_carol"
    task = Task(
        id="task_abc",
        user_id=user_id,
        goal="Implement deterministic observations and evidence hashes",
        target_level=4,
        status="completed",
        started_at=datetime.utcnow() - timedelta(days=2),
    )
    commit = Commit(
        id="c_01",
        user_id=user_id,
        project_id="proj_1",
        task_id="task_abc",
        sha="9876543210abcdef",
        message="feat: observation pipeline",
        committed_at=datetime.utcnow(),
        lines_added=150,
        lines_deleted=10,
    )

    res_tasks = MagicMock()
    res_tasks.scalars.return_value.all.return_value = [task]

    res_commits = MagicMock()
    res_commits.scalars.return_value.all.return_value = [commit]

    res_assess = MagicMock()
    res_assess.scalars.return_value.all.return_value = []

    db.execute.side_effect = [res_tasks, res_commits, res_assess]

    generator = ContentGenerator(db)
    result = await generator.generate_linkedin_update(user_id=user_id, days=7)

    assert "post_body" in result
    post_body = result["post_body"]
    assert "[TRO-EVID-" in result["citation_tag"]
    assert result["tasks_substantiated"] == 1
    assert result["commits_substantiated"] == 1
    assert result["lines_added"] == 150
    assert "Implement deterministic observations" in post_body

    # Verification: Must strictly adhere to "Evidence before claims"
    # Never claim unmeasured properties like "100% test coverage" or "reviewed"
    assert "100% test coverage" not in post_body
    assert "reviewed" not in post_body.lower()


@pytest.mark.asyncio
async def test_mcp_server_tenant_isolation():
    # 1. Calling tool without api_key fails authorization
    resp_unauth = await handle_tool_call("get_engineering_audit", {})
    assert resp_unauth.get("authenticated") is False
    assert "Authentication failed" in resp_unauth.get("error", "")

    # 2. Calling with invalid api_key fails authorization
    with patch("app.mcp.server.AsyncSessionLocal") as mock_session:
        db_mock = AsyncMock()
        mock_session.return_value.__aenter__.return_value = db_mock

        # User lookup returns None
        mock_res = MagicMock()
        mock_res.scalar_one_or_none.return_value = None
        db_mock.execute.return_value = mock_res

        resp_invalid = await handle_tool_call("get_engineering_audit", {"api_key": "invalid_key"})
        assert resp_invalid.get("authenticated") is False

    # 3. Calling with valid tenant credentials resolves scoped tenant data
    with patch("app.mcp.server.AsyncSessionLocal") as mock_session:
        db_mock = AsyncMock()
        mock_session.return_value.__aenter__.return_value = db_mock

        test_user = User(id="usr_alice", email="alice@example.com", name="Alice")
        
        # 1. UserSession lookup returns None
        mock_session_res = MagicMock()
        mock_session_res.scalar_one_or_none.return_value = None

        # 2. User lookup by ID returns test_user
        mock_user_res = MagicMock()
        mock_user_res.scalar_one_or_none.return_value = test_user

        # 3. Tasks lookup
        mock_tasks_res = MagicMock()
        mock_tasks_res.scalars.return_value.all.return_value = [
            Task(id="t1", user_id="usr_alice", goal="Isolation test", status="completed")
        ]

        # 4. Commits lookup
        mock_commits_res = MagicMock()
        mock_commits_res.scalars.return_value.all.return_value = [
            Commit(id="c1", user_id="usr_alice", sha="abc1234", message="feat: isolation")
        ]

        # Sequence of execute calls: UserSession -> User -> Tasks -> Commits
        db_mock.execute.side_effect = [mock_session_res, mock_user_res, mock_tasks_res, mock_commits_res]

        resp_auth = await handle_tool_call("get_engineering_audit", {"api_key": "usr_alice"})
        assert resp_auth.get("tenant_id") == "usr_alice"
        assert resp_auth.get("total_tasks") == 1
        assert resp_auth.get("completed_tasks") == 1
        assert resp_auth.get("total_commits") == 1
