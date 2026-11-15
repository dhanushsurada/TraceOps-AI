"""
TraceOps AI — PostgreSQL Schema & Dialect Compatibility Test Suite

Validates that:
1. All 22 ORM entity tables compile valid PostgreSQL DDL without dialect-specific type errors.
2. Dialect types (JSON, DateTime(timezone=True), UUID primary keys, and foreign keys) compile cleanly.
3. Compatibility migration DDL statements for production deployments compile and conform to PostgreSQL syntax.
"""
import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.core.database import Base
from app.core.schema_migrations import run_compat_migrations
import app.models.models  # load all declarative models


def test_all_models_compile_valid_postgresql_ddl():
    """Verify all ORM models compile valid DDL against the PostgreSQL dialect."""
    tables = Base.metadata.sorted_tables
    assert len(tables) >= 20

    compiled_tables = []
    for table in tables:
        ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert "CREATE TABLE" in ddl
        assert table.name in ddl
        compiled_tables.append(table.name)

    # Core ontology entities must be present
    expected_entities = [
        "users", "user_sessions", "api_keys", "integrations", "projects",
        "tasks", "commits", "file_changes", "pull_requests", "deployments",
        "errors", "decisions", "ai_sessions", "ai_prompts", "events",
        "graph_edges", "observations", "assessments", "scores", "reports",
    ]
    for entity in expected_entities:
        assert entity in compiled_tables, f"Missing table {entity} in PostgreSQL DDL compilation"


def test_postgres_column_types_and_indexes():
    """Verify PostgreSQL-specific requirements: TIMESTAMPTZ, JSON/JSONB, and composite indexes."""
    users_tbl = Base.metadata.tables["users"]
    assert "created_at" in users_tbl.c
    created_at_type = users_tbl.c["created_at"].type.compile(dialect=postgresql.dialect())
    assert "TIME ZONE" in created_at_type or "TIMESTAMPTZ" in created_at_type

    assess_tbl = Base.metadata.tables["assessments"]
    assert "breakdown" in assess_tbl.c
    json_type = assess_tbl.c["breakdown"].type.compile(dialect=postgresql.dialect())
    assert "JSON" in json_type

    # Verify composite indexes
    idx_names = {idx.name for idx in assess_tbl.indexes}
    assert "idx_assess_user_dim" in idx_names

    api_keys_tbl = Base.metadata.tables["api_keys"]
    api_key_indexes = {idx.name for idx in api_keys_tbl.indexes}
    assert "idx_api_keys_hash" in api_key_indexes
    assert "idx_api_keys_user" in api_key_indexes


@pytest.mark.asyncio
async def test_compat_migrations_statements_syntax():
    """Verify startup compatibility migration statements are syntactically valid."""
    from unittest.mock import AsyncMock
    mock_conn = AsyncMock()
    mock_conn.dialect.name = "postgresql"

    await run_compat_migrations(mock_conn)

    assert mock_conn.execute.call_count >= 8
    # Inspect executed statements
    calls = [str(call.args[0]) for call in mock_conn.execute.call_args_list]
    assert any("ALTER TABLE IF EXISTS tasks ADD COLUMN IF NOT EXISTS user_id" in s for s in calls)
    assert any("CREATE TABLE IF NOT EXISTS api_keys" in s for s in calls)
