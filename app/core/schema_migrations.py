"""Small startup migrations for deployments without Alembic history."""
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection


async def run_compat_migrations(conn: AsyncConnection) -> None:
    """Bring older TraceOps databases up to the current ORM shape.

    ``Base.metadata.create_all`` creates missing tables, but it does not add
    columns to tables that already exist. Render's persistent Postgres keeps
    those old tables between deploys, so we patch nullable user-scoping columns
    in place before the app starts serving requests.
    """
    if conn.dialect.name != "postgresql":
        return

    statements = [
        "ALTER TABLE IF EXISTS tasks ADD COLUMN IF NOT EXISTS user_id VARCHAR",
        "ALTER TABLE IF EXISTS events ADD COLUMN IF NOT EXISTS user_id VARCHAR",
        "ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS user_id VARCHAR",
        "ALTER TABLE IF EXISTS ai_proxy_logs ADD COLUMN IF NOT EXISTS user_id VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_tasks_user_id ON tasks (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_events_user_id ON events (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_reports_user_id ON reports (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_ai_proxy_logs_user_id ON ai_proxy_logs (user_id)",
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id VARCHAR PRIMARY KEY,
            user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(128) DEFAULT 'Default Key',
            key_prefix VARCHAR(16) NOT NULL,
            key_hash VARCHAR(64) UNIQUE NOT NULL,
            scopes VARCHAR(256) DEFAULT 'read,write,mcp',
            revoked BOOLEAN DEFAULT FALSE,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_used_at TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash)",
        "CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id)",
    ]
    for statement in statements:
        await conn.execute(text(statement))
