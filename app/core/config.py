from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

# Fixed dev-only Fernet key for local development and unit tests.
# IN PRODUCTION: ENCRYPTION_KEY is mandatory via environment and MUST NOT equal this dev key.
DEV_ENCRYPTION_KEY: str = "Dpp6wUH0A8PCQ3VvMA9qSwnS3z7rqa5h2AmrnDdwVAA="
DEV_WEBHOOK_SECRET: str = "dev_github_webhook_secret_32bytes_min"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://traceops_user:traceops_pass@localhost:5432/traceops_db"
    SYNC_DATABASE_URL: str = "postgresql://traceops_user:traceops_pass@localhost:5432/traceops_db"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # AI Providers
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # LLM Analyzer
    LLM_PROVIDER: str = "openai"
    LLM_MODEL: str = "gpt-4o"

    # Loop Detection
    EMBEDDING_SIMILARITY_THRESHOLD: float = 0.85
    LOOP_MIN_OCCURRENCES: int = 3

    # Scoring
    VELOCITY_FAST_THRESHOLD_HOURS: int = 3
    VELOCITY_MED_THRESHOLD_HOURS: int = 6

    # App
    APP_ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production"
    LOG_LEVEL: str = "INFO"

    # OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    FRONTEND_URL: str = "https://traceops-ai.onrender.com"
    SESSION_EXPIRE_DAYS: int = 30

    # Integration Webhooks (Dedicated Secret - Fallback to SECRET_KEY is forbidden)
    GITHUB_WEBHOOK_SECRET: str = DEV_WEBHOOK_SECRET

    # Encryption & Key Management (Dedicated Key - Fallback to SECRET_KEY is forbidden)
    ENCRYPTION_KEY: str = DEV_ENCRYPTION_KEY
    PREVIOUS_ENCRYPTION_KEYS: str = ""          # Comma-separated previous keys for rotation

    # MCP Server Service Account Configuration
    TRACEOPS_API_KEY: str = ""
    TRACEOPS_SERVICE_TENANT_ID: str = ""        # Mandatory if TRACEOPS_API_KEY is configured


settings = Settings()


def validate_security_configuration(s: Settings = settings) -> None:
    """
    Validate platform security configuration.
    Fails startup immediately if any production security invariant is violated.
    """
    from cryptography.fernet import Fernet

    if s.APP_ENV == "production":
        # 1. SECRET_KEY validation
        if not s.SECRET_KEY or s.SECRET_KEY in ("change-me-in-production", "secret", "default") or len(s.SECRET_KEY) < 32:
            raise RuntimeError(
                "Production startup failed: Insecure SECRET_KEY. "
                "Must be a dedicated, cryptographically strong random secret of at least 32 characters."
            )

        # 2. ENCRYPTION_KEY validation (mandatory independent key; no fallback to SECRET_KEY permitted)
        if not s.ENCRYPTION_KEY or not s.ENCRYPTION_KEY.strip():
            raise RuntimeError(
                "Production startup failed: ENCRYPTION_KEY is mandatory. "
                "Silent fallback to SECRET_KEY is forbidden. Provide a separately managed 32-byte urlsafe base64 Fernet key."
            )
        if s.ENCRYPTION_KEY == DEV_ENCRYPTION_KEY:
            raise RuntimeError(
                "Production startup failed: ENCRYPTION_KEY cannot use the default development key. "
                "In Render Dashboard -> Environment, set ENCRYPTION_KEY to a dedicated Fernet key (e.g. cOOe1mO4arWvmsu8yf2a7aeAQkkTEgq8LQtlDydLA5U=)."
            )
        try:
            from app.services.crypto import normalize_fernet_key
            norm_key = normalize_fernet_key(s.ENCRYPTION_KEY)
            Fernet(norm_key)
        except Exception as e:
            raise RuntimeError(
                f"Production startup failed: ENCRYPTION_KEY is invalid: {e}. Must be at least 32 characters or a valid Fernet key."
            )

        # 3. Dedicated GITHUB_WEBHOOK_SECRET validation
        if not s.GITHUB_WEBHOOK_SECRET or not s.GITHUB_WEBHOOK_SECRET.strip():
            raise RuntimeError(
                "Production startup failed: GITHUB_WEBHOOK_SECRET is mandatory for GitHub webhook ingestion. "
                "Falling back to SECRET_KEY is forbidden."
            )
        if s.GITHUB_WEBHOOK_SECRET == DEV_WEBHOOK_SECRET:
            raise RuntimeError(
                "Production startup failed: GITHUB_WEBHOOK_SECRET cannot use the default development secret. "
                "In Render Dashboard -> Environment, set GITHUB_WEBHOOK_SECRET to a dedicated secret (e.g. 0a95b030b9b00fd899bd41a35ae1693ca0ff113d9774c11f89a15f3563dfd3d1)."
            )
        if s.GITHUB_WEBHOOK_SECRET == s.SECRET_KEY:
            raise RuntimeError(
                "Production startup failed: GITHUB_WEBHOOK_SECRET must be distinct from SECRET_KEY. "
                "Secret separation is mandatory."
            )

        # 4. Service Account Key validation
        if s.TRACEOPS_API_KEY and not s.TRACEOPS_SERVICE_TENANT_ID:
            raise RuntimeError(
                "Production startup failed: TRACEOPS_API_KEY requires an explicit TRACEOPS_SERVICE_TENANT_ID."
            )

    # In any environment: if ENCRYPTION_KEY is configured, it must be valid Fernet
    if s.ENCRYPTION_KEY and s.ENCRYPTION_KEY.strip():
        try:
            Fernet(s.ENCRYPTION_KEY.encode().strip())
        except Exception as e:
            raise ValueError(f"Configured ENCRYPTION_KEY is invalid: {e}")

    # Validate rotation keys if configured
    if s.PREVIOUS_ENCRYPTION_KEYS and s.PREVIOUS_ENCRYPTION_KEYS.strip():
        for prev in s.PREVIOUS_ENCRYPTION_KEYS.split(","):
            prev_clean = prev.strip().encode()
            if prev_clean:
                try:
                    Fernet(prev_clean)
                except Exception as e:
                    raise ValueError(f"Invalid rotation key in PREVIOUS_ENCRYPTION_KEYS: {e}")
