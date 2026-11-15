"""
Auth Service

Handles:
- Session creation/validation/deletion
- User upsert from OAuth provider data
- Secure session token generation
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.models import User, UserSession, ApiKey


def _now() -> datetime:
    return datetime.now(timezone.utc)


def generate_session_token() -> str:
    """Cryptographically secure session token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Store hashed version in DB — never raw token."""
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(
    db: AsyncSession,
    user_id: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """Create a new session. Returns the raw session token (send to client)."""
    raw_token = generate_session_token()
    hashed    = hash_token(raw_token)
    expires   = _now() + timedelta(days=settings.SESSION_EXPIRE_DAYS)

    session = UserSession(
        user_id=user_id,
        session_token=hashed,
        expires_at=expires,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    await db.flush()
    return raw_token


async def get_user_from_session(
    db: AsyncSession,
    raw_token: str,
) -> Optional[User]:
    """Validate session token and return the User. Returns None if invalid/expired."""
    if not raw_token:
        return None
    hashed = hash_token(raw_token)
    result = await db.execute(
        select(UserSession)
        .where(UserSession.session_token == hashed)
        .where(UserSession.expires_at > _now())
    )
    session = result.scalar_one_or_none()
    if not session:
        return None
    result2 = await db.execute(select(User).where(User.id == session.user_id, User.is_active == True))
    return result2.scalar_one_or_none()


async def delete_session(db: AsyncSession, raw_token: str) -> bool:
    """Logout — delete session by raw token."""
    hashed = hash_token(raw_token)
    result = await db.execute(select(UserSession).where(UserSession.session_token == hashed))
    session = result.scalar_one_or_none()
    if session:
        await db.delete(session)
        return True
    return False


async def create_api_key(
    db: AsyncSession,
    user_id: str,
    name: str = "Default Key",
    scopes: str = "read,write,mcp",
    expires_in_days: Optional[int] = 365,
) -> Tuple[str, ApiKey]:
    """
    Generate a cryptographically secure, scoped API key.
    Returns (raw_key, api_key_record). Only the hash is persisted in the database.
    """
    raw_key = f"tro_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    expires_at = _now() + timedelta(days=expires_in_days) if expires_in_days else None

    api_key = ApiKey(
        user_id=user_id,
        name=name,
        key_prefix="tro_live_",
        key_hash=key_hash,
        scopes=scopes,
        revoked=False,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.flush()
    return raw_key, api_key


async def verify_api_key(
    db: AsyncSession,
    raw_key: str,
    required_scope: Optional[str] = None,
) -> Optional[User]:
    """
    Verify API key hash, revocation status, expiration, and scope.
    Updates last_used_at on successful verification.
    """
    if not raw_key or not isinstance(raw_key, str) or not raw_key.startswith("tro_"):
        return None

    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    now = _now()

    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked == False)
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        return None

    if api_key.expires_at:
        exp = api_key.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            return None

    if required_scope:
        allowed_scopes = [s.strip() for s in api_key.scopes.split(",") if s.strip()]
        if required_scope not in allowed_scopes and "*" not in allowed_scopes:
            return None

    # Fetch active user
    u_res = await db.execute(select(User).where(User.id == api_key.user_id, User.is_active == True))
    user = u_res.scalar_one_or_none()
    if not user:
        return None

    api_key.last_used_at = now
    await db.flush()
    return user


async def revoke_api_key(db: AsyncSession, user_id: str, key_id: str) -> bool:
    """Revoke an API key belonging to a tenant."""
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user_id)
    result = await db.execute(stmt)
    api_key = result.scalar_one_or_none()
    if api_key:
        api_key.revoked = True
        await db.flush()
        return True
    return False


async def upsert_github_user(
    db: AsyncSession,
    github_id: str,
    email: str,
    name: Optional[str],
    avatar_url: Optional[str],
    username: Optional[str],
) -> User:
    """Create or update user from GitHub OAuth data."""
    # Try by github_id first
    result = await db.execute(select(User).where(User.github_id == str(github_id)))
    user = result.scalar_one_or_none()

    if not user and email:
        # Try by email (might have signed in with Google before)
        result2 = await db.execute(select(User).where(User.email == email))
        user = result2.scalar_one_or_none()

    if user:
        user.github_id       = str(github_id)
        user.github_username = username
        if name:       user.name       = name
        if avatar_url: user.avatar_url = avatar_url
    else:
        user = User(
            email=email or f"github_{github_id}@traceops.local",
            name=name,
            avatar_url=avatar_url,
            github_id=str(github_id),
            github_username=username,
        )
        db.add(user)

    await db.flush()
    return user


async def upsert_google_user(
    db: AsyncSession,
    google_id: str,
    email: str,
    name: Optional[str],
    avatar_url: Optional[str],
) -> User:
    """Create or update user from Google OAuth data."""
    result = await db.execute(select(User).where(User.google_id == google_id))
    user = result.scalar_one_or_none()

    if not user and email:
        result2 = await db.execute(select(User).where(User.email == email))
        user = result2.scalar_one_or_none()

    if user:
        user.google_id = google_id
        if name:       user.name       = name
        if avatar_url: user.avatar_url = avatar_url
    else:
        user = User(
            email=email,
            name=name,
            avatar_url=avatar_url,
            google_id=google_id,
        )
        db.add(user)

    await db.flush()
    return user
