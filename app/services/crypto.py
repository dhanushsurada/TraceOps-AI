"""
TraceOps AI — Cryptographic Services & Key Management

Provides authenticated encryption (Fernet / AES-128-CBC + HMAC-SHA256) for
sensitive integration tokens with:
- Dedicated key management and key rotation (MultiFernet)
- Versioned ciphertext envelope format (v1:<token>)
- Strict failure handling (raising DecryptionError rather than silent return)
- Controlled backward-compatible legacy token migration path
"""
import base64
import hashlib
import logging
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import settings

log = logging.getLogger("traceops.crypto")

CIPHERTEXT_VERSION_PREFIX = "v1:"


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class DecryptionError(CryptoError):
    """Raised when ciphertext cannot be decrypted by active or rotated keys."""
    pass


def _get_active_fernets() -> MultiFernet:
    """
    Construct MultiFernet instance using primary key and any configured rotation keys.
    Primary key is always first (used for encryption).
    Raises CryptoError if no valid ENCRYPTION_KEY is configured. Never falls back to SECRET_KEY.
    """
    keys: List[bytes] = []

    # 1. Primary key - dedicated independent Fernet key
    if settings.ENCRYPTION_KEY and settings.ENCRYPTION_KEY.strip():
        try:
            k = settings.ENCRYPTION_KEY.encode().strip()
            Fernet(k)
            keys.append(k)
        except Exception as e:
            raise CryptoError(f"Configured ENCRYPTION_KEY is invalid: {e}")
    else:
        raise CryptoError(
            "ENCRYPTION_KEY is not configured. A separately managed 32-byte Fernet key is required. "
            "Silent fallback to SECRET_KEY is forbidden."
        )

    # 2. Previous keys for seamless rotation
    if settings.PREVIOUS_ENCRYPTION_KEYS and settings.PREVIOUS_ENCRYPTION_KEYS.strip():
        for prev in settings.PREVIOUS_ENCRYPTION_KEYS.split(","):
            prev_clean = prev.strip().encode()
            if prev_clean:
                try:
                    Fernet(prev_clean)
                    keys.append(prev_clean)
                except Exception as e:
                    raise CryptoError(f"Invalid rotation key in PREVIOUS_ENCRYPTION_KEYS: {e}")

    fernet_instances = [Fernet(k) for k in keys]
    return MultiFernet(fernet_instances)


def encrypt_secret(plain_text: Optional[str]) -> Optional[str]:
    """
    Encrypt plaintext string into versioned envelope (v1:<token>).
    Returns None if input is None.
    """
    if plain_text is None:
        return None
    if plain_text == "":
        return ""

    mf = _get_active_fernets()
    encrypted_bytes = mf.encrypt(plain_text.encode("utf-8"))
    return f"{CIPHERTEXT_VERSION_PREFIX}{encrypted_bytes.decode('utf-8')}"


def decrypt_secret(cipher_text: Optional[str]) -> Optional[str]:
    """
    Decrypt versioned envelope back to plaintext string.
    - If versioned (v1:...): decrypts using MultiFernet (primary or rotated keys).
      Raises DecryptionError on corruption or invalid keys.
    - If unversioned: detects legacy plaintext, logs migration notice, returns string.
    """
    if cipher_text is None:
        return None
    if cipher_text == "":
        return ""

    if cipher_text.startswith(CIPHERTEXT_VERSION_PREFIX):
        raw_token = cipher_text[len(CIPHERTEXT_VERSION_PREFIX):].encode("utf-8")
        mf = _get_active_fernets()
        try:
            decrypted = mf.decrypt(raw_token)
            return decrypted.decode("utf-8")
        except (InvalidToken, Exception) as exc:
            log.error("Failed to decrypt secret with current and previous keys.")
            raise DecryptionError("Ciphertext is corrupted or encrypted with unknown key.") from exc

    # Unversioned legacy token check
    # Check if this resembles a legacy plaintext provider token
    if any(cipher_text.startswith(prefix) for prefix in ("ghp_", "gho_", "ghu_", "sk-", "sec_")) or len(cipher_text) < 128:
        log.warning("Reading unencrypted legacy token; should be re-saved to encrypt.")
        return cipher_text

    # If it is long and unversioned, try bare fernet decryption
    try:
        mf = _get_active_fernets()
        decrypted = mf.decrypt(cipher_text.encode("utf-8"))
        return decrypted.decode("utf-8")
    except Exception:
        raise DecryptionError("Unversioned ciphertext failed decryption and does not match known plaintext patterns.")


def rotate_secret(cipher_text: Optional[str]) -> Optional[str]:
    """
    Re-encrypt an existing ciphertext using the current primary key.
    Useful during key rotation routines.
    """
    if not cipher_text:
        return cipher_text
    plain = decrypt_secret(cipher_text)
    return encrypt_secret(plain)
