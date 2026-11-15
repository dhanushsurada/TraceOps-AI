"""
TraceOps AI — Cryptographic Services
Provides envelope encryption for access tokens, refresh tokens, and sensitive integration credentials.
"""
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet
from app.core.config import settings

def _get_fernet_key() -> bytes:
    # Derive a valid 32-byte urlsafe base64 key from settings.SECRET_KEY
    key_material = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return base64.urlsafe_b64encode(key_material)

def encrypt_secret(plain_text: Optional[str]) -> Optional[str]:
    """Encrypt plaintext string with Fernet (AES-128-CBC + HMAC)."""
    if not plain_text:
        return plain_text
    f = Fernet(_get_fernet_key())
    return f.encrypt(plain_text.encode()).decode()

def decrypt_secret(cipher_text: Optional[str]) -> Optional[str]:
    """Decrypt Fernet ciphertext back to plaintext."""
    if not cipher_text:
        return cipher_text
    try:
        f = Fernet(_get_fernet_key())
        return f.decrypt(cipher_text.encode()).decode()
    except Exception:
        # Fallback if text was stored unencrypted before migration
        return cipher_text
