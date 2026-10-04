"""Authentication primitives.

Deliberately dependency-free (stdlib only):
- Passwords: PBKDF2-HMAC-SHA256, 600k iterations, per-user 16-byte salt.
- Sessions: JWT signed with HS256 (HMAC-SHA256) via the app SECRET_KEY.

This is auditable, has no native-extension risk, and is more than adequate for
the MVP threat model. See SECURITY.md.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

_PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    if len(password.encode()) < 8:
        raise ValueError("Password must be at least 8 characters")
    if len(password.encode()) > 128:
        raise ValueError("Password too long")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass
class TokenPayload:
    sub: str  # user id
    exp: int


def create_token(user_id: int, secret: str, expiry_hours: int = 24) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(
        json.dumps({"sub": str(user_id), "exp": int(time.time()) + expiry_hours * 3600}).encode()
    )
    sig = _b64url(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str, secret: str) -> TokenPayload | None:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        expected = _b64url(
            hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, sig_b64):
            return None
        payload = json.loads(_b64url_decode(payload_b64))
        if payload.get("exp", 0) < time.time():
            return None
        return TokenPayload(sub=str(payload["sub"]), exp=int(payload["exp"]))
    except Exception:
        return None
