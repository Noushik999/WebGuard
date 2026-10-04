"""Shared FastAPI dependencies: auth + rate limiting."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .config import get_settings
from .db import get_db
from .security import verify_token

_bearer = HTTPBearer(auto_error=False)

# Simple in-memory sliding-window rate limiter (per process; fine for MVP).
_hits: dict[str, deque[float]] = defaultdict(deque)


def rate_limit(request: Request, per_minute: int | None = None):
    settings = get_settings()
    limit = per_minute or settings.RATE_LIMIT_PER_MINUTE
    key = request.client.host if request.client else "unknown"
    now = time.time()
    window = _hits[key]
    while window and window[0] < now - 60:
        window.popleft()
    if len(window) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please slow down.")
    window.append(now)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = verify_token(credentials.credentials, get_settings().SECRET_KEY)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = db.get(models.User, int(payload.sub))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user
