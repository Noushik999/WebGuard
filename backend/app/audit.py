"""Audit logging helper. Never logs secrets."""

from __future__ import annotations

from sqlalchemy.orm import Session

from . import models


def audit(db: Session, action: str, user_id: int | None = None, **details):
    # Defensive: strip anything that looks secret.
    safe = {}
    for k, v in details.items():
        kl = k.lower()
        if any(s in kl for s in ("password", "token", "secret", "key", "cookie")):
            continue
        safe[k] = v
    db.add(models.AuditLog(user_id=user_id, action=action, details=safe))
