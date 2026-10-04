"""Target management. Authorization confirmation is REQUIRED to create a target."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from scanner.target_validator import TargetValidationError, validate_target
from .. import models, schemas
from ..audit import audit
from ..config import get_settings
from ..db import get_db
from ..deps import get_current_user, rate_limit

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _out(t: models.Target, db: Session) -> schemas.TargetOut:
    count = db.query(models.Assessment).filter(models.Assessment.target_id == t.id).count()
    latest = (
        db.query(models.Assessment)
        .filter(models.Assessment.target_id == t.id, models.Assessment.status == "COMPLETED")
        .order_by(models.Assessment.created_at.desc())
        .first()
    )
    return schemas.TargetOut(
        id=t.id, name=t.name, url=t.url, description=t.description, scope=t.scope,
        auth_confirmed=t.auth_confirmed, auth_confirmed_at=t.auth_confirmed_at,
        is_demo=t.is_demo, created_at=t.created_at,
        assessment_count=count, latest_score=latest.score if latest else None,
    )


@router.post("", response_model=schemas.TargetOut)
def create_target(
    body: schemas.TargetIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rate_limit(request)
    # Validate the URL up front (SSRF rules) so bad targets fail fast.
    try:
        normalized = validate_target(
            body.url, allow_private_networks=get_settings().ALLOW_PRIVATE_NETWORKS
        )
    except TargetValidationError as e:
        raise HTTPException(400, f"Invalid target: {e}")

    # Duplicate protection per user.
    existing = (
        db.query(models.Target)
        .filter(models.Target.user_id == user.id, models.Target.url == normalized)
        .first()
    )
    if existing:
        raise HTTPException(409, "This target is already in your list")

    t = models.Target(
        user_id=user.id,
        name=body.name.strip(),
        url=normalized,
        description=body.description.strip(),
        scope=body.scope.strip(),
        auth_confirmed=True,
        auth_confirmed_at=datetime.now(timezone.utc),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    audit(db, "target.created", user_id=user.id, target_id=t.id, url=t.url)
    db.commit()
    return _out(t, db)


@router.get("", response_model=list[schemas.TargetOut])
def list_targets(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    targets = (
        db.query(models.Target)
        .filter(models.Target.user_id == user.id)
        .order_by(models.Target.created_at.desc())
        .all()
    )
    return [_out(t, db) for t in targets]


@router.get("/{target_id}", response_model=schemas.TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    t = db.query(models.Target).filter(
        models.Target.id == target_id, models.Target.user_id == user.id
    ).first()
    if not t:
        raise HTTPException(404, "Target not found")
    return _out(t, db)


@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    t = db.query(models.Target).filter(
        models.Target.id == target_id, models.Target.user_id == user.id
    ).first()
    if not t:
        raise HTTPException(404, "Target not found")
    audit(db, "target.deleted", user_id=user.id, target_id=t.id, url=t.url)
    db.delete(t)
    db.commit()
    return {"ok": True}
