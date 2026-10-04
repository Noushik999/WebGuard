"""Auth endpoints: register / login / me."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..audit import audit
from ..config import get_settings
from ..db import get_db
from ..deps import get_current_user, rate_limit
from ..security import create_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _user_out(u: models.User) -> schemas.UserOut:
    return schemas.UserOut(id=u.id, email=u.email, is_admin=u.is_admin, created_at=u.created_at)


@router.post("/register", response_model=schemas.TokenOut)
def register(body: schemas.RegisterIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(request, per_minute=10)
    email = body.email.strip().lower()
    if "@" not in email:
        raise HTTPException(400, "Invalid email address")
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(400, "An account with this email already exists")
    try:
        pw_hash = hash_password(body.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = models.User(email=email, password_hash=pw_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit(db, "user.register", user_id=user.id, email=email)
    db.commit()
    token = create_token(user.id, get_settings().SECRET_KEY, get_settings().JWT_EXPIRY_HOURS)
    return schemas.TokenOut(access_token=token, user=_user_out(user))


@router.post("/login", response_model=schemas.TokenOut)
def login(body: schemas.LoginIn, request: Request, db: Session = Depends(get_db)):
    rate_limit(request, per_minute=10)
    email = body.email.strip().lower()
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    audit(db, "user.login", user_id=user.id)
    db.commit()
    token = create_token(user.id, get_settings().SECRET_KEY, get_settings().JWT_EXPIRY_HOURS)
    return schemas.TokenOut(access_token=token, user=_user_out(user))


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return _user_out(user)
