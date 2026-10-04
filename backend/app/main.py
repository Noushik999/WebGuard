"""WebGuard API — FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import models
from .api import assessments, auth, dashboard, demo, findings, reports, targets
from .audit import audit
from .config import get_settings
from .db import SessionLocal, engine
from .security import hash_password
from .worker import run_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    models.Base.metadata.create_all(engine)

    # Bootstrap the default admin on first run.
    db = SessionLocal()
    try:
        if db.query(models.User).count() == 0:
            admin = models.User(
                email=settings.ADMIN_EMAIL.lower(),
                password_hash=hash_password(settings.ADMIN_PASSWORD),
                is_admin=True,
            )
            db.add(admin)
            db.commit()
            audit(db, "user.bootstrap_admin", user_id=admin.id, email=admin.email)
            db.commit()
    finally:
        db.close()

    app.state.cancel_events = {}
    app.state.worker_stop = threading.Event()
    worker_task = asyncio.create_task(run_worker(app.state.cancel_events, app.state.worker_stop))
    yield
    app.state.worker_stop.set()
    worker_task.cancel()


app = FastAPI(title="WebGuard", version="1.0.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # HSTS only makes sense when served over TLS; harmless otherwise.
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=[get_settings().FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    # Never leak stack traces to API consumers; log server-side.
    import logging
    logging.getLogger("webguard").exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/api/health")
def health():
    return {"ok": True, "service": "webguard", "version": "1.0.0"}


app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(assessments.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(demo.router)
