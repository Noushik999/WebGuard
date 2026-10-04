"""In-process assessment worker.

MVP decision (documented in ARCHITECTURE.md): instead of Celery/Redis, a single
asyncio task polls the DB for QUEUED assessments and runs the scanner engine in
a worker thread. Jobs are durable (DB-backed): a restart re-queues them.

Job lifecycle: QUEUED -> VALIDATING -> RUNNING -> ANALYZING -> GENERATING_RESULTS
             -> COMPLETED | FAILED | CANCELLED
"""

from __future__ import annotations

import asyncio
import threading
import time
import traceback
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from scanner import engine as scan_engine
from scanner.schemas import Finding as ScannerFinding
from . import models
from .audit import audit
from .config import get_settings
from .db import SessionLocal

POLL_SECONDS = 2.0

STATUS_MAP = {
    "VALIDATING": "VALIDATING",
    "COLLECTING": "VALIDATING",
    "RUNNING": "RUNNING",
    "ANALYZING": "ANALYZING",
    "GENERATING_RESULTS": "GENERATING_RESULTS",
}


class ScanCancelled(Exception):
    pass


def _run_one(assessment_id: int, cancel_event: threading.Event):
    settings = get_settings()
    db: Session = SessionLocal()
    try:
        asm = db.get(models.Assessment, assessment_id)
        if asm is None or asm.status != "QUEUED":
            return
        target = db.get(models.Target, asm.target_id)
        if target is None:
            asm.status = "FAILED"
            asm.error = "Target no longer exists."
            db.commit()
            return

        asm.status = "VALIDATING"
        asm.started_at = datetime.now(timezone.utc)
        asm.config = {**(asm.config or {}),
                      "allow_private_networks": settings.ALLOW_PRIVATE_NETWORKS,
                      "request_timeout": settings.SCAN_REQUEST_TIMEOUT,
                      "max_requests": settings.SCAN_MAX_REQUESTS}
        db.commit()
        audit(db, "assessment.started", user_id=asm.user_id,
              assessment_id=asm.id, target_id=target.id, url=target.url)
        db.commit()

        def progress(stage: str, pct: int):
            if cancel_event.is_set():
                raise ScanCancelled()
            # Fresh short-lived session for thread safety.
            s = SessionLocal()
            try:
                a = s.get(models.Assessment, assessment_id)
                if a:
                    mapped = STATUS_MAP.get(stage, a.status)
                    if a.status != "CANCELLED":
                        a.status = mapped
                        a.current_stage = stage
                        a.progress = pct
                        s.commit()
            finally:
                s.close()

        def stop_check() -> bool:
            return cancel_event.is_set()

        try:
            result = scan_engine.run_assessment(
                target.url,
                allow_private_networks=settings.ALLOW_PRIVATE_NETWORKS,
                request_timeout=settings.SCAN_REQUEST_TIMEOUT,
                max_requests=settings.SCAN_MAX_REQUESTS,
                user_agent=settings.SCAN_USER_AGENT,
                progress=progress,
                stop_check=stop_check,
            )
        except (ScanCancelled, scan_engine.ScanCancelledByUser):
            raise ScanCancelled()
        except Exception as e:
            asm.status = "FAILED"
            asm.error = f"{type(e).__name__}: {str(e)[:300]}"
            asm.finished_at = datetime.now(timezone.utc)
            db.commit()
            audit(db, "assessment.failed", user_id=asm.user_id,
                  assessment_id=asm.id, error=asm.error)
            db.commit()
            return

        # Persist findings
        for f in result.findings:
            db.add(models.FindingInstance(
                assessment_id=asm.id,
                fingerprint=f.fingerprint,
                title=f.title[:512],
                category=f.category,
                owasp_mapping=f.owasp_mapping,
                severity=f.severity,
                confidence=f.confidence,
                description=f.description,
                why_it_matters=f.why_it_matters,
                evidence=f.evidence[:8000],
                recommendation=f.recommendation,
                verification=f.verification,
                references=list(f.references)[:10],
                affected_url=f.affected_url[:2048],
                scanner=f.scanner,
                detected_at=f.detected_at,
            ))
        asm.status = "COMPLETED"
        asm.progress = 100
        asm.current_stage = "COMPLETED"
        asm.score = result.score
        asm.findings_count = len(result.findings)
        asm.severity_counts = result.severity_counts
        asm.config = {
            **asm.config,
            "score_breakdown": result.score_breakdown,
            "grade": result.grade,
            "module_errors": result.module_errors,
            "stats": result.stats,
        }
        asm.finished_at = datetime.now(timezone.utc)
        if asm.started_at:
            asm.duration_s = (asm.finished_at - asm.started_at).total_seconds()
        db.commit()
        audit(db, "assessment.completed", user_id=asm.user_id,
              assessment_id=asm.id, score=result.score,
              findings=len(result.findings))
        db.commit()
    except ScanCancelled:
        db.rollback()
        asm = db.get(models.Assessment, assessment_id)
        if asm:
            asm.status = "CANCELLED"
            asm.finished_at = datetime.now(timezone.utc)
            db.commit()
            audit(db, "assessment.cancelled", user_id=asm.user_id, assessment_id=asm.id)
            db.commit()
    except Exception:
        db.rollback()
        try:
            asm = db.get(models.Assessment, assessment_id)
            if asm:
                asm.status = "FAILED"
                asm.error = "Worker error: " + traceback.format_exc(limit=3)[-300:]
                asm.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


async def _worker_loop(cancel_events: dict[int, threading.Event], stop: threading.Event):
    settings = get_settings()
    overall_timeout = settings.SCAN_TIMEOUT_SECONDS + 60
    while not stop.is_set():
        db: Session = SessionLocal()
        try:
            asm = (
                db.query(models.Assessment)
                .filter(models.Assessment.status == "QUEUED")
                .order_by(models.Assessment.created_at.asc())
                .first()
            )
            asm_id = asm.id if asm else None
        finally:
            db.close()

        if asm_id is not None:
            cancel_events[asm_id] = threading.Event()
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(_run_one, asm_id, cancel_events[asm_id]),
                    timeout=overall_timeout,
                )
            except asyncio.TimeoutError:
                cancel_events[asm_id].set()
                db2: Session = SessionLocal()
                try:
                    a = db2.get(models.Assessment, asm_id)
                    if a and a.status not in ("COMPLETED", "FAILED", "CANCELLED"):
                        a.status = "FAILED"
                        a.error = f"Assessment exceeded the {settings.SCAN_TIMEOUT_SECONDS}s time budget."
                        a.finished_at = datetime.now(timezone.utc)
                        db2.commit()
                finally:
                    db2.close()
            finally:
                cancel_events.pop(asm_id, None)
        else:
            await asyncio.sleep(POLL_SECONDS)


def recover_stale_jobs():
    """On startup: requeue QUEUED, fail jobs stuck mid-run from a previous process."""
    db: Session = SessionLocal()
    try:
        stale = db.query(models.Assessment).filter(
            models.Assessment.status.in_(["VALIDATING", "RUNNING", "ANALYZING", "GENERATING_RESULTS"])
        ).all()
        for a in stale:
            a.status = "FAILED"
            a.error = "Worker restarted while this assessment was running."
            a.finished_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()


async def run_worker(cancel_events: dict[int, threading.Event], stop: threading.Event):
    recover_stale_jobs()
    await _worker_loop(cancel_events, stop)
