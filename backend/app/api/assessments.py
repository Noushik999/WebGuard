"""Assessment lifecycle: create (queue) -> poll status -> findings -> rescan/compare."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from scanner import engine as scan_engine
from scanner.risk import compare_fingerprints
from .. import models, schemas
from ..audit import audit
from ..db import get_db
from ..deps import get_current_user, rate_limit

router = APIRouter(prefix="/api/assessments", tags=["assessments"])

TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")


def _summary(a: models.Assessment, target_name: str = "") -> schemas.AssessmentSummaryOut:
    return schemas.AssessmentSummaryOut(
        id=a.id, target_id=a.target_id, target_name=target_name, status=a.status,
        progress=a.progress, current_stage=a.current_stage, score=a.score,
        findings_count=a.findings_count, severity_counts=a.severity_counts or {},
        is_demo=a.is_demo, error=a.error, duration_s=a.duration_s,
        created_at=a.created_at, finished_at=a.finished_at,
    )


def _owned_assessment(db: Session, user_id: int, assessment_id: int) -> models.Assessment:
    a = (
        db.query(models.Assessment)
        .join(models.Target, models.Target.id == models.Assessment.target_id)
        .filter(models.Assessment.id == assessment_id, models.Target.user_id == user_id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Assessment not found")
    return a


def _queue_assessment(db: Session, user: models.User, target: models.Target) -> models.Assessment:
    # Don't stack duplicate running jobs for the same target.
    active = (
        db.query(models.Assessment)
        .filter(
            models.Assessment.target_id == target.id,
            models.Assessment.status.notin_(TERMINAL),
        )
        .first()
    )
    if active:
        raise HTTPException(409, f"An assessment (#{active.id}) is already running for this target")
    if not target.auth_confirmed and not target.is_demo:
        raise HTTPException(400, "Target authorization has not been confirmed")
    a = models.Assessment(
        user_id=user.id, target_id=target.id, status="QUEUED",
        scanner_version=scan_engine.SCANNER_VERSION,
        config={"allow_private": False},
        is_demo=target.is_demo,
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    audit(db, "assessment.queued", user_id=user.id, assessment_id=a.id, target_id=target.id)
    db.commit()
    return a


@router.post("/targets/{target_id}", response_model=schemas.AssessmentSummaryOut)
def start_assessment(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rate_limit(request, per_minute=20)
    target = db.query(models.Target).filter(
        models.Target.id == target_id, models.Target.user_id == user.id
    ).first()
    if not target:
        raise HTTPException(404, "Target not found")
    a = _queue_assessment(db, user, target)
    return _summary(a, target.name)


@router.get("", response_model=list[schemas.AssessmentSummaryOut])
def list_assessments(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rows = (
        db.query(models.Assessment, models.Target.name)
        .join(models.Target, models.Target.id == models.Assessment.target_id)
        .filter(models.Target.user_id == user.id)
        .order_by(models.Assessment.created_at.desc())
        .limit(100)
        .all()
    )
    return [_summary(a, name) for a, name in rows]


@router.get("/{assessment_id}", response_model=schemas.AssessmentDetailOut)
def get_assessment(assessment_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    a = _owned_assessment(db, user.id, assessment_id)
    s = _summary(a, a.target.name)
    cfg = a.config or {}
    return schemas.AssessmentDetailOut(
        **s.model_dump(),
        scanner_version=a.scanner_version,
        module_errors=cfg.get("module_errors", {}),
        score_breakdown=cfg.get("score_breakdown", []),
        grade=cfg.get("grade", ""),
    )


@router.get("/{assessment_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(
    assessment_id: int,
    severity: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    a = _owned_assessment(db, user.id, assessment_id)
    q = db.query(models.FindingInstance).filter(models.FindingInstance.assessment_id == a.id)
    if severity:
        q = q.filter(models.FindingInstance.severity == severity)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    rows = q.all()
    rows.sort(key=lambda f: (order.get(f.severity, 5), f.title))
    return [schemas.FindingOut(
        id=f.id, assessment_id=f.assessment_id, fingerprint=f.fingerprint, title=f.title,
        category=f.category, owasp_mapping=f.owasp_mapping, severity=f.severity,
        confidence=f.confidence, description=f.description, why_it_matters=f.why_it_matters,
        evidence=f.evidence, recommendation=f.recommendation, verification=f.verification,
        references=f.references or [], affected_url=f.affected_url, scanner=f.scanner,
        detected_at=f.detected_at, status=f.status, ai_analysis=f.ai_analysis,
    ) for f in rows]


@router.post("/{assessment_id}/cancel")
def cancel_assessment(
    assessment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rate_limit(request)
    a = _owned_assessment(db, user.id, assessment_id)
    if a.status in TERMINAL:
        raise HTTPException(400, f"Assessment is already {a.status}")
    # The worker's cancel_events map lives on the app; fall back to status flag.
    cancel_events = request.app.state.cancel_events
    if assessment_id in cancel_events:
        cancel_events[assessment_id].set()
    a.status = "CANCELLED"
    db.commit()
    audit(db, "assessment.cancel_requested", user_id=user.id, assessment_id=a.id)
    db.commit()
    return {"ok": True, "status": "CANCELLED"}


@router.post("/{assessment_id}/rescan", response_model=schemas.AssessmentSummaryOut)
def rescan(
    assessment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rate_limit(request, per_minute=20)
    a = _owned_assessment(db, user.id, assessment_id)
    target = db.get(models.Target, a.target_id)
    new_a = _queue_assessment(db, user, target)
    return _summary(new_a, target.name)


@router.get("/{assessment_id}/compare/{other_id}", response_model=schemas.ComparisonOut)
def compare(
    assessment_id: int, other_id: int,
    db: Session = Depends(get_db), user: models.User = Depends(get_current_user),
):
    a = _owned_assessment(db, user.id, assessment_id)
    b = _owned_assessment(db, user.id, other_id)
    if a.status != "COMPLETED" or b.status != "COMPLETED":
        raise HTTPException(400, "Both assessments must be completed to compare")
    if a.target_id != b.target_id:
        raise HTTPException(400, "Can only compare assessments of the same target")
    # assessment_id = newer (B), other_id = older (A)
    older, newer = (b, a) if a.created_at >= b.created_at else (a, b)

    def fp_map(asm):
        rows = db.query(models.FindingInstance).filter(
            models.FindingInstance.assessment_id == asm.id).all()
        return {r.fingerprint: {"severity": r.severity, "title": r.title,
                                "category": r.category, "finding_id": r.id} for r in rows}

    diff = compare_fingerprints(fp_map(older), fp_map(newer))
    delta = None
    if older.score is not None and newer.score is not None:
        delta = newer.score - older.score
    return schemas.ComparisonOut(
        assessment_a_id=older.id, assessment_b_id=newer.id,
        score_a=older.score, score_b=newer.score, score_delta=delta, **diff,
    )
