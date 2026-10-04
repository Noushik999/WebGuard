"""Report generation and retrieval."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from reports.generator import build_report
from .. import models, schemas
from ..audit import audit
from ..db import get_db
from ..deps import get_current_user, rate_limit

router = APIRouter(prefix="/api", tags=["reports"])


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


@router.post("/assessments/{assessment_id}/report", response_model=dict)
def generate_report(
    assessment_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rate_limit(request, per_minute=20)
    a = _owned_assessment(db, user.id, assessment_id)
    if a.status != "COMPLETED":
        raise HTTPException(400, "Report can only be generated for completed assessments")
    target = db.get(models.Target, a.target_id)
    findings = (
        db.query(models.FindingInstance)
        .filter(models.FindingInstance.assessment_id == a.id)
        .order_by(models.FindingInstance.severity)
        .all()
    )
    # Previous completed assessment for the comparison section.
    prev = (
        db.query(models.Assessment)
        .filter(models.Assessment.target_id == a.target_id,
                models.Assessment.status == "COMPLETED",
                models.Assessment.id != a.id)
        .order_by(models.Assessment.created_at.desc())
        .first()
    )
    comparison = None
    if prev:
        comparison = {"assessment_a_id": prev.id, "assessment_b_id": a.id,
                      "score_a": prev.score, "score_b": a.score,
                      "score_delta": (a.score - prev.score) if a.score is not None and prev.score is not None else 0,
                      "resolved_count": 0, "new_count": 0, "persistent_count": 0}

    html = build_report(assessment=a, target=target, findings=findings,
                        comparison=comparison, generated_by=user.email,
                        is_demo=a.is_demo)
    # Replace existing report for idempotency.
    db.query(models.Report).filter(models.Report.assessment_id == a.id).delete()
    rep = models.Report(assessment_id=a.id, format="html", html=html)
    db.add(rep)
    db.commit()
    db.refresh(rep)
    audit(db, "report.generated", user_id=user.id, assessment_id=a.id, report_id=rep.id)
    db.commit()
    return {"report_id": rep.id}


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    rep = (
        db.query(models.Report)
        .join(models.Assessment, models.Assessment.id == models.Report.assessment_id)
        .join(models.Target, models.Target.id == models.Assessment.target_id)
        .filter(models.Report.id == report_id, models.Target.user_id == user.id)
        .first()
    )
    if not rep:
        raise HTTPException(404, "Report not found")
    return Response(content=rep.html, media_type="text/html")


@router.get("/assessments/{assessment_id}/report-view")
def view_latest_report(assessment_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    a = _owned_assessment(db, user.id, assessment_id)
    rep = (
        db.query(models.Report)
        .filter(models.Report.assessment_id == a.id)
        .order_by(models.Report.created_at.desc())
        .first()
    )
    if not rep:
        raise HTTPException(404, "No report generated yet for this assessment")
    return Response(content=rep.html, media_type="text/html")
