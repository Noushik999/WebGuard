"""Dashboard aggregates: scores, counts, history, top findings, recent activity."""

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("", response_model=schemas.DashboardOut)
def dashboard(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    targets = db.query(models.Target).filter(models.Target.user_id == user.id).all()
    target_ids = [t.id for t in targets]

    assessments = (
        db.query(models.Assessment)
        .filter(models.Assessment.user_id == user.id)
        .order_by(models.Assessment.created_at.desc())
        .limit(200)
        .all()
    )
    completed = [a for a in assessments if a.status == "COMPLETED"]
    running = [a for a in assessments if a.status not in ("COMPLETED", "FAILED", "CANCELLED")]

    # Latest completed assessment per target -> score history + severity totals.
    latest_by_target: dict[int, models.Assessment] = {}
    for a in completed:
        if a.target_id not in latest_by_target:
            latest_by_target[a.target_id] = a
    latest_score = None
    if completed:
        latest_score = completed[0].score

    score_history = [
        {"assessment_id": a.id, "target_id": a.target_id, "score": a.score,
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in sorted(completed, key=lambda x: x.created_at)[:50]
    ]

    severity_totals: Counter = Counter()
    top_findings: list[dict] = []
    for a in latest_by_target.values():
        for sev, n in (a.severity_counts or {}).items():
            severity_totals[sev] += n
        rows = (
            db.query(models.FindingInstance)
            .filter(models.FindingInstance.assessment_id == a.id)
            .all()
        )
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        rows.sort(key=lambda f: (order.get(f.severity, 5), f.title))
        for f in rows[:3]:
            top_findings.append({
                "id": f.id, "assessment_id": a.id, "title": f.title,
                "severity": f.severity, "category": f.category,
                "target_name": next((t.name for t in targets if t.id == a.target_id), ""),
            })
    top_findings.sort(key=lambda x: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}[x["severity"]], x["title"]))
    top_findings = top_findings[:8]

    name_by_id = {t.id: t.name for t in targets}
    recent = [
        schemas.AssessmentSummaryOut(
            id=a.id, target_id=a.target_id, target_name=name_by_id.get(a.target_id, ""),
            status=a.status, progress=a.progress, current_stage=a.current_stage,
            score=a.score, findings_count=a.findings_count,
            severity_counts=a.severity_counts or {}, is_demo=a.is_demo, error=a.error,
            duration_s=a.duration_s, created_at=a.created_at, finished_at=a.finished_at,
        )
        for a in assessments[:10]
    ]

    return schemas.DashboardOut(
        target_count=len(targets),
        assessment_count=len(assessments),
        completed_count=len(completed),
        running_count=len(running),
        latest_score=latest_score,
        score_history=score_history,
        severity_totals=dict(severity_totals),
        top_findings=top_findings,
        recent_assessments=recent,
    )
