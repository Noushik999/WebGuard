"""Finding detail, triage status, and AI analysis."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from scanner.schemas import Finding as ScannerFinding
from .. import ai_analyst, models, schemas
from ..audit import audit
from ..db import get_db
from ..deps import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _owned_finding(db: Session, user_id: int, finding_id: int) -> models.FindingInstance:
    f = (
        db.query(models.FindingInstance)
        .join(models.Assessment, models.Assessment.id == models.FindingInstance.assessment_id)
        .join(models.Target, models.Target.id == models.Assessment.target_id)
        .filter(models.FindingInstance.id == finding_id, models.Target.user_id == user_id)
        .first()
    )
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


def _out(f: models.FindingInstance) -> schemas.FindingOut:
    return schemas.FindingOut(
        id=f.id, assessment_id=f.assessment_id, fingerprint=f.fingerprint, title=f.title,
        category=f.category, owasp_mapping=f.owasp_mapping, severity=f.severity,
        confidence=f.confidence, description=f.description, why_it_matters=f.why_it_matters,
        evidence=f.evidence, recommendation=f.recommendation, verification=f.verification,
        references=f.references or [], affected_url=f.affected_url, scanner=f.scanner,
        detected_at=f.detected_at, status=f.status, ai_analysis=f.ai_analysis,
    )


@router.get("/{finding_id}", response_model=schemas.FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return _out(_owned_finding(db, user.id, finding_id))


@router.patch("/{finding_id}", response_model=schemas.FindingOut)
def triage_finding(
    finding_id: int, body: schemas.FindingStatusIn,
    db: Session = Depends(get_db), user: models.User = Depends(get_current_user),
):
    f = _owned_finding(db, user.id, finding_id)
    f.status = body.status
    db.commit()
    audit(db, "finding.triage", user_id=user.id, finding_id=f.id, status=body.status)
    db.commit()
    return _out(f)


@router.get("/{finding_id}/analysis", response_model=schemas.AIAnalysisOut)
def finding_analysis(
    finding_id: int, refresh: bool = False,
    db: Session = Depends(get_db), user: models.User = Depends(get_current_user),
):
    f = _owned_finding(db, user.id, finding_id)
    if f.ai_analysis and not refresh:
        return schemas.AIAnalysisOut(**f.ai_analysis)
    scanner_finding = ScannerFinding(
        title=f.title, category=f.category, owasp_mapping=f.owasp_mapping,
        severity=f.severity, confidence=f.confidence, description=f.description,
        why_it_matters=f.why_it_matters, evidence=f.evidence,
        recommendation=f.recommendation, verification=f.verification,
        references=f.references or [], affected_url=f.affected_url, scanner=f.scanner,
        detected_at=f.detected_at, fingerprint=f.fingerprint,
    )
    analysis = ai_analyst.analyze(scanner_finding)
    f.ai_analysis = analysis
    db.commit()
    audit(db, "finding.analyzed", user_id=user.id, finding_id=f.id, source=analysis.get("source"))
    db.commit()
    return schemas.AIAnalysisOut(**analysis)
