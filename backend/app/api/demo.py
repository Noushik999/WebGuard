"""Demo mode: a pre-seeded demo target with realistic SIMULATED findings.

Everything created here is marked is_demo=True and surfaced in the UI/report as
DEMO / SAMPLE. No real network scan is performed for the demo assessment.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from scanner import engine as scan_engine
from scanner.risk import grade, score_findings, severity_counts
from scanner.schemas import Finding
from .. import models
from ..audit import audit
from ..db import get_db
from ..deps import get_current_user

router = APIRouter(prefix="/api/demo", tags=["demo"])

DEMO_URL = "https://demo-university.webguard.local"


def _f(title, category, owasp, severity, confidence, scanner, description,
        why, evidence, recommendation, verification, refs=None, path="/"):
    return Finding(
        title=title, category=category, owasp_mapping=owasp, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=refs or [], affected_url=DEMO_URL + path, scanner=scanner,
        detected_at=datetime.now(timezone.utc),
    )


def demo_findings() -> list[Finding]:
    return [
        _f("Cookie 'sessid' missing Secure flag", "Session / Cookie Security",
           "A01:2021 – Broken Access Control", "High", 0.95, "cookies",
           "The session cookie 'sessid' is set without the Secure attribute on an HTTPS site.",
           "Without Secure, browsers may transmit the session cookie over plain HTTP, letting "
           "network attackers steal it and hijack the user's session.",
           "Set-Cookie: sessid=9f3a…; Path=/; HttpOnly (Secure flag absent)",
           "Add `Secure` to the Set-Cookie attributes for 'sessid' and serve the site HTTPS-only.",
           "Open devtools → Application → Cookies and confirm Secure is set on 'sessid'.",
           ["https://owasp.org/www-community/controls/SecureCookieAttribute"]),
        _f("Cookie 'sessid' missing HttpOnly flag", "Session / Cookie Security",
           "A01:2021 – Broken Access Control", "High", 0.90, "cookies",
           "The session cookie 'sessid' is readable from JavaScript (no HttpOnly).",
           "Any cross-site scripting flaw becomes instant session theft — JavaScript can read "
           "document.cookie and exfiltrate it.",
           "Set-Cookie: sessid=9f3a…; Path=/ (HttpOnly flag absent)",
           "Add `HttpOnly` to 'sessid' unless client-side JS genuinely needs it.",
           "Confirm HttpOnly is set in devtools cookie inspector.",
           ["https://owasp.org/www-community/HttpOnly"]),
        _f("Missing Content-Security-Policy header", "Security Headers",
           "A05:2021 – Security Misconfiguration", "Medium", 0.95, "security_headers",
           "No Content-Security-Policy header is sent.",
           "Without CSP there is no allow-list for scripts and resources, making XSS and "
           "content-injection flaws far easier to exploit.",
           "Response headers for " + DEMO_URL + "/ contain no content-security-policy entry.",
           "Deploy a restrictive CSP (default-src 'self'; script-src with nonces instead of 'unsafe-inline').",
           "Re-run this assessment and confirm a CSP header is present."),
        _f("Missing Strict-Transport-Security header", "Security Headers",
           "A05:2021 – Security Misconfiguration", "Medium", 0.95, "security_headers",
           "The HTTPS responses do not include Strict-Transport-Security.",
           "Users stay exposed to SSL-stripping downgrade attacks on first visit.",
           "No strict-transport-security header observed on " + DEMO_URL + "/.",
           "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses.",
           "Re-run this assessment and confirm HSTS is present."),
        _f("Missing clickjacking protection", "Security Headers",
           "A05:2021 – Security Misconfiguration", "Medium", 0.90, "security_headers",
           "Neither X-Frame-Options nor CSP frame-ancestors is set.",
           "The site can be embedded invisibly in a malicious page (clickjacking), tricking users "
           "into unintended clicks.",
           "Response headers contain neither x-frame-options nor frame-ancestors.",
           "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'self'`.",
           "Re-run this assessment and confirm the finding is gone."),
        _f("TLS certificate expires soon", "Cryptographic / Transport",
           "A02:2021 – Cryptographic Failures", "Medium", 0.85, "tls",
           "The TLS certificate expires in 9 days.",
           "Expiry takes the site offline for security-conscious users and erodes trust.",
           "Certificate notAfter is 9 days away; issuer Demo CA.",
           "Renew now and automate renewal with expiry alerting.",
           "Re-run this assessment and confirm expiry exceeds 30 days."),
        _f("Server version disclosure (Apache/2.4.49)", "Information Disclosure",
           "A05:2021 – Security Misconfiguration", "Low", 0.95, "disclosure",
           "The Server header reveals 'Apache/2.4.49'.",
           "Version banners help attackers pick version-targeted exploits (this exact version has "
           "known CVEs). It doesn't create a flaw by itself, but it sharpens attacks.",
           "Response header: Server: Apache/2.4.49 (Unix)",
           "Set `ServerTokens Prod` and `ServerSignature Off` to minimize the banner.",
           "Re-run this assessment and confirm the version is hidden."),
        _f("Missing X-Content-Type-Options header", "Security Headers",
           "A05:2021 – Security Misconfiguration", "Low", 0.95, "security_headers",
           "X-Content-Type-Options: nosniff is not set.",
           "Browsers may MIME-sniff responses and execute them as scripts, enabling injection attacks.",
           "No x-content-type-options header observed.",
           "Send `X-Content-Type-Options: nosniff` on all responses.",
           "Re-run this assessment and confirm the header is present."),
        _f("Missing Referrer-Policy header", "Security Headers",
           "A05:2021 – Security Misconfiguration", "Informational", 0.95, "security_headers",
           "No Referrer-Policy header is set.",
           "Full page URLs (possibly containing tokens) may leak to third parties as Referer.",
           "No referrer-policy header observed.",
           "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
           "Re-run this assessment and confirm the header is present."),
        _f("Missing security.txt contact file", "Information Disclosure",
           "A05:2021 – Security Misconfiguration", "Informational", 0.90, "disclosure",
           "No security.txt at /.well-known/security.txt.",
           "Researchers who find a vulnerability can't easily report it responsibly.",
           "GET /.well-known/security.txt → 404.",
           "Publish a security.txt with a Contact: address per RFC 9116.",
           "Fetch the URL and confirm it loads.", ["https://securitytxt.org/"]),
    ]


@router.post("/seed")
def seed_demo(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    existing = db.query(models.Target).filter(
        models.Target.user_id == user.id, models.Target.is_demo.is_(True)).first()
    if existing:
        raise HTTPException(409, "Demo target already exists")
    now = datetime.now(timezone.utc)
    target = models.Target(
        user_id=user.id, name="WebGuard Demo Target", url=DEMO_URL,
        description="Demo University Website — simulated assessment for presentations.",
        scope="Simulated data only; no real scan performed.", auth_confirmed=True,
        auth_confirmed_at=now, is_demo=True,
    )
    db.add(target)
    db.flush()

    findings = demo_findings()
    from scanner.normalizer import normalize
    findings = normalize(findings)
    score, breakdown = score_findings(findings)

    asm = models.Assessment(
        user_id=user.id, target_id=target.id, status="COMPLETED", progress=100,
        current_stage="COMPLETED", score=score, findings_count=len(findings),
        severity_counts=severity_counts(findings),
        scanner_version=scan_engine.SCANNER_VERSION + "-demo",
        config={"grade": grade(score), "score_breakdown": breakdown,
                "module_errors": {}, "stats": {"demo": True}},
        is_demo=True, started_at=now, finished_at=now, duration_s=4.2,
    )
    db.add(asm)
    db.flush()
    for f in findings:
        db.add(models.FindingInstance(
            assessment_id=asm.id, fingerprint=f.fingerprint, title=f.title,
            category=f.category, owasp_mapping=f.owasp_mapping, severity=f.severity,
            confidence=f.confidence, description=f.description,
            why_it_matters=f.why_it_matters, evidence=f.evidence,
            recommendation=f.recommendation, verification=f.verification,
            references=list(f.references), affected_url=f.affected_url,
            scanner=f.scanner, detected_at=f.detected_at,
        ))
    db.commit()
    audit(db, "demo.seeded", user_id=user.id, target_id=target.id, assessment_id=asm.id)
    db.commit()
    return {"target_id": target.id, "assessment_id": asm.id, "score": score}
