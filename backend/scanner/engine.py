"""Assessment engine: orchestrates validation, collection, modules, scoring.

Pipeline:
    VALIDATING -> collecting base page (+ robots.txt, security.txt, TLS info)
    RUNNING    -> each scanner module in isolation (one module can never crash the run)
    ANALYZING  -> normalization + risk scoring
    GENERATING_RESULTS -> packaging

Progress is reported via an optional callback(stage, percent).
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

from . import modules as _modules  # noqa: F401  (package marker)
from .http_client import SafeHttpClient, parse_set_cookies
from .modules import cookies as m_cookies
from .modules import cors as m_cors
from .modules import disclosure as m_disclosure
from .modules import http_config as m_http_config
from .modules import security_headers as m_headers
from .modules import tech as m_tech
from .modules import tls as m_tls
from .normalizer import normalize
from .risk import grade, score_findings, severity_counts
from .schemas import Finding, ScanContext
from .target_validator import validate_target

SCANNER_VERSION = "1.0.0"

MODULES = [
    m_headers,   # security headers
    m_tls,       # TLS / HTTPS
    m_cookies,   # cookie flags
    m_cors,      # CORS probe
    m_disclosure,  # information disclosure
    m_http_config,  # HTTP configuration
    m_tech,      # technology fingerprinting
]

ProgressCb = Callable[[str, int], None]


class ScanCancelledByUser(Exception):
    pass


class ScanResult:
    def __init__(self):
        self.findings: list[Finding] = []
        self.module_errors: dict[str, str] = {}
        self.score: int = 100
        self.score_breakdown: list[dict] = []
        self.grade: str = ""
        self.severity_counts: dict[str, int] = {}
        self.stats: dict = {}


def _collect_tls_info(host: str, port: int, timeout: float) -> dict:
    """Non-exploitative TLS handshake: cert validity/expiry + negotiated version."""
    info: dict = {}
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        # We want our OWN validation view, so don't fail on untrusted certs here;
        # the module reports what we observe. Disable hostname check for info gathering.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(raw, server_hostname=host) as ssock:
            info["tls_version"] = ssock.version()
            cert = ssock.getpeercert()
        if cert:
            from datetime import datetime as dt
            not_after = cert.get("notAfter")
            if not_after:
                # format: 'Oct  4 12:00:00 2026 GMT'
                expiry = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                delta = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
                info["cert_expires_in_days"] = round(delta, 1)
            issuers = cert.get("issuer", ())
            info["cert_issuer"] = ", ".join(v for _, v in [t for r in issuers for t in r]) or "unknown"
    except Exception as e:
        info["cert_error"] = f"{type(e).__name__}: {str(e)[:160]}"
    return info


def run_assessment(
    raw_url: str,
    *,
    allow_private_networks: bool = False,
    request_timeout: float = 10.0,
    max_requests: int = 40,
    user_agent: str = "WebGuard/1.0 (authorized passive security assessment)",
    progress: ProgressCb | None = None,
    stop_check: Callable[[], bool] | None = None,
) -> ScanResult:
    result = ScanResult()

    def emit(stage: str, pct: int):
        if stop_check and stop_check():
            raise ScanCancelledByUser()
        if progress:
            progress(stage, pct)

    emit("VALIDATING", 5)
    target_url = validate_target(raw_url, allow_private_networks=allow_private_networks)
    parsed = urlparse(target_url)

    client = SafeHttpClient(
        user_agent=user_agent,
        timeout=request_timeout,
        max_requests=max_requests,
        allow_private_networks=allow_private_networks,
    )
    try:
        emit("COLLECTING", 15)
        resp = client.get(target_url)
        chain = getattr(resp, "request_chain", [target_url])
        raw_headers = [(k, v) for k, v in resp.headers.raw]
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body_bytes = resp.content or b""
        body = body_bytes.decode("utf-8", errors="replace")
        cookies = parse_set_cookies(raw_headers)

        # TLS info for https targets
        tls_info: dict = {}
        if parsed.scheme == "https":
            tls_info = _collect_tls_info(parsed.hostname or "", parsed.port or 443, timeout=8.0)
            # http -> https redirect check (single bounded request)
            try:
                http_variant = "http://" + target_url[len("https://"):]
                r2 = client.get(http_variant)
                c2 = getattr(r2, "request_chain", [])
                tls_info["http_redirects_to_https"] = any(u.startswith("https://") for u in c2[1:])
            except Exception:
                tls_info["http_redirects_to_https"] = None

        # Small set of well-known public files (bounded, passive)
        emit("COLLECTING", 25)
        extra_pages: dict[str, dict] = {}
        for path in ("/robots.txt", "/.well-known/security.txt"):
            try:
                r = client.get(urljoin(target_url, path))
                extra_pages[path] = {
                    "status": r.status_code,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": (r.text or "")[:8192],
                }
            except Exception as e:
                extra_pages[path] = {"status": None, "error": str(e)[:200]}

        ctx = ScanContext(
            target_url=target_url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers=headers,
            raw_headers=[(k.decode("latin1"), v.decode("latin1")) for k, v in raw_headers],
            body=body,
            body_truncated=len(body_bytes) > 512 * 1024,
            cookies=cookies,
            redirect_chain=chain,
            tls_info=tls_info,
            extra_pages=extra_pages,
            request_count=client.request_count,
        )

        emit("RUNNING", 35)
        all_findings: list[Finding] = []
        for i, mod in enumerate(MODULES):
            try:
                found = mod.run(ctx, client) or []
                all_findings.extend(found)
            except Exception as e:
                # One module must never crash the assessment.
                result.module_errors[mod.NAME] = f"{type(e).__name__}: {str(e)[:200]}"
            emit("RUNNING", 35 + int(45 * (i + 1) / len(MODULES)))

        emit("ANALYZING", 85)
        result.findings = normalize(all_findings)
        result.score, result.score_breakdown = score_findings(result.findings)
        result.grade = grade(result.score)
        result.severity_counts = severity_counts(result.findings)
        result.stats = {
            "request_count": client.request_count,
            "final_url": ctx.final_url,
            "status_code": ctx.status_code,
            "modules_run": len(MODULES),
            "modules_failed": len(result.module_errors),
        }
        emit("GENERATING_RESULTS", 95)
    finally:
        client.close()

    emit("COMPLETED", 100)
    return result
