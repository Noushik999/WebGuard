"""Information-disclosure module: passive indicators only.

We read what the server volunteers (headers, robots.txt, security.txt, generator
meta tags) and probe one non-existent path for verbose error pages. We never
download sensitive files or attempt to read protected data.
"""

from __future__ import annotations

import re

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "disclosure"
CATEGORY = "Information Disclosure"
OWASP = "A05:2021 – Security Misconfiguration"

STACKTRACE_HINTS = (
    "traceback", "stack trace", "exception in", "sql syntax", "odbc",
    "warning: mysql", "pg_query()", "nullpointerexception", ".java:",
    "at java.", "at sun.", "django", "laravel", "whoops",
)


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url, refs=None) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=refs or [],
        affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url

    server = ctx.header("server")
    if server:
        has_version = bool(re.search(r"[\d]", server))
        findings.append(_mk(
            f"Server version disclosure ({server[:60]})",
            "Low" if has_version else "Informational", 0.95,
            f"The Server header reveals '{server}'.",
            "Version banners help attackers fingerprint the stack and target known vulnerabilities "
            "in that exact version. It doesn't create a vulnerability by itself, but it sharpens attacks.",
            f"Response header: Server: {server}",
            "Configure the server to send a minimal Server header (or none). E.g. nginx "
            "`server_tokens off;`, Apache `ServerTokens Prod`.",
            "Re-run this assessment and confirm the version is no longer disclosed.",
            url))

    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        val = ctx.header(hdr)
        if val:
            findings.append(_mk(
                f"Technology disclosure via {hdr} header",
                "Low", 0.95,
                f"The {hdr} header reveals '{val}'.",
                "Framework banners make fingerprinting trivial and invite version-targeted attacks.",
                f"Response header: {hdr}: {val}",
                "Remove or minimize framework-identifying headers.",
                "Re-run this assessment and confirm the header is gone.",
                url))

    # robots.txt analysis (already fetched by the engine, bounded)
    robots = ctx.extra_pages.get("/robots.txt")
    if robots and robots.get("status") == 200 and robots.get("body"):
        interesting = [l for l in robots["body"].splitlines()
                       if l.strip().lower().startswith(("disallow:", "allow:"))
                       and any(k in l.lower() for k in ("admin", "config", "backup", ".git", "wp-", "private", "test"))]
        if interesting:
            findings.append(_mk(
                "robots.txt exposes sensitive-looking paths", "Informational", 0.75,
                "robots.txt lists paths that look sensitive.",
                "robots.txt is public; attackers routinely mine it for admin panels, backups and "
                "config locations. Sensitive paths should need authentication regardless.",
                "robots.txt excerpts:\n" + "\n".join(interesting[:8]),
                "Ensure every sensitive path requires authentication; don't rely on robots.txt for secrecy.",
                "Review robots.txt and confirm sensitive paths are access-controlled.",
                url.rstrip("/") + "/robots.txt"))

    # security.txt (RFC 9116) — best practice for coordinated disclosure
    sec = ctx.extra_pages.get("/.well-known/security.txt")
    if not sec or sec.get("status") != 200:
        findings.append(_mk(
            "Missing security.txt contact file", "Informational", 0.9,
            "No security.txt was found at /.well-known/security.txt.",
            "Without a published contact, researchers who find a vulnerability can't easily report it "
            "responsibly — findings may go public instead.",
            "GET /.well-known/security.txt did not return a valid contact file.",
            "Publish a security.txt with a Contact: address per RFC 9116.",
            "Fetch https://<domain>/.well-known/security.txt and confirm it loads.",
            url, ["https://securitytxt.org/"]))

    # Verbose error page probe: one request to a non-existent path.
    probe_path = "/webguard-nonexistent-" + "x" * 8
    try:
        resp = client.get(ctx.target_url.rstrip("/") + probe_path)
        body = (resp.text or "")[:4000].lower()
        if any(h in body for h in STACKTRACE_HINTS) and resp.status_code >= 500:
            findings.append(_mk(
                "Verbose error page leaks internals", "Medium", 0.8,
                f"Requesting a non-existent path ({probe_path}) returned a {resp.status_code} page "
                "containing stack-trace-like content.",
                "Verbose errors disclose code paths, library names and sometimes query fragments — "
                "useful reconnaissance for attackers and unprofessional for users.",
                f"GET {probe_path} → {resp.status_code}; body contains error/stack-trace indicators.",
                "Configure custom error pages that reveal nothing technical; log details server-side only.",
                "Request a bad URL and confirm you see a generic error page.",
                ctx.target_url.rstrip("/") + probe_path))
    except Exception:
        pass  # probe failure is not a finding

    # Generator meta tag
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', ctx.body, re.I)
    if m:
        findings.append(_mk(
            f"Generator meta tag discloses software ({m.group(1)[:60]})", "Informational", 0.9,
            f"The page contains <meta name=\"generator\" content=\"{m.group(1)}\">.",
            "CMS/framework version hints help attackers pick version-specific exploits.",
            f"Meta tag: {m.group(0)[:160]}",
            "Remove the generator meta tag or strip the version number.",
            "View page source and confirm the tag is gone.",
            url))

    return findings
