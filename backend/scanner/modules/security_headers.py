"""Security-headers module: presence AND quality analysis."""

from __future__ import annotations

import re

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "security_headers"
CATEGORY = "Security Headers"
OWASP = "A05:2021 – Security Misconfiguration"

REFS = {
    "csp": ["https://owasp.org/www-project-secure-headers/#content-security-policy"],
    "hsts": ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
    "xcto": ["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
    "frame": ["https://owasp.org/www-project-secure-headers/#x-frame-options"],
    "referrer": ["https://owasp.org/www-project-secure-headers/#referrer-policy"],
    "permissions": ["https://owasp.org/www-project-secure-headers/#permissions-policy"],
}

MDN_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url, refs) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=refs, affected_url=affected_url, scanner=NAME,
    )


def _analyze_csp(csp: str) -> list[str]:
    """Return a list of weakness descriptions for a CSP value."""
    issues = []
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = [t.strip("'").lower() for t in tokens[1:]]
    script = directives.get("script-src", directives.get("default-src", []))
    if "unsafe-inline" in script:
        issues.append("script-src allows 'unsafe-inline' — inline scripts can execute, weakening XSS protection")
    if "unsafe-eval" in script:
        issues.append("script-src allows 'unsafe-eval' — dynamic code evaluation is permitted")
    if "*" in script or "https:" in script or "http:" in script or "data:" in script:
        issues.append("script-src allows broad sources (*, https:, http: or data:) — nearly any script can load")
    if "object-src" not in directives:
        issues.append("object-src is not set — plugins/objects fall back to default-src")
    if "base-uri" not in directives:
        issues.append("base-uri is not restricted — base-tag injection could redirect relative URLs")
    return issues


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url
    is_https = url.startswith("https://")

    # --- Content-Security-Policy ---
    csp = ctx.header("content-security-policy")
    if not csp:
        findings.append(_mk(
            "Missing Content-Security-Policy header", "Medium", 0.95,
            "The response does not include a Content-Security-Policy (CSP) header.",
            "Without CSP the browser cannot restrict where scripts, styles and other resources "
            "may load from, leaving cross-site scripting (XSS) and content-injection flaws easier to exploit.",
            f"Response headers for {url} contain no content-security-policy entry.",
            "Add a Content-Security-Policy header. Start with a restrictive policy (e.g. "
            "default-src 'self') and expand deliberately; use nonces or hashes instead of 'unsafe-inline'.",
            "Re-run this assessment and confirm a CSP header is present; test the site in a browser "
            "console for CSP violations after deploying.",
            url, REFS["csp"] + [MDN_CSP]))
    else:
        weaknesses = _analyze_csp(csp)
        if weaknesses:
            findings.append(_mk(
                "Content-Security-Policy is present but weak", "Medium", 0.85,
                "A Content-Security-Policy header exists, but its configuration undermines its protection.",
                "A permissive CSP gives a false sense of security: XSS payloads the policy was meant "
                "to block may still execute.",
                "CSP value: " + csp[:400] + "\nWeaknesses:\n- " + "\n- ".join(weaknesses),
                "Tighten script-src: remove 'unsafe-inline'/'unsafe-eval' (use nonces/hashes), avoid "
                "wildcards and scheme sources, and add object-src 'none' and base-uri 'self'.",
                "Re-run this assessment and confirm no CSP weaknesses are reported.",
                url, REFS["csp"] + [MDN_CSP]))

    # --- Strict-Transport-Security ---
    hsts = ctx.header("strict-transport-security")
    if is_https:
        if not hsts:
            findings.append(_mk(
                "Missing Strict-Transport-Security header", "Medium", 0.95,
                "The HTTPS response does not include Strict-Transport-Security (HSTS).",
                "Without HSTS, users remain exposed to SSL-stripping downgrade attacks on first visit "
                "or after cache expiry — an attacker on the network could force plain HTTP.",
                f"No strict-transport-security header observed on {url}.",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS "
                "responses. Consider `preload` and submitting to hstspreload.org once stable.",
                "Re-run this assessment and confirm the HSTS header is present with max-age ≥ 31536000.",
                url, REFS["hsts"]))
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < 31536000:
                findings.append(_mk(
                    "HSTS max-age is shorter than recommended", "Low", 0.9,
                    f"HSTS is set but max-age is only {max_age} seconds (recommended: at least 31536000, i.e. one year).",
                    "A short HSTS duration narrows the window of downgrade protection; users who don't "
                    "visit often lose the protection.",
                    f"Header value: {hsts}",
                    "Raise max-age to 31536000 (one year) or 63072000 (two years).",
                    "Re-run this assessment and confirm max-age ≥ 31536000.",
                    url, REFS["hsts"]))
            if "includesubdomains" not in hsts.lower():
                findings.append(_mk(
                    "HSTS does not include subdomains", "Low", 0.9,
                    "The HSTS header lacks the includeSubDomains directive.",
                    "Subdomains remain reachable over plain HTTP and can be targeted by cookie-injection "
                    "or downgrade attacks.",
                    f"Header value: {hsts}",
                    "Add `includeSubDomains` to the HSTS header (after verifying all subdomains support HTTPS).",
                    "Re-run this assessment and confirm includeSubDomains is present.",
                    url, REFS["hsts"]))

    # --- Clickjacking: X-Frame-Options / CSP frame-ancestors ---
    xfo = ctx.header("x-frame-options")
    csp_frame = "frame-ancestors" in csp.lower()
    if not xfo and not csp_frame:
        findings.append(_mk(
            "Missing clickjacking protection", "Medium", 0.9,
            "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be embedded in "
            "an iframe on any site.",
            "Attackers can overlay the site invisibly inside a malicious page (clickjacking) and trick "
            "users into clicking actions they didn't intend.",
            f"Response headers for {url} contain neither x-frame-options nor a CSP frame-ancestors directive.",
            "Add `X-Frame-Options: DENY` (or SAMEORIGIN if framing is needed) or a CSP "
            "`frame-ancestors 'self'` directive.",
            "Re-run this assessment and confirm the finding is gone.",
            url, REFS["frame"]))

    # --- X-Content-Type-Options ---
    if ctx.header("x-content-type-options").lower() != "nosniff":
        findings.append(_mk(
            "Missing X-Content-Type-Options header", "Low", 0.95,
            "The X-Content-Type-Options: nosniff header is not set.",
            "Without it, browsers may MIME-sniff responses and execute them as scripts, enabling "
            "certain content-injection attacks.",
            f"No x-content-type-options: nosniff header observed on {url}.",
            "Send `X-Content-Type-Options: nosniff` on all responses.",
            "Re-run this assessment and confirm the header is present.",
            url, REFS["xcto"]))

    # --- Referrer-Policy ---
    if not ctx.header("referrer-policy"):
        findings.append(_mk(
            "Missing Referrer-Policy header", "Informational", 0.95,
            "No Referrer-Policy header is set; browsers fall back to a default that may leak full URLs.",
            "Full page URLs (which can contain tokens or sensitive query parameters) may be sent to "
            "third-party sites as the Referer header.",
            f"No referrer-policy header observed on {url}.",
            "Send a restrictive policy such as `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
            "Re-run this assessment and confirm the header is present.",
            url, REFS["referrer"]))

    # --- Permissions-Policy ---
    if not ctx.header("permissions-policy") and not ctx.header("feature-policy"):
        findings.append(_mk(
            "Missing Permissions-Policy header", "Informational", 0.9,
            "No Permissions-Policy (or legacy Feature-Policy) header is set.",
            "The page cannot restrict access to powerful browser features (camera, microphone, "
            "geolocation); a compromised third-party script could abuse them.",
            f"No permissions-policy header observed on {url}.",
            "Send a Permissions-Policy that disables unneeded features, e.g. "
            "`Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
            "Re-run this assessment and confirm the header is present.",
            url, REFS["permissions"]))

    return findings
