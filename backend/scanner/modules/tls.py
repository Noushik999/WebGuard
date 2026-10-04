"""TLS / HTTPS module: transport security signals (non-exploitative)."""

from __future__ import annotations

import re

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "tls"
CATEGORY = "Cryptographic / Transport"
OWASP = "A02:2021 – Cryptographic Failures"


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url, refs) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=refs, affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url
    tls = ctx.tls_info or {}
    uses_https = url.startswith("https://")

    if not uses_https:
        findings.append(_mk(
            "Site does not use HTTPS", "High", 0.98,
            "The site is served over plain HTTP. All traffic — including any credentials, "
            "cookies and page content — travels unencrypted.",
            "Anyone on the network path (public Wi-Fi, ISP, compromised router) can read and "
            "modify traffic, steal sessions and inject content.",
            f"Final URL after redirects: {url} (scheme is http, not https).",
            "Obtain a TLS certificate (free via Let's Encrypt), serve the site over HTTPS, and "
            "redirect all HTTP traffic to HTTPS with HSTS enabled.",
            "Browse to the http:// URL and confirm it redirects to https:// with a valid certificate.",
            url, ["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"]))
        return findings  # remaining TLS checks don't apply

    # Certificate checks
    if tls.get("cert_error"):
        findings.append(_mk(
            "TLS certificate problem detected", "High", 0.9,
            f"The TLS handshake reported a certificate problem: {tls['cert_error']}",
            "Certificate errors break the chain of trust: users see browser warnings and attackers "
            "can more easily impersonate the site.",
            f"TLS error for {url}: {tls['cert_error']}",
            "Install a valid certificate from a trusted CA covering all served hostnames; "
            "ensure the full chain is served and renew before expiry.",
            "Re-run this assessment and confirm no certificate problem is reported; check with "
            "your browser's certificate viewer or ssllabs.com.",
            url, ["https://wiki.mozilla.org/Security/Server_Side_TLS"]))
    else:
        days = tls.get("cert_expires_in_days")
        if days is not None and days < 0:
            findings.append(_mk(
                "TLS certificate has expired", "High", 0.95,
                f"The certificate expired {-days:.0f} day(s) ago.",
                "Browsers block or warn heavily on expired certificates; users cannot securely use the site.",
                f"Certificate notAfter indicates expiry {-days:.0f} day(s) ago.",
                "Renew the certificate immediately and automate renewal (e.g. certbot).",
                "Re-run this assessment and confirm the certificate is valid.",
                url, ["https://wiki.mozilla.org/Security/Server_Side_TLS"]))
        elif days is not None and days < 30:
            findings.append(_mk(
                "TLS certificate expires soon", "Medium", 0.95,
                f"The certificate expires in {days:.0f} day(s) (issuer: {tls.get('cert_issuer', 'unknown')}).",
                "An expired certificate takes the site offline for security-conscious users; "
                "last-minute renewals risk outages.",
                f"Certificate expires in {days:.0f} day(s); issuer {tls.get('cert_issuer', 'unknown')}.",
                "Renew now and set up automated renewal with expiry alerting.",
                "Re-run this assessment and confirm expiry is more than 30 days away.",
                url, ["https://wiki.mozilla.org/Security/Server_Side_TLS"]))

    # Negotiated protocol version
    version = (tls.get("tls_version") or "").upper().replace("_", " ").replace("V", "v")
    if tls.get("tls_version") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(_mk(
            f"Outdated TLS protocol negotiated ({tls.get('tls_version')})", "High", 0.9,
            f"The server negotiated {tls.get('tls_version')}, which has known cryptographic weaknesses.",
            "Outdated protocol versions are vulnerable to downgrade and decryption attacks; "
            "modern compliance standards require TLS 1.2+.",
            f"Negotiated protocol: {tls.get('tls_version')} for {url}.",
            "Disable TLS 1.0/1.1 (and SSL entirely); support TLS 1.2 as minimum, TLS 1.3 preferred.",
            "Re-run this assessment and confirm TLS 1.2+ is negotiated.",
            url, ["https://wiki.mozilla.org/Security/Server_Side_TLS"]))

    # HTTP -> HTTPS redirect
    if tls.get("http_redirects_to_https") is False:
        findings.append(_mk(
            "HTTP does not redirect to HTTPS", "Medium", 0.9,
            "The plain-HTTP version of the site does not redirect to HTTPS.",
            "Users who type the domain or follow an http:// link stay on unencrypted HTTP, "
            "exposed to eavesdropping and content injection.",
            f"Request to the http:// variant of {url} did not redirect to https://.",
            "Configure the web server to issue a 301 redirect from http:// to https:// for all paths.",
            "Visit the http:// URL and confirm you land on https://.",
            url, ["https://owasp.org/www-project-secure-headers/"]))

    # Mixed content (only observable signals from the HTML)
    if ctx.body:
        http_refs = sorted(set(re.findall(r'''(?:src|href)\s*=\s*["']http://[^"']+''', ctx.body, re.I)))
        if http_refs:
            findings.append(_mk(
                "Mixed content: page loads resources over HTTP", "Medium", 0.85,
                f"The HTTPS page references {len(http_refs)} resource(s) over plain HTTP.",
                "Active mixed content is blocked by browsers (breaking the page); passive mixed "
                "content leaks user behavior and can be tampered with.",
                "Examples:\n" + "\n".join(http_refs[:5]),
                "Serve all sub-resources over HTTPS and use protocol-relative or https:// URLs.",
                "Reload the page and confirm the browser reports no mixed-content warnings.",
                url, ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]))

    return findings
