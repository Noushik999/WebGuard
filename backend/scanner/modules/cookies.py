"""Cookie-security module: inspects Set-Cookie flags (no session theft, ever)."""

from __future__ import annotations

from ..http_client import SafeHttpClient, looks_session_cookie
from ..schemas import Finding, ScanContext

NAME = "cookies"
CATEGORY = "Session / Cookie Security"
OWASP = "A01:2021 – Broken Access Control"


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=["https://owasp.org/www-community/controls/SecureCookieAttribute",
                    "https://owasp.org/www-community/HttpOnly"],
        affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url
    is_https = url.startswith("https://")

    for cookie in ctx.cookies:
        name = cookie["name"]
        session_like = looks_session_cookie(name)
        base_sev = "High" if session_like else "Medium"

        if is_https and not cookie["secure"]:
            findings.append(_mk(
                f"Cookie '{name}' missing Secure flag",
                base_sev, 0.95,
                f"The cookie '{name}' is set without the Secure attribute on an HTTPS site.",
                "Without Secure, the browser may send the cookie over plain HTTP (e.g. after a "
                "downgrade or to an http:// URL), exposing it to network eavesdroppers. "
                + ("This cookie name looks session-related, so theft could mean account takeover." if session_like else ""),
                f"Set-Cookie: {name}=... (Secure flag absent; HttpOnly={cookie['httponly']}, SameSite={cookie['samesite']})",
                f"Add `Secure` to the Set-Cookie for '{name}'. Serve the cookie only over HTTPS.",
                f"Inspect cookies in browser devtools for {url} and confirm Secure is set.",
                url))

        if not cookie["httponly"]:
            findings.append(_mk(
                f"Cookie '{name}' missing HttpOnly flag",
                base_sev if session_like else "Low", 0.95,
                f"The cookie '{name}' is set without the HttpOnly attribute.",
                "Without HttpOnly, JavaScript can read the cookie — so any cross-site scripting (XSS) "
                "flaw can immediately steal it. "
                + ("This cookie name looks session-related, making XSS-to-account-takeover much easier." if session_like else ""),
                f"Set-Cookie: {name}=... (HttpOnly flag absent)",
                f"Add `HttpOnly` to the Set-Cookie for '{name}' unless JavaScript genuinely needs to read it.",
                f"Inspect cookies in browser devtools for {url} and confirm HttpOnly is set.",
                url))

        samesite = (cookie["samesite"] or "")
        if not samesite:
            findings.append(_mk(
                f"Cookie '{name}' missing SameSite attribute",
                "Low", 0.9,
                f"The cookie '{name}' has no SameSite attribute, so browsers apply their default (Lax).",
                "Explicit SameSite is the primary defense against cross-site request forgery (CSRF); "
                "relying on browser defaults is fragile.",
                f"Set-Cookie: {name}=... (SameSite attribute absent)",
                f"Set `SameSite=Lax` (or `Strict` for sensitive cookies) on '{name}'. Use `SameSite=None; Secure` "
                "only if cross-site usage is genuinely required.",
                f"Inspect cookies in browser devtools for {url} and confirm SameSite is set.",
                url))
        elif samesite == "None" and not cookie["secure"]:
            findings.append(_mk(
                f"Cookie '{name}' uses SameSite=None without Secure",
                "Medium", 0.95,
                f"The cookie '{name}' sets SameSite=None without the Secure attribute.",
                "Browsers reject SameSite=None cookies without Secure, so the cookie may not work — "
                "and the intent (cross-site sending) weakens CSRF protection.",
                f"Set-Cookie: {name}=... (SameSite=None without Secure)",
                "Either add `Secure` (and keep None only if cross-site is required) or switch to `SameSite=Lax`.",
                f"Inspect cookies in browser devtools for {url} and confirm the flags.",
                url))

    return findings
