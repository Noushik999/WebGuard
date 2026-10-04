"""CORS module: single non-destructive probe with a bogus Origin.

We send one GET with `Origin: https://webguard-probe.invalid` and observe whether
the server reflects it. No credentials are sent and nothing is accessed.
"""

from __future__ import annotations

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "cors"
CATEGORY = "Access Control"
OWASP = "A01:2021 – Broken Access Control"
PROBE_ORIGIN = "https://webguard-probe.invalid"


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url
    try:
        resp = client.get(url, headers={"Origin": PROBE_ORIGIN})
    except Exception as e:
        # Probe failure is not a finding; the main fetch already succeeded.
        ctx.extra_pages["cors_probe_error"] = {"error": str(e)[:200]}
        return findings

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    vary = resp.headers.get("vary", "").lower()

    if acao == PROBE_ORIGIN and acac:
        findings.append(_mk(
            "CORS reflects arbitrary origins with credentials allowed", "High", 0.95,
            "The server echoed our untrusted probe Origin in Access-Control-Allow-Origin and set "
            "Access-Control-Allow-Credentials: true.",
            "Any website can then make credentialed cross-origin requests and read the responses — "
            "effectively bypassing the same-origin policy for logged-in users (data theft, actions "
            "on their behalf).",
            f"Request Origin: {PROBE_ORIGIN}\n"
            f"Response Access-Control-Allow-Origin: {acao}\n"
            "Response Access-Control-Allow-Credentials: true",
            "Never reflect arbitrary Origin values. Allow-list exact trusted origins, validate the "
            "Origin server-side, and only send Access-Control-Allow-Credentials for those.",
            "Repeat the probe with curl and confirm the untrusted origin is no longer reflected.",
            url))
    elif acao == PROBE_ORIGIN:
        findings.append(_mk(
            "CORS reflects arbitrary origins", "Medium", 0.9,
            "The server echoed our untrusted probe Origin in Access-Control-Allow-Origin "
            "(without credentials).",
            "Any site can read responses cross-origin. Without credentials the impact is lower, but "
            "it still leaks data to arbitrary third parties and often indicates a misconfigured "
            "allow-list that may later be combined with credentials.",
            f"Request Origin: {PROBE_ORIGIN}\nResponse Access-Control-Allow-Origin: {acao}",
            "Allow-list exact trusted origins instead of reflecting the request Origin.",
            "Repeat the probe with curl and confirm the untrusted origin is no longer reflected.",
            url))
    elif acao == "*":
        if acac:
            findings.append(_mk(
                "CORS allows any origin (*) with credentials", "High", 0.95,
                "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.",
                "Browsers ignore this combination, but some frameworks mishandle it — and it signals "
                "a fundamentally permissive CORS design.",
                "Response Access-Control-Allow-Origin: *\nResponse Access-Control-Allow-Credentials: true",
                "Replace '*' with an explicit allow-list of trusted origins.",
                "Repeat the probe and confirm a strict allow-list.",
                url))
        else:
            findings.append(_mk(
                "CORS allows any origin (*)", "Low", 0.9,
                "Access-Control-Allow-Origin is '*' (without credentials).",
                "Any website can read non-credentialed responses. Acceptable for genuinely public APIs, "
                "but worth confirming it's intentional.",
                "Response Access-Control-Allow-Origin: *",
                "If the resource isn't meant to be public, restrict to an explicit origin allow-list.",
                "Review whether public cross-origin access is intended for this endpoint.",
                url))

    if acao and "origin" not in vary and acao not in ("*", PROBE_ORIGIN):
        findings.append(_mk(
            "CORS response may be cache-poisoned (missing Vary: Origin)", "Low", 0.7,
            "The response includes Access-Control-Allow-Origin but no `Vary: Origin` header.",
            "Caches may serve a response with one site's CORS headers to a different origin, "
            "leaking data or breaking legitimate clients.",
            f"Access-Control-Allow-Origin: {acao}\nVary: {resp.headers.get('vary', '(absent)')}",
            "Add `Vary: Origin` whenever CORS headers vary by request origin.",
            "Re-run this assessment and confirm Vary includes Origin.",
            url))

    return findings
