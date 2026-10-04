"""HTTP-configuration module: observable server behavior (no destructive testing).

We only *observe* what the server advertises (e.g. Allow headers on OPTIONS) —
we never send PUT/DELETE/TRACE or attempt state-changing requests.
"""

from __future__ import annotations

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "http_config"
CATEGORY = "Security Misconfiguration"
OWASP = "A05:2021 – Security Misconfiguration"

RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url) -> Finding:
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation, verification=verification,
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
        affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url

    # OPTIONS: observe advertised methods only.
    try:
        resp = client.options(url)
        allow = resp.headers.get("allow", "")
        if allow:
            advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = sorted(advertised & RISKY_METHODS)
            if risky:
                sev = "Medium" if "TRACE" in risky or "PUT" in risky else "Low"
                findings.append(_mk(
                    f"Potentially unsafe HTTP methods advertised: {', '.join(risky)}",
                    sev, 0.8,
                    f"The server's OPTIONS response advertises: {allow}.",
                    "TRACE enables cross-site tracing (a variant of XSS data theft); PUT/DELETE may "
                    "allow file upload or deletion if the application also fails to authorize them. "
                    "WebGuard only observed the advertisement — it did not test these methods.",
                    f"OPTIONS {url} → Allow: {allow}",
                    "Disable unneeded methods at the server/proxy level (allow only GET, HEAD, POST, "
                    "OPTIONS where required); ensure authorization is enforced per method.",
                    "Send OPTIONS to the URL and confirm only required methods are advertised.",
                    url))
    except Exception:
        pass

    # Redirect chain sanity: too many hops or http downgrade inside chain.
    chain = ctx.redirect_chain or []
    if len(chain) > 3:
        findings.append(_mk(
            "Long redirect chain", "Low", 0.85,
            f"Fetching the target followed {len(chain)} redirects.",
            "Long chains slow the site, complicate security analysis and can mask open-redirect issues.",
            "Chain:\n" + "\n".join(f"  {i+1}. {u}" for i, u in enumerate(chain[:8])),
            "Reduce redirects to the minimum necessary (ideally one hop to the canonical HTTPS URL).",
            "Fetch the target URL and count the redirects.",
            url))
    for hop in chain[1:]:
        if hop.startswith("http://") and url.startswith("https://"):
            findings.append(_mk(
                "Redirect chain downgrades to HTTP", "High", 0.95,
                "A redirect in the chain goes from HTTPS back to plain HTTP.",
                "Users end up on an unencrypted page where traffic can be intercepted and modified.",
                "Chain:\n" + "\n".join(f"  {i+1}. {u}" for i, u in enumerate(chain[:8])),
                "Ensure every redirect in the chain stays on HTTPS.",
                "Fetch the target and confirm no hop uses http://.",
                url))
            break

    return findings
