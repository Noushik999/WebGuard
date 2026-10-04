"""Technology-fingerprint module: passive identification of visible stack signals.

We identify technologies from volunteered signals (headers, meta tags, script URLs)
and compare library versions against a small bundled advisory list.

HONESTY RULE: a detected old version is reported as "outdated version detected —
vulnerability NOT confirmed". We never claim a CVE applies without confirmation.
"""

from __future__ import annotations

import re

from ..http_client import SafeHttpClient
from ..schemas import Finding, ScanContext

NAME = "tech"
CATEGORY = "Software / Dependency Risk"
OWASP = "A06:2021 – Vulnerable and Outdated Components"

# (regex on script src / body, library name, latest-known-good major line, advisory note)
LIBRARY_SIGNALS = [
    (r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "jQuery", "3.7",
     "jQuery versions before 3.5.0 have known XSS CVEs (e.g. CVE-2020-11022/11023)."),
    (r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)", "Bootstrap", "5.3",
     "Bootstrap 4.x and earlier have known XSS issues in some components."),
    (r"angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "AngularJS", "1.8",
     "AngularJS 1.x is end-of-life; many template-injection CVEs exist in old releases."),
    (r"react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "React", "18.3",
     "Old React releases may miss security fixes; keep current."),
    (r"vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "Vue.js", "3.4",
     "Old Vue 2.x releases are end-of-life; migrate to Vue 3."),
    (r"lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "Lodash", "4.17",
     "Lodash before 4.17.21 has prototype-pollution CVEs (e.g. CVE-2020-28500)."),
    (r"moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", "Moment.js", "2.30",
     "Moment.js is in maintenance mode; old versions have ReDoS/path-traversal issues."),
]

TECH_HEADER_HINTS = {
    "x-powered-by": "framework",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "generator",
}


def _older(v: str, ref: str) -> bool:
    def parts(s):
        return [int(x) for x in re.findall(r"\d+", s)][:3]
    try:
        return parts(v) < parts(ref)
    except Exception:
        return False


def _mk(title, severity, confidence, description, why, evidence, recommendation,
        verification, affected_url, vuln_confirmed: bool) -> Finding:
    suffix = "" if vuln_confirmed else (
        "\n\nNote: WebGuard detected the version from public page content. "
        "A specific vulnerability is NOT confirmed — this is a risk signal, not proof of exploitability.")
    return Finding(
        title=title, category=CATEGORY, owasp_mapping=OWASP, severity=severity,
        confidence=confidence, description=description, why_it_matters=why,
        evidence=evidence, recommendation=recommendation + suffix, verification=verification,
        references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        affected_url=affected_url, scanner=NAME,
    )


def run(ctx: ScanContext, client: SafeHttpClient) -> list[Finding]:
    findings: list[Finding] = []
    url = ctx.final_url
    seen: set[str] = set()

    haystack = ctx.body or ""
    for pattern, lib, latest, note in LIBRARY_SIGNALS:
        for m in re.finditer(pattern, haystack, re.I):
            version = m.group(1)
            key = f"{lib}@{version}"
            if key in seen:
                continue
            seen.add(key)
            outdated = _older(version, latest)
            findings.append(_mk(
                f"{'Outdated' if outdated else 'Detected'} JavaScript library: {lib} {version}",
                "Medium" if outdated else "Informational",
                0.75 if outdated else 0.9,
                f"The page loads {lib} version {version} (latest line known to WebGuard: {latest}). {note if outdated else ''}",
                "Outdated client-side libraries are a common entry point: known CVEs in old versions "
                "are exploited at scale by automated scanners.",
                f"Matched reference: {m.group(0)[:120]}",
                f"Upgrade {lib} to a currently supported release ({latest}+ line) and re-test the site.",
                "View page source, confirm the library version, and check it against the vendor's security advisories.",
                url, vuln_confirmed=False))

    # Server/framework hints are informational inventory (versions covered in disclosure module).
    server = ctx.header("server")
    if server and "webguard" not in server.lower():
        findings.append(_mk(
            f"Web server identified: {server[:80]}", "Informational", 0.85,
            f"The Server header identifies '{server}'.",
            "Knowing the stack helps defenders keep the right components patched; attackers use the "
            "same information for targeting.",
            f"Server: {server}",
            "Keep this component patched and subscribe to its security announcements.",
            "Confirm the component version against vendor advisories.",
            url, vuln_confirmed=False))

    return findings
