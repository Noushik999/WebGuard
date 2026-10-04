"""Professional HTML security report generator (Jinja2).

Sections: executive summary, target info, date, scope, methodology, score,
findings summary, detailed findings, severity breakdown, remediation,
rescan comparison, limitations, authorization notice, references.
Print CSS is included so the report can be saved as PDF from any browser.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TPL_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TPL_DIR)),
    autoescape=select_autoescape(["html"]),
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _fmt_dt(dt) -> str:
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M %Z")


def build_report(
    *,
    assessment,
    target,
    findings: list,
    comparison: dict | None = None,
    generated_by: str = "",
    is_demo: bool = False,
) -> str:
    tpl = _env.get_template("report.html")
    sev_counts = assessment.severity_counts or {}
    by_severity: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        by_severity.get(f.severity, by_severity["Informational"]).append(f)

    top_remediations = []
    for s in SEVERITY_ORDER:
        for f in by_severity[s]:
            if f.severity in ("Critical", "High", "Medium"):
                top_remediations.append(f)
            if len(top_remediations) >= 8:
                break

    return tpl.render(
        now=_fmt_dt(datetime.now(timezone.utc)),
        assessment=assessment,
        target=target,
        findings=findings,
        by_severity=by_severity,
        sev_counts=sev_counts,
        severity_order=SEVERITY_ORDER,
        score=assessment.score,
        grade=(assessment.config or {}).get("grade", ""),
        score_breakdown=(assessment.config or {}).get("score_breakdown", []),
        module_errors=(assessment.config or {}).get("module_errors", {}),
        top_remediations=top_remediations,
        comparison=comparison,
        generated_by=generated_by,
        is_demo=is_demo or assessment.is_demo,
        fmt_dt=_fmt_dt,
    )
