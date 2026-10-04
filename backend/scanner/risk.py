"""Deterministic risk engine: severity rules live in modules; this file turns
normalized findings into an explainable 0-100 score.

Model (documented in-app and in ARCHITECTURE.md):
    deduction(f) = SEVERITY_WEIGHT[f.severity] * f.confidence
    score = round(max(0, 100 - sum(deductions)))

Weights: Critical 25, High 15, Medium 8, Low 3, Informational 0.

The score measures ONLY what WebGuard checks. It is not a guarantee of security.
The deterministic engine is the source of truth; the AI layer only explains.
"""

from __future__ import annotations

from collections import Counter

from .schemas import Finding

SEVERITY_WEIGHT = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Informational": 0}

GRADE_BANDS = [
    (90, "Very strong baseline"),
    (75, "Good"),
    (60, "Needs improvement"),
    (40, "Significant concerns"),
    (0, "Serious security concerns"),
]


def score_findings(findings: list[Finding]) -> tuple[int, list[dict]]:
    """Return (score, breakdown) where breakdown explains each deduction."""
    breakdown = []
    total = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHT.get(f.severity, 0)
        deduction = round(weight * f.confidence, 2)
        total += deduction
        if deduction > 0:
            breakdown.append(
                {
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "weight": weight,
                    "deduction": deduction,
                }
            )
    breakdown.sort(key=lambda d: -d["deduction"])
    score = max(0, min(100, round(100 - total)))
    return score, breakdown


def grade(score: int) -> str:
    for threshold, label in GRADE_BANDS:
        if score >= threshold:
            return label
    return GRADE_BANDS[-1][1]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {s: counts.get(s, 0) for s in ("Critical", "High", "Medium", "Low", "Informational")}


def compare_fingerprints(
    old: dict[str, dict], new: dict[str, dict]
) -> dict:
    """Diff two assessments by finding fingerprint.

    Each dict: fingerprint -> {"severity": ..., "title": ...}
    Returns new/resolved/persistent findings + severity changes.
    """
    old_keys, new_keys = set(old), set(new)
    new_fps = new_keys - old_keys
    resolved_fps = old_keys - new_keys
    persistent = []
    severity_changes = []
    for fp in old_keys & new_keys:
        entry = {"fingerprint": fp, "title": new[fp]["title"],
                 "old_severity": old[fp]["severity"], "new_severity": new[fp]["severity"]}
        persistent.append(entry)
        if old[fp]["severity"] != new[fp]["severity"]:
            severity_changes.append(entry)
    return {
        "new": [{"fingerprint": fp, **new[fp]} for fp in sorted(new_fps)],
        "resolved": [{"fingerprint": fp, **old[fp]} for fp in sorted(resolved_fps)],
        "persistent": sorted(persistent, key=lambda e: e["title"]),
        "severity_changes": severity_changes,
        "new_count": len(new_fps),
        "resolved_count": len(resolved_fps),
        "persistent_count": len(old_keys & new_keys),
    }
