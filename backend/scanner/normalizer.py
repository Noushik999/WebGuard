"""Finding normalization: stable fingerprints + deterministic ordering."""

from __future__ import annotations

import hashlib

from .schemas import SEVERITY_RANK, Finding


def fingerprint(f: Finding) -> str:
    """Stable identity for a finding across rescans: module + title + URL path."""
    key = f"{f.scanner}|{f.title}|{f.affected_url.split('?')[0].rstrip('/')}".lower()
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def normalize(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        f.fingerprint = fingerprint(f)
        # Keep the highest-confidence duplicate.
        if f.fingerprint not in seen or f.confidence > seen[f.fingerprint].confidence:
            seen[f.fingerprint] = f
    ordered = sorted(
        seen.values(), key=lambda f: (SEVERITY_RANK[f.severity], -f.confidence, f.title)
    )
    return ordered
