"""Standard finding schema. Every scanner module returns these."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class Finding(BaseModel):
    title: str
    category: str
    owasp_mapping: str = ""
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    why_it_matters: str
    evidence: str
    recommendation: str
    verification: str = ""
    references: list[str] = Field(default_factory=list)
    affected_url: str
    scanner: str  # module name, e.g. "security_headers"
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: str = ""  # filled in by the normalizer


class ScanContext(BaseModel):
    """Shared, bounded data collected once per assessment and handed to modules."""

    model_config = {"arbitrary_types_allowed": True}

    target_url: str          # validated, normalized
    final_url: str           # after redirects
    status_code: int
    headers: dict[str, str]  # lower-cased names
    raw_headers: list[tuple[str, str]]
    body: str                # truncated
    body_truncated: bool
    cookies: list[dict]      # parsed Set-Cookie
    redirect_chain: list[str]
    tls_info: dict           # {} for plain http
    extra_pages: dict[str, dict]  # path -> {status, headers, body}
    request_count: int = 0

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)
