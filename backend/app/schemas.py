"""Pydantic request/response schemas for the REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
FindingStatus = Literal["Open", "Fixed", "Accepted Risk", "False Positive"]


# ---------- Auth ----------
class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    is_admin: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ---------- Targets ----------
class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    description: str = Field(default="", max_length=2000)
    scope: str = Field(default="", max_length=2000)
    auth_confirmed: bool = False

    @field_validator("auth_confirmed")
    @classmethod
    def must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm that you own this target or have explicit permission to assess it."
            )
        return v


class TargetOut(BaseModel):
    id: int
    name: str
    url: str
    description: str
    scope: str
    auth_confirmed: bool
    auth_confirmed_at: datetime | None
    is_demo: bool
    created_at: datetime
    assessment_count: int = 0
    latest_score: int | None = None


# ---------- Assessments ----------
class AssessmentSummaryOut(BaseModel):
    id: int
    target_id: int
    target_name: str = ""
    status: str
    progress: int
    current_stage: str
    score: int | None
    findings_count: int
    severity_counts: dict
    is_demo: bool
    error: str | None
    duration_s: float | None
    created_at: datetime
    finished_at: datetime | None


class AssessmentDetailOut(AssessmentSummaryOut):
    scanner_version: str
    module_errors: dict = {}
    score_breakdown: list[dict] = []
    grade: str = ""


class FindingOut(BaseModel):
    id: int
    assessment_id: int
    fingerprint: str
    title: str
    category: str
    owasp_mapping: str
    severity: Severity
    confidence: float
    description: str
    why_it_matters: str
    evidence: str
    recommendation: str
    verification: str
    references: list[str]
    affected_url: str
    scanner: str
    detected_at: datetime
    status: str
    ai_analysis: dict | None = None


class FindingStatusIn(BaseModel):
    status: FindingStatus


# ---------- Comparison ----------
class ComparisonOut(BaseModel):
    assessment_a_id: int
    assessment_b_id: int
    score_a: int | None
    score_b: int | None
    score_delta: int | None
    new: list[dict]
    resolved: list[dict]
    persistent: list[dict]
    severity_changes: list[dict]
    new_count: int
    resolved_count: int
    persistent_count: int


# ---------- Dashboard ----------
class DashboardOut(BaseModel):
    target_count: int
    assessment_count: int
    completed_count: int
    running_count: int
    latest_score: int | None
    score_history: list[dict]
    severity_totals: dict
    top_findings: list[dict]
    recent_assessments: list[AssessmentSummaryOut]


# ---------- AI ----------
class AIAnalysisOut(BaseModel):
    plain_english: str
    technical: str
    impact: str
    priority: str
    remediation_steps: list[str]
    verification: str
    confidence_note: str
    source: str  # "rules" | "llm"
