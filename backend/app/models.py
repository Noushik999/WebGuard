"""SQLAlchemy models. Timestamps everywhere; no secrets stored in plaintext."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    targets: Mapped[list["Target"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    scope: Mapped[str] = mapped_column(Text, default="", nullable=False)
    auth_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    auth_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    owner: Mapped["User"] = relationship(back_populates="targets")
    assessments: Mapped[list["Assessment"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", order_by="Assessment.created_at.desc()"
    )


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="QUEUED", index=True, nullable=False)
    # QUEUED -> VALIDATING -> RUNNING -> ANALYZING -> GENERATING_RESULTS -> COMPLETED | FAILED | CANCELLED
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0-100
    current_stage: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    severity_counts: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)

    target: Mapped["Target"] = relationship(back_populates="assessments")
    findings: Mapped[list["FindingInstance"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class FindingInstance(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    owasp_mapping: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    why_it_matters: Mapped[str] = mapped_column(Text, default="", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    verification: Mapped[str] = mapped_column(Text, default="", nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    affected_url: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="Open", nullable=False)
    # Open | Fixed | Accepted Risk | False Positive
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    assessment: Mapped["Assessment"] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_findings_assessment_severity", "assessment_id", "severity"),)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    format: Mapped[str] = mapped_column(String(16), default="html", nullable=False)
    html: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
