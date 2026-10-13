from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, JSON, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now_utc():
    return datetime.now(timezone.utc)


class FileRecord(Base):
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    file_type: Mapped[str] = mapped_column(String(80))
    static_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    disposition: Mapped[str] = mapped_column(String(24), default="managed")
    artifact_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="file", cascade="all, delete-orphan")


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    recommendation: Mapped[str] = mapped_column(String(32), default="analyze_further")
    completeness: Mapped[str] = mapped_column(String(24), default="partial")
    summary: Mapped[str] = mapped_column(Text, default="Analysis has not completed.")
    stage_status: Mapped[dict] = mapped_column(JSON, default=lambda: {"static": "pending", "decompile": "not_configured", "interpretation": "not_configured", "sandbox": "not_configured", "correlation": "pending"})
    correlations: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    file: Mapped[FileRecord] = relationship(back_populates="analyses")
    findings: Mapped[list["Finding"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    functions: Mapped[list["FunctionSummary"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")
    events: Mapped[list["SandboxEvent"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(200))
    detail: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class FunctionSummary(Base):
    __tablename__ = "function_summaries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(200), default="unknown")
    pseudocode: Mapped[str] = mapped_column(Text, default="")
    purpose: Mapped[str] = mapped_column(Text)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    supporting_evidence: Mapped[list] = mapped_column(JSON, default=list)
    limitations: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    model_name: Mapped[str] = mapped_column(String(160))
    prompt_version: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    analysis: Mapped[Analysis] = relationship(back_populates="functions")


class SandboxEvent(Base):
    __tablename__ = "sandbox_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    process: Mapped[str] = mapped_column(String(500), default="")
    target: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(80), default="isolated_vm")
    analysis: Mapped[Analysis] = relationship(back_populates="events")


class AnalystCorrection(Base):
    __tablename__ = "analyst_corrections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    decision: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(24))
    note: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)


class EvidenceOutbox(Base):
    __tablename__ = "evidence_outbox"
    __table_args__ = (UniqueConstraint("analysis_id", name="uq_evidence_outbox_analysis"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    file_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    analysis_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    operation: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(120), default="local-analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
