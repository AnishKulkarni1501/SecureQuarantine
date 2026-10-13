"""Celery worker for durable static-analysis jobs and automatic transient retries."""
import os

from celery import Celery
from sqlalchemy import select

from .analyzer import analyze_bytes
from .db import SessionLocal
from .models import Analysis, AuditLog, FileRecord, Finding
from .policy import assess_risk, correlate
from .evidence_store import drain_snapshot, queue_snapshot

broker = os.getenv("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
celery_app = Celery("securequarantine", broker=broker, backend=os.getenv("CELERY_RESULT_BACKEND", broker))
celery_app.conf.update(task_track_started=True, task_acks_late=True, worker_prefetch_multiplier=1, task_serializer="json", result_serializer="json", accept_content=["json"])


@celery_app.task(bind=True, name="securequarantine.run_static_analysis", max_retries=3, default_retry_delay=5)
def run_static_analysis(self, analysis_id: str):
    db = SessionLocal()
    try:
        analysis = db.get(Analysis, analysis_id)
        if not analysis:
            return {"status": "missing", "analysis_id": analysis_id}
        record = db.get(FileRecord, analysis.file_id)
        if not record:
            analysis.status = "failed"
            analysis.summary = "The managed artifact record is missing."
            db.commit()
            return {"status": "failed", "analysis_id": analysis_id}
        try:
            data = open(record.artifact_path, "rb").read()
            findings, static_score, static_recommendation, summary = analyze_bytes(data, record.file_type)
            for item in findings:
                analysis.findings.append(Finding(**item))
            analysis.stage_status = {**analysis.stage_status, "static": "completed", "correlation": "completed"}
            analysis.status = "completed"
            analysis.summary = summary
            analysis.correlations = correlate(findings, [], [])
            assessment = assess_risk(findings, [], [], "partial", analysis.stage_status)
            analysis.risk_score = max(static_score, assessment["score"])
            analysis.recommendation = static_recommendation if static_recommendation == "human_review" else assessment["recommendation"]
            analysis.completed_at = analysis.completed_at or __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
            queue_snapshot(db, analysis.id)
            db.add(AuditLog(file_id=record.id, analysis_id=analysis.id, operation="analysis.worker_complete", outcome="completed", reason="Static analysis worker completed; advanced stages remain explicit."))
            db.commit()
            drain_snapshot(db, analysis.id)
            return {"status": "completed", "analysis_id": analysis_id}
        except Exception as exc:
            db.rollback()
            try:
                raise self.retry(exc=exc)
            except self.MaxRetriesExceededError:
                failed = db.get(Analysis, analysis_id)
                if failed:
                    failed.status = "failed"
                    failed.stage_status = {**failed.stage_status, "static": "failed"}
                    failed.summary = "Static analysis failed after retry attempts; this is inconclusive."
                    db.add(AuditLog(file_id=failed.file_id, analysis_id=failed.id, operation="analysis.worker_failure", outcome="failed", reason=type(exc).__name__))
                    db.commit()
                raise
    finally:
        db.close()
