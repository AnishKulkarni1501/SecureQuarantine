"""Mongo evidence projection with SQL outbox/retry for cross-store recovery."""
import os

from pymongo import MongoClient
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .models import Analysis, EvidenceOutbox


def build_snapshot(analysis: Analysis) -> dict:
    return {
        "analysis_id": analysis.id,
        "file_id": analysis.file_id,
        "stage_status": analysis.stage_status,
        "completeness": analysis.completeness,
        "risk_score": analysis.risk_score,
        "recommendation": analysis.recommendation,
        "summary": analysis.summary,
        "correlations": analysis.correlations,
        "findings": [{"kind": f.kind, "title": f.title, "detail": f.detail, "source": f.source, "confidence": f.confidence} for f in analysis.findings],
        "functions": [{"address": f.address, "name": f.name, "pseudocode": f.pseudocode, "purpose": f.purpose, "capabilities": f.capabilities, "supporting_evidence": f.supporting_evidence, "limitations": f.limitations, "confidence": f.confidence, "model_name": f.model_name, "prompt_version": f.prompt_version} for f in analysis.functions],
        "events": [{"event_type": e.event_type, "observed_at": e.observed_at.isoformat(), "process": e.process, "target": e.target, "details": e.details, "source": e.source} for e in analysis.events],
    }


def queue_snapshot(db: Session, analysis_id: str) -> None:
    analysis = db.scalar(select(Analysis).options(selectinload(Analysis.findings), selectinload(Analysis.functions), selectinload(Analysis.events)).where(Analysis.id == analysis_id))
    if not analysis:
        return
    outbox = db.scalar(select(EvidenceOutbox).where(EvidenceOutbox.analysis_id == analysis_id))
    snapshot = build_snapshot(analysis)
    if outbox:
        outbox.payload = snapshot
        outbox.status = "pending"
        outbox.last_error = ""
    else:
        db.add(EvidenceOutbox(analysis_id=analysis_id, payload=snapshot))


def _client():
    uri = os.getenv("MONGO_URI", "").strip()
    if not uri:
        return None
    return MongoClient(uri, serverSelectionTimeoutMS=1500, connectTimeoutMS=1500)


def drain_snapshot(db: Session, analysis_id: str) -> bool:
    item = db.scalar(select(EvidenceOutbox).where(EvidenceOutbox.analysis_id == analysis_id))
    if not item:
        return True
    client = _client()
    if client is None:
        item.status = "pending"
        item.last_error = "Mongo URI not configured"
        item.attempts += 1
        db.commit()
        return False
    snapshot = item.payload
    try:
        database = client[os.getenv("MONGO_DATABASE", "securequarantine")]
        for collection_name, key in (("function_summaries", "functions"), ("sandbox_events", "events")):
            collection = database[collection_name]
            collection.delete_many({"analysis_id": analysis_id})
            docs = [{"analysis_id": analysis_id, **row} for row in snapshot[key]]
            if docs:
                collection.insert_many(docs, ordered=True)
        database["evidence_reports"].replace_one({"analysis_id": analysis_id}, {"analysis_id": analysis_id, **{k: v for k, v in snapshot.items() if k not in {"functions", "events"}}}, upsert=True)
        item.status = "synced"
        item.last_error = ""
        item.attempts += 1
        db.commit()
        return True
    except Exception as exc:
        item.status = "pending"
        item.last_error = type(exc).__name__[:200]
        item.attempts += 1
        db.commit()
        return False
    finally:
        client.close()


def drain_pending(db: Session, limit: int = 50) -> dict:
    items = list(db.scalars(select(EvidenceOutbox).where(EvidenceOutbox.status == "pending").order_by(EvidenceOutbox.updated_at).limit(limit)))
    synced = sum(drain_snapshot(db, item.analysis_id) for item in items)
    return {"attempted": len(items), "synced": synced, "pending": len(items) - synced}


def read_snapshot(analysis_id: str) -> dict | None:
    client = _client()
    if client is None:
        return None
    try:
        database = client[os.getenv("MONGO_DATABASE", "securequarantine")]
        report = database["evidence_reports"].find_one({"analysis_id": analysis_id}, {"_id": 0})
        if not report:
            return None
        report["functions"] = list(database["function_summaries"].find({"analysis_id": analysis_id}, {"_id": 0}))
        report["events"] = list(database["sandbox_events"].find({"analysis_id": analysis_id}, {"_id": 0}))
        return report
    finally:
        client.close()
