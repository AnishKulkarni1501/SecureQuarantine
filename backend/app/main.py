import hashlib
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .analyzer import analyze_bytes, extract_metadata, identify
from .db import Base, engine, get_db, migrate_legacy_sqlite_schema
from .models import Analysis, AnalystCorrection, AuditLog, EvidenceOutbox, FileRecord, Finding, FunctionSummary, SandboxEvent
from .schemas import AnalysisDetail, AnalysisOut, DispositionRequest, FileOut
from .auth import Actor, analyst, reviewer
from .adapters import AdapterUnavailable, ghidra_decompile, interpret_function, refine_pseudocode, run_isolated_sandbox, sandbox_is_configured
from .contracts import AnalystCorrection as AnalystCorrectionIn, EnrichmentRequest
from .policy import assess_risk, correlate
from .evidence_store import drain_pending, drain_snapshot, queue_snapshot, read_snapshot


ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", Path(__file__).resolve().parents[1] / "data" / "artifacts"))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_BYTES", 50 * 1024 * 1024))
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
Base.metadata.create_all(bind=engine)
migrate_legacy_sqlite_schema()

app = FastAPI(title="SecureQuarantine API", version="0.1.0", description="Local prototype. Uploaded binaries are inspected as bytes; dynamic execution is available only when an analyst opts into a configured sandbox worker.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"])


def audit(db: Session, operation: str, outcome: str, reason: str = "", file_id: str | None = None, analysis_id: str | None = None, actor: str = "local-analyst"):
    db.add(AuditLog(operation=operation, outcome=outcome, reason=reason, file_id=file_id, analysis_id=analysis_id, actor=actor))


async def sandbox_result(data: bytes, sha256: str):
    try:
        return await run_isolated_sandbox(data, sha256), None
    except Exception as exc:
        return None, exc


@app.get("/api/health")
def health():
    sandbox_mode = os.getenv("SANDBOX_MODE", "hardened_vm").strip().lower()
    return {"status": "ok", "mode": os.getenv("APP_ENV", "development"), "sample_execution": False, "sandbox_mode": sandbox_mode if sandbox_is_configured() else None, "configured": {"mysql_or_sqlite": True, "mongodb": bool(os.getenv("MONGO_URI")), "celery": bool(os.getenv("CELERY_BROKER_URL")), "ghidra": bool(os.getenv("GHIDRA_WORKER_URL")), "llm4decompile": bool(os.getenv("LLM4DECOMPILE_URL")), "zysec_interpreter": bool(os.getenv("ZYSEC_INTERPRETER_URL")), "sandbox": sandbox_is_configured()}}


@app.post("/api/files", response_model=FileOut, status_code=201)
async def upload_file(file: UploadFile = File(...), actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    name = Path(file.filename or "unnamed").name[:255]
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(1024 * 1024):
        total += len(chunk)
        if total > MAX_UPLOAD:
            raise HTTPException(413, f"File exceeds the {MAX_UPLOAD // (1024 * 1024)} MiB upload limit")
        chunks.append(chunk)
        digest.update(chunk)
    if total == 0:
        raise HTTPException(400, "Empty files are not accepted")
    sha256 = digest.hexdigest()
    existing = db.scalar(select(FileRecord).where(FileRecord.sha256 == sha256))
    if existing:
        audit(db, "file.upload_duplicate", "accepted", "Existing content hash reused.", existing.id, actor=actor.name)
        db.commit()
        return existing
    data = b"".join(chunks)
    record_id = str(uuid4())
    destination = ARTIFACT_DIR / record_id
    destination.write_bytes(data)
    record = FileRecord(id=record_id, filename=name, size=total, sha256=sha256, file_type=identify(data), static_metadata=extract_metadata(data), artifact_path=str(destination))
    db.add(record)
    audit(db, "file.upload", "accepted", f"Stored {total} bytes; no execution performed.", record_id, actor=actor.name)
    db.commit()
    db.refresh(record)
    return record


@app.get("/api/files", response_model=list[FileOut])
def list_files(actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    return list(db.scalars(select(FileRecord).order_by(FileRecord.created_at.desc()).limit(200)))


@app.post("/api/analyses", response_model=AnalysisOut, status_code=201)
def submit_analysis(file_id: str, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    record = db.get(FileRecord, file_id)
    if not record:
        raise HTTPException(404, "File not found")
    if os.getenv("CELERY_BROKER_URL"):
        stage_status = {"static": "queued", "decompile": "not_configured", "llm4decompile": "not_configured", "interpretation": "not_configured", "sandbox": "not_configured", "correlation": "pending"}
        analysis = Analysis(file_id=record.id, status="queued", recommendation="analyze_further", completeness="partial", summary="Static analysis is queued. No safety conclusion is available yet.", stage_status=stage_status)
        db.add(analysis)
        db.flush()
        audit(db, "analysis.queued", "accepted", "Static work submitted to Celery/Redis.", record.id, analysis.id, actor.name)
        db.commit()
        try:
            from .worker import run_static_analysis
            run_static_analysis.delay(analysis.id)
        except Exception as exc:
            analysis.status = "failed"
            analysis.stage_status = {**analysis.stage_status, "static": "failed"}
            analysis.summary = "Job queue unavailable. Retry after restoring the worker service."
            audit(db, "analysis.enqueue", "failed", type(exc).__name__, record.id, analysis.id, actor.name)
            db.commit()
        db.refresh(analysis)
        return analysis
    data = Path(record.artifact_path).read_bytes()
    findings, score, recommendation, summary = analyze_bytes(data, record.file_type)
    stage_status = {"static": "completed", "decompile": "not_configured", "llm4decompile": "not_configured", "interpretation": "not_configured", "sandbox": "not_configured", "correlation": "completed"}
    initial_risk = assess_risk([], [], [], "partial", stage_status)
    analysis = Analysis(file_id=record.id, status="completed", risk_score=max(score, initial_risk["score"]), recommendation=recommendation if recommendation == "human_review" else initial_risk["recommendation"], completeness="partial", summary=summary, stage_status=stage_status, correlations={}, completed_at=datetime.now(timezone.utc))
    db.add(analysis)
    db.flush()
    for item in findings:
        analysis.findings.append(Finding(**item))
    assessment = assess_risk(findings, [], [], "partial", stage_status)
    analysis.risk_score = max(score, assessment["score"])
    analysis.recommendation = recommendation if recommendation == "human_review" else assessment["recommendation"]
    analysis.correlations = correlate(findings, [], [])
    queue_snapshot(db, analysis.id)
    audit(db, "analysis.complete", "completed", "Byte-only static baseline; dynamic and AI stages unavailable.", record.id, analysis.id, actor=actor.name)
    db.commit()
    drain_snapshot(db, analysis.id)
    db.refresh(analysis)
    return analysis


@app.post("/api/analyses/{analysis_id}/enrich", response_model=AnalysisDetail)
async def enrich_analysis(analysis_id: str, request: EnrichmentRequest, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    analysis = db.scalar(select(Analysis).options(selectinload(Analysis.file), selectinload(Analysis.findings), selectinload(Analysis.functions), selectinload(Analysis.events)).where(Analysis.id == analysis_id))
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    data = Path(analysis.file.artifact_path).read_bytes()
    sandbox_task = asyncio.create_task(sandbox_result(data, analysis.file.sha256)) if request.include_sandbox else None
    if request.include_ai:
        try:
            report = await ghidra_decompile(data, analysis.file.filename)
            analysis.stage_status["decompile"] = "completed"
            analysis.stage_status["ghidra_version"] = report.tool_version
            for function in report.functions[:100]:
                pseudocode = function.pseudocode
                model_name, prompt_version = "ghidra-baseline", "baseline-v1"
                try:
                    refined = await refine_pseudocode(function.model_dump())
                    pseudocode, model_name, prompt_version = refined.pseudocode, refined.model_name, refined.prompt_version
                    analysis.stage_status["llm4decompile"] = "completed"
                except AdapterUnavailable as exc:
                    analysis.stage_status["llm4decompile"] = "not_configured" if "not configured" in str(exc) else "failed"
                try:
                    interpretation = await interpret_function({"address": function.address, "name": function.name, "pseudocode": pseudocode})
                    analysis.functions.append(FunctionSummary(address=function.address, name=function.name, pseudocode=pseudocode, purpose=interpretation.purpose, capabilities=interpretation.capabilities, supporting_evidence=interpretation.supporting_evidence, limitations=[*report.limitations, *interpretation.limitations], confidence=interpretation.confidence, model_name=interpretation.model_name, prompt_version=interpretation.prompt_version))
                    analysis.stage_status["interpretation"] = "completed"
                except AdapterUnavailable as exc:
                    analysis.stage_status["interpretation"] = "not_configured" if "not configured" in str(exc) else "failed"
                    audit(db, "analysis.function_interpretation", "inconclusive", str(exc), analysis.file_id, analysis.id, actor.name)
        except AdapterUnavailable as exc:
            analysis.stage_status["decompile"] = "not_configured" if "not configured" in str(exc) else "failed"
            analysis.stage_status["interpretation"] = "not_run"
            audit(db, "analysis.ghidra", "inconclusive", str(exc), analysis.file_id, analysis.id, actor.name)
    if request.include_sandbox:
        try:
            report, sandbox_error = await sandbox_task
            if sandbox_error:
                raise sandbox_error
            analysis.events.clear()
            for event in report.events:
                analysis.events.append(SandboxEvent(event_type=event.event_type, observed_at=event.observed_at, process=event.process, target=event.target, details=event.details, source=event.source))
            analysis.stage_status["sandbox"] = "completed" if report.complete else "incomplete"
            audit(db, "analysis.sandbox", "completed" if report.complete else "incomplete", f"{os.getenv('SANDBOX_MODE', 'hardened_vm')} worker run {report.run_id}; {len(report.events)} events. Limitations: {'; '.join(report.limitations)[:600]}", analysis.file_id, analysis.id, actor.name)
        except AdapterUnavailable as exc:
            analysis.stage_status["sandbox"] = "not_configured" if "disabled" in str(exc) or "not configured" in str(exc) else "failed"
            audit(db, "analysis.sandbox", "inconclusive", str(exc), analysis.file_id, analysis.id, actor.name)
    analysis.stage_status = dict(analysis.stage_status)
    db.flush()
    analysis.correlations = correlate(analysis.findings, analysis.functions, analysis.events)
    all_stages_done = all(analysis.stage_status.get(k) == "completed" for k in ("static", "decompile", "llm4decompile", "interpretation", "sandbox"))
    analysis.completeness = "complete" if all_stages_done else "partial"
    assessment = assess_risk(analysis.findings, analysis.functions, analysis.events, analysis.completeness, analysis.stage_status)
    analysis.risk_score = assessment["score"]
    analysis.recommendation = assessment["recommendation"]
    queue_snapshot(db, analysis.id)
    audit(db, "analysis.enrich", "completed", "Optional analysis stages requested; unavailable stages remain explicit.", analysis.file_id, analysis.id, actor.name)
    db.commit()
    drain_snapshot(db, analysis.id)
    return db.scalar(select(Analysis).options(selectinload(Analysis.file), selectinload(Analysis.findings), selectinload(Analysis.functions), selectinload(Analysis.events)).where(Analysis.id == analysis_id))


@app.post("/api/analyses/{analysis_id}/retry", response_model=AnalysisOut)
def retry_analysis(analysis_id: str, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    if not os.getenv("CELERY_BROKER_URL"):
        raise HTTPException(503, "Durable retry requires CELERY_BROKER_URL and a running Celery worker")
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    if analysis.status != "failed":
        raise HTTPException(409, "Only failed jobs can be retried")
    analysis.status = "queued"
    analysis.stage_status = {**analysis.stage_status, "static": "queued"}
    analysis.summary = "Static analysis retry is queued. No safety conclusion is available yet."
    audit(db, "analysis.retry", "queued", "Analyst requested a retry.", analysis.file_id, analysis.id, actor.name)
    db.commit()
    try:
        from .worker import run_static_analysis
        run_static_analysis.delay(analysis.id)
    except Exception as exc:
        analysis.status = "failed"
        analysis.stage_status = {**analysis.stage_status, "static": "failed"}
        audit(db, "analysis.retry_enqueue", "failed", type(exc).__name__, analysis.file_id, analysis.id, actor.name)
        db.commit()
    db.refresh(analysis)
    return analysis


@app.post("/api/analyses/{analysis_id}/corrections")
def record_correction(analysis_id: str, correction: AnalystCorrectionIn, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    analysis = db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    db.add(AnalystCorrection(analysis_id=analysis.id, decision=correction.decision, label=correction.label, note=correction.note.strip(), actor=actor.name))
    audit(db, "analysis.analyst_correction", "recorded", correction.note.strip(), analysis.file_id, analysis.id, actor.name)
    db.commit()
    return {"status": "recorded", "analysis_id": analysis.id}


@app.get("/api/evaluation/summary")
def evaluation_summary(actor: Actor = Depends(reviewer), db: Session = Depends(get_db)):
    rows = list(db.scalars(select(AnalystCorrection).order_by(AnalystCorrection.created_at)))
    labeled = [row for row in rows if row.label in {"benign", "malicious"}]
    analyses = {a.id: a for a in db.scalars(select(Analysis).where(Analysis.id.in_([r.analysis_id for r in labeled])))} if labeled else {}
    outcomes = []
    for row in labeled:
        analysis = analyses.get(row.analysis_id)
        if not analysis:
            continue
        predicted_malicious = analysis.recommendation in {"quarantine", "human_review"}
        actual_malicious = row.label == "malicious"
        outcomes.append((predicted_malicious, actual_malicious))
    tp = sum(pred and actual for pred, actual in outcomes)
    fp = sum(pred and not actual for pred, actual in outcomes)
    fn = sum(not pred and actual for pred, actual in outcomes)
    tn = sum(not pred and not actual for pred, actual in outcomes)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    return {"labeled_corrections": len(outcomes), "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn}, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None, "caveat": "Exploratory only. Analyst-labeled corrections are not an independent, lineage-split benchmark set."}


@app.get("/api/analyses", response_model=list[AnalysisOut])
def list_analyses(actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    return list(db.scalars(select(Analysis).order_by(Analysis.created_at.desc()).limit(200)))


@app.get("/api/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: str, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    analysis = db.scalar(select(Analysis).options(selectinload(Analysis.file), selectinload(Analysis.findings), selectinload(Analysis.functions), selectinload(Analysis.events)).where(Analysis.id == analysis_id))
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    return analysis


@app.get("/api/analyses/{analysis_id}/evidence")
def get_evidence(analysis_id: str, actor: Actor = Depends(analyst), db: Session = Depends(get_db)):
    analysis = db.scalar(select(Analysis).options(selectinload(Analysis.findings)).where(Analysis.id == analysis_id))
    if not analysis:
        raise HTTPException(404, "Analysis not found")
    try:
        stored = read_snapshot(analysis_id)
    except Exception:
        stored = None
    if stored:
        sandbox_limitation = "Docker dynamic analysis supports Linux ELF64 x86-64 only; its container shares the WSL2 Linux kernel and is not a disposable VM." if os.getenv("SANDBOX_MODE", "").lower() == "docker_wsl2" else "Sandbox execution is a separate, opt-in isolated VM stage."
        return {**stored, "mongo_sync": "synced", "limitations": [sandbox_limitation, "AI-generated function interpretations are hypotheses, not recovered ground truth.", "Absence of a string match or runtime event is not evidence of safety."]}
    pending = db.scalar(select(EvidenceOutbox).where(EvidenceOutbox.analysis_id == analysis_id))
    sandbox_limitation = "Docker dynamic analysis supports Linux ELF64 x86-64 only; its container shares the WSL2 Linux kernel and is not a disposable VM." if os.getenv("SANDBOX_MODE", "").lower() == "docker_wsl2" else "Sandbox execution is a separate, opt-in isolated VM stage."
    return {"analysis_id": analysis.id, "completeness": analysis.completeness, "findings": [{"kind": f.kind, "title": f.title, "detail": f.detail, "source": f.source, "confidence": f.confidence} for f in analysis.findings], "functions": [{"address": f.address, "name": f.name, "purpose": f.purpose, "capabilities": f.capabilities, "confidence": f.confidence, "model_name": f.model_name, "prompt_version": f.prompt_version} for f in analysis.functions], "events": [{"event_type": e.event_type, "observed_at": e.observed_at, "process": e.process, "target": e.target, "details": e.details} for e in analysis.events], "correlations": analysis.correlations, "mongo_sync": pending.status if pending else "not_queued", "limitations": [sandbox_limitation, "AI-generated function interpretations are hypotheses, not recovered ground truth.", "Absence of a string match or runtime event is not evidence of safety."]}


@app.post("/api/files/{file_id}/{action}", response_model=FileOut)
def set_disposition(file_id: str, action: str, request: DispositionRequest, actor: Actor = Depends(reviewer), db: Session = Depends(get_db)):
    if action not in {"quarantine", "release"}:
        raise HTTPException(404, "Unknown disposition action")
    record = db.get(FileRecord, file_id)
    if not record:
        raise HTTPException(404, "File not found")
    if not request.reason.strip():
        raise HTTPException(422, "A reason is required")
    record.disposition = "quarantined" if action == "quarantine" else "managed"
    audit(db, f"file.{action}", "recorded", request.reason.strip()[:2000], record.id, actor=actor.name)
    db.commit()
    db.refresh(record)
    return record


@app.get("/api/audit")
def list_audit(actor: Actor = Depends(reviewer), db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500))
    return [{"id": r.id, "file_id": r.file_id, "analysis_id": r.analysis_id, "operation": r.operation, "outcome": r.outcome, "reason": r.reason, "actor": r.actor, "created_at": r.created_at} for r in rows]


@app.post("/api/admin/evidence/reconcile")
def reconcile_evidence(actor: Actor = Depends(reviewer), db: Session = Depends(get_db)):
    result = drain_pending(db)
    audit(db, "evidence.reconcile", "completed", str(result), actor=actor.name)
    db.commit()
    return result
