from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class FileOut(ORMModel):
    id: str
    filename: str
    size: int
    sha256: str
    file_type: str
    static_metadata: dict
    disposition: str
    created_at: datetime


class FindingOut(ORMModel):
    kind: str
    title: str
    detail: str
    source: str
    confidence: float | None


class FunctionOut(ORMModel):
    address: str
    name: str
    pseudocode: str
    purpose: str
    capabilities: list
    supporting_evidence: list
    limitations: list
    confidence: float | None
    model_name: str
    prompt_version: str


class EventOut(ORMModel):
    event_type: str
    observed_at: datetime
    process: str
    target: str
    details: dict
    source: str


class AnalysisOut(ORMModel):
    id: str
    file_id: str
    status: str
    risk_score: float | None
    recommendation: str
    completeness: str
    summary: str
    stage_status: dict
    correlations: dict
    created_at: datetime
    completed_at: datetime | None


class AnalysisDetail(AnalysisOut):
    file: FileOut
    findings: list[FindingOut]
    functions: list[FunctionOut]
    events: list[EventOut]


class DispositionRequest(BaseModel):
    reason: str
