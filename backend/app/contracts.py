from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class GhidraFunction(BaseModel):
    address: str = Field(min_length=1, max_length=80)
    name: str = Field(default="unknown", max_length=200)
    pseudocode: str = Field(min_length=1, max_length=100_000)


class GhidraReport(BaseModel):
    tool_version: str = Field(max_length=160)
    functions: list[GhidraFunction] = Field(max_length=500)
    limitations: list[str] = Field(default_factory=list, max_length=50)


class RefinedPseudocode(BaseModel):
    address: str
    pseudocode: str = Field(min_length=1, max_length=100_000)
    model_name: str = Field(max_length=160)
    prompt_version: str = Field(max_length=80)


class FunctionInterpretation(BaseModel):
    address: str = Field(min_length=1, max_length=80)
    purpose: str = Field(min_length=1, max_length=2000)
    capabilities: list[str] = Field(default_factory=list, max_length=30)
    supporting_evidence: list[str] = Field(default_factory=list, max_length=40)
    limitations: list[str] = Field(default_factory=list, max_length=40)
    confidence: float | None = Field(default=None, ge=0, le=1)
    model_name: str = Field(max_length=160)
    prompt_version: str = Field(max_length=80)


class SandboxEventInput(BaseModel):
    event_type: Literal["process", "file", "network", "registry", "other"]
    observed_at: datetime
    process: str = Field(default="", max_length=500)
    target: str = Field(default="", max_length=4000)
    details: dict = Field(default_factory=dict)
    source: str = Field(default="isolated_vm", max_length=80)


class SandboxReport(BaseModel):
    run_id: str = Field(min_length=1, max_length=200)
    complete: bool
    events: list[SandboxEventInput] = Field(default_factory=list, max_length=10_000)
    limitations: list[str] = Field(default_factory=list, max_length=100)


class EnrichmentRequest(BaseModel):
    include_sandbox: bool = False
    include_ai: bool = True


class AnalystCorrection(BaseModel):
    decision: Literal["release", "quarantine", "analyze_further", "human_review"]
    label: Literal["benign", "malicious", "unknown"] = "unknown"
    note: str = Field(min_length=1, max_length=2000)
