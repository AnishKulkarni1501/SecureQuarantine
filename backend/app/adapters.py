"""Adapters for separately hosted, replaceable analysis services.

This process never starts a binary. Dynamic execution is sent to an explicitly
configured worker; the Docker Desktop mode is bounded, opt-in, and not a VM.
AI endpoints return JSON matching the versioned contracts.
"""
import os
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from .contracts import FunctionInterpretation, GhidraReport, RefinedPseudocode, SandboxReport

# Local Ghidra analyses and CPU model inference can take several minutes.
TIMEOUT = httpx.Timeout(300.0, connect=5.0)


class AdapterUnavailable(RuntimeError):
    pass


async def _post_json(url: str, payload: dict, headers: dict | None = None) -> dict:
    parsed = urlparse(url)
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in local_hosts):
        raise AdapterUnavailable("Worker URL must use HTTPS unless it targets localhost")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise AdapterUnavailable("Adapter response must be a JSON object")
            return result
    except (httpx.HTTPError, ValueError) as exc:
        raise AdapterUnavailable(f"Analysis adapter unavailable: {type(exc).__name__}") from exc


async def ghidra_decompile(data: bytes, filename: str) -> GhidraReport:
    url = os.getenv("GHIDRA_WORKER_URL", "").strip()
    if not url:
        raise AdapterUnavailable("Ghidra worker is not configured")
    # Binary sent only to the configured isolated analysis worker, never a shell command.
    import base64
    result = await _post_json(url.rstrip("/") + "/v1/decompile", {"filename": filename[:255], "sha256": __import__("hashlib").sha256(data).hexdigest(), "binary_base64": base64.b64encode(data).decode("ascii")})
    try:
        return GhidraReport.model_validate(result)
    except ValidationError as exc:
        raise AdapterUnavailable("Ghidra worker returned invalid structured output") from exc


async def refine_pseudocode(function: dict) -> RefinedPseudocode:
    url = os.getenv("LLM4DECOMPILE_URL", "").strip()
    if not url:
        raise AdapterUnavailable("LLM4Decompile service is not configured")
    result = await _post_json(url.rstrip("/") + "/v1/refine", function)
    try:
        validated = RefinedPseudocode.model_validate(result)
        if validated.address != function["address"]:
            raise AdapterUnavailable("Refinement changed the source function address")
        return validated
    except ValidationError as exc:
        raise AdapterUnavailable("LLM4Decompile returned invalid structured output") from exc


async def interpret_function(function: dict) -> FunctionInterpretation:
    url = os.getenv("ZYSEC_INTERPRETER_URL", "").strip()
    if not url:
        raise AdapterUnavailable("Security interpretation service is not configured")
    result = await _post_json(url.rstrip("/") + "/v1/interpret", function)
    try:
        validated = FunctionInterpretation.model_validate(result)
        if validated.address != function["address"]:
            raise AdapterUnavailable("Interpretation references a different source function")
        return validated
    except ValidationError as exc:
        raise AdapterUnavailable("Interpreter returned invalid structured output") from exc


def sandbox_is_configured() -> bool:
    mode = os.getenv("SANDBOX_MODE", "hardened_vm").strip().lower()
    worker_ready = bool(os.getenv("SANDBOX_WORKER_URL", "").strip() and os.getenv("SANDBOX_WORKER_TOKEN", ""))
    if mode == "docker_wsl2":
        return worker_ready and os.getenv("SANDBOX_DOCKER_CONTAINMENT_ACK", "").lower() == "true"
    if mode == "hardened_vm":
        return worker_ready and os.getenv("SANDBOX_ISOLATION_ATTESTED", "").lower() == "true"
    return False


async def run_isolated_sandbox(data: bytes, sha256: str) -> SandboxReport:
    url = os.getenv("SANDBOX_WORKER_URL", "").strip()
    mode = os.getenv("SANDBOX_MODE", "hardened_vm").strip().lower()
    if not sandbox_is_configured():
        raise AdapterUnavailable("Sandbox disabled: configure a worker and explicitly acknowledge its isolation mode")
    secret = os.getenv("SANDBOX_WORKER_TOKEN", "")
    if not secret:
        raise AdapterUnavailable("Sandbox worker token is not configured")
    import base64
    runtime_limit = 30 if mode == "docker_wsl2" else 90
    result = await _post_json(url.rstrip("/") + "/v1/run", {"sha256": sha256, "binary_base64": base64.b64encode(data).decode("ascii"), "network": "disabled_by_default", "timeout_seconds": runtime_limit, "destroy_after_run": True}, {"Authorization": f"Bearer {secret}"})
    try:
        return SandboxReport.model_validate(result)
    except ValidationError as exc:
        raise AdapterUnavailable("Sandbox worker returned invalid structured telemetry") from exc
