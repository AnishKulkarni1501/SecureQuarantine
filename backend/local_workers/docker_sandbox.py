"""Loopback Docker worker for bounded, no-network Linux x86-64 ELF analysis.

This is best-effort container telemetry, not a disposable VM boundary.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


IMAGE = os.getenv("SANDBOX_DOCKER_IMAGE", "securequarantine/elf-sandbox:0.1")
MAX_INPUT = 50 * 1024 * 1024
MAX_RUNTIME_SECONDS = 30
MAX_EVENTS = 10_000
app = FastAPI(title="SecureQuarantine Docker ELF Worker", version="1")

LIMITATIONS = [
    "Linux ELF64 x86-64 only; Windows PE and other ELF architectures are not executed.",
    "The disposable container shares Docker Desktop's WSL2 Linux kernel and is not a disposable VM; kernel escape risk remains.",
    "Container networking is disabled. Network events show attempted calls only, not behavior on a live network.",
    "strace records selected syscalls; malware can detect, evade, or tamper with tracing. Missing events do not prove safety.",
    "The run is limited to 30 seconds, 256 MiB RAM, one CPU, 32 processes, and ephemeral writable memory.",
]


class RunRequest(BaseModel):
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    binary_base64: str
    network: str = "disabled_by_default"
    timeout_seconds: int = Field(default=30, ge=1, le=90)
    destroy_after_run: bool = True


def docker_cli() -> str:
    cli = shutil.which("docker") or shutil.which("docker.exe")
    if not cli:
        raise HTTPException(503, "Docker CLI is not available to the worker")
    return cli


def docker(args: list[str], timeout: float = 15, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [docker_cli(), *args], capture_output=True, text=True,
            timeout=timeout, check=False, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(503, "Docker command timed out") from exc
    except OSError as exc:
        raise HTTPException(503, "Docker CLI could not be started") from exc
    if check and result.returncode != 0:
        # Do not return raw daemon output to the API caller.
        raise HTTPException(503, "Docker worker command failed")
    return result


def decode_and_validate(request: RunRequest) -> bytes:
    if request.network != "disabled_by_default":
        raise HTTPException(400, "This worker only supports network-disabled analysis")
    if request.destroy_after_run is not True:
        raise HTTPException(400, "This worker only supports disposable containers")
    try:
        data = base64.b64decode(request.binary_base64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HTTPException(400, "Invalid base64 artifact") from exc
    if not data or len(data) > MAX_INPUT:
        raise HTTPException(413, "Artifact is empty or exceeds the 50 MiB worker limit")
    if hashlib.sha256(data).hexdigest().lower() != request.sha256.lower():
        raise HTTPException(400, "Artifact hash mismatch")
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise HTTPException(415, "Only Linux ELF64 x86-64 samples are accepted")
    if data[4] != 2 or data[5] != 1:
        raise HTTPException(415, "Only little-endian ELF64 samples are accepted")
    if int.from_bytes(data[18:20], "little") != 62:
        raise HTTPException(415, "Only x86-64 ELF samples are accepted")
    return data


def verify_container(container_id: str) -> None:
    result = docker(["inspect", container_id], timeout=10)
    try:
        info = json.loads(result.stdout)[0]
        host = info["HostConfig"]
        config = info["Config"]
        mounts = info.get("Mounts", [])
        input_mounts = [mount for mount in mounts if mount.get("Destination") == "/input"]
        tmpfs = host.get("Tmpfs") or {}
        safe = (
            host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and "ALL" in (host.get("CapDrop") or [])
            and any("no-new-privileges" in value for value in (host.get("SecurityOpt") or []))
            and host.get("Memory") == 256 * 1024 * 1024
            and host.get("MemorySwap") == 256 * 1024 * 1024
            and host.get("PidsLimit") == 32
            and host.get("NanoCpus") == 1_000_000_000
            and config.get("User") == "65534:65534"
            and not host.get("Binds")
            and len(input_mounts) == 1
            and input_mounts[0].get("RW") is False
            and input_mounts[0].get("Type") == "bind"
            and set(tmpfs) == {"/work", "/tmp"}
        )
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(503, "Could not verify Docker sandbox settings") from exc
    if not safe:
        raise HTTPException(503, "Docker sandbox settings did not match the required isolation profile")


def parse_events(log: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    pattern = re.compile(r"^(?:\[pid\s+(\d+)\]\s*|(\d+)\s+)?(\d{9,}(?:\.\d+)?)\s+([A-Za-z_][A-Za-z0-9_]*)\((.*)$")
    first_string = re.compile(r'"((?:\\.|[^"\\])*)"')
    process_calls = {"execve", "execveat", "clone", "clone3", "fork", "vfork", "exit", "exit_group"}
    file_calls = {"open", "openat", "openat2", "creat", "access", "faccessat", "faccessat2", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmod", "chown", "truncate", "link", "symlink", "newfstatat"}
    network_calls = {"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "getpeername"}
    for line in log.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        pid = match.group(1) or match.group(2) or ""
        try:
            observed = datetime.fromtimestamp(float(match.group(3)), tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            observed = datetime.now(timezone.utc).isoformat()
        syscall, args = match.group(4), match.group(5)
        if syscall in process_calls:
            event_type = "process"
        elif syscall in file_calls:
            event_type = "file"
        elif syscall in network_calls:
            event_type = "network"
        else:
            continue
        string_arg = first_string.search(args)
        target = string_arg.group(1)[:2000] if string_arg else args[:2000]
        result = args.rsplit("=", 1)[-1].strip()[:500] if "=" in args else ""
        events.append({
            "event_type": event_type,
            "observed_at": observed,
            "process": "sample.elf",
            "target": target,
            "details": {"syscall": syscall, "pid": pid, "result": result},
            "source": "docker_elf_strace",
        })
        if len(events) >= MAX_EVENTS:
            break
    return events


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        engine = docker(["info", "--format", "{{.OSType}}"], timeout=5).stdout.strip()
        if engine != "linux":
            raise HTTPException(503, "Docker worker requires a Linux container engine")
        image_ready = docker(["image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=5).returncode == 0
        return {
            "status": "ok" if image_ready else "setup_required",
            "engine": "linux",
            "image_ready": image_ready,
            "sample_format": "Linux ELF64 x86-64 only",
            "network": "none",
            "isolation": "Docker Desktop/WSL2 container; shared-kernel limitation applies",
        }
    except HTTPException:
        raise


@app.post("/v1/run")
def run(request: RunRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    expected = os.getenv("SANDBOX_WORKER_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(401, "Invalid worker token")
    data = decode_and_validate(request)
    if docker(["info", "--format", "{{.OSType}}"], timeout=5).stdout.strip() != "linux":
        raise HTTPException(503, "Docker worker requires a Linux container engine")
    if docker(["image", "inspect", IMAGE, "--format", "{{.Id}}"], timeout=5, check=False).returncode != 0:
        raise HTTPException(503, "Required sandbox image is not built")

    run_id = uuid.uuid4().hex
    container = "sq-elf-" + run_id
    with tempfile.TemporaryDirectory(prefix="sq-elf-input-") as temp_dir:
        sample = Path(temp_dir) / "sample.elf"
        sample.write_bytes(data)
        sample_dir = Path(temp_dir).as_posix()
        command = [
            "create", "--name", container,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges=true",
            "--pids-limit=32", "--memory=256m", "--memory-swap=256m", "--cpus=1",
            "--user=65534:65534", "--init",
            "--log-driver=json-file", "--log-opt", "max-size=4m", "--log-opt", "max-file=1",
            "--ulimit", "cpu=30:30", "--ulimit", "fsize=4194304:4194304",
            "--ulimit", "nofile=64:64", "--ulimit", "core=0:0",
            "--mount", f"type=bind,source={sample_dir},target=/input,readonly",
            "--tmpfs", "/work:rw,nosuid,nodev,exec,size=64m,uid=65534,gid=65534,mode=700",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=65534,gid=65534,mode=700",
            "--workdir", "/work", IMAGE, "sample.elf",
        ]
        container_id = ""
        try:
            created = docker(command, timeout=20)
            container_id = created.stdout.strip()
            if not container_id:
                raise HTTPException(503, "Docker did not return a container ID")
            verify_container(container_id)
            docker(["start", container_id], timeout=10)
            run_complete = True
            try:
                waited = docker(["wait", container_id], timeout=min(request.timeout_seconds, MAX_RUNTIME_SECONDS) + 12)
                exit_code = int(waited.stdout.strip())
            except (HTTPException, ValueError):
                run_complete = False
                exit_code = -1
                docker(["kill", container_id], timeout=8, check=False)
            logs_result = docker(["logs", "--tail", "20000", container_id], timeout=12, check=False)
            log = (logs_result.stdout or "") + "\n" + (logs_result.stderr or "")
            marker = re.search(r"__SQ_EXIT_CODE__=(-?\d+)", log)
            timed_out = not run_complete or bool(marker and marker.group(1) == "124")
            complete = run_complete and marker is not None and not timed_out and "__SQ_SETUP_ERROR__" not in log
            events = parse_events(log)
            if len(events) >= MAX_EVENTS:
                complete = False
            limitations = list(LIMITATIONS)
            if timed_out:
                limitations.append("The sample exceeded the configured runtime or Docker wait limit and was terminated.")
            elif marker is None:
                limitations.append("The container did not return its completion marker; telemetry may be incomplete.")
            if not events:
                limitations.append("No selected syscalls were captured; this does not establish that the sample is benign.")
            return {
                "run_id": run_id,
                "complete": complete,
                "events": events,
                "limitations": limitations,
            }
        except HTTPException:
            raise
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(503, f"Docker analysis failed: {type(exc).__name__}") from exc
        finally:
            if container_id:
                docker(["rm", "--force", container_id], timeout=10, check=False)
