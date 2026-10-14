# SecureQuarantine

An analyst-focused malware analysis prototype. The first increment provides safe file intake, static indicators, an auditable analysis workflow, uncertainty-aware baseline decisions, and a React dashboard.

## Safety and scope

Uploaded files are stored as managed artifacts and inspected as bytes. Dynamic execution is opt-in and sent to a separate worker; the API process never runs a submitted sample. The Docker worker supports Linux ELF64 x86-64 only and is for synthetic or authorized samples. It disables networking and bounds resources, but its containers share Docker Desktop's WSL2 Linux kernel, so it is not a hardened disposable VM. Use a separate hardened VM for highly hostile samples. Quarantine/release changes the application's recorded disposition only; it never deletes or changes files on the host.

## Run locally

Backend (Python 3.11+):

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend (Node 20+), in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. FastAPI docs are at http://localhost:8000/docs. The API uses a local SQLite database by default (`backend/securequarantine.db`) and stores artifacts under `backend/data/artifacts`; both locations can be overridden with `DATABASE_URL` and `ARTIFACT_DIR`. If using `.env`, start the backend with `uvicorn --env-file ..\.env app.main:app --reload` from `backend` so its optional service settings are loaded.

This remains a local development foundation, not a production deployment: it has no user provisioning or token rotation, and does not bundle a hardened sandbox VM. Production schema migration, secrets management, backup/restore, and operational hardening still need deployment-specific work.

## Expanded pipeline and services

The API now has versioned Pydantic contracts for Ghidra function output, LLM4Decompile refinement, ZySec-style security interpretation, and normalized sandbox events. `POST /api/analyses/{id}/enrich` attempts the configured stages and records each missing or failed stage explicitly. `include_sandbox` must be requested explicitly. The default worker mode requires a separately hardened disposable VM and operator attestation. The optional `docker_wsl2` mode requires a separate explicit acknowledgement and accepts only Linux ELF64 x86-64 artifacts. It uses an ephemeral container with `--network none`, a read-only root filesystem, no capabilities, `no-new-privileges`, bounded CPU/memory/process count, one read-only input mount, and ephemeral writable tmpfs. It does not provide a VM boundary, and syscall telemetry is best-effort.

The adapters use these service contracts:

- `GHIDRA_WORKER_URL/v1/decompile`: receives a base64 artifact and returns `tool_version` plus function records containing `address`, `name`, and baseline `pseudocode`.
- `LLM4DECOMPILE_URL/v1/refine`: accepts a function record and returns address-preserving refined pseudocode, model name and prompt version.
- `ZYSEC_INTERPRETER_URL/v1/interpret`: accepts the pseudocode and returns a structured purpose, capability hypotheses, supporting text, limitations, and model metadata.
- `SANDBOX_WORKER_URL/v1/run`: receives the artifact, network-disabled-by-default and timeout/destruction settings; returns normalized events and a completeness flag. Requires `SANDBOX_WORKER_TOKEN` and `SANDBOX_ISOLATION_ATTESTED=true`.

These are adapter contracts, not a sandbox appliance. The repository includes an optional loopback-only Ghidra, LLM4Decompile, and SecurityLLM adapter (`backend/local_workers/service.py`); Ghidra performs static parsing and decompilation only. Run it only with synthetic or authorized files. It is not an isolated VM boundary. The LLM4Decompile checkpoint loads on first refinement request and currently uses CPU inference on this Windows setup. SecurityLLM uses an optional AWQ vLLM process in WSL and may exceed this machine's GPU memory. Sandbox execution remains disabled until a separately validated hardened VM worker is configured. LLM confidence is stored for traceability but excluded from the risk calculation. Scores are heuristic until calibrated on an independent validation set.

Start the local Ghidra/model worker from the repository root after extracting the Ghidra archive and installing Java 21 or newer:

```powershell
$env:JAVA_HOME = "C:\Program Files\Java\jdk-25"
cd backend
python -m uvicorn local_workers.service:app --host 127.0.0.1 --port 8100
```

Set `GHIDRA_WORKER_URL` and `LLM4DECOMPILE_URL` to `http://127.0.0.1:8100` in `.env`, then start/restart the API with that environment file. Check worker readiness at `http://127.0.0.1:8100/health`.

To try the SecurityLLM AWQ checkpoint in WSL Ubuntu, install `backend/local_workers/requirements-vllm.txt` in a dedicated WSL virtual environment, then run WSL `vllm serve` with the local model path, `--served-model-name securityllm`, `--quantization awq`, `--max-model-len 1024`, `--max-num-seqs 1`, and `--gpu-memory-utilization 0.90` on port 8200. When `http://127.0.0.1:8200/health` responds, set `ZYSEC_INTERPRETER_URL=http://127.0.0.1:8100` in `.env` and restart the API. The worker proxies structured interpretation requests to vLLM. A successful launch still needs a real inference request before treating the stage as operational.

### Docker dynamic analysis for Linux ELF

Build the fixed runner image from the repository root:

```powershell
docker build -t securequarantine/elf-sandbox:0.1 -f backend/docker_sandbox/Dockerfile backend/docker_sandbox
```

Set `SANDBOX_MODE=docker_wsl2`, `SANDBOX_DOCKER_CONTAINMENT_ACK=true`, `SANDBOX_WORKER_URL=http://127.0.0.1:8201`, and a unique `SANDBOX_WORKER_TOKEN` in `.env`. Keep `SANDBOX_ISOLATION_ATTESTED=false`; Docker container acknowledgement is distinct from VM attestation. Start the worker from `backend` with:

```powershell
python -m uvicorn local_workers.docker_sandbox:app --host 127.0.0.1 --port 8201
```

Check `http://127.0.0.1:8201/health`, then restart FastAPI so it loads the worker settings. The dashboard requires an analyst to request the Docker run. Each run is capped at 30 seconds, 256 MiB RAM, one CPU and 32 processes; networking is disabled and the named container is removed afterward. `strace` observations can be incomplete or tampered with by a sample and must not be treated as proof of safety. The worker does not emulate Windows APIs or run PE files.

### Optional local infrastructure

Copy `.env.example` to `.env`, set local-only secrets, and start supporting services:

```powershell
docker compose up -d mysql mongo redis
```

For MySQL, set `DATABASE_URL=mysql+pymysql://sq_app:<password>@127.0.0.1:3307/securequarantine` (host port 3307 avoids collisions with an existing local MySQL service). For Mongo, use `MONGO_URI=mongodb://127.0.0.1:27018` (host port 27018). Set `MONGO_DATABASE` to enable Mongo evidence projections. The SQL database remains authoritative; pending Mongo writes are stored in an SQL outbox and can be retried with `POST /api/admin/evidence/reconcile`.

For durable static-analysis jobs, set `CELERY_BROKER_URL=redis://127.0.0.1:6379/0` before starting FastAPI, then start a worker in another terminal:

```powershell
cd backend
celery -A app.worker.celery_app worker -l info --pool solo
```

Queued analyses retry transient worker errors up to three times. Without the broker setting, the local app keeps its synchronous static-analysis behavior. Production mode requires `APP_ENV=production`, separate `ANALYST_API_TOKEN` and `REVIEWER_API_TOKEN` values; the dashboard's lock button accepts a token for the current browser tab.

### Evaluation scaffold

Create family-disjoint data splits and save only held-out test rows as JSONL with `split`, `family`, `label`, `static_hits`, `runtime_event_types`, `supported_ai_capabilities`, `static_complete`, `dynamic_complete`, `ai_complete`, and optional `latency_ms`. Run `python evaluate_dataset.py <test.jsonl>` from `backend`. It reports A-D heuristic ablation metrics, including false-positive/negative rates and human-review counts. This scaffold does not train or calibrate a classifier and is not evidence of improved accuracy by itself.

The REST API also exposes `GET /api/evaluation/summary` for analyst-labeled corrections; its response flags that this is exploratory data rather than an independent benchmark. Quarantine/release are audited changes to managed artifact disposition records only.
