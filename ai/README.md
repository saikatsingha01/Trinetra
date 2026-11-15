# Trinetra AI — Email Forensic Analysis

The **Trinetra AI** component is the AI/ML backend of the Trinetra platform that analyzes email evidence for phishing, business email compromise (BEC), and social engineering, and produces a grounded, evidence-based AI assessment.

It is implemented in Python and runs on top of a local large language model served through [Ollama](https://ollama.com). The component receives a structured email evidence package from the Trinetra backend, runs a hardened and evidence-grounded analysis around the local LLM, validates and grounds the LLM output, and forwards the resulting AI assessment to the Trinetra Logic Engine.

The AI component **analyzes**. It does **not** decide. Final risk scoring and final verdicts belong to the downstream Trinetra Logic Engine.

## Table of Contents

1. [Overview](#overview)
2. [AI Component Role in Trinetra](#ai-component-role-in-trinetra)
3. [Implemented Features](#implemented-features)
4. [Architecture and Processing Workflow](#architecture-and-processing-workflow)
5. [Ollama Integration](#ollama-integration)
6. [Models Used](#models-used)
7. [Technology Stack](#technology-stack)
8. [Project Structure](#project-structure)
9. [Prerequisites](#prerequisites)
10. [Installation](#installation)
11. [Environment Configuration](#environment-configuration)
12. [Ollama Setup and Model Requirements](#ollama-setup-and-model-requirements)
13. [Execution](#execution)
14. [Backend Integration](#backend-integration)
15. [Usage](#usage)
16. [Current Limitations](#current-limitations)
17. [Future Improvements](#future-improvements)
18. [Contributing](#contributing)

---

## Overview

The Trinetra AI component consumes an **EvidencePackage** — an email plus the security analysis, threat intelligence, and forensic evidence derived from it — and produces an **AIAssessment**.

The assessment carries:

- `phishing_probability` (0.0–1.0)
- `bec_probability` (0.0–1.0)
- `social_engineering_probability` (0.0–1.0)
- `urgency_detected`, `credential_request_detected`, `financial_request_detected`
- `suspicious_language`, `detected_patterns`, `explanation`
- `model_info`
- Attachment / forensic conclusions: `attachment_risk_detected`, `malicious_attachment_detected`, `attachment_findings`

The AI never emits a final risk score or a final verdict. Those are owned by the Trinetra Logic Engine.

## AI Component Role in Trinetra

The AI component is a subordinate analysis stage in the Trinetra decision pipeline:

1. The Trinetra backend assembles an `EvidencePackage` from a raw inbound email and the security, threat-intelligence and forensic data derived from it.
2. The AI component validates, normalizes, understands, builds context, builds the prompt, and runs the local LLM.
3. The AI component validates the LLM output and grounds it against the supplied evidence.
4. The AI component reconciles deterministic corrections and returns a grounded `AIAssessment`.
5. The AI component forwards the assessment — or an explicit failure notification — to the Trinetra Logic Engine.

The Logic Engine receives the AI assessment and is responsible for risk scoring, correlation, and the final decision.

## Implemented Features

### End-to-end forensic pipeline

The pipeline runs eleven stages:

1. **Input security** — structural guard validating case ID, email fields, and recursive size/depth/key/list/string limits for security analysis, threat intelligence, and forensic evidence.
2. **Content isolation** — untrusted email content is separated from trusted system instructions; all evidence is carried as untrusted.
3. **Normalization** — evidence is normalized while original evidence is preserved.
4. **Understanding** — deterministic signal extraction from email content and forensic evidence, with provenance paths.
5. **Context building** — structured analysis context assembled from normalized evidence and understanding signals.
6. **Prompt building** — trusted system instructions and untrusted evidence rendered into a structured prompt; per-case allowed provenance paths are derived.
7. **LLM inference (Ollama)** — structured JSON generation through the Ollama generate API.
8. **Output validation** — JSON extraction from raw responses, strict Pydantic validation, probability clamping, evidence-strength repair, and one targeted provenance retry.
9. **Grounding / quality control** — checks that assessments and findings are supported by the supplied evidence.
10. **Reconciliation** — deterministic corrections, probability ceilings, BEC evidence floor, and final re-grounding.
11. **Assessment return** — grounded `AIAssessment` returned as the pipeline result.

### Attachment and forensic evidence support

The component supports arbitrarily nested forensic evidence (attachments, embedded files, hashes, sandbox results, IP/URL/domain intelligence) and emits attachment findings that cite an exact, resolvable evidence path.

### Runtime behaviour

The Ollama receiver runs a bounded queue and worker pool with backpressure, graceful shutdown, health/metrics/debug endpoints, and explicit Ollama failure notifications to the Logic Engine.

---

## Architecture and Processing Workflow

```text
EvidencePackage
   |
   v
Input Guard
   |
   v
Content Isolation
   |
   v
Normalization
   |
   v
Understanding
   |
   v
Context Builder
   |
   v
Prompt Builder
   |
   v
Ollama (Local LLM)
   |
   v
Output Validation
   |
   v
Grounding / QC
   |
   v
Reconciliation + Re-grounding
   |
   v
AIAssessment
   |
   v
Logic Engine
```

## Ollama Integration

The AI component talks to a local Ollama server through a Python client:

- Base URL: `OLLAMA_BASE_URL` (default `http://localhost:11434`)
- Generate endpoint: `OLLAMA_GENERATE_ENDPOINT` (default `/api/generate`)
- Model: `OLLAMA_MODEL` (default `qwen2.5:7b-instruct`)
- Timeout: `OLLAMA_TIMEOUT_SECONDS` (default `600`)
- Temperature: `OLLAMA_TEMPERATURE` (default `0.2`)

The client sends a JSON generation request containing the model name, system prompt, user prompt, `stream` set to `false`, a structured-output JSON schema (`format`), and generation options.

When per-case allowed provenance paths exist, the JSON schema sent to Ollama is constrained to that exact case-specific enum. Otherwise the global assessment schema is used.

Error handling covers connection failures, timeouts, HTTP errors, invalid responses, and model-not-found errors; each is mapped to a pipeline stage.

If strict validation fails specifically because of a provenance (`evidence_path`) problem, the pipeline performs exactly one targeted retry with a correction prompt. All other failures fail fast.

## Models Used

- `qwen2.5:7b-instruct` — local Ollama model used for forensic analysis.

The model is configurable through the `OLLAMA_MODEL` environment variable.

## Technology Stack

- Python 3.12+
- FastAPI, Uvicorn, Pydantic v2 (`pydantic`, `pydantic-settings`)
- HTTP clients: `httpx`, `requests`
- Configuration: `python-dotenv`
- Local LLM runtime: Ollama
- Testing: `pytest`

## Project Structure

```text
.
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── integration_models.py
├── logic_model.py
├── logic_receive.py
├── logic_send.py
├── ollama_model.py
├── ollama_receive.py
├── docs/
├── example/
├── manual_test/
└── src/
    └── ai/
        ├── __init__.py
        ├── pipeline.py
        ├── provenance.py
        ├── contracts/
        ├── llm/
        ├── normalization/
        ├── prompting/
        ├── results/
        ├── security/
        ├── understanding/
        └── validation/
```

## Prerequisites

- Python 3.12 or newer
- [Ollama](https://ollama.com) installed and running
- Hardware sufficient for local inference (CPU or GPU)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate with:

```powershell
.venv\Scripts\activate
```

## Environment Configuration

Copy the example environment file and adjust the values:

```bash
cp .env.example .env
```

Key variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `LOGIC_PUBLIC_URL` | Public base URL of the Logic Engine | required |
| `LOGIC_FAILURE_PATH` | Failure notification path | `/receive-ollama-failure` |
| `LOGIC_TIMEOUT_SECONDS` | Timeout for Logic Engine delivery | `30` |
| `OLLAMA_BASE_URL` | Ollama server base URL | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model | `qwen2.5:7b-instruct` |
| `OLLAMA_TIMEOUT_SECONDS` | Ollama request timeout | `600` |
| `OLLAMA_GENERATE_ENDPOINT` | Ollama generate endpoint | `/api/generate` |
| `OLLAMA_TEMPERATURE` | Generation temperature | `0.2` |
| `OLLAMA_SEED` | Optional fixed seed | unset |
| `OLLAMA_MAX_CONCURRENCY` | Max concurrent AI workers | `2` |
| `OLLAMA_QUEUE_MAXSIZE` | Queue backpressure limit | `50` |
| `OLLAMA_SHUTDOWN_TIMEOUT_SECONDS` | Graceful shutdown timeout | `10.0` |

## Ollama Setup and Model Requirements

Start Ollama and pull the model:

```bash
ollama serve
ollama pull qwen2.5:7b-instruct
```

## Execution

Start the Ollama receiver:

```bash
python ollama_receive.py
```

The Ollama receiver listens on `0.0.0.0:8002`.

Start the Logic Engine receiver:

```bash
python logic_receive.py
```

The Logic Engine receiver listens on `0.0.0.0:8001`.

## Backend Integration

The AI component exposes an endpoint that accepts an Ollama evidence request:

- `POST /receive-backend` — accepts an evidence package for AI analysis and queues it for processing. Returns `202 Accepted`.

On success, the component sends a `LogicAnalysisReport` to the Logic Engine:

- `POST {LOGIC_PUBLIC_URL}/receive-ollama`

On failure, the component sends an explicit Ollama failure notification:

- `POST {LOGIC_PUBLIC_URL}{LOGIC_FAILURE_PATH}`

## Usage

Run the disposable manual test harness:

```bash
python manual_test/run_manual_test.py
```

---

## Current Limitations

- The analysis runs on a single local model (`qwen2.5:7b-instruct`); inference latency and throughput depend on local hardware.
- The Logic Engine receiver keeps received reports and failures in memory only.
- The pipeline performs a single targeted retry for provenance validation failures.
- The AI component produces probabilities and findings; it does not compute the final risk score or verdict.

## Future Improvements

- Continue the phased roadmap documented in `docs/ROADMAP.md`, `docs/V2.md`, and `docs/V3.md`.

## Contributing

- Fork the repository and open a pull request.
- Preserve the existing pipeline architecture, contracts, and separation of responsibilities.
- Do not introduce a second pipeline, a second model, or external API calls without prior discussion.

