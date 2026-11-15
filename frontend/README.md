# TRINETRA Logic Engine — Final Correlation Service (Logic Receiver is Source of Truth)

Standalone deterministic microservice that **receives Subhom's technical findings + Saikat's AI assessment independently, correlates via `case_id`, and produces final risk score + verdict**. All communication is HTTPS/JSON through Cloudflare Tunnel — no shared code, no localhost coupling, no mock mode. **Logic Receiver owns the final result** and frontend polls it directly.

```
                         TRINETRA FLOW (Logic Receiver is source of truth)

   FRONTEND (browser) --POST /receive-email (.eml)--> SUBHOM BACKEND (Cloudflare)
                                                          |
                                                          | processing -> security/threat
                                                          v
                              SUBHOM --POST /receive-analysis--> LOGIC RECEIVER <--POST /receive-ollama-- SAIKAT (Ollama)
                                                                   |
                                                                   | correlate via case_id
                                                                   | LogicEngine -> risk_score + verdict
                                                                   | STORE final result by case_id
                                                                   v
                              FRONTEND --GET /analysis/{case_id}--> LOGIC RECEIVER (poll directly)
                                                                   -> {status:"processing"} | {status:"completed", risk_score, verdict, ...}
```

Legacy `POST /receive-analysis` (combined `security_analysis + threat_intelligence + ai_assessment`) remains for backward compat and tests — immediate processing without store.

## Responsibility

This repository **owns**:

- **Rules** — 17 security rule evaluators (`logic/rules.py`)
- **Correlation** — cross-source findings (`logic/correlation.py`) — e.g., `SPF fail + high AI phishing → stronger evidence`
- **Risk scoring** — capped / linear / sqrt (`logic/scoring.py`) — final 0–100
- **Verdict** — LOW / MEDIUM / HIGH / CRITICAL / MALICIOUS (`logic/verdict.py`)
- **Correlation store** — in-memory `cases[case_id] = {backend, ollama, status: waiting|processing|completed|failed, result}` with `asyncio.Lock` (atomic claim, duplicate protection) — **Logic Receiver is source of truth for final report**
- **Result delivery** — `GET /analysis/{case_id}` polled directly by frontend (no Subhom round-trip)

Via `logic/engine.py` (`LogicEngine.analyze()` / `get_detailed_report()`) these layers are orchestrated — receiver never duplicates logic. Frontend never calculates risk_score; it only displays what Logic Receiver returns.

## Does NOT Contain

- Email `.eml` parsing / MIME / IOC extraction (Workflow 1 — Subhom)
- SPF/DKIM/DMARC fetching / IP/domain/URL intel fetching (Workflows 2/3 — Subhom)
- Ollama / AI inference (Saikat)
- Database — pending store is in-memory for prototype/demo; no external DB required

Frontend orchestration: `frontend/` uploads to Subhom (`POST /receive-email`) and **polls Logic Receiver directly** (`GET /analysis/{case_id}`) — it does not rely on Subhom's `/analysis` for final result.

Communication is **HTTP JSON only**.

## Quick Start

### 1. Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
# source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env   # set BACKEND_PUBLIC_URL
```

Key vars (see `.env.example`):

- `VITE_BACKEND_BASE_URL` / `VITE_LOGIC_BASE_URL` in `frontend/.env` — Subhom upload vs Logic poll (frontend must poll Logic Receiver, not Subhom)
- `LOGIC_PUBLIC_BASE_URL=https://<MY-CLOUDFLARE-DOMAIN>` — my public Logic URL to give Subhom/Saikat and to set as `VITE_LOGIC_BASE_URL` when multi-machine
- `BACKEND_PUBLIC_URL=https://<SUBHOM-CLOUDFLARE-DOMAIN>` — only needed if `ENABLE_BACKEND_CALLBACK=true` (disabled by default; Logic Receiver is source of truth)
- `LOGIC_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173` — must include frontend origin that polls Logic Receiver
- `LOGIC_HOST=0.0.0.0`, `LOGIC_PORT=8000`, `LOGIC_LOG_LEVEL=INFO`
- `TRINETRA_*` overrides for thresholds/weights (see `config.yaml`)

Defaults listen on `0.0.0.0:8001`.

### 3. Run (canonical)

```bash
uvicorn logic_api:app --host 0.0.0.0 --port 8001
# compat aliases (same app):
# uvicorn logic_reciever:app --host 0.0.0.0 --port 8000
# uvicorn logic_receiver:app --host 0.0.0.0 --port 8000
```

### 4. Verify

```bash
curl http://localhost:8001/health
# {"status":"healthy","service":"trinetra-logic-engine"}
curl http://localhost:8001/pending
# {"pending_cases":{},"count":0}
```

No Subhom/Saikat server required to start.

## API — Two-Source (Production)

### `POST /receive-subhom-analysis` — Subhom → Logic Engine

```json
{
  "case_id": "CASE-001",
  "email": {"sender":"attacker@evil.com","recipient":"victim@company.com","subject":"Urgent","iocs":{"ips":["1.2.3.4"],"domains":["evil.com"],"urls":["http://evil.com"],"hashes":[]}},
  "security_analysis": {
    "authentication_analysis": {"spf":[{"result":"fail","domain":"evil.com"}],"dkim":false,"dmarc":{"result":"fail","policy":"reject"}},
    "sender_analysis": {"from":{"email_address":"attacker@evil.com"},"reply_to":{"email_address":"attacker@evil-reply.net"},"findings":["domain_mismatch"]},
    "header_analysis": {"received":[{},{},{},{},{}],"authentication_results":["spf=fail"],"findings":["relay_anomaly"]},
    "phishing_analysis": [{"indicator":"spoofing","evidence":"mismatch","severity":"high"}]
  },
  "threat_intelligence": {
    "ip_analysis": {"abuseIPDB_report":[{"ipAddress":"1.2.3.4","abuseConfidenceScore":92}]},
    "url_analysis": {"virusTotal_report":[{"url":"http://evil.com","positives":55,"total":70}]},
    "domain_analysis": {"virusTotal_report":[{"domain":"evil.com","positives":50,"total":70}]},
    "attachment_analysis": {"virusTotal_report":[]}
  },
  "forensic_evidence": {}
}
```

Accepts `case_id`/`email_id` alias, `threat_intelligence`/`threat_analysis` alias, legacy flat `ips/domains/urls/hashes` or new provider reports. `email_id` kept for compat.

**Response if counterpart missing** → `200 {"status":"pending","case_id":"CASE-001","message":"Subhom data stored, waiting for AI assessment"}`

**Response when both present** → `200` detailed result (see below) and final report is **stored in Logic Receiver** for frontend polling. Optional async `POST ${BACKEND_PUBLIC_URL}/receive-logic-result` only if `ENABLE_BACKEND_CALLBACK=true` (disabled by default per architecture). Duplicate `case_id` after `completed` → `200 {"status":"already_completed","result":{...}}` (no second analysis). Near-simultaneous arrivals are atomic via `asyncio.Lock` (`waiting→processing→completed`).

### `POST /receive-ai-analysis` — Saikat → Logic Engine

```json
{
  "case_id": "CASE-001",
  "ai_assessment": {
    "phishing_probability": 0.95,
    "bec_probability": 0.85,
    "social_engineering_probability": 0.90,
    "urgency_detected": true,
    "credential_request_detected": true,
    "financial_request_detected": true,
    "suspicious_language": ["urgent payment"],
    "detected_patterns": ["phishing"],
    "explanation": "High confidence phishing"
  },
  "grounding": {"grounded": true, "unsupported_claims": []},
  "processing_time_seconds": 2.5,
  "model_info": {"provider": "ollama", "model": "llama3.1:8b"}
}
```

Same alias/persistence behavior as Subhom endpoint. Order does not matter.

### `GET /analysis/{case_id}` — Frontend → Logic Receiver (poll)

**Poll target — Logic Receiver is source of truth (per master prompt). Browser calls this directly.**

- `processing` → `200 {"status":"processing","case_id":"CASE-001","detail":"Analysis is still processing."}`
- `completed` → `200 {"status":"completed","case_id":"CASE-001","risk_score":85,"verdict":"MALICIOUS","result":{...},"analysis":{...},"email":{...},"security_analysis":{...},"threat_intelligence":{...}}`  (includes top-level `risk_score`/`verdict` plus full report under `result`/`analysis` for backward compat; frontend `normalizeReport()` handles both)
- `failed` → `200 {"status":"failed","case_id":"...","error":"..."}`  or `404` if case not yet known (frontend keeps polling after upload, since Subhom forwards async)
- CORS is configured at FastAPI app level via `LOGIC_CORS_ORIGINS` (must include `http://localhost:5173` etc.); browser must be able to reach this URL — use Cloudflare public URL when multi-machine, not `localhost` when frontend is on another machine.

### `POST /receive-logic-result` — Logic Engine → Subhom (optional callback, disabled by default)

Only triggered if `ENABLE_BACKEND_CALLBACK=true` and `BACKEND_PUBLIC_URL` is set. Disabled by default because **Logic Receiver retains the final result** and frontend polls it directly — the final score does not need to travel back through Subhom for display.

```json
{
  "case_id": "CASE-001",
  "email_id": "CASE-001",
  "logic_analysis": {
    "case_id": "CASE-001",
    "risk_score": 85,
    "verdict": "MALICIOUS",
    ...
  }
}
```

### `POST /receive-analysis` — Legacy combined (immediate)

For tests/compat where Subhom already aggregates Saikat:

```json
{
  "case_id": "CASE-123",
  "security_analysis": {...},
  "threat_intelligence": {...},
  "ai_assessment": {...}
}
```

Returns detailed result directly (no store, no callback). Preserved so `pytest` suite and `manual_test.py` keep working.

### `GET /health` / `GET /` / `GET /cases` / `GET /pending`

Health probes and debug. `GET /cases` shows `has_backend/has_ollama/status` without payload. `GET /pending` alias also available.

## Project Structure

```
TRINETRA-Logic-Engine/
├── logic/
│   ├── config.py          # YAML + TRINETRA_* env overrides
│   ├── logging.py         # structured / JSON logging
│   ├── models.py          # SecurityAnalysis, ThreatIntelligence, AnalysisInput, LogicOutput
│   ├── rules.py           # 17 rule evaluators
│   ├── correlation.py     # cross-signal findings
│   ├── scoring.py         # RiskScorer
│   ├── verdict.py         # VerdictEngine
│   └── engine.py          # LogicEngine.get_detailed_report() orchestrator (single source of truth)
├── integration/
│   └── adapters.py        # Subhom/Saikat JSON → internal models (ONLY Subhom/Saikat-aware module)
├── tests/
│   ├── test_api.py        # FastAPI tests against canonical logic_api:app (legacy + two-phase)
│   └── test_engine.py     # unit tests for rules/correlation/scoring/verdict
├── logic_api.py           # ★ Canonical FastAPI app — two-source correlation + store + callback
├── logic_reciever.py      # Thin re-export (typo kept for existing tunnel) — same app
├── logic_receiver.py      # Correct-spelling re-export — same app
├── logic_models.py        # Legacy LogicRequestModel (email_id, security_analysis, threat_analysis)
├── config.yaml
├── .env.example
└── README.md
```

`logic/` contains **no** Subhom/Saikat parsing; all external-shape handling lives in `integration/adapters.py`.

## Adapter Mapping (abbreviated)

- `security_analysis` → `SecurityAnalysis` (`spf` list→`SPFResult`, `dkim` bool→`DKIMResult`, `dmarc` obj→`DMARCResult`, `sender_analysis`→`SenderIdentity`, `header_analysis.received`→`HeaderAnalysis.ip_hops`, `phishing_analysis`→`suspicious_indicators`)
- `threat_intelligence` (`ip_analysis`/`url_analysis`/`domain_analysis`/`attachment_analysis` with provider reports) → `ThreatIntelligence` (reputation from `abuseConfidenceScore` or `positives/total*100`)
- `email.iocs` (`ips`/`ip_addresses`→`IOCData.ips`, `domains`, `urls`, `hashes`) → `IOCData`
- `ai_assessment` (`phishing_probability` etc) → `AIAssessment` (defaults `0.0`/`False` when absent — no fabrication)

## AI Input — Saikat is a Signal, Not the Verdict

- AI-dependent rules (`high_phishing_probability` etc) fire only when Saikat sends real probabilities; otherwise defaults keep them inactive.
- Final `risk_score` (0–100) and `verdict` are **always** computed by `logic/` deterministic engine, never copied from AI.

## Cloudflare Tunnel

```bash
uvicorn logic_api:app --host 0.0.0.0 --port 8001
cloudflared tunnel --url http://localhost:8001
# → https://<random>.trycloudflare.com/receive-subhom-analysis
#    https://<random>.trycloudflare.com/receive-ai-analysis

# Named tunnel:
cloudflared tunnel create trinetra-logic
cloudflared tunnel route dns trinetra-logic logic.yourdomain.com
cloudflared tunnel run trinetra-logic
# ingress: logic.yourdomain.com -> http://localhost:8001
```

Give Subhom: `https://logic.yourdomain.com/receive-analysis` and Saikat: `.../receive-ollama` (or legacy `.../receive-subhom-analysis` / `.../receive-ai-analysis` aliases). Set `VITE_LOGIC_BASE_URL=https://logic.yourdomain.com` in `frontend/.env` so the browser can poll the Logic Receiver directly (multi-machine) — or `http://127.0.0.1:8000` when same-machine. `BACKEND_PUBLIC_URL` only needed if `ENABLE_BACKEND_CALLBACK=true`.

## Testing

```bash
pip install -r requirements.txt
pytest -v  # 37 tests (legacy + engine)

# Two-phase manual:
# Terminal 1: uvicorn logic_api:app --host 0.0.0.0 --port 8001
# Terminal 2:
curl -X POST http://localhost:8001/receive-subhom-analysis -H "Content-Type: application/json" -d @manual_test_data/backend.json
curl -X POST http://localhost:8001/receive-ai-analysis -H "Content-Type: application/json" -d @manual_test_data/ai_assessment.json
# second call returns correlated result; check Subhom callback or /pending
curl http://localhost:8001/pending
```

All tests import `logic_api:app` — production app == tested app.

## Configuration

| YAML | Env Override | Default |
|------|--------------|---------|
| `verdict_thresholds.low_max` | `TRINETRA_VERDICT_LOW_MAX` | 20 |
| `rule_weights.spf_fail` | `TRINETRA_WEIGHT_SPF_FAIL` | 10 |
| `thresholds.reputation` | `TRINETRA_THRESHOLD_REPUTATION` | 70 |
| `scoring.method` | `TRINETRA_SCORING_METHOD` | capped |
| `logging.level` | `TRINETRA_LOG_LEVEL` | INFO |

## Requirements

```
fastapi, uvicorn, pydantic, pyyaml, python-dotenv, requests, httpx, pytest, pytest-asyncio
```

No Ollama SDK, no DB driver.

## License

Internal TRINETRA project — not for public distribution.
