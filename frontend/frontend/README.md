# TRINETRA Frontend

A frontend for the TRINETRA email-threat engine — Logic Receiver is source of truth.

```
Frontend (browser) --POST multipart/form-data /receive-email--> Subhom Backend (Cloudflare Tunnel)
Subhom Backend -> parsing / security / intel  ─┐
Ollama (Saikat)  -> AI assessment              ─┼─> Logic Receiver (MY laptop, Cloudflare)
                                               │    correlates via case_id, calculates risk_score + verdict
Frontend (browser) --GET /analysis/{case_id} ──┘    (poll directly, no Subhom round-trip)
```

## Overview

```
.EML file (ONE raw file, field "email")  →  POST multipart/form-data /receive-email to Subhom  →  202 {status:"processing", case_id}
    →  GET /analysis/{case_id} polling to Logic Receiver  →  {status:"processing"} ... {status:"completed", risk_score, verdict, ...}  →  display
```

Nothing in this directory analyses email. The browser sends ONE raw `.eml` as `multipart/form-data` field `email` to Subhom, receives `case_id`/`email_id` with `202 Accepted`, then polls the **Logic Receiver** `GET /analysis/{case_id}` until `completed`. Subhom handles email parsing, security/threat analysis, and forwarding to Ollama + Logic; Logic Receiver owns final risk score + verdict.

## What this frontend does not do

It does not parse `.eml` files, extract headers, URLs, IPs, domains or hashes, evaluate SPF/DKIM/DMARC, query threat intelligence, calculate a risk score, determine a verdict, or correlate findings. All Logic Engine work lives in `logic/` and is reached via the Logic Receiver. The browser never calls VirusTotal, AbuseIPDB, AlienVault, or Ollama directly; it only uploads the raw `.eml` to Subhom and polls the Logic Receiver for the result. The frontend never calculates risk_score — it only displays what Logic Receiver returns.

## Requirements

Node 20.19+ or 22.12+ (Vite 7's floor).

## Run

```bash
cd frontend
npm install
cp .env.example .env      # then edit if needed
npm run dev               # http://localhost:5173
```

Other scripts: `npm run typecheck`, `npm run build`, `npm run preview`.

## Configuration

All configuration is read once, in `src/services/api.ts`. Two base URLs are required (per master prompt):

| Variable | Default | Purpose |
| --- | --- | --- |
| `VITE_BACKEND_BASE_URL` | `http://localhost:8000` | **Subhom backend** base URL via Cloudflare Tunnel (no trailing slash). Production example: `https://<subhom>.trycloudflare.com`. Used **only** for `POST /receive-email`. |
| `VITE_LOGIC_BASE_URL` | `http://127.0.0.1:8000` | **Logic Receiver** base URL (poll target). Same-machine: `http://127.0.0.1:8000`, multi-machine: `https://<logic>.trycloudflare.com`. Browser polls `GET /analysis/{case_id}` here. Must be reachable by browser. |
| `VITE_API_BASE_URL` | `http://localhost:8000` | Legacy alias for `VITE_BACKEND_BASE_URL`. Prefer `VITE_BACKEND_BASE_URL`. |
| `VITE_ANALYZE_PATH` | `/receive-email` | `POST` multipart field `email` with ONE raw `.eml` to Subhom. Backend returns `202 {status:"processing", email_id/case_id}`. No manual `Content-Type` header — browser sets multipart boundary. |
| `VITE_ANALYSIS_PATH` | `/analysis` | Poll `GET {VITE_ANALYSIS_PATH}/{case_id}` on **Logic Receiver** until `{status:"completed"}` or `{status:"failed"}`. While `processing`, polling continues every ~1.5s. Frontend does NOT poll Subhom for final result. |
| `VITE_API_TIMEOUT_MS` | `300000` | Total polling timeout in ms for Logic pipeline (parsing + intel + Ollama + Logic). Per-request fetch timeouts are separate (60s upload, 15s poll). |
| `VITE_ANALYSIS_POLL_INTERVAL_MS` | `1500` | Interval between poll requests to Logic Receiver. |
| `VITE_MAX_UPLOAD_MB` | `25` | Browser-side guard rail only; the backend declares no limit. |

Frontend contacts **Subhom only for upload** (`POST /receive-email`) and **Logic Receiver for result** (`GET /analysis/{case_id}`). The Logic Receiver is the source of truth for final risk score + verdict; the frontend never re-calculates it.

## What the API must return

Required: `risk_score` (number) and `verdict` (one of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `MALICIOUS`). A response without both is treated as a failed analysis.

Everything else is optional and rendered when present: `case_id`, `processing_time_ms`, `verdict_info`, `reasons`, `correlations`, `correlations_by_severity`, `score_breakdown`, `triggered_rules`, `email`, `security_analysis`, `threat_intelligence`, `ai_assessment`, `iocs`, `analyzed_at`, `source_file`.

The field names mirror `logic/models.py` and `LogicEngine.get_detailed_report()` exactly, including: `sender_identity.from` (the Pydantic field is `from_address` with `validation_alias="from"`), and `score_breakdown.triggered_rules`, which is a **count**, while the top-level `triggered_rules` is an **array**.

A response carrying `_temporary: true` is displayed with a "Temporary backend" notice.

## Layout

```
src/
  services/api.ts     the only file that performs HTTP; all errors defined here
  types/analysis.ts   transcription of the Python contract
  lib/severity.ts     verdict/severity → colour. Decides how risk LOOKS, never what it IS
  lib/format.ts       bytes, dates, durations, probabilities
  store/session.tsx   case list, report cache, backend reachability
  components/         primitives, upload flow, and one file per report section
  pages/              Dashboard, AnalyzeEmail, Cases, CaseDetail, ThreatIntel, Settings
```

To swap in a different backend, change `src/services/api.ts`. No component imports `fetch` directly.

## Design notes

Two rules carry the visual system. **Saturated colour means risk** — the only strong colours in the product are the verdict colours (green/amber/orange/red), so a red pixel always means something. **Monospace means machine output** — addresses, hashes, rule ids and scores are set in mono; commentary and model explanations are set in the body face.

The risk score is drawn as a ladder rather than a dial. The engine returns the threshold table it used (`verdict_info.thresholds`), so the score is plotted against the real bands.

The processing screen shows only what is actually known: the file was sent as `multipart/form-data` field `email` to Subhom, Subhom returned `202 {status:"processing", case_id}`, and the UI polls `GET /analysis/{case_id}` on the **Logic Receiver** every 1.5s until `completed`. No per-stage telemetry is implied. Timeout shows “Analysis is taking longer than expected. Please try again or check the connection.”

Motion is limited to a 120ms settle on state changes, one spinner, and one pulsing status dot. `prefers-reduced-motion` removes all of it.
