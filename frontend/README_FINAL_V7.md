# TRINETRA V7 - PDF Export, Ollama Fallback, Confidence Clarity

## Included changes
- Balanced readable Gmail text inside the 3D paper texture.
- `TRINETRA` wordmark in the active 3D Gmail scene; canonical ThreeDPaper source remains unchanged.
- `EXPORT AS PDF` action on every completed report.
- Backend endpoint: `GET /analysis/{case_id}/pdf`.
- PDF export uses ReportLab and includes the final verdict, risk score, confidence score, confidence factor definitions/values, email metadata, security analysis, threat intelligence, IOC inventory, AI assessment, reasons, correlations, triggered rules, score breakdown, and metadata.
- Ollama failure path remains deterministic: the report is calculated from Subhom security/threat evidence only, confidence is capped lower, the UI and PDF clearly explain the missing AI signal, and the user is asked to re-upload.
- Confidence UI explicitly explains what each confidence factor means and distinguishes confidence from risk.

## Run

Backend:
```bash
pip install -r requirements.txt
uvicorn logic_receiver:app --host 0.0.0.0 --port 8000
```

Frontend:
```bash
cd frontend
npm ci
npm run build
npm run dev
```

The browser needs `VITE_LOGIC_BASE_URL` pointed at the Logic Receiver URL so the PDF download endpoint is reachable.
