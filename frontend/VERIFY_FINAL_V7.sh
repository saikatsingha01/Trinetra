#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
python -m py_compile logic_receiver.py pdf_report.py
node --check frontend/src/components/SecurityReport.js
node --check frontend/src/components/SecurityOverview.js
node --check frontend/src/lib/pdf.js
node --check frontend/src/pages/BatchResults.js
node --check frontend/src/pages/AnalyzeEmail.js
node --check frontend/src/components/UploadZone.js
python - <<'PY'
from pathlib import Path
from pdf_report import build_report_pdf
sample={'case_id':'verify','risk_score':61,'verdict':'HIGH','analysis_mode':'subhom_only','analysis_confidence':{'score':41,'label':'Low','factors':{'ai_availability':0},'rationale':['Ollama AI assessment was unavailable.']},'email':{'subject':'Verify','from':'a@example.com','to':'b@example.com'},'security_analysis':{'spf':{'result':'pass'}},'threat_intelligence':{},'iocs':{},'ai_assessment':{},'reasons':['test'], 'correlations':[], 'triggered_rules':[], 'score_breakdown':{}, 'model_info':{}}
pdf=build_report_pdf(sample)
assert pdf.startswith(b'%PDF-') and len(pdf)>1000
print('PDF generation OK', len(pdf))
PY
if grep -RIn 'NOCTURNE' frontend/src frontend/public/threeui/ThreeDPaper-email.html >/tmp/nocturne_hits 2>/dev/null; then
  cat /tmp/nocturne_hits
  echo 'ERROR: NOCTURNE remains in active files'
  exit 1
fi
grep -RIn 'EXPORT AS PDF' frontend/src/components/SecurityReport.js frontend/src/components/SecurityReport.tsx >/dev/null
grep -RIn 'multiple: true' frontend/src/components/UploadZone.js >/dev/null
grep -RIn 'subhom_only' logic_receiver.py frontend/src/components/SecurityReport.js >/dev/null
echo 'TRINETRA V7 verification OK'
