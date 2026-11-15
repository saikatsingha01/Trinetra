#!/usr/bin/env bash
set -euo pipefail
FE="$(cd "$(dirname "$0")/frontend" && pwd)"
cd "$FE"
fail=0
check(){ if grep -RIn --include='*.js' --include='*.tsx' --include='*.ts' "$1" src >/dev/null; then echo "[OK] $2"; else echo "[FAIL] $2"; fail=1; fi; }
if grep -RIn --include='*.js' --include='*.tsx' --include='*.ts' 'Subhom is processing security and threat' src >/dev/null; then echo '[FAIL] stale Subhom loader text'; fail=1; else echo '[OK] stale Subhom loader text removed'; fi
check 'TRINETRA is processing security and threat signal' 'TRINETRA loader text'
check 'multiple: true' 'multi-file picker in runnable JS'
check 'SEE PROVIDED GMAIL' 'provided Gmail button'
check 'ThreeDPaper-email.html' '3D email viewer route'
check 'batch-results-tabs' 'result tabs'
if [[ "$(sha256sum public/threeui/ThreeDPaper-japanese-exact.html | awk '{print $1}')" == '8ec1b71c0dbcafbadf908100ae2a08045d0a1087c00a09d28245ef19366c7353' ]]; then echo '[OK] exact ThreeDPaper source hash'; else echo '[FAIL] exact ThreeDPaper source hash'; fail=1; fi
node --check src/components/SecurityReport.js
node --check src/pages/BatchResults.js
node --check src/pages/AnalyzeEmail.js
node --check src/components/UploadZone.js
node --check src/lib/emailViewer.js
echo '[OK] runnable JS syntax'
exit "$fail"
