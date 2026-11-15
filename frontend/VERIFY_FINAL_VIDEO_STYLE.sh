#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
F="$ROOT/frontend"
H=$(sha256sum "$F/public/threeui/ThreeDPaper-original-exact.html" | awk '{print $1}')
test "$H" = "8ec1b71c0dbcafbadf908100ae2a08045d0a1087c00a09d28245ef19366c7353"
grep -q 'multiple: true' "$F/src/components/UploadZone.js"
grep -q 'TRINETRA is processing security and threat signal.' "$F/src/components/AnalysisProgress.js"
grep -q 'ThreeDPaper-email.html' "$F/src/components/SecurityReport.js"
grep -q 'provided-gmail-modal__close' "$F/src/components/SecurityReport.js"
grep -q 'batch-results-tabs' "$F/src/pages/BatchResults.js"
grep -q "type!=='trinetra-email'" "$F/public/threeui/ThreeDPaper-email.html"
echo PASS
