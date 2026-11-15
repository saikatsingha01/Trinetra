#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
FRONTEND="$ROOT/frontend"
PAPER="$FRONTEND/public/threeui/ThreeDPaper-japanese-exact.html"

expected='8ec1b71c0dbcafbadf908100ae2a08045d0a1087c00a09d28245ef19366c7353'
actual="$(sha256sum "$PAPER" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || { echo "ThreeDPaper SHA mismatch: $actual"; exit 1; }
[[ "$(wc -c < "$PAPER")" == "630847" ]] || { echo "ThreeDPaper byte-size mismatch"; exit 1; }
! grep -R --exclude-dir=node_modules -q "Subhom is processing security and threat signals" "$FRONTEND/src" || { echo "Stale loader text remains"; exit 1; }
grep -R --exclude-dir=node_modules -q "TRINETRA is processing security and threat signal\." "$FRONTEND/src/components" || { echo "TRINETRA loader text missing"; exit 1; }
grep -q 'multiple: true' "$FRONTEND/src/components/UploadZone.js" || { echo "Multiple upload missing in runnable JS"; exit 1; }
grep -q "SEE PROVIDED GMAIL" "$FRONTEND/src/components/SecurityReport.js" || { echo "Provided Gmail button missing in runnable JS"; exit 1; }
grep -q 'cases/batch' "$FRONTEND/src/App.js" || { echo "Batch route missing in runnable JS"; exit 1; }

echo "TRINETRA fixes verified."
