#!/usr/bin/env bash
set -euo pipefail
FILE="frontend/public/threeui/ThreeDPaper-japanese-exact.html"
EXPECTED_SHA="8ec1b71c0dbcafbadf908100ae2a08045d0a1087c00a09d28245ef19366c7353"
EXPECTED_BYTES=630847
ACTUAL_SHA="$(sha256sum "$FILE" | awk '{print $1}')"
ACTUAL_BYTES="$(wc -c < "$FILE")"
[[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || { echo "SHA mismatch: $ACTUAL_SHA"; exit 1; }
[[ "$ACTUAL_BYTES" == "$EXPECTED_BYTES" ]] || { echo "Size mismatch: $ACTUAL_BYTES"; exit 1; }
echo "ThreeDPaper exact source verified."
