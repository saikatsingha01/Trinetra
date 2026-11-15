#!/bin/sh
set -eu
F="frontend/public/threeui/ThreeDPaper-email.html"
grep -q '<div id="bg"><h1>TRINETRA</h1></div>' "$F"
! grep -q '<div id="bg"><h1>NOCTURNE</h1></div>' "$F"
grep -q "700 88px \"Inter Tight\"" "$F"
grep -q "500 26px Inter" "$F"
printf '%s\n' 'OK: TRINETRA wordmark and enlarged Gmail typography are present.'
