#!/bin/sh
# Push a branch without storing the token anywhere. Usage: TOKEN=... sh docs/status/push.sh [branch]
set -e
b="${1:-v2}"
B64=$(printf 'x-access-token:%s' "$TOKEN" | base64 -w0)
git -c http.extraheader="Authorization: Basic $B64" push -q origin "$b" 2>&1 | grep -v negotiation || true
git status -sb | head -1
