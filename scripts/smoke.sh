#!/usr/bin/env bash
# Smoke / acceptance test against a RUNNING instance (curl + cookie jar, no browser).
#
#   ACCESS_CODE=... scripts/smoke.sh [BASE_URL]            # full run
#   scripts/smoke.sh --health-only [BASE_URL]              # /healthz, /readyz, headers only
#
# BASE_URL defaults to $BASE_URL or http://localhost:8000. CURL_OPTS adds curl options (e.g. "--cacert ca.pem").
#
# The full run needs at least one active chair and a price in effect, and WRITES TO THE LEDGER: it
# registers a profile named "Smoke Test <timestamp>", records a single and a double coffee, replays a
# POST, and undoes what the undo window allows. Afterwards deactivate that profile in /admin/users.
set -uo pipefail

health_only=0
if [ "${1:-}" = "--health-only" ]; then health_only=1; shift; fi
base="${1:-${BASE_URL:-http://localhost:8000}}"
base="${base%/}"
code="${ACCESS_CODE:-}"
if [ "$health_only" -eq 0 ] && [ -z "$code" ]; then
  echo "error: set ACCESS_CODE (or use --health-only)" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
jar="$tmp/jar"
read -r -a extra <<<"${CURL_OPTS:-}"
origin="$(printf '%s' "$base" | sed -E 's#^(https?://[^/]+).*#\1#')"

step=0
fail() { echo "FAIL: $*" >&2; [ -s "$tmp/body" ] && head -c 400 "$tmp/body" >&2; exit 1; }
ok() { step=$((step + 1)); printf 'ok %02d  %s\n' "$step" "$*"; }

# req METHOD PATH [curl args...] -> sets STATUS, LOCATION; headers in $tmp/head, body in $tmp/body
req() {
  local method="$1" path="$2"
  shift 2
  STATUS="$(curl -sS ${extra[@]+"${extra[@]}"} -X "$method" -b "$jar" -c "$jar" -D "$tmp/head" -o "$tmp/body" \
    -H "Origin: $origin" -H "Sec-Fetch-Site: same-origin" -w '%{http_code}' --max-time 20 "$@" "$base$path")" \
    || fail "$method $path: curl error"
  LOCATION="$(tr -d '\r' <"$tmp/head" | sed -n 's/^[Ll]ocation: //p' | head -n1)"
}
expect() { # expect STATUS [LOCATION-regex] description
  [ "$STATUS" = "$1" ] || fail "$3: expected HTTP $1, got $STATUS ($LOCATION)"
  [ -z "$2" ] || printf '%s' "$LOCATION" | grep -Eq "$2" || fail "$3: expected redirect to $2, got '$LOCATION'"
  ok "$3"
}
field() { # field NAME -> value of <input name="NAME" value="..."> in the last body
  sed -n "s/.*name=\"$1\"[^>]*value=\"\([^\"]*\)\".*/\1/p" "$tmp/body" | head -n1
}
header_present() { tr -d '\r' <"$tmp/head" | grep -qi "^$1:"; }

req GET /healthz; expect 200 "" "GET /healthz"
req GET /readyz; expect 200 "" "GET /readyz (database reachable and migrated)"
req GET /; header_present content-security-policy || fail "Content-Security-Policy header missing"
header_present x-content-type-options || fail "X-Content-Type-Options header missing"
ok "security headers present"
if printf '%s' "$base" | grep -q '^https://'; then
  header_present strict-transport-security || fail "HSTS header missing (is ENVIRONMENT=production?)"
  ok "HSTS present"
fi
[ "$health_only" -eq 0 ] || { echo "smoke (health only): all checks passed"; exit 0; }

req GET /admin/; [ "$STATUS" != 200 ] || fail "/admin answers anonymous callers with 200"
ok "/admin is not open to anonymous callers (HTTP $STATUS)"

# --- first scan without a session: pending action + access gate + registration ------------------
req GET /coffee/single; expect 200 "" "GET /coffee/single (issues a token, writes nothing)"
token="$(field token)"; [ -n "$token" ] || fail "no scan token in the page"
req POST /coffee/single --data-urlencode "token=$token"; expect 303 '/join$' "POST scan without session -> /join"
req GET /register; [ "$STATUS" != 200 ] || fail "/register reachable without the access code"
ok "/register is closed without the access code (HTTP $STATUS)"
req POST /join --data-urlencode "code=wrong-$$-code"; [ -z "$LOCATION" ] || fail "wrong access code accepted"
ok "wrong access code rejected"
req POST /join --data-urlencode "code=$code"; expect 303 '/join$' "correct access code accepted"
req GET /register; expect 200 "" "GET /register with gate cookie"
csrf="$(field csrf_token)"; reg="$(field registration_token)"
chair="$(sed -n 's/.*<option value="\([0-9a-fA-F-]\{36\}\)".*/\1/p' "$tmp/body" | head -n1)"
[ -n "$csrf" ] && [ -n "$reg" ] || fail "registration form tokens missing"
[ -n "$chair" ] || fail "no active chair to register with: create one in /admin/chairs first"
name="Smoke Test $(date -u +%Y%m%dT%H%M%SZ)"
req POST /register --data-urlencode "csrf_token=$csrf" --data-urlencode "registration_token=$reg" \
  --data-urlencode "display_name=$name" --data-urlencode "chair_id=$chair" --data-urlencode "privacy_ack=1"
[ "$STATUS" != 503 ] || fail "registration reached the ledger but no price is configured: set one first"
expect 303 '/coffee/done/[0-9a-f-]{36}$' "register -> pending coffee recorded"
single="${LOCATION##*/}"
req POST /register --data-urlencode "csrf_token=$csrf" --data-urlencode "registration_token=$reg" \
  --data-urlencode "display_name=$name" --data-urlencode "chair_id=$chair" --data-urlencode "privacy_ack=1"
[ "$STATUS" = 303 ] && [ "${LOCATION##*/}" = "$single" ] || fail "double-submitted registration did not return the same result"
ok "double-submitted registration is idempotent"

req GET "/coffee/done/$single"; expect 200 "" "success page"
req GET "/coffee/done/$single"; expect 200 "" "refreshing the success page"

# --- second scan from the same browser: no prompt, replay is idempotent ----------------------------
req GET /coffee/double; token="$(field token)"; [ -n "$token" ] || fail "no scan token"
req POST /coffee/double --data-urlencode "token=$token"
expect 303 '/coffee/done/[0-9a-f-]{36}$' "second scan records immediately (no code, no registration)"
double="${LOCATION##*/}"
[ "$double" != "$single" ] || fail "second scan returned the first event"
req POST /coffee/double --data-urlencode "token=$token"
[ "$STATUS" = 303 ] && [ "${LOCATION##*/}" = "$double" ] || fail "replayed token created or returned a different event"
ok "replayed scan token -> same event, no duplicate"
req GET /account; expect 200 "" "GET /account"

# --- undo (best effort within the undo window) -------------------------------------------------------
req GET "/coffee/done/$double"; csrf="$(field csrf_token)"
if [ -n "$csrf" ]; then
  req POST "/coffee/undo/$double" --data-urlencode "csrf_token=$csrf"; expect 303 "/coffee/done/$double\$" "undo the double"
  req GET "/coffee/done/$single"; csrf="$(field csrf_token)"
  if [ -n "$csrf" ]; then
    req POST "/coffee/undo/$single" --data-urlencode "csrf_token=$csrf"; expect 303 "/coffee/done/$single\$" "undo the single"
  else
    echo "note: only the latest coffee can be undone; the single coffee stays on the profile '$name'"
  fi
else
  echo "note: undo window already expired; the balance of '$name' is not zero"
fi

# --- a browser without the session cannot read the event --------------------------------------------
STATUS="$(curl -sS ${extra[@]+"${extra[@]}"} -o /dev/null -w '%{http_code}' --max-time 20 "$base/coffee/done/$single")"
[ "$STATUS" != 200 ] || fail "success page readable without a session"
ok "success page is closed without a session (HTTP $STATUS)"

echo "smoke: all checks passed. Test profile: '$name' (deactivate it in /admin/users)."
