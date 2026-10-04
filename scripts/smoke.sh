#!/usr/bin/env bash
# Smoke / acceptance test against a RUNNING instance (curl + cookie jar, no browser).
#
#   scripts/smoke.sh --health-only [BASE_URL]   # /healthz, /readyz, security headers (+ HSTS over https); writes nothing
#   scripts/smoke.sh [BASE_URL]                 # adds the public pages: /register, /login, anonymous /overview, /coffee/single
#   SMOKE_USERNAME=... SMOKE_PASSWORD=... scripts/smoke.sh [BASE_URL]   # full run, signs in as a test account
#
# BASE_URL defaults to $BASE_URL or http://localhost:8000. CURL_OPTS adds curl options (e.g. "--cacert ca.pem").
#
# Public checks (no account needed): GET /register and /login answer 200, an anonymous GET /overview
# redirects to /login with Cache-Control: no-store (it parks one `view_site` pending action, the only write),
# an anonymous GET /coffee/single answers 200 and sets no cookie (a GET never writes), /admin is not open.
#
# The full run needs a price in effect and an existing verified test account (create it through /register,
# which sends a confirmation mail; a guest account needs its sponsor's approval), and WRITES TO THE LEDGER:
# it scans without a session (pending coffee), signs in as that account, which records a single, records a
# double, replays a POST, reads the site pages, and undoes what the undo window allows. Afterwards deactivate
# the test account in /admin/users.
set -uo pipefail

health_only=0
if [ "${1:-}" = "--health-only" ]; then health_only=1; shift; fi
base="${1:-${BASE_URL:-http://localhost:8000}}"
base="${base%/}"
smoke_user="${SMOKE_USERNAME:-}"
smoke_password="${SMOKE_PASSWORD:-}"
signed_in_run=0
if [ -n "$smoke_user" ] && [ -n "$smoke_password" ]; then signed_in_run=1; fi
if [ -n "$smoke_user$smoke_password" ] && [ "$signed_in_run" -eq 0 ]; then
  echo "error: set both SMOKE_USERNAME and SMOKE_PASSWORD, or neither" >&2
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
header_value() { tr -d '\r' <"$tmp/head" | sed -n "s/^$1: *//Ip" | head -n1; }

req GET /healthz; expect 200 "" "GET /healthz"
req GET /readyz; expect 200 "" "GET /readyz (database reachable and migrated)"
req GET /; header_present content-security-policy || fail "Content-Security-Policy header missing"
header_present x-content-type-options || fail "X-Content-Type-Options header missing"
header_present referrer-policy || fail "Referrer-Policy header missing"
ok "security headers present (CSP, X-Content-Type-Options, Referrer-Policy)"
if printf '%s' "$base" | grep -q '^https://'; then
  header_present strict-transport-security || fail "HSTS header missing (is ENVIRONMENT=production?)"
  ok "HSTS present"
else
  echo "note: base URL is not https; the HSTS check is skipped"
fi
[ "$health_only" -eq 0 ] || { echo "smoke (health only): all checks passed"; exit 0; }

# --- public pages (no account) --------------------------------------------------------------------
req GET /register; expect 200 "" "GET /register"
req GET /login; expect 200 "" "GET /login"
grep -q 'href="/register"' "$tmp/body" || fail "/login has no link to /register"
req GET /overview; expect 303 '/login$' "anonymous GET /overview -> /login"
header_value cache-control | grep -qi 'no-store' || fail "anonymous /overview redirect lacks Cache-Control: no-store"
ok "the redirect carries Cache-Control: no-store"
rm -f "$jar"
req GET /coffee/single; expect 200 "" "GET /coffee/single (issues a token, writes nothing)"
if header_present set-cookie; then fail "GET /coffee/single set a cookie (a GET must not write anything)"; fi
ok "GET /coffee/single sets no cookie"
req GET /admin/; [ "$STATUS" != 200 ] || fail "/admin answers anonymous callers with 200"
ok "/admin is not open to anonymous callers (HTTP $STATUS)"
if [ "$signed_in_run" -eq 0 ]; then
  echo "smoke (public checks): all passed. Set SMOKE_USERNAME and SMOKE_PASSWORD for the signed-in run (it writes to the ledger)."
  exit 0
fi

# --- first scan without a session: pending action, then sign in ------------------------------------
rm -f "$jar"
req GET /coffee/single; token="$(field token)"; [ -n "$token" ] || fail "no scan token in the page"
req POST /coffee/single --data-urlencode "token=$token"; expect 303 '/login$' "POST scan without session -> /login"
req GET /login; expect 200 "" "GET /login (with the pending coffee)"
csrf="$(field csrf_token)"; [ -n "$csrf" ] || fail "login form has no CSRF token"
req POST /login --data-urlencode "csrf_token=$csrf" --data-urlencode "username=smoke-$$-nobody" \
  --data-urlencode "password=wrong-$$-password"; expect 401 "" "unknown account rejected"
req POST /login --data-urlencode "csrf_token=$csrf" --data-urlencode "username=$smoke_user" \
  --data-urlencode "password=$smoke_password"
[ "$STATUS" != 503 ] || fail "sign-in reached the ledger but no price is configured: set one first"
expect 303 '/coffee/done/[0-9a-f-]{36}$' "sign in -> pending coffee recorded"
single="${LOCATION##*/}"
req GET "/coffee/done/$single"; expect 200 "" "success page"
req GET "/coffee/done/$single"; expect 200 "" "refreshing the success page"

# --- second scan from the same browser: no prompt, replay is idempotent ----------------------------
req GET /coffee/double; token="$(field token)"; [ -n "$token" ] || fail "no scan token"
req POST /coffee/double --data-urlencode "token=$token"
expect 303 '/coffee/done/[0-9a-f-]{36}$' "second scan records immediately (no sign-in prompt)"
double="${LOCATION##*/}"
[ "$double" != "$single" ] || fail "second scan returned the first event"
req POST /coffee/double --data-urlencode "token=$token"
[ "$STATUS" = 303 ] && [ "${LOCATION##*/}" = "$double" ] || fail "replayed token created or returned a different event"
ok "replayed scan token -> same event, no duplicate"
req GET /account; expect 200 "" "GET /account"

# --- the site (every signed-in account may read it) -------------------------------------------------
req GET /overview; expect 200 "" "signed in: GET /overview"
header_value cache-control | grep -qi 'no-store' || fail "/overview lacks Cache-Control: no-store"
ok "/overview is Cache-Control: no-store"
req GET /overview/people; expect 200 "" "signed in: GET /overview/people"
req GET /privacy; expect 200 "" "GET /privacy"

# --- undo (best effort within the undo window) -------------------------------------------------------
req GET "/coffee/done/$double"; csrf="$(field csrf_token)"
if [ -n "$csrf" ]; then
  req POST "/coffee/undo/$double" --data-urlencode "csrf_token=$csrf"; expect 303 "/coffee/done/$double\$" "undo the double"
  req GET "/coffee/done/$single"; csrf="$(field csrf_token)"
  if [ -n "$csrf" ]; then
    req POST "/coffee/undo/$single" --data-urlencode "csrf_token=$csrf"; expect 303 "/coffee/done/$single\$" "undo the single"
  else
    echo "note: only the latest coffee can be undone; the single coffee stays on the account '$smoke_user'"
  fi
else
  echo "note: undo window already expired; the balance of '$smoke_user' is not zero"
fi

# --- a browser without the session cannot read the event --------------------------------------------
STATUS="$(curl -sS ${extra[@]+"${extra[@]}"} -o /dev/null -w '%{http_code}' --max-time 20 "$base/coffee/done/$single")"
[ "$STATUS" != 200 ] || fail "success page readable without a session"
ok "success page is closed without a session (HTTP $STATUS)"

echo "smoke: all checks passed. Test account: '$smoke_user' (deactivate it in /admin/users when done)."
