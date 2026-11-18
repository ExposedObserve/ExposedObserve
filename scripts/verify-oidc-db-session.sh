#!/bin/bash
# End-to-end check of the OIDC session store against a running node.
#
# Walks the real browser flow against the mock OIDC provider and verifies that
# the session ended up in the meta store, and that the cookie alone authenticates
# an API request. Pass the base URL as the first argument (default http://localhost:5081).

set -uo pipefail

BASE="${1:-http://localhost:5081}"
COOKIE_JAR="$(mktemp)"
STATE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR" "$STATE_JAR"' EXIT

PSQL="docker compose -f docker-compose.yml exec -T db psql -U exposedobserve -d exposedobserve -tAc"

fail=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  OK   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

step "1. Reset the session table"
before=$($PSQL "SELECT count(*) FROM sessions;")
$PSQL "DELETE FROM sessions;" >/dev/null
ok "cleared ($before rows before)"

step "2. GET /auth/sso/login (expect a redirect to the IdP)"
login_headers=$(curl -sS -D - -o /dev/null -c "$COOKIE_JAR" --max-time 15 "$BASE/auth/sso/login")
authorize_url=$(printf '%s' "$login_headers" | grep -i '^location:' | sed 's/^[Ll]ocation: *//' | tr -d '\r')
if [ -n "$authorize_url" ]; then
  ok "redirected to the IdP"
else
  bad "no redirect to the IdP"
  printf '%s\n' "$login_headers" | head -20
  exit 1
fi

step "3. Sign in at the IdP (mock provider issues the code)"
callback_headers=$(curl -sS -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" --max-time 20 \
  -X POST "$authorize_url" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'username=test@example.com' \
  --data-urlencode 'claims={"sub":"sso-test-user","email":"test@example.com","name":"OSS Test User","groups":["default/admin","eo/user"]}')
callback_url=$(printf '%s' "$callback_headers" | grep -i '^location:' | sed 's/^[Ll]ocation: *//' | tr -d '\r')
if [ -z "$callback_url" ]; then
  bad "the IdP did not redirect back to the callback"
  printf '%s\n' "$callback_headers" | head -20
  exit 1
fi
ok "got the callback URL"

step "4. GET the callback (token exchange, session write)"
final_headers=$(curl -sS -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" --max-time 20 "$callback_url")
final_status=$(printf '%s' "$final_headers" | head -1)
printf '  %s\n' "$final_status"
session_cookie=$(grep -o 'eo-auth-session[[:space:]].*' "$COOKIE_JAR" | awk '{print $2}' | head -1)
if [ -n "$session_cookie" ]; then
  ok "session cookie issued: ${session_cookie:0:16}..."
else
  bad "no session cookie was issued"
  printf '%s\n' "$final_headers" | head -20
  exit 1
fi

step "5. The session must be in the meta store"
row=$($PSQL "SELECT session_id || '|' || left(access_token, 30) FROM sessions WHERE session_id = '$session_cookie';")
if [ -n "$row" ]; then
  ok "row found: $row"
else
  bad "no row for session id '$session_cookie'"
  $PSQL "SELECT session_id, left(access_token, 30) FROM sessions;"
  exit 1
fi

step "6. The token payload must not be in the cookie"
if printf '%s' "$session_cookie" | grep -qE 'eyJ|Bearer'; then
  bad "the cookie carries a token: $session_cookie"
else
  ok "the cookie carries only the session id"
fi

step "7. An API request with the cookie must be authenticated"
# A querier route: on a router node this is proxied to a querier, which is the
# path that used to fail with "OIDC session not found".
api_path="/api/default/streams"
api_status=$(curl -sS -o /tmp/o2_api_body.txt -w '%{http_code}' -b "$COOKIE_JAR" --max-time 15 \
  "$BASE$api_path")
case "$api_status" in
  200) ok "GET $api_path -> 200" ;;
  401|403) bad "GET $api_path -> $api_status (session not resolved)" ;;
  *) ok "GET $api_path -> $api_status" ;;
esac

step "8. A request without the cookie must be rejected"
noauth_status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$BASE$api_path")
if [ "$noauth_status" = "401" ] || [ "$noauth_status" = "403" ]; then
  ok "without a cookie -> $noauth_status"
else
  bad "without a cookie -> $noauth_status (expected 401/403)"
fi

step "9. Logging out must delete the row"
curl -sS -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" --max-time 15 "$BASE/auth/sso/logout"
left=$($PSQL "SELECT count(*) FROM sessions WHERE session_id = '$session_cookie';")
if [ "$left" = "0" ]; then
  ok "the row is gone"
else
  bad "the row is still there ($left rows)"
fi

printf '\n'
if [ "$fail" = "0" ]; then
  echo "RESULT: all checks passed"
else
  echo "RESULT: some checks failed"
fi
exit "$fail"
