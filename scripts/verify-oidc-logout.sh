#!/bin/bash
# Reproduces the logout scenario: log in through OIDC, log out, log in as root,
# and check that the API request is no longer authenticated as the OIDC user.
#
# The session that the OIDC login created must not survive the logout, and the
# native login that follows must not be shadowed by it.

set -uo pipefail

BASE="${1:-http://localhost:5081}"
JAR="$(mktemp)"
STATE="$(mktemp)"
trap 'rm -f "$JAR" "$STATE"' EXIT

fail=0
ok()   { printf '  OK   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n' "$1"; fail=1; }

sessions() {
  sqlite3 /opt/git/ExposedObserve/data/openobserve/db/metadata.sqlite \
    "SELECT count(*) FROM sessions;" 2>/dev/null || echo "?"
}

printf '\n=== 1. Log in through OIDC ===\n'
AUTH=$(curl -sS -D - -o /dev/null -c "$JAR" --max-time 15 \
  "$BASE/auth/sso/login" | grep -i '^location:' | sed 's/^[Ll]ocation: *//' | tr -d '\r')
[ -n "$AUTH" ] && ok "redirected to the IdP" || { bad "no redirect"; exit 1; }

CB=$(curl -sS -D - -o /dev/null -b "$JAR" -c "$JAR" -X POST "$AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'username=test@example.com' \
  --data-urlencode 'claims={"sub":"sso-test-user","email":"test@example.com","name":"OSS Test User","groups":["default/admin","eo/user"]}' \
  | grep -i '^location:' | sed 's/^[Ll]ocation: *//' | tr -d '\r')
[ -n "$CB" ] && ok "got the callback URL" || { bad "no callback"; exit 1; }

curl -sS -o /dev/null -b "$JAR" -c "$JAR" --max-time 15 "$CB"
if grep -q 'eo-auth-session' "$JAR"; then
  ok "session cookie issued"
else
  bad "no session cookie"; exit 1
fi
printf '  sessions in the meta store: %s\n' "$(sessions)"

printf '\n=== 2. The session authenticates an API request ===\n'
code=$(curl -sS -o /tmp/o2_before.txt -w '%{http_code}' -b "$JAR" --max-time 15 "$BASE/api/default/streams")
if [ "$code" = "200" ]; then ok "GET /api/default/streams -> 200 (OIDC user)"; else bad "GET /api/default/streams -> $code"; fi

printf '\n=== 3. Log out ===\n'
curl -sS -o /dev/null -b "$JAR" -c "$JAR" --max-time 15 "$BASE/config/logout"
if grep -q 'eo-auth-session' "$JAR"; then
  bad "the session cookie is still set"
else
  ok "the session cookie was cleared"
fi
printf '  sessions in the meta store: %s\n' "$(sessions)"

printf '\n=== 4. Log in as root ===\n'
curl -sS -o /dev/null -c "$JAR" --max-time 15 -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  --data '{"email":"root@example.com","password":"Complexpass#123"}'
if grep -q 'auth_tokens' "$JAR"; then ok "root session issued"; else bad "no root session"; fi

printf '\n=== 5. The API request must not be the OIDC user any more ===\n'
code=$(curl -sS -o /tmp/o2_after.txt -w '%{http_code}' -b "$JAR" --max-time 15 "$BASE/api/default/streams")
printf '  GET /api/default/streams -> %s\n' "$code"
if [ "$code" = "200" ]; then
  if grep -qi 'test@example.com' /tmp/o2_after.txt; then
    bad "the response still carries the OIDC user"
  else
    ok "the response is the root user, not the OIDC one"
  fi
else
  ok "the request is no longer the OIDC user (status $code)"
fi

printf '\n'
if [ "$fail" = "0" ]; then echo "RESULT: the logout ends the OIDC session"; else echo "RESULT: something still carries the OIDC session"; fi
exit "$fail"
