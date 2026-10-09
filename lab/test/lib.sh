#!/bin/sh
# Shared assertion helpers for Hedgerow lab checks. POSIX sh; no bats on host.
# Each check script sources this file, runs assertions, and exits non-zero on
# the first failure so a missing lab fails loudly instead of passing vacuously.
set -u
LAB_DIR=$(cd "$(dirname "$0")/.." && pwd)
COMPOSE="docker compose --project-directory $LAB_DIR"
FAILS=0
PASSES=0

pass() { PASSES=$((PASSES + 1)); printf 'ok   %s\n' "$1"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL %s\n' "$1" >&2; }

assert_eq() { # expected actual label
  if [ "$1" = "$2" ]; then pass "$3"; else fail "$3: expected [$1] got [$2]"; fi
}
assert_contains() { # needle haystack label
  case "$2" in *"$1"*) pass "$3" ;; *) fail "$3: [$1] not in output" ;; esac
}
assert_not_contains() { # needle haystack label
  case "$2" in *"$1"*) fail "$3: [$1] unexpectedly present" ;; *) pass "$3" ;; esac
}
assert_cmd_fails() { # label cmd...
  label=$1; shift
  if "$@" >/dev/null 2>&1; then fail "$label: command unexpectedly succeeded"; else pass "$label"; fi
}

# Run a command inside a lab service container. Fails (non-zero) if the
# service is not running, which is the intended non-vacuity behaviour.
in_svc() { svc=$1; shift; $COMPOSE exec -T "$svc" "$@"; }

load_env() {
  if [ -f "$LAB_DIR/.env" ]; then
    # shellcheck disable=SC1091
    set -a; . "$LAB_DIR/.env"; set +a
  fi
  : "${PIHOLE_API_PASSWORD:?lab/.env missing PIHOLE_API_PASSWORD; run lab/bin/lab init}"
  : "${RG_PIHOLE_HOST_PORT:=8053}"
  RG_PIHOLE_API_BASE="http://127.0.0.1:${RG_PIHOLE_HOST_PORT}/api"
}

# Authenticate once; prints nothing. Session id kept in a variable, never logged.
api_login() {
  resp=$(curl -sS --max-time 10 -X POST "$RG_PIHOLE_API_BASE/auth" \
    -H 'content-type: application/json' \
    --data "{\"password\":$(printf '%s' "$PIHOLE_API_PASSWORD" | jq -Rs .)}")
  SID=$(printf '%s' "$resp" | jq -r '.session.sid // empty')
  [ -n "$SID" ] || { fail "api auth: no session.sid in response"; return 1; }
}
api_logout() { [ -n "${SID:-}" ] && curl -sS --max-time 10 -o /dev/null -X DELETE "$RG_PIHOLE_API_BASE/auth" -H "X-FTL-SID: $SID"; }
api() { # method path [json]
  if [ $# -ge 3 ]; then
    curl -sS --max-time 15 -X "$1" "$RG_PIHOLE_API_BASE$2" -H "X-FTL-SID: $SID" -H 'content-type: application/json' --data "$3"
  else
    curl -sS --max-time 15 -X "$1" "$RG_PIHOLE_API_BASE$2" -H "X-FTL-SID: $SID"
  fi
}

report() {
  printf '%s: %d passed, %d failed\n' "$(basename "$0")" "$PASSES" "$FAILS"
  [ "$FAILS" -eq 0 ]
}
