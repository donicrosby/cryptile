#!/usr/bin/env bash

# Copyright 2026 Doni Crosby
# SPDX-License-Identifier: Apache-2.0
# Cryptile live-fire test suite: boots a real Vaultwarden via compose,
# provisions it through the public API, runs the real cryptile binary
# against it, tears everything down. Exit code = number of failures.
#
# Safe output: no plaintext secrets are ever printed (assertions compare
# values, print only pass/fail and lengths).

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO/integration/docker-compose.yml"
PROJECT="cryptile-vw"
BASE_URL="${CRYPTILE_LIVE_BASE:-http://127.0.0.1:8222}"
STATE_DIR="$REPO/integration/.run/state"
RUN_DIR="$REPO/integration/.run"
SUMMARY="$RUN_DIR/provision-summary.json"
EMAIL="svc-hermes@live.test"
PASSPHRASE="live-keyring-passphrase"
PASS_COUNT=0
FAIL_COUNT=0
BIN="$REPO/target/debug/cryptile"

cd "$REPO"

cleanup() {
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || \
        /usr/local/bin/docker-compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

expect_eq() {
    # expect_eq <label> <expected> <actual>
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1 (expected '$2', got '$3')"
    fi
}

expect_secret_eq() {
    # expect_secret_eq <label> <expected> <actual> — never prints the values
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1 (values differ; expected len ${#2}, got len ${#3})"
    fi
}

expect_secret_contains() {
    # expect_secret_contains <label> <secret-needle> <haystack> — no value echo
    case "$3" in
        *"$2"*) pass "$1" ;;
        *) fail "$1 (secret needle absent)" ;;
    esac
}

expect_contains() {
    # expect_contains <label> <needle> <haystack>
    case "$3" in
        *"$2"*) pass "$1" ;;
        *) fail "$1 (missing '$2')" ;;
    esac
}

# ---------------------------------------------------------------------------
echo "== build =="
cargo build -p cryptile || { echo "build failed"; exit 99; }

# ---------------------------------------------------------------------------
echo "== compose up =="
COMPOSE="docker compose"
$COMPOSE version >/dev/null 2>&1 || COMPOSE="/usr/local/bin/docker-compose"
if ! $COMPOSE -p "$PROJECT" -f "$COMPOSE_FILE" up -d --quiet-pull; then
    echo "compose up failed"; exit 99
fi

echo "== wait for healthy =="
READY=0
for _ in $(seq 1 60); do
    if curl -fsS "$BASE_URL/alive" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done
[ "$READY" = "1" ] || { echo "vaultwarden never became healthy"; exit 99; }

# ---------------------------------------------------------------------------
echo "== provision =="
rm -rf "$RUN_DIR"
mkdir -p "$STATE_DIR"
export CRYPTILE_LIVE_SUMMARY="$SUMMARY"
if ! python3 "$REPO/integration/provision.py" "$BASE_URL" "$EMAIL" "harness-master-password"; then
    echo "provision failed"
    exit 99
fi
ITEM_PASSWORD="$(python3 -c "import json,os; print(json.load(open(os.environ['CRYPTILE_LIVE_SUMMARY']))['item_password'])")"
[ -n "$ITEM_PASSWORD" ] || { echo "no item password in summary"; exit 99; }

# ---------------------------------------------------------------------------
run() {
    # run <passphrase> <args...>  -> sets OUT/ERR/RC
    # Runs under a pty (`script`) so TTY-gated passphrase prompts fire; the
    # passphrase is piped to stdin. The pty echoes both the prompt and the
    # piped passphrase into the output stream; both are stripped below so
    # OUT contains only cryptile's own output lines. RC comes from a temp
    # file (PIPESTATUS is clobbered by command substitution).
    local pp="$1"; shift
    local rcfile
    rcfile="$(mktemp)"
    # PIPESTATUS[1] is script's slot; with -e script exits with the child's
    # (cryptile's) code. Expanded before echo runs, so it still holds the
    # pipeline's statuses.
    OUT="$(
        printf '%s\n' "$pp" \
        | CRYPTILE_MASTER_PASSWORD="harness-master-password" CRYPTILE_PASSPHRASE="$pp" \
          script -qec "$BIN --state-dir $STATE_DIR $(printf '%q ' "$@")" /dev/null \
          2>/tmp/cryptile-live.err \
        | tr -d '\r' \
        | grep -v -F -e "$pp" -e 'keyring passphrase:'
        echo "${PIPESTATUS[1]}" > "$rcfile"
    )"
    RC="$(cat "$rcfile")"
    rm -f "$rcfile"
    ERR="$(cat /tmp/cryptile-live.err)"
}

run_env() {
    # run_env <args...> -> sets OUT/ERR/RC. No pty: for commands that
    # take --passphrase-env (no TTY prompt), so stderr (spans) stays
    # separate from stdout (values) under RUST_LOG.
    local rcfile
    rcfile="$(mktemp)"
    OUT="$(CRYPTILE_PASSPHRASE="$PASSPHRASE" \
          "$BIN" --state-dir "$STATE_DIR" "$@" \
          2>/tmp/cryptile-live.env.err)"
    RC=$?
    echo "$RC" > "$rcfile"
    ERR="$(cat /tmp/cryptile-live.env.err)"
    rm -f "$rcfile"
}

echo "== login =="
run "$PASSPHRASE" login --server "$BASE_URL" --account "$EMAIL" --passphrase-env CRYPTILE_PASSPHRASE --master-password-env CRYPTILE_MASTER_PASSWORD
expect_eq "login exit 0" 0 "$RC"
expect_contains "login sealed" "logged in" "$OUT"

echo "== get =="
run "$PASSPHRASE" get "vw://shared/Postgres HQ#password"
expect_eq "get exit 0" 0 "$RC"
expect_secret_eq "get returns seeded plaintext" "$ITEM_PASSWORD" "$OUT"

echo "== sync cache =="
CACHE_FILE="$STATE_DIR/cache/cipher-index"
if [ -f "$CACHE_FILE" ]; then
    pass "cold get wrote cache file"
else
    fail "cold get wrote cache file"
fi
# Warm get: same answer, and the phase spans prove no full sync happened.
RUST_LOG=cryptile=debug run_env get "vw://shared/Postgres HQ#password" --passphrase-env CRYPTILE_PASSPHRASE
expect_eq "warm get exit 0" 0 "$RC"
expect_secret_eq "warm get returns seeded plaintext" "$ITEM_PASSWORD" "$OUT"
expect_contains "warm get hit span" "get_warm" "$ERR"
expect_contains "warm get recorded hit" "hit=\"true\"" "$ERR"
# Keep the warm-run stderr for post-mortem (diagnostics only, no secrets).
cp /tmp/cryptile-live.env.err "$RUN_DIR/warm.err" 2>/dev/null || true
case "$ERR" in
    *"op=\"sync\""*) fail "warm get avoided full sync" ;;
    *) pass "warm get avoided full sync" ;;
esac
case "$ERR" in
    *"op=\"collections\""*) fail "warm get avoided collections fetch" ;;
    *) pass "warm get avoided collections fetch" ;;
esac
# Self-heal: corrupt the sealed cache; the next get must still succeed.
printf 'crc1.garbage.garbage.garbage.garbage' > "$CACHE_FILE"
run "$PASSPHRASE" get "vw://shared/Postgres HQ#password"
expect_eq "tampered-cache get exit 0" 0 "$RC"
expect_secret_eq "tampered-cache get still correct" "$ITEM_PASSWORD" "$OUT"
[ -f "$CACHE_FILE" ] && pass "tampered cache rebuilt" || fail "tampered cache rebuilt"
# --refresh-cache escape hatch.
RUST_LOG=cryptile=debug run_env get "vw://shared/Postgres HQ#password" --refresh-cache --passphrase-env CRYPTILE_PASSPHRASE
expect_eq "refresh-cache get exit 0" 0 "$RC"
expect_secret_eq "refresh-cache get correct" "$ITEM_PASSWORD" "$OUT"
expect_contains "refresh-cache forced sync" "op=\"sync\"" "$ERR"

echo "== list =="
run "$PASSPHRASE" list shared
expect_eq "list exit 0" 0 "$RC"
expect_contains "list shows item name" "Postgres HQ" "$OUT"
case "$OUT" in
    *"$ITEM_PASSWORD"*) fail "list leaks plaintext" ;;
    *) pass "list metadata only" ;;
esac

echo "== export env =="
run "$PASSPHRASE" export --namespace shared --format env
expect_eq "export env exit 0" 0 "$RC"
expect_contains "export env has mangled key" "PASSWORD=" "$OUT"
expect_secret_contains "export env value" "$ITEM_PASSWORD" "$OUT"

echo "== export json =="
run "$PASSPHRASE" export --namespace shared --format json
expect_eq "export json exit 0" 0 "$RC"
echo "$OUT" | python3 -m json.tool >/dev/null 2>&1 && pass "export json valid" || fail "export json invalid"
expect_secret_contains "export json value" "$ITEM_PASSWORD" "$OUT"

echo "== wrong passphrase =="
run "wrong-passphrase" export --namespace shared --format env
if [ "$RC" -ne 0 ]; then
    pass "wrong passphrase nonzero exit (got $RC)"
else
    fail "wrong passphrase exited 0"
fi

echo "== not found =="
run "$PASSPHRASE" get "vw://shared/nonexistent#password"
expect_eq "not-found exit 5" 5 "$RC"

echo "== backends =="
run "$PASSPHRASE" backends
expect_eq "backends exit 0" 0 "$RC"
expect_contains "backends lists vw" "vw" "$OUT"

# ---------------------------------------------------------------------------
echo "== hermes plugin e2e =="
if [ -d "${HERMES_REPO:-/tmp/hermes}" ] && command -v python3 >/dev/null 2>&1; then
    PLUGIN_LOG="$(mktemp)"
    if CRYPTILE_STATE_DIR="$STATE_DIR" CRYPTILE_PASSPHRASE="$PASSPHRASE" \
       CRYPTILE_LIVE_SUMMARY="$SUMMARY" HERMES_REPO="${HERMES_REPO:-/tmp/hermes}" \
       python3 "$REPO/integration/hermes_plugin_e2e.py" | tee "$PLUGIN_LOG"; then
        :
    else
        echo "(plugin e2e exited nonzero; failures listed above)"
    fi
    PLUGIN_P="$(grep -c '^PASS:' "$PLUGIN_LOG" || true)"
    PLUGIN_F="$(grep -c '^FAIL:' "$PLUGIN_LOG" || true)"
    PASS_COUNT=$((PASS_COUNT + PLUGIN_P))
    FAIL_COUNT=$((FAIL_COUNT + PLUGIN_F))
    rm -f "$PLUGIN_LOG"
else
    echo "SKIP: hermes plugin e2e (no hermes checkout at HERMES_REPO)"
fi

# ---------------------------------------------------------------------------
echo "== bench stage =="
if [ "${SKIP_BENCH:-0}" = "1" ]; then
    echo "SKIP: bench stage (SKIP_BENCH=1)"
else
    BENCH_LOG="$(mktemp)"
    if CRYPTILE_STATE_DIR="$STATE_DIR" CRYPTILE_PASSPHRASE="$PASSPHRASE" \
       CRYPTILE_LIVE_SUMMARY="$SUMMARY" CRYPTILE_LIVE_BASE="$BASE_URL" \
       python3 "$REPO/integration/bench_stage.py" | tee "$BENCH_LOG"; then
        :
    else
        echo "(bench stage exited nonzero; failures listed above)"
    fi
    BENCH_P="$(grep -c '^PASS:' "$BENCH_LOG" || true)"
    BENCH_F="$(grep -c '^FAIL:' "$BENCH_LOG" || true)"
    PASS_COUNT=$((PASS_COUNT + BENCH_P))
    FAIL_COUNT=$((FAIL_COUNT + BENCH_F))
    rm -f "$BENCH_LOG"
fi

# ---------------------------------------------------------------------------
echo
echo "results: $PASS_COUNT passed, $FAIL_COUNT failed"
exit "$FAIL_COUNT"
