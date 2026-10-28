#!/usr/bin/env bash
# Full local demonstration for Getter.
#
# This script exercises real separate processes over TLS on loopback:
#   1. initialize a coordinator and two workers;
#   2. prove unauthorized enrollment is rejected;
#   3. run the real sum-of-squares job across two workers and validate hashes;
#   4. pause one worker, kill the other during a recovery job, expire its leases;
#   5. crash and restart the coordinator while the job is in flight;
#   6. resume the remaining worker and verify retry, completion, and aggregation.
#
# It uses only localhost and requires no internet. Python 3, bash, and cargo are
# prerequisites. Set GETTER_BIN to reuse a binary; otherwise a release binary is
# built if target/release/getter does not exist.
#
# Usage: bash scripts/e2e-local.sh
set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$REPO_ROOT"

log() { printf '%s\n' "$*" >&2; }
die() {
    log "E2E FAILURE: $*"
    if [[ -n "${ROOT:-}" && -d "${ROOT:-}" ]]; then
        log "--- diagnostics ---"
        for file in "$ROOT/coord.log" "$ROOT/w1.log" "$ROOT/w2.log"; do
            [[ -f "$file" ]] && { log "### $file"; tail -80 "$file" || true; }
        done
    fi
    exit 1
}

if [[ -n "${GETTER_BIN:-}" ]]; then
    BIN=$GETTER_BIN
elif [[ -x target/release/getter ]]; then
    BIN=$REPO_ROOT/target/release/getter
else
    log "Building release binary (this is the only compilation step)..."
    cargo build --locked -p getter-cli --release || die "cargo build failed"
    BIN=$REPO_ROOT/target/release/getter
fi
[[ -x "$BIN" ]] || die "binary not executable: $BIN"
command -v python3 >/dev/null || die "python3 is required for job generation and JSON assertions"

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

COORD_PORT=$(free_port)
W1_PORT=$(free_port)
W2_PORT=$(free_port)
[[ -n "$COORD_PORT" && -n "$W1_PORT" && -n "$W2_PORT" ]] || die "could not allocate ports"
[[ "$COORD_PORT" != "$W1_PORT" && "$COORD_PORT" != "$W2_PORT" && "$W1_PORT" != "$W2_PORT" ]] || die "port allocation collision"


ROOT=$(mktemp -d "${TMPDIR:-/tmp}/getter-e2e.XXXXXX")
COORD_HOME="$ROOT/coord"
W1_HOME="$ROOT/w1"
W2_HOME="$ROOT/w2"
ROGUE_HOME="$ROOT/rogue"
mkdir -p "$ROOT"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ "${KEEP_E2E_STATE:-0}" == "1" ]]; then
        log "E2E state retained at $ROOT"
    else
        rm -rf "$ROOT"
    fi
}
trap cleanup EXIT

json_get() {
    # json_get <file> <expression>; expression is evaluated in Python with d=obj.
    python3 - "$1" "$2" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    d = json.load(handle)
print(eval(sys.argv[2], {"__builtins__": {}}, {"d": d, "sum": sum, "len": len}))
PY
}

wait_status_json() {
    # wait_status_json <attempts> <suffix: file>? Uses the coordinator status command.
    local attempts=$1
    local i
    for ((i=1; i<=attempts; i++)); do
        if "$BIN" --home "$COORD_HOME" status >/dev/null 2>>"$ROOT/status.err"; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

start_coordinator() {
    "$BIN" --home "$COORD_HOME" coordinator start >>"$ROOT/coord.log" 2>&1 &
    COORD_PID=$!
    PIDS+=("$COORD_PID")
    wait_status_json 80 || die "coordinator did not become reachable"
}

log "1/8 Initializing coordinator and workers ($ROOT)"
"$BIN" --home "$COORD_HOME" init --role coordinator --name e2e-coordinator --bind "127.0.0.1:$COORD_PORT" \
    >>"$ROOT/init.log" 2>&1 || die "coordinator init failed"
start_coordinator

"$BIN" --home "$COORD_HOME" status >>"$ROOT/status.log" 2>&1
"$BIN" --json --home "$COORD_HOME" status >"$ROOT/status.json" 2>>"$ROOT/status.err"
[[ "$(json_get "$ROOT/status.json" 'd["database_healthy"]')" == "True" ]] || die "database is not healthy"

pair_worker() {
    local name=$1 home=$2 control_port=$3 pair_file=$4
    "$BIN" --json --home "$COORD_HOME" pair --name "$name" --ttl-secs 600 >"$pair_file" 2>>"$ROOT/pair.log" \
        || die "pairing failed for $name"
    local token coordinator_url fingerprint
    token=$(json_get "$pair_file" 'd["token"]')
    coordinator_url=$(json_get "$pair_file" 'd["coordinator_url"]')
    fingerprint=$(json_get "$pair_file" 'd["ca_fingerprint"]')
    "$BIN" --home "$home" init --role worker --name "$name" --control-bind "127.0.0.1:$control_port" \
        >>"$ROOT/init.log" 2>&1 || die "worker init failed for $name"
    token_file="$ROOT/join-token-${name}.secret"
    umask 077
    printf '%s\n' "$token" >"$token_file"
    chmod 600 "$token_file"
    "$BIN" --home "$home" worker join --coordinator "$coordinator_url" --token-file "$token_file" \
        --ca-fingerprint "$fingerprint" >>"$ROOT/join.log" 2>&1 || die "worker join failed for $name"
    printf '%s\n' "$fingerprint" >"$ROOT/$name.fingerprint"
}

pair_worker e2e-w1 "$W1_HOME" "$W1_PORT" "$ROOT/w1-pair.json"
pair_worker e2e-w2 "$W2_HOME" "$W2_PORT" "$ROOT/w2-pair.json"

log "2/8 Verifying unauthorized enrollment is rejected"
CA_FINGERPRINT=$(cat "$ROOT/e2e-w1.fingerprint")
"$BIN" --home "$ROGUE_HOME" init --role worker --name rogue-worker --control-bind "127.0.0.1:$(free_port)" \
    >>"$ROOT/init.log" 2>&1 || die "rogue worker init failed"
if "$BIN" --home "$ROGUE_HOME" worker join --coordinator "https://127.0.0.1:$COORD_PORT" \
    --token getter_pair_invalid_invalid_invalid --ca-fingerprint "$CA_FINGERPRINT" \
    >>"$ROOT/rogue.log" 2>&1; then
    die "unauthorized worker unexpectedly enrolled"
fi

log "3/8 Starting two workers"
"$BIN" --home "$W1_HOME" worker start >>"$ROOT/w1.log" 2>&1 & W1_PID=$!; PIDS+=("$W1_PID")
"$BIN" --home "$W2_HOME" worker start >>"$ROOT/w2.log" 2>&1 & W2_PID=$!; PIDS+=("$W2_PID")

ONLINE=0
for _ in $(seq 1 60); do
    sleep 0.25
    "$BIN" --json --home "$COORD_HOME" workers >"$ROOT/workers.json" 2>>"$ROOT/workers.err" || continue
    ONLINE=$(json_get "$ROOT/workers.json" 'sum(1 for w in d["workers"] if w["status"] == "online")')
    [[ "$ONLINE" -ge 2 ]] && break
done
[[ "$ONLINE" -ge 2 ]] || die "two workers did not come online"

log "4/8 Running the real two-worker job"
"$BIN" --json --home "$COORD_HOME" jobs submit --file examples/sum-squares/job.json \
    >"$ROOT/normal-submit.json" 2>>"$ROOT/job.log" || die "normal job submission failed"
NORMAL_JOB_ID=$(json_get "$ROOT/normal-submit.json" 'd["job"]["id"]')
NORMAL_STATE=""
for _ in $(seq 1 120); do
    sleep 0.25
    "$BIN" --json --home "$COORD_HOME" jobs inspect "$NORMAL_JOB_ID" >"$ROOT/normal.json" 2>>"$ROOT/job.log" || true
    NORMAL_STATE=$(json_get "$ROOT/normal.json" 'd["job"]["state"]')
    [[ "$NORMAL_STATE" == "completed" ]] && break
    [[ "$NORMAL_STATE" == "failed" || "$NORMAL_STATE" == "cancelled" ]] && break
done
[[ "$NORMAL_STATE" == "completed" ]] || die "normal job ended in $NORMAL_STATE"
python3 - "$ROOT/normal.json" <<'PY' || die "normal job assertions failed"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["job"]["state"] == "completed", d["job"]["state"]
assert d["progress"]["completed"] == 12, d["progress"]
assert d["progress"]["failed"] == 0, d["progress"]
assert d["result"] is not None
assert d["result"]["verified_tasks"] == 12, d["result"]
assert d["result"]["aggregate_matches_expected"] is True, d["result"]
assert d["result"]["aggregate"] == {"total": "575999928000002000000"}, d["result"]["aggregate"]
workers = {task["assigned_worker_name"] for task in d["tasks"] if task["assigned_worker_name"]}
assert len(workers) == 2, workers
assert all(task["validation_status"] == "verified" for task in d["tasks"]), d["tasks"]
PY
"$BIN" --home "$COORD_HOME" jobs inspect "$NORMAL_JOB_ID" >>"$ROOT/job.log" 2>&1 || true

log "5/8 Preparing deterministic failure recovery"
"$BIN" --home "$W2_HOME" worker pause >>"$ROOT/w2.log" 2>&1 || die "could not pause w2"
python3 examples/sum-squares/generate_job.py --tasks 4 --values 80000000 \
    --timeout-secs 25 --lease-seconds 30 \
    --artifact "$REPO_ROOT/examples/sum-squares/sum_squares.wasm" \
    --out "$ROOT/recovery-job.json" >>"$ROOT/generate.log" 2>&1 || die "recovery job generation failed"
RECOVERY_JOB_ID=$("$BIN" --json --home "$COORD_HOME" jobs submit --file "$ROOT/recovery-job.json" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["job"]["id"])') \
    || die "recovery job submission failed"
RECOVERY_TOTAL=$(json_get "$ROOT/recovery-job.json" 'd["expected_aggregate"]["total"]')
ACTIVE=0
for _ in $(seq 1 200); do
    "$BIN" --json --home "$W1_HOME" worker status >"$ROOT/w1-status.json" 2>>"$ROOT/job.log" || true
    ACTIVE=$(json_get "$ROOT/w1-status.json" 'len(d.get("active_tasks", []))' 2>/dev/null || echo 0)
    [[ "$ACTIVE" -gt 0 ]] && break
    sleep 0.05
done
[[ "$ACTIVE" -gt 0 ]] || die "w1 never reported an active recovery task"
kill -STOP "$W1_PID" 2>/dev/null || die "could not freeze w1"
sleep 0.2
kill -KILL "$W1_PID" 2>/dev/null || true
wait "$W1_PID" 2>/dev/null || true
log "   w1 killed with $ACTIVE active task(s)"

log "6/8 Crashing and restarting the coordinator with the job in flight"
sleep 1
"$BIN" --json --home "$COORD_HOME" jobs inspect "$RECOVERY_JOB_ID" >"$ROOT/pre-restart.json" 2>>"$ROOT/job.log" \
    || die "could not inspect recovery job before restart"
python3 - "$ROOT/pre-restart.json" <<'PY' || die "recovery job was not running before restart"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["job"]["state"] == "running", d["job"]["state"]
assert d["progress"]["running"] + d["progress"]["assigned"] >= 1, d["progress"]
PY
kill -KILL "$COORD_PID" 2>/dev/null || true
wait "$COORD_PID" 2>/dev/null || true
start_coordinator
"$BIN" --json --home "$COORD_HOME" jobs inspect "$RECOVERY_JOB_ID" >"$ROOT/post-restart.json" 2>>"$ROOT/job.log" \
    || die "recovery job disappeared after coordinator restart"
post_restart_state=$(json_get "$ROOT/post-restart.json" 'd["job"]["state"]')
[[ "$post_restart_state" == "running" || "$post_restart_state" == "completed" ]] \
    || die "recovery job state after restart was $post_restart_state"

log "7/8 Resuming w2 and waiting for lease expiry, retry, and completion"
"$BIN" --home "$W2_HOME" worker resume >>"$ROOT/w2.log" 2>&1 || die "could not resume w2"
RECOVERY_STATE=""
for _ in $(seq 1 120); do
    sleep 1
    "$BIN" --json --home "$COORD_HOME" jobs inspect "$RECOVERY_JOB_ID" >"$ROOT/recovery-final.json" 2>>"$ROOT/job.log" || continue
    RECOVERY_STATE=$(json_get "$ROOT/recovery-final.json" 'd["job"]["state"]')
    [[ "$RECOVERY_STATE" == "completed" || "$RECOVERY_STATE" == "failed" || "$RECOVERY_STATE" == "cancelled" ]] && break
done
[[ "$RECOVERY_STATE" == "completed" ]] || die "recovery job ended in $RECOVERY_STATE"
python3 - "$ROOT/recovery-final.json" "$RECOVERY_TOTAL" <<'PY' || die "recovery job assertions failed"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
expected_total = sys.argv[2]
assert d["job"]["state"] == "completed", d["job"]["state"]
assert d["progress"]["completed"] == 4, d["progress"]
assert d["result"] is not None
assert d["result"]["verified_tasks"] == 4, d["result"]
assert d["result"]["aggregate_matches_expected"] is True, d["result"]
assert d["result"]["aggregate"] == {"total": expected_total}, d["result"]["aggregate"]
assert all(task["validation_status"] == "verified" for task in d["tasks"]), d["tasks"]
assert all(task["state"] == "completed" for task in d["tasks"]), d["tasks"]
assert any(task["attempts"] >= 2 for task in d["tasks"]), d["tasks"]
assert all(task["assigned_worker_name"] == "e2e-w2" for task in d["tasks"]), d["tasks"]
PY

log "8/8 Verifying CLI status, workers, contribution, and doctor"
"$BIN" --home "$COORD_HOME" workers >"$ROOT/workers-final.txt" 2>>"$ROOT/cli.log"
grep -q 'e2e-w1' "$ROOT/workers-final.txt" || die "w1 missing from worker list"
grep -q 'offline' "$ROOT/workers-final.txt" || die "killed worker was not shown offline"
grep -q 'e2e-w2' "$ROOT/workers-final.txt" || die "w2 missing from worker list"
"$BIN" --json --home "$COORD_HOME" contribute >"$ROOT/contribution.json" 2>>"$ROOT/cli.log"
python3 - "$ROOT/contribution.json" <<'PY' || die "contribution assertions failed"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["summary"]["successful_tasks"] >= 16, d["summary"]
assert d["summary"]["failed_attempts"] >= 3, d["summary"]
assert d["summary"]["completed_jobs"] >= 2, d["summary"]
assert d["summary"]["verified_tasks"] >= 16, d["summary"]
assert d["summary"]["compute_ms"] > 0, d["summary"]
PY
"$BIN" --home "$COORD_HOME" doctor >"$ROOT/doctor.log" 2>>"$ROOT/cli.log" \
    || { cat "$ROOT/doctor.log" >&2; die "doctor reported blocking problems"; }
# The coordinator is still running; the worker list can lag heartbeat timeout.
"$BIN" --home "$COORD_HOME" status >>"$ROOT/cli.log" 2>&1 || die "final status failed"

if [[ "${KEEP_E2E_STATE:-0}" == "1" ]]; then
    log "logs: $ROOT"
else
    # Give the coordinator a moment to record the final state before cleanup.
    sleep 0.2
fi

printf 'GETTER_E2E_PASS jobs=2 workers=2 retried_tasks=1 coordinator_restarts=1 verification=exact_sha256\n'
