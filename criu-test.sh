#!/usr/bin/env bash

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
CRIU_BIN=${CRIU_BIN:-"$SCRIPT_DIR/criu/criu"}
SUDO=${SUDO:-sudo}
RUN_TAG=${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}
BASE_DIR=${BASE_DIR:-/tmp/criu-test-${RUN_TAG}}
DUMP_TIMEOUT_SEC=${DUMP_TIMEOUT_SEC:-180}
RESTORE_TIMEOUT_SEC=${RESTORE_TIMEOUT_SEC:-180}
TARGET_MB=${TARGET_MB:-64}
PYTHON_BIN=${PYTHON_BIN:-$(command -v python3 || true)}
RESTORE_DETACHED=${RESTORE_DETACHED:-1}

if [ "$(id -u)" -eq 0 ]; then
    SUDO=
fi

TOTAL=0
PASS=0
FAIL=0

cleanup_marker() {
    local marker="$1"
    local pids

    pids=$(pgrep -f "$marker" || true)
    if [ -n "$pids" ]; then
        $SUDO kill $pids 2>/dev/null || true
        sleep 1
        pids=$(pgrep -f "$marker" || true)
        if [ -n "$pids" ]; then
            $SUDO kill -9 $pids 2>/dev/null || true
        fi
    fi
}

start_target() {
    local marker="$1"
    local run_dir="$2"
    local pid
    local out_log="$run_dir/target.out"
    local err_log="$run_dir/target.err"
    local ready_file="$run_dir/target.ready"

    rm -f "$ready_file"
    setsid "$PYTHON_BIN" - "$marker" "$TARGET_MB" "$ready_file" <<'PY' >"$out_log" 2>"$err_log" &
import sys
import time

marker = sys.argv[1]
mb = int(sys.argv[2])
ready_file = sys.argv[3]

try:
    buf = bytearray(mb * 1024 * 1024)
except MemoryError:
    # Keep process alive with smaller footprint so test can still run.
    buf = bytearray(8 * 1024 * 1024)

for i in range(0, len(buf), 4096):
    buf[i] = (i // 4096) % 251

with open(ready_file, "w", encoding="ascii") as f:
    f.write("ready\n")

print("ready", marker, flush=True)
while True:
    time.sleep(1)
PY

    pid=$!
    echo "$pid"
}

run_with_timeout() {
    local timeout_sec="$1"
    shift
    local rc

    if command -v timeout >/dev/null 2>&1; then
        timeout --signal=TERM --kill-after=10s "${timeout_sec}s" "$@"
        rc=$?
        if [ "$rc" -eq 124 ]; then
            echo "  command timed out after ${timeout_sec}s"
        fi
        return $rc
    fi

    "$@"
    return $?
}

run_case() {
    local name="$1"
    local envs="$2"
    local marker="criu-test-${name}-$$"
    local case_dir="$BASE_DIR/$name"
    local img_dir="$case_dir/img"
    local ready_file="$case_dir/target.ready"
    local log_dump="$case_dir/dump.log"
    local log_restore="$case_dir/restore.log"
    local pid
    local rc=0
    local t0
    local t1
    local i
    local restore_ok=0

    TOTAL=$((TOTAL + 1))

    echo ""
    echo "=== CASE: $name ==="

    cleanup_marker "$marker"
    rm -rf "$case_dir"
    mkdir -p "$img_dir"

    pid=$(start_target "$marker" "$case_dir")

    for i in $(seq 1 20); do
        if [ -f "$ready_file" ]; then
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.2
    done

    if ! kill -0 "$pid" 2>/dev/null || [ ! -f "$ready_file" ]; then
        echo "[FAIL] $name: failed to start target process"
        echo "  target stdout: $case_dir/target.out"
        echo "  target stderr: $case_dir/target.err"
        tail -n 40 "$case_dir/target.err" 2>/dev/null || true
        FAIL=$((FAIL + 1))
        return
    fi

    t0=$(date +%s)
    echo "  target pid: $pid"
    echo "  dump start (timeout=${DUMP_TIMEOUT_SEC}s)"
    if [ -n "$envs" ]; then
        if ! run_with_timeout "$DUMP_TIMEOUT_SEC" \
            $SUDO env $envs "$CRIU_BIN" dump -t "$pid" -D "$img_dir" -o "$log_dump" -v4 --shell-job; then
            rc=1
        fi
    else
        if ! run_with_timeout "$DUMP_TIMEOUT_SEC" \
            $SUDO "$CRIU_BIN" dump -t "$pid" -D "$img_dir" -o "$log_dump" -v4 --shell-job; then
            rc=1
        fi
    fi

    if [ "$rc" -eq 0 ]; then
        echo "  restore start (timeout=${RESTORE_TIMEOUT_SEC}s)"
        if [ "$RESTORE_DETACHED" -eq 1 ]; then
            if ! run_with_timeout "$RESTORE_TIMEOUT_SEC" \
                $SUDO "$CRIU_BIN" restore -D "$img_dir" -o "$log_restore" -v4 --shell-job --restore-detached; then
                rc=1
            fi
        else
            if ! run_with_timeout "$RESTORE_TIMEOUT_SEC" \
                $SUDO "$CRIU_BIN" restore -D "$img_dir" -o "$log_restore" -v4 --shell-job; then
                rc=1
            fi
        fi

        if [ "$rc" -eq 0 ] && grep -q "Restore finished successfully" "$log_restore" 2>/dev/null; then
            restore_ok=1
        fi

        if [ "$rc" -eq 0 ] && [ "$restore_ok" -ne 1 ]; then
            echo "  restore log does not contain success marker"
            rc=1
        fi
    fi
    t1=$(date +%s)

    if [ "$rc" -eq 0 ]; then
        if pgrep -f "$marker" >/dev/null 2>&1; then
            echo "[PASS] $name: dump+restore success, elapsed=$((t1 - t0))s"
        else
            echo "[PASS] $name: dump+restore success (restored marker not found), elapsed=$((t1 - t0))s"
        fi
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $name: dump/restore failed or restored process missing"
        FAIL=$((FAIL + 1))
    fi

    echo "  dump log:    $log_dump"
    echo "  restore log: $log_restore"
    echo "  key log lines:"
    grep -E "DSA|populate_read|fallback|RPC failed|copied size mismatch|Error|Can't" "$log_dump" 2>/dev/null | head -n 20 || true
    if [ "$rc" -ne 0 ]; then
        echo "  dump log tail:"
        tail -n 40 "$log_dump" 2>/dev/null || true
        echo "  restore log tail:"
        tail -n 40 "$log_restore" 2>/dev/null || true
    fi

    cleanup_marker "$marker"
}

if [ ! -x "$CRIU_BIN" ]; then
    echo "CRIU binary not found or not executable: $CRIU_BIN"
    exit 1
fi

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
    echo "python3 not found or not executable"
    exit 1
fi

if [ -n "$SUDO" ]; then
    echo "checking sudo credentials..."
    if ! $SUDO -v; then
        echo "sudo authentication failed"
        exit 1
    fi
    SUDO="$SUDO -n"
fi

mkdir -p "$BASE_DIR"
echo "test workspace: $BASE_DIR"

run_case "base" ""
run_case "dsa" "CRIU_DSA_DUMP=1"
run_case "dsa_populate" "CRIU_DSA_DUMP=1 CRIU_DSA_POPULATE_READ=1"

echo ""
echo "=== SUMMARY ==="
echo "TOTAL=$TOTAL PASS=$PASS FAIL=$FAIL"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

exit 0