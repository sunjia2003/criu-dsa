#!/usr/bin/env bash

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
CRIU_BIN=${CRIU_BIN:-"$SCRIPT_DIR/criu/criu"}
SUDO=${SUDO:-sudo}
RUN_TAG=${RUN_TAG:-$(date +%Y%m%d-%H%M%S)-$$}
BASE_DIR=${BASE_DIR:-/tmp/criu-test-${RUN_TAG}}
TARGET_MB=${TARGET_MB:-2048}
TARGET_STRICT_ALLOC=${TARGET_STRICT_ALLOC:-1}
TARGET_WORKSPACE_WRAP=${TARGET_WORKSPACE_WRAP:-1}
TARGET_WORKSPACE_WRAP_REQUIRE_NS=${TARGET_WORKSPACE_WRAP_REQUIRE_NS:-1}
TARGET_WORKSPACE_WRAP_BIND_TMP=${TARGET_WORKSPACE_WRAP_BIND_TMP:-1}
WORKSPACE_WRAP_BIN=${WORKSPACE_WRAP_BIN:-"$SCRIPT_DIR/test/zdtm/workspace-wrap.sh"}
WORKSPACE_WRAP_ROOT=${WORKSPACE_WRAP_ROOT:-"$BASE_DIR/workspace"}
EXTERNAL_TARGET_START_HOOK=${EXTERNAL_TARGET_START_HOOK:-}
EXTERNAL_TARGET_STOP_HOOK=${EXTERNAL_TARGET_STOP_HOOK:-}

if [ -z "${TARGET_READY_TIMEOUT_SEC+x}" ]; then
    if [ "$TARGET_MB" -ge 2048 ]; then
        TARGET_READY_TIMEOUT_SEC=30
    else
        TARGET_READY_TIMEOUT_SEC=4
    fi
fi

if [ -z "${DUMP_TIMEOUT_SEC+x}" ]; then
    if [ "$TARGET_MB" -ge 2048 ]; then
        DUMP_TIMEOUT_SEC=120
    else
        DUMP_TIMEOUT_SEC=10
    fi
fi

if [ -z "${RESTORE_TIMEOUT_SEC+x}" ]; then
    if [ "$TARGET_MB" -ge 2048 ]; then
        RESTORE_TIMEOUT_SEC=120
    else
        RESTORE_TIMEOUT_SEC=10
    fi
fi

PYTHON_BIN=${PYTHON_BIN:-$(command -v python3 || true)}
RESTORE_DETACHED=${RESTORE_DETACHED:-1}
BENCH_ROUNDS=${BENCH_ROUNDS:-1}

if [ "$(id -u)" -eq 0 ]; then
    SUDO=
fi

TOTAL=0
PASS=0
FAIL=0

declare -a ACTIVE_MARKERS=()
declare -A MARKER_PID_HINT=()
declare -A MARKER_RUN_DIR=()

declare -A CASE_FROZEN_US
declare -A CASE_MEMDUMP_US
declare -A CASE_MEMWRITE_US
declare -A CASE_DSA_RPC_US
declare -A CASE_ASYNC_WAIT_US
declare -A CASE_VMA_AVG_KB
declare -A CASE_VMA_P95_KB
declare -A CASE_VMA_P99_KB
declare -A SUM_FROZEN_US
declare -A SUM_MEMDUMP_US
declare -A SUM_MEMWRITE_US
declare -A SUM_DSA_RPC_US
declare -A SUM_ASYNC_WAIT_US
declare -A SUM_VMA_AVG_KB
declare -A SUM_VMA_P95_KB
declare -A SUM_VMA_P99_KB
declare -A CNT_TIMING
declare -A CNT_WORK
declare -A CNT_VMA

declare -A CASE_WL_TOTAL_US
declare -A CASE_WL_PREPARE_US
declare -A CASE_WL_MEMDUMP_US
declare -A CASE_WL_OTHER_RES_US
declare -A CASE_WL_MEMWRITE_US
declare -A CASE_WL_SCAN_IOV_US
declare -A CASE_WL_BASE_RPC_US
declare -A CASE_WL_DSA_CTX_US
declare -A CASE_WL_DSA_BUILD_US
declare -A CASE_WL_DSA_RPC_US
declare -A CASE_WL_DSA_REPLAY_US
declare -A CASE_WL_MISC_US

declare -A SUM_WL_TOTAL_US
declare -A SUM_WL_PREPARE_US
declare -A SUM_WL_MEMDUMP_US
declare -A SUM_WL_OTHER_RES_US
declare -A SUM_WL_MEMWRITE_US
declare -A SUM_WL_SCAN_IOV_US
declare -A SUM_WL_BASE_RPC_US
declare -A SUM_WL_DSA_CTX_US
declare -A SUM_WL_DSA_BUILD_US
declare -A SUM_WL_DSA_RPC_US
declare -A SUM_WL_DSA_REPLAY_US
declare -A SUM_WL_MISC_US

declare -A CASE_DSA_DEGRADE_TOTAL
declare -A CASE_DSA_DEGRADE_SHARED
declare -A CASE_DSA_DEGRADE_SUBMIT
declare -A CASE_DSA_SUBMIT_ENQCMD
declare -A CASE_DSA_SUBMIT_WRITE
declare -A CASE_DSA_MAP_POP_FALLBACK
declare -A CASE_DSA_PREFAULT_US
declare -A CASE_DSA_SUBMIT_US
declare -A CASE_DSA_POLL_US
declare -A CASE_DSA_SUBMIT_POLL_US
declare -A SUM_DSA_DEGRADE_TOTAL
declare -A SUM_DSA_DEGRADE_SHARED
declare -A SUM_DSA_DEGRADE_SUBMIT
declare -A SUM_DSA_SUBMIT_ENQCMD
declare -A SUM_DSA_SUBMIT_WRITE
declare -A SUM_DSA_MAP_POP_FALLBACK
declare -A SUM_DSA_PREFAULT_US
declare -A SUM_DSA_SUBMIT_US
declare -A SUM_DSA_POLL_US
declare -A SUM_DSA_SUBMIT_POLL_US

avg_kb() {
    local sum="$1"
    local cnt="$2"

    if [ -z "$sum" ] || [ -z "$cnt" ] || [ "$cnt" -le 0 ]; then
        echo ""
        return
    fi

    echo $(( sum / cnt ))
}

record_case_vma_stats() {
    local name="$1"
    local pid="$2"
    local group
    local tmp
    local n
    local sum_bytes
    local avg_kb_val
    local p95_rank
    local p99_rank
    local p95_bytes
    local p99_bytes
    local p95_kb_val
    local p99_kb_val

    tmp=$(mktemp)
    if [ -z "$tmp" ]; then
        return
    fi

    if ! $SUDO awk '
        {
            split($1, a, "-");
            s = strtonum("0x" a[1]);
            e = strtonum("0x" a[2]);
            if (e > s)
                print e - s;
        }
    ' "/proc/$pid/maps" | sort -n > "$tmp"; then
        rm -f "$tmp"
        return
    fi

    n=$(wc -l < "$tmp")
    if [ "$n" -le 0 ]; then
        rm -f "$tmp"
        return
    fi

    sum_bytes=$(awk '{s += $1} END {print s + 0}' "$tmp")
    avg_kb_val=$(( (sum_bytes / n) / 1024 ))

    p95_rank=$(( (95 * n + 99) / 100 ))
    p99_rank=$(( (99 * n + 99) / 100 ))
    if [ "$p95_rank" -lt 1 ]; then
        p95_rank=1
    fi
    if [ "$p99_rank" -lt 1 ]; then
        p99_rank=1
    fi

    p95_bytes=$(sed -n "${p95_rank}p" "$tmp")
    p99_bytes=$(sed -n "${p99_rank}p" "$tmp")
    p95_kb_val=$(( p95_bytes / 1024 ))
    p99_kb_val=$(( p99_bytes / 1024 ))

    rm -f "$tmp"

    CASE_VMA_AVG_KB["$name"]=$avg_kb_val
    CASE_VMA_P95_KB["$name"]=$p95_kb_val
    CASE_VMA_P99_KB["$name"]=$p99_kb_val

    group=$(normalize_case_group "$name")
    SUM_VMA_AVG_KB["$group"]=$(( ${SUM_VMA_AVG_KB[$group]:-0} + avg_kb_val ))
    SUM_VMA_P95_KB["$group"]=$(( ${SUM_VMA_P95_KB[$group]:-0} + p95_kb_val ))
    SUM_VMA_P99_KB["$group"]=$(( ${SUM_VMA_P99_KB[$group]:-0} + p99_kb_val ))
    CNT_VMA["$group"]=$(( ${CNT_VMA[$group]:-0} + 1 ))
}

print_vma_metric_compare() {
    local label="$1"
    local base_kb="$2"
    local dsa_live_kb="$3"

    if [ -z "$base_kb" ] || [ -z "$dsa_live_kb" ]; then
        echo "  $label: n/a (missing VMA data)"
        return
    fi

    awk -v label="$label" -v base="$base_kb" -v dsa_live="$dsa_live_kb" 'BEGIN {
        diff = base - dsa_live;
        if (base > 0)
            pct = (diff * 100.0) / base;
        else
            pct = 0.0;
        printf("  %s: base=%d KiB dsa_live=%d KiB delta=%+d KiB (%+.2f%%)\n", label, base, dsa_live, diff, pct);
    }'
}

normalize_case_group() {
    local name="$1"

    case "$name" in
        dsa_live|dsa_live_*)
            echo "dsa_live"
            ;;
        base|base_*)
            echo "base"
            ;;
        *)
            echo "$name"
            ;;
    esac
}

extract_timing_field_us() {
    local line="$1"
    local field="$2"

    echo "$line" | sed -n "s/.*${field}=\([0-9][0-9]*\) us.*/\1/p"
}

extract_workload_field_us() {
    local line="$1"
    local field="$2"

    echo "$line" | sed -n "s/.*${field}=\([0-9][0-9]*\) us.*/\1/p"
}

record_case_timing() {
    local name="$1"
    local log_dump="$2"
    local line
    local group
    local frozen_us
    local memdump_us
    local memwrite_us
    local dsa_rpc_us
    local async_wait_us
    local wl_task_line
    local wl_mem_line
    local wl_total_us
    local wl_prepare_us
    local wl_memdump_us
    local wl_other_res_us
    local wl_memwrite_us
    local wl_scan_iov_us
    local wl_base_rpc_us
    local wl_dsa_ctx_us
    local wl_dsa_build_us
    local wl_dsa_rpc_us
    local wl_dsa_replay_us
    local wl_misc_us
    local dsa_degrade_total
    local dsa_degrade_shared
    local dsa_degrade_submit
    local dsa_submit_enqcmd
    local dsa_submit_write
    local dsa_map_pop_fallback
    local dsa_prefault_us
    local dsa_submit_us
    local dsa_poll_us
    local dsa_submit_poll_us
    local dsa_mode_samples
    local temp_cdf_desc_samples
    local temp_cdf_gap_samples
    local temp_cdf_ratio_samples

    line=$($SUDO awk '/Dump timing:/{l=$0} END{print l}' "$log_dump" 2>/dev/null || true)
    if [ -z "$line" ]; then
        line=""
    fi

    group=$(normalize_case_group "$name")

    frozen_us=$(extract_timing_field_us "$line" "frozen")
    memdump_us=$(extract_timing_field_us "$line" "memdump")
    memwrite_us=$(extract_timing_field_us "$line" "memwrite")
    dsa_rpc_us=$(extract_timing_field_us "$line" "dsa_rpc")
    async_wait_us=$(extract_timing_field_us "$line" "async_wait")

    if [ -n "$frozen_us" ]; then
        CASE_FROZEN_US["$name"]=$frozen_us
        SUM_FROZEN_US["$group"]=$(( ${SUM_FROZEN_US[$group]:-0} + frozen_us ))
    fi
    if [ -n "$memdump_us" ]; then
        CASE_MEMDUMP_US["$name"]=$memdump_us
        SUM_MEMDUMP_US["$group"]=$(( ${SUM_MEMDUMP_US[$group]:-0} + memdump_us ))
    fi
    if [ -n "$memwrite_us" ]; then
        CASE_MEMWRITE_US["$name"]=$memwrite_us
        SUM_MEMWRITE_US["$group"]=$(( ${SUM_MEMWRITE_US[$group]:-0} + memwrite_us ))
    fi
    if [ -n "$dsa_rpc_us" ]; then
        CASE_DSA_RPC_US["$name"]=$dsa_rpc_us
        SUM_DSA_RPC_US["$group"]=$(( ${SUM_DSA_RPC_US[$group]:-0} + dsa_rpc_us ))
    fi
    if [ -n "$async_wait_us" ]; then
        CASE_ASYNC_WAIT_US["$name"]=$async_wait_us
        SUM_ASYNC_WAIT_US["$group"]=$(( ${SUM_ASYNC_WAIT_US[$group]:-0} + async_wait_us ))
    fi

    if [ -n "$frozen_us" ] || [ -n "$memdump_us" ] || [ -n "$memwrite_us" ]; then
        CNT_TIMING["$group"]=$(( ${CNT_TIMING[$group]:-0} + 1 ))
    fi

    wl_task_line=$($SUDO awk '/WORKLOAD_TASK:/{l=$0} END{print l}' "$log_dump" 2>/dev/null || true)
    wl_mem_line=$($SUDO awk '/WORKLOAD_MEMDUMP_BREAKDOWN:/{l=$0} END{print l}' "$log_dump" 2>/dev/null || true)

    if [ -n "$wl_task_line" ]; then
        wl_total_us=$(extract_workload_field_us "$wl_task_line" "total_work")
        wl_prepare_us=$(extract_workload_field_us "$wl_task_line" "prepare")
        wl_memdump_us=$(extract_workload_field_us "$wl_task_line" "memdump")
        wl_other_res_us=$(extract_workload_field_us "$wl_task_line" "other_res")
        wl_memwrite_us=$(extract_workload_field_us "$wl_task_line" "memwrite")

        if [ -n "$wl_total_us" ]; then
            CASE_WL_TOTAL_US["$name"]=$wl_total_us
            SUM_WL_TOTAL_US["$group"]=$(( ${SUM_WL_TOTAL_US[$group]:-0} + wl_total_us ))
        fi
        if [ -n "$wl_prepare_us" ]; then
            CASE_WL_PREPARE_US["$name"]=$wl_prepare_us
            SUM_WL_PREPARE_US["$group"]=$(( ${SUM_WL_PREPARE_US[$group]:-0} + wl_prepare_us ))
        fi
        if [ -n "$wl_memdump_us" ]; then
            CASE_WL_MEMDUMP_US["$name"]=$wl_memdump_us
            SUM_WL_MEMDUMP_US["$group"]=$(( ${SUM_WL_MEMDUMP_US[$group]:-0} + wl_memdump_us ))
        fi
        if [ -n "$wl_other_res_us" ]; then
            CASE_WL_OTHER_RES_US["$name"]=$wl_other_res_us
            SUM_WL_OTHER_RES_US["$group"]=$(( ${SUM_WL_OTHER_RES_US[$group]:-0} + wl_other_res_us ))
        fi
        if [ -n "$wl_memwrite_us" ]; then
            CASE_WL_MEMWRITE_US["$name"]=$wl_memwrite_us
            SUM_WL_MEMWRITE_US["$group"]=$(( ${SUM_WL_MEMWRITE_US[$group]:-0} + wl_memwrite_us ))
        fi
    fi

    if [ -n "$wl_mem_line" ]; then
        wl_scan_iov_us=$(extract_workload_field_us "$wl_mem_line" "scan_iov")
        wl_base_rpc_us=$(extract_workload_field_us "$wl_mem_line" "base_rpc")
        wl_dsa_ctx_us=$(extract_workload_field_us "$wl_mem_line" "dsa_ctx_init")
        wl_dsa_build_us=$(extract_workload_field_us "$wl_mem_line" "dsa_batch_build")
        wl_dsa_rpc_us=$(extract_workload_field_us "$wl_mem_line" "dsa_rpc")
        wl_dsa_replay_us=$(extract_workload_field_us "$wl_mem_line" "dsa_replay")
        wl_misc_us=$(extract_workload_field_us "$wl_mem_line" "misc")

        if [ -n "$wl_scan_iov_us" ]; then
            CASE_WL_SCAN_IOV_US["$name"]=$wl_scan_iov_us
            SUM_WL_SCAN_IOV_US["$group"]=$(( ${SUM_WL_SCAN_IOV_US[$group]:-0} + wl_scan_iov_us ))
        fi
        if [ -n "$wl_base_rpc_us" ]; then
            CASE_WL_BASE_RPC_US["$name"]=$wl_base_rpc_us
            SUM_WL_BASE_RPC_US["$group"]=$(( ${SUM_WL_BASE_RPC_US[$group]:-0} + wl_base_rpc_us ))
        fi
        if [ -n "$wl_dsa_ctx_us" ]; then
            CASE_WL_DSA_CTX_US["$name"]=$wl_dsa_ctx_us
            SUM_WL_DSA_CTX_US["$group"]=$(( ${SUM_WL_DSA_CTX_US[$group]:-0} + wl_dsa_ctx_us ))
        fi
        if [ -n "$wl_dsa_build_us" ]; then
            CASE_WL_DSA_BUILD_US["$name"]=$wl_dsa_build_us
            SUM_WL_DSA_BUILD_US["$group"]=$(( ${SUM_WL_DSA_BUILD_US[$group]:-0} + wl_dsa_build_us ))
        fi
        if [ -n "$wl_dsa_rpc_us" ]; then
            CASE_WL_DSA_RPC_US["$name"]=$wl_dsa_rpc_us
            SUM_WL_DSA_RPC_US["$group"]=$(( ${SUM_WL_DSA_RPC_US[$group]:-0} + wl_dsa_rpc_us ))
        fi
        if [ -n "$wl_dsa_replay_us" ]; then
            CASE_WL_DSA_REPLAY_US["$name"]=$wl_dsa_replay_us
            SUM_WL_DSA_REPLAY_US["$group"]=$(( ${SUM_WL_DSA_REPLAY_US[$group]:-0} + wl_dsa_replay_us ))
        fi
        if [ -n "$wl_misc_us" ]; then
            CASE_WL_MISC_US["$name"]=$wl_misc_us
            SUM_WL_MISC_US["$group"]=$(( ${SUM_WL_MISC_US[$group]:-0} + wl_misc_us ))
        fi
    fi

    if [ -n "$wl_task_line" ] || [ -n "$wl_mem_line" ]; then
        CNT_WORK["$group"]=$(( ${CNT_WORK[$group]:-0} + 1 ))
    fi

    dsa_degrade_total=$($SUDO awk '/DSA_DEGRADE:/{c++} END{print c+0}' "$log_dump" 2>/dev/null || echo 0)
    dsa_degrade_shared=$($SUDO awk '/DSA_DEGRADE:.*category=shared_mem/{c++} END{print c+0}' "$log_dump" 2>/dev/null || echo 0)
    dsa_degrade_submit=$($SUDO awk '/DSA_DEGRADE:.*category=submit/{c++} END{print c+0}' "$log_dump" 2>/dev/null || echo 0)
    dsa_submit_enqcmd=0
    dsa_submit_write=0
    dsa_map_pop_fallback=0
    dsa_prefault_us=0
    dsa_submit_us=0
    dsa_poll_us=0
    dsa_submit_poll_us=$(( dsa_submit_us + dsa_poll_us ))
    dsa_mode_samples=0

    CASE_DSA_DEGRADE_TOTAL["$name"]=$dsa_degrade_total
    CASE_DSA_DEGRADE_SHARED["$name"]=$dsa_degrade_shared
    CASE_DSA_DEGRADE_SUBMIT["$name"]=$dsa_degrade_submit
    CASE_DSA_SUBMIT_ENQCMD["$name"]=$dsa_submit_enqcmd
    CASE_DSA_SUBMIT_WRITE["$name"]=$dsa_submit_write
    CASE_DSA_MAP_POP_FALLBACK["$name"]=$dsa_map_pop_fallback
    CASE_DSA_PREFAULT_US["$name"]=$dsa_prefault_us
    CASE_DSA_SUBMIT_US["$name"]=$dsa_submit_us
    CASE_DSA_POLL_US["$name"]=$dsa_poll_us
    CASE_DSA_SUBMIT_POLL_US["$name"]=$dsa_submit_poll_us

    SUM_DSA_DEGRADE_TOTAL["$group"]=$(( ${SUM_DSA_DEGRADE_TOTAL[$group]:-0} + dsa_degrade_total ))
    SUM_DSA_DEGRADE_SHARED["$group"]=$(( ${SUM_DSA_DEGRADE_SHARED[$group]:-0} + dsa_degrade_shared ))
    SUM_DSA_DEGRADE_SUBMIT["$group"]=$(( ${SUM_DSA_DEGRADE_SUBMIT[$group]:-0} + dsa_degrade_submit ))
    SUM_DSA_SUBMIT_ENQCMD["$group"]=$(( ${SUM_DSA_SUBMIT_ENQCMD[$group]:-0} + dsa_submit_enqcmd ))
    SUM_DSA_SUBMIT_WRITE["$group"]=$(( ${SUM_DSA_SUBMIT_WRITE[$group]:-0} + dsa_submit_write ))
    SUM_DSA_MAP_POP_FALLBACK["$group"]=$(( ${SUM_DSA_MAP_POP_FALLBACK[$group]:-0} + dsa_map_pop_fallback ))
    SUM_DSA_PREFAULT_US["$group"]=$(( ${SUM_DSA_PREFAULT_US[$group]:-0} + dsa_prefault_us ))
    SUM_DSA_SUBMIT_US["$group"]=$(( ${SUM_DSA_SUBMIT_US[$group]:-0} + dsa_submit_us ))
    SUM_DSA_POLL_US["$group"]=$(( ${SUM_DSA_POLL_US[$group]:-0} + dsa_poll_us ))
    SUM_DSA_SUBMIT_POLL_US["$group"]=$(( ${SUM_DSA_SUBMIT_POLL_US[$group]:-0} + dsa_submit_poll_us ))

}

avg_us() {
    avg_kb "$1" "$2"
}

sum_us() {
    local a="$1"
    local b="$2"

    if [ -z "$a" ] || [ -z "$b" ]; then
        echo ""
        return
    fi

    echo $(( a + b ))
}

sub_us_nonneg() {
    local a="$1"
    local b="$2"
    local diff

    if [ -z "$a" ] || [ -z "$b" ]; then
        echo ""
        return
    fi

    diff=$(( a - b ))
    if [ "$diff" -lt 0 ]; then
        diff=0
    fi

    echo "$diff"
}

pct_of() {
    local part="$1"
    local total="$2"

    if [ -z "$part" ] || [ -z "$total" ] || [ "$total" -le 0 ]; then
        echo ""
        return
    fi

    awk -v p="$part" -v t="$total" 'BEGIN { printf("%.2f", (p * 100.0) / t) }'
}

print_metric_compare() {
    local label="$1"
    local base="$2"
    local dsa_live="$3"

    if [ -z "$base" ] || [ -z "$dsa_live" ]; then
        echo "  $label: n/a (missing timing data)"
        return
    fi

    awk -v label="$label" -v base="$base" -v dsa_live="$dsa_live" 'BEGIN {
        diff = base - dsa_live;
        if (base > 0)
            pct = (diff * 100.0) / base;
        else
            pct = 0.0;
        printf("  %s: base=%d us dsa_live=%d us delta=%+d us (%+.2f%%)\n", label, base, dsa_live, diff, pct);
    }'
}

cleanup_marker() {
    local marker="$1"
    local pid_hint="${MARKER_PID_HINT[$marker]:-}"
    local run_dir="${MARKER_RUN_DIR[$marker]:-}"
    local pids

    if [ -n "$pid_hint" ] && kill -0 "$pid_hint" 2>/dev/null; then
        if [ -n "$EXTERNAL_TARGET_STOP_HOOK" ] && [ -x "$EXTERNAL_TARGET_STOP_HOOK" ]; then
            "$EXTERNAL_TARGET_STOP_HOOK" "$marker" "$pid_hint" "$run_dir" || true
        fi

        $SUDO kill "$pid_hint" 2>/dev/null || true
        sleep 1
        if kill -0 "$pid_hint" 2>/dev/null; then
            $SUDO kill -9 "$pid_hint" 2>/dev/null || true
        fi
    fi

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

cleanup_all_markers() {
    local marker

    for marker in "${ACTIVE_MARKERS[@]}"; do
        cleanup_marker "$marker"
    done
}

register_marker() {
    local marker="$1"

    ACTIVE_MARKERS+=("$marker")
}

unregister_marker() {
    local marker="$1"
    local keep=()
    local m

    for m in "${ACTIVE_MARKERS[@]}"; do
        if [ "$m" != "$marker" ]; then
            keep+=("$m")
        fi
    done

    ACTIVE_MARKERS=("${keep[@]}")
    unset MARKER_PID_HINT["$marker"]
    unset MARKER_RUN_DIR["$marker"]
}

start_target() {
    local marker="$1"
    local run_dir="$2"
    local pid
    local out_log="$run_dir/target.out"
    local err_log="$run_dir/target.err"
    local ready_file="$run_dir/target.ready"
    local wrap_run_id="target-${marker}"
    local -a wrap_cmd

    rm -f "$ready_file"

    if [ -n "$EXTERNAL_TARGET_START_HOOK" ]; then
        if [ ! -x "$EXTERNAL_TARGET_START_HOOK" ]; then
            echo "external start hook not executable: $EXTERNAL_TARGET_START_HOOK" >&2
            return 1
        fi

        "$EXTERNAL_TARGET_START_HOOK" "$marker" "$run_dir" "$ready_file"
        return $?
    fi

    wrap_cmd=()
    if [ "$TARGET_WORKSPACE_WRAP" -eq 1 ]; then
        wrap_cmd+=("$WORKSPACE_WRAP_BIN")
        wrap_cmd+=(--workspace-root "$WORKSPACE_WRAP_ROOT")
        wrap_cmd+=(--run-id "$wrap_run_id")
        wrap_cmd+=(--require-namespace "$TARGET_WORKSPACE_WRAP_REQUIRE_NS")
        if [ "$TARGET_WORKSPACE_WRAP_BIND_TMP" -ne 1 ]; then
            wrap_cmd+=(--no-bind-tmp)
        fi
        wrap_cmd+=(--)
    fi

    setsid "${wrap_cmd[@]}" "$PYTHON_BIN" - "$marker" "$TARGET_MB" "$ready_file" "$TARGET_STRICT_ALLOC" <<'PY' >"$out_log" 2>"$err_log" &
import sys
import time

marker = sys.argv[1]
mb = int(sys.argv[2])
ready_file = sys.argv[3]
strict_alloc = int(sys.argv[4]) != 0

try:
    buf = bytearray(mb * 1024 * 1024)
except MemoryError:
    if strict_alloc:
        print(f"failed to allocate {mb} MiB dirty buffer", file=sys.stderr, flush=True)
        sys.exit(42)

    # Keep process alive with smaller footprint when strict mode is disabled.
    buf = bytearray(8 * 1024 * 1024)

for i in range(0, len(buf), 4096):
    buf[i] = (i // 4096) % 251

with open(ready_file, "w", encoding="ascii") as f:
    f.write("ready\n")

print("ready", marker, len(buf), flush=True)
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
    local mode="${3:-restore}"
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
    local ready_loops
    local restore_ok=0

    TOTAL=$((TOTAL + 1))

    echo ""
    echo "=== CASE: $name ==="

    register_marker "$marker"
    cleanup_marker "$marker"
    rm -rf "$case_dir"
    mkdir -p "$img_dir"

    pid=$(start_target "$marker" "$case_dir")
    if [ -z "$pid" ]; then
        echo "[FAIL] $name: target start hook failed"
        FAIL=$((FAIL + 1))
        unregister_marker "$marker"
        return
    fi
    MARKER_PID_HINT["$marker"]="$pid"
    MARKER_RUN_DIR["$marker"]="$case_dir"

    ready_loops=$(( TARGET_READY_TIMEOUT_SEC * 5 ))
    if [ "$ready_loops" -lt 1 ]; then
        ready_loops=1
    fi

    for i in $(seq 1 "$ready_loops"); do
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
        unregister_marker "$marker"
        return
    fi

    record_case_vma_stats "$name" "$pid"

    t0=$(date +%s)
    echo "  target pid: $pid"
    echo "  target dirty footprint: ${TARGET_MB} MiB"
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
        if [ "$mode" = "dump-only" ]; then
            echo "  dump-only mode: skip restore"
        elif [ "$mode" = "live-restore-check" ]; then
            echo "  live mode: verify target keeps running"
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "  live mode target exited unexpectedly"
                rc=1
            fi

            if [ "$rc" -eq 0 ]; then
                echo "  live mode: stop original target before restore check"
                cleanup_marker "$marker"

                echo "  restore check start (timeout=${RESTORE_TIMEOUT_SEC}s)"
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
        else
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
    fi
    t1=$(date +%s)

    if [ "$rc" -eq 0 ]; then
        if [ "$mode" = "dump-only" ]; then
            echo "[PASS] $name: dump-only success, elapsed=$((t1 - t0))s"
        elif [ "$mode" = "live-restore-check" ]; then
            if pgrep -f "$marker" >/dev/null 2>&1; then
                echo "[PASS] $name: live dump + restore check success, elapsed=$((t1 - t0))s"
            else
                echo "[PASS] $name: live dump + restore check success (restored marker not found), elapsed=$((t1 - t0))s"
            fi
        elif pgrep -f "$marker" >/dev/null 2>&1; then
            echo "[PASS] $name: dump+restore success, elapsed=$((t1 - t0))s"
        else
            echo "[PASS] $name: dump+restore success (restored marker not found), elapsed=$((t1 - t0))s"
        fi
    fi

    if [ "$rc" -eq 0 ]; then
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $name: dump/restore failed or restored process missing"
        FAIL=$((FAIL + 1))
    fi

    echo "  dump log:    $log_dump"
    echo "  restore log: $log_restore"
    if [ -n "${CASE_VMA_AVG_KB[$name]:-}" ]; then
        echo "  vma size summary: avg=${CASE_VMA_AVG_KB[$name]} KiB p95=${CASE_VMA_P95_KB[$name]} KiB p99=${CASE_VMA_P99_KB[$name]} KiB"
    fi
    echo "  timing summary:"
    $SUDO grep -E "timing:" "$log_dump" 2>/dev/null | tail -n 5 || true

    record_case_timing "$name" "$log_dump"

    echo "  key log lines:"
    $SUDO grep -E "DSA|populate_read|fallback|RPC failed|copied size mismatch|timing:|Error|Can't" "$log_dump" 2>/dev/null | head -n 30 || true
    if [ "$rc" -ne 0 ]; then
        echo "  dump log tail:"
        $SUDO tail -n 40 "$log_dump" 2>/dev/null || true
        echo "  restore log tail:"
        $SUDO tail -n 40 "$log_restore" 2>/dev/null || true
    fi

    cleanup_marker "$marker"
    unregister_marker "$marker"
}

if [ ! -x "$CRIU_BIN" ]; then
    echo "CRIU binary not found or not executable: $CRIU_BIN"
    exit 1
fi

if [ -z "$PYTHON_BIN" ] || [ ! -x "$PYTHON_BIN" ]; then
    echo "python3 not found or not executable"
    exit 1
fi

if [ "$TARGET_WORKSPACE_WRAP" -eq 1 ] && [ ! -x "$WORKSPACE_WRAP_BIN" ]; then
    echo "workspace wrapper not found or not executable: $WORKSPACE_WRAP_BIN"
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
if [ "$TARGET_WORKSPACE_WRAP" -eq 1 ]; then
    mkdir -p "$WORKSPACE_WRAP_ROOT"
fi
trap cleanup_all_markers EXIT INT TERM

echo "test workspace: $BASE_DIR"
echo "benchmark rounds: $BENCH_ROUNDS"
echo "target dirty footprint: ${TARGET_MB} MiB"
echo "target alloc strict: ${TARGET_STRICT_ALLOC}"
echo "target ready timeout: ${TARGET_READY_TIMEOUT_SEC}s"
echo "target workspace wrap: ${TARGET_WORKSPACE_WRAP} (root=${WORKSPACE_WRAP_ROOT})"

if [ "$BENCH_ROUNDS" -le 1 ]; then
    run_case "base" "CRIU_DSA_DUMP=0 CRIU_DSA_POPULATE_READ=0" "dump-only"
    run_case "dsa_live" "CRIU_DSA_DUMP=1" "live-restore-check"
else
    for i in $(seq 1 "$BENCH_ROUNDS"); do
        run_case "base_$i" "CRIU_DSA_DUMP=0 CRIU_DSA_POPULATE_READ=0" "dump-only"
        run_case "dsa_live_$i" "CRIU_DSA_DUMP=1" "live-restore-check"
    done
fi

echo ""
echo "=== SUMMARY ==="
echo "TOTAL=$TOTAL PASS=$PASS FAIL=$FAIL"

echo ""
echo "=== TIMING COMPARE (base vs dsa_live) ==="
echo "  samples: base=${CNT_TIMING[base]:-0} dsa_live=${CNT_TIMING[dsa_live]:-0}"

BASE_FROZEN_AVG=$(avg_us "${SUM_FROZEN_US[base]:-}" "${CNT_TIMING[base]:-0}")
DSA_FROZEN_AVG=$(avg_us "${SUM_FROZEN_US[dsa_live]:-}" "${CNT_TIMING[dsa_live]:-0}")
BASE_MEMDUMP_AVG=$(avg_us "${SUM_MEMDUMP_US[base]:-}" "${CNT_TIMING[base]:-0}")
DSA_MEMDUMP_AVG=$(avg_us "${SUM_MEMDUMP_US[dsa_live]:-}" "${CNT_TIMING[dsa_live]:-0}")
BASE_MEMWRITE_AVG=$(avg_us "${SUM_MEMWRITE_US[base]:-}" "${CNT_TIMING[base]:-0}")
DSA_MEMWRITE_AVG=$(avg_us "${SUM_MEMWRITE_US[dsa_live]:-}" "${CNT_TIMING[dsa_live]:-0}")
BASE_DSA_RPC_AVG=$(avg_us "${SUM_DSA_RPC_US[base]:-}" "${CNT_TIMING[base]:-0}")
DSA_DSA_RPC_AVG=$(avg_us "${SUM_DSA_RPC_US[dsa_live]:-}" "${CNT_TIMING[dsa_live]:-0}")
BASE_ASYNC_WAIT_AVG=$(avg_us "${SUM_ASYNC_WAIT_US[base]:-}" "${CNT_TIMING[base]:-0}")
DSA_ASYNC_WAIT_AVG=$(avg_us "${SUM_ASYNC_WAIT_US[dsa_live]:-}" "${CNT_TIMING[dsa_live]:-0}")
BASE_MEMWRITE_E2E_AVG=$(sum_us "$BASE_MEMWRITE_AVG" "$BASE_ASYNC_WAIT_AVG")
DSA_MEMWRITE_E2E_AVG=$(sum_us "$DSA_MEMWRITE_AVG" "$DSA_ASYNC_WAIT_AVG")

print_metric_compare "frozen(avg)" "$BASE_FROZEN_AVG" "$DSA_FROZEN_AVG"
print_metric_compare "memdump(avg)" "$BASE_MEMDUMP_AVG" "$DSA_MEMDUMP_AVG"
print_metric_compare "memwrite(avg)" "$BASE_MEMWRITE_AVG" "$DSA_MEMWRITE_AVG"
print_metric_compare "dsa_rpc(avg)" "$BASE_DSA_RPC_AVG" "$DSA_DSA_RPC_AVG"
print_metric_compare "async_wait(avg)" "$BASE_ASYNC_WAIT_AVG" "$DSA_ASYNC_WAIT_AVG"
print_metric_compare "memwrite_e2e(avg=memwrite+async_wait)" "$BASE_MEMWRITE_E2E_AVG" "$DSA_MEMWRITE_E2E_AVG"

echo ""
echo "=== WORKLOAD COMPARE (base vs dsa_live) ==="
echo "  samples: base=${CNT_WORK[base]:-0} dsa_live=${CNT_WORK[dsa_live]:-0}"
echo "  note: workload_* is aggregated scope time across threads, not wall-clock timing."

BASE_WL_TOTAL_AVG=$(avg_us "${SUM_WL_TOTAL_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_TOTAL_AVG=$(avg_us "${SUM_WL_TOTAL_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_PREPARE_AVG=$(avg_us "${SUM_WL_PREPARE_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_PREPARE_AVG=$(avg_us "${SUM_WL_PREPARE_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_MEMDUMP_AVG=$(avg_us "${SUM_WL_MEMDUMP_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_MEMDUMP_AVG=$(avg_us "${SUM_WL_MEMDUMP_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_OTHER_AVG=$(avg_us "${SUM_WL_OTHER_RES_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_OTHER_AVG=$(avg_us "${SUM_WL_OTHER_RES_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_MEMWRITE_AVG=$(avg_us "${SUM_WL_MEMWRITE_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_MEMWRITE_AVG=$(avg_us "${SUM_WL_MEMWRITE_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")

print_metric_compare "work_total(avg)" "$BASE_WL_TOTAL_AVG" "$DSA_WL_TOTAL_AVG"
print_metric_compare "work_prepare(avg)" "$BASE_WL_PREPARE_AVG" "$DSA_WL_PREPARE_AVG"
print_metric_compare "work_memdump(avg)" "$BASE_WL_MEMDUMP_AVG" "$DSA_WL_MEMDUMP_AVG"
print_metric_compare "work_other_res(avg)" "$BASE_WL_OTHER_AVG" "$DSA_WL_OTHER_AVG"
print_metric_compare "work_memwrite(avg)" "$BASE_WL_MEMWRITE_AVG" "$DSA_WL_MEMWRITE_AVG"

BASE_WL_SCAN_AVG=$(avg_us "${SUM_WL_SCAN_IOV_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_SCAN_AVG=$(avg_us "${SUM_WL_SCAN_IOV_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_BASE_RPC_AVG=$(avg_us "${SUM_WL_BASE_RPC_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_BASE_RPC_AVG=$(avg_us "${SUM_WL_BASE_RPC_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_DSA_CTX_AVG=$(avg_us "${SUM_WL_DSA_CTX_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_DSA_CTX_AVG=$(avg_us "${SUM_WL_DSA_CTX_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_DSA_BUILD_AVG=$(avg_us "${SUM_WL_DSA_BUILD_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_DSA_BUILD_AVG=$(avg_us "${SUM_WL_DSA_BUILD_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_DSA_RPC_AVG=$(avg_us "${SUM_WL_DSA_RPC_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_DSA_RPC_AVG=$(avg_us "${SUM_WL_DSA_RPC_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_DSA_REPLAY_AVG=$(avg_us "${SUM_WL_DSA_REPLAY_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_DSA_REPLAY_AVG=$(avg_us "${SUM_WL_DSA_REPLAY_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_MISC_AVG=$(avg_us "${SUM_WL_MISC_US[base]:-}" "${CNT_WORK[base]:-0}")
DSA_WL_MISC_AVG=$(avg_us "${SUM_WL_MISC_US[dsa_live]:-}" "${CNT_WORK[dsa_live]:-0}")
BASE_WL_MEMDUMP_CORE_AVG=$(sub_us_nonneg "$BASE_WL_MEMDUMP_AVG" "$BASE_WL_DSA_REPLAY_AVG")
DSA_WL_MEMDUMP_CORE_AVG=$(sub_us_nonneg "$DSA_WL_MEMDUMP_AVG" "$DSA_WL_DSA_REPLAY_AVG")

print_metric_compare "work_scan_iov(avg)" "$BASE_WL_SCAN_AVG" "$DSA_WL_SCAN_AVG"
print_metric_compare "work_base_rpc(avg)" "$BASE_WL_BASE_RPC_AVG" "$DSA_WL_BASE_RPC_AVG"
print_metric_compare "work_dsa_ctx_init(avg)" "$BASE_WL_DSA_CTX_AVG" "$DSA_WL_DSA_CTX_AVG"
print_metric_compare "work_dsa_batch_build(avg)" "$BASE_WL_DSA_BUILD_AVG" "$DSA_WL_DSA_BUILD_AVG"
print_metric_compare "work_dsa_rpc(avg)" "$BASE_WL_DSA_RPC_AVG" "$DSA_WL_DSA_RPC_AVG"
print_metric_compare "work_dsa_replay(avg)" "$BASE_WL_DSA_REPLAY_AVG" "$DSA_WL_DSA_REPLAY_AVG"
print_metric_compare "work_memdump_core(avg=work_memdump-work_dsa_replay)" "$BASE_WL_MEMDUMP_CORE_AVG" "$DSA_WL_MEMDUMP_CORE_AVG"
print_metric_compare "work_memdump_misc(avg)" "$BASE_WL_MISC_AVG" "$DSA_WL_MISC_AVG"

echo ""
echo "=== VMA SIZE COMPARE (base vs dsa_live) ==="
echo "  samples: base=${CNT_VMA[base]:-0} dsa_live=${CNT_VMA[dsa_live]:-0}"

BASE_VMA_AVG_KB=$(avg_kb "${SUM_VMA_AVG_KB[base]:-}" "${CNT_VMA[base]:-0}")
DSA_VMA_AVG_KB=$(avg_kb "${SUM_VMA_AVG_KB[dsa_live]:-}" "${CNT_VMA[dsa_live]:-0}")
BASE_VMA_P95_KB=$(avg_kb "${SUM_VMA_P95_KB[base]:-}" "${CNT_VMA[base]:-0}")
DSA_VMA_P95_KB=$(avg_kb "${SUM_VMA_P95_KB[dsa_live]:-}" "${CNT_VMA[dsa_live]:-0}")
BASE_VMA_P99_KB=$(avg_kb "${SUM_VMA_P99_KB[base]:-}" "${CNT_VMA[base]:-0}")
DSA_VMA_P99_KB=$(avg_kb "${SUM_VMA_P99_KB[dsa_live]:-}" "${CNT_VMA[dsa_live]:-0}")

print_vma_metric_compare "vma_avg" "$BASE_VMA_AVG_KB" "$DSA_VMA_AVG_KB"
print_vma_metric_compare "vma_p95" "$BASE_VMA_P95_KB" "$DSA_VMA_P95_KB"
print_vma_metric_compare "vma_p99" "$BASE_VMA_P99_KB" "$DSA_VMA_P99_KB"

if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

exit 0
