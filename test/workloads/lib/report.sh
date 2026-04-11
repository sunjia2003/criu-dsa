#!/usr/bin/env bash

set -u

PHASE_FILE=${PHASE_FILE:-}
RUN_RESULT=${RUN_RESULT:-FAIL}
RUN_ERROR_CODE=${RUN_ERROR_CODE:-}
RUN_ERROR_MSG=${RUN_ERROR_MSG:-}

rp_init() {
	PHASE_FILE="$RUN_STATE_DIR/phases.tsv"
	: >"$PHASE_FILE"
}

rp_phase_begin() {
	PHASE_NAME="$1"
	PHASE_T0=$(date +%s%3N)
}

rp_phase_end() {
	local rc="$1"
	local t1
	local dur
	t1=$(date +%s%3N)
	dur=$((t1 - PHASE_T0))
	printf "%s\t%s\t%s\n" "$PHASE_NAME" "$rc" "$dur" >>"$PHASE_FILE"
}

rp_set_result() {
	RUN_RESULT="$1"
	RUN_ERROR_CODE="${2:-}"
	RUN_ERROR_MSG="${3:-}"
}

rp_emit_manifest() {
	local path="$RUN_ARTIFACT_DIR/manifest.json"
	local target_pid_json="null"
	local phases_json=""
	local first=1
	local line
	local name rc dur

	if [ -n "${TARGET_PID:-}" ]; then
		target_pid_json="$TARGET_PID"
	fi

	while IFS=$'\t' read -r name rc dur; do
		[ -z "$name" ] && continue
		if [ "$first" -eq 0 ]; then
			phases_json="$phases_json,"
		fi
		phases_json="$phases_json{\"name\":\"$name\",\"rc\":$rc,\"duration_ms\":$dur}"
		first=0
	done <"$PHASE_FILE"

	cat >"$path" <<EOF
{
  "run_id": "$RUN_ID",
  "workload": "$WORKLOAD_NAME",
  "mode": "$WORKLOAD_MODE",
  "profile": "$WORKLOAD_PROFILE",
  "target_pid": $target_pid_json,
  "resource": {
    "port": "${TARGET_RESOURCE_PORT:-}",
    "socket": "${TARGET_RESOURCE_SOCKET:-}",
    "pid_file": "${TARGET_RESOURCE_PID_FILE:-}",
    "datadir": "${TARGET_RESOURCE_DATADIR:-}",
    "log_dir": "${TARGET_RESOURCE_LOG_DIR:-}"
  },
  "workload_logs": "${WORKLOAD_LOG_PATHS:-}",
  "result": "$RUN_RESULT",
  "error": {
    "code": "${RUN_ERROR_CODE:-}",
    "message": "${RUN_ERROR_MSG:-}"
  },
  "phases": [${phases_json}]
}
EOF
}

rp_emit_summary_line() {
	local out="$1"
	printf "%s\t%s\t%s\t%s\n" "$RUN_ID" "$WORKLOAD_NAME" "$WORKLOAD_MODE" "$RUN_RESULT" >>"$out"
}
