#!/usr/bin/env bash

set -u

LAMMPS_LOG=
LAMMPS_INPUT=
STEP_BEFORE=0
LAMMPS_BIN=

adapter_prepare() {
	LAMMPS_BIN=$(cm_resolve_cmd \
		"${LAMMPS_BIN:-}" \
		"${LAMMPS_BIN_OVERRIDE:-}" \
		"$HOME/workspace/lammps/build/lmp" \
		lmp \
		2>/dev/null || true)

	if [ -z "$LAMMPS_BIN" ]; then
		cm_err "required command not found: lmp"
		return 1
	fi

	LAMMPS_LOG="$RUN_LOG_DIR/lammps.log"
	LAMMPS_INPUT="$SCRIPT_DIR/lammps-bd/in.bd.small"
	cm_append_log_path "$LAMMPS_LOG"
	return 0
}

adapter_start() {
	"$LAMMPS_BIN" -in "$LAMMPS_INPUT" -log "$LAMMPS_LOG" >"$RUN_LOG_DIR/lammps-stdout.log" 2>"$RUN_LOG_DIR/lammps-stderr.log" &
	TARGET_PID=$!
	return 0
}

adapter_ready() {
	local timeout_sec="$1"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if grep -q "Step" "$LAMMPS_LOG" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

adapter_verify() {
	local i
	local step_after
	STEP_BEFORE=$(awk '/^[[:space:]]*[0-9]+[[:space:]]/ {s=$1} END {print s+0}' "$LAMMPS_LOG" 2>/dev/null)
	for i in $(seq 1 10); do
		sleep 1
		step_after=$(awk '/^[[:space:]]*[0-9]+[[:space:]]/ {s=$1} END {print s+0}' "$LAMMPS_LOG" 2>/dev/null)
		if [ "$step_after" -gt "$STEP_BEFORE" ]; then
			return 0
		fi
	done

	return 1
}

adapter_stop() {
	if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
		kill -TERM "$TARGET_PID" 2>/dev/null || true
		sleep 2
		if kill -0 "$TARGET_PID" 2>/dev/null; then
			kill -KILL "$TARGET_PID" 2>/dev/null || true
		fi
	fi
	return 0
}

adapter_collect() {
	return 0
}
