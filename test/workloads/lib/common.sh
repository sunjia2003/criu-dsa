#!/usr/bin/env bash

set -u

WORKLOADS_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT_ROOT=$(cd -- "$WORKLOADS_ROOT/../.." && pwd)

RUN_BASE=${RUN_BASE:-/tmp/criu-workloads}
RUN_ID=${RUN_ID:-}
RUN_ROOT=${RUN_ROOT:-}
RUN_LOG_DIR=${RUN_LOG_DIR:-}
RUN_ARTIFACT_DIR=${RUN_ARTIFACT_DIR:-}
RUN_STATE_DIR=${RUN_STATE_DIR:-}
TARGET_PID=${TARGET_PID:-}
TARGET_RESOURCE_PORT=${TARGET_RESOURCE_PORT:-}
TARGET_RESOURCE_SOCKET=${TARGET_RESOURCE_SOCKET:-}
TARGET_RESOURCE_PID_FILE=${TARGET_RESOURCE_PID_FILE:-}
TARGET_RESOURCE_DATADIR=${TARGET_RESOURCE_DATADIR:-}
TARGET_RESOURCE_LOG_DIR=${TARGET_RESOURCE_LOG_DIR:-}
TARGET_EXTRA_PIDS=${TARGET_EXTRA_PIDS:-}
WORKLOAD_LOG_PATHS=${WORKLOAD_LOG_PATHS:-}
TARGET_ENV_EXPORTS=${TARGET_ENV_EXPORTS:-}

cm_now_ms() {
	date +%s%3N
}

cm_gen_run_id() {
	printf "run-%s-%s" "$(date +%Y%m%d-%H%M%S)" "$$"
}

cm_log() {
	printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"
}

cm_err() {
	printf "[%s] ERROR: %s\n" "$(date +%H:%M:%S)" "$*" >&2
}

cm_die() {
	cm_err "$*"
	exit 1
}

cm_require_cmd() {
	local cmd="$1"
	if ! command -v "$cmd" >/dev/null 2>&1; then
		cm_err "required command not found: $cmd"
		return 1
	fi
	return 0
}

cm_resolve_cmd() {
	local candidate

	for candidate in "$@"; do
		[ -z "$candidate" ] && continue

		if [ -x "$candidate" ]; then
			echo "$candidate"
			return 0
		fi

		if command -v "$candidate" >/dev/null 2>&1; then
			command -v "$candidate"
			return 0
		fi
	done

	return 1
}

cm_mkdir_run_tree() {
	if [ -z "$RUN_ID" ]; then
		RUN_ID=$(cm_gen_run_id)
	fi
	RUN_ROOT="$RUN_BASE/$RUN_ID"
	RUN_LOG_DIR="$RUN_ROOT/logs"
	RUN_ARTIFACT_DIR="$RUN_ROOT/artifacts"
	RUN_STATE_DIR="$RUN_ROOT/state"
	mkdir -p "$RUN_LOG_DIR" "$RUN_ARTIFACT_DIR" "$RUN_STATE_DIR"
}

cm_wait_for_file() {
	local path="$1"
	local timeout_sec="$2"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if [ -f "$path" ]; then
			return 0
		fi
		sleep 1
	done
	return 1
}

cm_wait_for_pid_alive() {
	local pid="$1"
	local timeout_sec="$2"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	return 1
}

cm_run_timeout() {
	local timeout_sec="$1"
	shift
	if command -v timeout >/dev/null 2>&1; then
		timeout --signal=TERM --kill-after=10s "${timeout_sec}s" "$@"
		return $?
	fi
	"$@"
}

cm_port_in_use() {
	local port="$1"
	if command -v ss >/dev/null 2>&1; then
		ss -lnt "( sport = :$port )" 2>/dev/null | grep -q ":$port"
		return $?
	fi
	netstat -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$port$"
}

cm_alloc_port() {
	local start="$1"
	local end="$2"
	local p
	for p in $(seq "$start" "$end"); do
		if ! cm_port_in_use "$p"; then
			echo "$p"
			return 0
		fi
	done
	return 1
}

cm_append_log_path() {
	local path="$1"
	if [ -z "$WORKLOAD_LOG_PATHS" ]; then
		WORKLOAD_LOG_PATHS="$path"
	else
		WORKLOAD_LOG_PATHS="$WORKLOAD_LOG_PATHS;$path"
	fi
}

cm_append_extra_pid() {
	local pid="$1"
	if [ -z "$TARGET_EXTRA_PIDS" ]; then
		TARGET_EXTRA_PIDS="$pid"
	else
		TARGET_EXTRA_PIDS="$TARGET_EXTRA_PIDS,$pid"
	fi
}
