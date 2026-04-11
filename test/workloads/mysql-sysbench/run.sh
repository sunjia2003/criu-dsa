#!/usr/bin/env bash

set -u

MYSQL_PORT=
MYSQL_DATADIR=
MYSQL_SOCKET=
MYSQL_SOCKET_DIR=
MYSQL_PID_FILE=
MYSQL_LOG=
MYSQL_DEFAULTS=
MYSQL_ADMIN_LOG=
MYSQL_INIT_LOG=
SYSBENCH_PREPARE_LOG=
MYSQL_VERIFY_LOG=
SYSBENCH_BG_PID=

adapter_prepare() {
	cm_require_cmd mysqld || return 1
	cm_require_cmd mysql || return 1
	cm_require_cmd mysqladmin || return 1
	cm_require_cmd sysbench || return 1

	MYSQL_PORT=$(cm_alloc_port 23306 23406) || return 1
	MYSQL_DATADIR="$RUN_ROOT/mysql-data"
	MYSQL_SOCKET_DIR=${MYSQL_SOCKET_DIR:-$RUN_ROOT}
	mkdir -p "$MYSQL_SOCKET_DIR"
	MYSQL_SOCKET="$MYSQL_SOCKET_DIR/m.sock"
	if [ ${#MYSQL_SOCKET} -gt 100 ]; then
		cm_err "mysql socket path is too long: $MYSQL_SOCKET"
		return 1
	fi
	MYSQL_PID_FILE="$RUN_ROOT/mysql.pid"
	MYSQL_LOG="$RUN_LOG_DIR/mysql.log"
	MYSQL_DEFAULTS="$RUN_ROOT/my.cnf"
	MYSQL_ADMIN_LOG="$RUN_LOG_DIR/mysql-admin.log"
	MYSQL_INIT_LOG="$RUN_LOG_DIR/mysql-init.log"
	SYSBENCH_PREPARE_LOG="$RUN_LOG_DIR/sysbench-prepare.log"
	MYSQL_VERIFY_LOG="$RUN_LOG_DIR/mysql-verify.log"
	mkdir -p "$MYSQL_DATADIR"

	sf_mysql_capture_baseline

	sed \
		-e "s|%MYSQL_USER%|$(id -un)|g" \
		-e "s|%MYSQL_PORT%|$MYSQL_PORT|g" \
		-e "s|%MYSQL_SOCKET%|$MYSQL_SOCKET|g" \
		-e "s|%MYSQL_PID_FILE%|$MYSQL_PID_FILE|g" \
		-e "s|%MYSQL_DATADIR%|$MYSQL_DATADIR|g" \
		-e "s|%MYSQL_ERROR_LOG%|$MYSQL_LOG|g" \
		"$SCRIPT_DIR/mysql-sysbench/my.cnf.template" >"$MYSQL_DEFAULTS"

	if ! sf_mysql_preflight_guard "$MYSQL_PORT" "$MYSQL_DATADIR" "$MYSQL_SOCKET" "$MYSQL_PID_FILE" "$RUN_LOG_DIR" "$MYSQL_DEFAULTS"; then
		return 1
	fi

	TARGET_RESOURCE_PORT="$MYSQL_PORT"
	TARGET_RESOURCE_SOCKET="$MYSQL_SOCKET"
	TARGET_RESOURCE_PID_FILE="$MYSQL_PID_FILE"
	TARGET_RESOURCE_DATADIR="$MYSQL_DATADIR"
	TARGET_RESOURCE_LOG_DIR="$RUN_LOG_DIR"
	TARGET_CRIU_DUMP_OPTS="--file-locks --ext-unix-sk"
	cm_append_log_path "$MYSQL_LOG"
	cm_append_log_path "$MYSQL_ADMIN_LOG"
	cm_append_log_path "$MYSQL_INIT_LOG"
	cm_append_log_path "$SYSBENCH_PREPARE_LOG"
	cm_append_log_path "$MYSQL_VERIFY_LOG"
	cm_append_log_path "$RUN_LOG_DIR/sysbench.log"
	return 0
}

adapter_start() {
	local mysql_unconfined
	local -a mysql_cmd

	mysql_unconfined=${MYSQL_UNCONFINED_PROFILE:-1}

	if [ ! -d "$MYSQL_DATADIR/mysql" ]; then
		if [ "$mysql_unconfined" = "1" ] && command -v aa-exec >/dev/null 2>&1; then
			aa-exec -p unconfined -- mysqld --defaults-file="$MYSQL_DEFAULTS" --initialize-insecure >>"$MYSQL_INIT_LOG" 2>&1 || return 1
		else
			mysqld --defaults-file="$MYSQL_DEFAULTS" --initialize-insecure >>"$MYSQL_INIT_LOG" 2>&1 || return 1
		fi
	fi

	rm -f "$MYSQL_SOCKET"

	if [ "$mysql_unconfined" = "1" ] && command -v aa-exec >/dev/null 2>&1; then
		mysql_cmd=(aa-exec -p unconfined -- mysqld --defaults-file="$MYSQL_DEFAULTS")
	else
		mysql_cmd=(mysqld --defaults-file="$MYSQL_DEFAULTS")
	fi

	"${mysql_cmd[@]}" >"$RUN_LOG_DIR/mysqld-stdout.log" 2>"$RUN_LOG_DIR/mysqld-stderr.log" &
	TARGET_PID=$!
	return 0
}

adapter_ready() {
	local timeout_sec="$1"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if [ -n "${TARGET_PID:-}" ] && ! kill -0 "$TARGET_PID" 2>/dev/null; then
			cm_err "mysqld exited before ready"
			if [ -s "$MYSQL_LOG" ]; then
				cm_err "last lines from $MYSQL_LOG:"
				tail -n 40 "$MYSQL_LOG" >&2 || true
			fi
			return 1
		fi

		if mysqladmin --user=root --socket="$MYSQL_SOCKET" ping >>"$MYSQL_ADMIN_LOG" 2>&1; then
			mysql --user=root --socket="$MYSQL_SOCKET" -e "CREATE DATABASE IF NOT EXISTS sbtest;" >>"$MYSQL_ADMIN_LOG" 2>&1 || true
			sysbench oltp_read_write --mysql-socket="$MYSQL_SOCKET" --mysql-user=root --mysql-db=sbtest --threads=2 --time=5 prepare >>"$SYSBENCH_PREPARE_LOG" 2>&1 || true
			(
				while true; do
					sysbench oltp_read_write --mysql-socket="$MYSQL_SOCKET" --mysql-user=root --mysql-db=sbtest --threads=2 --time=10 run >>"$RUN_LOG_DIR/sysbench.log" 2>&1 || true
					sleep 1
				done
			) &
			SYSBENCH_BG_PID=$!
			cm_append_extra_pid "$SYSBENCH_BG_PID"
			return 0
		fi
		sleep 1
	done
	return 1
}

adapter_verify() {
	mysql --user=root --socket="$MYSQL_SOCKET" -e "select 1" >>"$MYSQL_VERIFY_LOG" 2>&1 || return 1
	sysbench oltp_read_write --mysql-socket="$MYSQL_SOCKET" --mysql-user=root --mysql-db=sbtest --threads=2 --time=10 run >>"$RUN_LOG_DIR/sysbench.log" 2>&1
}

adapter_before_dump() {
	local i

	if [ -n "${SYSBENCH_BG_PID:-}" ] && kill -0 "$SYSBENCH_BG_PID" 2>/dev/null; then
		kill -TERM "$SYSBENCH_BG_PID" 2>/dev/null || true
		sleep 2
		if kill -0 "$SYSBENCH_BG_PID" 2>/dev/null; then
			kill -KILL "$SYSBENCH_BG_PID" 2>/dev/null || true
		fi
	fi
	SYSBENCH_BG_PID=

	if command -v ss >/dev/null 2>&1; then
		for i in $(seq 1 15); do
			if ! ss -xna 2>/dev/null | grep -F "$MYSQL_SOCKET" | grep -q "ESTAB"; then
				return 0
			fi
			sleep 1
		done
		cm_err "mysql unix socket still has ESTAB peers before dump"
		return 1
	fi

	return 0
}

adapter_stop_for_restore() {
	local pids

	if [ -n "${SYSBENCH_BG_PID:-}" ] && kill -0 "$SYSBENCH_BG_PID" 2>/dev/null; then
		kill -TERM "$SYSBENCH_BG_PID" 2>/dev/null || true
	fi
	SYSBENCH_BG_PID=

	if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
		kill -KILL "$TARGET_PID" 2>/dev/null || true
	fi

	pids=$(pgrep -f "mysqld --defaults-file=$MYSQL_DEFAULTS" || true)
	if [ -n "$pids" ]; then
		kill -KILL $pids 2>/dev/null || true
	fi

	return 0
}

adapter_stop() {
	local pids

	if [ -n "${SYSBENCH_BG_PID:-}" ] && kill -0 "$SYSBENCH_BG_PID" 2>/dev/null; then
		kill -TERM "$SYSBENCH_BG_PID" 2>/dev/null || true
	fi
	sf_safe_shutdown_pidfile "$MYSQL_PID_FILE" "$MYSQL_DEFAULTS" "$MYSQL_SOCKET" || return 1

	pids=$(pgrep -f "mysqld --defaults-file=$MYSQL_DEFAULTS" || true)
	if [ -n "$pids" ]; then
		kill -TERM $pids 2>/dev/null || true
		sleep 2
		pids=$(pgrep -f "mysqld --defaults-file=$MYSQL_DEFAULTS" || true)
		if [ -n "$pids" ]; then
			kill -KILL $pids 2>/dev/null || true
		fi
	fi

	if ! sf_mysql_compare_baseline; then
		return 1
	fi
	return 0
}

adapter_collect() {
	return 0
}
