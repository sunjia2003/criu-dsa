#!/usr/bin/env bash

set -u

MYSQL_BASELINE_PROC_FILE=${MYSQL_BASELINE_PROC_FILE:-}
MYSQL_BASELINE_LISTEN_FILE=${MYSQL_BASELINE_LISTEN_FILE:-}

sf_path_must_be_under() {
	local path="$1"
	local root="$2"
	case "$path" in
	"$root"|"$root"/*)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

sf_mysql_capture_baseline() {
	MYSQL_BASELINE_PROC_FILE="$RUN_STATE_DIR/mysql-baseline-proc.txt"
	MYSQL_BASELINE_LISTEN_FILE="$RUN_STATE_DIR/mysql-baseline-listen.txt"
	ps -eo pid,user,cmd | grep -E "[m]ysqld" >"$MYSQL_BASELINE_PROC_FILE" || true
	ss -lntup | grep -E "3306|33060|mysqld" >"$MYSQL_BASELINE_LISTEN_FILE" || true
}

sf_mysql_compare_baseline() {
	local now_proc="$RUN_STATE_DIR/mysql-now-proc.txt"
	local now_listen="$RUN_STATE_DIR/mysql-now-listen.txt"
	ps -eo pid,user,cmd | grep -E "[m]ysqld" >"$now_proc" || true
	ss -lntup | grep -E "3306|33060|mysqld" >"$now_listen" || true

	if ! cmp -s "$MYSQL_BASELINE_PROC_FILE" "$now_proc"; then
		return 1
	fi
	if ! cmp -s "$MYSQL_BASELINE_LISTEN_FILE" "$now_listen"; then
		return 1
	fi
	return 0
}

sf_mysql_preflight_guard() {
	local port="$1"
	local datadir="$2"
	local sock="$3"
	local pidf="$4"
	local logdir="$5"
	local defaults_file="$6"

	if [ "$port" = "3306" ] || [ "$port" = "33060" ]; then
		return 1
	fi

	sf_path_must_be_under "$datadir" "$RUN_ROOT" || return 1
	sf_path_must_be_under "$sock" "$RUN_ROOT" || return 1
	sf_path_must_be_under "$pidf" "$RUN_ROOT" || return 1
	sf_path_must_be_under "$logdir" "$RUN_ROOT" || return 1
	sf_path_must_be_under "$defaults_file" "$RUN_ROOT" || return 1

	case "$datadir" in
	/var/lib/mysql*|/var/run/mysqld*)
		return 1
		;;
	esac
	return 0
}

sf_safe_shutdown_pidfile() {
	local pidfile="$1"
	local defaults_file="$2"
	local socket_path="${3:-}"
	local pid
	local cmdline

	if [ ! -f "$pidfile" ]; then
		return 0
	fi

	pid=$(cat "$pidfile" 2>/dev/null || true)
	if [ -z "$pid" ]; then
		return 0
	fi

	if ! kill -0 "$pid" 2>/dev/null; then
		return 0
	fi

	cmdline=$(tr '\0' ' ' </proc/"$pid"/cmdline 2>/dev/null || true)
	if ! echo "$cmdline" | grep -F -- "$defaults_file" >/dev/null 2>&1; then
		return 1
	fi

	if [ -n "$socket_path" ] && command -v mysqladmin >/dev/null 2>&1; then
		mysqladmin --socket="$socket_path" shutdown >/dev/null 2>&1 || true
		sleep 2
	fi

	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null || true
		sleep 3
	fi

	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	return 0
}
