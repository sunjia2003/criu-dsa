#!/usr/bin/env bash

set -u

REDIS_PORT=
REDIS_CONF=
REDIS_PID_FILE=
REDIS_LOG=
YCSB_LOG=
REDIS_ADMIN_LOG=
YCSB_PROBE_LOG=
YCSB_PID=
YCSB_BIN=
REDIS_TCP_ESTABLISHED=

redis_ping_ok() {
	local out

	out=$(redis-cli -p "$REDIS_PORT" ping 2>>"$REDIS_ADMIN_LOG" || true)
	printf "%s\n" "$out" >>"$REDIS_ADMIN_LOG"
	echo "$out" | grep -q "PONG"
}

redis_stop_ycsb() {
	if [ -n "${YCSB_PID:-}" ] && kill -0 "$YCSB_PID" 2>/dev/null; then
		kill -TERM "$YCSB_PID" 2>/dev/null || true
		sleep 1
		if kill -0 "$YCSB_PID" 2>/dev/null; then
			kill -KILL "$YCSB_PID" 2>/dev/null || true
		fi
		wait "$YCSB_PID" 2>/dev/null || true
	fi

	YCSB_PID=
}

adapter_prepare() {
	cm_require_cmd redis-server || return 1
	cm_require_cmd redis-cli || return 1
	REDIS_PORT=$(cm_alloc_port 16379 16479) || return 1
	REDIS_CONF="$RUN_ROOT/redis.conf"
	REDIS_PID_FILE="$RUN_ROOT/redis.pid"
	REDIS_LOG="$RUN_LOG_DIR/redis.log"
	YCSB_LOG="$RUN_LOG_DIR/ycsb.log"
	REDIS_ADMIN_LOG="$RUN_LOG_DIR/redis-admin.log"
	YCSB_PROBE_LOG="$RUN_LOG_DIR/ycsb-probe.log"

	cat >"$REDIS_CONF" <<EOF
bind 127.0.0.1
port $REDIS_PORT
dir $RUN_ROOT
daemonize no
pidfile $REDIS_PID_FILE
logfile $REDIS_LOG
save ""
appendonly no
EOF

	TARGET_RESOURCE_PORT="$REDIS_PORT"
	TARGET_RESOURCE_PID_FILE="$REDIS_PID_FILE"
	TARGET_RESOURCE_LOG_DIR="$RUN_LOG_DIR"
	cm_append_log_path "$REDIS_LOG"
	cm_append_log_path "$YCSB_LOG"
	cm_append_log_path "$REDIS_ADMIN_LOG"
	cm_append_log_path "$YCSB_PROBE_LOG"

	REDIS_TCP_ESTABLISHED=${REDIS_TCP_ESTABLISHED:-1}
	if [ "$REDIS_TCP_ESTABLISHED" = "1" ]; then
		TARGET_CRIU_DUMP_OPTS="--tcp-established --network-lock skip"
		TARGET_CRIU_RESTORE_OPTS="--tcp-established"
	fi

	YCSB_BIN=$(cm_resolve_cmd \
		"${YCSB_BIN:-}" \
		"${YCSB_BIN_OVERRIDE:-}" \
		ycsb.sh \
		"$HOME/workspace/ycsb-0.17.0/bin/ycsb.sh" \
		ycsb \
		"$HOME/workspace/ycsb-0.17.0/bin/ycsb" \
		2>/dev/null || true)

	if [ -n "$YCSB_BIN" ] && [ "$(basename "$YCSB_BIN")" = "ycsb" ]; then
		if "$YCSB_BIN" -help >"$YCSB_PROBE_LOG" 2>&1; then
			:
		else
			YCSB_BIN=$(cm_resolve_cmd ycsb.sh "$HOME/workspace/ycsb-0.17.0/bin/ycsb.sh" 2>/dev/null || true)
		fi
	fi

	return 0
}

adapter_start() {
	local profile_file="$SCRIPT_DIR/redis-ycsb/profile-small.conf"

	redis-server "$REDIS_CONF" >"$RUN_LOG_DIR/redis-stdout.log" 2>"$RUN_LOG_DIR/redis-stderr.log" &
	TARGET_PID=$!
	if [ -n "${YCSB_BIN:-}" ]; then
		(
			while true; do
				"$YCSB_BIN" run redis -p "redis.host=127.0.0.1" -p "redis.port=$REDIS_PORT" -threads 4 -target 2000 -P "$profile_file" >>"$YCSB_LOG" 2>&1 || true
				sleep 1
			done
		) &
		YCSB_PID=$!
		cm_append_extra_pid "$YCSB_PID"
	fi
	return 0
}

adapter_ready() {
	local timeout_sec="$1"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if redis_ping_ok; then
			return 0
		fi
		sleep 1
	done
	return 1
}

adapter_verify() {
	redis_ping_ok
}

adapter_before_dump() {
	local i

	redis_stop_ycsb

	if command -v ss >/dev/null 2>&1; then
		for i in $(seq 1 10); do
			if ! ss -tn state established 2>/dev/null | grep -q ":$REDIS_PORT"; then
				return 0
			fi
			sleep 1
		done
		cm_err "redis still has established TCP sessions before dump"
		return 1
	fi

	return 0
}

adapter_stop() {
	redis_stop_ycsb
	if [ -f "$REDIS_PID_FILE" ]; then
		redis-cli -p "$REDIS_PORT" shutdown nosave >>"$REDIS_ADMIN_LOG" 2>&1 || true
	fi
	if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
		kill -TERM "$TARGET_PID" 2>/dev/null || true
	fi
	return 0
}

adapter_collect() {
	return 0
}
