#!/usr/bin/env bash

set -u
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)

# shellcheck source=test/workloads/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=test/workloads/lib/adapter.sh
source "$SCRIPT_DIR/lib/adapter.sh"
# shellcheck source=test/workloads/lib/report.sh
source "$SCRIPT_DIR/lib/report.sh"
# shellcheck source=test/workloads/lib/safety.sh
source "$SCRIPT_DIR/lib/safety.sh"

CRIU_BIN=${CRIU_BIN:-"$PROJECT_ROOT/criu/criu"}
WARMUP_SEC=${WARMUP_SEC:-30}
READY_TIMEOUT_SEC=${READY_TIMEOUT_SEC:-60}
PROFILE=${PROFILE:-small}
MODE=${MODE:-all}
WORKSPACE_SNAPSHOT_MODE=${WORKSPACE_SNAPSHOT_MODE:-on}
WORKSPACE_SNAPSHOT_SOURCE_ROOT=${WORKSPACE_SNAPSHOT_SOURCE_ROOT:-}
WORKSPACE_SNAPSHOT_PARENT=${WORKSPACE_SNAPSHOT_PARENT:-}
WORKSPACE_SNAPSHOT_DIR=${WORKSPACE_SNAPSHOT_DIR:-ws-snaps}
WORKSPACE_SNAPSHOT_META_DIR=${WORKSPACE_SNAPSHOT_META_DIR:-ws-meta}
WORKSPACE_RUN_BASE=${WORKSPACE_RUN_BASE:-"$PROJECT_ROOT/workspace/ws-src/r"}
WORKSPACE_CLEANUP_MODE=${WORKSPACE_CLEANUP_MODE:-on}
SMOKE=0
FAIL_FAST=0
ROUNDS=1
WORKLOAD_ARG=all
SUMMARY_FILE=

usage() {
	cat <<EOF
Usage: run-matrix.sh [options]

Options:
  --list
  --workload <name|all|name1,name2>
  --mode <base|dsa_live|all>
  --profile <small>
  --rounds <n>
  --warmup-sec <n>
  --ready-timeout-sec <n>
	--workspace-snapshot
	--no-workspace-snapshot
	--workspace-snapshot-mode <on|off>
	--workspace-snapshot-parent <path>
	--workspace-snapshot-source-root <path>
	--workspace-run-base <path>
	--workspace-snapshot-dir <name>
	--workspace-snapshot-meta-dir <name>
	--workspace-cleanup
	--no-workspace-cleanup
  --smoke
  --fail-fast
  --run-base <path>
  --help
EOF
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--list)
			echo "redis-ycsb"
			echo "mysql-sysbench"
			echo "lammps-bd"
			echo "verilator-linux"
			exit 0
			;;
		--workload)
			WORKLOAD_ARG="$2"
			shift 2
			;;
		--mode)
			MODE="$2"
			shift 2
			;;
		--profile)
			PROFILE="$2"
			shift 2
			;;
		--rounds)
			ROUNDS="$2"
			shift 2
			;;
		--warmup-sec)
			WARMUP_SEC="$2"
			shift 2
			;;
		--ready-timeout-sec)
			READY_TIMEOUT_SEC="$2"
			shift 2
			;;
		--workspace-snapshot)
			WORKSPACE_SNAPSHOT_MODE=on
			shift
			;;
		--no-workspace-snapshot)
			WORKSPACE_SNAPSHOT_MODE=off
			shift
			;;
		--workspace-snapshot-mode)
			WORKSPACE_SNAPSHOT_MODE="$2"
			shift 2
			;;
		--workspace-snapshot-parent)
			WORKSPACE_SNAPSHOT_PARENT="$2"
			shift 2
			;;
		--workspace-snapshot-source-root)
			WORKSPACE_SNAPSHOT_SOURCE_ROOT="$2"
			shift 2
			;;
		--workspace-run-base)
			WORKSPACE_RUN_BASE="$2"
			shift 2
			;;
		--workspace-snapshot-dir)
			WORKSPACE_SNAPSHOT_DIR="$2"
			shift 2
			;;
		--workspace-snapshot-meta-dir)
			WORKSPACE_SNAPSHOT_META_DIR="$2"
			shift 2
			;;
		--workspace-cleanup)
			WORKSPACE_CLEANUP_MODE=on
			shift
			;;
		--no-workspace-cleanup)
			WORKSPACE_CLEANUP_MODE=off
			shift
			;;
		--smoke)
			SMOKE=1
			shift
			;;
		--fail-fast)
			FAIL_FAST=1
			shift
			;;
		--run-base)
			RUN_BASE="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			cm_die "unknown option: $1"
			;;
		esac
	done
}

load_adapter() {
	local workload="$1"
	local adapter="$SCRIPT_DIR/$workload/run.sh"
	if [ ! -f "$adapter" ]; then
		cm_die "adapter not found: $adapter"
	fi
	# shellcheck source=/dev/null
	source "$adapter"
}

reset_case_context() {
	TARGET_PID=
	TARGET_RESOURCE_PORT=
	TARGET_RESOURCE_SOCKET=
	TARGET_RESOURCE_PID_FILE=
	TARGET_RESOURCE_DATADIR=
	TARGET_RESOURCE_LOG_DIR=
	TARGET_EXTRA_PIDS=
	WORKLOAD_LOG_PATHS=
	TARGET_ENV_EXPORTS=
	TARGET_CRIU_DUMP_OPTS=
	TARGET_CRIU_RESTORE_OPTS=
	TARGET_RESTORE_EEXIST_RETRIES=1
	TARGET_RESTORE_RETRY_BACKOFF_SEC=1
	TARGET_WORKSPACE_SNAPSHOT_ENABLED=0
	TARGET_WORKSPACE_SNAPSHOT_ROOT=
	TARGET_WORKSPACE_SNAPSHOT_PARENT=
	TARGET_WORKSPACE_SNAPSHOT_DIR=
	TARGET_WORKSPACE_SNAPSHOT_META_DIR=
	TARGET_WORKSPACE_SNAPSHOT_ACTION_SCRIPT=
	TARGET_CRIU_IMG_DIR=
}

fs_type_of_path() {
	local path="$1"

	stat -f -c %T "$path" 2>/dev/null || true
}

remove_path_with_subvolume_support() {
	local path="$1"

	[ -n "$path" ] || return 0
	[ -e "$path" ] || return 0

	if command -v btrfs >/dev/null 2>&1 && [ -d "$path" ] &&
		btrfs subvolume show "$path" >/dev/null 2>&1; then
		if ! btrfs subvolume delete "$path" >/dev/null 2>&1; then
			cm_err "failed to delete btrfs subvolume: $path"
			return 1
		fi
		return 0
	fi

	rm -rf -- "$path"
}

init_case_run_tree() {
	cm_mkdir_run_tree

	if [ "$WORKSPACE_SNAPSHOT_MODE" != "on" ] || [ "$SMOKE" -eq 1 ]; then
		return 0
	fi

	if ! command -v btrfs >/dev/null 2>&1; then
		cm_err "btrfs command not found; required in workspace snapshot mode"
		return 1
	fi

	if [ -e "$RUN_ROOT" ]; then
		if ! remove_path_with_subvolume_support "$RUN_ROOT"; then
			return 1
		fi
	fi

	if ! btrfs subvolume create "$RUN_ROOT" >/dev/null 2>&1; then
		cm_err "failed to create btrfs run subvolume: $RUN_ROOT"
		return 1
	fi

	mkdir -p "$RUN_LOG_DIR" "$RUN_ARTIFACT_DIR" "$RUN_STATE_DIR"
	return 0
}

generate_workspace_snapshot_action_script() {
	local hook_dir="$1"
	local state_dir="$2"
	local source_root="$3"
	local snapshot_parent="$4"
	local snapshot_dir="$5"
	local meta_dir="$6"
	local action_script="$hook_dir/workspace-snapshot-action.sh"
	local state_file="$state_dir/$RUN_ID.snapshot"

	mkdir -p "$hook_dir" "$state_dir"

	cat >"$action_script" <<EOF
#!/usr/bin/env bash

set -eu

action="\${CRTOOLS_SCRIPT_ACTION:-}"
source_root="$source_root"
snapshot_parent="$snapshot_parent"
snapshot_dir="$snapshot_dir"
meta_dir="$meta_dir"
state_file="$state_file"

latest_meta_for_source() {
	local meta
	local src

	if [ ! -d "\$snapshot_parent/\$meta_dir" ]; then
		return 1
	fi

	while IFS= read -r meta; do
		[ -f "\$meta" ] || continue
		src=\$(awk -F= '/^source_root=/{print substr(\$0, index(\$0, "=")+1)}' "\$meta")
		[ "\$src" = "\$source_root" ] || continue
		echo "\$meta"
		return 0
	done < <(ls -1t "\$snapshot_parent/\$meta_dir"/dump-*.meta 2>/dev/null || true)

	return 1
}

snapshot_path_from_meta() {
	local meta="\$1"

	awk -F= '/^snapshot_path=/{print substr(\$0, index(\$0, "=")+1)}' "\$meta"
}

restore_source_from_snapshot() {
	local snapshot_path="\$1"
	local entry
	local base

	[ -d "\$snapshot_path" ] || return 1
	[ -d "\$source_root" ] || mkdir -p "\$source_root"

	if command -v rsync >/dev/null 2>&1; then
		rsync -a --delete \
			--exclude '/state/' \
			--exclude '/artifacts/' \
			--exclude '/.ws-parent/' \
			"\$snapshot_path"/ "\$source_root"/
		return \$?
	fi

	find "\$source_root" -mindepth 1 -maxdepth 1 \
		! -name state ! -name artifacts ! -name .ws-parent \
		-exec rm -rf -- {} +

	for entry in "\$snapshot_path"/* "\$snapshot_path"/.[!.]* "\$snapshot_path"/..?*; do
		[ -e "\$entry" ] || continue
		base=\$(basename "\$entry")
		case "\$base" in
		state|artifacts|.ws-parent)
			continue
			;;
		esac
		cp -a "\$entry" "\$source_root"/
	done
}

case "\$action" in
post-dump)
	meta=""
	for _i in \$(seq 1 50); do
		meta=\$(latest_meta_for_source || true)
		if [ -n "\$meta" ]; then
			break
		fi
		sleep 0.1
	done

	if [ -z "\$meta" ]; then
		echo "workspace-snapshot-action: metadata not ready for \$source_root (will resolve on pre-restore)" >&2
		exit 0
	fi

	snapshot_path=\$(snapshot_path_from_meta "\$meta")
	if [ -z "\$snapshot_path" ]; then
		echo "workspace-snapshot-action: snapshot path missing in \$meta (will resolve on pre-restore)" >&2
		exit 0
	fi

	printf "%s\n" "\$snapshot_path" >"\$state_file"
	;;
pre-restore)
	snapshot_path=""
	if [ -f "\$state_file" ]; then
		snapshot_path=\$(cat "\$state_file")
	fi

	if [ -z "\$snapshot_path" ]; then
		meta=\$(latest_meta_for_source || true)
		if [ -n "\$meta" ]; then
			snapshot_path=\$(snapshot_path_from_meta "\$meta")
		fi
	fi

	if [ -z "\$snapshot_path" ]; then
		echo "workspace-snapshot-action: failed to resolve snapshot path for \$source_root" >&2
		exit 1
	fi

	restore_source_from_snapshot "\$snapshot_path"
	;;
*)
	;;
esac

exit 0
EOF

	chmod 0700 "$action_script"
	TARGET_WORKSPACE_SNAPSHOT_ACTION_SCRIPT="$action_script"
}

configure_workspace_snapshot_for_case() {
	local mode="$WORKSPACE_SNAPSHOT_MODE"
	local source_root
	local snapshot_parent
	local source_real
	local parent_real
	local run_real
	local source_fstype
	local parent_fstype
	local hook_dir
	local state_dir
	local img_root

	case "$mode" in
	off|on)
		;;
	*)
		cm_err "invalid WORKSPACE_SNAPSHOT_MODE: $mode"
		return 1
		;;
	esac

	if [ "$SMOKE" -eq 1 ] || [ "$mode" = "off" ]; then
		TARGET_WORKSPACE_SNAPSHOT_ENABLED=0
		TARGET_CRIU_IMG_DIR="$RUN_ROOT/img"
		return 0
	fi

	source_root="$WORKSPACE_SNAPSHOT_SOURCE_ROOT"
	if [ -z "$source_root" ]; then
		source_root="$RUN_ROOT"
	fi
	snapshot_parent="$WORKSPACE_SNAPSHOT_PARENT"
	if [ -z "$snapshot_parent" ]; then
		snapshot_parent="$RUN_BASE/.ws-parent/$RUN_ID"
	fi

	mkdir -p "$source_root" "$snapshot_parent"

	source_real=$(realpath "$source_root" 2>/dev/null || true)
	parent_real=$(realpath "$snapshot_parent" 2>/dev/null || true)
	run_real=$(realpath "$RUN_ROOT" 2>/dev/null || true)

	if [ -z "$source_real" ] || [ -z "$parent_real" ] || [ -z "$run_real" ]; then
		cm_err "workspace snapshot path resolution failed"
		return 1
	fi

	if [ "$run_real" != "$source_real" ] && [[ "$run_real" != "$source_real/"* ]]; then
		cm_err "run root must be inside workspace snapshot source root (run=$run_real source=$source_real)"
		return 1
	fi

	source_fstype=$(fs_type_of_path "$source_real")
	parent_fstype=$(fs_type_of_path "$parent_real")

	if [ "$source_fstype" != "btrfs" ] || [ "$parent_fstype" != "btrfs" ]; then
		cm_err "workspace snapshot requires btrfs source/parent (source=$source_fstype parent=$parent_fstype)"
		return 1
	fi

	TARGET_WORKSPACE_SNAPSHOT_ENABLED=1
	TARGET_WORKSPACE_SNAPSHOT_ROOT="$source_real"
	TARGET_WORKSPACE_SNAPSHOT_PARENT="$parent_real"
	TARGET_WORKSPACE_SNAPSHOT_DIR="$WORKSPACE_SNAPSHOT_DIR"
	TARGET_WORKSPACE_SNAPSHOT_META_DIR="$WORKSPACE_SNAPSHOT_META_DIR"
	img_root="$TARGET_WORKSPACE_SNAPSHOT_PARENT/.ws-images/$RUN_ID"
	mkdir -p "$img_root"
	TARGET_CRIU_IMG_DIR="$img_root"

	hook_dir="$TARGET_WORKSPACE_SNAPSHOT_PARENT/.ws-hooks/$RUN_ID"
	state_dir="$TARGET_WORKSPACE_SNAPSHOT_PARENT/.ws-state"

	generate_workspace_snapshot_action_script \
		"$hook_dir" \
		"$state_dir" \
		"$TARGET_WORKSPACE_SNAPSHOT_ROOT" \
		"$TARGET_WORKSPACE_SNAPSHOT_PARENT" \
		"$TARGET_WORKSPACE_SNAPSHOT_DIR" \
		"$TARGET_WORKSPACE_SNAPSHOT_META_DIR"

	cm_log "workspace snapshot enabled root=$TARGET_WORKSPACE_SNAPSHOT_ROOT parent=$TARGET_WORKSPACE_SNAPSHOT_PARENT img_dir=$TARGET_CRIU_IMG_DIR"
	return 0
}

cleanup_extra_pids() {
	local pid
	local -a extra_pids=()

	if [ -z "${TARGET_EXTRA_PIDS:-}" ]; then
		return 0
	fi

	IFS=',' read -r -a extra_pids <<<"$TARGET_EXTRA_PIDS"
	for pid in "${extra_pids[@]}"; do
		[ -z "$pid" ] && continue

		if kill -0 "$pid" 2>/dev/null; then
			kill -TERM "$pid" 2>/dev/null || true
			sleep 1
			if kill -0 "$pid" 2>/dev/null; then
				kill -KILL "$pid" 2>/dev/null || true
			fi
		fi

		wait "$pid" 2>/dev/null || true
	done
}

stop_case_targets() {
	adapter_stop || true
	cleanup_extra_pids || true
	if [ -n "${TARGET_PID:-}" ]; then
		wait "$TARGET_PID" 2>/dev/null || true
	fi
}

ensure_target_stopped_before_restore() {
	local i

	if [ -z "${TARGET_PID:-}" ] || ! kill -0 "$TARGET_PID" 2>/dev/null; then
		return 0
	fi

	cm_log "target pid $TARGET_PID is still alive after dump; stopping before restore"
	adapter_stop_for_restore || true

	for i in $(seq 1 10); do
		wait "$TARGET_PID" 2>/dev/null || true
		if ! kill -0 "$TARGET_PID" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done

	cm_err "target pid $TARGET_PID is still alive before restore"
	return 1
}

is_restore_eexist_error() {
	local restore_log="$1"

	[ -f "$restore_log" ] || return 1
	grep -q "Can't fork for" "$restore_log" 2>/dev/null || return 1
	grep -q "File exists" "$restore_log" 2>/dev/null || return 1
	return 0
}

run_restore_with_retry() {
	local img_dir="$1"
	local restore_log="$2"
	shift 2
	local -a restore_extra_opts=("$@")
	local retries="${TARGET_RESTORE_EEXIST_RETRIES:-1}"
	local backoff="${TARGET_RESTORE_RETRY_BACKOFF_SEC:-1}"
	local max_attempts
	local attempt=1

	if ! [[ "$retries" =~ ^[0-9]+$ ]]; then
		retries=1
	fi

	if ! [[ "$backoff" =~ ^[0-9]+$ ]]; then
		backoff=1
	fi

	max_attempts=$((retries + 1))

	while [ "$attempt" -le "$max_attempts" ]; do
		cm_log "restore attempt $attempt/$max_attempts"
		: >"$restore_log"

		if "$CRIU_BIN" restore -D "$img_dir" -o "$restore_log" -v4 --shell-job --restore-detached "${restore_extra_opts[@]}"; then
			if grep -q "Restore finished successfully" "$restore_log" 2>/dev/null; then
				return 0
			fi
		fi

		if [ "$attempt" -ge "$max_attempts" ]; then
			return 1
		fi

		if ! is_restore_eexist_error "$restore_log"; then
			return 1
		fi

		cm_log "restore hit EEXIST; cleanup and retry"
		adapter_stop_for_restore || true
		cleanup_extra_pids || true
		if [ "$backoff" -gt 0 ]; then
			sleep "$backoff"
		fi

		attempt=$((attempt + 1))
	done

	return 1
}

run_criu_phase() {
	local envs="$1"
	local img_dir="${TARGET_CRIU_IMG_DIR:-$RUN_ROOT/img}"
	local criu_log_dir="$RUN_ARTIFACT_DIR/criu-logs"
	local dump_log="$criu_log_dir/dump.log"
	local restore_log="$criu_log_dir/restore.log"
	local -a dump_extra_opts=()
	local -a restore_extra_opts=()
	mkdir -p "$criu_log_dir"
	mkdir -p "$img_dir"

	if [ -n "${TARGET_CRIU_DUMP_OPTS:-}" ]; then
		read -r -a dump_extra_opts <<<"$TARGET_CRIU_DUMP_OPTS"
	fi

	if [ -n "${TARGET_CRIU_RESTORE_OPTS:-}" ]; then
		read -r -a restore_extra_opts <<<"$TARGET_CRIU_RESTORE_OPTS"
	fi

	if [ "${TARGET_WORKSPACE_SNAPSHOT_ENABLED:-0}" = "1" ]; then
		dump_extra_opts+=(
			--workspace-snapshot
			--workspace-root "$TARGET_WORKSPACE_SNAPSHOT_ROOT"
			--workspace-snapshot-parent "$TARGET_WORKSPACE_SNAPSHOT_PARENT"
			--workspace-snapshot-dir "$TARGET_WORKSPACE_SNAPSHOT_DIR"
			--workspace-snapshot-meta-dir "$TARGET_WORKSPACE_SNAPSHOT_META_DIR"
			--no-workspace-snapshot-strict
			--action-script "$TARGET_WORKSPACE_SNAPSHOT_ACTION_SCRIPT"
		)
		restore_extra_opts+=(--action-script "$TARGET_WORKSPACE_SNAPSHOT_ACTION_SCRIPT")
	fi

	rp_phase_begin dump
	if [ -n "$envs" ]; then
		if ! env $envs "$CRIU_BIN" dump -t "$TARGET_PID" -D "$img_dir" -o "$dump_log" -v4 --shell-job "${dump_extra_opts[@]}"; then
			rp_phase_end 1
			return 1
		fi
	else
		if ! "$CRIU_BIN" dump -t "$TARGET_PID" -D "$img_dir" -o "$dump_log" -v4 --shell-job "${dump_extra_opts[@]}"; then
			rp_phase_end 1
			return 1
		fi
	fi
	rp_phase_end 0

	if ! ensure_target_stopped_before_restore; then
		return 1
	fi

	rp_phase_begin restore
	if ! run_restore_with_retry "$img_dir" "$restore_log" "${restore_extra_opts[@]}"; then
		rp_phase_end 1
		return 1
	fi
	rp_phase_end 0
	return 0
}

short_workload_tag() {
	local workload="$1"

	case "$workload" in
	redis-ycsb)
		echo "rd"
		;;
	mysql-sysbench)
		echo "my"
		;;
	lammps-bd)
		echo "la"
		;;
	verilator-linux)
		echo "ve"
		;;
	*)
		echo "wk"
		;;
	esac
}

short_mode_tag() {
	local mode="$1"

	case "$mode" in
	base)
		echo "b"
		;;
	dsa_live)
		echo "d"
		;;
	*)
		echo "x"
		;;
	esac
}

gen_case_run_id() {
	local workload="$1"
	local mode="$2"
	local round="$3"
	local wtag
	local mtag
	local ts
	local rnd

	wtag=$(short_workload_tag "$workload")
	mtag=$(short_mode_tag "$mode")
	ts=$(date +%m%d%H%M%S)
	rnd=$(printf "%04x" "$((RANDOM % 65536))")

	printf "%s%s-r%s-%s-%s" "$wtag" "$mtag" "$round" "$ts" "$rnd"
}

cleanup_workspace_case_data() {
	local mode="$WORKSPACE_CLEANUP_MODE"
	local run_real
	local source_real
	local should_delete_run=0
	local parent
	local snapshot_root
	local meta_root
	local state_file
	local hook_dir
	local img_dir
	local snapshot_path
	local meta
	local meta_snapshot
	local dump_path

	case "$mode" in
	off)
		return 0
		;;
	on)
		;;
	*)
		cm_err "invalid WORKSPACE_CLEANUP_MODE: $mode"
		return 1
		;;
	esac

	if [ -n "${RUN_ROOT:-}" ] && [ -e "$RUN_ROOT" ]; then
		run_real=$(realpath "$RUN_ROOT" 2>/dev/null || true)
		source_real=$(realpath "${TARGET_WORKSPACE_SNAPSHOT_ROOT:-$WORKSPACE_SNAPSHOT_SOURCE_ROOT}" 2>/dev/null || true)

		if [ -n "$run_real" ] && [ -n "$source_real" ] && { [ "$run_real" = "$source_real" ] || [[ "$run_real" == "$source_real/"* ]]; }; then
			should_delete_run=1
		fi
	fi

	if [ "${TARGET_WORKSPACE_SNAPSHOT_ENABLED:-0}" != "1" ]; then
		return 0
	fi

	parent="${TARGET_WORKSPACE_SNAPSHOT_PARENT:-}"
	[ -n "$parent" ] || return 0

	snapshot_root="$parent/${TARGET_WORKSPACE_SNAPSHOT_DIR:-$WORKSPACE_SNAPSHOT_DIR}"
	meta_root="$parent/${TARGET_WORKSPACE_SNAPSHOT_META_DIR:-$WORKSPACE_SNAPSHOT_META_DIR}"
	state_file="$parent/.ws-state/$RUN_ID.snapshot"
	hook_dir="$parent/.ws-hooks/$RUN_ID"
	img_dir="${TARGET_CRIU_IMG_DIR:-}"

	snapshot_path=
	if [ -f "$state_file" ]; then
		snapshot_path=$(cat "$state_file" 2>/dev/null || true)
	fi

	if [ -n "$img_dir" ] && [ -d "$img_dir" ] && [[ "$img_dir" == "$parent/.ws-images/"* ]]; then
		remove_path_with_subvolume_support "$img_dir" || true
	fi

	if [ -d "$hook_dir" ] && [[ "$hook_dir" == "$parent/.ws-hooks/"* ]]; then
		rm -rf -- "$hook_dir"
	fi

	if [ -f "$state_file" ] && [[ "$state_file" == "$parent/.ws-state/"* ]]; then
		rm -f -- "$state_file"
	fi

	if [ -d "$snapshot_root" ]; then
		if [ -n "$snapshot_path" ] && [ -d "$snapshot_path" ] && [[ "$snapshot_path" == "$snapshot_root/"* ]]; then
			remove_path_with_subvolume_support "$snapshot_path" || true
		fi

		while IFS= read -r dump_path; do
			[ -n "$dump_path" ] || continue
			remove_path_with_subvolume_support "$dump_path" || true
		done < <(
			find "$snapshot_root" -type d -name 'dump-*' 2>/dev/null |
				awk '{print length($0) "\t" $0}' |
				sort -rn |
				cut -f2-
		)
	fi

	if [ -n "$snapshot_path" ] && [ -d "$meta_root" ]; then
		for meta in "$meta_root"/dump-*.meta; do
			[ -f "$meta" ] || continue
			meta_snapshot=$(awk -F= '/^snapshot_path=/{print substr($0, index($0, "=")+1)}' "$meta")
			if [ "$meta_snapshot" = "$snapshot_path" ]; then
				rm -f -- "$meta"
			fi
		done
	fi

	if [ "$should_delete_run" -eq 1 ] && [ -n "$run_real" ]; then
		remove_path_with_subvolume_support "$run_real" || true
	fi

	return 0
}

emit_failure_diagnostics() {
	local phase_file="$RUN_STATE_DIR/phases.tsv"
	local manifest_file="$RUN_ARTIFACT_DIR/manifest.json"
	local dump_log="$RUN_ARTIFACT_DIR/criu-logs/dump.log"
	local restore_log="$RUN_ARTIFACT_DIR/criu-logs/restore.log"
	local f
	local base
	local count=0

	cm_err "case fail run_id=$RUN_ID workload=$WORKLOAD_NAME mode=$WORKLOAD_MODE run_root=$RUN_ROOT"

	if [ -f "$phase_file" ]; then
		cm_err "phase tail: $phase_file"
		tail -n 20 "$phase_file" >&2 || true
	fi

	if [ -f "$manifest_file" ]; then
		cm_err "manifest: $manifest_file"
		cat "$manifest_file" >&2 || true
	fi

	if [ -f "$dump_log" ]; then
		cm_err "dump log tail: $dump_log"
		tail -n 80 "$dump_log" >&2 || true
	fi

	if [ -f "$restore_log" ]; then
		cm_err "restore log tail: $restore_log"
		tail -n 80 "$restore_log" >&2 || true
	fi

	for f in "$RUN_LOG_DIR"/*.log; do
		[ -f "$f" ] || continue
		base=$(basename "$f")
		case "$base" in
		dump.log|restore.log)
			continue
			;;
		esac

		cm_err "workload log tail: $f"
		tail -n 40 "$f" >&2 || true
		count=$((count + 1))
		if [ "$count" -ge 6 ]; then
			break
		fi
	done
}

run_one_case() {
	local workload="$1"
	local mode="$2"
	local round="$3"
	local envs=""
	local phase_rc=0
	WORKLOAD_NAME="$workload"
	WORKLOAD_MODE="$mode"
	WORKLOAD_PROFILE="$PROFILE"
	reset_case_context
	RUN_ID=$(gen_case_run_id "$workload" "$mode" "$round")
	if ! init_case_run_tree; then
		cm_mkdir_run_tree
		rp_init
		rp_set_result FAIL FATAL_RUNTIME "run tree init failed"
		rp_emit_manifest
		return 1
	fi
	rp_init

	cm_log "case start workload=$workload mode=$mode round=$round run_id=$RUN_ID"

	load_adapter "$workload"

	rp_phase_begin prepare
	adapter_prepare
	phase_rc=$?
	if [ "$phase_rc" -ne 0 ]; then
		rp_phase_end "$phase_rc"
		rp_set_result FAIL FATAL_RUNTIME "prepare failed"
		adapter_collect || true
		stop_case_targets
		rp_emit_manifest
		return 1
	fi

	if ! configure_workspace_snapshot_for_case; then
		rp_phase_end 1
		rp_set_result FAIL FATAL_RUNTIME "workspace snapshot setup failed"
		adapter_collect || true
		stop_case_targets
		rp_emit_manifest
		return 1
	fi
	rp_phase_end 0

	rp_phase_begin start
	adapter_start
	phase_rc=$?
	if [ "$phase_rc" -ne 0 ]; then
		rp_phase_end "$phase_rc"
		rp_set_result FAIL FATAL_RUNTIME "start failed"
		adapter_collect || true
		stop_case_targets
		rp_emit_manifest
		return 1
	fi
	rp_phase_end 0

	rp_phase_begin ready
	adapter_ready "$READY_TIMEOUT_SEC"
	phase_rc=$?
	if [ "$phase_rc" -ne 0 ]; then
		rp_phase_end "$phase_rc"
		rp_set_result FAIL FATAL_RUNTIME "ready timeout"
		adapter_collect || true
		stop_case_targets
		rp_emit_manifest
		return 1
	fi
	rp_phase_end 0

	if [ "$SMOKE" -eq 0 ]; then
		rp_phase_begin warmup
		sleep "$WARMUP_SEC"
		rp_phase_end 0

		if [ "$mode" = "base" ]; then
			envs="CRIU_DSA_DUMP=0 CRIU_DSA_POPULATE_READ=0 ${TARGET_ENV_EXPORTS:-}"
		else
			envs="CRIU_DSA_DUMP=1 CRIU_DSA_DESC_SCAN=1 ${TARGET_ENV_EXPORTS:-}"
		fi

		rp_phase_begin pre_dump
		adapter_before_dump
		phase_rc=$?
		if [ "$phase_rc" -ne 0 ]; then
			rp_phase_end "$phase_rc"
			rp_set_result FAIL FATAL_RUNTIME "pre_dump failed"
			adapter_collect || true
			stop_case_targets
			rp_emit_manifest
			return 1
		fi
		rp_phase_end 0

		if ! run_criu_phase "$envs"; then
			rp_set_result FAIL FATAL_CRIU "dump or restore failed"
			adapter_collect || true
			stop_case_targets
			rp_emit_manifest
			return 1
		fi

		rp_phase_begin post_restore
		adapter_after_restore
		phase_rc=$?
		if [ "$phase_rc" -ne 0 ]; then
			rp_phase_end "$phase_rc"
			rp_set_result FAIL FATAL_RUNTIME "post_restore failed"
			adapter_collect || true
			stop_case_targets
			rp_emit_manifest
			return 1
		fi
		rp_phase_end 0
	fi

	rp_phase_begin verify
	adapter_verify
	phase_rc=$?
	if [ "$phase_rc" -ne 0 ]; then
		rp_phase_end "$phase_rc"
		rp_set_result FAIL FATAL_VERIFY "verify failed"
		adapter_collect || true
		stop_case_targets
		rp_emit_manifest
		return 1
	fi
	rp_phase_end 0

	rp_phase_begin collect
	adapter_collect || true
	rp_phase_end 0

	rp_phase_begin stop
	phase_rc=0
	adapter_stop || phase_rc=$?
	cleanup_extra_pids || true
	if [ -n "${TARGET_PID:-}" ]; then
		wait "$TARGET_PID" 2>/dev/null || true
	fi
	if [ "$phase_rc" -ne 0 ]; then
		rp_phase_end "$phase_rc"
		rp_set_result FAIL FATAL_RUNTIME "stop failed"
		rp_emit_manifest
		return 1
	fi
	rp_phase_end 0

	rp_set_result PASS
	rp_emit_manifest
	cm_log "case pass run_id=$RUN_ID manifest=$RUN_ARTIFACT_DIR/manifest.json"
	return 0
}

expand_workloads() {
	if [ "$WORKLOAD_ARG" = "all" ]; then
		echo "redis-ycsb mysql-sysbench lammps-bd verilator-linux"
		return 0
	fi
	echo "$WORKLOAD_ARG" | tr ',' ' '
}

expand_modes() {
	case "$MODE" in
	base)
		echo "base"
		;;
	dsa_live)
		echo "dsa_live"
		;;
	all)
		echo "base dsa_live"
		;;
	*)
		cm_die "invalid mode: $MODE"
		;;
	esac
}

main() {
	local workloads
	local modes
	local w
	local m
	local r
	local rc=0
	local pass=0
	local fail=0
	local summary_base
	local run_base_fstype

	parse_args "$@"
	summary_base="$RUN_BASE"

	if [ "$WORKSPACE_SNAPSHOT_MODE" = "on" ]; then
		mkdir -p "$WORKSPACE_RUN_BASE"
		run_base_fstype=$(fs_type_of_path "$WORKSPACE_RUN_BASE")
		if [ "$run_base_fstype" != "btrfs" ]; then
			cm_die "workspace run base must be on btrfs in snapshot mode: $WORKSPACE_RUN_BASE (fs=$run_base_fstype)"
		fi

		if [ "$RUN_BASE" != "$WORKSPACE_RUN_BASE" ]; then
			cm_log "snapshot mode on: run data base forced to $WORKSPACE_RUN_BASE (summary remains at $RUN_BASE)"
		fi

		RUN_BASE="$WORKSPACE_RUN_BASE"
	fi

	[ -x "$CRIU_BIN" ] || cm_die "criu binary not executable: $CRIU_BIN"
	mkdir -p "$summary_base"
	SUMMARY_FILE="$summary_base/summary.tsv"
	: >"$SUMMARY_FILE"

	workloads=$(expand_workloads)
	modes=$(expand_modes)

	for r in $(seq 1 "$ROUNDS"); do
		for w in $workloads; do
			for m in $modes; do
				if run_one_case "$w" "$m" "$r"; then
					pass=$((pass + 1))
				else
					fail=$((fail + 1))
					rc=1
					emit_failure_diagnostics
				fi
				rp_emit_summary_line "$SUMMARY_FILE"
				cleanup_workspace_case_data || true
				if [ "$FAIL_FAST" -eq 1 ] && [ "$rc" -ne 0 ]; then
					cm_err "fail-fast triggered"
					exit 1
				fi
			done
		done
	done

	cm_log "summary pass=$pass fail=$fail summary_file=$SUMMARY_FILE"
	return "$rc"
}

main "$@"
