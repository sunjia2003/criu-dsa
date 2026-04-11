#!/usr/bin/env bash

set -u

VERI_LOG=
VERI_CMD=
VERI_PGID=
STEP_BEFORE=0
VERI_READY_REGEX=${VERILATOR_READY_REGEX:-"Linux version|Booting Linux|Booting from serial|BIOS CRC passed|LiteX git sha1"}
VERI_READY_PROGRESS_SEC=${VERILATOR_READY_PROGRESS_SEC:-20}
VERI_SIM_EXTRA_ARGS=${VERILATOR_SIM_EXTRA_ARGS:-"--jobs 2 --threads 1"}

veri_pick_python() {
	local py

	py=$(cm_resolve_cmd \
		"${VERILATOR_PYTHON:-}" \
		"$HOME/workspace/litex-env/bin/python" \
		python3 \
		python) || return 1

	echo "$py"
	return 0
}

veri_pick_toolchain_bin_dir() {
	local gcc_cmd

	if [ -n "${RISCV_GCC_BIN_DIR:-}" ] && [ -d "${RISCV_GCC_BIN_DIR}" ]; then
		echo "${RISCV_GCC_BIN_DIR}"
		return 0
	fi

	gcc_cmd=$(cm_resolve_cmd \
		"${RISCV_GCC_CMD:-}" \
		riscv64-unknown-elf-gcc \
		riscv32-unknown-elf-gcc \
		"$HOME/workspace/riscv64-unknown-elf-gcc-8.1.0-2019.01.0-x86_64-linux-ubuntu14/bin/riscv64-unknown-elf-gcc" \
		"$HOME/workspace/riscv64-unknown-elf-gcc-8.3.0-2019.08.0-x86_64-linux-ubuntu14/bin/riscv64-unknown-elf-gcc") || return 1

	dirname "$gcc_cmd"
	return 0
}

veri_group_has_members() {
	local pgid="$1"
	local members

	[ -z "$pgid" ] && return 1
	members=$(ps -o pid= -g "$pgid" 2>/dev/null | tr -d '[:space:]')
	[ -n "$members" ]
}

veri_wait_group_exit() {
	local pgid="$1"
	local timeout_sec="${2:-3}"
	local i

	[ -z "$pgid" ] && return 0

	for i in $(seq 1 "$timeout_sec"); do
		if ! veri_group_has_members "$pgid"; then
			return 0
		fi
		sleep 1
	done

	if ! veri_group_has_members "$pgid"; then
		return 0
	fi

	return 1
}

veri_stop_group() {
	local pgid="$1"

	[ -z "$pgid" ] && return 0

	kill -TERM -- "-$pgid" 2>/dev/null || true
	if veri_wait_group_exit "$pgid" 3; then
		return 0
	fi

	kill -KILL -- "-$pgid" 2>/dev/null || true
	veri_wait_group_exit "$pgid" 3
}

adapter_prepare() {
	cm_require_cmd verilator || return 1

	VERI_LOG="$RUN_LOG_DIR/verilator-linux.log"
	VERI_CMD="${VERILATOR_LINUX_CMD:-}"
	VERI_PGID=

	if [ -z "$VERI_CMD" ] && [ -x "$HOME/workspace/linux-on-litex-vexriscv/sim.py" ]; then
		local sim_py
		local sim_py_dir
		local sim_output_dir
		local py_cmd
		local py_bin_dir
		local tc_bin_dir
		local sim_extra_args

		sim_py="$HOME/workspace/linux-on-litex-vexriscv/sim.py"
		sim_py_dir=$(dirname "$sim_py")
		sim_output_dir="${VERILATOR_OUTPUT_DIR:-$RUN_ROOT/verilator-build}"
		mkdir -p "$sim_output_dir" || return 1

		if ! command -v dtc >/dev/null 2>&1; then
			if [ ! -f "$sim_py_dir/images/rv32.dtb" ]; then
				cm_err "dtc not found and prebuilt images/rv32.dtb is missing"
				return 1
			fi
			cm_log "dtc not found; using existing images/rv32.dtb"
		fi

		py_cmd=$(veri_pick_python) || {
			cm_err "unable to find Python for LiteX simulation (set VERILATOR_PYTHON)"
			return 1
		}
		py_bin_dir=$(dirname "$py_cmd")

		tc_bin_dir=$(veri_pick_toolchain_bin_dir) || {
			cm_err "unable to find RISC-V GCC toolchain (set RISCV_GCC_BIN_DIR or RISCV_GCC_CMD)"
			return 1
		}

		sim_extra_args=""
		if [ -n "$VERI_SIM_EXTRA_ARGS" ]; then
			sim_extra_args=" $VERI_SIM_EXTRA_ARGS"
		fi

		VERI_CMD="cd $sim_py_dir && PATH=\"$py_bin_dir:$tc_bin_dir:\$PATH\" $py_cmd ./sim.py --output-dir \"$sim_output_dir\"$sim_extra_args"
	fi

	if [ -z "$VERI_CMD" ]; then
		cm_err "VERILATOR_LINUX_CMD is not set and default sim.py was not found"
		return 1
	fi
	cm_append_log_path "$VERI_LOG"
	return 0
}

adapter_start() {
	setsid bash -c "$VERI_CMD" >"$VERI_LOG" 2>&1 &
	TARGET_PID=$!
	VERI_PGID="$TARGET_PID"
	if ps -o pgid= -p "$TARGET_PID" >/dev/null 2>&1; then
		VERI_PGID=$(ps -o pgid= -p "$TARGET_PID" | tr -d '[:space:]')
	fi
	return 0
}

adapter_ready() {
	local timeout_sec="$1"
	local i
	for i in $(seq 1 "$timeout_sec"); do
		if grep -E "$VERI_READY_REGEX" "$VERI_LOG" >/dev/null 2>&1; then
			return 0
		fi

		if [ -n "${TARGET_PID:-}" ] && ! kill -0 "$TARGET_PID" 2>/dev/null; then
			cm_err "verilator process exited before ready"
			if [ -s "$VERI_LOG" ]; then
				cm_err "last lines from $VERI_LOG:"
				tail -n 40 "$VERI_LOG" >&2 || true
			fi
			return 1
		fi

		if [ "$VERI_READY_PROGRESS_SEC" -gt 0 ] && [ $((i % VERI_READY_PROGRESS_SEC)) -eq 0 ]; then
			cm_log "waiting verilator ready... ${i}s/${timeout_sec}s"
		fi
		sleep 1
	done

	cm_err "verilator ready timeout after ${timeout_sec}s"
	if [ -s "$VERI_LOG" ]; then
		cm_err "last lines from $VERI_LOG:"
		tail -n 40 "$VERI_LOG" >&2 || true
	fi
	return 1
}

adapter_verify() {
	if [ -z "${TARGET_PID:-}" ] || ! kill -0 "$TARGET_PID" 2>/dev/null; then
		return 1
	fi

	if grep -E "$VERI_READY_REGEX" "$VERI_LOG" >/dev/null 2>&1; then
		return 0
	fi

	return 1
}

adapter_stop() {
	local pgid
	local target_alive=0

	if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
		target_alive=1
	fi

	if [ "$target_alive" -eq 0 ] && [ -z "${VERI_PGID:-}" ]; then
		return 0
	fi

	pgid="${VERI_PGID:-}"
	if [ -z "$pgid" ] && [ -n "${TARGET_PID:-}" ]; then
		pgid="$TARGET_PID"
		if ps -o pgid= -p "$TARGET_PID" >/dev/null 2>&1; then
			pgid=$(ps -o pgid= -p "$TARGET_PID" | tr -d '[:space:]')
		fi
	fi

	if [ -n "$pgid" ]; then
		if ! veri_stop_group "$pgid"; then
			cm_err "verilator process group $pgid still alive after TERM/KILL"
		fi
	fi

	if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
		kill -KILL "$TARGET_PID" 2>/dev/null || true
	fi

	if [ -n "${TARGET_PID:-}" ]; then
		wait "$TARGET_PID" 2>/dev/null || true
	fi

	if [ -n "$pgid" ] && veri_group_has_members "$pgid"; then
		cm_err "verilator process group $pgid still has live members"
		return 1
	fi

	VERI_PGID=
	return 0
}

adapter_stop_for_restore() {
	adapter_stop
	return $?
}

adapter_collect() {
	return 0
}
