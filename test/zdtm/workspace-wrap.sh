#!/usr/bin/env bash

set -euo pipefail

usage() {
	cat <<'EOF'
Usage: workspace-wrap.sh --workspace-root <path> [options] -- <command> [args...]

Options:
  --workspace-root <path>       Root directory to place writable run artifacts.
  --run-id <id>                 Optional run identifier (default: timestamp-pid).
  --require-namespace <0|1>     Fail when mount namespace setup fails (default: 1).
  --no-bind-tmp                 Do not bind-mount /tmp and /var/tmp.
  --help                        Show this help.
EOF
}

workspace_root=""
run_id=""
require_namespace=1
bind_tmp=1
entered_namespace=0

while [ "$#" -gt 0 ]; do
	case "$1" in
	--workspace-root)
		if [ "$#" -lt 2 ]; then
			echo "workspace-wrap: missing value for --workspace-root" >&2
			exit 2
		fi
		workspace_root="$2"
		shift 2
		;;
	--run-id)
		if [ "$#" -lt 2 ]; then
			echo "workspace-wrap: missing value for --run-id" >&2
			exit 2
		fi
		run_id="$2"
		shift 2
		;;
	--require-namespace)
		if [ "$#" -lt 2 ]; then
			echo "workspace-wrap: missing value for --require-namespace" >&2
			exit 2
		fi
		require_namespace="$2"
		shift 2
		;;
	--no-bind-tmp)
		bind_tmp=0
		shift
		;;
	--entered-namespace)
		entered_namespace=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	*)
		echo "workspace-wrap: unknown option: $1" >&2
		usage
		exit 2
		;;
	esac
done

if [ -z "$workspace_root" ]; then
	echo "workspace-wrap: --workspace-root is required" >&2
	exit 2
fi

if [ "$#" -eq 0 ]; then
	echo "workspace-wrap: command is required" >&2
	exit 2
fi

if [ -z "$run_id" ]; then
	run_id="$(date +%s)-$$"
fi

case "$require_namespace" in
0|1)
	;;
*)
	echo "workspace-wrap: --require-namespace must be 0 or 1" >&2
	exit 2
	;;
esac

mkdir -p "$workspace_root"
workspace_root="$(realpath "$workspace_root")"

run_root="$workspace_root/run/$run_id"
tmp_root="$workspace_root/tmp/$run_id"
home_root="$workspace_root/home/$run_id"
runtime_root="$workspace_root/runtime/$run_id"
log_root="$workspace_root/log/$run_id"

mkdir -p "$run_root" "$tmp_root" "$home_root" "$runtime_root" "$log_root"
chmod 0700 "$runtime_root"

if [ "$entered_namespace" -eq 0 ]; then
	if command -v unshare >/dev/null 2>&1; then
		ns_args=(
			--entered-namespace
			--workspace-root "$workspace_root"
			--run-id "$run_id"
			--require-namespace "$require_namespace"
		)
		if [ "$bind_tmp" -eq 0 ]; then
			ns_args+=(--no-bind-tmp)
		fi

		if unshare -m -- "$0" "${ns_args[@]}" -- "$@"; then
			exit 0
		fi

		unshare_rc=$?
		if [ "$require_namespace" -eq 1 ]; then
			echo "workspace-wrap: failed to enter mount namespace" >&2
			exit "$unshare_rc"
		fi

		echo "workspace-wrap: mount namespace unavailable, fallback to env-only redirection" >&2
	else
		if [ "$require_namespace" -eq 1 ]; then
			echo "workspace-wrap: unshare not found" >&2
			exit 1
		fi

		echo "workspace-wrap: unshare not found, fallback to env-only redirection" >&2
	fi
fi

if [ "$entered_namespace" -eq 1 ]; then
	mount --make-rprivate /

	if [ "$bind_tmp" -eq 1 ]; then
		mount --bind "$tmp_root" /tmp
		if [ -d /var/tmp ]; then
			mount --bind "$tmp_root" /var/tmp
		fi
	fi
fi

export TMPDIR="$tmp_root"
export HOME="$home_root"
export XDG_RUNTIME_DIR="$runtime_root"
export WORKSPACE_WRAPPED_RUN_DIR="$run_root"
export WORKSPACE_WRAPPED_LOG_DIR="$log_root"

cd "$run_root"
exec "$@"
