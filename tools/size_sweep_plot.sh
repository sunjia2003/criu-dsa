#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
OUT_DIR="$ROOT_DIR/output"
CSV="$OUT_DIR/base_dsa_size_sweep.csv"
FROZEN_PNG="$OUT_DIR/base_dsa_frozen_compare.png"
MEMDUMP_PNG="$OUT_DIR/base_dsa_memdump_compare.png"

SIZES_MB=(64 128 256 512 1024 2048)

mkdir -p "$OUT_DIR"
: > "$CSV"
echo "size_mb,base_frozen_us,dsa_frozen_us,base_memdump_us,dsa_memdump_us" >> "$CSV"

for size in "${SIZES_MB[@]}"; do
    echo "[RUN] TARGET_MB=$size (serial)"

    run_output=$(cd "$ROOT_DIR" && sudo BENCH_ROUNDS=1 RUN_POPULATE_CASE=0 TARGET_MB="$size" ./criu-test.sh)
    echo "$run_output"

    ws=$(echo "$run_output" | sed -n 's/^test workspace: //p' | tail -n1)
    if [[ -z "$ws" ]]; then
        echo "[ERR] cannot parse test workspace for size=$size" >&2
        exit 1
    fi

    base_log="$ws/base/dump.log"
    dsa_log="$ws/dsa_live/dump.log"

    if [[ ! -f "$base_log" || ! -f "$dsa_log" ]]; then
        echo "[ERR] missing dump logs for size=$size: $base_log / $dsa_log" >&2
        exit 1
    fi

    base_line=$(sudo awk '/Dump timing:/{l=$0} END{print l}' "$base_log" 2>/dev/null || true)
    dsa_line=$(sudo awk '/Dump timing:/{l=$0} END{print l}' "$dsa_log" 2>/dev/null || true)

    if [[ -z "$base_line" || -z "$dsa_line" ]]; then
        echo "[ERR] missing Dump timing line for size=$size" >&2
        exit 1
    fi

    base_frozen=$(echo "$base_line" | sed -n 's/.*frozen=\([0-9][0-9]*\) us.*/\1/p')
    base_memdump=$(echo "$base_line" | sed -n 's/.*memdump=\([0-9][0-9]*\) us.*/\1/p')
    dsa_frozen=$(echo "$dsa_line" | sed -n 's/.*frozen=\([0-9][0-9]*\) us.*/\1/p')
    dsa_memdump=$(echo "$dsa_line" | sed -n 's/.*memdump=\([0-9][0-9]*\) us.*/\1/p')

    if [[ -z "$base_frozen" || -z "$base_memdump" || -z "$dsa_frozen" || -z "$dsa_memdump" ]]; then
        echo "[ERR] failed to parse timing fields for size=$size" >&2
        exit 1
    fi

    echo "$size,$base_frozen,$dsa_frozen,$base_memdump,$dsa_memdump" >> "$CSV"
    echo "[OK] size=$size base(frozen=$base_frozen, memdump=$base_memdump) dsa(frozen=$dsa_frozen, memdump=$dsa_memdump)"
done

python3 - "$CSV" "$FROZEN_PNG" "$MEMDUMP_PNG" <<'PY'
import csv
import sys
from pathlib import Path

csv_path = Path(sys.argv[1])
frozen_png = Path(sys.argv[2])
memdump_png = Path(sys.argv[3])

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception as e:
    print(f"[ERR] matplotlib unavailable: {e}", file=sys.stderr)
    sys.exit(1)

sizes = []
base_frozen_ms = []
dsa_frozen_ms = []
base_memdump_ms = []
dsa_memdump_ms = []

with csv_path.open(newline="", encoding="utf-8") as f:
    r = csv.DictReader(f)
    for row in r:
        sizes.append(int(row["size_mb"]))
        base_frozen_ms.append(int(row["base_frozen_us"]) / 1000.0)
        dsa_frozen_ms.append(int(row["dsa_frozen_us"]) / 1000.0)
        base_memdump_ms.append(int(row["base_memdump_us"]) / 1000.0)
        dsa_memdump_ms.append(int(row["dsa_memdump_us"]) / 1000.0)

plt.figure(figsize=(9, 5.4))
plt.plot(sizes, base_frozen_ms, marker="o", linewidth=2, label="base")
plt.plot(sizes, dsa_frozen_ms, marker="o", linewidth=2, label="dsa_live")
plt.title("Frozen Time vs Dirty Footprint")
plt.xlabel("Dirty footprint (MB)")
plt.ylabel("Frozen time (ms)")
plt.grid(True, alpha=0.35)
plt.legend()
plt.tight_layout()
plt.savefig(frozen_png, dpi=150)
plt.close()

plt.figure(figsize=(9, 5.4))
plt.plot(sizes, base_memdump_ms, marker="o", linewidth=2, label="base")
plt.plot(sizes, dsa_memdump_ms, marker="o", linewidth=2, label="dsa_live")
plt.title("Memdump Time vs Dirty Footprint")
plt.xlabel("Dirty footprint (MB)")
plt.ylabel("Memdump time (ms)")
plt.grid(True, alpha=0.35)
plt.legend()
plt.tight_layout()
plt.savefig(memdump_png, dpi=150)
plt.close()

print(f"[OK] wrote {frozen_png}")
print(f"[OK] wrote {memdump_png}")
PY

echo "[DONE] csv: $CSV"
echo "[DONE] frozen plot: $FROZEN_PNG"
echo "[DONE] memdump plot: $MEMDUMP_PNG"
