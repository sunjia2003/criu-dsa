# Workload Harness

This directory adds an external workload harness for CRIU dump/restore checks.

## Covered Workloads

- redis-ycsb
- mysql-sysbench
- lammps-bd
- verilator-linux

## Quick Start

List workloads:

```bash
test/workloads/run-matrix.sh --list
```

Run a single smoke case:

```bash
test/workloads/run-matrix.sh --workload verilator-linux --mode base --smoke
```

Run a full case (requires root + dependencies):

```bash
sudo test/workloads/run-matrix.sh --workload redis-ycsb --mode dsa_live --profile small --rounds 1
```

Run full matrix:

```bash
sudo test/workloads/run-matrix.sh --workload all --mode all --profile small --rounds 1
```

## Output Layout

Default run root is `/tmp/criu-workloads`.

Per case artifacts:
- `logs/`: workload logs and CRIU logs
- `state/phases.tsv`: phase rc and duration
- `artifacts/manifest.json`: normalized case record

Matrix output:
- `summary.tsv` at run-base root

## MySQL Safety Red Lines

The mysql-sysbench adapter enforces:

- Test instance port must not be `3306` or `33060`
- `datadir`, `socket`, `pid-file`, logs and defaults file must all be under run root
- No broad kill patterns (`pkill mysqld`, `killall mysqld`, `pgrep -f mysql`)
- Shutdown is pidfile + cmdline fingerprint based
- Baseline process/listen snapshots are compared before/after case

## Dependency Notes

Required binaries by workload:

- redis-ycsb: `redis-server`, `redis-cli`, optional `ycsb`
- mysql-sysbench: `mysqld`, `mysql`, `mysqladmin`, `sysbench`
- lammps-bd: `lmp`
- verilator-linux: set `VERILATOR_LINUX_CMD` to your long-running simulation command

Local (non-global) install support:

- `redis-ycsb` will auto-detect YCSB from:
	- `YCSB_BIN_OVERRIDE`
	- `ycsb.sh` / `ycsb` in PATH
	- `$HOME/workspace/ycsb-0.17.0/bin/ycsb.sh`
	- `$HOME/workspace/ycsb-0.17.0/bin/ycsb`
- `lammps-bd` will auto-detect LAMMPS from:
	- `LAMMPS_BIN_OVERRIDE`
	- `$HOME/workspace/lammps/build/lmp`
	- `lmp` in PATH

Verilator Linux real-boot prerequisites (LiteX flow):

- `verilator` binary
- `linux-on-litex-vexriscv` repository and Linux images
- LiteX tooling (`litex_term`/`litex_server`)
- Device tree compiler (`dtc`) or prebuilt `images/rv32.dtb`
- RISC-V toolchain (common setup uses `riscv64-unknown-elf-gcc`)
- Python environment with LiteX dependencies (default auto-detect: `$HOME/workspace/litex-env/bin/python`)

If `VERILATOR_LINUX_CMD` is unset, adapter will try default:

- `$HOME/workspace/linux-on-litex-vexriscv/sim.py`

Verilator adapter optional overrides:

- `VERILATOR_PYTHON`: Python binary used for default `sim.py` flow
- `RISCV_GCC_BIN_DIR`: prepend toolchain bin dir to `PATH` for default flow
- `RISCV_GCC_CMD`: explicit gcc command path when auto-detection fails
- `VERILATOR_OUTPUT_DIR`: LiteX build output dir for default flow (default: `$RUN_ROOT/verilator-build`)
- `VERILATOR_READY_REGEX`: customize ready log regex (default also accepts BIOS boot lines)
- `VERILATOR_SIM_EXTRA_ARGS`: extra args appended to default `sim.py` command (default: `--jobs 2 --threads 1`)
- `VERILATOR_READY_PROGRESS_SEC`: ready-stage progress print interval in seconds (default: `20`)

Headless harness behavior:

- `sim.py` is patched to run headless by default (`interactive=false`) to avoid TTY/termios failures.
- Set `LITEX_SIM_INTERACTIVE=1` only when you intentionally want interactive terminal input.
- If simulation exits before ready, adapter now fails immediately and prints log tail (no long silent wait).

## Troubleshooting

- Case fails at `prepare`: missing dependency or safety guard rejection.
- Case fails at `ready`: check workload logs under run root `logs/`.
- Case fails at `restore`: inspect `logs/restore.log` and `logs/dump.log`.
