#!/usr/bin/env python3
"""Plot empirical TEMP_CDF raw samples from CRIU dump outputs.

The CRIU DSA log points to a raw dirty-extent sample file:

  TEMP_CDF_COUNTS: size=... gap=... ratio_q20=...
  TEMP_CDF_FILE: path=temp-cdf.raw

The raw file contains:

  TEMP_CDF_COUNTS: size=... gap=... ratio_q20=...
  TEMP_CDF_VALUE: metric=size value=...
  TEMP_CDF_VALUE: metric=gap value=...
  TEMP_CDF_VALUE: metric=ratio_q20 value=...

This script sorts the raw samples and plots real empirical CDF curves. It
accepts either individual log files or directories, recursively scanning
directories for dsa-dump.log files that point to TEMP_CDF raw files.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


COUNTS_RE = re.compile(
    r"TEMP_CDF_COUNTS:\s*size=(\d+)\s+gap=(\d+)\s+ratio_q20=(\d+)"
)
FILE_RE = re.compile(r"TEMP_CDF_FILE:\s*path=(\S+)")
VALUE_RE = re.compile(r"TEMP_CDF_VALUE:\s*metric=([a-zA-Z0-9_]+)\s+value=(-?\d+)")
PAGE_SIZE = 4096.0
MAX_GAP_PAGES = 128.0
MAX_LOCALITY_RATIO = 10.0


@dataclass(frozen=True)
class CdfSeries:
    log: Path
    metric: str
    n: int
    values: tuple[float, ...]


@dataclass(frozen=True)
class RawSamples:
    log: Path
    sizes: tuple[float, ...]
    gaps: tuple[float, ...]
    ratios: tuple[float, ...]


def find_logs(paths: Iterable[Path]) -> list[Path]:
    logs: list[Path] = []
    for path in paths:
        if path.is_file():
            logs.append(path)
        elif path.is_dir():
            logs.extend(p for p in path.rglob("dsa-dump.log") if p.is_file())
            logs.extend(p for p in path.rglob("temp-cdf.raw") if p.is_file())
        else:
            print(f"warn: skip missing path: {path}", file=sys.stderr)
    return sorted(set(logs))


def raw_path_from_log(path: Path) -> Path | None:
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        print(f"warn: cannot read {path}: {exc}", file=sys.stderr)
        return None

    match = FILE_RE.search(text)
    if match:
        raw = Path(match.group(1))
        if not raw.is_absolute():
            raw = path.parent / raw
        return raw

    print(f"warn: skip {path}: no TEMP_CDF_FILE", file=sys.stderr)
    return None


def parse_raw_file(path: Path, label_path: Path | None = None) -> RawSamples | None:
    samples: dict[str, list[float]] = {"size": [], "gap": [], "ratio_q20": []}
    counts: dict[str, int] | None = None

    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        print(f"warn: cannot read {path}: {exc}", file=sys.stderr)
        return None

    for line in text.splitlines():
        count_match = COUNTS_RE.search(line)
        if count_match:
            counts = {
                "size": int(count_match.group(1)),
                "gap": int(count_match.group(2)),
                "ratio_q20": int(count_match.group(3)),
            }
            continue

        match = VALUE_RE.search(line)
        if not match:
            continue

        metric = match.group(1)
        if metric not in samples:
            continue
        value = float(match.group(2))
        if metric in ("size", "gap"):
            value /= PAGE_SIZE
        elif metric == "ratio_q20":
            value /= float(1 << 20)
        samples[metric].append(value)

    if counts:
        for metric, n in counts.items():
            if len(samples[metric]) != n:
                print(
                    f"warn: skip {path}: {metric} values={len(samples[metric])} != n={n}",
                    file=sys.stderr,
                )
                samples[metric].clear()

    series_path = label_path if label_path else path
    if not samples["size"]:
        return None
    return RawSamples(
        series_path,
        tuple(samples["size"]),
        tuple(samples["gap"]),
        tuple(samples["ratio_q20"]),
    )


def parse_input(path: Path) -> RawSamples | None:
    if path.name == "temp-cdf.raw":
        return parse_raw_file(path)

    raw = raw_path_from_log(path)
    if not raw:
        return None
    return parse_raw_file(raw, path)


def cdf_series_from_raw(raw_logs: list[RawSamples]) -> list[CdfSeries]:
    series: list[CdfSeries] = []
    for raw in raw_logs:
        metrics = {
            "size": raw.sizes,
            "gap": tuple(min(value, MAX_GAP_PAGES) for value in raw.gaps),
            "ratio_q20": tuple(min(value, MAX_LOCALITY_RATIO) for value in raw.ratios),
        }
        for metric, values in metrics.items():
            if values:
                series.append(CdfSeries(raw.log, metric, len(values), tuple(sorted(values))))
    return series


def short_label(log: Path, root: Path | None) -> str:
    if root:
        try:
            return str(log.relative_to(root))
        except ValueError:
            pass

    parent = log.parent.name
    if parent:
        return f"{parent}/{log.name}"
    return log.name


def write_csv(series: list[CdfSeries], output: Path, root: Path | None) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["log", "metric", "n", "rank", "cdf", "value", "unit"])
        for s in series:
            label = short_label(s.log, root)
            unit = "pages" if s.metric in ("size", "gap") else "ratio"
            for idx, value in enumerate(s.values, start=1):
                writer.writerow([label, s.metric, s.n, idx, idx / s.n, value, unit])


def plot(series: list[CdfSeries], output: Path, root: Path | None) -> None:
    try:
        import matplotlib.pyplot as plt
        from matplotlib.ticker import AutoMinorLocator, MaxNLocator
    except ImportError as exc:
        raise RuntimeError("matplotlib is required for PNG output; CSV was still written") from exc

    plt.rcParams.update({
        "font.size": 20,
        "axes.titlesize": 24,
        "axes.labelsize": 22,
        "xtick.labelsize": 18,
        "ytick.labelsize": 18,
        "legend.fontsize": 14,
    })

    metrics = ("size", "gap", "ratio_q20")
    titles = {
        "size": "Dirty extent size",
        "gap": "Dirty extent gap",
        "ratio_q20": "Locality ratio",
    }
    xlabels = {
        "size": "pages",
        "gap": "pages",
        "ratio_q20": "ratio",
    }

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5), constrained_layout=True)
    for ax, metric in zip(axes, metrics):
        plotted = False
        for s in series:
            if s.metric != metric:
                continue
            xs = list(s.values)
            ys = [(idx + 1) / s.n for idx in range(s.n)]
            ax.plot(xs, ys, drawstyle="steps-post", linewidth=1.6, label=f"{short_label(s.log, root)} (n={s.n})")
            plotted = True

        ax.set_title(titles[metric])
        ax.set_xlabel(xlabels[metric])
        ax.set_ylabel("CDF")
        ax.set_ylim(0, 1.02)
        ax.grid(True, alpha=0.3)
        if metric in ("size", "gap"):
            ax.set_xscale("log", base=2)
            ax.set_xlim(left=1)
        elif metric == "ratio_q20":
            ax.xaxis.set_major_locator(MaxNLocator(nbins=3))
            ax.xaxis.set_minor_locator(AutoMinorLocator(2))
            ax.grid(True, which="minor", alpha=0.18)
        if plotted:
            ax.legend(fontsize=14)
        else:
            ax.text(0.5, 0.5, "no data", ha="center", va="center", transform=ax.transAxes)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)


def extent_positions(raw: RawSamples) -> tuple[list[float], list[float]]:
    starts: list[float] = []
    sizes: list[float] = []
    pos = 0.0

    for idx, size in enumerate(raw.sizes):
        starts.append(pos)
        sizes.append(size)
        pos += size
        if idx < len(raw.gaps):
            pos += raw.gaps[idx]

    return starts, sizes


def plot_extent_map(raw_logs: list[RawSamples], output: Path, root: Path | None) -> None:
    try:
        import matplotlib.pyplot as plt
        from matplotlib.colors import LogNorm
        from matplotlib.collections import LineCollection
    except ImportError as exc:
        raise RuntimeError("matplotlib is required for extent map output") from exc

    plt.rcParams.update({
        "font.size": 18,
        "axes.titlesize": 22,
        "axes.labelsize": 20,
        "xtick.labelsize": 16,
        "ytick.labelsize": 16,
        "legend.fontsize": 12,
    })

    fig, (ax_map, ax_scatter) = plt.subplots(
        2, 1, figsize=(14, 8), constrained_layout=True,
        gridspec_kw={"height_ratios": [1, 2]},
    )

    all_sizes: list[float] = []
    for raw in raw_logs:
        all_sizes.extend(raw.sizes)
    if not all_sizes:
        return

    norm = LogNorm(vmin=max(min(all_sizes), 1.0), vmax=max(all_sizes))
    cmap = plt.get_cmap("viridis")
    yticks: list[float] = []
    ylabels: list[str] = []

    for row, raw in enumerate(raw_logs):
        starts, sizes = extent_positions(raw)
        label = short_label(raw.log, root)
        yticks.append(row + 0.4)
        ylabels.append(label)

        segments = [
            ((start / 256.0, row + 0.4), ((start + size) / 256.0, row + 0.4))
            for start, size in zip(starts, sizes)
        ]
        colors = [cmap(norm(max(size, 1.0))) for size in sizes]
        ax_map.add_collection(
            LineCollection(segments, colors=colors, linewidths=6, rasterized=True)
        )

        ax_scatter.scatter(
            [start / 256.0 for start in starts],
            [size / 256.0 for size in sizes],
            s=10,
            alpha=0.72,
            rasterized=True,
            label=f"{label} (n={len(sizes)})",
        )

    ax_map.set_title("Dirty Extent Address Map")
    ax_map.set_xlabel("relative address offset (MiB)")
    ax_map.set_yticks(yticks)
    ax_map.set_yticklabels(ylabels)
    ax_map.grid(True, axis="x", alpha=0.25)

    ax_scatter.set_title("Dirty Extent Size by Address")
    ax_scatter.set_xlabel("relative address offset (MiB)")
    ax_scatter.set_ylabel("extent size (MiB)")
    ax_scatter.set_yscale("log", base=2)
    ax_scatter.set_ylim(bottom=1 / 256)
    ax_scatter.grid(True, alpha=0.3)
    ax_scatter.legend()

    sm = plt.cm.ScalarMappable(norm=norm, cmap=cmap)
    sm.set_array([])
    fig.colorbar(sm, ax=ax_map, orientation="horizontal", label="extent size (pages)")

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot CRIU DSA TEMP_CDF raw samples from dump logs.")
    parser.add_argument("paths", nargs="+", type=Path, help="dump.log files or directories to scan recursively")
    parser.add_argument("-o", "--output", type=Path, default=Path("temp_cdf.png"), help="output PNG path")
    parser.add_argument("--csv", type=Path, default=None, help="output CSV path, default: PNG path with .csv suffix")
    parser.add_argument("--extent-output", type=Path, default=None, help="extent distribution PNG path, default: OUTPUT with _extents suffix")
    parser.add_argument("--no-extent-output", action="store_true", help="skip extent distribution PNG output")
    parser.add_argument("--label-root", type=Path, default=None, help="make legend labels relative to this directory")
    args = parser.parse_args()

    logs = find_logs(args.paths)
    raw_logs: list[RawSamples] = []
    for log in logs:
        raw = parse_input(log)
        if raw:
            raw_logs.append(raw)

    series = cdf_series_from_raw(raw_logs)

    if not series:
        print("error: no valid TEMP_CDF raw data found", file=sys.stderr)
        return 1

    csv_path = args.csv if args.csv else args.output.with_suffix(".csv")
    extent_path = args.extent_output
    if extent_path is None:
        extent_path = args.output.with_name(f"{args.output.stem}_extents{args.output.suffix}")
    root = args.label_root.resolve() if args.label_root else None

    write_csv(series, csv_path, root)
    try:
        plot(series, args.output, root)
        if not args.no_extent_output:
            plot_extent_map(raw_logs, extent_path, root)
    except RuntimeError as exc:
        print(f"warn: {exc}", file=sys.stderr)
        print(f"wrote CSV: {csv_path}")
        return 2

    print(f"wrote plot: {args.output}")
    if not args.no_extent_output:
        print(f"wrote extent plot: {extent_path}")
    print(f"wrote CSV:  {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
