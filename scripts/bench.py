#!/usr/bin/env python3
"""Macro benchmark: wall time, per-phase time, and peak RSS by job count.

    python3 scripts/bench.py \
        --samples scripts/corpus-bench.txt \
        --capa-cli target/release/capa-x \
        --jobs 1,2,4,default --runs 5 --markdown

Reports each phase separately (rule loading, file loading and recovery,
feature extraction, rule matching, result construction, total) because they
scale differently and only a split can say which one a change moved. Rule
loading in particular is fixed per invocation and serial, so it caps the
end-to-end speedup `--jobs` can ever show -- reading a single "total" column
would attribute that ceiling to the parallel code.

Timings come from the binary's own `--timing`, which measures the phases from
inside the process; the wall time measured here additionally includes process
start-up and output writing, so `total` is always a little under wall.

Peak RSS is the kernel's own number for each child (`os.wait4`), not a sampled
approximation, so it is exact but coarse: it is the high-water mark of the
whole process, and cannot attribute memory to a phase.

`--python <path>` adds pinned Python capa to the table for context. That
comparison is informative, not a gate: the backends do different work.
Gate J3 is the Rust-versus-Rust speedup, which `--jobs 1` anchors.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
from difftest import DEFAULT_SIGS_DIR, read_sample_list, shellcode_format_flag  # noqa: E402

PHASES = ["rules", "load+recovery", "extraction", "matching", "result", "total"]

# `ru_maxrss` is bytes on macOS and kilobytes on Linux. Getting this wrong is
# a 1024x error in a published table, so it is decided once, here.
RSS_TO_MIB = 1 / (1024 * 1024) if sys.platform == "darwin" else 1 / 1024


def measure(args: list[str]) -> tuple[float, float, dict[str, float]]:
    """Runs one command, returning (wall seconds, peak RSS MiB, phase times).

    `os.posix_spawn` plus `os.wait4` rather than `subprocess.run`: rusage for
    *this* child is only available through `wait4`, and `RUSAGE_CHILDREN`
    would report a high-water mark across every child the script has ever
    run -- which, on a benchmark that runs the largest sample somewhere in the
    middle, is a number that quietly stops changing.
    """
    read_fd, write_fd = os.pipe()
    devnull = os.open(os.devnull, os.O_WRONLY)
    started = perf_counter()
    pid = os.posix_spawn(
        args[0],
        args,
        os.environ,
        file_actions=[
            (os.POSIX_SPAWN_DUP2, devnull, 1),
            (os.POSIX_SPAWN_DUP2, write_fd, 2),
        ],
    )
    os.close(write_fd)
    os.close(devnull)
    stderr = b""
    with os.fdopen(read_fd, "rb") as pipe:
        stderr = pipe.read()
    _, status, usage = os.wait4(pid, 0)
    wall = perf_counter() - started
    if status != 0:
        raise RuntimeError(f"{args[0]} exited {status}: {stderr.decode(errors='replace')[:400]}")

    phases: dict[str, float] = {}
    for line in stderr.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "timing":
            phases[parts[1]] = float(parts[2])
    return wall, usage.ru_maxrss * RSS_TO_MIB, phases


def capa_args(capa_cli: Path, rules: Path, sample: Path, jobs: str) -> list[str]:
    args = [str(capa_cli.resolve()), "-r", str(rules), "-j", "--timing"]
    if jobs != "default":
        args += ["--jobs", jobs]
    return args + shellcode_format_flag(sample) + [str(sample)]


def median_of(runs: list[dict], key: str) -> float:
    return statistics.median(run[key] for run in runs if key in run)


def bench_sample(
    capa_cli: Path, rules: Path, sample: Path, jobs: str, runs: int
) -> dict[str, float]:
    # One warm-up so the page cache and the rules directory are hot; a cold
    # first read of 1,000+ rule files would otherwise land in whichever job
    # count happened to go first.
    measure(capa_args(capa_cli, rules, sample, jobs))
    observations = []
    for _ in range(runs):
        wall, rss, phases = measure(capa_args(capa_cli, rules, sample, jobs))
        observations.append({"wall": wall, "rss": rss, **phases})
    result = {key: median_of(observations, key) for key in ["wall", "rss", *PHASES]}
    result["wall_min"] = min(run["wall"] for run in observations)
    result["wall_max"] = max(run["wall"] for run in observations)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, default=Path("scripts/corpus-bench.txt"))
    parser.add_argument("--capa-cli", type=Path, default=Path("target/release/capa-x"))
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument("--jobs", default="1,2,4,default")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument(
        "--python",
        type=Path,
        default=None,
        help="pinned Python capa to include for context (e.g. .venv/bin/capa)",
    )
    parser.add_argument(
        "--sigs",
        type=Path,
        default=DEFAULT_SIGS_DIR,
        help="FLIRT signatures for --python (default: reference/capa/sigs). A "
        "PyPI-installed flare-capa ships no sigs/ directory of its own, so "
        "omitting -s crashes on any PE sample with 'default signature path "
        "doesn't exist' -- this must be passed explicitly, the same way "
        "difftest.py always does.",
    )
    parser.add_argument("--json", type=Path, default=None, help="write raw results here")
    parser.add_argument("--markdown", action="store_true", help="print README-ready tables")
    args = parser.parse_args(argv)

    job_counts = [part.strip() for part in args.jobs.split(",") if part.strip()]
    if "1" not in job_counts:
        parser.error("--jobs must include 1: it is the baseline every speedup is measured against")

    samples = read_sample_list(args.samples)
    results: dict[str, dict[str, dict[str, float]]] = {}

    for sample in samples:
        name = sample.name
        results[name] = {}
        for jobs in job_counts:
            results[name][jobs] = bench_sample(
                args.capa_cli, args.rules, sample, jobs, args.runs
            )
            print(
                f"{name[:44]:<46} jobs={jobs:<8} "
                f"wall={results[name][jobs]['wall']:.3f}s "
                f"rss={results[name][jobs]['rss']:.0f}MiB",
                flush=True,
            )
        if args.python:
            wall = []
            for _ in range(args.runs):
                started = perf_counter()
                measured, _, _ = measure(
                    [
                        str(args.python.resolve()),
                        "-r",
                        str(args.rules),
                        "-s",
                        str(args.sigs),
                        "-j",
                        *shellcode_format_flag(sample),
                        str(sample),
                    ]
                )
                wall.append(measured)
            results[name]["python"] = {"wall": statistics.median(wall)}
            print(f"{name[:44]:<46} python   wall={results[name]['python']['wall']:.3f}s")

    baseline = "1"
    fastest = "default" if "default" in job_counts else job_counts[-1]
    speedups = [
        results[name][baseline]["wall"] / results[name][fastest]["wall"] for name in results
    ]
    slowest = min(speedups)

    print("\n== summary ==")
    print(f"samples: {len(results)}, runs per point: {args.runs}, host cpus: {os.cpu_count()}")
    print(f"median speedup --jobs {fastest} vs --jobs 1: {statistics.median(speedups):.2f}x")
    print(f"worst sample:                                {slowest:.2f}x")
    print(
        "J3 (median >= 1.50x, no sample below 0.91x): "
        f"{'PASS' if statistics.median(speedups) >= 1.5 and slowest >= 0.9091 else 'FAIL'}"
    )

    # The parallel seams are extraction and matching; everything else is
    # serial by design. Reporting the ratio makes the ceiling explicit rather
    # than leaving a reader to infer it from a disappointing total.
    parallelizable = [
        (results[name][baseline]["extraction"] + results[name][baseline]["matching"])
        / results[name][baseline]["total"]
        for name in results
        if results[name][baseline].get("total")
    ]
    if parallelizable:
        print(
            f"share of --jobs 1 time in the parallel seams: "
            f"median {statistics.median(parallelizable) * 100:.1f}%, "
            f"max {max(parallelizable) * 100:.1f}%"
        )

    if args.markdown:
        print("\n| Sample | " + " | ".join(f"--jobs {j}" for j in job_counts) + " | Speedup |")
        print("|---" * (len(job_counts) + 2) + "|")
        for name, by_jobs in results.items():
            cells = " | ".join(f"{by_jobs[j]['wall']:.3f} s" for j in job_counts)
            ratio = by_jobs[baseline]["wall"] / by_jobs[fastest]["wall"]
            print(f"| `{name}` | {cells} | {ratio:.2f}x |")

        print("\n| Phase | " + " | ".join(f"--jobs {j}" for j in job_counts) + " |")
        print("|---" * (len(job_counts) + 1) + "|")
        for phase in PHASES:
            cells = " | ".join(
                f"{sum(results[name][j].get(phase, 0.0) for name in results):.3f} s"
                for j in job_counts
            )
            print(f"| {phase} | {cells} |")

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "host_cpus": os.cpu_count(),
                    "platform": sys.platform,
                    "runs": args.runs,
                    "samples": results,
                },
                indent=1,
            )
        )
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
