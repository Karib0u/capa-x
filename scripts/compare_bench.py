#!/usr/bin/env python3
"""Compare capa-x, Python capa, and capa-rs on one fixed corpus.

Example:

    python3 scripts/compare_bench.py \
        --samples scripts/corpus-bench.txt \
        --capa-rs /tmp/capa-rs/target/release/examples/capa_cli \
        --runs 5

Each successful sample gets one warm-up followed by the requested number of
measured runs. A tool that exits successfully without producing JSON is still
reported as a failed sample. The benchmark is intended for Unix hosts with
the external `/usr/bin/time` utility.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from difftest import read_sample_list  # noqa: E402


def parse_rss(time_path: Path) -> float | None:
    if not time_path.exists():
        return None

    for line in time_path.read_text(errors="replace").splitlines():
        if "maximum resident set size" in line:
            return int(line.split()[0]) / (1024 * 1024)
        if "Maximum resident set size (kbytes)" in line:
            return int(line.rsplit(":", 1)[1].strip()) / 1024
    return None


def time_prefix(time_path: Path) -> list[str]:
    time_bin = Path("/usr/bin/time")
    if not time_bin.exists():
        raise RuntimeError("/usr/bin/time is required for peak RSS measurement")
    if sys.platform == "darwin":
        return [str(time_bin), "-l", "-o", str(time_path)]
    return [str(time_bin), "-v", "-o", str(time_path)]


def kill_process(proc: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
    proc.kill()


def run_once(
    tool: str,
    binary: Path,
    sample: Path,
    rules: Path,
    signatures: Path,
    output_dir: Path,
    run_id: str,
    timeout: int,
) -> dict[str, object]:
    time_path = output_dir / f"{run_id}.time"
    if tool == "capa-rs 0.5.2":
        output_path = output_dir / f"{run_id}.json"
        argv = [
            str(binary),
            "-r",
            str(rules),
            "--signatures",
            str(signatures),
            "-o",
            str(output_path),
            str(sample),
        ]
    elif tool == "Python capa":
        output_path = None
        argv = [
            str(binary),
            "-r",
            str(rules),
            "-s",
            str(signatures),
            "-j",
            str(sample),
        ]
    else:
        output_path = None
        argv = [
            str(binary),
            "-r",
            str(rules),
            "-s",
            str(signatures),
            "-j",
            str(sample),
        ]

    started = time.perf_counter()
    proc = subprocess.Popen(
        [*time_prefix(time_path), *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_process(proc)
        stdout, stderr = proc.communicate()

    result: dict[str, object] = {
        "wall": time.perf_counter() - started,
        "rss": parse_rss(time_path),
        "valid": False,
    }
    if timed_out:
        result["detail"] = "timeout"
        return result
    if proc.returncode != 0:
        result["detail"] = f"exit {proc.returncode}"
        return result

    try:
        if output_path is None:
            json.loads(stdout)
        elif not output_path.exists() or output_path.stat().st_size == 0:
            raise ValueError("no output")
        else:
            json.loads(output_path.read_text())
    except (json.JSONDecodeError, ValueError) as error:
        result["detail"] = str(error)
        if stderr:
            lines = stderr.decode(errors="replace").strip().splitlines()
            if lines:
                result["detail"] += f": {lines[-1][:160]}"
        return result

    result["valid"] = True
    result["detail"] = "ok"
    return result


def sample_median(entry: dict[str, object]) -> float:
    runs = entry["runs"]
    assert isinstance(runs, list)
    return statistics.median(float(run["wall"]) for run in runs)


def successful_entry(entry: dict[str, object]) -> bool:
    runs = entry["runs"]
    return isinstance(runs, list) and bool(runs) and all(run["valid"] for run in runs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, default=Path("scripts/corpus-bench.txt"))
    parser.add_argument("--capa-cli", type=Path, default=Path("target/release/capa-x"))
    parser.add_argument("--python", type=Path, default=Path(".venv/bin/capa"))
    parser.add_argument("--capa-rs", type=Path, required=True)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument("--signatures", type=Path, default=Path("capa-x/sigs"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--json", type=Path, help="write raw results to this path")
    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be positive")
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    for path in (args.samples, args.capa_cli, args.python, args.capa_rs, args.rules, args.signatures):
        if not path.exists():
            parser.error(f"path does not exist: {path}")

    tools = {
        "capa-x": args.capa_cli,
        "Python capa": args.python,
        "capa-rs 0.5.2": args.capa_rs,
    }
    samples = read_sample_list(args.samples)
    results: dict[str, object] = {
        "samples_file": str(args.samples),
        "runs": args.runs,
        "timeout": args.timeout,
        "samples": {},
    }

    with tempfile.TemporaryDirectory(prefix="capa-compare-bench-") as scratch:
        scratch_path = Path(scratch)
        for sample_index, sample in enumerate(samples):
            by_tool: dict[str, object] = {}
            print(f"\n== {sample.name} ==", flush=True)
            for tool, binary in tools.items():
                warmup = run_once(
                    tool,
                    binary,
                    sample,
                    args.rules,
                    args.signatures,
                    scratch_path,
                    f"{sample_index}-warm-{tool.replace(' ', '_')}",
                    args.timeout,
                )
                entry: dict[str, object] = {"warmup": warmup, "runs": []}
                if warmup["valid"]:
                    measured = []
                    for run_index in range(args.runs):
                        measured.append(
                            run_once(
                                tool,
                                binary,
                                sample,
                                args.rules,
                                args.signatures,
                                scratch_path,
                                f"{sample_index}-run-{run_index}-{tool.replace(' ', '_')}",
                                args.timeout,
                            )
                        )
                    entry["runs"] = measured
                by_tool[tool] = entry
                if successful_entry(entry):
                    print(
                        f"{tool}: {sample_median(entry):.3f}s, "
                        f"RSS {max(float(run['rss'] or 0) for run in entry['runs']):.0f} MiB",
                        flush=True,
                    )
                else:
                    failed_runs = [
                        run["detail"] for run in entry["runs"] if not run["valid"]
                    ]
                    detail = failed_runs[0] if failed_runs else warmup["detail"]
                    print(f"{tool}: {detail}", flush=True)
            results["samples"][sample.name] = by_tool

    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
        print(f"\nraw results: {args.json}")

    print("\n| Tool | Valid | Failed | Median successful sample | Successful medians total | Peak RSS (valid) |")
    print("|---|---:|---:|---:|---:|---:|")
    successful_samples: dict[str, set[str]] = {tool: set() for tool in tools}
    for tool in tools:
        entries = [
            by_tool[tool]
            for by_tool in results["samples"].values()
            if successful_entry(by_tool[tool])
        ]
        for sample_name, by_tool in results["samples"].items():
            if successful_entry(by_tool[tool]):
                successful_samples[tool].add(sample_name)
        medians = [sample_median(entry) for entry in entries]
        rss_values = [
            float(run["rss"] or 0)
            for entry in entries
            for run in entry["runs"]
        ]
        failed = len(samples) - len(entries)
        median_text = f"{statistics.median(medians):.3f} s" if medians else "n/a"
        total_text = f"{sum(medians):.2f} s" if medians else "n/a"
        print(
            f"| {tool} | {len(entries)}/{len(samples)} | {failed} | "
            f"{median_text} | {total_text} | "
            f"{max(rss_values, default=0):.0f} MiB |"
        )

    common = set.intersection(*successful_samples.values())
    print(f"\nCommon successful samples: {len(common)}/{len(samples)}")
    if common:
        for tool in tools:
            common_medians = [
                sample_median(results["samples"][sample_name][tool])
                for sample_name in common
            ]
            print(f"{tool}: median {statistics.median(common_medians):.3f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
