#!/usr/bin/env python3
"""Compare two bench_signatures executables in alternating fresh processes.

Usage: python3 scripts/bench_signature_storage.py /tmp/load-main /tmp/load-new
Run zero warms filesystem caches and is excluded from the summary. Each child
waits after loading, so ps samples RSS while its signatures remain live.
Requires a POSIX host with ps and wait4. Output contains all runs and medians.
"""

import json
import os
from pathlib import Path
import statistics
import subprocess
import sys


def measure(binary: Path, jobs: int) -> dict:
    with subprocess.Popen(
        [str(binary.resolve()), str(jobs), "--wait"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as child:
        try:
            line = child.stdout.readline()
            if not line.startswith("load_seconds\t"):
                raise RuntimeError(f"{binary}: {line} {child.stderr.read()}")
            rss = int(subprocess.check_output(
                ["ps", "-o", "rss=", "-p", str(child.pid)], text=True
            )) / 1024
            child.stdin.write("\n")
            child.stdin.flush()
            _, status, usage = os.wait4(child.pid, 0)
            child.returncode = os.waitstatus_to_exitcode(status)
            if child.returncode:
                raise RuntimeError(f"{binary}: {child.stderr.read()}")
            peak_scale = 1024 * 1024 if sys.platform == "darwin" else 1024
            return {
                "load_seconds": float(line.split()[1]),
                "rss_mib": rss,
                "peak_mib": usage.ru_maxrss / peak_scale,
                "cpu_seconds": usage.ru_utime + usage.ru_stime,
            }
        finally:
            if child.returncode is None:
                child.kill()
                child.wait()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: bench_signature_storage.py BEFORE AFTER")
    binaries = {"before": Path(sys.argv[1]), "after": Path(sys.argv[2])}
    runs = []
    for jobs in (1, 4):
        for run in range(6):
            order = ("before", "after") if run % 2 == 0 else ("after", "before")
            for version in order:
                runs.append({
                    "version": version, "jobs": jobs, "run": run,
                    **measure(binaries[version], jobs),
                })
    summaries = []
    for jobs in (1, 4):
        for version in binaries:
            selected = [r for r in runs if r["jobs"] == jobs and r["version"] == version and r["run"]]
            summaries.append({
                "version": version, "jobs": jobs,
                **{key: statistics.median(r[key] for r in selected)
                   for key in ("load_seconds", "rss_mib", "peak_mib", "cpu_seconds")},
            })
    print(json.dumps({"runs": runs, "medians": summaries}, indent=2))


if __name__ == "__main__":
    main()
