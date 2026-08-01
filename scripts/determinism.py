#!/usr/bin/env python3
"""`--jobs N` must be byte-identical to `--jobs 1`. Gate J2, CLI half.

Runs the shipped binary over a sample list at several job counts, normalizes
away the fields that legitimately vary between two runs of the *same* command
(timestamp, argv, tool version, rules path -- `difftest.py`'s own
`normalize_result_doc`), and compares the results byte for byte against the
single-threaded reference.

    python3 scripts/determinism.py \
        --samples scripts/corpus-bench.txt \
        --capa-cli target/release/capa-x \
        --jobs 1,2,4 --repeat 5

Exit code is nonzero if any sample's output depends on the job count, and the
first differing JSON path is printed. This is deliberately not part of
`difftest.py`: difftest compares capa-x against *Python capa*, and this
compares capa-x against itself, so a failure here means something entirely
different -- a scheduling-dependent result, not a parity gap.

The library-level counterpart, which exercises the same two seams without a
subprocess, is `capa-x/tests/jobs_determinism.rs`.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from difftest import (  # noqa: E402
    normalize_result_doc,
    read_sample_list,
    shellcode_format_flag,
)


def run(capa_cli: Path, rules: Path, sample: Path, jobs: int) -> dict:
    args = [
        str(capa_cli),
        "-r",
        str(rules),
        "-j",
        "--jobs",
        str(jobs),
        *shellcode_format_flag(sample),
        str(sample),
    ]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{sample.name}: capa exited {proc.returncode} at --jobs {jobs}: "
            f"{proc.stderr.strip()[:400]}"
        )
    doc = json.loads(proc.stdout)
    normalize_result_doc(doc)
    return doc


def first_difference(a, b, path: str = "") -> str | None:
    """The first path at which two normalized documents disagree.

    Reported instead of a whole diff because a job-count difference is never
    subtle once located: it is an ordering or a dropped match, and the path
    names which.
    """
    if type(a) is not type(b):
        return f"{path}: {type(a).__name__} vs {type(b).__name__}"
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                return f"{path}.{key}: missing in --jobs 1 output"
            if key not in b:
                return f"{path}.{key}: missing in parallel output"
            found = first_difference(a[key], b[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} entries vs {len(b)}"
        for index, (left, right) in enumerate(zip(a, b)):
            found = first_difference(left, right, f"{path}[{index}]")
            if found:
                return found
        return None
    return None if a == b else f"{path}: {a!r} vs {b!r}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--capa-cli", type=Path, default=Path("target/release/capa-x"))
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    parser.add_argument(
        "--jobs",
        default="1,2,4",
        help="comma-separated job counts to compare against --jobs 1 (default: 1,2,4)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="repetitions per job count; a scheduling-dependent result may need "
        "several runs to show itself (default: 1)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="samples to check concurrently (default: 1). Safe to raise well past "
        "the core count: this gate is about output, not time, and oversubscribing "
        "makes worker completion order *less* predictable, which is the thing "
        "being tested.",
    )
    args = parser.parse_args(argv)

    job_counts = [int(part) for part in args.jobs.split(",") if part.strip()]
    if any(count < 1 for count in job_counts):
        parser.error("job counts must be at least 1")

    samples = read_sample_list(args.samples)

    def check(path: Path) -> tuple[Path, int, list[str]]:
        reference = run(args.capa_cli, args.rules, path, 1)
        reference_text = json.dumps(reference, sort_keys=True)
        compared = 0
        problems: list[str] = []
        for jobs in job_counts:
            for repeat in range(args.repeat):
                doc = run(args.capa_cli, args.rules, path, jobs)
                compared += 1
                if json.dumps(doc, sort_keys=True) == reference_text:
                    continue
                where = first_difference(reference, doc) or "(equal by path walk)"
                problems.append(
                    f"{path.name}: --jobs {jobs} (repeat {repeat}) differs at {where}"
                )
        return path, compared, problems

    failures: list[str] = []
    errors: list[str] = []
    compared = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for future in [pool.submit(check, sample) for sample in samples]:
            try:
                path, ran, problems = future.result()
            except Exception as error:  # a nonzero exit is a failure, not a skip
                errors.append(str(error))
                print(f"ERR  {error}", flush=True)
                continue
            compared += ran
            failures.extend(problems)
            print(f"{'DIFF' if problems else 'ok  '} {path.name}", flush=True)

    print(f"\n{compared} parallel runs compared against --jobs 1 over {len(samples)} samples")
    if errors:
        print(f"{len(errors)} sample(s) could not be analysed:")
        for error in errors:
            print(f"  {error}")
    if failures:
        print(f"{len(failures)} FAILED:")
        for failure in failures:
            print(f"  {failure}")
    if failures or errors:
        return 1
    print("byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
