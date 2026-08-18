#!/usr/bin/env python3
"""
Difftest harness: compare capa-x's output against the pinned Python capa
reference, on the same corpus.

The freeze-driven modes share the same cache: for each sample in the given list file,
use the pinned .venv capa (reference/capa, see PINNED.md) to generate a capa
freeze file (capa.features.freeze.dump) and a `capa -f freeze -j` result
JSON, cached under --cache-dir keyed by the sample's sha256, so re-runs
(and CI) only pay the vivisect/dotnet/etc. analysis cost once per sample.

capa-x's side is cached symmetrically, under `<cache-dir>/rust/`, keyed by
the contents of the sample, the capa-x-cli binary and the rule set (see
`cached_rust_output`) -- so re-running a corpus with an unchanged binary is
near-instant, and a rebuild only invalidates what actually changed. Pass
--no-rust-cache to force live capa-x-cli runs.

--mode json (default): run `capa-x-cli --rules <rules> -f freeze -j
  <freeze file>` and structurally diff the full result document against the
  Python reference's, after normalizing fields that are expected to differ
  (tool version/argv, timestamps, rules-path -- see `normalize_result_doc`).
  This exercises the whole result-document schema, not just which (rule, address)
  pairs matched.

--mode freeze: run `capa-x-cli --rules <rules> --dump-matches <freeze
  file>` and compare only the set of (rule name, matched address) pairs.
  The narrowest mode; --mode json is a superset of it, and the default.

--mode file-features: for a raw PE/ELF sample (not a freeze file),
  compare (a) the raw extracted global+file feature set, via `capa-x-cli
  --dump-features <sample>` vs `scripts/dump_file_features.py --mode
  dump-features <sample>` (the latter runs the pinned Python capa's
  *file-only* extractors -- `PefileFeatureExtractor`/`ElfFeatureExtractor`,
  same ones `tests/fixtures.py` uses -- not the full vivisect backend,
  which is not what the file-scope extractors port), and (b) the full
  result document, the same
  way --mode json does, except the Python reference comes from
  `dump_file_features.py --mode dump-freeze` (the file-only extractor's
  freeze dump, re-analyzed via `capa -f freeze -j` same as every other
  mode's reference) while capa-x is invoked directly on the raw sample
  (`capa-x-cli -j <sample>`, exercising the file-scope extractors end-to-end,
  not freeze-driven).

--mode full: the real acceptance gate -- both
  sides run their own complete extraction pipeline against the *original*
  sample, not a shared freeze file. The Python reference is the pinned
  capa's direct vivisect-based analysis, cached separately from the
  freeze-driven reference because freezes do not preserve FLIRT library
  markings and would therefore change which functions capa skips.
  capa-x runs `--dump-matches` directly on the raw sample (auto-detected
  PE/ELF; exercises recovery/FLIRT/insn/bb/function extraction, not
  freeze-driven). Compares the *set of rule names matched* per sample
  (the bar being "an identical matched-rule set"), not per-address/location
  detail -- most
  real diffs here trace to *function-boundary* choices (vivisect's
  emulation-assisted sweep vs this crate's recursive-descent + seeds),
  which can legitimately shift a match's *address* even when the
  capability itself is still detected somewhere in the sample; the
  freeze-difftest already guards match-engine correctness (address-exact)
  on a shared, fixed feature set, so this mode isolates extraction-driven
  differences at the granularity that actually matters.

--mode binding: the Python binding
  (capa-x-python/), not the CLI, is under test. Runs `capa_x.analyze()`
  on the raw sample via `scripts/binding_analyze.py` (under the pinned
  `.venv`, which needs the binding installed into it: `pip install
  ./capa-x-python` or `maturin develop --release` from that venv), validates
  the returned document against pinned capa's own `ResultDocument.
  model_validate_json`, and compares the binding's matched rule names
  against the CLI's own (`capa-x-cli --dump-matches <sample>`, the same
  full-pipeline invocation and cache entry `--mode full`'s v2-static
  profile already produces) -- same bytes, same ruleset, same options on
  both sides. Only wired for --profile v2-static.

Exits 1 (after printing every diff) if any sample disagrees -- unless the
corpus list has a recorded per-sample baseline (`<list>.expected.json`, see
`check_expected`), in which case the exit status reports *regressions* against
that baseline instead: a sample that was identical and now differs, or that
diverges by more rules than it did. That is the point of the mid loop -- a
corpus where 8 samples are known to differ still needs to fail the moment a
9th one does, and a headline score cannot say that.

--profile: which backend/reference pairing to run, orthogonal to --mode.
  v2-static (default) is everything above, unchanged. The others only wire
  --mode full, since they don't share a single freeze file across both
  sides the way v2-static's freeze/json modes need to:
    dotnet: `.venv/bin/capa -f dotnet -j <sample>` vs `capa -f dotnet -j
      <sample>` over scripts/corpus-dotnet.txt. The "backend not implemented"
      early-exit above
      still guards any future capa-x-cli build that predates it.
    aarch64-binexport: `.venv/bin/capa -f binexport2 -j <.BinExport>` vs
      `capa -j <raw .elf_>` over the pinned pairs in
      scripts/corpus-aarch64.txt (sha256-checked so a testfiles bump can't
      silently pair unrelated files). The profile reports a contextual error
      when the AArch64 backend is unavailable, rather than a diff,
      which is an expected pre-backend state, not a harness bug.
    macho-fixture: reference is a captured structure oracle, not live
      Python capa (upstream has no raw Mach-O support). Reports "no
      samples" and exits 0 until the fixture corpus exists.

usage:
  scripts/difftest.py --samples scripts/corpus-freeze.txt
  scripts/difftest.py --mode freeze --samples scripts/corpus-freeze.txt --only <substring>
  scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
      --capa-cli target/release/capa-x --jobs 6           # guarded by the baseline
  scripts/difftest.py --mode full --samples scripts/corpus-smoke.txt \
      --capa-cli target/release/capa-x --jobs 6 --write-expected   # re-record it
  scripts/difftest.py --profile aarch64-binexport --mode full \
      --capa-cli target/release/capa-x --no-expected
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import contextlib
import dataclasses
import gc
import hashlib
import io
import json
import logging
import multiprocessing
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"
DEFAULT_SIGS_DIR = REPO_ROOT / "reference" / "capa" / "sigs"
DEFAULT_SAMPLES_ROOT = REPO_ROOT / "tests" / "testfiles"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "difftest"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python3"

_USE_IN_PROCESS_REFERENCE = False
_REFERENCE_MATCHERS: dict[str, object] = {}


def initialize_worker() -> None:
    """Reuse compiled Python FLIRT matchers for every sample in this worker."""
    global _USE_IN_PROCESS_REFERENCE

    import flirt
    import viv_utils.flirt

    def register_cached_flirt_analyzers(vw: object, sigpaths: list[str]) -> None:
        for sigpath in sigpaths:
            matcher = _REFERENCE_MATCHERS.get(sigpath)
            if matcher is None:
                signatures = viv_utils.flirt.load_flirt_signature(sigpath)
                matcher = flirt.compile(signatures)
                _REFERENCE_MATCHERS[sigpath] = matcher
            analyzer = viv_utils.flirt.FlirtFunctionAnalyzer(matcher, sigpath)
            viv_utils.flirt.addFlirtFunctionAnalyzer(vw, analyzer)

    viv_utils.flirt.register_flirt_signature_analyzers = register_cached_flirt_analyzers
    _USE_IN_PROCESS_REFERENCE = True


def shellcode_format_flag(sample: Path) -> list[str]:
    """
    `-f sc32`/`sc64` samples have no PE/ELF magic bytes to auto-detect
    from, so both sides need to be told the format explicitly. This repo's
    shellcode corpus follows `tests/fixtures.py::get_viv_extractor`'s
    "raw32"/"raw64" filename substring convention (there's no `.sc32`/`.sc64`
    file suffix upstream -- that's the format *name*, not a filename
    convention). Every other sample auto-detects, so this returns `[]`.
    """
    if "raw32" in sample.name:
        return ["-f", "sc32"]
    if "raw64" in sample.name:
        return ["-f", "sc64"]
    return []


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_FINGERPRINTS: dict[str, str] = {}


def file_fingerprint(path: Path) -> str:
    """sha256 of a file, memoized per worker process (the capa-x-cli binary is
    ~23 MB and every sample would otherwise re-hash it)."""
    key = f"file:{path}"
    fp = _FINGERPRINTS.get(key)
    if fp is None:
        fp = sha256_of(path)
        _FINGERPRINTS[key] = fp
    return fp


def rules_fingerprint(rules_dir: Path) -> str:
    """
    Content digest of the rule set capa-x was invoked with -- part of the
    cache key because a rules change legitimately changes which rules match,
    and `rules/` being a pinned submodule doesn't stop a local checkout from
    moving. Hashes relative paths as well as bytes so an added, removed or
    renamed rule invalidates too. ~840 KB across ~1045 files, so this costs
    well under a second, once per worker process.
    """
    key = f"rules:{rules_dir}"
    fp = _FINGERPRINTS.get(key)
    if fp is None:
        h = hashlib.sha256()
        for path in sorted(rules_dir.rglob("*.yml")):
            h.update(str(path.relative_to(rules_dir)).encode())
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
        fp = h.hexdigest()
        _FINGERPRINTS[key] = fp
    return fp


def cached_rust_output(
    kind: str,
    input_path: Path,
    capa_cli: Path,
    rules_dir: Path,
    extra_args: list[str],
    rust_cache: Path | None,
    produce,
) -> str:
    """
    The symmetric twin of `ensure_cached`/`ensure_full_cached`: those cache the
    *Python* reference's per-sample output by sample sha256, which is why a
    corpus re-run only pays vivisect's cost once -- but capa-x's side was
    re-run every time, so an unchanged binary still cost the full corpus
    wall-clock (minutes to hours in `full` mode).

    Keyed by everything that can change the output: the input file's contents
    (raw sample or freeze file), the capa-x-cli binary's contents (so any
    rebuild that actually changes the binary invalidates, and only that), the
    rule set's contents, and the exact invocation (`kind` plus any extra CLI
    flags, e.g. `-f sc32`). Entries for superseded binaries are left in place
    rather than pruned; `.cache/` is disposable.

    `kind` deliberately names the *invocation*, not the difftest `--mode`, so
    `full` and `full-exact` -- which run capa-x-cli identically and differ only
    in how this harness compares the result -- share one cache entry.

    `rust_cache=None` (`--no-rust-cache`) bypasses this entirely; it's the way
    to confirm a suspicious cached result against a live run.
    """
    if rust_cache is None:
        return produce()

    h = hashlib.sha256()
    for part in (
        kind,
        file_fingerprint(input_path),
        file_fingerprint(capa_cli),
        rules_fingerprint(rules_dir),
        " ".join(extra_args),
    ):
        h.update(part.encode())
        h.update(b"\0")

    out_path = rust_cache / f"{h.hexdigest()}.{kind}.out"
    if out_path.exists():
        return out_path.read_text()

    output = produce()
    rust_cache.mkdir(parents=True, exist_ok=True)
    # write-then-rename: two workers may produce the same key concurrently,
    # and a truncated cache entry would be indistinguishable from a real
    # (empty) result on the next run.
    tmp_path = out_path.with_suffix(f".out.{os.getpid()}.tmp")
    tmp_path.write_text(output)
    tmp_path.replace(out_path)
    return output


def read_sample_list(path: Path) -> list[Path]:
    samples = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        p = Path(line)
        if not p.is_absolute():
            p = DEFAULT_SAMPLES_ROOT / line
        samples.append(p)
    return samples


def _resolve(rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else DEFAULT_SAMPLES_ROOT / rel


def read_paired_sample_list(path: Path) -> list[tuple[Path, Path]]:
    """
    `--profile aarch64-binexport`'s corpus format: four whitespace-separated
    columns per row -- `<elf> <binexport> <elf sha256> <binexport sha256>`
    (see `scripts/corpus-aarch64.txt`). The recorded hashes are checked
    against the files on disk so a `tests/testfiles` submodule bump can't
    silently pair one sample's ELF with a stale or unrelated BinExport file.
    """
    pairs: list[tuple[Path, Path]] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 4:
            raise ValueError(f"{path}:{lineno}: expected 4 columns (elf binexport elf-sha256 binexport-sha256), got {len(parts)}")
        elf_rel, be2_rel, elf_sha, be2_sha = parts
        elf_path, be2_path = _resolve(elf_rel), _resolve(be2_rel)
        for p, expected in ((elf_path, elf_sha), (be2_path, be2_sha)):
            if not p.exists():
                raise ValueError(f"{path}:{lineno}: {p} does not exist")
            actual = sha256_of(p)
            if actual != expected:
                raise ValueError(
                    f"{path}:{lineno}: {p} sha256 is {actual}, expected {expected} -- "
                    "the testfiles pin moved out from under this pairing; re-verify and update the hash"
                )
        pairs.append((elf_path, be2_path))
    return pairs


@dataclasses.dataclass(frozen=True)
class Profile:
    """
    A difftest backend profile: which reference/rust invocation produces each
    side's output for a corpus, orthogonal to `--mode`
    (the backend profile definition).

    `reference_format`/`rust_format` are `-f` values (`None` for auto-detect).
    Only `--mode full` is wired for a non-`v2-static` profile: the freeze-driven
    modes (`json`/`freeze`/`file-features`) assume a single shared freeze file
    both sides can be driven from, which does not hold once the reference and
    rust sides read *different* input files (raw ELF vs. BinExport2) or a
    format neither side's freeze plumbing has ever carried (dotnet, Mach-O).
    """

    name: str
    reference_format: str | None = None
    rust_format: str | None = None
    paired: bool = False
    default_samples: Path | None = None


PROFILES: dict[str, Profile] = {
    "v2-static": Profile("v2-static"),
    "dotnet": Profile(
        "dotnet",
        reference_format="dotnet",
        rust_format="dotnet",
        default_samples=REPO_ROOT / "scripts" / "corpus-dotnet.txt",
    ),
    "aarch64-binexport": Profile(
        "aarch64-binexport",
        reference_format="binexport2",
        paired=True,
        default_samples=REPO_ROOT / "scripts" / "corpus-aarch64.txt",
    ),
    "macho-fixture": Profile(
        "macho-fixture",
        default_samples=REPO_ROOT / "scripts" / "corpus-macho.txt",
    ),
}


@dataclasses.dataclass(frozen=True)
class WorkItem:
    """One corpus row to diff: `display` is what shows up in reports/output;
    `reference_input`/`rust_input` are usually the same path (`display`) but
    diverge for a paired profile, where the reference reads a BinExport2 file
    and capa-x reads the raw ELF it was exported from."""

    display: Path
    reference_input: Path
    rust_input: Path


def read_work_items(profile: Profile, path: Path) -> list[WorkItem]:
    if profile.paired:
        return [WorkItem(display=elf, reference_input=be2, rust_input=elf) for elf, be2 in read_paired_sample_list(path)]
    return [WorkItem(display=s, reference_input=s, rust_input=s) for s in read_sample_list(path)]


def capa_cli_supports_format(capa_cli: Path, fmt: str) -> bool:
    """
    Whether this capa-x-cli build accepts `-f <fmt>` -- probed from `-h`'s
    clap-generated `[possible values: ...]` line rather than hardcoding a
    version check, so this starts reporting `True` the moment a phase (e.g.
    `-f dotnet`) actually lands the flag, with no further change
    here. Uses short `-h`, not long `--help`: clap renders the choice list on
    one line only in the short form once any value (e.g. `macho`) carries its
    own doc comment -- long `--help` then breaks one choice per line and this
    regex stops matching, silently reporting every such format unsupported.
    """
    proc = subprocess.run([str(capa_cli), "-h"], capture_output=True, text=True)
    match = re.search(r"--format.*?\[possible values: ([^\]]+)\]", proc.stdout, re.DOTALL)
    if not match:
        return False
    choices = {v.strip() for v in match.group(1).split(",")}
    return fmt in choices


_FREEZE_DUMP_SCRIPT = "import sys; import capa.features.freeze as frz; sys.exit(frz.main(sys.argv[1:]))"


def generate_freeze(sample: Path, out_path: Path, sigs_dir: Path) -> None:
    """
    shell out to the pinned .venv's Python to run
    `capa.features.freeze.main`, which is capa's own freeze-dump CLI
    (capa/features/freeze/__init__.py) -- it just isn't registered as a
    `python -m`-runnable entry point upstream, so we invoke it via `-c`,
    forwarding argv rather than interpolating paths into the script text.
    """
    if _USE_IN_PROCESS_REFERENCE:
        import capa.features.freeze as freeze

        status = freeze.main(["-s", str(sigs_dir), str(sample), str(out_path)])
        if status != 0:
            raise RuntimeError(f"freeze generation failed for {sample} with exit status {status}")
        gc.collect()
        return

    subprocess.run(
        [str(VENV_PYTHON), "-c", _FREEZE_DUMP_SCRIPT, "-s", str(sigs_dir), str(sample), str(out_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def generate_json(freeze_path: Path, out_path: Path, rules_dir: Path) -> None:
    """
    Deliberately re-analyzes the *freeze file*, not the original sample.

    Both sides are freeze-driven here, with no binary analysis involved at
    all, so the only thing under test here is matching-engine correctness on a fixed, shared
    feature set. Running the reference capa against the *original sample*
    instead would also exercise vivisect's `is_library_function` (FLIRT
    signature matching), which skips matching inside recognized
    statically-linked library functions -- information that doesn't exist
    in the freeze format at all (`FunctionFeatures` has no such field) and
    that a `NullStaticFeatureExtractor` (which is what both `capa -f freeze`
    and capa-x effectively read) always reports as `False`. Diffing
    against direct-sample analysis produces false-positive diffs: capa-x
    correctly matches inside those functions because the frozen data gives
    it no way to know they're library code, and neither does a freeze-based
    Python re-analysis (confirmed empirically: `capa -f freeze -j <frz>`
    reports the exact same extra matches capa-x does).
    """
    capa_bin = REPO_ROOT / ".venv" / "bin" / "capa"
    proc = subprocess.run(
        [str(capa_bin), "-r", str(rules_dir), "-f", "freeze", "-j", str(freeze_path)],
        capture_output=True,
        text=True,
    )
    # capa exits nonzero (but still emits valid JSON on stdout) for file
    # limitation warnings (e.g. packed samples) -- only a missing/empty
    # stdout is a real failure.
    if not proc.stdout.strip():
        raise RuntimeError(f"capa produced no output for {freeze_path}:\n{proc.stderr}")
    out_path.write_text(proc.stdout)


def ensure_cached(sample: Path, cache_dir: Path, rules_dir: Path, sigs_dir: Path) -> tuple[Path, Path]:
    digest = sha256_of(sample)
    frz_path = cache_dir / f"{digest}.frz"
    json_path = cache_dir / f"{digest}.json"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if not frz_path.exists():
        generate_freeze(sample, frz_path, sigs_dir)
    if not json_path.exists():
        generate_json(frz_path, json_path, rules_dir)

    return frz_path, json_path


def ensure_full_cached(
    sample: Path,
    cache_dir: Path,
    rules_dir: Path,
    sigs_dir: Path,
    *,
    extra_args: list[str] | None = None,
    cache_suffix: str = "",
    env_overrides: dict[str, str] | None = None,
) -> Path:
    """
    Cache pinned capa's direct raw-sample result for --mode full.

    `extra_args`/`cache_suffix` are how a difftest `Profile` other than
    `v2-static` drives this (e.g. `-f dotnet`) without disturbing the
    existing `{digest}.full.json` cache filename or invocation for the
    default profile -- every existing call site (and the on-disk cache it
    already paid for) is byte-for-byte unaffected by these defaults.

    `env_overrides` is `aarch64-binexport`'s way to set `CAPA_SAMPLES_DIR`:
    `get_sample_from_binexport2` (`capa/features/extractors/binexport2/
    __init__.py`) looks for the raw sample next to the `.BinExport` file
    first, then in that env var's directory -- and the pinned pairs live in
    two different `tests/testfiles/` subdirectories, so the first search
    always misses.
    """
    digest = sha256_of(sample)
    suffix = f".{cache_suffix}" if cache_suffix else ""
    json_path = cache_dir / f"{digest}{suffix}.full.json"
    cache_dir.mkdir(parents=True, exist_ok=True)
    if json_path.exists():
        return json_path

    format_args = (extra_args or []) + shellcode_format_flag(sample)
    if _USE_IN_PROCESS_REFERENCE:
        import capa.main

        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close()
        logging.getLogger("capa.capabilities.common").disabled = True
        stdout = io.StringIO()
        prior_env = {k: os.environ.get(k) for k in (env_overrides or {})}
        os.environ.update(env_overrides or {})
        try:
            with contextlib.redirect_stdout(stdout):
                status = capa.main.main(
                    ["-q", "-r", str(rules_dir), "-s", str(sigs_dir), *format_args, "-j", str(sample)]
                )
        finally:
            for k, v in prior_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close()
        output = stdout.getvalue()
        if not output.strip():
            raise RuntimeError(
                f"direct capa analysis failed for {sample} with exit status {status}"
            )
        json.loads(output)
        json_path.write_text(output)
        gc.collect()
        return json_path

    proc = subprocess.run(
        [
            str(REPO_ROOT / ".venv" / "bin" / "capa"),
            "-r",
            str(rules_dir),
            "-s",
            str(sigs_dir),
            *format_args,
            "-j",
            str(sample),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, **env_overrides} if env_overrides else None,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"direct capa analysis failed for {sample}:\n{proc.stderr}")
    json.loads(proc.stdout)
    json_path.write_text(proc.stdout)
    return json_path


def canonical_address(addr: dict) -> str:
    """
    mirrors capa_x::address::Address::canonical_key: "<type>:<value>",
    comma-joining tuple values, using the freeze wire format's own `type`
    tag names -- so this needs no knowledge of capa-x's Rust types, only
    of `capa -j`'s address JSON shape (frz.Address, `capa/features/freeze/
    __init__.py`), which is `{"type": ..., "value": ...}` with `value`
    omitted entirely when null (result_document.py renders with
    `exclude_none=True`).
    """
    t = addr["type"]
    v = addr.get("value")
    if v is None:
        return t
    if isinstance(v, list):
        return f"{t}:{','.join(str(x) for x in v)}"
    return f"{t}:{v}"


def python_matches(json_path: Path) -> dict[str, set[str]]:
    doc = json.loads(json_path.read_text())
    out: dict[str, set[str]] = {}
    for name, rule in doc.get("rules", {}).items():
        out[name] = {canonical_address(m[0]) for m in rule["matches"]}
    return out


def rust_matches(
    capa_cli: Path,
    rules_dir: Path,
    freeze_path: Path,
    extra_args: list[str] | None = None,
    rust_cache: Path | None = None,
    cache_kind: str = "dump-matches",
) -> dict[str, set[str]]:
    """`cache_kind` lets a non-`v2-static` `Profile` namespace its cache
    entries (e.g. `"dump-matches-dotnet"`) separately from the default
    profile's, without changing the default's own cache key."""
    extra_args = extra_args or []

    def produce() -> str:
        proc = subprocess.run(
            [str(capa_cli), "--rules", str(rules_dir), *extra_args, "--dump-matches", str(freeze_path)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"capa-x-cli failed on {freeze_path}:\n{proc.stderr}")
        return proc.stdout

    stdout = cached_rust_output(
        cache_kind, freeze_path, capa_cli, rules_dir, extra_args, rust_cache, produce
    )

    out: dict[str, set[str]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        name, addr = line.rsplit("@", 1)
        out.setdefault(name, set()).add(addr)
    return out


def diff_freeze_sample(
    sample: Path,
    capa_cli: Path,
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
    rust_cache: Path | None,
) -> list[str]:
    frz_path, json_path = ensure_cached(sample, cache_dir, rules_dir, sigs_dir)

    py = python_matches(json_path)
    rs = rust_matches(capa_cli, rules_dir, frz_path, rust_cache=rust_cache)

    problems = []
    for name in sorted(set(py) | set(rs)):
        p, r = py.get(name, set()), rs.get(name, set())
        if p != r:
            missing = sorted(p - r)
            extra = sorted(r - p)
            detail = []
            if missing:
                detail.append(f"missing in capa-x: {missing[:8]}{' ...' if len(missing) > 8 else ''}")
            if extra:
                detail.append(f"extra in capa-x: {extra[:8]}{' ...' if len(extra) > 8 else ''}")
            problems.append(f"  rule {name!r}: " + "; ".join(detail))
    return problems


def rust_json(capa_cli: Path, rules_dir: Path, freeze_path: Path, rust_cache: Path | None = None) -> dict:
    """
    run `capa-x-cli -r <rules> -f freeze -j <freeze_path>` and parse its
    stdout as JSON -- the result-document counterpart to `rust_matches`.
    """

    def produce() -> str:
        proc = subprocess.run(
            [str(capa_cli), "--rules", str(rules_dir), "-f", "freeze", "-j", str(freeze_path)],
            capture_output=True,
            text=True,
        )
        if not proc.stdout.strip():
            raise RuntimeError(
                f"capa-x-cli produced no output for {freeze_path} (exit {proc.returncode}):\n{proc.stderr}"
            )
        return proc.stdout

    stdout = cached_rust_output("freeze-json", freeze_path, capa_cli, rules_dir, [], rust_cache, produce)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"capa-x-cli did not produce valid JSON for {freeze_path}: {e}\n{stdout[:2000]}") from e


def normalize_result_doc(doc: dict) -> None:
    """
    strip the fields that are expected to differ between the pinned Python
    capa and capa-x (tool identity/invocation, wall-clock time, and the
    exact `-r` path string each side was invoked with), and de-duplicate
    exact-duplicate match entries, so the remaining structural diff is
    meaningful. Mutates `doc` in place.

    The dedup step works around a quirk in production capa's default
    matcher: `RuleSet.match()` calls the feature-indexed `_match()`
    optimizer (`paranoid=False`), not the simple `capa.engine.match()` that
    `_match` is validated against -- and that validation (`RuleSet.match`'s
    `paranoid=True` path) only asserts the *feature sets* and *matched rule
    name sets* agree, never that each rule's match *list* (count/order) is
    identical. Confirmed empirically: some rules end up with byte-identical
    duplicate `(address, match tree)` entries in the reference output
    (e.g. a FILE-scope rule matched twice at the same `NO_ADDRESS`, from a
    single `ruleset.match(Scope.FILE, ...)` call). capa-x ports the
    simple, always-correct matcher (the optimized indexed matcher is
    deliberately not ported), so it never produces
    these duplicates -- dedup both sides so this doesn't look like a
    missing-match bug.
    """
    meta = doc.get("meta", {})
    for key in ("timestamp", "version", "argv"):
        meta.pop(key, None)
    analysis = meta.get("analysis", {})
    analysis.pop("rules", None)

    for rule in doc.get("rules", {}).values():
        matches = rule.get("matches", [])
        seen = set()
        deduped = []
        for entry in matches:
            key = json.dumps(entry, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        rule["matches"] = deduped


_SYNTHETIC_SUFFIX_RE = re.compile(r"/([0-9a-f]{32}|[0-9]+)$")


def _strip_synthetic_suffixes(s: str) -> str:
    """
    a `match:` feature's value naming a synthetic subscope rule, e.g.
    `"execute syscall/6e88cc0b177f495aad6690a6e11db131"`, or -- when a
    subscope itself contains a nested subscope -- two levels deep, e.g.
    `"allocate or change RWX memory/c0bcbfbb.../a05e2ea3..."`
    (`capa.rules.RuleSet._extract_subscope_rules_rec` names these with a
    random `uuid4().hex` suffix per level; capa-x's port uses a
    deterministic per-parent counter instead -- see `capabilities::
    ruleset::extract_single_child`). Strips every trailing synthetic
    segment (hex uuid or decimal counter) so only the meaningful
    `<parent-name>` prefix remains comparable; the suffixes are arbitrary
    on *both* sides (even two runs of the pinned Python capa would
    disagree, since the reference does nothing to make them reproducible).
    """
    while True:
        stripped = _SYNTHETIC_SUFFIX_RE.sub("", s)
        if stripped == s:
            return s
        s = stripped


def _is_synthetic_subscope_ref(s) -> bool:
    return isinstance(s, str) and "/" in s


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True)


def _children_match_as_multiset(a: list, b: list) -> bool:
    return collections.Counter(map(_canon, a)) == collections.Counter(map(_canon, b))


def diff_value(a, b, path: str, problems: list[str], key: str | None = None, limit: int = 40) -> None:
    if len(problems) >= limit:
        return

    # `Match.from_capa` only rewrites a successful `match:` reference to a
    # subscope rule into a `subscope` statement; on a *failed* match the raw
    # `MatchFeature` (and its randomly-suffixed synthetic name) leaks
    # through unchanged. Compare only the `<parent-name>/` prefix for this
    # one field.
    if key == "match" and _is_synthetic_subscope_ref(a) and _is_synthetic_subscope_ref(b):
        pa, pb = _strip_synthetic_suffixes(a), _strip_synthetic_suffixes(b)
        if pa != pb:
            problems.append(f"  {path}: {a!r} (python) vs {b!r} (rust) -- differs beyond the synthetic suffix")
        return

    # `Match.from_capa` renders `result.locations` -- a Python `set()` --
    # via `list(...)` with no sorting, so its order is CPython's
    # arbitrary-but-deterministic-per-run hash-bucket order, not a
    # meaningful ordering. Compare as a multiset instead of positionally.
    if key == "locations" and isinstance(a, list) and isinstance(b, list):
        if not _children_match_as_multiset(a, b):
            problems.append(f"  {path}: location sets differ: {a} (python) vs {b} (rust)")
        return

    if type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        problems.append(f"  {path}: type mismatch: {type(a).__name__}={a!r} vs {type(b).__name__}={b!r}")
        return
    if isinstance(a, dict):
        ak, bk = set(a.keys()), set(b.keys())
        for k in sorted(ak - bk):
            problems.append(f"  {path}.{k}: present in capa (python) only: {a[k]!r}")
        for k in sorted(bk - ak):
            problems.append(f"  {path}.{k}: present in capa-x only: {b[k]!r}")
        for k in sorted(ak & bk):
            # `Match.captures`' values are also location lists sourced from
            # a Python `set()` (`_MatchedSubstring`/`_MatchedRegex.matches:
            # dict[str, set[Address]]`) -- same non-ordering as top-level
            # `locations`, so compare as a multiset instead of recursing
            # positionally.
            if key == "captures":
                if not _children_match_as_multiset(a[k], b[k]):
                    problems.append(f"  {path}.{k}: capture location sets differ: {a[k]} (python) vs {b[k]} (rust)")
            else:
                diff_value(a[k], b[k], f"{path}.{k}", problems, key=k, limit=limit)
    elif isinstance(a, list):
        if len(a) != len(b):
            if key == "children" and _children_match_as_multiset(a, b):
                return
            problems.append(f"  {path}: length mismatch: {len(a)} (python) vs {len(b)} (rust)")
            return
        if key == "children":
            # `Match.from_capa`'s namespace-match splicing
            # (`ns_rules = rules.rules_by_namespace[ns_name]`) iterates rules
            # in the order the reference `RuleSet` happened to end up with,
            # which traces back to `os.walk()`'s filesystem-native (not
            # sorted, not portable) directory-entry order -- so which
            # namespace member's subtree appears first among a `match:
            # <namespace>`'s spliced children isn't a meaningful ordering to
            # begin with. Positional compare first (cheap, and correct for
            # every ordinary And/Or/Some, whose child order *is* meaningful
            # and which capa-x's optimizer port now reproduces exactly);
            # only fall back to set comparison if that actually finds a
            # difference.
            scratch: list[str] = []
            for i, (x, y) in enumerate(zip(a, b)):
                diff_value(x, y, f"{path}[{i}]", scratch, key=key, limit=limit)
            if scratch and _children_match_as_multiset(a, b):
                return
            problems.extend(scratch)
            return
        for i, (x, y) in enumerate(zip(a, b)):
            diff_value(x, y, f"{path}[{i}]", problems, key=key, limit=limit)
    else:
        if a != b:
            problems.append(f"  {path}: {a!r} (python) vs {b!r} (rust)")


def diff_json_sample(
    sample: Path,
    capa_cli: Path,
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
    rust_cache: Path | None,
) -> list[str]:
    frz_path, json_path = ensure_cached(sample, cache_dir, rules_dir, sigs_dir)

    py_doc = json.loads(json_path.read_text())
    rs_doc = rust_json(capa_cli, rules_dir, frz_path, rust_cache=rust_cache)

    normalize_result_doc(py_doc)
    normalize_result_doc(rs_doc)

    problems: list[str] = []
    diff_value(py_doc, rs_doc, "$", problems)
    return problems


DUMP_FILE_FEATURES_SCRIPT = REPO_ROOT / "scripts" / "dump_file_features.py"
BINDING_ANALYZE_SCRIPT = REPO_ROOT / "scripts" / "binding_analyze.py"


def generate_file_only_freeze(sample: Path, out_path: Path) -> None:
    """
    the file-scope counterpart to `generate_freeze`: dumps a freeze file from the
    pinned Python capa's *file-only* extractor (not the full vivisect
    backend `capa.features.freeze.main`/`generate_freeze` would use for a
    raw PE/ELF path) -- see `scripts/dump_file_features.py`.
    """
    subprocess.run(
        [str(VENV_PYTHON), str(DUMP_FILE_FEATURES_SCRIPT), "--mode", "dump-freeze", str(sample), str(out_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def ensure_cached_file_features(sample: Path, cache_dir: Path, rules_dir: Path) -> tuple[Path, Path]:
    digest = sha256_of(sample)
    frz_path = cache_dir / f"{digest}.m4.frz"
    json_path = cache_dir / f"{digest}.m4.json"
    cache_dir.mkdir(parents=True, exist_ok=True)

    if not frz_path.exists():
        generate_file_only_freeze(sample, frz_path)
    if not json_path.exists():
        generate_json(frz_path, json_path, rules_dir)

    return frz_path, json_path


def python_dump_features(sample: Path) -> set[str]:
    proc = subprocess.run(
        [str(VENV_PYTHON), str(DUMP_FILE_FEATURES_SCRIPT), "--mode", "dump-features", str(sample)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"dump_file_features.py failed on {sample}:\n{proc.stderr}")
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def rust_dump_features(
    capa_cli: Path, rules_dir: Path, sample: Path, rust_cache: Path | None = None
) -> set[str]:
    def produce() -> str:
        proc = subprocess.run(
            [str(capa_cli), "--rules", str(rules_dir), "--dump-features", str(sample)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"capa-x-cli failed on {sample}:\n{proc.stderr}")
        return proc.stdout

    stdout = cached_rust_output("dump-features", sample, capa_cli, rules_dir, [], rust_cache, produce)
    return {line.strip() for line in stdout.splitlines() if line.strip()}


def rust_json_direct(capa_cli: Path, rules_dir: Path, sample: Path, rust_cache: Path | None = None) -> dict:
    """
    the direct counterpart to `rust_json`: runs capa-x-cli directly against the
    raw sample (format auto-detected -- exercising the PE/ELF file-scope
    extractors), rather than a pre-existing freeze file.
    """

    def produce() -> str:
        proc = subprocess.run(
            [str(capa_cli), "--rules", str(rules_dir), "--file-only", "-j", str(sample)],
            capture_output=True,
            text=True,
        )
        if not proc.stdout.strip():
            raise RuntimeError(
                f"capa-x-cli produced no output for {sample} (exit {proc.returncode}):\n{proc.stderr}"
            )
        return proc.stdout

    stdout = cached_rust_output("file-only-json", sample, capa_cli, rules_dir, [], rust_cache, produce)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"capa-x-cli did not produce valid JSON for {sample}: {e}\n{stdout[:2000]}") from e


def diff_file_features_sample(
    sample: Path, capa_cli: Path, rules_dir: Path, cache_dir: Path, rust_cache: Path | None
) -> list[str]:
    problems: list[str] = []

    py_features = python_dump_features(sample)
    rs_features = rust_dump_features(capa_cli, rules_dir, sample, rust_cache=rust_cache)
    if py_features != rs_features:
        missing = sorted(py_features - rs_features)
        extra = sorted(rs_features - py_features)
        if missing:
            problems.append(f"  missing feature(s) in capa-x: {missing[:10]}{' ...' if len(missing) > 10 else ''}")
        if extra:
            problems.append(f"  extra feature(s) in capa-x: {extra[:10]}{' ...' if len(extra) > 10 else ''}")

    _frz_path, json_path = ensure_cached_file_features(sample, cache_dir, rules_dir)
    py_doc = json.loads(json_path.read_text())
    rs_doc = rust_json_direct(capa_cli, rules_dir, sample, rust_cache=rust_cache)

    normalize_result_doc(py_doc)
    normalize_result_doc(rs_doc)
    # the Python reference is generated by re-analyzing a freeze dump of
    # the file-only extractor (`meta.analysis.format` ends up "freeze",
    # the CLI format flag `generate_json` invoked `capa` with, and
    # `meta.sample.path` is the cached `.m4.frz` path), whereas capa-x
    # runs directly against the raw sample -- correctly reporting "pe"/
    # "elf" (see capa-x-cli/src/main.rs's `resolved_format` plumbing) and the
    # real sample path. Both are differences in *this harness's*
    # measurement methodology (json/freeze modes feed both sides the exact
    # same freeze file, so they never needed this), not real divergences.
    for doc in (py_doc, rs_doc):
        doc.get("meta", {}).get("analysis", {}).pop("format", None)
        doc.get("meta", {}).get("sample", {}).pop("path", None)

    diff_value(py_doc, rs_doc, "$", problems)
    return problems


def diff_full_sample(
    item: WorkItem,
    capa_cli: Path,
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
    rust_cache: Path | None,
    exact: bool = False,
    profile: Profile = PROFILES["v2-static"],
) -> list[str]:
    """
    `profile` drives which `-f` value (if any) each side is invoked with, and
    which files each side reads (`item.reference_input`/`item.rust_input` --
    equal for every profile except `aarch64-binexport`'s paired corpus). The
    `v2-static` default reproduces the original, single-`sample` behavior
    exactly: no extra args, no cache-key suffix, `reference_input ==
    rust_input == display`.
    """
    reference_args = [] if profile.reference_format is None else ["-f", profile.reference_format]
    cache_suffix = "" if profile.name == "v2-static" else profile.name
    env_overrides = (
        {"CAPA_SAMPLES_DIR": str(item.rust_input.parent)} if item.reference_input != item.rust_input else None
    )
    json_path = ensure_full_cached(
        item.reference_input,
        cache_dir,
        rules_dir,
        sigs_dir,
        extra_args=reference_args,
        cache_suffix=cache_suffix,
        env_overrides=env_overrides,
    )

    py = python_matches(json_path)
    rust_args = [] if profile.rust_format is None else ["-f", profile.rust_format]
    rust_args += shellcode_format_flag(item.rust_input)
    cache_kind = "dump-matches" if profile.name == "v2-static" else f"dump-matches-{profile.name}"
    rs = rust_matches(
        capa_cli,
        rules_dir,
        item.rust_input,
        extra_args=rust_args,
        rust_cache=rust_cache,
        cache_kind=cache_kind,
    )

    if not exact:
        # full-names: development score -- rule presence only, ignoring
        # match addresses. A rule can be "identical" here while landing at
        # the wrong address (e.g. a function-scope match attributed to the
        # wrong function). Use full-exact for the release gate.
        py_names, rs_names = set(py), set(rs)
        # One problem line per diverging rule, so that `len(problems)` *is*
        # the number of rules this sample diverges by -- the unit used by the
        # accuracy and regression checks, and what the
        # regression guard (`--samples`' sibling `.expected.json`) compares.
        return [f"  rule missing in capa-x: {name!r}" for name in sorted(py_names - rs_names)] + [
            f"  rule extra in capa-x: {name!r}" for name in sorted(rs_names - py_names)
        ]

    # full-exact: release gate -- rule name AND every matched address must
    # agree. This is the same per-rule address-set comparison freeze mode
    # applies, but run against the raw sample (capa-x's own recovery)
    # rather than a shared freeze file, so recovery-boundary divergences
    # (mis-attributed function/basic-block scope) surface here.
    problems = []
    for name in sorted(set(py) | set(rs)):
        p, r = py.get(name, set()), rs.get(name, set())
        if p != r:
            missing = sorted(p - r)
            extra = sorted(r - p)
            detail = []
            if missing:
                detail.append(f"missing in capa-x: {missing[:8]}{' ...' if len(missing) > 8 else ''}")
            if extra:
                detail.append(f"extra in capa-x: {extra[:8]}{' ...' if len(extra) > 8 else ''}")
            problems.append(f"  rule {name!r}: " + "; ".join(detail))
    return problems


def binding_result(rules_dir: Path, sample: Path) -> dict:
    """Runs `scripts/binding_analyze.py` under the pinned `.venv` (see that
    script's module doc) and returns its parsed JSON summary: `ok` (did the
    binding import and run at all), `valid` (did the result document pass
    pinned capa's own `ResultDocument.model_validate_json`), and
    `rule_names` (the matched top-level rule names).

    Not cached (unlike `rust_matches`/`ensure_full_cached`): a J14 run is
    one `analyze()` call per sample, already sub-second per the pinned
    corpus, and caching it would need its own cache-invalidation key (the
    binding wheel's contents) this harness doesn't otherwise track.
    """
    proc = subprocess.run(
        [str(VENV_PYTHON), str(BINDING_ANALYZE_SCRIPT), str(rules_dir), str(sample)],
        capture_output=True,
        text=True,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"binding_analyze.py produced no output for {sample} (exit {proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def diff_binding_sample(sample: Path, capa_cli: Path, rules_dir: Path, rust_cache: Path | None) -> list[str]:
    """Every result document validates under
    pinned capa's own `ResultDocument` model, and the binding's matched
    rule names equal the CLI's -- same bytes, same ruleset, same options
    (both sides: full pipeline, format auto-detected, `jobs=1`).

    The CLI side reuses `rust_matches`' default cache entry
    (`cache_kind="dump-matches"`, no extra args) -- the same one `--mode
    full`'s v2-static profile already produces, so a J14 run over a corpus
    the outer loop just ran is a cache hit, per the roadmap's "run it over
    whatever the outer loop ran."
    """
    result = binding_result(rules_dir, sample)
    if not result["ok"]:
        return [f"  capa_x binding failed to run: {result['error']}"]
    if not result["valid"]:
        return [f"  result document failed pinned ResultDocument validation: {result['validation_error']}"]

    cli = rust_matches(capa_cli, rules_dir, sample, rust_cache=rust_cache)
    cli_names, binding_names = set(cli), set(result["rule_names"])
    return [f"  rule missing in capa_x binding: {name!r}" for name in sorted(cli_names - binding_names)] + [
        f"  rule extra in capa_x binding: {name!r}" for name in sorted(binding_names - cli_names)
    ]


def diff_sample(
    mode: str,
    item: WorkItem,
    profile: Profile,
    capa_cli: Path,
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
    rust_cache: Path | None,
) -> list[str]:
    # The freeze-driven modes assume one shared freeze file drives both
    # sides -- true only for `v2-static`, where `item.display ==
    # item.reference_input == item.rust_input`. A non-default profile only
    # wires `--mode full` (see `Profile`'s docstring).
    if mode in ("json", "freeze", "file-features", "binding") and profile.name != "v2-static":
        raise ValueError(
            f"--mode {mode} is only wired for --profile v2-static; "
            f"--profile {profile.name} only supports --mode full/full-exact"
        )
    sample = item.display
    if mode == "json":
        return diff_json_sample(sample, capa_cli, rules_dir, sigs_dir, cache_dir, rust_cache)
    elif mode == "freeze":
        return diff_freeze_sample(sample, capa_cli, rules_dir, sigs_dir, cache_dir, rust_cache)
    elif mode == "file-features":
        return diff_file_features_sample(sample, capa_cli, rules_dir, cache_dir, rust_cache)
    elif mode == "binding":
        return diff_binding_sample(sample, capa_cli, rules_dir, rust_cache)
    elif mode == "full":
        return diff_full_sample(item, capa_cli, rules_dir, sigs_dir, cache_dir, rust_cache, exact=False, profile=profile)
    elif mode == "full-exact":
        return diff_full_sample(item, capa_cli, rules_dir, sigs_dir, cache_dir, rust_cache, exact=True, profile=profile)
    else:
        raise ValueError(f"unknown mode: {mode}")


def run_sample(
    mode: str,
    item: WorkItem,
    profile: Profile,
    capa_cli: Path,
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
    rust_cache: Path | None,
) -> tuple[list[str], float]:
    t0 = time.monotonic()
    problems = diff_sample(mode, item, profile, capa_cli, rules_dir, sigs_dir, cache_dir, rust_cache)
    return problems, time.monotonic() - t0


def expected_path_for(samples_path: Path) -> Path:
    """`scripts/corpus-smoke.txt` -> `scripts/corpus-smoke.expected.json`."""
    return samples_path.with_suffix(".expected.json")


def results_to_expected(mode: str, results: dict[Path, tuple[list[str], float]]) -> dict:
    return {
        "mode": mode,
        "samples": {
            sample.name: {"diffs": len(problems), "details": problems}
            for sample, (problems, _duration) in sorted(results.items(), key=lambda kv: kv[0].name)
        },
    }


def check_expected(
    expected: dict,
    mode: str,
    results: dict[Path, tuple[list[str], float]],
    partial_run: bool = False,
) -> tuple[dict[str, list[str]], list[str]]:
    """
    Compare a run against a recorded per-sample baseline.

    A whole-corpus score cannot tell a fix from a trade: the prologue and
    `block_starts`
    changes both had to be judged by headline count alone. So a sample that
    was identical and now differs -- or that now diverges by *more* rules than
    it did -- is a regression and fails the run, whatever the total does.

    Returns ({sample name: reason lines}, notices). Notices are improvements
    and same-size drift: real information, but never a failure.
    """
    baseline = expected.get("samples", {})
    regressions: dict[str, list[str]] = {}
    notices: list[str] = []

    if expected.get("mode") != mode:
        return {}, [
            f"baseline was recorded for --mode {expected.get('mode')!r}, not {mode!r}: guard skipped"
        ]

    for sample, (problems, _duration) in sorted(results.items(), key=lambda kv: kv[0].name):
        was = baseline.get(sample.name)
        now = len(problems)
        if was is None:
            notices.append(f"{sample.name}: not in the baseline ({now} diff(s)) -- re-record it")
            continue
        before = was["diffs"]
        if before == 0 and now > 0:
            regressions[sample.name] = [f"was identical, now diverges by {now} rule(s):", *problems]
        elif now > before:
            regressions[sample.name] = [f"diverged by {before} rule(s), now {now}:", *problems]
        elif now < before:
            notices.append(f"{sample.name}: improved, {before} -> {now} diff(s)")
        elif problems != was["details"]:
            notices.append(f"{sample.name}: still {now} diff(s), but different ones:")
            notices.extend(problems)

    # A filtered run (--only) legitimately covers a subset; only a full run
    # can tell "gone from the corpus" from "not selected".
    if not partial_run:
        for name in sorted(set(baseline) - {sample.name for sample in results}):
            notices.append(f"{name}: in the baseline but not in this run")

    return regressions, notices


def rule_level_agreement(
    mode: str,
    items: list[WorkItem],
    profile: Profile,
    results: dict[Path, tuple[list[str], float]],
    rules_dir: Path,
    sigs_dir: Path,
    cache_dir: Path,
) -> dict[str, int | float] | None:
    """The headline metric: what fraction of the reference's matched rules do
    the two sides agree on?

    `Identical: N/200` has no denominator -- it counts *samples*, so a sample
    that diverges by one rule out of ninety scores the same as one that
    diverges by all ninety. Two phases of this project were scoped off that
    number before anyone divided by the rules. Computing it here means no one
    has to do it by hand again.

    The denominator is every rule the pinned reference matched across the
    corpus, read back from the same cached JSON the diff already used, so this
    costs a local file read per sample and never re-runs capa. Only the two
    name-level modes have one: `freeze`/`json` compare whole documents, and
    `full-exact` counts a rule matched at the wrong address as a divergence,
    which is a different (stricter) question.
    """
    if mode != "full":
        return None

    reference_args = [] if profile.reference_format is None else ["-f", profile.reference_format]
    cache_suffix = "" if profile.name == "v2-static" else profile.name
    reference_rules = 0
    for item in items:
        try:
            env_overrides = (
                {"CAPA_SAMPLES_DIR": str(item.rust_input.parent)} if item.reference_input != item.rust_input else None
            )
            json_path = ensure_full_cached(
                item.reference_input,
                cache_dir,
                rules_dir,
                sigs_dir,
                extra_args=reference_args,
                env_overrides=env_overrides,
                cache_suffix=cache_suffix,
            )
            reference_rules += len(python_matches(json_path))
        except Exception:  # noqa: BLE001 -- a sample that could not be read has no denominator to add
            continue

    # `diff_full_sample` emits exactly one line per diverging rule, which is
    # what makes counting them meaningful -- see the comment there before
    # changing either side.
    missing = extra = 0
    for problems, _duration in results.values():
        missing += sum(p.startswith("  rule missing in capa-x:") for p in problems)
        extra += sum(p.startswith("  rule extra in capa-x:") for p in problems)

    divergences = missing + extra
    return {
        "reference_rules": reference_rules,
        "divergences": divergences,
        "missing": missing,
        "extra": extra,
        "agreement": (1 - divergences / reference_rules) if reference_rules else 0.0,
    }


def format_agreement(stats: dict[str, int | float]) -> list[str]:
    return [
        f"- **Rule-level agreement: {stats['agreement']:.2%}** "
        f"({stats['divergences']} divergence(s) / {stats['reference_rules']} reference-matched rules)",
        f"- Divergences: {stats['missing']} missing, {stats['extra']} extra",
    ]


def write_report(
    path: Path,
    mode: str,
    samples: list[Path],
    results: dict[Path, tuple[list[str], float]],
    agreement: dict[str, int | float] | None = None,
) -> None:
    identical = sum(not problems for problems, _duration in results.values())
    lines = [
        "# Differential test report",
        "",
        f"- Mode: `{mode}`",
        f"- Samples: {len(samples)}",
    ]
    # Agreement leads; samples-identical follows. The order is the point --
    # see the benchmark methodology and the README.
    if agreement is not None:
        lines.extend(format_agreement(agreement))
    lines += [
        f"- Identical: {identical} ({identical / len(samples):.1%})",
        f"- Different or failed: {len(samples) - identical}",
        "",
        "| Sample | Result | Diffs | Seconds | Details |",
        "|---|---:|---:|---:|---|",
    ]
    for sample in samples:
        problems, duration = results[sample]
        status = "ok" if not problems else "diff"
        details = "<br>".join(problem.strip().replace("|", "\\|") for problem in problems)
        lines.append(f"| `{sample.name}` | {status} | {len(problems)} | {duration:.1f} | {details} |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    if Path(sys.prefix).resolve() != VENV_PYTHON.parent.parent.resolve():
        os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *(argv or sys.argv[1:])])

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--mode",
        choices=["json", "freeze", "file-features", "full", "full-exact", "binding"],
        default="json",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="v2-static",
        help="which backend/reference pairing to run; v2-static (default) is today's PE/ELF/shellcode "
        "behavior, unchanged",
    )
    parser.add_argument(
        "--samples",
        type=Path,
        default=None,
        help="path to a corpus list file (default: the profile's own corpus, e.g. "
        "scripts/corpus-dotnet.txt for --profile dotnet)",
    )
    parser.add_argument("--only", type=str, default=None, help="only run samples whose path contains this substring")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--sigs", type=Path, default=DEFAULT_SIGS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument(
        "--no-rust-cache",
        action="store_true",
        help="always re-run capa-x-cli instead of reusing its cached output "
        "(the cache keys on the binary's contents, so this is only needed to "
        "double-check a suspicious cached result)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="number of samples to process concurrently (default: 1; use 2 for memory-heavy full mode)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write a Markdown per-sample report (full mode defaults to target/difftest-report.md)",
    )
    parser.add_argument(
        "--expected",
        type=Path,
        default=None,
        help="per-sample baseline to guard against (default: the --samples list's "
        "sibling `<name>.expected.json`, if it exists). With a baseline active, "
        "the exit status reports *regressions* -- a sample that was identical and "
        "now differs, or diverges by more rules than before -- rather than the raw "
        "presence of known diffs.",
    )
    parser.add_argument(
        "--no-expected",
        action="store_true",
        help="ignore the baseline: exit nonzero if any sample differs at all",
    )
    parser.add_argument(
        "--write-expected",
        action="store_true",
        help="record this run's per-sample results as the baseline and exit 0 "
        "(unless a sample errored)",
    )
    parser.add_argument(
        "--capa-cli",
        type=Path,
        default=REPO_ROOT / "target" / "debug" / "capa-x",
        help="path to the capa-x binary (default: debug build)",
    )
    args = parser.parse_args(argv)

    if not args.capa_cli.exists():
        print(f"error: {args.capa_cli} not found -- run `cargo build -p capa-x-cli` first", file=sys.stderr)
        return 2
    if args.jobs < 1:
        print("error: --jobs must be at least 1", file=sys.stderr)
        return 2

    profile = PROFILES[args.profile]
    if profile.name != "v2-static" and args.mode not in ("full", "full-exact"):
        print(
            f"error: --mode {args.mode} is only wired for --profile v2-static; "
            f"--profile {profile.name} only supports --mode full (see the profile definition)",
            file=sys.stderr,
        )
        return 2

    # A profile whose rust side needs a `-f` value this capa-x-cli build
    # doesn't accept yet (e.g. an unimplemented `-f` value) is not a
    # failure -- it's the expected state until the backend lands. Report it
    # plainly and exit clean rather than letting every sample fail with a
    # confusing clap error.
    if profile.rust_format is not None and not capa_cli_supports_format(args.capa_cli, profile.rust_format):
        print(
            f"profile {profile.name!r}: capa-x-cli does not support `-f {profile.rust_format}` yet "
            "(backend not implemented) -- 0/0 samples run",
            flush=True,
        )
        return 0

    samples_path = args.samples or profile.default_samples
    if samples_path is None:
        print(f"error: --profile {profile.name} has no default corpus; pass --samples explicitly", file=sys.stderr)
        return 2

    items = read_work_items(profile, samples_path)
    if args.only:
        items = [item for item in items if args.only in str(item.display)]
    if not items:
        if profile.name != "v2-static":
            # An empty profile corpus (macho-fixture before task 4/5 builds
            # one) is the expected state, not an error -- report and exit
            # clean the same way an unsupported `-f` value does above.
            print(f"profile {profile.name!r}: no samples in {samples_path} -- 0/0 samples run", flush=True)
            return 0
        print("error: no samples selected", file=sys.stderr)
        return 2

    failures: dict[str, list[str]] = {}
    errored: list[str] = []
    results: dict[Path, tuple[list[str], float]] = {}
    ready = [item for item in items if item.reference_input.exists() and item.rust_input.exists()]
    for item in items:
        if item not in ready:
            missing = [p for p in (item.reference_input, item.rust_input) if not p.exists()]
            problems = [f"  input file not found: {p}" for p in missing]
            failures[str(item.display)] = problems
            errored.append(str(item.display))
            results[item.display] = (problems, 0.0)

    rust_cache = None if args.no_rust_cache else args.cache_dir / "rust"

    context = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=args.jobs, mp_context=context, initializer=initialize_worker
    ) as executor:
        pending = {
            executor.submit(
                run_sample,
                args.mode,
                item,
                profile,
                args.capa_cli,
                args.rules,
                args.sigs,
                args.cache_dir,
                rust_cache,
            ): item
            for item in ready
        }
        completed = len(items) - len(ready)
        for future in concurrent.futures.as_completed(pending):
            item = pending[future]
            sample = item.display
            completed += 1
            try:
                problems, duration = future.result()
            except Exception as error:  # noqa: BLE001 -- report and continue with the rest of the corpus
                problems = [f"  error: {error}"]
                duration = 0.0
                status = f"ERROR ({error})"
                errored.append(str(sample))
            else:
                status = f"DIFF ({len(problems)} issue(s))" if problems else "ok"
            results[sample] = (problems, duration)
            if problems:
                failures[str(sample)] = problems
            print(f"[{completed}/{len(items)}] {sample.name}: {status} ({duration:.1f}s)", flush=True)

    agreement = rule_level_agreement(
        args.mode, items, profile, results, args.rules, args.sigs, args.cache_dir
    )

    samples = [item.display for item in items]

    report = args.report
    if report is None and args.mode == "full":
        report = REPO_ROOT / "target" / "difftest-report.md"
    elif report is None and args.mode == "full-exact":
        report = REPO_ROOT / "target" / "difftest-report-exact.md"
    if report is not None:
        write_report(report, args.mode, samples, results, agreement)
        print(f"report: {report}", flush=True)

    if agreement is not None:
        identical = sum(not problems for problems, _duration in results.values())
        print("", flush=True)
        for line in format_agreement(agreement):
            print(line.replace("**", "").lstrip("- "), flush=True)
        print(f"Samples identical: {identical}/{len(samples)} ({identical / len(samples):.1%})", flush=True)

    if failures:
        print(f"\n{len(failures)}/{len(samples)} sample(s) differ:\n")
        for sample, problems in failures.items():
            print(f"{sample}:")
            for p in problems:
                print(p)

    if args.write_expected:
        expected_path = args.expected or expected_path_for(samples_path)
        expected_path.write_text(json.dumps(results_to_expected(args.mode, results), indent=2) + "\n")
        print(f"\nbaseline written: {expected_path}")
        if errored:
            print(f"but {len(errored)} sample(s) errored -- baseline records the error", file=sys.stderr)
            return 1
        return 0

    expected_path = args.expected
    if expected_path is None and not args.no_expected:
        candidate = expected_path_for(samples_path)
        expected_path = candidate if candidate.exists() else None
    if args.no_expected:
        expected_path = None

    if expected_path is not None:
        if not expected_path.exists():
            print(f"error: baseline {expected_path} not found -- record it with --write-expected", file=sys.stderr)
            return 2
        regressions, notices = check_expected(
            json.loads(expected_path.read_text()),
            args.mode,
            results,
            partial_run=bool(args.only),
        )
        print(f"\nbaseline: {expected_path}")
        for notice in notices:
            print(notice if notice.startswith("  ") else f"  note: {notice}")
        if notices:
            print("  (re-record with --write-expected once the change is deliberate)")
        if regressions or errored:
            print(f"\nREGRESSION: {len(regressions)} sample(s) worse than the baseline:\n")
            for sample, lines in regressions.items():
                print(f"{sample}: {lines[0]}")
                for line in lines[1:]:
                    print(line)
            for sample in errored:
                print(f"{sample}: errored")
            return 1
        print(
            f"no regressions: {len(failures)}/{len(samples)} sample(s) differ, all within the baseline"
        )
        return 0

    if failures:
        return 1

    print(f"\nall {len(samples)} sample(s) match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
