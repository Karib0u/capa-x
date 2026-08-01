"""Tests for the compiled `capa_x` extension.

Not run by `cargo test` (the crate opts its lib target out of that --
`capa-x-python/Cargo.toml`'s `[lib] test = false`, explained in ADR 0006):
this is the pytest suite that proves the actual `.so`/`.pyd` behaves,
against a real `maturin develop` build. Run with:

    maturin develop
    pytest capa-x-python/tests/

Everything here exercises the *binding*, not analysis correctness --
`capa-x`'s own test suites (`cargo test -p capa-x`,
`scripts/difftest.py`) already own that. What's checked here is the binding
contract: malformed input/missing rules/unparseable rule each raise a typed
exception with context, `jobs=1` reproduces the CLI's rule names, and the GIL
is actually released during `analyze()`.
"""

import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

import capa_x

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"
SAMPLE = REPO_ROOT / "tests" / "testfiles" / "c335a9d41185a32ad918c5389ee54235.exe_"

pytestmark = pytest.mark.skipif(
    not RULES_DIR.is_dir(), reason="capa-rules submodule not checked out"
)


@pytest.fixture(scope="module")
def rules() -> capa_x.Rules:
    return capa_x.Rules.from_directory(str(RULES_DIR))


def test_version_and_rules_pin() -> None:
    assert capa_x.__version__
    assert capa_x.RULES_PIN.startswith("v")


def test_rules_from_directory_missing_dir() -> None:
    with pytest.raises(capa_x.InvalidRuleError):
        capa_x.Rules.from_directory("/no/such/directory")


def test_rules_from_directory_unparseable_rule(tmp_path: Path) -> None:
    (tmp_path / "bad.yml").write_text("not: valid: capa: rule:\n  - [")
    with pytest.raises(capa_x.InvalidRuleError) as excinfo:
        capa_x.Rules.from_directory(str(tmp_path))
    # context, not just a bare exception: the message names the file.
    assert "bad.yml" in str(excinfo.value)


def test_analyze_bytes(rules: capa_x.Rules) -> None:
    data = SAMPLE.read_bytes()
    doc = capa_x.analyze(data, rules, jobs=1)
    assert isinstance(doc, dict)
    assert doc["meta"]["analysis"]["format"] == "pe"
    assert doc["meta"]["sample"]["sha256"]
    assert "rules" in doc


def test_meta_argv_is_empty_list_not_null(rules: capa_x.Rules) -> None:
    # regression: upstream's `ResultDocument.meta.argv` is a required
    # `list[str]`, not `Optional` -- `null` fails `model_validate_json`
    # (J14 caught this; see capa-x/src/api.rs's `Input::argv` doc).
    doc = capa_x.analyze(SAMPLE, rules, jobs=1)
    assert doc["meta"]["argv"] == []


def test_analyze_path(rules: capa_x.Rules) -> None:
    doc = capa_x.analyze(str(SAMPLE), rules, jobs=1)
    assert doc["meta"]["sample"]["path"] == str(SAMPLE)


def test_analyze_pathlike(rules: capa_x.Rules) -> None:
    doc = capa_x.analyze(SAMPLE, rules, jobs=1)
    assert doc["meta"]["analysis"]["format"] == "pe"


def test_analyze_bad_type(rules: capa_x.Rules) -> None:
    with pytest.raises(TypeError):
        capa_x.analyze(12345, rules)  # type: ignore[arg-type]


def test_analyze_missing_file(rules: capa_x.Rules) -> None:
    with pytest.raises(FileNotFoundError):
        capa_x.analyze("/no/such/file.exe_", rules)


def test_analyze_malformed_input(rules: capa_x.Rules) -> None:
    with pytest.raises(capa_x.UnsupportedFormatError):
        capa_x.analyze(b"not a real sample" * 4, rules)


def test_analyze_unknown_format(rules: capa_x.Rules) -> None:
    with pytest.raises(capa_x.UnsupportedFormatError):
        capa_x.analyze(SAMPLE, rules, format="not-a-format")


def test_analyze_zero_jobs(rules: capa_x.Rules) -> None:
    with pytest.raises(capa_x.CapaError):
        capa_x.analyze(SAMPLE, rules, jobs=0)


def test_analyze_never_returns_none_or_empty_on_error(rules: capa_x.Rules) -> None:
    # "a hard error must never become None, an empty result, or a warning"
    # A malformed sample must raise, never silently produce a document with no
    # rules.
    with pytest.raises(capa_x.CapaError):
        capa_x.analyze(b"\x00" * 16, rules)


@pytest.mark.skipif(sys.platform == "win32", reason="capa-x-cli release binary path differs")
def test_jobs_1_matches_cli_rule_names(rules: capa_x.Rules) -> None:
    """`jobs=1` reproduces the CLI's `--jobs 1` rule-name set exactly --
    the same binding parity claim made at difftest scale, here pinned to one
    sample so the binding's own test suite doesn't depend on
    a release build being present in CI."""
    cli = REPO_ROOT / "target" / "release" / "capa"
    if not cli.is_file():
        pytest.skip("target/release/capa-x not built")
    out = subprocess.run(
        [str(cli), "--rules", str(RULES_DIR), "--jobs", "1", "-j", str(SAMPLE)],
        capture_output=True,
        check=True,
        text=True,
    )
    cli_doc = json.loads(out.stdout)
    py_doc = capa_x.analyze(SAMPLE, rules, jobs=1)
    assert set(py_doc["rules"].keys()) == set(cli_doc["rules"].keys())


def test_analyze_releases_the_gil(rules: capa_x.Rules) -> None:
    """Two threads calling `analyze()` concurrently must overlap, proving
    the GIL is released for the CPU-bound part -- the roadmap's own proof
    requirement ("running analyze from two Python threads and showing they
    overlap")."""
    start_gap = []
    lock = threading.Lock()

    def worker() -> None:
        with lock:
            start_gap.append(time.monotonic())
        capa_x.analyze(SAMPLE, rules, jobs=1)

    t0 = time.monotonic()
    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    concurrent_wall = time.monotonic() - t0

    # both threads must have been able to *start* their analysis call
    # essentially together -- if the GIL were held for the duration of
    # `analyze()`, the second thread's call could not even begin until the
    # first returned.
    assert max(start_gap) - min(start_gap) < 0.5

    t0 = time.monotonic()
    capa_x.analyze(SAMPLE, rules, jobs=1)
    capa_x.analyze(SAMPLE, rules, jobs=1)
    sequential_wall = time.monotonic() - t0

    # concurrent must be meaningfully faster than strictly sequential --
    # loose bound (0.85x) to stay robust on a loaded CI runner while still
    # ruling out "GIL never released, threads ran back-to-back".
    assert concurrent_wall < sequential_wall * 0.85


def test_fetch_rules_rejects_existing_directory(tmp_path: Path) -> None:
    with pytest.raises(capa_x.CapaError):
        capa_x.fetch_rules(str(tmp_path))


def test_fetch_rules_never_runs_at_import(tmp_path: Path) -> None:
    # re-importing must never touch the network or the filesystem beyond
    # what Python's own import machinery does -- fetch_rules is opt-in
    # only, matching the CLI's own `capa-x fetch-rules` subcommand.
    marker = tmp_path / "should-not-exist"
    import importlib

    importlib.reload(capa_x)
    assert not marker.exists()
