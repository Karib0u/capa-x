#!/usr/bin/env python3
"""
Regenerates the row tables in `capa-x/tests/dotnet_features_parity.rs`
and `capa-x/tests/aarch64_features_parity.rs` from the pinned Python capa
test suite's `FEATURE_PRESENCE_TESTS_DOTNET`/`FEATURE_COUNT_TESTS_DOTNET`
(`reference/capa/tests/fixtures.py`) and
`FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64`
(`reference/capa/tests/test_binexport_features.py`).

Dev-time only: run this under the pinned `.venv` whenever PINNED.md's
`mandiant/capa` pin bumps, paste its
output into the two `#[rustfmt::skip] const ROWS: &[Row] = &[ ... ];`
blocks, and re-run `cargo fmt`/`cargo test`. The generated Rust is committed
-- `cargo test` never invokes Python (AGENTS.md "No Python at runtime").

`pytest` isn't a runtime dependency of the pinned capa package, so this
stubs it out well enough for `fixtures.py`/`test_binexport_features.py` to
import cleanly (both only use `@pytest.fixture`/`pytest.mark.parametrize`-
style decorators at module scope, never anything this script calls).

usage:
  .venv/bin/python3 scripts/gen_fixture_tables.py dotnet
  .venv/bin/python3 scripts/gen_fixture_tables.py aarch64
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class _DummyMark:
    def __getattr__(self, name):
        def decorator_factory(*args, **kwargs):
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]
            return lambda f: f

        return decorator_factory


class _DummyPytest(types.ModuleType):
    """Just enough of `pytest`'s decorator surface for `fixtures.py`/
    `test_binexport_features.py` to import without the real package."""

    def __getattr__(self, name):
        if name == "mark":
            return _DummyMark()

        def passthrough(*args, **kwargs):
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]
            return lambda f: f

        return passthrough


def _install_pytest_stub_and_path() -> None:
    sys.modules["pytest"] = _DummyPytest("pytest")
    sys.path.insert(0, str(REPO_ROOT / "reference" / "capa" / "tests"))
    sys.path.insert(0, str(REPO_ROOT / "reference" / "capa"))


def rust_str(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def feature_ctor(feature) -> str:
    """Maps a pinned-capa `capa.features.*` instance to the matching helper
    constructor call in the generated Rust file (`api_`, `string_`, ...) --
    same names `features_parity.rs` already uses for the x86/x64 tables."""
    t = type(feature).__name__
    v = getattr(feature, "value", None)
    simple = {
        "API": "api_",
        "Arch": "arch_",
        "OS": "os_",
        "Format": "format_",
        "Characteristic": "characteristic_",
        "Import": "import_",
        "Export": "export_",
        "FunctionName": "function_name_",
        "Section": "section_",
        "Mnemonic": "mnemonic_",
        "String": "string_",
        "Substring": "substring_",
        "Regex": "regex_",
        "Class": "class_",
        "Namespace": "namespace_",
    }
    if t in simple:
        return f"{simple[t]}({rust_str(v)})"
    if t == "Bytes":
        return f"bytes_hex({rust_str(v.hex())})"
    if t == "Number":
        assert isinstance(v, int), f"non-int Number not handled: {v!r}"
        return f"num({v})"
    if t == "Offset":
        assert isinstance(v, int)
        return f"off({v})"
    if t == "OperandNumber":
        assert isinstance(v, int)
        return f"opnum({feature.index}, {v})"
    if t == "OperandOffset":
        assert isinstance(v, int)
        return f"opoff({feature.index}, {v})"
    if t == "Property":
        # capa.features.common.Property(name, access=None); access is
        # "read"/"write"/None, not surfaced via .value.
        access = getattr(feature, "access", None)
        access_repr = f'Some({rust_str(access)})' if access else "None"
        return f"property_({rust_str(v)}, {access_repr})"
    raise NotImplementedError(f"unhandled feature type {t} (value {v!r}) -- add it to feature_ctor")


def dump_dotnet() -> None:
    import fixtures

    # `hello-world`/`mixed-mode-64` live in dnfile's own bundled test
    # fixtures (a nested, differently-pinned `tests/data` submodule inside
    # `reference/capa` that this repo does not check out -- see
    # dotnet_features_parity.rs's module doc). Excluded, not silently
    # dropped: this script records why every time it regenerates the table.
    unbacked = {"hello-world", "mixed-mode-64"}

    print("// --- FEATURE_PRESENCE_TESTS_DOTNET " + "-" * 40)
    excluded = 0
    for sample, scope, feature, expected in fixtures.FEATURE_PRESENCE_TESTS_DOTNET:
        if sample in unbacked:
            excluded += 1
            continue
        ctor = feature_ctor(feature)
        print(
            f"    Row {{ sample: {rust_str(sample)}, scope: {rust_str(scope)}, "
            f"feature: || {ctor}, expected: {str(expected).lower()} }},"
        )
    print(f"// excluded {excluded} row(s) referencing dnfile-testfiles samples (hello-world, mixed-mode-64)")
    print()
    print("// --- FEATURE_COUNT_TESTS_DOTNET " + "-" * 40)
    for sample, scope, feature, expected in fixtures.FEATURE_COUNT_TESTS_DOTNET:
        ctor = feature_ctor(feature)
        print(
            f"    CountRow {{ sample: {rust_str(sample)}, scope: {rust_str(scope)}, "
            f"feature: || {ctor}, expected: {expected} }},"
        )


def dump_aarch64() -> None:
    import test_binexport_features as tbf

    print("// --- FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64 " + "-" * 30)
    for row in tbf.FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64:
        sample, scope, feature, expected = row[0], row[1], row[2], row[3]
        ctor = feature_ctor(feature)
        if isinstance(expected, bool):
            exp_repr = f"Expected::Bool({str(expected).lower()})"
        else:
            # "xfail: <reason>" strings -- see test_binexport_features.py's
            # own `if not isinstance(expected, bool): pytest.xfail(expected)`.
            exp_repr = f"Expected::Xfail({rust_str(expected)})"
        print(
            f"    Row {{ sample: {rust_str(sample)}, scope: {rust_str(scope)}, "
            f"feature: || {ctor}, expected: {exp_repr} }},"
        )


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("dotnet", "aarch64"):
        print(__doc__, file=sys.stderr)
        return 2
    _install_pytest_stub_and_path()
    if sys.argv[1] == "dotnet":
        dump_dotnet()
    else:
        dump_aarch64()
    return 0


if __name__ == "__main__":
    sys.exit(main())
