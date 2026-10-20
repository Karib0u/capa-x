#!/usr/bin/env python3
"""
Regenerates the row tables in `capa-x/tests/dotnet_features_parity.rs`
and `capa-x/tests/aarch64_features_parity.rs` from the pinned Python capa
test suite's JSON manifests under `reference/capa/tests/fixtures/features/`.
The upstream fixture loader parses and validates every selected assertion.

Dev-time only: run this under the pinned `.venv` whenever PINNED.md's
`mandiant/capa` pin bumps, paste its
output into the two `#[rustfmt::skip] const ROWS: &[Row] = &[ ... ];`
blocks, and re-run `cargo fmt`/`cargo test`. The generated Rust is committed
-- `cargo test` never invokes Python (AGENTS.md "No Python at runtime").

`pytest` isn't a runtime dependency of the pinned capa package, so this
stubs the decorator surface used when the `fixtures` package imports.
Fixture selection and assertion parsing still run in the upstream loader.

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
    """Just enough of pytest's decorators for the upstream fixture loader."""

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

    import capa.engine

    rows = fixtures.select_feature_fixtures(
        fixtures.BackendFeaturePolicy("dnfile", include_tags={"dotnet"})
    )
    counts = []
    excluded = 0
    print("// --- FEATURE_PRESENCE_TESTS_DOTNET " + "-" * 40)
    for row in rows:
        if row.sample_key in unbacked:
            excluded += 1
            continue
        if row.marks:
            raise ValueError(f"unhandled .NET fixture marks: {row}")
        feature = row.statement
        if isinstance(feature, capa.engine.Range):
            if not row.expected or feature.min != feature.max:
                raise ValueError(f"expected an exact positive count assertion: {row}")
            counts.append(row)
            continue
        print(
            f"    Row {{ sample: {rust_str(row.sample_key)}, scope: {rust_str(row.location)}, "
            f"feature: || {feature_ctor(feature)}, expected: {str(row.expected).lower()} }},"
        )
    print(f"// excluded {excluded} row(s) referencing dnfile-testfiles samples (hello-world, mixed-mode-64)")
    print()
    print("// --- FEATURE_COUNT_TESTS_DOTNET " + "-" * 40)
    for row in counts:
        print(
            f"    CountRow {{ sample: {rust_str(row.sample_key)}, scope: {rust_str(row.location)}, "
            f"feature: || {feature_ctor(row.statement.child)}, expected: {row.statement.min} }},"
        )


def dump_aarch64() -> None:
    import fixtures

    rows = fixtures.select_feature_fixtures(
        fixtures.BackendFeaturePolicy("binexport", include_tags={"aarch64"})
    )
    print("// --- FEATURE_PRESENCE_TESTS_BE2_ELF_AARCH64 " + "-" * 30)
    for row in rows:
        exp_repr = f"Expected::Bool({str(row.expected).lower()})"
        for mark in row.marks:
            if mark.backend != "binexport" or mark.mark != "xfail":
                raise ValueError(f"unhandled AArch64 fixture mark: {mark}")
            exp_repr = f"Expected::Xfail({rust_str('xfail: ' + mark.reason)})"
        print(
            f"    Row {{ sample: {rust_str(row.sample_key)}, scope: {rust_str(row.location)}, "
            f"feature: || {feature_ctor(row.statement)}, expected: {exp_repr} }},"
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
