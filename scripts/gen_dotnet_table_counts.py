#!/usr/bin/env python3
"""Dump per-table row counts for the pinned .NET corpus using pinned Python
`dnfile`, as the oracle for capa-x's vendored Rust `dnfile` metadata reader.

Usage: .venv/bin/python3 scripts/gen_dotnet_table_counts.py > \
    capa-x/tests/fixtures/dotnet/table_counts.json
"""

import json
import sys
from pathlib import Path

import dnfile

TABLE_NAMES = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRva",
    "EncLog",
    "EncMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    # ECMA-335 table 0x2B's standard name; the vendored Rust `dnfile` fork
    # (third_party/dnfile) calls this same table "GenericMethod" instead --
    # a labeling difference between the two crates, not a row-count one. See
    # capa-x/src/extract/dotnet/mod.rs's `TABLE_NAMES`.
    "MethodSpec",
    "GenericParamConstraint",
]


def dump_one(path: Path) -> dict:
    pe = dnfile.dnPE(str(path))
    assert pe.net is not None
    assert pe.net.mdtables is not None
    counts = {}
    for name in TABLE_NAMES:
        table = getattr(pe.net.mdtables, name, None)
        counts[name] = 0 if table is None else int(table.num_rows)
    return counts


def main() -> None:
    corpus_dir = Path("tests/testfiles/dotnet")
    samples = sorted(
        p for p in corpus_dir.iterdir() if p.suffix in (".exe_", ".dll_")
    )
    out = {}
    for sample in samples:
        out[sample.name] = dump_one(sample)
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
