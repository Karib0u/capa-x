#!/usr/bin/env python3
"""Dump the resolved name model for the pinned .NET corpus using pinned
Python `dnfile`/capa, as the oracle for capa-x's Rust name model.

Usage: .venv/bin/python3 scripts/gen_dotnet_name_model.py > \
    capa-x/tests/fixtures/dotnet/name_model.json
"""

import json
import sys
from pathlib import Path
from typing import Optional

import dnfile

from capa.features.extractors.dnfile.helpers import (
    get_dotnet_types,
    get_dotnet_fields,
    is_dotnet_mixed_mode,
    get_dotnet_managed_imports,
    get_dotnet_managed_methods,
    get_dotnet_unmanaged_imports,
)
from capa.features.extractors.dnfile.types import DnType, DnUnmanagedMethod


def dn_type_to_dict(t: DnType) -> dict:
    # `get_dotnet_fields` (helpers.py) passes `member=field.row.Name` without
    # casting to `str` (unlike every other call site here, which does) -- the
    # attribute is a `dnfile.stream.HeapItemString`, not a plain `str`. Its
    # `__str__` renders identically, so cast explicitly rather than leak the
    # wrapper type into the oracle (capa-x's `DnType.member` is always a
    # plain `String`).
    return {
        "token": t.token,
        "namespace": str(t.namespace),
        "class": [str(c) for c in t.class_],
        "member": str(t.member),
        "access": t.access,
        "str": str(t),
    }


def dn_unmanaged_to_dict(m: DnUnmanagedMethod) -> dict:
    return {
        "token": m.token,
        "module": str(m.module),
        "method": str(m.method),
        "str": str(m),
    }


def dump_one(path: Path) -> dict:
    pe = dnfile.dnPE(str(path))
    assert pe.net is not None

    return {
        "mixed_mode": is_dotnet_mixed_mode(pe),
        "types": [dn_type_to_dict(t) for t in get_dotnet_types(pe)],
        "managed_imports": [dn_type_to_dict(t) for t in get_dotnet_managed_imports(pe)],
        "managed_methods": [dn_type_to_dict(t) for t in get_dotnet_managed_methods(pe)],
        "fields": [dn_type_to_dict(t) for t in get_dotnet_fields(pe)],
        "unmanaged_imports": [dn_unmanaged_to_dict(m) for m in get_dotnet_unmanaged_imports(pe)],
    }


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
