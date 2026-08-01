#!/usr/bin/env python3
"""
Difftest helper: run the pinned Python capa's *file-only* extractors
(`PefileFeatureExtractor` / `ElfFeatureExtractor` -- the same ones
`tests/fixtures.py` uses, not the full vivisect backend) against a raw
PE/ELF sample, and either:

  --mode dump-features: print one canonical
    "global\\t<feature>" / "file\\t<feature>\\t<address>" line per extracted
    feature, sorted -- the same shape as `capa-x-cli --dump-features`
    (capa-x-cli/src/main.rs's `print_dump_features`), so the two can be
    diffed as plain line sets.

  --mode dump-freeze: write a magic+zlib freeze file (`capa.features.
    freeze.dumps_static`, with `get_functions` patched to yield nothing,
    since the file-only extractors raise `NotImplementedError` for it) so
    the existing `scripts/difftest.py` JSON-diff machinery (which expects a
    freeze file, not a raw sample) can be reused unchanged for the matched
    file-scope-rules comparison.

The feature/address string formats here are a *from-scratch* port of
`capa_x::features::Feature`'s `Display` impl and `capa_x::address::
Address::canonical_key` (see capa-x/src/features.rs,
capa-x/src/address.rs) -- deliberately not capa's own `Feature.__str__`
(whose `get_name_str()` is `type(self).__name__.lower()`, e.g.
"functionname" not "function-name"), so this only needs to match the Rust
side, not vice versa.
"""

from __future__ import annotations

import sys
import zlib
import argparse
from pathlib import Path

MATCH_PE = b"MZ"
MATCH_ELF = b"\x7fELF"


def get_extractor(sample: Path):
    buf = sample.read_bytes()
    if buf.startswith(MATCH_PE):
        import capa.features.extractors.pefile as pefile_ext

        return pefile_ext.PefileFeatureExtractor(sample)
    elif buf.startswith(MATCH_ELF):
        import capa.features.extractors.elffile as elffile_ext

        return elffile_ext.ElfFeatureExtractor(sample)
    else:
        raise ValueError(f"not a PE or ELF file: {sample}")


def canonical_address(addr) -> str:
    from capa.features.address import _NoAddress, AbsoluteVirtualAddress, FileOffsetAddress

    # order matters: `_NoAddress.__eq__` returns `True` unconditionally
    # (see `capa/features/address.py`), so `addr == NO_ADDRESS` is a
    # tautology for *any* `addr` once Python falls back to the reflected
    # `NO_ADDRESS.__eq__(addr)` -- check the concrete `int` subclasses by
    # `isinstance` first, and use `isinstance(addr, _NoAddress)` (not `==`)
    # for the no-address case.
    if isinstance(addr, AbsoluteVirtualAddress):
        return f"absolute:{int(addr)}"
    if isinstance(addr, FileOffsetAddress):
        return f"file:{int(addr)}"
    if isinstance(addr, _NoAddress):
        return "no address"
    raise ValueError(f"unexpected address kind in file/global scope: {addr!r}")


def canonical_feature(feature) -> str:
    """
    mirrors `capa_x::features::Feature`'s `Display` impl exactly, for the
    subset of feature kinds the file-only extractors can ever produce
    (Os, Arch, Format, Characteristic, Section, Import, Export, String,
    FunctionName -- the last never actually emitted).
    """
    from capa.features.common import OS, Arch, Format, String, Characteristic
    from capa.features.file import Export, Import, Section, FunctionName

    v = feature.value
    if isinstance(feature, OS):
        return f"os({v})"
    if isinstance(feature, Arch):
        return f"arch({v})"
    if isinstance(feature, Format):
        return f"format({v})"
    if isinstance(feature, Characteristic):
        return f"characteristic({v})"
    if isinstance(feature, Section):
        return f"section({v})"
    if isinstance(feature, Import):
        return f"import({v})"
    if isinstance(feature, Export):
        return f"export({v})"
    if isinstance(feature, FunctionName):
        return f"function-name({v})"
    if isinstance(feature, String):
        return f"string({v})"
    raise ValueError(f"unexpected feature kind in file/global scope: {feature!r}")


def dump_features(sample: Path) -> list[str]:
    extractor = get_extractor(sample)

    lines = []
    for feature, _addr in extractor.extract_global_features():
        lines.append(f"global\t{canonical_feature(feature)}")
    for feature, addr in extractor.extract_file_features():
        lines.append(f"file\t{canonical_feature(feature)}\t{canonical_address(addr)}")
    lines.sort()
    return lines


def dump_freeze(sample: Path, out_path: Path) -> None:
    import capa.features.freeze as frz

    extractor = get_extractor(sample)
    # the file-only extractors NotImplementedError on function/bb/insn
    # scope; `dumps_static` always calls `get_functions()` regardless of
    # whether any rule needs function scope, so patch it to look like a
    # sample with zero recognized functions, which is exactly what the
    # file-only extractors report anyway.
    extractor.get_functions = lambda: iter([])

    doc = frz.dumps_static(extractor)
    out_path.write_bytes(frz.MAGIC + zlib.compress(doc.encode("utf-8")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["dump-features", "dump-freeze"], required=True)
    parser.add_argument("sample", type=Path)
    parser.add_argument("out", type=Path, nargs="?", help="output path (dump-freeze only)")
    args = parser.parse_args(argv)

    if args.mode == "dump-features":
        for line in dump_features(args.sample):
            print(line)
    else:
        if args.out is None:
            print("error: --mode dump-freeze requires an output path", file=sys.stderr)
            return 2
        dump_freeze(args.sample, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
