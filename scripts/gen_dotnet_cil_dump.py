#!/usr/bin/env python3
"""Dump the decoded CIL model for the pinned .NET corpus using pinned
Python `dnfile`/`dncil`/capa, as the oracle for capa-x's Rust CIL decoder and
call graph.

Float operands (ldc.r4/ldc.r8) are dumped as their raw IEEE-754 bit pattern
(a u32/u64), not as a JSON float, so NaN/Infinity/-0.0 compare exactly
without depending on JSON's non-standard NaN/Infinity literals.

Usage: .venv/bin/python3 scripts/gen_dotnet_cil_dump.py > \
    capa-x/tests/fixtures/dotnet/cil_dump.json
"""

import json
import struct
import sys
from pathlib import Path
from typing import Optional

from dncil.clr.local import Local
from dncil.clr.token import Token, StringToken
from dncil.clr.argument import Argument
from dncil.cil.instruction import Instruction

from capa.features.extractors.dnfile.extractor import DnfileFeatureExtractor
from capa.features.extractors.dnfile.helpers import get_dotnet_managed_method_bodies


def operand_to_dict(operand) -> dict:
    if operand is None:
        return {"kind": "none"}
    if isinstance(operand, StringToken):
        return {"kind": "string_token", "value": operand.value}
    if isinstance(operand, Token):
        return {"kind": "token", "value": operand.value}
    if isinstance(operand, Local):
        return {"kind": "local", "value": operand.index}
    if isinstance(operand, Argument):
        return {"kind": "argument", "value": operand.index}
    if isinstance(operand, list):
        return {"kind": "switch", "value": list(operand)}
    if isinstance(operand, bool):
        raise TypeError("unexpected bool operand")
    if isinstance(operand, int):
        return {"kind": "int", "value": operand}
    if isinstance(operand, float):
        # ldc.r4 operands are still Python floats (dncil always reads them
        # as 64-bit); the *opcode* (not the operand type) tells a reader
        # which width was on the wire, so dump both possible bit widths and
        # let the Rust side pick the one that matches its own read width.
        return {
            "kind": "float",
            "bits64": struct.unpack("<Q", struct.pack("<d", operand))[0],
            "bits32": struct.unpack("<I", struct.pack("<f", operand))[0],
        }
    raise TypeError(f"unhandled operand type: {type(operand)}")


def instruction_to_dict(insn: Instruction) -> dict:
    return {
        "offset": insn.offset,
        "mnemonic": insn.mnemonic,
        "size": insn.size,
        "operand": operand_to_dict(insn.operand),
    }


def exception_handler_to_dict(eh) -> dict:
    return {
        "exception_type": eh.exception_type,
        "try_start": eh.try_start,
        "try_end": eh.try_end,
        "filter_start": eh.filter_start,
        "handler_start": eh.handler_start,
        "handler_end": eh.handler_end,
        "catch_type": eh.catch_type.value if eh.catch_type is not None else None,
    }


def function_to_dict(token: int, body) -> dict:
    return {
        "token": token,
        "offset": body.offset,
        "header_size": body.header_size,
        "code_size": body.code_size,
        "max_stack": body.max_stack,
        "size": body.size,
        "is_tiny": body.flags.is_tiny(),
        "is_fat": body.flags.is_fat(),
        "more_sects": body.flags.MoreSects,
        "instructions": [instruction_to_dict(i) for i in body.instructions],
        "exception_handlers": [exception_handler_to_dict(e) for e in body.exception_handlers],
    }


def dump_one(path: Path) -> dict:
    functions = {token: function_to_dict(token, body) for token, body in get_dotnet_managed_method_bodies_ordered(path)}

    extractor = DnfileFeatureExtractor(path)
    calls_to: dict[str, list[int]] = {}
    calls_from: dict[str, list[int]] = {}
    order: list[int] = []
    for fh in extractor.get_functions():
        token = int(fh.address)
        order.append(token)
        calls_to[str(token)] = sorted(int(a) for a in fh.ctx["calls_to"])
        calls_from[str(token)] = sorted(int(a) for a in fh.ctx["calls_from"])

    return {
        "order": order,
        "functions": functions,
        "calls_to": calls_to,
        "calls_from": calls_from,
    }


def get_dotnet_managed_method_bodies_ordered(path: Path):
    import dnfile

    pe = dnfile.dnPE(str(path))
    return list(get_dotnet_managed_method_bodies(pe))


def main() -> None:
    corpus_dir = Path("tests/testfiles/dotnet")
    samples = sorted(p for p in corpus_dir.iterdir() if p.suffix in (".exe_", ".dll_"))
    out = {}
    for sample in samples:
        out[sample.name] = dump_one(sample)
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
