#!/usr/bin/env python3
"""Generate file-scope parity fixtures with the pinned Python capa implementation."""

from __future__ import annotations

import io
import json
from pathlib import Path

from capa.features.extractors.elf import detect_elf_os
from capa.features.extractors.strings import extract_ascii_strings, extract_unicode_strings


ROOT = Path(__file__).resolve().parent.parent
TESTFILES = ROOT / "tests" / "testfiles"
FIXTURES = ROOT / "capa-x" / "tests" / "fixtures" / "file-features"

STRING_SAMPLES = (
    "aarch64/c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486.elf_",
    "5e4263575796c6ea2445505a843e616111e0e540ec49441e3bb3fc99be7d3afb.elf_",
    "bb38149ff4b5c95722b83f24ca27a42b.elf_",
    "Practical Malware Analysis Lab 01-02.exe_",
    "dotnet/dd9098ff91717f4906afe9dafdfa2f52.exe_",
)


def relative_sample_paths() -> list[Path]:
    return sorted(
        path.relative_to(TESTFILES)
        for path in TESTFILES.rglob("*")
        if path.is_file() and ".git" not in path.parts
    )


def generate_elf_os() -> dict[str, str]:
    expected = {}
    for relative in relative_sample_paths():
        data = (TESTFILES / relative).read_bytes()
        if data.startswith(b"\x7fELF"):
            expected[relative.as_posix()] = detect_elf_os(io.BytesIO(data))
    return expected


def serialize_strings(data: bytes, unicode: bool) -> list[dict[str, object]]:
    extractor = extract_unicode_strings if unicode else extract_ascii_strings
    return [{"value": value.s, "offset": value.offset} for value in extractor(data)]


def generate_strings() -> dict[str, dict[str, list[dict[str, object]]]]:
    expected = {}
    for relative_text in STRING_SAMPLES:
        data = (TESTFILES / relative_text).read_bytes()
        expected[relative_text] = {
            "ascii": serialize_strings(data, unicode=False),
            "utf16le": serialize_strings(data, unicode=True),
        }
    return expected


def write_json(name: str, value: object) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    (FIXTURES / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    write_json("elf-os.json", generate_elf_os())
    write_json("strings.json", generate_strings())


if __name__ == "__main__":
    main()
