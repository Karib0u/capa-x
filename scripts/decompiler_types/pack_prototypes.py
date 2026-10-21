#!/usr/bin/env python3
"""Development-only: pack the ExportPrototypes.java TSV into a block-compressed lookup file.

usage: pack_prototypes.py INPUT.tsv OUTPUT.pack

Layout (little endian):
  magic        8 bytes  "CXPROTO1"
  block_count  u32
  per block    u32 offset (from start of data), u32 compressed length, u32 raw length,
               u16 key length, first key bytes
  data         zlib streams, one per block
Raw block: lines "key<TAB>value\\n" sorted by key. Keys are "F:<function>" and "T:<hex id>".
Blocks hold up to 96 KiB raw so one lookup inflates a small, bounded amount.
"""
import struct, sys, zlib

BLOCK = 96 * 1024

def main():
    src, dst = sys.argv[1:3]
    entries = []
    for line in open(src, encoding="utf-8"):
        line = line.rstrip("\n")
        kind, rest = line.split("\t", 1)
        if kind == "F":
            name, xml = rest.split("\t", 1)
            entries.append(("F:" + name, xml))
        elif kind == "T":
            ident, body = rest.split("\t", 1)       # body = "name<TAB>xml"
            entries.append(("T:" + ident, body))
        else:
            raise SystemExit("bad record kind " + kind)
    entries.sort()
    blocks, cur, size = [], [], 0
    for key, value in entries:
        raw = f"{key}\t{value}\n".encode("utf-8")
        if cur and size + len(raw) > BLOCK:
            blocks.append(cur); cur, size = [], 0
        cur.append((key, raw)); size += len(raw)
    if cur:
        blocks.append(cur)
    index, data = [], bytearray()
    for block in blocks:
        raw = b"".join(r for _, r in block)
        comp = zlib.compress(raw, 9)
        index.append((len(data), len(comp), len(raw), block[0][0].encode()))
        data += comp
    with open(dst, "wb") as out:
        out.write(b"CXPROTO1" + struct.pack("<I", len(index)))
        for off, clen, rlen, key in index:
            out.write(struct.pack("<IIIH", off, clen, rlen, len(key)) + key)
        out.write(data)
    print(f"{len(entries)} entries, {len(blocks)} blocks, {len(data) + 12 + sum(18 + len(i[3]) for i in index)} bytes")

main()
