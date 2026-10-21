#!/usr/bin/env python3
"""Development-only: pack the ExportFid.java output into the compact FID lookup file.

usage: pack_fid.py EXPORT_DIR OUTPUT.pack [--variants Release] DB_NAME...

EXPORT_DIR holds N.libs.tsv, N.funcs.tsv, N.sup.bin and N.inf.bin for each DB_NAME.

Layout (little endian), every offset from the start of the file:
  header (64 bytes)
    magic "CXFID001", u32 n_records, u32 n_names, u32 n_dbs, u32 name_block_raw,
    u32 off_fh, u32 off_rec, u32 off_name_index, u32 off_name_blocks, u32 off_rel,
    zero padding
  fh[n_records]           u64, ascending (the full hash)
  rec[n_records]          17 bytes: u32 specific_hash (low 32 bits), u40 function key (low 40 bits),
                          u16 code_units, i8 specific_additional, u8 flags, u8 db, u24 name id
                          flags: 1 terminator, 2 auto pass, 4 auto fail, 8 force specific, 16 force relation
  name_index[n_names + 1] u32 offset into the raw name stream (names are NUL terminated, sorted)
  name_blocks             u32 count, count * (u32 raw_start, u32 comp_off, u32 comp_len), zlib streams;
                          a block holds whole names
  relations               u32 set_count (= 2 * n_dbs), then per set (superior, inferior per db):
                          u32 offset, u32 count, u32 reserved; each set is
                          u32 bucket_start[4097] followed by u24 remainder[count], where a 36-bit
                          smash key splits into bucket = key >> 24 and remainder = key & 0xffffff

A relation smash key is (function_key * FNV_PRIME) ^ other_full_hash, kept to 36 bits. Only the low
36 bits of a function key matter, because multiplication never carries downwards.
"""
import struct, sys, zlib, collections

PRIME = 1099511628211
M64 = (1 << 64) - 1
M40 = (1 << 40) - 1
M36 = (1 << 36) - 1
NAME_BLOCK = 64 * 1024


def main():
    args = sys.argv[1:]
    variants = None
    if "--variants" in args:
        i = args.index("--variants")
        variants = set(args[i + 1].split(","))
        del args[i : i + 2]
    export, dst, dbs = args[0], args[1], args[2:]
    records, names = [], set()
    sets = []
    for db_index, db in enumerate(dbs):
        libs = {}
        for line in open(f"{export}/{db}.libs.tsv", encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            libs[int(p[0])] = (p[1], p[2], p[3])
        for line in open(f"{export}/{db}.funcs.tsv", encoding="utf-8", errors="replace"):
            p = line.rstrip("\n").split("\t")
            variant = libs[int(p[1])][2]
            if variants and variant not in variants:
                continue
            name = p[7]
            if not name or "\0" in name:
                continue
            names.add(name)
            records.append(
                dict(
                    fh=int(p[2], 16),
                    sh=int(p[5], 16) & 0xFFFFFFFF,
                    key=int(p[0]) & M40,
                    cus=int(p[3]),
                    add=int(p[4]),
                    flags=int(p[6]),
                    db=db_index,
                    name=name,
                )
            )
        for kind in ("sup", "inf"):
            raw = open(f"{export}/{db}.{kind}.bin", "rb").read()
            keys = struct.unpack("<%dQ" % (len(raw) // 8), raw)
            sets.append(sorted({k & M36 for k in keys}))
    sorted_names = sorted(names)
    ids = {n: i for i, n in enumerate(sorted_names)}
    if len(sorted_names) >= 1 << 24:
        raise SystemExit("too many names")
    records.sort(key=lambda r: (r["fh"], ids[r["name"]], r["db"], r["key"]))

    # Names: raw stream, whole names per compressed block.
    index, blocks, raw_pos = [], [], 0
    cur, cur_start = bytearray(), 0
    for n in sorted_names:
        data = n.encode("utf-8") + b"\0"
        if cur and len(cur) + len(data) > NAME_BLOCK:
            blocks.append((cur_start, bytes(cur)))
            cur_start += len(cur)
            cur = bytearray()
        index.append(raw_pos)
        cur += data
        raw_pos += len(data)
    if cur:
        blocks.append((cur_start, bytes(cur)))
    index.append(raw_pos)
    comp, name_blocks = bytearray(), []
    for start, raw in blocks:
        z = zlib.compress(raw, 9)
        name_blocks.append((start, len(comp), len(z)))
        comp += z

    fh = b"".join(struct.pack("<Q", r["fh"]) for r in records)
    rec = bytearray()
    for r in records:
        rec += struct.pack("<I", r["sh"]) + r["key"].to_bytes(5, "little")
        rec += struct.pack("<HbBB", r["cus"], r["add"], r["flags"] & 0xFF, r["db"])
        rec += ids[r["name"]].to_bytes(3, "little")
    assert len(rec) == 17 * len(records)
    index_bytes = b"".join(struct.pack("<I", i) for i in index)

    # Relations.
    rel_bodies, rel_table = [], []
    for keys in sets:
        starts = [0] * 4098
        for k in keys:
            starts[(k >> 24) + 1] += 1
        for i in range(4097):
            starts[i + 1] += starts[i]
        body = b"".join(struct.pack("<I", s) for s in starts[:4097])
        body += b"".join((k & 0xFFFFFF).to_bytes(3, "little") for k in keys)
        rel_bodies.append(body)
        rel_table.append((len(keys), 0))

    out = bytearray(64)
    off_fh = len(out); out += fh
    off_rec = len(out); out += rec
    off_idx = len(out); out += index_bytes
    off_blk = len(out)
    out += struct.pack("<I", len(name_blocks))
    data_start = len(out) + 12 * len(name_blocks)
    for start, off, clen in name_blocks:
        out += struct.pack("<III", start, data_start + off, clen)
    out += comp
    off_rel = len(out)
    out += struct.pack("<I", len(sets))
    body_start = len(out) + 12 * len(sets)
    cursor = body_start
    for (count, bits), body in zip(rel_table, rel_bodies):
        out += struct.pack("<III", cursor, count, bits)
        cursor += len(body)
    for body in rel_bodies:
        out += body
    header = b"CXFID001" + struct.pack(
        "<IIIIIIIII", len(records), len(sorted_names), len(dbs), NAME_BLOCK, off_fh, off_rec, off_idx, off_blk, off_rel
    )
    out[: len(header)] = header
    open(dst, "wb").write(out)
    print(
        f"{len(records)} records, {len(sorted_names)} names, {sum(len(s) for s in sets)} relation keys, "
        f"{len(out)} bytes (records {len(fh) + len(rec)}, names {len(index_bytes) + len(comp)}, "
        f"relations {sum(len(b) for b in rel_bodies)})"
    )


main()
