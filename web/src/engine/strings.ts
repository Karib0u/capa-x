import type { StringEntry } from "../types";

const MAX_STRINGS = 20000;
const MIN = 5;

/** ASCII and UTF-16LE strings (>= 5 chars) mapped to virtual addresses via the PE section table. */
export function extractStrings(buf: Uint8Array): { strings: StringEntry[]; entry: number | null } {
  const none = { strings: [], entry: null };
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const sections: { va: number; size: number; raw: number; rawSize: number }[] = [];
  let base = 0n, entryRva = 0;
  try {
    const pe = dv.getUint32(0x3c, true);
    if (dv.getUint32(pe, true) !== 0x4550) return none;
    const n = dv.getUint16(pe + 6, true), optSize = dv.getUint16(pe + 20, true), opt = pe + 24;
    base = dv.getUint16(opt, true) === 0x20b ? dv.getBigUint64(opt + 24, true) : BigInt(dv.getUint32(opt + 28, true));
    entryRva = dv.getUint32(opt + 16, true);
    for (let i = 0; i < n; i++) {
      const o = opt + optSize + i * 40;
      sections.push({ va: dv.getUint32(o + 12, true), size: dv.getUint32(o + 8, true), raw: dv.getUint32(o + 20, true), rawSize: dv.getUint32(o + 16, true) });
    }
  } catch { return none; }

  const toVa = (off: number) => {
    for (const s of sections) if (off >= s.raw && off < s.raw + Math.min(s.rawSize, s.size || s.rawSize)) return Number(base) + s.va + (off - s.raw);
    return null;
  };
  const out: StringEntry[] = [];
  const push = (off: number, text: string, w: boolean) => {
    // Drop machine code and padding that happens to be printable: needs mostly alphanumerics and a 3-letter run.
    const alnum = (text.match(/[A-Za-z0-9]/g) ?? []).length;
    if (alnum / text.length < 0.4 || !/[A-Za-z]{3}/.test(text)) return;
    const a = toVa(off);
    if (a !== null) out.push({ a, s: text.length > 400 ? text.slice(0, 400) + "…" : text, w });
  };
  const printable = (c: number) => (c >= 0x20 && c < 0x7f) || c === 9;
  const latin1 = new TextDecoder("latin1"), utf16 = new TextDecoder("utf-16le");

  for (let i = 0; i < buf.length;) {
    let j = i;
    while (j < buf.length && printable(buf[j])) j++;
    if (j - i >= MIN) push(i, latin1.decode(buf.subarray(i, j)), false);
    i = j + 1;
  }
  for (let i = 0; i + 1 < buf.length;) {
    let j = i;
    while (j + 1 < buf.length && buf[j + 1] === 0 && printable(buf[j])) j += 2;
    if ((j - i) / 2 >= MIN) push(i, utf16.decode(buf.subarray(i, j)), true);
    i = j > i ? j : i + 1;
  }
  return { strings: out.sort((x, y) => x.a - y.a).slice(0, MAX_STRINGS), entry: Number(base) + entryRva };
}
