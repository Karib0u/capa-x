// Tiny local API: POST /api/analyze with the raw binary as the body.
// Runs capa-x (capabilities) and capa-x --decompile-all concurrently and
// streams a single NDJSON response so the UI can render as results arrive.
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const BIN = process.env.CAPA_X_BIN ?? join(root, "target/release/capa-x");
const MAX_BYTES = 256 * 1024 * 1024;
const PORT = Number(process.env.PORT ?? 8787);

async function findRules() {
  const candidates = [process.env.CAPA_RULES_DIR, join(root, "rules")];
  // In a git worktree the rules submodule may be uninitialised; look in the main checkout too.
  const m = root.match(/^(.*)\/\.claude\/worktrees\//);
  if (m) candidates.push(join(m[1], "rules"));
  for (const c of candidates) {
    if (!c) continue;
    try { await access(join(c, "anti-analysis")); return c; } catch {}
  }
  return null;
}

const MAX_STRINGS = 20000;

/** ASCII and UTF-16LE strings (>= 5 chars) mapped to virtual addresses via the PE section table. */
function extractStrings(buf) {
  let sections = [], base = 0n, entryRva = 0;
  try {
    const pe = buf.readUInt32LE(0x3c);
    if (buf.toString("latin1", pe, pe + 4) !== "PE\0\0") return { strings: [], entry: null };
    const n = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20), opt = pe + 24;
    base = buf.readUInt16LE(opt) === 0x20b ? buf.readBigUInt64LE(opt + 24) : BigInt(buf.readUInt32LE(opt + 28));
    entryRva = buf.readUInt32LE(opt + 16);
    for (let i = 0; i < n; i++) {
      const o = opt + optSize + i * 40;
      sections.push({ va: buf.readUInt32LE(o + 12), size: buf.readUInt32LE(o + 8), raw: buf.readUInt32LE(o + 20), rawSize: buf.readUInt32LE(o + 16) });
    }
  } catch { return { strings: [], entry: null }; }
  const toVa = (off) => {
    for (const s of sections) if (off >= s.raw && off < s.raw + Math.min(s.rawSize, s.size || s.rawSize)) return Number(base) + s.va + (off - s.raw);
    return null;
  };
  const out = [];
  const push = (off, text, wide) => {
    const a = toVa(off);
    // Drop machine code and padding that happens to be printable: needs mostly alphanumerics and a 3-letter run.
    const alnum = (text.match(/[A-Za-z0-9]/g) ?? []).length;
    if (alnum / text.length < 0.4 || !/[A-Za-z]{3}/.test(text)) return;
    if (a !== null) out.push({ a, s: text.length > 400 ? text.slice(0, 400) + "…" : text, w: wide });
  };
  const MIN = 5, printable = (c) => (c >= 0x20 && c < 0x7f) || c === 9;
  for (let i = 0; i < buf.length;) {
    let j = i;
    while (j < buf.length && printable(buf[j])) j++;
    if (j - i >= MIN) push(i, buf.toString("latin1", i, j), false);
    i = j + 1;
  }
  for (let i = 0; i + 1 < buf.length;) {
    let j = i;
    while (j + 1 < buf.length && buf[j + 1] === 0 && printable(buf[j])) j += 2;
    if ((j - i) / 2 >= MIN) push(i, buf.toString("utf16le", i, j), true);
    i = j > i ? j : i + 1;
  }
  return { strings: out.sort((x, y) => x.a - y.a).slice(0, MAX_STRINGS), entry: Number(base) + entryRva };
}

const addr = (a) => (a && a.type === "absolute" ? a.value : null);

function summarizeCapa(doc) {
  const rules = Object.values(doc.rules).map((r) => {
    const m = r.meta;
    const scope = m.scopes?.static ?? Object.values(m.scopes ?? {})[0] ?? "file";
    const addresses = r.matches.map(([a]) => addr(a)).filter((a) => a !== null);
    return {
      name: m.name, namespace: m.namespace ?? null, scope, lib: !!m.lib,
      attack: (m.attack ?? []).map((a) => ({ id: a.id, tactic: a.tactic, technique: a.technique, subtechnique: a.subtechnique })),
      mbc: (m.mbc ?? []).map((b) => ({ id: b.id, objective: b.objective, behavior: b.behavior, method: b.method })),
      description: m.description ?? "", count: r.matches.length, addresses,
    };
  });
  const a = doc.meta.analysis;
  return {
    sample: { md5: doc.meta.sample.md5, sha256: doc.meta.sample.sha256 },
    format: a.format, arch: a.arch, os: a.os, baseAddress: addr(a.base_address),
    rules,
  };
}

function run(cmd, args, env, onLine) {
  return new Promise((ok, fail) => {
    const p = spawn(cmd, args, { env: { ...process.env, ...env } });
    let err = "", buf = "";
    p.stderr.on("data", (d) => (err += d));
    p.stdout.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); }
    });
    p.on("error", fail);
    p.on("close", (code) => { if (buf) onLine(buf); code === 0 ? ok() : fail(new Error(err.trim() || `exit ${code}`)); });
  });
}

async function analyze(req, res) {
  const chunks = []; let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BYTES) { res.writeHead(413).end("file too large"); return; }
    chunks.push(c);
  }
  if (!size) { res.writeHead(400).end("empty body"); return; }
  const rules = await findRules();
  if (!rules) { res.writeHead(500).end("capa rules not found: set CAPA_RULES_DIR"); return; }

  const dir = await mkdtemp(join(tmpdir(), "capa-x-web-"));
  const file = join(dir, "sample.bin");
  await writeFile(file, Buffer.concat(chunks));

  res.writeHead(200, { "content-type": "application/x-ndjson", "cache-control": "no-store" });
  const send = (o) => res.write(JSON.stringify(o) + "\n");
  const aborted = new AbortController();
  res.on("close", () => aborted.abort());

  const { strings, entry } = extractStrings(Buffer.concat(chunks));
  send({ type: "strings", strings, entry });

  const capa = (async () => {
    let json = "";
    await run(BIN, [file, "--json"], { CAPA_RULES_DIR: rules }, (l) => (json += l));
    send({ type: "capa", ...summarizeCapa(JSON.parse(json)) });
  })().catch((e) => send({ type: "capa_error", message: String(e.message ?? e) }));

  const decomp = run(BIN, [file, "--decompile-all"], {}, (l) => {
    if (l.trim()) res.write(l + "\n");
  }).catch((e) => send({ type: "decompile_error", message: String(e.message ?? e) }));

  await Promise.all([capa, decomp]);
  send({ type: "done" });
  res.end();
  rm(dir, { recursive: true, force: true }).catch(() => {});
}

http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/analyze") {
    analyze(req, res).catch((e) => { if (!res.headersSent) res.writeHead(500); res.end(String(e)); });
  } else res.writeHead(404).end();
}).listen(PORT, "127.0.0.1", () => console.log(`capa-x api on http://127.0.0.1:${PORT} (bin: ${BIN})`));
