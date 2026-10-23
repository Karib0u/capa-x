// Everything the engine needs from the network, downloaded once per page load with aggregate
// progress: the compiled wasm module, the FLIRT signature databases, the Function ID pack for the
// sample's architecture, and the capa rules.
import wasmUrl from "../wasm/capa_x.wasm?url";

export type Arch = "x64" | "x86" | null;
export interface Progress { label: string; fraction: number | null }

const base = import.meta.env.BASE_URL;
const SIGNATURES = ["1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig", "3_flare_common_libs.sig"];

interface Download { loaded: number; total: number | null }
const downloads = new Map<string, Download>();
const cache = new Map<string, Promise<Uint8Array<ArrayBuffer>>>();
let listener: ((p: Progress) => void) | null = null;

function report() {
  if (!listener) return;
  if (!downloads.size) return listener({ label: "Starting analysis engine", fraction: null });
  let loaded = 0, total = 0, known = true;
  for (const d of downloads.values()) {
    loaded += d.loaded;
    if (d.total === null) known = false; else total += d.total;
  }
  const mb = (n: number) => (n / 1048576).toFixed(0);
  listener({
    label: known && total ? `Downloading analysis engine · ${mb(loaded)} / ${mb(total)} MB` : `Downloading analysis engine · ${mb(loaded)} MB`,
    fraction: known && total ? Math.min(1, loaded / total) : null,
  });
}

/** Fetches `url` once (later callers share the result), reporting bytes as they arrive. */
function download(url: string): Promise<Uint8Array<ArrayBuffer>> {
  let hit = cache.get(url);
  if (!hit) {
    hit = (async () => {
      const res = await fetch(url);
      if (!res.ok || !res.body) throw new Error(`could not download ${url} (${res.status}); run \`npm run prepare-assets\``);
      // With content-encoding the header holds the compressed size, not what the stream yields.
      const length = Number(res.headers.get("content-length"));
      const entry: Download = { loaded: 0, total: res.headers.get("content-encoding") || !length ? null : length };
      downloads.set(url, entry);
      const chunks: Uint8Array[] = [];
      const reader = res.body.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
        entry.loaded += value.length;
        report();
      }
      const out = new Uint8Array(entry.loaded);
      let at = 0;
      for (const c of chunks) { out.set(c, at); at += c.length; }
      entry.total = entry.loaded;
      report();
      return out;
    })();
    hit.catch(() => cache.delete(url));
    cache.set(url, hit);
  }
  return hit;
}

let wasmModule: Promise<WebAssembly.Module> | null = null;
const loadModule = () => (wasmModule ??= download(wasmUrl).then((b) => WebAssembly.compile(b)).catch((e) => { wasmModule = null; throw e; }));

export interface Assets {
  module: WebAssembly.Module;
  /** Files for the module's `/sigs`. Fresh copies per call, since workers take ownership. */
  data(kind: "capa" | "decompile"): Record<string, ArrayBuffer>;
  rules: Record<string, string>;
}

export async function loadAssets(arch: Arch, onProgress: (p: Progress | null) => void): Promise<Assets> {
  downloads.clear();
  listener = onProgress;
  report();
  try {
    const fid = arch ? `fid-${arch}.pack` : null;
    const [module, sigs, pack, rules] = await Promise.all([
      loadModule(),
      Promise.all(SIGNATURES.map((n) => download(`${base}sigs/${n}`))),
      fid ? download(`${base}sigs/${fid}`) : Promise.resolve(null),
      download(`${base}rules.json`).then((b) => JSON.parse(new TextDecoder().decode(b)) as Record<string, string>),
    ]);
    const copy = (b: Uint8Array<ArrayBuffer>) => b.slice().buffer;
    return {
      module,
      rules,
      data(kind) {
        const files: Record<string, ArrayBuffer> = {};
        SIGNATURES.forEach((n, i) => (files[n] = copy(sigs[i])));
        if (kind === "decompile" && fid && pack) files[fid] = copy(pack);
        return files;
      },
    };
  } finally {
    listener = null;
    onProgress(null);
  }
}

/** The PE machine type, enough to pick the Function ID pack. */
export function peArch(buf: Uint8Array): Arch {
  if (buf.length < 0x40) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const pe = dv.getUint32(0x3c, true);
  if (pe + 6 > buf.length || dv.getUint32(pe, true) !== 0x4550) return null;
  const machine = dv.getUint16(pe + 4, true);
  return machine === 0x8664 ? "x64" : machine === 0x14c ? "x86" : null;
}
