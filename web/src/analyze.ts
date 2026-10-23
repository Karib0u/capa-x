import type { Analysis, DecompiledFunction } from "./types";
import { loadAssets, peArch } from "./engine/assets";
import { summarizeCapa } from "./engine/capa";
import { runEngine } from "./engine/run";
import { extractStrings } from "./engine/strings";

type Event =
  | { type: "start"; functions: number[] }
  | ({ type: "function" } & DecompiledFunction);

const message = (e: unknown) => String((e as Error)?.message ?? e);

/** Decompiler workers: each holds its own engine instance, so leave cores for capa and the page. */
function decompileWorkers() {
  const cores = navigator.hardwareConcurrency || 4;
  return Math.max(1, Math.min(4, cores - 2));
}

/**
 * Analyzes the binary entirely in the browser: capa-x's capability engine and the native Ghidra
 * decompiler both run as WebAssembly in workers. The decompiler's functions are split round-robin
 * across several workers; every result is fed into `onUpdate` as it arrives.
 */
export async function analyze(file: File, onUpdate: (a: Analysis) => void, signal: AbortSignal) {
  const a: Analysis = {
    fileName: file.name, size: file.size, strings: [], entry: null, order: [], functions: new Map(),
    capa: null, capaError: null, decompileError: null, loading: null, done: false,
  };
  let pending = false;
  const flush = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => { pending = false; onUpdate({ ...a, functions: new Map(a.functions) }); }, 80);
  };

  const bytes = await file.arrayBuffer();
  const view = new Uint8Array(bytes);
  ({ strings: a.strings, entry: a.entry } = extractStrings(view));
  const arch = peArch(view);
  flush();

  const assets = await loadAssets(arch, (p) => { a.loading = p; flush(); });
  if (signal.aborted) return;

  const capa = (async () => {
    let json = "";
    await runEngine(
      { kind: "capa", module: assets.module, sample: bytes.slice(0), data: assets.data("capa"), rules: assets.rules },
      (l) => (json += l), signal,
    );
    a.capa = summarizeCapa(JSON.parse(json));
    flush();
  })().catch((e) => { if (!signal.aborted) { a.capaError = message(e); flush(); } });

  const shards = decompileWorkers();
  const onLine = (line: string) => {
    if (!line.trim()) return;
    const e = JSON.parse(line) as Event;
    if (e.type === "start") a.order = e.functions;
    else if (e.type === "function") {
      // A callee several shards found (one recovery never listed) arrives more than once: keep the first.
      if (a.functions.has(e.address)) return;
      a.functions.set(e.address, e);
      // A callee the decompiler found that recovery never listed: make it a navigable function.
      if (!a.order.includes(e.address)) a.order = [...a.order, e.address].sort((x, y) => x - y);
    }
    flush();
  };
  const decompile = Promise.all(
    Array.from({ length: shards }, (_, i) =>
      runEngine(
        { kind: "decompile", module: assets.module, sample: bytes.slice(0), data: assets.data("decompile"), shard: [i, shards] },
        onLine, signal,
      ),
    ),
  ).catch((e) => { if (!signal.aborted) { a.decompileError = message(e); flush(); } });

  await Promise.all([capa, decompile]);
  if (signal.aborted) return;
  a.done = true;
  onUpdate({ ...a, functions: new Map(a.functions) });
}
