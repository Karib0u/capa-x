import type { Analysis, CapaResult, DecompiledFunction, StringEntry } from "./types";

type Event =
  | { type: "start"; functions: number[] }
  | ({ type: "function" } & DecompiledFunction)
  | ({ type: "capa" } & CapaResult)
  | { type: "capa_error" | "decompile_error"; message: string }
  | { type: "strings"; strings: StringEntry[]; entry: number | null }
  | { type: "done" };

/** Uploads the binary and feeds each streamed result into `onUpdate`. */
export async function analyze(file: File, onUpdate: (a: Analysis) => void, signal: AbortSignal) {
  const a: Analysis = {
    fileName: file.name, size: file.size, strings: [], entry: null, order: [], functions: new Map(),
    capa: null, capaError: null, decompileError: null, done: false,
  };
  let pending = false;
  const flush = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => { pending = false; onUpdate({ ...a, functions: new Map(a.functions) }); }, 80);
  };

  const res = await fetch("/api/analyze", { method: "POST", body: file, signal });
  if (!res.ok || !res.body) throw new Error((await res.text()) || `Request failed (${res.status})`);

  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  const handle = (line: string) => {
    if (!line.trim()) return;
    const e = JSON.parse(line) as Event;
    switch (e.type) {
      case "start": a.order = e.functions; break;
      case "function":
        a.functions.set(e.address, e);
        // A callee the decompiler found that recovery never listed: make it a navigable function.
        if (!a.order.includes(e.address)) a.order = [...a.order, e.address].sort((x, y) => x - y);
        break;
      case "capa": a.capa = e; break;
      case "capa_error": a.capaError = e.message; break;
      case "decompile_error": a.decompileError = e.message; break;
      case "strings": a.strings = e.strings; a.entry = e.entry; break;
      case "done": a.done = true; break;
    }
    flush();
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) { handle(buf.slice(0, i)); buf = buf.slice(i + 1); }
  }
  handle(buf);
  a.done = true;
  onUpdate({ ...a, functions: new Map(a.functions) });
}
