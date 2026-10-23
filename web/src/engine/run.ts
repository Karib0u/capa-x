import type { EngineMessage, EngineRequest } from "./engine.worker";

/**
 * Runs one WebAssembly capa-x invocation in its own worker (a fresh module per run, so its memory
 * is returned afterwards) and calls `onLine` for each stdout line as it is printed.
 */
export function runEngine(req: EngineRequest, onLine: (line: string) => void, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./engine.worker.ts", import.meta.url), { type: "module" });
    const finish = (fn: () => void) => { signal.removeEventListener("abort", onAbort); worker.terminate(); fn(); };
    const onAbort = () => finish(() => reject(new DOMException("aborted", "AbortError")));
    if (signal.aborted) return onAbort();
    signal.addEventListener("abort", onAbort);
    worker.onmessage = (ev: MessageEvent<EngineMessage>) => {
      const m = ev.data;
      if (m.type === "line") onLine(m.line);
      else if (m.type === "done") finish(resolve);
      else finish(() => reject(new Error(m.message)));
    };
    worker.onerror = (ev) => finish(() => reject(new Error(ev.message || "worker failed")));
    worker.postMessage(req, [req.sample, ...Object.values(req.data)]);
  });
}
