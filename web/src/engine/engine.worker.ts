// Runs one capa-x invocation (the Rust CLI compiled to WebAssembly with the Ghidra decompiler)
// against an in-memory copy of the sample. stdout lines stream back as they are printed.
import createCapaX from "../wasm/capa-x.js";

interface Common {
  /** Compiled once by the page and shared by every worker. */
  module: WebAssembly.Module;
  sample: ArrayBuffer;
  /** Signature databases and Function ID pack, mounted at `/sigs`. */
  data: Record<string, ArrayBuffer>;
}
export type EngineRequest =
  | (Common & { kind: "capa"; rules: Record<string, string> })
  | (Common & { kind: "decompile"; shard: [number, number] });

export type EngineMessage =
  | { type: "line"; line: string }
  | { type: "done" }
  | { type: "fail"; message: string };

const post = (m: EngineMessage) => (self as unknown as Worker).postMessage(m);

function mkdirs(fs: { mkdir(p: string): void }, path: string, made: Set<string>) {
  let cur = "";
  for (const part of path.split("/").filter(Boolean)) {
    cur += "/" + part;
    if (!made.has(cur)) { fs.mkdir(cur); made.add(cur); }
  }
}

self.onmessage = async (ev: MessageEvent<EngineRequest>) => {
  const req = ev.data;
  const stderr: string[] = [];
  try {
    const mod = await createCapaX({
      print: (line: string) => post({ type: "line", line }),
      printErr: (line: string) => { if (stderr.length < 50) stderr.push(line); },
      instantiateWasm: (imports, success) => {
        WebAssembly.instantiate(req.module, imports).then((instance) => success(instance, req.module));
        return {};
      },
    });
    mod.FS.mkdir("/sigs");
    for (const [name, bytes] of Object.entries(req.data)) mod.FS.writeFile("/sigs/" + name, new Uint8Array(bytes));
    mod.FS.writeFile("/sample.bin", new Uint8Array(req.sample));
    let args: string[];
    if (req.kind === "capa") {
      const made = new Set<string>(["/rules"]);
      mod.FS.mkdir("/rules");
      for (const [path, text] of Object.entries(req.rules)) {
        const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
        if (dir) mkdirs(mod.FS, "/rules/" + dir, made);
        mod.FS.writeFile("/rules/" + path, text);
      }
      // No threads in the browser build: --jobs 1 is the serial reference path.
      args = ["/sample.bin", "--json", "--jobs", "1", "--rules", "/rules"];
    } else {
      args = ["/sample.bin", "--decompile-all", "--shard", `${req.shard[0]}/${req.shard[1]}`];
    }
    let code = 0;
    try { code = mod.callMain(args) ?? 0; } catch (e) {
      const status = (e as { status?: number }).status;
      if (typeof status !== "number") throw e;
      code = status;
    }
    if (code !== 0) post({ type: "fail", message: stderr.join("\n").trim() || `capa-x exited with status ${code}` });
    else post({ type: "done" });
  } catch (e) {
    post({ type: "fail", message: String((e as Error)?.message ?? e) });
  }
};
