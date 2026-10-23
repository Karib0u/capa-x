import { useEffect, useMemo, useRef, useState } from "react";
import DropZone from "./DropZone";
import { Code, unescapeLiteral } from "./highlight";
import { analyze } from "./analyze";
import type { Analysis, CapaRule, StringEntry } from "./types";

/** The one name a function goes by everywhere: its recovered name, else Ghidra's FUN_ label. */
const fnLabel = (ad: number, name?: string | null) => name ?? "FUN_" + ad.toString(16).padStart(8, "0");
const hex = (n: number) => "0x" + n.toString(16);
const bytes = (n: number) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB");

export default function App() {
  const [a, setA] = useState<Analysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);

  const start = (file: File) => {
    abort.current?.abort();
    const ctl = (abort.current = new AbortController());
    setError(null);
    setA({ fileName: file.name, size: file.size, order: [], strings: [], entry: null, functions: new Map(), capa: null, capaError: null, decompileError: null, done: false });
    analyze(file, setA, ctl.signal).catch((e) => {
      if (ctl.signal.aborted) return;
      setA(null);
      setError(String(e.message ?? e));
    });
  };

  if (!a) return <DropZone onFile={start} error={error} />;
  return <Workspace a={a} onNew={() => { abort.current?.abort(); setA(null); }} onFile={start} />;
}

/** Maps every function-or-smaller rule match onto its containing function. */
function useFunctionRules(a: Analysis) {
  return useMemo(() => {
    const byFn = new Map<number, CapaRule[]>();
    const fileLevel: CapaRule[] = [];
    const order = a.order;
    const owner = (addr: number) => {
      let lo = 0, hi = order.length - 1, r = -1;
      while (lo <= hi) { const mid = (lo + hi) >> 1; if (order[mid] <= addr) { r = mid; lo = mid + 1; } else hi = mid - 1; }
      return r < 0 ? null : order[r];
    };
    for (const rule of a.capa?.rules ?? []) {
      if (rule.lib) continue;
      const owners = new Set<number>();
      if (rule.scope !== "file") for (const ad of rule.addresses) { const o = owner(ad); if (o !== null) owners.add(o); }
      if (!owners.size) { fileLevel.push(rule); continue; }
      for (const o of owners) byFn.set(o, [...(byFn.get(o) ?? []), rule]);
    }
    return { byFn, fileLevel };
  }, [a.order, a.capa]);
}

function Workspace({ a, onNew, onFile }: { a: Analysis; onNew: () => void; onFile: (f: File) => void }) {
  const { byFn, fileLevel } = useFunctionRules(a);
  type Sel = number | "capa" | "strings";
  const [nav, setNav] = useState<{ stack: Sel[]; i: number }>({ stack: ["capa"], i: 0 });
  const sel = nav.stack[nav.i];
  const touched = useRef(false);
  const setSel = (s: Sel) => { touched.current = true; setNav((n) => n.stack[n.i] === s ? n : { stack: [...n.stack.slice(0, n.i + 1), s], i: n.i + 1 }); };
  const back = () => { touched.current = true; setNav((n) => ({ ...n, i: Math.max(0, n.i - 1) })); };
  const forward = () => { touched.current = true; setNav((n) => ({ ...n, i: Math.min(n.stack.length - 1, n.i + 1) })); };
  const [q, setQ] = useState("");
  const [strQuery, setStrQuery] = useState("");
  const [onlyCaps, setOnlyCaps] = useState(false);
  const [dragging, setDragging] = useState(false);

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return a.order.filter((ad) => {
      if (onlyCaps && !byFn.has(ad)) return false;
      if (!needle) return true;
      const f = a.functions.get(ad);
      return hex(ad).includes(needle) || (f?.name ?? "").toLowerCase().includes(needle) ||
        (byFn.get(ad) ?? []).some((r) => r.name.toLowerCase().includes(needle));
    });
  }, [a.order, a.functions, q, onlyCaps, byFn]);

  // Keyboard: j/k or arrows move through the visible list.
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === "INPUT") return;
      if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) { e.preventDefault(); (e.key === "ArrowLeft" ? back : forward)(); return; }
      const dir = e.key === "ArrowDown" || e.key === "j" ? 1 : e.key === "ArrowUp" || e.key === "k" ? -1 : 0;
      if (!dir) return;
      e.preventDefault();
      const i = typeof sel === "number" ? list.indexOf(sel) : -1;
      const next = list[Math.min(list.length - 1, Math.max(0, i + dir))];
      if (next !== undefined) setSel(next);
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [list, sel]);

  // Open on `main` when it has been recognised, else on the entry point, until the user picks something.
  useEffect(() => {
    if (touched.current || !a.order.length) return;
    const named = a.order.find((ad) => /^_*(w|t)?(win)?main(crt)?$/i.test(a.functions.get(ad)?.name ?? ""));
    const owner = a.entry === null ? undefined : [...a.order].reverse().find((x) => x <= a.entry!);
    const target = named ?? owner;
    if (target !== undefined) setNav((n) => (n.stack.length === 1 && n.stack[0] !== target ? { stack: [target], i: 0 } : n));
  }, [a.order, a.entry, a.functions]);

  const total = a.order.length;
  const done = a.functions.size;
  const totalCaps = (a.capa?.rules ?? []).filter((r) => !r.lib).length;
  const progress = total ? done / total : 0;
  const goto = (ad: number) => {
    const o = a.order.filter((x) => x <= ad).pop();
    if (o !== undefined) setSel(o);
  };

  // Cross-references are derived from the decompiled text: any identifier or hex literal that names a function.
  const byName = useMemo(() => {
    const m = new Map<string, number>();
    for (const ad of a.order) {
      m.set("FUN_" + ad.toString(16).padStart(8, "0"), ad);
      const n = a.functions.get(ad)?.name;
      if (n) m.set(n, ad);
    }
    return m;
  }, [a.order, a.functions]);
  const resolve = (tok: string) => {
    const hit = byName.get(tok);
    if (hit !== undefined) return hit;
    return /^0x[0-9a-f]+$/i.test(tok) && a.order.includes(parseInt(tok, 16)) ? parseInt(tok, 16) : undefined;
  };
  const { callees, callers } = useMemo(() => {
    const callees = new Map<number, number[]>(), callers = new Map<number, number[]>();
    if (!a.done) return { callees, callers };
    const known = new Set(a.order);
    for (const [ad, f] of a.functions) {
      if (!f.text) continue;
      const out = new Set<number>();
      for (const t of f.text.match(/\b[A-Za-z_]\w*\b|\b0x[0-9a-fA-F]+\b/g) ?? []) {
        const hit = byName.get(t) ?? (t.startsWith("0x") && known.has(parseInt(t, 16)) ? parseInt(t, 16) : undefined);
        if (hit !== undefined && hit !== ad) out.add(hit);
      }
      callees.set(ad, [...out].sort((x, y) => x - y));
      for (const c of out) callers.set(c, [...(callers.get(c) ?? []), ad]);
    }
    return { callees, callers };
  }, [a.done, a.functions, a.order, byName]);

  // String xrefs: a function references a string when its text names the string's address,
  // either as a hex literal or as the address suffix of a Ghidra label (DAT_00412345, s_foo_00412345).
  const { strRefs, fnStrings } = useMemo(() => {
    const strRefs = new Map<number, number[]>(), fnStrings = new Map<number, number[]>();
    if (!a.done) return { strRefs, fnStrings };
    const known = new Set(a.strings.map((x) => x.a));
    const byText = new Map<string, number[]>();
    for (const x of a.strings) byText.set(x.s, [...(byText.get(x.s) ?? []), x.a]);
    for (const [ad, f] of a.functions) {
      if (!f.text) continue;
      const hits = new Set<number>();
      // The decompiler often prints a string inline (L"...") instead of naming its address.
      for (const lit of f.text.match(/L?"(?:\\.|[^"\\\n])*"/g) ?? []) for (const v of byText.get(unescapeLiteral(lit)) ?? []) hits.add(v);
      for (const t of f.text.match(/\b0x[0-9a-fA-F]{5,16}\b|\b[A-Za-z_]\w*_[0-9a-fA-F]{6,16}\b/g) ?? []) {
        const v = parseInt(t.startsWith("0x") ? t : t.slice(t.lastIndexOf("_") + 1), 16);
        if (known.has(v)) hits.add(v);
      }
      if (!hits.size) continue;
      fnStrings.set(ad, [...hits].sort((x, y) => x - y));
      for (const h of hits) strRefs.set(h, [...(strRefs.get(h) ?? []), ad]);
    }
    return { strRefs, fnStrings };
  }, [a.done, a.functions, a.strings]);
  const strByAddr = useMemo(() => new Map(a.strings.map((x) => [x.a, x])), [a.strings]);
  const showString = (text: string) => { setStrQuery(text); setSel("strings"); };

  return (
    <div className="app"
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false); }}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}>
      <header>
        <div className="brand sm" onClick={onNew}>capa<span>-x</span></div>
        <div className="file">
          <b>{a.fileName}</b>
          <span>{bytes(a.size)}{a.capa && ` · ${a.capa.format.toUpperCase()} ${a.capa.arch}`}</span>
        </div>
        <div className="status">
          {a.decompileError ? "Decompiler unavailable for this file" : a.done ? `${total} functions · ${totalCaps} capabilities` : total ? `Decompiling ${done}/${total}` : "Analyzing…"}
        </div>
        <div className="navbtns">
          <button className="ghost" onClick={back} disabled={nav.i === 0} title="Back (Alt+←)">←</button>
          <button className="ghost" onClick={forward} disabled={nav.i >= nav.stack.length - 1} title="Forward (Alt+→)">→</button>
        </div>
        <button className="ghost" onClick={onNew}>New</button>
        {!a.done && <div className="bar"><i style={{ width: `${Math.max(4, progress * 100)}%` }} /></div>}
      </header>

      <div className="body">
        <aside>
          <button className={"item overview" + (sel === "capa" ? " on" : "")} onClick={() => setSel("capa")}>
            <span>Capabilities</span><em>{a.capa ? totalCaps : "…"}</em>
          </button>
          <button className={"item overview" + (sel === "strings" ? " on" : "")} onClick={() => setSel("strings")}>
            <span>Strings</span><em>{a.strings.length || (a.done ? 0 : "…")}</em>
          </button>
          <div className="tools">
            <input placeholder="Filter functions" value={q} onChange={(e) => setQ(e.target.value)} />
            <label title="Only functions with capa matches">
              <input type="checkbox" checked={onlyCaps} onChange={(e) => setOnlyCaps(e.target.checked)} /> capa only
            </label>
          </div>
          <div className="list">
            {list.map((ad) => {
              const f = a.functions.get(ad);
              const rules = byFn.get(ad);
              return (
                <button key={ad} className={"item" + (sel === ad ? " on" : "")} onClick={() => setSel(ad)} ref={(el) => { if (el && sel === ad) el.scrollIntoView({ block: "nearest" }); }}>
                  <span className="fn">
                    <code>{fnLabel(ad, f?.name)}</code>
                    <small>{hex(ad)}</small>
                  </span>
                  {rules && <em className="pill">{rules.length}</em>}
                  {!f && <span className="dot" title="pending" />}
                  {f?.error && <span className="dot err" title="failed" />}
                </button>
              );
            })}
            {!list.length && <p className="empty">{total ? "No matches." : a.decompileError ? "No functions to show." : a.done ? "No functions found." : "Recovering functions…"}</p>}
          </div>
        </aside>

        <main className="pane">
          {sel === "capa"
            ? <CapabilityView a={a} fileLevel={fileLevel} onGoto={goto} />
            : sel === "strings"
            ? <StringsView a={a} refs={strRefs} onGoto={setSel} query={strQuery} setQuery={setStrQuery} />
            : <FunctionView a={a} address={sel} rules={byFn.get(sel) ?? []} resolve={resolve} onGoto={setSel}
              strings={(fnStrings.get(sel) ?? []).map((v) => strByAddr.get(v)!).filter(Boolean)} onString={showString} callers={callers.get(sel)} callees={callees.get(sel)} xrefsReady={a.done}
              strAt={(v) => strByAddr.get(v)?.s} />}
        </main>
      </div>
      {dragging && <div className="overlay">Drop to analyze a new binary</div>}
    </div>
  );
}

function RuleCard({ rule, onGoto, addr }: { rule: CapaRule; onGoto?: (a: number) => void; addr?: number }) {
  const attack = rule.attack.map((t) => t.id).filter(Boolean);
  return (
    <div className="rule">
      <div className="rule-head">
        <b>{rule.name}</b>
        {rule.count > 1 && addr === undefined && <small>{rule.count} matches</small>}
      </div>
      <div className="meta">
        {rule.namespace && <span>{rule.namespace}</span>}
        <span>{rule.scope}</span>
        {attack.map((id) => <span key={id} className="tag">{id}</span>)}
        {rule.mbc.map((m) => <span key={m.id} className="tag">{m.id}</span>)}
      </div>
      {onGoto && addr === undefined && rule.scope !== "file" && rule.addresses.length > 0 && (
        <div className="addrs">
          {rule.addresses.slice(0, 8).map((ad) => <button key={ad} onClick={() => onGoto(ad)}>{hex(ad)}</button>)}
          {rule.addresses.length > 8 && <small>+{rule.addresses.length - 8}</small>}
        </div>
      )}
    </div>
  );
}

function CapabilityView({ a, fileLevel, onGoto }: { a: Analysis; fileLevel: CapaRule[]; onGoto: (ad: number) => void }) {
  if (a.capaError) return <div className="notice error">Capability analysis failed: {a.capaError}</div>;
  if (!a.capa) return <div className="notice"><span className="spin" /> Matching capa rules…</div>;
  const rules = a.capa.rules.filter((r) => !r.lib);
  const groups = new Map<string, CapaRule[]>();
  for (const r of rules) {
    const key = r.namespace?.split("/")[0] ?? "other";
    groups.set(key, [...(groups.get(key) ?? []), r]);
  }
  const tactics = [...new Set(rules.flatMap((r) => r.attack.map((t) => t.tactic)))];
  return (
    <div className="view">
      <h1>Capabilities</h1>
      {a.decompileError && <div className="notice error">Decompiler: {a.decompileError.replace(/^error: /, "")}</div>}
      <div className="facts">
        <div><span>MD5</span><code>{a.capa.sample.md5}</code></div>
        <div><span>SHA-256</span><code>{a.capa.sample.sha256}</code></div>
        <div><span>Platform</span><code>{a.capa.os} · {a.capa.arch}</code></div>
        {tactics.length > 0 && <div><span>ATT&amp;CK</span><div className="chips">{tactics.map((t) => <i key={t}>{t}</i>)}</div></div>}
      </div>
      {rules.length === 0 && <p className="empty">No capabilities matched.</p>}
      {[...groups].sort(([x], [y]) => x.localeCompare(y)).map(([ns, rs]) => (
        <section key={ns}>
          <h2>{ns} <small>{rs.length}</small></h2>
          {rs.sort((x, y) => x.name.localeCompare(y.name)).map((r) => <RuleCard key={r.name} rule={r} onGoto={onGoto} />)}
        </section>
      ))}
      {fileLevel.length > 0 && <p className="fine">Includes {fileLevel.length} file-level matches.</p>}
    </div>
  );
}

/** Compact list of functions in the xref rail. */
function XrefGroup({ title, items, a, onGoto, pending }: { title: string; items?: number[]; a: Analysis; onGoto: (ad: number) => void; pending: boolean }) {
  return (
    <section className="rail-sec">
      <h3>{title} {items && <small>{items.length}</small>}</h3>
      {!items ? <p className="fine">{pending ? "Computed when decompilation finishes" : "—"}</p>
        : items.length === 0 ? <p className="fine">None</p>
        : items.map((ad) => <button key={ad} className="rail-item" onClick={() => onGoto(ad)} title={hex(ad)}>{fnLabel(ad, a.functions.get(ad)?.name)}</button>)}
    </section>
  );
}

const ADDR_IN_ASM = /\b([0-9A-F]{6,16})h\b/g;

/** Assembly listing; branch/call targets link to functions and string addresses show the string. */
function Asm({ rows, self, resolve, onGoto, strAt, label, active, onPick }: {
  active: Set<number>; onPick: (ad: number) => void;
  label: (ad: number) => string;
  rows: [number, string, string][]; self: number;
  resolve: (t: string) => number | undefined; onGoto: (ad: number) => void; strAt: (ad: number) => string | undefined;
}) {
  return (
    <div className="asm">
      {rows.map(([ad, bytes, text]) => {
        const sp = text.indexOf(" ");
        const mnem = sp < 0 ? text : text.slice(0, sp), ops = sp < 0 ? "" : text.slice(sp);
        const parts: React.ReactNode[] = [];
        let last = 0, k = 0, note: string | undefined;
        for (const m of ops.matchAll(ADDR_IN_ASM)) {
          const v = parseInt(m[1], 16), target = resolve("0x" + v.toString(16));
          parts.push(ops.slice(last, m.index));
          const lit = "0x" + v.toString(16);
          parts.push(target !== undefined && target !== self
            ? <a key={k++} href={"#" + lit} className="xref tk-f" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto(target); }}>{label(target)}</a>
            : <span key={k++} className="tk-n">{lit}</span>);
          last = m.index! + m[0].length;
          note ??= strAt(v);
        }
        parts.push(ops.slice(last));
        return (
          <div className={"insn" + (active.has(ad) ? " hl" : "")} key={ad} data-ad={ad} onClick={() => onPick(ad)}>
            <code className="ia">{ad.toString(16).padStart(8, "0")}</code>
            <code className="ib">{bytes}</code>
            <code className="it"><span className="tk-k">{mnem}</span>{parts}{note && <span className="tk-c">  ; {JSON.stringify(note.length > 60 ? note.slice(0, 60) + "…" : note)}</span>}</code>
          </div>
        );
      })}
    </div>
  );
}

interface FnViewProps {
  a: Analysis; address: number; rules: CapaRule[];
  resolve: (t: string) => number | undefined; onGoto: (ad: number) => void;
  callers?: number[]; callees?: number[]; xrefsReady: boolean;
  strings: StringEntry[]; onString: (text: string) => void; strAt: (ad: number) => string | undefined;
}

type Layout = "split" | "c" | "asm";

function FunctionView({ a, address, rules, resolve, onGoto, callers, callees, xrefsReady, strings, onString, strAt }: FnViewProps) {
  const f = a.functions.get(address);
  const [copied, setCopied] = useState(false);
  const [layout, setLayout] = useState<Layout>(() => (localStorage.getItem("layout") as Layout) || "split");
  useEffect(() => { try { localStorage.setItem("layout", layout); } catch {} }, [layout]);
  const copy = () => { if (f?.text) navigator.clipboard.writeText(f.text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); }); };
  const noSelf = (t: string) => { const r = resolve(t); return r === address ? undefined : r; };
  const hasAsm = !!f?.asm?.length;

  // Clicking a C line or an instruction highlights its counterpart(s) on the other side.
  const [focus, setFocus] = useState<{ kind: "c"; line: number } | { kind: "a"; ad: number } | null>(null);
  useEffect(() => setFocus(null), [address]);
  const lines = f?.lines ?? [];
  const hlAddrs = useMemo(() => new Set(focus?.kind === "c" ? lines[focus.line] ?? [] : focus?.kind === "a" ? [focus.ad] : []), [focus, f]);
  const hlLines = useMemo(() => {
    const set = new Set<number>();
    if (focus?.kind === "c") set.add(focus.line);
    if (focus?.kind === "a") lines.forEach((l, i) => { if (l.includes(focus.ad)) set.add(i); });
    return set;
  }, [focus, f]);
  const cPane = useRef<HTMLDivElement>(null), aPane = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // Bring the counterpart into view in the pane that was not clicked.
    const target = focus?.kind === "c" ? aPane.current?.querySelector(".insn.hl") : focus?.kind === "a" ? cPane.current?.querySelector(".ln.hl") : null;
    target?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [focus]);
  const trimmed = f?.text ? f.text.replace(/^\n+/, "") : "";
  const lineOffset = f?.text ? f.text.length - f.text.replace(/^\n+/, "").length : 0;
  const show = (l: Layout) => layout === "split" ? true : layout === l;

  return (
    <div className="cockpit">
      <div className="cp-head">
        <div className="cp-title">
          <h1>{fnLabel(address, f?.name)}</h1>
          <code className="addr">{hex(address)}</code>
          {rules.map((r) => <span key={r.name} className="cap" title={r.namespace ?? ""}>{r.name}</span>)}
        </div>
        <div className="seg">
          {(["c", "split", "asm"] as Layout[]).map((l) => (
            <button key={l} className={layout === l ? "on" : ""} onClick={() => setLayout(l)}>{l === "c" ? "C" : l === "asm" ? "Asm" : "Both"}</button>
          ))}
        </div>
        {f?.text && <button className="ghost" onClick={copy}>{copied ? "Copied" : "Copy C"}</button>}
      </div>

      <div className="cp-body">
        <div className={"cp-panes " + layout}>
          {show("c") && (
            <div className="cp-pane" ref={cPane}>
              <div className="pane-label">Decompiled</div>
              {!f && <div className="notice"><span className="spin" /> Decompiling…</div>}
              {f?.error && <div className="notice error">{f.error}</div>}
              {f?.text && (
                <>
                  {(f.incomplete || (f.warnings?.length ?? 0) > 1) && (
                    <details className="warn">
                      <summary>{f.incomplete ? "Output may be incomplete" : "Notes"}{f.unknown_callees ? " · unknown callees" : ""}</summary>
                      <ul>{f.warnings?.map((w, i) => <li key={i}>{w}</li>)}</ul>
                    </details>
                  )}
                  <Code text={trimmed.trimEnd()} lineOffset={lineOffset} active={hlLines} onLine={(line) => setFocus({ kind: "c", line })} resolve={noSelf} onGoto={onGoto} onString={onString} />
                </>
              )}
              {a.decompileError && <div className="notice error">Decompiler: {a.decompileError}</div>}
            </div>
          )}
          {show("asm") && (
            <div className="cp-pane" ref={aPane}>
              <div className="pane-label">Assembly</div>
              {hasAsm ? <Asm rows={f!.asm!} self={address} resolve={resolve} onGoto={onGoto} strAt={strAt} label={(ad) => fnLabel(ad, a.functions.get(ad)?.name)} active={hlAddrs} onPick={(ad) => setFocus({ kind: "a", ad })} />
                : <p className="fine">{f ? "No instruction listing." : "Waiting for analysis…"}</p>}
            </div>
          )}
        </div>

        <aside className="rail">
          <XrefGroup title="Calls" items={xrefsReady ? callees ?? [] : undefined} a={a} onGoto={onGoto} pending={!xrefsReady} />
          <XrefGroup title="Called by" items={xrefsReady ? callers ?? [] : undefined} a={a} onGoto={onGoto} pending={!xrefsReady} />
          <section className="rail-sec">
            <h3>Strings {xrefsReady && <small>{strings.length}</small>}</h3>
            {!xrefsReady ? <p className="fine">Computed when decompilation finishes</p>
              : strings.length === 0 ? <p className="fine">None</p>
              : strings.map((x) => (
                <button key={x.a} className="rail-item str-item" onClick={() => onString(x.s)} title={hex(x.a) + " — show in Strings"}>{x.s}</button>
              ))}
          </section>
        </aside>
      </div>
    </div>
  );
}

const PAGE = 300;

function StringsView({ a, refs, onGoto, query, setQuery }: {
  a: Analysis; refs: Map<number, number[]>; onGoto: (ad: number) => void; query: string; setQuery: (q: string) => void;
}) {
  const [limit, setLimit] = useState(PAGE);
  const [onlyRef, setOnlyRef] = useState(true);
  useEffect(() => setLimit(PAGE), [query, onlyRef]);
  const rows = useMemo(() => {
    const n = query.toLowerCase();
    return a.strings.filter((x) => (!onlyRef || refs.has(x.a)) && (!n || x.s.toLowerCase().includes(n) || hex(x.a).includes(n)));
  }, [a.strings, query, onlyRef, refs]);
  const fnName = (ad: number) => fnLabel(ad, a.functions.get(ad)?.name);

  return (
    <div className="view">
      <h1>Strings</h1>
      <p className="fine" style={{ marginTop: 4 }}>
        {a.strings.length} ASCII and UTF-16 strings{a.done ? "" : " · references appear once decompilation finishes"}
      </p>
      <div className="tools flat">
        <input placeholder="Search strings or addresses" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus />
        <label><input type="checkbox" checked={onlyRef} onChange={(e) => setOnlyRef(e.target.checked)} /> referenced only</label>
      </div>
      {rows.slice(0, limit).map((x) => {
        const r = refs.get(x.a);
        return (
          <div className="str" key={x.a + (x.w ? "w" : "a")}>
            <div className="str-head"><code>{hex(x.a)}</code>{x.w && <span className="tag">utf-16</span>}</div>
            <div className="str-text">{x.s}</div>
            <div className="addrs used">
              {r ? <><small>Used in</small>{r.slice(0, 12).map((ad) => <button key={ad} onClick={() => onGoto(ad)}>{fnName(ad)}</button>)}{r.length > 12 && <small>+{r.length - 12}</small>}</>
                : <small>{a.done ? "No function references found" : "Looking for references…"}</small>}
            </div>
          </div>
        );
      })}
      {rows.length > limit && <button className="ghost more" onClick={() => setLimit(limit + PAGE * 3)}>Show more ({rows.length - limit})</button>}
      {!rows.length && <p className="empty">No strings match.</p>}
    </div>
  );
}
