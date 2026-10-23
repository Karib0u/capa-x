import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { buildCfg, layoutCfg, type AsmRow, type EdgeKind } from "./graph";
import type { CapaRule } from "./types";

const ADDR_IN_ASM = /\b([0-9A-F]{6,16})h\b/g;
const LINE_H = 18, HEAD_H = 24, CAP_H = 18, PAD_X = 10, PAD_Y = 6;
const MIN_ZOOM = 0.1, MAX_ZOOM = 2.5;
const EDGE_VAR: Record<EdgeKind, string> = { true: "var(--c-str)", false: "var(--err)", jump: "var(--c-fn)" };

let charWidth = 0;
/** Width of one monospace character at the graph's font size, measured once. */
function measureChar() {
  if (charWidth) return charWidth;
  const mono = getComputedStyle(document.documentElement).getPropertyValue("--mono") || "monospace";
  const ctx = document.createElement("canvas").getContext("2d");
  if (ctx) { ctx.font = `12px ${mono}`; charWidth = ctx.measureText("0".repeat(20)).width / 20; }
  return (charWidth ||= 7.2);
}

interface Props {
  rows: AsmRow[];
  self: number;
  name: string;
  rules: CapaRule[];
  resolve: (t: string) => number | undefined;
  label: (ad: number) => string;
  strAt: (ad: number) => string | undefined;
  onGoto: (ad: number) => void;
}

interface View { x: number; y: number; k: number }

/** Control-flow graph of one function, in the manner of IDA's graph view: blocks, coloured edges, pan and zoom. */
export default function GraphView({ rows, self, name, rules, resolve, label, strAt, onGoto }: Props) {
  const cfg = useMemo(() => buildCfg(rows), [rows]);
  // The parent passes fresh closures and arrays on every render; key the layout on content so it is not redone (and the view reset).
  const strRef = useRef(strAt);
  strRef.current = strAt;
  const rulesRef = useRef(rules);
  rulesRef.current = rules;
  const ruleKey = rules.map((r) => r.name).join("|");

  // Blocks that hold a basic-block or instruction scoped capa match.
  const caps = useMemo(() => {
    const m = new Map<number, string[]>();
    for (const r of rulesRef.current) {
      if (r.scope !== "basic block" && r.scope !== "instruction") continue;
      for (const ad of r.addresses) {
        const b = [...cfg.blocks].reverse().find((x) => x.addr <= ad);
        if (b && !(m.get(b.id) ?? []).includes(r.name)) m.set(b.id, [...(m.get(b.id) ?? []), r.name]);
      }
    }
    return m;
  }, [ruleKey, cfg]);

  const layout = useMemo(() => {
    const cw = measureChar();
    return layoutCfg(cfg, (b) => {
      const noteLen = (text: string) => {
        for (const m of text.matchAll(ADDR_IN_ASM)) { const s = strRef.current(parseInt(m[1], 16)); if (s !== undefined) return Math.min(s.length, 40) + 8; }
        return 0;
      };
      const chars = Math.max(...b.rows.map((r) => 10 + r[2].length + noteLen(r[2]) + 2), 12);
      const headChars = (b.addr === self ? name.length : 4 + 8) + 2;
      return { w: Math.ceil(Math.max(chars, headChars) * cw) + PAD_X * 2, h: HEAD_H + (caps.get(b.id)?.length ?? 0) * CAP_H + b.rows.length * LINE_H + PAD_Y * 2 };
    });
  }, [cfg, caps, self, name]);

  const box = useRef<HTMLDivElement>(null);
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const [picked, setPicked] = useState<number | null>(null);
  const [panning, setPanning] = useState(false);

  // Until the user pans or zooms, the graph keeps itself fitted to the pane as it is resized.
  const touched = useRef(false);
  const fit = useCallback(() => {
    const el = box.current;
    if (!el || !layout.width || !el.clientWidth || !el.clientHeight) return;
    touched.current = false;
    const k = Math.min(1, el.clientWidth / layout.width, el.clientHeight / layout.height);
    setView({ k, x: Math.max(0, (el.clientWidth - layout.width * k) / 2), y: 0 });
  }, [layout]);
  useLayoutEffect(() => { fit(); setPicked(null); }, [fit]);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => { if (!touched.current) fit(); });
    ro.observe(el);
    return () => ro.disconnect();
  }, [fit]);

  const zoomAt = useCallback((factor: number, px: number, py: number) => {
    touched.current = true;
    setView((v) => {
      const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.k * factor));
      return { k, x: px - ((px - v.x) / v.k) * k, y: py - ((py - v.y) / v.k) * k };
    });
  }, []);
  const zoomCenter = (factor: number) => { const el = box.current; if (el) zoomAt(factor, el.clientWidth / 2, el.clientHeight / 2); };

  // Wheel pans; Ctrl/Cmd+wheel (and trackpad pinch, which arrives as ctrl+wheel) zooms. Needs a non-passive listener.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      if (e.ctrlKey || e.metaKey) zoomAt(Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top);
      else { touched.current = true; setView((v) => ({ ...v, x: v.x - e.deltaX, y: v.y - e.deltaY })); }
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  // Drag to pan, two fingers to pinch.
  const pointers = useRef(new Map<number, { x: number; y: number }>());
  const moved = useRef(0);
  const onDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest("a, button")) return;
    box.current?.setPointerCapture(e.pointerId);
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    moved.current = 0;
    setPanning(true);
  };
  const onMove = (e: React.PointerEvent) => {
    const prev = pointers.current.get(e.pointerId);
    if (!prev) return;
    const now = { x: e.clientX, y: e.clientY };
    const others = [...pointers.current].filter(([id]) => id !== e.pointerId).map(([, p]) => p);
    pointers.current.set(e.pointerId, now);
    moved.current += Math.abs(now.x - prev.x) + Math.abs(now.y - prev.y);
    if (others.length === 1) {
      const o = others[0], r = box.current!.getBoundingClientRect();
      const before = Math.hypot(prev.x - o.x, prev.y - o.y), after = Math.hypot(now.x - o.x, now.y - o.y);
      if (before > 0) zoomAt(after / before, (now.x + o.x) / 2 - r.left, (now.y + o.y) / 2 - r.top);
    } else {
      touched.current = true;
      setView((v) => ({ ...v, x: v.x + now.x - prev.x, y: v.y + now.y - prev.y }));
    }
  };
  const onUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId);
    if (!pointers.current.size) setPanning(false);
  };

  const edgeActive = (from: number, to: number) => picked !== null && (from === picked || to === picked);

  if (!cfg.blocks.length) return <p className="fine">No instruction listing.</p>;

  return (
    <div className="gv">
      <div className="graph-tools">
        <button onClick={() => zoomCenter(1 / 1.25)} aria-label="Zoom out">−</button>
        <span>{Math.round(view.k * 100)}%</span>
        <button onClick={() => zoomCenter(1.25)} aria-label="Zoom in">+</button>
        <button onClick={fit}>Fit</button>
        <small>{cfg.blocks.length} blocks · {cfg.edges.length} edges</small>
      </div>
      <div className="graph-legend"><i style={{ background: EDGE_VAR.true }} />true<i style={{ background: EDGE_VAR.false }} />false<i style={{ background: EDGE_VAR.jump }} />jump / fall-through</div>
      <div ref={box} className={"graph-view" + (panning ? " panning" : "")} onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerCancel={onUp}
        onClick={(e) => { if (moved.current < 4 && !(e.target as HTMLElement).closest(".gb")) setPicked(null); }}>
        <div className="graph-canvas" style={{ width: layout.width, height: layout.height, transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})` }}>
          <svg width={layout.width} height={layout.height} aria-hidden>
            <defs>
              {(Object.keys(EDGE_VAR) as EdgeKind[]).map((k) => (
                <marker key={k} id={"arrow-" + k} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
                  <path d="M0 1 L10 5 L0 9 z" fill={EDGE_VAR[k]} />
                </marker>
              ))}
            </defs>
            {layout.routes.map((r, i) => {
              const on = edgeActive(r.edge.from, r.edge.to);
              return (
                <path key={i} d={"M" + r.pts.map((p) => p.join(" ")).join(" L")} fill="none" stroke={EDGE_VAR[r.edge.kind]}
                  strokeWidth={on ? 2.4 : 1.5} strokeLinejoin="round" strokeDasharray={r.back ? "5 3" : undefined}
                  opacity={picked === null || on ? 1 : 0.25} markerEnd={`url(#arrow-${r.edge.kind})`} />
              );
            })}
          </svg>
          {layout.nodes.map((p) => {
            const b = cfg.blocks[p.id];
            const bcaps = caps.get(b.id) ?? [];
            return (
              <div key={b.id} className={"gb" + (picked === b.id ? " on" : "") + (b.addr === self ? " entry" : "")}
                style={{ left: p.x, top: p.y, width: p.w, height: p.h }}
                onClick={(e) => { if (moved.current < 4) { e.stopPropagation(); setPicked(picked === b.id ? null : b.id); } }}>
                <div className="gb-head">{b.addr === self ? name : "loc_" + b.addr.toString(16).padStart(8, "0")}</div>
                {bcaps.map((c) => <div key={c} className="gb-cap" title={c}>{c}</div>)}
                <div className="gb-body">
                  {b.rows.map(([ad, , text]) => <Insn key={ad} ad={ad} text={text} self={self} resolve={resolve} label={label} strAt={strAt} onGoto={onGoto} />)}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Insn({ ad, text, self, resolve, label, strAt, onGoto }: { ad: number; text: string } & Pick<Props, "self" | "resolve" | "label" | "strAt" | "onGoto">) {
  const sp = text.indexOf(" ");
  const mnem = sp < 0 ? text : text.slice(0, sp), ops = sp < 0 ? "" : text.slice(sp);
  const parts: React.ReactNode[] = [];
  let last = 0, k = 0, note: string | undefined;
  for (const m of ops.matchAll(ADDR_IN_ASM)) {
    const v = parseInt(m[1], 16), lit = "0x" + v.toString(16), target = resolve(lit);
    parts.push(ops.slice(last, m.index));
    parts.push(target !== undefined && target !== self
      ? <a key={k++} href={"#" + lit} className="xref tk-f" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto(target); }}>{label(target)}</a>
      : <span key={k++} className="tk-n">{lit}</span>);
    last = m.index! + m[0].length;
    note ??= strAt(v);
  }
  parts.push(ops.slice(last));
  return (
    <div className="gi">
      <code className="ia">{ad.toString(16).padStart(8, "0")}</code>
      <code><span className="tk-k">{mnem}</span>{parts}{note && <span className="tk-c">  ; {JSON.stringify(note.length > 40 ? note.slice(0, 40) + "…" : note)}</span>}</code>
    </div>
  );
}
