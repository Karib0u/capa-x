// Control-flow graph for the Graph view: basic blocks recovered from the instruction listing the
// engine already sends, then a layered (Sugiyama-style) layout. Everything runs in the page; the
// engine is not involved.

export type AsmRow = [number, string, string];
export type EdgeKind = "true" | "false" | "jump";

export interface Block {
  id: number;
  addr: number;
  rows: AsmRow[];
}
export interface CfgEdge {
  from: number;
  to: number;
  kind: EdgeKind;
}
export interface Cfg {
  blocks: Block[];
  edges: CfgEdge[];
}

const DIRECT = /^(?:(?:short|near ptr|far ptr)\s+)?([0-9A-F]{2,16})h$/i;

const split = (text: string): [string, string] => {
  const sp = text.indexOf(" ");
  return sp < 0 ? [text.toLowerCase(), ""] : [text.slice(0, sp).toLowerCase(), text.slice(sp + 1).trim()];
};
const isRet = (m: string) => m.startsWith("ret") || m === "iret" || m === "iretd" || m === "iretq" || m === "sysret";
const isHalt = (m: string) => m === "hlt" || m === "ud2" || m === "int3" || m === "ud1";
const isCond = (m: string) => (m.startsWith("j") && m !== "jmp") || m.startsWith("loop");

/** Splits a function's listing into basic blocks. Branch targets outside the listing (tail calls) get no edge. */
export function buildCfg(rows: AsmRow[]): Cfg {
  const sorted = [...rows].sort((x, y) => x[0] - y[0]);
  if (!sorted.length) return { blocks: [], edges: [] };
  const known = new Set(sorted.map((r) => r[0]));
  const target = (text: string): number | undefined => {
    const m = DIRECT.exec(split(text)[1]);
    if (!m) return undefined;
    const v = parseInt(m[1], 16);
    return known.has(v) ? v : undefined;
  };

  const leaders = new Set<number>([sorted[0][0]]);
  sorted.forEach((r, i) => {
    const [m] = split(r[2]);
    const branch = m === "jmp" || isCond(m);
    if (branch) {
      const t = target(r[2]);
      if (t !== undefined) leaders.add(t);
    }
    if ((branch || isRet(m) || isHalt(m)) && i + 1 < sorted.length) leaders.add(sorted[i + 1][0]);
  });

  const blocks: Block[] = [];
  for (const r of sorted) {
    if (leaders.has(r[0]) || !blocks.length) blocks.push({ id: blocks.length, addr: r[0], rows: [] });
    blocks[blocks.length - 1].rows.push(r);
  }
  const byAddr = new Map(blocks.map((b) => [b.addr, b.id]));

  const edges: CfgEdge[] = [];
  blocks.forEach((b, i) => {
    const last = b.rows[b.rows.length - 1];
    const [m] = split(last[2]);
    const next = i + 1 < blocks.length ? blocks[i + 1].id : undefined;
    const t = target(last[2]);
    const to = t === undefined ? undefined : byAddr.get(t);
    if (m === "jmp") {
      if (to !== undefined) edges.push({ from: b.id, to, kind: "jump" });
    } else if (isCond(m)) {
      if (to !== undefined) edges.push({ from: b.id, to, kind: "true" });
      if (next !== undefined) edges.push({ from: b.id, to: next, kind: "false" });
    } else if (!isRet(m) && !isHalt(m) && next !== undefined) {
      edges.push({ from: b.id, to: next, kind: "jump" });
    }
  });
  return { blocks, edges };
}

export interface Placed { id: number; x: number; y: number; w: number; h: number }
export interface Route { edge: CfgEdge; back: boolean; pts: [number, number][] }
export interface GraphLayout { nodes: Placed[]; routes: Route[]; width: number; height: number }

const GAP_X = 36, GAP_Y = 56, DUMMY_W = 14, MARGIN = 40, LANE = 18;

/** Layered layout: DFS back edges are routed around the side, the rest flow top to bottom. */
export function layoutCfg(cfg: Cfg, size: (b: Block) => { w: number; h: number }): GraphLayout {
  const n = cfg.blocks.length;
  if (!n) return { nodes: [], routes: [], width: 0, height: 0 };

  const out: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of cfg.edges) out[e.from].push(e);

  // 1. Back edges, by iterative DFS from the entry (then from any unreached block).
  const state = new Uint8Array(n); // 0 new, 1 on stack, 2 done
  const post: number[] = [];
  const back = new Set<CfgEdge>();
  for (let root = 0; root < n; root++) {
    if (state[root]) continue;
    const stack: [number, number][] = [[root, 0]];
    state[root] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const edges = out[top[0]];
      if (top[1] < edges.length) {
        const e = edges[top[1]++];
        if (state[e.to] === 1) back.add(e);
        else if (state[e.to] === 0) { state[e.to] = 1; stack.push([e.to, 0]); }
      } else {
        state[top[0]] = 2;
        post.push(top[0]);
        stack.pop();
      }
    }
  }
  const forward = cfg.edges.filter((e) => !back.has(e));

  // 2. Layers: longest path over forward edges, visiting in reverse post-order (a topological order).
  const layerOf = new Array<number>(n).fill(0);
  const fwdOut: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of forward) fwdOut[e.from].push(e);
  for (let i = post.length - 1; i >= 0; i--) {
    const u = post[i];
    for (const e of fwdOut[u]) layerOf[e.to] = Math.max(layerOf[e.to], layerOf[u] + 1);
  }

  // 3. Dummy nodes carry long edges through the intermediate layers.
  const layer = [...layerOf];
  const up: number[][] = cfg.blocks.map(() => []);
  const down: number[][] = cfg.blocks.map(() => []);
  const chains = new Map<CfgEdge, number[]>();
  for (const e of forward) {
    const chain: number[] = [];
    let prev = e.from;
    for (let l = layer[e.from] + 1; l < layer[e.to]; l++) {
      const d = layer.length;
      layer.push(l);
      up.push([]);
      down.push([]);
      chain.push(d);
      down[prev].push(d);
      up[d].push(prev);
      prev = d;
    }
    down[prev].push(e.to);
    up[e.to].push(prev);
    chains.set(e, chain);
  }
  const total = layer.length;
  const nlayers = Math.max(...layer) + 1;
  const layers: number[][] = Array.from({ length: nlayers }, () => []);
  // Seed the order by a walk from the entry that visits the "false" (fall-through) side first.
  const seen = new Uint8Array(total);
  const seed: number[] = [];
  const visit = (root: number) => {
    const q = [root];
    while (q.length) {
      const u = q.shift()!;
      if (seen[u]) continue;
      seen[u] = 1;
      seed.push(u);
      for (const v of down[u]) q.push(v);
    }
  };
  for (let r = 0; r < total; r++) if (!up[r].length) visit(r);
  for (let r = 0; r < total; r++) visit(r);
  for (const u of seed) layers[layer[u]].push(u);

  // 4. Crossing reduction: barycenter sweeps.
  const index = new Array<number>(total).fill(0);
  const reindex = () => layers.forEach((l) => l.forEach((u, i) => (index[u] = i)));
  reindex();
  const sweep = (l: number, nbr: number[][]) => {
    const key = new Map<number, number>();
    for (const u of layers[l]) {
      const ns = nbr[u];
      key.set(u, ns.length ? ns.reduce((s, v) => s + index[v], 0) / ns.length : index[u]);
    }
    layers[l].sort((x, y) => key.get(x)! - key.get(y)! || index[x] - index[y]);
    layers[l].forEach((u, i) => (index[u] = i));
  };
  for (let pass = 0; pass < 6; pass++) {
    for (let l = 1; l < nlayers; l++) sweep(l, up);
    for (let l = nlayers - 2; l >= 0; l--) sweep(l, down);
  }

  // 5. Coordinates. Real nodes use their measured size; dummies are thin pass-through points.
  const w = new Array<number>(total), h = new Array<number>(total);
  for (let u = 0; u < total; u++) {
    if (u < n) { const s = size(cfg.blocks[u]); w[u] = s.w; h[u] = s.h; } else { w[u] = DUMMY_W; h[u] = 0; }
  }
  const cx = new Array<number>(total).fill(0);
  for (const l of layers) {
    let x = 0;
    for (const u of l) { cx[u] = x + w[u] / 2; x += w[u] + GAP_X; }
  }
  const place = (l: number[], want: number[]) => {
    // Left-packed and right-packed placements both keep the spacing; their mean does too.
    const left: number[] = [], right: number[] = [];
    l.forEach((u, i) => {
      const min = i ? left[i - 1] + (w[l[i - 1]] + w[u]) / 2 + GAP_X : -Infinity;
      left.push(Math.max(want[i], min));
    });
    for (let i = l.length - 1; i >= 0; i--) {
      const u = l[i];
      const max = i < l.length - 1 ? right[i + 1] - (w[l[i + 1]] + w[u]) / 2 - GAP_X : Infinity;
      right[i] = Math.min(want[i], max);
    }
    l.forEach((u, i) => (cx[u] = (left[i] + right[i]) / 2));
  };
  const pull = (l: number, nbr: number[][]) =>
    place(layers[l], layers[l].map((u) => (nbr[u].length ? nbr[u].reduce((s, v) => s + cx[v], 0) / nbr[u].length : cx[u])));
  for (let pass = 0; pass < 8; pass++) {
    for (let l = 1; l < nlayers; l++) pull(l, up);
    for (let l = nlayers - 2; l >= 0; l--) pull(l, down);
  }
  let minX = Infinity;
  for (let u = 0; u < total; u++) minX = Math.min(minX, cx[u] - w[u] / 2);
  for (let u = 0; u < total; u++) cx[u] += MARGIN - minX;

  const layerTop: number[] = [], layerH: number[] = [];
  let y = MARGIN;
  layers.forEach((l, i) => {
    layerTop[i] = y;
    layerH[i] = Math.max(0, ...l.map((u) => h[u]));
    y += layerH[i] + GAP_Y;
  });
  const top = (u: number) => layerTop[layer[u]];
  const bottom = (u: number) => layerTop[layer[u]] + (u < n ? h[u] : layerH[layer[u]]);

  // 6. Edge routes. Edges sharing a block side are spread along it, ordered left to right so they do not cross.
  const slot = (u: number, k: number, count: number) => {
    const span = Math.min(w[u] - 24, Math.max(0, (count - 1) * 22));
    return count > 1 ? cx[u] - span / 2 + (span * k) / (count - 1) : cx[u];
  };
  const firstHop = (e: CfgEdge) => (chains.get(e)?.[0] ?? e.to);
  const lastHop = (e: CfgEdge) => { const c = chains.get(e); return c?.length ? c[c.length - 1] : e.from; };
  const outSlots = new Map<CfgEdge, number>(), inSlots = new Map<CfgEdge, number>();
  const incoming: CfgEdge[][] = cfg.blocks.map(() => []);
  for (const e of cfg.edges) incoming[e.to].push(e);
  cfg.blocks.forEach((b) => {
    const fw = out[b.id].filter((e) => !back.has(e)).sort((p, q) => cx[firstHop(p)] - cx[firstHop(q)]);
    fw.forEach((e, k) => outSlots.set(e, slot(b.id, k, fw.length)));
    const bk = out[b.id].filter((e) => back.has(e));
    bk.forEach((e, k) => outSlots.set(e, slot(b.id, k, bk.length)));
    const ins = incoming[b.id].filter((e) => !back.has(e)).sort((p, q) => cx[lastHop(p)] - cx[lastHop(q)]);
    ins.forEach((e, k) => inSlots.set(e, slot(b.id, k, ins.length)));
    const bin = incoming[b.id].filter((e) => back.has(e));
    bin.forEach((e, k) => inSlots.set(e, slot(b.id, k, bin.length)));
  });

  let right = 0;
  for (let u = 0; u < total; u++) right = Math.max(right, cx[u] + w[u] / 2);
  const routes: Route[] = [];
  let lane = 0;
  for (const e of cfg.edges) {
    const sx = outSlots.get(e)!, tx = inSlots.get(e)!;
    const sb = bottom(e.from), tt = top(e.to);
    if (back.has(e)) {
      const lx = right + MARGIN / 2 + LANE * lane++;
      const a = sb + 12 + (lane % 3) * 4, b = tt - 12 - (lane % 3) * 4;
      routes.push({ edge: e, back: true, pts: [[sx, sb], [sx, a], [lx, a], [lx, b], [tx, b], [tx, tt]] });
      continue;
    }
    const pts: [number, number][] = [[sx, sb]];
    let px = sx, py = sb;
    const go = (x: number, yTop: number) => {
      if (x !== px) { const ym = (py + yTop) / 2; pts.push([px, ym], [x, ym]); }
      pts.push([x, yTop]);
      px = x; py = yTop;
    };
    for (const d of chains.get(e) ?? []) {
      go(cx[d], top(d));
      pts.push([cx[d], bottom(d)]);
      px = cx[d]; py = bottom(d);
    }
    go(tx, tt);
    routes.push({ edge: e, back: false, pts });
  }
  const laneRight = right + MARGIN / 2 + LANE * lane;
  const nodes: Placed[] = cfg.blocks.map((b) => ({ id: b.id, x: cx[b.id] - w[b.id] / 2, y: top(b.id), w: w[b.id], h: h[b.id] }));
  return { nodes, routes, width: Math.max(right, laneRight) + MARGIN, height: y - GAP_Y + MARGIN };
}
