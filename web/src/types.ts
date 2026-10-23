export interface DecompiledFunction {
  address: number;
  name?: string | null;
  text?: string;
  /** Gaps only; each one makes the output incomplete. */
  warnings?: string[];
  /** Informational (modeled effects, inferred types); not shown in the banner. */
  notes?: string[];
  incomplete?: boolean;
  unknown_callees?: boolean;
  error?: string;
  /** Instruction listing: [address, hex bytes, text]. */
  asm?: [number, string, string][];
  /** Per line of `text`: instruction addresses of the operations printed on it. Empty when unknown. */
  lines?: number[][];
}

export interface CapaRule {
  name: string;
  namespace: string | null;
  scope: string;
  lib: boolean;
  attack: { id: string; tactic: string; technique: string; subtechnique: string }[];
  mbc: { id: string; objective: string; behavior: string; method: string }[];
  description: string;
  count: number;
  addresses: number[];
}

export interface CapaResult {
  sample: { md5: string; sha256: string };
  format: string;
  arch: string;
  os: string;
  baseAddress: number | null;
  rules: CapaRule[];
}

export interface StringEntry {
  a: number;
  s: string;
  /** UTF-16 rather than ASCII. */
  w: boolean;
}

export interface Analysis {
  strings: StringEntry[];
  /** Program entry point, when known. */
  entry: number | null;
  fileName: string;
  size: number;
  /** Sorted function entry points, known once recovery finishes. */
  order: number[];
  functions: Map<number, DecompiledFunction>;
  capa: CapaResult | null;
  capaError: string | null;
  decompileError: string | null;
  done: boolean;
}
