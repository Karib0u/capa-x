import { Fragment } from "react";

const KEYWORDS = "if|else|while|for|do|return|goto|break|continue|switch|case|default|sizeof|struct|union|enum|typedef";
const TYPES = "void|char|short|int|long|unsigned|signed|float|double|bool|byte|ushort|uint|ulong|code|undefined\\d*|u?int\\d+|xunknown\\d+|_?_?(?:stdcall|cdecl|fastcall|thiscall)";

// Order matters: each alternative claims its text before the later ones see it.
const TOKEN = new RegExp(
  [
    String.raw`(\/\*[\s\S]*?\*\/|\/\/[^\n]*)`,                                // 1 comment
    String.raw`(L?"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`,                          // 2 string
    String.raw`\b(0x[0-9a-fA-F]+|\d+)\b`,                                          // 3 number
    String.raw`\b(${KEYWORDS})\b`,                                                // 4 keyword
    String.raw`\b(${TYPES})\b`,                                                   // 5 type
    String.raw`\b((?:param|local|[a-z]{1,3}Var|[a-z]+Stack)_?\w*)\b`,             // 6 param / local
    String.raw`\b((?:DAT|PTR|LAB|s|u|g|_DAT|_PTR)_[0-9a-fA-F]{5,}|[su]_\w*_[0-9a-fA-F]{6,16}|[A-Za-z]+Stack_[0-9a-f]+)\b`, // 7 global / label
    String.raw`\b(FUN_\w+|[A-Za-z_]\w*(?=\s*\())`,                                         // 8 function call
    String.raw`([+\-*/%&|^~!<>=?:]+|->)`,                                          // 9 operator
  ].join("|"),
  "g",
);
const CLASSES = ["", "tk-c", "tk-s", "tk-n", "tk-k", "tk-t", "tk-v", "tk-g", "tk-f", "tk-o"];

/** Turns the C literal as printed by the decompiler back into the string's content. */
export const unescapeLiteral = (lit: string) =>
  lit.replace(/^L?["']|["']$/g, "").replace(/\\(x[0-9a-fA-F]{2}|.)/g, (_, c: string) =>
    c[0] === "x" ? String.fromCharCode(parseInt(c.slice(1), 16)) : ({ n: "\n", r: "\r", t: "\t", "0": "\0" } as Record<string, string>)[c] ?? c);

/** Minimal C-ish highlighter, enough to make decompiler output scannable. One block per source line. */
export function Code({ text, lineOffset = 0, active, onLine, resolve, onGoto, onString, strAt, inlineStrings = true }: {
  /** Show a referenced string in place of its data label (IDA / Binary Ninja style). */
  inlineStrings?: boolean;
  /** The string stored at a virtual address, if any. */
  strAt?: (address: number) => string | undefined;
  text: string;
  /** Index of the first displayed line within the decompiler's full output. */
  lineOffset?: number;
  /** Indexes (in the full output) of highlighted lines. */
  active?: Set<number>;
  onLine?: (index: number) => void;
  /** Maps an identifier or hex literal to a function entry, if it is one. */
  resolve?: (token: string) => number | undefined;
  onGoto?: (address: number) => void;
  /** Called with the content of a clicked string literal. */
  onString?: (content: string) => void;
}) {
  return (
    <div className="code">
      {text.split("\n").map((line, i) => {
        const index = i + lineOffset;
        return (
          <div key={i} data-ln={index} className={"ln" + (active?.has(index) ? " hl" : "")} onClick={() => onLine?.(index)}>
            {highlightLine(line, resolve, onGoto, onString, strAt, inlineStrings)}
          </div>
        );
      })}
    </div>
  );
}

function highlightLine(
  text: string,
  resolve?: (token: string) => number | undefined,
  onGoto?: (address: number) => void,
  onString?: (content: string) => void,
  strAt?: (address: number) => string | undefined,
  inlineStrings = true,
) {
  const out: React.ReactNode[] = [];
  let last = 0, k = 0;
  for (const m of text.matchAll(TOKEN)) {
    const i = m.index!;
    if (i > last) out.push(<Fragment key={k++}>{text.slice(last, i)}</Fragment>);
    const cls = CLASSES[m.findIndex((g, n) => n > 0 && g !== undefined)];
    if (m[2] && onString) {
      out.push(<a key={k++} className="xref tk-s" href="#str" title="Show in Strings"
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(unescapeLiteral(m[0])); }}>{m[0]}</a>);
      last = i + m[0].length;
      continue;
    }
    // A data label or hex literal that points at a known string: link it and show the string.
    if ((m[3] || m[7]) && onString && strAt) {
      const hit = m[3] ? (m[3].startsWith("0x") ? parseInt(m[3], 16) : undefined) : parseInt(m[0].slice(m[0].lastIndexOf("_") + 1), 16);
      const str = hit === undefined || Number.isNaN(hit) ? undefined : strAt(hit);
      if (str !== undefined) {
        const shown = JSON.stringify(str.length > 60 ? str.slice(0, 60) + "…" : str);
        const where = m[0] + " · 0x" + hit!.toString(16);
        out.push(inlineStrings
          ? <a key={k++} className="xref tk-s" href="#str" title={where}
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(str); }}>{shown}</a>
          : <Fragment key={k++}>
              <a className={"xref " + cls} href="#str" title={"String at 0x" + hit!.toString(16)}
                onClick={(e) => { e.preventDefault(); e.stopPropagation(); onString(str); }}>{m[0]}</a>
              <span className="tk-s str-hint">{" "}{shown}</span>
            </Fragment>);
        last = i + m[0].length;
        continue;
      }
    }
    const target = onGoto && (m[3] || m[8]) ? resolve?.(m[0]) : undefined;
    out.push(target !== undefined
      ? <a key={k++} className={"xref " + cls} href={"#" + target.toString(16)} title={"Go to 0x" + target.toString(16)}
          onClick={(e) => { e.preventDefault(); e.stopPropagation(); onGoto!(target); }}>{m[0]}</a>
      : <span key={k++} className={cls}>{m[0]}</span>);
    last = i + m[0].length;
  }
  out.push(<Fragment key={k++}>{text.slice(last)}</Fragment>);
  return out.length === 1 && text === "" ? "\u200b" : out;
}
