// Bundles the capa rules into public/rules.json ({ "relative/path.yml": "<yaml>" }) so the
// browser can mount them in the WebAssembly module's in-memory file system.
import { readdir, readFile, writeFile, mkdir, access } from "node:fs/promises";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const candidates = [process.env.CAPA_RULES_DIR, join(root, "rules")];
// In a git worktree the rules submodule may be uninitialised; look in the main checkout too.
const m = root.match(/^(.*)\/\.claude\/worktrees\//);
if (m) candidates.push(join(m[1], "rules"));

let dir = null;
for (const c of candidates) {
  if (!c) continue;
  try { await access(join(c, "anti-analysis")); dir = c; break; } catch {}
}
if (!dir) { console.error("capa rules not found: set CAPA_RULES_DIR or run `git submodule update --init rules`"); process.exit(1); }

const rules = {};
async function walk(d) {
  for (const e of (await readdir(d, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = join(d, e.name);
    if (e.isDirectory()) { if (e.name !== ".git") await walk(p); }
    else if (/\.ya?ml$/.test(e.name)) rules[relative(dir, p)] = await readFile(p, "utf8");
  }
}
await walk(dir);
const out = join(root, "web/public/rules.json");
await mkdir(dirname(out), { recursive: true });
await writeFile(out, JSON.stringify(rules));
console.log(`packed ${Object.keys(rules).length} rules from ${dir} -> web/public/rules.json`);
