#!/usr/bin/env python3
"""Development-only: a small local page to compare our decompiler output with Ghidra's and comment.

usage: serve.py COMPARISON_JSON [COMPARISON_JSON ...] [--reviews FILE] [--port N] [--reviewer NAME]

COMPARISON_JSON is what scripts/decompiler_baseline/compare.py writes (it carries both texts). Open
http://127.0.0.1:PORT. Verdicts and comments are appended to --reviews (default reviews.jsonl) as one JSON
object per line; the newest line for a function wins. Blind mode (default) hides our incomplete flag and
warnings until the verdict is saved, so the flag is not what leads the reader.

Local only: binds 127.0.0.1, refuses cross-origin posts, and the page only ever inserts sample text with
textContent, because strings from a sample can contain markup. Standard library only.
"""
import argparse, difflib, json, os, random, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

VERDICTS = ["correct", "wrong arguments", "wrong return", "wrong control flow", "wrong or missing name", "other"]


def load(paths):
    items = []
    for path in paths:
        for row in json.load(open(path)):
            items.append({
                "sample": row["sample"], "address": row["address"], "role": row.get("role", ""),
                "status": row.get("n_status", ""), "unknown": bool(row.get("n_unknown_callees")),
                "warnings": row.get("n_warnings", []), "missing": row.get("missing_callees", []),
                "native": row.get("n_c") or "", "ghidra": row.get("g_c") or "",
                "native_error": row.get("n_error", ""), "gsize": row.get("gsize", 0),
            })
    return items


def key(item):
    return item["sample"] + "@" + item["address"]


def read_reviews(path):
    latest = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            try:
                review = json.loads(line)
                latest[review["key"]] = review
            except (ValueError, KeyError):
                continue
    return latest


def diff_rows(left, right):
    """Aligned rows (left line, right line, changed) from a line diff."""
    a, b = left.splitlines(), right.splitlines()
    rows = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        for k in range(max(i2 - i1, j2 - j1)):
            x = a[i1 + k] if i1 + k < i2 else None
            y = b[j1 + k] if j1 + k < j2 else None
            rows.append([x, y, tag != "equal"])
    return rows


PAGE = """<!doctype html><meta charset=utf-8><title>Decompiler review</title>
<style>
body{font:13px system-ui,sans-serif;margin:0;display:flex;height:100vh}
#list{width:300px;overflow:auto;border-right:1px solid #8885;padding:6px}
#main{flex:1;overflow:auto;padding:8px 12px}
.item{padding:3px 5px;cursor:pointer;border-radius:3px;white-space:nowrap}
.item:hover{background:#8883}.item.cur{background:#4a8fe744}
.done::before{content:"\\2713 ";color:#2a2}
pre{margin:0;font:12px ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:0 8px}
.cols>div{padding:0 4px;min-height:1.3em}
.chg{background:#e8b84b33}.head{font-weight:600;padding:4px}
textarea{width:100%;height:70px;font:inherit}button,select,input[type=text]{font:inherit}
.small{color:#888}.flag{display:inline-block;padding:0 6px;border-radius:8px;background:#8883}
</style>
<div id=list><div><input id=q type=text placeholder="filter" style="width:150px">
<label><input id=blind type=checkbox checked> blind</label></div>
<div class=small id=count></div><div id=items></div></div>
<div id=main><div id=info class=small>pick a function</div>
<div id=flags></div>
<div class=cols id=cols></div>
<div style="margin-top:10px"><select id=verdict></select>
<button id=save>save</button> <button id=savenext>save and next</button>
<span id=saved class=small></span><textarea id=comment placeholder="comment"></textarea></div></div>
<script>
let items=[],cur=-1,reviews={};
const $=id=>document.getElementById(id);
const blind=()=>$('blind').checked;
async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});return r.json()}
function mk(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
function renderList(){
  const q=$('q').value.toLowerCase(),box=$('items');box.textContent='';let n=0,d=0;
  items.forEach((it,i)=>{const k=it.sample+'@'+it.address;
    if(q&&!(k.toLowerCase().includes(q)||it.role.includes(q)))return;
    n++;const done=!!reviews[k];if(done)d++;
    const e=mk('div',it.sample.slice(0,8)+' '+it.address+' '+it.role+(blind()?'':' ['+it.status+']'),'item'+(i==cur?' cur':'')+(done?' done':''));
    e.onclick=()=>show(i);box.appendChild(e)});
  $('count').textContent=n+' shown, '+d+' reviewed'}
async function show(i){
  cur=i;const it=items[i],k=it.sample+'@'+it.address,r=reviews[k]||{};
  $('info').textContent=it.sample+' '+it.address+' '+it.role+' (Ghidra size '+it.gsize+')';
  const fl=$('flags');fl.textContent='';
  if(!blind()||r.verdict){fl.appendChild(mk('span',it.status+(it.unknown?', unknown callees':''),'flag'));
    if(it.native_error)fl.appendChild(mk('span',' '+it.native_error,'small'));
    if(it.missing.length)fl.appendChild(mk('span',' Ghidra names, we do not: '+it.missing.join(', '),'small'));
    if(it.warnings.length)fl.appendChild(mk('div',it.warnings.join(' | '),'small'))}
  const rows=(await api('/api/diff/'+i)).rows,c=$('cols');c.textContent='';
  c.appendChild(mk('div','ours','head'));c.appendChild(mk('div','Ghidra','head'));
  for(const [x,y,ch] of rows){for(const t of [x,y]){const d=mk('div');const p=mk('pre',t===null?'':t);d.appendChild(p);if(ch)d.className='chg';c.appendChild(d)}}
  $('verdict').value=r.verdict||'';$('comment').value=r.comment||'';$('saved').textContent=r.verdict?'saved':'';renderList()}
async function save(next){
  if(cur<0||!$('verdict').value)return;const it=items[cur],k=it.sample+'@'+it.address;
  const rev=await api('/api/review',{key:k,verdict:$('verdict').value,comment:$('comment').value,blind:blind(),status:it.status,unknown:it.unknown});
  reviews[k]=rev;$('saved').textContent='saved';renderList();if(next&&cur+1<items.length)show(cur+1)}
(async()=>{const d=await api('/api/items');items=d.items;reviews=d.reviews;
  const v=$('verdict');v.appendChild(new Option('verdict...',''));for(const x of d.verdicts)v.appendChild(new Option(x,x));
  $('q').oninput=renderList;$('blind').onchange=()=>{renderList();if(cur>=0)show(cur)};
  $('save').onclick=()=>save(false);$('savenext').onclick=()=>save(true);renderList();if(items.length)show(0)})();
</script>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--reviews", default="reviews.jsonl")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--reviewer", default=os.environ.get("USER", ""))
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    items = load(args.inputs)
    random.Random(args.seed).shuffle(items)  # stable, so blind order does not follow the data
    origin = f"http://127.0.0.1:{args.port}"

    class Handler(BaseHTTPRequestHandler):
        def send(self, body, kind="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
            self.send_response(200)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/":
                self.send(PAGE, "text/html")
            elif self.path == "/api/items":
                slim = [{k: v for k, v in it.items() if k not in ("native", "ghidra")} for it in items]
                self.send(json.dumps({"items": slim, "reviews": read_reviews(args.reviews), "verdicts": VERDICTS}))
            elif self.path.startswith("/api/diff/"):
                try:
                    it = items[int(self.path.rsplit("/", 1)[1])]
                except (ValueError, IndexError):
                    return self.send_error(404)
                self.send(json.dumps({"rows": diff_rows(it["native"], it["ghidra"])}))
            elif self.path == "/api/summary":
                self.send(json.dumps(summary(items, read_reviews(args.reviews))))
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path != "/api/review":
                return self.send_error(404)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.send_error(415)
            if self.headers.get("Origin") not in (None, origin):
                return self.send_error(403)
            length = int(self.headers.get("Content-Length", "0"))
            if length > 100_000:
                return self.send_error(413)
            try:
                body = json.loads(self.rfile.read(length))
                review = {"key": str(body["key"]), "verdict": str(body["verdict"]), "comment": str(body.get("comment", "")),
                          "blind": bool(body.get("blind")), "status": str(body.get("status", "")),
                          "unknown": bool(body.get("unknown")), "reviewer": args.reviewer,
                          "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
            except (ValueError, KeyError):
                return self.send_error(400)
            if review["verdict"] not in VERDICTS:
                return self.send_error(400)
            with open(args.reviews, "a", encoding="utf-8") as out:
                out.write(json.dumps(review) + "\n")
            self.send(json.dumps(review))

        def log_message(self, *a):
            pass

    print(f"{len(items)} functions; reviews go to {args.reviews}; open {origin}", file=sys.stderr)
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


def summary(items, reviews):
    """Audit numbers: how right the 'complete' outputs are, and how many wrong ones were flagged."""
    by = {"complete": [0, 0], "incomplete": [0, 0]}
    for it in items:
        r = reviews.get(key(it))
        if not r:
            continue
        group = "complete" if it["status"] == "ok" else "incomplete"
        by[group][0] += 1
        by[group][1] += r["verdict"] == "correct"
    return {"reviewed": sum(v[0] for v in by.values()),
            **{g: {"reviewed": v[0], "correct": v[1]} for g, v in by.items()}}


if __name__ == "__main__":
    main()
