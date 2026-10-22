# Decompiler review page (development only)

A small local page to compare our decompiler output with Ghidra's side by side and record verdicts and
comments. Standard library only; nothing is sent anywhere.

```sh
# 1. the comparison file (it carries both texts); see scripts/decompiler_baseline/README.md
python3 -I scripts/decompiler_baseline/compare.py $O/ghidra $O/native $O/comparison.json --any-module
# 2. serve it and open http://127.0.0.1:8765
python3 -I scripts/decompiler_review/serve.py $O/comparison.json --reviews reviews.jsonl
```

- Several comparison files can be given; they are shuffled with a fixed seed.
- **Blind mode** (the default checkbox) hides our incomplete flag, warnings and status in the list and the
  header until a verdict is saved, so the flag being audited does not lead the reader.
- A verdict is one of: correct, wrong arguments, wrong return, wrong control flow, wrong or missing name,
  other, plus a free comment. **Save** keeps it, **save and next** moves on.
- Reviews are appended to `--reviews` as JSON lines (key `sample@address`, verdict, comment, blind, our
  status, reviewer, time). The newest line for a function wins. `GET /api/summary` gives the audit numbers:
  reviewed and correct among "complete" and among "incomplete" outputs. Review files are not committed.
- Binds `127.0.0.1`, refuses cross-origin and non-JSON posts, and shows sample text with `textContent` only.

Not included on purpose: disassembly or source panes, accounts, editing. Add the disassembly when the flag
audit needs it.
