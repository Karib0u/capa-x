# scripts/triage — divergence attribution tools

These answer "*why* does capa-x disagree with the reference here?" for one
divergence at a time. They are not part of any gate and nothing in CI runs
them: `scripts/difftest.py` tells you *that* a sample diverges, and these tell
you *who is at fault*.

Every `KD-` entry in [`KNOWN_DIVERGENCES.md`](../../KNOWN_DIVERGENCES.md) was
produced by one of them. That is why they are kept rather than deleted, and why
their analysis logic should not be casually rewritten — the recorded findings
have to keep meaning what they meant when they were recorded.

All of them need the pinned Python environment (`scripts/check_env.sh`), and
the attribution tools additionally need a release build of `capa` to compare
against. Run them with `.venv/bin/python3`, not the system interpreter.

| Tool | Question it answers |
|---|---|
| `attribute_missing.py` | A rule the reference matched and capa-x did not: which Vivisect function owns that address, does capa-x have that function at all, and *which analysis module created it*? Patches `envi.codeflow.CodeFlowContext.addEntryPoint`, so functions the reference reached by codeflow recursion resolve to the module that seeded the walk. |
| `attribute_extras.py` | A rule capa-x matched and the reference did not: what does the reference think lives at that address — a function it never made, bytes it classified as data, or a function it made but attributed elsewhere? |
| `attribute_shared_extras.py` | The narrower extras case where *both* sides recovered the function: which feature capa-x extracted there is the one the reference did not, and is that a heuristic difference or a port defect? |
| `dump_code_layout.py` | Emits the pinned Vivisect function layout — basic blocks, instruction addresses, CFG edges, call targets, no-return and thunk state — as JSON. The reference side of the layout oracle. |
| `compare_code_layout.py` | Diffs that dump against capa-x's `--dump-code-layout` per function, so ownership is compared function by function rather than as one flattened address set. The exactness track's measuring instrument. |

`_common.py` holds only what all of them need — repo paths, the pinned
interpreter, the difftest cache, and capa-x's recovered layout. Analysis and
classification stay in the individual tools on purpose.
