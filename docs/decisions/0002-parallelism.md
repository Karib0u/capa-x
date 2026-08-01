# ADR 0002: No parallelism dependency; scoped threads over an atomic cursor

- Status: Accepted
- Scope: bounded parallel analysis

## Context

The project needs bounded per-function parallelism for feature extraction and
code-scope matching. Earlier performance guidance suggested rayon, while the
dependency policy requires a decision record before adopting a concurrency
crate.

The roadmap also imposes constraints that any candidate has to satisfy:

- `--jobs 1` and `--jobs N` must produce byte-identical output (J2), so the
  join has to be ordered by something other than completion;
- the pool must be per-analysis and bounded, and must not mutate or replace a
  process-global pool;
- `#![forbid(unsafe_code)]` stays, and a worker failure must fail the whole
  analysis with context rather than disappearing.

## What the work actually looks like

Both seams are a **single flat map over a `BTreeMap` of recovered functions**:

- `extract::flirt::enrich_static_features` -- per function, read the immutable
  `Analysis`, produce an owned `FunctionFeatures`;
- `capabilities::find_static_capabilities` -- per function, read the immutable
  ruleset and freeze, produce owned `MatchResults` and a feature count.

There is no nesting, no recursion, no fork-join tree, and no shared mutable
state. Work items are chunky (a whole function's instruction/basic-block
extraction or matching) and highly uneven in size, so what matters is that an
idle worker can immediately claim the next item -- which an `AtomicUsize`
cursor over a slice does directly.

Everything else in the pipeline is serial by design: loading, recovery, FLIRT
classification, ruleset construction, file-scope aggregation, and result
construction. None of them is a parallel-iteration problem.

## Decision

**Add no dependency.** `capa-x/src/parallel.rs` is ~90 lines:
`std::thread::scope` spawns `min(jobs, items.len())` workers, each claiming
indices with `AtomicUsize::fetch_add`, accumulating `(index, result)` pairs
locally and returning them at the join. The caller sorts by index, so results
are in input order and the downstream merge is byte-for-byte the serial one.

## Why not rayon

Not a quality judgement -- rayon is excellent, and if a later phase needs
nested or recursive parallelism this ADR should be revisited. For *this* work:

1. **Its main advantage does not apply.** Work-stealing pays for itself on
   recursive `join`/`par_iter` trees where a worker can subdivide its own
   task. A flat map over a slice cannot subdivide, so a shared cursor achieves
   the same balancing with none of the machinery.
2. **The global pool is the wrong shape.** `par_iter` uses a process-global
   pool; honouring `--jobs` per analysis means building a `ThreadPool` and
   `install`ing on it anyway, which is the same amount of caller code as this
   module's entry point.
3. **Determinism is on us either way.** `rayon` preserves order for indexed
   parallel iterators, but the ordered *error* selection and the "wind down
   after the first failure" behaviour that J2 and A.3 ask for are ours to write
   regardless.
4. **The safety contract has to be re-established.** `rayon` and its
   `crossbeam` dependencies use internal `unsafe`; the project's own
   `forbid(unsafe_code)` is unaffected, but the roadmap's dependency policy
   asks whether the transitive risk is acceptable *for what it buys*. Here it
   buys load balancing we already have.
5. **Boring dependencies.** AGENTS.md requires a justification for any crate
   not named in a brief. This one is named in a brief -- and the justification
   still comes out negative once the work is a flat map.

The cost of the decision is ~90 lines of concurrency code to review and its
seven unit tests, against a dependency whose scheduler is far better tested
than ours. That trade is only defensible because the code is a cursor and a
join with no lifetimes beyond `scope`'s, and because the determinism gate (J2,
  `capa-x/tests/jobs_determinism.rs` plus `scripts/determinism.py`) tests the
property that would actually break.

## Consequences

- No new crate; `cargo tree` for `capa-x` is unchanged.
- `AnalysisOptions` is a library-level parameter, not a global -- two analyses
  in one process cannot interfere, which a global pool would not guarantee.
- A worker panic is re-raised on the calling thread (`resume_unwind`), so a
  panic surfaces identically with and without threads.
- If a later phase introduces genuinely recursive parallel work (a plausible
  candidate is cross-function dataflow), this decision should be re-opened
  rather than extended: the module deliberately exposes only `map`/`try_map`,
  so replacing its internals with `rayon` later is a contained change.
