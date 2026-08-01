//! A bounded, deterministic parallel map over an already-built list of work
//! items -- the only concurrency primitive in this crate.
//!
//! Two properties matter more than throughput here, and the shape of this
//! module follows from them:
//!
//! 1. **Determinism.** Results come back in *input* order, never completion
//!    order, so a parallel run and a `--jobs 1` run feed the same values, in
//!    the same sequence, into the same serial merge. Nothing downstream can
//!    observe how many threads ran. The same holds for errors: the *lowest
//!    indexed* failure is the one returned, so a failing analysis reports the
//!    same message every time.
//! 2. **No process-global state.** Each call spawns its own scoped threads and
//!    joins them before returning ([`std::thread::scope`]), so there is no
//!    global pool for one analysis to resize out from under another, and no
//!    thread outlives the borrow it was given.
//!
//! Deliberately not `rayon`: the work here is a single flat map over recovered
//! functions, with
//! no nesting and no recursion, and an atomic cursor over a slice already
//! gives the load balancing a work-stealing scheduler would. See
//! the rationale recorded in `docs/decisions/0002-parallelism.md`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// How many threads an analysis may use. Always at least 1; [`Jobs::SERIAL`]
/// is the reference execution mode against which every parallel run is
/// compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Jobs(usize);

/// Rejecting 0 rather than silently promoting it to 1: `--jobs 0` is a typo or
/// a shell variable that failed to expand, and quietly analysing the sample
/// anyway hides that.
#[derive(Debug, thiserror::Error)]
#[error("job count must be at least 1 (1 is the single-threaded reference mode)")]
pub struct ZeroJobs;

impl Jobs {
    /// Single-threaded. No threads are spawned at all in this mode -- not one
    /// worker, zero -- so the reference execution path stays exactly the code
    /// a serial `for` loop would run.
    pub const SERIAL: Jobs = Jobs(1);

    pub fn new(count: usize) -> Result<Jobs, ZeroJobs> {
        if count == 0 {
            return Err(ZeroJobs);
        }
        Ok(Jobs(count))
    }

    /// Available logical cores, falling back to serial when the platform will
    /// not say (a container with no CPU affinity information, for instance).
    pub fn available() -> Jobs {
        Jobs(
            std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1),
        )
    }

    pub fn get(self) -> usize {
        self.0
    }

    pub fn is_serial(self) -> bool {
        self.0 == 1
    }
}

impl Default for Jobs {
    fn default() -> Self {
        Jobs::available()
    }
}

/// Library-level knobs for one analysis. Passed by reference into the
/// extraction and matching drivers rather than read from a global, so two
/// analyses in one process cannot interfere.
///
/// `format`/`os`/`arch`/`file_only`/`signatures_path` are the analysis-shaped
/// CLI knobs `capa_x::api::analyze` reads; presentation
/// flags (`--json`, verbosity, `--timing`) stay CLI-only. `os`/`arch`/
/// `signatures_path` are `Option` (`None` = auto-detect / embedded
/// signatures) rather than the CLI's `"auto"`-sentinel `String`/`Option<PathBuf>`
/// convention, so [`SERIAL`](Self::SERIAL) stays a `const` -- `api.rs`
/// converts to/from the CLI's own sentinel strings at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisOptions {
    pub jobs: Jobs,
    pub format: crate::api::Format,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub file_only: bool,
    pub signatures_path: Option<std::path::PathBuf>,
}

impl AnalysisOptions {
    /// The reference mode: `--jobs 1`, no threads, the semantic baseline every
    /// other mode must reproduce byte for byte. Every other field is at its
    /// auto-detecting default; adjust with struct-update syntax
    /// (`AnalysisOptions { jobs: ..., ..AnalysisOptions::SERIAL }`) when a
    /// caller needs both.
    pub const SERIAL: AnalysisOptions = AnalysisOptions {
        jobs: Jobs::SERIAL,
        format: crate::api::Format::Auto,
        os: None,
        arch: None,
        file_only: false,
        signatures_path: None,
    };

    pub fn with_jobs(jobs: Jobs) -> AnalysisOptions {
        AnalysisOptions {
            jobs,
            ..AnalysisOptions::SERIAL
        }
    }
}

/// Applies `f` to every item, in parallel when `jobs` allows, returning the
/// results **in input order**.
///
/// The thread count is capped by the item count: a two-function image never
/// spawns eight threads. On failure the lowest-indexed error is returned and
/// the remaining items are abandoned -- workers check the stop flag before
/// claiming more work, so a failure winds the pool down instead of paying for
/// the whole corpus first.
///
/// A worker panic is resumed on the calling thread rather than converted into
/// a value: a panic is a bug in this crate (the no-panic rule covers every
/// path reachable from untrusted input), and it must surface identically
/// whether or not threads were involved.
pub fn try_map<T, R, E, F>(jobs: Jobs, items: &[T], f: F) -> Result<Vec<R>, E>
where
    T: Sync,
    R: Send,
    E: Send,
    F: Fn(&T) -> Result<R, E> + Sync,
{
    if jobs.is_serial() || items.len() < 2 {
        return items.iter().map(&f).collect();
    }

    let workers = jobs.get().min(items.len());
    let cursor = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let f = &f;
    let cursor = &cursor;
    let failed = &failed;

    let outcomes = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(move || {
                    let mut produced: Vec<(usize, R)> = Vec::new();
                    let mut error: Option<(usize, E)> = None;
                    loop {
                        // `Relaxed` is enough for both atomics: the cursor only
                        // has to hand every index to exactly one worker (which
                        // `fetch_add` guarantees on its own), and the flag is a
                        // hint -- correctness comes from checking `error` after
                        // the join, not from how promptly workers notice it.
                        if failed.load(Ordering::Relaxed) {
                            break;
                        }
                        let index = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break;
                        };
                        match f(item) {
                            Ok(value) => produced.push((index, value)),
                            Err(e) => {
                                failed.store(true, Ordering::Relaxed);
                                error = Some((index, e));
                                break;
                            }
                        }
                    }
                    (produced, error)
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| match handle.join() {
                Ok(outcome) => outcome,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect::<Vec<_>>()
    });

    let mut produced: Vec<(usize, R)> = Vec::with_capacity(items.len());
    let mut first_error: Option<(usize, E)> = None;
    for (values, error) in outcomes {
        produced.extend(values);
        if let Some((index, e)) = error {
            let replace = first_error
                .as_ref()
                .is_none_or(|(earlier, _)| index < *earlier);
            if replace {
                first_error = Some((index, e));
            }
        }
    }
    if let Some((_, error)) = first_error {
        return Err(error);
    }

    produced.sort_by_key(|(index, _)| *index);
    // Every index is handed out exactly once by `fetch_add`, so with no error
    // recorded above, every item was processed exactly once.
    debug_assert_eq!(produced.len(), items.len());
    Ok(produced.into_iter().map(|(_, value)| value).collect())
}

/// [`try_map`] for infallible work.
pub fn map<T, R, F>(jobs: Jobs, items: &[T], f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    match try_map(jobs, items, |item| {
        Ok::<R, std::convert::Infallible>(f(item))
    }) {
        Ok(values) => values,
        // `Infallible` is uninhabited, so this arm is unreachable by type.
        Err(never) => match never {},
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_jobs_is_rejected() {
        assert!(Jobs::new(0).is_err());
        assert_eq!(Jobs::new(1).unwrap(), Jobs::SERIAL);
        assert_eq!(Jobs::new(8).unwrap().get(), 8);
    }

    #[test]
    fn available_is_at_least_one() {
        assert!(Jobs::available().get() >= 1);
    }

    #[test]
    fn results_come_back_in_input_order() {
        let items: Vec<usize> = (0..1000).collect();
        for jobs in [1usize, 2, 3, 8, 64] {
            let out = map(Jobs::new(jobs).unwrap(), &items, |item| item * 2);
            let expected: Vec<usize> = items.iter().map(|item| item * 2).collect();
            assert_eq!(out, expected, "jobs={jobs}");
        }
    }

    #[test]
    fn thread_count_is_capped_by_item_count() {
        // A single item must never fan out; the serial path is taken and the
        // closure runs on the calling thread.
        let calling = std::thread::current().id();
        let out = map(Jobs::new(64).unwrap(), &[7usize], |item| {
            (*item, std::thread::current().id() == calling)
        });
        assert_eq!(out, vec![(7, true)]);
    }

    #[test]
    fn the_lowest_indexed_error_wins() {
        // Several items fail; whichever worker gets there first, the reported
        // error is always the earliest one in input order.
        let items: Vec<usize> = (0..500).collect();
        for _ in 0..20 {
            let result = try_map(Jobs::new(8).unwrap(), &items, |item| {
                if *item % 7 == 3 {
                    Err(*item)
                } else {
                    Ok(*item)
                }
            });
            assert_eq!(result, Err(3));
        }
    }

    #[test]
    fn an_error_stops_the_remaining_work() {
        let items: Vec<usize> = (0..10_000).collect();
        let processed = AtomicUsize::new(0);
        let result = try_map(Jobs::new(4).unwrap(), &items, |item| {
            processed.fetch_add(1, Ordering::Relaxed);
            if *item == 0 {
                Err("stop")
            } else {
                // Slow the survivors down so "the pool wound down" is a real
                // claim rather than a race the test happens to win.
                std::thread::yield_now();
                Ok(*item)
            }
        });
        assert_eq!(result, Err("stop"));
        assert!(
            processed.load(Ordering::Relaxed) < items.len(),
            "every item ran despite an early failure"
        );
    }

    #[test]
    fn serial_and_parallel_agree_on_the_same_input() {
        let items: Vec<u64> = (0..2000).map(|i| i * 31 % 977).collect();
        let serial = map(Jobs::SERIAL, &items, |item| item.wrapping_mul(2654435761));
        for jobs in [2usize, 4, 16] {
            let parallel = map(Jobs::new(jobs).unwrap(), &items, |item| {
                item.wrapping_mul(2654435761)
            });
            assert_eq!(serial, parallel, "jobs={jobs}");
        }
    }

    #[test]
    fn a_worker_panic_reaches_the_caller() {
        let items: Vec<usize> = (0..100).collect();
        let outcome = std::panic::catch_unwind(|| {
            map(Jobs::new(4).unwrap(), &items, |item| {
                assert_ne!(*item, 50, "injected worker panic");
                *item
            })
        });
        assert!(outcome.is_err(), "a worker panic was swallowed");
    }
}
