## Summary

Describe the problem and the result of this change.

## Reference behavior

For behavior changes, identify the pinned upstream file, function, or fixture
that defines the expected result.

## Validation

List the exact commands and results:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Add the relevant inner, smoke, outer, determinism, or benchmark result when the
change can affect it.

## Checklist

- [ ] The change is focused and includes tests where behavior changed.
- [ ] Unknown or unsupported input still fails with context.
- [ ] Untrusted input paths contain no new panic.
- [ ] Output remains deterministic across job counts.
- [ ] No pinned submodule content was modified.
- [ ] Documentation and changelog entries are updated when needed.
- [ ] New dependencies, if any, are justified and audited in the description.
