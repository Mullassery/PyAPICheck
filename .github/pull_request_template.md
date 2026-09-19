## What does this change?

<!-- What, and why. Link an issue if one exists. -->

## Checklist

- [ ] `cargo test -p pyapicheck-core` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `pytest tests/ -v` passes (if you touched `python/` or `bindings/`)
- [ ] If this adds a new finding/policy type, it names a specific,
      checkable reason (no black-box scores) — see `CONTRIBUTING.md`.
- [ ] If this touches `ROADMAP.md` scope, I updated it (checked boxes,
      added an honesty/scope-cut note if something was descoped).
- [ ] No new `unwrap()`/`expect()`/`panic!` outside of test code.

## Testing

<!-- What did you actually run, and what was the output? Not "should work." -->
