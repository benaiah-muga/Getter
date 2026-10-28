## Summary

<!-- What problem does this change solve, and why now? -->

## Changes

<!-- Bullet the user-visible and internal changes. Call out protocol/job/ABI or config changes. -->

## Compatibility and security

<!--
- Does this change any wire type, job format, ABI, config key, default, storage
  schema, or CLI flag?
- Does it add a dependency, host capability, unsafe code, or new trust boundary?
- Does it affect at-least-once semantics, output verification, authentication,
  TLS, lease handling, or resource limits?
Write "none" if not applicable, but consider each item.
-->

## Testing

Commands run and results:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

<!-- Include focused tests, the example build/job regeneration, and E2E results if relevant. -->

## Documentation

<!-- Link the docs updated, or explain why no docs change is needed. -->

## Checklist

- [ ] I read [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).
- [ ] The change is focused and does not include unrelated refactors.
- [ ] I added or updated tests for the behavior change.
- [ ] I updated the changelog for user-visible changes.
- [ ] I updated CLI/config/protocol/workload/security docs as applicable.
- [ ] I did not include secrets, tokens, private keys, or production data.
- [ ] Security-sensitive behavior has an explicit test or a documented reason it cannot.
- [ ] If the Wasm artifact changed, I rebuilt it with `scripts/build-example.sh` and regenerated `job.json`.
- [ ] New dependencies are justified, license-compatible, and reflected in `Cargo.lock`.
- [ ] I have not claimed CI or audit results that did not actually run.
