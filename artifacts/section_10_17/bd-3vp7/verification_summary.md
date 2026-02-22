# bd-3vp7 Verification Summary

## Scope
Fix compile blocker `E0433` in `crates/franken-node/src/policy/evidence_emission.rs` by ensuring `LedgerCapacity` is imported where used in tests.

## Code change
- Added test-only import:
  - `use crate::observability::evidence_ledger::LedgerCapacity;`
  - location: `crates/franken-node/src/policy/evidence_emission.rs` (`#[cfg(test)] mod tests`)

## Validation
All cargo operations were offloaded via `rch`.

1. Baseline failure observed before fix:
   - command: `rch exec -- cargo test -p frankenengine-node interface_hash::tests:: -- --nocapture`
   - result: exit `101`
   - key failure: `error[E0433]: cannot find type LedgerCapacity in this scope` at `crates/franken-node/src/policy/evidence_emission.rs:494`

2. Post-fix compile check:
   - command: `rch exec -- cargo check -p frankenengine-node --all-targets`
   - result: exit `0`
   - notes: warnings remain in unrelated files; no `E0433` for `LedgerCapacity`.

3. Re-check after import placement cleanup:
   - command: `rch exec -- cargo check -p frankenengine-node --all-targets`
   - result: exit `0`

## Outcome
- `bd-3vp7` objective met: the `LedgerCapacity` missing-type compile blocker is resolved.
