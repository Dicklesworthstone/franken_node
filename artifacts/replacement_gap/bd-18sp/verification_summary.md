# bd-18sp Verification Summary

**Section:** 10.11
**Completion-debt bead:** bd-18sp.1
**Verdict:** PASS

## Scope Delivered

The supervision temporal kernel now keeps restart-budget timestamps in a
monotone queue, prunes expired entries from the front on failure handling,
computes health-window state without allocating a filtered restart vector, and
adds an explicit `record_health_report()` path for structured `SUP-008` event
emission. The monotonic clock abstraction itself was already present; this bead
hardens the remaining restart-window implementation and adds regression checks
so synthetic time stubs do not silently return.

## Verification Status

- bd-18sp.1 completion-debt items are covered in
  `artifacts/replacement_gap/bd-18sp/verification_evidence.json`:
  `tests.unit.primary`, `tests.integration.primary`, `tests.e2e.primary`, and
  `tests.property.primary`.
- Package-level `cargo check -p frankenengine-node --lib --tests` is currently
  blocked by unrelated upstream errors in
  `franken_engine/src/ts_module_resolution.rs` (`lookup_exact_slot` missing).
- An isolated harness that path-includes
  `crates/franken-node/src/connector/supervision.rs` passed remote unit tests:
  `29 passed, 0 failed, 2 ignored`.
- The harness external-crate public API tests passed:
  `2 passed, 0 failed`.
- Harness clippy passed with `-D warnings`.
- The exhaustive/reference schedule search and source-level stub checker both
  passed inside the harness lane.

## Benchmark Result

Same-worker `hyperfine` against the retained Vec reference kernel showed:

- `reference`: `156.9 ms` mean
- `monotone-queue`: `116.1 ms` mean
- relative result: `1.35x` faster

Machine-readable benchmark output is in
`artifacts/replacement_gap/bd-18sp/hyperfine_supervision_kernel.json`.

## Notes

- The repository-level integration test file is present at
  `crates/franken-node/tests/supervision_temporal_kernel.rs`, but package-level
  cargo verification for that target is presently gated on the unrelated
  upstream `franken_engine` compile failure.
- The isolated harness under `artifacts/replacement_gap/bd-18sp/` exists only
  to verify the actual touched source file while that blocker remains active.
