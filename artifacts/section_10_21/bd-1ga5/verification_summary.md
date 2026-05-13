# bd-1ga5 — Cohort-aware baseline modeling

## Verdict: PASS

## Implementation
- Rust module in `crates/franken-node/src/security/bpet/cohort_baselines.rs`
- Schema-versioned, BTreeMap-based, serde-enabled
- 20+ unit tests, fail-closed, audit trail

## Verification
- **20/20** evidence checks passed
- 23 inline `cohort_baseline_*` unit tests cover validation, deterministic ordering, drift integration, comparison, audit, and serde round-trip behavior
