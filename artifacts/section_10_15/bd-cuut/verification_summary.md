# bd-cuut: Control-Plane Lane Mapping Policy -- Verification Summary

**Section:** 10.15 | **Bead:** bd-cuut | **Date:** 2026-02-22

## Gate Result: PASS

| Metric | Value |
|--------|-------|
| Rust in-module tests | 31 |
| Python gate checks | 62/62 |
| Python unit tests | 43/43 |
| Event codes | 5 (CLP_TASK_ASSIGNED..CLP_PREEMPT_TRIGGERED) |
| Error codes | 8 (ERR_CLP_UNKNOWN_TASK..ERR_CLP_PREEMPT_FAILED) |
| Invariants | 6 verified (INV-CLP-*) |
| Schema version | clp-v1.0 |
| Task classes | 19 across 3 lanes |

## Implementation

- `crates/franken-node/src/control_plane/control_lane_policy.rs` -- Lane policy engine
- `crates/franken-node/src/control_plane/mod.rs` -- Module registration
- `docs/specs/section_10_15/bd-cuut_contract.md` -- Spec contract
- `scripts/check_control_lane_policy.py` -- Verification gate
- `tests/test_check_control_lane_policy.py` -- Python test suite
- `tests/conformance/control_lane_policy.rs` -- Conformance tests
- `docs/specs/control_lane_mapping.md` -- Spec overview

## Key Capabilities

- Three-lane model: Cancel (priority 0), Timed (priority 1), Ready (priority 2)
- 19 well-known task classes with lane assignments
- Budget enforcement: Cancel >= 20%, Timed >= 30%, Ready >= 50%
- Starvation detection with per-lane configurable thresholds
- Priority-based scheduling: Cancel preempts Ready when both pending
- JSONL audit log with schema_version field
- CSV starvation metrics export
- Validate() enforces budget sum <= 100% and per-lane minimums
