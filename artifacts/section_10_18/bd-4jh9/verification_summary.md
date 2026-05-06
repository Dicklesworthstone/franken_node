# bd-4jh9: VEF Degraded-Mode Policy — Verification Summary

**Section**: 10.18 — Verifiable Execution Fabric
**Verdict**: PASS
**Date**: 2026-02-21

## Intent

Implement degraded-mode policies for the VEF proof pipeline when it
experiences lag or outage, defining three tiers (`restricted`, `quarantine`,
`halt`) with explicit SLOs, mandatory audit events, and recovery receipts.

## What Was Built

### Rust Implementation (`crates/franken-node/src/security/vef_degraded_mode.rs`)

- `VefDegradedModeEngine`: deterministic state machine with four modes
  (Normal, Restricted, Quarantine, Halt).
- `VefDegradedModeConfig`: policy-configurable SLO thresholds per tier,
  halt multiplier, heartbeat timeout, and stabilization window.
- `ProofLagMetrics`: snapshot struct for proof_lag_secs, backlog_depth,
  error_rate, and heartbeat_age_secs.
- `VefDegradedModeEvent` enum: union of ModeTransition, SloBreach,
  RecoveryInitiated, RecoveryComplete, and TransitionError events.
- `VefRecoveryReceipt`: includes degraded-mode duration, actions affected,
  recovery trigger, and pipeline health snapshot at recovery time.
- Action evaluation with three risk levels: HighRisk, LowRisk, HealthCheck.
- 28 Rust unit tests covering all transition paths, determinism, audit
  events, recovery receipts, custom SLO configuration, fail-closed
  thresholds, and no-silent-transitions invariant.
- Verification script now checks real Rust implementation/test evidence
  directly and has no Python lifecycle simulation checks.

### Specification (`docs/specs/section_10_18/bd-4jh9_contract.md`)

- Defines all three degraded-mode tiers with clear semantics.
- Explicit SLO thresholds for each tier.
- Transition rules (escalation immediate, de-escalation requires
  stabilization window).
- Audit event format with 5 event codes (VEF-DEGRADE-001 through ERR-001).
- Recovery receipt schema.
- 5 formal invariants.

### Policy (`docs/policy/vef_degraded_mode_policy.md`)

- Operator guidance for each tier.
- SLO threshold tables.
- Recovery receipt fields.

## Measured Outcomes

| Metric | Value |
|--------|-------|
| Rust tests | 28 |
| cargo check | PASS (warnings only, no errors) |
| Verification script checks | 100/100, including 6 real Rust evidence checks and 0 simulation checks |
| Python unit tests | 28 passed |
| Self-test checks | 100 passed |
| Transition paths tested | 9 |
| Event codes implemented | 5 |
| Invariants verified | 5 |

## Acceptance Criteria Status

| Criterion | Status |
|-----------|--------|
| Deterministic transitions | PASS |
| Configurable SLO thresholds | PASS |
| Audit events with required fields | PASS |
| Recovery receipts with required fields | PASS |
| No silent mode transitions | PASS |
| Mode enforcement consistent | PASS |

## Files

- `crates/franken-node/src/security/vef_degraded_mode.rs` — Rust implementation
- `crates/franken-node/src/security/mod.rs` — module wiring
- `docs/specs/section_10_18/bd-4jh9_contract.md` — specification
- `docs/policy/vef_degraded_mode_policy.md` — policy document
- `scripts/check_vef_degraded_mode.py` — verification script
- `tests/test_check_vef_degraded_mode.py` — Python unit tests
- `artifacts/section_10_18/bd-4jh9/verification_evidence.json` — evidence
- `artifacts/section_10_18/bd-4jh9/verification_summary.md` — this file
