# bd-1n5p Verification Summary: Obligation-Tracked Two-Phase Channels

**Bead:** bd-1n5p
**Section:** 10.15
**Verdict:** PASS
**Date:** 2026-02-22

## Overview

This bead replaces ad hoc fire-and-forget messaging in publish, revoke, quarantine,
migration, and fencing flows with obligation-tracked two-phase channels. Every
side-effecting operation goes through reserve/commit/rollback semantics with a
periodic leak oracle that detects and force-rolls-back orphaned obligations.

## Implementation

- **File:** `crates/franken-node/src/connector/obligation_tracker.rs`
- **Module:** Registered in `connector/mod.rs`
- **Schema version:** obl-v1.0

## Verification Results

| Check                | Status | Details                                          |
|----------------------|--------|--------------------------------------------------|
| SOURCE_EXISTS        | PASS   | obligation_tracker.rs present in connector       |
| EVENT_CODES          | PASS   | 5 codes: OBL-001 through OBL-005                |
| INVARIANTS           | PASS   | 8 invariants defined and enforced                |
| ERROR_CODES          | PASS   | 6 error codes defined                            |
| CORE_TYPES           | PASS   | 10 types: ObligationTracker, FlowObligationCounts, ObligationGuard, etc. |
| TRACKED_FLOWS        | PASS   | 5 flows: publish, revoke, quarantine, migration, fencing |
| REQUIRED_METHODS     | PASS   | 12 methods implemented (incl. try_reserve, per_flow_counts) |
| SCHEMA_VERSION       | PASS   | obl-v1.0 declared                                |
| SERDE_DERIVES        | PASS   | Serialize/Deserialize present                    |
| TEST_COVERAGE        | PASS   | 42 Rust unit tests (>= 15 required)             |
| MODULE_REGISTERED    | PASS   | obligation_tracker in connector/mod.rs           |
| SPEC_EXISTS          | PASS   | Contract spec at section_10_15/bd-1n5p           |
| TWO_PHASE_SPEC       | PASS   | Two-phase effects spec at two_phase_effects.md   |
| ORACLE_REPORT        | PASS   | Leak oracle report with PASS verdict             |
| OBLIGATION_GUARD     | PASS   | ObligationGuard with Drop implementation         |
| BUDGET_ENFORCEMENT   | PASS   | Per-flow budget via try_reserve (default: 256)   |
| LEAKED_STATE         | PASS   | ObligationState::Leaked variant for leak oracle  |
| PER_FLOW_COUNTS      | PASS   | FlowObligationCounts in leak oracle report       |

## Key Design Decisions

1. **Reserve/Commit/Rollback protocol:** Every critical side-effect is first
   reserved (creating a tracked obligation), then committed (fulfilling it),
   or rolled back (releasing tentative resources). INV-OBL-TWO-PHASE.
2. **Leak oracle:** A periodic scan detects obligations stuck in Reserved state
   beyond a configurable timeout, marking them as Leaked and emitting OBL-004
   events. The scan itself emits OBL-005. INV-OBL-NO-LEAK, INV-OBL-SCAN-PERIODIC.
3. **Idempotent rollback:** Rolling back an already-rolled-back or leaked obligation
   is a safe no-op. INV-OBL-ROLLBACK-SAFE.
4. **Audit completeness:** Every lifecycle transition emits an ObligationAuditRecord
   with event code, flow, state, and trace ID. INV-OBL-AUDIT-COMPLETE.
5. **Budget enforcement:** Per-flow concurrent reservation limits via `try_reserve()`
   prevent unbounded resource consumption. INV-OBL-BUDGET-BOUND.
6. **Drop safety:** ObligationGuard implements Drop to auto-rollback on scope exit
   if not explicitly resolved. INV-OBL-DROP-SAFE.
7. **Leaked state:** A dedicated `Leaked` variant in ObligationState distinguishes
   leak-oracle-detected obligations from explicit rollbacks.
8. **Per-flow counts:** The `FlowObligationCounts` struct reports per-flow obligation
   tallies (reserved, committed, rolled_back, leaked) in the leak oracle report.

## Test Coverage

- 42 Rust unit tests covering all invariants, state transitions, Leaked state,
  budget enforcement, per-flow counts, ObligationGuard, leak detection, audit
  logging, flow lifecycle, and error conditions.
- 84 gate checks in verification script with self-test mode.
- 40 Python unit tests for the verification script.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_15/bd-1n5p_contract.md` |
| Rust module | `crates/franken-node/src/connector/obligation_tracker.rs` |
| Leak oracle report | `artifacts/10.15/obligation_leak_oracle_report.json` |
| Verification script | `scripts/check_obligation_tracking.py` |
| Python tests | `tests/test_check_obligation_tracking.py` |
| Verification evidence | `artifacts/section_10_15/bd-1n5p/verification_evidence.json` |
| Verification summary | `artifacts/section_10_15/bd-1n5p/verification_summary.md` |
