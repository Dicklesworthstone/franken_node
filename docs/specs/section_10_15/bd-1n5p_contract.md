---
schema_version: obl-v1.0
bead_id: bd-1n5p
section: "10.15"
title: "Replace Critical Ad Hoc Messaging with Obligation-Tracked Two-Phase Channels"
---

# bd-1n5p: Replace Critical Ad Hoc Messaging with Obligation-Tracked Two-Phase Channels

## Summary

Replaces ad hoc publish/revoke/quarantine/migration messaging in the connector layer
with obligation-tracked two-phase channels. Every side-effecting operation is wrapped
in a reserve/commit/rollback protocol that prevents obligation leaks, partial commits,
and orphaned state transitions.

## Two-Phase Channel Contract

The `ObligationTracker` module enforces a two-phase protocol for all critical
connector operations:

```
reserve() -> ObligationId
  |
  +-- commit()   -> COMMITTED   (effect permanent, visible)
  |
  +-- rollback() -> ROLLED_BACK (tentative resources freed)
  |
  +-- (timeout)  -> LEAKED      (force-rolled-back by leak oracle)
```

### Obligation Lifecycle

```
RESERVED --commit()--> COMMITTED
RESERVED --rollback()--> ROLLED_BACK
RESERVED --(leak_timeout)--> LEAKED (force-rolled-back)
```

Valid terminal states: `COMMITTED`, `ROLLED_BACK`, `LEAKED`.

### Tracked Flows (Integration Points)

| Flow | Module | Description |
|------|--------|-------------|
| publish | connector/lifecycle.rs | Trust object publication |
| revoke | connector/lifecycle.rs | Trust object revocation |
| quarantine | connector/quarantine_promotion.rs | Quarantine entry/exit |
| migration | connector/schema_migration.rs | Schema migration step |
| fencing | connector/fencing.rs | Fencing token lifecycle |

### Leak Oracle Specification

A periodic sweep scans for obligations that remain in `Reserved` state beyond a
configurable timeout (default: 30 seconds). Leaked obligations are force-rolled-back
and emitted as OBL-004 events. The scan itself emits OBL-005.

- **Interval**: configurable via `leak_timeout_secs` (default 30s)
- **Action**: force-rollback stale reservations
- **Telemetry**: OBL-004 per leaked obligation, OBL-005 per scan completion
- **Report**: `artifacts/10.15/obligation_leak_oracle_report.json` contains per-flow counts

### ObligationGuard (Drop Safety)

The `ObligationGuard` struct wraps a reserved obligation and implements `Drop`. If the
guard is dropped without an explicit `commit()` or `rollback()`, the obligation is
automatically rolled back, satisfying INV-OBL-DROP-SAFE. Drop-time cleanup that finds
an already-terminal or missing obligation emits OBL-006 structured diagnostics instead
of silently succeeding.

## Invariants

| ID | Statement |
|----|-----------|
| INV-OBL-TWO-PHASE | Every side-effecting operation goes through reserve/commit/rollback |
| INV-OBL-NO-LEAK | No obligation remains in Reserved state beyond the leak timeout |
| INV-OBL-BUDGET-BOUND | Total concurrent reservations per flow are bounded by a configurable budget |
| INV-OBL-DROP-SAFE | Dropping an uncommitted ObligationGuard triggers automatic rollback |
| INV-OBL-ATOMIC-COMMIT | Commit is all-or-nothing; partial commits are impossible |
| INV-OBL-ROLLBACK-SAFE | Rollback is idempotent and always succeeds |
| INV-OBL-AUDIT-COMPLETE | Every reserve/commit/rollback emits an auditable event |
| INV-OBL-SCAN-PERIODIC | The leak oracle runs on a configurable interval |

## Event Codes

| Code | Description |
|------|-------------|
| OBL-001 | Obligation reserved |
| OBL-002 | Obligation committed |
| OBL-003 | Obligation rolled back |
| OBL-004 | Obligation leak detected (force-rollback) |
| OBL-005 | Leak scan completed |
| OBL-006 | Guard drop observed terminal or missing state and skipped rollback |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_OBL_ALREADY_COMMITTED | Attempt to rollback or re-commit a committed obligation |
| ERR_OBL_ALREADY_ROLLED_BACK | Attempt to commit or re-rollback a rolled-back obligation |
| ERR_OBL_NOT_FOUND | Obligation ID not found in tracker |
| ERR_OBL_LEAK_TIMEOUT | Obligation exceeded leak timeout threshold |
| ERR_OBL_DUPLICATE_RESERVE | Duplicate reservation attempt for same flow+key |

## Core Types

| Type | Kind | Description |
|------|------|-------------|
| `ObligationTracker` | struct | Central registry of active obligations with reserve/commit/rollback/leak-check operations |
| `ObligationId` | struct | Unique identifier for each obligation |
| `ObligationFlow` | enum | Tracked flow variant: Publish, Revoke, Quarantine, Migration, Fencing |
| `ObligationState` | enum | Lifecycle state: Reserved, Committed, RolledBack, Leaked |
| `Obligation` | struct | A single tracked obligation with ID, flow, state, payload, timestamps |
| `ObligationAuditRecord` | struct | Audit log entry for obligation lifecycle events |
| `LeakScanResult` | struct | Result of a single leak oracle scan |
| `LeakOracleReport` | struct | Aggregated leak oracle report for the artifact |
| `FlowObligationCounts` | struct | Per-flow obligation counts (reserved, committed, rolled_back, leaked) |
| `ObligationGuard` | struct | RAII guard implementing Drop for automatic rollback on scope exit |

## Gate Behavior

The gate script `scripts/check_obligation_tracking.py` validates:

1. Rust module exists at `crates/franken-node/src/connector/obligation_tracker.rs`
2. Spec contract exists at `docs/specs/section_10_15/bd-1n5p_contract.md`
3. Module is wired in `connector/mod.rs`
4. All invariant constants are present in source (INV-OBL-TWO-PHASE, INV-OBL-NO-LEAK, INV-OBL-BUDGET-BOUND, INV-OBL-DROP-SAFE)
5. All event codes OBL-001 through OBL-006 are defined
6. Leak oracle report artifact exists and is valid JSON
7. ObligationGuard with Drop implementation is present
8. Schema version `obl-v1.0` is declared

Exit code 0 on PASS, 1 on FAIL. Use `--json` for machine-readable output.

## Acceptance Criteria

1. `ObligationTracker` module exists in `crates/franken-node/src/connector/obligation_tracker.rs`
2. Module is wired in `connector/mod.rs`
3. Spec contract exists at `docs/specs/section_10_15/bd-1n5p_contract.md`
4. All five tracked flows (publish, revoke, quarantine, migration, fencing) are represented
5. Leak oracle report artifact exists at `artifacts/10.15/obligation_leak_oracle_report.json`
6. Event codes OBL-001 through OBL-006 are defined and emitted
7. All five error codes are defined
8. All eight invariants are referenced in source
9. At least 15 inline tests pass
10. Schema version `obl-v1.0` is declared
11. Verification script passes all checks
12. Serde derives are present for serialization
13. ObligationGuard implements Drop for automatic rollback

## Dependencies

- **Upstream**: bd-3h63 (saga wrappers, 10.15)
- **Downstream**: section 10.15 gate

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
