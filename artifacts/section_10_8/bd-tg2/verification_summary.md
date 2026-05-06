# bd-tg2: Fleet Control API for Quarantine/Revocation Operations

**Section:** 10.8 | **Verdict:** PASS | **Date:** 2026-02-21

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 109 | 109 |
| Rust unit tests | 52 | 52 |
| Real fleet evidence checks | 6 | 6 |

## Implementation

**File:** `crates/franken-node/src/api/fleet_quarantine.rs`

### Core Types (14 structs/enums)
- `QuarantineScope` — zone/tenant scoped quarantine target
- `RevocationScope` — zone/tenant scoped revocation target
- `RevocationSeverity` — Advisory, Mandatory, Emergency
- `FleetAction` — Quarantine, Revoke, Release, Status, Reconcile
- `FleetActionResult` — operation outcome with receipt and convergence
- `FleetStatus` — per-zone fleet health summary
- `FleetControlError` — typed errors with stable codes
- `FleetControlEvent` — structured audit events
- `ConvergenceState` — propagation tracking with ETA
- `ConvergencePhase` — Pending, Propagating, Converged, TimedOut
- `IncidentHandle` — quarantine/revocation incident reference
- `IncidentStatus` — Active, Resolving, Released
- `DecisionReceipt` — signed receipt for every operation
- `FleetControlManager` — central manager with safe-start mode

### Event Codes (5)
| Code | Description |
|------|-------------|
| FLEET-001 | FLEET_QUARANTINE_INITIATED |
| FLEET-002 | FLEET_REVOCATION_ISSUED |
| FLEET-003 | FLEET_CONVERGENCE_PROGRESS |
| FLEET-004 | FLEET_RELEASED |
| FLEET-005 | FLEET_RECONCILE_COMPLETED |

### Error Codes (5)
- FLEET_SCOPE_INVALID, FLEET_ZONE_UNREACHABLE, FLEET_CONVERGENCE_TIMEOUT
- FLEET_ROLLBACK_FAILED, FLEET_NOT_ACTIVATED

### Invariants (5)
- **INV-FLEET-ZONE-SCOPE**: Every operation scoped to zone/tenant
- **INV-FLEET-RECEIPT**: All operations produce signed decision receipts
- **INV-FLEET-CONVERGENCE**: Convergence tracked with progress + ETA
- **INV-FLEET-SAFE-START**: API starts read-only, requires activation
- **INV-FLEET-ROLLBACK**: Release deterministically rolls back state

## Verification Commands

```bash
python3 scripts/check_fleet_quarantine.py --json    # 109/109 PASS
python3 -m pytest tests/test_check_fleet_quarantine.py -v  # all PASS
```
