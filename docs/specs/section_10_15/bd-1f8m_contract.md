# bd-1f8m: Invariant-Breach Runbooks

**Section:** 10.15 — Asupersync-First Integration
**Type:** Documentation
**Status:** Delivered

## Purpose

Provide step-by-step incident runbooks for the three most critical asupersync
invariant breach scenarios: region-quiescence failure (Invariant #2),
obligation leak (Invariant #4), and cancel-timeout (Invariant #3).

## Runbooks

| Runbook | Invariant | Alert | Severity |
|---------|-----------|-------|----------|
| `region_quiescence_breach.md` | #2 Region Quiescence | RegionQuiescenceFailure | CRITICAL |
| `obligation_leak_incident.md` | #4 Obligation Tracking | ObligationLeak | CRITICAL |
| `cancel_timeout_incident.md` | #3 Cancellation Protocol | CancelLatencyBudgetExceeded | WARNING |

## Required Sections Per Runbook

Each runbook must include all four sections:

1. **Detection Signature** — metrics from bd-3gnh dashboards, log event codes, identification steps
2. **Immediate Containment** — stop breach propagation, force-close/release resources
3. **Replay Procedure** — capture state, export trace, replay in deterministic lab (bd-145n) with seed
4. **Rollback Procedure** — revert state, verify health, run integration tests

## Event Codes Referenced

| Runbook | Codes |
|---------|-------|
| Region quiescence | RGN-004, RGN-005 |
| Obligation leak | OBL-004 |
| Cancel timeout | CAN-004 |

## Metrics Referenced

### Region Health
- `fn_region_quiescence_failures`
- `fn_region_close_total`
- `fn_region_active_gauge`

### Obligation Health
- `fn_obligation_leaked_total`
- `fn_obligation_active_gauge`
- `fn_obligation_reserved_total`
- `fn_obligation_committed_total`

### Cancel Latency
- `fn_cancel_total_duration_ms`
- `fn_cancel_drain_duration_ms`
- `fn_cancel_finalize_duration_ms`
- `fn_cancel_request_duration_ms`

## Cross-References

- bd-3gnh: Observability dashboards (metrics source)
- bd-145n: Deterministic lab runtime (replay target)
- bd-2tdi: Region integration tests
- bd-1n5p: Obligation integration tests
- bd-1cs7: Cancel protocol integration tests

## Dependencies

- Upstream: bd-3gnh (observability dashboards must exist for metric references)
- Downstream: bd-20eg (section gate), bd-3qo (execution track epic)
