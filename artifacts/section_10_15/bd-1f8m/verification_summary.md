# bd-1f8m: Invariant-Breach Runbooks

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 69 | 69 |
| Python unit tests | 50 | 50 |

## Runbooks

| Runbook | Invariant | Severity | Alert |
|---------|-----------|----------|-------|
| Region Quiescence Breach | #2 | CRITICAL | RegionQuiescenceFailure |
| Obligation Leak Incident | #4 | CRITICAL | ObligationLeak |
| Cancel Timeout Incident | #3 | WARNING | CancelLatencyBudgetExceeded |

Each runbook includes:
- **Detection Signature**: Metrics from bd-3gnh dashboards + log event codes
- **Immediate Containment**: Step-by-step isolation and resource release
- **Replay Procedure**: State export + deterministic lab replay (bd-145n) with seed
- **Rollback Procedure**: State revert + integration test validation

## Cross-References

- Dashboard metrics validated against `docs/observability/asupersync_control_dashboards.md`
- All 6 alerts in `alert_policy_map.json` reference bd-1f8m runbooks
- Lab replay references bd-145n deterministic runtime with seed-based reproduction
- Integration test references: bd-2tdi (regions), bd-1n5p (obligations), bd-1cs7 (cancellation)

## Artifacts

- Runbooks: `docs/runbooks/region_quiescence_breach.md`, `obligation_leak_incident.md`, `cancel_timeout_incident.md`
- Verification: `scripts/check_runbook_links.py`
- Unit tests: `tests/test_check_runbook_links.py`
