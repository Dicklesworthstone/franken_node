# bd-3gnh: Observability Dashboards for Asupersync Control Health

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 39 | 39 |
| Python unit tests | 26 | 26 |

## Dashboard Panels

- **Region Health**: open/close/quiescence metrics (4 metrics)
- **Obligation Health**: reserve/commit/leak metrics (4 metrics)
- **Lane Pressure**: task count/starvation/throughput (3 metrics)
- **Cancel Latency**: request/drain/finalize/total histograms (4 metrics)

## Alert Thresholds

6 alerts defined, all with runbook links (bd-1f8m), severity levels, and dashboard categories.

## Artifacts

- Dashboard doc: `docs/observability/asupersync_control_dashboards.md`
- Snapshot: `artifacts/10.15/dashboard_snapshot.json`
- Alert map: `artifacts/10.15/alert_policy_map.json`
- Verification: `scripts/check_observability_dashboards.py`
- Unit tests: `tests/test_check_observability_dashboards.py`
