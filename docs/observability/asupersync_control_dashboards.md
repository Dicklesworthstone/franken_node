# Asupersync Control Dashboards

## Bead: bd-3gnh | Section: 10.15

## Purpose

Exposes core asupersync runtime health signals via structured dashboard panels and
alert thresholds. Maps every alert to a specific runbook action from bd-1f8m so
operators can respond to invariant stress before user-facing outages occur.

## Dashboard Panels

### 1. Region Health

| Metric | Type | Labels | Emission Point |
|--------|------|--------|----------------|
| `fn_region_open_total` | counter | `region_id` | lifecycle.rs: region open |
| `fn_region_close_total` | counter | `region_id`, `outcome` | lifecycle.rs: region close |
| `fn_region_quiescence_failures` | counter | `region_id` | lifecycle.rs: quiescence timeout |
| `fn_region_active_gauge` | gauge | none | lifecycle.rs: region state poll |

**Panel queries:**
- Active regions: `fn_region_active_gauge`
- Closing rate: `rate(fn_region_close_total[5m])`
- Quiescence failures: `fn_region_quiescence_failures`

### 2. Obligation Health

| Metric | Type | Labels | Emission Point |
|--------|------|--------|----------------|
| `fn_obligation_reserved_total` | counter | `obligation_type` | obligation tracker: reserve |
| `fn_obligation_committed_total` | counter | `obligation_type` | obligation tracker: commit |
| `fn_obligation_leaked_total` | counter | `obligation_type` | obligation tracker: leak detected |
| `fn_obligation_active_gauge` | gauge | none | obligation tracker: state poll |

**Panel queries:**
- Active obligations: `fn_obligation_active_gauge`
- Commit rate: `rate(fn_obligation_committed_total[1m])`
- Leak total: `fn_obligation_leaked_total`

### 3. Lane Pressure

| Metric | Type | Labels | Emission Point |
|--------|------|--------|----------------|
| `fn_lane_task_count` | gauge | `lane_id` | scheduler: task enqueue/dequeue |
| `fn_lane_starvation_ticks` | counter | `lane_id` | scheduler: starvation check |
| `fn_lane_throughput` | counter | `lane_id` | scheduler: task complete |

**Panel queries:**
- Per-lane task count: `fn_lane_task_count{lane_id=~".*"}`
- Starvation events: `rate(fn_lane_starvation_ticks[5m]) by (lane_id)`
- Lane throughput: `rate(fn_lane_throughput[1m]) by (lane_id)`

### 4. Cancel Latency

| Metric | Type | Labels | Emission Point |
|--------|------|--------|----------------|
| `fn_cancel_request_duration_ms` | histogram | `phase` | cancellation: request phase |
| `fn_cancel_drain_duration_ms` | histogram | `phase` | cancellation: drain phase |
| `fn_cancel_finalize_duration_ms` | histogram | `phase` | cancellation: finalize phase |
| `fn_cancel_total_duration_ms` | histogram | `workflow` | cancellation: end-to-end |

**Panel queries:**
- Cancel p50: `histogram_quantile(0.5, fn_cancel_total_duration_ms)`
- Cancel p95: `histogram_quantile(0.95, fn_cancel_total_duration_ms)`
- Cancel p99: `histogram_quantile(0.99, fn_cancel_total_duration_ms)`

## Alert Thresholds

| Alert Name | Condition | Severity | Runbook |
|------------|-----------|----------|---------|
| `RegionQuiescenceFailure` | `fn_region_quiescence_failures` increase > 0 in 5min | CRITICAL | bd-1f8m: region-quiescence-failure |
| `ObligationLeak` | `fn_obligation_leaked_total` increase > 0 | CRITICAL | bd-1f8m: obligation-leak |
| `LaneStarvation` | `fn_lane_starvation_ticks` > 3 consecutive in any lane | WARNING | bd-1f8m: lane-starvation |
| `CancelLatencyBudgetExceeded` | `fn_cancel_total_duration_ms` p99 > budget_ms | WARNING | bd-1f8m: cancel-timeout |
| `HighObligationCount` | `fn_obligation_active_gauge` > threshold | WARNING | bd-1f8m: obligation-accumulation |
| `RegionCloseFailureRate` | `rate(fn_region_close_total{outcome="failure"})` > 0.01 | WARNING | bd-1f8m: region-close-failure |

## Metrics Schema Versioning

- Metric names use `fn_` prefix for franken_node namespace.
- Label names are snake_case and stable across versions.
- Any metric rename requires a version bump in `dashboard_snapshot.json`.
- Schema version: `1.0`

## Event Codes

| Code | When Emitted |
|------|-------------|
| OBS-001 | Metric value emitted |
| OBS-002 | Alert threshold crossed |
| OBS-003 | Alert resolved (metric returned to safe range) |
| OBS-004 | Dashboard snapshot generated |

## Invariants

| ID | Statement |
|----|-----------|
| INV-OBS-COMPLETE | All four metric categories have emission points |
| INV-OBS-ALERT-LINKED | Every alert has a runbook reference |
| INV-OBS-STABLE-SCHEMA | Metric names and labels do not change without versioning |
| INV-OBS-FAIL-VISIBLE | Invariant breaches are surfaced within one dashboard poll interval |
