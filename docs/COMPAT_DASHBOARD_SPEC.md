# Compatibility Regression Dashboard

> Tracks compatibility pass/fail rates by API family and band,
> detects regressions, and produces machine-readable reports for CI.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [COMPATIBILITY_REGISTRY.json](COMPATIBILITY_REGISTRY.json), [DIVERGENCE_LEDGER.json](DIVERGENCE_LEDGER.json)

---

## 1. Purpose

The compatibility regression dashboard provides a single-pane view of franken_node's compatibility status. It aggregates results from the fixture runner and lockstep oracle into actionable summaries organized by API family and band.

## 2. Data Sources

| Source | What it provides |
|--------|-----------------|
| `COMPATIBILITY_REGISTRY.json` | List of all tracked behaviors with band/family |
| L1 lockstep oracle results | Per-fixture pass/fail with runtime comparison |
| `DIVERGENCE_LEDGER.json` | Known accepted divergences |
| Fixture runner results | Per-fixture execution results |

## 3. Dashboard Views

### 3.1 By API Family

Aggregate compatibility status per API family:

```json
{
  "family": "fs",
  "total_behaviors": 10,
  "tested": 8,
  "passing": 7,
  "failing": 1,
  "pass_rate": 0.875,
  "band_breakdown": {
    "core": {"tested": 5, "passing": 5},
    "high-value": {"tested": 2, "passing": 1},
    "edge": {"tested": 1, "passing": 1}
  }
}
```

### 3.2 By Band

Aggregate pass rates per compatibility band:

```json
{
  "band": "core",
  "total_fixtures": 50,
  "passing": 48,
  "failing": 2,
  "pass_rate": 0.96,
  "target": 1.0,
  "meets_target": false
}
```

### 3.3 Trend

Track pass rate changes over time:
- Snapshot per CI run with timestamp
- Delta from previous run
- Rolling 7-day and 30-day averages

### 3.4 Regressions

Newly failing fixtures since last successful run:

```json
{
  "regression": {
    "fixture_id": "fixture:fs:readFile:encoding-edge",
    "previously": "pass",
    "now": "fail",
    "first_failed": "2025-01-15T12:00:00Z",
    "band": "edge"
  }
}
```

## 4. Output Format

The dashboard produces a machine-readable JSON artifact conforming to `schemas/compat_dashboard.schema.json`:

```json
{
  "schema_version": "1.0",
  "timestamp": "2025-01-15T12:00:00Z",
  "overall": {
    "total_behaviors": 100,
    "tested": 80,
    "passing": 75,
    "failing": 5,
    "pass_rate": 0.9375
  },
  "by_family": [...],
  "by_band": [...],
  "regressions": [...]
}
```

## 5. Integration

- **CI Pipeline**: Dashboard artifact generated on every PR and release build
- **Release Gate**: Core band pass_rate < 1.0 blocks release; high-value < 0.95 warns
- **Public Scoreboard**: Dashboard feeds into the public compatibility scoreboard
- **Trend Storage**: Historical snapshots stored in `artifacts/dashboard/`

## 6. References

- [COMPATIBILITY_BANDS.md](COMPATIBILITY_BANDS.md) — Band definitions
- [COMPATIBILITY_REGISTRY.json](COMPATIBILITY_REGISTRY.json) — Behavior registry
- [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md) — Oracle runner
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
