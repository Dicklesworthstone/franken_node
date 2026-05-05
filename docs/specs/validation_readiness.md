# Validation Readiness Report

**Bead:** bd-mwu8b
**Input schema:** `franken-node/validation-readiness/input/v1`
**Report schema:** `franken-node/validation-readiness/report/v1`

## Purpose

`franken-node ops validation-readiness` tells operators whether validation
broker evidence is trustworthy right now. It aggregates Beads validation
requirements, broker proof statuses, validation receipts, RCH worker readiness,
and resource-governor contention hints into one pass/warn/fail report.

The report is intentionally not a closeout shortcut. A blocked or closed Bead
that requires validation is not considered complete unless the report sees a
fresh passing broker receipt or an explicit source-only waiver.

## CLI

```bash
franken-node ops validation-readiness \
  --input artifacts/validation_broker/readiness-snapshot.json \
  --receipt artifacts/validation_broker/bd-example/receipt.json \
  --trace-id ops-validation-readiness \
  --json
```

`--input` is optional. If omitted, the command emits a warning report that no
broker state was supplied. `--receipt` may be repeated; those receipt files are
merged into the snapshot before evaluation.

## Stable Checks

| Code | Scope | Pass | Warn | Fail |
|------|-------|------|------|------|
| `VR-SCHEMA-001` | `validation_readiness.schema` | supported input schema | n/a | unsupported schema |
| `VR-BROKER-002` | `validation_broker.state` | receipts or proof statuses supplied | no broker state supplied | n/a |
| `VR-BEAD-003` | `beads.validation_receipts` | tracked Beads have receipts or source-only waivers | open/running Beads still need proof | blocked/closed Beads lack proof |
| `VR-RECEIPT-004` | `validation_broker.receipt_freshness` | receipts validate and are fresh | no receipts or older than max age | stale or malformed receipts |
| `VR-PROOF-005` | `validation_broker.proof_status` | terminal proof with no failures | queued/running or worker/resource failure | product compile/test/format/clippy failure |
| `VR-RCH-006` | `rch.worker_readiness` | remote RCH proof or worker observations are healthy | missing/degraded worker observations | remote-required receipt did not run remotely |
| `VR-RESOURCE-007` | `resource_governor.contention` | resource governor allows validation | defer/source-only/dedupe/reject or missing observation | n/a |

## Failure Domains

The proof check separates product failures from infrastructure pressure:

- product: compile errors, test failures, clippy warnings, or format failures;
- worker: RCH transport timeouts, worker infrastructure errors, cancellation,
  or timeout exits;
- resource: environment contention and disk pressure.

Worker and resource failures never count as product green. They are warnings
that require retry, backoff, or an explicit source-only waiver.

## JSON Shape

The report includes:

- `overall_status` and `status_counts`;
- `checks[]` with stable `code`, `event_code`, `scope`, `status`, `message`,
  and `remediation`;
- `summary.proof_counts` for queued, leased, running, reused, passed, failed,
  source-only, cancelled, and unknown proof states;
- receipt freshness counters;
- missing required receipt count;
- product, worker, and resource failure counters;
- RCH remote receipt counters;
- `last_successful_cargo_proof_at`;
- `contention_state`.

## Fixtures

Golden fixtures live at:

`artifacts/validation_broker/bd-mwu8b/validation_readiness_fixtures.v1.json`

They cover empty broker state, blocked Beads without receipts, explicit
source-only waivers, and contention deferral.
