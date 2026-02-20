# bd-2f43 — Success Criterion: Low-Risk Migration Pathways

**Section:** 13 (Success Criteria)
**Bead:** bd-2f43
**Status:** in-progress
**Owner:** CrimsonCrane

## Summary

Defines the success criterion for low-risk migration pathways targeting Node.js
and Bun runtime cohorts. A migration pathway is considered "low-risk" when it
satisfies quantitative thresholds for success rate, rollback time, and data
integrity, and when every stage of the pathway produces machine-verifiable
evidence.

## Quantitative Targets

| Metric                  | Target            | Measurement Point              |
|-------------------------|-------------------|--------------------------------|
| Migration success rate  | >= 90%            | Post-rollout validation gate   |
| Rollback time           | < 5 min           | Time from rollback trigger to confirmed restore |
| Data-loss guarantee     | Zero              | Byte-level checksum comparison pre/post |
| Risk score threshold    | <= 0.30 (low)     | Composite score before rollout approval |

## Migration Pathway Requirements

### 1. Automated Analysis

Every candidate migration must undergo automated compatibility analysis before
any rollout proceeds. The analysis produces a structured report covering:

- API surface delta between source and target runtimes
- Dependency graph compatibility (transitive closure)
- Behavioral divergence catalog (event loop semantics, module resolution, etc.)
- Resource utilization projection (memory, CPU, file descriptors)

### 2. Risk Scoring

A composite risk score in [0.0, 1.0] is computed from three sub-dimensions:

| Sub-dimension       | Weight | Description                                      |
|---------------------|--------|--------------------------------------------------|
| Compatibility risk  | 0.40   | API surface and behavioral divergence severity   |
| Dependency risk     | 0.35   | Transitive dependency breakage probability       |
| Operational risk    | 0.25   | Deployment complexity, rollback complexity, blast radius |

A pathway is classified as **low-risk** when the composite score <= 0.30.

### 3. Staged Rollout

Rollout proceeds through mandatory stages:

1. **Canary** (1-5% traffic) — minimum 15 min observation window
2. **Progressive** (5-50% traffic, increments of 10%) — minimum 10 min per step
3. **Full** (100% traffic) — final validation within 30 min

Each stage gate requires:
- All health checks green
- Error rate delta < 0.5% above baseline
- Latency p99 delta < 50 ms above baseline

### 4. Rollback Safety

- Rollback must complete in < 5 minutes from trigger
- Rollback is automated when any stage gate fails
- Zero-data-loss guarantee: all writes committed before rollback are preserved
- Rollback evidence includes timestamps, affected cohort size, and root cause tag

## Event Codes

| Code    | Name                | Trigger                                       |
|---------|---------------------|-----------------------------------------------|
| MIG-001 | Pathway Validated   | Automated analysis completes with full report  |
| MIG-002 | Risk Scored         | Composite risk score computed and recorded     |
| MIG-003 | Rollout Staged      | A stage gate is entered or exited              |
| MIG-004 | Rollback Tested     | Rollback drill or actual rollback completes    |

All events are emitted as structured JSON with ISO-8601 timestamps, cohort
identifier, and correlation ID.

## Invariants

| ID                  | Statement                                                        |
|---------------------|------------------------------------------------------------------|
| INV-MIG-PATHWAY     | Every migration has a validated pathway before rollout begins    |
| INV-MIG-RISK        | No pathway with composite risk > 0.30 proceeds without explicit waiver |
| INV-MIG-ROLLBACK    | Rollback completes in < 5 min and preserves all committed data   |
| INV-MIG-EVIDENCE    | Every pathway stage produces machine-verifiable evidence         |

## Acceptance Criteria

1. Verification script `scripts/check_migration_pathways.py` passes all checks
   and produces evidence JSON with `overall_passed: true`.
2. All four invariants are enforced by at least one check each.
3. All four event codes are defined and referenced in implementation or spec.
4. Quantitative targets are encoded as constants, not free-form prose.
5. Unit tests in `tests/test_check_migration_pathways.py` cover success and
   failure paths for every check function.

## Dependencies

- bd-1ta (10.13 epic, closed) — connector modules that pathways build upon
- Section 10.3 migration system beads — foundational migration infrastructure

## Evidence

- `artifacts/section_13/bd-2f43/verification_evidence.json`
- `artifacts/section_13/bd-2f43/verification_summary.md`
