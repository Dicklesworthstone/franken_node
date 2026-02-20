# bd-1v65: sqlmodel_rust Integration

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust conformance tests | 42 | 42 |
| Python verification checks | 110 | 110 |
| Python unit tests | 27 | 27 |

## Implementation

`crates/franken-node/src/storage/models.rs` — 21 typed model structs with Serialize/Deserialize, model_name(), table_name(), column_names(), and all_model_metadata() registry.

`tests/conformance/sqlmodel_contracts.rs`

- **Types:** ModelClassification (3 variants), ModelSource (2 variants), TypedModel, DriftResult, RoundTripResult, SqlmodelEvent, SqlmodelIntegrationGate, IntegrationSummary
- **Event codes:** SQLMODEL_SCHEMA_DRIFT_DETECTED, SQLMODEL_ROUND_TRIP_PASS/FAIL, SQLMODEL_MODEL_REGISTERED, SQLMODEL_VERSION_COMPAT_FAIL
- **Invariants:** INV-SMI-DRIFT, INV-SMI-ROUNDTRIP, INV-SMI-MANDATORY, INV-SMI-OWNERSHIP

## Model Coverage

| Classification | Count | Drift | Round-trip |
|----------------|-------|-------|------------|
| Mandatory | 12 | All pass | All pass |
| ShouldUse | 7 | All pass | All pass |
| Optional | 2 | All pass | All pass |
| **Total** | **21** | **0 failures** | **0 failures** |

## Verification Coverage

- File existence (conformance test, CSV, policy matrix, spec doc)
- Rust test count (42, minimum 35)
- Serde derives present
- All 8 types, 12 methods, 5 event codes, 4 invariants verified
- All 42 conformance test names verified
- CSV: 21 rows, all drift pass, all round-trip pass, 12 mandatory, 7 should_use
- All 21 model names verified in CSV
- Spec doc: Types, Methods, Event Codes, Invariants, Acceptance Criteria
