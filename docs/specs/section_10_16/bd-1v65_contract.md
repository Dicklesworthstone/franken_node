# bd-1v65: sqlmodel_rust Integration

**Section:** 10.16 — Adjacent Substrate Integration
**Status:** Implementation Complete

## Purpose

Integrate sqlmodel_rust typed models for all persistence domains classified
as mandatory or should_use in the bd-bt82 policy. Schema drift is caught at
compile time and CI; round-trip serialization conformance is verified for
each integrated domain.

## Scope

- 21 persistence domains: 12 mandatory, 7 should_use, 2 optional
- Typed model structs with owner module, classification, source, version
- Schema drift detection and round-trip serialization conformance
- Gate blocking on drift failures or mandatory/should_use round-trip failures
- Integration domains CSV with per-domain status

## Types

| Type | Kind | Description |
|------|------|-------------|
| `ModelClassification` | enum | Mandatory, ShouldUse, Optional |
| `ModelSource` | enum | HandAuthored, Codegen |
| `TypedModel` | struct | Domain, owner, classification, source, model name, version |
| `DriftResult` | struct | Model name, drift detected flag, detail |
| `RoundTripResult` | struct | Model name, passed flag, latency |
| `SqlmodelEvent` | struct | Code, model name, detail |
| `SqlmodelIntegrationGate` | struct | Gate engine with models, drift/RT results, events |
| `IntegrationSummary` | struct | Aggregate counts by classification and failure type |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `ModelClassification::all()` | Classification | All three variants |
| `ModelClassification::label()` | Classification | Human-readable label |
| `ModelClassification::is_mandatory()` | Classification | True only for Mandatory |
| `SqlmodelIntegrationGate::register_model()` | Gate | Register a typed model |
| `SqlmodelIntegrationGate::check_drift()` | Gate | Record drift check result |
| `SqlmodelIntegrationGate::check_round_trip()` | Gate | Record round-trip result |
| `SqlmodelIntegrationGate::gate_pass()` | Gate | True if no drift, no mandatory/should_use RT failures |
| `SqlmodelIntegrationGate::summary()` | Gate | Aggregate counts |
| `SqlmodelIntegrationGate::models()` | Gate | Borrow model list |
| `SqlmodelIntegrationGate::events()` | Gate | Borrow event log |
| `SqlmodelIntegrationGate::take_events()` | Gate | Drain event log |
| `SqlmodelIntegrationGate::to_report()` | Gate | Structured JSON report |

## Event Codes

| Code | Level | Trigger |
|------|-------|---------|
| `SQLMODEL_SCHEMA_DRIFT_DETECTED` | error | Schema drift found |
| `SQLMODEL_ROUND_TRIP_PASS` | info | Round-trip passed |
| `SQLMODEL_ROUND_TRIP_FAIL` | error | Round-trip failed |
| `SQLMODEL_MODEL_REGISTERED` | info | Model registered |
| `SQLMODEL_VERSION_COMPAT_FAIL` | error | Version compatibility failure |

## Invariants

| ID | Rule |
|----|------|
| `INV-SMI-DRIFT` | No schema drift across any integrated domain |
| `INV-SMI-ROUNDTRIP` | Round-trip passes for mandatory and should_use domains |
| `INV-SMI-MANDATORY` | All 12 mandatory domains have typed models |
| `INV-SMI-OWNERSHIP` | Each model has exactly one owner module |

## Artifacts

| File | Description |
|------|-------------|
| `tests/conformance/sqlmodel_contracts.rs` | 42 Rust conformance tests |
| `artifacts/10.16/sqlmodel_integration_domains.csv` | 21 domains, all pass |
| `scripts/check_sqlmodel_integration.py` | Verification script |
| `tests/test_check_sqlmodel_integration.py` | Python unit tests |

## Acceptance Criteria

1. All 21 domains from bd-bt82 policy have typed model structs
2. 12 mandatory domains classified correctly
3. 7 should_use domains classified correctly
4. Schema drift status = pass for all domains
5. Round-trip status = pass for all domains
6. Model names are unique across all domains
7. All types implement Serialize + Deserialize
8. At least 35 Rust conformance tests
9. Verification script passes all checks with `--json` output
