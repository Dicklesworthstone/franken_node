# bd-8tvs: Per-Class Object Tuning Policy — Specification Contract

## Overview

Each object class (critical marker, trust receipt, replay bundle, telemetry artifact)
has distinct performance requirements. This module provides benchmark-derived default
tuning and a validated override path with full auditing.

## Canonical Object Classes

| Class | Label | Default Symbol Size | Overhead Ratio | Fetch Priority | Prefetch |
|-------|-------|--------------------:|---------------:|----------------|----------|
| CriticalMarker | `critical_marker` | 256 B | 0.02 | Critical | Eager |
| TrustReceipt | `trust_receipt` | 1024 B | 0.05 | Normal | Lazy |
| ReplayBundle | `replay_bundle` | 16384 B | 0.08 | Background | None |
| TelemetryArtifact | `telemetry_artifact` | 4096 B | 0.04 | Background | None |

Custom classes have no defaults and must be configured via overrides.

## Types

| Type | Kind | Purpose |
|------|------|---------|
| `ObjectClass` | enum | CriticalMarker, TrustReceipt, ReplayBundle, TelemetryArtifact, Custom(String) |
| `FetchPriority` | enum | Critical, Normal, Background |
| `PrefetchPolicy` | enum | Eager, Lazy, None |
| `ClassTuning` | struct | symbol_size_bytes, encoding_overhead_ratio, fetch_priority, prefetch_policy |
| `BenchmarkMeasurement` | struct | Benchmark data with latency percentiles |
| `TuningError` | struct | code + message |
| `TuningEvent` | struct | Audit event (code, class_id, detail) |
| `ObjectClassTuningEngine` | struct | Policy engine with override support |

## Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `resolve` | `(&self, class: &ObjectClass) -> Option<ClassTuning>` | Override > default |
| `apply_override` | `(&mut self, class, tuning) -> Result<(), TuningError>` | Validated override with audit |
| `remove_override` | `(&mut self, class) -> bool` | Revert to default |
| `has_override` | `(&self, class) -> bool` | Check active override |
| `active_overrides` | `(&self) -> &HashMap<...>` | All active overrides |
| `events` | `(&self) -> &[TuningEvent]` | Audit trail |
| `load_benchmark_baseline` | `(&mut self, measurements)` | Ingest benchmark data |
| `to_csv` | `(&self) -> String` | Export policy report |
| `validate` | `(&self) -> Result<(), TuningError>` | On ClassTuning |

## Validation Rules

- `symbol_size_bytes == 0` -> `ERR_ZERO_SYMBOL_SIZE`
- `encoding_overhead_ratio < 0.0 || > 1.0` -> `ERR_INVALID_OVERHEAD_RATIO`
- Unknown custom class with no default -> `ERR_UNKNOWN_CLASS`

## Event Codes

| Code | When |
|------|------|
| `OC_POLICY_ENGINE_INIT` | Engine created via `with_init_event()` |
| `OC_POLICY_OVERRIDE_APPLIED` | Valid override applied (logs before/after) |
| `OC_POLICY_OVERRIDE_REJECTED` | Invalid override rejected |
| `OC_BENCHMARK_BASELINE_LOADED` | Benchmark measurements ingested |

## Invariants

| Tag | Statement |
|-----|-----------|
| `INV-TUNE-CLASS-SPECIFIC` | Every canonical class has distinct tuning defaults |
| `INV-TUNE-OVERRIDE-AUDITED` | All policy overrides logged with before/after values |
| `INV-TUNE-REJECT-INVALID` | Zero size or ratio > 1.0 rejected |
| `INV-TUNE-DETERMINISTIC` | Same class + config always yields same policy |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/policy/object_class_tuning.rs` |
| Policy report CSV | `artifacts/10.14/object_class_policy_report.csv` |
