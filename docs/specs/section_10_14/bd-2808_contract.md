# bd-2808: Deterministic Repro Bundle Export

**Section**: 10.14
**Depends on**: bd-nupr (EvidenceEntry schema), bd-2e73 (evidence ledger)

## Purpose

Captures the complete execution context at the point of a control-plane failure
so that feeding the bundle into `replay_bundle` re-executes the incident step
by step with identical outcomes. This is the cornerstone of deterministic
verification: every failure can be reproduced mechanically.

## Key Types

| Type | Role |
|------|------|
| `ReproBundle` | Self-contained bundle: seed, config, event trace, evidence refs, failure context |
| `TraceEvent` | Single event in the control-plane event trace (seq, type, timestamp, payload) |
| `TraceEventType` | Enum: EpochTransition, BarrierEvent, PolicyEvaluation, MarkerIntegrityCheck, ConfigChange, ExternalSignal |
| `EvidenceRef` | Reference to evidence artifact with portable relative path |
| `FailureContext` | The failure condition: type, error message, trigger, timestamp |
| `FailureType` | Enum: EpochTransitionTimeout, BarrierTimeout, PolicyViolation, MarkerIntegrityBreak |
| `ConfigSnapshot` | Key-value configuration state at failure time |
| `ExportContext` | Input context for deterministic bundle generation |
| `ReplayOutcome` | Enum: Match (same failure reproduced), Divergence (replay differed) |
| `SchemaError` | Enum: MissingField, InvalidVersion, NonPortablePath, EmptyEventTrace |
| `ReproBundleExporter` | Manages auto/manual bundle export with configurable triggers |

## Invariants

- **INV-REPRO-DETERMINISTIC**: identical bundle replays produce identical outcomes
- **INV-REPRO-COMPLETE**: bundles are self-contained (no external state needed)
- **INV-REPRO-VERSIONED**: schema version field is present and validated

## Deterministic Bundle Generation

Bundle IDs are derived via `DefaultHasher` over: seed, epoch_id, timestamp_ms,
failure type/message, all event types/timestamps/payloads, all evidence refs,
and all config entries. Identical input always produces identical bundle_id.

## Auto-Export Triggers

Bundles are automatically exported on: epoch transition failures, barrier
timeouts, policy violations, and marker integrity breaks. Manual export via
API is also supported with time-range filtering.

## Event Codes

| Code | Meaning |
|------|---------|
| REPRO_BUNDLE_EXPORTED | Bundle exported (includes bundle_id, trigger, counts) |
| REPRO_BUNDLE_REPLAY_START | Replay started |
| REPRO_BUNDLE_REPLAY_COMPLETE | Replay completed with match |
| REPRO_BUNDLE_REPLAY_DIVERGENCE | Replay diverged from original |

## Portability

Bundles use relative paths only. `EvidenceRef.is_portable()` and
`ConfigSnapshot.is_portable()` reject absolute paths. `ReproBundle.is_portable()`
checks all refs and config values.

## Schema Validation

`validate_bundle()` checks: bundle_id present, schema_version == 1,
error_message non-empty, all paths portable. Returns `Vec<SchemaError>` on failure.
