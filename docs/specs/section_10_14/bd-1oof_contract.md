# bd-1oof: Trace-Witness References for High-Impact Ledger Entries

**Section**: 10.14
**Depends on**: bd-oolt (mandatory evidence emission)

## Purpose

High-impact control decisions need traceable links to the observations that caused
them. `WitnessRef` embeds stable witness IDs into evidence entries, enabling replay
tools to reconstruct the full decision context.

## Key Types

| Type | Role |
|------|------|
| `WitnessId` | Stable unique identifier for a witness observation |
| `WitnessKind` | Enum: Telemetry, StateSnapshot, ProofArtifact, ExternalSignal |
| `WitnessRef` | Reference with witness_id, kind, optional locator, SHA-256 hash |
| `WitnessSet` | Collection of witness references for an evidence entry |
| `WitnessValidator` | Validates presence, integrity, and resolvability |
| `WitnessAudit` | Coverage summary across a set of entries |
| `WitnessValidationError` | Error variants for validation failures |

## Invariants

- **INV-WITNESS-PRESENCE**: high-impact entries (Quarantine, Release, Escalate) must have >= 1 witness ref
- **INV-WITNESS-INTEGRITY**: witness SHA-256 hash must match content when available
- **INV-WITNESS-RESOLVABLE**: replay_bundle_locator must be non-empty for resolution (strict mode)

## High-Impact Classification

Entries with `DecisionKind` in {Quarantine, Release, Escalate} are classified as
high-impact and require at least one witness reference. Non-high-impact entries
(Admit, Deny, Rollback, Throttle) may optionally include witness references.

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-WITNESS-001 | Witness attached to entry |
| EVD-WITNESS-002 | Witness validation passed |
| EVD-WITNESS-003 | Broken reference detected |
| EVD-WITNESS-004 | Integrity hash mismatch |

## Validation Modes

- **Normal**: checks presence for high-impact entries and duplicate IDs
- **Strict**: additionally requires non-empty replay_bundle_locator on every witness

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_MISSING_WITNESSES | High-impact entry without witness refs |
| ERR_INTEGRITY_HASH_MISMATCH | SHA-256 doesn't match content |
| ERR_UNRESOLVABLE_LOCATOR | Empty or missing locator (strict mode) |
| ERR_DUPLICATE_WITNESS_ID | Same witness ID used twice on one entry |
