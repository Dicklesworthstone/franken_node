# bd-b9b6: Durability Contract Violation Diagnostic Bundles

**Section**: 10.14
**Depends on**: bd-nupr (EvidenceEntry schema), bd-3rya (hardening state machine), bd-1l62 (gating operations)

## Purpose

When hardening is fully exhausted and verifiability cannot be restored, emit a
comprehensive diagnostic bundle capturing the full causal chain. This is the
last-resort safety mechanism: fail-safe with full diagnostic context.

## Key Types

| Type | Role |
|------|------|
| `BundleId` | Deterministically-derived unique bundle identifier |
| `CausalEvent` | An event in the chain leading to violation |
| `CausalEventType` | Enum: GuardrailRejection, HardeningEscalation, RepairFailed, IntegrityCheckFailed, ArtifactUnverifiable |
| `FailedArtifact` | Artifact with expected/actual hash and failure reason |
| `ProofContext` | Failed, missing, and passed proofs at violation time |
| `HaltPolicy` | Enum: HaltAll, HaltScope(scope), WarnOnly |
| `ViolationBundle` | Complete diagnostic bundle with causal chain |
| `ViolationContext` | Input context for deterministic bundle generation |
| `DurabilityViolationDetector` | Manages halt state and generates bundles |
| `DurabilityHaltedError` | Error returned when durable op is blocked |

## Invariants

- **INV-VIOLATION-DETERMINISTIC**: identical context produces identical bundle (including bundle_id)
- **INV-VIOLATION-CAUSAL**: bundle includes complete causal event chain in order
- **INV-VIOLATION-HALT**: gating operations blocked after emission per halt policy

## Deterministic Bundle Generation

Bundle IDs are derived via `DefaultHasher` over: epoch_id, timestamp_ms,
hardening_level, all event types/timestamps/descriptions, and all artifact
paths/expected hashes. Identical input always produces identical bundle_id.

## Halt Policies

| Policy | Behavior |
|--------|----------|
| `HaltAll` | Block all durable operations globally |
| `HaltScope(scope)` | Block only operations in the matching scope |
| `WarnOnly` | Generate bundle, emit warning, but don't block |

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-VIOLATION-001 | Violation bundle generated |
| EVD-VIOLATION-002 | Gating operations halted |
| EVD-VIOLATION-003 | Halt cleared after remediation |
| EVD-VIOLATION-004 | Durable operation rejected during halt |

## Error Type

`DurabilityHaltedError` is returned when a durable operation is attempted
during a halt. It includes the `bundle_id` of the violation that caused the
halt and the `scope` of the rejected operation.
