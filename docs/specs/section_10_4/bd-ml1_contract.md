# bd-ml1: Publisher Reputation Model with Explainable Transitions

## Bead: bd-ml1 | Section: 10.4

## Purpose

Defines the canonical publisher reputation model for the extension ecosystem.
Reputation is the longitudinal trust signal: while provenance (bd-1ah) proves a
single artifact's origin and certification (bd-273) assesses a single version,
reputation captures a publisher's track record over time. The model is explicit,
quantitative, deterministic, and policy-actionable.

## Invariants

| ID | Statement |
|----|-----------|
| INV-REP-DETERMINISTIC | Same input signal history produces identical reputation scores. |
| INV-REP-EXPLAINABLE | Every reputation transition includes an explanation citing specific signals. |
| INV-REP-DECAY | Scores decay over time toward a configurable baseline without positive signals. |
| INV-REP-TIERS | Five reputation tiers (suspended, untrusted, provisional, established, trusted) map to documented policy defaults. |
| INV-REP-FREEZE | Reputation is frozen during active quarantine/recall investigations. |
| INV-REP-RECOVERY | Recovery paths are documented and testable for each tier. |
| INV-REP-AUDIT | Audit trail is append-only with hash-chained integrity. |
| INV-REP-EVENTS | All transitions emit structured event codes with trace IDs. |

## Canonical Data Model

- Rust module: `crates/franken-node/src/supply_chain/reputation.rs`

Primary structures:

1. `ReputationTier` — five tiers with score thresholds and policy descriptions
2. `SignalKind` — nine signal types with default weights
3. `ReputationSignal` — input signal with publisher, kind, weight, evidence
4. `DecayConfig` — configurable decay rate, baseline, and interval
5. `TransitionExplanation` — human-readable explanation of score changes
6. `AuditEntry` — hash-chained audit record with event payload
7. `AuditEvent` — six event types: signal ingested, score computed, decay applied, frozen, unfrozen, recovery started
8. `PublisherReputation` — full reputation state per publisher
9. `ReputationRegistry` — core engine managing state and audit trails
10. `RecoveryAction` — documented recovery steps per tier

## Reputation Tiers

| Tier | Score Range | Policy Default |
|------|-------------|----------------|
| Suspended | N/A (frozen) | All operations blocked during investigation. |
| Untrusted | [0, 20) | Read-only access. Cannot publish or modify artifacts. |
| Provisional | [20, 50) | Can publish with mandatory review. Cannot self-certify. |
| Established | [50, 80) | Standard publish and certification. Subject to spot checks. |
| Trusted | [80, 100] | Full publish privileges. Eligible for fast-track certification. |

## Signal Types

| Kind | Default Weight | Direction |
|------|---------------|-----------|
| provenance_consistency | +5.0 | Positive |
| vulnerability_response_time | +8.0 | Positive |
| revocation_event | -15.0 | Negative |
| extension_quality | +3.0 | Positive |
| community_report | +2.0 | Positive |
| certification_adherence | +6.0 | Positive |
| certification_lapse | -8.0 | Negative |
| quarantine_event | -20.0 | Negative |
| quarantine_resolution | +10.0 | Positive |

## Scoring Algorithm

1. New publishers start at score 30.0 (provisional tier).
2. Each signal applies its weight (default or overridden) to the current score.
3. Score is clamped to [0.0, 100.0] after each update.
4. Tier is derived from score thresholds.
5. Decay applies exponentially toward baseline: `new = baseline + (old - baseline) * (1 - rate)^days`.

## Decay Mechanism

- Default daily rate: 0.005 (0.5%)
- Default baseline: 50.0
- Minimum interval: 1 day
- Direction: scores above baseline decay downward; scores below baseline decay upward

## Freeze Semantics

1. When a quarantine/recall investigation begins, reputation is frozen.
2. Tier is set to `Suspended` regardless of score.
3. All signal ingestion and decay are rejected while frozen.
4. Upon unfreezing, tier is restored from the preserved score.

## Recovery Paths

| Tier | Recovery Actions |
|------|-----------------|
| Suspended | Resolve active investigation with evidence and remediation artifacts. |
| Untrusted | Submit verified provenance; demonstrate timely vulnerability response. |
| Provisional / Established | Complete certification renewal; improve quality metrics. |
| Trusted | No recovery needed. |

## Audit Trail

- Append-only with SHA-256 hash chaining.
- Each entry contains: sequence number, previous hash, entry hash, timestamp, publisher ID, event payload.
- Integrity can be verified by walking the chain and recomputing hashes.
- Queryable by publisher ID and time range.

## Event Codes

| Code | Trigger |
|------|---------|
| REPUTATION_COMPUTED | Score recomputed after signal or decay |
| REPUTATION_TRANSITION | Tier boundary crossed |
| REPUTATION_FROZEN | Investigation freeze activated |
| REPUTATION_UNFROZEN | Investigation concluded, freeze lifted |
| REPUTATION_DECAY_APPLIED | Time-based decay applied |
| REPUTATION_SIGNAL_INGESTED | New signal processed |
| REPUTATION_RECOVERY_STARTED | Publisher entered recovery workflow |
| REPUTATION_AUDIT_QUERIED | Audit trail accessed |

## Dependencies

- Upstream: bd-1gx (signed extension manifest — provides publisher identity)
- Downstream: bd-273 (certification levels), bd-phf (ecosystem telemetry), bd-261k (section gate)
