# bd-21fo: Self-Evolving Optimization Governor with Safety-Envelope Enforcement

**Section:** 10.17 -- Radical Expansion Execution Track
**Bead:** bd-21fo
**Status:** in_progress

## Purpose

The optimization governor evaluates candidate optimization proposals against a
safety envelope before they are applied to runtime knobs. Unsafe or non-beneficial
proposals are auto-rejected or auto-reverted with machine-readable evidence.
The governor is self-evolving: it can accept new proposals at runtime, maintain a
history of applied policies, and adapt thresholds within its safety envelope.

## Scope Constraints

- The governor adjusts **exposed runtime knobs only** -- it must never mutate
  engine-core internals.
- All candidate optimizations require **shadow evaluation** before live
  application: candidates run in shadow mode and their predicted effect is
  compared to the safety envelope.
- The safety envelope defines quantitative bounds (latency cap, throughput
  floor, error-rate ceiling, memory ceiling) that must never be violated.
- Policies that violate the envelope or produce non-beneficial outcomes are
  auto-rejected or auto-reverted; every decision is emitted with an evidence
  record.

## Data Model

### SafetyEnvelope

| Field | Type | Description |
|---|---|---|
| `max_latency_ms` | `u64` | Hard cap on p99 latency in milliseconds |
| `min_throughput_rps` | `u64` | Minimum requests per second floor |
| `max_error_rate_pct` | `f64` | Maximum error rate as percentage (0.0-100.0) |
| `max_memory_mb` | `u64` | Maximum memory usage in megabytes |

### OptimizationProposal

| Field | Type | Description |
|---|---|---|
| `proposal_id` | `String` | Unique identifier for the proposal |
| `knob` | `RuntimeKnob` | Which runtime knob to adjust |
| `old_value` | `u64` | Current value of the knob |
| `new_value` | `u64` | Proposed new value |
| `predicted_latency_ms` | `u64` | Predicted p99 latency after change |
| `predicted_throughput_rps` | `u64` | Predicted throughput after change |
| `predicted_error_rate_pct` | `f64` | Predicted error rate after change |
| `predicted_memory_mb` | `u64` | Predicted memory usage after change |
| `rationale` | `String` | Human-readable reason for the proposal |
| `trace_id` | `String` | Correlation ID for distributed tracing |

### GovernorDecision

| Variant | Description |
|---|---|
| `Approved` | Proposal passes shadow evaluation and safety checks |
| `Rejected(reason)` | Proposal violates safety envelope or non-beneficial |
| `Reverted(reason)` | Previously approved proposal auto-reverted after live check |
| `ShadowOnly` | Proposal accepted for shadow evaluation only, not yet applied |

### RuntimeKnob

Enumeration of adjustable runtime parameters:

| Variant | Description |
|---|---|
| `ConcurrencyLimit` | Maximum concurrent operations |
| `BatchSize` | Processing batch size |
| `CacheCapacity` | In-memory cache capacity |
| `DrainTimeoutMs` | Drain timeout in milliseconds |
| `RetryBudget` | Maximum retry attempts |

## Event Codes

| Code | Description |
|---|---|
| `GOV_001` | Optimization proposal submitted to governor |
| `GOV_002` | Shadow evaluation started for proposal |
| `GOV_003` | Proposal approved and applied |
| `GOV_004` | Proposal rejected (safety envelope violation or non-beneficial) |
| `GOV_005` | Previously applied proposal auto-reverted |
| `GOV_006` | Safety envelope updated |
| `GOV_007` | Governor state snapshot emitted |

## Error Codes

| Code | Description |
|---|---|
| `ERR_GOV_ENVELOPE_VIOLATION` | Proposal violates one or more safety-envelope bounds |
| `ERR_GOV_NON_BENEFICIAL` | Proposal does not improve any metric within envelope |
| `ERR_GOV_KNOB_LOCKED` | Target knob is locked by a higher-priority policy |
| `ERR_GOV_REVERT_FAILED` | Auto-revert of a previously applied proposal failed |
| `ERR_GOV_SHADOW_TIMEOUT` | Shadow evaluation exceeded its time budget |
| `ERR_GOV_INVALID_PROPOSAL` | Proposal has invalid or inconsistent fields |

## Invariants

| ID | Statement |
|---|---|
| `INV-GOV-ENVELOPE-NEVER-BREACHED` | No applied optimization may violate the safety envelope bounds |
| `INV-GOV-SHADOW-BEFORE-APPLY` | Every proposal must pass shadow evaluation before live application |
| `INV-GOV-EVIDENCE-ON-REJECT` | Every rejection emits a machine-readable evidence record |
| `INV-GOV-KNOBS-ONLY` | Governor may only adjust exposed runtime knobs, never engine-core internals |
| `INV-GOV-AUTO-REVERT` | Any applied policy that later violates the envelope is automatically reverted |
| `INV-GOV-DETERMINISTIC-ORDER` | Decision log entries are totally ordered by sequence number |

## Acceptance Criteria

1. Candidate optimizations require shadow evaluation plus anytime-valid safety
   checks.
2. Unsafe or non-beneficial policies auto-reject or auto-revert with evidence.
3. Governor can only adjust exposed runtime knobs, not local engine-core
   internals.
4. Machine-readable verification artifact at
   `artifacts/section_10_17/bd-21fo/verification_evidence.json`.
5. Inline Rust unit tests (>= 20 tests).
6. Check script with `--json` and `--self-test` flags.
7. Python unit test suite (>= 12 tests).

## Deliverables

- `docs/specs/section_10_17/bd-21fo_contract.md` (this file)
- `crates/franken-node/src/runtime/optimization_governor.rs`
- `scripts/check_optimization_governor.py`
- `tests/test_check_optimization_governor.py`
- `artifacts/section_10_17/bd-21fo/verification_evidence.json`
- `artifacts/section_10_17/bd-21fo/verification_summary.md`
