# bd-1zym: Automatic Hardening Trigger — Verification Summary

**Section**: 10.14
**Bead**: bd-1zym
**Status**: PASS
**Agent**: CrimsonCrane
**Date**: 2026-02-20

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_14/bd-1zym_contract.md` |
| Implementation | `crates/franken-node/src/policy/hardening_auto_trigger.rs` |
| Verification script | `scripts/check_hardening_auto_trigger.py` |
| Python unit tests | `tests/test_check_hardening_auto_trigger.py` |
| Evidence JSON | `artifacts/section_10_14/bd-1zym/verification_evidence.json` |

## Implementation Overview

Automatic hardening trigger that escalates the hardening state machine when
guardrail monitors block policy recommendations. Creates a feedback loop:
rejection -> escalation -> increased resistance.

### Key Types

| Type | Purpose |
|------|---------|
| `HardeningAutoTrigger` | Core engine: processes rejections, deduplicates, escalates |
| `TriggerResult` | Enum: Escalated, AlreadyAtMax, Suppressed |
| `TriggerEvent` | Causal evidence record linking trigger to rejection |
| `TriggerConfig` | max_trigger_latency_ms (100ms default), enable_idempotency |
| `IdempotencyKey` | Dedup key: (current_level, budget_id, epoch_id) |

### Event Codes

| Code | Meaning |
|------|---------|
| EVD-AUTOTRIG-001 | Trigger fired (escalation) |
| EVD-AUTOTRIG-002 | Trigger suppressed |
| EVD-AUTOTRIG-003 | Already at maximum level |
| EVD-AUTOTRIG-004 | Idempotent dedup applied |

### Invariants

| ID | Status |
|----|--------|
| INV-AUTOTRIG-LATENCY | Verified (synchronous = 0ms, within 100ms bound) |
| INV-AUTOTRIG-IDEMPOTENT | Verified (dedup at same level via governance-rollback test) |
| INV-AUTOTRIG-CAUSAL | Verified (trigger events link to rejection_id + evidence_entry_id) |

## Verification Results

| Metric | Count | Status |
|--------|-------|--------|
| Rust unit tests | 22 | All pass |
| Python verification checks | 54 | All pass |
| Python unit tests | 22 | All pass |

### Check Breakdown

- File existence: 2/2
- Module registration: 1/1
- Upstream dependencies: 2/2
- Upstream imports: 2/2
- Idempotency key: 1/1
- Next-level function: 1/1
- Test count: 1/1 (22 tests, minimum 20)
- Required types: 4/4
- Required methods: 8/8
- Event codes: 4/4
- Invariants: 3/3
- TriggerResult variants: 3/3
- Required test names: 22/22

**Total: 54/54 PASS**

## Upstream Dependencies

- bd-3rya (hardening state machine): CLOSED
- bd-3a3q (guardrail monitors): CLOSED

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
