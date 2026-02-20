# bd-1zym: Automatic Hardening Trigger on Guardrail Rejection Evidence

**Section**: 10.14
**Status**: Implementation complete
**Depends on**: bd-3rya (hardening state machine), bd-3a3q (guardrail monitors)

## Purpose

When a guardrail monitor blocks a policy recommendation, this is strong evidence that
the system's hardening level may be insufficient. The automatic hardening trigger
responds to guardrail rejection events by escalating the hardening state machine
within a configured latency bound, closing the gap between threat detection and
defense escalation.

## Key Types

| Type | Role |
|------|------|
| `HardeningAutoTrigger` | Core trigger engine; processes rejections, deduplicates, escalates |
| `TriggerResult` | Enum: `Escalated`, `AlreadyAtMax`, `Suppressed` |
| `TriggerEvent` | Causal evidence record linking trigger to originating rejection |
| `TriggerConfig` | Configuration: `max_trigger_latency_ms`, `enable_idempotency` |
| `IdempotencyKey` | Dedup key: `(current_level, budget_id, epoch_id)` |

## Invariants

- **INV-AUTOTRIG-LATENCY**: escalation within `max_trigger_latency_ms` of rejection event (default 100ms)
- **INV-AUTOTRIG-IDEMPOTENT**: duplicate rejections at same level produce one escalation
- **INV-AUTOTRIG-CAUSAL**: every trigger event links to its originating rejection

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-AUTOTRIG-001 | Trigger fired (escalation occurred) |
| EVD-AUTOTRIG-002 | Trigger suppressed (rate limited / dedup) |
| EVD-AUTOTRIG-003 | Already at maximum hardening level |
| EVD-AUTOTRIG-004 | Idempotent deduplication applied |

## Escalation Path

```
Baseline -> Standard -> Enhanced -> Maximum -> Critical
```

Each guardrail rejection escalates one level. At Critical, returns `AlreadyAtMax`.

## Idempotency

Key is derived from `(current_level, budget_id, epoch_id)`. Same key at same level
produces `Suppressed` result. Different epoch or different budget generates a new key.
Idempotency cache can be reset on epoch boundary via `reset_idempotency()`.

## Causal Evidence

Every trigger event records:
- `trigger_id`: monotonic trigger identifier
- `rejection_id`: composed from monitor_name + budget_id + epoch_id
- `evidence_entry_id`: evidence ledger reference
- `from_level` / `to_level`: escalation transition
- `timestamp`: monotonic timestamp

Events are exportable as JSONL via `TriggerEvent::to_jsonl()`.
