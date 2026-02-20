# bd-1ayu: Overhead/Rate Clamp Policy for Hardening Escalations

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** Implementation
**Upstream:** bd-3rya (hardening state machine)
**Downstream:** bd-1fp4 (integrity sweep scheduler), bd-3epz (section gate), bd-5rh (plan gate)

## Purpose

Rate-limits and overhead-caps hardening escalations to prevent "escalation storms"
where a burst of guardrail violations drives the system to maximum hardening faster
than operators can react. Supports Section 8.5 Invariant #9 (bounded resource
consumption).

## Data Model

### EscalationBudget

| Field | Type | Description |
|-------|------|-------------|
| `max_escalations_per_window` | `u32` | Max escalations allowed in one window |
| `window_duration_ms` | `u64` | Rolling window duration in milliseconds |
| `max_overhead_pct` | `f64` | Max additional CPU/memory overhead from hardening |
| `min_level` | `HardeningLevel` | Policy floor (cannot go below) |
| `max_level` | `HardeningLevel` | Policy ceiling (cannot go above) |

### ClampResult

| Variant | Fields | Meaning |
|---------|--------|---------|
| `Allowed` | none | Escalation proceeds as proposed |
| `Clamped` | `effective_level`, `reason` | Escalation proceeds but at a lower effective level |
| `Denied` | `reason` | Escalation blocked entirely |

### ClampEvent (telemetry)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `u64` | Monotonic counter |
| `proposed_level` | `HardeningLevel` | Level that was requested |
| `effective_level` | `HardeningLevel` | Level that was applied (or current if denied) |
| `reason` | `String` | Human-readable explanation |
| `budget_utilization_pct` | `f64` | Fraction of rate budget consumed (0.0-1.0) |

## Algorithm

```
check_escalation(proposed, current, budget, history):
  1. If proposed <= current: return Denied("not an escalation")
  2. If proposed > budget.max_level: effective = budget.max_level
  3. If effective < budget.min_level: effective = budget.min_level
  4. Count escalations in history within window_duration_ms
  5. If count >= max_escalations_per_window: return Denied("rate limit")
  6. Compute estimated_overhead(effective)
  7. If estimated_overhead > max_overhead_pct: find highest level within budget
  8. If effective <= current: return Denied("overhead limit")
  9. If effective != proposed: return Clamped { effective, reason }
  10. return Allowed
```

## Overhead Estimation

Each hardening level has a fixed estimated overhead percentage:

| Level | Overhead % |
|-------|-----------|
| Baseline | 0.0 |
| Standard | 5.0 |
| Enhanced | 15.0 |
| Maximum | 35.0 |
| Critical | 60.0 |

## Determinism

- No randomness, no wall-clock dependency.
- History uses monotonic counters, not system time.
- Identical (current_level, budget, history) produces identical output.

## Event Codes

| Code | Trigger |
|------|---------|
| `EVD-CLAMP-001` | Escalation allowed |
| `EVD-CLAMP-002` | Escalation clamped (effective < proposed) |
| `EVD-CLAMP-003` | Escalation denied |
| `EVD-CLAMP-004` | Budget recalculated |

## Performance

- `check_escalation` is O(N) in escalation history size within the window.
- Typical window contains <10 entries; no optimization needed.
