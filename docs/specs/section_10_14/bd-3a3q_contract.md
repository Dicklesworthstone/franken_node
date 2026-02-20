# bd-3a3q: Anytime-Valid Guardrail Monitor Set

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** Implementation
**Upstream:** bd-sddz (correctness envelope)
**Downstream:** bd-1zym (auto hardening trigger), bd-15u3 (guardrail precedence), bd-3epz (gate)

## Purpose

Provides always-on, anytime-valid bounds that prevent the system from taking
dangerous actions regardless of Bayesian engine recommendations. Enforces
Section 8.5 Invariant #6 (security/durability budgets are never exceeded) and
Invariant #8 (guardrail precedence over heuristics).

## Anytime-Valid Property

Monitors produce valid conclusions at any stopping point. Unlike fixed-sample
statistical tests, these monitors give valid results whether checked after 1
observation or 1 million. This is essential for a continuously-running system.

## Data Model

### GuardrailVerdict

| Variant | Severity | Meaning |
|---------|----------|---------|
| `Allow` | 0 | Action is within budget |
| `Warn` | 1 | Approaching budget, still allowed |
| `Block` | 2 | Exceeds budget, action blocked |

### SystemState (monitor input)

| Field | Type | Description |
|-------|------|-------------|
| `memory_used_bytes` | `u64` | Current memory usage |
| `memory_budget_bytes` | `u64` | Memory budget limit |
| `durability_level` | `f64` | Current durability (0.0-1.0) |
| `hardening_level` | `HardeningLevel` | Current level |
| `proposed_hardening_level` | `Option<HardeningLevel>` | Proposed change |
| `evidence_emission_active` | `bool` | Is evidence emission on |
| `epoch_id` | `u64` | Current epoch |

## Concrete Monitors

### MemoryBudgetGuardrail
- **Budget:** `memory_budget`
- **Block:** memory utilization >= `block_threshold` (default 0.95)
- **Warn:** memory utilization >= `warn_threshold` (default 0.80)
- **Envelope minimum:** block threshold cannot be below 0.5

### DurabilityLossGuardrail
- **Budget:** `durability_budget`
- **Block:** durability < `min_durability` (default 0.9)
- **Warn:** durability < `min_durability + warn_margin` (default margin 0.05)
- **Envelope minimum:** min durability cannot be below 0.5

### HardeningRegressionGuardrail
- **Budget:** `hardening_regression`
- **Block:** proposed level < current level (references INV-001)
- **Not configurable:** regression is always blocked

### EvidenceEmissionGuardrail
- **Budget:** `evidence_emission`
- **Block:** evidence emission is disabled (references INV-002)
- **Not configurable:** emission bypass is always blocked

## GuardrailMonitorSet

Runs all registered monitors and returns the most restrictive verdict.
Block > Warn > Allow. When multiple monitors block, the first block is returned
via `evaluate()`.

## Event Codes

| Code | Trigger |
|------|---------|
| `EVD-GUARD-001` | Monitor check passed |
| `EVD-GUARD-002` | Monitor blocked action |
| `EVD-GUARD-003` | Monitor warned |
| `EVD-GUARD-004` | Threshold reconfigured |

## Relationship to Correctness Envelope

Guardrail thresholds are policy-configurable but cannot be set below minimums
defined in the correctness envelope (bd-sddz). The envelope enforces:
- INV-001: Monotonic hardening (HardeningRegressionGuardrail)
- INV-002: Evidence emission mandatory (EvidenceEmissionGuardrail)
- INV-008: Guardrail precedence over Bayesian (GuardrailMonitorSet)
