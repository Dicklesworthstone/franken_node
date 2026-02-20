# bd-12q: Revocation Propagation + Freshness Integration for Extension Workflows

## Bead: bd-12q | Section: 10.4

## Purpose

Defines how extension install/update/load/invoke/uninstall workflows consume the
canonical 10.13 revocation stack so revoked or stale artifacts are blocked
before execution, with deterministic fail-closed behavior for higher-risk
operations.

## Invariants

| ID | Statement |
|----|-----------|
| INV-REVI-REGISTRY-CANONICAL | Extension revocation checks MUST read from the canonical 10.13 `RevocationRegistry` (`bd-y7lu`) and never from parallel shadow stores. |
| INV-REVI-MONOTONIC-HEAD | Revocation head observations are monotonic per zone. Head regression is rejected with `REVOCATION_HEAD_REGRESSION`. |
| INV-REVI-FRESHNESS-TIERS | Freshness is enforced by safety tier (`low`, `medium`, `high`) with configurable windows and fail-closed defaults for medium/high. |
| INV-REVI-HIGH-STALE-DENY | High-safety stale revocation data is denied with `REVOCATION_DATA_STALE`. |
| INV-REVI-LOW-STALE-WARN | Low-safety stale revocation data may proceed with explicit warning event and audit evidence. |
| INV-REVI-PROPAGATION-SLA | Revocation propagation latency is measured against `propagation_sla_secs` (default 60s), with explicit SLA-miss annotation. |
| INV-REVI-CASCADE | Revoked extension checks trigger cascade actions for dependents and active sessions with `REVOCATION_CASCADE_INITIATED`. |
| INV-REVI-EVIDENCE-LEDGER | Every revocation check decision is appended to an evidence ledger record for replayable audit completeness. |

## Integration Model

### Upstream 10.13 Dependencies

- `bd-y7lu`: `RevocationRegistry` monotonic revocation head checkpoints
- `bd-1m8r`: `evaluate_freshness(...)` tiered freshness gate

`RevocationIntegrationEngine` composes both:

1. `process_propagation(update)` advances canonical revocation head and records
   propagation latency + SLA compliance.
2. `evaluate_operation(context)` checks:
   - head monotonicity
   - extension revocation state
   - freshness tier policy
   - fail-closed/warning behavior
   - cascade requirements

## Policy Defaults

| Field | Default |
|-------|---------|
| `low_tier_max_age_secs` | 21600 (6h) |
| `medium_tier_max_age_secs` | 300 (5m) |
| `high_tier_max_age_secs` | 3600 (1h) |
| `propagation_sla_secs` | 60 |

## Event Codes

- `EXTENSION_REVOCATION_CHECK_PASSED`
- `EXTENSION_REVOCATION_CHECK_FAILED`
- `EXTENSION_REVOCATION_STALE_WARNING`
- `REVOCATION_PROPAGATION_RECEIVED`
- `REVOCATION_CASCADE_INITIATED`

## Stable Error Codes

- `REVOCATION_DATA_STALE`
- `REVOCATION_EXTENSION_REVOKED`
- `REVOCATION_DATA_UNAVAILABLE`
- `REVOCATION_HEAD_REGRESSION`
- `REVOCATION_PROPAGATION_SLA_MISSED`

## Artifacts

- Spec: `docs/specs/section_10_4/bd-12q_contract.md`
- Implementation: `crates/franken-node/src/supply_chain/revocation_integration.rs`
- Integration tests: `tests/integration/revocation_integration_workflow.rs`
- Verifier: `scripts/check_revocation_integration.py`
- Verifier tests: `tests/test_check_revocation_integration.py`
- Fixtures: `fixtures/provenance/revocation_integration_cases.json`
- Evidence: `artifacts/section_10_4/bd-12q/verification_evidence.json`
- Summary: `artifacts/section_10_4/bd-12q/verification_summary.md`
