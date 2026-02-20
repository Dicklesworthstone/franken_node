# bd-2yc: Operator Copilot Action Recommendation API

## Bead: bd-2yc | Section: 10.5

## Purpose

Implements the operator copilot: VOI-based action ranking with expected-loss vectors,
uncertainty bands, confidence context, and deterministic rollback commands. The copilot
is the primary human-facing decision support surface for live incident response. It
surfaces degraded-mode warnings and annotates recommendations affected by stale data.

## Invariants

| ID | Statement |
|----|-----------|
| INV-COP-VOI-RANK | Actions ranked by Value-of-Information (VOI = expected_gain_if_act - expected_gain_if_wait), not raw loss. |
| INV-COP-LOSS-VEC | Each recommendation includes a 5-dimensional expected-loss vector with non-negative values. |
| INV-COP-UNCERTAINTY | Uncertainty bands are non-degenerate (upper > lower) with explicit confidence level. |
| INV-COP-ROLLBACK | Every recommendation includes a deterministic rollback command validated at recommendation time. |
| INV-COP-DEGRADED | Degraded-mode responses include warning block with stale inputs and adjusted uncertainty bands. |
| INV-COP-RATIONALE | Each recommendation includes human-readable rationale referencing the dominant loss dimension. |
| INV-COP-AUDIT | Every served recommendation recorded in audit trail with recommendation_id, operator, and trace_id. |
| INV-COP-TOP-K | API returns at most top_k recommendations (configurable, default 5). |

## VOI Formula

```
VOI = expected_loss_if_wait.total() - expected_loss_if_act.total()
```

Higher VOI = more valuable for the operator to act on now.

## Expected-Loss Dimensions

| Dimension | Description |
|-----------|-------------|
| availability_loss | Availability impact. |
| integrity_loss | Integrity impact. |
| confidentiality_loss | Confidentiality impact. |
| financial_loss | Financial impact. |
| reputation_loss | Reputation impact. |

## Event Codes

| Code | When Emitted |
|------|--------------|
| COPILOT_RECOMMENDATION_REQUESTED | Operator requested recommendations. |
| COPILOT_RECOMMENDATION_SERVED | Ranked recommendations delivered. |
| COPILOT_ROLLBACK_VALIDATED | Rollback command validated. |
| COPILOT_DEGRADED_WARNING | System in degraded mode, warning emitted. |
| COPILOT_STREAM_STARTED | Streaming mode started. |
| COPILOT_STREAM_UPDATED | Streaming update pushed. |

## Dependencies

- Upstream: bd-2fa (counterfactual replay), bd-33b (expected-loss scoring), bd-3nr (degraded-mode policy)
- Downstream: bd-1koz (section gate), bd-20a (section rollup)
