# bd-1f8v: Operator Copilot Guidance for Dependency Updates

**Section:** 10.20 — Dependency Graph Immune System (9N)
**Status:** Implemented
**Module:** `crates/franken-node/src/security/dgis/update_copilot.rs`

## Purpose

Translates DGIS intelligence (topology metrics, fragility findings, contagion simulations, economic rankings) into actionable, contextualized recommendations for dependency update decisions. Operators receive topology-aware risk deltas, containment recommendations, verifier-backed confidence outputs, policy acknowledgement gates, and mitigation playbooks.

## Core Types

| Type | Role |
|------|------|
| `TopologyRiskMetrics` | Per-node risk scores: fan_out, betweenness_centrality, articulation_point, trust_bottleneck_score, transitive_dependency_count, max_depth_in_graph |
| `RiskDelta` | Pre/post update metrics with aggregate risk delta and per-metric breakdowns |
| `BlastRadiusEstimate` | Directly/transitively affected nodes, critical path flag, recovery time estimate |
| `BarrierRecommendation` | Barrier type, target node, configuration summary, rationale |
| `ContainmentRecommendation` | Blast radius + barriers + monitoring intensification |
| `ConfidenceOutput` | Confidence score with lower/upper bounds, data quality factors, calibration note |
| `AcknowledgementReceipt` | Signed operator acknowledgement with validation and content hashing |
| `AcknowledgementDecision` | Approved, Rejected, Deferred |
| `MitigationPlaybook` | Barrier configs + staged rollout plan + monitoring + rollback |
| `StagedRolloutPlan` | Four phases: canary (1%) -> limited (10%) -> progressive (50%) -> general (100%) |
| `RolloutPhaseSpec` | Phase name, traffic %, soak time, success criteria, rollback trigger |
| `MonitoringRecommendation` | Metric name, threshold, action on breach |
| `UpdateProposal` | Input: package, versions, pre/post metrics, affected nodes |
| `UpdateRiskLevel` | Low, Medium, High, Critical |
| `UpdateRecommendation` | Full copilot output: delta + risk level + containment + confidence + playbook |
| `CopilotInteraction` | Logged interaction with event code, trace ID, operator decision |
| `CopilotConfig` | Configurable thresholds: high_risk (0.3), critical_risk (0.6), low_confidence (0.5) |
| `UpdateCopilot` | Engine: evaluate proposals, process acknowledgements, export logs |

## Risk Classification

| Level | Condition | Acknowledgement |
|-------|-----------|-----------------|
| Low | Risk decreased or negligible | Not required |
| Medium | Risk increased below high_risk_threshold | Not required |
| High | Risk increased >= high_risk_threshold (0.3) | Required |
| Critical | Risk increased >= critical_risk_threshold (0.6) | Required |

## Aggregate Risk Formula

```
ap_weight    = 0.3 if articulation_point else 0.0
fan_out_norm = min(fan_out / 100.0, 1.0)
bc_norm      = min(betweenness_centrality, 1.0)
tb_norm      = min(trust_bottleneck_score, 1.0)
aggregate    = min(fan_out_norm * 0.2 + bc_norm * 0.25 + ap_weight + tb_norm * 0.25, 1.0)
```

## Per-Metric Delta Breakdown

Risk delta reports include before/after deltas for:
- `fan_out` — direct and transitive dependent count changes
- `betweenness_centrality` — centrality position changes
- `trust_bottleneck_score` — trust concentration changes
- `transitive_dependency_count` — dependency tree size changes

## Containment Recommendations

Barrier recommendations triggered by:
- **staged_rollout_fence**: Any risk increase (delta > 0)
- **composition_firewall**: Post-update node is articulation point
- **sandbox_escalation**: Post-update trust bottleneck score > 0.7

Monitoring intensification adds `dependency_health_score` and `trust_degradation_events` when risk increases.

## Mitigation Playbook (High/Critical only)

Four-phase staged rollout:

| Phase | Traffic | Min Soak | Success Criteria |
|-------|---------|----------|------------------|
| canary | 1% | 1h | Error rate < 0.1%, no trust degradation |
| limited | 10% | 2h | Error rate < 0.5%, latency p99 stable |
| progressive | 50% | 4h | All metrics within baseline envelopes |
| general | 100% | 24h | Full production stability |

Monitoring covers: error_rate, latency_p99, trust_degradation_events.

## Confidence Output

Confidence score derived from data quality factors:
- `provenance_completeness` — 0.8 if transitive deps > 0, else 0.4
- `metric_calibration` — 0.75 if fan_out > 0, else 0.5
- `history_depth` — deterministic signal depth from current topology history:
  - `dep_signal = min(transitive_dependency_count, 50) / 50`
  - `fan_out_signal = min(fan_out, 10) / 10` when `fan_out` is finite and positive, else 0.0
  - `history_depth = clamp((dep_signal + fan_out_signal) / 2, 0.0, 1.0)`

Unavailable, non-finite, or non-positive history inputs contribute 0.0 to the
history term, so the confidence score degrades explicitly instead of carrying a
fixed placeholder value.

Uncertainty bounds: `[score - uncertainty*0.5, score + uncertainty*0.5]` clamped to [0, 1].

## Policy Acknowledgement

High/Critical updates require signed `AcknowledgementReceipt`:
- Validated: operator_identity and signature_hex must be non-empty
- Content hash: SHA-256 of canonical JSON serialization
- Decisions: Approved, Rejected, Deferred
- Stored and queryable by proposal_id

## Event Codes

| Code | Meaning |
|------|---------|
| DGIS-COPILOT-001 | Recommendation generated |
| DGIS-COPILOT-002 | High-risk update flagged |
| DGIS-COPILOT-003 | Acknowledgement required |
| DGIS-COPILOT-004 | Acknowledgement received |
| DGIS-COPILOT-005 | Playbook generated |
| DGIS-COPILOT-006 | Update approved |
| DGIS-COPILOT-007 | Update rejected |
| DGIS-COPILOT-008 | Low confidence warning |
| DGIS-COPILOT-009 | Risk delta computed |
| DGIS-COPILOT-010 | Blast radius estimated |
| DGIS-COPILOT-011 | Barrier suggested |
| DGIS-COPILOT-012 | Interaction logged |

## Interaction Logging

Every copilot interaction is recorded as a `CopilotInteraction` with:
- Unique interaction_id and trace_id for correlation
- Event code, proposal_id, timestamp
- Optional: recommendation_id, operator_decision, risk_level, risk_delta
- Arbitrary details as JSON value
- JSONL export via `export_interactions_jsonl()`

## Invariants

- **INV-COPILOT-RISK-BOUNDED**: Aggregate risk scores are always in [0.0, 1.0]
- **INV-COPILOT-ACK-REQUIRED**: High/Critical updates cannot proceed without valid acknowledgement when require_ack_above_threshold is true
- **INV-COPILOT-CONFIDENCE-BOUNDED**: Confidence score and bounds are in [0.0, 1.0]
- **INV-COPILOT-PLAYBOOK-COMPLETE**: High-risk playbooks always include barriers, rollout phases, monitoring, and rollback
- **INV-COPILOT-LOG-COMPLETE**: Every evaluate_proposal and process_acknowledgement call generates a logged interaction
- **INV-COPILOT-HASH-DETERMINISTIC**: AcknowledgementReceipt content hash is deterministic for identical inputs

## Test Coverage

- 26 Rust inline tests covering: risk delta computation, risk classification, containment recommendations, confidence bounds, policy acknowledgement, mitigation playbooks, interaction logging, JSONL export, summary generation, content hashing, aggregate risk bounds
- 11 Python verification gate checks
- 17 Python unit tests

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_20/bd-1f8v_contract.md` |
| Rust module | `crates/franken-node/src/security/dgis/update_copilot.rs` |
| Check script | `scripts/check_dgis_copilot.py` |
| Unit tests | `tests/test_check_dgis_copilot.py` |
| Recommendation log | `artifacts/10.20/dgis_operator_recommendation_log.jsonl` |
| Evidence | `artifacts/section_10_20/bd-1f8v/verification_evidence.json` |
| Summary | `artifacts/section_10_20/bd-1f8v/verification_summary.md` |
