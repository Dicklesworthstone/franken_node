# Control Evidence Contract (bd-15j6)

## Policy-Influenced Control Decisions

Every policy-influenced control decision MUST emit an evidence entry to the
canonical evidence ledger (bd-2e73). A missing evidence entry for any
policy decision is a conformance failure.

### Decision Types

| Decision Type | Module | Description |
|--------------|--------|-------------|
| `HealthGateEval` | health_gate.rs | Health-gate pass/fail evaluation |
| `RolloutTransition` | rollout_state.rs | Rollout go/no-go state transition |
| `QuarantineAction` | state_model.rs | Quarantine promote/demote decision |
| `FencingDecision` | fencing.rs | Fencing grant/deny decision |
| `MigrationDecision` | lifecycle.rs | Migration proceed/abort decision |

### Required Evidence Fields

Each evidence entry MUST include:

| Field | Type | Description |
|-------|------|-------------|
| `decision_id` | String | Unique identifier for this decision |
| `decision_type` | DecisionType | One of the types above |
| `decision_kind` | DecisionKind | Canonical kind from bd-nupr schema |
| `policy_inputs` | Vec<String> | Policy signals consumed |
| `candidates_considered` | Vec<String> | Alternatives evaluated |
| `chosen_action` | String | Action taken |
| `rejection_reasons` | Vec<String> | Why alternatives were rejected |
| `epoch` | u64 | Current epoch |
| `trace_id` | String | Distributed trace correlation |
| `timestamp_ms` | u64 | Wall-clock time in milliseconds |

### Schema Alignment

Entries MUST match the canonical EvidenceEntry schema from bd-nupr (10.14):
- `schema_version`: "1.0"
- `decision_kind`: Maps to bd-nupr DecisionKind enum
- Deterministic field ordering: entries for the same decision appear
  in deterministic order

### Decision-to-Kind Mapping

| Decision Type | DecisionKind (admit/deny) |
|--------------|---------------------------|
| HealthGateEval (pass) | Admit |
| HealthGateEval (fail) | Deny |
| RolloutTransition (go) | Admit |
| RolloutTransition (no-go) | Deny |
| QuarantineAction (promote) | Release |
| QuarantineAction (demote) | Quarantine |
| FencingDecision (grant) | Admit |
| FencingDecision (deny) | Deny |
| MigrationDecision (proceed) | Admit |
| MigrationDecision (abort) | Deny |

### Ordering Guarantee

For entries sharing the same decision_id, the canonical ordering is:
1. Decision evaluation entry (inputs + candidates)
2. Action selection entry (chosen action + rejection reasons)

Same inputs MUST produce the same entry sequence.

## Event Codes

| Code | Description |
|------|-------------|
| EVD-001 | Evidence entry emitted |
| EVD-002 | Evidence entry missing — conformance failure |
| EVD-003 | Schema validation passed |
| EVD-004 | Schema validation failed |
| EVD-005 | Ordering violation detected |

## Conformance Requirements

1. Every decision type MUST emit evidence
2. Entries MUST use canonical EvidenceEntry schema
3. Deterministic ordering MUST be verifiable
4. Missing evidence MUST be a conformance failure (not warning)
5. Malformed evidence MUST be rejected with EVD-004
