# bd-15j6: Mandatory Evidence Emission for Policy-Influenced Control Decisions

## Summary

Makes evidence-ledger emission mandatory for all policy-influenced control decisions
in franken_node's product layer. A missing evidence entry for any policy decision is
a conformance failure, not a warning.

## Scope

### Decision Types Requiring Evidence

| Decision Type | Module | Approve Kind | Deny Kind |
|--------------|--------|--------------|-----------|
| HealthGateEval | health_gate.rs | Admit | Deny |
| RolloutTransition | rollout_state.rs | Admit | Deny |
| QuarantineAction | state_model.rs | Release | Quarantine |
| FencingDecision | fencing.rs | Admit | Deny |
| MigrationDecision | lifecycle.rs | Admit | Deny |

### Schema Alignment

All entries use the canonical EvidenceEntry schema from bd-nupr (10.14) v1.0.

### Required Fields Per Entry

- `schema_version`: "1.0"
- `decision_id`: unique decision identifier
- `decision_type`: one of the five types above
- `decision_kind`: canonical kind from mapping table
- `policy_inputs`: policy signals consumed
- `candidates_considered`: alternatives evaluated
- `chosen_action`: action taken
- `rejection_reasons`: why alternatives were rejected
- `epoch`: current epoch
- `trace_id`: distributed trace correlation
- `timestamp_ms`: wall-clock time

## Invariants

- **INV-CE-MANDATORY**: Every policy decision emits evidence
- **INV-CE-SCHEMA**: Entries match canonical EvidenceEntry schema
- **INV-CE-DETERMINISTIC**: Same inputs produce same entry sequence
- **INV-CE-FAIL-CLOSED**: Missing evidence blocks decision execution

## Event Codes

| Code | Description |
|------|-------------|
| EVD-001 | Evidence entry emitted |
| EVD-002 | Evidence entry missing (conformance failure) |
| EVD-003 | Schema validation passed |
| EVD-004 | Schema validation failed |
| EVD-005 | Ordering violation detected |

## Dependencies

- **Upstream**: bd-oolt (evidence emission requirement), bd-2e73 (bounded ledger), bd-nupr (schema)
- **Downstream**: bd-20eg (section gate), bd-tyr2 (evidence replay validator)

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/connector/control_evidence.rs` |
| Integration contract | `docs/integration/control_evidence_contract.md` |
| Evidence samples | `artifacts/10.15/control_evidence_samples.jsonl` |
| Verification script | `scripts/check_control_evidence.py` |
| Python tests | `tests/test_check_control_evidence.py` |
