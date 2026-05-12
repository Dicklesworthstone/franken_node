# bd-15j6: Mandatory Evidence Emission for Control Decisions

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-05-12

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust unit tests | 76 | 76 |
| Rust conformance target | 6 | 6 |
| Python verification checks | 101 | 101 |
| Python unit tests | 33 | 33 |

## Implementation

`crates/franken-node/src/connector/control_evidence.rs`

Named conformance target: `tests/conformance/control_policy_evidence_required.rs`
with the stable `policy_evidence_required` sentinel.

- **Types:** DecisionType (5 variants), DecisionKind (7 variants), DecisionOutcome, ControlEvidenceEntry, ConformanceError, ControlEvidenceEvent, ControlEvidenceEmitter
- **Event codes:** EVD-001 (emitted), EVD-002 (missing evidence), EVD-003 (schema valid), EVD-004 (schema invalid), EVD-005 (ordering violation)
- **Invariants:** INV-CE-MANDATORY, INV-CE-SCHEMA, INV-CE-DETERMINISTIC, INV-CE-FAIL-CLOSED
- **Decision types covered:** HealthGateEval, RolloutTransition, QuarantineAction, FencingDecision, MigrationDecision

## Verification Coverage

- File existence (impl, spec, samples JSONL, named conformance test)
- JSONL sample quality (10+ entries, all 5 decision types)
- Spec content (all decision types documented)
- Module registration in connector/mod.rs
- Serde derives present
- All 7 types, 13 methods, 5 event codes, 4 invariants, 51 required inline test names, and 6 conformance tests verified
