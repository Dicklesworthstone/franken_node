# bd-15j6: Mandatory Evidence Emission for Control Decisions

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust unit tests | 51 | 51 |
| Python verification checks | 94 | 94 |
| Python unit tests | 31 | 31 |

## Implementation

`crates/franken-node/src/connector/control_evidence.rs`

- **Types:** DecisionType (5 variants), DecisionKind (7 variants), DecisionOutcome, ControlEvidenceEntry, ConformanceError, ControlEvidenceEvent, ControlEvidenceEmitter
- **Event codes:** EVD-001 (emitted), EVD-002 (missing evidence), EVD-003 (schema valid), EVD-004 (schema invalid), EVD-005 (ordering violation)
- **Invariants:** INV-CE-MANDATORY, INV-CE-SCHEMA, INV-CE-DETERMINISTIC, INV-CE-FAIL-CLOSED
- **Decision types covered:** HealthGateEval, RolloutTransition, QuarantineAction, FencingDecision, MigrationDecision

## Verification Coverage

- File existence (impl, spec, samples JSONL)
- JSONL sample quality (10+ entries, all 5 decision types)
- Spec content (all decision types documented)
- Module registration in connector/mod.rs
- Serde derives present
- All 7 types, 13 methods, 5 event codes, 4 invariants, 51 test functions verified
