# bd-tyr2: Evidence Replay Validator Integration

**Section:** 10.15 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust unit tests (impl) | 68 | 68 |
| Rust conformance tests | 19 | 19 |
| Python verification checks | 147 | 147 |
| Python unit tests | 43 | 43 |

## Implementation

`crates/franken-node/src/connector/control_evidence_replay.rs`

- **Types:** ReplayVerdict (3 variants), ControlReplayGate, ReplayGateEvent, ReplayGateSummary
- **Event codes:** RPL-001 (initiated), RPL-002 (reproduced), RPL-003 (diverged), RPL-004 (error), RPL-005 (gate decision)
- **Invariants:** INV-CRG-CANONICAL, INV-CRG-BLOCK-DIVERGED, INV-CRG-DETERMINISTIC, INV-CRG-COMPLETE
- **Decision types covered:** HealthGateEval, RolloutTransition, QuarantineAction, FencingDecision, MigrationDecision
- **Bridge functions:** map_to_ledger_kind, to_ledger_entry, build_replay_context
- **Canonical validator:** Delegates ALL replay to `tools::evidence_replay_validator::EvidenceReplayValidator`

## Verification Coverage

- File existence (7 files: impl, conformance test, spec, adoption doc, report, validator, control_evidence)
- Module registration in connector/mod.rs
- Test counts (68 impl + 19 conformance)
- Serde derives present
- Canonical validator usage (no custom replay logic)
- All 4 types, 12 methods, 5 event codes, 4 invariants verified
- All 64 impl tests and 19 conformance tests verified
- Adoption doc: 5 decision types + 3 verdicts documented
- Spec: 5 decision types + 3 verdicts documented
- Replay report: valid JSON, 5 decision types, adversarial tests, determinism, gate behavior
