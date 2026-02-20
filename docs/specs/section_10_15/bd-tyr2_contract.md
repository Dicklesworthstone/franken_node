# bd-tyr2: Integrate Canonical Evidence Replay Validator into Control-Plane Decision Gates

## Summary

Wires the canonical evidence-ledger replay validator (from 10.14, bd-2ona) into
franken_node's control-plane decision gates so that every policy-influenced
decision can be verified post-hoc. The control-plane gate consumes the validator's
verdict and blocks releases where decisions cannot be replayed.

## Scope

### Decision Types Verified via Replay

| Decision Type | Module | Replay Verdict on Match |
|--------------|--------|------------------------|
| HealthGateEval | health_gate.rs | REPRODUCED |
| RolloutTransition | rollout_state.rs | REPRODUCED |
| QuarantineAction | state_model.rs | REPRODUCED |
| FencingDecision | fencing.rs | REPRODUCED |
| MigrationDecision | lifecycle.rs | REPRODUCED |

### Verdict Format

| Verdict | Meaning | Gate Action |
|---------|---------|-------------|
| REPRODUCED | Replay produced same action | Pass |
| DIVERGED | Replay produced different action (with diff) | Block |
| ERROR | Validator could not complete replay | Block |

### Canonical Validator Requirement

The product layer MUST use the canonical 10.14 replay validator
(`crate::tools::evidence_replay_validator::EvidenceReplayValidator`).
Custom replay logic is prohibited (INV-CRG-CANONICAL).

## Invariants

- **INV-CRG-CANONICAL**: Uses the 10.14 canonical replay validator (no custom logic)
- **INV-CRG-BLOCK-DIVERGED**: DIVERGED/ERROR verdicts block the gate
- **INV-CRG-DETERMINISTIC**: Same inputs produce same verdict
- **INV-CRG-COMPLETE**: All 5 control decision types have replay coverage

## Event Codes

| Code | Description |
|------|-------------|
| RPL-001 | Replay initiated for a control decision |
| RPL-002 | REPRODUCED verdict |
| RPL-003 | DIVERGED verdict (with diff hash) |
| RPL-004 | ERROR verdict |
| RPL-005 | Gate decision based on replay verdict |

## Dependencies

- **Upstream**: bd-2ona (canonical evidence-ledger replay validator)
- **Downstream**: bd-20eg (section gate), bd-3qo (execution track)

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/connector/control_evidence_replay.rs` |
| Adoption contract | `docs/integration/control_evidence_replay_adoption.md` |
| Replay report | `artifacts/10.15/control_evidence_replay_report.json` |
| Verification script | `scripts/check_control_evidence_replay.py` |
| Python tests | `tests/test_check_control_evidence_replay.py` |
