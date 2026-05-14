# bd-7om Verification Summary

## Result
PASS

## Completion-Debt Follow-Up
- Reconciled `bd-7om.1` against the reopened audit finding: `artifacts/10.15` currently contains 30 artifact files, including `cancel_protocol_timing.csv` and `control_evidence_replay_report.json`.
- The 10.15 cancellation source artifact is `artifacts/10.15/cancel_protocol_timing.csv`; `scripts/check_cancellation_protocol.py:13` points at it and `scripts/check_cancellation_protocol.py:133` through `scripts/check_cancellation_protocol.py:138` validate its header and workflow rows.
- The 10.15 control evidence replay artifact is `artifacts/10.15/control_evidence_replay_report.json`; `scripts/check_control_evidence_replay.py:20` through `scripts/check_control_evidence_replay.py:25` bind the implementation, conformance test, adoption doc, spec, report, and canonical replay validator.
- The product-service adoption surface remains the 10.11 bd-7om runtime contract: `docs/specs/section_10_11/bd-7om_contract.md:11` through `docs/specs/section_10_11/bd-7om_contract.md:16` state that this bead adopts the canonical 10.15 cancel -> drain -> finalize protocol for product services, and `crates/franken-node/src/runtime/cancellable_task.rs` implements the `CancellableTask` / `CancellationRuntime` surface.
- Scope boundary: `control_evidence_replay_report.json` is part of the broader 10.15 control-plane evidence corpus, not a second bd-7om implementation target. It is cross-referenced here to make the completion audit explicit about the artifact corpus named in `bd-7om.1`.

## Delivered
- `crates/franken-node/src/runtime/cancellable_task.rs`
- `crates/franken-node/src/runtime/mod.rs` (wired cancellable_task module)
- `docs/specs/section_10_11/bd-7om_contract.md`
- `scripts/check_cancellable_task_protocol.py`
- `tests/test_check_cancellable_task_protocol.py`
- `artifacts/section_10_11/bd-7om/verification_evidence.json`
- `artifacts/section_10_11/bd-7om/verification_summary.md`

## Invariants

| ID | Status |
|----|--------|
| INV-CXT-THREE-PHASE | Enforced -- phase FSM rejects out-of-order transitions |
| INV-CXT-DRAIN-BOUNDED | Enforced -- DrainConfig with configurable timeout |
| INV-CXT-FINALIZE-RECORD | Enforced -- every finalization produces FinalizeRecord |
| INV-CXT-CLOSURE-COMPLETE | Enforced -- ObligationClosureProof checked at finalize |
| INV-CXT-LANE-RELEASE | Enforced -- FN-CX-008 emitted after finalization |
| INV-CXT-NESTED-PROPAGATION | Enforced -- cancel propagates to registered child tasks |

## Event Codes

| Code | Description | Status |
|------|-------------|--------|
| FN-CX-001 | Task registered | Implemented |
| FN-CX-002 | Cancel signal sent | Implemented |
| FN-CX-003 | Drain started | Implemented |
| FN-CX-004 | Drain completed | Implemented |
| FN-CX-005 | Drain timed out | Implemented |
| FN-CX-006 | Finalize started | Implemented |
| FN-CX-007 | FinalizeRecord produced | Implemented |
| FN-CX-008 | Lane slot released | Implemented |
| FN-CX-009 | Nested cancel propagated | Implemented |
| FN-CX-010 | Obligation closure incomplete | Implemented |

## Error Codes

| Code | Description | Status |
|------|-------------|--------|
| ERR_CXT_INVALID_PHASE | Invalid phase transition | Implemented |
| ERR_CXT_DRAIN_TIMEOUT | Drain exceeded timeout | Implemented |
| ERR_CXT_CLOSURE_INCOMPLETE | Obligation closure incomplete | Implemented |
| ERR_CXT_TASK_NOT_FOUND | Task not found | Implemented |
| ERR_CXT_ALREADY_FINALIZED | Already finalized | Implemented |
| ERR_CXT_DUPLICATE_TASK | Duplicate registration | Implemented |

## Gate Results
- `python3 scripts/check_cancellable_task_protocol.py --json` -> PASS
- `python3 scripts/check_cancellable_task_protocol.py --self-test` -> PASS
- `python3 -m pytest tests/test_check_cancellable_task_protocol.py -v` -> PASS
- `python3 scripts/check_cancellation_protocol.py --json` -> PASS, validates the upstream 10.15 cancellation artifact corpus including `cancel_protocol_timing.csv`
- `python3 scripts/check_control_evidence_replay.py --json` -> PASS, validates the 10.15 control evidence replay report named by the completion-debt finding
