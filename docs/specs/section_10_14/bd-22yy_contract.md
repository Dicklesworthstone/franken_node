# bd-22yy: DPOR-Style Schedule Exploration Gates — Spec Contract

**Section:** 10.14 | **Bead:** bd-22yy | **Status:** Active

## Purpose

Dynamic Partial Order Reduction (DPOR) systematically explores different
interleavings of concurrent operations while pruning equivalent schedules.
Targets epoch barrier coordination, remote capability operations, and marker
stream mutations to verify no schedule produces a safety violation.

## Protocol Models

| Model                      | Operations | Safety Properties |
|---------------------------|-----------|------------------|
| Epoch barrier coordination | 5 (propose, 3x drain, commit) | no_dual_epoch, commit_requires_all_drains |
| Remote capability ops      | 4 (acquire, execute, release, epoch-transition) | no_execute_without_cap, release_after_execute |
| Marker stream mutations    | 4 (append x2, fence, read-head) | dense_sequence, hash_chain_valid |

## Invariants

- **INV-DPOR-COMPLETE**: all non-equivalent schedules explored for bounded models
- **INV-DPOR-COUNTEREXAMPLE**: violations produce minimal counterexample traces
- **INV-DPOR-BOUNDED**: exploration respects CI time and memory budgets
- **INV-DPOR-DETERMINISTIC**: same model always explores same schedules
- **INV-DPOR-COVERAGE**: coverage metrics track explored/estimated ratio
- **INV-DPOR-SAFETY**: safety properties checked at every explored state

## Event Codes

| Code                      | Description                      |
|---------------------------|----------------------------------|
| DPOR_EXPLORATION_START    | Exploration started              |
| DPOR_SCHEDULE_EXPLORED    | Schedule explored (debug)        |
| DPOR_VIOLATION_FOUND      | Safety violation found           |
| DPOR_EXPLORATION_COMPLETE | Exploration complete             |
| DPOR_BUDGET_EXCEEDED      | Time/memory budget exceeded      |
| DPOR_MODEL_REGISTERED     | Protocol model registered        |
| DPOR_PROPERTY_CHECKED     | Safety property checked          |
| DPOR_COUNTEREXAMPLE_EMITTED | Counterexample emitted         |
| DPOR_PRUNED_EQUIVALENT    | Equivalent schedule pruned       |
| DPOR_REPORT_EXPORTED      | Report exported                  |

## Error Codes

| Code                      | Description                      |
|---------------------------|----------------------------------|
| ERR_DPOR_BUDGET_EXCEEDED  | Time budget exceeded             |
| ERR_DPOR_MEMORY_EXCEEDED  | Memory budget exceeded           |
| ERR_DPOR_UNKNOWN_MODEL    | Unknown model reference          |
| ERR_DPOR_INVALID_OPERATION| Invalid operation in model       |
| ERR_DPOR_SAFETY_VIOLATION | Safety property violated         |
| ERR_DPOR_CYCLE_DETECTED   | Dependency cycle in model        |
| ERR_DPOR_EMPTY_MODEL      | Model has no operations          |
| ERR_DPOR_NO_PROPERTIES    | Model has no safety properties   |

## Dependencies

- **bd-3hdv**: Monotonic control epoch (epoch model semantics)
- **bd-ac83**: Named remote computation registry (remote model identifiers)

## Verification Artifacts

- `crates/franken-node/src/control_plane/dpor_exploration.rs`: canonical DPOR framework.
- `tests/lab/control_dpor_exploration.rs`: canonical lab coverage for control-plane DPOR interactions. This is the shipped artifact that supersedes the historical master-plan name `tests/lab/dpor_protocol_exploration.rs`.
- `scripts/check_dpor_exploration.py`: verification gate for the framework, contract, module wiring, and canonical lab test presence.
- `artifacts/section_10_14/bd-22yy/verification_evidence.json`: machine-readable verification evidence.

Schema version: `dpor-v1.0`
