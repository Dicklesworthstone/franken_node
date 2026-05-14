# DGIS Quarantine Orchestration

## Scope

This contract defines how the Dependency Graph Immune System converts a
choke-point containment decision into runtime quarantine barriers. The
authoritative implementation is `crates/franken-node/src/security/dgis` and the
focused containment regression is `tests/security/dgis_quarantine_containment.rs`.

## Containment Model

A quarantine plan is a `BarrierPlan` with one stable `plan_id` and one or more
barriers for the affected dependency graph node. For a high-risk choke point,
the plan must compose all applicable controls instead of relying on a single
flag:

| Control | Required behavior |
| --- | --- |
| Sandbox escalation | Raise the node to the required `SandboxTier` and deny listed capabilities. |
| Composition firewall | Block lateral movement across the named trust boundary unless an explicit allow-list entry exists. |
| Verified-fork pin | Reject dependency artifacts whose digest does not match the trusted fork pin. |
| Staged rollout fence | Hold rollout at the current phase until progression criteria are satisfied. |

## Invariants

- `INV-DGIS-QUARANTINE-PLAN-TRACE`: every applied barrier receipt preserves the
  source `plan_id` in receipt details.
- `INV-DGIS-QUARANTINE-LATERAL-BLOCK`: blocked capabilities crossing a protected
  boundary emit `DGIS-BARRIER-006` and return a denial error.
- `INV-DGIS-QUARANTINE-FORK-PIN`: fork digest mismatches emit a denial and cannot
  be treated as a successful containment check.
- `INV-DGIS-QUARANTINE-ROLLOUT-FENCE`: direct promotion from canary to general
  rollout is denied until staged progression advances.
- `INV-DGIS-QUARANTINE-COVERAGE-GAP`: a node with no matching authoritative
  barrier emits `DGIS-BARRIER-007` (`not_applicable`) so coverage gaps remain
  visible to the operator and to replay.

## Audit Contract

Quarantine orchestration is auditable through the existing barrier receipt
schema. A containment drill must be able to export JSONL with:

- `event_code` for every apply, deny, pass, rollback, and not-applicable check,
- `trace_id` linking the runtime check to the operator drill or incident,
- `barrier_id`, `node_id`, `barrier_type`, and `action`,
- the source `plan_id` on applied barrier receipts.

The audit log must never synthesize a pass for missing coverage. If a check does
not find a matching barrier, it must emit an explicit `not_applicable` receipt
and preserve the requested capability, boundary, or artifact digest in details.

## Regression Coverage

`tests/security/dgis_quarantine_containment.rs` covers:

- a graph-aware containment plan that applies sandbox, firewall, fork-pin, and
  rollout-fence barriers to a choke-point node,
- fail-closed denials for runtime capability, lateral export, fork drift, and
  direct rollout promotion,
- explicit `not_applicable` receipts for uncataloged nodes,
- JSONL audit export preserving denial event codes, source plan traceability, and
  check trace IDs.
