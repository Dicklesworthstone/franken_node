# bd-2o8b: Heterogeneous Hardware Planner with Policy-Evidenced Placements

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-2o8b |
| Section | 10.17 |
| Title | Implement heterogeneous hardware planner with policy-evidenced placements |
| Type | task |

## Purpose

The franken_node radical expansion track requires a heterogeneous hardware planner
that assigns workloads to hardware targets while producing machine-readable evidence
of the policy reasoning behind each placement decision. This bead implements the
core planner, placement policy engine, hardware profile registry, and evidence trail.

The planner enables:
- Registration of heterogeneous hardware profiles with capability/risk annotations.
- Policy-driven placement decisions that satisfy capability and risk constraints.
- Deterministic reproducibility: identical inputs yield identical placement decisions.
- Fallback path selection on resource contention with documented reasoning.
- Machine-readable policy evidence for every placement decision.
- Dispatch execution gated through approved runtime/engine interfaces.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-2o8b_contract.md` |
| Rust module | `crates/franken-node/src/runtime/hardware_planner.rs` |
| Check script | `scripts/check_hardware_planner.py` |
| Test suite | `tests/test_check_hardware_planner.py` |
| Evidence | `artifacts/section_10_17/bd-2o8b/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-2o8b/verification_summary.md` |

## Invariants

- **INV-HWP-DETERMINISTIC**: Given identical hardware profiles, policies, and
  workload requests, the planner produces identical placement decisions. All
  collections use BTreeMap/BTreeSet for deterministic ordering.
- **INV-HWP-CAPABILITY-MATCH**: A workload is only placed on hardware whose
  capability set is a superset of the workload's required capabilities.
- **INV-HWP-RISK-BOUND**: A placement is rejected if the hardware's risk level
  exceeds the workload's maximum tolerated risk level.
- **INV-HWP-EVIDENCE-COMPLETE**: Every placement decision (success or rejection)
  carries a PolicyEvidence record documenting the reasoning chain.
- **INV-HWP-FALLBACK-PATH**: On resource contention, the planner attempts a
  fallback path and records the contention reason in the evidence trail.
- **INV-HWP-DISPATCH-GATED**: Dispatch executes only through an approved
  runtime/engine interface; direct hardware access is forbidden.
- **INV-HWP-SCHEMA-VERSIONED**: All serialized outputs carry a schema version
  for backward-detectable format changes.
- **INV-HWP-AUDIT-COMPLETE**: Every planner decision is recorded in a structured
  audit log with stable event codes.

## Event Codes

| Code | Meaning |
|------|---------|
| HWP-001 | Hardware profile registered |
| HWP-002 | Placement policy registered |
| HWP-003 | Placement requested |
| HWP-004 | Placement succeeded |
| HWP-005 | Placement rejected (capability mismatch) |
| HWP-006 | Placement rejected (risk exceeded) |
| HWP-007 | Placement rejected (capacity exhausted) |
| HWP-008 | Fallback path attempted |
| HWP-009 | Fallback path succeeded |
| HWP-010 | Fallback path exhausted |
| HWP-011 | Dispatch executed through approved interface |
| HWP-012 | Policy evidence recorded |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_HWP_NO_CAPABLE_TARGET | No registered hardware satisfies workload capabilities |
| ERR_HWP_RISK_EXCEEDED | All capable hardware exceeds workload risk tolerance |
| ERR_HWP_CAPACITY_EXHAUSTED | All capable hardware at capacity (no slots) |
| ERR_HWP_DUPLICATE_PROFILE | Hardware profile ID already registered |
| ERR_HWP_DUPLICATE_POLICY | Policy ID already registered |
| ERR_HWP_UNKNOWN_PROFILE | Referenced hardware profile does not exist |
| ERR_HWP_EMPTY_CAPABILITIES | Workload declares zero required capabilities |
| ERR_HWP_DISPATCH_UNGATED | Dispatch attempted without approved interface |
| ERR_HWP_INVALID_RISK_LEVEL | Risk level outside valid range [0, 100] |
| ERR_HWP_FALLBACK_EXHAUSTED | All fallback paths exhausted without successful placement |

## Acceptance Criteria

1. Placement decisions satisfy capability/risk constraints and remain reproducible
   from identical inputs.
2. Planner reports policy reasoning and fallback path on resource contention.
3. Dispatch executes through approved runtime/engine interfaces.
4. All collections use BTreeMap/BTreeSet for deterministic ordering.
5. Schema version constant present on all serialized outputs.
6. Every decision produces structured audit entries with stable event codes.
7. Minimum 20 inline unit tests covering all error paths and invariants.
8. Check script produces machine-readable JSON evidence.

## Testing Requirements

- Unit tests for every error variant and every invariant.
- Deterministic replay: given identical inputs, identical placement output.
- Capability matching: workloads only placed on sufficient hardware.
- Risk bounding: risk-exceeding placements rejected.
- Fallback path: contention triggers fallback with evidence.
- Structured log entries with stable event codes for triage.
