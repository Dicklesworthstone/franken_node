# bd-gad3 Contract: Adaptive Multi-Rail Isolation Mesh with Hot-Elevation Policy

## Section
10.17 -- Radical Expansion Execution Track

## Objective
Ship an adaptive multi-rail isolation mesh that allows workloads to be promoted
to stricter isolation rails at runtime without losing policy continuity. Latency-sensitive
trusted workloads remain on high-performance rails within budget.

## Acceptance Criteria
- Workloads can be promoted to stricter rails at runtime without losing policy continuity.
- Latency-sensitive trusted workloads remain on high-performance rails within budget.
- Hot-elevation transitions are atomic: no workload runs with inconsistent policy state.
- Demotion from a stricter rail to a less strict rail is explicitly forbidden (fail-closed).
- Mesh topology is deterministic and auditable via structured events.
- Latency budget enforcement rejects elevation requests that would violate the budget.

## Key Types

### IsolationRailLevel
Ordered isolation tiers from least to most strict:
- `Shared` -- default shared-memory rail, lowest isolation
- `ProcessIsolated` -- separate process boundary
- `SandboxIsolated` -- sandboxed execution with capability filtering
- `HardwareIsolated` -- hardware-backed isolation (TEE / enclave)

### IsolationRail
A named rail instance with a level, latency budget, and capacity.

### ElevationPolicy
Controls whether elevation is permitted, the maximum target level, and whether
the workload's latency budget must be preserved during promotion.

### MeshTopology
The set of configured rails and their relationships. Rails are stored in a
BTreeMap for deterministic ordering.

### RailState
Per-rail runtime state tracking active workload count and elevation history.

### WorkloadPlacement
Records the rail a workload is currently assigned to, its policy, and
the trace of elevations it has undergone.

## Event Codes

| Code | Meaning |
|------|---------|
| MESH_001 | Workload placed on initial rail |
| MESH_002 | Hot-elevation completed successfully |
| MESH_003 | Elevation denied: policy violation |
| MESH_004 | Elevation denied: latency budget exceeded |
| MESH_005 | Workload removed from mesh |
| MESH_006 | Mesh topology reloaded |
| MESH_007 | Demotion attempt blocked |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_MESH_UNKNOWN_RAIL | Referenced rail does not exist in topology |
| ERR_MESH_UNKNOWN_WORKLOAD | Referenced workload not found in mesh |
| ERR_MESH_ELEVATION_DENIED | Elevation blocked by policy |
| ERR_MESH_DEMOTION_FORBIDDEN | Demotion is never permitted |
| ERR_MESH_LATENCY_EXCEEDED | Elevation would violate latency budget |
| ERR_MESH_RAIL_AT_CAPACITY | Target rail has no remaining capacity |
| ERR_MESH_DUPLICATE_WORKLOAD | Workload already placed in mesh |
| ERR_MESH_INVALID_TOPOLOGY | Topology validation failed |

## Invariants

| ID | Statement |
|----|-----------|
| INV-MESH-MONOTONIC-ELEVATION | Workload isolation level can only increase (never demote) |
| INV-MESH-POLICY-CONTINUITY | Policy envelope is preserved across elevation transitions |
| INV-MESH-ATOMIC-TRANSITION | No workload observes inconsistent policy during elevation |
| INV-MESH-LATENCY-BUDGET | Elevation respects the workload latency budget or is rejected |
| INV-MESH-DETERMINISTIC-TOPOLOGY | Mesh topology iteration order is deterministic (BTreeMap) |
| INV-MESH-FAIL-CLOSED | Unknown rails, invalid policies, and demotions fail closed |

## Artifacts
- `crates/franken-node/src/runtime/isolation_mesh.rs`
- `docs/specs/section_10_17/bd-gad3_contract.md`
- `scripts/check_isolation_mesh.py`
- `tests/test_check_isolation_mesh.py`
- `artifacts/section_10_17/bd-gad3/verification_evidence.json`
- `artifacts/section_10_17/bd-gad3/verification_summary.md`
