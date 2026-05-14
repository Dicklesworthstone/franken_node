# DGIS Immunization Planner

## Purpose

The immunization planner converts DGIS topology risk metrics into ranked,
enforceable barrier plans. It sits between graph intelligence and the DGIS
barrier engine: topology identifies choke points, the planner selects a
minimum-cost bounded barrier set, and `BarrierPlan` carries the selected
barriers to runtime enforcement.

## Inputs

- `CriticalNodeInput`: node id, `TopologyRiskMetrics`, and expected cascade
  loss for that node.
- `PolicyConstraints`: nodes that must not receive planner-selected barriers.
- `BarrierInventory`: available primitive families and node-specific verified
  fork pin material.
- `ImmunizationPlannerConfig`: target cascade loss, total overhead ceiling,
  maximum barriers per plan, maximum returned plans, and bounded search width.

All floating-point inputs must be finite and non-negative. Invalid metrics,
duplicate node ids, empty node ids, and embedded NUL bytes are rejected before
planning.

## Candidate Synthesis

The planner synthesizes barrier candidates from graph-structure signals:

| Signal | Candidate barrier | Mitigated metric |
| --- | --- | --- |
| Articulation point or high betweenness | Composition firewall | `articulation_point_or_betweenness` |
| High trust bottleneck or aggregate risk | Sandbox escalation | `trust_bottleneck_score` |
| High fan-out or aggregate risk | Staged rollout fence | `fan_out_or_aggregate_risk` |
| Deep transitive graph with supplied fork material | Verified fork pin | `transitive_dependency_count` |

Verified fork pin candidates are emitted only when the input inventory provides
real fork material for the node. The planner does not fabricate fork URLs,
commits, keys, or expected digests.

## Selection

Candidate barriers are sorted deterministically by cost effectiveness,
cost, overhead, node id, barrier type, and stable candidate id. The search
enumerates the configured candidate window and returns the lowest-cost feasible
plans that reduce total expected cascade loss below `target_cascade_loss` while
respecting policy exclusions, overhead budget, and barrier-count limits.

If the target is already met, the catalog contains a no-op plan. If no
candidate set can satisfy the target under constraints, planning fails closed
with `NoFeasiblePlan` instead of emitting a synthetic pass.

## Output Contract

`BarrierPlanCatalog` is machine-readable and replayable:

- `baseline_cascade_loss` and `target_cascade_loss` define the optimization
  objective.
- Each `ImmunizationPlan` includes rank, stable plan id, enforceable
  `BarrierPlan`, total cost, total overhead, expected post-plan cascade loss,
  cumulative reduction, and target status.
- Each `PlannedBarrier` includes the exact `Barrier`, cost, overhead,
  risk-reduction delta, and a `BarrierRationale` linking the recommendation to
  the mitigated metric.
- `PlanningEvent` records stable `DGIS-IMMUNE-*` codes for catalog generation,
  candidate synthesis, policy exclusions, no-op outcomes, and incremental
  replan scope.

## Incremental Replanning

`plan_incremental` accepts a set of changed node ids and runs the same planner
against only the matching input nodes. The output includes
`IncrementalReplanSummary` with changed, scoped, and skipped node counts so
callers can prove the replan was scoped to graph deltas rather than a full
recompute.

## Implementation

- `crates/franken-node/src/security/dgis/immunization_planner.rs`
- `crates/franken-node/src/security/dgis/mod.rs`
- `tests/security/dgis_immunization_planner.rs`
