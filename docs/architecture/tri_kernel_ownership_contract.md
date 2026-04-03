---
schema_version: "1.0"
bead_id: "bd-1id0"
section: "10.15"
kernels:
  franken_engine:
    plane: execution
    owns:
      - runtime execution internals
      - extension host sandbox boundary
      - low-level remote/effect execution primitives
  asupersync:
    plane: correctness-control
    owns:
      - cancellation protocol semantics
      - lane scheduling discipline
      - epoch transition barriers
      - deterministic replay/evidence contracts
  franken_node:
    plane: product
    owns:
      - user/operator product surfaces
      - policy orchestration and UX
      - evidence consumption and publication
hard_runtime_invariant_owners:
  HRI-01: asupersync
  HRI-02: asupersync
  HRI-03: asupersync
  HRI-04: asupersync
  HRI-05: asupersync
  HRI-06: asupersync
  HRI-07: asupersync
  HRI-08: asupersync
  HRI-09: asupersync
  HRI-10: franken_node
permitted_cross_kernel_interfaces:
  - "franken_node -> asupersync: Cx/Region/Epoch stable facades only"
  - "franken_node -> franken_engine: public runtime API only"
  - "asupersync -> franken_engine: explicit execution adapters only"
  - "no kernel may import another kernel's *_internal modules"
canonical_asupersync_primitives:
  - cx_propagation
  - region_ownership_scope
  - cancellation_protocol
  - obligation_tracking
  - remote_computation_registry
  - epoch_validity_window
  - evidence_ledger_emission
waiver_policy:
  registry_path: "docs/governance/ownership_boundary_waivers.json"
  required_fields:
    - waiver_id
    - file
    - boundary
    - rationale
    - signed_by
    - signature
    - expires_at
  expiry_enforced: true
  unsigned_allowed: false
structured_event_codes:
  - OWN-001
  - OWN-002
  - OWN-003
  - OWN-004
---

# Tri-Kernel Ownership Contract

## Scope

This contract defines hard ownership boundaries between:

- `franken_engine` (execution kernel)
- `asupersync` (correctness/control kernel)
- `franken_node` (product kernel)

Boundary violations are CI-fatal unless covered by a signed, non-expired waiver in
`docs/governance/ownership_boundary_waivers.json`.

## Ownership Planes

### Execution Plane (`franken_engine`)

Responsibilities:

- Runtime internals and low-level execution behavior
- Extension host isolation and sandbox substrate
- Primitive remote/effect execution mechanisms

Prohibited from:

- Embedding product UX/policy semantics
- Re-defining correctness-level cancellation/epoch protocol rules

### Correctness/Control Plane (`asupersync`)

Responsibilities:

- Cancellation protocol (`request -> drain -> finalize`)
- Scheduler lane semantics and starvation policy
- Epoch barriers and transition safety
- Deterministic evidence/replay correctness contracts

Prohibited from:

- Implementing product UX orchestration directly
- Bypassing execution kernel public interfaces

### Product Plane (`franken_node`)

Responsibilities:

- Product APIs, operator workflows, diagnostics, and reporting
- Policy orchestration over correctness/execution APIs
- Publication and governance surfaces

Prohibited from:

- Re-implementing execution primitives from `franken_engine`
- Re-implementing correctness protocol internals from `asupersync`

## Boundary Rules

1. Product code may consume correctness behavior only via approved facade APIs.
2. Product code may consume execution behavior only via approved execution APIs.
3. Direct imports into internal correctness/execution implementation modules are violations.
4. Duplicate implementation of ownership-scoped capabilities across kernels is prohibited.
5. Any exception requires a signed waiver with explicit expiry.

## Canonical Primitive Vocabulary

The canonical primitive list used by workflow-mapping gates is declared in frontmatter under
`canonical_asupersync_primitives` and currently includes:

- `cx_propagation`
- `region_ownership_scope`
- `cancellation_protocol`
- `obligation_tracking`
- `remote_computation_registry`
- `epoch_validity_window`
- `evidence_ledger_emission`

## Waiver Contract

A waiver record MUST include:

- `waiver_id` (stable identifier)
- `file` (project-relative path)
- `boundary` (e.g., `product->correctness-internal`)
- `rationale`
- `signed_by` (human approver)
- `signature` (non-empty approval proof string)
- `expires_at` (RFC 3339 date-time)

Unsigned or expired waivers fail CI (`OWN-004`).

## Structured Events

- `OWN-001`: boundary check pass
- `OWN-002`: boundary violation detected
- `OWN-003`: valid waiver applied
- `OWN-004`: waiver invalid or expired

## CI Enforcement

Primary gate artifact:

- `artifacts/10.15/ownership_boundary_report.json`

Conformance test surface:

- `tests/conformance/ownership_boundary_checks.rs`

Section evidence outputs:

- `artifacts/section_10_15/bd-1id0/verification_evidence.json`
- `artifacts/section_10_15/bd-1id0/verification_summary.md`

## Semantic Twin Inventory And Classification Matrix

**Bead:** `bd-1now.5.1`

This section records the current local Asupersync-like semantic twins in
`franken_node` and classifies each one against the upstream ownership boundary.
It exists so future contributors do not have to reconstruct the decision from
chat history or infer it from scattered beads.

When a row points to a heavy cargo validation surface instead of a pure
doc/script gate, that validation must be run through `rch`.

### Outcome Vocabulary

| Outcome | Meaning | Allowed change shape |
|---|---|---|
| `Keep local model` | Local surface remains in `franken_node` because it currently describes product semantics, deterministic modeling, or bounded publication behavior rather than owning a live canonical runtime primitive. | Tighten local invariants, docs, and tests. Do not present it as the canonical primitive. |
| `Wrap canonical ownership` | Local surface may exist, but its semantics are downstream of an upstream-owned primitive or approved adapter boundary. | Keep the wrapper/facade if useful, but align vocabulary, invariants, and verdicts with the canonical boundary. |
| `Defer until trigger` | Native Asupersync adoption is premature because the crate does not yet own the required runtime topology. | Keep the local skeleton or documentation only until the named trigger exists. |
| `Forbid duplicate fork` | A second local implementation would create two competing truths for the same primitive. | Extend an existing sanctioned surface or the upstream adapter instead of adding a new primitive. |

### Decision Procedure For New Surfaces

1. If the surface owns real long-lived concurrency, shutdown, backpressure, restart, or reply obligations today, compare it against the upstream adapter first and prefer `Wrap canonical ownership`.
2. If the surface is a model/spec/test kernel with no live runtime owner underneath it, prefer `Keep local model`.
3. If the surface only sketches a future service or actor boundary, classify it as `Defer until trigger` and name the trigger explicitly.
4. If a new implementation would create a second local source of truth for Cx/region/cancellation/obligation/epoch/lane semantics, classify it as `Forbid duplicate fork`.
5. Every classification must point to at least one proof surface: spec, checker, unit/integration test, artifact bundle, or an explicit note that the row is document-only for now.

### Inventory Matrix

| Local surface | Related canonical primitive or adapter | Current role in `franken_node` | Outcome | Trigger or non-trigger | Drift consequence | Enforcement or proof surface |
|---|---|---|---|---|---|---|
| `crates/franken-node/src/connector/region_ownership.rs` | `region_ownership_scope`; `franken_engine::control_plane::{Cx, TraceId, Budget}` | Deterministic region-owned connector lifecycle model plus `ControlPlaneCx` vocabulary for connector orchestration. | `Keep local model` | Keep local until a live owned runtime boundary actually executes beneath these regions. Vocabulary alone is not enough to justify substrate migration. | Product docs and policy gates could promise quiescence/ownership guarantees that the live runtime does not actually enforce. | `scripts/check_region_ownership.py`, `tests/test_check_region_ownership.py`, `docs/specs/region_tree_topology.md`, `artifacts/section_10_15/bd-2tdi/` |
| `crates/franken-node/src/connector/supervision.rs` | Asupersync-flavored supervision and restart-budget semantics (no direct upstream adapter exposed here today) | Deterministic supervision model, restart-budget kernel, and failure-policy proof surface for future actor-style ownership. | `Keep local model` | Keep local until the crate owns a real actor/owned-worker topology that needs runtime supervision semantics (`bd-1now.7`). | Restart/escalation docs and operator expectations could diverge from the actual failure behavior of the live runtime seam. | `scripts/check_supervision_tree.py`, `tests/test_check_supervision_tree.py`, `crates/franken-node/tests/supervision_temporal_kernel.rs`, `artifacts/section_10_11/bd-3he/`, `artifacts/replacement_gap/bd-18sp/` |
| `crates/franken-node/src/runtime/region_tree.rs` | `region_ownership_scope` | Hierarchical region/quiescence tree for runtime-side modeling and deterministic close-order behavior. | `Keep local model` | Do not let it become a second canonical region kernel. Revisit only if the runtime seam starts using it as the real owner of live tasks. | Contributors could treat `runtime/region_tree.rs` and `connector/region_ownership.rs` as competing runtime authorities and silently split shutdown semantics. | `scripts/check_region_tree_topology.py`, `tests/test_check_region_tree_topology.py`, `docs/specs/region_tree_topology.md` |
| `crates/franken-node/src/connector/perf_budget_guard.rs` and `crates/franken-node/src/policy/perf_budget_guard.rs` | Scheduler/lane hot-path budget discipline; no approved upstream native budget contract is imported here today | Product-facing performance budget gates, operator thresholds, and regression reporting for control-path overhead. | `Keep local model` | Keep local until upstream exposes a canonical performance-budget surface worth consuming directly. These files may govern budgets, but they must not invent a second scheduler semantics. | Performance claims become incomparable if local hot-path names or thresholds drift away from the canonical lane/control vocabulary. | `docs/specs/section_10_15/bd-1xwz_contract.md`, `artifacts/section_10_15/bd-20eg/verification_summary.md` |
| `crates/franken-node/src/connector/cancellation_protocol.rs` and `crates/franken-node/src/control_plane/cancellation_protocol.rs` | `cancellation_protocol` | Connector and control-plane REQUEST -> DRAIN -> FINALIZE contracts for high-impact workflows. | `Wrap canonical ownership` | No local semantic invention is allowed here. If an upstream adapter surface grows, these modules should collapse toward it rather than evolve independently. | Cancellation order, timeout, or leak semantics can drift from the hard runtime invariants and break cross-kernel shutdown assumptions. | `docs/specs/cancellation_protocol_contract.md`, `docs/specs/section_10_15/bd-1cs7_contract.md`, `artifacts/section_10_15/bd-1cs7/`, `docs/runbooks/cancel_timeout_incident.md` |
| `crates/franken-node/src/connector/obligation_tracker.rs` and `crates/franken-node/src/runtime/obligation_channel.rs` | `obligation_tracking` | Product-side reserve/commit/rollback tracker plus runtime obligation-channel abstractions for two-phase flows. | `Wrap canonical ownership` | Keep the local API if it helps product code, but do not introduce a second incompatible obligation lifecycle. | Partial commits, deadline/rollback handling, and replay expectations can diverge across cancellation, rollout, and incident tooling. | `docs/specs/two_phase_effects.md`, `docs/runbooks/obligation_leak_incident.md`, `artifacts/10.15/obligation_leak_oracle_report.json`, `docs/observability/asupersync_control_dashboards.md` |
| `crates/franken-node/src/control_plane/control_epoch.rs`, `crates/franken-node/src/control_plane/epoch_transition_barrier.rs`, `crates/franken-node/src/runtime/epoch_transition.rs`, and `crates/franken-node/src/runtime/epoch_guard.rs` | `epoch_validity_window` and epoch barrier semantics | Local epoch fencing, validity-window enforcement, runtime transition coordination, and epoch admission guard surfaces. | `Wrap canonical ownership` | Do not create another epoch primitive elsewhere in `franken_node`; extend these surfaces or the upstream adapter boundary only. | Split-brain epoch state, contradictory validity windows, and barrier semantics that disagree with replay/trust logic. | `docs/specs/section_10_14/bd-3hdv_contract.md`, `docs/specs/section_10_14/bd-2wsm_contract.md`, `artifacts/section_10_14/bd-3hdv/`, `artifacts/section_10_14/bd-2wsm/` |
| `crates/franken-node/src/observability/evidence_ledger.rs` and `crates/franken-node/src/policy/evidence_emission.rs` | `evidence_ledger_emission`; upstream `EvidenceLedger` through the control-plane adapter | Bounded local storage/publication sink plus policy-action evidence emission gate, not the canonical definition of proof validity. | `Keep local model` | Keep local as a product-plane sink and emission gate. Do not let it redefine what counts as canonical evidence emission or proof correctness. | The publication layer can accept, retain, or present entries that violate the upstream correctness contract, degrading replay trust and incident forensics. | `docs/specs/section_10_14/bd-2e73_contract.md`, `artifacts/section_10_14/bd-2e73/`, `docs/runbooks/evidence_ledger_divergence.md` |
| `crates/franken-node/src/remote/computation_registry.rs` | `remote_computation_registry`; `RemoteCap` gating | Product-side named catalog and dispatch gate for remote computations. | `Wrap canonical ownership` | Naming/catalog UX may stay local, but low-level execution capability semantics must remain bound to `RemoteCap` and the approved adapter boundary. | Operators can see a registry that authorizes work the capability boundary rejects, or vice versa, creating security and diagnosis confusion. | `docs/specs/section_10_14/bd-ac83_contract.md`, `artifacts/section_10_14/bd-ac83/` |
| `crates/franken-node/src/control_plane/control_lane_mapping.rs`, `crates/franken-node/src/control_plane/control_lane_policy.rs`, `crates/franken-node/src/runtime/lane_scheduler.rs`, and `crates/franken-node/src/runtime/lane_router.rs` | Lane scheduling discipline owned by the correctness/control plane | Product-facing lane maps/policies plus runtime schedulers/routers that must remain downstream of the canonical lane contract rather than inventing an independent scheduler truth. | `Wrap canonical ownership` | These files may map or route product task classes, but they must not become a second scheduler kernel with independent fairness semantics. | Task routing, starvation policy, and budget language can diverge from the canonical lane model and invalidate operator interpretation. | `docs/specs/section_10_14/bd-qlc6_contract.md`, `docs/architecture/high_impact_workflow_map.md`, `scripts/check_scheduler_lanes.py`, `tests/test_check_scheduler_lanes.py` |
| `crates/franken-node/src/api/service.rs` | Future request-region/service-boundary ownership | In-process catalog/dispatch layer that assembles route metadata, middleware, and endpoint catalogs, but does not own a real async server boundary. Endpoint reports explicitly mark the boundary as non-live and perf baselines as unavailable pending transport ownership. | `Defer until trigger` | Trigger: a real async HTTP or gRPC boundary with owned request lifecycle, cancellation, and backpressure. Until then, native request-region adoption is premature. | Premature substrate migration would create a fake service runtime and tech debt instead of solving a real ownership problem. | Code-and-doc quarantine for now: `docs/architecture/blueprint.md` plus `crates/franken-node/src/api/service.rs`. Future proof surface lands under `bd-1now.6`. |
| Any new local file that re-defines Cx/region/cancellation/obligation/epoch/lane semantics outside the sanctioned surfaces above | All canonical primitives listed in this contract frontmatter | None; this would be a second truth, not a needed product surface. | `Forbid duplicate fork` | No trigger. Extend an existing sanctioned wrapper/model or the upstream adapter instead. | Two competing semantic kernels make verification, operator docs, and future migrations incoherent. | This contract, `docs/architecture/blueprint.md`, and the follow-on anti-drift lane `bd-1now.5.2` |

### Representative Analogies For Future Classification

- `connector/region_ownership.rs` is the representative `Keep local model` case: it uses canonical vocabulary, but today it is still a local semantic/model surface rather than the owner of a live async substrate.
- `connector/cancellation_protocol.rs` is the representative `Wrap canonical ownership` case: product code can expose the contract, but it must not fork the upstream semantics.
- `api/service.rs` is the representative `Defer until trigger` case: the boundary is conceptually real but not operationally owned yet.
- "new local primitive file" is the representative `Forbid duplicate fork` case: if the existing sanctioned surfaces are insufficient, the answer is to extend them or the adapter, not create a rival kernel.

### Anti-Drift Rule Catalog

`scripts/check_ownership_violations.py` is the implementation-layer anti-drift
guard for this policy. It emits the stable rule ids below so later proof
lanes can reuse the same vocabulary instead of inventing a parallel one.

| Rule ID | Reason code | Failure condition | Required contributor action |
|---|---|---|---|
| `OWN-SEMB-001` | `SEMANTIC_BOUNDARY_CONTRACT_DRIFT` | The ownership contract is missing the semantic-twin matrix, the anti-drift rule catalog, or a sanctioned protected path that the checker expects. | Update this contract and the checker in the same change so the documented and machine-readable policy stay aligned. |
| `OWN-SEMB-002` | `UNDOCUMENTED_SEMANTIC_FAMILY` | A protected semantic-family filename appears outside the sanctioned path set documented in this contract. | Reuse or extend an existing sanctioned surface, or update the matrix/rule catalog explicitly before landing a new family member. |
| `OWN-SEMB-003` | `FORBIDDEN_INTERNAL_BOUNDARY_CROSSING` | `franken_node` imports another kernel's `*_internal` or `::internal::` modules directly. | Route through the approved public adapter/facade surface instead of reaching into internals. |
