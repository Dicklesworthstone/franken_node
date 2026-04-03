# Architecture Blueprint

**Bead:** bd-k25j | **Section:** 8

## 8.1 Repository and Package Topology

| Repository | Package | Responsibility |
|-----------|---------|---------------|
| /dp/franken_engine | crates/franken-engine, crates/franken-extension-host | Runtime internals |
| /dp/franken_node | crates/franken-node | Product kernel |
| /dp/asupersync | crates/asupersync | Correctness kernel |
| /dp/frankentui | crates/frankentui | Terminal UI substrate |
| /dp/frankensqlite | crates/frankensqlite | SQLite persistence substrate |
| /dp/sqlmodel_rust | crates/sqlmodel-rust | Typed schema/query substrate |
| /dp/fastapi_rust | crates/fastapi-rust | HTTP service substrate |

## 8.2 Product Planes

### PP-01: Compatibility Plane

Node/Bun behavior surfaces and divergence governance. Manages compatibility
mode transitions, divergence receipts, and policy-visible mode gates.

**Key components:** Compatibility shim registry, divergence receipt generator,
mode transition policy engine.

### PP-02: Migration Plane

Discovery, risk scoring, automated rewrites, and rollout guidance. Provides
the one-command migration audit and risk map (IBD-02).

**Key components:** API scanner, risk scorer, rewrite engine, rollout advisor.

### PP-03: Trust Plane

Policy controls, trust cards, revocation and quarantine UX. Implements
the core trust-native product surfaces (TNS-01 through TNS-05).

**Key components:** Trust card generator, policy engine, revocation checker,
quarantine manager.

### PP-04: Ecosystem Plane

Registry integration, reputation graph, certification channels. Manages
extension trust cards and ecosystem reputation.

**Key components:** Registry adapter, reputation graph engine, certification
pipeline.

### PP-05: Operations Plane

Fleet control, audit/replay export, benchmark verifier interfaces. Provides
operational confidence at fleet scale.

**Key components:** Fleet controller, audit exporter, replay engine, verifier SDK.

## 8.3 Control Planes

### CP-01: Release Control Plane

Staged rollout with feature-policy gating. Manages release lifecycle from
canary through production with automatic rollback triggers.

### CP-02: Incident Control Plane

Replay, counterfactual simulation, and response automation. Enables
deterministic incident replay (IBD-04) and autonomous containment (TNS-05).

### CP-03: Economics Control Plane

Expected-loss and attack-cost aware policy guidance. Powers the
control-plane recommended actions with expected-loss rationale (IBD-08).

## 8.4 Three-Kernel Architecture

### Execution Kernel: franken_engine

The execution kernel owns language and runtime internals:
- JavaScript/TypeScript execution engine
- Extension host and sandboxing
- Memory management and GC integration
- Native API bindings

**Boundary rule:** franken_node NEVER reaches into engine internals.
All interaction goes through defined API surfaces.

### Correctness Kernel: asupersync

The correctness kernel owns concurrency, cancellation, and formal properties:
- Async scheduling with cancel/timed/ready lanes
- Cancellation protocol: request → drain → finalize
- Remote effects with capability gating
- Epoch-scoped transitions with barrier mediation
- Evidence ledger with deterministic trace witnesses

**Boundary rule:** asupersync primitives are used via defined integration
points (Cx, Region, Epoch), not by reaching into scheduler internals.

### Product Kernel: franken_node

The product kernel owns the user-facing product:
- Compatibility capture and divergence governance
- Migration tooling and rollout guidance
- Trust UX (trust cards, policy receipts, containment rationale)
- Ecosystem integration (registry, reputation, certification)
- Operational interfaces (fleet control, audit, replay, verification)

**Boundary rule:** franken_node orchestrates and verifies but does not
implement runtime or concurrency primitives.

## 8.5 Ten Hard Runtime Invariants

### HRI-01: Cx-First Control APIs

All high-impact async operations take `&Cx` as their first parameter.
Cx carries region membership, epoch binding, cancellation state, and
evidence context. Operations without Cx are uncontrolled.

### HRI-02: Region-Owned Lifecycle Execution

Region close implies quiescence. When a region closes, all tasks owned
by that region must complete their drain phase before the region transitions
to closed state. No orphaned tasks.

### HRI-03: Cancellation Protocol Semantics

Cancellation follows the three-phase protocol: request → drain → finalize.
Task-drop (immediate destruction without drain) is prohibited. Every
cancellation produces a cancellation receipt.

### HRI-04: Two-Phase Effects for High-Impact Operations

High-impact operations use reserve/commit with obligation guarantees.
The reserve phase acquires resources; the commit phase makes effects
visible. Failed commits trigger obligation rollback.

### HRI-05: Scheduler Lane Discipline

The scheduler maintains three lanes: Cancel (highest priority), Timed
(deadline-ordered), and Ready (FIFO). Starvation protection ensures
all lanes make progress. Lane assignment is determined by operation type.

### HRI-06: Remote Effects Contract

Remote effects are capability-gated, named, idempotent, and saga-safe.
No ambient network access. Every remote effect declares its capability
requirements and provides idempotency keys.

### HRI-07: Epoch and Transition Barriers

State transitions are epoch-scoped. Epoch boundaries are mediated by
barriers that ensure all pending operations in the current epoch complete
before the new epoch begins.

### HRI-08: Evidence-by-Default Decisions

All policy decisions, trust evaluations, and control-plane actions produce
deterministic evidence entries in the evidence ledger. Evidence includes
trace witnesses linking the decision to its inputs.

### HRI-09: Deterministic Protocol Verification Gates

Protocol conformance is verified through three gate types: lab verification
(controlled environment replay), cancellation injection (stress testing
cancellation paths), and schedule exploration (non-determinism detection).

### HRI-10: No Ambient Authority

Any ambient network, spawn, or privileged side effect is a defect.
All authority flows through explicit capability grants. Capability
grants are auditable and revocable.

## 8.6 Selective Asupersync Leverage Decision Record

**Bead:** bd-1now.1

This section records the 2026-03-09 architecture decision on whether
`franken_node` should adopt more native Asupersync machinery immediately.
The conclusion is intentionally selective:

- do not launch a crate-wide migration just because local modules use Asupersync-flavored vocabulary,
- remove dead executor scaffolding where the downside is near-zero,
- add guardrails so ambient runtime creep does not silently return,
- focus substantive runtime-ownership work on the telemetry ingestion seam,
- defer broader adoption until this crate owns a real async service boundary or an actor-style ownership topology that justifies it.

### Tokio Footprint After Bootstrap Cleanup

| Surface | Evidence | Decision Impact |
|---------|----------|-----------------|
| `Cargo.toml` | Workspace manifest still carries a shared `tokio` version slot. | Guardrail and fixture surfaces can still refer to Tokio patterns without implying that the primary crate uses Tokio at runtime. |
| `crates/franken-node/Cargo.toml` | No `tokio.workspace = true` entry remains. | `frankenengine-node` is no longer a direct Tokio consumer. |
| `crates/franken-node/src/main.rs` | Plain `fn main() -> Result<()>` entrypoint. | The dead executor shell cleanup has already landed; the CLI no longer bootstraps Tokio. |
| `crates/franken-node/src/ops/tokio_drift_checker.rs` | Guardrail logic and fixtures still scan for Tokio bootstrap/runtime patterns. | The remaining Tokio-facing work is preventative: block ambient executor reintroduction unless the documented exception path is activated. |

### Indirect Canonical Asupersync Leverage Already Present

`franken_node` is not starting from zero. The upstream execution-side adapter in
`/data/projects/franken_engine/crates/franken-engine/src/control_plane/mod.rs`
already centralizes canonical imports from the Asupersync-owned crates:

- `franken_kernel::{Budget, CapabilitySet, Cx, DecisionId, NoCaps, PolicyId, SchemaVersion, TraceId}`
- `franken_decision::{DecisionContract, DecisionOutcome, EvalContext, FallbackPolicy, LossMatrix, Posterior}`
- `franken_evidence::{EvidenceLedger, EvidenceLedgerBuilder}`

That changes the adoption strategy. `franken_node` already benefits from the
canonical correctness/control substrate indirectly through `franken_engine`, so
additional node-side migration must clear a higher bar than "this looks like an
Asupersync concept."

## 8.7 Runtime Seam Classification And Adoption Boundaries

### Surface Classification

| Class | Files | Why It Belongs Here | Adoption Stance |
|------|-------|---------------------|-----------------|
| Live runtime seam | `crates/franken-node/src/ops/telemetry_bridge.rs`, `crates/franken-node/src/ops/engine_dispatcher.rs` | This is the one place the crate owns long-lived background work: `thread::spawn`, nested per-connection threads, Unix socket ingestion, and `Arc<Mutex<FrankensqliteAdapter>>` with no explicit stop/join contract. | Primary immediate refactor candidate for selective Asupersync leverage. |
| Local semantic/model layer | `crates/franken-node/src/connector/region_ownership.rs`, `crates/franken-node/src/connector/supervision.rs`, `crates/franken-node/src/runtime/region_tree.rs` | These files model region ownership, supervision, quiescence, and deterministic lifecycle semantics, but they are mostly invariant/spec/data-structure surfaces rather than live async runtime boundaries. | Keep local unless semantic drift from canonical upstream adapters becomes costly or a real runtime topology appears underneath them. |
| Skeleton/future service boundary | `crates/franken-node/src/api/service.rs` | The file assembles route metadata, middleware, metrics, and endpoint catalogs, and now reports itself explicitly as an in-process catalog/dispatch layer. It still does not own a live async HTTP or gRPC boundary, and perf baselines are intentionally marked unavailable until that trigger exists. | Defer native Asupersync request-region/service-boundary migration until the service becomes real. |
| Bootstrap guardrail | `crates/franken-node/src/main.rs`, `crates/franken-node/src/ops/tokio_drift_checker.rs` | The ambient Tokio bootstrap has already been removed from the CLI, but the crate still carries an explicit guardrail against reintroducing it without a documented exception path. | Keep the guardrail in place; only reintroduce Tokio through the runtime guardrail exception path below. |

### Implementation Graph And Current Status

| Bead | Purpose | Why Now |
|------|---------|---------|
| `bd-1now.2` | Remove dead Tokio bootstrap from `frankenengine-node` CLI | Completed: `main.rs` is synchronous and the product crate no longer declares a direct Tokio dependency. |
| `bd-1now.3` | Add guardrail against ambient Tokio/runtime reintroduction | Completed: guardrail code and verification now keep Tokio/bootstrap as an explicit future exception path. |
| `bd-1now.4` | TelemetryBridge selective Asupersync adoption cluster | Highest-leverage seam for ownership, backpressure, shutdown, and supervision improvements. |
| `bd-1now.5` | Decide local semantic twin policy versus canonical upstream adapters | Prevents semantic drift between local model layers and the upstream canonical control-plane substrate. |

The row-level semantic-twin policy for `bd-1now.5` lives in
`docs/architecture/tri_kernel_ownership_contract.md` under
`Semantic Twin Inventory And Classification Matrix` (`bd-1now.5.1`). Future
boundary or anti-drift work should extend that matrix and its proof surfaces
instead of creating a second policy table here.

### Deferred Trigger Conditions

| Bead | Trigger Condition | Why Deferred |
|------|-------------------|--------------|
| `bd-1now.6` | A real async HTTP or gRPC server boundary lands in `franken_node` | Native Asupersync request-region APIs are premature until this crate owns a live service boundary. |
| `bd-1now.7` | A concrete actor-style ownership topology appears with restart, mailbox, or reply obligations | Replacing local mutex/singleton state with actor-style ownership only makes sense when the concurrency topology demands it. |

### Widening Criteria

Future contributors must not widen Asupersync adoption unless the target surface
meets all of the following:

1. The surface owns real long-lived work, backpressure, shutdown, restart, or reply obligations.
2. The surface is not already receiving the needed guarantees indirectly through the upstream `franken_engine` adapter boundary.
3. The migration yields a concrete correctness, robustness, or performance win that can be stated plainly.
4. The work does not merely replace a local semantic model with a runtime substrate for aesthetic consistency.
5. The resulting ownership boundary remains clearer, not blurrier, than the current three-kernel split.

### Runtime Guardrail Exception Path

The Tokio/bootstrap guardrail introduced under `bd-1now.3` is intentionally
strict: `franken_node` must not regain ambient executor scaffolding by default.
If a future change introduces a real async boundary and needs a Tokio bootstrap
or direct runtime builder in this crate, all of the following must happen in
the same implementation cluster:

1. Update this decision record to name the new boundary, its owner, and why an ambient executor is now justified.
2. Update `scripts/check_tokio_bootstrap_guardrail.py` with an intentional exception entry for the exact source file and rationale; do not use a broad wildcard or a silent bypass.
3. Land matching proof in the guardrail verification lane (`bd-1now.3.2` or its successor), including both a failing forbidden-case fixture and an allowed-case fixture for the newly approved boundary.

## 8.8 Five Alignment Contracts

### AC-01: Scope Boundary

franken_node defines policy, orchestration, and verification. Engine
internals stay in franken_engine. Concurrency primitives stay in asupersync.

### AC-02: Terminology

"Extension" is the primary user-facing entity. "Connector" and "provider"
are internal terms that map to extension integration classes.

### AC-03: Dual-Oracle

L1 product oracle compares Node/Bun/franken_node external behavior.
L2 engine boundary oracle verifies runtime integrity properties beyond
surface compatibility.

### AC-04: Path Convention

`src/` paths are crate-root relative. `docs/` paths are repo-root relative.
Test fixtures use `tests/fixtures/` relative to the test file.

### AC-05: KPI Clarity

Primary KPI is migration-friction collapse with safety and verifier-backed
trust guarantees. Secondary KPIs measure compatibility coverage, security
improvement, and operational confidence.

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| ARC-001 | info | Architecture compliance verified |
| ARC-002 | error | Kernel boundary violation detected |
| ARC-003 | error | Runtime invariant violation detected |
| ARC-004 | error | Alignment contract violation detected |

## Invariants

| ID | Statement |
|----|-----------|
| INV-ARC-KERNEL | Three-kernel boundaries are enforced by CI |
| INV-ARC-HRI | All 10 runtime invariants have conformance tests |
| INV-ARC-ALIGN | All 5 alignment contracts are enforceable |
| INV-ARC-PLANE | All 5 product planes have defined interfaces |
