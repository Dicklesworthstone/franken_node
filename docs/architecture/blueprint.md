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
