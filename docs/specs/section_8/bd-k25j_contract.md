# bd-k25j: Architecture Blueprint

**Section:** 8 — Architecture
**Type:** Architecture Document
**Status:** In Progress

## Three-Kernel Architecture (8.4)

| Kernel | Repository | Responsibility |
|--------|-----------|---------------|
| Execution | /dp/franken_engine | Language/runtime internals |
| Correctness | /dp/asupersync | Concurrency, cancellation, remote effects, epochs |
| Product | /dp/franken_node | Compatibility, migration, trust UX, ecosystem |

## 5 Product Planes (8.2)

| ID | Plane | Domain |
|----|-------|--------|
| PP-01 | Compatibility | Node/Bun behavior and divergence governance |
| PP-02 | Migration | Discovery, risk scoring, rewrites, rollout |
| PP-03 | Trust | Policy controls, trust cards, revocation |
| PP-04 | Ecosystem | Registry, reputation graph, certification |
| PP-05 | Operations | Fleet control, audit/replay, verifier interfaces |

## 3 Control Planes (8.3)

| ID | Plane | Domain |
|----|-------|--------|
| CP-01 | Release | Staged rollout, rollback, feature-policy gating |
| CP-02 | Incident | Replay, counterfactual simulation, response |
| CP-03 | Economics | Expected-loss and attack-cost policy guidance |

## 10 Hard Runtime Invariants (8.5)

| ID | Invariant |
|----|-----------|
| HRI-01 | Cx-first control APIs |
| HRI-02 | Region-owned lifecycle execution |
| HRI-03 | Cancellation protocol semantics |
| HRI-04 | Two-phase effects for high-impact ops |
| HRI-05 | Scheduler lane discipline |
| HRI-06 | Remote effects contract |
| HRI-07 | Epoch and transition barriers |
| HRI-08 | Evidence-by-default decisions |
| HRI-09 | Deterministic protocol verification gates |
| HRI-10 | No ambient authority |

## 5 Alignment Contracts (8.8)

| ID | Contract |
|----|----------|
| AC-01 | Scope boundary: franken_node = policy/orchestration/verification |
| AC-02 | Terminology: "extension" is primary entity |
| AC-03 | Dual-oracle: L1 product + L2 engine boundary |
| AC-04 | Path convention: src/ crate-relative, docs/ repo-relative |
| AC-05 | KPI: migration-friction collapse with safety guarantees |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| ARC-001 | info | Architecture compliance verified |
| ARC-002 | error | Kernel boundary violation |
| ARC-003 | error | Runtime invariant violation |
| ARC-004 | error | Alignment contract violation |

## Invariants

| ID | Statement |
|----|-----------|
| INV-ARC-KERNEL | Three-kernel boundaries enforced by CI |
| INV-ARC-HRI | All 10 runtime invariants have conformance tests |
| INV-ARC-ALIGN | All 5 alignment contracts are enforceable |
| INV-ARC-PLANE | All 5 product planes have defined interfaces |

## Artifacts

- Architecture doc: `docs/architecture/blueprint.md`
- Spec contract: `docs/specs/section_8/bd-k25j_contract.md`
- Verification: `scripts/check_architecture_blueprint.py`
- Tests: `tests/test_check_architecture_blueprint.py`
