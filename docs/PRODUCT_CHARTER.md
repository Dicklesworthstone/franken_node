# franken_node Product Charter

> Canonical scope boundary, governance model, and decision rules for the franken_node runtime platform.
> This document is the authoritative reference for what franken_node is, what it is not, and how decisions about its direction are made.

**Charter Version:** 1.1 (ratified)
**Effective Date:** 2026-02-20
**Owner:** Repository maintainer (`Dicklesworthstone`)
**Canonical Plan:** [`PLAN_TO_CREATE_FRANKEN_NODE.md`](plans/PLAN_TO_CREATE_FRANKEN_NODE.md)
**Engine Plan Alignment:** [`PLAN_TO_CREATE_FRANKEN_ENGINE.md`](/dp/franken_engine/PLAN_TO_CREATE_FRANKEN_ENGINE.md)

### Ratification Log

| Version | Date | Change | Bead |
|---------|------|--------|------|
| 1.0 | 2026-02-20 | Initial charter created | bd-2nd |
| 1.1 | 2026-02-20 | Ratified as canonical 10.1 artifact; engine plan alignment verified; governance cross-reference matrix added | bd-vjq |

---

## 1. Product Purpose

franken_node is a **trust-native JavaScript/TypeScript runtime platform** for extension-heavy systems. It combines Node/Bun ecosystem migration velocity with deterministic security controls, cryptographically-grounded trust operations, and replayable incident forensics.

The product layer sits atop [`franken_engine`](../../franken_engine/) and converts engine breakthroughs into mass adoption surfaces for a new runtime category: **zero-illusion trust operations with JS/TS ecosystem speed**.

### Core Proposition (Three Pillars)

| Pillar | Commitment |
|--------|------------|
| **Compatibility is table stakes** | Node/Bun-level ergonomics with >= 95% pass on targeted compatibility corpus |
| **Trust-native operations are the differentiator** | Impossible-by-default capabilities that incumbent runtimes cannot provide |
| **Migration velocity is the growth engine** | >= 3x migration throughput/confidence vs. baseline patterns |

### What franken_node Is

- A product surface for trust-native runtime behavior (policy gates, revocation-first execution, quarantine controls)
- A migration system (audit, rewrite, validate, rollout) for Node/Bun codebases
- A compatibility capture layer with lockstep oracle validation
- An extension ecosystem with provenance, trust cards, and reputation scoring
- An incident forensics platform with deterministic replay and counterfactual simulation
- A fleet governance control plane for quarantine, release, and convergence operations

### What franken_node Is Not

- A general-purpose JavaScript engine (that is `franken_engine`)
- A binding/wrapper around V8, QuickJS, or any existing engine
- A compatibility-only Node/Bun clone (compatibility is a wedge, not the destination)
- A security theater layer that adds decorative controls without measurable behavior

---

## 2. Scope Boundary: franken_node vs franken_engine

This boundary is enforced by the [Engine Split Contract](ENGINE_SPLIT_CONTRACT.md) and the duplicate-implementation CI gate.

### franken_engine Owns

- Native runtime internals (VM, parser, AST, interpreter, GC)
- Policy semantics and trust primitives at the VM level
- Bayesian sentinel inference and containment actions
- Native Rust execution (no V8/QuickJS bindings)

### franken_node Owns

- Compatibility capture from Node/Bun ecosystems
- Migration and operator experience (audit, rewrite, validate, rollout)
- Extension ecosystem and trust distribution (registry, trust cards, reputation)
- Packaging, rollout, and enterprise control planes
- Product-layer policy controls and verification surfaces
- L1 Product Oracle (compatibility semantics vs. Node/Bun)
- Fleet operations (quarantine, incident replay, convergence)

### Hard Boundary Rules

1. `franken_node` consumes engine crates from `/dp/franken_engine` via path dependencies.
2. No local reintroduction of `franken-engine` or `franken-extension-host` crates in this repository.
3. Product behavior changes that require engine internals must land in `franken_engine` first.
4. `franken_node` may ship on a different cadence but must pin and validate an explicit engine revision.
5. Ownership violations are caught by the [Capability Ownership Registry](CAPABILITY_OWNERSHIP_REGISTRY.md) and the duplicate-implementation CI gate.

---

## 3. Target Users

### Developer Teams

JavaScript/TypeScript teams deploying extension-heavy systems who need rapid ecosystem velocity without security compromise. Pain point: incompatibility friction and trust ambiguity across extension updates.

### Operations/SRE Teams

Platform operators managing fleet-scale extension governance who need deterministic incident replay, revocation controls, and risk-aware decision support. Pain point: supply-chain uncertainty, incident investigation chaos, manual policy tuning.

### Security/Compliance Teams

Security engineers and compliance auditors who need verifiable claims, behavioral transparency, and cryptographic auditability. Pain point: black-box runtime decisions, weak provenance controls, incident non-determinism.

---

## 4. Non-Negotiable Requirements

### Substrate Dependencies (Mandatory)

| Substrate | Role | Contract |
|-----------|------|----------|
| `/dp/asupersync` | Control/correctness semantics | Cx-first, region-owned, cancel-correct, obligation-tracked |
| `/dp/frankentui` | Console/TUI surfaces | All operator-facing output routes through frankentui |
| `/dp/frankensqlite` | Persistence, audit, replay | All durable state and evidence goes through frankensqlite |
| `/dp/sqlmodel_rust` | Typed schema/model integration | Schema-first persistence layer |
| `/dp/fastapi_rust` | Control-plane API exposure | All external API surfaces route through fastapi_rust |

### Execution Constraints

- High-impact async must be Cx-first and obligation-tracked; detached tasks are off-charter.
- Compatibility shims must be explicit, typed, and policy-visible.
- Line-by-line legacy translation from Bun/Node is off-charter.
- Dangerous compatibility must be gated by policy with auditable receipts.
- Every major claim ships with reproducible evidence artifacts.

### Strategic Constraints

- Parity-only outcomes are insufficient; if users get the same outcomes with a wrapper around Node/Bun defaults, the feature is insufficient.
- Claims that cannot be independently verified are insufficient.
- Compatibility is a strategic wedge for adoption, not the product destination.
- De-scoping is not the default answer; ambition reduction without explicit owner direction is off-charter.

---

## 5. Category-Defining Success Criteria

These metrics define whether the program is on-charter:

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Targeted compatibility corpus pass rate | >= 95% | Lockstep oracle verdicts on high-value Node/Bun usage bands |
| Migration throughput/confidence vs. baseline | >= 3x | Measured time-to-production + confidence score delta |
| Reduction in successful host compromise | >= 10x | Adversarial extension campaigns on instrumented test harness |
| Install-to-safe-workload friction | Friction-minimized | Automation-first, operator-guided path with deterministic gates |
| Deterministic replay availability | 100% | High-severity incidents have full replay bundles |
| Impossible-by-default capabilities adopted | >= 3 | Production users exercising trust-native features |

---

## 6. Impossible-by-Default Capability Index

franken_node must productionize these capabilities that Node/Bun cannot provide natively:

1. **Policy-visible compatibility behavior** with explicit divergence receipts
2. **One-command migration audit** and risk map for Node/Bun projects
3. **Signed policy checkpoints** and revocation-aware execution gates
4. **Deterministic incident replay** with counterfactual policy simulation
5. **Fleet quarantine propagation** with bounded convergence guarantees
6. **Extension trust cards** combining provenance, behavior, and revocation state
7. **Compatibility lockstep oracle** across Node/Bun/franken_node
8. **Control-plane recommended actions** with expected-loss rationale
9. **Ecosystem reputation graph** with explainable trust transitions
10. **Public verifier toolkit** for benchmark and security claims

---

## 7. Governance Model

### Decision Authority

| Decision Class | Authority | Escalation Path |
|---------------|-----------|----------------|
| Feature scope changes | Repository owner | N/A (owner is final authority) |
| Engine boundary changes | Repository owner + franken_engine alignment | Cross-repo coordination required |
| Substrate dependency additions | Repository owner | Must satisfy non-negotiable substrate doctrine |
| Capability ownership changes | Repository owner via [Capability Ownership Registry](CAPABILITY_OWNERSHIP_REGISTRY.md) | Registry update + CI gate verification |
| De-scoping or ambition reduction | Repository owner only | Not delegatable to agents or automation |

### Change Control

1. **Scope changes** must be justified against the canonical plan and this charter. Changes that reduce ambition require explicit owner approval.
2. **Boundary changes** between franken_node and franken_engine follow the [Engine Split Contract](ENGINE_SPLIT_CONTRACT.md). Neither repository may unilaterally redefine the boundary.
3. **Capability ownership** is governed by the [Capability Ownership Registry](CAPABILITY_OWNERSHIP_REGISTRY.md). Single canonical owner per capability; non-owners constrained to integration, adoption, gating, or policy roles.
4. **Evidence contracts** require every significant claim to ship with reproducible verification artifacts. Claims without evidence are not claims.

### Dual-Oracle Close Condition

Program completion requires three simultaneous green signals:

| Oracle | Scope | Owner Section |
|--------|-------|---------------|
| **L1 Product Oracle** | Product-level semantics vs. Node/Bun | 10.2 |
| **L2 Engine-Boundary Oracle** | franken_engine integration conformance | 10.17 |
| **Release Policy Linkage** | Both oracles consumed by release gates | 10.2 |

No partial success. No waivers. See [DUAL_ORACLE_CLOSE_CONDITION.md](DUAL_ORACLE_CLOSE_CONDITION.md).

---

## 8. Execution Tracks

The product plan is organized into 22 canonical execution tracks:

| Track | Domain |
|-------|--------|
| 10.0 | Top 10 initiative tracking (rollup) |
| 10.1 | Charter + split governance *(this document)* |
| 10.2 | Compatibility core, spec-first extraction, L1 oracle |
| 10.3 | Migration system (audit / rewrite / validate / rollout) |
| 10.4 | Extension ecosystem + registry |
| 10.5 | Security + policy product surfaces |
| 10.6 | Performance + packaging |
| 10.7 | Conformance + verification |
| 10.8 | Operational readiness (fleet, incidents, runbooks) |
| 10.9 | Moonshot disruption track |
| 10.10 | FCP-inspired hardening + interop |
| 10.11 | FrankenSQLite-inspired runtime systems |
| 10.12 | Frontier programs (5 core programs) |
| 10.13 | FCP deep-mined: connectors, control channels, revocation |
| 10.14 | FrankenSQLite deep-mined: evidence, epochs, remote effects |
| 10.15 | Asupersync integration: control-plane adoption |
| 10.16 | Adjacent substrate integration |
| 10.17 | Radical expansion: verifier SDK, L2 oracle, adversary |
| 10.18 | VEF: Verifiable Execution Fabric |
| 10.19 | ATC: Adversarial Trust Commons |
| 10.20 | DGIS: Dependency Graph Immune System |
| 10.21 | BPET: Behavioral Phenotype Evolution Tracker |

Tracks 11-16 cover cross-cutting concerns: evidence/decision contracts (11), risk register (12), success criteria instrumentation (13), benchmark ownership (14), ecosystem capture (15), and scientific contribution (16).

---

## 9. Methodology Stack

Four complementary disciplines govern execution quality:

| Discipline | Application |
|-----------|-------------|
| **extreme-software-optimization** | Baseline, profile, prove invariance, implement one lever, verify, re-profile |
| **alien-artifact-coding** | Expected-loss decisions, posterior trust updates, confidence-aware recommendations |
| **alien-graveyard** | EV-thresholded primitive selection (>= 2.0), failure-mode predesign |
| **porting-to-rust** (spec-first) | Extract behavior into specs, capture Node/Bun fixtures, implement from spec+fixtures |

---

## 10. Off-Charter Behaviors

The following are explicitly off-charter and constitute program violations:

- Framing de-scoping as the default answer to complexity
- Recommending parity-only outcomes as acceptable
- Treating compatibility as mission rather than strategic wedge
- Introducing engine-internal code in this repository
- Merging claims without reproducible evidence artifacts
- Accepting partial oracle closure as program completion
- Reducing ambition without explicit owner direction

---

## 11. Engine Plan Alignment Verification

This charter has been verified for consistency with the franken_engine canonical plan (`PLAN_TO_CREATE_FRANKEN_ENGINE.md`). The following alignment matrix documents the contract points between both plans.

### Alignment Matrix

| Dimension | franken_engine Plan | franken_node Charter | Status |
|-----------|-------------------|---------------------|--------|
| **Core thesis** | frankenengine is native execution substrate; franken_node is compatibility/runtime surface (Section 2) | Product layer sits atop franken_engine; converts engine breakthroughs into adoption surfaces (Section 1) | Aligned |
| **No-bindings rule** | No `rusty_v8`, `rquickjs`, or equivalent binding-based core execution (Section 4) | franken_node is not a binding/wrapper around any existing engine (Section 1) | Aligned |
| **Scope boundary** | Engine owns VM, parser, AST, interpreter, GC, policy primitives, Bayesian sentinel (Sections 2, 6) | Product owns compatibility, migration, trust UX, fleet ops, policy surfaces (Section 2) | Aligned |
| **Ambition doctrine** | Ambition reduction without owner request is off-charter (Caveat) | De-scoping as default answer is off-charter; ambition reduction requires owner direction (Sections 4, 10) | Aligned |
| **Methodology stack** | extreme-software-optimization + alien-artifact-coding + alien-graveyard (Section 5) | Same three methodologies plus porting-to-rust spec-first (Section 9) | Aligned (product adds spec-first) |
| **Evidence contracts** | Every major claim ships with artifacts (Section 4) | Claims without reproducible evidence are not claims (Section 7) | Aligned |
| **Parity constraint** | Compatibility gates valid only paired with net-new capability advantage (Section 4) | Parity-only outcomes are insufficient (Section 4) | Aligned |
| **Category creation** | Pursues new class, not best-in-class among similar tools (Section 3.1) | Zero-illusion trust operations with JS/TS ecosystem speed (Section 1) | Aligned |
| **Impossible-by-default** | 13 capabilities engine must deliver (Section 3.2) | 10 product-level capabilities that Node/Bun cannot provide (Section 6) | Aligned (engine primitives power product surfaces) |
| **Success metrics** | >= 3x throughput, >= 10x compromise reduction, <= 250ms containment, 100% replay (Section 3) | >= 95% compat, >= 3x migration, >= 10x compromise reduction, 100% replay (Section 5) | Aligned (product metrics complement engine metrics) |

### Boundary Enforcement Points

The following CI/governance mechanisms ensure the boundary stays consistent:

1. **Duplicate-implementation gate** (`scripts/check_ownership_violations.py`) - Prevents capability ownership violations
2. **Engine split contract** (`docs/ENGINE_SPLIT_CONTRACT.md`) - Enforces path dependency rules
3. **Capability ownership registry** (`docs/capability_ownership_registry.json`) - Single canonical owner per capability
4. **Dual-oracle close condition** (`docs/DUAL_ORACLE_CLOSE_CONDITION.md`) - Both product and engine oracles must be green

---

## 12. Cross-References

| Document | Relationship |
|----------|-------------|
| [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) | Canonical plan (this charter is derived from it) |
| [PLAN_TO_CREATE_FRANKEN_ENGINE.md](/dp/franken_engine/PLAN_TO_CREATE_FRANKEN_ENGINE.md) | Engine canonical plan (alignment verified in Section 11) |
| [ENGINE_SPLIT_CONTRACT.md](ENGINE_SPLIT_CONTRACT.md) | Boundary enforcement between repositories |
| [ROADMAP.md](ROADMAP.md) | Phased delivery plan (supporting summary) |
| [CAPABILITY_OWNERSHIP_REGISTRY.md](CAPABILITY_OWNERSHIP_REGISTRY.md) | Single-owner enforcement per capability |
| [DUAL_ORACLE_CLOSE_CONDITION.md](DUAL_ORACLE_CLOSE_CONDITION.md) | Program completion criteria |
| [ENGINE_ARCHITECTURE.md](ENGINE_ARCHITECTURE.md) | Engine-layer architecture reference |
| [ADR-001-hybrid-baseline-strategy.md](adr/ADR-001-hybrid-baseline-strategy.md) | Baseline build strategy decision record |
| [IMPLEMENTATION_GOVERNANCE.md](IMPLEMENTATION_GOVERNANCE.md) | PR governance for compatibility work |
