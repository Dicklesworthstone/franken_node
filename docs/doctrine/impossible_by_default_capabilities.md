# Impossible-by-Default Capability Index

**Bead:** bd-2hrg | **Section:** 3.2

## Purpose

These 10 capabilities define what franken_node can do that incumbent runtimes
(Node.js, Bun) CANNOT do by default. Every capability must be productionized
with verifiable evidence. If users can replicate the outcome with a thin wrapper
around Node/Bun defaults, the capability is insufficient.

## The 10 Capabilities

### IBD-01: Policy-Visible Compatibility with Divergence Receipts

**Owner tracks:** 10.2, 10.5

Every compatibility shim in franken_node is typed, auditable, and policy-gated.
When franken_node's behavior diverges from Node/Bun in a compatibility surface,
a structured divergence receipt is emitted containing the exact behavior difference,
the policy decision that allowed it, and the compatibility mode active at the time.

**Why impossible in Node/Bun:** Node/Bun have no concept of policy-gated
compatibility surfaces. Behavior differences are undocumented implementation details.

### IBD-02: One-Command Migration Audit and Risk Map

**Owner tracks:** 10.3, 10.12

A single command analyzes a Node/Bun project and produces a structured risk map
showing: which APIs are fully compatible, which have known divergences, which
require migration work, and a recommended migration sequence with rollout guidance.

**Why impossible in Node/Bun:** Node/Bun have no migration tooling because
they are the incumbent. Cross-runtime migration analysis requires understanding
of both source and target runtime semantics.

### IBD-03: Signed Policy Checkpoints and Revocation-Aware Gates

**Owner tracks:** 10.13, 10.10

Every execution gate checks revocation status before allowing code to run.
Policy checkpoints are cryptographically signed, creating a tamper-evident
chain of trust decisions. Stale revocation data triggers degraded mode, not
silent bypass.

**Why impossible in Node/Bun:** Node/Bun have no concept of execution-time
revocation checks or signed policy checkpoints.

### IBD-04: Deterministic Incident Replay with Counterfactual Simulation

**Owner tracks:** 10.5, 10.17

High-severity security incidents produce signed receipts that enable full-fidelity
deterministic replay. Operators can re-run the incident with different policy
parameters (counterfactual simulation) to evaluate alternative responses.

**Why impossible in Node/Bun:** Node/Bun have no deterministic replay
infrastructure. Incident analysis relies on log files and memory.

### IBD-05: Fleet Quarantine with Bounded Convergence Guarantees

**Owner tracks:** 10.8, 10.20

When a security threat is detected, quarantine propagates across the entire fleet
with mathematically bounded convergence time. Operators see real-time blast-radius
views and convergence indicators with rollback controls.

**Why impossible in Node/Bun:** Node/Bun instances are independent processes
with no fleet-level coordination or quarantine propagation.

### IBD-06: Extension Trust Cards

**Owner tracks:** 10.4, 10.21

Every extension has a trust card combining provenance data (publisher, signatures,
build reproducibility), runtime behavior observations, and revocation state into
a single explainable trust model readable by both humans and automation.

**Why impossible in Node/Bun:** npm/Bun package metadata is limited to author
and version. No behavioral trust scoring or revocation integration.

### IBD-07: Compatibility Lockstep Oracle

**Owner tracks:** 10.2 (Layer 1), 10.17 (Layer 2)

A dual-layer oracle that compares franken_node behavior against Node and Bun
simultaneously. Layer 1 verifies external API behavior parity. Layer 2 verifies
runtime integrity properties that go beyond surface compatibility.

**Why impossible in Node/Bun:** Incumbents have no cross-runtime comparison
infrastructure. Compatibility is assumed, not verified.

### IBD-08: Control-Plane Recommended Actions with Expected-Loss Rationale

**Owner tracks:** 10.5, 10.17

When the control plane recommends an action (rollback, quarantine, upgrade),
it provides expected-loss rationale: VOI-based ranking of alternatives, confidence
intervals, and deterministic rollback commands for each option.

**Why impossible in Node/Bun:** Node/Bun have no control plane. Operational
decisions are made by humans without decision-theoretic support.

### IBD-09: Ecosystem Reputation Graph with Trust Transitions

**Owner tracks:** 10.4, 10.19, 10.21

A Bayesian adversary graph that models publisher reputation, package dependency
trust propagation, and federated intelligence from multiple deployments. Trust
transitions are explainable and auditable.

**Why impossible in Node/Bun:** npm's trust model is binary (published/unpublished).
No reputation graph, no trust propagation, no federated intelligence.

### IBD-10: Public Verifier Toolkit

**Owner tracks:** 10.17, 10.14

A universal verifier SDK that allows third parties to independently verify
franken_node's security and compatibility claims. Includes replay capsules,
a claim compiler, and a public trust scoreboard.

**Why impossible in Node/Bun:** Node/Bun make no verifiable claims. Their
security posture cannot be independently audited with standardized tools.

## Category-Creation Test

Every capability must pass three tests:

### Uniqueness Test

If users can get the same outcomes with a thin wrapper around Node/Bun defaults,
the feature is insufficient. The capability must require franken_node's trust-native
architecture to function.

### Verifiability Test

If claims cannot be independently verified using the public verifier toolkit
(IBD-10), the feature is insufficient. Every capability must produce verifiable
evidence artifacts.

### Migration Test

If migration cost remains high for real teams, the feature is insufficient.
Each capability must be accessible without requiring a complete runtime migration.

## Quantitative Targets

| ID | Target | Threshold | Measurement |
|----|--------|-----------|-------------|
| QT-01 | Compatibility corpus pass rate | >= 95% | Automated corpus test suite |
| QT-02 | Migration throughput vs baseline | >= 3x | Migration time comparison study |
| QT-03 | Host compromise reduction | >= 10x | Adversarial extension campaign simulation |
| QT-04 | Incident replay availability | 100% | High-severity event replay verification |
| QT-05 | Adopted impossible capabilities | >= 3 | Production usage telemetry |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| IBD-001 | info | Capability index audit completed |
| IBD-002 | error | Capability missing implementation mapping |
| IBD-003 | info | Capability evidence verified |
| IBD-004 | error | Capability fails category-creation test |

## Invariants

| ID | Statement |
|----|-----------|
| INV-IBD-MAPPED | All 10 capabilities map to active implementation beads |
| INV-IBD-EVIDENCE | Each capability has reproducible evidence artifacts |
| INV-IBD-UNIQUE | Each capability passes the category-creation uniqueness test |
| INV-IBD-COMPLETE | No capability silently dropped by scope erosion |
