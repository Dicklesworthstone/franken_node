# ADR-001: Hybrid Baseline Strategy

**Status**: Accepted
**Date**: 2025-01-15
**Deciders**: Repository maintainer (Dicklesworthstone)
**Relates to**: PLAN Section 3.3, Charter Section 1, Section 10.1

## Context

franken_node must establish a build strategy for achieving Node.js/Bun API compatibility while delivering trust-native capabilities (revocation-first execution, deterministic replay, policy-visible compatibility). Two viable paths exist:

**Path A — Bun-first clone**: Clean-room reimplementation following Bun's source structure. Produces familiar architecture quickly but creates lock-in to legacy runtime design patterns, blocking trust-native differentiators.

**Path B — Spec-first hybrid**: Extract behavioral specifications from Node/Bun as oracle targets, implement natively on franken_engine + asupersync with franken_node trust architecture from day one. Higher upfront specification effort but preserves the design space for category-defining features.

## Decision

**Adopt Path B: Spec-first hybrid with native implementation.**

Use Node and Bun as behavioral reference systems and oracle targets, NOT as architecture templates. Execute spec-first compatibility capture for prioritized high-value API/runtime bands. Implement product/runtime behavior natively on franken_engine + asupersync with franken_node trust/migration architecture from day one.

## Rules Codified

### Rule 1: No Bun-First Clone
A Bun-first clone path is explicitly off-charter. franken_node will not replicate the internal architecture of Bun, Node.js, or any existing runtime. Legacy runtimes are reference oracles, not implementation blueprints.

### Rule 2: Spec-First Extraction Discipline
All compatibility work must follow the Spec-First Essence Extraction Protocol:
1. Extract behavior into explicit specs (data shapes, invariants, defaults, errors, edge cases)
2. Capture Node/Bun fixture outputs as conformance baselines
3. Implement from spec + fixture contracts — not from legacy source structure

### Rule 3: Native Implementation Required
All runtime behavior is implemented natively on franken_engine + asupersync. No binding-based execution core (no `rusty_v8`, `rquickjs`, or equivalent). Compatibility shims must be explicit, typed, and policy-visible.

### Rule 4: Line-by-Line Translation Forbidden
Legacy code is input to specification and oracle generation, not an implementation blueprint. Line-by-line translation from Bun/Node source is a policy violation. Compatibility PRs must cite spec sections and fixture IDs, not source file references.

### Rule 5: Fixture-Oracle Validation
The L1 lockstep oracle (Node/Bun/franken_node) validates behavioral conformance. Implementation correctness is measured against spec + fixture contracts, not source-level similarity.

### Rule 6: Trust-Native From Day One
Category-defining differentiators (impossible-by-default execution, cryptographic provenance, verifiable migration) are architectural requirements from the start, not features added later. The baseline strategy must preserve the design space for these capabilities.

## Consequences

### Positive
- Avoids architecture lock-in to legacy runtime patterns
- Preserves native trust-primitive design space (ATC, DGIS, BPET, VEF)
- Enables impossible-by-default capabilities as first-class citizens
- Compatibility is measured objectively against spec + fixture contracts

### Constraints
- Requires upfront specification effort for each compatibility band
- Cannot mechanically port legacy source — specification extraction is mandatory
- Mandates fixture-oracle validation infrastructure

### Governance Enforcement
- CI gates block PRs that lack spec/fixture references
- Implementation-governance policy (bd-1pc) forbids line-by-line legacy translation
- Claim-language policy (bd-1mj) requires verifier artifacts for all compatibility claims

## References

- [PLAN_TO_CREATE_FRANKEN_NODE.md](../plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 3.3 — Baseline Build Strategy Decision
- [PLAN_TO_CREATE_FRANKEN_NODE.md](../plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 5.4 — Spec-First Essence Extraction Protocol
- [PRODUCT_CHARTER.md](../PRODUCT_CHARTER.md) Section 1 — Category-Creating Doctrine
- [PRODUCT_CHARTER.md](../PRODUCT_CHARTER.md) Section 10 — Off-Charter Behaviors
- [ENGINE_SPLIT_CONTRACT.md](../ENGINE_SPLIT_CONTRACT.md) — Engine split boundary
