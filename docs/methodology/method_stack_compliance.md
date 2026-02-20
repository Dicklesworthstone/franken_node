# Method Stack Compliance — Reference Guide

**Bead:** bd-22e7 | Section: 5

## Purpose

This document defines the four mandatory execution disciplines for all franken_node
implementation work. Every PR must cite which method stack(s) it follows, and each
stack has specific artifact requirements that must be satisfied.

## Method Stacks

### MS-01: extreme-software-optimization

**Domain:** Performance-sensitive changes
**Required for:** Sections 10.6, 10.14, 10.15, 10.17, 10.18

**Mandatory loop:**

1. **Baseline** — Capture p50/p95/p99 latency, throughput, memory footprint, and cold-start time
2. **Profile** — Identify top hotspots (flamegraph or equivalent)
3. **Prove** — Demonstrate behavior invariance and compatibility envelopes are preserved
4. **Implement** — Apply one optimization lever per cycle
5. **Verify** — Confirm compatibility/security artifacts still pass
6. **Re-profile** — Measure improvement against baseline

**Required artifacts:**
- Before/after benchmark results (CSV or JSON)
- Flamegraph evidence (SVG or folded stacks)
- Compatibility envelope proof (test results showing no regression)

**Compliance check:** `MSC-001:MS-01` — Verify baseline + re-profile artifacts exist.

### MS-02: alien-artifact-coding

**Domain:** Product control surfaces and decision points
**Required for:** Sections 10.5, 10.17, 10.19, 10.20, 10.21

**Decision systems:**
- Expected-loss rollout choices with quantified risk
- Posterior trust state updates using Bayesian or equivalent framework
- Confidence-aware migration recommendations with calibrated uncertainty
- Explainable policy decisions with human-readable receipts

**Required artifacts:**
- Formal decision rationale (JSON with loss function, alternatives, chosen action)
- Policy receipt showing inputs → decision → justification chain

**Compliance check:** `MSC-001:MS-02` — Verify formal decision rationale artifact exists.

### MS-03: alien-graveyard

**Domain:** Adoption of advanced primitives
**Required for:** All 10.x tracks adopting primitives from external substrates

**Selection criteria:**
- EV thresholding: only adopt primitives with Expected Value >= 2.0
- Failure-mode predesign: every primitive must have a documented degraded-operation pathway
- Deterministic degraded operation: system must function (possibly with reduced capability) even if the primitive fails

**Required artifacts:**
- EV analysis document (primitive, EV score, justification, fallback contract)
- Degraded-mode test results showing the system operates without the primitive

**Compliance check:** `MSC-001:MS-03` — Verify EV analysis and fallback contract exist.

### MS-04: porting-to-rust

**Domain:** Compatibility surfaces
**Required for:** Sections 10.2, 10.3, 10.7

**Spec-first extraction protocol:**
1. **Extract** — Convert legacy behavior into explicit specs: data shapes, invariants, defaults, errors, edge cases
2. **Capture** — Run Node/Bun fixture outputs as conformance baselines
3. **Implement** — Build from spec and fixture contracts, NOT from legacy source structure
4. **Enforce** — Use lockstep oracle + artifact gates to detect parity/divergence

**RULE:** Legacy code is input to specification and oracle generation, NOT an implementation blueprint. Line-by-line translation is explicitly prohibited (constraint C-09).

**Required artifacts:**
- Spec reference (conformance spec document)
- Fixture IDs (test fixture identifiers mapped to Node/Bun baselines)
- Parity report (lockstep oracle comparison results)

**Compliance check:** `MSC-001:MS-04` — Verify spec reference and fixture IDs exist.

## Compliance Matrix

The compliance matrix maps each execution track to its required method stacks:

| Section | MS-01 (Perf) | MS-02 (Decision) | MS-03 (Primitive) | MS-04 (Compat) |
|---------|:---:|:---:|:---:|:---:|
| 10.2 | | | | REQUIRED |
| 10.3 | | | | REQUIRED |
| 10.4 | | | APPLICABLE | |
| 10.5 | | REQUIRED | | |
| 10.6 | REQUIRED | | | |
| 10.7 | | | | REQUIRED |
| 10.14 | REQUIRED | | APPLICABLE | |
| 10.15 | REQUIRED | | APPLICABLE | |
| 10.16 | | | APPLICABLE | |
| 10.17 | REQUIRED | REQUIRED | | |
| 10.18 | REQUIRED | | | |
| 10.19 | | REQUIRED | | |
| 10.20 | | REQUIRED | | |
| 10.21 | | REQUIRED | | |

## PR Compliance Checklist

Every PR description must include:

```
## Method Stack Compliance
- [ ] Stack(s): MS-XX (list applicable stacks)
- [ ] Artifacts: (list artifact locations)
- [ ] Verification: (link to check script output)
```

## Event Codes

| Code | Meaning |
|------|---------|
| MSC-001 | Compliance check passed (with stack ID suffix) |
| MSC-002 | Compliance violation detected |
| MSC-003 | Method stack citation found in PR description |
| MSC-004 | Missing required artifact for the cited method stack |

## Invariants

| ID | Statement |
|----|-----------|
| INV-MSC-CITED | Every PR cites which method stack(s) it follows |
| INV-MSC-ARTIFACT | Performance PRs include before/after benchmark artifacts |
| INV-MSC-FORMAL | Decision-surface PRs include formal decision rationale |
| INV-MSC-SPEC-FIRST | Compatibility PRs reference specs and fixture IDs, not legacy source |
