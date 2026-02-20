# bd-22e7: Method Stack Compliance

**Section:** 5 — Execution Disciplines
**Type:** Cross-Cutting Methodology
**Status:** In Progress

## Four Mandatory Method Stacks

| Stack | ID | Domain | Required For |
|-------|----|--------|-------------|
| extreme-software-optimization | MS-01 | Performance | 10.6, 10.14, 10.15, 10.17, 10.18 |
| alien-artifact-coding | MS-02 | Decision Surfaces | 10.5, 10.17, 10.19, 10.20, 10.21 |
| alien-graveyard | MS-03 | Primitive Selection | All 10.x adopting advanced primitives |
| porting-to-rust | MS-04 | Compatibility | 10.2, 10.3, 10.7 |

## Compliance Requirements

### MS-01: Performance Discipline
- Baseline: p50/p95/p99 + throughput + memory + cold start
- Profile → prove invariance → implement → verify → re-profile
- Artifact: before/after benchmark evidence

### MS-02: Mathematical Decision Core
- Expected-loss rollout choices
- Posterior trust state updates
- Confidence-aware migration recommendations
- Artifact: formal decision rationale

### MS-03: High-EV Primitive Selection
- EV thresholding (EV >= 2.0)
- Failure-mode predesign
- Deterministic degraded operation pathways
- Artifact: EV analysis + fallback contract

### MS-04: Spec-First Essence Extraction
- Extract behavior specs from legacy code
- Capture conformance baselines from Node/Bun fixtures
- Implement from spec, NOT from legacy source
- Artifact: spec reference + fixture IDs

## Event Codes

- `MSC-001`: Method stack compliance check passed
- `MSC-002`: Method stack compliance violation
- `MSC-003`: Method stack citation found in PR
- `MSC-004`: Missing required artifact for method stack

## Invariants

- `INV-MSC-CITED`: Every PR cites applicable method stack(s)
- `INV-MSC-ARTIFACT`: Performance PRs include before/after artifacts
- `INV-MSC-FORMAL`: Decision-surface PRs include formal rationale
- `INV-MSC-SPEC-FIRST`: Compatibility PRs reference specs, not legacy source

## Artifacts

- Method stack doc: `docs/methodology/method_stack_compliance.md`
- Compliance matrix: `docs/methodology/compliance_matrix.json`
- Verification: `scripts/check_method_stack_compliance.py`
- Tests: `tests/test_check_method_stack_compliance.py`
