# bd-2hrg: Impossible-by-Default Capability Index

**Section:** 3.2 — Category Differentiators
**Type:** Epic (Capability Index)
**Status:** In Progress

## The 10 Impossible-by-Default Capabilities

| ID | Capability | Owner Tracks |
|----|-----------|-------------|
| IBD-01 | Policy-visible compatibility with divergence receipts | 10.2, 10.5 |
| IBD-02 | One-command migration audit and risk map | 10.3, 10.12 |
| IBD-03 | Signed policy checkpoints and revocation-aware gates | 10.13, 10.10 |
| IBD-04 | Deterministic incident replay with counterfactual sim | 10.5, 10.17 |
| IBD-05 | Fleet quarantine with bounded convergence | 10.8, 10.20 |
| IBD-06 | Extension trust cards (provenance + behavior + revocation) | 10.4, 10.21 |
| IBD-07 | Compatibility lockstep oracle across runtimes | 10.2, 10.17 |
| IBD-08 | Control-plane actions with expected-loss rationale | 10.5, 10.17 |
| IBD-09 | Ecosystem reputation graph with trust transitions | 10.4, 10.19, 10.21 |
| IBD-10 | Public verifier toolkit for claims | 10.17, 10.14 |

## Category-Creation Test

| Test | Pass Criterion |
|------|---------------|
| Uniqueness | Cannot replicate with thin Node/Bun wrapper |
| Verifiability | Claims independently verifiable |
| Migration | Real teams can adopt without prohibitive cost |

## Quantitative Targets

| ID | Target | Threshold |
|----|--------|-----------|
| QT-01 | Compatibility corpus pass rate | >= 95% |
| QT-02 | Migration throughput vs baseline | >= 3x |
| QT-03 | Host compromise reduction | >= 10x |
| QT-04 | Incident replay availability | 100% |
| QT-05 | Adopted impossible capabilities | >= 3 |

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

## Artifacts

- Capability index doc: `docs/doctrine/impossible_by_default_capabilities.md`
- Spec contract: `docs/specs/section_3_2/bd-2hrg_contract.md`
- Verification: `scripts/check_impossible_capabilities.py`
- Tests: `tests/test_check_impossible_capabilities.py`
