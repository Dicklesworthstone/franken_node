# Section 16 Verification Summary

- Gate bead: `bd-unkm`
- Verdict: `FAIL`
- Contributions passing: `7/8`
- Publication checklist: `4/4`

## Contribution Matrix

| Bead | Criterion | Script | Unit Tests | Evidence | Overall |
|------|-----------|--------|------------|----------|---------|
| bd-f955 | Open specs are published and versioned | PASS | PASS | PASS | PASS |
| bd-2ad0 | Reproducible datasets are published | PASS | PASS | PASS | PASS |
| bd-nbh7 | Methodology publications are structured and citable | PASS | PASS | PASS | PASS |
| bd-3id1 | External red-team and independent evaluations are completed | FAIL | FAIL | PASS | FAIL |
| bd-10ee | Transparent technical reports are published | PASS | PASS | PASS | PASS |
| bd-1sgr | Report output contract is enforced | PASS | PASS | PASS | PASS |
| bd-e5cz | External replication claim contract is enforced | PASS | PASS | PASS | PASS |
| bd-33u2 | Verifier/benchmark release contract is enforced | PASS | PASS | PASS | PASS |

## Publication Checklist

| Check | Target | Measured | Required | Source | Pass |
|------|--------|----------|----------|--------|------|
| PUB-16-REPORTS | >= 3 reproducible reports | 3 | 3 | bd-1sgr publishable_report_count | PASS |
| PUB-16-REPLICATIONS | >= 2 external replications | 2 | 2 | external_replication_claims::MIN_REPLICATIONS | PASS |
| PUB-16-REDTEAM | >= 2 red-team engagements | 5 | 2 | bd-3id1 evaluation_types capacity | PASS |
| PUB-16-DATASET-DOI | >= 1 dataset publication with DOI-style identifier | 1 | 1 | bd-2ad0 + INV-BMP-CITABLE | PASS |

## Gate Checks

| Gate | Status |
|------|--------|
| GATE-16-SCRIPTS | FAIL |
| GATE-16-TESTS | FAIL |
| GATE-16-EVIDENCE | PASS |
| GATE-16-PER-CONTRIBUTION | FAIL |
| GATE-16-PUBLICATION-CHECKLIST | PASS |
| GATE-16-ALL-BEADS | FAIL |

## Gap Analysis
1. `bd-3id1` criterion 'External red-team and independent evaluations are completed' not fully satisfied. Remediation timeline: within the next release cycle (<=14 days).
