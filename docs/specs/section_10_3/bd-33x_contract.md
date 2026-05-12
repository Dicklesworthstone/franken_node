# bd-33x: Migration Risk Scoring Model

## Decision Rationale

Migration decisions require quantitative risk assessment. The risk scoring model takes project scan output and produces a weighted, explainable risk score that operators can use to decide whether to proceed, what to address first, and what the expected migration effort is.

## Scope

Build a migration risk scoring model with explainable features that:
1. Takes a project scan report as input
2. Computes a weighted risk score (0-100, lower is better)
3. Provides per-feature explanations for the score
4. Classifies overall migration difficulty

## Primary Implementation Surface

- `scripts/migration_risk_scorer.py` is the executable scorer implementation. It owns feature extraction, weighted score computation, difficulty classification, CLI output, and the self-test evidence emitted by `--self-test --json`.
- `scripts/check_risk_scorer.py` is the verifier for this contract. Its `SCORER-IMPL` check fails if the primary scorer implementation path is missing from this contract.
- `tests/test_check_risk_scorer.py` covers the scorer behavior and requires checked-in machine evidence to cite the primary implementation path.

## Scoring Formula

```
risk_score = Σ (weight_i × feature_i) / max_possible × 100
```

### Feature Weights

| Feature | Weight | Rationale |
|---------|--------|-----------|
| Critical API usage count | 10 | Blocks migration entirely |
| High-risk API usage count | 5 | Requires verification effort |
| Medium-risk API count | 2 | Minor migration effort |
| Native addon dependency count | 15 | Requires port or replacement |
| Unsafe API usage count | 12 | Security-sensitive, hard to migrate |
| Total dependency count | 0.5 | Complexity indicator |
| Untracked API count | 3 | Unknown compatibility |

### Difficulty Bands

| Score | Difficulty | Recommendation |
|-------|-----------|----------------|
| 0-15 | Low | Proceed with standard migration |
| 16-40 | Medium | Address high-risk items first |
| 41-70 | High | Significant effort required |
| 71-100 | Critical | Migration not recommended without major changes |

## Invariants

1. Score is deterministic for identical input.
2. Every feature contribution is explained in the output.
3. Score is bounded [0, 100].
4. Difficulty classification is consistent with score.

## References

- [bd-2a0_contract.md](bd-2a0_contract.md) — Project Scanner
- [COMPATIBILITY_BANDS.md](../../COMPATIBILITY_BANDS.md)
