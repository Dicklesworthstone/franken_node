# bd-2igi: Bayesian Posterior Diagnostics for Explainable Policy Ranking

**Section**: 10.14
**Depends on**: bd-sddz (correctness envelope), bd-nupr (EvidenceEntry schema)

## Purpose

Provides data-driven, explainable ranking of policy action candidates using
Bayesian posterior inference. This is the "soft recommendation" layer that works
alongside hard guardrails to provide informed suggestions.

## Key Types

| Type | Role |
|------|------|
| `BayesianDiagnostics` | Core engine: update with observations, rank candidates |
| `CandidateRef` | Reference to a policy action candidate |
| `Observation` | Evidence about a candidate (success/failure with epoch) |
| `RankedCandidate` | Candidate with posterior_prob, prior_prob, confidence_interval |
| `DiagnosticConfidence` | Enum: Low, Medium, High (based on observation count) |
| `BetaState` | Internal Beta distribution state for conjugate Bayesian update |

## Invariants

- **INV-BAYES-ADVISORY**: Diagnostics never directly execute actions
- **INV-BAYES-REPRODUCIBLE**: replay_from with identical observations produces identical rankings
- **INV-BAYES-NORMALIZED**: Posterior probabilities sum to 1.0 (within tolerance)
- **INV-BAYES-TRANSPARENT**: Every RankedCandidate includes full posterior_prob, prior_prob, observation_count, and confidence_interval

## Event Codes

| Code | Meaning |
|------|---------|
| EVD-BAYES-001 | Posterior update |
| EVD-BAYES-002 | Ranking produced |
| EVD-BAYES-003 | Guardrail conflict detected |
| EVD-BAYES-004 | Replay completed |

## Guardrail Interaction

- Diagnostics NEVER directly execute actions; they only produce rankings
- `guardrail_filtered` flag indicates when the top candidate would be blocked
- Guardrails do not modify the posterior; they only flag candidates
