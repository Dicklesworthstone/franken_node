# EvidenceEntry Schema v1

## Scope

This specification defines the canonical `EvidenceEntry` schema for product control decisions in Section 10.14. It is the machine-readable contract for decision evidence that feeds replay, policy auditing, and downstream verification gates.

## Purpose

`EvidenceEntry` records:

- decision kind
- ordered candidate set
- constraint evaluations
- chosen action
- witness references

The schema must be deterministic so independent verifiers can replay ranking and selection without hidden context.

## Invariants

| ID | Statement |
|----|-----------|
| INV-EE-ROOT-ORDER | Root object fields follow the canonical root field order listed in `canonical_order.root_fields`. |
| INV-EE-CANDIDATE-ORDER | `candidates` are ordered by ascending `ordinal`; ties are broken by lexicographic `candidate_id`. |
| INV-EE-CONSISTENCY | `chosen_action.candidate_id` must reference an existing candidate entry. |
| INV-EE-WITNESS | Each witness reference contains a valid SHA-256 digest and a stable witness type. |
| INV-EE-DETERMINISTIC | Equivalent decision inputs produce structurally identical JSON after canonical sorting. |

## Canonical Root Field Order

1. `schema_version`
2. `decision_id`
3. `decision_kind`
4. `decision_time`
5. `trace_id`
6. `candidates`
7. `constraints`
8. `chosen_action`
9. `witness_refs`
10. `canonical_order`

## Data Model

### Root Fields

- `schema_version: "1.0"`
- `decision_id: string` (`DEC-<UTCDate>-<suffix>`)
- `decision_kind: enum` (`admit`, `deny`, `quarantine`, `release`, `rollback`, `throttle`, `escalate`)
- `decision_time: string` (RFC 3339)
- `trace_id: string`
- `candidates: Candidate[]`
- `constraints: ConstraintEvaluation[]`
- `chosen_action: ChosenAction`
- `witness_refs: WitnessRef[]`
- `canonical_order: CanonicalOrder`

### Candidate

- `ordinal: integer` (1-based deterministic ordering key)
- `candidate_id: string`
- `action_code: string`
- `score: number`
- `feasible: boolean`
- `rationale_refs: string[]`

### ConstraintEvaluation

- `constraint_id: string`
- `severity: enum` (`low`, `medium`, `high`, `critical`)
- `status: enum` (`pass`, `fail`, `waived`)
- `details: string`

### ChosenAction

- `candidate_id: string`
- `action_code: string`
- `justification: string`
- `expected_loss: number`

### WitnessRef

- `witness_id: string`
- `witness_type: enum` (`marker`, `proof`, `receipt`, `log`, `snapshot`)
- `digest_sha256: string` (64 lowercase hex chars)
- `uri: string`

### CanonicalOrder

- `root_fields: string[]` (must equal canonical root field order)
- `candidate_sort_rule: "ordinal-ascending-then-candidate-id"`
- `constraint_sort_rule: "constraint-id-lexicographic"`

## Deterministic Serialization Rules

1. Producers must emit root fields in canonical root order.
2. `candidates` must be sorted per `candidate_sort_rule` before serialization.
3. `constraints` must be sorted lexicographically by `constraint_id`.
4. Numbers must use JSON number encoding (no stringified numeric fields).
5. SHA-256 digests must be lowercase hex.

## Error and Event Codes

### Validation Error Codes

- `EE_MISSING_REQUIRED_FIELD`
- `EE_INVALID_CANONICAL_ORDER`
- `EE_INVALID_CANDIDATE_ORDER`
- `EE_UNKNOWN_CHOSEN_CANDIDATE`
- `EE_INVALID_WITNESS_DIGEST`

### Structured Event Codes

- `EVIDENCE_SCHEMA_VALIDATION_STARTED`
- `EVIDENCE_SCHEMA_VALIDATION_CASE`
- `EVIDENCE_SCHEMA_VALIDATION_COMPLETED`

## Artifacts

- Schema: `spec/evidence_entry_v1.json`
- Validation report: `artifacts/10.14/evidence_schema_validation_report.json`
- Bead evidence: `artifacts/section_10_14/bd-nupr/verification_evidence.json`
- Verification summary: `artifacts/section_10_14/bd-nupr/verification_summary.md`
- Verifier script: `scripts/check_evidence_entry_schema.py`
- Unit tests: `tests/test_check_evidence_entry_schema.py`
