# bd-1o4v Contract: Proof-Verification Gate API for Control-Plane Trust Decisions

**Bead:** bd-1o4v
**Section:** 10.18 (Verifiable Execution Fabric)
**Status:** Active
**Owner:** SilverMeadow

## Purpose

Implement a proof-verification gate that accepts compliance proofs, validates
them against policy predicates, and emits deterministic trust decisions
(Allow / Deny / Degrade) with structured evidence. The gate serves as the
control-plane integration point for trust decisions in the VEF pipeline.

## Configuration

| Field                   | Type  | Default     | Description                                                  |
|-------------------------|-------|-------------|--------------------------------------------------------------|
| `max_proof_age_millis`  | u64   | 3_600_000   | Max proof age in ms before denial                            |
| `degrade_threshold`     | u8    | 80          | Confidence below min but above this triggers Degrade         |
| `enforce_policy_version`| bool  | true        | Require proof policy hash to match predicate policy hash     |

## Event Codes

| Code    | Severity | Structured Log Event              | Description                              |
|---------|----------|-----------------------------------|------------------------------------------|
| PVF-001 | INFO     | `pvf.request_received`            | Verification request received            |
| PVF-002 | INFO     | `pvf.proof_validated`             | Proof validated against predicate        |
| PVF-003 | INFO     | `pvf.decision_emitted`            | Trust decision emitted                   |
| PVF-004 | WARN     | `pvf.deny_logged`                 | Deny decision logged (INV-PVF-DENY-LOGGED) |
| PVF-005 | WARN     | `pvf.degrade_logged`              | Degrade decision logged                  |
| PVF-006 | INFO     | `pvf.report_finalized`            | Report finalized with evidence           |

## Error Codes

| Code                   | Description                                          |
|------------------------|------------------------------------------------------|
| ERR-PVF-PROOF-EXPIRED  | Proof has expired or exceeds maximum age              |
| ERR-PVF-POLICY-MISSING | No matching policy predicate for the action class     |
| ERR-PVF-INVALID-FORMAT | Proof payload does not conform to expected format     |
| ERR-PVF-INTERNAL       | Internal verification error                          |

## Invariants

- **INV-PVF-DETERMINISTIC** -- Identical proof inputs and policy state produce
  identical trust decisions and report digests.
- **INV-PVF-DENY-LOGGED** -- Every Deny decision is logged with a structured
  event containing the reason and trace context.
- **INV-PVF-EVIDENCE-COMPLETE** -- Every verification report includes complete
  evidence linking proof, policy predicate, decision, and trace context.

## Types

### TrustDecision

| Variant        | Fields      | Description                                          |
|----------------|-------------|------------------------------------------------------|
| `Allow`        | --          | Proof valid, all predicates satisfied                |
| `Deny(reason)` | `String`   | Proof failed; reason describes which checks failed   |
| `Degrade(lvl)` | `u8`       | Partial satisfaction; 1=mild, 5=severe               |

### PolicyPredicate

| Field                  | Type   | Description                                    |
|------------------------|--------|------------------------------------------------|
| `predicate_id`         | String | Unique predicate identifier                    |
| `action_class`         | String | Action class this predicate applies to         |
| `max_proof_age_millis` | u64    | Max proof age for this predicate               |
| `min_confidence`       | u8     | Minimum confidence score (0..=100)             |
| `require_witnesses`    | bool   | Whether witnesses are required                 |
| `min_witness_count`    | usize  | Minimum witness count (when required)          |
| `policy_version_hash`  | String | Policy version hash for binding                |

### ComplianceProof

| Field                  | Type        | Description                              |
|------------------------|-------------|------------------------------------------|
| `proof_id`             | String      | Unique proof identifier                  |
| `action_class`         | String      | Action class this proof covers           |
| `proof_hash`           | String      | Cryptographic proof payload hash         |
| `confidence`           | u8          | Confidence score (0..=100)               |
| `generated_at_millis`  | u64         | When proof was generated                 |
| `expires_at_millis`    | u64         | Expiration timestamp                     |
| `witness_references`   | Vec<String> | Witness references                       |
| `policy_version_hash`  | String      | Policy version hash                      |
| `trace_id`             | String      | Trace ID for correlation                 |

### VerificationRequest

| Field         | Type            | Description                              |
|---------------|-----------------|------------------------------------------|
| `request_id`  | String          | Unique request identifier                |
| `proof`       | ComplianceProof | The proof to verify                      |
| `now_millis`  | u64             | Current timestamp for freshness checks   |
| `trace_id`    | String          | Trace ID for correlation                 |

### VerificationReport

| Field            | Type                 | Description                            |
|------------------|----------------------|----------------------------------------|
| `schema_version` | String               | Schema version                         |
| `request_id`     | String               | Request that produced this report      |
| `proof_id`       | String               | Proof that was verified                |
| `action_class`   | String               | Action class                           |
| `decision`       | TrustDecision        | The trust decision                     |
| `evidence`       | Vec<PredicateEvidence> | Per-check evidence                   |
| `events`         | Vec<VerifierEvent>   | Events emitted during verification     |
| `report_digest`  | String               | Deterministic SHA-256 digest           |
| `trace_id`       | String               | Trace ID                               |
| `created_at_millis` | u64              | Timestamp of report creation           |

### DecisionSummary

| Field           | Type                     | Description                          |
|-----------------|--------------------------|--------------------------------------|
| `total_reports` | usize                    | Total reports rendered               |
| `allow_count`   | usize                    | Allow decisions                      |
| `deny_count`    | usize                    | Deny decisions                       |
| `degrade_count` | usize                    | Degrade decisions                    |
| `deny_reasons`  | BTreeMap<String, usize>  | Deny reason frequencies              |

## Acceptance Criteria

1. `ProofVerifier` in `crates/franken-node/src/vef/proof_verifier.rs` validates
   compliance proofs against policy predicates.
2. `TrustDecision` enum with Allow, Deny(reason), and Degrade(level) variants.
3. `VerificationGate` as the control-plane integration point managing predicates
   and producing deterministic reports.
4. `VerificationRequest` and `VerificationReport` with structured evidence.
5. Event codes PVF-001 through PVF-006.
6. Invariants INV-PVF-DETERMINISTIC, INV-PVF-DENY-LOGGED, INV-PVF-EVIDENCE-COMPLETE enforced.
7. Error codes ERR-PVF-PROOF-EXPIRED, ERR-PVF-POLICY-MISSING, ERR-PVF-INVALID-FORMAT, ERR-PVF-INTERNAL.
8. All decisions are deterministic and logged.
9. >= 25 unit tests covering all invariants.
10. Verification script `scripts/check_proof_verifier.py` passes.
11. Evidence artifacts in `artifacts/section_10_18/bd-1o4v/`.

## Dependencies

- Section 10.18 VEF receipt chain (proof source context).

## File Layout

```
docs/specs/section_10_18/bd-1o4v_contract.md   (this file)
crates/franken-node/src/vef/proof_verifier.rs
scripts/check_proof_verifier.py
tests/test_check_proof_verifier.py
artifacts/section_10_18/bd-1o4v/verification_evidence.json
artifacts/section_10_18/bd-1o4v/verification_summary.md
```
