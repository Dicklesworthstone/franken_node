# bd-kcg9 Contract: Zero-Knowledge Attestation for Selective Compliance Verification

## Section

10.17 -- Radical Expansion Execution Track

## Objective

Add zero-knowledge attestation support so verifiers can validate compliance
predicates without requiring privileged disclosure of full private metadata.
Invalid or forged proofs must fail admission deterministically.

## Invariants

- **INV-ZKA-SELECTIVE**: attestation proofs reveal only the compliance predicate
  result, never full private metadata.
- **INV-ZKA-SOUNDNESS**: forged or corrupted proofs are rejected with a
  deterministic error; no partial admission.
- **INV-ZKA-COMPLETENESS**: a valid proof for a satisfied predicate always
  passes verification within the configured timeout.
- **INV-ZKA-POLICY-BOUND**: every attestation is bound to a specific `ZkPolicy`;
  a proof generated under policy P cannot verify under policy Q.
- **INV-ZKA-AUDIT-TRAIL**: every verification attempt (pass or fail) is logged
  with a trace ID, timestamp, and policy reference.
- **INV-ZKA-SCHEMA-VERSIONED**: all serialised attestation payloads carry a
  schema version tag for forward-compatible deserialisation.

## Event Codes

| Code       | Meaning                                     |
|------------|---------------------------------------------|
| FN-ZK-001  | Attestation proof generated                 |
| FN-ZK-002  | Attestation proof submitted for verification|
| FN-ZK-003  | Verification passed                         |
| FN-ZK-004  | Verification rejected (invalid proof)       |
| FN-ZK-005  | Verification rejected (policy mismatch)     |
| FN-ZK-006  | Verification timed out                      |
| FN-ZK-007  | Proof revoked by issuer                     |
| FN-ZK-008  | Policy registered                           |
| FN-ZK-009  | Policy deregistered                         |
| FN-ZK-010  | Attestation audit record created            |
| FN-ZK-011  | Batch verification initiated                |
| FN-ZK-012  | Batch verification completed                |

## Error Codes

| Code                        | Meaning                                       |
|-----------------------------|-----------------------------------------------|
| ERR_ZKA_INVALID_PROOF       | Proof bytes do not parse or signature invalid  |
| ERR_ZKA_POLICY_MISMATCH     | Proof was generated under a different policy   |
| ERR_ZKA_EXPIRED             | Proof exceeded its validity window             |
| ERR_ZKA_REVOKED             | Proof has been explicitly revoked              |
| ERR_ZKA_PREDICATE_UNSATISFIED | Compliance predicate not met                 |
| ERR_ZKA_DUPLICATE           | Same proof already submitted                   |
| ERR_ZKA_TIMEOUT             | Verification did not complete in time          |
| ERR_ZKA_POLICY_NOT_FOUND    | Referenced policy not registered               |
| ERR_ZKA_BATCH_PARTIAL       | Some proofs in batch failed                    |
| ERR_ZKA_METADATA_LEAK       | Proof structure would reveal private fields    |

## Types

- `ZkAttestation` -- a generated proof attesting to a compliance predicate.
- `ZkPolicy` -- defines the predicate, issuer, and validity constraints.
- `ZkVerificationResult` -- outcome of verifying a single attestation.
- `ZkBatchResult` -- outcome of verifying a batch of attestations.
- `ZkAuditRecord` -- log entry for an attestation event.
- `PredicateOutcome` -- enum of Pass / Fail / Error.
- `AttestationStatus` -- lifecycle enum: Active / Expired / Revoked.
- `PolicyRegistry` -- BTreeMap-backed registry of active policies.
- `AttestationLedger` -- BTreeMap-backed ledger of all attestations and their statuses.
- `ZkProofPayload` -- raw proof bytes with schema version tag.

## Methods

- `generate_proof` -- produce a ZkAttestation from private data and a ZkPolicy.
- `verify_proof` -- verify a ZkAttestation against a ZkPolicy.
- `verify_batch` -- verify multiple attestations, returning a ZkBatchResult.
- `register_policy` -- add a ZkPolicy to the PolicyRegistry.
- `deregister_policy` -- remove a ZkPolicy from the PolicyRegistry.
- `revoke_attestation` -- mark a previously issued attestation as revoked.
- `query_audit` -- return audit records matching a filter.
- `is_valid` -- check if an attestation is still active and within its validity window.
- `sweep_expired` -- mark all expired attestations and return them.
- `generate_compliance_report` -- produce a summary of attestation outcomes for a policy.

## Acceptance Criteria

1. Verifiers can validate compliance predicates without privileged disclosure
   of full private metadata.
2. Invalid or forged proofs fail admission deterministically.
3. Every verification is bound to a specific ZkPolicy; cross-policy proofs are
   rejected.
4. All events produce structured log entries with stable event codes.
5. All serialised types carry a schema version for forward compatibility.
6. BTreeMap is used for all ordered collections.
7. At least 20 inline unit tests under `#[cfg(test)]`.

## Deliverables

- `docs/specs/section_10_17/bd-kcg9_contract.md` (this file)
- `crates/franken-node/src/security/zk_attestation.rs`
- `scripts/check_zk_attestation.py`
- `tests/test_check_zk_attestation.py`
- `artifacts/section_10_17/bd-kcg9/verification_evidence.json`
- `artifacts/section_10_17/bd-kcg9/verification_summary.md`
