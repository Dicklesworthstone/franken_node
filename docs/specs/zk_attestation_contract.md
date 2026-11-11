# ZK Attestation Contract -- bd-kcg9

## Current implementation boundary

The legacy `zka-v1.0` wire format is retained strictly for historical lifecycle
records. Because `zka-v1.0` has no cryptographic witness relation, verifier key,
or authenticated public statement, `generate_proof` + `verify_proof` on legacy
records continue to fail closed with `ERR_ZKA_VERIFIER_UNAVAILABLE` and `FN-ZK-004`
so historical registrations can never confer compliance authority.

Authenticated selective-compliance verification (`bd-reality-20260923-26n9r.18`)
uses schema `zka-ristretto255-v2.0` (`CRYPTO_SCHEMA_VERSION`) over prime-order
Ristretto255 (`curve25519-dalek`, `#![forbid(unsafe_code)]`, zero trusted setup):
- Pedersen commitments `C = v * G + r * H` with nothing-up-my-sleeve generator
  `H = RistrettoPoint::from_uniform_bytes(SHA512("franken-node/zka-ristretto255/pedersen-generator-h/v1"))`.
- `ZkComplianceRelation::ThresholdAtLeast { threshold, range_bits }`: homomorphic
  shift `C - threshold * G == sum_{j=0}^{k-1} 2^j * C_j` paired with `k` parallel
  CDS94 1-of-2 Schnorr OR-proofs bound via Fiat-Shamir to `(attestation_id, params_sha256, C, C_0..C_{k-1})`.
- `ZkComplianceRelation::AllowlistMembership { allowed_values, merkle_root_hex }`:
  domain-separated binary Merkle root check paired with a CDS94 1-of-N Schnorr OR-proof.
- `ZkVerifierParams` binds the full `ZkPolicy` content (`policy_binding_sha256`),
  `verifier_key_id`, `epoch`, `challenge_nonce`, and `relation`; invalid witness
  or Schnorr transcripts fail deterministically with `ERR_ZKA_WITNESS_INVALID`
  (`ERR_ZK_WITNESS_INVALID`).

## Section

10.17 -- Radical Expansion Execution Track

## Overview

Zero-knowledge attestation support for selective compliance verification.
Verifiers can validate compliance predicates without privileged disclosure of
full private metadata.  Invalid or forged proofs fail admission deterministically.

## Invariants

| ID                        | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| INV-ZK-NO-DISCLOSURE      | Proofs reveal only the compliance predicate result, never full metadata.    |
| INV-ZK-PROOF-SOUNDNESS    | Forged or corrupted proofs are rejected deterministically.                  |
| INV-ZK-FAIL-CLOSED        | On any verification error the system denies admission.                     |
| INV-ZK-PREDICATE-COMPLETENESS | Valid proofs for satisfied predicates always pass verification.         |
| INV-ZKA-SELECTIVE          | Alias: proofs reveal only predicate results, not private metadata.         |
| INV-ZKA-SOUNDNESS          | Alias: forged proofs rejected with deterministic error.                    |
| INV-ZKA-COMPLETENESS       | Alias: valid proof for satisfied predicate passes within timeout.          |
| INV-ZKA-POLICY-BOUND       | Attestation bound to a specific ZkPolicy; cross-policy proofs rejected.    |
| INV-ZKA-AUDIT-TRAIL        | Every verification attempt logged with trace ID, timestamp, policy ref.    |
| INV-ZKA-SCHEMA-VERSIONED   | All serialised payloads carry a schema version tag.                        |

## Event Codes

| Code                      | FN Code    | Meaning                                          |
|---------------------------|------------|--------------------------------------------------|
| ZK_ATTESTATION_REQUEST    | FN-ZK-002  | Attestation proof submitted for verification     |
| ZK_PROOF_GENERATED        | FN-ZK-001  | Attestation proof generated                      |
| ZK_PROOF_VERIFIED         | FN-ZK-003  | Verification passed                              |
| ZK_PREDICATE_SATISFIED    | FN-ZK-003  | Compliance predicate satisfied                   |
| ZK_ATTESTATION_ISSUED     | FN-ZK-001  | Attestation issued to requester                  |
| FN-ZK-004                 | FN-ZK-004  | Verification rejected (invalid proof)            |
| FN-ZK-005                 | FN-ZK-005  | Verification rejected (policy mismatch)          |
| FN-ZK-006                 | FN-ZK-006  | Verification timed out                           |
| FN-ZK-007                 | FN-ZK-007  | Proof revoked by issuer                          |
| FN-ZK-008                 | FN-ZK-008  | Policy registered                                |
| FN-ZK-009                 | FN-ZK-009  | Policy deregistered                              |
| FN-ZK-010                 | FN-ZK-010  | Attestation audit record created                 |
| FN-ZK-011                 | FN-ZK-011  | Batch verification initiated                     |
| FN-ZK-012                 | FN-ZK-012  | Batch verification completed                     |

## Error Codes

| Code                          | Meaning                                            |
|-------------------------------|----------------------------------------------------|
| ERR_ZK_PROOF_INVALID          | Proof bytes do not parse or signature invalid       |
| ERR_ZK_PROOF_FORGED           | Proof structure indicates forgery attempt           |
| ERR_ZK_PREDICATE_UNSATISFIED  | Compliance predicate not met                        |
| ERR_ZK_WITNESS_MISSING        | Required witness data not provided                  |
| ERR_ZK_CIRCUIT_MISMATCH       | Proof was generated for different circuit/policy    |
| ERR_ZK_ATTESTATION_EXPIRED    | Proof exceeded its validity window                  |
| ERR_ZKA_INVALID_PROOF         | Impl: proof bytes invalid or signature invalid      |
| ERR_ZKA_POLICY_MISMATCH       | Impl: proof generated under different policy        |
| ERR_ZKA_EXPIRED               | Impl: proof exceeded validity window                |
| ERR_ZKA_REVOKED               | Impl: proof explicitly revoked                      |
| ERR_ZKA_PREDICATE_UNSATISFIED | Impl: compliance predicate not met                  |
| ERR_ZKA_DUPLICATE             | Impl: same proof already submitted                  |
| ERR_ZKA_TIMEOUT               | Impl: verification did not complete in time         |
| ERR_ZKA_POLICY_NOT_FOUND      | Impl: referenced policy not registered              |
| ERR_ZKA_BATCH_PARTIAL         | Impl: some proofs in batch failed                   |
| ERR_ZKA_METADATA_LEAK         | Impl: proof structure would reveal private fields   |
| ERR_ZK_WITNESS_INVALID        | Cryptographic witness or Schnorr relation failed    |
| ERR_ZKA_WITNESS_INVALID       | Impl: commitment or CDS94 Schnorr proof invalid     |

## Types

- `ZkAttestation` -- generated proof attesting to a compliance predicate.
- `ZkPolicy` -- defines predicate, issuer, and validity constraints.
- `ZkVerificationResult` -- outcome of verifying a single attestation.
- `ZkBatchResult` -- outcome of verifying a batch of attestations.
- `ZkAuditRecord` -- log entry for an attestation event.
- `PredicateOutcome` -- enum: Pass / Fail / Error.
- `AttestationStatus` -- lifecycle enum: Active / Expired / Revoked.
- `PolicyRegistry` -- BTreeMap-backed registry of active policies.
- `AttestationLedger` -- BTreeMap-backed ledger of all attestations.
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
- `generate_compliance_report` -- summary of attestation outcomes for a policy.

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

- `docs/specs/zk_attestation_contract.md` (this file)
- `docs/specs/section_10_17/bd-kcg9_contract.md` (detailed contract)
- `crates/franken-node/src/security/zk_attestation.rs`
- `tests/security/zk_attestation_verification.rs`
- `scripts/check_zk_attestation.py`
- `tests/test_check_zk_attestation.py`
- `artifacts/10.17/zk_attestation_vectors.json`
- `artifacts/section_10_17/bd-kcg9/verification_evidence.json`
- `artifacts/section_10_17/bd-kcg9/verification_summary.md`
