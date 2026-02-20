# bd-20uo: Proof-Carrying Repair Artifacts

**Section**: 10.14
**Module**: `crates/franken-node/src/repair/proof_carrying_decode.rs`
**Depends on**: bd-1l62 (DurableClaimGate)

## Overview

Every repair/reconstruction operation emits a `RepairProof` containing fragment
hashes, algorithm identifier, output hash, and signed attestation. Downstream
trust decisions (quarantine promotion, durable claims) are evidence-based.

## Modes

| Mode | Behavior |
|------|----------|
| Mandatory | Missing proofs are hard errors |
| Advisory | Missing proofs are warnings |

## Types

| Type | Purpose |
|------|---------|
| `ProofCarryingDecoder` | Decoder that emits proof artifacts during reconstruction |
| `RepairProof` | Proof binding input fragments to output via signed attestation |
| `ProofVerificationApi` | Verifies repair proofs against stored originals |
| `Fragment` | Input fragment with data and hash |
| `AlgorithmId` | Registered reconstruction algorithm identifier |
| `Attestation` | Signed attestation binding fragments to output |
| `VerificationResult` | Valid, InvalidFragmentHash, UnknownAlgorithm, OutputHashMismatch, InvalidSignature, MissingProof |
| `ProofMode` | Mandatory or Advisory enforcement |
| `DecodeResult` | Decode output with optional proof |
| `ProofAuditEvent` | Structured audit event |
| `ProofCarryingDecodeError` | MissingProofInMandatoryMode, InvalidProof, ReconstructionFailed |

## Event Codes

| Code | Trigger |
|------|---------|
| REPAIR_PROOF_EMITTED | Proof generated during decode |
| REPAIR_PROOF_VERIFIED | Proof passed verification |
| REPAIR_PROOF_MISSING | No proof present for object |
| REPAIR_PROOF_INVALID | Proof failed verification |

## Invariants

| ID | Description |
|----|-------------|
| INV-REPAIR-PROOF-COMPLETE | Every repair output has a proof or explicit rejection |
| INV-REPAIR-PROOF-BINDING | Proof binds input fragments to output via signed attestation |
| INV-REPAIR-PROOF-DETERMINISTIC | Same inputs produce identical proof structure |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/repair/proof_carrying_decode.rs` |
| Spec contract | `docs/specs/section_10_14/bd-20uo_contract.md` |
| Verification script | `scripts/check_proof_carrying_decode.py` |
| Python unit tests | `tests/test_check_proof_carrying_decode.py` |
| Golden vectors | `artifacts/10.14/repair_proof_samples.json` |
| Verification evidence | `artifacts/section_10_14/bd-20uo/verification_evidence.json` |
| Verification summary | `artifacts/section_10_14/bd-20uo/verification_summary.md` |

## Dependencies

- **Upstream**: bd-1l62 (DurableClaimGate for repair completion claims)
- **Downstream**: bd-3epz (section gate), bd-5rh (plan gate)
