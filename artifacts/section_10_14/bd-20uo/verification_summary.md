# bd-20uo: Verification Summary

## Proof-Carrying Repair Artifacts for Decode/Reconstruction Paths

**Section:** 10.14 (FrankenSQLite Deep-Mined Expansion)
**Status:** PASS (66/66 checks)
**Agent:** CrimsonCrane (claude-code, claude-opus-4-6)
**Date:** 2026-02-20

## Implementation

- **Module:** `crates/franken-node/src/repair/proof_carrying_decode.rs`
- **Spec:** `docs/specs/section_10_14/bd-20uo_contract.md`
- **Verification:** `scripts/check_proof_carrying_decode.py`
- **Test Suite:** `tests/test_check_proof_carrying_decode.py` (23 tests)

## Architecture

| Type | Purpose |
|------|---------|
| `ProofCarryingDecoder` | Emits proof artifacts during decode/reconstruction |
| `RepairProof` | Binds input fragment hashes to output via signed attestation |
| `ProofVerificationApi` | Validates repair proofs against stored originals |
| `Fragment` | Input fragment with data and cryptographic hash |
| `AlgorithmId` | Registered reconstruction algorithm identifier |
| `Attestation` | Signed binding of fragments to output |
| `VerificationResult` | Valid, InvalidFragmentHash, UnknownAlgorithm, OutputHashMismatch, InvalidSignature, MissingProof |
| `ProofMode` | Mandatory (hard error) or Advisory (warning) |
| `DecodeResult` | Reconstructed data with optional proof |
| `ProofAuditEvent` | Structured audit event for evidence ledger |
| `ProofCarryingDecodeError` | MissingProofInMandatoryMode, InvalidProof, ReconstructionFailed |

## Key Properties

- **Proof binding**: Every proof contains input fragment hashes, algorithm ID, output hash, and HMAC signature
- **Mode enforcement**: Mandatory mode rejects missing proofs; Advisory mode warns
- **Verification API**: Validates fragment hashes, algorithm registration, output hash, and signature
- **Deterministic**: Same inputs produce identical proof structure
- **Serializable**: All proof types round-trip through JSON

## Event Codes

| Code | Trigger |
|------|---------|
| REPAIR_PROOF_EMITTED | Proof generated during decode |
| REPAIR_PROOF_VERIFIED | Proof passed verification |
| REPAIR_PROOF_MISSING | No proof present for object |
| REPAIR_PROOF_INVALID | Proof failed verification |

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Rust unit tests | 35 | All pass |
| Python verification checks | 66 | All pass |
| Python unit tests | 23 | All pass |

## Downstream Unblocked

- bd-3epz: Section 10.14 verification gate
- bd-5rh: 10.14 plan gate
