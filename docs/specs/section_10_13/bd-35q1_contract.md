# bd-35q1: Threshold Signature Verification

## Bead: bd-35q1 | Section: 10.13

## Purpose

Implements threshold signature verification for connector publication
artifacts. Publication requires a configured k-of-n quorum. Partial
signature sets below the threshold are rejected. Verification failures
produce stable, deterministic failure reasons for diagnostics.

## Invariants

| ID | Statement |
|----|-----------|
| INV-THRESH-QUORUM | Publication requires at least k valid signatures from the configured n signers. |
| INV-THRESH-PARTIAL-REJECT | Signature sets with fewer than k valid signatures are always rejected. |
| INV-THRESH-STABLE-REASON | Verification failures produce a stable, machine-readable failure reason. |
| INV-THRESH-NO-DUPLICATE | Duplicate signatures from the same signer are counted only once. |

## Types

### ThresholdConfig
- `threshold: u32` — minimum signatures required (k)
- `total_signers: u32` — total configured signers (n)
- `signer_keys: Vec<SignerKey>`

### SignerKey
- `key_id: String` — unique signer identifier
- `public_key_hex: String` — hex-encoded public key

### PartialSignature
- `signer_id: String` — which signer produced this
- `key_id: String` — which key was used
- `signature_hex: String` — hex-encoded signature

### PublicationArtifact
- `artifact_id: String`
- `connector_id: String`
- `content_hash: String` — hash of the artifact content
- `signatures: Vec<PartialSignature>`

### VerificationResult
- `artifact_id: String`
- `verified: bool`
- `valid_signatures: u32`
- `threshold: u32`
- `failure_reason: Option<FailureReason>`
- `trace_id: String`
- `timestamp: String`

### FailureReason
- `BelowThreshold { have, need }` — not enough valid signatures
- `UnknownSigner { signer_id }` — signer not in configured set
- `InvalidSignature { signer_id }` — signature verification failed
- `DuplicateSigner { signer_id }` — same signer signed twice
- `ConfigInvalid { reason }` — threshold > total_signers or similar

## Error Codes

| Code | Trigger |
|------|---------|
| `THRESH_BELOW_QUORUM` | Valid signatures < threshold. |
| `THRESH_UNKNOWN_SIGNER` | Signature from unknown key_id. |
| `THRESH_INVALID_SIG` | Signature does not verify against content hash. |
| `THRESH_CONFIG_INVALID` | Threshold config is malformed. |

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-35q1_contract.md` |
| Public spec alias | `docs/specs/threshold_signatures.md` |
| Implementation | `crates/franken-node/src/security/threshold_sig.rs` |
| Security tests | `tests/security/threshold_signature_verification.rs` |
| Test vectors | `artifacts/section_10_13/bd-35q1/threshold_signature_vectors.json` |
| Verification evidence | `artifacts/section_10_13/bd-35q1/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-35q1/verification_summary.md` |
