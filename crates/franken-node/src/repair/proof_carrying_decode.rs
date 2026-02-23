//! bd-20uo: Proof-carrying repair artifacts for decode/reconstruction paths.
//!
//! Every repair operation emits a `RepairProof` containing fragment hashes,
//! algorithm identifier, output hash, and signed attestation. Downstream
//! trust decisions (quarantine promotion, durable claims) are evidence-based.
//!
//! # Modes
//!
//! - **Mandatory**: Missing proofs are hard errors preventing use of repaired objects.
//! - **Advisory**: Missing proofs are logged as warnings but operation proceeds.
//!
//! # Invariants
//!
//! - INV-REPAIR-PROOF-COMPLETE: Every repair output has a proof or an explicit rejection.
//! - INV-REPAIR-PROOF-BINDING: Proof binds input fragments to output via signed attestation.
//! - INV-REPAIR-PROOF-DETERMINISTIC: Same inputs produce identical proof structure.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const REPAIR_PROOF_EMITTED: &str = "REPAIR_PROOF_EMITTED";
pub const REPAIR_PROOF_VERIFIED: &str = "REPAIR_PROOF_VERIFIED";
pub const REPAIR_PROOF_MISSING: &str = "REPAIR_PROOF_MISSING";
pub const REPAIR_PROOF_INVALID: &str = "REPAIR_PROOF_INVALID";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Proof enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    Mandatory,
    Advisory,
}

/// Registered reconstruction algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlgorithmId(pub String);

impl AlgorithmId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fragment used in reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    pub fragment_id: String,
    pub data: Vec<u8>,
}

impl Fragment {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"proof_carrying_fragment_v1:");
        hasher.update(&self.data);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Signed attestation binding fragments to output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub signer_id: String,
    pub signature: String,
    pub payload_hash: String,
}

/// Proof emitted during a repair/reconstruction operation.
///
/// INV-REPAIR-PROOF-BINDING: binds input_fragment_hashes to output_hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairProof {
    pub proof_id: String,
    pub object_id: String,
    pub input_fragment_hashes: Vec<String>,
    pub algorithm_id: AlgorithmId,
    pub output_hash: String,
    pub attestation: Attestation,
    pub fragment_count: usize,
    pub timestamp_epoch_secs: u64,
    pub trace_id: String,
}

/// Result of proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    Valid,
    InvalidFragmentHash {
        index: usize,
        expected: String,
        actual: String,
    },
    UnknownAlgorithm {
        algorithm_id: AlgorithmId,
    },
    OutputHashMismatch {
        expected: String,
        actual: String,
    },
    InvalidSignature,
    MissingProof,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Valid => REPAIR_PROOF_VERIFIED,
            Self::MissingProof => REPAIR_PROOF_MISSING,
            _ => REPAIR_PROOF_INVALID,
        }
    }
}

/// Audit event for proof operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAuditEvent {
    pub event_code: String,
    pub object_id: String,
    pub fragment_count: usize,
    pub algorithm: String,
    pub proof_hash: String,
    pub mode: String,
    pub trace_id: String,
}

/// Errors from proof-carrying decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofCarryingDecodeError {
    MissingProofInMandatoryMode { object_id: String },
    InvalidProof { object_id: String, reason: String },
    ReconstructionFailed { object_id: String, reason: String },
}

impl ProofCarryingDecodeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingProofInMandatoryMode { .. } => "PROOF_MISSING_MANDATORY",
            Self::InvalidProof { .. } => "PROOF_INVALID",
            Self::ReconstructionFailed { .. } => "RECONSTRUCTION_FAILED",
        }
    }
}

impl std::fmt::Display for ProofCarryingDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingProofInMandatoryMode { object_id } => {
                write!(f, "{}: object {object_id} has no repair proof", self.code())
            }
            Self::InvalidProof { object_id, reason } => {
                write!(f, "{}: object {object_id}: {reason}", self.code())
            }
            Self::ReconstructionFailed { object_id, reason } => {
                write!(f, "{}: object {object_id}: {reason}", self.code())
            }
        }
    }
}

impl std::error::Error for ProofCarryingDecodeError {}

/// Decode result containing reconstructed data and proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodeResult {
    pub object_id: String,
    pub output_data: Vec<u8>,
    pub proof: Option<RepairProof>,
}

// ---------------------------------------------------------------------------
// ProofCarryingDecoder
// ---------------------------------------------------------------------------

/// Decoder that emits proof artifacts during reconstruction.
///
/// INV-REPAIR-PROOF-COMPLETE: every decode either emits a proof or errors.
#[derive(Debug, Clone)]
pub struct ProofCarryingDecoder {
    mode: ProofMode,
    signer_id: String,
    signing_secret: String,
    registered_algorithms: Vec<AlgorithmId>,
    audit_log: Vec<ProofAuditEvent>,
}

impl ProofCarryingDecoder {
    pub fn new(mode: ProofMode, signer_id: &str, signing_secret: &str) -> Self {
        Self {
            mode,
            signer_id: signer_id.to_string(),
            signing_secret: signing_secret.to_string(),
            registered_algorithms: vec![
                AlgorithmId::new("reed_solomon_8_4"),
                AlgorithmId::new("xor_parity_2"),
                AlgorithmId::new("simple_concat"),
            ],
            audit_log: Vec::new(),
        }
    }

    pub fn mode(&self) -> ProofMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: ProofMode) {
        self.mode = mode;
    }

    pub fn registered_algorithms(&self) -> &[AlgorithmId] {
        &self.registered_algorithms
    }

    pub fn register_algorithm(&mut self, algorithm_id: AlgorithmId) {
        if !self.registered_algorithms.contains(&algorithm_id) {
            self.registered_algorithms.push(algorithm_id);
        }
    }

    pub fn audit_log(&self) -> &[ProofAuditEvent] {
        &self.audit_log
    }

    /// Decode/reconstruct an object from fragments.
    ///
    /// Emits REPAIR_PROOF_EMITTED on success.
    pub fn decode(
        &mut self,
        object_id: &str,
        fragments: &[Fragment],
        algorithm_id: &AlgorithmId,
        now_epoch_secs: u64,
        trace_id: &str,
    ) -> Result<DecodeResult, ProofCarryingDecodeError> {
        if !self.registered_algorithms.contains(algorithm_id) {
            return Err(ProofCarryingDecodeError::ReconstructionFailed {
                object_id: object_id.to_string(),
                reason: format!("unregistered algorithm: {algorithm_id}"),
            });
        }

        if fragments.is_empty() {
            return Err(ProofCarryingDecodeError::ReconstructionFailed {
                object_id: object_id.to_string(),
                reason: "no fragments provided".to_string(),
            });
        }

        // Simulate reconstruction: concatenate fragment data
        let mut output_data = Vec::new();
        for fragment in fragments {
            output_data.extend_from_slice(&fragment.data);
        }

        // Compute fragment hashes
        let input_fragment_hashes: Vec<String> =
            fragments.iter().map(|f| hex::encode(f.hash())).collect();

        // Compute output hash
        let output_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_output_v1:");
            hasher.update(&output_data);
            hex::encode(hasher.finalize())
        };

        // Create attestation
        let payload_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_payload_v1:");
            for h in &input_fragment_hashes {
                hasher.update(h.as_bytes());
                hasher.update(b"|");
            }
            hasher.update(algorithm_id.as_str().as_bytes());
            hasher.update(b"|");
            hasher.update(output_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        let signature = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_signature_v1:");
            hasher.update(self.signing_secret.as_bytes());
            hasher.update(b"|");
            hasher.update(payload_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        let proof_id = format!("rp-{}", &output_hash[..16]);

        let proof = RepairProof {
            proof_id,
            object_id: object_id.to_string(),
            input_fragment_hashes,
            algorithm_id: algorithm_id.clone(),
            output_hash: output_hash.clone(),
            attestation: Attestation {
                signer_id: self.signer_id.clone(),
                signature,
                payload_hash,
            },
            fragment_count: fragments.len(),
            timestamp_epoch_secs: now_epoch_secs,
            trace_id: trace_id.to_string(),
        };

        // [REPAIR_PROOF_EMITTED]
        self.audit_log.push(ProofAuditEvent {
            event_code: REPAIR_PROOF_EMITTED.to_string(),
            object_id: object_id.to_string(),
            fragment_count: fragments.len(),
            algorithm: algorithm_id.as_str().to_string(),
            proof_hash: output_hash,
            mode: format!("{:?}", self.mode),
            trace_id: trace_id.to_string(),
        });

        Ok(DecodeResult {
            object_id: object_id.to_string(),
            output_data,
            proof: Some(proof),
        })
    }
}

// ---------------------------------------------------------------------------
// ProofVerificationApi
// ---------------------------------------------------------------------------

/// Verification API for repair proofs.
pub struct ProofVerificationApi {
    signing_secret: String,
    registered_algorithms: Vec<AlgorithmId>,
}

impl ProofVerificationApi {
    pub fn new(signing_secret: &str, registered_algorithms: Vec<AlgorithmId>) -> Self {
        Self {
            signing_secret: signing_secret.to_string(),
            registered_algorithms,
        }
    }

    /// Verify a repair proof against stored fragment originals and recomputed output.
    pub fn verify(
        &self,
        proof: &RepairProof,
        original_fragment_hashes: &[String],
        recomputed_output_hash: &str,
    ) -> VerificationResult {
        // (a) Check input fragment hashes match stored originals
        if proof.input_fragment_hashes.len() != original_fragment_hashes.len() {
            return VerificationResult::InvalidFragmentHash {
                index: 0,
                expected: format!("count={}", original_fragment_hashes.len()),
                actual: format!("count={}", proof.input_fragment_hashes.len()),
            };
        }
        for (i, (proof_hash, original_hash)) in proof
            .input_fragment_hashes
            .iter()
            .zip(original_fragment_hashes.iter())
            .enumerate()
        {
            if proof_hash != original_hash {
                return VerificationResult::InvalidFragmentHash {
                    index: i,
                    expected: original_hash.clone(),
                    actual: proof_hash.clone(),
                };
            }
        }

        // (b) Check algorithm is registered
        if !self.registered_algorithms.contains(&proof.algorithm_id) {
            return VerificationResult::UnknownAlgorithm {
                algorithm_id: proof.algorithm_id.clone(),
            };
        }

        // (c) Check output hash matches recomputed value
        if proof.output_hash != recomputed_output_hash {
            return VerificationResult::OutputHashMismatch {
                expected: recomputed_output_hash.to_string(),
                actual: proof.output_hash.clone(),
            };
        }

        // (d) Verify signature
        let expected_payload_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_payload_v1:");
            for h in &proof.input_fragment_hashes {
                hasher.update(h.as_bytes());
                hasher.update(b"|");
            }
            hasher.update(proof.algorithm_id.as_str().as_bytes());
            hasher.update(b"|");
            hasher.update(proof.output_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        if proof.attestation.payload_hash != expected_payload_hash {
            return VerificationResult::InvalidSignature;
        }

        let expected_signature = {
            let mut hasher = Sha256::new();
            hasher.update(b"proof_carrying_signature_v1:");
            hasher.update(self.signing_secret.as_bytes());
            hasher.update(b"|");
            hasher.update(expected_payload_hash.as_bytes());
            hex::encode(hasher.finalize())
        };

        if proof.attestation.signature != expected_signature {
            return VerificationResult::InvalidSignature;
        }

        VerificationResult::Valid
    }

    /// Check whether a proof is present (for mandatory mode enforcement).
    pub fn check_proof_presence(
        &self,
        proof: Option<&RepairProof>,
        mode: ProofMode,
        object_id: &str,
    ) -> Result<(), ProofCarryingDecodeError> {
        match (proof, mode) {
            (None, ProofMode::Mandatory) => {
                Err(ProofCarryingDecodeError::MissingProofInMandatoryMode {
                    object_id: object_id.to_string(),
                })
            }
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fragments() -> Vec<Fragment> {
        vec![
            Fragment {
                fragment_id: "frag-001".to_string(),
                data: vec![0xAA; 32],
            },
            Fragment {
                fragment_id: "frag-002".to_string(),
                data: vec![0xBB; 32],
            },
            Fragment {
                fragment_id: "frag-003".to_string(),
                data: vec![0xCC; 32],
            },
        ]
    }

    fn decoder() -> ProofCarryingDecoder {
        ProofCarryingDecoder::new(ProofMode::Mandatory, "test-signer", "test-secret")
    }

    fn verification_api() -> ProofVerificationApi {
        ProofVerificationApi::new(
            "test-secret",
            vec![
                AlgorithmId::new("reed_solomon_8_4"),
                AlgorithmId::new("xor_parity_2"),
                AlgorithmId::new("simple_concat"),
            ],
        )
    }

    // ── Fragment tests ──

    #[test]
    fn test_fragment_hash_deterministic() {
        let f = Fragment {
            fragment_id: "f-1".to_string(),
            data: vec![0x42; 16],
        };
        assert_eq!(f.hash(), f.hash());
    }

    #[test]
    fn test_fragment_hash_different_data() {
        let f1 = Fragment {
            fragment_id: "f-1".to_string(),
            data: vec![0x00; 16],
        };
        let f2 = Fragment {
            fragment_id: "f-2".to_string(),
            data: vec![0xFF; 16],
        };
        assert_ne!(f1.hash(), f2.hash());
    }

    // ── AlgorithmId tests ──

    #[test]
    fn test_algorithm_id_display() {
        let id = AlgorithmId::new("reed_solomon_8_4");
        assert_eq!(id.to_string(), "reed_solomon_8_4");
        assert_eq!(id.as_str(), "reed_solomon_8_4");
    }

    // ── ProofCarryingDecoder tests ──

    #[test]
    fn test_decode_success() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.object_id, "obj-001");
        assert!(!result.output_data.is_empty());
        assert!(result.proof.is_some());
    }

    #[test]
    fn test_decode_emits_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();
        assert_eq!(proof.object_id, "obj-001");
        assert_eq!(proof.fragment_count, 3);
        assert_eq!(proof.input_fragment_hashes.len(), 3);
        assert!(!proof.output_hash.is_empty());
        assert!(!proof.attestation.signature.is_empty());
    }

    #[test]
    fn test_decode_audit_event() {
        let mut dec = decoder();
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        assert_eq!(dec.audit_log().len(), 1);
        assert_eq!(dec.audit_log()[0].event_code, REPAIR_PROOF_EMITTED);
    }

    #[test]
    fn test_decode_unregistered_algorithm() {
        let mut dec = decoder();
        let frags = test_fragments();
        let err = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("unknown_algo"),
                1000,
                "t-1",
            )
            .unwrap_err();
        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
    }

    #[test]
    fn test_decode_empty_fragments() {
        let mut dec = decoder();
        let err = dec
            .decode(
                "obj-001",
                &[],
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap_err();
        assert_eq!(err.code(), "RECONSTRUCTION_FAILED");
    }

    #[test]
    fn test_decode_output_is_concatenation() {
        let mut dec = decoder();
        let frags = vec![
            Fragment {
                fragment_id: "a".into(),
                data: vec![1, 2, 3],
            },
            Fragment {
                fragment_id: "b".into(),
                data: vec![4, 5, 6],
            },
        ];
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.output_data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_decode_proof_id_format() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();
        assert!(proof.proof_id.starts_with("rp-"));
    }

    #[test]
    fn test_decode_timestamp_propagated() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                9999,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.proof.unwrap().timestamp_epoch_secs, 9999);
    }

    #[test]
    fn test_decode_trace_id_propagated() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "trace-xyz",
            )
            .unwrap();
        assert_eq!(result.proof.unwrap().trace_id, "trace-xyz");
    }

    // ── ProofMode tests ──

    #[test]
    fn test_mode_mandatory() {
        let dec = ProofCarryingDecoder::new(ProofMode::Mandatory, "s", "k");
        assert_eq!(dec.mode(), ProofMode::Mandatory);
    }

    #[test]
    fn test_mode_advisory() {
        let dec = ProofCarryingDecoder::new(ProofMode::Advisory, "s", "k");
        assert_eq!(dec.mode(), ProofMode::Advisory);
    }

    #[test]
    fn test_mode_switch() {
        let mut dec = decoder();
        assert_eq!(dec.mode(), ProofMode::Mandatory);
        dec.set_mode(ProofMode::Advisory);
        assert_eq!(dec.mode(), ProofMode::Advisory);
    }

    // ── Register algorithm tests ──

    #[test]
    fn test_register_algorithm() {
        let mut dec = decoder();
        let initial = dec.registered_algorithms().len();
        dec.register_algorithm(AlgorithmId::new("custom_algo"));
        assert_eq!(dec.registered_algorithms().len(), initial + 1);
    }

    #[test]
    fn test_register_duplicate_algorithm() {
        let mut dec = decoder();
        let initial = dec.registered_algorithms().len();
        dec.register_algorithm(AlgorithmId::new("simple_concat"));
        assert_eq!(dec.registered_algorithms().len(), initial);
    }

    // ── ProofVerificationApi tests ──

    #[test]
    fn test_verify_valid_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();

        let mut hasher = Sha256::new();
        hasher.update(b"proof_carrying_output_v1:");
        hasher.update(&result.output_data);
        let recomputed = hex::encode(hasher.finalize());

        let v = api.verify(&proof, &original_hashes, &recomputed);
        assert!(v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_VERIFIED);
    }

    #[test]
    fn test_verify_tampered_fragment_hash() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();

        let api = verification_api();
        let mut original_hashes: Vec<String> =
            frags.iter().map(|f| hex::encode(f.hash())).collect();
        original_hashes[0] = "tampered_hash".to_string();

        let v = api.verify(&proof, &original_hashes, &proof.output_hash);
        assert!(!v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_INVALID);
    }

    #[test]
    fn test_verify_wrong_algorithm() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let mut proof = result.proof.unwrap();
        proof.algorithm_id = AlgorithmId::new("nonexistent_algo");

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();
        let v = api.verify(&proof, &original_hashes, &proof.output_hash);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_verify_output_hash_mismatch() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();
        let v = api.verify(&proof, &original_hashes, "wrong_output_hash");
        assert!(!v.is_valid());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let mut proof = result.proof.unwrap();
        proof.attestation.signature = "forged".to_string();

        let api = verification_api();
        let original_hashes: Vec<String> = frags.iter().map(|f| hex::encode(f.hash())).collect();

        let mut hasher = Sha256::new();
        hasher.update(b"proof_carrying_output_v1:");
        hasher.update(&result.output_data);
        let recomputed = hex::encode(hasher.finalize());

        let v = api.verify(&proof, &original_hashes, &recomputed);
        assert!(!v.is_valid());
        assert_eq!(v.event_code(), REPAIR_PROOF_INVALID);
    }

    // ── Proof presence check tests ──

    #[test]
    fn test_presence_mandatory_with_proof() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let api = verification_api();
        let check =
            api.check_proof_presence(result.proof.as_ref(), ProofMode::Mandatory, "obj-001");
        assert!(check.is_ok());
    }

    #[test]
    fn test_presence_mandatory_without_proof() {
        let api = verification_api();
        let err = api
            .check_proof_presence(None, ProofMode::Mandatory, "obj-001")
            .unwrap_err();
        assert_eq!(err.code(), "PROOF_MISSING_MANDATORY");
    }

    #[test]
    fn test_presence_advisory_without_proof() {
        let api = verification_api();
        let check = api.check_proof_presence(None, ProofMode::Advisory, "obj-001");
        assert!(check.is_ok());
    }

    // ── VerificationResult tests ──

    #[test]
    fn test_verification_result_event_codes() {
        assert_eq!(
            VerificationResult::Valid.event_code(),
            REPAIR_PROOF_VERIFIED
        );
        assert_eq!(
            VerificationResult::MissingProof.event_code(),
            REPAIR_PROOF_MISSING
        );
        let inv = VerificationResult::InvalidSignature;
        assert_eq!(inv.event_code(), REPAIR_PROOF_INVALID);
    }

    // ── Serialization tests ──

    #[test]
    fn test_repair_proof_roundtrip() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let proof = result.proof.unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: RepairProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_id, proof.object_id);
        assert_eq!(parsed.output_hash, proof.output_hash);
    }

    #[test]
    fn test_decode_result_roundtrip() {
        let mut dec = decoder();
        let frags = test_fragments();
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: DecodeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.object_id, "obj-001");
    }

    #[test]
    fn test_proof_mode_roundtrip() {
        let json = serde_json::to_string(&ProofMode::Mandatory).unwrap();
        let parsed: ProofMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ProofMode::Mandatory);
    }

    // ── Error display tests ──

    #[test]
    fn test_error_display_missing() {
        let err = ProofCarryingDecodeError::MissingProofInMandatoryMode {
            object_id: "obj-1".to_string(),
        };
        assert!(err.to_string().contains("PROOF_MISSING_MANDATORY"));
    }

    #[test]
    fn test_error_display_invalid() {
        let err = ProofCarryingDecodeError::InvalidProof {
            object_id: "obj-1".to_string(),
            reason: "bad hash".to_string(),
        };
        assert!(err.to_string().contains("PROOF_INVALID"));
    }

    #[test]
    fn test_error_display_reconstruction() {
        let err = ProofCarryingDecodeError::ReconstructionFailed {
            object_id: "obj-1".to_string(),
            reason: "no fragments".to_string(),
        };
        assert!(err.to_string().contains("RECONSTRUCTION_FAILED"));
    }

    // ── Determinism test (INV-REPAIR-PROOF-DETERMINISTIC) ──

    #[test]
    fn test_proof_deterministic() {
        let frags = test_fragments();
        let mut dec1 = decoder();
        let mut dec2 = decoder();
        let r1 = dec1
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let r2 = dec2
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        let p1 = r1.proof.unwrap();
        let p2 = r2.proof.unwrap();
        assert_eq!(p1.output_hash, p2.output_hash);
        assert_eq!(p1.attestation.signature, p2.attestation.signature);
    }

    // ── Multiple decodes test ──

    #[test]
    fn test_multiple_decodes_audit_log() {
        let mut dec = decoder();
        let frags = test_fragments();
        dec.decode(
            "obj-001",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1000,
            "t-1",
        )
        .unwrap();
        dec.decode(
            "obj-002",
            &frags,
            &AlgorithmId::new("simple_concat"),
            1001,
            "t-2",
        )
        .unwrap();
        assert_eq!(dec.audit_log().len(), 2);
    }

    // ── Single fragment test ──

    #[test]
    fn test_decode_single_fragment() {
        let mut dec = decoder();
        let frags = vec![Fragment {
            fragment_id: "single".into(),
            data: vec![0xFF; 8],
        }];
        let result = dec
            .decode(
                "obj-001",
                &frags,
                &AlgorithmId::new("simple_concat"),
                1000,
                "t-1",
            )
            .unwrap();
        assert_eq!(result.output_data, vec![0xFF; 8]);
        assert_eq!(result.proof.unwrap().fragment_count, 1);
    }
}
