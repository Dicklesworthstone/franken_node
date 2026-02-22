//! Threshold signature verification for connector publication artifacts (bd-35q1).
//!
//! Publication requires a configured k-of-n quorum. Partial signature sets
//! below threshold are rejected. Verification failures produce stable,
//! machine-readable failure reasons.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};

// ── Types ───────────────────────────────────────────────────────────

/// Threshold configuration: k-of-n quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub threshold: u32,
    pub total_signers: u32,
    pub signer_keys: Vec<SignerKey>,
}

impl ThresholdConfig {
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.threshold == 0 {
            return Err(ThresholdError::ConfigInvalid {
                reason: "threshold must be > 0".to_string(),
            });
        }
        if self.threshold > self.total_signers {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "threshold {} exceeds total_signers {}",
                    self.threshold, self.total_signers
                ),
            });
        }
        if self.signer_keys.len() != self.total_signers as usize {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "signer_keys count {} != total_signers {}",
                    self.signer_keys.len(),
                    self.total_signers
                ),
            });
        }
        Ok(())
    }
}

/// A signer's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerKey {
    pub key_id: String,
    pub public_key_hex: String,
}

/// A partial signature from one signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignature {
    pub signer_id: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// A publication artifact with collected signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationArtifact {
    pub artifact_id: String,
    pub connector_id: String,
    pub content_hash: String,
    pub signatures: Vec<PartialSignature>,
}

// ── Verification result ─────────────────────────────────────────────

/// Result of threshold signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub artifact_id: String,
    pub verified: bool,
    pub valid_signatures: u32,
    pub threshold: u32,
    pub failure_reason: Option<FailureReason>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Reason for verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    BelowThreshold { have: u32, need: u32 },
    UnknownSigner { signer_id: String },
    InvalidSignature { signer_id: String },
    DuplicateSigner { signer_id: String },
    ConfigInvalid { reason: String },
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowThreshold { have, need } => {
                write!(f, "THRESH_BELOW_QUORUM: have {have}, need {need}")
            }
            Self::UnknownSigner { signer_id } => {
                write!(f, "THRESH_UNKNOWN_SIGNER: {signer_id}")
            }
            Self::InvalidSignature { signer_id } => {
                write!(f, "THRESH_INVALID_SIG: {signer_id}")
            }
            Self::DuplicateSigner { signer_id } => {
                write!(f, "duplicate signer: {signer_id}")
            }
            Self::ConfigInvalid { reason } => {
                write!(f, "THRESH_CONFIG_INVALID: {reason}")
            }
        }
    }
}

// ── Signature verification ──────────────────────────────────────────

/// Simulate signature verification. In production this would use Ed25519
/// or similar. Here we verify: H(key || content_hash) == signature.
fn verify_signature(key: &SignerKey, content_hash: &str, sig: &PartialSignature) -> bool {
    let mut hasher = DefaultHasher::new();
    key.public_key_hex.hash(&mut hasher);
    ":".hash(&mut hasher);
    content_hash.hash(&mut hasher);
    let expected = format!("{:016x}", hasher.finish());
    sig.signature_hex == expected
}

/// Create a valid signature for testing.
pub fn sign(key: &SignerKey, content_hash: &str) -> PartialSignature {
    let mut hasher = DefaultHasher::new();
    key.public_key_hex.hash(&mut hasher);
    ":".hash(&mut hasher);
    content_hash.hash(&mut hasher);
    PartialSignature {
        signer_id: key.key_id.clone(),
        key_id: key.key_id.clone(),
        signature_hex: format!("{:016x}", hasher.finish()),
    }
}

/// Verify a publication artifact against a threshold config.
pub fn verify_threshold(
    config: &ThresholdConfig,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
) -> VerificationResult {
    // Validate config first
    if let Err(e) = config.validate() {
        return VerificationResult {
            artifact_id: artifact.artifact_id.clone(),
            verified: false,
            valid_signatures: 0,
            threshold: config.threshold,
            failure_reason: Some(FailureReason::ConfigInvalid {
                reason: e.to_string(),
            }),
            trace_id: trace_id.to_string(),
            timestamp: timestamp.to_string(),
        };
    }

    let known_key_ids: HashSet<&str> = config
        .signer_keys
        .iter()
        .map(|k| k.key_id.as_str())
        .collect();
    let mut seen_signers: HashSet<&str> = HashSet::new();
    let mut seen_key_ids: HashSet<&str> = HashSet::new();
    let mut valid_count = 0u32;
    let mut first_failure: Option<FailureReason> = None;

    for sig in &artifact.signatures {
        // Check for unknown signer
        if !known_key_ids.contains(sig.key_id.as_str()) {
            if first_failure.is_none() {
                first_failure = Some(FailureReason::UnknownSigner {
                    signer_id: sig.signer_id.clone(),
                });
            }
            continue;
        }

        // A signer key can only contribute once toward quorum.
        if !seen_key_ids.insert(sig.key_id.as_str()) {
            if first_failure.is_none() {
                first_failure = Some(FailureReason::DuplicateSigner {
                    signer_id: sig.signer_id.clone(),
                });
            }
            continue;
        }

        // Signer IDs must also be unique within the signature set.
        if !seen_signers.insert(sig.signer_id.as_str()) {
            if first_failure.is_none() {
                first_failure = Some(FailureReason::DuplicateSigner {
                    signer_id: sig.signer_id.clone(),
                });
            }
            continue;
        }

        // Verify signature
        let key = config.signer_keys.iter().find(|k| k.key_id == sig.key_id);
        if let Some(key) = key {
            if verify_signature(key, &artifact.content_hash, sig) {
                valid_count += 1;
            } else if first_failure.is_none() {
                first_failure = Some(FailureReason::InvalidSignature {
                    signer_id: sig.signer_id.clone(),
                });
            }
        }
    }

    let verified = valid_count >= config.threshold;
    let failure_reason = if verified {
        None
    } else {
        first_failure.or(Some(FailureReason::BelowThreshold {
            have: valid_count,
            need: config.threshold,
        }))
    };

    VerificationResult {
        artifact_id: artifact.artifact_id.clone(),
        verified,
        valid_signatures: valid_count,
        threshold: config.threshold,
        failure_reason,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for threshold signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdError {
    #[serde(rename = "THRESH_BELOW_QUORUM")]
    BelowQuorum { have: u32, need: u32 },
    #[serde(rename = "THRESH_UNKNOWN_SIGNER")]
    UnknownSigner { signer_id: String },
    #[serde(rename = "THRESH_INVALID_SIG")]
    InvalidSignature { signer_id: String },
    #[serde(rename = "THRESH_CONFIG_INVALID")]
    ConfigInvalid { reason: String },
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowQuorum { have, need } => {
                write!(f, "THRESH_BELOW_QUORUM: have {have}, need {need}")
            }
            Self::UnknownSigner { signer_id } => {
                write!(f, "THRESH_UNKNOWN_SIGNER: {signer_id}")
            }
            Self::InvalidSignature { signer_id } => {
                write!(f, "THRESH_INVALID_SIG: {signer_id}")
            }
            Self::ConfigInvalid { reason } => {
                write!(f, "THRESH_CONFIG_INVALID: {reason}")
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(n: u32) -> Vec<SignerKey> {
        (0..n)
            .map(|i| SignerKey {
                key_id: format!("signer-{i}"),
                public_key_hex: format!("pubkey_{i:04x}"),
            })
            .collect()
    }

    fn test_config(k: u32, n: u32) -> ThresholdConfig {
        ThresholdConfig {
            threshold: k,
            total_signers: n,
            signer_keys: test_keys(n),
        }
    }

    fn signed_artifact(config: &ThresholdConfig, hash: &str, count: usize) -> PublicationArtifact {
        let sigs: Vec<PartialSignature> = config
            .signer_keys
            .iter()
            .take(count)
            .map(|key| sign(key, hash))
            .collect();
        PublicationArtifact {
            artifact_id: "art-1".into(),
            connector_id: "conn-1".into(),
            content_hash: hash.to_string(),
            signatures: sigs,
        }
    }

    // === Config validation ===

    #[test]
    fn config_valid() {
        assert!(test_config(2, 3).validate().is_ok());
    }

    #[test]
    fn config_threshold_zero_invalid() {
        let c = test_config(0, 3);
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_threshold_exceeds_total() {
        let mut c = test_config(5, 3);
        c.threshold = 5;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_key_count_mismatch() {
        let mut c = test_config(2, 3);
        c.signer_keys.pop();
        assert!(c.validate().is_err());
    }

    // === Threshold verification ===

    #[test]
    fn full_quorum_passes() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 3);
        let result = verify_threshold(&config, &artifact, "t1", "ts");
        assert!(result.verified);
        assert_eq!(result.valid_signatures, 3);
    }

    #[test]
    fn exact_threshold_passes() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "t2", "ts");
        assert!(result.verified);
        assert_eq!(result.valid_signatures, 2);
    }

    #[test]
    fn below_threshold_rejected() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 1);
        let result = verify_threshold(&config, &artifact, "t3", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::BelowThreshold { have: 1, need: 2 })
        ));
    }

    #[test]
    fn zero_signatures_rejected() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 0);
        let result = verify_threshold(&config, &artifact, "t4", "ts");
        assert!(!result.verified);
    }

    // === Unknown signer ===

    #[test]
    fn unknown_signer_not_counted() {
        let config = test_config(2, 3);
        let mut artifact = signed_artifact(&config, "hash-abc", 1);
        artifact.signatures.push(PartialSignature {
            signer_id: "unknown-signer".into(),
            key_id: "unknown-key".into(),
            signature_hex: "deadbeef00000000".into(),
        });
        let result = verify_threshold(&config, &artifact, "t5", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    // === Invalid signature ===

    #[test]
    fn invalid_signature_not_counted() {
        let config = test_config(2, 3);
        let mut artifact = signed_artifact(&config, "hash-abc", 1);
        artifact.signatures.push(PartialSignature {
            signer_id: "signer-1".into(),
            key_id: "signer-1".into(),
            signature_hex: "badbadbadbadbadb".into(), // wrong signature
        });
        let result = verify_threshold(&config, &artifact, "t6", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    // === Duplicate signer ===

    #[test]
    fn duplicate_signer_counted_once() {
        let config = test_config(2, 3);
        let mut artifact = signed_artifact(&config, "hash-abc", 1);
        // Add same signer again
        artifact
            .signatures
            .push(sign(&config.signer_keys[0], "hash-abc"));
        let result = verify_threshold(&config, &artifact, "t7", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    #[test]
    fn duplicate_key_with_different_signer_id_counted_once() {
        let config = test_config(2, 3);
        let mut artifact = signed_artifact(&config, "hash-abc", 1);

        let mut replay = sign(&config.signer_keys[0], "hash-abc");
        replay.signer_id = "signer-0-alias".to_string();
        artifact.signatures.push(replay);

        let result = verify_threshold(&config, &artifact, "t7b", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::DuplicateSigner { .. })
        ));
    }

    // === Trace and timestamp ===

    #[test]
    fn result_has_trace_id() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "trace-xyz", "ts");
        assert_eq!(result.trace_id, "trace-xyz");
    }

    // === sign helper ===

    #[test]
    fn sign_deterministic() {
        let key = &test_keys(1)[0];
        let s1 = sign(key, "hash");
        let s2 = sign(key, "hash");
        assert_eq!(s1.signature_hex, s2.signature_hex);
    }

    #[test]
    fn sign_different_for_different_hashes() {
        let key = &test_keys(1)[0];
        let s1 = sign(key, "hash-a");
        let s2 = sign(key, "hash-b");
        assert_ne!(s1.signature_hex, s2.signature_hex);
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_result() {
        let config = test_config(2, 3);
        let artifact = signed_artifact(&config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "t8", "ts");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn serde_roundtrip_config() {
        let config = test_config(2, 3);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ThresholdConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = ThresholdError::BelowQuorum { have: 1, need: 2 };
        assert!(e1.to_string().contains("THRESH_BELOW_QUORUM"));

        let e2 = ThresholdError::UnknownSigner {
            signer_id: "x".into(),
        };
        assert!(e2.to_string().contains("THRESH_UNKNOWN_SIGNER"));

        let e3 = ThresholdError::InvalidSignature {
            signer_id: "y".into(),
        };
        assert!(e3.to_string().contains("THRESH_INVALID_SIG"));

        let e4 = ThresholdError::ConfigInvalid {
            reason: "bad".into(),
        };
        assert!(e4.to_string().contains("THRESH_CONFIG_INVALID"));
    }

    // === Failure reason display ===

    #[test]
    fn failure_reason_display() {
        let r = FailureReason::BelowThreshold { have: 1, need: 3 };
        assert!(r.to_string().contains("THRESH_BELOW_QUORUM"));
    }
}
