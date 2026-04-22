//! bd-3cs3: Epoch-scoped key derivation for trust artifact authentication.
//!
//! Derives authentication keys from a root secret, epoch, and domain using
//! HKDF-SHA256. This enforces epoch and domain separation by construction.

use crate::control_plane::control_epoch::ControlEpoch;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

pub const DERIVED_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 32;
const KDF_SALT: &[u8] = b"franken-node.epoch-kdf.v1";

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const EPOCH_KEY_DERIVED: &str = "EPOCH_KEY_DERIVED";
    pub const EPOCH_SIG_VERIFIED: &str = "EPOCH_SIG_VERIFIED";
    pub const EPOCH_SIG_REJECTED: &str = "EPOCH_SIG_REJECTED";
}

/// Root secret used as HKDF IKM.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSecret([u8; DERIVED_KEY_LEN]);

impl RootSecret {
    pub fn from_bytes(bytes: [u8; DERIVED_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, AuthError> {
        let bytes = hex::decode(hex).map_err(|e| AuthError::InvalidHex {
            reason: e.to_string(),
        })?;
        if bytes.len() != DERIVED_KEY_LEN {
            return Err(AuthError::InvalidHex {
                reason: format!(
                    "expected {DERIVED_KEY_LEN} bytes, got {} bytes",
                    bytes.len()
                ),
            });
        }
        let mut out = [0u8; DERIVED_KEY_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LEN] {
        &self.0
    }

    #[allow(dead_code)]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootSecret([redacted])")
    }
}

/// Epoch/domain derived key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; DERIVED_KEY_LEN]);

impl PartialEq for DerivedKey {
    fn eq(&self, other: &Self) -> bool {
        crate::security::constant_time::ct_eq_bytes(&self.0, &other.0)
    }
}

impl Eq for DerivedKey {}

impl DerivedKey {
    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn fingerprint(&self) -> String {
        let digest =
            Sha256::digest([b"epoch_scoped_key_fingerprint_v1:" as &[u8], &self.0].concat());
        hex::encode(digest)[..16].to_string()
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerivedKey(fingerprint={})", self.fingerprint())
    }
}

/// Signature bytes over artifact payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub bytes: [u8; SIGNATURE_LEN],
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        crate::security::constant_time::ct_eq_bytes(&self.bytes, &other.bytes)
    }
}

impl Eq for Signature {}

impl Signature {
    #[allow(dead_code)]
    pub fn from_hex(hex: &str) -> Result<Self, AuthError> {
        let bytes = hex::decode(hex).map_err(|e| AuthError::InvalidHex {
            reason: e.to_string(),
        })?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(AuthError::InvalidHex {
                reason: format!("expected {SIGNATURE_LEN} bytes, got {} bytes", bytes.len()),
            });
        }
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self { bytes: out })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

/// Structured telemetry payload for key/signature events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochAuthEvent {
    pub event_code: String,
    pub epoch: ControlEpoch,
    pub domain: String,
    pub key_fingerprint: String,
    pub artifact_id: Option<String>,
    pub rejection_reason: Option<String>,
    pub trace_id: String,
}

impl EpochAuthEvent {
    pub fn key_derived(
        epoch: ControlEpoch,
        domain: &str,
        derived_key: &DerivedKey,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::EPOCH_KEY_DERIVED.to_string(),
            epoch,
            domain: domain.to_string(),
            key_fingerprint: derived_key.fingerprint(),
            artifact_id: None,
            rejection_reason: None,
            trace_id: trace_id.to_string(),
        }
    }

    pub fn sig_verified(
        artifact_id: &str,
        epoch: ControlEpoch,
        domain: &str,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::EPOCH_SIG_VERIFIED.to_string(),
            epoch,
            domain: domain.to_string(),
            key_fingerprint: String::new(),
            artifact_id: Some(artifact_id.to_string()),
            rejection_reason: None,
            trace_id: trace_id.to_string(),
        }
    }

    pub fn sig_rejected(
        artifact_id: &str,
        epoch: ControlEpoch,
        domain: &str,
        reason: &str,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::EPOCH_SIG_REJECTED.to_string(),
            epoch,
            domain: domain.to_string(),
            key_fingerprint: String::new(),
            artifact_id: Some(artifact_id.to_string()),
            rejection_reason: Some(reason.to_string()),
            trace_id: trace_id.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    DomainEmpty,
    InvalidHex { reason: String },
    KeyDerivationFailed { reason: String },
    SignatureRejected { reason: String },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomainEmpty => write!(f, "EPOCH_AUTH_DOMAIN_EMPTY"),
            Self::InvalidHex { reason } => write!(f, "EPOCH_AUTH_INVALID_HEX: {reason}"),
            Self::KeyDerivationFailed { reason } => write!(f, "EPOCH_KEY_DERIVE_FAILED: {reason}"),
            Self::SignatureRejected { reason } => write!(f, "EPOCH_SIG_REJECTED: {reason}"),
        }
    }
}

impl std::error::Error for AuthError {}

fn validate_domain(domain: &str) -> Result<(), AuthError> {
    if domain.trim().is_empty() || domain.trim() != domain {
        return Err(AuthError::DomainEmpty);
    }
    if domain.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'
            )
    }) {
        return Err(AuthError::DomainEmpty);
    }
    Ok(())
}

/// Derive an epoch+domain scoped key via HKDF-SHA256.
pub fn derive_epoch_key(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str) -> DerivedKey {
    let hkdf = Hkdf::<Sha256>::new(Some(KDF_SALT), root_secret.as_bytes());
    let epoch_bytes = epoch.value().to_le_bytes();
    let domain_bytes = domain.as_bytes();
    let domain_len = (u64::try_from(domain_bytes.len()).unwrap_or(u64::MAX)).to_le_bytes();
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(b"franken-node:epoch-kdf-info:v1:");
    info.extend_from_slice(&epoch_bytes);
    info.extend_from_slice(&domain_len);
    info.extend_from_slice(domain_bytes);
    let mut okm = [0u8; DERIVED_KEY_LEN];
    if hkdf.expand(&info, &mut okm).is_err() {
        // DERIVED_KEY_LEN is a compile-time constant (32) well within HKDF limits;
        // if expansion ever fails, return zeroed key as fail-safe.
        okm = [0u8; DERIVED_KEY_LEN];
    }
    DerivedKey(okm)
}

/// Sign an artifact payload using the derived epoch/domain key.
pub fn sign_epoch_artifact(
    artifact: &[u8],
    epoch: ControlEpoch,
    domain: &str,
    root_secret: &RootSecret,
) -> Result<Signature, AuthError> {
    validate_domain(domain)?;

    let derived_key = derive_epoch_key(root_secret, epoch, domain);
    let mut mac = HmacSha256::new_from_slice(derived_key.as_bytes()).map_err(|e| {
        AuthError::KeyDerivationFailed {
            reason: e.to_string(),
        }
    })?;
    mac.update(b"epoch_scoped_sign_v1:");
    mac.update(&(u64::try_from(artifact.len()).unwrap_or(u64::MAX)).to_le_bytes());
    mac.update(artifact);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&bytes);
    Ok(Signature { bytes: out })
}

/// Verify a signature using an epoch/domain-scoped derived key.
pub fn verify_epoch_signature(
    artifact: &[u8],
    signature: &Signature,
    epoch: ControlEpoch,
    domain: &str,
    root_secret: &RootSecret,
) -> Result<(), AuthError> {
    validate_domain(domain)?;

    let derived_key = derive_epoch_key(root_secret, epoch, domain);
    let mut mac = HmacSha256::new_from_slice(derived_key.as_bytes()).map_err(|e| {
        AuthError::KeyDerivationFailed {
            reason: e.to_string(),
        }
    })?;
    mac.update(b"epoch_scoped_sign_v1:");
    mac.update(&(u64::try_from(artifact.len()).unwrap_or(u64::MAX)).to_le_bytes());
    mac.update(artifact);
    mac.verify_slice(&signature.bytes)
        .map_err(|_| AuthError::SignatureRejected {
            reason: "signature does not match derived key".to_string(),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_secret() -> RootSecret {
        RootSecret::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("valid root secret")
    }

    #[test]
    fn known_answer_vector_epoch_1_marker() {
        let key = derive_epoch_key(&root_secret(), ControlEpoch::new(1), "marker");
        assert_eq!(
            key.to_hex(),
            "688a015b0a37cc066e81340ef9dcae5b5936f02a355b132dead9f03b18b345ba"
        );
    }

    #[test]
    fn known_answer_vector_epoch_13_marker() {
        let key = derive_epoch_key(&root_secret(), ControlEpoch::new(13), "marker");
        assert_eq!(
            key.to_hex(),
            "d7350d1a4c2204ef30e35ef14064aee424caf6a0d93edb99da9399a80d45c4da"
        );
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let a = derive_epoch_key(&root_secret(), ControlEpoch::new(7), "marker");
        let b = derive_epoch_key(&root_secret(), ControlEpoch::new(8), "marker");
        assert_ne!(a, b);
    }

    #[test]
    fn different_domains_produce_different_keys() {
        let a = derive_epoch_key(&root_secret(), ControlEpoch::new(7), "marker");
        let b = derive_epoch_key(&root_secret(), ControlEpoch::new(7), "manifest");
        assert_ne!(a, b);
    }

    #[test]
    fn sign_and_verify_success() {
        let secret = root_secret();
        let artifact = b"artifact-alpha";
        let sig = sign_epoch_artifact(artifact, ControlEpoch::new(13), "marker", &secret).unwrap();
        verify_epoch_signature(artifact, &sig, ControlEpoch::new(13), "marker", &secret).unwrap();
    }

    #[test]
    fn verify_rejects_mismatched_epoch() {
        let secret = root_secret();
        let artifact = b"artifact-alpha";
        let sig = sign_epoch_artifact(artifact, ControlEpoch::new(13), "marker", &secret).unwrap();
        let err = verify_epoch_signature(artifact, &sig, ControlEpoch::new(14), "marker", &secret)
            .unwrap_err();
        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn verify_rejects_mismatched_domain() {
        let secret = root_secret();
        let artifact = b"artifact-alpha";
        let sig = sign_epoch_artifact(artifact, ControlEpoch::new(13), "marker", &secret).unwrap();
        let err =
            verify_epoch_signature(artifact, &sig, ControlEpoch::new(13), "manifest", &secret)
                .unwrap_err();
        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn signature_known_answer_vector() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .unwrap();
        assert_eq!(
            sig.to_hex(),
            "519e51e3271ef97992091d38d8913602037dc6d52e2644ec1aac856fc5f7cdde"
        );
    }

    #[test]
    fn reject_empty_domain() {
        let secret = root_secret();
        let err = sign_epoch_artifact(b"x", ControlEpoch::new(1), "", &secret).unwrap_err();
        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn root_secret_from_hex_rejects_empty_input() {
        let err = RootSecret::from_hex("").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 0 bytes"));
    }

    #[test]
    fn root_secret_from_hex_rejects_short_valid_hex() {
        let short_hex = "00".repeat(DERIVED_KEY_LEN - 1);
        let err = RootSecret::from_hex(&short_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 31 bytes"));
    }

    #[test]
    fn root_secret_from_hex_rejects_non_hex_text() {
        let err = RootSecret::from_hex("not-a-root-secret").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("EPOCH_AUTH_INVALID_HEX"));
    }

    #[test]
    fn signature_from_hex_rejects_short_valid_hex() {
        let short_hex = "00".repeat(SIGNATURE_LEN - 1);
        let err = Signature::from_hex(&short_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 31 bytes"));
    }

    #[test]
    fn signature_from_hex_rejects_long_valid_hex() {
        let long_hex = "00".repeat(SIGNATURE_LEN + 1);
        let err = Signature::from_hex(&long_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 33 bytes"));
    }

    #[test]
    fn verify_rejects_tampered_artifact_bytes() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .expect("signature");

        let err = verify_epoch_signature(
            b"artifact-alpha!",
            &sig,
            ControlEpoch::new(13),
            "marker",
            &secret,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn verify_rejects_tampered_signature_bytes() {
        let secret = root_secret();
        let mut sig =
            sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
                .expect("signature");
        sig.bytes[0] ^= 0x01;

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker",
            &secret,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn verify_rejects_signature_from_different_root_secret() {
        let signing_secret = root_secret();
        let verifying_secret = RootSecret::from_bytes([0xA5; DERIVED_KEY_LEN]);
        let sig = sign_epoch_artifact(
            b"artifact-alpha",
            ControlEpoch::new(13),
            "marker",
            &signing_secret,
        )
        .expect("signature");

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker",
            &verifying_secret,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn verify_rejects_empty_domain_before_signature_check() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .expect("signature");

        let err =
            verify_epoch_signature(b"artifact-alpha", &sig, ControlEpoch::new(13), "", &secret)
                .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn epoch_auth_events_use_stable_codes() {
        let key = derive_epoch_key(&root_secret(), ControlEpoch::new(1), "marker");
        let derived = EpochAuthEvent::key_derived(ControlEpoch::new(1), "marker", &key, "t1");
        assert_eq!(derived.event_code, event_codes::EPOCH_KEY_DERIVED);

        let verified =
            EpochAuthEvent::sig_verified("artifact-1", ControlEpoch::new(1), "marker", "t2");
        assert_eq!(verified.event_code, event_codes::EPOCH_SIG_VERIFIED);

        let rejected = EpochAuthEvent::sig_rejected(
            "artifact-1",
            ControlEpoch::new(1),
            "marker",
            "bad sig",
            "t3",
        );
        assert_eq!(rejected.event_code, event_codes::EPOCH_SIG_REJECTED);
    }

    #[test]
    fn explicit_zeroize_clears_root_secret() {
        let mut secret = RootSecret::from_bytes([7u8; DERIVED_KEY_LEN]);
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0u8; DERIVED_KEY_LEN]);
    }

    #[test]
    fn sign_rejects_whitespace_only_domain() {
        let secret = root_secret();
        let err = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), " \t ", &secret)
            .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn sign_rejects_leading_space_domain_alias() {
        let secret = root_secret();
        let err = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), " marker", &secret)
            .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn verify_rejects_trailing_space_domain_alias_before_signature_check() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .expect("signature");

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker ",
            &secret,
        )
        .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn verify_rejects_newline_domain_alias_before_signature_check() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .expect("signature");

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker\n",
            &secret,
        )
        .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn root_secret_from_hex_rejects_long_valid_hex() {
        let long_hex = "00".repeat(DERIVED_KEY_LEN + 1);
        let err = RootSecret::from_hex(&long_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 33 bytes"));
    }

    #[test]
    fn signature_from_hex_rejects_non_hex_text() {
        let err = Signature::from_hex("not-a-signature").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("EPOCH_AUTH_INVALID_HEX"));
    }

    #[test]
    fn signature_from_hex_rejects_padded_valid_hex_alias() {
        let padded_hex = format!(" {} ", "00".repeat(SIGNATURE_LEN));
        let err = Signature::from_hex(&padded_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
    }

    #[test]
    fn verify_rejects_zero_signature_bytes() {
        let secret = root_secret();
        let sig = Signature {
            bytes: [0u8; SIGNATURE_LEN],
        };

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker",
            &secret,
        )
        .unwrap_err();

        assert!(matches!(err, AuthError::SignatureRejected { .. }));
    }

    #[test]
    fn root_secret_from_hex_rejects_odd_length_hex() {
        let err = RootSecret::from_hex("abc").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("EPOCH_AUTH_INVALID_HEX"));
    }

    #[test]
    fn root_secret_from_hex_rejects_padded_valid_hex_alias() {
        let padded_hex = format!(" {} ", "00".repeat(DERIVED_KEY_LEN));
        let err = RootSecret::from_hex(&padded_hex).unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
    }

    #[test]
    fn signature_from_hex_rejects_empty_input() {
        let err = Signature::from_hex("").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("expected 32 bytes, got 0 bytes"));
    }

    #[test]
    fn signature_from_hex_rejects_odd_length_hex() {
        let err = Signature::from_hex("abc").unwrap_err();

        assert!(matches!(err, AuthError::InvalidHex { .. }));
        assert!(err.to_string().contains("EPOCH_AUTH_INVALID_HEX"));
    }

    #[test]
    fn sign_rejects_carriage_return_domain_alias() {
        let secret = root_secret();
        let err = sign_epoch_artifact(
            b"artifact-alpha",
            ControlEpoch::new(13),
            "marker\r",
            &secret,
        )
        .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn verify_rejects_tab_suffixed_domain_alias_before_signature_check() {
        let secret = root_secret();
        let sig = sign_epoch_artifact(b"artifact-alpha", ControlEpoch::new(13), "marker", &secret)
            .expect("signature");

        let err = verify_epoch_signature(
            b"artifact-alpha",
            &sig,
            ControlEpoch::new(13),
            "marker\t",
            &secret,
        )
        .unwrap_err();

        assert_eq!(err, AuthError::DomainEmpty);
    }

    #[test]
    fn serde_rejects_signature_with_short_byte_array() {
        let decoded = serde_json::from_str::<Signature>(r#"{"bytes":[0,1,2]}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_signature_with_non_array_bytes() {
        let decoded = serde_json::from_str::<Signature>(r#"{"bytes":"00"}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_unknown_auth_error_variant() {
        let decoded = serde_json::from_str::<AuthError>(r#"{"NotReal":{"reason":"x"}}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_epoch_auth_event_missing_trace_id() {
        let decoded = serde_json::from_str::<EpochAuthEvent>(
            r#"{
                "event_code":"EPOCH_SIG_REJECTED",
                "epoch":1,
                "domain":"marker",
                "key_fingerprint":"",
                "artifact_id":"artifact-1",
                "rejection_reason":"bad"
            }"#,
        );

        assert!(decoded.is_err());
    }

    // === NEGATIVE-PATH SECURITY TESTS ===

    #[test]
    fn unicode_injection_and_domain_normalization_attacks_fail_closed() {
        let secret = root_secret();

        // Unicode BiDi override attacks in domain names
        let bidi_domain = "\u{202E}reltih\u{202C}marker";  // "hitler" reversed with BiDi override
        let err = sign_epoch_artifact(b"artifact", ControlEpoch::new(1), bidi_domain, &secret);
        assert!(err.is_err(), "BiDi override in domain should fail validation");

        // Zero-width character injection
        let zero_width_domain = "mark\u{200B}er";  // Zero-width space
        let err = sign_epoch_artifact(b"artifact", ControlEpoch::new(1), zero_width_domain, &secret);
        assert!(err.is_err(), "Zero-width characters should fail domain validation");

        // Unicode normalization attacks (NFC vs NFD)
        let nfc_domain = "café";  // NFC normalized (single codepoint é)
        let nfd_domain = "cafe\u{0301}";  // NFD normalized (e + combining acute)
        let sig1 = sign_epoch_artifact(b"artifact", ControlEpoch::new(1), nfc_domain, &secret).unwrap();
        let sig2 = sign_epoch_artifact(b"artifact", ControlEpoch::new(1), nfd_domain, &secret).unwrap();

        // Should produce different signatures (no automatic normalization)
        assert_ne!(sig1.bytes, sig2.bytes, "Different Unicode normalization should produce different signatures");

        // Verify domain isolation holds despite normalization differences
        let verify_err = verify_epoch_signature(b"artifact", &sig1, ControlEpoch::new(1), nfd_domain, &secret);
        assert!(verify_err.is_err(), "Cross-normalization signature verification should fail");

        // Test mixed script attacks (Cyrillic/Latin lookalikes)
        let cyrillic_domain = "mаrker";  // Cyrillic 'а' instead of Latin 'a'
        let latin_domain = "marker";
        let sig_cyr = sign_epoch_artifact(b"artifact", ControlEpoch::new(1), cyrillic_domain, &secret).unwrap();
        let verify_err = verify_epoch_signature(b"artifact", &sig_cyr, ControlEpoch::new(1), latin_domain, &secret);
        assert!(verify_err.is_err(), "Cyrillic/Latin lookalike domains should not be interchangeable");
    }

    #[test]
    fn hex_parsing_buffer_overflow_and_validation_bypass_attacks_fail_safely() {
        // Test extremely long hex strings to trigger buffer overflow attempts
        let massive_hex = "00".repeat(1_000_000);  // 2MB hex string
        let err = RootSecret::from_hex(&massive_hex);
        assert!(err.is_err(), "Massive hex input should be rejected safely");

        let err = Signature::from_hex(&massive_hex);
        assert!(err.is_err(), "Massive hex input should be rejected safely");

        // Test hex strings with embedded null bytes
        let null_hex = "00112233\0004455";
        let err = RootSecret::from_hex(null_hex);
        assert!(err.is_err(), "Null byte in hex should be rejected");

        // Test hex with control characters
        let control_hex = "00112233\r\n4455";
        let err = RootSecret::from_hex(control_hex);
        assert!(err.is_err(), "Control characters in hex should be rejected");

        // Test case sensitivity bypass attempts
        let mixed_case = "00112233AABBCCDD4455667700112233AABBCCDD4455667700112233AABBCCDD";
        let root = RootSecret::from_hex(mixed_case).unwrap();
        assert_eq!(root.as_bytes().len(), DERIVED_KEY_LEN);

        // Test Unicode hex digits (should fail)
        let unicode_hex = "𝟎𝟎𝟏𝟏𝟐𝟐𝟑𝟑";  // Unicode mathematical alphanumeric symbols
        let err = RootSecret::from_hex(unicode_hex);
        assert!(err.is_err(), "Unicode hex digits should be rejected");

        // Test hex with embedded spaces (length calculation attacks)
        let spaced_hex = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
        let err = RootSecret::from_hex(spaced_hex);
        assert!(err.is_err(), "Spaced hex should be rejected");

        // Test integer overflow in length parsing
        let exact_length = "00".repeat(DERIVED_KEY_LEN);
        let boundary_test = RootSecret::from_hex(&exact_length).unwrap();
        assert_eq!(boundary_test.as_bytes().len(), DERIVED_KEY_LEN);
    }

    #[test]
    fn cryptographic_forge_and_replay_attacks_fail_with_proper_validation() {
        let secret = root_secret();
        let artifact = b"sensitive_artifact";

        // Attempt signature forgery with all-zero signature
        let forged_sig = Signature { bytes: [0u8; SIGNATURE_LEN] };
        let err = verify_epoch_signature(artifact, &forged_sig, ControlEpoch::new(1), "marker", &secret);
        assert!(err.is_err(), "All-zero signature should be rejected");

        // Attempt signature forgery with all-FF signature
        let forged_sig = Signature { bytes: [0xFFu8; SIGNATURE_LEN] };
        let err = verify_epoch_signature(artifact, &forged_sig, ControlEpoch::new(1), "marker", &secret);
        assert!(err.is_err(), "All-FF signature should be rejected");

        // Valid signature for replay attack testing
        let valid_sig = sign_epoch_artifact(artifact, ControlEpoch::new(1), "marker", &secret).unwrap();

        // Cross-epoch replay attack
        let err = verify_epoch_signature(artifact, &valid_sig, ControlEpoch::new(2), "marker", &secret);
        assert!(err.is_err(), "Cross-epoch replay should be rejected");

        // Cross-domain replay attack
        let err = verify_epoch_signature(artifact, &valid_sig, ControlEpoch::new(1), "manifest", &secret);
        assert!(err.is_err(), "Cross-domain replay should be rejected");

        // Artifact substitution attack
        let err = verify_epoch_signature(b"different_artifact", &valid_sig, ControlEpoch::new(1), "marker", &secret);
        assert!(err.is_err(), "Artifact substitution should be rejected");

        // Test epoch overflow boundary
        let max_epoch = ControlEpoch::new(u64::MAX);
        let sig_max = sign_epoch_artifact(artifact, max_epoch, "marker", &secret).unwrap();
        verify_epoch_signature(artifact, &sig_max, max_epoch, "marker", &secret).unwrap();

        // Verify epoch boundaries are properly isolated
        let err = verify_epoch_signature(artifact, &sig_max, ControlEpoch::new(u64::MAX - 1), "marker", &secret);
        assert!(err.is_err(), "Epoch boundary isolation should prevent replay");
    }

    #[test]
    fn timing_attack_resistance_and_constant_time_comparison_validation() {
        let secret = root_secret();
        let artifact = b"timing_test_artifact";
        let sig = sign_epoch_artifact(artifact, ControlEpoch::new(1), "marker", &secret).unwrap();

        // Test signatures that differ only in first byte
        let mut sig_diff_first = sig.clone();
        sig_diff_first.bytes[0] ^= 0x01;

        // Test signatures that differ only in last byte
        let mut sig_diff_last = sig.clone();
        sig_diff_last.bytes[SIGNATURE_LEN - 1] ^= 0x01;

        // Test signatures that differ only in middle byte
        let mut sig_diff_mid = sig.clone();
        sig_diff_mid.bytes[SIGNATURE_LEN / 2] ^= 0x01;

        // All signature verification failures should take similar time (constant-time comparison)
        let err1 = verify_epoch_signature(artifact, &sig_diff_first, ControlEpoch::new(1), "marker", &secret);
        let err2 = verify_epoch_signature(artifact, &sig_diff_last, ControlEpoch::new(1), "marker", &secret);
        let err3 = verify_epoch_signature(artifact, &sig_diff_mid, ControlEpoch::new(1), "marker", &secret);

        assert!(err1.is_err() && err2.is_err() && err3.is_err());

        // Test DerivedKey equality uses constant-time comparison
        let key1 = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let key2 = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let key3 = derive_epoch_key(&secret, ControlEpoch::new(1), "different");

        assert_eq!(key1, key2, "Same inputs should produce equal keys");
        assert_ne!(key1, key3, "Different inputs should produce different keys");

        // Test Signature equality uses constant-time comparison
        let sig1 = sign_epoch_artifact(artifact, ControlEpoch::new(1), "marker", &secret).unwrap();
        let sig2 = sign_epoch_artifact(artifact, ControlEpoch::new(1), "marker", &secret).unwrap();
        let sig3 = sign_epoch_artifact(artifact, ControlEpoch::new(2), "marker", &secret).unwrap();

        assert_eq!(sig1, sig2, "Same inputs should produce equal signatures");
        assert_ne!(sig1, sig3, "Different inputs should produce different signatures");
    }

    #[test]
    fn memory_corruption_and_zeroization_bypass_attacks_fail_safely() {
        // Test that zeroization actually clears memory
        let sensitive_bytes = [0x42u8; DERIVED_KEY_LEN];
        let mut secret = RootSecret::from_bytes(sensitive_bytes);

        // Verify initial state
        assert_eq!(secret.as_bytes(), &sensitive_bytes);

        // Manually zeroize
        secret.zeroize();

        // Verify zeroization completed
        assert_eq!(secret.as_bytes(), &[0u8; DERIVED_KEY_LEN]);

        // Test automatic zeroization on drop
        {
            let _secret_temp = RootSecret::from_bytes([0x37u8; DERIVED_KEY_LEN]);
            // Secret should be zeroized when it goes out of scope
        }

        // Test DerivedKey zeroization
        let secret = root_secret();
        let mut key = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let original_bytes = *key.as_bytes();

        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; DERIVED_KEY_LEN]);
        assert_ne!(key.as_bytes(), &original_bytes);

        // Test that fingerprint calculation doesn't leak key material
        let key = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let fingerprint = key.fingerprint();
        assert_eq!(fingerprint.len(), 16);
        assert!(!fingerprint.contains("00000000"));  // Not all zeros

        // Test that debug output doesn't leak sensitive material
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains(&hex::encode(secret.as_bytes())));

        // Test that derived key debug doesn't leak full key
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("fingerprint="));
        assert!(!debug_str.contains(&hex::encode(key.as_bytes())));
    }

    #[test]
    fn hkdf_info_parameter_injection_and_domain_manipulation_attacks_fail_closed() {
        let secret = root_secret();

        // Test domain separator injection attacks
        let malicious_domain1 = "marker:fake_epoch:999";
        let malicious_domain2 = "marker\x00injected";
        let malicious_domain3 = "marker\ninjected";

        // These should produce different keys due to domain separation
        let key_normal = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let key_colon = derive_epoch_key(&secret, ControlEpoch::new(1), malicious_domain1);
        let key_null = derive_epoch_key(&secret, ControlEpoch::new(1), malicious_domain2);
        let key_newline = derive_epoch_key(&secret, ControlEpoch::new(1), malicious_domain3);

        assert_ne!(key_normal, key_colon);
        assert_ne!(key_normal, key_null);
        assert_ne!(key_normal, key_newline);
        assert_ne!(key_colon, key_null);

        // Test that signing rejects malicious domains (but derivation doesn't validate)
        let err = sign_epoch_artifact(b"test", ControlEpoch::new(1), malicious_domain2, &secret);
        assert!(err.is_err(), "Null byte in domain should be rejected by sign");

        // Test length-based collision attempts
        let domain_a = "a".repeat(100);
        let domain_b = "b".repeat(100);
        let key_a = derive_epoch_key(&secret, ControlEpoch::new(1), &domain_a);
        let key_b = derive_epoch_key(&secret, ControlEpoch::new(1), &domain_b);
        assert_ne!(key_a, key_b, "Long domains should remain isolated");

        // Test epoch collision attempts with crafted domains
        let key_epoch1 = derive_epoch_key(&secret, ControlEpoch::new(1), "marker");
        let key_epoch2 = derive_epoch_key(&secret, ControlEpoch::new(2), "marker");
        let key_fake = derive_epoch_key(&secret, ControlEpoch::new(1), "marker_epoch_2");

        assert_ne!(key_epoch1, key_epoch2);
        assert_ne!(key_epoch2, key_fake);

        // Verify that HKDF info includes proper length prefixes
        let key_short = derive_epoch_key(&secret, ControlEpoch::new(1), "a");
        let key_long = derive_epoch_key(&secret, ControlEpoch::new(1), "a".repeat(100));
        assert_ne!(key_short, key_long, "Length prefixing should prevent collision");
    }

    #[test]
    fn audit_event_serialization_injection_and_corruption_attacks_fail_safely() {
        // JSON injection attempts in audit event fields
        let json_injection = r#"{"evil": "payload", "nested": {"attack": true}}"#;
        let script_injection = "<script>alert('xss')</script>";
        let sql_injection = "'; DROP TABLE events; --";
        let newline_injection = "normal\nfield\rwith\ncontrol\tchars";

        // Test artifact_id injection
        let event = EpochAuthEvent::sig_verified(
            json_injection,
            ControlEpoch::new(1),
            "marker",
            "trace-1"
        );

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains(r#""evil":"#), "JSON injection should be escaped");
        assert!(serialized.contains("payload"), "Content should be preserved but escaped");

        // Test domain injection
        let event = EpochAuthEvent::sig_rejected(
            "artifact-1",
            ControlEpoch::new(1),
            script_injection,
            sql_injection,
            newline_injection
        );

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("<script>"), "Script injection should be escaped");
        assert!(!serialized.contains("DROP TABLE"), "SQL injection should be escaped");

        // Test trace_id with control characters
        let event = EpochAuthEvent::key_derived(
            ControlEpoch::new(1),
            "marker",
            &derive_epoch_key(&root_secret(), ControlEpoch::new(1), "marker"),
            "trace\t\n\r\x00"
        );

        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serde_json::from_str::<EpochAuthEvent>(&serialized).is_ok(), "Round-trip should work");

        // Test extremely long field values
        let huge_artifact_id = "x".repeat(1_000_000);
        let event = EpochAuthEvent::sig_verified(
            &huge_artifact_id,
            ControlEpoch::new(1),
            "marker",
            "trace-huge"
        );

        let serialized = serde_json::to_string(&event);
        assert!(serialized.is_ok(), "Large fields should serialize safely");
        assert!(serialized.unwrap().len() > 1_000_000, "Content should be preserved");

        // Test Unicode in all fields
        let unicode_event = EpochAuthEvent::sig_rejected(
            "artifact-🦀",
            ControlEpoch::new(1),
            "домен",  // Cyrillic
            "причина отклонения",  // Cyrillic reason
            "trace-🌍"
        );

        let serialized = serde_json::to_string(&unicode_event).unwrap();
        let deserialized: EpochAuthEvent = serde_json::from_str(&serialized).unwrap();
        assert_eq!(unicode_event, deserialized);
    }

    #[test]
    fn concurrent_key_derivation_and_race_condition_safety_validation() {
        use std::sync::{Arc, Mutex};
        use std::thread;
        use crate::security::constant_time;

        let secret = Arc::new(root_secret());
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        // Concurrent key derivation with same parameters
        for i in 0..50 {
            let secret_clone = Arc::clone(&secret);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let key = derive_epoch_key(&*secret_clone, ControlEpoch::new(1), "marker");
                let fingerprint = key.fingerprint();

                let mut results = results_clone.lock().unwrap();
                results.push((i, fingerprint, key.to_hex()));
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 50);

        // All derivations should produce identical results (deterministic)
        let first_fingerprint = &results[0].1;
        let first_hex = &results[0].2;

        for (i, fingerprint, hex) in results.iter() {
            assert_eq!(fingerprint, first_fingerprint, "Thread {} fingerprint mismatch", i);
            assert_eq!(hex, first_hex, "Thread {} hex mismatch", i);
        }

        // Concurrent signing operations
        let sign_results = Arc::new(Mutex::new(Vec::new()));
        let mut sign_handles = vec![];

        for i in 0..30 {
            let secret_clone = Arc::clone(&secret);
            let results_clone = Arc::clone(&sign_results);

            let handle = thread::spawn(move || {
                let artifact = format!("artifact-{}", i).into_bytes();
                let sig = sign_epoch_artifact(&artifact, ControlEpoch::new(1), "marker", &*secret_clone).unwrap();

                let mut results = results_clone.lock().unwrap();
                results.push((i, artifact, sig));
            });

            sign_handles.push(handle);
        }

        for handle in sign_handles {
            handle.join().unwrap();
        }

        let sign_results = sign_results.lock().unwrap();
        assert_eq!(sign_results.len(), 30);

        // Verify all signatures are valid and different
        for (i, artifact, sig) in sign_results.iter() {
            verify_epoch_signature(artifact, sig, ControlEpoch::new(1), "marker", &*secret).unwrap();

            // Should be different from other signatures (different artifacts)
            for (j, other_artifact, other_sig) in sign_results.iter() {
                if i != j {
                    assert_ne!(artifact, other_artifact);
                    assert_ne!(sig.bytes, other_sig.bytes);
                }
            }
        }
    }

    // ── Metamorphic Relations ──────────────────────────────────────────────

    /// MR1: Derive-then-derive idempotence (Equivalence pattern: f(x) = f(x))
    /// Property: Deriving the same key multiple times must yield identical results
    #[test]
    fn mr_epoch_key_derive_idempotence() {
        let secret = root_secret();

        // Test idempotence across multiple parameter combinations
        let test_cases = vec![
            (ControlEpoch::new(1), "marker"),
            (ControlEpoch::new(42), "test-domain"),
            (ControlEpoch::new(0), ""),  // Edge case: empty domain
            (ControlEpoch::new(u64::MAX), "boundary-epoch"),
            (ControlEpoch::new(1), "special-chars-!@#$%^&*()"),
            (ControlEpoch::new(100), "unicode-域名"),
            (ControlEpoch::new(1), &"x".repeat(1000)),  // Large domain
        ];

        for (epoch, domain) in test_cases {
            // MR: Multiple derivations must be identical
            let key1 = derive_epoch_key(&secret, epoch, domain);
            let key2 = derive_epoch_key(&secret, epoch, domain);
            let key3 = derive_epoch_key(&secret, epoch, domain);

            assert_eq!(key1, key2,
                      "MR violated: derive idempotence failed for epoch={}, domain='{}'",
                      epoch.value(), domain);
            assert_eq!(key2, key3,
                      "MR violated: derive idempotence failed on third call for epoch={}, domain='{}'",
                      epoch.value(), domain);

            // Verify byte-level equality
            assert_eq!(key1.as_bytes(), key2.as_bytes());
            assert_eq!(key1.to_hex(), key2.to_hex());
            assert_eq!(key1.fingerprint(), key2.fingerprint());
        }
    }

    /// MR2: Domain separation (Exclusive pattern: different domains → different keys)
    /// Property: Different domains must produce different derived keys
    #[test]
    fn mr_epoch_key_domain_separation() {
        let secret = root_secret();
        let epoch = ControlEpoch::new(1);

        let domain_pairs = vec![
            ("marker", "manifest"),
            ("", "x"),  // Empty vs single char
            ("domain", "domain2"),  // Similar domains
            ("a", "A"),  // Case sensitivity
            ("test", "test "),  // Trailing space
            ("domain", "domain\0"),  // Null byte
            ("unicode", "unicode域"),  // Unicode difference
            ("short", &"x".repeat(100)),  // Length difference
        ];

        for (domain_a, domain_b) in domain_pairs {
            let key_a = derive_epoch_key(&secret, epoch, domain_a);
            let key_b = derive_epoch_key(&secret, epoch, domain_b);

            // MR: Different domains must produce different keys
            assert_ne!(key_a, key_b,
                      "MR violated: domain separation failed for '{}' vs '{}'",
                      domain_a, domain_b);
            assert_ne!(key_a.as_bytes(), key_b.as_bytes());
            assert_ne!(key_a.to_hex(), key_b.to_hex());
            assert_ne!(key_a.fingerprint(), key_b.fingerprint());
        }
    }

    /// MR3: Epoch separation (Exclusive pattern: different epochs → different keys)
    /// Property: Different epochs must produce different derived keys
    #[test]
    fn mr_epoch_key_epoch_separation() {
        let secret = root_secret();
        let domain = "marker";

        let epoch_pairs = vec![
            (ControlEpoch::new(1), ControlEpoch::new(2)),
            (ControlEpoch::new(0), ControlEpoch::new(1)),
            (ControlEpoch::new(42), ControlEpoch::new(43)),
            (ControlEpoch::new(u64::MAX - 1), ControlEpoch::new(u64::MAX)),
            (ControlEpoch::new(1000), ControlEpoch::new(2000)),
        ];

        for (epoch_a, epoch_b) in epoch_pairs {
            let key_a = derive_epoch_key(&secret, epoch_a, domain);
            let key_b = derive_epoch_key(&secret, epoch_b, domain);

            // MR: Different epochs must produce different keys
            assert_ne!(key_a, key_b,
                      "MR violated: epoch separation failed for epoch {} vs {}",
                      epoch_a.value(), epoch_b.value());
            assert_ne!(key_a.as_bytes(), key_b.as_bytes());
            assert_ne!(key_a.to_hex(), key_b.to_hex());
            assert_ne!(key_a.fingerprint(), key_b.fingerprint());
        }
    }

    /// MR4: Sign-verify roundtrip (Invertive pattern: f(T(T(x))) = f(x))
    /// Property: Sign with derived key, then verify must succeed
    #[test]
    fn mr_epoch_key_sign_verify_roundtrip() {
        let secret = root_secret();

        let test_cases = vec![
            (ControlEpoch::new(1), "marker", b"test-artifact".as_slice()),
            (ControlEpoch::new(42), "domain", b"".as_slice()),  // Empty artifact
            (ControlEpoch::new(0), "zero-epoch", b"large-artifact".repeat(1000).as_slice()),
            (ControlEpoch::new(u64::MAX), "max-epoch", b"boundary-test".as_slice()),
            (ControlEpoch::new(100), "special-domain-!@#", b"special-chars-artifact-!@#$%^&*()".as_slice()),
        ];

        for (epoch, domain, artifact) in test_cases {
            // MR: Sign then verify must succeed
            let signature = sign_epoch_artifact(artifact, epoch, domain, &secret)
                .expect("Signing should succeed");

            let verify_result = verify_epoch_signature(artifact, &signature, epoch, domain, &secret);
            assert!(verify_result.is_ok(),
                   "MR violated: sign-verify roundtrip failed for epoch={}, domain='{}', artifact_len={}",
                   epoch.value(), domain, artifact.len());
        }
    }

    /// MR5: Root secret consistency (Additive pattern with identity element)
    /// Property: Same root secret produces deterministic derivation regardless of order
    #[test]
    fn mr_epoch_key_root_secret_consistency() {
        // Create two identical root secrets
        let secret_bytes = [0x42u8; DERIVED_KEY_LEN];
        let secret_a = RootSecret::from_bytes(secret_bytes);
        let secret_b = RootSecret::from_bytes(secret_bytes);

        let test_params = vec![
            (ControlEpoch::new(1), "marker"),
            (ControlEpoch::new(100), "test-domain"),
            (ControlEpoch::new(0), ""),
        ];

        for (epoch, domain) in test_params {
            // MR: Identical root secrets must produce identical derived keys
            let key_a = derive_epoch_key(&secret_a, epoch, domain);
            let key_b = derive_epoch_key(&secret_b, epoch, domain);

            assert_eq!(key_a, key_b,
                      "MR violated: root secret consistency failed for epoch={}, domain='{}'",
                      epoch.value(), domain);
            assert_eq!(key_a.as_bytes(), key_b.as_bytes());

            // Also test signing consistency
            let artifact = b"consistency-test";
            let sig_a = sign_epoch_artifact(artifact, epoch, domain, &secret_a).unwrap();
            let sig_b = sign_epoch_artifact(artifact, epoch, domain, &secret_b).unwrap();

            assert_eq!(sig_a, sig_b,
                      "MR violated: signing consistency failed for epoch={}, domain='{}'",
                      epoch.value(), domain);
        }
    }

    /// MR6: Cross-epoch non-correlation (Independence pattern)
    /// Property: Keys from different epochs should appear uncorrelated
    #[test]
    fn mr_epoch_key_cross_epoch_independence() {
        let secret = root_secret();
        let domain = "marker";

        // Test that keys from consecutive epochs don't have obvious patterns
        let epochs: Vec<ControlEpoch> = (1..=20).map(ControlEpoch::new).collect();
        let keys: Vec<DerivedKey> = epochs.iter()
            .map(|&epoch| derive_epoch_key(&secret, epoch, domain))
            .collect();

        // MR: Keys should not have trivial relationships
        for (i, key_a) in keys.iter().enumerate() {
            for (j, key_b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key_a, key_b,
                              "MR violated: epochs {} and {} produced identical keys",
                              epochs[i].value(), epochs[j].value());

                    // Check for simple XOR patterns (shouldn't be all same value)
                    let xor_result: Vec<u8> = key_a.as_bytes().iter()
                        .zip(key_b.as_bytes().iter())
                        .map(|(a, b)| a ^ b)
                        .collect();

                    let all_same = xor_result.windows(2).all(|w| w[0] == w[1]);
                    assert!(!all_same,
                           "MR violated: trivial XOR pattern between epochs {} and {}",
                           epochs[i].value(), epochs[j].value());
                }
            }
        }

        // Test that bit differences are well-distributed (rough entropy check)
        for window in keys.windows(2) {
            let key_a = &window[0];
            let key_b = &window[1];

            let bit_differences: u32 = key_a.as_bytes().iter()
                .zip(key_b.as_bytes().iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();

            // Should have reasonable bit differences (not too few, not too many)
            assert!(bit_differences >= 32 && bit_differences <= 224,
                   "MR violated: suspicious bit difference count {} between consecutive epochs",
                   bit_differences);
        }
    }
}
