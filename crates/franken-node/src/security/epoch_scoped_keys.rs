//! bd-3cs3: Epoch-scoped key derivation for trust artifact authentication.
//!
//! Derives authentication keys from a root secret, epoch, and domain using
//! HKDF-SHA256. This enforces epoch and domain separation by construction.

use crate::control_plane::control_epoch::ControlEpoch;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
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
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey([u8; DERIVED_KEY_LEN]);

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub bytes: [u8; SIGNATURE_LEN],
}

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

/// Derive an epoch+domain scoped key via HKDF-SHA256.
pub fn derive_epoch_key(root_secret: &RootSecret, epoch: ControlEpoch, domain: &str) -> DerivedKey {
    let hkdf = Hkdf::<Sha256>::new(Some(KDF_SALT), root_secret.as_bytes());
    let info = format!("franken-node:epoch={}:domain={domain}", epoch.value());
    let mut okm = [0u8; DERIVED_KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut okm)
        .expect("DERIVED_KEY_LEN is fixed and valid");
    DerivedKey(okm)
}

/// Sign an artifact payload using the derived epoch/domain key.
pub fn sign_epoch_artifact(
    artifact: &[u8],
    epoch: ControlEpoch,
    domain: &str,
    root_secret: &RootSecret,
) -> Result<Signature, AuthError> {
    if domain.is_empty() {
        return Err(AuthError::DomainEmpty);
    }

    let derived_key = derive_epoch_key(root_secret, epoch, domain);
    let mut mac = HmacSha256::new_from_slice(derived_key.as_bytes()).map_err(|e| {
        AuthError::KeyDerivationFailed {
            reason: e.to_string(),
        }
    })?;
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
    if domain.is_empty() {
        return Err(AuthError::DomainEmpty);
    }

    let derived_key = derive_epoch_key(root_secret, epoch, domain);
    let mut mac = HmacSha256::new_from_slice(derived_key.as_bytes()).map_err(|e| {
        AuthError::KeyDerivationFailed {
            reason: e.to_string(),
        }
    })?;
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
            "3a2c69af2025b183040dd2646c3c6c2a4ca2e7f74c20a3a0bd88f38ae2236af6"
        );
    }

    #[test]
    fn known_answer_vector_epoch_13_marker() {
        let key = derive_epoch_key(&root_secret(), ControlEpoch::new(13), "marker");
        assert_eq!(
            key.to_hex(),
            "7b2a3bbde4103713f9986ccde3c763e116d0d5723635e353297e724c1d2a50f0"
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
            "ab39e9df44b940453a89358528d54bff9bd9d180359dac0a1f3dd2f924e43494"
        );
    }

    #[test]
    fn reject_empty_domain() {
        let secret = root_secret();
        let err = sign_epoch_artifact(b"x", ControlEpoch::new(1), "", &secret).unwrap_err();
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
}
