//! Cryptographic signature verification trait abstractions.
//!
//! This module provides trait-based abstractions over signature verification
//! operations, allowing for algorithm agility, better testability, and
//! consistent error handling across the codebase.

use ed25519_dalek::VerifyingKey;
use std::fmt;

/// Error types for signature verification operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureVerificationError {
    /// The signature is malformed or has incorrect length
    MalformedSignature,
    /// The public key is malformed or invalid
    MalformedPublicKey,
    /// The signature verification failed
    VerificationFailed,
    /// The signature algorithm is not supported
    UnsupportedAlgorithm(String),
}

impl fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedSignature => write!(f, "malformed signature"),
            Self::MalformedPublicKey => write!(f, "malformed public key"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported algorithm: {}", alg),
        }
    }
}

impl std::error::Error for SignatureVerificationError {}

/// Trait for verifying digital signatures over raw message bytes.
///
/// This trait provides a generic interface for signature verification that can
/// be implemented by different cryptographic algorithms (Ed25519, ECDSA, etc.).
/// It enables algorithm agility and better testability.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a signature over the given message bytes.
    ///
    /// # Arguments
    /// * `message` - The raw message bytes that were signed
    /// * `signature_bytes` - The signature bytes to verify
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err` otherwise.
    fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), SignatureVerificationError>;

    /// Get the algorithm name for this verifier (e.g., "ed25519").
    fn algorithm(&self) -> &'static str;

    /// Get the public key bytes for this verifier.
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// Ed25519 signature verifier implementation.
///
/// Provides Ed25519 signature verification using the ed25519-dalek crate.
/// This is the primary signature algorithm used throughout the franken_node codebase.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    /// The Ed25519 verifying (public) key
    verifying_key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Create a new Ed25519 verifier from a verifying key.
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Create a new Ed25519 verifier from raw public key bytes.
    pub fn from_bytes(public_key_bytes: &[u8]) -> Result<Self, SignatureVerificationError> {
        if public_key_bytes.len() != 32 {
            return Err(SignatureVerificationError::MalformedPublicKey);
        }

        let key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| SignatureVerificationError::MalformedPublicKey)?;

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|_| SignatureVerificationError::MalformedPublicKey)?;

        Ok(Self::new(verifying_key))
    }

    /// Create a new Ed25519 verifier from a hex-encoded public key string.
    pub fn from_hex(public_key_hex: &str) -> Result<Self, SignatureVerificationError> {
        let key_bytes = hex::decode(public_key_hex)
            .map_err(|_| SignatureVerificationError::MalformedPublicKey)?;
        Self::from_bytes(&key_bytes)
    }

    /// Get the underlying VerifyingKey for cases that need direct access.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), SignatureVerificationError> {
        use ed25519_dalek::Verifier;

        if signature_bytes.len() != 64 {
            return Err(SignatureVerificationError::MalformedSignature);
        }

        let sig_array: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| SignatureVerificationError::MalformedSignature)?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| SignatureVerificationError::VerificationFailed)
    }

    fn algorithm(&self) -> &'static str {
        "ed25519"
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.as_bytes().to_vec()
    }
}

/// Helper trait for verifying signatures against hex-encoded signatures.
///
/// This is a convenience trait for common patterns in the codebase where
/// signatures are stored as hex strings.
pub trait HexSignatureVerifier {
    /// Verify a signature where the signature is provided as a hex string.
    fn verify_hex(&self, message: &[u8], signature_hex: &str) -> Result<(), SignatureVerificationError>;
}

impl<V: SignatureVerifier> HexSignatureVerifier for V {
    fn verify_hex(&self, message: &[u8], signature_hex: &str) -> Result<(), SignatureVerificationError> {
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|_| SignatureVerificationError::MalformedSignature)?;
        self.verify(message, &signature_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn ed25519_verifier_basic_verification() {
        let (signing_key, verifying_key) = test_keypair();
        let verifier = Ed25519Verifier::new(verifying_key);

        let message = b"test message";
        let signature = signing_key.sign(message);

        assert!(verifier.verify(message, &signature.to_bytes()).is_ok());
    }

    #[test]
    fn ed25519_verifier_invalid_signature() {
        let (_, verifying_key) = test_keypair();
        let verifier = Ed25519Verifier::new(verifying_key);

        let message = b"test message";
        let invalid_signature = [0u8; 64];

        assert!(verifier.verify(message, &invalid_signature).is_err());
    }

    #[test]
    fn ed25519_verifier_from_bytes() {
        let (_, verifying_key) = test_keypair();
        let key_bytes = verifying_key.as_bytes();

        let verifier = Ed25519Verifier::from_bytes(key_bytes).unwrap();
        assert_eq!(verifier.algorithm(), "ed25519");
        assert_eq!(verifier.public_key_bytes(), key_bytes.to_vec());
    }

    #[test]
    fn ed25519_verifier_from_hex() {
        let (_, verifying_key) = test_keypair();
        let key_hex = hex::encode(verifying_key.as_bytes());

        let verifier = Ed25519Verifier::from_hex(&key_hex).unwrap();
        assert_eq!(verifier.public_key_bytes(), verifying_key.as_bytes().to_vec());
    }

    #[test]
    fn hex_signature_verification() {
        let (signing_key, verifying_key) = test_keypair();
        let verifier = Ed25519Verifier::new(verifying_key);

        let message = b"test message";
        let signature = signing_key.sign(message);
        let signature_hex = hex::encode(signature.to_bytes());

        assert!(verifier.verify_hex(message, &signature_hex).is_ok());
    }

    #[test]
    fn malformed_signature_length() {
        let (_, verifying_key) = test_keypair();
        let verifier = Ed25519Verifier::new(verifying_key);

        let message = b"test message";
        let short_signature = [0u8; 32]; // Wrong length

        let result = verifier.verify(message, &short_signature);
        assert!(matches!(result, Err(SignatureVerificationError::MalformedSignature)));
    }

    #[test]
    fn malformed_public_key() {
        let invalid_key_bytes = [0u8; 16]; // Wrong length
        let result = Ed25519Verifier::from_bytes(&invalid_key_bytes);
        assert!(matches!(result, Err(SignatureVerificationError::MalformedPublicKey)));
    }
}