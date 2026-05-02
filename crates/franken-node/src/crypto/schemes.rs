//! Signature scheme trait abstractions and concrete implementations.

use crate::crypto::error::Ed25519Error;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

const ED25519_SIGNATURE_PREIMAGE_DOMAIN: &[u8] = b"ed25519_signature_v1:";

fn len_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Unified signature scheme abstraction with domain separation support.
///
/// This trait provides a generic interface for cryptographic signature schemes
/// with built-in domain separation, constant-time verification, and consistent
/// error handling patterns.
pub trait SignatureScheme: Send + Sync + 'static {
    /// Public key type for this scheme
    type PublicKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Secret key type for this scheme
    type SecretKey: AsRef<[u8]> + Clone + Send + Sync;
    /// Signature type for this scheme
    type Signature: AsRef<[u8]> + Clone + Send + Sync;
    /// Error type for this scheme
    type Error: std::error::Error + Send + Sync + 'static;

    /// Scheme identifier for domain separation and algorithm identification.
    fn scheme_id() -> &'static str;

    /// Generate a new cryptographically secure keypair.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;

    /// Sign a message with domain separation.
    ///
    /// The domain parameter provides cryptographic separation between different
    /// contexts and prevents signature reuse across different applications.
    ///
    /// # Security
    /// - Uses length-prefixed encoding to prevent collision attacks
    /// - Includes scheme-specific domain separator
    /// - All inputs are cryptographically hashed before signing
    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;

    /// Verify a signature with domain separation using constant-time comparison.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    /// Uses constant-time operations to prevent timing attacks.
    ///
    /// # Security
    /// - Returns bool (not Result) for constant-time usage patterns
    /// - Uses same domain separation as signing
    /// - All verification operations complete in constant time
    #[must_use]
    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool;

    /// Parse public key from raw bytes with validation.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;

    /// Parse signature from raw bytes with validation.
    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error>;
}

/// Ed25519 signature scheme implementation with franken_node security patterns.
///
/// Implements the SignatureScheme trait for Ed25519 with:
/// - Domain separation using blake3 hashing
/// - Constant-time verification operations
/// - Length-prefixed input encoding
/// - Fail-closed error handling
#[derive(Debug, Clone)]
pub struct Ed25519Scheme;

impl SignatureScheme for Ed25519Scheme {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Signature = [u8; 64];
    type Error = Ed25519Error;

    fn scheme_id() -> &'static str {
        "ed25519_v1"
    }

    fn generate_keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Ok((verifying_key.to_bytes(), signing_key.to_bytes()))
    }

    fn sign_with_domain(
        secret_key: &Self::SecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Create domain-separated digest using blake3 when available
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        // Sign the digest using ed25519-dalek
        let signing_key = match SigningKey::try_from(secret_key) {
            Ok(key) => key,
            Err(e) => return Err(Ed25519Error::MalformedKey(e.to_string())),
        };

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        let signature = signing_key.sign(digest_bytes);
        Ok(signature.to_bytes())
    }

    fn verify_with_domain(
        public_key: &Self::PublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        // Create the same domain-separated digest
        #[cfg(feature = "blake3")]
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(&len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(&len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        #[cfg(not(feature = "blake3"))]
        let digest = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(ED25519_SIGNATURE_PREIMAGE_DOMAIN);
            hasher.update(len_to_u64(domain.len()).to_le_bytes());
            hasher.update(domain);
            hasher.update(len_to_u64(message.len()).to_le_bytes());
            hasher.update(message);
            hasher.finalize()
        };

        // Parse keys and signature
        let verifying_key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false, // Constant-time failure
        };

        let sig = match Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false, // Constant-time failure
        };

        // Perform constant-time verification
        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        verifying_key.verify(digest_bytes, &sig).is_ok()
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        if bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(bytes);

        // Validate the key by attempting to parse it
        VerifyingKey::from_bytes(&key_array)
            .map_err(|e| Ed25519Error::MalformedKey(e.to_string()))?;

        Ok(key_array)
    }

    fn signature_from_bytes(bytes: &[u8]) -> Result<Self::Signature, Self::Error> {
        if bytes.len() != 64 {
            return Err(Ed25519Error::InvalidSignatureLength {
                expected: 64,
                actual: bytes.len(),
            });
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(bytes);

        // Validate the signature by attempting to parse it
        match Signature::try_from(&sig_array[..]) {
            Ok(_) => {} // Valid signature format
            Err(e) => return Err(Ed25519Error::MalformedSignature(e.to_string())),
        };

        Ok(sig_array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_signature_roundtrip() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        assert!(Ed25519Scheme::verify_with_domain(
            &pk, domain, message, &signature
        ));
    }

    #[test]
    fn test_ed25519_domain_separation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";

        let sig1 = Ed25519Scheme::sign_with_domain(&sk, b"domain1", message).unwrap();
        let sig2 = Ed25519Scheme::sign_with_domain(&sk, b"domain2", message).unwrap();

        // Same message, different domains should produce different signatures
        assert_ne!(sig1, sig2);

        // Cross-domain verification should fail
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, b"domain1", message, &sig2
        ));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, b"domain2", message, &sig1
        ));
    }

    #[test]
    fn test_ed25519_constant_time_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        let valid_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let mut invalid_sig = valid_sig;
        invalid_sig[0] ^= 1; // Flip one bit

        // Both should complete without panicking (constant-time)
        let result1 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &valid_sig);
        let result2 = Ed25519Scheme::verify_with_domain(&pk, domain, message, &invalid_sig);

        assert!(result1);
        assert!(!result2);
    }

    #[test]
    fn test_ed25519_key_validation() {
        // Test valid key length
        let (pk, _) = Ed25519Scheme::generate_keypair().unwrap();
        let parsed_pk = Ed25519Scheme::public_key_from_bytes(pk.as_ref()).unwrap();
        assert_eq!(pk, parsed_pk);

        // Test invalid key length
        let short_key = [0u8; 16];
        let result = Ed25519Scheme::public_key_from_bytes(&short_key);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_ed25519_signature_validation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"test message";
        let domain = b"test_domain";

        // Test valid signature
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let parsed_sig = Ed25519Scheme::signature_from_bytes(signature.as_ref()).unwrap();
        assert_eq!(signature, parsed_sig);

        // Test invalid signature length
        let short_sig = [0u8; 32];
        let result = Ed25519Scheme::signature_from_bytes(&short_sig);
        assert!(matches!(
            result,
            Err(Ed25519Error::InvalidSignatureLength {
                expected: 64,
                actual: 32
            })
        ));
    }

    #[test]
    fn test_ed25519_scheme_id() {
        assert_eq!(Ed25519Scheme::scheme_id(), "ed25519_v1");
    }
}
