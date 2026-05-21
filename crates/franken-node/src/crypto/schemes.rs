//! Signature scheme trait abstractions and concrete implementations.
//!
//! # Ed25519 Preparsed Key Handles (Performance Optimization)
//!
//! The stateless [`SignatureScheme`] trait parses keys from raw bytes on every
//! operation. This is intentional: other schemes (RSA, ECDSA) may not support
//! keypair caching, and the trait surface must remain generic.
//!
//! For **Ed25519 specifically**, repeated parsing is expensive:
//! - `SigningKey::from_bytes` performs SHA-512 expansion + basepoint scalar multiply
//! - `VerifyingKey::from_bytes` decompresses the Edwards curve point
//!
//! When signing/verifying in a loop with the same key, callers should use the
//! preparsed handle types instead:
//!
//! - [`Ed25519PreparsedSigner`]: Wraps a `SigningKey` for repeated signing.
//! - [`Ed25519PreparsedVerifier`]: Wraps a `VerifyingKey` for repeated verification.
//!
//! ## Thread Safety
//!
//! Both types implement `Send + Sync` and can be stored in `Arc<>`, `OnceCell<>`,
//! or other shared containers on long-lived control-plane objects.
//!
//! ## ZeroizeOnDrop
//!
//! `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop` (dalek 2.x). The
//! [`Ed25519PreparsedSigner`] wrapper inherits this: when dropped, the secret
//! key material is securely zeroed. Callers do not need explicit cleanup.
//!
//! ## Constructor Semantics
//!
//! - `Ed25519PreparsedSigner::from_secret_bytes(&[u8; 32])` is **infallible**:
//!   any 32-byte input is a valid Ed25519 seed.
//! - `Ed25519PreparsedVerifier::from_public_bytes(&[u8; 32])` is **fallible**:
//!   the compressed Edwards point may fail to decompress.
//!
//! ## Domain Separation
//!
//! The preparsed `sign_with_domain` / `verify_with_domain` methods produce
//! bit-for-bit identical output to [`Ed25519Scheme::sign_with_domain`] and
//! [`Ed25519Scheme::verify_with_domain`]. The canonical preimage is:
//!
//! ```text
//! b"ed25519_signature_v1:" || len(domain) as u64 LE || domain || len(msg) as u64 LE || msg
//! ```
//!
//! This is hashed (blake3 or SHA-256 depending on feature flags) before signing.

use crate::crypto::error::Ed25519Error;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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

    /// Sign the exact bytes provided, without any wrapper domain or length framing.
    ///
    /// Use this when the caller has already constructed a canonical preimage that
    /// embeds its own domain separator and length-prefix scheme (e.g. signed
    /// receipts that prepend `DECISION_RECEIPT_SIGNATURE_VERSION` and a sorted
    /// JSON body, or replay bundles with their own header). Calling
    /// [`sign_with_domain`](Self::sign_with_domain) on those preimages would
    /// double-wrap the bytes and break on-the-wire signature compatibility with
    /// existing artifacts.
    ///
    /// # Security
    /// - The caller is responsible for cryptographic domain separation.
    /// - Output bytes are bit-for-bit identical to a direct Ed25519 sign over
    ///   `message` for [`Ed25519Scheme`].
    fn sign_raw(
        secret_key: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error>;

    /// Verify a signature over the exact bytes provided, without any wrapper
    /// domain or length framing.
    ///
    /// Mirror of [`sign_raw`](Self::sign_raw). Returns `false` on any failure
    /// (malformed key, malformed signature, or verification mismatch) so that
    /// callers can branch in constant time.
    ///
    /// # Security
    /// - Uses strict verification (rejects malleable / non-canonical signatures)
    ///   for schemes that support it.
    #[must_use]
    fn verify_raw(
        public_key: &Self::PublicKey,
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

        verifying_key.verify_strict(digest_bytes, &sig).is_ok()
    }

    fn sign_raw(
        secret_key: &Self::SecretKey,
        message: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        // Construct a SigningKey directly from the 32-byte seed.
        // `SigningKey::from_bytes` for ed25519-dalek 2.x is infallible for any
        // 32-byte input, but we keep the Result return type to match the trait
        // contract so other schemes (RSA / ECDSA) can fail.
        let signing_key = SigningKey::from_bytes(secret_key);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    fn verify_raw(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> bool {
        // Parse keys and signature; any parse failure means "not valid".
        // Return false without leaking which step failed.
        let verifying_key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let sig = match Signature::try_from(&signature[..]) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        // verify_strict rejects malleable / non-canonical-s signatures.
        // decision_receipt and other consumers historically rely on strict
        // verification for replay/forgery hardening; keep that contract here.
        verifying_key.verify_strict(message, &sig).is_ok()
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

// ---------------------------------------------------------------------------
// Ed25519 Preparsed Key Handles
// ---------------------------------------------------------------------------

/// Preparsed Ed25519 signer for repeated signing with the same secret key.
///
/// Wraps an `ed25519_dalek::SigningKey` to avoid repeated SHA-512 expansion
/// and basepoint scalar multiplication on each signing operation.
///
/// # Security
///
/// - Implements `Send + Sync` for safe sharing across threads.
/// - The inner `SigningKey` implements `ZeroizeOnDrop` (dalek 2.x): secret key
///   material is securely zeroed when this handle is dropped.
/// - `sign_raw` produces bit-for-bit identical output to [`Ed25519Scheme::sign_raw`].
///
/// # Example
///
/// ```ignore
/// let signer = Ed25519PreparsedSigner::from_secret_bytes(&secret_key);
/// let sig1 = signer.sign_raw(b"message 1");
/// let sig2 = signer.sign_raw(b"message 2"); // No key re-parsing
/// ```
#[derive(Debug)]
pub struct Ed25519PreparsedSigner {
    inner: SigningKey,
}

// `ed25519_dalek::SigningKey` is already `Send + Sync` in dalek 2.x, so this
// wrapper auto-derives both. Explicit `unsafe impl Send/Sync` blocks are
// redundant AND illegal under the crate-wide `#![forbid(unsafe_code)]` policy
// (see `crates/franken-node/src/lib.rs`), so they are intentionally absent.

impl Ed25519PreparsedSigner {
    /// Create a preparsed signer from a 32-byte secret key seed.
    ///
    /// This constructor is **infallible**: any 32-byte input is a valid Ed25519 seed.
    /// The `SigningKey` is constructed once and cached for subsequent operations.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(secret),
        }
    }

    /// Sign a message without domain separation.
    ///
    /// Output is bit-for-bit identical to [`Ed25519Scheme::sign_raw`] with the
    /// same secret key and message.
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.inner.sign(message).to_bytes()
    }

    /// Sign a message with domain separation.
    ///
    /// Output is bit-for-bit identical to [`Ed25519Scheme::sign_with_domain`]
    /// with the same secret key, domain, and message.
    pub fn sign_with_domain(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
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

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        self.inner.sign(digest_bytes).to_bytes()
    }

    /// Get the public key corresponding to this signer.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }
}

/// Preparsed Ed25519 verifier for repeated verification with the same public key.
///
/// Wraps an `ed25519_dalek::VerifyingKey` to avoid repeated Edwards point
/// decompression on each verification operation.
///
/// # Security
///
/// - Implements `Send + Sync` for safe sharing across threads.
/// - `verify_raw` returns the same result as [`Ed25519Scheme::verify_raw`].
/// - Uses `verify_strict` to reject malleable / non-canonical signatures.
///
/// # Example
///
/// ```ignore
/// let verifier = Ed25519PreparsedVerifier::from_public_bytes(&public_key)?;
/// let valid1 = verifier.verify_raw(b"message 1", &sig1);
/// let valid2 = verifier.verify_raw(b"message 2", &sig2); // No key re-parsing
/// ```
#[derive(Debug, Clone)]
pub struct Ed25519PreparsedVerifier {
    inner: VerifyingKey,
}

// `ed25519_dalek::VerifyingKey` is already `Send + Sync` in dalek 2.x, so
// this wrapper auto-derives both. Explicit `unsafe impl Send/Sync` blocks are
// redundant AND illegal under the crate-wide `#![forbid(unsafe_code)]` policy
// (see `crates/franken-node/src/lib.rs`), so they are intentionally absent.

impl Ed25519PreparsedVerifier {
    /// Create a preparsed verifier from a 32-byte compressed public key.
    ///
    /// This constructor is **fallible**: the compressed Edwards point may fail
    /// to decompress if the bytes do not represent a valid curve point.
    pub fn from_public_bytes(public: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let inner = VerifyingKey::from_bytes(public)
            .map_err(|e| Ed25519Error::MalformedKey(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Verify a signature without domain separation.
    ///
    /// Returns `true` if valid, `false` otherwise (including malformed signature).
    /// Uses `verify_strict` to reject malleable / non-canonical signatures.
    #[must_use]
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = match Signature::try_from(&signature[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.inner.verify_strict(message, &sig).is_ok()
    }

    /// Verify a signature with domain separation.
    ///
    /// Returns `true` if valid, `false` otherwise. Uses the same canonical
    /// preimage construction as [`Ed25519Scheme::verify_with_domain`].
    #[must_use]
    pub fn verify_with_domain(&self, domain: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
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

        #[cfg(feature = "blake3")]
        let digest_bytes = digest.as_bytes();
        #[cfg(not(feature = "blake3"))]
        let digest_bytes = &digest[..];

        let sig = match Signature::try_from(&signature[..]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.inner.verify_strict(digest_bytes, &sig).is_ok()
    }

    /// Get the raw public key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
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
    fn test_ed25519_length_prefix_counter_saturates() {
        assert_eq!(len_to_u64(0), 0);
        assert_eq!(len_to_u64(usize::MAX), u64::MAX);
    }

    #[test]
    fn test_ed25519_raw_signature_preserves_caller_preimage() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let message = b"caller-owned canonical preimage";
        let direct_key = SigningKey::from_bytes(&sk);
        let direct_signature = direct_key.sign(message).to_bytes();

        let raw_signature = Ed25519Scheme::sign_raw(&sk, message).unwrap();

        assert_eq!(raw_signature, direct_signature);
        assert!(Ed25519Scheme::verify_raw(&pk, message, &raw_signature));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk,
            b"decision_receipt",
            message,
            &raw_signature
        ));

        let wrapped_signature =
            Ed25519Scheme::sign_with_domain(&sk, b"decision_receipt", message).unwrap();
        assert!(!Ed25519Scheme::verify_raw(&pk, message, &wrapped_signature));
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

    // ── Preparsed handle tests ──

    #[test]
    fn preparsed_signer_sign_raw_matches_scheme() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let message = b"test message for raw signing";

        let scheme_sig = Ed25519Scheme::sign_raw(&sk, message).unwrap();
        let preparsed_sig = signer.sign_raw(message);

        assert_eq!(scheme_sig, preparsed_sig, "sign_raw output must be bit-for-bit identical");
    }

    #[test]
    fn preparsed_signer_sign_with_domain_matches_scheme() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let domain = b"test_domain";
        let message = b"test message for domain signing";

        let scheme_sig = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();
        let preparsed_sig = signer.sign_with_domain(domain, message);

        assert_eq!(scheme_sig, preparsed_sig, "sign_with_domain output must be bit-for-bit identical");
    }

    #[test]
    fn preparsed_verifier_verify_raw_matches_scheme() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"test message for raw verification";
        let signature = Ed25519Scheme::sign_raw(&sk, message).unwrap();

        let scheme_result = Ed25519Scheme::verify_raw(&pk, message, &signature);
        let preparsed_result = verifier.verify_raw(message, &signature);

        assert_eq!(scheme_result, preparsed_result, "verify_raw must produce identical boolean");
        assert!(preparsed_result, "valid signature should verify");
    }

    #[test]
    fn preparsed_verifier_verify_with_domain_matches_scheme() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let domain = b"test_domain";
        let message = b"test message for domain verification";
        let signature = Ed25519Scheme::sign_with_domain(&sk, domain, message).unwrap();

        let scheme_result = Ed25519Scheme::verify_with_domain(&pk, domain, message, &signature);
        let preparsed_result = verifier.verify_with_domain(domain, message, &signature);

        assert_eq!(scheme_result, preparsed_result, "verify_with_domain must produce identical boolean");
        assert!(preparsed_result, "valid signature should verify");
    }

    #[test]
    fn preparsed_signer_public_key_matches() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);

        assert_eq!(signer.public_key(), pk, "public_key() must match original");
    }

    #[test]
    fn preparsed_verifier_rejects_invalid_public_key() {
        let invalid_key = [0u8; 32]; // All zeros is not a valid Edwards point
        let result = Ed25519PreparsedVerifier::from_public_bytes(&invalid_key);
        assert!(result.is_err(), "all-zero key should fail decompression");
    }

    #[test]
    fn preparsed_verifier_rejects_invalid_signature() {
        let (pk, _) = Ed25519Scheme::generate_keypair().unwrap();
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"test message";
        let bad_signature = [0u8; 64];

        assert!(!verifier.verify_raw(message, &bad_signature), "zero signature should fail");
    }

    #[test]
    fn preparsed_signer_sign_raw_multiple_payload_sizes() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);

        let payloads: &[&[u8]] = &[
            &[],                        // 0 B
            &[0x42],                    // 1 B
            &[0xAA; 64],                // 64 B
            &[0xBB; 512],               // 512 B
            &[0xCC; 4096],              // 4096 B
        ];

        for payload in payloads {
            let scheme_sig = Ed25519Scheme::sign_raw(&sk, payload).unwrap();
            let preparsed_sig = signer.sign_raw(payload);
            assert_eq!(
                scheme_sig, preparsed_sig,
                "sign_raw must be bit-identical for payload of {} bytes",
                payload.len()
            );
        }
    }

    #[test]
    fn preparsed_verifier_uses_strict_verification() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519PreparsedSigner::from_secret_bytes(&sk);
        let verifier = Ed25519PreparsedVerifier::from_public_bytes(&pk).unwrap();
        let message = b"strict verification test";

        let sig = signer.sign_raw(message);
        assert!(verifier.verify_raw(message, &sig), "valid signature should pass");

        let mut tampered_sig = sig;
        tampered_sig[63] ^= 0x80;
        assert!(
            !verifier.verify_raw(message, &tampered_sig),
            "tampered signature should fail strict verification"
        );
    }

    #[test]
    fn preparsed_signer_zeroize_on_drop_compile_check() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    }
}
