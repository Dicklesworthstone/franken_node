//! High-level cryptographic signer trait and implementations.

use crate::crypto::{Ed25519Error, Ed25519Scheme, SignatureScheme};
use serde::Serialize;
use serde_json::Value;
use std::marker::PhantomData;

/// High-level signing operations with built-in security patterns.
///
/// This trait provides convenient signing operations that automatically
/// apply franken_node security patterns:
/// - Automatic domain separation with context prefixes
/// - Type-safe structured data signing with JSON serialization
/// - Consistent error handling across signing operations
pub trait CryptoSigner {
    /// The underlying signature scheme
    type Scheme: SignatureScheme;
    /// The signing key type for this signer
    type SigningKey;

    /// Sign a message with automatic domain separation.
    ///
    /// The context parameter is automatically prefixed with "franken_node_"
    /// to create a domain separator, preventing signature reuse across
    /// different applications.
    ///
    /// # Arguments
    /// * `key` - The signing key to use
    /// * `context` - Context string for domain separation (e.g., "decision_receipt")
    /// * `message` - Raw message bytes to sign
    ///
    /// # Security
    /// - Automatically applies "franken_node_" prefix to context
    /// - Uses underlying scheme's domain separation
    /// - All operations are constant-time where possible
    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<
        <Self::Scheme as SignatureScheme>::Signature,
        <Self::Scheme as SignatureScheme>::Error,
    >;

    /// Sign structured data with type-safe domain separation.
    ///
    /// Serializes the structured data to JSON and signs the resulting bytes.
    /// This provides a convenient interface for signing structured data types
    /// while maintaining cryptographic safety.
    ///
    /// # Arguments
    /// * `key` - The signing key to use
    /// * `context` - Context string for domain separation
    /// * `data` - Structured data to serialize and sign
    ///
    /// # Security
    /// - Uses deterministic JSON serialization
    /// - Same domain separation as sign_message
    /// - Serialization errors are propagated as signing errors
    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<
        <Self::Scheme as SignatureScheme>::Signature,
        <Self::Scheme as SignatureScheme>::Error,
    >;
}

/// Ed25519-specific signer with franken_node security patterns.
///
/// Implements the CryptoSigner trait for Ed25519 signatures with:
/// - Automatic "franken_node_" context prefixing
/// - JSON serialization for structured data
/// - Consistent error handling and propagation
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    _phantom: PhantomData<Ed25519Scheme>,
}

impl Ed25519Signer {
    /// Create a new Ed25519 signer.
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl Default for Ed25519Signer {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoSigner for Ed25519Signer {
    type Scheme = Ed25519Scheme;
    type SigningKey = [u8; 32];

    fn sign_message(
        &self,
        key: &Self::SigningKey,
        context: &str,
        message: &[u8],
    ) -> Result<[u8; 64], Ed25519Error> {
        let domain = format!("franken_node_{}:", context);
        Ed25519Scheme::sign_with_domain(key, domain.as_bytes(), message)
    }

    fn sign_structured<T: Serialize>(
        &self,
        key: &Self::SigningKey,
        context: &str,
        data: &T,
    ) -> Result<[u8; 64], Ed25519Error> {
        let serialized = to_canonical_bytes(data)
            .map_err(|e| Ed25519Error::SerializationFailed(e.to_string()))?;
        self.sign_message(key, context, &serialized)
    }
}

/// Serialize data to canonical bytes for deterministic signing.
/// Ensures consistent ordering of object keys to prevent signature variation.
fn to_canonical_bytes<T: Serialize>(data: &T) -> Result<Vec<u8>, serde_json::Error> {
    let value = serde_json::to_value(data)?;
    let canonical = canonicalize_json(&value);
    serde_json::to_vec(&canonical)
}

/// Canonicalize JSON by sorting object keys recursively.
/// This ensures deterministic serialization regardless of input ordering.
fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                out.insert(key.to_string(), canonicalize_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        id: u64,
        name: String,
        active: bool,
    }

    #[test]
    fn test_ed25519_signer_message_signing() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519Signer::new();

        let message = b"test message";
        let context = "test_context";

        let signature = signer.sign_message(&sk, context, message).unwrap();

        // Verify using the underlying scheme with the expected domain
        let expected_domain = b"franken_node_test_context:";
        assert!(Ed25519Scheme::verify_with_domain(
            &pk,
            expected_domain,
            message,
            &signature
        ));
    }

    #[test]
    fn test_ed25519_signer_structured_signing() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519Signer::new();

        let test_data = TestData {
            id: 123,
            name: "test".to_string(),
            active: true,
        };

        let context = "test_struct";
        let signature = signer.sign_structured(&sk, context, &test_data).unwrap();

        // `sign_structured` signs the CANONICAL preimage (object keys sorted
        // recursively — bd-3eko7 "use canonical bytes for structured Ed25519
        // signing"), not the struct's declaration-order serialization.
        // Reconstruct the exact preimage with the prod helper before verifying.
        let serialized = to_canonical_bytes(&test_data).unwrap();
        let expected_domain = b"franken_node_test_struct:";
        assert!(Ed25519Scheme::verify_with_domain(
            &pk,
            expected_domain,
            &serialized,
            &signature
        ));
    }

    #[test]
    fn test_ed25519_signer_context_separation() {
        let (pk, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519Signer::new();

        let message = b"same message";

        let sig1 = signer.sign_message(&sk, "context1", message).unwrap();
        let sig2 = signer.sign_message(&sk, "context2", message).unwrap();

        // Different contexts should produce different signatures
        assert_ne!(sig1, sig2);

        // Cross-context verification should fail
        let domain1 = b"franken_node_context1:";
        let domain2 = b"franken_node_context2:";

        assert!(Ed25519Scheme::verify_with_domain(
            &pk, domain1, message, &sig1
        ));
        assert!(Ed25519Scheme::verify_with_domain(
            &pk, domain2, message, &sig2
        ));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, domain1, message, &sig2
        ));
        assert!(!Ed25519Scheme::verify_with_domain(
            &pk, domain2, message, &sig1
        ));
    }

    #[test]
    fn test_ed25519_signer_serialization_determinism() {
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let signer = Ed25519Signer::new();

        let test_data = TestData {
            id: 456,
            name: "deterministic".to_string(),
            active: false,
        };

        // Sign the same data multiple times
        let sig1 = signer
            .sign_structured(&sk, "deterministic", &test_data)
            .unwrap();
        let sig2 = signer
            .sign_structured(&sk, "deterministic", &test_data)
            .unwrap();

        // Should produce identical signatures (deterministic serialization)
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_ed25519_signer_default() {
        let signer1 = Ed25519Signer::new();
        let signer2 = Ed25519Signer::default();

        // Both constructors should yield behaviorally identical signers: signing the same
        // data with the same key must produce identical (deterministic Ed25519) signatures.
        let (_, sk) = Ed25519Scheme::generate_keypair().unwrap();
        let test_data = TestData {
            id: 789,
            name: "default-equiv".to_string(),
            active: true,
        };
        let sig1 = signer1
            .sign_structured(&sk, "default-equiv", &test_data)
            .unwrap();
        let sig2 = signer2
            .sign_structured(&sk, "default-equiv", &test_data)
            .unwrap();
        assert_eq!(
            sig1, sig2,
            "new() and default() signers should be equivalent"
        );
    }
}
