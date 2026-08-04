//! Error types for cryptographic operations.

use std::fmt;

/// Error types for Ed25519 signature operations.
#[derive(Debug, Clone, PartialEq)]
pub enum Ed25519Error {
    /// The key has an invalid length
    InvalidKeyLength { expected: usize, actual: usize },
    /// The signature has an invalid length
    InvalidSignatureLength { expected: usize, actual: usize },
    /// Signature verification failed
    VerificationFailed,
    /// Serialization failed during structured signing
    SerializationFailed(String),
    /// Key generation failed
    KeyGenerationFailed(String),
    /// The provided key bytes are malformed
    MalformedKey(String),
    /// The provided signature bytes are malformed
    MalformedSignature(String),
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "Invalid signature length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {}", msg),
            Self::KeyGenerationFailed(msg) => write!(f, "Key generation failed: {}", msg),
            Self::MalformedKey(msg) => write!(f, "Malformed key: {}", msg),
            Self::MalformedSignature(msg) => write!(f, "Malformed signature: {}", msg),
        }
    }
}

impl std::error::Error for Ed25519Error {}

/// Error types for the hash-based one-time signature anchor.
#[derive(Debug, Clone, PartialEq)]
pub enum HashOtsError {
    /// The secret key seed has an invalid length.
    InvalidSecretKeyLength { expected: usize, actual: usize },
    /// The expanded public key has an invalid length.
    InvalidPublicKeyLength { expected: usize, actual: usize },
    /// The one-time signature has an invalid length.
    InvalidSignatureLength { expected: usize, actual: usize },
    /// A serialized hybrid anchor component could not be decoded.
    DecodeFailed(String),
    /// Ed25519 signing failed while building a hybrid anchor.
    Ed25519Failed(String),
}

impl fmt::Display for HashOtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid hash-OTS secret key length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid hash-OTS public key length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidSignatureLength { expected, actual } => {
                write!(
                    f,
                    "Invalid hash-OTS signature length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::DecodeFailed(msg) => write!(f, "Hash-OTS decode failed: {}", msg),
            Self::Ed25519Failed(msg) => write!(f, "Hybrid Ed25519 component failed: {}", msg),
        }
    }
}

impl std::error::Error for HashOtsError {}

/// Error types for key material operations.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyMaterialError {
    /// Key not found in secure storage
    KeyNotFound(String),
    /// Key has expired
    KeyExpired,
    /// Storage operation failed
    StorageFailed(String),
    /// Key rotation failed
    RotationFailed(String),
    /// Invalid key format
    InvalidFormat(String),
}

impl fmt::Display for KeyMaterialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound(key_id) => write!(f, "Key not found: {}", key_id),
            Self::KeyExpired => write!(f, "Key has expired"),
            Self::StorageFailed(msg) => write!(f, "Storage operation failed: {}", msg),
            Self::RotationFailed(msg) => write!(f, "Key rotation failed: {}", msg),
            Self::InvalidFormat(msg) => write!(f, "Invalid key format: {}", msg),
        }
    }
}

impl std::error::Error for KeyMaterialError {}
