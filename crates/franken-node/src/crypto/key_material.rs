//! Key material management trait and implementations.

use crate::crypto::error::KeyMaterialError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Key material management with security guarantees.
///
/// This trait provides a secure interface for managing cryptographic key material
/// with support for:
/// - Secure storage and retrieval
/// - Key validation and expiration checking
/// - Secure key rotation
/// - Key fingerprinting for identification
pub trait KeyMaterial: Send + Sync {
    /// Public key type for this key material
    type PublicKey: AsRef<[u8]> + Clone;
    /// Secret key type (may be reference to secure storage)
    type SecretKey;
    /// Error type for key material operations
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load key material from secure storage.
    ///
    /// This method should perform any necessary validation of the key material
    /// and ensure that the key is currently valid (not expired).
    ///
    /// # Arguments
    /// * `key_id` - Unique identifier for the key in secure storage
    ///
    /// # Security
    /// - Should validate key integrity during loading
    /// - Should check key expiration status
    /// - Should fail securely if key is invalid or expired
    fn load_from_secure_storage(key_id: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Export public key for verification operations.
    ///
    /// Returns a reference to the public key component that can be used
    /// for signature verification or key identification.
    fn public_key(&self) -> &Self::PublicKey;

    /// Check if key material is valid and not expired.
    ///
    /// This should perform all necessary checks to ensure the key material
    /// is safe to use for cryptographic operations.
    ///
    /// # Security
    /// - Uses fail-closed semantics (invalid if in doubt)
    /// - Should check expiration with >= comparison
    /// - Should validate key integrity
    #[must_use]
    fn is_valid(&self) -> bool;

    /// Get key fingerprint for logging and identification.
    ///
    /// Returns a human-readable fingerprint of the public key that can be
    /// used for logging, debugging, and key identification without exposing
    /// sensitive key material.
    ///
    /// # Security
    /// - Should not expose sensitive key material
    /// - Should be deterministic for the same key
    /// - Should use cryptographically strong hash function
    fn fingerprint(&self) -> String;

    /// Secure key rotation.
    ///
    /// Generates new key material and securely replaces the current key.
    /// The old key material should be securely erased.
    ///
    /// # Security
    /// - Should securely erase old key material
    /// - Should use cryptographically secure randomness
    /// - Should atomically update key material
    fn rotate(&mut self) -> Result<(), Self::Error>;
}

/// Ed25519 key material implementation with in-memory storage.
///
/// This is a basic implementation suitable for testing and development.
/// Production systems should use hardware security modules or other
/// secure key storage mechanisms.
#[derive(Debug, Clone)]
pub struct Ed25519KeyMaterial {
    key_id: String,
    public_key: [u8; 32],
    secret_key: [u8; 32],
    created_at: std::time::SystemTime,
    expires_at: std::time::SystemTime,
}

impl Ed25519KeyMaterial {
    /// Create new key material with specified expiration.
    pub fn new(
        key_id: String,
        expires_at: std::time::SystemTime,
    ) -> Result<Self, KeyMaterialError> {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            key_id,
            public_key: verifying_key.to_bytes(),
            secret_key: signing_key.to_bytes(),
            created_at: std::time::SystemTime::now(),
            expires_at,
        })
    }

    /// Get the secret key for signing operations.
    ///
    /// # Security Note
    /// In production systems, this should return a reference to secure storage
    /// rather than exposing the raw key material in memory.
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }

    /// Get the key ID.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> std::time::SystemTime {
        self.created_at
    }

    /// Get the expiration timestamp.
    pub fn expires_at(&self) -> std::time::SystemTime {
        self.expires_at
    }
}

// Simple in-memory key storage for testing/development
const MAX_TEST_KEYS: usize = crate::capacity_defaults::base::TRACE;

lazy_static::lazy_static! {
    static ref KEY_STORAGE: Arc<Mutex<HashMap<String, Ed25519KeyMaterial>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

impl KeyMaterial for Ed25519KeyMaterial {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Error = KeyMaterialError;

    fn load_from_secure_storage(key_id: &str) -> Result<Self, Self::Error> {
        let storage = KEY_STORAGE.lock().map_err(|_| {
            KeyMaterialError::StorageFailed("Failed to acquire storage lock".to_string())
        })?;

        let key_material = storage
            .get(key_id)
            .ok_or_else(|| KeyMaterialError::KeyNotFound(key_id.to_string()))?
            .clone();

        // Check if key is still valid
        if !key_material.is_valid() {
            return Err(KeyMaterialError::KeyExpired);
        }

        Ok(key_material)
    }

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }

    fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now();
        // Use fail-closed semantics: >= means expired
        now < self.expires_at
    }

    fn fingerprint(&self) -> String {
        // Use blake3 for consistent, strong fingerprinting when available
        #[cfg(feature = "blake3")]
        {
            let hash = blake3::hash(&self.public_key);
            format!("ed25519:{}", hex::encode(&hash.as_bytes()[..8]))
        }
        #[cfg(not(feature = "blake3"))]
        {
            // Fallback to SHA256 when blake3 is not available
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&self.public_key);
            format!("ed25519:{}", hex::encode(&hash.as_slice()[..8]))
        }
    }

    fn rotate(&mut self) -> Result<(), Self::Error> {
        let mut rng = rand::thread_rng();
        let new_signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let new_verifying_key = new_signing_key.verifying_key();

        // Securely overwrite old key material
        self.secret_key.fill(0);
        self.public_key.fill(0);

        // Install new key material
        self.secret_key = new_signing_key.to_bytes();
        self.public_key = new_verifying_key.to_bytes();
        self.created_at = std::time::SystemTime::now();

        // Update in storage
        let mut storage = KEY_STORAGE.lock().map_err(|_| {
            KeyMaterialError::StorageFailed("Failed to acquire storage lock".to_string())
        })?;
        storage.insert(self.key_id.clone(), self.clone());

        Ok(())
    }
}

/// Utility functions for key material management.
impl Ed25519KeyMaterial {
    /// Store key material in secure storage.
    pub fn store_in_secure_storage(&self) -> Result<(), KeyMaterialError> {
        let mut storage = KEY_STORAGE.lock().map_err(|_| {
            KeyMaterialError::StorageFailed("Failed to acquire storage lock".to_string())
        })?;

        // Reject key_id if it would exceed length bound (prevent memory exhaustion)
        if self.key_id.len() > 256 {
            return Err(KeyMaterialError::StorageFailed(
                "Key ID too long".to_string(),
            ));
        }

        // Prevent unbounded storage growth in test scenarios
        if !storage.contains_key(&self.key_id) && storage.len() >= MAX_TEST_KEYS {
            return Err(KeyMaterialError::StorageFailed(
                "Test key storage capacity exceeded".to_string(),
            ));
        }

        storage.insert(self.key_id.clone(), self.clone());
        Ok(())
    }

    /// Remove key material from secure storage.
    pub fn remove_from_secure_storage(key_id: &str) -> Result<(), KeyMaterialError> {
        let mut storage = KEY_STORAGE.lock().map_err(|_| {
            KeyMaterialError::StorageFailed("Failed to acquire storage lock".to_string())
        })?;

        storage.remove(key_id);
        Ok(())
    }

    /// List all key IDs in secure storage.
    pub fn list_key_ids() -> Result<Vec<String>, KeyMaterialError> {
        let storage = KEY_STORAGE.lock().map_err(|_| {
            KeyMaterialError::StorageFailed("Failed to acquire storage lock".to_string())
        })?;

        Ok(storage.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_ed25519_key_material_creation() {
        let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
        let key_material = Ed25519KeyMaterial::new("test_key".to_string(), expires_at).unwrap();

        assert_eq!(key_material.key_id(), "test_key");
        assert_eq!(key_material.public_key().len(), 32);
        assert_eq!(key_material.secret_key().len(), 32);
        assert!(key_material.is_valid());
    }

    #[test]
    fn test_ed25519_key_material_expiration() {
        // Create expired key
        let expires_at = std::time::SystemTime::now() - Duration::from_secs(1);
        let key_material = Ed25519KeyMaterial::new("expired_key".to_string(), expires_at).unwrap();

        assert!(!key_material.is_valid());
    }

    #[test]
    fn test_ed25519_key_material_fingerprint() {
        let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
        let key_material =
            Ed25519KeyMaterial::new("fingerprint_test".to_string(), expires_at).unwrap();

        let fingerprint = key_material.fingerprint();
        assert!(fingerprint.starts_with("ed25519:"));
        assert_eq!(fingerprint.len(), 8 + 16 + 1); // "ed25519:" + 16 hex chars

        // Fingerprint should be deterministic
        let fingerprint2 = key_material.fingerprint();
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_ed25519_key_material_storage() {
        let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
        let key_material = Ed25519KeyMaterial::new("storage_test".to_string(), expires_at).unwrap();
        let key_id = key_material.key_id().to_string();

        // Store the key
        key_material.store_in_secure_storage().unwrap();

        // Load it back
        let loaded_material = Ed25519KeyMaterial::load_from_secure_storage(&key_id).unwrap();
        assert_eq!(loaded_material.key_id(), key_material.key_id());
        assert_eq!(loaded_material.public_key(), key_material.public_key());

        // Clean up
        Ed25519KeyMaterial::remove_from_secure_storage(&key_id).unwrap();
    }

    #[test]
    fn test_ed25519_key_material_rotation() {
        let expires_at = std::time::SystemTime::now() + Duration::from_secs(3600);
        let mut key_material =
            Ed25519KeyMaterial::new("rotation_test".to_string(), expires_at).unwrap();

        let old_public_key = *key_material.public_key();
        let old_fingerprint = key_material.fingerprint();

        // Rotate the key
        key_material.rotate().unwrap();

        // Should have new key material
        assert_ne!(key_material.public_key(), &old_public_key);
        assert_ne!(key_material.fingerprint(), old_fingerprint);
        assert!(key_material.is_valid());
    }

    #[test]
    fn test_ed25519_key_material_load_nonexistent() {
        let result = Ed25519KeyMaterial::load_from_secure_storage("nonexistent_key");
        assert!(matches!(result, Err(KeyMaterialError::KeyNotFound(_))));
    }

    #[test]
    fn test_ed25519_key_material_load_expired() {
        let expires_at = std::time::SystemTime::now() - Duration::from_secs(1);
        let key_material =
            Ed25519KeyMaterial::new("expired_storage_test".to_string(), expires_at).unwrap();
        let key_id = key_material.key_id().to_string();

        // Store the expired key
        key_material.store_in_secure_storage().unwrap();

        // Should fail to load expired key
        let result = Ed25519KeyMaterial::load_from_secure_storage(&key_id);
        assert!(matches!(result, Err(KeyMaterialError::KeyExpired)));

        // Clean up
        Ed25519KeyMaterial::remove_from_secure_storage(&key_id).unwrap();
    }
}
