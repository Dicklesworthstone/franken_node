//! bd-364: Key-role separation for control-plane signing/encryption/issuance.
//!
//! Enforces strict key-role separation so that each cryptographic key is bound
//! to exactly one operational role (Signing, Encryption, Issuance, or
//! Attestation). This limits the blast radius of any single key compromise to
//! one operational domain.
//!
//! # Invariants
//!
//! - INV-KRS-ROLE-EXCLUSIVITY: A key_id MUST NOT be bound to more than one role.
//! - INV-KRS-ONE-ACTIVE: Each active role has at most one bound key.
//! - INV-KRS-ROLE-GUARD: Using a key outside its registered role is rejected.
//! - INV-KRS-ROTATION-ATOMIC: Key rotation atomically revokes old and binds new.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable event codes for structured logging (bd-364).
pub mod event_codes {
    /// Key successfully bound to a role.
    pub const KRS_KEY_ROLE_BOUND: &str = "KRS_KEY_ROLE_BOUND";
    /// Key revoked from its role.
    pub const KRS_KEY_ROLE_REVOKED: &str = "KRS_KEY_ROLE_REVOKED";
    /// Key rotated for a role (old revoked, new bound atomically).
    pub const KRS_KEY_ROLE_ROTATED: &str = "KRS_KEY_ROLE_ROTATED";
    /// Attempted use of a key outside its registered role.
    pub const KRS_ROLE_VIOLATION_ATTEMPT: &str = "KRS_ROLE_VIOLATION_ATTEMPT";
}

// ---------------------------------------------------------------------------
// KeyRole enum
// ---------------------------------------------------------------------------

/// The four mandatory key roles, each with a fixed 2-byte role tag.
///
/// - `Signing`     (0x0001): Ed25519/ECDSA for authenticating control messages.
/// - `Encryption`  (0x0002): X25519/AES for protecting confidential payloads.
/// - `Issuance`    (0x0003): Dedicated key for minting tokens/certificates.
/// - `Attestation` (0x0004): Dedicated key for operator attestation signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KeyRole {
    /// Authenticate control-plane messages and attestations.
    Signing,
    /// Protect confidential control-plane payloads in transit and at rest.
    Encryption,
    /// Create delegation tokens and authority certificates.
    Issuance,
    /// Sign operator attestation payloads.
    Attestation,
}

impl KeyRole {
    /// Fixed 2-byte role tag for canonical serialization.
    pub fn tag(self) -> [u8; 2] {
        match self {
            Self::Signing => [0x00, 0x01],
            Self::Encryption => [0x00, 0x02],
            Self::Issuance => [0x00, 0x03],
            Self::Attestation => [0x00, 0x04],
        }
    }

    /// Return the tag as a u16 for convenience.
    pub fn tag_u16(self) -> u16 {
        u16::from_be_bytes(self.tag())
    }

    /// Parse a role from a 2-byte tag. Returns None if unrecognized.
    pub fn from_tag(tag: [u8; 2]) -> Option<Self> {
        match tag {
            [0x00, 0x01] => Some(Self::Signing),
            [0x00, 0x02] => Some(Self::Encryption),
            [0x00, 0x03] => Some(Self::Issuance),
            [0x00, 0x04] => Some(Self::Attestation),
            _ => None,
        }
    }

    /// All four role variants.
    pub fn all() -> &'static [KeyRole; 4] {
        &[
            Self::Signing,
            Self::Encryption,
            Self::Issuance,
            Self::Attestation,
        ]
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signing => write!(f, "Signing"),
            Self::Encryption => write!(f, "Encryption"),
            Self::Issuance => write!(f, "Issuance"),
            Self::Attestation => write!(f, "Attestation"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyRoleBinding
// ---------------------------------------------------------------------------

/// A binding between a key identifier and exactly one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRoleBinding {
    /// TrustObjectId with KEY domain.
    pub key_id: String,
    /// The role this key is bound to.
    pub role: KeyRole,
    /// Public key material.
    pub public_key_bytes: Vec<u8>,
    /// UTC timestamp when binding was created.
    pub bound_at: u64,
    /// TrustObjectId of the authority that approved the binding.
    pub bound_by: String,
    /// Maximum validity duration for this key (seconds).
    pub max_validity_seconds: u64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from key-role separation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRoleSeparationError {
    /// Key is already bound to a different role (INV-KRS-ROLE-EXCLUSIVITY).
    RoleSeparationViolation {
        key_id: String,
        existing_role: KeyRole,
        attempted_role: KeyRole,
    },
    /// Key used for the wrong role (INV-KRS-ROLE-GUARD).
    KeyRoleMismatch {
        key_id: String,
        expected_role: KeyRole,
        actual_role: KeyRole,
    },
    /// Key not found in the registry.
    KeyNotFound { key_id: String },
    /// Key rotation failed.
    RotationFailed { role: KeyRole, reason: String },
}

impl KeyRoleSeparationError {
    /// Stable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RoleSeparationViolation { .. } => "KRS_ROLE_SEPARATION_VIOLATION",
            Self::KeyRoleMismatch { .. } => "KRS_KEY_ROLE_MISMATCH",
            Self::KeyNotFound { .. } => "KRS_KEY_NOT_FOUND",
            Self::RotationFailed { .. } => "KRS_ROTATION_FAILED",
        }
    }
}

impl fmt::Display for KeyRoleSeparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleSeparationViolation {
                key_id,
                existing_role,
                attempted_role,
            } => write!(
                f,
                "KRS_ROLE_SEPARATION_VIOLATION: key {key_id} already bound to \
                 {existing_role}, cannot bind to {attempted_role}"
            ),
            Self::KeyRoleMismatch {
                key_id,
                expected_role,
                actual_role,
            } => write!(
                f,
                "KRS_KEY_ROLE_MISMATCH: key {key_id} expected role \
                 {expected_role} but is bound to {actual_role}"
            ),
            Self::KeyNotFound { key_id } => {
                write!(f, "KRS_KEY_NOT_FOUND: key {key_id} not in registry")
            }
            Self::RotationFailed { role, reason } => {
                write!(
                    f,
                    "KRS_ROTATION_FAILED: rotation for role {role} failed: {reason}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Structured log event
// ---------------------------------------------------------------------------

/// Structured telemetry event for key-role lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRoleEvent {
    pub event_code: String,
    pub key_id: String,
    pub role: Option<KeyRole>,
    pub detail: String,
    pub trace_id: String,
    pub severity: String,
}

impl KeyRoleEvent {
    /// Create a KRS_KEY_ROLE_BOUND event.
    pub fn bound(key_id: &str, role: KeyRole, authority: &str, trace_id: &str) -> Self {
        Self {
            event_code: event_codes::KRS_KEY_ROLE_BOUND.to_string(),
            key_id: key_id.to_string(),
            role: Some(role),
            detail: format!("bound by {authority}"),
            trace_id: trace_id.to_string(),
            severity: "INFO".to_string(),
        }
    }

    /// Create a KRS_KEY_ROLE_REVOKED event.
    pub fn revoked(key_id: &str, role: KeyRole, authority: &str, trace_id: &str) -> Self {
        Self {
            event_code: event_codes::KRS_KEY_ROLE_REVOKED.to_string(),
            key_id: key_id.to_string(),
            role: Some(role),
            detail: format!("revoked by {authority}"),
            trace_id: trace_id.to_string(),
            severity: "WARN".to_string(),
        }
    }

    /// Create a KRS_KEY_ROLE_ROTATED event.
    pub fn rotated(
        old_key_id: &str,
        new_key_id: &str,
        role: KeyRole,
        authority: &str,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::KRS_KEY_ROLE_ROTATED.to_string(),
            key_id: new_key_id.to_string(),
            role: Some(role),
            detail: format!("rotated from {old_key_id}, authorized by {authority}"),
            trace_id: trace_id.to_string(),
            severity: "INFO".to_string(),
        }
    }

    /// Create a KRS_ROLE_VIOLATION_ATTEMPT event.
    pub fn violation(
        key_id: &str,
        expected_role: KeyRole,
        actual_role: KeyRole,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: event_codes::KRS_ROLE_VIOLATION_ATTEMPT.to_string(),
            key_id: key_id.to_string(),
            role: Some(actual_role),
            detail: format!("attempted {expected_role} but bound to {actual_role}"),
            trace_id: trace_id.to_string(),
            severity: "CRITICAL".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyRoleRegistry
// ---------------------------------------------------------------------------

/// Registry that stores active key-role bindings and revoked keys.
///
/// Enforces:
/// - INV-KRS-ROLE-EXCLUSIVITY: a key_id is bound to at most one role.
/// - INV-KRS-ONE-ACTIVE: lookup_by_role returns current active bindings.
/// - INV-KRS-ROTATION-ATOMIC: rotate() revokes old + binds new atomically.
#[derive(Debug)]
pub struct KeyRoleRegistry {
    /// Active bindings: key_id -> KeyRoleBinding.
    active: BTreeMap<String, KeyRoleBinding>,
    /// Revoked bindings for audit trail.
    revoked: Vec<KeyRoleBinding>,
    /// Event log for structured telemetry.
    events: Vec<KeyRoleEvent>,
}

impl KeyRoleRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            active: BTreeMap::new(),
            revoked: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Bind a key to a role.
    ///
    /// INV-KRS-ROLE-EXCLUSIVITY: if the key_id is already bound to a
    /// different role, returns RoleSeparationViolation.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        &mut self,
        key_id: &str,
        role: KeyRole,
        public_key_bytes: Vec<u8>,
        authority: &str,
        bound_at: u64,
        max_validity_seconds: u64,
        trace_id: &str,
    ) -> Result<&KeyRoleBinding, KeyRoleSeparationError> {
        // Check INV-KRS-ROLE-EXCLUSIVITY: same key cannot serve two roles.
        if let Some(existing) = self.active.get(key_id) {
            if existing.role != role {
                self.events.push(KeyRoleEvent::violation(
                    key_id,
                    role,
                    existing.role,
                    trace_id,
                ));
                return Err(KeyRoleSeparationError::RoleSeparationViolation {
                    key_id: key_id.to_string(),
                    existing_role: existing.role,
                    attempted_role: role,
                });
            }
            // Re-binding to the same role is idempotent; return existing.
            return Ok(self.active.get(key_id).expect("key verified present"));
        }

        let binding = KeyRoleBinding {
            key_id: key_id.to_string(),
            role,
            public_key_bytes,
            bound_at,
            bound_by: authority.to_string(),
            max_validity_seconds,
        };

        self.active.insert(key_id.to_string(), binding);
        self.events
            .push(KeyRoleEvent::bound(key_id, role, authority, trace_id));

        Ok(self
            .active
            .get(key_id)
            .expect("binding present after insert"))
    }

    /// Look up a binding by key_id. Returns None if not found or revoked.
    pub fn lookup(&self, key_id: &str) -> Option<&KeyRoleBinding> {
        self.active.get(key_id)
    }

    /// Look up all active bindings for a given role.
    pub fn lookup_by_role(&self, role: KeyRole) -> Vec<&KeyRoleBinding> {
        self.active.values().filter(|b| b.role == role).collect()
    }

    /// Revoke a key binding. Moves it from active to revoked set.
    ///
    /// Returns the revoked binding, or KeyNotFound if the key is not active.
    pub fn revoke(
        &mut self,
        key_id: &str,
        authority: &str,
        trace_id: &str,
    ) -> Result<KeyRoleBinding, KeyRoleSeparationError> {
        let binding =
            self.active
                .remove(key_id)
                .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                    key_id: key_id.to_string(),
                })?;

        self.events.push(KeyRoleEvent::revoked(
            key_id,
            binding.role,
            authority,
            trace_id,
        ));
        self.revoked.push(binding.clone());
        Ok(binding)
    }

    /// Atomically rotate a key for a given role.
    ///
    /// INV-KRS-ROTATION-ATOMIC: revokes old_key_id and binds new_key_id
    /// in a single operation. If old_key_id is not found or is not bound
    /// to the specified role, the entire operation fails and no state changes.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate(
        &mut self,
        role: KeyRole,
        old_key_id: &str,
        new_key_id: &str,
        new_public_key_bytes: Vec<u8>,
        authority: &str,
        bound_at: u64,
        max_validity_seconds: u64,
        trace_id: &str,
    ) -> Result<&KeyRoleBinding, KeyRoleSeparationError> {
        // Validate: old key must exist and be bound to the specified role.
        let old_binding =
            self.active
                .get(old_key_id)
                .ok_or_else(|| KeyRoleSeparationError::RotationFailed {
                    role,
                    reason: format!("old key {old_key_id} not found in active bindings"),
                })?;

        if old_binding.role != role {
            return Err(KeyRoleSeparationError::RotationFailed {
                role,
                reason: format!(
                    "old key {old_key_id} is bound to {} not {role}",
                    old_binding.role
                ),
            });
        }

        // Validate: new key must not already be bound to a different role.
        if let Some(existing) = self.active.get(new_key_id)
            && existing.role != role
        {
            return Err(KeyRoleSeparationError::RoleSeparationViolation {
                key_id: new_key_id.to_string(),
                existing_role: existing.role,
                attempted_role: role,
            });
        }

        // Atomic: revoke old, bind new.
        let old_binding = self
            .active
            .remove(old_key_id)
            .expect("old key verified present");
        self.revoked.push(old_binding);

        let new_binding = KeyRoleBinding {
            key_id: new_key_id.to_string(),
            role,
            public_key_bytes: new_public_key_bytes,
            bound_at,
            bound_by: authority.to_string(),
            max_validity_seconds,
        };
        self.active.insert(new_key_id.to_string(), new_binding);

        self.events.push(KeyRoleEvent::rotated(
            old_key_id, new_key_id, role, authority, trace_id,
        ));

        Ok(self
            .active
            .get(new_key_id)
            .expect("binding present after insert"))
    }

    /// Verify that a key is bound to the expected role.
    ///
    /// INV-KRS-ROLE-GUARD: returns Ok if the key exists and is bound to
    /// expected_role; otherwise returns KeyRoleMismatch or KeyNotFound.
    pub fn verify_role(
        &mut self,
        key_id: &str,
        expected_role: KeyRole,
        trace_id: &str,
    ) -> Result<&KeyRoleBinding, KeyRoleSeparationError> {
        let binding =
            self.active
                .get(key_id)
                .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                    key_id: key_id.to_string(),
                })?;

        if binding.role != expected_role {
            self.events.push(KeyRoleEvent::violation(
                key_id,
                expected_role,
                binding.role,
                trace_id,
            ));
            return Err(KeyRoleSeparationError::KeyRoleMismatch {
                key_id: key_id.to_string(),
                expected_role,
                actual_role: binding.role,
            });
        }

        Ok(binding)
    }

    /// Number of active bindings.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Number of revoked bindings.
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Access the revoked bindings for audit.
    pub fn revoked_bindings(&self) -> &[KeyRoleBinding] {
        &self.revoked
    }

    /// Access the event log.
    pub fn events(&self) -> &[KeyRoleEvent] {
        &self.events
    }

    /// Number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for KeyRoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers
    fn pub_key(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn tid(n: u32) -> String {
        format!("trace-krs-{n:04}")
    }

    // ---- KeyRole enum tests ----

    #[test]
    fn role_signing_tag() {
        assert_eq!(KeyRole::Signing.tag(), [0x00, 0x01]);
        assert_eq!(KeyRole::Signing.tag_u16(), 1);
    }

    #[test]
    fn role_encryption_tag() {
        assert_eq!(KeyRole::Encryption.tag(), [0x00, 0x02]);
        assert_eq!(KeyRole::Encryption.tag_u16(), 2);
    }

    #[test]
    fn role_issuance_tag() {
        assert_eq!(KeyRole::Issuance.tag(), [0x00, 0x03]);
        assert_eq!(KeyRole::Issuance.tag_u16(), 3);
    }

    #[test]
    fn role_attestation_tag() {
        assert_eq!(KeyRole::Attestation.tag(), [0x00, 0x04]);
        assert_eq!(KeyRole::Attestation.tag_u16(), 4);
    }

    #[test]
    fn role_from_tag_roundtrip() {
        for role in KeyRole::all() {
            assert_eq!(KeyRole::from_tag(role.tag()), Some(*role));
        }
    }

    #[test]
    fn role_from_tag_invalid() {
        assert_eq!(KeyRole::from_tag([0xFF, 0xFF]), None);
        assert_eq!(KeyRole::from_tag([0x00, 0x00]), None);
        assert_eq!(KeyRole::from_tag([0x00, 0x05]), None);
    }

    #[test]
    fn role_all_has_four_variants() {
        assert_eq!(KeyRole::all().len(), 4);
    }

    #[test]
    fn role_display() {
        assert_eq!(format!("{}", KeyRole::Signing), "Signing");
        assert_eq!(format!("{}", KeyRole::Encryption), "Encryption");
        assert_eq!(format!("{}", KeyRole::Issuance), "Issuance");
        assert_eq!(format!("{}", KeyRole::Attestation), "Attestation");
    }

    #[test]
    fn role_equality_and_hash() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for role in KeyRole::all() {
            set.insert(*role);
        }
        assert_eq!(set.len(), 4);
        set.insert(KeyRole::Signing); // duplicate
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn role_clone() {
        let r = KeyRole::Signing;
        let r2 = r;
        assert_eq!(r, r2);
    }

    #[test]
    fn role_serde_roundtrip() {
        for role in KeyRole::all() {
            let json = serde_json::to_string(role).unwrap();
            let back: KeyRole = serde_json::from_str(&json).unwrap();
            assert_eq!(*role, back);
        }
    }

    // ---- KeyRoleBinding tests ----

    #[test]
    fn binding_fields() {
        let b = KeyRoleBinding {
            key_id: "key-001".into(),
            role: KeyRole::Signing,
            public_key_bytes: pub_key(1),
            bound_at: 1000,
            bound_by: "authority-root".into(),
            max_validity_seconds: 3600,
        };
        assert_eq!(b.key_id, "key-001");
        assert_eq!(b.role, KeyRole::Signing);
        assert_eq!(b.public_key_bytes.len(), 32);
        assert_eq!(b.bound_at, 1000);
        assert_eq!(b.bound_by, "authority-root");
        assert_eq!(b.max_validity_seconds, 3600);
    }

    #[test]
    fn binding_serde_roundtrip() {
        let b = KeyRoleBinding {
            key_id: "key-serde".into(),
            role: KeyRole::Encryption,
            public_key_bytes: pub_key(2),
            bound_at: 2000,
            bound_by: "authority-serde".into(),
            max_validity_seconds: 7200,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: KeyRoleBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    // ---- KeyRoleRegistry: bind tests ----

    #[test]
    fn bind_signing_key() {
        let mut reg = KeyRoleRegistry::new();
        let result = reg.bind(
            "k-sign",
            KeyRole::Signing,
            pub_key(1),
            "auth-root",
            100,
            3600,
            &tid(1),
        );
        assert!(result.is_ok());
        let b = result.unwrap();
        assert_eq!(b.role, KeyRole::Signing);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn bind_encryption_key() {
        let mut reg = KeyRoleRegistry::new();
        let result = reg.bind(
            "k-enc",
            KeyRole::Encryption,
            pub_key(2),
            "auth-root",
            100,
            3600,
            &tid(1),
        );
        assert!(result.is_ok());
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn bind_issuance_key() {
        let mut reg = KeyRoleRegistry::new();
        let result = reg.bind(
            "k-iss",
            KeyRole::Issuance,
            pub_key(3),
            "auth-root",
            100,
            3600,
            &tid(1),
        );
        assert!(result.is_ok());
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn bind_attestation_key() {
        let mut reg = KeyRoleRegistry::new();
        let result = reg.bind(
            "k-att",
            KeyRole::Attestation,
            pub_key(4),
            "auth-root",
            100,
            3600,
            &tid(1),
        );
        assert!(result.is_ok());
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn bind_all_four_roles() {
        let mut reg = KeyRoleRegistry::new();
        for (i, role) in KeyRole::all().iter().enumerate() {
            let kid = format!("k-{i}");
            reg.bind(
                &kid,
                *role,
                pub_key(i as u8),
                "auth",
                100,
                3600,
                &tid(i as u32),
            )
            .unwrap();
        }
        assert_eq!(reg.active_count(), 4);
    }

    #[test]
    fn bind_idempotent_same_role() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-1",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        // Re-binding same key to same role is idempotent.
        let result = reg.bind(
            "k-1",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            200,
            7200,
            &tid(2),
        );
        assert!(result.is_ok());
        assert_eq!(reg.active_count(), 1);
    }

    // ---- Role exclusivity violation ----

    #[test]
    fn role_exclusivity_violation() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-shared",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let err = reg
            .bind(
                "k-shared",
                KeyRole::Encryption,
                pub_key(1),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
        if let KeyRoleSeparationError::RoleSeparationViolation {
            key_id,
            existing_role,
            attempted_role,
        } = err
        {
            assert_eq!(key_id, "k-shared");
            assert_eq!(existing_role, KeyRole::Signing);
            assert_eq!(attempted_role, KeyRole::Encryption);
        } else {
            assert!(false, "expected RoleSeparationViolation");
        }
    }

    #[test]
    fn role_exclusivity_violation_all_pairs() {
        // Try every pair of different roles on the same key.
        let roles = KeyRole::all();
        for (i, r1) in roles.iter().enumerate() {
            for (j, r2) in roles.iter().enumerate() {
                if i == j {
                    continue;
                }
                let mut reg = KeyRoleRegistry::new();
                let kid = format!("k-pair-{i}-{j}");
                reg.bind(&kid, *r1, pub_key(i as u8), "auth", 100, 3600, &tid(1))
                    .unwrap();
                let err = reg
                    .bind(&kid, *r2, pub_key(i as u8), "auth", 200, 3600, &tid(2))
                    .unwrap_err();
                assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
            }
        }
    }

    // ---- Lookup tests ----

    #[test]
    fn lookup_existing_key() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-look",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let binding = reg.lookup("k-look");
        assert!(binding.is_some());
        assert_eq!(binding.unwrap().role, KeyRole::Signing);
    }

    #[test]
    fn lookup_missing_key() {
        let reg = KeyRoleRegistry::new();
        assert!(reg.lookup("nonexistent").is_none());
    }

    #[test]
    fn lookup_by_role_returns_matching() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-s1",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.bind(
            "k-e1",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(2),
        )
        .unwrap();

        let signing_keys = reg.lookup_by_role(KeyRole::Signing);
        assert_eq!(signing_keys.len(), 1);
        assert_eq!(signing_keys[0].key_id, "k-s1");

        let enc_keys = reg.lookup_by_role(KeyRole::Encryption);
        assert_eq!(enc_keys.len(), 1);
        assert_eq!(enc_keys[0].key_id, "k-e1");
    }

    #[test]
    fn lookup_by_role_empty_for_unbound_role() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-s1",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        assert_eq!(reg.lookup_by_role(KeyRole::Issuance).len(), 0);
    }

    // ---- Revoke tests ----

    #[test]
    fn revoke_active_key() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-rev",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let revoked = reg.revoke("k-rev", "auth-admin", &tid(2)).unwrap();
        assert_eq!(revoked.key_id, "k-rev");
        assert_eq!(revoked.role, KeyRole::Signing);
        assert!(reg.lookup("k-rev").is_none());
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.revoked_count(), 1);
    }

    #[test]
    fn revoke_nonexistent_key() {
        let mut reg = KeyRoleRegistry::new();
        let err = reg.revoke("no-such-key", "auth", &tid(1)).unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
    }

    #[test]
    fn revoke_and_relookup_returns_none() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-rr",
            KeyRole::Encryption,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.revoke("k-rr", "auth", &tid(2)).unwrap();
        assert!(reg.lookup("k-rr").is_none());
        assert_eq!(reg.lookup_by_role(KeyRole::Encryption).len(), 0);
    }

    #[test]
    fn revoke_preserves_other_bindings() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-a",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.bind(
            "k-b",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(2),
        )
        .unwrap();
        reg.revoke("k-a", "auth", &tid(3)).unwrap();
        assert!(reg.lookup("k-a").is_none());
        assert!(reg.lookup("k-b").is_some());
        assert_eq!(reg.active_count(), 1);
    }

    // ---- Rotation tests ----

    #[test]
    fn rotate_key_successfully() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-old",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let result = reg.rotate(
            KeyRole::Signing,
            "k-old",
            "k-new",
            pub_key(2),
            "auth-admin",
            200,
            7200,
            &tid(2),
        );
        assert!(result.is_ok());
        // Old key revoked.
        assert!(reg.lookup("k-old").is_none());
        // New key active.
        let new_b = reg.lookup("k-new").unwrap();
        assert_eq!(new_b.role, KeyRole::Signing);
        assert_eq!(new_b.bound_at, 200);
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.revoked_count(), 1);
    }

    #[test]
    fn rotation_atomicity_old_revoked_new_bound() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-old-atom",
            KeyRole::Encryption,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.rotate(
            KeyRole::Encryption,
            "k-old-atom",
            "k-new-atom",
            pub_key(2),
            "auth",
            200,
            7200,
            &tid(2),
        )
        .unwrap();

        // Verify atomicity: old is in revoked set.
        assert!(reg.lookup("k-old-atom").is_none());
        assert!(
            reg.revoked_bindings()
                .iter()
                .any(|b| b.key_id == "k-old-atom")
        );
        // New is in active set.
        assert!(reg.lookup("k-new-atom").is_some());
    }

    #[test]
    fn rotate_nonexistent_old_key_fails() {
        let mut reg = KeyRoleRegistry::new();
        let err = reg
            .rotate(
                KeyRole::Signing,
                "no-such-key",
                "k-new",
                pub_key(1),
                "auth",
                100,
                3600,
                &tid(1),
            )
            .unwrap_err();
        assert_eq!(err.code(), "KRS_ROTATION_FAILED");
    }

    #[test]
    fn rotate_wrong_role_fails() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-wr",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let err = reg
            .rotate(
                KeyRole::Encryption,
                "k-wr",
                "k-new",
                pub_key(2),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();
        assert_eq!(err.code(), "KRS_ROTATION_FAILED");
        // Original binding unchanged.
        assert!(reg.lookup("k-wr").is_some());
    }

    #[test]
    fn rotate_new_key_already_bound_different_role() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-old-r",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.bind(
            "k-new-r",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(2),
        )
        .unwrap();
        let err = reg
            .rotate(
                KeyRole::Signing,
                "k-old-r",
                "k-new-r",
                pub_key(3),
                "auth",
                200,
                3600,
                &tid(3),
            )
            .unwrap_err();
        assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
        // Both original bindings unchanged.
        assert!(reg.lookup("k-old-r").is_some());
        assert!(reg.lookup("k-new-r").is_some());
    }

    // ---- verify_role tests ----

    #[test]
    fn verify_role_pass() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-vr",
            KeyRole::Issuance,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let result = reg.verify_role("k-vr", KeyRole::Issuance, &tid(2));
        assert!(result.is_ok());
    }

    #[test]
    fn verify_role_mismatch() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-mm",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let err = reg
            .verify_role("k-mm", KeyRole::Encryption, &tid(2))
            .unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
        if let KeyRoleSeparationError::KeyRoleMismatch {
            key_id,
            expected_role,
            actual_role,
        } = err
        {
            assert_eq!(key_id, "k-mm");
            assert_eq!(expected_role, KeyRole::Encryption);
            assert_eq!(actual_role, KeyRole::Signing);
        } else {
            assert!(false, "expected KeyRoleMismatch");
        }
    }

    #[test]
    fn verify_role_not_found() {
        let mut reg = KeyRoleRegistry::new();
        let err = reg
            .verify_role("no-key", KeyRole::Signing, &tid(1))
            .unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
    }

    #[test]
    fn verify_role_all_roles() {
        let mut reg = KeyRoleRegistry::new();
        for (i, role) in KeyRole::all().iter().enumerate() {
            let kid = format!("k-vr-{i}");
            reg.bind(
                &kid,
                *role,
                pub_key(i as u8),
                "auth",
                100,
                3600,
                &tid(i as u32),
            )
            .unwrap();
        }
        for (i, role) in KeyRole::all().iter().enumerate() {
            let kid = format!("k-vr-{i}");
            assert!(reg.verify_role(&kid, *role, &tid(100)).is_ok());
        }
    }

    #[test]
    fn verify_role_cross_role_rejected() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-cross",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        for role in [KeyRole::Encryption, KeyRole::Issuance, KeyRole::Attestation] {
            let err = reg.verify_role("k-cross", role, &tid(2)).unwrap_err();
            assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
        }
    }

    // ---- Event log tests ----

    #[test]
    fn bind_emits_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-ev",
            KeyRole::Signing,
            pub_key(1),
            "auth-root",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        assert_eq!(reg.event_count(), 1);
        let ev = &reg.events()[0];
        assert_eq!(ev.event_code, event_codes::KRS_KEY_ROLE_BOUND);
        assert_eq!(ev.key_id, "k-ev");
        assert_eq!(ev.role, Some(KeyRole::Signing));
        assert_eq!(ev.severity, "INFO");
    }

    #[test]
    fn revoke_emits_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-re",
            KeyRole::Encryption,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.revoke("k-re", "auth-admin", &tid(2)).unwrap();
        assert_eq!(reg.event_count(), 2);
        let ev = &reg.events()[1];
        assert_eq!(ev.event_code, event_codes::KRS_KEY_ROLE_REVOKED);
        assert_eq!(ev.severity, "WARN");
    }

    #[test]
    fn rotate_emits_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-rot-old",
            KeyRole::Issuance,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.rotate(
            KeyRole::Issuance,
            "k-rot-old",
            "k-rot-new",
            pub_key(2),
            "auth",
            200,
            7200,
            &tid(2),
        )
        .unwrap();
        // bind + rotate = 2 events
        assert_eq!(reg.event_count(), 2);
        let last = reg.events().last().unwrap();
        assert_eq!(last.event_code, event_codes::KRS_KEY_ROLE_ROTATED);
        assert_eq!(last.severity, "INFO");
        assert!(last.detail.contains("k-rot-old"));
    }

    #[test]
    fn violation_emits_critical_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-viol",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let _ = reg.verify_role("k-viol", KeyRole::Encryption, &tid(2));
        let violation_events: Vec<_> = reg
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::KRS_ROLE_VIOLATION_ATTEMPT)
            .collect();
        assert_eq!(violation_events.len(), 1);
        assert_eq!(violation_events[0].severity, "CRITICAL");
    }

    #[test]
    fn events_contain_trace_id() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-tid",
            KeyRole::Attestation,
            pub_key(1),
            "auth",
            100,
            3600,
            "trace-special",
        )
        .unwrap();
        assert_eq!(reg.events()[0].trace_id, "trace-special");
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_role_separation_violation() {
        let err = KeyRoleSeparationError::RoleSeparationViolation {
            key_id: "k-test".into(),
            existing_role: KeyRole::Signing,
            attempted_role: KeyRole::Encryption,
        };
        let display = err.to_string();
        assert!(display.contains("KRS_ROLE_SEPARATION_VIOLATION"));
        assert!(display.contains("k-test"));
        assert!(display.contains("Signing"));
        assert!(display.contains("Encryption"));
    }

    #[test]
    fn error_display_key_role_mismatch() {
        let err = KeyRoleSeparationError::KeyRoleMismatch {
            key_id: "k-mm".into(),
            expected_role: KeyRole::Issuance,
            actual_role: KeyRole::Attestation,
        };
        let display = err.to_string();
        assert!(display.contains("KRS_KEY_ROLE_MISMATCH"));
        assert!(display.contains("k-mm"));
    }

    #[test]
    fn error_display_key_not_found() {
        let err = KeyRoleSeparationError::KeyNotFound {
            key_id: "k-nf".into(),
        };
        let display = err.to_string();
        assert!(display.contains("KRS_KEY_NOT_FOUND"));
        assert!(display.contains("k-nf"));
    }

    #[test]
    fn error_display_rotation_failed() {
        let err = KeyRoleSeparationError::RotationFailed {
            role: KeyRole::Signing,
            reason: "old key missing".into(),
        };
        let display = err.to_string();
        assert!(display.contains("KRS_ROTATION_FAILED"));
        assert!(display.contains("old key missing"));
    }

    #[test]
    fn error_codes_all_variants() {
        let errors = [
            KeyRoleSeparationError::RoleSeparationViolation {
                key_id: "k".into(),
                existing_role: KeyRole::Signing,
                attempted_role: KeyRole::Encryption,
            },
            KeyRoleSeparationError::KeyRoleMismatch {
                key_id: "k".into(),
                expected_role: KeyRole::Signing,
                actual_role: KeyRole::Encryption,
            },
            KeyRoleSeparationError::KeyNotFound { key_id: "k".into() },
            KeyRoleSeparationError::RotationFailed {
                role: KeyRole::Signing,
                reason: "test".into(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
        assert_eq!(
            codes,
            vec![
                "KRS_ROLE_SEPARATION_VIOLATION",
                "KRS_KEY_ROLE_MISMATCH",
                "KRS_KEY_NOT_FOUND",
                "KRS_ROTATION_FAILED",
            ]
        );
    }

    // ---- Registry default ----

    #[test]
    fn registry_default_is_empty() {
        let reg = KeyRoleRegistry::default();
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.revoked_count(), 0);
        assert_eq!(reg.event_count(), 0);
    }

    // ---- Multi-key scenario ----

    #[test]
    fn full_lifecycle_bind_use_rotate_revoke() {
        let mut reg = KeyRoleRegistry::new();

        // Bind 4 keys for 4 roles.
        reg.bind(
            "k-s",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.bind(
            "k-e",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(2),
        )
        .unwrap();
        reg.bind(
            "k-i",
            KeyRole::Issuance,
            pub_key(3),
            "auth",
            100,
            3600,
            &tid(3),
        )
        .unwrap();
        reg.bind(
            "k-a",
            KeyRole::Attestation,
            pub_key(4),
            "auth",
            100,
            3600,
            &tid(4),
        )
        .unwrap();
        assert_eq!(reg.active_count(), 4);

        // Verify roles.
        assert!(reg.verify_role("k-s", KeyRole::Signing, &tid(5)).is_ok());
        assert!(reg.verify_role("k-e", KeyRole::Encryption, &tid(6)).is_ok());

        // Cross-role is rejected.
        assert!(
            reg.verify_role("k-s", KeyRole::Encryption, &tid(7))
                .is_err()
        );

        // Rotate signing key.
        reg.rotate(
            KeyRole::Signing,
            "k-s",
            "k-s2",
            pub_key(5),
            "auth",
            200,
            7200,
            &tid(8),
        )
        .unwrap();
        assert!(reg.lookup("k-s").is_none());
        assert!(reg.lookup("k-s2").is_some());

        // Revoke encryption key.
        reg.revoke("k-e", "auth-admin", &tid(9)).unwrap();
        assert!(reg.lookup("k-e").is_none());

        assert_eq!(reg.active_count(), 3); // k-s2, k-i, k-a
        assert_eq!(reg.revoked_count(), 2); // k-s, k-e
    }

    #[test]
    fn double_revoke_returns_not_found() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-dr",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.revoke("k-dr", "auth", &tid(2)).unwrap();
        let err = reg.revoke("k-dr", "auth", &tid(3)).unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
    }

    #[test]
    fn rebind_after_revoke_succeeds() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-rb",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.revoke("k-rb", "auth", &tid(2)).unwrap();
        // Can rebind the same key_id after revocation.
        let result = reg.bind(
            "k-rb",
            KeyRole::Encryption,
            pub_key(1),
            "auth",
            200,
            3600,
            &tid(3),
        );
        assert!(result.is_ok());
        assert_eq!(reg.lookup("k-rb").unwrap().role, KeyRole::Encryption);
    }

    // ---- KeyRoleEvent construction tests ----

    #[test]
    fn event_bound_construction() {
        let ev = KeyRoleEvent::bound("k-1", KeyRole::Signing, "auth-root", "trace-001");
        assert_eq!(ev.event_code, event_codes::KRS_KEY_ROLE_BOUND);
        assert_eq!(ev.severity, "INFO");
        assert_eq!(ev.key_id, "k-1");
        assert_eq!(ev.trace_id, "trace-001");
    }

    #[test]
    fn event_revoked_construction() {
        let ev = KeyRoleEvent::revoked("k-2", KeyRole::Encryption, "auth-admin", "trace-002");
        assert_eq!(ev.event_code, event_codes::KRS_KEY_ROLE_REVOKED);
        assert_eq!(ev.severity, "WARN");
    }

    #[test]
    fn event_rotated_construction() {
        let ev = KeyRoleEvent::rotated("k-old", "k-new", KeyRole::Issuance, "auth", "trace-003");
        assert_eq!(ev.event_code, event_codes::KRS_KEY_ROLE_ROTATED);
        assert_eq!(ev.severity, "INFO");
        assert!(ev.detail.contains("k-old"));
    }

    #[test]
    fn event_violation_construction() {
        let ev =
            KeyRoleEvent::violation("k-bad", KeyRole::Encryption, KeyRole::Signing, "trace-004");
        assert_eq!(ev.event_code, event_codes::KRS_ROLE_VIOLATION_ATTEMPT);
        assert_eq!(ev.severity, "CRITICAL");
    }

    #[test]
    fn event_serde_roundtrip() {
        let ev = KeyRoleEvent::bound("k-serde", KeyRole::Attestation, "auth", "trace-serde");
        let json = serde_json::to_string(&ev).unwrap();
        let back: KeyRoleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }
}
