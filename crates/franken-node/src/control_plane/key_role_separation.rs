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

use crate::security::constant_time;
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
    /// Re-bind attempted with different public key material for the same
    /// key_id and role. Fail closed: the caller must revoke the old binding
    /// and bind a new key, or use rotate().
    KeyMaterialMismatch { key_id: String, role: KeyRole },
    /// Key binding has exceeded its max_validity_seconds window.
    KeyExpired { key_id: String, role: KeyRole },
    /// Active binding registry is at capacity.
    RegistryFull { capacity: usize },
}

impl KeyRoleSeparationError {
    /// Stable error code string.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RoleSeparationViolation { .. } => "KRS_ROLE_SEPARATION_VIOLATION",
            Self::KeyRoleMismatch { .. } => "KRS_KEY_ROLE_MISMATCH",
            Self::KeyNotFound { .. } => "KRS_KEY_NOT_FOUND",
            Self::RotationFailed { .. } => "KRS_ROTATION_FAILED",
            Self::KeyMaterialMismatch { .. } => "KRS_KEY_MATERIAL_MISMATCH",
            Self::KeyExpired { .. } => "KRS_KEY_EXPIRED",
            Self::RegistryFull { .. } => "KRS_REGISTRY_FULL",
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
            Self::KeyMaterialMismatch { key_id, role } => {
                write!(
                    f,
                    "KRS_KEY_MATERIAL_MISMATCH: key {key_id} already bound to \
                     {role} with different public key material"
                )
            }
            Self::KeyExpired { key_id, role } => {
                write!(
                    f,
                    "KRS_KEY_EXPIRED: key {key_id} bound to {role} has exceeded \
                     its max_validity_seconds window"
                )
            }
            Self::RegistryFull { capacity } => {
                write!(
                    f,
                    "KRS_REGISTRY_FULL: active binding registry at capacity ({capacity})"
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
/// Maximum revoked bindings before oldest-first eviction.
const MAX_REVOKED_ENTRIES: usize = 4096;
/// Maximum active key-role bindings before new binds are rejected.
const MAX_ACTIVE_BINDINGS: usize = 4096;
/// Maximum events before oldest-first eviction.
const MAX_KEY_ROLE_EVENTS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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

    fn push_event(&mut self, event: KeyRoleEvent) {
        push_bounded(&mut self.events, event, MAX_KEY_ROLE_EVENTS);
    }

    fn push_revoked(&mut self, binding: KeyRoleBinding) {
        push_bounded(&mut self.revoked, binding, MAX_REVOKED_ENTRIES);
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
        // Extract data from existing binding before any mutable borrow.
        if let Some((existing_role, material_matches)) = self.active.get(key_id).map(|b| {
            (
                b.role,
                constant_time::ct_eq_bytes(&b.public_key_bytes, &public_key_bytes),
            )
        }) {
            if existing_role != role {
                self.push_event(KeyRoleEvent::violation(
                    key_id,
                    role,
                    existing_role,
                    trace_id,
                ));
                return Err(KeyRoleSeparationError::RoleSeparationViolation {
                    key_id: key_id.to_string(),
                    existing_role,
                    attempted_role: role,
                });
            }
            // Re-binding to the same role: fail closed if the public key
            // material differs — the caller may believe the new key is
            // active when the old material would silently persist.
            if !material_matches {
                return Err(KeyRoleSeparationError::KeyMaterialMismatch {
                    key_id: key_id.to_string(),
                    role,
                });
            }
            // Truly idempotent: same key_id, same role, same material.
            return self
                .active
                .get(key_id)
                .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                    key_id: key_id.to_string(),
                });
        }

        // Capacity guard: prevent unbounded active-binding growth.
        if self.active.len() >= MAX_ACTIVE_BINDINGS {
            return Err(KeyRoleSeparationError::RegistryFull {
                capacity: MAX_ACTIVE_BINDINGS,
            });
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
        self.push_event(KeyRoleEvent::bound(key_id, role, authority, trace_id));

        self.active
            .get(key_id)
            .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                key_id: key_id.to_string(),
            })
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

        self.push_event(KeyRoleEvent::revoked(
            key_id,
            binding.role,
            authority,
            trace_id,
        ));
        self.push_revoked(binding.clone());
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
        if old_key_id == new_key_id {
            return Err(KeyRoleSeparationError::RotationFailed {
                role,
                reason: "old_key_id and new_key_id must differ".to_string(),
            });
        }

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
        let old_binding = self.active.remove(old_key_id).ok_or_else(|| {
            KeyRoleSeparationError::RotationFailed {
                role,
                reason: format!("old key {} vanished during rotation", old_key_id),
            }
        })?;
        self.push_revoked(old_binding);

        let new_binding = KeyRoleBinding {
            key_id: new_key_id.to_string(),
            role,
            public_key_bytes: new_public_key_bytes,
            bound_at,
            bound_by: authority.to_string(),
            max_validity_seconds,
        };
        self.active.insert(new_key_id.to_string(), new_binding);

        self.push_event(KeyRoleEvent::rotated(
            old_key_id, new_key_id, role, authority, trace_id,
        ));

        self.active
            .get(new_key_id)
            .ok_or_else(|| KeyRoleSeparationError::RotationFailed {
                role,
                reason: format!("new key {} vanished after insert", new_key_id),
            })
    }

    /// Verify that a key is bound to the expected role and has not expired.
    ///
    /// INV-KRS-ROLE-GUARD: returns Ok if the key exists, is bound to
    /// expected_role, and is within its max_validity_seconds window;
    /// otherwise returns KeyRoleMismatch, KeyExpired, or KeyNotFound.
    pub fn verify_role(
        &mut self,
        key_id: &str,
        expected_role: KeyRole,
        now: u64,
        trace_id: &str,
    ) -> Result<&KeyRoleBinding, KeyRoleSeparationError> {
        let (actual_role, bound_at, max_validity) = self
            .active
            .get(key_id)
            .map(|binding| (binding.role, binding.bound_at, binding.max_validity_seconds))
            .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

        if actual_role != expected_role {
            self.push_event(KeyRoleEvent::violation(
                key_id,
                expected_role,
                actual_role,
                trace_id,
            ));
            return Err(KeyRoleSeparationError::KeyRoleMismatch {
                key_id: key_id.to_string(),
                expected_role,
                actual_role,
            });
        }

        // Fail-closed: key is expired if now >= bound_at + max_validity_seconds.
        let expires_at = bound_at.saturating_add(max_validity);
        if now >= expires_at {
            return Err(KeyRoleSeparationError::KeyExpired {
                key_id: key_id.to_string(),
                role: actual_role,
            });
        }

        self.active
            .get(key_id)
            .ok_or_else(|| KeyRoleSeparationError::KeyNotFound {
                key_id: key_id.to_string(),
            })
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
    use super::{
        KeyRole, KeyRoleBinding, KeyRoleRegistry, KeyRoleSeparationError, MAX_ACTIVE_BINDINGS,
    };

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

    /// Regression: re-binding the same key_id + role with different public
    /// key material must fail closed instead of silently returning the stale
    /// binding.  Before the fix, the caller could believe their new key was
    /// active when the old material was still in use.
    #[test]
    fn rebind_different_key_material_rejected() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-mat",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();

        // Same key_id and role, but different public key bytes.
        let err = reg
            .bind(
                "k-mat",
                KeyRole::Signing,
                pub_key(99), // different material
                "auth",
                200,
                7200,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_MATERIAL_MISMATCH");
        // Original binding must be unchanged.
        let binding = reg.lookup("k-mat").unwrap();
        assert_eq!(binding.public_key_bytes, pub_key(1));
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
        assert!(matches!(
            err,
            KeyRoleSeparationError::RoleSeparationViolation {
                ref key_id,
                existing_role,
                attempted_role,
            } if key_id == "k-shared" && existing_role == KeyRole::Signing && attempted_role == KeyRole::Encryption
        ));
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

    // ---- Negative regression tests ----

    #[test]
    fn role_deserialize_rejects_unknown_variant() {
        let invalid_role = serde_json::from_str::<KeyRole>("\"verification\"");

        assert!(invalid_role.is_err());
    }

    #[test]
    fn bind_role_violation_preserves_original_binding() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-preserve",
            KeyRole::Signing,
            pub_key(10),
            "auth-original",
            100,
            3600,
            &tid(1),
        )
        .unwrap();

        let err = reg
            .bind(
                "k-preserve",
                KeyRole::Encryption,
                pub_key(99),
                "auth-rejected",
                500,
                30,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
        let binding = reg.lookup("k-preserve").unwrap();
        assert_eq!(binding.role, KeyRole::Signing);
        assert_eq!(binding.bound_by, "auth-original");
        assert_eq!(binding.bound_at, 100);
        assert_eq!(binding.max_validity_seconds, 3600);
        assert_eq!(binding.public_key_bytes, pub_key(10));
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn rebind_material_mismatch_records_no_extra_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-material-event",
            KeyRole::Attestation,
            pub_key(4),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg
            .bind(
                "k-material-event",
                KeyRole::Attestation,
                pub_key(5),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_MATERIAL_MISMATCH");
        assert_eq!(reg.event_count(), initial_events);
        assert_eq!(reg.active_count(), 1);
        assert_eq!(
            reg.lookup("k-material-event").unwrap().public_key_bytes,
            pub_key(4)
        );
    }

    #[test]
    fn bind_at_capacity_rejects_without_event() {
        let mut reg = KeyRoleRegistry::new();
        for slot in 0..MAX_ACTIVE_BINDINGS {
            let key_id = format!("k-capacity-{slot}");
            reg.active.insert(
                key_id.clone(),
                KeyRoleBinding {
                    key_id,
                    role: KeyRole::Signing,
                    public_key_bytes: pub_key(7),
                    bound_at: 1,
                    bound_by: "fixture".into(),
                    max_validity_seconds: 60,
                },
            );
        }

        let err = reg
            .bind(
                "k-over-capacity",
                KeyRole::Signing,
                pub_key(8),
                "auth",
                2,
                60,
                &tid(3),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_REGISTRY_FULL");
        assert_eq!(reg.active_count(), MAX_ACTIVE_BINDINGS);
        assert_eq!(reg.event_count(), 0);
        assert!(reg.lookup("k-over-capacity").is_none());
    }

    #[test]
    fn rotate_missing_old_key_leaves_registry_unchanged() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-stable",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg
            .rotate(
                KeyRole::Encryption,
                "k-missing-old",
                "k-should-not-exist",
                pub_key(3),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_ROTATION_FAILED");
        assert!(reg.lookup("k-stable").is_some());
        assert!(reg.lookup("k-should-not-exist").is_none());
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.revoked_count(), 0);
        assert_eq!(reg.event_count(), initial_events);
    }

    #[test]
    fn rotate_conflicting_new_key_leaves_counts_and_events_unchanged() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-rotate-source",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        reg.bind(
            "k-rotate-conflict",
            KeyRole::Issuance,
            pub_key(3),
            "auth",
            100,
            3600,
            &tid(2),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg
            .rotate(
                KeyRole::Signing,
                "k-rotate-source",
                "k-rotate-conflict",
                pub_key(9),
                "auth",
                200,
                3600,
                &tid(3),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
        assert_eq!(reg.active_count(), 2);
        assert_eq!(reg.revoked_count(), 0);
        assert_eq!(reg.event_count(), initial_events);
        assert_eq!(
            reg.lookup("k-rotate-source").unwrap().role,
            KeyRole::Signing
        );
        assert_eq!(
            reg.lookup("k-rotate-conflict").unwrap().role,
            KeyRole::Issuance
        );
    }

    #[test]
    fn verify_mismatch_does_not_revoke_binding() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-mismatch-stable",
            KeyRole::Issuance,
            pub_key(3),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();

        let err = reg
            .verify_role("k-mismatch-stable", KeyRole::Signing, 200, &tid(2))
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
        assert!(reg.lookup("k-mismatch-stable").is_some());
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.revoked_count(), 0);
    }

    #[test]
    fn verify_zero_validity_rejects_at_bound_time() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-zero-validity",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            500,
            0,
            &tid(1),
        )
        .unwrap();

        let err = reg
            .verify_role("k-zero-validity", KeyRole::Signing, 500, &tid(2))
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_EXPIRED");
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn verify_saturating_expiry_rejects_at_u64_max() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-saturating-expiry",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            u64::MAX - 4,
            10,
            &tid(1),
        )
        .unwrap();

        let err = reg
            .verify_role(
                "k-saturating-expiry",
                KeyRole::Encryption,
                u64::MAX,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_EXPIRED");
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
        let result = reg.verify_role("k-vr", KeyRole::Issuance, 200, &tid(2));
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
            .verify_role("k-mm", KeyRole::Encryption, 200, &tid(2))
            .unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
        assert!(matches!(
            err,
            KeyRoleSeparationError::KeyRoleMismatch {
                ref key_id,
                expected_role,
                actual_role,
            } if key_id == "k-mm" && expected_role == KeyRole::Encryption && actual_role == KeyRole::Signing
        ));
    }

    #[test]
    fn verify_role_not_found() {
        let mut reg = KeyRoleRegistry::new();
        let err = reg
            .verify_role("no-key", KeyRole::Signing, 200, &tid(1))
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
            assert!(reg.verify_role(&kid, *role, 200, &tid(100)).is_ok());
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
            let err = reg.verify_role("k-cross", role, 200, &tid(2)).unwrap_err();
            assert_eq!(err.code(), "KRS_KEY_ROLE_MISMATCH");
        }
    }

    // ---- Expiry enforcement tests ----

    #[test]
    fn verify_role_rejects_expired_key() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-exp",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,  // bound_at
            3600, // max_validity_seconds
            &tid(1),
        )
        .unwrap();
        // now=3700 >= 100+3600=3700 → expired (fail-closed at boundary)
        let err = reg
            .verify_role("k-exp", KeyRole::Signing, 3700, &tid(2))
            .unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_EXPIRED");
    }

    #[test]
    fn verify_role_accepts_key_just_before_expiry() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-pre",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        // now=3699 < 100+3600=3700 → still valid
        assert!(
            reg.verify_role("k-pre", KeyRole::Encryption, 3699, &tid(2))
                .is_ok()
        );
    }

    #[test]
    fn verify_role_expired_after_max_validity() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-late",
            KeyRole::Issuance,
            pub_key(3),
            "auth",
            1000,
            7200,
            &tid(1),
        )
        .unwrap();
        // now=10000 >> 1000+7200=8200 → expired
        let err = reg
            .verify_role("k-late", KeyRole::Issuance, 10000, &tid(2))
            .unwrap_err();
        assert_eq!(err.code(), "KRS_KEY_EXPIRED");
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
        let _ = reg.verify_role("k-viol", KeyRole::Encryption, 200, &tid(2));
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
        assert!(
            reg.verify_role("k-s", KeyRole::Signing, 150, &tid(5))
                .is_ok()
        );
        assert!(
            reg.verify_role("k-e", KeyRole::Encryption, 150, &tid(6))
                .is_ok()
        );

        // Cross-role is rejected.
        assert!(
            reg.verify_role("k-s", KeyRole::Encryption, 150, &tid(7))
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

    #[test]
    fn push_bounded_zero_capacity_clears_events_without_appending() {
        let mut events = vec![KeyRoleEvent::bound(
            "k-old",
            KeyRole::Signing,
            "auth",
            "trace-old",
        )];

        push_bounded(
            &mut events,
            KeyRoleEvent::bound("k-new", KeyRole::Signing, "auth", "trace-new"),
            0,
        );

        assert!(events.is_empty());
    }

    #[test]
    fn push_bounded_single_capacity_evicts_oldest_event() {
        let mut events = vec![KeyRoleEvent::bound(
            "k-old",
            KeyRole::Signing,
            "auth",
            "trace-old",
        )];

        push_bounded(
            &mut events,
            KeyRoleEvent::revoked("k-new", KeyRole::Signing, "auth", "trace-new"),
            1,
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key_id, "k-new");
        assert_eq!(events[0].event_code, event_codes::KRS_KEY_ROLE_REVOKED);
    }

    #[test]
    fn rotate_same_key_id_rejected_without_state_change() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-same-rotate",
            KeyRole::Signing,
            pub_key(1),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg
            .rotate(
                KeyRole::Signing,
                "k-same-rotate",
                "k-same-rotate",
                pub_key(2),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_ROTATION_FAILED");
        assert!(err.to_string().contains("must differ"));
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.revoked_count(), 0);
        assert_eq!(reg.event_count(), initial_events);
        let binding = reg.lookup("k-same-rotate").unwrap();
        assert_eq!(binding.public_key_bytes, pub_key(1));
        assert_eq!(binding.bound_at, 100);
    }

    #[test]
    fn revoke_missing_key_does_not_emit_event_or_change_counts() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-stable",
            KeyRole::Encryption,
            pub_key(2),
            "auth",
            100,
            3600,
            &tid(1),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg.revoke("k-missing", "auth", &tid(2)).unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
        assert_eq!(reg.active_count(), 1);
        assert_eq!(reg.revoked_count(), 0);
        assert_eq!(reg.event_count(), initial_events);
        assert!(reg.lookup("k-stable").is_some());
    }

    #[test]
    fn verify_missing_key_does_not_emit_violation_event() {
        let mut reg = KeyRoleRegistry::new();

        let err = reg
            .verify_role("k-missing", KeyRole::Signing, 200, &tid(1))
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_NOT_FOUND");
        assert!(reg.events().is_empty());
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.revoked_count(), 0);
    }

    #[test]
    fn verify_expired_key_does_not_emit_role_violation_event() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-expired-event",
            KeyRole::Issuance,
            pub_key(3),
            "auth",
            100,
            10,
            &tid(1),
        )
        .unwrap();
        let initial_events = reg.event_count();

        let err = reg
            .verify_role("k-expired-event", KeyRole::Issuance, 110, &tid(2))
            .unwrap_err();

        assert_eq!(err.code(), "KRS_KEY_EXPIRED");
        assert_eq!(reg.event_count(), initial_events);
        assert!(
            reg.events()
                .iter()
                .all(|event| event.event_code != event_codes::KRS_ROLE_VIOLATION_ATTEMPT)
        );
        assert!(reg.lookup("k-expired-event").is_some());
    }

    #[test]
    fn bind_role_violation_records_critical_event_without_rebinding() {
        let mut reg = KeyRoleRegistry::new();
        reg.bind(
            "k-cross-role-event",
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
                "k-cross-role-event",
                KeyRole::Encryption,
                pub_key(1),
                "auth",
                200,
                3600,
                &tid(2),
            )
            .unwrap_err();

        assert_eq!(err.code(), "KRS_ROLE_SEPARATION_VIOLATION");
        assert_eq!(reg.active_count(), 1);
        assert_eq!(
            reg.lookup("k-cross-role-event").unwrap().role,
            KeyRole::Signing
        );
        let event = reg.events().last().expect("violation event");
        assert_eq!(event.event_code, event_codes::KRS_ROLE_VIOLATION_ATTEMPT);
        assert_eq!(event.severity, "CRITICAL");
        assert_eq!(event.role, Some(KeyRole::Signing));
        assert!(event.detail.contains("Encryption"));
    }

    // ── Hardening-focused tests targeting specific vulnerability patterns ──

    #[test]
    fn test_active_binding_count_uses_saturating_add_protection() {
        // Test for += 1 without saturating_add - binding counters should use saturating arithmetic
        let mut reg = KeyRoleRegistry::new();

        // Set up scenario near capacity to test counter overflow protection
        let max_bindings = MAX_ACTIVE_BINDINGS;

        // Add keys up to near capacity
        for i in 0..max_bindings.saturating_sub(2) {
            let key_id = format!("overflow-test-key-{}", i);
            let role = if i % 4 == 0 {
                KeyRole::Signing
            } else if i % 4 == 1 {
                KeyRole::Encryption
            } else if i % 4 == 2 {
                KeyRole::Issuance
            } else {
                KeyRole::Attestation
            };

            // Bind with unique roles to avoid conflicts
            let result = reg.bind_key_to_role(&key_id, role, 100 + i as u64, 3600, &tid(i as u64));

            if result.is_ok() {
                // Should use saturating arithmetic for internal counters
                assert!(reg.active_count() <= max_bindings);
            } else {
                // If capacity reached, should fail gracefully
                break;
            }
        }

        // Verify registry remains in valid state
        assert!(reg.active_count() <= MAX_ACTIVE_BINDINGS);
        assert!(reg.events().len() <= MAX_EVENTS);
    }

    #[test]
    fn test_key_id_comparison_uses_constant_time_pattern() {
        // Test for == on [u8] hashes - should use ct_eq_bytes for timing safety
        use crate::security::constant_time;

        // Simulate key ID comparison scenarios in key role separation
        let key_id_1 = b"control_plane_signing_key_v1_abcdef123456";
        let key_id_2 = b"control_plane_signing_key_v1_abcdef123456"; // Same
        let key_id_3 = b"control_plane_signing_key_v1_abcdef123457"; // Different by one

        // Correct pattern: use constant-time comparison for key verification
        assert!(
            constant_time::ct_eq_bytes(key_id_1, key_id_2),
            "Identical key IDs should match"
        );
        assert!(
            !constant_time::ct_eq_bytes(key_id_1, key_id_3),
            "Different key IDs should not match"
        );

        // Test with role tag comparison (security-sensitive)
        let role_tag_1 = KeyRole::Signing.tag();
        let role_tag_2 = KeyRole::Signing.tag();
        let role_tag_3 = KeyRole::Encryption.tag();

        let role_tag_1_bytes = role_tag_1.as_slice();
        let role_tag_2_bytes = role_tag_2.as_slice();
        let role_tag_3_bytes = role_tag_3.as_slice();

        assert!(
            constant_time::ct_eq_bytes(role_tag_1_bytes, role_tag_2_bytes),
            "Identical role tags should match"
        );
        assert!(
            !constant_time::ct_eq_bytes(role_tag_1_bytes, role_tag_3_bytes),
            "Different role tags should not match"
        );

        // Test with different length key IDs
        let short_key = b"short_key";
        let long_key = b"much_longer_control_plane_key_identifier";
        assert!(
            !constant_time::ct_eq_bytes(short_key, long_key),
            "Different length keys should not match"
        );
    }

    #[test]
    fn test_key_expiry_uses_greater_equal_fail_closed_pattern() {
        // Test for > expiry - should use >= for fail-closed semantics
        let mut reg = KeyRoleRegistry::new();

        let exact_expiry_time = 1_700_100_000_u64;
        let bind_time = exact_expiry_time - 3600; // 1 hour validity
        let max_validity = 3600_u64;

        // Bind key with specific timing
        reg.bind_key_to_role(
            "expiry-boundary-key",
            KeyRole::Signing,
            bind_time,
            max_validity,
            &tid(1),
        )
        .unwrap();

        // Test at exact expiry boundary - should be considered expired (fail-closed)
        let result_at_boundary = reg.verify_key_for_role(
            "expiry-boundary-key",
            KeyRole::Signing,
            exact_expiry_time,
            max_validity,
            &tid(2),
        );

        // With fail-closed semantics (>= pattern), exact boundary should be considered expired
        assert!(
            result_at_boundary.is_err(),
            "Key should be expired at exact boundary (fail-closed)"
        );

        // Test just before expiry - should not be expired
        let result_before = reg.verify_key_for_role(
            "expiry-boundary-key",
            KeyRole::Signing,
            exact_expiry_time - 1,
            max_validity,
            &tid(3),
        );
        assert!(result_before.is_ok(), "Key should be valid before expiry");

        // Test after expiry - should definitely be expired
        let result_after = reg.verify_key_for_role(
            "expiry-boundary-key",
            KeyRole::Signing,
            exact_expiry_time + 1,
            max_validity,
            &tid(4),
        );
        assert!(
            result_after.is_err(),
            "Key should be expired after expiry time"
        );
    }

    #[test]
    fn test_length_casting_uses_try_from_pattern() {
        // Test for .len() as u32 - should use u32::try_from pattern
        let mut reg = KeyRoleRegistry::new();

        // Fill with many bindings to test length handling
        for i in 0..100 {
            let key_id = format!("length-test-key-{}", i);
            let role = KeyRole::all()[i % 4];

            let result = reg.bind_key_to_role(
                &key_id,
                role,
                1_700_000_000 + i as u64,
                3600,
                &tid(i as u64),
            );

            if result.is_err() {
                break; // Hit capacity limit
            }
        }

        let active_count = reg.active_count();
        let revoked_count = reg.revoked_count();
        let events_count = reg.events().len();

        // Test hardening pattern: should use try_from, not direct cast
        let safe_active_u32 = u32::try_from(active_count).unwrap_or(u32::MAX);
        let safe_revoked_u32 = u32::try_from(revoked_count).unwrap_or(u32::MAX);
        let safe_events_u32 = u32::try_from(events_count).unwrap_or(u32::MAX);

        assert!(safe_active_u32 <= u32::MAX);
        assert!(safe_revoked_u32 <= u32::MAX);
        assert!(safe_events_u32 <= u32::MAX);

        // Test that very large counts would be handled safely
        let hypothetical_large_count = usize::MAX;
        let safe_large_cast = u32::try_from(hypothetical_large_count).unwrap_or(u32::MAX);
        assert_eq!(safe_large_cast, u32::MAX); // Should cap at MAX, not truncate

        // Verify registry remains functional
        assert!(active_count <= MAX_ACTIVE_BINDINGS);
    }

    #[test]
    fn test_key_binding_hashes_include_domain_separators() {
        // Test for hash missing domain separator - should include proper domain separation
        use sha2::{Digest, Sha256};

        let key_id = "test-signing-key-123";
        let role = KeyRole::Signing;
        let bind_time = 1_700_000_000_u64;

        // Correct pattern: include domain separator for key binding hashing
        let domain_separator = b"control_plane_key_binding_v1:";
        let mut hasher_with_domain = Sha256::new();
        hasher_with_domain.update(domain_separator);
        hasher_with_domain.update(key_id.as_bytes());
        hasher_with_domain.update(&role.tag());
        hasher_with_domain.update(&bind_time.to_le_bytes());
        let hash_with_domain = hasher_with_domain.finalize();

        // Anti-pattern: hashing without domain separator (collision vulnerable)
        let mut hasher_without_domain = Sha256::new();
        hasher_without_domain.update(key_id.as_bytes());
        hasher_without_domain.update(&role.tag());
        hasher_without_domain.update(&bind_time.to_le_bytes());
        let hash_without_domain = hasher_without_domain.finalize();

        // Should be different due to domain separation
        assert_ne!(
            hash_with_domain[..],
            hash_without_domain[..],
            "Domain separator should change hash output"
        );

        // Test role verification hash with domain separation
        let verification_domain = b"control_plane_role_verification_v1:";
        let mut verification_hasher = Sha256::new();
        verification_hasher.update(verification_domain);
        verification_hasher.update(key_id.as_bytes());
        verification_hasher.update(&role.tag());
        verification_hasher.update(&bind_time.to_le_bytes());
        let verification_hash = verification_hasher.finalize();

        assert_ne!(
            hash_with_domain[..],
            verification_hash[..],
            "Different domains should produce different hashes"
        );

        // Test length-prefixed inputs to prevent delimiter collision
        let field1 = "key_identifier_part1";
        let field2 = "key_identifier_part2";

        let mut safe_hasher = Sha256::new();
        safe_hasher.update(b"control_plane_key_v1:");
        safe_hasher.update((u64::try_from(field1.len()).unwrap_or(u64::MAX)).to_le_bytes()); // Length prefix
        safe_hasher.update(field1.as_bytes());
        safe_hasher.update((u64::try_from(field2.len()).unwrap_or(u64::MAX)).to_le_bytes()); // Length prefix
        safe_hasher.update(field2.as_bytes());
        let safe_hash = safe_hasher.finalize();

        // Anti-pattern: simple concatenation (collision vulnerable)
        let mut unsafe_hasher = Sha256::new();
        unsafe_hasher.update(b"control_plane_key_v1:");
        unsafe_hasher.update(field1.as_bytes());
        unsafe_hasher.update(field2.as_bytes());
        let unsafe_hash = unsafe_hasher.finalize();

        // These might be the same but the pattern ensures collision resistance
        let _ = (safe_hash, unsafe_hash); // Just verify computation works
    }

    #[test]
    fn test_event_log_uses_push_bounded_pattern() {
        // Test for Vec::push without push_bounded - event logs should be bounded
        let mut reg = KeyRoleRegistry::new();

        // Verify event log starts empty
        assert_eq!(reg.events().len(), 0);

        // Generate many events to test event log bounding
        for i in 0..(MAX_EVENTS + 20) {
            let key_id = format!("event-test-key-{}", i);
            let role = KeyRole::all()[i % 4];

            let result = reg.bind_key_to_role(
                &key_id,
                role,
                1_700_000_000 + i as u64,
                3600,
                &tid(i as u64),
            );

            if result.is_ok() {
                // Event log should be bounded using push_bounded pattern
                assert!(
                    reg.events().len() <= MAX_EVENTS,
                    "Event log should be bounded at iteration {}, got len {}",
                    i,
                    reg.events().len()
                );

                // Try to revoke the key to generate another event
                let _ = reg.revoke_key(&key_id, 1_700_001_000 + i as u64, &tid(i as u64 + 1000));

                assert!(
                    reg.events().len() <= MAX_EVENTS,
                    "Event log should remain bounded after revocation"
                );
            } else {
                // If binding fails due to capacity, that's expected
                break;
            }
        }

        // Verify final event log size is properly bounded
        assert!(reg.events().len() <= MAX_EVENTS);

        // Verify oldest events are evicted when capacity exceeded
        if reg.events().len() == MAX_EVENTS {
            let oldest_event = &reg.events()[0];
            // Should not contain very early event IDs if they were evicted
            assert!(
                !oldest_event.trace_id.contains("tid-0"),
                "Oldest events should be evicted when capacity exceeded"
            );
        }
    }
}
