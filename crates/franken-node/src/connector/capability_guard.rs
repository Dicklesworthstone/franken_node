//! bd-cvt: Capability profiles for product subsystems with narrowing enforcement.
//!
//! Establishes explicit capability profiles for product subsystems. Each
//! subsystem declares what capabilities it needs, and the runtime enforces
//! that declaration. Undeclared capability usage is rejected. This implements
//! the least-privilege capability narrowing required by Section 9G.1.
//!
//! # Capability Taxonomy
//!
//! Capabilities use a hierarchical naming scheme:
//!
//! - `cap:network:listen` — Bind a listening socket.
//! - `cap:network:connect` — Initiate outbound connections.
//! - `cap:fs:read` — Read files from the file system.
//! - `cap:fs:write` — Write files to the file system.
//! - `cap:fs:temp` — Create/use temporary files.
//! - `cap:process:spawn` — Spawn child processes.
//! - `cap:crypto:sign` — Produce cryptographic signatures.
//! - `cap:crypto:verify` — Verify cryptographic signatures.
//! - `cap:crypto:derive` — Derive keys or key material.
//! - `cap:trust:read` — Read trust state.
//! - `cap:trust:write` — Mutate trust state.
//! - `cap:trust:revoke` — Revoke trust objects.
//!
//! # Invariants
//!
//! - INV-CAP-LEAST-PRIVILEGE: Subsystems receive only their declared capabilities.
//! - INV-CAP-DENY-DEFAULT: Any capability not explicitly granted is denied.
//! - INV-CAP-AUDIT-COMPLETE: Every grant/deny decision is recorded in the audit trail.
//! - INV-CAP-PROFILE-VERSIONED: Capability profiles carry a version; changes are detected.
//! - INV-CAP-DETERMINISTIC: All outputs use BTreeMap for deterministic ordering.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Capability granted to subsystem.
    pub const CAP_001: &str = "CAP-001";
    /// Capability denied to subsystem.
    pub const CAP_002: &str = "CAP-002";
    /// Capability profile changed (version mismatch).
    pub const CAP_003: &str = "CAP-003";
    /// Audit gap detected (missing audit entries).
    pub const CAP_004: &str = "CAP-004";
    /// Capability profile loaded.
    pub const CAP_005: &str = "CAP-005";
    /// Capability guard initialized.
    pub const CAP_006: &str = "CAP-006";
    /// Subsystem capability check completed.
    pub const CAP_007: &str = "CAP-007";
    /// Capability narrowing enforced.
    pub const CAP_008: &str = "CAP-008";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CAP_UNDECLARED: &str = "ERR_CAP_UNDECLARED";
    pub const ERR_CAP_DENIED: &str = "ERR_CAP_DENIED";
    pub const ERR_CAP_PROFILE_MISSING: &str = "ERR_CAP_PROFILE_MISSING";
    pub const ERR_CAP_INVALID_LEVEL: &str = "ERR_CAP_INVALID_LEVEL";
    pub const ERR_CAP_AUDIT_FAILURE: &str = "ERR_CAP_AUDIT_FAILURE";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_CAP_LEAST_PRIVILEGE: &str = "INV-CAP-LEAST-PRIVILEGE";
    pub const INV_CAP_DENY_DEFAULT: &str = "INV-CAP-DENY-DEFAULT";
    pub const INV_CAP_AUDIT_COMPLETE: &str = "INV-CAP-AUDIT-COMPLETE";
    pub const INV_CAP_PROFILE_VERSIONED: &str = "INV-CAP-PROFILE-VERSIONED";
    pub const INV_CAP_DETERMINISTIC: &str = "INV-CAP-DETERMINISTIC";
}

/// Schema version for capability profile format.
pub const SCHEMA_VERSION: &str = "cap-v1.0";

// ---------------------------------------------------------------------------
// CapabilityName
// ---------------------------------------------------------------------------

/// A capability in the hierarchical taxonomy.
///
/// Capabilities follow the pattern `cap:<domain>:<action>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapabilityName(pub String);

impl CapabilityName {
    /// Create a new capability name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is a valid capability name in the taxonomy.
    pub fn is_valid(&self) -> bool {
        CAPABILITY_TAXONOMY.iter().any(|entry| entry.name == self.0)
    }
}

impl fmt::Display for CapabilityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// RiskLevel
// ---------------------------------------------------------------------------

/// Risk classification for capabilities and subsystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// CapabilityTaxonomyEntry
// ---------------------------------------------------------------------------

/// A single entry in the capability taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityTaxonomyEntry {
    /// Capability name (e.g., "cap:network:listen").
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Risk level of this capability.
    pub risk_level: RiskLevel,
    /// Whether this capability requires audit logging.
    pub audit_required: bool,
}

/// The complete capability taxonomy (12 capabilities).
pub const CAPABILITY_TAXONOMY: &[CapabilityTaxonomyEntry] = &[
    CapabilityTaxonomyEntry {
        name: "cap:network:listen",
        description: "Bind a listening socket for inbound connections",
        risk_level: RiskLevel::High,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:network:connect",
        description: "Initiate outbound network connections",
        risk_level: RiskLevel::Medium,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:fs:read",
        description: "Read files from the file system",
        risk_level: RiskLevel::Low,
        audit_required: false,
    },
    CapabilityTaxonomyEntry {
        name: "cap:fs:write",
        description: "Write files to the file system",
        risk_level: RiskLevel::Medium,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:fs:temp",
        description: "Create and use temporary files",
        risk_level: RiskLevel::Low,
        audit_required: false,
    },
    CapabilityTaxonomyEntry {
        name: "cap:process:spawn",
        description: "Spawn child processes",
        risk_level: RiskLevel::Critical,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:crypto:sign",
        description: "Produce cryptographic signatures",
        risk_level: RiskLevel::Critical,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:crypto:verify",
        description: "Verify cryptographic signatures",
        risk_level: RiskLevel::Low,
        audit_required: false,
    },
    CapabilityTaxonomyEntry {
        name: "cap:crypto:derive",
        description: "Derive keys or key material",
        risk_level: RiskLevel::Critical,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:trust:read",
        description: "Read trust state from the trust store",
        risk_level: RiskLevel::Low,
        audit_required: false,
    },
    CapabilityTaxonomyEntry {
        name: "cap:trust:write",
        description: "Mutate trust state in the trust store",
        risk_level: RiskLevel::High,
        audit_required: true,
    },
    CapabilityTaxonomyEntry {
        name: "cap:trust:revoke",
        description: "Revoke trust objects (irreversible)",
        risk_level: RiskLevel::Critical,
        audit_required: true,
    },
];

/// Return the full capability taxonomy as a BTreeMap for deterministic output.
///
/// # INV-CAP-DETERMINISTIC
pub fn capability_taxonomy() -> BTreeMap<String, CapabilityTaxonomyEntry> {
    let mut map = BTreeMap::new();
    for entry in CAPABILITY_TAXONOMY {
        map.insert(entry.name.to_string(), entry.clone());
    }
    map
}

/// All capability names in the taxonomy.
pub fn all_capability_names() -> Vec<String> {
    CAPABILITY_TAXONOMY
        .iter()
        .map(|e| e.name.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// CapabilityJustification
// ---------------------------------------------------------------------------

/// A capability requirement with justification for why the subsystem needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityJustification {
    /// The capability name.
    pub capability: String,
    /// Why this subsystem needs this capability.
    pub justification: String,
}

// ---------------------------------------------------------------------------
// CapabilityProfile
// ---------------------------------------------------------------------------

/// Capability profile for a product subsystem.
///
/// # INV-CAP-LEAST-PRIVILEGE
/// Each subsystem declares only the capabilities it needs with justification.
///
/// # INV-CAP-PROFILE-VERSIONED
/// Profiles carry a version string; changes trigger security review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProfile {
    /// Subsystem name (e.g., "trust_fabric").
    pub subsystem: String,
    /// Profile version for change detection.
    pub version: String,
    /// Risk level of this subsystem.
    pub risk_level: RiskLevel,
    /// Required capabilities with justifications, keyed by capability name.
    pub capabilities: BTreeMap<String, CapabilityJustification>,
}

impl CapabilityProfile {
    /// Create a new empty profile.
    pub fn new(
        subsystem: impl Into<String>,
        version: impl Into<String>,
        risk_level: RiskLevel,
    ) -> Self {
        Self {
            subsystem: subsystem.into(),
            version: version.into(),
            risk_level,
            capabilities: BTreeMap::new(),
        }
    }

    /// Add a capability requirement with justification.
    pub fn add_capability(
        &mut self,
        capability: impl Into<String>,
        justification: impl Into<String>,
    ) {
        let cap = capability.into();
        self.capabilities.insert(
            cap.clone(),
            CapabilityJustification {
                capability: cap,
                justification: justification.into(),
            },
        );
    }

    /// Check if this profile declares a specific capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains_key(capability)
    }

    /// Number of declared capabilities.
    pub fn capability_count(&self) -> usize {
        self.capabilities.len()
    }

    /// All declared capability names, sorted.
    pub fn capability_names(&self) -> Vec<String> {
        self.capabilities.keys().cloned().collect()
    }

    /// Validate that all declared capabilities exist in the taxonomy.
    pub fn validate(&self) -> Vec<CapabilityGuardError> {
        let valid_names: Vec<String> = all_capability_names();
        let mut errors = Vec::new();
        for cap_name in self.capabilities.keys() {
            if !valid_names.contains(cap_name) {
                errors.push(CapabilityGuardError::UndeclaredCapability {
                    subsystem: self.subsystem.clone(),
                    capability: cap_name.clone(),
                });
            }
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// ProfileChange
// ---------------------------------------------------------------------------

/// Detected change in a subsystem's capability profile.
///
/// # INV-CAP-PROFILE-VERSIONED
/// Changes are flagged for security review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileChange {
    /// Subsystem whose profile changed.
    pub subsystem: String,
    /// Previous version.
    pub old_version: String,
    /// New version.
    pub new_version: String,
    /// Capabilities added in the new version.
    pub added: Vec<String>,
    /// Capabilities removed in the new version.
    pub removed: Vec<String>,
    /// Whether this change requires security review.
    pub requires_review: bool,
}

impl ProfileChange {
    /// Detect changes between two profiles for the same subsystem.
    pub fn detect(old: &CapabilityProfile, new: &CapabilityProfile) -> Option<Self> {
        if old.version == new.version && old.capabilities == new.capabilities {
            return None;
        }
        let old_caps: std::collections::BTreeSet<&String> = old.capabilities.keys().collect();
        let new_caps: std::collections::BTreeSet<&String> = new.capabilities.keys().collect();
        let added: Vec<String> = new_caps
            .difference(&old_caps)
            .map(|s| (*s).clone())
            .collect();
        let removed: Vec<String> = old_caps
            .difference(&new_caps)
            .map(|s| (*s).clone())
            .collect();
        let requires_review = !added.is_empty() || !removed.is_empty();
        Some(Self {
            subsystem: new.subsystem.clone(),
            old_version: old.version.clone(),
            new_version: new.version.clone(),
            added,
            removed,
            requires_review,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityAuditEntry
// ---------------------------------------------------------------------------

/// Audit trail entry for a capability grant/deny decision.
///
/// # INV-CAP-AUDIT-COMPLETE
/// Every decision is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAuditEntry {
    /// Subsystem identity.
    pub subsystem: String,
    /// Capability name.
    pub capability: String,
    /// Timestamp (ISO 8601).
    pub timestamp: String,
    /// Outcome: "granted" or "denied".
    pub outcome: String,
    /// Event code for this entry.
    pub event_code: String,
    /// Additional detail.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// CapabilityGuardError
// ---------------------------------------------------------------------------

/// Errors from capability guard operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityGuardError {
    UndeclaredCapability {
        subsystem: String,
        capability: String,
    },
    CapabilityDenied {
        subsystem: String,
        capability: String,
    },
    ProfileMissing {
        subsystem: String,
    },
    InvalidLevel {
        level: String,
    },
    AuditFailure {
        detail: String,
    },
}

impl CapabilityGuardError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UndeclaredCapability { .. } => error_codes::ERR_CAP_UNDECLARED,
            Self::CapabilityDenied { .. } => error_codes::ERR_CAP_DENIED,
            Self::ProfileMissing { .. } => error_codes::ERR_CAP_PROFILE_MISSING,
            Self::InvalidLevel { .. } => error_codes::ERR_CAP_INVALID_LEVEL,
            Self::AuditFailure { .. } => error_codes::ERR_CAP_AUDIT_FAILURE,
        }
    }
}

impl fmt::Display for CapabilityGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndeclaredCapability {
                subsystem,
                capability,
            } => write!(
                f,
                "capability {capability} not declared in profile for {subsystem}"
            ),
            Self::CapabilityDenied {
                subsystem,
                capability,
            } => write!(
                f,
                "capability {capability} denied for subsystem {subsystem}"
            ),
            Self::ProfileMissing { subsystem } => {
                write!(f, "no capability profile registered for {subsystem}")
            }
            Self::InvalidLevel { level } => {
                write!(f, "invalid risk level: {level}")
            }
            Self::AuditFailure { detail } => {
                write!(f, "audit failure: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityGuard
// ---------------------------------------------------------------------------

/// Guard that checks a calling subsystem's profile and grants or denies
/// capability requests.
///
/// # INV-CAP-DENY-DEFAULT
/// Any capability not explicitly granted in the profile is denied.
///
/// # INV-CAP-AUDIT-COMPLETE
/// Every check produces an audit entry.
///
/// # INV-CAP-DETERMINISTIC
/// Profiles stored in BTreeMap for deterministic iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGuard {
    /// Schema version.
    pub schema_version: String,
    /// Registered capability profiles, keyed by subsystem name.
    pub profiles: BTreeMap<String, CapabilityProfile>,
    /// Audit trail.
    pub audit_trail: Vec<CapabilityAuditEntry>,
    /// Events emitted during guard operations.
    pub events: Vec<CapabilityGuardEvent>,
}

impl CapabilityGuard {
    /// Create a new empty guard.
    pub fn new() -> Self {
        let mut guard = Self {
            schema_version: SCHEMA_VERSION.to_string(),
            profiles: BTreeMap::new(),
            audit_trail: Vec::new(),
            events: Vec::new(),
        };
        guard.events.push(CapabilityGuardEvent {
            event_code: event_codes::CAP_006.to_string(),
            subsystem: String::new(),
            detail: "capability guard initialized".to_string(),
        });
        guard
    }

    /// Register a capability profile for a subsystem.
    ///
    /// # INV-CAP-PROFILE-VERSIONED
    /// If a profile already exists for this subsystem, a ProfileChange is detected.
    pub fn register_profile(&mut self, profile: CapabilityProfile) -> Option<ProfileChange> {
        let change = if let Some(existing) = self.profiles.get(&profile.subsystem) {
            let change = ProfileChange::detect(existing, &profile);
            if let Some(ref c) = change {
                self.events.push(CapabilityGuardEvent {
                    event_code: event_codes::CAP_003.to_string(),
                    subsystem: profile.subsystem.clone(),
                    detail: format!(
                        "profile changed from {} to {} (added: {:?}, removed: {:?})",
                        c.old_version, c.new_version, c.added, c.removed,
                    ),
                });
            }
            change
        } else {
            None
        };

        self.events.push(CapabilityGuardEvent {
            event_code: event_codes::CAP_005.to_string(),
            subsystem: profile.subsystem.clone(),
            detail: format!(
                "profile loaded: {} caps at {} risk",
                profile.capability_count(),
                profile.risk_level,
            ),
        });

        self.profiles.insert(profile.subsystem.clone(), profile);
        change
    }

    /// Check whether a subsystem is allowed to use a capability.
    ///
    /// # INV-CAP-DENY-DEFAULT
    /// Returns `Err` if the capability is not in the subsystem's profile.
    ///
    /// # INV-CAP-AUDIT-COMPLETE
    /// Records an audit entry for every check.
    pub fn check_capability(
        &mut self,
        subsystem: &str,
        capability: &str,
        timestamp: &str,
    ) -> Result<(), CapabilityGuardError> {
        let profile = match self.profiles.get(subsystem) {
            Some(p) => p.clone(),
            None => {
                let entry = CapabilityAuditEntry {
                    subsystem: subsystem.to_string(),
                    capability: capability.to_string(),
                    timestamp: timestamp.to_string(),
                    outcome: "denied".to_string(),
                    event_code: event_codes::CAP_002.to_string(),
                    detail: format!("no profile registered for subsystem {subsystem}"),
                };
                self.audit_trail.push(entry);
                self.events.push(CapabilityGuardEvent {
                    event_code: event_codes::CAP_002.to_string(),
                    subsystem: subsystem.to_string(),
                    detail: format!("denied {capability}: profile missing"),
                });
                return Err(CapabilityGuardError::ProfileMissing {
                    subsystem: subsystem.to_string(),
                });
            }
        };

        if profile.has_capability(capability) {
            let entry = CapabilityAuditEntry {
                subsystem: subsystem.to_string(),
                capability: capability.to_string(),
                timestamp: timestamp.to_string(),
                outcome: "granted".to_string(),
                event_code: event_codes::CAP_001.to_string(),
                detail: format!("capability {capability} granted to {subsystem}"),
            };
            self.audit_trail.push(entry);
            self.events.push(CapabilityGuardEvent {
                event_code: event_codes::CAP_001.to_string(),
                subsystem: subsystem.to_string(),
                detail: format!("granted {capability}"),
            });
            self.events.push(CapabilityGuardEvent {
                event_code: event_codes::CAP_008.to_string(),
                subsystem: subsystem.to_string(),
                detail: format!("narrowing enforced: {capability} within profile"),
            });
            Ok(())
        } else {
            // INV-CAP-DENY-DEFAULT: not in profile => denied
            let entry = CapabilityAuditEntry {
                subsystem: subsystem.to_string(),
                capability: capability.to_string(),
                timestamp: timestamp.to_string(),
                outcome: "denied".to_string(),
                event_code: event_codes::CAP_002.to_string(),
                detail: format!("capability {capability} not declared in profile for {subsystem}"),
            };
            self.audit_trail.push(entry);
            self.events.push(CapabilityGuardEvent {
                event_code: event_codes::CAP_002.to_string(),
                subsystem: subsystem.to_string(),
                detail: format!("denied {capability}: not in profile"),
            });
            Err(CapabilityGuardError::CapabilityDenied {
                subsystem: subsystem.to_string(),
                capability: capability.to_string(),
            })
        }
    }

    /// Check all capabilities for a subsystem and return a report.
    ///
    /// # INV-CAP-AUDIT-COMPLETE
    pub fn check_all(
        &mut self,
        subsystem: &str,
        requested: &[&str],
        timestamp: &str,
    ) -> CapabilityCheckReport {
        let mut granted = Vec::new();
        let mut denied = Vec::new();
        for cap in requested {
            match self.check_capability(subsystem, cap, timestamp) {
                Ok(()) => granted.push(cap.to_string()),
                Err(e) => denied.push((cap.to_string(), e)),
            }
        }
        self.events.push(CapabilityGuardEvent {
            event_code: event_codes::CAP_007.to_string(),
            subsystem: subsystem.to_string(),
            detail: format!(
                "check completed: {}/{} granted",
                granted.len(),
                granted.len() + denied.len(),
            ),
        });
        let verdict = if denied.is_empty() { "PASS" } else { "FAIL" };
        CapabilityCheckReport {
            subsystem: subsystem.to_string(),
            granted,
            denied: denied
                .into_iter()
                .map(|(cap, err)| (cap, err.code().to_string()))
                .collect(),
            verdict: verdict.to_string(),
        }
    }

    /// Return the audit trail.
    pub fn audit_trail(&self) -> &[CapabilityAuditEntry] {
        &self.audit_trail
    }

    /// Return events.
    pub fn events(&self) -> &[CapabilityGuardEvent] {
        &self.events
    }

    /// Number of registered profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Check for audit gaps (subsystems with no audit entries).
    pub fn detect_audit_gaps(&mut self) -> Vec<String> {
        let audited: std::collections::BTreeSet<String> = self
            .audit_trail
            .iter()
            .map(|e| e.subsystem.clone())
            .collect();
        let mut gaps = Vec::new();
        for subsystem in self.profiles.keys() {
            if !audited.contains(subsystem) {
                gaps.push(subsystem.clone());
                self.events.push(CapabilityGuardEvent {
                    event_code: event_codes::CAP_004.to_string(),
                    subsystem: subsystem.clone(),
                    detail: "audit gap: no capability checks recorded".to_string(),
                });
            }
        }
        gaps
    }

    /// Build a guard preloaded with the default product subsystem profiles.
    pub fn with_default_profiles() -> Self {
        let mut guard = Self::new();
        for profile in default_profiles() {
            guard.register_profile(profile);
        }
        guard
    }
}

impl Default for CapabilityGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CapabilityGuardEvent
// ---------------------------------------------------------------------------

/// Structured event emitted by the capability guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGuardEvent {
    pub event_code: String,
    pub subsystem: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// CapabilityCheckReport
// ---------------------------------------------------------------------------

/// Report from checking multiple capabilities for a subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCheckReport {
    pub subsystem: String,
    pub granted: Vec<String>,
    pub denied: Vec<(String, String)>,
    pub verdict: String,
}

impl CapabilityCheckReport {
    pub fn summary(&self) -> String {
        format!(
            "CapabilityCheck(subsystem={}, granted={}, denied={}, verdict={})",
            self.subsystem,
            self.granted.len(),
            self.denied.len(),
            self.verdict,
        )
    }
}

// ---------------------------------------------------------------------------
// Default product profiles
// ---------------------------------------------------------------------------

/// Build the default product subsystem capability profiles.
pub fn default_profiles() -> Vec<CapabilityProfile> {
    let mut profiles = Vec::new();

    // trust_fabric
    let mut tf = CapabilityProfile::new("trust_fabric", "1.0.0", RiskLevel::High);
    tf.add_capability("cap:trust:read", "Reads trust state for convergence checks");
    tf.add_capability(
        "cap:trust:write",
        "Writes updated trust state after convergence",
    );
    tf.add_capability(
        "cap:network:connect",
        "Connects to peer nodes for trust gossip",
    );
    profiles.push(tf);

    // migration_engine
    let mut me = CapabilityProfile::new("migration_engine", "1.0.0", RiskLevel::Medium);
    me.add_capability("cap:fs:read", "Reads migration data files");
    me.add_capability("cap:fs:write", "Writes migrated data output");
    me.add_capability(
        "cap:crypto:verify",
        "Verifies signatures on migration bundles",
    );
    profiles.push(me);

    // epoch_guard
    let mut eg = CapabilityProfile::new("epoch_guard", "1.0.0", RiskLevel::Critical);
    eg.add_capability("cap:crypto:sign", "Signs epoch transition attestations");
    eg.add_capability("cap:crypto:verify", "Verifies prior epoch signatures");
    eg.add_capability("cap:trust:read", "Reads trust state for epoch validation");
    profiles.push(eg);

    // artifact_signing
    let mut as_ = CapabilityProfile::new("artifact_signing", "1.0.0", RiskLevel::Critical);
    as_.add_capability("cap:crypto:sign", "Signs build and release artifacts");
    as_.add_capability("cap:crypto:derive", "Derives per-artifact signing keys");
    profiles.push(as_);

    // network_guard
    let mut ng = CapabilityProfile::new("network_guard", "1.0.0", RiskLevel::High);
    ng.add_capability(
        "cap:network:listen",
        "Binds listening sockets for inbound traffic",
    );
    ng.add_capability(
        "cap:network:connect",
        "Establishes outbound connections for egress checks",
    );
    profiles.push(ng);

    profiles
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Event codes ──────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::CAP_001, "CAP-001");
        assert_eq!(event_codes::CAP_002, "CAP-002");
        assert_eq!(event_codes::CAP_003, "CAP-003");
        assert_eq!(event_codes::CAP_004, "CAP-004");
        assert_eq!(event_codes::CAP_005, "CAP-005");
        assert_eq!(event_codes::CAP_006, "CAP-006");
        assert_eq!(event_codes::CAP_007, "CAP-007");
        assert_eq!(event_codes::CAP_008, "CAP-008");
    }

    // ── Error codes ──────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(error_codes::ERR_CAP_UNDECLARED, "ERR_CAP_UNDECLARED");
        assert_eq!(error_codes::ERR_CAP_DENIED, "ERR_CAP_DENIED");
        assert_eq!(
            error_codes::ERR_CAP_PROFILE_MISSING,
            "ERR_CAP_PROFILE_MISSING"
        );
        assert_eq!(error_codes::ERR_CAP_INVALID_LEVEL, "ERR_CAP_INVALID_LEVEL");
        assert_eq!(error_codes::ERR_CAP_AUDIT_FAILURE, "ERR_CAP_AUDIT_FAILURE");
    }

    // ── Invariants ───────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(
            invariants::INV_CAP_LEAST_PRIVILEGE,
            "INV-CAP-LEAST-PRIVILEGE"
        );
        assert_eq!(invariants::INV_CAP_DENY_DEFAULT, "INV-CAP-DENY-DEFAULT");
        assert_eq!(invariants::INV_CAP_AUDIT_COMPLETE, "INV-CAP-AUDIT-COMPLETE");
        assert_eq!(
            invariants::INV_CAP_PROFILE_VERSIONED,
            "INV-CAP-PROFILE-VERSIONED"
        );
        assert_eq!(invariants::INV_CAP_DETERMINISTIC, "INV-CAP-DETERMINISTIC");
    }

    // ── Schema version ───────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "cap-v1.0");
    }

    // ── Capability taxonomy ──────────────────────────────────────────

    #[test]
    fn test_taxonomy_has_12_capabilities() {
        assert_eq!(CAPABILITY_TAXONOMY.len(), 12);
    }

    #[test]
    fn test_taxonomy_names_unique() {
        let names: Vec<&str> = CAPABILITY_TAXONOMY.iter().map(|e| e.name).collect();
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn test_taxonomy_all_have_cap_prefix() {
        for entry in CAPABILITY_TAXONOMY {
            assert!(
                entry.name.starts_with("cap:"),
                "capability {} does not start with 'cap:'",
                entry.name
            );
        }
    }

    #[test]
    fn test_capability_taxonomy_btreemap() {
        let map = capability_taxonomy();
        assert_eq!(map.len(), 12);
        // BTreeMap keys are sorted
        let keys: Vec<String> = map.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn test_all_capability_names() {
        let names = all_capability_names();
        assert_eq!(names.len(), 12);
        assert!(names.contains(&"cap:network:listen".to_string()));
        assert!(names.contains(&"cap:trust:revoke".to_string()));
    }

    // ── CapabilityName ───────────────────────────────────────────────

    #[test]
    fn test_capability_name_valid() {
        let name = CapabilityName::new("cap:network:listen");
        assert!(name.is_valid());
        assert_eq!(name.as_str(), "cap:network:listen");
    }

    #[test]
    fn test_capability_name_invalid() {
        let name = CapabilityName::new("cap:bogus:thing");
        assert!(!name.is_valid());
    }

    #[test]
    fn test_capability_name_display() {
        let name = CapabilityName::new("cap:fs:read");
        assert_eq!(format!("{name}"), "cap:fs:read");
    }

    // ── RiskLevel ────────────────────────────────────────────────────

    #[test]
    fn test_risk_level_labels() {
        assert_eq!(RiskLevel::Low.label(), "low");
        assert_eq!(RiskLevel::Medium.label(), "medium");
        assert_eq!(RiskLevel::High.label(), "high");
        assert_eq!(RiskLevel::Critical.label(), "critical");
    }

    #[test]
    fn test_risk_level_from_label() {
        assert_eq!(RiskLevel::from_label("low"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::from_label("critical"), Some(RiskLevel::Critical));
        assert_eq!(RiskLevel::from_label("bogus"), None);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_serde() {
        let json = serde_json::to_string(&RiskLevel::Critical).unwrap();
        let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, RiskLevel::Critical);
    }

    // ── CapabilityProfile ────────────────────────────────────────────

    #[test]
    fn test_profile_new() {
        let profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Medium);
        assert_eq!(profile.subsystem, "test_sub");
        assert_eq!(profile.version, "1.0.0");
        assert_eq!(profile.risk_level, RiskLevel::Medium);
        assert_eq!(profile.capability_count(), 0);
    }

    #[test]
    fn test_profile_add_capability() {
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "needs to read config files");
        assert!(profile.has_capability("cap:fs:read"));
        assert!(!profile.has_capability("cap:fs:write"));
        assert_eq!(profile.capability_count(), 1);
    }

    #[test]
    fn test_profile_capability_names_sorted() {
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:trust:write", "write trust");
        profile.add_capability("cap:fs:read", "read files");
        profile.add_capability("cap:network:connect", "connect");
        let names = profile.capability_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "capability names must be sorted (BTreeMap)");
    }

    #[test]
    fn test_profile_validate_all_valid() {
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read files");
        profile.add_capability("cap:crypto:verify", "verify sigs");
        let errors = profile.validate();
        assert!(errors.is_empty());
    }

    #[test]
    fn test_profile_validate_invalid_capability() {
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:bogus:thing", "invalid cap");
        let errors = profile.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code(), error_codes::ERR_CAP_UNDECLARED);
    }

    #[test]
    fn test_profile_serde() {
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::High);
        profile.add_capability("cap:fs:read", "read");
        let json = serde_json::to_string(&profile).unwrap();
        let parsed: CapabilityProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.subsystem, "test_sub");
        assert!(parsed.has_capability("cap:fs:read"));
    }

    // ── ProfileChange ────────────────────────────────────────────────

    #[test]
    fn test_profile_change_none_when_same() {
        let mut p1 = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        p1.add_capability("cap:fs:read", "read");
        let p2 = p1.clone();
        assert!(ProfileChange::detect(&p1, &p2).is_none());
    }

    #[test]
    fn test_profile_change_detected_on_version_bump() {
        let mut p1 = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        p1.add_capability("cap:fs:read", "read");
        let mut p2 = p1.clone();
        p2.version = "1.1.0".to_string();
        p2.add_capability("cap:fs:write", "write");
        let change = ProfileChange::detect(&p1, &p2).unwrap();
        assert_eq!(change.old_version, "1.0.0");
        assert_eq!(change.new_version, "1.1.0");
        assert!(change.added.contains(&"cap:fs:write".to_string()));
        assert!(change.requires_review);
    }

    #[test]
    fn test_profile_change_removed_capability() {
        let mut p1 = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        p1.add_capability("cap:fs:read", "read");
        p1.add_capability("cap:fs:write", "write");
        let mut p2 = CapabilityProfile::new("sub", "1.1.0", RiskLevel::Low);
        p2.add_capability("cap:fs:read", "read");
        let change = ProfileChange::detect(&p1, &p2).unwrap();
        assert!(change.removed.contains(&"cap:fs:write".to_string()));
    }

    // ── CapabilityGuard: grant/deny ──────────────────────────────────

    #[test]
    fn test_guard_new() {
        let guard = CapabilityGuard::new();
        assert_eq!(guard.schema_version, SCHEMA_VERSION);
        assert_eq!(guard.profile_count(), 0);
        assert!(guard.audit_trail().is_empty());
    }

    #[test]
    fn test_guard_register_profile() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        let change = guard.register_profile(profile);
        assert!(change.is_none()); // first registration, no change
        assert_eq!(guard.profile_count(), 1);
    }

    #[test]
    fn test_guard_register_profile_change_detection() {
        let mut guard = CapabilityGuard::new();
        let mut p1 = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        p1.add_capability("cap:fs:read", "read");
        guard.register_profile(p1);
        let mut p2 = CapabilityProfile::new("sub", "1.1.0", RiskLevel::Low);
        p2.add_capability("cap:fs:read", "read");
        p2.add_capability("cap:fs:write", "write");
        let change = guard.register_profile(p2);
        assert!(change.is_some());
        let c = change.unwrap();
        assert!(c.added.contains(&"cap:fs:write".to_string()));
    }

    #[test]
    fn test_guard_check_capability_granted() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("trust_fabric", "1.0.0", RiskLevel::High);
        profile.add_capability("cap:trust:read", "read trust");
        guard.register_profile(profile);

        let result =
            guard.check_capability("trust_fabric", "cap:trust:read", "2026-02-21T00:00:00Z");
        assert!(result.is_ok());
        assert_eq!(guard.audit_trail().len(), 1);
        assert_eq!(guard.audit_trail()[0].outcome, "granted");
    }

    #[test]
    fn test_guard_check_capability_denied_not_in_profile() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("trust_fabric", "1.0.0", RiskLevel::High);
        profile.add_capability("cap:trust:read", "read trust");
        guard.register_profile(profile);

        // INV-CAP-DENY-DEFAULT: cap:trust:write not in profile => denied
        let result =
            guard.check_capability("trust_fabric", "cap:trust:write", "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        assert_eq!(guard.audit_trail().last().unwrap().outcome, "denied");
    }

    #[test]
    fn test_guard_check_capability_denied_no_profile() {
        let mut guard = CapabilityGuard::new();
        let result =
            guard.check_capability("unknown_subsystem", "cap:fs:read", "2026-02-21T00:00:00Z");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CAP_PROFILE_MISSING);
    }

    #[test]
    fn test_guard_check_all_pass() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("epoch_guard", "1.0.0", RiskLevel::Critical);
        profile.add_capability("cap:crypto:sign", "sign");
        profile.add_capability("cap:crypto:verify", "verify");
        guard.register_profile(profile);

        let report = guard.check_all(
            "epoch_guard",
            &["cap:crypto:sign", "cap:crypto:verify"],
            "2026-02-21T00:00:00Z",
        );
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.granted.len(), 2);
        assert!(report.denied.is_empty());
    }

    #[test]
    fn test_guard_check_all_partial_deny() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("epoch_guard", "1.0.0", RiskLevel::Critical);
        profile.add_capability("cap:crypto:sign", "sign");
        guard.register_profile(profile);

        let report = guard.check_all(
            "epoch_guard",
            &["cap:crypto:sign", "cap:crypto:verify"],
            "2026-02-21T00:00:00Z",
        );
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.granted.len(), 1);
        assert_eq!(report.denied.len(), 1);
    }

    #[test]
    fn test_guard_audit_trail_completeness() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile);

        // 3 checks => 3 audit entries
        let _ = guard.check_capability("sub", "cap:fs:read", "t1");
        let _ = guard.check_capability("sub", "cap:fs:write", "t2");
        let _ = guard.check_capability("sub", "cap:fs:read", "t3");
        assert_eq!(guard.audit_trail().len(), 3);
    }

    #[test]
    fn test_guard_detect_audit_gaps() {
        let mut guard = CapabilityGuard::new();
        let p1 = CapabilityProfile::new("sub_a", "1.0.0", RiskLevel::Low);
        let p2 = CapabilityProfile::new("sub_b", "1.0.0", RiskLevel::Low);
        guard.register_profile(p1);
        guard.register_profile(p2);
        // No checks performed => both have audit gaps
        let gaps = guard.detect_audit_gaps();
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn test_guard_events_include_init() {
        let guard = CapabilityGuard::new();
        assert!(
            guard
                .events()
                .iter()
                .any(|e| e.event_code == event_codes::CAP_006)
        );
    }

    // ── Default profiles ─────────────────────────────────────────────

    #[test]
    fn test_default_profiles_count() {
        let profiles = default_profiles();
        assert_eq!(profiles.len(), 5);
    }

    #[test]
    fn test_default_profiles_names() {
        let profiles = default_profiles();
        let names: Vec<&str> = profiles.iter().map(|p| p.subsystem.as_str()).collect();
        assert!(names.contains(&"trust_fabric"));
        assert!(names.contains(&"migration_engine"));
        assert!(names.contains(&"epoch_guard"));
        assert!(names.contains(&"artifact_signing"));
        assert!(names.contains(&"network_guard"));
    }

    #[test]
    fn test_default_profiles_all_valid() {
        for profile in default_profiles() {
            let errors = profile.validate();
            assert!(
                errors.is_empty(),
                "profile {} has invalid capabilities: {:?}",
                profile.subsystem,
                errors,
            );
        }
    }

    #[test]
    fn test_guard_with_default_profiles() {
        let guard = CapabilityGuard::with_default_profiles();
        assert_eq!(guard.profile_count(), 5);
    }

    // ── CapabilityGuardError ─────────────────────────────────────────

    #[test]
    fn test_error_codes_mapping() {
        let e1 = CapabilityGuardError::UndeclaredCapability {
            subsystem: "s".into(),
            capability: "c".into(),
        };
        assert_eq!(e1.code(), "ERR_CAP_UNDECLARED");
        let e2 = CapabilityGuardError::CapabilityDenied {
            subsystem: "s".into(),
            capability: "c".into(),
        };
        assert_eq!(e2.code(), "ERR_CAP_DENIED");
        let e3 = CapabilityGuardError::ProfileMissing {
            subsystem: "s".into(),
        };
        assert_eq!(e3.code(), "ERR_CAP_PROFILE_MISSING");
        let e4 = CapabilityGuardError::InvalidLevel { level: "x".into() };
        assert_eq!(e4.code(), "ERR_CAP_INVALID_LEVEL");
        let e5 = CapabilityGuardError::AuditFailure { detail: "d".into() };
        assert_eq!(e5.code(), "ERR_CAP_AUDIT_FAILURE");
    }

    #[test]
    fn test_error_display() {
        let e = CapabilityGuardError::CapabilityDenied {
            subsystem: "trust_fabric".into(),
            capability: "cap:trust:revoke".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("trust_fabric"));
        assert!(s.contains("cap:trust:revoke"));
    }

    // ── CapabilityCheckReport ────────────────────────────────────────

    #[test]
    fn test_check_report_summary() {
        let report = CapabilityCheckReport {
            subsystem: "test".to_string(),
            granted: vec!["cap:fs:read".to_string()],
            denied: vec![],
            verdict: "PASS".to_string(),
        };
        let summary = report.summary();
        assert!(summary.contains("test"));
        assert!(summary.contains("PASS"));
    }

    // ── Serde round-trips ────────────────────────────────────────────

    #[test]
    fn test_guard_serde() {
        let guard = CapabilityGuard::with_default_profiles();
        let json = serde_json::to_string(&guard).unwrap();
        let parsed: CapabilityGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.profile_count(), 5);
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_audit_entry_serde() {
        let entry = CapabilityAuditEntry {
            subsystem: "test".to_string(),
            capability: "cap:fs:read".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            outcome: "granted".to_string(),
            event_code: event_codes::CAP_001.to_string(),
            detail: "test grant".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: CapabilityAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.outcome, "granted");
    }

    #[test]
    fn test_capability_guard_event_serde() {
        let event = CapabilityGuardEvent {
            event_code: event_codes::CAP_001.to_string(),
            subsystem: "test".to_string(),
            detail: "granted cap:fs:read".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CapabilityGuardEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "CAP-001");
    }

    // ── Determinism ──────────────────────────────────────────────────

    #[test]
    fn test_deterministic_profile_ordering() {
        let guard = CapabilityGuard::with_default_profiles();
        let keys: Vec<String> = guard.profiles.keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap keys must be sorted");
    }

    // ── Send + Sync ──────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<CapabilityName>();
        assert_sync::<CapabilityName>();
        assert_send::<RiskLevel>();
        assert_sync::<RiskLevel>();
        assert_send::<CapabilityProfile>();
        assert_sync::<CapabilityProfile>();
        assert_send::<CapabilityGuard>();
        assert_sync::<CapabilityGuard>();
        assert_send::<CapabilityGuardError>();
        assert_sync::<CapabilityGuardError>();
        assert_send::<CapabilityAuditEntry>();
        assert_sync::<CapabilityAuditEntry>();
        assert_send::<CapabilityGuardEvent>();
        assert_sync::<CapabilityGuardEvent>();
        assert_send::<ProfileChange>();
        assert_sync::<ProfileChange>();
        assert_send::<CapabilityCheckReport>();
        assert_sync::<CapabilityCheckReport>();
    }
}
