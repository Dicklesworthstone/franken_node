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

use crate::capacity_defaults::aliases::{MAX_AUDIT_TRAIL_ENTRIES, MAX_EVENTS};

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
        push_bounded(
            &mut guard.events,
            CapabilityGuardEvent {
                event_code: event_codes::CAP_006.to_string(),
                subsystem: String::new(),
                detail: "capability guard initialized".to_string(),
            },
            MAX_EVENTS,
        );
        guard
    }

    /// Register a capability profile for a subsystem.
    ///
    /// # INV-CAP-PROFILE-VERSIONED
    /// If a profile already exists for this subsystem, a ProfileChange is detected.
    pub fn register_profile(
        &mut self,
        profile: CapabilityProfile,
    ) -> Result<Option<ProfileChange>, CapabilityGuardError> {
        if let Some(err) = profile.validate().into_iter().next() {
            self.emit_event(CapabilityGuardEvent {
                event_code: event_codes::CAP_002.to_string(),
                subsystem: profile.subsystem.clone(),
                detail: format!("rejected invalid capability profile: {err}"),
            });
            return Err(err);
        }

        let change = if let Some(existing) = self.profiles.get(&profile.subsystem) {
            let change = ProfileChange::detect(existing, &profile);
            if let Some(ref c) = change {
                self.emit_event(CapabilityGuardEvent {
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

        self.emit_event(CapabilityGuardEvent {
            event_code: event_codes::CAP_005.to_string(),
            subsystem: profile.subsystem.clone(),
            detail: format!(
                "profile loaded: {} caps at {} risk",
                profile.capability_count(),
                profile.risk_level,
            ),
        });

        self.profiles.insert(profile.subsystem.clone(), profile);
        Ok(change)
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
                self.emit_audit(entry);
                self.emit_event(CapabilityGuardEvent {
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
            self.emit_audit(entry);
            self.emit_event(CapabilityGuardEvent {
                event_code: event_codes::CAP_001.to_string(),
                subsystem: subsystem.to_string(),
                detail: format!("granted {capability}"),
            });
            self.emit_event(CapabilityGuardEvent {
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
            self.emit_audit(entry);
            self.emit_event(CapabilityGuardEvent {
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
        self.emit_event(CapabilityGuardEvent {
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
        let subsystems: Vec<String> = self.profiles.keys().cloned().collect();
        let mut gaps = Vec::new();
        for subsystem in subsystems {
            if !audited.contains(&subsystem) {
                gaps.push(subsystem.clone());
                self.emit_event(CapabilityGuardEvent {
                    event_code: event_codes::CAP_004.to_string(),
                    subsystem,
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
            guard
                .register_profile(profile)
                .expect("default capability profiles must be valid");
        }
        guard
    }

    fn emit_event(&mut self, event: CapabilityGuardEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    fn emit_audit(&mut self, entry: CapabilityAuditEntry) {
        push_bounded(&mut self.audit_trail, entry, MAX_AUDIT_TRAIL_ENTRIES);
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

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
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
        let change = guard.register_profile(profile).unwrap();
        assert!(change.is_none()); // first registration, no change
        assert_eq!(guard.profile_count(), 1);
    }

    #[test]
    fn test_guard_register_profile_change_detection() {
        let mut guard = CapabilityGuard::new();
        let mut p1 = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        p1.add_capability("cap:fs:read", "read");
        guard.register_profile(p1).unwrap();
        let mut p2 = CapabilityProfile::new("sub", "1.1.0", RiskLevel::Low);
        p2.add_capability("cap:fs:read", "read");
        p2.add_capability("cap:fs:write", "write");
        let change = guard.register_profile(p2).unwrap();
        assert!(change.is_some());
        let c = change.unwrap();
        assert!(c.added.contains(&"cap:fs:write".to_string()));
    }

    #[test]
    fn test_guard_register_profile_rejects_invalid_capability() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("bad_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:made:up", "not part of the taxonomy");

        let err = guard.register_profile(profile).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CAP_UNDECLARED);
        assert_eq!(guard.profile_count(), 0);
        assert!(guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_002
                && event.detail.contains("rejected invalid capability profile")
        }));
    }

    #[test]
    fn test_guard_check_capability_granted() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("trust_fabric", "1.0.0", RiskLevel::High);
        profile.add_capability("cap:trust:read", "read trust");
        guard.register_profile(profile).unwrap();

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
        guard.register_profile(profile).unwrap();

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
        guard.register_profile(profile).unwrap();

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
        guard.register_profile(profile).unwrap();

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
        guard.register_profile(profile).unwrap();

        // 3 checks => 3 audit entries
        guard.check_capability("sub", "cap:fs:read", "t1").expect("fs:read should be granted");
        let _denied_result = guard.check_capability("sub", "cap:fs:write", "t2"); // Expected denial
        guard.check_capability("sub", "cap:fs:read", "t3").expect("fs:read should be granted");
        assert_eq!(guard.audit_trail().len(), 3);
    }

    #[test]
    fn test_guard_audit_trail_capacity_enforces_oldest_first_eviction() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        for i in 0..(MAX_AUDIT_TRAIL_ENTRIES + 2) {
            guard
                .check_capability("sub", "cap:fs:read", &format!("ts-{i}"))
                .unwrap();
        }

        assert_eq!(guard.audit_trail().len(), MAX_AUDIT_TRAIL_ENTRIES);
        assert_eq!(guard.audit_trail().first().unwrap().timestamp, "ts-2");
        assert_eq!(
            guard.audit_trail().last().unwrap().timestamp,
            format!("ts-{}", MAX_AUDIT_TRAIL_ENTRIES + 1)
        );
    }

    #[test]
    fn test_guard_detect_audit_gaps() {
        let mut guard = CapabilityGuard::new();
        let p1 = CapabilityProfile::new("sub_a", "1.0.0", RiskLevel::Low);
        let p2 = CapabilityProfile::new("sub_b", "1.0.0", RiskLevel::Low);
        guard.register_profile(p1).unwrap();
        guard.register_profile(p2).unwrap();
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

    #[test]
    fn test_risk_level_from_label_rejects_case_and_padding() {
        assert_eq!(RiskLevel::from_label("High"), None);
        assert_eq!(RiskLevel::from_label(" high"), None);
        assert_eq!(RiskLevel::from_label("high "), None);
        assert_eq!(RiskLevel::from_label(""), None);
    }

    #[test]
    fn test_capability_name_rejects_prefix_only_and_padding() {
        assert!(!CapabilityName::new("cap:").is_valid());
        assert!(!CapabilityName::new(" cap:fs:read").is_valid());
        assert!(!CapabilityName::new("cap:fs:read ").is_valid());
        assert!(!CapabilityName::new("cap:fs").is_valid());
    }

    #[test]
    fn test_profile_validate_reports_each_invalid_capability() {
        let mut profile = CapabilityProfile::new("bad_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "valid control");
        profile.add_capability("cap:bogus:alpha", "invalid alpha");
        profile.add_capability("cap:bogus:beta", "invalid beta");

        let errors = profile.validate();

        assert_eq!(errors.len(), 2);
        assert!(errors.iter().all(|err| {
            matches!(
                err,
                CapabilityGuardError::UndeclaredCapability {
                    subsystem,
                    capability
                } if subsystem == "bad_sub" && capability.starts_with("cap:bogus:")
            )
        }));
    }

    #[test]
    fn test_register_invalid_profile_does_not_replace_existing_profile() {
        let mut guard = CapabilityGuard::new();
        let mut valid = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        valid.add_capability("cap:fs:read", "read");
        guard.register_profile(valid).unwrap();
        let mut invalid = CapabilityProfile::new("sub", "2.0.0", RiskLevel::Critical);
        invalid.add_capability("cap:made:up", "should not replace");

        let err = guard.register_profile(invalid).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_UNDECLARED);
        assert_eq!(guard.profile_count(), 1);
        let retained = guard
            .profiles
            .get("sub")
            .expect("original profile retained");
        assert_eq!(retained.version, "1.0.0");
        assert!(retained.has_capability("cap:fs:read"));
        assert!(!retained.has_capability("cap:made:up"));
    }

    #[test]
    fn test_check_capability_rejects_empty_capability_name() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "", "ts-empty-cap")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        let audit = guard
            .audit_trail()
            .last()
            .expect("denial should be audited");
        assert_eq!(audit.capability, "");
        assert_eq!(audit.outcome, "denied");
    }

    #[test]
    fn test_check_capability_rejects_unknown_capability_even_with_profile() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "cap:network:listen", "ts-deny")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        assert!(guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_002
                && event.subsystem == "sub"
                && event.detail.contains("not in profile")
        }));
    }

    #[test]
    fn test_check_all_missing_profile_denies_every_requested_capability() {
        let mut guard = CapabilityGuard::new();

        let report = guard.check_all(
            "missing_sub",
            &["cap:fs:read", "cap:crypto:verify"],
            "ts-missing",
        );

        assert_eq!(report.verdict, "FAIL");
        assert!(report.granted.is_empty());
        assert_eq!(report.denied.len(), 2);
        assert!(
            report
                .denied
                .iter()
                .all(|(_, code)| { code == error_codes::ERR_CAP_PROFILE_MISSING })
        );
        assert_eq!(guard.audit_trail().len(), 2);
    }

    #[test]
    fn test_audit_gap_detection_ignores_missing_profile_denials() {
        let mut guard = CapabilityGuard::new();
        let profile = CapabilityProfile::new("registered_without_checks", "1.0.0", RiskLevel::Low);
        guard.register_profile(profile).unwrap();
        let _missing_profile_result = guard.check_capability("unknown_sub", "cap:fs:read", "ts-missing");

        let gaps = guard.detect_audit_gaps();

        assert_eq!(gaps, vec!["registered_without_checks".to_string()]);
        assert!(guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_004
                && event.subsystem == "registered_without_checks"
        }));
    }

    #[test]
    fn negative_check_capability_rejects_case_mismatched_name() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "CAP:fs:read", "ts-case")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        let audit = guard.audit_trail().last().unwrap();
        assert_eq!(audit.capability, "CAP:fs:read");
        assert_eq!(audit.outcome, "denied");
    }

    #[test]
    fn negative_check_capability_rejects_padded_name() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "cap:fs:read ", "ts-padded")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        let audit = guard.audit_trail().last().unwrap();
        assert_eq!(audit.capability, "cap:fs:read ");
        assert_eq!(audit.timestamp, "ts-padded");
        assert_eq!(audit.outcome, "denied");
    }

    #[test]
    fn negative_missing_profile_denial_records_timestamp_and_detail() {
        let mut guard = CapabilityGuard::new();

        let err = guard
            .check_capability("missing", "cap:fs:read", "ts-missing-detail")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_PROFILE_MISSING);
        let audit = guard.audit_trail().last().unwrap();
        assert_eq!(audit.subsystem, "missing");
        assert_eq!(audit.capability, "cap:fs:read");
        assert_eq!(audit.timestamp, "ts-missing-detail");
        assert_eq!(audit.outcome, "denied");
        assert!(audit.detail.contains("no profile registered"));
    }

    #[test]
    fn negative_check_all_preserves_mixed_denial_order() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let report = guard.check_all(
            "sub",
            &["cap:fs:write", "cap:fs:read", "cap:bogus:thing"],
            "ts-mixed",
        );

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.granted, vec!["cap:fs:read".to_string()]);
        assert_eq!(report.denied.len(), 2);
        assert_eq!(report.denied[0].0, "cap:fs:write");
        assert_eq!(report.denied[1].0, "cap:bogus:thing");
        assert!(
            report
                .denied
                .iter()
                .all(|(_, code)| code == error_codes::ERR_CAP_DENIED)
        );
    }

    #[test]
    fn negative_invalid_profile_registration_emits_no_loaded_event() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("bad_sub", "1.0.0", RiskLevel::Critical);
        profile.add_capability("cap:not:real", "invalid");

        let err = guard.register_profile(profile).unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_UNDECLARED);
        assert!(guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_002 && event.subsystem == "bad_sub"
        }));
        assert!(!guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_005 && event.subsystem == "bad_sub"
        }));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_item_without_panic() {
        let mut items = vec!["old"];

        push_bounded(&mut items, "new", 0);

        assert!(items.is_empty());
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

    // ═══════════════════════════════════════════════════════════════════════
    // NEGATIVE-PATH EDGE CASE AND SECURITY ATTACK VECTOR TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn negative_capability_profile_with_massive_field_lengths() {
        // Test capability profile with extremely large field values
        let huge_subsystem = "s".repeat(1_000_000); // 1MB subsystem name
        let huge_version = "v".repeat(500_000); // 500KB version string
        let huge_capability = "c".repeat(250_000); // 250KB capability name
        let huge_justification = "j".repeat(2_000_000); // 2MB justification

        let mut profile =
            CapabilityProfile::new(&huge_subsystem, &huge_version, RiskLevel::Critical);

        let start = std::time::Instant::now();
        profile.add_capability(&huge_capability, &huge_justification);
        let duration = start.elapsed();

        // Should handle massive fields without panic and within reasonable time
        assert_eq!(profile.subsystem.len(), 1_000_000);
        assert_eq!(profile.version.len(), 500_000);
        assert!(profile.capabilities.contains_key(&huge_capability));
        assert!(duration < std::time::Duration::from_secs(10)); // Generous timeout

        // Test serialization with massive fields
        let json_start = std::time::Instant::now();
        let json_result = serde_json::to_string(&profile);
        let json_duration = json_start.elapsed();

        assert!(json_result.is_ok());
        assert!(json_duration < std::time::Duration::from_secs(15));
    }

    #[test]
    fn negative_capability_name_with_unicode_and_injection_attacks() {
        // Test various Unicode and injection attacks in capability names
        let malicious_capabilities = vec![
            "cap\u{202E}fake:fs:read\u{202D}",        // Unicode BiDi override
            "cap:fs\u{00A0}nonbreaking:read",         // Non-breaking space
            "cap:fs\u{200B}zerowidth:read",           // Zero-width space
            "cap:fs\u{FEFF}bom:read",                 // BOM character
            "cap:fs\u{0000}null:read",                // Null byte
            "cap:fs\x1F\x1E\x1D:read",                // Control characters
            "cap/../../../etc/passwd",                // Path traversal
            "cap:fs'; DROP TABLE caps; --:read",      // SQL injection attempt
            "cap:<script>alert('xss')</script>:read", // XSS attempt
            "cap:fs|nc attacker.com:read",            // Command injection
            "\u{1F4A9}cap:fs:read",                   // Emoji prefix
            "cap:café\u{0301}:read",                  // NFD normalization
        ];

        for malicious_cap in malicious_capabilities {
            let capability_name = CapabilityName::new(&malicious_cap);

            // Should store name literally but mark as invalid since not in taxonomy
            assert_eq!(capability_name.as_str(), malicious_cap);
            assert!(!capability_name.is_valid()); // Not in taxonomy
            assert_eq!(format!("{}", capability_name), malicious_cap);

            // Test in capability profile
            let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
            profile.add_capability(&malicious_cap, "malicious capability test");

            // Should store literally but validation should catch it
            assert!(profile.has_capability(&malicious_cap));
            let errors = profile.validate();
            assert!(!errors.is_empty());
            assert!(
                errors
                    .iter()
                    .all(|e| matches!(e, CapabilityGuardError::UndeclaredCapability { .. }))
            );
        }
    }

    #[test]
    fn negative_risk_level_exhaustive_boundary_and_injection_testing() {
        // Test RiskLevel::from_label with comprehensive invalid inputs
        let invalid_risk_levels = vec![
            "",                             // Empty
            " ",                            // Whitespace only
            "Low",                          // Wrong case
            "HIGH",                         // Wrong case
            " low",                         // Leading space
            "low ",                         // Trailing space
            "\tlow",                        // Tab prefix
            "low\n",                        // Newline suffix
            "medium\x00",                   // Null byte
            "high\u{202E}override\u{202D}", // BiDi override
            "critical\u{200B}invisible",    // Zero-width space
            "lowmedium",                    // Concatenated
            "low-medium",                   // Hyphenated
            "undefined",                    // Different word
            "0",                            // Numeric
            "true",                         // Boolean string
            "null",                         // Null string
            "{'level':'low'}",              // JSON-like
            "<level>low</level>",           // XML-like
            "../../../etc/passwd",          // Path traversal
            "'; DROP TABLE risks; --",      // SQL injection
        ];

        for invalid_level in invalid_risk_levels {
            let result = RiskLevel::from_label(invalid_level);
            assert!(
                result.is_none(),
                "Invalid risk level '{}' should return None",
                invalid_level
            );
        }

        // Test that valid levels still work exactly
        assert_eq!(RiskLevel::from_label("low"), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::from_label("medium"), Some(RiskLevel::Medium));
        assert_eq!(RiskLevel::from_label("high"), Some(RiskLevel::High));
        assert_eq!(RiskLevel::from_label("critical"), Some(RiskLevel::Critical));

        // Test ordering consistency under edge cases
        assert!(RiskLevel::Low < RiskLevel::Critical);
        assert!(RiskLevel::Critical > RiskLevel::Low);

        let all_levels = vec![
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ];
        for i in 0..all_levels.len() {
            for j in 0..all_levels.len() {
                if i < j {
                    assert!(all_levels[i] < all_levels[j]);
                } else if i > j {
                    assert!(all_levels[i] > all_levels[j]);
                } else {
                    assert_eq!(all_levels[i], all_levels[j]);
                }
            }
        }
    }

    #[test]
    fn negative_capability_guard_with_maximum_capacity_stress_testing() {
        let mut guard = CapabilityGuard::new();

        // Create maximum number of profiles to test capacity management
        for i in 0..1000 {
            let subsystem_name = format!("subsystem_{:04}", i);
            let mut profile = CapabilityProfile::new(&subsystem_name, "1.0.0", RiskLevel::Low);
            profile.add_capability("cap:fs:read", "read capability");

            let result = guard.register_profile(profile);
            assert!(result.is_ok(), "Profile registration {} should succeed", i);
        }

        assert_eq!(guard.profile_count(), 1000);

        // Test capability checking performance with many profiles
        let start = std::time::Instant::now();
        for i in 0..100 {
            let subsystem = format!("subsystem_{:04}", i);
            let result = guard.check_capability(&subsystem, "cap:fs:read", &format!("ts-{}", i));
            assert!(result.is_ok());
        }
        let duration = start.elapsed();

        // Should handle many profiles efficiently (under 5 seconds for 100 checks)
        assert!(duration < std::time::Duration::from_secs(5));
        assert!(guard.audit_trail().len() >= 100);
    }

    #[test]
    fn negative_audit_trail_capacity_overflow_with_rapid_operations() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("stress_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        // Rapidly perform capability checks to overflow audit trail multiple times
        let operations_count = MAX_AUDIT_TRAIL_ENTRIES * 3; // 3x overflow
        for i in 0..operations_count {
            let timestamp = format!("ts-{:06}", i);
            guard.check_capability("stress_sub", "cap:fs:read", &timestamp).expect("stress test should succeed");
        }

        // Should maintain exact capacity limit
        assert_eq!(guard.audit_trail().len(), MAX_AUDIT_TRAIL_ENTRIES);

        // Most recent entries should be present (FIFO eviction)
        let last_entry = guard.audit_trail().last().unwrap();
        let expected_last_ts = format!("ts-{:06}", operations_count - 1);
        assert_eq!(last_entry.timestamp, expected_last_ts);

        // Earliest entries should be evicted
        let first_entry = guard.audit_trail().first().unwrap();
        let earliest_retained = operations_count - MAX_AUDIT_TRAIL_ENTRIES;
        let expected_first_ts = format!("ts-{:06}", earliest_retained);
        assert_eq!(first_entry.timestamp, expected_first_ts);
    }

    #[test]
    fn negative_capability_guard_error_display_injection_resistance() {
        // Test that error display methods safely handle malicious content
        let injection_payloads = vec![
            "<script>alert('xss')</script>",
            "'; DROP TABLE capabilities; --",
            "\x00\x01\x02\x03null_and_control",
            "\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>",
            "\u{202E}override\u{202D}fake",
            "capability\u{200B}with\u{FEFF}invisible\u{034F}chars",
        ];

        for payload in &injection_payloads {
            // Test various error types with injection content
            let errors = vec![
                CapabilityGuardError::UndeclaredCapability {
                    subsystem: payload.to_string(),
                    capability: format!("cap:{}:read", payload),
                },
                CapabilityGuardError::CapabilityDenied {
                    subsystem: format!("sub_{}", payload),
                    capability: payload.to_string(),
                },
                CapabilityGuardError::ProfileMissing {
                    subsystem: payload.to_string(),
                },
                CapabilityGuardError::InvalidLevel {
                    level: payload.to_string(),
                },
                CapabilityGuardError::AuditFailure {
                    detail: format!("Audit failed: {}", payload),
                },
            ];

            for error in errors {
                let display_string = format!("{}", error);

                // Error display should contain the injection content literally (no interpretation)
                assert!(display_string.contains(payload));

                // But should not contain any dangerous interpretable patterns when used in logs
                // The content should be safely embedded in error message format
                assert!(display_string.len() > payload.len()); // Should have error context

                // Error code should be safe constant
                let code = error.code();
                assert!(code.starts_with("ERR_CAP_"));
                assert!(code.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
            }
        }
    }

    #[test]
    fn negative_profile_change_detection_with_complex_capability_permutations() {
        // Test ProfileChange detection with complex capability addition/removal patterns
        let mut old_profile = CapabilityProfile::new("complex_sub", "1.0.0", RiskLevel::Medium);
        old_profile.add_capability("cap:fs:read", "read files");
        old_profile.add_capability("cap:fs:write", "write files");
        old_profile.add_capability("cap:crypto:verify", "verify signatures");
        old_profile.add_capability("cap:network:connect", "connect to network");

        let test_cases = vec![
            // (description, modifications, expected_added, expected_removed)
            (
                "capability substitution",
                |p: &mut CapabilityProfile| {
                    p.capabilities.remove("cap:fs:write");
                    p.add_capability("cap:fs:temp", "temp files");
                },
                vec!["cap:fs:temp"],
                vec!["cap:fs:write"],
            ),
            (
                "capability expansion",
                |p: &mut CapabilityProfile| {
                    p.add_capability("cap:trust:read", "read trust");
                    p.add_capability("cap:trust:write", "write trust");
                },
                vec!["cap:trust:read", "cap:trust:write"],
                vec![],
            ),
            (
                "capability reduction",
                |p: &mut CapabilityProfile| {
                    p.capabilities.remove("cap:crypto:verify");
                    p.capabilities.remove("cap:network:connect");
                },
                vec![],
                vec!["cap:crypto:verify", "cap:network:connect"],
            ),
            (
                "complete replacement",
                |p: &mut CapabilityProfile| {
                    p.capabilities.clear();
                    p.add_capability("cap:process:spawn", "spawn processes");
                    p.add_capability("cap:crypto:sign", "sign data");
                },
                vec!["cap:process:spawn", "cap:crypto:sign"],
                vec![
                    "cap:fs:read",
                    "cap:fs:write",
                    "cap:crypto:verify",
                    "cap:network:connect",
                ],
            ),
        ];

        for (description, modifier, expected_added, expected_removed) in test_cases {
            let mut new_profile = old_profile.clone();
            new_profile.version = "2.0.0".to_string();
            modifier(&mut new_profile);

            let change = ProfileChange::detect(&old_profile, &new_profile);
            assert!(
                change.is_some(),
                "Change should be detected for: {}",
                description
            );

            let change = change.unwrap();
            assert_eq!(change.old_version, "1.0.0");
            assert_eq!(change.new_version, "2.0.0");
            assert!(
                change.requires_review,
                "Change should require review: {}",
                description
            );

            // Verify added capabilities
            assert_eq!(
                change.added.len(),
                expected_added.len(),
                "Added count mismatch for: {}",
                description
            );
            for expected in &expected_added {
                assert!(
                    change.added.contains(&expected.to_string()),
                    "Missing added capability '{}' for: {}",
                    expected,
                    description
                );
            }

            // Verify removed capabilities
            assert_eq!(
                change.removed.len(),
                expected_removed.len(),
                "Removed count mismatch for: {}",
                description
            );
            for expected in &expected_removed {
                assert!(
                    change.removed.contains(&expected.to_string()),
                    "Missing removed capability '{}' for: {}",
                    expected,
                    description
                );
            }
        }
    }

    #[test]
    fn negative_capability_check_with_malformed_timestamps() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("time_test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        // Test various malformed timestamp formats
        let malformed_timestamps = vec![
            "",                                     // Empty
            "not-a-timestamp",                      // Invalid format
            "2026-02-31T25:61:61Z",                 // Invalid date/time
            "2026\x0002\x0021T00:00:00Z",           // Null bytes
            "2026-02-21T00:00:00Z\n<script>",       // Injection attempt
            "\u{202E}Z00:00:00T12-20-6202\u{202D}", // BiDi override
            "9".repeat(1000),                       // Extremely long
            "\u{1F4A9}2026-02-21T00:00:00Z",        // Emoji prefix
        ];

        for timestamp in malformed_timestamps {
            // Should handle malformed timestamps gracefully - store literally in audit
            let result = guard.check_capability("time_test_sub", "cap:fs:read", timestamp);
            assert!(
                result.is_ok(),
                "Capability check should succeed regardless of timestamp format"
            );

            // Timestamp should be stored literally in audit trail
            let audit_entry = guard.audit_trail().last().unwrap();
            assert_eq!(audit_entry.timestamp, timestamp);
            assert_eq!(audit_entry.outcome, "granted");
            assert_eq!(audit_entry.subsystem, "time_test_sub");
            assert_eq!(audit_entry.capability, "cap:fs:read");
        }
    }

    #[test]
    fn negative_capability_taxonomy_consistency_under_concurrent_access_simulation() {
        // Simulate concurrent access patterns to capability taxonomy
        let start = std::time::Instant::now();

        // Perform many rapid taxonomy operations
        for _ in 0..10000 {
            let taxonomy = capability_taxonomy();
            let names = all_capability_names();

            // Verify consistency between different access methods
            assert_eq!(taxonomy.len(), 12);
            assert_eq!(names.len(), 12);
            assert_eq!(CAPABILITY_TAXONOMY.len(), 12);

            // Verify taxonomy structure
            for entry in CAPABILITY_TAXONOMY {
                assert!(taxonomy.contains_key(entry.name));
                assert!(names.contains(&entry.name.to_string()));
                assert!(entry.name.starts_with("cap:"));
            }

            // Verify ordering consistency (BTreeMap should be sorted)
            let keys: Vec<String> = taxonomy.keys().cloned().collect();
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            assert_eq!(keys, sorted_keys);
        }

        let duration = start.elapsed();
        // Should handle rapid access efficiently
        assert!(duration < std::time::Duration::from_secs(10));
    }

    #[test]
    fn negative_default_profiles_modification_resistance() {
        // Test that default profiles are immutable and consistent
        let profiles1 = default_profiles();
        let profiles2 = default_profiles();

        // Should return identical profiles on multiple calls
        assert_eq!(profiles1.len(), profiles2.len());
        assert_eq!(profiles1.len(), 5);

        for (p1, p2) in profiles1.iter().zip(profiles2.iter()) {
            assert_eq!(p1.subsystem, p2.subsystem);
            assert_eq!(p1.version, p2.version);
            assert_eq!(p1.risk_level, p2.risk_level);
            assert_eq!(p1.capabilities, p2.capabilities);
        }

        // Verify specific profile characteristics that shouldn't change
        let trust_fabric = profiles1
            .iter()
            .find(|p| p.subsystem == "trust_fabric")
            .unwrap();
        assert!(trust_fabric.has_capability("cap:trust:read"));
        assert!(trust_fabric.has_capability("cap:trust:write"));
        assert!(trust_fabric.has_capability("cap:network:connect"));
        assert_eq!(trust_fabric.risk_level, RiskLevel::High);

        let artifact_signing = profiles1
            .iter()
            .find(|p| p.subsystem == "artifact_signing")
            .unwrap();
        assert!(artifact_signing.has_capability("cap:crypto:sign"));
        assert!(artifact_signing.has_capability("cap:crypto:derive"));
        assert_eq!(artifact_signing.risk_level, RiskLevel::Critical);

        // Test guard creation with default profiles multiple times
        let guard1 = CapabilityGuard::with_default_profiles();
        let guard2 = CapabilityGuard::with_default_profiles();

        assert_eq!(guard1.profile_count(), guard2.profile_count());
        assert_eq!(guard1.profile_count(), 5);
        assert_eq!(guard1.schema_version, guard2.schema_version);
    }

    #[test]
    fn negative_push_bounded_edge_cases_with_various_capacities() {
        // Test push_bounded with various edge case capacity values
        let test_cases = vec![
            (0, vec!["existing"], "new", vec![]),     // Zero capacity
            (1, vec![], "new", vec!["new"]),          // Minimal capacity, empty
            (1, vec!["old"], "new", vec!["new"]),     // Minimal capacity, replacement
            (2, vec!["a", "b"], "c", vec!["b", "c"]), // Exact capacity, eviction
            (10, vec![], "new", vec!["new"]),         // Large capacity, single item
            (3, vec!["1", "2", "3", "4", "5"], "6", vec!["4", "5", "6"]), // Multiple evictions
        ];

        for (capacity, mut initial, new_item, expected) in test_cases {
            push_bounded(&mut initial, new_item, capacity);
            assert_eq!(
                initial, expected,
                "Failed for capacity={}, new_item={}",
                capacity, new_item
            );
        }

        // Test with large capacity and many items
        let mut large_vec = Vec::new();
        for i in 0..1000 {
            push_bounded(&mut large_vec, i, 500);
        }
        assert_eq!(large_vec.len(), 500);
        assert_eq!(large_vec[0], 500); // First item after eviction
        assert_eq!(large_vec[499], 999); // Last item
    }

    #[test]
    fn negative_capability_guard_schema_version_consistency_and_tampering_resistance() {
        let guard = CapabilityGuard::new();

        // Schema version should be the defined constant
        assert_eq!(guard.schema_version, SCHEMA_VERSION);
        assert_eq!(guard.schema_version, "cap-v1.0");

        // Test serialization preserves schema version
        let json = serde_json::to_string(&guard).unwrap();
        assert!(json.contains("cap-v1.0"));

        let parsed: CapabilityGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);

        // Test with default profiles
        let guard_with_profiles = CapabilityGuard::with_default_profiles();
        assert_eq!(guard_with_profiles.schema_version, SCHEMA_VERSION);

        // Test that schema version is preserved through operations
        let mut mutable_guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("test_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        mutable_guard.register_profile(profile).unwrap();
        mutable_guard
            .check_capability("test_sub", "cap:fs:read", "ts")
            .unwrap();

        assert_eq!(mutable_guard.schema_version, SCHEMA_VERSION);

        // Schema version should not be empty or contain dangerous characters
        assert!(!mutable_guard.schema_version.is_empty());
        assert!(!mutable_guard.schema_version.contains('\0'));
        assert!(!mutable_guard.schema_version.contains('<'));
        assert!(!mutable_guard.schema_version.contains('>'));
        assert!(mutable_guard.schema_version.is_ascii());
    }

    #[test]
    fn negative_profile_validate_rejects_null_byte_capability_name() {
        let mut profile = CapabilityProfile::new("null_cap_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read\0", "null-byte capability suffix");

        let errors = profile.validate();

        assert_eq!(errors.len(), 1);
        assert!(matches!(
            &errors[0],
            CapabilityGuardError::UndeclaredCapability {
                subsystem,
                capability
            } if subsystem == "null_cap_sub" && capability == "cap:fs:read\0"
        ));
    }

    #[test]
    fn negative_profile_validate_rejects_newline_capability_name() {
        let mut profile = CapabilityProfile::new("newline_cap_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read\ncap:trust:write", "newline injection");

        let errors = profile.validate();

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code(), error_codes::ERR_CAP_UNDECLARED);
        assert!(format!("{}", errors[0]).contains("cap:fs:read\ncap:trust:write"));
    }

    #[test]
    fn negative_register_profile_reports_first_invalid_capability_in_sorted_order() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sorted_invalid_sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:zz:invalid", "later invalid name");
        profile.add_capability("cap:aa:invalid", "earlier invalid name");

        let err = guard.register_profile(profile).unwrap_err();

        assert!(matches!(
            err,
            CapabilityGuardError::UndeclaredCapability {
                ref subsystem,
                ref capability
            } if subsystem == "sorted_invalid_sub" && capability == "cap:aa:invalid"
        ));
        assert_eq!(guard.profile_count(), 0);
    }

    #[test]
    fn negative_check_capability_rejects_null_byte_requested_name_and_audits_literal() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "cap:fs:read\0", "ts-null-cap")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        let audit = guard.audit_trail().last().unwrap();
        assert_eq!(audit.capability, "cap:fs:read\0");
        assert_eq!(audit.outcome, "denied");
        assert_eq!(audit.timestamp, "ts-null-cap");
    }

    #[test]
    fn negative_check_capability_rejects_newline_requested_name_and_emits_deny_event() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let err = guard
            .check_capability("sub", "cap:fs:read\n", "ts-newline-cap")
            .unwrap_err();

        assert_eq!(err.code(), error_codes::ERR_CAP_DENIED);
        assert!(guard.events().iter().any(|event| {
            event.event_code == event_codes::CAP_002
                && event.subsystem == "sub"
                && event.detail.contains("not in profile")
        }));
    }

    #[test]
    fn negative_check_all_with_duplicate_denials_preserves_each_attempt() {
        let mut guard = CapabilityGuard::new();
        let mut profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        profile.add_capability("cap:fs:read", "read");
        guard.register_profile(profile).unwrap();

        let report = guard.check_all(
            "sub",
            &["cap:fs:write", "cap:fs:write", "cap:fs:read"],
            "ts-duplicate-deny",
        );

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.granted, vec!["cap:fs:read".to_string()]);
        assert_eq!(report.denied.len(), 2);
        assert_eq!(report.denied[0].0, "cap:fs:write");
        assert_eq!(report.denied[1].0, "cap:fs:write");
        assert_eq!(guard.audit_trail().len(), 3);
    }

    #[test]
    fn negative_profile_change_treats_zero_width_lookalike_as_distinct_capability() {
        let mut old_profile = CapabilityProfile::new("sub", "1.0.0", RiskLevel::Low);
        old_profile.add_capability("cap:fs:read", "read");
        let mut new_profile = CapabilityProfile::new("sub", "1.1.0", RiskLevel::Low);
        new_profile.add_capability("cap:fs:read\u{200b}", "lookalike read");

        let change = ProfileChange::detect(&old_profile, &new_profile).unwrap();

        assert_eq!(change.added, vec!["cap:fs:read\u{200b}".to_string()]);
        assert_eq!(change.removed, vec!["cap:fs:read".to_string()]);
        assert!(change.requires_review);
    }
}
