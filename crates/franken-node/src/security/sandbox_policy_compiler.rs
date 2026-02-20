//! Sandbox profile system with policy compiler.
//!
//! Four tiers: strict, strict_plus, moderate, permissive. The policy
//! compiler translates a profile into enforceable capability grants.
//! Downgrades are blocked; profile selection is auditable.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Sandbox profile tiers, ordered from most to least restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    Strict,
    StrictPlus,
    Moderate,
    Permissive,
}

impl SandboxProfile {
    pub const ALL: [SandboxProfile; 4] = [
        Self::Strict,
        Self::StrictPlus,
        Self::Moderate,
        Self::Permissive,
    ];

    /// Numeric level: higher = more permissive.
    pub fn level(&self) -> u8 {
        match self {
            Self::Strict => 0,
            Self::StrictPlus => 1,
            Self::Moderate => 2,
            Self::Permissive => 3,
        }
    }

    /// Parse profile from string name.
    pub fn parse(name: &str) -> Result<Self, SandboxError> {
        match name {
            "strict" => Ok(Self::Strict),
            "strict_plus" => Ok(Self::StrictPlus),
            "moderate" => Ok(Self::Moderate),
            "permissive" => Ok(Self::Permissive),
            _ => Err(SandboxError::ProfileUnknown {
                name: name.to_string(),
            }),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::StrictPlus => "strict_plus",
            Self::Moderate => "moderate",
            Self::Permissive => "permissive",
        }
    }

    /// Check if transition from self to target is a downgrade (blocked).
    pub fn is_downgrade_to(&self, target: &SandboxProfile) -> bool {
        target.level() < self.level()
    }
}

impl fmt::Display for SandboxProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Access level for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    Deny,
    Scoped,
    Filtered,
    Allow,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => write!(f, "deny"),
            Self::Scoped => write!(f, "scoped"),
            Self::Filtered => write!(f, "filtered"),
            Self::Allow => write!(f, "allow"),
        }
    }
}

/// A single capability grant in a compiled policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: String,
    pub access: AccessLevel,
}

/// The compiled policy output for a sandbox profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub profile: SandboxProfile,
    pub level: u8,
    pub grants: Vec<CapabilityGrant>,
}

/// Compile a sandbox profile into an enforceable policy.
pub fn compile_policy(profile: SandboxProfile) -> CompiledPolicy {
    let grants = match profile {
        SandboxProfile::Strict => vec![
            grant("network_access", AccessLevel::Deny),
            grant("fs_read", AccessLevel::Deny),
            grant("fs_write", AccessLevel::Deny),
            grant("process_exec", AccessLevel::Deny),
            grant("ipc", AccessLevel::Deny),
            grant("env_access", AccessLevel::Deny),
        ],
        SandboxProfile::StrictPlus => vec![
            grant("network_access", AccessLevel::Deny),
            grant("fs_read", AccessLevel::Deny),
            grant("fs_write", AccessLevel::Deny),
            grant("process_exec", AccessLevel::Deny),
            grant("ipc", AccessLevel::Deny),
            grant("env_access", AccessLevel::Deny),
        ],
        SandboxProfile::Moderate => vec![
            grant("network_access", AccessLevel::Filtered),
            grant("fs_read", AccessLevel::Scoped),
            grant("fs_write", AccessLevel::Deny),
            grant("process_exec", AccessLevel::Deny),
            grant("ipc", AccessLevel::Scoped),
            grant("env_access", AccessLevel::Filtered),
        ],
        SandboxProfile::Permissive => vec![
            grant("network_access", AccessLevel::Allow),
            grant("fs_read", AccessLevel::Allow),
            grant("fs_write", AccessLevel::Allow),
            grant("process_exec", AccessLevel::Allow),
            grant("ipc", AccessLevel::Allow),
            grant("env_access", AccessLevel::Allow),
        ],
    };

    CompiledPolicy {
        profile,
        level: profile.level(),
        grants,
    }
}

fn grant(capability: &str, access: AccessLevel) -> CapabilityGrant {
    CapabilityGrant {
        capability: capability.to_string(),
        access,
    }
}

/// The 6 standard capabilities.
pub const CAPABILITIES: [&str; 6] = [
    "network_access",
    "fs_read",
    "fs_write",
    "process_exec",
    "ipc",
    "env_access",
];

/// Validate that a compiled policy has no conflicts
/// (e.g., no capability appears with contradictory access levels).
pub fn validate_policy(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    let mut seen = std::collections::HashMap::new();
    for g in &policy.grants {
        if let Some(prev) = seen.insert(&g.capability, &g.access) {
            if prev != &g.access {
                return Err(SandboxError::PolicyConflict {
                    capability: g.capability.clone(),
                    access_a: format!("{prev}"),
                    access_b: format!("{}", g.access),
                });
            }
        }
    }
    Ok(())
}

/// Audit record for profile selection/change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileAuditRecord {
    pub connector_id: String,
    pub old_profile: Option<SandboxProfile>,
    pub new_profile: SandboxProfile,
    pub changed_at: String,
    pub reason: String,
}

/// Profile tracker for a connector, enforcing downgrade rules and auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileTracker {
    pub connector_id: String,
    pub current_profile: SandboxProfile,
    pub compiled_policy: CompiledPolicy,
    pub audit_log: Vec<ProfileAuditRecord>,
}

impl ProfileTracker {
    pub fn new(connector_id: String, initial_profile: SandboxProfile) -> Self {
        let compiled = compile_policy(initial_profile);
        let audit = ProfileAuditRecord {
            connector_id: connector_id.clone(),
            old_profile: None,
            new_profile: initial_profile,
            changed_at: String::new(),
            reason: "initial assignment".to_string(),
        };
        Self {
            connector_id,
            current_profile: initial_profile,
            compiled_policy: compiled,
            audit_log: vec![audit],
        }
    }

    /// Change to a new profile. Downgrades are blocked unless overridden.
    pub fn change_profile(
        &mut self,
        new_profile: SandboxProfile,
        reason: String,
        timestamp: String,
        allow_downgrade: bool,
    ) -> Result<ProfileAuditRecord, SandboxError> {
        if self.current_profile.is_downgrade_to(&new_profile) && !allow_downgrade {
            return Err(SandboxError::DowngradeBlocked {
                current: self.current_profile,
                requested: new_profile,
            });
        }

        let audit = ProfileAuditRecord {
            connector_id: self.connector_id.clone(),
            old_profile: Some(self.current_profile),
            new_profile,
            changed_at: timestamp,
            reason,
        };

        self.current_profile = new_profile;
        self.compiled_policy = compile_policy(new_profile);
        self.audit_log.push(audit.clone());
        Ok(audit)
    }

    /// Check if a capability is granted under the current policy.
    pub fn is_capability_allowed(&self, capability: &str) -> AccessLevel {
        for g in &self.compiled_policy.grants {
            if g.capability == capability {
                return g.access;
            }
        }
        AccessLevel::Deny // default deny for unknown capabilities
    }
}

/// Errors for sandbox operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxError {
    #[serde(rename = "SANDBOX_DOWNGRADE_BLOCKED")]
    DowngradeBlocked {
        current: SandboxProfile,
        requested: SandboxProfile,
    },
    #[serde(rename = "SANDBOX_PROFILE_UNKNOWN")]
    ProfileUnknown { name: String },
    #[serde(rename = "SANDBOX_POLICY_CONFLICT")]
    PolicyConflict {
        capability: String,
        access_a: String,
        access_b: String,
    },
    #[serde(rename = "SANDBOX_COMPILE_ERROR")]
    CompileError { reason: String },
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DowngradeBlocked { current, requested } => {
                write!(
                    f,
                    "SANDBOX_DOWNGRADE_BLOCKED: cannot move from {current} to {requested}"
                )
            }
            Self::ProfileUnknown { name } => {
                write!(f, "SANDBOX_PROFILE_UNKNOWN: '{name}'")
            }
            Self::PolicyConflict {
                capability,
                access_a,
                access_b,
            } => {
                write!(
                    f,
                    "SANDBOX_POLICY_CONFLICT: capability '{capability}' has conflicting access: {access_a} vs {access_b}"
                )
            }
            Self::CompileError { reason } => {
                write!(f, "SANDBOX_COMPILE_ERROR: {reason}")
            }
        }
    }
}

impl std::error::Error for SandboxError {}

#[cfg(test)]
mod tests {
    use super::*;

    // === Profile basics ===

    #[test]
    fn four_profiles() {
        assert_eq!(SandboxProfile::ALL.len(), 4);
    }

    #[test]
    fn profile_levels_ordered() {
        assert!(SandboxProfile::Strict.level() < SandboxProfile::StrictPlus.level());
        assert!(SandboxProfile::StrictPlus.level() < SandboxProfile::Moderate.level());
        assert!(SandboxProfile::Moderate.level() < SandboxProfile::Permissive.level());
    }

    #[test]
    fn parse_valid_profiles() {
        for p in &SandboxProfile::ALL {
            let parsed = SandboxProfile::parse(p.as_str()).unwrap();
            assert_eq!(&parsed, p);
        }
    }

    #[test]
    fn parse_unknown_profile() {
        let err = SandboxProfile::parse("ultra_strict").unwrap_err();
        assert!(matches!(err, SandboxError::ProfileUnknown { .. }));
    }

    // === Downgrade detection ===

    #[test]
    fn downgrade_detected() {
        assert!(SandboxProfile::Moderate.is_downgrade_to(&SandboxProfile::Strict));
        assert!(SandboxProfile::Permissive.is_downgrade_to(&SandboxProfile::Moderate));
    }

    #[test]
    fn upgrade_not_downgrade() {
        assert!(!SandboxProfile::Strict.is_downgrade_to(&SandboxProfile::Moderate));
        assert!(!SandboxProfile::Moderate.is_downgrade_to(&SandboxProfile::Permissive));
    }

    #[test]
    fn same_level_not_downgrade() {
        assert!(!SandboxProfile::Moderate.is_downgrade_to(&SandboxProfile::Moderate));
    }

    // === Policy compilation ===

    #[test]
    fn strict_all_deny() {
        let policy = compile_policy(SandboxProfile::Strict);
        for g in &policy.grants {
            assert_eq!(g.access, AccessLevel::Deny);
        }
    }

    #[test]
    fn permissive_all_allow() {
        let policy = compile_policy(SandboxProfile::Permissive);
        for g in &policy.grants {
            assert_eq!(g.access, AccessLevel::Allow);
        }
    }

    #[test]
    fn moderate_mixed_access() {
        let policy = compile_policy(SandboxProfile::Moderate);
        let net = policy
            .grants
            .iter()
            .find(|g| g.capability == "network_access")
            .unwrap();
        assert_eq!(net.access, AccessLevel::Filtered);
        let fsw = policy
            .grants
            .iter()
            .find(|g| g.capability == "fs_write")
            .unwrap();
        assert_eq!(fsw.access, AccessLevel::Deny);
    }

    #[test]
    fn all_profiles_produce_6_grants() {
        for p in &SandboxProfile::ALL {
            let policy = compile_policy(*p);
            assert_eq!(policy.grants.len(), 6, "profile {p} should have 6 grants");
        }
    }

    #[test]
    fn compile_deterministic() {
        let a = compile_policy(SandboxProfile::Moderate);
        let b = compile_policy(SandboxProfile::Moderate);
        assert_eq!(a, b);
    }

    // === Policy validation ===

    #[test]
    fn valid_policy_passes() {
        let policy = compile_policy(SandboxProfile::Strict);
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn conflicting_policy_detected() {
        let mut policy = compile_policy(SandboxProfile::Strict);
        policy.grants.push(CapabilityGrant {
            capability: "network_access".into(),
            access: AccessLevel::Allow,
        });
        let err = validate_policy(&policy).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyConflict { .. }));
    }

    // === Profile tracker ===

    #[test]
    fn tracker_initial_profile() {
        let t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
        assert_eq!(t.current_profile, SandboxProfile::Strict);
        assert_eq!(t.audit_log.len(), 1);
    }

    #[test]
    fn tracker_upgrade_allowed() {
        let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
        let audit = t
            .change_profile(
                SandboxProfile::Moderate,
                "needs network".into(),
                "t".into(),
                false,
            )
            .unwrap();
        assert_eq!(audit.new_profile, SandboxProfile::Moderate);
        assert_eq!(t.current_profile, SandboxProfile::Moderate);
        assert_eq!(t.audit_log.len(), 2);
    }

    #[test]
    fn tracker_downgrade_blocked() {
        let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Moderate);
        let err = t
            .change_profile(
                SandboxProfile::Strict,
                "lock down".into(),
                "t".into(),
                false,
            )
            .unwrap_err();
        assert!(matches!(err, SandboxError::DowngradeBlocked { .. }));
        assert_eq!(t.current_profile, SandboxProfile::Moderate); // unchanged
    }

    #[test]
    fn tracker_downgrade_with_override() {
        let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Moderate);
        let audit = t
            .change_profile(SandboxProfile::Strict, "emergency".into(), "t".into(), true)
            .unwrap();
        assert_eq!(audit.new_profile, SandboxProfile::Strict);
        assert_eq!(t.current_profile, SandboxProfile::Strict);
    }

    #[test]
    fn tracker_capability_check() {
        let t = ProfileTracker::new("conn-1".into(), SandboxProfile::Moderate);
        assert_eq!(
            t.is_capability_allowed("network_access"),
            AccessLevel::Filtered
        );
        assert_eq!(t.is_capability_allowed("fs_write"), AccessLevel::Deny);
        assert_eq!(t.is_capability_allowed("unknown"), AccessLevel::Deny);
    }

    // === Serde roundtrip ===

    #[test]
    fn serde_roundtrip_profile() {
        for p in &SandboxProfile::ALL {
            let json = serde_json::to_string(p).unwrap();
            let parsed: SandboxProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, p);
        }
    }

    #[test]
    fn serde_roundtrip_policy() {
        let policy = compile_policy(SandboxProfile::Moderate);
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }

    #[test]
    fn error_display_messages() {
        let e1 = SandboxError::DowngradeBlocked {
            current: SandboxProfile::Moderate,
            requested: SandboxProfile::Strict,
        };
        assert!(e1.to_string().contains("SANDBOX_DOWNGRADE_BLOCKED"));

        let e2 = SandboxError::ProfileUnknown { name: "bad".into() };
        assert!(e2.to_string().contains("SANDBOX_PROFILE_UNKNOWN"));

        let e3 = SandboxError::PolicyConflict {
            capability: "net".into(),
            access_a: "deny".into(),
            access_b: "allow".into(),
        };
        assert!(e3.to_string().contains("SANDBOX_POLICY_CONFLICT"));

        let e4 = SandboxError::CompileError {
            reason: "failed".into(),
        };
        assert!(e4.to_string().contains("SANDBOX_COMPILE_ERROR"));
    }
}
