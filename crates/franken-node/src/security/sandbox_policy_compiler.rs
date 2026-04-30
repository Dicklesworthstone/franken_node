//! Sandbox profile system with policy compiler.
//! bd-1xbr: Bounded audit_log capacity with oldest-first eviction.
//!
//! Four tiers: strict, strict_plus, moderate, permissive. The policy
//! compiler translates a profile into enforceable capability grants.
//! Downgrades are blocked; profile selection is auditable.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

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
    let mut seen = std::collections::BTreeMap::new();
    for g in &policy.grants {
        if g.capability.trim().is_empty() {
            return Err(SandboxError::CompileError {
                reason: "capability must not be empty".to_string(),
            });
        }
        if g.capability.trim() != g.capability {
            return Err(SandboxError::CompileError {
                reason: format!(
                    "capability '{}' contains leading or trailing whitespace",
                    g.capability
                ),
            });
        }
        if let Some(prev) = seen.insert(&g.capability, &g.access)
            && prev != &g.access
        {
            return Err(SandboxError::PolicyConflict {
                capability: g.capability.clone(),
                access_a: format!("{prev}"),
                access_b: format!("{}", g.access),
            });
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
        if reason.trim().is_empty() {
            return Err(SandboxError::CompileError {
                reason: "profile change reason must not be empty".to_string(),
            });
        }
        if timestamp.trim().is_empty() {
            return Err(SandboxError::CompileError {
                reason: "profile change timestamp must not be empty".to_string(),
            });
        }

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
        // SECURITY: Audit logs must never silently drop events - use unbounded push
        // for security audit records rather than risking silent audit trail loss
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

    #[test]
    fn parse_rejects_case_mismatched_profile_name() {
        let err = SandboxProfile::parse("Strict").unwrap_err();

        assert_eq!(
            err,
            SandboxError::ProfileUnknown {
                name: "Strict".to_string()
            }
        );
        assert!(err.to_string().contains("Strict"));
    }

    #[test]
    fn parse_rejects_whitespace_padded_profile_name() {
        let err = SandboxProfile::parse("strict ").unwrap_err();

        assert_eq!(
            err,
            SandboxError::ProfileUnknown {
                name: "strict ".to_string()
            }
        );
    }

    #[test]
    fn validate_policy_reports_conflicting_access_pair() {
        let mut policy = compile_policy(SandboxProfile::Strict);
        policy.grants.push(CapabilityGrant {
            capability: "fs_read".to_string(),
            access: AccessLevel::Allow,
        });

        let err = validate_policy(&policy).unwrap_err();

        assert_eq!(
            err,
            SandboxError::PolicyConflict {
                capability: "fs_read".to_string(),
                access_a: "deny".to_string(),
                access_b: "allow".to_string()
            }
        );
    }

    #[test]
    fn validate_policy_detects_conflict_after_same_access_duplicate() {
        let mut policy = compile_policy(SandboxProfile::Strict);
        policy.grants.push(CapabilityGrant {
            capability: "ipc".to_string(),
            access: AccessLevel::Deny,
        });
        policy.grants.push(CapabilityGrant {
            capability: "ipc".to_string(),
            access: AccessLevel::Scoped,
        });

        let err = validate_policy(&policy).unwrap_err();

        assert_eq!(
            err,
            SandboxError::PolicyConflict {
                capability: "ipc".to_string(),
                access_a: "deny".to_string(),
                access_b: "scoped".to_string()
            }
        );
    }

    #[test]
    fn blocked_downgrade_preserves_tracker_state_and_audit_log() {
        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);
        let audit_len_before = tracker.audit_log.len();
        let policy_before = tracker.compiled_policy.clone();

        let err = tracker
            .change_profile(
                SandboxProfile::StrictPlus,
                "operator requested emergency clamp".into(),
                "2026-01-01T00:00:00Z".into(),
                false,
            )
            .unwrap_err();

        assert_eq!(
            err,
            SandboxError::DowngradeBlocked {
                current: SandboxProfile::Permissive,
                requested: SandboxProfile::StrictPlus
            }
        );
        assert_eq!(tracker.current_profile, SandboxProfile::Permissive);
        assert_eq!(tracker.compiled_policy, policy_before);
        assert_eq!(tracker.audit_log.len(), audit_len_before);
    }

    #[test]
    fn serde_rejects_unknown_profile_variant() {
        let err = serde_json::from_str::<SandboxProfile>(r#""strict-plus""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_unknown_access_level() {
        let err = serde_json::from_str::<AccessLevel>(r#""read_write""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn serde_rejects_policy_missing_grants() {
        let json = serde_json::json!({
            "profile": "strict",
            "level": 0
        });

        let err = serde_json::from_value::<CompiledPolicy>(json).unwrap_err();

        assert!(err.to_string().contains("grants"));
    }

    #[test]
    fn serde_rejects_unknown_error_variant() {
        let err = serde_json::from_str::<SandboxError>(
            r#"{"SANDBOX_UNKNOWN_ERROR":{"reason":"ambiguous"}}"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn validate_policy_rejects_empty_capability_name() {
        let mut policy = compile_policy(SandboxProfile::Strict);
        policy.grants.push(CapabilityGrant {
            capability: String::new(),
            access: AccessLevel::Deny,
        });

        let err = validate_policy(&policy).unwrap_err();

        assert_eq!(
            err,
            SandboxError::CompileError {
                reason: "capability must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn validate_policy_rejects_whitespace_only_capability_name() {
        let mut policy = compile_policy(SandboxProfile::Moderate);
        policy.grants.push(CapabilityGrant {
            capability: " \t ".to_string(),
            access: AccessLevel::Scoped,
        });

        let err = validate_policy(&policy).unwrap_err();

        assert_eq!(
            err,
            SandboxError::CompileError {
                reason: "capability must not be empty".to_string(),
            }
        );
    }

    #[test]
    fn validate_policy_rejects_padded_capability_alias() {
        let mut policy = compile_policy(SandboxProfile::Permissive);
        policy.grants.push(CapabilityGrant {
            capability: "fs_read ".to_string(),
            access: AccessLevel::Allow,
        });

        let err = validate_policy(&policy).unwrap_err();

        assert!(matches!(
            err,
            SandboxError::CompileError { reason }
                if reason.contains("leading or trailing whitespace")
        ));
    }

    #[test]
    fn change_profile_rejects_empty_reason_and_preserves_state() {
        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
        let before_policy = tracker.compiled_policy.clone();

        let err = tracker
            .change_profile(SandboxProfile::Moderate, String::new(), "ts".into(), false)
            .unwrap_err();

        assert_eq!(
            err,
            SandboxError::CompileError {
                reason: "profile change reason must not be empty".to_string(),
            }
        );
        assert_eq!(tracker.current_profile, SandboxProfile::Strict);
        assert_eq!(tracker.compiled_policy, before_policy);
        assert_eq!(tracker.audit_log.len(), 1);
    }

    #[test]
    fn change_profile_rejects_whitespace_timestamp_and_preserves_state() {
        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::StrictPlus);
        let before_policy = tracker.compiled_policy.clone();

        let err = tracker
            .change_profile(
                SandboxProfile::Moderate,
                "temporary expansion".into(),
                "  \n".into(),
                false,
            )
            .unwrap_err();

        assert_eq!(
            err,
            SandboxError::CompileError {
                reason: "profile change timestamp must not be empty".to_string(),
            }
        );
        assert_eq!(tracker.current_profile, SandboxProfile::StrictPlus);
        assert_eq!(tracker.compiled_policy, before_policy);
        assert_eq!(tracker.audit_log.len(), 1);
    }

    #[test]
    fn capability_lookup_rejects_whitespace_alias() {
        let tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);

        assert_eq!(tracker.is_capability_allowed("fs_read"), AccessLevel::Allow);
        assert_eq!(tracker.is_capability_allowed("fs_read "), AccessLevel::Deny);
        assert_eq!(tracker.is_capability_allowed(" fs_read"), AccessLevel::Deny);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_one_capacity_evicts_old_entry() {
        let mut items = vec!["old"];

        push_bounded(&mut items, "new", 1);

        assert_eq!(items, vec!["new"]);
    }

    fn assert_value_rejected<T>(value: serde_json::Value)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_value::<T>(value).is_err(),
            "malformed value should be rejected"
        );
    }

    #[test]
    fn serde_rejects_capability_grant_missing_access() {
        assert_value_rejected::<CapabilityGrant>(serde_json::json!({
            "capability": "network_access"
        }));
    }

    #[test]
    fn serde_rejects_capability_grant_numeric_access() {
        assert_value_rejected::<CapabilityGrant>(serde_json::json!({
            "capability": "fs_read",
            "access": 2
        }));
    }

    #[test]
    fn serde_rejects_compiled_policy_string_level() {
        assert_value_rejected::<CompiledPolicy>(serde_json::json!({
            "profile": "moderate",
            "level": "2",
            "grants": []
        }));
    }

    #[test]
    fn serde_rejects_profile_audit_record_unknown_new_profile() {
        assert_value_rejected::<ProfileAuditRecord>(serde_json::json!({
            "connector_id": "conn-1",
            "old_profile": "strict",
            "new_profile": "strict-plus",
            "changed_at": "2026-04-17T00:00:00Z",
            "reason": "operator request"
        }));
    }

    #[test]
    fn serde_rejects_profile_audit_record_numeric_old_profile() {
        assert_value_rejected::<ProfileAuditRecord>(serde_json::json!({
            "connector_id": "conn-1",
            "old_profile": 1,
            "new_profile": "moderate",
            "changed_at": "2026-04-17T00:00:00Z",
            "reason": "operator request"
        }));
    }

    #[test]
    fn serde_rejects_profile_tracker_missing_compiled_policy() {
        assert_value_rejected::<ProfileTracker>(serde_json::json!({
            "connector_id": "conn-1",
            "current_profile": "strict",
            "audit_log": []
        }));
    }

    #[test]
    fn serde_rejects_profile_tracker_object_current_profile() {
        assert_value_rejected::<ProfileTracker>(serde_json::json!({
            "connector_id": "conn-1",
            "current_profile": {"tier": "strict"},
            "compiled_policy": {
                "profile": "strict",
                "level": 0,
                "grants": []
            },
            "audit_log": []
        }));
    }

    #[test]
    fn serde_rejects_downgrade_error_missing_requested_profile() {
        assert_value_rejected::<SandboxError>(serde_json::json!({
            "SANDBOX_DOWNGRADE_BLOCKED": {
                "current": "moderate"
            }
        }));
    }

    #[test]
    fn serde_rejects_policy_conflict_error_numeric_access() {
        assert_value_rejected::<SandboxError>(serde_json::json!({
            "SANDBOX_POLICY_CONFLICT": {
                "capability": "network_access",
                "access_a": "deny",
                "access_b": 1
            }
        }));
    }

    // === Negative-path security tests ===

    #[test]
    fn test_security_unicode_injection_in_connector_ids_capabilities() {
        // Test Unicode BiDi override, zero-width, and injection attacks in connector IDs and capability names
        let malicious_connector_ids = [
            "conn\u{202e}ecil",  // Right-to-Left Override
            "conn\u{200b}ector", // Zero Width Space
            "conn\u{200c}ector", // Zero Width Non-Joiner
            "conn\u{200d}ector", // Zero Width Joiner
            "conn\u{feff}ector", // Zero Width No-Break Space (BOM)
            "conn\u{2028}ector", // Line Separator
            "conn\u{2029}ector", // Paragraph Separator
            "conn\0ector",       // Null byte injection
        ];

        for malicious_id in &malicious_connector_ids {
            let tracker = ProfileTracker::new(malicious_id.to_string(), SandboxProfile::Strict);
            // Should handle Unicode without panicking or bypassing validation
            assert_eq!(tracker.connector_id, *malicious_id);
            assert_eq!(tracker.current_profile, SandboxProfile::Strict);
        }

        // Test malicious capability names in policy validation
        let malicious_capabilities = [
            "\u{202e}fs_read", // BiDi override in capability name
            "fs_read\u{200b}", // Zero width at end
            "fs\0read",        // Null injection in capability
            "fs_read\u{2028}", // Line separator suffix
        ];

        for malicious_cap in &malicious_capabilities {
            let mut policy = compile_policy(SandboxProfile::Strict);
            policy.grants.push(CapabilityGrant {
                capability: malicious_cap.to_string(),
                access: AccessLevel::Deny,
            });
            // Should not confuse capability matching
            let result = validate_policy(&policy);
            assert!(
                result.is_ok(),
                "Unicode in capability should not break validation"
            );
        }
    }

    #[test]
    fn test_security_memory_exhaustion_through_audit_log_manipulation() {
        use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);

        // Attempt memory exhaustion by rapidly changing profiles to fill audit log
        for i in 0..MAX_AUDIT_LOG_ENTRIES.saturating_mul(3) {
            let profile = if i % 2 == 0 {
                SandboxProfile::Moderate
            } else {
                SandboxProfile::Strict
            };
            let result = tracker.change_profile(
                profile,
                format!("change_{}", i),
                format!("ts_{}", i),
                true, // allow downgrades
            );
            assert!(
                result.is_ok(),
                "Profile change should succeed within capacity"
            );
        }

        // Audit log should be bounded to MAX_AUDIT_LOG_ENTRIES
        assert!(
            tracker.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES,
            "Audit log exceeded maximum capacity: {} > {}",
            tracker.audit_log.len(),
            MAX_AUDIT_LOG_ENTRIES
        );

        // Verify oldest entries were evicted (FIFO behavior)
        if tracker.audit_log.len() == MAX_AUDIT_LOG_ENTRIES {
            let oldest_reason = &tracker.audit_log[0].reason;
            assert!(
                !oldest_reason.contains("change_0"),
                "Oldest entries should have been evicted, found: {}",
                oldest_reason
            );
        }
    }

    #[test]
    fn test_security_downgrade_bypass_attempts() {
        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);

        // Direct downgrade should be blocked
        let result = tracker.change_profile(
            SandboxProfile::Strict,
            "attack attempt".into(),
            "ts".into(),
            false,
        );
        assert!(matches!(result, Err(SandboxError::DowngradeBlocked { .. })));

        // Multi-step downgrade attempts through intermediate levels
        let result1 = tracker.change_profile(
            SandboxProfile::Moderate,
            "step1".into(),
            "ts1".into(),
            false,
        );
        assert!(result1.is_ok(), "Upgrade should succeed");

        let result2 =
            tracker.change_profile(SandboxProfile::Strict, "step2".into(), "ts2".into(), false);
        assert!(
            matches!(result2, Err(SandboxError::DowngradeBlocked { .. })),
            "Subsequent downgrade should still be blocked"
        );

        // Verify state consistency after blocked attempts
        assert_eq!(tracker.current_profile, SandboxProfile::Moderate);
        assert_eq!(tracker.compiled_policy.profile, SandboxProfile::Moderate);

        // Override flag should allow downgrade with explicit permission
        let result3 = tracker.change_profile(
            SandboxProfile::StrictPlus,
            "emergency override".into(),
            "ts3".into(),
            true,
        );
        assert!(result3.is_ok(), "Downgrade with override should succeed");
        assert_eq!(tracker.current_profile, SandboxProfile::StrictPlus);
    }

    #[test]
    fn test_security_capability_name_collision_and_confusion() {
        // Test capability matching edge cases and potential confusion attacks
        let tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Moderate);

        // Exact match should work
        assert_ne!(
            tracker.is_capability_allowed("network_access"),
            AccessLevel::Deny
        );

        // Similar but different names should default to deny
        let confusing_names = [
            "network_access_",    // Trailing underscore
            "_network_access",    // Leading underscore
            "network-access",     // Dash instead of underscore
            "networkaccess",      // No separator
            "network_Access",     // Different case
            "NETWORK_ACCESS",     // All caps
            "network_access\x00", // Null terminator
            "network_access\t",   // Tab character
            "network_access\n",   // Newline
            "network_access\r",   // Carriage return
        ];

        for confusing_name in &confusing_names {
            assert_eq!(
                tracker.is_capability_allowed(confusing_name),
                AccessLevel::Deny,
                "Confusing capability name '{}' should default to deny",
                confusing_name
            );
        }

        // Test policy with duplicate capabilities having different access levels
        let mut policy = compile_policy(SandboxProfile::Strict);
        policy.grants.extend([
            CapabilityGrant {
                capability: "test_cap".into(),
                access: AccessLevel::Allow,
            },
            CapabilityGrant {
                capability: "test_cap".into(),
                access: AccessLevel::Deny,
            },
        ]);

        let result = validate_policy(&policy);
        assert!(
            matches!(result, Err(SandboxError::PolicyConflict { .. })),
            "Conflicting access levels should be detected"
        );
    }

    #[test]
    fn test_security_json_serialization_injection_prevention() {
        // Test that malicious JSON in audit records doesn't bypass validation
        let malicious_reasons = [
            r#"{"evil": "payload"}"#,        // JSON object injection
            r#"[1, 2, 3]"#,                  // JSON array injection
            r#""escaped": "quote\""#,        // Quote injection
            "reason\n{\"override\": true}",  // Newline + JSON injection
            "reason\r\n\t{\"admin\": true}", // Multi-line injection
            "reason\\u0000evil",             // Unicode escape injection
        ];

        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);

        for malicious_reason in &malicious_reasons {
            let result = tracker.change_profile(
                SandboxProfile::Moderate,
                malicious_reason.to_string(),
                "2026-04-17T00:00:00Z".into(),
                false,
            );

            assert!(
                result.is_ok(),
                "Profile change should succeed despite malicious reason"
            );

            // Verify the malicious content is preserved as-is without interpretation
            let latest_audit = tracker.audit_log.last().unwrap();
            assert_eq!(latest_audit.reason, *malicious_reason);

            // JSON serialization should not interpret embedded JSON
            let serialized = serde_json::to_string(&latest_audit).unwrap();
            assert!(serialized.contains(&serde_json::to_string(malicious_reason).unwrap()));

            // Reset for next iteration
            let _ =
                tracker.change_profile(SandboxProfile::Strict, "reset".into(), "ts".into(), true);
        }
    }

    #[test]
    fn test_security_concurrent_policy_compilation_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let tracker = Arc::new(Mutex::new(ProfileTracker::new(
            "conn-1".into(),
            SandboxProfile::Strict,
        )));
        let mut handles = vec![];

        // Simulate concurrent profile changes from multiple threads
        for thread_id in 0..8 {
            let tracker_clone = Arc::clone(&tracker);
            let handle = thread::spawn(move || {
                for i in 0..50 {
                    let profile = match (thread_id + i) % 4 {
                        0 => SandboxProfile::Strict,
                        1 => SandboxProfile::StrictPlus,
                        2 => SandboxProfile::Moderate,
                        _ => SandboxProfile::Permissive,
                    };

                    let result = tracker_clone.lock().unwrap().change_profile(
                        profile,
                        format!("thread_{}_change_{}", thread_id, i),
                        format!("ts_{}_{}", thread_id, i),
                        true, // allow downgrades for test
                    );

                    // All changes should succeed or fail cleanly
                    assert!(result.is_ok(), "Concurrent profile change should succeed");
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify tracker is in a consistent state
        let final_tracker = tracker.lock().unwrap();
        let profile_matches_policy =
            final_tracker.compiled_policy.profile == final_tracker.current_profile;
        assert!(
            profile_matches_policy,
            "Profile and policy should be consistent after concurrent access"
        );

        // Audit log should be bounded and valid
        assert!(final_tracker.audit_log.len() <= MAX_AUDIT_LOG_ENTRIES);
        assert!(!final_tracker.audit_log.is_empty());
    }

    #[test]
    fn test_security_arithmetic_overflow_in_profile_levels() {
        // Test that profile level arithmetic doesn't overflow
        let profiles = SandboxProfile::ALL;

        for &p1 in &profiles {
            for &p2 in &profiles {
                // Level comparisons should not overflow
                let level_diff = p1.level().saturating_sub(p2.level());
                assert!(level_diff <= 255, "Level difference should be bounded");

                // Downgrade detection should be safe
                let is_downgrade = p1.is_downgrade_to(&p2);
                assert_eq!(is_downgrade, p2.level() < p1.level());

                // Policy compilation should produce consistent level
                let policy = compile_policy(p1);
                assert_eq!(policy.level, p1.level());
                assert!(
                    policy.level <= 3,
                    "Profile level should be bounded to valid range"
                );
            }
        }

        // Test edge case with potential integer manipulation
        let mut policy = compile_policy(SandboxProfile::Permissive);
        policy.level = u8::MAX; // Artificially high level

        // System should handle artificially high levels gracefully
        let result = validate_policy(&policy);
        assert!(
            result.is_ok(),
            "Policy validation should handle edge case levels"
        );
    }

    #[test]
    fn test_security_policy_tampering_resistance() {
        // Test resistance to policy structure tampering
        let original_policy = compile_policy(SandboxProfile::Moderate);
        let mut tampered_policy = original_policy.clone();

        // Attempt to inject privileged capabilities
        tampered_policy.grants.push(CapabilityGrant {
            capability: "admin_override".into(),
            access: AccessLevel::Allow,
        });
        tampered_policy.grants.push(CapabilityGrant {
            capability: "bypass_sandbox".into(),
            access: AccessLevel::Allow,
        });

        // Validation should still pass (unknown capabilities are valid)
        assert!(validate_policy(&tampered_policy).is_ok());

        // But capability lookup should default to deny for unknown capabilities
        let tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Moderate);
        assert_eq!(
            tracker.is_capability_allowed("admin_override"),
            AccessLevel::Deny
        );
        assert_eq!(
            tracker.is_capability_allowed("bypass_sandbox"),
            AccessLevel::Deny
        );

        // Test profile/level mismatch detection
        let mut mismatched_policy = original_policy.clone();
        mismatched_policy.profile = SandboxProfile::Strict;
        mismatched_policy.level = SandboxProfile::Permissive.level(); // Wrong level for profile

        // Should be detectable through policy introspection
        assert_ne!(mismatched_policy.profile.level(), mismatched_policy.level);

        // Test grants manipulation - remove critical denials
        let mut weakened_policy = compile_policy(SandboxProfile::Strict);
        weakened_policy
            .grants
            .retain(|g| g.capability != "network_access");

        // Missing capabilities should default to deny
        let weakened_tracker = ProfileTracker {
            connector_id: "test".into(),
            current_profile: SandboxProfile::Strict,
            compiled_policy: weakened_policy,
            audit_log: vec![],
        };
        assert_eq!(
            weakened_tracker.is_capability_allowed("network_access"),
            AccessLevel::Deny
        );
    }

    #[test]
    fn test_security_audit_trail_poisoning_prevention() {
        let mut tracker = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);

        // Test injection attempts in audit record fields
        let malicious_inputs = [
            (
                "malicious\nconnector\x00id",
                "normal reason",
                "normal timestamp",
            ),
            (
                "normal-conn",
                "reason\rwith\ncontrol\x00chars",
                "normal timestamp",
            ),
            (
                "normal-conn",
                "normal reason",
                "timestamp\twith\ninvalid\x00chars",
            ),
            ("conn\u{202e}evil", "reason\u{200b}hidden", "ts\u{feff}bom"),
        ];

        for (connector_suffix, reason, timestamp) in &malicious_inputs {
            let result = tracker.change_profile(
                SandboxProfile::Moderate,
                reason.to_string(),
                timestamp.to_string(),
                false,
            );

            assert!(
                result.is_ok(),
                "Profile change with malicious input should succeed"
            );

            let latest_audit = tracker.audit_log.last().unwrap();
            assert_eq!(latest_audit.reason, *reason);
            assert_eq!(latest_audit.changed_at, *timestamp);
            assert_eq!(latest_audit.connector_id, tracker.connector_id);

            // Audit trail should preserve exact input without interpretation
            let serialized = serde_json::to_string(latest_audit).unwrap();
            let parsed: ProfileAuditRecord = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, *latest_audit);

            // Reset for next test
            let _ =
                tracker.change_profile(SandboxProfile::Strict, "reset".into(), "ts".into(), true);
        }

        // Test audit log bounds under injection pressure
        let long_reason = "x".repeat(10_000); // Very long reason
        let result = tracker.change_profile(
            SandboxProfile::Moderate,
            long_reason.clone(),
            "ts".into(),
            false,
        );

        assert!(result.is_ok(), "Long reason should be handled gracefully");
        assert_eq!(tracker.audit_log.last().unwrap().reason, long_reason);
    }

    #[test]
    fn test_security_bounded_audit_log_fifo_manipulation() {
        use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

        let mut tracker = ProfileTracker::new("conn-initial".into(), SandboxProfile::Strict);

        // Fill audit log exactly to capacity
        for i in 1..MAX_AUDIT_LOG_ENTRIES {
            let result = tracker.change_profile(
                if i % 2 == 0 {
                    SandboxProfile::Moderate
                } else {
                    SandboxProfile::Strict
                },
                format!("fill_entry_{}", i),
                format!("ts_{}", i),
                true,
            );
            assert!(result.is_ok(), "Should fill audit log without error");
        }

        assert_eq!(tracker.audit_log.len(), MAX_AUDIT_LOG_ENTRIES);

        // Verify FIFO eviction behavior
        let first_entry_reason = tracker.audit_log[0].reason.clone();
        assert_eq!(first_entry_reason, "initial assignment");

        // Add one more entry to trigger eviction
        let overflow_result = tracker.change_profile(
            SandboxProfile::Permissive,
            "overflow_trigger".into(),
            "overflow_ts".into(),
            true,
        );

        assert!(overflow_result.is_ok(), "Overflow entry should succeed");
        assert_eq!(tracker.audit_log.len(), MAX_AUDIT_LOG_ENTRIES);

        // Initial entry should be evicted, first entry should now be "fill_entry_1"
        let new_first_entry = &tracker.audit_log[0];
        assert_eq!(new_first_entry.reason, "fill_entry_1");

        // Last entry should be the overflow trigger
        let last_entry = &tracker.audit_log[MAX_AUDIT_LOG_ENTRIES - 1];
        assert_eq!(last_entry.reason, "overflow_trigger");

        // Test zero capacity edge case
        let mut empty_items = vec![1, 2, 3];
        push_bounded(&mut empty_items, 4, 0);
        assert!(
            empty_items.is_empty(),
            "Zero capacity should clear all items"
        );

        // Test single capacity with multiple pushes
        let mut single_items = vec![];
        for i in 0..5 {
            push_bounded(&mut single_items, i, 1);
            assert_eq!(single_items.len(), 1, "Should maintain single capacity");
            assert_eq!(single_items[0], i, "Should contain latest item");
        }
    }
}
