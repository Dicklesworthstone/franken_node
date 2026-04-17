//! bd-8vby: Device profile registry and placement policy schema.
//!
//! Profiles are schema-validated on registration. Stale profiles are excluded
//! from placement. Placement evaluation is deterministic.

use std::collections::{BTreeMap, BTreeSet};

/// A registered device profile.
#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub device_id: String,
    pub capabilities: Vec<String>,
    pub region: String,
    pub tier: String,
    pub registered_at: u64,
    pub schema_version: u32,
}

/// A placement constraint for execution targeting.
#[derive(Debug, Clone)]
pub struct PlacementConstraint {
    pub required_capabilities: Vec<String>,
    pub preferred_region: String,
    pub min_tier: String,
    pub max_latency_ms: u64,
}

/// Placement policy: constraints + freshness bounds.
#[derive(Debug, Clone)]
pub struct PlacementPolicy {
    pub constraints: Vec<PlacementConstraint>,
    pub freshness_max_age_secs: u64,
    pub trace_id: String,
}

/// A device match/rejection reason in a placement result.
#[derive(Debug, Clone)]
pub struct DeviceMatch {
    pub device_id: String,
    pub matched: bool,
    pub reason: String,
    pub score: u64,
}

/// Result of placement evaluation.
#[derive(Debug, Clone)]
pub struct PlacementResult {
    pub matched: Vec<DeviceMatch>,
    pub rejected: Vec<DeviceMatch>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Errors from registry operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    SchemaInvalid { device_id: String, field: String },
    StaleProfile { device_id: String, age_secs: u64 },
    InvalidConstraint { reason: String },
    NoMatch,
}

impl RegistryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaInvalid { .. } => "DPR_SCHEMA_INVALID",
            Self::StaleProfile { .. } => "DPR_STALE_PROFILE",
            Self::InvalidConstraint { .. } => "DPR_INVALID_CONSTRAINT",
            Self::NoMatch => "DPR_NO_MATCH",
        }
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaInvalid { device_id, field } => {
                write!(f, "DPR_SCHEMA_INVALID: {device_id} field {field}")
            }
            Self::StaleProfile {
                device_id,
                age_secs,
            } => {
                write!(f, "DPR_STALE_PROFILE: {device_id} age {age_secs}s")
            }
            Self::InvalidConstraint { reason } => {
                write!(f, "DPR_INVALID_CONSTRAINT: {reason}")
            }
            Self::NoMatch => write!(f, "DPR_NO_MATCH"),
        }
    }
}

/// Tier ordering for comparison. Higher = more capable.
fn tier_rank(tier: &str) -> u8 {
    match tier {
        "Standard" => 1,
        "Risky" => 2,
        "Dangerous" => 3,
        _ => 0,
    }
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

/// Validate a device profile schema.
///
/// INV-DPR-SCHEMA: profiles must have non-empty device_id, region, tier,
/// at least one capability, and a valid schema_version.
pub fn validate_profile(profile: &DeviceProfile) -> Result<(), RegistryError> {
    if profile.device_id.trim().is_empty()
        || profile.device_id.trim() != profile.device_id
        || contains_nul(&profile.device_id)
    {
        return Err(RegistryError::SchemaInvalid {
            device_id: "(empty)".into(),
            field: "device_id".into(),
        });
    }
    if profile.capabilities.is_empty()
        || profile
            .capabilities
            .iter()
            .any(|capability| {
                capability.trim().is_empty()
                    || capability.trim() != capability
                    || contains_nul(capability)
            })
    {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "capabilities".into(),
        });
    }
    let mut seen_capabilities = BTreeSet::new();
    for capability in &profile.capabilities {
        if !seen_capabilities.insert(capability.as_str()) {
            return Err(RegistryError::SchemaInvalid {
                device_id: profile.device_id.clone(),
                field: "capabilities".into(),
            });
        }
    }
    if profile.region.trim().is_empty()
        || profile.region.trim() != profile.region
        || contains_nul(&profile.region)
    {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "region".into(),
        });
    }
    if profile.tier.trim().is_empty()
        || profile.tier.trim() != profile.tier
        || contains_nul(&profile.tier)
    {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "tier".into(),
        });
    }
    if profile.schema_version == 0 {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "schema_version".into(),
        });
    }
    Ok(())
}

/// Validate placement constraints.
///
/// INV-DPR-REJECT-INVALID: malformed constraints are rejected.
pub fn validate_constraints(constraints: &[PlacementConstraint]) -> Result<(), RegistryError> {
    if constraints.is_empty() {
        return Err(RegistryError::InvalidConstraint {
            reason: "no constraints provided".into(),
        });
    }
    for c in constraints {
        if c.required_capabilities.is_empty()
            || c.required_capabilities
                .iter()
                .any(|capability| capability.trim().is_empty() || capability.trim() != capability)
        {
            return Err(RegistryError::InvalidConstraint {
                reason: "required_capabilities contains empty or non-canonical capability".into(),
            });
        }
        if c.required_capabilities
            .iter()
            .any(|capability| contains_nul(capability))
        {
            return Err(RegistryError::InvalidConstraint {
                reason: "required_capabilities must not contain NUL bytes".into(),
            });
        }
        let mut seen_required = BTreeSet::new();
        for capability in &c.required_capabilities {
            if !seen_required.insert(capability.as_str()) {
                return Err(RegistryError::InvalidConstraint {
                    reason: "required_capabilities must not contain duplicates".into(),
                });
            }
        }
        if !c.preferred_region.is_empty()
            && (c.preferred_region.trim() != c.preferred_region
                || contains_nul(&c.preferred_region))
        {
            return Err(RegistryError::InvalidConstraint {
                reason: "preferred_region is not canonical".into(),
            });
        }
        if !c.min_tier.is_empty()
            && (c.min_tier.trim() != c.min_tier || tier_rank(&c.min_tier) == 0)
        {
            return Err(RegistryError::InvalidConstraint {
                reason: "min_tier is not a canonical supported tier".into(),
            });
        }
        if c.max_latency_ms == 0 {
            return Err(RegistryError::InvalidConstraint {
                reason: "max_latency_ms must be > 0".into(),
            });
        }
    }
    Ok(())
}

/// Device profile registry.
#[derive(Default)]
pub struct DeviceProfileRegistry {
    profiles: BTreeMap<String, DeviceProfile>,
}

impl DeviceProfileRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device profile after schema validation.
    ///
    /// INV-DPR-SCHEMA: validates before accepting.
    pub fn register(&mut self, profile: DeviceProfile) -> Result<(), RegistryError> {
        validate_profile(&profile)?;
        self.profiles.insert(profile.device_id.clone(), profile);
        Ok(())
    }

    /// Deregister a device by ID.
    pub fn deregister(&mut self, device_id: &str) -> bool {
        self.profiles.remove(device_id).is_some()
    }

    /// Number of registered profiles.
    pub fn count(&self) -> usize {
        self.profiles.len()
    }

    /// Get a profile by device ID.
    pub fn get(&self, device_id: &str) -> Option<&DeviceProfile> {
        self.profiles.get(device_id)
    }

    /// Evaluate placement policy against registered profiles.
    ///
    /// INV-DPR-FRESHNESS: stale profiles are excluded.
    /// INV-DPR-DETERMINISTIC: same inputs → same result.
    pub fn evaluate_placement(
        &self,
        policy: &PlacementPolicy,
        now: u64,
        timestamp: &str,
    ) -> Result<PlacementResult, RegistryError> {
        validate_constraints(&policy.constraints)?;

        let mut matched = Vec::new();
        let mut rejected = Vec::new();

        // Sort profiles by device_id for deterministic ordering
        let mut sorted_profiles: Vec<&DeviceProfile> = self.profiles.values().collect();
        sorted_profiles.sort_by(|a, b| a.device_id.cmp(&b.device_id));

        for profile in sorted_profiles {
            // INV-DPR-FRESHNESS: check staleness
            let age = now.saturating_sub(profile.registered_at);
            if age >= policy.freshness_max_age_secs {
                rejected.push(DeviceMatch {
                    device_id: profile.device_id.clone(),
                    matched: false,
                    reason: format!(
                        "stale: age {}s >= max {}s",
                        age, policy.freshness_max_age_secs
                    ),
                    score: 0,
                });
                continue;
            }

            // Check each constraint
            let mut total_score: u64 = 0;
            let mut failed = false;
            let mut fail_reason = String::new();

            for constraint in &policy.constraints {
                // Check required capabilities
                let has_caps = constraint
                    .required_capabilities
                    .iter()
                    .all(|cap| profile.capabilities.contains(cap));
                if !has_caps {
                    failed = true;
                    fail_reason = "missing_capabilities".into();
                    break;
                }

                // Check minimum tier
                if !constraint.min_tier.is_empty()
                    && tier_rank(&profile.tier) < tier_rank(&constraint.min_tier)
                {
                    failed = true;
                    fail_reason =
                        format!("tier {} below min {}", profile.tier, constraint.min_tier);
                    break;
                }

                // Score: +10 for region match, +1 base
                let region_bonus = if !constraint.preferred_region.is_empty()
                    && profile.region == constraint.preferred_region
                {
                    10
                } else {
                    0
                };
                total_score = total_score.saturating_add(1_u64.saturating_add(region_bonus));
            }

            if failed {
                rejected.push(DeviceMatch {
                    device_id: profile.device_id.clone(),
                    matched: false,
                    reason: fail_reason,
                    score: 0,
                });
            } else {
                matched.push(DeviceMatch {
                    device_id: profile.device_id.clone(),
                    matched: true,
                    reason: "all constraints satisfied".into(),
                    score: total_score,
                });
            }
        }

        // Sort matched by score descending, then device_id for determinism
        matched.sort_by(|a, b| b.score.cmp(&a.score).then(a.device_id.cmp(&b.device_id)));

        if matched.is_empty() {
            return Err(RegistryError::NoMatch);
        }

        Ok(PlacementResult {
            matched,
            rejected,
            trace_id: policy.trace_id.clone(),
            timestamp: timestamp.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prof(id: &str, caps: &[&str], region: &str, tier: &str, registered: u64) -> DeviceProfile {
        DeviceProfile {
            device_id: id.into(),
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            region: region.into(),
            tier: tier.into(),
            registered_at: registered,
            schema_version: 1,
        }
    }

    fn constraint(
        caps: &[&str],
        region: &str,
        min_tier: &str,
        max_latency: u64,
    ) -> PlacementConstraint {
        PlacementConstraint {
            required_capabilities: caps.iter().map(|c| c.to_string()).collect(),
            preferred_region: region.into(),
            min_tier: min_tier.into(),
            max_latency_ms: max_latency,
        }
    }

    fn policy(constraints: Vec<PlacementConstraint>, max_age: u64) -> PlacementPolicy {
        PlacementPolicy {
            constraints,
            freshness_max_age_secs: max_age,
            trace_id: "tr-test".into(),
        }
    }

    #[test]
    fn register_valid_profile() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d1", &["gpu", "tpu"], "us-east", "Standard", 100);
        assert!(reg.register(p).is_ok());
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn register_empty_device_id_fails() {
        let mut reg = DeviceProfileRegistry::new();
        let p = DeviceProfile {
            device_id: "".into(),
            capabilities: vec!["gpu".into()],
            region: "us".into(),
            tier: "Standard".into(),
            registered_at: 100,
            schema_version: 1,
        };
        let err = reg.register(p).unwrap_err();
        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
    }

    #[test]
    fn register_no_capabilities_fails() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d1", &[], "us", "Standard", 100);
        // Override caps to empty
        let p2 = DeviceProfile {
            capabilities: vec![],
            ..p
        };
        let err = reg.register(p2).unwrap_err();
        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
    }

    #[test]
    fn register_empty_region_fails() {
        let mut reg = DeviceProfileRegistry::new();
        let p = DeviceProfile {
            device_id: "d1".into(),
            capabilities: vec!["gpu".into()],
            region: "".into(),
            tier: "Standard".into(),
            registered_at: 100,
            schema_version: 1,
        };
        let err = reg.register(p).unwrap_err();
        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
    }

    #[test]
    fn register_zero_schema_version_fails() {
        let mut reg = DeviceProfileRegistry::new();
        let p = DeviceProfile {
            device_id: "d1".into(),
            capabilities: vec!["gpu".into()],
            region: "us".into(),
            tier: "Standard".into(),
            registered_at: 100,
            schema_version: 0,
        };
        let err = reg.register(p).unwrap_err();
        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
    }

    #[test]
    fn deregister_existing() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        assert!(reg.deregister("d1"));
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn deregister_missing() {
        let mut reg = DeviceProfileRegistry::new();
        assert!(!reg.deregister("d1"));
    }

    #[test]
    fn placement_matches_capable_device() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu", "tpu"], "us-east", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us-east", "", 100)], 3600);
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.matched[0].device_id, "d1");
    }

    #[test]
    fn placement_rejects_missing_capability() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["tpu"], "us", "", 100)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_rejects_stale_profile() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 50);
        // now=200, registered=100 → age=100 > max_age=50
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_rejects_below_min_tier() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "Risky", 100)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_deterministic() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        reg.register(prof("d2", &["gpu"], "eu", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 3600);
        let r1 = reg.evaluate_placement(&p, 200, "ts").unwrap();
        let r2 = reg.evaluate_placement(&p, 200, "ts").unwrap();
        let ids1: Vec<&str> = r1.matched.iter().map(|m| m.device_id.as_str()).collect();
        let ids2: Vec<&str> = r2.matched.iter().map(|m| m.device_id.as_str()).collect();
        assert_eq!(ids1, ids2, "INV-DPR-DETERMINISTIC violated");
    }

    #[test]
    fn placement_region_preferred_scores_higher() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "eu", "Standard", 100))
            .unwrap();
        reg.register(prof("d2", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 3600);
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.matched[0].device_id, "d2"); // us region preferred
    }

    #[test]
    fn empty_constraints_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = PlacementPolicy {
            constraints: vec![],
            freshness_max_age_secs: 3600,
            trace_id: "tr".into(),
        };
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
    }

    #[test]
    fn constraint_empty_caps_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&[], "us", "", 100)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
    }

    #[test]
    fn constraint_zero_latency_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&["gpu"], "us", "", 0)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            RegistryError::SchemaInvalid {
                device_id: "x".into(),
                field: "y".into()
            }
            .code(),
            "DPR_SCHEMA_INVALID"
        );
        assert_eq!(
            RegistryError::StaleProfile {
                device_id: "x".into(),
                age_secs: 0
            }
            .code(),
            "DPR_STALE_PROFILE"
        );
        assert_eq!(
            RegistryError::InvalidConstraint { reason: "x".into() }.code(),
            "DPR_INVALID_CONSTRAINT"
        );
        assert_eq!(RegistryError::NoMatch.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn error_display() {
        let e = RegistryError::SchemaInvalid {
            device_id: "d1".into(),
            field: "region".into(),
        };
        assert!(e.to_string().contains("DPR_SCHEMA_INVALID"));
    }

    #[test]
    fn get_profile() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        assert!(reg.get("d1").is_some());
        assert!(reg.get("d2").is_none());
    }

    #[test]
    fn result_has_trace() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "", "", 100)], 3600);
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.trace_id, "tr-test");
    }

    #[test]
    fn multiple_constraints_all_must_match() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu", "tpu"], "us", "Risky", 100))
            .unwrap();
        let p = policy(
            vec![
                constraint(&["gpu"], "us", "", 100),
                constraint(&["tpu"], "", "Risky", 100),
            ],
            3600,
        );
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.matched.len(), 1);
    }

    #[test]
    fn register_empty_tier_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-empty-tier", &["gpu"], "us", "", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-empty-tier").is_none());
    }

    #[test]
    fn register_whitespace_device_id_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof(" d-space ", &["gpu"], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get(" d-space ").is_none());
    }

    #[test]
    fn register_whitespace_region_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-region", &["gpu"], " us ", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-region").is_none());
    }

    #[test]
    fn register_whitespace_tier_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-tier", &["gpu"], "us", " Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-tier").is_none());
    }

    #[test]
    fn register_blank_capability_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-blank-cap", &["gpu", " "], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-blank-cap").is_none());
    }

    #[test]
    fn register_padded_capability_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-padded-cap", &["gpu", " tpu"], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-padded-cap").is_none());
    }

    #[test]
    fn constraint_padded_required_capability_is_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&[" gpu"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("required_capabilities"));
    }

    #[test]
    fn failed_register_does_not_replace_existing_profile() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let invalid_replacement = DeviceProfile {
            device_id: "d1".into(),
            capabilities: Vec::new(),
            region: "eu".into(),
            tier: "Dangerous".into(),
            registered_at: 200,
            schema_version: 1,
        };

        let err = reg.register(invalid_replacement).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        let original = reg.get("d1").expect("original profile should remain");
        assert_eq!(original.region, "us");
        assert_eq!(original.tier, "Standard");
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn placement_with_no_profiles_returns_no_match_for_valid_policy() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err, RegistryError::NoMatch);
    }

    #[test]
    fn stale_at_exact_freshness_boundary_is_excluded() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d-stale", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 100);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn case_mismatched_capability_requirement_fails_closed() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d-case", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["GPU"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn unknown_device_tier_fails_min_tier_requirement() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d-unknown-tier", &["gpu"], "us", "Experimental", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "Standard", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn stale_profile_is_reported_in_rejected_set_when_other_device_matches() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d-fresh", &["gpu"], "us", "Standard", 190))
            .unwrap();
        reg.register(prof("d-stale", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 100);

        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();

        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.matched[0].device_id, "d-fresh");
        assert_eq!(result.rejected.len(), 1);
        assert_eq!(result.rejected[0].device_id, "d-stale");
        assert!(result.rejected[0].reason.contains("stale"));
    }

    #[test]
    fn invalid_later_constraint_rejects_policy_before_matching_profiles() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Dangerous", 100))
            .unwrap();
        let p = policy(
            vec![
                constraint(&["gpu"], "us", "Standard", 100),
                constraint(&["tpu"], "us", "Standard", 0),
            ],
            3600,
        );

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
    }

    #[test]
    fn register_trailing_capability_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-trailing-cap", &["gpu", "tpu "], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-trailing-cap").is_none());
    }

    #[test]
    fn validate_profile_reports_capability_field_for_blank_capability() {
        let p = prof("d-cap-field", &["gpu", "\t"], "us", "Standard", 100);

        let err = validate_profile(&p).unwrap_err();

        assert_eq!(
            err,
            RegistryError::SchemaInvalid {
                device_id: "d-cap-field".to_string(),
                field: "capabilities".to_string(),
            }
        );
    }

    #[test]
    fn blank_required_capability_is_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&["\n"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("required_capabilities"));
    }

    #[test]
    fn later_blank_required_capability_rejects_before_profile_matching() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu", " "], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert_eq!(reg.count(), 1);
        assert!(reg.get("d1").is_some());
    }

    #[test]
    fn unknown_min_tier_constraint_is_rejected() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Dangerous", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "Experimental", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("min_tier"));
    }

    #[test]
    fn padded_min_tier_constraint_is_rejected() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Dangerous", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "Risky ", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("min_tier"));
    }

    #[test]
    fn register_device_id_with_nul_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("dev\0ice", &["gpu"], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("dev\0ice").is_none());
    }

    #[test]
    fn register_capability_with_nul_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-nul-cap", &["gpu\0bad"], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-nul-cap").is_none());
    }

    #[test]
    fn register_region_with_nul_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-nul-region", &["gpu"], "us\0east", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-nul-region").is_none());
    }

    #[test]
    fn register_tier_with_nul_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-nul-tier", &["gpu"], "us", "Standard\0", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-nul-tier").is_none());
    }

    #[test]
    fn register_duplicate_capability_fails_without_mutating_registry() {
        let mut reg = DeviceProfileRegistry::new();
        let p = prof("d-dup-cap", &["gpu", "gpu"], "us", "Standard", 100);

        let err = reg.register(p).unwrap_err();

        assert_eq!(err.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(reg.count(), 0);
        assert!(reg.get("d-dup-cap").is_none());
    }

    #[test]
    fn required_capability_with_nul_is_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&["gpu\0bad"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn duplicate_required_capability_is_rejected() {
        let reg = DeviceProfileRegistry::new();
        let p = policy(vec![constraint(&["gpu", "gpu"], "us", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("duplicates"));
    }

    #[test]
    fn padded_preferred_region_is_rejected_before_matching_profiles() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], " us ", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("preferred_region"));
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn preferred_region_with_nul_is_rejected_before_matching_profiles() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100))
            .unwrap();
        let p = policy(vec![constraint(&["gpu"], "us\0east", "", 100)], 3600);

        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();

        assert_eq!(err.code(), "DPR_INVALID_CONSTRAINT");
        assert!(err.to_string().contains("preferred_region"));
        assert_eq!(reg.count(), 1);
    }
}
