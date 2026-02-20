//! bd-8vby: Device profile registry and placement policy schema.
//!
//! Profiles are schema-validated on registration. Stale profiles are excluded
//! from placement. Placement evaluation is deterministic.

use std::collections::HashMap;

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
            Self::StaleProfile { device_id, age_secs } => {
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

/// Validate a device profile schema.
///
/// INV-DPR-SCHEMA: profiles must have non-empty device_id, region, tier,
/// at least one capability, and a valid schema_version.
pub fn validate_profile(profile: &DeviceProfile) -> Result<(), RegistryError> {
    if profile.device_id.is_empty() {
        return Err(RegistryError::SchemaInvalid {
            device_id: "(empty)".into(),
            field: "device_id".into(),
        });
    }
    if profile.capabilities.is_empty() {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "capabilities".into(),
        });
    }
    if profile.region.is_empty() {
        return Err(RegistryError::SchemaInvalid {
            device_id: profile.device_id.clone(),
            field: "region".into(),
        });
    }
    if profile.tier.is_empty() {
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
        if c.required_capabilities.is_empty() {
            return Err(RegistryError::InvalidConstraint {
                reason: "required_capabilities is empty".into(),
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
pub struct DeviceProfileRegistry {
    profiles: HashMap<String, DeviceProfile>,
}

impl DeviceProfileRegistry {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
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
            if age > policy.freshness_max_age_secs {
                rejected.push(DeviceMatch {
                    device_id: profile.device_id.clone(),
                    matched: false,
                    reason: format!("stale: age {}s > max {}s", age, policy.freshness_max_age_secs),
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
                    fail_reason = format!("tier {} below min {}", profile.tier, constraint.min_tier);
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
                total_score += 1 + region_bonus;
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

    fn constraint(caps: &[&str], region: &str, min_tier: &str, max_latency: u64) -> PlacementConstraint {
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
        let p2 = DeviceProfile { capabilities: vec![], ..p };
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
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
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
        reg.register(prof("d1", &["gpu", "tpu"], "us-east", "Standard", 100)).unwrap();
        let p = policy(vec![constraint(&["gpu"], "us-east", "", 100)], 3600);
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.matched[0].device_id, "d1");
    }

    #[test]
    fn placement_rejects_missing_capability() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        let p = policy(vec![constraint(&["tpu"], "us", "", 100)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_rejects_stale_profile() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "", 100)], 50);
        // now=200, registered=100 → age=100 > max_age=50
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_rejects_below_min_tier() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        let p = policy(vec![constraint(&["gpu"], "us", "Risky", 100)], 3600);
        let err = reg.evaluate_placement(&p, 200, "ts").unwrap_err();
        assert_eq!(err.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn placement_deterministic() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        reg.register(prof("d2", &["gpu"], "eu", "Standard", 100)).unwrap();
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
        reg.register(prof("d1", &["gpu"], "eu", "Standard", 100)).unwrap();
        reg.register(prof("d2", &["gpu"], "us", "Standard", 100)).unwrap();
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
        assert_eq!(RegistryError::SchemaInvalid { device_id: "x".into(), field: "y".into() }.code(), "DPR_SCHEMA_INVALID");
        assert_eq!(RegistryError::StaleProfile { device_id: "x".into(), age_secs: 0 }.code(), "DPR_STALE_PROFILE");
        assert_eq!(RegistryError::InvalidConstraint { reason: "x".into() }.code(), "DPR_INVALID_CONSTRAINT");
        assert_eq!(RegistryError::NoMatch.code(), "DPR_NO_MATCH");
    }

    #[test]
    fn error_display() {
        let e = RegistryError::SchemaInvalid { device_id: "d1".into(), field: "region".into() };
        assert!(e.to_string().contains("DPR_SCHEMA_INVALID"));
    }

    #[test]
    fn get_profile() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        assert!(reg.get("d1").is_some());
        assert!(reg.get("d2").is_none());
    }

    #[test]
    fn result_has_trace() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu"], "us", "Standard", 100)).unwrap();
        let p = policy(vec![constraint(&["gpu"], "", "", 100)], 3600);
        let result = reg.evaluate_placement(&p, 200, "ts").unwrap();
        assert_eq!(result.trace_id, "tr-test");
    }

    #[test]
    fn multiple_constraints_all_must_match() {
        let mut reg = DeviceProfileRegistry::new();
        reg.register(prof("d1", &["gpu", "tpu"], "us", "Risky", 100)).unwrap();
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
}
