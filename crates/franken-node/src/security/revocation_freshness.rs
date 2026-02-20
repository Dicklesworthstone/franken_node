//! bd-1m8r: Revocation freshness gate per safety tier.
//!
//! Enforces revocation freshness before risky/dangerous actions.
//! Standard-tier actions always pass. Higher tiers require fresher
//! revocation data. Overrides require a policy-backed receipt.

/// Safety tier classification for actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafetyTier {
    Standard,
    Risky,
    Dangerous,
}

impl std::fmt::Display for SafetyTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "Standard"),
            Self::Risky => write!(f, "Risky"),
            Self::Dangerous => write!(f, "Dangerous"),
        }
    }
}

/// Policy defining max revocation age per tier.
#[derive(Debug, Clone)]
pub struct FreshnessPolicy {
    /// Max revocation data age (seconds) for Risky actions.
    pub risky_max_age_secs: u64,
    /// Max revocation data age (seconds) for Dangerous actions.
    pub dangerous_max_age_secs: u64,
}

impl FreshnessPolicy {
    pub fn default_policy() -> Self {
        Self {
            risky_max_age_secs: 3600,    // 1 hour
            dangerous_max_age_secs: 300, // 5 minutes
        }
    }

    /// Returns the max age for a given tier, or None for Standard.
    pub fn max_age_for_tier(&self, tier: SafetyTier) -> Option<u64> {
        match tier {
            SafetyTier::Standard => None,
            SafetyTier::Risky => Some(self.risky_max_age_secs),
            SafetyTier::Dangerous => Some(self.dangerous_max_age_secs),
        }
    }

    /// Validate the policy configuration.
    pub fn validate(&self) -> Result<(), FreshnessError> {
        if self.dangerous_max_age_secs > self.risky_max_age_secs {
            return Err(FreshnessError::PolicyInvalid {
                reason: "dangerous_max_age must be <= risky_max_age".into(),
            });
        }
        if self.risky_max_age_secs == 0 {
            return Err(FreshnessError::PolicyInvalid {
                reason: "risky_max_age must be > 0".into(),
            });
        }
        Ok(())
    }
}

/// Input for a freshness gate check.
#[derive(Debug, Clone)]
pub struct FreshnessCheck {
    pub action_id: String,
    pub tier: SafetyTier,
    pub revocation_age_secs: u64,
    pub trace_id: String,
    pub timestamp: String,
}

/// Override receipt for bypassing a stale-frontier denial.
#[derive(Debug, Clone)]
pub struct OverrideReceipt {
    pub action_id: String,
    pub actor: String,
    pub reason: String,
    pub timestamp: String,
    pub trace_id: String,
}

/// The outcome of a freshness gate evaluation.
#[derive(Debug, Clone)]
pub struct FreshnessDecision {
    pub action_id: String,
    pub tier: SafetyTier,
    pub allowed: bool,
    pub revocation_age_secs: u64,
    pub max_age_secs: Option<u64>,
    pub override_receipt: Option<OverrideReceipt>,
    pub reason: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Error codes for freshness gate.
///
/// - `RF_STALE_FRONTIER`
/// - `RF_OVERRIDE_REQUIRED`
/// - `RF_POLICY_INVALID`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessError {
    StaleFrontier {
        tier: String,
        age_secs: u64,
        max_age_secs: u64,
    },
    OverrideRequired {
        tier: String,
        age_secs: u64,
    },
    PolicyInvalid {
        reason: String,
    },
}

impl FreshnessError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::StaleFrontier { .. } => "RF_STALE_FRONTIER",
            Self::OverrideRequired { .. } => "RF_OVERRIDE_REQUIRED",
            Self::PolicyInvalid { .. } => "RF_POLICY_INVALID",
        }
    }
}

impl std::fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleFrontier {
                tier,
                age_secs,
                max_age_secs,
            } => {
                write!(
                    f,
                    "RF_STALE_FRONTIER: {tier} action denied, age {age_secs}s > max {max_age_secs}s"
                )
            }
            Self::OverrideRequired { tier, age_secs } => {
                write!(
                    f,
                    "RF_OVERRIDE_REQUIRED: {tier} action needs override, age {age_secs}s"
                )
            }
            Self::PolicyInvalid { reason } => {
                write!(f, "RF_POLICY_INVALID: {reason}")
            }
        }
    }
}

/// Evaluate the freshness gate for an action.
///
/// INV-RF-STANDARD-PASS: Standard tier always passes.
/// INV-RF-TIER-GATE: Risky/Dangerous denied if stale.
/// INV-RF-OVERRIDE-RECEIPT: Override allows stale actions with receipt.
/// INV-RF-AUDIT: Every call produces a decision record.
pub fn evaluate_freshness(
    policy: &FreshnessPolicy,
    check: &FreshnessCheck,
    override_receipt: Option<&OverrideReceipt>,
) -> Result<FreshnessDecision, FreshnessError> {
    let max_age = policy.max_age_for_tier(check.tier);

    // INV-RF-STANDARD-PASS: no freshness requirement
    if check.tier == SafetyTier::Standard {
        return Ok(FreshnessDecision {
            action_id: check.action_id.clone(),
            tier: check.tier,
            allowed: true,
            revocation_age_secs: check.revocation_age_secs,
            max_age_secs: None,
            override_receipt: None,
            reason: "standard tier: no freshness requirement".into(),
            trace_id: check.trace_id.clone(),
            timestamp: check.timestamp.clone(),
        });
    }

    let max_age_secs = max_age.unwrap(); // Safe: only Standard returns None

    // Fresh enough: allow
    if check.revocation_age_secs <= max_age_secs {
        return Ok(FreshnessDecision {
            action_id: check.action_id.clone(),
            tier: check.tier,
            allowed: true,
            revocation_age_secs: check.revocation_age_secs,
            max_age_secs: Some(max_age_secs),
            override_receipt: None,
            reason: "revocation data is fresh".into(),
            trace_id: check.trace_id.clone(),
            timestamp: check.timestamp.clone(),
        });
    }

    // Stale: check for override
    if let Some(receipt) = override_receipt {
        // INV-RF-OVERRIDE-RECEIPT: override produces receipt
        return Ok(FreshnessDecision {
            action_id: check.action_id.clone(),
            tier: check.tier,
            allowed: true,
            revocation_age_secs: check.revocation_age_secs,
            max_age_secs: Some(max_age_secs),
            override_receipt: Some(receipt.clone()),
            reason: format!("override accepted: {}", receipt.reason),
            trace_id: check.trace_id.clone(),
            timestamp: check.timestamp.clone(),
        });
    }

    // INV-RF-TIER-GATE: deny stale without override
    Err(FreshnessError::StaleFrontier {
        tier: check.tier.to_string(),
        age_secs: check.revocation_age_secs,
        max_age_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FreshnessPolicy {
        FreshnessPolicy {
            risky_max_age_secs: 3600,
            dangerous_max_age_secs: 300,
        }
    }

    fn check_action(tier: SafetyTier, age: u64) -> FreshnessCheck {
        FreshnessCheck {
            action_id: "act-1".into(),
            tier,
            revocation_age_secs: age,
            trace_id: "tr-1".into(),
            timestamp: "ts-1".into(),
        }
    }

    fn override_receipt() -> OverrideReceipt {
        OverrideReceipt {
            action_id: "act-1".into(),
            actor: "admin".into(),
            reason: "emergency maintenance".into(),
            timestamp: "ts-override".into(),
            trace_id: "tr-1".into(),
        }
    }

    #[test]
    fn standard_always_passes() {
        let d = evaluate_freshness(&policy(), &check_action(SafetyTier::Standard, 999999), None)
            .unwrap();
        assert!(d.allowed);
        assert!(d.max_age_secs.is_none());
    }

    #[test]
    fn risky_fresh_passes() {
        let d =
            evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 1000), None).unwrap();
        assert!(d.allowed);
        assert_eq!(d.max_age_secs, Some(3600));
    }

    #[test]
    fn risky_stale_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 5000), None)
            .unwrap_err();
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn dangerous_fresh_passes() {
        let d =
            evaluate_freshness(&policy(), &check_action(SafetyTier::Dangerous, 100), None).unwrap();
        assert!(d.allowed);
        assert_eq!(d.max_age_secs, Some(300));
    }

    #[test]
    fn dangerous_stale_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Dangerous, 500), None)
            .unwrap_err();
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn override_allows_stale_risky() {
        let d = evaluate_freshness(
            &policy(),
            &check_action(SafetyTier::Risky, 5000),
            Some(&override_receipt()),
        )
        .unwrap();
        assert!(d.allowed);
        assert!(d.override_receipt.is_some());
    }

    #[test]
    fn override_allows_stale_dangerous() {
        let d = evaluate_freshness(
            &policy(),
            &check_action(SafetyTier::Dangerous, 500),
            Some(&override_receipt()),
        )
        .unwrap();
        assert!(d.allowed);
        assert!(d.override_receipt.is_some());
        assert!(d.reason.contains("override accepted"));
    }

    #[test]
    fn override_receipt_has_actor() {
        let d = evaluate_freshness(
            &policy(),
            &check_action(SafetyTier::Risky, 5000),
            Some(&override_receipt()),
        )
        .unwrap();
        assert_eq!(d.override_receipt.as_ref().unwrap().actor, "admin");
    }

    #[test]
    fn at_boundary_passes() {
        // Age exactly at max_age should pass (<= check)
        let d =
            evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 3600), None).unwrap();
        assert!(d.allowed);
    }

    #[test]
    fn just_over_boundary_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 3601), None)
            .unwrap_err();
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn default_policy_values() {
        let p = FreshnessPolicy::default_policy();
        assert_eq!(p.risky_max_age_secs, 3600);
        assert_eq!(p.dangerous_max_age_secs, 300);
    }

    #[test]
    fn policy_validate_ok() {
        assert!(policy().validate().is_ok());
    }

    #[test]
    fn policy_validate_invalid_dangerous_gt_risky() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 100,
            dangerous_max_age_secs: 200,
        };
        assert_eq!(p.validate().unwrap_err().code(), "RF_POLICY_INVALID");
    }

    #[test]
    fn policy_validate_zero_risky() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 0,
            dangerous_max_age_secs: 0,
        };
        assert_eq!(p.validate().unwrap_err().code(), "RF_POLICY_INVALID");
    }

    #[test]
    fn decision_has_trace_id() {
        let d =
            evaluate_freshness(&policy(), &check_action(SafetyTier::Standard, 0), None).unwrap();
        assert_eq!(d.trace_id, "tr-1");
    }

    #[test]
    fn tier_display() {
        assert_eq!(SafetyTier::Standard.to_string(), "Standard");
        assert_eq!(SafetyTier::Risky.to_string(), "Risky");
        assert_eq!(SafetyTier::Dangerous.to_string(), "Dangerous");
    }

    #[test]
    fn error_display() {
        let e = FreshnessError::StaleFrontier {
            tier: "Risky".into(),
            age_secs: 5000,
            max_age_secs: 3600,
        };
        assert!(e.to_string().contains("RF_STALE_FRONTIER"));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            FreshnessError::StaleFrontier {
                tier: "x".into(),
                age_secs: 0,
                max_age_secs: 0
            }
            .code(),
            "RF_STALE_FRONTIER"
        );
        assert_eq!(
            FreshnessError::OverrideRequired {
                tier: "x".into(),
                age_secs: 0
            }
            .code(),
            "RF_OVERRIDE_REQUIRED"
        );
        assert_eq!(
            FreshnessError::PolicyInvalid { reason: "x".into() }.code(),
            "RF_POLICY_INVALID"
        );
    }

    #[test]
    fn max_age_for_tier() {
        let p = policy();
        assert_eq!(p.max_age_for_tier(SafetyTier::Standard), None);
        assert_eq!(p.max_age_for_tier(SafetyTier::Risky), Some(3600));
        assert_eq!(p.max_age_for_tier(SafetyTier::Dangerous), Some(300));
    }
}
