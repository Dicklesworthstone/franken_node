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
    let max_age_secs = match check.tier {
        // INV-RF-STANDARD-PASS: no freshness requirement
        SafetyTier::Standard => {
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
        SafetyTier::Risky => policy.risky_max_age_secs,
        SafetyTier::Dangerous => policy.dangerous_max_age_secs,
    };

    // Fresh enough: allow (fail-closed: exact boundary = stale)
    if check.revocation_age_secs < max_age_secs {
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
        validate_override_receipt(check, receipt)?;

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

fn validate_override_receipt(
    check: &FreshnessCheck,
    receipt: &OverrideReceipt,
) -> Result<(), FreshnessError> {
    let invalid = check.action_id.trim().is_empty()
        || receipt.action_id.trim().is_empty()
        || receipt.action_id != check.action_id
        || check.trace_id.trim().is_empty()
        || receipt.trace_id != check.trace_id
        || receipt.actor.trim().is_empty()
        || receipt.reason.trim().is_empty()
        || receipt.timestamp.trim().is_empty()
        || receipt.trace_id.trim().is_empty();

    if invalid {
        return Err(FreshnessError::OverrideRequired {
            tier: check.tier.to_string(),
            age_secs: check.revocation_age_secs,
        });
    }

    Ok(())
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
            .expect("should succeed");
        assert!(d.allowed);
        assert!(d.max_age_secs.is_none());
    }

    #[test]
    fn risky_fresh_passes() {
        let d = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 1000), None)
            .expect("should succeed");
        assert!(d.allowed);
        assert_eq!(d.max_age_secs, Some(3600));
    }

    #[test]
    fn risky_stale_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 5000), None)
            .expect_err("should fail");
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn dangerous_fresh_passes() {
        let d = evaluate_freshness(&policy(), &check_action(SafetyTier::Dangerous, 100), None)
            .expect("should succeed");
        assert!(d.allowed);
        assert_eq!(d.max_age_secs, Some(300));
    }

    #[test]
    fn dangerous_stale_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Dangerous, 500), None)
            .expect_err("should fail");
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn override_allows_stale_risky() {
        let d = evaluate_freshness(
            &policy(),
            &check_action(SafetyTier::Risky, 5000),
            Some(&override_receipt()),
        )
        .expect("should succeed");
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
        .expect("should succeed");
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
        .expect("should succeed");
        assert_eq!(
            d.override_receipt
                .as_ref()
                .expect("should have receipt")
                .actor,
            "admin"
        );
    }

    #[test]
    fn at_boundary_denied() {
        // Fail-closed: age exactly at max_age is stale
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 3600), None)
            .expect_err("should fail");
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn risky_boundary_denial_reports_exact_age_and_limit() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 3600), None)
            .expect_err("boundary should fail closed");

        assert_eq!(
            err,
            FreshnessError::StaleFrontier {
                tier: "Risky".to_string(),
                age_secs: 3600,
                max_age_secs: 3600,
            }
        );
    }

    #[test]
    fn dangerous_boundary_denial_reports_exact_age_and_limit() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Dangerous, 300), None)
            .expect_err("boundary should fail closed");

        assert_eq!(
            err,
            FreshnessError::StaleFrontier {
                tier: "Dangerous".to_string(),
                age_secs: 300,
                max_age_secs: 300,
            }
        );
    }

    #[test]
    fn just_over_boundary_denied() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 3601), None)
            .expect_err("should fail");
        assert_eq!(err.code(), "RF_STALE_FRONTIER");
    }

    #[test]
    fn stale_error_display_includes_observed_age_and_max_age() {
        let err = evaluate_freshness(&policy(), &check_action(SafetyTier::Risky, 7200), None)
            .expect_err("stale action should be denied");
        let message = err.to_string();

        assert!(message.contains("Risky action denied"));
        assert!(message.contains("age 7200s"));
        assert!(message.contains("max 3600s"));
    }

    #[test]
    fn dangerous_zero_max_age_fails_closed_even_at_zero_age() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 1,
            dangerous_max_age_secs: 0,
        };

        let err = evaluate_freshness(&p, &check_action(SafetyTier::Dangerous, 0), None)
            .expect_err("zero max age should fail closed at the boundary");

        assert_eq!(
            err,
            FreshnessError::StaleFrontier {
                tier: "Dangerous".to_string(),
                age_secs: 0,
                max_age_secs: 0,
            }
        );
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
        assert_eq!(
            p.validate().expect_err("should fail").code(),
            "RF_POLICY_INVALID"
        );
    }

    #[test]
    fn policy_validate_invalid_dangerous_gt_risky_reason_is_specific() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 100,
            dangerous_max_age_secs: 101,
        };

        let err = p.validate().expect_err("policy should be invalid");

        assert_eq!(
            err,
            FreshnessError::PolicyInvalid {
                reason: "dangerous_max_age must be <= risky_max_age".to_string(),
            }
        );
    }

    #[test]
    fn policy_validate_zero_risky() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 0,
            dangerous_max_age_secs: 0,
        };
        assert_eq!(
            p.validate().expect_err("should fail").code(),
            "RF_POLICY_INVALID"
        );
    }

    #[test]
    fn policy_validate_zero_risky_reason_is_specific() {
        let p = FreshnessPolicy {
            risky_max_age_secs: 0,
            dangerous_max_age_secs: 0,
        };

        let err = p.validate().expect_err("policy should be invalid");

        assert_eq!(
            err,
            FreshnessError::PolicyInvalid {
                reason: "risky_max_age must be > 0".to_string(),
            }
        );
    }

    #[test]
    fn stale_without_override_does_not_emit_decision_record() {
        let err = evaluate_freshness(
            &policy(),
            &check_action(SafetyTier::Dangerous, u64::MAX),
            None,
        )
        .expect_err("stale dangerous action should be denied");

        assert!(matches!(
            err,
            FreshnessError::StaleFrontier {
                tier,
                age_secs: u64::MAX,
                max_age_secs: 300,
            } if tier == "Dangerous"
        ));
    }

    #[test]
    fn decision_has_trace_id() {
        let d = evaluate_freshness(&policy(), &check_action(SafetyTier::Standard, 0), None)
            .expect("should succeed");
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

#[cfg(test)]
mod override_receipt_negative_tests {
    use super::*;

    fn policy() -> FreshnessPolicy {
        FreshnessPolicy {
            risky_max_age_secs: 3600,
            dangerous_max_age_secs: 300,
        }
    }

    fn stale_check(tier: SafetyTier) -> FreshnessCheck {
        FreshnessCheck {
            action_id: "action-a".to_string(),
            tier,
            revocation_age_secs: 7200,
            trace_id: "trace-a".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
        }
    }

    fn receipt() -> OverrideReceipt {
        OverrideReceipt {
            action_id: "action-a".to_string(),
            actor: "operator-a".to_string(),
            reason: "break-glass maintenance".to_string(),
            timestamp: "2026-04-17T00:01:00Z".to_string(),
            trace_id: "trace-a".to_string(),
        }
    }

    fn expect_override_required(err: FreshnessError, tier: SafetyTier, age_secs: u64) {
        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: tier.to_string(),
                age_secs,
            }
        );
    }

    #[test]
    fn stale_override_rejects_mismatched_action_id() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.action_id = "other-action".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_empty_actor() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.actor = String::new();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_actor() {
        let check = stale_check(SafetyTier::Dangerous);
        let mut override_receipt = receipt();
        override_receipt.actor = "   ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }

    #[test]
    fn stale_override_rejects_empty_reason() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.reason = String::new();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_empty_receipt_timestamp() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.timestamp = String::new();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_empty_receipt_trace_id() {
        let check = stale_check(SafetyTier::Dangerous);
        let mut override_receipt = receipt();
        override_receipt.trace_id = String::new();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_reason() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.reason = "   ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_receipt_timestamp() {
        let check = stale_check(SafetyTier::Dangerous);
        let mut override_receipt = receipt();
        override_receipt.timestamp = "\t  ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_receipt_trace_id() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.trace_id = " \n ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_trace_id_mismatch() {
        let check = stale_check(SafetyTier::Dangerous);
        let mut override_receipt = receipt();
        override_receipt.trace_id = "other-trace".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }

    #[test]
    fn stale_override_rejects_empty_action_id_even_when_receipt_matches() {
        let mut check = stale_check(SafetyTier::Risky);
        check.action_id.clear();
        let mut override_receipt = receipt();
        override_receipt.action_id.clear();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_action_id_even_when_receipt_matches() {
        let mut check = stale_check(SafetyTier::Dangerous);
        check.action_id = "   ".to_string();
        let mut override_receipt = receipt();
        override_receipt.action_id = "   ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }

    #[test]
    fn stale_override_rejects_trailing_space_action_id_alias() {
        let check = stale_check(SafetyTier::Risky);
        let mut override_receipt = receipt();
        override_receipt.action_id = "action-a ".to_string();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn standard_tier_drops_invalid_override_receipt_instead_of_recording_bypass() {
        let check = FreshnessCheck {
            tier: SafetyTier::Standard,
            ..stale_check(SafetyTier::Risky)
        };
        let mut override_receipt = receipt();
        override_receipt.trace_id = "other-trace".to_string();

        let decision =
            evaluate_freshness(&policy(), &check, Some(&override_receipt)).expect("standard pass");

        assert!(decision.allowed);
        assert!(decision.override_receipt.is_none());
        assert!(decision.max_age_secs.is_none());
    }

    #[test]
    fn valid_override_still_allows_stale_action() {
        let check = stale_check(SafetyTier::Dangerous);
        let override_receipt = receipt();

        let decision =
            evaluate_freshness(&policy(), &check, Some(&override_receipt)).expect("valid override");

        assert!(decision.allowed);
        assert!(decision.override_receipt.is_some());
    }

    #[test]
    fn stale_override_rejects_empty_check_trace_id() {
        let mut check = stale_check(SafetyTier::Risky);
        check.trace_id = String::new();
        let override_receipt = receipt();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Risky, 7200);
    }

    #[test]
    fn stale_override_rejects_whitespace_check_trace_id() {
        let mut check = stale_check(SafetyTier::Dangerous);
        check.trace_id = "   ".to_string();
        let override_receipt = receipt();

        let err = evaluate_freshness(&policy(), &check, Some(&override_receipt)).unwrap_err();

        expect_override_required(err, SafetyTier::Dangerous, 7200);
    }
}

#[cfg(test)]
mod revocation_freshness_boundary_negative_tests {
    use super::*;

    fn strict_policy_for_boundary_negatives() -> FreshnessPolicy {
        FreshnessPolicy {
            risky_max_age_secs: 10,
            dangerous_max_age_secs: 5,
        }
    }

    fn boundary_check(tier: SafetyTier, age: u64) -> FreshnessCheck {
        FreshnessCheck {
            action_id: "boundary-action".to_string(),
            tier,
            revocation_age_secs: age,
            trace_id: "boundary-trace".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
        }
    }

    fn boundary_receipt() -> OverrideReceipt {
        OverrideReceipt {
            action_id: "boundary-action".to_string(),
            actor: "operator-boundary".to_string(),
            reason: "boundary override".to_string(),
            timestamp: "2026-04-17T00:01:00Z".to_string(),
            trace_id: "boundary-trace".to_string(),
        }
    }

    #[test]
    fn risky_zero_max_age_fails_closed_at_exact_zero_age() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 0,
            dangerous_max_age_secs: 0,
        };

        let err = evaluate_freshness(&policy, &boundary_check(SafetyTier::Risky, 0), None)
            .expect_err("zero max age should fail closed at exact boundary");

        assert_eq!(
            err,
            FreshnessError::StaleFrontier {
                tier: "Risky".to_string(),
                age_secs: 0,
                max_age_secs: 0,
            }
        );
    }

    #[test]
    fn risky_exact_boundary_rejects_invalid_override_receipt() {
        let mut receipt = boundary_receipt();
        receipt.reason.clear();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Risky, 10),
            Some(&receipt),
        )
        .expect_err("invalid override receipt should be rejected at stale boundary");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Risky".to_string(),
                age_secs: 10,
            }
        );
    }

    #[test]
    fn dangerous_exact_boundary_rejects_action_id_case_alias() {
        let mut receipt = boundary_receipt();
        receipt.action_id = "BOUNDARY-ACTION".to_string();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Dangerous, 5),
            Some(&receipt),
        )
        .expect_err("action_id matching must be exact");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Dangerous".to_string(),
                age_secs: 5,
            }
        );
    }

    #[test]
    fn dangerous_stale_rejects_nul_suffixed_action_id_alias() {
        let mut receipt = boundary_receipt();
        receipt.action_id = "boundary-action\0".to_string();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Dangerous, 500),
            Some(&receipt),
        )
        .expect_err("nul-suffixed action alias must not satisfy override");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Dangerous".to_string(),
                age_secs: 500,
            }
        );
    }

    #[test]
    fn risky_stale_rejects_trace_id_with_trailing_space_alias() {
        let mut receipt = boundary_receipt();
        receipt.trace_id = "boundary-trace ".to_string();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Risky, 11),
            Some(&receipt),
        )
        .expect_err("trace_id matching must be exact");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Risky".to_string(),
                age_secs: 11,
            }
        );
    }

    #[test]
    fn risky_stale_rejects_actor_with_carriage_return_only() {
        let mut receipt = boundary_receipt();
        receipt.actor = "\r".to_string();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Risky, 11),
            Some(&receipt),
        )
        .expect_err("blank actor should not authorize stale override");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Risky".to_string(),
                age_secs: 11,
            }
        );
    }

    #[test]
    fn dangerous_stale_rejects_reason_with_newline_only() {
        let mut receipt = boundary_receipt();
        receipt.reason = "\n".to_string();

        let err = evaluate_freshness(
            &strict_policy_for_boundary_negatives(),
            &boundary_check(SafetyTier::Dangerous, 6),
            Some(&receipt),
        )
        .expect_err("blank reason should not authorize stale override");

        assert_eq!(
            err,
            FreshnessError::OverrideRequired {
                tier: "Dangerous".to_string(),
                age_secs: 6,
            }
        );
    }

    #[test]
    fn policy_validation_reports_dangerous_over_risky_before_zero_risky() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 0,
            dangerous_max_age_secs: 1,
        };

        let err = policy.validate().expect_err("policy should fail closed");

        assert_eq!(
            err,
            FreshnessError::PolicyInvalid {
                reason: "dangerous_max_age must be <= risky_max_age".to_string(),
            }
        );
    }
}
