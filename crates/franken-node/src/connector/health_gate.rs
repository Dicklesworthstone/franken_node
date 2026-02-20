//! Health gate for connector lifecycle transitions.
//!
//! A health gate is a set of preconditions that must pass before a connector
//! can transition to the `Active` state. Each check has a name, a required
//! flag, and a pass/fail status.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, EpochRejectionReason, ValidityWindowPolicy,
    check_artifact_epoch,
};

/// Stable event codes for epoch-scoped validity checks.
pub mod epoch_event_codes {
    pub const EPOCH_CHECK_PASSED: &str = "EPV-001";
    pub const FUTURE_EPOCH_REJECTED: &str = "EPV-002";
    pub const STALE_EPOCH_REJECTED: &str = "EPV-003";
    pub const EPOCH_SCOPE_LOGGED: &str = "EPV-004";
}

/// A single health check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub required: bool,
    pub passed: bool,
    pub message: Option<String>,
}

/// The aggregate result of running all health checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGateResult {
    pub checks: Vec<HealthCheck>,
    pub gate_passed: bool,
}

impl HealthGateResult {
    /// Evaluate a set of health checks and determine if the gate passes.
    ///
    /// The gate passes if and only if all required checks pass.
    pub fn evaluate(checks: Vec<HealthCheck>) -> Self {
        let gate_passed = checks.iter().filter(|c| c.required).all(|c| c.passed);
        Self {
            checks,
            gate_passed,
        }
    }

    /// Returns the names of all failing required checks.
    pub fn failing_required(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| c.required && !c.passed)
            .map(|c| c.name.as_str())
            .collect()
    }
}

/// Error returned when a health gate blocks activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGateError {
    pub code: String,
    pub failing_checks: Vec<String>,
    pub message: String,
}

impl HealthGateError {
    pub fn from_result(result: &HealthGateResult) -> Option<Self> {
        if result.gate_passed {
            return None;
        }
        let failing: Vec<String> = result
            .failing_required()
            .iter()
            .map(|s| s.to_string())
            .collect();
        Some(Self {
            code: "HEALTH_GATE_FAILED".to_string(),
            failing_checks: failing.clone(),
            message: format!(
                "Health gate failed: {} required check(s) did not pass: {}",
                failing.len(),
                failing.join(", ")
            ),
        })
    }
}

impl fmt::Display for HealthGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for HealthGateError {}

/// Epoch-scoped health-gate policy artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopedHealthPolicy {
    pub policy_id: String,
    pub policy_epoch: ControlEpoch,
    pub checks: Vec<HealthCheck>,
    pub trace_id: String,
}

impl EpochScopedHealthPolicy {
    #[must_use]
    pub fn new(
        policy_id: String,
        policy_epoch: ControlEpoch,
        checks: Vec<HealthCheck>,
        trace_id: String,
    ) -> Self {
        Self {
            policy_id,
            policy_epoch,
            checks,
            trace_id,
        }
    }
}

/// Structured epoch-scope log for accepted high-impact operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopeLog {
    pub event_code: String,
    pub artifact_type: String,
    pub artifact_id: String,
    pub artifact_epoch: ControlEpoch,
    pub current_epoch: ControlEpoch,
    pub trace_id: String,
}

impl EpochScopeLog {
    fn for_health_policy(
        artifact_id: &str,
        artifact_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: epoch_event_codes::EPOCH_SCOPE_LOGGED.to_string(),
            artifact_type: "health_gate_policy".to_string(),
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch,
            trace_id: trace_id.to_string(),
        }
    }
}

/// Result of evaluating an epoch-scoped health policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopedHealthResult {
    pub epoch_check_event_code: String,
    pub gate_result: HealthGateResult,
    pub epoch_event: EpochArtifactEvent,
    pub scope_log: EpochScopeLog,
}

/// Error returned when epoch-scoped policy validation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code")]
pub enum EpochHealthGateError {
    #[serde(rename = "EPV-002")]
    FutureEpochRejected { rejection: EpochRejection },
    #[serde(rename = "EPV-003")]
    StaleEpochRejected { rejection: EpochRejection },
}

impl EpochHealthGateError {
    fn from_rejection(rejection: EpochRejection) -> Self {
        match rejection.rejection_reason {
            EpochRejectionReason::FutureEpoch => Self::FutureEpochRejected { rejection },
            EpochRejectionReason::ExpiredEpoch => Self::StaleEpochRejected { rejection },
        }
    }

    #[must_use]
    pub fn rejection(&self) -> &EpochRejection {
        match self {
            Self::FutureEpochRejected { rejection } | Self::StaleEpochRejected { rejection } => {
                rejection
            }
        }
    }
}

impl fmt::Display for EpochHealthGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rejection = self.rejection();
        write!(
            f,
            "{}: artifact={} artifact_epoch={} current_epoch={} reason={}",
            rejection.code(),
            rejection.artifact_id,
            rejection.artifact_epoch.value(),
            rejection.current_epoch.value(),
            rejection.code()
        )
    }
}

impl std::error::Error for EpochHealthGateError {}

/// Evaluate a health gate only after canonical epoch-window validation.
pub fn evaluate_epoch_scoped_policy(
    policy: &EpochScopedHealthPolicy,
    validity_policy: &ValidityWindowPolicy,
) -> Result<EpochScopedHealthResult, EpochHealthGateError> {
    check_artifact_epoch(
        &policy.policy_id,
        policy.policy_epoch,
        validity_policy,
        &policy.trace_id,
    )
    .map_err(EpochHealthGateError::from_rejection)?;

    let gate_result = HealthGateResult::evaluate(policy.checks.clone());
    let current_epoch = validity_policy.current_epoch();

    Ok(EpochScopedHealthResult {
        epoch_check_event_code: epoch_event_codes::EPOCH_CHECK_PASSED.to_string(),
        gate_result,
        epoch_event: EpochArtifactEvent::accepted(
            &policy.policy_id,
            policy.policy_epoch,
            current_epoch,
            &policy.trace_id,
        ),
        scope_log: EpochScopeLog::for_health_policy(
            &policy.policy_id,
            policy.policy_epoch,
            current_epoch,
            &policy.trace_id,
        ),
    })
}

/// The four standard health checks per the specification.
pub fn standard_checks(
    liveness: bool,
    readiness: bool,
    config_valid: bool,
    resource_ok: bool,
) -> Vec<HealthCheck> {
    vec![
        HealthCheck {
            name: "liveness".to_string(),
            required: true,
            passed: liveness,
            message: None,
        },
        HealthCheck {
            name: "readiness".to_string(),
            required: true,
            passed: readiness,
            message: None,
        },
        HealthCheck {
            name: "config_valid".to_string(),
            required: true,
            passed: config_valid,
            message: None,
        },
        HealthCheck {
            name: "resource_ok".to_string(),
            required: false,
            passed: resource_ok,
            message: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_pass_gate_passes() {
        let checks = standard_checks(true, true, true, true);
        let result = HealthGateResult::evaluate(checks);
        assert!(result.gate_passed);
        assert!(result.failing_required().is_empty());
    }

    #[test]
    fn optional_fail_gate_still_passes() {
        let checks = standard_checks(true, true, true, false);
        let result = HealthGateResult::evaluate(checks);
        assert!(result.gate_passed);
    }

    #[test]
    fn required_fail_gate_fails() {
        let checks = standard_checks(true, false, true, true);
        let result = HealthGateResult::evaluate(checks);
        assert!(!result.gate_passed);
        assert_eq!(result.failing_required(), vec!["readiness"]);
    }

    #[test]
    fn multiple_required_fail() {
        let checks = standard_checks(false, false, true, true);
        let result = HealthGateResult::evaluate(checks);
        assert!(!result.gate_passed);
        assert_eq!(result.failing_required().len(), 2);
    }

    #[test]
    fn error_from_failing_result() {
        let checks = standard_checks(true, false, true, true);
        let result = HealthGateResult::evaluate(checks);
        let err = HealthGateError::from_result(&result).unwrap();
        assert_eq!(err.code, "HEALTH_GATE_FAILED");
        assert!(err.failing_checks.contains(&"readiness".to_string()));
    }

    #[test]
    fn no_error_from_passing_result() {
        let checks = standard_checks(true, true, true, true);
        let result = HealthGateResult::evaluate(checks);
        assert!(HealthGateError::from_result(&result).is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let checks = standard_checks(true, true, true, false);
        let result = HealthGateResult::evaluate(checks);
        let json = serde_json::to_string(&result).unwrap();
        let parsed: HealthGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn epoch_scoped_policy_accepts_current_epoch() {
        let policy = EpochScopedHealthPolicy::new(
            "health-policy-1".to_string(),
            ControlEpoch::new(7),
            standard_checks(true, true, true, true),
            "trace-hg-accept".to_string(),
        );
        let validity = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let result = evaluate_epoch_scoped_policy(&policy, &validity).unwrap();
        assert_eq!(
            result.epoch_check_event_code,
            epoch_event_codes::EPOCH_CHECK_PASSED
        );
        assert_eq!(
            result.scope_log.event_code,
            epoch_event_codes::EPOCH_SCOPE_LOGGED
        );
        assert_eq!(result.scope_log.artifact_epoch, ControlEpoch::new(7));
    }

    #[test]
    fn epoch_scoped_policy_rejects_future_epoch() {
        let policy = EpochScopedHealthPolicy::new(
            "health-policy-future".to_string(),
            ControlEpoch::new(9),
            standard_checks(true, true, true, true),
            "trace-hg-future".to_string(),
        );
        let validity = ValidityWindowPolicy::new(ControlEpoch::new(8), 2);

        let err = evaluate_epoch_scoped_policy(&policy, &validity).unwrap_err();
        assert!(matches!(
            err,
            EpochHealthGateError::FutureEpochRejected { .. }
        ));
    }

    #[test]
    fn epoch_scoped_policy_rejects_stale_epoch() {
        let policy = EpochScopedHealthPolicy::new(
            "health-policy-stale".to_string(),
            ControlEpoch::new(2),
            standard_checks(true, true, true, true),
            "trace-hg-stale".to_string(),
        );
        let validity = ValidityWindowPolicy::new(ControlEpoch::new(8), 2);

        let err = evaluate_epoch_scoped_policy(&policy, &validity).unwrap_err();
        assert!(matches!(
            err,
            EpochHealthGateError::StaleEpochRejected { .. }
        ));
    }
}
