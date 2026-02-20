//! Health gate for connector lifecycle transitions.
//!
//! A health gate is a set of preconditions that must pass before a connector
//! can transition to the `Active` state. Each check has a name, a required
//! flag, and a pass/fail status.

use serde::{Deserialize, Serialize};
use std::fmt;

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
        let gate_passed = checks
            .iter()
            .filter(|c| c.required)
            .all(|c| c.passed);
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
}
