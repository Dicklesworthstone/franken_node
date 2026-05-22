//! Core traits and types for MMR conformance testing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Main trait for MMR conformance tests
pub trait ConformanceTest: Send + Sync {
    /// Unique test identifier (e.g., "R1.1")
    fn id(&self) -> &str;

    /// Human-readable test name
    fn name(&self) -> &str;

    /// Test category for organization
    fn category(&self) -> TestCategory;

    /// Requirement level from specification
    fn requirement_level(&self) -> RequirementLevel;

    /// Specification section reference
    fn spec_section(&self) -> &str;

    /// Description of what this test validates
    fn description(&self) -> &str;

    /// Execute the conformance test
    fn run(&self, ctx: &super::TestContext) -> TestResult;

    /// Optional setup before running the test
    fn setup(&self, _ctx: &mut super::TestContext) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Optional cleanup after running the test
    fn cleanup(&self, _ctx: &mut super::TestContext) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// Test categories for organization and filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    /// Basic unit-level functionality
    Unit,
    /// Integration between components
    Integration,
    /// Edge cases and boundary conditions
    EdgeCase,
    /// Performance and scalability
    Performance,
    /// Security-specific validations
    Security,
    /// Error handling and failure modes
    ErrorHandling,
    /// Serialization and data format
    Serialization,
}

impl fmt::Display for TestCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit => write!(f, "Unit"),
            Self::Integration => write!(f, "Integration"),
            Self::EdgeCase => write!(f, "EdgeCase"),
            Self::Performance => write!(f, "Performance"),
            Self::Security => write!(f, "Security"),
            Self::ErrorHandling => write!(f, "ErrorHandling"),
            Self::Serialization => write!(f, "Serialization"),
        }
    }
}

/// Requirement levels from RFC 2119
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RequirementLevel {
    /// MUST / REQUIRED / SHALL
    Must,
    /// SHOULD / RECOMMENDED
    Should,
    /// MAY / OPTIONAL
    May,
}

impl fmt::Display for RequirementLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Must => write!(f, "MUST"),
            Self::Should => write!(f, "SHOULD"),
            Self::May => write!(f, "MAY"),
        }
    }
}

/// Test execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    /// Test passed successfully
    Pass,
    /// Test failed with specific reason
    Fail {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
    },
    /// Test was skipped with reason
    Skipped { reason: String },
    /// Expected failure (known divergence from spec)
    ExpectedFailure {
        reason: String,
        /// Reference to DISCREPANCIES.md entry
        discrepancy_id: String,
    },
    /// Test encountered an internal error
    Error { reason: String },
}

impl TestResult {
    /// Create a passing result
    pub fn pass() -> Self {
        Self::Pass
    }

    /// Create a failing result with reason
    pub fn fail(reason: impl Into<String>) -> Self {
        Self::Fail {
            reason: reason.into(),
            details: None,
        }
    }

    /// Create a failing result with reason and structured details
    pub fn fail_with_details(reason: impl Into<String>, details: serde_json::Value) -> Self {
        Self::Fail {
            reason: reason.into(),
            details: Some(details),
        }
    }

    /// Create a skipped result
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self::Skipped { reason: reason.into() }
    }

    /// Create an expected failure result
    pub fn expected_failure(reason: impl Into<String>, discrepancy_id: impl Into<String>) -> Self {
        Self::ExpectedFailure {
            reason: reason.into(),
            discrepancy_id: discrepancy_id.into(),
        }
    }

    /// Create an error result
    pub fn error(reason: impl Into<String>) -> Self {
        Self::Error { reason: reason.into() }
    }

    /// Check if this result represents a passing test
    pub fn is_passing(&self) -> bool {
        matches!(self, Self::Pass | Self::ExpectedFailure { .. })
    }

    /// Check if this result represents a test failure
    pub fn is_failing(&self) -> bool {
        matches!(self, Self::Fail { .. } | Self::Error { .. })
    }

    /// Check if this result represents a skipped test
    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reason, .. } => write!(f, "FAIL: {}", reason),
            Self::Skipped { reason } => write!(f, "SKIP: {}", reason),
            Self::ExpectedFailure { reason, discrepancy_id } => {
                write!(f, "XFAIL ({}): {}", discrepancy_id, reason)
            }
            Self::Error { reason } => write!(f, "ERROR: {}", reason),
        }
    }
}

/// Test execution statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub expected_failures: usize,
    pub errors: usize,

    // Breakdown by requirement level
    pub must_total: usize,
    pub must_passed: usize,
    pub should_total: usize,
    pub should_passed: usize,
    pub may_total: usize,
    pub may_passed: usize,
}

impl TestStats {
    /// Calculate pass rate for MUST requirements
    pub fn must_pass_rate(&self) -> f64 {
        if self.must_total == 0 {
            1.0
        } else {
            self.must_passed as f64 / self.must_total as f64
        }
    }

    /// Calculate overall pass rate
    pub fn overall_pass_rate(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.passed + self.expected_failures) as f64 / self.total as f64
        }
    }

    /// Check if conformance requirements are met (≥95% MUST coverage)
    pub fn is_conformant(&self) -> bool {
        self.must_pass_rate() >= 0.95
    }
}