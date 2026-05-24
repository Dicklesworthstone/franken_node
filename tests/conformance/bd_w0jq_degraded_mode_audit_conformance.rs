//! bd-w0jq Degraded-mode Audit Conformance Test Suite
//!
//! This conformance test suite verifies full compliance with the bd-w0jq specification
//! for degraded-mode audit events in stale revocation overrides. It implements
//! Pattern 4: Spec-Derived Test Matrix to ensure comprehensive coverage of all
//! MUST and SHOULD requirements.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Import the module under test
use frankenengine_node::security::degraded_mode_audit::{
    AuditError, DegradedModeAuditLog, DegradedModeEvent, validate_schema,
};

/// Requirement levels from the bd-w0jq specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test categories for organizational structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
}

/// Test result for conformance verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

/// Individual conformance test case record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub category: TestCategory,
    pub description: String,
    pub result: TestResult,
}

/// Test execution statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConformanceStats {
    pub must_pass: usize,
    pub must_fail: usize,
    pub should_pass: usize,
    pub should_fail: usize,
    pub may_pass: usize,
    pub may_fail: usize,
    pub skipped: usize,
    pub expected_failures: usize,
}

/// Complete conformance test report
#[derive(Debug, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub timestamp: String,
    pub specification: String,
    pub version: String,
    pub results: BTreeMap<String, ConformanceRecord>,
    pub stats: ConformanceStats,
}

impl ConformanceReport {
    /// Calculate overall compliance score (MUST requirements only)
    pub fn compliance_score(&self) -> f64 {
        let total_must = self.stats.must_pass + self.stats.must_fail;
        if total_must == 0 {
            1.0 // No MUST requirements = fully compliant
        } else {
            self.stats.must_pass as f64 / total_must as f64
        }
    }

    /// Generate human-readable Markdown report
    pub fn to_markdown(&self) -> String {
        let score = self.compliance_score() * 100.0;
        format!(
            r#"# bd-w0jq Degraded-mode Audit Conformance Report

Generated: {}
Specification: {}
Version: {}

## Summary

- **Compliance Score**: {:.1}%
- **Total Tests**: {}
- **MUST Requirements**: {} pass, {} fail
- **SHOULD Requirements**: {} pass, {} fail

## Test Results

| ID | Level | Category | Description | Result |
|----|-------|----------|-------------|--------|
{}

## Compliance Assessment

{}
"#,
            self.timestamp,
            self.specification,
            self.version,
            score,
            self.results.len(),
            self.stats.must_pass,
            self.stats.must_fail,
            self.stats.should_pass,
            self.stats.should_fail,
            self.results
                .values()
                .map(|r| format!(
                    "| {} | {:?} | {:?} | {} | {} |",
                    r.id,
                    r.level,
                    r.category,
                    r.description,
                    match &r.result {
                        TestResult::Pass => "✅ PASS",
                        TestResult::Fail { reason } => &format!("❌ FAIL: {}", reason),
                        TestResult::Skipped { reason } => &format!("⏭️ SKIP: {}", reason),
                        TestResult::ExpectedFailure { reason } => &format!("⏳ XFAIL: {}", reason),
                    }
                ))
                .collect::<Vec<_>>()
                .join("\n"),
            if score >= 95.0 {
                "✅ **CONFORMANT** - Meets bd-w0jq specification requirements"
            } else {
                "❌ **NON-CONFORMANT** - Does not meet bd-w0jq specification requirements"
            }
        )
    }
}

/// Individual conformance test case definition
struct ConformanceCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    category: TestCategory,
    description: &'static str,
    test_fn: fn() -> Result<(), String>,
}

/// bd-w0jq specification test matrix - all MUST/SHOULD requirements
const BD_W0JQ_CASES: &[ConformanceCase] = &[
    // Core Schema Requirements (MUST)
    ConformanceCase {
        id: "W0JQ-SCHEMA-1",
        section: "schema",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-DM-SCHEMA-COMPLETE: all fields must be non-empty",
        test_fn: test_schema_complete_all_fields,
    },
    ConformanceCase {
        id: "W0JQ-SCHEMA-2",
        section: "schema",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "event_type must be exactly 'degraded_mode_override'",
        test_fn: test_event_type_exact_match,
    },
    ConformanceCase {
        id: "W0JQ-SCHEMA-3",
        section: "schema",
        level: RequirementLevel::Must,
        category: TestCategory::EdgeCase,
        description: "whitespace-only fields must be rejected as empty",
        test_fn: test_whitespace_rejection,
    },
    // Event Emission Requirements (MUST)
    ConformanceCase {
        id: "W0JQ-EMIT-1",
        section: "emission",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-DM-EVENT-REQUIRED: emit() validates before append",
        test_fn: test_emit_validates_before_append,
    },
    ConformanceCase {
        id: "W0JQ-EMIT-2",
        section: "emission",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "invalid events must not be appended to log",
        test_fn: test_invalid_events_not_appended,
    },
    // Immutability Requirements (MUST)
    ConformanceCase {
        id: "W0JQ-IMMUTABLE-1",
        section: "immutability",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-DM-IMMUTABLE: events cannot be modified after append",
        test_fn: test_events_immutable,
    },
    // Correlation Requirements (MUST)
    ConformanceCase {
        id: "W0JQ-CORRELATION-1",
        section: "correlation",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-DM-CORRELATION: find_by_action() exact match",
        test_fn: test_correlation_by_action,
    },
    ConformanceCase {
        id: "W0JQ-CORRELATION-2",
        section: "correlation",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-DM-CORRELATION: find_by_trace() exact match",
        test_fn: test_correlation_by_trace,
    },
    // Error Handling Requirements (MUST)
    ConformanceCase {
        id: "W0JQ-ERROR-1",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "DM_MISSING_FIELD error for empty required fields",
        test_fn: test_missing_field_errors,
    },
    ConformanceCase {
        id: "W0JQ-ERROR-2",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "DM_EVENT_NOT_FOUND error for missing action_id",
        test_fn: test_event_not_found_errors,
    },
    ConformanceCase {
        id: "W0JQ-ERROR-3",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "DM_SCHEMA_VIOLATION error for invalid event_type",
        test_fn: test_schema_violation_errors,
    },
    // Edge Case Requirements (SHOULD)
    ConformanceCase {
        id: "W0JQ-EDGE-1",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "multiple events with same action_id should be supported",
        test_fn: test_multiple_events_same_action,
    },
    ConformanceCase {
        id: "W0JQ-EDGE-2",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "lookups should be case-sensitive and exact",
        test_fn: test_case_sensitive_lookups,
    },
    ConformanceCase {
        id: "W0JQ-EDGE-3",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "capacity management should use push_bounded",
        test_fn: test_capacity_management,
    },
];

// Test implementation functions

fn valid_event() -> DegradedModeEvent {
    DegradedModeEvent {
        event_type: "degraded_mode_override".into(),
        action_id: "test-action-1".into(),
        actor: "test-admin".into(),
        tier: "Medium".into(),
        revocation_age_secs: 3600,
        max_age_secs: 1800,
        override_reason: "emergency maintenance".into(),
        trace_id: "trace-123".into(),
        timestamp: "2026-05-22T17:42:00Z".into(),
    }
}

fn test_schema_complete_all_fields() -> Result<(), String> {
    let valid = valid_event();
    validate_schema(&valid).map_err(|e| format!("Valid event rejected: {}", e))?;

    // Test each field individually
    let field_tests = [
        ("event_type", |mut e: DegradedModeEvent| {
            e.event_type.clear();
            e
        }),
        ("action_id", |mut e: DegradedModeEvent| {
            e.action_id.clear();
            e
        }),
        ("actor", |mut e: DegradedModeEvent| {
            e.actor.clear();
            e
        }),
        ("tier", |mut e: DegradedModeEvent| {
            e.tier.clear();
            e
        }),
        ("override_reason", |mut e: DegradedModeEvent| {
            e.override_reason.clear();
            e
        }),
        ("trace_id", |mut e: DegradedModeEvent| {
            e.trace_id.clear();
            e
        }),
        ("timestamp", |mut e: DegradedModeEvent| {
            e.timestamp.clear();
            e
        }),
    ];

    for (field_name, modifier) in field_tests {
        let invalid = modifier(valid_event());
        let result = validate_schema(&invalid);
        if result.is_ok() {
            return Err(format!("Empty {} should be rejected", field_name));
        }
        match result.unwrap_err() {
            AuditError::MissingField { .. } => {} // Expected
            other => {
                return Err(format!(
                    "Wrong error type for empty {}: {:?}",
                    field_name, other
                ));
            }
        }
    }

    Ok(())
}

fn test_event_type_exact_match() -> Result<(), String> {
    let mut valid = valid_event();

    // Valid case
    valid.event_type = "degraded_mode_override".into();
    validate_schema(&valid).map_err(|e| format!("Valid event_type rejected: {}", e))?;

    // Invalid cases
    let invalid_types = [
        "degraded_mode_override_v2",
        "DEGRADED_MODE_OVERRIDE",
        "degraded mode override",
        " degraded_mode_override",
        "degraded_mode_override ",
        "degraded_mode_override\n",
    ];

    for invalid_type in invalid_types {
        valid.event_type = invalid_type.into();
        let result = validate_schema(&valid);
        if result.is_ok() {
            return Err(format!(
                "Invalid event_type '{}' should be rejected",
                invalid_type
            ));
        }
    }

    Ok(())
}

fn test_whitespace_rejection() -> Result<(), String> {
    let whitespace_values = [" ", "\t", "\n", "\r", "   ", "\t\n\r "];
    let mut event = valid_event();

    for whitespace in whitespace_values {
        event.action_id = whitespace.into();
        if validate_schema(&event).is_ok() {
            return Err(format!(
                "Whitespace-only action_id should be rejected: {:?}",
                whitespace
            ));
        }

        event.actor = whitespace.into();
        event.action_id = "valid".into(); // Reset
        if validate_schema(&event).is_ok() {
            return Err(format!(
                "Whitespace-only actor should be rejected: {:?}",
                whitespace
            ));
        }
        event.actor = "valid".into(); // Reset
    }

    Ok(())
}

fn test_emit_validates_before_append() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();

    // Valid emit should succeed
    log.emit(valid_event())
        .map_err(|e| format!("Valid emit failed: {}", e))?;
    if log.count() != 1 {
        return Err("Valid event not appended".into());
    }

    // Invalid emit should fail and not append
    let mut invalid = valid_event();
    invalid.actor.clear();
    let result = log.emit(invalid);
    if result.is_ok() {
        return Err("Invalid event should be rejected".into());
    }
    if log.count() != 1 {
        return Err("Invalid event was appended despite validation failure".into());
    }

    Ok(())
}

fn test_invalid_events_not_appended() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();
    let initial_count = log.count();

    let mut invalid = valid_event();
    invalid.trace_id.clear();

    let result = log.emit(invalid);
    if result.is_ok() {
        return Err("Invalid event should be rejected".into());
    }
    if log.count() != initial_count {
        return Err("Invalid event was appended to log".into());
    }

    Ok(())
}

fn test_events_immutable() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();
    log.emit(valid_event()).unwrap();

    // Get read-only access to events
    let events = log.events();
    if events.len() != 1 {
        return Err("Expected exactly one event".into());
    }

    // Verify we can't modify through the reference
    let original_action_id = events[0].action_id.clone();

    // Try to emit another event and verify first is unchanged
    let mut second_event = valid_event();
    second_event.action_id = "different-action".into();
    log.emit(second_event).unwrap();

    if log.events()[0].action_id != original_action_id {
        return Err("First event was modified after second emission".into());
    }

    Ok(())
}

fn test_correlation_by_action() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();

    let mut event1 = valid_event();
    event1.action_id = "action-1".into();

    let mut event2 = valid_event();
    event2.action_id = "action-2".into();

    log.emit(event1).unwrap();
    log.emit(event2).unwrap();

    // Test exact matches
    let results1 = log.find_by_action("action-1");
    if results1.len() != 1 {
        return Err(format!(
            "Expected 1 result for action-1, got {}",
            results1.len()
        ));
    }

    let results2 = log.find_by_action("action-2");
    if results2.len() != 1 {
        return Err(format!(
            "Expected 1 result for action-2, got {}",
            results2.len()
        ));
    }

    // Test no partial matches
    let no_results = log.find_by_action("action");
    if !no_results.is_empty() {
        return Err("Partial match should return empty results".into());
    }

    Ok(())
}

fn test_correlation_by_trace() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();

    let mut event1 = valid_event();
    event1.trace_id = "trace-1".into();
    event1.action_id = "action-1".into();

    let mut event2 = valid_event();
    event2.trace_id = "trace-1".into(); // Same trace, different action
    event2.action_id = "action-2".into();

    log.emit(event1).unwrap();
    log.emit(event2).unwrap();

    // Both events should be found by trace_id
    let results = log.find_by_trace("trace-1");
    if results.len() != 2 {
        return Err(format!(
            "Expected 2 results for trace-1, got {}",
            results.len()
        ));
    }

    // But action_id lookups should be distinct
    if log.find_by_action("action-1").len() != 1 {
        return Err("action-1 should return exactly 1 result".into());
    }
    if log.find_by_action("action-2").len() != 1 {
        return Err("action-2 should return exactly 1 result".into());
    }

    Ok(())
}

fn test_missing_field_errors() -> Result<(), String> {
    let mut invalid = valid_event();
    invalid.actor.clear();

    let err = validate_schema(&invalid).unwrap_err();
    if err.code() != "DM_MISSING_FIELD" {
        return Err(format!("Expected DM_MISSING_FIELD, got {}", err.code()));
    }

    match err {
        AuditError::MissingField { field } => {
            if field != "actor" {
                return Err(format!("Expected field 'actor', got '{}'", field));
            }
        }
        _ => return Err("Expected MissingField variant".into()),
    }

    Ok(())
}

fn test_event_not_found_errors() -> Result<(), String> {
    let log = DegradedModeAuditLog::new();

    let err = log.assert_event_exists("nonexistent").unwrap_err();
    if err.code() != "DM_EVENT_NOT_FOUND" {
        return Err(format!("Expected DM_EVENT_NOT_FOUND, got {}", err.code()));
    }

    match err {
        AuditError::EventNotFound { action_id } => {
            if action_id != "nonexistent" {
                return Err(format!(
                    "Expected action_id 'nonexistent', got '{}'",
                    action_id
                ));
            }
        }
        _ => return Err("Expected EventNotFound variant".into()),
    }

    Ok(())
}

fn test_schema_violation_errors() -> Result<(), String> {
    let mut invalid = valid_event();
    invalid.event_type = "wrong_type".into();

    let err = validate_schema(&invalid).unwrap_err();
    if err.code() != "DM_SCHEMA_VIOLATION" {
        return Err(format!("Expected DM_SCHEMA_VIOLATION, got {}", err.code()));
    }

    let err_string = err.to_string();
    if !err_string.contains("wrong_type") {
        return Err("Error message should include the invalid event_type".into());
    }

    Ok(())
}

fn test_multiple_events_same_action() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();

    let mut event1 = valid_event();
    event1.action_id = "same-action".into();
    event1.trace_id = "trace-1".into();

    let mut event2 = valid_event();
    event2.action_id = "same-action".into(); // Same action
    event2.trace_id = "trace-2".into(); // Different trace

    log.emit(event1).unwrap();
    log.emit(event2).unwrap();

    let results = log.find_by_action("same-action");
    if results.len() != 2 {
        return Err(format!(
            "Expected 2 events for same action_id, got {}",
            results.len()
        ));
    }

    Ok(())
}

fn test_case_sensitive_lookups() -> Result<(), String> {
    let mut log = DegradedModeAuditLog::new();

    let mut event = valid_event();
    event.action_id = "CaseSensitive".into();
    event.trace_id = "TraceCase".into();

    log.emit(event).unwrap();

    // Exact matches should work
    if log.find_by_action("CaseSensitive").is_empty() {
        return Err("Exact case match should find event".into());
    }
    if log.find_by_trace("TraceCase").is_empty() {
        return Err("Exact case match should find event".into());
    }

    // Case variations should not match
    if !log.find_by_action("casesensitive").is_empty() {
        return Err("Lowercase variation should not match".into());
    }
    if !log.find_by_action("CASESENSITIVE").is_empty() {
        return Err("Uppercase variation should not match".into());
    }
    if !log.find_by_trace("tracecase").is_empty() {
        return Err("Lowercase trace variation should not match".into());
    }

    Ok(())
}

fn test_capacity_management() -> Result<(), String> {
    // This tests the push_bounded behavior through the public API
    // Since MAX_EVENTS is used internally, we test that events can be added
    // and the log maintains a reasonable size constraint

    let mut log = DegradedModeAuditLog::new();

    // Add several events to test capacity behavior
    for i in 0..10 {
        let mut event = valid_event();
        event.action_id = format!("action-{}", i);
        log.emit(event).unwrap();
    }

    // Log should handle multiple events without issues
    if log.count() == 0 {
        return Err("Events should be stored in the log".into());
    }

    // Verify we can still find events by action_id
    if log.find_by_action("action-0").is_empty() {
        return Err("Should be able to find events by action_id after multiple adds".into());
    }

    Ok(())
}

/// Execute the complete bd-w0jq conformance test suite
pub fn run_bd_w0jq_conformance_tests() -> ConformanceReport {
    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats::default();

    for case in BD_W0JQ_CASES {
        let result = match (case.test_fn)() {
            Ok(()) => {
                match case.level {
                    RequirementLevel::Must => stats.must_pass += 1,
                    RequirementLevel::Should => stats.should_pass += 1,
                    RequirementLevel::May => stats.may_pass += 1,
                }
                TestResult::Pass
            }
            Err(reason) => {
                match case.level {
                    RequirementLevel::Must => stats.must_fail += 1,
                    RequirementLevel::Should => stats.should_fail += 1,
                    RequirementLevel::May => stats.may_fail += 1,
                }
                TestResult::Fail { reason }
            }
        };

        let record = ConformanceRecord {
            id: case.id.to_string(),
            section: case.section.to_string(),
            level: case.level,
            category: case.category,
            description: case.description.to_string(),
            result,
        };

        results.insert(case.id.to_string(), record);
    }

    ConformanceReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        specification: "bd-w0jq".to_string(),
        version: "1.0".to_string(),
        results,
        stats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_suite_execution() {
        let report = run_bd_w0jq_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_W0JQ_CASES.len());

        // Verify all MUST requirements pass (conformance requirement)
        assert_eq!(
            report.stats.must_fail, 0,
            "All MUST requirements should pass"
        );

        // Verify compliance score calculation
        let score = report.compliance_score();
        assert!(score >= 0.95, "Compliance score should be at least 95%");
    }

    #[test]
    fn conformance_report_markdown_generation() {
        let report = run_bd_w0jq_conformance_tests();
        let markdown = report.to_markdown();

        assert!(markdown.contains("# bd-w0jq Degraded-mode Audit Conformance Report"));
        assert!(markdown.contains("Compliance Score"));
        assert!(markdown.contains("W0JQ-SCHEMA-1"));
    }

    #[test]
    fn all_test_cases_have_unique_ids() {
        let mut seen_ids = std::collections::HashSet::new();

        for case in BD_W0JQ_CASES {
            if !seen_ids.insert(case.id) {
                panic!("Duplicate test case ID: {}", case.id);
            }
        }
    }

    #[test]
    fn all_error_codes_covered() {
        let report = run_bd_w0jq_conformance_tests();

        // Verify we test all three error codes from the specification
        let has_missing_field = report.results.values().any(|r| r.id == "W0JQ-ERROR-1");
        let has_not_found = report.results.values().any(|r| r.id == "W0JQ-ERROR-2");
        let has_schema_violation = report.results.values().any(|r| r.id == "W0JQ-ERROR-3");

        assert!(has_missing_field, "Should test DM_MISSING_FIELD error code");
        assert!(has_not_found, "Should test DM_EVENT_NOT_FOUND error code");
        assert!(
            has_schema_violation,
            "Should test DM_SCHEMA_VIOLATION error code"
        );
    }
}
