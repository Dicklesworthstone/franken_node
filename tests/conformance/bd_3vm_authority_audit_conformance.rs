//! bd-3vm Ambient Authority Audit Conformance Test Suite
//!
//! This conformance test suite verifies full compliance with the bd-3vm specification
//! for ambient authority audit gates in security-critical modules. It implements
//! Pattern 4: Spec-Derived Test Matrix to ensure comprehensive coverage of all
//! MUST and SHOULD requirements.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// Import the module under test
use frankenengine_node::runtime::authority_audit::{
    AuthorityAuditGuard, CapabilityContext, Capability, SecurityCriticalInventory,
    SecurityCriticalModule, RiskLevel, AmbientAuthorityViolation, AuditReport,
    generate_audit_report, error_codes, event_codes, invariants, SCHEMA_VERSION
};

/// Requirement levels from the bd-3vm specification
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
            r#"# bd-3vm Ambient Authority Audit Conformance Report

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
                "✅ **CONFORMANT** - Meets bd-3vm specification requirements"
            } else {
                "❌ **NON-CONFORMANT** - Does not meet bd-3vm specification requirements"
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

/// bd-3vm specification test matrix - all MUST/SHOULD requirements
const BD_3VM_CASES: &[ConformanceCase] = &[
    // Core Invariants (MUST)
    ConformanceCase {
        id: "3VM-INV-1",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-AA-NO-AMBIENT: no security-critical module may use ambient authority",
        test_fn: test_no_ambient_invariant,
    },
    ConformanceCase {
        id: "3VM-INV-2",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-AA-GUARD-ENFORCED: guard must be consulted before security-critical operations",
        test_fn: test_guard_enforced_invariant,
    },
    ConformanceCase {
        id: "3VM-INV-3",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-AA-AUDIT-COMPLETE: every audit run must produce complete report covering all modules",
        test_fn: test_audit_complete_invariant,
    },
    ConformanceCase {
        id: "3VM-INV-4",
        section: "invariants",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-AA-DETERMINISTIC: audit results are deterministic for same input",
        test_fn: test_deterministic_invariant,
    },

    // Event Code Requirements (MUST)
    ConformanceCase {
        id: "3VM-EVT-1",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "FN_AA_001 emitted for audit start events",
        test_fn: test_audit_start_events,
    },
    ConformanceCase {
        id: "3VM-EVT-2",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "FN_AA_003 emitted for ambient authority violations",
        test_fn: test_violation_events,
    },
    ConformanceCase {
        id: "3VM-EVT-3",
        section: "events",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "FN_AA_008 emitted for guard enforcement decisions",
        test_fn: test_enforcement_decision_events,
    },

    // Error Handling Requirements (MUST)
    ConformanceCase {
        id: "3VM-ERR-1",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "ERR_AA_MISSING_CAPABILITY error for missing required capabilities",
        test_fn: test_missing_capability_errors,
    },
    ConformanceCase {
        id: "3VM-ERR-2",
        section: "errors",
        level: RequirementLevel::Must,
        category: TestCategory::EdgeCase,
        description: "strict mode enforcement blocks operations on missing capabilities",
        test_fn: test_strict_mode_enforcement,
    },

    // Capability Context Requirements (MUST)
    ConformanceCase {
        id: "3VM-CAP-1",
        section: "capabilities",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "CapabilityContext correctly validates required capabilities",
        test_fn: test_capability_validation,
    },
    ConformanceCase {
        id: "3VM-CAP-2",
        section: "capabilities",
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "has_all() requires every capability in required set",
        test_fn: test_capability_completeness,
    },

    // Edge Cases (SHOULD)
    ConformanceCase {
        id: "3VM-EDGE-1",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "unknown modules should pass without restrictions",
        test_fn: test_unknown_module_handling,
    },
    ConformanceCase {
        id: "3VM-EDGE-2",
        section: "edge_cases",
        level: RequirementLevel::Should,
        category: TestCategory::EdgeCase,
        description: "advisory mode should record violations but allow operations",
        test_fn: test_advisory_mode_behavior,
    },
];

// Test implementation functions

fn test_no_ambient_invariant() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);

    // Test with context that has no capabilities (ambient authority usage)
    let no_caps_ctx = CapabilityContext::new(&[], "trace-no-ambient", "principal-test");

    // This should fail for security-critical modules
    let result = guard.check_context("crate::security::network_guard", &no_caps_ctx);
    if result.is_ok() {
        return Err("Should reject operations without required capabilities (INV-AA-NO-AMBIENT)".to_string());
    }

    // Test with proper capabilities
    let proper_ctx = CapabilityContext::new(
        &[Capability::NetworkEgress, Capability::PolicyEvaluation],
        "trace-proper",
        "principal-test"
    );

    let result = guard.check_context("crate::security::network_guard", &proper_ctx);
    if result.is_err() {
        return Err("Should allow operations with proper capabilities".to_string());
    }

    Ok(())
}

fn test_guard_enforced_invariant() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);

    // Verify guard is consulted (events emitted)
    let ctx = CapabilityContext::new(&[Capability::KeyAccess], "trace-guard", "principal-test");

    let initial_event_count = guard.events().len();
    let _ = guard.check_context("crate::supply_chain::artifact_signing", &ctx);

    if guard.events().len() == initial_event_count {
        return Err("Guard was not consulted - no events emitted (INV-AA-GUARD-ENFORCED)".to_string());
    }

    // Verify enforcement decisions are recorded
    let has_enforcement_event = guard.events().iter()
        .any(|e| e.event_code == event_codes::FN_AA_008);

    if !has_enforcement_event {
        return Err("Guard enforcement decision not recorded".to_string());
    }

    Ok(())
}

fn test_audit_complete_invariant() -> Result<(), String> {
    let ctx = CapabilityContext::new(&[Capability::KeyAccess], "trace-complete", "principal-test");

    // Run complete audit
    let report = generate_audit_report(&ctx, true);

    // Verify report covers all modules in default inventory
    let inventory = SecurityCriticalInventory::default_inventory();

    if report.total_modules != inventory.module_count() {
        return Err(format!(
            "Audit incomplete: {} modules in report, {} in inventory (INV-AA-AUDIT-COMPLETE)",
            report.total_modules, inventory.module_count()
        ));
    }

    // Verify every inventory module is in report
    for module_path in inventory.modules.keys() {
        if !report.module_results.contains_key(module_path) {
            return Err(format!("Module {} missing from audit report", module_path));
        }
    }

    Ok(())
}

fn test_deterministic_invariant() -> Result<(), String> {
    let ctx = CapabilityContext::new(
        &[Capability::KeyAccess, Capability::NetworkEgress],
        "trace-deterministic",
        "principal-test"
    );

    // Run audit multiple times
    let report1 = generate_audit_report(&ctx, true);
    let report2 = generate_audit_report(&ctx, true);

    // Results should be identical
    if report1.verdict != report2.verdict {
        return Err("Non-deterministic verdict".to_string());
    }

    if report1.total_modules != report2.total_modules {
        return Err("Non-deterministic module count".to_string());
    }

    if report1.passed != report2.passed || report1.failed != report2.failed {
        return Err("Non-deterministic pass/fail counts".to_string());
    }

    // Module results order should be deterministic (BTreeMap)
    let keys1: Vec<_> = report1.module_results.keys().collect();
    let keys2: Vec<_> = report2.module_results.keys().collect();

    if keys1 != keys2 {
        return Err("Non-deterministic module result ordering (INV-AA-DETERMINISTIC)".to_string());
    }

    Ok(())
}

fn test_audit_start_events() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[Capability::KeyAccess], "trace-start", "principal-test");

    let _ = guard.check_context("crate::security::network_guard", &ctx);

    let start_events: Vec<_> = guard.events().iter()
        .filter(|e| e.event_code == event_codes::FN_AA_001)
        .collect();

    if start_events.is_empty() {
        return Err("Expected FN_AA_001 event for audit start".to_string());
    }

    if !start_events[0].detail.contains("audit started") {
        return Err("FN_AA_001 event missing expected detail content".to_string());
    }

    Ok(())
}

fn test_violation_events() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[], "trace-violation", "principal-test");

    let _ = guard.check_context("crate::security::network_guard", &ctx);

    let violation_events: Vec<_> = guard.events().iter()
        .filter(|e| e.event_code == event_codes::FN_AA_003)
        .collect();

    if violation_events.is_empty() {
        return Err("Expected FN_AA_003 event for ambient authority violation".to_string());
    }

    if !violation_events[0].detail.contains("ambient authority violation") {
        return Err("FN_AA_003 event missing expected violation detail".to_string());
    }

    Ok(())
}

fn test_enforcement_decision_events() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[], "trace-enforcement", "principal-test");

    let _ = guard.check_context("crate::security::network_guard", &ctx);

    let decision_events: Vec<_> = guard.events().iter()
        .filter(|e| e.event_code == event_codes::FN_AA_008)
        .collect();

    if decision_events.is_empty() {
        return Err("Expected FN_AA_008 event for guard enforcement decision".to_string());
    }

    let decision_detail = &decision_events[0].detail;
    if !decision_detail.contains("guard enforcement:") {
        return Err("FN_AA_008 event missing enforcement decision detail".to_string());
    }

    if !decision_detail.contains("REJECT") && !decision_detail.contains("ALLOW") {
        return Err("FN_AA_008 event missing REJECT/ALLOW decision".to_string());
    }

    Ok(())
}

fn test_missing_capability_errors() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[], "trace-missing", "principal-test");

    let result = guard.check_context("crate::security::network_guard", &ctx);

    match result {
        Err(violation) => {
            if violation.code() != error_codes::ERR_AA_MISSING_CAPABILITY {
                return Err(format!(
                    "Expected ERR_AA_MISSING_CAPABILITY, got {}",
                    violation.code()
                ));
            }
            if !violation.description.contains("missing capabilities") {
                return Err("Missing capability error should describe missing capabilities".to_string());
            }
        },
        Ok(_) => return Err("Expected error for missing capabilities".to_string()),
    }

    Ok(())
}

fn test_strict_mode_enforcement() -> Result<(), String> {
    // Strict mode should block operations
    let mut strict_guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[], "trace-strict", "principal-test");

    let strict_result = strict_guard.check_context("crate::security::network_guard", &ctx);
    if strict_result.is_ok() {
        return Err("Strict mode should block operations on missing capabilities".to_string());
    }

    // Advisory mode should allow operations
    let mut advisory_guard = AuthorityAuditGuard::with_default_inventory(false);
    let advisory_result = advisory_guard.check_context("crate::security::network_guard", &ctx);
    if advisory_result.is_err() {
        return Err("Advisory mode should allow operations even with missing capabilities".to_string());
    }

    // But advisory mode should still record violations
    if advisory_guard.violations().is_empty() {
        return Err("Advisory mode should record violations even when allowing operations".to_string());
    }

    Ok(())
}

fn test_capability_validation() -> Result<(), String> {
    let ctx = CapabilityContext::new(
        &[Capability::KeyAccess, Capability::NetworkEgress],
        "trace-validation",
        "principal-test"
    );

    // Test individual capability checks
    if !ctx.has_capability(&Capability::KeyAccess) {
        return Err("Should have key_access capability".to_string());
    }

    if !ctx.has_capability(&Capability::NetworkEgress) {
        return Err("Should have network_egress capability".to_string());
    }

    if ctx.has_capability(&Capability::FileSystemWrite) {
        return Err("Should not have file_system_write capability".to_string());
    }

    // Test missing capabilities detection
    let missing = ctx.missing_capabilities(&[
        Capability::KeyAccess,
        Capability::FileSystemWrite,
        Capability::ArtifactSigning
    ]);

    if missing.len() != 2 {
        return Err(format!("Expected 2 missing capabilities, got {}", missing.len()));
    }

    if !missing.contains(&Capability::FileSystemWrite) || !missing.contains(&Capability::ArtifactSigning) {
        return Err("Missing capabilities detection incorrect".to_string());
    }

    Ok(())
}

fn test_capability_completeness() -> Result<(), String> {
    let ctx = CapabilityContext::new(
        &[Capability::KeyAccess, Capability::ArtifactSigning],
        "trace-completeness",
        "principal-test"
    );

    // Should have all of these
    let required_subset = [Capability::KeyAccess, Capability::ArtifactSigning];
    if !ctx.has_all(&required_subset) {
        return Err("Should have all required capabilities in subset".to_string());
    }

    // Should NOT have all of these (missing NetworkEgress)
    let required_with_missing = [
        Capability::KeyAccess,
        Capability::ArtifactSigning,
        Capability::NetworkEgress
    ];
    if ctx.has_all(&required_with_missing) {
        return Err("Should not have all capabilities when some are missing".to_string());
    }

    // Empty requirement set should always pass
    if !ctx.has_all(&[]) {
        return Err("Empty requirement set should always be satisfied".to_string());
    }

    Ok(())
}

fn test_unknown_module_handling() -> Result<(), String> {
    let mut guard = AuthorityAuditGuard::with_default_inventory(true);
    let ctx = CapabilityContext::new(&[], "trace-unknown", "principal-test");

    // Unknown modules should pass without restrictions
    let result = guard.check_context("crate::unknown::module", &ctx);
    if result.is_err() {
        return Err("Unknown modules should pass without capability restrictions".to_string());
    }

    // Should emit appropriate event
    let pass_events: Vec<_> = guard.events().iter()
        .filter(|e| e.event_code == event_codes::FN_AA_002)
        .collect();

    if pass_events.is_empty() {
        return Err("Expected FN_AA_002 event for unknown module pass".to_string());
    }

    if !pass_events[0].detail.contains("not in security-critical inventory") {
        return Err("FN_AA_002 event should explain unknown module handling".to_string());
    }

    Ok(())
}

fn test_advisory_mode_behavior() -> Result<(), String> {
    let ctx = CapabilityContext::new(&[], "trace-advisory", "principal-test");

    // Generate report in advisory mode
    let advisory_report = generate_audit_report(&ctx, false);

    // Should pass overall despite violations
    if advisory_report.verdict != "PASS" {
        return Err("Advisory mode should pass overall despite individual violations".to_string());
    }

    // But should record violations
    if advisory_report.violations.is_empty() {
        return Err("Advisory mode should record violations for tracking purposes".to_string());
    }

    // All module results should show as passed in advisory mode
    for result in advisory_report.module_results.values() {
        if !result.passed {
            return Err("All modules should show as passed in advisory mode".to_string());
        }
        if result.violation.is_some() {
            return Err("Module results should not contain violations in advisory mode".to_string());
        }
    }

    // But violations should be recorded at report level
    if advisory_report.violations.len() != advisory_report.total_modules {
        return Err("Advisory mode should record violation for each module with missing capabilities".to_string());
    }

    Ok(())
}

/// Execute the complete bd-3vm conformance test suite
pub fn run_bd_3vm_conformance_tests() -> ConformanceReport {
    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats::default();

    for case in BD_3VM_CASES {
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
        specification: "bd-3vm".to_string(),
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
        let report = run_bd_3vm_conformance_tests();

        // Verify we have the expected number of test cases
        assert_eq!(report.results.len(), BD_3VM_CASES.len());

        // Verify all MUST requirements pass (conformance requirement)
        assert_eq!(report.stats.must_fail, 0, "All MUST requirements should pass");

        // Verify compliance score calculation
        let score = report.compliance_score();
        assert!(score >= 0.95, "Compliance score should be at least 95%");
    }

    #[test]
    fn conformance_report_markdown_generation() {
        let report = run_bd_3vm_conformance_tests();
        let markdown = report.to_markdown();

        assert!(markdown.contains("# bd-3vm Ambient Authority Audit Conformance Report"));
        assert!(markdown.contains("Compliance Score"));
        assert!(markdown.contains("3VM-INV-1"));
    }

    #[test]
    fn all_test_cases_have_unique_ids() {
        let mut seen_ids = std::collections::HashSet::new();

        for case in BD_3VM_CASES {
            if !seen_ids.insert(case.id) {
                panic!("Duplicate test case ID: {}", case.id);
            }
        }
    }

    #[test]
    fn all_invariants_covered() {
        let has_no_ambient = BD_3VM_CASES.iter().any(|c| c.id == "3VM-INV-1");
        let has_guard_enforced = BD_3VM_CASES.iter().any(|c| c.id == "3VM-INV-2");
        let has_audit_complete = BD_3VM_CASES.iter().any(|c| c.id == "3VM-INV-3");
        let has_deterministic = BD_3VM_CASES.iter().any(|c| c.id == "3VM-INV-4");

        assert!(has_no_ambient, "Should test INV-AA-NO-AMBIENT");
        assert!(has_guard_enforced, "Should test INV-AA-GUARD-ENFORCED");
        assert!(has_audit_complete, "Should test INV-AA-AUDIT-COMPLETE");
        assert!(has_deterministic, "Should test INV-AA-DETERMINISTIC");
    }

    #[test]
    fn schema_version_matches_implementation() {
        assert_eq!(SCHEMA_VERSION, "aa-v1.0");
    }
}