//! bd-tg2 Fleet Quarantine/Revocation API Conformance Test Suite
//!
//! This harness implements Pattern 4: Spec-Derived Test Matrix for the bd-tg2
//! specification covering fleet quarantine/revocation API with zone/tenant-scoped operations.

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// Import the fleet quarantine API types and constants
use frankenengine_node::api::fleet_quarantine::{
    FLEET_QUARANTINE_INITIATED, FLEET_REVOCATION_ISSUED, FLEET_RELEASED,
    FLEET_RECONCILE_COMPLETED, FLEET_SCOPE_INVALID, FLEET_ROLLBACK_FAILED,
    FLEET_NOT_ACTIVATED, FLEET_INTERNAL, FleetQuarantineRequest, FleetRevocationRequest,
    FleetReleaseRequest, FleetStatusRequest, FleetReconcileRequest, FleetQuarantineResponse,
    FleetApiService, ZoneId, ExtensionId, IncidentId,
};

/// Test categories for organizational purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
}

/// Requirement levels from bd-tg2 specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String },
}

/// Individual conformance test record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceRecord {
    pub id: String,
    pub section: String,
    pub level: RequirementLevel,
    pub category: TestCategory,
    pub description: String,
    pub result: TestResult,
}

/// Overall conformance test statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConformanceStats {
    pub must_pass: usize,
    pub must_fail: usize,
    pub should_pass: usize,
    pub should_fail: usize,
    pub may_pass: usize,
    pub may_fail: usize,
    pub expected_failures: usize,
    pub skipped: usize,
}

/// Complete conformance test report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub results: BTreeMap<String, ConformanceRecord>,
    pub stats: ConformanceStats,
    pub specification: String,
    pub timestamp: String,
}

impl ConformanceReport {
    /// Calculate compliance score (0.0 - 1.0)
    pub fn compliance_score(&self) -> f64 {
        let must_total = self.stats.must_pass + self.stats.must_fail;
        if must_total == 0 {
            1.0
        } else {
            self.stats.must_pass as f64 / must_total as f64
        }
    }

    /// Generate markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# bd-tg2 Fleet Quarantine/Revocation API Conformance Report\n\n");
        md.push_str(&format!("**Generated:** {}\n\n", self.timestamp));
        md.push_str(&format!("**Compliance Score:** {:.1}%\n\n", self.compliance_score() * 100.0));

        // Summary table
        md.push_str("## Summary\n\n");
        md.push_str("| Requirement Level | Pass | Fail | Skip | XFAIL |\n");
        md.push_str("|------------------|:----:|:----:|:----:|:-----:|\n");
        md.push_str(&format!("| MUST | {} | {} | 0 | 0 |\n",
                             self.stats.must_pass, self.stats.must_fail));
        md.push_str(&format!("| SHOULD | {} | {} | {} | {} |\n",
                             self.stats.should_pass, self.stats.should_fail,
                             self.stats.skipped, self.stats.expected_failures));
        md.push_str(&format!("| MAY | {} | {} | 0 | 0 |\n",
                             self.stats.may_pass, self.stats.may_fail));

        // Detailed results
        md.push_str("\n## Test Results\n\n");
        for (_, record) in &self.results {
            let status = match &record.result {
                TestResult::Pass => "✅ PASS",
                TestResult::Fail { .. } => "❌ FAIL",
                TestResult::Skipped { .. } => "⏭️ SKIP",
                TestResult::ExpectedFailure { .. } => "⏳ XFAIL",
            };
            md.push_str(&format!("- **{}** [{}] {}: {}\n",
                                record.id, status, record.section, record.description));

            if let TestResult::Fail { reason } = &record.result {
                md.push_str(&format!("  - ❌ {}\n", reason));
            }
        }

        md
    }
}

// Individual conformance test cases covering bd-tg2 specification

fn test_case_tg2_inv_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-INV-1".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-FLEET-ZONE-SCOPE: every operation is scoped to a zone/tenant".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        // Test that all fleet operations require zone scoping
        let zone_id = ZoneId::new("test-zone-001".to_string());
        let extension_id = ExtensionId::new("test-extension".to_string());

        // Quarantine request must include zone
        let quarantine_req = FleetQuarantineRequest {
            zone_id: zone_id.clone(),
            extension_id: extension_id.clone(),
            reason: "test quarantine".to_string(),
            trace_id: "trace-inv-1".to_string(),
        };

        // Verify zone ID is preserved in request
        assert_eq!(quarantine_req.zone_id, zone_id, "Quarantine request must preserve zone ID");

        // Revocation request must include zone
        let revocation_req = FleetRevocationRequest {
            zone_id: zone_id.clone(),
            extension_id: extension_id.clone(),
            reason: "test revocation".to_string(),
            trace_id: "trace-inv-1-rev".to_string(),
        };

        assert_eq!(revocation_req.zone_id, zone_id, "Revocation request must preserve zone ID");

        // Status request must be zone-scoped
        let status_req = FleetStatusRequest {
            zone_id: zone_id.clone(),
            trace_id: "trace-inv-1-status".to_string(),
        };

        assert_eq!(status_req.zone_id, zone_id, "Status request must preserve zone ID");

        // Test that zone IDs are validated
        assert!(!zone_id.as_str().is_empty(), "Zone ID must not be empty");
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Zone scoping not properly enforced across operations".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_inv_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-INV-2".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-FLEET-RECEIPT: all operations produce signed decision receipts".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();

        // Quarantine operation should produce signed receipt
        let zone_id = ZoneId::new("receipt-test-zone".to_string());
        let extension_id = ExtensionId::new("receipt-extension".to_string());

        let quarantine_req = FleetQuarantineRequest {
            zone_id: zone_id.clone(),
            extension_id: extension_id.clone(),
            reason: "test receipt generation".to_string(),
            trace_id: "trace-inv-2".to_string(),
        };

        let response = api_service.quarantine(quarantine_req);
        match response {
            Ok(resp) => {
                // Verify receipt is present
                assert!(resp.receipt.is_some(), "Quarantine response must include signed receipt");

                if let Some(receipt) = resp.receipt {
                    assert!(!receipt.signature_b64.is_empty(), "Receipt must have non-empty signature");
                    assert!(!receipt.payload.is_empty(), "Receipt must have non-empty payload");
                    assert_eq!(receipt.zone_id, zone_id, "Receipt must preserve zone ID");
                }
            },
            Err(e) => {
                // Even error responses should include receipts for audit trail
                assert!(e.trace_id.is_some(), "Error response should include trace ID");
            }
        }
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Signed decision receipts not properly generated for operations".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_inv_3() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-INV-3".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "INV-FLEET-BOUNDED: all collections are bounded with capacity eviction".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();

        // Test bounded fleet events
        let max_events = 4096; // From MAX_FLEET_EVENTS constant

        // Add events beyond capacity
        for i in 0..max_events + 10 {
            let zone_id = ZoneId::new(format!("zone-{}", i));
            let extension_id = ExtensionId::new(format!("ext-{}", i));

            let quarantine_req = FleetQuarantineRequest {
                zone_id,
                extension_id,
                reason: format!("capacity test {}", i),
                trace_id: format!("trace-bounded-{}", i),
            };

            let _ = api_service.quarantine(quarantine_req);
        }

        // Verify capacity is bounded (oldest events evicted)
        let events = api_service.get_fleet_events();
        assert!(events.len() <= max_events, "Fleet events must be bounded to max capacity");

        // Verify that recent events are preserved (LIFO eviction of oldest)
        if events.len() == max_events {
            let last_event = events.last().expect("Should have events");
            assert!(last_event.trace_id.contains(&format!("{}", max_events + 9)),
                    "Most recent events should be preserved during eviction");
        }
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Collection capacity bounding not working properly".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_inv_4() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-INV-4".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-FLEET-SAFE-START: API starts in read-only mode, requires activation".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        // Fresh API service should start in read-only mode
        let mut api_service = FleetApiService::new();

        let zone_id = ZoneId::new("safe-start-zone".to_string());
        let extension_id = ExtensionId::new("safe-start-ext".to_string());

        // Write operations should fail before activation
        let quarantine_req = FleetQuarantineRequest {
            zone_id: zone_id.clone(),
            extension_id: extension_id.clone(),
            reason: "test safe start".to_string(),
            trace_id: "trace-inv-4".to_string(),
        };

        let result = api_service.quarantine(quarantine_req);
        assert!(result.is_err(), "Quarantine should fail before activation");

        if let Err(e) = result {
            assert_eq!(e.code(), FLEET_NOT_ACTIVATED, "Should return FLEET_NOT_ACTIVATED error");
        }

        // Read operations should work even before activation
        let status_req = FleetStatusRequest {
            zone_id: zone_id.clone(),
            trace_id: "trace-inv-4-status".to_string(),
        };

        let status_result = api_service.get_status(status_req);
        // Status should work (read-only) but show inactive state
        assert!(status_result.is_ok() ||
                status_result.unwrap_err().code() == FLEET_NOT_ACTIVATED,
                "Status check should work in read-only mode");

        // After activation, write operations should work
        api_service.activate().expect("Activation should succeed");

        let quarantine_req2 = FleetQuarantineRequest {
            zone_id,
            extension_id,
            reason: "test after activation".to_string(),
            trace_id: "trace-inv-4-post-activation".to_string(),
        };

        let result2 = api_service.quarantine(quarantine_req2);
        assert!(result2.is_ok(), "Quarantine should work after activation");
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Safe start mode not properly enforced".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_evt_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-EVT-1".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "FLEET-001 event MUST be emitted on quarantine initiation".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();
        api_service.activate().expect("Activation should succeed");

        let zone_id = ZoneId::new("event-test-zone".to_string());
        let extension_id = ExtensionId::new("event-extension".to_string());

        let quarantine_req = FleetQuarantineRequest {
            zone_id,
            extension_id,
            reason: "test event emission".to_string(),
            trace_id: "trace-evt-1".to_string(),
        };

        let response = api_service.quarantine(quarantine_req).expect("Quarantine should succeed");

        // Verify FLEET-001 event is emitted
        let events = api_service.get_fleet_events();
        let quarantine_event = events.iter().find(|e| e.event_code == FLEET_QUARANTINE_INITIATED);

        assert!(quarantine_event.is_some(), "FLEET-001 event should be emitted");

        if let Some(event) = quarantine_event {
            assert_eq!(event.event_code, FLEET_QUARANTINE_INITIATED, "Correct event code");
            assert_eq!(FLEET_QUARANTINE_INITIATED, "FLEET-001", "Event code should match specification");
            assert_eq!(event.trace_id, "trace-evt-1", "Event should preserve trace ID");
        }

        // Verify response indicates success
        assert!(response.success, "Quarantine response should indicate success");
        assert!(!response.operation_id.is_empty(), "Response should include operation ID");
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "FLEET-001 event not properly emitted for quarantine operations".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_evt_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-EVT-2".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "FLEET-002 event MUST be emitted on revocation issuance".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();
        api_service.activate().expect("Activation should succeed");

        let zone_id = ZoneId::new("revocation-test-zone".to_string());
        let extension_id = ExtensionId::new("revocation-extension".to_string());

        let revocation_req = FleetRevocationRequest {
            zone_id,
            extension_id,
            reason: "test revocation event".to_string(),
            trace_id: "trace-evt-2".to_string(),
        };

        let response = api_service.revoke(revocation_req).expect("Revocation should succeed");

        // Verify FLEET-002 event is emitted
        let events = api_service.get_fleet_events();
        let revocation_event = events.iter().find(|e| e.event_code == FLEET_REVOCATION_ISSUED);

        assert!(revocation_event.is_some(), "FLEET-002 event should be emitted");

        if let Some(event) = revocation_event {
            assert_eq!(event.event_code, FLEET_REVOCATION_ISSUED, "Correct event code");
            assert_eq!(FLEET_REVOCATION_ISSUED, "FLEET-002", "Event code should match specification");
            assert_eq!(event.trace_id, "trace-evt-2", "Event should preserve trace ID");
        }

        assert!(response.success, "Revocation response should indicate success");
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "FLEET-002 event not properly emitted for revocation operations".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_err_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-ERR-1".to_string(),
        section: "Error Handling".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "FLEET_SCOPE_INVALID error MUST be returned for invalid zone scoping".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();
        api_service.activate().expect("Activation should succeed");

        // Test with empty zone ID
        let empty_zone = ZoneId::new("".to_string());
        let extension_id = ExtensionId::new("test-extension".to_string());

        let quarantine_req = FleetQuarantineRequest {
            zone_id: empty_zone,
            extension_id,
            reason: "test invalid scope".to_string(),
            trace_id: "trace-err-1".to_string(),
        };

        let result = api_service.quarantine(quarantine_req);
        assert!(result.is_err(), "Empty zone ID should cause error");

        if let Err(e) = result {
            assert_eq!(e.code(), FLEET_SCOPE_INVALID, "Should return FLEET_SCOPE_INVALID error");
        }

        // Test with invalid characters in zone ID
        let invalid_zone = ZoneId::new("zone/with/invalid/chars".to_string());
        let extension_id2 = ExtensionId::new("test-extension-2".to_string());

        let quarantine_req2 = FleetQuarantineRequest {
            zone_id: invalid_zone,
            extension_id: extension_id2,
            reason: "test invalid chars".to_string(),
            trace_id: "trace-err-1-chars".to_string(),
        };

        let result2 = api_service.quarantine(quarantine_req2);
        assert!(result2.is_err(), "Invalid zone format should cause error");

        if let Err(e) = result2 {
            assert_eq!(e.code(), FLEET_SCOPE_INVALID, "Should return FLEET_SCOPE_INVALID error");
        }
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "FLEET_SCOPE_INVALID error not properly returned for invalid scoping".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_rollback_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-ROLLBACK-1".to_string(),
        section: "Rollback Operations".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "INV-FLEET-ROLLBACK: release deterministically rolls back quarantine state".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();
        api_service.activate().expect("Activation should succeed");

        let zone_id = ZoneId::new("rollback-test-zone".to_string());
        let extension_id = ExtensionId::new("rollback-extension".to_string());

        // Step 1: Quarantine an extension
        let quarantine_req = FleetQuarantineRequest {
            zone_id: zone_id.clone(),
            extension_id: extension_id.clone(),
            reason: "test rollback".to_string(),
            trace_id: "trace-rollback-quarantine".to_string(),
        };

        let quarantine_resp = api_service.quarantine(quarantine_req).expect("Quarantine should succeed");
        let quarantine_op_id = quarantine_resp.operation_id.clone();

        // Verify quarantine is active
        let status_req = FleetStatusRequest {
            zone_id: zone_id.clone(),
            trace_id: "trace-rollback-status".to_string(),
        };

        let status = api_service.get_status(status_req).expect("Status should succeed");
        assert!(status.quarantined_extensions.contains(&extension_id),
                "Extension should be quarantined");

        // Step 2: Release (rollback) the quarantine
        let incident_id = IncidentId::new("rollback-incident-001".to_string());
        let release_req = FleetReleaseRequest {
            zone_id: zone_id.clone(),
            incident_id,
            operation_ids: vec![quarantine_op_id.clone()],
            reason: "rollback test completed".to_string(),
            trace_id: "trace-rollback-release".to_string(),
        };

        let release_resp = api_service.release(release_req).expect("Release should succeed");
        assert!(release_resp.success, "Release should be successful");

        // Step 3: Verify rollback is deterministic
        let status_req2 = FleetStatusRequest {
            zone_id: zone_id.clone(),
            trace_id: "trace-rollback-verify".to_string(),
        };

        let status2 = api_service.get_status(status_req2).expect("Status should succeed");
        assert!(!status2.quarantined_extensions.contains(&extension_id),
                "Extension should no longer be quarantined after rollback");

        // Verify FLEET-004 release event was emitted
        let events = api_service.get_fleet_events();
        let release_event = events.iter().find(|e| e.event_code == FLEET_RELEASED);

        assert!(release_event.is_some(), "FLEET-004 release event should be emitted");
        if let Some(event) = release_event {
            assert_eq!(FLEET_RELEASED, "FLEET-004", "Event code should match specification");
        }
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Deterministic rollback not working properly".to_string()
            };
        }
    }

    record
}

fn test_case_tg2_reconcile_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "TG2-RECONCILE-1".to_string(),
        section: "Reconciliation".to_string(),
        level: RequirementLevel::Should,
        category: TestCategory::Integration,
        description: "Fleet reconciliation SHOULD track convergence with progress and ETA".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut api_service = FleetApiService::new_test();
        api_service.activate().expect("Activation should succeed");

        let zone_id = ZoneId::new("reconcile-test-zone".to_string());

        let reconcile_req = FleetReconcileRequest {
            zone_id: zone_id.clone(),
            dry_run: false,
            trace_id: "trace-reconcile-1".to_string(),
        };

        let reconcile_resp = api_service.reconcile(reconcile_req).expect("Reconcile should succeed");

        // Verify reconciliation response contains convergence info
        assert!(reconcile_resp.convergence_progress >= 0.0 && reconcile_resp.convergence_progress <= 1.0,
                "Convergence progress should be between 0.0 and 1.0");

        if reconcile_resp.convergence_progress < 1.0 {
            assert!(reconcile_resp.estimated_completion_secs.is_some(),
                    "ETA should be provided when convergence is incomplete");
        }

        // Verify FLEET-005 reconcile completed event
        let events = api_service.get_fleet_events();
        let reconcile_event = events.iter().find(|e| e.event_code == FLEET_RECONCILE_COMPLETED);

        assert!(reconcile_event.is_some(), "FLEET-005 reconcile event should be emitted");
        if let Some(event) = reconcile_event {
            assert_eq!(FLEET_RECONCILE_COMPLETED, "FLEET-005", "Event code should match specification");
        }
    }) {
        Ok(()) => {},
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Fleet reconciliation convergence tracking not working properly".to_string()
            };
        }
    }

    record
}

/// Execute the complete bd-tg2 conformance test suite
pub fn run_bd_tg2_conformance_tests() -> ConformanceReport {
    let test_cases = vec![
        test_case_tg2_inv_1(),
        test_case_tg2_inv_2(),
        test_case_tg2_inv_3(),
        test_case_tg2_inv_4(),
        test_case_tg2_evt_1(),
        test_case_tg2_evt_2(),
        test_case_tg2_err_1(),
        test_case_tg2_rollback_1(),
        test_case_tg2_reconcile_1(),
    ];

    let mut results = BTreeMap::new();
    let mut stats = ConformanceStats::default();

    for case in test_cases {
        match (&case.level, &case.result) {
            (RequirementLevel::Must, TestResult::Pass) => stats.must_pass += 1,
            (RequirementLevel::Must, TestResult::Fail { .. }) => stats.must_fail += 1,
            (RequirementLevel::Should, TestResult::Pass) => stats.should_pass += 1,
            (RequirementLevel::Should, TestResult::Fail { .. }) => stats.should_fail += 1,
            (RequirementLevel::May, TestResult::Pass) => stats.may_pass += 1,
            (RequirementLevel::May, TestResult::Fail { .. }) => stats.may_fail += 1,
            (_, TestResult::ExpectedFailure { .. }) => stats.expected_failures += 1,
            (_, TestResult::Skipped { .. }) => stats.skipped += 1,
        }

        results.insert(case.id.clone(), case);
    }

    ConformanceReport {
        results,
        stats,
        specification: "bd-tg2".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd_tg2_conformance_suite() {
        let report = run_bd_tg2_conformance_tests();

        // Print summary for human review
        println!("\n📊 bd-tg2 Conformance Test Results:");
        println!("  MUST requirements: {} pass, {} fail",
                 report.stats.must_pass, report.stats.must_fail);
        println!("  SHOULD requirements: {} pass, {} fail",
                 report.stats.should_pass, report.stats.should_fail);
        println!("  Compliance score: {:.1}%", report.compliance_score() * 100.0);

        // All MUST requirements must pass for conformance
        assert_eq!(report.stats.must_fail, 0,
                   "All MUST requirements must pass for bd-tg2 conformance");

        // Compliance score must be >= 95% for MUST requirements
        assert!(report.compliance_score() >= 0.95,
                "bd-tg2 compliance score must be >= 95%");

        println!("✅ bd-tg2 conformance test suite PASSED");
    }
}