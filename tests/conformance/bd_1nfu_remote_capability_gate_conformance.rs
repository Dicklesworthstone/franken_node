//! bd-1nfu Remote Capability Gate Conformance Test Suite
//!
//! This harness implements Pattern 4: Spec-Derived Test Matrix for the bd-1nfu
//! specification covering remote capability gates for network-bound trust/control operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// API-DRIFT REMEDIATION (bd-rjc2m.7): dropped now-unused RemoteCap, RemoteCapAuditEvent, RemoteCapError
// imports (field peeking replaced by accessor methods; error codes asserted via str literals).
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope,
};

// API-DRIFT REMEDIATION (bd-rjc2m.7): the previous secret literal "test-secret" (11 chars) is
// rejected by production's hardened key-material validator (MIN_SECRET_MATERIAL_LEN = 16 chars
// AND MIN_SECRET_ENTROPY_BITS = 56), surfacing as CryptoEngineUnavailable at runtime. This is a
// latent test bug exposed once the gate runs as a real integration binary. Use a single shared,
// sufficiently long/high-entropy, non-weak secret for both the provider and the verifying gate so
// HMAC verification still matches across them.
const RC_TEST_SECRET: &str = "conformance-secret-material-x7Q2z9";

/// Test categories for organizational purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
}

/// Requirement levels from bd-1nfu specification
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
        md.push_str("# bd-1nfu Remote Capability Gate Conformance Report\n\n");
        md.push_str(&format!("**Generated:** {}\n\n", self.timestamp));
        md.push_str(&format!(
            "**Compliance Score:** {:.1}%\n\n",
            self.compliance_score() * 100.0
        ));

        // Summary table
        md.push_str("## Summary\n\n");
        md.push_str("| Requirement Level | Pass | Fail | Skip | XFAIL |\n");
        md.push_str("|------------------|:----:|:----:|:----:|:-----:|\n");
        md.push_str(&format!(
            "| MUST | {} | {} | 0 | 0 |\n",
            self.stats.must_pass, self.stats.must_fail
        ));
        md.push_str(&format!(
            "| SHOULD | {} | {} | {} | {} |\n",
            self.stats.should_pass,
            self.stats.should_fail,
            self.stats.skipped,
            self.stats.expected_failures
        ));
        md.push_str(&format!(
            "| MAY | {} | {} | 0 | 0 |\n",
            self.stats.may_pass, self.stats.may_fail
        ));

        // Detailed results
        md.push_str("\n## Test Results\n\n");
        for (_, record) in &self.results {
            let status = match &record.result {
                TestResult::Pass => "✅ PASS",
                TestResult::Fail { .. } => "❌ FAIL",
                TestResult::Skipped { .. } => "⏭️ SKIP",
                TestResult::ExpectedFailure { .. } => "⏳ XFAIL",
            };
            md.push_str(&format!(
                "- **{}** [{}] {}: {}\n",
                record.id, status, record.section, record.description
            ));

            if let TestResult::Fail { reason } = &record.result {
                md.push_str(&format!("  - ❌ {}\n", reason));
            }
        }

        md
    }
}

// Individual conformance test cases covering bd-1nfu specification

fn test_case_1nfu_inv_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-INV-1".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "RemoteCap tokens MUST contain scope, issuer, expiry, and signature"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _event) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-inv-1")
            .expect("capability issuance should succeed");

        // Verify all required fields are present and non-empty
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.token_id -> cap.token_id().
        assert!(!cap.token_id().is_empty(), "token_id must be non-empty");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.issuer_identity -> cap.issuer_identity().
        assert!(
            !cap.issuer_identity().is_empty(),
            "issuer_identity must be non-empty"
        );
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.expires_at_epoch_secs -> cap.expires_at_epoch_secs().
        assert!(
            cap.expires_at_epoch_secs() > 0,
            "expires_at_epoch_secs must be positive"
        );
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.scope.endpoint_prefixes -> cap.scope().endpoint_prefixes().
        assert!(
            !cap.scope().endpoint_prefixes().is_empty(),
            "scope must have endpoint prefixes"
        );
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.signature_b64 -> cap.signature() (field removed, accessor added).
        assert!(!cap.signature().is_empty(), "signature must be non-empty");

        // Verify scope has endpoint prefixes
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.scope.endpoint_prefixes -> cap.scope().endpoint_prefixes().
        assert!(
            !cap.scope().endpoint_prefixes().is_empty(),
            "scope endpoint prefixes required"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "RemoteCap token missing required fields".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_inv_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-INV-2".to_string(),
        section: "Core Invariants".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "CapabilityGate MUST be the single validation/enforcement point".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-inv-2")
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Valid token should pass through gate
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-gate-check",
        );

        assert!(result.is_ok(), "valid capability should pass gate check");

        // Gate should record audit event
        assert!(
            !gate.audit_log().is_empty(),
            "gate must record audit events"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "CapabilityGate not functioning as single enforcement point".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_evt_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-EVT-1".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "REMOTECAP_ISSUED event MUST be emitted on successful capability issuance"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (_cap, event) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-evt-1")
            .expect("capability issuance should succeed");

        // Verify REMOTECAP_ISSUED event is emitted
        assert_eq!(event.event_code, "REMOTECAP_ISSUED", "correct event code");
        assert_eq!(
            event.legacy_event_code, "RC_CAP_GRANTED",
            "correct legacy event code"
        );
        assert!(event.allowed, "event should indicate success");
        assert!(event.token_id.is_some(), "event should include token_id");
        assert!(
            event.issuer_identity.is_some(),
            "event should include issuer_identity"
        );
        assert_eq!(
            event.trace_id, "trace-evt-1",
            "event should include trace_id"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "REMOTECAP_ISSUED event not properly emitted".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_evt_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-EVT-2".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "REMOTECAP_DENIED event MUST be emitted on capability check failures"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Attempt operation without capability (should fail)
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            None,
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1000,
            "trace-evt-2",
        );

        assert!(result.is_err(), "check without capability should fail");

        // Verify REMOTECAP_DENIED event is emitted
        let audit_log = gate.audit_log();
        assert!(!audit_log.is_empty(), "audit log should contain events");

        let event = audit_log.last().expect("last audit event");
        assert_eq!(event.event_code, "REMOTECAP_DENIED", "correct event code");
        assert_eq!(
            event.legacy_event_code, "RC_CHECK_DENIED",
            "correct legacy event code"
        );
        assert!(!event.allowed, "event should indicate denial");
        assert!(
            event.denial_code.is_some(),
            "event should include denial code"
        );
        assert_eq!(
            event.trace_id, "trace-evt-2",
            "event should include trace_id"
        );
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "REMOTECAP_DENIED event not properly emitted".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_evt_3() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-EVT-3".to_string(),
        section: "Event Codes".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "REMOTECAP_CONSUMED event MUST be emitted on single-use token consumption"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "test-issuer",
                scope,
                1000,
                300,
                true,
                true,
                "trace-evt-3", // single_use = true
            )
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Use the single-use token
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-consume",
        );

        assert!(result.is_ok(), "valid single-use capability should pass");

        // Verify REMOTECAP_CONSUMED event is emitted
        let audit_log = gate.audit_log();
        let event = audit_log.last().expect("consumption audit event");
        assert_eq!(event.event_code, "REMOTECAP_CONSUMED", "correct event code");
        assert_eq!(
            event.legacy_event_code, "RC_CHECK_PASSED",
            "correct legacy event code"
        );
        assert!(event.allowed, "event should indicate success");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "REMOTECAP_CONSUMED event not properly emitted".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_err_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-ERR-1".to_string(),
        section: "Error Handling".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "REMOTECAP_MISSING error MUST be returned when no capability provided"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            None, // No capability provided
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1000,
            "trace-err-1",
        );

        assert!(result.is_err(), "check without capability should fail");
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_MISSING", "correct error code");

        // Verify audit event has correct denial code
        let audit_log = gate.audit_log();
        let event = audit_log.last().expect("denial audit event");
        assert_eq!(event.denial_code.as_deref(), Some("REMOTECAP_MISSING"));
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "REMOTECAP_MISSING error not properly handled".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_err_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-ERR-2".to_string(),
        section: "Error Handling".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "REMOTECAP_EXPIRED error MUST be returned for expired capabilities"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "test-issuer",
                scope,
                1000,
                1,
                true,
                false,
                "trace-err-2", // TTL = 1 second
            )
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Use capability after expiry
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1002, // After expiry (1000 + 1 + 1)
            "trace-expired",
        );

        assert!(result.is_err(), "expired capability should fail");
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_EXPIRED", "correct error code");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "REMOTECAP_EXPIRED error not properly handled".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_sec_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-SEC-1".to_string(),
        section: "Security".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "Signature verification MUST prevent capability forgery".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (mut cap, _) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-sec-1")
            .expect("capability issuance should succeed");

        // Corrupt the signature
        // API-DRIFT REMEDIATION (bd-rjc2m.7): cap.signature_b64 = .. (field removed) -> cap.corrupt_signature_for_test(..) test-support mutator.
        cap.corrupt_signature_for_test("invalid-signature");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-forged",
        );

        assert!(
            result.is_err(),
            "forged capability should fail verification"
        );
        let err = result.unwrap_err();
        // API-DRIFT REMEDIATION (bd-rjc2m.7): expected code "REMOTECAP_INVALID_SIGNATURE" -> "REMOTECAP_INVALID"
        // (RemoteCapError::InvalidSignature.code() is "REMOTECAP_INVALID" in current production).
        assert_eq!(err.code(), "REMOTECAP_INVALID", "correct error code");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Signature verification not preventing forgery".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_sec_2() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-SEC-2".to_string(),
        section: "Security".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Unit,
        description: "Scope validation MUST prevent unauthorized endpoint access".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-sec-2")
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Try to access endpoint outside scope
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://evil.com/upload", // Outside scope
            1100,
            "trace-scope-violation",
        );

        assert!(result.is_err(), "out-of-scope access should fail");
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED", "correct error code");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Scope validation not preventing unauthorized access".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_rep_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-REP-1".to_string(),
        section: "Replay Protection".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "Single-use tokens MUST prevent replay attacks".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        let (cap, _) = provider
            .issue(
                "test-issuer",
                scope,
                1000,
                300,
                true,
                true,
                "trace-rep-1", // single_use = true
            )
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // First use should succeed
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result1 = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-first-use",
        );
        assert!(result1.is_ok(), "first use should succeed");

        // Second use should fail (replay)
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let result2 = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-replay-attempt",
        );
        assert!(result2.is_err(), "replay should fail");
        let err = result2.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_REPLAY", "correct error code");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Replay protection not working for single-use tokens".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_loc_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-LOC-1".to_string(),
        section: "Local Mode".to_string(),
        level: RequirementLevel::Should,
        category: TestCategory::Integration,
        description: "Local-only mode SHOULD allow operations without network capabilities"
            .to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let mut gate = CapabilityGate::with_mode(RC_TEST_SECRET, ConnectivityMode::LocalOnly)
            .expect("valid gate in local mode");

        // Authorize local operation
        gate.authorize_local_operation("local_report_generation", 1000, "trace-loc-1");

        // Verify local mode event is emitted
        let audit_log = gate.audit_log();
        let event = audit_log.last().expect("local mode audit event");
        assert_eq!(
            event.event_code, "REMOTECAP_LOCAL_MODE_ACTIVE",
            "correct event code"
        );
        assert_eq!(
            event.legacy_event_code, "RC_LOCAL_MODE_ACTIVE",
            "correct legacy event code"
        );
        assert!(event.allowed, "local operation should be allowed");
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Local mode not functioning correctly".to_string(),
            };
        }
    }

    record
}

fn test_case_1nfu_aud_1() -> ConformanceRecord {
    let mut record = ConformanceRecord {
        id: "1NFU-AUD-1".to_string(),
        section: "Audit Trail".to_string(),
        level: RequirementLevel::Must,
        category: TestCategory::Integration,
        description: "All capability operations MUST generate audit events".to_string(),
        result: TestResult::Pass,
    };

    match std::panic::catch_unwind(|| {
        let provider = CapabilityProvider::new(RC_TEST_SECRET).expect("valid provider");
        // API-DRIFT REMEDIATION (bd-rjc2m.7): RemoteScope::new(endpoints) -> RemoteScope::new(operations, endpoints).
        let scope = RemoteScope::new(
            vec![RemoteOperation::ArtifactUpload],
            vec!["https://api.example/v1".to_string()],
        );

        // Issue capability (should generate audit event)
        let (cap, _) = provider
            .issue("test-issuer", scope, 1000, 300, true, false, "trace-aud-1")
            .expect("capability issuance should succeed");

        let mut gate = CapabilityGate::new(RC_TEST_SECRET).expect("valid gate");

        // Use capability (should generate audit event)
        // API-DRIFT REMEDIATION (bd-rjc2m.7): gate.check(..) -> gate.authorize_network(..); RemoteOperation::Upload -> ArtifactUpload.
        let _result = gate.authorize_network(
            Some(&cap),
            RemoteOperation::ArtifactUpload,
            "https://api.example/v1/upload",
            1100,
            "trace-use",
        );

        // Revoke capability (should generate audit event)
        let _revoke_event = gate.revoke(&cap, 1200, "trace-revoke");

        // Verify all operations generated audit events
        let provider_audit = provider.audit_log();
        assert!(
            !provider_audit.is_empty(),
            "provider should have audit events"
        );

        let gate_audit = gate.audit_log();
        assert!(!gate_audit.is_empty(), "gate should have audit events");

        // Verify audit events have required fields
        for event in gate_audit {
            assert!(!event.event_code.is_empty(), "event_code required");
            assert!(!event.trace_id.is_empty(), "trace_id required");
            assert!(event.timestamp_epoch_secs > 0, "timestamp required");
        }
    }) {
        Ok(()) => {}
        Err(_) => {
            record.result = TestResult::Fail {
                reason: "Audit trail not comprehensive".to_string(),
            };
        }
    }

    record
}

/// Execute the complete bd-1nfu conformance test suite
pub fn run_bd_1nfu_conformance_tests() -> ConformanceReport {
    let test_cases = vec![
        test_case_1nfu_inv_1(),
        test_case_1nfu_inv_2(),
        test_case_1nfu_evt_1(),
        test_case_1nfu_evt_2(),
        test_case_1nfu_evt_3(),
        test_case_1nfu_err_1(),
        test_case_1nfu_err_2(),
        test_case_1nfu_sec_1(),
        test_case_1nfu_sec_2(),
        test_case_1nfu_rep_1(),
        test_case_1nfu_loc_1(),
        test_case_1nfu_aud_1(),
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
        specification: "bd-1nfu".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bd_1nfu_conformance_suite() {
        let report = run_bd_1nfu_conformance_tests();

        // Print summary for human review
        println!("\n📊 bd-1nfu Conformance Test Results:");
        println!(
            "  MUST requirements: {} pass, {} fail",
            report.stats.must_pass, report.stats.must_fail
        );
        println!(
            "  SHOULD requirements: {} pass, {} fail",
            report.stats.should_pass, report.stats.should_fail
        );
        println!(
            "  Compliance score: {:.1}%",
            report.compliance_score() * 100.0
        );

        // All MUST requirements must pass for conformance
        assert_eq!(
            report.stats.must_fail, 0,
            "All MUST requirements must pass for bd-1nfu conformance"
        );

        // Compliance score must be >= 95% for MUST requirements
        assert!(
            report.compliance_score() >= 0.95,
            "bd-1nfu compliance score must be >= 95%"
        );

        println!("✅ bd-1nfu conformance test suite PASSED");
    }
}
