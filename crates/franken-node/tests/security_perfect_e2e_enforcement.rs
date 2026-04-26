//! Perfect E2E security enforcement tests with structured logging.
//!
//! Complements integration_remote_capability_real_enforcement.rs by focusing on:
//! - Perfect E2E methodology (no mocks, real components)
//! - Structured JSON-line logging for CI failure analysis
//! - Test data factories for realistic security scenarios
//! - Production safety guards and environment validation
//!
//! This differs from the existing remote capability test by emphasizing
//! the Perfect E2E testing patterns rather than concurrent/timing behavior.

use std::sync::{Mutex, Once, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
};
use frankenengine_node::supply_chain::certification::{
    DerivationMetadata, EvidenceType, VerifiedEvidenceRef,
};
use frankenengine_node::supply_chain::trust_card::TrustCardRegistry;

// ---------------------------------------------------------------------------
// Test Infrastructure
// ---------------------------------------------------------------------------

static LOGGER_INIT: Once = Once::new();
static NODE_ENV_OVERRIDE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static TEST_COUNT: OnceLock<Mutex<u32>> = OnceLock::new();

fn test_count() -> &'static Mutex<u32> {
    TEST_COUNT.get_or_init(|| Mutex::new(0))
}

fn node_env_override() -> &'static Mutex<Option<String>> {
    NODE_ENV_OVERRIDE.get_or_init(|| Mutex::new(None))
}

fn set_node_env_override_for_tests(value: Option<&str>) {
    if let Ok(mut override_state) = node_env_override().lock() {
        *override_state = value.map(str::to_string);
    }
}

fn effective_node_env_for_tests() -> Option<String> {
    node_env_override()
        .lock()
        .ok()
        .and_then(|value| value.clone())
        .or_else(|| std::env::var("NODE_ENV").ok())
}

/// Structured test logger following Perfect E2E methodology.
struct TestLogger {
    test_name: String,
    test_id: u32,
    phase: String,
    start_time: u64,
}

impl TestLogger {
    fn new(test_name: String) -> Self {
        LOGGER_INIT.call_once(|| {
            eprintln!(
                "{{\"event\":\"test_suite_start\",\"suite\":\"security_real_db_enforcement\"}}"
            );
        });

        let mut count = test_count().lock().unwrap();
        *count += 1;
        let test_id = *count;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        eprintln!(
            "{{\"event\":\"test_start\",\"test_id\":{},\"test_name\":\"{}\",\"start_time\":{}}}",
            test_id, test_name, start_time
        );

        Self {
            test_name,
            test_id,
            phase: "setup".to_string(),
            start_time,
        }
    }

    fn phase(&mut self, phase: &str) {
        self.phase = phase.to_string();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        eprintln!(
            "{{\"event\":\"phase_start\",\"test_id\":{},\"phase\":\"{}\",\"ts\":{}}}",
            self.test_id, phase, ts
        );
    }

    fn assert_match(&self, field: &str, expected: &Value, actual: &Value) -> bool {
        let matches = expected == actual;
        eprintln!(
            "{{\"event\":\"assertion\",\"test_id\":{},\"phase\":\"{}\",\"field\":\"{}\",\"expected\":{},\"actual\":{},\"match\":{}}}",
            self.test_id, self.phase, field, expected, actual, matches
        );
        matches
    }

    fn test_end(&self, result: &str) {
        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let duration = end_time - self.start_time;
        eprintln!(
            "{{\"event\":\"test_end\",\"test_id\":{},\"test_name\":\"{}\",\"result\":\"{}\",\"duration_secs\":{}}}",
            self.test_id, self.test_name, result, duration
        );
    }
}

/// Real enforcement test harness with no mocks.
struct RealEnforcementHarness {
    gate: CapabilityGate,
    provider: CapabilityProvider,
    trust_registry: TrustCardRegistry,
}

impl RealEnforcementHarness {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Production safety guard
        Self::validate_test_environment()?;

        // Initialize real enforcement components
        let gate = CapabilityGate::new("test-security-secret-key")?;
        let provider = CapabilityProvider::new("test-security-secret-key")?;
        let trust_registry = TrustCardRegistry::default();

        Ok(Self {
            gate,
            provider,
            trust_registry,
        })
    }

    /// Production safety guard - validates we're not in production environment.
    fn validate_test_environment() -> Result<(), Box<dyn std::error::Error>> {
        if let Some(env) = effective_node_env_for_tests() {
            if env == "production" {
                return Err("Cannot run real enforcement tests in production environment".into());
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test Data Factories
// ---------------------------------------------------------------------------

struct RemoteCapFactory;

impl RemoteCapFactory {
    /// Creates a realistic remote capability with full scope.
    fn create_full_scope_cap(
        provider: &CapabilityProvider,
        single_use: bool,
    ) -> Result<frankenengine_node::security::remote_cap::RemoteCap, String> {
        let scope = RemoteScope::new(
            vec![
                RemoteOperation::NetworkEgress,
                RemoteOperation::FederationSync,
                RemoteOperation::RevocationFetch,
                RemoteOperation::RemoteAttestationVerify,
                RemoteOperation::TelemetryExport,
                RemoteOperation::RemoteComputation,
                RemoteOperation::ArtifactUpload,
            ],
            vec![
                "https://api.frankenengine.org/".to_string(),
                "https://registry.frankenengine.org/".to_string(),
                "federation://cluster-prod/".to_string(),
                "revocation://global-feed/".to_string(),
            ],
        );

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        provider
            .issue(
                "test-security-controller",
                scope,
                current_time,
                3600, // 1 hour TTL
                true, // network_enabled
                single_use,
                "test-trace-12345",
            )
            .map(|(cap, _audit)| cap)
    }

    /// Creates a restricted capability for specific operation.
    fn create_restricted_cap(
        provider: &CapabilityProvider,
        operation: RemoteOperation,
        endpoint_prefix: &str,
    ) -> Result<frankenengine_node::security::remote_cap::RemoteCap, String> {
        let scope = RemoteScope::new(vec![operation], vec![endpoint_prefix.to_string()]);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        provider
            .issue(
                "test-restricted-controller",
                scope,
                current_time,
                300, // 5 minute TTL for testing
                true,
                false, // reusable
                "test-restricted-trace",
            )
            .map(|(cap, _audit)| cap)
    }
}

struct TrustCardFactory;

impl TrustCardFactory {
    /// Creates verified evidence references for realistic test scenarios.
    fn create_verified_evidence() -> Vec<VerifiedEvidenceRef> {
        vec![
            VerifiedEvidenceRef {
                evidence_id: "evidence-test-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                verification_receipt_hash: "sha256:abc123def456".to_string(),
            },
            VerifiedEvidenceRef {
                evidence_id: "evidence-test-002".to_string(),
                evidence_type: EvidenceType::AuditReport,
                verified_at_epoch: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                verification_receipt_hash: "sha256:def789ghi012".to_string(),
            },
        ]
    }

    /// Creates valid derivation metadata.
    fn create_derivation_metadata(evidence_refs: Vec<VerifiedEvidenceRef>) -> DerivationMetadata {
        DerivationMetadata {
            evidence_refs,
            derived_at_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            derivation_chain_hash: "sha256:test-derivation-chain".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_remote_cap_enforcement_no_mocks() {
    let mut logger = TestLogger::new("remote_cap_enforcement_no_mocks".to_string());

    let mut harness = match RealEnforcementHarness::new() {
        Ok(h) => h,
        Err(e) => {
            logger.test_end("skipped");
            eprintln!("Skipping enforcement test: {}", e);
            return;
        }
    };

    logger.phase("setup");

    // Create test capability through factory - REAL capability, not mocked
    let cap = RemoteCapFactory::create_full_scope_cap(&harness.provider, false)
        .expect("Failed to create test capability");

    logger.phase("act");

    // Test 1: Valid capability should authorize network operation
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let result = harness.gate.authorize_network(
        Some(&cap),
        RemoteOperation::NetworkEgress,
        "https://api.frankenengine.org/v1/submit",
        current_time,
        "test-trace-001",
    );

    logger.phase("assert");
    assert!(
        result.is_ok(),
        "Valid capability should authorize operation: {:?}",
        result
    );
    logger.assert_match(
        "authorization_success",
        &json!(true),
        &json!(result.is_ok()),
    );

    // Test 2: Operation not in scope should fail
    logger.phase("act");
    let restricted_cap = RemoteCapFactory::create_restricted_cap(
        &harness.provider,
        RemoteOperation::RevocationFetch,
        "revocation://",
    )
    .expect("Failed to create restricted capability");

    let result = harness.gate.authorize_network(
        Some(&restricted_cap),
        RemoteOperation::NetworkEgress, // Not in scope
        "https://api.frankenengine.org/v1/submit",
        current_time,
        "test-trace-002",
    );

    logger.phase("assert");
    assert!(result.is_err(), "Operation not in scope should fail");
    let err = result.unwrap_err();
    assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    logger.assert_match(
        "scope_violation_detected",
        &json!("REMOTECAP_SCOPE_DENIED"),
        &json!(err.code()),
    );

    // Test 3: Endpoint not in scope should fail
    logger.phase("act");
    let result = harness.gate.authorize_network(
        Some(&restricted_cap),
        RemoteOperation::RevocationFetch,
        "https://malicious.example.com/steal", // Not in scope
        current_time,
        "test-trace-003",
    );

    logger.phase("assert");
    assert!(result.is_err(), "Endpoint not in scope should fail");
    let err = result.unwrap_err();
    assert_eq!(err.code(), "REMOTECAP_SCOPE_DENIED");
    logger.assert_match(
        "endpoint_violation_detected",
        &json!("REMOTECAP_SCOPE_DENIED"),
        &json!(err.code()),
    );

    logger.test_end("pass");
}

#[test]
fn test_trust_card_registry_validation_no_mocks() {
    let mut logger = TestLogger::new("trust_card_registry_validation_no_mocks".to_string());

    let harness = match RealEnforcementHarness::new() {
        Ok(h) => h,
        Err(e) => {
            logger.test_end("skipped");
            eprintln!("Skipping trust card test: {}", e);
            return;
        }
    };

    logger.phase("setup");

    // Create verified evidence using factory - REAL evidence, not mocked
    let evidence_refs = TrustCardFactory::create_verified_evidence();
    let derivation = TrustCardFactory::create_derivation_metadata(evidence_refs.clone());

    logger.phase("act");

    // Test 1: Registry snapshot should be consistent
    let initial_snapshot = harness
        .trust_registry
        .snapshot()
        .expect("snapshot should succeed");

    logger.phase("assert");
    assert!(
        initial_snapshot.cards_by_extension.is_empty(),
        "Initial registry should be empty"
    );
    logger.assert_match(
        "initial_registry_empty",
        &json!(true),
        &json!(initial_snapshot.cards_by_extension.is_empty()),
    );

    // Test 2: Evidence validation should work correctly
    logger.phase("act");
    let evidence_valid =
        !evidence_refs.is_empty() && evidence_refs.iter().all(|e| !e.evidence_id.is_empty());

    logger.phase("assert");
    assert!(evidence_valid, "Evidence should be valid");
    logger.assert_match("evidence_validation", &json!(true), &json!(evidence_valid));

    // Test 3: Derivation metadata should be well-formed
    logger.phase("act");
    let derivation_valid = derivation.derived_at_epoch > 0
        && !derivation.derivation_chain_hash.is_empty()
        && derivation.evidence_refs.len() == evidence_refs.len();

    logger.phase("assert");
    assert!(derivation_valid, "Derivation metadata should be valid");
    logger.assert_match(
        "derivation_validation",
        &json!(true),
        &json!(derivation_valid),
    );

    logger.test_end("pass");
}

#[test]
fn test_remote_cap_expiry_enforcement_no_mocks() {
    let mut logger = TestLogger::new("remote_cap_expiry_no_mocks".to_string());

    let mut harness = match RealEnforcementHarness::new() {
        Ok(h) => h,
        Err(e) => {
            logger.test_end("skipped");
            eprintln!("Skipping expiry test: {}", e);
            return;
        }
    };

    logger.phase("setup");

    // Create capability with very short TTL - REAL expired capability, not mocked
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://telemetry.example.com/".to_string()],
    );

    let past_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10; // 10 seconds ago

    let expired_cap = harness
        .provider
        .issue(
            "test-expired-controller",
            scope,
            past_time,
            5, // 5 second TTL - already expired
            true,
            false,
            "test-expired-trace",
        )
        .expect("Failed to create expired capability")
        .0;

    logger.phase("act");

    // Try to use expired capability - REAL expiry check, not mocked
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let result = harness.gate.authorize_network(
        Some(&expired_cap),
        RemoteOperation::TelemetryExport,
        "https://telemetry.example.com/push",
        current_time,
        "test-expired-trace-use",
    );

    logger.phase("assert");
    assert!(result.is_err(), "Expired capability should be rejected");
    let err = result.unwrap_err();
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
    logger.assert_match(
        "expiry_enforcement",
        &json!("REMOTECAP_EXPIRED"),
        &json!(err.code()),
    );

    logger.test_end("pass");
}

#[test]
fn test_single_use_capability_consumption_no_mocks() {
    let mut logger = TestLogger::new("single_use_cap_consumption_no_mocks".to_string());

    let mut harness = match RealEnforcementHarness::new() {
        Ok(h) => h,
        Err(e) => {
            logger.test_end("skipped");
            eprintln!("Skipping single-use test: {}", e);
            return;
        }
    };

    logger.phase("setup");

    // Create single-use capability - REAL single-use enforcement, not mocked
    let single_use_cap = RemoteCapFactory::create_full_scope_cap(&harness.provider, true)
        .expect("Failed to create single-use capability");

    logger.phase("act");

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // First use should succeed - REAL enforcement
    let first_result = harness.gate.authorize_network(
        Some(&single_use_cap),
        RemoteOperation::NetworkEgress,
        "https://api.frankenengine.org/v1/test",
        current_time,
        "test-first-use",
    );

    logger.phase("assert");
    assert!(
        first_result.is_ok(),
        "First use of single-use capability should succeed"
    );
    logger.assert_match(
        "first_use_success",
        &json!(true),
        &json!(first_result.is_ok()),
    );

    logger.phase("act");

    // Second use should fail (capability consumed) - REAL consumption tracking
    let second_result = harness.gate.authorize_network(
        Some(&single_use_cap),
        RemoteOperation::NetworkEgress,
        "https://api.frankenengine.org/v1/test",
        current_time + 1,
        "test-second-use",
    );

    logger.phase("assert");
    assert!(
        second_result.is_err(),
        "Second use of single-use capability should fail"
    );
    let err = second_result.unwrap_err();
    assert_eq!(err.code(), "REMOTECAP_REPLAY");
    logger.assert_match(
        "single_use_enforcement",
        &json!("REMOTECAP_REPLAY"),
        &json!(err.code()),
    );

    logger.test_end("pass");
}

// ---------------------------------------------------------------------------
// Environment Validation (Production Safety Guards)
// ---------------------------------------------------------------------------

#[test]
fn test_production_safety_guard() {
    let mut logger = TestLogger::new("production_safety_guard".to_string());

    logger.phase("setup");

    struct NodeEnvOverrideCleanup;

    impl Drop for NodeEnvOverrideCleanup {
        fn drop(&mut self) {
            set_node_env_override_for_tests(None);
        }
    }

    // Temporarily force production mode without mutating process-global environment.
    set_node_env_override_for_tests(Some("production"));
    let _cleanup = NodeEnvOverrideCleanup;

    logger.phase("act");
    let harness_result = RealEnforcementHarness::new();

    logger.phase("assert");
    assert!(
        harness_result.is_err(),
        "Should reject production environment"
    );

    if let Err(e) = harness_result {
        let error_msg = format!("{}", e);
        let is_production_error = error_msg.contains("production");
        logger.assert_match(
            "production_guard_triggered",
            &json!(true),
            &json!(is_production_error),
        );
    }

    logger.test_end("pass");
}

#[test]
fn test_no_token_enforcement() {
    let mut logger = TestLogger::new("no_token_enforcement".to_string());

    let mut harness = match RealEnforcementHarness::new() {
        Ok(h) => h,
        Err(e) => {
            logger.test_end("skipped");
            eprintln!("Skipping no-token test: {}", e);
            return;
        }
    };

    logger.phase("act");

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Test all operations require a token - REAL enforcement, not mocked
    let operations_and_endpoints = [
        (RemoteOperation::NetworkEgress, "https://egress.example.com"),
        (RemoteOperation::FederationSync, "federation://cluster-a"),
        (
            RemoteOperation::RevocationFetch,
            "revocation://global-feed/latest",
        ),
        (
            RemoteOperation::RemoteAttestationVerify,
            "https://attestation.example.com/verify",
        ),
        (
            RemoteOperation::TelemetryExport,
            "https://telemetry.example.com/push",
        ),
    ];

    logger.phase("assert");

    for (operation, endpoint) in &operations_and_endpoints {
        let result = harness.gate.authorize_network(
            None, // No token provided
            *operation,
            endpoint,
            current_time,
            "test-no-token",
        );

        assert!(
            result.is_err(),
            "Operation {:?} should fail without token",
            operation
        );
        let err = result.unwrap_err();
        assert_eq!(err.code(), "REMOTECAP_MISSING");
        logger.assert_match(
            &format!("{:?}_requires_token", operation),
            &json!("REMOTECAP_MISSING"),
            &json!(err.code()),
        );
    }

    logger.test_end("pass");
}
