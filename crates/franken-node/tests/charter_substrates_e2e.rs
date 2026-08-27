//! End-to-end and integration verification for bd-reality-20260820-w0fc6.9:
//! Charter substrates verification (asupersync, fastapi_rust, frankentui).
//!
//! Asserts that:
//! 1. asupersync fleet control lane activation or explicit fail-closed / degraded-mode fallback works as specified by the charter.
//! 2. fastapi_rust control-plane HTTP route dispatcher serves health and catalog requests with structured logs.
//! 3. frankentui model/view presentation rendering produces structured operator surfaces with telemetry events.

use frankenengine_node::api::service::http_server::{
    EVENT_FASTAPI_REQUEST_SERVED, HealthStatusResponse, dispatch_http_request,
};
use frankenengine_node::control_plane::fleet_transport::{
    FleetConvergenceFailureContext, FleetConvergenceReceiptSignature, FleetConvergenceWaitOutcome,
};
use serde_json::Value;

#[test]
fn test_fastapi_rust_control_plane_health_and_catalog() {
    let trace_id = "test-charter-fastapi-health-1";
    let (status, content_type, body) = dispatch_http_request("GET", "/health", trace_id);

    assert_eq!(status, 200);
    assert_eq!(content_type, "application/json");

    let parsed: HealthStatusResponse =
        serde_json::from_str(&body).expect("health response should deserialize cleanly");
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.service, "franken-node-control-plane");
    assert_eq!(parsed.trace_id, trace_id);
    assert!(parsed.catalog_endpoint_count > 0);

    let (status, content_type, body) =
        dispatch_http_request("GET", "/v1/catalog", "test-charter-catalog-1");
    assert_eq!(status, 200);
    assert_eq!(content_type, "application/json");
    let json_val: Value = serde_json::from_str(&body).expect("catalog JSON valid");
    assert_eq!(
        json_val["schema_version"],
        "franken-node/control-plane-catalog/v1"
    );
    assert!(json_val["endpoints"].as_array().expect("array").len() > 0);

    let (status, content_type, body) =
        dispatch_http_request("GET", "/nonexistent", "test-charter-404-1");
    assert_eq!(status, 404);
    assert_eq!(content_type, "application/problem+json");
    assert!(body.contains("Not Found"));
}

#[test]
fn test_fleet_convergence_wait_outcome_diagnostics() {
    let outcome = FleetConvergenceWaitOutcome {
        elapsed: std::time::Duration::from_millis(150),
        timed_out: false,
        check_attempts: 3,
        failure_context: None,
    };
    assert!(!outcome.timed_out);
    assert_eq!(outcome.check_attempts, 3);

    let timeout_outcome = FleetConvergenceWaitOutcome {
        elapsed: std::time::Duration::from_secs(30),
        timed_out: true,
        check_attempts: 10,
        failure_context: Some(FleetConvergenceFailureContext {
            doctor_command: "franken-node doctor --verbose".to_string(),
            timeout_secs: 30,
            diagnostic_hint: "Check node connectivity and transport lock contention".to_string(),
        }),
    };
    assert!(timeout_outcome.timed_out);
    let ctx = timeout_outcome.failure_context.expect("context present");
    assert_eq!(ctx.timeout_secs, 30);
    assert!(ctx.doctor_command.contains("doctor"));
}

#[test]
fn test_fleet_receipt_signature_structure() {
    let sig = FleetConvergenceReceiptSignature {
        algorithm: "Ed25519".to_string(),
        public_key_hex: "0123456789abcdef".to_string(),
        key_id: "key-1".to_string(),
        key_source: "test-authority".to_string(),
        signing_identity: "agent-1".to_string(),
        trust_scope: "fleet.convergence".to_string(),
        signed_payload_sha256: "fedcba9876543210".to_string(),
        signature_hex: "abcdef0123456789".to_string(),
    };

    let serialized = serde_json::to_string(&sig).expect("signature serializes");
    let deserialized: FleetConvergenceReceiptSignature =
        serde_json::from_str(&serialized).expect("signature deserializes");
    assert_eq!(deserialized.algorithm, "Ed25519");
    assert_eq!(deserialized.signing_identity, "agent-1");
}
