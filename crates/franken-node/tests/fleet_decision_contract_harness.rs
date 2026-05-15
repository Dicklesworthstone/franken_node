//! Control Plane Fleet Decision Conformance Harness
//!
//! Validates the fleet decision contract end-to-end against specification requirements.

use frankenengine_node::api::fleet_control_routes::{
    CoordinationRequest, CoordinationStatus, execute_coordination,
};
use frankenengine_node::api::fleet_quarantine::{
    DecisionReceiptPayload, QuarantineScope, canonical_decision_receipt_payload_hash,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};

fn fleet_admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-decision-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn fleet_trace(trace_id: &str) -> TraceContext {
    TraceContext {
        trace_id: trace_id.to_string(),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn quarantine_scope(zone_id: &str) -> QuarantineScope {
    QuarantineScope {
        zone_id: zone_id.to_string(),
        tenant_id: None,
        affected_nodes: 3,
        reason: "fleet decision contract quarantine".to_string(),
    }
}

#[test]
fn test_decision_receipt_quarantine_creation() {
    // MUST: Create valid quarantine decision receipt
    let scope = quarantine_scope("zone-contract");
    let payload = DecisionReceiptPayload::quarantine("test-extension", &scope);

    assert_eq!(payload.action_type, "quarantine");
    assert_eq!(payload.extension_id.as_deref(), Some("test-extension"));
    assert_eq!(payload.scope.zone_id, "zone-contract");
    assert_eq!(payload.scope.affected_nodes, Some(3));
    assert_eq!(payload.reason, "fleet decision contract quarantine");
}

#[test]
fn test_decision_receipt_payload_hash() {
    // MUST: Payload hash must be deterministic and non-empty
    let scope = quarantine_scope("zone-contract");
    let payload = DecisionReceiptPayload::quarantine("test-ext", &scope);
    let hash1 = canonical_decision_receipt_payload_hash(
        "op-contract-1",
        "fleet-admin",
        "zone-contract",
        "2026-04-25T00:00:00Z",
        &payload,
    );
    let hash2 = canonical_decision_receipt_payload_hash(
        "op-contract-1",
        "fleet-admin",
        "zone-contract",
        "2026-04-25T00:00:00Z",
        &payload,
    );

    assert!(!hash1.is_empty());
    assert_eq!(hash1, hash2, "Hash must be deterministic");
}

#[test]
fn test_decision_receipt_different_inputs_different_hashes() {
    // MUST: Different payloads must produce different hashes
    let scope = quarantine_scope("zone-contract");
    let payload1 = DecisionReceiptPayload::quarantine("ext-1", &scope);
    let payload2 = DecisionReceiptPayload::quarantine("ext-2", &scope);

    let hash1 = canonical_decision_receipt_payload_hash(
        "op-contract-1",
        "fleet-admin",
        "zone-contract",
        "2026-04-25T00:00:00Z",
        &payload1,
    );
    let hash2 = canonical_decision_receipt_payload_hash(
        "op-contract-1",
        "fleet-admin",
        "zone-contract",
        "2026-04-25T00:00:00Z",
        &payload2,
    );

    assert_ne!(
        hash1, hash2,
        "Different payloads must produce different hashes"
    );
}

#[test]
fn coordination_rejects_empty_target_set() {
    let identity = fleet_admin_identity();
    let trace = fleet_trace("fleet-decision-empty-targets");
    let request = CoordinationRequest {
        command_type: "policy-update".to_string(),
        target_nodes: Vec::new(),
        timeout_seconds: 30,
    };

    let err = execute_coordination(&identity, &trace, &request).expect_err("empty targets");
    let problem = err.to_problem("/v1/fleet/coordinate");

    assert_eq!(problem.status, 400);
    assert_eq!(problem.trace_id, trace.trace_id);
    assert!(problem.detail.contains("at least one target node"));
}

#[test]
fn coordination_rejects_duplicate_target_nodes_after_normalization() {
    let identity = fleet_admin_identity();
    let trace = fleet_trace("fleet-decision-duplicate-targets");
    let request = CoordinationRequest {
        command_type: "policy-update".to_string(),
        target_nodes: vec![" node-1 ".to_string(), "node-1".to_string()],
        timeout_seconds: 30,
    };

    let err = execute_coordination(&identity, &trace, &request).expect_err("duplicate targets");
    let problem = err.to_problem("/v1/fleet/coordinate");

    assert_eq!(problem.status, 400);
    assert_eq!(problem.trace_id, trace.trace_id);
    assert!(problem.detail.contains("duplicate target node `node-1`"));
}

#[test]
fn coordination_preserves_distinct_target_success_contract() -> Result<(), String> {
    let identity = fleet_admin_identity();
    let trace = fleet_trace("fleet-decision-distinct-targets");
    let request = CoordinationRequest {
        command_type: "policy-update".to_string(),
        target_nodes: vec!["node-1".to_string(), "node-2".to_string()],
        timeout_seconds: 30,
    };

    let response = execute_coordination(&identity, &trace, &request)
        .map_err(|err| format!("expected coordination success, got {err:?}"))?;

    assert!(response.ok);
    assert_eq!(response.data.command_type, "policy-update");
    assert_eq!(
        response.data.participating_nodes,
        vec!["node-1".to_string(), "node-2".to_string()]
    );
    assert_eq!(response.data.ack_count, 2);
    assert_eq!(response.data.total_nodes, 2);
    assert_eq!(response.data.status, CoordinationStatus::Acknowledged);
    Ok(())
}
