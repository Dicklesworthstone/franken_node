use chrono::{Duration, TimeZone, Utc};
use frankenengine_node::api::fleet_quarantine::{
    DecisionReceipt, DecisionReceiptPayload, FLEET_ROLLBACK_UNVERIFIED, FleetControlError,
    FleetControlManager, QuarantineScope, canonical_decision_receipt_payload_hash,
    sign_decision_receipt,
};
use frankenengine_node::api::middleware::{AuthIdentity, AuthMethod, TraceContext};

const SIGNING_KEY_BYTES: [u8; 32] = [91_u8; 32];

fn admin_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "fleet-rollback-boundary-admin".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string()],
    }
}

fn trace_context(phase: &str) -> TraceContext {
    TraceContext {
        trace_id: format!("fleet-rollback-boundary-{phase}"),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

fn activated_manager() -> FleetControlManager {
    let mut manager = FleetControlManager::with_decision_signing_key(
        ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES),
        "fleet-rollback-boundary-test",
        "fleet-rollback-boundary",
    );
    manager.activate();
    manager
}

fn rollback_receipt(
    incident_id: &str,
    zone_id: &str,
    issued_at: chrono::DateTime<Utc>,
) -> DecisionReceipt {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&SIGNING_KEY_BYTES);
    let operation_id = format!("rollback-{incident_id}");
    let issued_at = issued_at.to_rfc3339();
    let decision_payload =
        DecisionReceiptPayload::rollback(incident_id, zone_id, "test convergence rollback receipt");
    let payload_hash = canonical_decision_receipt_payload_hash(
        &operation_id,
        "fleet-rollback-boundary-admin",
        zone_id,
        &issued_at,
        &decision_payload,
    );
    let mut receipt = DecisionReceipt {
        operation_id: operation_id.clone(),
        receipt_id: format!("rcpt-{operation_id}"),
        issuer: "fleet-rollback-boundary-admin".to_string(),
        issued_at,
        zone_id: zone_id.to_string(),
        payload_hash,
        decision_payload,
        signature: None,
    };
    receipt.signature = Some(sign_decision_receipt(
        &receipt,
        &signing_key,
        "fleet-rollback-boundary-test",
        "fleet-rollback-boundary",
    ));
    receipt
}

fn quarantined_incident(manager: &mut FleetControlManager) -> (String, QuarantineScope) {
    let scope = QuarantineScope {
        zone_id: "zone-rollback-boundary".to_string(),
        tenant_id: Some("tenant-rollback-boundary".to_string()),
        affected_nodes: 3,
        reason: "rollback boundary regression".to_string(),
    };
    let result = manager
        .quarantine(
            "ext-rollback-boundary",
            &scope,
            &admin_identity(),
            &trace_context("quarantine"),
        )
        .expect("quarantine should create incident");
    (format!("inc-{}", result.operation_id), scope)
}

#[test]
fn rollback_receipt_exact_ttl_boundary_fails_closed() {
    let mut manager = activated_manager();
    let (incident_id, scope) = quarantined_incident(&mut manager);
    let issued_at = Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap();

    manager.register_rollback_receipt(
        &incident_id,
        rollback_receipt(&incident_id, &scope.zone_id, issued_at),
    );

    manager
        .verify_convergence_rollback_receipt_at_for_tests(
            &incident_id,
            issued_at + Duration::hours(24) - Duration::milliseconds(1),
        )
        .expect("rollback receipt should remain valid just before TTL");

    let err = manager
        .verify_convergence_rollback_receipt_at_for_tests(
            &incident_id,
            issued_at + Duration::hours(24),
        )
        .expect_err("rollback receipt must fail closed at exact TTL boundary");

    match err {
        FleetControlError::RollbackUnverified { code, detail, .. } => {
            assert_eq!(code, FLEET_ROLLBACK_UNVERIFIED);
            assert!(detail.contains("at least 24 hours old"));
        }
        other => panic!("expected rollback-unverified stale receipt, got {other:?}"),
    }
}
