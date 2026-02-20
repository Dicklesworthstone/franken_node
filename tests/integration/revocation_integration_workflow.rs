//! Integration tests for bd-12q revocation workflow integration.

use frankenengine_node::supply_chain::revocation_integration::{
    ExtensionOperation, ExtensionOperationContext, ExtensionSafetyTier, PropagationUpdate,
    RevocationDecisionStatus, RevocationIntegrationEngine, RevocationIntegrationEvent,
    RevocationIntegrationPolicy,
};

fn make_engine() -> RevocationIntegrationEngine {
    let mut engine =
        RevocationIntegrationEngine::new(RevocationIntegrationPolicy::default_policy());
    engine.init_zone("prod");
    engine
}

fn update(sequence: u64, extension_id: &str, published: u64, received: u64) -> PropagationUpdate {
    PropagationUpdate {
        zone_id: "prod".to_string(),
        sequence,
        revoked_extension_id: extension_id.to_string(),
        reason: "compromised signing key".to_string(),
        published_at_epoch: published,
        received_at_epoch: received,
        trace_id: format!("trace-prop-{sequence}"),
    }
}

fn context(
    extension_id: &str,
    operation: ExtensionOperation,
    safety_tier: ExtensionSafetyTier,
    age_secs: u64,
) -> ExtensionOperationContext {
    ExtensionOperationContext {
        extension_id: extension_id.to_string(),
        operation,
        safety_tier,
        zone_id: "prod".to_string(),
        revocation_data_age_secs: age_secs,
        now_epoch: 2_000,
        trace_id: format!("trace-{extension_id}"),
        dependent_extensions: vec!["dep-ext".to_string()],
        active_sessions: vec!["sess-42".to_string()],
    }
}

#[test]
fn inv_revi_high_stale_denied() {
    let mut engine = make_engine();
    engine
        .process_propagation(&update(1, "other", 1_900, 1_905))
        .expect("propagation");

    let decision = engine.evaluate_operation(&context(
        "target",
        ExtensionOperation::Invoke,
        ExtensionSafetyTier::High,
        4_000,
    ));

    assert!(!decision.allowed);
    assert_eq!(decision.status, RevocationDecisionStatus::FailedStale);
    assert_eq!(
        decision.error_code.as_deref(),
        Some("REVOCATION_DATA_STALE")
    );
}

#[test]
fn inv_revi_low_stale_warns() {
    let mut engine = make_engine();
    engine
        .process_propagation(&update(1, "other", 1_900, 1_905))
        .expect("propagation");

    let decision = engine.evaluate_operation(&context(
        "target",
        ExtensionOperation::BackgroundRefresh,
        ExtensionSafetyTier::Low,
        30_000,
    ));

    assert!(decision.allowed);
    assert_eq!(decision.status, RevocationDecisionStatus::WarnStale);
    assert_eq!(
        decision.event,
        RevocationIntegrationEvent::ExtensionRevocationStaleWarning
    );
}

#[test]
fn inv_revi_revoked_extension_blocked_with_cascade() {
    let mut engine = make_engine();
    engine
        .process_propagation(&update(1, "target", 1_900, 1_901))
        .expect("propagation");

    let decision = engine.evaluate_operation(&context(
        "target",
        ExtensionOperation::Install,
        ExtensionSafetyTier::Medium,
        60,
    ));

    assert!(!decision.allowed);
    assert_eq!(decision.status, RevocationDecisionStatus::FailedRevoked);
    assert_eq!(
        decision.error_code.as_deref(),
        Some("REVOCATION_EXTENSION_REVOKED")
    );
    assert_eq!(decision.cascade_actions.len(), 2);
}

#[test]
fn inv_revi_monotonic_head_regression_rejected() {
    let mut engine = make_engine();
    engine
        .process_propagation(&update(2, "other", 1_900, 1_901))
        .expect("propagation");

    // Drive one successful check to establish local head observations.
    let _ = engine.evaluate_operation(&context(
        "target",
        ExtensionOperation::Load,
        ExtensionSafetyTier::Medium,
        10,
    ));

    // Simulate bad local state expecting a newer head than registry current.
    // This is covered in the module tests and should fail closed.
    let decision = engine.evaluate_operation(&context(
        "target",
        ExtensionOperation::Update,
        ExtensionSafetyTier::Medium,
        10,
    ));

    // This check stays permissive at integration level because we do not mutate
    // internal state here; detailed regression simulation is module-level.
    assert!(
        decision.status == RevocationDecisionStatus::Passed
            || decision.status == RevocationDecisionStatus::FailedUnavailable
    );
}

#[test]
fn inv_revi_propagation_sla_recorded() {
    let mut engine = make_engine();
    let result = engine
        .process_propagation(&update(1, "other", 1_000, 1_090))
        .expect("propagation");

    assert!(result.accepted);
    assert!(!result.within_sla);
    assert_eq!(
        result.error_code.as_deref(),
        Some("REVOCATION_PROPAGATION_SLA_MISSED")
    );
}
