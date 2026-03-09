#![cfg(feature = "extended-surfaces")]

use std::collections::BTreeMap;

use frankenengine_node::policy::compat_gates::{
    CompatGateEvaluator, CompatibilityBand, CompatibilityMode, GateDecision, ShimRegistry,
    ShimRegistryEntry, ShimRiskCategory,
};
use frankenengine_node::policy::compatibility_gate::{
    CompatMode, GateCheckRequest, GateEngine, ModeTransitionRequest, Verdict,
};

fn sample_registry() -> ShimRegistry {
    let mut registry = ShimRegistry::new();
    registry
        .register(ShimRegistryEntry {
            shim_id: "shim-edge".to_string(),
            description: "edge-compatible shim".to_string(),
            band: CompatibilityBand::Edge,
            risk_category: ShimRiskCategory::Low,
            activation_policy_id: "policy-shim-edge".to_string(),
            divergence_rationale: "integration test".to_string(),
            api_family: "fs".to_string(),
            active: true,
        })
        .unwrap();
    registry
}

#[test]
fn compat_gates_pipeline_round_trips_signed_mode_receipts() {
    let mut evaluator = CompatGateEvaluator::new(sample_registry());
    let receipt = evaluator
        .set_mode(
            "tenant-compat",
            CompatibilityMode::Balanced,
            "operator",
            "integration pipeline coverage",
            true,
        )
        .unwrap();
    assert!(receipt.verify_signature());

    let result = evaluator
        .evaluate_gate("shim-edge", "tenant-compat", "trace-integration-1")
        .unwrap();
    assert_eq!(result.decision, GateDecision::Allow);
    assert_eq!(result.event_code, "PCG-001");
    assert_eq!(evaluator.audit_log_for_scope("tenant-compat").len(), 1);
}

#[test]
fn legacy_compatibility_pipeline_round_trips_signed_receipts() {
    let mut engine = GateEngine::new(b"integration-key".to_vec());
    engine.set_scope_mode("tenant-legacy", CompatMode::Balanced);

    let gate = engine.gate_check(&GateCheckRequest {
        package_id: "shim-edge".to_string(),
        requested_mode: CompatMode::Strict,
        scope: "tenant-legacy".to_string(),
        policy_context: BTreeMap::new(),
    });
    assert_eq!(gate.decision, Verdict::Allow);

    let transition = engine
        .request_transition(&ModeTransitionRequest {
            scope_id: "tenant-legacy".to_string(),
            from_mode: CompatMode::Balanced,
            to_mode: CompatMode::Strict,
            justification: "integration tightening coverage".to_string(),
            requestor: "operator".to_string(),
        })
        .unwrap();
    assert!(engine.verify_transition_signature(&transition));

    let divergence = engine.issue_divergence_receipt(
        "tenant-legacy",
        "shim-edge",
        "integration divergence coverage",
        "minor",
    );
    assert!(engine.verify_receipt_signature(&divergence));
}
