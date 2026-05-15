use frankenengine_node::security::dgis::barrier_primitives::{
    Barrier, BarrierAction, BarrierConfig, BarrierEngine, BarrierError, BarrierPlan, BarrierType,
    CompositionFirewallConfig, ProgressionCriteria, RiskLevel, RolloutPhase,
    SandboxEscalationConfig, SandboxTier, StagedRolloutFenceConfig, VerifiedForkPinConfig,
    event_codes,
};
use std::collections::BTreeMap;

fn barrier(
    barrier_id: &str,
    node_id: &str,
    barrier_type: BarrierType,
    config: BarrierConfig,
) -> Barrier {
    Barrier {
        barrier_id: barrier_id.to_string(),
        node_id: node_id.to_string(),
        barrier_type,
        config,
        applied_at: "2026-05-14T00:00:00Z".to_string(),
        expires_at: None,
        source_plan_id: None,
    }
}

fn containment_plan() -> BarrierPlan {
    let mut rollout_criteria = BTreeMap::new();
    rollout_criteria.insert(
        "canary".to_string(),
        ProgressionCriteria::new(60, 0.01, 10).expect("test rollout criteria should be finite"),
    );

    BarrierPlan {
        plan_id: "dgis-quarantine-plan-001".to_string(),
        created_at: "2026-05-14T00:00:00Z".to_string(),
        barriers: vec![
            barrier(
                "sandbox-core",
                "pkg:core-auth",
                BarrierType::SandboxEscalation,
                BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
                    min_tier: SandboxTier::Isolated,
                    denied_capabilities: vec!["net.raw".to_string(), "fs.root".to_string()],
                    risk_threshold: RiskLevel::Critical,
                }),
            ),
            barrier(
                "firewall-core",
                "pkg:core-auth",
                BarrierType::CompositionFirewall,
                BarrierConfig::CompositionFirewall(CompositionFirewallConfig {
                    boundary_id: "payments-trust-boundary".to_string(),
                    blocked_capabilities: vec!["token.export".to_string()],
                    allow_list: vec!["metrics.read".to_string()],
                }),
            ),
            barrier(
                "fork-pin-core",
                "pkg:core-auth",
                BarrierType::VerifiedForkPin,
                BarrierConfig::VerifiedForkPin(VerifiedForkPinConfig {
                    fork_url: "https://example.invalid/core-auth-fork.git".to_string(),
                    pinned_commit: "0123456789abcdef".to_string(),
                    signature_pubkey_hex: "pubkey-core-auth".to_string(),
                    expected_digest: "sha256:trusted-core-auth".to_string(),
                }),
            ),
            barrier(
                "rollout-core",
                "pkg:core-auth",
                BarrierType::StagedRolloutFence,
                BarrierConfig::StagedRolloutFence(StagedRolloutFenceConfig {
                    initial_phase: RolloutPhase::Canary,
                    progression_criteria: rollout_criteria,
                    auto_rollback_on_breach: true,
                }),
            ),
        ],
    }
}

#[test]
fn quarantine_containment_plan_blocks_all_high_risk_escape_paths() {
    let mut engine = BarrierEngine::new();
    let receipts = containment_plan()
        .apply_to(&mut engine, "trace-quarantine-apply")
        .expect("containment barriers should apply");

    assert_eq!(receipts.len(), 4);
    assert_eq!(engine.active_barrier_count(), 4);
    assert!(
        receipts
            .iter()
            .all(|receipt| receipt.details["source_plan_id"] == "dgis-quarantine-plan-001")
    );

    let sandbox_err = engine
        .check_sandbox_escalation(
            "pkg:core-auth",
            "net.raw",
            SandboxTier::Isolated,
            "trace-quarantine-sandbox",
        )
        .expect_err("quarantine must block denied runtime capability");
    assert!(matches!(sandbox_err, BarrierError::SandboxEscalation(_)));

    let firewall_err = engine
        .check_composition_firewall(
            "pkg:core-auth",
            "token.export",
            "payments-trust-boundary",
            "trace-quarantine-firewall",
        )
        .expect_err("quarantine must block lateral token export");
    assert!(matches!(
        firewall_err,
        BarrierError::FirewallViolation {
            capability,
            boundary
        } if capability == "token.export" && boundary == "payments-trust-boundary"
    ));

    let pin_err = engine
        .check_fork_pin(
            "pkg:core-auth",
            "sha256:untrusted-core-auth",
            "trace-quarantine-fork",
        )
        .expect_err("quarantine must reject unverified fork drift");
    assert!(matches!(pin_err, BarrierError::ForkPinVerification(_)));

    let rollout_err = engine
        .check_rollout_fence(
            "rollout-core",
            RolloutPhase::General,
            "trace-quarantine-rollout",
        )
        .expect_err("quarantine must prevent direct promotion to general rollout");
    let rollout_reason = match rollout_err {
        BarrierError::RolloutFenceBlocked { reason, .. } => reason,
        other => format!("{other}"),
    };
    assert!(rollout_reason.contains("requires phase general"));

    let denied = engine
        .audit_log()
        .iter()
        .filter(|receipt| receipt.action == BarrierAction::CheckDenied)
        .count();
    assert_eq!(denied, 4);
}

#[test]
fn quarantine_containment_records_missing_barrier_coverage_explicitly() {
    let mut engine = BarrierEngine::new();
    containment_plan()
        .apply_to(&mut engine, "trace-quarantine-coverage")
        .expect("containment barriers should apply");

    let receipt = engine
        .check_composition_firewall(
            "pkg:uncataloged-leaf",
            "token.export",
            "payments-trust-boundary",
            "trace-missing-firewall",
        )
        .expect("missing coverage should emit an explicit not-applicable receipt");

    assert_eq!(
        receipt.event_code,
        event_codes::BARRIER_CHECK_NOT_APPLICABLE
    );
    assert_eq!(receipt.action, BarrierAction::NotApplicable);
    assert_eq!(receipt.node_id, "pkg:uncataloged-leaf");
    assert_eq!(
        receipt.details["reason"], "no_matching_firewall_boundary",
        "coverage gaps must not be rendered as synthetic passes"
    );
}

#[test]
fn quarantine_containment_jsonl_preserves_traceable_denials() {
    let mut engine = BarrierEngine::new();
    containment_plan()
        .apply_to(&mut engine, "trace-quarantine-jsonl")
        .expect("containment barriers should apply");

    let _ = engine.check_sandbox_escalation(
        "pkg:core-auth",
        "fs.root",
        SandboxTier::Isolated,
        "trace-denied-fs-root",
    );

    let jsonl = engine
        .export_audit_log_jsonl()
        .expect("audit log should serialize");
    let lines: Vec<&str> = jsonl.lines().collect();

    assert!(lines.len() >= 5);
    assert!(jsonl.contains("\"event_code\":\"DGIS-BARRIER-006\""));
    assert!(jsonl.contains("\"trace_id\":\"trace-denied-fs-root\""));
    assert!(jsonl.contains("\"source_plan_id\":\"dgis-quarantine-plan-001\""));
}
