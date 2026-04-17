//! Dependency Graph Immune System (DGIS) enforcement layer.
//!
//! Provides trust barrier primitives and policy wiring for
//! behavioral sandbox escalation, composition firewalls,
//! verified-fork pinning, and staged rollout fences.

pub mod barrier_primitives;
pub mod update_copilot;

#[cfg(test)]
mod dgis_barrier_engine_negative_tests {
    use super::barrier_primitives::{
        Barrier, BarrierConfig, BarrierEngine, BarrierError, BarrierType,
        CompositionFirewallConfig, OverrideJustification, ProgressionCriteria, RiskLevel,
        RolloutPhase, SandboxEscalationConfig, SandboxTier, StagedRolloutFenceConfig,
        VerifiedForkPinConfig,
    };
    use std::collections::BTreeMap;

    fn base_barrier(
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
            applied_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: None,
            source_plan_id: None,
        }
    }

    fn sandbox_barrier(barrier_id: &str, node_id: &str) -> Barrier {
        base_barrier(
            barrier_id,
            node_id,
            BarrierType::SandboxEscalation,
            BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
                min_tier: SandboxTier::Strict,
                denied_capabilities: vec!["network.open".to_string()],
                risk_threshold: RiskLevel::High,
            }),
        )
    }

    fn firewall_barrier(barrier_id: &str, node_id: &str) -> Barrier {
        base_barrier(
            barrier_id,
            node_id,
            BarrierType::CompositionFirewall,
            BarrierConfig::CompositionFirewall(CompositionFirewallConfig {
                boundary_id: "payments".to_string(),
                blocked_capabilities: vec!["secret.export".to_string()],
                allow_list: vec!["metrics.read".to_string()],
            }),
        )
    }

    fn fork_pin_barrier(barrier_id: &str, node_id: &str) -> Barrier {
        base_barrier(
            barrier_id,
            node_id,
            BarrierType::VerifiedForkPin,
            BarrierConfig::VerifiedForkPin(VerifiedForkPinConfig {
                fork_url: "https://example.invalid/fork.git".to_string(),
                pinned_commit: "abcdef1234567890".to_string(),
                signature_pubkey_hex: "pubkey".to_string(),
                expected_digest: "digest:expected".to_string(),
            }),
        )
    }

    fn rollout_barrier(barrier_id: &str, node_id: &str) -> Barrier {
        base_barrier(
            barrier_id,
            node_id,
            BarrierType::StagedRolloutFence,
            BarrierConfig::StagedRolloutFence(StagedRolloutFenceConfig {
                initial_phase: RolloutPhase::Canary,
                progression_criteria: BTreeMap::<String, ProgressionCriteria>::new(),
                auto_rollback_on_breach: true,
            }),
        )
    }

    fn valid_override() -> OverrideJustification {
        OverrideJustification {
            override_id: "override-1".to_string(),
            principal_identity: "operator-A".to_string(),
            reason: "break-glass rehearsal".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            signature_hex: "sig-1".to_string(),
        }
    }

    #[test]
    fn negative_override_rejects_missing_principal() {
        let mut justification = valid_override();
        justification.principal_identity.clear();

        let err = justification
            .validate()
            .expect_err("override without principal must be rejected");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(reason) if reason.contains("principal_identity")
        ));
    }

    #[test]
    fn negative_override_rejects_missing_reason_before_lookup() {
        let mut engine = BarrierEngine::new();
        let mut justification = valid_override();
        justification.reason.clear();

        let err = engine
            .override_barrier("missing-barrier", justification, "trace-invalid-override")
            .expect_err("invalid override justification must be rejected first");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(reason) if reason.contains("reason")
        ));
    }

    #[test]
    fn negative_override_rejects_missing_signature() {
        let mut justification = valid_override();
        justification.signature_hex.clear();

        let err = justification
            .validate()
            .expect_err("override without signature must be rejected");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(reason) if reason.contains("signature")
        ));
    }

    #[test]
    fn negative_duplicate_barrier_id_is_rejected() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("barrier-1", "node-a"), "trace-apply")
            .expect("first barrier should apply");

        let err = engine
            .apply_barrier(firewall_barrier("barrier-1", "node-a"), "trace-duplicate")
            .expect_err("duplicate barrier IDs must be rejected");

        assert!(matches!(
            err,
            BarrierError::CompositionConflict(reason) if reason.contains("already exists")
        ));
    }

    #[test]
    fn negative_sandbox_check_rejects_under_tiered_node() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("sandbox-1", "node-a"), "trace-apply")
            .expect("sandbox barrier should apply");

        let err = engine
            .check_sandbox_escalation(
                "node-a",
                "fs.read",
                SandboxTier::Moderate,
                "trace-sandbox-tier",
            )
            .expect_err("node below minimum sandbox tier must be rejected");

        assert!(matches!(
            err,
            BarrierError::SandboxEscalation(reason)
                if reason.contains("requires at least")
        ));
    }

    #[test]
    fn negative_sandbox_check_rejects_denied_capability() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("sandbox-1", "node-a"), "trace-apply")
            .expect("sandbox barrier should apply");

        let err = engine
            .check_sandbox_escalation(
                "node-a",
                "network.open",
                SandboxTier::Strict,
                "trace-sandbox-capability",
            )
            .expect_err("denied capability must be rejected even at sufficient tier");

        assert!(matches!(
            err,
            BarrierError::SandboxEscalation(reason) if reason.contains("network.open")
        ));
    }

    #[test]
    fn negative_composition_firewall_rejects_blocked_capability() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(firewall_barrier("firewall-1", "node-a"), "trace-apply")
            .expect("firewall barrier should apply");

        let err = engine
            .check_composition_firewall("node-a", "secret.export", "payments", "trace-firewall")
            .expect_err("blocked capability must not cross protected boundary");

        assert!(matches!(
            err,
            BarrierError::FirewallViolation {
                capability,
                boundary
            } if capability == "secret.export" && boundary == "payments"
        ));
    }

    #[test]
    fn negative_fork_pin_rejects_digest_mismatch() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(fork_pin_barrier("fork-1", "node-a"), "trace-apply")
            .expect("fork pin barrier should apply");

        let err = engine
            .check_fork_pin("node-a", "digest:actual", "trace-fork")
            .expect_err("artifact digest mismatch must be rejected");

        assert!(matches!(
            err,
            BarrierError::ForkPinVerification(reason) if reason.contains("digest mismatch")
        ));
    }

    #[test]
    fn negative_rollout_fence_rejects_required_future_phase() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(rollout_barrier("rollout-1", "node-a"), "trace-apply")
            .expect("rollout barrier should apply");

        let err = engine
            .check_rollout_fence("rollout-1", RolloutPhase::General, "trace-rollout")
            .expect_err("canary rollout must not satisfy general phase requirement");

        assert!(matches!(
            err,
            BarrierError::RolloutFenceBlocked { phase, reason }
                if phase == "canary" && reason.contains("requires phase general")
        ));
    }

    #[test]
    fn negative_second_rollout_fence_on_same_node_is_rejected() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(rollout_barrier("rollout-1", "node-a"), "trace-apply")
            .expect("first rollout barrier should apply");

        let err = engine
            .apply_barrier(rollout_barrier("rollout-2", "node-a"), "trace-conflict")
            .expect_err("same node must not have two staged rollout fences");

        assert!(matches!(
            err,
            BarrierError::CompositionConflict(reason)
                if reason.contains("already has a staged rollout fence")
        ));
    }

    #[test]
    fn negative_remove_unknown_barrier_is_rejected() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .remove_barrier("missing-barrier", "trace-remove")
            .expect_err("removing an unknown barrier must be rejected");

        assert!(matches!(err, BarrierError::NotFound(id) if id == "missing-barrier"));
    }
}

#[cfg(test)]
mod dgis_acknowledgement_negative_tests {
    use super::barrier_primitives::{
        Barrier, BarrierConfig, BarrierEngine, BarrierError, BarrierType, OverrideJustification,
        RiskLevel, SandboxEscalationConfig, SandboxTier,
    };
    use super::update_copilot::{
        AcknowledgementDecision, AcknowledgementReceipt, CopilotError, UpdateCopilot,
    };

    fn override_justification(
        principal_identity: &str,
        reason: &str,
        signature_hex: &str,
    ) -> OverrideJustification {
        OverrideJustification {
            override_id: "override-1".to_string(),
            principal_identity: principal_identity.to_string(),
            reason: reason.to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: signature_hex.to_string(),
        }
    }

    fn acknowledgement(operator_identity: &str, signature_hex: &str) -> AcknowledgementReceipt {
        AcknowledgementReceipt {
            receipt_id: "ack-1".to_string(),
            proposal_id: "proposal-1".to_string(),
            operator_identity: operator_identity.to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "risk accepted for controlled rollout".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: signature_hex.to_string(),
        }
    }

    fn sandbox_barrier(barrier_id: &str) -> Barrier {
        Barrier {
            barrier_id: barrier_id.to_string(),
            node_id: "node-a".to_string(),
            barrier_type: BarrierType::SandboxEscalation,
            config: BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
                min_tier: SandboxTier::Strict,
                denied_capabilities: vec!["net.raw".to_string()],
                risk_threshold: RiskLevel::High,
            }),
            applied_at: "2026-04-17T00:00:00Z".to_string(),
            expires_at: None,
            source_plan_id: Some("plan-a".to_string()),
        }
    }

    #[test]
    fn negative_path_override_validation_rejects_empty_principal_identity() {
        let err = override_justification("", "incident response", "aabbcc")
            .validate()
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("principal_identity")
        ));
    }

    #[test]
    fn negative_path_override_validation_rejects_empty_reason() {
        let err = override_justification("operator-1", "", "aabbcc")
            .validate()
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("reason")
        ));
    }

    #[test]
    fn negative_path_override_validation_rejects_empty_signature() {
        let err = override_justification("operator-1", "incident response", "")
            .validate()
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("signature")
        ));
    }

    #[test]
    fn negative_path_acknowledgement_validation_rejects_empty_operator_identity() {
        let err = acknowledgement("", "aabbcc").validate().unwrap_err();

        assert!(matches!(
            err,
            CopilotError::AcknowledgementRejected(message)
                if message.contains("operator_identity")
        ));
    }

    #[test]
    fn negative_path_acknowledgement_validation_rejects_empty_signature() {
        let err = acknowledgement("operator-1", "").validate().unwrap_err();

        assert!(matches!(
            err,
            CopilotError::AcknowledgementRejected(message) if message.contains("signature")
        ));
    }

    #[test]
    fn copilot_does_not_store_invalid_acknowledgement() {
        let mut copilot = UpdateCopilot::default();
        let err = copilot
            .process_acknowledgement(acknowledgement("", "aabbcc"), "trace-invalid-ack")
            .unwrap_err();

        assert!(matches!(
            err,
            CopilotError::AcknowledgementRejected(message)
                if message.contains("operator_identity")
        ));
        assert!(!copilot.is_acknowledged("proposal-1"));
    }

    #[test]
    fn removing_missing_barrier_fails_closed() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .remove_barrier("missing-barrier", "trace-remove")
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(barrier_id) if barrier_id == "missing-barrier"
        ));
    }

    #[test]
    fn overriding_missing_barrier_fails_closed_after_valid_justification() {
        let mut engine = BarrierEngine::new();
        let justification = override_justification("operator-1", "incident response", "aabbcc");

        let err = engine
            .override_barrier("missing-barrier", justification, "trace-override")
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::NotFound(barrier_id) if barrier_id == "missing-barrier"
        ));
    }

    #[test]
    fn applying_duplicate_barrier_id_is_rejected() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("barrier-a"), "trace-first")
            .expect("first barrier should apply");

        let err = engine
            .apply_barrier(sandbox_barrier("barrier-a"), "trace-duplicate")
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::CompositionConflict(message) if message.contains("already exists")
        ));
    }

    #[test]
    fn sandbox_check_rejects_tier_below_required_minimum() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("barrier-a"), "trace-apply")
            .expect("sandbox barrier should apply");

        let err = engine
            .check_sandbox_escalation(
                "node-a",
                "fs.read",
                SandboxTier::Moderate,
                "trace-tier-deny",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::SandboxEscalation(message)
                if message.contains("requires at least")
        ));
    }

    #[test]
    fn sandbox_check_rejects_denied_capability() {
        let mut engine = BarrierEngine::new();
        engine
            .apply_barrier(sandbox_barrier("barrier-a"), "trace-apply")
            .expect("sandbox barrier should apply");

        let err = engine
            .check_sandbox_escalation("node-a", "net.raw", SandboxTier::Strict, "trace-cap-deny")
            .unwrap_err();

        assert!(matches!(
            err,
            BarrierError::SandboxEscalation(message) if message.contains("net.raw")
        ));
    }
}

#[cfg(test)]
mod dgis_barrier_copilot_negative_tests {
    use super::barrier_primitives::{
        Barrier, BarrierConfig, BarrierEngine, BarrierError, BarrierType, OverrideJustification,
        RiskLevel, SandboxEscalationConfig, SandboxTier,
    };
    use super::update_copilot::{
        AcknowledgementDecision, AcknowledgementReceipt, CopilotError, TopologyRiskMetrics,
        UpdateCopilot,
    };

    fn sandbox_barrier(id: &str, node_id: &str) -> Barrier {
        Barrier {
            barrier_id: id.to_string(),
            node_id: node_id.to_string(),
            barrier_type: BarrierType::SandboxEscalation,
            config: BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
                min_tier: SandboxTier::Strict,
                denied_capabilities: vec!["network".to_string()],
                risk_threshold: RiskLevel::High,
            }),
            applied_at: "2026-04-17T12:00:00Z".to_string(),
            expires_at: None,
            source_plan_id: Some("plan-dgis-negative".to_string()),
        }
    }

    fn valid_override() -> OverrideJustification {
        OverrideJustification {
            override_id: "override-dgis-negative".to_string(),
            principal_identity: "operator@example.com".to_string(),
            reason: "break-glass test fixture".to_string(),
            timestamp: "2026-04-17T12:00:00Z".to_string(),
            signature_hex: "abcdef".to_string(),
        }
    }

    fn valid_acknowledgement(proposal_id: &str) -> AcknowledgementReceipt {
        AcknowledgementReceipt {
            receipt_id: format!("receipt-{proposal_id}"),
            proposal_id: proposal_id.to_string(),
            operator_identity: "operator@example.com".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "accepted risk for test fixture".to_string(),
            timestamp: "2026-04-17T12:00:00Z".to_string(),
            signature_hex: "abcdef".to_string(),
        }
    }

    #[test]
    fn negative_dgis_override_rejects_missing_principal() {
        let mut override_request = valid_override();
        override_request.principal_identity.clear();

        let err = override_request
            .validate()
            .expect_err("override without principal must be rejected");

        assert!(matches!(err, BarrierError::OverrideRejected(_)));
    }

    #[test]
    fn negative_dgis_override_rejects_missing_reason() {
        let mut override_request = valid_override();
        override_request.reason.clear();

        let err = override_request
            .validate()
            .expect_err("override without reason must be rejected");

        assert!(matches!(err, BarrierError::OverrideRejected(_)));
    }

    #[test]
    fn negative_dgis_override_rejects_missing_signature() {
        let mut override_request = valid_override();
        override_request.signature_hex.clear();

        let err = override_request
            .validate()
            .expect_err("override without signature must be rejected");

        assert!(matches!(err, BarrierError::OverrideRejected(_)));
    }

    #[test]
    fn negative_dgis_remove_unknown_barrier_reports_not_found() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .remove_barrier("missing-barrier", "trace-remove-missing")
            .expect_err("unknown barrier removal must fail closed");

        assert!(matches!(err, BarrierError::NotFound(id) if id == "missing-barrier"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_dgis_override_unknown_barrier_reports_not_found() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .override_barrier(
                "missing-barrier",
                valid_override(),
                "trace-override-missing",
            )
            .expect_err("unknown barrier override must fail closed");

        assert!(matches!(err, BarrierError::NotFound(id) if id == "missing-barrier"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_dgis_duplicate_barrier_id_is_rejected() {
        let mut engine = BarrierEngine::new();
        let first = sandbox_barrier("barrier-duplicate", "node-a");
        let second = sandbox_barrier("barrier-duplicate", "node-b");
        engine
            .apply_barrier(first, "trace-first")
            .expect("first barrier applies");

        let err = engine
            .apply_barrier(second, "trace-second")
            .expect_err("duplicate barrier id must be rejected");

        assert!(matches!(err, BarrierError::CompositionConflict(_)));
        assert_eq!(engine.active_barrier_count(), 1);
    }

    #[test]
    fn negative_dgis_acknowledgement_rejects_missing_operator() {
        let mut receipt = valid_acknowledgement("proposal-no-operator");
        receipt.operator_identity.clear();

        let err = receipt
            .validate()
            .expect_err("acknowledgement without operator must be rejected");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
    }

    #[test]
    fn negative_dgis_acknowledgement_rejects_missing_signature() {
        let mut receipt = valid_acknowledgement("proposal-no-signature");
        receipt.signature_hex.clear();

        let err = receipt
            .validate()
            .expect_err("acknowledgement without signature must be rejected");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
    }

    #[test]
    fn negative_dgis_copilot_does_not_store_invalid_acknowledgement() {
        let mut copilot = UpdateCopilot::default();
        let mut receipt = valid_acknowledgement("proposal-invalid-ack");
        receipt.signature_hex.clear();

        let err = copilot
            .process_acknowledgement(receipt, "trace-invalid-ack")
            .expect_err("invalid acknowledgement must not be stored");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
        assert!(!copilot.is_acknowledged("proposal-invalid-ack"));
        assert!(copilot.interactions().is_empty());
    }

    #[test]
    fn negative_dgis_non_finite_topology_metrics_fail_closed_to_unit_risk() {
        let metrics = TopologyRiskMetrics {
            fan_out: f64::INFINITY,
            betweenness_centrality: f64::NAN,
            articulation_point: true,
            trust_bottleneck_score: f64::NEG_INFINITY,
            transitive_dependency_count: u32::MAX,
            max_depth_in_graph: u32::MAX,
        };

        let aggregate = metrics.aggregate_risk();

        assert!(aggregate.is_finite());
        assert!((0.0..=1.0).contains(&aggregate));
    }
}

#[cfg(test)]
mod dgis_module_negative_tests {
    use super::barrier_primitives::{
        BarrierEngine, BarrierError, OverrideJustification, RolloutPhase, SandboxTier,
    };
    use super::update_copilot::{
        AcknowledgementDecision, AcknowledgementReceipt, CopilotError, TopologyRiskMetrics,
        UpdateCopilot,
    };

    fn valid_ack(proposal_id: &str) -> AcknowledgementReceipt {
        AcknowledgementReceipt {
            receipt_id: format!("receipt-{proposal_id}"),
            proposal_id: proposal_id.to_string(),
            operator_identity: "operator@example.test".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "approved with monitoring".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: "abcdef0123456789".to_string(),
        }
    }

    fn valid_override() -> OverrideJustification {
        OverrideJustification {
            override_id: "override-1".to_string(),
            principal_identity: "security-lead@example.test".to_string(),
            reason: "temporary emergency exception".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: "0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn negative_acknowledgement_rejects_empty_operator_identity() {
        let mut ack = valid_ack("proposal-empty-operator");
        ack.operator_identity.clear();

        let err = ack.validate().expect_err("operator identity is required");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
    }

    #[test]
    fn negative_acknowledgement_rejects_empty_signature() {
        let mut ack = valid_ack("proposal-empty-signature");
        ack.signature_hex.clear();

        let err = ack.validate().expect_err("signature is required");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
    }

    #[test]
    fn negative_copilot_does_not_log_invalid_acknowledgement() {
        let mut copilot = UpdateCopilot::default();
        let mut ack = valid_ack("proposal-no-log");
        ack.operator_identity.clear();

        let err = copilot
            .process_acknowledgement(ack, "trace-no-log")
            .expect_err("invalid acknowledgement must fail before logging");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
        assert!(copilot.interactions().is_empty());
        assert!(!copilot.is_acknowledged("proposal-no-log"));
    }

    #[test]
    fn negative_unknown_acknowledgement_decision_variant_is_rejected() {
        let result: Result<AcknowledgementDecision, _> = serde_json::from_str(r#""cancelled""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_non_finite_topology_metrics_fail_closed_to_max_risk() {
        let metrics = TopologyRiskMetrics {
            fan_out: f64::NAN,
            betweenness_centrality: f64::INFINITY,
            articulation_point: true,
            trust_bottleneck_score: f64::NEG_INFINITY,
            transitive_dependency_count: u32::MAX,
            max_depth_in_graph: u32::MAX,
        };

        let risk = metrics.aggregate_risk();

        assert!(risk.is_finite());
        assert_eq!(risk, 1.0);
    }

    #[test]
    fn negative_override_rejects_empty_principal_identity() {
        let mut justification = valid_override();
        justification.principal_identity.clear();

        let err = justification
            .validate()
            .expect_err("principal identity is required");

        assert!(matches!(err, BarrierError::OverrideRejected(_)));
    }

    #[test]
    fn negative_override_rejects_empty_reason() {
        let mut justification = valid_override();
        justification.reason.clear();

        let err = justification.validate().expect_err("reason is required");

        assert!(matches!(err, BarrierError::OverrideRejected(_)));
    }

    #[test]
    fn negative_remove_unknown_barrier_has_no_audit_side_effect() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .remove_barrier("missing-barrier", "trace-remove-missing")
            .expect_err("missing barrier removal must fail");

        assert!(matches!(err, BarrierError::NotFound(ref id) if id == "missing-barrier"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn negative_unknown_rollout_phase_variant_is_rejected() {
        let result: Result<RolloutPhase, _> = serde_json::from_str(r#""post_general""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_unknown_sandbox_tier_variant_is_rejected() {
        let result: Result<SandboxTier, _> = serde_json::from_str(r#""root""#);

        assert!(result.is_err());
    }
}

#[cfg(test)]
mod negative_path_tests {
    use super::barrier_primitives::{
        BarrierEngine, BarrierError, BarrierType, OverrideJustification,
    };
    use super::update_copilot::{
        AcknowledgementDecision, AcknowledgementReceipt, CopilotError, TopologyRiskMetrics,
        UpdateCopilot,
    };

    fn override_justification() -> OverrideJustification {
        OverrideJustification {
            override_id: "override-negative".to_string(),
            principal_identity: "operator@example.com".to_string(),
            reason: "emergency containment drill".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: "abcd1234".to_string(),
        }
    }

    fn acknowledgement() -> AcknowledgementReceipt {
        AcknowledgementReceipt {
            receipt_id: "ack-negative".to_string(),
            proposal_id: "proposal-negative".to_string(),
            operator_identity: "operator@example.com".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "reviewed elevated risk".to_string(),
            timestamp: "2026-04-17T00:00:00Z".to_string(),
            signature_hex: "abcd1234".to_string(),
        }
    }

    #[test]
    fn override_validation_rejects_empty_principal_identity() {
        let mut justification = override_justification();
        justification.principal_identity.clear();

        let err = justification
            .validate()
            .expect_err("empty override principal must fail closed");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message)
                if message.contains("principal_identity")
        ));
    }

    #[test]
    fn override_validation_rejects_empty_reason() {
        let mut justification = override_justification();
        justification.reason.clear();

        let err = justification
            .validate()
            .expect_err("empty override reason must fail closed");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("reason")
        ));
    }

    #[test]
    fn override_validation_rejects_empty_signature() {
        let mut justification = override_justification();
        justification.signature_hex.clear();

        let err = justification
            .validate()
            .expect_err("empty override signature must fail closed");

        assert!(matches!(
            err,
            BarrierError::OverrideRejected(message) if message.contains("signature")
        ));
    }

    #[test]
    fn acknowledgement_validation_rejects_empty_operator_identity() {
        let mut receipt = acknowledgement();
        receipt.operator_identity.clear();

        let err = receipt
            .validate()
            .expect_err("empty acknowledgement operator must fail closed");

        assert!(matches!(
            err,
            CopilotError::AcknowledgementRejected(message)
                if message.contains("operator_identity")
        ));
    }

    #[test]
    fn acknowledgement_validation_rejects_empty_signature() {
        let mut receipt = acknowledgement();
        receipt.signature_hex.clear();

        let err = receipt
            .validate()
            .expect_err("empty acknowledgement signature must fail closed");

        assert!(matches!(
            err,
            CopilotError::AcknowledgementRejected(message)
                if message.contains("signature")
        ));
    }

    #[test]
    fn copilot_rejects_invalid_acknowledgement_without_recording_it() {
        let mut copilot = UpdateCopilot::default();
        let mut receipt = acknowledgement();
        receipt.signature_hex.clear();

        let err = copilot
            .process_acknowledgement(receipt, "trace-invalid-ack")
            .expect_err("invalid acknowledgement must fail closed");

        assert!(matches!(err, CopilotError::AcknowledgementRejected(_)));
        assert!(!copilot.is_acknowledged("proposal-negative"));
        assert!(copilot.interactions().is_empty());
    }

    #[test]
    fn non_finite_topology_metrics_remain_bounded() {
        let metrics = TopologyRiskMetrics {
            fan_out: f64::INFINITY,
            betweenness_centrality: f64::NAN,
            articulation_point: true,
            trust_bottleneck_score: f64::NEG_INFINITY,
            transitive_dependency_count: u32::MAX,
            max_depth_in_graph: u32::MAX,
        };

        let risk = metrics.aggregate_risk();

        assert!(risk.is_finite());
        assert!((0.0..=1.0).contains(&risk));
    }

    #[test]
    fn removing_unknown_barrier_fails_closed_without_audit() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .remove_barrier("missing-barrier", "trace-remove-missing")
            .expect_err("missing barrier removal must fail closed");

        assert!(matches!(err, BarrierError::NotFound(id) if id == "missing-barrier"));
        assert_eq!(engine.active_barrier_count(), 0);
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn recording_observation_for_unknown_rollout_fails_closed() {
        let mut engine = BarrierEngine::new();

        let err = engine
            .record_rollout_observation("missing-rollout", false)
            .expect_err("unknown rollout observation must fail closed");

        assert!(
            matches!(err, BarrierError::NotFound(message) if message.contains("missing-rollout"))
        );
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn barrier_type_rejects_unknown_json_variant() {
        let parsed: Result<BarrierType, _> = serde_json::from_str(r#""ambient_authority""#);

        assert!(parsed.is_err());
    }
}
