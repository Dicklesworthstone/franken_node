use frankenengine_node::observability::evidence_ledger::DecisionKind;
use frankenengine_node::observability::test_support::{
    malicious_replay_bundle_locators, obs_digest, obs_entry, obs_single_witness_set, obs_witness,
    safe_replay_bundle_locators,
};
use frankenengine_node::observability::witness_ref::{
    WitnessKind, WitnessValidationError, WitnessValidator,
};
use frankenengine_node::security::quarantine_controller::{
    ControlAction, ControlDecision, DEFAULT_QUARANTINE_SCOPE, QuarantineController,
    QuarantineThresholdPolicy,
};

const VALID_EVIDENCE_HASH: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn quarantine_controller() -> QuarantineController {
    QuarantineController::new(QuarantineThresholdPolicy::default(), "salt").expect("controller")
}

fn quarantine_decision(
    controller: &QuarantineController,
    principal_id: &str,
    posterior: f64,
    trace_id: &str,
) -> ControlDecision {
    controller
        .decide_for_posterior_with_context(
            principal_id,
            posterior,
            1,
            VALID_EVIDENCE_HASH,
            DEFAULT_QUARANTINE_SCOPE,
            trace_id,
        )
        .expect("valid evidence context")
        .expect("non-finite posterior should fail closed to revoke")
}

#[test]
fn quarantine_controller_debug_redacts_hmac_signing_key() {
    let signing_key = "super-secret-quarantine-hmac-key";
    let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), signing_key)
        .expect("controller");

    let debug = format!("{controller:?}");

    assert!(debug.contains("QuarantineController"));
    assert!(debug.contains("signing_key"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(signing_key));
}

#[test]
fn quarantine_controller_signed_evidence_binds_fresh_identity_and_age() {
    let controller = quarantine_controller();
    let first = quarantine_decision(&controller, "ext:fresh", 0.91, "trace-fresh");
    let second = quarantine_decision(&controller, "ext:fresh", 0.91, "trace-fresh");

    let decision_id = uuid::Uuid::parse_str(&first.signed_evidence.decision_id)
        .expect("decision id should be a UUID");
    assert_eq!(decision_id.get_version(), Some(uuid::Version::SortRand));
    assert_ne!(
        first.signed_evidence.decision_id,
        second.signed_evidence.decision_id
    );
    assert_ne!(
        first.signed_evidence.signature,
        second.signed_evidence.signature
    );
    assert!(first.signed_evidence.issued_at_ms > 0);
    assert!(controller.verify_signature(&first.signed_evidence));

    let issued_at_ms = first.signed_evidence.issued_at_ms;
    assert!(controller.verify_signed_decision(
        &first.signed_evidence,
        issued_at_ms.saturating_add(999),
        1_000
    ));
    assert!(!controller.verify_signed_decision(
        &first.signed_evidence,
        issued_at_ms.saturating_add(1_000),
        1_000
    ));
    assert!(!controller.verify_signed_decision(
        &first.signed_evidence,
        issued_at_ms.saturating_sub(1),
        1_000
    ));
}

#[test]
fn quarantine_controller_signed_evidence_rejects_freshness_field_tampering() {
    let controller = quarantine_controller();
    let mut decision = quarantine_decision(&controller, "ext:tamper", 0.91, "trace-tamper");

    assert!(controller.verify_signature(&decision.signed_evidence));

    decision.signed_evidence.decision_id = uuid::Uuid::now_v7().to_string();
    assert!(!controller.verify_signature(&decision.signed_evidence));

    let mut decision = quarantine_decision(&controller, "ext:tamper", 0.91, "trace-tamper");
    decision.signed_evidence.issued_at_ms = decision.signed_evidence.issued_at_ms.saturating_add(1);
    assert!(!controller.verify_signature(&decision.signed_evidence));
}

#[test]
fn observability_adversarial_regressions_locator_injection_attacks_fail_closed() {
    for locator in malicious_replay_bundle_locators() {
        let entry = obs_entry("obs-locator-injection", DecisionKind::Quarantine);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-malicious-locator", WitnessKind::ProofArtifact, 42)
                .with_locator(locator.clone()),
        );
        let mut validator = WitnessValidator::strict();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("strict validator must reject unsafe replay bundle locators");

        assert!(
            matches!(
                err,
                WitnessValidationError::UnresolvableLocator { .. }
                    | WitnessValidationError::MissingWitnesses { .. }
            ),
            "unexpected error for locator {locator:?}: {err:?}"
        );
        assert_eq!(validator.rejected_count(), 1);
        assert_eq!(validator.validated_count(), 0);
    }
}

#[test]
fn observability_adversarial_regressions_safe_relative_locators_pass_strict() {
    for locator in safe_replay_bundle_locators() {
        let entry = obs_entry("obs-safe-locator", DecisionKind::Quarantine);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-safe-locator-witness", WitnessKind::ProofArtifact, 43)
                .with_locator(*locator),
        );
        let mut validator = WitnessValidator::strict();

        validator
            .validate(&entry, &witnesses)
            .expect("strict validator should accept safe relative replay bundle locators");

        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 0);
    }
}

#[test]
fn observability_adversarial_regressions_hash_collision_attempts_fail_integrity() {
    let collision_attempts = [
        ([0x00; 32], "zero digest"),
        ([0x01; 32], "one digest"),
        ([0xff; 32], "max digest"),
        ([0xaa; 32], "alternating high bits"),
        ([0x55; 32], "alternating low bits"),
    ];
    let witness = obs_witness("obs-collision-witness", WitnessKind::StateSnapshot, 50);
    let mut validator = WitnessValidator::new();

    for (malicious_digest, description) in collision_attempts {
        assert_ne!(obs_digest(50), malicious_digest);
        let err = validator
            .verify_integrity("obs-collision-entry", &witness, &malicious_digest)
            .expect_err("hash collision attempt should fail integrity check");

        assert_eq!(
            err.code(),
            "ERR_INTEGRITY_HASH_MISMATCH",
            "unexpected integrity error for {description}"
        );
    }

    assert_eq!(validator.validated_count(), 0);
    assert_eq!(
        validator.rejected_count(),
        u64::try_from(collision_attempts.len()).unwrap_or(u64::MAX)
    );
}

#[test]
fn observability_adversarial_regressions_high_impact_missing_witness_is_typed() {
    let entry = obs_entry("obs-high-impact-missing", DecisionKind::Release);
    let witnesses = frankenengine_node::observability::witness_ref::WitnessSet::new();
    let mut validator = WitnessValidator::new();

    let err = validator
        .validate(&entry, &witnesses)
        .expect_err("release decisions without witnesses must fail closed");

    assert!(matches!(
        err,
        WitnessValidationError::MissingWitnesses { ref entry_id, .. }
            if entry_id == "obs-high-impact-missing"
    ));
    assert_eq!(err.code(), "ERR_MISSING_WITNESSES");
    assert_eq!(validator.rejected_count(), 1);
    assert_eq!(validator.validated_count(), 0);
}

#[test]
fn quarantine_controller_clamps_nan_posterior_before_signing() {
    let controller = quarantine_controller();
    let decision = quarantine_decision(&controller, "ext:nan", f64::NAN, "trace-nan");

    assert_eq!(decision.action, ControlAction::Revoke);
    assert_eq!(decision.posterior, controller.policy().revoke);
    assert_eq!(
        decision.signed_evidence.posterior,
        controller.policy().revoke
    );
    assert!(decision.posterior.is_finite());
    assert!(decision.signed_evidence.posterior.is_finite());
    assert!(controller.verify_decision(&decision));

    let json = serde_json::to_string(&decision).expect("finite clamped decision should serialize");
    assert!(!json.contains("NaN"));
    assert!(!json.contains("null"));
}

#[test]
fn quarantine_controller_clamps_infinite_posteriors_before_signing() {
    let controller = quarantine_controller();

    for (principal_id, posterior) in [
        ("ext:positive-limit", f64::INFINITY),
        ("ext:negative-limit", f64::NEG_INFINITY),
    ] {
        let decision = quarantine_decision(&controller, principal_id, posterior, "trace-boundary");

        assert_eq!(decision.action, ControlAction::Revoke);
        assert_eq!(decision.posterior, controller.policy().revoke);
        assert_eq!(
            decision.signed_evidence.posterior,
            controller.policy().revoke
        );
        assert!(decision.posterior.is_finite());
        assert!(decision.signed_evidence.posterior.is_finite());
        assert!(controller.verify_decision(&decision));

        let json =
            serde_json::to_string(&decision).expect("finite clamped decision should serialize");
        assert!(!json.contains("inf"));
        assert!(!json.contains("null"));
    }
}
