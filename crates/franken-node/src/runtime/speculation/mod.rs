pub mod proof_executor;

#[cfg(test)]
mod tests {
    use super::proof_executor::{
        ActivationDecision, BaselineMode, GuardConfig, GuardFailureReason, ProofExecutor,
        SpeculationTransform, deterministic_baseline_digest, make_receipt,
    };

    const APPROVED_INTERFACE: &str = "franken_engine::speculative_hotpath";
    const ACCEPTED_SIGNER: &str = "validator-A";
    const NOW_EPOCH_MS: u64 = 10_000;
    const FUTURE_EPOCH_MS: u64 = 20_000;

    fn executor() -> ProofExecutor {
        ProofExecutor::new(
            GuardConfig::new(NOW_EPOCH_MS)
                .with_interface(APPROVED_INTERFACE)
                .with_signer(ACCEPTED_SIGNER),
        )
    }

    fn valid_receipt() -> super::proof_executor::ProofReceipt {
        make_receipt(
            "receipt-negative-path",
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            ACCEPTED_SIGNER,
            FUTURE_EPOCH_MS,
            "trace-negative-path",
        )
    }

    fn assert_degraded(decision: &ActivationDecision, expected: GuardFailureReason) {
        assert!(
            matches!(
                decision,
                ActivationDecision::Degraded { reason, .. } if reason == &expected
            ),
            "expected degraded decision with {expected:?}, got {decision:?}"
        );
    }

    fn assert_degraded_baseline(
        outcome: &super::proof_executor::ExecutionOutcome,
        expected: GuardFailureReason,
        baseline_input: &[u8],
    ) {
        assert_degraded(&outcome.decision, expected);
        let expected_digest = deterministic_baseline_digest(baseline_input);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
    }

    #[test]
    fn negative_empty_approval_set_rejects_valid_receipt() {
        let receipt = valid_receipt();
        let executor =
            ProofExecutor::new(GuardConfig::new(NOW_EPOCH_MS).with_signer(ACCEPTED_SIGNER));

        let decision = executor.evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::InterfaceUnapproved);
    }

    #[test]
    fn negative_empty_signer_set_rejects_valid_receipt() {
        let receipt = valid_receipt();
        let executor =
            ProofExecutor::new(GuardConfig::new(NOW_EPOCH_MS).with_interface(APPROVED_INTERFACE));

        let decision = executor.evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::SignatureInvalid);
    }

    #[test]
    fn negative_receipt_expiring_at_now_is_fail_closed() {
        let receipt = make_receipt(
            "receipt-expiry-boundary",
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            ACCEPTED_SIGNER,
            NOW_EPOCH_MS,
            "trace-expiry-boundary",
        );

        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::ExpiredReceipt);
    }

    #[test]
    fn negative_expiry_tampering_invalidates_receipt_signature() {
        let mut receipt = valid_receipt();
        receipt.expires_epoch_ms = FUTURE_EPOCH_MS.saturating_add(1);

        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::SignatureInvalid);
    }

    #[test]
    fn negative_signer_tampering_invalidates_receipt_signature() {
        let mut receipt = valid_receipt();
        receipt.signer_id = "validator-B".to_string();
        let executor = ProofExecutor::new(
            GuardConfig::new(NOW_EPOCH_MS)
                .with_interface(APPROVED_INTERFACE)
                .with_signer(ACCEPTED_SIGNER)
                .with_signer("validator-B"),
        );

        let decision = executor.evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::SignatureInvalid);
    }

    #[test]
    fn negative_transform_mismatch_precedes_expiry_failure() {
        let expired_receipt = make_receipt(
            "receipt-expired-transform",
            SpeculationTransform::ParallelProbe,
            APPROVED_INTERFACE,
            ACCEPTED_SIGNER,
            NOW_EPOCH_MS.saturating_sub(1),
            "trace-expired-transform",
        );

        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&expired_receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::TransformMismatch);
    }

    #[test]
    fn negative_guard_failure_uses_safe_baseline_digest() {
        let receipt = valid_receipt();
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            false,
            b"baseline-input",
        );
        let expected_digest = deterministic_baseline_digest(b"baseline-input");

        assert_degraded(&outcome.decision, GuardFailureReason::GuardRejected);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
    }

    #[test]
    fn negative_missing_receipt_precedes_guard_failure() {
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            None,
            false,
            b"missing-receipt-baseline",
        );

        assert_degraded(&outcome.decision, GuardFailureReason::MissingReceipt);
        assert_eq!(outcome.trace_id, "trace:missing-proof");
    }

    #[test]
    fn negative_unknown_transform_variant_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<SpeculationTransform>(r#""branch_prediction""#);

        assert!(decoded.is_err());
    }

    #[test]
    fn negative_unknown_failure_reason_variant_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<GuardFailureReason>(r#""policy_denied""#);

        assert!(decoded.is_err());
    }

    #[test]
    fn negative_receipt_for_other_interface_uses_baseline() {
        let receipt = make_receipt(
            "receipt-other-interface",
            SpeculationTransform::CacheWarmup,
            "franken_engine::other_hotpath",
            ACCEPTED_SIGNER,
            FUTURE_EPOCH_MS,
            "trace-other-interface",
        );
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            b"interface-mismatch-baseline",
        );
        let expected_digest = deterministic_baseline_digest(b"interface-mismatch-baseline");

        assert_degraded(&outcome.decision, GuardFailureReason::InterfaceMismatch);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
    }

    #[test]
    fn negative_whitespace_padded_receipt_interface_is_not_normalized() {
        let receipt = make_receipt(
            "receipt-padded-interface",
            SpeculationTransform::CacheWarmup,
            " franken_engine::speculative_hotpath ",
            ACCEPTED_SIGNER,
            FUTURE_EPOCH_MS,
            "trace-padded-interface",
        );

        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::InterfaceMismatch);
    }

    #[test]
    fn negative_blank_receipt_id_degrades_to_baseline() {
        let mut receipt = valid_receipt();
        receipt.receipt_id.clear();
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            b"blank-receipt-id-baseline",
        );
        let expected_digest = deterministic_baseline_digest(b"blank-receipt-id-baseline");

        assert_degraded(&outcome.decision, GuardFailureReason::SignatureInvalid);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
    }

    #[test]
    fn negative_blank_trace_id_degrades_to_baseline() {
        let mut receipt = valid_receipt();
        receipt.trace_id.clear();
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            b"blank-trace-id-baseline",
        );
        let expected_digest = deterministic_baseline_digest(b"blank-trace-id-baseline");

        assert_degraded(&outcome.decision, GuardFailureReason::SignatureInvalid);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
        assert!(outcome.trace_id.is_empty());
    }

    #[test]
    fn negative_unapproved_interface_ignores_valid_receipt() {
        let receipt = make_receipt(
            "receipt-unapproved-interface",
            SpeculationTransform::CacheWarmup,
            "franken_engine::unapproved_hotpath",
            ACCEPTED_SIGNER,
            FUTURE_EPOCH_MS,
            "trace-unapproved-interface",
        );
        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            "franken_engine::unapproved_hotpath",
            Some(&receipt),
            true,
            b"unapproved-interface-baseline",
        );
        let expected_digest = deterministic_baseline_digest(b"unapproved-interface-baseline");

        assert_degraded(&outcome.decision, GuardFailureReason::InterfaceUnapproved);
        assert!(crate::security::constant_time::ct_eq(
            &outcome.output_digest,
            &expected_digest
        ));
    }

    #[test]
    fn negative_unknown_activation_decision_variant_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<ActivationDecision>(
            r#"{"speculation_allowed":{"receipt_id":"r1"}}"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn negative_unknown_baseline_mode_variant_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<BaselineMode>(r#""best_effort_fast_path""#);

        assert!(decoded.is_err());
    }

    #[test]
    fn negative_requested_interface_padding_is_unapproved_before_receipt_check() {
        let receipt = valid_receipt();
        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            " franken_engine::speculative_hotpath ",
            Some(&receipt),
            true,
        );

        assert_degraded(&decision, GuardFailureReason::InterfaceUnapproved);
    }

    #[test]
    fn negative_proof_hash_tampering_degrades_to_baseline() {
        let mut receipt = valid_receipt();
        receipt.proof_hash = format!("{}00", receipt.proof_hash);
        let baseline_input = b"tampered-proof-hash-baseline";

        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            baseline_input,
        );

        assert_degraded_baseline(
            &outcome,
            GuardFailureReason::SignatureInvalid,
            baseline_input,
        );
        assert_eq!(outcome.trace_id, "trace-negative-path");
    }

    #[test]
    fn negative_blank_proof_hash_degrades_to_baseline() {
        let mut receipt = valid_receipt();
        receipt.proof_hash.clear();
        let baseline_input = b"blank-proof-hash-baseline";

        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            baseline_input,
        );

        assert_degraded_baseline(
            &outcome,
            GuardFailureReason::SignatureInvalid,
            baseline_input,
        );
    }

    #[test]
    fn negative_padded_signature_degrades_to_baseline() {
        let mut receipt = valid_receipt();
        let padded_signature = format!(" {} ", receipt.signature);
        receipt.signature = padded_signature;
        let baseline_input = b"padded-signature-baseline";

        let outcome = executor().execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            baseline_input,
        );

        assert_degraded_baseline(
            &outcome,
            GuardFailureReason::SignatureInvalid,
            baseline_input,
        );
    }

    #[test]
    fn negative_padded_signer_id_rejected_even_if_config_accepts_literal() {
        let receipt = make_receipt(
            "receipt-padded-signer",
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            " validator-A ",
            FUTURE_EPOCH_MS,
            "trace-padded-signer",
        );
        let executor = ProofExecutor::new(
            GuardConfig::new(NOW_EPOCH_MS)
                .with_interface(APPROVED_INTERFACE)
                .with_signer(" validator-A "),
        );
        let baseline_input = b"padded-signer-baseline";

        let outcome = executor.execute_with_fallback(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            true,
            baseline_input,
        );

        assert_degraded_baseline(
            &outcome,
            GuardFailureReason::SignatureInvalid,
            baseline_input,
        );
        assert_eq!(outcome.trace_id, "trace-padded-signer");
    }

    #[test]
    fn negative_invalid_signature_precedes_guard_rejection() {
        let mut receipt = valid_receipt();
        receipt.signature = "tampered-signature".to_string();

        let decision = executor().evaluate_activation(
            SpeculationTransform::CacheWarmup,
            APPROVED_INTERFACE,
            Some(&receipt),
            false,
        );

        assert_degraded(&decision, GuardFailureReason::SignatureInvalid);
    }

    #[test]
    fn negative_degraded_decision_missing_baseline_mode_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<ActivationDecision>(
            r#"{"degraded":{"reason":"missing_receipt","event_code":"SPECULATION_DEGRADED"}}"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn negative_activated_decision_missing_event_code_is_rejected_by_serde() {
        let decoded = serde_json::from_str::<ActivationDecision>(
            r#"{"activated":{"receipt_id":"r1","interface_id":"franken_engine::speculative_hotpath"}}"#,
        );

        assert!(decoded.is_err());
    }
}
