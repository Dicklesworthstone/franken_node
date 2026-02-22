//! Supplemental conformance coverage for bd-1u8m proof-generation service.
//!
//! These tests exercise backend selection, fail-closed behavior, and
//! deterministic semantics using standalone fixture wiring.

#[path = "../../crates/franken-node/src/connector/vef_execution_receipt.rs"]
pub mod vef_execution_receipt;

mod connector {
    pub use super::vef_execution_receipt;
}

#[path = "../../crates/franken-node/src/vef/receipt_chain.rs"]
mod receipt_chain;

#[path = "../../crates/franken-node/src/vef/proof_scheduler.rs"]
mod proof_scheduler;

#[path = "../../crates/franken-node/src/vef/proof_service.rs"]
mod proof_service;

#[cfg(test)]
mod tests {
    use super::proof_scheduler::WorkloadTier;
    use super::proof_service::{
        ProofBackendId, ProofInputEnvelope, ProofServiceConfig, VefProofService, error_codes,
        event_codes,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn sample_input(start_index: u64, end_index: u64, trace_suffix: u64) -> ProofInputEnvelope {
        let receipt_hashes = (start_index..=end_index)
            .map(|index| format!("sha256:{:064x}", index + 1))
            .collect::<Vec<_>>();
        ProofInputEnvelope {
            schema_version: super::proof_service::PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            job_id: format!("job-{trace_suffix}"),
            window_id: format!("window-{start_index}-{end_index}"),
            tier: WorkloadTier::High,
            trace_id: format!("trace-{trace_suffix}"),
            receipt_start_index: start_index,
            receipt_end_index: end_index,
            checkpoint_id: None,
            chain_head_hash: receipt_hashes
                .last()
                .cloned()
                .expect("receipt window should have at least one hash"),
            checkpoint_commitment_hash: None,
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            policy_predicates: vec![
                "action_class in {network_access,secret_access}".to_string(),
                "policy.effect != audit_only".to_string(),
            ],
            receipt_hashes,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn backend_override_selects_expected_backend_and_emits_selection_event() {
        let input = sample_input(10, 19, 1);
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_000_100_000,
            )
            .expect("proof generation should succeed");
        assert_eq!(proof.backend_id, ProofBackendId::DoubleHashAttestationV1);
        service
            .verify_proof(&input, &proof)
            .expect("generated proof should verify");

        let selected_event = service
            .events()
            .iter()
            .find(|entry| entry.event_code == event_codes::VEF_PROOF_002_BACKEND_SELECTED)
            .expect("backend-selected event should be present");
        assert!(
            selected_event
                .detail
                .contains(ProofBackendId::DoubleHashAttestationV1.as_str()),
            "unexpected backend selection detail: {}",
            selected_event.detail
        );
    }

    #[test]
    fn disabled_backend_override_fails_closed() {
        let input = sample_input(0, 7, 2);
        let config = ProofServiceConfig {
            default_backend: ProofBackendId::HashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
            backend_parameters: BTreeMap::new(),
        };
        let mut service = VefProofService::new(config);
        let err = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_000_200_000,
            )
            .expect_err("disabled backend override must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
        assert!(!err.retriable, "disabled backend must be non-retriable");
    }

    #[test]
    fn timeout_failure_is_classified_and_logged() {
        let mut input = sample_input(40, 49, 3);
        input
            .metadata
            .insert("simulate_failure".to_string(), "timeout".to_string());
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let err = service
            .generate_proof(&input, None, 1_705_000_300_000)
            .expect_err("simulated timeout must fail");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_TIMEOUT);
        assert_eq!(err.event_code, event_codes::VEF_PROOF_ERR_001_TIMEOUT);
        assert!(err.retriable, "timeout should be retriable");
        assert!(
            service
                .events()
                .iter()
                .any(|entry| entry.event_code == event_codes::VEF_PROOF_001_REQUEST_RECEIVED),
            "request-received event should be recorded"
        );
    }

    #[test]
    fn backend_swap_changes_material_but_keeps_verification_semantics() {
        let input = sample_input(100, 111, 4);
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let proof_a = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_000_400_000,
            )
            .expect("hash backend proof should generate");
        let proof_b = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_000_400_001,
            )
            .expect("double-hash backend proof should generate");

        assert_ne!(proof_a.proof_material, proof_b.proof_material);
        assert_eq!(proof_a.input_commitment_hash, proof_b.input_commitment_hash);
        service
            .verify_proof(&input, &proof_a)
            .expect("proof A should verify");
        service
            .verify_proof(&input, &proof_b)
            .expect("proof B should verify");
    }
}
