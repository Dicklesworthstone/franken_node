//! Supplemental performance-path coverage for bd-1u8m proof-generation service.
//!
//! These tests focus on high-volume deterministic behavior without relying on
//! timing-sensitive assertions.

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
        ProofBackendId, ProofInputEnvelope, ProofServiceConfig, VefProofService, event_codes,
    };
    use std::collections::BTreeMap;

    fn input_for(index: u64) -> ProofInputEnvelope {
        let start_index = index * 4;
        let end_index = start_index + 3;
        let receipt_hashes = (start_index..=end_index)
            .map(|seq| format!("sha256:{:064x}", seq + 11))
            .collect::<Vec<_>>();
        ProofInputEnvelope {
            schema_version: super::proof_service::PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            job_id: format!("perf-job-{index}"),
            window_id: format!("window-{start_index}-{end_index}"),
            tier: WorkloadTier::Standard,
            trace_id: format!("trace-perf-{index}"),
            receipt_start_index: start_index,
            receipt_end_index: end_index,
            checkpoint_id: None,
            chain_head_hash: receipt_hashes
                .last()
                .cloned()
                .expect("receipt window should include hashes"),
            checkpoint_commitment_hash: None,
            policy_hash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            policy_predicates: vec![
                "policy.effect != audit_only".to_string(),
                "tier in {standard,high,critical}".to_string(),
            ],
            receipt_hashes,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn high_volume_generation_emits_one_completion_event_per_job() {
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let total_jobs: u64 = 256;
        for index in 0..total_jobs {
            let input = input_for(index);
            let proof = service
                .generate_proof(&input, None, 1_706_000_000_000 + index)
                .expect("proof generation should succeed");
            service
                .verify_proof(&input, &proof)
                .expect("generated proof should verify");
        }

        let generated_events = service
            .events()
            .iter()
            .filter(|entry| entry.event_code == event_codes::VEF_PROOF_003_PROOF_GENERATED)
            .count();
        assert_eq!(generated_events as u64, total_jobs);
    }

    #[test]
    fn proofs_are_deterministic_for_identical_inputs_per_backend() {
        let input = input_for(512);
        let mut service = VefProofService::new(ProofServiceConfig::default());

        for backend in [
            ProofBackendId::HashAttestationV1,
            ProofBackendId::DoubleHashAttestationV1,
        ] {
            let proof_a = service
                .generate_proof(&input, Some(backend), 1_706_100_000_000)
                .expect("proof A should generate");
            let proof_b = service
                .generate_proof(&input, Some(backend), 1_706_100_000_001)
                .expect("proof B should generate");

            assert_eq!(proof_a.backend_id, backend);
            assert_eq!(proof_b.backend_id, backend);
            assert_eq!(proof_a.proof_material, proof_b.proof_material);
            assert_eq!(proof_a.input_commitment_hash, proof_b.input_commitment_hash);
        }
    }

    #[test]
    fn mixed_backend_sequence_preserves_verification_integrity() {
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let total_jobs: u64 = 64;
        let mut hash_jobs = 0_u64;
        let mut double_hash_jobs = 0_u64;

        for index in 0..total_jobs {
            let input = input_for(1_000 + index);
            let backend = if index % 2 == 0 {
                hash_jobs += 1;
                ProofBackendId::HashAttestationV1
            } else {
                double_hash_jobs += 1;
                ProofBackendId::DoubleHashAttestationV1
            };
            let proof = service
                .generate_proof(&input, Some(backend), 1_706_200_000_000 + index)
                .expect("mixed backend proof generation should succeed");
            service
                .verify_proof(&input, &proof)
                .expect("mixed backend proof should verify");
        }

        let hash_selected = service
            .events()
            .iter()
            .filter(|entry| {
                entry.event_code == event_codes::VEF_PROOF_002_BACKEND_SELECTED
                    && entry.detail
                        == format!("backend={}", ProofBackendId::HashAttestationV1.as_str())
            })
            .count() as u64;
        let double_hash_selected = service
            .events()
            .iter()
            .filter(|entry| {
                entry.event_code == event_codes::VEF_PROOF_002_BACKEND_SELECTED
                    && entry.detail
                        == format!(
                            "backend={}",
                            ProofBackendId::DoubleHashAttestationV1.as_str()
                        )
            })
            .count() as u64;

        assert_eq!(hash_selected, hash_jobs);
        assert_eq!(double_hash_selected, double_hash_jobs);
    }
}
