use frankenengine_node::vef::proof_scheduler::WorkloadTier;
use frankenengine_node::vef::proof_service::{
    PROOF_SERVICE_SCHEMA_VERSION, ProofBackendId, ProofInputEnvelope, ProofServiceConfig,
    VefProofService, error_codes,
};
use std::collections::{BTreeMap, BTreeSet};

fn sha256_fill(digit: char) -> String {
    format!(
        "sha256:{}",
        std::iter::repeat_n(digit, 64).collect::<String>()
    )
}

fn sample_input() -> ProofInputEnvelope {
    ProofInputEnvelope {
        schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
        job_id: "job-fail-closed".to_string(),
        window_id: "window-fail-closed".to_string(),
        tier: WorkloadTier::High,
        trace_id: "trace-fail-closed".to_string(),
        receipt_start_index: 10,
        receipt_end_index: 11,
        checkpoint_id: None,
        chain_head_hash: sha256_fill('a'),
        checkpoint_commitment_hash: Some(sha256_fill('b')),
        policy_hash: sha256_fill('c'),
        policy_predicates: vec!["receipt.integrity verified".to_string()],
        receipt_hashes: vec![sha256_fill('d'), sha256_fill('e')],
        metadata: BTreeMap::new(),
    }
}

#[test]
fn generate_rejects_missing_enabled_backend_parameters() {
    let input = sample_input();
    let config = ProofServiceConfig {
        default_backend: ProofBackendId::HashAttestationV1,
        enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
        backend_parameters: BTreeMap::new(),
    };
    let mut service = VefProofService::new(config);

    let err = service
        .generate_proof(&input, None, 1_706_100_000_000)
        .expect_err("enabled backend without backend_parameters must fail closed");

    assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
    assert!(err.message.contains("missing backend_parameters"));
    assert!(!err.retriable);
}

#[test]
fn verify_rejects_missing_enabled_backend_parameters() {
    let input = sample_input();
    let mut generating_service =
        VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
    let proof = generating_service
        .generate_proof(
            &input,
            Some(ProofBackendId::HashAttestationV1),
            1_706_100_000_100,
        )
        .expect("generate proof with fully configured service");

    let verifying_service = VefProofService::new(ProofServiceConfig {
        default_backend: ProofBackendId::HashAttestationV1,
        enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
        backend_parameters: BTreeMap::new(),
    });

    let err = verifying_service
        .verify_proof(&input, &proof)
        .expect_err("verification without backend_parameters must fail closed");

    assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
    assert!(err.message.contains("missing backend_parameters"));
    assert!(!err.retriable);
}

#[test]
fn default_config_rejects_generate_until_backend_is_explicitly_enabled() {
    let input = sample_input();
    let mut service = VefProofService::new(ProofServiceConfig::default());

    let err = service
        .generate_proof(&input, None, 1_706_100_000_200)
        .expect_err("default proof-service config must fail closed");

    assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
    assert!(err.message.contains("not enabled"));
    assert!(!err.retriable);
}

#[test]
fn simulate_failure_metadata_does_not_trigger_production_fault_injection() {
    let mut input = sample_input();
    input
        .metadata
        .insert("simulate_failure".to_string(), "timeout".to_string());
    let mut service = VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

    let proof = service
        .generate_proof(&input, None, 1_706_100_000_300)
        .expect("simulate_failure metadata must not bypass backend generation");

    service
        .verify_proof(&input, &proof)
        .expect("proof generated with ordinary metadata should verify");
}
