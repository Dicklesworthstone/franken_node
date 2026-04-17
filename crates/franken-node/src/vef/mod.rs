pub mod constraint_compiler;
pub mod control_integration;
pub mod evidence_capsule;
pub mod proof_generator;
pub mod proof_scheduler;
pub mod proof_service;
pub mod proof_verifier;
pub mod receipt_chain;
pub mod sdk_integration;
pub mod verification_state;

// Re-export connector for sibling VEF modules so they can be compiled both
// from the crate root and from standalone test fixtures.
pub(crate) use crate::connector;

#[cfg(test)]
mod proof_verifier_conformance_tests;

#[cfg(test)]
mod negative_path_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::proof_scheduler::WorkloadTier;
    use super::proof_service::{
        PROOF_SERVICE_SCHEMA_VERSION, ProofBackendId, ProofInputEnvelope, ProofServiceConfig,
        VefProofService, error_codes,
    };

    fn sha256_fill(digit: char) -> String {
        format!(
            "sha256:{}",
            std::iter::repeat(digit).take(64).collect::<String>()
        )
    }

    fn valid_input() -> ProofInputEnvelope {
        ProofInputEnvelope {
            schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            job_id: "job-root-negative".to_string(),
            window_id: "window-root-negative".to_string(),
            tier: WorkloadTier::High,
            trace_id: "trace-root-negative".to_string(),
            receipt_start_index: 7,
            receipt_end_index: 8,
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
    fn proof_input_rejects_blank_job_identity() {
        let mut input = valid_input();
        input.job_id = "   ".to_string();

        let err = input
            .validate()
            .expect_err("blank proof job id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("job_id"));
        assert!(!err.retriable);
    }

    #[test]
    fn proof_input_rejects_malformed_checkpoint_commitment_hash() {
        let mut input = valid_input();
        input.checkpoint_commitment_hash = Some("sha256:not-valid-hex".to_string());

        let err = input
            .validate()
            .expect_err("malformed checkpoint commitment must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("checkpoint_commitment_hash"));
    }

    #[test]
    fn proof_input_rejects_malformed_policy_hash() {
        let mut input = valid_input();
        input.policy_hash = "policy:unsigned".to_string();

        let err = input
            .validate()
            .expect_err("policy hash without sha256 envelope must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("policy_hash"));
    }

    #[test]
    fn proof_service_rejects_unknown_simulated_failure_mode() {
        let mut input = valid_input();
        input
            .metadata
            .insert("simulate_failure".to_string(), "latency_spike".to_string());
        let mut service = VefProofService::new(ProofServiceConfig::default());

        let err = service
            .generate_proof(&input, None, 1_705_400_000_000)
            .expect_err("unknown simulated backend failure mode must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("unknown simulate_failure mode"));
        assert!(!err.retriable);
    }

    #[test]
    fn proof_service_rejects_disabled_default_backend() {
        let input = valid_input();
        let config = ProofServiceConfig {
            default_backend: ProofBackendId::DoubleHashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
            backend_parameters: BTreeMap::new(),
        };
        let mut service = VefProofService::new(config);

        let err = service
            .generate_proof(&input, None, 1_705_400_000_100)
            .expect_err("disabled default backend must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn proof_output_rejects_schema_downgrade() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_200,
            )
            .expect("generate proof for tamper test");
        proof.schema_version = "vef-proof-service-v0".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("proof schema downgrade must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("schema_version"));
    }

    #[test]
    fn proof_output_rejects_empty_trace_id() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_300,
            )
            .expect("generate proof for trace test");
        proof.trace_id.clear();

        let err = proof
            .validate_against(&input)
            .expect_err("empty proof trace id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("trace_id"));
    }

    #[test]
    fn proof_output_rejects_trace_mismatch() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_400,
            )
            .expect("generate proof for trace mismatch test");
        proof.trace_id = "trace-from-other-request".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("trace mismatch must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("trace_id mismatch"));
    }

    #[test]
    fn proof_verification_rejects_tampered_material() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_500,
            )
            .expect("generate proof for material tamper test");
        proof.proof_material = sha256_fill('f');

        let err = service
            .verify_proof(&input, &proof)
            .expect_err("tampered proof material must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("proof material mismatch"));
    }

    #[test]
    fn proof_verification_rejects_backend_disabled_after_generation() {
        let input = valid_input();
        let mut generator = VefProofService::new(ProofServiceConfig::default());
        let proof = generator
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_600,
            )
            .expect("generate proof with hash backend");
        let verifier_config = ProofServiceConfig {
            default_backend: ProofBackendId::DoubleHashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::DoubleHashAttestationV1]),
            backend_parameters: BTreeMap::new(),
        };
        let verifier = VefProofService::new(verifier_config);

        let err = verifier
            .verify_proof(&input, &proof)
            .expect_err("proof from disabled backend must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn proof_input_rejects_schema_version_mismatch() {
        let mut input = valid_input();
        input.schema_version = "vef-proof-service-v0".to_string();

        let err = input
            .validate()
            .expect_err("proof input schema downgrade must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("schema_version"));
        assert!(!err.retriable);
    }

    #[test]
    fn proof_input_rejects_reversed_receipt_range() {
        let mut input = valid_input();
        input.receipt_start_index = 9;
        input.receipt_end_index = 8;

        let err = input
            .validate()
            .expect_err("reversed receipt range must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("invalid receipt range"));
    }

    #[test]
    fn proof_input_rejects_receipt_hash_count_mismatch() {
        let mut input = valid_input();
        input
            .receipt_hashes
            .pop()
            .expect("fixture starts with two receipt hashes");

        let err = input
            .validate()
            .expect_err("receipt hash count mismatch must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("receipt hash count mismatch"));
    }

    #[test]
    fn proof_input_rejects_malformed_receipt_hash() {
        let mut input = valid_input();
        input.receipt_hashes[1] = "sha256:not-hex".to_string();

        let err = input
            .validate()
            .expect_err("malformed receipt hash must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("receipt hashes"));
    }

    #[test]
    fn proof_input_rejects_blank_policy_predicate() {
        let mut input = valid_input();
        input.policy_predicates.push(" \t ".to_string());

        let err = input
            .validate()
            .expect_err("blank policy predicate must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("policy_predicates"));
    }

    #[test]
    fn proof_input_commitment_rejects_bad_chain_head_hash() {
        let mut input = valid_input();
        input.chain_head_hash = "sha256:bad".to_string();

        let err = input
            .commitment_hash()
            .expect_err("bad chain head hash must block commitment creation");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("chain_head_hash"));
    }

    #[test]
    fn proof_output_rejects_blank_proof_id() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_700,
            )
            .expect("generate proof for blank proof id test");
        proof.proof_id = "  ".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("blank proof id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("proof_id"));
    }

    #[test]
    fn proof_output_rejects_malformed_input_commitment_hash() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_800,
            )
            .expect("generate proof for malformed input commitment test");
        proof.input_commitment_hash = "not-sha256".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("malformed input commitment hash must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("input_commitment_hash"));
    }

    #[test]
    fn proof_input_rejects_blank_window_identity() {
        let mut input = valid_input();
        input.window_id = "\n\t ".to_string();

        let err = input
            .validate()
            .expect_err("blank proof window id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("window_id"));
        assert!(!err.retriable);
    }

    #[test]
    fn proof_input_rejects_blank_trace_identity() {
        let mut input = valid_input();
        input.trace_id.clear();

        let err = input
            .validate()
            .expect_err("blank proof trace id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("trace_id"));
        assert!(!err.retriable);
    }

    #[test]
    fn proof_input_rejects_uppercase_sha256_prefix() {
        let mut input = valid_input();
        input.chain_head_hash =
            "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let err = input
            .validate()
            .expect_err("uppercase hash prefix must not be normalized");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("chain_head_hash"));
    }

    #[test]
    fn proof_output_rejects_blank_backend_version() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_000_900,
            )
            .expect("generate proof for backend version test");
        proof.backend_version = " \t ".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("blank backend version must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("backend_version"));
    }

    #[test]
    fn proof_output_rejects_malformed_proof_material() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_001_000,
            )
            .expect("generate proof for proof material test");
        proof.proof_material = "sha256:zzzz".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("malformed proof material must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("proof_material"));
    }

    #[test]
    fn proof_output_rejects_well_formed_commitment_mismatch() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_001_100,
            )
            .expect("generate proof for commitment mismatch test");
        proof.input_commitment_hash = sha256_fill('9');

        let err = proof
            .validate_against(&input)
            .expect_err("well-formed but wrong commitment must fail verification");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("input commitment mismatch"));
    }

    #[test]
    fn proof_verification_rejects_backend_id_tamper() {
        let input = valid_input();
        let mut service = VefProofService::new(ProofServiceConfig::default());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_400_001_200,
            )
            .expect("generate proof for backend tamper test");
        proof.backend_id = ProofBackendId::DoubleHashAttestationV1;

        let err = service
            .verify_proof(&input, &proof)
            .expect_err("backend id tamper must fail proof verification");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("proof material mismatch"));
    }
}
