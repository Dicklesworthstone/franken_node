use frankenengine_node::{
    connector::vef_execution_receipt::{
        error_codes, receipt_hash_sha256, serialize_canonical, verify_hash, ExecutionActionType,
        ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    },
    vef::{
        proof_generator::{
            ComplianceProof, ConcurrentProofGenerator, ProofBackend, ProofGeneratorConfig,
            ProofGeneratorError, ProofRequest,
        },
        proof_scheduler::{ProofWindow, WorkloadTier},
        receipt_chain::{ReceiptChain, ReceiptChainConfig, ReceiptChainEntry},
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier},
};

struct BlockingBackend {
    started: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl ProofBackend for BlockingBackend {
    fn backend_name(&self) -> &str {
        "blocking-test"
    }

    fn generate(&self, request: &ProofRequest) -> Result<ComplianceProof, ProofGeneratorError> {
        self.started.wait();
        self.release.wait();
        Ok(ComplianceProof {
            proof_id: format!("proof-{}", request.request_id),
            format_version: "test-v1".to_string(),
            receipt_window_ref: request.window.window_id.clone(),
            proof_data: b"proof".to_vec(),
            proof_data_hash: "sha256:proof".to_string(),
            generated_at_millis: request.created_at_millis,
            backend_name: self.backend_name().to_string(),
            metadata: BTreeMap::new(),
            trace_id: request.trace_id.clone(),
        })
    }

    fn verify(
        &self,
        _proof: &ComplianceProof,
        _entries: &[ReceiptChainEntry],
    ) -> Result<bool, ProofGeneratorError> {
        Ok(true)
    }
}

fn receipt(sequence_number: u64) -> ExecutionReceipt {
    let mut capability_context = BTreeMap::new();
    capability_context.insert("domain".to_string(), "vef".to_string());
    capability_context.insert("capability".to_string(), "proof-generation".to_string());

    ExecutionReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        action_type: ExecutionActionType::NetworkAccess,
        capability_context,
        actor_identity: format!("actor-{sequence_number}"),
        artifact_identity: format!("artifact-{sequence_number}"),
        policy_snapshot_hash: format!("sha256:{sequence_number:064x}"),
        timestamp_millis: 10_000 + sequence_number,
        sequence_number,
        witness_references: vec![format!("witness-{sequence_number}")],
        trace_id: format!("trace-{sequence_number}"),
    }
}

fn sample_entries() -> Vec<ReceiptChainEntry> {
    let mut chain = ReceiptChain::new(ReceiptChainConfig {
        checkpoint_every_entries: 0,
        checkpoint_every_millis: 0,
    });
    chain
        .append(receipt(1), 10_001, "trace-chain")
        .expect("receipt append should succeed");
    chain.entries().to_vec()
}

fn sample_window() -> ProofWindow {
    ProofWindow {
        window_id: "window-timeout-race".to_string(),
        start_index: 0,
        end_index: 0,
        entry_count: 1,
        aligned_checkpoint_id: None,
        tier: WorkloadTier::High,
        created_at_millis: 10_000,
        trace_id: "trace-window".to_string(),
    }
}

#[test]
fn execution_receipt_hash_rejects_legacy_unframed_preimage() {
    let receipt = receipt(7);
    let canonical_bytes = serialize_canonical(&receipt).expect("receipt should serialize");
    let mut legacy_hasher = Sha256::new();
    legacy_hasher.update(b"vef_execution_receipt_v1:");
    legacy_hasher.update(canonical_bytes.as_slice());
    let legacy_hash = format!("sha256:{}", hex::encode(legacy_hasher.finalize()));

    assert_ne!(
        receipt_hash_sha256(&receipt).expect("receipt hash should compute"),
        legacy_hash
    );
    let err = verify_hash(&receipt, &legacy_hash).expect_err("legacy unframed hash must fail");
    assert_eq!(err.code, error_codes::ERR_VEF_RECEIPT_HASH_MISMATCH);
}

#[test]
fn concurrent_generator_completes_when_timeout_races_before_deadline_finish() {
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let backend = Arc::new(BlockingBackend {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    });
    let generator = Arc::new(ConcurrentProofGenerator::new(
        backend,
        ProofGeneratorConfig {
            default_timeout_millis: 1_000,
            ..ProofGeneratorConfig::default()
        },
    ));
    let entries = sample_entries();
    let window = sample_window();
    let request_id = generator
        .submit_request(&window, &entries, 10_000, "trace-submit")
        .expect("request should submit");

    let worker = {
        let generator = Arc::clone(&generator);
        let window = window.clone();
        let entries = entries.clone();
        let request_id = request_id.clone();
        std::thread::spawn(move || generator.generate_proof(&request_id, &window, &entries, 10_100))
    };

    started.wait();
    let timed_out = generator.enforce_timeouts(11_500);
    assert_eq!(timed_out, vec![request_id.clone()]);
    release.wait();

    let proof = worker
        .join()
        .expect("proof worker should not panic")
        .expect("proof completion before its deadline must win timeout race");
    assert_eq!(proof.receipt_window_ref, "window-timeout-race");
}
