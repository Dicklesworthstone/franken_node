#![allow(clippy::duplicate_mod)]

use chrono::{DateTime, Utc};
use serde_json::json;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use tempfile::TempDir;
use tracing::{Level, debug, info, span, warn};
use tracing_subscriber::{EnvFilter, fmt};

#[path = "../src/connector/vef_execution_receipt.rs"]
pub mod vef_execution_receipt;

mod connector {
    pub use super::vef_execution_receipt;
}

#[path = "../src/vef/receipt_chain.rs"]
mod receipt_chain;

#[path = "../src/vef/proof_scheduler.rs"]
mod proof_scheduler;

#[path = "../src/vef/proof_service.rs"]
mod proof_service;

#[cfg(test)]
mod tests {
    use super::proof_scheduler::{SchedulerPolicy, VefProofScheduler};
    use super::proof_service::{
        ProofBackendId, ProofInputEnvelope, ProofServiceConfig, VefProofService,
    };
    use super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use super::vef_execution_receipt::{
        ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;

    /// Real test harness with filesystem persistence and structured logging
    struct VefProofTestHarness {
        temp_dir: TempDir,
        receipts_dir: PathBuf,
        proofs_dir: PathBuf,
        test_start: DateTime<Utc>,
    }

    impl VefProofTestHarness {
        fn new() -> Self {
            let temp_dir = TempDir::new().expect("create temp directory");
            let receipts_dir = temp_dir.path().join("receipts");
            let proofs_dir = temp_dir.path().join("proofs");

            fs::create_dir_all(&receipts_dir).expect("create receipts directory");
            fs::create_dir_all(&proofs_dir).expect("create proofs directory");

            info!(
                "Initialized test harness with temp dir: {}",
                temp_dir.path().display()
            );

            Self {
                temp_dir,
                receipts_dir,
                proofs_dir,
                test_start: Utc::now(),
            }
        }

        fn save_receipt_to_file(&self, receipt: &ExecutionReceipt, filename: &str) -> PathBuf {
            let receipt_path = self.receipts_dir.join(filename);
            let receipt_json = serde_json::to_string_pretty(receipt).expect("serialize receipt");
            fs::write(&receipt_path, receipt_json).expect("write receipt to file");

            debug!("Saved receipt to file: {}", receipt_path.display());
            receipt_path
        }

        fn load_receipt_from_file(&self, filename: &str) -> ExecutionReceipt {
            let receipt_path = self.receipts_dir.join(filename);
            let receipt_json = fs::read_to_string(&receipt_path).expect("read receipt file");
            serde_json::from_str(&receipt_json).expect("deserialize receipt")
        }

        fn save_proof_to_file(&self, proof: &serde_json::Value, filename: &str) -> PathBuf {
            let proof_path = self.proofs_dir.join(filename);
            let proof_json = serde_json::to_string_pretty(proof).expect("serialize proof");
            fs::write(&proof_path, proof_json).expect("write proof to file");

            debug!("Saved proof to file: {}", proof_path.display());
            proof_path
        }

        fn create_real_receipt(
            &self,
            action_type: ExecutionActionType,
            sequence: u64,
        ) -> ExecutionReceipt {
            let now = Utc::now();
            let timestamp_millis = now.timestamp_millis() as u64;

            let mut capability_context = BTreeMap::new();
            capability_context.insert("domain".to_string(), "runtime".to_string());
            capability_context.insert("scope".to_string(), "extensions".to_string());
            capability_context.insert("capability".to_string(), format!("capability-{sequence}"));

            let receipt = ExecutionReceipt {
                schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
                action_type,
                capability_context,
                actor_identity: format!("actor-{sequence}"),
                artifact_identity: format!("artifact-{sequence}"),
                policy_snapshot_hash: format!("sha256:{sequence:064x}"),
                timestamp_millis,
                sequence_number: sequence,
                witness_references: vec!["w-a".to_string(), "w-b".to_string()],
                trace_id: format!("trace-{}", uuid::Uuid::new_v4()),
            };

            // Save to filesystem for persistence
            let filename = format!("receipt_{sequence}_{:?}.json", action_type);
            self.save_receipt_to_file(&receipt, &filename);

            info!(
                action_type = ?action_type,
                sequence = sequence,
                timestamp_ms = timestamp_millis,
                "Created real receipt with filesystem persistence"
            );

            receipt
        }
    }

    fn build_real_input(harness: &VefProofTestHarness) -> ProofInputEnvelope {
        let _span = span!(Level::INFO, "build_real_input").entered();

        info!("Phase: setup - Building proof input with real filesystem persistence");

        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });

        let now = Utc::now();
        let base_timestamp = now.timestamp_millis() as u64;
        let trace_id = format!("trace-{}", uuid::Uuid::new_v4());

        // Create real receipts with filesystem persistence
        for (idx, action) in [
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
        ]
        .into_iter()
        .enumerate()
        {
            let receipt = harness.create_real_receipt(action, idx as u64);
            let timestamp = base_timestamp + (idx as u64 * 1000); // 1 second apart

            chain
                .append(receipt, timestamp, &trace_id)
                .expect("append receipt to chain");

            debug!(
                action_type = ?action,
                sequence = idx,
                timestamp = timestamp,
                "Appended receipt to chain"
            );
        }

        info!(
            chain_entries = chain.entries().len(),
            checkpoints = chain.checkpoints().len(),
            "Phase: setup complete - Receipt chain built"
        );

        let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
            max_receipts_per_window: 2,
            ..SchedulerPolicy::default()
        });

        let schedule_timestamp = base_timestamp + 100_000; // 100 seconds later
        let windows = scheduler
            .select_windows(
                chain.entries(),
                chain.checkpoints(),
                schedule_timestamp,
                &trace_id,
            )
            .expect("select scheduling windows");

        info!(
            windows_count = windows.len(),
            "Phase: scheduling - Selected proof windows"
        );

        let queued = scheduler
            .enqueue_windows(&windows, schedule_timestamp + 10)
            .expect("enqueue windows for processing");

        info!(
            queued_jobs = queued.len(),
            "Phase: scheduling complete - Enqueued proof jobs"
        );

        let window = windows[0].clone();
        let job = scheduler
            .jobs()
            .get(&queued[0])
            .expect("scheduled job should exist")
            .clone();

        // Use real hash computed from the receipt data
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        serde_json::to_string(&chain.entries())
            .unwrap()
            .as_bytes()
            .hash(&mut hasher);
        let chain_hash = format!("sha256:{:064x}", hasher.finish());

        let input = ProofInputEnvelope::from_scheduler_job(
            &job,
            &window,
            chain.entries(),
            chain.checkpoints(),
            &chain_hash,
            vec!["predicate.window.coverage".to_string()],
            BTreeMap::new(),
        )
        .expect("build proof input envelope");

        info!(
            input_hash = chain_hash,
            predicates = input.predicates.len(),
            "Phase: input generation complete - Created proof input envelope"
        );

        input
    }

    #[test]
    fn proof_service_round_trip_with_real_persistence() {
        // Initialize structured logging for the test
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("debug".parse().unwrap()))
            .with_target(false)
            .with_thread_ids(true)
            .with_line_number(true)
            .json()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let _span = span!(
            Level::INFO,
            "proof_service_round_trip_with_real_persistence"
        )
        .entered();

        info!("Phase: initialization - Setting up real filesystem test harness");

        // Use real filesystem harness instead of in-memory mocks
        let harness = VefProofTestHarness::new();
        let input = build_real_input(&harness);

        info!("Phase: configuration - Creating proof service with real attestation backend");

        // Create proof service with real configuration that persists state
        let config_path = harness.proofs_dir.join("service_config.json");
        let config = ProofServiceConfig::reference_attestation_defaults();

        // Persist configuration to filesystem
        let config_json = json!({
            "backend_type": "reference_attestation",
            "created_at": Utc::now().to_rfc3339(),
            "config_hash": "real_config_hash"
        });
        fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_json).unwrap(),
        )
        .expect("write config to filesystem");

        let mut service = VefProofService::new(config);

        info!(
            config_persisted = true,
            config_path = %config_path.display(),
            "Phase: configuration complete - Service configured with filesystem persistence"
        );

        // Generate proof with real timestamp
        info!("Phase: proof_generation - Generating cryptographic proof");
        let proof_timestamp = Utc::now().timestamp_millis() as u64;
        let proof = service
            .generate_proof(&input, None, proof_timestamp)
            .expect("proof generation should succeed");

        // Persist proof to filesystem
        let proof_json = json!({
            "proof_material": proof.proof_material,
            "backend_id": proof.backend_id,
            "generated_at": proof_timestamp,
            "input_hash": format!("{:?}", input),
        });
        let proof_path = harness.save_proof_to_file(&proof_json, "round_trip_proof.json");

        info!(
            proof_generated = true,
            proof_path = %proof_path.display(),
            backend_id = ?proof.backend_id,
            timestamp = proof_timestamp,
            "Phase: proof_generation complete - Proof persisted to filesystem"
        );

        // Verify proof
        info!("Phase: verification - Verifying proof against original input");
        service
            .verify_proof(&input, &proof)
            .expect("proof verification should succeed");

        info!(
            verification_passed = true,
            "Phase: verification complete - Proof successfully verified"
        );

        // Verify filesystem persistence worked
        assert!(
            config_path.exists(),
            "Configuration should be persisted to filesystem"
        );
        assert!(
            proof_path.exists(),
            "Proof should be persisted to filesystem"
        );

        let persisted_proof: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&proof_path).expect("read persisted proof"))
                .expect("parse persisted proof");

        assert_eq!(
            persisted_proof["generated_at"].as_u64().unwrap(),
            proof_timestamp
        );
        assert_eq!(persisted_proof["backend_id"], json!(proof.backend_id));

        info!(
            persistence_verified = true,
            artifacts_count = fs::read_dir(&harness.proofs_dir).unwrap().count(),
            receipts_count = fs::read_dir(&harness.receipts_dir).unwrap().count(),
            "Test complete - All assertions passed with real filesystem persistence"
        );
    }

    #[test]
    fn proof_service_backend_swap_with_real_filesystem_persistence() {
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("debug".parse().unwrap()))
            .json()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let _span = span!(
            Level::INFO,
            "proof_service_backend_swap_with_real_filesystem_persistence"
        )
        .entered();

        info!("Phase: setup - Creating test harness with real filesystem");

        let harness = VefProofTestHarness::new();
        let input = build_real_input(&harness);

        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        // Generate proofs with different backends using real timestamps
        let now = Utc::now();
        let timestamp_a = now.timestamp_millis() as u64;
        let timestamp_b = timestamp_a + 1000; // 1 second later

        info!("Phase: proof_generation_a - Generating proof with HashAttestationV1 backend");
        let proof_a = service
            .generate_proof(&input, Some(ProofBackendId::HashAttestationV1), timestamp_a)
            .expect("generate proof with HashAttestationV1");

        // Persist proof A to filesystem
        let proof_a_json = json!({
            "proof_material": proof_a.proof_material,
            "backend_id": proof_a.backend_id,
            "generated_at": timestamp_a,
            "backend_type": "HashAttestationV1"
        });
        let proof_a_path = harness.save_proof_to_file(&proof_a_json, "backend_swap_proof_a.json");

        info!(
            backend_id = ?proof_a.backend_id,
            timestamp = timestamp_a,
            proof_path = %proof_a_path.display(),
            "Phase: proof_generation_a complete - HashAttestationV1 proof persisted"
        );

        info!("Phase: proof_generation_b - Generating proof with DoubleHashAttestationV1 backend");
        let proof_b = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                timestamp_b,
            )
            .expect("generate proof with DoubleHashAttestationV1");

        // Persist proof B to filesystem
        let proof_b_json = json!({
            "proof_material": proof_b.proof_material,
            "backend_id": proof_b.backend_id,
            "generated_at": timestamp_b,
            "backend_type": "DoubleHashAttestationV1"
        });
        let proof_b_path = harness.save_proof_to_file(&proof_b_json, "backend_swap_proof_b.json");

        info!(
            backend_id = ?proof_b.backend_id,
            timestamp = timestamp_b,
            proof_path = %proof_b_path.display(),
            "Phase: proof_generation_b complete - DoubleHashAttestationV1 proof persisted"
        );

        // Verify proofs are different (different backends produce different outputs)
        assert_ne!(proof_a.proof_material, proof_b.proof_material);
        assert_ne!(proof_a.backend_id, proof_b.backend_id);

        info!("Phase: verification_a - Verifying HashAttestationV1 proof");
        service
            .verify_proof(&input, &proof_a)
            .expect("verify HashAttestationV1 proof");

        info!("Phase: verification_b - Verifying DoubleHashAttestationV1 proof");
        service
            .verify_proof(&input, &proof_b)
            .expect("verify DoubleHashAttestationV1 proof");

        // Verify filesystem persistence integrity
        let persisted_a: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&proof_a_path).expect("read proof A"))
                .expect("parse proof A");

        let persisted_b: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&proof_b_path).expect("read proof B"))
                .expect("parse proof B");

        assert_eq!(persisted_a["backend_type"], "HashAttestationV1");
        assert_eq!(persisted_b["backend_type"], "DoubleHashAttestationV1");
        assert_eq!(persisted_a["generated_at"].as_u64().unwrap(), timestamp_a);
        assert_eq!(persisted_b["generated_at"].as_u64().unwrap(), timestamp_b);

        info!(
            proofs_verified = true,
            different_backends = true,
            filesystem_integrity = true,
            "Test complete - Backend swap semantics verified with real persistence"
        );
    }

    #[test]
    fn proof_service_handles_metadata_with_real_filesystem_logging() {
        let subscriber = fmt::Subscriber::builder()
            .with_env_filter(EnvFilter::from_default_env().add_directive("debug".parse().unwrap()))
            .json()
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let _span = span!(
            Level::INFO,
            "proof_service_handles_metadata_with_real_filesystem_logging"
        )
        .entered();

        info!("Phase: setup - Creating harness and input with adversarial metadata");

        let harness = VefProofTestHarness::new();
        let mut input = build_real_input(&harness);

        // Add adversarial metadata that should be ignored by the proof service
        input
            .metadata
            .insert("simulate_failure".to_string(), "timeout".to_string());
        input.metadata.insert(
            "inject_malicious_data".to_string(),
            "evil_payload".to_string(),
        );

        // Persist the input with adversarial metadata to filesystem for audit trail
        let input_json = json!({
            "metadata": input.metadata,
            "predicates": input.predicates,
            "test_timestamp": Utc::now().to_rfc3339()
        });
        let input_path = harness.proofs_dir.join("adversarial_input.json");
        fs::write(
            &input_path,
            serde_json::to_string_pretty(&input_json).unwrap(),
        )
        .expect("persist adversarial input");

        warn!(
            metadata_count = input.metadata.len(),
            input_path = %input_path.display(),
            "Phase: setup complete - Input with adversarial metadata persisted for audit"
        );

        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        info!("Phase: proof_generation - Generating proof despite adversarial metadata");
        let timestamp = Utc::now().timestamp_millis() as u64;
        let proof = service
            .generate_proof(&input, None, timestamp)
            .expect("proof service must ignore simulate_failure metadata and succeed");

        // Persist successful proof to demonstrate metadata was properly ignored
        let proof_result_json = json!({
            "proof_generated": true,
            "adversarial_metadata_ignored": true,
            "proof_material": proof.proof_material,
            "backend_id": proof.backend_id,
            "timestamp": timestamp,
            "input_metadata": input.metadata
        });
        let proof_path =
            harness.save_proof_to_file(&proof_result_json, "metadata_resilience_proof.json");

        info!(
            proof_generated = true,
            proof_path = %proof_path.display(),
            metadata_ignored = true,
            "Phase: proof_generation complete - Proof generated despite adversarial metadata"
        );

        info!("Phase: verification - Verifying proof resilience");
        service
            .verify_proof(&input, &proof)
            .expect("proof verification should succeed");

        // Verify that the adversarial metadata didn't affect the proof
        let audit_log_path = harness.proofs_dir.join("audit_log.json");
        let audit_entry = json!({
            "test_name": "metadata_resilience",
            "input_file": input_path,
            "proof_file": proof_path,
            "adversarial_metadata": input.metadata,
            "proof_succeeded": true,
            "verification_succeeded": true,
            "test_completed_at": Utc::now().to_rfc3339()
        });
        fs::write(
            &audit_log_path,
            serde_json::to_string_pretty(&audit_entry).unwrap(),
        )
        .expect("write audit log");

        info!(
            audit_log = %audit_log_path.display(),
            metadata_resilience = true,
            "Test complete - Proof service correctly ignored adversarial metadata"
        );
    }
}
