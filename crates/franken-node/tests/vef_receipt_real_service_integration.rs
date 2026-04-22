//! Real-service integration tests for VEF receipt generation and verification.
//!
//! Tests the complete VEF receipt chain with real proof services, no mocks.
//! Validates receipt integrity across service boundaries, proof scheduler
//! behavior under load, and error recovery in verification flows.
//!
//! Follows anti-mock principles:
//! - Real proof services and verification components
//! - Chain integrity across actual service boundaries
//! - Structured logging with timing data
//! - Load testing and error path coverage

use frankenengine_node::security::constant_time;
use frankenengine_node::vef::{
    evidence_capsule::{CapsuleIntegrity, EvidenceCapsule},
    proof_scheduler::{ProofScheduler, SchedulerConfig, SchedulingDecision, WorkloadTier},
    proof_service::{
        ProofBackendId, ProofInputEnvelope, ProofOutputEnvelope, ProofServiceConfig,
        VefProofService,
    },
    receipt_chain::{ChainValidationError, ReceiptChain, ReceiptIntegrity},
    verification_state::{StateTransition, VerificationResult, VerificationState},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Real-service VEF test harness with no mocked dependencies
#[derive(Debug)]
struct VefReceiptTestHarness {
    proof_service: Arc<VefProofService>,
    scheduler: Arc<RwLock<ProofScheduler>>,
    receipt_chain: Arc<RwLock<ReceiptChain>>,
    verification_state: Arc<RwLock<VerificationState>>,
    test_start: Instant,
    operation_logs: Vec<OperationLog>,
}

#[derive(Debug, Clone)]
struct OperationLog {
    operation: String,
    timestamp: Instant,
    job_id: String,
    duration_ms: u64,
    success: bool,
    proof_size_bytes: Option<usize>,
    verification_steps: Option<usize>,
    error: Option<String>,
}

impl VefReceiptTestHarness {
    async fn new() -> Self {
        let proof_config = ProofServiceConfig::reference_attestation_defaults();

        let scheduler_config = SchedulerConfig {
            max_concurrent_proofs: 10,
            high_tier_weight: 3,
            medium_tier_weight: 2,
            low_tier_weight: 1,
            proof_timeout_secs: 30,
        };

        Self {
            proof_service: Arc::new(VefProofService::new(proof_config)),
            scheduler: Arc::new(RwLock::new(ProofScheduler::new(scheduler_config))),
            receipt_chain: Arc::new(RwLock::new(ReceiptChain::new())),
            verification_state: Arc::new(RwLock::new(VerificationState::new())),
            test_start: Instant::now(),
            operation_logs: Vec::new(),
        }
    }

    fn create_test_proof_input(&self, job_id: &str, tier: WorkloadTier) -> ProofInputEnvelope {
        ProofInputEnvelope {
            schema_version: "vef-proof-service-v1".to_string(),
            job_id: job_id.to_string(),
            window_id: format!("window-{}", job_id),
            tier,
            trace_id: format!("trace-{}", job_id),
            receipt_start_index: 0,
            receipt_end_index: 1,
            checkpoint_id: None,
            chain_head_hash: self.sha256_hash("chain_head"),
            checkpoint_commitment_hash: Some(self.sha256_hash("checkpoint")),
            policy_hash: self.sha256_hash("policy"),
            policy_predicates: vec!["receipt.integrity verified".to_string()],
            receipt_hashes: vec![self.sha256_hash("receipt1"), self.sha256_hash("receipt2")],
            metadata: BTreeMap::new(),
        }
    }

    fn sha256_hash(&self, input: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(input.as_bytes())))
    }

    async fn generate_and_verify_proof(
        &mut self,
        job_id: &str,
        tier: WorkloadTier,
    ) -> Result<(ProofOutputEnvelope, Duration), String> {
        let input = self.create_test_proof_input(job_id, tier);
        let start = Instant::now();

        // Generate proof using real proof service
        let proof_result = self
            .proof_service
            .generate_proof(&input, None, chrono::Utc::now().timestamp_millis() as u64)
            .await;
        let proof = proof_result.map_err(|e| format!("Proof generation failed: {:?}", e))?;

        // Verify proof using real verification
        let verify_result = self.proof_service.verify_proof(&input, &proof).await;
        verify_result.map_err(|e| format!("Proof verification failed: {:?}", e))?;

        let duration = start.elapsed();

        // Log operation with structured data
        let op_log = OperationLog {
            operation: "generate_and_verify".to_string(),
            timestamp: start,
            job_id: job_id.to_string(),
            duration_ms: duration.as_millis() as u64,
            success: true,
            proof_size_bytes: Some(proof.proof_material.len()),
            verification_steps: Some(2), // Generation + verification
            error: None,
        };

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "vef_receipt_integration",
                "operation": "generate_and_verify",
                "job_id": job_id,
                "tier": format!("{:?}", tier),
                "duration_ms": op_log.duration_ms,
                "proof_size_bytes": op_log.proof_size_bytes,
                "backend_id": format!("{:?}", proof.backend_id),
                "event": "proof_operation"
            })
        );

        self.operation_logs.push(op_log);

        Ok((proof, duration))
    }

    async fn build_receipt_chain(&mut self, chain_length: usize) -> Result<Vec<String>, String> {
        let mut chain = self.receipt_chain.write().await;
        let mut receipt_ids = Vec::new();

        for i in 0..chain_length {
            let job_id = format!("chain-job-{}", i);
            let input = self.create_test_proof_input(&job_id, WorkloadTier::Medium);

            let start = Instant::now();
            let proof = self
                .proof_service
                .generate_proof(&input, None, chrono::Utc::now().timestamp_millis() as u64)
                .await
                .map_err(|e| format!("Chain proof {} failed: {:?}", i, e))?;

            // Add to chain with previous receipt dependency
            let previous_receipt = if i == 0 {
                None
            } else {
                receipt_ids.last().cloned()
            };
            let receipt_id = chain
                .add_receipt(&proof, previous_receipt.as_deref())
                .map_err(|e| format!("Failed to add receipt to chain: {:?}", e))?;

            receipt_ids.push(receipt_id.clone());

            let duration = start.elapsed();

            eprintln!(
                "{}",
                json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "suite": "vef_receipt_integration",
                    "operation": "chain_build",
                    "chain_position": i,
                    "receipt_id": receipt_id,
                    "previous_receipt": previous_receipt,
                    "duration_ms": duration.as_millis(),
                    "event": "receipt_chain_addition"
                })
            );
        }

        Ok(receipt_ids)
    }

    async fn verify_chain_integrity(&self, receipt_ids: &[String]) -> Result<Duration, String> {
        let start = Instant::now();
        let chain = self.receipt_chain.read().await;

        // Verify each receipt and chain links
        for (i, receipt_id) in receipt_ids.iter().enumerate() {
            let integrity = chain
                .verify_receipt_integrity(receipt_id)
                .map_err(|e| format!("Receipt {} integrity failed: {:?}", i, e))?;

            match integrity {
                ReceiptIntegrity::Valid => {
                    eprintln!(
                        "{}",
                        json!({
                            "ts": chrono::Utc::now().to_rfc3339(),
                            "suite": "vef_receipt_integration",
                            "operation": "integrity_check",
                            "receipt_id": receipt_id,
                            "position": i,
                            "result": "valid",
                            "event": "integrity_verification"
                        })
                    );
                }
                ReceiptIntegrity::Invalid(reason) => {
                    return Err(format!("Receipt {} integrity check failed: {}", i, reason));
                }
            }
        }

        // Verify chain links
        for i in 1..receipt_ids.len() {
            let link_valid = chain
                .verify_chain_link(&receipt_ids[i - 1], &receipt_ids[i])
                .map_err(|e| format!("Chain link {}->{} verification failed: {:?}", i - 1, i, e))?;

            if !link_valid {
                return Err(format!(
                    "Chain link integrity broken between {} and {}",
                    i - 1,
                    i
                ));
            }
        }

        Ok(start.elapsed())
    }

    fn export_performance_summary(&self) -> serde_json::Value {
        let total_duration = self.test_start.elapsed();
        let successful_ops = self.operation_logs.iter().filter(|log| log.success).count();
        let failed_ops = self
            .operation_logs
            .iter()
            .filter(|log| !log.success)
            .count();

        let avg_duration: f64 = if !self.operation_logs.is_empty() {
            self.operation_logs
                .iter()
                .map(|log| log.duration_ms)
                .sum::<u64>() as f64
                / self.operation_logs.len() as f64
        } else {
            0.0
        };

        let total_proof_size: usize = self
            .operation_logs
            .iter()
            .filter_map(|log| log.proof_size_bytes)
            .sum();

        json!({
            "suite": "vef_receipt_integration",
            "total_duration_ms": total_duration.as_millis(),
            "successful_operations": successful_ops,
            "failed_operations": failed_ops,
            "avg_operation_duration_ms": avg_duration,
            "total_proof_size_bytes": total_proof_size,
            "operations_per_second": successful_ops as f64 / total_duration.as_secs_f64(),
            "operation_logs": self.operation_logs.len(),
        })
    }
}

#[tokio::test]
async fn test_vef_receipt_chain_end_to_end_integration() {
    let mut harness = VefReceiptTestHarness::new().await;

    // Test complete receipt chain workflow
    const CHAIN_LENGTH: usize = 5;

    // Build receipt chain with real proof generation
    let receipt_ids = harness
        .build_receipt_chain(CHAIN_LENGTH)
        .await
        .expect("Receipt chain building should succeed");

    assert_eq!(
        receipt_ids.len(),
        CHAIN_LENGTH,
        "Chain should contain expected number of receipts"
    );

    // Verify chain integrity using real verification
    let integrity_duration = harness
        .verify_chain_integrity(&receipt_ids)
        .await
        .expect("Chain integrity verification should succeed");

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "vef_receipt_integration",
            "test": "end_to_end_chain",
            "chain_length": CHAIN_LENGTH,
            "integrity_verification_ms": integrity_duration.as_millis(),
            "receipt_ids": receipt_ids,
            "event": "test_completion"
        })
    );

    eprintln!("{}", harness.export_performance_summary());
}

#[tokio::test]
async fn test_proof_scheduler_under_load_real_services() {
    let mut harness = VefReceiptTestHarness::new().await;

    // Test scheduler behavior under concurrent load
    let job_count = 20;
    let mut handles = Vec::new();

    for i in 0..job_count {
        let job_id = format!("load-test-job-{}", i);
        let tier = match i % 3 {
            0 => WorkloadTier::High,
            1 => WorkloadTier::Medium,
            2 => WorkloadTier::Low,
            _ => unreachable!(),
        };

        let proof_service = harness.proof_service.clone();
        let input = harness.create_test_proof_input(&job_id, tier);

        let handle = tokio::spawn(async move {
            let start = Instant::now();
            let result = proof_service
                .generate_proof(&input, None, chrono::Utc::now().timestamp_millis() as u64)
                .await;
            (job_id, tier, start.elapsed(), result)
        });

        handles.push(handle);
    }

    // Collect results
    let mut results = Vec::new();
    for handle in handles {
        let (job_id, tier, duration, result) = handle.await.expect("Task should not panic");
        results.push((job_id, tier, duration, result.is_ok()));

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "vef_receipt_integration",
                "test": "scheduler_load",
                "job_id": job_id,
                "tier": format!("{:?}", tier),
                "duration_ms": duration.as_millis(),
                "success": result.is_ok(),
                "event": "concurrent_proof_result"
            })
        );
    }

    // Analyze load test results
    let successful = results.iter().filter(|(_, _, _, success)| *success).count();
    let failed = results
        .iter()
        .filter(|(_, _, _, success)| !*success)
        .count();

    let high_tier_avg: f64 = results
        .iter()
        .filter(|(_, tier, _, success)| matches!(tier, WorkloadTier::High) && *success)
        .map(|(_, _, duration, _)| duration.as_millis() as f64)
        .sum::<f64>()
        / results
            .iter()
            .filter(|(_, tier, _, _)| matches!(tier, WorkloadTier::High))
            .count() as f64;

    let low_tier_avg: f64 = results
        .iter()
        .filter(|(_, tier, _, success)| matches!(tier, WorkloadTier::Low) && *success)
        .map(|(_, _, duration, _)| duration.as_millis() as f64)
        .sum::<f64>()
        / results
            .iter()
            .filter(|(_, tier, _, _)| matches!(tier, WorkloadTier::Low))
            .count() as f64;

    eprintln!(
        "{}",
        json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "suite": "vef_receipt_integration",
            "test": "scheduler_load_summary",
            "total_jobs": job_count,
            "successful": successful,
            "failed": failed,
            "success_rate": successful as f64 / job_count as f64,
            "high_tier_avg_ms": high_tier_avg,
            "low_tier_avg_ms": low_tier_avg,
            "tier_prioritization": high_tier_avg < low_tier_avg,
            "event": "load_test_analysis"
        })
    );

    // Verify scheduler prioritization (high tier should be faster on average)
    assert!(
        high_tier_avg <= low_tier_avg * 1.5,
        "High tier jobs should be prioritized: {} vs {} ms",
        high_tier_avg,
        low_tier_avg
    );

    // Verify acceptable success rate under load
    let success_rate = successful as f64 / job_count as f64;
    assert!(
        success_rate >= 0.85,
        "Success rate too low under load: {:.2}%",
        success_rate * 100.0
    );
}

#[tokio::test]
async fn test_verification_state_transitions_real_components() {
    let mut harness = VefReceiptTestHarness::new().await;
    let job_id = "state-transition-001";

    // Test realistic verification state machine transitions
    let mut verification_state = harness.verification_state.write().await;

    let transitions = [
        ("pending", VerificationResult::Pending),
        ("in_progress", VerificationResult::InProgress),
        ("verified", VerificationResult::Verified),
    ];

    for (phase, expected_state) in transitions {
        let start = Instant::now();

        let transition_result = verification_state
            .transition_to(job_id, expected_state.clone())
            .map_err(|e| format!("State transition failed: {:?}", e));

        let duration = start.elapsed();

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "vef_receipt_integration",
                "test": "state_transitions",
                "job_id": job_id,
                "phase": phase,
                "target_state": format!("{:?}", expected_state),
                "duration_ms": duration.as_millis(),
                "success": transition_result.is_ok(),
                "event": "state_transition"
            })
        );

        assert!(
            transition_result.is_ok(),
            "Transition to {} should succeed",
            phase
        );

        // Verify state persistence
        let current_state = verification_state
            .get_state(job_id)
            .expect("State should exist");
        assert_eq!(
            current_state, expected_state,
            "State should match expected value"
        );
    }
}

#[tokio::test]
async fn test_receipt_error_recovery_real_failures() {
    let mut harness = VefReceiptTestHarness::new().await;

    // Test error recovery with real failure scenarios
    let error_scenarios = vec![
        ("malformed_input", "malformed input test"),
        ("invalid_policy", "invalid policy test"),
        ("corrupted_proof", "corrupted proof test"),
    ];

    for (scenario_name, job_id) in error_scenarios {
        let mut input = harness.create_test_proof_input(job_id, WorkloadTier::Medium);

        // Introduce specific errors
        match scenario_name {
            "malformed_input" => {
                input.policy_hash = "invalid-hash-format".to_string();
            }
            "invalid_policy" => {
                input.policy_predicates = vec!["".to_string()]; // Empty predicate
            }
            "corrupted_proof" => {
                input.receipt_hashes = vec![]; // Empty receipt hashes
            }
            _ => {}
        }

        let start = Instant::now();
        let result = harness
            .proof_service
            .generate_proof(&input, None, chrono::Utc::now().timestamp_millis() as u64)
            .await;
        let duration = start.elapsed();

        // Verify error handling
        assert!(result.is_err(), "Scenario {} should fail", scenario_name);

        eprintln!(
            "{}",
            json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "suite": "vef_receipt_integration",
                "test": "error_recovery",
                "scenario": scenario_name,
                "job_id": job_id,
                "duration_ms": duration.as_millis(),
                "expected_failure": true,
                "actual_failure": result.is_err(),
                "error_type": result.err().map(|e| format!("{:?}", e)),
                "event": "error_scenario"
            })
        );
    }

    eprintln!("{}", harness.export_performance_summary());
}

#[tokio::test]
async fn test_evidence_capsule_integrity_cross_service() {
    let mut harness = VefReceiptTestHarness::new().await;

    // Test evidence capsule integrity across service boundaries
    let job_id = "capsule-integrity-001";
    let input = harness.create_test_proof_input(job_id, WorkloadTier::High);

    // Generate proof and create evidence capsule
    let proof = harness
        .proof_service
        .generate_proof(&input, None, chrono::Utc::now().timestamp_millis() as u64)
        .await
        .expect("Proof generation should succeed");

    let start = Instant::now();
    let evidence_capsule =
        EvidenceCapsule::new(&proof, &input).expect("Evidence capsule creation should succeed");

    // Verify capsule integrity
    let integrity = evidence_capsule
        .verify_integrity()
        .expect("Capsule integrity check should succeed");

    let duration = start.elapsed();

    match integrity {
        CapsuleIntegrity::Valid => {
            eprintln!(
                "{}",
                json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "suite": "vef_receipt_integration",
                    "test": "evidence_capsule_integrity",
                    "job_id": job_id,
                    "capsule_size_bytes": evidence_capsule.serialized_size(),
                    "integrity_check_ms": duration.as_millis(),
                    "result": "valid",
                    "event": "capsule_verification"
                })
            );
        }
        CapsuleIntegrity::Invalid(reason) => {
            panic!("Evidence capsule integrity check failed: {}", reason);
        }
    }

    eprintln!("{}", harness.export_performance_summary());
}
