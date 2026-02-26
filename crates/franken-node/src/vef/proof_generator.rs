//! bd-1u8m: Proof-generation service interface (backend-agnostic) for receipt-window compliance proofs.
//!
//! This module implements a backend-agnostic proof generation interface that
//! creates versioned, self-describing compliance proofs for receipt windows.
//! The design supports pluggable backends: mock/hash-based, future ZK, or
//! external proving services.
//!
//! # Invariants
//!
//! - INV-PGN-BACKEND-AGNOSTIC: The proof generation interface (`ProofBackend` trait) is
//!   fully decoupled from any specific proving system. Backends are interchangeable
//!   without modifying the orchestrator.
//! - INV-PGN-VERSIONED-FORMAT: Every `ComplianceProof` carries an explicit `format_version`
//!   and `backend_name`, making the proof self-describing and forward-compatible.
//! - INV-PGN-DETERMINISTIC: Given identical inputs and backend state, proof generation
//!   produces identical outputs (subject to backend determinism guarantees).

use super::proof_scheduler::ProofWindow;
use super::receipt_chain::ReceiptChainEntry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Schema version for proof generator output format.
pub const PROOF_GENERATOR_SCHEMA_VERSION: &str = "vef-proof-generator-v1";

/// Format version stamped into every compliance proof.
pub const PROOF_FORMAT_VERSION: &str = "1.0.0";

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-PGN-BACKEND-AGNOSTIC: The ProofBackend trait decouples generation from any specific proving system.
pub const INV_PGN_BACKEND_AGNOSTIC: &str = "INV-PGN-BACKEND-AGNOSTIC";

/// INV-PGN-VERSIONED-FORMAT: Every proof carries explicit format version and backend name.
pub const INV_PGN_VERSIONED_FORMAT: &str = "INV-PGN-VERSIONED-FORMAT";

/// INV-PGN-DETERMINISTIC: Identical inputs produce identical proofs (given deterministic backend).
pub const INV_PGN_DETERMINISTIC: &str = "INV-PGN-DETERMINISTIC";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Proof generation request received.
    pub const PGN_001_REQUEST_RECEIVED: &str = "PGN-001";
    /// Proof generation started by backend.
    pub const PGN_002_GENERATION_STARTED: &str = "PGN-002";
    /// Proof generation completed successfully.
    pub const PGN_003_GENERATION_COMPLETE: &str = "PGN-003";
    /// Proof generation failed.
    pub const PGN_004_GENERATION_FAILED: &str = "PGN-004";
    /// Backend registered or swapped.
    pub const PGN_005_BACKEND_REGISTERED: &str = "PGN-005";
    /// Proof verification performed.
    pub const PGN_006_PROOF_VERIFIED: &str = "PGN-006";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Backend is not available or not registered.
    pub const ERR_PGN_BACKEND_UNAVAILABLE: &str = "ERR-PGN-BACKEND-UNAVAILABLE";
    /// Receipt window is empty; cannot generate proof over zero entries.
    pub const ERR_PGN_WINDOW_EMPTY: &str = "ERR-PGN-WINDOW-EMPTY";
    /// Proof generation exceeded the configured timeout.
    pub const ERR_PGN_TIMEOUT: &str = "ERR-PGN-TIMEOUT";
    /// Internal error in proof generation pipeline.
    pub const ERR_PGN_INTERNAL: &str = "ERR-PGN-INTERNAL";
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGeneratorError {
    pub code: String,
    pub event_code: String,
    pub message: String,
}

impl ProofGeneratorError {
    pub fn backend_unavailable(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PGN_BACKEND_UNAVAILABLE.to_string(),
            event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
            message: message.into(),
        }
    }

    pub fn window_empty(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PGN_WINDOW_EMPTY.to_string(),
            event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
            message: message.into(),
        }
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PGN_TIMEOUT.to_string(),
            event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PGN_INTERNAL.to_string(),
            event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ProofGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ProofGeneratorError {}

// ── Event type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGeneratorEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

// ── Proof status ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    /// Request received, not yet started.
    Pending,
    /// Backend is actively generating the proof.
    Generating,
    /// Proof generation completed successfully.
    Complete,
    /// Proof generation failed.
    Failed,
}

// ── Proof request ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The proof window this request targets.
    pub window: ProofWindow,
    /// The receipt chain entries within the window.
    pub entries: Vec<ReceiptChainEntry>,
    /// Timeout in milliseconds for proof generation.
    pub timeout_millis: u64,
    /// Trace correlation ID.
    pub trace_id: String,
    /// Timestamp when the request was created (millis since epoch).
    pub created_at_millis: u64,
}

// ── Compliance proof ────────────────────────────────────────────────────────

/// A versioned, self-describing compliance proof for a receipt window.
/// INV-PGN-VERSIONED-FORMAT: carries format_version and backend_name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceProof {
    /// Unique proof identifier.
    pub proof_id: String,
    /// Format version of this proof structure.
    pub format_version: String,
    /// Reference to the receipt window that was proved.
    pub receipt_window_ref: String,
    /// Opaque proof data produced by the backend.
    pub proof_data: Vec<u8>,
    /// SHA-256 hash of the proof data for integrity.
    pub proof_data_hash: String,
    /// Timestamp when the proof was generated (millis since epoch).
    pub generated_at_millis: u64,
    /// Name of the backend that produced this proof.
    pub backend_name: String,
    /// Additional metadata from the backend (BTreeMap for determinism).
    pub metadata: BTreeMap<String, String>,
    /// Trace correlation ID.
    pub trace_id: String,
}

// ── Backend trait ───────────────────────────────────────────────────────────

/// Backend-agnostic proof generation interface.
/// INV-PGN-BACKEND-AGNOSTIC: any struct implementing this trait can serve as
/// a proof backend without changes to the orchestrator.
pub trait ProofBackend: Send + Sync {
    /// Human-readable name of this backend (e.g., "test-hash", "groth16", "stark").
    fn backend_name(&self) -> &str;

    /// Generate a compliance proof for the given request.
    fn generate(&self, request: &ProofRequest) -> Result<ComplianceProof, ProofGeneratorError>;

    /// Verify a previously generated compliance proof.
    /// Returns `true` if the proof is valid for the given entries.
    fn verify(
        &self,
        proof: &ComplianceProof,
        entries: &[ReceiptChainEntry],
    ) -> Result<bool, ProofGeneratorError>;
}

// ── Test hash-based backend ─────────────────────────────────────────────────

/// Hash-based proof backend for testing and development.
/// Produces deterministic SHA-256 proofs. INV-PGN-DETERMINISTIC.
#[derive(Debug, Clone)]
pub struct TestProofBackend {
    /// Name reported by this backend.
    name: String,
}

impl TestProofBackend {
    pub fn new() -> Self {
        Self {
            name: "test-hash".to_string(),
        }
    }

    pub fn with_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Compute deterministic proof data from entries.
    /// INV-PGN-DETERMINISTIC: identical entries produce identical proof bytes.
    fn compute_proof_bytes(&self, entries: &[ReceiptChainEntry]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"proof_generator_hash_v1:");
        hasher.update(b"proof-backend-v1:");
        for entry in entries {
            hasher.update(entry.chain_hash.as_bytes());
            hasher.update(b"|");
        }
        hasher.finalize().to_vec()
    }

    fn hash_bytes(data: &[u8]) -> String {
        let digest = Sha256::digest([b"proof_generator_hash_v1:" as &[u8], data].concat());
        format!("sha256:{digest:x}")
    }
}

impl Default for TestProofBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofBackend for TestProofBackend {
    fn backend_name(&self) -> &str {
        &self.name
    }

    fn generate(&self, request: &ProofRequest) -> Result<ComplianceProof, ProofGeneratorError> {
        if request.entries.is_empty() {
            return Err(ProofGeneratorError::window_empty(
                "cannot generate proof for empty receipt window",
            ));
        }

        let proof_data = self.compute_proof_bytes(&request.entries);
        let proof_data_hash = Self::hash_bytes(&proof_data);

        let mut metadata = BTreeMap::new();
        metadata.insert("backend_type".to_string(), "test-hash".to_string());
        metadata.insert("entry_count".to_string(), request.entries.len().to_string());
        metadata.insert(
            "window_start".to_string(),
            request.window.start_index.to_string(),
        );
        metadata.insert(
            "window_end".to_string(),
            request.window.end_index.to_string(),
        );

        Ok(ComplianceProof {
            proof_id: format!("proof-{}", request.request_id),
            format_version: PROOF_FORMAT_VERSION.to_string(),
            receipt_window_ref: request.window.window_id.clone(),
            proof_data,
            proof_data_hash,
            generated_at_millis: request.created_at_millis,
            backend_name: self.name.clone(),
            metadata,
            trace_id: request.trace_id.clone(),
        })
    }

    fn verify(
        &self,
        proof: &ComplianceProof,
        entries: &[ReceiptChainEntry],
    ) -> Result<bool, ProofGeneratorError> {
        if entries.is_empty() {
            return Ok(false);
        }
        let expected_data = self.compute_proof_bytes(entries);
        let expected_hash = Self::hash_bytes(&expected_data);
        Ok(crate::security::constant_time::ct_eq_bytes(&proof.proof_data, &expected_data)
            && crate::security::constant_time::ct_eq(&proof.proof_data_hash, &expected_hash))
    }
}

// ── Proof generator orchestrator ────────────────────────────────────────────

/// Configuration for the proof generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGeneratorConfig {
    /// Default timeout for proof generation requests (millis).
    pub default_timeout_millis: u64,
    /// Maximum number of entries per proof request.
    pub max_entries_per_request: usize,
    /// Maximum number of concurrent proof requests tracked.
    pub max_pending_requests: usize,
}

impl Default for ProofGeneratorConfig {
    fn default() -> Self {
        Self {
            default_timeout_millis: 60_000,
            max_entries_per_request: 256,
            max_pending_requests: 64,
        }
    }
}

/// Tracks the status of a proof generation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestStatus {
    pub request_id: String,
    pub window_id: String,
    pub status: ProofStatus,
    pub proof: Option<ComplianceProof>,
    pub error: Option<ProofGeneratorError>,
    pub created_at_millis: u64,
    pub completed_at_millis: Option<u64>,
    pub trace_id: String,
}

/// Orchestrates proof creation from receipt windows using a pluggable backend.
/// INV-PGN-BACKEND-AGNOSTIC: the backend is injected at construction time.
pub struct ProofGenerator {
    pub schema_version: String,
    pub config: ProofGeneratorConfig,
    backend: Arc<dyn ProofBackend>,
    requests: BTreeMap<String, ProofRequestStatus>,
    next_request_seq: u64,
    events: Vec<ProofGeneratorEvent>,
}

impl ProofGenerator {
    /// Create a new proof generator with the given backend and config.
    pub fn new(backend: Arc<dyn ProofBackend>, config: ProofGeneratorConfig) -> Self {
        let backend_name = backend.backend_name().to_string();
        let mut generator = Self {
            schema_version: PROOF_GENERATOR_SCHEMA_VERSION.to_string(),
            config,
            backend,
            requests: BTreeMap::new(),
            next_request_seq: 0,
            events: Vec::new(),
        };
        generator.events.push(ProofGeneratorEvent {
            event_code: event_codes::PGN_005_BACKEND_REGISTERED.to_string(),
            trace_id: "init".to_string(),
            detail: format!("backend={backend_name} registered"),
        });
        generator
    }

    /// Get the name of the currently registered backend.
    pub fn backend_name(&self) -> &str {
        self.backend.backend_name()
    }

    /// Get all tracked request statuses.
    pub fn requests(&self) -> &BTreeMap<String, ProofRequestStatus> {
        &self.requests
    }

    /// Get all events emitted by this generator.
    pub fn events(&self) -> &[ProofGeneratorEvent] {
        &self.events
    }

    /// Submit a proof generation request for a given window and entries.
    pub fn submit_request(
        &mut self,
        window: &ProofWindow,
        entries: &[ReceiptChainEntry],
        now_millis: u64,
        trace_id: &str,
    ) -> Result<String, ProofGeneratorError> {
        // Validate: non-empty window
        if entries.is_empty() {
            return Err(ProofGeneratorError::window_empty(format!(
                "receipt window {} has no entries",
                window.window_id
            )));
        }

        // Check pending request capacity
        let active_count = self
            .requests
            .values()
            .filter(|r| matches!(r.status, ProofStatus::Pending | ProofStatus::Generating))
            .count();
        if active_count >= self.config.max_pending_requests {
            return Err(ProofGeneratorError::internal(
                "pending request capacity exhausted",
            ));
        }

        // Check entry count limit
        if entries.len() > self.config.max_entries_per_request {
            return Err(ProofGeneratorError::internal(format!(
                "entry count {} exceeds max_entries_per_request {}",
                entries.len(),
                self.config.max_entries_per_request
            )));
        }

        let request_id = format!("req-{:08}", self.next_request_seq);
        self.next_request_seq = self
            .next_request_seq
            .checked_add(1)
            .ok_or_else(|| ProofGeneratorError::internal("request sequence overflow"))?;

        let status = ProofRequestStatus {
            request_id: request_id.clone(),
            window_id: window.window_id.clone(),
            status: ProofStatus::Pending,
            proof: None,
            error: None,
            created_at_millis: now_millis,
            completed_at_millis: None,
            trace_id: trace_id.to_string(),
        };
        self.requests.insert(request_id.clone(), status);

        self.events.push(ProofGeneratorEvent {
            event_code: event_codes::PGN_001_REQUEST_RECEIVED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("request={request_id} window={}", window.window_id),
        });

        Ok(request_id)
    }

    /// Execute proof generation for a pending request.
    pub fn generate_proof(
        &mut self,
        request_id: &str,
        window: &ProofWindow,
        entries: &[ReceiptChainEntry],
        now_millis: u64,
    ) -> Result<ComplianceProof, ProofGeneratorError> {
        let status = self.requests.get_mut(request_id).ok_or_else(|| {
            ProofGeneratorError::internal(format!("unknown request_id {request_id}"))
        })?;

        // Transition to Generating
        status.status = ProofStatus::Generating;
        let trace_id = status.trace_id.clone();

        self.events.push(ProofGeneratorEvent {
            event_code: event_codes::PGN_002_GENERATION_STARTED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!("request={request_id} generation started"),
        });

        // Build the proof request
        let proof_request = ProofRequest {
            request_id: request_id.to_string(),
            window: window.clone(),
            entries: entries.to_vec(),
            timeout_millis: self.config.default_timeout_millis,
            trace_id: trace_id.clone(),
            created_at_millis: now_millis,
        };

        // Call the backend
        match self.backend.generate(&proof_request) {
            Ok(proof) => {
                let status = self.requests.get_mut(request_id).ok_or_else(|| {
                    ProofGeneratorError::internal(format!(
                        "request {request_id} vanished after generation"
                    ))
                })?;
                status.status = ProofStatus::Complete;
                status.proof = Some(proof.clone());
                status.completed_at_millis = Some(now_millis);

                self.events.push(ProofGeneratorEvent {
                    event_code: event_codes::PGN_003_GENERATION_COMPLETE.to_string(),
                    trace_id: trace_id.clone(),
                    detail: format!(
                        "request={request_id} proof={} backend={}",
                        proof.proof_id, proof.backend_name
                    ),
                });

                Ok(proof)
            }
            Err(err) => {
                let status = self.requests.get_mut(request_id).ok_or_else(|| {
                    ProofGeneratorError::internal(format!(
                        "request {request_id} vanished after generation"
                    ))
                })?;
                status.status = ProofStatus::Failed;
                status.error = Some(err.clone());
                status.completed_at_millis = Some(now_millis);

                self.events.push(ProofGeneratorEvent {
                    event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
                    trace_id,
                    detail: format!("request={request_id} error={err}"),
                });

                Err(err)
            }
        }
    }

    /// Verify a compliance proof against a set of entries.
    pub fn verify_proof(
        &mut self,
        proof: &ComplianceProof,
        entries: &[ReceiptChainEntry],
        trace_id: &str,
    ) -> Result<bool, ProofGeneratorError> {
        let valid = self.backend.verify(proof, entries)?;
        self.events.push(ProofGeneratorEvent {
            event_code: event_codes::PGN_006_PROOF_VERIFIED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!(
                "proof={} valid={valid} backend={}",
                proof.proof_id, proof.backend_name
            ),
        });
        Ok(valid)
    }

    /// Enforce timeouts on pending/generating requests.
    pub fn enforce_timeouts(&mut self, now_millis: u64) -> Vec<String> {
        let mut timed_out = Vec::new();
        for status in self.requests.values_mut() {
            if matches!(
                status.status,
                ProofStatus::Pending | ProofStatus::Generating
            ) {
                let elapsed = now_millis.saturating_sub(status.created_at_millis);
                if elapsed >= self.config.default_timeout_millis {
                    status.status = ProofStatus::Failed;
                    status.error = Some(ProofGeneratorError::timeout(format!(
                        "request {} exceeded timeout of {}ms",
                        status.request_id, self.config.default_timeout_millis
                    )));
                    status.completed_at_millis = Some(now_millis);
                    timed_out.push(status.request_id.clone());
                    self.events.push(ProofGeneratorEvent {
                        event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
                        trace_id: status.trace_id.clone(),
                        detail: format!("request={} timed out", status.request_id),
                    });
                }
            }
        }
        timed_out
    }

    /// Get counts of requests by status.
    pub fn status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        counts.insert("pending".to_string(), 0);
        counts.insert("generating".to_string(), 0);
        counts.insert("complete".to_string(), 0);
        counts.insert("failed".to_string(), 0);
        for status in self.requests.values() {
            let key = match status.status {
                ProofStatus::Pending => "pending",
                ProofStatus::Generating => "generating",
                ProofStatus::Complete => "complete",
                ProofStatus::Failed => "failed",
            };
            *counts.entry(key.to_string()).or_default() += 1;
        }
        counts
    }

    /// Swap the backend to a new implementation.
    /// INV-PGN-BACKEND-AGNOSTIC: backends are interchangeable at runtime.
    pub fn swap_backend(&mut self, new_backend: Arc<dyn ProofBackend>, trace_id: &str) {
        let new_name = new_backend.backend_name().to_string();
        self.backend = new_backend;
        self.events.push(ProofGeneratorEvent {
            event_code: event_codes::PGN_005_BACKEND_REGISTERED.to_string(),
            trace_id: trace_id.to_string(),
            detail: format!("backend swapped to {new_name}"),
        });
    }
}

/// Thread-safe wrapper for ProofGenerator.
pub struct ConcurrentProofGenerator {
    inner: Arc<Mutex<ProofGenerator>>,
}

impl ConcurrentProofGenerator {
    pub fn new(backend: Arc<dyn ProofBackend>, config: ProofGeneratorConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProofGenerator::new(backend, config))),
        }
    }

    pub fn submit_request(
        &self,
        window: &ProofWindow,
        entries: &[ReceiptChainEntry],
        now_millis: u64,
        trace_id: &str,
    ) -> Result<String, ProofGeneratorError> {
        self.inner
            .lock()
            .map_err(|_| ProofGeneratorError::internal("proof generator mutex poisoned"))?
            .submit_request(window, entries, now_millis, trace_id)
    }

    pub fn generate_proof(
        &self,
        request_id: &str,
        window: &ProofWindow,
        entries: &[ReceiptChainEntry],
        now_millis: u64,
    ) -> Result<ComplianceProof, ProofGeneratorError> {
        self.inner
            .lock()
            .map_err(|_| ProofGeneratorError::internal("proof generator mutex poisoned"))?
            .generate_proof(request_id, window, entries, now_millis)
    }
}

impl Clone for ConcurrentProofGenerator {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::connector::vef_execution_receipt::{
        ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };
    use super::super::proof_scheduler::{ProofWindow, WorkloadTier};
    use super::super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use super::*;
    use std::collections::BTreeMap;

    fn receipt(action: ExecutionActionType, n: u64) -> ExecutionReceipt {
        let mut capability_context = BTreeMap::new();
        capability_context.insert("domain".to_string(), "runtime".to_string());
        capability_context.insert("scope".to_string(), "extensions".to_string());
        capability_context.insert("capability".to_string(), format!("capability-{n}"));
        ExecutionReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
            action_type: action,
            capability_context,
            actor_identity: format!("actor-{n}"),
            artifact_identity: format!("artifact-{n}"),
            policy_snapshot_hash: format!("sha256:{n:064x}"),
            timestamp_millis: 1_702_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["w-a".to_string(), "w-b".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    fn sample_chain_entries() -> Vec<ReceiptChainEntry> {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for n in 0..4_u64 {
            chain
                .append(
                    receipt(ExecutionActionType::NetworkAccess, n),
                    1_702_000_010_000 + n,
                    "trace-sample",
                )
                .unwrap();
        }
        chain.entries().to_vec()
    }

    fn sample_window() -> ProofWindow {
        ProofWindow {
            window_id: "win-0-3".to_string(),
            start_index: 0,
            end_index: 3,
            entry_count: 4,
            aligned_checkpoint_id: None,
            tier: WorkloadTier::High,
            created_at_millis: 1_702_000_020_000,
            trace_id: "trace-win".to_string(),
        }
    }

    fn test_generator() -> ProofGenerator {
        let backend = Arc::new(TestProofBackend::new());
        ProofGenerator::new(backend, ProofGeneratorConfig::default())
    }

    // ── 1. Test backend generates proof successfully ──

    #[test]
    fn test_backend_generates_proof() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-001".to_string(),
            window: window.clone(),
            entries: entries.clone(),
            timeout_millis: 60_000,
            trace_id: "trace-test".to_string(),
            created_at_millis: 1_702_000_030_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert_eq!(proof.backend_name, "test-hash");
        assert!(!proof.proof_data.is_empty());
        assert!(proof.proof_data_hash.starts_with("sha256:"));
    }

    // ── 2. Empty window returns error ──

    #[test]
    fn test_backend_rejects_empty_window() {
        let backend = TestProofBackend::new();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-empty".to_string(),
            window,
            entries: vec![],
            timeout_millis: 60_000,
            trace_id: "trace-empty".to_string(),
            created_at_millis: 1_702_000_031_000,
        };
        let err = backend.generate(&request).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PGN_WINDOW_EMPTY);
    }

    // ── 3. Proof format is versioned ──

    #[test]
    fn proof_carries_format_version() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-ver".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-ver".to_string(),
            created_at_millis: 1_702_000_032_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert_eq!(proof.format_version, PROOF_FORMAT_VERSION);
    }

    // ── 4. Proof is self-describing with backend name ──

    #[test]
    fn proof_carries_backend_name() {
        let backend = TestProofBackend::with_name("custom-backend");
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-name".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-name".to_string(),
            created_at_millis: 1_702_000_033_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert_eq!(proof.backend_name, "custom-backend");
    }

    // ── 5. Deterministic proof generation ──

    #[test]
    fn deterministic_proof_generation() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req1 = ProofRequest {
            request_id: "req-a".to_string(),
            window: window.clone(),
            entries: entries.clone(),
            timeout_millis: 60_000,
            trace_id: "trace-a".to_string(),
            created_at_millis: 1_702_000_034_000,
        };
        let req2 = ProofRequest {
            request_id: "req-b".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-b".to_string(),
            created_at_millis: 1_702_000_034_000,
        };
        let proof1 = backend.generate(&req1).unwrap();
        let proof2 = backend.generate(&req2).unwrap();
        assert_eq!(proof1.proof_data, proof2.proof_data);
        assert_eq!(proof1.proof_data_hash, proof2.proof_data_hash);
    }

    // ── 6. Proof verification succeeds for matching entries ──

    #[test]
    fn verify_proof_succeeds_for_matching_entries() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-verify".to_string(),
            window,
            entries: entries.clone(),
            timeout_millis: 60_000,
            trace_id: "trace-verify".to_string(),
            created_at_millis: 1_702_000_035_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert!(backend.verify(&proof, &entries).unwrap());
    }

    // ── 7. Proof verification fails for mismatched entries ──

    #[test]
    fn verify_proof_fails_for_mismatched_entries() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-mismatch".to_string(),
            window,
            entries: entries.clone(),
            timeout_millis: 60_000,
            trace_id: "trace-mismatch".to_string(),
            created_at_millis: 1_702_000_036_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert!(!backend.verify(&proof, &entries[..2]).unwrap());
    }

    // ── 8. Proof verification with empty entries returns false ──

    #[test]
    fn verify_proof_empty_entries_returns_false() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-empty-verify".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-ev".to_string(),
            created_at_millis: 1_702_000_037_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert!(!backend.verify(&proof, &[]).unwrap());
    }

    // ── 9. ProofGenerator submit_request success ──

    #[test]
    fn generator_submit_request_success() {
        let mut pg = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = pg
            .submit_request(&window, &entries, 1_702_000_040_000, "trace-submit")
            .unwrap();
        assert!(req_id.starts_with("req-"));
        assert_eq!(pg.requests().len(), 1);
        assert_eq!(
            pg.requests().get(&req_id).unwrap().status,
            ProofStatus::Pending
        );
    }

    // ── 10. ProofGenerator rejects empty entries ──

    #[test]
    fn generator_rejects_empty_entries() {
        let mut pg = test_generator();
        let window = sample_window();
        let err = pg
            .submit_request(&window, &[], 1_702_000_041_000, "trace-empty-gen")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PGN_WINDOW_EMPTY);
    }

    // ── 11. ProofGenerator generate_proof completes ──

    #[test]
    fn generator_generate_proof_completes() {
        let mut pg = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = pg
            .submit_request(&window, &entries, 1_702_000_042_000, "trace-gen")
            .unwrap();
        let proof = pg
            .generate_proof(&req_id, &window, &entries, 1_702_000_042_100)
            .unwrap();
        assert_eq!(
            pg.requests().get(&req_id).unwrap().status,
            ProofStatus::Complete
        );
        assert!(proof.proof_id.contains(&req_id));
    }

    // ── 12. ProofGenerator verify_proof ──

    #[test]
    fn generator_verify_proof() {
        let mut pg = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = pg
            .submit_request(&window, &entries, 1_702_000_043_000, "trace-gv")
            .unwrap();
        let proof = pg
            .generate_proof(&req_id, &window, &entries, 1_702_000_043_100)
            .unwrap();
        let valid = pg.verify_proof(&proof, &entries, "trace-gv").unwrap();
        assert!(valid);
    }

    // ── 13. Event codes emitted in order ──

    #[test]
    fn events_emitted_in_order() {
        let mut pg = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = pg
            .submit_request(&window, &entries, 1_702_000_044_000, "trace-events")
            .unwrap();
        pg.generate_proof(&req_id, &window, &entries, 1_702_000_044_100)
            .unwrap();
        let events = pg.events();
        let codes: Vec<&str> = events.iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::PGN_005_BACKEND_REGISTERED));
        assert!(codes.contains(&event_codes::PGN_001_REQUEST_RECEIVED));
        assert!(codes.contains(&event_codes::PGN_002_GENERATION_STARTED));
        assert!(codes.contains(&event_codes::PGN_003_GENERATION_COMPLETE));
    }

    // ── 14. Timeout enforcement ──

    #[test]
    fn enforce_timeouts_marks_expired_requests() {
        let backend = Arc::new(TestProofBackend::new());
        let config = ProofGeneratorConfig {
            default_timeout_millis: 1_000,
            ..ProofGeneratorConfig::default()
        };
        let mut pgr = ProofGenerator::new(backend, config);
        let entries = sample_chain_entries();
        let window = sample_window();
        pgr.submit_request(&window, &entries, 1_702_000_050_000, "trace-timeout")
            .unwrap();
        let timed_out = pgr.enforce_timeouts(1_702_000_052_000);
        assert_eq!(timed_out.len(), 1);
        let status = pgr.requests().values().next().unwrap();
        assert_eq!(status.status, ProofStatus::Failed);
        assert_eq!(
            status.error.as_ref().unwrap().code,
            error_codes::ERR_PGN_TIMEOUT
        );
    }

    // ── 15. Status counts ──

    #[test]
    fn status_counts_accurate() {
        let mut pgr = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        pgr.submit_request(&window, &entries, 1_702_000_060_000, "trace-counts-1")
            .unwrap();
        let req2 = pgr
            .submit_request(&window, &entries, 1_702_000_060_001, "trace-counts-2")
            .unwrap();
        pgr.generate_proof(&req2, &window, &entries, 1_702_000_060_100)
            .unwrap();
        let counts = pgr.status_counts();
        assert_eq!(*counts.get("pending").unwrap(), 1);
        assert_eq!(*counts.get("complete").unwrap(), 1);
    }

    // ── 16. Backend swap ──

    #[test]
    fn swap_backend_changes_name() {
        let mut pgr = test_generator();
        assert_eq!(pgr.backend_name(), "test-hash");
        let new_backend = Arc::new(TestProofBackend::with_name("zk-groth16"));
        pgr.swap_backend(new_backend, "trace-swap");
        assert_eq!(pgr.backend_name(), "zk-groth16");
        let swap_events: Vec<_> = pgr
            .events()
            .iter()
            .filter(|e| e.detail.contains("swapped"))
            .collect();
        assert!(!swap_events.is_empty());
    }

    // ── 17. Proof metadata contains entry count ──

    #[test]
    fn proof_metadata_contains_entry_count() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-meta".to_string(),
            window,
            entries: entries.clone(),
            timeout_millis: 60_000,
            trace_id: "trace-meta".to_string(),
            created_at_millis: 1_702_000_070_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert_eq!(
            proof.metadata.get("entry_count").unwrap(),
            &entries.len().to_string()
        );
    }

    // ── 18. Proof receipt_window_ref matches window_id ──

    #[test]
    fn proof_receipt_window_ref_matches_window() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-ref".to_string(),
            window: window.clone(),
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-ref".to_string(),
            created_at_millis: 1_702_000_071_000,
        };
        let proof = backend.generate(&request).unwrap();
        assert_eq!(proof.receipt_window_ref, window.window_id);
    }

    // ── 19. Pending request capacity enforced ──

    #[test]
    fn pending_capacity_enforced() {
        let backend = Arc::new(TestProofBackend::new());
        let config = ProofGeneratorConfig {
            max_pending_requests: 2,
            ..ProofGeneratorConfig::default()
        };
        let mut pgr = ProofGenerator::new(backend, config);
        let entries = sample_chain_entries();
        let window = sample_window();
        pgr.submit_request(&window, &entries, 1_702_000_080_000, "t1")
            .unwrap();
        pgr.submit_request(&window, &entries, 1_702_000_080_001, "t2")
            .unwrap();
        let err = pgr
            .submit_request(&window, &entries, 1_702_000_080_002, "t3")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
    }

    // ── 20. Max entries per request enforced ──

    #[test]
    fn max_entries_per_request_enforced() {
        let backend = Arc::new(TestProofBackend::new());
        let config = ProofGeneratorConfig {
            max_entries_per_request: 2,
            ..ProofGeneratorConfig::default()
        };
        let mut pgr = ProofGenerator::new(backend, config);
        let entries = sample_chain_entries(); // 4 entries
        let window = sample_window();
        let err = pgr
            .submit_request(&window, &entries, 1_702_000_081_000, "t-max")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
    }

    // ── 21. Schema version is set correctly ──

    #[test]
    fn schema_version_set() {
        let pgr = test_generator();
        assert_eq!(pgr.schema_version, PROOF_GENERATOR_SCHEMA_VERSION);
    }

    // ── 22. ComplianceProof serde round-trip ──

    #[test]
    fn compliance_proof_serde_roundtrip() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-serde".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-serde".to_string(),
            created_at_millis: 1_702_000_090_000,
        };
        let proof = backend.generate(&request).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ComplianceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    // ── 23. ProofRequest serde round-trip ──

    #[test]
    fn proof_request_serde_roundtrip() {
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-rt".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-rt".to_string(),
            created_at_millis: 1_702_000_091_000,
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ProofRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request, deserialized);
    }

    // ── 24. ProofGeneratorError Display ──

    #[test]
    fn error_display_format() {
        let err = ProofGeneratorError::backend_unavailable("no backend found");
        let display = format!("{err}");
        assert!(display.contains(error_codes::ERR_PGN_BACKEND_UNAVAILABLE));
        assert!(display.contains("no backend found"));
    }

    // ── 25. ProofStatus serde round-trip ──

    #[test]
    fn proof_status_serde_roundtrip() {
        for status in [
            ProofStatus::Pending,
            ProofStatus::Generating,
            ProofStatus::Complete,
            ProofStatus::Failed,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ProofStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    // ── 26. ConcurrentProofGenerator submit and generate ──

    #[test]
    fn concurrent_generator_submit_and_generate() {
        let backend = Arc::new(TestProofBackend::new());
        let cpg = ConcurrentProofGenerator::new(backend, ProofGeneratorConfig::default());
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = cpg
            .submit_request(&window, &entries, 1_702_000_100_000, "trace-conc")
            .unwrap();
        let proof = cpg
            .generate_proof(&req_id, &window, &entries, 1_702_000_100_100)
            .unwrap();
        assert!(!proof.proof_data.is_empty());
    }

    // ── 27. Proof data hash integrity ──

    #[test]
    fn proof_data_hash_integrity() {
        let backend = TestProofBackend::new();
        let entries = sample_chain_entries();
        let window = sample_window();
        let request = ProofRequest {
            request_id: "req-hash".to_string(),
            window,
            entries,
            timeout_millis: 60_000,
            trace_id: "trace-hash".to_string(),
            created_at_millis: 1_702_000_110_000,
        };
        let proof = backend.generate(&request).unwrap();
        let recomputed = TestProofBackend::hash_bytes(&proof.proof_data);
        assert_eq!(proof.proof_data_hash, recomputed);
    }

    // ── 28. Different entries produce different proofs ──

    #[test]
    fn different_entries_produce_different_proofs() {
        let backend = TestProofBackend::new();
        let entries1 = sample_chain_entries();
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 0,
            checkpoint_every_millis: 0,
        });
        for n in 10..14_u64 {
            chain
                .append(
                    receipt(ExecutionActionType::SecretAccess, n),
                    1_702_000_120_000 + n,
                    "trace-diff",
                )
                .unwrap();
        }
        let entries2 = chain.entries().to_vec();
        let window = sample_window();

        let req1 = ProofRequest {
            request_id: "req-d1".to_string(),
            window: window.clone(),
            entries: entries1,
            timeout_millis: 60_000,
            trace_id: "trace-d1".to_string(),
            created_at_millis: 1_702_000_130_000,
        };
        let req2 = ProofRequest {
            request_id: "req-d2".to_string(),
            window,
            entries: entries2,
            timeout_millis: 60_000,
            trace_id: "trace-d2".to_string(),
            created_at_millis: 1_702_000_130_000,
        };
        let proof1 = backend.generate(&req1).unwrap();
        let proof2 = backend.generate(&req2).unwrap();
        assert_ne!(proof1.proof_data, proof2.proof_data);
    }

    // ── 29. Backend name reported correctly ──

    #[test]
    fn backend_name_reported() {
        let pgr = test_generator();
        assert_eq!(pgr.backend_name(), "test-hash");
    }

    // ── 30. ProofGeneratorEvent has all fields populated ──

    #[test]
    fn events_have_all_fields() {
        let mut pgr = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        pgr.submit_request(&window, &entries, 1_702_000_140_000, "trace-fields")
            .unwrap();
        for event in pgr.events() {
            assert!(!event.event_code.is_empty());
            assert!(!event.trace_id.is_empty());
            assert!(!event.detail.is_empty());
        }
    }
}
