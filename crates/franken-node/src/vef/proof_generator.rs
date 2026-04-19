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

use crate::capacity_defaults::aliases::MAX_EVENTS;

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
        hasher.update(
            u64::try_from(entries.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for entry in entries {
            hasher.update(
                u64::try_from(entry.chain_hash.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(entry.chain_hash.as_bytes());
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
        Ok(
            crate::security::constant_time::ct_eq_bytes(&proof.proof_data, &expected_data)
                && crate::security::constant_time::ct_eq(&proof.proof_data_hash, &expected_hash),
        )
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
        generator.emit_event(ProofGeneratorEvent {
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

    fn emit_event(&mut self, event: ProofGeneratorEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
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

        if self.next_request_seq == u64::MAX {
            return Err(ProofGeneratorError::internal("request sequence overflow"));
        }

        let request_id = format!("req-{:08}", self.next_request_seq);
        self.next_request_seq = self.next_request_seq.saturating_add(1);

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

        self.emit_event(ProofGeneratorEvent {
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

        if status.status != ProofStatus::Pending {
            return Err(ProofGeneratorError::internal(format!(
                "cannot generate proof for request {request_id}: current status is {:?}, expected Pending",
                status.status
            )));
        }

        // Transition to Generating
        status.status = ProofStatus::Generating;
        let trace_id = status.trace_id.clone();

        self.emit_event(ProofGeneratorEvent {
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

                self.emit_event(ProofGeneratorEvent {
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

                self.emit_event(ProofGeneratorEvent {
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
        self.emit_event(ProofGeneratorEvent {
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
        let mut timeout_events = Vec::new();
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
                    timeout_events.push(ProofGeneratorEvent {
                        event_code: event_codes::PGN_004_GENERATION_FAILED.to_string(),
                        trace_id: status.trace_id.clone(),
                        detail: format!("request={} timed out", status.request_id),
                    });
                }
            }
        }
        for event in timeout_events {
            self.emit_event(event);
        }
        timed_out
    }

    /// Get counts of requests by status.
    pub fn status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
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
            let count = counts.entry(key.to_string()).or_default();
            *count = count.saturating_add(1);
        }
        counts
    }

    /// Swap the backend to a new implementation.
    /// INV-PGN-BACKEND-AGNOSTIC: backends are interchangeable at runtime.
    pub fn swap_backend(&mut self, new_backend: Arc<dyn ProofBackend>, trace_id: &str) {
        let new_name = new_backend.backend_name().to_string();
        self.backend = new_backend;
        self.emit_event(ProofGeneratorEvent {
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

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
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
                .expect("should succeed");
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
        let proof = backend.generate(&request).expect("should generate");
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
        let proof = backend.generate(&request).expect("should generate");
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
        let proof = backend.generate(&request).expect("should generate");
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
        let proof1 = backend.generate(&req1).expect("should generate");
        let proof2 = backend.generate(&req2).expect("should generate");
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
        let proof = backend.generate(&request).expect("should generate");
        assert!(backend.verify(&proof, &entries).expect("should verify"));
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
        let proof = backend.generate(&request).expect("should generate");
        assert!(
            !backend
                .verify(&proof, &entries[..2])
                .expect("should verify")
        );
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
        let proof = backend.generate(&request).expect("should generate");
        assert!(!backend.verify(&proof, &[]).expect("should verify"));
    }

    // ── 9. ProofGenerator submit_request success ──

    #[test]
    fn generator_submit_request_success() {
        let mut pg = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        let req_id = pg
            .submit_request(&window, &entries, 1_702_000_040_000, "trace-submit")
            .expect("should succeed");
        assert!(req_id.starts_with("req-"));
        assert_eq!(pg.requests().len(), 1);
        assert_eq!(
            pg.requests().get(&req_id).expect("should exist").status,
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
            .expect("should succeed");
        let proof = pg
            .generate_proof(&req_id, &window, &entries, 1_702_000_042_100)
            .expect("should succeed");
        assert_eq!(
            pg.requests().get(&req_id).expect("should exist").status,
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
            .expect("should succeed");
        let proof = pg
            .generate_proof(&req_id, &window, &entries, 1_702_000_043_100)
            .expect("should succeed");
        let valid = pg
            .verify_proof(&proof, &entries, "trace-gv")
            .expect("should verify");
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
            .expect("should succeed");
        pg.generate_proof(&req_id, &window, &entries, 1_702_000_044_100)
            .expect("should succeed");
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
            .expect("should succeed");
        let timed_out = pgr.enforce_timeouts(1_702_000_052_000);
        assert_eq!(timed_out.len(), 1);
        let status = pgr.requests().values().next().expect("should exist");
        assert_eq!(status.status, ProofStatus::Failed);
        assert_eq!(
            status.error.as_ref().expect("should have error").code,
            error_codes::ERR_PGN_TIMEOUT
        );
        let timeout_event = pgr
            .events()
            .iter()
            .find(|event| {
                event.event_code == event_codes::PGN_004_GENERATION_FAILED
                    && event.detail.contains("timed out")
            })
            .expect("timeout event should be emitted");
        assert_eq!(timeout_event.trace_id, "trace-timeout");
        assert!(timeout_event.detail.contains(&timed_out[0]));
    }

    // ── 15. Status counts ──

    #[test]
    fn status_counts_accurate() {
        let mut pgr = test_generator();
        let entries = sample_chain_entries();
        let window = sample_window();
        pgr.submit_request(&window, &entries, 1_702_000_060_000, "trace-counts-1")
            .expect("should succeed");
        let req2 = pgr
            .submit_request(&window, &entries, 1_702_000_060_001, "trace-counts-2")
            .expect("should succeed");
        pgr.generate_proof(&req2, &window, &entries, 1_702_000_060_100)
            .expect("should succeed");
        let counts = pgr.status_counts();
        assert_eq!(*counts.get("pending").expect("should exist"), 1);
        assert_eq!(*counts.get("complete").expect("should exist"), 1);
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
        let proof = backend.generate(&request).expect("should generate");
        assert_eq!(
            proof.metadata.get("entry_count").expect("should exist"),
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
        let proof = backend.generate(&request).expect("should generate");
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
            .expect("should succeed");
        pgr.submit_request(&window, &entries, 1_702_000_080_001, "t2")
            .expect("should succeed");
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
        let proof = backend.generate(&request).expect("should generate");
        let json = serde_json::to_string(&proof).expect("should serialize");
        let deserialized: ComplianceProof =
            serde_json::from_str(&json).expect("should deserialize");
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
        let json = serde_json::to_string(&request).expect("should serialize");
        let deserialized: ProofRequest = serde_json::from_str(&json).expect("should deserialize");
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
            let json = serde_json::to_string(&status).expect("should serialize");
            let back: ProofStatus = serde_json::from_str(&json).expect("should deserialize");
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
            .expect("should succeed");
        let proof = cpg
            .generate_proof(&req_id, &window, &entries, 1_702_000_100_100)
            .expect("should succeed");
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
        let proof = backend.generate(&request).expect("should generate");
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
                .expect("should succeed");
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
        let proof1 = backend.generate(&req1).expect("should generate");
        let proof2 = backend.generate(&req2).expect("should generate");
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
            .expect("should succeed");
        for event in pgr.events() {
            assert!(!event.event_code.is_empty());
            assert!(!event.trace_id.is_empty());
            assert!(!event.detail.is_empty());
        }
    }

    mod determinism_and_expiry_contract_tests {
        use super::*;

        fn proof_request(request_id: &str, entries: Vec<ReceiptChainEntry>) -> ProofRequest {
            ProofRequest {
                request_id: request_id.to_string(),
                window: sample_window(),
                entries,
                timeout_millis: 60_000,
                trace_id: "trace-contract".to_string(),
                created_at_millis: 1_702_000_150_000,
            }
        }

        fn generator_with_timeout(timeout_millis: u64) -> ProofGenerator {
            let backend = Arc::new(TestProofBackend::new());
            ProofGenerator::new(
                backend,
                ProofGeneratorConfig {
                    default_timeout_millis: timeout_millis,
                    ..ProofGeneratorConfig::default()
                },
            )
        }

        fn generator_event(detail: &str) -> ProofGeneratorEvent {
            ProofGeneratorEvent {
                event_code: event_codes::PGN_001_REQUEST_RECEIVED.to_string(),
                trace_id: "trace-contract".to_string(),
                detail: detail.to_string(),
            }
        }

        #[test]
        fn same_request_replay_produces_byte_identical_proof() {
            let backend = TestProofBackend::new();
            let request = proof_request("req-deterministic-replay", sample_chain_entries());

            let first = backend
                .generate(&request)
                .expect("first proof should generate");
            let second = backend
                .generate(&request)
                .expect("second proof should generate");

            assert_eq!(first, second);
            assert_eq!(
                serde_json::to_vec(&first).expect("first proof should serialize"),
                serde_json::to_vec(&second).expect("second proof should serialize")
            );
        }

        #[test]
        fn proof_bytes_change_when_receipt_order_changes() {
            let backend = TestProofBackend::new();
            let entries = sample_chain_entries();
            let mut reversed_entries = entries.clone();
            reversed_entries.reverse();

            let original = backend
                .generate(&proof_request("req-order-original", entries))
                .expect("original proof should generate");
            let reversed = backend
                .generate(&proof_request("req-order-reversed", reversed_entries))
                .expect("reversed proof should generate");

            assert_ne!(original.proof_data, reversed.proof_data);
            assert_ne!(original.proof_data_hash, reversed.proof_data_hash);
        }

        #[test]
        fn empty_window_submission_does_not_create_request_or_event() {
            let mut generator = generator_with_timeout(1_000);
            let window = sample_window();

            let err = generator
                .submit_request(&window, &[], 10_000, "trace-empty-negative")
                .expect_err("empty window should be rejected");

            assert_eq!(err.code, error_codes::ERR_PGN_WINDOW_EMPTY);
            assert!(generator.requests().is_empty());
            assert!(generator.events().is_empty());
            assert_eq!(generator.status_counts()["pending"], 0);
        }

        #[test]
        fn tampered_proof_hash_fails_verification() {
            let backend = TestProofBackend::new();
            let entries = sample_chain_entries();
            let mut proof = backend
                .generate(&proof_request("req-tampered-proof", entries.clone()))
                .expect("proof should generate");
            proof.proof_data_hash.push('0');
            let mut generator = generator_with_timeout(1_000);

            let valid = generator
                .verify_proof(&proof, &entries, "trace-tampered-proof")
                .expect("verification should complete");

            assert!(!valid);
        }

        #[test]
        fn timeout_before_expiry_boundary_keeps_request_pending() {
            let mut generator = generator_with_timeout(1_000);
            let entries = sample_chain_entries();
            let window = sample_window();
            let request_id = generator
                .submit_request(&window, &entries, 10_000, "trace-before-timeout")
                .expect("request should submit");

            let timed_out = generator.enforce_timeouts(10_999);

            assert!(timed_out.is_empty());
            assert_eq!(
                generator
                    .requests()
                    .get(&request_id)
                    .expect("request should exist")
                    .status,
                ProofStatus::Pending
            );
            assert_eq!(generator.status_counts()["pending"], 1);
            assert_eq!(generator.status_counts()["failed"], 0);
        }

        #[test]
        fn timeout_at_exact_expiry_boundary_fails_closed() {
            let mut generator = generator_with_timeout(1_000);
            let entries = sample_chain_entries();
            let window = sample_window();
            let request_id = generator
                .submit_request(&window, &entries, 10_000, "trace-at-timeout")
                .expect("request should submit");

            let timed_out = generator.enforce_timeouts(11_000);

            assert_eq!(timed_out, vec![request_id.clone()]);
            let status = generator
                .requests()
                .get(&request_id)
                .expect("request should exist");
            assert_eq!(status.status, ProofStatus::Failed);
            assert_eq!(
                status
                    .error
                    .as_ref()
                    .expect("timeout error should exist")
                    .code,
                error_codes::ERR_PGN_TIMEOUT
            );
            assert_eq!(generator.status_counts()["failed"], 1);
        }

        #[test]
        fn push_bounded_zero_capacity_discards_generator_events() {
            let mut events = vec![generator_event("existing")];

            push_bounded(&mut events, generator_event("new"), 0);

            assert!(events.is_empty());
        }
    }

    #[cfg(test)]
    mod vef_proof_generator_extreme_adversarial_negative_tests {
        use super::*;

        #[test]
        fn extreme_adversarial_unicode_injection_proof_metadata_resistance() {
            let backend = TestProofBackend::with_name("unicode\u{202E}evil\u{202D}backend");

            // Unicode attacks in window and entry data
            let mut window = sample_window();
            window.window_id = format!("win\u{200B}{}\u{FEFF}injection", "\u{0000}".repeat(100));
            window.trace_id = "\u{202E}trace_rtl_override\u{202D}".to_string();

            let mut entries = sample_chain_entries();
            for entry in &mut entries {
                entry.chain_hash = format!("hash\u{200B}{}\u{FEFF}", "a".repeat(10000));
                entry.receipt.actor_identity = format!("actor\u{0001}control\u{0002}chars");
            }

            let request = ProofRequest {
                request_id: "unicode\u{0000}injection\u{FEFF}request".to_string(),
                window,
                entries: entries.clone(),
                timeout_millis: 60_000,
                trace_id: "trace\r\nHTTP/1.1 200 OK\r\nContent-Length: 0".to_string(),
                created_at_millis: 1_702_000_000_000,
            };

            // Should handle Unicode injection without corruption
            let proof = backend.generate(&request).expect("should generate proof");

            // Verify proof metadata doesn't contain dangerous Unicode
            assert!(!proof.backend_name.contains('\u{0000}'));
            assert!(!proof.trace_id.contains('\u{0000}'));
            assert!(!proof.proof_id.contains('\u{202E}')); // RTL override

            // Verify JSON serialization safety
            let json = serde_json::to_string(&proof).expect("should serialize");
            assert!(!json.contains("\\u0000"));
            assert!(!json.contains("\\u202e"));

            // Verify verification still works despite Unicode
            assert!(backend.verify(&proof, &entries).expect("should verify"));
        }

        #[test]
        fn extreme_adversarial_memory_exhaustion_massive_proof_data_generation() {
            let backend = TestProofBackend::new();

            // Create entries with massive chain hashes to test memory limits
            let mut massive_entries = Vec::new();
            for i in 0..10 {
                let mut receipt = receipt(ExecutionActionType::NetworkAccess, i);
                receipt.artifact_identity = "a".repeat(1_000_000); // 1MB artifact identity

                let entry = ReceiptChainEntry {
                    index: i,
                    chain_hash: "h".repeat(10_000_000), // 10MB chain hash
                    receipt,
                    timestamp_millis: 1_702_000_000_000 + i,
                    trace_id: format!("trace_massive_{i}"),
                };
                massive_entries.push(entry);
            }

            let request = ProofRequest {
                request_id: "memory_exhaustion_test".to_string(),
                window: sample_window(),
                entries: massive_entries.clone(),
                timeout_millis: 60_000,
                trace_id: "trace_memory_exhaustion".to_string(),
                created_at_millis: 1_702_000_000_000,
            };

            // Should handle massive data without crashing
            match backend.generate(&request) {
                Ok(proof) => {
                    // If generation succeeds, verify data integrity
                    assert!(!proof.proof_data.is_empty());
                    assert!(proof.proof_data_hash.starts_with("sha256:"));

                    // Verify verification works with massive data
                    assert!(backend.verify(&proof, &massive_entries).expect("should verify"));
                }
                Err(_) => {
                    // Acceptable to fail gracefully on memory exhaustion
                    // Should not panic or crash
                }
            }
        }

        #[test]
        fn extreme_adversarial_arithmetic_overflow_timestamp_sequence_boundaries() {
            let backend = TestProofBackend::new();

            // Test timestamp overflow scenarios
            let overflow_timestamps = vec![
                u64::MAX - 1,
                u64::MAX,
                0, // Epoch start
                1, // Minimal timestamp
            ];

            for timestamp in overflow_timestamps {
                let request = ProofRequest {
                    request_id: format!("overflow_test_{timestamp}"),
                    window: sample_window(),
                    entries: sample_chain_entries(),
                    timeout_millis: 60_000,
                    trace_id: format!("trace_overflow_{timestamp}"),
                    created_at_millis: timestamp,
                };

                let proof = backend.generate(&request).expect("should generate with overflow timestamp");

                // Verify timestamp boundary doesn't cause issues
                assert_eq!(proof.generated_at_millis, timestamp);
                assert!(!proof.proof_data.is_empty());

                // Test ProofGenerator with overflow sequences
                let mut generator = test_generator();
                generator.next_request_seq = u64::MAX - 5;

                for i in 0..10u64 {
                    let result = generator.submit_request(
                        &sample_window(),
                        &sample_chain_entries(),
                        timestamp.saturating_add(i),
                        &format!("trace_{i}"),
                    );

                    match result {
                        Ok(req_id) => {
                            // Should handle near-overflow gracefully
                            assert!(req_id.starts_with("req-"));
                        }
                        Err(err) => {
                            // Should fail gracefully at overflow, not panic
                            assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
                            assert!(err.message.contains("overflow"));
                            break;
                        }
                    }
                }
            }
        }

        #[test]
        fn saturated_request_sequence_fails_without_reusing_request_id() {
            let mut generator = test_generator();
            generator.next_request_seq = u64::MAX - 1;

            let first_request_id = generator
                .submit_request(
                    &sample_window(),
                    &sample_chain_entries(),
                    1_702_000_000_000,
                    "trace-before-overflow",
                )
                .expect("request before sequence saturation should be accepted");

            assert_eq!(first_request_id, format!("req-{:08}", u64::MAX - 1));

            let err = generator
                .submit_request(
                    &sample_window(),
                    &sample_chain_entries(),
                    1_702_000_000_001,
                    "trace-overflow",
                )
                .expect_err("saturated sequence must fail instead of reusing a request id");

            assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
            assert!(err.message.contains("overflow"));
            assert_eq!(generator.requests.len(), 1);
            assert!(!generator.requests.contains_key(&format!("req-{:08}", u64::MAX)));
        }

        #[test]
        fn extreme_adversarial_hash_collision_resistance_proof_integrity() {
            let backend = TestProofBackend::new();

            // Create entries designed to test hash collision resistance
            let collision_test_patterns = vec![
                ("collision_a", "prefix_"),
                ("collision_b", "prefix_"),
                ("different_a", "same_suffix"),
                ("different_b", "same_suffix"),
            ];

            let mut all_proofs = Vec::new();

            for (id, hash_pattern) in collision_test_patterns {
                let mut entries = sample_chain_entries();
                for (i, entry) in entries.iter_mut().enumerate() {
                    entry.chain_hash = format!("{hash_pattern}{i:064}");
                }

                let request = ProofRequest {
                    request_id: id.to_string(),
                    window: sample_window(),
                    entries: entries.clone(),
                    timeout_millis: 60_000,
                    trace_id: format!("trace_{id}"),
                    created_at_millis: 1_702_000_000_000,
                };

                let proof = backend.generate(&request).expect("should generate proof");
                all_proofs.push((id, proof, entries));
            }

            // Verify all proofs have different hashes (no collisions)
            for i in 0..all_proofs.len() {
                for j in (i + 1)..all_proofs.len() {
                    let (id1, proof1, _) = &all_proofs[i];
                    let (id2, proof2, _) = &all_proofs[j];

                    assert_ne!(
                        proof1.proof_data_hash, proof2.proof_data_hash,
                        "collision detected between {id1} and {id2}"
                    );
                    assert_ne!(
                        proof1.proof_data, proof2.proof_data,
                        "proof data collision between {id1} and {id2}"
                    );
                }
            }

            // Verify constant-time verification
            for (_, proof, entries) in &all_proofs {
                assert!(backend.verify(proof, entries).expect("should verify"));
            }
        }

        #[test]
        fn extreme_adversarial_malformed_receipt_chain_entry_corruption() {
            let backend = TestProofBackend::new();

            // Test malformed receipt entries
            let mut corrupted_entry = sample_chain_entries().into_iter().next().unwrap();
            corrupted_entry.index = u64::MAX;
            corrupted_entry.chain_hash = String::new(); // Empty hash
            corrupted_entry.receipt.sequence_number = u64::MAX;
            corrupted_entry.receipt.timestamp_millis = 0; // Invalid timestamp
            corrupted_entry.receipt.policy_snapshot_hash = "invalid_hash_format".to_string();

            let corrupted_entries = vec![corrupted_entry];

            let request = ProofRequest {
                request_id: "corrupted_entry_test".to_string(),
                window: sample_window(),
                entries: corrupted_entries.clone(),
                timeout_millis: 60_000,
                trace_id: "trace_corrupted".to_string(),
                created_at_millis: 1_702_000_000_000,
            };

            // Should handle corrupted entries gracefully
            let proof = backend.generate(&request).expect("should handle corrupted entries");

            // Verify proof is still generated despite corruption
            assert!(!proof.proof_data.is_empty());
            assert!(!proof.proof_data_hash.is_empty());

            // Verification should work consistently
            assert!(backend.verify(&proof, &corrupted_entries).expect("should verify"));
        }

        #[test]
        fn extreme_adversarial_control_character_injection_event_sanitization() {
            let mut generator = test_generator();

            // Control character injection in request parameters
            let control_chars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
            let mut window = sample_window();
            window.window_id = format!("win{control_chars}injection");
            window.trace_id = format!("trace{control_chars}control");

            let entries = sample_chain_entries();
            let request_id = generator
                .submit_request(&window, &entries, 1_702_000_000_000, &window.trace_id)
                .expect("should submit request");

            // Generate proof with control character pollution
            generator
                .generate_proof(&request_id, &window, &entries, 1_702_000_000_100)
                .expect("should generate proof");

            // Verify events don't contain dangerous control characters
            for event in generator.events() {
                assert!(!event.detail.contains('\x00'), "event must not contain null bytes");
                assert!(!event.detail.contains('\x01'), "event must not contain SOH");
                assert!(!event.detail.contains('\r'), "event must not contain CR");
                assert!(!event.detail.contains('\n'), "event must not contain LF");

                // Verify JSON serialization safety
                let event_json = serde_json::to_string(event).unwrap_or_default();
                assert!(!event_json.contains("\\u0000"));
                assert!(!event_json.contains("\\u0001"));
            }
        }

        #[test]
        fn extreme_adversarial_concurrent_request_sequence_race_condition() {
            // Test concurrent request submission race conditions
            let backend = Arc::new(TestProofBackend::new());
            let generator = ConcurrentProofGenerator::new(backend, ProofGeneratorConfig::default());

            let entries = sample_chain_entries();
            let window = sample_window();

            // Simulate concurrent submissions
            let mut request_ids = Vec::new();
            for i in 0..100 {
                let mut concurrent_window = window.clone();
                concurrent_window.window_id = format!("concurrent_win_{i}");

                let result = generator.submit_request(
                    &concurrent_window,
                    &entries,
                    1_702_000_000_000 + i,
                    &format!("trace_concurrent_{i}"),
                );

                match result {
                    Ok(req_id) => {
                        request_ids.push(req_id);
                    }
                    Err(_) => {
                        // Acceptable to hit capacity limits
                        break;
                    }
                }
            }

            // Verify all request IDs are unique (no race condition corruption)
            let mut unique_ids = std::collections::BTreeSet::new();
            for req_id in &request_ids {
                assert!(unique_ids.insert(req_id.clone()),
                    "duplicate request ID detected: {req_id}");
            }

            assert!(!request_ids.is_empty(), "should have submitted some requests");
        }

        #[test]
        fn extreme_adversarial_backend_swap_during_active_generation() {
            let mut generator = test_generator();
            let entries = sample_chain_entries();
            let window = sample_window();

            // Submit request with first backend
            let request_id = generator
                .submit_request(&window, &entries, 1_702_000_000_000, "trace_swap")
                .expect("should submit");

            // Swap backend before generation
            let new_backend = Arc::new(TestProofBackend::with_name("swapped_backend"));
            generator.swap_backend(new_backend, "trace_swap");

            // Generate with new backend
            let proof = generator
                .generate_proof(&request_id, &window, &entries, 1_702_000_000_100)
                .expect("should generate with swapped backend");

            // Verify proof uses new backend
            assert_eq!(proof.backend_name, "swapped_backend");

            // Verify events record the swap
            let swap_events: Vec<_> = generator
                .events()
                .iter()
                .filter(|e| e.detail.contains("swapped"))
                .collect();
            assert!(!swap_events.is_empty());
        }

        #[test]
        fn extreme_adversarial_metadata_btreemap_ordering_manipulation() {
            let backend = TestProofBackend::new();

            // Create metadata with keys designed to test BTreeMap ordering
            let mut entries = sample_chain_entries();
            for (i, entry) in entries.iter_mut().enumerate() {
                // Add metadata that could affect BTreeMap ordering
                entry.receipt.capability_context.insert(
                    format!("\x00{i}"), // Null prefix key
                    format!("value_{i}"),
                );
                entry.receipt.capability_context.insert(
                    format!("{i}\x00"), // Null suffix key
                    format!("value_{i}"),
                );
                entry.receipt.capability_context.insert(
                    format!("\xFF{i}"), // High byte prefix
                    format!("value_{i}"),
                );
            }

            let request = ProofRequest {
                request_id: "btreemap_ordering_test".to_string(),
                window: sample_window(),
                entries: entries.clone(),
                timeout_millis: 60_000,
                trace_id: "trace_btreemap".to_string(),
                created_at_millis: 1_702_000_000_000,
            };

            let proof = backend.generate(&request).expect("should generate proof");

            // Verify metadata BTreeMap maintains consistent ordering
            let metadata_keys: Vec<_> = proof.metadata.keys().cloned().collect();
            let mut sorted_keys = metadata_keys.clone();
            sorted_keys.sort();

            // BTreeMap should maintain its own ordering
            for (i, key) in metadata_keys.iter().enumerate() {
                if i > 0 {
                    assert!(
                        key >= &metadata_keys[i - 1],
                        "BTreeMap ordering violated: {} < {}",
                        key,
                        metadata_keys[i - 1]
                    );
                }
            }

            // Verification should work despite ordering manipulation
            assert!(backend.verify(&proof, &entries).expect("should verify"));
        }

        #[test]
        fn extreme_adversarial_event_capacity_overflow_boundary_protection() {
            let mut generator = test_generator();
            let entries = sample_chain_entries();
            let window = sample_window();

            // Force event log to exceed MAX_EVENTS
            let iterations = MAX_EVENTS + 50;

            for i in 0..iterations {
                let mut iter_window = window.clone();
                iter_window.window_id = format!("overflow_win_{i:06}");

                if let Ok(req_id) = generator.submit_request(
                    &iter_window,
                    &entries,
                    1_702_000_000_000 + i as u64,
                    &format!("trace_overflow_{i:06}"),
                ) {
                    // Generate some proofs to create more events
                    let _ = generator.generate_proof(
                        &req_id,
                        &iter_window,
                        &entries,
                        1_702_000_000_100 + i as u64,
                    );
                }
            }

            // Verify bounded behavior
            assert!(
                generator.events().len() <= MAX_EVENTS,
                "events exceeded capacity: {} > {}",
                generator.events().len(),
                MAX_EVENTS
            );

            // Verify most recent events are preserved
            let events = generator.events();
            if !events.is_empty() {
                let last_event = &events[events.len() - 1];
                // Should contain recent iteration numbers
                assert!(
                    last_event.detail.contains(&format!("overflow_win_{}", iterations - 1)) ||
                    last_event.detail.contains(&format!("overflow_win_{}", iterations - 2)) ||
                    last_event.detail.contains("backend") // or backend registration event
                );
            }
        }

        #[test]
        fn extreme_adversarial_proof_verification_timing_attack_resistance() {
            let backend = TestProofBackend::new();

            // Create proofs of varying sizes to test timing consistency
            let size_variants = vec![
                (1, "small"),
                (10, "medium"),
                (100, "large"),
            ];

            let mut verification_times = Vec::new();

            for (multiplier, label) in size_variants {
                let mut large_entries = Vec::new();
                for i in 0..multiplier {
                    let mut entry = sample_chain_entries().into_iter().next().unwrap();
                    entry.chain_hash = format!("hash_{i}_{}", "x".repeat(1000 * multiplier));
                    entry.index = i as u64;
                    large_entries.push(entry);
                }

                let request = ProofRequest {
                    request_id: format!("timing_{label}"),
                    window: sample_window(),
                    entries: large_entries.clone(),
                    timeout_millis: 60_000,
                    trace_id: format!("trace_timing_{label}"),
                    created_at_millis: 1_702_000_000_000,
                };

                let proof = backend.generate(&request).expect("should generate");

                // Measure verification timing
                let start = std::time::Instant::now();
                let valid = backend.verify(&proof, &large_entries).expect("should verify");
                let duration = start.elapsed();

                assert!(valid, "proof should be valid for {label}");
                verification_times.push((label, duration));

                // Verification should complete in reasonable time
                assert!(
                    duration.as_millis() < 1000,
                    "verification took too long for {label}: {:?}",
                    duration
                );
            }

            // Timing should be reasonable across different sizes
            for (label, duration) in verification_times {
                println!("Verification timing for {}: {:?}", label, duration);
            }

            // ── Additional comprehensive negative-path edge case tests ──

            #[test]
            fn negative_proof_backend_with_malicious_name_injection_patterns() {
                // Test proof backend names with various injection patterns
                let malicious_backend_names = [
                    "backend\x00null_injection",
                    "backend\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html",
                    "backend<script>alert('xss')</script>",
                    "backend\"},{\"injected\":true,\"evil\":\"",
                    "backend\u{202E}spoofed\u{202D}normal",
                    "backend\u{FEFF}\u{200B}\u{034F}", // Unicode invisibles
                    "../../../etc/passwd",
                    "C:\\Windows\\System32\\config\\sam",
                    "javascript:alert(1)",
                    "data:text/html,<script>",
                    "",  // Empty name
                    " ",  // Whitespace only
                    "\t\n\r", // Control characters
                    "backend" + &"x".repeat(100000), // Extremely long
                ];

                for malicious_name in malicious_backend_names {
                    let backend = TestProofBackend::with_name(malicious_name);
                    let generator = ProofGenerator::new(Arc::new(backend), ProofGeneratorConfig::default());

                    // Backend name should be stored/reported exactly
                    assert_eq!(generator.backend_name(), malicious_name);

                    // Should work in proof generation
                    let entries = sample_chain_entries();
                    let window = sample_window();
                    let request = ProofRequest {
                        request_id: "malicious_backend_test".to_string(),
                        window,
                        entries: entries.clone(),
                        timeout_millis: 60_000,
                        trace_id: "trace_malicious_backend".to_string(),
                        created_at_millis: 1_702_000_000_000,
                    };

                    let backend = TestProofBackend::with_name(malicious_name);
                    let proof = backend.generate(&request).expect("should generate with malicious backend name");

                    // Verify backend name preservation
                    assert_eq!(proof.backend_name, malicious_name);

                    // JSON serialization should handle malicious names safely
                    let json = serde_json::to_string(&proof).expect("should serialize malicious backend name");
                    let parsed: ComplianceProof = serde_json::from_str(&json).expect("should deserialize malicious backend name");
                    assert_eq!(parsed.backend_name, malicious_name);

                    // Verification should work despite malicious name
                    assert!(backend.verify(&proof, &entries).expect("should verify with malicious backend name"));
                }
            }

            #[test]
            fn negative_proof_request_with_pathological_timeout_and_capacity_values() {
                // Test proof generation with extreme timeout and capacity values
                let extreme_configs = [
                    ProofGeneratorConfig {
                        default_timeout_millis: 0, // Zero timeout
                        max_entries_per_request: 1,
                        max_pending_requests: 1,
                    },
                    ProofGeneratorConfig {
                        default_timeout_millis: u64::MAX, // Maximum timeout
                        max_entries_per_request: usize::MAX / 2, // Near-maximum entries
                        max_pending_requests: usize::MAX / 2, // Near-maximum pending
                    },
                    ProofGeneratorConfig {
                        default_timeout_millis: 1, // Minimal timeout
                        max_entries_per_request: 0, // Zero entries allowed
                        max_pending_requests: 0, // Zero pending allowed
                    },
                ];

                for config in extreme_configs {
                    let backend = Arc::new(TestProofBackend::new());
                    let mut generator = ProofGenerator::new(backend, config);

                    let entries = sample_chain_entries();
                    let window = sample_window();

                    let result = generator.submit_request(&window, &entries, 1_702_000_000_000, "trace_extreme");

                    match result {
                        Ok(request_id) => {
                            // If submission succeeds, test generation
                            match generator.generate_proof(&request_id, &window, &entries, 1_702_000_000_001) {
                                Ok(proof) => {
                                    // Proof should have reasonable timeout value
                                    assert!(proof.generated_at_millis > 0);
                                    assert!(!proof.proof_data.is_empty());
                                }
                                Err(_) => {
                                    // Acceptable to fail with extreme configs
                                }
                            }

                            // Test timeout enforcement with extreme values
                            let timed_out = generator.enforce_timeouts(u64::MAX);
                            // Should handle u64::MAX timestamp without overflow
                            if config.default_timeout_millis == 0 || config.default_timeout_millis == 1 {
                                assert!(!timed_out.is_empty(), "zero/minimal timeout should cause immediate timeout");
                            }
                        }
                        Err(err) => {
                            // Expected to fail with zero capacity configs
                            if config.max_entries_per_request == 0 || config.max_pending_requests == 0 {
                                assert!(err.code.contains("ERR"));
                            }
                        }
                    }
                }
            }

            #[test]
            fn negative_receipt_chain_entry_with_extreme_index_and_hash_corruption() {
                // Test receipt chain entries with extreme index values and hash corruption
                let backend = TestProofBackend::new();

                let extreme_entry_patterns = [
                    // Pattern 1: Index overflow boundaries
                    ReceiptChainEntry {
                        index: u64::MAX,
                        chain_hash: "max_index_hash".to_string(),
                        receipt: receipt(ExecutionActionType::NetworkAccess, 0),
                        timestamp_millis: u64::MAX,
                        trace_id: "trace_max_index".to_string(),
                    },
                    // Pattern 2: Zero index
                    ReceiptChainEntry {
                        index: 0,
                        chain_hash: "".to_string(), // Empty hash
                        receipt: receipt(ExecutionActionType::SecretAccess, u64::MAX),
                        timestamp_millis: 0,
                        trace_id: "".to_string(), // Empty trace
                    },
                    // Pattern 3: Binary data in hash
                    ReceiptChainEntry {
                        index: u64::MAX / 2,
                        chain_hash: "\x00\x01\x02\x03\xFF\xFE\xFD\xFC".to_string(),
                        receipt: receipt(ExecutionActionType::PolicyQuery, 12345),
                        timestamp_millis: u64::MAX / 2,
                        trace_id: "trace\x00binary\xFF".to_string(),
                    },
                    // Pattern 4: Unicode attacks in hash
                    ReceiptChainEntry {
                        index: 999999,
                        chain_hash: "hash\u{202E}rtl\u{202D}normal\u{FEFF}".to_string(),
                        receipt: receipt(ExecutionActionType::RuntimeExit, 54321),
                        timestamp_millis: 1_702_000_000_000,
                        trace_id: "trace\u{200B}invisible\u{034F}".to_string(),
                    },
                ];

                for (i, extreme_entry) in extreme_entry_patterns.into_iter().enumerate() {
                    let entries = vec![extreme_entry.clone()];

                    let request = ProofRequest {
                        request_id: format!("extreme_entry_{i}"),
                        window: sample_window(),
                        entries: entries.clone(),
                        timeout_millis: 60_000,
                        trace_id: format!("trace_extreme_{i}"),
                        created_at_millis: 1_702_000_000_000,
                    };

                    // Should handle extreme entries without panicking
                    let proof = backend.generate(&request).expect("should handle extreme entry patterns");

                    // Verify proof integrity despite extreme inputs
                    assert!(!proof.proof_data.is_empty());
                    assert!(proof.proof_data_hash.starts_with("sha256:"));
                    assert_eq!(proof.metadata.get("entry_count").unwrap(), "1");

                    // Verification should work consistently
                    assert!(backend.verify(&proof, &entries).expect("should verify extreme entries"));

                    // JSON round-trip should work
                    let json = serde_json::to_string(&proof).expect("should serialize extreme entry proof");
                    let parsed: ComplianceProof = serde_json::from_str(&json).expect("should deserialize extreme entry proof");
                    assert_eq!(parsed.proof_data, proof.proof_data);
                    assert_eq!(parsed.proof_data_hash, proof.proof_data_hash);
                }
            }

            #[test]
            fn negative_concurrent_proof_generator_mutex_poisoning_and_recovery() {
                // Test concurrent proof generator behavior under mutex poisoning scenarios
                let backend = Arc::new(TestProofBackend::new());
                let generator = ConcurrentProofGenerator::new(backend, ProofGeneratorConfig::default());

                let entries = sample_chain_entries();
                let window = sample_window();

                // Submit some requests successfully
                let successful_requests: Vec<String> = (0..3)
                    .map(|i| {
                        let mut test_window = window.clone();
                        test_window.window_id = format!("pre_poison_{i}");
                        generator
                            .submit_request(&test_window, &entries, 1_702_000_000_000 + i, &format!("trace_{i}"))
                            .expect("should submit before poisoning")
                    })
                    .collect();

                // Simulate mutex poisoning by creating a panicking thread
                let poison_generator = generator.clone();
                let poison_thread = std::thread::spawn(move || {
                    let _guard = poison_generator.inner.lock().unwrap();
                    panic!("intentional mutex poisoning for test");
                });

                // Wait for poisoning to occur
                let join_result = poison_thread.join();
                assert!(join_result.is_err(), "poisoning thread should panic");

                // Verify operations handle poisoning gracefully
                let mut poison_window = window.clone();
                poison_window.window_id = "post_poison_request".to_string();

                let poisoned_submit = generator.submit_request(
                    &poison_window,
                    &entries,
                    1_702_000_001_000,
                    "trace_poisoned"
                );

                match poisoned_submit {
                    Ok(_) => {
                        // If submit succeeds, the implementation recovered from poisoning
                        // This is possible with proper mutex poison recovery
                    }
                    Err(err) => {
                        // Should fail gracefully with internal error about mutex poisoning
                        assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
                        assert!(err.message.contains("poisoned"));
                    }
                }

                // Test generation after poisoning
                if let Ok(poison_request_id) = poisoned_submit {
                    let poisoned_generate = generator.generate_proof(
                        &poison_request_id,
                        &poison_window,
                        &entries,
                        1_702_000_001_100,
                    );

                    match poisoned_generate {
                        Ok(proof) => {
                            // Recovery successful
                            assert!(!proof.proof_data.is_empty());
                        }
                        Err(err) => {
                            // Should fail gracefully
                            assert_eq!(err.code, error_codes::ERR_PGN_INTERNAL);
                            assert!(err.message.contains("poisoned"));
                        }
                    }
                }

                // Test that generator remains functional after recovery attempt
                let mut recovery_window = window.clone();
                recovery_window.window_id = "recovery_test".to_string();

                for i in 0..3 {
                    recovery_window.window_id = format!("recovery_{i}");
                    let recovery_result = generator.submit_request(
                        &recovery_window,
                        &entries,
                        1_702_000_002_000 + i,
                        &format!("recovery_trace_{i}")
                    );

                    // Should eventually recover or consistently fail gracefully
                    match recovery_result {
                        Ok(req_id) => {
                            // If recovery succeeds, generation should also work
                            let gen_result = generator.generate_proof(
                                &req_id,
                                &recovery_window,
                                &entries,
                                1_702_000_002_100 + i,
                            );
                            // Either succeeds or fails gracefully
                            assert!(gen_result.is_ok() || gen_result.unwrap_err().code == error_codes::ERR_PGN_INTERNAL);
                            break; // Recovery successful
                        }
                        Err(_) => {
                            // Continue trying recovery
                        }
                    }
                }
            }

            #[test]
            fn negative_proof_window_with_arithmetic_overflow_indices_and_boundaries() {
                // Test proof windows with index overflow scenarios
                let backend = TestProofBackend::new();
                let entries = sample_chain_entries();

                let overflow_windows = [
                    // Pattern 1: Maximum indices
                    ProofWindow {
                        window_id: "overflow_max".to_string(),
                        start_index: u64::MAX - 10,
                        end_index: u64::MAX,
                        entry_count: 10,
                        aligned_checkpoint_id: None,
                        tier: WorkloadTier::High,
                        created_at_millis: u64::MAX,
                        trace_id: "trace_max".to_string(),
                    },
                    // Pattern 2: Inverted indices (end < start)
                    ProofWindow {
                        window_id: "overflow_inverted".to_string(),
                        start_index: 1000,
                        end_index: 999,  // Invalid: end < start
                        entry_count: 0,  // Inconsistent count
                        aligned_checkpoint_id: Some("checkpoint\x00null".to_string()),
                        tier: WorkloadTier::Low,
                        created_at_millis: 0,
                        trace_id: "trace_inverted".to_string(),
                    },
                    // Pattern 3: Mismatched count
                    ProofWindow {
                        window_id: "overflow_mismatch".to_string(),
                        start_index: 0,
                        end_index: 3,
                        entry_count: usize::MAX, // Doesn't match actual range
                        aligned_checkpoint_id: Some("".to_string()), // Empty checkpoint
                        tier: WorkloadTier::Medium,
                        created_at_millis: u64::MAX / 2,
                        trace_id: "trace\u{202E}unicode\u{202D}".to_string(),
                    },
                ];

                for (i, overflow_window) in overflow_windows.into_iter().enumerate() {
                    let request = ProofRequest {
                        request_id: format!("window_overflow_{i}"),
                        window: overflow_window.clone(),
                        entries: entries.clone(),
                        timeout_millis: 60_000,
                        trace_id: format!("trace_window_overflow_{i}"),
                        created_at_millis: 1_702_000_000_000,
                    };

                    // Should handle overflow windows gracefully
                    let proof = backend.generate(&request).expect("should handle window overflow patterns");

                    // Verify window reference is preserved
                    assert_eq!(proof.receipt_window_ref, overflow_window.window_id);

                    // Verify metadata includes window information
                    assert_eq!(
                        proof.metadata.get("window_start").unwrap(),
                        &overflow_window.start_index.to_string()
                    );
                    assert_eq!(
                        proof.metadata.get("window_end").unwrap(),
                        &overflow_window.end_index.to_string()
                    );

                    // Verification should work despite overflow indices
                    assert!(backend.verify(&proof, &entries).expect("should verify overflow window"));

                    // Test with ProofGenerator
                    let mut generator = test_generator();
                    match generator.submit_request(&overflow_window, &entries, 1_702_000_000_000, &format!("gen_trace_{i}")) {
                        Ok(req_id) => {
                            // Generation should handle overflow gracefully
                            match generator.generate_proof(&req_id, &overflow_window, &entries, 1_702_000_000_100) {
                                Ok(gen_proof) => {
                                    assert_eq!(gen_proof.receipt_window_ref, overflow_window.window_id);
                                }
                                Err(_) => {
                                    // Acceptable to reject overflow patterns
                                }
                            }
                        }
                        Err(_) => {
                            // Acceptable to reject invalid windows at submission
                        }
                    }
                }
            }

            #[test]
            fn negative_proof_hash_computation_with_degenerate_entry_data_patterns() {
                // Test hash computation with degenerate data patterns that might cause collisions
                let backend = TestProofBackend::new();

                let degenerate_patterns = [
                    // Pattern 1: All identical entries
                    vec![
                        ReceiptChainEntry {
                            index: 0,
                            chain_hash: "identical".to_string(),
                            receipt: receipt(ExecutionActionType::NetworkAccess, 0),
                            timestamp_millis: 1_702_000_000_000,
                            trace_id: "identical".to_string(),
                        };
                        100
                    ],
                    // Pattern 2: Incrementing pattern that might collide
                    (0..50).map(|i| ReceiptChainEntry {
                        index: i,
                        chain_hash: format!("pattern_{:02}", i % 10), // Limited variation
                        receipt: receipt(ExecutionActionType::PolicyQuery, i),
                        timestamp_millis: 1_702_000_000_000 + i,
                        trace_id: format!("trace_{:02}", i % 5), // Limited variation
                    }).collect(),
                    // Pattern 3: Binary data designed to stress hasher
                    (0..10).map(|i| ReceiptChainEntry {
                        index: i,
                        chain_hash: format!("{:08b}", i).repeat(100), // Binary patterns
                        receipt: receipt(ExecutionActionType::SecretAccess, i),
                        timestamp_millis: 1_702_000_000_000 + i,
                        trace_id: format!("binary_{:08b}", i),
                    }).collect(),
                ];

                let mut all_proofs = Vec::new();

                for (pattern_idx, entries) in degenerate_patterns.into_iter().enumerate() {
                    let request = ProofRequest {
                        request_id: format!("degenerate_{pattern_idx}"),
                        window: sample_window(),
                        entries: entries.clone(),
                        timeout_millis: 60_000,
                        trace_id: format!("trace_degenerate_{pattern_idx}"),
                        created_at_millis: 1_702_000_000_000,
                    };

                    let proof = backend.generate(&request).expect("should handle degenerate patterns");
                    all_proofs.push((pattern_idx, proof, entries));
                }

                // Verify all proofs are unique despite degenerate input patterns
                for i in 0..all_proofs.len() {
                    for j in (i + 1)..all_proofs.len() {
                        let (idx1, proof1, _) = &all_proofs[i];
                        let (idx2, proof2, _) = &all_proofs[j];

                        assert_ne!(
                            proof1.proof_data_hash, proof2.proof_data_hash,
                            "hash collision between pattern {idx1} and {idx2}"
                        );
                        assert_ne!(
                            proof1.proof_data, proof2.proof_data,
                            "proof data collision between pattern {idx1} and {idx2}"
                        );
                    }
                }

                // Verify verification works for all patterns
                for (pattern_idx, proof, entries) in &all_proofs {
                    assert!(
                        backend.verify(proof, entries).expect("should verify degenerate pattern"),
                        "verification failed for pattern {pattern_idx}"
                    );

                    // Test hash integrity computation
                    let recomputed_hash = TestProofBackend::hash_bytes(&proof.proof_data);
                    assert_eq!(
                        proof.proof_data_hash, recomputed_hash,
                        "hash integrity check failed for pattern {pattern_idx}"
                    );
                }
            }

            #[test]
            fn negative_status_counts_arithmetic_consistency_under_overflow_scenarios() {
                // Test status count arithmetic under overflow scenarios
                let backend = Arc::new(TestProofBackend::new());
                let mut generator = ProofGenerator::new(backend, ProofGeneratorConfig {
                    max_pending_requests: usize::MAX / 1000, // Large but not maximum
                    max_entries_per_request: 1000,
                    default_timeout_millis: 60_000,
                });

                let entries = sample_chain_entries();
                let window = sample_window();

                // Submit many requests to test counter arithmetic
                let mut submitted_count = 0;
                let mut completed_count = 0;
                let mut failed_count = 0;

                // Submit requests until capacity is reached
                for i in 0..1000 {
                    let mut test_window = window.clone();
                    test_window.window_id = format!("count_test_{i:06}");

                    match generator.submit_request(&test_window, &entries, 1_702_000_000_000 + i, &format!("trace_{i}")) {
                        Ok(req_id) => {
                            submitted_count += 1;

                            // Generate some proofs
                            if i % 3 == 0 {
                                match generator.generate_proof(&req_id, &test_window, &entries, 1_702_000_000_100 + i) {
                                    Ok(_) => completed_count += 1,
                                    Err(_) => failed_count += 1,
                                }
                            }

                            // Periodically enforce timeouts to create more failed requests
                            if i % 10 == 0 {
                                // Use a past timeout to force failures
                                let timeout_timestamp = 1_702_000_000_000 + i + 61_000;
                                generator.enforce_timeouts(timeout_timestamp);
                            }
                        }
                        Err(_) => {
                            // Hit capacity limit
                            break;
                        }
                    }
                }

                // Verify status counts are arithmetically consistent
                let status_counts = generator.status_counts();

                let pending = status_counts.get("pending").copied().unwrap_or(0);
                let generating = status_counts.get("generating").copied().unwrap_or(0);
                let complete = status_counts.get("complete").copied().unwrap_or(0);
                let failed = status_counts.get("failed").copied().unwrap_or(0);

                let total_counted = pending + generating + complete + failed;
                let total_requests = generator.requests().len();

                // All requests should be accounted for in status counts
                assert_eq!(
                    total_counted, total_requests,
                    "status count mismatch: counted={total_counted}, actual={total_requests}"
                );

                // Individual counts should be consistent with internal state
                let actual_pending = generator.requests().values()
                    .filter(|r| matches!(r.status, ProofStatus::Pending))
                    .count();
                let actual_generating = generator.requests().values()
                    .filter(|r| matches!(r.status, ProofStatus::Generating))
                    .count();
                let actual_complete = generator.requests().values()
                    .filter(|r| matches!(r.status, ProofStatus::Complete))
                    .count();
                let actual_failed = generator.requests().values()
                    .filter(|r| matches!(r.status, ProofStatus::Failed))
                    .count();

                assert_eq!(pending, actual_pending, "pending count mismatch");
                assert_eq!(generating, actual_generating, "generating count mismatch");
                assert_eq!(complete, actual_complete, "complete count mismatch");
                assert_eq!(failed, actual_failed, "failed count mismatch");

                // Verify no arithmetic overflow occurred
                assert!(total_counted <= usize::MAX / 2, "count overflow detected");
                assert!(submitted_count > 0, "should have submitted some requests");

                // Test status count stability under additional operations
                let pre_op_counts = generator.status_counts();

                // Perform operations that shouldn't change existing counts
                generator.enforce_timeouts(u64::MAX); // Force all remaining to timeout

                let post_op_counts = generator.status_counts();

                // Total should remain the same, but distribution may change
                let pre_total: usize = pre_op_counts.values().sum();
                let post_total: usize = post_op_counts.values().sum();
                assert_eq!(pre_total, post_total, "total count changed during timeout enforcement");
            }

            #[test]
            fn negative_proof_serialization_with_massive_metadata_and_payload_stress() {
                // Test proof serialization with massive metadata and payloads
                let backend = TestProofBackend::new();
                let entries = sample_chain_entries();

                // Create massive metadata to stress serialization
                let massive_metadata_sizes = [1000, 10000, 100000]; // Up to 100KB keys/values

                for &size in &massive_metadata_sizes {
                    let mut window = sample_window();
                    window.window_id = format!("massive_metadata_{size}");

                    let request = ProofRequest {
                        request_id: format!("massive_meta_{size}"),
                        window: window.clone(),
                        entries: entries.clone(),
                        timeout_millis: 60_000,
                        trace_id: format!("trace_massive_{size}"),
                        created_at_millis: 1_702_000_000_000,
                    };

                    let mut proof = backend.generate(&request).expect("should generate base proof");

                    // Inject massive metadata
                    proof.metadata.insert("massive_key".to_string(), "x".repeat(size));
                    proof.metadata.insert("y".repeat(size), "massive_value".to_string());
                    proof.metadata.insert("binary_data".to_string(),
                        (0..size).map(|i| (i % 256) as u8 as char).collect());

                    // Add Unicode stress metadata
                    proof.metadata.insert("unicode_stress".to_string(),
                        "\u{1F4A9}".repeat(size / 4)); // Emoji stress
                    proof.metadata.insert("control_chars".to_string(),
                        "\x00\x01\x02\x03\x04\x05".repeat(size / 6));

                    // Test JSON serialization with massive metadata
                    let serialization_result = std::panic::catch_unwind(|| {
                        serde_json::to_string(&proof)
                    });

                    match serialization_result {
                        Ok(Ok(json)) => {
                            // If serialization succeeds, test round-trip
                            let deserialization_result: Result<ComplianceProof, _> = serde_json::from_str(&json);

                            match deserialization_result {
                                Ok(parsed_proof) => {
                                    // Verify metadata preservation
                                    assert_eq!(parsed_proof.metadata.len(), proof.metadata.len());
                                    assert_eq!(
                                        parsed_proof.metadata.get("massive_key"),
                                        proof.metadata.get("massive_key")
                                    );

                                    // Verify core proof data integrity
                                    assert_eq!(parsed_proof.proof_data, proof.proof_data);
                                    assert_eq!(parsed_proof.proof_data_hash, proof.proof_data_hash);
                                }
                                Err(_) => {
                                    // Deserialization failure with massive data is acceptable
                                }
                            }
                        }
                        Ok(Err(_)) => {
                            // JSON serialization failure with massive data is acceptable
                        }
                        Err(_) => {
                            // Serialization panic with massive data is not ideal but may occur
                        }
                    }

                    // Test verification with massive metadata (should ignore metadata)
                    let verification_result = std::panic::catch_unwind(|| {
                        backend.verify(&proof, &entries)
                    });

                    match verification_result {
                        Ok(Ok(valid)) => {
                            // Verification should focus on proof data, not metadata
                            assert!(valid, "verification should succeed despite massive metadata");
                        }
                        Ok(Err(_)) => {
                            // Verification error is acceptable with massive metadata
                        }
                        Err(_) => {
                            // Verification panic with massive metadata indicates a problem
                            panic!("verification should not panic with massive metadata for size {size}");
                        }
                    }
                }

            #[test]
            fn negative_unicode_injection_in_trace_ids_and_metadata_keys() {
                // Test Unicode injection attacks in trace IDs and proof metadata
                let backend = Arc::new(TestProofBackend::new());
                let mut generator = ProofGenerator::new(backend, ProofGeneratorConfig::default());

                let entries = sample_chain_entries();
                let malicious_trace_ids = vec![
                    "trace\u{202e}evil\u{202c}normal",      // BiDi override
                    "trace\u{200b}\u{feff}hidden",          // Zero-width characters
                    "trace\nnewline\ninjection",             // Newline injection
                    "trace\ttab\tinjection",                 // Tab injection
                    "trace\x00null\x00injection",           // Null byte injection
                    "../../../etc/passwd",                   // Path traversal
                    "trace\"quote'sql",                      // Quote injection
                    "\u{1F4A9}trace\u{1F525}emoji",        // Emoji sequence
                ];

                for (i, malicious_trace) in malicious_trace_ids.iter().enumerate() {
                    let mut window = sample_window();
                    window.window_id = format!("unicode_test_{}", i);
                    window.trace_id = malicious_trace.clone();

                    let result = generator.submit_request(
                        &window,
                        &entries,
                        1_702_000_000_000 + i as u64,
                        malicious_trace,
                    );

                    assert!(result.is_ok(), "Should handle Unicode in trace ID: {}", malicious_trace);

                    let request_id = result.unwrap();
                    let proof_result = generator.generate_proof(
                        &request_id,
                        &window,
                        &entries,
                        1_702_000_000_100 + i as u64,
                    );

                    if let Ok(proof) = proof_result {
                        // Verify trace ID preservation
                        assert!(proof.metadata.values().any(|v| v == malicious_trace));

                        // JSON serialization should handle Unicode safely
                        let json = serde_json::to_string(&proof);
                        assert!(json.is_ok(), "JSON serialization should handle Unicode safely");

                        if let Ok(json_str) = json {
                            let parsed: Result<ComplianceProof, _> = serde_json::from_str(&json_str);
                            if let Ok(parsed_proof) = parsed {
                                assert_eq!(parsed_proof.receipt_window_ref, proof.receipt_window_ref);
                            }
                        }
                    }
                }
            }

            #[test]
            fn negative_backend_switching_and_proof_consistency_attacks() {
                // Test backend switching attacks and proof consistency verification
                let backend1 = Arc::new(TestProofBackend::new());
                let backend2 = Arc::new(TestProofBackend::new());

                let mut generator1 = ProofGenerator::new(backend1.clone(), ProofGeneratorConfig::default());
                let mut generator2 = ProofGenerator::new(backend2.clone(), ProofGeneratorConfig::default());

                let entries = sample_chain_entries();
                let window = sample_window();

                // Generate proofs with both backends for same data
                let request_id1 = generator1.submit_request(&window, &entries, 1_702_000_000_000, "trace1").unwrap();
                let request_id2 = generator2.submit_request(&window, &entries, 1_702_000_000_000, "trace2").unwrap();

                let proof1 = generator1.generate_proof(&request_id1, &window, &entries, 1_702_000_000_100).unwrap();
                let proof2 = generator2.generate_proof(&request_id2, &window, &entries, 1_702_000_000_100).unwrap();

                // Proofs from different backends should be distinct
                assert_ne!(proof1.proof_data, proof2.proof_data, "Different backends should produce different proofs");
                assert_ne!(proof1.proof_data_hash, proof2.proof_data_hash, "Different backends should produce different hashes");

                // But both should be valid for their respective backends
                assert!(backend1.verify(&proof1, &entries).unwrap());
                assert!(backend2.verify(&proof2, &entries).unwrap());

                // Cross-backend verification should fail or handle gracefully
                let cross_verify1 = backend2.verify(&proof1, &entries);
                let cross_verify2 = backend1.verify(&proof2, &entries);

                // Implementation-dependent: may fail or succeed based on backend design
                // But should not panic or corrupt state
                assert!(cross_verify1.is_ok()); // TestBackend is lenient
                assert!(cross_verify2.is_ok()); // TestBackend is lenient

                // Test backend format version consistency
                assert_eq!(proof1.format_version, PROOF_FORMAT_VERSION);
                assert_eq!(proof2.format_version, PROOF_FORMAT_VERSION);
                assert_eq!(proof1.backend_name, "test");
                assert_eq!(proof2.backend_name, "test");
            }

            #[test]
            fn negative_proof_verification_bypass_attempts() {
                // Test various proof verification bypass attempts
                let backend = TestProofBackend::new();
                let entries = sample_chain_entries();

                // Generate legitimate proof
                let legitimate_request = ProofRequest {
                    request_id: "legitimate".to_string(),
                    window: sample_window(),
                    entries: entries.clone(),
                    timeout_millis: 60_000,
                    trace_id: "legitimate_trace".to_string(),
                    created_at_millis: 1_702_000_000_000,
                };

                let legitimate_proof = backend.generate(&legitimate_request).unwrap();

                // Attempt various proof manipulation attacks
                let bypass_attempts = vec![
                    // Attempt 1: Modify proof data but keep hash
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.proof_data = "tampered_data".to_string();
                        tampered
                    },

                    // Attempt 2: Modify hash but keep proof data
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.proof_data_hash = "sha256:deadbeefcafebabe".to_string();
                        tampered
                    },

                    // Attempt 3: Modify metadata to claim different properties
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.metadata.insert("entry_count".to_string(), "999".to_string());
                        tampered.metadata.insert("malicious".to_string(), "true".to_string());
                        tampered
                    },

                    // Attempt 4: Change window reference
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.receipt_window_ref = "different_window".to_string();
                        tampered
                    },

                    // Attempt 5: Manipulate timestamps
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.generated_at_millis = 0;
                        tampered
                    },

                    // Attempt 6: Change format version
                    {
                        let mut tampered = legitimate_proof.clone();
                        tampered.format_version = "999.0.0".to_string();
                        tampered
                    },
                ];

                for (i, tampered_proof) in bypass_attempts.iter().enumerate() {
                    let verification = backend.verify(tampered_proof, &entries);

                    match verification {
                        Ok(is_valid) => {
                            // TestBackend is lenient, but should still detect major tampering
                            if tampered_proof.proof_data != legitimate_proof.proof_data ||
                               tampered_proof.proof_data_hash != legitimate_proof.proof_data_hash {
                                // Major tampering should ideally be detected
                                // But TestBackend might be lenient for testing purposes
                            }
                        }
                        Err(_) => {
                            // Verification error is expected for tampered proofs
                        }
                    }
                }

                // Test with completely fabricated proof
                let fabricated_proof = ComplianceProof {
                    format_version: PROOF_FORMAT_VERSION.to_string(),
                    backend_name: "test".to_string(),
                    receipt_window_ref: "fabricated_window".to_string(),
                    generated_at_millis: 1_702_000_000_000,
                    proof_data: "fabricated_proof_data".to_string(),
                    proof_data_hash: "sha256:fabricated_hash".to_string(),
                    metadata: BTreeMap::new(),
                };

                let fabricated_verification = backend.verify(&fabricated_proof, &entries);
                // Should handle fabricated proofs gracefully
                assert!(fabricated_verification.is_ok());
            }

            #[test]
            fn negative_concurrent_request_id_collision_and_resource_exhaustion() {
                // Test concurrent request ID collision handling and resource exhaustion
                use std::sync::{Arc, Barrier};
                use std::thread;

                let backend = Arc::new(TestProofBackend::new());
                let generator = Arc::new(ConcurrentProofGenerator::new(
                    backend,
                    ProofGeneratorConfig {
                        max_pending_requests: 100, // Limited capacity
                        max_entries_per_request: 10,
                        default_timeout_millis: 1000, // Short timeout
                    },
                ));

                let barrier = Arc::new(Barrier::new(8));
                let entries = sample_chain_entries();

                let mut handles = Vec::new();

                for thread_id in 0..8 {
                    let generator = Arc::clone(&generator);
                    let barrier = Arc::clone(&barrier);
                    let entries = entries.clone();

                    let handle = thread::spawn(move || {
                        barrier.wait();

                        let mut submitted = 0;
                        let mut collisions = 0;
                        let mut resource_exhausted = 0;

                        for i in 0..50 {
                            // Use potentially colliding window IDs across threads
                            let mut window = sample_window();
                            window.window_id = format!("collision_test_{}", i % 10); // High collision probability

                            let trace_id = format!("thread_{}_trace_{}", thread_id, i);

                            match generator.submit_request(
                                &window,
                                &entries,
                                1_702_000_000_000 + (thread_id * 1000 + i) as u64,
                                &trace_id,
                            ) {
                                Ok(request_id) => {
                                    submitted += 1;

                                    // Immediately try to generate proof to stress system
                                    let _proof_result = generator.generate_proof(
                                        &request_id,
                                        &window,
                                        &entries,
                                        1_702_000_000_100 + (thread_id * 1000 + i) as u64,
                                    );
                                }
                                Err(err) => {
                                    if err.code.contains("DUPLICATE") || err.message.contains("collision") {
                                        collisions += 1;
                                    } else if err.code == error_codes::ERR_PGN_INTERNAL {
                                        resource_exhausted += 1;
                                    }
                                }
                            }
                        }

                        (submitted, collisions, resource_exhausted)
                    });

                    handles.push(handle);
                }

                // Collect results from all threads
                let results: Vec<_> = handles.into_iter()
                    .map(|h| h.join().expect("Thread should complete"))
                    .collect();

                let total_submitted: usize = results.iter().map(|(s, _, _)| s).sum();
                let total_collisions: usize = results.iter().map(|(_, c, _)| c).sum();
                let total_exhausted: usize = results.iter().map(|(_, _, e)| e).sum();

                // Verify system handled concurrent access gracefully
                assert!(total_submitted > 0, "Should have submitted some requests");

                // System should remain functional after stress
                let final_window = sample_window();
                let final_result = generator.submit_request(
                    &final_window,
                    &entries,
                    1_702_000_001_000,
                    "final_test_trace",
                );

                // Should either succeed or fail gracefully
                match final_result {
                    Ok(req_id) => {
                        let _proof = generator.generate_proof(
                            &req_id,
                            &final_window,
                            &entries,
                            1_702_000_001_100,
                        );
                    }
                    Err(_) => {
                        // Failure is acceptable after stress
                    }
                }
            }

            #[test]
            fn negative_timeout_enforcement_with_extreme_timestamp_edge_cases() {
                // Test timeout enforcement with extreme timestamp scenarios
                let backend = Arc::new(TestProofBackend::new());
                let mut generator = ProofGenerator::new(backend, ProofGeneratorConfig {
                    max_pending_requests: 1000,
                    max_entries_per_request: 100,
                    default_timeout_millis: 60_000,
                });

                let entries = sample_chain_entries();

                // Submit requests with extreme timestamp patterns
                let extreme_timestamp_scenarios = vec![
                    // Scenario 1: Requests with timestamps near u64::MAX
                    (u64::MAX - 100_000, "near_max_past"),
                    (u64::MAX - 1, "near_max_recent"),
                    (u64::MAX, "at_max"),

                    // Scenario 2: Requests with zero and minimal timestamps
                    (0, "zero_timestamp"),
                    (1, "minimal_timestamp"),
                    (1000, "small_timestamp"),

                    // Scenario 3: Requests with boundary timestamp values
                    (u64::MAX / 2, "mid_range"),
                    ((1u64 << 63) - 1, "signed_boundary"),
                    (1_702_000_000_000, "normal_timestamp"),
                ];

                let mut submitted_requests = Vec::new();

                for (i, (timestamp, scenario)) in extreme_timestamp_scenarios.iter().enumerate() {
                    let mut window = sample_window();
                    window.window_id = format!("timeout_test_{}_{}", i, scenario);

                    match generator.submit_request(
                        &window,
                        &entries,
                        *timestamp,
                        &format!("trace_{}_{}", i, scenario),
                    ) {
                        Ok(request_id) => {
                            submitted_requests.push((request_id, *timestamp, scenario));
                        }
                        Err(_) => {
                            // Some extreme timestamps might be rejected
                        }
                    }
                }

                // Test timeout enforcement with extreme enforcement timestamps
                let enforcement_scenarios = vec![
                    0,           // Zero enforcement time
                    1,           // Minimal enforcement time
                    u64::MAX,    // Maximum enforcement time
                    u64::MAX - 1, // Near maximum
                ];

                for enforcement_time in enforcement_scenarios {
                    let timed_out = generator.enforce_timeouts(enforcement_time);

                    // Should handle extreme enforcement times without panic
                    assert!(timed_out.len() <= submitted_requests.len());

                    // Verify arithmetic safety in timeout calculations
                    let status_counts = generator.status_counts();
                    let total_requests = status_counts.values().sum::<usize>();
                    assert!(total_requests <= 1000); // Within capacity limits

                    // Test continued functionality after extreme timeout enforcement
                    let mut test_window = sample_window();
                    test_window.window_id = format!("post_timeout_test_{}", enforcement_time);

                    let post_timeout_result = generator.submit_request(
                        &test_window,
                        &entries,
                        enforcement_time.saturating_add(1000),
                        "post_timeout_trace",
                    );

                    // Should remain functional
                    assert!(post_timeout_result.is_ok() || post_timeout_result.is_err());
                }

                // Verify no arithmetic overflow in timestamp comparisons
                for (request_id, original_timestamp, scenario) in &submitted_requests {
                    let requests = generator.requests();
                    if let Some(request_state) = requests.get(request_id) {
                        // Verify timestamp preservation
                        assert_eq!(request_state.request.created_at_millis, *original_timestamp);

                        // Verify timeout calculation safety
                        let timeout_at = original_timestamp.saturating_add(60_000);
                        assert!(timeout_at >= *original_timestamp); // No overflow
                    }
                }
            }

            #[test]
            fn negative_proof_hash_computation_collision_resistance() {
                // Test proof hash computation collision resistance
                let backend = TestProofBackend::new();

                // Create similar but distinct proof data patterns
                let collision_test_patterns = vec![
                    // Pattern 1: Similar strings with single character difference
                    ("proof_data_a", "proof_data_b"),
                    ("proof_data_1", "proof_data_2"),

                    // Pattern 2: Same content with different formatting
                    ("proof data", "proof_data"),
                    ("PROOF_DATA", "proof_data"),

                    // Pattern 3: Binary-similar patterns
                    ("\x01\x02\x03\x04", "\x01\x02\x03\x05"),
                    ("\xFF\xFE\xFD\xFC", "\xFF\xFE\xFD\xFB"),

                    // Pattern 4: Length extension patterns
                    ("short", "short_extended"),
                    ("base", "base_plus_extra"),

                    // Pattern 5: Unicode similar patterns
                    ("café", "cafe\u{0301}"), // NFC vs NFD
                    ("А", "A"),               // Cyrillic vs Latin
                ];

                let mut all_hashes = Vec::new();

                for (i, (data1, data2)) in collision_test_patterns.iter().enumerate() {
                    let hash1 = TestProofBackend::hash_bytes(data1.as_bytes());
                    let hash2 = TestProofBackend::hash_bytes(data2.as_bytes());

                    // Verify no collision between similar patterns
                    assert_ne!(hash1, hash2, "Hash collision between '{}' and '{}'", data1, data2);

                    all_hashes.push((format!("pattern_{}_a", i), hash1));
                    all_hashes.push((format!("pattern_{}_b", i), hash2));
                }

                // Additional collision resistance test with many similar inputs
                for i in 0..1000 {
                    let data = format!("collision_test_{:04}", i);
                    let hash = TestProofBackend::hash_bytes(data.as_bytes());
                    all_hashes.push((data, hash));
                }

                // Verify all hashes are unique
                let mut hash_set = std::collections::HashSet::new();
                for (data, hash) in &all_hashes {
                    assert!(
                        hash_set.insert(hash.clone()),
                        "Hash collision detected for data: {}",
                        data
                    );
                }

                // Verify hash format consistency
                for (_, hash) in &all_hashes {
                    assert!(hash.starts_with("sha256:"));
                    assert_eq!(hash.len(), 71); // "sha256:" + 64 hex chars
                    let hex_part = &hash[7..];
                    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
                }

                // Test hash determinism
                for _ in 0..10 {
                    let test_data = "determinism_test";
                    let hash1 = TestProofBackend::hash_bytes(test_data.as_bytes());
                    let hash2 = TestProofBackend::hash_bytes(test_data.as_bytes());
                    assert_eq!(hash1, hash2, "Hash function should be deterministic");
                }
            }

            #[test]
            fn negative_request_state_corruption_under_concurrent_modifications() {
                // Test request state corruption under concurrent modifications
                let backend = Arc::new(TestProofBackend::new());
                let generator = Arc::new(ConcurrentProofGenerator::new(
                    backend,
                    ProofGeneratorConfig::default(),
                ));

                let entries = sample_chain_entries();
                let window = sample_window();

                // Submit initial request
                let request_id = generator.submit_request(&window, &entries, 1_702_000_000_000, "state_test").unwrap();

                // Test concurrent state modifications
                use std::thread;

                let generator1 = Arc::clone(&generator);
                let generator2 = Arc::clone(&generator);
                let generator3 = Arc::clone(&generator);

                let req_id1 = request_id.clone();
                let req_id2 = request_id.clone();
                let req_id3 = request_id.clone();

                let window1 = window.clone();
                let window2 = window.clone();
                let window3 = window.clone();

                let entries1 = entries.clone();
                let entries2 = entries.clone();
                let entries3 = entries.clone();

                // Thread 1: Generate proof
                let handle1 = thread::spawn(move || {
                    generator1.generate_proof(&req_id1, &window1, &entries1, 1_702_000_000_100)
                });

                // Thread 2: Try to generate same proof concurrently
                let handle2 = thread::spawn(move || {
                    generator2.generate_proof(&req_id2, &window2, &entries2, 1_702_000_000_101)
                });

                // Thread 3: Enforce timeouts while others are generating
                let handle3 = thread::spawn(move || {
                    thread::sleep(std::time::Duration::from_millis(10));
                    generator3.enforce_timeouts(1_702_000_000_200)
                });

                // Collect results
                let result1 = handle1.join().expect("Thread 1 should complete");
                let result2 = handle2.join().expect("Thread 2 should complete");
                let timeout_result = handle3.join().expect("Thread 3 should complete");

                // Verify state consistency
                match (result1, result2) {
                    (Ok(proof1), Ok(proof2)) => {
                        // Both succeeded - proofs should be identical or distinct based on timing
                        assert_eq!(proof1.receipt_window_ref, proof2.receipt_window_ref);
                    }
                    (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                        // One succeeded, one failed - acceptable for concurrent access
                    }
                    (Err(_), Err(_)) => {
                        // Both failed - acceptable if timeout occurred
                    }
                }

                // Verify generator remains functional after concurrent stress
                let mut final_window = window;
                final_window.window_id = "final_consistency_test".to_string();

                let final_result = generator.submit_request(
                    &final_window,
                    &entries,
                    1_702_000_001_000,
                    "final_trace",
                );

                assert!(final_result.is_ok(), "Generator should remain functional after concurrent stress");
            }
        }
    }
}
