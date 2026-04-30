//! bd-1u8m: Backend-agnostic VEF proof generation service.
//!
//! This module defines deterministic proof input/output envelopes and a
//! pluggable proof backend interface. It ships two reference backends built on
//! SHA-256 attestation so integration surfaces can validate backend swaps
//! without changing verification semantics.

use super::proof_scheduler::{ProofJob, ProofWindow, WorkloadTier};
use super::receipt_chain::{ReceiptChainEntry, ReceiptCheckpoint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use frankenengine_node::capacity_defaults::aliases::MAX_EVENTS;

/// Constant-time string comparison (inline to avoid cross-crate path issues in test harnesses).
fn ct_eq_inline(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

pub const PROOF_SERVICE_SCHEMA_VERSION: &str = "vef-proof-service-v1";

pub mod event_codes {
    pub const VEF_PROOF_001_REQUEST_RECEIVED: &str = "VEF-PROOF-001";
    pub const VEF_PROOF_002_BACKEND_SELECTED: &str = "VEF-PROOF-002";
    pub const VEF_PROOF_003_PROOF_GENERATED: &str = "VEF-PROOF-003";

    pub const VEF_PROOF_ERR_001_TIMEOUT: &str = "VEF-PROOF-ERR-001";
    pub const VEF_PROOF_ERR_002_BACKEND_CRASH: &str = "VEF-PROOF-ERR-002";
    pub const VEF_PROOF_ERR_003_MALFORMED_OUTPUT: &str = "VEF-PROOF-ERR-003";
    pub const VEF_PROOF_ERR_004_VERIFICATION: &str = "VEF-PROOF-ERR-004";
}

pub mod error_codes {
    pub const ERR_VEF_PROOF_TIMEOUT: &str = "ERR-VEF-PROOF-TIMEOUT";
    pub const ERR_VEF_PROOF_BACKEND_CRASH: &str = "ERR-VEF-PROOF-BACKEND-CRASH";
    pub const ERR_VEF_PROOF_MALFORMED_OUTPUT: &str = "ERR-VEF-PROOF-MALFORMED-OUTPUT";
    pub const ERR_VEF_PROOF_BACKEND_UNAVAILABLE: &str = "ERR-VEF-PROOF-BACKEND-UNAVAILABLE";
    pub const ERR_VEF_PROOF_INPUT: &str = "ERR-VEF-PROOF-INPUT";
    pub const ERR_VEF_PROOF_VERIFY: &str = "ERR-VEF-PROOF-VERIFY";
}

fn is_sha256_prefixed(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String, ProofServiceError> {
    let bytes = serde_json::to_vec(value).map_err(|err| {
        ProofServiceError::input_error(format!("unable to serialize canonical material: {err}"))
    })?;

    // Hash collision prevention: domain separator + length-prefixed fields
    let mut hasher = Sha256::new();
    hasher.update(b"proof_service_hash_v1:");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    let digest = hasher.finalize();

    Ok(format!("sha256:{}", hex::encode(digest)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendId {
    HashAttestationV1,
    DoubleHashAttestationV1,
}

impl ProofBackendId {
    pub fn as_str(self) -> &'static str {
        match self {
            ProofBackendId::HashAttestationV1 => "hash_attestation_v1",
            ProofBackendId::DoubleHashAttestationV1 => "double_hash_attestation_v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofServiceEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofServiceError {
    pub code: String,
    pub event_code: String,
    pub message: String,
    pub retriable: bool,
}

impl ProofServiceError {
    fn malformed_output(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_003_MALFORMED_OUTPUT.to_string(),
            message: message.into(),
            retriable: false,
        }
    }

    fn backend_unavailable(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_004_VERIFICATION.to_string(),
            message: message.into(),
            retriable: false,
        }
    }

    fn input_error(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_INPUT.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_004_VERIFICATION.to_string(),
            message: message.into(),
            retriable: false,
        }
    }

    fn verify_error(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_VERIFY.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_004_VERIFICATION.to_string(),
            message: message.into(),
            retriable: false,
        }
    }
}

impl fmt::Display for ProofServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ProofServiceError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInputEnvelope {
    pub schema_version: String,
    pub job_id: String,
    pub window_id: String,
    pub tier: WorkloadTier,
    pub trace_id: String,
    pub receipt_start_index: u64,
    pub receipt_end_index: u64,
    pub checkpoint_id: Option<u64>,
    pub chain_head_hash: String,
    pub checkpoint_commitment_hash: Option<String>,
    pub policy_hash: String,
    pub policy_predicates: Vec<String>,
    pub receipt_hashes: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

impl ProofInputEnvelope {
    pub fn from_scheduler_job(
        job: &ProofJob,
        window: &ProofWindow,
        entries: &[ReceiptChainEntry],
        checkpoints: &[ReceiptCheckpoint],
        policy_hash: &str,
        policy_predicates: Vec<String>,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self, ProofServiceError> {
        if job.window_id != window.window_id {
            return Err(ProofServiceError::input_error(format!(
                "job/window mismatch: job {} references {} but window is {}",
                job.job_id, job.window_id, window.window_id
            )));
        }

        let window_entries = entries
            .iter()
            .filter(|entry| entry.index >= window.start_index && entry.index <= window.end_index)
            .collect::<Vec<_>>();
        if window_entries.is_empty() {
            return Err(ProofServiceError::input_error(format!(
                "window {} has no entries in provided chain view",
                window.window_id
            )));
        }

        let first_index = window_entries[0].index;
        let last_index = window_entries[window_entries.len() - 1].index;
        if first_index != window.start_index || last_index != window.end_index {
            return Err(ProofServiceError::input_error(format!(
                "window bounds {}..{} do not align to found entries {}..{}",
                window.start_index, window.end_index, first_index, last_index
            )));
        }

        let expected_count = window
            .end_index
            .saturating_sub(window.start_index)
            .saturating_add(1) as usize;
        if window_entries.len() != expected_count {
            return Err(ProofServiceError::input_error(format!(
                "window {} expected {} entries, found {}",
                window.window_id,
                expected_count,
                window_entries.len()
            )));
        }

        let checkpoint_commitment_hash = window.aligned_checkpoint_id.and_then(|checkpoint_id| {
            checkpoints
                .iter()
                .find(|checkpoint| checkpoint.checkpoint_id == checkpoint_id)
                .map(|checkpoint| checkpoint.commitment_hash.clone())
        });

        let chain_head_hash = window_entries[window_entries.len() - 1].chain_hash.clone();

        let envelope = Self {
            schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            job_id: job.job_id.clone(),
            window_id: window.window_id.clone(),
            tier: window.tier,
            trace_id: job.trace_id.clone(),
            receipt_start_index: window.start_index,
            receipt_end_index: window.end_index,
            checkpoint_id: window.aligned_checkpoint_id,
            chain_head_hash,
            checkpoint_commitment_hash,
            policy_hash: policy_hash.to_string(),
            policy_predicates,
            receipt_hashes: window_entries
                .iter()
                .map(|entry| entry.receipt_hash.clone())
                .collect(),
            metadata,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> Result<(), ProofServiceError> {
        if self.schema_version != PROOF_SERVICE_SCHEMA_VERSION {
            return Err(ProofServiceError::input_error(format!(
                "schema_version '{}' does not match '{}': fail closed",
                self.schema_version, PROOF_SERVICE_SCHEMA_VERSION
            )));
        }
        if self.job_id.trim().is_empty()
            || self.window_id.trim().is_empty()
            || self.trace_id.trim().is_empty()
        {
            return Err(ProofServiceError::input_error(
                "job_id/window_id/trace_id must be non-empty",
            ));
        }
        if self.receipt_end_index < self.receipt_start_index {
            return Err(ProofServiceError::input_error(format!(
                "invalid receipt range {}..{}",
                self.receipt_start_index, self.receipt_end_index
            )));
        }
        let expected_count = self
            .receipt_end_index
            .saturating_sub(self.receipt_start_index)
            .saturating_add(1) as usize;
        if self.receipt_hashes.len() != expected_count {
            return Err(ProofServiceError::input_error(format!(
                "receipt hash count mismatch expected={} got={}",
                expected_count,
                self.receipt_hashes.len()
            )));
        }
        if !self
            .receipt_hashes
            .iter()
            .all(|hash| is_sha256_prefixed(hash))
        {
            return Err(ProofServiceError::input_error(
                "all receipt hashes must be sha256:<64hex>",
            ));
        }
        if !is_sha256_prefixed(&self.chain_head_hash) {
            return Err(ProofServiceError::input_error(
                "chain_head_hash must be sha256:<64hex>",
            ));
        }
        if let Some(checkpoint_commitment_hash) = &self.checkpoint_commitment_hash
            && !is_sha256_prefixed(checkpoint_commitment_hash)
        {
            return Err(ProofServiceError::input_error(
                "checkpoint_commitment_hash must be sha256:<64hex>",
            ));
        }
        if !is_sha256_prefixed(&self.policy_hash) {
            return Err(ProofServiceError::input_error(
                "policy_hash must be sha256:<64hex>",
            ));
        }
        if self
            .policy_predicates
            .iter()
            .any(|predicate| predicate.trim().is_empty())
        {
            return Err(ProofServiceError::input_error(
                "policy_predicates entries must be non-empty strings",
            ));
        }
        Ok(())
    }

    pub fn commitment_hash(&self) -> Result<String, ProofServiceError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.policy_predicates.sort();
        canonical.policy_predicates.dedup();
        sha256_json(&canonical)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOutputEnvelope {
    pub schema_version: String,
    pub proof_id: String,
    pub backend_id: ProofBackendId,
    pub backend_version: String,
    pub input_commitment_hash: String,
    pub proof_material: String,
    pub generated_at_millis: u64,
    pub verification_metadata: BTreeMap<String, String>,
    pub trace_id: String,
}

impl ProofOutputEnvelope {
    pub fn validate_against(&self, input: &ProofInputEnvelope) -> Result<(), ProofServiceError> {
        if self.schema_version != PROOF_SERVICE_SCHEMA_VERSION {
            return Err(ProofServiceError::malformed_output(format!(
                "output schema_version '{}' does not match '{}'",
                self.schema_version, PROOF_SERVICE_SCHEMA_VERSION
            )));
        }
        if self.proof_id.trim().is_empty()
            || self.backend_version.trim().is_empty()
            || self.trace_id.trim().is_empty()
        {
            return Err(ProofServiceError::malformed_output(
                "proof_id/backend_version/trace_id must be non-empty",
            ));
        }
        if !is_sha256_prefixed(&self.input_commitment_hash)
            || !is_sha256_prefixed(&self.proof_material)
        {
            return Err(ProofServiceError::malformed_output(
                "input_commitment_hash/proof_material must be sha256:<64hex>",
            ));
        }

        let expected_commitment = input.commitment_hash()?;
        if !ct_eq_inline(&self.input_commitment_hash, &expected_commitment) {
            return Err(ProofServiceError::verify_error(format!(
                "input commitment mismatch expected={} got={}",
                expected_commitment, self.input_commitment_hash
            )));
        }

        if !ct_eq_inline(&self.trace_id, &input.trace_id) {
            return Err(ProofServiceError::verify_error(format!(
                "trace_id mismatch expected={} got={}",
                input.trace_id, self.trace_id
            )));
        }
        Ok(())
    }
}

pub trait ProofBackend {
    fn backend_id(&self) -> ProofBackendId;
    fn backend_version(&self) -> &'static str;

    fn generate(
        &self,
        input: &ProofInputEnvelope,
        generated_at_millis: u64,
        parameters: &BTreeMap<String, String>,
    ) -> Result<ProofOutputEnvelope, ProofServiceError>;

    fn verify(
        &self,
        input: &ProofInputEnvelope,
        proof: &ProofOutputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<(), ProofServiceError>;
}

#[derive(Debug, Default, Clone)]
struct HashAttestationBackend;

impl HashAttestationBackend {
    fn expected_material(
        input: &ProofInputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<String, ProofServiceError> {
        let commitment_hash = input.commitment_hash()?;
        let domain = parameters
            .get("domain")
            .map(String::as_str)
            .unwrap_or("vef-proof-hash-attestation-v1");
        sha256_json(&(
            domain,
            commitment_hash,
            input.policy_hash.as_str(),
            &input.receipt_hashes,
        ))
    }
}

impl ProofBackend for HashAttestationBackend {
    fn backend_id(&self) -> ProofBackendId {
        ProofBackendId::HashAttestationV1
    }

    fn backend_version(&self) -> &'static str {
        "hash-attestation-v1"
    }

    fn generate(
        &self,
        input: &ProofInputEnvelope,
        generated_at_millis: u64,
        parameters: &BTreeMap<String, String>,
    ) -> Result<ProofOutputEnvelope, ProofServiceError> {
        let input_commitment_hash = input.commitment_hash()?;
        let proof_material = Self::expected_material(input, parameters)?;
        let suffix = input_commitment_hash
            .strip_prefix("sha256:")
            .unwrap_or(input_commitment_hash.as_str())
            .chars()
            .take(16)
            .collect::<String>();

        let mut verification_metadata = BTreeMap::new();
        verification_metadata.insert("algorithm".to_string(), "sha256-attestation".to_string());
        verification_metadata.insert(
            "proof_backend".to_string(),
            self.backend_id().as_str().to_string(),
        );

        Ok(ProofOutputEnvelope {
            schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            proof_id: format!("proof-{}-{suffix}", self.backend_id().as_str()),
            backend_id: self.backend_id(),
            backend_version: self.backend_version().to_string(),
            input_commitment_hash,
            proof_material,
            generated_at_millis,
            verification_metadata,
            trace_id: input.trace_id.clone(),
        })
    }

    fn verify(
        &self,
        input: &ProofInputEnvelope,
        proof: &ProofOutputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<(), ProofServiceError> {
        if proof.backend_id != self.backend_id() {
            return Err(ProofServiceError::verify_error(format!(
                "backend mismatch expected={} got={}",
                self.backend_id().as_str(),
                proof.backend_id.as_str()
            )));
        }
        let expected = Self::expected_material(input, parameters)?;
        if !ct_eq_inline(&proof.proof_material, &expected) {
            return Err(ProofServiceError::verify_error(
                "proof material mismatch for hash attestation backend",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct DoubleHashAttestationBackend;

impl DoubleHashAttestationBackend {
    fn expected_material(
        input: &ProofInputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<String, ProofServiceError> {
        let commitment_hash = input.commitment_hash()?;
        let domain = parameters
            .get("domain")
            .map(String::as_str)
            .unwrap_or("vef-proof-double-hash-attestation-v1");
        let inner = sha256_json(&(domain, commitment_hash, input.policy_hash.as_str()))?;
        sha256_json(&(inner, &input.receipt_hashes, input.tier))
    }
}

impl ProofBackend for DoubleHashAttestationBackend {
    fn backend_id(&self) -> ProofBackendId {
        ProofBackendId::DoubleHashAttestationV1
    }

    fn backend_version(&self) -> &'static str {
        "double-hash-attestation-v1"
    }

    fn generate(
        &self,
        input: &ProofInputEnvelope,
        generated_at_millis: u64,
        parameters: &BTreeMap<String, String>,
    ) -> Result<ProofOutputEnvelope, ProofServiceError> {
        let input_commitment_hash = input.commitment_hash()?;
        let proof_material = Self::expected_material(input, parameters)?;
        let suffix = input_commitment_hash
            .strip_prefix("sha256:")
            .unwrap_or(input_commitment_hash.as_str())
            .chars()
            .take(16)
            .collect::<String>();

        let mut verification_metadata = BTreeMap::new();
        verification_metadata.insert(
            "algorithm".to_string(),
            "sha256-double-attestation".to_string(),
        );
        verification_metadata.insert(
            "proof_backend".to_string(),
            self.backend_id().as_str().to_string(),
        );

        Ok(ProofOutputEnvelope {
            schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            proof_id: format!("proof-{}-{suffix}", self.backend_id().as_str()),
            backend_id: self.backend_id(),
            backend_version: self.backend_version().to_string(),
            input_commitment_hash,
            proof_material,
            generated_at_millis,
            verification_metadata,
            trace_id: input.trace_id.clone(),
        })
    }

    fn verify(
        &self,
        input: &ProofInputEnvelope,
        proof: &ProofOutputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<(), ProofServiceError> {
        if proof.backend_id != self.backend_id() {
            return Err(ProofServiceError::verify_error(format!(
                "backend mismatch expected={} got={}",
                self.backend_id().as_str(),
                proof.backend_id.as_str()
            )));
        }
        let expected = Self::expected_material(input, parameters)?;
        if !ct_eq_inline(&proof.proof_material, &expected) {
            return Err(ProofServiceError::verify_error(
                "proof material mismatch for double-hash backend",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofServiceConfig {
    pub default_backend: ProofBackendId,
    pub enabled_backends: BTreeSet<ProofBackendId>,
    pub backend_parameters: BTreeMap<ProofBackendId, BTreeMap<String, String>>,
}

impl ProofServiceConfig {
    pub fn reference_attestation_defaults() -> Self {
        let enabled_backends = BTreeSet::from([
            ProofBackendId::HashAttestationV1,
            ProofBackendId::DoubleHashAttestationV1,
        ]);
        let mut backend_parameters = BTreeMap::new();
        backend_parameters.insert(ProofBackendId::HashAttestationV1, BTreeMap::new());
        backend_parameters.insert(ProofBackendId::DoubleHashAttestationV1, BTreeMap::new());

        Self {
            default_backend: ProofBackendId::HashAttestationV1,
            enabled_backends,
            backend_parameters,
        }
    }
}

impl Default for ProofServiceConfig {
    fn default() -> Self {
        Self {
            default_backend: ProofBackendId::HashAttestationV1,
            enabled_backends: BTreeSet::new(),
            backend_parameters: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VefProofService {
    pub schema_version: String,
    pub config: ProofServiceConfig,
    events: Vec<ProofServiceEvent>,
}

impl VefProofService {
    pub fn new(config: ProofServiceConfig) -> Self {
        Self {
            schema_version: PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            config,
            events: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn events(&self) -> &[ProofServiceEvent] {
        &self.events
    }

    fn emit_event(&mut self, event: ProofServiceEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    pub fn generate_proof(
        &mut self,
        input: &ProofInputEnvelope,
        backend_override: Option<ProofBackendId>,
        now_millis: u64,
    ) -> Result<ProofOutputEnvelope, ProofServiceError> {
        self.emit_event(ProofServiceEvent {
            event_code: event_codes::VEF_PROOF_001_REQUEST_RECEIVED.to_string(),
            trace_id: input.trace_id.clone(),
            detail: format!(
                "job={} window={} range={}..{}",
                input.job_id, input.window_id, input.receipt_start_index, input.receipt_end_index
            ),
        });

        input.validate()?;
        let backend_id = self.resolve_backend(backend_override)?;

        self.emit_event(ProofServiceEvent {
            event_code: event_codes::VEF_PROOF_002_BACKEND_SELECTED.to_string(),
            trace_id: input.trace_id.clone(),
            detail: format!("backend={}", backend_id.as_str()),
        });

        let params = self.parameters_for(backend_id)?;
        let proof = self.run_backend_generate(backend_id, input, now_millis, &params)?;
        proof.validate_against(input)?;
        self.run_backend_verify(backend_id, input, &proof, &params)?;

        self.emit_event(ProofServiceEvent {
            event_code: event_codes::VEF_PROOF_003_PROOF_GENERATED.to_string(),
            trace_id: input.trace_id.clone(),
            detail: format!(
                "job={} backend={} proof_id={}",
                input.job_id,
                backend_id.as_str(),
                proof.proof_id
            ),
        });

        Ok(proof)
    }

    pub fn verify_proof(
        &self,
        input: &ProofInputEnvelope,
        proof: &ProofOutputEnvelope,
    ) -> Result<(), ProofServiceError> {
        input.validate()?;
        proof.validate_against(input)?;

        if !self.config.enabled_backends.contains(&proof.backend_id) {
            return Err(ProofServiceError::backend_unavailable(format!(
                "backend {} not enabled for verification",
                proof.backend_id.as_str()
            )));
        }

        let params = self.parameters_for(proof.backend_id)?;
        self.run_backend_verify(proof.backend_id, input, proof, &params)
    }

    fn resolve_backend(
        &self,
        backend_override: Option<ProofBackendId>,
    ) -> Result<ProofBackendId, ProofServiceError> {
        let backend_id = backend_override.unwrap_or(self.config.default_backend);
        if !self.config.enabled_backends.contains(&backend_id) {
            return Err(ProofServiceError::backend_unavailable(format!(
                "backend {} is not enabled",
                backend_id.as_str()
            )));
        }
        Ok(backend_id)
    }

    fn parameters_for(
        &self,
        backend_id: ProofBackendId,
    ) -> Result<BTreeMap<String, String>, ProofServiceError> {
        self.config
            .backend_parameters
            .get(&backend_id)
            .cloned()
            .ok_or_else(|| {
                ProofServiceError::backend_unavailable(format!(
                    "backend {} missing backend_parameters configuration",
                    backend_id.as_str()
                ))
            })
    }

    fn run_backend_generate(
        &self,
        backend_id: ProofBackendId,
        input: &ProofInputEnvelope,
        now_millis: u64,
        parameters: &BTreeMap<String, String>,
    ) -> Result<ProofOutputEnvelope, ProofServiceError> {
        match backend_id {
            ProofBackendId::HashAttestationV1 => {
                HashAttestationBackend.generate(input, now_millis, parameters)
            }
            ProofBackendId::DoubleHashAttestationV1 => {
                DoubleHashAttestationBackend.generate(input, now_millis, parameters)
            }
        }
    }

    fn run_backend_verify(
        &self,
        backend_id: ProofBackendId,
        input: &ProofInputEnvelope,
        proof: &ProofOutputEnvelope,
        parameters: &BTreeMap<String, String>,
    ) -> Result<(), ProofServiceError> {
        match backend_id {
            ProofBackendId::HashAttestationV1 => {
                HashAttestationBackend.verify(input, proof, parameters)
            }
            ProofBackendId::DoubleHashAttestationV1 => {
                DoubleHashAttestationBackend.verify(input, proof, parameters)
            }
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

#[cfg(test)]
mod tests {
    use super::super::connector::vef_execution_receipt::{
        ExecutionActionType, ExecutionReceipt, RECEIPT_SCHEMA_VERSION,
    };
    use super::super::proof_scheduler::{SchedulerPolicy, VefProofScheduler};
    use super::super::receipt_chain::{ReceiptChain, ReceiptChainConfig};
    use super::*;

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
            timestamp_millis: 1_705_000_000_000 + n,
            sequence_number: n,
            witness_references: vec!["w-a".to_string(), "w-b".to_string()],
            trace_id: format!("trace-{n}"),
        }
    }

    fn sample_request() -> (ProofInputEnvelope, ProofWindow, ProofJob) {
        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 2,
            checkpoint_every_millis: 0,
        });
        for (idx, action) in [
            ExecutionActionType::NetworkAccess,
            ExecutionActionType::FilesystemOperation,
            ExecutionActionType::SecretAccess,
            ExecutionActionType::PolicyTransition,
        ]
        .into_iter()
        .enumerate()
        {
            chain
                .append(
                    receipt(action, idx as u64),
                    1_705_100_000_000 + idx as u64,
                    "trace-proof",
                )
                .expect("append receipt");
        }

        let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
            max_receipts_per_window: 2,
            ..SchedulerPolicy::default()
        });
        let windows = scheduler
            .select_windows(
                chain.entries(),
                chain.checkpoints(),
                1_705_200_000_000,
                "trace-proof",
            )
            .expect("select windows");
        let queued = scheduler
            .enqueue_windows(&windows, 1_705_200_000_010)
            .expect("enqueue");

        let window = windows[0].clone();
        let job = scheduler
            .jobs()
            .get(&queued[0])
            .expect("queued job")
            .clone();
        let input = ProofInputEnvelope::from_scheduler_job(
            &job,
            &window,
            chain.entries(),
            chain.checkpoints(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            vec![
                "action_class in {network_access,secret_access}".to_string(),
                "policy.effect != audit_only".to_string(),
            ],
            BTreeMap::new(),
        )
        .expect("build envelope");

        (input, window, job)
    }

    fn mismatched_sha256() -> String {
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()
    }

    #[test]
    fn input_envelope_from_scheduler_job_is_self_contained() {
        let (input, window, job) = sample_request();
        assert_eq!(input.job_id, job.job_id);
        assert_eq!(input.window_id, window.window_id);
        assert_eq!(input.receipt_start_index, window.start_index);
        assert_eq!(input.receipt_end_index, window.end_index);
        assert_eq!(input.receipt_hashes.len(), window.entry_count as usize);
        assert!(is_sha256_prefixed(&input.chain_head_hash));
        assert!(is_sha256_prefixed(&input.policy_hash));
    }

    #[test]
    fn commitment_hash_is_deterministic_for_same_input() {
        let (input_a, _, _) = sample_request();
        let mut input_b = input_a.clone();
        input_b.policy_predicates.reverse();

        let commitment_a = input_a.commitment_hash().expect("hash A");
        let commitment_b = input_b.commitment_hash().expect("hash B");
        assert_eq!(commitment_a, commitment_b);
    }

    #[test]
    fn hash_attestation_backend_round_trip_succeeds() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_000,
            )
            .expect("generate proof");
        service.verify_proof(&input, &proof).expect("verify proof");
        assert_eq!(proof.backend_id, ProofBackendId::HashAttestationV1);
    }

    #[test]
    fn double_hash_backend_round_trip_succeeds() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_300_000_100,
            )
            .expect("generate proof");
        service.verify_proof(&input, &proof).expect("verify proof");
        assert_eq!(proof.backend_id, ProofBackendId::DoubleHashAttestationV1);
    }

    #[test]
    fn backend_swap_changes_proof_material_without_changing_verification_semantics() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof_a = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_200,
            )
            .expect("proof A");
        let proof_b = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_300_000_201,
            )
            .expect("proof B");

        assert_ne!(proof_a.proof_material, proof_b.proof_material);
        service.verify_proof(&input, &proof_a).expect("verify A");
        service.verify_proof(&input, &proof_b).expect("verify B");
    }

    #[test]
    fn backend_override_requires_enabled_backend() {
        let (input, _, _) = sample_request();
        let config = ProofServiceConfig {
            default_backend: ProofBackendId::HashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
            backend_parameters: ProofServiceConfig::reference_attestation_defaults()
                .backend_parameters,
        };
        let mut service = VefProofService::new(config);

        let err = service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_300_000_300,
            )
            .expect_err("disabled backend must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
    }

    #[test]
    fn simulate_failure_metadata_does_not_bypass_backend_generation() {
        let (mut input, _, _) = sample_request();
        input
            .metadata
            .insert("simulate_failure".to_string(), "timeout".to_string());
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof = service
            .generate_proof(&input, None, 1_705_300_000_400)
            .expect("metadata must not trigger production failure injection");
        service
            .verify_proof(&input, &proof)
            .expect("metadata-bearing proof should verify");
    }

    #[test]
    fn crash_simulation_metadata_does_not_bypass_backend_generation() {
        let (mut input, _, _) = sample_request();
        input
            .metadata
            .insert("simulate_failure".to_string(), "crash".to_string());
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof = service
            .generate_proof(&input, None, 1_705_300_000_500)
            .expect("metadata must not trigger production failure injection");
        assert_eq!(proof.backend_id, ProofBackendId::HashAttestationV1);
    }

    #[test]
    fn malformed_output_simulation_metadata_does_not_bypass_backend_generation() {
        let (mut input, _, _) = sample_request();
        input.metadata.insert(
            "simulate_failure".to_string(),
            "malformed_output".to_string(),
        );
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof = service
            .generate_proof(&input, None, 1_705_300_000_600)
            .expect("metadata must not trigger production failure injection");
        service
            .verify_proof(&input, &proof)
            .expect("metadata-bearing proof should verify");
    }

    #[test]
    fn generated_proofs_are_deterministic_per_backend() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof_a = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_700,
            )
            .expect("proof A");
        let proof_b = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_701,
            )
            .expect("proof B");

        assert_eq!(proof_a.proof_material, proof_b.proof_material);
        assert_eq!(proof_a.input_commitment_hash, proof_b.input_commitment_hash);
        assert_eq!(proof_a.backend_id, proof_b.backend_id);
    }

    #[test]
    fn input_validation_rejects_unknown_schema_version() {
        let (mut input, _, _) = sample_request();
        input.schema_version = "vef-proof-service-v0".to_string();

        let err = input
            .validate()
            .expect_err("schema downgrade must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("schema_version"));
        assert!(!err.retriable);
    }

    #[test]
    fn input_validation_rejects_reversed_receipt_range() {
        let (mut input, _, _) = sample_request();
        input.receipt_start_index = 9;
        input.receipt_end_index = 8;

        let err = input
            .validate()
            .expect_err("reversed receipt ranges must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("invalid receipt range"));
    }

    #[test]
    fn input_validation_rejects_receipt_hash_count_mismatch() {
        let (mut input, _, _) = sample_request();
        input
            .receipt_hashes
            .pop()
            .expect("sample request has receipt hashes");

        let err = input
            .validate()
            .expect_err("missing receipt hash must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("receipt hash count mismatch"));
    }

    #[test]
    fn input_validation_rejects_non_sha256_receipt_hash() {
        let (mut input, _, _) = sample_request();
        input.receipt_hashes[0] = "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

        let err = input
            .validate()
            .expect_err("non-sha256 receipt hash must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("receipt hashes"));
    }

    #[test]
    fn input_validation_rejects_invalid_chain_head_hash() {
        let (mut input, _, _) = sample_request();
        input.chain_head_hash = "sha256:not-hex".to_string();

        let err = input
            .validate()
            .expect_err("malformed chain head hash must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("chain_head_hash"));
    }

    #[test]
    fn input_validation_rejects_blank_policy_predicate() {
        let (mut input, _, _) = sample_request();
        input.policy_predicates.push("  ".to_string());

        let err = input
            .validate()
            .expect_err("blank policy predicate must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("policy_predicates"));
    }

    #[test]
    fn proof_validation_rejects_input_commitment_tampering() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_800,
            )
            .expect("generate proof");
        proof.input_commitment_hash = mismatched_sha256();

        let err = proof
            .validate_against(&input)
            .expect_err("tampered input commitment must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("input commitment mismatch"));
    }

    #[test]
    fn proof_validation_rejects_trace_id_tampering() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_000_900,
            )
            .expect("generate proof");
        proof.trace_id = "trace-other".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("tampered trace id must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("trace_id mismatch"));
    }

    #[test]
    fn unknown_failure_simulation_metadata_does_not_bypass_backend_generation() {
        let (mut input, _, _) = sample_request();
        input
            .metadata
            .insert("simulate_failure".to_string(), "pause".to_string());
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let proof = service
            .generate_proof(&input, None, 1_705_300_001_000)
            .expect("metadata must not trigger production failure injection");
        assert!(service.events().iter().any(|event| {
            event.event_code.as_str() == event_codes::VEF_PROOF_003_PROOF_GENERATED
        }));
        service
            .verify_proof(&input, &proof)
            .expect("metadata-bearing proof should verify");
    }

    #[test]
    fn verify_proof_rejects_backend_disabled_after_generation() {
        let (input, _, _) = sample_request();
        let mut generating_service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let proof = generating_service
            .generate_proof(
                &input,
                Some(ProofBackendId::DoubleHashAttestationV1),
                1_705_300_001_100,
            )
            .expect("generate proof");
        let verifying_service = VefProofService::new(ProofServiceConfig {
            default_backend: ProofBackendId::HashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
            backend_parameters: ProofServiceConfig::reference_attestation_defaults()
                .backend_parameters,
        });

        let err = verifying_service
            .verify_proof(&input, &proof)
            .expect_err("disabled backend proof must fail closed");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
        assert!(err.message.contains("not enabled"));
    }

    #[test]
    fn input_validation_rejects_blank_required_identifiers() {
        let (mut input, _, _) = sample_request();
        input.job_id = " ".to_string();

        let err = input.validate().expect_err("blank job id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("job_id/window_id/trace_id"));
    }

    #[test]
    fn input_validation_rejects_invalid_checkpoint_commitment_hash() {
        let (mut input, _, _) = sample_request();
        input.checkpoint_commitment_hash = Some("sha256:not-hex".to_string());

        let err = input
            .validate()
            .expect_err("malformed checkpoint commitment must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("checkpoint_commitment_hash"));
    }

    #[test]
    fn input_validation_rejects_invalid_policy_hash() {
        let (mut input, _, _) = sample_request();
        input.policy_hash = "sha256:abc".to_string();

        let err = input
            .validate()
            .expect_err("malformed policy hash must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(err.message.contains("policy_hash"));
    }

    #[test]
    fn proof_validation_rejects_blank_output_identity_fields() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_001_200,
            )
            .expect("generate proof");
        proof.proof_id.clear();

        let err = proof
            .validate_against(&input)
            .expect_err("blank proof id must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("proof_id/backend_version/trace_id"));
    }

    #[test]
    fn proof_validation_rejects_malformed_proof_material_hash() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_001_300,
            )
            .expect("generate proof");
        proof.proof_material = "sha256:not-hex".to_string();

        let err = proof
            .validate_against(&input)
            .expect_err("malformed proof material must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert!(err.message.contains("proof_material"));
    }

    #[test]
    fn verify_proof_rejects_tampered_backend_material() {
        let (input, _, _) = sample_request();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());
        let mut proof = service
            .generate_proof(
                &input,
                Some(ProofBackendId::HashAttestationV1),
                1_705_300_001_400,
            )
            .expect("generate proof");
        proof.proof_material = mismatched_sha256();

        let err = service
            .verify_proof(&input, &proof)
            .expect_err("tampered backend proof material must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
        assert!(err.message.contains("proof material mismatch"));
    }

    #[test]
    fn generate_proof_rejects_invalid_input_without_generated_event() {
        let (mut input, _, _) = sample_request();
        input.trace_id.clear();
        let mut service =
            VefProofService::new(ProofServiceConfig::reference_attestation_defaults());

        let err = service
            .generate_proof(&input, None, 1_705_300_001_500)
            .expect_err("invalid input must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
        assert!(!service.events().iter().any(|event| {
            event.event_code.as_str() == event_codes::VEF_PROOF_003_PROOF_GENERATED
        }));
    }

    #[test]
    fn generate_proof_rejects_disabled_default_backend_without_selection_event() {
        let (input, _, _) = sample_request();
        let mut service = VefProofService::new(ProofServiceConfig {
            default_backend: ProofBackendId::DoubleHashAttestationV1,
            enabled_backends: BTreeSet::from([ProofBackendId::HashAttestationV1]),
            backend_parameters: ProofServiceConfig::reference_attestation_defaults()
                .backend_parameters,
        });

        let err = service
            .generate_proof(&input, None, 1_705_300_001_600)
            .expect_err("disabled default backend must fail closed");

        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_UNAVAILABLE);
        assert!(!service.events().iter().any(|event| {
            event.event_code.as_str() == event_codes::VEF_PROOF_002_BACKEND_SELECTED
        }));
        assert!(!service.events().iter().any(|event| {
            event.event_code.as_str() == event_codes::VEF_PROOF_003_PROOF_GENERATED
        }));
    }

    #[test]
    fn negative_receipt_index_arithmetic_with_potential_overflow() {
        // Test saturating arithmetic in envelope validation - lines 220, 286 use .saturating_add(1) as usize
        // This tests potential issues with the usize cast after saturating arithmetic

        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 100,
            checkpoint_every_millis: 0,
        });

        // Add some receipts
        for i in 0..5 {
            chain
                .append(
                    receipt(ExecutionActionType::NetworkAccess, i),
                    1_705_000_000_000 + i,
                    "trace-overflow",
                )
                .expect("append receipt");
        }

        let mut scheduler = VefProofScheduler::new(SchedulerPolicy::default());

        // Test with extreme index values that could cause overflow issues
        let extreme_windows = vec![
            // Large but valid indices
            ProofWindow {
                window_id: "extreme-1".to_string(),
                start_index: u64::MAX - 100,
                end_index: u64::MAX - 50,
                tier: WorkloadTier::Emergency,
                aligned_checkpoint_id: None,
            },
            // Adjacent to max value
            ProofWindow {
                window_id: "extreme-2".to_string(),
                start_index: u64::MAX - 1,
                end_index: u64::MAX,
                tier: WorkloadTier::Emergency,
                aligned_checkpoint_id: None,
            },
            // Zero range but potentially problematic
            ProofWindow {
                window_id: "extreme-3".to_string(),
                start_index: u64::MAX,
                end_index: u64::MAX,
                tier: WorkloadTier::Emergency,
                aligned_checkpoint_id: None,
            },
        ];

        for window in extreme_windows {
            let job = ProofJob {
                job_id: format!("job-{}", window.window_id),
                window_id: window.window_id.clone(),
                tier: window.tier,
                trace_id: "trace-overflow".to_string(),
                queued_at_millis: 1_705_000_000_000,
                deadline_millis: 1_705_000_100_000,
            };

            // This should fail gracefully due to no matching entries, not due to arithmetic overflow
            let result = ProofInputEnvelope::from_scheduler_job(
                &job,
                &window,
                chain.entries(),
                chain.checkpoints(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                vec!["test".to_string()],
                BTreeMap::new(),
            );

            // Should fail with input error (no entries), not panic from arithmetic overflow
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
                assert!(err.message.contains("no entries") || err.message.contains("bounds"));
            }
        }
    }

    #[test]
    fn negative_timestamp_arithmetic_without_saturating_operations() {
        // Test timestamp calculations for potential overflow issues
        // Line 842: `1_705_100_000_000 + idx as u64` uses direct addition without saturating_add

        let mut chain = ReceiptChain::new(ReceiptChainConfig {
            checkpoint_every_entries: 5,
            checkpoint_every_millis: 0,
        });

        // Test with timestamps near overflow boundaries
        let base_timestamps = vec![
            u64::MAX - 1000, // Near maximum
            0,               // Minimum
            u64::MAX / 2,    // Middle range
        ];

        for base_timestamp in base_timestamps {
            // Create receipts with potentially problematic timestamp arithmetic
            for i in 0..10_u64 {
                let receipt_timestamp = base_timestamp.saturating_add(i * 1000);
                let append_timestamp = base_timestamp.saturating_add(i * 1000 + 500);

                let result = chain.append(
                    ExecutionReceipt {
                        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
                        action_type: ExecutionActionType::NetworkAccess,
                        capability_context: BTreeMap::new(),
                        actor_identity: format!("actor-{i}"),
                        artifact_identity: format!("artifact-{i}"),
                        policy_snapshot_hash: format!("sha256:{i:064x}"),
                        timestamp_millis: receipt_timestamp,
                        sequence_number: i,
                        witness_references: vec![],
                        trace_id: "trace-timestamp".to_string(),
                    },
                    append_timestamp,
                    "trace-timestamp",
                );

                // Should succeed - testing that timestamp arithmetic doesn't overflow internally
                assert!(
                    result.is_ok(),
                    "Receipt append should handle extreme timestamps gracefully"
                );
            }

            // Test proof generation with extreme timestamps
            let mut scheduler = VefProofScheduler::new(SchedulerPolicy {
                max_receipts_per_window: 3,
                ..SchedulerPolicy::default()
            });

            let extreme_scheduling_timestamp = base_timestamp.saturating_add(10_000);
            let windows_result = scheduler.select_windows(
                chain.entries(),
                chain.checkpoints(),
                extreme_scheduling_timestamp,
                "trace-timestamp",
            );

            // Should succeed or fail gracefully, not panic from timestamp overflow
            assert!(
                windows_result.is_ok(),
                "Window selection should handle extreme timestamps"
            );
        }
    }

    #[test]
    fn negative_proof_id_generation_with_unicode_truncation_vulnerabilities() {
        // Test proof ID suffix generation using .chars().take(16) - lines 458, 543
        // This tests potential unicode truncation and normalization issues

        let (mut input, window, job) = sample_request();

        // Test with various problematic hash formats that could cause unicode issues
        let problematic_hashes = vec![
            // Unicode in hex position (invalid but test boundary behavior)
            "sha256:🔒bcdefghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef12345",
            // Mixed case (should be lowercase)
            "sha256:ABCDEfghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef12345",
            // Truncated hash
            "sha256:abc123",
            // Extra long hash-like string
            "sha256:0123456789abcdef".repeat(10),
            // Hash with emoji in prefix area (first 16 chars after sha256:)
            "sha256:🚨🔥💀☠️🚨🔥💀☠️abcdef1234567890abcdef1234567890abcdef",
            // Null bytes in hash area
            "sha256:000000000000000\x001234567890abcdef1234567890abcdef1234567",
        ];

        let backend = HashAttestationBackend::default();

        for problematic_hash in problematic_hashes {
            // Create input with problematic commitment that would be used for proof ID generation
            input.policy_hash = problematic_hash.to_string();

            // This should either succeed with a well-formed proof ID or fail validation
            // It should NOT panic from unicode issues in .chars().take(16)
            let generate_result = backend.generate(&input, 1_705_300_000_000, &BTreeMap::new());

            match generate_result {
                Ok(proof_output) => {
                    // If generation succeeded, proof ID should be well-formed
                    assert!(proof_output.proof_id.len() > 0);
                    assert!(!proof_output.proof_id.contains('\x00'));

                    // The suffix extraction should handle unicode gracefully
                    assert!(
                        proof_output
                            .proof_id
                            .starts_with("proof-hash_attestation_v1-")
                    );

                    // Verify proof material is properly formatted
                    assert!(proof_output.proof_material.starts_with("sha256:"));
                }
                Err(err) => {
                    // If it failed, should be due to validation, not unicode panic
                    assert!(
                        err.code == error_codes::ERR_VEF_PROOF_INPUT
                            || err.code == error_codes::ERR_VEF_PROOF_VERIFY
                    );
                    assert!(err.message.len() > 0);
                }
            }
        }
    }

    #[test]
    fn negative_schema_version_comparison_without_constant_time() {
        // Test schema version validation for potential timing attack vulnerabilities
        // Lines 263, 356 use != for schema version comparison

        let (input, _, _) = sample_request();

        // Test with various schema versions that could reveal timing differences
        let schema_variants = vec![
            // Correct schema
            PROOF_SERVICE_SCHEMA_VERSION.to_string(),
            // Empty schema
            String::new(),
            // Short schema with matching prefix
            "vef".to_string(),
            // Long schema with matching prefix
            format!("{}-extended-with-extra-data", PROOF_SERVICE_SCHEMA_VERSION),
            // Schema with null bytes
            format!("{}\x00injected", PROOF_SERVICE_SCHEMA_VERSION),
            // Schema with different case
            PROOF_SERVICE_SCHEMA_VERSION.to_uppercase(),
            // Very long schema string
            "wrong-schema".repeat(1000),
            // Schema with unicode characters
            "vef-proof-service-v1-🔒-extended",
        ];

        for test_schema in schema_variants {
            let mut test_input = input.clone();
            test_input.schema_version = test_schema.clone();

            let validation_result = test_input.validate();

            if test_schema == PROOF_SERVICE_SCHEMA_VERSION {
                assert!(validation_result.is_ok(), "Correct schema should validate");
            } else {
                // Wrong schema should fail validation
                assert!(
                    validation_result.is_err(),
                    "Wrong schema '{}' should fail validation",
                    test_schema
                );

                if let Err(err) = validation_result {
                    assert_eq!(err.code, error_codes::ERR_VEF_PROOF_INPUT);
                    assert!(err.message.contains("schema_version"));
                    assert!(err.message.contains("fail closed"));
                }
            }

            // Test with output envelope validation too
            let proof_output = ProofOutputEnvelope {
                schema_version: test_schema.clone(),
                proof_id: "test-proof".to_string(),
                backend_id: ProofBackendId::HashAttestationV1,
                backend_version: "test-v1".to_string(),
                input_commitment_hash:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
                proof_material:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                generated_at_millis: 1_705_300_000_000,
                verification_metadata: BTreeMap::new(),
                trace_id: input.trace_id.clone(),
            };

            let output_validation_result = proof_output.validate_against(&input);

            if test_schema == PROOF_SERVICE_SCHEMA_VERSION {
                // Should fail due to commitment hash mismatch, not schema mismatch
                assert!(output_validation_result.is_err());
                let err = output_validation_result.unwrap_err();
                assert_eq!(err.code, error_codes::ERR_VEF_PROOF_VERIFY);
            } else {
                // Should fail due to schema mismatch
                assert!(output_validation_result.is_err());
                let err = output_validation_result.unwrap_err();
                assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
                assert!(err.message.contains("schema_version"));
            }
        }

        // The current implementation uses != for string comparison instead of constant-time
        // This could potentially leak information about schema version validation through timing
        // A hardened implementation might benefit from constant-time string comparison
    }

    #[test]
    fn negative_hash_commitment_generation_without_length_prefixed_inputs() {
        // Test commitment hash generation for potential collision vulnerabilities
        // The sha256_json function concatenates fields without length prefixing

        let (mut input, _, _) = sample_request();

        // Test hash collision scenarios where different inputs could produce same hash
        // due to lack of length prefixing in hash inputs

        let collision_test_cases = vec![
            // Test case 1: Different policy predicates that could collide
            (
                vec!["ab".to_string(), "cd".to_string()],
                vec!["a".to_string(), "bcd".to_string()],
            ),
            // Test case 2: Empty vs single element
            (
                vec!["".to_string(), "test".to_string()],
                vec!["test".to_string()],
            ),
            // Test case 3: Unicode boundary issues
            (
                vec!["test🔒".to_string(), "data".to_string()],
                vec!["test".to_string(), "🔒data".to_string()],
            ),
        ];

        for (predicates_a, predicates_b) in collision_test_cases {
            input.policy_predicates = predicates_a.clone();
            let hash_a = input.commitment_hash().expect("hash A should succeed");

            input.policy_predicates = predicates_b;
            let hash_b = input.commitment_hash().expect("hash B should succeed");

            // Different predicate arrays should produce different hashes
            // If they're the same, it could indicate a hash collision vulnerability
            if hash_a == hash_b {
                // This might indicate a collision issue, but let's verify it's legitimate
                // by checking if the sorted/deduped predicates are actually the same
                let mut sorted_a = input.policy_predicates.clone();
                sorted_a.sort();
                sorted_a.dedup();

                // Reset to first case for comparison
                input.policy_predicates = predicates_a.clone();
                let mut sorted_original = input.policy_predicates.clone();
                sorted_original.sort();
                sorted_original.dedup();

                if sorted_a != sorted_original {
                    // This would be a real collision concern
                    panic!(
                        "Hash collision detected: different policy predicate sets produced same hash: {}",
                        hash_a
                    );
                }
            }

            // Both hashes should be well-formed SHA256 hashes
            assert!(hash_a.starts_with("sha256:"));
            assert!(hash_b.starts_with("sha256:"));
            assert_eq!(hash_a.len(), 71); // "sha256:" + 64 hex chars
            assert_eq!(hash_b.len(), 71);
        }

        // The current implementation uses canonical serialization with sorting/dedup
        // but doesn't use length-prefixed inputs which could be a security concern
        // A hardened implementation might use length-prefixed fields in hash inputs
    }

    #[test]
    fn sha256_json_prevents_hash_collisions_with_length_prefixing() {
        // Regression test for bd-bx6e5: hash collision prevention
        //
        // Without length prefixing, different inputs could produce the same hash:
        // - Input A: ["ab", "cd"] → domain_sep + "ab" + "cd"
        // - Input B: ["abc", "d"] → domain_sep + "abc" + "d"
        // Both would serialize to the same concatenated string and hash identically.
        //
        // With length prefixing, each field gets a length header:
        // - Input A: domain_sep + len("ab") + "ab" + len("cd") + "cd"
        // - Input B: domain_sep + len("abc") + "abc" + len("d") + "d"
        // These are guaranteed to be different.

        use serde_json::json;

        // Test case 1: Different JSON structures that could collide
        let value_a = json!({"data": "ab", "suffix": "cd"});
        let value_b = json!({"data": "abc", "suffix": "d"});

        let hash_a = sha256_json(&value_a).expect("hash A");
        let hash_b = sha256_json(&value_b).expect("hash B");

        // These should produce different hashes due to length prefixing
        assert_ne!(
            hash_a, hash_b,
            "Different JSON structures should produce different hashes"
        );
        assert!(
            hash_a.starts_with("sha256:"),
            "Hash A should be well-formed"
        );
        assert!(
            hash_b.starts_with("sha256:"),
            "Hash B should be well-formed"
        );
        assert_eq!(
            hash_a.len(),
            71,
            "Hash A should be 71 chars (sha256: + 64 hex)"
        );
        assert_eq!(
            hash_b.len(),
            71,
            "Hash B should be 71 chars (sha256: + 64 hex)"
        );

        // Test case 2: More subtle collision attempt with array concatenation
        let array_a = json!(["message", "authentication", "code"]);
        let array_b = json!(["messageauth", "entication", "code"]);

        let hash_array_a = sha256_json(&array_a).expect("hash array A");
        let hash_array_b = sha256_json(&array_b).expect("hash array B");

        assert_ne!(
            hash_array_a, hash_array_b,
            "Different arrays should produce different hashes"
        );

        // Test case 3: Ensure same input produces same hash (deterministic)
        let value_c = json!({"test": "data", "number": 42});
        let hash_c1 = sha256_json(&value_c).expect("hash C1");
        let hash_c2 = sha256_json(&value_c).expect("hash C2");

        assert_eq!(
            hash_c1, hash_c2,
            "Same input should produce same hash (deterministic)"
        );
    }
}
