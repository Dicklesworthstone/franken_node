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
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
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
    fn timeout(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_TIMEOUT.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_001_TIMEOUT.to_string(),
            message: message.into(),
            retriable: true,
        }
    }

    fn backend_crash(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_VEF_PROOF_BACKEND_CRASH.to_string(),
            event_code: event_codes::VEF_PROOF_ERR_002_BACKEND_CRASH.to_string(),
            message: message.into(),
            retriable: true,
        }
    }

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

        let expected_count = (window.end_index - window.start_index + 1) as usize;
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
        let expected_count = (self.receipt_end_index - self.receipt_start_index + 1) as usize;
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
        if self.input_commitment_hash != expected_commitment {
            return Err(ProofServiceError::verify_error(format!(
                "input commitment mismatch expected={} got={}",
                expected_commitment, self.input_commitment_hash
            )));
        }

        if self.trace_id != input.trace_id {
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
        if proof.proof_material != expected {
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
        if proof.proof_material != expected {
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

impl Default for ProofServiceConfig {
    fn default() -> Self {
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

    pub fn generate_proof(
        &mut self,
        input: &ProofInputEnvelope,
        backend_override: Option<ProofBackendId>,
        now_millis: u64,
    ) -> Result<ProofOutputEnvelope, ProofServiceError> {
        self.events.push(ProofServiceEvent {
            event_code: event_codes::VEF_PROOF_001_REQUEST_RECEIVED.to_string(),
            trace_id: input.trace_id.clone(),
            detail: format!(
                "job={} window={} range={}..{}",
                input.job_id, input.window_id, input.receipt_start_index, input.receipt_end_index
            ),
        });

        input.validate()?;
        let backend_id = self.resolve_backend(backend_override)?;

        self.events.push(ProofServiceEvent {
            event_code: event_codes::VEF_PROOF_002_BACKEND_SELECTED.to_string(),
            trace_id: input.trace_id.clone(),
            detail: format!("backend={}", backend_id.as_str()),
        });

        if let Some(simulate_failure) = input.metadata.get("simulate_failure") {
            return match simulate_failure.as_str() {
                "timeout" => Err(ProofServiceError::timeout(format!(
                    "backend={} exceeded timeout while proving job={}",
                    backend_id.as_str(),
                    input.job_id
                ))),
                "crash" => Err(ProofServiceError::backend_crash(format!(
                    "backend={} crashed while proving job={}",
                    backend_id.as_str(),
                    input.job_id
                ))),
                "malformed_output" => Err(ProofServiceError::malformed_output(format!(
                    "backend={} returned malformed output for job={}",
                    backend_id.as_str(),
                    input.job_id
                ))),
                _ => Err(ProofServiceError::input_error(format!(
                    "unknown simulate_failure mode '{}': expected timeout|crash|malformed_output",
                    simulate_failure
                ))),
            };
        }

        let params = self.parameters_for(backend_id);
        let proof = self.run_backend_generate(backend_id, input, now_millis, params)?;
        proof.validate_against(input)?;
        self.run_backend_verify(backend_id, input, &proof, params)?;

        self.events.push(ProofServiceEvent {
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

        let params = self.parameters_for(proof.backend_id);
        self.run_backend_verify(proof.backend_id, input, proof, params)
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

    fn parameters_for(&self, backend_id: ProofBackendId) -> &BTreeMap<String, String> {
        self.config
            .backend_parameters
            .get(&backend_id)
            .unwrap_or_else(|| {
                // Fall back to empty deterministic parameter set if absent.
                static EMPTY: std::sync::OnceLock<BTreeMap<String, String>> =
                    std::sync::OnceLock::new();
                EMPTY.get_or_init(BTreeMap::new)
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
        let mut service = VefProofService::new(ProofServiceConfig::default());
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
        let mut service = VefProofService::new(ProofServiceConfig::default());
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
        let mut service = VefProofService::new(ProofServiceConfig::default());

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
            backend_parameters: BTreeMap::new(),
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
    fn timeout_failure_is_classified_and_retriable() {
        let (mut input, _, _) = sample_request();
        input
            .metadata
            .insert("simulate_failure".to_string(), "timeout".to_string());
        let mut service = VefProofService::new(ProofServiceConfig::default());

        let err = service
            .generate_proof(&input, None, 1_705_300_000_400)
            .expect_err("simulated timeout must fail");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_TIMEOUT);
        assert_eq!(err.event_code, event_codes::VEF_PROOF_ERR_001_TIMEOUT);
        assert!(err.retriable);
    }

    #[test]
    fn crash_failure_is_classified_and_retriable() {
        let (mut input, _, _) = sample_request();
        input
            .metadata
            .insert("simulate_failure".to_string(), "crash".to_string());
        let mut service = VefProofService::new(ProofServiceConfig::default());

        let err = service
            .generate_proof(&input, None, 1_705_300_000_500)
            .expect_err("simulated crash must fail");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_BACKEND_CRASH);
        assert_eq!(err.event_code, event_codes::VEF_PROOF_ERR_002_BACKEND_CRASH);
        assert!(err.retriable);
    }

    #[test]
    fn malformed_output_failure_is_classified() {
        let (mut input, _, _) = sample_request();
        input.metadata.insert(
            "simulate_failure".to_string(),
            "malformed_output".to_string(),
        );
        let mut service = VefProofService::new(ProofServiceConfig::default());

        let err = service
            .generate_proof(&input, None, 1_705_300_000_600)
            .expect_err("simulated malformed output must fail");
        assert_eq!(err.code, error_codes::ERR_VEF_PROOF_MALFORMED_OUTPUT);
        assert_eq!(
            err.event_code,
            event_codes::VEF_PROOF_ERR_003_MALFORMED_OUTPUT
        );
        assert!(!err.retriable);
    }

    #[test]
    fn generated_proofs_are_deterministic_per_backend() {
        let (input, _, _) = sample_request();
        let mut service = VefProofService::new(ProofServiceConfig::default());

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
}
