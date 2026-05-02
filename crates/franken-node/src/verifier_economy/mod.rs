// Verifier Economy Portal and External Attestation Publishing Flow
//
// bd-m8p / section 10.9
//
// Implements:
//   - Verifier registration with identity, capabilities, and public key
//   - Attestation submission, review, and publishing flow
//   - Verifier reputation scoring with deterministic computation
//   - Public trust scoreboard with aggregate scores and historical trends
//   - Anti-gaming measures (sybil resistance, selective reporting detection)
//   - Replay capsule access and integrity verification
//
// Event codes: VEP-001 .. VEP-008
// Invariants:  INV-VEP-ATTESTATION, INV-VEP-SIGNATURE, INV-VEP-REPUTATION, INV-VEP-PUBLISH

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::{
    MAX_ATTESTATIONS, MAX_DISPUTES, MAX_EVENTS, MAX_REPLAY_CAPSULES, MAX_VERIFIERS,
};
use crate::connector::verifier_sdk::{
    compute_capsule_integrity_hash, compute_trace_commitment_root, parse_ed25519_verifying_key_hex,
    replay_capsule_signature_payload, verify_ed25519_signature_hex,
    verify_ed25519_signature_with_key_hex,
};
use crate::security::constant_time;

const REPLAY_CAPSULE_SCHEMA_VERSION: &str = "vep-replay-capsule-v2";
const DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS: i64 = 3600;

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

fn push_length_prefixed(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(u64::try_from(value.len()).unwrap_or(u64::MAX)).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn is_sha256_prefixed_hex(value: &str) -> bool {
    let normalized = value.strip_prefix("sha256:").unwrap_or(value);
    normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn strip_sha256_prefix(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed
        .as_bytes()
        .get(0..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"sha256:"))
    {
        &trimmed[7..]
    } else {
        trimmed
    }
}

fn canonicalize_sha256_prefixed_hex(value: &str) -> Option<String> {
    let normalized = strip_sha256_prefix(value);
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{}", normalized.to_ascii_lowercase()))
}

fn compute_claim_metadata_hash(
    dimension: &VerificationDimension,
    statement: &str,
    score: f64,
    suite_id: &str,
) -> String {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"verifier_economy_replay_claim_v1:");
    push_length_prefixed(&mut payload, &dimension.to_string());
    push_length_prefixed(&mut payload, statement);
    let score_bits = if score.is_finite() {
        score.to_bits()
    } else {
        0_f64.to_bits()
    };
    payload.extend_from_slice(&score_bits.to_le_bytes());
    push_length_prefixed(&mut payload, suite_id);
    format!("sha256:{}", hex::encode(Sha256::digest(payload)))
}

fn canonicalize_ed25519_public_key_hex(public_key: &str) -> Result<String, String> {
    parse_ed25519_verifying_key_hex(public_key)
        .map(|key| hex::encode(key.to_bytes()))
        .map_err(|err| err.to_string())
}

fn canonicalized_ed25519_public_keys_match(expected_key: &str, actual_key: &str) -> bool {
    match (
        canonicalize_ed25519_public_key_hex(expected_key),
        canonicalize_ed25519_public_key_hex(actual_key),
    ) {
        (Ok(expected), Ok(actual)) => constant_time::ct_eq(&expected, &actual),
        _ => false,
    }
}

fn replay_capsule_freshness_window_valid(
    issued_at: &str,
    expires_at: &str,
    freshness_secs: i64,
) -> bool {
    let issued_at = match chrono::DateTime::parse_from_rfc3339(issued_at) {
        Ok(ts) => ts.with_timezone(&chrono::Utc),
        Err(_) => return false,
    };
    let expires_at = match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(ts) => ts.with_timezone(&chrono::Utc),
        Err(_) => return false,
    };
    if freshness_secs <= 0 {
        return false;
    }
    let window = expires_at.signed_duration_since(issued_at);
    if window <= chrono::Duration::zero() || window > chrono::Duration::seconds(freshness_secs) {
        return false;
    }
    // Fail-closed: reject capsules outside their validity interval.
    let now = chrono::Utc::now();
    issued_at <= now && now < expires_at
}

fn replay_capsule_issued_at_sort_key(issued_at: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(issued_at)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
}

pub(crate) fn attestation_signature_payload(submission: &AttestationSubmission) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"verifier_economy_attestation_v1:");
    push_length_prefixed(&mut payload, &submission.verifier_id);
    push_length_prefixed(&mut payload, &submission.claim.dimension.to_string());
    push_length_prefixed(&mut payload, &submission.claim.statement);
    let score_bits = if submission.claim.score.is_finite() {
        submission.claim.score.to_bits()
    } else {
        0_f64.to_bits()
    };
    payload.extend_from_slice(&score_bits.to_le_bytes());
    push_length_prefixed(&mut payload, &submission.evidence.suite_id);
    push_length_prefixed(&mut payload, &submission.evidence.execution_trace_hash);
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.measurements.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for measurement in &submission.evidence.measurements {
        push_length_prefixed(&mut payload, measurement);
    }
    payload.extend_from_slice(
        &(u64::try_from(submission.evidence.environment.len()).unwrap_or(u64::MAX)).to_le_bytes(),
    );
    for (key, value) in &submission.evidence.environment {
        push_length_prefixed(&mut payload, key);
        push_length_prefixed(&mut payload, value);
    }
    push_length_prefixed(&mut payload, &submission.timestamp);
    payload
}

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const VEP_001: &str = "VEP-001"; // Attestation submitted
pub const VEP_002: &str = "VEP-002"; // Attestation published
pub const VEP_003: &str = "VEP-003"; // Dispute filed
pub const VEP_004: &str = "VEP-004"; // Reputation updated
pub const VEP_005: &str = "VEP-005"; // Verifier registered
pub const VEP_006: &str = "VEP-006"; // Anti-gaming triggered
pub const VEP_007: &str = "VEP-007"; // Replay capsule accessed
pub const VEP_008: &str = "VEP-008"; // Attestation rejected

// ---------------------------------------------------------------------------
// Invariant tags (used in audit trail entries)
// ---------------------------------------------------------------------------

pub const INV_VEP_ATTESTATION: &str = "INV-VEP-ATTESTATION";
pub const INV_VEP_SIGNATURE: &str = "INV-VEP-SIGNATURE";
pub const INV_VEP_REPUTATION: &str = "INV-VEP-REPUTATION";
pub const INV_VEP_PUBLISH: &str = "INV-VEP-PUBLISH";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_VEP_INVALID_SIGNATURE: &str = "ERR-VEP-INVALID-SIGNATURE";
pub const ERR_VEP_INVALID_PUBLIC_KEY: &str = "ERR-VEP-INVALID-PUBLIC-KEY";
pub const ERR_VEP_INVALID_CAPSULE: &str = "ERR-VEP-INVALID-CAPSULE";
pub const ERR_VEP_DUPLICATE_SUBMISSION: &str = "ERR-VEP-DUPLICATE-SUBMISSION";
pub const ERR_VEP_UNREGISTERED_VERIFIER: &str = "ERR-VEP-UNREGISTERED-VERIFIER";
pub const ERR_VEP_INCOMPLETE_PAYLOAD: &str = "ERR-VEP-INCOMPLETE-PAYLOAD";
pub const ERR_VEP_ANTI_GAMING: &str = "ERR-VEP-ANTI-GAMING";
pub const ERR_VEP_CAPACITY_EXCEEDED: &str = "ERR-VEP-CAPACITY-EXCEEDED";

// Stable replay-capsule verification reason codes (bd-1h2w4)
pub const ERR_VEP_CAPSULE_SCHEMA: &str = "ERR-VEP-CAPSULE-SCHEMA";
pub const ERR_VEP_CAPSULE_FRESHNESS: &str = "ERR-VEP-CAPSULE-FRESHNESS";
pub const ERR_VEP_CAPSULE_ATTESTATION_BINDING: &str = "ERR-VEP-CAPSULE-ATTESTATION-BINDING";
pub const ERR_VEP_CAPSULE_TRACE_COMMITMENT: &str = "ERR-VEP-CAPSULE-TRACE-COMMITMENT";
pub const ERR_VEP_CAPSULE_INTEGRITY_HASH: &str = "ERR-VEP-CAPSULE-INTEGRITY-HASH";
pub const ERR_VEP_CAPSULE_SIGNATURE: &str = "ERR-VEP-CAPSULE-SIGNATURE";
pub const ERR_VEP_CAPSULE_MISSING_FIELDS: &str = "ERR-VEP-CAPSULE-MISSING-FIELDS";
pub const ERR_VEP_CAPSULE_HASH_FORMAT: &str = "ERR-VEP-CAPSULE-HASH-FORMAT";
pub const ERR_VEP_CAPSULE_VERIFIER_MISMATCH: &str = "ERR-VEP-CAPSULE-VERIFIER-MISMATCH";
pub const ERR_VEP_CAPSULE_CLAIM_MISMATCH: &str = "ERR-VEP-CAPSULE-CLAIM-MISMATCH";

/// Stable failure reasons for replay-capsule verification (bd-1h2w4).
///
/// Each variant maps to a deterministic reason code so operators can
/// diagnose capsule rejection without replaying verification logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleVerificationFailure {
    /// Required fields are empty (capsule_id, schema_version, attestation_id, etc.).
    MissingFields(&'static str),
    /// Schema version does not match the expected version.
    SchemaVersionMismatch,
    /// Freshness window is invalid or expired.
    FreshnessWindowInvalid,
    /// Trace chunk hashes are empty or contain non-SHA256 values.
    TraceChunkInvalid,
    /// Component hash is not valid SHA-256 hex.
    HashFormatInvalid(&'static str),
    /// Trace commitment root does not match recomputed Merkle root.
    TraceCommitmentMismatch,
    /// Integrity hash does not match recomputed integrity digest.
    IntegrityHashMismatch,
    /// Verifier is not registered.
    VerifierNotRegistered,
    /// Capsule verifier_id does not match attestation verifier_id.
    VerifierMismatch,
    /// Claim metadata hash does not match attestation claim.
    ClaimMetadataMismatch,
    /// Attestation not found for the given attestation_id.
    AttestationNotFound,
    /// Capsule signature failed verification.
    SignatureFailed,
}

impl CapsuleVerificationFailure {
    /// Stable error code for this failure reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     CapsuleVerificationFailure, ERR_VEP_CAPSULE_MISSING_FIELDS,
    /// };
    ///
    /// let failure = CapsuleVerificationFailure::MissingFields("capsule_id");
    /// assert_eq!(failure.code(), ERR_VEP_CAPSULE_MISSING_FIELDS);
    /// ```
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingFields(_) => ERR_VEP_CAPSULE_MISSING_FIELDS,
            Self::SchemaVersionMismatch => ERR_VEP_CAPSULE_SCHEMA,
            Self::FreshnessWindowInvalid => ERR_VEP_CAPSULE_FRESHNESS,
            Self::TraceChunkInvalid => ERR_VEP_CAPSULE_HASH_FORMAT,
            Self::HashFormatInvalid(_) => ERR_VEP_CAPSULE_HASH_FORMAT,
            Self::TraceCommitmentMismatch => ERR_VEP_CAPSULE_TRACE_COMMITMENT,
            Self::IntegrityHashMismatch => ERR_VEP_CAPSULE_INTEGRITY_HASH,
            Self::VerifierNotRegistered => ERR_VEP_UNREGISTERED_VERIFIER,
            Self::VerifierMismatch => ERR_VEP_CAPSULE_VERIFIER_MISMATCH,
            Self::ClaimMetadataMismatch => ERR_VEP_CAPSULE_CLAIM_MISMATCH,
            Self::AttestationNotFound => ERR_VEP_CAPSULE_ATTESTATION_BINDING,
            Self::SignatureFailed => ERR_VEP_CAPSULE_SIGNATURE,
        }
    }

    /// Human-readable detail for structured logging.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::CapsuleVerificationFailure;
    ///
    /// let detail = CapsuleVerificationFailure::HashFormatInvalid("integrity_hash").detail();
    /// assert!(detail.contains("integrity_hash"));
    /// ```
    pub fn detail(&self) -> String {
        match self {
            Self::MissingFields(field) => format!("required field empty: {field}"),
            Self::SchemaVersionMismatch => {
                format!("schema version mismatch: expected {REPLAY_CAPSULE_SCHEMA_VERSION}")
            }
            Self::FreshnessWindowInvalid => "freshness window invalid or expired".to_string(),
            Self::TraceChunkInvalid => "trace chunk hashes empty or invalid format".to_string(),
            Self::HashFormatInvalid(field) => {
                format!("hash field not valid SHA-256 hex: {field}")
            }
            Self::TraceCommitmentMismatch => {
                "trace commitment root does not match recomputed Merkle root".to_string()
            }
            Self::IntegrityHashMismatch => {
                "integrity hash does not match recomputed digest".to_string()
            }
            Self::VerifierNotRegistered => "verifier not registered".to_string(),
            Self::VerifierMismatch => {
                "capsule verifier_id does not match attestation verifier_id".to_string()
            }
            Self::ClaimMetadataMismatch => {
                "claim metadata hash does not match attestation claim".to_string()
            }
            Self::AttestationNotFound => "attestation not found".to_string(),
            Self::SignatureFailed => "capsule signature verification failed".to_string(),
        }
    }
}

impl fmt::Display for CapsuleVerificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Verification dimension that a verifier can attest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VerificationDimension {
    Compatibility,
    Security,
    Performance,
    SupplyChain,
    Conformance,
}

impl fmt::Display for VerificationDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatibility => write!(f, "compatibility"),
            Self::Security => write!(f, "security"),
            Self::Performance => write!(f, "performance"),
            Self::SupplyChain => write!(f, "supply_chain"),
            Self::Conformance => write!(f, "conformance"),
        }
    }
}

/// Verifier registration tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierTier {
    Basic,
    Advanced,
}

impl fmt::Display for VerifierTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Advanced => write!(f, "advanced"),
        }
    }
}

/// Reputation tier derived from the reputation score.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReputationTier {
    Novice,
    Active,
    Established,
    Trusted,
}

impl fmt::Display for ReputationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Novice => write!(f, "Novice"),
            Self::Active => write!(f, "Active"),
            Self::Established => write!(f, "Established"),
            Self::Trusted => write!(f, "Trusted"),
        }
    }
}

/// Map a reputation score (0-100) to a tier.
///
/// # Examples
///
/// ```
/// use frankenengine_node::verifier_economy::{reputation_tier_from_score, ReputationTier};
///
/// assert_eq!(reputation_tier_from_score(10), ReputationTier::Novice);
/// assert_eq!(reputation_tier_from_score(90), ReputationTier::Trusted);
/// ```
pub fn reputation_tier_from_score(score: u32) -> ReputationTier {
    match score {
        0..=24 => ReputationTier::Novice,
        25..=49 => ReputationTier::Active,
        50..=74 => ReputationTier::Established,
        _ => ReputationTier::Trusted,
    }
}

/// Attestation lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationState {
    Submitted,
    UnderReview,
    Published,
    Rejected,
    Disputed,
}

impl fmt::Display for AttestationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted => write!(f, "submitted"),
            Self::UnderReview => write!(f, "under_review"),
            Self::Published => write!(f, "published"),
            Self::Rejected => write!(f, "rejected"),
            Self::Disputed => write!(f, "disputed"),
        }
    }
}

/// Dispute outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeOutcome {
    Upheld,
    Rejected,
    Inconclusive,
}

impl fmt::Display for DisputeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upheld => write!(f, "upheld"),
            Self::Rejected => write!(f, "rejected"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core structs
// ---------------------------------------------------------------------------

/// Claim within an attestation.
#[derive(Debug, Clone)]
pub struct AttestationClaim {
    pub dimension: VerificationDimension,
    pub statement: String,
    pub score: f64,
}

/// Evidence within an attestation.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub suite_id: String,
    pub measurements: Vec<String>,
    pub execution_trace_hash: String,
    pub environment: BTreeMap<String, String>,
}

/// Cryptographic signature.
#[derive(Debug, Clone)]
pub struct AttestationSignature {
    pub algorithm: String,
    pub public_key: String,
    pub value: String,
}

/// A verification attestation.
#[derive(Debug, Clone)]
pub struct Attestation {
    pub attestation_id: String,
    pub verifier_id: String,
    pub claim: AttestationClaim,
    pub evidence: AttestationEvidence,
    pub signature: AttestationSignature,
    pub timestamp: String,
    pub immutable: bool,
    pub state: AttestationState,
}

/// Input for submitting an attestation.
#[derive(Debug, Clone)]
pub struct AttestationSubmission {
    pub verifier_id: String,
    pub claim: AttestationClaim,
    pub evidence: AttestationEvidence,
    pub signature: AttestationSignature,
    pub timestamp: String,
}

/// Registered verifier.
#[derive(Debug, Clone)]
pub struct Verifier {
    pub verifier_id: String,
    pub name: String,
    pub contact: String,
    pub public_key: String,
    pub capabilities: Vec<VerificationDimension>,
    pub tier: VerifierTier,
    pub reputation_score: u32,
    pub reputation_tier: ReputationTier,
    pub registered_at: String,
    pub active: bool,
}

/// Input for registering a verifier.
#[derive(Debug, Clone)]
pub struct VerifierRegistration {
    pub name: String,
    pub contact: String,
    pub public_key: String,
    pub capabilities: Vec<VerificationDimension>,
    pub tier: VerifierTier,
}

/// Reputation dimension scores for deterministic computation.
#[derive(Debug, Clone)]
pub struct ReputationDimensions {
    pub consistency: f64,
    pub coverage: f64,
    pub accuracy: f64,
    pub longevity: f64,
}

/// Dispute filed against an attestation.
#[derive(Debug, Clone)]
pub struct Dispute {
    pub dispute_id: String,
    pub attestation_id: String,
    pub filed_by: String,
    pub justification: String,
    pub supporting_evidence: Vec<String>,
    pub outcome: Option<DisputeOutcome>,
    pub filed_at: String,
    pub resolved_at: Option<String>,
}

/// Replay capsule for independent verification.
#[derive(Debug, Clone)]
pub struct ReplayCapsule {
    pub capsule_id: String,
    pub schema_version: String,
    pub attestation_id: String,
    pub verifier_id: String,
    pub claim_metadata_hash: String,
    pub issued_at: String,
    pub expires_at: String,
    pub input_state_hash: String,
    pub trace_chunk_hashes: Vec<String>,
    pub trace_commitment_root: String,
    pub output_state_hash: String,
    pub expected_result_hash: String,
    pub integrity_hash: String,
    pub signature: AttestationSignature,
}

/// Scoreboard entry for a single verifier.
#[derive(Debug, Clone)]
pub struct ScoreboardEntry {
    pub verifier_id: String,
    pub verifier_name: String,
    pub reputation_score: u32,
    pub reputation_tier: ReputationTier,
    pub attestation_count: usize,
    pub dimensions_covered: Vec<VerificationDimension>,
}

/// Aggregate scoreboard for public display.
#[derive(Debug, Clone)]
pub struct TrustScoreboard {
    pub entries: Vec<ScoreboardEntry>,
    pub total_attestations: usize,
    pub total_verifiers: usize,
    pub aggregate_score: f64,
}

/// Event emitted by the verifier economy system.
#[derive(Debug, Clone)]
pub struct VerifierEconomyEvent {
    pub code: String,
    pub detail: String,
    pub timestamp: u64,
}

/// Result type for verifier economy operations.
#[derive(Debug, Clone)]
pub struct VepError {
    pub code: String,
    pub message: String,
}

impl fmt::Display for VepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type VepResult<T> = Result<T, VepError>;

#[derive(Default)]
struct PublishedVerifierStats {
    attestation_count: usize,
    dimensions: BTreeSet<VerificationDimension>,
}

fn next_sequential_id(
    counter: &mut u64,
    exhausted: &mut bool,
    prefix: &str,
    entity: &str,
) -> VepResult<String> {
    if *exhausted {
        return Err(VepError {
            code: ERR_VEP_CAPACITY_EXCEEDED.to_string(),
            message: format!("{entity} ID sequence exhausted"),
        });
    }

    let current = *counter;
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    } else {
        *exhausted = true;
    }
    Ok(format!("{prefix}-{:04}", current))
}

fn increment_submission_count(count: &mut u32, verifier_id: &str) -> VepResult<u32> {
    let next = count.checked_add(1).ok_or_else(|| VepError {
        code: ERR_VEP_ANTI_GAMING.to_string(),
        message: format!("Submission counter exhausted for verifier {verifier_id}"),
    })?;
    *count = next;
    Ok(next)
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Central registry for the verifier economy.
pub struct VerifierEconomyRegistry {
    verifiers: BTreeMap<String, Verifier>,
    registered_public_keys: BTreeSet<String>,
    attestations: BTreeMap<String, Attestation>,
    attestation_fingerprints: BTreeSet<(String, String)>,
    disputes: BTreeMap<String, Dispute>,
    replay_capsules: BTreeMap<String, ReplayCapsule>,
    events: Vec<VerifierEconomyEvent>,
    parsed_verifier_keys: BTreeMap<String, VerifyingKey>,
    next_verifier_id: u64,
    next_attestation_id: u64,
    next_dispute_id: u64,
    verifier_id_exhausted: bool,
    attestation_id_exhausted: bool,
    dispute_id_exhausted: bool,
    /// Sybil resistance: track submission counts per verifier per window.
    submission_counts: BTreeMap<String, u32>,
    /// Maximum submissions per verifier per window.
    max_submissions_per_window: u32,
    /// Maximum allowed freshness window for replay capsules.
    replay_capsule_freshness_secs: i64,
}

impl Default for VerifierEconomyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierEconomyRegistry {
    /// Create an empty verifier-economy registry.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert_eq!(registry.verifier_count(), 0);
    /// assert!(registry.events().is_empty());
    /// ```
    pub fn new() -> Self {
        Self::with_replay_capsule_freshness_secs(DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS as u64)
    }

    /// Create a registry with a custom replay-capsule freshness limit.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::with_replay_capsule_freshness_secs(120);
    /// assert_eq!(registry.replay_capsule_freshness_secs(), 120);
    /// ```
    pub fn with_replay_capsule_freshness_secs(replay_capsule_freshness_secs: u64) -> Self {
        Self::with_replay_capsule_freshness_and_submissions(replay_capsule_freshness_secs, 100)
    }

    /// Create a registry with custom replay-capsule freshness and submission limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::with_replay_capsule_freshness_and_submissions(120, 50);
    /// assert_eq!(registry.replay_capsule_freshness_secs(), 120);
    /// ```
    pub fn with_replay_capsule_freshness_and_submissions(
        replay_capsule_freshness_secs: u64,
        max_submissions_per_window: u32,
    ) -> Self {
        let replay_capsule_freshness_secs =
            i64::try_from(replay_capsule_freshness_secs.max(1)).unwrap_or(i64::MAX);
        Self {
            verifiers: BTreeMap::new(),
            registered_public_keys: BTreeSet::new(),
            attestations: BTreeMap::new(),
            attestation_fingerprints: BTreeSet::new(),
            disputes: BTreeMap::new(),
            replay_capsules: BTreeMap::new(),
            events: Vec::new(),
            parsed_verifier_keys: BTreeMap::new(),
            next_verifier_id: 1,
            next_attestation_id: 1,
            next_dispute_id: 1,
            verifier_id_exhausted: false,
            attestation_id_exhausted: false,
            dispute_id_exhausted: false,
            submission_counts: BTreeMap::new(),
            max_submissions_per_window,
            replay_capsule_freshness_secs,
        }
    }

    /// Create a registry from replay configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::config::ReplayConfig;
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let config = ReplayConfig { max_replay_capsule_freshness_secs: 90, ..ReplayConfig::default() };
    /// let registry = VerifierEconomyRegistry::from_replay_config(&config);
    /// assert_eq!(registry.replay_capsule_freshness_secs(), 90);
    /// ```
    pub fn from_replay_config(config: &crate::config::ReplayConfig) -> Self {
        Self::with_replay_capsule_freshness_and_submissions(
            config.max_replay_capsule_freshness_secs,
            config.max_submissions_per_window.unwrap_or(100),
        )
    }

    /// Return the configured replay-capsule freshness limit in seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::with_replay_capsule_freshness_secs(1);
    /// assert_eq!(registry.replay_capsule_freshness_secs(), 1);
    /// ```
    #[must_use]
    pub fn replay_capsule_freshness_secs(&self) -> i64 {
        self.replay_capsule_freshness_secs
    }

    fn now_epoch(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn emit(&mut self, code: &str, detail: &str) {
        let ts = self.now_epoch();
        push_bounded(
            &mut self.events,
            VerifierEconomyEvent {
                code: code.to_string(),
                detail: detail.to_string(),
                timestamp: ts,
            },
            MAX_EVENTS,
        );
    }

    fn evict_oldest_terminal_attestation(&mut self) -> bool {
        let terminal_key = self
            .attestations
            .iter()
            .filter(|(_, attestation)| {
                matches!(
                    attestation.state,
                    AttestationState::Published | AttestationState::Rejected
                )
            })
            .min_by_key(|(_, att)| att.timestamp.as_str())
            .map(|(id, _)| id.clone());

        if let Some(id) = terminal_key
            && let Some(evicted) = self.attestations.remove(&id)
        {
            self.attestation_fingerprints
                .remove(&(evicted.verifier_id, evicted.evidence.execution_trace_hash));
            return true;
        }

        false
    }

    fn ensure_attestation_capacity(&mut self) -> VepResult<()> {
        if self.attestations.len() < MAX_ATTESTATIONS || self.evict_oldest_terminal_attestation() {
            return Ok(());
        }

        Err(VepError {
            code: ERR_VEP_CAPACITY_EXCEEDED.to_string(),
            message: "Attestation registry is full of live entries; resolve published or rejected attestations before accepting more submissions".to_string(),
        })
    }

    fn evict_oldest_resolved_dispute(&mut self) -> bool {
        let resolved_key = self
            .disputes
            .iter()
            .filter(|(_, dispute)| dispute.outcome.is_some())
            .min_by_key(|(_, dispute)| dispute.resolved_at.as_deref().unwrap_or(""))
            .map(|(id, _)| id.clone());

        resolved_key
            .and_then(|id| self.disputes.remove(&id))
            .is_some()
    }

    fn ensure_dispute_capacity(&mut self) -> VepResult<()> {
        if self.disputes.len() < MAX_DISPUTES || self.evict_oldest_resolved_dispute() {
            return Ok(());
        }

        Err(VepError {
            code: ERR_VEP_CAPACITY_EXCEEDED.to_string(),
            message: "Dispute registry is full of unresolved entries; resolve existing disputes before filing more".to_string(),
        })
    }

    /// Return emitted verifier-economy events without draining them.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.events().is_empty());
    /// ```
    pub fn events(&self) -> &[VerifierEconomyEvent] {
        &self.events
    }

    /// Drain and return all emitted verifier-economy events.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// assert!(registry.take_events().is_empty());
    /// ```
    pub fn take_events(&mut self) -> Vec<VerifierEconomyEvent> {
        std::mem::take(&mut self.events)
    }

    // -- Verifier registration -----------------------------------------------

    /// Register a verifier identity and canonicalize its Ed25519 public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     VerifierEconomyRegistry, VerifierRegistration, VerifierTier, VerificationDimension,
    ///     ERR_VEP_INVALID_PUBLIC_KEY,
    /// };
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.register_verifier(VerifierRegistration {
    ///     name: "Example Verifier".to_string(),
    ///     contact: "verify@example.test".to_string(),
    ///     public_key: "not-an-ed25519-key".to_string(),
    ///     capabilities: vec![VerificationDimension::Compatibility],
    ///     tier: VerifierTier::Basic,
    /// }).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INVALID_PUBLIC_KEY);
    /// ```
    pub fn register_verifier(&mut self, reg: VerifierRegistration) -> VepResult<Verifier> {
        let canonical_public_key =
            canonicalize_ed25519_public_key_hex(&reg.public_key).map_err(|message| VepError {
                code: ERR_VEP_INVALID_PUBLIC_KEY.to_string(),
                message: format!("Verifier public key invalid: {message}"),
            })?;

        // Check for duplicate public key
        if self.registered_public_keys.contains(&canonical_public_key) {
            return Err(VepError {
                code: ERR_VEP_DUPLICATE_SUBMISSION.to_string(),
                message: "A verifier with this public key is already registered".to_string(),
            });
        }

        let verifier_id = next_sequential_id(
            &mut self.next_verifier_id,
            &mut self.verifier_id_exhausted,
            "ver",
            "Verifier",
        )?;

        let verifier = Verifier {
            verifier_id: verifier_id.clone(),
            name: reg.name,
            contact: reg.contact,
            public_key: canonical_public_key,
            capabilities: reg.capabilities,
            tier: reg.tier,
            reputation_score: 0,
            reputation_tier: ReputationTier::Novice,
            registered_at: format!("{}", self.now_epoch()),
            active: true,
        };

        if self.verifiers.len() >= MAX_VERIFIERS
            && !self.verifiers.contains_key(&verifier_id)
            && let Some(oldest_key) = self.verifiers.keys().next().cloned()
            && let Some(evicted) = self.verifiers.remove(&oldest_key)
        {
            self.registered_public_keys.remove(&evicted.public_key);
            self.parsed_verifier_keys.remove(&evicted.verifier_id);
        }
        self.registered_public_keys
            .insert(verifier.public_key.clone());
        self.verifiers.insert(verifier_id.clone(), verifier.clone());
        self.emit(VEP_005, &format!("Verifier registered: {}", verifier_id));

        Ok(verifier)
    }

    /// Look up a verifier by ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.get_verifier("ver-0001").is_none());
    /// ```
    pub fn get_verifier(&self, verifier_id: &str) -> Option<&Verifier> {
        self.verifiers.get(verifier_id)
    }

    /// List registered verifiers in deterministic key order.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.list_verifiers().is_empty());
    /// ```
    pub fn list_verifiers(&self) -> Vec<&Verifier> {
        self.verifiers.values().collect()
    }

    /// Return the number of registered verifiers.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// assert_eq!(VerifierEconomyRegistry::new().verifier_count(), 0);
    /// ```
    pub fn verifier_count(&self) -> usize {
        self.verifiers.len()
    }

    // -- Attestation submission & publishing ----------------------------------

    /// Submit an attestation. Validates structure and signature before accepting.
    /// Follows INV-VEP-PUBLISH: submit -> review -> publish.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     AttestationClaim, AttestationEvidence, AttestationSignature, AttestationSubmission,
    ///     ERR_VEP_UNREGISTERED_VERIFIER, VerifierEconomyRegistry, VerificationDimension,
    /// };
    /// use std::collections::BTreeMap;
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.submit_attestation(AttestationSubmission {
    ///     verifier_id: "ver-0001".to_string(),
    ///     claim: AttestationClaim {
    ///         dimension: VerificationDimension::Compatibility,
    ///         statement: "compatibility suite passed".to_string(),
    ///         score: 0.95,
    ///     },
    ///     evidence: AttestationEvidence {
    ///         suite_id: "suite-compat".to_string(),
    ///         measurements: Vec::new(),
    ///         execution_trace_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    ///         environment: BTreeMap::new(),
    ///     },
    ///     signature: AttestationSignature {
    ///         algorithm: "ed25519".to_string(),
    ///         public_key: String::new(),
    ///         value: String::new(),
    ///     },
    ///     timestamp: "2026-04-25T00:00:00Z".to_string(),
    /// }).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_UNREGISTERED_VERIFIER);
    /// ```
    pub fn submit_attestation(
        &mut self,
        mut submission: AttestationSubmission,
    ) -> VepResult<Attestation> {
        // INV-VEP-PUBLISH: Stage 1 — Submission

        // Check verifier is registered
        let verifier_public_key = match self.verifiers.get(&submission.verifier_id) {
            Some(v) => v.public_key.clone(),
            None => {
                self.emit(
                    VEP_008,
                    &format!("Rejected: unregistered verifier {}", submission.verifier_id),
                );
                return Err(VepError {
                    code: ERR_VEP_UNREGISTERED_VERIFIER.to_string(),
                    message: format!("Verifier {} is not registered", submission.verifier_id),
                });
            }
        };

        // Validate payload completeness (INV-VEP-ATTESTATION)
        if submission.claim.statement.is_empty() || submission.evidence.suite_id.is_empty() {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: incomplete payload from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: "Attestation claim statement and evidence suite_id are required"
                    .to_string(),
            });
        }

        let canonical_trace_hash = match canonicalize_sha256_prefixed_hex(
            &submission.evidence.execution_trace_hash,
        ) {
            Some(hash)
                if constant_time::ct_eq(&hash, &submission.evidence.execution_trace_hash) =>
            {
                hash
            }
            _ => {
                self.emit(
                    VEP_008,
                    &format!(
                        "Rejected: noncanonical execution_trace_hash from {}",
                        submission.verifier_id
                    ),
                );
                return Err(VepError {
                    code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                    message: "Attestation evidence execution_trace_hash must use canonical lowercase sha256:<64-hex> form"
                        .to_string(),
                });
            }
        };
        submission.evidence.execution_trace_hash = canonical_trace_hash;

        let signature_payload = attestation_signature_payload(&submission);

        // INV-VEP-SIGNATURE: Verify signature
        if !self.verify_signature_with_cached_key(
            &submission.signature,
            &submission.verifier_id,
            &verifier_public_key,
            &signature_payload,
        ) {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: invalid signature from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_INVALID_SIGNATURE.to_string(),
                message: "Attestation signature verification failed".to_string(),
            });
        }

        // Anti-gaming: sybil resistance rate limiting
        let submission_total = {
            let count = self
                .submission_counts
                .entry(submission.verifier_id.clone())
                .or_insert(0);
            increment_submission_count(count, &submission.verifier_id)
        };
        let submission_total = match submission_total {
            Ok(total) => total,
            Err(error) => {
                self.emit(
                    VEP_006,
                    &format!(
                        "Anti-gaming: submission counter exhausted for {}",
                        submission.verifier_id
                    ),
                );
                return Err(error);
            }
        };
        if submission_total > self.max_submissions_per_window {
            self.emit(
                VEP_006,
                &format!(
                    "Anti-gaming: rate limit exceeded for {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_ANTI_GAMING.to_string(),
                message: "Submission rate limit exceeded".to_string(),
            });
        }

        let fingerprint = (
            submission.verifier_id.clone(),
            submission.evidence.execution_trace_hash.clone(),
        );

        // Check for duplicate submission
        if self.attestation_fingerprints.contains(&fingerprint) {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: duplicate submission from {}",
                    submission.verifier_id
                ),
            );
            return Err(VepError {
                code: ERR_VEP_DUPLICATE_SUBMISSION.to_string(),
                message: "Duplicate attestation submission".to_string(),
            });
        }

        if let Err(error) = self.ensure_attestation_capacity() {
            self.emit(
                VEP_008,
                &format!(
                    "Rejected: attestation registry at capacity for {}",
                    submission.verifier_id
                ),
            );
            return Err(error);
        }

        let attestation_id = next_sequential_id(
            &mut self.next_attestation_id,
            &mut self.attestation_id_exhausted,
            "att",
            "Attestation",
        )?;

        // Bound evidence measurements to prevent DoS attacks
        let mut bounded_measurements = Vec::new();
        for measurement in submission.evidence.measurements {
            push_bounded(&mut bounded_measurements, measurement, 20);
        }
        let bounded_evidence = AttestationEvidence {
            suite_id: submission.evidence.suite_id,
            measurements: bounded_measurements,
            execution_trace_hash: submission.evidence.execution_trace_hash,
            environment: submission.evidence.environment,
        };

        let attestation = Attestation {
            attestation_id: attestation_id.clone(),
            verifier_id: submission.verifier_id,
            claim: submission.claim,
            evidence: bounded_evidence,
            signature: submission.signature,
            timestamp: submission.timestamp,
            immutable: false, // Not yet published
            state: AttestationState::Submitted,
        };
        self.attestation_fingerprints.insert(fingerprint);
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.emit(
            VEP_001,
            &format!("Attestation submitted: {}", attestation_id),
        );

        Ok(attestation)
    }

    /// Review an attestation. Transitions from Submitted to UnderReview.
    /// Part of INV-VEP-PUBLISH flow.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD};
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.review_attestation("att-0001").unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn review_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::Submitted {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Cannot review attestation in state {}", att.state),
            });
        }

        att.state = AttestationState::UnderReview;
        Ok(AttestationState::UnderReview)
    }

    /// Publish an attestation. Transitions from UnderReview to Published.
    /// Sets immutable=true per INV-VEP-ATTESTATION.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD};
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.publish_attestation("att-0001").unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn publish_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::UnderReview {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!(
                    "Cannot publish attestation in state {} (must be under_review)",
                    att.state
                ),
            });
        }

        // INV-VEP-ATTESTATION: mark as immutable
        att.state = AttestationState::Published;
        att.immutable = true;

        self.emit(
            VEP_002,
            &format!("Attestation published: {}", attestation_id),
        );
        Ok(AttestationState::Published)
    }

    /// Reject an attestation during review.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD};
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.reject_attestation("att-0001").unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn reject_attestation(&mut self, attestation_id: &str) -> VepResult<AttestationState> {
        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::UnderReview {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Cannot reject attestation in state {}", att.state),
            });
        }

        att.state = AttestationState::Rejected;
        self.emit(
            VEP_008,
            &format!("Attestation rejected: {}", attestation_id),
        );
        Ok(AttestationState::Rejected)
    }

    /// Look up an attestation by ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.get_attestation("att-0001").is_none());
    /// ```
    pub fn get_attestation(&self, attestation_id: &str) -> Option<&Attestation> {
        self.attestations.get(attestation_id)
    }

    /// List all attestations in deterministic key order.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.list_attestations().is_empty());
    /// ```
    pub fn list_attestations(&self) -> Vec<&Attestation> {
        self.attestations.values().collect()
    }

    /// List only published attestations.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.published_attestations().is_empty());
    /// ```
    pub fn published_attestations(&self) -> Vec<&Attestation> {
        self.attestations
            .values()
            .filter(|a| a.state == AttestationState::Published)
            .collect()
    }

    /// Return the number of tracked attestations.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// assert_eq!(VerifierEconomyRegistry::new().attestation_count(), 0);
    /// ```
    pub fn attestation_count(&self) -> usize {
        self.attestations.len()
    }

    // -- Signature verification -----------------------------------------------

    /// Verify an attestation signature against the verifier's public key.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{AttestationSignature, VerifierEconomyRegistry};
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// let signature = AttestationSignature {
    ///     algorithm: "ed25519".to_string(),
    ///     public_key: "not-a-key".to_string(),
    ///     value: String::new(),
    /// };
    /// assert!(!registry.verify_signature(&signature, "not-a-key", b"payload"));
    /// ```
    pub fn verify_signature(
        &self,
        sig: &AttestationSignature,
        expected_key: &str,
        payload: &[u8],
    ) -> bool {
        sig.algorithm.eq_ignore_ascii_case("ed25519")
            && canonicalized_ed25519_public_keys_match(expected_key, &sig.public_key)
            && canonicalize_ed25519_public_key_hex(expected_key)
                .ok()
                .is_some_and(|canonical_expected| {
                    verify_ed25519_signature_hex(&canonical_expected, payload, &sig.value).is_ok()
                })
    }

    fn verify_signature_with_cached_key(
        &mut self,
        sig: &AttestationSignature,
        verifier_id: &str,
        expected_key: &str,
        payload: &[u8],
    ) -> bool {
        if !sig.algorithm.eq_ignore_ascii_case("ed25519")
            || !canonicalized_ed25519_public_keys_match(expected_key, &sig.public_key)
        {
            return false;
        }

        if let Some(verifying_key) = self.parsed_verifier_keys.get(verifier_id) {
            return verify_ed25519_signature_with_key_hex(verifying_key, payload, &sig.value)
                .is_ok();
        }

        let canonical_expected = match canonicalize_ed25519_public_key_hex(expected_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let parsed_key = match parse_ed25519_verifying_key_hex(&canonical_expected) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let verifying_key = self
            .parsed_verifier_keys
            .entry(verifier_id.to_string())
            .or_insert(parsed_key);
        verify_ed25519_signature_with_key_hex(verifying_key, payload, &sig.value).is_ok()
    }

    // -- Reputation scoring ---------------------------------------------------

    /// Compute verifier reputation deterministically.
    /// INV-VEP-REPUTATION: same inputs always produce the same score.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{ReputationDimensions, VerifierEconomyRegistry};
    ///
    /// let score = VerifierEconomyRegistry::compute_reputation(&ReputationDimensions {
    ///     consistency: 1.0,
    ///     coverage: 0.8,
    ///     accuracy: 0.9,
    ///     longevity: 0.5,
    /// });
    /// assert!(score <= 100);
    /// ```
    pub fn compute_reputation(dims: &ReputationDimensions) -> u32 {
        let raw = 0.35 * dims.consistency
            + 0.25 * dims.coverage
            + 0.30 * dims.accuracy
            + 0.10 * dims.longevity;
        if !raw.is_finite() {
            return 0;
        }
        let score = (raw * 100.0).round() as i64;
        score.clamp(0, 100) as u32
    }

    /// Update a verifier's reputation score with new dimension values.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     ERR_VEP_UNREGISTERED_VERIFIER, ReputationDimensions, VerifierEconomyRegistry,
    /// };
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.update_reputation("ver-0001", &ReputationDimensions {
    ///     consistency: 1.0,
    ///     coverage: 1.0,
    ///     accuracy: 1.0,
    ///     longevity: 1.0,
    /// }).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_UNREGISTERED_VERIFIER);
    /// ```
    pub fn update_reputation(
        &mut self,
        verifier_id: &str,
        dims: &ReputationDimensions,
    ) -> VepResult<u32> {
        let verifier = self.verifiers.get_mut(verifier_id).ok_or(VepError {
            code: ERR_VEP_UNREGISTERED_VERIFIER.to_string(),
            message: format!("Verifier {} not found", verifier_id),
        })?;

        let new_score = Self::compute_reputation(dims);
        let old_tier = verifier.reputation_tier.clone();
        verifier.reputation_score = new_score;
        verifier.reputation_tier = reputation_tier_from_score(new_score);

        let new_tier = verifier.reputation_tier.clone();

        self.emit(
            VEP_004,
            &format!(
                "Reputation updated: {} score={} tier={} (was {})",
                verifier_id, new_score, new_tier, old_tier
            ),
        );

        Ok(new_score)
    }

    // -- Disputes -------------------------------------------------------------

    /// File a dispute against a published attestation.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD};
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.file_dispute(
    ///     "att-0001",
    ///     "operator@example.test",
    ///     "evidence mismatch",
    ///     vec!["trace mismatch".to_string()],
    /// ).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn file_dispute(
        &mut self,
        attestation_id: &str,
        filed_by: &str,
        justification: &str,
        supporting_evidence: Vec<String>,
    ) -> VepResult<Dispute> {
        // Verify attestation exists and is published before reserving dispute capacity.
        let att = self.attestations.get(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;

        if att.state != AttestationState::Published {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: "Can only dispute published attestations".to_string(),
            });
        }

        self.ensure_dispute_capacity()?;

        let att = self.attestations.get_mut(attestation_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Attestation {} not found", attestation_id),
        })?;
        att.state = AttestationState::Disputed;

        let dispute_id = next_sequential_id(
            &mut self.next_dispute_id,
            &mut self.dispute_id_exhausted,
            "dsp",
            "Dispute",
        )?;

        // Bound supporting evidence to prevent DoS attacks
        let mut bounded_evidence = Vec::new();
        for evidence in supporting_evidence {
            push_bounded(&mut bounded_evidence, evidence, 10);
        }

        let dispute = Dispute {
            dispute_id: dispute_id.clone(),
            attestation_id: attestation_id.to_string(),
            filed_by: filed_by.to_string(),
            justification: justification.to_string(),
            supporting_evidence: bounded_evidence,
            outcome: None,
            filed_at: format!("{}", self.now_epoch()),
            resolved_at: None,
        };

        self.disputes.insert(dispute_id.clone(), dispute.clone());
        self.emit(
            VEP_003,
            &format!("Dispute filed: {} against {}", dispute_id, attestation_id),
        );

        Ok(dispute)
    }

    /// Resolve a dispute with an outcome.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     DisputeOutcome, VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD,
    /// };
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.resolve_dispute("dsp-0001", DisputeOutcome::Rejected).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn resolve_dispute(&mut self, dispute_id: &str, outcome: DisputeOutcome) -> VepResult<()> {
        let now = self.now_epoch();
        let outcome_display = format!("{}", outcome);
        let dispute_id_owned = dispute_id.to_string();
        let attestation_id = {
            let dispute = self.disputes.get(dispute_id).ok_or(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Dispute {} not found", dispute_id),
            })?;

            if dispute.outcome.is_some() {
                return Err(VepError {
                    code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                    message: format!("Dispute {} already resolved", dispute_id),
                });
            }

            dispute.attestation_id.clone()
        };

        let settlement_state = match &outcome {
            DisputeOutcome::Upheld => AttestationState::Rejected,
            DisputeOutcome::Rejected | DisputeOutcome::Inconclusive => AttestationState::Published,
        };

        if !self.attestations.contains_key(&attestation_id) {
            return Err(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Attestation {} not found", attestation_id),
            });
        }

        let dispute = self.disputes.get_mut(dispute_id).ok_or(VepError {
            code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
            message: format!("Dispute {} not found", dispute_id),
        })?;

        dispute.outcome = Some(outcome);
        dispute.resolved_at = Some(format!("{}", now));

        let attestation = self
            .attestations
            .get_mut(&attestation_id)
            .expect("attestation existence checked before dispute resolution");
        attestation.state = settlement_state;

        self.emit(
            VEP_004,
            &format!("Dispute {} resolved: {}", dispute_id_owned, outcome_display),
        );

        Ok(())
    }

    /// Look up a dispute by ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.get_dispute("dsp-0001").is_none());
    /// ```
    pub fn get_dispute(&self, dispute_id: &str) -> Option<&Dispute> {
        self.disputes.get(dispute_id)
    }

    /// List tracked disputes in deterministic key order.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.list_disputes().is_empty());
    /// ```
    pub fn list_disputes(&self) -> Vec<&Dispute> {
        self.disputes.values().collect()
    }

    // -- Replay capsules ------------------------------------------------------

    fn replay_capsule_rejection_error(
        capsule_id: &str,
        failure: &CapsuleVerificationFailure,
    ) -> VepError {
        VepError {
            code: failure.code().to_string(),
            message: format!(
                "Replay capsule {} rejected: reason_code={}; {}",
                capsule_id,
                failure.code(),
                failure.detail()
            ),
        }
    }

    fn oldest_replay_capsule_key(&self) -> Option<String> {
        self.replay_capsules
            .iter()
            .min_by(|(left_id, left_capsule), (right_id, right_capsule)| {
                replay_capsule_issued_at_sort_key(&left_capsule.issued_at)
                    .cmp(&replay_capsule_issued_at_sort_key(&right_capsule.issued_at))
                    .then_with(|| left_id.cmp(right_id))
            })
            .map(|(capsule_id, _)| capsule_id.clone())
    }

    /// Register a replay capsule after structural, binding, and signature checks.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     AttestationSignature, ReplayCapsule, VerifierEconomyRegistry,
    ///     ERR_VEP_CAPSULE_MISSING_FIELDS,
    /// };
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.register_replay_capsule(ReplayCapsule {
    ///     capsule_id: String::new(),
    ///     schema_version: String::new(),
    ///     attestation_id: String::new(),
    ///     verifier_id: String::new(),
    ///     claim_metadata_hash: String::new(),
    ///     issued_at: String::new(),
    ///     expires_at: String::new(),
    ///     input_state_hash: String::new(),
    ///     trace_chunk_hashes: Vec::new(),
    ///     trace_commitment_root: String::new(),
    ///     output_state_hash: String::new(),
    ///     expected_result_hash: String::new(),
    ///     integrity_hash: String::new(),
    ///     signature: AttestationSignature {
    ///         algorithm: String::new(),
    ///         public_key: String::new(),
    ///         value: String::new(),
    ///     },
    /// }).unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_CAPSULE_MISSING_FIELDS);
    /// ```
    pub fn register_replay_capsule(&mut self, capsule: ReplayCapsule) -> VepResult<()> {
        if let Err(failure) = self.verify_replay_capsule(&capsule) {
            return Err(Self::replay_capsule_rejection_error(
                &capsule.capsule_id,
                &failure,
            ));
        }
        let capsule_id = capsule.capsule_id.clone();
        if self.replay_capsules.len() >= MAX_REPLAY_CAPSULES
            && !self.replay_capsules.contains_key(&capsule_id)
            && let Some(oldest_key) = self.oldest_replay_capsule_key()
        {
            self.replay_capsules.remove(&oldest_key);
        }
        // Bound trace chunk hashes to prevent DoS attacks
        let mut bounded_trace_chunks = Vec::new();
        for chunk_hash in capsule.trace_chunk_hashes {
            push_bounded(&mut bounded_trace_chunks, chunk_hash, 100);
        }
        let bounded_capsule = ReplayCapsule {
            trace_chunk_hashes: bounded_trace_chunks,
            ..capsule
        };

        self.replay_capsules
            .insert(capsule_id.clone(), bounded_capsule);
        Ok(())
    }

    /// Access a replay capsule by ID and re-verify it before returning it.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{VerifierEconomyRegistry, ERR_VEP_INCOMPLETE_PAYLOAD};
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// let err = registry.access_replay_capsule("capsule-1").unwrap_err();
    /// assert_eq!(err.code, ERR_VEP_INCOMPLETE_PAYLOAD);
    /// ```
    pub fn access_replay_capsule(&mut self, capsule_id: &str) -> VepResult<ReplayCapsule> {
        let capsule = self
            .replay_capsules
            .get(capsule_id)
            .cloned()
            .ok_or(VepError {
                code: ERR_VEP_INCOMPLETE_PAYLOAD.to_string(),
                message: format!("Replay capsule {} not found", capsule_id),
            })?;

        if let Err(failure) = self.verify_replay_capsule(&capsule) {
            return Err(Self::replay_capsule_rejection_error(capsule_id, &failure));
        }

        self.emit(VEP_007, &format!("Replay capsule accessed: {}", capsule_id));

        Ok(capsule)
    }

    /// Verify replay capsule integrity by checking hash consistency.
    ///
    /// This public helper enforces the default replay-capsule freshness
    /// window. Registry methods that support a configured freshness limit
    /// call the internal helper with the registry-local value instead.
    ///
    /// Returns `Ok(())` if the capsule passes all structural and
    /// cryptographic integrity checks, or a specific
    /// [`CapsuleVerificationFailure`] identifying the first failing check.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     AttestationSignature, CapsuleVerificationFailure, ReplayCapsule, VerifierEconomyRegistry,
    /// };
    ///
    /// let failure = VerifierEconomyRegistry::verify_capsule_integrity(&ReplayCapsule {
    ///     capsule_id: String::new(),
    ///     schema_version: String::new(),
    ///     attestation_id: String::new(),
    ///     verifier_id: String::new(),
    ///     claim_metadata_hash: String::new(),
    ///     issued_at: String::new(),
    ///     expires_at: String::new(),
    ///     input_state_hash: String::new(),
    ///     trace_chunk_hashes: Vec::new(),
    ///     trace_commitment_root: String::new(),
    ///     output_state_hash: String::new(),
    ///     expected_result_hash: String::new(),
    ///     integrity_hash: String::new(),
    ///     signature: AttestationSignature {
    ///         algorithm: String::new(),
    ///         public_key: String::new(),
    ///         value: String::new(),
    ///     },
    /// }).unwrap_err();
    /// assert_eq!(failure, CapsuleVerificationFailure::MissingFields("capsule_id"));
    /// ```
    pub fn verify_capsule_integrity(
        capsule: &ReplayCapsule,
    ) -> Result<(), CapsuleVerificationFailure> {
        Self::verify_capsule_integrity_with_freshness(
            capsule,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        )
    }

    fn verify_capsule_integrity_with_freshness(
        capsule: &ReplayCapsule,
        freshness_secs: i64,
    ) -> Result<(), CapsuleVerificationFailure> {
        if capsule.capsule_id.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("capsule_id"));
        }
        if capsule.schema_version.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("schema_version"));
        }
        if capsule.attestation_id.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("attestation_id"));
        }
        if capsule.verifier_id.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("verifier_id"));
        }
        if capsule.issued_at.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("issued_at"));
        }
        if capsule.expires_at.is_empty() {
            return Err(CapsuleVerificationFailure::MissingFields("expires_at"));
        }
        if capsule.schema_version != REPLAY_CAPSULE_SCHEMA_VERSION {
            return Err(CapsuleVerificationFailure::SchemaVersionMismatch);
        }
        if !replay_capsule_freshness_window_valid(
            &capsule.issued_at,
            &capsule.expires_at,
            freshness_secs,
        ) {
            return Err(CapsuleVerificationFailure::FreshnessWindowInvalid);
        }
        if capsule.trace_chunk_hashes.is_empty() {
            return Err(CapsuleVerificationFailure::TraceChunkInvalid);
        }

        let hash_fields: &[(&str, &str)] = &[
            ("claim_metadata_hash", &capsule.claim_metadata_hash),
            ("input_state_hash", &capsule.input_state_hash),
            ("trace_commitment_root", &capsule.trace_commitment_root),
            ("output_state_hash", &capsule.output_state_hash),
            ("expected_result_hash", &capsule.expected_result_hash),
            ("integrity_hash", &capsule.integrity_hash),
        ];
        for &(name, value) in hash_fields {
            if !is_sha256_prefixed_hex(value) {
                // Use a static label for the first invalid field.
                return Err(CapsuleVerificationFailure::HashFormatInvalid(match name {
                    "claim_metadata_hash" => "claim_metadata_hash",
                    "input_state_hash" => "input_state_hash",
                    "trace_commitment_root" => "trace_commitment_root",
                    "output_state_hash" => "output_state_hash",
                    "expected_result_hash" => "expected_result_hash",
                    "integrity_hash" => "integrity_hash",
                    _ => "unknown",
                }));
            }
        }
        if capsule
            .trace_chunk_hashes
            .iter()
            .any(|hash| !is_sha256_prefixed_hex(hash))
        {
            return Err(CapsuleVerificationFailure::TraceChunkInvalid);
        }
        let expected_trace_root = compute_trace_commitment_root(&capsule.trace_chunk_hashes)
            .ok_or(CapsuleVerificationFailure::TraceCommitmentMismatch)?;
        if !constant_time::ct_eq(&capsule.trace_commitment_root, &expected_trace_root) {
            return Err(CapsuleVerificationFailure::TraceCommitmentMismatch);
        }

        let expected_integrity = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );

        if !constant_time::ct_eq(&capsule.integrity_hash, &expected_integrity) {
            return Err(CapsuleVerificationFailure::IntegrityHashMismatch);
        }
        Ok(())
    }

    /// Legacy bool wrapper — returns `true` if capsule passes integrity.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::{
    ///     AttestationSignature, ReplayCapsule, VerifierEconomyRegistry,
    /// };
    ///
    /// let capsule = ReplayCapsule {
    ///     capsule_id: String::new(),
    ///     schema_version: String::new(),
    ///     attestation_id: String::new(),
    ///     verifier_id: String::new(),
    ///     claim_metadata_hash: String::new(),
    ///     issued_at: String::new(),
    ///     expires_at: String::new(),
    ///     input_state_hash: String::new(),
    ///     trace_chunk_hashes: Vec::new(),
    ///     trace_commitment_root: String::new(),
    ///     output_state_hash: String::new(),
    ///     expected_result_hash: String::new(),
    ///     integrity_hash: String::new(),
    ///     signature: AttestationSignature {
    ///         algorithm: String::new(),
    ///         public_key: String::new(),
    ///         value: String::new(),
    ///     },
    /// };
    /// assert!(!VerifierEconomyRegistry::verify_capsule_integrity_bool(&capsule));
    /// ```
    pub fn verify_capsule_integrity_bool(capsule: &ReplayCapsule) -> bool {
        Self::verify_capsule_integrity(capsule).is_ok()
    }

    fn verify_replay_capsule(
        &mut self,
        capsule: &ReplayCapsule,
    ) -> Result<(), CapsuleVerificationFailure> {
        Self::verify_capsule_integrity_with_freshness(capsule, self.replay_capsule_freshness_secs)?;

        let verifier_public_key = match self.verifiers.get(&capsule.verifier_id) {
            Some(verifier) => verifier.public_key.clone(),
            None => return Err(CapsuleVerificationFailure::VerifierNotRegistered),
        };

        let (attestation_verifier_id, expected_claim_metadata_hash) =
            match self.attestations.get(&capsule.attestation_id) {
                Some(attestation) => (
                    attestation.verifier_id.clone(),
                    compute_claim_metadata_hash(
                        &attestation.claim.dimension,
                        &attestation.claim.statement,
                        attestation.claim.score,
                        &attestation.evidence.suite_id,
                    ),
                ),
                None => return Err(CapsuleVerificationFailure::AttestationNotFound),
            };
        if attestation_verifier_id != capsule.verifier_id {
            return Err(CapsuleVerificationFailure::VerifierMismatch);
        }
        if !constant_time::ct_eq(&capsule.claim_metadata_hash, &expected_claim_metadata_hash) {
            return Err(CapsuleVerificationFailure::ClaimMetadataMismatch);
        }

        let signature_payload = replay_capsule_signature_payload(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_chunk_hashes,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
            &capsule.integrity_hash,
        );
        if !self.verify_signature_with_cached_key(
            &capsule.signature,
            &capsule.verifier_id,
            &verifier_public_key,
            &signature_payload,
        ) {
            return Err(CapsuleVerificationFailure::SignatureFailed);
        }
        Ok(())
    }

    // -- Trust scoreboard -----------------------------------------------------

    /// Build the public trust scoreboard.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let scoreboard = VerifierEconomyRegistry::new().build_scoreboard();
    /// assert_eq!(scoreboard.total_verifiers, 0);
    /// assert_eq!(scoreboard.aggregate_score, 0.0);
    /// ```
    pub fn build_scoreboard(&self) -> TrustScoreboard {
        let mut published_stats = BTreeMap::<String, PublishedVerifierStats>::new();
        let mut total_attestations: usize = 0;

        // Single-pass accumulation keeps scoreboard construction O(V + A).
        for attestation in self.attestations.values() {
            if attestation.state != AttestationState::Published {
                continue;
            }
            total_attestations = total_attestations.saturating_add(1);
            let stats = published_stats
                .entry(attestation.verifier_id.clone())
                .or_default();
            stats.attestation_count = stats.attestation_count.saturating_add(1);
            stats.dimensions.insert(attestation.claim.dimension.clone());
        }

        let mut entries = Vec::new();
        let mut aggregate_score_sum = 0.0;
        for verifier in self.verifiers.values() {
            if !verifier.active {
                continue;
            }
            let published = published_stats
                .remove(&verifier.verifier_id)
                .unwrap_or_default();
            aggregate_score_sum += verifier.reputation_score as f64;
            if !aggregate_score_sum.is_finite() {
                aggregate_score_sum = 0.0;
            }
            entries.push(ScoreboardEntry {
                verifier_id: verifier.verifier_id.clone(),
                verifier_name: verifier.name.clone(),
                reputation_score: verifier.reputation_score,
                reputation_tier: verifier.reputation_tier.clone(),
                attestation_count: published.attestation_count,
                dimensions_covered: published.dimensions.into_iter().collect(),
            });
        }
        let total_verifiers = entries.len();
        let mut aggregate_score = if total_verifiers > 0 {
            aggregate_score_sum / total_verifiers as f64
        } else {
            0.0
        };
        if !aggregate_score.is_finite() {
            aggregate_score = 0.0;
        }

        TrustScoreboard {
            entries,
            total_attestations,
            total_verifiers,
            aggregate_score,
        }
    }

    // -- Anti-gaming: selective reporting detection ----------------------------

    /// Check whether a verifier has been selectively reporting.
    /// Returns true if the verifier's dimension coverage is below the threshold.
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let registry = VerifierEconomyRegistry::new();
    /// assert!(registry.check_selective_reporting("ver-0001", 1));
    /// ```
    pub fn check_selective_reporting(&self, verifier_id: &str, min_dimensions: usize) -> bool {
        let dims: std::collections::BTreeSet<_> = self
            .attestations
            .values()
            .filter(|a| a.verifier_id == verifier_id && a.state == AttestationState::Published)
            .map(|a| a.claim.dimension.clone())
            .collect();

        dims.len() < min_dimensions
    }

    /// Reset submission counts (call at window boundaries).
    ///
    /// # Examples
    ///
    /// ```
    /// use frankenengine_node::verifier_economy::VerifierEconomyRegistry;
    ///
    /// let mut registry = VerifierEconomyRegistry::new();
    /// registry.reset_submission_counts();
    /// assert!(registry.events().is_empty());
    /// ```
    pub fn reset_submission_counts(&mut self) {
        self.submission_counts.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn make_registry() -> VerifierEconomyRegistry {
        VerifierEconomyRegistry::new()
    }

    fn test_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn registration_signing_key() -> SigningKey {
        test_signing_key(1)
    }

    fn sample_sha256(label: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(label.as_bytes())))
    }

    fn make_registration() -> VerifierRegistration {
        let signing_key = registration_signing_key();
        VerifierRegistration {
            name: "Acme Verifiers".to_string(),
            contact: "verify@acme.example".to_string(),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            capabilities: vec![
                VerificationDimension::Compatibility,
                VerificationDimension::Security,
            ],
            tier: VerifierTier::Basic,
        }
    }

    fn prefixed_uppercase_public_key(signing_key: &SigningKey) -> String {
        format!(
            "ed25519:{}",
            hex::encode(signing_key.verifying_key().to_bytes()).to_uppercase()
        )
    }

    fn sign_submission(submission: &mut AttestationSubmission, signing_key: &SigningKey) {
        submission.signature.algorithm = "ed25519".to_string();
        submission.signature.public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let payload = attestation_signature_payload(submission);
        let signature = signing_key.sign(&payload);
        submission.signature.value = hex::encode(signature.to_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn make_submission_with(
        verifier_id: &str,
        signing_key: &SigningKey,
        dimension: VerificationDimension,
        statement: &str,
        score: f64,
        suite_id: &str,
        trace_label: &str,
        timestamp: &str,
    ) -> AttestationSubmission {
        let mut submission = AttestationSubmission {
            verifier_id: verifier_id.to_string(),
            claim: AttestationClaim {
                dimension,
                statement: statement.to_string(),
                score,
            },
            evidence: AttestationEvidence {
                suite_id: suite_id.to_string(),
                measurements: vec!["endpoint-coverage: 98%".to_string()],
                execution_trace_hash: sample_sha256(trace_label),
                environment: BTreeMap::from([
                    ("os".to_string(), "linux".to_string()),
                    ("rust".to_string(), "nightly-2026-02-15".to_string()),
                ]),
            },
            signature: AttestationSignature {
                algorithm: String::new(),
                public_key: String::new(),
                value: String::new(),
            },
            timestamp: timestamp.to_string(),
        };
        sign_submission(&mut submission, signing_key);
        submission
    }

    fn make_submission(verifier_id: &str, signing_key: &SigningKey) -> AttestationSubmission {
        make_submission_with(
            verifier_id,
            signing_key,
            VerificationDimension::Compatibility,
            "franken_node API is compatible with v2.0 spec",
            0.95,
            "suite-compat-v1",
            "trace-compat-v1",
            "2026-02-20T12:00:00Z",
        )
    }

    fn sign_capsule(capsule: &mut ReplayCapsule, signing_key: &SigningKey) {
        capsule.signature.algorithm = "ed25519".to_string();
        capsule.signature.public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let payload = replay_capsule_signature_payload(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_chunk_hashes,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
            &capsule.integrity_hash,
        );
        let signature = signing_key.sign(&payload);
        capsule.signature.value = hex::encode(signature.to_bytes());
    }

    fn make_capsule(
        capsule_id: &str,
        verifier_id: &str,
        attestation: &Attestation,
        signing_key: &SigningKey,
        label: &str,
    ) -> ReplayCapsule {
        let input_state_hash = sample_sha256(&format!("{label}:input"));
        let trace_chunk_hashes = vec![
            sample_sha256(&format!("{label}:trace:chunk-0")),
            sample_sha256(&format!("{label}:trace:chunk-1")),
            sample_sha256(&format!("{label}:trace:chunk-2")),
        ];
        let trace_commitment_root = compute_trace_commitment_root(&trace_chunk_hashes)
            .expect("trace chunks should produce a commitment root");
        let output_state_hash = sample_sha256(&format!("{label}:output"));
        let expected_result_hash = sample_sha256(&format!("{label}:expected"));
        let claim_metadata_hash = compute_claim_metadata_hash(
            &attestation.claim.dimension,
            &attestation.claim.statement,
            attestation.claim.score,
            &attestation.evidence.suite_id,
        );
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(3600))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let integrity_hash = compute_capsule_integrity_hash(
            capsule_id,
            REPLAY_CAPSULE_SCHEMA_VERSION,
            &attestation.attestation_id,
            verifier_id,
            &claim_metadata_hash,
            &issued_at,
            &expires_at,
            &input_state_hash,
            &trace_commitment_root,
            &output_state_hash,
            &expected_result_hash,
        );
        let mut capsule = ReplayCapsule {
            capsule_id: capsule_id.to_string(),
            schema_version: REPLAY_CAPSULE_SCHEMA_VERSION.to_string(),
            attestation_id: attestation.attestation_id.clone(),
            verifier_id: verifier_id.to_string(),
            claim_metadata_hash,
            issued_at,
            expires_at,
            input_state_hash,
            trace_chunk_hashes,
            trace_commitment_root,
            output_state_hash,
            expected_result_hash,
            integrity_hash,
            signature: AttestationSignature {
                algorithm: String::new(),
                public_key: String::new(),
                value: String::new(),
            },
        };
        sign_capsule(&mut capsule, signing_key);
        capsule
    }

    fn register_capsule_with_times(
        reg: &mut VerifierEconomyRegistry,
        verifier_id: &str,
        attestation: &Attestation,
        signing_key: &SigningKey,
        capsule_id: &str,
        label: &str,
        issued_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) {
        let mut capsule = make_capsule(capsule_id, verifier_id, attestation, signing_key, label);
        capsule.issued_at = issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, signing_key);
        reg.register_replay_capsule(capsule)
            .expect("capsule should register");
    }

    fn register_and_submit(reg: &mut VerifierEconomyRegistry) -> (Verifier, Attestation) {
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let sub = make_submission(&v.verifier_id, &registration_signing_key());
        let att = reg.submit_attestation(sub).expect("should succeed");
        (v, att)
    }

    fn register_publish_default(reg: &mut VerifierEconomyRegistry) -> (Verifier, Attestation) {
        let (verifier, attestation) = register_and_submit(reg);
        reg.review_attestation(&attestation.attestation_id)
            .expect("review should succeed");
        reg.publish_attestation(&attestation.attestation_id)
            .expect("publish should succeed");
        (verifier, attestation)
    }

    fn file_default_dispute(
        reg: &mut VerifierEconomyRegistry,
        verifier_id: &str,
        attestation_id: &str,
    ) -> Dispute {
        reg.file_dispute(
            attestation_id,
            verifier_id,
            "economic settlement challenge",
            vec!["deterministic-evidence".to_string()],
        )
        .expect("dispute should file")
    }

    #[test]
    fn test_push_bounded_zero_capacity_discards_existing_values() {
        let mut items = vec!["old-event", "older-event"];

        push_bounded(&mut items, "new-event", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_push_bounded_zero_capacity_ignores_new_value() {
        let mut items = Vec::new();

        push_bounded(&mut items, "new-event", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn test_sha256_canonicalization_rejects_short_digest() {
        assert!(canonicalize_sha256_prefixed_hex("sha256:abc123").is_none());
    }

    #[test]
    fn test_sha256_canonicalization_rejects_non_hex_digest() {
        let malformed = format!("sha256:{}", "g".repeat(64));

        assert!(canonicalize_sha256_prefixed_hex(&malformed).is_none());
    }

    #[test]
    fn test_sha256_canonicalization_rejects_duplicate_prefix_payload() {
        let malformed = format!("sha256:{}", sample_sha256("nested-prefix"));

        assert!(canonicalize_sha256_prefixed_hex(&malformed).is_none());
    }

    #[test]
    fn test_sha256_canonicalization_rejects_digest_with_embedded_whitespace() {
        let malformed = format!("sha256:{} {}", "a".repeat(32), "b".repeat(31));

        assert!(canonicalize_sha256_prefixed_hex(&malformed).is_none());
    }

    #[test]
    fn test_public_key_match_rejects_malformed_expected_key() {
        let signing_key = registration_signing_key();
        let actual_key = hex::encode(signing_key.verifying_key().to_bytes());

        assert!(!canonicalized_ed25519_public_keys_match(
            "not-an-ed25519-key",
            &actual_key,
        ));
    }

    #[test]
    fn test_public_key_match_rejects_malformed_actual_key() {
        let signing_key = registration_signing_key();
        let expected_key = hex::encode(signing_key.verifying_key().to_bytes());

        assert!(!canonicalized_ed25519_public_keys_match(
            &expected_key,
            "not-an-ed25519-key",
        ));
    }

    #[test]
    fn test_replay_freshness_rejects_nonpositive_window() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            0,
        ));
        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            -1,
        ));
    }

    #[test]
    fn test_replay_freshness_rejects_inverted_window() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at =
            (now - chrono::Duration::seconds(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            60,
        ));
    }

    #[test]
    fn test_replay_freshness_rejects_malformed_timestamp() {
        let now = chrono::Utc::now();
        let expires_at = (now + chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        assert!(!replay_capsule_freshness_window_valid(
            "not-a-timestamp",
            &expires_at,
            60,
        ));
    }

    // -- Registration tests ---------------------------------------------------

    #[test]
    fn test_register_verifier() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        assert!(v.verifier_id.starts_with("ver-"));
        assert_eq!(v.reputation_score, 0);
        assert_eq!(v.reputation_tier, ReputationTier::Novice);
        assert!(v.active);
    }

    #[test]
    fn test_register_emits_vep005() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration())
            .expect("should succeed");
        let events = reg.events();
        assert!(events.iter().any(|e| e.code == VEP_005));
    }

    #[test]
    fn test_duplicate_public_key_rejected() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration())
            .expect("should succeed");
        let result = reg.register_verifier(make_registration());
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_DUPLICATE_SUBMISSION
        );
    }

    #[test]
    fn test_duplicate_public_key_rejected_under_mixed_encodings() {
        let mut reg = make_registry();
        let signing_key = registration_signing_key();
        let mut canonical = make_registration();
        canonical.public_key = hex::encode(signing_key.verifying_key().to_bytes());
        reg.register_verifier(canonical).unwrap();

        let mut prefixed_uppercase = make_registration();
        prefixed_uppercase.public_key = prefixed_uppercase_public_key(&signing_key);
        let result = reg.register_verifier(prefixed_uppercase);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_DUPLICATE_SUBMISSION
        );
    }

    #[test]
    fn test_register_verifier_fails_when_id_sequence_is_exhausted() {
        let mut reg = make_registry();
        reg.next_verifier_id = u64::MAX;
        reg.verifier_id_exhausted = true;

        let error = reg.register_verifier(make_registration()).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert!(error.message.contains("Verifier ID sequence exhausted"));
    }

    #[test]
    fn test_next_sequential_id_uses_last_value_before_exhausting() {
        let mut counter = u64::MAX;
        let mut exhausted = false;

        let final_id = next_sequential_id(&mut counter, &mut exhausted, "ver", "Verifier")
            .expect("last sequential ID should still be usable");
        assert_eq!(final_id, "ver-18446744073709551615");
        assert!(exhausted);
        assert_eq!(counter, u64::MAX);

        let error = next_sequential_id(&mut counter, &mut exhausted, "ver", "Verifier")
            .expect_err("allocator should fail after the last sequential ID");
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert!(error.message.contains("Verifier ID sequence exhausted"));
    }

    #[test]
    fn test_register_verifier_rejects_malformed_public_key() {
        let mut reg = make_registry();
        let mut registration = make_registration();
        registration.public_key = "ed25519:not-hex".to_string();

        let result = reg.register_verifier(registration);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_INVALID_PUBLIC_KEY
        );
    }

    #[test]
    fn test_verifier_count() {
        let mut reg = make_registry();
        assert_eq!(reg.verifier_count(), 0);
        reg.register_verifier(make_registration())
            .expect("should succeed");
        assert_eq!(reg.verifier_count(), 1);
    }

    #[test]
    fn test_get_verifier() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let found = reg.get_verifier(&v.verifier_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Acme Verifiers");
    }

    #[test]
    fn test_list_verifiers() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration())
            .expect("should succeed");
        assert_eq!(reg.list_verifiers().len(), 1);
    }

    // -- Attestation submission tests -----------------------------------------

    #[test]
    fn test_submit_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        assert!(att.attestation_id.starts_with("att-"));
        assert_eq!(att.state, AttestationState::Submitted);
        assert!(!att.immutable);
    }

    #[test]
    fn test_submit_emits_vep001() {
        let mut reg = make_registry();
        register_and_submit(&mut reg);
        assert!(reg.events().iter().any(|e| e.code == VEP_001));
    }

    #[test]
    fn test_submit_unregistered_verifier_rejected() {
        let mut reg = make_registry();
        let sub = make_submission("ver-9999", &test_signing_key(99));
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_UNREGISTERED_VERIFIER);
    }

    #[test]
    fn test_submit_invalid_signature_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.signature.algorithm = "rsa".to_string(); // Wrong algorithm
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_INVALID_SIGNATURE
        );
    }

    #[test]
    fn test_submit_attestation_accepts_equivalent_public_key_encoding() {
        let mut reg = make_registry();
        let signing_key = registration_signing_key();
        let mut registration = make_registration();
        registration.public_key = prefixed_uppercase_public_key(&signing_key);
        let verifier = reg.register_verifier(registration).unwrap();

        let result = reg.submit_attestation(make_submission(&verifier.verifier_id, &signing_key));
        assert!(result.is_ok());
    }

    #[test]
    fn test_submit_tampered_payload_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.claim.statement.push_str(" but tampered after signing");
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_INVALID_SIGNATURE
        );
    }

    #[test]
    fn test_submit_empty_statement_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.claim.statement = String::new();
        sign_submission(&mut sub, &registration_signing_key());
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_INCOMPLETE_PAYLOAD);
    }

    #[test]
    fn test_submit_empty_suite_id_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.evidence.suite_id = String::new();
        sign_submission(&mut sub, &registration_signing_key());
        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_INCOMPLETE_PAYLOAD);
    }

    #[test]
    fn test_submit_duplicate_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let sub1 = make_submission(&v.verifier_id, &registration_signing_key());
        reg.submit_attestation(sub1).expect("should succeed");
        let sub2 = make_submission(&v.verifier_id, &registration_signing_key());
        let result = reg.submit_attestation(sub2);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_DUPLICATE_SUBMISSION
        );
    }

    #[test]
    fn test_submit_uppercase_execution_trace_hash_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.evidence.execution_trace_hash = sub.evidence.execution_trace_hash.to_uppercase();
        sign_submission(&mut sub, &registration_signing_key());

        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("execution_trace_hash"));
    }

    #[test]
    fn test_submit_prefixless_execution_trace_hash_rejected() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.evidence.execution_trace_hash = sub
            .evidence
            .execution_trace_hash
            .trim_start_matches("sha256:")
            .to_string();
        sign_submission(&mut sub, &registration_signing_key());

        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("execution_trace_hash"));
    }

    #[test]
    fn test_submit_duplicate_cannot_bypass_with_hash_encoding_variant() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        reg.submit_attestation(make_submission(&v.verifier_id, &registration_signing_key()))
            .unwrap();

        let mut sub = make_submission(&v.verifier_id, &registration_signing_key());
        sub.evidence.execution_trace_hash = sub
            .evidence
            .execution_trace_hash
            .trim_start_matches("sha256:")
            .to_string();
        sign_submission(&mut sub, &registration_signing_key());

        let result = reg.submit_attestation(sub);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("execution_trace_hash"));
    }

    #[test]
    fn test_submit_duplicate_rejected_after_publish_state_change() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let sub1 = make_submission(&v.verifier_id, &registration_signing_key());
        let attestation = reg.submit_attestation(sub1).expect("should succeed");
        reg.review_attestation(&attestation.attestation_id)
            .expect("should succeed");
        reg.publish_attestation(&attestation.attestation_id)
            .expect("should succeed");

        let sub2 = make_submission(&v.verifier_id, &registration_signing_key());
        let result = reg.submit_attestation(sub2);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("should fail").code,
            ERR_VEP_DUPLICATE_SUBMISSION
        );
    }

    #[test]
    fn test_submit_attestation_rejects_when_registry_full_of_live_entries() {
        let mut reg = make_registry();
        let verifier = reg
            .register_verifier(make_registration())
            .expect("should succeed");

        for i in 0..MAX_ATTESTATIONS {
            let attestation_id = format!("att-{:04}", i + 1);
            let trace_hash = sample_sha256(&format!("live-attestation-{i}"));
            reg.attestation_fingerprints
                .insert((verifier.verifier_id.clone(), trace_hash.clone()));
            reg.attestations.insert(
                attestation_id.clone(),
                Attestation {
                    attestation_id,
                    verifier_id: verifier.verifier_id.clone(),
                    claim: AttestationClaim {
                        dimension: VerificationDimension::Compatibility,
                        statement: format!("live claim {i}"),
                        score: 0.9,
                    },
                    evidence: AttestationEvidence {
                        suite_id: format!("suite-{i}"),
                        measurements: Vec::new(),
                        execution_trace_hash: trace_hash,
                        environment: BTreeMap::new(),
                    },
                    signature: AttestationSignature {
                        algorithm: "ed25519".to_string(),
                        public_key: verifier.public_key.clone(),
                        value: format!("seed-signature-{i}"),
                    },
                    timestamp: format!("{i}"),
                    immutable: false,
                    state: AttestationState::Submitted,
                },
            );
        }
        reg.next_attestation_id = MAX_ATTESTATIONS as u64 + 1;

        let result = reg.submit_attestation(make_submission(
            &verifier.verifier_id,
            &registration_signing_key(),
        ));

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert_eq!(reg.attestation_count(), MAX_ATTESTATIONS);
        assert!(
            reg.events()
                .last()
                .is_some_and(|event| event.code == VEP_008 && event.detail.contains("capacity"))
        );
    }

    #[test]
    fn test_submit_attestation_fails_when_id_sequence_is_exhausted() {
        let mut reg = make_registry();
        let verifier = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        reg.next_attestation_id = u64::MAX;
        reg.attestation_id_exhausted = true;

        let error = reg
            .submit_attestation(make_submission(
                &verifier.verifier_id,
                &registration_signing_key(),
            ))
            .unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert!(error.message.contains("Attestation ID sequence exhausted"));
    }

    // -- Publishing flow tests (INV-VEP-PUBLISH) ------------------------------

    #[test]
    fn test_publish_flow_submit_review_publish() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);

        let state = reg.review_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::UnderReview);

        let state = reg.publish_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::Published);

        let published = reg.get_attestation(&att.attestation_id).unwrap();
        assert!(published.immutable);
        assert_eq!(published.state, AttestationState::Published);
    }

    #[test]
    fn test_publish_emits_vep002() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_002));
    }

    #[test]
    fn test_cannot_publish_without_review() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        // Skip review — try to publish directly
        let result = reg.publish_attestation(&att.attestation_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_review_already_published() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let result = reg.review_attestation(&att.attestation_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        let state = reg.reject_attestation(&att.attestation_id).unwrap();
        assert_eq!(state, AttestationState::Rejected);
    }

    #[test]
    fn test_reject_emits_vep008() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.reject_attestation(&att.attestation_id).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_008));
    }

    // -- Reputation tests -----------------------------------------------------

    #[test]
    fn test_compute_reputation_deterministic() {
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.7,
            accuracy: 0.9,
            longevity: 0.5,
        };
        let score1 = VerifierEconomyRegistry::compute_reputation(&dims);
        let score2 = VerifierEconomyRegistry::compute_reputation(&dims);
        assert_eq!(score1, score2);
    }

    #[test]
    fn test_compute_reputation_all_ones() {
        let dims = ReputationDimensions {
            consistency: 1.0,
            coverage: 1.0,
            accuracy: 1.0,
            longevity: 1.0,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 100);
    }

    #[test]
    fn test_compute_reputation_all_zeros() {
        let dims = ReputationDimensions {
            consistency: 0.0,
            coverage: 0.0,
            accuracy: 0.0,
            longevity: 0.0,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 0);
    }

    #[test]
    fn test_compute_reputation_mixed() {
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.6,
            accuracy: 0.9,
            longevity: 0.5,
        };
        // 0.35*0.8 + 0.25*0.6 + 0.30*0.9 + 0.10*0.5
        // = 0.28 + 0.15 + 0.27 + 0.05 = 0.75 -> 75
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 75);
    }

    #[test]
    fn test_reputation_incentive_is_monotonic_with_accuracy() {
        let lower_accuracy = ReputationDimensions {
            consistency: 0.7,
            coverage: 0.7,
            accuracy: 0.2,
            longevity: 0.7,
        };
        let higher_accuracy = ReputationDimensions {
            accuracy: 0.9,
            ..lower_accuracy.clone()
        };

        let lower_score = VerifierEconomyRegistry::compute_reputation(&lower_accuracy);
        let higher_score = VerifierEconomyRegistry::compute_reputation(&higher_accuracy);
        assert!(higher_score > lower_score);
    }

    #[test]
    fn test_update_reputation() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let dims = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.6,
            accuracy: 0.9,
            longevity: 0.5,
        };
        let score = reg.update_reputation(&v.verifier_id, &dims).unwrap();
        assert_eq!(score, 75);
        let updated = reg.get_verifier(&v.verifier_id).unwrap();
        assert_eq!(updated.reputation_tier, ReputationTier::Trusted);
    }

    #[test]
    fn test_update_reputation_emits_vep004() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let dims = ReputationDimensions {
            consistency: 0.5,
            coverage: 0.5,
            accuracy: 0.5,
            longevity: 0.5,
        };
        reg.update_reputation(&v.verifier_id, &dims).unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_004));
    }

    // -- Reputation tier tests ------------------------------------------------

    #[test]
    fn test_reputation_tier_novice() {
        assert_eq!(reputation_tier_from_score(0), ReputationTier::Novice);
        assert_eq!(reputation_tier_from_score(24), ReputationTier::Novice);
    }

    #[test]
    fn test_reputation_tier_active() {
        assert_eq!(reputation_tier_from_score(25), ReputationTier::Active);
        assert_eq!(reputation_tier_from_score(49), ReputationTier::Active);
    }

    #[test]
    fn test_reputation_tier_established() {
        assert_eq!(reputation_tier_from_score(50), ReputationTier::Established);
        assert_eq!(reputation_tier_from_score(74), ReputationTier::Established);
    }

    #[test]
    fn test_reputation_tier_trusted() {
        assert_eq!(reputation_tier_from_score(75), ReputationTier::Trusted);
        assert_eq!(reputation_tier_from_score(100), ReputationTier::Trusted);
    }

    // -- Dispute tests --------------------------------------------------------

    #[test]
    fn test_file_dispute() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();

        let dispute = reg
            .file_dispute(
                &att.attestation_id,
                &v.verifier_id,
                "Results inconsistent with reference",
                vec!["evidence-1".to_string()],
            )
            .unwrap();

        assert!(dispute.dispute_id.starts_with("dsp-"));
        assert!(dispute.outcome.is_none());
    }

    #[test]
    fn test_file_dispute_emits_vep003() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        reg.file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_003));
    }

    #[test]
    fn test_cannot_dispute_unpublished() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        let result = reg.file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_dispute_upheld() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let dispute = reg
            .file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
            .unwrap();
        let resolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(resolved.outcome, Some(DisputeOutcome::Upheld));
        assert!(resolved.resolved_at.is_some());
    }

    #[test]
    fn test_resolve_dispute_rejected() {
        let mut reg = make_registry();
        let (v, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        let dispute = reg
            .file_dispute(&att.attestation_id, &v.verifier_id, "Reason", vec![])
            .unwrap();
        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap();
        let resolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(resolved.outcome, Some(DisputeOutcome::Rejected));
    }

    #[test]
    fn test_unresolved_dispute_holds_attestation_bond_out_of_scoreboard() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);

        let initial_scoreboard = reg.build_scoreboard();
        assert_eq!(initial_scoreboard.total_attestations, 1);
        assert_eq!(initial_scoreboard.entries[0].attestation_count, 1);

        file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        let held = reg.get_attestation(&attestation.attestation_id).unwrap();
        assert_eq!(held.state, AttestationState::Disputed);
        let disputed_scoreboard = reg.build_scoreboard();
        assert_eq!(disputed_scoreboard.total_attestations, 0);
        assert_eq!(disputed_scoreboard.entries[0].attestation_count, 0);
    }

    #[test]
    fn test_rejected_dispute_releases_bond_by_republishing_attestation() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap();

        let released = reg.get_attestation(&attestation.attestation_id).unwrap();
        assert_eq!(released.state, AttestationState::Published);
        assert!(released.immutable);
        let scoreboard = reg.build_scoreboard();
        assert_eq!(scoreboard.total_attestations, 1);
        assert_eq!(scoreboard.entries[0].attestation_count, 1);
    }

    #[test]
    fn test_inconclusive_dispute_releases_bond_without_slash() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Inconclusive)
            .unwrap();

        let released = reg.get_attestation(&attestation.attestation_id).unwrap();
        assert_eq!(released.state, AttestationState::Published);
        let resolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(resolved.outcome, Some(DisputeOutcome::Inconclusive));
    }

    #[test]
    fn test_upheld_dispute_slashes_by_rejecting_attestation() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
            .unwrap();

        let slashed = reg.get_attestation(&attestation.attestation_id).unwrap();
        assert_eq!(slashed.state, AttestationState::Rejected);
        let scoreboard = reg.build_scoreboard();
        assert_eq!(scoreboard.total_attestations, 0);
        assert_eq!(scoreboard.entries[0].attestation_count, 0);
    }

    #[test]
    fn test_resolve_dispute_is_single_assignment_for_slashing_determinism() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap();
        let error = reg
            .resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
            .unwrap_err();

        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("already resolved"));
        assert_eq!(
            reg.get_dispute(&dispute.dispute_id).unwrap().outcome,
            Some(DisputeOutcome::Rejected)
        );
        assert_eq!(
            reg.get_attestation(&attestation.attestation_id)
                .unwrap()
                .state,
            AttestationState::Published
        );
    }

    #[test]
    fn test_resolve_dispute_same_outcome_twice_is_rejected() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);

        reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap();
        let error = reg
            .resolve_dispute(&dispute.dispute_id, DisputeOutcome::Rejected)
            .unwrap_err();

        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("already resolved"));
        assert_eq!(
            reg.get_dispute(&dispute.dispute_id).unwrap().outcome,
            Some(DisputeOutcome::Rejected)
        );
        assert_eq!(
            reg.get_attestation(&attestation.attestation_id)
                .unwrap()
                .state,
            AttestationState::Published
        );
    }

    #[test]
    fn test_resolve_dispute_missing_attestation_does_not_settle_outcome() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_publish_default(&mut reg);
        let dispute =
            file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);
        reg.attestations.remove(&attestation.attestation_id);

        let error = reg
            .resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
            .unwrap_err();

        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("Attestation"));
        let unresolved = reg.get_dispute(&dispute.dispute_id).unwrap();
        assert_eq!(unresolved.outcome, None);
        assert_eq!(unresolved.resolved_at, None);
    }

    #[test]
    fn test_resolve_unknown_dispute_does_not_mutate_published_attestation() {
        let mut reg = make_registry();
        let (_verifier, attestation) = register_publish_default(&mut reg);
        let events_before = reg.events().len();

        let error = reg
            .resolve_dispute("dsp-does-not-exist", DisputeOutcome::Upheld)
            .unwrap_err();

        assert_eq!(error.code, ERR_VEP_INCOMPLETE_PAYLOAD);
        assert!(error.message.contains("not found"));
        assert_eq!(
            reg.get_attestation(&attestation.attestation_id)
                .unwrap()
                .state,
            AttestationState::Published
        );
        assert_eq!(reg.events().len(), events_before);
    }

    #[test]
    fn test_slashing_settlement_is_deterministic_across_registries() {
        let settle = || {
            let mut reg = make_registry();
            let (verifier, attestation) = register_publish_default(&mut reg);
            let dispute =
                file_default_dispute(&mut reg, &verifier.verifier_id, &attestation.attestation_id);
            reg.resolve_dispute(&dispute.dispute_id, DisputeOutcome::Upheld)
                .unwrap();
            (
                reg.get_dispute(&dispute.dispute_id)
                    .unwrap()
                    .outcome
                    .clone(),
                reg.get_attestation(&attestation.attestation_id)
                    .unwrap()
                    .state
                    .clone(),
                reg.build_scoreboard().total_attestations,
            )
        };

        assert_eq!(settle(), settle());
    }

    #[test]
    fn test_file_dispute_rejects_when_registry_full_of_unresolved_entries() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        reg.review_attestation(&attestation.attestation_id).unwrap();
        reg.publish_attestation(&attestation.attestation_id)
            .unwrap();

        for i in 0..MAX_DISPUTES {
            let dispute_id = format!("dsp-{:04}", i + 1);
            reg.disputes.insert(
                dispute_id.clone(),
                Dispute {
                    dispute_id,
                    attestation_id: attestation.attestation_id.clone(),
                    filed_by: verifier.verifier_id.clone(),
                    justification: format!("pending dispute {i}"),
                    supporting_evidence: Vec::new(),
                    outcome: None,
                    filed_at: format!("{i}"),
                    resolved_at: None,
                },
            );
        }
        reg.next_dispute_id = MAX_DISPUTES as u64 + 1;

        let result = reg.file_dispute(
            &attestation.attestation_id,
            &verifier.verifier_id,
            "overflow dispute",
            vec![],
        );

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert_eq!(reg.disputes.len(), MAX_DISPUTES);
        assert_eq!(
            reg.get_attestation(&attestation.attestation_id)
                .expect("published attestation should remain present")
                .state,
            AttestationState::Published
        );
    }

    #[test]
    fn test_file_dispute_fails_when_id_sequence_is_exhausted() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        reg.review_attestation(&attestation.attestation_id).unwrap();
        reg.publish_attestation(&attestation.attestation_id)
            .unwrap();
        reg.next_dispute_id = u64::MAX;
        reg.dispute_id_exhausted = true;

        let error = reg
            .file_dispute(
                &attestation.attestation_id,
                &verifier.verifier_id,
                "overflow dispute id",
                vec![],
            )
            .unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPACITY_EXCEEDED);
        assert!(error.message.contains("Dispute ID sequence exhausted"));
    }

    // -- Replay capsule tests -------------------------------------------------

    #[test]
    fn test_register_and_access_capsule() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-001",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-001",
        );
        reg.register_replay_capsule(capsule).unwrap();
        let accessed = reg.access_replay_capsule("cap-001").unwrap();
        assert_eq!(accessed.capsule_id, "cap-001");
    }

    #[test]
    fn test_access_capsule_emits_vep007() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-002",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-002",
        );
        reg.register_replay_capsule(capsule).unwrap();
        reg.access_replay_capsule("cap-002").unwrap();
        assert!(reg.events().iter().any(|e| e.code == VEP_007));
    }

    #[test]
    fn test_register_replay_capsule_evicts_oldest_issued_at_with_capsule_id_tiebreak() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let signing_key = registration_signing_key();
        let base = chrono::Utc::now() - chrono::Duration::minutes(50);

        let register_at =
            |reg: &mut VerifierEconomyRegistry, capsule_id: &str, label: &str, offset_secs: i64| {
                let issued_at = base + chrono::Duration::seconds(offset_secs);
                let expires_at =
                    issued_at + chrono::Duration::seconds(DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS);
                register_capsule_with_times(
                    reg,
                    &verifier.verifier_id,
                    &attestation,
                    &signing_key,
                    capsule_id,
                    label,
                    issued_at,
                    expires_at,
                );
            };

        register_at(&mut reg, "yyy-oldest", "capsule-oldest-y", 0);
        register_at(&mut reg, "zzz-oldest", "capsule-oldest-z", 0);

        for idx in 0..(MAX_REPLAY_CAPSULES - 3) {
            let offset_secs = i64::try_from(idx + 1).expect("capsule offset should fit within i64");
            let capsule_id = format!("mid-{idx:04}");
            let label = format!("capsule-mid-{idx:04}");
            register_at(&mut reg, &capsule_id, &label, offset_secs);
        }

        let newest_offset =
            i64::try_from(MAX_REPLAY_CAPSULES).expect("capsule offset should fit within i64");
        register_at(&mut reg, "aaa-newest", "capsule-newest-a", newest_offset);
        assert_eq!(reg.replay_capsules.len(), MAX_REPLAY_CAPSULES);

        register_at(
            &mut reg,
            "inserted-after-capacity",
            "capsule-inserted-after-capacity",
            newest_offset + 1,
        );

        assert_eq!(reg.replay_capsules.len(), MAX_REPLAY_CAPSULES);
        assert!(!reg.replay_capsules.contains_key("yyy-oldest"));
        assert!(reg.replay_capsules.contains_key("zzz-oldest"));
        assert!(reg.replay_capsules.contains_key("aaa-newest"));
        assert!(reg.replay_capsules.contains_key("inserted-after-capacity"));
    }

    #[test]
    fn test_capsule_integrity_valid() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-003",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-003",
        );
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule).is_ok());
    }

    #[test]
    fn test_capsule_integrity_invalid_empty_hash() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-004",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-004",
        );
        capsule.input_state_hash = String::new();
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule).is_err());
    }

    #[test]
    fn test_register_replay_capsule_rejects_tampered_integrity_hash() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-005",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-005",
        );
        capsule.integrity_hash = sample_sha256("tampered-integrity");
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_INTEGRITY_HASH);
    }

    #[test]
    fn test_capsule_integrity_rejects_tampered_verifier_id() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-006",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-006",
        );
        capsule.verifier_id = "verifier-tampered".to_string();
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule).is_err());
    }

    #[test]
    fn test_capsule_integrity_rejects_invalid_freshness_window() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-007",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-007",
        );
        capsule.expires_at = "2026-03-10T03:30:00Z".to_string();
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule).is_err());
    }

    #[test]
    fn test_capsule_integrity_rejects_zero_length_freshness_window() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-007b",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-007b",
        );
        let shared_timestamp = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.issued_at = shared_timestamp.clone();
        capsule.expires_at = shared_timestamp;
        assert_eq!(
            VerifierEconomyRegistry::verify_capsule_integrity(&capsule),
            Err(CapsuleVerificationFailure::FreshnessWindowInvalid)
        );
    }

    #[test]
    fn test_capsule_integrity_rejects_future_issued_freshness_window() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-007c",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-007c",
        );
        let now = chrono::Utc::now();
        capsule.issued_at =
            (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.expires_at = (now + chrono::Duration::minutes(65))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert_eq!(
            VerifierEconomyRegistry::verify_capsule_integrity(&capsule),
            Err(CapsuleVerificationFailure::FreshnessWindowInvalid)
        );
    }

    #[test]
    fn test_capsule_integrity_rejects_tampered_trace_chunk_hash() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-008",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-008",
        );
        capsule.trace_chunk_hashes[1] = sample_sha256("tampered-trace-chunk");
        assert!(VerifierEconomyRegistry::verify_capsule_integrity(&capsule).is_err());
    }

    #[test]
    fn test_capsule_trace_commitment_proof_roundtrip() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-009",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-009",
        );
        let proof = crate::connector::verifier_sdk::build_trace_commitment_proof(
            &capsule.trace_chunk_hashes,
            1,
        )
        .expect("proof exists");
        assert!(
            crate::connector::verifier_sdk::verify_trace_commitment_proof(
                &capsule.trace_chunk_hashes[1],
                &proof,
                &capsule.trace_commitment_root
            )
        );
        assert!(
            !crate::connector::verifier_sdk::verify_trace_commitment_proof(
                &capsule.trace_chunk_hashes[0],
                &proof,
                &capsule.trace_commitment_root
            )
        );
    }

    #[test]
    fn test_register_replay_capsule_rejects_tampered_signature() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-010",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-010",
        );
        capsule.signature.value = "00".repeat(64);
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_SIGNATURE);
    }

    #[test]
    fn test_register_replay_capsule_accepts_equivalent_public_key_encoding() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-010a",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-010a",
        );
        capsule.signature.public_key = prefixed_uppercase_public_key(&registration_signing_key());

        let result = reg.register_replay_capsule(capsule);
        assert!(result.is_ok());
    }

    #[test]
    fn test_register_replay_capsule_rejects_claim_hash_not_bound_to_attestation() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-011",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-011",
        );
        capsule.claim_metadata_hash = sample_sha256("forged-claim-hash");
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, &registration_signing_key());
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_CLAIM_MISMATCH);
    }

    #[test]
    fn test_register_replay_capsule_rejects_wrong_verifier_key() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-012",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "capsule-012",
        );
        sign_capsule(&mut capsule, &test_signing_key(7));
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_SIGNATURE);
    }

    // -- Scoreboard tests -----------------------------------------------------

    #[test]
    fn test_empty_scoreboard() {
        let reg = make_registry();
        let sb = reg.build_scoreboard();
        assert_eq!(sb.total_verifiers, 0);
        assert_eq!(sb.total_attestations, 0);
        assert_eq!(sb.aggregate_score, 0.0);
    }

    #[test]
    fn test_scoreboard_with_published_attestation() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();

        let sb = reg.build_scoreboard();
        assert_eq!(sb.total_verifiers, 1);
        assert_eq!(sb.total_attestations, 1);
    }

    #[test]
    fn test_scoreboard_ignores_inactive_verifiers_but_preserves_global_published_count() {
        let mut reg = make_registry();
        let signing_key = registration_signing_key();

        let verifier_one = reg.register_verifier(make_registration()).unwrap();
        let mut second_registration = make_registration();
        second_registration.public_key =
            hex::encode(test_signing_key(7).verifying_key().to_bytes());
        second_registration.name = "Dormant Verifier".to_string();
        let verifier_two = reg.register_verifier(second_registration).unwrap();

        let attestation_one = reg
            .submit_attestation(make_submission(&verifier_one.verifier_id, &signing_key))
            .unwrap();
        reg.review_attestation(&attestation_one.attestation_id)
            .unwrap();
        reg.publish_attestation(&attestation_one.attestation_id)
            .unwrap();

        let second_signing_key = test_signing_key(7);
        let attestation_two = reg
            .submit_attestation(make_submission_with(
                &verifier_two.verifier_id,
                &second_signing_key,
                VerificationDimension::Security,
                "Dormant security claim",
                0.84,
                "suite-dormant",
                "trace-dormant",
                "2026-02-20T12:03:00Z",
            ))
            .unwrap();
        reg.review_attestation(&attestation_two.attestation_id)
            .unwrap();
        reg.publish_attestation(&attestation_two.attestation_id)
            .unwrap();
        reg.verifiers
            .get_mut(&verifier_two.verifier_id)
            .unwrap()
            .active = false;

        let scoreboard = reg.build_scoreboard();
        assert_eq!(scoreboard.total_attestations, 2);
        assert_eq!(scoreboard.total_verifiers, 1);
        assert_eq!(scoreboard.entries[0].verifier_id, verifier_one.verifier_id);
    }

    #[test]
    fn test_scoreboard_aggregate_rewards_active_reputation_mean() {
        let mut reg = make_registry();
        let verifier_one = reg.register_verifier(make_registration()).unwrap();
        let mut second_registration = make_registration();
        second_registration.public_key =
            hex::encode(test_signing_key(7).verifying_key().to_bytes());
        second_registration.name = "Second Verifier".to_string();
        let verifier_two = reg.register_verifier(second_registration).unwrap();

        let high_reputation = ReputationDimensions {
            consistency: 0.8,
            coverage: 0.8,
            accuracy: 0.8,
            longevity: 0.8,
        };
        let low_reputation = ReputationDimensions {
            consistency: 0.4,
            coverage: 0.4,
            accuracy: 0.4,
            longevity: 0.4,
        };
        reg.update_reputation(&verifier_one.verifier_id, &high_reputation)
            .unwrap();
        reg.update_reputation(&verifier_two.verifier_id, &low_reputation)
            .unwrap();

        let aggregate = reg.build_scoreboard().aggregate_score;
        assert!((aggregate - 60.0).abs() < f64::EPSILON);

        reg.verifiers
            .get_mut(&verifier_two.verifier_id)
            .unwrap()
            .active = false;
        let active_only = reg.build_scoreboard();
        assert_eq!(active_only.total_verifiers, 1);
        assert!((active_only.aggregate_score - 80.0).abs() < f64::EPSILON);
    }

    // -- Anti-gaming tests ----------------------------------------------------

    #[test]
    fn test_sybil_rate_limiting() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 2;

        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let signing_key = registration_signing_key();

        let sub1 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Compatibility,
            "Claim 1",
            0.9,
            "suite-1",
            "trace-1",
            "2026-02-20T12:00:00Z",
        );
        reg.submit_attestation(sub1).expect("should succeed");

        let sub2 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Security,
            "Claim 2",
            0.85,
            "suite-2",
            "trace-2",
            "2026-02-20T12:01:00Z",
        );
        reg.submit_attestation(sub2).unwrap();

        // Third submission should be rate-limited
        let sub3 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Performance,
            "Claim 3",
            0.80,
            "suite-3",
            "trace-3",
            "2026-02-20T12:02:00Z",
        );
        let result = reg.submit_attestation(sub3);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ERR_VEP_ANTI_GAMING);
    }

    #[test]
    fn test_sybil_rate_limit_emits_vep006() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 0; // Trigger immediately

        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let sub = make_submission(&v.verifier_id, &registration_signing_key());
        let _ = reg.submit_attestation(sub);
        assert!(reg.events().iter().any(|e| e.code == VEP_006));
    }

    #[test]
    fn test_submit_attestation_fails_closed_when_submission_counter_overflows() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = u32::MAX;
        let verifier = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        reg.submission_counts
            .insert(verifier.verifier_id.clone(), u32::MAX);

        let error = reg
            .submit_attestation(make_submission(
                &verifier.verifier_id,
                &registration_signing_key(),
            ))
            .unwrap_err();
        assert_eq!(error.code, ERR_VEP_ANTI_GAMING);
        assert!(error.message.contains("Submission counter exhausted"));
        assert!(reg.events().iter().any(|event| event.code == VEP_006));
    }

    #[test]
    fn test_selective_reporting_check_passes() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let signing_key = registration_signing_key();

        // Submit and publish attestations in two different dimensions
        let sub1 = make_submission(&v.verifier_id, &signing_key);
        let att1 = reg.submit_attestation(sub1).expect("should succeed");
        reg.review_attestation(&att1.attestation_id)
            .expect("should succeed");
        reg.publish_attestation(&att1.attestation_id)
            .expect("should succeed");

        let sub2 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Security,
            "Security claim",
            0.8,
            "suite-sec",
            "trace-unique",
            "2026-02-20T12:01:00Z",
        );
        let att2 = reg.submit_attestation(sub2).expect("should succeed");
        reg.review_attestation(&att2.attestation_id)
            .expect("should succeed");
        reg.publish_attestation(&att2.attestation_id)
            .expect("should succeed");

        // With 2 published dimensions: 2 >= 2, no selective reporting
        assert!(!reg.check_selective_reporting(&v.verifier_id, 2));
        // With 2 published dimensions: 2 < 3, selective reporting detected
        assert!(reg.check_selective_reporting(&v.verifier_id, 3));
    }

    #[test]
    fn test_selective_reporting_ignores_unpublished_attestations() {
        let mut reg = make_registry();
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let signing_key = registration_signing_key();

        // Submit attestation in one dimension and publish it
        let sub1 = make_submission(&v.verifier_id, &signing_key);
        let att1 = reg.submit_attestation(sub1).expect("should succeed");
        reg.review_attestation(&att1.attestation_id)
            .expect("should succeed");
        reg.publish_attestation(&att1.attestation_id)
            .expect("should succeed");

        // Submit attestation in another dimension but leave it in Submitted state
        let sub2 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Security,
            "Security claim unpublished",
            0.8,
            "suite-sec-unp",
            "trace-unp",
            "2026-02-20T12:02:00Z",
        );
        reg.submit_attestation(sub2).unwrap();

        // Submit attestation in third dimension and reject it
        let sub3 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Performance,
            "Performance claim rejected",
            0.7,
            "suite-perf-rej",
            "trace-rej",
            "2026-02-20T12:03:00Z",
        );
        let att3 = reg.submit_attestation(sub3).unwrap();
        reg.review_attestation(&att3.attestation_id).unwrap();
        reg.reject_attestation(&att3.attestation_id).unwrap();

        // Only 1 published dimension — unpublished and rejected don't count
        assert!(!reg.check_selective_reporting(&v.verifier_id, 1));
        assert!(reg.check_selective_reporting(&v.verifier_id, 2));
    }

    #[test]
    fn test_reset_submission_counts() {
        let mut reg = make_registry();
        reg.max_submissions_per_window = 1;
        let v = reg
            .register_verifier(make_registration())
            .expect("should succeed");
        let signing_key = registration_signing_key();
        let sub = make_submission(&v.verifier_id, &signing_key);
        reg.submit_attestation(sub).expect("should succeed");

        // Reset and try again with different trace hash
        reg.reset_submission_counts();

        let sub2 = make_submission_with(
            &v.verifier_id,
            &signing_key,
            VerificationDimension::Security,
            "New claim",
            0.9,
            "suite-new",
            "trace-new",
            "2026-02-20T13:00:00Z",
        );
        assert!(reg.submit_attestation(sub2).is_ok());
    }

    // -- Event tests ----------------------------------------------------------

    #[test]
    fn test_take_events_drains() {
        let mut reg = make_registry();
        reg.register_verifier(make_registration())
            .expect("should succeed");
        let events = reg.take_events();
        assert!(!events.is_empty());
        assert!(reg.events().is_empty());
    }

    // -- Display tests --------------------------------------------------------

    #[test]
    fn test_dimension_display() {
        assert_eq!(
            format!("{}", VerificationDimension::Compatibility),
            "compatibility"
        );
        assert_eq!(format!("{}", VerificationDimension::Security), "security");
        assert_eq!(
            format!("{}", VerificationDimension::Performance),
            "performance"
        );
        assert_eq!(
            format!("{}", VerificationDimension::SupplyChain),
            "supply_chain"
        );
        assert_eq!(
            format!("{}", VerificationDimension::Conformance),
            "conformance"
        );
    }

    #[test]
    fn test_verifier_tier_display() {
        assert_eq!(format!("{}", VerifierTier::Basic), "basic");
        assert_eq!(format!("{}", VerifierTier::Advanced), "advanced");
    }

    #[test]
    fn test_reputation_tier_display() {
        assert_eq!(format!("{}", ReputationTier::Novice), "Novice");
        assert_eq!(format!("{}", ReputationTier::Active), "Active");
        assert_eq!(format!("{}", ReputationTier::Established), "Established");
        assert_eq!(format!("{}", ReputationTier::Trusted), "Trusted");
    }

    #[test]
    fn test_attestation_state_display() {
        assert_eq!(format!("{}", AttestationState::Submitted), "submitted");
        assert_eq!(format!("{}", AttestationState::UnderReview), "under_review");
        assert_eq!(format!("{}", AttestationState::Published), "published");
        assert_eq!(format!("{}", AttestationState::Rejected), "rejected");
        assert_eq!(format!("{}", AttestationState::Disputed), "disputed");
    }

    #[test]
    fn test_dispute_outcome_display() {
        assert_eq!(format!("{}", DisputeOutcome::Upheld), "upheld");
        assert_eq!(format!("{}", DisputeOutcome::Rejected), "rejected");
        assert_eq!(format!("{}", DisputeOutcome::Inconclusive), "inconclusive");
    }

    #[test]
    fn test_vep_error_display() {
        let err = VepError {
            code: ERR_VEP_INVALID_SIGNATURE.to_string(),
            message: "bad sig".to_string(),
        };
        let s = format!("{}", err);
        assert!(s.contains(ERR_VEP_INVALID_SIGNATURE));
        assert!(s.contains("bad sig"));
    }

    // -- Signature verification tests -----------------------------------------

    #[test]
    fn test_verify_signature_valid() {
        let reg = make_registry();
        let signing_key = registration_signing_key();
        let submission = make_submission("ver-0001", &signing_key);
        assert!(reg.verify_signature(
            &submission.signature,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &attestation_signature_payload(&submission),
        ));
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let reg = make_registry();
        let signing_key = registration_signing_key();
        let submission = make_submission("ver-0001", &signing_key);
        assert!(!reg.verify_signature(
            &submission.signature,
            &hex::encode(test_signing_key(2).verifying_key().to_bytes()),
            &attestation_signature_payload(&submission),
        ));
    }

    #[test]
    fn test_verify_signature_wrong_algorithm() {
        let reg = make_registry();
        let signing_key = registration_signing_key();
        let mut submission = make_submission("ver-0001", &signing_key);
        submission.signature.algorithm = "rsa".to_string();
        assert!(!reg.verify_signature(
            &submission.signature,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &attestation_signature_payload(&submission),
        ));
    }

    #[test]
    fn test_verify_signature_empty_value() {
        let reg = make_registry();
        let signing_key = registration_signing_key();
        let mut submission = make_submission("ver-0001", &signing_key);
        submission.signature.value = String::new();
        assert!(!reg.verify_signature(
            &submission.signature,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &attestation_signature_payload(&submission),
        ));
    }

    #[test]
    fn test_verify_signature_rejects_tampered_payload() {
        let reg = make_registry();
        let signing_key = registration_signing_key();
        let mut submission = make_submission("ver-0001", &signing_key);
        let original_signature = submission.signature.clone();
        submission.claim.statement.push_str(" tampered");
        assert!(!reg.verify_signature(
            &original_signature,
            &hex::encode(signing_key.verifying_key().to_bytes()),
            &attestation_signature_payload(&submission),
        ));
    }

    #[test]
    fn test_submit_attestation_populates_and_reuses_verifying_key_cache() {
        let mut reg = make_registry();
        let verifier = reg.register_verifier(make_registration()).unwrap();
        let signing_key = registration_signing_key();

        assert!(reg.parsed_verifier_keys.is_empty());

        reg.submit_attestation(make_submission(&verifier.verifier_id, &signing_key))
            .unwrap();
        assert_eq!(reg.parsed_verifier_keys.len(), 1);
        assert!(reg.parsed_verifier_keys.contains_key(&verifier.verifier_id));

        reg.reset_submission_counts();
        reg.submit_attestation(make_submission_with(
            &verifier.verifier_id,
            &signing_key,
            VerificationDimension::Security,
            "Fresh trace for cache reuse",
            0.88,
            "suite-cache",
            "trace-cache-reuse",
            "2026-02-20T13:00:00Z",
        ))
        .unwrap();
        assert_eq!(reg.parsed_verifier_keys.len(), 1);
    }

    // -- Default trait test ----------------------------------------------------

    #[test]
    fn test_default_registry() {
        let reg = VerifierEconomyRegistry::default();
        assert_eq!(reg.verifier_count(), 0);
        assert_eq!(reg.attestation_count(), 0);
    }

    #[test]
    fn test_registry_uses_configured_replay_capsule_freshness() {
        let config = crate::config::ReplayConfig {
            persist_high_severity: true,
            bundle_version: "v1".to_string(),
            max_replay_capsule_freshness_secs: 30,
            capsule_freshness_secs: None,
            max_submissions_per_window: None,
        };
        let mut reg = VerifierEconomyRegistry::from_replay_config(&config);
        let (verifier, attestation) = register_and_submit(&mut reg);
        let signing_key = registration_signing_key();
        let issued_at = chrono::Utc::now() - chrono::Duration::seconds(20);
        let expires_at = issued_at + chrono::Duration::seconds(31);
        let mut capsule = make_capsule(
            "capsule-over-configured-window",
            &verifier.verifier_id,
            &attestation,
            &signing_key,
            "capsule-over-configured-window",
        );
        capsule.issued_at = issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, &signing_key);
        let err = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(err.code, ERR_VEP_CAPSULE_FRESHNESS);
    }

    #[test]
    fn test_registry_honors_looser_configured_replay_capsule_freshness() {
        let configured_freshness_secs = u64::try_from(DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS + 120)
            .expect("configured freshness should fit within u64");
        let mut reg =
            VerifierEconomyRegistry::with_replay_capsule_freshness_secs(configured_freshness_secs);
        let (verifier, attestation) = register_and_submit(&mut reg);
        let signing_key = registration_signing_key();
        let issued_at = chrono::Utc::now() - chrono::Duration::seconds(20);
        let expires_at =
            issued_at + chrono::Duration::seconds(DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS + 60);
        let mut capsule = make_capsule(
            "capsule-over-default-window",
            &verifier.verifier_id,
            &attestation,
            &signing_key,
            "capsule-over-default-window",
        );
        capsule.issued_at = issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.expires_at = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, &signing_key);

        assert_eq!(
            VerifierEconomyRegistry::verify_capsule_integrity(&capsule),
            Err(CapsuleVerificationFailure::FreshnessWindowInvalid)
        );
        reg.register_replay_capsule(capsule)
            .expect("registry should honor configured freshness window");
    }

    // -- Published attestations filter ----------------------------------------

    #[test]
    fn test_published_attestations_filter() {
        let mut reg = make_registry();
        let (_, att) = register_and_submit(&mut reg);
        assert_eq!(reg.published_attestations().len(), 0);

        reg.review_attestation(&att.attestation_id).unwrap();
        reg.publish_attestation(&att.attestation_id).unwrap();
        assert_eq!(reg.published_attestations().len(), 1);
    }

    // -- Event constant tests -------------------------------------------------

    #[test]
    fn test_event_code_constants() {
        assert_eq!(VEP_001, "VEP-001");
        assert_eq!(VEP_002, "VEP-002");
        assert_eq!(VEP_003, "VEP-003");
        assert_eq!(VEP_004, "VEP-004");
        assert_eq!(VEP_005, "VEP-005");
        assert_eq!(VEP_006, "VEP-006");
        assert_eq!(VEP_007, "VEP-007");
        assert_eq!(VEP_008, "VEP-008");
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_VEP_ATTESTATION, "INV-VEP-ATTESTATION");
        assert_eq!(INV_VEP_SIGNATURE, "INV-VEP-SIGNATURE");
        assert_eq!(INV_VEP_REPUTATION, "INV-VEP-REPUTATION");
        assert_eq!(INV_VEP_PUBLISH, "INV-VEP-PUBLISH");
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ERR_VEP_INVALID_SIGNATURE, "ERR-VEP-INVALID-SIGNATURE");
        assert_eq!(ERR_VEP_INVALID_CAPSULE, "ERR-VEP-INVALID-CAPSULE");
        assert_eq!(ERR_VEP_DUPLICATE_SUBMISSION, "ERR-VEP-DUPLICATE-SUBMISSION");
        assert_eq!(
            ERR_VEP_UNREGISTERED_VERIFIER,
            "ERR-VEP-UNREGISTERED-VERIFIER"
        );
        assert_eq!(ERR_VEP_INCOMPLETE_PAYLOAD, "ERR-VEP-INCOMPLETE-PAYLOAD");
        assert_eq!(ERR_VEP_ANTI_GAMING, "ERR-VEP-ANTI-GAMING");
        assert_eq!(ERR_VEP_CAPACITY_EXCEEDED, "ERR-VEP-CAPACITY-EXCEEDED");
    }

    #[test]
    fn test_capsule_reason_code_constants() {
        assert_eq!(ERR_VEP_CAPSULE_SCHEMA, "ERR-VEP-CAPSULE-SCHEMA");
        assert_eq!(ERR_VEP_CAPSULE_FRESHNESS, "ERR-VEP-CAPSULE-FRESHNESS");
        assert_eq!(
            ERR_VEP_CAPSULE_ATTESTATION_BINDING,
            "ERR-VEP-CAPSULE-ATTESTATION-BINDING"
        );
        assert_eq!(
            ERR_VEP_CAPSULE_TRACE_COMMITMENT,
            "ERR-VEP-CAPSULE-TRACE-COMMITMENT"
        );
        assert_eq!(
            ERR_VEP_CAPSULE_INTEGRITY_HASH,
            "ERR-VEP-CAPSULE-INTEGRITY-HASH"
        );
        assert_eq!(ERR_VEP_CAPSULE_SIGNATURE, "ERR-VEP-CAPSULE-SIGNATURE");
        assert_eq!(
            ERR_VEP_CAPSULE_MISSING_FIELDS,
            "ERR-VEP-CAPSULE-MISSING-FIELDS"
        );
        assert_eq!(ERR_VEP_CAPSULE_HASH_FORMAT, "ERR-VEP-CAPSULE-HASH-FORMAT");
        assert_eq!(
            ERR_VEP_CAPSULE_VERIFIER_MISMATCH,
            "ERR-VEP-CAPSULE-VERIFIER-MISMATCH"
        );
        assert_eq!(
            ERR_VEP_CAPSULE_CLAIM_MISMATCH,
            "ERR-VEP-CAPSULE-CLAIM-MISMATCH"
        );
    }

    // -- bd-1h2w4: Capsule reason code regression tests -----------------------

    #[test]
    fn test_capsule_rejection_missing_capsule_id() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-01",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-01",
        );
        capsule.capsule_id = String::new();
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_MISSING_FIELDS);
        assert!(
            error
                .message
                .contains("reason_code=ERR-VEP-CAPSULE-MISSING-FIELDS")
        );
        assert!(error.message.contains("capsule_id"));
    }

    #[test]
    fn test_capsule_rejection_schema_mismatch() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-02",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-02",
        );
        capsule.schema_version = "wrong-schema-v99".to_string();
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_SCHEMA);
    }

    #[test]
    fn test_capsule_rejection_freshness_expired() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-03",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-03",
        );
        let past = chrono::Utc::now() - chrono::Duration::hours(5);
        capsule.issued_at = past.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        capsule.expires_at =
            (past + chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_FRESHNESS);
    }

    #[test]
    fn test_capsule_rejection_hash_format_invalid() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-04",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-04",
        );
        capsule.input_state_hash = "not-a-valid-hash".to_string();
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_HASH_FORMAT);
        assert!(
            error
                .message
                .contains("reason_code=ERR-VEP-CAPSULE-HASH-FORMAT")
        );
        assert!(error.message.contains("input_state_hash"));
    }

    #[test]
    fn test_capsule_rejection_trace_commitment_mismatch() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-05",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-05",
        );
        capsule.trace_commitment_root = sample_sha256("wrong-trace-root");
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_TRACE_COMMITMENT);
    }

    #[test]
    fn test_capsule_rejection_integrity_hash_mismatch() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-06",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-06",
        );
        capsule.integrity_hash = sample_sha256("wrong-integrity");
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_INTEGRITY_HASH);
    }

    #[test]
    fn test_capsule_rejection_signature_failed() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-07",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-07",
        );
        capsule.signature.value = "00".repeat(64);
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_SIGNATURE);
    }

    #[test]
    fn test_capsule_rejection_claim_metadata_mismatch() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-08",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-08",
        );
        capsule.claim_metadata_hash = sample_sha256("wrong-claim");
        // Recompute integrity so integrity check passes but claim binding fails
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, &registration_signing_key());
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_CLAIM_MISMATCH);
    }

    #[test]
    fn test_capsule_rejection_attestation_not_found() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let mut capsule = make_capsule(
            "cap-rc-09",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-09",
        );
        capsule.attestation_id = "nonexistent-attestation-id".to_string();
        // Recompute integrity with the new attestation_id
        capsule.integrity_hash = compute_capsule_integrity_hash(
            &capsule.capsule_id,
            &capsule.schema_version,
            &capsule.attestation_id,
            &capsule.verifier_id,
            &capsule.claim_metadata_hash,
            &capsule.issued_at,
            &capsule.expires_at,
            &capsule.input_state_hash,
            &capsule.trace_commitment_root,
            &capsule.output_state_hash,
            &capsule.expected_result_hash,
        );
        sign_capsule(&mut capsule, &registration_signing_key());
        let error = reg.register_replay_capsule(capsule).unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_ATTESTATION_BINDING);
    }

    #[test]
    fn test_access_capsule_rejection_freshness_reason_code() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-rc-10",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-10",
        );
        reg.register_replay_capsule(capsule).unwrap();

        {
            let stored = reg.replay_capsules.get_mut("cap-rc-10").unwrap();
            let past = chrono::Utc::now() - chrono::Duration::hours(5);
            stored.issued_at = past.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            stored.expires_at = (past + chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        }

        let error = reg.access_replay_capsule("cap-rc-10").unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_FRESHNESS);
        assert!(
            error
                .message
                .contains("reason_code=ERR-VEP-CAPSULE-FRESHNESS")
        );
    }

    #[test]
    fn test_access_capsule_rejection_attestation_binding_reason_code() {
        let mut reg = make_registry();
        let (verifier, attestation) = register_and_submit(&mut reg);
        let capsule = make_capsule(
            "cap-rc-11",
            &verifier.verifier_id,
            &attestation,
            &registration_signing_key(),
            "reason-11",
        );
        reg.register_replay_capsule(capsule).unwrap();

        {
            let stored = reg.replay_capsules.get_mut("cap-rc-11").unwrap();
            stored.attestation_id = "nonexistent-attestation-id".to_string();
            stored.integrity_hash = compute_capsule_integrity_hash(
                &stored.capsule_id,
                &stored.schema_version,
                &stored.attestation_id,
                &stored.verifier_id,
                &stored.claim_metadata_hash,
                &stored.issued_at,
                &stored.expires_at,
                &stored.input_state_hash,
                &stored.trace_commitment_root,
                &stored.output_state_hash,
                &stored.expected_result_hash,
            );
            sign_capsule(stored, &registration_signing_key());
        }

        let error = reg.access_replay_capsule("cap-rc-11").unwrap_err();
        assert_eq!(error.code, ERR_VEP_CAPSULE_ATTESTATION_BINDING);
        assert!(
            error
                .message
                .contains("reason_code=ERR-VEP-CAPSULE-ATTESTATION-BINDING")
        );
        assert!(error.message.contains("attestation not found"));
    }

    #[test]
    fn test_capsule_verification_failure_display() {
        let f = CapsuleVerificationFailure::SchemaVersionMismatch;
        let s = format!("{f}");
        assert!(s.contains(ERR_VEP_CAPSULE_SCHEMA));
        assert!(s.contains("schema version mismatch"));
    }

    #[test]
    fn test_capsule_verification_failure_codes_deterministic() {
        // Verify every variant maps to a stable code.
        let cases: Vec<(CapsuleVerificationFailure, &str)> = vec![
            (
                CapsuleVerificationFailure::MissingFields("test"),
                ERR_VEP_CAPSULE_MISSING_FIELDS,
            ),
            (
                CapsuleVerificationFailure::SchemaVersionMismatch,
                ERR_VEP_CAPSULE_SCHEMA,
            ),
            (
                CapsuleVerificationFailure::FreshnessWindowInvalid,
                ERR_VEP_CAPSULE_FRESHNESS,
            ),
            (
                CapsuleVerificationFailure::TraceChunkInvalid,
                ERR_VEP_CAPSULE_HASH_FORMAT,
            ),
            (
                CapsuleVerificationFailure::HashFormatInvalid("x"),
                ERR_VEP_CAPSULE_HASH_FORMAT,
            ),
            (
                CapsuleVerificationFailure::TraceCommitmentMismatch,
                ERR_VEP_CAPSULE_TRACE_COMMITMENT,
            ),
            (
                CapsuleVerificationFailure::IntegrityHashMismatch,
                ERR_VEP_CAPSULE_INTEGRITY_HASH,
            ),
            (
                CapsuleVerificationFailure::VerifierNotRegistered,
                ERR_VEP_UNREGISTERED_VERIFIER,
            ),
            (
                CapsuleVerificationFailure::VerifierMismatch,
                ERR_VEP_CAPSULE_VERIFIER_MISMATCH,
            ),
            (
                CapsuleVerificationFailure::ClaimMetadataMismatch,
                ERR_VEP_CAPSULE_CLAIM_MISMATCH,
            ),
            (
                CapsuleVerificationFailure::AttestationNotFound,
                ERR_VEP_CAPSULE_ATTESTATION_BINDING,
            ),
            (
                CapsuleVerificationFailure::SignatureFailed,
                ERR_VEP_CAPSULE_SIGNATURE,
            ),
        ];
        for (failure, expected_code) in cases {
            assert_eq!(failure.code(), expected_code, "mismatch for {failure:?}");
            assert!(!failure.detail().is_empty(), "empty detail for {failure:?}");
        }
    }

    #[test]
    fn test_compute_reputation_nan_returns_zero() {
        let dims = ReputationDimensions {
            consistency: f64::NAN,
            coverage: 0.8,
            accuracy: 0.9,
            longevity: 0.5,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 0);
    }

    #[test]
    fn test_compute_reputation_inf_returns_zero() {
        let dims = ReputationDimensions {
            consistency: f64::INFINITY,
            coverage: 0.8,
            accuracy: 0.9,
            longevity: 0.5,
        };
        assert_eq!(VerifierEconomyRegistry::compute_reputation(&dims), 0);
    }

    #[test]
    fn expired_capsule_rejected_by_freshness_check() {
        // A capsule with a valid 1-hour window but already past its deadline.
        let past = chrono::Utc::now() - chrono::Duration::hours(2);
        let issued_at = past.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at =
            (past + chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        ));
    }

    #[test]
    fn current_capsule_with_future_expiry_accepted_by_freshness_check() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(3600))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        ));
    }

    #[test]
    fn zero_length_capsule_rejected_by_freshness_check() {
        let shared_timestamp = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(!replay_capsule_freshness_window_valid(
            &shared_timestamp,
            &shared_timestamp,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        ));
    }

    #[test]
    fn future_issued_capsule_rejected_by_freshness_check() {
        let now = chrono::Utc::now();
        let issued_at =
            (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::minutes(65))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        ));
    }

    #[test]
    fn overlong_subsecond_capsule_rejected_by_freshness_check() {
        let now = chrono::Utc::now();
        let issued_at = now.to_rfc3339();
        let expires_at = (now
            + chrono::Duration::seconds(DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS)
            + chrono::Duration::milliseconds(1))
        .to_rfc3339();
        assert!(!replay_capsule_freshness_window_valid(
            &issued_at,
            &expires_at,
            DEFAULT_REPLAY_CAPSULE_FRESHNESS_SECS,
        ));
    }
}
