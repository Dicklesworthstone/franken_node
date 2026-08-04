//! Canonical replay bundle serialization and verification helpers.
//!
//! The verifier SDK verifies deterministic bytes, stable hashes, in-bundle
//! artifact integrity, and detached Ed25519 signatures over sealed bundle
//! identity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::SDK_VERSION;

/// Stable schema marker for SDK replay bundles.
pub const REPLAY_BUNDLE_SCHEMA_VERSION: &str = "vsdk-replay-bundle-v1.0";

/// Hash algorithm tag accepted by the verifier SDK bundle surface.
pub const REPLAY_BUNDLE_HASH_ALGORITHM: &str = "sha256";
/// Timeline event type that carries one proof-carrying host-effect receipt.
pub const EFFECT_RECEIPT_EVENT_TYPE: &str = "effect_receipt";
/// Stable schema marker for effect receipts embedded in verifier SDK bundles.
pub const EFFECT_RECEIPT_SCHEMA_VERSION: &str = "effect-receipt-v1.1";
/// Event code emitted when offline effect-chain verification starts.
pub const FN_VSDK_EFFECT_CHAIN_START: &str = "FN-VSDK-EFFECT-CHAIN-START";
/// Event code emitted for each verified effect receipt.
pub const FN_VSDK_EFFECT_VERIFIED: &str = "FN-VSDK-EFFECT-VERIFIED";
/// Event code emitted when offline effect-chain verification succeeds.
pub const FN_VSDK_EFFECT_CHAIN_PASS: &str = "FN-VSDK-EFFECT-CHAIN-PASS";
/// Event code emitted when non-exfiltration verification starts.
pub const FN_VSDK_NON_EXFILTRATION_START: &str = "FN-VSDK-NON-EXFILTRATION-START";
/// Event code emitted for each effect considered by a non-exfiltration proof.
pub const FN_VSDK_NON_EXFILTRATION_EFFECT: &str = "FN-VSDK-NON-EXFILTRATION-EFFECT";
/// Event code emitted when non-exfiltration verification succeeds.
pub const FN_VSDK_NON_EXFILTRATION_PASS: &str = "FN-VSDK-NON-EXFILTRATION-PASS";
/// Stable schema marker for proof-carrying capability grants.
pub const CAPABILITY_PROOF_SCHEMA_VERSION: &str = "capability-proof-v1";
/// Stable schema marker for proof-carrying capability receipts.
pub const CAPABILITY_RECEIPT_SCHEMA_VERSION: &str = "capability-receipt-v1";
/// Event code emitted when capability proof/receipt schema verification starts.
pub const FN_VSDK_CAPABILITY_SCHEMA_START: &str = "FN-VSDK-CAPABILITY-SCHEMA-START";
/// Event code emitted when a capability proof hash and fields verify.
pub const FN_VSDK_CAPABILITY_PROOF_VERIFIED: &str = "FN-VSDK-CAPABILITY-PROOF-VERIFIED";
/// Event code emitted when a capability receipt hash and bindings verify.
pub const FN_VSDK_CAPABILITY_RECEIPT_VERIFIED: &str = "FN-VSDK-CAPABILITY-RECEIPT-VERIFIED";
/// Event code emitted when capability proof/receipt schema verification succeeds.
pub const FN_VSDK_CAPABILITY_SCHEMA_PASS: &str = "FN-VSDK-CAPABILITY-SCHEMA-PASS";

const HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:canonical-hash:v1:";
const SIGNATURE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:structural-signature:v1:";
const ED25519_BUNDLE_SIGNATURE_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:ed25519-bundle-signature:v1:";
const CAS_HASH_DOMAIN: &[u8] = b"storage_cas_content_hash_v1:";
const EFFECT_RECEIPT_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_canonical_v1:";
const EFFECT_RECEIPT_CHAIN_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_chain_v1:";
const NON_EXFILTRATION_CLAIM_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:non-exfiltration-claim:v1:";
const CAPABILITY_PROOF_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:capability-proof:v1:";
const CAPABILITY_RECEIPT_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:capability-receipt:v1:";
const CONTENT_HASH_PREFIX: &str = "sha256:";
const EFFECT_RECEIPT_CHAIN_GENESIS: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A deterministic replay bundle that external verifiers can serialize, hash,
/// and verify without depending on privileged product internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub header: BundleHeader,
    pub schema_version: String,
    pub sdk_version: String,
    pub bundle_id: String,
    pub incident_id: String,
    pub created_at: String,
    pub policy_version: String,
    pub verifier_identity: String,
    pub timeline: Vec<TimelineEvent>,
    pub initial_state_snapshot: Value,
    pub evidence_refs: Vec<String>,
    pub artifacts: BTreeMap<String, BundleArtifact>,
    pub chunks: Vec<BundleChunk>,
    pub metadata: BTreeMap<String, String>,
    pub integrity_hash: String,
    pub signature: BundleSignature,
}

/// Versioned replay bundle header checked before payload integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleHeader {
    pub hash_algorithm: String,
    pub payload_length_bytes: u64,
    pub chunk_count: u32,
}

/// A single event in replay order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub sequence_number: u64,
    pub event_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub payload: Value,
    pub state_snapshot: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_parent: Option<u64>,
    pub policy_version: String,
}

/// Manifest entry describing one payload chunk in deterministic order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleChunk {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub artifact_path: String,
    pub payload_length_bytes: u64,
    pub payload_digest: String,
}

/// Opaque bundle artifact bytes plus their SDK hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleArtifact {
    pub media_type: String,
    pub digest: String,
    pub bytes_hex: String,
}

/// Structural signature over a sealed bundle's integrity hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct BundleSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

/// Class of host effect described by an embedded proof-carrying receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FsRead,
    FsWrite,
    NetConnect,
    HttpRequest,
    Spawn,
    ModuleResolve,
}

impl EffectKind {
    const fn tag(self) -> u8 {
        match self {
            Self::FsRead => 1,
            Self::FsWrite => 2,
            Self::NetConnect => 3,
            Self::HttpRequest => 4,
            Self::Spawn => 5,
            Self::ModuleResolve => 6,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetConnect => "net_connect",
            Self::HttpRequest => "http_request",
            Self::Spawn => "spawn",
            Self::ModuleResolve => "module_resolve",
        }
    }
}

/// Pre-execution policy decision bound into an effect receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EffectPolicyOutcome {
    Allowed { capability_ref: String },
    Denied { reason: String },
}

impl EffectPolicyOutcome {
    const fn tag(&self) -> u8 {
        match self {
            Self::Allowed { .. } => 1,
            Self::Denied { .. } => 2,
        }
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::Allowed { .. } => "allowed",
            Self::Denied { .. } => "denied",
        }
    }

    fn capability_ref(&self) -> Option<&str> {
        match self {
            Self::Allowed { capability_ref } => Some(capability_ref),
            Self::Denied { .. } => None,
        }
    }
}

/// Information-flow verdict bound into an effect receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowPolicyVerdict {
    LabelClean,
    Declassified,
    Blocked,
}

impl FlowPolicyVerdict {
    const fn tag(self) -> u8 {
        match self {
            Self::LabelClean => 1,
            Self::Declassified => 2,
            Self::Blocked => 3,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::LabelClean => "label_clean",
            Self::Declassified => "declassified",
            Self::Blocked => "blocked",
        }
    }
}

/// Effect receipt wire shape accepted by offline SDK verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceipt {
    pub schema_version: String,
    pub seq: u64,
    pub trace_id: String,
    pub effect_kind: EffectKind,
    pub policy_outcome: EffectPolicyOutcome,
    pub pre_state_hash: String,
    pub args_hash: String,
    pub result_hash: Option<String>,
    pub post_state_hash: Option<String>,
    pub input_lineage_hash: String,
    pub output_lineage_hash: Option<String>,
    pub label_set_commitment: String,
    pub declassification_ref: Option<String>,
    pub flow_policy_verdict: FlowPolicyVerdict,
    pub recorded_at_millis: u64,
}

/// One append-only effect receipt chain entry embedded in a replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptChainEntry {
    pub index: u64,
    pub prev_chain_hash: String,
    pub receipt_hash: String,
    pub chain_hash: String,
    pub receipt: EffectReceipt,
}

/// One receipt field proven against a CAS byte artifact in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCasBinding {
    pub field: String,
    pub hash: String,
    pub artifact_path: String,
    pub byte_length: u64,
}

/// Effect receipt summary after offline chain and CAS-byte verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEffect {
    pub index: u64,
    pub seq: u64,
    pub trace_id: String,
    pub effect_kind: String,
    pub outcome: String,
    pub capability_ref: Option<String>,
    pub result_hash: Option<String>,
    pub input_lineage_hash: String,
    pub output_lineage_hash: Option<String>,
    pub label_set_commitment: String,
    pub declassification_ref: Option<String>,
    pub flow_policy_verdict: String,
    pub cas_bindings: Vec<VerifiedCasBinding>,
}

/// Offline verification report for an effect-chain-bearing replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectChainVerification {
    pub bundle_id: String,
    pub verifier_identity: String,
    pub effect_count: usize,
    pub head_chain_hash: String,
    pub verified_effects: Vec<VerifiedEffect>,
    pub event_codes: Vec<String>,
}

/// Selective-disclosure non-exfiltration claim checked over a verified effect chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonExfiltrationClaim {
    /// Sensitive label-set commitments disclosed to this verifier.
    pub forbidden_label_set_commitments: Vec<String>,
    /// Host-effect kinds considered external sinks for this claim.
    pub external_sink_effect_kinds: Vec<String>,
    /// Scoped declassification receipts accepted by this verifier.
    pub allowed_declassification_refs: Vec<String>,
}

/// One selectively disclosed effect proof in a non-exfiltration verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonExfiltrationEffectProof {
    pub index: u64,
    pub effect_kind: String,
    pub disclosed_label_set_commitment: Option<String>,
    pub flow_policy_verdict: String,
    pub declassification_ref: Option<String>,
    pub proof_outcome: String,
}

/// SDK proof that forbidden labels did not reach the disclosed sink set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonExfiltrationVerification {
    pub bundle_id: String,
    pub verifier_identity: String,
    pub effect_count: usize,
    pub head_chain_hash: String,
    pub claim_hash: String,
    pub claim: NonExfiltrationClaim,
    pub examined_effects: Vec<NonExfiltrationEffectProof>,
    pub event_codes: Vec<String>,
}

/// Runtime policy profile under which a capability proof was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPolicyProfile {
    Strict,
    Balanced,
    LegacyRisky,
}

impl CapabilityPolicyProfile {
    const fn label(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy_risky",
        }
    }
}

/// Revocation status evidence bound into a capability proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityRevocationFreshness {
    Fresh {
        checked_at_millis: u64,
        evidence_ref: String,
    },
    Stale {
        last_checked_at_millis: u64,
        evidence_ref: String,
    },
    Revoked {
        revoked_at_millis: u64,
        revocation_ref: String,
    },
}

/// A single scope allowed by a proof-carrying capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityScope {
    pub capability: String,
    pub resource: String,
    pub access: String,
}

/// A canonical postcondition hash expected or observed for a capability use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPostcondition {
    pub field: String,
    pub expected_hash: String,
}

/// Proof-carrying capability grant independently checkable by the SDK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityProof {
    pub schema_version: String,
    pub proof_id: String,
    pub actor: String,
    pub audience: String,
    pub scopes: Vec<CapabilityScope>,
    pub policy_profile: CapabilityPolicyProfile,
    pub revocation_freshness: CapabilityRevocationFreshness,
    pub epoch: u64,
    pub side_effect_kind: EffectKind,
    pub evidence_refs: Vec<String>,
    pub expected_postconditions: Vec<CapabilityPostcondition>,
    pub issued_at_millis: u64,
    pub expires_at_millis: u64,
    pub proof_hash: String,
}

/// Runtime receipt proving a capability use matched the issued proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub proof_id: String,
    pub proof_hash: String,
    pub actor: String,
    pub audience: String,
    pub exercised_scope: CapabilityScope,
    pub policy_profile: CapabilityPolicyProfile,
    pub epoch: u64,
    pub side_effect_kind: EffectKind,
    pub effect_receipt_chain_hash: String,
    pub observed_postconditions: Vec<CapabilityPostcondition>,
    pub recorded_at_millis: u64,
    pub receipt_hash: String,
}

/// Verified binding between a capability proof and a capability-use receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReceiptVerification {
    pub proof_id: String,
    pub receipt_id: String,
    pub actor: String,
    pub audience: String,
    pub scope: CapabilityScope,
    pub policy_profile: String,
    pub epoch: u64,
    pub side_effect_kind: String,
    pub proof_hash: String,
    pub receipt_hash: String,
    pub effect_receipt_chain_hash: String,
    pub postcondition_count: usize,
    pub evidence_ref_count: usize,
    pub event_codes: Vec<String>,
}

/// Errors returned by replay bundle serialization and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Json(String),
    UnsupportedSchema {
        expected: String,
        actual: String,
    },
    UnsupportedSdk {
        expected: String,
        actual: String,
    },
    UnsupportedHashAlgorithm {
        expected: String,
        actual: String,
    },
    MissingField {
        field: &'static str,
    },
    EmptyTimeline,
    EmptyArtifacts,
    EmptyChunks,
    NonCanonicalEncoding,
    NonDeterministicFloat {
        path: String,
    },
    PayloadLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ChunkCountMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkIndexMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkArtifactMissing {
        path: String,
    },
    InvalidArtifactPath {
        path: String,
    },
    NonCanonicalField {
        field: &'static str,
        actual: String,
    },
    ChunkPayloadLengthMismatch {
        artifact_path: String,
        expected: u64,
        actual: u64,
    },
    ChunkDigestMismatch {
        artifact_path: String,
        expected: String,
        actual: String,
    },
    InvalidTimestamp {
        field: &'static str,
        actual: String,
    },
    NonMonotonicTimestamp {
        previous: String,
        current: String,
        event_id: String,
    },
    InvalidArtifactHex {
        path: String,
        source: String,
    },
    ArtifactDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    IntegrityMismatch {
        expected: String,
        actual: String,
    },
    SignatureMismatch {
        expected: String,
        actual: String,
    },
    InvalidVerifierIdentity {
        actual: String,
    },
    EventPolicyVersionMismatch {
        bundle_policy_version: String,
        event_id: String,
        event_policy_version: String,
    },
    Ed25519SignatureMalformed {
        length: usize,
    },
    Ed25519SignatureInvalid,
    EmptyEffectChain,
    InvalidEffectReceiptPayload {
        event_id: String,
        source: String,
    },
    UnsupportedEffectReceiptSchema {
        index: u64,
        expected: String,
        actual: String,
    },
    MalformedEffectContentHash {
        index: u64,
        field: &'static str,
        value: String,
    },
    MalformedEffectLineageHash {
        index: u64,
        field: &'static str,
        value: String,
    },
    EffectReceiptLineagePolicy {
        index: u64,
        detail: String,
    },
    EffectReceiptAllowedMissingHash {
        index: u64,
        field: &'static str,
    },
    EffectReceiptDeniedHasHash {
        index: u64,
        field: &'static str,
    },
    EffectReceiptMissingCasBytes {
        index: u64,
        field: &'static str,
        hash: String,
    },
    EffectChainIntegrity {
        index: u64,
        detail: String,
    },
    EmptyNonExfiltrationClaim {
        field: &'static str,
    },
    MalformedNonExfiltrationLabelCommitment {
        value: String,
    },
    InvalidNonExfiltrationClaimValue {
        field: &'static str,
        value: String,
    },
    NonExfiltrationViolation {
        index: u64,
        effect_kind: String,
        label_set_commitment: String,
        detail: String,
    },
    UnsupportedCapabilityProofSchema {
        expected: String,
        actual: String,
    },
    UnsupportedCapabilityReceiptSchema {
        expected: String,
        actual: String,
    },
    InvalidCapabilityField {
        field: &'static str,
        reason: String,
    },
    MalformedCapabilityHash {
        field: &'static str,
        value: String,
    },
    CapabilityReceiptMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => write!(formatter, "replay bundle JSON error: {message}"),
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "replay bundle schema mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedSdk { expected, actual } => write!(
                formatter,
                "replay bundle SDK mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedHashAlgorithm { expected, actual } => write!(
                formatter,
                "replay bundle hash algorithm mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingField { field } => {
                write!(formatter, "replay bundle field is empty: {field}")
            }
            Self::EmptyTimeline => write!(formatter, "replay bundle timeline is empty"),
            Self::EmptyArtifacts => write!(formatter, "replay bundle artifacts are empty"),
            Self::EmptyChunks => write!(formatter, "replay bundle chunks are empty"),
            Self::NonCanonicalEncoding => {
                write!(formatter, "replay bundle bytes are not canonical")
            }
            Self::NonDeterministicFloat { path } => {
                write!(
                    formatter,
                    "replay bundle contains non-deterministic float at {path}"
                )
            }
            Self::PayloadLengthMismatch { expected, actual } => write!(
                formatter,
                "replay bundle payload length mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkCountMismatch { expected, actual } => write!(
                formatter,
                "replay bundle chunk count mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkIndexMismatch { expected, actual } => write!(
                formatter,
                "replay bundle chunk index mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkArtifactMissing { path } => {
                write!(
                    formatter,
                    "replay bundle chunk references missing artifact {path}"
                )
            }
            Self::InvalidArtifactPath { path } => {
                write!(formatter, "replay bundle artifact path is invalid: {path}")
            }
            Self::NonCanonicalField { field, actual: _ } => write!(
                formatter,
                "replay bundle field {field} must not contain surrounding whitespace"
            ),
            Self::ChunkPayloadLengthMismatch {
                artifact_path,
                expected,
                actual,
            } => write!(
                formatter,
                "replay bundle chunk {artifact_path} payload length mismatch: expected {expected}, got {actual}"
            ),
            Self::ChunkDigestMismatch {
                artifact_path,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle chunk {artifact_path} digest mismatch (expected and actual digests redacted)"
            ),
            Self::InvalidTimestamp { field, actual: _ } => {
                write!(formatter, "replay bundle field {field} must be RFC3339")
            }
            Self::NonMonotonicTimestamp {
                previous,
                current,
                event_id,
            } => write!(
                formatter,
                "replay bundle timestamp for {event_id} is non-monotonic: previous {previous}, current {current}"
            ),
            Self::InvalidArtifactHex { path, source } => {
                write!(
                    formatter,
                    "replay bundle artifact {path} has invalid hex: {source}"
                )
            }
            Self::ArtifactDigestMismatch {
                path,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle artifact {path} digest mismatch (expected and actual digests redacted)"
            ),
            Self::IntegrityMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle integrity mismatch (expected and actual digests redacted)"
            ),
            Self::SignatureMismatch {
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "replay bundle signature mismatch (expected and actual signatures redacted)"
            ),
            Self::InvalidVerifierIdentity { actual: _ } => write!(
                formatter,
                "replay bundle verifier identity must use external verifier:// scheme with non-empty name"
            ),
            Self::EventPolicyVersionMismatch {
                bundle_policy_version,
                event_id,
                event_policy_version,
            } => write!(
                formatter,
                "replay bundle event {event_id} policy_version mismatch: bundle={bundle_policy_version}, event={event_policy_version}"
            ),
            Self::Ed25519SignatureMalformed { length } => write!(
                formatter,
                "replay bundle Ed25519 signature has invalid length {length}"
            ),
            Self::Ed25519SignatureInvalid => {
                write!(
                    formatter,
                    "replay bundle Ed25519 signature verification failed"
                )
            }
            Self::EmptyEffectChain => {
                write!(formatter, "replay bundle carries no effect_receipt events")
            }
            Self::InvalidEffectReceiptPayload { event_id, source } => write!(
                formatter,
                "replay bundle effect receipt payload for {event_id} is invalid: {source}"
            ),
            Self::UnsupportedEffectReceiptSchema {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "effect receipt {index} schema mismatch: expected {expected}, got {actual}"
            ),
            Self::MalformedEffectContentHash {
                index,
                field,
                value: _,
            } => write!(
                formatter,
                "effect receipt {index} field {field} is not a canonical sha256:<hex> content hash"
            ),
            Self::MalformedEffectLineageHash {
                index,
                field,
                value: _,
            } => write!(
                formatter,
                "effect receipt {index} lineage field {field} is not a canonical sha256:<hex> hash"
            ),
            Self::EffectReceiptLineagePolicy { index, detail } => write!(
                formatter,
                "effect receipt {index} lineage policy invalid: {detail}"
            ),
            Self::EffectReceiptAllowedMissingHash { index, field } => write!(
                formatter,
                "allowed effect receipt {index} is missing {field}"
            ),
            Self::EffectReceiptDeniedHasHash { index, field } => write!(
                formatter,
                "denied effect receipt {index} must not carry {field}"
            ),
            Self::EffectReceiptMissingCasBytes {
                index,
                field,
                hash: _,
            } => write!(
                formatter,
                "effect receipt {index} field {field} references CAS bytes not bundled"
            ),
            Self::EffectChainIntegrity { index, detail } => write!(
                formatter,
                "effect receipt chain integrity violation at index {index}: {detail}"
            ),
            Self::EmptyNonExfiltrationClaim { field } => {
                write!(formatter, "non-exfiltration claim field is empty: {field}")
            }
            Self::MalformedNonExfiltrationLabelCommitment { value: _ } => write!(
                formatter,
                "non-exfiltration claim label commitment must be canonical sha256:<hex>"
            ),
            Self::InvalidNonExfiltrationClaimValue { field, value: _ } => write!(
                formatter,
                "non-exfiltration claim field {field} contains a non-canonical value"
            ),
            Self::NonExfiltrationViolation {
                index,
                effect_kind,
                label_set_commitment: _,
                detail,
            } => write!(
                formatter,
                "non-exfiltration violation at effect {index} ({effect_kind}): {detail}"
            ),
            Self::UnsupportedCapabilityProofSchema { expected, actual } => write!(
                formatter,
                "capability proof schema mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedCapabilityReceiptSchema { expected, actual } => write!(
                formatter,
                "capability receipt schema mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidCapabilityField { field, reason } => write!(
                formatter,
                "capability proof/receipt field {field} is invalid: {reason}"
            ),
            Self::MalformedCapabilityHash { field, value: _ } => write!(
                formatter,
                "capability proof/receipt field {field} is not a canonical sha256:<hex> hash"
            ),
            Self::CapabilityReceiptMismatch {
                field,
                expected: _,
                actual: _,
            } => write!(
                formatter,
                "capability receipt field {field} does not match the bound proof"
            ),
        }
    }
}

impl std::error::Error for BundleError {}

/// Standard result type returned by replay bundle helpers.
pub type BundleResult<T> = Result<T, BundleError>;

#[derive(Serialize)]
struct ReplayBundleIntegrityView<'a> {
    header: &'a BundleHeader,
    schema_version: &'a str,
    sdk_version: &'a str,
    bundle_id: &'a str,
    incident_id: &'a str,
    created_at: &'a str,
    policy_version: &'a str,
    verifier_identity: &'a str,
    timeline: &'a [TimelineEvent],
    initial_state_snapshot: &'a Value,
    evidence_refs: &'a [String],
    artifacts: &'a BTreeMap<String, BundleArtifact>,
    chunks: &'a [BundleChunk],
    metadata: &'a BTreeMap<String, String>,
}

/// Serialize a replay bundle to canonical JSON bytes.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bytes = bundle::serialize(&sealed_bundle)?;
/// ```
pub fn serialize(bundle: &ReplayBundle) -> BundleResult<Vec<u8>> {
    canonical_bytes(bundle)
}

/// Deserialize replay bundle bytes without performing integrity verification.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bundle = bundle::deserialize(&canonical_bytes)?;
/// ```
pub fn deserialize(bytes: &[u8]) -> BundleResult<ReplayBundle> {
    serde_json::from_slice(bytes).map_err(|source| BundleError::Json(source.to_string()))
}

/// Compute the SDK's domain-separated SHA-256 hash for canonical bytes.
///
/// # Examples
///
/// ```rust
/// use frankenengine_verifier_sdk::bundle;
///
/// let digest = bundle::hash(b"payload");
/// assert_eq!(digest.len(), 64);
/// ```
#[must_use]
pub fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute the integrity hash over all replay bundle fields except
/// `integrity_hash`.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let digest = bundle::integrity_hash(&bundle)?;
/// ```
pub fn integrity_hash(bundle: &ReplayBundle) -> BundleResult<String> {
    let view = ReplayBundleIntegrityView {
        header: &bundle.header,
        schema_version: &bundle.schema_version,
        sdk_version: &bundle.sdk_version,
        bundle_id: &bundle.bundle_id,
        incident_id: &bundle.incident_id,
        created_at: &bundle.created_at,
        policy_version: &bundle.policy_version,
        verifier_identity: &bundle.verifier_identity,
        timeline: &bundle.timeline,
        initial_state_snapshot: &bundle.initial_state_snapshot,
        evidence_refs: &bundle.evidence_refs,
        artifacts: &bundle.artifacts,
        chunks: &bundle.chunks,
        metadata: &bundle.metadata,
    };
    Ok(hash(&canonical_bytes(&view)?))
}

/// Populate `integrity_hash` from the current replay bundle contents.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// bundle::seal(&mut bundle)?;
/// ```
pub fn seal(bundle: &mut ReplayBundle) -> BundleResult<()> {
    bundle.integrity_hash = integrity_hash(bundle)?;
    bundle.signature = BundleSignature {
        algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
        signature_hex: compute_signature_hex(&bundle.integrity_hash),
    };
    Ok(())
}

/// Sign a sealed replay bundle with Ed25519.
///
/// The signature preimage is domain-separated and binds the public bundle
/// schema, SDK version, bundle id, incident id, creation timestamp, and
/// structural `integrity_hash`. Callers should `seal` the bundle before
/// signing; `verify_signed_bundle` enforces that structural seal before
/// checking the detached Ed25519 signature.
///
/// # Examples
///
/// ```rust,ignore
/// use ed25519_dalek::SigningKey;
/// use frankenengine_verifier_sdk::bundle;
///
/// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
/// let signature = bundle::sign_bundle(&signing_key, &sealed_bundle);
/// ```
#[must_use]
pub fn sign_bundle(signing_key: &SigningKey, bundle: &ReplayBundle) -> Signature {
    signing_key.sign(&ed25519_bundle_signature_payload(bundle))
}

/// Verify a detached Ed25519 signature over caller-supplied bytes.
///
/// This is intentionally payload-agnostic so downstream verifiers can check
/// registry entries and other public signed artifacts without depending on
/// privileged `franken-node` internals.
///
/// # Examples
///
/// ```rust
/// use ed25519_dalek::{Signer, SigningKey};
/// use frankenengine_verifier_sdk::bundle;
///
/// let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
/// let payload = b"registry-entry";
/// let signature = signing_key.sign(payload);
/// bundle::verify_ed25519_signature(
///     &signing_key.verifying_key(),
///     payload,
///     &signature.to_bytes(),
/// )?;
/// # Ok::<(), frankenengine_verifier_sdk::bundle::BundleError>(())
/// ```
pub fn verify_ed25519_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_bytes: &[u8],
) -> BundleResult<()> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| {
        BundleError::Ed25519SignatureMalformed {
            length: signature_bytes.len(),
        }
    })?;
    verifying_key
        .verify_strict(payload, &signature)
        .map_err(|_| BundleError::Ed25519SignatureInvalid)
}

/// Verify a detached Ed25519 signature over a sealed replay bundle.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// bundle::verify_signed_bundle(&verifying_key, &sealed_bundle, &signature_bytes)?;
/// ```
pub fn verify_signed_bundle(
    verifying_key: &VerifyingKey,
    bundle: &ReplayBundle,
    signature_bytes: &[u8],
) -> BundleResult<()> {
    let canonical = serialize(bundle)?;
    verify(&canonical)?;
    verify_ed25519_signature(
        verifying_key,
        &ed25519_bundle_signature_payload(bundle),
        signature_bytes,
    )
}

/// Verify canonical encoding, schema, artifact hashes, and bundle integrity.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::bundle;
///
/// let bundle = bundle::verify(&canonical_bytes)?;
/// ```
pub fn verify(bytes: &[u8]) -> BundleResult<ReplayBundle> {
    let bundle = deserialize(bytes)?;
    let canonical = serialize(&bundle)?;
    if canonical != bytes {
        return Err(BundleError::NonCanonicalEncoding);
    }
    validate_structure(&bundle)?;
    validate_artifacts(&bundle)?;
    validate_header(&bundle)?;
    validate_chunks(&bundle)?;
    let actual = integrity_hash(&bundle)?;
    if !constant_time_eq(&bundle.integrity_hash, &actual) {
        return Err(BundleError::IntegrityMismatch {
            expected: bundle.integrity_hash,
            actual,
        });
    }
    validate_signature(&bundle)?;
    Ok(bundle)
}

/// Verify a replay bundle and then independently verify its embedded
/// proof-carrying effect receipt chain against bundled CAS bytes.
///
/// The SDK recomputes each receipt hash, chain hash, and referenced CAS content
/// hash without consulting privileged runtime internals. Structural bundle
/// verification runs first, so unsupported bundle schema/sdk versions and
/// non-canonical bytes fail closed before effect-chain parsing.
pub fn verify_effect_chain(bytes: &[u8]) -> BundleResult<EffectChainVerification> {
    let bundle = verify(bytes)?;
    verify_effect_chain_in_bundle(&bundle)
}

/// Verify effect receipt chain events in an already structurally verified
/// replay bundle.
pub fn verify_effect_chain_in_bundle(
    bundle: &ReplayBundle,
) -> BundleResult<EffectChainVerification> {
    let cas_lookup = cas_artifact_lookup(bundle)?;
    let entries = effect_chain_entries(bundle)?;
    verify_effect_chain_core(
        &entries,
        Some(&cas_lookup),
        bundle.bundle_id.clone(),
        bundle.verifier_identity.clone(),
    )
}

/// Re-derive and verify a bare effect-receipt chain offline from its entries
/// alone — the surface a `franken-node run --json` host-effect ledger is verified
/// against, with no surrounding replay bundle. This proves every entry's index,
/// prev/chain-hash linkage, and receipt-hash integrity (the tamper-evident
/// chain) and fails closed on any mismatch.
///
/// CAS byte-bindings are intentionally NOT checked here: a bare ledger carries
/// only content hashes, not the addressed bytes. Use
/// [`verify_effect_chain_in_bundle`] for full byte-binding verification over an
/// exported replay bundle.
pub fn verify_effect_chain_entries(
    entries: &[EffectReceiptChainEntry],
) -> BundleResult<EffectChainVerification> {
    verify_effect_chain_core(entries, None, String::new(), String::new())
}

fn verify_effect_chain_core(
    entries: &[EffectReceiptChainEntry],
    cas_lookup: Option<&BTreeMap<String, CasArtifactBinding>>,
    bundle_id: String,
    verifier_identity: String,
) -> BundleResult<EffectChainVerification> {
    if entries.is_empty() {
        return Err(BundleError::EmptyEffectChain);
    }

    let mut expected_prev = EFFECT_RECEIPT_CHAIN_GENESIS.to_string();
    let mut verified_effects = Vec::with_capacity(entries.len());
    for (position, entry) in entries.iter().enumerate() {
        let expected_index = u64::try_from(position).unwrap_or(u64::MAX);
        if entry.index != expected_index {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: format!(
                    "index field {} does not match effect event position {expected_index}",
                    entry.index
                ),
            });
        }
        if !constant_time_eq(&entry.prev_chain_hash, &expected_prev) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "prev_chain_hash does not match prior effect entry".to_string(),
            });
        }

        validate_effect_receipt(expected_index, &entry.receipt)?;
        let recomputed_receipt = effect_receipt_hash(&entry.receipt);
        if !constant_time_eq(&recomputed_receipt, &entry.receipt_hash) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "receipt_hash does not match receipt contents".to_string(),
            });
        }
        let recomputed_chain =
            effect_chain_hash(entry.index, &entry.prev_chain_hash, &entry.receipt_hash);
        if !constant_time_eq(&recomputed_chain, &entry.chain_hash) {
            return Err(BundleError::EffectChainIntegrity {
                index: expected_index,
                detail: "chain_hash does not match index, prev_chain_hash, and receipt_hash"
                    .to_string(),
            });
        }

        let cas_bindings = match cas_lookup {
            Some(lookup) => verify_receipt_cas_bindings(expected_index, &entry.receipt, lookup)?,
            None => Vec::new(),
        };
        verified_effects.push(VerifiedEffect {
            index: entry.index,
            seq: entry.receipt.seq,
            trace_id: entry.receipt.trace_id.clone(),
            effect_kind: entry.receipt.effect_kind.label().to_string(),
            outcome: entry.receipt.policy_outcome.label().to_string(),
            capability_ref: entry
                .receipt
                .policy_outcome
                .capability_ref()
                .map(str::to_string),
            result_hash: entry.receipt.result_hash.clone(),
            input_lineage_hash: entry.receipt.input_lineage_hash.clone(),
            output_lineage_hash: entry.receipt.output_lineage_hash.clone(),
            label_set_commitment: entry.receipt.label_set_commitment.clone(),
            declassification_ref: entry.receipt.declassification_ref.clone(),
            flow_policy_verdict: entry.receipt.flow_policy_verdict.label().to_string(),
            cas_bindings,
        });

        expected_prev = entry.chain_hash.clone();
    }

    Ok(EffectChainVerification {
        bundle_id,
        verifier_identity,
        effect_count: verified_effects.len(),
        head_chain_hash: expected_prev,
        verified_effects,
        event_codes: vec![
            FN_VSDK_EFFECT_CHAIN_START.to_string(),
            FN_VSDK_EFFECT_VERIFIED.to_string(),
            FN_VSDK_EFFECT_CHAIN_PASS.to_string(),
        ],
    })
}

/// Render a deterministic operator transcript for a verified effect chain.
#[must_use]
pub fn render_effect_chain_transcript(report: &EffectChainVerification) -> String {
    let mut transcript = String::new();
    transcript.push_str(&format!(
        "{FN_VSDK_EFFECT_CHAIN_START} bundle_id={} effect_count={}\n",
        report.bundle_id, report.effect_count
    ));
    for effect in &report.verified_effects {
        let capability = effect.capability_ref.as_deref().unwrap_or("none");
        let result_hash = effect.result_hash.as_deref().unwrap_or("none");
        let output_lineage_hash = effect.output_lineage_hash.as_deref().unwrap_or("none");
        let declassification_ref = effect.declassification_ref.as_deref().unwrap_or("none");
        transcript.push_str(&format!(
            "{FN_VSDK_EFFECT_VERIFIED} index={} seq={} kind={} outcome={} capability_ref={} result_hash={} flow_policy_verdict={} input_lineage_hash={} output_lineage_hash={} label_set_commitment={} declassification_ref={} cas_bindings={}\n",
            effect.index,
            effect.seq,
            effect.effect_kind,
            effect.outcome,
            capability,
            result_hash,
            effect.flow_policy_verdict,
            effect.input_lineage_hash,
            output_lineage_hash,
            effect.label_set_commitment,
            declassification_ref,
            effect.cas_bindings.len()
        ));
    }
    transcript.push_str(&format!(
        "{FN_VSDK_EFFECT_CHAIN_PASS} bundle_id={} head_chain_hash={}\n",
        report.bundle_id, report.head_chain_hash
    ));
    transcript
}

/// Verify a replay bundle and prove a selective-disclosure non-exfiltration claim.
pub fn verify_non_exfiltration_claim(
    bytes: &[u8],
    claim: &NonExfiltrationClaim,
) -> BundleResult<NonExfiltrationVerification> {
    let report = verify_effect_chain(bytes)?;
    verify_non_exfiltration_claim_in_report(&report, claim)
}

/// Prove a selective-disclosure non-exfiltration claim over an already verified chain.
pub fn verify_non_exfiltration_claim_in_report(
    report: &EffectChainVerification,
    claim: &NonExfiltrationClaim,
) -> BundleResult<NonExfiltrationVerification> {
    let claim = normalize_non_exfiltration_claim(claim)?;
    let forbidden: BTreeSet<&str> = claim
        .forbidden_label_set_commitments
        .iter()
        .map(String::as_str)
        .collect();
    let sinks: BTreeSet<&str> = claim
        .external_sink_effect_kinds
        .iter()
        .map(String::as_str)
        .collect();
    let allowed_declassifications: BTreeSet<&str> = claim
        .allowed_declassification_refs
        .iter()
        .map(String::as_str)
        .collect();

    let mut examined_effects = Vec::with_capacity(report.verified_effects.len());
    for effect in &report.verified_effects {
        let label_matches = forbidden.contains(effect.label_set_commitment.as_str());
        let is_external_sink = sinks.contains(effect.effect_kind.as_str());
        let disclosed_label_set_commitment =
            label_matches.then(|| effect.label_set_commitment.clone());
        let declassification_ref = if label_matches {
            effect.declassification_ref.clone()
        } else {
            None
        };

        let proof_outcome = if !label_matches {
            "label_not_disclosed"
        } else if !is_external_sink {
            "not_external_sink"
        } else if effect.flow_policy_verdict == "blocked" && effect.outcome == "denied" {
            "blocked_before_sink"
        } else if effect.flow_policy_verdict == "declassified"
            && effect
                .declassification_ref
                .as_deref()
                .is_some_and(|declassification_ref| {
                    allowed_declassifications.contains(declassification_ref)
                })
        {
            "authorized_declassification"
        } else {
            return Err(BundleError::NonExfiltrationViolation {
                index: effect.index,
                effect_kind: effect.effect_kind.clone(),
                label_set_commitment: effect.label_set_commitment.clone(),
                detail: format!(
                    "forbidden label commitment reached {} with verdict {}",
                    effect.effect_kind, effect.flow_policy_verdict
                ),
            });
        };

        examined_effects.push(NonExfiltrationEffectProof {
            index: effect.index,
            effect_kind: effect.effect_kind.clone(),
            disclosed_label_set_commitment,
            flow_policy_verdict: effect.flow_policy_verdict.clone(),
            declassification_ref,
            proof_outcome: proof_outcome.to_string(),
        });
    }

    Ok(NonExfiltrationVerification {
        bundle_id: report.bundle_id.clone(),
        verifier_identity: report.verifier_identity.clone(),
        effect_count: report.effect_count,
        head_chain_hash: report.head_chain_hash.clone(),
        claim_hash: non_exfiltration_claim_hash(report, &claim),
        claim,
        examined_effects,
        event_codes: vec![
            FN_VSDK_NON_EXFILTRATION_START.to_string(),
            FN_VSDK_NON_EXFILTRATION_EFFECT.to_string(),
            FN_VSDK_NON_EXFILTRATION_PASS.to_string(),
        ],
    })
}

fn normalize_non_exfiltration_claim(
    claim: &NonExfiltrationClaim,
) -> BundleResult<NonExfiltrationClaim> {
    if claim.forbidden_label_set_commitments.is_empty() {
        return Err(BundleError::EmptyNonExfiltrationClaim {
            field: "forbidden_label_set_commitments",
        });
    }
    if claim.external_sink_effect_kinds.is_empty() {
        return Err(BundleError::EmptyNonExfiltrationClaim {
            field: "external_sink_effect_kinds",
        });
    }

    let mut forbidden_label_set_commitments = claim.forbidden_label_set_commitments.clone();
    for commitment in &forbidden_label_set_commitments {
        validate_non_exfiltration_label_commitment(commitment)?;
    }
    forbidden_label_set_commitments.sort();
    forbidden_label_set_commitments.dedup();

    let mut external_sink_effect_kinds = claim.external_sink_effect_kinds.clone();
    for effect_kind in &external_sink_effect_kinds {
        validate_non_exfiltration_effect_kind(effect_kind)?;
    }
    external_sink_effect_kinds.sort();
    external_sink_effect_kinds.dedup();

    let mut allowed_declassification_refs = claim.allowed_declassification_refs.clone();
    for declassification_ref in &allowed_declassification_refs {
        validate_non_exfiltration_claim_text(
            "allowed_declassification_refs",
            declassification_ref,
        )?;
    }
    allowed_declassification_refs.sort();
    allowed_declassification_refs.dedup();

    Ok(NonExfiltrationClaim {
        forbidden_label_set_commitments,
        external_sink_effect_kinds,
        allowed_declassification_refs,
    })
}

fn validate_non_exfiltration_label_commitment(value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedNonExfiltrationLabelCommitment {
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedNonExfiltrationLabelCommitment {
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_non_exfiltration_effect_kind(value: &str) -> BundleResult<()> {
    validate_non_exfiltration_claim_text("external_sink_effect_kinds", value)?;
    if !matches!(
        value,
        "fs_read" | "fs_write" | "net_connect" | "http_request" | "spawn" | "module_resolve"
    ) {
        return Err(BundleError::InvalidNonExfiltrationClaimValue {
            field: "external_sink_effect_kinds",
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_non_exfiltration_claim_text(field: &'static str, value: &str) -> BundleResult<()> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(BundleError::InvalidNonExfiltrationClaimValue {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn non_exfiltration_claim_hash(
    report: &EffectChainVerification,
    claim: &NonExfiltrationClaim,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(NON_EXFILTRATION_CLAIM_HASH_DOMAIN);
    update_hash_str(&mut hasher, &report.bundle_id);
    update_hash_str(&mut hasher, &report.verifier_identity);
    update_hash_str(&mut hasher, &report.head_chain_hash);
    update_hash_vec(&mut hasher, &claim.forbidden_label_set_commitments);
    update_hash_vec(&mut hasher, &claim.external_sink_effect_kinds);
    update_hash_vec(&mut hasher, &claim.allowed_declassification_refs);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

#[derive(Serialize)]
struct CapabilityProofPayload<'a> {
    schema_version: &'a str,
    proof_id: &'a str,
    actor: &'a str,
    audience: &'a str,
    scopes: &'a [CapabilityScope],
    policy_profile: CapabilityPolicyProfile,
    revocation_freshness: &'a CapabilityRevocationFreshness,
    epoch: u64,
    side_effect_kind: EffectKind,
    evidence_refs: &'a [String],
    expected_postconditions: &'a [CapabilityPostcondition],
    issued_at_millis: u64,
    expires_at_millis: u64,
}

#[derive(Serialize)]
struct CapabilityReceiptPayload<'a> {
    schema_version: &'a str,
    receipt_id: &'a str,
    proof_id: &'a str,
    proof_hash: &'a str,
    actor: &'a str,
    audience: &'a str,
    exercised_scope: &'a CapabilityScope,
    policy_profile: CapabilityPolicyProfile,
    epoch: u64,
    side_effect_kind: EffectKind,
    effect_receipt_chain_hash: &'a str,
    observed_postconditions: &'a [CapabilityPostcondition],
    recorded_at_millis: u64,
}

/// Return canonical payload bytes for a capability proof, excluding `proof_hash`.
pub fn capability_proof_canonical_bytes(proof: &CapabilityProof) -> BundleResult<Vec<u8>> {
    validate_capability_proof_payload(proof)?;
    canonical_bytes(&CapabilityProofPayload {
        schema_version: &proof.schema_version,
        proof_id: &proof.proof_id,
        actor: &proof.actor,
        audience: &proof.audience,
        scopes: &proof.scopes,
        policy_profile: proof.policy_profile,
        revocation_freshness: &proof.revocation_freshness,
        epoch: proof.epoch,
        side_effect_kind: proof.side_effect_kind,
        evidence_refs: &proof.evidence_refs,
        expected_postconditions: &proof.expected_postconditions,
        issued_at_millis: proof.issued_at_millis,
        expires_at_millis: proof.expires_at_millis,
    })
}

/// Return canonical payload bytes for a capability receipt, excluding `receipt_hash`.
pub fn capability_receipt_canonical_bytes(receipt: &CapabilityReceipt) -> BundleResult<Vec<u8>> {
    validate_capability_receipt_payload(receipt)?;
    canonical_bytes(&CapabilityReceiptPayload {
        schema_version: &receipt.schema_version,
        receipt_id: &receipt.receipt_id,
        proof_id: &receipt.proof_id,
        proof_hash: &receipt.proof_hash,
        actor: &receipt.actor,
        audience: &receipt.audience,
        exercised_scope: &receipt.exercised_scope,
        policy_profile: receipt.policy_profile,
        epoch: receipt.epoch,
        side_effect_kind: receipt.side_effect_kind,
        effect_receipt_chain_hash: &receipt.effect_receipt_chain_hash,
        observed_postconditions: &receipt.observed_postconditions,
        recorded_at_millis: receipt.recorded_at_millis,
    })
}

/// Compute the domain-separated canonical hash for a capability proof payload.
pub fn capability_proof_hash(proof: &CapabilityProof) -> BundleResult<String> {
    let canonical = capability_proof_canonical_bytes(proof)?;
    Ok(hash_with_domain(CAPABILITY_PROOF_HASH_DOMAIN, &canonical))
}

/// Compute the domain-separated canonical hash for a capability receipt payload.
pub fn capability_receipt_hash(receipt: &CapabilityReceipt) -> BundleResult<String> {
    let canonical = capability_receipt_canonical_bytes(receipt)?;
    Ok(hash_with_domain(CAPABILITY_RECEIPT_HASH_DOMAIN, &canonical))
}

/// Populate the self-binding hash on a capability proof.
pub fn seal_capability_proof(proof: &mut CapabilityProof) -> BundleResult<()> {
    proof.proof_hash = capability_proof_hash(proof)?;
    Ok(())
}

/// Populate the self-binding hash on a capability receipt.
pub fn seal_capability_receipt(receipt: &mut CapabilityReceipt) -> BundleResult<()> {
    receipt.receipt_hash = capability_receipt_hash(receipt)?;
    Ok(())
}

/// Verify a capability proof's schema, canonical fields, and self-binding hash.
pub fn verify_capability_proof_schema(proof: &CapabilityProof) -> BundleResult<String> {
    validate_capability_proof_payload(proof)?;
    validate_capability_hash("proof_hash", &proof.proof_hash)?;
    let expected = capability_proof_hash(proof)?;
    if !constant_time_eq(&proof.proof_hash, &expected) {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "proof_hash",
            expected,
            actual: proof.proof_hash.clone(),
        });
    }
    Ok(proof.proof_hash.clone())
}

/// Verify that a capability-use receipt is bound to the supplied proof.
pub fn verify_capability_receipt_schema(
    proof: &CapabilityProof,
    receipt: &CapabilityReceipt,
) -> BundleResult<CapabilityReceiptVerification> {
    let proof_hash = verify_capability_proof_schema(proof)?;
    ensure_capability_revocation_is_fresh(&proof.revocation_freshness)?;
    validate_capability_receipt_payload(receipt)?;
    validate_capability_hash("receipt_hash", &receipt.receipt_hash)?;

    let expected_receipt_hash = capability_receipt_hash(receipt)?;
    if !constant_time_eq(&receipt.receipt_hash, &expected_receipt_hash) {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "receipt_hash",
            expected: expected_receipt_hash,
            actual: receipt.receipt_hash.clone(),
        });
    }
    require_capability_match("proof_id", &proof.proof_id, &receipt.proof_id)?;
    require_capability_match("proof_hash", &proof_hash, &receipt.proof_hash)?;
    require_capability_match("actor", &proof.actor, &receipt.actor)?;
    require_capability_match("audience", &proof.audience, &receipt.audience)?;
    if proof.policy_profile != receipt.policy_profile {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "policy_profile",
            expected: proof.policy_profile.label().to_string(),
            actual: receipt.policy_profile.label().to_string(),
        });
    }
    if proof.epoch != receipt.epoch {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "epoch",
            expected: proof.epoch.to_string(),
            actual: receipt.epoch.to_string(),
        });
    }
    if proof.side_effect_kind != receipt.side_effect_kind {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "side_effect_kind",
            expected: proof.side_effect_kind.label().to_string(),
            actual: receipt.side_effect_kind.label().to_string(),
        });
    }
    if !proof.scopes.contains(&receipt.exercised_scope) {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "exercised_scope",
            expected: "scope included in proof".to_string(),
            actual: capability_scope_key(&receipt.exercised_scope),
        });
    }
    if proof.expected_postconditions != receipt.observed_postconditions {
        return Err(BundleError::CapabilityReceiptMismatch {
            field: "observed_postconditions",
            expected: format!(
                "{} expected postconditions",
                proof.expected_postconditions.len()
            ),
            actual: format!(
                "{} observed postconditions",
                receipt.observed_postconditions.len()
            ),
        });
    }
    if receipt.recorded_at_millis < proof.issued_at_millis {
        return Err(BundleError::InvalidCapabilityField {
            field: "recorded_at_millis",
            reason: "receipt predates capability proof issuance".to_string(),
        });
    }
    if receipt.recorded_at_millis > proof.expires_at_millis {
        return Err(BundleError::InvalidCapabilityField {
            field: "recorded_at_millis",
            reason: "receipt was recorded after capability proof expiry".to_string(),
        });
    }

    Ok(CapabilityReceiptVerification {
        proof_id: proof.proof_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        actor: proof.actor.clone(),
        audience: proof.audience.clone(),
        scope: receipt.exercised_scope.clone(),
        policy_profile: proof.policy_profile.label().to_string(),
        epoch: proof.epoch,
        side_effect_kind: proof.side_effect_kind.label().to_string(),
        proof_hash,
        receipt_hash: receipt.receipt_hash.clone(),
        effect_receipt_chain_hash: receipt.effect_receipt_chain_hash.clone(),
        postcondition_count: proof.expected_postconditions.len(),
        evidence_ref_count: proof.evidence_refs.len(),
        event_codes: vec![
            FN_VSDK_CAPABILITY_SCHEMA_START.to_string(),
            FN_VSDK_CAPABILITY_PROOF_VERIFIED.to_string(),
            FN_VSDK_CAPABILITY_RECEIPT_VERIFIED.to_string(),
            FN_VSDK_CAPABILITY_SCHEMA_PASS.to_string(),
        ],
    })
}

/// Render a deterministic operator transcript for a verified capability use.
#[must_use]
pub fn render_capability_verification_transcript(report: &CapabilityReceiptVerification) -> String {
    let mut transcript = String::new();
    transcript.push_str(&format!(
        "{FN_VSDK_CAPABILITY_SCHEMA_START} proof_id={} receipt_id={} actor={} audience={}\n",
        report.proof_id, report.receipt_id, report.actor, report.audience
    ));
    transcript.push_str(&format!(
        "{FN_VSDK_CAPABILITY_PROOF_VERIFIED} proof_hash={} policy_profile={} epoch={} side_effect_kind={} evidence_refs={}\n",
        report.proof_hash,
        report.policy_profile,
        report.epoch,
        report.side_effect_kind,
        report.evidence_ref_count
    ));
    transcript.push_str(&format!(
        "{FN_VSDK_CAPABILITY_RECEIPT_VERIFIED} receipt_hash={} scope_capability={} scope_access={} scope_resource={} effect_receipt_chain_hash={} postconditions={}\n",
        report.receipt_hash,
        report.scope.capability,
        report.scope.access,
        report.scope.resource,
        report.effect_receipt_chain_hash,
        report.postcondition_count
    ));
    transcript.push_str(&format!(
        "{FN_VSDK_CAPABILITY_SCHEMA_PASS} proof_id={} receipt_id={}\n",
        report.proof_id, report.receipt_id
    ));
    transcript
}

fn validate_capability_proof_payload(proof: &CapabilityProof) -> BundleResult<()> {
    if proof.schema_version != CAPABILITY_PROOF_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedCapabilityProofSchema {
            expected: CAPABILITY_PROOF_SCHEMA_VERSION.to_string(),
            actual: proof.schema_version.clone(),
        });
    }
    validate_capability_text("proof_id", &proof.proof_id)?;
    validate_capability_text("actor", &proof.actor)?;
    validate_capability_text("audience", &proof.audience)?;
    validate_capability_scopes(&proof.scopes)?;
    validate_capability_revocation_freshness(&proof.revocation_freshness)?;
    validate_capability_string_list("evidence_refs", &proof.evidence_refs)?;
    validate_capability_postconditions("expected_postconditions", &proof.expected_postconditions)?;
    if proof.issued_at_millis >= proof.expires_at_millis {
        return Err(BundleError::InvalidCapabilityField {
            field: "expires_at_millis",
            reason: "capability proof must expire after issuance".to_string(),
        });
    }
    Ok(())
}

fn validate_capability_receipt_payload(receipt: &CapabilityReceipt) -> BundleResult<()> {
    if receipt.schema_version != CAPABILITY_RECEIPT_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedCapabilityReceiptSchema {
            expected: CAPABILITY_RECEIPT_SCHEMA_VERSION.to_string(),
            actual: receipt.schema_version.clone(),
        });
    }
    validate_capability_text("receipt_id", &receipt.receipt_id)?;
    validate_capability_text("proof_id", &receipt.proof_id)?;
    validate_capability_hash("proof_hash", &receipt.proof_hash)?;
    validate_capability_text("actor", &receipt.actor)?;
    validate_capability_text("audience", &receipt.audience)?;
    validate_capability_scope("exercised_scope", &receipt.exercised_scope)?;
    validate_capability_hash(
        "effect_receipt_chain_hash",
        &receipt.effect_receipt_chain_hash,
    )?;
    validate_capability_postconditions(
        "observed_postconditions",
        &receipt.observed_postconditions,
    )?;
    Ok(())
}

fn validate_capability_text(field: &'static str, value: &str) -> BundleResult<()> {
    validate_canonical_text(field, value)?;
    if value.len() > 512 {
        return Err(BundleError::InvalidCapabilityField {
            field,
            reason: "field exceeds 512 bytes".to_string(),
        });
    }
    if value
        .bytes()
        .any(|byte| byte == b'\0' || byte.is_ascii_control())
    {
        return Err(BundleError::InvalidCapabilityField {
            field,
            reason: "field contains a control byte".to_string(),
        });
    }
    Ok(())
}

fn validate_capability_hash(field: &'static str, value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedCapabilityHash {
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedCapabilityHash {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_capability_string_list(field: &'static str, values: &[String]) -> BundleResult<()> {
    if values.is_empty() {
        return Err(BundleError::InvalidCapabilityField {
            field,
            reason: "collection must not be empty".to_string(),
        });
    }
    let mut previous = None;
    for value in values {
        validate_capability_text(field, value)?;
        if previous.is_some_and(|prior: &str| value.as_str() <= prior) {
            return Err(BundleError::InvalidCapabilityField {
                field,
                reason: "collection must be sorted and unique".to_string(),
            });
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn validate_capability_scopes(scopes: &[CapabilityScope]) -> BundleResult<()> {
    if scopes.is_empty() {
        return Err(BundleError::InvalidCapabilityField {
            field: "scopes",
            reason: "collection must not be empty".to_string(),
        });
    }
    let mut previous = None;
    for scope in scopes {
        validate_capability_scope("scopes", scope)?;
        let key = capability_scope_key(scope);
        if previous
            .as_deref()
            .is_some_and(|prior| key.as_str() <= prior)
        {
            return Err(BundleError::InvalidCapabilityField {
                field: "scopes",
                reason: "collection must be sorted and unique".to_string(),
            });
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_capability_scope(field: &'static str, scope: &CapabilityScope) -> BundleResult<()> {
    validate_capability_text(field, &scope.capability)?;
    validate_capability_text(field, &scope.resource)?;
    validate_capability_text(field, &scope.access)?;
    Ok(())
}

fn validate_capability_postconditions(
    field: &'static str,
    postconditions: &[CapabilityPostcondition],
) -> BundleResult<()> {
    if postconditions.is_empty() {
        return Err(BundleError::InvalidCapabilityField {
            field,
            reason: "collection must not be empty".to_string(),
        });
    }
    let mut previous = None;
    for postcondition in postconditions {
        validate_capability_text(field, &postcondition.field)?;
        validate_capability_hash(field, &postcondition.expected_hash)?;
        if previous.is_some_and(|prior: &str| postcondition.field.as_str() <= prior) {
            return Err(BundleError::InvalidCapabilityField {
                field,
                reason: "collection must be sorted and unique by field".to_string(),
            });
        }
        previous = Some(postcondition.field.as_str());
    }
    Ok(())
}

fn validate_capability_revocation_freshness(
    freshness: &CapabilityRevocationFreshness,
) -> BundleResult<()> {
    match freshness {
        CapabilityRevocationFreshness::Fresh { evidence_ref, .. }
        | CapabilityRevocationFreshness::Stale { evidence_ref, .. } => {
            validate_capability_text("revocation_freshness.evidence_ref", evidence_ref)
        }
        CapabilityRevocationFreshness::Revoked { revocation_ref, .. } => {
            validate_capability_text("revocation_freshness.revocation_ref", revocation_ref)
        }
    }
}

fn ensure_capability_revocation_is_fresh(
    freshness: &CapabilityRevocationFreshness,
) -> BundleResult<()> {
    if matches!(freshness, CapabilityRevocationFreshness::Fresh { .. }) {
        Ok(())
    } else {
        Err(BundleError::InvalidCapabilityField {
            field: "revocation_freshness",
            reason: "capability proof must carry fresh revocation evidence".to_string(),
        })
    }
}

fn require_capability_match(field: &'static str, expected: &str, actual: &str) -> BundleResult<()> {
    if constant_time_eq(expected, actual) {
        Ok(())
    } else {
        Err(BundleError::CapabilityReceiptMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

fn capability_scope_key(scope: &CapabilityScope) -> String {
    format!(
        "{}\x1f{}\x1f{}",
        scope.capability, scope.resource, scope.access
    )
}

fn hash_with_domain(domain: &[u8], canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(canonical.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(canonical);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn update_hash_vec(hasher: &mut Sha256, values: &[String]) {
    hasher.update(
        u64::try_from(values.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for value in values {
        update_hash_str(hasher, value);
    }
}

#[derive(Debug, Clone)]
struct CasArtifactBinding {
    artifact_path: String,
    byte_length: u64,
}

fn cas_artifact_lookup(
    bundle: &ReplayBundle,
) -> BundleResult<BTreeMap<String, CasArtifactBinding>> {
    let mut lookup = BTreeMap::new();
    for (path, artifact) in &bundle.artifacts {
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let content_hash = cas_content_hash(&bytes);
        lookup.entry(content_hash).or_insert_with(|| {
            let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            CasArtifactBinding {
                artifact_path: path.clone(),
                byte_length,
            }
        });
    }
    Ok(lookup)
}

fn effect_chain_entries(bundle: &ReplayBundle) -> BundleResult<Vec<EffectReceiptChainEntry>> {
    bundle
        .timeline
        .iter()
        .filter(|event| event.event_type == EFFECT_RECEIPT_EVENT_TYPE)
        .map(|event| {
            serde_json::from_value(event.payload.clone()).map_err(|source| {
                BundleError::InvalidEffectReceiptPayload {
                    event_id: event.event_id.clone(),
                    source: source.to_string(),
                }
            })
        })
        .collect()
}

fn validate_effect_receipt(index: u64, receipt: &EffectReceipt) -> BundleResult<()> {
    if receipt.schema_version != EFFECT_RECEIPT_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedEffectReceiptSchema {
            index,
            expected: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            actual: receipt.schema_version.clone(),
        });
    }
    validate_effect_content_hash(index, "pre_state_hash", &receipt.pre_state_hash)?;
    validate_effect_content_hash(index, "args_hash", &receipt.args_hash)?;
    validate_effect_lineage_hash(index, "input_lineage_hash", &receipt.input_lineage_hash)?;
    validate_effect_lineage_hash(index, "label_set_commitment", &receipt.label_set_commitment)?;
    if let Some(output_lineage_hash) = &receipt.output_lineage_hash {
        validate_effect_lineage_hash(index, "output_lineage_hash", output_lineage_hash)?;
    }
    if receipt
        .declassification_ref
        .as_ref()
        .is_some_and(|declassification_ref| declassification_ref.trim().is_empty())
    {
        return Err(BundleError::EffectReceiptLineagePolicy {
            index,
            detail: "declassification_ref must not be empty".to_string(),
        });
    }
    let is_allowed = matches!(&receipt.policy_outcome, EffectPolicyOutcome::Allowed { .. });
    match &receipt.policy_outcome {
        EffectPolicyOutcome::Allowed { .. } => {
            if receipt.result_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "result_hash",
                });
            }
            if receipt.post_state_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "post_state_hash",
                });
            }
            if receipt.output_lineage_hash.is_none() {
                return Err(BundleError::EffectReceiptAllowedMissingHash {
                    index,
                    field: "output_lineage_hash",
                });
            }
        }
        EffectPolicyOutcome::Denied { .. } => {
            if receipt.result_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "result_hash",
                });
            }
            if receipt.post_state_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "post_state_hash",
                });
            }
            if receipt.output_lineage_hash.is_some() {
                return Err(BundleError::EffectReceiptDeniedHasHash {
                    index,
                    field: "output_lineage_hash",
                });
            }
        }
    }
    match receipt.flow_policy_verdict {
        FlowPolicyVerdict::LabelClean => {
            if receipt.declassification_ref.is_some() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "label-clean effects must not carry declassification_ref".to_string(),
                });
            }
        }
        FlowPolicyVerdict::Declassified => {
            if !is_allowed {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "declassified flow verdict requires an allowed effect".to_string(),
                });
            }
            if receipt.declassification_ref.is_none() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "declassified flow verdict requires declassification_ref".to_string(),
                });
            }
        }
        FlowPolicyVerdict::Blocked => {
            if is_allowed {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "blocked flow verdict requires a denied effect".to_string(),
                });
            }
            if receipt.declassification_ref.is_some() {
                return Err(BundleError::EffectReceiptLineagePolicy {
                    index,
                    detail: "blocked flow verdict must not carry declassification_ref".to_string(),
                });
            }
        }
    }
    if let Some(hash) = &receipt.result_hash {
        validate_effect_content_hash(index, "result_hash", hash)?;
    }
    if let Some(hash) = &receipt.post_state_hash {
        validate_effect_content_hash(index, "post_state_hash", hash)?;
    }
    Ok(())
}

fn validate_effect_lineage_hash(index: u64, field: &'static str, value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedEffectLineageHash {
            index,
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedEffectLineageHash {
            index,
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_effect_content_hash(index: u64, field: &'static str, value: &str) -> BundleResult<()> {
    let Some(hex) = value.strip_prefix(CONTENT_HASH_PREFIX) else {
        return Err(BundleError::MalformedEffectContentHash {
            index,
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64 || !is_canonical_lower_hex(hex) {
        return Err(BundleError::MalformedEffectContentHash {
            index,
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn verify_receipt_cas_bindings(
    index: u64,
    receipt: &EffectReceipt,
    cas_lookup: &BTreeMap<String, CasArtifactBinding>,
) -> BundleResult<Vec<VerifiedCasBinding>> {
    let mut bindings = Vec::new();
    push_verified_cas_binding(
        &mut bindings,
        index,
        "pre_state_hash",
        &receipt.pre_state_hash,
        cas_lookup,
    )?;
    push_verified_cas_binding(
        &mut bindings,
        index,
        "args_hash",
        &receipt.args_hash,
        cas_lookup,
    )?;
    if let Some(hash) = &receipt.result_hash {
        push_verified_cas_binding(&mut bindings, index, "result_hash", hash, cas_lookup)?;
    }
    if let Some(hash) = &receipt.post_state_hash {
        push_verified_cas_binding(&mut bindings, index, "post_state_hash", hash, cas_lookup)?;
    }
    Ok(bindings)
}

fn push_verified_cas_binding(
    bindings: &mut Vec<VerifiedCasBinding>,
    index: u64,
    field: &'static str,
    hash: &str,
    cas_lookup: &BTreeMap<String, CasArtifactBinding>,
) -> BundleResult<()> {
    let artifact =
        cas_lookup
            .get(hash)
            .ok_or_else(|| BundleError::EffectReceiptMissingCasBytes {
                index,
                field,
                hash: hash.to_string(),
            })?;
    bindings.push(VerifiedCasBinding {
        field: field.to_string(),
        hash: hash.to_string(),
        artifact_path: artifact.artifact_path.clone(),
        byte_length: artifact.byte_length,
    });
    Ok(())
}

fn cas_content_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CAS_HASH_DOMAIN);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn effect_receipt_hash(receipt: &EffectReceipt) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_RECEIPT_HASH_DOMAIN);
    update_hash_str(&mut hasher, &receipt.schema_version);
    hasher.update(receipt.seq.to_le_bytes());
    update_hash_str(&mut hasher, &receipt.trace_id);
    hasher.update([receipt.effect_kind.tag()]);
    hasher.update([receipt.policy_outcome.tag()]);
    match &receipt.policy_outcome {
        EffectPolicyOutcome::Allowed { capability_ref } => {
            update_hash_str(&mut hasher, capability_ref);
        }
        EffectPolicyOutcome::Denied { reason } => {
            update_hash_str(&mut hasher, reason);
        }
    }
    update_hash_str(&mut hasher, &receipt.pre_state_hash);
    update_hash_str(&mut hasher, &receipt.args_hash);
    update_optional_hash_str(&mut hasher, receipt.result_hash.as_deref());
    update_optional_hash_str(&mut hasher, receipt.post_state_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.input_lineage_hash);
    update_optional_hash_str(&mut hasher, receipt.output_lineage_hash.as_deref());
    update_hash_str(&mut hasher, &receipt.label_set_commitment);
    update_optional_hash_str(&mut hasher, receipt.declassification_ref.as_deref());
    hasher.update([receipt.flow_policy_verdict.tag()]);
    hasher.update(receipt.recorded_at_millis.to_le_bytes());
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn update_hash_str(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn update_optional_hash_str(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(hash) => {
            hasher.update([1_u8]);
            update_hash_str(hasher, hash);
        }
        None => hasher.update([0_u8]),
    }
}

fn effect_chain_hash(index: u64, prev_chain_hash: &str, receipt_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EFFECT_RECEIPT_CHAIN_HASH_DOMAIN);
    hasher.update(index.to_le_bytes());
    update_hash_str(&mut hasher, prev_chain_hash);
    update_hash_str(&mut hasher, receipt_hash);
    format!("{CONTENT_HASH_PREFIX}{}", hex::encode(hasher.finalize()))
}

fn validate_structure(bundle: &ReplayBundle) -> Result<(), BundleError> {
    if bundle.schema_version != REPLAY_BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::UnsupportedSchema {
            expected: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            actual: bundle.schema_version.clone(),
        });
    }
    if bundle.sdk_version != SDK_VERSION {
        return Err(BundleError::UnsupportedSdk {
            expected: SDK_VERSION.to_string(),
            actual: bundle.sdk_version.clone(),
        });
    }
    validate_hash_algorithm(&bundle.header.hash_algorithm)?;
    validate_hash_algorithm(&bundle.signature.algorithm)?;
    validate_canonical_text("bundle_id", &bundle.bundle_id)?;
    validate_canonical_text("incident_id", &bundle.incident_id)?;
    validate_nonempty("created_at", &bundle.created_at)?;
    parse_rfc3339_timestamp("created_at", &bundle.created_at)?;
    validate_canonical_text("policy_version", &bundle.policy_version)?;
    validate_nonempty("verifier_identity", &bundle.verifier_identity)?;
    validate_verifier_identity(&bundle.verifier_identity)?;
    validate_nonempty("integrity_hash", &bundle.integrity_hash)?;
    validate_nonempty("signature.signature_hex", &bundle.signature.signature_hex)?;
    if bundle.timeline.is_empty() {
        return Err(BundleError::EmptyTimeline);
    }
    if bundle.artifacts.is_empty() {
        return Err(BundleError::EmptyArtifacts);
    }
    if bundle.chunks.is_empty() {
        return Err(BundleError::EmptyChunks);
    }

    let mut previous_sequence = None;
    let mut previous_timestamp: Option<(DateTime<FixedOffset>, &str)> = None;
    for event in &bundle.timeline {
        validate_canonical_text("timeline.event_id", &event.event_id)?;
        validate_nonempty("timeline.timestamp", &event.timestamp)?;
        let parsed_timestamp = parse_rfc3339_timestamp("timeline.timestamp", &event.timestamp)?;
        validate_canonical_text("timeline.event_type", &event.event_type)?;
        validate_canonical_text("timeline.policy_version", &event.policy_version)?;
        if event.policy_version != bundle.policy_version {
            return Err(BundleError::EventPolicyVersionMismatch {
                bundle_policy_version: bundle.policy_version.clone(),
                event_id: event.event_id.clone(),
                event_policy_version: event.policy_version.clone(),
            });
        }
        if let Some(previous) = previous_sequence
            && event.sequence_number <= previous
        {
            return Err(BundleError::MissingField {
                field: "timeline.sequence_number",
            });
        }
        previous_sequence = Some(event.sequence_number);
        if let Some((previous, previous_raw)) = previous_timestamp
            && parsed_timestamp <= previous
        {
            return Err(BundleError::NonMonotonicTimestamp {
                previous: previous_raw.to_string(),
                current: event.timestamp.clone(),
                event_id: event.event_id.clone(),
            });
        }
        previous_timestamp = Some((parsed_timestamp, event.timestamp.as_str()));
    }
    Ok(())
}

fn validate_hash_algorithm(actual: &str) -> Result<(), BundleError> {
    if actual != REPLAY_BUNDLE_HASH_ALGORITHM {
        Err(BundleError::UnsupportedHashAlgorithm {
            expected: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            actual: actual.to_string(),
        })
    } else {
        Ok(())
    }
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), BundleError> {
    if verifier_identity != verifier_identity.trim() {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    let Some(remainder) = verifier_identity.strip_prefix("verifier://") else {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(BundleError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
        });
    }
    Ok(())
}

fn validate_artifacts(bundle: &ReplayBundle) -> Result<(), BundleError> {
    for (path, artifact) in &bundle.artifacts {
        validate_artifact_path(path)?;
        validate_nonempty("artifacts.media_type", &artifact.media_type)?;
        validate_nonempty("artifacts.digest", &artifact.digest)?;
        validate_nonempty("artifacts.bytes_hex", &artifact.bytes_hex)?;
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let actual = hash(&bytes);
        if !constant_time_eq(&artifact.digest, &actual) {
            return Err(BundleError::ArtifactDigestMismatch {
                path: path.clone(),
                expected: artifact.digest.clone(),
                actual,
            });
        }
    }
    Ok(())
}

fn validate_header(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let actual_payload_length = payload_length_bytes(&bundle.artifacts)?;
    if bundle.header.payload_length_bytes != actual_payload_length {
        return Err(BundleError::PayloadLengthMismatch {
            expected: bundle.header.payload_length_bytes,
            actual: actual_payload_length,
        });
    }

    let actual_chunk_count =
        u32::try_from(bundle.chunks.len()).map_err(|_| BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: u32::MAX,
        })?;
    if bundle.header.chunk_count != actual_chunk_count {
        return Err(BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: actual_chunk_count,
        });
    }
    Ok(())
}

fn validate_chunks(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let total_chunks =
        u32::try_from(bundle.chunks.len()).map_err(|_| BundleError::ChunkCountMismatch {
            expected: bundle.header.chunk_count,
            actual: u32::MAX,
        })?;

    for (index, chunk) in bundle.chunks.iter().enumerate() {
        let expected_index = u32::try_from(index).map_err(|_| BundleError::ChunkIndexMismatch {
            expected: u32::MAX,
            actual: chunk.chunk_index,
        })?;
        if chunk.chunk_index != expected_index {
            return Err(BundleError::ChunkIndexMismatch {
                expected: expected_index,
                actual: chunk.chunk_index,
            });
        }
        if chunk.total_chunks != total_chunks {
            return Err(BundleError::ChunkCountMismatch {
                expected: total_chunks,
                actual: chunk.total_chunks,
            });
        }
        validate_artifact_path(&chunk.artifact_path)?;

        let artifact = bundle.artifacts.get(&chunk.artifact_path).ok_or_else(|| {
            BundleError::ChunkArtifactMissing {
                path: chunk.artifact_path.clone(),
            }
        })?;
        let bytes = decode_canonical_artifact_hex(&chunk.artifact_path, &artifact.bytes_hex)?;
        let actual_payload_length =
            u64::try_from(bytes.len()).map_err(|_| BundleError::ChunkPayloadLengthMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: chunk.payload_length_bytes,
                actual: u64::MAX,
            })?;
        if chunk.payload_length_bytes != actual_payload_length {
            return Err(BundleError::ChunkPayloadLengthMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: chunk.payload_length_bytes,
                actual: actual_payload_length,
            });
        }
        if !constant_time_eq(&chunk.payload_digest, &artifact.digest) {
            return Err(BundleError::ChunkDigestMismatch {
                artifact_path: chunk.artifact_path.clone(),
                expected: artifact.digest.clone(),
                actual: chunk.payload_digest.clone(),
            });
        }
    }
    Ok(())
}

fn payload_length_bytes(artifacts: &BTreeMap<String, BundleArtifact>) -> Result<u64, BundleError> {
    let mut total = 0_u64;
    for (path, artifact) in artifacts {
        let bytes = decode_canonical_artifact_hex(path, &artifact.bytes_hex)?;
        let length =
            u64::try_from(bytes.len()).map_err(|_| BundleError::PayloadLengthMismatch {
                expected: u64::MAX,
                actual: u64::MAX,
            })?;
        total = total
            .checked_add(length)
            .ok_or(BundleError::PayloadLengthMismatch {
                expected: u64::MAX,
                actual: u64::MAX,
            })?;
    }
    Ok(total)
}

fn validate_signature(bundle: &ReplayBundle) -> Result<(), BundleError> {
    let expected = compute_signature_hex(&bundle.integrity_hash);
    if !constant_time_eq(&bundle.signature.signature_hex, &expected) {
        return Err(BundleError::SignatureMismatch {
            expected,
            actual: bundle.signature.signature_hex.clone(),
        });
    }
    Ok(())
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), BundleError> {
    if value.trim().is_empty() {
        Err(BundleError::MissingField { field })
    } else {
        Ok(())
    }
}

fn decode_canonical_artifact_hex(path: &str, bytes_hex: &str) -> Result<Vec<u8>, BundleError> {
    if !is_canonical_lower_hex(bytes_hex) {
        return Err(BundleError::InvalidArtifactHex {
            path: path.to_string(),
            source: "artifact bytes_hex must use canonical lowercase hex".to_string(),
        });
    }
    Vec::from_hex(bytes_hex).map_err(|source| BundleError::InvalidArtifactHex {
        path: path.to_string(),
        source: source.to_string(),
    })
}

fn is_canonical_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_artifact_path(path: &str) -> Result<(), BundleError> {
    if path.trim().is_empty()
        || path.trim() != path
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|byte| {
            byte == b'\0'
                || byte.is_ascii_control()
                || !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'/')
        })
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(BundleError::InvalidArtifactPath {
            path: path.to_string(),
        });
    }
    Ok(())
}

fn validate_canonical_text(field: &'static str, value: &str) -> Result<(), BundleError> {
    validate_nonempty(field, value)?;
    if value.trim() != value {
        return Err(BundleError::NonCanonicalField {
            field,
            actual: value.to_string(),
        });
    }
    Ok(())
}

fn parse_rfc3339_timestamp(
    field: &'static str,
    value: &str,
) -> Result<DateTime<FixedOffset>, BundleError> {
    DateTime::parse_from_rfc3339(value).map_err(|_| BundleError::InvalidTimestamp {
        field,
        actual: value.to_string(),
    })
}

fn compute_signature_hex(integrity_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(integrity_hash.as_bytes());
    hex::encode(hasher.finalize())
}

fn ed25519_bundle_signature_payload(bundle: &ReplayBundle) -> Vec<u8> {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, ED25519_BUNDLE_SIGNATURE_DOMAIN);
    push_length_prefixed(&mut payload, bundle.schema_version.as_bytes());
    push_length_prefixed(&mut payload, bundle.sdk_version.as_bytes());
    push_length_prefixed(&mut payload, bundle.bundle_id.as_bytes());
    push_length_prefixed(&mut payload, bundle.incident_id.as_bytes());
    push_length_prefixed(&mut payload, bundle.created_at.as_bytes());
    push_length_prefixed(&mut payload, bundle.integrity_hash.as_bytes());
    payload
}

fn push_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, BundleError> {
    let value =
        serde_json::to_value(value).map_err(|source| BundleError::Json(source.to_string()))?;
    let canonical = canonicalize_value(value, "$")?;
    serde_json::to_vec(&canonical).map_err(|source| BundleError::Json(source.to_string()))
}

fn canonicalize_value(value: Value, path: &str) -> Result<Value, BundleError> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .enumerate()
            .map(|(index, item)| canonicalize_value(item, &format!("{path}[{index}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(map) => {
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

            let mut canonical = serde_json::Map::with_capacity(entries.len());
            for (key, item) in entries {
                canonical.insert(
                    key.clone(),
                    canonicalize_value(item, &format!("{path}.{key}"))?,
                );
            }
            Ok(Value::Object(canonical))
        }
        Value::Number(number) if number.is_f64() => Err(BundleError::NonDeterministicFloat {
            path: path.to_string(),
        }),
        other => Ok(other),
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// bd-5r99w.12: the verifier SDK re-derives a bare effect-receipt chain — the
    /// `franken-node run --json` host-effect ledger surface — offline, with no
    /// surrounding replay bundle. The entries here are built EXACTLY as
    /// franken_node's `build_host_effect_ledger` builds them (same canonical
    /// receipt/chain hashing), so a passing verify proves cross-format
    /// compatibility; tampering and an empty chain both fail closed.
    #[test]
    fn verify_effect_chain_entries_re_derives_run_ledger_offline_bd_5r99w_12() {
        let empty =
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        let build_entry = |index: u64, prev: &str, receipt: EffectReceipt| {
            let receipt_hash = effect_receipt_hash(&receipt);
            let chain_hash = effect_chain_hash(index, prev, &receipt_hash);
            EffectReceiptChainEntry {
                index,
                prev_chain_hash: prev.to_string(),
                receipt_hash,
                chain_hash,
                receipt,
            }
        };

        let read_hash = cas_content_hash(b"hello");
        let allowed = EffectReceipt {
            schema_version: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            seq: 0,
            trace_id: "trace-bd-5r99w-12".to_string(),
            effect_kind: EffectKind::FsRead,
            policy_outcome: EffectPolicyOutcome::Allowed {
                capability_ref: "host-io:fs_read".to_string(),
            },
            pre_state_hash: read_hash.clone(),
            args_hash: cas_content_hash(b"input.txt"),
            result_hash: Some(read_hash.clone()),
            post_state_hash: Some(read_hash.clone()),
            input_lineage_hash: empty.clone(),
            output_lineage_hash: Some(empty.clone()),
            label_set_commitment: empty.clone(),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::LabelClean,
            recorded_at_millis: 1_700_000_000_000,
        };
        let denied = EffectReceipt {
            schema_version: EFFECT_RECEIPT_SCHEMA_VERSION.to_string(),
            seq: 1,
            trace_id: "trace-bd-5r99w-12".to_string(),
            effect_kind: EffectKind::FsWrite,
            policy_outcome: EffectPolicyOutcome::Denied {
                reason: "host I/O sandbox violation: absolute path escapes sandbox root"
                    .to_string(),
            },
            pre_state_hash: cas_content_hash(b"nope"),
            args_hash: cas_content_hash(b"/escape.txt"),
            result_hash: None,
            post_state_hash: None,
            input_lineage_hash: empty.clone(),
            output_lineage_hash: None,
            label_set_commitment: empty.clone(),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::LabelClean,
            recorded_at_millis: 1_700_000_000_000,
        };

        let e0 = build_entry(0, EFFECT_RECEIPT_CHAIN_GENESIS, allowed);
        let e1 = build_entry(1, &e0.chain_hash, denied);
        let entries = vec![e0, e1];

        // Offline re-derivation of the bare run --json ledger succeeds.
        let report = verify_effect_chain_entries(&entries).expect("offline chain verifies");
        assert_eq!(report.effect_count, 2);
        assert_eq!(report.head_chain_hash, entries[1].chain_hash);
        assert_eq!(report.verified_effects[0].effect_kind, "fs_read");
        assert_eq!(report.verified_effects[0].outcome, "allowed");
        assert_eq!(
            report.verified_effects[0].capability_ref.as_deref(),
            Some("host-io:fs_read")
        );
        assert_eq!(report.verified_effects[1].effect_kind, "fs_write");
        assert_eq!(report.verified_effects[1].outcome, "denied");
        assert!(report.verified_effects[1].result_hash.is_none());

        // Tamper a receipt field → recomputed receipt hash diverges → fail closed.
        let mut tampered = entries.clone();
        tampered[0].receipt.trace_id = "trace-tampered".to_string();
        assert!(
            verify_effect_chain_entries(&tampered).is_err(),
            "tampered chain must fail closed"
        );

        // Empty ledger → explicit fail-closed error.
        assert!(matches!(
            verify_effect_chain_entries(&[]),
            Err(BundleError::EmptyEffectChain)
        ));
    }

    fn make_test_bundle(verifier_identity: &str) -> ReplayBundle {
        let artifact_bytes = b"bundle-artifact";
        let artifact_path = "artifacts/replay.json".to_string();
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            artifact_path.clone(),
            BundleArtifact {
                media_type: "application/json".to_string(),
                digest: hash(artifact_bytes),
                bytes_hex: hex::encode(artifact_bytes),
            },
        );
        let mut bundle = ReplayBundle {
            header: BundleHeader {
                hash_algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                chunk_count: 1,
            },
            schema_version: REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            sdk_version: SDK_VERSION.to_string(),
            bundle_id: "bundle-alpha".to_string(),
            incident_id: "incident-alpha".to_string(),
            created_at: "2026-02-21T00:00:00Z".to_string(),
            policy_version: "policy.v1".to_string(),
            verifier_identity: verifier_identity.to_string(),
            timeline: vec![TimelineEvent {
                sequence_number: 1,
                event_id: "evt-1".to_string(),
                timestamp: "2026-02-21T00:00:01Z".to_string(),
                event_type: "verification.started".to_string(),
                payload: json!({"phase": "replay"}),
                state_snapshot: json!({"step": 1}),
                causal_parent: None,
                policy_version: "policy.v1".to_string(),
            }],
            initial_state_snapshot: json!({"baseline": true}),
            evidence_refs: vec!["evidence://capsule/alpha".to_string()],
            artifacts,
            chunks: vec![BundleChunk {
                chunk_index: 0,
                total_chunks: 1,
                artifact_path,
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                payload_digest: hash(artifact_bytes),
            }],
            metadata: BTreeMap::new(),
            integrity_hash: String::new(),
            signature: BundleSignature {
                algorithm: REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                signature_hex: String::new(),
            },
        };
        seal(&mut bundle).expect("test bundle should seal");
        bundle
    }

    #[test]
    fn verify_accepts_external_verifier_identity() {
        let bundle = make_test_bundle("verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let verified = verify(&bytes).expect("external verifier identity should verify");

        assert_eq!(verified.verifier_identity, "verifier://alpha");
    }

    #[test]
    fn verify_rejects_non_verifier_identity_scheme() {
        let bundle = make_test_bundle("operator://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("non-verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_empty_verifier_identity_after_scheme() {
        let bundle = make_test_bundle("verifier://");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("empty verifier name must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_whitespace_only_verifier_identity_after_scheme() {
        let bundle = make_test_bundle("verifier://   ");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-only verifier name must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_leading_whitespace_padded_verifier_identity() {
        let bundle = make_test_bundle(" verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes)
            .expect_err("leading-whitespace-padded verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_trailing_whitespace_padded_verifier_identity() {
        let bundle = make_test_bundle("verifier://alpha ");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes)
            .expect_err("trailing-whitespace-padded verifier identity must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_embedded_spaces() {
        let bundle = make_test_bundle("verifier://alpha beta");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("embedded spaces must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_path_like_suffix() {
        let bundle = make_test_bundle("verifier://alpha/beta");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("path-like verifier names must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_verifier_identity_with_null_byte() {
        let bundle = make_test_bundle("verifier://alpha\u{0000}");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("null-byte verifier names must fail closed");

        assert!(matches!(err, BundleError::InvalidVerifierIdentity { .. }));
    }

    #[test]
    fn verify_rejects_whitespace_padded_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert(" artifacts/replay.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = " artifacts/replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("padded artifact map key must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == " artifacts/replay.json"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "artifacts/replay.json ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("padded chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts/replay.json "
        ));
    }

    #[test]
    fn verify_rejects_path_traversal_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert("../escape.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = "../escape.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("path traversal artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "../escape.json"
        ));
    }

    #[test]
    fn verify_rejects_absolute_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "/absolute/replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("absolute chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "/absolute/replay.json"
        ));
    }

    #[test]
    fn verify_rejects_backslash_artifact_map_key() {
        let mut bundle = make_test_bundle("verifier://alpha");
        let artifact = bundle
            .artifacts
            .remove("artifacts/replay.json")
            .expect("fixture artifact must exist");
        bundle
            .artifacts
            .insert("artifacts\\replay.json".to_string(), artifact);
        bundle.chunks[0].artifact_path = "artifacts\\replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("backslash artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts\\replay.json"
        ));
    }

    #[test]
    fn verify_rejects_null_byte_chunk_artifact_path() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.chunks[0].artifact_path = "artifacts/\u{0000}replay.json".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("null-byte chunk artifact path must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactPath { path } if path == "artifacts/\u{0000}replay.json"
        ));
    }

    #[test]
    fn verify_rejects_uppercase_artifact_bytes_hex() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle
            .artifacts
            .get_mut("artifacts/replay.json")
            .expect("fixture artifact must exist")
            .bytes_hex = "62756E646C652D4152544946414354".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("uppercase artifact bytes_hex must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidArtifactHex { path, source }
                if path == "artifacts/replay.json"
                    && source.contains("canonical lowercase hex")
        ));
    }

    #[test]
    fn verify_rejects_malformed_created_at_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.created_at = "not-a-timestamp".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("malformed created_at must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "created_at" && actual == "not-a-timestamp"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_created_at_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.created_at = " 2026-02-21T00:00:00Z ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded created_at must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "created_at" && actual == " 2026-02-21T00:00:00Z "
        ));
    }

    #[test]
    fn verify_rejects_malformed_timeline_timestamp() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].timestamp = "tomorrow-ish".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("malformed timeline timestamp must fail closed");

        assert!(matches!(
            err,
            BundleError::InvalidTimestamp { field, actual }
                if field == "timeline.timestamp" && actual == "tomorrow-ish"
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_bundle_id() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.bundle_id = " bundle-alpha ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded bundle_id must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "bundle_id" && actual == " bundle-alpha "
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_timeline_event_id() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].event_id = " evt-1 ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("whitespace-padded timeline.event_id must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "timeline.event_id" && actual == " evt-1 "
        ));
    }

    #[test]
    fn verify_rejects_whitespace_padded_timeline_event_type() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].event_type = " verification.started ".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err =
            verify(&bytes).expect_err("whitespace-padded timeline.event_type must fail closed");

        assert!(matches!(
            err,
            BundleError::NonCanonicalField { field, actual }
                if field == "timeline.event_type" && actual == " verification.started "
        ));
    }

    #[test]
    fn bundle_error_display_redacts_verifier_and_digest_values() {
        let verifier_error = BundleError::InvalidVerifierIdentity {
            actual: "verifier://evil\nspoof".to_string(),
        };
        let field_error = BundleError::NonCanonicalField {
            field: "bundle_id",
            actual: " bundle-alpha ".to_string(),
        };
        let timestamp_error = BundleError::InvalidTimestamp {
            field: "created_at",
            actual: "not-a-timestamp".to_string(),
        };
        let digest_error = BundleError::IntegrityMismatch {
            expected: "expected-digest".to_string(),
            actual: "actual-digest".to_string(),
        };
        let signature_error = BundleError::SignatureMismatch {
            expected: "expected-signature".to_string(),
            actual: "actual-signature".to_string(),
        };

        let verifier_display = verifier_error.to_string();
        assert!(!verifier_display.contains("verifier://evil"));
        assert!(!verifier_display.contains("spoof"));

        let field_display = field_error.to_string();
        assert!(field_display.contains("bundle_id"));
        assert!(!field_display.contains(" bundle-alpha "));

        let timestamp_display = timestamp_error.to_string();
        assert!(timestamp_display.contains("created_at"));
        assert!(!timestamp_display.contains("not-a-timestamp"));

        let digest_display = digest_error.to_string();
        assert!(digest_display.contains("redacted"));
        assert!(!digest_display.contains("expected-digest"));
        assert!(!digest_display.contains("actual-digest"));

        let signature_display = signature_error.to_string();
        assert!(signature_display.contains("redacted"));
        assert!(!signature_display.contains("expected-signature"));
        assert!(!signature_display.contains("actual-signature"));
    }

    #[test]
    fn verify_accepts_uniform_event_policy_versions() {
        let bundle = make_test_bundle("verifier://alpha");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let verified = verify(&bytes).expect("uniform policy_version should verify");

        assert_eq!(verified.policy_version, "policy.v1");
        assert_eq!(verified.timeline[0].policy_version, "policy.v1");
    }

    #[test]
    fn verify_rejects_mixed_event_policy_versions() {
        let mut bundle = make_test_bundle("verifier://alpha");
        bundle.timeline[0].policy_version = "policy.v2".to_string();
        seal(&mut bundle).expect("test bundle should reseal");
        let bytes = serialize(&bundle).expect("test bundle should serialize");

        let err = verify(&bytes).expect_err("mixed event policy_version must fail closed");

        assert!(matches!(
            err,
            BundleError::EventPolicyVersionMismatch {
                bundle_policy_version,
                event_id,
                event_policy_version,
            } if bundle_policy_version == "policy.v1"
                && event_id == "evt-1"
                && event_policy_version == "policy.v2"
        ));
    }
}
