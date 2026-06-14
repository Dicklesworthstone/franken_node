//! Proof-Carrying Host Effects — the EffectReceipt object (bd-f5b04.2.2.1, TNR
//! Phase 1 keystone).
//!
//! Every time guest code crosses into the host (`fs.read`, `fs.write`,
//! `net.connect`, `http` request, `child_process.spawn`, `require()` /
//! module resolution) the runtime emits an **EffectReceipt**: a signed,
//! content-addressed, hash-chained record that is *simultaneously* the API
//! execution record, the capability-authorization record, the replay
//! side-effect record, the CAS index for the bytes touched, and the
//! policy-decision binding. Forcing all of those to be true at one point is
//! what keeps the kernel / replay / verifier layers from drifting apart.
//!
//! The actual bytes (file contents, request/response bodies, resolver
//! snapshots) live in [`crate::storage::cas`]; the receipt carries only their
//! [`ContentHash`]es. Deterministic `verify-replay` (bd-f5b04.2.3) re-derives
//! `result_hash` from the CAS and asserts it matches.
//!
//! ## Fail-closed gating
//!
//! A receipt records the *pre-execution* policy decision. A
//! [`PolicyOutcome::Denied`] receipt has **no** `result_hash` / `post_state_hash`
//! — it is cryptographic proof that the effect was refused and *did not
//! execute*. Policy *evaluation* (remote-capability scope, SSRF/endpoint
//! checks, artifact-contract capability declarations) happens in the
//! dispatcher (bd-f5b04.2.6) and is handed to this module as a
//! [`PolicyOutcome`]; this module owns the receipt contract, canonical
//! encoding, and the tamper-evident chain.
//!
//! Chain framing mirrors the proven [`crate::vef::receipt_chain`] pattern:
//! domain-separated, length-prefixed SHA-256 with `chain_hash =
//! H(prev_chain_hash || receipt_hash)` so any tampering breaks every
//! downstream entry.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::constant_time::ct_eq;
use crate::storage::cas::ContentHash;

/// Schema/format version for the EffectReceipt wire shape. Local copy per the
/// `schema_versions` convention.
pub const EFFECT_RECEIPT_SCHEMA: &str = "effect-receipt-v1.1";
/// Deterministic placeholder for effects whose payload has no sensitive lineage.
pub const EFFECT_RECEIPT_EMPTY_LINEAGE_HASH: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Deterministic commitment for an empty label set.
pub const EFFECT_RECEIPT_EMPTY_LABEL_SET_COMMITMENT: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Domain separator for the canonical receipt preimage.
const RECEIPT_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_canonical_v1:";
/// Domain separator for the chain-hash preimage.
const CHAIN_HASH_DOMAIN: &[u8] = b"runtime_effect_receipt_chain_v1:";
/// Genesis `prev_chain_hash` for the first entry in a chain.
const CHAIN_GENESIS: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// Hard cap on entries in one in-memory chain (bounded growth).
pub const DEFAULT_MAX_CHAIN_ENTRIES: usize = 1_000_000;

/// The class of host effect a receipt describes. Each carries a fixed 1-byte
/// tag committed into the canonical preimage so the encoding is stable.
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
    /// Stable 1-byte discriminant for the canonical preimage.
    const fn tag(self) -> u8 {
        match self {
            EffectKind::FsRead => 1,
            EffectKind::FsWrite => 2,
            EffectKind::NetConnect => 3,
            EffectKind::HttpRequest => 4,
            EffectKind::Spawn => 5,
            EffectKind::ModuleResolve => 6,
        }
    }

    /// Stable string label for logs / structured events.
    pub const fn label(self) -> &'static str {
        match self {
            EffectKind::FsRead => "fs_read",
            EffectKind::FsWrite => "fs_write",
            EffectKind::NetConnect => "net_connect",
            EffectKind::HttpRequest => "http_request",
            EffectKind::Spawn => "spawn",
            EffectKind::ModuleResolve => "module_resolve",
        }
    }
}

/// The pre-execution policy decision bound into the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// The effect was authorized and executed; the capability token id that
    /// authorized it is recorded for audit.
    Allowed { capability_ref: String },
    /// The effect was refused before execution. Carries the typed refusal
    /// reason; the receipt will have no result/post-state (fail-closed proof
    /// that nothing ran).
    Denied { reason: String },
}

impl PolicyOutcome {
    const fn tag(&self) -> u8 {
        match self {
            PolicyOutcome::Allowed { .. } => 1,
            PolicyOutcome::Denied { .. } => 2,
        }
    }
}

/// Information-flow verdict bound into the effect receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowPolicyVerdict {
    /// The effect payload was label-clean at the host boundary.
    LabelClean,
    /// The payload carried forbidden labels but a scoped declassification receipt
    /// authorized this exact effect.
    Declassified,
    /// The flow policy blocked the effect before execution.
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

    pub const fn label(self) -> &'static str {
        match self {
            Self::LabelClean => "label_clean",
            Self::Declassified => "declassified",
            Self::Blocked => "blocked",
        }
    }
}

/// Lineage fields attached to an [`EffectReceipt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectLineageFields {
    pub input_lineage_hash: String,
    pub output_lineage_hash: Option<String>,
    pub label_set_commitment: String,
    pub declassification_ref: Option<String>,
    pub flow_policy_verdict: FlowPolicyVerdict,
}

impl EffectLineageFields {
    pub fn label_clean_allowed() -> Self {
        Self {
            input_lineage_hash: EFFECT_RECEIPT_EMPTY_LINEAGE_HASH.to_string(),
            output_lineage_hash: Some(EFFECT_RECEIPT_EMPTY_LINEAGE_HASH.to_string()),
            label_set_commitment: EFFECT_RECEIPT_EMPTY_LABEL_SET_COMMITMENT.to_string(),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::LabelClean,
        }
    }

    pub fn label_clean_denied() -> Self {
        Self {
            input_lineage_hash: EFFECT_RECEIPT_EMPTY_LINEAGE_HASH.to_string(),
            output_lineage_hash: None,
            label_set_commitment: EFFECT_RECEIPT_EMPTY_LABEL_SET_COMMITMENT.to_string(),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::LabelClean,
        }
    }

    pub fn declassified(
        input_lineage_hash: impl Into<String>,
        output_lineage_hash: impl Into<String>,
        label_set_commitment: impl Into<String>,
        declassification_ref: impl Into<String>,
    ) -> Self {
        Self {
            input_lineage_hash: input_lineage_hash.into(),
            output_lineage_hash: Some(output_lineage_hash.into()),
            label_set_commitment: label_set_commitment.into(),
            declassification_ref: Some(declassification_ref.into()),
            flow_policy_verdict: FlowPolicyVerdict::Declassified,
        }
    }

    pub fn blocked(
        input_lineage_hash: impl Into<String>,
        label_set_commitment: impl Into<String>,
    ) -> Self {
        Self {
            input_lineage_hash: input_lineage_hash.into(),
            output_lineage_hash: None,
            label_set_commitment: label_set_commitment.into(),
            declassification_ref: None,
            flow_policy_verdict: FlowPolicyVerdict::Blocked,
        }
    }
}

/// Errors surfaced by the effect-receipt chain. Every variant fails closed.
#[derive(Debug, thiserror::Error)]
pub enum EffectReceiptError {
    #[error("effect receipt schema mismatch: expected {expected}, got {actual:?}")]
    SchemaVersionMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("effect receipt audit field {field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("allowed effect receipt is missing its {field}")]
    AllowedMissingHash { field: &'static str },
    #[error("denied effect receipt must not carry a {field}")]
    DeniedHasHash { field: &'static str },
    #[error("effect receipt lineage field {field} must be canonical sha256:<hex>")]
    MalformedLineageHash { field: &'static str, value: String },
    #[error("effect receipt lineage policy invalid: {detail}")]
    LineagePolicyInvalid { detail: String },
    #[error("effect receipt chain is at capacity ({max} entries)")]
    CapacityExceeded { max: usize },
    #[error("chain integrity violation at index {index}: {detail}")]
    ChainIntegrity { index: u64, detail: String },
}

/// The unsigned, canonical effect record. `result_hash`/`post_state_hash` are
/// present iff the effect was `Allowed` and executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceipt {
    pub schema_version: String,
    /// Monotonic sequence within the originating workflow trace.
    pub seq: u64,
    pub trace_id: String,
    pub effect_kind: EffectKind,
    pub policy_outcome: PolicyOutcome,
    /// CAS hash of the relevant input state before the effect (e.g. file bytes
    /// read, resolver view). Always present — inputs are known even on denial.
    pub pre_state_hash: ContentHash,
    /// Canonical hash of the call arguments. Always present.
    pub args_hash: ContentHash,
    /// CAS hash of the bytes produced (file content written, response body).
    /// `None` when denied.
    pub result_hash: Option<ContentHash>,
    /// CAS hash of the relevant state after the effect. `None` when denied.
    pub post_state_hash: Option<ContentHash>,
    /// Canonical lineage-chain hash of inputs consumed by this effect.
    pub input_lineage_hash: String,
    /// Canonical lineage-chain hash after this effect. `None` when the effect
    /// did not execute.
    pub output_lineage_hash: Option<String>,
    /// Commitment to the exact label set observed at this boundary.
    pub label_set_commitment: String,
    /// Optional signed declassification receipt id authorizing this flow.
    pub declassification_ref: Option<String>,
    /// Information-flow policy verdict for the effect payload.
    pub flow_policy_verdict: FlowPolicyVerdict,
    /// UTC milliseconds the receipt was recorded (supplied by the caller's
    /// clock discipline; this module never reads the wall clock).
    pub recorded_at_millis: u64,
}

impl EffectReceipt {
    /// Build a receipt for an effect that was authorized and executed.
    #[allow(clippy::too_many_arguments)]
    pub fn allowed(
        seq: u64,
        trace_id: impl Into<String>,
        effect_kind: EffectKind,
        capability_ref: impl Into<String>,
        pre_state_hash: ContentHash,
        args_hash: ContentHash,
        result_hash: ContentHash,
        post_state_hash: ContentHash,
        recorded_at_millis: u64,
    ) -> Self {
        Self::allowed_with_lineage(
            seq,
            trace_id,
            effect_kind,
            capability_ref,
            pre_state_hash,
            args_hash,
            result_hash,
            post_state_hash,
            recorded_at_millis,
            EffectLineageFields::label_clean_allowed(),
        )
    }

    /// Build a receipt for an authorized effect with explicit lineage metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn allowed_with_lineage(
        seq: u64,
        trace_id: impl Into<String>,
        effect_kind: EffectKind,
        capability_ref: impl Into<String>,
        pre_state_hash: ContentHash,
        args_hash: ContentHash,
        result_hash: ContentHash,
        post_state_hash: ContentHash,
        recorded_at_millis: u64,
        lineage: EffectLineageFields,
    ) -> Self {
        Self {
            schema_version: EFFECT_RECEIPT_SCHEMA.to_string(),
            seq,
            trace_id: trace_id.into(),
            effect_kind,
            policy_outcome: PolicyOutcome::Allowed {
                capability_ref: capability_ref.into(),
            },
            pre_state_hash,
            args_hash,
            result_hash: Some(result_hash),
            post_state_hash: Some(post_state_hash),
            input_lineage_hash: lineage.input_lineage_hash,
            output_lineage_hash: lineage.output_lineage_hash,
            label_set_commitment: lineage.label_set_commitment,
            declassification_ref: lineage.declassification_ref,
            flow_policy_verdict: lineage.flow_policy_verdict,
            recorded_at_millis,
        }
    }

    /// Build a fail-closed receipt for an effect that was refused before
    /// execution. There is deliberately no result/post-state: the receipt is
    /// proof that nothing ran.
    pub fn denied(
        seq: u64,
        trace_id: impl Into<String>,
        effect_kind: EffectKind,
        reason: impl Into<String>,
        pre_state_hash: ContentHash,
        args_hash: ContentHash,
        recorded_at_millis: u64,
    ) -> Self {
        Self::denied_with_lineage(
            seq,
            trace_id,
            effect_kind,
            reason,
            pre_state_hash,
            args_hash,
            recorded_at_millis,
            EffectLineageFields::label_clean_denied(),
        )
    }

    /// Build a fail-closed denied receipt with explicit lineage metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn denied_with_lineage(
        seq: u64,
        trace_id: impl Into<String>,
        effect_kind: EffectKind,
        reason: impl Into<String>,
        pre_state_hash: ContentHash,
        args_hash: ContentHash,
        recorded_at_millis: u64,
        lineage: EffectLineageFields,
    ) -> Self {
        Self {
            schema_version: EFFECT_RECEIPT_SCHEMA.to_string(),
            seq,
            trace_id: trace_id.into(),
            effect_kind,
            policy_outcome: PolicyOutcome::Denied {
                reason: reason.into(),
            },
            pre_state_hash,
            args_hash,
            result_hash: None,
            post_state_hash: None,
            input_lineage_hash: lineage.input_lineage_hash,
            output_lineage_hash: lineage.output_lineage_hash,
            label_set_commitment: lineage.label_set_commitment,
            declassification_ref: lineage.declassification_ref,
            flow_policy_verdict: lineage.flow_policy_verdict,
            recorded_at_millis,
        }
    }

    /// Validate the receipt: known schema version (refuse-on-unknown, so a
    /// deserialized/cross-boundary receipt with an unexpected schema fails
    /// closed) plus the allowed/denied invariant — an `Allowed` receipt must
    /// carry a result and post-state; a `Denied` receipt must carry neither.
    pub fn validate(&self) -> Result<(), EffectReceiptError> {
        if self.schema_version != EFFECT_RECEIPT_SCHEMA {
            return Err(EffectReceiptError::SchemaVersionMismatch {
                expected: EFFECT_RECEIPT_SCHEMA,
                actual: self.schema_version.clone(),
            });
        }
        // Audit identifiers must be non-empty — a receipt with an empty
        // trace_id / capability_ref / reason is an unauditable degenerate
        // record and fails closed (matches the corpus-record validate_non_empty
        // discipline).
        if self.trace_id.trim().is_empty() {
            return Err(EffectReceiptError::EmptyField { field: "trace_id" });
        }
        validate_lineage_hash("input_lineage_hash", &self.input_lineage_hash)?;
        validate_lineage_hash("label_set_commitment", &self.label_set_commitment)?;
        if let Some(output_lineage_hash) = &self.output_lineage_hash {
            validate_lineage_hash("output_lineage_hash", output_lineage_hash)?;
        }
        if self
            .declassification_ref
            .as_ref()
            .is_some_and(|declassification_ref| declassification_ref.trim().is_empty())
        {
            return Err(EffectReceiptError::EmptyField {
                field: "declassification_ref",
            });
        }
        let is_allowed = matches!(&self.policy_outcome, PolicyOutcome::Allowed { .. });
        match &self.policy_outcome {
            PolicyOutcome::Allowed { capability_ref } => {
                if capability_ref.trim().is_empty() {
                    return Err(EffectReceiptError::EmptyField {
                        field: "capability_ref",
                    });
                }
                if self.result_hash.is_none() {
                    return Err(EffectReceiptError::AllowedMissingHash {
                        field: "result_hash",
                    });
                }
                if self.post_state_hash.is_none() {
                    return Err(EffectReceiptError::AllowedMissingHash {
                        field: "post_state_hash",
                    });
                }
                if self.output_lineage_hash.is_none() {
                    return Err(EffectReceiptError::AllowedMissingHash {
                        field: "output_lineage_hash",
                    });
                }
            }
            PolicyOutcome::Denied { reason } => {
                if reason.trim().is_empty() {
                    return Err(EffectReceiptError::EmptyField { field: "reason" });
                }
                if self.result_hash.is_some() {
                    return Err(EffectReceiptError::DeniedHasHash {
                        field: "result_hash",
                    });
                }
                if self.post_state_hash.is_some() {
                    return Err(EffectReceiptError::DeniedHasHash {
                        field: "post_state_hash",
                    });
                }
                if self.output_lineage_hash.is_some() {
                    return Err(EffectReceiptError::DeniedHasHash {
                        field: "output_lineage_hash",
                    });
                }
            }
        }
        match self.flow_policy_verdict {
            FlowPolicyVerdict::LabelClean => {
                if self.declassification_ref.is_some() {
                    return Err(EffectReceiptError::LineagePolicyInvalid {
                        detail: "label-clean effects must not carry declassification_ref"
                            .to_string(),
                    });
                }
            }
            FlowPolicyVerdict::Declassified => {
                if !is_allowed {
                    return Err(EffectReceiptError::LineagePolicyInvalid {
                        detail: "declassified flow verdict requires an allowed effect".to_string(),
                    });
                }
                if self.declassification_ref.is_none() {
                    return Err(EffectReceiptError::LineagePolicyInvalid {
                        detail: "declassified flow verdict requires declassification_ref"
                            .to_string(),
                    });
                }
            }
            FlowPolicyVerdict::Blocked => {
                if is_allowed {
                    return Err(EffectReceiptError::LineagePolicyInvalid {
                        detail: "blocked flow verdict requires a denied effect".to_string(),
                    });
                }
                if self.declassification_ref.is_some() {
                    return Err(EffectReceiptError::LineagePolicyInvalid {
                        detail: "blocked flow verdict must not carry declassification_ref"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Canonical, domain-separated, length-prefixed hash over the receipt's
    /// stable fields. Deterministic and float-free by construction (manual
    /// framing, no serde indirection).
    pub fn receipt_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(RECEIPT_HASH_DOMAIN);
        update_str(&mut h, &self.schema_version);
        h.update(self.seq.to_le_bytes());
        update_str(&mut h, &self.trace_id);
        h.update([self.effect_kind.tag()]);
        h.update([self.policy_outcome.tag()]);
        match &self.policy_outcome {
            PolicyOutcome::Allowed { capability_ref } => update_str(&mut h, capability_ref),
            PolicyOutcome::Denied { reason } => update_str(&mut h, reason),
        }
        update_str(&mut h, self.pre_state_hash.as_str());
        update_str(&mut h, self.args_hash.as_str());
        update_opt_hash(&mut h, self.result_hash.as_ref());
        update_opt_hash(&mut h, self.post_state_hash.as_ref());
        update_str(&mut h, &self.input_lineage_hash);
        update_opt_str(&mut h, self.output_lineage_hash.as_deref());
        update_str(&mut h, &self.label_set_commitment);
        update_opt_str(&mut h, self.declassification_ref.as_deref());
        h.update([self.flow_policy_verdict.tag()]);
        h.update(self.recorded_at_millis.to_le_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }
}

/// Length-prefix then absorb a string (defeats delimiter-collision on the
/// preimage).
fn update_str(h: &mut Sha256, s: &str) {
    let bytes = s.as_bytes();
    h.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    h.update(bytes);
}

/// Absorb an optional hash with a present/absent discriminant so `None` and an
/// empty string can never collide.
fn update_opt_hash(h: &mut Sha256, value: Option<&ContentHash>) {
    match value {
        Some(hash) => {
            h.update([1u8]);
            update_str(h, hash.as_str());
        }
        None => h.update([0u8]),
    }
}

fn update_opt_str(h: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            h.update([1u8]);
            update_str(h, value);
        }
        None => h.update([0u8]),
    }
}

fn validate_lineage_hash(field: &'static str, value: &str) -> Result<(), EffectReceiptError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(EffectReceiptError::MalformedLineageHash {
            field,
            value: value.to_string(),
        });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(EffectReceiptError::MalformedLineageHash {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn compute_chain_hash(index: u64, prev_chain_hash: &str, receipt_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(CHAIN_HASH_DOMAIN);
    h.update(index.to_le_bytes());
    update_str(&mut h, prev_chain_hash);
    update_str(&mut h, receipt_hash);
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// One tamper-evident entry: the receipt plus its position and chain linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceiptChainEntry {
    pub index: u64,
    pub prev_chain_hash: String,
    pub receipt_hash: String,
    pub chain_hash: String,
    pub receipt: EffectReceipt,
}

/// An append-only, hash-chained log of effect receipts for one workflow trace.
#[derive(Debug, Clone)]
pub struct EffectReceiptChain {
    entries: Vec<EffectReceiptChainEntry>,
    max_entries: usize,
}

impl Default for EffectReceiptChain {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_CHAIN_ENTRIES)
    }
}

impl EffectReceiptChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[EffectReceiptChainEntry] {
        &self.entries
    }

    /// The current chain head hash (genesis if empty).
    pub fn head_hash(&self) -> String {
        self.entries
            .last()
            .map_or_else(|| CHAIN_GENESIS.to_string(), |e| e.chain_hash.clone())
    }

    /// Validate and append a receipt, returning the new entry. Rejects an
    /// invalid (allowed-without-result / denied-with-result) receipt and a
    /// chain past capacity, both fail-closed.
    pub fn append(
        &mut self,
        receipt: EffectReceipt,
    ) -> Result<&EffectReceiptChainEntry, EffectReceiptError> {
        receipt.validate()?;
        if self.entries.len() >= self.max_entries {
            return Err(EffectReceiptError::CapacityExceeded {
                max: self.max_entries,
            });
        }
        let index = u64::try_from(self.entries.len()).unwrap_or(u64::MAX);
        let prev_chain_hash = self.head_hash();
        let receipt_hash = receipt.receipt_hash();
        let chain_hash = compute_chain_hash(index, &prev_chain_hash, &receipt_hash);
        self.entries.push(EffectReceiptChainEntry {
            index,
            prev_chain_hash,
            receipt_hash,
            chain_hash,
            receipt,
        });
        // Safe: just pushed.
        Ok(self.entries.last().expect("entry just pushed"))
    }

    /// Recompute every entry's receipt-hash, chain linkage, and index and
    /// compare (constant time) against the recorded values. Any tampering with
    /// a receipt, a hash, or the ordering fails closed.
    pub fn verify_integrity(&self) -> Result<(), EffectReceiptError> {
        Self::verify_entries_integrity(&self.entries)
    }

    /// Verify a persisted or deserialized chain entry slice without requiring
    /// callers to rebuild an [`EffectReceiptChain`] value. This is the
    /// verifier-facing form used by replay/incident tooling after entries have
    /// crossed a storage or bundle boundary.
    pub fn verify_entries_integrity(
        entries: &[EffectReceiptChainEntry],
    ) -> Result<(), EffectReceiptError> {
        let mut expected_prev = CHAIN_GENESIS.to_string();
        for (idx, entry) in entries.iter().enumerate() {
            let index = u64::try_from(idx).unwrap_or(u64::MAX);
            if entry.index != index {
                return Err(EffectReceiptError::ChainIntegrity {
                    index,
                    detail: format!("index field {} != position {index}", entry.index),
                });
            }
            if !ct_eq(&entry.prev_chain_hash, &expected_prev) {
                return Err(EffectReceiptError::ChainIntegrity {
                    index,
                    detail: "prev_chain_hash does not match prior entry".to_string(),
                });
            }
            let recomputed_receipt = entry.receipt.receipt_hash();
            if !ct_eq(&recomputed_receipt, &entry.receipt_hash) {
                return Err(EffectReceiptError::ChainIntegrity {
                    index,
                    detail: "receipt_hash does not match receipt contents".to_string(),
                });
            }
            let recomputed_chain =
                compute_chain_hash(entry.index, &entry.prev_chain_hash, &entry.receipt_hash);
            if !ct_eq(&recomputed_chain, &entry.chain_hash) {
                return Err(EffectReceiptError::ChainIntegrity {
                    index,
                    detail: "chain_hash does not match (index, prev, receipt)".to_string(),
                });
            }
            expected_prev = entry.chain_hash.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cas::content_hash;

    fn h(s: &str) -> ContentHash {
        content_hash(s.as_bytes())
    }

    fn lineage_hash(s: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(s.as_bytes())))
    }

    fn allowed(seq: u64) -> EffectReceipt {
        EffectReceipt::allowed(
            seq,
            "trace-1",
            EffectKind::FsRead,
            "cap-token-7",
            h("pre"),
            h("args"),
            h("result"),
            h("post"),
            1000 + seq,
        )
    }

    #[test]
    fn allowed_receipt_validates_and_carries_results() {
        let r = allowed(0);
        assert!(r.validate().is_ok());
        assert!(r.result_hash.is_some());
        assert!(r.post_state_hash.is_some());
        assert_eq!(r.flow_policy_verdict, FlowPolicyVerdict::LabelClean);
        assert!(r.output_lineage_hash.is_some());
        assert!(r.declassification_ref.is_none());
        assert_eq!(
            r.label_set_commitment,
            EFFECT_RECEIPT_EMPTY_LABEL_SET_COMMITMENT
        );
    }

    #[test]
    fn empty_audit_identifiers_fail_closed() {
        // Empty trace_id.
        let mut r = allowed(0);
        r.trace_id = "  ".to_string();
        assert!(matches!(
            r.validate(),
            Err(EffectReceiptError::EmptyField { field: "trace_id" })
        ));
        // Empty capability_ref on an allowed receipt.
        let r = EffectReceipt::allowed(
            0,
            "trace",
            EffectKind::FsRead,
            "",
            h("pre"),
            h("args"),
            h("result"),
            h("post"),
            0,
        );
        assert!(matches!(
            r.validate(),
            Err(EffectReceiptError::EmptyField {
                field: "capability_ref"
            })
        ));
        // Empty reason on a denied receipt.
        let r = EffectReceipt::denied(0, "trace", EffectKind::Spawn, "", h("pre"), h("args"), 0);
        assert!(matches!(
            r.validate(),
            Err(EffectReceiptError::EmptyField { field: "reason" })
        ));
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let mut r = allowed(0);
        r.schema_version = "effect-receipt-v999".to_string();
        assert!(
            matches!(
                r.validate(),
                Err(EffectReceiptError::SchemaVersionMismatch { .. })
            ),
            "a receipt with an unknown schema version must be refused"
        );
        // And it must not be appendable to a chain.
        let mut chain = EffectReceiptChain::new();
        assert!(matches!(
            chain.append(r),
            Err(EffectReceiptError::SchemaVersionMismatch { .. })
        ));
    }

    #[test]
    fn denied_receipt_is_fail_closed_no_results() {
        let r = EffectReceipt::denied(
            0,
            "trace-1",
            EffectKind::HttpRequest,
            "ssrf: endpoint in deny CIDR",
            h("pre"),
            h("args"),
            1234,
        );
        assert!(r.validate().is_ok());
        assert!(
            r.result_hash.is_none() && r.post_state_hash.is_none(),
            "a denied effect must prove nothing ran"
        );
    }

    #[test]
    fn receipt_hash_is_deterministic_and_content_sensitive() {
        let a = allowed(0).receipt_hash();
        let b = allowed(0).receipt_hash();
        assert_eq!(a, b, "same receipt hashes identically");
        let mut other = allowed(0);
        other.seq = 1;
        assert_ne!(a, other.receipt_hash(), "seq change changes the hash");
    }

    #[test]
    fn receipt_hash_commits_to_lineage_fields() {
        let baseline = allowed(0).receipt_hash();
        let receipt = EffectReceipt::allowed_with_lineage(
            0,
            "trace-1",
            EffectKind::FsRead,
            "cap-token-7",
            h("pre"),
            h("args"),
            h("result"),
            h("post"),
            1000,
            EffectLineageFields::declassified(
                lineage_hash("input"),
                lineage_hash("output"),
                lineage_hash("labels:operator_secret"),
                "ifl-declass:receipt-7",
            ),
        );
        assert!(receipt.validate().is_ok());
        assert_eq!(receipt.flow_policy_verdict, FlowPolicyVerdict::Declassified);
        assert_eq!(
            receipt.declassification_ref.as_deref(),
            Some("ifl-declass:receipt-7")
        );
        assert_ne!(
            baseline,
            receipt.receipt_hash(),
            "lineage metadata must be committed into the canonical receipt hash"
        );
    }

    #[test]
    fn declassified_verdict_requires_receipt_ref_and_allowed_effect() {
        let mut missing_ref = EffectReceipt::allowed_with_lineage(
            0,
            "trace-1",
            EffectKind::FsWrite,
            "cap-token-7",
            h("pre"),
            h("args"),
            h("result"),
            h("post"),
            1000,
            EffectLineageFields::declassified(
                lineage_hash("input"),
                lineage_hash("output"),
                lineage_hash("labels"),
                "ifl-declass:receipt-7",
            ),
        );
        missing_ref.declassification_ref = None;
        assert!(matches!(
            missing_ref.validate(),
            Err(EffectReceiptError::LineagePolicyInvalid { .. })
        ));

        let denied = EffectReceipt::denied_with_lineage(
            0,
            "trace-1",
            EffectKind::HttpRequest,
            "flow_policy: blocked",
            h("pre"),
            h("args"),
            1000,
            EffectLineageFields {
                output_lineage_hash: None,
                ..EffectLineageFields::declassified(
                    lineage_hash("input"),
                    lineage_hash("output"),
                    lineage_hash("labels"),
                    "ifl-declass:receipt-7",
                )
            },
        );
        assert!(matches!(
            denied.validate(),
            Err(EffectReceiptError::LineagePolicyInvalid { .. })
        ));
    }

    #[test]
    fn blocked_flow_verdict_requires_denied_effect_without_output_lineage() {
        let blocked = EffectReceipt::denied_with_lineage(
            0,
            "trace-1",
            EffectKind::HttpRequest,
            "flow_policy: forbidden label reached network egress",
            h("pre"),
            h("args"),
            1000,
            EffectLineageFields::blocked(lineage_hash("input"), lineage_hash("operator_secret")),
        );
        assert!(blocked.validate().is_ok());
        assert_eq!(blocked.flow_policy_verdict, FlowPolicyVerdict::Blocked);
        assert!(blocked.output_lineage_hash.is_none());
        assert!(blocked.declassification_ref.is_none());

        let allowed = EffectReceipt::allowed_with_lineage(
            0,
            "trace-1",
            EffectKind::HttpRequest,
            "cap-token-7",
            h("pre"),
            h("args"),
            h("result"),
            h("post"),
            1000,
            EffectLineageFields::blocked(lineage_hash("input"), lineage_hash("operator_secret")),
        );
        assert!(matches!(
            allowed.validate(),
            Err(EffectReceiptError::AllowedMissingHash {
                field: "output_lineage_hash"
            })
        ));
    }

    #[test]
    fn malformed_lineage_hash_fails_closed() {
        let mut receipt = allowed(0);
        receipt.label_set_commitment = "sha256:ABC".to_string();
        assert!(matches!(
            receipt.validate(),
            Err(EffectReceiptError::MalformedLineageHash {
                field: "label_set_commitment",
                ..
            })
        ));
    }

    #[test]
    fn chain_appends_and_verifies() {
        let mut chain = EffectReceiptChain::new();
        for seq in 0..5 {
            chain.append(allowed(seq)).expect("append");
        }
        assert_eq!(chain.len(), 5);
        assert!(chain.verify_integrity().is_ok());
        // Each entry links to the previous chain hash.
        assert_eq!(chain.entries()[0].prev_chain_hash, CHAIN_GENESIS);
        assert_eq!(
            chain.entries()[1].prev_chain_hash,
            chain.entries()[0].chain_hash
        );
    }

    #[test]
    fn tampering_with_a_receipt_breaks_the_chain() {
        let mut chain = EffectReceiptChain::new();
        for seq in 0..3 {
            chain.append(allowed(seq)).expect("append");
        }
        // Forge the middle receipt's trace_id without recomputing hashes.
        chain.entries[1].receipt.trace_id = "evil".to_string();
        let err = chain.verify_integrity().unwrap_err();
        assert!(
            matches!(err, EffectReceiptError::ChainIntegrity { index: 1, .. }),
            "tampered receipt must fail closed at its index, got {err:?}"
        );
    }

    #[test]
    fn reordering_entries_breaks_the_chain() {
        let mut chain = EffectReceiptChain::new();
        for seq in 0..3 {
            chain.append(allowed(seq)).expect("append");
        }
        chain.entries.swap(0, 2);
        assert!(
            chain.verify_integrity().is_err(),
            "reordered entries must fail integrity"
        );
    }

    #[test]
    fn append_rejects_invalid_receipt() {
        // An "allowed" receipt with no result must be rejected on append.
        let mut bogus = allowed(0);
        bogus.result_hash = None;
        let mut chain = EffectReceiptChain::new();
        assert!(matches!(
            chain.append(bogus),
            Err(EffectReceiptError::AllowedMissingHash { .. })
        ));
    }

    #[test]
    fn capacity_is_bounded() {
        let mut chain = EffectReceiptChain::with_capacity(2);
        chain.append(allowed(0)).expect("0");
        chain.append(allowed(1)).expect("1");
        assert!(matches!(
            chain.append(allowed(2)),
            Err(EffectReceiptError::CapacityExceeded { max: 2 })
        ));
    }

    #[test]
    fn denied_and_allowed_with_same_inputs_differ() {
        let a = allowed(0).receipt_hash();
        let d = EffectReceipt::denied(
            0,
            "trace-1",
            EffectKind::FsRead,
            "cap-token-7",
            h("pre"),
            h("args"),
            1000,
        )
        .receipt_hash();
        assert_ne!(a, d, "allowed vs denied must never share a hash");
    }
}
