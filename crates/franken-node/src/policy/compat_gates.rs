//! bd-137: Policy-visible compatibility gate APIs.
//!
//! Implements typed shim registry, mode selection with signed receipts,
//! gate evaluation returning structured allow/deny/audit decisions,
//! policy-as-data predicates, and non-interference / monotonicity
//! enforcement for compatibility shims.
//!
//! # Invariants
//!
//! - **INV-PCG-VISIBLE**: All gate decisions are visible to operators via
//!   structured responses with machine-readable rationale.
//! - **INV-PCG-AUDITABLE**: Every gate decision, mode transition, and receipt
//!   emits a structured audit event with trace correlation ID.
//! - **INV-PCG-RECEIPT**: Every divergence and mode transition produces a
//!   cryptographically signed receipt.
//! - **INV-PCG-TRANSITION**: Mode transitions are policy-gated: escalating
//!   risk requires approval; de-escalating is auto-approved but audited.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

pub(crate) const COMPAT_POLICY_PREDICATE_DOMAIN: &str = "franken_node.policy.compat.predicate.v1";
pub(crate) const COMPAT_MODE_RECEIPT_DOMAIN: &str = "franken_node.policy.compat.mode_receipt.v1";
pub(crate) const COMPAT_TRANSITION_RECEIPT_DOMAIN: &str =
    "franken_node.policy.compat.transition_receipt.v1";
pub(crate) const COMPAT_DIVERGENCE_RECEIPT_DOMAIN: &str =
    "franken_node.policy.compat.divergence_receipt.v1";
const DEFAULT_RECEIPT_TTL_SECS: u64 = 3600;

pub mod reason_codes {
    pub const POLICY_COMPAT_ALLOW: &str = "POLICY_COMPAT_ALLOW";
    pub const POLICY_COMPAT_DENY_MODE: &str = "POLICY_COMPAT_DENY_MODE";
    pub const POLICY_COMPAT_DENY_UNKNOWN_STRICT: &str = "POLICY_COMPAT_DENY_UNKNOWN_STRICT";
    pub const POLICY_COMPAT_AUDIT_UNKNOWN: &str = "POLICY_COMPAT_AUDIT_UNKNOWN";
    pub const POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE: &str =
        "POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE";
    pub const POLICY_COMPAT_INVALID_PREDICATE_SIGNATURE: &str =
        "POLICY_COMPAT_INVALID_PREDICATE_SIGNATURE";
    pub const POLICY_COMPAT_STALE_RECEIPT: &str = "POLICY_COMPAT_STALE_RECEIPT";
    pub const POLICY_COMPAT_STALE_PREDICATE: &str = "POLICY_COMPAT_STALE_PREDICATE";
    pub const POLICY_COMPAT_MODE_RECEIPT_SIGNED: &str = "POLICY_COMPAT_MODE_RECEIPT_SIGNED";
    pub const POLICY_COMPAT_SCOPE_WIDENING: &str = "POLICY_COMPAT_SCOPE_WIDENING";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilitySignatureAlgorithm {
    Ed25519,
    HmacSha256,
}

impl CompatibilitySignatureAlgorithm {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::HmacSha256 => "hmac_sha256",
        }
    }
}

impl fmt::Display for CompatibilitySignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityFreshnessState {
    Fresh,
    Stale,
    InvalidTimestamp,
}

impl CompatibilityFreshnessState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::InvalidTimestamp => "invalid_timestamp",
        }
    }
}

impl fmt::Display for CompatibilityFreshnessState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityProofMetadata {
    pub algorithm: CompatibilitySignatureAlgorithm,
    pub key_id: String,
    pub parent_receipt_id: Option<String>,
    pub attenuation_trace: Vec<String>,
    pub scope_delta: Vec<String>,
    pub reason_codes: Vec<String>,
    pub recovery_hints: Vec<String>,
    pub explanation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompiledPolicyPredicate {
    pub predicate_id: String,
    pub normalized_activation_condition: String,
    pub attenuation_trace: Vec<String>,
}

pub(crate) fn build_proof_metadata(
    algorithm: CompatibilitySignatureAlgorithm,
    parent_receipt_id: Option<String>,
    attenuation_trace: Vec<String>,
    scope_delta: Vec<String>,
    reason_codes: Vec<String>,
    recovery_hints: Vec<String>,
) -> CompatibilityProofMetadata {
    let key_id = match algorithm {
        CompatibilitySignatureAlgorithm::Ed25519 => compatibility_external_key_id(),
        CompatibilitySignatureAlgorithm::HmacSha256 => compatibility_internal_key_id(),
    };

    let explanation_digest = explanation_digest(
        &reason_codes,
        &attenuation_trace,
        &scope_delta,
        &recovery_hints,
    );

    CompatibilityProofMetadata {
        algorithm,
        key_id,
        parent_receipt_id,
        attenuation_trace,
        scope_delta,
        reason_codes,
        recovery_hints,
        explanation_digest,
    }
}

pub(crate) fn compile_policy_predicate(
    predicate_id: &str,
    activation_condition: &str,
    attenuation_trace: Vec<String>,
) -> CompiledPolicyPredicate {
    CompiledPolicyPredicate {
        predicate_id: predicate_id.to_string(),
        normalized_activation_condition: normalize_policy_expression(activation_condition),
        attenuation_trace,
    }
}

pub(crate) fn validate_scope_attenuation_for_scope(
    scope_id: &str,
    attenuation: &[AttenuationConstraint],
) -> Result<Vec<String>, String> {
    let mut scope_delta = Vec::new();
    for constraint in attenuation {
        if constraint.scope_type == "scope" && constraint.scope_value != scope_id {
            return Err(format!(
                "attenuation scope {} widens beyond active scope {}",
                constraint.scope_value, scope_id
            ));
        }
        if constraint.scope_type == "scope" {
            scope_delta.push(format!("scope:{}->{}", constraint.scope_value, scope_id));
        }
    }
    Ok(scope_delta)
}

pub(crate) fn normalize_policy_expression(expression: &str) -> String {
    let mut tokens: Vec<String> = expression
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '-' | '.')))
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect();
    tokens.sort();
    tokens.dedup();
    tokens.join("&&")
}

pub(crate) fn explanation_digest(
    reason_codes: &[String],
    attenuation_trace: &[String],
    scope_delta: &[String],
    recovery_hints: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"franken_node.policy.compat.explanation_digest.v1:");
    for segment in [reason_codes, attenuation_trace, scope_delta, recovery_hints] {
        hasher.update((u64::try_from(segment.len()).unwrap_or(u64::MAX)).to_le_bytes());
        for item in segment {
            hasher.update((u64::try_from(item.len()).unwrap_or(u64::MAX)).to_le_bytes());
            hasher.update(item.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn default_receipt_expiry_with_ttl(issued_at: &str, ttl_secs: u64) -> String {
    if ttl_secs == DEFAULT_RECEIPT_TTL_SECS {
        return default_receipt_expiry(issued_at);
    }
    DateTime::parse_from_rfc3339(issued_at)
        .map(|ts| {
            let ttl_secs = i64::try_from(ttl_secs.max(1)).unwrap_or(i64::MAX);
            (ts.with_timezone(&Utc) + Duration::seconds(ttl_secs)).to_rfc3339()
        })
        .unwrap_or_else(|_| issued_at.to_string())
}

pub(crate) fn default_receipt_expiry(issued_at: &str) -> String {
    DateTime::parse_from_rfc3339(issued_at)
        .map(|ts| {
            (ts.with_timezone(&Utc) + Duration::seconds(DEFAULT_RECEIPT_TTL_SECS as i64))
                .to_rfc3339()
        })
        .unwrap_or_else(|_| issued_at.to_string())
}

pub(crate) fn compute_freshness_state(
    issued_at: &str,
    expires_at: &str,
) -> CompatibilityFreshnessState {
    let Ok(issued) = DateTime::parse_from_rfc3339(issued_at) else {
        return CompatibilityFreshnessState::InvalidTimestamp;
    };
    let Ok(expires) = DateTime::parse_from_rfc3339(expires_at) else {
        return CompatibilityFreshnessState::InvalidTimestamp;
    };
    if expires.with_timezone(&Utc) <= issued.with_timezone(&Utc) {
        return CompatibilityFreshnessState::InvalidTimestamp;
    }
    if Utc::now() >= expires.with_timezone(&Utc) {
        CompatibilityFreshnessState::Stale
    } else {
        CompatibilityFreshnessState::Fresh
    }
}

pub(crate) fn compatibility_external_key_id() -> String {
    let vk = compatibility_policy_verifying_key();
    key_id_from_bytes(
        b"franken_node.policy.compat.external_key_id.v1:",
        vk.as_bytes(),
    )
}

pub(crate) fn compatibility_internal_key_id() -> String {
    key_id_from_bytes(
        b"franken_node.policy.compat.internal_key_id.v1:",
        &compatibility_hmac_key(),
    )
}

fn compatibility_policy_signing_key() -> SigningKey {
    SigningKey::from_bytes(&seed_from_label(
        b"franken_node.policy.compat.ed25519.seed.v1:",
    ))
}

fn compatibility_policy_verifying_key() -> VerifyingKey {
    compatibility_policy_signing_key().verifying_key()
}

fn compatibility_hmac_key() -> [u8; 32] {
    seed_from_label(b"franken_node.policy.compat.hmac.seed.v1:")
}

fn seed_from_label(label: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(label);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    seed
}

fn key_id_from_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let digest = Sha256::digest([domain, bytes].concat());
    hex::encode(&digest[..8])
}

fn canonicalize_compat_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut canonical = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical.insert(key, canonicalize_compat_value(nested));
            }
            serde_json::Value::Object(canonical)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_compat_value).collect())
        }
        other => other,
    }
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_value(value)?;
    let canonical = canonicalize_compat_value(json);
    serde_json::to_vec(&canonical)
}

fn signature_preimage<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let canonical_payload = canonical_json_bytes(value)?;
    let mut preimage = Vec::with_capacity(16 + domain.len() + canonical_payload.len());
    preimage.extend_from_slice(b"compat_preimage_v1:");
    preimage.extend_from_slice(&(u64::try_from(domain.len()).unwrap_or(u64::MAX)).to_le_bytes());
    preimage.extend_from_slice(domain.as_bytes());
    preimage.extend_from_slice(&(u64::try_from(canonical_payload.len()).unwrap_or(u64::MAX)).to_le_bytes());
    preimage.extend_from_slice(&canonical_payload);
    Ok(preimage)
}

pub(crate) fn sign_ed25519_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, serde_json::Error> {
    let preimage = signature_preimage(domain, value)?;
    let signature = compatibility_policy_signing_key().sign(&preimage);
    Ok(hex::encode(signature.to_bytes()))
}

pub(crate) fn verify_ed25519_canonical<T: Serialize>(
    domain: &str,
    value: &T,
    signature_hex: &str,
    key_id: &str,
) -> bool {
    if !crate::security::constant_time::ct_eq(key_id, &compatibility_external_key_id()) {
        return false;
    }
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(signature_array) = <[u8; 64]>::try_from(signature_bytes.as_slice()) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    let Ok(preimage) = signature_preimage(domain, value) else {
        return false;
    };
    compatibility_policy_verifying_key()
        .verify(&preimage, &signature)
        .is_ok()
}

pub(crate) fn sign_hmac_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, serde_json::Error> {
    let preimage = signature_preimage(domain, value)?;
    let Ok(mut mac) = HmacSha256::new_from_slice(&compatibility_hmac_key()) else {
        return Ok(String::new());
    };
    mac.update(&preimage);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub(crate) fn verify_hmac_canonical<T: Serialize>(
    domain: &str,
    value: &T,
    signature_hex: &str,
    key_id: &str,
) -> bool {
    if !crate::security::constant_time::ct_eq(key_id, &compatibility_internal_key_id()) {
        return false;
    }
    let Ok(expected) = sign_hmac_canonical(domain, value) else {
        return false;
    };
    crate::security::constant_time::ct_eq(signature_hex, &expected)
}

fn authority_cache_key<T: Serialize>(
    domain: &str,
    value: &T,
    signature_hex: &str,
    key_id: &str,
) -> Result<String, serde_json::Error> {
    let preimage = signature_preimage(domain, value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"compat_authority_cache_v1:");
    hasher.update((u64::try_from(preimage.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(&preimage);
    hasher.update((u64::try_from(signature_hex.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(signature_hex.as_bytes());
    hasher.update((u64::try_from(key_id.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(key_id.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

// ── Event Codes ──────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Gate check passed: package/extension allowed under requested mode.
    pub const PCG_GATE_PASS: &str = "PCG-001";
    /// Gate check failed: package/extension denied with rationale.
    pub const PCG_GATE_DENY: &str = "PCG-002";
    /// Mode transition approved with signed receipt.
    pub const PCG_MODE_TRANSITION: &str = "PCG-003";
    /// Divergence receipt issued.
    pub const PCG_RECEIPT_ISSUED: &str = "PCG-004";
    /// Gate check resulted in audit (allow with observation).
    pub const PCG_GATE_AUDIT: &str = "PCG-005";
    /// Non-interference violation detected.
    pub const PCG_NONINTERFERENCE_VIOLATION: &str = "PCG-006";
    /// Monotonicity violation detected.
    pub const PCG_MONOTONICITY_VIOLATION: &str = "PCG-007";
    /// Shim registered in registry.
    pub const PCG_SHIM_REGISTERED: &str = "PCG-008";
}

// ── Compatibility Bands ──────────────────────────────────────────────────────

/// Compatibility band classifying API surface areas by priority and risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompatibilityBand {
    /// Foundation APIs (fs, path, process, Buffer, etc.) — highest priority.
    Core,
    /// Frequently-used patterns (http, crypto, timers, url).
    HighValue,
    /// Corner cases, undocumented behaviors, platform quirks.
    Edge,
    /// Dangerous behaviors (eval variants, unchecked native access) — lowest.
    Unsafe,
}

impl CompatibilityBand {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::HighValue => "high_value",
            Self::Edge => "edge",
            Self::Unsafe => "unsafe",
        }
    }

    /// Priority level (higher = more critical).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Core => 4,
            Self::HighValue => 3,
            Self::Edge => 2,
            Self::Unsafe => 1,
        }
    }
}

impl fmt::Display for CompatibilityBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Compatibility Modes ──────────────────────────────────────────────────────

/// Operator-selected compatibility mode governing divergence handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompatibilityMode {
    /// Only verified-compatible behaviors allowed. No shims activated.
    Strict,
    /// Tested shims activated with monitoring. Divergences produce warnings.
    Balanced,
    /// All available shims activated. Divergences tolerated with receipts.
    LegacyRisky,
}

impl CompatibilityMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy_risky",
        }
    }

    /// Risk level (higher = more risk).
    pub fn risk_level(&self) -> u8 {
        match self {
            Self::Strict => 1,
            Self::Balanced => 2,
            Self::LegacyRisky => 3,
        }
    }

    /// Whether transitioning from `self` to `target` escalates risk.
    pub fn is_escalation_to(&self, target: CompatibilityMode) -> bool {
        target.risk_level() > self.risk_level()
    }
}

impl fmt::Display for CompatibilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Band-Mode Policy Matrix ─────────────────────────────────────────────────

/// What happens when a divergence is detected for a given band+mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceAction {
    /// Divergence blocks execution.
    Error,
    /// Warning emitted, receipt generated, execution continues.
    Warn,
    /// Logged with receipt, no warning surfaced.
    Log,
    /// Shim/divergence is blocked entirely.
    Blocked,
}

impl DivergenceAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Log => "log",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for DivergenceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Look up the divergence action for a (band, mode) pair.
/// This encodes the mode-band matrix from bd-2wz.
pub fn divergence_action(band: CompatibilityBand, mode: CompatibilityMode) -> DivergenceAction {
    match (band, mode) {
        // Core band: always error on divergence
        (CompatibilityBand::Core, _) => DivergenceAction::Error,

        // High-value band
        (CompatibilityBand::HighValue, CompatibilityMode::Strict) => DivergenceAction::Error,
        (CompatibilityBand::HighValue, CompatibilityMode::Balanced) => DivergenceAction::Warn,
        (CompatibilityBand::HighValue, CompatibilityMode::LegacyRisky) => DivergenceAction::Warn,

        // Edge band
        (CompatibilityBand::Edge, CompatibilityMode::Strict) => DivergenceAction::Warn,
        (CompatibilityBand::Edge, CompatibilityMode::Balanced) => DivergenceAction::Log,
        (CompatibilityBand::Edge, CompatibilityMode::LegacyRisky) => DivergenceAction::Log,

        // Unsafe band
        (CompatibilityBand::Unsafe, CompatibilityMode::Strict) => DivergenceAction::Blocked,
        (CompatibilityBand::Unsafe, CompatibilityMode::Balanced) => DivergenceAction::Blocked,
        (CompatibilityBand::Unsafe, CompatibilityMode::LegacyRisky) => DivergenceAction::Warn,
    }
}

// ── Risk Category ────────────────────────────────────────────────────────────

/// Risk category for a compatibility shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShimRiskCategory {
    Low,
    Medium,
    High,
    Critical,
}

impl ShimRiskCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ShimRiskCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Shim Registry ────────────────────────────────────────────────────────────

/// A registered compatibility shim with full typed metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimRegistryEntry {
    /// Unique identifier for this shim.
    pub shim_id: String,
    /// Human-readable description of the shimmed behavior.
    pub description: String,
    /// Which compatibility band this shim belongs to.
    pub band: CompatibilityBand,
    /// Risk category.
    pub risk_category: ShimRiskCategory,
    /// The activation policy predicate ID controlling this shim.
    pub activation_policy_id: String,
    /// Rationale for why this divergence exists.
    pub divergence_rationale: String,
    /// Node/Bun API family (e.g. "fs", "http", "crypto").
    pub api_family: String,
    /// Whether this shim is currently active (subject to mode).
    pub active: bool,
}

/// Registry of all compatibility shims. Queryable with full metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShimRegistry {
    entries: Vec<ShimRegistryEntry>,
    index: BTreeMap<String, usize>,
}

impl ShimRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    /// Register a new shim. Returns Err if shim_id already exists.
    pub fn register(&mut self, entry: ShimRegistryEntry) -> Result<(), CompatGateError> {
        if self.index.contains_key(&entry.shim_id) {
            return Err(CompatGateError::DuplicateShim {
                shim_id: entry.shim_id.clone(),
            });
        }
        push_bounded(&mut self.entries, entry, MAX_ENTRIES);
        // Rebuild index to account for possible eviction shifting indices
        self.index.clear();
        for (i, e) in self.entries.iter().enumerate() {
            self.index.insert(e.shim_id.clone(), i);
        }
        Ok(())
    }

    /// Look up a shim by ID.
    pub fn get(&self, shim_id: &str) -> Option<&ShimRegistryEntry> {
        self.index.get(shim_id).map(|&idx| &self.entries[idx])
    }

    /// Return all registered shims.
    pub fn all(&self) -> &[ShimRegistryEntry] {
        &self.entries
    }

    /// Filter shims by band.
    pub fn by_band(&self, band: CompatibilityBand) -> Vec<&ShimRegistryEntry> {
        self.entries.iter().filter(|e| e.band == band).collect()
    }

    /// Filter shims by API family.
    pub fn by_api_family(&self, family: &str) -> Vec<&ShimRegistryEntry> {
        self.entries
            .iter()
            .filter(|e| e.api_family == family)
            .collect()
    }

    /// Number of registered shims.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List shims that would be active under a given mode.
    pub fn active_under_mode(&self, mode: CompatibilityMode) -> Vec<&ShimRegistryEntry> {
        self.entries
            .iter()
            .filter(|e| {
                let action = divergence_action(e.band, mode);
                !matches!(action, DivergenceAction::Blocked | DivergenceAction::Error)
            })
            .collect()
    }
}

// ── Policy Predicate ─────────────────────────────────────────────────────────

/// A machine-verifiable policy predicate constraining shim activation.
/// Per 9B.5: cryptographically signed with attenuation semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPredicate {
    /// Unique identifier for this predicate.
    pub predicate_id: String,
    /// Hex-encoded signature over the predicate body.
    pub signature: String,
    /// Scope-limiting attenuation constraints.
    pub attenuation: Vec<AttenuationConstraint>,
    /// Boolean condition for activation (serialized expression).
    pub activation_condition: String,
    /// RFC3339 timestamp when the predicate was signed.
    pub issued_at: String,
    /// RFC3339 timestamp after which the predicate is stale.
    pub expires_at: String,
    /// Structured proof metadata emitted with every predicate.
    pub proof: CompatibilityProofMetadata,
}

/// A scope-limiting constraint that narrows predicate applicability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttenuationConstraint {
    pub scope_type: String,
    pub scope_value: String,
}

#[derive(Debug, Serialize)]
struct PolicyPredicateSigningPayload<'a> {
    predicate_id: &'a str,
    attenuation: &'a [AttenuationConstraint],
    activation_condition: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    proof: &'a CompatibilityProofMetadata,
}

impl<'a> From<&'a PolicyPredicate> for PolicyPredicateSigningPayload<'a> {
    fn from(value: &'a PolicyPredicate) -> Self {
        Self {
            predicate_id: &value.predicate_id,
            attenuation: &value.attenuation,
            activation_condition: &value.activation_condition,
            issued_at: &value.issued_at,
            expires_at: &value.expires_at,
            proof: &value.proof,
        }
    }
}

impl PolicyPredicate {
    pub fn verify_signature(&self) -> bool {
        if compute_freshness_state(&self.issued_at, &self.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return false;
        }
        verify_ed25519_canonical(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &PolicyPredicateSigningPayload::from(self),
            &self.signature,
            &self.proof.key_id,
        )
    }

    pub(crate) fn compile(&self) -> CompiledPolicyPredicate {
        compile_policy_predicate(
            &self.predicate_id,
            &self.activation_condition,
            self.attenuation
                .iter()
                .map(|constraint| format!("{}={}", constraint.scope_type, constraint.scope_value))
                .collect(),
        )
    }

    pub fn freshness_state(&self) -> CompatibilityFreshnessState {
        compute_freshness_state(&self.issued_at, &self.expires_at)
    }

    /// Check if the predicate applies to the given scope.
    pub fn applies_to_scope(&self, scope_type: &str, scope_value: &str) -> bool {
        if self.attenuation.is_empty() {
            return true; // No attenuation = universal
        }
        self.attenuation
            .iter()
            .any(|a| a.scope_type == scope_type && a.scope_value == scope_value)
    }
}

// ── Gate Decision ────────────────────────────────────────────────────────────

/// Decision returned by the compatibility gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateDecision {
    /// Operation allowed under current policy.
    Allow,
    /// Operation denied — rationale explains why.
    Deny,
    /// Operation allowed but under observation (audit trail generated).
    Audit,
}

impl GateDecision {
    pub fn event_code(&self) -> &'static str {
        match self {
            Self::Allow => event_codes::PCG_GATE_PASS,
            Self::Deny => event_codes::PCG_GATE_DENY,
            Self::Audit => event_codes::PCG_GATE_AUDIT,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
        }
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Gate Check Result ────────────────────────────────────────────────────────

/// Full result of a gate evaluation including rationale and audit metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCheckResult {
    /// The decision: allow, deny, or audit.
    pub decision: GateDecision,
    /// Machine-readable rationale explaining the decision.
    pub rationale: Vec<String>,
    /// Trace correlation ID for audit trail linkage.
    pub trace_id: String,
    /// Unique receipt ID if a receipt was generated.
    pub receipt_id: Option<String>,
    /// The package/shim that was evaluated.
    pub package_id: String,
    /// The mode under which evaluation occurred.
    pub mode: CompatibilityMode,
    /// The scope in which evaluation occurred.
    pub scope_id: String,
    /// Event code emitted.
    pub event_code: String,
    /// Stable reason codes for allow/deny/audit outcomes.
    pub reason_codes: Vec<String>,
    /// Machine-readable explanation of attenuation applied to the request.
    pub attenuation_trace: Vec<String>,
    /// Human-readable delta between parent and derived scope.
    pub scope_delta: Vec<String>,
    /// Current freshness state of the authority material consulted.
    pub freshness_state: CompatibilityFreshnessState,
    /// Recovery hints for operators.
    pub recovery_hints: Vec<String>,
    /// Digest of the explanation bundle for stable correlation.
    pub explanation_digest: String,
}

// ── Mode Selection Receipt ───────────────────────────────────────────────────

/// A signed receipt recording a mode selection or transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSelectionReceipt {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Scope this mode applies to.
    pub scope_id: String,
    /// The selected mode.
    pub mode: CompatibilityMode,
    /// Previous mode (None if first selection).
    pub previous_mode: Option<CompatibilityMode>,
    /// When the mode was activated.
    pub activated_at: String,
    /// RFC3339 time after which the receipt is stale.
    pub expires_at: String,
    /// Hex-encoded signature over receipt body.
    pub signature: String,
    /// Who requested the transition.
    pub requestor: String,
    /// Justification for the transition.
    pub justification: String,
    /// Whether approval was required (true for escalations).
    pub approval_required: bool,
    /// Whether the transition was approved.
    pub approved: bool,
    /// Structured proof metadata emitted with every receipt.
    pub proof: CompatibilityProofMetadata,
}

#[derive(Debug, Serialize)]
struct ModeSelectionReceiptSigningPayload<'a> {
    receipt_id: &'a str,
    scope_id: &'a str,
    mode: CompatibilityMode,
    previous_mode: Option<CompatibilityMode>,
    activated_at: &'a str,
    expires_at: &'a str,
    requestor: &'a str,
    justification: &'a str,
    approval_required: bool,
    approved: bool,
    proof: &'a CompatibilityProofMetadata,
}

impl<'a> From<&'a ModeSelectionReceipt> for ModeSelectionReceiptSigningPayload<'a> {
    fn from(value: &'a ModeSelectionReceipt) -> Self {
        Self {
            receipt_id: &value.receipt_id,
            scope_id: &value.scope_id,
            mode: value.mode,
            previous_mode: value.previous_mode,
            activated_at: &value.activated_at,
            expires_at: &value.expires_at,
            requestor: &value.requestor,
            justification: &value.justification,
            approval_required: value.approval_required,
            approved: value.approved,
            proof: &value.proof,
        }
    }
}

impl ModeSelectionReceipt {
    pub fn verify_signature(&self) -> bool {
        if compute_freshness_state(&self.activated_at, &self.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return false;
        }
        verify_hmac_canonical(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(self),
            &self.signature,
            &self.proof.key_id,
        )
    }

    pub fn freshness_state(&self) -> CompatibilityFreshnessState {
        compute_freshness_state(&self.activated_at, &self.expires_at)
    }
}

// ── Scope Config ─────────────────────────────────────────────────────────────

/// Per-scope compatibility configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    pub scope_id: String,
    pub mode: CompatibilityMode,
    pub receipt: ModeSelectionReceipt,
    pub policy_predicates: Vec<PolicyPredicate>,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Error type for compatibility gate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompatGateError {
    /// Shim ID already exists in registry.
    DuplicateShim { shim_id: String },
    /// Scope not found.
    ScopeNotFound { scope_id: String },
    /// Mode transition denied (escalation without approval).
    TransitionDenied {
        from: String,
        to: String,
        reason: String,
    },
    /// Non-interference violation detected.
    NonInterferenceViolation {
        scope_a: String,
        scope_b: String,
        detail: String,
    },
    /// Monotonicity violation detected.
    MonotonicityViolation { shim_id: String, detail: String },
    /// Invalid policy predicate.
    InvalidPredicate {
        predicate_id: String,
        reason: String,
    },
    /// Internal sequence counter exhausted.
    CounterExhausted { counter: String },
    /// Package not found.
    PackageNotFound { package_id: String },
}

impl fmt::Display for CompatGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateShim { shim_id } => {
                write!(f, "duplicate shim: {shim_id}")
            }
            Self::ScopeNotFound { scope_id } => {
                write!(f, "scope not found: {scope_id}")
            }
            Self::TransitionDenied { from, to, reason } => {
                write!(f, "mode transition denied ({from} -> {to}): {reason}")
            }
            Self::NonInterferenceViolation {
                scope_a,
                scope_b,
                detail,
            } => {
                write!(
                    f,
                    "non-interference violation between {scope_a} and {scope_b}: {detail}"
                )
            }
            Self::MonotonicityViolation { shim_id, detail } => {
                write!(f, "monotonicity violation for shim {shim_id}: {detail}")
            }
            Self::InvalidPredicate {
                predicate_id,
                reason,
            } => {
                write!(f, "invalid predicate {predicate_id}: {reason}")
            }
            Self::CounterExhausted { counter } => {
                write!(f, "counter exhausted: {counter}")
            }
            Self::PackageNotFound { package_id } => {
                write!(f, "package not found: {package_id}")
            }
        }
    }
}

impl std::error::Error for CompatGateError {}

// ── Gate Evaluator ───────────────────────────────────────────────────────────

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_ENTRIES, MAX_RECEIPTS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

/// The compatibility gate evaluator. Central entry point for gate checks,
/// mode queries, and shim registry queries.
#[derive(Debug, Clone)]
pub struct CompatGateEvaluator {
    registry: ShimRegistry,
    scopes: BTreeMap<String, ScopeConfig>,
    audit_log: Vec<GateCheckResult>,
    receipts: Vec<ModeSelectionReceipt>,
    receipt_ttl_secs: u64,
    compiled_predicates: BTreeMap<String, CompiledPolicyPredicate>,
    validated_receipts: BTreeMap<String, String>,
    validated_predicates: BTreeMap<String, String>,
    next_receipt_seq: u64,
    next_audit_seq: u64,
    receipt_seq_exhausted: bool,
    audit_seq_exhausted: bool,
}

impl CompatGateEvaluator {
    pub fn new(registry: ShimRegistry) -> Self {
        Self::with_receipt_ttl(registry, DEFAULT_RECEIPT_TTL_SECS)
    }

    pub fn with_receipt_ttl(registry: ShimRegistry, receipt_ttl_secs: u64) -> Self {
        Self {
            registry,
            scopes: BTreeMap::new(),
            audit_log: Vec::new(),
            receipts: Vec::new(),
            receipt_ttl_secs: receipt_ttl_secs.max(1),
            compiled_predicates: BTreeMap::new(),
            validated_receipts: BTreeMap::new(),
            validated_predicates: BTreeMap::new(),
            next_receipt_seq: 0,
            next_audit_seq: 0,
            receipt_seq_exhausted: false,
            audit_seq_exhausted: false,
        }
    }

    pub fn from_compatibility_config(
        registry: ShimRegistry,
        config: &crate::config::CompatibilityConfig,
    ) -> Self {
        Self::with_receipt_ttl(registry, config.default_receipt_ttl_secs)
    }

    /// Get a reference to the shim registry.
    pub fn registry(&self) -> &ShimRegistry {
        &self.registry
    }

    fn next_receipt_sequence(&mut self) -> Result<u64, CompatGateError> {
        if self.receipt_seq_exhausted {
            return Err(CompatGateError::CounterExhausted {
                counter: "receipt_sequence".to_string(),
            });
        }

        let sequence = self.next_receipt_seq;
        if let Some(next) = self.next_receipt_seq.checked_add(1) {
            self.next_receipt_seq = next;
        } else {
            self.receipt_seq_exhausted = true;
        }
        Ok(sequence)
    }

    fn next_audit_sequence(&mut self) -> Result<u64, CompatGateError> {
        if self.audit_seq_exhausted {
            return Err(CompatGateError::CounterExhausted {
                counter: "audit_sequence".to_string(),
            });
        }

        let sequence = self.next_audit_seq;
        if let Some(next) = self.next_audit_seq.checked_add(1) {
            self.next_audit_seq = next;
        } else {
            self.audit_seq_exhausted = true;
        }
        Ok(sequence)
    }

    // ── Mode Management ──

    /// Set the compatibility mode for a scope. Produces a signed receipt.
    /// Escalations (increasing risk level) require `approval` to be true.
    pub fn set_mode(
        &mut self,
        scope_id: &str,
        mode: CompatibilityMode,
        requestor: &str,
        justification: &str,
        approval: bool,
    ) -> Result<ModeSelectionReceipt, CompatGateError> {
        let previous_mode = self.scopes.get(scope_id).map(|s| s.mode);

        // Check escalation policy
        if let Some(prev) = previous_mode
            && prev.is_escalation_to(mode)
            && !approval
        {
            return Err(CompatGateError::TransitionDenied {
                from: prev.label().to_string(),
                to: mode.label().to_string(),
                reason: "escalation requires explicit approval".to_string(),
            });
        }

        let activated_at = Utc::now().to_rfc3339();
        let expires_at = default_receipt_expiry_with_ttl(&activated_at, self.receipt_ttl_secs);
        let scope_delta = match previous_mode {
            Some(prev) if prev != mode => vec![format!("mode:{}->{}", prev.label(), mode.label())],
            Some(prev) => vec![format!("mode:{}->{}", prev.label(), mode.label())],
            None => vec![format!("mode:unset->{}", mode.label())],
        };
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::HmacSha256,
            None,
            vec![format!("scope={scope_id}")],
            scope_delta,
            vec![reason_codes::POLICY_COMPAT_MODE_RECEIPT_SIGNED.to_string()],
            vec!["request explicit approval before risk escalation".to_string()],
        );
        let seq = self.next_receipt_sequence()?;
        let mut receipt = ModeSelectionReceipt {
            receipt_id: format!("rcpt-{}-{}", scope_id, seq),
            scope_id: scope_id.to_string(),
            mode,
            previous_mode,
            activated_at,
            expires_at,
            signature: String::new(),
            requestor: requestor.to_string(),
            justification: justification.to_string(),
            approval_required: previous_mode.is_some_and(|p| p.is_escalation_to(mode)),
            approved: approval,
            proof,
        };
        receipt.signature = sign_hmac_canonical(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&receipt),
        )
        .map_err(|reason| CompatGateError::InvalidPredicate {
            predicate_id: format!("mode-receipt:{scope_id}"),
            reason: format!("failed canonicalizing receipt payload: {reason}"),
        })?;

        let scope_config = ScopeConfig {
            scope_id: scope_id.to_string(),
            mode,
            receipt: receipt.clone(),
            policy_predicates: Vec::new(),
        };

        let receipt_cache_key = authority_cache_key(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&receipt),
            &receipt.signature,
            &receipt.proof.key_id,
        )
        .map_err(|reason| CompatGateError::InvalidPredicate {
            predicate_id: format!("mode-receipt:{scope_id}"),
            reason: format!("failed to canonicalize receipt cache key: {reason}"),
        })?;

        self.scopes.insert(scope_id.to_string(), scope_config);
        push_bounded(&mut self.receipts, receipt.clone(), MAX_RECEIPTS);
        self.validated_receipts
            .insert(scope_id.to_string(), receipt_cache_key);
        tracing::info!(
            event_code = %event_codes::PCG_MODE_TRANSITION,
            scope_id = scope_id,
            receipt_id = %receipt.receipt_id,
            mode = %receipt.mode,
            previous_mode = ?receipt.previous_mode,
            approved = receipt.approved,
            "compatibility mode receipt issued"
        );
        Ok(receipt)
    }

    pub fn add_policy_predicate(
        &mut self,
        scope_id: &str,
        predicate: PolicyPredicate,
    ) -> Result<(), CompatGateError> {
        if !predicate.verify_signature() {
            return Err(CompatGateError::InvalidPredicate {
                predicate_id: predicate.predicate_id.clone(),
                reason: "signature verification failed or predicate is stale".to_string(),
            });
        }

        validate_scope_attenuation_for_scope(scope_id, &predicate.attenuation).map_err(
            |reason| CompatGateError::InvalidPredicate {
                predicate_id: predicate.predicate_id.clone(),
                reason,
            },
        )?;

        let Some(scope) = self.scopes.get(scope_id) else {
            return Err(CompatGateError::ScopeNotFound {
                scope_id: scope_id.to_string(),
            });
        };
        if scope.policy_predicates.len() >= MAX_ENTRIES {
            return Err(CompatGateError::InvalidPredicate {
                predicate_id: predicate.predicate_id.clone(),
                reason: format!("scope policy predicate set at capacity ({MAX_ENTRIES} entries)"),
            });
        }

        let compiled = predicate.compile();
        self.compiled_predicates
            .insert(predicate.predicate_id.clone(), compiled);
        let predicate_cache_key = authority_cache_key(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &PolicyPredicateSigningPayload::from(&predicate),
            &predicate.signature,
            &predicate.proof.key_id,
        )
        .map_err(|reason| CompatGateError::InvalidPredicate {
            predicate_id: predicate.predicate_id.clone(),
            reason: format!("failed to canonicalize predicate cache key: {reason}"),
        })?;

        let scope =
            self.scopes
                .get_mut(scope_id)
                .ok_or_else(|| CompatGateError::ScopeNotFound {
                    scope_id: scope_id.to_string(),
                })?;
        let predicate_id = predicate.predicate_id.clone();
        scope.policy_predicates.push(predicate);
        self.validated_predicates
            .insert(predicate_id, predicate_cache_key);
        tracing::info!(
            event_code = %event_codes::PCG_RECEIPT_ISSUED,
            scope_id = scope_id,
            predicate_count = scope.policy_predicates.len(),
            "compatibility policy predicate registered"
        );
        Ok(())
    }

    /// Get the current mode for a scope.
    pub fn get_mode(&self, scope_id: &str) -> Option<CompatibilityMode> {
        self.scopes.get(scope_id).map(|s| s.mode)
    }

    /// Get the scope configuration.
    pub fn get_scope(&self, scope_id: &str) -> Option<&ScopeConfig> {
        self.scopes.get(scope_id)
    }

    // ── Gate Evaluation ──

    /// Evaluate whether a package/extension may operate under the compatibility
    /// mode configured for the given scope. Returns structured decision.
    ///
    /// [PCG-001] gate pass, [PCG-002] gate deny, [PCG-005] gate audit.
    pub fn evaluate_gate(
        &mut self,
        package_id: &str,
        scope_id: &str,
        trace_id: &str,
    ) -> Result<GateCheckResult, CompatGateError> {
        let audit_seq = self.next_audit_sequence()?;
        let (mode, scope_receipt, scope_predicates) = {
            let scope =
                self.scopes
                    .get(scope_id)
                    .ok_or_else(|| CompatGateError::ScopeNotFound {
                        scope_id: scope_id.to_string(),
                    })?;
            (
                scope.mode,
                scope.receipt.clone(),
                scope.policy_predicates.clone(),
            )
        };
        let mut rationale = Vec::new();
        let mut reason_codes = Vec::new();
        let mut attenuation_trace = Vec::new();
        let mut scope_delta = vec![format!("scope={scope_id}")];
        let mut recovery_hints = Vec::new();
        let mut freshness_state = scope_receipt.freshness_state();

        if freshness_state != CompatibilityFreshnessState::Fresh {
            rationale.push(format!(
                "scope receipt {} is {}",
                scope_receipt.receipt_id,
                freshness_state.label()
            ));
            reason_codes.push(reason_codes::POLICY_COMPAT_STALE_RECEIPT.to_string());
            recovery_hints.push(
                "re-issue the scope mode receipt before evaluating compatibility".to_string(),
            );
            let explanation_digest = explanation_digest(
                &reason_codes,
                &attenuation_trace,
                &scope_delta,
                &recovery_hints,
            );
            let result = GateCheckResult {
                decision: GateDecision::Deny,
                rationale,
                trace_id: trace_id.to_string(),
                receipt_id: Some(scope_receipt.receipt_id.clone()),
                package_id: package_id.to_string(),
                mode,
                scope_id: scope_id.to_string(),
                event_code: GateDecision::Deny.event_code().to_string(),
                reason_codes,
                attenuation_trace,
                scope_delta,
                freshness_state,
                recovery_hints,
                explanation_digest,
            };
            tracing::info!(
                event_code = %result.event_code,
                trace_id = %result.trace_id,
                scope_id = %result.scope_id,
                package_id = %result.package_id,
                decision = %result.decision,
                reason_codes = ?result.reason_codes,
                freshness_state = %result.freshness_state,
                "compatibility gate evaluated"
            );
            push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
            return Ok(result);
        }

        let receipt_cache_key = authority_cache_key(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&scope_receipt),
            &scope_receipt.signature,
            &scope_receipt.proof.key_id,
        )
        .map_err(|reason| CompatGateError::InvalidPredicate {
            predicate_id: format!("mode-receipt:{scope_id}"),
            reason: format!("failed to canonicalize receipt cache key: {reason}"),
        })?;
        let receipt_cached = self.validated_receipts.get(scope_id).is_some_and(|cached| {
            crate::security::constant_time::ct_eq(cached, &receipt_cache_key)
        });

        if !receipt_cached && !scope_receipt.verify_signature() {
            rationale.push(format!(
                "scope receipt {} failed signature verification",
                scope_receipt.receipt_id
            ));
            reason_codes.push(reason_codes::POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE.to_string());
            recovery_hints.push(
                "re-sign the scope mode receipt with the canonical internal authenticator"
                    .to_string(),
            );
            let explanation_digest = explanation_digest(
                &reason_codes,
                &attenuation_trace,
                &scope_delta,
                &recovery_hints,
            );
            let result = GateCheckResult {
                decision: GateDecision::Deny,
                rationale,
                trace_id: trace_id.to_string(),
                receipt_id: Some(scope_receipt.receipt_id.clone()),
                package_id: package_id.to_string(),
                mode,
                scope_id: scope_id.to_string(),
                event_code: GateDecision::Deny.event_code().to_string(),
                reason_codes,
                attenuation_trace,
                scope_delta,
                freshness_state,
                recovery_hints,
                explanation_digest,
            };
            tracing::info!(
                event_code = %result.event_code,
                trace_id = %result.trace_id,
                scope_id = %result.scope_id,
                package_id = %result.package_id,
                decision = %result.decision,
                reason_codes = ?result.reason_codes,
                freshness_state = %result.freshness_state,
                "compatibility gate evaluated"
            );
            push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
            return Ok(result);
        }
        self.validated_receipts
            .insert(scope_id.to_string(), receipt_cache_key);

        for predicate in &scope_predicates {
            freshness_state = predicate.freshness_state();
            if freshness_state != CompatibilityFreshnessState::Fresh {
                rationale.push(format!(
                    "predicate {} is {}",
                    predicate.predicate_id,
                    freshness_state.label()
                ));
                reason_codes.push(reason_codes::POLICY_COMPAT_STALE_PREDICATE.to_string());
                recovery_hints.push(
                    "re-issue the compatibility predicate with a fresh validity window".to_string(),
                );
                let explanation_digest = explanation_digest(
                    &reason_codes,
                    &attenuation_trace,
                    &scope_delta,
                    &recovery_hints,
                );
                let result = GateCheckResult {
                    decision: GateDecision::Deny,
                    rationale,
                    trace_id: trace_id.to_string(),
                    receipt_id: Some(format!("gate-rcpt-{}-{}", scope_id, audit_seq)),
                    package_id: package_id.to_string(),
                    mode,
                    scope_id: scope_id.to_string(),
                    event_code: GateDecision::Deny.event_code().to_string(),
                    reason_codes,
                    attenuation_trace,
                    scope_delta,
                    freshness_state,
                    recovery_hints,
                    explanation_digest,
                };
                tracing::info!(
                    event_code = %result.event_code,
                    trace_id = %result.trace_id,
                    scope_id = %result.scope_id,
                    package_id = %result.package_id,
                    decision = %result.decision,
                    reason_codes = ?result.reason_codes,
                    freshness_state = %result.freshness_state,
                    "compatibility gate evaluated"
                );
                push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
                return Ok(result);
            }
            let predicate_cache_key = authority_cache_key(
                COMPAT_POLICY_PREDICATE_DOMAIN,
                &PolicyPredicateSigningPayload::from(predicate),
                &predicate.signature,
                &predicate.proof.key_id,
            )
            .map_err(|reason| CompatGateError::InvalidPredicate {
                predicate_id: predicate.predicate_id.clone(),
                reason: format!("failed to canonicalize predicate cache key: {reason}"),
            })?;
            let predicate_cached = self
                .validated_predicates
                .get(&predicate.predicate_id)
                .is_some_and(|cached| {
                    crate::security::constant_time::ct_eq(cached, &predicate_cache_key)
                });

            if !predicate_cached && !predicate.verify_signature() {
                rationale.push(format!(
                    "predicate {} failed signature verification",
                    predicate.predicate_id
                ));
                reason_codes
                    .push(reason_codes::POLICY_COMPAT_INVALID_PREDICATE_SIGNATURE.to_string());
                recovery_hints.push(
                    "re-sign the compatibility predicate with the canonical policy signer"
                        .to_string(),
                );
                let explanation_digest = explanation_digest(
                    &reason_codes,
                    &attenuation_trace,
                    &scope_delta,
                    &recovery_hints,
                );
                let result = GateCheckResult {
                    decision: GateDecision::Deny,
                    rationale,
                    trace_id: trace_id.to_string(),
                    receipt_id: Some(format!("gate-rcpt-{}-{}", scope_id, audit_seq)),
                    package_id: package_id.to_string(),
                    mode,
                    scope_id: scope_id.to_string(),
                    event_code: GateDecision::Deny.event_code().to_string(),
                    reason_codes,
                    attenuation_trace,
                    scope_delta,
                    freshness_state,
                    recovery_hints,
                    explanation_digest,
                };
                tracing::info!(
                    event_code = %result.event_code,
                    trace_id = %result.trace_id,
                    scope_id = %result.scope_id,
                    package_id = %result.package_id,
                    decision = %result.decision,
                    reason_codes = ?result.reason_codes,
                    freshness_state = %result.freshness_state,
                    "compatibility gate evaluated"
                );
                push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
                return Ok(result);
            }
            self.validated_predicates
                .insert(predicate.predicate_id.clone(), predicate_cache_key);

            if let Err(reason) =
                validate_scope_attenuation_for_scope(scope_id, &predicate.attenuation)
            {
                rationale.push(format!(
                    "predicate {} rejected: {reason}",
                    predicate.predicate_id
                ));
                reason_codes.push(reason_codes::POLICY_COMPAT_SCOPE_WIDENING.to_string());
                recovery_hints.push(
                    "narrow the predicate attenuation so it preserves the active scope envelope"
                        .to_string(),
                );
                let explanation_digest = explanation_digest(
                    &reason_codes,
                    &attenuation_trace,
                    &scope_delta,
                    &recovery_hints,
                );
                let result = GateCheckResult {
                    decision: GateDecision::Deny,
                    rationale,
                    trace_id: trace_id.to_string(),
                    receipt_id: Some(format!("gate-rcpt-{}-{}", scope_id, audit_seq)),
                    package_id: package_id.to_string(),
                    mode,
                    scope_id: scope_id.to_string(),
                    event_code: GateDecision::Deny.event_code().to_string(),
                    reason_codes,
                    attenuation_trace,
                    scope_delta,
                    freshness_state,
                    recovery_hints,
                    explanation_digest,
                };
                tracing::info!(
                    event_code = %result.event_code,
                    trace_id = %result.trace_id,
                    scope_id = %result.scope_id,
                    package_id = %result.package_id,
                    decision = %result.decision,
                    reason_codes = ?result.reason_codes,
                    freshness_state = %result.freshness_state,
                    "compatibility gate evaluated"
                );
                push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
                return Ok(result);
            }

            let compiled = self
                .compiled_predicates
                .entry(predicate.predicate_id.clone())
                .or_insert_with(|| predicate.compile());
            attenuation_trace.extend(predicate.proof.attenuation_trace.iter().cloned());
            attenuation_trace.extend(compiled.attenuation_trace.iter().cloned());
            scope_delta.extend(predicate.proof.scope_delta.iter().cloned());
            scope_delta.extend(
                validate_scope_attenuation_for_scope(scope_id, &predicate.attenuation)
                    .unwrap_or_default(),
            );
        }

        // Look up the package in the shim registry
        let shim = self.registry.get(package_id);

        let decision = match shim {
            Some(entry) => {
                let action = divergence_action(entry.band, mode);
                match action {
                    DivergenceAction::Error => {
                        rationale.push(format!(
                            "band={} mode={}: divergence blocks execution",
                            entry.band.label(),
                            mode.label()
                        ));
                        reason_codes.push(reason_codes::POLICY_COMPAT_DENY_MODE.to_string());
                        recovery_hints.push(
                            "reduce requested compatibility risk or move the scope to a broader mode with approval"
                                .to_string(),
                        );
                        GateDecision::Deny
                    }
                    DivergenceAction::Blocked => {
                        rationale.push(format!(
                            "band={} mode={}: shim blocked entirely",
                            entry.band.label(),
                            mode.label()
                        ));
                        reason_codes.push(reason_codes::POLICY_COMPAT_DENY_MODE.to_string());
                        recovery_hints.push(
                            "remove the blocked shim or keep the scope in a less permissive compatibility class"
                                .to_string(),
                        );
                        GateDecision::Deny
                    }
                    DivergenceAction::Warn => {
                        rationale.push(format!(
                            "band={} mode={}: allowed with warning and receipt",
                            entry.band.label(),
                            mode.label()
                        ));
                        reason_codes.push(reason_codes::POLICY_COMPAT_AUDIT_UNKNOWN.to_string());
                        recovery_hints.push(
                            "inspect the emitted receipt and lockstep evidence before rollout"
                                .to_string(),
                        );
                        GateDecision::Audit
                    }
                    DivergenceAction::Log => {
                        rationale.push(format!(
                            "band={} mode={}: allowed with logging",
                            entry.band.label(),
                            mode.label()
                        ));
                        reason_codes.push(reason_codes::POLICY_COMPAT_ALLOW.to_string());
                        GateDecision::Allow
                    }
                }
            }
            None => {
                // Unknown package — allow if mode is permissive, deny if strict
                rationale.push(format!("package {package_id} not in shim registry"));
                match mode {
                    CompatibilityMode::Strict => {
                        rationale.push("strict mode: unknown packages denied".to_string());
                        reason_codes
                            .push(reason_codes::POLICY_COMPAT_DENY_UNKNOWN_STRICT.to_string());
                        recovery_hints.push(
                            "register the shim or re-run under balanced mode with explicit audit"
                                .to_string(),
                        );
                        GateDecision::Deny
                    }
                    CompatibilityMode::Balanced => {
                        rationale.push("balanced mode: unknown packages audited".to_string());
                        reason_codes.push(reason_codes::POLICY_COMPAT_AUDIT_UNKNOWN.to_string());
                        recovery_hints.push(
                            "capture a divergence receipt and inspect the audited package"
                                .to_string(),
                        );
                        GateDecision::Audit
                    }
                    CompatibilityMode::LegacyRisky => {
                        // INV-PCG-RECEIPT: unknown packages are divergences that
                        // must produce a receipt even in permissive modes.
                        rationale.push("legacy_risky mode: unknown packages audited".to_string());
                        reason_codes.push(reason_codes::POLICY_COMPAT_AUDIT_UNKNOWN.to_string());
                        recovery_hints.push(
                            "emit a divergence receipt and schedule lockstep validation for the unknown package"
                                .to_string(),
                        );
                        GateDecision::Audit
                    }
                }
            }
        };

        let receipt_id = if decision != GateDecision::Allow {
            Some(format!("gate-rcpt-{}-{}", scope_id, audit_seq))
        } else {
            None
        };

        let result = GateCheckResult {
            explanation_digest: explanation_digest(
                &reason_codes,
                &attenuation_trace,
                &scope_delta,
                &recovery_hints,
            ),
            decision,
            rationale,
            trace_id: trace_id.to_string(),
            receipt_id,
            package_id: package_id.to_string(),
            mode,
            scope_id: scope_id.to_string(),
            event_code: decision.event_code().to_string(),
            reason_codes,
            attenuation_trace,
            scope_delta: scope_delta.clone(),
            freshness_state,
            recovery_hints: recovery_hints.clone(),
        };

        tracing::info!(
            event_code = %result.event_code,
            trace_id = %result.trace_id,
            scope_id = %result.scope_id,
            package_id = %result.package_id,
            decision = %result.decision,
            reason_codes = ?result.reason_codes,
            freshness_state = %result.freshness_state,
            "compatibility gate evaluated"
        );
        push_bounded(&mut self.audit_log, result.clone(), MAX_AUDIT_LOG_ENTRIES);
        Ok(result)
    }

    // ── Non-Interference Check ──

    /// Verify that shim activation in scope_a has no observable effect in scope_b.
    /// Returns Ok(()) if non-interference holds; Err with violation details otherwise.
    ///
    /// Non-interference means: the gate decision for any package in scope_b is
    /// identical regardless of what shims are active in scope_a.
    pub fn check_non_interference(
        &self,
        scope_a: &str,
        scope_b: &str,
    ) -> Result<(), CompatGateError> {
        let Some(config_a) = self.scopes.get(scope_a) else {
            return Ok(());
        };
        let Some(config_b) = self.scopes.get(scope_b) else {
            return Ok(());
        };

        // If either scope doesn't exist, non-interference holds vacuously.
        let mode_b = config_b.mode;

        // For each shim, the decision in scope_b must be determined solely by
        // scope_b's mode, not scope_a's state. Since our gate evaluation is
        // purely a function of (shim.band, scope.mode), scopes are isolated
        // by construction — but we verify by checking that no cross-scope
        // predicate leaks.
        for entry in self.registry.all() {
            let action_b = divergence_action(entry.band, mode_b);
            // Check that no policy predicate from scope_a applies to scope_b
            for pred in &config_a.policy_predicates {
                if pred.applies_to_scope("scope", scope_b) {
                    return Err(CompatGateError::NonInterferenceViolation {
                        scope_a: scope_a.to_string(),
                        scope_b: scope_b.to_string(),
                        detail: format!(
                            "predicate {} from scope {} applies to scope {}",
                            pred.predicate_id, scope_a, scope_b
                        ),
                    });
                }
            }
            // Action is solely a function of (band, mode_b) — no cross-scope leak
            let _ = action_b;
        }

        Ok(())
    }

    // ── Monotonicity Check ──

    /// Verify that adding a shim to the registry does not weaken existing security
    /// guarantees. Formally: if the current registry allows operation O under mode M,
    /// then registry + new_shim also allows operation O under mode M.
    ///
    /// A shim weakens guarantees if it downgrades the divergence action for
    /// an existing entry (e.g., from Error to Warn).
    pub fn check_monotonicity(&self, new_shim: &ShimRegistryEntry) -> Result<(), CompatGateError> {
        // Monotonicity: adding a new shim to the registry must not change the
        // gate decision for any *existing* shim. Since gate decisions are a
        // function of (shim.band, scope.mode) and adding a new entry doesn't
        // change any existing entry's band, monotonicity holds by construction.
        //
        // However, we verify: if the new shim has the same shim_id as an existing
        // entry (replacement scenario), the replacement must not reduce the
        // strictness of the action for any mode.
        if let Some(existing) = self.registry.get(&new_shim.shim_id) {
            for mode in [
                CompatibilityMode::Strict,
                CompatibilityMode::Balanced,
                CompatibilityMode::LegacyRisky,
            ] {
                let existing_action = divergence_action(existing.band, mode);
                let new_action = divergence_action(new_shim.band, mode);
                if action_strictness(new_action) < action_strictness(existing_action) {
                    return Err(CompatGateError::MonotonicityViolation {
                        shim_id: new_shim.shim_id.clone(),
                        detail: format!(
                            "mode {}: action downgraded from {} to {}",
                            mode.label(),
                            existing_action.label(),
                            new_action.label()
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    // ── Query APIs ──

    /// Get all gate decisions for a given scope (audit log).
    pub fn audit_log_for_scope(&self, scope_id: &str) -> Vec<&GateCheckResult> {
        self.audit_log
            .iter()
            .filter(|r| r.scope_id == scope_id)
            .collect()
    }

    /// Get all receipts for a given scope.
    pub fn receipts_for_scope(&self, scope_id: &str) -> Vec<&ModeSelectionReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.scope_id == scope_id)
            .collect()
    }

    /// Get all receipts.
    pub fn all_receipts(&self) -> &[ModeSelectionReceipt] {
        &self.receipts
    }

    /// Total number of gate evaluations.
    pub fn evaluation_count(&self) -> usize {
        self.audit_log.len()
    }

    /// Number of configured scopes.
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

/// Strictness rank of a divergence action (higher = stricter).
fn action_strictness(action: DivergenceAction) -> u8 {
    match action {
        DivergenceAction::Blocked => 4,
        DivergenceAction::Error => 3,
        DivergenceAction::Warn => 2,
        DivergenceAction::Log => 1,
    }
}

// ── Gate Report ──────────────────────────────────────────────────────────────

/// Summary report for the compatibility gate system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatGateReport {
    pub total_shims: usize,
    pub total_scopes: usize,
    pub total_evaluations: usize,
    pub total_receipts: usize,
    pub shims_by_band: BTreeMap<String, usize>,
    pub shims_by_risk: BTreeMap<String, usize>,
    pub decisions_summary: BTreeMap<String, usize>,
    pub generated_at: String,
}

/// Generate a summary report of the compatibility gate system.
pub fn generate_compat_report(evaluator: &CompatGateEvaluator) -> CompatGateReport {
    let registry = evaluator.registry();

    let mut shims_by_band: BTreeMap<String, usize> = BTreeMap::new();
    let mut shims_by_risk: BTreeMap<String, usize> = BTreeMap::new();

    for entry in registry.all() {
        let count = shims_by_band
            .entry(entry.band.label().to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
        let count = shims_by_risk
            .entry(entry.risk_category.label().to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
    }

    let mut decisions_summary: BTreeMap<String, usize> = BTreeMap::new();
    for result in &evaluator.audit_log {
        let count = decisions_summary
            .entry(result.decision.label().to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
    }

    CompatGateReport {
        total_shims: registry.len(),
        total_scopes: evaluator.scope_count(),
        total_evaluations: evaluator.evaluation_count(),
        total_receipts: evaluator.all_receipts().len(),
        shims_by_band,
        shims_by_risk,
        decisions_summary,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──

    fn make_shim(id: &str, band: CompatibilityBand, risk: ShimRiskCategory) -> ShimRegistryEntry {
        ShimRegistryEntry {
            shim_id: id.to_string(),
            description: format!("Test shim {id}"),
            band,
            risk_category: risk,
            activation_policy_id: format!("policy-{id}"),
            divergence_rationale: format!("Rationale for {id}"),
            api_family: "fs".to_string(),
            active: true,
        }
    }

    fn sample_registry() -> ShimRegistry {
        let mut reg = ShimRegistry::new();
        reg.register(make_shim(
            "shim-core-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-hv-1",
            CompatibilityBand::HighValue,
            ShimRiskCategory::Medium,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-edge-1",
            CompatibilityBand::Edge,
            ShimRiskCategory::Low,
        ))
        .unwrap();
        reg.register(make_shim(
            "shim-unsafe-1",
            CompatibilityBand::Unsafe,
            ShimRiskCategory::Critical,
        ))
        .unwrap();
        reg
    }

    fn evaluator_with_scope() -> CompatGateEvaluator {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "project-1",
            CompatibilityMode::Balanced,
            "admin",
            "initial setup",
            true,
        )
        .unwrap();
        eval
    }

    #[test]
    fn evaluator_uses_configured_receipt_ttl_secs() {
        let config = crate::config::CompatibilityConfig {
            mode: crate::config::CompatibilityMode::Balanced,
            emit_divergence_receipts: true,
            default_receipt_ttl_secs: 90,
            gate_ttl_secs: None,
        };
        let mut eval = CompatGateEvaluator::from_compatibility_config(sample_registry(), &config);
        let receipt = eval
            .set_mode(
                "project-ttl",
                CompatibilityMode::Balanced,
                "admin",
                "configured ttl",
                true,
            )
            .unwrap();
        let activated_at = chrono::DateTime::parse_from_rfc3339(&receipt.activated_at).unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&receipt.expires_at).unwrap();
        assert_eq!(
            expires_at.signed_duration_since(activated_at).num_seconds(),
            90
        );
    }

    fn future_window() -> (String, String) {
        let issued_at = "2099-01-01T00:00:00Z".to_string();
        let expires_at = "2099-01-01T01:00:00Z".to_string();
        (issued_at, expires_at)
    }

    fn stale_window() -> (String, String) {
        let issued_at = "2000-01-01T00:00:00Z".to_string();
        let expires_at = "2000-01-01T01:00:00Z".to_string();
        (issued_at, expires_at)
    }

    fn signed_test_predicate_with_id(
        predicate_id: &str,
        attenuation: Vec<AttenuationConstraint>,
    ) -> PolicyPredicate {
        let (issued_at, expires_at) = future_window();
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::Ed25519,
            Some("parent-compat-receipt".to_string()),
            attenuation
                .iter()
                .map(|constraint| format!("{}={}", constraint.scope_type, constraint.scope_value))
                .collect(),
            vec!["scope:parent->project-1".to_string()],
            vec!["POLICY_COMPAT_TEST_PREDICATE".to_string()],
            vec!["re-sign the predicate if the signature changes".to_string()],
        );
        let mut predicate = PolicyPredicate {
            predicate_id: predicate_id.to_string(),
            signature: String::new(),
            attenuation,
            activation_condition: "mode == balanced".to_string(),
            issued_at,
            expires_at,
            proof,
        };
        predicate.signature = sign_ed25519_canonical(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &PolicyPredicateSigningPayload::from(&predicate),
        )
        .unwrap();
        predicate
    }

    fn signed_test_predicate(attenuation: Vec<AttenuationConstraint>) -> PolicyPredicate {
        signed_test_predicate_with_id("pred-1", attenuation)
    }

    fn signed_test_receipt() -> ModeSelectionReceipt {
        let (activated_at, expires_at) = future_window();
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::HmacSha256,
            Some("parent-mode-receipt".to_string()),
            vec!["scope=project-1".to_string()],
            vec!["mode:strict->balanced".to_string()],
            vec!["POLICY_COMPAT_TEST_RECEIPT".to_string()],
            vec!["re-issue the receipt if freshness expires".to_string()],
        );
        let mut receipt = ModeSelectionReceipt {
            receipt_id: "r1".to_string(),
            scope_id: "s1".to_string(),
            mode: CompatibilityMode::Balanced,
            previous_mode: Some(CompatibilityMode::Strict),
            activated_at,
            expires_at,
            signature: String::new(),
            requestor: "admin".to_string(),
            justification: "test".to_string(),
            approval_required: true,
            approved: true,
            proof,
        };
        receipt.signature = sign_hmac_canonical(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&receipt),
        )
        .unwrap();
        receipt
    }

    // ── CompatibilityBand ──

    #[test]
    fn band_labels() {
        assert_eq!(CompatibilityBand::Core.label(), "core");
        assert_eq!(CompatibilityBand::HighValue.label(), "high_value");
        assert_eq!(CompatibilityBand::Edge.label(), "edge");
        assert_eq!(CompatibilityBand::Unsafe.label(), "unsafe");
    }

    #[test]
    fn band_priority_ordering() {
        assert!(CompatibilityBand::Core.priority() > CompatibilityBand::HighValue.priority());
        assert!(CompatibilityBand::HighValue.priority() > CompatibilityBand::Edge.priority());
        assert!(CompatibilityBand::Edge.priority() > CompatibilityBand::Unsafe.priority());
    }

    #[test]
    fn band_display() {
        assert_eq!(CompatibilityBand::Core.to_string(), "core");
    }

    // ── CompatibilityMode ──

    #[test]
    fn mode_labels() {
        assert_eq!(CompatibilityMode::Strict.label(), "strict");
        assert_eq!(CompatibilityMode::Balanced.label(), "balanced");
        assert_eq!(CompatibilityMode::LegacyRisky.label(), "legacy_risky");
    }

    #[test]
    fn mode_risk_ordering() {
        assert!(CompatibilityMode::Strict.risk_level() < CompatibilityMode::Balanced.risk_level());
        assert!(
            CompatibilityMode::Balanced.risk_level() < CompatibilityMode::LegacyRisky.risk_level()
        );
    }

    #[test]
    fn mode_escalation_detection() {
        assert!(CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::Balanced));
        assert!(CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::LegacyRisky));
        assert!(CompatibilityMode::Balanced.is_escalation_to(CompatibilityMode::LegacyRisky));
        assert!(!CompatibilityMode::LegacyRisky.is_escalation_to(CompatibilityMode::Strict));
        assert!(!CompatibilityMode::Balanced.is_escalation_to(CompatibilityMode::Strict));
        assert!(!CompatibilityMode::Strict.is_escalation_to(CompatibilityMode::Strict));
    }

    #[test]
    fn mode_display() {
        assert_eq!(CompatibilityMode::Balanced.to_string(), "balanced");
    }

    // ── Divergence Action Matrix ──

    #[test]
    fn divergence_matrix_core_always_error() {
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::Strict),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::Balanced),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Core, CompatibilityMode::LegacyRisky),
            DivergenceAction::Error
        );
    }

    #[test]
    fn divergence_matrix_high_value() {
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::Strict),
            DivergenceAction::Error
        );
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::Balanced),
            DivergenceAction::Warn
        );
        assert_eq!(
            divergence_action(CompatibilityBand::HighValue, CompatibilityMode::LegacyRisky),
            DivergenceAction::Warn
        );
    }

    #[test]
    fn divergence_matrix_edge() {
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::Strict),
            DivergenceAction::Warn
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::Balanced),
            DivergenceAction::Log
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Edge, CompatibilityMode::LegacyRisky),
            DivergenceAction::Log
        );
    }

    #[test]
    fn divergence_matrix_unsafe() {
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::Strict),
            DivergenceAction::Blocked
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::Balanced),
            DivergenceAction::Blocked
        );
        assert_eq!(
            divergence_action(CompatibilityBand::Unsafe, CompatibilityMode::LegacyRisky),
            DivergenceAction::Warn
        );
    }

    #[test]
    fn divergence_matrix_is_complete() {
        // 4 bands x 3 modes = 12 cells
        let bands = [
            CompatibilityBand::Core,
            CompatibilityBand::HighValue,
            CompatibilityBand::Edge,
            CompatibilityBand::Unsafe,
        ];
        let modes = [
            CompatibilityMode::Strict,
            CompatibilityMode::Balanced,
            CompatibilityMode::LegacyRisky,
        ];
        let mut count = 0;
        for band in &bands {
            for mode in &modes {
                let _ = divergence_action(*band, *mode);
                count = count.saturating_add(1);
            }
        }
        assert_eq!(count, 12);
    }

    // ── ShimRegistry ──

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = ShimRegistry::new();
        assert!(reg.is_empty());
        reg.register(make_shim(
            "shim-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
        let entry = reg.get("shim-1").unwrap();
        assert_eq!(entry.shim_id, "shim-1");
        assert_eq!(entry.band, CompatibilityBand::Core);
    }

    #[test]
    fn registry_duplicate_rejected() {
        let mut reg = ShimRegistry::new();
        reg.register(make_shim(
            "shim-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();
        let err = reg
            .register(make_shim(
                "shim-1",
                CompatibilityBand::Edge,
                ShimRiskCategory::Low,
            ))
            .unwrap_err();
        assert!(matches!(err, CompatGateError::DuplicateShim { .. }));
    }

    #[test]
    fn registry_duplicate_preserves_original_entry() {
        let mut reg = ShimRegistry::new();
        reg.register(make_shim(
            "shim-dupe",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        ))
        .unwrap();

        let err = reg
            .register(make_shim(
                "shim-dupe",
                CompatibilityBand::Unsafe,
                ShimRiskCategory::Critical,
            ))
            .unwrap_err();

        assert!(matches!(err, CompatGateError::DuplicateShim { .. }));
        assert_eq!(reg.len(), 1);
        let original = reg.get("shim-dupe").unwrap();
        assert_eq!(original.band, CompatibilityBand::Core);
        assert_eq!(original.risk_category, ShimRiskCategory::High);
    }

    #[test]
    fn registry_by_band() {
        let reg = sample_registry();
        assert_eq!(reg.by_band(CompatibilityBand::Core).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::HighValue).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::Edge).len(), 1);
        assert_eq!(reg.by_band(CompatibilityBand::Unsafe).len(), 1);
    }

    #[test]
    fn registry_by_api_family() {
        let reg = sample_registry();
        assert_eq!(reg.by_api_family("fs").len(), 4);
        assert_eq!(reg.by_api_family("http").len(), 0);
    }

    #[test]
    fn registry_active_under_mode() {
        let reg = sample_registry();
        // Strict: core=Error(deny), hv=Error(deny), edge=Warn(allow), unsafe=Blocked(deny)
        // Only edge shim is active (Warn = not blocked/error)
        let strict_active = reg.active_under_mode(CompatibilityMode::Strict);
        assert_eq!(strict_active.len(), 1);
        assert_eq!(strict_active[0].band, CompatibilityBand::Edge);

        // Balanced: core=Error, hv=Warn(active), edge=Log(active), unsafe=Blocked
        let balanced_active = reg.active_under_mode(CompatibilityMode::Balanced);
        assert_eq!(balanced_active.len(), 2);

        // LegacyRisky: core=Error, hv=Warn(active), edge=Log(active), unsafe=Warn(active)
        let risky_active = reg.active_under_mode(CompatibilityMode::LegacyRisky);
        assert_eq!(risky_active.len(), 3);
    }

    #[test]
    fn registry_all() {
        let reg = sample_registry();
        assert_eq!(reg.all().len(), 4);
    }

    // ── PolicyPredicate ──

    #[test]
    fn predicate_signature_valid() {
        let pred = signed_test_predicate(vec![]);
        assert!(pred.verify_signature());
    }

    #[test]
    fn predicate_signature_too_short() {
        let mut pred = signed_test_predicate(vec![]);
        pred.signature = "abcd".to_string();
        assert!(!pred.verify_signature());
    }

    #[test]
    fn predicate_scope_universal() {
        let pred = signed_test_predicate(vec![]);
        assert!(pred.applies_to_scope("scope", "any"));
    }

    #[test]
    fn predicate_scope_attenuated() {
        let pred = signed_test_predicate(vec![AttenuationConstraint {
            scope_type: "project".to_string(),
            scope_value: "proj-1".to_string(),
        }]);
        assert!(pred.applies_to_scope("project", "proj-1"));
        assert!(!pred.applies_to_scope("project", "proj-2"));
    }

    #[test]
    fn predicate_same_length_forgery_rejected() {
        let mut pred = signed_test_predicate(vec![]);
        pred.activation_condition = "mode == legacyyy".to_string();
        assert_eq!(pred.activation_condition.len(), "mode == balanced".len());
        assert!(!pred.verify_signature());
    }

    #[test]
    fn freshness_rejects_malformed_issued_timestamp() {
        let state = compute_freshness_state("not-rfc3339", "2099-01-01T01:00:00Z");

        assert_eq!(state, CompatibilityFreshnessState::InvalidTimestamp);
    }

    #[test]
    fn freshness_rejects_malformed_expiration_timestamp() {
        let state = compute_freshness_state("2099-01-01T00:00:00Z", "not-rfc3339");

        assert_eq!(state, CompatibilityFreshnessState::InvalidTimestamp);
    }

    #[test]
    fn freshness_rejects_non_increasing_window() {
        let state = compute_freshness_state("2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z");

        assert_eq!(state, CompatibilityFreshnessState::InvalidTimestamp);
    }

    #[test]
    fn predicate_wrong_key_id_rejected() {
        let mut pred = signed_test_predicate(vec![]);
        pred.proof.key_id = compatibility_internal_key_id();

        assert!(!pred.verify_signature());
    }

    #[test]
    fn predicate_wrong_domain_separator_rejected() {
        let pred = signed_test_predicate(vec![]);

        assert!(!verify_ed25519_canonical(
            COMPAT_DIVERGENCE_RECEIPT_DOMAIN,
            &PolicyPredicateSigningPayload::from(&pred),
            &pred.signature,
            &pred.proof.key_id,
        ));
    }

    #[test]
    fn mode_receipt_wrong_key_id_rejected() {
        let mut receipt = signed_test_receipt();
        receipt.proof.key_id = compatibility_external_key_id();

        assert!(!receipt.verify_signature());
    }

    #[test]
    fn mode_receipt_wrong_domain_separator_rejected() {
        let receipt = signed_test_receipt();

        assert!(!verify_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&receipt),
            &receipt.signature,
            &receipt.proof.key_id,
        ));
    }

    // ── GateDecision ──

    #[test]
    fn gate_decision_event_codes() {
        assert_eq!(GateDecision::Allow.event_code(), "PCG-001");
        assert_eq!(GateDecision::Deny.event_code(), "PCG-002");
        assert_eq!(GateDecision::Audit.event_code(), "PCG-005");
    }

    #[test]
    fn gate_decision_labels() {
        assert_eq!(GateDecision::Allow.label(), "allow");
        assert_eq!(GateDecision::Deny.label(), "deny");
        assert_eq!(GateDecision::Audit.label(), "audit");
    }

    #[test]
    fn gate_decision_display() {
        assert_eq!(GateDecision::Deny.to_string(), "deny");
    }

    // ── Mode Selection ──

    #[test]
    fn set_mode_initial() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::Strict,
                "admin",
                "initial",
                true,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::Strict);
        assert!(receipt.previous_mode.is_none());
        assert!(!receipt.approval_required);
    }

    #[test]
    fn set_mode_escalation_requires_approval() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();

        // Escalation without approval should fail
        let err = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::LegacyRisky,
                "admin",
                "need legacy",
                false,
            )
            .unwrap_err();
        assert!(matches!(err, CompatGateError::TransitionDenied { .. }));
    }

    #[test]
    fn set_mode_denied_escalation_preserves_scope_and_receipts() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        let receipt_count = eval.all_receipts().len();

        let err = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::LegacyRisky,
                "admin",
                "escalation denied",
                false,
            )
            .unwrap_err();

        assert!(matches!(err, CompatGateError::TransitionDenied { .. }));
        assert_eq!(eval.get_mode("scope-1"), Some(CompatibilityMode::Strict));
        assert_eq!(eval.all_receipts().len(), receipt_count);
        assert_eq!(eval.receipts_for_scope("scope-1").len(), 1);
    }

    #[test]
    fn set_mode_escalation_with_approval() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::LegacyRisky,
                "admin",
                "need legacy",
                true,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::LegacyRisky);
        assert_eq!(receipt.previous_mode, Some(CompatibilityMode::Strict));
        assert!(receipt.approval_required);
    }

    #[test]
    fn set_mode_de_escalation_auto_approved() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-1",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        // De-escalation should not require approval
        let receipt = eval
            .set_mode(
                "scope-1",
                CompatibilityMode::Strict,
                "admin",
                "tighten",
                false,
            )
            .unwrap();
        assert_eq!(receipt.mode, CompatibilityMode::Strict);
        assert!(!receipt.approval_required);
    }

    #[test]
    fn get_mode() {
        let eval = evaluator_with_scope();
        assert_eq!(
            eval.get_mode("project-1"),
            Some(CompatibilityMode::Balanced)
        );
        assert_eq!(eval.get_mode("nonexistent"), None);
    }

    #[test]
    fn add_policy_predicate_rejects_scope_widening() {
        let mut eval = evaluator_with_scope();
        let err = eval
            .add_policy_predicate(
                "project-1",
                signed_test_predicate(vec![AttenuationConstraint {
                    scope_type: "scope".to_string(),
                    scope_value: "project-2".to_string(),
                }]),
            )
            .unwrap_err();
        assert!(matches!(err, CompatGateError::InvalidPredicate { .. }));
    }

    #[test]
    fn add_policy_predicate_rejects_unknown_scope_without_side_effects() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let predicate = signed_test_predicate(vec![]);

        let err = eval
            .add_policy_predicate("missing-scope", predicate)
            .unwrap_err();

        assert!(matches!(
            err,
            CompatGateError::ScopeNotFound { ref scope_id } if scope_id == "missing-scope"
        ));
        assert!(eval.compiled_predicates.is_empty());
        assert!(eval.validated_predicates.is_empty());
    }

    #[test]
    fn add_policy_predicate_rejects_overflow_without_eviction() {
        let mut eval = evaluator_with_scope();
        for idx in 0..MAX_ENTRIES {
            let predicate_id = format!("pred-{idx:04}");
            eval.add_policy_predicate(
                "project-1",
                signed_test_predicate_with_id(
                    &predicate_id,
                    vec![AttenuationConstraint {
                        scope_type: "scope".to_string(),
                        scope_value: "project-1".to_string(),
                    }],
                ),
            )
            .expect("filling scope predicates to the cap should succeed");
        }

        let err = eval
            .add_policy_predicate(
                "project-1",
                signed_test_predicate_with_id(
                    "pred-overflow",
                    vec![AttenuationConstraint {
                        scope_type: "scope".to_string(),
                        scope_value: "project-1".to_string(),
                    }],
                ),
            )
            .expect_err("overflow must fail closed instead of evicting scope predicates");

        assert!(matches!(err, CompatGateError::InvalidPredicate { .. }));
        assert_eq!(
            eval.get_scope("project-1")
                .expect("scope should exist")
                .policy_predicates
                .len(),
            MAX_ENTRIES
        );
        assert_eq!(
            eval.get_scope("project-1")
                .expect("scope should exist")
                .policy_predicates
                .first()
                .expect("oldest predicate should remain")
                .predicate_id,
            "pred-0000"
        );
        assert!(
            !eval
                .get_scope("project-1")
                .expect("scope should exist")
                .policy_predicates
                .iter()
                .any(|predicate| predicate.predicate_id == "pred-overflow")
        );
        assert_eq!(eval.compiled_predicates.len(), MAX_ENTRIES);
        assert_eq!(eval.validated_predicates.len(), MAX_ENTRIES);
        assert!(!eval.compiled_predicates.contains_key("pred-overflow"));
        assert!(!eval.validated_predicates.contains_key("pred-overflow"));
    }

    // ── Gate Evaluation ──

    #[test]
    fn gate_eval_core_shim_denied_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-core-1", "project-1", "trace-1")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(!result.rationale.is_empty());
        assert_eq!(result.event_code, event_codes::PCG_GATE_DENY);
    }

    #[test]
    fn gate_eval_hv_shim_audited_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-hv-1", "project-1", "trace-2")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
        assert_eq!(result.event_code, event_codes::PCG_GATE_AUDIT);
    }

    #[test]
    fn gate_eval_edge_shim_allowed_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-3")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Allow);
        assert_eq!(result.event_code, event_codes::PCG_GATE_PASS);
    }

    #[test]
    fn gate_eval_unsafe_shim_denied_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-unsafe-1", "project-1", "trace-4")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_eval_unknown_package_in_strict() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-strict",
            CompatibilityMode::Strict,
            "admin",
            "init",
            true,
        )
        .unwrap();
        let result = eval
            .evaluate_gate("unknown-pkg", "scope-strict", "trace-5")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_eval_unknown_package_in_balanced() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("unknown-pkg", "project-1", "trace-6")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
    }

    #[test]
    fn gate_eval_unknown_package_in_legacy_risky() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "scope-risky",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        let result = eval
            .evaluate_gate("unknown-pkg", "scope-risky", "trace-7")
            .unwrap();
        // INV-PCG-RECEIPT: unknown packages are divergences that produce
        // receipts even in permissive modes.
        assert_eq!(result.decision, GateDecision::Audit);
        assert!(result.receipt_id.is_some(), "receipt must be generated");
    }

    #[test]
    fn gate_eval_scope_not_found() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let err = eval
            .evaluate_gate("shim-core-1", "nonexistent", "trace-8")
            .unwrap_err();
        assert!(matches!(err, CompatGateError::ScopeNotFound { .. }));
    }

    #[test]
    fn gate_eval_trace_id_preserved() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "my-trace-123")
            .unwrap();
        assert_eq!(result.trace_id, "my-trace-123");
    }

    #[test]
    fn gate_eval_receipt_id_on_deny() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-core-1", "project-1", "trace-9")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(result.receipt_id.is_some());
    }

    #[test]
    fn gate_eval_no_receipt_on_allow() {
        let mut eval = evaluator_with_scope();
        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-10")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Allow);
        assert!(result.receipt_id.is_none());
    }

    #[test]
    fn gate_eval_rejects_tampered_scope_receipt() {
        let mut eval = evaluator_with_scope();
        let scope = eval.scopes.get_mut("project-1").unwrap();
        scope.receipt.justification = "initial setvp".to_string();
        assert_eq!(scope.receipt.justification.len(), "initial setup".len());

        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-tampered-receipt")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE.to_string())
        );
    }

    #[test]
    fn gate_eval_rejects_stale_scope_receipt() {
        let mut eval = evaluator_with_scope();
        let scope = eval.scopes.get_mut("project-1").unwrap();
        let (activated_at, expires_at) = stale_window();
        scope.receipt.activated_at = activated_at;
        scope.receipt.expires_at = expires_at;
        scope.receipt.signature = sign_hmac_canonical(
            COMPAT_MODE_RECEIPT_DOMAIN,
            &ModeSelectionReceiptSigningPayload::from(&scope.receipt),
        )
        .unwrap();

        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-stale-receipt")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_STALE_RECEIPT.to_string())
        );
    }

    #[test]
    fn gate_eval_rejects_scope_widening_predicate() {
        let mut eval = evaluator_with_scope();
        let mut pred = signed_test_predicate(vec![AttenuationConstraint {
            scope_type: "scope".to_string(),
            scope_value: "project-2".to_string(),
        }]);
        pred.proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::Ed25519,
            Some("parent-compat-receipt".to_string()),
            vec!["scope=project-2".to_string()],
            vec!["scope:project-2->project-1".to_string()],
            vec![reason_codes::POLICY_COMPAT_SCOPE_WIDENING.to_string()],
            vec!["narrow the predicate before retrying".to_string()],
        );
        pred.signature = sign_ed25519_canonical(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &PolicyPredicateSigningPayload::from(&pred),
        )
        .unwrap();
        eval.scopes
            .get_mut("project-1")
            .unwrap()
            .policy_predicates
            .push(pred);

        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-scope-widen")
            .unwrap();
        assert_eq!(result.decision, GateDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_SCOPE_WIDENING.to_string())
        );
    }

    #[test]
    fn gate_eval_rejects_cached_predicate_tampering() {
        let mut eval = evaluator_with_scope();
        let predicate = signed_test_predicate(vec![AttenuationConstraint {
            scope_type: "scope".to_string(),
            scope_value: "project-1".to_string(),
        }]);
        eval.add_policy_predicate("project-1", predicate).unwrap();
        {
            let predicate = eval
                .scopes
                .get_mut("project-1")
                .unwrap()
                .policy_predicates
                .first_mut()
                .unwrap();
            predicate.activation_condition = "mode == legacyyy".to_string();
            assert_eq!(
                predicate.activation_condition.len(),
                "mode == balanced".len()
            );
        }

        let result = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-tampered-predicate")
            .unwrap();

        assert_eq!(result.decision, GateDecision::Deny);
        assert!(
            result
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_INVALID_PREDICATE_SIGNATURE.to_string())
        );
    }

    #[test]
    fn gate_eval_caches_compiled_predicates_under_budget() {
        let mut eval = evaluator_with_scope();
        let predicate = signed_test_predicate(vec![AttenuationConstraint {
            scope_type: "scope".to_string(),
            scope_value: "project-1".to_string(),
        }]);
        eval.add_policy_predicate("project-1", predicate).unwrap();

        eval.evaluate_gate("shim-edge-1", "project-1", "trace-warmup")
            .unwrap();

        let mut samples = Vec::with_capacity(512);
        for idx in 0..512 {
            let started = std::time::Instant::now();
            let result = eval
                .evaluate_gate("shim-edge-1", "project-1", &format!("trace-bench-{idx}"))
                .unwrap();
            assert_eq!(result.decision, GateDecision::Allow);
            samples.push(started.elapsed().as_nanos() as u64);
        }

        samples.sort_unstable();
        let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
        assert!(
            p99 < 1_000_000,
            "cached gate evaluation p99 {}ns exceeded 1ms budget",
            p99
        );
        assert_eq!(eval.compiled_predicates.len(), 1);
    }

    // ── Audit Log ──

    #[test]
    fn audit_log_records_evaluations() {
        let mut eval = evaluator_with_scope();
        eval.evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        eval.evaluate_gate("shim-edge-1", "project-1", "t2")
            .unwrap();
        assert_eq!(eval.evaluation_count(), 2);
        assert_eq!(eval.audit_log_for_scope("project-1").len(), 2);
        assert_eq!(eval.audit_log_for_scope("other").len(), 0);
    }

    #[test]
    fn gate_eval_fails_closed_when_audit_sequence_exhausted() {
        let mut eval = evaluator_with_scope();
        eval.next_audit_seq = u64::MAX;
        eval.audit_seq_exhausted = true;

        let err = eval
            .evaluate_gate("shim-edge-1", "project-1", "trace-audit-overflow")
            .unwrap_err();

        assert!(matches!(
            err,
            CompatGateError::CounterExhausted { ref counter } if counter == "audit_sequence"
        ));
    }

    // ── Non-Interference ──

    #[test]
    fn non_interference_isolated_scopes() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("scope-a", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        eval.set_mode(
            "scope-b",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();
        assert!(eval.check_non_interference("scope-a", "scope-b").is_ok());
    }

    #[test]
    fn non_interference_missing_scope() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Non-existent scopes → vacuously OK
        assert!(eval.check_non_interference("x", "y").is_ok());
    }

    // ── Monotonicity ──

    #[test]
    fn monotonicity_new_shim_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        let new_shim = make_shim("shim-new", CompatibilityBand::Edge, ShimRiskCategory::Low);
        assert!(eval.check_monotonicity(&new_shim).is_ok());
    }

    #[test]
    fn monotonicity_replacement_same_band_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace shim-core-1 with same band → same actions → OK
        let replacement = make_shim(
            "shim-core-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        );
        assert!(eval.check_monotonicity(&replacement).is_ok());
    }

    #[test]
    fn monotonicity_replacement_stricter_ok() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace edge shim with core band → strictly more restrictive → OK
        let replacement = make_shim(
            "shim-edge-1",
            CompatibilityBand::Core,
            ShimRiskCategory::High,
        );
        assert!(eval.check_monotonicity(&replacement).is_ok());
    }

    #[test]
    fn monotonicity_replacement_weaker_rejected() {
        let eval = CompatGateEvaluator::new(sample_registry());
        // Replace core shim with edge band → less restrictive → violation
        let replacement = make_shim(
            "shim-core-1",
            CompatibilityBand::Edge,
            ShimRiskCategory::Low,
        );
        let err = eval.check_monotonicity(&replacement).unwrap_err();
        assert!(matches!(err, CompatGateError::MonotonicityViolation { .. }));
    }

    // ── Receipts ──

    #[test]
    fn receipts_accumulated() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode("s1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        eval.set_mode("s2", CompatibilityMode::Balanced, "admin", "init", true)
            .unwrap();
        assert_eq!(eval.all_receipts().len(), 2);
        assert_eq!(eval.receipts_for_scope("s1").len(), 1);
        assert_eq!(eval.receipts_for_scope("s2").len(), 1);
    }

    #[test]
    fn receipt_sequence_uses_last_value_before_exhausting() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.next_receipt_seq = u64::MAX;

        let final_seq = eval
            .next_receipt_sequence()
            .expect("last receipt sequence should still be usable");
        assert_eq!(final_seq, u64::MAX);
        assert!(eval.receipt_seq_exhausted);

        let err = eval
            .next_receipt_sequence()
            .expect_err("receipt sequence should fail after last value");
        assert!(matches!(
            err,
            CompatGateError::CounterExhausted { ref counter } if counter == "receipt_sequence"
        ));
    }

    #[test]
    fn audit_sequence_uses_last_value_before_exhausting() {
        let mut eval = evaluator_with_scope();
        eval.next_audit_seq = u64::MAX;

        let final_seq = eval
            .next_audit_sequence()
            .expect("last audit sequence should still be usable");
        assert_eq!(final_seq, u64::MAX);
        assert!(eval.audit_seq_exhausted);

        let err = eval
            .next_audit_sequence()
            .expect_err("audit sequence should fail after last value");
        assert!(matches!(
            err,
            CompatGateError::CounterExhausted { ref counter } if counter == "audit_sequence"
        ));
    }

    #[test]
    fn set_mode_fails_closed_when_receipt_sequence_exhausted() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.next_receipt_seq = u64::MAX;
        eval.receipt_seq_exhausted = true;

        let err = eval
            .set_mode("s1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap_err();

        assert!(matches!(
            err,
            CompatGateError::CounterExhausted { ref counter } if counter == "receipt_sequence"
        ));
    }

    #[test]
    fn receipt_signature_verification() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        let receipt = eval
            .set_mode("s1", CompatibilityMode::Strict, "admin", "init", true)
            .unwrap();
        assert!(receipt.verify_signature());
    }

    // ── Report ──

    #[test]
    fn report_generation() {
        let mut eval = evaluator_with_scope();
        eval.evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        eval.evaluate_gate("shim-edge-1", "project-1", "t2")
            .unwrap();

        let report = generate_compat_report(&eval);
        assert_eq!(report.total_shims, 4);
        assert_eq!(report.total_scopes, 1);
        assert_eq!(report.total_evaluations, 2);
        assert_eq!(report.total_receipts, 1);
        assert!(!report.generated_at.is_empty());
        assert_eq!(*report.shims_by_band.get("core").unwrap_or(&0), 1);
    }

    // ── Error Display ──

    #[test]
    fn error_display_duplicate_shim() {
        let err = CompatGateError::DuplicateShim {
            shim_id: "test".to_string(),
        };
        assert!(err.to_string().contains("duplicate shim"));
    }

    #[test]
    fn error_display_scope_not_found() {
        let err = CompatGateError::ScopeNotFound {
            scope_id: "x".to_string(),
        };
        assert!(err.to_string().contains("scope not found"));
    }

    #[test]
    fn error_display_transition_denied() {
        let err = CompatGateError::TransitionDenied {
            from: "strict".to_string(),
            to: "legacy_risky".to_string(),
            reason: "no approval".to_string(),
        };
        assert!(err.to_string().contains("mode transition denied"));
    }

    #[test]
    fn error_display_non_interference() {
        let err = CompatGateError::NonInterferenceViolation {
            scope_a: "a".to_string(),
            scope_b: "b".to_string(),
            detail: "leak".to_string(),
        };
        assert!(err.to_string().contains("non-interference"));
    }

    #[test]
    fn error_display_monotonicity() {
        let err = CompatGateError::MonotonicityViolation {
            shim_id: "s".to_string(),
            detail: "weaker".to_string(),
        };
        assert!(err.to_string().contains("monotonicity"));
    }

    #[test]
    fn error_display_invalid_predicate() {
        let err = CompatGateError::InvalidPredicate {
            predicate_id: "p".to_string(),
            reason: "bad".to_string(),
        };
        assert!(err.to_string().contains("invalid predicate"));
    }

    #[test]
    fn error_display_package_not_found() {
        let err = CompatGateError::PackageNotFound {
            package_id: "pkg".to_string(),
        };
        assert!(err.to_string().contains("package not found"));
    }

    // ── Serde Roundtrips ──

    #[test]
    fn shim_entry_serde() {
        let entry = make_shim("s1", CompatibilityBand::Core, ShimRiskCategory::High);
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ShimRegistryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.shim_id, "s1");
        assert_eq!(parsed.band, CompatibilityBand::Core);
    }

    #[test]
    fn gate_check_result_serde() {
        let result = GateCheckResult {
            decision: GateDecision::Deny,
            rationale: vec!["reason".to_string()],
            trace_id: "t1".to_string(),
            receipt_id: Some("r1".to_string()),
            package_id: "pkg".to_string(),
            mode: CompatibilityMode::Strict,
            scope_id: "s1".to_string(),
            event_code: "PCG-002".to_string(),
            reason_codes: vec!["POLICY_COMPAT_DENY_MODE".to_string()],
            attenuation_trace: vec!["scope=project-1".to_string()],
            scope_delta: vec!["scope:root->s1".to_string()],
            freshness_state: CompatibilityFreshnessState::Fresh,
            recovery_hints: vec!["retry with approval".to_string()],
            explanation_digest: "digest".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: GateCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decision, GateDecision::Deny);
        assert_eq!(parsed.trace_id, "t1");
    }

    #[test]
    fn mode_selection_receipt_serde() {
        let receipt = signed_test_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ModeSelectionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.receipt_id, "r1");
        assert_eq!(parsed.mode, CompatibilityMode::Balanced);
    }

    #[test]
    fn compat_gate_report_serde() {
        let eval = evaluator_with_scope();
        let report = generate_compat_report(&eval);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: CompatGateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_shims, 4);
    }

    #[test]
    fn compatibility_sources_do_not_reintroduce_placeholder_signature_shortcuts() {
        let compat_gates_src = include_str!("compat_gates.rs");
        let compatibility_gate_src = include_str!("compatibility_gate.rs");
        for banned in [
            ["placeholder", "signature"].join(" "),
            ["Simplified", "HMAC", "for", "demonstration"].join(" "),
            ["compat", "gate", "sign", "v1:"].join("_"),
        ] {
            assert!(
                !compat_gates_src.contains(&banned),
                "compat_gates.rs should not contain banned shortcut marker: {banned}"
            );
            assert!(
                !compatibility_gate_src.contains(&banned),
                "compatibility_gate.rs should not contain banned shortcut marker: {banned}"
            );
        }
    }

    // ── Edge Cases ──

    #[test]
    fn empty_registry_gate_eval() {
        let mut eval = CompatGateEvaluator::new(ShimRegistry::new());
        eval.set_mode("s1", CompatibilityMode::Balanced, "admin", "init", true)
            .unwrap();
        let result = eval.evaluate_gate("any-pkg", "s1", "t1").unwrap();
        assert_eq!(result.decision, GateDecision::Audit);
    }

    #[test]
    fn multiple_scopes_independent() {
        let mut eval = CompatGateEvaluator::new(sample_registry());
        eval.set_mode(
            "strict-scope",
            CompatibilityMode::Strict,
            "admin",
            "init",
            true,
        )
        .unwrap();
        eval.set_mode(
            "risky-scope",
            CompatibilityMode::LegacyRisky,
            "admin",
            "init",
            true,
        )
        .unwrap();

        // Same package, different scopes → different decisions
        let strict_result = eval
            .evaluate_gate("shim-hv-1", "strict-scope", "t1")
            .unwrap();
        let risky_result = eval
            .evaluate_gate("shim-hv-1", "risky-scope", "t2")
            .unwrap();

        assert_eq!(strict_result.decision, GateDecision::Deny);
        assert_eq!(risky_result.decision, GateDecision::Audit);
    }

    #[test]
    fn scope_count() {
        let eval = evaluator_with_scope();
        assert_eq!(eval.scope_count(), 1);
    }

    #[test]
    fn evaluation_count_starts_at_zero() {
        let eval = CompatGateEvaluator::new(sample_registry());
        assert_eq!(eval.evaluation_count(), 0);
    }

    #[test]
    fn action_strictness_ordering() {
        assert!(
            action_strictness(DivergenceAction::Blocked)
                > action_strictness(DivergenceAction::Error)
        );
        assert!(
            action_strictness(DivergenceAction::Error) > action_strictness(DivergenceAction::Warn)
        );
        assert!(
            action_strictness(DivergenceAction::Warn) > action_strictness(DivergenceAction::Log)
        );
    }

    #[test]
    fn divergence_action_display() {
        assert_eq!(DivergenceAction::Error.to_string(), "error");
        assert_eq!(DivergenceAction::Warn.to_string(), "warn");
        assert_eq!(DivergenceAction::Log.to_string(), "log");
        assert_eq!(DivergenceAction::Blocked.to_string(), "blocked");
    }

    #[test]
    fn shim_risk_category_label() {
        assert_eq!(ShimRiskCategory::Low.label(), "low");
        assert_eq!(ShimRiskCategory::Medium.label(), "medium");
        assert_eq!(ShimRiskCategory::High.label(), "high");
        assert_eq!(ShimRiskCategory::Critical.label(), "critical");
    }

    #[test]
    fn event_codes_defined() {
        assert_eq!(event_codes::PCG_GATE_PASS, "PCG-001");
        assert_eq!(event_codes::PCG_GATE_DENY, "PCG-002");
        assert_eq!(event_codes::PCG_MODE_TRANSITION, "PCG-003");
        assert_eq!(event_codes::PCG_RECEIPT_ISSUED, "PCG-004");
        assert_eq!(event_codes::PCG_GATE_AUDIT, "PCG-005");
        assert_eq!(event_codes::PCG_NONINTERFERENCE_VIOLATION, "PCG-006");
        assert_eq!(event_codes::PCG_MONOTONICITY_VIOLATION, "PCG-007");
        assert_eq!(event_codes::PCG_SHIM_REGISTERED, "PCG-008");
    }

    // ── Deterministic evaluation ──

    #[test]
    fn gate_eval_deterministic() {
        let mut eval1 = evaluator_with_scope();
        let mut eval2 = evaluator_with_scope();

        let r1 = eval1
            .evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();
        let r2 = eval2
            .evaluate_gate("shim-core-1", "project-1", "t1")
            .unwrap();

        assert_eq!(r1.decision, r2.decision);
        assert_eq!(r1.rationale, r2.rationale);
        assert_eq!(r1.event_code, r2.event_code);
    }

    #[test]
    fn unsafe_shim_allowed_only_in_legacy_risky() {
        let mut eval_strict = CompatGateEvaluator::new(sample_registry());
        eval_strict
            .set_mode("s", CompatibilityMode::Strict, "a", "i", true)
            .unwrap();
        let r = eval_strict
            .evaluate_gate("shim-unsafe-1", "s", "t")
            .unwrap();
        assert_eq!(r.decision, GateDecision::Deny);

        let mut eval_balanced = CompatGateEvaluator::new(sample_registry());
        eval_balanced
            .set_mode("s", CompatibilityMode::Balanced, "a", "i", true)
            .unwrap();
        let r = eval_balanced
            .evaluate_gate("shim-unsafe-1", "s", "t")
            .unwrap();
        assert_eq!(r.decision, GateDecision::Deny);

        let mut eval_risky = CompatGateEvaluator::new(sample_registry());
        eval_risky
            .set_mode("s", CompatibilityMode::LegacyRisky, "a", "i", true)
            .unwrap();
        let r = eval_risky.evaluate_gate("shim-unsafe-1", "s", "t").unwrap();
        assert_eq!(r.decision, GateDecision::Audit);
    }

    #[test]
    fn push_bounded_zero_capacity_clears_compat_gate_window() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_preserves_latest_compat_gate_entries() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }
}
