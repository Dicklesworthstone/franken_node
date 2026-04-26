//! Signed decision receipts for high-impact policy/control actions (bd-21z).
//!
//! This module provides:
//! - Deterministic receipt payload hashing (`SHA-256`)
//! - Ed25519 detached signing/verification over canonical JSON
//! - Append-only hash-chain linkage for tamper evidence
//! - JSON + CBOR export/import and query filtering
//! - High-impact action receipt enforcement

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::runtime::clock;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::capacity_defaults::aliases::MAX_RECEIPT_CHAIN;

/// Process-local receipt persistence lock.
///
/// Canonical lifecycle: receipt exports validate the target path and parent
/// directory first, then `write_bytes_atomically` acquires this lock before
/// creating the temp file, writing, syncing, and renaming it into place. The
/// lock is released by the guard drop on every return path; no caller may hold
/// another module's persist lock while acquiring it. If it is left held or
/// poisoned, subsequent receipt JSON/CBOR/Markdown writes in this process block
/// or fail before creating new receipt temp files.
static PERSIST_LOCK: Mutex<()> = Mutex::new(());

fn sync_directory(path: &Path) -> Result<(), ReceiptError> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ReceiptError::WriteFailed {
            path: path.display().to_string(),
            source,
            remediation_hint: "Check target directory permissions and filesystem consistency"
                .to_string(),
        })
}

fn normalized_directory(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

mod canonical_f64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.to_bits())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<f64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bits = u64::deserialize(deserializer)?;
        let value = f64::from_bits(bits);
        if value.is_finite() {
            Ok(value)
        } else {
            Err(de::Error::custom(
                "canonical f64 value must decode to a finite float",
            ))
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
        items.drain(0..overflow);
    }
    items.push(item);
}

pub type Ed25519PrivateKey = SigningKey;
pub type Ed25519PublicKey = VerifyingKey;
/// Canonical signature algorithm/version bound into every decision receipt payload.
pub const DECISION_RECEIPT_SIGNATURE_VERSION: &str = "ed25519-v1";

/// High-impact decision classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
    Escalated,
}

/// Unsigned receipt payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub action_name: String,
    pub actor_identity: String,
    pub timestamp: String,
    /// Signature algorithm/version committed into the canonical payload.
    pub signature_version: String,
    pub input_hash: String,
    pub output_hash: String,
    pub decision: Decision,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
    pub policy_rule_chain: Vec<String>,
    #[serde(with = "canonical_f64")]
    pub confidence: f64,
    pub rollback_command: String,
    pub previous_receipt_hash: Option<String>,
}

/// Signed receipt with hash-chain evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedReceipt {
    #[serde(flatten)]
    pub receipt: Receipt,
    pub signer_key_id: String,
    pub chain_hash: String,
    pub signature: String,
}

/// Query filter for exporting receipt subsets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    pub action_name: Option<String>,
    pub from_timestamp: Option<String>,
    pub to_timestamp: Option<String>,
    pub limit: Option<usize>,
}

/// Runtime registry for actions that require receipts.
#[derive(Debug, Clone, Default)]
pub struct HighImpactActionRegistry {
    actions: BTreeSet<String>,
}

/// Errors for receipt processing.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("failed to serialize canonical JSON: {0}")]
    CanonicalJson(serde_json::Error),
    #[error("failed to encode receipts as JSON: {0}")]
    JsonEncode(serde_json::Error),
    #[error("failed to encode receipts as CBOR: {0}")]
    #[cfg(feature = "cbor-serialization")]
    CborEncode(serde_cbor::Error),
    #[error("failed to decode receipts from CBOR: {0}")]
    #[cfg(feature = "cbor-serialization")]
    CborDecode(serde_cbor::Error),
    #[error("failed to decode signature: {0}")]
    SignatureDecode(base64::DecodeError),
    #[error("invalid Ed25519 signature bytes")]
    SignatureBytes,
    #[error("failed to parse timestamp '{timestamp}': {source}")]
    TimestampParse {
        timestamp: String,
        source: chrono::ParseError,
    },
    #[error("receipt confidence must be finite and within [0.0, 1.0], got {value}")]
    InvalidConfidence { value: f64 },
    #[error("unsupported decision receipt signature_version '{found}', expected '{expected}'")]
    UnsupportedSignatureVersion {
        expected: &'static str,
        found: String,
    },
    #[error("high-impact action '{action_name}' requires a signed receipt")]
    MissingHighImpactReceipt { action_name: String },
    #[error("hash-chain mismatch: expected {expected}, got {actual}")]
    HashChainMismatch { expected: String, actual: String },
    #[error("timestamp not monotonic: current '{current}' is not after previous '{previous}'")]
    TimestampNotMonotonic { current: String, previous: String },
    /// Failed to write receipt file to filesystem.
    ///
    /// This error occurs during atomic receipt persistence operations including:
    /// - Temporary file creation/writing
    /// - Directory creation for receipt storage
    /// - Atomic rename to final path
    /// - Lock acquisition for concurrent write safety
    #[error("failed to write receipt to {path}: {source}. {remediation_hint}")]
    WriteFailed {
        /// Filesystem path where the write operation failed
        path: String,
        /// Underlying I/O error from the filesystem operation
        source: std::io::Error,
        /// Specific remediation guidance for operators
        remediation_hint: String,
    },
    #[error("unsafe path '{path}': {reason}")]
    UnsafePath { path: String, reason: String },
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
}

impl Receipt {
    /// Construct a new receipt with canonical input/output hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_name: &str,
        actor_identity: &str,
        input: &impl Serialize,
        output: &impl Serialize,
        decision: Decision,
        rationale: &str,
        evidence_refs: Vec<String>,
        policy_rule_chain: Vec<String>,
        confidence: f64,
        rollback_command: &str,
    ) -> Result<Self, ReceiptError> {
        validate_confidence(confidence)?;
        Ok(Self {
            receipt_id: Uuid::now_v7().to_string(),
            action_name: action_name.to_string(),
            actor_identity: actor_identity.to_string(),
            timestamp: clock::wall_now().to_rfc3339(),
            signature_version: DECISION_RECEIPT_SIGNATURE_VERSION.to_string(),
            input_hash: hash_canonical_json(input)?,
            output_hash: hash_canonical_json(output)?,
            decision,
            rationale: rationale.to_string(),
            evidence_refs,
            policy_rule_chain,
            confidence,
            rollback_command: rollback_command.to_string(),
            previous_receipt_hash: None,
        })
    }

    /// Attach previous hash link for append-only chain usage.
    pub fn with_previous_hash(mut self, previous_receipt_hash: Option<String>) -> Self {
        self.previous_receipt_hash = previous_receipt_hash;
        self
    }

    /// Validate timestamp monotonicity against previous receipt.
    ///
    /// Ensures this receipt's timestamp is strictly after the previous receipt's timestamp
    /// to prevent chronological manipulation attacks via backdating or clock skew.
    pub fn validate_timestamp_monotonicity(
        &self,
        previous_timestamp: &str,
    ) -> Result<(), ReceiptError> {
        use chrono::DateTime;

        // Parse both timestamps
        let prev_time = DateTime::parse_from_rfc3339(previous_timestamp).map_err(|source| {
            ReceiptError::TimestampParse {
                timestamp: previous_timestamp.to_string(),
                source,
            }
        })?;

        let current_time = DateTime::parse_from_rfc3339(&self.timestamp).map_err(|source| {
            ReceiptError::TimestampParse {
                timestamp: self.timestamp.clone(),
                source,
            }
        })?;

        // SECURITY: Require strict monotonic ordering to prevent chronological manipulation
        if current_time <= prev_time {
            return Err(ReceiptError::TimestampNotMonotonic {
                current: self.timestamp.clone(),
                previous: previous_timestamp.to_string(),
            });
        }

        Ok(())
    }

    /// Create a new receipt with timestamp monotonicity validation against previous receipt.
    ///
    /// This constructor ensures cryptographically committed temporal ordering by:
    /// 1. Requiring the new timestamp to be strictly after the previous receipt's timestamp
    /// 2. Setting up the hash chain linkage via previous_receipt_hash
    /// 3. Preventing chronological manipulation attacks
    pub fn new_with_monotonic_timestamp(
        action_name: &str,
        actor_identity: &str,
        input: &impl Serialize,
        output: &impl Serialize,
        decision: Decision,
        rationale: &str,
        evidence_refs: Vec<String>,
        policy_rule_chain: Vec<String>,
        confidence: f64,
        rollback_command: &str,
        previous_receipt: Option<&Receipt>,
    ) -> Result<Self, ReceiptError> {
        let mut receipt = Self::new(
            action_name,
            actor_identity,
            input,
            output,
            decision,
            rationale,
            evidence_refs,
            policy_rule_chain,
            confidence,
            rollback_command,
        )?;

        // SECURITY: If there's a previous receipt, validate monotonic timestamp ordering
        if let Some(prev_receipt) = previous_receipt {
            receipt.validate_timestamp_monotonicity(&prev_receipt.timestamp)?;

            // Compute hash of previous receipt for chain integrity
            let prev_hash = hash_canonical_json(prev_receipt)?;
            receipt.previous_receipt_hash = Some(prev_hash);
        }

        Ok(receipt)
    }
}

impl HighImpactActionRegistry {
    /// Registry with default high-impact action classes from the bead contract.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::default();
        for action in [
            "quarantine",
            "revocation",
            "policy_change",
            "deployment_promotion",
            "trust_level_transition",
        ] {
            registry.register(action);
        }
        registry
    }

    pub fn register(&mut self, action_name: &str) {
        self.actions.insert(action_name.to_string());
    }

    #[must_use]
    pub fn is_high_impact(&self, action_name: &str) -> bool {
        self.actions.contains(action_name)
    }
}

/// Enforce that high-impact actions produce signed receipts.
///
/// Verifies both that a receipt is present AND that its action_name matches
/// the action being enforced. Without the action_name check, a receipt for
/// any low-impact action could satisfy the gate for a high-impact action.
pub fn enforce_high_impact_receipt(
    action_name: &str,
    registry: &HighImpactActionRegistry,
    receipt: Option<&SignedReceipt>,
) -> Result<(), ReceiptError> {
    if registry.is_high_impact(action_name) {
        match receipt {
            None => {
                return Err(ReceiptError::MissingHighImpactReceipt {
                    action_name: action_name.to_string(),
                });
            }
            Some(signed) if signed.receipt.action_name != action_name => {
                return Err(ReceiptError::MissingHighImpactReceipt {
                    action_name: action_name.to_string(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Create a detached Ed25519 signature over canonical receipt JSON.
pub fn sign_receipt(
    receipt: &Receipt,
    signing_key: &Ed25519PrivateKey,
) -> Result<SignedReceipt, ReceiptError> {
    validate_confidence(receipt.confidence)?;
    validate_signature_version(&receipt.signature_version)?;
    let payload = canonical_json(receipt)?;
    let signature = signing_key.sign(payload.as_bytes());
    let signature_b64 = BASE64_STANDARD.encode(signature.to_bytes());
    let chain_hash = compute_chain_hash(receipt.previous_receipt_hash.as_deref(), &payload);
    let signer_key_id = signing_key_id(&signing_key.verifying_key());

    Ok(SignedReceipt {
        receipt: receipt.clone(),
        signer_key_id,
        chain_hash,
        signature: signature_b64,
    })
}

/// Verify signature and hash-chain material for a signed receipt.
pub fn verify_receipt(
    signed: &SignedReceipt,
    public_key: &Ed25519PublicKey,
) -> Result<bool, ReceiptError> {
    validate_confidence(signed.receipt.confidence)?;
    validate_signature_version(&signed.receipt.signature_version)?;
    let expected_key_id = signing_key_id(public_key);
    if !crate::security::constant_time::ct_eq(&signed.signer_key_id, &expected_key_id) {
        return Ok(false);
    }

    let payload = canonical_json(&signed.receipt)?;
    let sig_bytes = BASE64_STANDARD
        .decode(&signed.signature)
        .map_err(ReceiptError::SignatureDecode)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| ReceiptError::SignatureBytes)?;

    if public_key.verify(payload.as_bytes(), &signature).is_err() {
        return Ok(false);
    }

    let expected_chain_hash =
        compute_chain_hash(signed.receipt.previous_receipt_hash.as_deref(), &payload);
    Ok(crate::security::constant_time::ct_eq(
        &expected_chain_hash,
        &signed.chain_hash,
    ))
}

/// Deterministic key ID shared with release-verification trust roots.
#[must_use]
pub fn signing_key_id(public_key: &Ed25519PublicKey) -> String {
    let hash = Sha256::digest(
        [
            b"artifact_signing_keyid_v1:" as &[u8],
            public_key.as_bytes(),
        ]
        .concat(),
    );
    hex::encode(&hash[..8])
}

/// Append and sign a receipt while preserving chain linkage.
pub fn append_signed_receipt(
    chain: &mut Vec<SignedReceipt>,
    receipt: Receipt,
    signing_key: &Ed25519PrivateKey,
) -> Result<SignedReceipt, ReceiptError> {
    let previous = chain.last().map(|r| r.chain_hash.clone());
    let signed = sign_receipt(&receipt.with_previous_hash(previous), signing_key)?;
    push_bounded(chain, signed.clone(), MAX_RECEIPT_CHAIN);
    Ok(signed)
}

/// Verify append-only hash-chain linkage and deterministic hash material.
pub fn verify_hash_chain(receipts: &[SignedReceipt]) -> Result<(), ReceiptError> {
    for (idx, signed) in receipts.iter().enumerate() {
        validate_signature_version(&signed.receipt.signature_version)?;
        let expected_previous = if idx == 0 {
            None
        } else {
            Some(receipts[idx - 1].chain_hash.clone())
        };
        let prev_match = match (&signed.receipt.previous_receipt_hash, &expected_previous) {
            (Some(a), Some(b)) => crate::security::constant_time::ct_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        if !prev_match {
            return Err(ReceiptError::HashChainMismatch {
                expected: expected_previous.unwrap_or_else(|| "<none>".to_string()),
                actual: signed
                    .receipt
                    .previous_receipt_hash
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string()),
            });
        }

        let payload = canonical_json(&signed.receipt)?;
        let expected_chain =
            compute_chain_hash(signed.receipt.previous_receipt_hash.as_deref(), &payload);
        if !crate::security::constant_time::ct_eq(&signed.chain_hash, &expected_chain) {
            return Err(ReceiptError::HashChainMismatch {
                expected: expected_chain,
                actual: signed.chain_hash.clone(),
            });
        }
    }
    Ok(())
}

/// Filter receipts by action and time window.
#[must_use]
pub fn export_receipts(receipts: &[SignedReceipt], filter: &ReceiptQuery) -> Vec<SignedReceipt> {
    let from = match filter
        .from_timestamp
        .as_deref()
        .map(parse_timestamp)
        .transpose()
    {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let to = match filter
        .to_timestamp
        .as_deref()
        .map(parse_timestamp)
        .transpose()
    {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    if from
        .as_ref()
        .zip(to.as_ref())
        .is_some_and(|(from_ts, to_ts)| from_ts > to_ts)
    {
        return Vec::new();
    }

    let mut selected: Vec<SignedReceipt> = receipts
        .iter()
        .filter(|receipt| {
            if let Some(action_name) = filter.action_name.as_deref()
                && receipt.receipt.action_name != action_name
            {
                return false;
            }

            let timestamp = match parse_timestamp(&receipt.receipt.timestamp) {
                Ok(value) => value,
                Err(_) => return false,
            };

            if let Some(from_ts) = from.as_ref()
                && &timestamp < from_ts
            {
                return false;
            }
            if let Some(to_ts) = to.as_ref()
                && &timestamp > to_ts
            {
                return false;
            }
            true
        })
        .cloned()
        .collect();

    if let Some(limit) = filter.limit {
        selected.truncate(limit);
    }
    selected
}

/// Export filtered receipts as JSON.
pub fn export_receipts_json(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
) -> Result<String, ReceiptError> {
    serde_json::to_string_pretty(&export_receipts(receipts, filter))
        .map_err(ReceiptError::JsonEncode)
}

/// Export filtered receipts as CBOR.
#[cfg(feature = "cbor-serialization")]
pub fn export_receipts_cbor(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
) -> Result<Vec<u8>, ReceiptError> {
    serde_cbor::to_vec(&export_receipts(receipts, filter)).map_err(ReceiptError::CborEncode)
}

/// Import receipts from CBOR.
#[cfg(feature = "cbor-serialization")]
pub fn import_receipts_cbor(bytes: &[u8]) -> Result<Vec<SignedReceipt>, ReceiptError> {
    let receipts: Vec<SignedReceipt> =
        serde_cbor::from_slice(bytes).map_err(ReceiptError::CborDecode)?;
    for signed in &receipts {
        validate_confidence(signed.receipt.confidence)?;
    }
    Ok(receipts)
}

/// Write filtered receipt export to file. `.cbor` writes binary CBOR; all other
/// suffixes write JSON.
pub fn export_receipts_to_path(
    receipts: &[SignedReceipt],
    filter: &ReceiptQuery,
    path: &Path,
) -> Result<(), ReceiptError> {
    validate_safe_path(path)?;
    ensure_parent_dir(path)?;
    if path.extension().and_then(std::ffi::OsStr::to_str) == Some("cbor") {
        #[cfg(feature = "cbor-serialization")]
        {
            let bytes = export_receipts_cbor(receipts, filter)?;
            write_bytes_atomically(path, &bytes)
        }
        #[cfg(not(feature = "cbor-serialization"))]
        {
            Err(ReceiptError::UnsupportedFormat(
                "CBOR export disabled (cbor-serialization feature not enabled)".to_string(),
            ))
        }
    } else {
        let json = export_receipts_json(receipts, filter)?;
        write_bytes_atomically(path, json.as_bytes())
    }
}

/// Render a human-readable Markdown export.
#[must_use]
pub fn render_receipts_markdown(receipts: &[SignedReceipt]) -> String {
    let mut output = String::from(
        "# Signed Decision Receipts\n\n| Receipt ID | Action | Actor | Decision | Key ID | Timestamp |\n|---|---|---|---|---|---|\n",
    );
    for receipt in receipts {
        let decision = match receipt.receipt.decision {
            Decision::Approved => "approved",
            Decision::Denied => "denied",
            Decision::Escalated => "escalated",
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            receipt.receipt.receipt_id,
            receipt.receipt.action_name,
            receipt.receipt.actor_identity,
            decision,
            receipt.signer_key_id,
            receipt.receipt.timestamp
        ));
    }
    output
}

pub fn write_receipts_markdown(
    receipts: &[SignedReceipt],
    path: &Path,
) -> Result<(), ReceiptError> {
    validate_safe_path(path)?;
    ensure_parent_dir(path)?;
    let markdown = render_receipts_markdown(receipts);
    write_bytes_atomically(path, markdown.as_bytes())
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), ReceiptError> {
    let _guard = PERSIST_LOCK.lock().map_err(|_| ReceiptError::WriteFailed {
        path: path.display().to_string(),
        source: std::io::Error::other("receipt persist lock poisoned"),
        remediation_hint: "Check for concurrent receipt operations or restart process".to_string(),
    })?;
    let parent = normalized_directory(path.parent().unwrap_or_else(|| Path::new(".")));
    let mut temp = TempFileGuard::new(path);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp.path())
            .map_err(|source| ReceiptError::WriteFailed {
                path: path.display().to_string(),
                source,
                remediation_hint: "Check directory permissions and available disk space"
                    .to_string(),
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| ReceiptError::WriteFailed {
                path: path.display().to_string(),
                source,
                remediation_hint: "Check available disk space and filesystem integrity".to_string(),
            })?;
    }
    temp.persist(path)?;
    sync_directory(parent)?;
    if let Some(ancestor) = parent.parent() {
        let ancestor = normalized_directory(ancestor);
        if ancestor != parent {
            sync_directory(ancestor)?;
        }
    }
    Ok(())
}

struct TempFileGuard {
    path: PathBuf,
    persisted: bool,
}

impl TempFileGuard {
    fn new(target: &Path) -> Self {
        let file_name = target
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .filter(|name| !name.is_empty())
            .unwrap_or("receipt-export");
        let temp_name = format!(".{file_name}.{}.tmp", Uuid::now_v7());
        let temp_path = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(
                || PathBuf::from(&temp_name),
                |parent| parent.join(&temp_name),
            );

        Self {
            path: temp_path,
            persisted: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&mut self, target: &Path) -> Result<(), ReceiptError> {
        std::fs::rename(&self.path, target).map_err(|source| ReceiptError::WriteFailed {
            path: target.display().to_string(),
            source,
            remediation_hint: "Check target directory permissions and filesystem consistency"
                .to_string(),
        })?;
        self.persisted = true;
        Ok(())
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn fixture_signing_key(label: &[u8]) -> Ed25519PrivateKey {
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_test_fixture_key_v1:");
    hasher.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    let seed: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&seed)
}

/// Deterministic fixture signing key for tests and sample artifacts.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn demo_signing_key() -> Ed25519PrivateKey {
    fixture_signing_key(b"decision-receipt-demo-key-1")
}

/// Deterministic fixture verification key matching [`demo_signing_key`].
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn demo_public_key() -> Ed25519PublicKey {
    demo_signing_key().verifying_key()
}

fn parse_timestamp(timestamp: &str) -> Result<DateTime<Utc>, ReceiptError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|source| ReceiptError::TimestampParse {
            timestamp: timestamp.to_string(),
            source,
        })
}

fn validate_confidence(confidence: f64) -> Result<(), ReceiptError> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(ReceiptError::InvalidConfidence { value: confidence });
    }
    Ok(())
}

fn validate_signature_version(signature_version: &str) -> Result<(), ReceiptError> {
    if signature_version == DECISION_RECEIPT_SIGNATURE_VERSION {
        return Ok(());
    }

    Err(ReceiptError::UnsupportedSignatureVersion {
        expected: DECISION_RECEIPT_SIGNATURE_VERSION,
        found: signature_version.to_string(),
    })
}

fn hash_canonical_json(value: &impl Serialize) -> Result<String, ReceiptError> {
    let canonical = canonical_json(value)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn canonical_json(value: &impl Serialize) -> Result<String, ReceiptError> {
    let serialized = serde_json::to_value(value).map_err(ReceiptError::CanonicalJson)?;
    let canonicalized = canonicalize_value(serialized);
    serde_json::to_string(&canonicalized).map_err(ReceiptError::CanonicalJson)
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            let mut canonical_map = serde_json::Map::with_capacity(entries.len());
            for (key, nested) in entries {
                canonical_map.insert(key, canonicalize_value(nested));
            }
            Value::Object(canonical_map)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_hash_v1:");
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn compute_chain_hash(previous_hash: Option<&str>, payload: &str) -> String {
    let prev = previous_hash.unwrap_or("GENESIS");
    let mut hasher = Sha256::new();
    hasher.update(b"decision_receipt_chain_v1:");
    hasher.update(u64::try_from(prev.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(
        u64::try_from(payload.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

fn validate_safe_path(path: &Path) -> Result<(), ReceiptError> {
    let path_str = path.to_string_lossy();

    // Reject null bytes
    if path_str.contains('\0') {
        return Err(ReceiptError::UnsafePath {
            path: path_str.to_string(),
            reason: "contains null bytes".to_string(),
        });
    }

    // Reject absolute paths (leading /)
    if path.is_absolute() {
        return Err(ReceiptError::UnsafePath {
            path: path_str.to_string(),
            reason: "absolute paths not allowed".to_string(),
        });
    }

    // Check each path component for traversal attempts
    for component in path.components() {
        let component_str = component.as_os_str().to_string_lossy();

        // Reject parent directory traversal
        if component_str == ".." {
            return Err(ReceiptError::UnsafePath {
                path: path_str.to_string(),
                reason: "path traversal with '..' not allowed".to_string(),
            });
        }

        // Reject backslashes on Unix (potential Windows-style traversal)
        if component_str.contains('\\') {
            return Err(ReceiptError::UnsafePath {
                path: path_str.to_string(),
                reason: "backslashes not allowed in path components".to_string(),
            });
        }
    }

    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), ReceiptError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| ReceiptError::WriteFailed {
            path: path.display().to_string(),
            source,
            remediation_hint: "Check parent directory permissions and available inodes".to_string(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};

    fn cwd_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn make_receipt(action_name: &str, decision: Decision) -> Receipt {
        Receipt::new(
            action_name,
            "control-plane@prod",
            &json!({"z": 1, "a": 2}),
            &json!({"result": "ok"}),
            decision,
            "policy gate evaluated",
            vec!["ledger-001".to_string()],
            vec!["rule-A".to_string(), "rule-B".to_string()],
            0.91,
            "franken-node trust release --incident INC-001",
        )
        .expect("receipt construction")
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let canonical = canonical_json(&json!({"b": 2, "a": 1})).expect("canonical JSON");
        assert_eq!(canonical, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn sign_receipt_records_signer_key_id() {
        let receipt = make_receipt("quarantine", Decision::Approved);
        let signing_key = demo_signing_key();
        let signed = sign_receipt(&receipt, &signing_key).expect("receipt should sign");
        assert_eq!(
            signed.signer_key_id,
            signing_key_id(&signing_key.verifying_key())
        );
    }

    #[test]
    fn receipt_new_sets_signature_version() {
        let receipt = make_receipt("quarantine", Decision::Approved);
        assert_eq!(
            receipt.signature_version,
            DECISION_RECEIPT_SIGNATURE_VERSION
        );
    }

    #[test]
    fn demo_signing_key_is_test_support_fixture_only() {
        let first = demo_signing_key();
        let second = demo_signing_key();

        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_ne!(first.to_bytes(), [42_u8; 32]);
        assert_eq!(
            demo_public_key().as_bytes(),
            first.verifying_key().as_bytes()
        );
    }

    #[test]
    fn receipt_new_rejects_out_of_range_confidence() {
        let err = Receipt::new(
            "quarantine",
            "control-plane@prod",
            &json!({"z": 1, "a": 2}),
            &json!({"result": "ok"}),
            Decision::Approved,
            "policy gate evaluated",
            vec!["ledger-001".to_string()],
            vec!["rule-A".to_string(), "rule-B".to_string()],
            1.5,
            "franken-node trust release --incident INC-001",
        )
        .expect_err("out-of-range confidence must fail");
        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value == 1.5));
    }

    #[test]
    fn receipt_new_rejects_nan_confidence() {
        let err = Receipt::new(
            "quarantine",
            "control-plane@prod",
            &json!({"z": 1, "a": 2}),
            &json!({"result": "ok"}),
            Decision::Approved,
            "policy gate evaluated",
            vec!["ledger-001".to_string()],
            vec!["rule-A".to_string()],
            f64::NAN,
            "franken-node trust release --incident INC-001",
        )
        .expect_err("NaN confidence must fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value.is_nan()));
    }

    #[test]
    fn sign_receipt_rejects_negative_confidence() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.confidence = -0.01;

        let err = sign_receipt(&receipt, &key).expect_err("negative confidence must fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value == -0.01));
    }

    #[test]
    fn sign_receipt_rejects_infinite_confidence() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.confidence = f64::INFINITY;

        let err = sign_receipt(&receipt, &key).expect_err("infinite confidence must fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value.is_infinite()));
    }

    #[test]
    fn sign_receipt_rejects_above_one_confidence_after_mutation() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.confidence = 1.01;

        let err = sign_receipt(&receipt, &key).expect_err("confidence above one must fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value == 1.01));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let receipt = make_receipt("quarantine", Decision::Approved);
        let signed = sign_receipt(&receipt, &key).expect("sign");
        let verified = verify_receipt(&signed, &public_key).expect("verify");
        assert!(verified);
    }

    #[test]
    fn verify_receipt_rejects_non_finite_confidence() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.receipt.confidence = f64::NAN;

        let err = verify_receipt(&signed, &public_key)
            .expect_err("non-finite confidence must fail verification");
        assert!(matches!(err, ReceiptError::InvalidConfidence { value } if value.is_nan()));
    }

    #[test]
    fn verify_receipt_rejects_unknown_signature_version() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.receipt.signature_version = "ed25519-v2".to_string();

        let err = verify_receipt(&signed, &public_key)
            .expect_err("unknown signature version must fail verification");

        assert!(matches!(
            err,
            ReceiptError::UnsupportedSignatureVersion { ref found, .. } if found == "ed25519-v2"
        ));
    }

    #[test]
    fn unversioned_signed_receipt_json_fails_before_verification() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        let mut legacy_json = serde_json::to_value(&signed).expect("signed receipt to JSON");
        legacy_json
            .as_object_mut()
            .expect("signed receipt JSON object")
            .remove("signature_version");

        let err = serde_json::from_value::<SignedReceipt>(legacy_json)
            .expect_err("missing signature_version must fail deserialization");

        assert!(err.to_string().contains("signature_version"));
    }

    #[test]
    fn verify_receipt_rejects_wrong_signer_key_id() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.signer_key_id = "deadbeefdeadbeef".to_string();
        let verified = verify_receipt(&signed, &public_key).expect("verify");
        assert!(!verified);
    }

    #[test]
    fn verify_receipt_rejects_whitespace_signer_key_id() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.signer_key_id = format!(" {} ", signed.signer_key_id);

        let verified = verify_receipt(&signed, &public_key).expect("verify");

        assert!(!verified);
    }

    #[test]
    fn tamper_detection_fails_verification() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let receipt = make_receipt("revocation", Decision::Denied);
        let mut signed = sign_receipt(&receipt, &key).expect("sign");
        signed.receipt.rationale = "tampered".to_string();
        let verified = verify_receipt(&signed, &public_key).expect("verify");
        assert!(!verified);
    }

    #[test]
    fn verify_receipt_rejects_invalid_base64_signature() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.signature = "not base64!!!".to_string();

        let err = verify_receipt(&signed, &public_key)
            .expect_err("invalid base64 signature should error");

        assert!(matches!(err, ReceiptError::SignatureDecode(_)));
    }

    #[test]
    fn verify_receipt_rejects_wrong_signature_length() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.signature = BASE64_STANDARD.encode([0_u8; 31]);

        let err =
            verify_receipt(&signed, &public_key).expect_err("wrong signature length should error");

        assert!(matches!(err, ReceiptError::SignatureBytes));
    }

    #[test]
    fn verify_receipt_with_wrong_public_key_returns_false() {
        let key = demo_signing_key();
        let wrong_public_key = SigningKey::from_bytes(&[7_u8; 32]).verifying_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");

        let verified = verify_receipt(&signed, &wrong_public_key).expect("verify");

        assert!(!verified);
    }

    #[test]
    fn verify_receipt_rejects_tampered_chain_hash() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.chain_hash = "00".repeat(32);

        let verified = verify_receipt(&signed, &public_key).expect("verify");

        assert!(!verified);
    }

    #[test]
    fn verify_receipt_rejects_empty_signature_bytes() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.signature = BASE64_STANDARD.encode([]);

        let err =
            verify_receipt(&signed, &public_key).expect_err("empty signature bytes must fail");

        assert!(matches!(err, ReceiptError::SignatureBytes));
    }

    #[test]
    fn verify_receipt_rejects_action_name_tampering_after_signing() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let mut signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        signed.receipt.action_name = "revocation".to_string();

        let verified = verify_receipt(&signed, &public_key).expect("verify");

        assert!(!verified);
    }

    #[test]
    fn verify_receipt_rejects_previous_hash_tampering_after_signing() {
        let key = demo_signing_key();
        let public_key = key.verifying_key();
        let receipt = make_receipt("quarantine", Decision::Approved)
            .with_previous_hash(Some("prior-link".to_string()));
        let mut signed = sign_receipt(&receipt, &key).expect("sign");
        signed.receipt.previous_receipt_hash = Some("other-link".to_string());

        let verified = verify_receipt(&signed, &public_key).expect("verify");

        assert!(!verified);
    }

    #[test]
    fn hash_chain_verification_detects_breaks() {
        let key = demo_signing_key();
        let mut chain = Vec::new();

        append_signed_receipt(
            &mut chain,
            make_receipt("quarantine", Decision::Approved),
            &key,
        )
        .expect("append #1");
        append_signed_receipt(
            &mut chain,
            make_receipt("deployment_promotion", Decision::Escalated),
            &key,
        )
        .expect("append #2");

        verify_hash_chain(&chain).expect("chain should be valid");

        chain[1].receipt.previous_receipt_hash = Some("broken-link".to_string());
        let err = verify_hash_chain(&chain).expect_err("chain should fail");
        assert!(matches!(err, ReceiptError::HashChainMismatch { .. }));
    }

    #[test]
    fn hash_chain_rejects_genesis_receipt_with_previous_hash() {
        let key = demo_signing_key();
        let receipt = make_receipt("quarantine", Decision::Approved)
            .with_previous_hash(Some("unexpected-previous".to_string()));
        let signed = sign_receipt(&receipt, &key).expect("sign");

        let err = verify_hash_chain(&[signed]).expect_err("genesis previous hash must fail");

        assert!(matches!(
            err,
            ReceiptError::HashChainMismatch { expected, actual }
                if expected == "<none>" && actual == "unexpected-previous"
        ));
    }

    #[test]
    fn hash_chain_rejects_out_of_order_receipts() {
        let key = demo_signing_key();
        let mut chain = Vec::new();
        append_signed_receipt(
            &mut chain,
            make_receipt("quarantine", Decision::Approved),
            &key,
        )
        .expect("append #1");
        append_signed_receipt(
            &mut chain,
            make_receipt("revocation", Decision::Denied),
            &key,
        )
        .expect("append #2");

        chain.swap(0, 1);
        let err = verify_hash_chain(&chain).expect_err("reordered chain must fail");

        assert!(matches!(err, ReceiptError::HashChainMismatch { .. }));
    }

    #[test]
    fn hash_chain_rejects_second_receipt_missing_previous_hash() {
        let key = demo_signing_key();
        let mut chain = Vec::new();
        append_signed_receipt(
            &mut chain,
            make_receipt("quarantine", Decision::Approved),
            &key,
        )
        .expect("append #1");
        append_signed_receipt(
            &mut chain,
            make_receipt("revocation", Decision::Denied),
            &key,
        )
        .expect("append #2");

        let expected_previous = chain[0].chain_hash.clone();
        chain[1].receipt.previous_receipt_hash = None;
        let err = verify_hash_chain(&chain).expect_err("missing second link must fail");

        assert!(matches!(
            err,
            ReceiptError::HashChainMismatch { expected, actual }
                if expected == expected_previous && actual == "<none>"
        ));
    }

    #[test]
    fn hash_chain_rejects_second_receipt_tampered_chain_hash() {
        let key = demo_signing_key();
        let mut chain = Vec::new();
        append_signed_receipt(
            &mut chain,
            make_receipt("quarantine", Decision::Approved),
            &key,
        )
        .expect("append #1");
        append_signed_receipt(
            &mut chain,
            make_receipt("revocation", Decision::Denied),
            &key,
        )
        .expect("append #2");

        chain[1].chain_hash = "ff".repeat(32);
        let err = verify_hash_chain(&chain).expect_err("tampered chain hash must fail");

        assert!(matches!(err, ReceiptError::HashChainMismatch { .. }));
    }

    #[test]
    fn cbor_roundtrip_preserves_receipts() {
        let key = demo_signing_key();
        let mut chain = Vec::new();
        append_signed_receipt(
            &mut chain,
            make_receipt("policy_change", Decision::Approved),
            &key,
        )
        .expect("append");

        let filter = ReceiptQuery::default();
        let encoded = export_receipts_cbor(&chain, &filter).expect("encode CBOR");
        let decoded = import_receipts_cbor(&encoded).expect("decode CBOR");
        assert_eq!(decoded, chain);
    }

    #[test]
    #[cfg(feature = "cbor-serialization")]
    fn import_receipts_cbor_rejects_invalid_bytes() {
        let err = import_receipts_cbor(b"not-cbor").expect_err("invalid CBOR must fail");

        assert!(matches!(err, ReceiptError::CborDecode(_)));
    }

    #[test]
    #[cfg(feature = "cbor-serialization")]
    fn import_receipts_cbor_rejects_partially_shaped_receipt_list() {
        let encoded = serde_cbor::to_vec(&vec![json!({
            "receipt_id": "receipt-1",
            "action_name": "quarantine"
        })])
        .expect("encode partial receipt");

        let err = import_receipts_cbor(&encoded).expect_err("partial receipt list must fail");

        assert!(matches!(err, ReceiptError::CborDecode(_)));
    }

    #[test]
    fn export_filter_supports_action_and_time_window() {
        let key = demo_signing_key();
        let mut first = make_receipt("quarantine", Decision::Approved);
        first.timestamp = "2026-02-20T10:00:00Z".to_string();
        let mut second = make_receipt("revocation", Decision::Denied);
        second.timestamp = "2026-02-20T11:00:00Z".to_string();

        let first = sign_receipt(&first, &key).expect("sign first");
        let second = sign_receipt(&second, &key).expect("sign second");
        let chain = vec![first.clone(), second];

        let filter = ReceiptQuery {
            action_name: Some("quarantine".to_string()),
            from_timestamp: Some("2026-02-20T09:30:00Z".to_string()),
            to_timestamp: Some("2026-02-20T10:30:00Z".to_string()),
            limit: Some(10),
        };
        let exported = export_receipts(&chain, &filter);
        assert_eq!(exported, vec![first]);
    }

    #[test]
    fn export_filter_excludes_receipts_with_invalid_timestamps() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.timestamp = "not-a-timestamp".to_string();
        let signed = sign_receipt(&receipt, &key).expect("sign");

        let exported = export_receipts(&[signed], &ReceiptQuery::default());

        assert!(exported.is_empty());
    }

    #[test]
    fn export_filter_action_name_is_exact_and_not_normalized() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        let chain = vec![signed];

        for action_name in [" quarantine", "quarantine ", "QUARANTINE"] {
            let exported = export_receipts(
                &chain,
                &ReceiptQuery {
                    action_name: Some(action_name.to_string()),
                    ..ReceiptQuery::default()
                },
            );

            assert!(exported.is_empty());
        }
    }

    #[test]
    fn export_filter_reversed_time_window_returns_empty() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.timestamp = "2026-02-20T10:00:00Z".to_string();
        let signed = sign_receipt(&receipt, &key).expect("sign");
        let filter = ReceiptQuery {
            from_timestamp: Some("2026-02-20T11:00:00Z".to_string()),
            to_timestamp: Some("2026-02-20T09:00:00Z".to_string()),
            ..ReceiptQuery::default()
        };

        let exported = export_receipts(&[signed], &filter);

        assert!(exported.is_empty());
    }

    #[test]
    fn export_filter_invalid_from_timestamp_fails_closed() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.timestamp = "2026-02-20T10:00:00Z".to_string();
        let signed = sign_receipt(&receipt, &key).expect("sign");
        let filter = ReceiptQuery {
            from_timestamp: Some("not-a-timestamp".to_string()),
            ..ReceiptQuery::default()
        };

        let exported = export_receipts(&[signed], &filter);

        assert!(exported.is_empty());
    }

    #[test]
    fn export_filter_invalid_to_timestamp_fails_closed() {
        let key = demo_signing_key();
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.timestamp = "2026-02-20T10:00:00Z".to_string();
        let signed = sign_receipt(&receipt, &key).expect("sign");
        let filter = ReceiptQuery {
            to_timestamp: Some("not-a-timestamp".to_string()),
            ..ReceiptQuery::default()
        };

        let exported = export_receipts(&[signed], &filter);

        assert!(exported.is_empty());
    }

    #[test]
    fn export_filter_zero_limit_returns_empty() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        let filter = ReceiptQuery {
            limit: Some(0),
            ..ReceiptQuery::default()
        };

        let exported = export_receipts(&[signed], &filter);

        assert!(exported.is_empty());
    }

    #[test]
    #[cfg(feature = "cbor-serialization")]
    fn import_receipts_cbor_rejects_non_receipt_shape() {
        let encoded = serde_cbor::to_vec(&json!({"not": "a receipt list"})).expect("encode");

        let err = import_receipts_cbor(&encoded).expect_err("non-receipt CBOR shape must fail");

        assert!(matches!(err, ReceiptError::CborDecode(_)));
    }

    #[test]
    fn high_impact_registry_requires_receipt() {
        let registry = HighImpactActionRegistry::with_defaults();
        let err =
            enforce_high_impact_receipt("quarantine", &registry, None).expect_err("must fail");
        assert!(matches!(err, ReceiptError::MissingHighImpactReceipt { .. }));
        assert!(
            enforce_high_impact_receipt(
                "quarantine",
                &registry,
                Some(
                    &sign_receipt(
                        &make_receipt("quarantine", Decision::Approved),
                        &demo_signing_key(),
                    )
                    .expect("sign")
                )
            )
            .is_ok()
        );
    }

    #[test]
    fn high_impact_registry_rejects_receipt_for_different_action() {
        let registry = HighImpactActionRegistry::with_defaults();
        let signed = sign_receipt(
            &make_receipt("revocation", Decision::Approved),
            &demo_signing_key(),
        )
        .expect("sign");

        let err = enforce_high_impact_receipt("quarantine", &registry, Some(&signed))
            .expect_err("mismatched high-impact receipt must fail");

        assert!(matches!(
            err,
            ReceiptError::MissingHighImpactReceipt { action_name }
                if action_name == "quarantine"
        ));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_item_without_panic() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn markdown_render_contains_headers() {
        let key = demo_signing_key();
        let signed = sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).unwrap();
        let markdown = render_receipts_markdown(&[signed]);
        assert!(markdown.contains("Signed Decision Receipts"));
        assert!(
            markdown.contains("| Receipt ID | Action | Actor | Decision | Key ID | Timestamp |")
        );
    }

    #[test]
    fn export_receipts_to_path_creates_missing_parent_directories() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");
        let dir = tempfile::tempdir().expect("tempdir");
        let output_path = dir.path().join("nested/receipts.json");

        export_receipts_to_path(&[signed], &ReceiptQuery::default(), &output_path).expect("export");

        let exported = std::fs::read_to_string(&output_path).expect("read");
        assert!(exported.contains("quarantine"));
    }

    #[test]
    fn write_receipts_markdown_creates_missing_parent_directories() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("revocation", Decision::Denied), &key).expect("sign");
        let dir = tempfile::tempdir().expect("tempdir");
        let output_path = dir.path().join("nested/receipts.md");

        write_receipts_markdown(&[signed], &output_path).expect("write markdown");

        let markdown = std::fs::read_to_string(&output_path).expect("read");
        assert!(markdown.contains("Signed Decision Receipts"));
        assert!(markdown.contains("revocation"));
    }

    #[test]
    fn write_receipts_markdown_supports_relative_output_in_current_directory() {
        let _guard = cwd_test_lock().lock().expect("cwd lock");
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("revocation", Decision::Denied), &key).expect("sign");
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("cwd");

        std::env::set_current_dir(dir.path()).expect("set cwd");
        let write_result = write_receipts_markdown(&[signed], Path::new("receipts.md"));
        let restore_result = std::env::set_current_dir(&previous_cwd);

        write_result.expect("write relative markdown");
        restore_result.expect("restore cwd");
        let markdown = std::fs::read_to_string(dir.path().join("receipts.md")).expect("read");
        assert!(markdown.contains("Signed Decision Receipts"));
        assert!(markdown.contains("revocation"));
    }

    #[test]
    fn atomic_export_failure_leaves_no_partial_target_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target_dir = dir.path().join("receipts.json");
        std::fs::create_dir(&target_dir).expect("create target directory");

        let err = write_bytes_atomically(&target_dir, b"partial export bytes")
            .expect_err("rename over a directory must fail");

        assert!(matches!(err, ReceiptError::WriteFailed { .. }));
        assert!(target_dir.is_dir());
        assert!(std::fs::read_to_string(&target_dir).is_err());
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read tempdir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("receipts.json")]);
    }

    /// Negative path: empty receipt ID accepted but may cause lookup issues
    #[test]
    fn receipt_with_empty_id_field_constructed_successfully() {
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.receipt_id = String::new();

        let key = demo_signing_key();
        let signed = sign_receipt(&receipt, &key).expect("empty receipt_id should be signable");

        assert_eq!(signed.receipt.receipt_id, "");
        assert!(!signed.signature.is_empty());
    }

    /// Negative path: unicode and special characters in action names
    #[test]
    fn unicode_action_name_preserved_through_signature_process() {
        let mut receipt = make_receipt("🔥quarantine🚫", Decision::Denied);
        receipt.actor_identity = "用户@🌍.example.com".to_string();
        receipt.rationale = "Policy violation: 漢字 and émoji mixed content".to_string();

        let key = demo_signing_key();
        let signed = sign_receipt(&receipt, &key).expect("unicode content should be signable");

        assert_eq!(signed.receipt.action_name, "🔥quarantine🚫");
        assert!(signed.receipt.rationale.contains("漢字"));

        // Verification should still work with unicode content
        let verified = verify_receipt(&signed, &key.verifying_key()).expect("verify");
        assert!(verified);
    }

    /// Negative path: extremely long string fields approaching memory limits
    #[test]
    fn extremely_long_rationale_field_accepted_despite_memory_pressure() {
        let huge_rationale = "A".repeat(1_000_000); // 1MB rationale
        let mut receipt = make_receipt("quarantine", Decision::Escalated);
        receipt.rationale = huge_rationale.clone();

        let key = demo_signing_key();
        let signed = sign_receipt(&receipt, &key).expect("huge rationale should be signable");

        assert_eq!(signed.receipt.rationale.len(), 1_000_000);
        assert!(signed.receipt.rationale.starts_with("AAAA"));

        // Hash computation should handle large inputs
        assert!(!signed.chain_hash.is_empty());
        assert_eq!(signed.chain_hash.len(), 64); // SHA-256 hex length
    }

    /// Negative path: null bytes embedded in string fields
    #[test]
    fn null_bytes_in_receipt_fields_preserved_causing_downstream_issues() {
        let mut receipt = make_receipt("quarantine", Decision::Approved);
        receipt.actor_identity = "admin\0@example.com".to_string();
        receipt.rollback_command = "franken-node\0 --incident \0 INC-\0001".to_string();
        receipt.evidence_refs = vec!["EVD\0-001".to_string(), "ref\0with\0nulls".to_string()];

        let key = demo_signing_key();
        let signed = sign_receipt(&receipt, &key).expect("null bytes should be preserved");

        assert!(signed.receipt.actor_identity.contains('\0'));
        assert!(signed.receipt.rollback_command.contains('\0'));
        assert!(signed.receipt.evidence_refs[0].contains('\0'));

        // Canonical JSON serialization preserves null bytes which may break downstream parsers
        let canonical = canonical_json(&signed.receipt).expect("canonical JSON");
        assert!(canonical.contains("\\u0000"));
    }

    /// Negative path: malformed file path handling in export operations
    #[test]
    fn export_to_invalid_file_path_returns_write_error() {
        let key = demo_signing_key();
        let signed =
            sign_receipt(&make_receipt("quarantine", Decision::Approved), &key).expect("sign");

        // Attempt to write to invalid path (contains null byte on Unix systems)
        let invalid_path = std::path::Path::new("receipts\0.json");
        let err = export_receipts_to_path(&[signed], &ReceiptQuery::default(), invalid_path)
            .expect_err("invalid path should fail");

        assert!(matches!(err, ReceiptError::UnsafePath { .. }));
    }

    #[test]
    fn validate_safe_path_rejects_null_bytes() {
        let err = validate_safe_path(std::path::Path::new("file\0name.json"))
            .expect_err("null bytes should be rejected");

        assert!(
            matches!(err, ReceiptError::UnsafePath { reason, .. } if reason.contains("null bytes"))
        );
    }

    #[test]
    fn validate_safe_path_rejects_absolute_paths() {
        let err = validate_safe_path(std::path::Path::new("/etc/passwd"))
            .expect_err("absolute paths should be rejected");

        assert!(
            matches!(err, ReceiptError::UnsafePath { reason, .. } if reason.contains("absolute paths"))
        );
    }

    #[test]
    fn validate_safe_path_rejects_parent_directory_traversal() {
        let err = validate_safe_path(std::path::Path::new("../../../etc/passwd"))
            .expect_err("parent directory traversal should be rejected");

        assert!(
            matches!(err, ReceiptError::UnsafePath { reason, .. } if reason.contains("path traversal"))
        );
    }

    #[test]
    fn validate_safe_path_rejects_backslashes() {
        let err = validate_safe_path(std::path::Path::new("directory\\filename.json"))
            .expect_err("backslashes should be rejected");

        assert!(
            matches!(err, ReceiptError::UnsafePath { reason, .. } if reason.contains("backslashes"))
        );
    }

    #[test]
    fn validate_safe_path_accepts_safe_relative_paths() {
        validate_safe_path(std::path::Path::new("receipts/export.json"))
            .expect("safe relative path should be accepted");

        validate_safe_path(std::path::Path::new("nested/directory/file.cbor"))
            .expect("nested safe path should be accepted");

        validate_safe_path(std::path::Path::new("simple.md"))
            .expect("simple filename should be accepted");
    }

    /// Negative path: hash chain computation with pathological inputs
    #[test]
    fn hash_chain_computation_handles_extremely_long_payload_without_overflow() {
        let huge_payload = "x".repeat(100_000_000); // 100MB payload
        let chain_hash = compute_chain_hash(Some("previous-hash"), &huge_payload);

        // Should not panic or overflow despite massive input
        assert_eq!(chain_hash.len(), 64); // SHA-256 hex output length
        assert!(chain_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Different huge payloads should produce different hashes
        let other_payload = "y".repeat(100_000_000);
        let other_hash = compute_chain_hash(Some("previous-hash"), &other_payload);
        assert_ne!(chain_hash, other_hash);
    }

    /// Negative path: confidence validation edge cases around floating-point precision
    #[test]
    fn confidence_validation_rejects_values_just_outside_bounds_due_to_precision() {
        // Slightly above 1.0 due to floating-point precision
        let just_over_one = 1.0 + f64::EPSILON * 2.0;
        let err = Receipt::new(
            "quarantine",
            "actor",
            &json!({}),
            &json!({}),
            Decision::Approved,
            "rationale exceeding bounds",
            vec![],
            vec![],
            just_over_one,
            "rollback command",
        )
        .expect_err("just over 1.0 should fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { .. }));

        // Slightly below 0.0
        let just_under_zero = 0.0 - f64::EPSILON * 2.0;
        let err = Receipt::new(
            "quarantine",
            "actor",
            &json!({}),
            &json!({}),
            Decision::Denied,
            "rationale below bounds check",
            vec![],
            vec![],
            just_under_zero,
            "rollback command",
        )
        .expect_err("just under 0.0 should fail");

        assert!(matches!(err, ReceiptError::InvalidConfidence { .. }));
    }

    /// Negative path: circular reference in input/output serialization
    #[test]
    fn receipt_creation_with_self_referential_json_value_handled_gracefully() {
        // Create a JSON value that would cause issues in naive serialization
        let problematic_input = json!({
            "data": "test",
            "nested": {
                "recursive": null  // Not actually recursive, but simulating the pattern
            }
        });

        // Self-referential structures can't be created directly in serde_json::Value,
        // but we can test with deeply nested structures that might cause stack overflow
        let deeply_nested =
            (0..10000).fold(json!({}), |acc, i| json!({ format!("level_{}", i): acc }));

        let receipt = Receipt::new(
            "test_action",
            "test_actor",
            &deeply_nested,
            &problematic_input,
            Decision::Approved,
            "Testing deeply nested structure handling during hash computation",
            vec!["test-evidence".to_string()],
            vec!["test-rule".to_string()],
            0.95,
            "test rollback command",
        )
        .expect("deeply nested input should be handled without stack overflow");

        assert!(!receipt.input_hash.is_empty());
        assert!(!receipt.output_hash.is_empty());
        assert_ne!(receipt.input_hash, receipt.output_hash);
    }

    /// Negative path: timestamp parsing edge cases with malformed formats
    #[test]
    fn export_filter_handles_malformed_timestamps_in_various_formats_gracefully() {
        let key = demo_signing_key();

        let malformed_timestamps = vec![
            "",                          // Empty string
            "2026",                      // Year only
            "2026-13-45T25:70:90Z",      // Invalid date/time components
            "not-a-date-at-all",         // Non-date string
            "2026-02-20T10:00:00",       // Missing timezone
            "2026-02-20T10:00:00+25:00", // Invalid timezone offset
            "\x00\x01\x02",              // Binary data
        ];

        for malformed_ts in malformed_timestamps {
            let mut receipt = make_receipt("test", Decision::Approved);
            receipt.timestamp = malformed_ts.to_string();
            let signed =
                sign_receipt(&receipt, &key).expect("should sign despite malformed timestamp");

            // Export filter should exclude receipts with unparseable timestamps
            let exported = export_receipts(&[signed], &ReceiptQuery::default());
            assert!(
                exported.is_empty(),
                "malformed timestamp '{}' should be excluded",
                malformed_ts
            );
        }
    }
}
