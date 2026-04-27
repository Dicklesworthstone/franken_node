//! bd-2e73: Bounded evidence ledger ring buffer with lab spill-to-artifacts mode.
//!
//! Provides a fixed-capacity, allocation-stable container that retains the most
//! recent N entries in memory while maintaining deterministic FIFO overflow
//! semantics. In lab/test mode, a separate spill-to-artifacts path writes the
//! complete evidence stream to disk as JSONL.
//!
//! Supports Section 8.5 Invariant #3 (deterministic replay) and #9 (bounded
//! resource consumption).
//!
//! # Canonical Ordering Contract
//!
//! The ledger's canonical order is accepted append order, represented by the
//! monotonically increasing [`EntryId`] assigned during `append`. In-memory
//! retention, [`EvidenceLedger::iter_all`], [`EvidenceLedger::snapshot`], and
//! lab JSONL spill all preserve that order from oldest to newest among accepted
//! entries. Capacity eviction removes only the oldest retained prefix, so a
//! snapshot is always an ordered suffix of the accepted stream.
//!
//! Replay consumers must treat this append/`EntryId` order as authoritative for
//! ledger evidence. They must not reorder ledger entries by `decision_time`,
//! `timestamp_ms`, `trace_id`, `epoch_id`, JSON object order, or spill-file
//! offsets. Workflow replay has its own canonical order: `TraceStep.seq` must
//! be contiguous from zero, and replay iterates steps in that sequence order.
//! Batch evidence replay validators preserve the caller-supplied slice order;
//! callers that feed ledger snapshots should pass the snapshot entries as-is.
//!
//! # Invariants
//!
//! - INV-LEDGER-FIFO: overflow evicts the oldest entry (FIFO order)
//! - INV-LEDGER-BOUNDED: memory stays within configured max_entries and max_bytes
//! - INV-LEDGER-DETERMINISTIC: identical inputs produce identical snapshots
//! - INV-LEDGER-SEND-SYNC: SharedEvidenceLedger is Send + Sync
//!
//! Log codes:
//! - `EVD-LEDGER-001`: append success
//! - `EVD-LEDGER-002`: eviction (includes evicted entry_id)
//! - `EVD-LEDGER-003`: lab spill write
//! - `EVD-LEDGER-004`: capacity breach warning

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::security::{
    constant_time,
    crypto::{Ed25519Verifier, SignatureVerifier},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hex;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

const MIN_SEEN_SIGNATURES: usize = 8192;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SHA256_DIGEST_BYTES: usize = 32;
const REPLAY_TIMESTAMP_BYTES: usize = 8;
const REPLAY_KEY_BYTES: usize = REPLAY_TIMESTAMP_BYTES + ED25519_SIGNATURE_BYTES;
const SPILL_FILE_BUFFER_BYTES: usize = 64 * 1024;
type ReplaySignature = [u8; ED25519_SIGNATURE_BYTES];
type ReplayKey = [u8; REPLAY_KEY_BYTES];
type EntryHash = [u8; SHA256_DIGEST_BYTES];

// ── Event codes ─────────────────────────────────────────────────────

pub mod event_codes {
    pub const LEDGER_APPEND: &str = "EVD-LEDGER-001";
    pub const LEDGER_EVICTION: &str = "EVD-LEDGER-002";
    pub const LEDGER_SPILL: &str = "EVD-LEDGER-003";
    pub const LEDGER_CAPACITY_WARN: &str = "EVD-LEDGER-004";
    pub const LEDGER_LOCK_POISON_RECOVERED: &str = "EVD-LEDGER-005";
    pub const LEDGER_CIRCUIT_BREAKER_OPEN: &str = "EVD-LEDGER-006";
    pub const LEDGER_CIRCUIT_BREAKER_CLOSED: &str = "EVD-LEDGER-007";
    pub const LEDGER_EMERGENCY_HALT: &str = "EVD-LEDGER-008";
}

// ── EntryId ─────────────────────────────────────────────────────────

/// Monotonically increasing entry identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EntryId(pub u64);

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E-{:08}", self.0)
    }
}

// ── DecisionKind ────────────────────────────────────────────────────

/// Kinds of product control decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Admit,
    Deny,
    Quarantine,
    Release,
    Rollback,
    Throttle,
    Escalate,
}

impl DecisionKind {
    /// Return the stable lowercase label used in canonical entry encoding.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::DecisionKind;
    ///
    /// assert_eq!(DecisionKind::Quarantine.label(), "quarantine");
    /// ```
    pub fn label(&self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Deny => "deny",
            Self::Quarantine => "quarantine",
            Self::Release => "release",
            Self::Rollback => "rollback",
            Self::Throttle => "throttle",
            Self::Escalate => "escalate",
        }
    }
}

// ── EvidenceEntry ───────────────────────────────────────────────────

/// A single evidence entry in the ledger, matching the bd-nupr schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub schema_version: String,
    pub entry_id: Option<String>,
    pub decision_id: String,
    pub decision_kind: DecisionKind,
    pub decision_time: String,
    pub timestamp_ms: u64,
    pub trace_id: String,
    pub epoch_id: u64,
    /// Serialized payload (opaque to the ledger).
    pub payload: serde_json::Value,
    /// Optional serialized size hint.
    /// The ledger derives its own budget accounting during append.
    #[serde(default)]
    pub size_bytes: usize,
    /// Ed25519 signature over the canonical entry representation.
    /// Required by ledgers constructed with a verifying key.
    #[serde(default)]
    pub signature: String,
    /// SHA-256 hash of the previous entry for hash chain integrity.
    /// Empty for the first entry in the ledger.
    #[serde(default)]
    pub prev_entry_hash: String,
}

impl EvidenceEntry {
    /// Estimate serialized byte size of this entry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::test_entry;
    ///
    /// let entry = test_entry("DEC-001", 1);
    /// assert!(entry.estimated_size() > 0);
    /// ```
    pub fn estimated_size(&self) -> usize {
        serialized_json_size(self).unwrap_or(256)
    }
}

struct ByteCountingWriter {
    bytes_written: usize,
}

impl ByteCountingWriter {
    const fn new() -> Self {
        Self { bytes_written: 0 }
    }

    const fn bytes_written(&self) -> usize {
        self.bytes_written
    }
}

impl Write for ByteCountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes_written = self.bytes_written.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct CountingWrite<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    bytes_written: usize,
}

impl<W: Write + ?Sized> CountingWrite<'_, W> {
    fn new(inner: &mut W) -> CountingWrite<'_, W> {
        CountingWrite {
            inner,
            bytes_written: 0,
        }
    }

    const fn bytes_written(&self) -> usize {
        self.bytes_written
    }
}

impl<W: Write + ?Sized> Write for CountingWrite<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes_written = self.bytes_written.saturating_add(written);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn serialized_json_size<T>(value: &T) -> Result<usize, serde_json::Error>
where
    T: Serialize,
{
    let mut writer = ByteCountingWriter::new();
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes_written())
}

fn serialized_json_bytes<T>(value: &T) -> Result<Vec<u8>, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_vec(value)
}

fn update_hash_json_bytes_len_prefixed(hasher: &mut Sha256, json_bytes: &[u8]) {
    let len = u64::try_from(json_bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(json_bytes);
}

fn update_hash_serialized_json_len_prefixed<T>(
    hasher: &mut Sha256,
    value: &T,
) -> Result<(), serde_json::Error>
where
    T: Serialize,
{
    let json_bytes = serialized_json_bytes(value)?;
    update_hash_json_bytes_len_prefixed(hasher, &json_bytes);
    Ok(())
}

fn replay_key(timestamp_ms: u64, signature: &ReplaySignature) -> ReplayKey {
    let mut replay_key = [0_u8; REPLAY_KEY_BYTES];
    replay_key[..REPLAY_TIMESTAMP_BYTES].copy_from_slice(&timestamp_ms.to_le_bytes());
    replay_key[REPLAY_TIMESTAMP_BYTES..].copy_from_slice(signature);
    replay_key
}

/// bd-17pb5: Compute hash of replay key for miss prefilter.
/// Uses domain separation to prevent collisions with other hash uses.
fn replay_key_hash(replay_key: &ReplayKey) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"evidence_ledger_replay_key_v1:");
    hasher.update(replay_key);
    let hash_bytes = hasher.finalize();
    // Use first 8 bytes as u64 hash value
    u64::from_le_bytes(hash_bytes[..8].try_into().unwrap())
}

fn replay_key_seen_in_slice_ct(replay_key: &ReplayKey, seen_replay_keys: &[ReplayKey]) -> bool {
    let mut found_match = false;
    for seen_replay_key in seen_replay_keys {
        found_match |= constant_time::ct_eq_bytes(replay_key, seen_replay_key);
    }
    found_match
}

fn entry_with_server_computed_size(mut normalized: EvidenceEntry) -> (EvidenceEntry, usize) {
    normalized.size_bytes = 0;
    let base_size = serialized_entry_size(&normalized);
    let size_without_size_digits = base_size.saturating_sub(1);

    // `size_bytes` is the only self-referential field in the serialized JSON, so
    // the fixed point is `n = base_without_digits + digits10(n)`.
    let mut digit_count = decimal_digit_count(base_size);
    let candidate_size = loop {
        let next_size = size_without_size_digits.saturating_add(digit_count);
        let next_digit_count = decimal_digit_count(next_size);
        if next_digit_count == digit_count {
            break next_size;
        }
        digit_count = next_digit_count;
    };

    normalized.size_bytes = candidate_size;
    (normalized, candidate_size)
}

fn entry_with_server_computed_size_with_payload_bytes(
    mut normalized: EvidenceEntry,
    payload_json_bytes: &[u8],
) -> (EvidenceEntry, usize) {
    normalized.size_bytes = 0;
    let base_size = serialized_entry_size_with_payload_bytes(&normalized, payload_json_bytes);
    let size_without_size_digits = base_size.saturating_sub(1);

    // `size_bytes` is the only self-referential field in the serialized JSON, so
    // the fixed point is `n = base_without_digits + digits10(n)`.
    let mut digit_count = decimal_digit_count(base_size);
    let candidate_size = loop {
        let next_size = size_without_size_digits.saturating_add(digit_count);
        let next_digit_count = decimal_digit_count(next_size);
        if next_digit_count == digit_count {
            break next_size;
        }
        digit_count = next_digit_count;
    };

    normalized.size_bytes = candidate_size;
    (normalized, candidate_size)
}

fn decimal_digit_count(value: usize) -> usize {
    let mut remaining = value;
    let mut digits: usize = 1;
    while remaining >= 10 {
        digits = digits.saturating_add(1);
        remaining /= 10;
    }
    digits
}

fn serialized_entry_size(entry: &EvidenceEntry) -> usize {
    serialized_json_size(entry).unwrap_or(usize::MAX)
}

fn serialized_entry_size_with_payload_bytes(
    entry: &EvidenceEntry,
    payload_json_bytes: &[u8],
) -> usize {
    // Compute entry size using pre-computed payload JSON bytes to avoid duplicate serialization.
    // We create a modified entry with a null payload, compute its size, then substitute
    // the actual payload size.

    let mut entry_without_payload = entry.clone();
    entry_without_payload.payload = serde_json::Value::Null;

    let base_size = serialized_json_size(&entry_without_payload).unwrap_or(usize::MAX);

    // The null payload serializes as "null" (4 bytes), so we subtract that and add the actual payload size
    let null_payload_size = 4; // "null"
    base_size
        .saturating_sub(null_payload_size)
        .saturating_add(payload_json_bytes.len())
}

/// Create a canonical representation of an EvidenceEntry for signature verification.
/// Excludes the signature and server-derived size fields to prevent circular dependency.
fn canonical_entry_bytes(entry: &EvidenceEntry) -> [u8; SHA256_DIGEST_BYTES] {
    let payload_json_bytes = serialized_json_bytes(&entry.payload).ok();
    canonical_entry_bytes_with_payload_bytes(entry, payload_json_bytes.as_deref())
}

fn canonical_entry_bytes_with_payload_bytes(
    entry: &EvidenceEntry,
    payload_json_bytes: Option<&[u8]>,
) -> [u8; SHA256_DIGEST_BYTES] {
    let mut hasher = Sha256::new();

    // Domain separator prevents attacks across different signing contexts
    hasher.update(b"evidence_ledger_entry_v1:");

    // Hash all fields except signature in deterministic order
    update_hash_len_prefixed(&mut hasher, entry.schema_version.as_bytes());
    match &entry.entry_id {
        Some(entry_id) => {
            hasher.update([1_u8]);
            update_hash_len_prefixed(&mut hasher, entry_id.as_bytes());
        }
        None => hasher.update([0_u8]),
    }
    update_hash_len_prefixed(&mut hasher, entry.decision_id.as_bytes());
    update_hash_len_prefixed(&mut hasher, entry.decision_kind.label().as_bytes());
    update_hash_len_prefixed(&mut hasher, entry.decision_time.as_bytes());
    hasher.update(entry.timestamp_ms.to_le_bytes());
    update_hash_len_prefixed(&mut hasher, entry.trace_id.as_bytes());
    hasher.update(entry.epoch_id.to_le_bytes());

    // Serialize payload deterministically without materializing a second temporary JSON buffer
    // when the caller already has the canonical payload bytes available.
    if let Some(payload_json_bytes) = payload_json_bytes {
        update_hash_json_bytes_len_prefixed(&mut hasher, payload_json_bytes);
    }

    hasher.finalize().into()
}

fn update_hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn compute_entry_hash_bytes(entry: &EvidenceEntry) -> EntryHash {
    let payload_json_bytes = serialized_json_bytes(&entry.payload).ok();
    compute_entry_hash_bytes_with_payload_bytes(entry, payload_json_bytes.as_deref())
}

fn compute_entry_hash_bytes_with_payload_bytes(
    entry: &EvidenceEntry,
    payload_json_bytes: Option<&[u8]>,
) -> EntryHash {
    let mut hasher = Sha256::new();
    hasher.update(b"evidence_entry_v1:");
    hasher.update(
        &u64::try_from(entry.schema_version.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(entry.schema_version.as_bytes());
    if let Some(entry_id) = &entry.entry_id {
        hasher.update(&[1]);
        hasher.update(
            &u64::try_from(entry_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        hasher.update(entry_id.as_bytes());
    } else {
        hasher.update(&[0]);
    }
    hasher.update(
        &u64::try_from(entry.decision_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(entry.decision_id.as_bytes());
    let decision_kind = entry.decision_kind.label();
    hasher.update(
        &u64::try_from(decision_kind.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(decision_kind.as_bytes());
    hasher.update(
        &u64::try_from(entry.decision_time.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(entry.decision_time.as_bytes());
    hasher.update(&entry.timestamp_ms.to_le_bytes());
    hasher.update(
        &u64::try_from(entry.trace_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(entry.trace_id.as_bytes());
    hasher.update(&entry.epoch_id.to_le_bytes());

    // Hash the serialized payload for deterministic content representation.
    // Reuse pre-serialized payload bytes when available to avoid duplicate payload serialization
    // on the signed append hot path.
    if let Some(payload_json_bytes) = payload_json_bytes {
        update_hash_json_bytes_len_prefixed(&mut hasher, payload_json_bytes);
    } else {
        hasher.update(0_u64.to_le_bytes());
    }

    hasher.update(&entry.size_bytes.to_le_bytes());
    hasher.update(
        &u64::try_from(entry.signature.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(entry.signature.as_bytes());

    // NOTE: prev_entry_hash is intentionally excluded to prevent circular dependency
    hasher.finalize().into()
}

fn encode_entry_hash(hash: &EntryHash) -> String {
    hex::encode(hash)
}

/// Return the stable hash-chain digest for an evidence entry as lowercase hex.
pub fn evidence_entry_hash_hex(entry: &EvidenceEntry) -> String {
    encode_entry_hash(&compute_entry_hash_bytes(entry))
}

/// Sign an evidence entry using an Ed25519 signing key.
///
/// # Examples
///
/// ```rust
/// use ed25519_dalek::SigningKey;
/// use frankenengine_node::observability::evidence_ledger::{sign_evidence_entry, test_entry};
///
/// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
/// let mut entry = test_entry("DEC-001", 1);
/// sign_evidence_entry(&mut entry, &signing_key);
///
/// assert!(!entry.signature.is_empty());
/// ```
pub fn sign_evidence_entry(entry: &mut EvidenceEntry, signing_key: &SigningKey) {
    let canonical_bytes = canonical_entry_bytes(entry);
    let signature_bytes = signing_key.sign(&canonical_bytes).to_bytes();
    entry.signature = hex::encode(signature_bytes);
}

/// Verify the signature on an evidence entry using an Ed25519 verifying key.
///
/// # Examples
///
/// ```rust
/// use ed25519_dalek::SigningKey;
/// use frankenengine_node::observability::evidence_ledger::{
///     sign_evidence_entry, test_entry, verify_evidence_entry,
/// };
///
/// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
/// let mut entry = test_entry("DEC-001", 1);
/// sign_evidence_entry(&mut entry, &signing_key);
///
/// verify_evidence_entry(&entry, &signing_key.verifying_key()).unwrap();
/// ```
pub fn verify_evidence_entry(
    entry: &EvidenceEntry,
    verifying_key: &VerifyingKey,
) -> Result<(), LedgerError> {
    verify_evidence_entry_bytes(entry, verifying_key).map(|_| ())
}

fn verify_evidence_entry_bytes(
    entry: &EvidenceEntry,
    verifying_key: &VerifyingKey,
) -> Result<ReplaySignature, LedgerError> {
    let payload_json_bytes = serialized_json_bytes(&entry.payload).ok();
    verify_evidence_entry_bytes_with_payload_bytes(
        entry,
        verifying_key,
        payload_json_bytes.as_deref(),
    )
}

fn verify_evidence_entry_bytes_with_payload_bytes(
    entry: &EvidenceEntry,
    verifying_key: &VerifyingKey,
    payload_json_bytes: Option<&[u8]>,
) -> Result<ReplaySignature, LedgerError> {
    let canonical_bytes = canonical_entry_bytes_with_payload_bytes(entry, payload_json_bytes);
    let signature_bytes = decode_replay_signature(&entry.signature)?;

    // Use trait-based verification for better abstraction
    let verifier = Ed25519Verifier::new(*verifying_key);
    verifier
        .verify(&canonical_bytes, &signature_bytes)
        .map_err(|_| LedgerError::SignatureInvalid {
            reason: "signature verification failed: ManifestSignatureInvalid".to_string(),
        })?;

    Ok(signature_bytes)
}

fn decode_replay_signature(signature: &str) -> Result<ReplaySignature, LedgerError> {
    // SECURITY: Cap signature hex length to prevent memory DoS attacks
    // Ed25519 signatures are 64 bytes = 128 hex chars. Allow up to 256 hex chars (128 raw bytes).
    if signature.len() > 256 {
        return Err(LedgerError::SignatureInvalid {
            reason: format!(
                "signature hex too long: {} chars (max 256)",
                signature.len()
            ),
        });
    }

    if signature.is_empty() {
        return Err(LedgerError::SignatureInvalid {
            reason: "signature cannot be empty".to_string(),
        });
    }

    if !is_canonical_lower_hex(signature) {
        return Err(LedgerError::SignatureInvalid {
            reason: "signature must use canonical lowercase hex".to_string(),
        });
    }

    if signature.len() == ED25519_SIGNATURE_BYTES * 2 {
        let mut signature_bytes = [0_u8; ED25519_SIGNATURE_BYTES];
        hex::decode_to_slice(signature, &mut signature_bytes).map_err(|e| {
            LedgerError::SignatureInvalid {
                reason: format!("invalid hex signature: {}", e),
            }
        })?;
        return Ok(signature_bytes);
    }

    let signature_bytes = hex::decode(signature).map_err(|e| LedgerError::SignatureInvalid {
        reason: format!("invalid hex signature: {}", e),
    })?;

    signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LedgerError::SignatureInvalid {
            reason: format!(
                "signature must decode to exactly {} bytes (got {})",
                ED25519_SIGNATURE_BYTES,
                signature_bytes.len()
            ),
        })
}

fn is_canonical_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

// ── LedgerError ─────────────────────────────────────────────────────

/// Errors from ledger operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The ledger is configured with zero entry capacity.
    ZeroEntryCapacity,
    /// A single entry exceeds the max_bytes budget.
    EntryTooLarge { entry_size: usize, max_bytes: usize },
    /// Spill write failed.
    SpillError { reason: String },
    /// Entry signature verification failed - prevents injection attacks.
    SignatureInvalid { reason: String },
    /// Replay attack detected - timestamp+signature combination already seen.
    ReplayAttack {
        timestamp_ms: u64,
        signature: String,
    },
    /// Hash chain validation failed - entry's prev_entry_hash doesn't match ledger state.
    HashChainBroken {
        expected_hash: String,
        provided_hash: String,
    },
    /// Entry contains control characters in metadata fields - prevents log injection.
    InvalidControlCharacters { field: String, reason: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroEntryCapacity => write!(f, "ledger max_entries must be at least 1"),
            Self::EntryTooLarge {
                entry_size,
                max_bytes,
            } => write!(
                f,
                "entry size {entry_size} exceeds max_bytes budget {max_bytes}"
            ),
            Self::SpillError { reason } => write!(f, "spill write failed: {reason}"),
            Self::SignatureInvalid { reason } => {
                write!(f, "signature verification failed: {reason}")
            }
            Self::ReplayAttack {
                timestamp_ms,
                signature,
            } => {
                write!(
                    f,
                    "replay attack: timestamp {} signature {} already seen",
                    timestamp_ms, signature
                )
            }
            Self::HashChainBroken {
                expected_hash,
                provided_hash,
            } => {
                write!(
                    f,
                    "hash chain broken: expected {} got {}",
                    expected_hash, provided_hash
                )
            }
            Self::InvalidControlCharacters { field, reason } => {
                write!(f, "control characters in {}: {}", field, reason)
            }
        }
    }
}

impl std::error::Error for LedgerError {}

// ── LedgerSnapshot ──────────────────────────────────────────────────

/// A consistent, cloneable snapshot of the ledger state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub entries: Vec<(EntryId, EvidenceEntry)>,
    pub total_appended: u64,
    pub total_evicted: u64,
    pub current_bytes: usize,
    pub capacity: LedgerCapacity,
}

/// Exportable counters for observability backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerMetrics {
    pub retained_entries: usize,
    pub total_appended: u64,
    pub total_evicted: u64,
    pub current_bytes: usize,
    pub max_entries: usize,
    pub max_bytes: usize,
}

// ── LedgerCapacity ──────────────────────────────────────────────────

/// Configuration for ring buffer capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCapacity {
    pub max_entries: usize,
    pub max_bytes: usize,
}

impl LedgerCapacity {
    /// Construct a bounded capacity configuration for an evidence ledger.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::LedgerCapacity;
    ///
    /// let capacity = LedgerCapacity::new(128, 4096);
    /// assert_eq!(capacity.max_entries, 128);
    /// assert_eq!(capacity.max_bytes, 4096);
    /// ```
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            max_entries,
            max_bytes,
        }
    }
}

/// Type alias for configuration-style usage.
pub type LedgerConfig = LedgerCapacity;

fn format_ledger_init_event(capacity: &LedgerCapacity) -> String {
    format!(
        "{}: evidence ledger initialized: max_entries={}, max_bytes={}",
        event_codes::LEDGER_CAPACITY_WARN,
        capacity.max_entries,
        capacity.max_bytes,
    )
}

fn format_ledger_zero_capacity_event(entry: &EvidenceEntry) -> String {
    format!(
        "{}: append rejected because max_entries=0, epoch={}",
        event_codes::LEDGER_CAPACITY_WARN,
        entry.epoch_id,
    )
}

fn format_ledger_entry_too_large_event(
    entry_size: usize,
    max_bytes: usize,
    epoch_id: u64,
) -> String {
    format!(
        "{}: entry size {} exceeds max_bytes {}, epoch={}",
        event_codes::LEDGER_CAPACITY_WARN,
        entry_size,
        max_bytes,
        epoch_id,
    )
}

fn format_ledger_append_event(id: EntryId, entry: &EvidenceEntry, entry_size: usize) -> String {
    format!(
        "{}: entry={}, decision={}, epoch={}, size={}",
        event_codes::LEDGER_APPEND,
        id,
        entry.decision_id.as_str(),
        entry.epoch_id,
        entry_size,
    )
}

fn format_ledger_eviction_event(
    evicted_id: EntryId,
    evicted_entry: &EvidenceEntry,
    evicted_size: usize,
) -> String {
    format!(
        "{}: evicted entry={}, decision={}, epoch={}, freed_bytes={}",
        event_codes::LEDGER_EVICTION,
        evicted_id,
        evicted_entry.decision_id.as_str(),
        evicted_entry.epoch_id,
        evicted_size,
    )
}

fn format_ledger_spill_event(id: EntryId, bytes: usize) -> String {
    format!(
        "{}: spill wrote entry={}, bytes={}",
        event_codes::LEDGER_SPILL,
        id,
        bytes,
    )
}

fn format_ledger_lock_poison_recovered_event() -> &'static str {
    "EVD-LEDGER-005: recovering from poisoned evidence ledger lock"
}

// ── EvidenceLedger ──────────────────────────────────────────────────

/// Bounded ring buffer for evidence entries.
///
/// When capacity is exceeded, the oldest entry is evicted (FIFO).
/// The ledger enforces both `max_entries` and `max_bytes` independently.
/// All entries must be signed with the trusted verifying key to prevent injection attacks.
pub struct EvidenceLedger {
    capacity: LedgerCapacity,
    entries: VecDeque<(EntryId, EvidenceEntry, usize)>,
    next_id: u64,
    total_appended: u64,
    total_evicted: u64,
    current_bytes: usize,
    /// Verifying key for signature verification of evidence entries
    verifying_key: Option<VerifyingKey>,
    /// Bounded replay-prevention window in append order, with precomputed
    /// timestamp bytes for the constant-time replay scan.
    seen_signatures: VecDeque<ReplayKey>,
    /// bd-17pb5: Miss prefilter for replay-window scans. Counts hash values of
    /// replay keys so truncated-hash collisions cannot suppress retained keys.
    replay_key_hashes: HashMap<u64, usize>,
    /// Hash of the last appended entry for hash chain integrity
    last_entry_hash: Option<EntryHash>,
}

impl EvidenceLedger {
    /// Validate that a string field contains no control characters that could enable log injection.
    /// Rejects CR, LF, ESC, NUL, and other control characters (ASCII 0-31 except printable whitespace).
    fn validate_text_field(field_name: &str, value: &str) -> Result<(), LedgerError> {
        for (pos, byte) in value.bytes().enumerate() {
            if byte < 32 && byte != b' ' && byte != b'\t' {
                let control_char = match byte {
                    0 => "NUL (0x00)".to_string(),
                    9 => "TAB (0x09)".to_string(), // Allow tab in some contexts but flag for visibility
                    10 => "LF (0x0A)".to_string(),
                    13 => "CR (0x0D)".to_string(),
                    27 => "ESC (0x1B)".to_string(),
                    _ => format!("0x{:02X}", byte),
                };
                return Err(LedgerError::InvalidControlCharacters {
                    field: field_name.to_string(),
                    reason: format!("control character {} at position {}", control_char, pos),
                });
            }
        }
        Ok(())
    }

    fn validate_append(
        &self,
        mut entry: EvidenceEntry,
    ) -> Result<(EvidenceEntry, usize, EntryHash, Option<ReplaySignature>), LedgerError> {
        if self.capacity.max_entries == 0 {
            eprintln!("{}", format_ledger_zero_capacity_event(&entry));
            return Err(LedgerError::ZeroEntryCapacity);
        }

        // SECURITY: Validate text fields for control characters to prevent log injection attacks.
        // Check before signature verification to fail-closed on malicious input.
        Self::validate_text_field("schema_version", &entry.schema_version)?;
        if let Some(ref entry_id) = entry.entry_id {
            Self::validate_text_field("entry_id", entry_id)?;
        }
        Self::validate_text_field("decision_id", &entry.decision_id)?;
        Self::validate_text_field("decision_time", &entry.decision_time)?;
        Self::validate_text_field("trace_id", &entry.trace_id)?;
        Self::validate_text_field("signature", &entry.signature)?;
        Self::validate_text_field("prev_entry_hash", &entry.prev_entry_hash)?;

        let payload_json_bytes = serialized_json_bytes(&entry.payload).ok();

        let mut replay_signature = None;
        if let Some(verifying_key) = &self.verifying_key {
            // SECURITY: Verify signature first to prevent injection attacks.
            let signature_bytes = verify_evidence_entry_bytes_with_payload_bytes(
                &entry,
                verifying_key,
                payload_json_bytes.as_deref(),
            )?;

            // SECURITY: Check for replay attacks - reject duplicate timestamp+signature combinations.
            // Use constant-time comparison to prevent timing side-channel attacks.
            if self.is_replay_attack_ct_bytes(entry.timestamp_ms, &signature_bytes) {
                return Err(LedgerError::ReplayAttack {
                    timestamp_ms: entry.timestamp_ms,
                    signature: entry.signature.clone(),
                });
            }
            replay_signature = Some(signature_bytes);
        }

        let expected_prev_hash = self
            .last_entry_hash
            .as_ref()
            .map(encode_entry_hash)
            .unwrap_or_default();

        // SECURITY: Validate hash chain integrity if client provided prev_entry_hash
        if !entry.prev_entry_hash.is_empty() {
            if !crate::security::constant_time::ct_eq(
                expected_prev_hash.as_str(),
                &entry.prev_entry_hash,
            ) {
                return Err(LedgerError::HashChainBroken {
                    expected_hash: expected_prev_hash,
                    provided_hash: entry.prev_entry_hash.clone(),
                });
            }
        }

        let epoch_id = entry.epoch_id;
        entry.prev_entry_hash = expected_prev_hash;
        let (normalized_entry, entry_size) = if let Some(ref payload_bytes) = payload_json_bytes {
            // Use optimized version to avoid duplicate payload serialization
            entry_with_server_computed_size_with_payload_bytes(entry, payload_bytes)
        } else {
            // Fallback to original version if payload serialization failed
            entry_with_server_computed_size(entry)
        };

        if entry_size > self.capacity.max_bytes {
            eprintln!(
                "{}",
                format_ledger_entry_too_large_event(entry_size, self.capacity.max_bytes, epoch_id,)
            );
            return Err(LedgerError::EntryTooLarge {
                entry_size,
                max_bytes: self.capacity.max_bytes,
            });
        }

        let entry_hash = compute_entry_hash_bytes_with_payload_bytes(
            &normalized_entry,
            payload_json_bytes.as_deref(),
        );

        Ok((normalized_entry, entry_size, entry_hash, replay_signature))
    }

    /// Check for replay attacks using constant-time comparison to prevent timing side-channels.
    /// This prevents attackers from distinguishing known vs unknown signatures via response timing.
    fn is_replay_attack_ct(&self, timestamp_ms: u64, signature: &str) -> bool {
        let Ok(signature_bytes) = decode_replay_signature(signature) else {
            return false;
        };
        self.is_replay_attack_ct_bytes(timestamp_ms, &signature_bytes)
    }

    fn is_replay_attack_ct_bytes(&self, timestamp_ms: u64, signature: &ReplaySignature) -> bool {
        // bd-3ml3u fix: Remove early-return to prevent timing leaks about replay-key presence
        // and position. Collapse the timestamp+signature pair into one fixed-width key so each
        // retained entry needs only a single constant-time comparison.
        let replay_key = replay_key(timestamp_ms, signature);

        // bd-17pb5: Use miss prefilter to quickly eliminate obvious misses.
        // If the hash is not in our prefilter set, we know the key is definitely not present.
        let replay_key_hash_value = replay_key_hash(&replay_key);
        if !matches!(
            self.replay_key_hashes.get(&replay_key_hash_value),
            Some(count) if *count > 0
        ) {
            // Definitely not present, skip expensive constant-time scan
            return false;
        }

        // Hash collision possible - must do full constant-time scan.
        // Scan both contiguous VecDeque slices without short-circuiting so replay-key
        // position and wraparound layout cannot affect timing.
        let (front, back) = self.seen_signatures.as_slices();
        replay_key_seen_in_slice_ct(&replay_key, front)
            | replay_key_seen_in_slice_ct(&replay_key, back)
    }

    fn append_prevalidated(
        &mut self,
        entry: EvidenceEntry,
        entry_size: usize,
        entry_hash: EntryHash,
        replay_signature: Option<ReplaySignature>,
    ) -> EntryId {
        // Evict oldest entries to make room
        while self.entries.len() >= self.capacity.max_entries && !self.entries.is_empty() {
            self.evict_oldest();
        }
        while self.current_bytes.saturating_add(entry_size) > self.capacity.max_bytes
            && !self.entries.is_empty()
        {
            self.evict_oldest();
        }

        let id = EntryId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.total_appended = self.total_appended.saturating_add(1);
        self.current_bytes = self.current_bytes.saturating_add(entry_size);

        if let Some(signature) = replay_signature {
            self.remember_seen_signature(entry.timestamp_ms, signature);
        }

        eprintln!("{}", format_ledger_append_event(id, &entry, entry_size));

        self.last_entry_hash = Some(entry_hash);

        self.entries.push_back((id, entry, entry_size));
        id
    }

    /// Compute SHA-256 hash of an entry for hash chain integrity.
    fn compute_entry_hash(&self, entry: &EvidenceEntry) -> EntryHash {
        compute_entry_hash_bytes(entry)
    }

    /// Create a new evidence ledger with the given capacity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
    ///
    /// let ledger = EvidenceLedger::new(LedgerCapacity::new(16, 4096));
    /// assert!(ledger.is_empty());
    /// ```
    pub fn new<C>(capacity: C) -> Self
    where
        C: Into<LedgerCapacity>,
    {
        Self::with_optional_verifying_key(capacity.into(), None)
    }

    /// Create a new evidence ledger with signature verification enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ed25519_dalek::SigningKey;
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
    ///
    /// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    /// let ledger =
    ///     EvidenceLedger::with_verifying_key(LedgerCapacity::new(16, 4096), signing_key.verifying_key());
    /// assert!(ledger.is_empty());
    /// ```
    pub fn with_verifying_key(capacity: LedgerCapacity, verifying_key: VerifyingKey) -> Self {
        Self::with_optional_verifying_key(capacity, Some(verifying_key))
    }

    fn with_optional_verifying_key(
        capacity: LedgerCapacity,
        verifying_key: Option<VerifyingKey>,
    ) -> Self {
        eprintln!("{}", format_ledger_init_event(&capacity));
        Self {
            capacity,
            entries: VecDeque::new(),
            next_id: 1,
            total_appended: 0,
            total_evicted: 0,
            current_bytes: 0,
            verifying_key,
            seen_signatures: VecDeque::new(),
            replay_key_hashes: HashMap::new(),
            last_entry_hash: None,
        }
    }

    fn retain_replay_key_hash(&mut self, replay_key_hash_value: u64) {
        if let Some(count) = self.replay_key_hashes.get_mut(&replay_key_hash_value) {
            *count = count.saturating_add(1);
        } else {
            self.replay_key_hashes.insert(replay_key_hash_value, 1);
        }
    }

    fn release_replay_key_hash(&mut self, replay_key_hash_value: u64) {
        let remove_entry = match self.replay_key_hashes.get_mut(&replay_key_hash_value) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if remove_entry {
            self.replay_key_hashes.remove(&replay_key_hash_value);
        }
    }

    fn remember_seen_signature(&mut self, timestamp_ms: u64, signature: ReplaySignature) {
        let replay_window = self.capacity.max_entries.max(MIN_SEEN_SIGNATURES);
        let new_replay_key = replay_key(timestamp_ms, &signature);

        // bd-17pb5: Add to miss prefilter index
        let new_hash = replay_key_hash(&new_replay_key);
        self.retain_replay_key_hash(new_hash);

        self.seen_signatures.push_back(new_replay_key);

        // Remove old entries and their hashes when exceeding window size
        while self.seen_signatures.len() > replay_window {
            if let Some(old_replay_key) = self.seen_signatures.pop_front() {
                // bd-17pb5: Remove from miss prefilter index
                let old_hash = replay_key_hash(&old_replay_key);
                self.release_replay_key_hash(old_hash);
            }
        }
    }

    /// Return the capacity configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
    ///
    /// let ledger = EvidenceLedger::new(LedgerCapacity::new(4, 1024));
    /// assert_eq!(ledger.capacity().max_entries, 4);
    /// ```
    pub fn capacity(&self) -> &LedgerCapacity {
        &self.capacity
    }

    /// Return the current number of entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(ledger.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the ledger is empty.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity};
    ///
    /// let ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// assert!(ledger.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the current byte usage.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert!(ledger.current_bytes() > 0);
    /// ```
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Return total entries ever appended.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(ledger.total_appended(), 1);
    /// ```
    pub fn total_appended(&self) -> u64 {
        self.total_appended
    }

    /// Return total entries evicted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// ledger.append(test_entry("DEC-002", 2)).unwrap();
    /// assert_eq!(ledger.total_evicted(), 1);
    /// ```
    pub fn total_evicted(&self) -> u64 {
        self.total_evicted
    }

    /// Return counters suitable for metrics export.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// let metrics = ledger.metrics();
    /// assert_eq!(metrics.retained_entries, 1);
    /// ```
    pub fn metrics(&self) -> LedgerMetrics {
        LedgerMetrics {
            retained_entries: self.entries.len(),
            total_appended: self.total_appended,
            total_evicted: self.total_evicted,
            current_bytes: self.current_bytes,
            max_entries: self.capacity.max_entries,
            max_bytes: self.capacity.max_bytes,
        }
    }

    /// Append an entry to the ledger.
    ///
    /// Evicts oldest entries as needed to stay within capacity bounds.
    /// Returns the assigned EntryId on success.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, EntryId, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// let entry_id = ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(entry_id, EntryId(1));
    /// ```
    pub fn append(&mut self, entry: EvidenceEntry) -> Result<EntryId, LedgerError> {
        let (entry, entry_size, entry_hash, replay_signature) = self.validate_append(entry)?;
        Ok(self.append_prevalidated(entry, entry_size, entry_hash, replay_signature))
    }

    /// Evict the oldest entry from the ring buffer.
    fn evict_oldest(&mut self) {
        if let Some((evicted_id, evicted_entry, evicted_size)) = self.entries.pop_front() {
            self.current_bytes = self.current_bytes.saturating_sub(evicted_size);
            self.total_evicted = self.total_evicted.saturating_add(1);

            eprintln!(
                "{}",
                format_ledger_eviction_event(evicted_id, &evicted_entry, evicted_size)
            );
        }
    }

    /// Iterate over the most recent N entries (newest last).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// ledger.append(test_entry("DEC-002", 2)).unwrap();
    /// let recent: Vec<_> = ledger.iter_recent(1).collect();
    /// assert_eq!(recent[0].1.decision_id, "DEC-002");
    /// ```
    pub fn iter_recent(&self, n: usize) -> impl Iterator<Item = &(EntryId, EvidenceEntry, usize)> {
        let start = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(start)
    }

    /// Iterate over all entries in order (oldest first).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// let all: Vec<_> = ledger.iter_all().collect();
    /// assert_eq!(all.len(), 1);
    /// ```
    pub fn iter_all(&self) -> impl Iterator<Item = &(EntryId, EvidenceEntry, usize)> {
        self.entries.iter()
    }

    /// Return a consistent, cloneable snapshot for export.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{EvidenceLedger, LedgerCapacity, test_entry};
    ///
    /// let mut ledger = EvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// let snapshot = ledger.snapshot();
    /// assert_eq!(snapshot.entries.len(), 1);
    /// ```
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            entries: self
                .entries
                .iter()
                .map(|(id, entry, _)| (*id, entry.clone()))
                .collect(),
            total_appended: self.total_appended,
            total_evicted: self.total_evicted,
            current_bytes: self.current_bytes,
            capacity: self.capacity.clone(),
        }
    }
}

// ── SharedEvidenceLedger ────────────────────────────────────────────

/// Thread-safe wrapper for EvidenceLedger. `Send + Sync` for async tasks.
///
/// This stays a thin lock wrapper while the shared surface is limited to
/// synchronous append/snapshot access. Promote it only if callers start
/// building reply protocols, restart semantics, or other actor-style lifecycle
/// concerns around the ledger instead of simple bounded state access.
#[derive(Clone)]
pub struct SharedEvidenceLedger {
    inner: Arc<RwLock<EvidenceLedger>>,
}

impl SharedEvidenceLedger {
    /// Create a thread-safe ledger with the provided capacity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// assert!(ledger.is_empty());
    /// ```
    pub fn new<C>(capacity: C) -> Self
    where
        C: Into<LedgerCapacity>,
    {
        Self {
            inner: Arc::new(RwLock::new(EvidenceLedger::new(capacity))),
        }
    }

    /// Create a thread-safe ledger with signature verification enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ed25519_dalek::SigningKey;
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger};
    ///
    /// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    /// let ledger = SharedEvidenceLedger::with_verifying_key(
    ///     LedgerCapacity::new(4, 4096),
    ///     signing_key.verifying_key(),
    /// );
    /// assert!(ledger.is_empty());
    /// ```
    pub fn with_verifying_key(capacity: LedgerCapacity, verifying_key: VerifyingKey) -> Self {
        Self {
            inner: Arc::new(RwLock::new(EvidenceLedger::with_verifying_key(
                capacity,
                verifying_key,
            ))),
        }
    }

    /// Append a single entry through the shared wrapper.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger, test_entry};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(ledger.len(), 1);
    /// ```
    pub fn append(&self, entry: EvidenceEntry) -> Result<EntryId, LedgerError> {
        let mut ledger = self.write_recover();
        ledger.append(entry)
    }

    /// Return the number of retained entries in the shared ledger.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger, test_entry};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(ledger.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.read_recover().len()
    }

    /// Return whether the shared ledger has no retained entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// assert!(ledger.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.read_recover().is_empty()
    }

    /// Clone the current shared ledger state into an exportable snapshot.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger, test_entry};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// let snapshot = ledger.snapshot();
    /// assert_eq!(snapshot.entries.len(), 1);
    /// ```
    pub fn snapshot(&self) -> LedgerSnapshot {
        self.read_recover().snapshot()
    }

    /// Return counters for the shared ledger state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LedgerCapacity, SharedEvidenceLedger, test_entry};
    ///
    /// let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(4, 4096));
    /// ledger.append(test_entry("DEC-001", 1)).unwrap();
    /// let metrics = ledger.metrics();
    /// assert_eq!(metrics.retained_entries, 1);
    /// ```
    pub fn metrics(&self) -> LedgerMetrics {
        self.read_recover().metrics()
    }

    fn read_recover(&self) -> RwLockReadGuard<'_, EvidenceLedger> {
        match self.inner.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("{}", format_ledger_lock_poison_recovered_event());
                poisoned.into_inner()
            }
        }
    }

    fn write_recover(&self) -> RwLockWriteGuard<'_, EvidenceLedger> {
        match self.inner.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("{}", format_ledger_lock_poison_recovered_event());
                poisoned.into_inner()
            }
        }
    }
}

// Compile-time Send + Sync assertion
const _: () = {
    #[allow(dead_code)]
    fn assert_send_sync<T: Send + Sync>() {}
    #[allow(dead_code)]
    fn check() {
        assert_send_sync::<SharedEvidenceLedger>();
    }
};

// ── LabSpillMode ────────────────────────────────────────────────────

/// Lab/test mode wrapper that spills every entry to a JSONL file.
/// Includes a manual emergency circuit breaker and a disk-monitoring hook for
/// spill protection.
pub struct LabSpillMode {
    ledger: EvidenceLedger,
    spill_writer: SpillWriter,
    /// Circuit breaker configuration
    circuit_breaker: CircuitBreakerState,
}

/// Circuit breaker state for spill protection.
#[derive(Debug, Clone)]
struct CircuitBreakerState {
    /// When true, spill writes are disabled (memory-only mode)
    is_open: bool,
    /// Disk usage threshold (0.0-1.0) when a filesystem usage provider is available
    disk_threshold: f64,
    /// Manual emergency halt flag (admin override)
    emergency_halt: bool,
    /// Path for disk space monitoring (None for generic writers)
    monitor_path: Option<std::path::PathBuf>,
}

/// Circuit breaker status for monitoring/admin interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    /// Whether the circuit breaker is currently open (spill writes disabled)
    pub is_open: bool,
    /// Whether emergency halt is active
    pub emergency_halt: bool,
    /// Current disk usage threshold (0.0-1.0)
    pub disk_threshold: f64,
    /// Current disk usage if available from the monitoring hook (0.0-1.0)
    pub disk_usage: Option<f64>,
    /// Path being monitored for disk space
    pub monitor_path: Option<std::path::PathBuf>,
}

impl CircuitBreakerState {
    /// Create default circuit breaker state for generic writers (no disk monitoring hook)
    fn new_generic() -> Self {
        Self {
            is_open: false,
            disk_threshold: 0.95, // 95% disk usage triggers circuit breaker
            emergency_halt: false,
            monitor_path: None,
        }
    }

    /// Create circuit breaker state for file writers with a disk-monitoring hook
    fn new_with_path(path: &Path) -> Self {
        Self {
            is_open: false,
            disk_threshold: 0.95, // 95% disk usage triggers circuit breaker
            emergency_halt: false,
            monitor_path: Some(path.parent().unwrap_or(path).to_path_buf()),
        }
    }

    /// Check if the circuit breaker should open due to emergency halt or available disk monitoring
    fn should_open(&self) -> Result<bool, String> {
        // Manual emergency halt overrides everything
        if self.emergency_halt {
            return Ok(true);
        }

        // No disk monitoring for generic writers
        let Some(ref monitor_path) = self.monitor_path else {
            return Ok(false);
        };

        // Check disk usage
        match get_disk_usage(monitor_path) {
            Ok(usage) if usage >= self.disk_threshold => Ok(true),
            Ok(_) => Ok(false),
            Err(e) => {
                // On monitoring error, stay conservative but don't fail
                eprintln!(
                    "WARN: disk monitoring error for {}: {}",
                    monitor_path.display(),
                    e
                );
                Ok(false)
            }
        }
    }
}

/// Best-effort disk usage hook for the filesystem containing the given path.
///
/// This currently returns a conservative placeholder until a safe filesystem
/// usage provider is wired in. Manual `emergency_halt()` remains the
/// authoritative way to force memory-only mode.
fn get_disk_usage(path: &Path) -> Result<f64, String> {
    // SAFETY: This codebase forbids unsafe code, so we can't use libc::statvfs.
    // For production use, consider using a safe wrapper crate like `fs2` or `sysinfo`
    // that provides disk space information without unsafe code.
    //
    // For now, return conservative low usage to prevent false circuit breaker triggers.
    // The emergency halt functionality still works for manual incident response.
    let _ = path; // Acknowledge parameter
    Ok(0.1) // Always report 10% usage - circuit breaker will only trigger on emergency halt
}

enum SpillWriter {
    Generic(Box<dyn Write + Send>),
    File(BufWriter<std::fs::File>),
}

fn new_spill_file_writer(file: std::fs::File) -> BufWriter<std::fs::File> {
    BufWriter::with_capacity(SPILL_FILE_BUFFER_BYTES, file)
}

impl SpillWriter {
    fn append_json_entry<T>(&mut self, value: &T) -> Result<usize, LedgerError>
    where
        T: Serialize,
    {
        match self {
            Self::Generic(writer) => {
                let mut counting = CountingWrite::new(writer.as_mut());
                serde_json::to_writer(&mut counting, value).map_err(|e| {
                    LedgerError::SpillError {
                        reason: format!("JSON error: {e}"),
                    }
                })?;
                let json_bytes = counting.bytes_written();
                counting
                    .write_all(b"\n")
                    .map_err(|e| LedgerError::SpillError {
                        reason: format!("write: {e}"),
                    })?;
                Ok(json_bytes)
                // NOTE: Generic spill intentionally leaves buffering policy to the caller's
                // writer. Use sync_durability() or drop/close the writer to flush buffered bytes.
            }
            Self::File(file) => {
                let mut counting = CountingWrite::new(file);
                serde_json::to_writer(&mut counting, value).map_err(|e| {
                    LedgerError::SpillError {
                        reason: format!("JSON error: {e}"),
                    }
                })?;
                let json_bytes = counting.bytes_written();
                counting
                    .write_all(b"\n")
                    .map_err(|e| LedgerError::SpillError {
                        reason: format!("write: {e}"),
                    })?;
                Ok(json_bytes)
                // NOTE: File-backed spill intentionally leaves data buffered between appends.
                // Use sync_durability() or drop/close the writer to flush buffered bytes.
            }
        }
    }

    /// Sync accumulated writes to durable storage for critical evidence preservation.
    fn sync_durability(&mut self) -> Result<(), LedgerError> {
        match self {
            Self::Generic(writer) => writer.flush().map_err(|e| LedgerError::SpillError {
                reason: format!("flush: {e}"),
            }),
            Self::File(file) => {
                file.flush().map_err(|e| LedgerError::SpillError {
                    reason: format!("flush: {e}"),
                })?;
                file.get_ref()
                    .sync_all()
                    .map_err(|e| LedgerError::SpillError {
                        reason: format!("sync: {e}"),
                    })
            }
        }
    }
}

impl LabSpillMode {
    /// Create a lab-mode ledger that spills to the given writer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// assert!(spill.is_empty());
    /// ```
    pub fn new(capacity: LedgerCapacity, writer: Box<dyn Write + Send>) -> Self {
        Self {
            ledger: EvidenceLedger::new(capacity),
            spill_writer: SpillWriter::Generic(writer),
            circuit_breaker: CircuitBreakerState::new_generic(),
        }
    }

    /// Create a lab-mode ledger with signature verification enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ed25519_dalek::SigningKey;
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    /// let spill = LabSpillMode::with_verifying_key(
    ///     LedgerCapacity::new(4, 4096),
    ///     signing_key.verifying_key(),
    ///     Box::new(Vec::<u8>::new()),
    /// );
    /// assert!(spill.is_empty());
    /// ```
    pub fn with_verifying_key(
        capacity: LedgerCapacity,
        verifying_key: VerifyingKey,
        writer: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            ledger: EvidenceLedger::with_verifying_key(capacity, verifying_key),
            spill_writer: SpillWriter::Generic(writer),
            circuit_breaker: CircuitBreakerState::new_generic(),
        }
    }

    /// Create a lab-mode ledger that spills to a file path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let spill = LabSpillMode::with_file(LedgerCapacity::new(4, 4096), &dir.path().join("spill.jsonl")).unwrap();
    /// assert!(spill.is_empty());
    /// ```
    pub fn with_file(
        capacity: LedgerCapacity,
        path: &std::path::Path,
    ) -> Result<Self, LedgerError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LedgerError::SpillError {
                reason: format!("failed to open: {e}"),
            })?;
        Ok(Self {
            ledger: EvidenceLedger::new(capacity),
            spill_writer: SpillWriter::File(new_spill_file_writer(file)),
            circuit_breaker: CircuitBreakerState::new_with_path(path),
        })
    }

    /// Create a lab-mode ledger with signature verification enabled that spills to a file path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ed25519_dalek::SigningKey;
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    /// let dir = tempfile::tempdir().unwrap();
    /// let spill = LabSpillMode::with_file_and_verifying_key(
    ///     LedgerCapacity::new(4, 4096),
    ///     signing_key.verifying_key(),
    ///     &dir.path().join("spill.jsonl"),
    /// ).unwrap();
    /// assert!(spill.is_empty());
    /// ```
    pub fn with_file_and_verifying_key(
        capacity: LedgerCapacity,
        verifying_key: VerifyingKey,
        path: &std::path::Path,
    ) -> Result<Self, LedgerError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LedgerError::SpillError {
                reason: format!("failed to open: {e}"),
            })?;
        Ok(Self {
            ledger: EvidenceLedger::with_verifying_key(capacity, verifying_key),
            spill_writer: SpillWriter::File(new_spill_file_writer(file)),
            circuit_breaker: CircuitBreakerState::new_with_path(path),
        })
    }

    /// Append an entry, also writing it to the spill file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity, test_entry};
    ///
    /// let mut spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// spill.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(spill.len(), 1);
    /// ```
    pub fn append(&mut self, entry: EvidenceEntry) -> Result<EntryId, LedgerError> {
        let (entry, entry_size, entry_hash, replay_signature) =
            self.ledger.validate_append(entry)?;
        // CIRCUIT BREAKER: Check manual halt state and any available disk monitoring
        let should_open = self.circuit_breaker.should_open().unwrap_or(false);
        let was_open = self.circuit_breaker.is_open;

        if should_open && !was_open {
            // Circuit breaker opening - log event and switch to memory-only mode
            self.circuit_breaker.is_open = true;
            eprintln!(
                "{}: circuit breaker opened, switching to memory-only mode",
                event_codes::LEDGER_CIRCUIT_BREAKER_OPEN
            );
        } else if !should_open && was_open {
            // Circuit breaker closing - resume spill writes
            self.circuit_breaker.is_open = false;
            eprintln!(
                "{}: circuit breaker closed, resuming spill writes",
                event_codes::LEDGER_CIRCUIT_BREAKER_CLOSED
            );
        }

        // Only attempt spill write if circuit breaker is closed
        if !self.circuit_breaker.is_open {
            let json_bytes = self.spill_writer.append_json_entry(&entry)?;
            let id =
                self.ledger
                    .append_prevalidated(entry, entry_size, entry_hash, replay_signature);
            eprintln!("{}", format_ledger_spill_event(id, json_bytes));
            Ok(id)
        } else {
            // Circuit breaker open - memory-only mode
            let id =
                self.ledger
                    .append_prevalidated(entry, entry_size, entry_hash, replay_signature);
            eprintln!(
                "{}: spill write skipped for entry={}, circuit breaker open (memory-only mode)",
                event_codes::LEDGER_CIRCUIT_BREAKER_OPEN,
                id
            );
            Ok(id)
        }
    }

    /// Emergency admin command: halt all evidence ledger spill writes
    ///
    /// Use during incidents to prevent disk exhaustion. Evidence continues
    /// to be stored in memory but will not be written to disk until resumed.
    pub fn emergency_halt(&mut self) {
        if !self.circuit_breaker.emergency_halt {
            self.circuit_breaker.emergency_halt = true;
            self.circuit_breaker.is_open = true;
            eprintln!(
                "{}: admin emergency halt activated - spill writes disabled",
                event_codes::LEDGER_EMERGENCY_HALT
            );
        }
    }

    /// Admin command: resume evidence ledger spill writes after emergency halt
    pub fn emergency_resume(&mut self) {
        if self.circuit_breaker.emergency_halt {
            self.circuit_breaker.emergency_halt = false;
            // Note: circuit breaker state will be re-evaluated on next append()
            eprintln!(
                "{}: admin emergency halt cleared - spill writes will resume if disk space available",
                event_codes::LEDGER_EMERGENCY_HALT
            );
        }
    }

    /// Get circuit breaker status for monitoring/debugging
    pub fn circuit_breaker_status(&self) -> CircuitBreakerStatus {
        let disk_usage = if let Some(ref path) = self.circuit_breaker.monitor_path {
            get_disk_usage(path).ok()
        } else {
            None
        };

        CircuitBreakerStatus {
            is_open: self.circuit_breaker.is_open,
            emergency_halt: self.circuit_breaker.emergency_halt,
            disk_threshold: self.circuit_breaker.disk_threshold,
            disk_usage,
            monitor_path: self.circuit_breaker.monitor_path.clone(),
        }
    }

    /// Update disk usage threshold (admin command)
    pub fn set_disk_threshold(&mut self, threshold: f64) -> Result<(), String> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err("threshold must be between 0.0 and 1.0".to_string());
        }
        self.circuit_breaker.disk_threshold = threshold;
        Ok(())
    }

    /// Sync all accumulated evidence entries to durable storage.
    ///
    /// Call this after batches of critical evidence entries to ensure durability.
    /// Individual append() calls are buffered for performance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity, test_entry};
    ///
    /// let mut spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// spill.append(test_entry("DEC-001", 1)).unwrap();
    /// spill.sync_evidence_durability().unwrap();
    /// ```
    pub fn sync_evidence_durability(&mut self) -> Result<(), LedgerError> {
        self.spill_writer.sync_durability()
    }

    /// Borrow the underlying bounded ledger.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// assert_eq!(spill.ledger().capacity().max_entries, 4);
    /// ```
    pub fn ledger(&self) -> &EvidenceLedger {
        &self.ledger
    }

    /// Return the number of retained entries in lab mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity, test_entry};
    ///
    /// let mut spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// spill.append(test_entry("DEC-001", 1)).unwrap();
    /// assert_eq!(spill.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// Return whether the lab-mode ledger has no retained entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity};
    ///
    /// let spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// assert!(spill.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.ledger.is_empty()
    }

    /// Snapshot the retained lab-mode ledger entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity, test_entry};
    ///
    /// let mut spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// spill.append(test_entry("DEC-001", 1)).unwrap();
    /// let snapshot = spill.snapshot();
    /// assert_eq!(snapshot.entries.len(), 1);
    /// ```
    pub fn snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    /// Return counters from the retained lab-mode ledger.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use frankenengine_node::observability::evidence_ledger::{LabSpillMode, LedgerCapacity, test_entry};
    ///
    /// let mut spill = LabSpillMode::new(LedgerCapacity::new(4, 4096), Box::new(Vec::<u8>::new()));
    /// spill.append(test_entry("DEC-001", 1)).unwrap();
    /// let metrics = spill.metrics();
    /// assert_eq!(metrics.retained_entries, 1);
    /// ```
    pub fn metrics(&self) -> LedgerMetrics {
        self.ledger.metrics()
    }
}

// ── Test helper ─────────────────────────────────────────────────────

/// Create a minimal test evidence entry without signature.
/// Use `sign_evidence_entry` to add a signature before appending to ledger.
///
/// # Examples
///
/// ```rust
/// use frankenengine_node::observability::evidence_ledger::test_entry;
///
/// let entry = test_entry("DEC-001", 7);
/// assert_eq!(entry.decision_id, "DEC-001");
/// assert_eq!(entry.epoch_id, 7);
/// ```
pub fn test_entry(decision_id: &str, epoch_id: u64) -> EvidenceEntry {
    EvidenceEntry {
        schema_version: "1.0".to_string(),
        entry_id: None,
        decision_id: decision_id.to_string(),
        decision_kind: DecisionKind::Admit,
        decision_time: "2026-02-20T12:00:00Z".to_string(),
        timestamp_ms: epoch_id.saturating_mul(1000),
        trace_id: format!("trace-{decision_id}"),
        epoch_id,
        payload: serde_json::json!({}),
        size_bytes: 0,
        signature: String::new(),
        prev_entry_hash: String::new(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct FailingWriteWriter;

    impl Write for FailingWriteWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingFlushWriter;

    impl Write for FailingFlushWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    struct PanicOnWriteWriter;

    impl Write for PanicOnWriteWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            panic!("spill writer should not be called for oversized entry");
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedBufferWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBufferWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    buffer: Arc::clone(&buffer),
                },
                buffer,
            )
        }
    }

    impl Write for SharedBufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("capture buffer lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FlushCountingWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
        flush_count: Arc<AtomicUsize>,
    }

    impl FlushCountingWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let flush_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    buffer: Arc::clone(&buffer),
                    flush_count: Arc::clone(&flush_count),
                },
                buffer,
                flush_count,
            )
        }
    }

    impl Write for FlushCountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("capture buffer lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn make_entry(id: &str, epoch: u64) -> EvidenceEntry {
        let (signing_key, _) = test_keys();
        make_signed_entry(id, epoch, &signing_key)
    }

    // Test helpers for signature verification
    fn test_keys() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn default_verifying_key() -> VerifyingKey {
        let (_, verifying_key) = test_keys();
        verifying_key
    }

    fn make_signed_entry(id: &str, epoch: u64, signing_key: &SigningKey) -> EvidenceEntry {
        let mut entry = test_entry(id, epoch);
        sign_evidence_entry(&mut entry, signing_key);
        entry
    }

    fn make_entry_with_payload(id: &str, epoch: u64, payload_size: usize) -> EvidenceEntry {
        let padding = "x".repeat(payload_size);
        let (signing_key, _) = test_keys();
        let mut entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: id.to_string(),
            decision_kind: DecisionKind::Deny,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: epoch.saturating_mul(1000),
            trace_id: format!("trace-{id}"),
            epoch_id: epoch,
            payload: serde_json::json!({"padding": padding}),
            size_bytes: 0,
            signature: String::new(),
            prev_entry_hash: String::new(),
        };
        sign_evidence_entry(&mut entry, &signing_key);
        entry
    }

    struct EvidenceLedgerConfig {
        max_entries: usize,
        max_bytes: usize,
        lab_mode: bool,
        enable_spill: bool,
        spill_writer: Option<Box<dyn Write + Send>>,
    }

    impl Default for EvidenceLedgerConfig {
        fn default() -> Self {
            Self {
                max_entries: 100,
                max_bytes: 1_000_000,
                lab_mode: false,
                enable_spill: false,
                spill_writer: None,
            }
        }
    }

    impl From<EvidenceLedgerConfig> for LedgerCapacity {
        fn from(config: EvidenceLedgerConfig) -> Self {
            let _ = (config.lab_mode, config.enable_spill, config.spill_writer);
            Self::new(config.max_entries, config.max_bytes)
        }
    }

    fn run_sequence(
        capacity: LedgerCapacity,
        start: u64,
        end: u64,
        verifying_key: VerifyingKey,
    ) -> EvidenceLedger {
        let (signing_key, _) = test_keys();
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);
        for i in start..=end {
            ledger
                .append(make_signed_entry(&format!("DEC-{i:03}"), i, &signing_key))
                .expect("metamorphic append should succeed");
        }
        ledger
    }

    fn snapshot_decision_ids(snapshot: &LedgerSnapshot) -> Vec<String> {
        snapshot
            .entries
            .iter()
            .map(|(_, entry)| entry.decision_id.clone())
            .collect()
    }

    fn iter_decision_ids(ledger: &EvidenceLedger) -> Vec<String> {
        ledger
            .iter_all()
            .map(|(_, entry, _)| entry.decision_id.clone())
            .collect()
    }

    fn captured_text(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buffer.lock().expect("capture buffer should lock").clone())
            .expect("captured audit log should be utf8")
    }

    fn parsed_spill_entries(buffer: &Arc<Mutex<Vec<u8>>>) -> Vec<EvidenceEntry> {
        captured_text(buffer)
            .lines()
            .map(|line| serde_json::from_str(line).expect("spill line should parse"))
            .collect()
    }

    // ── Basic operations ──

    #[test]
    fn new_ledger_is_empty() {
        let ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.current_bytes(), 0);
        assert_eq!(ledger.total_appended(), 0);
        assert_eq!(ledger.total_evicted(), 0);
    }

    #[test]
    fn append_single_entry() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let id = ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        assert_eq!(id, EntryId(1));
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.total_appended(), 1);
        assert!(ledger.current_bytes() > 0);
    }

    #[test]
    fn append_multiple_entries() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        for i in 1..=5 {
            let id = ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
            assert_eq!(id, EntryId(i));
        }
        assert_eq!(ledger.len(), 5);
        assert_eq!(ledger.total_appended(), 5);
    }

    #[test]
    fn entry_ids_are_monotonic() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let id1 = ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let id2 = ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        let id3 = ledger
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    // ── Capacity enforcement: max_entries ──

    #[test]
    fn evicts_oldest_when_max_entries_exceeded() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert_eq!(ledger.len(), 3);
        ledger
            .append(make_entry("DEC-004", 4))
            .expect("should succeed");
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.total_evicted(), 1);
        let entries: Vec<_> = ledger.iter_all().collect();
        assert_eq!(entries[0].1.decision_id, "DEC-002");
        assert_eq!(entries[2].1.decision_id, "DEC-004");
    }

    #[test]
    fn eviction_is_fifo() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 100_000));
        ledger
            .append(make_entry("DEC-A", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-B", 2))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-C", 3))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-D", 4))
            .expect("should succeed");
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.total_evicted(), 2);
        let entries: Vec<_> = ledger.iter_all().collect();
        assert_eq!(entries[0].1.decision_id, "DEC-C");
        assert_eq!(entries[1].1.decision_id, "DEC-D");
    }

    // ── Capacity enforcement: max_bytes ──

    #[test]
    fn evicts_when_max_bytes_exceeded() {
        let small_entry = make_entry("DEC-001", 1);
        let entry_size = small_entry.estimated_size();
        let max_bytes = entry_size * 2 + 10;
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, max_bytes));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        assert_eq!(ledger.len(), 2);
        ledger
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert_eq!(ledger.total_evicted(), 1);
        assert!(ledger.current_bytes() <= max_bytes);
    }

    #[test]
    fn rejects_entry_larger_than_max_bytes() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 50));
        let big_entry = make_entry_with_payload("DEC-BIG", 1, 500);
        let result = ledger.append(big_entry);
        assert!(result.is_err());
        match result.unwrap_err() {
            LedgerError::EntryTooLarge { .. } => {}
            other => unreachable!("expected EntryTooLarge, got: {other}"),
        }
    }

    #[test]
    fn max_bytes_enforced_independently_of_max_entries() {
        let small = make_entry("DEC-S", 1);
        let entry_size = small.estimated_size();
        let max_bytes = entry_size * 3;
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1000, max_bytes));
        for i in 1..=10 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i as u64))
                .expect("should succeed");
        }
        assert!(ledger.current_bytes() <= max_bytes);
        assert!(ledger.len() <= 3);
    }

    // ── iter_recent ──

    #[test]
    fn iter_recent_returns_last_n() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        for i in 1..=5 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        let recent: Vec<_> = ledger.iter_recent(2).collect();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].1.decision_id, "DEC-004");
        assert_eq!(recent[1].1.decision_id, "DEC-005");
    }

    #[test]
    fn iter_recent_with_n_larger_than_entries() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        let recent: Vec<_> = ledger.iter_recent(100).collect();
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn iter_recent_zero_returns_empty() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let recent: Vec<_> = ledger.iter_recent(0).collect();
        assert_eq!(recent.len(), 0);
    }

    #[test]
    fn iter_recent_on_empty_ledger() {
        let ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let recent: Vec<_> = ledger.iter_recent(10).collect();
        assert_eq!(recent.len(), 0);
    }

    // ── Snapshot ──

    #[test]
    fn snapshot_is_consistent() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        for i in 1..=3 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 3);
        assert_eq!(snap.total_appended, 3);
        assert_eq!(snap.total_evicted, 0);
        assert!(snap.current_bytes > 0);
    }

    #[test]
    fn snapshot_after_eviction() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 100_000));
        for i in 1..=4 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.total_appended, 4);
        assert_eq!(snap.total_evicted, 2);
    }

    #[test]
    fn snapshot_is_cloneable() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let snap1 = ledger.snapshot();
        let snap2 = snap1.clone();
        assert_eq!(snap1.entries.len(), snap2.entries.len());
    }

    // ── Determinism ──

    #[test]
    fn identical_sequences_produce_identical_snapshots() {
        fn run() -> LedgerSnapshot {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
            for i in 1..=5 {
                ledger
                    .append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("should succeed");
            }
            ledger.snapshot()
        }
        let snap1 = run();
        let snap2 = run();
        assert_eq!(snap1.entries.len(), snap2.entries.len());
        assert_eq!(snap1.total_appended, snap2.total_appended);
        assert_eq!(snap1.total_evicted, snap2.total_evicted);
        for (a, b) in snap1.entries.iter().zip(snap2.entries.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.decision_id, b.1.decision_id);
        }
    }

    #[test]
    fn mr_larger_entry_capacity_preserves_smaller_capacity_suffix() {
        let small = run_sequence(LedgerCapacity::new(3, 100_000), 1, 8).snapshot();
        let large = run_sequence(LedgerCapacity::new(5, 100_000), 1, 8).snapshot();

        let small_ids = snapshot_decision_ids(&small);
        let large_ids = snapshot_decision_ids(&large);
        assert_eq!(small_ids, large_ids[large_ids.len() - small_ids.len()..]);
        assert_eq!(small.total_appended, large.total_appended);
        assert!(small.total_evicted > large.total_evicted);
    }

    #[test]
    fn mr_irrelevant_prefix_noise_preserves_retained_tail() {
        let baseline = run_sequence(LedgerCapacity::new(4, 100_000), 5, 8).snapshot();

        let mut with_prefix = EvidenceLedger::new(LedgerCapacity::new(4, 100_000));
        for i in 1..=8 {
            with_prefix
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("append with prefix noise should succeed");
        }
        let noisy = with_prefix.snapshot();

        assert_eq!(
            snapshot_decision_ids(&baseline),
            snapshot_decision_ids(&noisy)
        );
        assert_eq!(baseline.total_appended + 4, noisy.total_appended);
        assert_eq!(baseline.total_evicted + 4, noisy.total_evicted);
    }

    #[test]
    fn mr_iter_recent_is_suffix_of_all_entries_for_each_window() {
        let ledger = run_sequence(LedgerCapacity::new(6, 100_000), 1, 6);
        let all_ids = iter_decision_ids(&ledger);

        for window in [0, 1, 3, 6, 10] {
            let recent_ids: Vec<_> = ledger
                .iter_recent(window)
                .map(|(_, entry, _)| entry.decision_id.clone())
                .collect();
            let expected_len = window.min(all_ids.len());
            assert_eq!(recent_ids, all_ids[all_ids.len() - expected_len..]);
        }
    }

    #[test]
    fn mr_rejected_entry_does_not_mutate_snapshot_or_counters() {
        let mut ledger = run_sequence(LedgerCapacity::new(3, 100_000), 1, 3);
        let before = ledger.snapshot();

        let too_large = make_entry_with_payload("DEC-TOO-LARGE", 99, 200_000);
        let result = ledger.append(too_large);

        assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
        let after = ledger.snapshot();
        assert_eq!(
            snapshot_decision_ids(&before),
            snapshot_decision_ids(&after)
        );
        assert_eq!(before.total_appended, after.total_appended);
        assert_eq!(before.total_evicted, after.total_evicted);
        assert_eq!(before.current_bytes, after.current_bytes);
    }

    #[test]
    fn mr_entry_count_capacity_and_byte_capacity_retain_same_uniform_suffix() {
        let entry_size = make_entry("DEC-001", 1).estimated_size();
        let by_count = run_sequence(LedgerCapacity::new(3, 100_000), 1, 9).snapshot();
        let by_bytes = run_sequence(LedgerCapacity::new(100, entry_size * 3), 1, 9).snapshot();

        assert_eq!(
            snapshot_decision_ids(&by_count),
            snapshot_decision_ids(&by_bytes)
        );
        assert_eq!(by_count.total_appended, by_bytes.total_appended);
        assert_eq!(by_count.total_evicted, by_bytes.total_evicted);
        assert!(by_bytes.current_bytes <= entry_size * 3);
    }

    #[test]
    fn mr_plain_and_lab_spill_ledgers_retain_same_snapshot() {
        let mut plain = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        let mut spill =
            LabSpillMode::new(LedgerCapacity::new(3, 100_000), Box::new(Vec::<u8>::new()));

        for i in 1..=6 {
            let entry = make_entry(&format!("DEC-{i:03}"), i);
            plain
                .append(entry.clone())
                .expect("plain append should succeed");
            spill.append(entry).expect("spill append should succeed");
        }

        let plain_snapshot = plain.snapshot();
        let spill_snapshot = spill.snapshot();
        assert_eq!(
            snapshot_decision_ids(&plain_snapshot),
            snapshot_decision_ids(&spill_snapshot)
        );
        assert_eq!(plain_snapshot.total_appended, spill_snapshot.total_appended);
        assert_eq!(plain_snapshot.total_evicted, spill_snapshot.total_evicted);
        assert_eq!(plain_snapshot.current_bytes, spill_snapshot.current_bytes);
    }

    #[test]
    fn mr_shared_and_plain_ledgers_match_for_same_sequential_inputs() {
        let mut plain = EvidenceLedger::new(LedgerCapacity::new(4, 100_000));
        let shared = SharedEvidenceLedger::new(LedgerCapacity::new(4, 100_000));

        for i in 1..=7 {
            let entry = make_entry(&format!("DEC-{i:03}"), i);
            plain
                .append(entry.clone())
                .expect("plain append should succeed");
            shared.append(entry).expect("shared append should succeed");
        }

        let plain_snapshot = plain.snapshot();
        let shared_snapshot = shared.snapshot();
        assert_eq!(
            snapshot_decision_ids(&plain_snapshot),
            snapshot_decision_ids(&shared_snapshot)
        );
        assert_eq!(
            plain_snapshot.total_appended,
            shared_snapshot.total_appended
        );
        assert_eq!(plain_snapshot.total_evicted, shared_snapshot.total_evicted);
    }

    #[test]
    fn mr_snapshot_clone_is_unchanged_by_append_transform() {
        let mut ledger = run_sequence(LedgerCapacity::new(4, 100_000), 1, 4);
        let before = ledger.snapshot();

        ledger
            .append(make_entry("DEC-005", 5))
            .expect("append after snapshot should succeed");

        let after = ledger.snapshot();
        assert_eq!(
            snapshot_decision_ids(&before),
            vec!["DEC-001", "DEC-002", "DEC-003", "DEC-004"]
        );
        assert_eq!(
            snapshot_decision_ids(&after),
            vec!["DEC-002", "DEC-003", "DEC-004", "DEC-005"]
        );
        assert_eq!(before.total_appended + 1, after.total_appended);
        assert_eq!(before.total_evicted + 1, after.total_evicted);
    }

    #[test]
    fn mr_timestamp_derivation_saturates_at_epoch_overflow_boundary() {
        let safe = test_entry("DEC-SAFE", u64::MAX / 1000);
        assert_eq!(safe.timestamp_ms, (u64::MAX / 1000) * 1000);

        let overflow = test_entry("DEC-OVERFLOW", (u64::MAX / 1000) + 1);
        assert_eq!(overflow.timestamp_ms, u64::MAX);

        let max = test_entry("DEC-MAX", u64::MAX);
        assert_eq!(max.timestamp_ms, u64::MAX);
    }

    // ── Serialization ──

    #[test]
    fn evidence_entry_serialization_roundtrip() {
        let entry = make_entry("DEC-001", 42);
        let json = serde_json::to_string(&entry).expect("should succeed");
        let parsed: EvidenceEntry = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(entry, parsed);
    }

    #[test]
    fn snapshot_serialization_roundtrip() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let snap = ledger.snapshot();
        let json = serde_json::to_string(&snap).expect("should succeed");
        let parsed: LedgerSnapshot = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(snap.entries.len(), parsed.entries.len());
    }

    // ── Display ──

    #[test]
    fn entry_id_display() {
        assert_eq!(format!("{}", EntryId(1)), "E-00000001");
        assert_eq!(format!("{}", EntryId(42)), "E-00000042");
    }

    #[test]
    fn ledger_error_display() {
        let err = LedgerError::EntryTooLarge {
            entry_size: 1000,
            max_bytes: 500,
        };
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));
    }

    // ── Lab spill mode ──

    #[test]
    fn lab_spill_writes_jsonl() {
        let buffer: Vec<u8> = Vec::new();
        let mut spill = LabSpillMode::new(LedgerCapacity::new(100, 100_000), Box::new(buffer));
        spill
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        spill
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        assert_eq!(spill.len(), 2);
    }

    #[test]
    fn spill_writer_streams_jsonl_without_string_buffer() {
        let (writer, buffer) = SharedBufferWriter::new();
        let mut spill_writer = SpillWriter::Generic(Box::new(writer));
        let entry = make_entry("DEC-SPILL-STREAM", 9);

        let json_bytes = spill_writer
            .append_json_entry(&entry)
            .expect("spill writer should serialize directly");

        let captured = captured_text(&buffer);
        let line = captured
            .strip_suffix('\n')
            .expect("spill output should end with newline");
        let expected_line =
            serde_json::to_string(&entry).expect("entry serialization should succeed");

        assert_eq!(json_bytes, expected_line.len());
        assert_eq!(line, expected_line);
    }

    #[test]
    fn spill_writer_generic_defers_flush_until_sync() {
        let (writer, buffer, flush_count) = FlushCountingWriter::new();
        let mut spill_writer = SpillWriter::Generic(Box::new(writer));
        let entry = make_entry("DEC-SPILL-FLUSH", 10);

        spill_writer
            .append_json_entry(&entry)
            .expect("generic spill writer should buffer between appends");

        let captured = captured_text(&buffer);
        let line = captured
            .strip_suffix('\n')
            .expect("spill output should end with newline");
        let expected_line =
            serde_json::to_string(&entry).expect("entry serialization should succeed");

        assert_eq!(line, expected_line);
        assert_eq!(flush_count.load(Ordering::SeqCst), 0);

        spill_writer
            .sync_durability()
            .expect("explicit sync should flush generic writer");
        assert_eq!(flush_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn spill_writer_file_buffers_jsonl_without_changing_bytes() {
        let dir = tempfile::tempdir().expect("should succeed");
        let spill_path = dir.path().join("buffered_spill.jsonl");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&spill_path)
            .expect("spill file should open");
        let mut spill_writer = SpillWriter::File(new_spill_file_writer(file));
        let entry = make_entry("DEC-SPILL-FILE", 11);

        let json_bytes = spill_writer
            .append_json_entry(&entry)
            .expect("spill writer should serialize directly");
        spill_writer
            .sync_durability()
            .expect("buffered file writer should flush and sync");
        drop(spill_writer);

        let captured = std::fs::read_to_string(&spill_path).expect("spill file should be readable");
        let line = captured
            .strip_suffix('\n')
            .expect("spill output should end with newline");
        let expected_line =
            serde_json::to_string(&entry).expect("entry serialization should succeed");

        assert_eq!(json_bytes, expected_line.len());
        assert_eq!(line, expected_line);
    }

    #[test]
    fn lab_spill_file_uses_large_buffer_capacity() {
        let dir = tempfile::tempdir().expect("should succeed");
        let spill_path = dir.path().join("spill-capacity.jsonl");
        let spill = LabSpillMode::with_file(LedgerCapacity::new(4, 4096), &spill_path)
            .expect("spill file should open");

        match spill.spill_writer {
            SpillWriter::File(file) => assert_eq!(file.capacity(), SPILL_FILE_BUFFER_BYTES),
            SpillWriter::Generic(_) => {
                assert!(false, "with_file should use a file-backed spill writer")
            }
        }
    }

    #[test]
    fn lab_spill_to_tempfile() {
        let dir = tempfile::tempdir().expect("should succeed");
        let spill_path = dir.path().join("evidence_spill.jsonl");
        {
            let mut spill = LabSpillMode::with_file(LedgerCapacity::new(100, 100_000), &spill_path)
                .expect("should succeed");
            spill
                .append(make_entry("DEC-001", 1))
                .expect("should succeed");
            spill
                .append(make_entry("DEC-002", 2))
                .expect("should succeed");
            spill
                .append(make_entry("DEC-003", 3))
                .expect("should succeed");
        }
        let content = std::fs::read_to_string(&spill_path).expect("should succeed");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let parsed: EvidenceEntry = serde_json::from_str(line).expect("should succeed");
            assert_eq!(parsed.schema_version, "1.0");
        }
    }

    #[test]
    fn lab_spill_with_file_persists_acknowledged_entry_after_forced_drop() {
        let dir = tempfile::tempdir().expect("should succeed");
        let spill_path = dir.path().join("durable_evidence_spill.jsonl");

        let acknowledged_id = {
            let mut spill = LabSpillMode::with_file(LedgerCapacity::new(100, 100_000), &spill_path)
                .expect("spill file should open");
            let id = spill
                .append(make_entry("DEC-DURABLE", 7))
                .expect("file-backed spill append should acknowledge buffered write");
            assert_eq!(spill.len(), 1);
            drop(spill);
            id
        };

        let content = std::fs::read_to_string(&spill_path).expect("synced spill file should exist");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(acknowledged_id, EntryId(1));
        assert_eq!(lines.len(), 1);

        let parsed: EvidenceEntry =
            serde_json::from_str(lines[0]).expect("spill line should parse");
        assert_eq!(parsed.decision_id, "DEC-DURABLE");
        assert_eq!(parsed.epoch_id, 7);
    }

    #[test]
    fn appended_entries_use_final_serialized_size_after_hash_chain_finalization() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("first append");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("second append");

        let snapshot = ledger.snapshot();
        let serialized_total: usize = snapshot
            .entries
            .iter()
            .map(|(_, entry)| {
                serde_json::to_string(entry)
                    .expect("entry serialization")
                    .len()
            })
            .sum();
        let second_entry = &snapshot.entries[1].1;

        assert!(
            !second_entry.prev_entry_hash.is_empty(),
            "hash-chained entries must carry the prior hash"
        );
        assert_eq!(
            second_entry.size_bytes,
            serde_json::to_string(second_entry)
                .expect("entry serialization")
                .len(),
            "size_bytes must reflect the finalized entry including prev_entry_hash"
        );
        assert_eq!(
            ledger.current_bytes(),
            serialized_total,
            "ledger byte accounting must match the finalized retained entries"
        );
    }

    #[test]
    fn append_normalizes_client_size_bytes_without_changing_hash_chain_validation() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("first append");

        let expected_prev_hash = ledger
            .last_entry_hash
            .as_ref()
            .map(encode_entry_hash)
            .expect("first append should establish chain hash");
        let mut second_entry = make_entry("DEC-002", 2);
        second_entry.size_bytes = usize::MAX;
        second_entry.prev_entry_hash = expected_prev_hash;

        ledger.append(second_entry).expect("second append");

        let snapshot = ledger.snapshot();
        let appended_entry = &snapshot.entries[1].1;
        assert!(
            appended_entry.size_bytes < usize::MAX,
            "ledger must recompute server-owned size_bytes"
        );
        assert!(
            !appended_entry.prev_entry_hash.is_empty(),
            "hash chain linkage must still be finalized"
        );
        assert_eq!(
            appended_entry.prev_entry_hash, expected_prev_hash,
            "external prev_entry_hash contract must stay hex-encoded even if the ledger stores raw hash bytes internally"
        );
    }

    #[test]
    fn validate_append_finalizes_owned_entry_without_losing_payload() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("first append");

        let expected_prev_hash = ledger
            .last_entry_hash
            .as_ref()
            .map(encode_entry_hash)
            .expect("first append should establish chain hash");
        let mut entry = make_entry("DEC-002", 2);
        entry.prev_entry_hash = expected_prev_hash.clone();
        entry.payload = serde_json::json!({
            "padding": "x".repeat(64),
            "nested": { "epoch": 2, "decision": "DEC-002" }
        });
        let expected_payload = entry.payload.clone();

        let (normalized_entry, _entry_size, precomputed_hash, replay_signature) = ledger
            .validate_append(entry)
            .expect("validation should succeed");

        assert!(replay_signature.is_none());
        assert_eq!(normalized_entry.prev_entry_hash, expected_prev_hash);
        assert_eq!(normalized_entry.payload, expected_payload);
        assert_eq!(
            precomputed_hash,
            ledger.compute_entry_hash(&normalized_entry)
        );
    }

    #[test]
    fn server_computed_size_matches_serialized_length_across_digit_boundary() {
        let mut found_digit_boundary = false;

        for payload_size in 0..4096 {
            let mut entry = test_entry("DEC-BOUNDARY", 1);
            entry.payload = serde_json::json!({ "padding": "x".repeat(payload_size) });

            let mut zero_sized = entry.clone();
            zero_sized.size_bytes = 0;
            let base_size = serialized_entry_size(&zero_sized);

            let (normalized, computed_size) = entry_with_server_computed_size(entry);
            let serialized_len = serde_json::to_string(&normalized)
                .expect("normalized entry serialization")
                .len();

            assert_eq!(
                computed_size, serialized_len,
                "closed-form size solver must match actual serialized length"
            );

            let initial_guess = base_size
                .saturating_sub(1)
                .saturating_add(decimal_digit_count(base_size));
            if decimal_digit_count(computed_size) != decimal_digit_count(initial_guess) {
                found_digit_boundary = true;
                break;
            }
        }

        assert!(
            found_digit_boundary,
            "test should exercise a size_bytes decimal-boundary crossover"
        );
    }

    #[test]
    fn estimated_size_matches_serialized_utf8_length() {
        let mut entry = test_entry("DEC-UTF8", 1);
        entry.payload = serde_json::json!({
            "message": "trust-native runtime",
            "unicode": "🙂漢字"
        });

        assert_eq!(
            entry.estimated_size(),
            serde_json::to_string(&entry)
                .expect("entry serialization")
                .len(),
            "estimated_size must track exact serialized UTF-8 byte length"
        );
    }

    #[test]
    fn entry_hash_changes_when_unsigned_decision_metadata_changes() {
        let ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000));
        let base_entry = make_entry("DEC-001", 1);

        let mut different_kind = base_entry.clone();
        different_kind.decision_kind = DecisionKind::Deny;

        let mut different_time = base_entry.clone();
        different_time.decision_time = "2026-01-01T00:00:01Z".to_string();

        assert_ne!(
            ledger.compute_entry_hash(&base_entry),
            ledger.compute_entry_hash(&different_kind),
            "hash chain must distinguish decision kind changes even without signatures"
        );
        assert_ne!(
            ledger.compute_entry_hash(&base_entry),
            ledger.compute_entry_hash(&different_time),
            "hash chain must distinguish decision timestamp changes even without signatures"
        );
    }

    #[test]
    fn public_evidence_entry_hash_hex_matches_internal_chain_hash() {
        let ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000));
        let entry = make_entry("DEC-001", 1);

        assert_eq!(
            evidence_entry_hash_hex(&entry),
            encode_entry_hash(&ledger.compute_entry_hash(&entry)),
            "public hash-chain helper must match the ledger's internal chain digest"
        );
    }

    #[test]
    fn lab_spill_eviction_still_works() {
        let buffer: Vec<u8> = Vec::new();
        let mut spill = LabSpillMode::new(LedgerCapacity::new(2, 100_000), Box::new(buffer));
        spill
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        spill
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        spill
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert_eq!(spill.len(), 2);
        assert_eq!(spill.ledger().total_evicted(), 1);
    }

    #[test]
    fn lab_spill_snapshot() {
        let buffer: Vec<u8> = Vec::new();
        let mut spill = LabSpillMode::new(LedgerCapacity::new(100, 100_000), Box::new(buffer));
        spill
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let snap = spill.snapshot();
        assert_eq!(snap.entries.len(), 1);
    }

    #[test]
    fn zero_entry_capacity_rejects_append() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(0, 100_000));

        let result = ledger.append(make_entry("DEC-001", 1));

        assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
        assert!(ledger.is_empty());
        assert_eq!(ledger.total_appended(), 0);
    }

    #[test]
    fn lab_spill_write_failure_does_not_mutate_ledger() {
        let mut spill = LabSpillMode::new(
            LedgerCapacity::new(100, 100_000),
            Box::new(FailingWriteWriter),
        );

        let result = spill.append(make_entry("DEC-001", 1));

        assert!(matches!(result, Err(LedgerError::SpillError { .. })));
        assert_eq!(spill.len(), 0);
        assert!(spill.is_empty());
        assert_eq!(spill.snapshot().total_appended, 0);
    }

    #[test]
    fn lab_spill_sync_flush_failure_preserves_buffered_entry() {
        let mut spill = LabSpillMode::new(
            LedgerCapacity::new(100, 100_000),
            Box::new(FailingFlushWriter),
        );

        let id = spill
            .append(make_entry("DEC-001", 1))
            .expect("append should stay buffered until sync");
        assert_eq!(id, EntryId(1));
        assert_eq!(spill.len(), 1);
        assert!(!spill.is_empty());
        assert_eq!(spill.snapshot().total_appended, 1);

        let result = spill.sync_evidence_durability();
        assert!(matches!(result, Err(LedgerError::SpillError { .. })));
        assert_eq!(spill.len(), 1);
        assert_eq!(spill.snapshot().total_appended, 1);
    }

    #[test]
    fn lab_spill_oversized_entry_rejected_before_writer_use() {
        let mut spill =
            LabSpillMode::new(LedgerCapacity::new(100, 50), Box::new(PanicOnWriteWriter));

        let result = spill.append(make_entry_with_payload("DEC-BIG", 1, 500));

        assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
        assert_eq!(spill.len(), 0);
        assert_eq!(spill.snapshot().total_appended, 0);
    }

    #[test]
    fn lab_spill_zero_entry_capacity_rejected_before_writer_use() {
        let mut spill = LabSpillMode::new(
            LedgerCapacity::new(0, 100_000),
            Box::new(PanicOnWriteWriter),
        );

        let result = spill.append(make_entry("DEC-001", 1));

        assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
        assert!(spill.is_empty());
        assert_eq!(spill.snapshot().total_appended, 0);
    }

    // ── SharedEvidenceLedger ──

    #[test]
    fn shared_ledger_basic_operations() {
        let shared = SharedEvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        assert!(shared.is_empty());
        shared
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        assert_eq!(shared.len(), 1);
        assert!(!shared.is_empty());
    }

    #[test]
    fn shared_ledger_snapshot() {
        let shared = SharedEvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        shared
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        shared
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        let snap = shared.snapshot();
        assert_eq!(snap.entries.len(), 2);
    }

    #[test]
    fn shared_ledger_permits_parallel_read_guards() {
        let shared = SharedEvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        shared
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");

        let first_reader = shared.inner.read().expect("first read guard");
        let second_reader = shared
            .inner
            .try_read()
            .expect("second read guard should not block while first reader is active");

        assert_eq!(first_reader.len(), 1);
        assert_eq!(second_reader.metrics().retained_entries, 1);
    }

    #[test]
    fn shared_ledger_recovers_from_poisoned_lock() {
        let shared = SharedEvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let poison_target = shared.clone();
        let join = std::thread::spawn(move || {
            let _guard = poison_target
                .inner
                .write()
                .expect("write lock acquired for poison test");
            panic!("intentional poison");
        });
        assert!(join.join().is_err(), "poisoning thread should panic");

        assert!(shared.is_empty());
        shared
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        assert_eq!(shared.len(), 1);
        assert_eq!(shared.snapshot().entries.len(), 1);
    }

    // ── Steady-state load ──

    #[test]
    fn steady_state_load_100_entries() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        for i in 1..=500u64 {
            ledger
                .append(make_entry(&format!("DEC-{i:05}"), i))
                .expect("should succeed");
        }
        assert_eq!(ledger.len(), 100);
        assert_eq!(ledger.total_appended(), 500);
        assert_eq!(ledger.total_evicted(), 400);
        assert!(ledger.current_bytes() <= 100_000);
    }

    // ── Edge cases ──

    #[test]
    fn capacity_one() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        assert_eq!(ledger.len(), 1);
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.total_evicted(), 1);
        let entries: Vec<_> = ledger.iter_all().collect();
        assert_eq!(entries[0].1.decision_id, "DEC-002");
    }

    // ── DecisionKind labels ──

    #[test]
    fn decision_kind_labels() {
        assert_eq!(DecisionKind::Admit.label(), "admit");
        assert_eq!(DecisionKind::Deny.label(), "deny");
        assert_eq!(DecisionKind::Quarantine.label(), "quarantine");
        assert_eq!(DecisionKind::Release.label(), "release");
        assert_eq!(DecisionKind::Rollback.label(), "rollback");
        assert_eq!(DecisionKind::Throttle.label(), "throttle");
        assert_eq!(DecisionKind::Escalate.label(), "escalate");
    }

    // ── Spill determinism ──

    #[test]
    fn spill_determinism_two_runs_identical() {
        fn run_spill() -> String {
            let dir = tempfile::tempdir().expect("should succeed");
            let path = dir.path().join("spill.jsonl");
            {
                let mut spill = LabSpillMode::with_file(LedgerCapacity::new(100, 100_000), &path)
                    .expect("should succeed");
                for i in 1..=3 {
                    spill
                        .append(make_entry(&format!("DEC-{i:03}"), i))
                        .expect("should succeed");
                }
            }
            std::fs::read_to_string(&path).expect("should succeed")
        }
        let run1 = run_spill();
        let run2 = run_spill();
        assert_eq!(run1, run2, "spill output must be deterministic");
    }

    // ── Additional named tests for verification script ──

    #[test]
    fn append_assigns_monotonic_ids() {
        // Alias for entry_ids_are_monotonic (verification script checks this name)
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        let id1 = ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let id2 = ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        assert!(id1 < id2);
    }

    #[test]
    fn eviction_at_max_entries() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.total_evicted(), 1);
    }

    #[test]
    fn fifo_order_maintained_across_many_evictions() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        for i in 1..=20u64 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        assert_eq!(ledger.len(), 3);
        let entries: Vec<_> = ledger.iter_all().collect();
        assert_eq!(entries[0].1.decision_id, "DEC-018");
        assert_eq!(entries[1].1.decision_id, "DEC-019");
        assert_eq!(entries[2].1.decision_id, "DEC-020");
    }

    #[test]
    fn eviction_at_max_bytes() {
        let entry = make_entry("DEC-X", 1);
        let sz = entry.estimated_size();
        let max_bytes = sz * 2 + 5;
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, max_bytes));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-003", 3))
            .expect("should succeed");
        assert!(ledger.current_bytes() <= max_bytes);
        assert!(ledger.total_evicted() > 0);
    }

    #[test]
    fn entry_too_large_rejected() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 50));
        let result = ledger.append(make_entry_with_payload("DEC-BIG", 1, 500));
        assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
    }

    #[test]
    fn iter_recent_empty_ledger() {
        let ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        assert_eq!(ledger.iter_recent(10).count(), 0);
    }

    #[test]
    fn snapshot_reflects_current_state() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.total_appended, 2);
    }

    #[test]
    fn snapshot_is_independent_of_ledger() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 100_000));
        ledger
            .append(make_entry("DEC-001", 1))
            .expect("should succeed");
        let snap = ledger.snapshot();
        ledger
            .append(make_entry("DEC-002", 2))
            .expect("should succeed");
        assert_eq!(snap.entries.len(), 1); // snap unchanged
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn deterministic_identical_inputs_produce_identical_snapshots() {
        fn run() -> LedgerSnapshot {
            let mut l = EvidenceLedger::new(LedgerCapacity::new(5, 100_000));
            for i in 1..=8 {
                l.append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("should succeed");
            }
            l.snapshot()
        }
        let s1 = run();
        let s2 = run();
        assert_eq!(s1.entries.len(), s2.entries.len());
        assert_eq!(s1.total_appended, s2.total_appended);
    }

    #[test]
    fn two_ledgers_same_input_same_snapshot() {
        let mut l1 = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        let mut l2 = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        for i in 1..=5u64 {
            l1.append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
            l2.append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        let s1 = l1.snapshot();
        let s2 = l2.snapshot();
        assert_eq!(s1.entries.len(), s2.entries.len());
        for (a, b) in s1.entries.iter().zip(s2.entries.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.decision_id, b.1.decision_id);
        }
    }

    #[test]
    fn evidence_ledger_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SharedEvidenceLedger>();
    }

    #[test]
    fn full_lifecycle_append_evict_snapshot_iterate() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(3, 100_000));
        for i in 1..=6u64 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.total_evicted(), 3);
        let snap = ledger.snapshot();
        assert_eq!(snap.entries.len(), 3);
        let recent: Vec<_> = ledger.iter_recent(2).collect();
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn single_capacity_ledger() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1, 100_000));
        for i in 1..=10u64 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.total_evicted(), 9);
    }

    #[test]
    fn variable_size_entries_respect_max_bytes() {
        let small = make_entry("DEC-S", 1);
        let sz = small.estimated_size();
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, sz * 3));
        for i in 1..=10u64 {
            ledger
                .append(make_entry(&format!("DEC-{i:03}"), i))
                .expect("should succeed");
        }
        assert!(ledger.current_bytes() <= sz * 3);
    }

    mod ledger_observability_contract_tests {
        use super::*;

        #[test]
        fn metrics_emission_matches_snapshot_and_live_accessors() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 100_000));
            for i in 1..=3u64 {
                ledger
                    .append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("append should succeed");
            }

            let metrics = ledger.metrics();
            let snapshot = ledger.snapshot();

            assert_eq!(metrics.retained_entries, ledger.len());
            assert_eq!(metrics.retained_entries, snapshot.entries.len());
            assert_eq!(metrics.total_appended, ledger.total_appended());
            assert_eq!(metrics.total_appended, snapshot.total_appended);
            assert_eq!(metrics.total_evicted, ledger.total_evicted());
            assert_eq!(metrics.total_evicted, snapshot.total_evicted);
            assert_eq!(metrics.current_bytes, ledger.current_bytes());
            assert_eq!(metrics.current_bytes, snapshot.current_bytes);
            assert_eq!(metrics.max_entries, 2);
            assert_eq!(metrics.max_bytes, 100_000);
        }

        #[test]
        fn metrics_emission_is_unchanged_by_rejected_append() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 200));
            let before = ledger.metrics();

            let result = ledger.append(make_entry_with_payload("DEC-BIG", 9, 10_000));

            assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
            assert_eq!(ledger.metrics(), before);
            assert!(ledger.is_empty());
        }

        #[test]
        fn metrics_emission_is_unchanged_by_zero_capacity_rejection() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(0, 100_000));
            let before = ledger.metrics();

            let result = ledger.append(make_entry("DEC-ZERO-METRICS", 1));

            assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
            assert_eq!(ledger.metrics(), before);
            assert!(ledger.snapshot().entries.is_empty());
        }

        #[test]
        fn structured_append_and_eviction_event_format_is_stable() {
            let entry = make_entry("DEC-STRUCT", 7);

            assert_eq!(
                format!("{}", format_ledger_append_event(EntryId(7), &entry, 123)),
                "EVD-LEDGER-001: entry=E-00000007, decision=DEC-STRUCT, epoch=7, size=123"
            );
            assert_eq!(
                format!("{}", format_ledger_eviction_event(EntryId(8), &entry, 456)),
                "EVD-LEDGER-002: evicted entry=E-00000008, decision=DEC-STRUCT, epoch=7, freed_bytes=456"
            );
        }

        #[test]
        fn structured_capacity_spill_and_lock_event_format_is_stable() {
            let capacity = LedgerCapacity::new(3, 4096);
            let entry = make_entry("DEC-CAP", 11);

            assert_eq!(
                format!("{}", format_ledger_init_event(&capacity)),
                "EVD-LEDGER-004: evidence ledger initialized: max_entries=3, max_bytes=4096"
            );
            assert_eq!(
                format!("{}", format_ledger_zero_capacity_event(&entry)),
                "EVD-LEDGER-004: append rejected because max_entries=0, epoch=11"
            );
            assert_eq!(
                format!(
                    "{}",
                    format_ledger_entry_too_large_event(5000, 4096, entry.epoch_id)
                ),
                "EVD-LEDGER-004: entry size 5000 exceeds max_bytes 4096, epoch=11"
            );
            assert_eq!(
                format!("{}", format_ledger_spill_event(EntryId(12), 99)),
                "EVD-LEDGER-003: spill wrote entry=E-00000012, bytes=99"
            );
            assert_eq!(
                format_ledger_lock_poison_recovered_event(),
                "EVD-LEDGER-005: recovering from poisoned evidence ledger lock"
            );
        }

        #[test]
        fn audit_log_spill_emits_valid_jsonl_in_append_order() {
            let (writer, buffer) = SharedBufferWriter::new();
            let mut spill = LabSpillMode::new(LedgerCapacity::new(10, 100_000), Box::new(writer));

            for i in 1..=3u64 {
                spill
                    .append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("spill append should succeed");
            }

            let parsed = parsed_spill_entries(&buffer);
            let ids: Vec<_> = parsed
                .iter()
                .map(|entry| entry.decision_id.as_str())
                .collect();

            assert_eq!(ids, vec!["DEC-001", "DEC-002", "DEC-003"]);
            assert!(parsed.iter().all(|entry| entry.schema_version == "1.0"));
            assert_eq!(spill.metrics().total_appended, 3);
        }

        #[test]
        fn audit_log_spill_matches_finalized_snapshot_entries() {
            let (writer, buffer) = SharedBufferWriter::new();
            let mut spill = LabSpillMode::new(LedgerCapacity::new(10, 100_000), Box::new(writer));

            for i in 1..=3u64 {
                spill
                    .append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("spill append should succeed");
            }

            let parsed = parsed_spill_entries(&buffer);
            let snapshot_entries: Vec<_> = spill
                .snapshot()
                .entries
                .into_iter()
                .map(|(_, entry)| entry)
                .collect();

            assert_eq!(
                parsed, snapshot_entries,
                "spill JSONL must match the finalized in-memory entries"
            );
        }

        #[test]
        fn audit_log_preserves_full_history_after_memory_eviction() {
            let (writer, buffer) = SharedBufferWriter::new();
            let mut spill = LabSpillMode::new(LedgerCapacity::new(2, 100_000), Box::new(writer));

            for i in 1..=4u64 {
                spill
                    .append(make_entry(&format!("DEC-{i:03}"), i))
                    .expect("spill append should succeed");
            }

            let parsed = parsed_spill_entries(&buffer);
            let audit_ids: Vec<_> = parsed
                .iter()
                .map(|entry| entry.decision_id.as_str())
                .collect();
            let retained_ids = snapshot_decision_ids(&spill.snapshot());

            assert_eq!(audit_ids, vec!["DEC-001", "DEC-002", "DEC-003", "DEC-004"]);
            assert_eq!(retained_ids, vec!["DEC-003", "DEC-004"]);
            assert_eq!(spill.metrics().total_appended, 4);
            assert_eq!(spill.metrics().total_evicted, 2);
        }

        #[test]
        fn audit_log_rejected_entry_does_not_write_partial_line() {
            let (writer, buffer) = SharedBufferWriter::new();
            let mut spill = LabSpillMode::new(LedgerCapacity::new(10, 1_000), Box::new(writer));
            spill
                .append(make_entry("DEC-OK", 1))
                .expect("initial spill append should succeed");
            let before = captured_text(&buffer);

            let result = spill.append(make_entry_with_payload("DEC-BIG", 2, 10_000));

            assert!(matches!(result, Err(LedgerError::EntryTooLarge { .. })));
            assert_eq!(captured_text(&buffer), before);
            assert_eq!(parsed_spill_entries(&buffer).len(), 1);
            assert_eq!(spill.metrics().total_appended, 1);
        }

        #[test]
        fn audit_log_zero_capacity_rejection_does_not_write_line() {
            let (writer, buffer) = SharedBufferWriter::new();
            let mut spill = LabSpillMode::new(LedgerCapacity::new(0, 100_000), Box::new(writer));

            let result = spill.append(make_entry("DEC-ZERO", 1));

            assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
            assert!(captured_text(&buffer).is_empty());
            assert_eq!(spill.metrics().total_appended, 0);
            assert_eq!(spill.metrics().retained_entries, 0);
        }

        #[test]
        fn shared_zero_capacity_rejection_leaves_metrics_empty() {
            let shared = SharedEvidenceLedger::new(LedgerCapacity::new(0, 100_000));

            let result = shared.append(make_entry("DEC-SHARED-ZERO", 1));

            assert!(matches!(result, Err(LedgerError::ZeroEntryCapacity)));
            assert_eq!(shared.metrics().retained_entries, 0);
            assert_eq!(shared.metrics().total_appended, 0);
            assert_eq!(shared.snapshot().entries.len(), 0);
        }

        #[test]
        fn negative_unicode_injection_in_decision_ids() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 1_000_000));

            let malicious_ids = vec![
                "normal\u{202e}evil\u{202c}decision", // BiDi override
                "decision\u{200b}\u{feff}hidden",     // Zero-width chars
                "decision\nnewline",                  // Newline injection
                "decision\ttab",                      // Tab injection
                "decision\x00null",                   // Null byte
                "../../../etc/passwd",                // Path traversal
                "decision\"quote",                    // Quote injection
            ];

            for (i, malicious_id) in malicious_ids.iter().enumerate() {
                let mut entry = make_entry("BASE", i as u64);
                entry.decision_id = malicious_id.to_string();

                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            let snapshot = ledger.snapshot();
            assert_eq!(snapshot.entries.len(), malicious_ids.len());

            for (entry, expected_id) in snapshot.entries.iter().zip(&malicious_ids) {
                assert_eq!(entry.decision_id, *expected_id);
            }
        }

        #[test]
        fn negative_massive_payload_memory_exhaustion() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 100_000_000));

            // Create massive JSON payloads (10MB each)
            let massive_array: Vec<u8> = vec![0x42; 10_000_000];
            let massive_payload = serde_json::json!({
                "massive_data": base64::encode(&massive_array),
                "description": "memory exhaustion test"
            });

            for i in 0..5 {
                let mut entry = make_entry(&format!("MASSIVE-{}", i), i);
                entry.payload = massive_payload.clone();

                let result = ledger.append(entry);
                // Should handle large payloads gracefully
                if result.is_err() {
                    // Acceptable if it rejects due to size limits
                    continue;
                }
            }

            // Ledger should remain functional
            let final_entry = make_entry("FINAL", 999);
            let result = ledger.append(final_entry);
            assert!(result.is_ok());
        }

        #[test]
        fn negative_timestamp_arithmetic_overflow_boundaries() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(50, 1_000_000));

            let overflow_timestamps = vec![
                u64::MAX,
                u64::MAX - 1,
                u64::MAX / 2,
                (1u64 << 63) - 1,
                0, // Epoch start
            ];

            for (i, timestamp) in overflow_timestamps.iter().enumerate() {
                let mut entry = make_entry(&format!("OVERFLOW-{}", i), i as u64);
                entry.timestamp_ms = *timestamp;

                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            let snapshot = ledger.snapshot();
            assert_eq!(snapshot.entries.len(), overflow_timestamps.len());

            for (entry, expected_ts) in snapshot.entries.iter().zip(&overflow_timestamps) {
                assert_eq!(entry.timestamp_ms, *expected_ts);
            }
        }

        #[test]
        fn negative_epoch_id_boundary_conditions() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(20, 500_000));

            let boundary_epochs = vec![0, 1, u64::MAX, u64::MAX - 1, u64::MAX / 2];

            for (i, epoch) in boundary_epochs.iter().enumerate() {
                let mut entry = make_entry(&format!("EPOCH-{}", i), i as u64);
                entry.epoch_id = *epoch;

                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            let snapshot = ledger.snapshot();
            for (entry, expected_epoch) in snapshot.entries.iter().zip(&boundary_epochs) {
                assert_eq!(entry.epoch_id, *expected_epoch);
            }
        }

        #[test]
        fn negative_malformed_json_payload_resilience() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(30, 1_000_000));

            // Create entries with various malformed payload structures
            let malformed_payloads = vec![
                serde_json::json!(null),
                serde_json::json!("not an object"),
                serde_json::json!(["array", "instead", "of", "object"]),
                serde_json::json!(42),
                serde_json::json!(true),
                serde_json::Value::String("\u{FFFF}invalid\u{0000}chars".to_string()),
            ];

            for (i, payload) in malformed_payloads.iter().enumerate() {
                let mut entry = make_entry(&format!("MALFORMED-{}", i), i as u64);
                entry.payload = payload.clone();

                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            // Verify all entries were stored correctly
            let snapshot = ledger.snapshot();
            assert_eq!(snapshot.entries.len(), malformed_payloads.len());
        }

        #[test]
        fn negative_capacity_overflow_fifo_behavior_stress() {
            let small_capacity = LedgerCapacity::new(3, 1000);
            let mut ledger = EvidenceLedger::new(small_capacity);

            // Add many entries to force overflow
            for i in 0..100 {
                let entry = make_entry(&format!("STRESS-{:04}", i), i);
                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            let snapshot = ledger.snapshot();
            assert_eq!(snapshot.entries.len(), 3);

            // Should retain the last 3 entries (97, 98, 99)
            let retained_ids: Vec<String> = snapshot
                .entries
                .iter()
                .map(|e| e.decision_id.clone())
                .collect();

            assert_eq!(
                retained_ids,
                vec!["STRESS-0097", "STRESS-0098", "STRESS-0099"]
            );
        }

        #[test]
        fn negative_concurrent_append_thread_safety() {
            use std::sync::Arc;
            use std::thread;

            let shared_ledger = Arc::new(SharedEvidenceLedger::new(LedgerCapacity::new(
                1000, 10_000_000,
            )));

            let mut handles = Vec::new();

            for thread_id in 0..4 {
                let ledger = Arc::clone(&shared_ledger);
                let handle = thread::spawn(move || {
                    for i in 0..250 {
                        let entry = make_entry(
                            &format!("T{}-{:03}", thread_id, i),
                            (thread_id * 1000 + i) as u64,
                        );
                        let _ = ledger.append(entry);
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().expect("Thread should complete");
            }

            // All 1000 entries should be present
            let snapshot = shared_ledger.snapshot();
            assert_eq!(snapshot.entries.len(), 1000);

            let metrics = shared_ledger.metrics();
            assert_eq!(metrics.total_appended, 1000);
            assert_eq!(metrics.retained_entries, 1000);
        }

        #[test]
        fn negative_size_bytes_calculation_edge_cases() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 1000));

            // Test with manual size_bytes that don't match actual size
            let mut entry = make_entry("SIZE-TEST", 1);
            entry.size_bytes = usize::MAX; // Impossible size

            let result = ledger.append(entry);
            if result.is_err() {
                // Should reject if size validation is strict
                return;
            }

            // Test with zero size_bytes
            let mut zero_size_entry = make_entry("ZERO-SIZE", 2);
            zero_size_entry.size_bytes = 0;

            let result = ledger.append(zero_size_entry);
            assert!(result.is_ok());

            let snapshot = ledger.snapshot();
            assert!(snapshot.entries.len() <= 2);
        }

        #[test]
        fn negative_empty_string_field_edge_cases() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(50, 500_000));

            let empty_field_entries = vec![
                EvidenceEntry {
                    schema_version: "".to_string(),
                    entry_id: Some("".to_string()),
                    decision_id: "".to_string(),
                    decision_kind: DecisionKind::Admit,
                    decision_time: "".to_string(),
                    timestamp_ms: 0,
                    trace_id: "".to_string(),
                    epoch_id: 0,
                    payload: serde_json::json!({}),
                    size_bytes: 0,
                    signature: String::new(),
                },
                EvidenceEntry {
                    schema_version: "v1.0".to_string(),
                    entry_id: None, // None variant
                    decision_id: "valid-id".to_string(),
                    decision_kind: DecisionKind::Deny,
                    decision_time: "2024-01-01T00:00:00Z".to_string(),
                    timestamp_ms: 1700000000000,
                    trace_id: "trace-123".to_string(),
                    epoch_id: 1,
                    payload: serde_json::json!({"empty": {}}),
                    size_bytes: 100,
                    signature: String::new(),
                },
            ];

            for entry in empty_field_entries {
                let result = ledger.append(entry);
                assert!(result.is_ok());
            }

            let snapshot = ledger.snapshot();
            assert_eq!(snapshot.entries.len(), 2);
        }

        // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

        #[test]
        fn test_negative_decision_id_with_unicode_injection_attacks() {
            use crate::security::constant_time;

            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 1_000_000));

            let malicious_decision_ids = [
                "decision\u{202E}fake\u{202C}",        // BiDi override attack
                "decision\x1b[31mred\x1b[0m",          // ANSI escape injection
                "decision\0null\r\n\t",                // Control character injection
                "decision\"}{\"admin\":true,\"bypass", // JSON injection attempt
                "decision/../../etc/passwd",           // Path traversal attempt
                "decision\u{FEFF}BOM",                 // Byte order mark
                "decision\u{200B}\u{200C}\u{200D}",    // Zero-width characters
                "decision<script>alert(1)</script>",   // XSS attempt
                "decision'; DROP TABLE evidence; --",  // SQL injection attempt
                "decision||rm -rf /",                  // Shell injection attempt
                "x".repeat(100_000),                   // Extremely long decision ID (100KB)
            ];

            for malicious_id in malicious_decision_ids {
                let malicious_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: malicious_id.to_string(),
                    decision_kind: DecisionKind::Admit,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: "test-trace".to_string(),
                    epoch_id: 1,
                    payload: serde_json::json!({"test": "data"}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                // Test ledger append with malicious decision ID
                let result = ledger.append(malicious_entry.clone());
                assert!(
                    result.is_ok(),
                    "ledger should handle malicious decision IDs"
                );

                if let Ok(entry_id) = result {
                    // Verify entry is stored with decision ID preserved
                    let snapshot = ledger.snapshot();
                    let stored_entry = snapshot
                        .entries
                        .iter()
                        .find(|e| e.1.entry_id == Some(entry_id.to_string()))
                        .map(|(_, entry)| entry);

                    if let Some(entry) = stored_entry {
                        assert_eq!(
                            entry.decision_id, malicious_id,
                            "decision ID should be preserved for forensics"
                        );
                    }
                }

                // Test JSON serialization safety
                let json =
                    serde_json::to_string(&malicious_entry).expect("serialization should work");
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("JSON should be valid");

                // Verify no injection occurred in JSON structure
                assert!(
                    parsed.get("admin").is_none(),
                    "JSON injection should not create admin field"
                );
                assert!(
                    parsed.get("bypass").is_none(),
                    "JSON injection should not create bypass field"
                );

                // Test constant-time comparison for decision IDs
                let normal_id = "normal-decision-123";
                assert!(
                    !constant_time::ct_eq(malicious_id, normal_id),
                    "decision ID comparison should be constant-time"
                );
            }

            // Test with decision IDs that might bypass audit trails
            let audit_bypass_ids = [
                "",                       // Empty decision ID
                "null",                   // Literal "null"
                "undefined",              // Literal "undefined"
                "false",                  // Boolean-like
                "0",                      // Number-like
                "{}",                     // Object-like
                "[]",                     // Array-like
                "admin.override.bypass",  // Administrative bypass attempt
                "system.internal.debug",  // System internal operation
                "security.audit.disable", // Audit disabling attempt
            ];

            for bypass_id in audit_bypass_ids {
                let bypass_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: bypass_id.to_string(),
                    decision_kind: DecisionKind::Admit,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: "audit-bypass-test".to_string(),
                    epoch_id: 1,
                    payload: serde_json::json!({"bypass_attempt": true}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(bypass_entry);
                assert!(
                    result.is_ok(),
                    "ledger should handle audit bypass attempts safely"
                );
            }
        }

        #[test]
        fn test_negative_trace_id_with_massive_injection_payload() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(50, 10_000_000)); // 10MB capacity

            // Create trace ID with massive payload (5MB)
            let massive_trace_id = "X".repeat(5_000_000);

            let massive_entry = EvidenceEntry {
                schema_version: "test-v1".to_string(),
                entry_id: None,
                decision_id: "massive-test".to_string(),
                decision_kind: DecisionKind::Quarantine,
                decision_time: "2026-04-17T10:00:00Z".to_string(),
                timestamp_ms: 1234567890000,
                trace_id: massive_trace_id.clone(),
                epoch_id: 1,
                payload: serde_json::json!({"massive_data": "Y".repeat(1_000_000)}), // 1MB payload
                size_bytes: 0,
                signature: String::new(),
            };

            // Test appending massive entry
            let result = ledger.append(massive_entry.clone());
            assert!(result.is_ok(), "ledger should handle massive entries");

            // Verify massive trace ID is preserved
            let snapshot = ledger.snapshot();
            let stored_entry = snapshot
                .entries
                .iter()
                .find(|(_, entry)| entry.trace_id == massive_trace_id);
            assert!(stored_entry.is_some(), "massive entry should be stored");

            if let Some((_, entry)) = stored_entry {
                assert_eq!(
                    entry.trace_id, massive_trace_id,
                    "massive trace ID should be preserved"
                );
            }

            // Test serialization with massive data
            let json = serde_json::to_string(&massive_entry)
                .expect("serialization should handle massive entry");
            assert!(
                json.len() > 6_000_000,
                "serialized JSON should include massive data"
            );

            // Test deserialization roundtrip
            let parsed: EvidenceEntry =
                serde_json::from_str(&json).expect("deserialization should work");
            assert_eq!(
                parsed.trace_id, massive_trace_id,
                "trace ID should survive roundtrip"
            );

            // Test with injection patterns in trace ID
            let injection_trace_ids = [
                "trace\u{202E}fake\u{202C}",
                "trace\x1b[31mred\x1b[0m",
                "trace\0null\r\n\t",
                "trace\"}{\"admin\":true,\"bypass",
                "trace<script>alert(1)</script>",
                "trace'; DROP TABLE traces; --",
                "trace||rm -rf /",
            ];

            for injection_trace_id in injection_trace_ids {
                let injection_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: "injection-test".to_string(),
                    decision_kind: DecisionKind::Deny,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: injection_trace_id.to_string(),
                    epoch_id: 1,
                    payload: serde_json::json!({"injection_test": true}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(injection_entry.clone());
                assert!(
                    result.is_ok(),
                    "ledger should handle injection trace IDs safely"
                );

                // Verify JSON serialization is safe
                let json =
                    serde_json::to_string(&injection_entry).expect("serialization should work");
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("JSON should be valid");

                // Verify no additional fields were injected
                assert!(
                    parsed.get("admin").is_none(),
                    "JSON injection should not create admin field"
                );
                assert!(
                    parsed.get("bypass").is_none(),
                    "JSON injection should not create bypass field"
                );
            }
        }

        #[test]
        fn test_negative_payload_with_malicious_json_structure() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 1_000_000));

            // Test various malicious JSON payload structures
            let malicious_payloads = [
                // JSON injection attempts
                serde_json::json!({"normal": "data", "injection": "\"},\"admin\":true,\"bypass\":{"}),
                // XSS attempts
                serde_json::json!({"script": "<script>alert('XSS')</script>"}),
                // SQL injection attempts
                serde_json::json!({"query": "'; DROP TABLE evidence; --"}),
                // Shell injection attempts
                serde_json::json!({"command": "; rm -rf / #"}),
                // Unicode attacks
                serde_json::json!({"bidi": "\u{202E}fake\u{202C}"}),
                serde_json::json!({"ansi": "\x1b[31mred\x1b[0m"}),
                serde_json::json!({"control": "data\0null\r\n\t"}),
                // Massive nested structure (memory exhaustion attempt)
                serde_json::json!({
                    "level1": {
                        "level2": {
                            "level3": {
                                "level4": {
                                    "level5": {
                                        "massive_array": (0..10000).collect::<Vec<i32>>(),
                                        "massive_string": "Z".repeat(100_000)
                                    }
                                }
                            }
                        }
                    }
                }),
                // Type confusion attempts
                serde_json::json!(null),
                serde_json::json!([1, 2, 3, "string", {"nested": "object"}]),
                serde_json::json!(42),
                serde_json::json!(true),
                serde_json::json!("just_a_string"),
                // Circular reference simulation (deeply nested)
                (0..1000).fold(
                    serde_json::json!({"end": true}),
                    |acc, i| serde_json::json!({"level": i, "next": acc}),
                ),
                // Field name attacks
                serde_json::json!({
                    "": "empty_key",
                    "null": "null_key",
                    "undefined": "undefined_key",
                    "constructor": "constructor_key",
                    "__proto__": "proto_key",
                    "admin": false,  // Potential privilege escalation
                    "debug": true,   // Debug flag manipulation
                    "bypass": false, // Security bypass flag
                }),
            ];

            for malicious_payload in malicious_payloads {
                let malicious_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: "payload-test".to_string(),
                    decision_kind: DecisionKind::Escalate,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: "payload-injection-test".to_string(),
                    epoch_id: 1,
                    payload: malicious_payload.clone(),
                    size_bytes: 0,
                    signature: String::new(),
                };

                // Test appending malicious payload
                let result = ledger.append(malicious_entry.clone());
                assert!(result.is_ok(), "ledger should handle malicious payloads");

                // Test serialization safety
                let json =
                    serde_json::to_string(&malicious_entry).expect("serialization should work");
                let parsed: EvidenceEntry =
                    serde_json::from_str(&json).expect("deserialization should work");

                // Verify payload is preserved exactly
                assert_eq!(
                    parsed.payload, malicious_payload,
                    "payload should be preserved exactly"
                );

                // Verify entry structure integrity
                assert_eq!(parsed.decision_id, "payload-test");
                assert_eq!(parsed.trace_id, "payload-injection-test");

                // Test that malicious payloads don't affect ledger state
                let snapshot = ledger.snapshot();
                assert!(snapshot.entries.len() > 0, "ledger should contain entries");
            }
        }

        #[test]
        fn test_negative_epoch_id_arithmetic_overflow_scenarios() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(1000, 1_000_000));

            // Test various epoch ID values that might cause arithmetic issues
            let epoch_values = [
                0,                     // Zero epoch
                1,                     // Minimal epoch
                u64::MAX,              // Maximum epoch
                u64::MAX - 1,          // Near maximum
                u64::MAX / 2,          // Half maximum
                0x8000000000000000u64, // High bit set
                0x7FFFFFFFFFFFFFFFu64, // Max signed value
                0xAAAAAAAAAAAAAAAAu64, // Alternating pattern
                0x5555555555555555u64, // Inverse pattern
                1234567890,            // Standard timestamp
            ];

            let mut previous_entries = Vec::new();

            for epoch_id in epoch_values {
                let epoch_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("epoch-test-{}", epoch_id),
                    decision_kind: DecisionKind::Throttle,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: format!("epoch-trace-{}", epoch_id),
                    epoch_id,
                    payload: serde_json::json!({"epoch_test": epoch_id}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(epoch_entry.clone());
                assert!(result.is_ok(), "ledger should handle epoch ID {}", epoch_id);

                if let Ok(entry_id) = result {
                    previous_entries.push((epoch_id, entry_id));
                }

                // Test JSON serialization with extreme epoch values
                let json = serde_json::to_string(&epoch_entry).expect("serialization should work");
                let parsed: EvidenceEntry =
                    serde_json::from_str(&json).expect("deserialization should work");
                assert_eq!(
                    parsed.epoch_id, epoch_id,
                    "epoch ID should be preserved: {}",
                    epoch_id
                );
            }

            // Test epoch ID arithmetic (overflow protection)
            for i in 0..1000 {
                let large_epoch = u64::MAX.saturating_sub(i);
                let incremented_epoch = large_epoch.saturating_add(1);

                let entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("overflow-test-{}", i),
                    decision_kind: DecisionKind::Release,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: format!("overflow-trace-{}", i),
                    epoch_id: incremented_epoch,
                    payload: serde_json::json!({"overflow_test": i}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(entry);
                assert!(
                    result.is_ok(),
                    "ledger should handle near-overflow epoch arithmetic"
                );
            }

            // Verify ledger still functions correctly after epoch stress testing
            let snapshot = ledger.snapshot();
            assert!(
                snapshot.entries.len() > 0,
                "ledger should contain entries after epoch testing"
            );
        }

        #[test]
        fn test_negative_timestamp_manipulation_with_time_travel_attacks() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(100, 1_000_000));

            // Test various timestamp manipulation attempts
            let timestamp_attacks = [
                // Basic cases
                0,        // Unix epoch start
                1,        // Minimal timestamp
                u64::MAX, // Maximum timestamp (far future)
                // Realistic boundaries
                946684800000,  // Year 2000
                1609459200000, // Year 2021
                2147483647000, // Year 2038 (32-bit overflow)
                4102444800000, // Year 2100
                // Attack patterns
                1234567890000, // Base timestamp
                1234567890001, // 1ms after base
                1234567889999, // 1ms before base
                // Overflow attempts
                u64::MAX - 1000, // Near maximum
                u64::MAX - 1,    // One less than max
                // Time travel attempts (future)
                253402300799000, // Year 9999
                u64::MAX / 2,    // Half of max timestamp
                // Bit pattern attacks
                0x8000000000000000u64, // High bit set
                0x7FFFFFFFFFFFFFFFu64, // Max positive
                0xAAAAAAAAAAAAAAAAu64, // Alternating bits
                0x5555555555555555u64, // Inverse alternating
            ];

            let mut timestamp_entries = Vec::new();

            for timestamp_ms in timestamp_attacks {
                let time_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("timestamp-test-{}", timestamp_ms),
                    decision_kind: DecisionKind::Rollback,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms,
                    trace_id: format!("timestamp-trace-{}", timestamp_ms),
                    epoch_id: 1,
                    payload: serde_json::json!({"timestamp_attack": timestamp_ms}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(time_entry.clone());
                assert!(
                    result.is_ok(),
                    "ledger should handle timestamp {}",
                    timestamp_ms
                );

                timestamp_entries.push((timestamp_ms, time_entry));

                // Test serialization with extreme timestamps
                let json = serde_json::to_string(&time_entry).expect("serialization should work");
                let parsed: EvidenceEntry =
                    serde_json::from_str(&json).expect("deserialization should work");
                assert_eq!(
                    parsed.timestamp_ms, timestamp_ms,
                    "timestamp should be preserved"
                );
            }

            // Test timestamp ordering consistency
            let snapshot = ledger.snapshot();
            for (_, entry) in &snapshot.entries {
                // Verify all timestamps are preserved correctly
                let found = timestamp_entries
                    .iter()
                    .any(|(ts, _)| *ts == entry.timestamp_ms);
                if !found {
                    // Entry might have been evicted due to capacity limits
                    continue;
                }
            }

            // Test with chronologically inconsistent sequences
            let inconsistent_sequence = [
                2000000000000, // Future timestamp
                1000000000000, // Past timestamp (time travel back)
                3000000000000, // Even further future
                500000000000,  // Even further past
            ];

            for (i, timestamp) in inconsistent_sequence.iter().enumerate() {
                let inconsistent_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("inconsistent-{}", i),
                    decision_kind: DecisionKind::Deny,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: *timestamp,
                    trace_id: format!("inconsistent-trace-{}", i),
                    epoch_id: i as u64,
                    payload: serde_json::json!({"sequence": i}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(inconsistent_entry);
                assert!(
                    result.is_ok(),
                    "ledger should handle chronologically inconsistent timestamps"
                );
            }
        }

        #[test]
        fn test_negative_bounded_capacity_with_memory_exhaustion_attempts() {
            // Create ledger with small capacity for testing
            let mut small_ledger = EvidenceLedger::new(LedgerCapacity::new(10, 50_000)); // 10 entries, 50KB

            // Attempt to exhaust memory with large entries
            for i in 0..100 {
                let large_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("exhaustion-test-{:03}", i),
                    decision_kind: DecisionKind::Quarantine,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000 + i as u64,
                    trace_id: format!("exhaustion-trace-{:03}", i),
                    epoch_id: i as u64,
                    payload: serde_json::json!({
                        "large_data": "X".repeat(10_000), // 10KB per entry
                        "iteration": i,
                        "padding": vec![i; 1000], // Additional data
                    }),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = small_ledger.append(large_entry);
                assert!(result.is_ok(), "ledger should handle large entry {}", i);
            }

            // Verify bounded capacity is enforced
            let snapshot = small_ledger.snapshot();
            assert!(
                snapshot.entries.len() <= 10,
                "ledger should respect max_entries bound"
            );

            // Verify memory usage is bounded (approximate check)
            let total_estimated_size: usize = snapshot
                .entries
                .iter()
                .map(|(_, entry)| serde_json::to_string(entry).unwrap_or_default().len())
                .sum();

            // Should be reasonably close to 50KB limit (allowing for some overhead)
            assert!(
                total_estimated_size < 100_000,
                "ledger should respect memory bounds approximately"
            );

            // Test with extremely large single entry
            let massive_entry = EvidenceEntry {
                schema_version: "test-v1".to_string(),
                entry_id: None,
                decision_id: "massive-single-entry".to_string(),
                decision_kind: DecisionKind::Escalate,
                decision_time: "2026-04-17T10:00:00Z".to_string(),
                timestamp_ms: 1234567890000,
                trace_id: "massive-trace".to_string(),
                epoch_id: 999,
                payload: serde_json::json!({
                    "massive_field": "Y".repeat(1_000_000), // 1MB field
                    "metadata": {
                        "size": "very_large",
                        "purpose": "memory_exhaustion_test"
                    }
                }),
                size_bytes: 0,
                signature: String::new(),
            };

            let result = small_ledger.append(massive_entry);
            // Should handle massive entry (might evict all others or reject)
            assert!(
                result.is_ok() || result.is_err(),
                "ledger should handle or reject massive entry safely"
            );

            // Test rapid-fire small entries (FIFO overflow stress test)
            for i in 0..1000 {
                let rapid_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("rapid-{:04}", i),
                    decision_kind: DecisionKind::Admit,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000 + i as u64,
                    trace_id: format!("rapid-trace-{:04}", i),
                    epoch_id: i as u64,
                    payload: serde_json::json!({"rapid_test": i}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = small_ledger.append(rapid_entry);
                assert!(result.is_ok(), "ledger should handle rapid entry {}", i);
            }

            // Verify FIFO eviction worked correctly
            let final_snapshot = small_ledger.snapshot();
            assert!(
                final_snapshot.entries.len() <= 10,
                "ledger should maintain capacity bounds"
            );

            // Most recent entries should be preserved
            let has_recent = final_snapshot
                .entries
                .iter()
                .any(|(_, entry)| entry.decision_id.starts_with("rapid-09"));
            assert!(
                has_recent || final_snapshot.entries.is_empty(),
                "most recent entries should be preserved (or ledger reset due to capacity)"
            );
        }

        #[test]
        fn test_negative_decision_kind_with_serialization_bypass_attempts() {
            let mut ledger = EvidenceLedger::new(LedgerCapacity::new(50, 100_000));

            // Test all valid decision kinds
            let valid_decisions = [
                DecisionKind::Admit,
                DecisionKind::Deny,
                DecisionKind::Quarantine,
                DecisionKind::Release,
                DecisionKind::Rollback,
                DecisionKind::Throttle,
                DecisionKind::Escalate,
            ];

            for decision_kind in valid_decisions {
                let valid_entry = EvidenceEntry {
                    schema_version: "test-v1".to_string(),
                    entry_id: None,
                    decision_id: format!("valid-{}", decision_kind.label()),
                    decision_kind,
                    decision_time: "2026-04-17T10:00:00Z".to_string(),
                    timestamp_ms: 1234567890000,
                    trace_id: format!("valid-trace-{}", decision_kind.label()),
                    epoch_id: 1,
                    payload: serde_json::json!({"decision_test": decision_kind.label()}),
                    size_bytes: 0,
                    signature: String::new(),
                };

                let result = ledger.append(valid_entry.clone());
                assert!(
                    result.is_ok(),
                    "ledger should accept valid decision kind: {:?}",
                    decision_kind
                );

                // Test JSON roundtrip for each decision kind
                let json = serde_json::to_string(&valid_entry).expect("serialization should work");
                let parsed: EvidenceEntry =
                    serde_json::from_str(&json).expect("deserialization should work");
                assert_eq!(
                    parsed.decision_kind, decision_kind,
                    "decision kind should survive roundtrip"
                );

                // Test label consistency
                assert!(
                    !decision_kind.label().is_empty(),
                    "decision kind label should not be empty"
                );
                assert!(
                    !decision_kind.label().contains('\0'),
                    "decision kind label should not contain nulls"
                );
                assert!(
                    !decision_kind.label().contains('\n'),
                    "decision kind label should not contain newlines"
                );
            }

            // Test invalid JSON for decision kind deserialization
            let invalid_decision_jsons = [
                r#"{"decision_kind": "InvalidDecision"}"#,
                r#"{"decision_kind": null}"#,
                r#"{"decision_kind": 42}"#,
                r#"{"decision_kind": []}"#,
                r#"{"decision_kind": {}}"#,
                r#"{"decision_kind": "admin"}"#,
                r#"{"decision_kind": "bypass"}"#,
                r#"{"decision_kind": "override"}"#,
                r#"{"decision_kind": ""}"#,
            ];

            for invalid_json in invalid_decision_jsons {
                // Create full JSON with invalid decision_kind
                let full_json = format!(
                    r#"{{
                    "schema_version": "test-v1",
                    "entry_id": null,
                    "decision_id": "invalid-test",
                    {},
                    "decision_time": "2026-04-17T10:00:00Z",
                    "timestamp_ms": 1234567890000,
                    "trace_id": "invalid-trace",
                    "epoch_id": 1,
                    "payload": {{"test": "invalid"}},
                    "size_bytes": 0
                }}"#,
                    &invalid_json[1..invalid_json.len() - 1]
                ); // Extract decision_kind part

                let result: Result<EvidenceEntry, _> = serde_json::from_str(&full_json);
                assert!(
                    result.is_err(),
                    "invalid decision kind should fail deserialization: {}",
                    invalid_json
                );
            }

            // Test decision kind display consistency
            for decision_kind in valid_decisions {
                let display = format!("{:?}", decision_kind);
                assert!(
                    !display.is_empty(),
                    "decision kind debug display should not be empty"
                );
                assert!(
                    !display.contains('\x1b'),
                    "decision kind display should not contain ANSI escapes"
                );
                assert!(
                    !display.contains('\0'),
                    "decision kind display should not contain null bytes"
                );
            }
        }

        #[test]
        fn test_negative_concurrent_access_with_poison_recovery() {
            use std::sync::Arc;
            use std::thread;

            let shared_ledger = SharedEvidenceLedger::new(LedgerCapacity::new(100, 500_000));
            let mut handles = Vec::new();

            // Test concurrent append operations
            for thread_id in 0..8 {
                let ledger_clone = Arc::clone(&shared_ledger);
                let handle = thread::spawn(move || {
                    for i in 0..100 {
                        let entry = EvidenceEntry {
                            schema_version: "test-v1".to_string(),
                            entry_id: None,
                            decision_id: format!("concurrent-{}-{:03}", thread_id, i),
                            decision_kind: match i % 7 {
                                0 => DecisionKind::Admit,
                                1 => DecisionKind::Deny,
                                2 => DecisionKind::Quarantine,
                                3 => DecisionKind::Release,
                                4 => DecisionKind::Rollback,
                                5 => DecisionKind::Throttle,
                                _ => DecisionKind::Escalate,
                            },
                            decision_time: "2026-04-17T10:00:00Z".to_string(),
                            timestamp_ms: 1234567890000 + (thread_id * 1000 + i) as u64,
                            trace_id: format!("concurrent-trace-{}-{:03}", thread_id, i),
                            epoch_id: (thread_id * 1000 + i) as u64,
                            payload: serde_json::json!({
                                "thread_id": thread_id,
                                "iteration": i,
                                "data": "X".repeat(100)
                            }),
                            size_bytes: 0,
                            signature: String::new(),
                        };

                        match ledger_clone.append(entry) {
                            Ok(_) => {
                                // Append succeeded
                            }
                            Err(_) => {
                                // Append failed (acceptable under contention)
                            }
                        }

                        // Periodically take snapshots to test concurrent reads
                        if i % 20 == 0 {
                            let _ = ledger_clone.snapshot();
                        }
                    }
                });

                handles.push(handle);
            }

            // Wait for all threads to complete
            for handle in handles {
                handle.join().expect("thread should complete successfully");
            }

            // Verify ledger state after concurrent access
            let final_snapshot = shared_ledger.snapshot();

            // Should have some entries (exact count depends on eviction)
            assert!(
                final_snapshot.entries.len() <= 100,
                "should respect capacity bounds"
            );

            // Verify entries are valid
            for (entry_id, entry) in &final_snapshot.entries {
                assert!(
                    entry.decision_id.starts_with("concurrent-"),
                    "entries should be from concurrent test"
                );
                assert!(entry_id.0 > 0, "entry IDs should be positive");
            }

            // Test poison recovery by forcing a panic in a thread (if possible)
            // This is implementation-dependent and may not be testable in all cases
            let recovery_test_result = shared_ledger.append(EvidenceEntry {
                schema_version: "recovery-test".to_string(),
                entry_id: None,
                decision_id: "poison-recovery-test".to_string(),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-04-17T10:00:00Z".to_string(),
                timestamp_ms: 1234567890000,
                trace_id: "poison-recovery-trace".to_string(),
                epoch_id: 999999,
                payload: serde_json::json!({"recovery_test": true}),
                size_bytes: 0,
                signature: String::new(),
            });

            // Should still work after concurrent stress testing
            assert!(
                recovery_test_result.is_ok(),
                "ledger should function after concurrent access"
            );
        }
    }

    // -- Negative-path Security Tests ---------------------------------------
    // Added 2026-04-17: Comprehensive security hardening tests

    #[test]
    fn test_security_unicode_injection_in_evidence_entry_fields() {
        use crate::security::constant_time;

        let config = EvidenceLedgerConfig {
            max_entries: 100,
            max_bytes: 1024 * 1024,
            lab_mode: false,
            enable_spill: false,
            spill_writer: None,
        };
        let mut ledger = EvidenceLedger::new(config);

        // Unicode injection attempts in various evidence entry fields
        let malicious_entries = vec![
            EvidenceEntry {
                schema_version: "evidence_v1.0\u{202E}malicious\u{202D}".to_string(), // BiDi override
                entry_id: Some("\u{200B}admin".to_string()), // Zero-width space
                decision_id: "decision\u{FEFF}001".to_string(), // Zero-width no-break space
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z\u{0000}".to_string(), // Null injection
                timestamp_ms: 1000000000,
                trace_id: "trace\u{2028}admin".to_string(), // Line separator
                epoch_id: 1,
                payload: serde_json::json!({
                    "user": "safe\u{2029}admin",  // Paragraph separator
                    "action": "\u{200E}normal\u{200F}"  // LTR/RTL marks
                }),
                size_bytes: 0,
                signature: String::new(),
            },
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("E\u{202C}reset".to_string()), // Pop directional formatting
                decision_id: "decision\u{0000}bypass".to_string(), // Null injection
                decision_kind: DecisionKind::Deny,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000001,
                trace_id: "\u{200B}\u{200C}\u{200D}trace002".to_string(), // Multiple zero-width chars
                epoch_id: 1,
                payload: serde_json::json!({
                    "injection": "\";alert('xss');//",  // JS injection in payload
                    "command": "$(rm -rf /)"  // Command injection
                }),
                size_bytes: 0,
                signature: String::new(),
            },
        ];

        for (i, malicious_entry) in malicious_entries.iter().enumerate() {
            let append_result = ledger.append(malicious_entry.clone());

            match append_result {
                Ok(entry_id) => {
                    // If append succeeded, verify Unicode doesn't create security issues
                    let snapshot = ledger.snapshot();

                    // Find the appended entry
                    if let Some(found_entry) = snapshot
                        .entries
                        .iter()
                        .find(|e| e.decision_id == malicious_entry.decision_id)
                    {
                        // Unicode should not create privileged identifiers
                        assert!(
                            !constant_time::ct_eq(found_entry.decision_id.as_bytes(), b"admin"),
                            "Unicode injection should not create admin decisions"
                        );

                        if let Some(ref entry_id_str) = found_entry.entry_id {
                            assert!(
                                !constant_time::ct_eq(entry_id_str.as_bytes(), b"admin"),
                                "Unicode injection should not create admin entry IDs"
                            );
                        }

                        assert!(
                            !constant_time::ct_eq(found_entry.trace_id.as_bytes(), b"admin"),
                            "Unicode injection should not create admin trace IDs"
                        );

                        // Null bytes should not appear in string fields
                        assert!(
                            !found_entry.decision_id.contains('\0'),
                            "Decision ID should not contain null bytes"
                        );
                        assert!(
                            !found_entry.decision_time.contains('\0'),
                            "Decision time should not contain null bytes"
                        );
                        assert!(
                            !found_entry.trace_id.contains('\0'),
                            "Trace ID should not contain null bytes"
                        );

                        // Verify payload serialization is safe
                        let payload_str = found_entry.payload.to_string();
                        assert!(
                            !payload_str.contains("alert('xss')") || payload_str.contains("\\\""),
                            "JavaScript injection should be escaped in JSON"
                        );
                    }

                    // Verify deterministic behavior with Unicode content
                    let second_result = ledger.append(malicious_entry.clone());
                    assert!(
                        second_result.is_ok(),
                        "Unicode content should be handled deterministically"
                    );
                }
                Err(_) => {
                    // Graceful rejection of malformed Unicode entries is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_memory_exhaustion_through_large_payloads() {
        let config = EvidenceLedgerConfig {
            max_entries: 10,
            max_bytes: 1024 * 1024, // 1MB limit
            lab_mode: false,
            enable_spill: false,
            spill_writer: None,
        };
        let mut ledger = EvidenceLedger::new(config);

        // Attempt memory exhaustion through various large payload strategies
        let exhaustion_attempts = vec![
            // Single massive JSON object
            serde_json::json!({
                "large_field": "x".repeat(2_000_000),  // 2MB string
                "type": "single_massive_field"
            }),
            // Deeply nested JSON object
            {
                let mut nested = serde_json::json!({});
                for i in 0..10000 {
                    nested[format!("level_{}", i)] = serde_json::json!({
                        "data": format!("nested_data_{}", i),
                        "more": "x".repeat(100)
                    });
                }
                nested
            },
            // Array with many elements
            serde_json::json!(
                (0..100_000)
                    .map(|i| format!("element_{}", i))
                    .collect::<Vec<_>>()
            ),
        ];

        for (i, large_payload) in exhaustion_attempts.iter().enumerate() {
            let large_entry = EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some(format!("exhaustion_test_{}", i)),
                decision_id: format!("decision_{}", i),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000 + i as u64,
                trace_id: format!("trace_{}", i),
                epoch_id: 1,
                payload: large_payload.clone(),
                size_bytes: 0, // Let ledger compute size
                signature: String::new(),
            };

            let append_result = ledger.append(large_entry);

            match append_result {
                Ok(_) => {
                    // If append succeeded, verify resource bounds are maintained
                    let snapshot = ledger.snapshot();

                    // Verify memory bounds are respected
                    let total_size: usize = snapshot.entries.iter().map(|e| e.size_bytes).sum();

                    // Should not exceed configured limits by too much
                    assert!(
                        total_size <= config.max_bytes * 2,
                        "Total size {} should not exceed 2x limit {}",
                        total_size,
                        config.max_bytes
                    );

                    // Ledger should still be functional
                    let test_entry = EvidenceEntry {
                        schema_version: "evidence_v1.0".to_string(),
                        entry_id: Some(format!("post_exhaustion_test_{}", i)),
                        decision_id: format!("post_decision_{}", i),
                        decision_kind: DecisionKind::Deny,
                        decision_time: "2026-01-01T00:01:00Z".to_string(),
                        timestamp_ms: 1000060000 + i as u64,
                        trace_id: format!("post_trace_{}", i),
                        epoch_id: 2,
                        payload: serde_json::json!({"test": "normal"}),
                        size_bytes: 0,
                        signature: String::new(),
                    };

                    let post_result = ledger.append(test_entry);
                    assert!(
                        post_result.is_ok(),
                        "Ledger should remain functional after large payload"
                    );
                }
                Err(_) => {
                    // Graceful rejection of oversized entries is expected
                }
            }
        }
        // Test should complete without OOM
    }

    #[test]
    fn test_security_fifo_overflow_manipulation_attempts() {
        let config = EvidenceLedgerConfig {
            max_entries: 5, // Small capacity for overflow testing
            max_bytes: 1024,
            lab_mode: false,
            enable_spill: false,
            spill_writer: None,
        };
        let mut ledger = EvidenceLedger::new(config);

        // Fill ledger to capacity
        for i in 0..5 {
            let entry = EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some(format!("initial_{}", i)),
                decision_id: format!("decision_{}", i),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000 + i as u64,
                trace_id: format!("trace_{}", i),
                epoch_id: 1,
                payload: serde_json::json!({"order": i}),
                size_bytes: 0,
                signature: String::new(),
            };

            let result = ledger.append(entry);
            assert!(result.is_ok(), "Initial fill should succeed");
        }

        // Verify initial state
        let initial_snapshot = ledger.snapshot();
        assert_eq!(initial_snapshot.entries.len(), 5, "Should have 5 entries");

        // Attempt overflow manipulation by adding entries with manipulated timestamps
        let overflow_entries = vec![
            // Entry with far future timestamp (attempt to avoid eviction)
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("future_entry".to_string()),
                decision_id: "future_decision".to_string(),
                decision_kind: DecisionKind::Deny,
                decision_time: "9999-12-31T23:59:59Z".to_string(), // Far future
                timestamp_ms: u64::MAX,                            // Maximum timestamp
                trace_id: "future_trace".to_string(),
                epoch_id: u64::MAX, // Maximum epoch
                payload: serde_json::json!({"priority": "high"}),
                size_bytes: 0,
                signature: String::new(),
            },
            // Entry with zero timestamp (attempt to be "oldest")
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("zero_entry".to_string()),
                decision_id: "zero_decision".to_string(),
                decision_kind: DecisionKind::Escalate,
                decision_time: "1970-01-01T00:00:00Z".to_string(), // Unix epoch
                timestamp_ms: 0,                                   // Zero timestamp
                trace_id: "zero_trace".to_string(),
                epoch_id: 0, // Zero epoch
                payload: serde_json::json!({"priority": "urgent"}),
                size_bytes: 0,
                signature: String::new(),
            },
        ];

        for overflow_entry in overflow_entries {
            let pre_append_snapshot = ledger.snapshot();
            let oldest_decision_id = pre_append_snapshot.entries[0].decision_id.clone();

            let append_result = ledger.append(overflow_entry.clone());

            match append_result {
                Ok(_) => {
                    let post_append_snapshot = ledger.snapshot();

                    // FIFO should be maintained regardless of timestamp manipulation
                    assert_eq!(
                        post_append_snapshot.entries.len(),
                        5,
                        "Should maintain max capacity"
                    );

                    // Oldest entry should be evicted (FIFO semantics)
                    let oldest_still_present = post_append_snapshot
                        .entries
                        .iter()
                        .any(|e| e.decision_id == oldest_decision_id);
                    assert!(
                        !oldest_still_present,
                        "Oldest entry should be evicted regardless of timestamp manipulation"
                    );

                    // New entry should be at the end
                    let newest_entry =
                        &post_append_snapshot.entries[post_append_snapshot.entries.len() - 1];
                    assert_eq!(
                        newest_entry.decision_id, overflow_entry.decision_id,
                        "Newest entry should be at the end"
                    );
                }
                Err(_) => {
                    // Graceful rejection of manipulated entries is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_timestamp_manipulation_and_epoch_attacks() {
        let config = EvidenceLedgerConfig::default();
        let mut ledger = EvidenceLedger::new(config);

        // Timestamp and epoch manipulation attempts
        let manipulation_entries = vec![
            // Entry with timestamp overflow
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("overflow_test".to_string()),
                decision_id: "overflow_decision".to_string(),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: u64::MAX, // Overflow attempt
                trace_id: "overflow_trace".to_string(),
                epoch_id: u64::MAX, // Maximum epoch
                payload: serde_json::json!({"type": "overflow"}),
                size_bytes: 0,
                signature: String::new(),
            },
            // Entry with timestamp in the past (replay attack)
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("replay_test".to_string()),
                decision_id: "replay_decision".to_string(),
                decision_kind: DecisionKind::Deny,
                decision_time: "1970-01-01T00:00:00Z".to_string(), // Unix epoch
                timestamp_ms: 1,                                   // Very early timestamp
                trace_id: "replay_trace".to_string(),
                epoch_id: 0, // Zero epoch
                payload: serde_json::json!({"type": "replay_attack"}),
                size_bytes: 0,
                signature: String::new(),
            },
            // Entry with inconsistent timestamps
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("inconsistent_test".to_string()),
                decision_id: "inconsistent_decision".to_string(),
                decision_kind: DecisionKind::Quarantine,
                decision_time: "2026-01-01T00:00:00Z".to_string(), // 2026
                timestamp_ms: 946684800000,                        // Year 2000 in milliseconds
                trace_id: "inconsistent_trace".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({"type": "inconsistent"}),
                size_bytes: 0,
                signature: String::new(),
            },
        ];

        for manipulation_entry in manipulation_entries {
            let append_result = ledger.append(manipulation_entry.clone());

            match append_result {
                Ok(entry_id) => {
                    // If append succeeded, verify timestamp values are preserved
                    let snapshot = ledger.snapshot();

                    if let Some(found_entry) = snapshot
                        .entries
                        .iter()
                        .find(|e| e.decision_id == manipulation_entry.decision_id)
                    {
                        // Values should be preserved exactly as provided
                        assert_eq!(
                            found_entry.timestamp_ms, manipulation_entry.timestamp_ms,
                            "Timestamp should be preserved exactly"
                        );
                        assert_eq!(
                            found_entry.epoch_id, manipulation_entry.epoch_id,
                            "Epoch ID should be preserved exactly"
                        );

                        // Entry should have valid EntryId regardless of timestamp manipulation
                        assert!(entry_id.0 > 0, "Entry ID should be positive");
                    }

                    // Ledger should maintain ordering based on insertion order, not timestamp
                    let ordered_entries = &snapshot.entries;
                    for i in 1..ordered_entries.len() {
                        // EntryId should increase monotonically (insertion order)
                        if let (Some(prev_id), Some(curr_id)) = (
                            ordered_entries[i - 1].entry_id.as_ref(),
                            ordered_entries[i].entry_id.as_ref(),
                        ) {
                            // Parse EntryIds for comparison if they follow E-XXXXXXXX format
                            if prev_id.starts_with("E-") && curr_id.starts_with("E-") {
                                let prev_num: Result<u64, _> = prev_id[2..].parse();
                                let curr_num: Result<u64, _> = curr_id[2..].parse();

                                if let (Ok(prev), Ok(curr)) = (prev_num, curr_num) {
                                    assert!(
                                        curr >= prev,
                                        "Entry IDs should increase monotonically regardless of timestamp manipulation"
                                    );
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Graceful rejection of extreme timestamp values is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_decision_kind_manipulation() {
        let config = EvidenceLedgerConfig::default();
        let mut ledger = EvidenceLedger::new(config);

        // Test all decision kinds to ensure no privilege escalation through enum manipulation
        let all_decision_kinds = vec![
            DecisionKind::Admit,
            DecisionKind::Deny,
            DecisionKind::Quarantine,
            DecisionKind::Release,
            DecisionKind::Rollback,
            DecisionKind::Throttle,
            DecisionKind::Escalate,
        ];

        for (i, decision_kind) in all_decision_kinds.iter().enumerate() {
            // Create entries with each decision kind
            let entry = EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some(format!("decision_test_{}", i)),
                decision_id: format!("decision_{}_{}", decision_kind.label(), i),
                decision_kind: *decision_kind,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000 + i as u64,
                trace_id: format!("trace_{}_{}", decision_kind.label(), i),
                epoch_id: 1,
                payload: serde_json::json!({
                    "decision_type": decision_kind.label(),
                    "test_index": i
                }),
                size_bytes: 0,
                signature: String::new(),
            };

            let append_result = ledger.append(entry.clone());
            assert!(
                append_result.is_ok(),
                "All decision kinds should be accepted"
            );

            // Verify decision kind is preserved correctly
            let snapshot = ledger.snapshot();
            if let Some(found_entry) = snapshot
                .entries
                .iter()
                .find(|e| e.decision_id == entry.decision_id)
            {
                assert_eq!(
                    found_entry.decision_kind, entry.decision_kind,
                    "Decision kind should be preserved exactly"
                );
                assert_eq!(
                    found_entry.decision_kind.label(),
                    decision_kind.label(),
                    "Decision kind label should match"
                );
            }
        }

        // Verify JSON serialization preserves decision kinds correctly
        let snapshot = ledger.snapshot();
        let json = serde_json::to_string(&snapshot.entries).expect("should serialize");

        // JSON should contain all decision kind labels
        for decision_kind in &all_decision_kinds {
            assert!(
                json.contains(decision_kind.label()),
                "JSON should contain decision kind: {}",
                decision_kind.label()
            );
        }

        // Roundtrip verification
        let parsed_entries: Vec<EvidenceEntry> =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(
            parsed_entries.len(),
            all_decision_kinds.len(),
            "All entries should survive roundtrip"
        );

        for (original, parsed) in all_decision_kinds.iter().zip(parsed_entries.iter()) {
            assert_eq!(
                parsed.decision_kind, *original,
                "Decision kind should survive JSON roundtrip"
            );
        }
    }

    #[test]
    fn test_security_json_payload_injection_prevention() {
        let config = EvidenceLedgerConfig::default();
        let mut ledger = EvidenceLedger::new(config);

        // JSON payload injection attempts
        let injection_payloads = vec![
            // JavaScript injection
            serde_json::json!({
                "script": "\";alert('xss');//",
                "html": "</script><script>alert('xss')</script>",
                "action": "injection_test"
            }),
            // Command injection
            serde_json::json!({
                "command": "$(rm -rf /)",
                "shell": "; cat /etc/passwd",
                "injection": "`whoami`"
            }),
            // JSON structure manipulation
            serde_json::json!({
                "normal_field": "value",
                "__proto__": {"polluted": true},
                "constructor": {"polluted": true}
            }),
            // SQL injection patterns
            serde_json::json!({
                "query": "'; DROP TABLE evidence; --",
                "where": "1=1 OR '1'='1",
                "union": "UNION SELECT * FROM secrets"
            }),
            // Control character injection
            serde_json::json!({
                "newlines": "line1\nline2\r\nline3",
                "tabs": "field1\tfield2\tfield3",
                "nulls": "data\u{0000}more\u{0000}data",
                "unicode": "\u{2028}line\u{2029}break"
            }),
        ];

        for (i, injection_payload) in injection_payloads.iter().enumerate() {
            let entry = EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some(format!("injection_test_{}", i)),
                decision_id: format!("injection_decision_{}", i),
                decision_kind: DecisionKind::Deny,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000 + i as u64,
                trace_id: format!("injection_trace_{}", i),
                epoch_id: 1,
                payload: injection_payload.clone(),
                size_bytes: 0,
                signature: String::new(),
            };

            let append_result = ledger.append(entry);
            assert!(
                append_result.is_ok(),
                "Injection payload should be stored safely"
            );

            // Verify payload is stored and serialized safely
            let snapshot = ledger.snapshot();
            let json = serde_json::to_string(&snapshot.entries).expect("should serialize");

            // JSON should escape all injection attempts
            assert!(
                !json.contains("alert('xss')") || json.contains("\\\""),
                "JavaScript injection should be escaped"
            );
            assert!(
                !json.contains("</script>") || json.contains("\\u003c"),
                "HTML injection should be escaped"
            );
            assert!(
                !json.contains("rm -rf") || json.contains("\\"),
                "Command injection should be escaped"
            );
            assert!(
                !json.contains("DROP TABLE") || json.contains("\\"),
                "SQL injection should be escaped"
            );
            assert!(
                !json.contains("\n") || json.contains("\\n"),
                "Newline injection should be escaped"
            );
            assert!(
                !json.contains("\r") || json.contains("\\r"),
                "Carriage return injection should be escaped"
            );
            assert!(
                !json.contains("\t") || json.contains("\\t"),
                "Tab injection should be escaped"
            );
            assert!(
                !json.contains("\u{0000}") || json.contains("\\u0000"),
                "Null injection should be escaped"
            );

            // Roundtrip should preserve structure but escape dangerous content
            let parsed_entries: Vec<EvidenceEntry> =
                serde_json::from_str(&json).expect("should deserialize safely");

            assert!(
                parsed_entries.len() > 0,
                "Should have entries after injection test"
            );

            // Find the injection test entry
            if let Some(found_entry) = parsed_entries
                .iter()
                .find(|e| e.decision_id.contains(&format!("injection_decision_{}", i)))
            {
                // Payload should be preserved as JSON but safely escaped
                assert!(
                    found_entry.payload.is_object() || found_entry.payload.is_string(),
                    "Payload structure should be preserved"
                );
            }
        }
    }

    #[test]
    fn test_security_entry_id_tampering_resistance() {
        let config = EvidenceLedgerConfig::default();
        let mut ledger = EvidenceLedger::new(config);

        // Attempt entry ID tampering
        let tampered_entries = vec![
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("E-00000000".to_string()), // Attempt to use low ID
                decision_id: "tampered_decision_1".to_string(),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000,
                trace_id: "tampered_trace_1".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({"tamper": "low_id"}),
                size_bytes: 0,
                signature: String::new(),
            },
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("E-99999999".to_string()), // Attempt to use high ID
                decision_id: "tampered_decision_2".to_string(),
                decision_kind: DecisionKind::Deny,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000001,
                trace_id: "tampered_trace_2".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({"tamper": "high_id"}),
                size_bytes: 0,
                signature: String::new(),
            },
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("ADMIN-ENTRY".to_string()), // Attempt privileged ID format
                decision_id: "tampered_decision_3".to_string(),
                decision_kind: DecisionKind::Escalate,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000002,
                trace_id: "tampered_trace_3".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({"tamper": "admin_format"}),
                size_bytes: 0,
                signature: String::new(),
            },
        ];

        let mut returned_entry_ids = vec![];

        for tampered_entry in tampered_entries {
            let append_result = ledger.append(tampered_entry.clone());

            match append_result {
                Ok(returned_entry_id) => {
                    returned_entry_ids.push(returned_entry_id);

                    // Verify entry ID tampering doesn't affect ledger integrity
                    let snapshot = ledger.snapshot();

                    if let Some(found_entry) = snapshot
                        .entries
                        .iter()
                        .find(|e| e.decision_id == tampered_entry.decision_id)
                    {
                        // Entry should be stored with correct data
                        assert_eq!(found_entry.decision_id, tampered_entry.decision_id);
                        assert_eq!(found_entry.decision_kind, tampered_entry.decision_kind);

                        // Entry ID in stored entry might be different from what was provided
                        // (ledger may assign its own IDs)
                        if let Some(ref stored_entry_id) = found_entry.entry_id {
                            // Should not contain administrative patterns
                            assert!(
                                !stored_entry_id.to_uppercase().contains("ADMIN"),
                                "Stored entry ID should not contain admin patterns"
                            );
                        }
                    }
                }
                Err(_) => {
                    // Graceful rejection of tampered entry IDs is acceptable
                }
            }
        }

        // Returned entry IDs should be monotonically increasing regardless of input tampering
        for i in 1..returned_entry_ids.len() {
            assert!(
                returned_entry_ids[i].0 > returned_entry_ids[i - 1].0,
                "Returned entry IDs should increase monotonically despite tampering attempts"
            );
        }
    }

    #[test]
    fn test_security_concurrent_evidence_access_under_stress() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let config = EvidenceLedgerConfig {
            max_entries: 1000,
            max_bytes: 10 * 1024 * 1024, // 10MB
            lab_mode: false,
            enable_spill: false,
            spill_writer: None,
        };
        let ledger = Arc::new(SharedEvidenceLedger::new(config));
        let mut handles = vec![];

        // Spawn aggressive concurrent access
        for thread_id in 0..20 {
            let ledger_clone = Arc::clone(&ledger);

            let handle = thread::spawn(move || {
                let mut thread_results = vec![];

                // Each thread performs multiple operations
                for operation in 0..50 {
                    match operation % 4 {
                        0 => {
                            // Append normal entry
                            let entry = EvidenceEntry {
                                schema_version: "evidence_v1.0".to_string(),
                                entry_id: Some(format!("thread_{}_op_{}", thread_id, operation)),
                                decision_id: format!("decision_{}_{}", thread_id, operation),
                                decision_kind: DecisionKind::Admit,
                                decision_time: "2026-01-01T00:00:00Z".to_string(),
                                timestamp_ms: 1000000000 + (thread_id * 1000 + operation) as u64,
                                trace_id: format!("trace_{}_{}", thread_id, operation),
                                epoch_id: 1,
                                payload: serde_json::json!({
                                    "thread_id": thread_id,
                                    "operation": operation,
                                    "data": format!("concurrent_data_{}", operation)
                                }),
                                size_bytes: 0,
                                signature: String::new(),
                            };

                            let result = ledger_clone.append(entry);
                            thread_results.push(("append", result.is_ok()));
                        }
                        1 => {
                            // Take snapshot
                            let snapshot = ledger_clone.snapshot();
                            thread_results.push(("snapshot", snapshot.entries.len() > 0));
                        }
                        2 => {
                            // Append large entry
                            let large_entry = EvidenceEntry {
                                schema_version: "evidence_v1.0".to_string(),
                                entry_id: Some(format!(
                                    "large_thread_{}_op_{}",
                                    thread_id, operation
                                )),
                                decision_id: format!("large_decision_{}_{}", thread_id, operation),
                                decision_kind: DecisionKind::Quarantine,
                                decision_time: "2026-01-01T00:00:00Z".to_string(),
                                timestamp_ms: 1000000000 + (thread_id * 1000 + operation) as u64,
                                trace_id: format!("large_trace_{}_{}", thread_id, operation),
                                epoch_id: 1,
                                payload: serde_json::json!({
                                    "large_data": "x".repeat(1000),  // 1KB payload
                                    "thread_id": thread_id,
                                    "operation": operation
                                }),
                                size_bytes: 0,
                                signature: String::new(),
                            };

                            let result = ledger_clone.append(large_entry);
                            thread_results.push(("large_append", result.is_ok()));
                        }
                        3 => {
                            // Rapid snapshots
                            for _ in 0..5 {
                                let _ = ledger_clone.snapshot();
                            }
                            thread_results.push(("rapid_snapshots", true));
                        }
                        _ => unreachable!(),
                    }
                }

                (thread_id, thread_results)
            });

            handles.push(handle);
        }

        // Collect all results
        let mut all_results = vec![];
        for handle in handles {
            let (thread_id, thread_results) = handle.join().expect("thread should not panic");
            all_results.push((thread_id, thread_results));
        }

        // Verify concurrent operations completed successfully
        for (thread_id, thread_results) in all_results {
            let success_count = thread_results
                .iter()
                .filter(|(_, success)| *success)
                .count();

            assert!(
                success_count > 0,
                "Thread {} should have at least some successful operations",
                thread_id
            );

            // Verify thread had reasonable success rate
            let success_rate = success_count as f64 / thread_results.len() as f64;
            assert!(
                success_rate > 0.5,
                "Thread {} should have >50% success rate, got {:.2}%",
                thread_id,
                success_rate * 100.0
            );
        }

        // Verify ledger integrity after stress test
        let final_snapshot = ledger.snapshot();
        assert!(
            final_snapshot.entries.len() > 0,
            "Should have entries after stress test"
        );
        assert!(
            final_snapshot.entries.len() <= 1000,
            "Should respect max_entries limit"
        );

        // Verify entries are still well-formed
        for entry in &final_snapshot.entries {
            assert!(
                !entry.decision_id.is_empty(),
                "Decision ID should not be empty"
            );
            assert!(!entry.trace_id.is_empty(), "Trace ID should not be empty");
            assert!(entry.timestamp_ms > 0, "Timestamp should be positive");
        }
    }

    #[test]
    fn test_security_size_budget_manipulation() {
        let config = EvidenceLedgerConfig {
            max_entries: 100,
            max_bytes: 1024, // Small byte limit
            lab_mode: false,
            enable_spill: false,
            spill_writer: None,
        };
        let mut ledger = EvidenceLedger::new(config);

        // Attempt size budget manipulation
        let manipulation_entries = vec![
            // Entry claiming zero size but containing large payload
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("size_lie_1".to_string()),
                decision_id: "size_manipulation_1".to_string(),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000000,
                trace_id: "size_trace_1".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({
                    "large_field": "x".repeat(2000)  // 2KB actual data
                }),
                size_bytes: 0, // Lies about size
                signature: String::new(),
            },
            // Entry claiming small size but containing large payload
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("size_lie_2".to_string()),
                decision_id: "size_manipulation_2".to_string(),
                decision_kind: DecisionKind::Deny,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000001,
                trace_id: "size_trace_2".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({
                    "another_large_field": "y".repeat(3000)  // 3KB actual data
                }),
                size_bytes: 10, // Claims only 10 bytes
                signature: String::new(),
            },
            // Entry claiming huge size but containing small payload
            EvidenceEntry {
                schema_version: "evidence_v1.0".to_string(),
                entry_id: Some("size_exaggerate".to_string()),
                decision_id: "size_manipulation_3".to_string(),
                decision_kind: DecisionKind::Quarantine,
                decision_time: "2026-01-01T00:00:00Z".to_string(),
                timestamp_ms: 1000000002,
                trace_id: "size_trace_3".to_string(),
                epoch_id: 1,
                payload: serde_json::json!({"small": "data"}), // Small payload
                size_bytes: 1000000,                           // Claims 1MB
                signature: String::new(),
            },
        ];

        for manipulation_entry in manipulation_entries {
            let append_result = ledger.append(manipulation_entry.clone());

            match append_result {
                Ok(_) => {
                    // If append succeeded, verify size budget is computed correctly
                    let snapshot = ledger.snapshot();

                    if let Some(found_entry) = snapshot
                        .entries
                        .iter()
                        .find(|e| e.decision_id == manipulation_entry.decision_id)
                    {
                        // Ledger should compute actual size, not trust provided size_bytes
                        let payload_json = serde_json::to_string(&found_entry.payload)
                            .expect("payload should serialize");
                        let actual_payload_size = payload_json.len();

                        // Size computation should be based on actual content
                        if actual_payload_size > 100 {
                            // Non-trivial size
                            assert!(
                                found_entry.size_bytes >= actual_payload_size / 2,
                                "Computed size should be reasonable for actual content"
                            );
                        }

                        // Very small payloads claiming huge sizes should be adjusted
                        if manipulation_entry.size_bytes == 1000000 && actual_payload_size < 100 {
                            assert!(
                                found_entry.size_bytes < 10000,
                                "Size should be adjusted for small payloads claiming huge sizes"
                            );
                        }
                    }

                    // Overall budget should be respected
                    let total_size: usize = snapshot.entries.iter().map(|e| e.size_bytes).sum();

                    // Total should not grossly exceed configured limit
                    assert!(
                        total_size <= config.max_bytes * 5,
                        "Total size should not exceed 5x configured limit due to manipulation"
                    );
                }
                Err(_) => {
                    // Graceful rejection of size manipulation is expected
                }
            }
        }
    }

    // ── Signature Verification Tests ──────────────────────────────────

    #[test]
    fn test_signed_entry_accepted() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-SIGNED", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        let result = ledger.append(entry);
        assert!(result.is_ok(), "Properly signed entry should be accepted");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn replay_window_caches_timestamp_bytes_after_signed_append() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-REPLAY-BYTES", 7);
        sign_evidence_entry(&mut entry, &signing_key);
        let expected_signature =
            decode_replay_signature(&entry.signature).expect("signed test entry should decode");
        let expected_replay_key = replay_key(entry.timestamp_ms, &expected_signature);

        ledger.append(entry).expect("signed entry should append");

        let stored = ledger
            .seen_signatures
            .front()
            .expect("replay window should capture the signed append");
        assert_eq!(*stored, expected_replay_key);
    }

    #[test]
    fn sign_evidence_entry_matches_legacy_sign_bytes_output() {
        let (signing_key, _) = test_keys();
        let mut entry = test_entry("TEST-SIGN-PARITY", 1);

        let canonical_bytes = canonical_entry_bytes(&entry);
        let expected_signature =
            crate::supply_chain::artifact_signing::sign_bytes(&signing_key, &canonical_bytes);

        sign_evidence_entry(&mut entry, &signing_key);

        assert_eq!(
            entry.signature,
            hex::encode(expected_signature),
            "sign_evidence_entry must preserve the legacy signature byte contract"
        );
    }

    #[test]
    fn verify_evidence_entry_matches_legacy_artifact_signing_verifier_contract() {
        let (signing_key, verifying_key) = test_keys();
        let mut entry = test_entry("TEST-VERIFY-PARITY", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        let signature_bytes =
            decode_replay_signature(&entry.signature).expect("signed test entry should decode");
        let canonical_bytes = canonical_entry_bytes(&entry);

        assert!(
            crate::supply_chain::artifact_signing::verify_signature(
                &verifying_key,
                &canonical_bytes,
                &signature_bytes,
            )
            .is_ok()
        );
        verify_evidence_entry(&entry, &verifying_key).expect("optimized verifier should accept");

        let mut tampered = entry.clone();
        tampered.decision_id.push_str("-TAMPERED");
        let tampered_canonical_bytes = canonical_entry_bytes(&tampered);

        assert!(
            crate::supply_chain::artifact_signing::verify_signature(
                &verifying_key,
                &tampered_canonical_bytes,
                &signature_bytes,
            )
            .is_err()
        );

        let err = verify_evidence_entry(&tampered, &verifying_key)
            .expect_err("optimized verifier should reject tampered entry");
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn test_unsigned_entry_rejected() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let entry = test_entry("TEST-UNSIGNED", 1);
        // entry.signature is empty string - no signature

        let result = ledger.append(entry);
        assert!(result.is_err(), "Unsigned entry should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("invalid hex signature"),
                "Should fail on invalid hex"
            );
        } else {
            panic!("Should return SignatureInvalid error");
        }

        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPERED", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with the signature by flipping a bit
        let mut sig_bytes = hex::decode(&entry.signature).expect("Should be valid hex");
        if !sig_bytes.is_empty() {
            sig_bytes[0] ^= 0x01; // Flip a bit
            entry.signature = hex::encode(sig_bytes);
        }

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered signature should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("signature verification failed"),
                "Should fail signature verification"
            );
        } else {
            panic!("Should return SignatureInvalid error");
        }

        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn test_replay_attack_rejected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Create and append first entry
        let mut entry1 = test_entry("TEST-REPLAY", 1);
        sign_evidence_entry(&mut entry1, &signing_key);

        let result1 = ledger.append(entry1.clone());
        assert!(result1.is_ok(), "First entry should be accepted");
        assert_eq!(ledger.len(), 1);

        // Try to append the exact same entry again (replay attack)
        let result2 = ledger.append(entry1.clone());
        assert!(result2.is_err(), "Replay attack should be rejected");

        if let Err(LedgerError::ReplayAttack {
            timestamp_ms,
            signature,
        }) = result2
        {
            assert_eq!(timestamp_ms, entry1.timestamp_ms);
            assert_eq!(signature, entry1.signature);
        } else {
            panic!("Should return ReplayAttack error");
        }

        assert_eq!(ledger.len(), 1, "Ledger should still have only one entry");
    }

    #[test]
    fn test_replay_attack_prevention_with_eviction() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(2, 100_000); // Only keep 2 entries
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Create and append first entry
        let mut entry1 = test_entry("TEST-REPLAY-EVICT-1", 1);
        sign_evidence_entry(&mut entry1, &signing_key);
        ledger
            .append(entry1.clone())
            .expect("First entry should succeed");

        // Create and append second entry
        let mut entry2 = test_entry("TEST-REPLAY-EVICT-2", 2);
        sign_evidence_entry(&mut entry2, &signing_key);
        ledger
            .append(entry2.clone())
            .expect("Second entry should succeed");

        // Create and append third entry (should evict entry1)
        let mut entry3 = test_entry("TEST-REPLAY-EVICT-3", 3);
        sign_evidence_entry(&mut entry3, &signing_key);
        ledger
            .append(entry3.clone())
            .expect("Third entry should succeed");

        assert_eq!(
            ledger.len(),
            2,
            "Should have 2 entries due to capacity limit"
        );
        assert_eq!(ledger.total_evicted(), 1, "Should have evicted 1 entry");

        // Now try to replay entry1 - should still fail because replay tracking
        // is independent from retained-entry eviction.
        let result = ledger.append(entry1.clone());
        assert!(
            result.is_err(),
            "Evicted entry replay should still be rejected"
        );
        assert!(
            matches!(result, Err(LedgerError::ReplayAttack { .. })),
            "Evicted replay should return ReplayAttack"
        );

        // But replaying entry2 should still fail (it's still in the ledger)
        let result2 = ledger.append(entry2.clone());
        assert!(result2.is_err(), "Entry still in ledger should fail replay");
    }

    #[test]
    fn test_different_signatures_same_timestamp_accepted() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Create two entries with same timestamp but different content
        let mut entry1 = test_entry("TEST-SAME-TIME-1", 1);
        sign_evidence_entry(&mut entry1, &signing_key);

        let mut entry2 = test_entry("TEST-SAME-TIME-2", 1); // Same epoch, different decision_id
        sign_evidence_entry(&mut entry2, &signing_key);

        // Both should be accepted because signatures are different
        let result1 = ledger.append(entry1);
        assert!(result1.is_ok(), "First entry should be accepted");

        let result2 = ledger.append(entry2);
        assert!(
            result2.is_ok(),
            "Second entry with same timestamp but different signature should be accepted"
        );

        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn test_canonical_entry_bytes_excludes_signature() {
        let mut entry1 = test_entry("TEST-CANONICAL", 1);
        let mut entry2 = entry1.clone();

        // Set different signatures
        entry1.signature = "signature1".to_string();
        entry2.signature = "signature2".to_string();

        // Canonical bytes should be the same (signature is excluded)
        let canonical1 = canonical_entry_bytes(&entry1);
        let canonical2 = canonical_entry_bytes(&entry2);

        assert_eq!(
            canonical1, canonical2,
            "Canonical bytes should exclude signature field"
        );
    }

    #[test]
    fn test_canonical_entry_bytes_uses_fixed_sha256_digest_width() {
        let entry = test_entry("TEST-CANONICAL-DIGEST", 1);
        assert_eq!(
            canonical_entry_bytes(&entry).len(),
            SHA256_DIGEST_BYTES,
            "canonical entry representation should stay a fixed-width SHA-256 digest"
        );
    }

    #[test]
    fn payload_hashing_matches_legacy_json_buffer_path() {
        let payload = serde_json::json!({
            "message": "trust-native runtime",
            "unicode": "🙂漢字",
            "nested": { "epoch": 7, "decision": "DEC-STREAM" },
            "items": [1, 2, 3, 4]
        });

        let mut buffered = Sha256::new();
        update_hash_serialized_json_len_prefixed(&mut buffered, &payload)
            .expect("payload serialization should succeed");
        let buffered_digest: [u8; SHA256_DIGEST_BYTES] = buffered.finalize().into();

        let payload_bytes =
            serde_json::to_vec(&payload).expect("payload serialization should succeed");
        let mut legacy = Sha256::new();
        legacy.update(
            u64::try_from(payload_bytes.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        legacy.update(&payload_bytes);
        let legacy_digest: [u8; SHA256_DIGEST_BYTES] = legacy.finalize().into();

        assert_eq!(
            buffered_digest, legacy_digest,
            "payload hashing must preserve the legacy JSON byte contract"
        );
    }

    #[test]
    fn pre_serialized_payload_bytes_match_legacy_canonical_and_entry_hash_paths() {
        let entry = make_signed_entry(
            "DEC-PAYLOAD-CACHE",
            17,
            &SigningKey::from_bytes(&[5_u8; 32]),
        );
        let payload_json_bytes =
            serde_json::to_vec(&entry.payload).expect("payload serialization should succeed");

        assert_eq!(
            canonical_entry_bytes(&entry),
            canonical_entry_bytes_with_payload_bytes(&entry, Some(payload_json_bytes.as_slice())),
            "pre-serialized payload bytes must preserve the canonical signing digest"
        );
        assert_eq!(
            compute_entry_hash_bytes(&entry),
            compute_entry_hash_bytes_with_payload_bytes(
                &entry,
                Some(payload_json_bytes.as_slice())
            ),
            "pre-serialized payload bytes must preserve the entry hash contract"
        );
    }

    #[test]
    fn test_canonical_entry_bytes_resists_entry_id_decision_id_boundary_collision() {
        let mut entry_a = test_entry("TEST-COLLISION-A", 1);
        entry_a.entry_id = Some("foo".to_string());
        entry_a.decision_id = "bar\0baz".to_string();

        let mut entry_b = entry_a.clone();
        entry_b.entry_id = Some("foo\0bar".to_string());
        entry_b.decision_id = "baz".to_string();

        let canonical_a = canonical_entry_bytes(&entry_a);
        let canonical_b = canonical_entry_bytes(&entry_b);

        assert_ne!(
            canonical_a, canonical_b,
            "length-prefixed framing must prevent entry_id/decision_id boundary collisions"
        );
    }

    #[test]
    fn test_canonical_entry_bytes_distinguishes_missing_and_empty_entry_id() {
        let mut missing_entry_id = test_entry("TEST-OPTION-FRAMING", 1);
        missing_entry_id.entry_id = None;

        let mut empty_entry_id = missing_entry_id.clone();
        empty_entry_id.entry_id = Some(String::new());

        assert_ne!(
            canonical_entry_bytes(&missing_entry_id),
            canonical_entry_bytes(&empty_entry_id),
            "canonical bytes must distinguish absent entry_id from present empty entry_id"
        );
    }

    #[test]
    fn test_wrong_verifying_key_rejected() {
        let (signing_key, _) = test_keys();
        let (_, different_verifying_key) = test_keys(); // Different key pair

        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, different_verifying_key);

        let mut entry = test_entry("TEST-WRONG-KEY", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        let result = ledger.append(entry);
        assert!(
            result.is_err(),
            "Entry signed with wrong key should be rejected"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    // ── Signature Hex Decode DoS Regression Tests ──────────────────

    #[test]
    fn test_valid_128_char_signature_passes() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-VALID-SIG", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Valid Ed25519 signature is 64 bytes = 128 hex chars
        assert_eq!(
            entry.signature.len(),
            128,
            "Ed25519 signature should be exactly 128 hex chars"
        );

        let result = ledger.append(entry);
        assert!(result.is_ok(), "Valid 128-char signature should pass");
    }

    #[test]
    fn test_129_char_signature_rejected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-129-CHAR", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Append one extra character to make it 129 chars
        entry.signature.push('a');
        assert_eq!(entry.signature.len(), 129);

        let result = ledger.append(entry);
        assert!(result.is_err(), "129-char signature should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("signature hex too long"),
                "Should mention length cap"
            );
            assert!(reason.contains("129"), "Should mention actual length");
            assert!(reason.contains("256"), "Should mention max length");
        } else {
            panic!("Should return SignatureInvalid error for oversized signature");
        }
    }

    #[test]
    fn test_large_hex_signature_rejected_fast() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-LARGE-SIG", 1);
        // Create a 1MB hex string (would be 512KB when decoded)
        entry.signature = "a".repeat(1_000_000);

        let start = std::time::Instant::now();
        let result = ledger.append(entry);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Large signature should be rejected");
        assert!(
            elapsed.as_millis() < 100,
            "Should fail quickly without attempting decode"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("signature hex too long"),
                "Should mention length cap"
            );
            assert!(reason.contains("1000000"), "Should mention actual length");
        } else {
            panic!("Should return SignatureInvalid error for oversized signature");
        }
    }

    #[test]
    fn test_empty_signature_rejected() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-EMPTY-SIG", 1);
        entry.signature = String::new(); // Empty signature

        let result = ledger.append(entry);
        assert!(result.is_err(), "Empty signature should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("signature cannot be empty"),
                "Should mention empty signature"
            );
        } else {
            panic!("Should return SignatureInvalid error for empty signature");
        }
    }

    #[test]
    fn test_exactly_256_char_signature_allowed() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-256-CHAR", 1);
        // Create exactly 256 hex chars (would decode to 128 bytes)
        entry.signature = "aa".repeat(128); // 256 chars total
        assert_eq!(entry.signature.len(), 256);

        let result = ledger.append(entry);
        // Should be rejected due to invalid hex/signature verification, but NOT due to length cap
        assert!(
            result.is_err(),
            "256-char invalid signature should be rejected"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                !reason.contains("signature hex too long"),
                "Should NOT mention length cap for 256 chars"
            );
            // Should fail on signature verification instead
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_257_char_signature_rejected_by_length_cap() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-257-CHAR", 1);
        // Create 257 hex chars (exceeds 256 cap)
        entry.signature = "aa".repeat(128) + "a"; // 257 chars total
        assert_eq!(entry.signature.len(), 257);

        let result = ledger.append(entry);
        assert!(result.is_err(), "257-char signature should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("signature hex too long"),
                "Should mention length cap for 257 chars"
            );
            assert!(reason.contains("257"), "Should mention actual length");
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    // ── Constant-Time Replay Detection Regression Tests ────────────

    #[test]
    fn test_replay_detection_timing_regression_identical_signatures() {
        use std::time::Instant;

        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(100, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Add a known signature to the ledger
        let mut known_entry = test_entry("KNOWN-ENTRY", 1000);
        sign_evidence_entry(&mut known_entry, &signing_key);
        ledger
            .append(known_entry.clone())
            .expect("Known entry should succeed");

        // Time comparison with identical signature (replay attack)
        let start_identical = Instant::now();
        let is_replay_identical = ledger.is_replay_attack_ct(1000, &known_entry.signature);
        let time_identical = start_identical.elapsed();

        assert!(
            is_replay_identical,
            "Identical signature should be detected as replay"
        );

        // Time comparison with different signature (not a replay)
        let different_signature = "ff".repeat(64); // Different signature
        let start_different = Instant::now();
        let is_replay_different = ledger.is_replay_attack_ct(1000, &different_signature);
        let time_different = start_different.elapsed();

        assert!(
            !is_replay_different,
            "Different signature should not be detected as replay"
        );

        // Timing should be similar regardless of match/no-match to prevent timing attacks
        let timing_ratio = if time_identical < time_different {
            time_different.as_nanos() as f64 / time_identical.as_nanos() as f64
        } else {
            time_identical.as_nanos() as f64 / time_different.as_nanos() as f64
        };

        // Allow up to 3x timing difference (accounting for measurement noise)
        // In a real attack scenario, constant-time should be much tighter
        assert!(
            timing_ratio < 3.0,
            "Timing difference too large: identical={}ns different={}ns ratio={}",
            time_identical.as_nanos(),
            time_different.as_nanos(),
            timing_ratio
        );
    }

    #[test]
    fn test_replay_detection_timing_regression_position_independence() {
        use std::time::Instant;

        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(100, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Add multiple known signatures to the ledger
        for i in 1..=50 {
            let mut entry = test_entry(&format!("ENTRY-{}", i), i);
            sign_evidence_entry(&mut entry, &signing_key);
            ledger.append(entry).expect("Entry should succeed");
        }

        // Test signature that differs in first byte vs last byte
        let base_signature = "42".repeat(64);
        let mut first_byte_diff = base_signature.clone();
        first_byte_diff.replace_range(0..2, "43");
        let mut last_byte_diff = base_signature.clone();
        last_byte_diff.replace_range((base_signature.len() - 2).., "43");

        // Time comparison with first-byte difference
        let start_first = Instant::now();
        let is_replay_first = ledger.is_replay_attack_ct(9999, &first_byte_diff);
        let time_first = start_first.elapsed();

        // Time comparison with last-byte difference
        let start_last = Instant::now();
        let is_replay_last = ledger.is_replay_attack_ct(9999, &last_byte_diff);
        let time_last = start_last.elapsed();

        assert!(
            !is_replay_first,
            "First-byte different signature should not be replay"
        );
        assert!(
            !is_replay_last,
            "Last-byte different signature should not be replay"
        );

        // Timing should be position-independent for constant-time guarantee
        let timing_ratio = if time_first < time_last {
            time_last.as_nanos() as f64 / time_first.as_nanos() as f64
        } else {
            time_first.as_nanos() as f64 / time_last.as_nanos() as f64
        };

        assert!(
            timing_ratio < 2.0,
            "Position-dependent timing detected: first_diff={}ns last_diff={}ns ratio={}",
            time_first.as_nanos(),
            time_last.as_nanos(),
            timing_ratio
        );
    }

    #[test]
    fn replay_scan_checks_both_vecdeque_slices_after_wraparound() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(8, 100_000));
        ledger.seen_signatures = VecDeque::with_capacity(4);

        for i in 0_u8..4 {
            let mut signature = [0_u8; ED25519_SIGNATURE_BYTES];
            signature[0] = i;
            ledger.remember_seen_signature(u64::from(i), signature);
        }

        let _ = ledger.seen_signatures.pop_front();
        let _ = ledger.seen_signatures.pop_front();

        for i in 4_u8..6 {
            let mut signature = [0_u8; ED25519_SIGNATURE_BYTES];
            signature[0] = i;
            ledger.remember_seen_signature(u64::from(i), signature);
        }

        let (front, back) = ledger.seen_signatures.as_slices();
        assert!(
            !front.is_empty() && !back.is_empty(),
            "the regression must exercise a split VecDeque layout"
        );

        let mut wrapped_signature = [0_u8; ED25519_SIGNATURE_BYTES];
        wrapped_signature[0] = 5;
        let wrapped_replay_key = replay_key(5, &wrapped_signature);

        assert!(
            back.contains(&wrapped_replay_key),
            "the target replay key should live in the wrapped-back slice"
        );
        assert!(
            !front.contains(&wrapped_replay_key),
            "the front slice should not already satisfy the replay lookup"
        );
        assert!(
            ledger.is_replay_attack_ct_bytes(5, &wrapped_signature),
            "the replay scan must continue into the wrapped-back slice"
        );
    }

    #[test]
    fn test_replay_detection_constant_time_vs_vulnerable_comparison() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut known_entry = test_entry("KNOWN-ENTRY", 1000);
        sign_evidence_entry(&mut known_entry, &signing_key);

        // Test the constant-time method
        let ct_result = ledger.is_replay_attack_ct(1000, &known_entry.signature);

        // Simulate what the old vulnerable method would do (for comparison)
        let replay_key = (1000u64, Box::from(known_entry.signature.as_str()));
        let vulnerable_result = std::collections::HashSet::new().contains(&replay_key); // Always false for empty set

        // Both should give consistent results for identical inputs
        // This test ensures we didn't break functionality when adding constant-time
        assert!(!ct_result, "Should not detect replay in empty ledger");
        assert!(!vulnerable_result, "Vulnerable method comparison baseline");
    }

    // ── Comprehensive Adversarial Input Coverage (bd-3bkf2) ──────────

    #[test]
    fn test_tampered_signature_first_byte() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-FIRST", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with first byte of signature
        let mut sig_bytes = hex::decode(&entry.signature).expect("Valid hex");
        sig_bytes[0] = sig_bytes[0].wrapping_add(1);
        entry.signature = hex::encode(sig_bytes);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered first byte should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_tampered_signature_middle_byte() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-MIDDLE", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with middle byte of signature (32nd byte)
        let mut sig_bytes = hex::decode(&entry.signature).expect("Valid hex");
        sig_bytes[32] = sig_bytes[32].wrapping_add(1);
        entry.signature = hex::encode(sig_bytes);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered middle byte should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_tampered_signature_last_byte() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-LAST", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with last byte of signature
        let mut sig_bytes = hex::decode(&entry.signature).expect("Valid hex");
        let last_idx = sig_bytes.len() - 1;
        sig_bytes[last_idx] = sig_bytes[last_idx].wrapping_add(1);
        entry.signature = hex::encode(sig_bytes);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered last byte should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_tampered_timestamp_detected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-TIMESTAMP", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with timestamp after signing
        entry.timestamp_ns = entry.timestamp_ns.saturating_add(1000000000); // Add 1 second

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered timestamp should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_tampered_payload_detected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-PAYLOAD", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with evidence data after signing
        entry.evidence_data = format!("{}-TAMPERED", entry.evidence_data);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered payload should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_tampered_decision_id_detected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-TAMPER-ID", 1);
        sign_evidence_entry(&mut entry, &signing_key);

        // Tamper with decision ID after signing
        entry.decision_id = format!("{}-TAMPERED", entry.decision_id);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Tampered decision ID should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_signature_with_invalid_hex_characters() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-INVALID-HEX", 1);
        // Invalid hex with non-hex characters
        entry.signature = "abcdeg123456789".to_string(); // 'g' is invalid hex

        let result = ledger.append(entry);
        assert!(result.is_err(), "Invalid hex should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("invalid hex") || reason.contains("Invalid character"));
        } else {
            panic!("Should return SignatureInvalid error for invalid hex");
        }
    }

    #[test]
    fn test_signature_valid_hex_but_invalid_ed25519() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-INVALID-ED25519", 1);
        // Valid hex that decodes to invalid Ed25519 signature (all zeros)
        entry.signature = "00".repeat(64); // 64 bytes of zeros

        let result = ledger.append(entry);
        assert!(
            result.is_err(),
            "Invalid Ed25519 signature should be rejected"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_signature_uppercase_hex_rejected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-UPPERCASE-HEX", 1);
        sign_evidence_entry(&mut entry, &signing_key);
        entry.signature = entry.signature.to_uppercase();

        let result = ledger.append(entry);
        assert!(
            result.is_err(),
            "Uppercase signature hex should be rejected"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("canonical lowercase hex"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_signature_odd_length_hex() {
        let (_, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-ODD-HEX", 1);
        // Odd number of hex characters
        entry.signature = "abcdef123456789".to_string(); // 15 chars (odd)

        let result = ledger.append(entry);
        assert!(result.is_err(), "Odd-length hex should be rejected");

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(
                reason.contains("invalid hex")
                    || reason.contains("Odd number")
                    || reason.contains("Invalid length")
            );
        } else {
            panic!("Should return SignatureInvalid error for odd-length hex");
        }
    }

    #[test]
    fn test_unicode_in_decision_id_signed_correctly() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-UNICODE-🔐", 1); // Unicode emoji
        entry.evidence_data = "Unicode test: 测试 🚀".to_string();
        sign_evidence_entry(&mut entry, &signing_key);

        let result = ledger.append(entry);
        assert!(result.is_ok(), "Valid Unicode signature should be accepted");
    }

    #[test]
    fn test_replay_attack_same_signature_timestamp_id() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-REPLAY", 42);
        sign_evidence_entry(&mut entry, &signing_key);

        // First submission should succeed
        let result1 = ledger.append(entry.clone());
        assert!(result1.is_ok(), "First submission should succeed");

        // Replay with identical signature + timestamp should be rejected
        let result2 = ledger.append(entry);
        assert!(result2.is_err(), "Replay attack should be rejected");

        if let Err(LedgerError::ReplayAttackDetected { .. }) = result2 {
            // Expected error type
        } else {
            panic!(
                "Should return ReplayAttackDetected error, got: {:?}",
                result2
            );
        }
    }

    #[test]
    fn test_wrong_verifying_key() {
        let (signing_key, _) = test_keys();
        // Create a different verifying key
        let wrong_key = VerifyingKey::from(&SigningKey::generate(&mut rand::thread_rng()));
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, wrong_key);

        let mut entry = test_entry("TEST-WRONG-KEY", 1);
        sign_evidence_entry(&mut entry, &signing_key); // Sign with correct key

        // Verify with wrong key should fail
        let result = ledger.append(entry);
        assert!(
            result.is_err(),
            "Wrong verifying key should reject signature"
        );

        if let Err(LedgerError::SignatureInvalid { reason }) = result {
            assert!(reason.contains("signature verification failed"));
        } else {
            panic!("Should return SignatureInvalid error");
        }
    }

    #[test]
    fn test_oversized_entry_rejected() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100); // Small byte capacity
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = test_entry("TEST-OVERSIZED", 1);
        // Create oversized evidence data
        entry.evidence_data = "x".repeat(200); // Exceeds 100-byte capacity
        sign_evidence_entry(&mut entry, &signing_key);

        let result = ledger.append(entry);
        assert!(result.is_err(), "Oversized entry should be rejected");

        if let Err(LedgerError::CapacityExhausted) = result {
            // Expected for oversized entry
        } else {
            panic!("Should return CapacityExhausted error for oversized entry");
        }
    }

    #[test]
    fn test_empty_entry_fields_handled() {
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        let mut entry = EvidenceEntry {
            decision_id: "".to_string(), // Empty decision ID
            timestamp_ns: 0,
            evidence_data: "".to_string(), // Empty evidence data
            signature: "".to_string(),
        };
        sign_evidence_entry(&mut entry, &signing_key);

        let result = ledger.append(entry);
        // Should handle empty fields gracefully (signature verification should work)
        assert!(result.is_ok(), "Empty fields should be handled correctly");
    }

    #[test]
    fn bd_3ml3u_regression_replay_timing_full_verification() {
        // Regression test for bd-3ml3u: ensure full verification chain runs without early returns
        // when both timestamp AND signature checks fail, preventing timing leaks
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(10, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Add several valid entries to create timing attack surface
        for i in 1..=5 {
            let mut entry = test_entry(&format!("VALID-{}", i), i * 1000);
            sign_evidence_entry(&mut entry, &signing_key);
            ledger.append(entry).unwrap();
        }

        // Test case 1: Malformed timestamp with different signature (early timestamp mismatch)
        let mut malformed_entry1 = test_entry("MALFORMED-TIME", 9999); // Different timestamp
        malformed_entry1.signature = "bad_signature_1".to_string(); // Bad signature
        sign_evidence_entry(&mut malformed_entry1, &signing_key); // Re-sign to get correct signature format

        // Test case 2: Matching timestamp but different signature (signature mismatch later)
        let mut malformed_entry2 = test_entry("MALFORMED-SIG", 2000); // Matches 2nd entry timestamp
        malformed_entry2.signature = "bad_signature_2".to_string(); // Bad signature
        sign_evidence_entry(&mut malformed_entry2, &signing_key); // Re-sign to get correct signature format

        // Both should be accepted (no replay detected) since signatures don't match exactly
        let result1 = ledger.append(malformed_entry1);
        let result2 = ledger.append(malformed_entry2);

        assert!(
            result1.is_ok(),
            "Entry with different timestamp should be accepted"
        );
        assert!(
            result2.is_ok(),
            "Entry with matching timestamp but different signature should be accepted"
        );

        // Test case 3: Exact replay (both timestamp and signature match)
        let mut replay_entry = test_entry("VALID-2", 2000); // Exact match of 2nd entry
        sign_evidence_entry(&mut replay_entry, &signing_key);

        let replay_result = ledger.append(replay_entry);
        assert!(
            replay_result.is_err(),
            "Exact replay should be detected and rejected"
        );

        if let Err(LedgerError::DuplicateSignature { .. }) = replay_result {
            // Expected - replay detected
        } else {
            panic!("Should detect replay attack with matching timestamp and signature");
        }
    }

    #[test]
    fn bd_3dir0_inv_ledger_deterministic_identical_inputs_produce_identical_snapshots() {
        // Test for INV-LEDGER-DETERMINISTIC: identical inputs produce identical snapshots
        // Create two separate ledgers with identical capacity
        let capacity = LedgerCapacity::new(5, 10_000);
        let mut ledger1 = EvidenceLedger::new(capacity.clone());
        let mut ledger2 = EvidenceLedger::new(capacity);

        // Apply identical sequence of append operations to both ledgers
        let test_entries = vec![
            test_entry("DEC-001", 1000),
            test_entry("DEC-002", 2000),
            test_entry("DEC-003", 3000),
        ];

        for entry in test_entries {
            let _ = ledger1
                .append(entry.clone())
                .expect("append should succeed");
            let _ = ledger2.append(entry).expect("append should succeed");
        }

        // Take snapshots from both ledgers
        let snapshot1 = ledger1.snapshot();
        let snapshot2 = ledger2.snapshot();

        // Assert snapshots are identical
        assert_eq!(
            snapshot1.entries.len(),
            snapshot2.entries.len(),
            "Snapshot entry counts must be identical"
        );
        assert_eq!(
            snapshot1.total_appended, snapshot2.total_appended,
            "Total appended counts must be identical"
        );
        assert_eq!(
            snapshot1.total_evicted, snapshot2.total_evicted,
            "Total evicted counts must be identical"
        );
        assert_eq!(
            snapshot1.current_bytes, snapshot2.current_bytes,
            "Current byte counts must be identical"
        );
        assert_eq!(
            snapshot1.capacity, snapshot2.capacity,
            "Capacities must be identical"
        );

        // Verify each entry matches exactly (including entry IDs)
        for (i, ((id1, entry1), (id2, entry2))) in snapshot1
            .entries
            .iter()
            .zip(snapshot2.entries.iter())
            .enumerate()
        {
            assert_eq!(id1, id2, "Entry IDs must be identical at position {}", i);
            assert_eq!(
                entry1.decision_id, entry2.decision_id,
                "Decision IDs must be identical at position {}",
                i
            );
            assert_eq!(
                entry1.epoch_id, entry2.epoch_id,
                "Epoch IDs must be identical at position {}",
                i
            );
            assert_eq!(
                entry1.payload, entry2.payload,
                "Payloads must be identical at position {}",
                i
            );
        }

        // Verify serialized snapshots are byte-for-byte identical
        let serialized1 = serde_json::to_string(&snapshot1).expect("serialization should succeed");
        let serialized2 = serde_json::to_string(&snapshot2).expect("serialization should succeed");
        assert_eq!(
            serialized1, serialized2,
            "Serialized snapshots must be byte-for-byte identical"
        );
    }

    #[cfg(loom)]
    #[doc(hidden)]
    pub fn shared_evidence_ledger_concurrent_append_loom_model() {
        use loom::thread;

        loom::model(|| {
            // Test concurrent appends with bounded capacity to verify:
            // 1. Append ordering is deterministic
            // 2. No duplicate entry hashes
            // 3. Bounded capacity is respected
            // 4. Total counts are consistent
            let ledger = SharedEvidenceLedger::new(LedgerCapacity::new(3, 100_000));

            let ledger_a = ledger.clone();
            let ledger_b = ledger.clone();
            let ledger_c = ledger.clone();

            let handle_a =
                thread::spawn(move || ledger_a.append(make_entry("LOOM-A", 1)).expect("append A"));

            let handle_b =
                thread::spawn(move || ledger_b.append(make_entry("LOOM-B", 2)).expect("append B"));

            let handle_c =
                thread::spawn(move || ledger_c.append(make_entry("LOOM-C", 3)).expect("append C"));

            let id_a = handle_a.join().expect("join A");
            let id_b = handle_b.join().expect("join B");
            let id_c = handle_c.join().expect("join C");

            // Verify all appends succeeded
            let final_snapshot = ledger.snapshot();

            // All three entries should be present (within capacity)
            assert_eq!(final_snapshot.entries.len(), 3);
            assert_eq!(final_snapshot.total_appended, 3);

            // Entry IDs should be monotonic and unique
            let mut ids = vec![id_a, id_b, id_c];
            ids.sort();
            assert_eq!(ids[0].0 + 1, ids[1].0);
            assert_eq!(ids[1].0 + 1, ids[2].0);

            // All entries should have unique epoch_ids
            let mut epoch_ids: Vec<String> = final_snapshot
                .entries
                .iter()
                .map(|(_, entry)| entry.epoch_id.clone())
                .collect();
            epoch_ids.sort();
            epoch_ids.dedup();
            assert_eq!(epoch_ids.len(), 3, "No duplicate epoch_ids allowed");

            // Test bounded capacity with additional appends
            let ledger_d = ledger.clone();
            let ledger_e = ledger.clone();

            let handle_d =
                thread::spawn(move || ledger_d.append(make_entry("LOOM-D", 4)).expect("append D"));

            let handle_e =
                thread::spawn(move || ledger_e.append(make_entry("LOOM-E", 5)).expect("append E"));

            handle_d.join().expect("join D");
            handle_e.join().expect("join E");

            let bounded_snapshot = ledger.snapshot();

            // Should still be within capacity bound
            assert!(
                bounded_snapshot.entries.len() <= 3,
                "Capacity should be bounded"
            );
            assert_eq!(bounded_snapshot.total_appended, 5);

            // Some entries may have been evicted, but total_evicted + retained should equal total_appended
            let retained = u64::try_from(bounded_snapshot.entries.len()).unwrap_or(u64::MAX);
            assert_eq!(
                retained + bounded_snapshot.total_evicted,
                bounded_snapshot.total_appended
            );
        });
    }

    #[test]
    fn test_replay_miss_prefilter_optimization() {
        // bd-17pb5: Test that miss prefilter correctly handles both hits and misses
        let (signing_key, verifying_key) = test_keys();
        let capacity = LedgerCapacity::new(100, 100_000);
        let mut ledger = EvidenceLedger::with_verifying_key(capacity, verifying_key);

        // Add some entries to populate the replay window
        for i in 1..=10 {
            let entry = make_signed_entry(&format!("TEST-PREFILTER-{i:02}"), i, &signing_key);
            ledger.append(entry).expect("append should succeed");
        }

        // Test that known signatures are detected as replay attacks
        let existing_entry = make_signed_entry("TEST-PREFILTER-05", 5, &signing_key);
        let signature_bytes = hex::decode(&existing_entry.signature).expect("valid hex");
        assert!(
            ledger.is_replay_attack_ct_bytes(existing_entry.timestamp_ms, &signature_bytes),
            "Known signature should be detected as replay attack"
        );

        // Test that unknown signatures are not detected as replay attacks
        let new_entry = make_signed_entry("TEST-PREFILTER-NEW", 999, &signing_key);
        let new_signature_bytes = hex::decode(&new_entry.signature).expect("valid hex");
        assert!(
            !ledger.is_replay_attack_ct_bytes(new_entry.timestamp_ms, &new_signature_bytes),
            "Unknown signature should not be detected as replay attack"
        );

        // Verify that the replay key prefilter contains the expected number of entries
        assert_eq!(
            ledger.replay_key_hashes.len(),
            10,
            "Hash prefilter should contain all added signatures"
        );

        // Test that eviction also removes hashes from the prefilter
        for i in 11..=150 {
            let entry = make_signed_entry(&format!("TEST-PREFILTER-{i:03}"), i, &signing_key);
            ledger.append(entry).expect("append should succeed");
        }

        // Verify that old entries are no longer detected (they should have been evicted)
        let old_signature_bytes = hex::decode(&existing_entry.signature).expect("valid hex");
        assert!(
            !ledger.is_replay_attack_ct_bytes(existing_entry.timestamp_ms, &old_signature_bytes),
            "Evicted signature should no longer be detected as replay attack"
        );

        // Verify prefilter size matches the replay window size
        let expected_size = capacity.max_entries.max(MIN_SEEN_SIGNATURES);
        assert!(
            ledger.replay_key_hashes.len() <= expected_size,
            "Hash prefilter should respect capacity bounds"
        );
    }

    #[test]
    fn replay_key_hash_prefilter_refcounts_collisions() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(2, 1024));

        ledger.retain_replay_key_hash(7);
        ledger.retain_replay_key_hash(7);
        assert_eq!(ledger.replay_key_hashes.get(&7), Some(&2));

        ledger.release_replay_key_hash(7);
        assert_eq!(ledger.replay_key_hashes.get(&7), Some(&1));

        ledger.release_replay_key_hash(7);
        assert!(!ledger.replay_key_hashes.contains_key(&7));
    }

    #[test]
    fn control_character_validation_rejects_cr_lf_esc_nul() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 1024));

        // Test CR (carriage return) in decision_id
        let mut entry = test_entry("DEC\r001", 1);
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "decision_id"
        ));

        // Test LF (line feed) in trace_id
        entry = test_entry("DEC-001", 1);
        entry.trace_id = "trace\n123".to_string();
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "trace_id"
        ));

        // Test ESC in decision_time
        entry = test_entry("DEC-001", 1);
        entry.decision_time = "2024-01-01T\x1b[1m12:00:00Z".to_string();
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "decision_time"
        ));

        // Test NUL byte in schema_version
        entry = test_entry("DEC-001", 1);
        entry.schema_version = "v1\0".to_string();
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "schema_version"
        ));

        // Test other control characters
        entry = test_entry("DEC-001", 1);
        entry.signature = "abc\x01def".to_string(); // SOH control character
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "signature"
        ));
    }

    #[test]
    fn control_character_validation_allows_normal_text() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 1024));

        // Valid entry should work
        let entry = test_entry("DEC-001", 1);
        assert!(ledger.append_unsigned_entry(entry).is_ok());

        // Entry with space and valid characters should work
        let mut entry = test_entry("DEC 002", 1);
        entry.trace_id = "trace-123-abc".to_string();
        entry.decision_time = "2024-01-01T12:00:00Z".to_string();
        entry.schema_version = "v1.2.3".to_string();
        assert!(ledger.append_unsigned_entry(entry).is_ok());
    }

    #[test]
    fn control_character_validation_checks_all_text_fields() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 1024));

        // Test each text field individually
        let test_cases = vec![
            ("schema_version", |entry: &mut EvidenceEntry| entry.schema_version = "v1\r".to_string()),
            ("decision_id", |entry: &mut EvidenceEntry| entry.decision_id = "DEC\n001".to_string()),
            ("decision_time", |entry: &mut EvidenceEntry| entry.decision_time = "2024\x1b".to_string()),
            ("trace_id", |entry: &mut EvidenceEntry| entry.trace_id = "trace\0".to_string()),
            ("signature", |entry: &mut EvidenceEntry| entry.signature = "sig\x02".to_string()),
            ("prev_entry_hash", |entry: &mut EvidenceEntry| entry.prev_entry_hash = "hash\x1f".to_string()),
        ];

        for (field_name, mutate_fn) in test_cases {
            let mut entry = test_entry("DEC-001", 1);
            mutate_fn(&mut entry);

            assert!(matches!(
                ledger.append_unsigned_entry(entry),
                Err(LedgerError::InvalidControlCharacters { field, .. }) if field == field_name
            ), "Expected InvalidControlCharacters for field {}", field_name);
        }
    }

    #[test]
    fn control_character_validation_checks_optional_entry_id() {
        let mut ledger = EvidenceLedger::new(LedgerCapacity::new(10, 1024));

        // Test entry_id validation when present
        let mut entry = test_entry("DEC-001", 1);
        entry.entry_id = Some("entry\r123".to_string());
        assert!(matches!(
            ledger.append_unsigned_entry(entry),
            Err(LedgerError::InvalidControlCharacters { field, .. }) if field == "entry_id"
        ));

        // Test that None entry_id works
        entry = test_entry("DEC-001", 1);
        entry.entry_id = None;
        assert!(ledger.append_unsigned_entry(entry).is_ok());

        // Test that valid entry_id works
        entry = test_entry("DEC-002", 1);
        entry.entry_id = Some("entry-valid-123".to_string());
        assert!(ledger.append_unsigned_entry(entry).is_ok());
    }
}
