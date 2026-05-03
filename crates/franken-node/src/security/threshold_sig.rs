//! Threshold signature verification for connector publication artifacts (bd-35q1).
//!
//! Publication requires a configured k-of-n quorum. Partial signature sets
//! below threshold are rejected. Verification failures produce stable,
//! machine-readable failure reasons.

#[cfg(test)]
use crate::push_bounded;
use crate::security::constant_time;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

// Maximum bounds for Vec collections to prevent memory exhaustion
#[cfg(test)]
const MAX_SIGNER_KEYS: usize = 1024;
#[cfg(test)]
const MAX_SIGNATURES: usize = 2048;
#[cfg(test)]
const MAX_TEST_RESULTS: usize = 1024;

// ── Types ───────────────────────────────────────────────────────────

const RESERVED_ARTIFACT_ID: &str = "<unknown>";
const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;
const ED25519_SIGNATURE_HEX_LEN: usize = 128;
const MAX_THRESHOLD_IDENTIFIER_BYTES: usize = 4096;
const MAX_SEEN_KEY_PREALLOC: usize = 64;
const SIGNING_MESSAGE_DOMAIN_LEN: usize = 24;
const SIGNING_MESSAGE_DOMAIN: &[u8; SIGNING_MESSAGE_DOMAIN_LEN] = b"threshold_sig_verify_v2:";
const INLINE_SIGNING_MESSAGE_IDENTIFIER_BYTES: usize = 128;
const INLINE_SIGNING_MESSAGE_CONTENT_HASH_BYTES: usize = 64;
const INLINE_SIGNING_MESSAGE_BYTES: usize = SIGNING_MESSAGE_DOMAIN_LEN
    + 8
    + INLINE_SIGNING_MESSAGE_IDENTIFIER_BYTES
    + 8
    + INLINE_SIGNING_MESSAGE_IDENTIFIER_BYTES
    + 8
    + INLINE_SIGNING_MESSAGE_CONTENT_HASH_BYTES;

/// Threshold configuration: k-of-n quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub threshold: u32,
    pub total_signers: u32,
    pub signer_keys: Vec<SignerKey>,
}

/// SECURITY: Validates that an identifier contains only safe characters to prevent
/// control characters, invisible Unicode, or bidirectional text override attacks
/// that could confuse logs, metrics, or operator workflows.
fn validate_safe_identifier(identifier: &str) -> Result<(), &'static str> {
    if identifier.is_empty() {
        return Err("identifier cannot be empty");
    }

    // Reject if too long (prevent DoS via extremely long identifiers)
    if identifier.len() > 128 {
        return Err("identifier exceeds maximum length of 128 characters");
    }

    // Allow only: alphanumeric ASCII, hyphen, underscore, and dot
    // This prevents control chars, invisible Unicode, bidi overrides, etc.
    for byte in identifier.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                // Safe character, continue
            }
            _ => {
                return Err(
                    "identifier contains unsafe characters (only alphanumeric, hyphen, underscore, dot allowed)",
                );
            }
        }
    }

    Ok(())
}

impl ThresholdConfig {
    pub fn validate(&self) -> Result<(), ThresholdError> {
        if self.threshold == 0 {
            return Err(ThresholdError::ConfigInvalid {
                reason: "threshold must be > 0".to_string(),
            });
        }
        if self.threshold > self.total_signers {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "threshold {} exceeds total_signers {}",
                    self.threshold, self.total_signers
                ),
            });
        }
        if u32::try_from(self.signer_keys.len()).unwrap_or(u32::MAX) != self.total_signers {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "signer_keys count {} != total_signers {}",
                    self.signer_keys.len(),
                    self.total_signers
                ),
            });
        }
        let mut seen_key_ids = HashSet::with_capacity(self.signer_keys.len());
        let mut seen_public_keys = HashSet::with_capacity(self.signer_keys.len());
        for signer in &self.signer_keys {
            // SECURITY: Validate key_id contains only safe characters to prevent
            // control characters, invisible Unicode, or bidi tricks in logs/metrics
            if let Err(reason) = validate_safe_identifier(&signer.key_id) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("invalid signer key_id '{}': {}", signer.key_id, reason),
                });
            }

            if !seen_key_ids.insert(signer.key_id.as_str()) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("duplicate signer key_id {}", signer.key_id),
                });
            }
            let canonical_public_key_hex = CanonicalPublicKeyHex::new(&signer.public_key_hex);
            if !seen_public_keys.insert(canonical_public_key_hex) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("duplicate signer public_key_hex {}", signer.public_key_hex),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum CanonicalPublicKeyHex {
    Fixed([u8; ED25519_PUBLIC_KEY_HEX_LEN]),
    Other(String),
}

impl CanonicalPublicKeyHex {
    fn new(public_key_hex: &str) -> Self {
        if public_key_hex.len() != ED25519_PUBLIC_KEY_HEX_LEN {
            return Self::Other(public_key_hex.to_ascii_lowercase());
        }

        let mut fixed = [0_u8; ED25519_PUBLIC_KEY_HEX_LEN];
        for (dst, src) in fixed.iter_mut().zip(public_key_hex.bytes()) {
            *dst = src.to_ascii_lowercase();
        }
        Self::Fixed(fixed)
    }
}

/// A signer's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerKey {
    pub key_id: String,
    pub public_key_hex: String,
}

/// Cached threshold configuration with pre-parsed verifying keys for performance.
/// Eliminates repeated hex decoding and VerifyingKey construction during verification.
#[derive(Debug)]
pub struct CachedThresholdConfig {
    pub config: ThresholdConfig,
    /// Pre-parsed VerifyingKey objects indexed by key_id for O(1) lookup
    verifying_keys: HashMap<String, VerifyingKey>,
}

impl CachedThresholdConfig {
    /// Create a cached config from a validated ThresholdConfig.
    /// Pre-parses all public keys to avoid repeated hex decoding during verification.
    pub fn new(config: ThresholdConfig) -> Result<Self, ThresholdError> {
        // Validate config first
        config.validate()?;

        let mut verifying_keys = HashMap::with_capacity(config.signer_keys.len());
        for signer in &config.signer_keys {
            if signer.public_key_hex.len() != ED25519_PUBLIC_KEY_HEX_LEN {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("invalid public key hex length for {}", signer.key_id),
                });
            }

            // Pre-parse the public key
            let mut pk_array = [0_u8; 32];
            hex::decode_to_slice(&signer.public_key_hex, &mut pk_array).map_err(|_| {
                ThresholdError::ConfigInvalid {
                    reason: format!("invalid public key hex for {}", signer.key_id),
                }
            })?;
            let verifying_key =
                VerifyingKey::from_bytes(&pk_array).map_err(|_| ThresholdError::ConfigInvalid {
                    reason: format!("invalid public key for {}", signer.key_id),
                })?;

            verifying_keys.insert(signer.key_id.clone(), verifying_key);
        }

        Ok(CachedThresholdConfig {
            config,
            verifying_keys,
        })
    }

    /// Get pre-parsed VerifyingKey for a given key_id
    pub fn get_verifying_key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.verifying_keys.get(key_id)
    }

    /// Check if a key_id is known in this configuration
    pub fn contains_key_id(&self, key_id: &str) -> bool {
        self.verifying_keys.contains_key(key_id)
    }
}

#[derive(Debug)]
struct PreparedThresholdKeys<'a> {
    verifying_keys: HashMap<&'a str, Option<VerifyingKey>>,
}

impl<'a> PreparedThresholdKeys<'a> {
    fn new(config: &'a ThresholdConfig) -> Self {
        let mut verifying_keys = HashMap::with_capacity(config.signer_keys.len());
        for signer in &config.signer_keys {
            verifying_keys.insert(
                signer.key_id.as_str(),
                parse_verifying_key(&signer.public_key_hex),
            );
        }
        Self { verifying_keys }
    }

    fn new_validated(config: &'a ThresholdConfig) -> Result<Self, ThresholdError> {
        if config.threshold == 0 {
            return Err(ThresholdError::ConfigInvalid {
                reason: "threshold must be > 0".to_string(),
            });
        }
        if config.threshold > config.total_signers {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "threshold {} exceeds total_signers {}",
                    config.threshold, config.total_signers
                ),
            });
        }
        if u32::try_from(config.signer_keys.len()).unwrap_or(u32::MAX) != config.total_signers {
            return Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "signer_keys count {} != total_signers {}",
                    config.signer_keys.len(),
                    config.total_signers
                ),
            });
        }

        let mut seen_key_ids = HashSet::with_capacity(config.signer_keys.len());
        let mut seen_public_keys = HashSet::with_capacity(config.signer_keys.len());
        let mut verifying_keys = HashMap::with_capacity(config.signer_keys.len());
        for signer in &config.signer_keys {
            if let Err(reason) = validate_safe_identifier(&signer.key_id) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("invalid signer key_id '{}': {}", signer.key_id, reason),
                });
            }

            if !seen_key_ids.insert(signer.key_id.as_str()) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("duplicate signer key_id {}", signer.key_id),
                });
            }
            let canonical_public_key_hex = CanonicalPublicKeyHex::new(&signer.public_key_hex);
            if !seen_public_keys.insert(canonical_public_key_hex) {
                return Err(ThresholdError::ConfigInvalid {
                    reason: format!("duplicate signer public_key_hex {}", signer.public_key_hex),
                });
            }

            verifying_keys.insert(
                signer.key_id.as_str(),
                parse_verifying_key(&signer.public_key_hex),
            );
        }

        Ok(Self { verifying_keys })
    }
}

trait VerifyingKeyLookup {
    fn lookup_verifying_key(&self, key_id: &str) -> VerifyingKeyLookupResult<'_>;
}

enum VerifyingKeyLookupResult<'a> {
    Unknown,
    Invalid,
    Valid(&'a VerifyingKey),
}

impl VerifyingKeyLookup for CachedThresholdConfig {
    fn lookup_verifying_key(&self, key_id: &str) -> VerifyingKeyLookupResult<'_> {
        match self.verifying_keys.get(key_id) {
            Some(verifying_key) => VerifyingKeyLookupResult::Valid(verifying_key),
            None => VerifyingKeyLookupResult::Unknown,
        }
    }
}

impl VerifyingKeyLookup for PreparedThresholdKeys<'_> {
    fn lookup_verifying_key(&self, key_id: &str) -> VerifyingKeyLookupResult<'_> {
        match self.verifying_keys.get(key_id) {
            Some(Some(verifying_key)) => VerifyingKeyLookupResult::Valid(verifying_key),
            Some(None) => VerifyingKeyLookupResult::Invalid,
            None => VerifyingKeyLookupResult::Unknown,
        }
    }
}

/// A partial signature from one signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Logical signer identity. This must match `key_id` for the signature
    /// to count toward quorum, otherwise the signer identity is unauthenticated.
    pub signer_id: String,
    pub key_id: String,
    pub signature_hex: String,
}

/// A publication artifact with collected signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationArtifact {
    pub artifact_id: String,
    pub connector_id: String,
    pub content_hash: String,
    pub signatures: Vec<PartialSignature>,
}

// ── Verification result ─────────────────────────────────────────────

/// Result of threshold signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub artifact_id: String,
    pub verified: bool,
    pub valid_signatures: u32,
    pub threshold: u32,
    pub failure_reason: Option<FailureReason>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Reason for verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    BelowThreshold { have: u32, need: u32 },
    UnknownSigner { signer_id: String },
    InvalidSignature { signer_id: String },
    DuplicateSigner { signer_id: String },
    ConfigInvalid { reason: String },
    InvalidArtifactId { reason: String },
    InvalidConnectorId { reason: String },
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowThreshold { have, need } => {
                write!(f, "THRESH_BELOW_QUORUM: have {have}, need {need}")
            }
            Self::UnknownSigner { signer_id } => {
                write!(f, "THRESH_UNKNOWN_SIGNER: {}", display_safe_text(signer_id))
            }
            Self::InvalidSignature { signer_id } => {
                write!(f, "THRESH_INVALID_SIG: {}", display_safe_text(signer_id))
            }
            Self::DuplicateSigner { signer_id } => {
                write!(f, "duplicate signer: {}", display_safe_text(signer_id))
            }
            Self::ConfigInvalid { reason } => {
                write!(f, "THRESH_CONFIG_INVALID: {}", display_safe_text(reason))
            }
            Self::InvalidArtifactId { reason } => {
                write!(
                    f,
                    "THRESH_INVALID_ARTIFACT_ID: {}",
                    display_safe_text(reason)
                )
            }
            Self::InvalidConnectorId { reason } => {
                write!(
                    f,
                    "THRESH_INVALID_CONNECTOR_ID: {}",
                    display_safe_text(reason)
                )
            }
        }
    }
}

// ── Signature verification ──────────────────────────────────────────

#[allow(dead_code)]
fn digest_prefix_u64(digest: &[u8]) -> u64 {
    let mut prefix = [0u8; 8];
    if let Some(first_eight) = digest.get(..8) {
        prefix.copy_from_slice(first_eight);
    }
    u64::from_le_bytes(prefix)
}

fn extend_len_prefixed_field(msg: &mut Vec<u8>, value: &str) {
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    msg.extend_from_slice(&value_len.to_le_bytes());
    msg.extend_from_slice(value.as_bytes());
}

/// Build the domain-separated message for signing/verification.
fn build_signing_message(artifact_id: &str, connector_id: &str, content_hash: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        SIGNING_MESSAGE_DOMAIN.len()
            + 24
            + artifact_id.len()
            + connector_id.len()
            + content_hash.len(),
    );
    msg.extend_from_slice(SIGNING_MESSAGE_DOMAIN);
    extend_len_prefixed_field(&mut msg, artifact_id);
    extend_len_prefixed_field(&mut msg, connector_id);
    extend_len_prefixed_field(&mut msg, content_hash);
    msg
}

enum SigningMessage {
    Inline {
        bytes: [u8; INLINE_SIGNING_MESSAGE_BYTES],
        len: usize,
    },
    Heap(Vec<u8>),
}

impl SigningMessage {
    fn new(artifact_id: &str, connector_id: &str, content_hash: &str) -> Self {
        if artifact_id.len() > INLINE_SIGNING_MESSAGE_IDENTIFIER_BYTES
            || connector_id.len() > INLINE_SIGNING_MESSAGE_IDENTIFIER_BYTES
            || content_hash.len() > INLINE_SIGNING_MESSAGE_CONTENT_HASH_BYTES
        {
            return Self::Heap(build_signing_message(
                artifact_id,
                connector_id,
                content_hash,
            ));
        }

        let mut bytes = [0_u8; INLINE_SIGNING_MESSAGE_BYTES];
        let mut len = 0;
        bytes[len..len + SIGNING_MESSAGE_DOMAIN_LEN].copy_from_slice(SIGNING_MESSAGE_DOMAIN);
        len += SIGNING_MESSAGE_DOMAIN_LEN;

        let artifact_id_len = u64::try_from(artifact_id.len()).unwrap_or(u64::MAX);
        bytes[len..len + 8].copy_from_slice(&artifact_id_len.to_le_bytes());
        len += 8;
        bytes[len..len + artifact_id.len()].copy_from_slice(artifact_id.as_bytes());
        len += artifact_id.len();

        let connector_id_len = u64::try_from(connector_id.len()).unwrap_or(u64::MAX);
        bytes[len..len + 8].copy_from_slice(&connector_id_len.to_le_bytes());
        len += 8;
        bytes[len..len + connector_id.len()].copy_from_slice(connector_id.as_bytes());
        len += connector_id.len();

        let content_hash_len = u64::try_from(content_hash.len()).unwrap_or(u64::MAX);
        bytes[len..len + 8].copy_from_slice(&content_hash_len.to_le_bytes());
        len += 8;

        bytes[len..len + content_hash.len()].copy_from_slice(content_hash.as_bytes());
        len += content_hash.len();

        Self::Inline { bytes, len }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { bytes, len } => &bytes[..*len],
            Self::Heap(bytes) => bytes,
        }
    }
}

fn display_safe_text(value: &str) -> String {
    value.escape_default().collect()
}

fn invalid_identifier_reason(field_name: &str, value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Some(format!("{field_name} must not be empty"));
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("{field_name} is reserved: {value:?}"));
    }
    if trimmed != value {
        return Some(format!(
            "{field_name} contains leading or trailing whitespace"
        ));
    }
    if value.contains('\0') {
        return Some(format!("{field_name} must not contain null bytes"));
    }
    if value.starts_with('/') {
        return Some(format!("{field_name} must not start with '/'"));
    }
    if value.contains('\\') {
        return Some(format!("{field_name} must not contain backslashes"));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Some(format!(
            "{field_name} must not contain parent-directory segments"
        ));
    }
    if value.len() > MAX_THRESHOLD_IDENTIFIER_BYTES {
        return Some(format!(
            "{field_name} must not exceed {MAX_THRESHOLD_IDENTIFIER_BYTES} bytes"
        ));
    }
    None
}

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    invalid_identifier_reason("artifact_id", artifact_id)
}

fn invalid_connector_id_reason(connector_id: &str) -> Option<String> {
    invalid_identifier_reason("connector_id", connector_id)
}

fn artifact_identifier_failure(artifact: &PublicationArtifact) -> Option<FailureReason> {
    if let Some(reason) = invalid_artifact_id_reason(&artifact.artifact_id) {
        return Some(FailureReason::InvalidArtifactId { reason });
    }

    if let Some(reason) = invalid_connector_id_reason(&artifact.connector_id) {
        return Some(FailureReason::InvalidConnectorId { reason });
    }

    None
}

fn failed_verification_result(
    threshold: u32,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
    failure_reason: FailureReason,
) -> VerificationResult {
    VerificationResult {
        artifact_id: artifact.artifact_id.clone(),
        verified: false,
        valid_signatures: 0,
        threshold,
        failure_reason: Some(failure_reason),
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

fn below_threshold_result(
    threshold: u32,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
    have: u32,
) -> VerificationResult {
    failed_verification_result(
        threshold,
        artifact,
        trace_id,
        timestamp,
        FailureReason::BelowThreshold {
            have,
            need: threshold,
        },
    )
}

fn parse_verifying_key(public_key_hex: &str) -> Option<VerifyingKey> {
    if public_key_hex.len() != ED25519_PUBLIC_KEY_HEX_LEN {
        return None;
    }

    let mut pk_array = [0_u8; 32];
    hex::decode_to_slice(public_key_hex, &mut pk_array).ok()?;
    VerifyingKey::from_bytes(&pk_array).ok()
}

fn parse_signature(signature_hex: &str) -> Option<Signature> {
    if signature_hex.len() != ED25519_SIGNATURE_HEX_LEN {
        return None;
    }

    let mut sig_bytes = [0_u8; 64];
    hex::decode_to_slice(signature_hex, &mut sig_bytes).ok()?;
    Some(Signature::from_bytes(&sig_bytes))
}

/// Verify a partial signature using Ed25519.
fn verify_signature(
    key: &SignerKey,
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
    sig: &PartialSignature,
) -> bool {
    let message = build_signing_message(artifact_id, connector_id, content_hash);
    verify_signature_with_message(key, &message, sig)
}

fn verify_signature_with_message(
    key: &SignerKey,
    message_bytes: &[u8],
    sig: &PartialSignature,
) -> bool {
    let Some(verifying_key) = parse_verifying_key(&key.public_key_hex) else {
        return false;
    };

    verify_signature_with_parsed_key(&verifying_key, message_bytes, sig)
}

fn verify_signature_with_parsed_key(
    verifying_key: &VerifyingKey,
    message_bytes: &[u8],
    sig: &PartialSignature,
) -> bool {
    let Some(signature) = parse_signature(&sig.signature_hex) else {
        return false;
    };

    verify_parsed_signature_with_key(verifying_key, message_bytes, &signature)
}

fn verify_parsed_signature_with_key(
    verifying_key: &VerifyingKey,
    message_bytes: &[u8],
    signature: &Signature,
) -> bool {
    // Use pre-parsed VerifyingKey and pre-computed message bytes
    verifying_key
        .verify_strict(message_bytes, signature)
        .is_ok()
}

enum PendingFailure<'a> {
    UnknownSigner(&'a str),
    InvalidSignature(&'a str),
    DuplicateSigner(&'a str),
    UnsafeSignerId(&'static str),
}

/// Tracks valid signer keys without allocating until a second distinct key appears.
enum SeenKeyIds<'a> {
    Empty,
    One(&'a str),
    Many(HashSet<&'a str>),
}

impl<'a> SeenKeyIds<'a> {
    fn insert(&mut self, key_id: &'a str, capacity: usize) -> bool {
        match self {
            Self::Empty => {
                *self = Self::One(key_id);
                true
            }
            Self::One(first_key_id) if *first_key_id == key_id => false,
            Self::One(first_key_id) => {
                let mut key_ids = HashSet::with_capacity(capacity);
                key_ids.insert(*first_key_id);
                key_ids.insert(key_id);
                *self = Self::Many(key_ids);
                true
            }
            Self::Many(key_ids) => key_ids.insert(key_id),
        }
    }
}

impl PendingFailure<'_> {
    fn into_failure_reason(self) -> FailureReason {
        match self {
            Self::UnknownSigner(signer_id) => FailureReason::UnknownSigner {
                signer_id: signer_id.to_string(),
            },
            Self::InvalidSignature(signer_id) => FailureReason::InvalidSignature {
                signer_id: signer_id.to_string(),
            },
            Self::DuplicateSigner(signer_id) => FailureReason::DuplicateSigner {
                signer_id: signer_id.to_string(),
            },
            Self::UnsafeSignerId(reason) => FailureReason::InvalidSignature {
                signer_id: format!("unsafe signer_id: {reason}"),
            },
        }
    }
}

/// Create an Ed25519 signature for a concrete publication context.
///
/// Requires the private signing key. The corresponding public key must be
/// registered in the threshold config for the signature to verify.
pub fn sign(
    signing_key: &SigningKey,
    key_id: &str,
    artifact_id: &str,
    connector_id: &str,
    content_hash: &str,
) -> PartialSignature {
    let message = SigningMessage::new(artifact_id, connector_id, content_hash);
    let signature = signing_key.sign(message.as_slice());
    PartialSignature {
        signer_id: key_id.to_string(),
        key_id: key_id.to_string(),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verify a publication artifact against a threshold config.
///
/// PERFORMANCE: This path validates the config once and prepares a borrowed
/// key lookup table for the current call. For repeated verifications of the
/// same config, `CachedThresholdConfig` still avoids the per-call key parse.
pub fn verify_threshold(
    config: &ThresholdConfig,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
) -> VerificationResult {
    match PreparedThresholdKeys::new_validated(config) {
        Ok(prepared_keys) => {
            if let Some(failure_reason) = artifact_identifier_failure(artifact) {
                return failed_verification_result(
                    config.threshold,
                    artifact,
                    trace_id,
                    timestamp,
                    failure_reason,
                );
            }

            if artifact.signatures.is_empty() {
                return below_threshold_result(config.threshold, artifact, trace_id, timestamp, 0);
            }

            verify_threshold_with_validated_artifact(
                config.threshold,
                &prepared_keys,
                artifact,
                trace_id,
                timestamp,
            )
        }
        Err(e) => {
            let reason = match e {
                ThresholdError::ConfigInvalid { reason } => reason,
                other => other.to_string(),
            };
            VerificationResult {
                artifact_id: artifact.artifact_id.clone(),
                verified: false,
                valid_signatures: 0,
                threshold: config.threshold,
                failure_reason: Some(FailureReason::ConfigInvalid { reason }),
                trace_id: trace_id.to_string(),
                timestamp: timestamp.to_string(),
            }
        }
    }
}

/// Optimized threshold verification using cached pre-parsed keys.
/// Eliminates repeated hex decoding and linear scans for better performance.
pub fn verify_threshold_cached(
    cached_config: &CachedThresholdConfig,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
) -> VerificationResult {
    if let Some(failure_reason) = artifact_identifier_failure(artifact) {
        return failed_verification_result(
            cached_config.config.threshold,
            artifact,
            trace_id,
            timestamp,
            failure_reason,
        );
    }

    if artifact.signatures.is_empty() {
        return below_threshold_result(
            cached_config.config.threshold,
            artifact,
            trace_id,
            timestamp,
            0,
        );
    }

    verify_threshold_with_validated_artifact(
        cached_config.config.threshold,
        cached_config,
        artifact,
        trace_id,
        timestamp,
    )
}

/// Runs the verification loop after artifact and connector identifiers have
/// already passed `artifact_identifier_failure`.
fn verify_threshold_with_validated_artifact(
    threshold: u32,
    key_lookup: &impl VerifyingKeyLookup,
    artifact: &PublicationArtifact,
    trace_id: &str,
    timestamp: &str,
) -> VerificationResult {
    let mut seen_key_ids = SeenKeyIds::Empty;
    let seen_key_ids_capacity = artifact.signatures.len().min(MAX_SEEN_KEY_PREALLOC);
    let mut valid_count = 0u32;
    let mut first_failure: Option<PendingFailure<'_>> = None;

    // Build message bytes only if a signature reaches cryptographic verification.
    let mut message_bytes: Option<SigningMessage> = None;

    for sig in &artifact.signatures {
        // SECURITY: Validate signer_id contains only safe characters to prevent
        // control characters, invisible Unicode, or bidi tricks in verification logs
        if let Err(reason) = validate_safe_identifier(&sig.signer_id) {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::UnsafeSignerId(reason));
            }
            continue;
        }

        let lookup_result = key_lookup.lookup_verifying_key(&sig.key_id);
        if let VerifyingKeyLookupResult::Unknown = lookup_result {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::UnknownSigner(&sig.signer_id));
            }
            continue;
        }

        // The signer identity must be bound to the configured key identity.
        // Otherwise a valid signature can be replayed under an arbitrary label.
        if !constant_time::ct_eq(&sig.signer_id, &sig.key_id) {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::InvalidSignature(&sig.signer_id));
            }
            continue;
        }

        let VerifyingKeyLookupResult::Valid(verifying_key) = lookup_result else {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::InvalidSignature(&sig.signer_id));
            }
            continue;
        };

        let Some(signature) = parse_signature(&sig.signature_hex) else {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::InvalidSignature(&sig.signer_id));
            }
            continue;
        };

        let message_bytes = message_bytes.get_or_insert_with(|| {
            SigningMessage::new(
                &artifact.artifact_id,
                &artifact.connector_id,
                &artifact.content_hash,
            )
        });
        if !verify_parsed_signature_with_key(verifying_key, message_bytes.as_slice(), &signature) {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::InvalidSignature(&sig.signer_id));
            }
            continue;
        }

        // A signer key can only contribute once toward quorum.
        if !seen_key_ids.insert(sig.key_id.as_str(), seen_key_ids_capacity) {
            if first_failure.is_none() {
                first_failure = Some(PendingFailure::DuplicateSigner(&sig.signer_id));
            }
            continue;
        }

        valid_count = valid_count.saturating_add(1);
    }

    let verified = valid_count >= threshold;
    let failure_reason = if verified {
        None
    } else {
        first_failure
            .map(PendingFailure::into_failure_reason)
            .or_else(|| {
                Some(FailureReason::BelowThreshold {
                    have: valid_count,
                    need: threshold,
                })
            })
    };

    VerificationResult {
        artifact_id: artifact.artifact_id.clone(),
        verified,
        valid_signatures: valid_count,
        threshold,
        failure_reason,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for threshold signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdError {
    #[serde(rename = "THRESH_BELOW_QUORUM")]
    BelowQuorum { have: u32, need: u32 },
    #[serde(rename = "THRESH_UNKNOWN_SIGNER")]
    UnknownSigner { signer_id: String },
    #[serde(rename = "THRESH_INVALID_SIG")]
    InvalidSignature { signer_id: String },
    #[serde(rename = "THRESH_CONFIG_INVALID")]
    ConfigInvalid { reason: String },
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowQuorum { have, need } => {
                write!(f, "THRESH_BELOW_QUORUM: have {have}, need {need}")
            }
            Self::UnknownSigner { signer_id } => {
                write!(f, "THRESH_UNKNOWN_SIGNER: {}", display_safe_text(signer_id))
            }
            Self::InvalidSignature { signer_id } => {
                write!(f, "THRESH_INVALID_SIG: {}", display_safe_text(signer_id))
            }
            Self::ConfigInvalid { reason } => {
                write!(f, "THRESH_CONFIG_INVALID: {}", display_safe_text(reason))
            }
        }
    }
}

impl std::error::Error for ThresholdError {}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const TEST_ARTIFACT_ID: &str = "art-1";
    const TEST_CONNECTOR_ID: &str = "conn-1";

    fn test_sign(signing_key: &SigningKey, key_id: &str, content_hash: &str) -> PartialSignature {
        sign(
            signing_key,
            key_id,
            TEST_ARTIFACT_ID,
            TEST_CONNECTOR_ID,
            content_hash,
        )
    }

    /// Deterministically generate an Ed25519 signing key from an index.
    fn test_signing_key(i: u32) -> SigningKey {
        let mut h = Sha256::new();
        h.update(b"test_signing_key_seed_v1:");
        h.update(i.to_le_bytes());
        let seed: [u8; 32] = h.finalize().into();
        SigningKey::from_bytes(&seed)
    }

    /// Generate n signing keys and the corresponding SignerKey structs.
    fn test_keys(n: u32) -> (Vec<SigningKey>, Vec<SignerKey>) {
        let mut signing_keys = Vec::new();
        let mut signer_keys = Vec::new();
        for i in 0..n {
            let sk = test_signing_key(i);
            let pk_hex = hex::encode(sk.verifying_key().to_bytes());
            push_bounded(
                &mut signer_keys,
                SignerKey {
                    key_id: format!("signer-{i}"),
                    public_key_hex: pk_hex,
                },
                MAX_SIGNER_KEYS,
            );
            push_bounded(&mut signing_keys, sk, MAX_SIGNER_KEYS);
        }
        (signing_keys, signer_keys)
    }

    fn test_config(k: u32, n: u32) -> (Vec<SigningKey>, ThresholdConfig) {
        let (signing_keys, signer_keys) = test_keys(n);
        let config = ThresholdConfig {
            threshold: k,
            total_signers: n,
            signer_keys,
        };
        (signing_keys, config)
    }

    fn signed_artifact(
        signing_keys: &[SigningKey],
        config: &ThresholdConfig,
        hash: &str,
        count: usize,
    ) -> PublicationArtifact {
        let sigs: Vec<PartialSignature> = signing_keys
            .iter()
            .zip(config.signer_keys.iter())
            .take(count)
            .map(|(sk, key)| test_sign(sk, &key.key_id, hash))
            .collect();
        PublicationArtifact {
            artifact_id: TEST_ARTIFACT_ID.into(),
            connector_id: TEST_CONNECTOR_ID.into(),
            content_hash: hash.to_string(),
            signatures: sigs,
        }
    }

    // === Config validation ===

    #[test]
    fn config_valid() {
        let (_sks, config) = test_config(2, 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn safe_identifier_validation_accepts_only_ascii_identifier_bytes() {
        assert!(validate_safe_identifier("signer-0_ok.v1").is_ok());
        assert_eq!(
            validate_safe_identifier(""),
            Err("identifier cannot be empty")
        );
        assert_eq!(
            validate_safe_identifier("signer-🙂"),
            Err(
                "identifier contains unsafe characters (only alphanumeric, hyphen, underscore, dot allowed)"
            )
        );
        assert_eq!(
            validate_safe_identifier("signer\u{202e}0"),
            Err(
                "identifier contains unsafe characters (only alphanumeric, hyphen, underscore, dot allowed)"
            )
        );
    }

    #[test]
    fn config_threshold_zero_invalid() {
        let (_sks, config) = test_config(0, 3);
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_threshold_exceeds_total() {
        let (_sks, mut config) = test_config(5, 3);
        config.threshold = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_key_count_mismatch() {
        let (_sks, mut config) = test_config(2, 3);
        config.signer_keys.pop();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_duplicate_key_ids_invalid() {
        let (_sks, mut config) = test_config(2, 3);
        config.signer_keys[1].key_id = config.signer_keys[0].key_id.clone();
        assert_eq!(
            config.validate(),
            Err(ThresholdError::ConfigInvalid {
                reason: "duplicate signer key_id signer-0".to_string(),
            })
        );
    }

    #[test]
    fn config_duplicate_public_keys_invalid() {
        let (_sks, mut config) = test_config(2, 3);
        let pk0 = config.signer_keys[0].public_key_hex.clone();
        config.signer_keys[1].public_key_hex = pk0.clone();
        assert_eq!(
            config.validate(),
            Err(ThresholdError::ConfigInvalid {
                reason: format!("duplicate signer public_key_hex {pk0}"),
            })
        );
    }

    #[test]
    fn config_duplicate_public_keys_with_different_hex_case_invalid() {
        let (_sks, mut config) = test_config(2, 3);
        let pk0 = config.signer_keys[0].public_key_hex.clone();
        config.signer_keys[1].public_key_hex = pk0.to_ascii_uppercase();
        assert_eq!(
            config.validate(),
            Err(ThresholdError::ConfigInvalid {
                reason: format!(
                    "duplicate signer public_key_hex {}",
                    config.signer_keys[1].public_key_hex
                ),
            })
        );
    }

    #[test]
    fn config_duplicate_malformed_public_keys_still_use_ascii_case_fold() {
        let (_sks, mut config) = test_config(2, 3);
        config.signer_keys[0].public_key_hex = "ABC".to_string();
        config.signer_keys[1].public_key_hex = "abc".to_string();
        assert_eq!(
            config.validate(),
            Err(ThresholdError::ConfigInvalid {
                reason: "duplicate signer public_key_hex abc".to_string(),
            })
        );
    }

    // === Threshold verification ===

    #[test]
    fn full_quorum_passes() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 3);
        let result = verify_threshold(&config, &artifact, "t1", "ts");
        assert!(result.verified);
        assert_eq!(result.valid_signatures, 3);
    }

    #[test]
    fn exact_threshold_passes() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "t2", "ts");
        assert!(result.verified);
        assert_eq!(result.valid_signatures, 2);
    }

    #[test]
    fn cached_verification_matches_verify_threshold_for_valid_artifact() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        let cached_config = CachedThresholdConfig::new(config.clone()).unwrap();

        let baseline = verify_threshold(&config, &artifact, "t2-cache", "ts");
        let cached = verify_threshold_cached(&cached_config, &artifact, "t2-cache", "ts");

        assert_eq!(cached, baseline);
    }

    #[test]
    fn fixed_buffer_hex_decoders_match_legacy_decode_paths() {
        let signing_key = test_signing_key(7);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let Some(parsed_key) = parse_verifying_key(&public_key_hex) else {
            assert!(false, "public key should parse");
            return;
        };

        assert_eq!(
            parsed_key.to_bytes(),
            signing_key.verifying_key().to_bytes()
        );

        let signature = test_sign(&signing_key, "signer-7", "hash-abc");
        let Some(parsed_signature) = parse_signature(&signature.signature_hex) else {
            assert!(false, "signature should parse");
            return;
        };
        let Ok(legacy_signature_vec) = hex::decode(&signature.signature_hex) else {
            assert!(false, "legacy decode should parse");
            return;
        };
        let Ok(legacy_signature_bytes) = <[u8; 64]>::try_from(legacy_signature_vec) else {
            assert!(false, "legacy signature length should be fixed");
            return;
        };

        assert_eq!(parsed_signature.to_bytes(), legacy_signature_bytes);

        let message = build_signing_message(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, "hash-abc");
        assert!(parsed_key
            .verify_strict(&message, &parsed_signature)
            .is_ok());
    }

    #[test]
    fn prepared_key_lookup_preserves_valid_invalid_and_unknown_cases() {
        let (_sks, mut config) = test_config(2, 3);
        config.signer_keys[1].public_key_hex = "abc".to_string();
        let prepared_keys = PreparedThresholdKeys::new(&config);

        assert!(matches!(
            prepared_keys.lookup_verifying_key("signer-0"),
            VerifyingKeyLookupResult::Valid(_)
        ));
        assert!(matches!(
            prepared_keys.lookup_verifying_key("signer-1"),
            VerifyingKeyLookupResult::Invalid
        ));
        assert!(matches!(
            prepared_keys.lookup_verifying_key("signer-missing"),
            VerifyingKeyLookupResult::Unknown
        ));
    }

    #[test]
    fn below_threshold_rejected() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let result = verify_threshold(&config, &artifact, "t3", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::BelowThreshold { have: 1, need: 2 })
        ));
    }

    #[test]
    fn zero_signatures_rejected() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 0);
        let result = verify_threshold(&config, &artifact, "t4", "ts");
        assert!(!result.verified);
    }

    #[test]
    fn invalid_config_reason_is_not_double_prefixed() {
        let (sks, config) = test_config(0, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 0);
        let result = verify_threshold(&config, &artifact, "t4-invalid", "ts");
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::ConfigInvalid {
                reason: "threshold must be > 0".to_string(),
            })
        );
    }

    #[test]
    fn invalid_artifact_id_rejected() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = String::new();
        let result = verify_threshold(&config, &artifact, "t4-bad-art", "ts");
        assert!(!result.verified);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId {
                reason: "artifact_id must not be empty".to_string(),
            })
        );
    }

    #[test]
    fn invalid_artifact_id_rejected_before_malformed_public_key_preparation() {
        let (sks, mut config) = test_config(2, 3);
        config.signer_keys[1].public_key_hex = "abc".to_string();
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = String::new();

        let result = verify_threshold(&config, &artifact, "t4-bad-art-before-keys", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId {
                reason: "artifact_id must not be empty".to_string(),
            })
        );
    }

    #[test]
    fn invalid_connector_id_rejected() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.connector_id = RESERVED_ARTIFACT_ID.to_string();
        let result = verify_threshold(&config, &artifact, "t4-bad-conn", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { .. })
        ));
    }

    #[test]
    fn duplicate_public_key_config_fails_closed_before_quorum_count() {
        let (sks, mut config) = test_config(2, 2);
        let pk0 = config.signer_keys[0].public_key_hex.clone();
        config.signer_keys[1].public_key_hex = pk0.clone();

        let artifact = PublicationArtifact {
            artifact_id: "art-dup-pubkey".into(),
            connector_id: "conn-1".into(),
            content_hash: "hash-abc".into(),
            signatures: vec![
                test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc"),
                test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc"),
            ],
        };

        let result = verify_threshold(&config, &artifact, "t4-dup-pubkey", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::ConfigInvalid {
                reason: format!("duplicate signer public_key_hex {pk0}"),
            })
        );
    }

    // === Unknown signer ===

    #[test]
    fn unknown_signer_not_counted() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "unknown-signer".into(),
                key_id: "unknown-key".into(),
                signature_hex: "deadbeef00000000".into(),
            },
            MAX_SIGNATURES,
        );
        let result = verify_threshold(&config, &artifact, "t5", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    // === Invalid signature ===

    #[test]
    fn invalid_signature_not_counted() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".into(),
                key_id: "signer-1".into(),
                signature_hex: "badbadbadbadbadb".into(), // wrong signature
            },
            MAX_SIGNATURES,
        );
        let result = verify_threshold(&config, &artifact, "t6", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    #[test]
    fn cached_verification_matches_verify_threshold_for_invalid_signature() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".into(),
                key_id: "signer-1".into(),
                signature_hex: "badbadbadbadbadb".into(),
            },
            MAX_SIGNATURES,
        );
        let cached_config = CachedThresholdConfig::new(config.clone()).unwrap();

        let baseline = verify_threshold(&config, &artifact, "t6-cache", "ts");
        let cached = verify_threshold_cached(&cached_config, &artifact, "t6-cache", "ts");

        assert_eq!(cached, baseline);
    }

    // === Duplicate signer ===

    #[test]
    fn duplicate_signer_counted_once() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        // Add same signer again
        push_bounded(
            &mut artifact.signatures,
            test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc"),
            MAX_SIGNATURES,
        );
        let result = verify_threshold(&config, &artifact, "t7", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::DuplicateSigner {
                signer_id: "signer-0".to_string(),
            })
        );
    }

    #[test]
    fn duplicate_key_with_different_signer_id_rejected_as_invalid() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);

        let mut replay = test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc");
        replay.signer_id = "signer-0-alias".to_string();
        push_bounded(&mut artifact.signatures, replay, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t7b", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature { .. })
        ));
    }

    #[test]
    fn mismatched_signer_id_does_not_count_toward_quorum() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);

        let mut replay = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        replay.signer_id = "signer-0".to_string();
        push_bounded(&mut artifact.signatures, replay, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t7c", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-0".to_string(),
            })
        );
    }

    // === Trace and timestamp ===

    #[test]
    fn result_has_trace_id() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "trace-xyz", "ts");
        assert_eq!(result.trace_id, "trace-xyz");
    }

    // === sign helper ===

    #[test]
    fn signing_message_layout_is_domain_separated_and_length_prefixed() {
        let message = build_signing_message("art", "conn", "hash");
        let mut expected = Vec::new();
        expected.extend_from_slice(SIGNING_MESSAGE_DOMAIN);
        expected.extend_from_slice(&3_u64.to_le_bytes());
        expected.extend_from_slice(b"art");
        expected.extend_from_slice(&4_u64.to_le_bytes());
        expected.extend_from_slice(b"conn");
        expected.extend_from_slice(&4_u64.to_le_bytes());
        expected.extend_from_slice(b"hash");

        assert_eq!(message, expected);
    }

    #[test]
    fn inline_signing_message_matches_vec_layout_for_digest_sized_hashes() {
        let content_hash = "a".repeat(INLINE_SIGNING_MESSAGE_CONTENT_HASH_BYTES);
        let inline_message =
            SigningMessage::new(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, &content_hash);
        let expected = build_signing_message(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, &content_hash);

        assert!(matches!(inline_message, SigningMessage::Inline { .. }));
        assert_eq!(inline_message.as_slice(), expected.as_slice());
    }

    #[test]
    fn oversized_signing_message_uses_heap_layout_without_changing_bytes() {
        let content_hash = "a".repeat(INLINE_SIGNING_MESSAGE_CONTENT_HASH_BYTES + 1);
        let heap_message = SigningMessage::new(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, &content_hash);
        let expected = build_signing_message(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, &content_hash);

        assert!(matches!(heap_message, SigningMessage::Heap(_)));
        assert_eq!(heap_message.as_slice(), expected.as_slice());
    }

    #[test]
    fn sign_deterministic() {
        let sk = test_signing_key(0);
        let s1 = test_sign(&sk, "signer-0", "hash");
        let s2 = test_sign(&sk, "signer-0", "hash");
        assert_eq!(s1.signature_hex, s2.signature_hex);
    }

    #[test]
    fn sign_different_for_different_hashes() {
        let sk = test_signing_key(0);
        let s1 = test_sign(&sk, "signer-0", "hash-a");
        let s2 = test_sign(&sk, "signer-0", "hash-b");
        assert_ne!(s1.signature_hex, s2.signature_hex);
    }

    #[test]
    fn sign_different_for_different_publication_contexts() {
        let sk = test_signing_key(0);
        let by_artifact = sign(&sk, "signer-0", "art-a", TEST_CONNECTOR_ID, "hash");
        let other_artifact = sign(&sk, "signer-0", "art-b", TEST_CONNECTOR_ID, "hash");
        let other_connector = sign(&sk, "signer-0", "art-a", "conn-b", "hash");

        assert_ne!(by_artifact.signature_hex, other_artifact.signature_hex);
        assert_ne!(by_artifact.signature_hex, other_connector.signature_hex);
    }

    #[test]
    fn signature_verification_helpers_agree_on_valid_and_invalid_signatures() {
        let (sks, config) = test_config(1, 1);
        let key = &config.signer_keys[0];
        let valid_signature = test_sign(&sks[0], &key.key_id, "hash-abc");
        let message = build_signing_message(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, "hash-abc");
        let parsed_key = parse_verifying_key(&key.public_key_hex).unwrap();

        assert!(verify_signature(
            key,
            TEST_ARTIFACT_ID,
            TEST_CONNECTOR_ID,
            "hash-abc",
            &valid_signature
        ));
        assert!(verify_signature_with_message(
            key,
            &message,
            &valid_signature
        ));
        assert!(verify_signature_with_parsed_key(
            &parsed_key,
            &message,
            &valid_signature
        ));

        let invalid_signature = PartialSignature {
            signer_id: valid_signature.signer_id.clone(),
            key_id: valid_signature.key_id.clone(),
            signature_hex: "deadbeef".to_string(),
        };

        assert!(!verify_signature(
            key,
            TEST_ARTIFACT_ID,
            TEST_CONNECTOR_ID,
            "hash-abc",
            &invalid_signature
        ));
        assert!(!verify_signature_with_message(
            key,
            &message,
            &invalid_signature
        ));
        assert!(!verify_signature_with_parsed_key(
            &parsed_key,
            &message,
            &invalid_signature
        ));
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_result() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "t8", "ts");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn serde_roundtrip_config() {
        let (_sks, config) = test_config(2, 3);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ThresholdConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = ThresholdError::BelowQuorum { have: 1, need: 2 };
        assert!(e1.to_string().contains("THRESH_BELOW_QUORUM"));

        let e2 = ThresholdError::UnknownSigner {
            signer_id: "x".into(),
        };
        assert!(e2.to_string().contains("THRESH_UNKNOWN_SIGNER"));

        let e3 = ThresholdError::InvalidSignature {
            signer_id: "y".into(),
        };
        assert!(e3.to_string().contains("THRESH_INVALID_SIG"));

        let e4 = ThresholdError::ConfigInvalid {
            reason: "bad".into(),
        };
        assert!(e4.to_string().contains("THRESH_CONFIG_INVALID"));
    }

    // === Failure reason display ===

    #[test]
    fn failure_reason_display() {
        let r = FailureReason::BelowThreshold { have: 1, need: 3 };
        assert!(r.to_string().contains("THRESH_BELOW_QUORUM"));
    }

    #[test]
    fn reserved_artifact_id_rejected_before_quorum_counting() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = RESERVED_ARTIFACT_ID.to_string();

        let result = verify_threshold(&config, &artifact, "t-reserved-art", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("reserved")
        ));
    }

    #[test]
    fn whitespace_artifact_id_rejected_before_signature_validation() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = " art-1".into();
        artifact.signatures[0].signature_hex = "not-hex".into();

        let result = verify_threshold(&config, &artifact, "t-space-art", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("leading or trailing whitespace")
        ));
    }

    #[test]
    fn empty_connector_id_rejected_before_signature_validation() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.connector_id = String::new();
        artifact.signatures[0].signature_hex = "not-hex".into();

        let result = verify_threshold(&config, &artifact, "t-empty-conn", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId {
                reason: "connector_id must not be empty".to_string(),
            })
        );
    }

    #[test]
    fn config_error_precedes_invalid_artifact_id() {
        let (sks, mut config) = test_config(2, 3);
        config.signer_keys.pop();
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = RESERVED_ARTIFACT_ID.to_string();

        let result = verify_threshold(&config, &artifact, "t-config-first", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::ConfigInvalid { ref reason })
                if reason.contains("signer_keys count")
        ));
    }

    #[test]
    fn malformed_public_key_hex_does_not_count_signature() {
        let (sks, mut config) = test_config(2, 3);
        config.signer_keys[1].public_key_hex = "not-hex".into();
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);

        let result = verify_threshold(&config, &artifact, "t-bad-pubkey", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn signature_for_different_content_hash_does_not_count() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-other"),
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-wrong-message", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn invalid_signature_does_not_poison_later_valid_same_signer() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".into(),
                key_id: "signer-1".into(),
                signature_hex: "not-hex".into(),
            },
            MAX_SIGNATURES,
        );
        push_bounded(
            &mut artifact.signatures,
            test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc"),
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-invalid-then-valid", "ts");

        assert!(result.verified);
        assert_eq!(result.valid_signatures, 2);
        assert_eq!(result.failure_reason, None);
    }

    #[test]
    fn duplicate_valid_signature_after_threshold_still_fails_if_threshold_not_met() {
        let (sks, config) = test_config(3, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        push_bounded(
            &mut artifact.signatures,
            test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc"),
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-duplicate-below", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 2);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::DuplicateSigner {
                signer_id: "signer-0".to_string(),
            })
        );
    }

    #[test]
    fn reserved_connector_id_rejected_before_quorum_counting() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.connector_id = RESERVED_ARTIFACT_ID.to_string();

        let result = verify_threshold(&config, &artifact, "t-reserved-conn", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("reserved")
        ));
    }

    #[test]
    fn whitespace_connector_id_rejected_before_invalid_signature() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.connector_id = "connector-1 ".to_string();
        artifact.signatures[0].signature_hex = "not-hex".to_string();

        let result = verify_threshold(&config, &artifact, "t-space-conn", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("leading or trailing whitespace")
        ));
    }

    #[test]
    fn whitespace_only_artifact_id_rejected_as_empty() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = "   ".to_string();

        let result = verify_threshold(&config, &artifact, "t-space-only-art", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId {
                reason: "artifact_id must not be empty".to_string(),
            })
        );
    }

    #[test]
    fn short_signature_hex_does_not_count_toward_threshold() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: "abcd".to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-short-sig", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn signer_id_case_mismatch_rejected_even_with_valid_key_signature() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let mut replay = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        replay.signer_id = "Signer-1".to_string();
        push_bounded(&mut artifact.signatures, replay, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t-case-mismatch", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "Signer-1".to_string(),
            })
        );
    }

    #[test]
    fn unknown_signer_failure_is_preserved_when_later_invalid_signature_also_fails() {
        let (sks, config) = test_config(3, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "unknown-signer".to_string(),
                key_id: "unknown-signer".to_string(),
                signature_hex: "deadbeef".to_string(),
            },
            MAX_SIGNATURES,
        );
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: "not-hex".to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-first-failure", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::UnknownSigner {
                signer_id: "unknown-signer".to_string(),
            })
        );
    }

    #[test]
    fn raw_content_hash_signature_without_domain_separator_is_rejected() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let raw_signature = sks[1].sign(b"hash-abc");
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: hex::encode(raw_signature.to_bytes()),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-raw-message", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn empty_signer_id_for_known_key_is_rejected() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let mut detached_identity = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        detached_identity.signer_id.clear();
        push_bounded(&mut artifact.signatures, detached_identity, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t-empty-signer-id", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: String::new(),
            })
        );
    }

    #[test]
    fn whitespace_key_id_is_unknown_even_when_signature_bytes_are_valid() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let mut shifted_key = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        shifted_key.signer_id = "signer-1 ".to_string();
        shifted_key.key_id = "signer-1 ".to_string();
        push_bounded(&mut artifact.signatures, shifted_key, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t-whitespace-key", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::UnknownSigner {
                signer_id: "signer-1 ".to_string(),
            })
        );
    }

    #[test]
    fn zeroed_signature_bytes_do_not_count_toward_threshold() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: hex::encode([0_u8; 64]),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-zeroed-signature", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn invalid_signature_failure_is_preserved_when_later_unknown_signer_also_fails() {
        let (sks, config) = test_config(3, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: "not-hex".to_string(),
            },
            MAX_SIGNATURES,
        );
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "unknown-signer".to_string(),
                key_id: "unknown-signer".to_string(),
                signature_hex: "deadbeef".to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-invalid-first", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn zero_signatures_reports_exact_below_threshold_counts() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 0);

        let result = verify_threshold(&config, &artifact, "t-empty-signatures", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::BelowThreshold { have: 0, need: 2 })
        );
    }

    #[test]
    fn short_public_key_bytes_do_not_count_signature() {
        let (sks, mut config) = test_config(2, 3);
        config.signer_keys[1].public_key_hex = hex::encode([7_u8; 31]);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);

        let result = verify_threshold(&config, &artifact, "t-short-pubkey", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn odd_length_public_key_hex_does_not_count_signature() {
        let (sks, mut config) = test_config(2, 3);
        config.signer_keys[1].public_key_hex = "abc".to_string();
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);

        let result = verify_threshold(&config, &artifact, "t-odd-pubkey", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn odd_length_signature_hex_does_not_count_toward_threshold() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: "abc".to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-odd-sig", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn empty_signature_hex_does_not_count_toward_threshold() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: String::new(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-empty-sig", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn known_signer_label_with_unknown_key_id_is_unknown() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let mut detached = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        detached.key_id = "signer-missing".to_string();
        push_bounded(&mut artifact.signatures, detached, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t-missing-key-id", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::UnknownSigner {
                signer_id: "signer-1".to_string(),
            })
        );
    }

    #[test]
    fn signature_replayed_under_different_known_key_is_rejected() {
        let (sks, config) = test_config(2, 3);
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        let mut replay = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        replay.signer_id = "signer-2".to_string();
        replay.key_id = "signer-2".to_string();
        push_bounded(&mut artifact.signatures, replay, MAX_SIGNATURES);

        let result = verify_threshold(&config, &artifact, "t-wrong-key-replay", "ts");

        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature {
                signer_id: "signer-2".to_string(),
            })
        );
    }

    #[test]
    fn serde_rejects_config_missing_signer_keys() {
        let decoded =
            serde_json::from_str::<ThresholdConfig>(r#"{"threshold":2,"total_signers":3}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_partial_signature_missing_signature_hex() {
        let decoded = serde_json::from_str::<PartialSignature>(
            r#"{"signer_id":"signer-1","key_id":"signer-1"}"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_publication_artifact_signatures_as_object() {
        let decoded = serde_json::from_str::<PublicationArtifact>(
            r#"{
                "artifact_id":"art-1",
                "connector_id":"conn-1",
                "content_hash":"hash-abc",
                "signatures":{"signer-1":"sig"}
            }"#,
        );

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_unknown_failure_reason_variant() {
        let decoded = serde_json::from_str::<FailureReason>(r#"{"unknown_reason":{"x":1}}"#);

        assert!(decoded.is_err());
    }

    #[test]
    fn serde_rejects_unknown_threshold_error_variant() {
        let decoded = serde_json::from_str::<ThresholdError>(r#"{"THRESH_NOT_REAL":{"x":1}}"#);

        assert!(decoded.is_err());
    }

    // === NEGATIVE-PATH SECURITY TESTS ===

    #[test]
    fn cryptographic_forge_signature_and_replay_attacks_fail_with_proper_rejection() {
        let (sks, config) = test_config(2, 3);

        // Attempt signature forgery with completely invalid signature bytes
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: "deadbeefcafebabe".repeat(8), // 64 bytes of garbage
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-forge", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);

        // Cross-message signature replay attack
        let valid_sig_hash_a = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-a");
        let mut replay_artifact = signed_artifact(&sks, &config, "hash-b", 1);
        push_bounded(
            &mut replay_artifact.signatures,
            PartialSignature {
                signer_id: valid_sig_hash_a.signer_id,
                key_id: valid_sig_hash_a.key_id,
                signature_hex: valid_sig_hash_a.signature_hex,
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &replay_artifact, "t-replay", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);

        // Signature malleability attack (flipping bits to try different valid points)
        let valid_sig = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");
        let mut malleable_bytes = hex::decode(&valid_sig.signature_hex).unwrap();
        malleable_bytes[0] ^= 0x01; // Flip a bit
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: hex::encode(malleable_bytes),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-malleable", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);

        // Public key substitution attack (valid signature for wrong key)
        let (other_sks, _) = test_keys(1);
        let wrong_key_sig = other_sks[0].sign(&build_signing_message(
            TEST_ARTIFACT_ID,
            TEST_CONNECTOR_ID,
            "hash-abc",
        ));
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: hex::encode(wrong_key_sig.to_bytes()),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-wrong-key", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);
    }

    #[test]
    fn threshold_bypass_and_vote_stuffing_attacks_fail_closed() {
        let (sks, config) = test_config(3, 5);

        // Attempt to bypass threshold by using duplicate keys with different signer IDs
        let valid_sig = test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc");
        let mut duplicate_votes = Vec::new();

        // Try to use same key signature with different signer aliases
        for i in 0..10 {
            push_bounded(
                &mut duplicate_votes,
                PartialSignature {
                    signer_id: format!("signer-0-alias-{}", i),
                    key_id: config.signer_keys[0].key_id.clone(),
                    signature_hex: valid_sig.signature_hex.clone(),
                },
                MAX_SIGNATURES,
            );
        }

        let artifact = PublicationArtifact {
            artifact_id: "vote-stuffing-test".to_string(),
            connector_id: "conn-1".to_string(),
            content_hash: "hash-abc".to_string(),
            signatures: duplicate_votes,
        };

        let result = verify_threshold(&config, &artifact, "t-vote-stuff", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0); // All rejected due to identity mismatch

        // Attempt threshold bypass with key replay under different identities
        let mut replay_artifact = signed_artifact(&sks, &config, "hash-abc", 2);

        // Add replayed signatures under bogus identities
        let sig1 = test_sign(&sks[0], &config.signer_keys[0].key_id, "hash-abc");
        let sig2 = test_sign(&sks[1], &config.signer_keys[1].key_id, "hash-abc");

        replay_artifact.signatures.extend([
            PartialSignature {
                signer_id: "admin".to_string(),
                key_id: sig1.key_id.clone(),
                signature_hex: sig1.signature_hex.clone(),
            },
            PartialSignature {
                signer_id: "root".to_string(),
                key_id: sig2.key_id,
                signature_hex: sig2.signature_hex,
            },
            PartialSignature {
                signer_id: "superuser".to_string(),
                key_id: sig1.key_id,
                signature_hex: sig1.signature_hex,
            },
        ]);

        let result = verify_threshold(&config, &replay_artifact, "t-replay-bypass", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 2); // Only the original 2 count

        // Test arithmetic overflow in threshold validation
        let mut overflow_config = config.clone();
        overflow_config.threshold = u32::MAX;
        overflow_config.total_signers = u32::MAX;

        let result = verify_threshold(&overflow_config, &replay_artifact, "t-overflow", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::ConfigInvalid { .. })
        ));
    }

    #[test]
    fn malicious_configuration_and_key_manipulation_attacks_fail_closed() {
        // Test configuration with zero total signers
        let mut malicious_config = ThresholdConfig {
            threshold: 1,
            total_signers: 0,
            signer_keys: vec![],
        };
        assert!(malicious_config.validate().is_err());

        // Test configuration with threshold greater than max possible
        malicious_config.threshold = u32::MAX;
        malicious_config.total_signers = 1;
        assert!(malicious_config.validate().is_err());

        // Test public key collision attack (same key, different IDs)
        let (sks, mut config) = test_config(2, 3);
        let first_pubkey = config.signer_keys[0].public_key_hex.clone();
        config.signer_keys[1].public_key_hex = first_pubkey.clone();
        config.signer_keys[2].public_key_hex = first_pubkey;

        assert!(config.validate().is_err());

        // Test malformed public key hex injection
        config.signer_keys[0].public_key_hex = "not_valid_hex".to_string();
        config.signer_keys[1].public_key_hex = hex::encode(vec![0u8; 33]); // Wrong length
        config.signer_keys[2].public_key_hex = "".to_string(); // Empty

        let artifact = signed_artifact(&sks, &config, "hash-abc", 3);
        let result = verify_threshold(&config, &artifact, "t-malformed", "ts");
        assert!(!result.verified);

        // Test key ID injection attacks
        let (_sks, mut injection_config) = test_config(2, 2);
        injection_config.signer_keys[0].key_id = "signer\0null".to_string();
        injection_config.signer_keys[1].key_id = "signer\nseparator".to_string();

        let artifact = PublicationArtifact {
            artifact_id: "injection-test".to_string(),
            connector_id: "conn-1".to_string(),
            content_hash: "hash-abc".to_string(),
            signatures: vec![
                PartialSignature {
                    signer_id: "signer\0null".to_string(),
                    key_id: "signer\0null".to_string(),
                    signature_hex: "00".repeat(64),
                },
                PartialSignature {
                    signer_id: "signer\nseparator".to_string(),
                    key_id: "signer\nseparator".to_string(),
                    signature_hex: "ff".repeat(64),
                },
            ],
        };

        // These should be treated as unknown signers due to exact matching requirements
        let result = verify_threshold(&injection_config, &artifact, "t-injection", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
    }

    #[test]
    fn unicode_injection_and_identity_spoofing_attacks_fail_with_proper_isolation() {
        let (sks, mut config) = test_config(2, 3);

        // Unicode BiDi override attacks in signer IDs
        let bidi_id = "\u{202E}regnis\u{202C}signer-0"; // "singer" reversed with BiDi override
        let zero_width_id = "signer-\u{200B}0"; // Zero-width space
        let mixed_script_id = "sіgner-0"; // Cyrillic 'і' instead of Latin 'i'

        config.signer_keys[0].key_id = bidi_id.to_string();
        config.signer_keys[1].key_id = zero_width_id.to_string();
        config.signer_keys[2].key_id = mixed_script_id.to_string();

        let artifact = PublicationArtifact {
            artifact_id: "unicode-test".to_string(),
            connector_id: "conn-1".to_string(),
            content_hash: "hash-abc".to_string(),
            signatures: vec![
                PartialSignature {
                    signer_id: "signer-0".to_string(), // Trying to match without Unicode
                    key_id: bidi_id.to_string(),
                    signature_hex: hex::encode([0u8; 64]),
                },
                PartialSignature {
                    signer_id: zero_width_id.to_string(),
                    key_id: "signer-0".to_string(), // Trying reverse match
                    signature_hex: hex::encode([1u8; 64]),
                },
                PartialSignature {
                    signer_id: "signer-0".to_string(), // Normal ASCII attempt
                    key_id: mixed_script_id.to_string(),
                    signature_hex: hex::encode([2u8; 64]),
                },
            ],
        };

        let result = verify_threshold(&config, &artifact, "t-unicode", "ts");
        assert!(!result.verified);

        // Test Unicode normalization attacks (NFC vs NFD)
        let nfc_id = "sígner-café"; // NFC normalized
        let nfd_id = "si\u{0301}gner-cafe\u{0301}"; // NFD normalized (same visual, different bytes)

        config.signer_keys[0].key_id = nfc_id.to_string();

        let artifact = PublicationArtifact {
            artifact_id: "normalization-test".to_string(),
            connector_id: "conn-1".to_string(),
            content_hash: "hash-abc".to_string(),
            signatures: vec![PartialSignature {
                signer_id: nfd_id.to_string(), // Different normalization
                key_id: nfc_id.to_string(),
                signature_hex: hex::encode([0u8; 64]),
            }],
        };

        let result = verify_threshold(&config, &artifact, "t-normalization", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidSignature { .. })
        ));
    }

    #[test]
    fn hex_parsing_buffer_overflow_and_injection_attacks_fail_safely() {
        let (sks, config) = test_config(2, 3);

        // Massive hex string to trigger potential buffer overflow
        let massive_sig = "00".repeat(1_000_000); // 2MB hex string
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: massive_sig,
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-massive", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 1);

        // Hex injection with control characters and null bytes
        let control_hex = "001122\0aabbcc\r\n33445566";
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-2".to_string(),
                key_id: "signer-2".to_string(),
                signature_hex: control_hex.to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-control", "ts");
        assert!(!result.verified);

        // Unicode hex characters (should be rejected as non-ASCII)
        let unicode_hex = "𝟎𝟎𝟏𝟏𝟐𝟐𝟑𝟑"; // Unicode mathematical digits
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-2".to_string(),
                key_id: "signer-2".to_string(),
                signature_hex: unicode_hex.to_string(),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-unicode-hex", "ts");
        assert!(!result.verified);

        // Integer overflow in hex parsing (extreme lengths)
        let length_attack = "ff".repeat(ED25519_SIGNATURE_HEX_LEN + 1);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-2".to_string(),
                key_id: "signer-2".to_string(),
                signature_hex: length_attack,
            },
            MAX_SIGNATURES,
        );

        // Should not crash, just fail verification
        let result = verify_threshold(&config, &artifact, "t-overflow-hex", "ts");
        assert!(!result.verified);

        // Mixed case hex with embedded whitespace
        let spaced_hex = "00 11 22 33 44 55 66 77".repeat(8);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-2".to_string(),
                key_id: "signer-2".to_string(),
                signature_hex: spaced_hex,
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-spaced", "ts");
        assert!(!result.verified);
    }

    #[test]
    fn artifact_id_injection_and_validation_bypass_attacks_fail_closed() {
        let (sks, config) = test_config(2, 3);

        // JSON injection in artifact ID
        let json_injection = r#"{"malicious": "payload"}"#;
        let mut artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        artifact.artifact_id = json_injection.to_string();

        let result = verify_threshold(&config, &artifact, "t-json", "ts");
        assert!(result.verified); // Valid JSON string as artifact ID should work

        // SQL injection in artifact ID
        artifact.artifact_id = "'; DROP TABLE artifacts; --".to_string();
        let result = verify_threshold(&config, &artifact, "t-sql", "ts");
        assert!(result.verified); // SQL injection string should be treated as literal

        // Script injection in artifact ID
        artifact.artifact_id = "<script>alert('xss')</script>".to_string();
        let result = verify_threshold(&config, &artifact, "t-script", "ts");
        assert!(result.verified); // Script string should be treated as literal

        // Control character injection
        artifact.artifact_id = "artifact\0null\nid".to_string();
        let result = verify_threshold(&config, &artifact, "t-control-art", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("null bytes")
        ));

        artifact.artifact_id = "../escaped-artifact".to_string();
        let result = verify_threshold(&config, &artifact, "t-parent-art", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("parent-directory")
        ));

        artifact.artifact_id = "/absolute-artifact".to_string();
        let result = verify_threshold(&config, &artifact, "t-absolute-art", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("must not start")
        ));

        artifact.artifact_id = r"windows\artifact".to_string();
        let result = verify_threshold(&config, &artifact, "t-backslash-art", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("backslashes")
        ));

        // Unicode injection in connector ID
        artifact.artifact_id = "artifact-valid".to_string();
        artifact.connector_id = "\u{202E}evil\u{202C}connector".to_string();
        let result = verify_threshold(&config, &artifact, "t-unicode-conn", "ts");
        assert!(result.verified); // Unicode in connector ID should be allowed

        artifact.connector_id = "connector\0null".to_string();
        let result = verify_threshold(&config, &artifact, "t-null-conn", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("null bytes")
        ));

        artifact.connector_id = "connectors/../admin".to_string();
        let result = verify_threshold(&config, &artifact, "t-parent-conn", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("parent-directory")
        ));

        artifact.connector_id = "/root-connector".to_string();
        let result = verify_threshold(&config, &artifact, "t-absolute-conn", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("must not start")
        ));

        artifact.connector_id = r"connectors\root".to_string();
        let result = verify_threshold(&config, &artifact, "t-backslash-conn", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("backslashes")
        ));

        // Extremely long IDs to test memory exhaustion
        artifact.connector_id = "connector-valid".to_string();
        artifact.artifact_id = "x".repeat(1_000_000);
        artifact.connector_id = "y".repeat(1_000_000);
        let result = verify_threshold(&config, &artifact, "t-huge-ids", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { ref reason })
                if reason.contains("must not exceed")
        ));

        artifact.artifact_id = "artifact-valid".to_string();
        artifact.connector_id = "y".repeat(1_000_000);
        let result = verify_threshold(&config, &artifact, "t-huge-connector", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidConnectorId { ref reason })
                if reason.contains("must not exceed")
        ));

        // Test reserved identifier bypass attempts
        artifact.artifact_id = format!(" {} ", RESERVED_ARTIFACT_ID); // Padded reserved ID
        let result = verify_threshold(&config, &artifact, "t-reserved-bypass", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { .. })
        ));

        // Test whitespace normalization bypass
        artifact.artifact_id = "normal-id\t".to_string(); // Trailing tab
        let result = verify_threshold(&config, &artifact, "t-tab-bypass", "ts");
        assert!(!result.verified);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn serialization_corruption_and_json_injection_attacks_fail_safely() {
        let (sks, config) = test_config(2, 3);
        let artifact = signed_artifact(&sks, &config, "hash-abc", 2);
        let result = verify_threshold(&config, &artifact, "t-serialize", "ts");

        // Test serialization of result with injection payloads
        assert!(result.verified);

        // Test malformed JSON deserialization attacks
        let malformed_json = r#"{"verified": true, "valid_signatures": "not_a_number"}"#;
        let parsed = serde_json::from_str::<VerificationResult>(malformed_json);
        assert!(parsed.is_err());

        // Test JSON injection in trace_id field
        let injection_trace = r#"", "injected": "field", "fake_verified": true, "real_trace": ""#;
        let result = verify_threshold(&config, &artifact, injection_trace, "ts");

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(
            !serialized.contains(r#""injected":"#),
            "JSON injection should be escaped"
        );
        assert!(
            serialized.contains("field"),
            "Content should be preserved but escaped"
        );

        // Test extremely long field values
        let huge_trace = "x".repeat(1_000_000);
        let result = verify_threshold(&config, &artifact, &huge_trace, "ts");
        let serialized = serde_json::to_string(&result);
        assert!(
            serialized.is_ok(),
            "Large trace IDs should serialize safely"
        );

        // Test Unicode in all result fields
        let unicode_artifact = PublicationArtifact {
            artifact_id: "artifact-🦀".to_string(),
            connector_id: "connector-🌍".to_string(),
            content_hash: "hash-café".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(&config, &unicode_artifact, "trace-🚀", "timestamp-⏰");
        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: VerificationResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(result.artifact_id, deserialized.artifact_id);
        assert_eq!(result.trace_id, deserialized.trace_id);

        // Test FailureReason serialization with injection payloads
        let failure_with_injection = FailureReason::InvalidSignature {
            signer_id: r#"{"evil": "payload"}"#.to_string(),
        };

        let failure_json = serde_json::to_string(&failure_with_injection).unwrap();
        assert!(
            !failure_json.contains(r#""evil":"#),
            "Injection should be escaped"
        );
    }

    #[test]
    fn failure_reason_display_escapes_control_characters() {
        let display = FailureReason::InvalidSignature {
            signer_id: "signer\nbad\t\u{0000}".to_string(),
        }
        .to_string();

        assert!(display.contains("\\n"));
        assert!(display.contains("\\t"));
        assert!(
            !display
                .chars()
                .any(|ch| matches!(ch, '\n' | '\r' | '\t' | '\0')),
            "display output must not contain raw control characters: {display:?}"
        );
    }

    #[test]
    fn threshold_error_display_escapes_control_characters() {
        let display = ThresholdError::ConfigInvalid {
            reason: "duplicate signer key_id signer\n0".to_string(),
        }
        .to_string();

        assert!(display.contains("\\n"));
        assert!(
            !display
                .chars()
                .any(|ch| matches!(ch, '\n' | '\r' | '\t' | '\0')),
            "display output must not contain raw control characters: {display:?}"
        );
    }

    #[test]
    fn domain_separator_bypass_and_message_substitution_attacks_fail_with_rejection() {
        let (sks, config) = test_config(2, 3);

        // Attempt to forge signature by signing raw content hash without domain separator
        let raw_content = "hash-abc";
        let raw_signature = sks[0].sign(raw_content.as_bytes());
        let mut artifact = signed_artifact(&sks, &config, raw_content, 0);

        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-0".to_string(),
                key_id: "signer-0".to_string(),
                signature_hex: hex::encode(raw_signature.to_bytes()),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-raw-bypass", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);

        // Attempt to substitute domain separator
        let mut fake_message = Vec::new();
        fake_message.extend_from_slice(b"fake_domain_separator:");
        let raw_content_len = u64::try_from(raw_content.len()).unwrap_or(u64::MAX);
        fake_message.extend_from_slice(&raw_content_len.to_le_bytes());
        fake_message.extend_from_slice(raw_content.as_bytes());

        let fake_signature = sks[1].sign(&fake_message);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-1".to_string(),
                key_id: "signer-1".to_string(),
                signature_hex: hex::encode(fake_signature.to_bytes()),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-fake-domain", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);

        // Attempt length extension attack
        let mut extended_message =
            build_signing_message(TEST_ARTIFACT_ID, TEST_CONNECTOR_ID, raw_content);
        extended_message.extend_from_slice(b"evil_extension");

        let extended_signature = sks[2].sign(&extended_message);
        push_bounded(
            &mut artifact.signatures,
            PartialSignature {
                signer_id: "signer-2".to_string(),
                key_id: "signer-2".to_string(),
                signature_hex: hex::encode(extended_signature.to_bytes()),
            },
            MAX_SIGNATURES,
        );

        let result = verify_threshold(&config, &artifact, "t-extension", "ts");
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);

        let mut valid_artifact = PublicationArtifact {
            artifact_id: "valid-test".to_string(),
            connector_id: "conn-1".to_string(),
            content_hash: raw_content.to_string(),
            signatures: vec![],
        };

        // Test that proper domain-separated signatures work.
        let proper_signature = sign(
            &sks[0],
            &config.signer_keys[0].key_id,
            &valid_artifact.artifact_id,
            &valid_artifact.connector_id,
            raw_content,
        );
        valid_artifact.signatures.push(proper_signature);

        let valid_sig_2 = sign(
            &sks[1],
            &config.signer_keys[1].key_id,
            &valid_artifact.artifact_id,
            &valid_artifact.connector_id,
            raw_content,
        );
        push_bounded(&mut valid_artifact.signatures, valid_sig_2, MAX_SIGNATURES);

        let result = verify_threshold(&config, &valid_artifact, "t-valid", "ts");
        assert!(result.verified);
        assert_eq!(result.valid_signatures, 2);
    }

    #[test]
    fn concurrent_verification_and_race_condition_safety_validation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let (sks, config) = test_config(2, 3);
        let config = Arc::new(config);
        let artifact = Arc::new(signed_artifact(&sks, &config, "hash-abc", 3));
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        // Concurrent verification attempts
        for i in 0..50 {
            let config_clone = Arc::clone(&config);
            let artifact_clone = Arc::clone(&artifact);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let result = verify_threshold(
                    &*config_clone,
                    &*artifact_clone,
                    &format!("trace-{}", i),
                    &format!("ts-{}", i),
                );

                let mut results = results_clone.lock().unwrap();
                push_bounded(
                    &mut results,
                    (i, result.verified, result.valid_signatures),
                    MAX_TEST_RESULTS,
                );
            });

            push_bounded(&mut handles, handle, MAX_TEST_RESULTS);
        }

        // Wait for all verifications to complete
        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 50);

        // All verifications should produce identical results (deterministic)
        for (i, verified, valid_count) in results.iter() {
            assert!(*verified, "Thread {} verification should succeed", i);
            assert_eq!(
                *valid_count, 3,
                "Thread {} should count 3 valid signatures",
                i
            );
        }

        // Test concurrent modification of artifacts (should be isolated)
        let mut modification_handles = vec![];
        let shared_counter = Arc::new(Mutex::new(0));

        for i in 0..20 {
            let config_clone = Arc::clone(&config);
            let counter_clone = Arc::clone(&shared_counter);

            let handle = thread::spawn(move || {
                // Each thread creates its own artifact
                let mut local_artifact = PublicationArtifact {
                    artifact_id: format!("concurrent-{}", i),
                    connector_id: "conn-1".to_string(),
                    content_hash: format!("hash-{}", i),
                    signatures: vec![],
                };

                // Add signatures based on thread ID
                push_bounded(
                    &mut local_artifact.signatures,
                    PartialSignature {
                        signer_id: "signer-0".to_string(),
                        key_id: "signer-0".to_string(),
                        signature_hex: format!("{:064x}", i),
                    },
                    MAX_SIGNATURES,
                );

                let result =
                    verify_threshold(&*config_clone, &local_artifact, &format!("t-{}", i), "ts");

                // Count failed verifications (expected due to invalid signatures)
                if !result.verified {
                    let mut counter = counter_clone.lock().unwrap();
                    *counter = (*counter).saturating_add(1);
                }
            });

            push_bounded(&mut modification_handles, handle, MAX_TEST_RESULTS);
        }

        for handle in modification_handles {
            handle.join().unwrap();
        }

        // All should fail verification due to invalid signatures
        let final_count = *shared_counter.lock().unwrap();
        assert_eq!(
            final_count, 20,
            "All concurrent invalid signatures should be rejected"
        );
    }

    // -- Negative-Path Tests --

    #[test]
    fn negative_massive_threshold_configuration_boundary_testing() {
        // Test threshold configurations at extreme boundaries
        let extreme_configs = vec![
            // Zero threshold (invalid)
            ThresholdConfig {
                threshold: 0,
                total_signers: 5,
                signer_keys: vec![],
            },
            // Threshold exceeds total signers (invalid)
            ThresholdConfig {
                threshold: 10,
                total_signers: 5,
                signer_keys: vec![],
            },
            // Maximum valid threshold
            ThresholdConfig {
                threshold: u32::MAX,
                total_signers: u32::MAX,
                signer_keys: vec![],
            },
            // Single signer, threshold 1 (edge case)
            ThresholdConfig {
                threshold: 1,
                total_signers: 1,
                signer_keys: vec![SignerKey {
                    key_id: "solo-signer".to_string(),
                    public_key_hex: "deadbeef".repeat(8),
                }],
            },
        ];

        for (i, config) in extreme_configs.iter().enumerate() {
            let validation_result = config.validate();

            match i {
                0 | 1 => {
                    // First two configs should fail validation
                    assert!(validation_result.is_err(), "Config {} should be invalid", i);
                    if let Err(err) = validation_result {
                        assert!(matches!(err, ThresholdError::ConfigInvalid { .. }));
                    }
                }
                2 => {
                    // Maximum config should fail due to empty signer_keys
                    assert!(validation_result.is_err());
                }
                3 => {
                    // Single signer should be valid
                    assert!(
                        validation_result.is_ok(),
                        "Single signer config should be valid"
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn negative_unicode_injection_in_cryptographic_identifiers() {
        // Test Unicode and control character injection in cryptographic identifiers
        let (_, mut base_config) = test_config(2, 3);

        let malicious_identifiers = vec![
            "signer\0null-injection",
            "signer🚀emoji-attack",
            "signer\u{200B}zero-width-space",
            "signer\u{FEFF}bom-marker",
            "signer\r\ncarriage-return",
            "signer/../../../etc/passwd",
            "signer\u{202E}rtl-override\u{202D}attack",
            "signer\x1B[H\x1B[2Jansi-escape",
            "хакер-кириллица",
            "攻击者-中文",
        ];

        for (i, malicious_id) in malicious_identifiers.iter().enumerate() {
            // Test malicious signer key IDs
            base_config.signer_keys[0].key_id = malicious_id.to_string();

            // Test malicious artifact with Unicode content
            let malicious_artifact = PublicationArtifact {
                artifact_id: format!("artifact-{}", malicious_id),
                connector_id: format!("connector-{}", malicious_id),
                content_hash: format!("hash-{}", malicious_id),
                signatures: vec![PartialSignature {
                    signer_id: malicious_id.to_string(),
                    key_id: malicious_id.to_string(),
                    signature_hex: "deadbeef".repeat(16),
                }],
            };

            let result = verify_threshold(
                &base_config,
                &malicious_artifact,
                &format!("t-malicious-id-{}", i),
                "ts",
            );

            // Should handle gracefully without panics
            assert!(!result.verified); // Should fail due to invalid signature format
            assert!(result.failure_reason.is_some());
        }
    }

    #[test]
    fn negative_signature_hex_format_corruption_and_injection_attempts() {
        // Test various corrupted and malicious signature hex formats
        let (_signing_keys, config) = test_config(2, 3);

        let malformed_signature_hex_cases = vec![
            "".to_string(),                              // Empty signature
            "not-hex-at-all!".to_string(),               // Non-hex characters
            "deadbeef".to_string(),                      // Too short
            "g".repeat(128),                             // Invalid hex characters
            "0".repeat(127),                             // Odd length
            "00".repeat(1000),                           // Extremely long
            "\0".repeat(64),                             // Null bytes
            "🚀".repeat(32),                             // Unicode in hex field
            "../etc/passwd".to_string(),                 // Path traversal attempt
            "<script>alert('xss')</script>".to_string(), // XSS injection
            "0x".repeat(64),                             // Malformed hex prefix
        ];

        for (i, malformed_hex) in malformed_signature_hex_cases.iter().enumerate() {
            let malicious_artifact = PublicationArtifact {
                artifact_id: format!("test-artifact-{}", i),
                connector_id: "test-connector".to_string(),
                content_hash: "valid-hash".to_string(),
                signatures: vec![PartialSignature {
                    signer_id: "signer-0".to_string(),
                    key_id: "signer-0".to_string(),
                    signature_hex: malformed_hex.clone(),
                }],
            };

            let result = verify_threshold(
                &config,
                &malicious_artifact,
                &format!("t-malformed-sig-{}", i),
                "ts",
            );

            // All should fail verification with appropriate error messages
            assert!(
                !result.verified,
                "Malformed signature should fail: {}",
                malformed_hex
            );
            assert_eq!(result.valid_signatures, 0);
            assert!(result.failure_reason.is_some());

            // Check that failure reasons contain appropriate error codes
            let has_format_error = result.failure_reason.as_ref().is_some_and(|reason| {
                let reason = reason.to_string().to_lowercase();
                reason.contains("invalid") || reason.contains("malformed") || reason.contains("hex")
            });
            assert!(
                has_format_error,
                "Should report format error for: {}",
                malformed_hex
            );
        }
    }

    #[test]
    fn negative_arithmetic_overflow_in_threshold_calculations() {
        // Test arithmetic operations near overflow boundaries in threshold logic
        let (signing_keys, _) = test_keys(3);

        // Create config with extreme values that could cause overflow
        let extreme_config = ThresholdConfig {
            threshold: u32::MAX.saturating_sub(1),
            total_signers: u32::MAX.saturating_sub(1),
            signer_keys: vec![
                SignerKey {
                    key_id: "extreme-signer-1".to_string(),
                    public_key_hex: hex::encode(signing_keys[0].verifying_key().to_bytes()),
                },
                SignerKey {
                    key_id: "extreme-signer-2".to_string(),
                    public_key_hex: hex::encode(signing_keys[1].verifying_key().to_bytes()),
                },
            ],
        };

        // Config validation should handle extreme values
        let validation_result = extreme_config.validate();
        assert!(validation_result.is_err()); // Should fail due to mismatched counts

        // Test with corrected config but extreme threshold
        let corrected_config = ThresholdConfig {
            threshold: 2,
            total_signers: 2,
            signer_keys: extreme_config.signer_keys.clone(),
        };

        // Create artifact with maximum u32 values in counters
        let stress_artifact = PublicationArtifact {
            artifact_id: "overflow-test".to_string(),
            connector_id: "stress-connector".to_string(),
            content_hash: "stress-hash".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(
            &corrected_config,
            &stress_artifact,
            "t-overflow-boundary",
            "ts",
        );

        // Should handle extreme values without arithmetic overflow
        assert!(!result.verified); // No signatures provided
        assert_eq!(result.valid_signatures, 0);
        assert_eq!(result.threshold, 2);
    }

    #[test]
    fn negative_duplicate_signature_injection_and_sybil_attacks() {
        // Test handling of duplicate signatures and sybil-style attacks
        let (signing_keys, config) = test_config(2, 3);
        let message = b"test message for duplicate attack";
        let content_hash = hex::encode(sha2::Sha256::digest(message));

        // Create valid signature
        let valid_sig_hex = sign(
            &signing_keys[0],
            &config.signer_keys[0].key_id,
            "duplicate-same",
            "test-connector",
            &content_hash,
        )
        .signature_hex;

        // Test various duplicate signature attack patterns
        let duplicate_attack_artifacts = vec![
            // Same signature repeated multiple times
            PublicationArtifact {
                artifact_id: "duplicate-same".to_string(),
                connector_id: "test-connector".to_string(),
                content_hash: content_hash.clone(),
                signatures: vec![
                    PartialSignature {
                        signer_id: "signer-0".to_string(),
                        key_id: "signer-0".to_string(),
                        signature_hex: valid_sig_hex.clone(),
                    },
                    PartialSignature {
                        signer_id: "signer-0".to_string(),
                        key_id: "signer-0".to_string(),
                        signature_hex: valid_sig_hex.clone(),
                    },
                ],
            },
            // Same key ID with different signer ID (identity confusion)
            PublicationArtifact {
                artifact_id: "identity-confusion".to_string(),
                connector_id: "test-connector".to_string(),
                content_hash: content_hash.clone(),
                signatures: vec![
                    PartialSignature {
                        signer_id: "signer-0".to_string(),
                        key_id: "signer-0".to_string(),
                        signature_hex: valid_sig_hex.clone(),
                    },
                    PartialSignature {
                        signer_id: "attacker-impersonation".to_string(),
                        key_id: "signer-0".to_string(),
                        signature_hex: valid_sig_hex.clone(),
                    },
                ],
            },
        ];

        for attack_artifact in duplicate_attack_artifacts {
            let result = verify_threshold(&config, &attack_artifact, "t-duplicate-injection", "ts");

            // Should only count each unique valid signature once
            assert!(
                result.valid_signatures <= 1,
                "Duplicate signatures should only count once for artifact: {}",
                attack_artifact.artifact_id
            );

            // Should not meet threshold with duplicates
            assert!(
                !result.verified,
                "Duplicate signature attack should not meet threshold: {}",
                attack_artifact.artifact_id
            );
        }
    }

    #[test]
    fn negative_massive_signature_collection_memory_exhaustion() {
        // Test behavior with massive number of signatures (potential DoS)
        let (_signing_keys, config) = test_config(2, 3);

        // Create artifact with massive signature collection
        let massive_signature_count = 10_000;
        let mut massive_signatures = Vec::new();

        for i in 0..massive_signature_count {
            push_bounded(
                &mut massive_signatures,
                PartialSignature {
                    signer_id: format!("mass-signer-{:06}", i),
                    key_id: format!("mass-key-{:06}", i),
                    signature_hex: format!("{:064x}", i), // Fake but well-formed hex
                },
                MAX_SIGNATURES,
            );
        }

        let massive_artifact = PublicationArtifact {
            artifact_id: "memory-stress-test".to_string(),
            connector_id: "stress-connector".to_string(),
            content_hash: "stress-test-hash".to_string(),
            signatures: massive_signatures,
        };

        // Verification should handle massive signature count without memory exhaustion
        let start_time = std::time::Instant::now();
        let result = verify_threshold(&config, &massive_artifact, "t-massive-signatures", "ts");
        let duration = start_time.elapsed();

        // Should complete in reasonable time despite large input
        assert!(
            duration.as_secs() < 30,
            "Verification should complete within 30 seconds"
        );

        // Should not verify due to invalid signatures
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0); // None should be valid

        // Should handle large failure reason collection
        assert!(result.failure_reason.is_some());
    }

    #[test]
    fn negative_cryptographic_timing_attack_resistance_validation() {
        // Test constant-time comparison resistance against timing attacks
        let (signing_keys, config) = test_config(3, 5);
        let message = b"timing attack test message";
        let content_hash = hex::encode(sha2::Sha256::digest(message));

        // Create signatures with systematic bit differences to test timing
        let base_signature = signing_keys[0].sign(message);
        let base_hex = hex::encode(base_signature.to_bytes());

        let mut timing_measurements = Vec::new();

        // Test signatures differing in first byte vs last byte
        for position in [0, 2, base_hex.len().saturating_sub(2)] {
            let mut modified_hex = base_hex.clone();
            if position < modified_hex.len() {
                // Flip one hex character
                let chars: Vec<char> = modified_hex.chars().collect();
                let modified_char = if chars[position] == '0' { '1' } else { '0' };
                modified_hex.replace_range(position..position + 1, &modified_char.to_string());
            }

            let timing_artifact = PublicationArtifact {
                artifact_id: format!("timing-test-{}", position),
                connector_id: "timing-test".to_string(),
                content_hash: content_hash.clone(),
                signatures: vec![PartialSignature {
                    signer_id: "signer-0".to_string(),
                    key_id: "signer-0".to_string(),
                    signature_hex: modified_hex,
                }],
            };

            // Measure verification timing
            let start = std::time::Instant::now();
            let result = verify_threshold(&config, &timing_artifact, "t-timing", "ts");
            let duration = start.elapsed();

            push_bounded(
                &mut timing_measurements,
                duration.as_nanos(),
                MAX_TEST_RESULTS,
            );

            // All should fail verification
            assert!(
                !result.verified,
                "Modified signature should fail verification"
            );
        }

        // Timing variance should be bounded (basic timing attack resistance check)
        let max_time = *timing_measurements.iter().max().unwrap();
        let min_time = *timing_measurements.iter().min().unwrap();
        assert!(min_time > 0, "timing measurement must be non-zero");
        let variance_ratio = max_time as f64 / min_time as f64;
        assert!(variance_ratio.is_finite(), "timing ratio must be finite");

        // Allow reasonable variance but flag excessive timing differences
        assert!(
            variance_ratio < 10.0,
            "Timing variance too high ({}x), possible timing vulnerability",
            variance_ratio
        );
    }

    #[test]
    fn negative_malformed_public_key_format_injection_attempts() {
        // Test handling of malformed public key formats in signer configuration
        let malformed_public_key_cases = vec![
            "".to_string(),                              // Empty public key
            "not-a-hex-key".to_string(),                 // Non-hex
            "00".repeat(16),                             // Too short (32 bytes expected)
            "ff".repeat(64),                             // Too long
            "GG".repeat(32),                             // Invalid hex characters
            "\0".repeat(64),                             // Null bytes
            "../../etc/passwd".to_string(),              // Path traversal
            "<script>alert('key')</script>".to_string(), // XSS injection
            "🔑".repeat(32),                             // Unicode emoji
            "DEADBEEF".repeat(8),                        // Valid hex but wrong case/content
        ];

        for (i, malformed_key) in malformed_public_key_cases.iter().enumerate() {
            let malformed_config = ThresholdConfig {
                threshold: 1,
                total_signers: 1,
                signer_keys: vec![SignerKey {
                    key_id: format!("malformed-key-{}", i),
                    public_key_hex: malformed_key.clone(),
                }],
            };

            let test_artifact = PublicationArtifact {
                artifact_id: format!("malformed-key-test-{}", i),
                connector_id: "test-connector".to_string(),
                content_hash: "test-hash".to_string(),
                signatures: vec![PartialSignature {
                    signer_id: format!("malformed-key-{}", i),
                    key_id: format!("malformed-key-{}", i),
                    signature_hex: "00".repeat(64), // Valid format but won't verify
                }],
            };

            let result = verify_threshold(
                &malformed_config,
                &test_artifact,
                &format!("t-malformed-key-{}", i),
                "ts",
            );

            // Should handle malformed keys without crashing
            assert!(
                !result.verified,
                "Malformed public key should lead to verification failure"
            );

            // Should provide meaningful error messages
            let has_key_error = result.failure_reason.as_ref().is_some_and(|reason| {
                let reason = reason.to_string().to_lowercase();
                reason.contains("key") || reason.contains("invalid") || reason.contains("malformed")
            });
            assert!(
                has_key_error,
                "Should report key or signature validation failure"
            );
        }
    }

    // ── Metamorphic Relations ──────────────────────────────────────────────

    /// MR1: Sign-then-verify roundtrip (Invertive pattern: f(T(T(x))) = f(x))
    /// Property: If we sign a message then verify, it must succeed
    #[test]
    fn mr_threshold_sig_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::thread_rng;

        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let key_id = "test-signer";

        // Create threshold config with single signer
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: key_id.to_string(),
                public_key_hex: hex::encode(verifying_key.to_bytes()),
            }],
        };

        // Test multiple content hashes
        let test_hashes = vec![
            "content-hash-1",
            "different-content",
            "special-chars-!@#$%^&*()",
            "",               // Edge case: empty hash
            "x".repeat(1000), // Large hash
        ];

        for content_hash in test_hashes {
            // MR: Sign then verify must succeed
            let signature = sign(
                &signing_key,
                key_id,
                "test-artifact",
                "test-connector",
                &content_hash,
            );

            let artifact = PublicationArtifact {
                artifact_id: "test-artifact".to_string(),
                connector_id: "test-connector".to_string(),
                content_hash: content_hash.to_string(),
                signatures: vec![signature],
            };

            let result = verify_threshold(&config, &artifact, "trace-1", "2026-01-01T00:00:00Z");

            assert!(
                result.verified,
                "MR violated: sign-then-verify roundtrip failed for content_hash: '{}'",
                content_hash
            );
            assert_eq!(result.valid_signatures, 1);
            assert!(result.failure_reason.is_none());
        }
    }

    /// MR2: Signature permutation invariance (Permutative pattern: f(permute(x)) = permute(f(x)))
    /// Property: Order of signatures in threshold verification shouldn't matter
    #[test]
    fn mr_threshold_sig_permutation_invariance() {
        use ed25519_dalek::SigningKey;
        use rand::{seq::SliceRandom, thread_rng};

        let mut rng = thread_rng();
        let content_hash = "test-content-for-permutation";

        // Create 3 signers for 2-of-3 threshold
        let signers: Vec<(SigningKey, String)> = (0..3)
            .map(|i| (SigningKey::generate(&mut rng), format!("signer-{}", i)))
            .collect();

        let config = ThresholdConfig {
            threshold: 2,
            total_signers: 3,
            signer_keys: signers
                .iter()
                .map(|(signing_key, key_id)| SignerKey {
                    key_id: key_id.clone(),
                    public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
                })
                .collect(),
        };

        // Create signatures from all 3 signers
        let mut signatures: Vec<PartialSignature> = signers
            .iter()
            .map(|(signing_key, key_id)| {
                sign(
                    signing_key,
                    key_id,
                    "permutation-test",
                    "test-connector",
                    content_hash,
                )
            })
            .collect();

        // Test original order
        let artifact_original = PublicationArtifact {
            artifact_id: "permutation-test".to_string(),
            connector_id: "test-connector".to_string(),
            content_hash: content_hash.to_string(),
            signatures: signatures.clone(),
        };

        let result_original = verify_threshold(
            &config,
            &artifact_original,
            "trace-1",
            "2026-01-01T00:00:00Z",
        );

        // Test 10 random permutations
        for i in 0..10 {
            signatures.shuffle(&mut rng);

            let artifact_permuted = PublicationArtifact {
                artifact_id: "permutation-test".to_string(),
                connector_id: "test-connector".to_string(),
                content_hash: content_hash.to_string(),
                signatures: signatures.clone(),
            };

            let result_permuted = verify_threshold(
                &config,
                &artifact_permuted,
                &format!("trace-{}", i),
                "2026-01-01T00:00:00Z",
            );

            // MR: Permuted signatures must have same verification outcome
            assert_eq!(
                result_original.verified, result_permuted.verified,
                "MR violated: permutation {} changed verification result",
                i
            );
            assert_eq!(
                result_original.valid_signatures, result_permuted.valid_signatures,
                "MR violated: permutation {} changed valid signature count",
                i
            );

            // Both should succeed with 3 valid signatures
            assert!(
                result_permuted.verified,
                "Permuted signatures should verify successfully"
            );
            assert_eq!(result_permuted.valid_signatures, 3);
        }
    }

    /// MR3: Message preservation (Equivalence pattern with negation)
    /// Property: Changing the message must cause verification to fail
    #[test]
    fn mr_threshold_sig_message_preservation() {
        use ed25519_dalek::SigningKey;
        use rand::thread_rng;

        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let key_id = "test-signer";

        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: key_id.to_string(),
                public_key_hex: hex::encode(verifying_key.to_bytes()),
            }],
        };

        let original_content = "original-content-hash";
        let signature = sign(
            &signing_key,
            key_id,
            "message-preservation-test",
            "test-connector",
            original_content,
        );

        // Test various message modifications
        let tampered_messages = vec![
            "different-content",       // Completely different
            "original-content-hash2",  // Appended character
            "Original-content-hash",   // Case change
            "original-content-has",    // Character substitution
            "",                        // Empty
            "original-content-hash\0", // Null byte appended
        ];

        for tampered_content in tampered_messages {
            let artifact = PublicationArtifact {
                artifact_id: "message-preservation-test".to_string(),
                connector_id: "test-connector".to_string(),
                content_hash: tampered_content.to_string(),
                signatures: vec![signature.clone()],
            };

            let result = verify_threshold(&config, &artifact, "trace-1", "2026-01-01T00:00:00Z");

            // MR: Modified message must cause verification failure
            assert!(
                !result.verified,
                "MR violated: signature verified with tampered message: '{}'",
                tampered_content
            );
            assert_eq!(result.valid_signatures, 0);
            assert!(result.failure_reason.is_some());
        }
    }
}
