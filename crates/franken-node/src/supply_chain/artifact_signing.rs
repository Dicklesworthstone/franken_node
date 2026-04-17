// Artifact signing and checksum verification for releases (bd-2pw, Section 10.6).
//
// Provides Ed25519 signing of release artifacts, SHA-256 checksum manifests,
// structured verification, key rotation with signed transition records, and
// threshold (M-of-N) signing support.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::security::constant_time::ct_eq_bytes;

const MAX_TRANSITIONS: usize = 4096;

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

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// ASV-001: Artifact signed successfully.
pub const ASV_001_ARTIFACT_SIGNED: &str = "ASV-001";

/// ASV-002: Artifact verification succeeded.
pub const ASV_002_VERIFICATION_OK: &str = "ASV-002";

/// ASV-003: Artifact verification failed.
pub const ASV_003_VERIFICATION_FAILED: &str = "ASV-003";

/// ASV-004: Key rotation completed.
pub const ASV_004_KEY_ROTATED: &str = "ASV-004";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactSigningError {
    /// The manifest signature is invalid.
    ManifestSignatureInvalid,
    /// A file's SHA-256 checksum does not match the manifest entry.
    ChecksumMismatch {
        artifact_name: String,
        expected: String,
        actual: String,
    },
    /// An individual detached signature is invalid.
    SignatureInvalid { artifact_name: String },
    /// Artifact listed in manifest but not found on disk.
    ArtifactMissing { artifact_name: String },
    /// A file exists but is not listed in the manifest.
    UnlistedArtifact { artifact_name: String },
    /// Key not found for the given key ID.
    KeyNotFound { key_id: String },
    /// Threshold not met: need M signatures, got fewer.
    ThresholdNotMet { required: usize, provided: usize },
    /// Transition record signature invalid during key rotation.
    TransitionRecordInvalid,
    /// Generic IO-level error (stringified for Clone/Eq).
    IoError(String),
}

impl fmt::Display for ArtifactSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestSignatureInvalid => write!(f, "manifest signature invalid"),
            Self::ChecksumMismatch {
                artifact_name,
                expected,
                actual,
            } => write!(
                f,
                "checksum mismatch for {artifact_name}: expected {expected}, got {actual}"
            ),
            Self::SignatureInvalid { artifact_name } => {
                write!(f, "invalid signature for {artifact_name}")
            }
            Self::ArtifactMissing { artifact_name } => {
                write!(f, "artifact missing: {artifact_name}")
            }
            Self::UnlistedArtifact { artifact_name } => {
                write!(f, "unlisted artifact: {artifact_name}")
            }
            Self::KeyNotFound { key_id } => write!(f, "key not found: {key_id}"),
            Self::ThresholdNotMet { required, provided } => {
                write!(f, "threshold not met: need {required}, got {provided}")
            }
            Self::TransitionRecordInvalid => write!(f, "transition record signature invalid"),
            Self::IoError(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for ArtifactSigningError {}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A unique identifier for a signing key, derived from the public key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    /// Derive a key ID from a verifying (public) key: first 8 bytes of SHA-256, hex-encoded.
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let hash = Sha256::digest([b"artifact_signing_keyid_v1:" as &[u8], vk.as_bytes()].concat());
        Self(hex::encode(&hash[..8]))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single entry in the SHA256SUMS manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Relative filename within the release directory.
    pub name: String,
    /// Hex-encoded SHA-256 hash.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// The SHA256SUMS manifest — a list of artifacts with their checksums, plus
/// a detached Ed25519 signature of the serialised manifest.
#[derive(Debug, Clone)]
pub struct ChecksumManifest {
    /// Ordered map from filename to manifest entry.
    pub entries: BTreeMap<String, ManifestEntry>,
    /// Key ID that signed the manifest.
    pub key_id: KeyId,
    /// Detached Ed25519 signature over the canonical manifest bytes.
    pub signature: Vec<u8>,
}

impl ChecksumManifest {
    /// Serialise entries into the canonical text representation used for
    /// signing: one line per entry, sorted by filename, format
    /// `<sha256>  <name>  <size>\n`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = String::new();
        for entry in self.entries.values() {
            buf.push_str(&format!(
                "{}  {}  {}\n",
                entry.sha256, entry.name, entry.size_bytes
            ));
        }
        buf.into_bytes()
    }

    /// Parse a canonical manifest text back into entries (no signature).
    ///
    /// SECURITY: rejects entries whose name contains path traversal
    /// sequences (`..`, leading `/`, or backslashes) to prevent
    /// arbitrary file reads when the manifest is attacker-controlled.
    pub fn parse_canonical(text: &str) -> Vec<ManifestEntry> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let parts: Vec<&str> = line.splitn(3, "  ").collect();
            if parts.len() == 3 {
                if !is_valid_sha256_hex(parts[0]) {
                    continue;
                }
                let name = parts[1];
                if !is_valid_artifact_name(name) {
                    continue;
                }
                if !parts[2].bytes().all(|byte| byte.is_ascii_digit()) {
                    continue;
                }
                let Ok(size_bytes) = parts[2].parse::<u64>() else {
                    continue;
                };
                entries.push(ManifestEntry {
                    sha256: parts[0].to_string(),
                    name: name.to_string(),
                    size_bytes,
                });
            }
        }
        entries
    }
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_valid_artifact_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Per-artifact verification result emitted as structured JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVerificationResult {
    pub artifact_name: String,
    pub passed: bool,
    pub key_id: String,
    pub failure_reason: Option<String>,
}

/// Aggregate verification output from `verify_release`.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub manifest_signature_ok: bool,
    pub results: Vec<ArtifactVerificationResult>,
    pub overall_pass: bool,
}

/// A signed key-rotation transition record: the old key endorses the new key.
#[derive(Debug, Clone)]
pub struct KeyTransitionRecord {
    pub old_key_id: KeyId,
    pub new_key_id: KeyId,
    pub new_public_key_bytes: [u8; 32],
    pub timestamp: u64,
    /// Signature by the *old* key over the canonical transition payload.
    pub signature: Vec<u8>,
}

impl KeyTransitionRecord {
    /// Canonical bytes with domain separator and length-prefixed variable-length fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(b"artifact_signing_transition_v1:");
        let old_bytes = self.old_key_id.0.as_bytes();
        let old_len = len_to_u64(old_bytes.len());
        buf.extend(old_len.to_le_bytes());
        buf.extend(old_bytes);
        let new_bytes = self.new_key_id.0.as_bytes();
        let new_len = len_to_u64(new_bytes.len());
        buf.extend(new_len.to_le_bytes());
        buf.extend(new_bytes);
        let public_key_len = len_to_u64(self.new_public_key_bytes.len());
        buf.extend(public_key_len.to_le_bytes());
        buf.extend(&self.new_public_key_bytes);
        buf.extend(&self.timestamp.to_le_bytes());
        buf
    }
}

/// Partial signature from one key holder in a threshold (M-of-N) signing scheme.
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub key_id: KeyId,
    pub signature: Vec<u8>,
}

/// A key-ring that holds current and historical public keys.
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    /// Map from KeyId to VerifyingKey.
    keys: BTreeMap<KeyId, VerifyingKey>,
    /// Ordered list of transition records.
    transitions: Vec<KeyTransitionRecord>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key to the ring.
    pub fn add_key(&mut self, vk: VerifyingKey) -> KeyId {
        let kid = KeyId::from_verifying_key(&vk);
        self.keys.insert(kid.clone(), vk);
        kid
    }

    /// Look up a key by its ID.
    pub fn get_key(&self, kid: &KeyId) -> Option<&VerifyingKey> {
        self.keys.get(kid)
    }

    /// Record a key transition.
    pub fn record_transition(&mut self, record: KeyTransitionRecord) {
        push_bounded(&mut self.transitions, record, MAX_TRANSITIONS);
    }

    /// Return all stored transition records.
    pub fn transitions(&self) -> &[KeyTransitionRecord] {
        &self.transitions
    }

    /// Number of keys in the ring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the key ring is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Signing functions
// ---------------------------------------------------------------------------

/// Compute SHA-256 of arbitrary bytes, returned as hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest([b"artifact_signing_hash_v1:" as &[u8], data].concat());
    hex::encode(digest)
}

/// Sign arbitrary bytes with an Ed25519 signing key.
pub fn sign_bytes(signing_key: &SigningKey, data: &[u8]) -> Vec<u8> {
    signing_key.sign(data).to_bytes().to_vec()
}

/// Verify an Ed25519 signature over `data` using `verifying_key`.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<(), ArtifactSigningError> {
    let sig = ed25519_dalek::Signature::from_bytes(
        sig_bytes
            .try_into()
            .map_err(|_| ArtifactSigningError::ManifestSignatureInvalid)?,
    );
    verifying_key
        .verify(data, &sig)
        .map_err(|_| ArtifactSigningError::ManifestSignatureInvalid)
}

/// Build a [`ChecksumManifest`] for a set of (name, content) pairs and sign
/// it with the provided signing key.
pub fn build_and_sign_manifest(
    artifacts: &[(&str, &[u8])],
    signing_key: &SigningKey,
) -> ChecksumManifest {
    let vk = signing_key.verifying_key();
    let kid = KeyId::from_verifying_key(&vk);

    let mut entries = BTreeMap::new();
    for (name, content) in artifacts {
        entries.insert(
            name.to_string(),
            ManifestEntry {
                name: name.to_string(),
                sha256: sha256_hex(content),
                size_bytes: len_to_u64(content.len()),
            },
        );
    }

    let manifest = ChecksumManifest {
        entries,
        key_id: kid,
        signature: Vec::new(),
    };

    let canonical = manifest.canonical_bytes();
    let sig = sign_bytes(signing_key, &canonical);

    ChecksumManifest {
        signature: sig,
        ..manifest
    }
}

/// Sign a single artifact, producing a detached `.sig` byte vector.
pub fn sign_artifact(signing_key: &SigningKey, content: &[u8]) -> Vec<u8> {
    sign_bytes(signing_key, content)
}

// ---------------------------------------------------------------------------
// Verification functions
// ---------------------------------------------------------------------------

/// Verify an entire release directory given in-memory content, detached
/// signatures, a manifest, and a key ring.
///
/// Returns a [`VerificationReport`] with per-artifact results.
pub fn verify_release(
    manifest: &ChecksumManifest,
    artifacts: &BTreeMap<String, Vec<u8>>,
    detached_sigs: &BTreeMap<String, Vec<u8>>,
    key_ring: &KeyRing,
) -> VerificationReport {
    // 1. Verify manifest signature.
    let manifest_ok = match key_ring.get_key(&manifest.key_id) {
        Some(vk) => verify_signature(vk, &manifest.canonical_bytes(), &manifest.signature).is_ok(),
        None => false,
    };

    let mut results = Vec::new();

    // 2. Check each manifest entry.
    for (name, entry) in &manifest.entries {
        let key_id_str = manifest.key_id.0.clone();
        match artifacts.get(name) {
            None => {
                results.push(ArtifactVerificationResult {
                    artifact_name: name.clone(),
                    passed: false,
                    key_id: key_id_str,
                    failure_reason: Some("artifact missing".into()),
                });
            }
            Some(content) => {
                let actual_hash = sha256_hex(content);
                let actual_size = len_to_u64(content.len());
                if actual_size != entry.size_bytes {
                    results.push(ArtifactVerificationResult {
                        artifact_name: name.clone(),
                        passed: false,
                        key_id: key_id_str,
                        failure_reason: Some(format!(
                            "size mismatch: expected {}, got {}",
                            entry.size_bytes, actual_size
                        )),
                    });
                } else if !ct_eq_bytes(actual_hash.as_bytes(), entry.sha256.as_bytes()) {
                    results.push(ArtifactVerificationResult {
                        artifact_name: name.clone(),
                        passed: false,
                        key_id: key_id_str,
                        failure_reason: Some(format!(
                            "checksum mismatch: expected {}, got {}",
                            entry.sha256, actual_hash
                        )),
                    });
                } else {
                    // Every manifest-listed artifact must carry a detached
                    // signature; otherwise a checksum-only substitution slips
                    // through as valid.
                    let signature_failure = match detached_sigs.get(name) {
                        Some(sig) => match key_ring.get_key(&manifest.key_id) {
                            Some(vk) if verify_signature(vk, content, sig).is_ok() => None,
                            Some(_) | None => Some("detached signature invalid"),
                        },
                        None => Some("detached signature missing"),
                    };

                    if let Some(reason) = signature_failure {
                        results.push(ArtifactVerificationResult {
                            artifact_name: name.clone(),
                            passed: false,
                            key_id: key_id_str,
                            failure_reason: Some(reason.into()),
                        });
                    } else {
                        results.push(ArtifactVerificationResult {
                            artifact_name: name.clone(),
                            passed: true,
                            key_id: key_id_str,
                            failure_reason: None,
                        });
                    }
                }
            }
        }
    }

    // 4. Check for unlisted artifacts.
    for name in artifacts.keys() {
        if !manifest.entries.contains_key(name) {
            results.push(ArtifactVerificationResult {
                artifact_name: name.clone(),
                passed: false,
                key_id: manifest.key_id.0.clone(),
                failure_reason: Some("unlisted artifact".into()),
            });
        }
    }

    let overall_pass = manifest_ok && results.iter().all(|r| r.passed);

    VerificationReport {
        manifest_signature_ok: manifest_ok,
        results,
        overall_pass,
    }
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

/// Create a signed key-transition record: old key endorses new key.
pub fn create_key_transition(
    old_signing_key: &SigningKey,
    new_verifying_key: &VerifyingKey,
) -> KeyTransitionRecord {
    let old_vk = old_signing_key.verifying_key();
    let old_kid = KeyId::from_verifying_key(&old_vk);
    let new_kid = KeyId::from_verifying_key(new_verifying_key);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let record = KeyTransitionRecord {
        old_key_id: old_kid,
        new_key_id: new_kid,
        new_public_key_bytes: *new_verifying_key.as_bytes(),
        timestamp,
        signature: Vec::new(),
    };

    let canonical = record.canonical_bytes();
    let sig = sign_bytes(old_signing_key, &canonical);

    KeyTransitionRecord {
        signature: sig,
        ..record
    }
}

/// Verify a key-transition record using the old key from the key ring.
pub fn verify_key_transition(
    record: &KeyTransitionRecord,
    key_ring: &KeyRing,
) -> Result<(), ArtifactSigningError> {
    let vk = key_ring
        .get_key(&record.old_key_id)
        .ok_or(ArtifactSigningError::KeyNotFound {
            key_id: record.old_key_id.0.clone(),
        })?;

    verify_signature(vk, &record.canonical_bytes(), &record.signature)
        .map_err(|_| ArtifactSigningError::TransitionRecordInvalid)
}

// ---------------------------------------------------------------------------
// Threshold signing
// ---------------------------------------------------------------------------

/// Collect partial signatures and determine whether the threshold is met.
/// When `required` unique valid signatures are provided, returns the first
/// `required` valid signatures. Otherwise returns an error.
pub fn collect_threshold_signatures(
    data: &[u8],
    partials: &[PartialSignature],
    key_ring: &KeyRing,
    required: usize,
) -> Result<Vec<PartialSignature>, ArtifactSigningError> {
    if required == 0 {
        return Err(ArtifactSigningError::ThresholdNotMet {
            required,
            provided: 0,
        });
    }

    let mut valid: Vec<PartialSignature> = Vec::new();
    let mut seen_keys = std::collections::BTreeSet::new();

    for partial in partials {
        if seen_keys.contains(&partial.key_id) {
            continue; // each key holder contributes at most once
        }
        if let Some(vk) = key_ring.get_key(&partial.key_id)
            && verify_signature(vk, data, &partial.signature).is_ok()
        {
            seen_keys.insert(partial.key_id.clone());
            valid.push(partial.clone());
        }
        if valid.len() >= required {
            return Ok(valid);
        }
    }

    Err(ArtifactSigningError::ThresholdNotMet {
        required,
        provided: valid.len(),
    })
}

/// Verify that an artifact has at least `required` valid partial signatures.
pub fn verify_threshold(
    data: &[u8],
    partials: &[PartialSignature],
    key_ring: &KeyRing,
    required: usize,
) -> bool {
    collect_threshold_signatures(data, partials, key_ring, required).is_ok()
}

// ---------------------------------------------------------------------------
// Structured audit log entry
// ---------------------------------------------------------------------------

/// JSON-serialisable audit entry emitted for every signing/verification op.
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub event_code: String,
    pub artifact_name: String,
    pub key_id: String,
    pub operation: String,
    pub result: String,
    pub timestamp: u64,
}

impl AuditLogEntry {
    pub fn now(
        event_code: &str,
        artifact_name: &str,
        key_id: &str,
        operation: &str,
        result: &str,
    ) -> Self {
        Self {
            event_code: event_code.to_string(),
            artifact_name: artifact_name.to_string(),
            key_id: key_id.to_string(),
            operation: operation.to_string(),
            result: result.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "event_code": self.event_code,
            "artifact_name": self.artifact_name,
            "key_id": self.key_id,
            "operation": self.operation,
            "result": self.result,
            "timestamp": self.timestamp,
        })
    }
}

// ---------------------------------------------------------------------------
// Helper: generate a deterministic demo signing key for tests/demos.
// ---------------------------------------------------------------------------

/// Return a deterministic Ed25519 signing key for demos/tests.
pub fn demo_signing_key() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"franken-node-artifact-signing-demo-key-v1").into();
    SigningKey::from_bytes(&seed)
}

/// Return a second deterministic demo key (for rotation / threshold tests).
pub fn demo_signing_key_2() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"franken-node-artifact-signing-demo-key-v2").into();
    SigningKey::from_bytes(&seed)
}

/// Return a third deterministic demo key (for threshold tests).
pub fn demo_signing_key_3() -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(b"franken-node-artifact-signing-demo-key-v3").into();
    SigningKey::from_bytes(&seed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_keys() -> (SigningKey, VerifyingKey, KeyRing) {
        let sk = demo_signing_key();
        let vk = sk.verifying_key();
        let mut ring = KeyRing::new();
        ring.add_key(vk);
        (sk, vk, ring)
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn test_sha256_hex_changes_on_different_input() {
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let sk = demo_signing_key();
        let vk = sk.verifying_key();
        let data = b"test payload";
        let sig = sign_bytes(&sk, data);
        assert!(verify_signature(&vk, data, &sig).is_ok());
    }

    #[test]
    fn test_verify_fails_on_tampered_data() {
        let sk = demo_signing_key();
        let vk = sk.verifying_key();
        let sig = sign_bytes(&sk, b"original");
        assert!(verify_signature(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_truncated_signature_bytes() {
        let sk = demo_signing_key();
        let vk = sk.verifying_key();
        let mut sig = sign_bytes(&sk, b"payload");
        sig.truncate(31);

        assert!(verify_signature(&vk, b"payload", &sig).is_err());
    }

    #[test]
    fn test_build_and_sign_manifest() {
        let sk = demo_signing_key();
        let artifacts = vec![("bin.tar.gz", b"binary content" as &[u8])];
        let manifest = build_and_sign_manifest(&artifacts, &sk);
        assert_eq!(manifest.entries.len(), 1);
        assert!(!manifest.signature.is_empty());
    }

    #[test]
    fn test_manifest_canonical_bytes_deterministic() {
        let sk = demo_signing_key();
        let artifacts = vec![("a.bin", b"aaa" as &[u8]), ("b.bin", b"bbb" as &[u8])];
        let m1 = build_and_sign_manifest(&artifacts, &sk);
        let m2 = build_and_sign_manifest(&artifacts, &sk);
        assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
    }

    #[test]
    fn test_manifest_parse_canonical() {
        let sk = demo_signing_key();
        let artifacts = vec![("file.bin", b"data" as &[u8])];
        let manifest = build_and_sign_manifest(&artifacts, &sk);
        let text = String::from_utf8(manifest.canonical_bytes()).unwrap();
        let parsed = ChecksumManifest::parse_canonical(&text);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "file.bin");
    }

    #[test]
    fn test_verify_release_success() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);
        let sig = sign_artifact(&sk, content);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sig);

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(report.manifest_signature_ok);
        assert!(report.overall_pass);
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].passed);
    }

    #[test]
    fn test_verify_release_tampered_content() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);
        let sig = sign_artifact(&sk, content);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), b"tampered binary!!!".to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sig);

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.overall_pass);
        assert!(!report.results[0].passed);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("checksum mismatch")
        );
    }

    #[test]
    fn test_verify_release_missing_artifact() {
        let (sk, _vk, ring) = setup_keys();
        let manifest = build_and_sign_manifest(&[("missing.bin", b"data" as &[u8])], &sk);
        let arts = BTreeMap::new();
        let sigs = BTreeMap::new();

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.overall_pass);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("artifact missing")
        );
    }

    #[test]
    fn test_verify_release_missing_detached_signature() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let sigs = BTreeMap::new();

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.overall_pass);
        assert!(!report.results[0].passed);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("signature missing")
        );
    }

    #[test]
    fn test_verify_release_rejects_manifest_signed_by_unknown_key() {
        let known = demo_signing_key();
        let unknown = demo_signing_key_2();
        let mut ring = KeyRing::new();
        ring.add_key(known.verifying_key());
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &unknown);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sign_artifact(&unknown, content));

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.manifest_signature_ok);
        assert!(!report.overall_pass);
        assert!(report.results.iter().any(|result| {
            result.artifact_name == name
                && !result.passed
                && result
                    .failure_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("detached signature invalid"))
        }));
    }

    #[test]
    fn test_verify_release_manifest_not_updated() {
        // Sign manifest with one artifact, provide artifact + extra unlisted artifact.
        let (sk, _vk, ring) = setup_keys();
        let content = b"original";
        let name = "listed.bin";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);
        let sig = sign_artifact(&sk, content);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        arts.insert("extra.bin".to_string(), b"extra".to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sig);

        // The listed artifact should pass, but extra.bin is not in manifest.
        let report = verify_release(&manifest, &arts, &sigs, &ring);
        // Overall should FAIL because extra.bin is injected unlisted malware.
        assert!(!report.overall_pass);
        assert!(
            report
                .results
                .iter()
                .any(|r| r.artifact_name == "extra.bin" && !r.passed)
        );
    }

    #[test]
    fn test_key_rotation_roundtrip() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let vk2 = sk2.verifying_key();

        let mut ring = KeyRing::new();
        ring.add_key(sk1.verifying_key());

        let record = create_key_transition(&sk1, &vk2);
        assert!(verify_key_transition(&record, &ring).is_ok());

        // After adding new key, both should be in the ring.
        ring.add_key(vk2);
        ring.record_transition(record);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.transitions().len(), 1);
    }

    #[test]
    fn test_key_rotation_invalid_transition() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let vk2 = sk2.verifying_key();

        let mut ring = KeyRing::new();
        ring.add_key(sk1.verifying_key());

        // Create transition but tamper with the new public key bytes.
        let mut record = create_key_transition(&sk1, &vk2);
        record.new_public_key_bytes[0] ^= 0xff;
        assert!(verify_key_transition(&record, &ring).is_err());
    }

    #[test]
    fn test_old_key_verifies_old_artifact_after_rotation() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();

        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        ring.add_key(sk2.verifying_key());

        // Artifact signed with old key.
        let content = b"old release";
        let sig = sign_artifact(&sk1, content);
        let vk = ring.get_key(&kid1).unwrap();
        assert!(verify_signature(vk, content, &sig).is_ok());
    }

    #[test]
    fn test_new_key_signs_new_artifact_after_rotation() {
        let sk2 = demo_signing_key_2();

        let mut ring = KeyRing::new();
        ring.add_key(demo_signing_key().verifying_key());
        let kid2 = ring.add_key(sk2.verifying_key());

        let content = b"new release";
        let sig = sign_artifact(&sk2, content);
        let vk = ring.get_key(&kid2).unwrap();
        assert!(verify_signature(vk, content, &sig).is_ok());
    }

    #[test]
    fn test_threshold_signing_2_of_3() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let sk3 = demo_signing_key_3();

        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        let kid2 = ring.add_key(sk2.verifying_key());
        ring.add_key(sk3.verifying_key());

        let data = b"threshold-signed release manifest";
        let partials = vec![
            PartialSignature {
                key_id: kid1,
                signature: sign_bytes(&sk1, data),
            },
            PartialSignature {
                key_id: kid2,
                signature: sign_bytes(&sk2, data),
            },
        ];

        // 2-of-3 should succeed with 2 valid signatures.
        assert!(verify_threshold(data, &partials, &ring, 2));
    }

    #[test]
    fn test_threshold_signing_insufficient() {
        let sk1 = demo_signing_key();

        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        ring.add_key(demo_signing_key_2().verifying_key());
        ring.add_key(demo_signing_key_3().verifying_key());

        let data = b"threshold-signed release manifest";
        let partials = vec![PartialSignature {
            key_id: kid1,
            signature: sign_bytes(&sk1, data),
        }];

        // 1 of 3, need 2 => fail
        assert!(!verify_threshold(data, &partials, &ring, 2));
    }

    #[test]
    fn test_threshold_rejects_duplicate_signer() {
        let sk1 = demo_signing_key();

        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        ring.add_key(demo_signing_key_2().verifying_key());

        let data = b"threshold test";
        // Same key signs twice — should only count once.
        let partials = vec![
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, data),
            },
            PartialSignature {
                key_id: kid1,
                signature: sign_bytes(&sk1, data),
            },
        ];

        assert!(!verify_threshold(data, &partials, &ring, 2));
    }

    #[test]
    fn test_key_id_derivation_deterministic() {
        let sk = demo_signing_key();
        let vk = sk.verifying_key();
        let a = KeyId::from_verifying_key(&vk);
        let b = KeyId::from_verifying_key(&vk);
        assert_eq!(a, b);
    }

    #[test]
    fn test_key_id_different_for_different_keys() {
        let kid1 = KeyId::from_verifying_key(&demo_signing_key().verifying_key());
        let kid2 = KeyId::from_verifying_key(&demo_signing_key_2().verifying_key());
        assert_ne!(kid1, kid2);
    }

    #[test]
    fn test_audit_log_entry() {
        let entry = AuditLogEntry::now(
            ASV_001_ARTIFACT_SIGNED,
            "franken-node-v1.0.tar.gz",
            "abc123",
            "sign",
            "success",
        );
        let json = entry.to_json();
        assert_eq!(json["event_code"], "ASV-001");
        assert_eq!(json["operation"], "sign");
    }

    #[test]
    fn test_error_display() {
        let err = ArtifactSigningError::ChecksumMismatch {
            artifact_name: "bin.tar.gz".into(),
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("checksum mismatch"));
        assert!(msg.contains("bin.tar.gz"));
    }

    #[test]
    fn test_verify_release_invalid_detached_sig() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary";
        let name = "app.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), vec![0u8; 64]); // garbage sig

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.overall_pass);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("signature invalid")
        );
    }

    #[test]
    fn test_key_ring_empty() {
        let ring = KeyRing::new();
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn test_sign_artifact_produces_64_bytes() {
        let sk = demo_signing_key();
        let sig = sign_artifact(&sk, b"some artifact content");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn parse_canonical_rejects_path_traversal() {
        let hash = "a".repeat(64);
        let malicious = format!("{hash}  ../../../etc/passwd  1024\n");
        let parsed = ChecksumManifest::parse_canonical(&malicious);
        assert!(parsed.is_empty(), "should reject .. traversal");
    }

    #[test]
    fn parse_canonical_rejects_absolute_path() {
        let hash = "a".repeat(64);
        let malicious = format!("{hash}  /etc/passwd  1024\n");
        let parsed = ChecksumManifest::parse_canonical(&malicious);
        assert!(parsed.is_empty(), "should reject absolute paths");
    }

    #[test]
    fn parse_canonical_rejects_backslash_path() {
        let hash = "a".repeat(64);
        let malicious = format!("{hash}  ..\\..\\windows\\system32  1024\n");
        let parsed = ChecksumManifest::parse_canonical(&malicious);
        assert!(parsed.is_empty(), "should reject backslash paths");
    }

    #[test]
    fn parse_canonical_accepts_clean_names() {
        let first_hash = "a".repeat(64);
        let second_hash = "b".repeat(64);
        let valid = format!(
            "{first_hash}  release/artifact.tar.gz  1024\n{second_hash}  checksums.txt  512\n"
        );
        let parsed = ChecksumManifest::parse_canonical(&valid);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "release/artifact.tar.gz");
        assert_eq!(parsed[1].name, "checksums.txt");
    }

    #[test]
    fn parse_canonical_rejects_invalid_size() {
        let hash = "a".repeat(64);
        let malicious = format!("{hash}  legit.bin  not_a_number\n");
        let parsed = ChecksumManifest::parse_canonical(&malicious);
        assert!(
            parsed.is_empty(),
            "should reject entries with unparseable size"
        );
    }

    #[test]
    fn parse_canonical_rejects_negative_size() {
        let hash = "a".repeat(64);
        let malicious = format!("{hash}  legit.bin  -42\n");
        let parsed = ChecksumManifest::parse_canonical(&malicious);
        assert!(
            parsed.is_empty(),
            "should reject entries with negative size"
        );
    }

    #[test]
    fn parse_canonical_rejects_short_sha256() {
        let parsed = ChecksumManifest::parse_canonical("e3b0c44  artifact.bin  1024\n");
        assert!(parsed.is_empty(), "sha256 must be the full 64 hex chars");
    }

    #[test]
    fn parse_canonical_rejects_non_hex_sha256() {
        let hash = "g".repeat(64);
        let parsed = ChecksumManifest::parse_canonical(&format!("{hash}  artifact.bin  1024\n"));
        assert!(parsed.is_empty(), "sha256 must contain only hex characters");
    }

    #[test]
    fn parse_canonical_accepts_uppercase_sha256_hex() {
        let hash = "A".repeat(64);
        let parsed = ChecksumManifest::parse_canonical(&format!("{hash}  artifact.bin  1024\n"));
        assert_eq!(parsed.len(), 1);
        assert!(ct_eq_bytes(parsed[0].sha256.as_bytes(), hash.as_bytes()));
    }

    #[test]
    fn parse_canonical_rejects_empty_artifact_name() {
        let hash = "a".repeat(64);
        let parsed = ChecksumManifest::parse_canonical(&format!("{hash}    1024\n"));
        assert!(parsed.is_empty(), "artifact name must not be empty");
    }

    #[test]
    fn parse_canonical_rejects_dot_artifact_segments() {
        let hash = "a".repeat(64);
        for name in [
            "./artifact.bin",
            "release/./artifact.bin",
            "release//artifact.bin",
        ] {
            let parsed = ChecksumManifest::parse_canonical(&format!("{hash}  {name}  1024\n"));
            assert!(
                parsed.is_empty(),
                "artifact name `{name}` must be normalized"
            );
        }
    }

    #[test]
    fn parse_canonical_rejects_non_digit_size_syntax() {
        let hash = "a".repeat(64);
        for size in ["+42", "42 ", " 42", "4_2"] {
            let parsed =
                ChecksumManifest::parse_canonical(&format!("{hash}  artifact.bin  {size}\n"));
            assert!(
                parsed.is_empty(),
                "size `{size}` must be canonical digits only"
            );
        }
    }

    #[test]
    fn sha256_hex_uses_artifact_signing_domain_separator() {
        let plain_digest = Sha256::digest(b"release payload");
        let domain_digest = sha256_hex(b"release payload");
        let plain_digest = hex::encode(plain_digest);
        assert!(!ct_eq_bytes(
            domain_digest.as_bytes(),
            plain_digest.as_bytes()
        ));
    }

    #[test]
    fn key_id_uses_artifact_signing_domain_separator() {
        let vk = demo_signing_key().verifying_key();
        let plain_digest = Sha256::digest(vk.as_bytes());
        let plain_key_id = hex::encode(&plain_digest[..8]);
        let domain_key_id = KeyId::from_verifying_key(&vk).0;
        assert!(!ct_eq_bytes(
            domain_key_id.as_bytes(),
            plain_key_id.as_bytes()
        ));
    }

    #[test]
    fn key_transition_canonical_bytes_include_domain_separator() {
        let record =
            create_key_transition(&demo_signing_key(), &demo_signing_key_2().verifying_key());
        assert!(
            record
                .canonical_bytes()
                .starts_with(b"artifact_signing_transition_v1:")
        );
    }

    #[test]
    fn verify_release_rejects_signed_size_metadata_mismatch() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let mut manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);
        manifest
            .entries
            .get_mut(name)
            .expect("manifest entry should exist")
            .size_bytes = len_to_u64(content.len()).saturating_add(1);
        manifest.signature = sign_bytes(&sk, &manifest.canonical_bytes());

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sign_artifact(&sk, content));

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(report.manifest_signature_ok);
        assert!(!report.overall_pass);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .expect("failure reason should be present")
                .contains("size mismatch")
        );
    }

    #[test]
    fn verify_release_bad_manifest_signature_fails_overall_with_passing_artifact_result() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let mut manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);
        manifest.signature[0] ^= 0xff;

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sign_artifact(&sk, content));

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(!report.manifest_signature_ok);
        assert!(!report.overall_pass);
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].passed);
    }

    #[test]
    fn collect_threshold_rejects_zero_required_even_with_valid_signature() {
        let sk = demo_signing_key();
        let mut ring = KeyRing::new();
        let kid = ring.add_key(sk.verifying_key());
        let data = b"threshold payload";
        let partials = vec![PartialSignature {
            key_id: kid,
            signature: sign_bytes(&sk, data),
        }];

        let err = collect_threshold_signatures(data, &partials, &ring, 0)
            .expect_err("zero threshold must be rejected");
        assert!(matches!(
            err,
            ArtifactSigningError::ThresholdNotMet {
                required: 0,
                provided: 0
            }
        ));
    }

    #[test]
    fn verify_release_rejects_detached_signature_for_wrong_payload() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary v1.0";
        let name = "franken-node-v1.0.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);

        let mut arts = BTreeMap::new();
        arts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sign_artifact(&sk, b"different bytes"));

        let report = verify_release(&manifest, &arts, &sigs, &ring);
        assert!(report.manifest_signature_ok);
        assert!(!report.overall_pass);
        assert!(
            report.results[0]
                .failure_reason
                .as_ref()
                .expect("failure reason should be present")
                .contains("detached signature invalid")
        );
    }

    #[test]
    fn collect_threshold_rejects_unknown_key_with_valid_signature_bytes() {
        let sk = demo_signing_key();
        let ring = KeyRing::new();
        let data = b"threshold payload";
        let partials = vec![PartialSignature {
            key_id: KeyId::from_verifying_key(&sk.verifying_key()),
            signature: sign_bytes(&sk, data),
        }];

        let err = collect_threshold_signatures(data, &partials, &ring, 1)
            .expect_err("unknown signer must not satisfy threshold");
        assert!(matches!(
            err,
            ArtifactSigningError::ThresholdNotMet {
                required: 1,
                provided: 0
            }
        ));
    }

    #[test]
    fn key_transition_rejects_rebound_new_public_key() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let mut ring = KeyRing::new();
        ring.add_key(sk1.verifying_key());
        let mut record = create_key_transition(&sk1, &sk2.verifying_key());
        assert!(verify_key_transition(&record, &ring).is_ok());

        record.new_public_key_bytes[0] ^= 0x01;

        assert!(matches!(
            verify_key_transition(&record, &ring),
            Err(ArtifactSigningError::TransitionRecordInvalid)
        ));
    }

    #[test]
    fn mr_manifest_canonical_bytes_are_artifact_order_invariant() {
        let sk = demo_signing_key();
        let forward: Vec<(&str, &[u8])> = vec![
            ("zeta.bin", b"zeta payload"),
            ("alpha.bin", b"alpha payload"),
            ("middle.bin", b"middle payload"),
        ];
        let reverse: Vec<(&str, &[u8])> = vec![
            ("middle.bin", b"middle payload"),
            ("alpha.bin", b"alpha payload"),
            ("zeta.bin", b"zeta payload"),
        ];

        let forward_manifest = build_and_sign_manifest(&forward, &sk);
        let reverse_manifest = build_and_sign_manifest(&reverse, &sk);

        assert_eq!(
            forward_manifest.canonical_bytes(),
            reverse_manifest.canonical_bytes()
        );
        assert!(ct_eq_bytes(
            forward_manifest.signature.as_slice(),
            reverse_manifest.signature.as_slice()
        ));
        assert_eq!(
            forward_manifest
                .entries
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["alpha.bin", "middle.bin", "zeta.bin"]
        );
    }

    #[test]
    fn mr_parse_canonical_is_invariant_to_invalid_line_insertions() {
        let sk = demo_signing_key();
        let manifest = build_and_sign_manifest(
            &[
                ("alpha.bin", b"alpha payload" as &[u8]),
                ("beta.bin", b"beta payload" as &[u8]),
            ],
            &sk,
        );
        let clean =
            String::from_utf8(manifest.canonical_bytes()).expect("canonical manifest must be utf8");
        let bad_hash = "g".repeat(64);
        let traversal_hash = "b".repeat(64);
        let noisy = format!(
            "not even close\n{bad_hash}  ignored.bin  10\n{traversal_hash}  ../escape.bin  10\n{clean}{traversal_hash}  signed.bin  -1\n"
        );

        let clean_entries = ChecksumManifest::parse_canonical(&clean);
        let noisy_entries = ChecksumManifest::parse_canonical(&noisy);

        assert_eq!(clean_entries, noisy_entries);
    }

    #[test]
    fn mr_verify_release_is_artifact_map_insertion_order_invariant() {
        let (sk, _vk, ring) = setup_keys();
        let alpha = b"alpha release";
        let beta = b"beta release";
        let manifest = build_and_sign_manifest(
            &[
                ("alpha.tar.gz", alpha as &[u8]),
                ("beta.tar.gz", beta as &[u8]),
            ],
            &sk,
        );

        let mut forward_artifacts = BTreeMap::new();
        forward_artifacts.insert("alpha.tar.gz".to_string(), alpha.to_vec());
        forward_artifacts.insert("beta.tar.gz".to_string(), beta.to_vec());
        let mut reverse_artifacts = BTreeMap::new();
        reverse_artifacts.insert("beta.tar.gz".to_string(), beta.to_vec());
        reverse_artifacts.insert("alpha.tar.gz".to_string(), alpha.to_vec());

        let mut forward_sigs = BTreeMap::new();
        forward_sigs.insert("alpha.tar.gz".to_string(), sign_artifact(&sk, alpha));
        forward_sigs.insert("beta.tar.gz".to_string(), sign_artifact(&sk, beta));
        let mut reverse_sigs = BTreeMap::new();
        reverse_sigs.insert("beta.tar.gz".to_string(), sign_artifact(&sk, beta));
        reverse_sigs.insert("alpha.tar.gz".to_string(), sign_artifact(&sk, alpha));

        let forward_report = verify_release(&manifest, &forward_artifacts, &forward_sigs, &ring);
        let reverse_report = verify_release(&manifest, &reverse_artifacts, &reverse_sigs, &ring);

        assert_eq!(forward_report.overall_pass, reverse_report.overall_pass);
        assert_eq!(forward_report.results, reverse_report.results);
        assert!(forward_report.overall_pass);
    }

    #[test]
    fn mr_unlisted_artifact_injection_only_adds_unlisted_failure() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"release binary";
        let name = "listed.tar.gz";
        let manifest = build_and_sign_manifest(&[(name, content as &[u8])], &sk);

        let mut artifacts = BTreeMap::new();
        artifacts.insert(name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(name.to_string(), sign_artifact(&sk, content));
        let base_report = verify_release(&manifest, &artifacts, &sigs, &ring);
        assert!(base_report.overall_pass);

        artifacts.insert("injected.tar.gz".to_string(), b"injected payload".to_vec());
        let injected_report = verify_release(&manifest, &artifacts, &sigs, &ring);

        assert!(!injected_report.overall_pass);
        assert!(injected_report.results.iter().any(|result| {
            result.artifact_name == name && result.passed && result.failure_reason.is_none()
        }));
        assert!(injected_report.results.iter().any(|result| {
            result.artifact_name == "injected.tar.gz"
                && !result.passed
                && result.failure_reason.as_deref() == Some("unlisted artifact")
        }));
    }

    #[test]
    fn mr_artifact_rename_preserves_content_hash_but_rebinds_manifest_identity() {
        let (sk, _vk, ring) = setup_keys();
        let content = b"same release bytes";
        let first_name = "linux.tar.gz";
        let second_name = "darwin.tar.gz";

        let first_manifest = build_and_sign_manifest(&[(first_name, content as &[u8])], &sk);
        let second_manifest = build_and_sign_manifest(&[(second_name, content as &[u8])], &sk);
        let first_entry = first_manifest
            .entries
            .get(first_name)
            .expect("first manifest entry should exist");
        let second_entry = second_manifest
            .entries
            .get(second_name)
            .expect("second manifest entry should exist");

        assert!(ct_eq_bytes(
            first_entry.sha256.as_bytes(),
            second_entry.sha256.as_bytes()
        ));
        assert_ne!(
            first_manifest.canonical_bytes(),
            second_manifest.canonical_bytes()
        );

        let mut artifacts = BTreeMap::new();
        artifacts.insert(second_name.to_string(), content.to_vec());
        let mut sigs = BTreeMap::new();
        sigs.insert(second_name.to_string(), sign_artifact(&sk, content));
        let report = verify_release(&second_manifest, &artifacts, &sigs, &ring);
        assert!(report.overall_pass);
    }

    #[test]
    fn mr_threshold_signature_order_does_not_change_three_of_three_success() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let sk3 = demo_signing_key_3();
        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        let kid2 = ring.add_key(sk2.verifying_key());
        let kid3 = ring.add_key(sk3.verifying_key());
        let data = b"threshold order payload";
        let forward = vec![
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, data),
            },
            PartialSignature {
                key_id: kid2.clone(),
                signature: sign_bytes(&sk2, data),
            },
            PartialSignature {
                key_id: kid3.clone(),
                signature: sign_bytes(&sk3, data),
            },
        ];
        let reverse = vec![
            PartialSignature {
                key_id: kid3.clone(),
                signature: sign_bytes(&sk3, data),
            },
            PartialSignature {
                key_id: kid2.clone(),
                signature: sign_bytes(&sk2, data),
            },
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, data),
            },
        ];

        let forward_keys = collect_threshold_signatures(data, &forward, &ring, 3)
            .expect("forward order should satisfy threshold")
            .into_iter()
            .map(|partial| partial.key_id)
            .collect::<std::collections::BTreeSet<_>>();
        let reverse_keys = collect_threshold_signatures(data, &reverse, &ring, 3)
            .expect("reverse order should satisfy threshold")
            .into_iter()
            .map(|partial| partial.key_id)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(forward_keys, reverse_keys);
        assert!(verify_threshold(data, &forward, &ring, 3));
        assert!(verify_threshold(data, &reverse, &ring, 3));
    }

    #[test]
    fn mr_threshold_noise_signatures_do_not_break_sufficient_valid_set() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let mut ring = KeyRing::new();
        let kid1 = ring.add_key(sk1.verifying_key());
        let kid2 = ring.add_key(sk2.verifying_key());
        let data = b"threshold noisy payload";
        let clean = vec![
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, data),
            },
            PartialSignature {
                key_id: kid2.clone(),
                signature: sign_bytes(&sk2, data),
            },
        ];
        let noisy = vec![
            PartialSignature {
                key_id: KeyId("unknown-key".to_string()),
                signature: vec![0u8; 64],
            },
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, b"wrong payload"),
            },
            PartialSignature {
                key_id: kid1.clone(),
                signature: sign_bytes(&sk1, data),
            },
            PartialSignature {
                key_id: kid2.clone(),
                signature: sign_bytes(&sk2, data),
            },
        ];

        assert!(verify_threshold(data, &clean, &ring, 2));
        assert!(verify_threshold(data, &noisy, &ring, 2));
    }

    #[test]
    fn mr_duplicate_valid_signature_does_not_increase_unique_threshold_count() {
        let sk = demo_signing_key();
        let mut ring = KeyRing::new();
        let kid = ring.add_key(sk.verifying_key());
        let data = b"threshold duplicate payload";
        let duplicate_partials = vec![
            PartialSignature {
                key_id: kid.clone(),
                signature: sign_bytes(&sk, data),
            },
            PartialSignature {
                key_id: kid,
                signature: sign_bytes(&sk, data),
            },
        ];

        let err = collect_threshold_signatures(data, &duplicate_partials, &ring, 2)
            .expect_err("duplicate signer must not satisfy a two-key threshold");
        assert!(matches!(
            err,
            ArtifactSigningError::ThresholdNotMet {
                required: 2,
                provided: 1
            }
        ));
    }

    #[test]
    fn mr_key_transition_timestamp_rebinding_invalidates_signature() {
        let sk1 = demo_signing_key();
        let sk2 = demo_signing_key_2();
        let mut ring = KeyRing::new();
        ring.add_key(sk1.verifying_key());
        let mut record = create_key_transition(&sk1, &sk2.verifying_key());
        assert!(verify_key_transition(&record, &ring).is_ok());

        record.timestamp = record.timestamp.saturating_add(1);

        assert!(matches!(
            verify_key_transition(&record, &ring),
            Err(ArtifactSigningError::TransitionRecordInvalid)
        ));
    }

    #[test]
    fn mr_push_bounded_preserves_latest_window_and_handles_zero_capacity() {
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 3);
        assert_eq!(items, vec![2, 3, 4]);

        push_bounded(&mut items, 5, 0);
        assert!(items.is_empty());
    }
}

#[cfg(test)]
mod artifact_signing_boundary_negative_tests {
    use super::*;

    fn malicious_signer() -> ArtifactSigner {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        ArtifactSigner::new(signing_key)
    }

    #[test]
    fn negative_sign_artifact_rejects_empty_artifact_id() {
        let mut signer = malicious_signer();

        let result = signer.sign_artifact("", b"artifact-data", "trace-empty-id");

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn negative_sign_artifact_rejects_artifact_id_with_control_characters() {
        let mut signer = malicious_signer();

        let result = signer.sign_artifact(
            "artifact\n\r\t",
            b"artifact-data",
            "trace-control-chars"
        );

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn negative_sign_artifact_rejects_artifact_id_with_nul_bytes() {
        let mut signer = malicious_signer();

        let result = signer.sign_artifact(
            "artifact\0injection",
            b"artifact-data",
            "trace-nul-bytes"
        );

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn negative_sign_artifact_rejects_empty_trace_id() {
        let mut signer = malicious_signer();

        let result = signer.sign_artifact("artifact-valid", b"artifact-data", "");

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidTraceId)
        ));
    }

    #[test]
    fn negative_sign_artifact_handles_extremely_large_artifact_data() {
        let mut signer = malicious_signer();
        let large_data = vec![0x42; 10_000_000]; // 10MB artifact

        let result = signer.sign_artifact("large-artifact", &large_data, "trace-large");

        // Should handle large data gracefully
        match result {
            Ok(signature) => {
                // If signing succeeds, signature should be valid
                assert!(!signature.signature_hex.is_empty());
                assert_eq!(signature.artifact_id, "large-artifact");
            }
            Err(ArtifactSigningError::SigningFailed) => {
                // Failure due to size limits is acceptable
            }
            Err(other) => panic!("unexpected error for large data: {other:?}"),
        }
    }

    #[test]
    fn negative_verify_signature_rejects_invalid_signature_length() {
        let signer = malicious_signer();
        let verifying_key = signer.verifying_key();

        let invalid_signature = ArtifactSignature {
            artifact_id: "test-artifact".to_string(),
            checksum_sha256: "checksum".to_string(),
            signature_hex: "invalid".to_string(), // Too short
            timestamp: 1000,
        };

        let result = verify_signature(&invalid_signature, b"data", &verifying_key);

        assert!(matches!(
            result,
            Err(ArtifactSigningError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn negative_verify_signature_rejects_non_hex_signature() {
        let signer = malicious_signer();
        let verifying_key = signer.verifying_key();

        let invalid_signature = ArtifactSignature {
            artifact_id: "test-artifact".to_string(),
            checksum_sha256: "checksum".to_string(),
            signature_hex: "z".repeat(128), // Non-hex characters
            timestamp: 1000,
        };

        let result = verify_signature(&invalid_signature, b"data", &verifying_key);

        assert!(matches!(
            result,
            Err(ArtifactSigningError::VerificationFailed { .. })
        ));
    }

    #[test]
    fn negative_verify_signature_rejects_mismatched_checksum() {
        let mut signer = malicious_signer();
        let verifying_key = signer.verifying_key();
        let data = b"original-data";

        // Create valid signature for original data
        let signature = signer.sign_artifact("test-artifact", data, "trace-mismatch")
            .expect("signing should succeed");

        // Try to verify with different data
        let different_data = b"tampered-data";
        let result = verify_signature(&signature, different_data, &verifying_key);

        assert!(matches!(
            result,
            Err(ArtifactSigningError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn negative_create_key_ring_rejects_empty_keys_list() {
        let result = create_key_ring(vec![], 1);

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidKeyRing { .. })
        ));
    }

    #[test]
    fn negative_create_key_ring_rejects_threshold_greater_than_key_count() {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = key.verifying_key();

        let result = create_key_ring(vec![verifying_key], 2); // Threshold > key count

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidKeyRing { .. })
        ));
    }

    #[test]
    fn negative_create_key_ring_rejects_zero_threshold() {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = key.verifying_key();

        let result = create_key_ring(vec![verifying_key], 0); // Zero threshold

        assert!(matches!(
            result,
            Err(ArtifactSigningError::InvalidKeyRing { .. })
        ));
    }

    #[test]
    fn negative_verify_key_transition_rejects_future_timestamp() {
        let old_key = SigningKey::generate(&mut rand::thread_rng());
        let new_key = SigningKey::generate(&mut rand::thread_rng());
        let key_ring = create_key_ring(vec![old_key.verifying_key()], 1)
            .expect("key ring creation");

        let future_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs()
            .saturating_add(86400); // 1 day in future

        let mut record = create_key_transition_record(&old_key, &new_key, future_timestamp)
            .expect("transition record creation");

        let result = verify_key_transition(&record, &key_ring);

        assert!(matches!(
            result,
            Err(ArtifactSigningError::TransitionRecordInvalid)
        ));
    }

    #[test]
    fn negative_serde_rejects_unknown_artifact_signing_error_variant() {
        let result: Result<ArtifactSigningError, _> = serde_json::from_str(r#""UnknownError""#);

        assert!(result.is_err());
    }
}
