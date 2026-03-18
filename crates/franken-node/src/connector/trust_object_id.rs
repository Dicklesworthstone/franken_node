//! bd-1l5: Canonical product trust object IDs with domain separation.
//!
//! Provides stable, collision-free identifiers for every trust object in the
//! system. Trust objects span multiple domains — extensions, trust cards,
//! receipts, policy checkpoints, migration artifacts, and verifier claims.
//! Domain separation via prefix ensures cross-domain collisions are
//! structurally impossible.
//!
//! # Invariants
//!
//! - INV-TOI-PREFIX: Every ID has a valid domain prefix from the registry.
//! - INV-TOI-DETERMINISTIC: Same inputs always produce the same ID.
//! - INV-TOI-COLLISION: Cross-domain collisions are structurally impossible
//!   due to the prefix scheme.
//! - INV-TOI-DIGEST: Digest uses SHA-256 (256-bit, >= 128 bits collision
//!   resistance).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Trust object ID derived.
    pub const TOI_DERIVED: &str = "TOI-001";
    /// Trust object ID validation failed.
    pub const TOI_VALIDATION_FAILED: &str = "TOI-002";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_TOI_INVALID_PREFIX: &str = "ERR_TOI_INVALID_PREFIX";
    pub const ERR_TOI_MALFORMED_DIGEST: &str = "ERR_TOI_MALFORMED_DIGEST";
    pub const ERR_TOI_INVALID_FORMAT: &str = "ERR_TOI_INVALID_FORMAT";
    pub const ERR_TOI_UNKNOWN_DOMAIN: &str = "ERR_TOI_UNKNOWN_DOMAIN";
}

// ---------------------------------------------------------------------------
// DomainPrefix
// ---------------------------------------------------------------------------

/// Trust object domain prefixes for collision-free ID separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DomainPrefix {
    /// Extension trust objects.
    Extension,
    /// Trust card objects.
    TrustCard,
    /// Receipt objects.
    Receipt,
    /// Policy checkpoint objects.
    PolicyCheckpoint,
    /// Migration artifact objects.
    MigrationArtifact,
    /// Verifier claim objects.
    VerifierClaim,
}

impl DomainPrefix {
    /// The canonical string prefix for this domain.
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::Extension => "ext:",
            Self::TrustCard => "tcard:",
            Self::Receipt => "rcpt:",
            Self::PolicyCheckpoint => "pchk:",
            Self::MigrationArtifact => "migr:",
            Self::VerifierClaim => "vclaim:",
        }
    }

    /// All domain prefixes.
    pub fn all() -> &'static [DomainPrefix; 6] {
        &[
            Self::Extension,
            Self::TrustCard,
            Self::Receipt,
            Self::PolicyCheckpoint,
            Self::MigrationArtifact,
            Self::VerifierClaim,
        ]
    }

    /// Parse a domain prefix from its string representation.
    pub fn from_prefix(s: &str) -> Option<Self> {
        match s {
            "ext:" => Some(Self::Extension),
            "tcard:" => Some(Self::TrustCard),
            "rcpt:" => Some(Self::Receipt),
            "pchk:" => Some(Self::PolicyCheckpoint),
            "migr:" => Some(Self::MigrationArtifact),
            "vclaim:" => Some(Self::VerifierClaim),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Extension => "extension",
            Self::TrustCard => "trust_card",
            Self::Receipt => "receipt",
            Self::PolicyCheckpoint => "policy_checkpoint",
            Self::MigrationArtifact => "migration_artifact",
            Self::VerifierClaim => "verifier_claim",
        }
    }
}

impl fmt::Display for DomainPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix())
    }
}

// ---------------------------------------------------------------------------
// DerivationMode
// ---------------------------------------------------------------------------

/// How a trust object ID was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DerivationMode {
    /// Derived from content hash alone: `<prefix>sha256:<digest>`.
    ContentAddressed,
    /// Derived from epoch + sequence + content: `<prefix><epoch>:<seq>:<digest>`.
    ContextAddressed,
}

impl DerivationMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ContentAddressed => "content_addressed",
            Self::ContextAddressed => "context_addressed",
        }
    }
}

// ---------------------------------------------------------------------------
// TrustObjectId
// ---------------------------------------------------------------------------

/// A canonical trust object identifier with domain separation.
///
/// # Format
///
/// Content-addressed: `<prefix>sha256:<hex_digest>`
/// Context-addressed: `<prefix><epoch>:<sequence>:<hex_digest>`
///
/// # INV-TOI-PREFIX
/// Every ID carries a valid domain prefix from the registry.
///
/// # INV-TOI-DETERMINISTIC
/// Same inputs always produce the same ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrustObjectId {
    /// Domain prefix.
    pub domain: DomainPrefix,
    /// Hash algorithm (always "sha256").
    pub hash_algorithm: String,
    /// Hex-encoded digest.
    pub digest: String,
    /// How this ID was derived.
    pub derivation_mode: DerivationMode,
    /// Epoch (context-addressed only).
    pub epoch: Option<u64>,
    /// Sequence within epoch (context-addressed only).
    pub sequence: Option<u64>,
}

impl TrustObjectId {
    /// Derive a content-addressed ID from raw data.
    ///
    /// Format: `<prefix>sha256:<hex_digest>`
    ///
    /// # INV-TOI-DETERMINISTIC
    /// Same domain + data always produce the same ID.
    pub fn derive_content_addressed(domain: DomainPrefix, data: &[u8]) -> Self {
        let digest = sha256_digest(data);
        Self {
            domain,
            hash_algorithm: "sha256".to_string(),
            digest,
            derivation_mode: DerivationMode::ContentAddressed,
            epoch: None,
            sequence: None,
        }
    }

    /// Derive a context-addressed ID from epoch, sequence, and data.
    ///
    /// Format: `<prefix><epoch>:<sequence>:<hex_digest>`
    ///
    /// The digest is computed over `canonical_bytes(epoch || sequence || data)`.
    pub fn derive_context_addressed(
        domain: DomainPrefix,
        epoch: u64,
        sequence: u64,
        data: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"trust_object_derive_v1:");
        hasher.update(epoch.to_be_bytes());
        hasher.update(sequence.to_be_bytes());
        hasher.update(data);
        let digest = hex::encode(hasher.finalize());
        Self {
            domain,
            hash_algorithm: "sha256".to_string(),
            digest,
            derivation_mode: DerivationMode::ContextAddressed,
            epoch: Some(epoch),
            sequence: Some(sequence),
        }
    }

    /// Full canonical string form.
    ///
    /// Content-addressed: `<prefix>sha256:<digest>`
    /// Context-addressed: `<prefix><epoch>:<sequence>:<digest>`
    pub fn full_form(&self) -> String {
        match self.derivation_mode {
            DerivationMode::ContentAddressed => {
                format!("{}sha256:{}", self.domain.prefix(), self.digest)
            }
            DerivationMode::ContextAddressed => {
                format!(
                    "{}{}:{}:{}",
                    self.domain.prefix(),
                    self.epoch.unwrap_or(0),
                    self.sequence.unwrap_or(0),
                    self.digest,
                )
            }
        }
    }

    /// Short form for logging: `<prefix><first_8_hex_chars>`.
    pub fn short_form(&self) -> String {
        let short_digest = if self.digest.len() >= 8 {
            &self.digest[..8]
        } else {
            &self.digest
        };
        format!("{}{short_digest}", self.domain.prefix())
    }

    /// Parse a trust object ID from its canonical string form.
    ///
    /// # INV-TOI-PREFIX
    /// Rejects IDs without a valid domain prefix.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        // Find the domain prefix
        let (domain, rest) = Self::split_prefix(s)?;

        // Try content-addressed: sha256:<digest>
        if let Some(digest) = rest.strip_prefix("sha256:") {
            validate_hex_digest(digest)?;
            return Ok(Self {
                domain,
                hash_algorithm: "sha256".to_string(),
                digest: digest.to_string(),
                derivation_mode: DerivationMode::ContentAddressed,
                epoch: None,
                sequence: None,
            });
        }

        // Try context-addressed: <epoch>:<sequence>:<digest>
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            let epoch = parts[0]
                .parse::<u64>()
                .map_err(|_| IdError::InvalidFormat {
                    input: s.to_string(),
                    reason: "epoch is not a valid u64".to_string(),
                })?;
            let sequence = parts[1]
                .parse::<u64>()
                .map_err(|_| IdError::InvalidFormat {
                    input: s.to_string(),
                    reason: "sequence is not a valid u64".to_string(),
                })?;
            let digest = parts[2];
            validate_hex_digest(digest)?;
            return Ok(Self {
                domain,
                hash_algorithm: "sha256".to_string(),
                digest: digest.to_string(),
                derivation_mode: DerivationMode::ContextAddressed,
                epoch: Some(epoch),
                sequence: Some(sequence),
            });
        }

        Err(IdError::InvalidFormat {
            input: s.to_string(),
            reason: "expected sha256:<digest> or <epoch>:<seq>:<digest> after prefix".to_string(),
        })
    }

    /// Validate a string as a well-formed trust object ID.
    pub fn validate(s: &str) -> bool {
        Self::parse(s).is_ok()
    }

    /// Split prefix from remainder.
    fn split_prefix(s: &str) -> Result<(DomainPrefix, &str), IdError> {
        for domain in DomainPrefix::all() {
            if let Some(rest) = s.strip_prefix(domain.prefix()) {
                return Ok((*domain, rest));
            }
        }
        Err(IdError::InvalidPrefix {
            input: s.to_string(),
        })
    }
}

impl fmt::Display for TrustObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_form())
    }
}

// ---------------------------------------------------------------------------
// IdError
// ---------------------------------------------------------------------------

/// Errors from trust object ID operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    InvalidPrefix { input: String },
    MalformedDigest { input: String, reason: String },
    InvalidFormat { input: String, reason: String },
    UnknownDomain { domain: String },
}

impl IdError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPrefix { .. } => error_codes::ERR_TOI_INVALID_PREFIX,
            Self::MalformedDigest { .. } => error_codes::ERR_TOI_MALFORMED_DIGEST,
            Self::InvalidFormat { .. } => error_codes::ERR_TOI_INVALID_FORMAT,
            Self::UnknownDomain { .. } => error_codes::ERR_TOI_UNKNOWN_DOMAIN,
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix { input } => {
                write!(f, "invalid prefix in trust object ID: {input}")
            }
            Self::MalformedDigest { input, reason } => {
                write!(f, "malformed digest: {reason} in {input}")
            }
            Self::InvalidFormat { input, reason } => {
                write!(f, "invalid format: {reason} in {input}")
            }
            Self::UnknownDomain { domain } => {
                write!(f, "unknown domain: {domain}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IdRegistry
// ---------------------------------------------------------------------------

/// Registry of valid domain prefixes with version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdRegistry {
    /// Schema version.
    pub version: String,
    /// Registered domain prefixes.
    pub domains: BTreeMap<String, DomainRegistryEntry>,
}

/// Entry in the domain prefix registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRegistryEntry {
    /// Human-readable description.
    pub description: String,
    /// The string prefix (e.g., "ext:").
    pub prefix: String,
    /// Hash algorithm required.
    pub hash_algorithm: String,
    /// Minimum digest length in hex chars.
    pub min_digest_hex_len: usize,
}

impl IdRegistry {
    /// Create a new registry with all 6 canonical domains.
    pub fn new() -> Self {
        let mut domains = BTreeMap::new();
        for dp in DomainPrefix::all() {
            domains.insert(
                dp.label().to_string(),
                DomainRegistryEntry {
                    description: format!("{} trust objects", dp.label()),
                    prefix: dp.prefix().to_string(),
                    hash_algorithm: "sha256".to_string(),
                    min_digest_hex_len: 64,
                },
            );
        }
        Self {
            version: "1.0.0".to_string(),
            domains,
        }
    }

    /// Check if a prefix string is valid.
    pub fn is_valid_prefix(&self, prefix: &str) -> bool {
        self.domains.values().any(|e| e.prefix == prefix)
    }

    /// Number of registered domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

impl Default for IdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IdEvent
// ---------------------------------------------------------------------------

/// Structured audit event for trust object ID operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdEvent {
    pub event_code: String,
    pub domain: String,
    pub derivation_mode: String,
    pub short_id: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute SHA-256 digest as hex string.
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trust_object_hash_v1:");
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Canonical byte representation for hashing. Sorts keys deterministically
/// for structured data. For raw bytes, returns as-is.
pub fn canonical_bytes(data: &[u8]) -> Vec<u8> {
    // For raw byte input, canonical form is identity.
    // For structured data, callers should pre-serialize with sorted keys.
    data.to_vec()
}

/// Validate a hex digest string.
fn validate_hex_digest(s: &str) -> Result<(), IdError> {
    if s.len() != 64 {
        return Err(IdError::MalformedDigest {
            input: s.to_string(),
            reason: format!("expected 64 hex chars, got {}", s.len()),
        });
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(IdError::MalformedDigest {
            input: s.to_string(),
            reason: "contains non-hex characters".to_string(),
        });
    }
    Ok(())
}

/// Demonstrate trust object ID derivation for all domains.
pub fn demo_trust_object_ids() -> Vec<IdEvent> {
    let mut events = Vec::new();

    for domain in DomainPrefix::all() {
        let data = format!("sample-{}", domain.label());
        let id = TrustObjectId::derive_content_addressed(*domain, data.as_bytes());
        events.push(IdEvent {
            event_code: event_codes::TOI_DERIVED.to_string(),
            domain: domain.label().to_string(),
            derivation_mode: "content_addressed".to_string(),
            short_id: id.short_form(),
            detail: format!("derived content-addressed ID for {}", domain.label()),
        });
    }

    // Context-addressed examples
    for (i, domain) in DomainPrefix::all().iter().enumerate() {
        let data = format!("ctx-sample-{}", domain.label());
        let id = TrustObjectId::derive_context_addressed(*domain, 100, i as u64, data.as_bytes());
        events.push(IdEvent {
            event_code: event_codes::TOI_DERIVED.to_string(),
            domain: domain.label().to_string(),
            derivation_mode: "context_addressed".to_string(),
            short_id: id.short_form(),
            detail: format!("derived context-addressed ID for {}", domain.label()),
        });
    }

    events
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── DomainPrefix tests ──────────────────────────────────────────

    #[test]
    fn test_all_domains_count() {
        assert_eq!(DomainPrefix::all().len(), 6);
    }

    #[test]
    fn test_domain_prefixes_unique() {
        let prefixes: Vec<&str> = DomainPrefix::all().iter().map(|d| d.prefix()).collect();
        let unique: std::collections::BTreeSet<&str> = prefixes.iter().copied().collect();
        assert_eq!(prefixes.len(), unique.len());
    }

    #[test]
    fn test_domain_prefix_round_trip() {
        for domain in DomainPrefix::all() {
            let parsed = DomainPrefix::from_prefix(domain.prefix());
            assert_eq!(parsed, Some(*domain), "round-trip failed for {domain:?}");
        }
    }

    #[test]
    fn test_domain_prefix_invalid() {
        assert_eq!(DomainPrefix::from_prefix("bogus:"), None);
        assert_eq!(DomainPrefix::from_prefix(""), None);
    }

    #[test]
    fn test_domain_labels_unique() {
        let labels: Vec<&str> = DomainPrefix::all().iter().map(|d| d.label()).collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn test_domain_prefix_display() {
        assert_eq!(format!("{}", DomainPrefix::Extension), "ext:");
        assert_eq!(format!("{}", DomainPrefix::VerifierClaim), "vclaim:");
    }

    // ── DerivationMode tests ────────────────────────────────────────

    #[test]
    fn test_derivation_mode_labels() {
        assert_eq!(
            DerivationMode::ContentAddressed.label(),
            "content_addressed"
        );
        assert_eq!(
            DerivationMode::ContextAddressed.label(),
            "context_addressed"
        );
    }

    // ── TrustObjectId: content-addressed ────────────────────────────

    #[test]
    fn test_derive_content_addressed() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"hello world");
        assert_eq!(id.domain, DomainPrefix::Extension);
        assert_eq!(id.hash_algorithm, "sha256");
        assert_eq!(id.derivation_mode, DerivationMode::ContentAddressed);
        assert_eq!(id.digest.len(), 64);
        assert!(id.epoch.is_none());
        assert!(id.sequence.is_none());
    }

    #[test]
    fn test_content_addressed_deterministic() {
        let id1 = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"data");
        let id2 = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"data");
        assert_eq!(id1, id2);
        assert_eq!(id1.full_form(), id2.full_form());
    }

    #[test]
    fn test_content_addressed_different_data() {
        let id1 = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"a");
        let id2 = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"b");
        assert_ne!(id1.digest, id2.digest);
    }

    #[test]
    fn test_cross_domain_different_ids() {
        let id1 = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"data");
        let id2 = TrustObjectId::derive_content_addressed(DomainPrefix::TrustCard, b"data");
        // Same digest, different full_form due to prefix
        assert_eq!(id1.digest, id2.digest);
        assert_ne!(id1.full_form(), id2.full_form());
    }

    #[test]
    fn test_content_addressed_full_form() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Receipt, b"test");
        let full = id.full_form();
        assert!(full.starts_with("rcpt:sha256:"));
        assert_eq!(full.len(), "rcpt:sha256:".len() + 64);
    }

    // ── TrustObjectId: context-addressed ────────────────────────────

    #[test]
    fn test_derive_context_addressed() {
        let id = TrustObjectId::derive_context_addressed(
            DomainPrefix::PolicyCheckpoint,
            42,
            7,
            b"checkpoint-data",
        );
        assert_eq!(id.domain, DomainPrefix::PolicyCheckpoint);
        assert_eq!(id.derivation_mode, DerivationMode::ContextAddressed);
        assert_eq!(id.epoch, Some(42));
        assert_eq!(id.sequence, Some(7));
        assert_eq!(id.digest.len(), 64);
    }

    #[test]
    fn test_context_addressed_deterministic() {
        let id1 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 1, 2, b"d");
        let id2 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 1, 2, b"d");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_context_addressed_different_epoch() {
        let id1 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 1, 0, b"d");
        let id2 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 2, 0, b"d");
        assert_ne!(id1.digest, id2.digest);
    }

    #[test]
    fn test_context_addressed_different_sequence() {
        let id1 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 1, 0, b"d");
        let id2 =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 1, 1, b"d");
        assert_ne!(id1.digest, id2.digest);
    }

    #[test]
    fn test_context_addressed_full_form() {
        let id =
            TrustObjectId::derive_context_addressed(DomainPrefix::MigrationArtifact, 10, 3, b"mig");
        let full = id.full_form();
        assert!(full.starts_with("migr:10:3:"));
    }

    // ── TrustObjectId: short form ───────────────────────────────────

    #[test]
    fn test_short_form() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"test");
        let short = id.short_form();
        assert!(short.starts_with("ext:"));
        // prefix + 8 hex chars
        assert_eq!(short.len(), "ext:".len() + 8);
    }

    #[test]
    fn test_short_form_all_domains() {
        for domain in DomainPrefix::all() {
            let id = TrustObjectId::derive_content_addressed(*domain, b"test");
            let short = id.short_form();
            assert!(short.starts_with(domain.prefix()));
        }
    }

    // ── TrustObjectId: parse ────────────────────────────────────────

    #[test]
    fn test_parse_content_addressed() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"hello");
        let full = id.full_form();
        let parsed = TrustObjectId::parse(&full).unwrap();
        assert_eq!(parsed.domain, DomainPrefix::Extension);
        assert_eq!(parsed.derivation_mode, DerivationMode::ContentAddressed);
        assert_eq!(parsed.digest, id.digest);
    }

    #[test]
    fn test_parse_context_addressed() {
        let id =
            TrustObjectId::derive_context_addressed(DomainPrefix::PolicyCheckpoint, 42, 7, b"data");
        let full = id.full_form();
        let parsed = TrustObjectId::parse(&full).unwrap();
        assert_eq!(parsed.domain, DomainPrefix::PolicyCheckpoint);
        assert_eq!(parsed.derivation_mode, DerivationMode::ContextAddressed);
        assert_eq!(parsed.epoch, Some(42));
        assert_eq!(parsed.sequence, Some(7));
        assert_eq!(parsed.digest, id.digest);
    }

    #[test]
    fn test_parse_round_trip_all_domains_content() {
        for domain in DomainPrefix::all() {
            let id = TrustObjectId::derive_content_addressed(*domain, b"test-data");
            let full = id.full_form();
            let parsed = TrustObjectId::parse(&full).unwrap();
            assert_eq!(parsed.domain, *domain);
            assert_eq!(parsed.digest, id.digest);
        }
    }

    #[test]
    fn test_parse_round_trip_all_domains_context() {
        for (i, domain) in DomainPrefix::all().iter().enumerate() {
            let id = TrustObjectId::derive_context_addressed(*domain, 100, i as u64, b"ctx-data");
            let full = id.full_form();
            let parsed = TrustObjectId::parse(&full).unwrap();
            assert_eq!(parsed.domain, *domain);
            assert_eq!(parsed.epoch, Some(100));
            assert_eq!(parsed.sequence, Some(i as u64));
        }
    }

    // ── TrustObjectId: parse errors ─────────────────────────────────

    #[test]
    fn test_parse_invalid_prefix() {
        let result = TrustObjectId::parse("bogus:sha256:abcd");
        assert!(result.is_err());
        match result.unwrap_err() {
            IdError::InvalidPrefix { .. } => {}
            other => unreachable!("expected InvalidPrefix, got {other}"),
        }
    }

    #[test]
    fn test_parse_malformed_digest_too_short() {
        let result = TrustObjectId::parse("ext:sha256:abcd");
        assert!(result.is_err());
        match result.unwrap_err() {
            IdError::MalformedDigest { reason, .. } => {
                assert!(reason.contains("64"));
            }
            other => unreachable!("expected MalformedDigest, got {other}"),
        }
    }

    #[test]
    fn test_parse_malformed_digest_non_hex() {
        let bad = format!("ext:sha256:{}", "g".repeat(64));
        let result = TrustObjectId::parse(&bad);
        assert!(result.is_err());
        match result.unwrap_err() {
            IdError::MalformedDigest { reason, .. } => {
                assert!(reason.contains("non-hex"));
            }
            other => unreachable!("expected MalformedDigest, got {other}"),
        }
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = TrustObjectId::parse("ext:not-valid");
        assert!(result.is_err());
    }

    // ── TrustObjectId: validate ─────────────────────────────────────

    #[test]
    fn test_validate_valid() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"v");
        assert!(TrustObjectId::validate(&id.full_form()));
    }

    #[test]
    fn test_validate_invalid() {
        assert!(!TrustObjectId::validate("bogus:sha256:abc"));
        assert!(!TrustObjectId::validate(""));
        assert!(!TrustObjectId::validate("ext:"));
    }

    // ── TrustObjectId: Display ──────────────────────────────────────

    #[test]
    fn test_display() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"disp");
        assert_eq!(format!("{id}"), id.full_form());
    }

    // ── IdError tests ───────────────────────────────────────────────

    #[test]
    fn test_error_codes() {
        let e1 = IdError::InvalidPrefix { input: "x".into() };
        assert_eq!(e1.code(), "ERR_TOI_INVALID_PREFIX");
        let e2 = IdError::MalformedDigest {
            input: "x".into(),
            reason: "r".into(),
        };
        assert_eq!(e2.code(), "ERR_TOI_MALFORMED_DIGEST");
        let e3 = IdError::InvalidFormat {
            input: "x".into(),
            reason: "r".into(),
        };
        assert_eq!(e3.code(), "ERR_TOI_INVALID_FORMAT");
        let e4 = IdError::UnknownDomain { domain: "x".into() };
        assert_eq!(e4.code(), "ERR_TOI_UNKNOWN_DOMAIN");
    }

    #[test]
    fn test_error_display() {
        let e = IdError::InvalidPrefix {
            input: "bad:id".into(),
        };
        assert!(e.to_string().contains("bad:id"));
    }

    // ── IdRegistry tests ────────────────────────────────────────────

    #[test]
    fn test_registry_new() {
        let reg = IdRegistry::new();
        assert_eq!(reg.domain_count(), 6);
        assert_eq!(reg.version, "1.0.0");
    }

    #[test]
    fn test_registry_valid_prefixes() {
        let reg = IdRegistry::new();
        for domain in DomainPrefix::all() {
            assert!(reg.is_valid_prefix(domain.prefix()));
        }
    }

    #[test]
    fn test_registry_invalid_prefix() {
        let reg = IdRegistry::new();
        assert!(!reg.is_valid_prefix("bogus:"));
    }

    #[test]
    fn test_registry_default() {
        let reg = IdRegistry::default();
        assert_eq!(reg.domain_count(), 6);
    }

    // ── Helper tests ────────────────────────────────────────────────

    #[test]
    fn test_sha256_digest_deterministic() {
        let d1 = sha256_digest(b"test");
        let d2 = sha256_digest(b"test");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sha256_digest_length() {
        let d = sha256_digest(b"x");
        assert_eq!(d.len(), 64);
    }

    #[test]
    fn test_sha256_digest_different_inputs() {
        let d1 = sha256_digest(b"a");
        let d2 = sha256_digest(b"b");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_canonical_bytes_identity() {
        let data = b"raw bytes";
        assert_eq!(canonical_bytes(data), data.to_vec());
    }

    #[test]
    fn test_validate_hex_digest_valid() {
        let d = sha256_digest(b"test");
        assert!(validate_hex_digest(&d).is_ok());
    }

    #[test]
    fn test_validate_hex_digest_too_short() {
        assert!(validate_hex_digest("abcd").is_err());
    }

    #[test]
    fn test_validate_hex_digest_non_hex() {
        assert!(validate_hex_digest(&"g".repeat(64)).is_err());
    }

    // ── Demo function ───────────────────────────────────────────────

    #[test]
    fn test_demo_trust_object_ids() {
        let events = demo_trust_object_ids();
        // 6 content-addressed + 6 context-addressed
        assert_eq!(events.len(), 12);
        for e in &events {
            assert_eq!(e.event_code, event_codes::TOI_DERIVED);
        }
    }

    // ── Cross-domain collision resistance ───────────────────────────

    #[test]
    fn test_cross_domain_collision_impossible() {
        let data = b"identical";
        let mut full_forms = std::collections::BTreeSet::new();
        for domain in DomainPrefix::all() {
            let id = TrustObjectId::derive_content_addressed(*domain, data);
            let inserted = full_forms.insert(id.full_form());
            assert!(inserted, "collision detected for {domain:?}");
        }
        assert_eq!(full_forms.len(), 6);
    }

    #[test]
    fn test_within_domain_no_collisions_random() {
        // Test 1000 random inputs in the same domain
        let mut digests = std::collections::BTreeSet::new();
        for i in 0..1000 {
            let data = format!("random-input-{i}");
            let id =
                TrustObjectId::derive_content_addressed(DomainPrefix::Extension, data.as_bytes());
            digests.insert(id.digest);
        }
        assert_eq!(digests.len(), 1000);
    }

    // ── Serde roundtrip ─────────────────────────────────────────────

    #[test]
    fn test_trust_object_id_serde() {
        let id = TrustObjectId::derive_content_addressed(DomainPrefix::Extension, b"ser");
        let json = serde_json::to_string(&id).unwrap();
        let parsed: TrustObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_domain_prefix_serde() {
        let json = serde_json::to_string(&DomainPrefix::Extension).unwrap();
        let parsed: DomainPrefix = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DomainPrefix::Extension);
    }

    #[test]
    fn test_derivation_mode_serde() {
        let json = serde_json::to_string(&DerivationMode::ContentAddressed).unwrap();
        let parsed: DerivationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DerivationMode::ContentAddressed);
    }

    #[test]
    fn test_id_registry_serde() {
        let reg = IdRegistry::new();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: IdRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.domain_count(), 6);
    }

    #[test]
    fn test_id_event_serde() {
        let e = IdEvent {
            event_code: "TOI-001".into(),
            domain: "extension".into(),
            derivation_mode: "content_addressed".into(),
            short_id: "ext:abcd1234".into(),
            detail: "test".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: IdEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "TOI-001");
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<DomainPrefix>();
        assert_sync::<DomainPrefix>();
        assert_send::<DerivationMode>();
        assert_sync::<DerivationMode>();
        assert_send::<TrustObjectId>();
        assert_sync::<TrustObjectId>();
        assert_send::<IdError>();
        assert_sync::<IdError>();
        assert_send::<IdRegistry>();
        assert_sync::<IdRegistry>();
        assert_send::<IdEvent>();
        assert_sync::<IdEvent>();
    }
}
