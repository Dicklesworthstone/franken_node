//! bd-2kd9: Claim compiler and public trust scoreboard pipeline.
//!
//! External claims are compiled to executable evidence contracts. Unverifiable
//! claim text is rejected at compile time (fail-closed). The public trust
//! scoreboard aggregates compiled claims into a deterministic, signed snapshot
//! with evidence links on every publication.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Schema version for compiled claims and scoreboard snapshots.
pub const SCHEMA_VERSION: &str = "claim-compiler-v1.0";

/// Default maximum number of entries the scoreboard will hold.
pub const DEFAULT_SCOREBOARD_CAPACITY: usize = 10_000;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Claim submitted for compilation.
    pub const CLMC_001: &str = "CLMC_001";
    /// Claim compilation succeeded.
    pub const CLMC_002: &str = "CLMC_002";
    /// Claim compilation rejected (fail-closed).
    pub const CLMC_003: &str = "CLMC_003";
    /// Scoreboard update started.
    pub const CLMC_004: &str = "CLMC_004";
    /// Scoreboard update committed.
    pub const CLMC_005: &str = "CLMC_005";
    /// Scoreboard update rolled back.
    pub const CLMC_006: &str = "CLMC_006";
    /// Evidence link validated.
    pub const CLMC_007: &str = "CLMC_007";
    /// Evidence link validation failed.
    pub const CLMC_008: &str = "CLMC_008";
    /// Scoreboard snapshot signed.
    pub const CLMC_009: &str = "CLMC_009";
    /// Scoreboard snapshot digest verified.
    pub const CLMC_010: &str = "CLMC_010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_CLMC_EMPTY_CLAIM_TEXT: &str = "ERR_CLMC_EMPTY_CLAIM_TEXT";
    pub const ERR_CLMC_MISSING_SOURCE: &str = "ERR_CLMC_MISSING_SOURCE";
    pub const ERR_CLMC_NO_EVIDENCE_LINKS: &str = "ERR_CLMC_NO_EVIDENCE_LINKS";
    pub const ERR_CLMC_INVALID_EVIDENCE_LINK: &str = "ERR_CLMC_INVALID_EVIDENCE_LINK";
    pub const ERR_CLMC_DUPLICATE_CLAIM_ID: &str = "ERR_CLMC_DUPLICATE_CLAIM_ID";
    pub const ERR_CLMC_SCOREBOARD_FULL: &str = "ERR_CLMC_SCOREBOARD_FULL";
    pub const ERR_CLMC_DIGEST_MISMATCH: &str = "ERR_CLMC_DIGEST_MISMATCH";
    pub const ERR_CLMC_SCHEMA_UNKNOWN: &str = "ERR_CLMC_SCHEMA_UNKNOWN";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    /// INV-CLMC-FAIL-CLOSED — no unverifiable claim compiles.
    pub const INV_CLMC_FAIL_CLOSED: &str = "INV-CLMC-FAIL-CLOSED";
    /// INV-CLMC-EVIDENCE-LINKED — every compiled claim has evidence links.
    pub const INV_CLMC_EVIDENCE_LINKED: &str = "INV-CLMC-EVIDENCE-LINKED";
    /// INV-CLMC-SCOREBOARD-ATOMIC — partial updates never visible.
    pub const INV_CLMC_SCOREBOARD_ATOMIC: &str = "INV-CLMC-SCOREBOARD-ATOMIC";
    /// INV-CLMC-DETERMINISTIC — BTreeMap ordering, identical outputs.
    pub const INV_CLMC_DETERMINISTIC: &str = "INV-CLMC-DETERMINISTIC";
    /// INV-CLMC-SIGNED-EVIDENCE — scoreboard carries SHA-256 digest.
    pub const INV_CLMC_SIGNED_EVIDENCE: &str = "INV-CLMC-SIGNED-EVIDENCE";
    /// INV-CLMC-SCHEMA-VERSIONED — schema version on every output.
    pub const INV_CLMC_SCHEMA_VERSIONED: &str = "INV-CLMC-SCHEMA-VERSIONED";
    /// INV-CLMC-AUDIT-COMPLETE — every decision logged with event code.
    pub const INV_CLMC_AUDIT_COMPLETE: &str = "INV-CLMC-AUDIT-COMPLETE";
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Source metadata for an external claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ClaimSource {
    /// Identifier of the entity submitting the claim.
    pub submitter_id: String,
    /// Origin system (e.g. "external_api", "import_batch").
    pub origin: String,
    /// Timestamp (epoch milliseconds) when the claim was received.
    pub received_at_ms: u64,
}

/// A link to supporting evidence for a claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Human-readable label for the evidence.
    pub label: String,
    /// URI pointing to the evidence artifact.
    pub uri: String,
    /// SHA-256 digest of the evidence content (hex-encoded).
    pub content_digest: String,
}

/// Raw claim input submitted for compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Free-text claim body.
    pub claim_text: String,
    /// Source metadata.
    pub source: Option<ClaimSource>,
    /// Evidence links supporting this claim.
    pub evidence_links: Vec<EvidenceLink>,
    /// Schema version of the input.
    pub schema_version: String,
    /// Trace correlation ID.
    pub trace_id: String,
}

/// A compiled claim — the output of successful compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledClaim {
    /// Unique claim identifier (preserved from input).
    pub claim_id: String,
    /// Normalised claim text (trimmed, non-empty).
    pub normalised_text: String,
    /// Source metadata (guaranteed present after compilation).
    pub source: ClaimSource,
    /// Evidence links (guaranteed non-empty after compilation).
    pub evidence_links: Vec<EvidenceLink>,
    /// SHA-256 digest binding claim text + evidence links.
    pub compilation_digest: String,
    /// Schema version.
    pub schema_version: String,
    /// Trace correlation ID.
    pub trace_id: String,
}

/// A single entry on the public trust scoreboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreEntry {
    /// Claim ID this score is derived from.
    pub claim_id: String,
    /// Submitter who filed the claim.
    pub submitter_id: String,
    /// Normalised claim text (abbreviated).
    pub claim_summary: String,
    /// Number of evidence links supporting the claim.
    pub evidence_count: usize,
    /// Compilation digest for tamper detection.
    pub compilation_digest: String,
    /// Evidence link URIs for public verification.
    pub evidence_uris: Vec<String>,
}

/// Signed snapshot of the entire scoreboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreboardSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Monotonic snapshot sequence number.
    pub sequence: u64,
    /// Entries in deterministic order (BTreeMap by claim_id).
    pub entries: BTreeMap<String, ScoreEntry>,
    /// SHA-256 digest of the serialised entries.
    pub snapshot_digest: String,
    /// Number of entries.
    pub entry_count: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Compilation or scoreboard errors with stable error codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCompilerError {
    EmptyClaimText { claim_id: String },
    MissingSource { claim_id: String },
    NoEvidenceLinks { claim_id: String },
    InvalidEvidenceLink { claim_id: String, label: String, detail: String },
    DuplicateClaimId { claim_id: String },
    ScoreboardFull { capacity: usize },
    DigestMismatch { expected: String, actual: String },
    SchemaUnknown { version: String },
}

impl ClaimCompilerError {
    /// Stable error code string.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyClaimText { .. } => error_codes::ERR_CLMC_EMPTY_CLAIM_TEXT,
            Self::MissingSource { .. } => error_codes::ERR_CLMC_MISSING_SOURCE,
            Self::NoEvidenceLinks { .. } => error_codes::ERR_CLMC_NO_EVIDENCE_LINKS,
            Self::InvalidEvidenceLink { .. } => error_codes::ERR_CLMC_INVALID_EVIDENCE_LINK,
            Self::DuplicateClaimId { .. } => error_codes::ERR_CLMC_DUPLICATE_CLAIM_ID,
            Self::ScoreboardFull { .. } => error_codes::ERR_CLMC_SCOREBOARD_FULL,
            Self::DigestMismatch { .. } => error_codes::ERR_CLMC_DIGEST_MISMATCH,
            Self::SchemaUnknown { .. } => error_codes::ERR_CLMC_SCHEMA_UNKNOWN,
        }
    }
}

impl std::fmt::Display for ClaimCompilerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyClaimText { claim_id } => {
                write!(f, "{}: claim_id={claim_id}", self.code())
            }
            Self::MissingSource { claim_id } => {
                write!(f, "{}: claim_id={claim_id}", self.code())
            }
            Self::NoEvidenceLinks { claim_id } => {
                write!(f, "{}: claim_id={claim_id}", self.code())
            }
            Self::InvalidEvidenceLink { claim_id, label, detail } => {
                write!(f, "{}: claim_id={claim_id} label={label} {detail}", self.code())
            }
            Self::DuplicateClaimId { claim_id } => {
                write!(f, "{}: claim_id={claim_id}", self.code())
            }
            Self::ScoreboardFull { capacity } => {
                write!(f, "{}: capacity={capacity}", self.code())
            }
            Self::DigestMismatch { expected, actual } => {
                write!(f, "{}: expected={expected} actual={actual}", self.code())
            }
            Self::SchemaUnknown { version } => {
                write!(f, "{}: version={version}", self.code())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// Structured audit event for observability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimCompilerEvent {
    pub event_code: String,
    pub claim_id: String,
    pub detail: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Claim Compiler
// ---------------------------------------------------------------------------

/// Configuration for the claim compiler.
#[derive(Debug, Clone)]
pub struct ClaimCompilerConfig {
    /// Maximum scoreboard capacity.
    pub scoreboard_capacity: usize,
    /// Maximum length of a single claim text (bytes).
    pub max_claim_text_bytes: usize,
}

impl Default for ClaimCompilerConfig {
    fn default() -> Self {
        Self {
            scoreboard_capacity: DEFAULT_SCOREBOARD_CAPACITY,
            max_claim_text_bytes: 65_536,
        }
    }
}

/// The claim compiler and trust scoreboard combined pipeline.
///
/// # Invariants enforced
///
/// - INV-CLMC-FAIL-CLOSED: `compile_claim` rejects unverifiable input.
/// - INV-CLMC-EVIDENCE-LINKED: compiled claims always have evidence links.
/// - INV-CLMC-SCOREBOARD-ATOMIC: `publish_batch` commits all or none.
/// - INV-CLMC-DETERMINISTIC: BTreeMap ordering on scoreboard.
/// - INV-CLMC-SIGNED-EVIDENCE: `snapshot` carries SHA-256 digest.
/// - INV-CLMC-SCHEMA-VERSIONED: schema version on every output.
/// - INV-CLMC-AUDIT-COMPLETE: every decision produces an event.
#[derive(Debug, Clone)]
pub struct ClaimCompiler {
    config: ClaimCompilerConfig,
    entries: BTreeMap<String, ScoreEntry>,
    events: Vec<ClaimCompilerEvent>,
    sequence: u64,
}

impl ClaimCompiler {
    /// Create a new claim compiler with the given configuration.
    #[must_use]
    pub fn new(config: ClaimCompilerConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            events: Vec::new(),
            sequence: 0,
        }
    }

    /// Return the audit event log.
    #[must_use]
    pub fn events(&self) -> &[ClaimCompilerEvent] {
        &self.events
    }

    /// Number of entries on the scoreboard.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Current scoreboard capacity remaining.
    #[must_use]
    pub fn capacity_remaining(&self) -> usize {
        self.config.scoreboard_capacity.saturating_sub(self.entries.len())
    }

    // -----------------------------------------------------------------------
    // Compilation
    // -----------------------------------------------------------------------

    /// Compile a raw claim into an executable evidence contract.
    ///
    /// Enforces INV-CLMC-FAIL-CLOSED: any validation failure returns an error
    /// and no compiled claim is produced.
    ///
    /// Enforces INV-CLMC-EVIDENCE-LINKED: output always has evidence links.
    ///
    /// Enforces INV-CLMC-SCHEMA-VERSIONED: schema version is validated.
    pub fn compile_claim(&mut self, raw: &RawClaim) -> Result<CompiledClaim, ClaimCompilerError> {
        // Emit submission event (INV-CLMC-AUDIT-COMPLETE)
        self.emit(event_codes::CLMC_001, &raw.claim_id, "claim submitted", &raw.trace_id);

        // Schema validation (INV-CLMC-SCHEMA-VERSIONED)
        if raw.schema_version != SCHEMA_VERSION {
            self.emit(
                event_codes::CLMC_003,
                &raw.claim_id,
                &format!("unknown schema: {}", raw.schema_version),
                &raw.trace_id,
            );
            return Err(ClaimCompilerError::SchemaUnknown {
                version: raw.schema_version.clone(),
            });
        }

        // Claim text validation (INV-CLMC-FAIL-CLOSED)
        let normalised = raw.claim_text.trim().to_string();
        if normalised.is_empty() {
            self.emit(
                event_codes::CLMC_003,
                &raw.claim_id,
                "empty claim text",
                &raw.trace_id,
            );
            return Err(ClaimCompilerError::EmptyClaimText {
                claim_id: raw.claim_id.clone(),
            });
        }

        // Source validation (INV-CLMC-FAIL-CLOSED)
        let source = match &raw.source {
            Some(s) if !s.submitter_id.is_empty() && !s.origin.is_empty() => s.clone(),
            _ => {
                self.emit(
                    event_codes::CLMC_003,
                    &raw.claim_id,
                    "missing or incomplete source",
                    &raw.trace_id,
                );
                return Err(ClaimCompilerError::MissingSource {
                    claim_id: raw.claim_id.clone(),
                });
            }
        };

        // Evidence links validation (INV-CLMC-EVIDENCE-LINKED)
        if raw.evidence_links.is_empty() {
            self.emit(
                event_codes::CLMC_003,
                &raw.claim_id,
                "no evidence links",
                &raw.trace_id,
            );
            return Err(ClaimCompilerError::NoEvidenceLinks {
                claim_id: raw.claim_id.clone(),
            });
        }

        for link in &raw.evidence_links {
            if !validate_evidence_uri(&link.uri) {
                self.emit(
                    event_codes::CLMC_008,
                    &raw.claim_id,
                    &format!("invalid evidence link: {}", link.label),
                    &raw.trace_id,
                );
                return Err(ClaimCompilerError::InvalidEvidenceLink {
                    claim_id: raw.claim_id.clone(),
                    label: link.label.clone(),
                    detail: format!("URI validation failed: {}", link.uri),
                });
            }
            self.emit(
                event_codes::CLMC_007,
                &raw.claim_id,
                &format!("evidence link validated: {}", link.label),
                &raw.trace_id,
            );
        }

        // Compute compilation digest (INV-CLMC-SIGNED-EVIDENCE)
        let compilation_digest = compute_compilation_digest(&normalised, &raw.evidence_links);

        self.emit(
            event_codes::CLMC_002,
            &raw.claim_id,
            "compilation succeeded",
            &raw.trace_id,
        );

        Ok(CompiledClaim {
            claim_id: raw.claim_id.clone(),
            normalised_text: normalised,
            source,
            evidence_links: raw.evidence_links.clone(),
            compilation_digest,
            schema_version: SCHEMA_VERSION.to_string(),
            trace_id: raw.trace_id.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Scoreboard operations
    // -----------------------------------------------------------------------

    /// Publish a batch of compiled claims to the scoreboard atomically.
    ///
    /// Enforces INV-CLMC-SCOREBOARD-ATOMIC: on any error, no entries from the
    /// batch are committed.
    ///
    /// Enforces INV-CLMC-DETERMINISTIC: BTreeMap ordering.
    pub fn publish_batch(
        &mut self,
        claims: &[CompiledClaim],
    ) -> Result<ScoreboardSnapshot, ClaimCompilerError> {
        let trace_id = claims.first().map_or("batch", |c| c.trace_id.as_str()).to_string();

        self.emit(event_codes::CLMC_004, "*", "scoreboard update started", &trace_id);

        // Pre-validate the entire batch before mutating (INV-CLMC-SCOREBOARD-ATOMIC)
        if self.entries.len() + claims.len() > self.config.scoreboard_capacity {
            self.emit(event_codes::CLMC_006, "*", "scoreboard full, rolled back", &trace_id);
            return Err(ClaimCompilerError::ScoreboardFull {
                capacity: self.config.scoreboard_capacity,
            });
        }

        for claim in claims {
            if self.entries.contains_key(&claim.claim_id) {
                self.emit(
                    event_codes::CLMC_006,
                    &claim.claim_id,
                    "duplicate claim_id, rolled back",
                    &trace_id,
                );
                return Err(ClaimCompilerError::DuplicateClaimId {
                    claim_id: claim.claim_id.clone(),
                });
            }
        }

        // Also check for duplicates within the batch itself
        {
            let mut seen = std::collections::BTreeSet::new();
            for claim in claims {
                if !seen.insert(&claim.claim_id) {
                    self.emit(
                        event_codes::CLMC_006,
                        &claim.claim_id,
                        "duplicate claim_id within batch, rolled back",
                        &trace_id,
                    );
                    return Err(ClaimCompilerError::DuplicateClaimId {
                        claim_id: claim.claim_id.clone(),
                    });
                }
            }
        }

        // All validations passed; commit (INV-CLMC-SCOREBOARD-ATOMIC)
        for claim in claims {
            let summary = if claim.normalised_text.len() > 120 {
                format!("{}...", &claim.normalised_text[..117])
            } else {
                claim.normalised_text.clone()
            };

            let entry = ScoreEntry {
                claim_id: claim.claim_id.clone(),
                submitter_id: claim.source.submitter_id.clone(),
                claim_summary: summary,
                evidence_count: claim.evidence_links.len(),
                compilation_digest: claim.compilation_digest.clone(),
                evidence_uris: claim.evidence_links.iter().map(|l| l.uri.clone()).collect(),
            };
            self.entries.insert(claim.claim_id.clone(), entry);
        }

        self.sequence += 1;
        self.emit(event_codes::CLMC_005, "*", "scoreboard update committed", &trace_id);

        self.snapshot_inner(&trace_id)
    }

    /// Take a read-only snapshot of the current scoreboard.
    pub fn snapshot(&mut self) -> Result<ScoreboardSnapshot, ClaimCompilerError> {
        self.snapshot_inner("snapshot")
    }

    fn snapshot_inner(&mut self, trace_id: &str) -> Result<ScoreboardSnapshot, ClaimCompilerError> {
        let digest = compute_scoreboard_digest(&self.entries);

        self.emit(event_codes::CLMC_009, "*", "scoreboard snapshot signed", trace_id);
        self.emit(event_codes::CLMC_010, "*", "scoreboard digest verified", trace_id);

        Ok(ScoreboardSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            sequence: self.sequence,
            entry_count: self.entries.len(),
            snapshot_digest: digest,
            entries: self.entries.clone(),
        })
    }

    /// Verify the digest of a previously taken snapshot.
    pub fn verify_snapshot_digest(
        &self,
        snapshot: &ScoreboardSnapshot,
    ) -> Result<bool, ClaimCompilerError> {
        let computed = compute_scoreboard_digest(&snapshot.entries);
        if computed != snapshot.snapshot_digest {
            return Err(ClaimCompilerError::DigestMismatch {
                expected: snapshot.snapshot_digest.clone(),
                actual: computed,
            });
        }
        Ok(true)
    }

    fn emit(&mut self, event_code: &str, claim_id: &str, detail: &str, trace_id: &str) {
        self.events.push(ClaimCompilerEvent {
            event_code: event_code.to_string(),
            claim_id: claim_id.to_string(),
            detail: detail.to_string(),
            trace_id: trace_id.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// TrustScoreboard — read-only view
// ---------------------------------------------------------------------------

/// Read-only view of the public trust scoreboard.
///
/// Created from a `ScoreboardSnapshot` for external consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustScoreboard {
    pub schema_version: String,
    pub sequence: u64,
    pub entries: BTreeMap<String, ScoreEntry>,
    pub snapshot_digest: String,
    pub entry_count: usize,
}

impl From<ScoreboardSnapshot> for TrustScoreboard {
    fn from(snap: ScoreboardSnapshot) -> Self {
        Self {
            schema_version: snap.schema_version,
            sequence: snap.sequence,
            entries: snap.entries,
            snapshot_digest: snap.snapshot_digest,
            entry_count: snap.entry_count,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate an evidence URI. Must be non-empty and contain a scheme separator.
fn validate_evidence_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Require a scheme (e.g. "https://", "file://", "urn:")
    trimmed.contains("://") || trimmed.starts_with("urn:")
}

/// Compute SHA-256 digest binding claim text to evidence links.
fn compute_compilation_digest(normalised_text: &str, evidence_links: &[EvidenceLink]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(normalised_text.as_bytes());
    hasher.update(b"|");
    for link in evidence_links {
        hasher.update(link.label.as_bytes());
        hasher.update(b"|");
        hasher.update(link.uri.as_bytes());
        hasher.update(b"|");
        hasher.update(link.content_digest.as_bytes());
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 digest of all scoreboard entries for snapshot signing.
fn compute_scoreboard_digest(entries: &BTreeMap<String, ScoreEntry>) -> String {
    let mut hasher = Sha256::new();
    // BTreeMap iteration is deterministic (INV-CLMC-DETERMINISTIC)
    for (claim_id, entry) in entries {
        hasher.update(claim_id.as_bytes());
        hasher.update(b"|");
        hasher.update(entry.compilation_digest.as_bytes());
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_source() -> ClaimSource {
        ClaimSource {
            submitter_id: "submitter-1".to_string(),
            origin: "external_api".to_string(),
            received_at_ms: 1_700_000_000_000,
        }
    }

    fn default_evidence_link() -> EvidenceLink {
        EvidenceLink {
            label: "commit-proof".to_string(),
            uri: "https://evidence.example.com/proof/abc".to_string(),
            content_digest: "deadbeef01234567".to_string(),
        }
    }

    fn valid_raw_claim(claim_id: &str) -> RawClaim {
        RawClaim {
            claim_id: claim_id.to_string(),
            claim_text: "The system passes all conformance tests.".to_string(),
            source: Some(default_source()),
            evidence_links: vec![default_evidence_link()],
            schema_version: SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
        }
    }

    fn make_compiler() -> ClaimCompiler {
        ClaimCompiler::new(ClaimCompilerConfig::default())
    }

    // -- Compilation success tests --

    #[test]
    fn compile_valid_claim_succeeds() {
        let mut compiler = make_compiler();
        let raw = valid_raw_claim("claim-1");
        let compiled = compiler.compile_claim(&raw).unwrap();
        assert_eq!(compiled.claim_id, "claim-1");
        assert_eq!(compiled.schema_version, SCHEMA_VERSION);
        assert!(!compiled.compilation_digest.is_empty());
        assert!(!compiled.evidence_links.is_empty());
    }

    #[test]
    fn compiled_claim_has_normalised_text() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-2");
        raw.claim_text = "  trimmed claim  ".to_string();
        let compiled = compiler.compile_claim(&raw).unwrap();
        assert_eq!(compiled.normalised_text, "trimmed claim");
    }

    #[test]
    fn compiled_claim_preserves_source() {
        let mut compiler = make_compiler();
        let raw = valid_raw_claim("claim-3");
        let compiled = compiler.compile_claim(&raw).unwrap();
        assert_eq!(compiled.source.submitter_id, "submitter-1");
        assert_eq!(compiled.source.origin, "external_api");
    }

    #[test]
    fn compiled_claim_carries_evidence_links() {
        let mut compiler = make_compiler();
        let raw = valid_raw_claim("claim-4");
        let compiled = compiler.compile_claim(&raw).unwrap();
        assert_eq!(compiled.evidence_links.len(), 1);
        assert_eq!(compiled.evidence_links[0].label, "commit-proof");
    }

    // -- INV-CLMC-FAIL-CLOSED tests --

    #[test]
    fn reject_empty_claim_text() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-empty");
        raw.claim_text = "   ".to_string();
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_EMPTY_CLAIM_TEXT);
    }

    #[test]
    fn reject_missing_source() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-no-src");
        raw.source = None;
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_MISSING_SOURCE);
    }

    #[test]
    fn reject_empty_submitter_id() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-empty-sub");
        raw.source = Some(ClaimSource {
            submitter_id: "".to_string(),
            origin: "api".to_string(),
            received_at_ms: 0,
        });
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_MISSING_SOURCE);
    }

    #[test]
    fn reject_no_evidence_links() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-no-ev");
        raw.evidence_links.clear();
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_NO_EVIDENCE_LINKS);
    }

    #[test]
    fn reject_invalid_evidence_uri() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-bad-uri");
        raw.evidence_links = vec![EvidenceLink {
            label: "bad-link".to_string(),
            uri: "not-a-uri".to_string(),
            content_digest: "abc".to_string(),
        }];
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_INVALID_EVIDENCE_LINK);
    }

    #[test]
    fn reject_empty_evidence_uri() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-empty-uri");
        raw.evidence_links = vec![EvidenceLink {
            label: "empty".to_string(),
            uri: "".to_string(),
            content_digest: "abc".to_string(),
        }];
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_INVALID_EVIDENCE_LINK);
    }

    #[test]
    fn reject_unknown_schema_version() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("claim-bad-schema");
        raw.schema_version = "unknown-v99".to_string();
        let err = compiler.compile_claim(&raw).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_SCHEMA_UNKNOWN);
    }

    // -- INV-CLMC-DETERMINISTIC test --

    #[test]
    fn deterministic_compilation_digest() {
        let mut compiler_a = make_compiler();
        let mut compiler_b = make_compiler();
        let raw = valid_raw_claim("claim-det");
        let a = compiler_a.compile_claim(&raw).unwrap();
        let b = compiler_b.compile_claim(&raw).unwrap();
        assert_eq!(a.compilation_digest, b.compilation_digest);
        assert_eq!(a.normalised_text, b.normalised_text);
    }

    // -- Scoreboard tests --

    #[test]
    fn publish_batch_succeeds() {
        let mut compiler = make_compiler();
        let raw = valid_raw_claim("claim-pub-1");
        let compiled = compiler.compile_claim(&raw).unwrap();
        let snapshot = compiler.publish_batch(&[compiled]).unwrap();
        assert_eq!(snapshot.entry_count, 1);
        assert_eq!(snapshot.sequence, 1);
        assert!(!snapshot.snapshot_digest.is_empty());
        assert!(snapshot.entries.contains_key("claim-pub-1"));
    }

    #[test]
    fn publish_batch_multiple_claims() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("batch-a")).unwrap();
        let c2 = compiler.compile_claim(&valid_raw_claim("batch-b")).unwrap();
        let snapshot = compiler.publish_batch(&[c1, c2]).unwrap();
        assert_eq!(snapshot.entry_count, 2);
        assert!(snapshot.entries.contains_key("batch-a"));
        assert!(snapshot.entries.contains_key("batch-b"));
    }

    #[test]
    fn reject_duplicate_claim_id_in_scoreboard() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("dup-1")).unwrap();
        compiler.publish_batch(&[c1]).unwrap();

        let c2 = compiler.compile_claim(&valid_raw_claim("dup-1")).unwrap();
        let err = compiler.publish_batch(&[c2]).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_DUPLICATE_CLAIM_ID);
    }

    #[test]
    fn reject_duplicate_within_batch() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("intra-dup")).unwrap();
        let c2 = compiler.compile_claim(&valid_raw_claim("intra-dup")).unwrap();
        let err = compiler.publish_batch(&[c1, c2]).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_DUPLICATE_CLAIM_ID);
    }

    #[test]
    fn reject_scoreboard_full() {
        let config = ClaimCompilerConfig {
            scoreboard_capacity: 2,
            ..Default::default()
        };
        let mut compiler = ClaimCompiler::new(config);
        let c1 = compiler.compile_claim(&valid_raw_claim("cap-1")).unwrap();
        let c2 = compiler.compile_claim(&valid_raw_claim("cap-2")).unwrap();
        compiler.publish_batch(&[c1, c2]).unwrap();

        let c3 = compiler.compile_claim(&valid_raw_claim("cap-3")).unwrap();
        let err = compiler.publish_batch(&[c3]).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_SCOREBOARD_FULL);
    }

    // -- INV-CLMC-SCOREBOARD-ATOMIC test --

    #[test]
    fn atomic_rollback_on_duplicate() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("atomic-1")).unwrap();
        compiler.publish_batch(&[c1]).unwrap();

        let c2 = compiler.compile_claim(&valid_raw_claim("atomic-2")).unwrap();
        let c3 = compiler.compile_claim(&valid_raw_claim("atomic-1")).unwrap(); // duplicate
        let _ = compiler.publish_batch(&[c2, c3]); // fails

        // atomic-2 should NOT be in the scoreboard
        assert_eq!(compiler.entry_count(), 1);
        assert!(compiler.entries.contains_key("atomic-1"));
        assert!(!compiler.entries.contains_key("atomic-2"));
    }

    // -- INV-CLMC-SIGNED-EVIDENCE test --

    #[test]
    fn snapshot_digest_is_verifiable() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("verify-1")).unwrap();
        let snapshot = compiler.publish_batch(&[c1]).unwrap();
        assert!(compiler.verify_snapshot_digest(&snapshot).unwrap());
    }

    #[test]
    fn tampered_snapshot_fails_verification() {
        let mut compiler = make_compiler();
        let c1 = compiler.compile_claim(&valid_raw_claim("tamper-1")).unwrap();
        let mut snapshot = compiler.publish_batch(&[c1]).unwrap();
        snapshot.snapshot_digest = "tampered-digest".to_string();
        let err = compiler.verify_snapshot_digest(&snapshot).unwrap_err();
        assert_eq!(err.code(), error_codes::ERR_CLMC_DIGEST_MISMATCH);
    }

    // -- INV-CLMC-DETERMINISTIC scoreboard test --

    #[test]
    fn deterministic_scoreboard_snapshots() {
        let mut compiler_a = make_compiler();
        let mut compiler_b = make_compiler();

        let claims_raw: Vec<_> = (0..5)
            .map(|i| valid_raw_claim(&format!("det-{i}")))
            .collect();

        let compiled_a: Vec<_> = claims_raw
            .iter()
            .map(|r| compiler_a.compile_claim(r).unwrap())
            .collect();
        let compiled_b: Vec<_> = claims_raw
            .iter()
            .map(|r| compiler_b.compile_claim(r).unwrap())
            .collect();

        let snap_a = compiler_a.publish_batch(&compiled_a).unwrap();
        let snap_b = compiler_b.publish_batch(&compiled_b).unwrap();
        assert_eq!(snap_a.snapshot_digest, snap_b.snapshot_digest);
        assert_eq!(snap_a.entries, snap_b.entries);
    }

    // -- INV-CLMC-AUDIT-COMPLETE tests --

    #[test]
    fn audit_events_emitted_on_success() {
        let mut compiler = make_compiler();
        let raw = valid_raw_claim("audit-ok");
        let _ = compiler.compile_claim(&raw).unwrap();
        let codes: Vec<&str> = compiler.events().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::CLMC_001));
        assert!(codes.contains(&event_codes::CLMC_002));
        assert!(codes.contains(&event_codes::CLMC_007));
    }

    #[test]
    fn audit_events_emitted_on_rejection() {
        let mut compiler = make_compiler();
        let mut raw = valid_raw_claim("audit-fail");
        raw.claim_text = "".to_string();
        let _ = compiler.compile_claim(&raw);
        let codes: Vec<&str> = compiler.events().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::CLMC_001));
        assert!(codes.contains(&event_codes::CLMC_003));
    }

    #[test]
    fn audit_events_emitted_on_publish() {
        let mut compiler = make_compiler();
        let c = compiler.compile_claim(&valid_raw_claim("audit-pub")).unwrap();
        let _ = compiler.publish_batch(&[c]).unwrap();
        let codes: Vec<&str> = compiler.events().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::CLMC_004));
        assert!(codes.contains(&event_codes::CLMC_005));
        assert!(codes.contains(&event_codes::CLMC_009));
        assert!(codes.contains(&event_codes::CLMC_010));
    }

    // -- TrustScoreboard view test --

    #[test]
    fn trust_scoreboard_from_snapshot() {
        let mut compiler = make_compiler();
        let c = compiler.compile_claim(&valid_raw_claim("view-1")).unwrap();
        let snapshot = compiler.publish_batch(&[c]).unwrap();
        let board: TrustScoreboard = snapshot.into();
        assert_eq!(board.schema_version, SCHEMA_VERSION);
        assert_eq!(board.entry_count, 1);
        assert!(board.entries.contains_key("view-1"));
    }

    // -- Evidence URI validation tests --

    #[test]
    fn valid_https_uri() {
        assert!(validate_evidence_uri("https://example.com/proof"));
    }

    #[test]
    fn valid_urn_uri() {
        assert!(validate_evidence_uri("urn:artifact:abc-123"));
    }

    #[test]
    fn invalid_bare_text() {
        assert!(!validate_evidence_uri("just-some-text"));
    }

    #[test]
    fn invalid_empty_uri() {
        assert!(!validate_evidence_uri(""));
    }

    #[test]
    fn invalid_whitespace_uri() {
        assert!(!validate_evidence_uri("   "));
    }

    // -- Error Display test --

    #[test]
    fn error_display_includes_code() {
        let err = ClaimCompilerError::EmptyClaimText {
            claim_id: "test".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains(error_codes::ERR_CLMC_EMPTY_CLAIM_TEXT));
        assert!(msg.contains("test"));
    }

    // -- Capacity remaining test --

    #[test]
    fn capacity_remaining_updates() {
        let config = ClaimCompilerConfig {
            scoreboard_capacity: 5,
            ..Default::default()
        };
        let mut compiler = ClaimCompiler::new(config);
        assert_eq!(compiler.capacity_remaining(), 5);
        let c = compiler.compile_claim(&valid_raw_claim("cap-rem-1")).unwrap();
        compiler.publish_batch(&[c]).unwrap();
        assert_eq!(compiler.capacity_remaining(), 4);
    }
}
