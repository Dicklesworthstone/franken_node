//! bd-2aj: Ecosystem compliance evidence API.
//!
//! Accepts, stores, indexes, and serves compliance evidence artifacts with
//! content-addressed storage (SHA-256 keyed) and tamper-evident retrieval.
//!
//! Evidence artifacts include verification_evidence.json blobs, signed
//! attestations, and audit reports.
//!
//! Satisfies INV-ENE-TAMPER: content-addressed storage ensures tamper-evident
//! retrieval.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::MAX_EVENTS;

// -- Event codes ---------------------------------------------------------------

pub const ENE_005_COMPLIANCE_EVIDENCE_STORED: &str = "ENE-005";
pub const ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED: &str = "ENE-006";
pub const ENE_007_COMPLIANCE_TAMPER_CHECK_PASS: &str = "ENE-007";
pub const ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL: &str = "ENE-008";

// -- Invariant tags ------------------------------------------------------------

pub const INV_ENE_TAMPER: &str = "INV-ENE-TAMPER";

// -- Error codes ---------------------------------------------------------------

pub const ERR_ENE_TAMPER: &str = "ERR-ENE-TAMPER";

// -- Errors --------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ComplianceError {
    #[error("evidence artifact `{0}` not found")]
    NotFound(String),
    #[error("invalid evidence artifact: {0}")]
    InvalidEvidence(String),
    #[error("tamper evidence check failed for `{0}` (code: {ERR_ENE_TAMPER})")]
    TamperDetected(String),
    #[error("duplicate evidence submission: hash `{0}` already exists")]
    DuplicateEvidence(String),
}

// -- Evidence source -----------------------------------------------------------

/// Source program that generated the compliance evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    MigrationSingularity,
    TrustFabric,
    VerifierEconomy,
    CompatibilityCore,
    SecurityAudit,
    External,
}

impl std::fmt::Display for EvidenceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MigrationSingularity => write!(f, "migration_singularity"),
            Self::TrustFabric => write!(f, "trust_fabric"),
            Self::VerifierEconomy => write!(f, "verifier_economy"),
            Self::CompatibilityCore => write!(f, "compatibility_core"),
            Self::SecurityAudit => write!(f, "security_audit"),
            Self::External => write!(f, "external"),
        }
    }
}

// -- Evidence artifact ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    /// Content-addressed hash (SHA-256 of canonical content).
    pub content_hash: String,
    /// Publisher ID that submitted this evidence.
    pub publisher_id: String,
    /// Source program that generated this evidence.
    pub source: EvidenceSource,
    /// Human-readable title.
    pub title: String,
    /// The actual evidence payload (canonical JSON string).
    pub content: String,
    /// Timestamp of submission.
    pub submitted_at: String,
    /// Optional signed attestation.
    pub attestation: Option<String>,
    /// Tags for indexing.
    pub tags: Vec<String>,
}

// -- Evidence events -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub event_code: String,
    pub content_hash: String,
    pub detail: String,
    pub timestamp: String,
    pub trace_id: String,
}

// -- Index entry ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceIndexEntry {
    pub content_hash: String,
    pub publisher_id: String,
    pub source: EvidenceSource,
    pub title: String,
    pub submitted_at: String,
    pub tags: Vec<String>,
}

// -- Compliance evidence store -------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvidenceStore {
    artifacts: BTreeMap<String, ComplianceEvidence>,
    events: Vec<ComplianceEvent>,
}

impl Default for ComplianceEvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceEvidenceStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            artifacts: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    fn emit_event(&mut self, event: ComplianceEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    fn validate_evidence_integrity(
        requested_hash: &str,
        evidence: &ComplianceEvidence,
    ) -> Result<(), String> {
        if !crate::security::constant_time::ct_eq(requested_hash, &evidence.content_hash) {
            return Err(format!(
                "requested hash {} does not match stored hash {}",
                requested_hash, evidence.content_hash
            ));
        }

        let recomputed = Self::compute_content_hash(&evidence.content);
        if !crate::security::constant_time::ct_eq(&recomputed, &evidence.content_hash) {
            return Err(format!(
                "tamper detected: expected {}, got {}",
                evidence.content_hash, recomputed
            ));
        }

        Ok(())
    }

    /// Compute the content-addressed hash for a piece of content.
    #[must_use]
    pub fn compute_content_hash(content: &str) -> String {
        let content_bytes = content.as_bytes();
        let content_len = u64::try_from(content_bytes.len()).unwrap_or(u64::MAX);
        let mut hasher = Sha256::new();
        hasher.update(b"ecosystem_compliance_hash_v1:");
        hasher.update(content_len.to_le_bytes());
        hasher.update(content_bytes);
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }

    /// Store a compliance evidence artifact.
    ///
    /// The content_hash is computed from the content and used as the storage key.
    /// Returns the content hash.
    #[allow(clippy::too_many_arguments)]
    pub fn store_evidence(
        &mut self,
        publisher_id: &str,
        source: EvidenceSource,
        title: &str,
        content: &str,
        attestation: Option<&str>,
        tags: &[String],
        timestamp: &str,
        trace_id: &str,
    ) -> Result<String, ComplianceError> {
        if publisher_id.trim().is_empty() {
            return Err(ComplianceError::InvalidEvidence(
                "publisher id must not be empty".to_owned(),
            ));
        }
        if publisher_id.trim() != publisher_id {
            return Err(ComplianceError::InvalidEvidence(
                "publisher id must be trimmed".to_owned(),
            ));
        }
        if title.trim().is_empty() {
            return Err(ComplianceError::InvalidEvidence(
                "title must not be empty".to_owned(),
            ));
        }
        if title.trim() != title {
            return Err(ComplianceError::InvalidEvidence(
                "title must be trimmed".to_owned(),
            ));
        }
        if content.trim().is_empty() {
            return Err(ComplianceError::InvalidEvidence(
                "content must not be empty".to_owned(),
            ));
        }
        if timestamp.trim().is_empty() {
            return Err(ComplianceError::InvalidEvidence(
                "timestamp must not be empty".to_owned(),
            ));
        }
        if timestamp.trim() != timestamp {
            return Err(ComplianceError::InvalidEvidence(
                "timestamp must be trimmed".to_owned(),
            ));
        }
        if attestation.is_some_and(|value| value.trim().is_empty() || value.trim() != value) {
            return Err(ComplianceError::InvalidEvidence(
                "attestation must be non-empty and trimmed when provided".to_owned(),
            ));
        }
        if tags
            .iter()
            .any(|tag| tag.trim().is_empty() || tag.trim() != tag)
        {
            return Err(ComplianceError::InvalidEvidence(
                "tags must be non-empty and trimmed".to_owned(),
            ));
        }

        let content_hash = Self::compute_content_hash(content);

        if self.artifacts.contains_key(&content_hash) {
            return Err(ComplianceError::DuplicateEvidence(content_hash));
        }

        let evidence = ComplianceEvidence {
            content_hash: content_hash.clone(),
            publisher_id: publisher_id.to_owned(),
            source,
            title: title.to_owned(),
            content: content.to_owned(),
            submitted_at: timestamp.to_owned(),
            attestation: attestation.map(|s| s.to_owned()),
            tags: tags.to_vec(),
        };

        self.artifacts.insert(content_hash.clone(), evidence);

        self.emit_event(ComplianceEvent {
            event_code: ENE_005_COMPLIANCE_EVIDENCE_STORED.to_owned(),
            content_hash: content_hash.clone(),
            detail: format!("stored evidence '{}' from {}", title, publisher_id),
            timestamp: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        });

        Ok(content_hash)
    }

    /// Retrieve evidence by content hash, with tamper-evidence verification.
    pub fn retrieve_evidence(
        &mut self,
        content_hash: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<ComplianceEvidence, ComplianceError> {
        let evidence = self
            .artifacts
            .get(content_hash)
            .cloned()
            .ok_or_else(|| ComplianceError::NotFound(content_hash.to_owned()))?;

        if let Err(detail) = Self::validate_evidence_integrity(content_hash, &evidence) {
            self.emit_event(ComplianceEvent {
                event_code: ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL.to_owned(),
                content_hash: content_hash.to_owned(),
                detail,
                timestamp: timestamp.to_owned(),
                trace_id: trace_id.to_owned(),
            });
            return Err(ComplianceError::TamperDetected(content_hash.to_owned()));
        }

        self.emit_event(ComplianceEvent {
            event_code: ENE_007_COMPLIANCE_TAMPER_CHECK_PASS.to_owned(),
            content_hash: content_hash.to_owned(),
            detail: "tamper check passed".to_owned(),
            timestamp: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        });

        self.emit_event(ComplianceEvent {
            event_code: ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED.to_owned(),
            content_hash: content_hash.to_owned(),
            detail: format!("retrieved evidence '{}'", evidence.title),
            timestamp: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        });

        Ok(evidence)
    }

    /// Verify tamper evidence for a stored artifact (without retrieving).
    pub fn verify_tamper_evidence(
        &mut self,
        content_hash: &str,
        timestamp: &str,
        trace_id: &str,
    ) -> Result<bool, ComplianceError> {
        let evidence = self
            .artifacts
            .get(content_hash)
            .ok_or_else(|| ComplianceError::NotFound(content_hash.to_owned()))?;

        let (valid, event_code, detail) =
            match Self::validate_evidence_integrity(content_hash, evidence) {
                Ok(()) => (
                    true,
                    ENE_007_COMPLIANCE_TAMPER_CHECK_PASS,
                    "tamper verification: pass".to_owned(),
                ),
                Err(detail) => (
                    false,
                    ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL,
                    format!("tamper verification: fail ({detail})"),
                ),
            };

        self.emit_event(ComplianceEvent {
            event_code: event_code.to_owned(),
            content_hash: content_hash.to_owned(),
            detail,
            timestamp: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        });

        Ok(valid)
    }

    /// Search the evidence index by source.
    #[must_use]
    pub fn search_by_source(&self, source: EvidenceSource) -> Vec<ComplianceIndexEntry> {
        self.artifacts
            .values()
            .filter(|e| e.source == source)
            .map(|e| ComplianceIndexEntry {
                content_hash: e.content_hash.clone(),
                publisher_id: e.publisher_id.clone(),
                source: e.source,
                title: e.title.clone(),
                submitted_at: e.submitted_at.clone(),
                tags: e.tags.clone(),
            })
            .collect()
    }

    /// Search the evidence index by publisher.
    #[must_use]
    pub fn search_by_publisher(&self, publisher_id: &str) -> Vec<ComplianceIndexEntry> {
        self.artifacts
            .values()
            .filter(|e| e.publisher_id == publisher_id)
            .map(|e| ComplianceIndexEntry {
                content_hash: e.content_hash.clone(),
                publisher_id: e.publisher_id.clone(),
                source: e.source,
                title: e.title.clone(),
                submitted_at: e.submitted_at.clone(),
                tags: e.tags.clone(),
            })
            .collect()
    }

    /// Search the evidence index by tag.
    #[must_use]
    pub fn search_by_tag(&self, tag: &str) -> Vec<ComplianceIndexEntry> {
        self.artifacts
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .map(|e| ComplianceIndexEntry {
                content_hash: e.content_hash.clone(),
                publisher_id: e.publisher_id.clone(),
                source: e.source,
                title: e.title.clone(),
                submitted_at: e.submitted_at.clone(),
                tags: e.tags.clone(),
            })
            .collect()
    }

    /// Get total stored evidence count.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.artifacts.len()
    }

    /// List all evidence artifacts (index view).
    #[must_use]
    pub fn list_evidence(&self) -> Vec<ComplianceIndexEntry> {
        self.artifacts
            .values()
            .map(|e| ComplianceIndexEntry {
                content_hash: e.content_hash.clone(),
                publisher_id: e.publisher_id.clone(),
                source: e.source,
                title: e.title.clone(),
                submitted_at: e.submitted_at.clone(),
                tags: e.tags.clone(),
            })
            .collect()
    }

    /// Take all pending events (drains the buffer).
    pub fn take_events(&mut self) -> Vec<ComplianceEvent> {
        std::mem::take(&mut self.events)
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

// -- Tests ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;

    fn ts(n: u32) -> String {
        format!("2026-01-{n:02}T00:00:00Z")
    }

    #[test]
    fn test_compute_content_hash() {
        let hash = ComplianceEvidenceStore::compute_content_hash("hello world");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_compute_content_hash_deterministic() {
        let h1 = ComplianceEvidenceStore::compute_content_hash("test content");
        let h2 = ComplianceEvidenceStore::compute_content_hash("test content");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_content_hash_different_content() {
        let h1 = ComplianceEvidenceStore::compute_content_hash("content A");
        let h2 = ComplianceEvidenceStore::compute_content_hash("content B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_content_hash_differs_from_legacy_unframed_digest() {
        let content = "legacy boundary payload";
        let framed = ComplianceEvidenceStore::compute_content_hash(content);
        let legacy_digest = Sha256::digest(
            [
                b"ecosystem_compliance_hash_v1:" as &[u8],
                content.as_bytes(),
            ]
            .concat(),
        );
        let legacy = format!("sha256:{}", hex::encode(legacy_digest));

        assert_ne!(framed, legacy);
    }

    #[test]
    fn test_store_evidence() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Migration Test",
                r#"{"pass": true}"#,
                None,
                &["migration".to_owned()],
                &ts(1),
                "trace-1",
            )
            .unwrap();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(store.evidence_count(), 1);
    }

    #[test]
    fn test_store_duplicate_rejected() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Evidence A",
                "same content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let result = store.store_evidence(
            "pub-2",
            EvidenceSource::TrustFabric,
            "Evidence B",
            "same content",
            None,
            &[],
            &ts(2),
            "t",
        );
        assert!(matches!(result, Err(ComplianceError::DuplicateEvidence(_))));
    }

    #[test]
    fn test_duplicate_submission_does_not_mutate_store_or_emit_event() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Evidence A",
                "same content",
                None,
                &[],
                &ts(1),
                "trace-original",
            )
            .unwrap();
        store.take_events();

        let duplicate = store.store_evidence(
            "pub-2",
            EvidenceSource::SecurityAudit,
            "Evidence B",
            "same content",
            Some("duplicate-attestation"),
            &["audit".to_owned()],
            &ts(2),
            "trace-duplicate",
        );

        assert!(matches!(
            duplicate,
            Err(ComplianceError::DuplicateEvidence(_))
        ));
        assert_eq!(store.evidence_count(), 1);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_publisher_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            " \t ",
            EvidenceSource::External,
            "Evidence",
            "payload",
            None,
            &[],
            &ts(1),
            "trace-blank-publisher",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail))
                if detail.contains("publisher id")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_title_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::External,
            "\n ",
            "payload",
            None,
            &[],
            &ts(1),
            "trace-blank-title",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("title")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_content_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::External,
            "Evidence",
            " \r\n ",
            None,
            &[],
            &ts(1),
            "trace-blank-content",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("content")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_timestamp_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::External,
            "Evidence",
            "payload",
            None,
            &[],
            " ",
            "trace-blank-timestamp",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("timestamp")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_attestation_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::SecurityAudit,
            "Evidence",
            "payload",
            Some(" \n "),
            &[],
            &ts(1),
            "trace-blank-attestation",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail))
                if detail.contains("attestation")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_blank_tag_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::SecurityAudit,
            "Evidence",
            "payload",
            None,
            &["audit".to_owned(), " ".to_owned()],
            &ts(1),
            "trace-blank-tag",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("tags")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_store_untrimmed_tag_rejected_without_event() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.store_evidence(
            "pub-1",
            EvidenceSource::SecurityAudit,
            "Evidence",
            "payload",
            None,
            &[" audit".to_owned()],
            &ts(1),
            "trace-untrimmed-tag",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("tags")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_retrieve_evidence() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Test Evidence",
                "test payload",
                Some("signed-attestation"),
                &["test".to_owned()],
                &ts(1),
                "t",
            )
            .unwrap();
        let evidence = store.retrieve_evidence(&hash, &ts(2), "t").unwrap();
        assert_eq!(evidence.publisher_id, "pub-1");
        assert_eq!(evidence.content, "test payload");
        assert_eq!(evidence.attestation.as_deref(), Some("signed-attestation"));
    }

    #[test]
    fn test_retrieve_not_found() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.retrieve_evidence("sha256:nonexistent", &ts(1), "t");
        assert!(matches!(result, Err(ComplianceError::NotFound(_))));
    }

    #[test]
    fn test_retrieve_not_found_does_not_emit_events() {
        let mut store = ComplianceEvidenceStore::new();

        let result = store.retrieve_evidence("sha256:missing", &ts(1), "trace-missing");

        assert!(matches!(result, Err(ComplianceError::NotFound(_))));
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_retrieve_tampered_detected() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Tamper Test",
                "payload-original",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();

        let entry = store.artifacts.get_mut(&hash).expect("stored evidence");
        entry.content = "payload-tampered".to_string();

        let result = store.retrieve_evidence(&hash, &ts(2), "t");
        assert!(matches!(result, Err(ComplianceError::TamperDetected(_))));
    }

    #[test]
    fn test_retrieve_tampered_does_not_emit_retrieved_event() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Tamper Test",
                "payload-original",
                None,
                &[],
                &ts(1),
                "trace-store",
            )
            .unwrap();
        store.take_events();

        let entry = store.artifacts.get_mut(&hash).expect("stored evidence");
        entry.content = "payload-tampered".to_string();

        let result = store.retrieve_evidence(&hash, &ts(2), "trace-retrieve");
        let events = store.take_events();

        assert!(matches!(result, Err(ComplianceError::TamperDetected(_))));
        assert!(
            events
                .iter()
                .any(|event| event.event_code == ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL)
        );
        assert!(
            events
                .iter()
                .all(|event| event.event_code != ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED)
        );
    }

    #[test]
    fn test_retrieve_tampered_index_hash_mismatch_detected() {
        let mut store = ComplianceEvidenceStore::new();
        let original_hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Index Alias Test",
                "payload-original",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let alias_hash = ComplianceEvidenceStore::compute_content_hash("payload-alias");
        let evidence = store
            .artifacts
            .remove(&original_hash)
            .expect("stored evidence");
        store.artifacts.insert(alias_hash.clone(), evidence);

        let result = store.retrieve_evidence(&alias_hash, &ts(2), "t");
        assert!(matches!(
            result,
            Err(ComplianceError::TamperDetected(ref hash)) if hash == &alias_hash
        ));
        let events = store.take_events();
        assert_eq!(
            events.last().unwrap().event_code,
            ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL
        );
        assert!(events.last().unwrap().detail.contains("requested hash"));
    }

    #[test]
    fn test_retrieve_tampered_hash_length_mismatch_detected() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Tamper Hash Length Test",
                "payload-original",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();

        let entry = store.artifacts.get_mut(&hash).expect("stored evidence");
        entry.content_hash.pop();

        let result = store.retrieve_evidence(&hash, &ts(2), "t");
        assert!(matches!(result, Err(ComplianceError::TamperDetected(_))));
    }

    #[test]
    fn test_retrieve_legacy_unframed_digest_rejected_as_tamper() {
        let mut store = ComplianceEvidenceStore::new();
        let content = "legacy-payload";
        let legacy_digest = Sha256::digest(
            [
                b"ecosystem_compliance_hash_v1:" as &[u8],
                content.as_bytes(),
            ]
            .concat(),
        );
        let legacy_hash = format!("sha256:{}", hex::encode(legacy_digest));

        store.artifacts.insert(
            legacy_hash.clone(),
            ComplianceEvidence {
                content_hash: legacy_hash.clone(),
                publisher_id: "pub-1".to_owned(),
                source: EvidenceSource::MigrationSingularity,
                title: "Legacy Digest Test".to_owned(),
                content: content.to_owned(),
                submitted_at: ts(1),
                attestation: None,
                tags: vec![],
            },
        );

        let result = store.retrieve_evidence(&legacy_hash, &ts(2), "trace-legacy");

        assert!(matches!(
            result,
            Err(ComplianceError::TamperDetected(ref hash)) if hash == &legacy_hash
        ));
        let events = store.take_events();
        assert_eq!(
            events.last().unwrap().event_code,
            ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL
        );
        assert!(events.last().unwrap().detail.contains("tamper detected"));
    }

    #[test]
    fn test_tamper_evidence_verification_pass() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Evidence",
                "content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let valid = store.verify_tamper_evidence(&hash, &ts(2), "t").unwrap();
        assert!(valid);
    }

    #[test]
    fn test_tamper_evidence_verification_fail_on_hash_length_mismatch() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Evidence",
                "content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let entry = store.artifacts.get_mut(&hash).expect("stored evidence");
        entry.content_hash.pop();

        let valid = store.verify_tamper_evidence(&hash, &ts(2), "t").unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tamper_evidence_verification_fail_on_index_hash_mismatch() {
        let mut store = ComplianceEvidenceStore::new();
        let original_hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Index Alias Test",
                "content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let alias_hash = ComplianceEvidenceStore::compute_content_hash("content-alias");
        let evidence = store
            .artifacts
            .remove(&original_hash)
            .expect("stored evidence");
        store.artifacts.insert(alias_hash.clone(), evidence);

        let valid = store
            .verify_tamper_evidence(&alias_hash, &ts(2), "t")
            .unwrap();
        assert!(!valid);
        let events = store.take_events();
        assert_eq!(
            events.last().unwrap().event_code,
            ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL
        );
        assert!(events.last().unwrap().detail.contains("requested hash"));
    }

    #[test]
    fn test_verify_tamper_not_found() {
        let mut store = ComplianceEvidenceStore::new();
        let result = store.verify_tamper_evidence("sha256:missing", &ts(1), "t");
        assert!(matches!(result, Err(ComplianceError::NotFound(_))));
    }

    #[test]
    fn test_verify_tamper_not_found_does_not_emit_events() {
        let mut store = ComplianceEvidenceStore::new();

        let result = store.verify_tamper_evidence("sha256:missing", &ts(1), "trace-missing");

        assert!(matches!(result, Err(ComplianceError::NotFound(_))));
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn test_verify_tamper_malformed_stored_hash_returns_false() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Evidence",
                "content",
                None,
                &[],
                &ts(1),
                "trace-store",
            )
            .unwrap();
        store.take_events();

        let entry = store.artifacts.get_mut(&hash).expect("stored evidence");
        entry.content_hash = "not-a-sha256-digest".to_string();

        let valid = store
            .verify_tamper_evidence(&hash, &ts(2), "trace-verify")
            .unwrap();
        let events = store.take_events();

        assert!(!valid);
        assert!(
            events
                .iter()
                .any(|event| event.event_code == ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL)
        );
    }

    #[test]
    fn test_search_by_source() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::MigrationSingularity,
                "Migration Ev",
                "m1",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::TrustFabric,
                "Trust Ev",
                "t1",
                None,
                &[],
                &ts(2),
                "t",
            )
            .unwrap();
        let results = store.search_by_source(EvidenceSource::MigrationSingularity);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Migration Ev");
    }

    #[test]
    fn test_search_by_source_returns_empty_for_unmatched_source() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "External Evidence",
                "external-content",
                None,
                &[],
                &ts(1),
                "trace-store",
            )
            .unwrap();

        let results = store.search_by_source(EvidenceSource::SecurityAudit);

        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_publisher() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Ev A",
                "a",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        store
            .store_evidence(
                "pub-2",
                EvidenceSource::External,
                "Ev B",
                "b",
                None,
                &[],
                &ts(2),
                "t",
            )
            .unwrap();
        let results = store.search_by_publisher("pub-1");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_by_publisher_is_exact_not_prefix() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Ev A",
                "a",
                None,
                &[],
                &ts(1),
                "trace-a",
            )
            .unwrap();
        store
            .store_evidence(
                "pub-10",
                EvidenceSource::External,
                "Ev B",
                "b",
                None,
                &[],
                &ts(2),
                "trace-b",
            )
            .unwrap();

        let results = store.search_by_publisher("pub-1");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].publisher_id, "pub-1");
    }

    #[test]
    fn test_search_by_tag() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Tagged",
                "content",
                None,
                &["security".to_owned(), "audit".to_owned()],
                &ts(1),
                "t",
            )
            .unwrap();
        let results = store.search_by_tag("security");
        assert_eq!(results.len(), 1);
        let results2 = store.search_by_tag("nonexistent");
        assert!(results2.is_empty());
    }

    #[test]
    fn test_search_by_tag_is_exact_not_substring() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Tagged",
                "content",
                None,
                &["security".to_owned()],
                &ts(1),
                "trace-store",
            )
            .unwrap();

        let results = store.search_by_tag("sec");

        assert!(results.is_empty());
    }

    #[test]
    fn test_search_by_tag_is_case_sensitive() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Tagged",
                "content",
                None,
                &["security".to_owned()],
                &ts(1),
                "trace-store",
            )
            .unwrap();

        let results = store.search_by_tag("Security");

        assert!(results.is_empty());
    }

    #[test]
    fn test_list_evidence() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "A",
                "a",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        store
            .store_evidence(
                "pub-2",
                EvidenceSource::External,
                "B",
                "b",
                None,
                &[],
                &ts(2),
                "t",
            )
            .unwrap();
        assert_eq!(store.list_evidence().len(), 2);
    }

    #[test]
    fn test_events_emitted_on_store() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Test",
                "content",
                None,
                &[],
                &ts(1),
                "trace-s",
            )
            .unwrap();
        let events = store.take_events();
        assert!(
            events
                .iter()
                .any(|e| e.event_code == ENE_005_COMPLIANCE_EVIDENCE_STORED)
        );
    }

    #[test]
    fn test_events_emitted_on_retrieve() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Test",
                "content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        store.take_events(); // drain store events
        store.retrieve_evidence(&hash, &ts(2), "t").unwrap();
        let events = store.take_events();
        assert!(
            events
                .iter()
                .any(|e| e.event_code == ENE_007_COMPLIANCE_TAMPER_CHECK_PASS)
        );
        assert!(
            events
                .iter()
                .any(|e| e.event_code == ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED)
        );
    }

    #[test]
    fn test_take_events_drains() {
        let mut store = ComplianceEvidenceStore::new();
        store
            .store_evidence(
                "pub-1",
                EvidenceSource::External,
                "Test",
                "content",
                None,
                &[],
                &ts(1),
                "t",
            )
            .unwrap();
        let e1 = store.take_events();
        assert!(!e1.is_empty());
        let e2 = store.take_events();
        assert!(e2.is_empty());
    }

    #[test]
    fn test_default_store() {
        let store = ComplianceEvidenceStore::default();
        assert_eq!(store.evidence_count(), 0);
    }

    #[test]
    fn test_evidence_source_display() {
        assert_eq!(
            EvidenceSource::MigrationSingularity.to_string(),
            "migration_singularity"
        );
        assert_eq!(EvidenceSource::TrustFabric.to_string(), "trust_fabric");
        assert_eq!(
            EvidenceSource::VerifierEconomy.to_string(),
            "verifier_economy"
        );
        assert_eq!(
            EvidenceSource::CompatibilityCore.to_string(),
            "compatibility_core"
        );
        assert_eq!(EvidenceSource::SecurityAudit.to_string(), "security_audit");
        assert_eq!(EvidenceSource::External.to_string(), "external");
    }

    #[test]
    fn test_event_code_constants() {
        assert_eq!(ENE_005_COMPLIANCE_EVIDENCE_STORED, "ENE-005");
        assert_eq!(ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED, "ENE-006");
        assert_eq!(ENE_007_COMPLIANCE_TAMPER_CHECK_PASS, "ENE-007");
        assert_eq!(ENE_008_COMPLIANCE_TAMPER_CHECK_FAIL, "ENE-008");
    }

    #[test]
    fn test_invariant_constants() {
        assert_eq!(INV_ENE_TAMPER, "INV-ENE-TAMPER");
    }

    #[test]
    fn test_error_code_constants() {
        assert_eq!(ERR_ENE_TAMPER, "ERR-ENE-TAMPER");
    }

    #[test]
    fn test_cross_program_migration_singularity_evidence() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "migration-system",
                EvidenceSource::MigrationSingularity,
                "Migration Run Results",
                r#"{"migration_id":"m-001","success":true,"pass_rate":0.98}"#,
                Some("signed-by-migration-system"),
                &["migration".to_owned(), "10.3".to_owned()],
                &ts(1),
                "t",
            )
            .unwrap();
        let evidence = store.retrieve_evidence(&hash, &ts(2), "t").unwrap();
        assert_eq!(evidence.source, EvidenceSource::MigrationSingularity);
        assert!(evidence.content.contains("migration_id"));
    }

    #[test]
    fn test_cross_program_trust_fabric_evidence() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "trust-fabric",
                EvidenceSource::TrustFabric,
                "Trust Artifact Validity Report",
                r#"{"fabric_id":"tf-001","valid_artifacts":42,"total_artifacts":45}"#,
                Some("signed-by-trust-fabric"),
                &["trust".to_owned(), "10.13".to_owned()],
                &ts(1),
                "t",
            )
            .unwrap();
        let evidence = store.retrieve_evidence(&hash, &ts(2), "t").unwrap();
        assert_eq!(evidence.source, EvidenceSource::TrustFabric);
        assert!(evidence.content.contains("fabric_id"));
    }

    #[test]
    fn test_store_with_attestation() {
        let mut store = ComplianceEvidenceStore::new();
        let hash = store
            .store_evidence(
                "pub-1",
                EvidenceSource::SecurityAudit,
                "Audit Report",
                "audit data",
                Some("attestation-signature-abc"),
                &["audit".to_owned()],
                &ts(1),
                "t",
            )
            .unwrap();
        let evidence = store.retrieve_evidence(&hash, &ts(2), "t").unwrap();
        assert_eq!(
            evidence.attestation.as_deref(),
            Some("attestation-signature-abc")
        );
    }

    #[test]
    fn negative_evidence_source_rejects_unknown_variant() {
        let err = serde_json::from_str::<EvidenceSource>(r#""verifier_market""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_compliance_evidence_rejects_missing_content_hash() {
        let value = serde_json::json!({
            "publisher_id": "publisher-1",
            "source": "security_audit",
            "title": "Audit",
            "content": "{}",
            "submitted_at": "2026-01-01T00:00:00Z",
            "attestation": null,
            "tags": ["audit"]
        });

        let err = serde_json::from_value::<ComplianceEvidence>(value).unwrap_err();

        assert!(err.to_string().contains("content_hash"));
    }

    #[test]
    fn negative_compliance_evidence_rejects_object_tags() {
        let value = serde_json::json!({
            "content_hash": "sha256:abc",
            "publisher_id": "publisher-1",
            "source": "security_audit",
            "title": "Audit",
            "content": "{}",
            "submitted_at": "2026-01-01T00:00:00Z",
            "attestation": null,
            "tags": {"audit": true}
        });

        let err = serde_json::from_value::<ComplianceEvidence>(value).unwrap_err();

        let message = err.to_string();
        assert!(message.contains("invalid type") || message.contains("sequence"));
    }

    #[test]
    fn negative_compliance_event_rejects_missing_trace_id() {
        let value = serde_json::json!({
            "event_code": ENE_005_COMPLIANCE_EVIDENCE_STORED,
            "content_hash": "sha256:abc",
            "detail": "stored",
            "timestamp": "2026-01-01T00:00:00Z"
        });

        let err = serde_json::from_value::<ComplianceEvent>(value).unwrap_err();

        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn negative_index_entry_rejects_uppercase_source_variant() {
        let value = serde_json::json!({
            "content_hash": "sha256:abc",
            "publisher_id": "publisher-1",
            "source": "SecurityAudit",
            "title": "Audit",
            "submitted_at": "2026-01-01T00:00:00Z",
            "tags": ["audit"]
        });

        let err = serde_json::from_value::<ComplianceIndexEntry>(value).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn negative_store_rejects_untrimmed_attestation_without_event() {
        let mut store = ComplianceEvidenceStore::new();

        let result = store.store_evidence(
            "publisher-1",
            EvidenceSource::External,
            "External report",
            "{}",
            Some(" signed "),
            &["external".to_owned()],
            &ts(1),
            "trace-attestation",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("attestation")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn negative_store_rejects_untrimmed_publisher_without_event() {
        let mut store = ComplianceEvidenceStore::new();

        let result = store.store_evidence(
            " publisher-1 ",
            EvidenceSource::External,
            "External report",
            "{}",
            None,
            &["external".to_owned()],
            &ts(1),
            "trace-publisher",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("publisher")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn negative_store_rejects_untrimmed_title_without_event() {
        let mut store = ComplianceEvidenceStore::new();

        let result = store.store_evidence(
            "publisher-1",
            EvidenceSource::External,
            " External report ",
            "{}",
            None,
            &["external".to_owned()],
            &ts(1),
            "trace-title",
        );

        assert!(matches!(
            result,
            Err(ComplianceError::InvalidEvidence(ref detail)) if detail.contains("title")
        ));
        assert_eq!(store.evidence_count(), 0);
        assert!(store.take_events().is_empty());
    }

    #[test]
    fn negative_push_bounded_zero_capacity_clears_without_inserting() {
        let mut events = vec![ComplianceEvent {
            event_code: ENE_005_COMPLIANCE_EVIDENCE_STORED.to_owned(),
            content_hash: "sha256:old".to_owned(),
            detail: "old".to_owned(),
            timestamp: ts(1),
            trace_id: "trace-old".to_owned(),
        }];
        let new_event = ComplianceEvent {
            event_code: ENE_006_COMPLIANCE_EVIDENCE_RETRIEVED.to_owned(),
            content_hash: "sha256:new".to_owned(),
            detail: "new".to_owned(),
            timestamp: ts(2),
            trace_id: "trace-new".to_owned(),
        };

        push_bounded(&mut events, new_event, 0);

        assert!(events.is_empty());
    }
}
