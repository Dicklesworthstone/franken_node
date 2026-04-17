//! bd-nbh7: Benchmark/verifier methodology publications (Section 16).
//!
//! Publishes methodology documentation for benchmark design and verifier
//! architecture. Each publication includes structured methodology sections,
//! citation references, reproducibility checklists, and peer-review status
//! tracking.
//!
//! # Capabilities
//!
//! - Methodology publication with structured sections
//! - Citation and reference management
//! - Reproducibility checklist verification
//! - Peer-review status tracking (Draft → Review → Published → Archived)
//! - Publication catalog with search by topic
//! - Content-addressed integrity hashing
//!
//! # Invariants
//!
//! - **INV-BMP-STRUCTURED**: Every publication has required methodology sections.
//! - **INV-BMP-DETERMINISTIC**: Same inputs produce same catalog output.
//! - **INV-BMP-CITABLE**: Every publication has a unique DOI-style identifier.
//! - **INV-BMP-REPRODUCIBLE**: Every publication includes a reproducibility checklist.
//! - **INV-BMP-VERSIONED**: Publication version embedded in every artifact.
//! - **INV-BMP-AUDITABLE**: Every state change produces an audit record.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const BMP_PUBLICATION_CREATED: &str = "BMP-001";
    pub const BMP_SECTION_VALIDATED: &str = "BMP-002";
    pub const BMP_CITATION_ADDED: &str = "BMP-003";
    pub const BMP_CHECKLIST_VERIFIED: &str = "BMP-004";
    pub const BMP_STATUS_CHANGED: &str = "BMP-005";
    pub const BMP_CATALOG_GENERATED: &str = "BMP-006";
    pub const BMP_INTEGRITY_VERIFIED: &str = "BMP-007";
    pub const BMP_VERSION_EMBEDDED: &str = "BMP-008";
    pub const BMP_SEARCH_EXECUTED: &str = "BMP-009";
    pub const BMP_ARCHIVE_TRIGGERED: &str = "BMP-010";
    pub const BMP_ERR_MISSING_SECTION: &str = "BMP-ERR-001";
    pub const BMP_ERR_INVALID_TRANSITION: &str = "BMP-ERR-002";
    pub const BMP_ERR_INVALID_PUBLICATION: &str = "BMP-ERR-003";
    pub const BMP_ERR_INVALID_CITATION: &str = "BMP-ERR-004";
}

pub mod invariants {
    pub const INV_BMP_STRUCTURED: &str = "INV-BMP-STRUCTURED";
    pub const INV_BMP_DETERMINISTIC: &str = "INV-BMP-DETERMINISTIC";
    pub const INV_BMP_CITABLE: &str = "INV-BMP-CITABLE";
    pub const INV_BMP_REPRODUCIBLE: &str = "INV-BMP-REPRODUCIBLE";
    pub const INV_BMP_VERSIONED: &str = "INV-BMP-VERSIONED";
    pub const INV_BMP_AUDITABLE: &str = "INV-BMP-AUDITABLE";
}

pub const PUB_VERSION: &str = "bmp-v1.0";

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
const MAX_CITATIONS: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }

    let overflow = items.len().saturating_add(1).saturating_sub(cap);
    if overflow > 0 {
        items.drain(0..overflow);
    }
    items.push(item);
}

fn compute_publication_hash(pub_entry: &Publication) -> String {
    let hash_input = serde_json::json!({
        "pub_id": &pub_entry.pub_id,
        "title": &pub_entry.title,
        "topic": pub_entry.topic.label(),
        "authors": &pub_entry.authors,
        "status": pub_entry.status.label(),
        "sections": &pub_entry.sections,
        "citations": &pub_entry.citations,
        "reproducibility_checklist": &pub_entry.reproducibility_checklist,
        "pub_version": &pub_entry.pub_version,
        "created_at": &pub_entry.created_at,
        "updated_at": &pub_entry.updated_at,
    })
    .to_string();
    let mut hasher = Sha256::new();
    hasher.update(b"benchmark_methodology_hash_v1:");
    hasher.update(hash_input.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_catalog_hash(
    total_publications: usize,
    by_topic: &BTreeMap<String, usize>,
    by_status: &BTreeMap<String, usize>,
    pub_version: &str,
) -> String {
    let hash_input = serde_json::json!({
        "total": total_publications,
        "by_topic": by_topic,
        "by_status": by_status,
        "pub_version": pub_version,
    })
    .to_string();
    let mut hasher = Sha256::new();
    hasher.update(b"benchmark_methodology_hash_v1:");
    hasher.update(hash_input.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Publication status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PubStatus {
    Draft,
    Review,
    Published,
    Archived,
}

impl PubStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Review => "review",
            Self::Published => "published",
            Self::Archived => "archived",
        }
    }

    /// Valid transitions from this status.
    pub fn valid_transitions(&self) -> &'static [PubStatus] {
        match self {
            Self::Draft => &[Self::Review],
            Self::Review => &[Self::Draft, Self::Published],
            Self::Published => &[Self::Archived],
            Self::Archived => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// Methodology topic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodologyTopic {
    BenchmarkDesign,
    VerifierArchitecture,
    MetricDefinition,
    ReproducibilityProtocol,
    ThreatModeling,
}

impl MethodologyTopic {
    pub fn all() -> &'static [MethodologyTopic] {
        &[
            Self::BenchmarkDesign,
            Self::VerifierArchitecture,
            Self::MetricDefinition,
            Self::ReproducibilityProtocol,
            Self::ThreatModeling,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::BenchmarkDesign => "benchmark_design",
            Self::VerifierArchitecture => "verifier_architecture",
            Self::MetricDefinition => "metric_definition",
            Self::ReproducibilityProtocol => "reproducibility_protocol",
            Self::ThreatModeling => "threat_modeling",
        }
    }
}

// ---------------------------------------------------------------------------
// Required methodology sections
// ---------------------------------------------------------------------------

/// Standard sections every methodology publication must include.
pub const REQUIRED_SECTIONS: &[&str] = &[
    "abstract",
    "introduction",
    "methodology",
    "results",
    "reproducibility",
    "limitations",
];

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A methodology publication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Publication {
    pub pub_id: String,
    pub title: String,
    pub topic: MethodologyTopic,
    pub authors: Vec<String>,
    pub status: PubStatus,
    pub sections: BTreeMap<String, String>,
    pub citations: Vec<Citation>,
    pub reproducibility_checklist: Vec<ChecklistItem>,
    pub content_hash: String,
    pub pub_version: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A citation reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Citation {
    pub cite_id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub year: u16,
    pub url: Option<String>,
}

/// A reproducibility checklist item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub item: String,
    pub verified: bool,
}

/// Publication catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationCatalog {
    pub catalog_id: String,
    pub timestamp: String,
    pub pub_version: String,
    pub total_publications: usize,
    pub by_topic: BTreeMap<String, usize>,
    pub by_status: BTreeMap<String, usize>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BmpAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Benchmark methodology publication engine.
#[derive(Debug, Clone)]
pub struct BenchmarkMethodology {
    pub_version: String,
    publications: BTreeMap<String, Publication>,
    audit_log: Vec<BmpAuditRecord>,
}

impl Default for BenchmarkMethodology {
    fn default() -> Self {
        Self {
            pub_version: PUB_VERSION.to_string(),
            publications: BTreeMap::new(),
            audit_log: Vec::new(),
        }
    }
}

impl BenchmarkMethodology {
    /// Create a new publication.
    pub fn create_publication(
        &mut self,
        mut pub_entry: Publication,
        trace_id: &str,
    ) -> Result<String, String> {
        if pub_entry.pub_id.trim().is_empty() {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({"reason": "empty pub_id"}),
            );
            return Err("publication id must not be empty".to_string());
        }
        if self.publications.contains_key(&pub_entry.pub_id) {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({"pub_id": &pub_entry.pub_id, "reason": "duplicate pub_id"}),
            );
            return Err(format!("duplicate publication: {}", pub_entry.pub_id));
        }
        if pub_entry.title.trim().is_empty() {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({"pub_id": &pub_entry.pub_id, "reason": "empty title"}),
            );
            return Err("publication title must not be empty".to_string());
        }
        if pub_entry.authors.is_empty()
            || pub_entry
                .authors
                .iter()
                .any(|author| author.trim().is_empty())
        {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({"pub_id": &pub_entry.pub_id, "reason": "invalid authors"}),
            );
            return Err("publication authors must not be empty".to_string());
        }

        // Validate required sections
        for sec in REQUIRED_SECTIONS {
            match pub_entry.sections.get(*sec) {
                Some(content) if !content.trim().is_empty() => {}
                _ => {
                    self.log(
                        event_codes::BMP_ERR_MISSING_SECTION,
                        trace_id,
                        serde_json::json!({
                            "pub_id": &pub_entry.pub_id,
                            "missing_section": sec,
                        }),
                    );
                    return Err(format!("Missing required section: {}", sec));
                }
            }
        }

        // Validate reproducibility checklist
        if pub_entry.reproducibility_checklist.is_empty() {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({
                    "pub_id": &pub_entry.pub_id,
                    "reason": "empty reproducibility_checklist",
                }),
            );
            return Err("Reproducibility checklist must not be empty".to_string());
        }
        if pub_entry
            .reproducibility_checklist
            .iter()
            .any(|item| item.item.trim().is_empty())
        {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({
                    "pub_id": &pub_entry.pub_id,
                    "reason": "empty checklist item",
                }),
            );
            return Err("reproducibility checklist items must not be empty".to_string());
        }
        if pub_entry
            .reproducibility_checklist
            .iter()
            .any(|item| !item.verified)
        {
            self.log(
                event_codes::BMP_ERR_INVALID_PUBLICATION,
                trace_id,
                serde_json::json!({
                    "pub_id": &pub_entry.pub_id,
                    "reason": "unverified checklist item",
                }),
            );
            return Err("all reproducibility checklist items must be verified".to_string());
        }

        self.log(
            event_codes::BMP_SECTION_VALIDATED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_entry.pub_id,
                "sections": pub_entry.sections.len(),
            }),
        );

        self.log(
            event_codes::BMP_CHECKLIST_VERIFIED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_entry.pub_id,
                "checklist_items": pub_entry.reproducibility_checklist.len(),
            }),
        );

        pub_entry.pub_version = self.pub_version.clone();
        pub_entry.status = PubStatus::Draft;
        pub_entry.created_at = Utc::now().to_rfc3339();
        pub_entry.updated_at = pub_entry.created_at.clone();
        pub_entry.content_hash = compute_publication_hash(&pub_entry);

        let pub_id = pub_entry.pub_id.clone();

        self.log(
            event_codes::BMP_INTEGRITY_VERIFIED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_id,
                "content_hash": &pub_entry.content_hash,
            }),
        );

        self.log(
            event_codes::BMP_VERSION_EMBEDDED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_id,
                "pub_version": &pub_entry.pub_version,
            }),
        );

        self.publications.insert(pub_id.clone(), pub_entry);

        self.log(
            event_codes::BMP_PUBLICATION_CREATED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_id,
            }),
        );

        Ok(pub_id)
    }

    /// Transition publication status.
    pub fn transition_status(
        &mut self,
        pub_id: &str,
        new_status: PubStatus,
        trace_id: &str,
    ) -> Result<(), String> {
        // Check current status and valid transitions (read-only borrow)
        let current_status = {
            let pub_entry = self
                .publications
                .get(pub_id)
                .ok_or_else(|| format!("Publication {} not found", pub_id))?;
            pub_entry.status
        };

        let valid = current_status.valid_transitions();
        if !valid.contains(&new_status) {
            self.log(
                event_codes::BMP_ERR_INVALID_TRANSITION,
                trace_id,
                serde_json::json!({
                    "pub_id": pub_id,
                    "from": current_status.label(),
                    "to": new_status.label(),
                }),
            );
            return Err(format!(
                "Cannot transition from {} to {}",
                current_status.label(),
                new_status.label()
            ));
        }

        // Now mutate — publication validated via immutable get() above
        let pub_entry = self
            .publications
            .get_mut(pub_id)
            .ok_or_else(|| format!("Publication {pub_id} not found"))?;
        pub_entry.status = new_status;
        pub_entry.updated_at = Utc::now().to_rfc3339();
        pub_entry.content_hash = compute_publication_hash(pub_entry);

        self.log(
            event_codes::BMP_STATUS_CHANGED,
            trace_id,
            serde_json::json!({
                "pub_id": pub_id,
                "new_status": new_status.label(),
            }),
        );

        Ok(())
    }

    /// Add a citation to a publication.
    pub fn add_citation(
        &mut self,
        pub_id: &str,
        citation: Citation,
        trace_id: &str,
    ) -> Result<(), String> {
        if !self.publications.contains_key(pub_id) {
            return Err(format!("Publication {} not found", pub_id));
        }
        if citation.cite_id.trim().is_empty() {
            self.log(
                event_codes::BMP_ERR_INVALID_CITATION,
                trace_id,
                serde_json::json!({"pub_id": pub_id, "reason": "empty cite_id"}),
            );
            return Err("citation id must not be empty".to_string());
        }
        if citation.title.trim().is_empty() {
            self.log(
                event_codes::BMP_ERR_INVALID_CITATION,
                trace_id,
                serde_json::json!({
                    "pub_id": pub_id,
                    "cite_id": &citation.cite_id,
                    "reason": "empty title",
                }),
            );
            return Err("citation title must not be empty".to_string());
        }
        if citation.authors.is_empty()
            || citation
                .authors
                .iter()
                .any(|author| author.trim().is_empty())
        {
            self.log(
                event_codes::BMP_ERR_INVALID_CITATION,
                trace_id,
                serde_json::json!({
                    "pub_id": pub_id,
                    "cite_id": &citation.cite_id,
                    "reason": "invalid authors",
                }),
            );
            return Err("citation authors must not be empty".to_string());
        }
        if self.publications.get(pub_id).is_some_and(|pub_entry| {
            pub_entry
                .citations
                .iter()
                .any(|existing| existing.cite_id == citation.cite_id)
        }) {
            self.log(
                event_codes::BMP_ERR_INVALID_CITATION,
                trace_id,
                serde_json::json!({
                    "pub_id": pub_id,
                    "cite_id": &citation.cite_id,
                    "reason": "duplicate cite_id",
                }),
            );
            return Err(format!("duplicate citation: {}", citation.cite_id));
        }

        let cite_id = citation.cite_id.clone();
        self.log(
            event_codes::BMP_CITATION_ADDED,
            trace_id,
            serde_json::json!({
                "pub_id": pub_id,
                "cite_id": &cite_id,
            }),
        );

        let pub_entry = self
            .publications
            .get_mut(pub_id)
            .ok_or_else(|| format!("Publication {pub_id} not found"))?;
        push_bounded(&mut pub_entry.citations, citation, MAX_CITATIONS);
        pub_entry.updated_at = Utc::now().to_rfc3339();
        pub_entry.content_hash = compute_publication_hash(pub_entry);
        Ok(())
    }

    /// Generate catalog of all publications.
    pub fn generate_catalog(&mut self, trace_id: &str) -> PublicationCatalog {
        let mut by_topic = BTreeMap::new();
        let mut by_status = BTreeMap::new();

        for pub_entry in self.publications.values() {
            let topic_count = by_topic
                .entry(pub_entry.topic.label().to_string())
                .or_insert(0usize);
            *topic_count = topic_count.saturating_add(1);

            let status_count = by_status
                .entry(pub_entry.status.label().to_string())
                .or_insert(0usize);
            *status_count = status_count.saturating_add(1);
        }

        let content_hash = compute_catalog_hash(
            self.publications.len(),
            &by_topic,
            &by_status,
            &self.pub_version,
        );

        self.log(
            event_codes::BMP_CATALOG_GENERATED,
            trace_id,
            serde_json::json!({
                "total": self.publications.len(),
            }),
        );

        PublicationCatalog {
            catalog_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            pub_version: self.pub_version.clone(),
            total_publications: self.publications.len(),
            by_topic,
            by_status,
            content_hash,
        }
    }

    /// Search publications by topic.
    pub fn search_by_topic(&self, topic: MethodologyTopic) -> Vec<&Publication> {
        self.publications
            .values()
            .filter(|p| p.topic == topic)
            .collect()
    }

    pub fn publications(&self) -> &BTreeMap<String, Publication> {
        &self.publications
    }

    pub fn audit_log(&self) -> &[BmpAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            BmpAuditRecord {
                record_id: Uuid::now_v7().to_string(),
                event_code: event_code.to_string(),
                timestamp: Utc::now().to_rfc3339(),
                trace_id: trace_id.to_string(),
                details,
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn sample_pub(id: &str, topic: MethodologyTopic) -> Publication {
        let mut sections = BTreeMap::new();
        for sec in REQUIRED_SECTIONS {
            sections.insert(sec.to_string(), format!("Content for {}", sec));
        }
        Publication {
            pub_id: id.to_string(),
            title: format!("Test publication: {}", id),
            topic,
            authors: vec!["Author A".to_string()],
            status: PubStatus::Draft,
            sections,
            citations: vec![],
            reproducibility_checklist: vec![
                ChecklistItem {
                    item: "Data available".to_string(),
                    verified: true,
                },
                ChecklistItem {
                    item: "Code available".to_string(),
                    verified: true,
                },
            ],
            content_hash: String::new(),
            pub_version: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn sample_citation(id: &str) -> Citation {
        Citation {
            cite_id: id.to_string(),
            title: "Test Paper".to_string(),
            authors: vec!["Author B".to_string()],
            year: 2025,
            url: Some("https://example.com".to_string()),
        }
    }

    #[test]
    fn push_bounded_zero_cap_drops_item_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_preexisting_overflow_keeps_newest_item() {
        let mut items = vec![1, 2, 3, 4];

        push_bounded(&mut items, 5, 3);

        assert_eq!(items, vec![3, 4, 5]);
    }

    // === Topics ===

    #[test]
    fn five_topics() {
        assert_eq!(MethodologyTopic::all().len(), 5);
    }

    #[test]
    fn topic_labels_unique() {
        let labels: Vec<&str> = MethodologyTopic::all().iter().map(|t| t.label()).collect();
        let mut dedup = labels.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(labels.len(), dedup.len());
    }

    // === Required sections ===

    #[test]
    fn six_required_sections() {
        assert_eq!(REQUIRED_SECTIONS.len(), 6);
    }

    // === Publication creation ===

    #[test]
    fn create_valid_publication() {
        let mut engine = BenchmarkMethodology::default();
        let p = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        assert!(engine.create_publication(p, &trace()).is_ok());
    }

    #[test]
    fn create_sets_content_hash() {
        let mut engine = BenchmarkMethodology::default();
        let p = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        engine.create_publication(p, &trace()).unwrap();
        let stored = engine.publications().get("pub-1").unwrap();
        assert_eq!(stored.content_hash.len(), 64);
    }

    #[test]
    fn publication_hash_covers_authors() {
        let mut p1 = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        p1.pub_version = PUB_VERSION.to_string();
        p1.created_at = "2026-01-01T00:00:00Z".to_string();
        p1.updated_at = p1.created_at.clone();

        let mut p2 = p1.clone();
        p2.authors.push("Author B".to_string());

        assert_ne!(compute_publication_hash(&p1), compute_publication_hash(&p2));
    }

    #[test]
    fn publication_hash_covers_citations() {
        let mut p1 = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        p1.pub_version = PUB_VERSION.to_string();
        p1.created_at = "2026-01-01T00:00:00Z".to_string();
        p1.updated_at = p1.created_at.clone();

        let mut p2 = p1.clone();
        p2.citations.push(Citation {
            cite_id: "cite-1".to_string(),
            title: "Test Paper".to_string(),
            authors: vec!["Author B".to_string()],
            year: 2025,
            url: Some("https://example.com".to_string()),
        });

        assert_ne!(compute_publication_hash(&p1), compute_publication_hash(&p2));
    }

    #[test]
    fn publication_hash_covers_reproducibility_checklist() {
        let mut p1 = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        p1.pub_version = PUB_VERSION.to_string();
        p1.created_at = "2026-01-01T00:00:00Z".to_string();
        p1.updated_at = p1.created_at.clone();

        let mut p2 = p1.clone();
        p2.reproducibility_checklist[0].verified = false;

        assert_ne!(compute_publication_hash(&p1), compute_publication_hash(&p2));
    }

    #[test]
    fn create_sets_version() {
        let mut engine = BenchmarkMethodology::default();
        let p = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        engine.create_publication(p, &trace()).unwrap();
        let stored = engine.publications().get("pub-1").unwrap();
        assert_eq!(stored.pub_version, PUB_VERSION);
    }

    #[test]
    fn create_missing_section_fails() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        p.sections.remove("methodology");
        assert!(engine.create_publication(p, &trace()).is_err());
    }

    #[test]
    fn create_empty_checklist_fails() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-1", MethodologyTopic::BenchmarkDesign);
        p.reproducibility_checklist.clear();
        assert!(engine.create_publication(p, &trace()).is_err());
    }

    #[test]
    fn create_empty_pub_id_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let err = engine
            .create_publication(
                sample_pub("", MethodologyTopic::BenchmarkDesign),
                "trace-empty-id",
            )
            .unwrap_err();

        assert!(err.contains("publication id"));
        assert!(engine.publications().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::BMP_ERR_INVALID_PUBLICATION
        );
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty pub_id")
        );
    }

    #[test]
    fn create_whitespace_pub_id_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let err = engine
            .create_publication(
                sample_pub(" \t ", MethodologyTopic::BenchmarkDesign),
                "trace-whitespace-id",
            )
            .unwrap_err();

        assert!(err.contains("publication id"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty pub_id")
        );
    }

    #[test]
    fn create_duplicate_pub_id_rejected_without_overwrite() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let original_hash = engine.publications()["pub-1"].content_hash.clone();
        let mut replacement = sample_pub("pub-1", MethodologyTopic::ThreatModeling);
        replacement.title = "Replacement".to_string();
        replacement.authors = vec!["Replacement Author".to_string()];
        let err = engine
            .create_publication(replacement, "trace-duplicate")
            .unwrap_err();

        assert!(err.contains("duplicate"));
        assert_eq!(engine.publications().len(), 1);
        assert_eq!(
            engine.publications()["pub-1"].topic,
            MethodologyTopic::BenchmarkDesign
        );
        assert!(crate::security::constant_time::ct_eq_bytes(
            engine.publications()["pub-1"].content_hash.as_bytes(),
            original_hash.as_bytes()
        ));
    }

    #[test]
    fn create_empty_title_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-empty-title", MethodologyTopic::BenchmarkDesign);
        p.title.clear();
        let err = engine
            .create_publication(p, "trace-empty-title")
            .unwrap_err();

        assert!(err.contains("title"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty title")
        );
    }

    #[test]
    fn create_whitespace_title_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-whitespace-title", MethodologyTopic::BenchmarkDesign);
        p.title = " \n\t ".to_string();
        let err = engine
            .create_publication(p, "trace-whitespace-title")
            .unwrap_err();

        assert!(err.contains("title"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty title")
        );
    }

    #[test]
    fn create_empty_author_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-empty-author", MethodologyTopic::BenchmarkDesign);
        p.authors = vec![String::new()];
        let err = engine
            .create_publication(p, "trace-empty-author")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("invalid authors")
        );
    }

    #[test]
    fn create_whitespace_author_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-whitespace-author", MethodologyTopic::BenchmarkDesign);
        p.authors = vec![" \t ".to_string()];
        let err = engine
            .create_publication(p, "trace-whitespace-author")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("invalid authors")
        );
    }

    #[test]
    fn create_empty_authors_vec_rejected_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-no-authors", MethodologyTopic::BenchmarkDesign);
        p.authors.clear();
        let err = engine
            .create_publication(p, "trace-no-authors")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications().is_empty());
        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("invalid authors")
        );
    }

    #[test]
    fn create_empty_required_section_content_fails_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-empty-section", MethodologyTopic::BenchmarkDesign);
        p.sections.insert("methodology".to_string(), String::new());
        let err = engine
            .create_publication(p, "trace-empty-section")
            .unwrap_err();

        assert!(err.contains("methodology"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::BMP_ERR_MISSING_SECTION
        );
        assert_eq!(
            engine.audit_log()[0].details["missing_section"].as_str(),
            Some("methodology")
        );
    }

    #[test]
    fn create_whitespace_required_section_content_fails_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-whitespace-section", MethodologyTopic::BenchmarkDesign);
        p.sections
            .insert("methodology".to_string(), " \n\t ".to_string());
        let err = engine
            .create_publication(p, "trace-whitespace-section")
            .unwrap_err();

        assert!(err.contains("methodology"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::BMP_ERR_MISSING_SECTION
        );
        assert_eq!(
            engine.audit_log()[0].details["missing_section"].as_str(),
            Some("methodology")
        );
    }

    #[test]
    fn create_unverified_checklist_item_fails_without_success_audit() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub("pub-unverified", MethodologyTopic::BenchmarkDesign);
        p.reproducibility_checklist[0].verified = false;
        let err = engine
            .create_publication(p, "trace-unverified")
            .unwrap_err();

        assert!(err.contains("verified"));
        assert!(engine.publications().is_empty());
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_PUBLICATION
            && record.details["reason"].as_str() == Some("unverified checklist item")));
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::BMP_PUBLICATION_CREATED)
        );
    }

    #[test]
    fn create_empty_checklist_item_fails_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub(
            "pub-empty-checklist-item",
            MethodologyTopic::BenchmarkDesign,
        );
        p.reproducibility_checklist[0].item.clear();
        let err = engine
            .create_publication(p, "trace-empty-checklist-item")
            .unwrap_err();

        assert!(err.contains("checklist"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty checklist item")
        );
    }

    #[test]
    fn create_whitespace_checklist_item_fails_without_insert() {
        let mut engine = BenchmarkMethodology::default();
        let mut p = sample_pub(
            "pub-whitespace-checklist-item",
            MethodologyTopic::BenchmarkDesign,
        );
        p.reproducibility_checklist[0].item = " \n\t ".to_string();
        let err = engine
            .create_publication(p, "trace-whitespace-checklist-item")
            .unwrap_err();

        assert!(err.contains("checklist"));
        assert!(engine.publications().is_empty());
        assert_eq!(
            engine.audit_log()[0].details["reason"].as_str(),
            Some("empty checklist item")
        );
    }

    // === Status transitions ===

    #[test]
    fn draft_to_review() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .transition_status("pub-1", PubStatus::Review, &trace())
                .is_ok()
        );
    }

    #[test]
    fn review_to_published() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .transition_status("pub-1", PubStatus::Review, &trace())
            .unwrap();
        assert!(
            engine
                .transition_status("pub-1", PubStatus::Published, &trace())
                .is_ok()
        );
    }

    #[test]
    fn draft_to_published_fails() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        assert!(
            engine
                .transition_status("pub-1", PubStatus::Published, &trace())
                .is_err()
        );
    }

    #[test]
    fn archived_cannot_transition() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .transition_status("pub-1", PubStatus::Review, &trace())
            .unwrap();
        engine
            .transition_status("pub-1", PubStatus::Published, &trace())
            .unwrap();
        engine
            .transition_status("pub-1", PubStatus::Archived, &trace())
            .unwrap();
        assert!(
            engine
                .transition_status("pub-1", PubStatus::Draft, &trace())
                .is_err()
        );
    }

    #[test]
    fn transition_status_refreshes_content_hash() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let before = engine
            .publications()
            .get("pub-1")
            .unwrap()
            .content_hash
            .clone();

        engine
            .transition_status("pub-1", PubStatus::Review, &trace())
            .unwrap();

        let stored = engine.publications().get("pub-1").unwrap();
        assert_eq!(stored.status, PubStatus::Review);
        assert_ne!(before, stored.content_hash);
    }

    #[test]
    fn transition_missing_publication_does_not_audit() {
        let mut engine = BenchmarkMethodology::default();

        let err = engine
            .transition_status("missing-pub", PubStatus::Review, "trace-missing-transition")
            .unwrap_err();

        assert!(err.contains("not found"));
        assert!(engine.publications().is_empty());
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn review_to_review_rejected_without_status_or_hash_change() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-review-loop", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .transition_status("pub-review-loop", PubStatus::Review, &trace())
            .unwrap();
        let before = engine.publications()["pub-review-loop"]
            .content_hash
            .clone();

        let err = engine
            .transition_status("pub-review-loop", PubStatus::Review, "trace-review-loop")
            .unwrap_err();

        assert!(err.contains("Cannot transition"));
        let stored = &engine.publications()["pub-review-loop"];
        assert_eq!(stored.status, PubStatus::Review);
        assert!(crate::security::constant_time::ct_eq_bytes(
            stored.content_hash.as_bytes(),
            before.as_bytes()
        ));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_TRANSITION
            && record.details["from"].as_str() == Some("review")
            && record.details["to"].as_str() == Some("review")));
    }

    #[test]
    fn published_to_draft_rejected_without_downgrade() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-no-downgrade", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .transition_status("pub-no-downgrade", PubStatus::Review, &trace())
            .unwrap();
        engine
            .transition_status("pub-no-downgrade", PubStatus::Published, &trace())
            .unwrap();
        let before = engine.publications()["pub-no-downgrade"]
            .content_hash
            .clone();

        let err = engine
            .transition_status("pub-no-downgrade", PubStatus::Draft, "trace-no-downgrade")
            .unwrap_err();

        assert!(err.contains("Cannot transition"));
        let stored = &engine.publications()["pub-no-downgrade"];
        assert_eq!(stored.status, PubStatus::Published);
        assert!(crate::security::constant_time::ct_eq_bytes(
            stored.content_hash.as_bytes(),
            before.as_bytes()
        ));
    }

    // === Citations ===

    #[test]
    fn add_citation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let cite = Citation {
            cite_id: "cite-1".to_string(),
            title: "Test Paper".to_string(),
            authors: vec!["Author B".to_string()],
            year: 2025,
            url: Some("https://example.com".to_string()),
        };
        assert!(engine.add_citation("pub-1", cite, &trace()).is_ok());
        assert_eq!(
            engine.publications().get("pub-1").unwrap().citations.len(),
            1
        );
    }

    #[test]
    fn add_citation_refreshes_content_hash() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let before = engine
            .publications()
            .get("pub-1")
            .unwrap()
            .content_hash
            .clone();

        engine
            .add_citation(
                "pub-1",
                Citation {
                    cite_id: "cite-1".to_string(),
                    title: "Test Paper".to_string(),
                    authors: vec!["Author B".to_string()],
                    year: 2025,
                    url: Some("https://example.com".to_string()),
                },
                &trace(),
            )
            .unwrap();

        let stored = engine.publications().get("pub-1").unwrap();
        assert_eq!(stored.citations.len(), 1);
        assert_ne!(before, stored.content_hash);
    }

    #[test]
    fn add_citation_missing_publication_does_not_audit() {
        let mut engine = BenchmarkMethodology::default();
        let err = engine
            .add_citation("missing", sample_citation("cite-1"), "trace-missing-pub")
            .unwrap_err();

        assert!(err.contains("not found"));
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn add_citation_missing_publication_takes_precedence_over_bad_citation() {
        let mut engine = BenchmarkMethodology::default();
        let mut bad_citation = sample_citation("");
        bad_citation.title.clear();
        bad_citation.authors.clear();

        let err = engine
            .add_citation("missing", bad_citation, "trace-missing-bad-cite")
            .unwrap_err();

        assert!(err.contains("not found"));
        assert!(engine.publications().is_empty());
        assert!(engine.audit_log().is_empty());
    }

    #[test]
    fn add_empty_citation_id_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let before_hash = engine.publications()["pub-1"].content_hash.clone();
        let err = engine
            .add_citation("pub-1", sample_citation(""), "trace-empty-cite")
            .unwrap_err();

        assert!(err.contains("citation id"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(crate::security::constant_time::ct_eq_bytes(
            engine.publications()["pub-1"].content_hash.as_bytes(),
            before_hash.as_bytes()
        ));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("empty cite_id")));
    }

    #[test]
    fn add_whitespace_citation_id_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let before_hash = engine.publications()["pub-1"].content_hash.clone();
        let err = engine
            .add_citation("pub-1", sample_citation(" \t "), "trace-blank-cite")
            .unwrap_err();

        assert!(err.contains("citation id"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(crate::security::constant_time::ct_eq_bytes(
            engine.publications()["pub-1"].content_hash.as_bytes(),
            before_hash.as_bytes()
        ));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("empty cite_id")));
    }

    #[test]
    fn add_empty_citation_title_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let mut citation = sample_citation("cite-empty-title");
        citation.title.clear();
        let err = engine
            .add_citation("pub-1", citation, "trace-empty-cite-title")
            .unwrap_err();

        assert!(err.contains("title"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("empty title")));
    }

    #[test]
    fn add_whitespace_citation_title_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let mut citation = sample_citation("cite-whitespace-title");
        citation.title = " \n\t ".to_string();
        let err = engine
            .add_citation("pub-1", citation, "trace-whitespace-cite-title")
            .unwrap_err();

        assert!(err.contains("title"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("empty title")));
    }

    #[test]
    fn add_empty_citation_author_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let mut citation = sample_citation("cite-empty-author");
        citation.authors = vec![String::new()];
        let err = engine
            .add_citation("pub-1", citation, "trace-empty-cite-author")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("invalid authors")));
    }

    #[test]
    fn add_whitespace_citation_author_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let mut citation = sample_citation("cite-whitespace-author");
        citation.authors = vec![" \t ".to_string()];
        let err = engine
            .add_citation("pub-1", citation, "trace-whitespace-cite-author")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("invalid authors")));
    }

    #[test]
    fn add_empty_citation_authors_vec_rejected_without_mutation() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let before_hash = engine.publications()["pub-1"].content_hash.clone();
        let mut citation = sample_citation("cite-no-authors");
        citation.authors.clear();
        let err = engine
            .add_citation("pub-1", citation, "trace-cite-no-authors")
            .unwrap_err();

        assert!(err.contains("authors"));
        assert!(engine.publications()["pub-1"].citations.is_empty());
        assert!(crate::security::constant_time::ct_eq_bytes(
            engine.publications()["pub-1"].content_hash.as_bytes(),
            before_hash.as_bytes()
        ));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("invalid authors")));
    }

    #[test]
    fn add_duplicate_citation_id_rejected_without_second_insert() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .add_citation("pub-1", sample_citation("cite-1"), &trace())
            .unwrap();
        let before_hash = engine.publications()["pub-1"].content_hash.clone();
        let err = engine
            .add_citation("pub-1", sample_citation("cite-1"), "trace-dupe-cite")
            .unwrap_err();

        assert!(err.contains("duplicate"));
        assert_eq!(engine.publications()["pub-1"].citations.len(), 1);
        assert!(crate::security::constant_time::ct_eq_bytes(
            engine.publications()["pub-1"].content_hash.as_bytes(),
            before_hash.as_bytes()
        ));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BMP_ERR_INVALID_CITATION
            && record.details["reason"].as_str() == Some("duplicate cite_id")));
    }

    // === Catalog ===

    #[test]
    fn catalog_empty() {
        let mut engine = BenchmarkMethodology::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_publications, 0);
    }

    #[test]
    fn catalog_counts_by_topic() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .create_publication(
                sample_pub("pub-2", MethodologyTopic::VerifierArchitecture),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.total_publications, 2);
        assert!(catalog.by_topic.contains_key("benchmark_design"));
    }

    #[test]
    fn catalog_has_content_hash() {
        let mut engine = BenchmarkMethodology::default();
        let catalog = engine.generate_catalog(&trace());
        assert_eq!(catalog.content_hash.len(), 64);
    }

    #[test]
    fn catalog_is_deterministic() {
        let mut e1 = BenchmarkMethodology::default();
        let mut e2 = BenchmarkMethodology::default();
        let c1 = e1.generate_catalog("trace-det");
        let c2 = e2.generate_catalog("trace-det");
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    // === Search ===

    #[test]
    fn search_by_topic() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        engine
            .create_publication(
                sample_pub("pub-2", MethodologyTopic::VerifierArchitecture),
                &trace(),
            )
            .unwrap();
        let results = engine.search_by_topic(MethodologyTopic::BenchmarkDesign);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_topic_without_matches_returns_empty_and_does_not_audit() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::VerifierArchitecture),
                &trace(),
            )
            .unwrap();
        let before_audit_len = engine.audit_log().len();

        let results = engine.search_by_topic(MethodologyTopic::ThreatModeling);

        assert!(results.is_empty());
        assert_eq!(engine.audit_log().len(), before_audit_len);
    }

    // === Status tracking ===

    #[test]
    fn four_statuses() {
        let statuses = [
            PubStatus::Draft,
            PubStatus::Review,
            PubStatus::Published,
            PubStatus::Archived,
        ];
        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn catalog_tracks_by_status() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let catalog = engine.generate_catalog(&trace());
        assert!(catalog.by_status.contains_key("draft"));
    }

    #[test]
    fn catalog_hash_covers_by_status() {
        let mut by_topic = BTreeMap::new();
        by_topic.insert("benchmark_design".to_string(), 1usize);

        let mut draft_status = BTreeMap::new();
        draft_status.insert("draft".to_string(), 1usize);

        let mut review_status = BTreeMap::new();
        review_status.insert("review".to_string(), 1usize);

        let draft_hash = compute_catalog_hash(1, &by_topic, &draft_status, PUB_VERSION);
        let review_hash = compute_catalog_hash(1, &by_topic, &review_status, PUB_VERSION);

        assert_ne!(draft_hash, review_hash);
    }

    // === Audit log ===

    #[test]
    fn audit_log_populated() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        assert_eq!(engine.audit_log().len(), 5);
    }

    #[test]
    fn export_jsonl() {
        let mut engine = BenchmarkMethodology::default();
        engine
            .create_publication(
                sample_pub("pub-1", MethodologyTopic::BenchmarkDesign),
                &trace(),
            )
            .unwrap();
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let first: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(first["event_code"].is_string());
    }

    #[test]
    fn export_empty_audit_log_is_empty_string() {
        let engine = BenchmarkMethodology::default();

        let jsonl = engine.export_audit_log_jsonl().unwrap();

        assert!(jsonl.is_empty());
    }
}
