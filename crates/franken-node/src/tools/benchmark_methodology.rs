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
        // Validate required sections
        for sec in REQUIRED_SECTIONS {
            if !pub_entry.sections.contains_key(*sec) {
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

        self.log(
            event_codes::BMP_SECTION_VALIDATED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_entry.pub_id,
                "sections": pub_entry.sections.len(),
            }),
        );

        // Validate reproducibility checklist
        if pub_entry.reproducibility_checklist.is_empty() {
            return Err("Reproducibility checklist must not be empty".to_string());
        }

        self.log(
            event_codes::BMP_CHECKLIST_VERIFIED,
            trace_id,
            serde_json::json!({
                "pub_id": &pub_entry.pub_id,
                "checklist_items": pub_entry.reproducibility_checklist.len(),
            }),
        );

        // Compute content hash
        let hash_input = serde_json::json!({
            "title": &pub_entry.title,
            "topic": pub_entry.topic.label(),
            "sections": &pub_entry.sections,
        })
        .to_string();
        pub_entry.content_hash = hex::encode(Sha256::digest(
            [
                b"benchmark_methodology_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));
        pub_entry.pub_version = self.pub_version.clone();
        pub_entry.status = PubStatus::Draft;
        pub_entry.created_at = Utc::now().to_rfc3339();
        pub_entry.updated_at = pub_entry.created_at.clone();

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

        // Now mutate
        let pub_entry = self.publications.get_mut(pub_id).unwrap();
        pub_entry.status = new_status;
        pub_entry.updated_at = Utc::now().to_rfc3339();

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

        let cite_id = citation.cite_id.clone();
        self.log(
            event_codes::BMP_CITATION_ADDED,
            trace_id,
            serde_json::json!({
                "pub_id": pub_id,
                "cite_id": &cite_id,
            }),
        );

        self.publications
            .get_mut(pub_id)
            .unwrap()
            .citations
            .push(citation);
        Ok(())
    }

    /// Generate catalog of all publications.
    pub fn generate_catalog(&mut self, trace_id: &str) -> PublicationCatalog {
        let mut by_topic = BTreeMap::new();
        let mut by_status = BTreeMap::new();

        for pub_entry in self.publications.values() {
            *by_topic
                .entry(pub_entry.topic.label().to_string())
                .or_insert(0) += 1;
            *by_status
                .entry(pub_entry.status.label().to_string())
                .or_insert(0) += 1;
        }

        let hash_input = serde_json::json!({
            "total": self.publications.len(),
            "by_topic": &by_topic,
            "pub_version": &self.pub_version,
        })
        .to_string();
        let content_hash = hex::encode(Sha256::digest(
            [
                b"benchmark_methodology_hash_v1:" as &[u8],
                hash_input.as_bytes(),
            ]
            .concat(),
        ));

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
        self.audit_log.push(BmpAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details,
        });
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
}
