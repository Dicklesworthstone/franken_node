//! Read-optimized evidence index primitives for swarm coordination.
//!
//! The index is intentionally metadata-only: callers provide bounded evidence
//! records from approved repo surfaces, and this module rejects raw logs,
//! session history, Agent Mail internals, and database/private state paths.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use thiserror::Error;

pub const EVIDENCE_INDEX_SCHEMA_VERSION: &str = "franken-node/evidence-index/v1";
pub const EVIDENCE_INDEX_RECORD_SCHEMA_VERSION: &str = "franken-node/evidence-index/record/v1";
pub const EVIDENCE_INDEX_REPORT_SCHEMA_VERSION: &str = "franken-node/evidence-index/report/v1";
pub const DEFAULT_MAX_EVIDENCE_RECORDS: usize = 50_000;
pub const DEFAULT_MAX_QUERY_RESULTS: usize = 128;
pub const DEFAULT_MAX_FIELD_BYTES: usize = 4096;
pub const DEFAULT_MAX_PATH_BYTES: usize = 4096;
pub const DEFAULT_MAX_TAGS_PER_RECORD: usize = 64;
pub const DEFAULT_MAX_TERMS_PER_RECORD: usize = 256;

pub mod error_codes {
    pub const ERR_EVIDENCE_INDEX_INVALID_POLICY: &str = "ERR_EVIDENCE_INDEX_INVALID_POLICY";
    pub const ERR_EVIDENCE_INDEX_INVALID_RECORD: &str = "ERR_EVIDENCE_INDEX_INVALID_RECORD";
    pub const ERR_EVIDENCE_INDEX_JSON: &str = "ERR_EVIDENCE_INDEX_JSON";
}

pub mod reason_codes {
    pub const SOURCE_ROOT_NOT_ALLOWED: &str = "EVIDENCE_INDEX_SOURCE_ROOT_NOT_ALLOWED";
    pub const PROTECTED_SOURCE_REJECTED: &str = "EVIDENCE_INDEX_PROTECTED_SOURCE_REJECTED";
    pub const INVALID_REPO_PATH: &str = "EVIDENCE_INDEX_INVALID_REPO_PATH";
    pub const FIELD_TOO_LARGE: &str = "EVIDENCE_INDEX_FIELD_TOO_LARGE";
    pub const REQUIRED_FIELD_EMPTY: &str = "EVIDENCE_INDEX_REQUIRED_FIELD_EMPTY";
    pub const NEGATIVE_MTIME: &str = "EVIDENCE_INDEX_NEGATIVE_MTIME";
    pub const SOURCE_STALE: &str = "EVIDENCE_INDEX_SOURCE_STALE";
    pub const TAGS_TRUNCATED: &str = "EVIDENCE_INDEX_TAGS_TRUNCATED";
    pub const TERMS_TRUNCATED: &str = "EVIDENCE_INDEX_TERMS_TRUNCATED";
    pub const RECORD_CAP_REACHED: &str = "EVIDENCE_INDEX_RECORD_CAP_REACHED";
    pub const DUPLICATE_RECORD: &str = "EVIDENCE_INDEX_DUPLICATE_RECORD";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceKind {
    BeadsIssue,
    AgentMailSummary,
    RchProofRecord,
    ValidationReceipt,
    DocsSpec,
    ArtifactManifest,
    SourceFile,
    GitCommitRef,
}

impl EvidenceSourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeadsIssue => "beads_issue",
            Self::AgentMailSummary => "agent_mail_summary",
            Self::RchProofRecord => "rch_proof_record",
            Self::ValidationReceipt => "validation_receipt",
            Self::DocsSpec => "docs_spec",
            Self::ArtifactManifest => "artifact_manifest",
            Self::SourceFile => "source_file",
            Self::GitCommitRef => "git_commit_ref",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSafetyClass {
    PublicMetadata,
    RepoContract,
    ProofReceipt,
    SourceReference,
    CoordinationSummary,
}

impl EvidenceSafetyClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicMetadata => "public_metadata",
            Self::RepoContract => "repo_contract",
            Self::ProofReceipt => "proof_receipt",
            Self::SourceReference => "source_reference",
            Self::CoordinationSummary => "coordination_summary",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIndexPolicy {
    pub policy_id: String,
    pub max_records: usize,
    pub max_query_results: usize,
    pub max_field_bytes: usize,
    pub max_path_bytes: usize,
    pub max_tags_per_record: usize,
    pub max_terms_per_record: usize,
    pub allowed_source_roots: Vec<String>,
}

impl Default for EvidenceIndexPolicy {
    fn default() -> Self {
        Self {
            policy_id: "franken-node/evidence-index/default-policy/v1".to_string(),
            max_records: DEFAULT_MAX_EVIDENCE_RECORDS,
            max_query_results: DEFAULT_MAX_QUERY_RESULTS,
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
            max_tags_per_record: DEFAULT_MAX_TAGS_PER_RECORD,
            max_terms_per_record: DEFAULT_MAX_TERMS_PER_RECORD,
            allowed_source_roots: vec![
                ".beads/issues.jsonl".to_string(),
                ".github/workflows".to_string(),
                "AGENTS.md".to_string(),
                "Cargo.lock".to_string(),
                "Cargo.toml".to_string(),
                "README.md".to_string(),
                "artifacts".to_string(),
                "crates".to_string(),
                "docs".to_string(),
                "packaging".to_string(),
                "scripts".to_string(),
                "sdk".to_string(),
                "tests".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub schema_version: String,
    pub record_id: String,
    pub source_kind: EvidenceSourceKind,
    pub safety_class: EvidenceSafetyClass,
    pub source_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mtime_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_mtime_seconds: Option<i64>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

impl EvidenceRecord {
    #[must_use]
    pub fn new(
        record_id: impl Into<String>,
        source_kind: EvidenceSourceKind,
        safety_class: EvidenceSafetyClass,
        source_path: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: EVIDENCE_INDEX_RECORD_SCHEMA_VERSION.to_string(),
            record_id: record_id.into(),
            source_kind,
            safety_class,
            source_path: source_path.into(),
            source_mtime_seconds: None,
            observed_mtime_seconds: None,
            title: title.into(),
            summary: None,
            tags: Vec::new(),
            bead_id: None,
            command_shape: None,
            proof_artifact: None,
            error_code: None,
            agent_name: None,
            git_commit: None,
        }
    }

    #[must_use]
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    #[must_use]
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    #[must_use]
    pub fn with_command_shape(mut self, command_shape: impl Into<String>) -> Self {
        self.command_shape = Some(command_shape.into());
        self
    }

    #[must_use]
    pub fn with_proof_artifact(mut self, proof_artifact: impl Into<String>) -> Self {
        self.proof_artifact = Some(proof_artifact.into());
        self
    }

    #[must_use]
    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    #[must_use]
    pub fn with_agent_name(mut self, agent_name: impl Into<String>) -> Self {
        self.agent_name = Some(agent_name.into());
        self
    }

    #[must_use]
    pub fn with_git_commit(mut self, git_commit: impl Into<String>) -> Self {
        self.git_commit = Some(git_commit.into());
        self
    }

    #[must_use]
    pub fn with_source_mtime_seconds(mut self, source_mtime_seconds: i64) -> Self {
        self.source_mtime_seconds = Some(source_mtime_seconds);
        self
    }

    #[must_use]
    pub fn with_observed_mtime_seconds(mut self, observed_mtime_seconds: i64) -> Self {
        self.observed_mtime_seconds = Some(observed_mtime_seconds);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIndexRejectedSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub source_path: String,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIndexStaleSource {
    pub record_id: String,
    pub source_path: String,
    pub source_mtime_seconds: i64,
    pub observed_mtime_seconds: i64,
    pub reason_code: String,
    pub rebuild_guidance: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIndexBuildReport {
    pub schema_version: String,
    pub accepted_records: usize,
    pub duplicate_records: usize,
    pub capped_records: usize,
    pub tag_truncated_records: usize,
    pub term_truncated_records: usize,
    pub rejected_sources: Vec<EvidenceIndexRejectedSource>,
    pub stale_sources: Vec<EvidenceIndexStaleSource>,
}

impl Default for EvidenceIndexBuildReport {
    fn default() -> Self {
        Self {
            schema_version: EVIDENCE_INDEX_REPORT_SCHEMA_VERSION.to_string(),
            accepted_records: 0,
            duplicate_records: 0,
            capped_records: 0,
            tag_truncated_records: 0,
            term_truncated_records: 0,
            rejected_sources: Vec::new(),
            stale_sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceIndexSnapshot {
    pub schema_version: String,
    pub policy: EvidenceIndexPolicy,
    pub report: EvidenceIndexBuildReport,
    pub records: Vec<EvidenceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvidenceQuery {
    pub terms: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_artifact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl EvidenceQuery {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_term(mut self, term: impl Into<String>) -> Self {
        self.terms.push(term.into());
        self
    }

    #[must_use]
    pub fn with_bead_id(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    #[must_use]
    pub fn with_source_path(mut self, source_path: impl Into<String>) -> Self {
        self.source_path = Some(source_path.into());
        self
    }

    #[must_use]
    pub fn with_command_shape(mut self, command_shape: impl Into<String>) -> Self {
        self.command_shape = Some(command_shape.into());
        self
    }

    #[must_use]
    pub fn with_proof_artifact(mut self, proof_artifact: impl Into<String>) -> Self {
        self.proof_artifact = Some(proof_artifact.into());
        self
    }

    #[must_use]
    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    #[must_use]
    pub fn with_agent_name(mut self, agent_name: impl Into<String>) -> Self {
        self.agent_name = Some(agent_name.into());
        self
    }

    #[must_use]
    pub fn with_git_commit(mut self, git_commit: impl Into<String>) -> Self {
        self.git_commit = Some(git_commit.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQueryResult {
    pub record_id: String,
    pub score: u32,
    pub matched_fields: Vec<String>,
    pub record: EvidenceRecord,
}

#[derive(Debug, Clone)]
pub struct EvidenceIndex {
    policy: EvidenceIndexPolicy,
    records: Vec<EvidenceRecord>,
    report: EvidenceIndexBuildReport,
    by_record_id: BTreeMap<String, usize>,
    by_bead_id: BTreeMap<String, BTreeSet<String>>,
    by_source_path: BTreeMap<String, BTreeSet<String>>,
    by_command_shape: BTreeMap<String, BTreeSet<String>>,
    by_proof_artifact: BTreeMap<String, BTreeSet<String>>,
    by_error_code: BTreeMap<String, BTreeSet<String>>,
    by_agent_name: BTreeMap<String, BTreeSet<String>>,
    by_git_commit: BTreeMap<String, BTreeSet<String>>,
    by_tag: BTreeMap<String, BTreeSet<String>>,
    by_term: BTreeMap<String, BTreeSet<String>>,
}

impl EvidenceIndex {
    pub fn from_records<I>(
        policy: EvidenceIndexPolicy,
        records: I,
    ) -> Result<Self, EvidenceIndexError>
    where
        I: IntoIterator<Item = EvidenceRecord>,
    {
        validate_policy(&policy)?;
        let mut report = EvidenceIndexBuildReport::default();
        let mut accepted_by_id = BTreeMap::new();

        for record in records {
            let record_id_hint =
                normalize_record_id_hint(&record.record_id, policy.max_field_bytes);
            let source_path_hint = record.source_path.trim().to_string();
            let normalized = match normalize_record(record, &policy) {
                Ok(normalized) => normalized,
                Err(rejection) => {
                    push_rejection(&mut report, rejection, record_id_hint, source_path_hint);
                    continue;
                }
            };

            if accepted_by_id.contains_key(&normalized.record.record_id) {
                report.duplicate_records = report.duplicate_records.saturating_add(1);
                continue;
            }

            if accepted_by_id.len() >= policy.max_records {
                report.capped_records = report.capped_records.saturating_add(1);
                continue;
            }

            if normalized.tags_truncated {
                report.tag_truncated_records = report.tag_truncated_records.saturating_add(1);
            }
            if normalized.terms_truncated {
                report.term_truncated_records = report.term_truncated_records.saturating_add(1);
            }
            if let Some(stale_source) = normalized.stale_source {
                report.stale_sources.push(stale_source);
            }

            accepted_by_id.insert(normalized.record.record_id.clone(), normalized.record);
        }

        report.accepted_records = accepted_by_id.len();
        report.stale_sources.sort_by(|left, right| {
            left.record_id
                .cmp(&right.record_id)
                .then(left.source_path.cmp(&right.source_path))
        });
        report.rejected_sources.sort_by(|left, right| {
            left.source_path
                .cmp(&right.source_path)
                .then(left.record_id.cmp(&right.record_id))
                .then(left.reason_code.cmp(&right.reason_code))
        });

        let records: Vec<_> = accepted_by_id.into_values().collect();
        Ok(Self::build_from_validated(policy, records, report))
    }

    #[must_use]
    pub fn empty(policy: EvidenceIndexPolicy) -> Self {
        Self::build_from_validated(policy, Vec::new(), EvidenceIndexBuildReport::default())
    }

    #[must_use]
    pub fn policy(&self) -> &EvidenceIndexPolicy {
        &self.policy
    }

    #[must_use]
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    #[must_use]
    pub fn report(&self) -> &EvidenceIndexBuildReport {
        &self.report
    }

    #[must_use]
    pub fn snapshot(&self) -> EvidenceIndexSnapshot {
        EvidenceIndexSnapshot {
            schema_version: EVIDENCE_INDEX_SCHEMA_VERSION.to_string(),
            policy: self.policy.clone(),
            report: self.report.clone(),
            records: self.records.clone(),
        }
    }

    #[must_use]
    pub fn query(&self, query: &EvidenceQuery) -> Vec<EvidenceQueryResult> {
        let limit = self.query_limit(query.limit);
        if limit == 0 {
            return Vec::new();
        }
        if query_is_empty(query) {
            return self
                .records
                .iter()
                .take(limit)
                .map(|record| EvidenceQueryResult {
                    record_id: record.record_id.clone(),
                    score: 0,
                    matched_fields: Vec::new(),
                    record: record.clone(),
                })
                .collect();
        }

        let mut scores: BTreeMap<String, ScoredMatch> = BTreeMap::new();
        self.score_optional_field(
            &mut scores,
            &self.by_bead_id,
            query.bead_id.as_deref(),
            "bead_id",
            50,
            normalize_exact_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_source_path,
            query.source_path.as_deref(),
            "source_path",
            45,
            normalize_query_path_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_command_shape,
            query.command_shape.as_deref(),
            "command_shape",
            40,
            normalize_exact_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_proof_artifact,
            query.proof_artifact.as_deref(),
            "proof_artifact",
            40,
            normalize_query_path_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_error_code,
            query.error_code.as_deref(),
            "error_code",
            35,
            normalize_exact_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_agent_name,
            query.agent_name.as_deref(),
            "agent_name",
            25,
            normalize_exact_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_git_commit,
            query.git_commit.as_deref(),
            "git_commit",
            25,
            normalize_exact_key,
        );
        self.score_optional_field(
            &mut scores,
            &self.by_tag,
            query.tag.as_deref(),
            "tag",
            20,
            normalize_tag_key,
        );

        for term in normalize_terms(query.terms.iter().map(String::as_str)) {
            self.score_term(&mut scores, &term);
        }

        let mut matches: Vec<_> = scores.into_iter().collect();
        matches.sort_by(|(left_id, left), (right_id, right)| {
            right
                .score
                .cmp(&left.score)
                .then(left_id.cmp(right_id))
                .then(left.matched_fields.cmp(&right.matched_fields))
        });

        matches
            .into_iter()
            .filter_map(|(record_id, scored)| {
                let record = self.record_by_id(&record_id)?.clone();
                Some(EvidenceQueryResult {
                    record_id,
                    score: scored.score,
                    matched_fields: scored.matched_fields.into_iter().collect(),
                    record,
                })
            })
            .take(limit)
            .collect()
    }

    #[must_use]
    fn build_from_validated(
        policy: EvidenceIndexPolicy,
        records: Vec<EvidenceRecord>,
        report: EvidenceIndexBuildReport,
    ) -> Self {
        let mut index = Self {
            policy,
            records,
            report,
            by_record_id: BTreeMap::new(),
            by_bead_id: BTreeMap::new(),
            by_source_path: BTreeMap::new(),
            by_command_shape: BTreeMap::new(),
            by_proof_artifact: BTreeMap::new(),
            by_error_code: BTreeMap::new(),
            by_agent_name: BTreeMap::new(),
            by_git_commit: BTreeMap::new(),
            by_tag: BTreeMap::new(),
            by_term: BTreeMap::new(),
        };
        index.rebuild_indexes();
        index
    }

    fn rebuild_indexes(&mut self) {
        for (idx, record) in self.records.iter().enumerate() {
            let record_id = record.record_id.clone();
            self.by_record_id.insert(record_id.clone(), idx);
            insert_index(&mut self.by_source_path, &record.source_path, &record_id);
            insert_optional_index(&mut self.by_bead_id, record.bead_id.as_deref(), &record_id);
            insert_optional_index(
                &mut self.by_command_shape,
                record.command_shape.as_deref(),
                &record_id,
            );
            insert_optional_index(
                &mut self.by_proof_artifact,
                record.proof_artifact.as_deref(),
                &record_id,
            );
            insert_optional_index(
                &mut self.by_error_code,
                record.error_code.as_deref(),
                &record_id,
            );
            insert_optional_index(
                &mut self.by_agent_name,
                record.agent_name.as_deref(),
                &record_id,
            );
            insert_optional_index(
                &mut self.by_git_commit,
                record.git_commit.as_deref(),
                &record_id,
            );
            for tag in &record.tags {
                insert_index(&mut self.by_tag, tag, &record_id);
            }
            let mut terms = record_terms(record);
            if terms.len() > self.policy.max_terms_per_record {
                terms.truncate(self.policy.max_terms_per_record);
            }
            for term in terms {
                insert_index(&mut self.by_term, &term, &record_id);
            }
        }
    }

    fn query_limit(&self, requested: Option<usize>) -> usize {
        requested
            .unwrap_or(self.policy.max_query_results)
            .min(self.policy.max_query_results)
    }

    fn record_by_id(&self, record_id: &str) -> Option<&EvidenceRecord> {
        self.by_record_id
            .get(record_id)
            .and_then(|idx| self.records.get(*idx))
    }

    fn score_optional_field<F>(
        &self,
        scores: &mut BTreeMap<String, ScoredMatch>,
        index: &BTreeMap<String, BTreeSet<String>>,
        value: Option<&str>,
        field_name: &'static str,
        points: u32,
        normalize: F,
    ) where
        F: Fn(&str) -> Option<String>,
    {
        let Some(raw_value) = value else {
            return;
        };
        let Some(key) = normalize(raw_value) else {
            return;
        };
        let Some(record_ids) = index.get(&key) else {
            return;
        };
        for record_id in record_ids {
            score_record(scores, record_id, points, field_name);
        }
    }

    fn score_term(&self, scores: &mut BTreeMap<String, ScoredMatch>, term: &str) {
        let Some(record_ids) = self.by_term.get(term) else {
            return;
        };
        for record_id in record_ids {
            score_record(scores, record_id, 10, "term");
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ScoredMatch {
    score: u32,
    matched_fields: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct NormalizedRecord {
    record: EvidenceRecord,
    stale_source: Option<EvidenceIndexStaleSource>,
    tags_truncated: bool,
    terms_truncated: bool,
}

#[derive(Debug, Clone)]
struct RecordRejection {
    reason_code: &'static str,
    detail: String,
}

#[derive(Debug, Error)]
pub enum EvidenceIndexError {
    #[error("{code}: {message}")]
    Contract { code: &'static str, message: String },
}

impl EvidenceIndexError {
    fn contract(code: &'static str, message: impl Into<String>) -> Self {
        Self::Contract {
            code,
            message: message.into(),
        }
    }
}

pub fn build_evidence_index<I>(
    policy: EvidenceIndexPolicy,
    records: I,
) -> Result<EvidenceIndex, EvidenceIndexError>
where
    I: IntoIterator<Item = EvidenceRecord>,
{
    EvidenceIndex::from_records(policy, records)
}

pub fn render_evidence_index_json(index: &EvidenceIndex) -> Result<String, EvidenceIndexError> {
    serde_json::to_string_pretty(&index.snapshot()).map_err(|err| {
        EvidenceIndexError::contract(
            error_codes::ERR_EVIDENCE_INDEX_JSON,
            format!("failed to render evidence index snapshot JSON: {err}"),
        )
    })
}

fn validate_policy(policy: &EvidenceIndexPolicy) -> Result<(), EvidenceIndexError> {
    validate_nonzero(policy.max_query_results, "max_query_results")?;
    validate_nonzero(policy.max_field_bytes, "max_field_bytes")?;
    validate_nonzero(policy.max_path_bytes, "max_path_bytes")?;
    validate_nonzero(policy.max_tags_per_record, "max_tags_per_record")?;
    validate_nonzero(policy.max_terms_per_record, "max_terms_per_record")?;
    let _ = bounded_required_string(
        &policy.policy_id,
        "policy_id",
        policy.max_field_bytes,
        error_codes::ERR_EVIDENCE_INDEX_INVALID_POLICY,
    )?;
    for root in &policy.allowed_source_roots {
        normalize_repo_relative_path(root, policy.max_path_bytes).map_err(|err| {
            EvidenceIndexError::contract(
                error_codes::ERR_EVIDENCE_INDEX_INVALID_POLICY,
                format!(
                    "invalid allowed_source_roots entry `{root}`: {}",
                    err.detail
                ),
            )
        })?;
    }
    Ok(())
}

fn validate_nonzero(value: usize, field_name: &'static str) -> Result<(), EvidenceIndexError> {
    if value == 0 {
        return Err(EvidenceIndexError::contract(
            error_codes::ERR_EVIDENCE_INDEX_INVALID_POLICY,
            format!("{field_name} must be greater than zero"),
        ));
    }
    Ok(())
}

fn normalize_record(
    record: EvidenceRecord,
    policy: &EvidenceIndexPolicy,
) -> Result<NormalizedRecord, RecordRejection> {
    let record_id = bounded_required_string(
        &record.record_id,
        "record_id",
        policy.max_field_bytes,
        error_codes::ERR_EVIDENCE_INDEX_INVALID_RECORD,
    )
    .map_err(|err| RecordRejection {
        reason_code: reason_from_contract_code(&err),
        detail: err.to_string(),
    })?;
    let source_path = normalize_repo_relative_path(&record.source_path, policy.max_path_bytes)?;
    if let Some((reason_code, detail)) = protected_source_reason(&source_path) {
        return Err(RecordRejection {
            reason_code,
            detail: detail.to_string(),
        });
    }
    if !is_allowed_source_path(&source_path, &policy.allowed_source_roots) {
        return Err(RecordRejection {
            reason_code: reason_codes::SOURCE_ROOT_NOT_ALLOWED,
            detail: format!("source path `{source_path}` is outside approved evidence roots"),
        });
    }

    let title = bounded_required_string(
        &record.title,
        "title",
        policy.max_field_bytes,
        error_codes::ERR_EVIDENCE_INDEX_INVALID_RECORD,
    )
    .map_err(|err| RecordRejection {
        reason_code: reason_from_contract_code(&err),
        detail: err.to_string(),
    })?;
    let summary = normalize_optional_field(record.summary, "summary", policy.max_field_bytes)?;
    let bead_id = normalize_optional_field(record.bead_id, "bead_id", policy.max_field_bytes)?;
    let command_shape = normalize_optional_field(
        record.command_shape,
        "command_shape",
        policy.max_field_bytes,
    )?;
    let proof_artifact = normalize_optional_path_field(record.proof_artifact, policy)?;
    let error_code =
        normalize_optional_field(record.error_code, "error_code", policy.max_field_bytes)?;
    let agent_name =
        normalize_optional_field(record.agent_name, "agent_name", policy.max_field_bytes)?;
    let git_commit =
        normalize_optional_field(record.git_commit, "git_commit", policy.max_field_bytes)?;
    validate_mtime(record.source_mtime_seconds)?;
    validate_mtime(record.observed_mtime_seconds)?;

    let (tags, tags_truncated) = normalize_tags(&record.tags, policy)?;
    let terms_truncated = record_terms_with_parts(RecordTermParts {
        title: &title,
        summary: summary.as_deref(),
        source_path: &source_path,
        tags: &tags,
        bead_id: bead_id.as_deref(),
        command_shape: command_shape.as_deref(),
        proof_artifact: proof_artifact.as_deref(),
        error_code: error_code.as_deref(),
        agent_name: agent_name.as_deref(),
        git_commit: git_commit.as_deref(),
    })
    .len()
        > policy.max_terms_per_record;
    let stale_source = stale_source_for_record(
        &record_id,
        &source_path,
        record.source_mtime_seconds,
        record.observed_mtime_seconds,
    );

    Ok(NormalizedRecord {
        record: EvidenceRecord {
            schema_version: EVIDENCE_INDEX_RECORD_SCHEMA_VERSION.to_string(),
            record_id,
            source_kind: record.source_kind,
            safety_class: record.safety_class,
            source_path,
            source_mtime_seconds: record.source_mtime_seconds,
            observed_mtime_seconds: record.observed_mtime_seconds,
            title,
            summary,
            tags,
            bead_id,
            command_shape,
            proof_artifact,
            error_code,
            agent_name,
            git_commit,
        },
        stale_source,
        tags_truncated,
        terms_truncated,
    })
}

fn bounded_required_string(
    value: &str,
    field_name: &'static str,
    max_bytes: usize,
    contract_code: &'static str,
) -> Result<String, EvidenceIndexError> {
    let trimmed = bounded_trimmed_string(value, field_name, max_bytes, contract_code)?;
    if trimmed.is_empty() {
        return Err(EvidenceIndexError::contract(
            contract_code,
            format!("{field_name} is required"),
        ));
    }
    Ok(trimmed)
}

fn bounded_trimmed_string(
    value: &str,
    field_name: &'static str,
    max_bytes: usize,
    contract_code: &'static str,
) -> Result<String, EvidenceIndexError> {
    if value.contains('\0') {
        return Err(EvidenceIndexError::contract(
            contract_code,
            format!("{field_name} contains a NUL byte"),
        ));
    }
    let trimmed = value.trim().to_string();
    if trimmed.len() > max_bytes {
        return Err(EvidenceIndexError::contract(
            contract_code,
            format!(
                "{field_name} is {} bytes; limit is {max_bytes}",
                trimmed.len()
            ),
        ));
    }
    Ok(trimmed)
}

fn normalize_optional_field(
    value: Option<String>,
    field_name: &'static str,
    max_bytes: usize,
) -> Result<Option<String>, RecordRejection> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = bounded_trimmed_string(
        &value,
        field_name,
        max_bytes,
        error_codes::ERR_EVIDENCE_INDEX_INVALID_RECORD,
    )
    .map_err(|err| RecordRejection {
        reason_code: reason_from_contract_code(&err),
        detail: err.to_string(),
    })?;
    if normalized.is_empty() {
        Ok(None)
    } else {
        Ok(Some(normalized))
    }
}

fn normalize_optional_path_field(
    value: Option<String>,
    policy: &EvidenceIndexPolicy,
) -> Result<Option<String>, RecordRejection> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    let path = normalize_repo_relative_path(&value, policy.max_path_bytes)?;
    if let Some((reason_code, detail)) = protected_source_reason(&path) {
        return Err(RecordRejection {
            reason_code,
            detail: detail.to_string(),
        });
    }
    if !is_allowed_source_path(&path, &policy.allowed_source_roots) {
        return Err(RecordRejection {
            reason_code: reason_codes::SOURCE_ROOT_NOT_ALLOWED,
            detail: format!("proof artifact `{path}` is outside approved evidence roots"),
        });
    }
    Ok(Some(path))
}

fn normalize_tags(
    tags: &[String],
    policy: &EvidenceIndexPolicy,
) -> Result<(Vec<String>, bool), RecordRejection> {
    let mut normalized = BTreeSet::new();
    for tag in tags {
        let Some(tag) = normalize_tag_key(tag) else {
            continue;
        };
        if tag.len() > policy.max_field_bytes {
            return Err(RecordRejection {
                reason_code: reason_codes::FIELD_TOO_LARGE,
                detail: format!(
                    "tag is {} bytes; limit is {}",
                    tag.len(),
                    policy.max_field_bytes
                ),
            });
        }
        normalized.insert(tag);
    }
    let truncated = normalized.len() > policy.max_tags_per_record;
    Ok((
        normalized
            .into_iter()
            .take(policy.max_tags_per_record)
            .collect(),
        truncated,
    ))
}

fn normalize_repo_relative_path(
    path: &str,
    max_path_bytes: usize,
) -> Result<String, RecordRejection> {
    let trimmed = path.trim().trim_start_matches("./");
    if trimmed.is_empty() {
        return Err(RecordRejection {
            reason_code: reason_codes::INVALID_REPO_PATH,
            detail: "repo-relative path is required".to_string(),
        });
    }
    if trimmed.contains('\0') {
        return Err(RecordRejection {
            reason_code: reason_codes::INVALID_REPO_PATH,
            detail: "repo-relative path contains a NUL byte".to_string(),
        });
    }
    if trimmed.contains('\\') {
        return Err(RecordRejection {
            reason_code: reason_codes::INVALID_REPO_PATH,
            detail: "repo-relative path must use forward slash separators".to_string(),
        });
    }
    if trimmed.len() > max_path_bytes {
        return Err(RecordRejection {
            reason_code: reason_codes::FIELD_TOO_LARGE,
            detail: format!(
                "repo-relative path is {} bytes; limit is {max_path_bytes}",
                trimmed.len()
            ),
        });
    }

    let mut components = Vec::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(value) => {
                let Some(value) = value.to_str() else {
                    return Err(RecordRejection {
                        reason_code: reason_codes::INVALID_REPO_PATH,
                        detail: "repo-relative path contains non-UTF-8 component".to_string(),
                    });
                };
                if value.is_empty() {
                    return Err(RecordRejection {
                        reason_code: reason_codes::INVALID_REPO_PATH,
                        detail: "repo-relative path contains an empty component".to_string(),
                    });
                }
                components.push(value.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RecordRejection {
                    reason_code: reason_codes::INVALID_REPO_PATH,
                    detail: "repo-relative path cannot escape the repository".to_string(),
                });
            }
        }
    }
    if components.is_empty() {
        return Err(RecordRejection {
            reason_code: reason_codes::INVALID_REPO_PATH,
            detail: "repo-relative path is required".to_string(),
        });
    }
    Ok(components.join("/"))
}

fn protected_source_reason(path: &str) -> Option<(&'static str, &'static str)> {
    let first = path.split('/').next().unwrap_or_default();
    if path == ".env" || path.starts_with(".env.") || first == "secrets" {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "secret-bearing paths are not indexable evidence sources",
        ));
    }
    if first == ".git" {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "git internals are not indexable evidence sources",
        ));
    }
    if first == "target" || first.starts_with(".cargo-target") || first.starts_with(".rch-target") {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "build output directories are not indexable evidence sources",
        ));
    }
    if first == "logs"
        || first == "log"
        || first == "session_history"
        || first == "memory"
        || first == "memories"
        || path.starts_with(".codex/memories/")
        || path.starts_with(".codex/sessions/")
        || path.starts_with(".claude/memories/")
        || path.starts_with(".claude/projects/")
    {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "raw logs, session history, and memory stores are not indexable evidence sources",
        ));
    }
    if has_large_binary_artifact_extension(path) {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "large binary artifacts are not indexable evidence sources",
        ));
    }
    if first == "messages" || first == "agents" || first == "attachments" || first == ".agent-mail"
    {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "Agent Mail internals are not indexable evidence sources",
        ));
    }
    if first == ".beads" && path != ".beads/issues.jsonl" {
        return Some((
            reason_codes::PROTECTED_SOURCE_REJECTED,
            "raw Beads database and recovery internals are not indexable evidence sources",
        ));
    }
    None
}

fn has_large_binary_artifact_extension(path: &str) -> bool {
    let Some((_, extension)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "a" | "bin"
            | "db"
            | "dylib"
            | "gif"
            | "gz"
            | "jpeg"
            | "jpg"
            | "mov"
            | "mp4"
            | "pdf"
            | "png"
            | "rlib"
            | "so"
            | "sqlite"
            | "tar"
            | "tgz"
            | "wasm"
            | "webp"
            | "zip"
            | "zst"
    )
}

fn is_allowed_source_path(path: &str, allowed_roots: &[String]) -> bool {
    if allowed_roots.is_empty() {
        return true;
    }
    allowed_roots.iter().any(|root| {
        let normalized = root.trim().trim_start_matches("./");
        path == normalized || path.starts_with(&format!("{normalized}/"))
    })
}

fn validate_mtime(value: Option<i64>) -> Result<(), RecordRejection> {
    if value.is_some_and(|value| value < 0) {
        return Err(RecordRejection {
            reason_code: reason_codes::NEGATIVE_MTIME,
            detail: "source mtime values must be non-negative".to_string(),
        });
    }
    Ok(())
}

fn stale_source_for_record(
    record_id: &str,
    source_path: &str,
    source_mtime_seconds: Option<i64>,
    observed_mtime_seconds: Option<i64>,
) -> Option<EvidenceIndexStaleSource> {
    let (Some(source_mtime_seconds), Some(observed_mtime_seconds)) =
        (source_mtime_seconds, observed_mtime_seconds)
    else {
        return None;
    };
    if source_mtime_seconds >= observed_mtime_seconds {
        return None;
    }
    Some(EvidenceIndexStaleSource {
        record_id: record_id.to_string(),
        source_path: source_path.to_string(),
        source_mtime_seconds,
        observed_mtime_seconds,
        reason_code: reason_codes::SOURCE_STALE.to_string(),
        rebuild_guidance: format!(
            "rebuild evidence index from `{source_path}` before using `{record_id}` for closeout"
        ),
    })
}

fn normalize_record_id_hint(record_id: &str, max_bytes: usize) -> Option<String> {
    let trimmed = record_id.trim();
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.len() > max_bytes {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn push_rejection(
    report: &mut EvidenceIndexBuildReport,
    rejection: RecordRejection,
    record_id: Option<String>,
    source_path: String,
) {
    report.rejected_sources.push(EvidenceIndexRejectedSource {
        record_id,
        source_path,
        reason_code: rejection.reason_code.to_string(),
        detail: rejection.detail,
    });
}

fn reason_from_contract_code(error: &EvidenceIndexError) -> &'static str {
    match error {
        EvidenceIndexError::Contract { message, .. } if message.contains("required") => {
            reason_codes::REQUIRED_FIELD_EMPTY
        }
        EvidenceIndexError::Contract { message, .. } if message.contains("bytes") => {
            reason_codes::FIELD_TOO_LARGE
        }
        EvidenceIndexError::Contract { .. } => reason_codes::FIELD_TOO_LARGE,
    }
}

fn insert_optional_index(
    index: &mut BTreeMap<String, BTreeSet<String>>,
    value: Option<&str>,
    record_id: &str,
) {
    let Some(value) = value else {
        return;
    };
    insert_index(index, value, record_id);
}

fn insert_index(index: &mut BTreeMap<String, BTreeSet<String>>, key: &str, record_id: &str) {
    index
        .entry(key.to_string())
        .or_default()
        .insert(record_id.to_string());
}

fn score_record(
    scores: &mut BTreeMap<String, ScoredMatch>,
    record_id: &str,
    points: u32,
    field_name: &'static str,
) {
    let entry = scores.entry(record_id.to_string()).or_default();
    entry.score = entry.score.saturating_add(points);
    entry.matched_fields.insert(field_name.to_string());
}

fn normalize_exact_key(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        None
    } else {
        Some(value.to_string())
    }
}

fn normalize_query_path_key(value: &str) -> Option<String> {
    normalize_repo_relative_path(value, DEFAULT_MAX_PATH_BYTES).ok()
}

fn normalize_tag_key(value: &str) -> Option<String> {
    let mut normalized = String::new();
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/') {
            normalized.push(ch.to_ascii_lowercase());
        }
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn query_is_empty(query: &EvidenceQuery) -> bool {
    query
        .terms
        .iter()
        .all(|term| normalize_terms([term.as_str()]).is_empty())
        && query
            .bead_id
            .as_deref()
            .and_then(normalize_exact_key)
            .is_none()
        && query
            .source_path
            .as_deref()
            .and_then(normalize_query_path_key)
            .is_none()
        && query
            .command_shape
            .as_deref()
            .and_then(normalize_exact_key)
            .is_none()
        && query
            .proof_artifact
            .as_deref()
            .and_then(normalize_query_path_key)
            .is_none()
        && query
            .error_code
            .as_deref()
            .and_then(normalize_exact_key)
            .is_none()
        && query
            .agent_name
            .as_deref()
            .and_then(normalize_exact_key)
            .is_none()
        && query
            .git_commit
            .as_deref()
            .and_then(normalize_exact_key)
            .is_none()
        && query.tag.as_deref().and_then(normalize_tag_key).is_none()
}

fn normalize_terms<'a, I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut terms = BTreeSet::new();
    for value in values {
        let mut current = String::new();
        for ch in value.chars() {
            if ch.is_ascii_alphanumeric() {
                current.push(ch.to_ascii_lowercase());
            } else if !current.is_empty() {
                terms.insert(std::mem::take(&mut current));
            }
        }
        if !current.is_empty() {
            terms.insert(current);
        }
    }
    terms.into_iter().collect()
}

struct RecordTermParts<'a> {
    title: &'a str,
    summary: Option<&'a str>,
    source_path: &'a str,
    tags: &'a [String],
    bead_id: Option<&'a str>,
    command_shape: Option<&'a str>,
    proof_artifact: Option<&'a str>,
    error_code: Option<&'a str>,
    agent_name: Option<&'a str>,
    git_commit: Option<&'a str>,
}

fn record_terms(record: &EvidenceRecord) -> Vec<String> {
    record_terms_with_parts(RecordTermParts {
        title: &record.title,
        summary: record.summary.as_deref(),
        source_path: &record.source_path,
        tags: &record.tags,
        bead_id: record.bead_id.as_deref(),
        command_shape: record.command_shape.as_deref(),
        proof_artifact: record.proof_artifact.as_deref(),
        error_code: record.error_code.as_deref(),
        agent_name: record.agent_name.as_deref(),
        git_commit: record.git_commit.as_deref(),
    })
}

fn record_terms_with_parts(parts: RecordTermParts<'_>) -> Vec<String> {
    let mut values = vec![parts.title, parts.source_path];
    values.extend(parts.summary);
    values.extend(parts.bead_id);
    values.extend(parts.command_shape);
    values.extend(parts.proof_artifact);
    values.extend(parts.error_code);
    values.extend(parts.agent_name);
    values.extend(parts.git_commit);
    values.extend(parts.tags.iter().map(String::as_str));
    normalize_terms(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EvidenceIndexPolicy {
        EvidenceIndexPolicy {
            max_records: 8,
            max_query_results: 4,
            max_field_bytes: 128,
            max_path_bytes: 256,
            max_tags_per_record: 3,
            max_terms_per_record: 12,
            ..EvidenceIndexPolicy::default()
        }
    }

    fn record(id: &str, path: &str, title: &str) -> EvidenceRecord {
        EvidenceRecord::new(
            id,
            EvidenceSourceKind::DocsSpec,
            EvidenceSafetyClass::RepoContract,
            path,
            title,
        )
    }

    #[test]
    fn empty_index_returns_no_query_results() {
        let index = EvidenceIndex::from_records(policy(), Vec::new()).expect("empty index");

        assert!(index.records().is_empty());
        assert_eq!(index.report().accepted_records, 0);
        assert!(
            index
                .query(&EvidenceQuery::new().with_term("anything"))
                .is_empty()
        );
    }

    #[test]
    fn duplicate_record_ids_are_deduped_deterministically() {
        let index = EvidenceIndex::from_records(
            policy(),
            [
                record("rec-1", "docs/specs/a.md", "first").with_bead_id("bd-1"),
                record("rec-1", "docs/specs/b.md", "second").with_bead_id("bd-2"),
            ],
        )
        .expect("index");

        assert_eq!(index.records().len(), 1);
        assert_eq!(index.records()[0].source_path, "docs/specs/a.md");
        assert_eq!(index.report().duplicate_records, 1);
    }

    #[test]
    fn stale_source_detection_keeps_rebuild_guidance() {
        let index = EvidenceIndex::from_records(
            policy(),
            [record("rec-stale", "docs/specs/stale.md", "stale")
                .with_source_mtime_seconds(10)
                .with_observed_mtime_seconds(12)],
        )
        .expect("index");

        assert_eq!(index.records().len(), 1);
        assert_eq!(index.report().stale_sources.len(), 1);
        assert_eq!(
            index.report().stale_sources[0].reason_code,
            reason_codes::SOURCE_STALE
        );
        assert!(
            index.report().stale_sources[0]
                .rebuild_guidance
                .contains("rebuild evidence index")
        );
    }

    #[test]
    fn protected_sources_are_rejected_fail_closed() {
        let index = EvidenceIndex::from_records(
            policy(),
            [
                record("log", "logs/session.jsonl", "raw log"),
                record("mail", "agents/CalmSnow/inbox/message.md", "mail"),
                record("beads-db", ".beads/beads.db", "raw beads"),
                record("memory", ".codex/memories/MEMORY.md", "memory"),
                record("binary", "artifacts/screenshots/proof.png", "binary"),
                record("secret", ".env", "secret"),
                record("ok", ".beads/issues.jsonl", "beads export"),
            ],
        )
        .expect("index");

        assert_eq!(index.records().len(), 1);
        assert_eq!(index.records()[0].record_id, "ok");
        assert_eq!(index.report().rejected_sources.len(), 6);
        assert!(
            index.report().rejected_sources.iter().all(|rejection| {
                rejection.reason_code == reason_codes::PROTECTED_SOURCE_REJECTED
            })
        );
    }

    #[test]
    fn record_cap_bounds_high_volume_ingestion() {
        let mut bounded_policy = policy();
        bounded_policy.max_records = 2;
        let index = EvidenceIndex::from_records(
            bounded_policy,
            [
                record("rec-a", "docs/specs/a.md", "a"),
                record("rec-b", "docs/specs/b.md", "b"),
                record("rec-c", "docs/specs/c.md", "c"),
                record("rec-d", "docs/specs/d.md", "d"),
            ],
        )
        .expect("index");

        assert_eq!(index.records().len(), 2);
        assert_eq!(index.report().capped_records, 2);
        assert_eq!(
            index
                .query(&EvidenceQuery::new().with_limit(10))
                .iter()
                .map(|result| result.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rec-a", "rec-b"]
        );
    }

    #[test]
    fn query_ranking_is_score_then_record_id_deterministic() {
        let index = EvidenceIndex::from_records(
            policy(),
            [
                record("rec-b", "docs/specs/b.md", "validation planner metadata")
                    .with_summary("shared proof cache guidance")
                    .with_tags(["proof", "planner"])
                    .with_bead_id("bd-38hez.5")
                    .with_command_shape("rch exec -- cargo test -p frankenengine-node")
                    .with_agent_name("SnowyBeaver"),
                record("rec-a", "artifacts/validation_broker/a.json", "metadata")
                    .with_summary("proof cache")
                    .with_tags(["proof"])
                    .with_bead_id("bd-38hez.5"),
                record("rec-c", "docs/specs/c.md", "metadata only").with_bead_id("bd-other"),
            ],
        )
        .expect("index");

        let results = index.query(
            &EvidenceQuery::new()
                .with_bead_id("bd-38hez.5")
                .with_term("proof")
                .with_agent_name("SnowyBeaver")
                .with_limit(2),
        );

        assert_eq!(
            results
                .iter()
                .map(|result| (result.record_id.as_str(), result.score))
                .collect::<Vec<_>>(),
            vec![("rec-b", 85), ("rec-a", 60)]
        );
        assert_eq!(
            index
                .query(&EvidenceQuery::new().with_bead_id("bd-38hez.5"))
                .iter()
                .map(|result| result.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rec-a", "rec-b"]
        );
    }

    #[test]
    fn tag_and_term_growth_is_bounded_per_record() {
        let mut bounded_policy = policy();
        bounded_policy.max_tags_per_record = 2;
        bounded_policy.max_terms_per_record = 3;
        let index = EvidenceIndex::from_records(
            bounded_policy,
            [record(
                "rec-tags",
                "docs/specs/tags.md",
                "alpha beta gamma delta epsilon",
            )
            .with_tags(["zeta", "eta", "theta", "iota"])
            .with_summary("kappa lambda mu")],
        )
        .expect("index");

        assert_eq!(index.records()[0].tags, vec!["eta", "iota"]);
        assert_eq!(index.report().tag_truncated_records, 1);
        assert_eq!(index.report().term_truncated_records, 1);
        assert_eq!(
            index
                .query(&EvidenceQuery::new().with_term("alpha").with_limit(10))
                .len(),
            1
        );
    }

    #[test]
    fn snapshot_json_is_stable_and_metadata_only() {
        let index = EvidenceIndex::from_records(
            policy(),
            [record("rec-json", "docs/specs/json.md", "json evidence")
                .with_proof_artifact("artifacts/proofs/json.json")
                .with_error_code("ERR_EXAMPLE")],
        )
        .expect("index");

        let json = render_evidence_index_json(&index).expect("json");

        assert!(json.contains(EVIDENCE_INDEX_SCHEMA_VERSION));
        assert!(json.contains("rec-json"));
        assert!(!json.contains("by_term"));
        assert!(!json.contains("by_record_id"));
    }
}
