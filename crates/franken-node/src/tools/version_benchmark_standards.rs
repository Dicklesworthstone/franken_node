//! bd-3v8g: Version benchmark standards with migration guidance (Section 14).
//!
//! Manages versioned benchmark standard definitions with explicit migration
//! paths between revisions. Ensures reproducibility by embedding version
//! identifiers in every benchmark artifact and providing machine-readable
//! migration guides when standards evolve.
//!
//! # Capabilities
//!
//! - Standard revision registry with semantic versioning
//! - Migration path computation between revisions
//! - Breaking-change detection and compatibility classification
//! - Migration guide generation with step-by-step instructions
//! - Deterministic version comparison and ordering
//!
//! # Invariants
//!
//! - **INV-BSV-SEMVER**: All standard versions follow semantic versioning.
//! - **INV-BSV-DETERMINISTIC**: Same version inputs produce same migration output.
//! - **INV-BSV-MIGRATION-PATH**: Every adjacent version pair has a migration guide.
//! - **INV-BSV-BACKWARD-COMPAT**: Non-breaking changes preserve backward compatibility.
//! - **INV-BSV-VERSIONED**: Standard version embedded in every benchmark artifact.
//! - **INV-BSV-GATED**: Breaking changes require explicit migration acknowledgment.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const BSV_REVISION_REGISTERED: &str = "BSV-001";
    pub const BSV_MIGRATION_COMPUTED: &str = "BSV-002";
    pub const BSV_COMPAT_CHECKED: &str = "BSV-003";
    pub const BSV_GUIDE_GENERATED: &str = "BSV-004";
    pub const BSV_BREAKING_DETECTED: &str = "BSV-005";
    pub const BSV_VERSION_COMPARED: &str = "BSV-006";
    pub const BSV_REPORT_GENERATED: &str = "BSV-007";
    pub const BSV_DEPRECATION_NOTICED: &str = "BSV-008";
    pub const BSV_ROLLBACK_COMPUTED: &str = "BSV-009";
    pub const BSV_STANDARD_LOCKED: &str = "BSV-010";
    pub const BSV_ERR_INVALID_VERSION: &str = "BSV-ERR-001";
    pub const BSV_ERR_NO_MIGRATION_PATH: &str = "BSV-ERR-002";
}

pub mod invariants {
    pub const INV_BSV_SEMVER: &str = "INV-BSV-SEMVER";
    pub const INV_BSV_DETERMINISTIC: &str = "INV-BSV-DETERMINISTIC";
    pub const INV_BSV_MIGRATION_PATH: &str = "INV-BSV-MIGRATION-PATH";
    pub const INV_BSV_BACKWARD_COMPAT: &str = "INV-BSV-BACKWARD-COMPAT";
    pub const INV_BSV_VERSIONED: &str = "INV-BSV-VERSIONED";
    pub const INV_BSV_GATED: &str = "INV-BSV-GATED";
}

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;

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

fn revision_validation_error(revision: &StandardRevision) -> Option<&'static str> {
    if revision.title.trim().is_empty() {
        return Some("empty title");
    }
    if revision.release_date.trim().is_empty() {
        return Some("empty release_date");
    }
    if revision.tracks.is_empty() {
        return Some("empty tracks");
    }
    if revision.tracks.iter().any(|track| track.trim().is_empty()) {
        return Some("blank track");
    }
    if revision.track_count != revision.tracks.len() {
        return Some("track_count mismatch");
    }
    if revision.scoring_formula_version.trim().is_empty() {
        return Some("empty scoring_formula_version");
    }
    if revision.harness_version.trim().is_empty() {
        return Some("empty harness_version");
    }
    if revision
        .changelog
        .iter()
        .any(|entry| entry.description.trim().is_empty())
    {
        return Some("empty changelog description");
    }
    if revision
        .changelog
        .iter()
        .flat_map(|entry| entry.affected_tracks.iter())
        .any(|track| track.trim().is_empty())
    {
        return Some("blank affected track");
    }
    None
}

// ---------------------------------------------------------------------------
// Semantic version
// ---------------------------------------------------------------------------

fn parse_semver_component(component: &str) -> Option<u32> {
    if component.is_empty() {
        return None;
    }
    if component.len() > 1 && component.starts_with('0') {
        return None;
    }
    if !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    component.parse().ok()
}

/// Semantic version for benchmark standards.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemVer {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn label(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('.');
        let major = parse_semver_component(parts.next()?)?;
        let minor = parse_semver_component(parts.next()?)?;
        let patch = parse_semver_component(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    pub fn is_breaking_from(&self, other: &SemVer) -> bool {
        self.major != other.major
    }

    pub fn is_feature_from(&self, other: &SemVer) -> bool {
        self.major == other.major && self.minor != other.minor
    }

    pub fn is_patch_from(&self, other: &SemVer) -> bool {
        self.major == other.major && self.minor == other.minor && self.patch != other.patch
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Standard revision
// ---------------------------------------------------------------------------

/// A benchmark standard revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StandardRevision {
    pub version: SemVer,
    pub title: String,
    pub release_date: String,
    pub tracks: Vec<String>,
    pub track_count: usize,
    pub scoring_formula_version: String,
    pub harness_version: String,
    pub deprecated: bool,
    pub changelog: Vec<ChangelogEntry>,
}

/// A single change entry in a revision's changelog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangelogEntry {
    pub change_type: ChangeType,
    pub description: String,
    pub affected_tracks: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Breaking,
    Feature,
    Fix,
    Deprecation,
}

// ---------------------------------------------------------------------------
// Migration types
// ---------------------------------------------------------------------------

/// Compatibility classification between two revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityLevel {
    FullyCompatible,
    BackwardCompatible,
    RequiresMigration,
    Incompatible,
}

/// Migration guide between two standard revisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationGuide {
    pub from_version: SemVer,
    pub to_version: SemVer,
    pub compatibility: CompatibilityLevel,
    pub breaking_changes: Vec<String>,
    pub migration_steps: Vec<MigrationStep>,
    pub rollback_possible: bool,
    pub estimated_effort: MigrationEffort,
    pub content_hash: String,
}

/// A single migration step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationStep {
    pub step_number: usize,
    pub action: String,
    pub description: String,
    pub automated: bool,
}

/// Migration effort estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationEffort {
    Trivial,
    Low,
    Medium,
    High,
}

// ---------------------------------------------------------------------------
// Versioning report
// ---------------------------------------------------------------------------

/// Full benchmark versioning report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersioningReport {
    pub report_id: String,
    pub timestamp: String,
    pub current_version: SemVer,
    pub revisions_registered: usize,
    pub migration_guides_available: usize,
    pub deprecation_notices: Vec<String>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BsvAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Benchmark standard versioning engine.
#[derive(Debug, Clone)]
pub struct BenchmarkVersioning {
    revisions: BTreeMap<SemVer, StandardRevision>,
    current_version: SemVer,
    audit_log: Vec<BsvAuditRecord>,
}

impl Default for BenchmarkVersioning {
    fn default() -> Self {
        let mut engine = Self {
            revisions: BTreeMap::new(),
            current_version: SemVer::new(1, 0, 0),
            audit_log: Vec::new(),
        };
        engine.register_initial_revisions();
        engine
    }
}

impl BenchmarkVersioning {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new standard revision.
    pub fn register_revision(&mut self, revision: StandardRevision, trace_id: &str) {
        if let Some(reason) = revision_validation_error(&revision) {
            self.log(
                event_codes::BSV_ERR_INVALID_VERSION,
                trace_id,
                serde_json::json!({
                    "version": revision.version.label(),
                    "reason": reason,
                }),
            );
            return;
        }

        self.log(
            event_codes::BSV_REVISION_REGISTERED,
            trace_id,
            serde_json::json!({
                "version": revision.version.label(),
                "title": &revision.title,
                "tracks": revision.track_count,
            }),
        );

        if revision.deprecated {
            self.log(
                event_codes::BSV_DEPRECATION_NOTICED,
                trace_id,
                serde_json::json!({
                    "version": revision.version.label(),
                }),
            );
        }

        if revision.version > self.current_version {
            self.current_version = revision.version.clone();
        }
        self.revisions.insert(revision.version.clone(), revision);
    }

    /// Compute migration guide between two versions.
    pub fn compute_migration(
        &mut self,
        from: &SemVer,
        to: &SemVer,
        trace_id: &str,
    ) -> Option<MigrationGuide> {
        let from_rev = self.revisions.get(from)?;
        let to_rev = self.revisions.get(to)?;

        let compatibility = if from == to {
            CompatibilityLevel::FullyCompatible
        } else if to.is_breaking_from(from) {
            CompatibilityLevel::RequiresMigration
        } else if to.is_feature_from(from) {
            CompatibilityLevel::BackwardCompatible
        } else {
            CompatibilityLevel::FullyCompatible
        };

        let breaking_changes: Vec<String> = to_rev
            .changelog
            .iter()
            .filter(|c| c.change_type == ChangeType::Breaking)
            .map(|c| c.description.clone())
            .collect();

        let steps = self.generate_migration_steps(from_rev, to_rev, &breaking_changes);
        let effort = self.estimate_effort(&breaking_changes, &steps);
        let rollback = compatibility != CompatibilityLevel::Incompatible;

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"version_benchmark_guide_hash_v1:");
            let from_label = from.label();
            h.update((from_label.len() as u64).to_le_bytes());
            h.update(from_label.as_bytes());
            let to_label = to.label();
            h.update((to_label.len() as u64).to_le_bytes());
            h.update(to_label.as_bytes());
            let compat_label = format!("{compatibility:?}");
            h.update((compat_label.len() as u64).to_le_bytes());
            h.update(compat_label.as_bytes());
            h.update((breaking_changes.len() as u64).to_le_bytes());
            for bc in &breaking_changes {
                h.update((bc.len() as u64).to_le_bytes());
                h.update(bc.as_bytes());
            }
            h.update((steps.len() as u64).to_le_bytes());
            for step in &steps {
                h.update((step.step_number as u64).to_le_bytes());
                h.update((step.action.len() as u64).to_le_bytes());
                h.update(step.action.as_bytes());
                h.update([u8::from(step.automated)]);
            }
            h.update([u8::from(rollback)]);
            let effort_label = format!("{effort:?}");
            h.update((effort_label.len() as u64).to_le_bytes());
            h.update(effort_label.as_bytes());
            hex::encode(h.finalize())
        };

        let guide = MigrationGuide {
            from_version: from.clone(),
            to_version: to.clone(),
            compatibility,
            breaking_changes,
            migration_steps: steps,
            rollback_possible: rollback,
            estimated_effort: effort,
            content_hash,
        };

        self.log(
            event_codes::BSV_MIGRATION_COMPUTED,
            trace_id,
            serde_json::json!({
                "from": from.label(),
                "to": to.label(),
                "compatibility": format!("{:?}", compatibility),
                "steps": guide.migration_steps.len(),
            }),
        );

        if guide.compatibility == CompatibilityLevel::RequiresMigration {
            self.log(
                event_codes::BSV_BREAKING_DETECTED,
                trace_id,
                serde_json::json!({
                    "from": from.label(),
                    "to": to.label(),
                    "breaking_count": guide.breaking_changes.len(),
                }),
            );
        }

        Some(guide)
    }

    /// Check compatibility between two versions.
    pub fn check_compatibility(
        &mut self,
        from: &SemVer,
        to: &SemVer,
        trace_id: &str,
    ) -> Option<CompatibilityLevel> {
        let guide = self.compute_migration(from, to, trace_id)?;
        self.log(
            event_codes::BSV_COMPAT_CHECKED,
            trace_id,
            serde_json::json!({
                "from": from.label(),
                "to": to.label(),
                "level": format!("{:?}", guide.compatibility),
            }),
        );
        Some(guide.compatibility)
    }

    /// Generate versioning status report.
    pub fn generate_report(&mut self, trace_id: &str) -> VersioningReport {
        let deprecations: Vec<String> = self
            .revisions
            .values()
            .filter(|r| r.deprecated)
            .map(|r| format!("{} ({})", r.version.label(), r.title))
            .collect();

        let migration_count = self.count_migration_paths();

        let content_hash = {
            let mut h = Sha256::new();
            h.update(b"version_benchmark_report_hash_v1:");
            let cur_label = self.current_version.label();
            h.update((cur_label.len() as u64).to_le_bytes());
            h.update(cur_label.as_bytes());
            h.update((self.revisions.len() as u64).to_le_bytes());
            h.update((migration_count as u64).to_le_bytes());
            h.update((deprecations.len() as u64).to_le_bytes());
            for d in &deprecations {
                h.update((d.len() as u64).to_le_bytes());
                h.update(d.as_bytes());
            }
            hex::encode(h.finalize())
        };

        let report = VersioningReport {
            report_id: Uuid::now_v7().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            current_version: self.current_version.clone(),
            revisions_registered: self.revisions.len(),
            migration_guides_available: migration_count,
            deprecation_notices: deprecations,
            content_hash,
        };

        self.log(
            event_codes::BSV_REPORT_GENERATED,
            trace_id,
            serde_json::json!({
                "report_id": &report.report_id,
                "revisions": report.revisions_registered,
            }),
        );

        report
    }

    pub fn revisions(&self) -> &BTreeMap<SemVer, StandardRevision> {
        &self.revisions
    }

    pub fn current_version(&self) -> &SemVer {
        &self.current_version
    }

    pub fn audit_log(&self) -> &[BsvAuditRecord] {
        &self.audit_log
    }

    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn register_initial_revisions(&mut self) {
        let v1 = StandardRevision {
            version: SemVer::new(1, 0, 0),
            title: "Initial benchmark standard".to_string(),
            release_date: "2026-01-01".to_string(),
            tracks: vec![
                "compatibility_correctness".to_string(),
                "security_trust".to_string(),
                "performance_under_hardening".to_string(),
                "containment_revocation_latency".to_string(),
                "replay_determinism".to_string(),
                "adversarial_resilience".to_string(),
            ],
            track_count: 6,
            scoring_formula_version: "sf-v1.0".to_string(),
            harness_version: "h-v1.0".to_string(),
            deprecated: false,
            changelog: vec![],
        };

        let v1_1 = StandardRevision {
            version: SemVer::new(1, 1, 0),
            title: "Add trust co-metrics tracks".to_string(),
            release_date: "2026-02-01".to_string(),
            tracks: vec![
                "compatibility_correctness".to_string(),
                "security_trust".to_string(),
                "performance_under_hardening".to_string(),
                "containment_revocation_latency".to_string(),
                "replay_determinism".to_string(),
                "adversarial_resilience".to_string(),
                "trust_co_metrics".to_string(),
            ],
            track_count: 7,
            scoring_formula_version: "sf-v1.1".to_string(),
            harness_version: "h-v1.0".to_string(),
            deprecated: false,
            changelog: vec![ChangelogEntry {
                change_type: ChangeType::Feature,
                description: "Added trust_co_metrics track".to_string(),
                affected_tracks: vec!["trust_co_metrics".to_string()],
            }],
        };

        let v2 = StandardRevision {
            version: SemVer::new(2, 0, 0),
            title: "Restructured scoring with verifier toolkit".to_string(),
            release_date: "2026-02-15".to_string(),
            tracks: vec![
                "compatibility_correctness".to_string(),
                "security_posture".to_string(),
                "performance_under_hardening".to_string(),
                "containment_revocation_latency".to_string(),
                "replay_determinism".to_string(),
                "adversarial_resilience".to_string(),
                "trust_co_metrics".to_string(),
                "verifier_validation".to_string(),
            ],
            track_count: 8,
            scoring_formula_version: "sf-v2.0".to_string(),
            harness_version: "h-v2.0".to_string(),
            deprecated: false,
            changelog: vec![
                ChangelogEntry {
                    change_type: ChangeType::Breaking,
                    description: "Renamed security_trust to security_posture".to_string(),
                    affected_tracks: vec!["security_posture".to_string()],
                },
                ChangelogEntry {
                    change_type: ChangeType::Feature,
                    description: "Added verifier_validation track".to_string(),
                    affected_tracks: vec!["verifier_validation".to_string()],
                },
                ChangelogEntry {
                    change_type: ChangeType::Breaking,
                    description: "New scoring formula v2.0 with weighted sub-metrics".to_string(),
                    affected_tracks: vec![],
                },
            ],
        };

        self.revisions.insert(v1.version.clone(), v1);
        self.revisions.insert(v1_1.version.clone(), v1_1);
        self.revisions.insert(v2.version.clone(), v2);
        self.current_version = SemVer::new(2, 0, 0);
    }

    fn generate_migration_steps(
        &self,
        _from: &StandardRevision,
        to: &StandardRevision,
        breaking_changes: &[String],
    ) -> Vec<MigrationStep> {
        let mut steps = Vec::new();
        let mut step_num = 1;

        steps.push(MigrationStep {
            step_number: step_num,
            action: "backup".to_string(),
            description: "Back up existing benchmark results and configuration".to_string(),
            automated: true,
        });
        step_num = step_num.saturating_add(1);

        for change in breaking_changes {
            steps.push(MigrationStep {
                step_number: step_num,
                action: "migrate".to_string(),
                description: format!("Address breaking change: {change}"),
                automated: false,
            });
            step_num = step_num.saturating_add(1);
        }

        steps.push(MigrationStep {
            step_number: step_num,
            action: "update_config".to_string(),
            description: format!(
                "Update scoring formula to {} and harness to {}",
                to.scoring_formula_version, to.harness_version
            ),
            automated: true,
        });
        step_num = step_num.saturating_add(1);

        steps.push(MigrationStep {
            step_number: step_num,
            action: "validate".to_string(),
            description: "Run benchmark suite against new standard version".to_string(),
            automated: true,
        });

        steps
    }

    fn estimate_effort(&self, breaking: &[String], steps: &[MigrationStep]) -> MigrationEffort {
        let manual_steps = steps.iter().filter(|s| !s.automated).count();
        if breaking.is_empty() && manual_steps == 0 {
            MigrationEffort::Trivial
        } else if breaking.len() <= 1 && manual_steps <= 1 {
            MigrationEffort::Low
        } else if breaking.len() <= 3 {
            MigrationEffort::Medium
        } else {
            MigrationEffort::High
        }
    }

    fn count_migration_paths(&self) -> usize {
        let versions: Vec<&SemVer> = self.revisions.keys().collect();
        if versions.len() <= 1 {
            return 0;
        }
        // Adjacent pairs
        versions.len() - 1
    }

    fn log(&mut self, event_code: &str, trace_id: &str, details: serde_json::Value) {
        push_bounded(
            &mut self.audit_log,
            BsvAuditRecord {
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

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn custom_revision(version: SemVer) -> StandardRevision {
        StandardRevision {
            version,
            title: "Custom revision".to_string(),
            release_date: "2026-03-01".to_string(),
            tracks: vec!["track_a".to_string()],
            track_count: 1,
            scoring_formula_version: "sf-v3.0".to_string(),
            harness_version: "h-v3.0".to_string(),
            deprecated: false,
            changelog: vec![],
        }
    }

    fn assert_invalid_revision_rejected(mut revision: StandardRevision, reason: &str) {
        let mut engine = BenchmarkVersioning::new();
        let version = revision.version.clone();
        let original_len = engine.revisions().len();
        revision.deprecated = true;

        engine.register_revision(revision, "trace-invalid-revision");

        assert_eq!(engine.revisions().len(), original_len);
        assert!(!engine.revisions().contains_key(&version));
        assert!(engine.audit_log().iter().any(|record| record.event_code
            == event_codes::BSV_ERR_INVALID_VERSION
            && record.details["reason"].as_str() == Some(reason)));
        assert!(
            !engine
                .audit_log()
                .iter()
                .any(|record| record.event_code == event_codes::BSV_DEPRECATION_NOTICED),
            "invalid deprecated revisions must fail before deprecation audit records"
        );
    }

    // === SemVer ===

    #[test]
    fn semver_parse() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v, SemVer::new(1, 2, 3));
    }

    #[test]
    fn semver_parse_invalid() {
        assert!(SemVer::parse("1.2").is_none());
        assert!(SemVer::parse("abc").is_none());
    }

    #[test]
    fn semver_label() {
        assert_eq!(SemVer::new(2, 0, 0).label(), "2.0.0");
    }

    #[test]
    fn semver_ordering() {
        let v1 = SemVer::new(1, 0, 0);
        let v1_1 = SemVer::new(1, 1, 0);
        let v2 = SemVer::new(2, 0, 0);
        assert!(v1 < v1_1);
        assert!(v1_1 < v2);
    }

    #[test]
    fn semver_breaking_detection() {
        let v1 = SemVer::new(1, 0, 0);
        let v2 = SemVer::new(2, 0, 0);
        assert!(v2.is_breaking_from(&v1));
        assert!(!SemVer::new(1, 1, 0).is_breaking_from(&v1));
    }

    #[test]
    fn semver_feature_detection() {
        let v1 = SemVer::new(1, 0, 0);
        assert!(SemVer::new(1, 1, 0).is_feature_from(&v1));
        assert!(!SemVer::new(2, 0, 0).is_feature_from(&v1));
    }

    #[test]
    fn semver_patch_detection() {
        let v1 = SemVer::new(1, 0, 0);
        assert!(SemVer::new(1, 0, 1).is_patch_from(&v1));
        assert!(!SemVer::new(1, 1, 0).is_patch_from(&v1));
    }

    // === Initial revisions ===

    #[test]
    fn default_has_three_revisions() {
        let engine = BenchmarkVersioning::new();
        assert_eq!(engine.revisions().len(), 3);
    }

    #[test]
    fn current_version_is_latest() {
        let engine = BenchmarkVersioning::new();
        assert_eq!(*engine.current_version(), SemVer::new(2, 0, 0));
    }

    #[test]
    fn v1_has_six_tracks() {
        let engine = BenchmarkVersioning::new();
        let v1 = engine.revisions().get(&SemVer::new(1, 0, 0)).unwrap();
        assert_eq!(v1.track_count, 6);
    }

    // === Migration ===

    #[test]
    fn migration_v1_to_v1_1_backward_compatible() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(1, 1, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.compatibility, CompatibilityLevel::BackwardCompatible);
        assert!(guide.breaking_changes.is_empty());
        assert!(guide.rollback_possible);
    }

    #[test]
    fn migration_v1_to_v2_requires_migration() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.compatibility, CompatibilityLevel::RequiresMigration);
        assert!(!guide.breaking_changes.is_empty());
    }

    #[test]
    fn migration_same_version_fully_compatible() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(1, 0, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.compatibility, CompatibilityLevel::FullyCompatible);
    }

    #[test]
    fn migration_has_steps() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.migration_steps.len(), 5);
    }

    #[test]
    fn migration_has_content_hash() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.content_hash.len(), 64);
    }

    #[test]
    fn migration_is_deterministic() {
        let mut e1 = BenchmarkVersioning::new();
        let mut e2 = BenchmarkVersioning::new();
        let g1 = e1
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), "trace-det")
            .unwrap();
        let g2 = e2
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), "trace-det")
            .unwrap();
        assert_eq!(g1.content_hash, g2.content_hash);
    }

    // === Compatibility ===

    #[test]
    fn check_compatibility_returns_level() {
        let mut engine = BenchmarkVersioning::new();
        let level = engine
            .check_compatibility(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace())
            .unwrap();
        assert_eq!(level, CompatibilityLevel::RequiresMigration);
    }

    #[test]
    fn nonexistent_version_returns_none() {
        let mut engine = BenchmarkVersioning::new();
        let result =
            engine.compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(9, 9, 9), &make_trace());
        assert!(result.is_none());
    }

    // === Effort estimation ===

    #[test]
    fn patch_migration_trivial_effort() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(1, 1, 0), &make_trace())
            .unwrap();
        assert_eq!(guide.estimated_effort, MigrationEffort::Trivial);
    }

    #[test]
    fn breaking_migration_medium_or_higher() {
        let mut engine = BenchmarkVersioning::new();
        let guide = engine
            .compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace())
            .unwrap();
        assert!(matches!(
            guide.estimated_effort,
            MigrationEffort::Medium | MigrationEffort::High
        ));
    }

    // === Report ===

    #[test]
    fn report_has_current_version() {
        let mut engine = BenchmarkVersioning::new();
        let report = engine.generate_report(&make_trace());
        assert_eq!(report.current_version, SemVer::new(2, 0, 0));
    }

    #[test]
    fn report_has_content_hash() {
        let mut engine = BenchmarkVersioning::new();
        let report = engine.generate_report(&make_trace());
        assert_eq!(report.content_hash.len(), 64);
    }

    #[test]
    fn report_counts_revisions() {
        let mut engine = BenchmarkVersioning::new();
        let report = engine.generate_report(&make_trace());
        assert_eq!(report.revisions_registered, 3);
    }

    #[test]
    fn report_counts_migrations() {
        let mut engine = BenchmarkVersioning::new();
        let report = engine.generate_report(&make_trace());
        assert_eq!(report.migration_guides_available, 2);
    }

    // === Audit log ===

    #[test]
    fn migration_logged() {
        let mut engine = BenchmarkVersioning::new();
        let initial_log_count = engine.audit_log().len();
        engine.compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace());
        assert!(engine.audit_log().len() > initial_log_count);
    }

    #[test]
    fn breaking_change_logged() {
        let mut engine = BenchmarkVersioning::new();
        engine.compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(2, 0, 0), &make_trace());
        let has_breaking = engine
            .audit_log()
            .iter()
            .any(|r| r.event_code == event_codes::BSV_BREAKING_DETECTED);
        assert!(has_breaking);
    }

    #[test]
    fn export_jsonl() {
        let mut engine = BenchmarkVersioning::new();
        engine.generate_report(&make_trace());
        let jsonl = engine.export_audit_log_jsonl().unwrap();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert!(parsed["event_code"].is_string());
    }

    // === Register custom revision ===

    #[test]
    fn register_custom_revision() {
        let mut engine = BenchmarkVersioning::new();
        let v3 = custom_revision(SemVer::new(3, 0, 0));
        engine.register_revision(v3, &make_trace());
        assert_eq!(engine.revisions().len(), 4);
    }

    #[test]
    fn register_newer_revision_updates_current_version() {
        let mut engine = BenchmarkVersioning::new();
        engine.register_revision(custom_revision(SemVer::new(3, 0, 0)), &make_trace());

        assert_eq!(*engine.current_version(), SemVer::new(3, 0, 0));
    }

    #[test]
    fn register_older_revision_does_not_downgrade_current_version() {
        let mut engine = BenchmarkVersioning::new();
        engine.register_revision(custom_revision(SemVer::new(1, 0, 1)), &make_trace());

        assert_eq!(*engine.current_version(), SemVer::new(2, 0, 0));
    }

    #[test]
    fn register_revision_rejects_whitespace_title_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 1, 0));
        revision.title = " \n\t ".to_string();

        assert_invalid_revision_rejected(revision, "empty title");
    }

    #[test]
    fn register_revision_rejects_empty_release_date_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 2, 0));
        revision.release_date.clear();

        assert_invalid_revision_rejected(revision, "empty release_date");
    }

    #[test]
    fn register_revision_rejects_empty_tracks_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 3, 0));
        revision.tracks.clear();
        revision.track_count = 0;

        assert_invalid_revision_rejected(revision, "empty tracks");
    }

    #[test]
    fn register_revision_rejects_blank_track_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 4, 0));
        revision.tracks = vec![" \t ".to_string()];
        revision.track_count = 1;

        assert_invalid_revision_rejected(revision, "blank track");
    }

    #[test]
    fn register_revision_rejects_track_count_mismatch_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 5, 0));
        revision.track_count = revision.tracks.len().saturating_add(1);

        assert_invalid_revision_rejected(revision, "track_count mismatch");
    }

    #[test]
    fn register_revision_rejects_empty_harness_version_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 6, 0));
        revision.harness_version = " \n\t ".to_string();

        assert_invalid_revision_rejected(revision, "empty harness_version");
    }

    #[test]
    fn register_revision_rejects_blank_changelog_description_without_insert() {
        let mut revision = custom_revision(SemVer::new(3, 7, 0));
        revision.changelog = vec![ChangelogEntry {
            change_type: ChangeType::Feature,
            description: " \t ".to_string(),
            affected_tracks: vec!["track_a".to_string()],
        }];

        assert_invalid_revision_rejected(revision, "empty changelog description");
    }

    #[test]
    fn push_bounded_zero_capacity_discards_existing_items() {
        let mut items = vec!["old-guide", "old-audit"];

        push_bounded(&mut items, "new-guide", 0);

        assert!(
            items.is_empty(),
            "zero-capacity bounded buffers must not retain stale versioning records"
        );
    }

    #[test]
    fn semver_parse_rejects_empty_components_and_extra_segments() {
        assert!(SemVer::parse("").is_none());
        assert!(SemVer::parse("1..0").is_none());
        assert!(SemVer::parse(".1.0").is_none());
        assert!(SemVer::parse("1.0.0.0").is_none());
    }

    #[test]
    fn semver_parse_rejects_non_numeric_and_overflowing_components() {
        assert!(SemVer::parse("1.two.3").is_none());
        assert!(SemVer::parse("1.0.-1").is_none());
        assert!(SemVer::parse("4294967296.0.0").is_none());
    }

    #[test]
    fn semver_parse_rejects_leading_zero_components() {
        assert!(SemVer::parse("01.2.3").is_none());
        assert!(SemVer::parse("1.02.3").is_none());
        assert!(SemVer::parse("1.2.03").is_none());
    }

    #[test]
    fn semver_parse_rejects_signs_and_whitespace() {
        assert!(SemVer::parse("+1.2.3").is_none());
        assert!(SemVer::parse("1.+2.3").is_none());
        assert!(SemVer::parse("1.2.+3").is_none());
        assert!(SemVer::parse("1.2.3 ").is_none());
    }

    #[test]
    fn missing_from_version_returns_none_without_audit() {
        let mut engine = BenchmarkVersioning::new();
        let audit_count_before = engine.audit_log().len();

        let guide =
            engine.compute_migration(&SemVer::new(9, 9, 9), &SemVer::new(2, 0, 0), &make_trace());

        assert!(guide.is_none());
        assert_eq!(
            engine.audit_log().len(),
            audit_count_before,
            "missing source versions must fail before migration audit records"
        );
    }

    #[test]
    fn missing_to_version_returns_none_without_migration_audit() {
        let mut engine = BenchmarkVersioning::new();
        let audit_count_before = engine.audit_log().len();

        let guide =
            engine.compute_migration(&SemVer::new(1, 0, 0), &SemVer::new(9, 9, 9), &make_trace());

        assert!(guide.is_none());
        assert_eq!(
            engine.audit_log().len(),
            audit_count_before,
            "missing target versions must fail before migration audit records"
        );
    }

    #[test]
    fn missing_compatibility_target_does_not_log_compat_checked() {
        let mut engine = BenchmarkVersioning::new();

        let level =
            engine.check_compatibility(&SemVer::new(1, 0, 0), &SemVer::new(4, 0, 0), &make_trace());

        assert!(level.is_none());
        assert!(
            engine
                .audit_log()
                .iter()
                .all(|record| record.event_code != event_codes::BSV_COMPAT_CHECKED),
            "missing compatibility target must not emit compatibility-checked audit records"
        );
    }

    #[test]
    fn empty_engine_report_has_no_migration_paths() {
        let mut engine = BenchmarkVersioning {
            revisions: BTreeMap::new(),
            current_version: SemVer::new(0, 0, 0),
            audit_log: Vec::new(),
        };

        let report = engine.generate_report(&make_trace());

        assert_eq!(report.revisions_registered, 0);
        assert_eq!(report.migration_guides_available, 0);
        assert!(report.deprecation_notices.is_empty());
        assert_eq!(report.current_version, SemVer::new(0, 0, 0));
    }

    #[test]
    fn empty_engine_audit_export_is_empty_before_report_generation() {
        let engine = BenchmarkVersioning {
            revisions: BTreeMap::new(),
            current_version: SemVer::new(0, 0, 0),
            audit_log: Vec::new(),
        };

        assert_eq!(engine.export_audit_log_jsonl().unwrap(), "");
    }

    #[test]
    fn semver_deserialize_rejects_string_component() {
        let raw = serde_json::json!({
            "major": "1",
            "minor": 0_u32,
            "patch": 0_u32,
        });

        let result: Result<SemVer, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "semver components must remain numeric in serialized artifacts"
        );
    }

    #[test]
    fn change_type_deserialize_rejects_camel_case_label() {
        let result: Result<ChangeType, _> = serde_json::from_str("\"BreakingChange\"");

        assert!(
            result.is_err(),
            "change-type labels must use the canonical snake_case contract"
        );
    }

    #[test]
    fn compatibility_level_deserialize_rejects_display_case_label() {
        let result: Result<CompatibilityLevel, _> = serde_json::from_str("\"RequiresMigration\"");

        assert!(
            result.is_err(),
            "compatibility labels must not accept Rust display/debug casing"
        );
    }

    #[test]
    fn migration_effort_deserialize_rejects_unknown_label() {
        let result: Result<MigrationEffort, _> = serde_json::from_str("\"extreme\"");

        assert!(
            result.is_err(),
            "unknown migration effort labels must fail closed"
        );
    }

    #[test]
    fn standard_revision_deserialize_rejects_missing_changelog() {
        let raw = serde_json::json!({
            "version": {"major": 1_u32, "minor": 2_u32, "patch": 0_u32},
            "title": "Incomplete revision",
            "release_date": "2026-04-01",
            "tracks": ["runtime"],
            "track_count": 1_usize,
            "scoring_formula_version": "sf-v1",
            "harness_version": "h-v1",
            "deprecated": false,
        });

        let result: Result<StandardRevision, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "standard revisions must carry explicit changelog evidence"
        );
    }

    #[test]
    fn migration_step_deserialize_rejects_string_step_number() {
        let raw = serde_json::json!({
            "step_number": "1",
            "action": "update scoring formula",
            "description": "Apply the new scoring formula before publishing artifacts.",
            "automated": true,
        });

        let result: Result<MigrationStep, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "migration step numbers must remain numeric for deterministic ordering"
        );
    }

    #[test]
    fn migration_guide_deserialize_rejects_missing_content_hash() {
        let raw = serde_json::json!({
            "from_version": {"major": 1_u32, "minor": 0_u32, "patch": 0_u32},
            "to_version": {"major": 2_u32, "minor": 0_u32, "patch": 0_u32},
            "compatibility": "requires_migration",
            "breaking_changes": ["Changed scoring denominator"],
            "migration_steps": [{
                "step_number": 1_usize,
                "action": "recompute baselines",
                "description": "Regenerate benchmark baselines under the new standard.",
                "automated": false,
            }],
            "rollback_possible": true,
            "estimated_effort": "medium",
        });

        let result: Result<MigrationGuide, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "migration guides must include an integrity hash"
        );
    }

    #[test]
    fn versioning_report_deserialize_rejects_string_revision_count() {
        let raw = serde_json::json!({
            "report_id": "bsv-report-1",
            "timestamp": "2026-04-01T00:00:00Z",
            "current_version": {"major": 2_u32, "minor": 0_u32, "patch": 0_u32},
            "revisions_registered": "3",
            "migration_guides_available": 2_usize,
            "deprecation_notices": [],
            "content_hash": "0123456789abcdef",
        });

        let result: Result<VersioningReport, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "versioning report counts must not accept stringly typed values"
        );
    }

    #[test]
    fn bsv_audit_record_deserialize_rejects_missing_details() {
        let raw = serde_json::json!({
            "record_id": "audit-1",
            "event_code": event_codes::BSV_REPORT_GENERATED,
            "timestamp": "2026-04-01T00:00:00Z",
            "trace_id": make_trace(),
        });

        let result: Result<BsvAuditRecord, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "audit records must include details for operator traceability"
        );
    }
}
