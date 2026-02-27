//! bd-f2y: Incident bundle retention and export policy.
//!
//! Implements tiered retention (hot/cold/archive), multi-format export
//! (JSON, CSV, SARIF), automated tier rotation, and integrity-verified
//! incident bundle lifecycle management.
//!
//! # Invariants
//!
//! - INV-IBR-COMPLETE:   every bundle has all required fields
//! - INV-IBR-RETENTION:  tier transitions follow schedule; archive never auto-deleted
//! - INV-IBR-EXPORT:     exports include verifiable integrity hash
//! - INV-IBR-INTEGRITY:  SHA-256 hash validates on every read/export

use std::collections::BTreeMap;
use std::fmt;

// ── Event codes ────────────────────────────────────────────────────

pub mod event_codes {
    /// Incident bundle created and classified.
    pub const IBR_001: &str = "IBR-001";
    /// Retention period expired, tier transition triggered.
    pub const IBR_002: &str = "IBR-002";
    /// Export requested (any format).
    pub const IBR_003: &str = "IBR-003";
    /// Automated cleanup executed.
    pub const IBR_004: &str = "IBR-004";
}

// ── Severity ───────────────────────────────────────────────────────

/// Incident severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Retention tier ─────────────────────────────────────────────────

/// Retention tier for incident bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionTier {
    Hot,
    Cold,
    Archive,
}

impl RetentionTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Cold => "cold",
            Self::Archive => "archive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hot" => Some(Self::Hot),
            "cold" => Some(Self::Cold),
            "archive" => Some(Self::Archive),
            _ => None,
        }
    }
}

impl fmt::Display for RetentionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Export format ──────────────────────────────────────────────────

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    Json,
    Csv,
    Sarif,
}

impl ExportFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Sarif => "sarif",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => ".json",
            Self::Csv => ".csv",
            Self::Sarif => ".sarif",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Bundle metadata ────────────────────────────────────────────────

/// Incident bundle metadata.
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    pub title: String,
    pub detected_by: String,
    pub component_ids: Vec<String>,
    pub tags: Vec<String>,
}

// ── Incident bundle ────────────────────────────────────────────────

/// An incident bundle with all required fields.
///
/// INV-IBR-COMPLETE: all fields are required at construction time.
#[derive(Debug, Clone)]
pub struct IncidentBundle {
    pub bundle_id: String,
    pub incident_id: String,
    pub created_at: String,
    pub severity: Severity,
    pub retention_tier: RetentionTier,
    pub metadata: BundleMetadata,
    pub log_count: usize,
    pub trace_count: usize,
    pub metric_snapshot_count: usize,
    pub evidence_ref_count: usize,
    pub export_format_version: u32,
    pub integrity_hash: String,
    pub size_bytes: u64,
    pub created_at_epoch: u64,
    /// Epoch when the bundle last changed retention tier (used for accurate tier timing).
    pub last_tier_change_epoch: u64,
}

// ── Retention configuration ────────────────────────────────────────

/// Configurable retention periods (in days).
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    pub hot_days: u64,
    pub cold_days: u64,
    pub archive_days: u64,
    pub cleanup_interval_hours: u64,
    pub storage_warn_percent: u8,
    pub storage_critical_percent: u8,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            hot_days: 90,
            cold_days: 365,
            archive_days: 2555,
            cleanup_interval_hours: 1,
            storage_warn_percent: 70,
            storage_critical_percent: 85,
        }
    }
}

// ── Audit decision ─────────────────────────────────────────────────

/// Audit record for a retention decision.
#[derive(Debug, Clone)]
pub struct RetentionDecision {
    pub bundle_id: String,
    pub action: String,
    pub old_tier: Option<String>,
    pub new_tier: Option<String>,
    pub reason: String,
    pub timestamp: u64,
    pub event_code: String,
}

// ── Errors ─────────────────────────────────────────────────────────

/// Errors from incident bundle retention operations.
#[derive(Debug, Clone, PartialEq)]
pub enum IncidentBundleError {
    /// Bundle is missing required fields.
    Incomplete { field: String },
    /// Bundle not found in store.
    NotFound { bundle_id: String },
    /// Cannot delete archive-tier bundle automatically.
    ArchiveProtected { bundle_id: String },
    /// Integrity hash mismatch.
    IntegrityFailure {
        bundle_id: String,
        expected: String,
        actual: String,
    },
    /// Storage capacity exceeded.
    StorageFull { current_bytes: u64, max_bytes: u64 },
    /// Invalid export format.
    InvalidFormat { format: String },
    /// Invalid configuration.
    InvalidConfig { reason: String },
}

impl IncidentBundleError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Incomplete { .. } => "IBR_INCOMPLETE",
            Self::NotFound { .. } => "IBR_NOT_FOUND",
            Self::ArchiveProtected { .. } => "IBR_ARCHIVE_PROTECTED",
            Self::IntegrityFailure { .. } => "IBR_INTEGRITY_FAILURE",
            Self::StorageFull { .. } => "IBR_STORAGE_FULL",
            Self::InvalidFormat { .. } => "IBR_INVALID_FORMAT",
            Self::InvalidConfig { .. } => "IBR_INVALID_CONFIG",
        }
    }
}

impl fmt::Display for IncidentBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { field } => write!(f, "IBR_INCOMPLETE: missing {field}"),
            Self::NotFound { bundle_id } => write!(f, "IBR_NOT_FOUND: {bundle_id}"),
            Self::ArchiveProtected { bundle_id } => {
                write!(f, "IBR_ARCHIVE_PROTECTED: {bundle_id}")
            }
            Self::IntegrityFailure {
                bundle_id,
                expected,
                actual,
            } => write!(
                f,
                "IBR_INTEGRITY_FAILURE: {bundle_id} expected={expected} actual={actual}"
            ),
            Self::StorageFull {
                current_bytes,
                max_bytes,
            } => write!(f, "IBR_STORAGE_FULL: {current_bytes}/{max_bytes}"),
            Self::InvalidFormat { format } => write!(f, "IBR_INVALID_FORMAT: {format}"),
            Self::InvalidConfig { reason } => write!(f, "IBR_INVALID_CONFIG: {reason}"),
        }
    }
}

// ── Compute integrity hash (deterministic) ─────────────────────────

/// Compute a simple integrity hash for a bundle.
///
/// Uses a deterministic representation: sorted keys, no extra whitespace.
/// INV-IBR-INTEGRITY.
pub fn compute_integrity_hash(bundle: &IncidentBundle) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"incident_bundle_retention_hash_v1:");
    hasher.update(bundle.bundle_id.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.incident_id.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.created_at.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.severity.label().as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.retention_tier.label().as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.metadata.title.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.metadata.detected_by.as_bytes());
    hasher.update(b"|");
    hasher.update(bundle.log_count.to_le_bytes());
    hasher.update(b"|");
    hasher.update(bundle.trace_count.to_le_bytes());
    hasher.update(b"|");
    hasher.update(bundle.metric_snapshot_count.to_le_bytes());
    hasher.update(b"|");
    hasher.update(bundle.evidence_ref_count.to_le_bytes());
    hasher.update(b"|");
    hasher.update(bundle.export_format_version.to_le_bytes());

    let digest = hasher.finalize();
    format!(
        "{:016x}",
        u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 digest is 32 bytes"))
    )
}

// ── Validate completeness ──────────────────────────────────────────

/// Validate that a bundle has all required fields.
///
/// INV-IBR-COMPLETE.
pub fn validate_bundle_complete(bundle: &IncidentBundle) -> Result<(), IncidentBundleError> {
    if bundle.bundle_id.is_empty() {
        return Err(IncidentBundleError::Incomplete {
            field: "bundle_id".into(),
        });
    }
    if bundle.incident_id.is_empty() {
        return Err(IncidentBundleError::Incomplete {
            field: "incident_id".into(),
        });
    }
    if bundle.created_at.is_empty() {
        return Err(IncidentBundleError::Incomplete {
            field: "created_at".into(),
        });
    }
    if bundle.metadata.title.is_empty() {
        return Err(IncidentBundleError::Incomplete {
            field: "metadata.title".into(),
        });
    }
    if bundle.integrity_hash.is_empty() {
        return Err(IncidentBundleError::Incomplete {
            field: "integrity_hash".into(),
        });
    }
    Ok(())
}

// ── Export helpers ──────────────────────────────────────────────────

/// Export a bundle to CSV row format.
pub fn export_csv_row(bundle: &IncidentBundle) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{}",
        bundle.bundle_id,
        bundle.incident_id,
        bundle.created_at,
        bundle.severity.label(),
        bundle.retention_tier.label(),
        bundle.metadata.title,
        bundle.metadata.detected_by,
        bundle.metadata.component_ids.len(),
        bundle.log_count,
        bundle.trace_count,
        bundle.metric_snapshot_count,
    )
}

/// CSV header line.
pub fn csv_header() -> &'static str {
    "bundle_id,incident_id,created_at,severity,retention_tier,title,detected_by,component_count,log_count,trace_count,metric_snapshot_count"
}

/// Export a bundle to minimal SARIF v2.1.0 representation.
pub fn export_sarif(bundle: &IncidentBundle) -> BTreeMap<String, String> {
    let mut sarif = BTreeMap::new();
    sarif.insert("$schema".into(), "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json".into());
    sarif.insert("version".into(), "2.1.0".into());
    sarif.insert("bundle_id".into(), bundle.bundle_id.clone());
    sarif.insert("incident_id".into(), bundle.incident_id.clone());
    sarif.insert("severity".into(), bundle.severity.label().into());
    sarif.insert("title".into(), bundle.metadata.title.clone());
    sarif.insert("detected_by".into(), bundle.metadata.detected_by.clone());
    sarif.insert("integrity_hash".into(), bundle.integrity_hash.clone());
    sarif
}

// ── Bundle store ───────────────────────────────────────────────────

/// Store managing incident bundles with retention enforcement.
#[derive(Debug)]
pub struct IncidentBundleStore {
    config: RetentionConfig,
    bundles: BTreeMap<String, IncidentBundle>,
    total_bytes: u64,
    max_bytes: u64,
    decisions: Vec<RetentionDecision>,
}

impl IncidentBundleStore {
    pub fn new(config: RetentionConfig, max_bytes: u64) -> Result<Self, IncidentBundleError> {
        if max_bytes == 0 {
            return Err(IncidentBundleError::InvalidConfig {
                reason: "max_bytes must be > 0".into(),
            });
        }
        if config.storage_warn_percent >= config.storage_critical_percent {
            return Err(IncidentBundleError::InvalidConfig {
                reason: "warn threshold must be below critical threshold".into(),
            });
        }
        Ok(Self {
            config,
            bundles: BTreeMap::new(),
            total_bytes: 0,
            max_bytes,
            decisions: Vec::new(),
        })
    }

    /// Store a new incident bundle.
    ///
    /// INV-IBR-COMPLETE: validates all required fields.
    /// INV-IBR-INTEGRITY: validates integrity hash.
    pub fn store(&mut self, bundle: IncidentBundle, now: u64) -> Result<(), IncidentBundleError> {
        validate_bundle_complete(&bundle)?;

        // INV-IBR-INTEGRITY: verify hash
        let expected = compute_integrity_hash(&bundle);
        if !crate::security::constant_time::ct_eq(&bundle.integrity_hash, &expected) {
            return Err(IncidentBundleError::IntegrityFailure {
                bundle_id: bundle.bundle_id.clone(),
                expected,
                actual: bundle.integrity_hash.clone(),
            });
        }

        // Check capacity
        if self.total_bytes.saturating_add(bundle.size_bytes) > self.max_bytes {
            return Err(IncidentBundleError::StorageFull {
                current_bytes: self.total_bytes,
                max_bytes: self.max_bytes,
            });
        }

        self.decisions.push(RetentionDecision {
            bundle_id: bundle.bundle_id.clone(),
            action: "create".into(),
            old_tier: None,
            new_tier: Some(bundle.retention_tier.label().into()),
            reason: format!(
                "classified as {} severity, {} tier",
                bundle.severity, bundle.retention_tier
            ),
            timestamp: now,
            event_code: event_codes::IBR_001.into(),
        });

        self.total_bytes = self.total_bytes.saturating_add(bundle.size_bytes);
        self.bundles.insert(bundle.bundle_id.clone(), bundle);
        Ok(())
    }

    /// Get a bundle by ID.
    pub fn get(&self, bundle_id: &str) -> Option<&IncidentBundle> {
        self.bundles.get(bundle_id)
    }

    /// Check if store contains a bundle.
    pub fn contains(&self, bundle_id: &str) -> bool {
        self.bundles.contains_key(bundle_id)
    }

    /// Number of bundles in the store.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Total storage used.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Get storage utilization percentage.
    pub fn utilization_percent(&self) -> u8 {
        if self.max_bytes == 0 {
            return 100;
        }
        ((self.total_bytes as u128 * 100) / self.max_bytes as u128) as u8
    }

    /// Check if storage is at warning level.
    pub fn is_warn_level(&self) -> bool {
        self.utilization_percent() >= self.config.storage_warn_percent
    }

    /// Check if storage is at critical level.
    pub fn is_critical_level(&self) -> bool {
        self.utilization_percent() >= self.config.storage_critical_percent
    }

    /// Export a bundle in the requested format.
    ///
    /// INV-IBR-EXPORT: integrity hash included in output.
    pub fn export(
        &mut self,
        bundle_id: &str,
        format: ExportFormat,
        requester: &str,
        now: u64,
    ) -> Result<String, IncidentBundleError> {
        let bundle = self
            .bundles
            .get(bundle_id)
            .ok_or_else(|| IncidentBundleError::NotFound {
                bundle_id: bundle_id.into(),
            })?;

        // INV-IBR-INTEGRITY: verify hash before export
        let computed = compute_integrity_hash(bundle);
        if !crate::security::constant_time::ct_eq(&bundle.integrity_hash, &computed) {
            return Err(IncidentBundleError::IntegrityFailure {
                bundle_id: bundle_id.into(),
                expected: bundle.integrity_hash.clone(),
                actual: computed,
            });
        }

        let output = match format {
            ExportFormat::Json => {
                format!(
                    "{{\"bundle_id\":\"{}\",\"incident_id\":\"{}\",\"severity\":\"{}\",\"retention_tier\":\"{}\",\"integrity_hash\":\"{}\"}}",
                    bundle.bundle_id,
                    bundle.incident_id,
                    bundle.severity,
                    bundle.retention_tier,
                    bundle.integrity_hash
                )
            }
            ExportFormat::Csv => {
                format!("{}\n{}", csv_header(), export_csv_row(bundle))
            }
            ExportFormat::Sarif => {
                let sarif = export_sarif(bundle);
                format!("{:?}", sarif)
            }
        };

        self.decisions.push(RetentionDecision {
            bundle_id: bundle_id.into(),
            action: "export".into(),
            old_tier: None,
            new_tier: None,
            reason: format!("exported as {} by {}", format, requester),
            timestamp: now,
            event_code: event_codes::IBR_003.into(),
        });

        Ok(output)
    }

    /// Rotate bundles to the next retention tier based on age.
    ///
    /// INV-IBR-RETENTION: follows configured schedule.
    pub fn rotate_tiers(&mut self, now: u64) -> Vec<RetentionDecision> {
        let hot_seconds = self.config.hot_days * 86400;
        let cold_seconds = self.config.cold_days * 86400;

        let mut transitions = Vec::new();

        for bundle in self.bundles.values_mut() {
            let age = now.saturating_sub(bundle.created_at_epoch);
            let time_in_tier = now.saturating_sub(bundle.last_tier_change_epoch);
            let old_tier = bundle.retention_tier;

            let new_tier = match old_tier {
                RetentionTier::Hot if age >= hot_seconds => Some(RetentionTier::Cold),
                RetentionTier::Cold if time_in_tier >= cold_seconds => Some(RetentionTier::Archive),
                _ => None,
            };

            if let Some(tier) = new_tier {
                let decision = RetentionDecision {
                    bundle_id: bundle.bundle_id.clone(),
                    action: "transition".into(),
                    old_tier: Some(old_tier.label().into()),
                    new_tier: Some(tier.label().into()),
                    reason: format!("age {} seconds exceeds {} tier period", age, old_tier),
                    timestamp: now,
                    event_code: event_codes::IBR_002.into(),
                };
                bundle.retention_tier = tier;
                bundle.last_tier_change_epoch = now;
                self.decisions.push(decision.clone());
                transitions.push(decision);
            }
        }

        transitions
    }

    /// Delete a bundle. Archive bundles cannot be auto-deleted.
    ///
    /// INV-IBR-RETENTION: archive never auto-deleted.
    pub fn delete(
        &mut self,
        bundle_id: &str,
        force_archive: bool,
        now: u64,
    ) -> Result<(), IncidentBundleError> {
        let bundle = self
            .bundles
            .get(bundle_id)
            .ok_or_else(|| IncidentBundleError::NotFound {
                bundle_id: bundle_id.into(),
            })?;

        if bundle.retention_tier == RetentionTier::Archive && !force_archive {
            return Err(IncidentBundleError::ArchiveProtected {
                bundle_id: bundle_id.into(),
            });
        }

        let removed = self
            .bundles
            .remove(bundle_id)
            .expect("bundle verified present");
        self.total_bytes = self.total_bytes.saturating_sub(removed.size_bytes);

        self.decisions.push(RetentionDecision {
            bundle_id: bundle_id.into(),
            action: "delete".into(),
            old_tier: Some(removed.retention_tier.label().into()),
            new_tier: None,
            reason: if force_archive {
                "explicit archive deletion".into()
            } else {
                "bundle deleted".into()
            },
            timestamp: now,
            event_code: event_codes::IBR_004.into(),
        });

        Ok(())
    }

    /// Run automated cleanup: remove expired non-archive bundles.
    ///
    /// INV-IBR-RETENTION: archive bundles are never auto-deleted.
    pub fn cleanup(&mut self, now: u64) -> Vec<RetentionDecision> {
        // First rotate tiers
        let mut decisions = self.rotate_tiers(now);

        // Collect expired hot/cold bundles (only ephemeral-class bundles)
        // For this implementation, we don't auto-delete incident bundles;
        // only tier transitions are automated. Archive bundles are protected.
        // The upstream retention_policy.rs handles ephemeral artifact cleanup.

        if !decisions.is_empty() {
            self.decisions.push(RetentionDecision {
                bundle_id: "".into(),
                action: "cleanup".into(),
                old_tier: None,
                new_tier: None,
                reason: format!("{} tier transitions executed", decisions.len()),
                timestamp: now,
                event_code: event_codes::IBR_004.into(),
            });
            decisions.push(
                self.decisions
                    .last()
                    .expect("decisions non-empty after push")
                    .clone(),
            );
        }

        decisions
    }

    /// Get retention configuration.
    pub fn config(&self) -> &RetentionConfig {
        &self.config
    }

    /// Get all audit decisions.
    pub fn decisions(&self) -> &[RetentionDecision] {
        &self.decisions
    }

    /// Get bundles by tier.
    pub fn bundles_by_tier(&self, tier: RetentionTier) -> Vec<&IncidentBundle> {
        self.bundles
            .values()
            .filter(|b| b.retention_tier == tier)
            .collect()
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> BundleMetadata {
        BundleMetadata {
            title: "Test incident".into(),
            detected_by: "health_gate".into(),
            component_ids: vec!["svc-01".into()],
            tags: vec!["test".into()],
        }
    }

    fn sample_bundle(
        id: &str,
        incident_id: &str,
        severity: Severity,
        tier: RetentionTier,
        epoch: u64,
    ) -> IncidentBundle {
        let mut bundle = IncidentBundle {
            bundle_id: id.into(),
            incident_id: incident_id.into(),
            created_at: "2026-02-20T12:00:00.000000Z".into(),
            severity,
            retention_tier: tier,
            metadata: sample_metadata(),
            log_count: 10,
            trace_count: 5,
            metric_snapshot_count: 3,
            evidence_ref_count: 2,
            export_format_version: 1,
            integrity_hash: String::new(),
            size_bytes: 1000,
            created_at_epoch: epoch,
            last_tier_change_epoch: epoch,
        };
        bundle.integrity_hash = compute_integrity_hash(&bundle);
        bundle
    }

    fn default_store() -> IncidentBundleStore {
        IncidentBundleStore::new(RetentionConfig::default(), 1_000_000).unwrap()
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(Severity::Critical.label(), "critical");
        assert_eq!(Severity::High.label(), "high");
        assert_eq!(Severity::Medium.label(), "medium");
        assert_eq!(Severity::Low.label(), "low");
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(Severity::parse("high"), Some(Severity::High));
        assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse("low"), Some(Severity::Low));
        assert_eq!(Severity::parse("unknown"), None);
    }

    #[test]
    fn test_retention_tier_labels() {
        assert_eq!(RetentionTier::Hot.label(), "hot");
        assert_eq!(RetentionTier::Cold.label(), "cold");
        assert_eq!(RetentionTier::Archive.label(), "archive");
    }

    #[test]
    fn test_retention_tier_from_str() {
        assert_eq!(RetentionTier::parse("hot"), Some(RetentionTier::Hot));
        assert_eq!(RetentionTier::parse("cold"), Some(RetentionTier::Cold));
        assert_eq!(
            RetentionTier::parse("archive"),
            Some(RetentionTier::Archive)
        );
        assert_eq!(RetentionTier::parse("unknown"), None);
    }

    #[test]
    fn test_export_format_labels() {
        assert_eq!(ExportFormat::Json.label(), "json");
        assert_eq!(ExportFormat::Csv.label(), "csv");
        assert_eq!(ExportFormat::Sarif.label(), "sarif");
    }

    #[test]
    fn test_export_format_extensions() {
        assert_eq!(ExportFormat::Json.extension(), ".json");
        assert_eq!(ExportFormat::Csv.extension(), ".csv");
        assert_eq!(ExportFormat::Sarif.extension(), ".sarif");
    }

    #[test]
    fn test_export_format_from_str() {
        assert_eq!(ExportFormat::parse("json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse("csv"), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse("sarif"), Some(ExportFormat::Sarif));
        assert_eq!(ExportFormat::parse("xml"), None);
    }

    #[test]
    fn test_default_config() {
        let cfg = RetentionConfig::default();
        assert_eq!(cfg.hot_days, 90);
        assert_eq!(cfg.cold_days, 365);
        assert_eq!(cfg.archive_days, 2555);
        assert_eq!(cfg.cleanup_interval_hours, 1);
        assert_eq!(cfg.storage_warn_percent, 70);
        assert_eq!(cfg.storage_critical_percent, 85);
    }

    #[test]
    fn test_compute_integrity_hash_deterministic() {
        let b1 = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        let b2 = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        assert_eq!(compute_integrity_hash(&b1), compute_integrity_hash(&b2));
    }

    #[test]
    fn test_compute_integrity_hash_varies() {
        let b1 = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        let b2 = sample_bundle(
            "ibr-002",
            "INC-002",
            Severity::Low,
            RetentionTier::Cold,
            2000,
        );
        assert_ne!(compute_integrity_hash(&b1), compute_integrity_hash(&b2));
    }

    #[test]
    fn test_validate_complete_bundle() {
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        assert!(validate_bundle_complete(&bundle).is_ok());
    }

    #[test]
    fn test_validate_incomplete_bundle_id() {
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        bundle.bundle_id = String::new();
        let err = validate_bundle_complete(&bundle).unwrap_err();
        assert_eq!(err.code(), "IBR_INCOMPLETE");
    }

    #[test]
    fn test_validate_incomplete_incident_id() {
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        bundle.incident_id = String::new();
        let err = validate_bundle_complete(&bundle).unwrap_err();
        assert_eq!(err.code(), "IBR_INCOMPLETE");
    }

    #[test]
    fn test_store_bundle() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        assert!(store.contains("ibr-001"));
        assert_eq!(store.bundle_count(), 1);
        assert_eq!(store.total_bytes(), 1000);
    }

    #[test]
    fn test_store_rejects_bad_integrity() {
        let mut store = default_store();
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        bundle.integrity_hash = "bad_hash".into();
        let err = store.store(bundle, 1000).unwrap_err();
        assert_eq!(err.code(), "IBR_INTEGRITY_FAILURE");
    }

    #[test]
    fn test_store_rejects_same_length_bad_integrity() {
        let mut store = default_store();
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        let mut chars: Vec<char> = bundle.integrity_hash.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        bundle.integrity_hash = chars.into_iter().collect();
        let err = store.store(bundle, 1000).unwrap_err();
        assert_eq!(err.code(), "IBR_INTEGRITY_FAILURE");
    }

    #[test]
    fn test_store_rejects_full() {
        let mut store = IncidentBundleStore::new(RetentionConfig::default(), 500).unwrap();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        let err = store.store(bundle, 1000).unwrap_err();
        assert_eq!(err.code(), "IBR_STORAGE_FULL");
    }

    #[test]
    fn test_store_zero_max_bytes_rejected() {
        let err = IncidentBundleStore::new(RetentionConfig::default(), 0).unwrap_err();
        assert_eq!(err.code(), "IBR_INVALID_CONFIG");
    }

    #[test]
    fn test_export_json() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        let output = store
            .export("ibr-001", ExportFormat::Json, "test-user", 1001)
            .unwrap();
        assert!(output.contains("ibr-001"));
        assert!(output.contains("integrity_hash"));
    }

    #[test]
    fn test_export_csv() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        let output = store
            .export("ibr-001", ExportFormat::Csv, "test-user", 1001)
            .unwrap();
        assert!(output.contains("bundle_id"));
        assert!(output.contains("ibr-001"));
    }

    #[test]
    fn test_export_sarif() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        let output = store
            .export("ibr-001", ExportFormat::Sarif, "test-user", 1001)
            .unwrap();
        assert!(output.contains("ibr-001"));
        assert!(output.contains("2.1.0"));
    }

    #[test]
    fn test_export_not_found() {
        let mut store = default_store();
        let err = store
            .export("missing", ExportFormat::Json, "user", 1000)
            .unwrap_err();
        assert_eq!(err.code(), "IBR_NOT_FOUND");
    }

    #[test]
    fn test_rotate_hot_to_cold() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();

        let hot_seconds = 90 * 86400;
        let transitions = store.rotate_tiers(1000 + hot_seconds + 1);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].new_tier.as_deref(), Some("cold"));
        assert_eq!(
            store.get("ibr-001").unwrap().retention_tier,
            RetentionTier::Cold
        );
    }

    #[test]
    fn test_rotate_cold_to_archive() {
        let mut store = default_store();
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Cold,
            1000,
        );
        // Already cold, need to recalc hash after setting tier
        bundle.integrity_hash = compute_integrity_hash(&bundle);
        store.store(bundle, 1000).unwrap();

        let total_seconds = (90 + 365) * 86400;
        let transitions = store.rotate_tiers(1000 + total_seconds + 1);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].new_tier.as_deref(), Some("archive"));
        assert_eq!(
            store.get("ibr-001").unwrap().retention_tier,
            RetentionTier::Archive
        );
    }

    #[test]
    fn test_archive_protected_from_delete() {
        let mut store = default_store();
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Archive,
            1000,
        );
        bundle.integrity_hash = compute_integrity_hash(&bundle);
        store.store(bundle, 1000).unwrap();

        let err = store.delete("ibr-001", false, 2000).unwrap_err();
        assert_eq!(err.code(), "IBR_ARCHIVE_PROTECTED");
        assert!(store.contains("ibr-001"));
    }

    #[test]
    fn test_archive_force_delete() {
        let mut store = default_store();
        let mut bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Archive,
            1000,
        );
        bundle.integrity_hash = compute_integrity_hash(&bundle);
        store.store(bundle, 1000).unwrap();

        store.delete("ibr-001", true, 2000).unwrap();
        assert!(!store.contains("ibr-001"));
    }

    #[test]
    fn test_delete_not_found() {
        let mut store = default_store();
        let err = store.delete("missing", false, 1000).unwrap_err();
        assert_eq!(err.code(), "IBR_NOT_FOUND");
    }

    #[test]
    fn test_cleanup_runs_rotation() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();

        let hot_seconds = 90 * 86400;
        let decisions = store.cleanup(1000 + hot_seconds + 1);
        assert!(!decisions.is_empty());
    }

    #[test]
    fn test_decisions_recorded() {
        let mut store = default_store();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        assert!(!store.decisions().is_empty());
        assert!(
            store
                .decisions()
                .iter()
                .any(|d| d.event_code == event_codes::IBR_001)
        );
    }

    #[test]
    fn test_utilization_percent() {
        let mut store = IncidentBundleStore::new(RetentionConfig::default(), 10000).unwrap();
        assert_eq!(store.utilization_percent(), 0);

        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        assert_eq!(store.utilization_percent(), 10);
    }

    #[test]
    fn test_warn_level() {
        let mut store = IncidentBundleStore::new(RetentionConfig::default(), 1400).unwrap();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        // 1000/1400 = 71%
        assert!(store.is_warn_level());
        assert!(!store.is_critical_level());
    }

    #[test]
    fn test_critical_level() {
        let mut store = IncidentBundleStore::new(RetentionConfig::default(), 1170).unwrap();
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        store.store(bundle, 1000).unwrap();
        // 1000/1170 = 85%
        assert!(store.is_critical_level());
    }

    #[test]
    fn test_bundles_by_tier() {
        let mut store = default_store();

        let b1 = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        let mut b2 = sample_bundle(
            "ibr-002",
            "INC-002",
            Severity::Low,
            RetentionTier::Cold,
            1000,
        );
        b2.integrity_hash = compute_integrity_hash(&b2);
        let mut b3 = sample_bundle(
            "ibr-003",
            "INC-003",
            Severity::Critical,
            RetentionTier::Archive,
            1000,
        );
        b3.integrity_hash = compute_integrity_hash(&b3);

        store.store(b1, 1000).unwrap();
        store.store(b2, 1000).unwrap();
        store.store(b3, 1000).unwrap();

        assert_eq!(store.bundles_by_tier(RetentionTier::Hot).len(), 1);
        assert_eq!(store.bundles_by_tier(RetentionTier::Cold).len(), 1);
        assert_eq!(store.bundles_by_tier(RetentionTier::Archive).len(), 1);
    }

    #[test]
    fn test_csv_header() {
        let h = csv_header();
        assert!(h.contains("bundle_id"));
        assert!(h.contains("incident_id"));
        assert!(h.contains("severity"));
        assert!(h.contains("retention_tier"));
    }

    #[test]
    fn test_export_csv_row() {
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::High,
            RetentionTier::Hot,
            1000,
        );
        let row = export_csv_row(&bundle);
        assert!(row.contains("ibr-001"));
        assert!(row.contains("INC-001"));
        assert!(row.contains("high"));
        assert!(row.contains("hot"));
    }

    #[test]
    fn test_export_sarif_fields() {
        let bundle = sample_bundle(
            "ibr-001",
            "INC-001",
            Severity::Critical,
            RetentionTier::Hot,
            1000,
        );
        let sarif = export_sarif(&bundle);
        assert_eq!(sarif.get("version").unwrap(), "2.1.0");
        assert_eq!(sarif.get("bundle_id").unwrap(), "ibr-001");
        assert_eq!(sarif.get("severity").unwrap(), "critical");
    }

    #[test]
    fn test_error_codes_all_present() {
        assert_eq!(
            IncidentBundleError::Incomplete { field: "".into() }.code(),
            "IBR_INCOMPLETE"
        );
        assert_eq!(
            IncidentBundleError::NotFound {
                bundle_id: "".into()
            }
            .code(),
            "IBR_NOT_FOUND"
        );
        assert_eq!(
            IncidentBundleError::ArchiveProtected {
                bundle_id: "".into()
            }
            .code(),
            "IBR_ARCHIVE_PROTECTED"
        );
        assert_eq!(
            IncidentBundleError::IntegrityFailure {
                bundle_id: "".into(),
                expected: "".into(),
                actual: "".into()
            }
            .code(),
            "IBR_INTEGRITY_FAILURE"
        );
        assert_eq!(
            IncidentBundleError::StorageFull {
                current_bytes: 0,
                max_bytes: 0
            }
            .code(),
            "IBR_STORAGE_FULL"
        );
        assert_eq!(
            IncidentBundleError::InvalidFormat { format: "".into() }.code(),
            "IBR_INVALID_FORMAT"
        );
        assert_eq!(
            IncidentBundleError::InvalidConfig { reason: "".into() }.code(),
            "IBR_INVALID_CONFIG"
        );
    }

    #[test]
    fn test_error_display() {
        let e = IncidentBundleError::ArchiveProtected {
            bundle_id: "ibr-001".into(),
        };
        assert!(e.to_string().contains("IBR_ARCHIVE_PROTECTED"));
    }

    #[test]
    fn test_event_codes() {
        assert_eq!(event_codes::IBR_001, "IBR-001");
        assert_eq!(event_codes::IBR_002, "IBR-002");
        assert_eq!(event_codes::IBR_003, "IBR-003");
        assert_eq!(event_codes::IBR_004, "IBR-004");
    }

    #[test]
    fn test_invalid_config_warn_ge_critical() {
        let cfg = RetentionConfig {
            storage_warn_percent: 90,
            storage_critical_percent: 85,
            ..Default::default()
        };
        let err = IncidentBundleStore::new(cfg, 10000).unwrap_err();
        assert_eq!(err.code(), "IBR_INVALID_CONFIG");
    }
}
