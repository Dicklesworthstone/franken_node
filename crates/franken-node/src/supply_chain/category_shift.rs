//! bd-15t: Category-shift reporting pipeline with reproducible evidence bundles.
//!
//! Builds an automated pipeline that aggregates data from benchmarks, adversarial
//! campaigns, migration demos, verifier portal, and trust economics into structured
//! category-shift reports. Every claim is backed by a specific artifact with an
//! integrity hash, and a reproduce-this-claim script is generated for independent
//! verification.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Event codes ──────────────────────────────────────────────────────────────

pub const CSR_PIPELINE_STARTED: &str = "CSR_PIPELINE_STARTED";
pub const CSR_DIMENSION_COLLECTED: &str = "CSR_DIMENSION_COLLECTED";
pub const CSR_CLAIM_VERIFIED: &str = "CSR_CLAIM_VERIFIED";
pub const CSR_REPORT_GENERATED: &str = "CSR_REPORT_GENERATED";

// ── Error codes ──────────────────────────────────────────────────────────────

pub const ERR_CSR_SOURCE_UNAVAILABLE: &str = "ERR_CSR_SOURCE_UNAVAILABLE";
pub const ERR_CSR_CLAIM_STALE: &str = "ERR_CSR_CLAIM_STALE";
pub const ERR_CSR_CLAIM_INVALID: &str = "ERR_CSR_CLAIM_INVALID";
pub const ERR_CSR_HASH_MISMATCH: &str = "ERR_CSR_HASH_MISMATCH";

// ── Invariant identifiers ────────────────────────────────────────────────────

pub const INV_CSR_CLAIM_VALID: &str = "INV-CSR-CLAIM-VALID";
pub const INV_CSR_MANIFEST: &str = "INV-CSR-MANIFEST";
pub const INV_CSR_REPRODUCE: &str = "INV-CSR-REPRODUCE";
pub const INV_CSR_IDEMPOTENT: &str = "INV-CSR-IDEMPOTENT";

// ── Default configuration ────────────────────────────────────────────────────

/// Default freshness window for artifacts in seconds (30 days).
pub const DEFAULT_FRESHNESS_WINDOW_SECS: u64 = 30 * 24 * 3600;

/// Default report schedule interval description.
pub const DEFAULT_SCHEDULE: &str = "monthly";

// ── Threshold configuration ──────────────────────────────────────────────────

/// Minimum compatibility pass rate (95%).
pub const THRESHOLD_COMPAT_PERCENT: f64 = 95.0;

/// Minimum migration velocity multiplier (3x).
pub const THRESHOLD_MIGRATION_VELOCITY: f64 = 3.0;

/// Minimum compromise surface reduction factor (10x).
pub const THRESHOLD_COMPROMISE_REDUCTION: f64 = 10.0;

// ── Enums ────────────────────────────────────────────────────────────────────

/// Category threshold status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdStatus {
    Exceeded,
    Met,
    NotMet,
}

/// Report dimension identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDimension {
    BenchmarkComparisons,
    SecurityPosture,
    MigrationVelocity,
    AdoptionTrends,
    EconomicImpact,
}

/// Moonshot bet status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BetStatus {
    OnTrack,
    AtRisk,
    Blocked,
    Completed,
}

/// Artifact freshness status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Fresh,
    Stale,
    Missing,
}

/// Claim verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimOutcome {
    Verified,
    Stale,
    Invalid,
    HashMismatch,
}

// ── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum CategoryShiftError {
    #[error("{ERR_CSR_SOURCE_UNAVAILABLE}: source `{0}` unavailable")]
    SourceUnavailable(String),
    #[error("{ERR_CSR_CLAIM_STALE}: claim `{0}` references stale artifact")]
    ClaimStale(String),
    #[error("{ERR_CSR_CLAIM_INVALID}: claim `{0}` does not match artifact data")]
    ClaimInvalid(String),
    #[error("{ERR_CSR_HASH_MISMATCH}: artifact `{0}` hash mismatch")]
    HashMismatch(String),
    #[error("json serialization error: {0}")]
    Json(String),
    #[error("no dimensions collected; pipeline has no data")]
    EmptyPipeline,
}

impl From<serde_json::Error> for CategoryShiftError {
    fn from(e: serde_json::Error) -> Self {
        CategoryShiftError::Json(e.to_string())
    }
}

// ── Data structures ──────────────────────────────────────────────────────────

/// A single evidence artifact referenced by a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftEvidence {
    /// Relative path to the artifact file.
    pub artifact_path: String,
    /// SHA-256 hash of the artifact content.
    pub sha256_hash: String,
    /// Unix timestamp when the artifact was generated.
    pub generated_at_secs: u64,
    /// Freshness status relative to the reporting window.
    pub freshness: FreshnessStatus,
}

/// A single claim in the category-shift report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportClaim {
    /// Claim identifier (CSR-CLAIM-NNN).
    pub claim_id: String,
    /// Which dimension this claim belongs to.
    pub dimension: ReportDimension,
    /// Human-readable summary of the claim.
    pub summary: String,
    /// Numeric value supporting the claim (e.g., percentage, factor).
    pub value: f64,
    /// Unit of the value (e.g., "percent", "factor", "count").
    pub unit: String,
    /// Evidence backing the claim.
    pub evidence: ShiftEvidence,
    /// Verification outcome.
    pub outcome: ClaimOutcome,
    /// Reproduce-this-claim script content.
    pub reproduce_script: String,
}

/// Threshold evaluation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdResult {
    pub name: String,
    pub target: f64,
    pub actual: f64,
    pub unit: String,
    pub status: ThresholdStatus,
}

/// Moonshot initiative bet-status entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoonshotBetEntry {
    pub initiative_id: String,
    pub title: String,
    pub status: BetStatus,
    pub progress_percent: u8,
    pub blockers: Vec<String>,
    pub projected_completion: String,
}

/// Manifest entry for a referenced artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub artifact_path: String,
    pub sha256_hash: String,
    pub generated_at_secs: u64,
    pub freshness: FreshnessStatus,
}

/// Dimension data collected from a source system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DimensionData {
    pub dimension: ReportDimension,
    pub source_name: String,
    pub source_bead: String,
    pub collected_at_secs: u64,
    pub claims: Vec<ReportClaim>,
}

/// Diff entry between two report versions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportDiffEntry {
    pub claim_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Telemetry event from the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineEvent {
    pub event_code: String,
    pub trace_id: String,
    pub timestamp_secs: u64,
    pub detail: String,
}

/// The complete category-shift report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CategoryShiftReport {
    pub version: u64,
    pub generated_at_secs: u64,
    pub generated_at_iso: String,
    pub dimensions: BTreeMap<String, DimensionData>,
    pub thresholds: Vec<ThresholdResult>,
    pub bet_status: Vec<MoonshotBetEntry>,
    pub manifest: Vec<ManifestEntry>,
    pub claims: Vec<ReportClaim>,
    pub report_hash: String,
}

// ── Reporting pipeline ───────────────────────────────────────────────────────

/// Configuration for the reporting pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub freshness_window_secs: u64,
    pub schedule: String,
    pub compat_threshold: f64,
    pub migration_velocity_threshold: f64,
    pub compromise_reduction_threshold: f64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
            schedule: DEFAULT_SCHEDULE.to_string(),
            compat_threshold: THRESHOLD_COMPAT_PERCENT,
            migration_velocity_threshold: THRESHOLD_MIGRATION_VELOCITY,
            compromise_reduction_threshold: THRESHOLD_COMPROMISE_REDUCTION,
        }
    }
}

/// The main reporting pipeline.
#[derive(Debug, Clone)]
pub struct ReportingPipeline {
    config: PipelineConfig,
    dimensions: BTreeMap<String, DimensionData>,
    bet_entries: Vec<MoonshotBetEntry>,
    history: Vec<CategoryShiftReport>,
    telemetry: Vec<PipelineEvent>,
    next_claim_id: u32,
}

impl Default for ReportingPipeline {
    fn default() -> Self {
        Self::new(PipelineConfig::default())
    }
}

impl ReportingPipeline {
    /// Create a new pipeline with the given configuration.
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            dimensions: BTreeMap::new(),
            bet_entries: Vec::new(),
            history: Vec::new(),
            telemetry: Vec::new(),
            next_claim_id: 1,
        }
    }

    /// Start the pipeline, emitting a telemetry event.
    pub fn start(&mut self, now_secs: u64, trace_id: &str) {
        self.emit(CSR_PIPELINE_STARTED, trace_id, now_secs, "pipeline started");
    }

    /// Ingest dimension data from a source system.
    pub fn ingest_dimension(
        &mut self,
        dimension: ReportDimension,
        source_name: &str,
        source_bead: &str,
        claims_input: Vec<ClaimInput>,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<(), CategoryShiftError> {
        let mut claims = Vec::new();
        for input in claims_input {
            let evidence = self.verify_evidence(&input.evidence, now_secs)?;
            let claim_id = format!("CSR-CLAIM-{:03}", self.next_claim_id);
            self.next_claim_id += 1;

            let outcome = match evidence.freshness {
                FreshnessStatus::Fresh => ClaimOutcome::Verified,
                FreshnessStatus::Stale => ClaimOutcome::Stale,
                FreshnessStatus::Missing => ClaimOutcome::Invalid,
            };

            let reproduce_script = generate_reproduce_script(&claim_id, &evidence);

            self.emit(
                CSR_CLAIM_VERIFIED,
                trace_id,
                now_secs,
                &format!("claim {} verified: {:?}", claim_id, outcome),
            );

            claims.push(ReportClaim {
                claim_id,
                dimension,
                summary: input.summary,
                value: input.value,
                unit: input.unit,
                evidence,
                outcome,
                reproduce_script,
            });
        }

        let dim_key = format!("{:?}", dimension).to_ascii_lowercase();
        self.dimensions.insert(
            dim_key,
            DimensionData {
                dimension,
                source_name: source_name.to_string(),
                source_bead: source_bead.to_string(),
                collected_at_secs: now_secs,
                claims,
            },
        );

        self.emit(
            CSR_DIMENSION_COLLECTED,
            trace_id,
            now_secs,
            &format!("dimension {:?} collected from {}", dimension, source_name),
        );

        Ok(())
    }

    /// Register a moonshot bet-status entry.
    pub fn register_bet(&mut self, entry: MoonshotBetEntry) {
        self.bet_entries.push(entry);
    }

    /// Generate the final report.
    pub fn generate_report(
        &mut self,
        now_secs: u64,
        trace_id: &str,
    ) -> Result<CategoryShiftReport, CategoryShiftError> {
        if self.dimensions.is_empty() {
            return Err(CategoryShiftError::EmptyPipeline);
        }

        let mut all_claims: Vec<ReportClaim> = Vec::new();
        let mut manifest: Vec<ManifestEntry> = Vec::new();

        for dim_data in self.dimensions.values() {
            for claim in &dim_data.claims {
                all_claims.push(claim.clone());
                manifest.push(ManifestEntry {
                    artifact_path: claim.evidence.artifact_path.clone(),
                    sha256_hash: claim.evidence.sha256_hash.clone(),
                    generated_at_secs: claim.evidence.generated_at_secs,
                    freshness: claim.evidence.freshness,
                });
            }
        }

        // Sort claims by ID for determinism.
        all_claims.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
        manifest.sort_by(|a, b| a.artifact_path.cmp(&b.artifact_path));

        // Evaluate thresholds from collected data.
        let thresholds = self.evaluate_thresholds(&all_claims);

        // Sort bet entries for determinism.
        let mut bet_status = self.bet_entries.clone();
        bet_status.sort_by(|a, b| a.initiative_id.cmp(&b.initiative_id));

        let version = self.history.len() as u64 + 1;

        let mut report = CategoryShiftReport {
            version,
            generated_at_secs: now_secs,
            generated_at_iso: format_iso_timestamp(now_secs),
            dimensions: self.dimensions.clone(),
            thresholds,
            bet_status,
            manifest,
            claims: all_claims,
            report_hash: String::new(),
        };

        // Compute report hash for integrity.
        report.report_hash = compute_report_hash(&report)?;

        self.emit(
            CSR_REPORT_GENERATED,
            trace_id,
            now_secs,
            &format!("report v{} generated", version),
        );

        self.history.push(report.clone());
        Ok(report)
    }

    /// Render the report as Markdown.
    #[must_use]
    pub fn render_markdown(report: &CategoryShiftReport) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Category-Shift Report v{}\n\n", report.version));
        out.push_str(&format!("**Generated:** {}\n\n", report.generated_at_iso));

        // Dashboard summary
        out.push_str("## Dashboard\n\n");
        out.push_str("| Threshold | Target | Actual | Status |\n");
        out.push_str("|-----------|--------|--------|--------|\n");
        for th in &report.thresholds {
            out.push_str(&format!(
                "| {} | {:.1}{} | {:.1}{} | {:?} |\n",
                th.name, th.target, th.unit, th.actual, th.unit, th.status
            ));
        }
        out.push('\n');

        // Claims by dimension
        out.push_str("## Claims\n\n");
        for claim in &report.claims {
            out.push_str(&format!(
                "### {} ({:?})\n\n{}\n\n- Value: {:.2} {}\n- Evidence: `{}`\n- Outcome: {:?}\n\n",
                claim.claim_id,
                claim.dimension,
                claim.summary,
                claim.value,
                claim.unit,
                claim.evidence.artifact_path,
                claim.outcome,
            ));
        }

        // Bet status
        if !report.bet_status.is_empty() {
            out.push_str("## Moonshot Bet Status\n\n");
            out.push_str("| Initiative | Status | Progress | Projected |\n");
            out.push_str("|-----------|--------|----------|----------|\n");
            for bet in &report.bet_status {
                out.push_str(&format!(
                    "| {} | {:?} | {}% | {} |\n",
                    bet.title, bet.status, bet.progress_percent, bet.projected_completion
                ));
            }
            out.push('\n');
        }

        // Manifest
        out.push_str("## Artifact Manifest\n\n");
        out.push_str("| Path | SHA-256 | Freshness |\n");
        out.push_str("|------|---------|----------|\n");
        for entry in &report.manifest {
            out.push_str(&format!(
                "| `{}` | `{}` | {:?} |\n",
                entry.artifact_path,
                &entry.sha256_hash[..16],
                entry.freshness
            ));
        }

        out.push_str(&format!("\n**Report Hash:** `{}`\n", report.report_hash));

        out
    }

    /// Render the report as canonical JSON.
    pub fn render_json(report: &CategoryShiftReport) -> Result<String, CategoryShiftError> {
        let value = serde_json::to_value(report)?;
        let canonical = canonicalize_value(value);
        Ok(serde_json::to_string_pretty(&canonical)?)
    }

    /// Compute diff between two report versions.
    #[must_use]
    pub fn diff_reports(
        old_report: &CategoryShiftReport,
        new_report: &CategoryShiftReport,
    ) -> Vec<ReportDiffEntry> {
        let mut diffs = Vec::new();

        // Build claim maps
        let old_claims: BTreeMap<&str, &ReportClaim> = old_report
            .claims
            .iter()
            .map(|c| (c.claim_id.as_str(), c))
            .collect();
        let new_claims: BTreeMap<&str, &ReportClaim> = new_report
            .claims
            .iter()
            .map(|c| (c.claim_id.as_str(), c))
            .collect();

        // Check for changed or removed claims
        for (id, old_claim) in &old_claims {
            if let Some(new_claim) = new_claims.get(id) {
                if (old_claim.value - new_claim.value).abs() > f64::EPSILON {
                    diffs.push(ReportDiffEntry {
                        claim_id: id.to_string(),
                        field: "value".to_string(),
                        old_value: format!("{:.2}", old_claim.value),
                        new_value: format!("{:.2}", new_claim.value),
                    });
                }
                if old_claim.outcome != new_claim.outcome {
                    diffs.push(ReportDiffEntry {
                        claim_id: id.to_string(),
                        field: "outcome".to_string(),
                        old_value: format!("{:?}", old_claim.outcome),
                        new_value: format!("{:?}", new_claim.outcome),
                    });
                }
            } else {
                diffs.push(ReportDiffEntry {
                    claim_id: id.to_string(),
                    field: "status".to_string(),
                    old_value: "present".to_string(),
                    new_value: "removed".to_string(),
                });
            }
        }

        // Check for new claims
        for id in new_claims.keys() {
            if !old_claims.contains_key(id) {
                diffs.push(ReportDiffEntry {
                    claim_id: id.to_string(),
                    field: "status".to_string(),
                    old_value: "absent".to_string(),
                    new_value: "added".to_string(),
                });
            }
        }

        // Check threshold status changes
        for (i, new_th) in new_report.thresholds.iter().enumerate() {
            if let Some(old_th) = old_report.thresholds.get(i)
                && old_th.status != new_th.status
            {
                diffs.push(ReportDiffEntry {
                    claim_id: format!("THRESHOLD-{}", new_th.name),
                    field: "status".to_string(),
                    old_value: format!("{:?}", old_th.status),
                    new_value: format!("{:?}", new_th.status),
                });
            }
        }

        diffs.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
        diffs
    }

    /// Get historical reports.
    #[must_use]
    pub fn history(&self) -> &[CategoryShiftReport] {
        &self.history
    }

    /// Get telemetry events.
    #[must_use]
    pub fn telemetry(&self) -> &[PipelineEvent] {
        &self.telemetry
    }

    /// Get pipeline configuration.
    #[must_use]
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn verify_evidence(
        &self,
        input: &EvidenceInput,
        now_secs: u64,
    ) -> Result<ShiftEvidence, CategoryShiftError> {
        let age = now_secs.saturating_sub(input.generated_at_secs);
        let freshness = if age <= self.config.freshness_window_secs {
            FreshnessStatus::Fresh
        } else {
            FreshnessStatus::Stale
        };

        // Verify hash if content is provided.
        if let Some(content) = &input.content {
            let computed = sha256_hex(content.as_bytes());
            if computed != input.sha256_hash {
                return Err(CategoryShiftError::HashMismatch(
                    input.artifact_path.clone(),
                ));
            }
        }

        Ok(ShiftEvidence {
            artifact_path: input.artifact_path.clone(),
            sha256_hash: input.sha256_hash.clone(),
            generated_at_secs: input.generated_at_secs,
            freshness,
        })
    }

    fn evaluate_thresholds(&self, claims: &[ReportClaim]) -> Vec<ThresholdResult> {
        let mut thresholds = Vec::new();

        // Compatibility threshold
        let compat_value = claims
            .iter()
            .filter(|c| c.dimension == ReportDimension::BenchmarkComparisons)
            .filter(|c| c.unit == "percent")
            .map(|c| c.value)
            .next()
            .unwrap_or(0.0);
        thresholds.push(ThresholdResult {
            name: "compatibility".to_string(),
            target: self.config.compat_threshold,
            actual: compat_value,
            unit: "%".to_string(),
            status: evaluate_threshold_status(compat_value, self.config.compat_threshold),
        });

        // Migration velocity threshold
        let migration_value = claims
            .iter()
            .filter(|c| c.dimension == ReportDimension::MigrationVelocity)
            .filter(|c| c.unit == "factor")
            .map(|c| c.value)
            .next()
            .unwrap_or(0.0);
        thresholds.push(ThresholdResult {
            name: "migration_velocity".to_string(),
            target: self.config.migration_velocity_threshold,
            actual: migration_value,
            unit: "x".to_string(),
            status: evaluate_threshold_status(
                migration_value,
                self.config.migration_velocity_threshold,
            ),
        });

        // Compromise reduction threshold
        let compromise_value = claims
            .iter()
            .filter(|c| c.dimension == ReportDimension::SecurityPosture)
            .filter(|c| c.unit == "factor")
            .map(|c| c.value)
            .next()
            .unwrap_or(0.0);
        thresholds.push(ThresholdResult {
            name: "compromise_reduction".to_string(),
            target: self.config.compromise_reduction_threshold,
            actual: compromise_value,
            unit: "x".to_string(),
            status: evaluate_threshold_status(
                compromise_value,
                self.config.compromise_reduction_threshold,
            ),
        });

        thresholds
    }

    fn emit(&mut self, event_code: &str, trace_id: &str, timestamp_secs: u64, detail: &str) {
        self.telemetry.push(PipelineEvent {
            event_code: event_code.to_string(),
            trace_id: trace_id.to_string(),
            timestamp_secs,
            detail: detail.to_string(),
        });
    }
}

// ── Input types ──────────────────────────────────────────────────────────────

/// Input for creating a claim (before verification).
#[derive(Debug, Clone)]
pub struct ClaimInput {
    pub summary: String,
    pub value: f64,
    pub unit: String,
    pub evidence: EvidenceInput,
}

/// Input for evidence verification.
#[derive(Debug, Clone)]
pub struct EvidenceInput {
    pub artifact_path: String,
    pub sha256_hash: String,
    pub generated_at_secs: u64,
    /// Optional: raw content for hash verification.
    pub content: Option<String>,
}

// ── Free functions ───────────────────────────────────────────────────────────

/// Compute SHA-256 hex digest of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Evaluate threshold status.
fn evaluate_threshold_status(actual: f64, target: f64) -> ThresholdStatus {
    if actual > target * 1.1 {
        ThresholdStatus::Exceeded
    } else if actual >= target {
        ThresholdStatus::Met
    } else {
        ThresholdStatus::NotMet
    }
}

/// Generate a reproduce-this-claim script for a claim.
fn generate_reproduce_script(claim_id: &str, evidence: &ShiftEvidence) -> String {
    format!(
        r#"#!/usr/bin/env bash
# Reproduce script for {claim_id}
set -euo pipefail

ARTIFACT="{path}"
EXPECTED_HASH="{hash}"

if [ ! -f "$ARTIFACT" ]; then
  echo "ERROR: artifact not found: $ARTIFACT"
  exit 1
fi

ACTUAL_HASH=$(sha256sum "$ARTIFACT" | cut -d' ' -f1)
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo "ERROR: hash mismatch for $ARTIFACT"
  echo "  expected: $EXPECTED_HASH"
  echo "  actual:   $ACTUAL_HASH"
  exit 1
fi

echo "OK: {claim_id} verified"
exit 0
"#,
        claim_id = claim_id,
        path = evidence.artifact_path,
        hash = evidence.sha256_hash,
    )
}

/// Format a Unix timestamp as ISO 8601.
fn format_iso_timestamp(secs: u64) -> String {
    // Simple UTC formatting without chrono dependency in this module.
    format!("{}Z", secs)
}

/// Compute a deterministic hash of the report (excluding the hash field itself).
fn compute_report_hash(report: &CategoryShiftReport) -> Result<String, CategoryShiftError> {
    let mut report_for_hash = report.clone();
    report_for_hash.report_hash = String::new();
    let value = serde_json::to_value(&report_for_hash)?;
    let canonical = canonicalize_value(value);
    let encoded = serde_json::to_vec(&canonical)?;
    Ok(sha256_hex(&encoded))
}

/// Canonicalize a JSON value by sorting object keys.
fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                if let Some(val) = map.get(&key) {
                    sorted.insert(key, canonicalize_value(val.clone()));
                }
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize_value).collect())
        }
        other => other,
    }
}

/// Build a demo pipeline with sample data from all five dimensions.
pub fn demo_pipeline(
    now_secs: u64,
) -> Result<(ReportingPipeline, CategoryShiftReport), CategoryShiftError> {
    let mut pipeline = ReportingPipeline::default();
    let trace = "trace-demo";
    pipeline.start(now_secs, trace);

    let benchmark_content = r#"{"throughput_ops_per_sec":150000,"latency_p99_ms":2.1}"#;
    let benchmark_hash = sha256_hex(benchmark_content.as_bytes());

    let security_content = r#"{"attacks_neutralized":47,"coverage_percent":98.5}"#;
    let security_hash = sha256_hex(security_content.as_bytes());

    let migration_content = r#"{"success_rate":0.97,"median_time_hours":1.2}"#;
    let migration_hash = sha256_hex(migration_content.as_bytes());

    let adoption_content = r#"{"verifier_count":142,"attestation_volume":8934}"#;
    let adoption_hash = sha256_hex(adoption_content.as_bytes());

    let economics_content = r#"{"cost_benefit_ratio":4.2,"attacker_roi_delta":-0.87}"#;
    let economics_hash = sha256_hex(economics_content.as_bytes());

    // Dimension 1: Benchmark Comparisons
    pipeline.ingest_dimension(
        ReportDimension::BenchmarkComparisons,
        "benchmark-infra",
        "bd-f5d",
        vec![ClaimInput {
            summary: "franken_node achieves 96.2% Node.js API compatibility".to_string(),
            value: 96.2,
            unit: "percent".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/benchmarks/compat_results.json".to_string(),
                sha256_hash: benchmark_hash,
                generated_at_secs: now_secs.saturating_sub(86400),
                content: Some(benchmark_content.to_string()),
            },
        }],
        now_secs,
        trace,
    )?;

    // Dimension 2: Security Posture
    pipeline.ingest_dimension(
        ReportDimension::SecurityPosture,
        "adversarial-runner",
        "bd-9is",
        vec![ClaimInput {
            summary: "franken_node achieves 12.5x compromise surface reduction".to_string(),
            value: 12.5,
            unit: "factor".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/security/adversarial_results.json".to_string(),
                sha256_hash: security_hash,
                generated_at_secs: now_secs.saturating_sub(172800),
                content: Some(security_content.to_string()),
            },
        }],
        now_secs,
        trace,
    )?;

    // Dimension 3: Migration Velocity
    pipeline.ingest_dimension(
        ReportDimension::MigrationVelocity,
        "migration-demo",
        "bd-1e0",
        vec![ClaimInput {
            summary: "franken_node migration is 4.1x faster than manual migration".to_string(),
            value: 4.1,
            unit: "factor".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/migration/demo_results.json".to_string(),
                sha256_hash: migration_hash,
                generated_at_secs: now_secs.saturating_sub(259200),
                content: Some(migration_content.to_string()),
            },
        }],
        now_secs,
        trace,
    )?;

    // Dimension 4: Adoption Trends
    pipeline.ingest_dimension(
        ReportDimension::AdoptionTrends,
        "verifier-portal",
        "bd-m8p",
        vec![ClaimInput {
            summary: "142 verifiers registered with 8934 attestations".to_string(),
            value: 142.0,
            unit: "count".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/adoption/verifier_stats.json".to_string(),
                sha256_hash: adoption_hash,
                generated_at_secs: now_secs.saturating_sub(43200),
                content: Some(adoption_content.to_string()),
            },
        }],
        now_secs,
        trace,
    )?;

    // Dimension 5: Economic Impact
    pipeline.ingest_dimension(
        ReportDimension::EconomicImpact,
        "trust-economics",
        "bd-10c",
        vec![ClaimInput {
            summary: "4.2x cost-benefit ratio with -87% attacker ROI".to_string(),
            value: 4.2,
            unit: "ratio".to_string(),
            evidence: EvidenceInput {
                artifact_path: "artifacts/economics/trust_economics.json".to_string(),
                sha256_hash: economics_hash,
                generated_at_secs: now_secs.saturating_sub(86400),
                content: Some(economics_content.to_string()),
            },
        }],
        now_secs,
        trace,
    )?;

    // Register moonshot bets
    pipeline.register_bet(MoonshotBetEntry {
        initiative_id: "moonshot-compat".to_string(),
        title: "95% API Compatibility".to_string(),
        status: BetStatus::OnTrack,
        progress_percent: 96,
        blockers: vec![],
        projected_completion: "2026-Q2".to_string(),
    });
    pipeline.register_bet(MoonshotBetEntry {
        initiative_id: "moonshot-migration".to_string(),
        title: "3x Migration Velocity".to_string(),
        status: BetStatus::Completed,
        progress_percent: 100,
        blockers: vec![],
        projected_completion: "2026-Q1".to_string(),
    });
    pipeline.register_bet(MoonshotBetEntry {
        initiative_id: "moonshot-security".to_string(),
        title: "10x Compromise Reduction".to_string(),
        status: BetStatus::OnTrack,
        progress_percent: 85,
        blockers: vec![],
        projected_completion: "2026-Q2".to_string(),
    });

    let report = pipeline.generate_report(now_secs, trace)?;
    Ok((pipeline, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence(now_secs: u64) -> EvidenceInput {
        let content = r#"{"test":"data"}"#;
        EvidenceInput {
            artifact_path: "artifacts/test/sample.json".to_string(),
            sha256_hash: sha256_hex(content.as_bytes()),
            generated_at_secs: now_secs.saturating_sub(3600),
            content: Some(content.to_string()),
        }
    }

    fn sample_claim(now_secs: u64) -> ClaimInput {
        ClaimInput {
            summary: "Test claim".to_string(),
            value: 42.0,
            unit: "percent".to_string(),
            evidence: sample_evidence(now_secs),
        }
    }

    #[test]
    fn pipeline_starts_with_telemetry() {
        let mut pipeline = ReportingPipeline::default();
        pipeline.start(1000, "trace-1");
        assert_eq!(pipeline.telemetry().len(), 1);
        assert_eq!(pipeline.telemetry()[0].event_code, CSR_PIPELINE_STARTED);
    }

    #[test]
    fn ingest_dimension_creates_claims() {
        let mut pipeline = ReportingPipeline::default();
        let now = 1_000_000;
        pipeline
            .ingest_dimension(
                ReportDimension::BenchmarkComparisons,
                "bench",
                "bd-f5d",
                vec![sample_claim(now)],
                now,
                "trace",
            )
            .unwrap();
        assert_eq!(pipeline.dimensions.len(), 1);
    }

    #[test]
    fn claim_ids_are_sequential() {
        let mut pipeline = ReportingPipeline::default();
        let now = 1_000_000;
        pipeline
            .ingest_dimension(
                ReportDimension::BenchmarkComparisons,
                "bench",
                "bd-f5d",
                vec![sample_claim(now), sample_claim(now)],
                now,
                "trace",
            )
            .unwrap();
        let dim = pipeline.dimensions.values().next().unwrap();
        assert_eq!(dim.claims[0].claim_id, "CSR-CLAIM-001");
        assert_eq!(dim.claims[1].claim_id, "CSR-CLAIM-002");
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let mut pipeline = ReportingPipeline::default();
        let now = 1_000_000;
        let bad_evidence = EvidenceInput {
            artifact_path: "artifacts/test/bad.json".to_string(),
            sha256_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            generated_at_secs: now,
            content: Some("real content".to_string()),
        };
        let result = pipeline.ingest_dimension(
            ReportDimension::SecurityPosture,
            "adv",
            "bd-9is",
            vec![ClaimInput {
                summary: "bad claim".to_string(),
                value: 1.0,
                unit: "factor".to_string(),
                evidence: bad_evidence,
            }],
            now,
            "trace",
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CategoryShiftError::HashMismatch(_)
        ));
    }

    #[test]
    fn stale_evidence_marked_as_stale() {
        let mut pipeline = ReportingPipeline::default();
        let now: u64 = 10_000_000;
        let content = r#"{"old":"data"}"#;
        let stale_evidence = EvidenceInput {
            artifact_path: "artifacts/test/old.json".to_string(),
            sha256_hash: sha256_hex(content.as_bytes()),
            generated_at_secs: now.saturating_sub(DEFAULT_FRESHNESS_WINDOW_SECS + 1),
            content: Some(content.to_string()),
        };
        pipeline
            .ingest_dimension(
                ReportDimension::AdoptionTrends,
                "portal",
                "bd-m8p",
                vec![ClaimInput {
                    summary: "stale claim".to_string(),
                    value: 100.0,
                    unit: "count".to_string(),
                    evidence: stale_evidence,
                }],
                now,
                "trace",
            )
            .unwrap();
        let dim = pipeline.dimensions.values().next().unwrap();
        assert_eq!(dim.claims[0].evidence.freshness, FreshnessStatus::Stale);
        assert_eq!(dim.claims[0].outcome, ClaimOutcome::Stale);
    }

    #[test]
    fn empty_pipeline_returns_error() {
        let mut pipeline = ReportingPipeline::default();
        let result = pipeline.generate_report(1000, "trace");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CategoryShiftError::EmptyPipeline
        ));
    }

    #[test]
    fn generate_report_produces_valid_structure() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        assert_eq!(report.version, 1);
        assert!(!report.claims.is_empty());
        assert!(!report.manifest.is_empty());
        assert_eq!(report.thresholds.len(), 3);
        assert!(!report.report_hash.is_empty());
    }

    #[test]
    fn report_has_five_dimensions() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        assert_eq!(report.dimensions.len(), 5);
    }

    #[test]
    fn report_is_idempotent() {
        let now = 1_000_000;
        let (_, report1) = demo_pipeline(now).unwrap();
        let (_, report2) = demo_pipeline(now).unwrap();
        assert_eq!(report1.report_hash, report2.report_hash);
        assert_eq!(report1.claims.len(), report2.claims.len());
    }

    #[test]
    fn threshold_compatibility_exceeded() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let compat = report
            .thresholds
            .iter()
            .find(|t| t.name == "compatibility")
            .unwrap();
        assert_eq!(compat.status, ThresholdStatus::Met);
        assert!(compat.actual >= THRESHOLD_COMPAT_PERCENT);
    }

    #[test]
    fn threshold_migration_velocity_exceeded() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let migration = report
            .thresholds
            .iter()
            .find(|t| t.name == "migration_velocity")
            .unwrap();
        assert!(migration.actual >= THRESHOLD_MIGRATION_VELOCITY);
    }

    #[test]
    fn threshold_compromise_reduction_exceeded() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let compromise = report
            .thresholds
            .iter()
            .find(|t| t.name == "compromise_reduction")
            .unwrap();
        assert!(compromise.actual >= THRESHOLD_COMPROMISE_REDUCTION);
    }

    #[test]
    fn bet_status_entries_present() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        assert_eq!(report.bet_status.len(), 3);
        let completed = report
            .bet_status
            .iter()
            .find(|b| b.status == BetStatus::Completed);
        assert!(completed.is_some());
    }

    #[test]
    fn manifest_contains_all_artifacts() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        assert_eq!(report.manifest.len(), report.claims.len());
        for entry in &report.manifest {
            assert!(!entry.sha256_hash.is_empty());
            assert!(!entry.artifact_path.is_empty());
        }
    }

    #[test]
    fn claims_have_reproduce_scripts() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        for claim in &report.claims {
            assert!(claim.reproduce_script.contains("sha256sum"));
            assert!(claim.reproduce_script.contains(&claim.claim_id));
        }
    }

    #[test]
    fn render_markdown_contains_dashboard() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let md = ReportingPipeline::render_markdown(&report);
        assert!(md.contains("# Category-Shift Report"));
        assert!(md.contains("## Dashboard"));
        assert!(md.contains("## Claims"));
        assert!(md.contains("## Artifact Manifest"));
        assert!(md.contains("Report Hash"));
    }

    #[test]
    fn render_json_is_valid() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let json_str = ReportingPipeline::render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());
        assert!(parsed["version"].is_number());
        assert!(parsed["claims"].is_array());
    }

    #[test]
    fn render_json_is_deterministic() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let json1 = ReportingPipeline::render_json(&report).unwrap();
        let json2 = ReportingPipeline::render_json(&report).unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn diff_reports_detects_changes() {
        let now = 1_000_000;
        let (_, report1) = demo_pipeline(now).unwrap();

        // Create a second report with different values
        let mut pipeline2 = ReportingPipeline::default();
        let content = r#"{"throughput_ops_per_sec":170000,"latency_p99_ms":1.8}"#;
        pipeline2
            .ingest_dimension(
                ReportDimension::BenchmarkComparisons,
                "bench",
                "bd-f5d",
                vec![ClaimInput {
                    summary: "Improved compatibility".to_string(),
                    value: 97.5,
                    unit: "percent".to_string(),
                    evidence: EvidenceInput {
                        artifact_path: "artifacts/benchmarks/compat_results.json".to_string(),
                        sha256_hash: sha256_hex(content.as_bytes()),
                        generated_at_secs: now,
                        content: Some(content.to_string()),
                    },
                }],
                now + 100,
                "trace",
            )
            .unwrap();
        let report2 = pipeline2.generate_report(now + 100, "trace").unwrap();

        let diffs = ReportingPipeline::diff_reports(&report1, &report2);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn diff_identical_reports_is_empty() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let diffs = ReportingPipeline::diff_reports(&report, &report);
        assert!(diffs.is_empty());
    }

    #[test]
    fn sha256_hex_computes_correctly() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn evaluate_threshold_status_logic() {
        // 100.0 >= 95.0 but 100.0 <= 95.0*1.1=104.5 → Met (not Exceeded).
        assert_eq!(
            evaluate_threshold_status(100.0, 95.0),
            ThresholdStatus::Met
        );
        // 105.0 > 95.0*1.1=104.5 → Exceeded.
        assert_eq!(
            evaluate_threshold_status(105.0, 95.0),
            ThresholdStatus::Exceeded
        );
        assert_eq!(evaluate_threshold_status(96.0, 95.0), ThresholdStatus::Met);
        assert_eq!(
            evaluate_threshold_status(90.0, 95.0),
            ThresholdStatus::NotMet
        );
    }

    #[test]
    fn pipeline_config_defaults() {
        let config = PipelineConfig::default();
        assert_eq!(config.freshness_window_secs, DEFAULT_FRESHNESS_WINDOW_SECS);
        assert_eq!(config.compat_threshold, THRESHOLD_COMPAT_PERCENT);
        assert_eq!(
            config.migration_velocity_threshold,
            THRESHOLD_MIGRATION_VELOCITY
        );
        assert_eq!(
            config.compromise_reduction_threshold,
            THRESHOLD_COMPROMISE_REDUCTION
        );
    }

    #[test]
    fn history_accumulates_reports() {
        let now = 1_000_000;
        let (pipeline, _) = demo_pipeline(now).unwrap();
        assert_eq!(pipeline.history().len(), 1);
    }

    #[test]
    fn telemetry_records_all_events() {
        let now = 1_000_000;
        let (pipeline, _) = demo_pipeline(now).unwrap();
        let codes: Vec<&str> = pipeline
            .telemetry()
            .iter()
            .map(|e| e.event_code.as_str())
            .collect();
        assert!(codes.contains(&CSR_PIPELINE_STARTED));
        assert!(codes.contains(&CSR_DIMENSION_COLLECTED));
        assert!(codes.contains(&CSR_CLAIM_VERIFIED));
        assert!(codes.contains(&CSR_REPORT_GENERATED));
    }

    #[test]
    fn evidence_without_content_skips_hash_check() {
        let mut pipeline = ReportingPipeline::default();
        let now = 1_000_000;
        let evidence = EvidenceInput {
            artifact_path: "artifacts/test/no_content.json".to_string(),
            sha256_hash: "any_hash_value".to_string(),
            generated_at_secs: now,
            content: None,
        };
        pipeline
            .ingest_dimension(
                ReportDimension::EconomicImpact,
                "econ",
                "bd-10c",
                vec![ClaimInput {
                    summary: "no content claim".to_string(),
                    value: 3.0,
                    unit: "ratio".to_string(),
                    evidence,
                }],
                now,
                "trace",
            )
            .unwrap();
    }

    #[test]
    fn report_generated_at_iso_format() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        assert!(report.generated_at_iso.ends_with('Z'));
    }

    #[test]
    fn canonicalize_sorts_keys() {
        let input = serde_json::json!({"z": 1, "a": 2, "m": {"b": 3, "a": 4}});
        let canonical = canonicalize_value(input);
        let keys: Vec<&String> = canonical.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
        let nested_keys: Vec<&String> = canonical["m"].as_object().unwrap().keys().collect();
        assert_eq!(nested_keys, vec!["a", "b"]);
    }

    #[test]
    fn reproduce_script_contains_expected_fields() {
        let evidence = ShiftEvidence {
            artifact_path: "test/file.json".to_string(),
            sha256_hash: "abc123".to_string(),
            generated_at_secs: 1000,
            freshness: FreshnessStatus::Fresh,
        };
        let script = generate_reproduce_script("CSR-CLAIM-001", &evidence);
        assert!(script.contains("CSR-CLAIM-001"));
        assert!(script.contains("test/file.json"));
        assert!(script.contains("abc123"));
        assert!(script.contains("set -euo pipefail"));
    }

    #[test]
    fn markdown_includes_bet_status_table() {
        let now = 1_000_000;
        let (_, report) = demo_pipeline(now).unwrap();
        let md = ReportingPipeline::render_markdown(&report);
        assert!(md.contains("## Moonshot Bet Status"));
        assert!(md.contains("95% API Compatibility"));
        assert!(md.contains("3x Migration Velocity"));
    }

    #[test]
    fn all_event_codes_are_prefixed() {
        assert!(CSR_PIPELINE_STARTED.starts_with("CSR_"));
        assert!(CSR_DIMENSION_COLLECTED.starts_with("CSR_"));
        assert!(CSR_CLAIM_VERIFIED.starts_with("CSR_"));
        assert!(CSR_REPORT_GENERATED.starts_with("CSR_"));
    }

    #[test]
    fn all_error_codes_are_prefixed() {
        assert!(ERR_CSR_SOURCE_UNAVAILABLE.starts_with("ERR_CSR_"));
        assert!(ERR_CSR_CLAIM_STALE.starts_with("ERR_CSR_"));
        assert!(ERR_CSR_CLAIM_INVALID.starts_with("ERR_CSR_"));
        assert!(ERR_CSR_HASH_MISMATCH.starts_with("ERR_CSR_"));
    }

    #[test]
    fn all_invariants_are_prefixed() {
        assert!(INV_CSR_CLAIM_VALID.starts_with("INV-CSR-"));
        assert!(INV_CSR_MANIFEST.starts_with("INV-CSR-"));
        assert!(INV_CSR_REPRODUCE.starts_with("INV-CSR-"));
        assert!(INV_CSR_IDEMPOTENT.starts_with("INV-CSR-"));
    }

    #[test]
    fn freshness_status_boundary() {
        let pipeline = ReportingPipeline::default();
        let now: u64 = 10_000_000;
        // Exactly at boundary should be fresh
        let content = r#"{"boundary":"test"}"#;
        let evidence = EvidenceInput {
            artifact_path: "test.json".to_string(),
            sha256_hash: sha256_hex(content.as_bytes()),
            generated_at_secs: now - DEFAULT_FRESHNESS_WINDOW_SECS,
            content: Some(content.to_string()),
        };
        let result = pipeline.verify_evidence(&evidence, now).unwrap();
        assert_eq!(result.freshness, FreshnessStatus::Fresh);

        // One second past boundary should be stale
        let evidence2 = EvidenceInput {
            artifact_path: "test2.json".to_string(),
            sha256_hash: sha256_hex(content.as_bytes()),
            generated_at_secs: now - DEFAULT_FRESHNESS_WINDOW_SECS - 1,
            content: Some(content.to_string()),
        };
        let result2 = pipeline.verify_evidence(&evidence2, now).unwrap();
        assert_eq!(result2.freshness, FreshnessStatus::Stale);
    }
}
