//! bd-29ct: Adversarial fuzz corpus gates for decode-DoS and replay/splice scenarios.
//!
//! Fuzz targets cover parser input, handshake replay/splice, token validation,
//! and decode-DoS. A campaign runner triages crashes into reproducible fixtures
//! and a gate enforces minimum health budgets.
//!
//! This module now carries two clearly separated surfaces:
//!
//! - `run_truthful_fuzz_gate(...)` is the only live evidence-bearing path.
//! - `DeterministicFuzzTestAdapter::run_fixture_gate()` is an allowlisted
//!   synthetic fixture adapter for tests and modeling only.
//!
//! `PSI-006` in `docs/governance/placeholder_surface_inventory.md` tracks the
//! synthetic boundary, and `docs/specs/section_10_13/bd-2fqyv_7_1_contract.md`
//! defines the live adapter/reporting contract.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../../../../fuzz/targets/migration_dependency_resolve.rs"]
mod migration_dependency_resolve_target;
#[allow(dead_code)]
#[path = "../../../../fuzz/targets/migration_directory_scan.rs"]
mod migration_directory_scan_target;
#[allow(dead_code)]
#[path = "../../../../fuzz/targets/migration_package_parse.rs"]
mod migration_package_parse_target;
#[allow(dead_code)]
#[path = "../../../../fuzz/targets/shim_api_translation.rs"]
mod shim_api_translation_target;
#[allow(dead_code)]
#[path = "../../../../fuzz/targets/shim_type_coercion.rs"]
mod shim_type_coercion_target;

const REPORT_SCHEMA_VERSION: &str = "fuzz_gate_truthful_report_v1";
const LIVE_ADAPTER_KIND: &str = "in_process_checked_fixtures";
const DEFAULT_LIVE_TIMEOUT_MS: u64 = 1_000;
#[cfg(any(test, feature = "test-support"))]
const DETERMINISTIC_FIXTURE_ADAPTER_KIND: &str = "deterministic_fixture_test_adapter";
#[cfg(any(test, feature = "test-support"))]
const DETERMINISTIC_FIXTURE_EXECUTION_MODE: &str = "synthetic_test_fixture";
#[cfg(any(test, feature = "test-support"))]
const DETERMINISTIC_FIXTURE_RUNNER_DETAIL: &str = "fixture_marker=synthetic_test_fixture crash_classifier=string_trigger coverage_semantics=placeholder_zero";

// ── Fuzz target categories ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FuzzCategory {
    ParserInput,
    HandshakeReplay,
    TokenValidation,
    DecodeDos,
}

impl fmt::Display for FuzzCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzCategory::ParserInput => write!(f, "parser_input"),
            FuzzCategory::HandshakeReplay => write!(f, "handshake_replay"),
            FuzzCategory::TokenValidation => write!(f, "token_validation"),
            FuzzCategory::DecodeDos => write!(f, "decode_dos"),
        }
    }
}

// ── Deterministic test/modeling adapter boundary ───────────────────────────

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct DeterministicFuzzTarget {
    pub name: String,
    pub category: FuzzCategory,
    pub description: String,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeterministicSeedOutcome {
    /// The input should be handled without crash.
    Handled,
    /// The input should be rejected (but not crash).
    Rejected,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct DeterministicFuzzSeed {
    pub target: String,
    pub input_data: String,
    pub expected: DeterministicSeedOutcome,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct DeterministicFuzzCampaignResult {
    pub target: String,
    pub seeds_run: usize,
    pub crashes: usize,
    pub hangs: usize,
    pub coverage_pct: f64,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct DeterministicTriagedCrash {
    pub target: String,
    pub seed_input: String,
    pub error: String,
    pub reproducer: String,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct DeterministicFuzzGateReport {
    pub adapter_kind: String,
    pub execution_mode: String,
    pub runner_detail: String,
    pub target_results: Vec<DeterministicFuzzCampaignResult>,
    pub triaged_crashes: Vec<DeterministicTriagedCrash>,
    pub verdict: String,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    /// FCG_MISSING_TARGET
    MissingTarget(String),
    /// FCG_INSUFFICIENT_CORPUS
    InsufficientCorpus {
        target: String,
        have: usize,
        need: usize,
    },
    /// FCG_REGRESSION
    Regression { target: String, seed: String },
    /// FCG_UNTRIAGED_CRASH
    UntriagedCrash { target: String, seed: String },
    /// FCG_GATE_FAILED
    GateFailed(String),
}

impl FuzzError {
    pub fn code(&self) -> &'static str {
        match self {
            FuzzError::MissingTarget(_) => "FCG_MISSING_TARGET",
            FuzzError::InsufficientCorpus { .. } => "FCG_INSUFFICIENT_CORPUS",
            FuzzError::Regression { .. } => "FCG_REGRESSION",
            FuzzError::UntriagedCrash { .. } => "FCG_UNTRIAGED_CRASH",
            FuzzError::GateFailed(_) => "FCG_GATE_FAILED",
        }
    }
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzError::MissingTarget(t) => write!(f, "FCG_MISSING_TARGET: {t}"),
            FuzzError::InsufficientCorpus { target, have, need } => {
                write!(
                    f,
                    "FCG_INSUFFICIENT_CORPUS: {target} have={have} need={need}"
                )
            }
            FuzzError::Regression { target, seed } => {
                write!(f, "FCG_REGRESSION: {target} seed={seed}")
            }
            FuzzError::UntriagedCrash { target, seed } => {
                write!(f, "FCG_UNTRIAGED_CRASH: {target} seed={seed}")
            }
            FuzzError::GateFailed(d) => write!(f, "FCG_GATE_FAILED: {d}"),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct DeterministicFuzzTestAdapter {
    targets: BTreeMap<String, DeterministicFuzzTarget>,
    seeds: BTreeMap<String, Vec<DeterministicFuzzSeed>>,
    min_seeds: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl DeterministicFuzzTestAdapter {
    pub fn new(min_seeds: usize) -> Self {
        Self {
            targets: BTreeMap::new(),
            seeds: BTreeMap::new(),
            min_seeds,
        }
    }

    /// Register a deterministic fixture target.
    pub fn add_target(&mut self, target: DeterministicFuzzTarget) {
        self.targets.insert(target.name.clone(), target);
    }

    /// Add a deterministic fixture seed to a target's corpus.
    pub fn add_seed(&mut self, seed: DeterministicFuzzSeed) -> Result<(), FuzzError> {
        if !self.targets.contains_key(&seed.target) {
            return Err(FuzzError::MissingTarget(seed.target.clone()));
        }
        self.seeds
            .entry(seed.target.clone())
            .or_default()
            .push(seed);
        Ok(())
    }

    /// Validate that all required categories have deterministic fixture coverage.
    pub fn validate(&self) -> Result<(), FuzzError> {
        let required = [
            FuzzCategory::ParserInput,
            FuzzCategory::HandshakeReplay,
            FuzzCategory::TokenValidation,
            FuzzCategory::DecodeDos,
        ];

        for cat in &required {
            let found = self.targets.values().any(|t| t.category == *cat);
            if !found {
                return Err(FuzzError::MissingTarget(cat.to_string()));
            }
        }

        for name in self.targets.keys() {
            let count = self.seeds.get(name).map_or(0, |s| s.len());
            if count < self.min_seeds {
                return Err(FuzzError::InsufficientCorpus {
                    target: name.clone(),
                    have: count,
                    need: self.min_seeds,
                });
            }
        }

        Ok(())
    }

    /// Execute the allowlisted synthetic fixture adapter.
    ///
    /// This must never be confused with real fuzz evidence. The returned
    /// payload carries explicit markers that the execution was deterministic
    /// and synthetic.
    pub fn run_fixture_gate(&self) -> DeterministicFuzzGateReport {
        let mut results = Vec::new();
        let mut triaged_crashes = Vec::new();

        for (target_name, seeds) in &self.seeds {
            let mut crashes = 0;
            for seed in seeds {
                // The deterministic fixture adapter uses a deliberate
                // string-trigger convention rather than empirical execution.
                if seed.input_data.contains("crash") {
                    crashes += 1;
                    triaged_crashes.push(DeterministicTriagedCrash {
                        target: target_name.clone(),
                        seed_input: seed.input_data.clone(),
                        error: format!("simulated crash ({DETERMINISTIC_FIXTURE_EXECUTION_MODE})"),
                        reproducer: serde_json::json!({
                            "target": target_name,
                            "input": seed.input_data,
                            "fixture_mode": DETERMINISTIC_FIXTURE_EXECUTION_MODE,
                        })
                        .to_string(),
                    });
                }
            }
            results.push(DeterministicFuzzCampaignResult {
                target: target_name.clone(),
                seeds_run: seeds.len(),
                crashes,
                hangs: 0,
                coverage_pct: 0.0,
            });
        }

        let verdict = if triaged_crashes.is_empty() {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        DeterministicFuzzGateReport {
            adapter_kind: DETERMINISTIC_FIXTURE_ADAPTER_KIND.to_string(),
            execution_mode: DETERMINISTIC_FIXTURE_EXECUTION_MODE.to_string(),
            runner_detail: DETERMINISTIC_FIXTURE_RUNNER_DETAIL.to_string(),
            target_results: results,
            triaged_crashes,
            verdict,
        }
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn seed_count(&self, target: &str) -> usize {
        self.seeds.get(target).map_or(0, |s| s.len())
    }
}

// ── Truthful live adapter/reporting surface ────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzTargetDescriptor {
    pub target_id: String,
    pub category: String,
    pub adapter_kind: String,
    pub execution_ref: String,
    pub working_directory: String,
    pub timeout_policy_ms: u64,
    pub coverage_mode: String,
    pub supports_remote_execution: bool,
    pub supported_artifact_kinds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzCoverageObservation {
    pub coverage_pct: Option<f64>,
    pub coverage_units: String,
    pub coverage_source: String,
    pub coverage_scope: String,
    pub coverage_status: String,
    pub coverage_detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzArtifactRef {
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_location: String,
    pub artifact_digest: String,
    pub produced_by: String,
    pub created_at: String,
    pub is_remote: bool,
    pub retention_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterHealth {
    pub adapter_kind: String,
    pub discovered_targets: usize,
    pub coverage_reports: usize,
    pub corpus_roots: Vec<String>,
    pub healthy: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SeedExecutionResult {
    pub target_id: String,
    pub seed_id: String,
    pub seed_digest: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
    pub outcome: String,
    pub exit_detail: String,
    pub crash_artifact: Option<FuzzArtifactRef>,
    pub hang_artifact: Option<FuzzArtifactRef>,
    pub coverage: Option<FuzzCoverageObservation>,
    pub artifact_refs: Vec<FuzzArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzExecutionReport {
    pub campaign_id: String,
    pub adapter_kind: String,
    pub target: FuzzTargetDescriptor,
    pub seed_results: Vec<SeedExecutionResult>,
    pub artifact_refs: Vec<FuzzArtifactRef>,
    pub coverage_summary: Option<FuzzCoverageObservation>,
    pub health: AdapterHealth,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriagedFailure {
    pub target_id: String,
    pub seed_id: String,
    pub seed_digest: String,
    pub outcome: String,
    pub classifier: String,
    pub detail: String,
    pub artifact_refs: Vec<FuzzArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetExecutionSummary {
    pub target_id: String,
    pub category: String,
    pub outcome: String,
    pub seeds_run: usize,
    pub crashes: usize,
    pub hangs: usize,
    pub coverage: Option<FuzzCoverageObservation>,
    pub artifact_refs: Vec<FuzzArtifactRef>,
    pub adapter_detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthfulFuzzGateReport {
    pub report_schema_version: String,
    pub campaign_id: String,
    pub adapter_kind: String,
    pub targets_total: usize,
    pub targets_executed: usize,
    pub seeds_total: usize,
    pub seeds_executed: usize,
    pub targets: Vec<TargetExecutionSummary>,
    pub triaged_failures: Vec<TriagedFailure>,
    pub artifact_refs: Vec<FuzzArtifactRef>,
    pub coverage_summary: Vec<FuzzCoverageObservation>,
    pub verdict: String,
    pub error_detail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LiveBudgetConfig {
    migration: LiveBudgetSection,
    shim: LiveBudgetSection,
}

#[derive(Debug, Deserialize)]
struct LiveBudgetSection {
    min_seconds_per_target: u64,
    targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoverageFixture {
    target: String,
    corpus_size: usize,
    lines_covered: usize,
    lines_total: usize,
    coverage_pct: f64,
    new_paths_found: usize,
    crashes_found: usize,
    event_code: String,
    timestamp: String,
}

#[derive(Debug, Clone)]
struct PreparedSeed {
    seed_id: String,
    seed_digest: String,
    bytes: Vec<u8>,
    artifact_ref: FuzzArtifactRef,
}

#[derive(Debug, Clone)]
struct PreparedCoverage {
    observation: FuzzCoverageObservation,
    artifact_ref: Option<FuzzArtifactRef>,
}

#[derive(Debug, Clone)]
struct PreparedFuzzCampaign {
    target: FuzzTargetDescriptor,
    seeds: Vec<PreparedSeed>,
    coverage: PreparedCoverage,
}

struct TargetDispatch {
    outcome: &'static str,
    detail: String,
}

impl TargetDispatch {
    fn handled(detail: impl Into<String>) -> Self {
        Self {
            outcome: "handled",
            detail: detail.into(),
        }
    }

    fn rejected(detail: impl Into<String>) -> Self {
        Self {
            outcome: "rejected",
            detail: detail.into(),
        }
    }

    fn crash(detail: impl Into<String>) -> Self {
        Self {
            outcome: "crash",
            detail: detail.into(),
        }
    }
}

impl TruthfulFuzzGateReport {
    fn discovery_error(detail: impl Into<String>) -> Self {
        Self {
            report_schema_version: REPORT_SCHEMA_VERSION.to_string(),
            campaign_id: "fcg-live-discovery-error".to_string(),
            adapter_kind: LIVE_ADAPTER_KIND.to_string(),
            targets_total: 0,
            targets_executed: 0,
            seeds_total: 0,
            seeds_executed: 0,
            targets: Vec::new(),
            triaged_failures: Vec::new(),
            artifact_refs: Vec::new(),
            coverage_summary: Vec::new(),
            verdict: "ERROR".to_string(),
            error_detail: Some(detail.into()),
        }
    }
}

pub fn default_truthful_fuzz_repo_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

pub fn discover_truthful_fuzz_targets(
    repo_root: impl AsRef<Path>,
) -> Result<Vec<FuzzTargetDescriptor>, String> {
    let repo_root = repo_root.as_ref();
    let config = load_live_budget_config(repo_root)?;
    let mut targets = Vec::new();

    for (category, section) in [("migration", &config.migration), ("shim", &config.shim)] {
        for slug in &section.targets {
            let target_id = format!("{category}_{slug}");
            let execution_ref = format!("fuzz/targets/{target_id}.rs");
            let target_path = repo_root.join(&execution_ref);
            if !target_path.is_file() {
                return Err(format!(
                    "missing target definition `{}`",
                    execution_ref.replace('\\', "/")
                ));
            }

            targets.push(FuzzTargetDescriptor {
                target_id,
                category: category.to_string(),
                adapter_kind: LIVE_ADAPTER_KIND.to_string(),
                execution_ref,
                working_directory: "fuzz".to_string(),
                timeout_policy_ms: DEFAULT_LIVE_TIMEOUT_MS
                    .max(section.min_seconds_per_target.max(1) * 1_000),
                coverage_mode: "category_fixture_report".to_string(),
                supports_remote_execution: false,
                supported_artifact_kinds: vec![
                    "corpus_seed".to_string(),
                    "regression_seed".to_string(),
                    "coverage_report".to_string(),
                ],
            });
        }
    }

    targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    if targets.is_empty() {
        return Err("fuzz/config/fuzz_budget.toml resolved zero active targets".to_string());
    }
    Ok(targets)
}

pub fn run_truthful_fuzz_gate(repo_root: impl AsRef<Path>) -> TruthfulFuzzGateReport {
    let repo_root = repo_root.as_ref();
    let targets = match discover_truthful_fuzz_targets(repo_root) {
        Ok(targets) => targets,
        Err(error) => return TruthfulFuzzGateReport::discovery_error(error),
    };
    let campaign_id = compute_campaign_id(&targets);
    let health = build_adapter_health(&targets);
    let mut reports = Vec::new();
    let mut preparation_errors = Vec::new();

    for target in &targets {
        match prepare_truthful_campaign(repo_root, target) {
            Ok(prepared) => {
                reports.push(execute_truthful_campaign(&campaign_id, &health, prepared))
            }
            Err(error) => preparation_errors.push((target.clone(), error)),
        }
    }

    aggregate_truthful_reports(
        &campaign_id,
        &health,
        targets.len(),
        reports,
        preparation_errors,
    )
}

fn load_live_budget_config(repo_root: &Path) -> Result<LiveBudgetConfig, String> {
    let path = repo_root.join("fuzz/config/fuzz_budget.toml");
    let content = fs::read_to_string(&path).map_err(|error| {
        format!(
            "failed to read {}: {error}",
            relative_path(repo_root, &path)
        )
    })?;
    toml::from_str(&content).map_err(|error| {
        format!(
            "failed to parse {}: {error}",
            relative_path(repo_root, &path)
        )
    })
}

fn validate_fuzz_category(category: &str) -> Result<(), String> {
    // Reject path traversal attempts
    if category.contains("..") {
        return Err("fuzz category contains path traversal segments".to_string());
    }

    // Reject absolute paths
    if category.starts_with('/') {
        return Err("fuzz category must be relative".to_string());
    }

    // Reject backslashes (Windows path separators that could enable traversal)
    if category.contains('\\') {
        return Err("fuzz category contains invalid path separators".to_string());
    }

    // Reject null bytes (path injection)
    if category.contains('\0') {
        return Err("fuzz category contains null bytes".to_string());
    }

    Ok(())
}

fn prepare_truthful_campaign(
    repo_root: &Path,
    target: &FuzzTargetDescriptor,
) -> Result<PreparedFuzzCampaign, String> {
    // Validate category before using it in path construction
    validate_fuzz_category(&target.category)?;

    let mut seeds = read_seed_directory(
        repo_root,
        &format!("fuzz/corpus/{}", target.category),
        "corpus_seed",
    )?;
    seeds.extend(read_seed_directory(
        repo_root,
        &format!("fuzz/regression/{}", target.category),
        "regression_seed",
    )?);
    seeds.sort_by(|left, right| left.seed_id.cmp(&right.seed_id));
    if seeds.is_empty() {
        return Err(format!(
            "target `{}` has no executable seeds",
            target.target_id
        ));
    }

    Ok(PreparedFuzzCampaign {
        target: target.clone(),
        seeds,
        coverage: load_category_coverage(repo_root, &target.category),
    })
}

fn execute_truthful_campaign(
    campaign_id: &str,
    health: &AdapterHealth,
    prepared: PreparedFuzzCampaign,
) -> FuzzExecutionReport {
    let mut artifact_refs = BTreeMap::new();
    let mut seed_results = Vec::new();

    if let Some(coverage_artifact) = prepared.coverage.artifact_ref.clone() {
        artifact_refs.insert(coverage_artifact.artifact_id.clone(), coverage_artifact);
    }

    for seed in prepared.seeds {
        artifact_refs.insert(
            seed.artifact_ref.artifact_id.clone(),
            seed.artifact_ref.clone(),
        );

        let started_at = current_timestamp();
        let started = Instant::now();
        let dispatched = catch_unwind(AssertUnwindSafe(|| {
            dispatch_target(&prepared.target.target_id, &seed.bytes)
        }));
        let duration_ms = started.elapsed().as_millis() as u64;
        let completed_at = current_timestamp();

        let (outcome, exit_detail, crash_artifact, hang_artifact) = match dispatched {
            Ok(Ok(dispatch)) => {
                if duration_ms > prepared.target.timeout_policy_ms {
                    (
                        "hang".to_string(),
                        format!(
                            "duration_ms={duration_ms} exceeded timeout_policy_ms={}",
                            prepared.target.timeout_policy_ms
                        ),
                        None,
                        Some(seed.artifact_ref.clone()),
                    )
                } else {
                    (dispatch.outcome.to_string(), dispatch.detail, None, None)
                }
            }
            Ok(Err(error)) => ("infra_failed".to_string(), error, None, None),
            Err(_) => (
                "crash".to_string(),
                "panic during in-process target execution".to_string(),
                Some(seed.artifact_ref.clone()),
                None,
            ),
        };

        let mut per_seed_artifacts = vec![seed.artifact_ref.clone()];
        if let Some(coverage_artifact) = prepared.coverage.artifact_ref.clone() {
            per_seed_artifacts.push(coverage_artifact);
        }
        if let Some(crash_artifact_ref) = crash_artifact.clone() {
            per_seed_artifacts.push(crash_artifact_ref);
        }
        if let Some(hang_artifact_ref) = hang_artifact.clone() {
            per_seed_artifacts.push(hang_artifact_ref);
        }

        seed_results.push(SeedExecutionResult {
            target_id: prepared.target.target_id.clone(),
            seed_id: seed.seed_id,
            seed_digest: seed.seed_digest,
            started_at,
            completed_at,
            duration_ms,
            outcome,
            exit_detail,
            crash_artifact,
            hang_artifact,
            coverage: Some(prepared.coverage.observation.clone()),
            artifact_refs: dedup_artifacts(per_seed_artifacts),
        });
    }

    FuzzExecutionReport {
        campaign_id: campaign_id.to_string(),
        adapter_kind: LIVE_ADAPTER_KIND.to_string(),
        target: prepared.target,
        seed_results,
        artifact_refs: artifact_refs.into_values().collect(),
        coverage_summary: Some(prepared.coverage.observation),
        health: health.clone(),
    }
}

fn aggregate_truthful_reports(
    campaign_id: &str,
    health: &AdapterHealth,
    targets_total: usize,
    reports: Vec<FuzzExecutionReport>,
    preparation_errors: Vec<(FuzzTargetDescriptor, String)>,
) -> TruthfulFuzzGateReport {
    let mut targets = Vec::new();
    let mut triaged_failures = Vec::new();
    let mut artifact_refs = BTreeMap::new();
    let mut coverage_summary = BTreeMap::new();
    let mut error_details = Vec::new();

    for report in &reports {
        for artifact in &report.artifact_refs {
            artifact_refs.insert(artifact.artifact_id.clone(), artifact.clone());
        }
        if let Some(coverage) = &report.coverage_summary {
            coverage_summary
                .entry(coverage.coverage_scope.clone())
                .or_insert_with(|| coverage.clone());
        }

        let crashes = report
            .seed_results
            .iter()
            .filter(|result| result.outcome == "crash")
            .count();
        let hangs = report
            .seed_results
            .iter()
            .filter(|result| result.outcome == "hang")
            .count();
        let infra_failed = report
            .seed_results
            .iter()
            .any(|result| result.outcome == "infra_failed" || result.outcome == "target_missing");
        let coverage_unavailable = report
            .coverage_summary
            .as_ref()
            .is_some_and(|coverage| coverage.coverage_status == "unavailable");
        let outcome = if infra_failed || coverage_unavailable {
            "error"
        } else if crashes > 0 || hangs > 0 {
            "fail"
        } else {
            "pass"
        };

        if outcome == "error" {
            let execution_error_detail = report
                .seed_results
                .iter()
                .find(|result| {
                    result.outcome == "infra_failed" || result.outcome == "target_missing"
                })
                .map(|result| result.exit_detail.as_str());
            let coverage_error_detail = report
                .coverage_summary
                .as_ref()
                .map(|coverage| coverage.coverage_detail.as_str());
            error_details.push(format!(
                "{}: {}",
                report.target.target_id,
                execution_error_detail
                    .or(coverage_error_detail)
                    .unwrap_or("execution infrastructure failure")
            ));
        }

        for result in report
            .seed_results
            .iter()
            .filter(|result| result.outcome == "crash" || result.outcome == "hang")
        {
            triaged_failures.push(TriagedFailure {
                target_id: result.target_id.clone(),
                seed_id: result.seed_id.clone(),
                seed_digest: result.seed_digest.clone(),
                outcome: result.outcome.clone(),
                classifier: if result.outcome == "crash" {
                    "seed_crash".to_string()
                } else {
                    "timeout".to_string()
                },
                detail: result.exit_detail.clone(),
                artifact_refs: result.artifact_refs.clone(),
            });
        }

        targets.push(TargetExecutionSummary {
            target_id: report.target.target_id.clone(),
            category: report.target.category.clone(),
            outcome: outcome.to_string(),
            seeds_run: report.seed_results.len(),
            crashes,
            hangs,
            coverage: report.coverage_summary.clone(),
            artifact_refs: report.artifact_refs.clone(),
            adapter_detail: format!(
                "adapter_kind={} healthy={} coverage_status={}",
                report.adapter_kind,
                health.healthy,
                report
                    .coverage_summary
                    .as_ref()
                    .map(|coverage| coverage.coverage_status.as_str())
                    .unwrap_or("unavailable")
            ),
        });
    }

    for (target, error) in preparation_errors {
        error_details.push(format!("{}: {error}", target.target_id));
        targets.push(TargetExecutionSummary {
            target_id: target.target_id,
            category: target.category,
            outcome: "error".to_string(),
            seeds_run: 0,
            crashes: 0,
            hangs: 0,
            coverage: None,
            artifact_refs: Vec::new(),
            adapter_detail: error,
        });
    }

    targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    triaged_failures.sort_by(|left, right| {
        left.target_id
            .cmp(&right.target_id)
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });

    let any_error = targets.iter().any(|target| target.outcome == "error");
    let any_fail = targets.iter().any(|target| target.outcome == "fail");
    let verdict = if any_error {
        "ERROR"
    } else if any_fail {
        "FAIL"
    } else {
        "PASS"
    };
    let seeds_total: usize = reports.iter().map(|report| report.seed_results.len()).sum();
    let seeds_executed = reports
        .iter()
        .flat_map(|report| report.seed_results.iter())
        .filter(|result| result.outcome != "target_missing")
        .count();

    TruthfulFuzzGateReport {
        report_schema_version: REPORT_SCHEMA_VERSION.to_string(),
        campaign_id: campaign_id.to_string(),
        adapter_kind: LIVE_ADAPTER_KIND.to_string(),
        targets_total,
        targets_executed: reports.len(),
        seeds_total,
        seeds_executed,
        targets,
        triaged_failures,
        artifact_refs: artifact_refs.into_values().collect(),
        coverage_summary: coverage_summary.into_values().collect(),
        verdict: verdict.to_string(),
        error_detail: if error_details.is_empty() {
            None
        } else {
            Some(error_details.join("; "))
        },
    }
}

fn build_adapter_health(targets: &[FuzzTargetDescriptor]) -> AdapterHealth {
    let mut corpus_roots = targets
        .iter()
        .map(|target| format!("fuzz/corpus/{}", target.category))
        .collect::<Vec<_>>();
    corpus_roots.sort();
    corpus_roots.dedup();

    AdapterHealth {
        adapter_kind: LIVE_ADAPTER_KIND.to_string(),
        discovered_targets: targets.len(),
        coverage_reports: 2,
        corpus_roots,
        healthy: true,
        detail: "discovered targets from fuzz/config/fuzz_budget.toml".to_string(),
    }
}

fn read_seed_directory(
    repo_root: &Path,
    relative_dir: &str,
    artifact_kind: &str,
) -> Result<Vec<PreparedSeed>, String> {
    let dir = repo_root.join(relative_dir);
    if !dir.is_dir() {
        return Err(format!(
            "missing seed directory `{}`",
            relative_path(repo_root, &dir)
        ));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(&dir)
        .map_err(|error| format!("failed to read {}: {error}", relative_path(repo_root, &dir)))?
    {
        let entry = entry.map_err(|error| {
            format!("failed to read {}: {error}", relative_path(repo_root, &dir))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "failed to read {}: {error}",
                relative_path(repo_root, &path)
            )
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_file() {
            paths.push(path);
        }
    }
    paths.sort();

    let mut seeds = Vec::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|error| {
            format!(
                "failed to read {}: {error}",
                relative_path(repo_root, &path)
            )
        })?;
        let digest = sha256_hex(&bytes);
        let rel_path = relative_path(repo_root, &path);
        seeds.push(PreparedSeed {
            seed_id: rel_path.clone(),
            seed_digest: digest.clone(),
            bytes,
            artifact_ref: FuzzArtifactRef {
                artifact_id: format!("{artifact_kind}:{digest}"),
                artifact_kind: artifact_kind.to_string(),
                artifact_location: rel_path,
                artifact_digest: digest,
                produced_by: "checked_in_fuzz_fixture".to_string(),
                created_at: file_created_at(&path),
                is_remote: false,
                retention_hint: if artifact_kind == "regression_seed" {
                    "permanent".to_string()
                } else {
                    "tracked_fixture".to_string()
                },
            },
        });
    }

    Ok(seeds)
}

fn load_category_coverage(repo_root: &Path, category: &str) -> PreparedCoverage {
    let relative_path_str = format!("fuzz/coverage/latest_{category}.json");
    let path = repo_root.join(&relative_path_str);
    let unavailable = |detail: String| PreparedCoverage {
        observation: FuzzCoverageObservation {
            coverage_pct: None,
            coverage_units: "lines".to_string(),
            coverage_source: "checked_in_fuzz_fixture".to_string(),
            coverage_scope: format!("category:{category}"),
            coverage_status: "unavailable".to_string(),
            coverage_detail: detail,
        },
        artifact_ref: None,
    };

    let content = match fs::read(&path) {
        Ok(content) => content,
        Err(error) => {
            return unavailable(format!(
                "expected coverage report `{relative_path_str}` is missing or unreadable: {error}"
            ));
        }
    };
    let report: CoverageFixture = match serde_json::from_slice(&content) {
        Ok(report) => report,
        Err(error) => {
            return unavailable(format!(
                "coverage report `{relative_path_str}` is invalid JSON: {error}"
            ));
        }
    };

    if report.event_code != "FZT-004" {
        return unavailable(format!(
            "coverage report `{relative_path_str}` has unexpected event_code `{}`",
            report.event_code
        ));
    }

    let digest = sha256_hex(&content);
    PreparedCoverage {
        observation: FuzzCoverageObservation {
            coverage_pct: Some(report.coverage_pct),
            coverage_units: "lines".to_string(),
            coverage_source: "checked_in_fuzz_fixture".to_string(),
            coverage_scope: format!("category:{category}"),
            coverage_status: "measured".to_string(),
            coverage_detail: format!(
                "target={} corpus_size={} lines={}/{} new_paths={} crashes_found={} timestamp={}",
                report.target,
                report.corpus_size,
                report.lines_covered,
                report.lines_total,
                report.new_paths_found,
                report.crashes_found,
                report.timestamp
            ),
        },
        artifact_ref: Some(FuzzArtifactRef {
            artifact_id: format!("coverage:{category}:{digest}"),
            artifact_kind: "coverage_report".to_string(),
            artifact_location: relative_path_str,
            artifact_digest: digest,
            produced_by: "checked_in_fuzz_fixture".to_string(),
            created_at: file_created_at(&path),
            is_remote: false,
            retention_hint: "baseline".to_string(),
        }),
    }
}

fn dispatch_target(target_id: &str, bytes: &[u8]) -> Result<TargetDispatch, String> {
    match target_id {
        "migration_dependency_resolve" => Ok(
            match migration_dependency_resolve_target::fuzz_dependency_resolve(bytes) {
                migration_dependency_resolve_target::FuzzResult::Ok => {
                    TargetDispatch::handled("ok")
                }
                migration_dependency_resolve_target::FuzzResult::InvalidInput => {
                    TargetDispatch::rejected("invalid_input")
                }
                migration_dependency_resolve_target::FuzzResult::Rejected(reason) => {
                    TargetDispatch::rejected(format!("rejected:{reason}"))
                }
                migration_dependency_resolve_target::FuzzResult::Crash(reason) => {
                    TargetDispatch::crash(reason)
                }
            },
        ),
        "migration_directory_scan" => Ok(
            match migration_directory_scan_target::fuzz_directory_scan(bytes) {
                migration_directory_scan_target::FuzzResult::Ok => TargetDispatch::handled("ok"),
                migration_directory_scan_target::FuzzResult::InvalidInput => {
                    TargetDispatch::rejected("invalid_input")
                }
                migration_directory_scan_target::FuzzResult::Rejected(reason) => {
                    TargetDispatch::rejected(format!("rejected:{reason}"))
                }
                migration_directory_scan_target::FuzzResult::Crash(reason) => {
                    TargetDispatch::crash(reason)
                }
            },
        ),
        "migration_package_parse" => Ok(
            match migration_package_parse_target::fuzz_package_parse(bytes) {
                migration_package_parse_target::FuzzResult::Ok => TargetDispatch::handled("ok"),
                migration_package_parse_target::FuzzResult::InvalidInput => {
                    TargetDispatch::rejected("invalid_input")
                }
                migration_package_parse_target::FuzzResult::Rejected(reason) => {
                    TargetDispatch::rejected(format!("rejected:{reason}"))
                }
                migration_package_parse_target::FuzzResult::Crash(reason) => {
                    TargetDispatch::crash(reason)
                }
            },
        ),
        "shim_api_translation" => Ok(
            match shim_api_translation_target::fuzz_api_translation(bytes) {
                shim_api_translation_target::FuzzResult::Ok => TargetDispatch::handled("ok"),
                shim_api_translation_target::FuzzResult::InvalidInput => {
                    TargetDispatch::rejected("invalid_input")
                }
                shim_api_translation_target::FuzzResult::Rejected(reason) => {
                    TargetDispatch::rejected(format!("rejected:{reason}"))
                }
                shim_api_translation_target::FuzzResult::Crash(reason) => {
                    TargetDispatch::crash(reason)
                }
            },
        ),
        "shim_type_coercion" => Ok(match shim_type_coercion_target::fuzz_type_coercion(bytes) {
            shim_type_coercion_target::FuzzResult::Ok => TargetDispatch::handled("ok"),
            shim_type_coercion_target::FuzzResult::InvalidInput => {
                TargetDispatch::rejected("invalid_input")
            }
            shim_type_coercion_target::FuzzResult::Rejected(reason) => {
                TargetDispatch::rejected(format!("rejected:{reason}"))
            }
            shim_type_coercion_target::FuzzResult::Crash(reason) => TargetDispatch::crash(reason),
        }),
        other => Err(format!("unsupported truthful fuzz target `{other}`")),
    }
}

fn compute_campaign_id(targets: &[FuzzTargetDescriptor]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"truthful_fuzz_gate_v1:");
    for target in targets {
        hasher.update(target.target_id.as_bytes());
        hasher.update([0]);
    }
    let digest = sha256_hex(&hasher.finalize());
    format!("fcg-live-{}", &digest[..12])
}

fn dedup_artifacts(mut artifacts: Vec<FuzzArtifactRef>) -> Vec<FuzzArtifactRef> {
    let mut deduped = BTreeMap::new();
    for artifact in artifacts.drain(..) {
        deduped.insert(artifact.artifact_id.clone(), artifact);
    }
    deduped.into_values().collect()
}

fn current_timestamp() -> String {
    Utc::now().to_rfc3339()
}

fn file_created_at(path: &Path) -> String {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map(|modified| DateTime::<Utc>::from(modified).to_rfc3339())
        .unwrap_or_else(|_| current_timestamp())
}

fn relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_target(name: &str, cat: FuzzCategory) -> DeterministicFuzzTarget {
        DeterministicFuzzTarget {
            name: name.to_string(),
            category: cat,
            description: format!("test target {name}"),
        }
    }

    fn make_seed(
        target: &str,
        input: &str,
        outcome: DeterministicSeedOutcome,
    ) -> DeterministicFuzzSeed {
        DeterministicFuzzSeed {
            target: target.to_string(),
            input_data: input.to_string(),
            expected: outcome,
        }
    }

    fn populated_fixture_adapter() -> DeterministicFuzzTestAdapter {
        let mut c = DeterministicFuzzTestAdapter::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        c.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        c.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));
        c.add_target(make_target("dos_fuzz", FuzzCategory::DecodeDos));

        for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
            for i in 0..3 {
                c.add_seed(make_seed(
                    target,
                    &format!("input_{i}"),
                    DeterministicSeedOutcome::Handled,
                ))
                .unwrap();
            }
        }
        c
    }

    #[test]
    fn validate_complete_corpus() {
        let c = populated_fixture_adapter();
        c.validate().unwrap();
    }

    #[test]
    fn reject_missing_category() {
        let mut c = DeterministicFuzzTestAdapter::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        // Missing 3 categories
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), "FCG_MISSING_TARGET");
    }

    #[test]
    fn reject_insufficient_seeds() {
        let mut c = DeterministicFuzzTestAdapter::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        c.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        c.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));
        c.add_target(make_target("dos_fuzz", FuzzCategory::DecodeDos));
        // Only 1 seed for parser_fuzz
        c.add_seed(make_seed(
            "parser_fuzz",
            "x",
            DeterministicSeedOutcome::Handled,
        ))
        .unwrap();
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), "FCG_INSUFFICIENT_CORPUS");
    }

    #[test]
    fn seed_to_missing_target() {
        let c = DeterministicFuzzTestAdapter::new(3);
        let err = !c.seeds.contains_key("no_such");
        assert!(err);
        let mut c2 = DeterministicFuzzTestAdapter::new(3);
        let err = c2
            .add_seed(make_seed("no_such", "x", DeterministicSeedOutcome::Handled))
            .unwrap_err();
        assert_eq!(err.code(), "FCG_MISSING_TARGET");
    }

    #[test]
    fn fixture_gate_pass_no_crashes() {
        let c = populated_fixture_adapter();
        let verdict = c.run_fixture_gate();
        assert_eq!(verdict.verdict, "PASS");
        assert!(verdict.triaged_crashes.is_empty());
    }

    #[test]
    fn fixture_gate_fail_with_crash() {
        let mut c = populated_fixture_adapter();
        c.add_seed(make_seed(
            "parser_fuzz",
            "crash_input",
            DeterministicSeedOutcome::Rejected,
        ))
        .unwrap();
        let verdict = c.run_fixture_gate();
        assert_eq!(verdict.verdict, "FAIL");
        assert!(!verdict.triaged_crashes.is_empty());
    }

    #[test]
    fn fixture_gate_reports_explicit_synthetic_markers() {
        let c = populated_fixture_adapter();
        let verdict = c.run_fixture_gate();
        assert_eq!(
            verdict.adapter_kind,
            DETERMINISTIC_FIXTURE_ADAPTER_KIND.to_string()
        );
        assert_eq!(
            verdict.execution_mode,
            DETERMINISTIC_FIXTURE_EXECUTION_MODE.to_string()
        );
        assert!(verdict.runner_detail.contains("fixture_marker"));
    }

    #[test]
    fn target_and_seed_counts() {
        let c = populated_fixture_adapter();
        assert_eq!(c.target_count(), 4);
        assert_eq!(c.seed_count("parser_fuzz"), 3);
        assert_eq!(c.seed_count("no_such"), 0);
    }

    #[test]
    fn category_display() {
        assert_eq!(FuzzCategory::ParserInput.to_string(), "parser_input");
        assert_eq!(
            FuzzCategory::HandshakeReplay.to_string(),
            "handshake_replay"
        );
        assert_eq!(
            FuzzCategory::TokenValidation.to_string(),
            "token_validation"
        );
        assert_eq!(FuzzCategory::DecodeDos.to_string(), "decode_dos");
    }

    #[test]
    fn error_display() {
        let e = FuzzError::MissingTarget("t".into());
        assert!(e.to_string().contains("FCG_MISSING_TARGET"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            FuzzError::MissingTarget("x".into()),
            FuzzError::InsufficientCorpus {
                target: "x".into(),
                have: 1,
                need: 3,
            },
            FuzzError::Regression {
                target: "x".into(),
                seed: "s".into(),
            },
            FuzzError::UntriagedCrash {
                target: "x".into(),
                seed: "s".into(),
            },
            FuzzError::GateFailed("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"FCG_MISSING_TARGET"));
        assert!(codes.contains(&"FCG_INSUFFICIENT_CORPUS"));
        assert!(codes.contains(&"FCG_REGRESSION"));
        assert!(codes.contains(&"FCG_UNTRIAGED_CRASH"));
        assert!(codes.contains(&"FCG_GATE_FAILED"));
    }

    #[test]
    fn triaged_crash_has_reproducer() {
        let tc = DeterministicTriagedCrash {
            target: "parser_fuzz".into(),
            seed_input: "bad_data".into(),
            error: "simulated crash (synthetic_test_fixture)".into(),
            reproducer: "{\"target\":\"parser_fuzz\",\"fixture_mode\":\"synthetic_test_fixture\"}"
                .into(),
        };
        assert!(tc.reproducer.contains("parser_fuzz"));
        assert!(tc.reproducer.contains("synthetic_test_fixture"));
    }

    fn write_file(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, content).expect("write file");
    }

    fn minimal_truthful_repo() -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/config/fuzz_budget.toml"),
            br#"
[migration]
min_seconds_per_target = 1
targets = ["directory_scan"]

[shim]
min_seconds_per_target = 1
targets = ["api_translation"]
"#,
        );
        write_file(
            &dir.path().join("fuzz/targets/migration_directory_scan.rs"),
            b"// checked by discovery only\n",
        );
        write_file(
            &dir.path().join("fuzz/targets/shim_api_translation.rs"),
            b"// checked by discovery only\n",
        );
        write_file(
            &dir.path().join("fuzz/corpus/migration/valid_path.txt"),
            b"src/main.rs",
        );
        write_file(
            &dir.path().join("fuzz/corpus/shim/valid_call.json"),
            br#"{"method":"getStatus","params":[]}"#,
        );
        write_file(
            &dir.path().join("fuzz/regression/migration/crash_01.bin"),
            b"src/lib.rs",
        );
        write_file(
            &dir.path().join("fuzz/regression/shim/crash_02.bin"),
            br#"{"method":"list","params":[]}"#,
        );
        dir
    }

    #[test]
    fn truthful_discovery_fails_closed_on_missing_target_definition() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/config/fuzz_budget.toml"),
            br#"
[migration]
min_seconds_per_target = 1
targets = ["directory_scan"]

[shim]
min_seconds_per_target = 1
targets = ["api_translation"]
"#,
        );
        write_file(
            &dir.path().join("fuzz/targets/migration_directory_scan.rs"),
            b"// present\n",
        );

        let error = discover_truthful_fuzz_targets(dir.path()).expect_err("must fail closed");
        assert!(error.contains("missing target definition"));
        assert!(error.contains("fuzz/targets/shim_api_translation.rs"));
    }

    #[test]
    fn truthful_discovery_rejects_missing_budget_config() {
        let dir = tempdir().expect("tempdir");

        let error = discover_truthful_fuzz_targets(dir.path()).expect_err("must fail closed");

        assert!(error.contains("failed to read"));
        assert!(error.contains("fuzz/config/fuzz_budget.toml"));
    }

    #[test]
    fn truthful_discovery_rejects_malformed_budget_toml() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/config/fuzz_budget.toml"),
            b"[migration\nmin_seconds_per_target = nope\n",
        );

        let error = discover_truthful_fuzz_targets(dir.path()).expect_err("must fail closed");

        assert!(error.contains("failed to parse"));
        assert!(error.contains("fuzz/config/fuzz_budget.toml"));
    }

    #[test]
    fn truthful_discovery_rejects_zero_active_targets() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/config/fuzz_budget.toml"),
            br#"
[migration]
min_seconds_per_target = 1
targets = []

[shim]
min_seconds_per_target = 1
targets = []
"#,
        );

        let error = discover_truthful_fuzz_targets(dir.path()).expect_err("must fail closed");

        assert!(error.contains("resolved zero active targets"));
    }

    #[test]
    fn read_seed_directory_rejects_missing_directory() {
        let dir = tempdir().expect("tempdir");

        let error = read_seed_directory(dir.path(), "fuzz/corpus/missing", "corpus_seed")
            .expect_err("missing seed root must fail closed");

        assert!(error.contains("missing seed directory"));
        assert!(error.contains("fuzz/corpus/missing"));
    }

    #[test]
    fn coverage_fixture_invalid_json_is_unavailable() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/coverage/latest_migration.json"),
            b"{invalid-json",
        );

        let coverage = load_category_coverage(dir.path(), "migration");

        assert_eq!(coverage.observation.coverage_status, "unavailable");
        assert!(coverage.artifact_ref.is_none());
        assert!(
            coverage
                .observation
                .coverage_detail
                .contains("invalid JSON")
        );
    }

    #[test]
    fn coverage_fixture_wrong_event_code_is_unavailable() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/coverage/latest_shim.json"),
            br#"{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "shim_api_translation",
  "corpus_size": 2,
  "lines_covered": 13,
  "lines_total": 18,
  "coverage_pct": 72.2,
  "new_paths_found": 2,
  "crashes_found": 0,
  "event_code": "FZT-999"
}"#,
        );

        let coverage = load_category_coverage(dir.path(), "shim");

        assert_eq!(coverage.observation.coverage_status, "unavailable");
        assert!(coverage.artifact_ref.is_none());
        assert!(
            coverage
                .observation
                .coverage_detail
                .contains("unexpected event_code")
        );
    }

    #[test]
    fn dispatch_target_rejects_unknown_truthful_target() {
        let error = dispatch_target("unknown_truthful_target", b"{}")
            .expect_err("unknown target must fail closed");

        assert!(error.contains("unsupported truthful fuzz target"));
        assert!(error.contains("unknown_truthful_target"));
    }

    #[test]
    fn aggregate_preparation_error_returns_error_verdict() {
        let health = AdapterHealth {
            adapter_kind: LIVE_ADAPTER_KIND.to_string(),
            discovered_targets: 1,
            coverage_reports: 0,
            corpus_roots: vec!["fuzz/corpus/migration".to_string()],
            healthy: false,
            detail: "fixture health unavailable".to_string(),
        };
        let target = FuzzTargetDescriptor {
            target_id: "migration_directory_scan".to_string(),
            category: "migration".to_string(),
            adapter_kind: LIVE_ADAPTER_KIND.to_string(),
            execution_ref: "fuzz/targets/migration_directory_scan.rs".to_string(),
            working_directory: "fuzz".to_string(),
            timeout_policy_ms: DEFAULT_LIVE_TIMEOUT_MS,
            coverage_mode: "category_fixture_report".to_string(),
            supports_remote_execution: false,
            supported_artifact_kinds: vec!["corpus_seed".to_string()],
        };

        let report = aggregate_truthful_reports(
            "fcg-test",
            &health,
            1,
            Vec::new(),
            vec![(
                target,
                "missing seed directory `fuzz/corpus/migration`".to_string(),
            )],
        );

        assert_eq!(report.verdict, "ERROR");
        assert_eq!(report.targets_total, 1);
        assert_eq!(report.targets_executed, 0);
        assert_eq!(report.seeds_executed, 0);
        assert_eq!(report.targets[0].outcome, "error");
        assert!(
            report
                .error_detail
                .as_deref()
                .expect("error detail")
                .contains("missing seed directory")
        );
    }

    #[test]
    fn truthful_gate_marks_missing_coverage_as_error() {
        let dir = minimal_truthful_repo();
        let report = run_truthful_fuzz_gate(dir.path());
        assert_eq!(report.verdict, "ERROR");
        assert!(
            report
                .error_detail
                .as_deref()
                .expect("error detail")
                .contains("expected coverage report")
        );
        assert!(
            report
                .targets
                .iter()
                .all(|target| target.outcome == "error")
        );
    }

    #[test]
    fn truthful_gate_uses_explicit_measured_coverage_semantics() {
        let dir = minimal_truthful_repo();
        write_file(
            &dir.path().join("fuzz/coverage/latest_migration.json"),
            br#"{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "migration_directory_scan",
  "corpus_size": 2,
  "lines_covered": 19,
  "lines_total": 24,
  "coverage_pct": 79.1,
  "new_paths_found": 1,
  "crashes_found": 0,
  "event_code": "FZT-004"
}"#,
        );
        write_file(
            &dir.path().join("fuzz/coverage/latest_shim.json"),
            br#"{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "shim_api_translation",
  "corpus_size": 2,
  "lines_covered": 13,
  "lines_total": 18,
  "coverage_pct": 72.2,
  "new_paths_found": 2,
  "crashes_found": 0,
  "event_code": "FZT-004"
}"#,
        );

        let report = run_truthful_fuzz_gate(dir.path());
        assert_eq!(report.verdict, "PASS");
        assert_eq!(report.targets_total, 2);
        assert_eq!(report.targets_executed, 2);
        assert!(report.triaged_failures.is_empty());
        assert!(report.coverage_summary.iter().all(|coverage| {
            coverage.coverage_status == "measured" && coverage.coverage_pct.unwrap_or(0.0) > 0.0
        }));
    }

    fn negative_truthful_target(target_id: &str, category: &str) -> FuzzTargetDescriptor {
        FuzzTargetDescriptor {
            target_id: target_id.to_string(),
            category: category.to_string(),
            adapter_kind: LIVE_ADAPTER_KIND.to_string(),
            execution_ref: format!("fuzz/targets/{target_id}.rs"),
            working_directory: "fuzz".to_string(),
            timeout_policy_ms: DEFAULT_LIVE_TIMEOUT_MS,
            coverage_mode: "category_fixture_report".to_string(),
            supports_remote_execution: false,
            supported_artifact_kinds: vec!["corpus_seed".to_string()],
        }
    }

    fn negative_measured_coverage(category: &str) -> FuzzCoverageObservation {
        FuzzCoverageObservation {
            coverage_pct: Some(72.5),
            coverage_units: "lines".to_string(),
            coverage_source: "checked_in_fuzz_fixture".to_string(),
            coverage_scope: format!("category:{category}"),
            coverage_status: "measured".to_string(),
            coverage_detail: "measured fixture coverage".to_string(),
        }
    }

    fn negative_seed_artifact(seed_id: &str) -> FuzzArtifactRef {
        let digest = sha256_hex(seed_id.as_bytes());
        FuzzArtifactRef {
            artifact_id: format!("corpus_seed:{digest}"),
            artifact_kind: "corpus_seed".to_string(),
            artifact_location: format!("fuzz/corpus/migration/{seed_id}"),
            artifact_digest: digest,
            produced_by: "negative-test-fixture".to_string(),
            created_at: "2026-02-20T12:00:00Z".to_string(),
            is_remote: false,
            retention_hint: "tracked_fixture".to_string(),
        }
    }

    fn negative_execution_report(outcome: &str, exit_detail: &str) -> FuzzExecutionReport {
        let target = negative_truthful_target("migration_directory_scan", "migration");
        let coverage = negative_measured_coverage("migration");
        let artifact = negative_seed_artifact("seed-negative");
        let seed_result = SeedExecutionResult {
            target_id: target.target_id.clone(),
            seed_id: "seed-negative".to_string(),
            seed_digest: artifact.artifact_digest.clone(),
            started_at: "2026-02-20T12:00:00Z".to_string(),
            completed_at: "2026-02-20T12:00:01Z".to_string(),
            duration_ms: if outcome == "hang" {
                DEFAULT_LIVE_TIMEOUT_MS.saturating_add(1)
            } else {
                1
            },
            outcome: outcome.to_string(),
            exit_detail: exit_detail.to_string(),
            crash_artifact: if outcome == "crash" {
                Some(artifact.clone())
            } else {
                None
            },
            hang_artifact: if outcome == "hang" {
                Some(artifact.clone())
            } else {
                None
            },
            coverage: Some(coverage.clone()),
            artifact_refs: vec![artifact.clone()],
        };

        FuzzExecutionReport {
            campaign_id: "fcg-negative".to_string(),
            adapter_kind: LIVE_ADAPTER_KIND.to_string(),
            target,
            seed_results: vec![seed_result],
            artifact_refs: vec![artifact],
            coverage_summary: Some(coverage),
            health: AdapterHealth {
                adapter_kind: LIVE_ADAPTER_KIND.to_string(),
                discovered_targets: 1,
                coverage_reports: 1,
                corpus_roots: vec!["fuzz/corpus/migration".to_string()],
                healthy: true,
                detail: "negative fixture health".to_string(),
            },
        }
    }

    #[test]
    fn fixture_gate_reproducer_escapes_json_metacharacters() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);
        adapter.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        let input = "crash_\"quoted\"\n{\"nested\":true}";
        adapter
            .add_seed(make_seed(
                "parser_fuzz",
                input,
                DeterministicSeedOutcome::Rejected,
            ))
            .unwrap();

        let report = adapter.run_fixture_gate();

        assert_eq!(report.verdict, "FAIL");
        let crash = report
            .triaged_crashes
            .first()
            .expect("crash seed should be triaged");
        let parsed: serde_json::Value =
            serde_json::from_str(&crash.reproducer).expect("reproducer should be valid JSON");
        assert_eq!(parsed["target"].as_str(), Some("parser_fuzz"));
        assert_eq!(parsed["input"].as_str(), Some(input));
        assert_eq!(
            parsed["fixture_mode"].as_str(),
            Some(DETERMINISTIC_FIXTURE_EXECUTION_MODE)
        );
    }

    #[test]
    fn validate_registered_target_with_zero_seeds_reports_insufficient_corpus() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);
        adapter.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        adapter.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        adapter.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));
        adapter.add_target(make_target("dos_fuzz", FuzzCategory::DecodeDos));

        let err = adapter.validate().unwrap_err();

        match err {
            FuzzError::InsufficientCorpus { have, need, .. } => {
                assert_eq!(have, 0);
                assert_eq!(need, 1);
            }
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[test]
    fn validate_reports_missing_decode_dos_category_before_seed_counts() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);
        adapter.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        adapter.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        adapter.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));

        let err = adapter.validate().unwrap_err();

        assert_eq!(err, FuzzError::MissingTarget("decode_dos".to_string()));
    }

    #[test]
    fn truthful_discovery_rejects_missing_shim_budget_section() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/config/fuzz_budget.toml"),
            br#"
[migration]
min_seconds_per_target = 1
targets = ["directory_scan"]
"#,
        );

        let error = discover_truthful_fuzz_targets(dir.path()).expect_err("must fail closed");

        assert!(error.contains("failed to parse"));
        assert!(error.contains("shim"));
    }

    #[test]
    fn coverage_fixture_missing_event_code_is_unavailable() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/coverage/latest_migration.json"),
            br#"{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "migration_directory_scan",
  "corpus_size": 2,
  "lines_covered": 19,
  "lines_total": 24,
  "coverage_pct": 79.1,
  "new_paths_found": 1,
  "crashes_found": 0
}"#,
        );

        let coverage = load_category_coverage(dir.path(), "migration");

        assert_eq!(coverage.observation.coverage_status, "unavailable");
        assert!(coverage.artifact_ref.is_none());
        assert!(
            coverage
                .observation
                .coverage_detail
                .contains("missing field")
        );
        assert!(coverage.observation.coverage_detail.contains("event_code"));
    }

    #[test]
    fn aggregate_hang_creates_timeout_triage_without_error_detail() {
        let report = negative_execution_report("hang", "duration exceeded timeout");
        let health = report.health.clone();

        let aggregate =
            aggregate_truthful_reports("fcg-negative", &health, 1, vec![report], Vec::new());

        assert_eq!(aggregate.verdict, "FAIL");
        assert!(aggregate.error_detail.is_none());
        assert_eq!(aggregate.triaged_failures.len(), 1);
        assert_eq!(aggregate.triaged_failures[0].classifier, "timeout");
        assert_eq!(aggregate.triaged_failures[0].outcome, "hang");
    }

    #[test]
    fn aggregate_infra_failure_uses_seed_exit_detail_for_error_detail() {
        let report = negative_execution_report("infra_failed", "target binary unavailable");
        let health = report.health.clone();

        let aggregate =
            aggregate_truthful_reports("fcg-negative", &health, 1, vec![report], Vec::new());

        assert_eq!(aggregate.verdict, "ERROR");
        assert!(aggregate.triaged_failures.is_empty());
        let detail = aggregate.error_detail.as_deref().expect("error detail");
        assert!(detail.contains("migration_directory_scan"));
        assert!(detail.contains("target binary unavailable"));
        assert!(!detail.contains("measured fixture coverage"));
    }

    #[test]
    fn add_seed_preserves_missing_target_name_in_error() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);

        let err = adapter
            .add_seed(make_seed(
                "missing_target",
                "seed",
                DeterministicSeedOutcome::Handled,
            ))
            .unwrap_err();

        assert_eq!(err, FuzzError::MissingTarget("missing_target".to_string()));
    }

    #[test]
    fn fixture_gate_triages_each_crash_seed_for_same_target() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);
        adapter.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        for input in ["crash_one", "prefix_crash_two"] {
            adapter
                .add_seed(make_seed(
                    "parser_fuzz",
                    input,
                    DeterministicSeedOutcome::Rejected,
                ))
                .unwrap();
        }

        let report = adapter.run_fixture_gate();

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.triaged_crashes.len(), 2);
        assert_eq!(report.target_results[0].crashes, 2);
    }

    #[test]
    fn fixture_gate_does_not_promote_rejected_fixture_without_crash_marker() {
        let mut adapter = DeterministicFuzzTestAdapter::new(1);
        adapter.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        adapter
            .add_seed(make_seed(
                "parser_fuzz",
                "invalid_but_non_crashing",
                DeterministicSeedOutcome::Rejected,
            ))
            .unwrap();

        let report = adapter.run_fixture_gate();

        assert_eq!(report.verdict, "PASS");
        assert!(report.triaged_crashes.is_empty());
        assert_eq!(report.target_results[0].crashes, 0);
    }

    #[test]
    fn prepare_truthful_campaign_rejects_empty_seed_roots() {
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("fuzz/corpus/migration")).unwrap();
        fs::create_dir_all(dir.path().join("fuzz/regression/migration")).unwrap();
        let target = negative_truthful_target("migration_directory_scan", "migration");

        let error =
            prepare_truthful_campaign(dir.path(), &target).expect_err("empty roots must fail");

        assert!(error.contains("has no executable seeds"));
        assert!(error.contains("migration_directory_scan"));
    }

    #[test]
    fn prepare_truthful_campaign_rejects_missing_regression_seed_root() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/corpus/migration/seed.txt"),
            b"src/main.rs",
        );
        let target = negative_truthful_target("migration_directory_scan", "migration");

        let error =
            prepare_truthful_campaign(dir.path(), &target).expect_err("missing root must fail");

        assert!(error.contains("missing seed directory"));
        assert!(error.contains("fuzz/regression/migration"));
    }

    #[test]
    fn coverage_fixture_type_mismatch_is_unavailable() {
        let dir = tempdir().expect("tempdir");
        write_file(
            &dir.path().join("fuzz/coverage/latest_migration.json"),
            br#"{
  "timestamp": "2026-02-20T12:00:00Z",
  "target": "migration_directory_scan",
  "corpus_size": "two",
  "lines_covered": 19,
  "lines_total": 24,
  "coverage_pct": 79.1,
  "new_paths_found": 1,
  "crashes_found": 0,
  "event_code": "FZT-004"
}"#,
        );

        let coverage = load_category_coverage(dir.path(), "migration");

        assert_eq!(coverage.observation.coverage_status, "unavailable");
        assert!(coverage.artifact_ref.is_none());
        assert!(
            coverage
                .observation
                .coverage_detail
                .contains("invalid JSON")
        );
    }

    #[test]
    fn aggregate_crash_creates_seed_crash_triage_without_error_detail() {
        let report = negative_execution_report("crash", "panic during target execution");
        let health = report.health.clone();

        let aggregate =
            aggregate_truthful_reports("fcg-negative", &health, 1, vec![report], Vec::new());

        assert_eq!(aggregate.verdict, "FAIL");
        assert!(aggregate.error_detail.is_none());
        assert_eq!(aggregate.triaged_failures.len(), 1);
        assert_eq!(aggregate.triaged_failures[0].classifier, "seed_crash");
        assert_eq!(aggregate.triaged_failures[0].outcome, "crash");
    }

    #[test]
    fn aggregate_target_missing_marks_seed_as_not_executed() {
        let report = negative_execution_report(
            "target_missing",
            "unsupported truthful fuzz target `missing`",
        );
        let health = report.health.clone();

        let aggregate =
            aggregate_truthful_reports("fcg-negative", &health, 1, vec![report], Vec::new());

        assert_eq!(aggregate.verdict, "ERROR");
        assert_eq!(aggregate.seeds_total, 1);
        assert_eq!(aggregate.seeds_executed, 0);
        assert_eq!(aggregate.targets[0].outcome, "error");
        let detail = aggregate.error_detail.as_deref().expect("error detail");
        assert!(detail.contains("unsupported truthful fuzz target"));
    }

    #[test]
    fn validate_fuzz_category_rejects_path_traversal() {
        // Test rejection of .. segments
        assert!(validate_fuzz_category("../escapes").is_err());
        assert!(validate_fuzz_category("valid/../escapes").is_err());
        assert!(validate_fuzz_category("escapes/..").is_err());
        assert!(validate_fuzz_category("../../etc/passwd").is_err());
    }

    #[test]
    fn validate_fuzz_category_rejects_absolute_paths() {
        // Test rejection of leading slash
        assert!(validate_fuzz_category("/absolute/path").is_err());
        assert!(validate_fuzz_category("/etc/passwd").is_err());
        assert!(validate_fuzz_category("/").is_err());
    }

    #[test]
    fn validate_fuzz_category_rejects_backslashes() {
        // Test rejection of backslashes
        assert!(validate_fuzz_category("windows\\path").is_err());
        assert!(validate_fuzz_category("path\\with\\backslashes").is_err());
        assert!(validate_fuzz_category("\\windows\\absolute").is_err());
    }

    #[test]
    fn validate_fuzz_category_rejects_null_bytes() {
        // Test rejection of null bytes
        assert!(validate_fuzz_category("path\0injection").is_err());
        assert!(validate_fuzz_category("\0null_start").is_err());
        assert!(validate_fuzz_category("null_end\0").is_err());
    }

    #[test]
    fn validate_fuzz_category_accepts_valid_categories() {
        // Test acceptance of valid categories
        assert!(validate_fuzz_category("corpus").is_ok());
        assert!(validate_fuzz_category("regression").is_ok());
        assert!(validate_fuzz_category("valid_category").is_ok());
        assert!(validate_fuzz_category("sub/category").is_ok());
        assert!(validate_fuzz_category("category-with-dashes").is_ok());
        assert!(validate_fuzz_category("category_with_underscores").is_ok());
    }
}
