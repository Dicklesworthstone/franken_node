//! bd-p9mpd.4: Workspace build admission and cleanup decision policy.
//!
//! Provides deterministic admission decisions for expensive work and cleanup
//! candidates based on workspace pressure, RCH availability, and resource constraints.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// External dependencies for disk space detection
extern crate fs2;

use crate::push_bounded;

/// Maximum cleanup candidates to suggest in one decision.
const MAX_CLEANUP_CANDIDATES: usize = 100;

/// Maximum diagnostic reasons to track per decision.
const MAX_DIAGNOSTIC_REASONS: usize = 32;

/// Workspace cost classification for different types of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkCostClass {
    /// Validation/proof jobs - moderate cost, RCH beneficial
    Validation,
    /// Fuzzing - high CPU, long duration, good RCH candidate
    Fuzzing,
    /// Benchmark runs - high cost, timing sensitive
    Benchmark,
    /// Documentation gates - low cost, usually local-only
    DocsGate,
    /// One-off source checks - very low cost, local preferred
    SourceOnly,
    /// Full workspace cleanup - I/O intensive
    Cleanup,
}

impl WorkCostClass {
    /// Returns the relative cost weight (higher = more expensive).
    pub const fn cost_weight(self) -> u32 {
        match self {
            Self::SourceOnly => 1,
            Self::DocsGate => 2,
            Self::Validation => 5,
            Self::Benchmark => 8,
            Self::Fuzzing => 10,
            Self::Cleanup => 6,
        }
    }

    /// Returns whether this work type benefits from RCH offloading.
    pub const fn prefers_rch(self) -> bool {
        matches!(
            self,
            Self::Validation | Self::Fuzzing | Self::Benchmark | Self::Cleanup
        )
    }
}

/// Build admission decision from workspace pressure analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionDecision {
    /// Proceed with local execution immediately.
    AllowLocal,
    /// Require RCH offloading for resource management.
    RequireRch,
    /// Queue the work for later execution.
    Queue { retry_after_ms: u32 },
    /// Wait briefly and retry admission decision.
    Wait { retry_after_ms: u32 },
    /// Refuse to use local fallback when RCH unavailable.
    RefuseLocalFallback,
}

/// Cleanup candidate with audit evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupCandidate {
    /// Canonical path to the cleanup target.
    pub path: PathBuf,
    /// Estimated bytes that would be freed.
    pub size_bytes: u64,
    /// Why this is eligible for cleanup.
    pub reason: String,
    /// Whether this requires explicit approval.
    pub requires_approval: bool,
    /// Last modified time (for staleness analysis).
    pub mtime: Option<String>,
}

/// Complete workspace pressure policy decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// The admission decision for the requested work.
    pub admission: AdmissionDecision,
    /// Cleanup candidates identified during analysis.
    pub cleanup_candidates: Vec<CleanupCandidate>,
    /// Machine-readable reason code.
    pub reason_code: String,
    /// Human-readable summary of the decision.
    pub summary: String,
    /// Detailed diagnostic reasons.
    pub diagnostic_reasons: Vec<String>,
    /// Confidence level in the decision (0.0-1.0).
    pub confidence: f32,
}

/// Workspace pressure inputs for policy decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePressureInputs {
    /// Free disk space in bytes.
    pub free_disk_bytes: u64,
    /// Total size of target directories in bytes.
    pub target_dir_bytes: u64,
    /// Number of active cargo/rustc processes.
    pub active_build_count: u32,
    /// RCH queue state (workers available).
    pub rch_available_slots: Option<u32>,
    /// Memory pressure (0.0-1.0, where 1.0 is full).
    pub memory_pressure: f32,
    /// Number of active file reservations.
    pub active_reservations: u32,
    /// Whether Agent Mail coordination is healthy.
    pub coordination_healthy: bool,
}

/// Workspace build admission policy engine.
#[derive(Debug, Clone)]
pub struct WorkspacePressurePolicy {
    /// Configuration thresholds for admission decisions.
    pub thresholds: PolicyThresholds,
}

/// Policy thresholds for workspace pressure decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyThresholds {
    /// Minimum free disk bytes before blocking new work.
    pub min_free_disk_bytes: u64,
    /// Maximum target directory size before cleanup suggestions.
    pub max_target_dir_bytes: u64,
    /// Maximum concurrent builds before RCH requirement.
    pub max_concurrent_builds: u32,
    /// Memory pressure threshold for build restrictions (0.0-1.0).
    pub max_memory_pressure: f32,
    /// Maximum active reservations before coordination warnings.
    pub max_active_reservations: u32,
}

impl PolicyThresholds {
    /// Create conservative default thresholds suitable for shared environments.
    pub fn conservative() -> Self {
        Self {
            min_free_disk_bytes: 1_000_000_000,  // 1GB
            max_target_dir_bytes: 5_000_000_000, // 5GB
            max_concurrent_builds: 3,
            max_memory_pressure: 0.8,
            max_active_reservations: 20,
        }
    }

    /// Create balanced default thresholds for typical development.
    pub fn balanced() -> Self {
        Self {
            min_free_disk_bytes: 500_000_000,     // 500MB
            max_target_dir_bytes: 10_000_000_000, // 10GB
            max_concurrent_builds: 5,
            max_memory_pressure: 0.9,
            max_active_reservations: 50,
        }
    }

    /// Create permissive thresholds for high-capacity environments.
    pub fn permissive() -> Self {
        Self {
            min_free_disk_bytes: 100_000_000,     // 100MB
            max_target_dir_bytes: 50_000_000_000, // 50GB
            max_concurrent_builds: 10,
            max_memory_pressure: 0.95,
            max_active_reservations: 100,
        }
    }
}

impl WorkspacePressurePolicy {
    /// Create a new policy with the given thresholds.
    pub fn new(thresholds: PolicyThresholds) -> Self {
        Self { thresholds }
    }

    /// Create a policy with balanced default thresholds.
    pub fn with_balanced_defaults() -> Self {
        Self::new(PolicyThresholds::balanced())
    }

    /// Make an admission decision for the given work and pressure inputs.
    pub fn decide_admission(
        &self,
        work_class: WorkCostClass,
        priority: u32,
        inputs: &WorkspacePressureInputs,
    ) -> PolicyDecision {
        let mut diagnostic_reasons = Vec::new();
        let mut cleanup_candidates = Vec::new();

        // Analyze disk pressure
        let disk_pressure =
            self.analyze_disk_pressure(inputs, &mut diagnostic_reasons, &mut cleanup_candidates);

        // Analyze build pressure
        let build_pressure = self.analyze_build_pressure(inputs, &mut diagnostic_reasons);

        // Analyze memory pressure
        let memory_pressure = self.analyze_memory_pressure(inputs, &mut diagnostic_reasons);

        // Analyze coordination health
        let coordination_issues = self.analyze_coordination_health(inputs, &mut diagnostic_reasons);

        // Make admission decision based on analysis
        let admission = self.compute_admission_decision(
            work_class,
            priority,
            inputs,
            disk_pressure,
            build_pressure,
            memory_pressure,
            coordination_issues,
            &mut diagnostic_reasons,
        );

        // Compute overall confidence
        let confidence = self.compute_confidence(
            &admission,
            inputs,
            disk_pressure,
            build_pressure,
            memory_pressure,
        );

        // Generate reason code and summary
        let (reason_code, summary) =
            self.generate_reason_and_summary(&admission, work_class, &diagnostic_reasons);

        PolicyDecision {
            admission,
            cleanup_candidates,
            reason_code,
            summary,
            diagnostic_reasons: limit_diagnostics(diagnostic_reasons),
            confidence,
        }
    }

    /// Propose cleanup candidates without requiring work admission.
    pub fn propose_cleanup(&self, inputs: &WorkspacePressureInputs) -> Vec<CleanupCandidate> {
        let mut candidates = Vec::new();

        // Add target directory cleanup candidates if over threshold
        if inputs.target_dir_bytes > self.thresholds.max_target_dir_bytes {
            candidates.push(CleanupCandidate {
                path: "target".into(),
                size_bytes: inputs
                    .target_dir_bytes
                    .saturating_sub(self.thresholds.max_target_dir_bytes / 2),
                reason: "Large target directory detected".to_string(),
                requires_approval: true,
                mtime: None,
            });
        }

        // Add temp file cleanup candidates if disk pressure high
        if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes.saturating_mul(2) {
            if let Ok(temp_size) = estimate_temp_artifacts_size() {
                if temp_size > 100_000_000 {
                    // 100MB
                    candidates.push(CleanupCandidate {
                        path: "/tmp/cargo-*".into(),
                        size_bytes: temp_size,
                        reason: "Temporary cargo artifacts consuming space".to_string(),
                        requires_approval: false,
                        mtime: None,
                    });
                }
            }
        }

        candidates
    }

    fn analyze_disk_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
        cleanup_candidates: &mut Vec<CleanupCandidate>,
    ) -> f32 {
        let disk_pressure = if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes {
            push_bounded(
                diagnostics,
                "Critical disk space shortage".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );

            // Suggest cleanup candidates
            cleanup_candidates.extend(self.propose_cleanup(inputs));

            1.0
        } else if inputs.free_disk_bytes < self.thresholds.min_free_disk_bytes.saturating_mul(2) {
            push_bounded(
                diagnostics,
                "Low disk space warning".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.7
        } else {
            0.0
        };

        if inputs.target_dir_bytes > self.thresholds.max_target_dir_bytes {
            push_bounded(
                diagnostics,
                "Target directories consuming excessive space".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
        }

        disk_pressure
    }

    fn analyze_build_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> f32 {
        if inputs.active_build_count > self.thresholds.max_concurrent_builds {
            push_bounded(
                diagnostics,
                "High concurrent build activity".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.8
        } else if inputs.active_build_count > self.thresholds.max_concurrent_builds / 2 {
            push_bounded(
                diagnostics,
                "Moderate build activity".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            0.4
        } else {
            0.0
        }
    }

    fn analyze_memory_pressure(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> f32 {
        if inputs.memory_pressure > self.thresholds.max_memory_pressure {
            push_bounded(
                diagnostics,
                "High memory pressure detected".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            inputs.memory_pressure
        } else {
            0.0
        }
    }

    fn analyze_coordination_health(
        &self,
        inputs: &WorkspacePressureInputs,
        diagnostics: &mut Vec<String>,
    ) -> bool {
        if !inputs.coordination_healthy {
            push_bounded(
                diagnostics,
                "Agent coordination degraded".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return true;
        }

        if inputs.active_reservations > self.thresholds.max_active_reservations {
            push_bounded(
                diagnostics,
                "High file reservation contention".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return true;
        }

        false
    }

    fn compute_admission_decision(
        &self,
        work_class: WorkCostClass,
        priority: u32,
        inputs: &WorkspacePressureInputs,
        disk_pressure: f32,
        build_pressure: f32,
        memory_pressure: f32,
        coordination_issues: bool,
        diagnostics: &mut Vec<String>,
    ) -> AdmissionDecision {
        // Critical disk pressure blocks most work
        if disk_pressure >= 1.0 && work_class != WorkCostClass::SourceOnly {
            return AdmissionDecision::RefuseLocalFallback;
        }

        // High memory pressure limits work
        if memory_pressure > 0.9 && work_class.cost_weight() > 2 {
            return AdmissionDecision::Queue {
                retry_after_ms: 30000,
            };
        }

        // RCH availability check
        match inputs.rch_available_slots {
            Some(slots) if slots > 0 => {
                // RCH available - use it for expensive work or high pressure
                if work_class.prefers_rch() || build_pressure > 0.5 || disk_pressure > 0.5 {
                    push_bounded(
                        diagnostics,
                        "Offloading to RCH for resource management".to_string(),
                        MAX_DIAGNOSTIC_REASONS,
                    );
                    return AdmissionDecision::RequireRch;
                }
            }
            Some(_) => {
                // RCH saturated
                if work_class.prefers_rch() && (build_pressure > 0.7 || memory_pressure > 0.8) {
                    push_bounded(
                        diagnostics,
                        "RCH saturated, queueing expensive work".to_string(),
                        MAX_DIAGNOSTIC_REASONS,
                    );
                    return AdmissionDecision::Queue {
                        retry_after_ms: 60000,
                    };
                }
            }
            None => {
                // RCH unavailable
                if work_class.prefers_rch() && work_class.cost_weight() > 7 {
                    return AdmissionDecision::RefuseLocalFallback;
                }
            }
        }

        // Coordination issues affect cleanup and high-contention work
        if coordination_issues && matches!(work_class, WorkCostClass::Cleanup) {
            push_bounded(
                diagnostics,
                "Deferring cleanup due to coordination issues".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return AdmissionDecision::Wait {
                retry_after_ms: 10000,
            };
        }

        // High priority work gets preference
        if priority >= 1 && work_class.cost_weight() <= 5 {
            push_bounded(
                diagnostics,
                "High priority work approved for local execution".to_string(),
                MAX_DIAGNOSTIC_REASONS,
            );
            return AdmissionDecision::AllowLocal;
        }

        // Default: allow local for low-cost work, moderate throttling for others
        if work_class.cost_weight() <= 3 || (build_pressure < 0.5 && memory_pressure < 0.7) {
            AdmissionDecision::AllowLocal
        } else {
            AdmissionDecision::Wait {
                retry_after_ms: 15000,
            }
        }
    }

    fn compute_confidence(
        &self,
        admission: &AdmissionDecision,
        inputs: &WorkspacePressureInputs,
        disk_pressure: f32,
        build_pressure: f32,
        memory_pressure: f32,
    ) -> f32 {
        // Higher confidence for clear decisions
        match admission {
            AdmissionDecision::RefuseLocalFallback => {
                if disk_pressure >= 1.0 || memory_pressure > 0.95 {
                    0.95 // Very confident in blocking critical pressure
                } else {
                    0.8
                }
            }
            AdmissionDecision::AllowLocal => {
                if disk_pressure < 0.3 && build_pressure < 0.3 && memory_pressure < 0.5 {
                    0.9 // Very confident in allowing when pressure is low
                } else {
                    0.7
                }
            }
            AdmissionDecision::RequireRch => {
                if inputs.rch_available_slots.is_some() {
                    0.85 // Confident when RCH is actually available
                } else {
                    0.6
                }
            }
            AdmissionDecision::Queue { .. } | AdmissionDecision::Wait { .. } => {
                0.75 // Moderate confidence in throttling decisions
            }
        }
    }

    fn generate_reason_and_summary(
        &self,
        admission: &AdmissionDecision,
        work_class: WorkCostClass,
        diagnostics: &[String],
    ) -> (String, String) {
        let reason_code = match admission {
            AdmissionDecision::AllowLocal => "ADMIT_LOCAL",
            AdmissionDecision::RequireRch => "REQUIRE_RCH",
            AdmissionDecision::Queue { .. } => "QUEUE_PRESSURE",
            AdmissionDecision::Wait { .. } => "WAIT_THROTTLE",
            AdmissionDecision::RefuseLocalFallback => "REFUSE_CRITICAL",
        };

        let summary = match admission {
            AdmissionDecision::AllowLocal => {
                format!("{:?} work approved for local execution", work_class)
            }
            AdmissionDecision::RequireRch => {
                format!("{:?} work requires RCH offloading", work_class)
            }
            AdmissionDecision::Queue { retry_after_ms } => {
                format!(
                    "{:?} work queued, retry after {}ms",
                    work_class, retry_after_ms
                )
            }
            AdmissionDecision::Wait { retry_after_ms } => {
                format!("{:?} work throttled, wait {}ms", work_class, retry_after_ms)
            }
            AdmissionDecision::RefuseLocalFallback => {
                format!("{:?} work refused due to critical pressure", work_class)
            }
        };

        (reason_code.to_string(), summary)
    }
}

/// Estimate size of temporary artifacts for cleanup analysis.
fn estimate_temp_artifacts_size() -> std::io::Result<u64> {
    let mut total: u64 = 0;

    // Check common temp locations
    let temp_patterns = ["/tmp/cargo-*", "/tmp/rust-*", "/tmp/rch-*"];

    for pattern in temp_patterns {
        if let Some(prefix) = pattern.strip_suffix('*') {
            if let Ok(entries) = std::fs::read_dir("/tmp") {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with(&prefix[5..]) {
                            // Remove "/tmp/" prefix
                            if let Ok(size) = calculate_directory_size_safe(&entry.path()) {
                                total = total.saturating_add(size);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(total)
}

/// Safe directory size calculation with bounds checking.
fn calculate_directory_size_safe<P: AsRef<Path>>(path: P) -> std::io::Result<u64> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(0);
    }

    let mut total: u64 = 0;
    const MAX_DEPTH: usize = 10; // Prevent infinite recursion

    fn calculate_recursive(path: &Path, depth: usize, total: &mut u64) -> std::io::Result<()> {
        if depth > MAX_DEPTH {
            return Ok(()); // Truncate very deep trees
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                calculate_recursive(&entry.path(), depth + 1, total)?;
            } else {
                *total = total.saturating_add(metadata.len());
            }

            // Safety check: don't let single operations take too long
            if *total > 100_000_000_000 {
                // 100GB limit
                break;
            }
        }
        Ok(())
    }

    calculate_recursive(path, 0, &mut total)?;
    Ok(total)
}

/// Limit diagnostic messages to prevent memory exhaustion.
fn limit_diagnostics(mut diagnostics: Vec<String>) -> Vec<String> {
    if diagnostics.len() > MAX_DIAGNOSTIC_REASONS {
        diagnostics.truncate(MAX_DIAGNOSTIC_REASONS);
        diagnostics.push("... additional diagnostics truncated".to_string());
    }
    diagnostics
}

/// Get available disk space for the current working directory.
///
/// Uses fs2::available_space to query the filesystem for actual available space.
/// This replaces the hardcoded placeholder value in main.rs with real disk monitoring.
pub fn get_available_disk_space(path: impl AsRef<std::path::Path>) -> std::io::Result<u64> {
    fs2::available_space(path)
}

/// Get available disk space for the current working directory with fallback.
///
/// Returns actual disk space or a conservative fallback if detection fails.
pub fn get_workspace_disk_space() -> Result<u64, Box<dyn std::error::Error>> {
    match get_available_disk_space(".") {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            // Log error but don't fail - return conservative estimate
            eprintln!("Warning: disk space detection failed: {e}. Using conservative estimate.");
            Ok(1_000_000_000) // 1GB conservative fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_cost_classes() {
        assert!(WorkCostClass::SourceOnly.cost_weight() < WorkCostClass::Fuzzing.cost_weight());
        assert!(WorkCostClass::Validation.prefers_rch());
        assert!(!WorkCostClass::SourceOnly.prefers_rch());
    }

    #[test]
    fn test_policy_thresholds() {
        let conservative = PolicyThresholds::conservative();
        let permissive = PolicyThresholds::permissive();

        assert!(conservative.min_free_disk_bytes > permissive.min_free_disk_bytes);
        assert!(conservative.max_concurrent_builds < permissive.max_concurrent_builds);
    }

    #[test]
    fn test_admission_decision_local_low_pressure() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000,
            target_dir_bytes: 1_000_000_000,
            active_build_count: 1,
            rch_available_slots: Some(5),
            memory_pressure: 0.3,
            active_reservations: 5,
            coordination_healthy: true,
        };

        let decision = policy.decide_admission(WorkCostClass::SourceOnly, 2, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::AllowLocal));
        assert!(decision.confidence > 0.8);
    }

    #[test]
    fn test_admission_decision_critical_pressure() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 100_000_000,     // Below threshold
            target_dir_bytes: 15_000_000_000, // Above threshold
            active_build_count: 8,
            rch_available_slots: None,
            memory_pressure: 0.95,
            active_reservations: 75,
            coordination_healthy: false,
        };

        let decision = policy.decide_admission(WorkCostClass::Fuzzing, 1, &inputs);
        assert!(matches!(
            decision.admission,
            AdmissionDecision::RefuseLocalFallback
        ));
        assert!(!decision.cleanup_candidates.is_empty());
    }

    #[test]
    fn test_require_rch_for_expensive_work() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 1_000_000_000,
            target_dir_bytes: 3_000_000_000,
            active_build_count: 4,
            rch_available_slots: Some(3),
            memory_pressure: 0.6,
            active_reservations: 15,
            coordination_healthy: true,
        };

        let decision = policy.decide_admission(WorkCostClass::Benchmark, 1, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::RequireRch));
    }

    #[test]
    fn test_cleanup_candidates_generation() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 200_000_000,     // Low
            target_dir_bytes: 20_000_000_000, // High
            active_build_count: 2,
            rch_available_slots: Some(2),
            memory_pressure: 0.4,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let candidates = policy.propose_cleanup(&inputs);
        assert!(!candidates.is_empty());
        assert!(
            candidates
                .iter()
                .any(|c| c.path.to_string_lossy().contains("target"))
        );
    }

    #[test]
    fn test_coordination_issues_affect_cleanup() {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 1_000_000_000,
            target_dir_bytes: 2_000_000_000,
            active_build_count: 1,
            rch_available_slots: Some(5),
            memory_pressure: 0.3,
            active_reservations: 60, // High
            coordination_healthy: false,
        };

        let decision = policy.decide_admission(WorkCostClass::Cleanup, 1, &inputs);
        assert!(matches!(decision.admission, AdmissionDecision::Wait { .. }));
    }

    #[test]
    fn test_get_available_disk_space() {
        // Test happy path - should return a reasonable value
        let disk_space = get_available_disk_space(".");
        assert!(disk_space.is_ok());
        let bytes = disk_space.unwrap();

        // Sanity check: should be more than 1MB and less than 100TB
        assert!(bytes >= 1_000_000); // At least 1MB
        assert!(bytes <= 100_000_000_000_000); // Less than 100TB
    }

    #[test]
    fn test_get_workspace_disk_space_success() {
        // Test that workspace function returns actual disk space when it works
        let workspace_result = get_workspace_disk_space();
        assert!(workspace_result.is_ok());
        let bytes = workspace_result.unwrap();

        // Should be a reasonable amount (more than 1MB, since we're in a valid workspace)
        assert!(bytes >= 1_000_000);
    }
}
