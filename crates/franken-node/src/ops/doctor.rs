//! bd-p9mpd.5: Doctor output for workspace pressure decisions.
//!
//! Surfaces workspace pressure governance decisions, resource status,
//! and recommended actions in both JSON and human-readable formats for operators.

use crate::ops::workspace_pressure_policy::{
    AdmissionDecision, PolicyDecision, PolicyThresholds, WorkCostClass,
    WorkspacePressureInputs, WorkspacePressurePolicy,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::push_bounded;

/// Maximum diagnostic messages to include in doctor output.
const MAX_DOCTOR_DIAGNOSTICS: usize = 20;

/// Maximum recommended actions to include in doctor output.
const MAX_RECOMMENDED_ACTIONS: usize = 10;

/// Schema version for doctor output format.
pub const DOCTOR_OUTPUT_SCHEMA_VERSION: &str = "franken-node/doctor/workspace-pressure/v1";

/// Doctor output status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    /// All systems healthy, no pressure detected.
    Healthy,
    /// Minor issues detected, monitor but continue operating.
    Warning,
    /// Significant pressure detected, action recommended.
    Degraded,
    /// Critical pressure, immediate action required.
    Critical,
}

impl DoctorStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::Warning => "WARNING",
            Self::Degraded => "DEGRADED",
            Self::Critical => "CRITICAL",
        }
    }

    #[must_use]
    pub const fn emoji(self) -> &'static str {
        match self {
            Self::Healthy => "✅",
            Self::Warning => "⚠️",
            Self::Degraded => "🔶",
            Self::Critical => "🚨",
        }
    }
}

/// Workspace resource summary for doctor output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSummary {
    /// Free disk space in bytes.
    pub free_disk_bytes: u64,
    /// Free disk space as human-readable string.
    pub free_disk_human: String,
    /// Target directory size in bytes.
    pub target_dir_bytes: u64,
    /// Target directory size as human-readable string.
    pub target_dir_human: String,
    /// Active cargo/rustc build processes.
    pub active_builds: u32,
    /// Memory pressure ratio (0.0-1.0).
    pub memory_pressure: f32,
    /// RCH worker availability.
    pub rch_status: RchStatus,
    /// File reservation activity.
    pub active_reservations: u32,
    /// Agent Mail coordination health.
    pub coordination_healthy: bool,
}

/// RCH worker status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RchStatus {
    /// Whether RCH is available.
    pub available: bool,
    /// Number of available worker slots (if known).
    pub available_slots: Option<u32>,
    /// Human-readable status description.
    pub status_desc: String,
}

/// Recommended action for operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    /// Action priority: "high", "medium", "low".
    pub priority: String,
    /// Short action description.
    pub action: String,
    /// Detailed explanation and rationale.
    pub explanation: String,
    /// Command to run (if applicable).
    pub command: Option<String>,
    /// Expected impact description.
    pub impact: String,
}

/// Complete doctor output for workspace pressure status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorOutput {
    /// Schema version for compatibility.
    pub schema_version: String,
    /// Timestamp when this report was generated.
    pub timestamp: DateTime<Utc>,
    /// Overall workspace health status.
    pub status: DoctorStatus,
    /// One-line summary of workspace state.
    pub summary: String,
    /// Resource utilization summary.
    pub resources: ResourceSummary,
    /// Policy decisions for different work classes.
    pub policy_decisions: BTreeMap<String, PolicyDecisionSummary>,
    /// Recommended actions for operator.
    pub recommended_actions: Vec<RecommendedAction>,
    /// Detailed diagnostic messages.
    pub diagnostics: Vec<String>,
    /// Machine-readable metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Summary of policy decision for a work class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionSummary {
    /// Work class name.
    pub work_class: String,
    /// Current admission decision.
    pub admission: String,
    /// Reason for the decision.
    pub reason_code: String,
    /// Human-readable summary.
    pub summary: String,
    /// Decision confidence (0.0-1.0).
    pub confidence: f32,
    /// Number of cleanup candidates available.
    pub cleanup_candidates_count: usize,
}

/// Workspace pressure doctor for generating operator reports.
#[derive(Debug, Clone)]
pub struct WorkspacePressureDoctor {
    /// Policy engine for admission decisions.
    policy: WorkspacePressurePolicy,
}

impl WorkspacePressureDoctor {
    /// Create new doctor with balanced policy thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: WorkspacePressurePolicy::with_balanced_defaults(),
        }
    }

    /// Create new doctor with custom policy thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: PolicyThresholds) -> Self {
        Self {
            policy: WorkspacePressurePolicy::new(thresholds),
        }
    }

    /// Generate complete doctor report for current workspace state.
    pub fn generate_report(&self, inputs: &WorkspacePressureInputs) -> DoctorOutput {
        let timestamp = Utc::now();
        let mut diagnostics = Vec::new();
        let mut recommended_actions = Vec::new();
        let mut metadata = BTreeMap::new();

        // Generate policy decisions for all work classes
        let work_classes = [
            (WorkCostClass::SourceOnly, 3),
            (WorkCostClass::DocsGate, 3),
            (WorkCostClass::Validation, 2),
            (WorkCostClass::Benchmark, 1),
            (WorkCostClass::Fuzzing, 1),
            (WorkCostClass::Cleanup, 2),
        ];

        let mut policy_decisions = BTreeMap::new();
        let mut has_critical_decisions = false;
        let mut has_degraded_decisions = false;
        let mut total_cleanup_candidates = 0;

        for (work_class, priority) in &work_classes {
            let decision = self.policy.decide_admission(*work_class, *priority, inputs);
            let work_class_str = format!("{:?}", work_class);

            // Check for degraded/critical decisions
            match &decision.admission {
                AdmissionDecision::RefuseLocalFallback => has_critical_decisions = true,
                AdmissionDecision::Queue { .. } | AdmissionDecision::Wait { .. } => {
                    has_degraded_decisions = true;
                }
                _ => {}
            }

            total_cleanup_candidates = total_cleanup_candidates.saturating_add(decision.cleanup_candidates.len());

            // Add cleanup recommendations if candidates exist
            if !decision.cleanup_candidates.is_empty() {
                self.add_cleanup_recommendations(
                    &decision,
                    &mut recommended_actions,
                    &work_class_str,
                );
            }

            // Add decision diagnostics
            for diag in &decision.diagnostic_reasons {
                push_bounded(&mut diagnostics, format!("{}: {}", work_class_str, diag), MAX_DOCTOR_DIAGNOSTICS);
            }

            let decision_summary = PolicyDecisionSummary {
                work_class: work_class_str.clone(),
                admission: self.format_admission_decision(&decision.admission),
                reason_code: decision.reason_code,
                summary: decision.summary,
                confidence: decision.confidence,
                cleanup_candidates_count: decision.cleanup_candidates.len(),
            };

            policy_decisions.insert(work_class_str, decision_summary);
        }

        // Generate resource summary
        let resources = self.generate_resource_summary(inputs);

        // Determine overall status
        let status = if has_critical_decisions {
            DoctorStatus::Critical
        } else if has_degraded_decisions || inputs.memory_pressure > 0.8 {
            DoctorStatus::Degraded
        } else if inputs.memory_pressure > 0.6 || total_cleanup_candidates > 0 {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Healthy
        };

        // Generate summary
        let summary = self.generate_summary(&status, inputs, total_cleanup_candidates);

        // Add resource pressure recommendations
        self.add_resource_recommendations(inputs, &mut recommended_actions);

        // Populate metadata
        metadata.insert("total_cleanup_candidates".to_string(), total_cleanup_candidates.to_string());
        metadata.insert("policy_decisions_count".to_string(), policy_decisions.len().to_string());
        metadata.insert("rch_available".to_string(), inputs.rch_available_slots.is_some().to_string());

        DoctorOutput {
            schema_version: DOCTOR_OUTPUT_SCHEMA_VERSION.to_string(),
            timestamp,
            status,
            summary,
            resources,
            policy_decisions,
            recommended_actions,
            diagnostics,
            metadata,
        }
    }

    /// Generate human-readable report text from doctor output.
    pub fn format_human_report(&self, output: &DoctorOutput) -> String {
        let mut report = String::new();

        // Header
        report.push_str(&format!(
            "{} Workspace Pressure Report ({})\n",
            output.status.emoji(),
            output.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        report.push_str(&format!("Status: {} - {}\n\n", output.status.as_str(), output.summary));

        // Resource summary
        report.push_str("📊 Resource Summary:\n");
        report.push_str(&format!("  • Free Disk: {}\n", output.resources.free_disk_human));
        report.push_str(&format!("  • Target Dir: {}\n", output.resources.target_dir_human));
        report.push_str(&format!("  • Active Builds: {}\n", output.resources.active_builds));
        report.push_str(&format!("  • Memory Pressure: {:.1}%\n", output.resources.memory_pressure * 100.0));
        report.push_str(&format!("  • RCH Status: {}\n", output.resources.rch_status.status_desc));
        report.push_str(&format!("  • File Reservations: {}\n", output.resources.active_reservations));
        report.push_str(&format!("  • Coordination: {}\n\n",
            if output.resources.coordination_healthy { "Healthy" } else { "Degraded" }));

        // Policy decisions
        if !output.policy_decisions.is_empty() {
            report.push_str("🎯 Policy Decisions:\n");
            for (_, decision) in &output.policy_decisions {
                let confidence_emoji = if decision.confidence >= 0.9 {
                    "🟢"
                } else if decision.confidence >= 0.7 {
                    "🟡"
                } else {
                    "🔴"
                };
                report.push_str(&format!(
                    "  • {}: {} {} (confidence: {:.0}%)\n",
                    decision.work_class,
                    decision.admission,
                    confidence_emoji,
                    decision.confidence * 100.0
                ));
                if decision.cleanup_candidates_count > 0 {
                    report.push_str(&format!(
                        "    └─ {} cleanup candidates available\n",
                        decision.cleanup_candidates_count
                    ));
                }
            }
            report.push('\n');
        }

        // Recommended actions
        if !output.recommended_actions.is_empty() {
            report.push_str("🔧 Recommended Actions:\n");
            for action in &output.recommended_actions {
                let priority_emoji = match action.priority.as_str() {
                    "high" => "🔴",
                    "medium" => "🟡",
                    "low" => "🟢",
                    _ => "⚪",
                };
                report.push_str(&format!("  {} {}\n", priority_emoji, action.action));
                report.push_str(&format!("    └─ {}\n", action.explanation));
                if let Some(command) = &action.command {
                    report.push_str(&format!("    └─ Run: {}\n", command));
                }
            }
            report.push('\n');
        }

        // Diagnostics (if any significant ones)
        if !output.diagnostics.is_empty() && output.status != DoctorStatus::Healthy {
            report.push_str("🔍 Diagnostics:\n");
            for (i, diag) in output.diagnostics.iter().enumerate() {
                if i >= 5 { // Limit to top 5 for human readability
                    report.push_str(&format!("  ... and {} more\n", output.diagnostics.len() - 5));
                    break;
                }
                report.push_str(&format!("  • {}\n", diag));
            }
            report.push('\n');
        }

        report.push_str(&format!("Generated at {} with {} schema\n",
            output.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            output.schema_version));

        report
    }

    fn generate_resource_summary(&self, inputs: &WorkspacePressureInputs) -> ResourceSummary {
        let rch_status = if let Some(slots) = inputs.rch_available_slots {
            RchStatus {
                available: true,
                available_slots: Some(slots),
                status_desc: if slots == 0 {
                    "Available (saturated)".to_string()
                } else {
                    format!("Available ({} slots)", slots)
                },
            }
        } else {
            RchStatus {
                available: false,
                available_slots: None,
                status_desc: "Unavailable".to_string(),
            }
        };

        ResourceSummary {
            free_disk_bytes: inputs.free_disk_bytes,
            free_disk_human: format_bytes(inputs.free_disk_bytes),
            target_dir_bytes: inputs.target_dir_bytes,
            target_dir_human: format_bytes(inputs.target_dir_bytes),
            active_builds: inputs.active_build_count,
            memory_pressure: inputs.memory_pressure,
            rch_status,
            active_reservations: inputs.active_reservations,
            coordination_healthy: inputs.coordination_healthy,
        }
    }

    fn generate_summary(&self, status: &DoctorStatus, inputs: &WorkspacePressureInputs, cleanup_candidates: usize) -> String {
        match status {
            DoctorStatus::Healthy => {
                "Workspace pressure is low, all systems operating normally".to_string()
            }
            DoctorStatus::Warning => {
                if cleanup_candidates > 0 {
                    format!("Minor resource pressure detected, {} cleanup opportunities available", cleanup_candidates)
                } else {
                    "Minor resource pressure detected, monitoring recommended".to_string()
                }
            }
            DoctorStatus::Degraded => {
                format!("Significant workspace pressure: {:.0}% memory, {} active builds",
                    inputs.memory_pressure * 100.0, inputs.active_build_count)
            }
            DoctorStatus::Critical => {
                if inputs.free_disk_bytes < 100_000_000 { // < 100MB
                    "Critical disk pressure detected, immediate cleanup required".to_string()
                } else {
                    "Critical workspace pressure, blocking high-cost operations".to_string()
                }
            }
        }
    }

    fn format_admission_decision(&self, admission: &AdmissionDecision) -> String {
        match admission {
            AdmissionDecision::AllowLocal => "ALLOW_LOCAL".to_string(),
            AdmissionDecision::RequireRch => "REQUIRE_RCH".to_string(),
            AdmissionDecision::Queue { retry_after_ms } => {
                format!("QUEUE (retry in {}ms)", retry_after_ms)
            }
            AdmissionDecision::Wait { retry_after_ms } => {
                format!("WAIT (retry in {}ms)", retry_after_ms)
            }
            AdmissionDecision::RefuseLocalFallback => "REFUSE_LOCAL_FALLBACK".to_string(),
        }
    }

    fn add_cleanup_recommendations(
        &self,
        decision: &PolicyDecision,
        recommendations: &mut Vec<RecommendedAction>,
        work_class: &str,
    ) {
        if decision.cleanup_candidates.is_empty() {
            return;
        }

        let total_size: u64 = decision.cleanup_candidates.iter().map(|c| c.size_bytes).sum();
        let priority = if total_size > 1_000_000_000 { // > 1GB
            "high"
        } else if total_size > 100_000_000 { // > 100MB
            "medium"
        } else {
            "low"
        };

        let action = RecommendedAction {
            priority: priority.to_string(),
            action: format!("Clean up {} targets for {}", decision.cleanup_candidates.len(), work_class),
            explanation: format!(
                "Remove {} of artifacts to reduce workspace pressure ({})",
                format_bytes(total_size),
                decision.cleanup_candidates[0].reason
            ),
            command: if decision.cleanup_candidates.len() == 1 {
                Some(format!("rm -rf '{}'", decision.cleanup_candidates[0].path.display()))
            } else {
                None
            },
            impact: format!("Free {} of disk space", format_bytes(total_size)),
        };

        push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
    }

    fn add_resource_recommendations(&self, inputs: &WorkspacePressureInputs, recommendations: &mut Vec<RecommendedAction>) {
        // Memory pressure recommendations
        if inputs.memory_pressure > 0.9 {
            let action = RecommendedAction {
                priority: "high".to_string(),
                action: "Reduce memory pressure".to_string(),
                explanation: format!("Memory usage at {:.0}%, close to exhaustion", inputs.memory_pressure * 100.0),
                command: Some("killall -TERM cargo rustc".to_string()),
                impact: "Prevent OOM kills and system instability".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        } else if inputs.memory_pressure > 0.8 {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Monitor memory usage".to_string(),
                explanation: format!("Memory usage at {:.0}%, approaching limits", inputs.memory_pressure * 100.0),
                command: Some("free -h && ps aux --sort=-%mem | head -10".to_string()),
                impact: "Prevent memory exhaustion".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // Build pressure recommendations
        if inputs.active_build_count > 8 {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Reduce concurrent builds".to_string(),
                explanation: format!("{} active builds detected, may cause resource contention", inputs.active_build_count),
                command: Some("pgrep -f 'cargo|rustc' | wc -l".to_string()),
                impact: "Improve build performance and reduce system load".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // RCH recommendations
        if inputs.rch_available_slots.is_none() {
            let action = RecommendedAction {
                priority: "low".to_string(),
                action: "Check RCH availability".to_string(),
                explanation: "RCH workers unavailable, falling back to local builds".to_string(),
                command: Some("rch status".to_string()),
                impact: "Enable build offloading to reduce local resource usage".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }

        // Coordination health recommendations
        if !inputs.coordination_healthy {
            let action = RecommendedAction {
                priority: "medium".to_string(),
                action: "Check Agent Mail coordination".to_string(),
                explanation: "Agent coordination health degraded, may affect file reservations".to_string(),
                command: None,
                impact: "Restore reliable inter-agent coordination".to_string(),
            };
            push_bounded(recommendations, action, MAX_RECOMMENDED_ACTIONS);
        }
    }
}

impl Default for WorkspacePressureDoctor {
    fn default() -> Self {
        Self::new()
    }
}

/// Format byte count as human-readable string.
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx = unit_idx.saturating_add(1);
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

/// Generate doctor report from workspace inputs and write to JSON file.
pub fn generate_doctor_report_file(
    inputs: &WorkspacePressureInputs,
    output_path: &Path,
) -> Result<DoctorOutput, Box<dyn std::error::Error>> {
    let doctor = WorkspacePressureDoctor::new();
    let output = doctor.generate_report(inputs);

    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_path, json)?;

    Ok(output)
}

/// Generate human-readable doctor report and write to text file.
pub fn generate_human_report_file(
    inputs: &WorkspacePressureInputs,
    output_path: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let doctor = WorkspacePressureDoctor::new();
    let output = doctor.generate_report(inputs);
    let human_report = doctor.format_human_report(&output);

    fs::write(output_path, &human_report)?;

    Ok(human_report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_doctor_status_formatting() {
        assert_eq!(DoctorStatus::Healthy.as_str(), "HEALTHY");
        assert_eq!(DoctorStatus::Warning.as_str(), "WARNING");
        assert_eq!(DoctorStatus::Degraded.as_str(), "DEGRADED");
        assert_eq!(DoctorStatus::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn test_doctor_output_healthy_scenario() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 10_000_000_000, // 10GB
            target_dir_bytes: 1_000_000_000,  // 1GB
            active_build_count: 1,
            rch_available_slots: Some(4),
            memory_pressure: 0.3,
            active_reservations: 5,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Healthy);
        assert!(output.summary.contains("low"));
        assert_eq!(output.resources.active_builds, 1);
        assert_eq!(output.policy_decisions.len(), 6);
    }

    #[test]
    fn test_doctor_output_critical_scenario() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 50_000_000,    // 50MB - critical
            target_dir_bytes: 5_000_000_000, // 5GB
            active_build_count: 10,
            rch_available_slots: None,
            memory_pressure: 0.95,
            active_reservations: 50,
            coordination_healthy: false,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Critical);
        assert!(output.summary.contains("Critical"));
        assert!(!output.recommended_actions.is_empty());
        assert!(output.recommended_actions.iter().any(|a| a.priority == "high"));
    }

    #[test]
    fn test_human_report_formatting() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_000_000_000, // 2GB
            target_dir_bytes: 3_000_000_000, // 3GB
            active_build_count: 3,
            rch_available_slots: Some(2),
            memory_pressure: 0.6,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);
        let human_report = doctor.format_human_report(&output);

        assert!(human_report.contains("Workspace Pressure Report"));
        assert!(human_report.contains("📊 Resource Summary"));
        assert!(human_report.contains("🎯 Policy Decisions"));
        assert!(human_report.contains("2.0 GB")); // Free disk formatting
        assert!(human_report.contains("3.0 GB")); // Target dir formatting
        assert!(human_report.contains("60.0%"));  // Memory pressure
    }
}