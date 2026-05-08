//! Integration tests for workspace pressure doctor output (bd-p9mpd.5).

#[cfg(test)]
mod tests {
    use crate::ops::doctor::{DoctorStatus, WorkspacePressureDoctor};
    use crate::ops::workspace_pressure_policy::{
        AdmissionDecision, PolicyDecision, PolicyThresholds, WorkCostClass,
        WorkspacePressureInputs, WorkspacePressurePolicy,
    };
    use serde_json::{json, Value};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const POLICY_DECISION_GOLDEN_RELATIVE_PATH: &str =
        "../../tests/golden/workspace_pressure_policy_decisions.json";
    const POLICY_DECISION_GOLDEN_SCHEMA_VERSION: &str = "bd-p9mpd.4/v1";

    fn sample_healthy_inputs() -> WorkspacePressureInputs {
        WorkspacePressureInputs {
            free_disk_bytes: 10_000_000_000, // 10GB
            target_dir_bytes: 500_000_000,   // 500MB
            active_build_count: 1,
            rch_available_slots: Some(8),
            memory_pressure: 0.2,
            active_reservations: 3,
            coordination_healthy: true,
        }
    }

    fn sample_critical_inputs() -> WorkspacePressureInputs {
        WorkspacePressureInputs {
            free_disk_bytes: 80_000_000,      // 80MB - critical
            target_dir_bytes: 15_000_000_000, // 15GB
            active_build_count: 12,
            rch_available_slots: None, // RCH unavailable
            memory_pressure: 0.96,
            active_reservations: 80,
            coordination_healthy: false,
        }
    }

    #[test]
    fn test_doctor_healthy_scenario() {
        let inputs = sample_healthy_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Healthy);
        assert!(output.summary.contains("low"));
        assert_eq!(output.resources.active_builds, 1);
        assert_eq!(output.resources.memory_pressure, 0.2);
        assert!(output.resources.rch_status.available);
        assert_eq!(output.resources.rch_status.available_slots, Some(8));
        assert_eq!(output.policy_decisions.len(), 6);
        assert!(output.recommended_actions.is_empty());
        assert_eq!(output.metadata.get("rch_available").unwrap(), "true");
    }

    #[test]
    fn test_doctor_critical_scenario() {
        let inputs = sample_critical_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(output.status, DoctorStatus::Critical);
        assert!(output.summary.contains("Critical"));
        assert_eq!(output.resources.active_builds, 12);
        assert_eq!(output.resources.memory_pressure, 0.96);
        assert!(!output.resources.rch_status.available);
        assert!(!output.resources.coordination_healthy);
        assert_eq!(output.policy_decisions.len(), 6);
        assert!(!output.recommended_actions.is_empty());
        assert!(output
            .recommended_actions
            .iter()
            .any(|a| a.priority == "high"));
        assert_eq!(output.metadata.get("rch_available").unwrap(), "false");
    }

    #[test]
    fn test_doctor_with_custom_thresholds() {
        let conservative_thresholds = PolicyThresholds::conservative();
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 800_000_000,    // 800MB
            target_dir_bytes: 2_000_000_000, // 2GB
            active_build_count: 2,
            rch_available_slots: Some(5),
            memory_pressure: 0.5,
            active_reservations: 10,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::with_thresholds(conservative_thresholds);
        let output = doctor.generate_report(&inputs);

        // With conservative thresholds, this should be more restrictive
        assert!(matches!(
            output.status,
            DoctorStatus::Warning | DoctorStatus::Degraded
        ));
        assert_eq!(output.policy_decisions.len(), 6);
    }

    #[test]
    fn test_human_report_formatting() {
        let inputs = sample_healthy_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);
        let human_report = doctor.format_human_report(&output);

        // Check essential sections
        assert!(human_report.contains("Workspace Pressure Report"));
        assert!(human_report.contains("📊 Resource Summary"));
        assert!(human_report.contains("🎯 Policy Decisions"));

        // Check resource formatting
        assert!(human_report.contains("Free Disk: 10.0 GB"));
        assert!(human_report.contains("Target Dir: 500.0 MB"));
        assert!(human_report.contains("Memory Pressure: 20.0%"));
        assert!(human_report.contains("RCH Status: Available (8 slots)"));
        assert!(human_report.contains("Coordination: Healthy"));

        // Check status emoji and formatting
        assert!(human_report.contains("✅")); // Healthy emoji
        assert!(human_report.contains("HEALTHY"));

        // Check policy decisions
        assert!(human_report.contains("SourceOnly:"));
        assert!(human_report.contains("ALLOW_LOCAL"));
        assert!(human_report.contains("confidence:"));
    }

    #[test]
    fn test_human_report_with_recommendations() {
        let inputs = sample_critical_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);
        let human_report = doctor.format_human_report(&output);

        // Check critical status formatting
        assert!(human_report.contains("🚨")); // Critical emoji
        assert!(human_report.contains("CRITICAL"));

        // Check recommendations section appears
        assert!(human_report.contains("🔧 Recommended Actions"));

        // Check resource pressure indicators
        assert!(human_report.contains("Memory Pressure: 96.0%"));
        assert!(human_report.contains("RCH Status: Unavailable"));
        assert!(human_report.contains("Coordination: Degraded"));
    }

    #[test]
    fn test_policy_decision_summary_formatting() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 1_000_000_000,  // 1GB
            target_dir_bytes: 8_000_000_000, // 8GB - high
            active_build_count: 6,
            rch_available_slots: Some(3),
            memory_pressure: 0.75,
            active_reservations: 25,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        // Verify all work classes are covered
        let expected_work_classes = [
            "SourceOnly",
            "DocsGate",
            "Validation",
            "Benchmark",
            "Fuzzing",
            "Cleanup",
        ];
        for work_class in &expected_work_classes {
            assert!(output.policy_decisions.contains_key(*work_class));
            let decision = &output.policy_decisions[*work_class];
            assert_eq!(decision.work_class, *work_class);
            assert!(!decision.admission.is_empty());
            assert!(!decision.reason_code.is_empty());
            assert!(!decision.summary.is_empty());
            assert!(decision.confidence >= 0.0 && decision.confidence <= 1.0);
        }
    }

    #[test]
    fn test_resource_summary_formatting() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 2_147_483_648,  // 2GB exactly
            target_dir_bytes: 1_073_741_824, // 1GB exactly
            active_build_count: 4,
            rch_available_slots: Some(0), // Available but saturated
            memory_pressure: 0.666,       // Test fractional display
            active_reservations: 20,
            coordination_healthy: true,
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        // Check byte formatting
        assert_eq!(output.resources.free_disk_human, "2.0 GB");
        assert_eq!(output.resources.target_dir_human, "1.0 GB");
        assert_eq!(output.resources.active_builds, 4);
        assert_eq!(output.resources.memory_pressure, 0.666);
        assert_eq!(output.resources.active_reservations, 20);

        // Check RCH status for saturated case
        assert!(output.resources.rch_status.available);
        assert_eq!(output.resources.rch_status.available_slots, Some(0));
        assert!(output
            .resources
            .rch_status
            .status_desc
            .contains("saturated"));
    }

    #[test]
    fn test_diagnostic_messages() {
        let inputs = WorkspacePressureInputs {
            free_disk_bytes: 200_000_000,     // Low disk
            target_dir_bytes: 12_000_000_000, // High target dir
            active_build_count: 8,            // High build count
            rch_available_slots: None,        // No RCH
            memory_pressure: 0.9,             // High memory
            active_reservations: 60,          // High reservations
            coordination_healthy: false,      // Coordination issues
        };

        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        // Should have diagnostic messages for various pressure sources
        assert!(!output.diagnostics.is_empty());

        // Check that diagnostics mention the work classes
        let diagnostic_text = output.diagnostics.join(" ");
        assert!(
            diagnostic_text.contains("SourceOnly")
                || diagnostic_text.contains("Validation")
                || diagnostic_text.contains("Cleanup")
        );
    }

    #[test]
    fn test_metadata_population() {
        let inputs = sample_healthy_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        // Check required metadata fields
        assert!(output.metadata.contains_key("total_cleanup_candidates"));
        assert!(output.metadata.contains_key("policy_decisions_count"));
        assert!(output.metadata.contains_key("rch_available"));

        // Verify metadata values
        assert_eq!(output.metadata.get("policy_decisions_count").unwrap(), "6");
        assert_eq!(output.metadata.get("rch_available").unwrap(), "true");

        // Cleanup candidates should be parseable as number
        let cleanup_count = output.metadata.get("total_cleanup_candidates").unwrap();
        assert!(cleanup_count.parse::<usize>().is_ok());
    }

    #[test]
    fn test_schema_version_consistency() {
        let inputs = sample_healthy_inputs();
        let doctor = WorkspacePressureDoctor::new();
        let output = doctor.generate_report(&inputs);

        assert_eq!(
            output.schema_version,
            "franken-node/doctor/workspace-pressure/v1"
        );
        assert!(!output.timestamp.to_rfc3339().is_empty());
    }

    #[test]
    fn workspace_pressure_policy_decision_golden_matches_real_policy() {
        let actual = build_policy_decision_golden();
        let actual_text =
            serde_json::to_string_pretty(&actual).expect("policy golden should serialize");
        let golden_path = policy_decision_golden_path();

        if std::env::var_os("UPDATE_GOLDENS").is_some() {
            fs::write(&golden_path, actual_text).expect("update policy decision golden");
            return;
        }

        let expected_text = fs::read_to_string(&golden_path).unwrap_or_else(|err| {
            panic!(
                "failed to read workspace pressure policy golden at {}: {err}. \
                 Run with UPDATE_GOLDENS=1 to create it.",
                golden_path.display()
            )
        });
        assert_eq!(
            expected_text, actual_text,
            "workspace pressure policy golden drifted from the real policy implementation; \
             rerun this test with UPDATE_GOLDENS=1 only after reviewing the diff"
        );
    }

    #[test]
    fn test_file_generation_integration() {
        let temp_dir = TempDir::new().expect("Should create temp directory");
        let json_path = temp_dir.path().join("doctor_report.json");
        let text_path = temp_dir.path().join("doctor_report.txt");

        let inputs = sample_critical_inputs();

        // Test JSON file generation
        let result = crate::ops::doctor::generate_doctor_report_file(&inputs, &json_path);
        assert!(result.is_ok());
        assert!(json_path.exists());

        let json_content = std::fs::read_to_string(&json_path).expect("Should read JSON file");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_content).expect("Should parse JSON");
        assert_eq!(parsed["status"], "critical");

        // Test human-readable file generation
        let human_result = crate::ops::doctor::generate_human_report_file(&inputs, &text_path);
        assert!(human_result.is_ok());
        assert!(text_path.exists());

        let text_content = std::fs::read_to_string(&text_path).expect("Should read text file");
        assert!(text_content.contains("Workspace Pressure Report"));
        assert!(text_content.contains("CRITICAL"));
    }

    fn policy_decision_golden_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(POLICY_DECISION_GOLDEN_RELATIVE_PATH)
    }

    fn build_policy_decision_golden() -> Value {
        let policy = WorkspacePressurePolicy::with_balanced_defaults();
        let work_types = policy_decision_work_types();
        let mut scenario_values = serde_json::Map::new();
        let mut decision_matrix = Vec::new();

        for (scenario_name, inputs) in policy_decision_scenarios() {
            let mut work_decisions = serde_json::Map::new();

            for (work_class, work_class_name, priority) in &work_types {
                let decision = policy.decide_admission(*work_class, *priority, &inputs);
                let cleanup_candidates = stable_cleanup_candidates(&decision);
                let has_cleanup_candidates = !cleanup_candidates.is_empty();
                let decision_value = json!({
                    "admission": admission_name(&decision.admission),
                    "cleanup_candidates": cleanup_candidates,
                    "confidence": decision.confidence,
                    "reason_code": decision.reason_code.as_str(),
                });

                decision_matrix.push(json!({
                    "decision": admission_name(&decision.admission),
                    "has_cleanup_candidates": has_cleanup_candidates,
                    "priority": priority,
                    "reason_code": decision.reason_code.as_str(),
                    "scenario": scenario_name,
                    "work_class": work_class_name,
                }));
                work_decisions.insert((*work_class_name).to_string(), decision_value);
            }

            scenario_values.insert(
                scenario_name.to_string(),
                json!({
                    "inputs": inputs,
                    "work_decisions": work_decisions,
                }),
            );
        }

        json!({
            "decision_matrix": decision_matrix,
            "description": "Workspace pressure policy decision golden artifacts",
            "scenarios": scenario_values,
            "schema_version": POLICY_DECISION_GOLDEN_SCHEMA_VERSION,
        })
    }

    fn policy_decision_work_types() -> Vec<(WorkCostClass, &'static str, u32)> {
        vec![
            (WorkCostClass::SourceOnly, "SourceOnly", 2),
            (WorkCostClass::DocsGate, "DocsGate", 2),
            (WorkCostClass::Validation, "Validation", 1),
            (WorkCostClass::Benchmark, "Benchmark", 1),
            (WorkCostClass::Fuzzing, "Fuzzing", 1),
            (WorkCostClass::Cleanup, "Cleanup", 3),
        ]
    }

    fn policy_decision_scenarios() -> Vec<(&'static str, WorkspacePressureInputs)> {
        vec![
            (
                "healthy",
                WorkspacePressureInputs {
                    free_disk_bytes: 5_000_000_000,
                    target_dir_bytes: 1_000_000_000,
                    active_build_count: 1,
                    rch_available_slots: Some(8),
                    memory_pressure: 0.3,
                    active_reservations: 5,
                    coordination_healthy: true,
                },
            ),
            (
                "disk_pressure",
                WorkspacePressureInputs {
                    free_disk_bytes: 200_000_000,
                    target_dir_bytes: 12_000_000_000,
                    active_build_count: 2,
                    rch_available_slots: Some(5),
                    memory_pressure: 0.4,
                    active_reservations: 10,
                    coordination_healthy: true,
                },
            ),
            (
                "build_pressure",
                WorkspacePressureInputs {
                    free_disk_bytes: 2_000_000_000,
                    target_dir_bytes: 3_000_000_000,
                    active_build_count: 8,
                    rch_available_slots: Some(2),
                    memory_pressure: 0.7,
                    active_reservations: 15,
                    coordination_healthy: true,
                },
            ),
            (
                "rch_unavailable",
                WorkspacePressureInputs {
                    free_disk_bytes: 1_500_000_000,
                    target_dir_bytes: 2_000_000_000,
                    active_build_count: 3,
                    rch_available_slots: None,
                    memory_pressure: 0.6,
                    active_reservations: 20,
                    coordination_healthy: true,
                },
            ),
            (
                "coordination_degraded",
                WorkspacePressureInputs {
                    free_disk_bytes: 1_000_000_000,
                    target_dir_bytes: 4_000_000_000,
                    active_build_count: 2,
                    rch_available_slots: None,
                    memory_pressure: 0.5,
                    active_reservations: 60,
                    coordination_healthy: false,
                },
            ),
            (
                "critical",
                WorkspacePressureInputs {
                    free_disk_bytes: 50_000_000,
                    target_dir_bytes: 15_000_000_000,
                    active_build_count: 10,
                    rch_available_slots: Some(0),
                    memory_pressure: 0.95,
                    active_reservations: 100,
                    coordination_healthy: false,
                },
            ),
        ]
    }

    fn stable_cleanup_candidates(decision: &PolicyDecision) -> Vec<Value> {
        decision
            .cleanup_candidates
            .iter()
            .filter(|candidate| candidate.path.as_path() == Path::new("target"))
            .map(|candidate| {
                json!({
                    "path": candidate.path.to_string_lossy().to_string(),
                    "reason": candidate.reason.as_str(),
                    "size_bytes": candidate.size_bytes,
                })
            })
            .collect()
    }

    fn admission_name(admission: &AdmissionDecision) -> &'static str {
        match admission {
            AdmissionDecision::AllowLocal => "AllowLocal",
            AdmissionDecision::RequireRch => "RequireRch",
            AdmissionDecision::Queue { .. } => "Queue",
            AdmissionDecision::Wait { .. } => "Wait",
            AdmissionDecision::RefuseLocalFallback => "RefuseLocalFallback",
        }
    }
}
