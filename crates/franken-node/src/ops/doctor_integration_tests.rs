//! Integration tests for workspace pressure doctor output (bd-p9mpd.5).

#[cfg(test)]
mod tests {
    use crate::ops::doctor::{DoctorStatus, WorkspacePressureDoctor};
    use crate::ops::workspace_pressure_policy::{PolicyThresholds, WorkspacePressureInputs};
    use std::path::Path;
    use tempfile::TempDir;

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
        assert!(
            output
                .recommended_actions
                .iter()
                .any(|a| a.priority == "high")
        );
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
        assert!(
            output
                .resources
                .rch_status
                .status_desc
                .contains("saturated")
        );
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
}
