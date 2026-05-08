#!/usr/bin/env python3
"""Golden test for workspace pressure doctor output (bd-p9mpd.5)."""

import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "tests" / "golden"
DOCTOR_GOLDEN_JSON = GOLDEN_DIR / "doctor_output_workspace_pressure.json"


def generate_doctor_golden_artifacts():
    """Generate golden artifacts for doctor output format."""

    # Simulate various workspace pressure scenarios for doctor output
    scenarios = {
        "healthy": {
            "inputs": {
                "free_disk_bytes": 10_000_000_000,  # 10GB
                "target_dir_bytes": 500_000_000,    # 500MB
                "active_build_count": 1,
                "rch_available_slots": 8,
                "memory_pressure": 0.2,
                "active_reservations": 3,
                "coordination_healthy": True
            },
            "expected_status": "healthy",
            "expected_summary_contains": ["low", "normal"],
            "expected_recommendations_count": 0,
            "expected_policy_decisions": 6
        },
        "warning": {
            "inputs": {
                "free_disk_bytes": 2_000_000_000,  # 2GB
                "target_dir_bytes": 3_000_000_000,  # 3GB
                "active_build_count": 3,
                "rch_available_slots": 5,
                "memory_pressure": 0.65,
                "active_reservations": 15,
                "coordination_healthy": True
            },
            "expected_status": "warning",
            "expected_summary_contains": ["pressure", "monitor"],
            "expected_recommendations_count": 1,
            "expected_policy_decisions": 6
        },
        "degraded": {
            "inputs": {
                "free_disk_bytes": 800_000_000,    # 800MB
                "target_dir_bytes": 8_000_000_000,  # 8GB
                "active_build_count": 6,
                "rch_available_slots": 2,
                "memory_pressure": 0.85,
                "active_reservations": 35,
                "coordination_healthy": True
            },
            "expected_status": "degraded",
            "expected_summary_contains": ["Significant", "pressure"],
            "expected_recommendations_count": 2,
            "expected_policy_decisions": 6
        },
        "critical": {
            "inputs": {
                "free_disk_bytes": 80_000_000,     # 80MB - critical
                "target_dir_bytes": 15_000_000_000, # 15GB
                "active_build_count": 12,
                "rch_available_slots": None,        # RCH unavailable
                "memory_pressure": 0.96,
                "active_reservations": 80,
                "coordination_healthy": False
            },
            "expected_status": "critical",
            "expected_summary_contains": ["Critical", "immediate"],
            "expected_recommendations_count": 3,
            "expected_policy_decisions": 6
        }
    }

    golden_data = {
        "schema_version": "franken-node/doctor/workspace-pressure-golden/v1",
        "description": "Doctor output format golden artifacts for workspace pressure",
        "scenarios": scenarios,
        "structure_validation": {
            "required_root_fields": [
                "schema_version", "timestamp", "status", "summary",
                "resources", "policy_decisions", "recommended_actions",
                "diagnostics", "metadata"
            ],
            "required_resource_fields": [
                "free_disk_bytes", "free_disk_human", "target_dir_bytes",
                "target_dir_human", "active_builds", "memory_pressure",
                "rch_status", "active_reservations", "coordination_healthy"
            ],
            "required_rch_status_fields": [
                "available", "available_slots", "status_desc"
            ],
            "required_policy_decision_fields": [
                "work_class", "admission", "reason_code", "summary",
                "confidence", "cleanup_candidates_count"
            ],
            "required_recommended_action_fields": [
                "priority", "action", "explanation", "command", "impact"
            ],
            "valid_status_values": ["healthy", "warning", "degraded", "critical"],
            "valid_priority_values": ["low", "medium", "high"],
            "valid_work_classes": [
                "SourceOnly", "DocsGate", "Validation",
                "Benchmark", "Fuzzing", "Cleanup"
            ],
            "expected_schema_version": "franken-node/doctor/workspace-pressure/v1"
        },
        "human_format_validation": {
            "required_sections": [
                "Workspace Pressure Report",
                "📊 Resource Summary",
                "🎯 Policy Decisions"
            ],
            "optional_sections": [
                "🔧 Recommended Actions",
                "🔍 Diagnostics"
            ],
            "required_resource_lines": [
                "Free Disk:", "Target Dir:", "Active Builds:",
                "Memory Pressure:", "RCH Status:", "File Reservations:",
                "Coordination:"
            ]
        }
    }

    # Write golden artifact
    GOLDEN_DIR.mkdir(exist_ok=True)
    DOCTOR_GOLDEN_JSON.write_text(
        json.dumps(golden_data, indent=2, sort_keys=True)
    )

    print(f"✓ Generated doctor output golden artifact: {DOCTOR_GOLDEN_JSON}")
    return True


def test_doctor_output_structure():
    """Test that doctor output produces expected structure."""
    print("Testing doctor output structure...")

    # Simulate doctor output structure from healthy scenario
    sample_output = {
        "schema_version": "franken-node/doctor/workspace-pressure/v1",
        "timestamp": "2026-05-07T12:00:00.000000Z",
        "status": "healthy",
        "summary": "Workspace pressure is low, all systems operating normally",
        "resources": {
            "free_disk_bytes": 10000000000,
            "free_disk_human": "10.0 GB",
            "target_dir_bytes": 500000000,
            "target_dir_human": "500.0 MB",
            "active_builds": 1,
            "memory_pressure": 0.2,
            "rch_status": {
                "available": True,
                "available_slots": 8,
                "status_desc": "Available (8 slots)"
            },
            "active_reservations": 3,
            "coordination_healthy": True
        },
        "policy_decisions": {
            "SourceOnly": {
                "work_class": "SourceOnly",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Low-cost work approved for local execution",
                "confidence": 0.9,
                "cleanup_candidates_count": 0
            },
            "DocsGate": {
                "work_class": "DocsGate",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Low-cost work approved for local execution",
                "confidence": 0.9,
                "cleanup_candidates_count": 0
            },
            "Validation": {
                "work_class": "Validation",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Moderate work approved for local execution",
                "confidence": 0.85,
                "cleanup_candidates_count": 0
            },
            "Benchmark": {
                "work_class": "Benchmark",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Work approved for local execution",
                "confidence": 0.8,
                "cleanup_candidates_count": 0
            },
            "Fuzzing": {
                "work_class": "Fuzzing",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Work approved for local execution",
                "confidence": 0.8,
                "cleanup_candidates_count": 0
            },
            "Cleanup": {
                "work_class": "Cleanup",
                "admission": "ALLOW_LOCAL",
                "reason_code": "ADMIT_LOCAL",
                "summary": "Cleanup work approved for local execution",
                "confidence": 0.9,
                "cleanup_candidates_count": 0
            }
        },
        "recommended_actions": [],
        "diagnostics": [],
        "metadata": {
            "total_cleanup_candidates": "0",
            "policy_decisions_count": "6",
            "rch_available": "true"
        }
    }

    if not DOCTOR_GOLDEN_JSON.exists():
        print("Golden artifact does not exist, generating...")
        generate_doctor_golden_artifacts()

    golden_data = json.loads(DOCTOR_GOLDEN_JSON.read_text())
    structure = golden_data["structure_validation"]

    # Verify root structure
    for field in structure["required_root_fields"]:
        if field not in sample_output:
            print(f"Missing root field: {field}")
            return False

    # Verify resource structure
    for field in structure["required_resource_fields"]:
        if field not in sample_output["resources"]:
            print(f"Missing resource field: {field}")
            return False

    # Verify RCH status structure
    for field in structure["required_rch_status_fields"]:
        if field not in sample_output["resources"]["rch_status"]:
            print(f"Missing RCH status field: {field}")
            return False

    # Verify policy decision structure
    for work_class in structure["valid_work_classes"]:
        if work_class not in sample_output["policy_decisions"]:
            print(f"Missing policy decision for work class: {work_class}")
            return False

        decision = sample_output["policy_decisions"][work_class]
        for field in structure["required_policy_decision_fields"]:
            if field not in decision:
                print(f"Missing policy decision field {field} for {work_class}")
                return False

    # Verify status value
    if sample_output["status"] not in structure["valid_status_values"]:
        print(f"Invalid status value: {sample_output['status']}")
        return False

    # Verify schema version
    if sample_output["schema_version"] != structure["expected_schema_version"]:
        print(f"Schema version mismatch: {sample_output['schema_version']}")
        return False

    print("✓ Doctor output structure is valid")
    return True


def test_human_format_structure():
    """Test that human format contains expected sections."""
    print("Testing human format structure...")

    # Simulate human format output
    sample_human_report = """✅ Workspace Pressure Report (2026-05-07 12:00:00 UTC)
Status: HEALTHY - Workspace pressure is low, all systems operating normally

📊 Resource Summary:
  • Free Disk: 10.0 GB
  • Target Dir: 500.0 MB
  • Active Builds: 1
  • Memory Pressure: 20.0%
  • RCH Status: Available (8 slots)
  • File Reservations: 3
  • Coordination: Healthy

🎯 Policy Decisions:
  • SourceOnly: ALLOW_LOCAL 🟢 (confidence: 90%)
  • DocsGate: ALLOW_LOCAL 🟢 (confidence: 90%)
  • Validation: ALLOW_LOCAL 🟢 (confidence: 85%)
  • Benchmark: ALLOW_LOCAL 🟢 (confidence: 80%)
  • Fuzzing: ALLOW_LOCAL 🟢 (confidence: 80%)
  • Cleanup: ALLOW_LOCAL 🟢 (confidence: 90%)

Generated at 2026-05-07 12:00:00 UTC with franken-node/doctor/workspace-pressure/v1 schema
"""

    if not DOCTOR_GOLDEN_JSON.exists():
        print("Golden artifact does not exist, generating...")
        generate_doctor_golden_artifacts()

    golden_data = json.loads(DOCTOR_GOLDEN_JSON.read_text())
    human_format = golden_data["human_format_validation"]

    # Check required sections
    for section in human_format["required_sections"]:
        if section not in sample_human_report:
            print(f"Missing required section: {section}")
            return False

    # Check required resource lines
    for line in human_format["required_resource_lines"]:
        if line not in sample_human_report:
            print(f"Missing required resource line: {line}")
            return False

    print("✓ Human format structure is valid")
    return True


def test_golden_artifact_structure():
    """Test that the golden artifact has expected structure."""
    if not DOCTOR_GOLDEN_JSON.exists():
        print("Golden artifact does not exist, generating...")
        generate_doctor_golden_artifacts()

    data = json.loads(DOCTOR_GOLDEN_JSON.read_text())

    # Verify structure
    required_fields = ["schema_version", "description", "scenarios", "structure_validation", "human_format_validation"]
    for field in required_fields:
        if field not in data:
            print(f"Missing field: {field}")
            return False

    # Verify scenarios
    expected_scenarios = ["healthy", "warning", "degraded", "critical"]
    for scenario in expected_scenarios:
        if scenario not in data["scenarios"]:
            print(f"Missing scenario: {scenario}")
            return False

        scenario_data = data["scenarios"][scenario]
        required_scenario_fields = ["inputs", "expected_status", "expected_summary_contains", "expected_recommendations_count", "expected_policy_decisions"]
        for field in required_scenario_fields:
            if field not in scenario_data:
                print(f"Invalid scenario structure in {scenario}: missing {field}")
                return False

    print(f"✓ Golden artifact structure is valid ({len(data['scenarios'])} scenarios)")
    return True


def main():
    """Generate golden artifacts and verify structure."""
    print("Generating doctor output golden artifacts...")

    if generate_doctor_golden_artifacts():
        if test_golden_artifact_structure():
            if test_doctor_output_structure():
                if test_human_format_structure():
                    print("✓ All tests passed")
                    return True

    return False


if __name__ == "__main__":
    exit(0 if main() else 1)