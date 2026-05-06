#!/usr/bin/env python3
"""Verification gate for DGIS operator copilot guidance (bd-1f8v).

Checks:
1. Source file exists with all required components
2. Risk delta computation with per-metric breakdowns
3. Containment recommendation generation
4. Confidence output with uncertainty bounds
5. Policy acknowledgement gate
6. Mitigation playbook generation
7. Interaction logging and JSONL export
8. Event codes following DGIS-COPILOT-NNN convention

Usage:
    python3 scripts/check_dgis_copilot.py          # human-readable
    python3 scripts/check_dgis_copilot.py --json    # machine-readable
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

COPILOT_SRC = ROOT / "crates/franken-node/src/security/dgis/update_copilot.rs"
DGIS_MOD = ROOT / "crates/franken-node/src/security/dgis/mod.rs"
SPEC_DOC = ROOT / "docs/specs/section_10_20/bd-1f8v_contract.md"

REQUIRED_STRUCTS = [
    "UpdateCopilot",
    "UpdateProposal",
    "UpdateRecommendation",
    "RiskDelta",
    "TopologyRiskMetrics",
    "BlastRadiusEstimate",
    "ContainmentRecommendation",
    "BarrierRecommendation",
    "ConfidenceOutput",
    "AcknowledgementReceipt",
    "MitigationPlaybook",
    "StagedRolloutPlan",
    "MonitoringRecommendation",
    "CopilotInteraction",
    "CopilotConfig",
]

REQUIRED_EVENT_CODES = [
    "DGIS-COPILOT-001",
    "DGIS-COPILOT-002",
    "DGIS-COPILOT-003",
    "DGIS-COPILOT-004",
    "DGIS-COPILOT-005",
    "DGIS-COPILOT-006",
    "DGIS-COPILOT-007",
]

REQUIRED_TEST_PATTERNS = [
    "risk_delta_computation",
    "risk_delta_shows_decrease",
    "low_risk_update_classified",
    "high_risk_update_classified",
    "containment_includes_blast_radius",
    "containment_suggests_barriers",
    "confidence_has_bounds",
    "high_risk_requires_acknowledgement",
    "acknowledgement_validation_rejects",
    "valid_acknowledgement_processes",
    "playbook_has_all_required",
    "playbook_rollout_has_four_phases",
    "interactions_are_logged",
    "jsonl_export",
]

REQUIRED_METRICS = [
    "fan_out",
    "betweenness_centrality",
    "articulation_point",
    "trust_bottleneck_score",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def check_source_exists() -> CheckResult:
    if COPILOT_SRC.exists():
        size = COPILOT_SRC.stat().st_size
        return CheckResult("source_exists", True, f"update_copilot.rs exists ({size} bytes)", {"size": size})
    return CheckResult("source_exists", False, "update_copilot.rs not found")


def check_module_wiring() -> CheckResult:
    if not DGIS_MOD.exists():
        return CheckResult("module_wiring", False, "dgis/mod.rs not found")
    content = DGIS_MOD.read_text()
    if "pub mod update_copilot" not in content:
        return CheckResult("module_wiring", False, "update_copilot not declared in dgis/mod.rs")
    return CheckResult("module_wiring", True, "update_copilot properly wired into dgis module")


def check_required_structs() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("structs", False, "source file missing")
    content = COPILOT_SRC.read_text()
    missing = [s for s in REQUIRED_STRUCTS if f"pub struct {s}" not in content and f"pub enum {s}" not in content]
    if missing:
        return CheckResult("structs", False, f"missing structs: {missing}", {"missing": missing})
    return CheckResult("structs", True, f"all {len(REQUIRED_STRUCTS)} required types present")


def check_event_codes() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("event_codes", False, "source file missing")
    content = COPILOT_SRC.read_text()
    missing = [c for c in REQUIRED_EVENT_CODES if c not in content]
    total = len(re.findall(r'"(DGIS-COPILOT-\d+)"', content))
    if missing:
        return CheckResult("event_codes", False, f"missing codes: {missing}", {"missing": missing})
    return CheckResult("event_codes", True, f"{total} event codes defined, all required present")


def check_risk_delta() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("risk_delta", False, "source file missing")
    content = COPILOT_SRC.read_text()
    checks = {
        "risk_delta_struct": "pub struct RiskDelta" in content,
        "per_metric_deltas": "per_metric_deltas" in content,
        "risk_increased_field": "risk_increased" in content,
        "compute_method": "fn compute(" in content,
    }
    for metric in REQUIRED_METRICS:
        checks[f"metric_{metric}"] = metric in content
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("risk_delta", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("risk_delta", True, "risk delta with per-metric breakdowns present")


def check_containment() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("containment", False, "source file missing")
    content = COPILOT_SRC.read_text()
    checks = {
        "blast_radius": "BlastRadiusEstimate" in content,
        "barrier_recommendation": "BarrierRecommendation" in content,
        "monitoring": "monitoring_intensification" in content,
        "containment_struct": "ContainmentRecommendation" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("containment", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("containment", True, "containment recommendations with blast radius present")


def check_confidence() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("confidence", False, "source file missing")
    if not SPEC_DOC.exists():
        return CheckResult("confidence", False, "spec file missing")
    content = COPILOT_SRC.read_text()
    spec = SPEC_DOC.read_text()
    stale_history_placeholder = "placeholder for real " "history check"
    checks = {
        "confidence_struct": "pub struct ConfidenceOutput" in content,
        "lower_bound": "lower_bound" in content,
        "upper_bound": "upper_bound" in content,
        "data_quality_factors": "data_quality_factors" in content,
        "calibration_note": "calibration_note" in content,
        "history_depth_factor": '"history_depth"' in content,
        "history_depth_dep_signal": "transitive_dependency_count as f64" in content,
        "history_depth_fan_out_signal": "fo.is_finite()" in content
        and "fo.min(10.0) / 10.0" in content,
        "spec_removes_history_placeholder": stale_history_placeholder not in spec,
        "spec_documents_history_formula": "dep_signal = min(transitive_dependency_count, 50) / 50"
        in spec
        and "history_depth = clamp((dep_signal + fan_out_signal) / 2, 0.0, 1.0)"
        in spec,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("confidence", False, f"missing: {failed}", {"missing": failed})
    return CheckResult(
        "confidence",
        True,
        "confidence output with uncertainty bounds and deterministic history-depth scoring present",
        {
            "history_depth": {
                "dependency_cap": 50,
                "fan_out_cap": 10,
                "unavailable_signal": 0.0,
            }
        },
    )


def check_acknowledgement_gate() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("acknowledgement", False, "source file missing")
    content = COPILOT_SRC.read_text()
    checks = {
        "ack_receipt": "AcknowledgementReceipt" in content,
        "ack_decision": "AcknowledgementDecision" in content,
        "requires_ack": "requires_acknowledgement" in content,
        "process_ack": "process_acknowledgement" in content,
        "validate_ack": "fn validate(" in content,
        "signature_check": "signature_hex" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("acknowledgement", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("acknowledgement", True, "policy acknowledgement gate with validation present")


def check_playbook() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("playbook", False, "source file missing")
    content = COPILOT_SRC.read_text()
    checks = {
        "playbook_struct": "MitigationPlaybook" in content,
        "staged_rollout": "StagedRolloutPlan" in content,
        "monitoring_rec": "MonitoringRecommendation" in content,
        "rollback_instructions": "rollback_instructions" in content,
        "barrier_configs": "barrier_configurations" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("playbook", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("playbook", True, "mitigation playbook with barriers, rollout, monitoring present")


def check_test_coverage() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("test_coverage", False, "source file missing")
    content = COPILOT_SRC.read_text()
    missing = [p for p in REQUIRED_TEST_PATTERNS if not re.search(p, content)]
    if missing:
        return CheckResult("test_coverage", False, f"missing test patterns: {missing}", {"missing": missing})
    return CheckResult("test_coverage", True, f"all {len(REQUIRED_TEST_PATTERNS)} test patterns found")


def check_interaction_logging() -> CheckResult:
    if not COPILOT_SRC.exists():
        return CheckResult("interaction_logging", False, "source file missing")
    content = COPILOT_SRC.read_text()
    checks = {
        "interaction_struct": "CopilotInteraction" in content,
        "log_interaction": "log_interaction" in content,
        "export_jsonl": "export_interactions_jsonl" in content,
        "trace_id": "trace_id" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("interaction_logging", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("interaction_logging", True, "interaction logging with JSONL export present")


def run_all_checks() -> list[CheckResult]:
    return [
        check_source_exists(),
        check_module_wiring(),
        check_required_structs(),
        check_event_codes(),
        check_risk_delta(),
        check_containment(),
        check_confidence(),
        check_acknowledgement_gate(),
        check_playbook(),
        check_test_coverage(),
        check_interaction_logging(),
    ]


def self_test() -> bool:
    results = run_all_checks()
    assert len(results) >= 10
    for r in results:
        assert isinstance(r.name, str) and len(r.name) > 0
        assert isinstance(r.passed, bool)
    return True


def main():
    logger = configure_test_logging("check_dgis_copilot")
    parser = argparse.ArgumentParser(description="DGIS copilot verification gate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        try:
            self_test()
            print("self_test: PASS")
            sys.exit(0)
        except AssertionError as e:
            print(f"self_test: FAIL - {e}")
            sys.exit(1)

    results = run_all_checks()
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    all_pass = passed == total

    if args.json:
        output = {
            "gate": "dgis_update_copilot",
            "bead": "bd-1f8v",
            "section": "10.20",
            "verdict": "PASS" if all_pass else "FAIL",
            "passed": passed,
            "total": total,
            "checks": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "message": r.message,
                    **({"details": r.details} if r.details else {}),
                }
                for r in results
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.name}: {r.message}")
        print(f"\n{'PASS' if all_pass else 'FAIL'}: {passed}/{total} checks passed")

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
