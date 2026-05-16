#!/usr/bin/env python3
"""Verification gate for BPET economic integration (bd-3cbi).

Checks:
1. Source file exists with all required components
2. Compromise propensity scoring from trajectory data
3. Economic pricing (risk-adjusted cost, insurance premium)
4. Intervention ROI computation with recommendations
5. Historical motif matching with default library
6. Operator guidance generation
7. Mitigation playbook with urgency levels
8. Audit logging and JSONL export
9. Event codes following BPET-ECON-NNN convention
10. Module wiring into security subsystem
11. Rust unit test coverage
12. Dedicated trust-surface bridge for BPET-to-trust-card mutations

Usage:
    python3 scripts/check_bpet_economic.py          # human-readable
    python3 scripts/check_bpet_economic.py --json    # machine-readable
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BPET_SRC = ROOT / "crates/franken-node/src/security/bpet/economic_integration.rs"
BPET_TRUST_SURFACE_SRC = ROOT / "crates/franken-node/src/security/bpet/trust_surface_integration.rs"
BPET_MOD = ROOT / "crates/franken-node/src/security/bpet/mod.rs"
SECURITY_MOD = ROOT / "crates/franken-node/src/security/mod.rs"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = _rust_block_comment_end(text, i + 2)
            continue

        raw_end = _rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = _rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def _rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def _rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def _rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor

REQUIRED_STRUCTS = [
    "PhenotypeObservation",
    "PhenotypeTrajectory",
    "CompromisePricing",
    "InterventionRoi",
    "InterventionRecommendation",
    "CompromiseMotif",
    "MotifIndicator",
    "MotifMatch",
    "BpetGuidance",
    "BpetMitigationPlaybook",
    "PlaybookUrgency",
    "PlaybookAction",
    "BpetAuditRecord",
    "BpetEconomicEngine",
    "BpetEconError",
]

REQUIRED_EVENT_CODES = [
    "BPET-ECON-001",
    "BPET-ECON-002",
    "BPET-ECON-003",
    "BPET-ECON-004",
    "BPET-ECON-005",
    "BPET-ECON-006",
    "BPET-ECON-007",
    "BPET-ECON-008",
    "BPET-ECON-009",
    "BPET-ECON-010",
]

REQUIRED_TEST_PATTERNS = [
    "healthy_trajectory_has_low_propensity",
    "declining_trajectory_has_high_propensity",
    "empty_trajectory_returns_zero_propensity",
    "propensity_bounded_zero_to_one",
    "pricing_computed_for_valid_trajectory",
    "pricing_fails_for_empty_trajectory",
    "high_risk_produces_higher_cost",
    "intervention_roi_computed_correctly",
    "intervention_rejects_zero_cost",
    "high_roi_is_strongly_recommended",
    "declining_trajectory_matches_motifs",
    "engine_generates_guidance",
    "engine_logs_guidance_interaction",
    "engine_exports_jsonl",
]

REQUIRED_CAPABILITIES = {
    "propensity_scoring": ["compromise_propensity", "single_observation_score"],
    "economic_pricing": ["risk_adjusted_cost", "insurance_premium_equivalent", "CompromisePricing"],
    "intervention_roi": ["InterventionRoi", "roi_ratio", "payback_period_days", "InterventionRecommendation"],
    "motif_matching": ["match_motifs", "CompromiseMotif", "MotifMatch", "match_score"],
    "playbook_generation": ["BpetMitigationPlaybook", "PlaybookUrgency", "PlaybookAction"],
    "audit_logging": ["BpetAuditRecord", "audit_log", "export_audit_log_jsonl"],
}

TRUST_SURFACE_REQUIRED_SYMBOLS = [
    "TRUST_SURFACE_SCHEMA_VERSION",
    "BpetTrustSurfaceAssessment",
    "AdversaryPosteriorUpdate",
    "TrustSurfaceIntegrationError",
    "assess_guidance_for_trust_surface",
    "trust_card_mutation_from_guidance",
    "adversary_posterior_update_from_guidance",
    "TrustCardMutation",
    "RiskAssessment",
    "RiskLevel",
]

TRUST_SURFACE_REQUIRED_TESTS = [
    "critical_bpet_guidance_maps_to_quarantining_trust_card_mutation",
    "routine_bpet_guidance_keeps_low_risk_without_quarantine",
    "non_finite_bpet_propensity_is_rejected_fail_closed",
    "adversary_posterior_update_uses_bounded_basis_points",
]


@dataclass
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def check_source_exists() -> CheckResult:
    if BPET_SRC.exists():
        size = BPET_SRC.stat().st_size
        return CheckResult("source_exists", True, f"economic_integration.rs exists ({size} bytes)", {"size": size})
    return CheckResult("source_exists", False, "economic_integration.rs not found")


def check_module_wiring() -> CheckResult:
    issues = []
    if not BPET_MOD.exists():
        issues.append("bpet/mod.rs not found")
    else:
        content = _read_rust_source(BPET_MOD)
        if "pub mod economic_integration" not in content:
            issues.append("economic_integration not declared in bpet/mod.rs")
        if "pub mod trust_surface_integration" not in content:
            issues.append("trust_surface_integration not declared in bpet/mod.rs")

    if not SECURITY_MOD.exists():
        issues.append("security/mod.rs not found")
    else:
        content = _read_rust_source(SECURITY_MOD)
        if "pub mod bpet" not in content:
            issues.append("bpet not declared in security/mod.rs")

    if issues:
        return CheckResult("module_wiring", False, "; ".join(issues), {"issues": issues})
    return CheckResult("module_wiring", True, "bpet module properly wired into security subsystem")


def check_required_structs() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("structs", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    missing = [s for s in REQUIRED_STRUCTS if f"pub struct {s}" not in content and f"pub enum {s}" not in content]
    if missing:
        return CheckResult("structs", False, f"missing types: {missing}", {"missing": missing})
    return CheckResult("structs", True, f"all {len(REQUIRED_STRUCTS)} required types present")


def check_event_codes() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("event_codes", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    missing = [c for c in REQUIRED_EVENT_CODES if c not in content]
    total = len(re.findall(r'"(BPET-ECON-\d+)"', content))
    if missing:
        return CheckResult("event_codes", False, f"missing codes: {missing}", {"missing": missing})
    return CheckResult("event_codes", True, f"{total} event codes defined, all required present")


def check_propensity_scoring() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("propensity_scoring", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "trajectory_struct": "pub struct PhenotypeTrajectory" in content,
        "observation_struct": "pub struct PhenotypeObservation" in content,
        "propensity_method": "fn compromise_propensity" in content,
        "trend_computation": "trend_score" in content,
        "maintainer_activity": "maintainer_activity_score" in content,
        "commit_velocity": "commit_velocity" in content,
        "issue_response_time": "issue_response_time_hours" in content,
        "contributor_diversity": "contributor_diversity_index" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("propensity_scoring", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("propensity_scoring", True, "propensity scoring with trend analysis present")


def check_economic_pricing() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("economic_pricing", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "pricing_struct": "pub struct CompromisePricing" in content,
        "risk_adjusted_cost": "risk_adjusted_cost" in content,
        "insurance_premium": "insurance_premium_equivalent" in content,
        "expected_loss": "expected_loss_if_compromised" in content,
        "compute_method": "fn compute(" in content,
        "loading_factor": "loading factor" in content.lower() or "1.2" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("economic_pricing", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("economic_pricing", True, "economic pricing with risk-adjusted cost present")


def check_intervention_roi() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("intervention_roi", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "roi_struct": "pub struct InterventionRoi" in content,
        "roi_ratio": "roi_ratio" in content,
        "payback_period": "payback_period_days" in content,
        "recommendation_enum": "InterventionRecommendation" in content,
        "strongly_recommended": "StronglyRecommended" in content,
        "not_recommended": "NotRecommended" in content,
        "compute_method": "fn compute(" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("intervention_roi", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("intervention_roi", True, "intervention ROI with recommendation tiers present")


def check_motif_matching() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("motif_matching", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "match_function": "fn match_motifs" in content,
        "motif_struct": "pub struct CompromiseMotif" in content,
        "match_result": "pub struct MotifMatch" in content,
        "indicator_struct": "pub struct MotifIndicator" in content,
        "direction_enum": "ThresholdDirection" in content,
        "default_library": "fn default_motif_library" in content,
        "abandoned_critical": "Abandoned Critical" in content,
        "maintainer_turnover": "Maintainer Turnover" in content,
        "slow_decay": "Slow Quality Decay" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("motif_matching", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("motif_matching", True, "historical motif matching with 3+ default patterns present")


def check_playbook_generation() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("playbook", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "playbook_struct": "BpetMitigationPlaybook" in content,
        "urgency_enum": "PlaybookUrgency" in content,
        "routine": "Routine" in content,
        "elevated": "Elevated" in content,
        "urgent": "Urgent" in content and "PlaybookUrgency" in content,
        "critical": "Critical" in content,
        "actions": "PlaybookAction" in content,
        "monitoring_escalation": "monitoring_escalation" in content,
        "fallback_strategy": "fallback_strategy" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("playbook", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("playbook", True, "mitigation playbook with 4 urgency tiers present")


def check_test_coverage() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("test_coverage", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    missing = [p for p in REQUIRED_TEST_PATTERNS if not re.search(p, content)]
    total_tests = len(re.findall(r"#\[test\]", content))
    if missing:
        return CheckResult("test_coverage", False, f"missing test patterns: {missing}", {"missing": missing, "total_tests": total_tests})
    return CheckResult("test_coverage", True, f"all {len(REQUIRED_TEST_PATTERNS)} required test patterns found ({total_tests} total tests)")


def check_audit_logging() -> CheckResult:
    if not BPET_SRC.exists():
        return CheckResult("audit_logging", False, "source file missing")
    content = _read_rust_source(BPET_SRC)
    checks = {
        "audit_struct": "pub struct BpetAuditRecord" in content,
        "audit_log_method": "fn audit_log" in content,
        "jsonl_export": "fn export_audit_log_jsonl" in content,
        "trace_id": "trace_id" in content,
        "event_code_field": "event_code" in content,
    }
    failed = [k for k, v in checks.items() if not v]
    if failed:
        return CheckResult("audit_logging", False, f"missing: {failed}", {"missing": failed})
    return CheckResult("audit_logging", True, "audit logging with JSONL export and trace IDs present")


def check_trust_surface_integration() -> CheckResult:
    issues = []
    if not BPET_TRUST_SURFACE_SRC.exists():
        return CheckResult(
            "trust_surface_integration",
            False,
            "trust_surface_integration.rs not found",
            {"path": str(BPET_TRUST_SURFACE_SRC.relative_to(ROOT))},
        )

    content = _read_rust_source(BPET_TRUST_SURFACE_SRC)
    missing_symbols = [symbol for symbol in TRUST_SURFACE_REQUIRED_SYMBOLS if symbol not in content]
    missing_tests = [test for test in TRUST_SURFACE_REQUIRED_TESTS if test not in content]
    if missing_symbols:
        issues.append(f"missing symbols: {missing_symbols}")
    if missing_tests:
        issues.append(f"missing tests: {missing_tests}")
    if "BPET trust-surface assessment" not in content:
        issues.append("operator-facing BPET trust-surface summary missing")
    if "active_quarantine: Some(assessment.active_quarantine_recommended)" not in content:
        issues.append("TrustCardMutation quarantine field not wired")
    if "user_facing_risk_assessment: Some(RiskAssessment" not in content:
        issues.append("TrustCardMutation risk assessment field not wired")
    if "NonFinitePropensity" not in content or "InvalidMotifScore" not in content:
        issues.append("fail-closed numeric validation missing")

    if issues:
        return CheckResult(
            "trust_surface_integration",
            False,
            "; ".join(issues),
            {"issues": issues},
        )
    return CheckResult(
        "trust_surface_integration",
        True,
        "dedicated BPET trust-surface bridge maps guidance to trust-card mutation and posterior update",
        {
            "path": str(BPET_TRUST_SURFACE_SRC.relative_to(ROOT)),
            "symbols": len(TRUST_SURFACE_REQUIRED_SYMBOLS),
            "tests": len(TRUST_SURFACE_REQUIRED_TESTS),
        },
    )


def run_all_checks() -> list[CheckResult]:
    return [
        check_source_exists(),
        check_module_wiring(),
        check_required_structs(),
        check_event_codes(),
        check_propensity_scoring(),
        check_economic_pricing(),
        check_intervention_roi(),
        check_motif_matching(),
        check_playbook_generation(),
        check_test_coverage(),
        check_audit_logging(),
        check_trust_surface_integration(),
    ]


def self_test() -> bool:
    results = run_all_checks()
    if len(results) < 10:
        raise AssertionError("expected at least 10 checks")
    for r in results:
        if not isinstance(r.name, str) or not r.name:
            raise AssertionError("check result has an invalid name")
        if not isinstance(r.passed, bool):
            raise AssertionError(f"{r.name} result has a non-bool passed value")
        if not isinstance(r.message, str):
            raise AssertionError(f"{r.name} result has a non-string message")
    return True


def main():
    configure_test_logging("check_bpet_economic")
    parser = argparse.ArgumentParser(description="BPET economic integration verification gate")
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
            "gate": "bpet_economic_integration",
            "bead": "bd-3cbi",
            "section": "10.21",
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
