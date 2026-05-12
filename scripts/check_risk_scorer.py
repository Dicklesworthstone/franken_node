#!/usr/bin/env python3
"""
Risk Scorer Verifier.

Usage:
    python3 scripts/check_risk_scorer.py [--json]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
import migration_risk_scorer as scorer  # noqa: E402


def check_primary_implementation_cited() -> dict:
    check = scorer.check_primary_implementation_cited()
    return {
        "id": "SCORER-IMPL",
        "status": check["status"],
        "details": check["details"],
    }


def check_scorer_exists() -> dict:
    check = {"id": "SCORER-EXISTS", "status": "PASS", "details": {}}
    check["details"]["scorer"] = (ROOT / "scripts" / "migration_risk_scorer.py").exists()
    check["details"]["spec"] = (ROOT / "docs" / "specs" / "section_10_3" / "bd-33x_contract.md").exists()
    if not all(check["details"].values()):
        check["status"] = "FAIL"
    return check


def check_weights_defined() -> dict:
    check = {"id": "SCORER-WEIGHTS", "status": "PASS", "details": {}}
    check["details"]["weight_count"] = len(scorer.WEIGHTS)
    check["details"]["has_critical_weight"] = "critical_api_count" in scorer.WEIGHTS
    check["details"]["has_native_weight"] = "native_addon_count" in scorer.WEIGHTS
    if len(scorer.WEIGHTS) < 5:
        check["status"] = "FAIL"
    return check


def check_difficulty_bands() -> dict:
    check = {"id": "SCORER-BANDS", "status": "PASS", "details": {}}
    check["details"]["band_count"] = len(scorer.DIFFICULTY_BANDS)
    levels = [b[1] for b in scorer.DIFFICULTY_BANDS]
    check["details"]["levels"] = levels
    if "low" not in levels or "critical" not in levels:
        check["status"] = "FAIL"
    return check


def check_self_test() -> dict:
    check = {"id": "SCORER-SELFTEST", "status": "PASS", "details": {}}
    result = scorer.self_test()
    check["details"]["verdict"] = result["verdict"]
    if result["verdict"] != "PASS":
        check["status"] = "FAIL"
    return check


def check_score_bounded() -> dict:
    check = {"id": "SCORER-BOUNDED", "status": "PASS", "details": {}}
    # Test with extreme input
    extreme = {
        "summary": {"risk_distribution": {"low": 0, "medium": 0, "high": 100, "critical": 100}},
        "api_usage": [{"api_family": "unsafe", "api_name": "eval"} for _ in range(50)],
        "dependencies": [{"has_native_addon": True} for _ in range(50)],
    }
    features = scorer.extract_features(extreme)
    score, _ = scorer.compute_score(features)
    check["details"]["extreme_score"] = score
    if score < 0 or score > 100:
        check["status"] = "FAIL"
    return check


def main():
    configure_test_logging("check_risk_scorer")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()

    checks = [
        check_primary_implementation_cited(),
        check_scorer_exists(),
        check_weights_defined(),
        check_difficulty_bands(),
        check_self_test(),
        check_score_bounded(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "risk_scorer_verification",
        "section": "10.3",
        "verdict": verdict,
        "timestamp": timestamp,
        "evidence_paths": scorer.EVIDENCE_PATHS,
        "verification_commands": scorer.VERIFICATION_COMMANDS,
        "checks": checks,
        "summary": {"total_checks": len(checks), "passing_checks": len(checks) - len(failing), "failing_checks": len(failing)},
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Risk Scorer Verifier ===")
        for c in checks:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
