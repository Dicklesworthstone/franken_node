#!/usr/bin/env python3
"""bd-145n: Control lab scenarios verification gate.

Usage:
    python3 scripts/check_control_lab_scenarios.py [--json] [--self-test]
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path


SCENARIOS_DOC = ROOT / "docs" / "testing" / "control_lab_scenarios.md"
SEED_MATRIX = ROOT / "artifacts" / "10.15" / "control_lab_seed_matrix.json"
SPEC_CONTRACT = ROOT / "docs" / "specs" / "section_10_15" / "bd-145n_contract.md"
SCENARIO_INDEX = ROOT / "tests" / "lab" / "control_protocol_scenarios.rs"
TEST_FILE = ROOT / "tests" / "test_check_control_lab_scenarios.py"

REQUIRED_SCENARIOS = [
    "lab_lifecycle_start_stop",
    "lab_rollout_go_abort",
    "lab_epoch_commit_abort",
    "lab_saga_forward_compensate",
    "lab_evidence_capture_replay",
]

REQUIRED_SEEDS = [0, 42, 12345]


def check_scenarios_doc_exists() -> dict:
    exists = SCENARIOS_DOC.exists()
    return {"id": "CLS-DOC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(SCENARIOS_DOC.relative_to(ROOT))}}


def check_seed_matrix_exists() -> dict:
    if not SEED_MATRIX.exists():
        return {"id": "CLS-MATRIX", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(SEED_MATRIX.read_text())
        ok = (data.get("bead") == "bd-145n"
              and isinstance(data.get("seed_matrix"), list)
              and len(data.get("seed_matrix", [])) >= 10)
        return {"id": "CLS-MATRIX", "status": "PASS" if ok else "FAIL", "details": {"valid": ok}}
    except json.JSONDecodeError as e:
        return {"id": "CLS-MATRIX", "status": "FAIL", "details": {"error": str(e)}}


def check_scenarios_documented() -> dict:
    if not SCENARIOS_DOC.exists():
        return {"id": "CLS-SCENARIOS", "status": "FAIL", "details": {"error": "doc not found"}}
    content = SCENARIOS_DOC.read_text()
    missing = [s for s in REQUIRED_SCENARIOS if s not in content]
    return {
        "id": "CLS-SCENARIOS",
        "status": "PASS" if not missing else "FAIL",
        "details": {"missing": missing, "total": len(REQUIRED_SCENARIOS)},
    }


def check_seed_controlled_model() -> dict:
    if not SCENARIOS_DOC.exists():
        return {"id": "CLS-SEED", "status": "FAIL", "details": {"error": "doc not found"}}
    content = SCENARIOS_DOC.read_text()
    has_seed = "Seed-controlled" in content or "seed-controlled" in content
    has_test_clock = "Test clock" in content or "test clock" in content
    has_replay = "Replay guarantee" in content or "replay guarantee" in content
    ok = has_seed and has_test_clock and has_replay
    return {"id": "CLS-SEED", "status": "PASS" if ok else "FAIL",
            "details": {"seed": has_seed, "clock": has_test_clock, "replay": has_replay}}


def check_invariants_per_scenario() -> dict:
    if not SCENARIOS_DOC.exists():
        return {"id": "CLS-INV", "status": "FAIL", "details": {"error": "doc not found"}}
    content = SCENARIOS_DOC.read_text()
    required = ["quiescence", "no resource leaks", "never happened", "split-brain", "replay fidelity"]
    found = sum(1 for r in required if r.lower() in content.lower())
    return {
        "id": "CLS-INV",
        "status": "PASS" if found >= 4 else "FAIL",
        "details": {"found": found, "total": len(required)},
    }


def check_failure_artifact_format() -> dict:
    if not SCENARIOS_DOC.exists():
        return {"id": "CLS-ARTIFACT", "status": "FAIL", "details": {"error": "doc not found"}}
    content = SCENARIOS_DOC.read_text()
    has_format = "Failure Artifact Format" in content
    has_seed_field = '"seed"' in content
    has_invariant_field = '"invariant_violated"' in content
    ok = has_format and has_seed_field and has_invariant_field
    return {"id": "CLS-ARTIFACT", "status": "PASS" if ok else "FAIL", "details": {"ok": ok}}


def check_matrix_all_scenarios_covered() -> dict:
    if not SEED_MATRIX.exists():
        return {"id": "CLS-COVERAGE", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(SEED_MATRIX.read_text())
        entries = data.get("seed_matrix", [])
        scenarios = set(e.get("scenario") for e in entries)
        missing = [s for s in REQUIRED_SCENARIOS if s not in scenarios]
        return {
            "id": "CLS-COVERAGE",
            "status": "PASS" if not missing else "FAIL",
            "details": {"missing": missing, "covered": len(scenarios)},
        }
    except json.JSONDecodeError as e:
        return {"id": "CLS-COVERAGE", "status": "FAIL", "details": {"error": str(e)}}


def check_matrix_all_pass() -> dict:
    if not SEED_MATRIX.exists():
        return {"id": "CLS-PASS", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(SEED_MATRIX.read_text())
        summary = data.get("summary", {})
        ok = summary.get("failing", -1) == 0 and summary.get("passing", 0) >= 10
        return {"id": "CLS-PASS", "status": "PASS" if ok else "FAIL", "details": summary}
    except json.JSONDecodeError as e:
        return {"id": "CLS-PASS", "status": "FAIL", "details": {"error": str(e)}}


def check_matrix_boundary_seeds() -> dict:
    if not SEED_MATRIX.exists():
        return {"id": "CLS-SEEDS", "status": "FAIL", "details": {"error": "not found"}}
    try:
        data = json.loads(SEED_MATRIX.read_text())
        entries = data.get("seed_matrix", [])
        seeds_used = set(e.get("seed") for e in entries)
        missing = [s for s in REQUIRED_SEEDS if s not in seeds_used]
        return {
            "id": "CLS-SEEDS",
            "status": "PASS" if not missing else "FAIL",
            "details": {"missing": missing, "seeds_used": len(seeds_used)},
        }
    except json.JSONDecodeError as e:
        return {"id": "CLS-SEEDS", "status": "FAIL", "details": {"error": str(e)}}


def check_spec_contract_exists() -> dict:
    exists = SPEC_CONTRACT.exists()
    return {"id": "CLS-SPEC", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(SPEC_CONTRACT.relative_to(ROOT))}}


def check_scenario_index_exists() -> dict:
    if not SCENARIO_INDEX.exists():
        return {"id": "CLS-SCENARIO-INDEX", "status": "FAIL", "details": {"error": "not found"}}
    content = SCENARIO_INDEX.read_text()
    missing = [s for s in REQUIRED_SCENARIOS if s not in content]
    has_seed_matrix = "INTERESTING_SEEDS" in content and "u64::MAX" in content
    has_failure_artifact = "FailureArtifact" in content and "invariant_violated" in content
    ok = not missing and has_seed_matrix and has_failure_artifact
    return {
        "id": "CLS-SCENARIO-INDEX",
        "status": "PASS" if ok else "FAIL",
        "details": {
            "path": str(SCENARIO_INDEX.relative_to(ROOT)),
            "missing": missing,
            "seed_matrix": has_seed_matrix,
            "failure_artifact": has_failure_artifact,
        },
    }


def check_test_file_exists() -> dict:
    exists = TEST_FILE.exists()
    return {"id": "CLS-TESTS", "status": "PASS" if exists else "FAIL",
            "details": {"path": str(TEST_FILE.relative_to(ROOT))}}


def self_test() -> dict:
    checks = [
        check_scenarios_doc_exists(),
        check_seed_matrix_exists(),
        check_scenarios_documented(),
        check_seed_controlled_model(),
        check_invariants_per_scenario(),
        check_failure_artifact_format(),
        check_matrix_all_scenarios_covered(),
        check_matrix_all_pass(),
        check_matrix_boundary_seeds(),
        check_spec_contract_exists(),
        check_scenario_index_exists(),
        check_test_file_exists(),
    ]

    failing = [c for c in checks if c["status"] != "PASS"]
    return {
        "gate": "control_lab_scenarios_verification",
        "bead": "bd-145n",
        "section": "10.15",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_control_lab_scenarios")
    json_output = "--json" in sys.argv
    result = self_test()
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for c in result["checks"]:
            print(f"  [{'OK' if c['status'] == 'PASS' else 'FAIL'}] {c['id']}")
        print(f"\nVerdict: {result['verdict']}")
    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
