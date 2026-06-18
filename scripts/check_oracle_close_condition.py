#!/usr/bin/env python3
"""
Dual-Oracle Completion Close-Condition Gate.

Enforces that L1 product oracle (10.2), L2 engine-boundary oracle (10.17),
and release-policy linkage are all GREEN before program completion is accepted.

Usage:
    python3 scripts/check_oracle_close_condition.py [--json] [--artifacts-dir DIR]

Exit codes:
    0 = PASS (all dimensions GREEN)
    1 = FAIL (one or more dimensions missing or not GREEN)
    2 = ERROR (malformed artifacts, parse error)
"""

import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ARTIFACTS_DIR = ROOT / "artifacts" / "oracle"
L1_PROOF_EVIDENCE_SCHEMA = "franken-node/l1-proof-carrying-effects/v1"
REQUIRED_L1_PROOF_SUBJECTS = ("fs.read", "fs.write", "http.request")

REQUIRED_DIMENSIONS = [
    {
        "id": "l1_product",
        "label": "L1 Product Oracle",
        "owner_track": "10.2",
        "artifact": "l1_product_verdict.json",
    },
    {
        "id": "l2_engine_boundary",
        "label": "L2 Engine-Boundary Oracle",
        "owner_track": "10.17",
        "artifact": "l2_engine_boundary_verdict.json",
    },
    {
        "id": "release_policy_linkage",
        "label": "Release Policy Linkage",
        "owner_track": "10.2",
        "artifact": "release_policy_verdict.json",
    },
]


def validate_l1_proof_carrying_evidence(data: dict) -> list[str]:
    """L1 is GREEN only when parity evidence is also proof-carrying."""
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        return ["L1 evidence object missing"]

    proof = evidence.get("proof_carrying_effects")
    if not isinstance(proof, dict):
        return ["L1 proof_carrying_effects evidence missing"]

    errors = []
    if proof.get("schema_version") != L1_PROOF_EVIDENCE_SCHEMA:
        errors.append("L1 proof_carrying_effects schema_version missing or unsupported")

    verified_subjects = proof.get("verified_subjects")
    if not isinstance(verified_subjects, list):
        verified_subjects = []
    verified_subjects = {subject for subject in verified_subjects if isinstance(subject, str)}
    for subject in REQUIRED_L1_PROOF_SUBJECTS:
        if subject not in verified_subjects:
            errors.append(f"L1 proof_carrying_effects missing subject {subject}")

    receipts_verified = proof.get("effect_receipts_verified")
    if not isinstance(receipts_verified, int) or receipts_verified < len(REQUIRED_L1_PROOF_SUBJECTS):
        errors.append(
            "L1 proof_carrying_effects effect_receipts_verified below required "
            f"{len(REQUIRED_L1_PROOF_SUBJECTS)}"
        )

    invalid_receipts = proof.get("invalid_receipts")
    if not isinstance(invalid_receipts, int):
        errors.append("L1 proof_carrying_effects invalid_receipts missing or invalid")
    elif invalid_receipts != 0:
        errors.append(f"L1 proof_carrying_effects reports {invalid_receipts} invalid receipt(s)")

    if proof.get("receipt_chain_verified") is not True:
        errors.append("L1 proof_carrying_effects receipt_chain_verified is not true")

    return errors


def check_dimension(artifacts_dir: Path, dim: dict) -> dict:
    """Check a single oracle dimension."""
    artifact_path = artifacts_dir / dim["artifact"]
    result = {
        "dimension": dim["id"],
        "label": dim["label"],
        "owner_track": dim["owner_track"],
        "present": False,
        "verdict": None,
        "error": None,
    }

    if not artifact_path.exists():
        result["error"] = f"Artifact not found: {artifact_path.name}"
        return result

    result["present"] = True

    try:
        with open(artifact_path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        result["error"] = f"Malformed artifact: {e}"
        return result

    verdict = data.get("verdict")
    if verdict not in ("GREEN", "YELLOW", "RED"):
        result["error"] = f"Invalid verdict value: {verdict}"
        return result

    result["verdict"] = verdict
    errors = []
    if verdict != "GREEN":
        errors.append(f"Verdict is {verdict}, expected GREEN")
    if dim["id"] == "l1_product":
        errors.extend(validate_l1_proof_carrying_evidence(data))
    if errors:
        result["error"] = "; ".join(errors)

    return result


def main():
    logger = configure_test_logging("check_oracle_close_condition")
    json_output = "--json" in sys.argv
    artifacts_dir = DEFAULT_ARTIFACTS_DIR

    for i, arg in enumerate(sys.argv):
        if arg == "--artifacts-dir" and i + 1 < len(sys.argv):
            artifacts_dir = Path(sys.argv[i + 1])

    timestamp = datetime.now(timezone.utc).isoformat()
    dimensions = {}
    failing = []

    for dim in REQUIRED_DIMENSIONS:
        result = check_dimension(artifacts_dir, dim)
        dimensions[dim["id"]] = result

        if result.get("error") or result["verdict"] != "GREEN":
            failing.append({
                "dimension": dim["id"],
                "label": dim["label"],
                "reason": result.get("error", f"Verdict: {result['verdict']}"),
            })

    verdict = "PASS" if not failing else "FAIL"

    report = {
        "gate": "dual_oracle_close_condition",
        "verdict": verdict,
        "timestamp": timestamp,
        "artifacts_dir": str(artifacts_dir),
        "dimensions": {
            k: {
                "present": v["present"],
                "verdict": v["verdict"],
                "error": v.get("error"),
            }
            for k, v in dimensions.items()
        },
        "failing_dimensions": failing,
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Dual-Oracle Close-Condition Gate ===")
        print(f"Artifacts: {artifacts_dir}")
        print(f"Timestamp: {timestamp}")
        print()
        for dim_id, dim_data in dimensions.items():
            status = "OK" if dim_data["verdict"] == "GREEN" else "FAIL"
            label = [d for d in REQUIRED_DIMENSIONS if d["id"] == dim_id][0]["label"]
            if dim_data["present"]:
                print(f"  [{status}] {label}: {dim_data['verdict']}")
            else:
                print(f"  [MISSING] {label}: artifact not found")
            if dim_data.get("error"):
                print(f"         Error: {dim_data['error']}")
        print()
        print(f"Verdict: {verdict}")
        if failing:
            print(f"Failing dimensions: {len(failing)}")
            for f in failing:
                print(f"  - {f['label']}: {f['reason']}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
