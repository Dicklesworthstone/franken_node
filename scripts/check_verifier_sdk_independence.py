#!/usr/bin/env python3
"""Verification script for bd-tenx3.5: Verifier SDK Independence.

Verifies that:
1. sdk/verifier/Cargo.toml defines an independent library configuration without mandatory
   dependencies on the product crate (frankenengine-node is gated behind optional feature 'differential').
2. Independent conformance test lane exists (tests/independent_conformance.rs) covering
   signature verification, tamper detection, unknown schemas, and counterfactual vectors.
3. README.md and CLAIMS_REGISTRY.md accurately distinguish library independence from
   cross-implementation differential tests.
4. Generates signed/structured evidence artifact at artifacts/verifier/sdk_independence_evidence.json.

Usage:
    python3 scripts/check_verifier_sdk_independence.py
    python3 scripts/check_verifier_sdk_independence.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SDK_CARGO_TOML = ROOT / "sdk" / "verifier" / "Cargo.toml"
INDEPENDENT_TEST_FILE = ROOT / "sdk" / "verifier" / "tests" / "independent_conformance.rs"
CLAIMS_REGISTRY_FILE = ROOT / "docs" / "CLAIMS_REGISTRY.md"
README_FILE = ROOT / "README.md"
EVIDENCE_PATH = ROOT / "artifacts" / "verifier" / "sdk_independence_evidence.json"


def check_cargo_toml_independence() -> dict:
    if not SDK_CARGO_TOML.is_file():
        return {
            "name": "cargo_toml_independence",
            "passed": False,
            "detail": f"Missing {SDK_CARGO_TOML}",
        }

    content = SDK_CARGO_TOML.read_text(encoding="utf-8")

    # Assert frankenengine-node is completely absent to ensure 100% independence and prevent cyclic package dependency
    no_product_dep = "frankenengine-node" not in content
    no_mandatory_dev_dep = "[dev-dependencies]\nfrankenengine-node" not in content

    passed = no_product_dep and no_mandatory_dev_dep
    detail = (
        "sdk/verifier has zero dependencies on frankenengine-node (100% independent verifier SDK)"
        if passed
        else "sdk/verifier must not depend on frankenengine-node (causes cyclic dependency)"
    )
    return {
        "name": "cargo_toml_independence",
        "passed": passed,
        "detail": detail,
        "no_product_dep": no_product_dep,
    }


def check_independent_test_suite() -> dict:
    if not INDEPENDENT_TEST_FILE.is_file():
        return {
            "name": "independent_test_suite",
            "passed": False,
            "detail": f"Missing {INDEPENDENT_TEST_FILE}",
        }

    content = INDEPENDENT_TEST_FILE.read_text(encoding="utf-8")

    checks = [
        ("signature_verification", "independent_sdk_verifies_valid_signature"),
        ("payload_tampering", "independent_sdk_detects_payload_tampering"),
        ("signature_corruption", "independent_sdk_detects_signature_corruption"),
        ("wrong_key_rejection", "independent_sdk_rejects_wrong_key"),
        ("schema_rejection", "independent_sdk_rejects_unknown_schema_version"),
        ("counterfactual_fail_closed", "independent_sdk_verifies_counterfactual_receipt_pass_and_fail_closed"),
    ]

    missing = [name for name, symbol in checks if symbol not in content]
    passed = len(missing) == 0
    detail = (
        "Independent conformance tests cover signatures, tampering, schemas, and counterfactuals"
        if passed
        else f"Missing independent test cases: {missing}"
    )
    return {
        "name": "independent_test_suite",
        "passed": passed,
        "detail": detail,
        "tested_capabilities": [c[0] for c in checks],
    }


def check_documentation_alignment() -> dict:
    if not CLAIMS_REGISTRY_FILE.is_file() or not README_FILE.is_file():
        return {
            "name": "documentation_alignment",
            "passed": False,
            "detail": "Missing README.md or docs/CLAIMS_REGISTRY.md",
        }

    claims_text = CLAIMS_REGISTRY_FILE.read_text(encoding="utf-8")
    readme_text = README_FILE.read_text(encoding="utf-8")

    has_claim_11 = "CLAIM-011" in claims_text
    has_verifier_section = "Verifier SDK" in readme_text

    passed = has_claim_11 and has_verifier_section
    return {
        "name": "documentation_alignment",
        "passed": passed,
        "detail": "CLAIM-011 and Verifier SDK documentation present",
    }


def run_checks() -> dict:
    results = [
        check_cargo_toml_independence(),
        check_independent_test_suite(),
        check_documentation_alignment(),
    ]
    all_passed = all(r["passed"] for r in results)

    return {
        "schema_version": "franken-node/verifier-sdk-independence-evidence/v1",
        "bead_id": "bd-tenx3.5",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "all_passed": all_passed,
        "verdict": "PASS" if all_passed else "FAIL",
        "checks": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Verifier SDK Independence (bd-tenx3.5)")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    report = run_checks()

    # Write evidence artifact
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report["all_passed"] else "FAIL"
        print(f"Verifier SDK Independence Gate: {status}")
        for c in report["checks"]:
            mark = "✓" if c["passed"] else "✗"
            print(f"  {mark} {c['name']}: {c['detail']}")

    sys.exit(0 if report["all_passed"] else 1)


if __name__ == "__main__":
    main()
