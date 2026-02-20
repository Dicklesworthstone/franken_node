#!/usr/bin/env python3
"""
Object-class profile registry verification for bd-2573.

Usage:
    python3 scripts/check_object_class_profiles.py [--json]
"""

from __future__ import annotations

import json
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "docs" / "specs" / "object_class_profiles.md"
CONFIG_PATH = ROOT / "config" / "object_class_profiles.toml"
REGISTRY_PATH = ROOT / "artifacts" / "10.14" / "object_class_registry.json"
FIXTURE_PATH = ROOT / "fixtures" / "object_class_profiles" / "cases.json"
EVIDENCE_PATH = ROOT / "artifacts" / "section_10_14" / "bd-2573" / "verification_evidence.json"

REQUIRED_CLASSES = [
    "critical_marker",
    "trust_receipt",
    "replay_bundle",
    "telemetry_artifact",
]

EVENT_CODES = [
    "OCP_REGISTRY_LOADED",
    "OCP_CLASS_VALIDATED",
    "OCP_UNKNOWN_CLASS_REJECTED",
    "OCP_REGISTRY_VERIFIED",
]

ERROR_CODES = [
    "OCP_MISSING_REQUIRED_CLASS",
    "OCP_UNKNOWN_CLASS",
    "OCP_INVALID_PROFILE_FIELD",
    "OCP_VERSION_MISMATCH",
]

CHECK_IDS = {
    "spec": "OCP-SPEC",
    "config": "OCP-CONFIG",
    "registry": "OCP-REGISTRY",
    "unit": "OCP-UNIT",
    "integration": "OCP-INTEGRATION",
    "e2e": "OCP-E2E",
    "logs": "OCP-LOGS",
}


def check_result(check_id: str, description: str, passed: bool, details: dict[str, Any] | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details is not None:
        item["details"] = details
    return item


def load_config() -> dict[str, Any]:
    return tomllib.loads(CONFIG_PATH.read_text())


def load_registry() -> dict[str, Any]:
    return json.loads(REGISTRY_PATH.read_text())


def validate_class_name(class_name: str, config: dict[str, Any]) -> tuple[bool, str | None]:
    classes = config.get("classes", {})
    if class_name in classes:
        return True, None
    return False, "OCP_UNKNOWN_CLASS"


def check_spec_contract() -> dict[str, Any]:
    if not SPEC_PATH.exists():
        return check_result(CHECK_IDS["spec"], "Spec describes required classes and invariants", False)

    content = SPEC_PATH.read_text().lower()
    required_terms = [
        "critical_marker",
        "trust_receipt",
        "replay_bundle",
        "telemetry_artifact",
        "inv-ocp-unknown-reject",
        "ocp_unknown_class",
    ]
    missing = [term for term in required_terms if term not in content]
    return check_result(
        CHECK_IDS["spec"],
        "Spec describes required classes and invariants",
        len(missing) == 0,
        {"missing_terms": missing},
    )


def check_config_contract() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return check_result(CHECK_IDS["config"], "TOML registry has required classes and reject policy", False)

    config = load_config()
    classes = config.get("classes", {})
    class_names = sorted(classes.keys())
    missing = [name for name in REQUIRED_CLASSES if name not in classes]
    reject_policy = config.get("default_unknown_class_policy") == "reject"

    profile_fields_ok = True
    missing_fields: dict[str, list[str]] = {}
    required_profile_fields = [
        "retention_class",
        "max_size_bytes",
        "symbol_overhead_budget",
        "fetch_policy",
        "integrity_level",
        "description",
    ]

    for name in REQUIRED_CLASSES:
        profile = classes.get(name, {})
        absent = [field for field in required_profile_fields if field not in profile]
        if absent:
            profile_fields_ok = False
            missing_fields[name] = absent

    passed = len(missing) == 0 and reject_policy and profile_fields_ok
    return check_result(
        CHECK_IDS["config"],
        "TOML registry has required classes and reject policy",
        passed,
        {
            "class_names": class_names,
            "missing_classes": missing,
            "reject_policy": reject_policy,
            "missing_profile_fields": missing_fields,
        },
    )


def check_registry_snapshot() -> dict[str, Any]:
    if not REGISTRY_PATH.exists() or not CONFIG_PATH.exists():
        return check_result(CHECK_IDS["registry"], "Registry JSON snapshot matches config and version contract", False)

    config = load_config()
    registry = load_registry()
    cfg_classes = config.get("classes", {})
    reg_classes = registry.get("classes", {})

    class_match = sorted(cfg_classes.keys()) == sorted(reg_classes.keys())
    reject_match = config.get("default_unknown_class_policy") == registry.get("default_unknown_class_policy")
    has_versions = config.get("schema_version") == "1.0" and registry.get("schema_version") == "1.0"

    passed = class_match and reject_match and has_versions
    return check_result(
        CHECK_IDS["registry"],
        "Registry JSON snapshot matches config and version contract",
        passed,
        {
            "class_match": class_match,
            "reject_match": reject_match,
            "versions_ok": has_versions,
        },
    )


def check_unit_semantics() -> dict[str, Any]:
    config = load_config() if CONFIG_PATH.exists() else {}
    known_ok, known_err = validate_class_name("critical_marker", config)
    unknown_ok, unknown_err = validate_class_name("shadow_object", config)
    passed = known_ok and known_err is None and (not unknown_ok) and unknown_err == "OCP_UNKNOWN_CLASS"
    return check_result(
        CHECK_IDS["unit"],
        "Class validator accepts required classes and rejects unknown class",
        passed,
        {
            "known_ok": known_ok,
            "unknown_ok": unknown_ok,
            "unknown_error": unknown_err,
        },
    )


def check_integration_fixture() -> dict[str, Any]:
    if not FIXTURE_PATH.exists() or not CONFIG_PATH.exists():
        return check_result(CHECK_IDS["integration"], "Fixture cases agree with registry validator semantics", False)

    fixture = json.loads(FIXTURE_PATH.read_text())
    config = load_config()
    cases = fixture.get("cases", [])
    matched = 0

    for case in cases:
        actual_valid, actual_err = validate_class_name(case.get("class_name", ""), config)
        expected_valid = bool(case.get("expected_valid"))
        if expected_valid == actual_valid:
            if (not expected_valid) and case.get("expected_error") not in (None, actual_err):
                continue
            matched += 1

    passed = len(cases) > 0 and matched == len(cases)
    return check_result(
        CHECK_IDS["integration"],
        "Fixture cases agree with registry validator semantics",
        passed,
        {"case_count": len(cases), "matched_cases": matched},
    )


def check_e2e_inputs() -> dict[str, Any]:
    required = [SPEC_PATH, CONFIG_PATH, REGISTRY_PATH, FIXTURE_PATH]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    return check_result(
        CHECK_IDS["e2e"],
        "End-to-end gate inputs exist for registry verification flow",
        len(missing) == 0,
        {"missing_paths": missing},
    )


def check_event_codes() -> dict[str, Any]:
    registry = load_registry() if REGISTRY_PATH.exists() else {}
    found_event_codes = registry.get("event_codes", [])
    found_error_codes = registry.get("error_codes", [])
    passed = set(EVENT_CODES).issubset(set(found_event_codes)) and set(ERROR_CODES).issubset(set(found_error_codes))
    return check_result(
        CHECK_IDS["logs"],
        "Stable event/error code sets are present for telemetry and triage",
        passed,
        {
            "event_codes": found_event_codes,
            "error_codes": found_error_codes,
        },
    )


def self_test() -> dict[str, Any]:
    checks = [
        check_spec_contract(),
        check_config_contract(),
        check_registry_snapshot(),
        check_unit_semantics(),
        check_integration_fixture(),
        check_e2e_inputs(),
        check_event_codes(),
    ]
    failing = [check for check in checks if check["status"] != "PASS"]
    return {
        "gate": "object_class_profile_registry_verification",
        "bead": "bd-2573",
        "section": "10.14",
        "verdict": "PASS" if not failing else "FAIL",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main() -> int:
    json_output = "--json" in sys.argv
    result = self_test()

    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(result, indent=2) + "\n")

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            icon = "OK" if check["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {check['id']}: {check['description']}")
        print(f"\nVerdict: {result['verdict']}")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
