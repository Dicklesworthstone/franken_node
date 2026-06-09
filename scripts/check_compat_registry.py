#!/usr/bin/env python3
"""
Compatibility Behavior Registry Verifier.

Validates that COMPATIBILITY_REGISTRY.json exists, conforms to schema rules,
and all entries have valid field values.

Usage:
    python3 scripts/check_compat_registry.py [--json]

Exit codes:
    0 = PASS
    1 = FAIL
"""

import json
import re
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from datetime import datetime, timezone

REGISTRY_PATH = ROOT / "docs" / "COMPATIBILITY_REGISTRY.json"
SCHEMA_PATH = ROOT / "schemas" / "compatibility_registry.schema.json"

EVIDENCE_PATHS = {
    "primary_registry": "docs/COMPATIBILITY_REGISTRY.json",
    "registry_schema": "schemas/compatibility_registry.schema.json",
    "contract": "docs/specs/section_10_2/bd-2qf_contract.md",
    "verifier": "scripts/check_compat_registry.py",
    "regression_tests": "tests/test_check_compat_registry.py",
    "machine_evidence": "artifacts/section_10_2/bd-2qf/verification_evidence.json",
    "human_summary": "artifacts/section_10_2/bd-2qf/verification_summary.md",
}

VERIFICATION_COMMANDS = [
    {
        "command": "python3 scripts/check_compat_registry.py --json",
        "covers": [
            "primary compatibility registry path",
            "registry schema path",
            "registry structure",
            "typed shim metadata fields",
            "first-tranche operation schemas",
            "Node/Bun error-code parity table",
            "resource budgets and policy hooks",
            "unique behavior IDs",
            "band coverage",
        ],
    },
    {
        "command": "python3 -m pytest tests/test_check_compat_registry.py",
        "covers": [
            "registry verifier checks",
            "typed metadata constants",
            "first-tranche contract requirements",
            "primary implementation evidence path citations",
        ],
    },
]

VALID_BANDS = {"core", "high-value", "edge", "unsafe"}
VALID_SHIM_TYPES = {"native", "polyfill", "bridge", "stub"}
VALID_ORACLE_STATUSES = {"validated", "pending", "not-applicable"}
VALID_SIDE_EFFECT_CATEGORIES = {
    "pure",
    "filesystem_read",
    "filesystem_write",
    "network_egress",
    "network_listener",
    "environment_read",
    "module_graph_read",
}
VALID_POLICY_HOOKS = {"capability", "ssrf", "profile"}
FIRST_TRANCHE_REQUIRED_IDS = {
    "compat:fs:readFile",
    "compat:fs:writeFile",
    "compat:http:request",
    "compat:process:env",
    "compat:module:resolve",
}
FIRST_TRANCHE_REQUIRED_POLICY_HOOKS = {
    "compat:fs:readFile": {"capability", "profile"},
    "compat:fs:writeFile": {"capability", "profile"},
    "compat:http:request": {"capability", "ssrf", "profile"},
    "compat:process:env": {"capability", "profile"},
    "compat:module:resolve": {"capability", "profile"},
}
FIRST_TRANCHE_SIDE_EFFECTS = {
    "compat:fs:readFile": "filesystem_read",
    "compat:fs:writeFile": "filesystem_write",
    "compat:http:request": "network_egress",
    "compat:process:env": "environment_read",
    "compat:module:resolve": "module_graph_read",
}
ID_PATTERN = re.compile(r'^compat:[a-z_]+:[a-zA-Z_]+$')
SCHEMA_ID_PATTERN = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+(\.[0-9]+)?$')
ERROR_CODE_PATTERN = re.compile(r'^(ERR_[A-Z0-9_]+|[A-Z][A-Z0-9_]+)$')


def check_registry_exists() -> dict:
    """REG-EXISTS: Check that COMPATIBILITY_REGISTRY.json exists."""
    check = {"id": "REG-EXISTS", "status": "PASS", "details": {}}
    if not REGISTRY_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "docs/COMPATIBILITY_REGISTRY.json not found"
    else:
        check["details"]["path"] = str(REGISTRY_PATH.relative_to(ROOT))
    return check


def check_schema_exists() -> dict:
    """REG-SCHEMA: Check that the JSON schema exists."""
    check = {"id": "REG-SCHEMA", "status": "PASS", "details": {}}
    if not SCHEMA_PATH.exists():
        check["status"] = "FAIL"
        check["details"]["error"] = "schemas/compatibility_registry.schema.json not found"
    else:
        check["details"]["path"] = str(SCHEMA_PATH.relative_to(ROOT))
    return check


def load_registry() -> tuple[dict | None, str | None]:
    """Load and parse the registry JSON."""
    if not REGISTRY_PATH.exists():
        return None, "File not found"
    try:
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        return data, None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"


def check_registry_structure() -> dict:
    """REG-STRUCTURE: Check registry has required top-level fields."""
    check = {"id": "REG-STRUCTURE", "status": "PASS", "details": {}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    if data.get("schema_version") != "1.0":
        check["status"] = "FAIL"
        check["details"]["error"] = f"schema_version must be '1.0', got '{data.get('schema_version')}'"
        return check

    if "behaviors" not in data or not isinstance(data["behaviors"], list):
        check["status"] = "FAIL"
        check["details"]["error"] = "Missing or invalid 'behaviors' array"
        return check

    check["details"]["behavior_count"] = len(data["behaviors"])
    return check


def check_entry_fields() -> dict:
    """REG-FIELDS: Check each entry has all required fields with valid values."""
    check = {"id": "REG-FIELDS", "status": "PASS", "details": {"entries": [], "errors": []}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    required_fields = [
        "id",
        "api_family",
        "api_name",
        "band",
        "shim_type",
        "spec_ref",
        "oracle_status",
        "args_schema",
        "result_schema",
        "error_schema",
        "node_error_codes",
        "bun_error_codes",
        "side_effect_category",
        "resource_budget",
        "policy_hooks",
    ]

    for i, entry in enumerate(data.get("behaviors", [])):
        entry_errors = []

        # Check required fields
        for field in required_fields:
            if field not in entry or not entry[field]:
                entry_errors.append(f"missing or empty '{field}'")

        # Validate ID format
        entry_id = entry.get("id", "")
        if entry_id and not ID_PATTERN.match(entry_id):
            entry_errors.append(f"invalid id format: '{entry_id}'")

        # Validate enum fields
        band = entry.get("band", "")
        if band and band not in VALID_BANDS:
            entry_errors.append(f"invalid band: '{band}'")

        shim_type = entry.get("shim_type", "")
        if shim_type and shim_type not in VALID_SHIM_TYPES:
            entry_errors.append(f"invalid shim_type: '{shim_type}'")

        oracle_status = entry.get("oracle_status", "")
        if oracle_status and oracle_status not in VALID_ORACLE_STATUSES:
            entry_errors.append(f"invalid oracle_status: '{oracle_status}'")

        for schema_field in ("args_schema", "result_schema", "error_schema"):
            schema_id = entry.get(schema_field, "")
            if schema_id and not SCHEMA_ID_PATTERN.match(schema_id):
                entry_errors.append(f"invalid {schema_field}: '{schema_id}'")

        for code_field in ("node_error_codes", "bun_error_codes"):
            codes = entry.get(code_field)
            if not isinstance(codes, list) or not codes:
                entry_errors.append(f"'{code_field}' must be a non-empty array")
            else:
                invalid_codes = [
                    code for code in codes
                    if not isinstance(code, str) or not ERROR_CODE_PATTERN.match(code)
                ]
                if invalid_codes:
                    entry_errors.append(f"invalid {code_field}: {invalid_codes}")

        side_effect_category = entry.get("side_effect_category", "")
        if side_effect_category and side_effect_category not in VALID_SIDE_EFFECT_CATEGORIES:
            entry_errors.append(f"invalid side_effect_category: '{side_effect_category}'")

        budget = entry.get("resource_budget")
        budget_fields = ("max_input_bytes", "max_output_bytes", "max_duration_ms", "max_side_effects")
        if not isinstance(budget, dict):
            entry_errors.append("'resource_budget' must be an object")
        else:
            for field in budget_fields:
                value = budget.get(field)
                if not isinstance(value, int):
                    entry_errors.append(f"resource_budget.{field} must be an integer")
                elif field == "max_duration_ms" and value < 1:
                    entry_errors.append("resource_budget.max_duration_ms must be >= 1")
                elif field != "max_duration_ms" and value < 0:
                    entry_errors.append(f"resource_budget.{field} must be >= 0")
            unknown_budget_fields = sorted(set(budget) - set(budget_fields))
            if unknown_budget_fields:
                entry_errors.append(f"unknown resource_budget fields: {unknown_budget_fields}")

        policy_hooks = entry.get("policy_hooks")
        if not isinstance(policy_hooks, list) or not policy_hooks:
            entry_errors.append("'policy_hooks' must be a non-empty array")
        else:
            invalid_hooks = [hook for hook in policy_hooks if hook not in VALID_POLICY_HOOKS]
            if invalid_hooks:
                entry_errors.append(f"invalid policy_hooks: {invalid_hooks}")
            if len(policy_hooks) != len(set(policy_hooks)):
                entry_errors.append("policy_hooks must not contain duplicates")

        if entry_errors:
            check["status"] = "FAIL"
            for e in entry_errors:
                check["details"]["errors"].append(f"behaviors[{i}] ({entry_id}): {e}")

        check["details"]["entries"].append({
            "id": entry_id,
            "band": band,
            "shim_type": shim_type,
            "side_effect_category": side_effect_category,
            "valid": len(entry_errors) == 0,
        })

    return check


def check_unique_ids() -> dict:
    """REG-UNIQUE: Check that all behavior IDs are unique."""
    check = {"id": "REG-UNIQUE", "status": "PASS", "details": {}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    ids = [b.get("id", "") for b in data.get("behaviors", [])]
    seen = set()
    duplicates = []
    for bid in ids:
        if bid in seen:
            duplicates.append(bid)
        seen.add(bid)

    check["details"]["total_ids"] = len(ids)
    check["details"]["unique_ids"] = len(seen)
    if duplicates:
        check["status"] = "FAIL"
        check["details"]["duplicates"] = duplicates
    return check


def check_band_coverage() -> dict:
    """REG-COVERAGE: Check that at least one entry exists per band with entries."""
    check = {"id": "REG-COVERAGE", "status": "PASS", "details": {"bands_represented": {}}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    bands_found = set()
    for entry in data.get("behaviors", []):
        band = entry.get("band", "")
        if band in VALID_BANDS:
            bands_found.add(band)

    for band in VALID_BANDS:
        check["details"]["bands_represented"][band] = band in bands_found

    # At minimum, core and high-value should have entries
    if "core" not in bands_found:
        check["status"] = "FAIL"
        check["details"]["error"] = "No 'core' band entries in registry"
    return check


def check_first_tranche_contracts() -> dict:
    """REG-FIRST-TRANCHE: Check required first-tranche operation contracts."""
    check = {"id": "REG-FIRST-TRANCHE", "status": "PASS", "details": {"errors": []}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    by_id = {entry.get("id"): entry for entry in data.get("behaviors", [])}
    missing = sorted(FIRST_TRANCHE_REQUIRED_IDS - set(by_id))
    check["details"]["required_ids"] = sorted(FIRST_TRANCHE_REQUIRED_IDS)
    check["details"]["present_ids"] = sorted(set(by_id) & FIRST_TRANCHE_REQUIRED_IDS)

    if missing:
        check["status"] = "FAIL"
        check["details"]["errors"].append(f"missing first-tranche ids: {missing}")

    for entry_id in sorted(FIRST_TRANCHE_REQUIRED_IDS & set(by_id)):
        entry = by_id[entry_id]
        expected_hooks = FIRST_TRANCHE_REQUIRED_POLICY_HOOKS[entry_id]
        actual_hooks = set(entry.get("policy_hooks", []))
        missing_hooks = sorted(expected_hooks - actual_hooks)
        if missing_hooks:
            check["status"] = "FAIL"
            check["details"]["errors"].append(f"{entry_id} missing policy hooks: {missing_hooks}")

        expected_side_effect = FIRST_TRANCHE_SIDE_EFFECTS[entry_id]
        actual_side_effect = entry.get("side_effect_category")
        if actual_side_effect != expected_side_effect:
            check["status"] = "FAIL"
            check["details"]["errors"].append(
                f"{entry_id} side_effect_category must be {expected_side_effect}, got {actual_side_effect}"
            )

        for schema_field in ("args_schema", "result_schema", "error_schema"):
            if not entry.get(schema_field):
                check["status"] = "FAIL"
                check["details"]["errors"].append(f"{entry_id} missing {schema_field}")

    return check


def check_error_parity_table() -> dict:
    """REG-ERROR-PARITY: Check first-tranche Node/Bun error tables are documented."""
    check = {"id": "REG-ERROR-PARITY", "status": "PASS", "details": {"errors": []}}
    data, err = load_registry()
    if err:
        check["status"] = "FAIL"
        check["details"]["error"] = err
        return check

    by_id = {entry.get("id"): entry for entry in data.get("behaviors", [])}
    for entry_id in sorted(FIRST_TRANCHE_REQUIRED_IDS):
        entry = by_id.get(entry_id)
        if entry is None:
            check["status"] = "FAIL"
            check["details"]["errors"].append(f"{entry_id} missing from registry")
            continue

        node_codes = entry.get("node_error_codes", [])
        bun_codes = entry.get("bun_error_codes", [])
        if not node_codes:
            check["status"] = "FAIL"
            check["details"]["errors"].append(f"{entry_id} missing node_error_codes")
        if not bun_codes:
            check["status"] = "FAIL"
            check["details"]["errors"].append(f"{entry_id} missing bun_error_codes")
        if node_codes and bun_codes and not (set(node_codes) & set(bun_codes)):
            check["status"] = "FAIL"
            check["details"]["errors"].append(
                f"{entry_id} has no shared Node/Bun error-code parity entries"
            )

    return check


def build_report(timestamp: str) -> dict:
    checks = [
        check_registry_exists(),
        check_schema_exists(),
        check_registry_structure(),
        check_entry_fields(),
        check_unique_ids(),
        check_band_coverage(),
        check_first_tranche_contracts(),
        check_error_parity_table(),
    ]

    failing = [c for c in checks if c["status"] == "FAIL"]
    verdict = "PASS" if not failing else "FAIL"

    return {
        "gate": "compatibility_registry_verification",
        "section": "10.2",
        "verdict": verdict,
        "timestamp": timestamp,
        "evidence_paths": EVIDENCE_PATHS,
        "verification_commands": VERIFICATION_COMMANDS,
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": sum(1 for c in checks if c["status"] == "PASS"),
            "failing_checks": len(failing),
        },
    }


def main():
    logger = configure_test_logging("check_compat_registry")
    json_output = "--json" in sys.argv
    timestamp = datetime.now(timezone.utc).isoformat()
    report = build_report(timestamp)

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=== Compatibility Behavior Registry Verifier ===")
        print(f"Timestamp: {timestamp}")
        print()
        for c in report["checks"]:
            icon = "OK" if c["status"] == "PASS" else "FAIL"
            print(f"  [{icon}] {c['id']}")
            if c["status"] == "FAIL":
                details = c.get("details", {})
                if "error" in details:
                    print(f"       Error: {details['error']}")
                if "errors" in details:
                    for e in details["errors"][:5]:
                        print(f"       Error: {e}")
        print()
        print(f"Checks: {report['summary']['passing_checks']}/{report['summary']['total_checks']} pass")
        print(f"Verdict: {report['verdict']}")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
