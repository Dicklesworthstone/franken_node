#!/usr/bin/env python3
"""Verifier for bd-2owx adjacent substrate policy contract."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BEAD_ID = "bd-2owx"
SECTION = "10.16"
TITLE = (
    "Publish substrate policy contract for `frankentui`, `frankensqlite`, "
    "`sqlmodel_rust`, and `fastapi_rust`."
)

POLICY_PATH = ROOT / "docs" / "architecture" / "adjacent_substrate_policy.md"
MANIFEST_PATH = ROOT / "artifacts" / "10.16" / "adjacent_substrate_policy_manifest.json"
EVIDENCE_PATH = (
    ROOT / "artifacts" / "section_10_16" / BEAD_ID / "verification_evidence.json"
)
SUMMARY_PATH = ROOT / "artifacts" / "section_10_16" / BEAD_ID / "verification_summary.md"

EVENT_POLICY_LOADED = "SUBSTRATE_POLICY_LOADED"
EVENT_MODULE_UNMAPPED = "SUBSTRATE_POLICY_MODULE_UNMAPPED"
EVENT_SCHEMA_INVALID = "SUBSTRATE_POLICY_SCHEMA_INVALID"
EXPECTED_EVENT_CODES = [
    EVENT_POLICY_LOADED,
    EVENT_MODULE_UNMAPPED,
    EVENT_SCHEMA_INVALID,
]

ALLOWED_SUBSTRATES = {
    "frankentui",
    "frankensqlite",
    "sqlmodel_rust",
    "fastapi_rust",
}
ALLOWED_PLANES = {"presentation", "persistence", "model", "service"}
REQUIRED_SCOPE_PATHS = [
    "crates/franken-node/src/connector/",
    "crates/franken-node/src/conformance/",
    "crates/franken-node/src/control_plane/",
    "crates/franken-node/src/runtime/",
    "crates/franken-node/src/security/",
    "crates/franken-node/src/supply_chain/",
    "crates/franken-node/src/cli.rs",
    "crates/franken-node/src/config.rs",
]
REQUIRED_WAIVER_FIELDS = ["risk_analysis", "scope", "owner_signoff", "expiry"]
EXPECTED_WAIVER_REFERENCE = "bd-159q"

CONTRACT_START = "<!-- POLICY_CONTRACT_START -->"
CONTRACT_END = "<!-- POLICY_CONTRACT_END -->"
TIER_KEYS = ("mandatory_modules", "should_use_modules", "optional_modules")


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "pass": bool(passed), "detail": detail}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def list_source_modules(module_root: str) -> list[str]:
    root = ROOT / module_root
    if not root.is_dir():
        return []
    modules = []
    for file_path in root.rglob("*.rs"):
        if file_path.is_file():
            modules.append(file_path.relative_to(ROOT).as_posix())
    modules.sort()
    return modules


def compute_policy_hash(manifest: dict[str, Any]) -> str:
    normalized = copy.deepcopy(manifest)
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        metadata = dict(metadata)
        metadata["policy_hash"] = "__POLICY_HASH_PLACEHOLDER__"
        normalized["metadata"] = metadata
    canonical = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def validate_manifest_schema(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required_top = [
        "schema_version",
        "policy_id",
        "module_root",
        "classification_mode",
        "substrates",
        "exceptions",
        "metadata",
    ]
    for key in required_top:
        if key not in manifest:
            errors.append(f"missing top-level key: {key}")

    substrates = manifest.get("substrates")
    if not isinstance(substrates, list) or not substrates:
        errors.append("substrates must be a non-empty array")
        substrates = []

    seen_names: set[str] = set()
    for idx, substrate in enumerate(substrates):
        if not isinstance(substrate, dict):
            errors.append(f"substrates[{idx}] must be an object")
            continue
        for key in ("name", "version", "plane", *TIER_KEYS):
            if key not in substrate:
                errors.append(f"substrates[{idx}] missing key: {key}")
        name = substrate.get("name")
        if not isinstance(name, str):
            errors.append(f"substrates[{idx}].name must be a string")
            continue
        if name in seen_names:
            errors.append(f"duplicate substrate name: {name}")
        seen_names.add(name)
        if name not in ALLOWED_SUBSTRATES:
            errors.append(f"unknown substrate name: {name}")

        version = substrate.get("version")
        if not isinstance(version, str) or not version.strip():
            errors.append(f"substrates[{idx}].version must be a non-empty string")
        plane = substrate.get("plane")
        if plane not in ALLOWED_PLANES:
            errors.append(f"substrates[{idx}].plane invalid: {plane}")

        for tier_key in TIER_KEYS:
            tier_values = substrate.get(tier_key)
            if not isinstance(tier_values, list) or not tier_values:
                errors.append(f"substrates[{idx}].{tier_key} must be a non-empty array")
                continue
            if any(not isinstance(value, str) or not value for value in tier_values):
                errors.append(f"substrates[{idx}].{tier_key} entries must be non-empty strings")

    exceptions = manifest.get("exceptions")
    if not isinstance(exceptions, list):
        errors.append("exceptions must be an array")
        exceptions = []
    for idx, entry in enumerate(exceptions):
        if not isinstance(entry, dict):
            errors.append(f"exceptions[{idx}] must be an object")
            continue
        for key in ("module", "substrate", "reason", "waiver_required"):
            if key not in entry:
                errors.append(f"exceptions[{idx}] missing key: {key}")
        if entry.get("substrate") not in ALLOWED_SUBSTRATES:
            errors.append(f"exceptions[{idx}] uses unknown substrate: {entry.get('substrate')}")
        if not isinstance(entry.get("module"), str) or not entry.get("module"):
            errors.append(f"exceptions[{idx}].module must be a non-empty string")
        if not isinstance(entry.get("reason"), str) or not entry.get("reason"):
            errors.append(f"exceptions[{idx}].reason must be a non-empty string")
        if not isinstance(entry.get("waiver_required"), bool):
            errors.append(f"exceptions[{idx}].waiver_required must be boolean")

    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
    else:
        for key in ("schema_version", "created_at", "policy_hash"):
            if key not in metadata:
                errors.append(f"metadata missing key: {key}")
            elif not isinstance(metadata.get(key), str) or not metadata.get(key):
                errors.append(f"metadata.{key} must be a non-empty string")

    if manifest.get("classification_mode") != "first_match":
        errors.append("classification_mode must be first_match")

    return errors


def classify_module(
    module_path: str,
    substrate: dict[str, Any],
) -> tuple[str | None, str | None]:
    for tier_key in TIER_KEYS:
        patterns = substrate.get(tier_key) or []
        if not isinstance(patterns, list):
            continue
        for pattern in patterns:
            if isinstance(pattern, str) and fnmatch.fnmatchcase(module_path, pattern):
                return tier_key, pattern
    return None, None


def classify_modules(
    modules: list[str],
    substrates: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, dict[str, str]]], list[dict[str, str]]]:
    assignments: dict[str, dict[str, dict[str, str]]] = {}
    unmapped: list[dict[str, str]] = []

    for substrate in substrates:
        name = str(substrate.get("name", ""))
        substrate_map: dict[str, dict[str, str]] = {}
        for module_path in modules:
            tier, pattern = classify_module(module_path, substrate)
            if tier is None:
                unmapped.append({"substrate": name, "module": module_path})
                continue
            substrate_map[module_path] = {"tier": tier, "pattern": str(pattern)}
        assignments[name] = substrate_map

    return assignments, unmapped


def tier_counts(assignments: dict[str, dict[str, dict[str, str]]]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for substrate, mapping in assignments.items():
        substrate_counts = {tier: 0 for tier in TIER_KEYS}
        for record in mapping.values():
            tier_name = record.get("tier")
            if tier_name in substrate_counts:
                substrate_counts[tier_name] += 1
        counts[substrate] = substrate_counts
    return counts


def parse_policy_contract_block(markdown: str) -> dict[str, Any] | None:
    if CONTRACT_START not in markdown or CONTRACT_END not in markdown:
        return None
    start = markdown.index(CONTRACT_START) + len(CONTRACT_START)
    end = markdown.index(CONTRACT_END, start)
    payload = markdown[start:end].strip()
    if not payload:
        return None
    try:
        parsed = json.JSONDecoder().decode(payload)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _configure_logging() -> None:
    from scripts.lib.test_logger import configure_test_logging

    configure_test_logging("check_adjacent_substrate_policy")


def compare_contract_to_manifest(
    contract: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if contract.get("policy_id") != manifest.get("policy_id"):
        errors.append("policy_id mismatch between markdown contract and manifest")
    if contract.get("schema_version") != manifest.get("schema_version"):
        errors.append("schema_version mismatch between markdown contract and manifest")
    if contract.get("manifest_path") != str(MANIFEST_PATH.relative_to(ROOT)):
        errors.append("manifest_path mismatch in markdown contract block")
    if contract.get("classification_mode") != manifest.get("classification_mode"):
        errors.append("classification_mode mismatch between markdown contract and manifest")

    contract_substrates = contract.get("substrates")
    manifest_substrates = manifest.get("substrates")
    if not isinstance(contract_substrates, list):
        errors.append("markdown contract substrates must be an array")
    if not isinstance(manifest_substrates, list):
        errors.append("manifest substrates must be an array")

    if isinstance(contract_substrates, list) and isinstance(manifest_substrates, list):
        normalized_contract = sorted(
            (
                item.get("name"),
                item.get("version"),
                item.get("plane"),
            )
            for item in contract_substrates
            if isinstance(item, dict)
        )
        normalized_manifest = sorted(
            (
                item.get("name"),
                item.get("version"),
                item.get("plane"),
            )
            for item in manifest_substrates
            if isinstance(item, dict)
        )
        if normalized_contract != normalized_manifest:
            errors.append("substrate descriptor mismatch between markdown contract and manifest")

    event_codes = contract.get("event_codes")
    if sorted(event_codes) != sorted(EXPECTED_EVENT_CODES):
        errors.append("event code list mismatch in markdown contract block")

    if contract.get("waiver_reference_bead") != EXPECTED_WAIVER_REFERENCE:
        errors.append("waiver_reference_bead must be bd-159q")

    waiver_fields = contract.get("waiver_required_metadata")
    if sorted(waiver_fields or []) != sorted(REQUIRED_WAIVER_FIELDS):
        errors.append("waiver_required_metadata mismatch in markdown contract block")

    manifest_policy_hash = (
        manifest.get("metadata", {}) if isinstance(manifest.get("metadata"), dict) else {}
    ).get("policy_hash")
    if contract.get("policy_hash") != manifest_policy_hash:
        errors.append("policy_hash mismatch between markdown contract and manifest")

    return errors


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    checks.append(_check("policy_file_exists", POLICY_PATH.is_file(), str(POLICY_PATH)))
    checks.append(_check("manifest_file_exists", MANIFEST_PATH.is_file(), str(MANIFEST_PATH)))

    policy_src = POLICY_PATH.read_text(encoding="utf-8") if POLICY_PATH.is_file() else ""
    manifest = _load_json(MANIFEST_PATH)
    checks.append(
        _check(
            "manifest_parseable",
            manifest is not None,
            "json parse ok" if manifest is not None else "invalid or missing manifest JSON",
        )
    )

    if manifest is None:
        passed = sum(1 for item in checks if item["pass"])
        failed = len(checks) - passed
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "title": TITLE,
            "checks": checks,
            "events": events,
            "total": len(checks),
            "passed": passed,
            "failed": failed,
            "overall_pass": False,
            "verdict": "FAIL",
            "status": "fail",
            "metrics": {},
        }

    schema_errors = validate_manifest_schema(manifest)
    checks.append(
        _check(
            "manifest_schema_valid",
            len(schema_errors) == 0,
            "schema ok" if not schema_errors else f"errors={schema_errors}",
        )
    )
    if schema_errors:
        events.append(
            {
                "code": EVENT_SCHEMA_INVALID,
                "detail": f"schema errors: {len(schema_errors)}",
            }
        )

    expected_hash = compute_policy_hash(manifest)
    actual_hash = (
        manifest.get("metadata", {}) if isinstance(manifest.get("metadata"), dict) else {}
    ).get("policy_hash")
    checks.append(
        _check(
            "policy_hash_matches",
            actual_hash == expected_hash,
            f"expected={expected_hash} actual={actual_hash}",
        )
    )
    checks.append(
        _check(
            "policy_hash_deterministic",
            expected_hash == compute_policy_hash(manifest),
            "hash computation stable across repeated evaluation",
        )
    )

    modules = list_source_modules(str(manifest.get("module_root", "")))
    checks.append(
        _check(
            "module_inventory_non_empty",
            len(modules) > 0,
            f"module_count={len(modules)}",
        )
    )

    required_missing = []
    for required in REQUIRED_SCOPE_PATHS:
        if required.endswith("/"):
            if not any(module.startswith(required) for module in modules):
                required_missing.append(required)
        else:
            if required not in modules:
                required_missing.append(required)
    checks.append(
        _check(
            "required_scope_classified",
            len(required_missing) == 0,
            f"missing={required_missing}",
        )
    )

    substrates = manifest.get("substrates")
    if not isinstance(substrates, list):
        substrates = []
    assignments, unmapped = classify_modules(
        modules,
        [entry for entry in substrates if isinstance(entry, dict)],
    )
    checks.append(
        _check(
            "module_coverage_complete",
            len(unmapped) == 0,
            f"unmapped_count={len(unmapped)}",
        )
    )
    if unmapped:
        events.append(
            {
                "code": EVENT_MODULE_UNMAPPED,
                "detail": f"unmapped modules found: {len(unmapped)}",
            }
        )
    else:
        events.append(
            {
                "code": EVENT_POLICY_LOADED,
                "detail": f"policy loaded for {len(modules)} modules",
            }
        )

    contract = parse_policy_contract_block(policy_src)
    checks.append(
        _check(
            "policy_contract_block_parseable",
            contract is not None,
            "policy contract block parsed as JSON"
            if contract is not None
            else "missing or invalid POLICY_CONTRACT block",
        )
    )
    if contract is not None:
        contract_errors = compare_contract_to_manifest(contract, manifest)
        checks.append(
            _check(
                "markdown_manifest_consistent",
                len(contract_errors) == 0,
                "contract and manifest are consistent"
                if not contract_errors
                else f"errors={contract_errors}",
            )
        )
    else:
        checks.append(
            _check(
                "markdown_manifest_consistent",
                False,
                "cannot compare because contract block is missing/invalid",
            )
        )

    checks.append(
        _check(
            "waiver_reference_present",
            EXPECTED_WAIVER_REFERENCE in policy_src,
            f"policy references {EXPECTED_WAIVER_REFERENCE}",
        )
    )
    checks.append(
        _check(
            "waiver_required_fields_documented",
            all(field in policy_src for field in REQUIRED_WAIVER_FIELDS),
            f"required_fields={REQUIRED_WAIVER_FIELDS}",
        )
    )
    checks.append(
        _check(
            "event_codes_documented",
            all(code in policy_src for code in EXPECTED_EVENT_CODES),
            f"event_codes={EXPECTED_EVENT_CODES}",
        )
    )

    exceptions = manifest.get("exceptions")
    exception_pattern_errors: list[str] = []
    if isinstance(exceptions, list):
        for idx, entry in enumerate(exceptions):
            if not isinstance(entry, dict):
                continue
            module_pattern = entry.get("module")
            if not isinstance(module_pattern, str):
                continue
            if not any(fnmatch.fnmatchcase(module, module_pattern) for module in modules):
                exception_pattern_errors.append(f"exceptions[{idx}] pattern matches no modules")
    checks.append(
        _check(
            "exception_patterns_resolve",
            len(exception_pattern_errors) == 0,
            "all exception module patterns match at least one source module"
            if not exception_pattern_errors
            else f"errors={exception_pattern_errors}",
        )
    )

    assignment_totals = {
        substrate: len(mapping) for substrate, mapping in assignments.items()
    }

    passed = sum(1 for item in checks if item["pass"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "checks": checks,
        "events": events,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "overall_pass": failed == 0,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "status": "pass" if failed == 0 else "fail",
        "metrics": {
            "module_count": len(modules),
            "substrate_count": len(assignments),
            "unmapped_count": len(unmapped),
            "assignment_totals": assignment_totals,
            "tier_counts": tier_counts(assignments),
            "expected_event_codes": EXPECTED_EVENT_CODES,
        },
    }


def self_test() -> bool:
    sample_manifest = {
        "schema_version": "1.0.0",
        "policy_id": "sample",
        "module_root": "crates/franken-node/src",
        "classification_mode": "first_match",
        "substrates": [
            {
                "name": "frankentui",
                "version": "^0.1.0",
                "plane": "presentation",
                "mandatory_modules": ["crates/franken-node/src/cli.rs"],
                "should_use_modules": ["crates/franken-node/src/main.rs"],
                "optional_modules": ["crates/franken-node/src/**"],
            }
        ],
        "exceptions": [],
        "metadata": {
            "schema_version": "1.0.0",
            "created_at": "2026-02-22T00:00:00Z",
            "policy_hash": "sha256:test",
        },
    }
    schema_errors = validate_manifest_schema(sample_manifest)
    if schema_errors:
        raise RuntimeError(f"expected valid sample manifest, got errors: {schema_errors}")

    bad_manifest = copy.deepcopy(sample_manifest)
    bad_manifest["substrates"][0]["name"] = "unknown"
    has_unknown_substrate_error = any(
        "unknown substrate name" in error for error in validate_manifest_schema(bad_manifest)
    )
    if not has_unknown_substrate_error:
        raise RuntimeError("expected unknown substrate validation error")

    markdown = (
        "prefix\n"
        f"{CONTRACT_START}\n"
        "{\"policy_id\":\"sample\",\"schema_version\":\"1.0.0\"}\n"
        f"{CONTRACT_END}\n"
    )
    parsed = parse_policy_contract_block(markdown)
    if parsed is None:
        raise RuntimeError("expected embedded policy contract JSON to parse")
    if parsed.get("policy_id") != "sample":
        raise RuntimeError(f"unexpected policy_id in parsed contract: {parsed!r}")

    result = run_all()
    if result["bead_id"] != BEAD_ID:
        raise RuntimeError(f"bead_id mismatch: {result['bead_id']}")
    if result["section"] != SECTION:
        raise RuntimeError(f"section mismatch: {result['section']}")
    if "checks" not in result or not isinstance(result["checks"], list):
        raise RuntimeError(f"malformed run_all result: {result!r}")
    return True


def main() -> None:
    _configure_logging()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run internal self test")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self_test passed")
        return

    result = run_all()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for item in result["checks"]:
            status = "PASS" if item["pass"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")
        print(f"\n{BEAD_ID}: {result['passed']}/{result['total']} checks - {result['verdict']}")

    sys.exit(0 if result["overall_pass"] else 1)


if __name__ == "__main__":
    main()
