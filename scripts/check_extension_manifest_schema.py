#!/usr/bin/env python3
"""Verification script for bd-1gx signed extension manifest schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402


SPEC_PATH = ROOT / "docs/specs/section_10_4/extension_manifest_schema.md"
SCHEMA_PATH = ROOT / "schemas/extension_manifest.schema.json"
RUST_IMPL_PATH = ROOT / "crates/franken-node/src/supply_chain/manifest.rs"
INTEGRATION_TEST_PATH = ROOT / "tests/integration/extension_manifest_admission.rs"

EVIDENCE_DIR = ROOT / "artifacts/section_10_4/bd-1gx"
EVIDENCE_PATH = EVIDENCE_DIR / "verification_evidence.json"
SUMMARY_PATH = EVIDENCE_DIR / "verification_summary.md"

REQUIRED_CAPABILITIES = [
    "fs_read",
    "fs_write",
    "network_egress",
    "process_spawn",
    "env_read",
]

REQUIRED_LOG_CODES = [
    "MANIFEST_CREATED",
    "MANIFEST_SIGNED",
    "MANIFEST_VALIDATED",
    "MANIFEST_REJECTED",
]

REQUIRED_TOP_LEVEL_FIELDS = [
    "schema_version",
    "package",
    "entrypoint",
    "capabilities",
    "behavioral_profile",
    "minimum_runtime_version",
    "provenance",
    "trust",
    "signature",
]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_rust_source(path: Path) -> str:
    return _strip_rust_comments(_read_text(path))


def _strip_rust_comments(text: str) -> str:
    result: list[str] = []
    cursor = 0
    length = len(text)
    while cursor < length:
        if text.startswith("//", cursor):
            end = text.find("\n", cursor)
            if end == -1:
                break
            result.append("\n")
            cursor = end + 1
            continue

        if text.startswith("/*", cursor):
            end = _rust_block_comment_end(text, cursor + 2)
            comment = text[cursor:end]
            result.append("\n" * comment.count("\n") or " ")
            cursor = end
            continue

        raw_end = _rust_raw_string_end(text, cursor)
        if raw_end is not None:
            result.append(text[cursor:raw_end])
            cursor = raw_end
            continue

        if text[cursor] == '"':
            end = _rust_quoted_literal_end(text, cursor)
            result.append(text[cursor:end])
            cursor = end
            continue

        result.append(text[cursor])
        cursor += 1

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


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.JSONDecoder().decode(_read_text(path))
    if not isinstance(payload, dict):
        raise TypeError("json payload is not an object")
    return payload


def _check(check_id: str, description: str, passed: bool, details: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": check_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
    }
    if details:
        record["details"] = details
    return record


def check_spec_contract() -> dict[str, Any]:
    if not SPEC_PATH.exists():
        return _check("EMS-SPEC", "Spec contract exists with invariants", False, "missing spec file")

    content = _read_text(SPEC_PATH)
    invariants = [
        "INV-EMS-CANONICAL-FIELDS",
        "INV-EMS-ENGINE-COMPAT",
        "INV-EMS-PROVENANCE-CHAIN",
        "INV-EMS-SIGNATURE-GATE",
        "INV-EMS-LOG-CODES",
    ]
    missing = [inv for inv in invariants if inv not in content]
    return _check(
        "EMS-SPEC",
        "Spec contract exists with invariants",
        not missing,
        None if not missing else f"missing invariants: {', '.join(missing)}",
    )


def check_schema_shape() -> dict[str, Any]:
    if not SCHEMA_PATH.exists():
        return _check("EMS-SCHEMA", "JSON schema exists with canonical field order", False, "missing schema file")

    try:
        data = _read_json_object(SCHEMA_PATH)
    except (json.JSONDecodeError, OSError, TypeError) as exc:
        return _check("EMS-SCHEMA", "JSON schema exists with canonical field order", False, f"invalid json: {exc}")

    required = data.get("required", [])
    has_required_fields = required == REQUIRED_TOP_LEVEL_FIELDS
    has_schema = data.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    has_no_extras = isinstance(data.get("additionalProperties"), bool) and not data["additionalProperties"]

    passed = has_required_fields and has_schema and has_no_extras
    details = None
    if not passed:
        details = (
            f"required={required}, schema={data.get('$schema')}, "
            f"additionalProperties={data.get('additionalProperties')}"
        )
    return _check("EMS-SCHEMA", "JSON schema exists with canonical field order", passed, details)


def check_capability_enum() -> dict[str, Any]:
    try:
        data = _read_json_object(SCHEMA_PATH)
    except (OSError, json.JSONDecodeError, TypeError):
        return _check("EMS-CAPS", "Capability enum aligns with engine ExtensionManifest", False)

    actual = (
        data.get("properties", {})
        .get("capabilities", {})
        .get("items", {})
        .get("enum", [])
    )
    passed = actual == REQUIRED_CAPABILITIES
    details = None if passed else f"capabilities={actual}"
    return _check("EMS-CAPS", "Capability enum aligns with engine ExtensionManifest", passed, details)


def check_rust_integration() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return _check("EMS-RUST", "Rust module implements schema + engine integration", False, "missing rust module")

    content = _read_rust_source(RUST_IMPL_PATH)
    required_markers = [
        "pub struct SignedExtensionManifest",
        "pub fn validate_signed_manifest",
        "validate_engine_manifest",
        "to_engine_manifest",
        "ManifestSchemaError",
    ]
    missing = [marker for marker in required_markers if marker not in content]
    return _check(
        "EMS-RUST",
        "Rust module implements schema + engine integration",
        not missing,
        None if not missing else f"missing markers: {', '.join(missing)}",
    )


def check_log_codes() -> dict[str, Any]:
    if not RUST_IMPL_PATH.exists():
        return _check("EMS-LOGS", "Structured manifest event codes are defined", False)

    content = _read_rust_source(RUST_IMPL_PATH)
    missing = [code for code in REQUIRED_LOG_CODES if code not in content]
    return _check(
        "EMS-LOGS",
        "Structured manifest event codes are defined",
        not missing,
        None if not missing else f"missing codes: {', '.join(missing)}",
    )


def check_integration_surface() -> dict[str, Any]:
    if not INTEGRATION_TEST_PATH.exists():
        return _check("EMS-INTEG", "Integration tests cover admission fail-closed invariants", False)

    content = _read_rust_source(INTEGRATION_TEST_PATH)
    invariants = [
        "inv_ems_engine_compatibility_gate",
        "inv_ems_signature_gate_fail_closed",
        "inv_ems_threshold_policy_required",
        "inv_ems_attestation_chain_required",
    ]
    missing = [inv for inv in invariants if inv not in content]
    return _check(
        "EMS-INTEG",
        "Integration tests cover admission fail-closed invariants",
        not missing,
        None if not missing else f"missing integration tests: {', '.join(missing)}",
    )


def collect_checks() -> list[dict[str, Any]]:
    return [
        check_spec_contract(),
        check_schema_shape(),
        check_capability_enum(),
        check_rust_integration(),
        check_log_codes(),
        check_integration_surface(),
    ]


def _make_summary_md(report: dict[str, Any]) -> str:
    lines = [
        "# bd-1gx: Signed Extension Manifest Schema — Verification Summary",
        "",
        f"## Verdict: {report['verdict']}",
        "",
        f"## Checks ({report['summary']['passing_checks']}/{report['summary']['total_checks']})",
        "",
        "| Check | Description | Status |",
        "|-------|-------------|--------|",
    ]
    for check in report["checks"]:
        lines.append(f"| {check['id']} | {check['description']} | {check['status']} |")

    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            "- Spec: `docs/specs/section_10_4/extension_manifest_schema.md`",
            "- Schema: `schemas/extension_manifest.schema.json`",
            "- Impl: `crates/franken-node/src/supply_chain/manifest.rs`",
            "- Integration: `tests/integration/extension_manifest_admission.rs`",
            "- Evidence: `artifacts/section_10_4/bd-1gx/verification_evidence.json`",
        ]
    )
    return "\n".join(lines) + "\n"


def self_test() -> bool:
    return all(check["status"] == "PASS" for check in collect_checks())


def main() -> int:
    configure_test_logging("check_extension_manifest_schema")
    checks = collect_checks()
    passing = sum(1 for check in checks if check["status"] == "PASS")
    total = len(checks)
    verdict = "PASS" if passing == total else "FAIL"

    report: dict[str, Any] = {
        "gate": "extension_manifest_schema_verification",
        "bead": "bd-1gx",
        "section": "10.4",
        "verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": total - passing,
        },
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    SUMMARY_PATH.write_text(_make_summary_md(report), encoding="utf-8")

    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print("bd-1gx: Signed Extension Manifest Schema — Verification")
        for check in checks:
            status = check["status"]
            print(f"  [{status}] {check['id']}: {check['description']}")
            if "details" in check:
                print(f"         {check['details']}")
        print(f"\nResult: {passing}/{total} checks passed")
        print(f"Verdict: {verdict}")

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
