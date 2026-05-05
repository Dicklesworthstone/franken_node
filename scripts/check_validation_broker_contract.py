#!/usr/bin/env python3
"""bd-1khdi validation broker contract checker.

Usage:
    python3 scripts/check_validation_broker_contract.py
    python3 scripts/check_validation_broker_contract.py --json
    python3 scripts/check_validation_broker_contract.py --self-test
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

BEAD_ID = "bd-1khdi"
TITLE = "Validation broker receipt and queue contract"
RECEIPT_SCHEMA_VERSION = "franken-node/validation-broker/receipt/v1"
SCHEMA_CATALOG_VERSION = "franken-node/validation-broker/schema-catalog/v1"
FIXTURE_SCHEMA_VERSION = "franken-node/validation-broker/fixtures/v1"

SPEC_FILE = ROOT / "docs/specs/validation_broker.md"
SCHEMA_FILE = ROOT / "artifacts/validation_broker/validation_broker_contract.schema.json"
FIXTURES_FILE = ROOT / "artifacts/validation_broker/validation_broker_fixtures.v1.json"
SCRIPT_FILE = ROOT / "scripts/check_validation_broker_contract.py"
TEST_FILE = ROOT / "tests/test_check_validation_broker_contract.py"

REQUIRED_SPEC_MARKERS = [
    "ValidationBrokerRequest",
    "BrokerQueueEntry",
    "WorkerCapabilityObservation",
    "ValidationReceipt",
    "INV-VB-COMMAND-DIGEST",
    "INV-VB-BEAD-THREAD-MATCH",
    "INV-VB-SOURCE-ONLY-EXPLICIT",
    "ERR_VB_MISSING_COMMAND_DIGEST",
    "ERR_VB_STALE_RECEIPT",
    "ERR_VB_INVALID_TIMEOUT_CLASS",
    "Beads Closeout",
    "Doctor Readiness",
    "CI Gate Consumption",
]

RECEIPT_REQUIRED_FIELDS = [
    "schema_version",
    "receipt_id",
    "request_id",
    "bead_id",
    "thread_id",
    "request_ref",
    "command",
    "command_digest",
    "environment_policy",
    "target_dir_policy",
    "input_digests",
    "rch",
    "timing",
    "exit",
    "artifacts",
    "trust",
    "classifications",
]

REQUIRED_ARTIFACT_PATH_FIELDS = [
    "stdout_path",
    "stderr_path",
    "summary_path",
    "receipt_path",
]

REQUIRED_TIMING_FIELDS = [
    "started_at",
    "finished_at",
    "duration_ms",
    "freshness_expires_at",
]

TIMEOUT_CLASSES = {
    "none",
    "queue_wait",
    "rch_dispatch",
    "ssh_command",
    "cargo_test_timeout",
    "process_idle",
    "process_wall",
    "worker_unreachable",
    "unknown",
}

ERROR_CLASSES = {
    "none",
    "compile_error",
    "test_failure",
    "clippy_warning",
    "format_failure",
    "transport_timeout",
    "worker_infra",
    "environment_contention",
    "disk_pressure",
    "source_only",
    "unknown",
}

SOURCE_ONLY_REASONS = {
    "cargo_contention",
    "rch_unavailable",
    "sibling_dependency_blocker",
    "disk_pressure",
    "reserved_surface",
    "no_cargo_requested",
    "docs_only",
}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_json(path: Path) -> Any:
    return json.JSONDecoder().decode(path.read_text(encoding="utf-8"))


def _check(check: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {
        "check": check,
        "passed": bool(passed),
        "detail": detail or ("ok" if passed else "FAIL"),
    }


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _get_path(payload: dict[str, Any], dotted_path: str) -> Any:
    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _set_path(payload: dict[str, Any], dotted_path: str, value: Any) -> None:
    current: dict[str, Any] = payload
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        next_value = current.setdefault(part, {})
        if not isinstance(next_value, dict):
            next_value = {}
            current[part] = next_value
        current = next_value
    current[parts[-1]] = value


def _remove_path(payload: dict[str, Any], dotted_path: str) -> None:
    current: Any = payload
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return
        current = current.get(part)
    if isinstance(current, dict):
        current.pop(parts[-1], None)


def apply_fixture_patch(base: Any, patch: dict[str, Any] | None) -> Any:
    patched = copy.deepcopy(base)
    if not patch:
        return patched
    for dotted_path in patch.get("remove", []):
        if isinstance(patched, dict):
            _remove_path(patched, str(dotted_path))
    for dotted_path, value in patch.get("set", {}).items():
        if isinstance(patched, dict):
            _set_path(patched, str(dotted_path), value)
    return patched


def validate_receipt(
    receipt: Any,
    *,
    expected_bead_id: str | None = None,
    now: datetime | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(receipt, dict):
        return ["ERR_VB_MALFORMED_RECEIPT"]

    for field in RECEIPT_REQUIRED_FIELDS:
        if field not in receipt:
            errors.append("ERR_VB_MALFORMED_RECEIPT")
            break

    if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        errors.append("ERR_VB_INVALID_SCHEMA_VERSION")

    bead_id = receipt.get("bead_id")
    thread_id = receipt.get("thread_id")
    request_ref = receipt.get("request_ref")
    ref_bead_id = request_ref.get("bead_id") if isinstance(request_ref, dict) else None
    ref_thread_id = request_ref.get("thread_id") if isinstance(request_ref, dict) else None
    if (
        not isinstance(bead_id, str)
        or not isinstance(thread_id, str)
        or not isinstance(ref_bead_id, str)
        or bead_id != ref_bead_id
        or thread_id != ref_thread_id
        or (expected_bead_id is not None and bead_id != expected_bead_id)
    ):
        errors.append("ERR_VB_BEAD_MISMATCH")

    command_digest = receipt.get("command_digest")
    if not isinstance(command_digest, dict):
        errors.append("ERR_VB_MISSING_COMMAND_DIGEST")
    else:
        digest_hex = command_digest.get("hex")
        material = command_digest.get("canonical_material")
        algorithm = command_digest.get("algorithm")
        computed = hashlib.sha256(material.encode("utf-8")).hexdigest() if isinstance(material, str) else ""
        digest_ok = (
            isinstance(algorithm, str)
            and hmac.compare_digest(algorithm, "sha256")
            and _is_sha256_hex(digest_hex)
            and isinstance(material, str)
            and isinstance(digest_hex, str)
            and hmac.compare_digest(computed, digest_hex)
        )
        if not digest_ok:
            errors.append("ERR_VB_MISSING_COMMAND_DIGEST")

    input_digests = receipt.get("input_digests")
    if not isinstance(input_digests, list) or not input_digests:
        errors.append("ERR_VB_MALFORMED_RECEIPT")
    else:
        for entry in input_digests:
            if (
                not isinstance(entry, dict)
                or entry.get("algorithm") != "sha256"
                or not _is_sha256_hex(entry.get("hex"))
                or not entry.get("path")
            ):
                errors.append("ERR_VB_MALFORMED_RECEIPT")
                break

    timing = receipt.get("timing")
    if not isinstance(timing, dict):
        errors.append("ERR_VB_MALFORMED_RECEIPT")
    else:
        if any(field not in timing for field in REQUIRED_TIMING_FIELDS):
            errors.append("ERR_VB_MALFORMED_RECEIPT")
        started = _parse_rfc3339(timing.get("started_at"))
        finished = _parse_rfc3339(timing.get("finished_at"))
        expires = _parse_rfc3339(timing.get("freshness_expires_at"))
        if started is None or finished is None or expires is None or finished < started:
            errors.append("ERR_VB_MALFORMED_RECEIPT")
        if now is not None and expires is not None and expires < now:
            errors.append("ERR_VB_STALE_RECEIPT")

    exit_info = receipt.get("exit")
    if not isinstance(exit_info, dict):
        errors.append("ERR_VB_MALFORMED_RECEIPT")
    else:
        timeout_class = exit_info.get("timeout_class")
        error_class = exit_info.get("error_class")
        if timeout_class not in TIMEOUT_CLASSES:
            errors.append("ERR_VB_INVALID_TIMEOUT_CLASS")
        if error_class not in ERROR_CLASSES:
            errors.append("ERR_VB_MALFORMED_RECEIPT")

    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("ERR_VB_MISSING_ARTIFACT_PATH")
    else:
        for field in REQUIRED_ARTIFACT_PATH_FIELDS:
            if not isinstance(artifacts.get(field), str) or not artifacts[field]:
                errors.append("ERR_VB_MISSING_ARTIFACT_PATH")
                break

    classifications = receipt.get("classifications")
    if not isinstance(classifications, dict):
        errors.append("ERR_VB_MALFORMED_RECEIPT")
    else:
        source_only = classifications.get("source_only_fallback")
        reason = classifications.get("source_only_reason")
        exit_kind = _get_path(receipt, "exit.kind")
        source_only_enabled = isinstance(source_only, bool) and source_only
        if source_only_enabled or exit_kind == "source_only":
            if reason not in SOURCE_ONLY_REASONS:
                errors.append("ERR_VB_UNDECLARED_SOURCE_ONLY")

    return sorted(set(errors))


def _load_contract_files() -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    schema = _load_json(SCHEMA_FILE) if SCHEMA_FILE.exists() else None
    fixtures = _load_json(FIXTURES_FILE) if FIXTURES_FILE.exists() else None
    return schema, fixtures


def _check_files() -> list[dict[str, Any]]:
    return [
        _check("spec_exists", SPEC_FILE.is_file(), str(SPEC_FILE)),
        _check("schema_catalog_exists", SCHEMA_FILE.is_file(), str(SCHEMA_FILE)),
        _check("fixtures_exist", FIXTURES_FILE.is_file(), str(FIXTURES_FILE)),
        _check("script_exists", SCRIPT_FILE.is_file(), str(SCRIPT_FILE)),
        _check("tests_exist", TEST_FILE.is_file(), str(TEST_FILE)),
    ]


def _check_spec() -> list[dict[str, Any]]:
    content = _read_text(SPEC_FILE)
    checks = []
    for marker in REQUIRED_SPEC_MARKERS:
        checks.append(_check(f"spec_marker:{marker}", marker in content, marker))
    return checks


def _check_schema(schema: dict[str, Any] | None) -> list[dict[str, Any]]:
    if schema is None:
        return [_check("schema_parseable", False, "schema missing or invalid")]

    checks = [
        _check(
            "schema_version",
            schema.get("schema_version") == SCHEMA_CATALOG_VERSION,
            str(schema.get("schema_version")),
        ),
        _check(
            "timeout_classes_complete",
            set(schema.get("timeout_classes", [])) == TIMEOUT_CLASSES,
            ",".join(schema.get("timeout_classes", [])),
        ),
        _check(
            "error_classes_complete",
            set(schema.get("error_classes", [])) == ERROR_CLASSES,
            ",".join(schema.get("error_classes", [])),
        ),
        _check(
            "source_only_reasons_complete",
            set(schema.get("source_only_reasons", [])) == SOURCE_ONLY_REASONS,
            ",".join(schema.get("source_only_reasons", [])),
        ),
    ]

    schemas = schema.get("schemas", {})
    for name in (
        "ValidationBrokerRequest",
        "BrokerQueueEntry",
        "WorkerCapabilityObservation",
        "ValidationReceipt",
    ):
        checks.append(_check(f"schema_def:{name}", name in schemas, name))

    receipt_schema = schemas.get("ValidationReceipt", {}) if isinstance(schemas, dict) else {}
    required = set(receipt_schema.get("required", []))
    for field in RECEIPT_REQUIRED_FIELDS:
        checks.append(_check(f"receipt_required:{field}", field in required, field))

    for field in (
        "receipt_id",
        "bead_id",
        "thread_id",
        "command_digest.hex",
        "timing.started_at",
        "timing.finished_at",
        "exit.kind",
        "artifacts.receipt_path",
        "trust.git_commit",
        "trust.freshness",
    ):
        checks.append(_check(
            f"closeout_field:{field}",
            field in schema.get("closeout_required_fields", []),
            field,
        ))

    for field in ("queue_depth", "worker_reachability", "timeout_class_counts"):
        checks.append(_check(
            f"doctor_field:{field}",
            field in schema.get("doctor_readiness_fields", []),
            field,
        ))

    return checks


def _check_fixtures(fixtures: dict[str, Any] | None) -> list[dict[str, Any]]:
    if fixtures is None:
        return [_check("fixtures_parseable", False, "fixtures missing or invalid")]

    checks = [
        _check(
            "fixtures_schema_version",
            fixtures.get("schema_version") == FIXTURE_SCHEMA_VERSION,
            str(fixtures.get("schema_version")),
        )
    ]
    validation_time = _parse_rfc3339(fixtures.get("validation_time"))
    checks.append(_check("fixtures_validation_time_parseable", validation_time is not None))
    now = validation_time or datetime.now(timezone.utc)

    valid_receipts = fixtures.get("valid_receipts", [])
    checks.append(_check("valid_receipts_present", isinstance(valid_receipts, list) and len(valid_receipts) >= 1))
    base_receipt = valid_receipts[0] if isinstance(valid_receipts, list) and valid_receipts else None
    for index, receipt in enumerate(valid_receipts if isinstance(valid_receipts, list) else []):
        errors = validate_receipt(receipt, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(
            f"valid_receipt:{index}",
            not errors,
            "ok" if not errors else ",".join(errors),
        ))

    invalid_receipts = fixtures.get("invalid_receipts", [])
    checks.append(_check(
        "invalid_receipts_present",
        isinstance(invalid_receipts, list) and len(invalid_receipts) >= 5,
        f"{len(invalid_receipts) if isinstance(invalid_receipts, list) else 0} invalid cases",
    ))
    for case in invalid_receipts if isinstance(invalid_receipts, list) else []:
        if not isinstance(case, dict):
            checks.append(_check("invalid_case_malformed", False, "case is not object"))
            continue
        receipt = case.get("receipt", apply_fixture_patch(base_receipt, case.get("patch")))
        errors = validate_receipt(receipt, expected_bead_id=BEAD_ID, now=now)
        expected = case.get("expected_error")
        checks.append(_check(
            f"invalid_case:{case.get('case', '<unnamed>')}",
            isinstance(expected, str) and expected in errors,
            ",".join(errors) or "no error",
        ))

    for example in fixtures.get("timeout_class_examples", []):
        receipt = apply_fixture_patch(base_receipt, {
            "set": {
                "exit.kind": example.get("exit_kind"),
                "exit.timeout_class": example.get("timeout_class"),
                "exit.error_class": "transport_timeout"
                if example.get("exit_kind") == "timeout"
                else "none",
                "exit.code": None if example.get("exit_kind") == "timeout" else 0,
            }
        })
        errors = validate_receipt(receipt, expected_bead_id=BEAD_ID, now=now)
        checks.append(_check(
            f"timeout_class:{example.get('timeout_class')}",
            "ERR_VB_INVALID_TIMEOUT_CLASS" not in errors,
            ",".join(errors) or "ok",
        ))

    return checks


def run_all() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(_check_files())
    checks.extend(_check_spec())

    schema, fixtures = _load_contract_files()
    checks.extend(_check_schema(schema))
    checks.extend(_check_fixtures(fixtures))

    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    verdict = "PASS" if failed == 0 else "FAIL"
    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "schema_version": SCHEMA_CATALOG_VERSION,
        "verdict": verdict,
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def self_test() -> dict[str, Any]:
    result = run_all()
    checks = [
        _check("run_all_returns_dict", isinstance(result, dict)),
        _check("bead_id_matches", result.get("bead_id") == BEAD_ID),
        _check("has_checks", isinstance(result.get("checks"), list) and len(result["checks"]) >= 40),
        _check("verdict_known", result.get("verdict") in {"PASS", "FAIL"}),
        _check("contract_passes", result.get("verdict") == "PASS", f"{result.get('passed')}/{result.get('total')}"),
    ]
    passed = sum(1 for check in checks if check["passed"])
    failed = len(checks) - passed
    return {
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
    }


def main() -> None:
    configure_test_logging("check_validation_broker_contract")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    result = self_test() if args.self_test else run_all()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"# {BEAD_ID}: {TITLE}")
        print(f"Verdict: {result['verdict']} ({result['passed']}/{result['total']})")
        for check in result["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
