#!/usr/bin/env python3
"""Validate the TNR structured logging and metrics registry."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

REGISTRY_PATH = ROOT / "docs" / "observability" / "tnr_event_metrics_registry.json"
DOCS_PATH = ROOT / "docs" / "observability" / "tnr_event_metrics_registry.md"
SCAN_DIRS = (ROOT / "crates" / "franken-node" / "src", ROOT / "scripts")

REQUIRED_SUBSYSTEMS = {
    "FN-COMPAT",
    "FN-EFFECT",
    "FN-CAS",
    "FN-TTR",
    "FN-FLOW",
    "FN-SENTINEL",
    "FN-CONFORMAL",
    "FN-CAP",
    "FN-MIGCERT",
    "FN-MCP",
    "FN-LTV",
    "FN-FLEETLOG",
    "FN-RESOLVE",
    "FN-CORPUS",
    "FN-CALIB",
    "FN-ACCEPT",
}
EVENT_CODE_RE = re.compile(r"\bFN-[A-Z0-9]+(?:-[A-Z0-9]+)*-(?:ERR-)?\d{3}\b")
METRIC_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _load_json(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.is_file():
        return None, [f"missing registry: {_safe_rel(path)}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"invalid registry JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, ["registry root must be an object"]
    return payload, []


def _namespace_for_code(code: str) -> str:
    if "-ERR-" in code:
        return code.split("-ERR-", 1)[0]
    return code.rsplit("-", 1)[0]


def _expand_legacy_codes(entry: dict[str, Any], errors: list[str]) -> set[str]:
    codes = set()
    for code in entry.get("codes", []):
        if isinstance(code, str):
            codes.add(code)
        else:
            errors.append("legacy code entries must be strings")

    ranges = entry.get("code_ranges", [])
    if not isinstance(ranges, list):
        errors.append("legacy code_ranges must be a list")
        return codes
    for item in ranges:
        if not isinstance(item, dict):
            errors.append("legacy code range entries must be objects")
            continue
        prefix = item.get("prefix")
        start = item.get("start")
        end = item.get("end")
        if not isinstance(prefix, str) or not isinstance(start, int) or not isinstance(end, int):
            errors.append("legacy code range requires string prefix and integer start/end")
            continue
        if start < 1 or end < start:
            errors.append(f"legacy code range for {prefix} has invalid bounds")
            continue
        for number in range(start, end + 1):
            codes.add(f"{prefix}-{number:03d}")
    return codes


def _registry_sets(registry: dict[str, Any]) -> tuple[set[str], set[str], set[str], set[str], list[str]]:
    errors: list[str] = []
    subsystem_ids: set[str] = set()
    tnr_codes: set[str] = set()
    all_codes: set[str] = set()
    metrics: set[str] = set()
    tnr_code_values: list[str] = []
    metric_values: list[str] = []

    subsystems = registry.get("subsystems")
    if not isinstance(subsystems, list):
        errors.append("registry.subsystems must be a list")
        subsystems = []

    for subsystem in subsystems:
        if not isinstance(subsystem, dict):
            errors.append("subsystem entries must be objects")
            continue
        subsystem_id = subsystem.get("id")
        if not isinstance(subsystem_id, str) or not subsystem_id:
            errors.append("subsystem.id must be a non-empty string")
            continue
        subsystem_ids.add(subsystem_id)

        for field in ("event_codes", "error_codes"):
            entries = subsystem.get(field)
            if not isinstance(entries, list) or not entries:
                errors.append(f"{subsystem_id}.{field} must be a non-empty list")
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    errors.append(f"{subsystem_id}.{field} entries must be objects")
                    continue
                code = entry.get("code")
                name = entry.get("name")
                description = entry.get("description")
                if not isinstance(code, str) or EVENT_CODE_RE.fullmatch(code) is None:
                    errors.append(f"{subsystem_id}.{field} has invalid code {code!r}")
                    continue
                if _namespace_for_code(code) != subsystem_id:
                    errors.append(f"{code} does not match subsystem namespace {subsystem_id}")
                if not isinstance(name, str) or not name.strip():
                    errors.append(f"{code} must include a non-empty name")
                if not isinstance(description, str) or not description.strip():
                    errors.append(f"{code} must include a non-empty description")
                tnr_codes.add(code)
                all_codes.add(code)
                tnr_code_values.append(code)

        metric_entries = subsystem.get("metrics")
        if not isinstance(metric_entries, list) or not metric_entries:
            errors.append(f"{subsystem_id}.metrics must be a non-empty list")
            continue
        for metric in metric_entries:
            if not isinstance(metric, dict):
                errors.append(f"{subsystem_id}.metrics entries must be objects")
                continue
            name = metric.get("name")
            metric_type = metric.get("type")
            description = metric.get("description")
            labels = metric.get("labels", [])
            if not isinstance(name, str) or METRIC_RE.fullmatch(name) is None:
                errors.append(f"{subsystem_id}.metrics has invalid name {name!r}")
                continue
            if not name.startswith("franken_node_"):
                errors.append(f"{name} must use franken_node_ metric namespace")
            if metric_type not in {"counter", "gauge", "histogram"}:
                errors.append(f"{name} has invalid metric type {metric_type!r}")
            if not isinstance(description, str) or not description.strip():
                errors.append(f"{name} must include a non-empty description")
            if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
                errors.append(f"{name}.labels must be a list of strings")
            metrics.add(name)
            metric_values.append(name)

    duplicate_codes = _duplicates(tnr_code_values)
    duplicate_metrics = _duplicates(metric_values)
    if duplicate_codes:
        errors.append(f"duplicate TNR event/error codes: {sorted(duplicate_codes)}")
    if duplicate_metrics:
        errors.append(f"duplicate TNR metrics: {sorted(duplicate_metrics)}")

    legacy_entries = registry.get("legacy_namespaces", [])
    if not isinstance(legacy_entries, list):
        errors.append("registry.legacy_namespaces must be a list")
        legacy_entries = []
    for entry in legacy_entries:
        if not isinstance(entry, dict):
            errors.append("legacy namespace entries must be objects")
            continue
        all_codes.update(_expand_legacy_codes(entry, errors))

    return subsystem_ids, tnr_codes, all_codes, metrics, errors


def _duplicates(values: list[str]) -> set[str]:
    seen: set[str] = set()
    duplicated: set[str] = set()
    for value in values:
        if value in seen:
            duplicated.add(value)
        seen.add(value)
    return duplicated


def check_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "tnr-observability-registry.v1":
        errors.append("registry.schema_version must be tnr-observability-registry.v1")
    subsystem_ids, _, _, _, set_errors = _registry_sets(registry)
    errors.extend(set_errors)
    missing = sorted(REQUIRED_SUBSYSTEMS - subsystem_ids)
    if missing:
        errors.append(f"missing required TNR subsystem(s): {', '.join(missing)}")
    return errors


def check_docs(registry: dict[str, Any], docs_path: Path = DOCS_PATH) -> list[str]:
    if not docs_path.is_file():
        return [f"missing docs: {_safe_rel(docs_path)}"]
    text = docs_path.read_text(encoding="utf-8")
    subsystem_ids, tnr_codes, _, metrics, set_errors = _registry_sets(registry)
    errors = list(set_errors)
    for subsystem_id in sorted(REQUIRED_SUBSYSTEMS & subsystem_ids):
        if subsystem_id not in text:
            errors.append(f"docs missing subsystem {subsystem_id}")
    for code in sorted(tnr_codes):
        if code not in text:
            errors.append(f"docs missing event/error code {code}")
    for metric in sorted(metrics):
        if metric not in text:
            errors.append(f"docs missing metric {metric}")
    return errors


def scan_concrete_event_codes(scan_dirs: tuple[Path, ...] = SCAN_DIRS) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for root in scan_dirs:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in {".rs", ".py", ".md"}:
                continue
            if path.name == "check_tnr_observability_contract.py":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for match in EVENT_CODE_RE.finditer(text):
                code = match.group(0)
                found.setdefault(code, []).append(_safe_rel(path))
    return found


def check_scan(registry: dict[str, Any], scan_dirs: tuple[Path, ...] = SCAN_DIRS) -> list[str]:
    _, _, all_codes, _, set_errors = _registry_sets(registry)
    errors = list(set_errors)
    found = scan_concrete_event_codes(scan_dirs)
    for code, paths in sorted(found.items()):
        if code not in all_codes:
            locations = ", ".join(sorted(set(paths))[:5])
            errors.append(f"unregistered event/error code {code} found in {locations}")
    return errors


def run_checks(
    *,
    registry_path: Path = REGISTRY_PATH,
    docs_path: Path = DOCS_PATH,
    scan_dirs: tuple[Path, ...] = SCAN_DIRS,
) -> dict[str, Any]:
    registry, load_errors = _load_json(registry_path)
    checks: list[dict[str, Any]] = []
    checks.append({
        "name": "registry_loads",
        "status": "PASS" if not load_errors else "FAIL",
        "detail": load_errors or _safe_rel(registry_path),
    })

    registry_errors: list[str] = []
    docs_errors: list[str] = []
    scan_errors: list[str] = []
    if registry is not None:
        registry_errors = check_registry(registry)
        docs_errors = check_docs(registry, docs_path)
        scan_errors = check_scan(registry, scan_dirs)

    checks.extend([
        {
            "name": "registry_contract",
            "status": "PASS" if not registry_errors else "FAIL",
            "detail": registry_errors,
        },
        {
            "name": "documentation_lists_registered_codes_and_metrics",
            "status": "PASS" if not docs_errors else "FAIL",
            "detail": docs_errors,
        },
        {
            "name": "source_event_codes_are_registered",
            "status": "PASS" if not scan_errors else "FAIL",
            "detail": scan_errors,
        },
    ])

    failing = [check for check in checks if check["status"] == "FAIL"]
    return {
        "gate": "tnr_observability_contract",
        "schema_version": "tnr-observability-contract-gate.v1",
        "timestamp": _utc_now_iso(),
        "verdict": "PASS" if not failing else "FAIL",
        "checks": checks,
        "summary": {
            "total_checks": len(checks),
            "passing_checks": len(checks) - len(failing),
            "failing_checks": len(failing),
        },
    }


def main(argv: list[str] | None = None) -> int:
    logger = configure_test_logging("check_tnr_observability_contract")
    parser = argparse.ArgumentParser(description="Validate TNR observability registry")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--docs", type=Path, default=DOCS_PATH)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    logger.info("starting tnr observability contract gate", extra={"registry": str(args.registry)})
    result = run_checks(registry_path=args.registry, docs_path=args.docs)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("=== TNR Observability Contract Gate ===")
        for check in result["checks"]:
            print(f"  [{'OK' if check['status'] == 'PASS' else 'FAIL'}] {check['name']}")
            detail = check.get("detail")
            if isinstance(detail, list):
                for entry in detail:
                    print(f"    - {entry}")
            elif detail:
                print(f"    {detail}")
        print(f"Verdict: {result['verdict']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
