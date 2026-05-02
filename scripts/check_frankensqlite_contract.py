#!/usr/bin/env python3
"""Validate frankensqlite persistence contract coverage and matrix integrity (bd-1a1j)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

CONTRACT_PATH = ROOT / "docs" / "specs" / "frankensqlite_persistence_contract.md"
MATRIX_PATH = ROOT / "artifacts" / "10.16" / "frankensqlite_persistence_matrix.json"
MODULE_ROOT = ROOT / "crates" / "franken-node" / "src" / "connector"

REQUIRED_CONTRACT_SECTIONS = [
    "## Persistence Class Enumeration",
    "## Durability Mode Mapping",
    "## Schema Ownership and Evolution",
    "## Replay Semantics",
    "## Concurrency Model",
    "## Event Codes",
]

REQUIRED_EVENT_CODES = {
    "PERSISTENCE_CONTRACT_LOADED",
    "PERSISTENCE_CLASS_UNMAPPED",
    "PERSISTENCE_TIER_INVALID",
    "PERSISTENCE_REPLAY_UNSUPPORTED",
}

REQUIRED_CLASS_KEYS = {
    "domain",
    "owner_module",
    "safety_tier",
    "durability_mode",
    "tables",
    "replay_support",
}

ALLOWED_TIERS = {"tier_1", "tier_2", "tier_3"}

# Known valid frankensqlite durability configurations for this contract.
ALLOWED_MODE_PAIRS = {
    ("WAL", "FULL"),
    ("WAL", "NORMAL"),
    ("MEMORY", "OFF"),
}

STATEFUL_STEM_PATTERN = re.compile(
    r"(state|store|storage|persistence|durability|snapshot|retention|"
    r"lease|quarantine|migration|fencing|channel|crdt|coverage|lifecycle|controller)"
)

EXPLICIT_STATEFUL_FILES = {
    "health_gate.rs",
    "durable_claim_gate.rs",
}

ALLOWED_CHECKLIST_STATUS = {"defined", "pending", "waived"}


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path = ROOT) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def discover_stateful_modules(
    module_root: Path = MODULE_ROOT,
    project_root: Path = ROOT,
) -> list[str]:
    if not module_root.exists():
        raise FileNotFoundError(f"module root not found: {module_root}")

    modules: list[str] = []
    for file_path in sorted(module_root.rglob("*.rs")):
        if file_path.name == "mod.rs":
            continue

        stem = file_path.stem
        if STATEFUL_STEM_PATTERN.search(stem) or file_path.name in EXPLICIT_STATEFUL_FILES:
            modules.append(_rel(file_path, project_root))

    return modules


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"unable to read JSON artifact `{_rel(path)}`: {exc}") from exc

    try:
        payload = json.JSONDecoder().decode(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in `{_rel(path)}`: {exc.msg}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON artifact `{_rel(path)}` must contain an object")
    return payload


def _validate_durability_modes(
    durability_modes: Any,
    mode_catalog: Any,
) -> list[str]:
    errors: list[str] = []

    if not isinstance(durability_modes, dict):
        return ["durability_modes must be an object"]
    if not isinstance(mode_catalog, dict):
        return ["mode_catalog must be an object"]

    for tier in sorted(ALLOWED_TIERS):
        tier_cfg = durability_modes.get(tier)
        if not isinstance(tier_cfg, dict):
            errors.append(f"durability_modes.{tier} must be an object")
            continue

        mode_name = tier_cfg.get("durability_mode")
        journal_mode = tier_cfg.get("journal_mode")
        synchronous = tier_cfg.get("synchronous")

        if not isinstance(mode_name, str) or not mode_name:
            errors.append(f"durability_modes.{tier}.durability_mode must be non-empty string")
            continue
        if not isinstance(journal_mode, str) or not isinstance(synchronous, str):
            errors.append(
                f"durability_modes.{tier} must include string journal_mode and synchronous"
            )
            continue

        if (journal_mode, synchronous) not in ALLOWED_MODE_PAIRS:
            errors.append(
                f"durability_modes.{tier} invalid pair: ({journal_mode}, {synchronous})"
            )

        mode_cfg = mode_catalog.get(mode_name)
        if not isinstance(mode_cfg, dict):
            errors.append(f"mode_catalog missing durability mode `{mode_name}`")
            continue

        cat_journal = mode_cfg.get("journal_mode")
        cat_sync = mode_cfg.get("synchronous")
        if cat_journal != journal_mode or cat_sync != synchronous:
            errors.append(
                f"mode_catalog mismatch for `{mode_name}`: expected ({journal_mode}, {synchronous})"
            )

    return errors


def evaluate_contract(
    matrix: dict[str, Any],
    contract_text: str,
    stateful_modules: list[str],
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    trace = _trace_id(matrix)
    events.append(
        {
            "event_code": "PERSISTENCE_CONTRACT_LOADED",
            "severity": "info",
            "trace_correlation": trace,
            "message": "Loaded frankensqlite persistence contract matrix.",
        }
    )

    for section in REQUIRED_CONTRACT_SECTIONS:
        if section not in contract_text:
            errors.append(f"contract missing section: {section}")

    matrix_event_codes = set(matrix.get("event_codes", []))
    missing_event_codes = sorted(REQUIRED_EVENT_CODES - matrix_event_codes)
    if missing_event_codes:
        errors.append(f"missing required event codes: {', '.join(missing_event_codes)}")

    durability_errors = _validate_durability_modes(
        matrix.get("durability_modes"),
        matrix.get("mode_catalog"),
    )
    errors.extend(durability_errors)

    classes = matrix.get("persistence_classes")
    if not isinstance(classes, list) or not classes:
        errors.append("persistence_classes must be a non-empty list")
        classes = []

    concurrency = matrix.get("concurrency_model")
    if not isinstance(concurrency, dict):
        errors.append("concurrency_model must be an object")
    else:
        pool_size = concurrency.get("pool_size")
        if not isinstance(pool_size, int) or pool_size <= 0:
            errors.append("concurrency_model.pool_size must be a positive integer")
        if not isinstance(concurrency.get("isolation_level"), str) or not concurrency.get(
            "isolation_level"
        ):
            errors.append("concurrency_model.isolation_level must be a non-empty string")
        if not isinstance(concurrency.get("conflict_resolution"), str) or not concurrency.get(
            "conflict_resolution"
        ):
            errors.append("concurrency_model.conflict_resolution must be a non-empty string")

    checklist = matrix.get("checklist")
    if not isinstance(checklist, list) or not checklist:
        errors.append("checklist must be a non-empty list")
    else:
        pending: list[str] = []
        for idx, item in enumerate(checklist):
            if not isinstance(item, dict):
                errors.append(f"checklist[{idx}] must be an object")
                continue
            status = item.get("status")
            if status not in ALLOWED_CHECKLIST_STATUS:
                errors.append(f"checklist[{idx}] has invalid status `{status}`")
                continue
            if status == "pending":
                pending.append(item.get("requirement", f"item_{idx}"))
        if pending:
            errors.append(f"pending checklist requirements: {', '.join(pending)}")

    mapped_modules: set[str] = set()
    table_owners: dict[str, str] = {}
    mode_catalog = matrix.get("mode_catalog", {})
    tier_defaults = matrix.get("durability_modes", {})

    for idx, item in enumerate(classes):
        if not isinstance(item, dict):
            errors.append(f"persistence_classes[{idx}] must be an object")
            continue

        missing = sorted(REQUIRED_CLASS_KEYS - set(item.keys()))
        if missing:
            errors.append(f"persistence_classes[{idx}] missing keys: {', '.join(missing)}")
            continue

        domain = item.get("domain")
        owner_module = item.get("owner_module")
        tier = item.get("safety_tier")
        durability_mode = item.get("durability_mode")
        tables = item.get("tables")
        replay_support = item.get("replay_support")
        replay_strategy = item.get("replay_strategy")

        if not isinstance(domain, str) or not domain:
            errors.append(f"persistence_classes[{idx}].domain must be a non-empty string")
        if not isinstance(owner_module, str) or not owner_module:
            errors.append(
                f"persistence_classes[{idx}].owner_module must be a non-empty string"
            )
        else:
            mapped_modules.add(owner_module)

        if tier not in ALLOWED_TIERS:
            message = f"{owner_module}: invalid safety_tier `{tier}`"
            errors.append(message)
            events.append(
                {
                    "event_code": "PERSISTENCE_TIER_INVALID",
                    "severity": "error",
                    "trace_correlation": trace,
                    "module": owner_module,
                    "message": message,
                }
            )

        if not isinstance(durability_mode, str) or not durability_mode:
            errors.append(f"{owner_module}: durability_mode must be a non-empty string")
        elif durability_mode not in mode_catalog:
            errors.append(f"{owner_module}: unknown durability_mode `{durability_mode}`")
        elif tier in tier_defaults:
            tier_mode = tier_defaults[tier].get("durability_mode")
            if tier_mode != durability_mode:
                warnings.append(
                    f"{owner_module}: durability_mode `{durability_mode}` differs from tier default `{tier_mode}`"
                )

        if not isinstance(tables, list) or not tables:
            errors.append(f"{owner_module}: tables must be a non-empty list")
        else:
            for table in tables:
                if not isinstance(table, str) or not table:
                    errors.append(f"{owner_module}: table names must be non-empty strings")
                    continue
                previous_owner = table_owners.get(table)
                if previous_owner is not None and previous_owner != owner_module:
                    errors.append(
                        f"table ownership conflict `{table}`: {previous_owner} vs {owner_module}"
                    )
                else:
                    table_owners[table] = owner_module

        if tier in {"tier_1", "tier_2"}:
            replay_ok = (
                isinstance(replay_support, bool)
                and replay_support
                and isinstance(replay_strategy, str)
                and bool(replay_strategy.strip())
            )
            if not replay_ok:
                message = (
                    f"{owner_module}: replay semantics required for {tier} "
                    "(replay_support=true and non-empty replay_strategy)"
                )
                # Event spec classifies this as warning, but this contract also treats it as a gate failure.
                events.append(
                    {
                        "event_code": "PERSISTENCE_REPLAY_UNSUPPORTED",
                        "severity": "warning",
                        "trace_correlation": trace,
                        "module": owner_module,
                        "message": message,
                    }
                )
                warnings.append(message)
                errors.append(message)

    discovered_set = set(stateful_modules)
    unmapped = sorted(discovered_set - mapped_modules)
    for module_path in unmapped:
        message = f"stateful connector module missing persistence class mapping: {module_path}"
        events.append(
            {
                "event_code": "PERSISTENCE_CLASS_UNMAPPED",
                "severity": "error",
                "trace_correlation": trace,
                "module": module_path,
                "message": message,
            }
        )
        errors.append(message)

    success = len(errors) == 0
    report = {
        "ok": success,
        "trace_correlation": trace,
        "mapped_module_count": len(mapped_modules),
        "detected_stateful_module_count": len(stateful_modules),
        "unmapped_stateful_modules": unmapped,
        "table_count": len(table_owners),
        "errors": errors,
        "warnings": warnings,
        "events": events,
    }
    return success, report


def run_checks(
    matrix_path: Path = MATRIX_PATH,
    contract_path: Path = CONTRACT_PATH,
    module_root: Path = MODULE_ROOT,
) -> tuple[bool, dict[str, Any]]:
    if not matrix_path.is_file():
        raise FileNotFoundError(f"missing persistence matrix: {matrix_path}")
    if not contract_path.is_file():
        raise FileNotFoundError(f"missing contract doc: {contract_path}")

    matrix = _load_json_object(matrix_path)
    contract_text = contract_path.read_text(encoding="utf-8")
    stateful_modules = discover_stateful_modules(module_root, ROOT)

    ok, report = evaluate_contract(matrix, contract_text, stateful_modules)
    result = {
        "bead_id": "bd-1a1j",
        "contract": _rel(contract_path),
        "matrix": _rel(matrix_path),
        "module_root": _rel(module_root),
        **report,
    }
    return ok, result


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="frankensqlite-contract-selftest-") as tmp:
        root = Path(tmp)
        module_root = root / "crates" / "franken-node" / "src" / "connector"
        module_root.mkdir(parents=True, exist_ok=True)

        (module_root / "fencing.rs").write_text("pub struct FenceState;\n", encoding="utf-8")
        (module_root / "health_gate.rs").write_text("pub struct HealthGateResult;\n", encoding="utf-8")

        contract = root / "contract.md"
        contract.write_text("\n".join(REQUIRED_CONTRACT_SECTIONS), encoding="utf-8")

        matrix = {
            "durability_modes": {
                "tier_1": {
                    "durability_mode": "wal_full",
                    "journal_mode": "WAL",
                    "synchronous": "FULL",
                },
                "tier_2": {
                    "durability_mode": "wal_normal",
                    "journal_mode": "WAL",
                    "synchronous": "NORMAL",
                },
                "tier_3": {
                    "durability_mode": "memory",
                    "journal_mode": "MEMORY",
                    "synchronous": "OFF",
                },
            },
            "mode_catalog": {
                "wal_full": {"journal_mode": "WAL", "synchronous": "FULL"},
                "wal_normal": {"journal_mode": "WAL", "synchronous": "NORMAL"},
                "memory": {"journal_mode": "MEMORY", "synchronous": "OFF"},
            },
            "concurrency_model": {
                "pool_size": 4,
                "isolation_level": "serializable",
                "conflict_resolution": "fencing",
            },
            "event_codes": sorted(REQUIRED_EVENT_CODES),
            "checklist": [{"requirement": "complete", "status": "defined"}],
            "persistence_classes": [
                {
                    "domain": "fencing",
                    "owner_module": "crates/franken-node/src/connector/fencing.rs",
                    "safety_tier": "tier_1",
                    "durability_mode": "wal_full",
                    "tables": ["fencing_table"],
                    "replay_support": True,
                    "replay_strategy": "ordered",
                },
                {
                    "domain": "health_gate",
                    "owner_module": "crates/franken-node/src/connector/health_gate.rs",
                    "safety_tier": "tier_1",
                    "durability_mode": "wal_full",
                    "tables": ["health_gate_table"],
                    "replay_support": True,
                    "replay_strategy": "ordered",
                },
            ],
        }

        modules = discover_stateful_modules(module_root, root)
        ok, report = evaluate_contract(matrix, contract.read_text(encoding="utf-8"), modules)
        if not ok:
            raise RuntimeError(f"self_test expected pass but got errors: {report['errors']}")

        # Integration check: adding a new stateful module must fail if unmapped.
        (module_root / "lease_service.rs").write_text("pub struct LeaseService;\n", encoding="utf-8")
        modules_with_extra = discover_stateful_modules(module_root, root)
        ok_missing, report_missing = evaluate_contract(
            matrix,
            contract.read_text(encoding="utf-8"),
            modules_with_extra,
        )
        if ok_missing:
            raise RuntimeError("self_test expected unmapped module failure")
        if not any("missing persistence class mapping" in e for e in report_missing["errors"]):
            raise RuntimeError("self_test expected missing persistence class mapping error")

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    configure_test_logging("check_frankensqlite_contract")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON output")
    parser.add_argument("--self-test", action="store_true", help="run internal self-test")
    args = parser.parse_args()

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            ok, payload = run_checks()
    except Exception as exc:  # pragma: no cover - defensive CLI guard
        payload = {"ok": False, "error": str(exc)}
        ok = False

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if ok:
            print("PASS")
        else:
            print("FAIL")
            for err in payload.get("errors", [payload.get("error", "unknown error")]):
                print(f"- {err}")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
