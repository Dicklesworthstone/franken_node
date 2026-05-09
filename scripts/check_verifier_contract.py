#!/usr/bin/env python3
"""bd-3ex verifier CLI conformance contract gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - Python < 3.11
    raise RuntimeError("Python 3.11+ is required for tomllib") from exc



BEAD_ID = "bd-3ex"
SECTION = "10.7"
TITLE = "Verifier CLI conformance contract tests"

CONTRACT_PATH = ROOT / "spec" / "verifier_cli_contract.toml"
CLI_PATH = ROOT / "crates" / "franken-node" / "src" / "cli.rs"
MAIN_PATH = ROOT / "crates" / "franken-node" / "src" / "main.rs"
SPEC_CONTRACT_PATH = ROOT / "docs" / "specs" / "section_10_7" / "bd-3ex_contract.md"
DEFAULT_BINARY_PATH = ROOT / "target" / "debug" / "franken-node"
RUNNER_ENV = "FRANKEN_NODE_VERIFY_BIN"
DEFAULT_RUNNER_TIMEOUT_SECONDS = 30

REQUIRED_COMMAND_IDS = [
    "verify-module",
    "verify-migration",
    "verify-compatibility",
    "verify-corpus",
]
COMMAND_LABELS = {
    "verify-module": "verify module",
    "verify-migration": "verify migration",
    "verify-compatibility": "verify compatibility",
    "verify-corpus": "verify corpus",
}
CLI_MARKERS = [
    "Module(VerifyModuleArgs)",
    "Migration(VerifyMigrationArgs)",
    "Compatibility(VerifyCompatibilityArgs)",
    "Corpus(VerifyCorpusArgs)",
]
MAIN_MARKERS = [
    "VerifyCommand::Module(args)",
    "VerifyCommand::Migration(args)",
    "VerifyCommand::Compatibility(args)",
    "VerifyCommand::Corpus(args)",
    "schema_versions::VERIFY_CLI_CONTRACT",
]


def _check(check: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": check, "passed": passed, "detail": detail}


def _self_test_check(passed: bool, message: str) -> None:
    if not passed:
        raise AssertionError(message)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _load_json(path: Path) -> tuple[bool, dict[str, Any] | None, str]:
    if not path.is_file():
        return False, None, "missing"
    try:
        payload = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, None, f"invalid-json:{exc.pos}"
    if not isinstance(payload, dict):
        return False, None, "json-root-not-object"
    return True, payload, "ok"


def _dump_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def load_contract(path: Path = CONTRACT_PATH) -> tuple[bool, dict[str, Any] | None, str]:
    if not path.is_file():
        return False, None, f"missing:{_display_path(path)}"
    try:
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        return False, None, f"invalid-toml:{exc}"
    if not isinstance(loaded, dict):
        return False, None, "toml-root-not-object"
    return True, loaded, "ok"


def _parse_major(version: str) -> int:
    try:
        return int(version.split(".")[0])
    except (ValueError, IndexError):
        return 0


def _resolve_runner(binary_path: Path | None) -> Path:
    if binary_path is not None:
        return binary_path
    env_path = os.environ.get(RUNNER_ENV)
    if env_path:
        return Path(env_path)
    return DEFAULT_BINARY_PATH


def _runner_available(binary_path: Path) -> bool:
    return binary_path.is_file() and os.access(binary_path, os.X_OK)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _prepare_migration_fixture(root: Path) -> None:
    _write_text(root / "dist" / "server.js", "console.log('ok');\n")
    _write_text(root / "evidence" / "rewrite-validation.json", "{\"validated\":true}\n")
    _write_json(
        root / ".franken-node" / "state" / "migrations" / "rewrite.json",
        {
            "schema_version": "franken-node/migration-evidence/v1",
            "migration_id": "rewrite",
            "project_root": str(root),
            "status": "applied",
            "post_conditions_met": True,
            "validation_record_path": "evidence/rewrite-validation.json",
            "post_conditions": [
                "dist/server.js",
                {
                    "path": "dist/server.js",
                    "exists": True,
                    "contains": "console.log",
                },
            ],
        },
    )


def _prepare_corpus_fixture(root: Path) -> Path:
    manifest_path = root / "fixtures" / "verify-corpus-contract" / "manifest.json"
    _write_json(
        manifest_path,
        {
            "schema_version": "corpus-v1.0",
            "bead_id": "bd-3ex-contract-corpus",
            "timestamp": _utc_timestamp(),
            "fixtures": [
                {
                    "fixture_id": "fixture-core-001",
                    "api_surface": "fs.readFile",
                    "band": "core",
                    "expected_behavior": "utf8 read matches Node semantics",
                    "node_version": "22.0.0",
                    "deterministic": True,
                    "spec_section": "fs",
                },
                {
                    "fixture_id": "fixture-high-value-001",
                    "api_surface": "process.env",
                    "band": "high_value",
                    "expected_behavior": "environment lookup preserves missing values",
                    "node_version": "22.0.0",
                    "deterministic": True,
                    "spec_section": "process",
                },
                {
                    "fixture_id": "fixture-edge-001",
                    "api_surface": "path.join",
                    "band": "edge",
                    "expected_behavior": "path normalization handles empty components",
                    "node_version": "22.0.0",
                    "deterministic": True,
                    "spec_section": "path",
                },
                {
                    "fixture_id": "fixture-unsafe-001",
                    "api_surface": "child_process.spawn",
                    "band": "unsafe",
                    "expected_behavior": "unsafe process launch is policy-gated",
                    "node_version": "22.0.0",
                    "deterministic": True,
                    "spec_section": "child_process",
                },
            ],
            "summary": {
                "total_fixtures": 4,
                "by_band": {
                    "core": 1,
                    "high_value": 1,
                    "edge": 1,
                    "unsafe": 1,
                },
            },
        },
    )
    return manifest_path


def _scenario_invocation(
    command_id: str,
    compat_version: int | None,
    fixture_root: Path,
) -> tuple[list[str], Path]:
    if command_id == "verify-module":
        args = ["verify", "module", "runtime"]
        cwd = ROOT
    elif command_id == "verify-migration":
        _prepare_migration_fixture(fixture_root)
        args = ["verify", "migration", "rewrite"]
        cwd = fixture_root
    elif command_id == "verify-compatibility":
        args = ["verify", "compatibility", "strict"]
        cwd = ROOT
    elif command_id == "verify-corpus":
        manifest_path = _prepare_corpus_fixture(fixture_root)
        args = ["verify", "corpus", str(manifest_path)]
        cwd = fixture_root
    else:
        raise ValueError(f"unknown command_id={command_id}")

    if compat_version is not None:
        args.extend(["--compat-version", str(compat_version)])
    args.append("--json")
    return args, cwd


def _run_verifier_scenario(
    *,
    binary_path: Path,
    command_id: str,
    compat_version: int | None,
    contract_version: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="bd3ex_verifier_contract_") as tmpdir:
        fixture_root = Path(tmpdir)
        args, cwd = _scenario_invocation(command_id, compat_version, fixture_root)
        env = os.environ.copy()
        env["FRANKEN_NODE_VERIFY_CONTRACT_VERSION"] = contract_version
        try:
            proc = subprocess.run(
                [str(binary_path), *args],
                cwd=cwd,
                env=env,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "ok": False,
                "argv": [str(binary_path), *args],
                "cwd": str(cwd),
                "detail": f"timeout after {timeout_seconds}s: {exc}",
                "process_exit_code": None,
                "payload": None,
            }
        except OSError as exc:
            return {
                "ok": False,
                "argv": [str(binary_path), *args],
                "cwd": str(cwd),
                "detail": f"runner execution failed: {exc}",
                "process_exit_code": None,
                "payload": None,
            }

        stdout = proc.stdout.strip()
        try:
            payload = json.JSONDecoder().decode(stdout)
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "argv": [str(binary_path), *args],
                "cwd": str(cwd),
                "detail": f"stdout was not JSON: {exc.msg} at {exc.pos}; stderr={proc.stderr.strip()[:300]}",
                "process_exit_code": proc.returncode,
                "payload": None,
            }
        if not isinstance(payload, dict):
            return {
                "ok": False,
                "argv": [str(binary_path), *args],
                "cwd": str(cwd),
                "detail": "stdout JSON root was not an object",
                "process_exit_code": proc.returncode,
                "payload": None,
            }

        return {
            "ok": True,
            "argv": [str(binary_path), *args],
            "cwd": str(cwd),
            "detail": "executed real verifier subprocess",
            "process_exit_code": proc.returncode,
            "payload": payload,
        }


def _compare_snapshot(actual: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    actual_keys = set(actual.keys())
    snapshot_keys = set(snapshot.keys())

    added_fields = sorted(actual_keys - snapshot_keys)
    removed_fields = sorted(snapshot_keys - actual_keys)
    changed_fields = sorted(
        key for key in actual_keys & snapshot_keys if actual.get(key) != snapshot.get(key)
    )

    breaking = bool(removed_fields or changed_fields)
    additive_only = bool(added_fields) and not breaking
    exact = not added_fields and not removed_fields and not changed_fields
    return {
        "breaking": breaking,
        "additive_only": additive_only,
        "exact": exact,
        "added_fields": added_fields,
        "removed_fields": removed_fields,
        "changed_fields": changed_fields,
    }


def run_checks(
    *,
    update_snapshots: bool = False,
    contract_path: Path = CONTRACT_PATH,
    binary_path: Path | None = None,
    runner_timeout_seconds: int = DEFAULT_RUNNER_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    snapshot_diffs: list[dict[str, Any]] = []
    runner_path = _resolve_runner(binary_path)

    ok, contract, status = load_contract(contract_path)
    checks.append(_check("contract_loadable", ok, status))
    if not ok or contract is None:
        return {
            "bead_id": BEAD_ID,
            "section": SECTION,
            "title": TITLE,
            "contract_path": _display_path(contract_path),
            "runner_path": _display_path(runner_path),
            "checks": checks,
            "snapshot_diffs": snapshot_diffs,
            "passed": 0,
            "failed": len(checks),
            "total": len(checks),
            "verdict": "FAIL",
            "all_passed": False,
            "status": "fail",
        }

    contract_version = str(contract.get("contract_version", "0.0.0"))
    major = _parse_major(contract_version)
    previous_major = int(contract.get("previous_contract_major", major))

    exit_codes = contract.get("exit_codes", {})
    exit_ok = isinstance(exit_codes, dict) and exit_codes == {
        "pass": 0,
        "fail": 1,
        "error": 2,
        "skipped": 3,
    }
    checks.append(_check("exit_code_taxonomy", exit_ok, "expect pass=0 fail=1 error=2 skipped=3"))

    error_format = contract.get("error_format", {})
    error_fields_ok = (
        isinstance(error_format, dict)
        and isinstance(error_format.get("required_fields"), list)
        and set(error_format["required_fields"]) == {"error_code", "message", "remediation"}
    )
    checks.append(_check("error_format_contract", error_fields_ok, "required_fields include error_code/message/remediation"))

    command_defs = contract.get("commands", [])
    command_ids = [row.get("id") for row in command_defs if isinstance(row, dict)]
    command_required_fields = {
        str(row.get("id")): set(row.get("required_output_fields", []))
        for row in command_defs
        if isinstance(row, dict) and isinstance(row.get("required_output_fields"), list)
    }
    commands_ok = all(command_id in command_ids for command_id in REQUIRED_COMMAND_IDS)
    checks.append(
        _check(
            "required_command_ids",
            commands_ok,
            f"found={','.join(str(c) for c in command_ids)}",
        )
    )

    runner_ok = _runner_available(runner_path)
    checks.append(
        _check(
            "verifier_runner_available",
            runner_ok,
            _display_path(runner_path),
        )
    )

    cli_text = _load_text(CLI_PATH)
    cli_ok = all(marker in cli_text for marker in CLI_MARKERS)
    checks.append(_check("cli_exposes_required_subcommands", cli_ok, "module/migration/compatibility/corpus variants present"))

    main_text = _load_text(MAIN_PATH)
    main_ok = all(marker in main_text for marker in MAIN_MARKERS)
    checks.append(_check("main_routes_required_subcommands", main_ok, "main.rs routes required verifier command variants"))

    spec_text = _load_text(SPEC_CONTRACT_PATH)
    spec_ok = bool(spec_text.strip()) and all(
        token in spec_text for token in ("verify-module", "verify-migration", "verify-compatibility", "verify-corpus")
    )
    checks.append(
        _check(
            "docs_spec_contract_present",
            spec_ok,
            str(SPEC_CONTRACT_PATH.relative_to(ROOT)),
        )
    )

    scenarios = contract.get("scenarios", [])
    scenario_ids = [row.get("scenario_id") for row in scenarios if isinstance(row, dict)]
    checks.append(_check("scenario_count", len(scenario_ids) >= 5, f"count={len(scenario_ids)}"))

    default_coverage_ok = True
    for cmd_id in REQUIRED_COMMAND_IDS:
        expected = f"{cmd_id.replace('-', '_')}_default"
        if expected not in scenario_ids:
            default_coverage_ok = False
            break
    checks.append(_check("default_scenario_coverage", default_coverage_ok, "each required command has a *_default scenario"))

    snapshot_updates = 0
    breaking_failures = 0
    for row in scenarios:
        if not isinstance(row, dict):
            checks.append(_check("scenario_row_shape", False, "scenario row is not object"))
            continue

        scenario_id = str(row.get("scenario_id", ""))
        command_id = str(row.get("command_id", ""))
        raw_compat = int(row.get("compat_version", 0))
        compat_version = None if raw_compat == 0 else raw_compat
        snapshot_rel = str(row.get("snapshot", ""))
        snapshot_path = ROOT / snapshot_rel

        if command_id not in COMMAND_LABELS:
            checks.append(_check(f"scenario:{scenario_id}:command_id", False, f"unknown command_id={command_id}"))
            continue
        checks.append(_check(f"scenario:{scenario_id}:snapshot_exists", snapshot_path.is_file(), snapshot_rel))
        ok_snapshot, snapshot_payload, snapshot_status = _load_json(snapshot_path)
        checks.append(
            _check(
                f"scenario:{scenario_id}:snapshot_json",
                ok_snapshot,
                f"{snapshot_rel}:{snapshot_status}",
            )
        )
        if not ok_snapshot or snapshot_payload is None:
            continue

        if not runner_ok:
            checks.append(
                _check(
                    f"scenario:{scenario_id}:runner_executed",
                    False,
                    f"missing executable verifier runner: {_display_path(runner_path)}",
                )
            )
            continue

        execution = _run_verifier_scenario(
            binary_path=runner_path,
            command_id=command_id,
            compat_version=compat_version,
            contract_version=contract_version,
            timeout_seconds=runner_timeout_seconds,
        )
        checks.append(
            _check(
                f"scenario:{scenario_id}:runner_executed",
                execution["ok"],
                f"{' '.join(execution['argv'])} (cwd={execution['cwd']})",
            )
        )
        if not execution["ok"] or execution["payload"] is None:
            checks.append(
                _check(
                    f"scenario:{scenario_id}:stdout_json",
                    False,
                    execution["detail"],
                )
            )
            continue

        checks.append(_check(f"scenario:{scenario_id}:stdout_json", True, "stdout parsed as JSON object"))
        actual = execution["payload"]
        process_exit_code = execution["process_exit_code"]
        reported_exit_code = actual.get("exit_code")
        exit_matches = isinstance(reported_exit_code, int) and reported_exit_code == process_exit_code
        checks.append(
            _check(
                f"scenario:{scenario_id}:exit_code_matches_process",
                exit_matches,
                f"reported={reported_exit_code} process={process_exit_code}",
            )
        )
        required_fields = command_required_fields.get(command_id, set())
        missing_required = sorted(field for field in required_fields if field not in actual)
        checks.append(
            _check(
                f"scenario:{scenario_id}:required_output_fields",
                not missing_required,
                f"missing={missing_required}",
            )
        )

        diff = _compare_snapshot(actual, snapshot_payload)
        snapshot_diffs.append(
            {
                "scenario_id": scenario_id,
                "process_exit_code": process_exit_code,
                "reported_exit_code": reported_exit_code,
                **diff,
            }
        )

        if diff["exact"]:
            checks.append(_check(f"scenario:{scenario_id}:snapshot_match", True, "exact"))
            continue

        if diff["additive_only"]:
            detail = f"added_fields={diff['added_fields']}"
            checks.append(_check(f"scenario:{scenario_id}:snapshot_additive", True, detail))
            if update_snapshots:
                merged = dict(snapshot_payload)
                merged.update(actual)
                _dump_json(snapshot_path, merged)
                snapshot_updates += 1
            continue

        if diff["breaking"]:
            if major > previous_major:
                checks.append(
                    _check(
                        f"scenario:{scenario_id}:snapshot_breaking_with_major_bump",
                        True,
                        f"breaking change allowed: major={major} previous={previous_major}",
                    )
                )
            else:
                checks.append(
                    _check(
                        f"scenario:{scenario_id}:snapshot_breaking_without_major_bump",
                        False,
                        f"removed={diff['removed_fields']} changed={diff['changed_fields']}",
                    )
                )
                breaking_failures += 1

    checks.append(_check("snapshot_updates", True, f"updated={snapshot_updates}" if update_snapshots else "update-snapshots disabled"))
    checks.append(_check("breaking_change_enforcement", breaking_failures == 0, f"breaking_failures={breaking_failures}"))

    passed = sum(1 for item in checks if item["passed"])
    failed = len(checks) - passed
    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": TITLE,
        "contract_path": _display_path(contract_path),
        "contract_version": contract_version,
        "runner_path": _display_path(runner_path),
        "checks": checks,
        "snapshot_diffs": snapshot_diffs,
        "passed": passed,
        "failed": failed,
        "total": len(checks),
        "verdict": "PASS" if failed == 0 else "FAIL",
        "all_passed": failed == 0,
        "status": "pass" if failed == 0 else "fail",
    }


def self_test() -> bool:
    exact = _compare_snapshot({"a": 1}, {"a": 1})
    _self_test_check(exact["exact"] and not exact["breaking"], "exact snapshots must compare cleanly")

    additive = _compare_snapshot({"a": 1, "b": 2}, {"a": 1})
    _self_test_check(additive["additive_only"], "added fields should be non-breaking additive")

    breaking = _compare_snapshot({"a": 2}, {"a": 1, "b": 2})
    _self_test_check(breaking["breaking"], "value changes/removals must be breaking")

    with tempfile.TemporaryDirectory(prefix="bd3ex_self_test_") as tmpdir:
        args, cwd = _scenario_invocation("verify-module", 9, Path(tmpdir))
    _self_test_check(
        args == ["verify", "module", "runtime", "--compat-version", "9", "--json"],
        "verify-module scenario invocation must include compat flag and JSON mode",
    )
    _self_test_check(cwd == ROOT, "verify-module scenario should execute from the repository root")

    return True


def main() -> int:
    configure_test_logging("check_verifier_contract")
    parser = argparse.ArgumentParser(description=f"Verify {BEAD_ID} contract conformance")
    parser.add_argument("--json", action="store_true", help="Emit JSON report.")
    parser.add_argument("--self-test", action="store_true", help="Run checker self-test.")
    parser.add_argument("--update-snapshots", action="store_true", help="Apply additive snapshot updates.")
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH, help="Path to verifier contract TOML.")
    parser.add_argument(
        "--binary",
        type=Path,
        default=None,
        help=f"Path to franken-node verifier binary. Defaults to ${RUNNER_ENV} or {_display_path(DEFAULT_BINARY_PATH)}.",
    )
    parser.add_argument(
        "--runner-timeout-seconds",
        type=int,
        default=DEFAULT_RUNNER_TIMEOUT_SECONDS,
        help="Per-scenario verifier subprocess timeout.",
    )
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        print("self_test passed" if ok else "self_test FAILED")
        return 0 if ok else 1

    report = run_checks(
        update_snapshots=args.update_snapshots,
        contract_path=args.contract,
        binary_path=args.binary,
        runner_timeout_seconds=args.runner_timeout_seconds,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"{BEAD_ID} verifier contract gate — {report['verdict']} "
            f"({report['passed']}/{report['total']})"
        )
        for item in report["checks"]:
            status = "PASS" if item["passed"] else "FAIL"
            print(f"[{status}] {item['check']}: {item['detail']}")

    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
