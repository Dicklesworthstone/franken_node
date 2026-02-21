#!/usr/bin/env python3
"""Validate Section 11 rollback-command contract field (bd-nglx)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

TEMPLATE_PATH = ROOT / "docs" / "templates" / "change_summary_template.md"
EXAMPLE_PATH = ROOT / "docs" / "change_summaries" / "example_change_summary.json"
DEFAULT_SUMMARY_DIR = ROOT / "docs" / "change_summaries"

REQUIRED_EVENT_CODES = {
    "CONTRACT_ROLLBACK_COMMAND_VALIDATED",
    "CONTRACT_ROLLBACK_COMMAND_MISSING",
    "CONTRACT_ROLLBACK_COMMAND_INCOMPLETE",
}

SUBSYSTEM_PATH_PREFIXES = (
    "crates/franken-node/src/",
    "crates/franken-engine/src/",
    "crates/asupersync/src/",
    "services/",
)

PLACEHOLDER_PATTERNS = (
    re.compile(r"<[^>]+>"),
    re.compile(r"\$\{[^}]+\}"),
    re.compile(r"\{\{[^}]+\}\}"),
    re.compile(r"%[sd]"),
    re.compile(r"\bTODO\b", re.IGNORECASE),
)

DURATION_TOKEN_RE = re.compile(r"\d+[hms]")
DURATION_RE = re.compile(r"^(?:(?:\d+h)?(?:\d+m)?(?:\d+s)?)$")


def _norm(path: Path | str) -> str:
    return str(path).replace("\\", "/")


def _rel(path: Path, base: Path) -> str:
    try:
        return _norm(path.relative_to(base))
    except ValueError:
        return _norm(path)


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_changed_files(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"changed-files list not found: {path}")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _discover_changed_files_from_git(project_root: Path) -> list[str]:
    commands = [
        ["git", "-C", str(project_root), "diff", "--name-only", "origin/main...HEAD"],
        ["git", "-C", str(project_root), "diff", "--name-only", "HEAD~1...HEAD"],
    ]
    last_error: Exception | None = None
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
            return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception as exc:  # pragma: no cover - defensive fallback
            last_error = exc
    raise RuntimeError(f"unable to discover changed files via git diff: {last_error}")


def _is_subsystem_path(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in SUBSYSTEM_PATH_PREFIXES)


def _require_non_empty_str(value: Any, field: str, errors: list[str]) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{field} must be a non-empty string")
        return ""
    return value.strip()


def _require_list(value: Any, field: str, errors: list[str], *, min_items: int = 0) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{field} must be a list")
        return []
    if len(value) < min_items:
        errors.append(f"{field} must contain at least {min_items} item(s)")
    return value


def _valid_duration(duration: str) -> bool:
    if DURATION_RE.fullmatch(duration) is None:
        return False
    return len(DURATION_TOKEN_RE.findall(duration)) > 0


def _contains_placeholder(command: str) -> bool:
    for pattern in PLACEHOLDER_PATTERNS:
        if pattern.search(command):
            return True
    return False


def _validate_summary_file(summary_path: Path, project_root: Path) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    summary_rel = _rel(summary_path, project_root)
    if not summary_path.is_file():
        message = f"summary file listed in diff but missing on disk: {summary_rel}"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_ROLLBACK_COMMAND_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"invalid JSON in {summary_rel}: {exc}"
        trace = _trace_id({"summary_file": summary_rel, "error": str(exc)})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_ROLLBACK_COMMAND_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    if not isinstance(payload, dict):
        message = f"{summary_rel} must contain a JSON object"
        trace = _trace_id({"summary_file": summary_rel, "error": message})
        return False, {
            "summary_file": summary_rel,
            "ok": False,
            "errors": [message],
            "warnings": [],
            "events": [
                {
                    "event_code": "CONTRACT_ROLLBACK_COMMAND_INCOMPLETE",
                    "severity": "error",
                    "trace_correlation": trace,
                    "summary_file": summary_rel,
                    "message": message,
                }
            ],
        }

    trace = _trace_id(payload)

    change_summary = payload.get("change_summary")
    if not isinstance(change_summary, dict):
        errors.append("change_summary must be an object")
        change_summary = {}

    rollback = change_summary.get("rollback_command")
    if not isinstance(rollback, dict):
        errors.append("change_summary.rollback_command must be an object")
        rollback = {}

    command = _require_non_empty_str(rollback.get("command"), "change_summary.rollback_command.command", errors)
    if command:
        if "\n" in command or "\r" in command:
            errors.append("change_summary.rollback_command.command must be single-line")
        if _contains_placeholder(command):
            errors.append(
                "change_summary.rollback_command.command contains unresolved placeholders"
            )

    idempotent = rollback.get("idempotent")
    if not isinstance(idempotent, bool):
        errors.append("change_summary.rollback_command.idempotent must be boolean")
    elif idempotent is not True:
        errors.append("change_summary.rollback_command.idempotent must be true")

    tested_in_ci = rollback.get("tested_in_ci")
    if not isinstance(tested_in_ci, bool):
        errors.append("change_summary.rollback_command.tested_in_ci must be boolean")
    elif tested_in_ci is not True:
        errors.append("change_summary.rollback_command.tested_in_ci must be true")

    test_evidence_artifact = _require_non_empty_str(
        rollback.get("test_evidence_artifact"),
        "change_summary.rollback_command.test_evidence_artifact",
        errors,
    )
    if test_evidence_artifact:
        artifact_abs = project_root / test_evidence_artifact
        if not artifact_abs.is_file():
            errors.append(
                "change_summary.rollback_command.test_evidence_artifact does not exist: "
                f"{test_evidence_artifact}"
            )

    rollback_scope = rollback.get("rollback_scope")
    if not isinstance(rollback_scope, dict):
        errors.append("change_summary.rollback_command.rollback_scope must be an object")
        rollback_scope = {}

    reverts_raw = _require_list(
        rollback_scope.get("reverts"),
        "change_summary.rollback_command.rollback_scope.reverts",
        errors,
        min_items=1,
    )
    does_not_revert_raw = _require_list(
        rollback_scope.get("does_not_revert"),
        "change_summary.rollback_command.rollback_scope.does_not_revert",
        errors,
        min_items=1,
    )

    reverts: list[str] = []
    for idx, item in enumerate(reverts_raw):
        if not isinstance(item, str) or not item.strip():
            errors.append(
                "change_summary.rollback_command.rollback_scope.reverts"
                f"[{idx}] must be a non-empty string"
            )
            continue
        reverts.append(item.strip())

    does_not_revert: list[str] = []
    for idx, item in enumerate(does_not_revert_raw):
        if not isinstance(item, str) or not item.strip():
            errors.append(
                "change_summary.rollback_command.rollback_scope.does_not_revert"
                f"[{idx}] must be a non-empty string"
            )
            continue
        does_not_revert.append(item.strip())

    estimated_duration = _require_non_empty_str(
        rollback.get("estimated_duration"),
        "change_summary.rollback_command.estimated_duration",
        errors,
    )
    if estimated_duration and not _valid_duration(estimated_duration):
        errors.append(
            "change_summary.rollback_command.estimated_duration must use compact duration format "
            "(e.g. 30s, 2m, 1h30m)"
        )

    ok = len(errors) == 0
    event_code = (
        "CONTRACT_ROLLBACK_COMMAND_VALIDATED"
        if ok
        else "CONTRACT_ROLLBACK_COMMAND_INCOMPLETE"
    )
    message = (
        f"rollback command contract validated: {summary_rel}"
        if ok
        else f"rollback command contract incomplete: {summary_rel}"
    )
    events.append(
        {
            "event_code": event_code,
            "severity": "info" if ok else "error",
            "trace_correlation": trace,
            "summary_file": summary_rel,
            "message": message,
        }
    )

    return ok, {
        "summary_file": summary_rel,
        "ok": ok,
        "trace_correlation": trace,
        "errors": errors,
        "warnings": warnings,
        "events": events,
        "reverts_count": len(reverts),
        "does_not_revert_count": len(does_not_revert),
        "estimated_duration": estimated_duration,
    }


def run_checks(
    *,
    changed_files: list[str] | None = None,
    changed_files_path: Path | None = None,
    project_root: Path = ROOT,
    summary_dir: Path | None = None,
) -> tuple[bool, dict[str, Any]]:
    summary_dir = summary_dir or (project_root / "docs" / "change_summaries")
    template_path = project_root / "docs" / "templates" / "change_summary_template.md"
    example_path = project_root / "docs" / "change_summaries" / "example_change_summary.json"

    errors: list[str] = []
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    if not template_path.is_file():
        errors.append(f"missing template file: {_rel(template_path, project_root)}")
    if not example_path.is_file():
        errors.append(f"missing example change summary: {_rel(example_path, project_root)}")
    if not summary_dir.exists():
        errors.append(f"missing summary directory: {_rel(summary_dir, project_root)}")

    if changed_files is None:
        if changed_files_path is not None:
            changed_files = _load_changed_files(changed_files_path)
            changed_source = _rel(changed_files_path, project_root)
        else:
            changed_files = _discover_changed_files_from_git(project_root)
            changed_source = "git-diff"
    else:
        changed_source = "inline"

    normalized_changed = sorted({_norm(path) for path in changed_files if path})
    changed_subsystem_files = [path for path in normalized_changed if _is_subsystem_path(path)]
    requires_contract = len(changed_subsystem_files) > 0

    summary_dir_rel = _rel(summary_dir, project_root)
    changed_summary_files = [
        path
        for path in normalized_changed
        if path.startswith(f"{summary_dir_rel}/") and path.endswith(".json")
    ]

    validated_summaries: list[dict[str, Any]] = []

    if requires_contract and not changed_summary_files:
        trace = _trace_id({"changed_subsystem_files": changed_subsystem_files})
        message = (
            "missing required change summary file under "
            f"{summary_dir_rel}/ for subsystem code changes"
        )
        errors.append(message)
        events.append(
            {
                "event_code": "CONTRACT_ROLLBACK_COMMAND_MISSING",
                "severity": "error",
                "trace_correlation": trace,
                "message": message,
                "changed_subsystem_files": changed_subsystem_files,
            }
        )

    for summary_rel in changed_summary_files:
        ok, detail = _validate_summary_file(project_root / summary_rel, project_root)
        validated_summaries.append(detail)
        events.extend(detail["events"])
        warnings.extend(detail["warnings"])
        if not ok:
            errors.extend(detail["errors"])

    ok = len(errors) == 0
    report = {
        "bead_id": "bd-nglx",
        "ok": ok,
        "changed_files_source": changed_source,
        "changed_file_count": len(normalized_changed),
        "subsystem_change_count": len(changed_subsystem_files),
        "requires_contract": requires_contract,
        "summary_files_checked": [item["summary_file"] for item in validated_summaries],
        "template": _rel(template_path, project_root),
        "example": _rel(example_path, project_root),
        "summary_directory": _rel(summary_dir, project_root),
        "required_event_codes": sorted(REQUIRED_EVENT_CODES),
        "errors": sorted(dict.fromkeys(errors)),
        "warnings": sorted(dict.fromkeys(warnings)),
        "events": events,
        "validated_summaries": validated_summaries,
    }
    return ok, report


def self_test() -> tuple[bool, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rollback-command-selftest-") as tmp:
        root = Path(tmp)
        (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
        (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)

        (root / "docs" / "templates" / "change_summary_template.md").write_text(
            "# template\n",
            encoding="utf-8",
        )
        (root / "artifacts" / "section_11" / "bd-nglx" / "rollback_command_ci_test.json").write_text(
            "{\"ok\":true}\n",
            encoding="utf-8",
        )

        valid_summary = {
            "summary_id": "chg-selftest",
            "contract_version": "1.0",
            "change_summary": {
                "rollback_command": {
                    "command": (
                        "franken-node rollback apply "
                        "--receipt artifacts/section_11/bd-nglx/rollback_command_ci_test.json "
                        "--force-safe"
                    ),
                    "idempotent": True,
                    "tested_in_ci": True,
                    "test_evidence_artifact": "artifacts/section_11/bd-nglx/rollback_command_ci_test.json",
                    "rollback_scope": {
                        "reverts": ["policy activation state"],
                        "does_not_revert": ["already-emitted audit logs"],
                    },
                    "estimated_duration": "45s",
                }
            },
        }

        example = root / "docs" / "change_summaries" / "example_change_summary.json"
        example.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")
        candidate = root / "docs" / "change_summaries" / "candidate.json"
        candidate.write_text(json.dumps(valid_summary, indent=2), encoding="utf-8")

        ok_pass, report_pass = run_checks(
            changed_files=[
                "crates/franken-node/src/connector/mock.rs",
                "docs/change_summaries/candidate.json",
            ],
            project_root=root,
        )
        assert ok_pass, f"self_test expected pass but failed: {report_pass['errors']}"

        invalid_summary = json.loads(json.dumps(valid_summary))
        invalid_summary["change_summary"]["rollback_command"]["command"] = (
            "franken-node rollback apply --receipt <receipt-path>"
        )
        candidate.write_text(json.dumps(invalid_summary, indent=2), encoding="utf-8")

        ok_fail, report_fail = run_checks(
            changed_files=[
                "crates/franken-node/src/connector/mock.rs",
                "docs/change_summaries/candidate.json",
            ],
            project_root=root,
        )
        assert not ok_fail, "self_test expected failure for placeholder rollback command"
        assert any("contains unresolved placeholders" in err for err in report_fail["errors"])

        ok_missing, report_missing = run_checks(
            changed_files=["crates/franken-node/src/connector/mock.rs"],
            project_root=root,
        )
        assert not ok_missing, "self_test expected missing-contract failure"
        assert any("missing required change summary file" in err for err in report_missing["errors"])

    return True, {"ok": True, "self_test": "passed"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        default=None,
        help="Path to newline-delimited changed-file list (recommended in CI).",
    )
    parser.add_argument(
        "--project-root",
        default=str(ROOT),
        help="Project root path.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test.")
    args = parser.parse_args()

    try:
        if args.self_test:
            ok, payload = self_test()
        else:
            changed_files_path = Path(args.changed_files) if args.changed_files else None
            ok, payload = run_checks(
                changed_files_path=changed_files_path,
                project_root=Path(args.project_root),
            )
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
