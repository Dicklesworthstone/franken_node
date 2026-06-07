#!/usr/bin/env python3
"""Run a validation command and fail closed if lockfiles change.

Validation gates are expected to be read-only with respect to dependency
resolution. This helper snapshots lockfiles before and after a command, emits a
structured report, and returns non-zero if the command changed a lockfile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "franken-node/lockfile-drift-guard/v1"
DEFAULT_LOCKFILES = ("Cargo.lock",)
DEFAULT_DRIFT_EXIT_CODE = 20
DEFAULT_TIMEOUT_SECONDS = 3600


def _sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _snapshot(root: Path, path: Path) -> dict[str, Any]:
    exists = path.exists()
    return {
        "path": _display_path(root, path),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else None,
        "sha256": _sha256(path),
    }


def _status(before: dict[str, Any], after: dict[str, Any]) -> str:
    if before["exists"] and after["exists"]:
        if before["sha256"] == after["sha256"] and before["size_bytes"] == after["size_bytes"]:
            return "unchanged"
        return "modified"
    if not before["exists"] and after["exists"]:
        return "created"
    if before["exists"] and not after["exists"]:
        return "deleted"
    return "missing"


def _normalize_lockfiles(root: Path, values: list[str]) -> list[Path]:
    selected = values or list(DEFAULT_LOCKFILES)
    paths: list[Path] = []
    seen: set[str] = set()
    for value in selected:
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        key = path.resolve().as_posix()
        if key not in seen:
            seen.add(key)
            paths.append(path)
    return paths


def _next_action(changed_paths: list[str], command_exit_code: int) -> str:
    if changed_paths:
        paths = ", ".join(changed_paths)
        return (
            f"Inspect the changed lockfile paths ({paths}) and commit intentional dependency-resolution "
            "changes, or rerun the validation from a clean lockfile state with a locked "
            "command where the tool supports it."
        )
    if command_exit_code != 0:
        return "Fix the validation command failure, then rerun the lockfile drift guard."
    return "No action required."


def build_report(
    *,
    root: Path,
    label: str,
    command: list[str],
    command_exit_code: int,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    drift_exit_code: int,
) -> dict[str, Any]:
    lockfiles: list[dict[str, Any]] = []
    changed_paths: list[str] = []
    for before_entry, after_entry in zip(before, after, strict=True):
        status = _status(before_entry, after_entry)
        path = after_entry["path"]
        if status in {"modified", "created", "deleted"}:
            changed_paths.append(path)
        lockfiles.append(
            {
                "path": path,
                "status": status,
                "before_exists": before_entry["exists"],
                "after_exists": after_entry["exists"],
                "before_sha256": before_entry["sha256"],
                "after_sha256": after_entry["sha256"],
                "before_size_bytes": before_entry["size_bytes"],
                "after_size_bytes": after_entry["size_bytes"],
            }
        )

    guard_exit_code = drift_exit_code if changed_paths else command_exit_code
    verdict = "FAIL" if guard_exit_code != 0 else "PASS"
    return {
        "schema_version": SCHEMA_VERSION,
        "label": label,
        "verdict": verdict,
        "cwd": root.as_posix(),
        "command": shlex.join(command),
        "command_argv": command,
        "command_exit_code": command_exit_code,
        "guard_exit_code": guard_exit_code,
        "changed_paths": changed_paths,
        "lockfiles": lockfiles,
        "next_action": _next_action(changed_paths, command_exit_code),
    }


def render_human(report: dict[str, Any]) -> str:
    lines = [
        f"lockfile drift guard: {report['verdict']}",
        f"label: {report['label']}",
        f"command: {report['command']}",
        f"command_exit_code: {report['command_exit_code']}",
        f"guard_exit_code: {report['guard_exit_code']}",
        "changed_paths:",
    ]
    changed_paths = report["changed_paths"]
    if changed_paths:
        lines.extend(f"- {path}" for path in changed_paths)
    else:
        lines.append("- none")
    lines.append(f"next_action: {report['next_action']}")
    return "\n".join(lines) + "\n"


def _write_report_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_command(command: list[str], root: Path, timeout_seconds: int) -> tuple[int, str, str]:
    try:
        process = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, "", f"{exc}\n"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        timeout_message = f"command timed out after {timeout_seconds} seconds\n"
        return 124, stdout, stderr + timeout_message
    return process.returncode, process.stdout or "", process.stderr or ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="repository root for relative lockfiles")
    parser.add_argument(
        "--lockfile",
        action="append",
        default=[],
        help="lockfile path to snapshot; defaults to Cargo.lock",
    )
    parser.add_argument("--label", default="validation command", help="operator-facing command label")
    parser.add_argument("--json", action="store_true", help="emit report JSON to stdout")
    parser.add_argument("--report-json", default=None, help="also write report JSON to this path")
    parser.add_argument(
        "--drift-exit-code",
        type=int,
        default=DEFAULT_DRIFT_EXIT_CODE,
        help="exit code used when lockfile drift is detected",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="maximum runtime for the wrapped command",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to run after --")
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("lockfile_drift_guard: missing command after --", file=sys.stderr)
        return 2

    root = Path(args.root).resolve()
    lockfiles = _normalize_lockfiles(root, args.lockfile)
    before = [_snapshot(root, path) for path in lockfiles]
    command_exit_code, command_stdout, command_stderr = _run_command(
        command,
        root,
        max(1, args.timeout_seconds),
    )
    after = [_snapshot(root, path) for path in lockfiles]
    report = build_report(
        root=root,
        label=args.label,
        command=command,
        command_exit_code=command_exit_code,
        before=before,
        after=after,
        drift_exit_code=args.drift_exit_code,
    )

    if args.report_json:
        _write_report_json(Path(args.report_json), report)

    if args.json:
        if command_stdout:
            sys.stderr.write(command_stdout)
        if command_stderr:
            sys.stderr.write(command_stderr)
        sys.stdout.write(json.dumps(report, sort_keys=True) + "\n")
    else:
        if command_stdout:
            sys.stdout.write(command_stdout)
        if command_stderr:
            sys.stderr.write(command_stderr)
        sys.stdout.write(render_human(report))

    return int(report["guard_exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
