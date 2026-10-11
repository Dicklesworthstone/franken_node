#!/usr/bin/env python3
"""Execute frozen multi-file projects against Node and the native runtime.

This is an executable project corpus, not the singleton fixture schema checker.
No packages are installed and no reference runtime substitutes for the native
candidate. Fixtures are trusted programs, not sandboxed by this runner.

    python3 scripts/project_compat_runner.py --bin target/release/franken-node \
        --artifacts-dir /tmp/project-compat-001

The artifact directory must be new. Exit 0 means every selected case passed;
1 means a mismatch or reference failure; 2 means invalid input/setup. Individual
case failures retain both runtime observations and do not stop the other cases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
from typing import Any, Sequence

try:
    from scripts.runtime_invoke_watchdog import (
        Cancellation, cancellation_signals, positive_bytes, positive_ms, supervise,
    )
except ModuleNotFoundError:
    from runtime_invoke_watchdog import (
        Cancellation, cancellation_signals, positive_bytes, positive_ms, supervise,
    )

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = ROOT / "fixtures" / "compatibility" / "projects" / "corpus.json"
SCHEMA = "franken-node/project-compat-corpus/v1"
REPORT_SCHEMA = "franken-node/project-compat-report/v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PROJECT_BYTES = 1024 * 1024
MAX_FILES = 256
MAX_CASES = 256
ID = re.compile(r"[a-z][a-z0-9_-]{0,79}\Z")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def _keys(value: Any, required: set[str], optional: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    missing, unknown = required - value.keys(), value.keys() - required - optional
    if missing or unknown:
        raise ValueError(f"{label}: missing {sorted(missing)}; unknown {sorted(unknown)}")


def _text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError(f"{label} must be a NUL-free string")
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return value


def relative_path(value: Any) -> str:
    name = _text(value, "project path", 1024)
    path = PurePosixPath(name)
    if (not name or "\\" in name or ":" in name or path.is_absolute()
            or any(part in ("", ".", "..") for part in name.split("/"))
            or any(ord(char) < 32 for char in name)):
        raise ValueError(f"unsafe project path: {name!r}")
    if any(part in (".git", ".franken-node") for part in path.parts):
        raise ValueError(f"reserved project path: {name!r}")
    return name


def validate_corpus(corpus: Any) -> dict[str, Any]:
    _keys(corpus, {"schema_version", "cases"}, {"description"}, "corpus")
    if corpus["schema_version"] != SCHEMA:
        raise ValueError(f"schema_version must be {SCHEMA}")
    cases = corpus["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError(f"corpus needs 1..{MAX_CASES} cases")
    ids: set[str] = set()
    for case in cases:
        _keys(case, {"id", "category", "entry", "files", "expected"},
              {"description", "args", "stdin"}, "case")
        name = _text(case["id"], "case id", 80)
        if not ID.fullmatch(name) or name in ids:
            raise ValueError(f"invalid or duplicate case id: {name!r}")
        ids.add(name)
        _text(case["category"], "category", 128)
        files = case["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
            raise ValueError(f"{name}: project needs 1..{MAX_FILES} files")
        paths = set()
        total = 0
        for path, content in files.items():
            paths.add(relative_path(path))
            total += len(_text(content, path, MAX_PROJECT_BYTES).encode("utf-8"))
        if total > MAX_PROJECT_BYTES:
            raise ValueError(f"{name}: project exceeds {MAX_PROJECT_BYTES} bytes")
        for path in paths:
            if any(str(parent) in paths for parent in PurePosixPath(path).parents):
                raise ValueError(f"{name}: file/directory collision at {path}")
        entry = relative_path(case["entry"])
        if entry not in paths or PurePosixPath(entry).suffix not in (".js", ".cjs", ".mjs"):
            raise ValueError(f"{name}: entry must name a captured JavaScript file")
        args = case.get("args", [])
        if not isinstance(args, list) or len(args) > 128:
            raise ValueError(f"{name}: args must be an array of at most 128 strings")
        for arg in args:
            _text(arg, "argument", 4096)
        if "stdin" in case:
            _text(case["stdin"], "stdin", MAX_PROJECT_BYTES)
        expected = case["expected"]
        _keys(expected, {"stdout", "stderr", "exit_code"}, set(), "expected")
        _text(expected["stdout"], "expected.stdout", MAX_PROJECT_BYTES)
        _text(expected["stderr"], "expected.stderr", MAX_PROJECT_BYTES)
        code = expected["exit_code"]
        if type(code) is not int or not 0 <= code <= 255:
            raise ValueError("expected.exit_code must be an integer in 0..255")
    return corpus


def load_corpus(path: Path) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    with path.open("rb") as source:
        data = source.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("corpus manifest exceeds size limit")
    return validate_corpus(json.loads(data, object_pairs_hook=unique_pairs))


def executable(name: str) -> Path:
    resolved = shutil.which(name)
    if resolved is None:
        raise ValueError(f"executable not found: {name!r}")
    return Path(resolved).resolve(strict=True)


def fingerprint(path: Path) -> dict[str, str]:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return {"path": str(path), "sha256": "sha256:" + hasher.hexdigest()}


def stage(case: dict[str, Any], workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=False)
    for name, content in sorted(case["files"].items()):
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(content.encode("utf-8"))


def observation(receipt: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "outcome": receipt["outcome"],
        "exit_code": receipt["runtime_exit_code"],
        "output_complete": receipt["output_complete"],
        "stdin_delivery_complete": receipt["stdin_delivery_complete"],
        "receipt_path": str(Path(receipt["stdout_path"]).parent / "watchdog.json"),
    }
    for stream in ("stdout", "stderr"):
        data = Path(receipt[f"{stream}_path"]).read_bytes()
        result[stream + "_sha256"] = digest(data)
        result[stream + "_bytes"] = len(data)
    return result


def differences(receipt: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    failures = []
    # An expected nonzero application exit is not a supervisor failure. Signals,
    # deadlines, missing runtimes and incomplete streams are never comparable.
    if (receipt["outcome"] not in ("completed", "runtime_failed")
            or not receipt["output_complete"] or not receipt["stdin_delivery_complete"]):
        failures.append("execution_incomplete")
    if receipt["runtime_exit_code"] != expected["exit_code"]:
        failures.append("exit_code")
    for stream in ("stdout", "stderr"):
        if Path(receipt[f"{stream}_path"]).read_bytes() != expected[stream].encode("utf-8"):
            failures.append(stream)
    return failures


def run_case(case: dict[str, Any], binary: Path, node: Path, directory: Path,
             policy: str, limits: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"id": case["id"], "category": case["category"],
                              "case_sha256": digest(encoded(case)), "verdict": "ERROR"}
    directory.mkdir()
    (directory / "case.json").write_bytes(encoded(case))
    # Separate workspaces prevent the reference's file mutations/cache/state
    # from seeding the candidate's result. Neither process sees the source tree.
    for runtime in ("reference", "candidate"):
        stage(case, directory / runtime / "project")
    native_cwd = directory / "candidate" / "project"
    setup = supervise([str(binary), "init", "--profile", policy, "--out-dir", "."],
                      directory / "setup", cwd=native_cwd, **limits)
    result["setup"] = observation(setup)
    if setup["outcome"] != "completed":
        result["detail"] = "candidate initialization failed"
        return result
    # init must not silently replace captured inputs (for example a fixture
    # that conflicts with the generated project configuration).
    for name, content in case["files"].items():
        target = native_cwd / name
        if target.is_symlink() or not target.is_file() or target.read_bytes() != content.encode("utf-8"):
            result["detail"] = f"candidate initialization changed fixture input: {name}"
            return result
    entry = "./" + case["entry"]
    args = case.get("args", [])
    commands = {
        "reference": [str(node), entry, *args],
        "candidate": [str(binary), "run", entry, "--policy", policy,
                      "--runtime", "franken-engine", "--console-only", *(["--", *args] if args else [])],
    }
    stdin = case.get("stdin")
    for runtime, command in commands.items():
        receipt = supervise(command, directory / runtime / "execution",
                            cwd=directory / runtime / "project",
                            stdin_data=stdin.encode("utf-8") if stdin is not None else None, **limits)
        result[runtime] = observation(receipt)
        result[runtime]["differences"] = differences(receipt, case["expected"])
    if result["reference"]["differences"]:
        result["verdict"] = "REFERENCE_FAILED"
    elif result["candidate"]["differences"]:
        result["verdict"] = "FAIL"
    else:
        result["verdict"] = "PASS"
    return result


def run_corpus(corpus: dict[str, Any], binary: Path, node: Path, artifacts: Path, *,
               policy: str = "balanced", selected: Sequence[str] = (),
               wall_time_ms: int = 10000, max_output_bytes: int = 1024 * 1024,
               cancellation: Cancellation | None = None) -> dict[str, Any]:
    validate_corpus(corpus)
    unknown = set(selected) - {case["id"] for case in corpus["cases"]}
    if unknown:
        raise ValueError(f"unknown case ids: {sorted(unknown)}")
    if policy not in ("strict", "balanced", "legacy-risky"):
        raise ValueError("invalid policy")
    positive_ms(str(wall_time_ms))
    positive_bytes(str(max_output_bytes))
    native_identity, reference_identity = fingerprint(binary), fingerprint(node)
    if native_identity["sha256"] == reference_identity["sha256"]:
        raise ValueError("candidate and reference must be different runtime binaries")
    artifacts = artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    (artifacts / "corpus.json").write_bytes(encoded(corpus))
    cases = [case for case in corpus["cases"] if not selected or case["id"] in selected]
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA, "verdict": "RUNNING", "policy": policy,
        "corpus_sha256": digest(encoded(corpus)), "corpus_case_count": len(corpus["cases"]),
        "selected_case_count": len(cases), "candidate": native_identity,
        "reference": reference_identity, "results": [],
        "claim_scope": "selected project cases only; not the micro-corpus compatibility score",
    }
    cancellation = cancellation or Cancellation()
    limits = {"wall_time_ms": wall_time_ms, "max_output_bytes": max_output_bytes,
              "cancellation": cancellation}
    report_path = artifacts / "report.json"
    report_path.write_bytes(encoded(report))
    for case in cases:
        if cancellation.signum is not None:
            break
        try:
            result = run_case(case, binary, node, artifacts / case["id"], policy, limits)
        except (OSError, ValueError) as error:
            result = {"id": case["id"], "category": case["category"], "verdict": "ERROR",
                      "detail": f"{type(error).__name__}: {error}"}
        report["results"].append(result)
        report_path.write_bytes(encoded(report))
    report["passing_cases"] = sum(row["verdict"] == "PASS" for row in report["results"])
    report["verdict"] = (
        "CANCELLED" if cancellation.signum is not None else
        "PASS" if report["passing_cases"] == len(cases) else "FAIL")
    report_path.write_bytes(encoded(report))
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--bin", default=os.environ.get("FRANKEN_NODE_BIN", str(ROOT / "target/release/franken-node")))
    parser.add_argument("--node", default="node")
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--policy", default="balanced", choices=["strict", "balanced", "legacy-risky"])
    parser.add_argument("--case", action="append", default=[], dest="selected")
    parser.add_argument("--wall-time-ms", type=positive_ms, default=10000)
    parser.add_argument("--max-output-bytes", type=positive_bytes, default=1024 * 1024)
    args = parser.parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        with cancellation_signals() as cancellation:
            report = run_corpus(corpus, executable(args.bin), executable(args.node), args.artifacts_dir,
                                policy=args.policy, selected=args.selected, wall_time_ms=args.wall_time_ms,
                                max_output_bytes=args.max_output_bytes, cancellation=cancellation)
    except (OSError, ValueError) as error:
        print(json.dumps({"schema_version": REPORT_SCHEMA, "verdict": "ERROR", "detail": str(error)}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
