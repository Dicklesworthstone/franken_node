#!/usr/bin/env python3
"""Execute frozen multi-file projects against Node, optional Bun, and native.

This is an executable project corpus, not the singleton fixture schema checker.
No packages are installed and no reference runtime substitutes for the native
candidate. Fixtures are trusted programs, not sandboxed by this runner.

    python3 scripts/project_compat_runner.py --bin target/release/franken-node \
        --bun bun --artifacts-dir /tmp/project-compat-001

The artifact directory must be new. Exit 0 means every selected case passed;
1 means a case/setup/reference failure or inconclusive reference disagreement;
2 means invalid input or missing prerequisites. Individual case failures retain
all completed runtime observations and do not stop later cases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
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
    if "description" in corpus:
        _text(corpus["description"], "description", 4096)
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
        if "description" in case:
            _text(case["description"], "description", 4096)
        files = case["files"]
        if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
            raise ValueError(f"{name}: project needs 1..{MAX_FILES} files")
        paths = set()
        total = 0
        for path, text in files.items():
            paths.add(relative_path(path))
            total += len(_text(text, path, MAX_PROJECT_BYTES).encode("utf-8"))
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
        if sum(len(arg.encode("utf-8")) for arg in args) > 32768:
            raise ValueError(f"{name}: total argument bytes exceed 32768")
        if "stdin" in case:
            _text(case["stdin"], "stdin", MAX_PROJECT_BYTES)
        expected = case["expected"]
        _keys(expected, {"stdout", "stderr", "exit_code"}, {"files"}, "expected")
        _text(expected["stdout"], "expected.stdout", MAX_PROJECT_BYTES)
        _text(expected["stderr"], "expected.stderr", MAX_PROJECT_BYTES)
        code = expected["exit_code"]
        if type(code) is not int or not 0 <= code <= 255:
            raise ValueError("expected.exit_code must be an integer in 0..255")
        output_files = expected.get("files", {})
        if not isinstance(output_files, dict) or len(output_files) > 32:
            raise ValueError("expected.files must map at most 32 paths to text or null")
        for path, value in output_files.items():
            relative_path(path)
            if value is not None:
                _text(value, "expected file", MAX_PROJECT_BYTES)
    if len(encoded(corpus)) > MAX_MANIFEST_BYTES:
        raise ValueError("canonical corpus manifest exceeds size limit")
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
    for name, text in sorted(case["files"].items()):
        target = workspace / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(text.encode("utf-8"))


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


def reference_disagreements(node: dict[str, Any], bun: dict[str, Any]) -> list[str]:
    """Compare measured reference behavior, excluding artifact-local receipt paths."""
    channels = []
    if (node["outcome"], node["exit_code"]) != (bun["outcome"], bun["exit_code"]):
        channels.append("termination")
    if (node["output_complete"], node["stdin_delivery_complete"]) != (
            bun["output_complete"], bun["stdin_delivery_complete"]):
        channels.append("completeness")
    if (node["stdout_sha256"], node["stdout_bytes"]) != (
            bun["stdout_sha256"], bun["stdout_bytes"]):
        channels.append("stdout")
    if (node["stderr_sha256"], node["stderr_bytes"]) != (
            bun["stderr_sha256"], bun["stderr_bytes"]):
        channels.append("stderr")
    if node.get("files", {}) != bun.get("files", {}):
        channels.append("files")
    return channels


def publish_report(path: Path, report: dict[str, Any]) -> None:
    """Atomically replace a report, including after each completed case."""
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".report-", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(encoded(report))
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def inspect_output_file(workspace: Path, name: str, expected: str | None) -> dict[str, Any]:
    """Read bounded regular output via no-follow directory-relative descriptors.

    Symlinks (including intermediate parents), devices and FIFOs cannot satisfy
    an expectation, even a null/absent expectation. A changing file fails closed.
    """
    relative_path(name)
    parent = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        with os.fdopen(os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                               dir_fd=parent), "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                return {"status": "unsafe", "matches": False}
            if before.st_size > MAX_PROJECT_BYTES:
                return {"status": "oversized", "matches": False, "bytes": before.st_size}
            data = source.read(MAX_PROJECT_BYTES + 1)
            after = os.fstat(source.fileno())
            named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)

            def identity(info: os.stat_result) -> tuple[int, ...]:
                return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)

            if (identity(before) != identity(after) or identity(after) != identity(named)
                    or len(data) != before.st_size):
                return {"status": "changed", "matches": False}
            return {"status": "regular", "bytes": len(data), "sha256": digest(data),
                    "matches": expected is not None and data == expected.encode("utf-8")}
    except FileNotFoundError:
        return {"status": "absent", "matches": expected is None}
    except OSError as error:
        return {"status": "unsafe", "matches": False, "error": str(error)}
    finally:
        os.close(parent)


def reject_runtime_overrides() -> None:
    """Do not let ambient loader hooks silently modify captured programs."""
    names = {"NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"}
    names.update(key for key in os.environ if key.startswith("FRANKEN_NODE_") and key != "FRANKEN_NODE_BIN")
    present = sorted(key for key in names if os.environ.get(key))
    if present:
        raise ValueError("unset ambient runtime overrides before comparison: " + ", ".join(present))


def run_case(case: dict[str, Any], binary: Path, node: Path, bun: Path | None,
             directory: Path, policy: str, limits: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"id": case["id"], "category": case["category"],
                              "case_sha256": digest(encoded(case)), "verdict": "ERROR"}
    directory.mkdir()
    (directory / "case.json").write_bytes(encoded(case))
    runtimes = ("reference", "bun", "candidate") if bun is not None else ("reference", "candidate")
    # Independent workspaces prevent either reference from seeding another role.
    # None of the processes executes from the source checkout.
    for runtime in runtimes:
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
    for name, text in case["files"].items():
        target = native_cwd / name
        if target.is_symlink() or not target.is_file() or target.read_bytes() != text.encode("utf-8"):
            result["detail"] = f"candidate initialization changed fixture input: {name}"
            return result
    entry = "./" + case["entry"]
    args = case.get("args", [])
    commands = {
        "reference": [str(node), entry, *args],
        "candidate": [str(binary), "run", entry, "--policy", policy,
                      "--runtime", "franken-engine", "--console-only",
                      *(["--", *args] if args else [])],
    }
    if bun is not None:
        commands["bun"] = [str(bun), entry, *args]
    stdin = case.get("stdin")
    for runtime in runtimes:
        command = commands[runtime]
        receipt = supervise(command, directory / runtime / "execution",
                            cwd=directory / runtime / "project",
                            stdin_data=stdin.encode("utf-8") if stdin is not None else None, **limits)
        result[runtime] = observation(receipt)
        result[runtime]["differences"] = differences(receipt, case["expected"])
        result[runtime]["files"] = {}
        for name, expected in case["expected"].get("files", {}).items():
            observed = inspect_output_file(directory / runtime / "project", name, expected)
            result[runtime]["files"][name] = observed
            if not observed["matches"]:
                result[runtime]["differences"].append("file:" + name)
    if bun is not None:
        result["reference_disagreements"] = reference_disagreements(result["reference"], result["bun"])
        if result["reference_disagreements"]:
            result["verdict"] = "INCONCLUSIVE"
        elif result["reference"]["differences"] or result["bun"]["differences"]:
            result["verdict"] = "REFERENCE_FAILED"
        elif result["candidate"]["differences"]:
            result["verdict"] = "FAIL"
        else:
            result["verdict"] = "PASS"
    elif result["reference"]["differences"]:
        result["verdict"] = "REFERENCE_FAILED"
    elif result["candidate"]["differences"]:
        result["verdict"] = "FAIL"
    else:
        result["verdict"] = "PASS"
    return result


def run_corpus(corpus: dict[str, Any], binary: Path, node: Path, artifacts: Path, *,
               bun: Path | None = None, policy: str = "balanced", selected: Sequence[str] = (),
               wall_time_ms: int = 10000, max_output_bytes: int = 1024 * 1024,
               cancellation: Cancellation | None = None,
               expected_corpus_sha256: str | None = None) -> dict[str, Any]:
    validate_corpus(corpus)
    reject_runtime_overrides()
    corpus_sha256 = digest(encoded(corpus))
    if expected_corpus_sha256 is not None and expected_corpus_sha256 != corpus_sha256:
        raise ValueError("corpus digest does not match --expect-corpus-sha256")
    unknown = set(selected) - {case["id"] for case in corpus["cases"]}
    if unknown:
        raise ValueError(f"unknown case ids: {sorted(unknown)}")
    if policy not in ("strict", "balanced", "legacy-risky"):
        raise ValueError("invalid policy")
    positive_ms(str(wall_time_ms))
    positive_bytes(str(max_output_bytes))
    native_identity, reference_identity = fingerprint(binary), fingerprint(node)
    if native_identity["sha256"] == reference_identity["sha256"]:
        raise ValueError("candidate and Node reference must be different runtime binaries")
    bun_identity = fingerprint(bun) if bun is not None else None
    if bun_identity is not None:
        if bun_identity["sha256"] == reference_identity["sha256"]:
            raise ValueError("Node and Bun references must be different runtime binaries")
        if bun_identity["sha256"] == native_identity["sha256"]:
            raise ValueError("candidate and Bun reference must be different runtime binaries")
    artifacts = artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=False)
    (artifacts / "corpus.json").write_bytes(encoded(corpus))
    cases = [case for case in corpus["cases"] if not selected or case["id"] in selected]
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA, "verdict": "RUNNING", "policy": policy,
        "oracle": "node-bun-native" if bun is not None else "node-native",
        "corpus_sha256": corpus_sha256, "corpus_case_count": len(corpus["cases"]),
        "selected_case_count": len(cases), "candidate": native_identity,
        "reference": reference_identity, "results": [],
        "runner": fingerprint(Path(__file__)),
        "limits": {"wall_time_ms": wall_time_ms, "max_output_bytes_per_stream": max_output_bytes},
        "environment_scope": "inherited; loader overrides rejected; not a hermetic environment replay",
        "claim_scope": "selected project cases only; not the micro-corpus compatibility score",
    }
    if bun_identity is not None:
        report["bun_reference"] = bun_identity
    cancellation = cancellation or Cancellation()
    limits = {"wall_time_ms": wall_time_ms, "max_output_bytes": max_output_bytes,
              "cancellation": cancellation}
    report_path = artifacts / "report.json"
    publish_report(report_path, report)
    for current_case in cases:
        if cancellation.signum is not None:
            break
        try:
            result = run_case(current_case, binary, node, bun,
                              artifacts / current_case["id"], policy, limits)
        except (OSError, ValueError) as error:
            result = {"id": current_case["id"], "category": current_case["category"],
                      "verdict": "ERROR", "detail": f"{type(error).__name__}: {error}"}
        report["results"].append(result)
        publish_report(report_path, report)
    report["categories"] = {}
    for row in report["results"]:
        counts = report["categories"].setdefault(
            row["category"], {"total": 0, "passed": 0, "inconclusive": 0})
        counts["total"] += 1
        counts["passed"] += row["verdict"] == "PASS"
        counts["inconclusive"] += row["verdict"] == "INCONCLUSIVE"
    report["passing_cases"] = sum(row["verdict"] == "PASS" for row in report["results"])
    report["inconclusive_cases"] = sum(
        row["verdict"] == "INCONCLUSIVE" for row in report["results"])
    report["failing_cases"] = sum(
        row["verdict"] in ("FAIL", "REFERENCE_FAILED", "ERROR") for row in report["results"])
    # Definite measured failures outrank uncertainty. Otherwise one unrelated
    # reference disagreement could hide a known native or oracle failure.
    report["verdict"] = (
        "CANCELLED" if cancellation.signum is not None else
        "FAIL" if report["failing_cases"] else
        "INCONCLUSIVE" if report["inconclusive_cases"] else
        "PASS" if report["passing_cases"] == len(cases) else "FAIL")
    publish_report(report_path, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--bin", default=os.environ.get(
        "FRANKEN_NODE_BIN", str(ROOT / "target/release/franken-node")))
    parser.add_argument("--node", default="node")
    parser.add_argument("--bun", help="optional second reference; disagreements make the case inconclusive")
    parser.add_argument("--expect-corpus-sha256", help="require this digest when rerunning a retained corpus")
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--policy", default="balanced", choices=["strict", "balanced", "legacy-risky"])
    parser.add_argument("--case", action="append", default=[], dest="selected")
    parser.add_argument("--wall-time-ms", type=positive_ms, default=10000)
    parser.add_argument("--max-output-bytes", type=positive_bytes, default=1024 * 1024)
    args = parser.parse_args(argv)
    try:
        corpus_value = load_corpus(args.corpus)
        with cancellation_signals() as cancellation:
            report = run_corpus(
                corpus_value, executable(args.bin), executable(args.node), args.artifacts_dir,
                bun=executable(args.bun) if args.bun else None,
                policy=args.policy, selected=args.selected, wall_time_ms=args.wall_time_ms,
                max_output_bytes=args.max_output_bytes, cancellation=cancellation,
                expected_corpus_sha256=args.expect_corpus_sha256)
    except (OSError, ValueError) as error:
        print(json.dumps({"schema_version": REPORT_SCHEMA, "verdict": "ERROR", "detail": str(error)}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
