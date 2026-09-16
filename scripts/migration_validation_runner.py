#!/usr/bin/env python3
"""Execute migration tests on two runtimes in independent workspace copies.

Default commands are Node.js and the native franken-node run path. Custom
commands are JSON argv arrays containing a standalone {test} argument; no shell
or package install is invoked. Execute only projects you trust: workspace copies
isolate relative filesystem mutations, not arbitrary code, network, or absolute
paths. This is a test-process oracle, not release certification or an OS sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = ROOT / "docs/specs/section_10_3/bd-2st_contract.md"
PRIMARY_IMPLEMENTATION_PATHS = {
    "migration_validation_runner": "scripts/migration_validation_runner.py",
    "lockstep_harness": "crates/franken-node/src/runtime/lockstep_harness.rs",
}
EVIDENCE_PATHS = {
    **PRIMARY_IMPLEMENTATION_PATHS,
    "contract": "docs/specs/section_10_3/bd-2st_contract.md",
    "verifier": "scripts/check_migration_validation.py",
    "regression_tests": "tests/test_check_migration_validation.py",
    "machine_evidence": "artifacts/section_10_3/bd-2st/verification_evidence.json",
    "human_summary": "artifacts/section_10_3/bd-2st/verification_summary.md",
}
VERIFICATION_COMMANDS = [
    {"command": "python3 scripts/check_migration_validation.py --json",
     "covers": ["runner self-test", "implementation citations", "discovery", "comparison"]},
    {"command": "python3 -m unittest discover -s tests -p test_check_migration_validation.py",
     "covers": ["real process execution", "isolation", "fail-closed verdicts", "CLI exit codes"]},
]
TEST_PATTERNS = [
    "**/*.test.js", "**/*.test.ts", "**/*.spec.js", "**/*.spec.ts",
    "**/__tests__/**/*.js", "**/__tests__/**/*.ts",
    "**/test/**/*.js", "**/test/**/*.ts",
]
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
PID_PATTERN = re.compile(r"\bpid[=: ]+\d+\b", re.IGNORECASE)
ABS_PATH_PATTERN = re.compile(r"(/[a-zA-Z0-9_./-]+){3,}")
DEFAULT_BASELINE_COMMAND = ("node", "{test}")
DEFAULT_MIGRATION_COMMAND = ("franken-node", "run", "--console-only", "{test}")
MAX_TEST_FILES = 1024
MAX_PROJECT_FILES = 50_000
MAX_PROJECT_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def raise_walk_error(error: OSError) -> None:
    """An unreadable subtree must never silently shrink the measured input."""
    raise error


def discover_tests(project_dir: Path) -> list[Path]:
    """Discover only project tests, excluding dependency and VCS directories."""
    tests = set()
    for directory, names, files in os.walk(project_dir, followlinks=False, onerror=raise_walk_error):
        names[:] = sorted(n for n in names if n not in {"node_modules", ".git"})
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(project_dir)
            if (name.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts",
                               ".test.mjs", ".spec.mjs", ".test.cjs", ".spec.cjs"))
                    or (set(relative.parts[:-1]) & {"test", "__tests__"}
                        and path.suffix in {".js", ".ts", ".mjs", ".cjs"})):
                tests.add(path)
                if len(tests) > MAX_TEST_FILES:
                    raise ValueError(f"test discovery exceeds {MAX_TEST_FILES} files")
    return sorted(tests)


def canonicalize_output(output: str) -> str:
    """Legacy diagnostic normalization; NEVER used to award a live PASS."""
    return ABS_PATH_PATTERN.sub("<ABS_PATH>", PID_PATTERN.sub(
        "pid=<PID>", TIMESTAMP_PATTERN.sub("<TIMESTAMP>", output)))


def compare_outputs(baseline: str, migration: str) -> dict:
    """Compare normalized diagnostic lines; live verdicts compare exact bytes."""
    b_lines = canonicalize_output(baseline).splitlines()
    m_lines = canonicalize_output(migration).splitlines()
    divergences = []
    for i in range(max(len(b_lines), len(m_lines))):
        b_line = b_lines[i] if i < len(b_lines) else None
        m_line = m_lines[i] if i < len(m_lines) else None
        if b_line != m_line:
            divergences.append({"line": i + 1, "baseline": b_line, "migration": m_line})
    return {"identical": not divergences, "divergence_count": len(divergences),
            "divergences": divergences[:20]}


def classify_divergence_severity(divergences: list[dict], band: str = "core") -> str:
    if not divergences:
        return "none"
    return {"core": "critical", "high-value": "high", "edge": "informational"}.get(band, "medium")


@dataclass(frozen=True)
class SnapshotEntry:
    path: str
    data: bytes | None
    mode: int
    link: str | None = None


def capture_project(project: Path, deadline: float) -> tuple[list[SnapshotEntry], str]:
    """Capture bounded regular files and contained symlinks before either leg.

    Dependencies and project configuration are included; .git is excluded.
    Internal links are preserved (absolute internal links become relative).
    External links and special files are refused rather than touching targets
    outside the disposable workspace. This is not an atomic filesystem snapshot.
    """
    entries = []
    total = 0
    digest = hashlib.sha256(b"franken-migration-input-v1\0")
    for directory, names, files in os.walk(project, followlinks=False, onerror=raise_walk_error):
        names[:] = sorted(n for n in names if n != ".git")
        for name in sorted(names + [name for name in files if name != ".git"]):
            if time.monotonic() >= deadline:
                raise TimeoutError("total validation budget exhausted during project capture")
            path = Path(directory) / name
            relative = path.relative_to(project).as_posix()
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode) & 0o777
            if stat.S_ISLNK(metadata.st_mode):
                target = path.resolve(strict=True)
                if not target.is_relative_to(project):
                    raise ValueError(f"external workspace symlink refused: {relative}")
                link = os.readlink(path)
                lexical_target = Path(os.path.abspath(path.parent / link))
                if (not lexical_target.is_relative_to(project)
                        or ".git" in lexical_target.relative_to(project).parts
                        or ".git" in target.relative_to(project).parts):
                    raise ValueError(f"external or excluded workspace symlink refused: {relative}")
                # Preserve intermediate links: flattening a->b->c would change
                # program behavior when a test retargets b.
                if os.path.isabs(link):
                    link = os.path.relpath(lexical_target, path.parent)
                entry = SnapshotEntry(relative, None, mode, link)
            elif stat.S_ISDIR(metadata.st_mode):
                entry = SnapshotEntry(relative, None, mode)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_size > MAX_PROJECT_BYTES - total:
                    raise ValueError(f"project exceeds {MAX_PROJECT_BYTES}-byte capture budget")
                flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                with os.fdopen(os.open(path, flags), "rb") as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError(f"nonregular project input refused: {relative}")
                    data = source.read(MAX_PROJECT_BYTES - total + 1)
                    after = os.fstat(source.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                          after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError(f"project input changed during capture: {relative}")
                total += len(data)
                if total > MAX_PROJECT_BYTES:
                    raise ValueError(f"project exceeds {MAX_PROJECT_BYTES}-byte capture budget")
                entry = SnapshotEntry(relative, data, mode)
            else:
                raise ValueError(f"nonregular project input refused: {relative}")
            entries.append(entry)
            if len(entries) > MAX_PROJECT_FILES:
                raise ValueError(f"project exceeds {MAX_PROJECT_FILES}-entry capture budget")
            # Length framing preserves path, type, mode, content and link identity.
            for part in (relative.encode(), str(mode).encode(),
                         b"link" if entry.link is not None else b"dir" if entry.data is None else b"file",
                         entry.link.encode() if entry.link is not None else entry.data or b""):
                digest.update(len(part).to_bytes(8, "big"))
                digest.update(part)
    return entries, digest.hexdigest()


def stage_project(entries: list[SnapshotEntry], destination: Path, deadline: float) -> None:
    """Materialize the captured input; no live source is reread between legs."""
    destination.mkdir()
    for entry in entries:
        if time.monotonic() >= deadline:
            raise TimeoutError("total validation budget exhausted while staging a test")
        path = destination / entry.path
        if entry.link is not None:
            path.symlink_to(entry.link)
        elif entry.data is None:
            path.mkdir()
        else:
            path.write_bytes(entry.data)
            path.chmod(entry.mode)
    # Keep directories writable during materialization, then preserve modes.
    for entry in reversed(entries):
        if entry.data is None and entry.link is None:
            (destination / entry.path).chmod(entry.mode)


def workspace_delta(before: list[SnapshotEntry], after: list[SnapshotEntry]) -> dict:
    """Compare effects on workspace state, not original-vs-rewritten source.

    Captures persistent file/link/mode changes only, not transient writes,
    external paths or network effects. Raw file bytes never enter the report.
    """
    def fingerprint(entry: SnapshotEntry) -> dict:
        return {"kind": "link" if entry.link is not None else "directory" if entry.data is None else "file",
                "mode": entry.mode,
                "sha256": hashlib.sha256(entry.link.encode() if entry.link is not None
                                         else entry.data or b"").hexdigest()}

    previous = {entry.path: fingerprint(entry) for entry in before}
    current = {entry.path: fingerprint(entry) for entry in after}
    return {path: {"change": "created" if path not in previous else "removed" if path not in current else "modified",
                   "after": current.get(path)}
            for path in sorted(previous.keys() | current.keys()) if previous.get(path) != current.get(path)}


def summarize_delta(delta: dict) -> dict:
    payload = json.dumps(delta, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": hashlib.sha256(b"franken-migration-workspace-delta-v1\0" + payload).hexdigest(),
            "changed_paths": len(delta), "changes": dict(list(delta.items())[:20]),
            "details_truncated": len(delta) > 20}


def resolve_command(command: tuple[str, ...] | list[str]) -> list[str]:
    if (not isinstance(command, (list, tuple)) or not command or len(command) > 256
            or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
            or command.count("{test}") != 1 or command[0] == "{test}"):
        raise ValueError("runtime command must be a nonempty argv array with one standalone {test}")
    if sum(len(arg.encode()) for arg in command) > 65536:
        raise ValueError("runtime argv exceeds the 65536-byte bound")
    executable = shutil.which(command[0])
    if executable is None:
        raise ValueError(f"runtime executable not found: {command[0]}")
    return [str(Path(executable).resolve()), *command[1:]]


def run_command(command: list[str], cwd: Path, *, timeout: float,
                max_output_bytes: int, environment: dict[str, str]) -> dict:
    """Bound both pipes and process lifetime, including inherited child pipes.

    A new POSIX session lets timeout/overflow cleanup kill this leg's process
    group. Even identical failures never qualify as successful validation.
    """
    started = time.monotonic()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {name: 0 for name in output}
    hashes = {name: hashlib.sha256() for name in output}
    reason = None
    with subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process:
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map() or process.poll() is None:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.05)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        name = key.data
                        counts[name] += len(chunk)
                        hashes[name].update(chunk)
                        room = max(0, max_output_bytes - len(output[name]))
                        output[name].extend(chunk[:room])
                        if counts[name] > max_output_bytes:
                            reason = "output_limit"
                            break
                    if reason:
                        break
        finally:
            # Reap background descendants even when the leader exited cleanly.
            # This only targets the new process group created above.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return {"exit_code": process.returncode,
            "termination": reason or ("signal" if process.returncode < 0 else "exited"),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "stdout": bytes(output["stdout"]), "stderr": bytes(output["stderr"]),
            "streams": {name: {"bytes_observed": counts[name],
                               "sha256": hashes[name].hexdigest(),
                               "complete": reason is None,
                               "retained_bytes": len(output[name])} for name in output}}


def validate_project(project_dir: Path, *, migrated_project: Path | None = None,
                     baseline_command=DEFAULT_BASELINE_COMMAND,
                     migration_command=DEFAULT_MIGRATION_COMMAND,
                     timeout_seconds: float = 30.0, total_timeout_seconds: float = 300.0,
                     max_output_bytes: int = 1_048_576, band: str = "core",
                     compare_filesystem: bool = False) -> dict:
    """Execute a nonempty test set; FAIL/ERROR/NO_TESTS can never yield PASS."""
    report = {"schema_version": "migration-validation-v1", "project": str(project_dir),
              "migrated_project": str(migrated_project or project_dir),
              "validation_timestamp": datetime.now(timezone.utc).isoformat(),
              "phase": "execution",
              "validation_scope": "test-process-and-workspace-delta" if compare_filesystem else "test-process-stdout-stderr-exit",
              "comparison_mode": "exact-bytes", "release_certification": False,
              "filesystem_comparison": compare_filesystem, "filesystem_exclusions": [".git"],
              "test_discovery": {"test_files_found": 0, "test_files": []},
              "validation_results": [], "errors": [],
              "summary": {"total_tests": 0, "passed": 0, "failed": 0, "skipped": 0,
                          "errored": 0, "verdict": "ERROR"}}
    summary = report["summary"]
    try:
        if os.name != "posix":
            raise ValueError("bounded process-group execution currently requires POSIX")
        if (not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 3600
                or not math.isfinite(total_timeout_seconds)
                or not 0 < total_timeout_seconds <= 86400):
            raise ValueError("timeouts must be finite positive seconds (per-test <=3600, total <=86400)")
        if type(max_output_bytes) is not int or not 0 < max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError(f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}")
        if band not in {"core", "high-value", "edge"}:
            raise ValueError("band must be core, high-value, or edge")
        deadline = time.monotonic() + total_timeout_seconds
        baseline_root = Path(project_dir).resolve(strict=True)
        migration_root = Path(migrated_project or project_dir).resolve(strict=True)
        if not baseline_root.is_dir() or not migration_root.is_dir():
            raise ValueError("both project paths must be directories")
        # Capture before executing anything; every case starts from these bytes.
        baseline_entries, baseline_digest = capture_project(baseline_root, deadline)
        if migration_root == baseline_root:
            migration_entries, migration_digest = baseline_entries, baseline_digest
        else:
            migration_entries, migration_digest = capture_project(migration_root, deadline)
        with tempfile.TemporaryDirectory(prefix="franken-migration-") as temporary:
            root = Path(temporary)
            discovery = root / "discovery"
            stage_project(baseline_entries, discovery, deadline)
            baseline_tests = {path.relative_to(discovery).as_posix() for path in discover_tests(discovery)}
            migration_discovery = root / "migration-discovery"
            stage_project(migration_entries, migration_discovery, deadline)
            migration_tests = {path.relative_to(migration_discovery).as_posix()
                               for path in discover_tests(migration_discovery)}
            tests = sorted(baseline_tests | migration_tests)
            report["test_discovery"] = {"test_files_found": len(tests), "test_files": tests,
                                        "missing_baseline": sorted(migration_tests - baseline_tests),
                                        "missing_migration": sorted(baseline_tests - migration_tests)}
            summary.update(total_tests=len(tests), skipped=len(tests))
            report["inputs"] = {"baseline_sha256": baseline_digest, "migration_sha256": migration_digest}
            if baseline_tests != migration_tests:
                raise ValueError("project test inventories differ; missing test counterparts are reported in test_discovery")
            if not tests:
                summary["verdict"] = "NO_TESTS"
                return report
            baseline = resolve_command(baseline_command)
            migration = resolve_command(migration_command)
            report["commands"] = {"baseline": baseline, "migration": migration}
            report["limits"] = {"per_leg_seconds": timeout_seconds, "total_seconds": total_timeout_seconds,
                                "per_stream_bytes": max_output_bytes}
            environment = dict(os.environ)
            # Freeze a single inherited environment for both legs; do not invent
            # permissive policy, signing keys, or degraded-runtime overrides.
            for index, test in enumerate(tests):
                row = {"test": test, "band": band, "status": "ERROR", "divergences": []}
                report["validation_results"].append(row)
                summary["skipped"] -= 1
                summary["errored"] += 1
                captures = {}
                deltas = {}
                # Release each pair before the next test: disk use must not
                # grow as number_of_tests * project_size.
                with tempfile.TemporaryDirectory(prefix=f"case-{index}-", dir=root) as case_dir:
                    for leg, entries, template in (("baseline", baseline_entries, baseline),
                                                   ("migration", migration_entries, migration)):
                        workspace = Path(case_dir) / leg
                        stage_project(entries, workspace, deadline)
                        if not (workspace / test).is_file():
                            raise ValueError(f"{leg} project is missing test {test}")
                        command = [f"./{test}" if arg == "{test}" else arg for arg in template]
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("total validation budget exhausted")
                        captures[leg] = run_command(command, workspace,
                                                    timeout=min(timeout_seconds, remaining),
                                                    max_output_bytes=max_output_bytes,
                                                    environment=environment)
                        # Keep completed-leg evidence even if the other leg
                        # encounters an infrastructure failure or total timeout.
                        row[leg] = {k: v for k, v in captures[leg].items() if k not in {"stdout", "stderr"}}
                        if compare_filesystem:
                            final_entries, _ = capture_project(workspace, deadline)
                            deltas[leg] = workspace_delta(entries, final_entries)
                            row[leg]["workspace_delta"] = summarize_delta(deltas[leg])
                for leg, capture in captures.items():
                    if capture["termination"] != "exited" or capture["exit_code"] != 0:
                        row["divergences"].append({"channel": leg, "reason": capture["termination"],
                                                   "exit_code": capture["exit_code"]})
                for channel in ("stdout", "stderr"):
                    if captures["baseline"][channel] != captures["migration"][channel]:
                        row["divergences"].append({"channel": channel, "reason": "byte_mismatch"})
                if compare_filesystem and deltas["baseline"] != deltas["migration"]:
                    row["divergences"].append({"channel": "filesystem", "reason": "workspace_delta_mismatch"})
                row["severity"] = classify_divergence_severity(row["divergences"], band)
                row["status"] = "FAIL" if row["divergences"] else "PASS"
                summary["passed" if row["status"] == "PASS" else "failed"] += 1
                summary["errored"] -= 1
            summary["verdict"] = "FAIL" if summary["failed"] else "PASS"
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
        summary["verdict"] = "ERROR"
    return report


def write_report(report: dict, destination: Path) -> None:
    """Atomically publish a private report; never leave half-written JSON."""
    payload = (json.dumps(report, indent=2, allow_nan=False) + "\n").encode("utf-8")
    # The operator explicitly chooses the destination. A failed write leaves
    # any previous report untouched; the temporary file contains no raw output.
    with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", dir=destination.parent,
                                     delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def check_primary_implementation_cited() -> dict:
    check = {"id": "VALIDATE-IMPL", "status": "PASS", "details": {
        "paths": PRIMARY_IMPLEMENTATION_PATHS, "existing_paths": {}, "contract_citations": {}}}
    contract = CONTRACT_PATH.read_text(encoding="utf-8") if CONTRACT_PATH.exists() else ""
    missing = []
    uncited = []
    for name, path in PRIMARY_IMPLEMENTATION_PATHS.items():
        check["details"]["existing_paths"][name] = (ROOT / path).exists()
        check["details"]["contract_citations"][name] = path in contract
        if not (ROOT / path).exists():
            missing.append(path)
        if path not in contract:
            uncited.append(path)
    if missing or uncited:
        check["status"] = "FAIL"
        check["details"].update(missing_paths=missing, missing_contract_citations=uncited)
    return check


def self_test() -> dict:
    checks = [check_primary_implementation_cited()]
    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary)
        (project / "app.test.js").write_text("test('x', () => {});", encoding="utf-8")
        (project / "lib.spec.ts").write_text("describe('y', () => {});", encoding="utf-8")
        (project / "util.js").write_text("module.exports = {};", encoding="utf-8")
        found = len(discover_tests(project))
    checks.append({"id": "VALIDATE-DISCOVERY", "status": "PASS" if found == 2 else "FAIL",
                   "details": {"found": found}})
    canon = canonicalize_output("Error at 2024-01-15T10:30:00 pid=12345 /home/user/project/file.js")
    canonical = all(part in canon for part in ("<TIMESTAMP>", "pid=<PID>", "<ABS_PATH>"))
    checks.extend([
        {"id": "VALIDATE-CANONICAL", "status": "PASS" if canonical else "FAIL"},
        {"id": "VALIDATE-COMPARE-SAME", "status": "PASS" if compare_outputs("hello\nworld", "hello\nworld")["identical"] else "FAIL"},
        {"id": "VALIDATE-COMPARE-DIFF", "status": "PASS" if compare_outputs("hello\nworld", "hello\nearth")["divergence_count"] == 1 else "FAIL"},
        {"id": "VALIDATE-SEVERITY", "status": "PASS" if classify_divergence_severity([{}], "core") == "critical" else "FAIL"},
    ])
    # A green self-test must exercise the executor, not just inspect strings.
    # Python is an explicitly named command here, not a fake Node/Franken binary.
    with tempfile.TemporaryDirectory(prefix="migration-self-test-") as temporary:
        project = Path(temporary)
        before, after = project / "before", project / "after"
        before.mkdir()
        after.mkdir()
        (before / "probe.test.js").write_text("print('reference')\n", encoding="utf-8")
        (after / "probe.test.js").write_text("print('candidate')\n", encoding="utf-8")
        execution = validate_project(before, migrated_project=after,
                                     baseline_command=[sys.executable, "{test}"],
                                     migration_command=[sys.executable, "{test}"])
        detected = (execution["summary"]["verdict"] == "FAIL"
                    and execution["summary"]["failed"] == 1
                    and execution["validation_results"][0]["baseline"]["exit_code"] == 0
                    and execution["validation_results"][0]["migration"]["exit_code"] == 0)
        checks.append({"id": "VALIDATE-LIVE-DIVERGENCE", "status": "PASS" if detected else "FAIL"})
    failing = sum(check["status"] == "FAIL" for check in checks)
    return {"gate": "migration_validation_verification", "section": "10.3",
            "verdict": "FAIL" if failing else "PASS", "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_paths": EVIDENCE_PATHS, "verification_commands": VERIFICATION_COMMANDS,
            "checks": checks, "summary": {"total_checks": len(checks), "passing_checks": len(checks) - failing,
                                           "failing_checks": failing}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", nargs="?", type=Path)
    parser.add_argument("--migrated-project", type=Path, help="post-rewrite tree (default: same input)")
    parser.add_argument("--baseline-command", type=json.loads, default=list(DEFAULT_BASELINE_COMMAND),
                        help='JSON argv, e.g. ["node", "--test", "{test}"]')
    parser.add_argument("--migration-command", type=json.loads, default=list(DEFAULT_MIGRATION_COMMAND),
                        help='JSON argv, e.g. ["franken-node", "run", "--console-only", "{test}"]')
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--total-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--max-output-bytes", type=int, default=1_048_576)
    parser.add_argument("--band", choices=("core", "high-value", "edge"), default="core")
    parser.add_argument("--out", type=Path, help="atomically write the JSON validation report")
    parser.add_argument("--compare-filesystem", action="store_true",
                        help="also compare persistent workspace file/link/mode changes; .git excluded")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test and args.project_dir is None:
        parser.error("project_dir is required unless --self-test is used")
    if args.self_test:
        result = self_test()
        verdict = result["verdict"]
    else:
        result = validate_project(args.project_dir, migrated_project=args.migrated_project,
                                  baseline_command=args.baseline_command, migration_command=args.migration_command,
                                  timeout_seconds=args.timeout_seconds, total_timeout_seconds=args.total_timeout_seconds,
                                  max_output_bytes=args.max_output_bytes, band=args.band,
                                  compare_filesystem=args.compare_filesystem)
        verdict = result["summary"]["verdict"]
    if args.out is not None:
        try:
            write_report(result, args.out)
        except OSError as error:
            print(f"cannot write validation report: {error}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result, indent=2, allow_nan=False))
    else:
        print(f"Verdict: {verdict}")
        print(json.dumps(result["summary"], indent=2))
        for error in result.get("errors", []):
            print(error["message"], file=sys.stderr)
        for row in result.get("validation_results", []):
            if row["status"] != "PASS":
                print(f"FAIL {row['test']}: {json.dumps(row['divergences'])}")
    return 0 if verdict == "PASS" else 1 if verdict == "FAIL" else 2


if __name__ == "__main__":
    sys.exit(main())
