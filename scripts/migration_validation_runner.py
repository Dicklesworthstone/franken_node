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
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
from contextlib import contextmanager
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
MAX_INPUT_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MIGRATION_TEST_MANIFEST = ".franken-node/migration-tests.json"
MIGRATION_TEST_SCHEMA = "franken-node/migration-tests/v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TEST_PATH_BYTES = 4096
REPLAY_BUNDLE_SCHEMA = "franken-node/migration-replay/v1"
MAX_REPLAY_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_REPLAY_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_REPLAY_OBJECTS = 60_000
TEST_EXTENSIONS = frozenset({"js", "mjs", "cjs", "ts", "mts", "cts"})
DISCOVERY_EXCLUSIONS = frozenset({"node_modules", ".git", ".migrate-backup", ".franken-node"})
EXECUTION_EXCLUSIONS = DISCOVERY_EXCLUSIONS | {".beads", ".franken-rewrite"}
PRIVATE_RUNTIME_VARIABLES = (
    "FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK", "FRANKEN_NODE_MIGRATION_FAILURE_DIR",
)


class ExecutionCancelled(RuntimeError):
    """A latched operator cancellation, never a compatibility divergence."""


@dataclass
class CancellationState:
    """Per-invocation cancellation; library calls do not install signal handlers."""

    signum: int | None = None

    def request(self, signum: int, _frame=None) -> None:
        # Signal handlers must not raise, perform I/O, or interrupt Popen/cleanup.
        # The first signal determines attribution even when subsequent signals
        # arrive while the owned process group is being terminated and reaped.
        if self.signum is None:
            self.signum = signum

    def check(self) -> None:
        if self.signum is not None:
            raise ExecutionCancelled(f"execution cancelled by signal {self.signum}")


@contextmanager
def termination_signals(cancellation: CancellationState):
    """CLI-only signal ownership, restored even after an exception."""
    previous = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, cancellation.request)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def check_cancellation(cancellation: CancellationState | None) -> None:
    if cancellation is not None:
        cancellation.check()


def record_cancellation(report: dict, cancellation: CancellationState | None) -> None:
    """Preserve completed observations but never turn an interrupted suite green."""
    if cancellation is not None and cancellation.signum is not None:
        report["cancellation"] = {"signal": cancellation.signum, "requested": True}
        if "summary" in report:
            report["summary"]["verdict"] = "ERROR"
        if "replay_outcome" in report:
            report["replay_outcome"] = "ERROR"
        if not any(error.get("type") == "ExecutionCancelled" for error in report.get("errors", [])):
            report.setdefault("errors", []).append({"type": "ExecutionCancelled",
                "message": f"execution cancelled by signal {cancellation.signum}"})


def raise_walk_error(error: OSError) -> None:
    """An unreadable subtree must never silently shrink the measured input."""
    raise error


def _is_discovered_test(name: str) -> bool:
    path = Path(name)
    extension = path.suffix.removeprefix(".")
    return (not (set(path.parts) & DISCOVERY_EXCLUSIONS)
            and extension in TEST_EXTENSIONS
            and (path.name.endswith((f".test.{extension}", f".spec.{extension}"))
                 or bool(set(path.parts[:-1]) & {"test", "__tests__"})))


def discover_tests(project_dir: Path) -> list[Path]:
    """Select tests from a bounded capture, including an explicit manifest.

    Invalid explicit inventories never fall back to heuristic discovery.
    Validation itself reuses its existing capture instead of recapturing here.
    """
    root = Path(project_dir).resolve(strict=True)
    entries, _ = capture_project(root, time.monotonic() + 300.0)
    return [root / name for name in captured_test_inventory(entries)]


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


@dataclass(frozen=True, repr=False)
class ExecutionSettings:
    """Captured application inputs, never a shell or a runtime selection."""

    cwd: str = ""
    stdin: str | None = None
    environment: tuple[tuple[str, str | None], ...] = ()

    def __repr__(self) -> str:
        # Environment values can be secrets. Do not include them in errors.
        return (f"ExecutionSettings(cwd={self.cwd!r}, stdin={self.stdin!r}, "
                f"environment_count={len(self.environment)})")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate migration test manifest key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite migration test manifest value")


def _utf8_size(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("migration test settings must contain valid Unicode") from None


def _canonical_test_path(name: object, excluded=DISCOVERY_EXCLUSIONS) -> str:
    if (not isinstance(name, str) or not name or _utf8_size(name) > MAX_TEST_PATH_BYTES
            or "\\" in name or any(unicodedata.category(char) == "Cc" for char in name)
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ValueError("migration test paths must be canonical project-relative paths")
    if set(name.split("/")) & excluded:
        raise ValueError("migration test paths cannot select dependencies, backups or reserved state")
    return name


def _ordinary_parents(entries: dict[str, SnapshotEntry], name: str) -> None:
    parts = name.split("/")
    for length in range(1, len(parts)):
        entry = entries.get("/".join(parts[:length]))
        if entry is None or entry.link is not None or entry.data is not None:
            raise ValueError("execution paths must have ordinary captured directory parents")


def _ordinary_file(entries: dict[str, SnapshotEntry], name: str) -> bytes:
    _ordinary_parents(entries, name)
    entry = entries.get(name)
    if entry is None or entry.link is not None or entry.data is None:
        raise ValueError("migration test input must be an ordinary captured file")
    return entry.data


def _application_variable(name: str) -> bool:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
        return False
    if name == "NODE_ENV":
        return True
    upper = name.upper()
    return (not upper.startswith(("NODE_", "BUN_", "FRANKEN_", "LD_", "DYLD_", "RUST_", "CARGO_", "NPM_"))
            and upper not in {"PATH", "HOME", "PWD", "OLDPWD", "TMPDIR", "TMP", "TEMP", "SHELL",
                              "ENV", "BASH_ENV", "IFS", "CDPATH", "GCONV_PATH"})


def _execution_settings(raw: object, entries: dict[str, SnapshotEntry], test: str) -> ExecutionSettings:
    if not isinstance(raw, dict) or set(raw) - {"cwd", "stdin", "environment"}:
        raise ValueError("invalid or unknown migration test execution settings")
    cwd = raw.get("cwd")
    if cwd in (None, "."):
        cwd = ""
    else:
        cwd = _canonical_test_path(cwd, EXECUTION_EXCLUSIONS)
        _ordinary_parents(entries, cwd)
        entry = entries.get(cwd)
        if entry is None or entry.data is not None or entry.link is not None:
            raise ValueError("test working directory must be an ordinary captured directory")
    if cwd and not test.startswith(cwd + "/"):
        raise ValueError("test entrypoint must be inside its working directory")
    stdin = raw.get("stdin")
    if stdin is not None:
        stdin = _canonical_test_path(stdin, EXECUTION_EXCLUSIONS)
        if len(_ordinary_file(entries, stdin)) > MAX_INPUT_BYTES:
            raise ValueError("captured test stdin exceeds 1 MiB")
    environment = raw.get("environment", {})
    if not isinstance(environment, dict) or len(environment) > 64:
        raise ValueError("at most 64 application environment overrides per test")
    size = 0
    for name, value in environment.items():
        if not _application_variable(name):
            raise ValueError("test environment cannot override runtime, loader or operator controls")
        if value is not None and (not isinstance(value, str) or "\0" in value or _utf8_size(value) > 4096):
            raise ValueError("test environment value must be a string of at most 4096 bytes without NUL, or null")
        size += len(name) + (0 if value is None else _utf8_size(value))
    if size > 16 * 1024:
        raise ValueError("test environment exceeds 16 KiB")
    return ExecutionSettings(cwd, stdin, tuple(sorted(environment.items())))


def captured_test_inventory(capture: list[SnapshotEntry]) -> dict[str, ExecutionSettings]:
    """Interpret only immutable captured bytes; never read live project files."""
    entries = {entry.path: entry for entry in capture}
    if len(entries) != len(capture):
        raise ValueError("duplicate captured project path")
    config = entries.get(".franken-node")
    if config is not None and config.link is not None:
        raise ValueError("migration test configuration directory must not be a symlink")
    manifest = entries.get(MIGRATION_TEST_MANIFEST)
    if manifest is None:
        tests = {entry.path: ExecutionSettings() for entry in capture
                 if (entry.data is not None or entry.link is not None) and _is_discovered_test(entry.path)}
        if len(tests) > MAX_TEST_FILES:
            raise ValueError(f"test discovery exceeds {MAX_TEST_FILES} files")
        return dict(sorted(tests.items()))
    contents = _ordinary_file(entries, MIGRATION_TEST_MANIFEST)
    if len(contents) > MAX_MANIFEST_BYTES:
        raise ValueError("migration test manifest exceeds the 64 KiB limit")
    try:
        raw = json.loads(contents.decode("utf-8"), object_pairs_hook=_unique_json_object,
                         parse_constant=_reject_json_constant)
    except (ValueError, RecursionError):
        raise ValueError("invalid migration test manifest") from None
    if (not isinstance(raw, dict) or set(raw) - {"schema_version", "tests", "execution"}
            or raw.get("schema_version") != MIGRATION_TEST_SCHEMA):
        raise ValueError("unsupported migration test manifest schema or fields")
    names = raw.get("tests")
    if not isinstance(names, list) or not 0 < len(names) <= MAX_TEST_FILES:
        raise ValueError("explicit migration test inventory must contain 1 to 1024 tests")
    tests = {}
    for name in names:
        name = _canonical_test_path(name)
        if Path(name).suffix.removeprefix(".") not in TEST_EXTENSIONS:
            raise ValueError("migration test manifest requires a standalone JS/TS entrypoint")
        _ordinary_file(entries, name)
        if name in tests:
            raise ValueError("duplicate migration test entrypoint")
        tests[name] = ExecutionSettings()
    overrides = raw.get("execution", {})
    if not isinstance(overrides, dict):
        raise ValueError("migration test execution must be an object")
    for name, value in overrides.items():
        _canonical_test_path(name)
        if name not in tests:
            raise ValueError("execution settings refer to an unselected test")
        tests[name] = _execution_settings(value, entries, name)
    return dict(sorted(tests.items()))


def _test_input(settings: ExecutionSettings, entries: dict[str, SnapshotEntry]) -> bytes | None:
    return None if settings.stdin is None else _ordinary_file(entries, settings.stdin)


def matched_test_execution(baseline: dict[str, ExecutionSettings], migration: dict[str, ExecutionSettings],
                           baseline_entries: dict[str, SnapshotEntry],
                           migration_entries: dict[str, SnapshotEntry]) -> None:
    if baseline != migration:
        raise ValueError("test execution settings differ between original and candidate")
    for name, settings in baseline.items():
        if _test_input(settings, baseline_entries) != _test_input(migration[name], migration_entries):
            raise ValueError("captured test stdin bytes differ between original and candidate")


def _test_environment(base: dict[str, str], settings: ExecutionSettings) -> dict[str, str]:
    environment = dict(base)
    for name, value in settings.environment:
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    for name in PRIVATE_RUNTIME_VARIABLES:
        environment.pop(name, None)
    return environment


def _file_version(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mode,
            metadata.st_nlink, metadata.st_mtime_ns, metadata.st_ctime_ns)


def snapshot_digest(entries: list[SnapshotEntry]) -> str:
    """The same length-framed input identity for live and recovered captures."""
    digest = hashlib.sha256(b"franken-migration-input-v1\0")
    for entry in entries:
        for part in (entry.path.encode(), str(entry.mode).encode(),
                     b"link" if entry.link is not None else b"dir" if entry.data is None else b"file",
                     entry.link.encode() if entry.link is not None else entry.data or b""):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def environment_digest(environment: dict[str, str]) -> str:
    """Bind effective environment bytes without exporting inherited secrets."""
    digest = hashlib.sha256(b"franken-migration-environment-v1\0")
    for name, value in sorted(environment.items()):
        for part in (os.fsencode(name), os.fsencode(value)):
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
    return digest.hexdigest()


def _bundle_destination(destination: Path, projects: tuple[Path, ...]) -> Path:
    destination = Path(os.path.abspath(destination))
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir() or os.path.lexists(destination):
        raise ValueError("replay bundle requires a new file in an existing directory")
    destination = parent / destination.name
    if any(destination.is_relative_to(project) for project in projects):
        raise ValueError("replay bundle must be outside both measured projects")
    return destination


class ReplayBundleWriter:
    """Opt-in, bounded capture of the actual inputs and retained process bytes.

    Objects are spooled once by SHA-256, not held again in memory. Publication
    is private, no-clobber and atomic. Bundles deliberately exclude the inherited
    environment and executable binaries; a hash is not a signing certificate.
    """

    def __init__(self, destination: Path, baseline: list[SnapshotEntry],
                 migration: list[SnapshotEntry], environments: dict[str, str]):
        self.destination = destination
        self.objects: dict[str, tuple[int, int]] = {}
        self.observations: list[dict] = []
        self.environments = environments
        self.byte_count = 0
        self.failed = False
        self.spool = tempfile.TemporaryFile(dir=destination.parent)
        try:
            self.snapshots = {"baseline": self._snapshot(baseline),
                              "migration": self._snapshot(migration)}
            _validate_snapshot_links({entry.path: entry for entry in baseline})
            _validate_snapshot_links({entry.path: entry for entry in migration})
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self.spool.close()

    def _store(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.objects:
            return digest
        count = len(self.objects) + 1
        # Reserve space for the manifest and both ZIP headers for each object.
        if (count > MAX_REPLAY_OBJECTS
                or self.byte_count + len(data) + MAX_REPLAY_MANIFEST_BYTES + 256 * count
                > MAX_REPLAY_BUNDLE_BYTES):
            raise ValueError("replay bundle exceeds its bounded object/byte budget")
        self.spool.seek(self.byte_count)
        self.spool.write(data)
        self.objects[digest] = (self.byte_count, len(data))
        self.byte_count += len(data)
        return digest

    def _snapshot(self, entries: list[SnapshotEntry]) -> list[dict]:
        captured = []
        for entry in entries:
            _canonical_test_path(entry.path, {".git"})
            item = {"path": entry.path, "mode": entry.mode}
            if entry.link is not None:
                item.update(kind="link", target=_relative_link_target(entry.link))
            elif entry.data is None:
                item.update(kind="directory")
            else:
                item.update(kind="file", blob=self._store(entry.data))
            captured.append(item)
        return captured

    def record(self, test: str, leg: str, capture: dict) -> None:
        try:
            self.observations.append({"test": test, "leg": leg,
                                      "stdout": self._store(capture["stdout"]),
                                      "stderr": self._store(capture["stderr"])})
        except (OSError, ValueError):
            # Do not publish a success-shaped archive with an unrecorded leg
            # or an orphaned object after exhausting the capture budget.
            self.failed = True
            raise

    @staticmethod
    def _member(name: str) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o600) << 16
        return info

    def publish(self, report: dict) -> dict:
        if self.failed:
            raise ValueError("replay output capture is incomplete; bundle not published")
        manifest = {"schema_version": REPLAY_BUNDLE_SCHEMA, "report": report,
                    "snapshots": self.snapshots, "observations": self.observations,
                    "environment_sha256": self.environments,
                    "objects": {digest: size for digest, (_, size) in sorted(self.objects.items())}}
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(payload) > MAX_REPLAY_MANIFEST_BYTES:
            raise ValueError("replay bundle manifest exceeds 16 MiB")
        # Link publishes a completed inode without overwriting a concurrent
        # creator, unlike replace(). The temporary inode is private (0600).
        with tempfile.NamedTemporaryFile(prefix=".franken-replay-", dir=self.destination.parent) as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
                archive.writestr(self._member("manifest.json"), payload)
                for digest, (offset, size) in sorted(self.objects.items()):
                    self.spool.seek(offset)
                    with archive.open(self._member(f"objects/{digest}"), "w") as member:
                        remaining = size
                        while remaining:
                            chunk = self.spool.read(min(65536, remaining))
                            if not chunk:
                                raise OSError("incomplete replay object spool")
                            member.write(chunk)
                            remaining -= len(chunk)
            stream.flush()
            size = stream.tell()
            if size > MAX_REPLAY_BUNDLE_BYTES:
                raise ValueError("replay bundle exceeds 512 MiB")
            os.fsync(stream.fileno())
            stream.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
            os.link(stream.name, self.destination)
            directory_fd = os.open(self.destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return {"path": str(self.destination), "schema_version": REPLAY_BUNDLE_SCHEMA,
                "sha256": digest.hexdigest(), "bytes": size,
                "contains_raw_project_and_process_bytes": True,
                "authenticated": False, "ambient_effects_replayable": False}


@dataclass
class ReplayBundle:
    manifest: dict
    objects: dict[str, bytes]
    snapshots: dict[str, list[SnapshotEntry]]
    sha256: str


def _digest_string(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _bundle_keys(value, keys: set[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"invalid replay {context} fields")


def _relative_link_target(target) -> str:
    if (not isinstance(target, str) or not target or target.startswith("/")
            or "\\" in target or _utf8_size(target) > MAX_TEST_PATH_BYTES
            or any(unicodedata.category(char) == "Cc" for char in target)):
        raise ValueError("invalid replay symlink target")
    return target


def _validate_snapshot_links(entries: dict[str, SnapshotEntry]) -> None:
    """Resolve captured links without consulting or touching the host filesystem."""
    for entry in entries.values():
        if entry.link is None:
            continue
        pending = entry.path.split("/")[:-1] + entry.link.split("/")
        resolved: list[str] = []
        expansions = 0
        while pending:
            component, pending = pending[0], pending[1:]
            if component in {"", "."}:
                continue
            if component == "..":
                if not resolved:
                    raise ValueError("replay symlink escapes its project")
                resolved.pop()
                continue
            if component == ".git":
                raise ValueError("replay symlink enters excluded .git state")
            name = "/".join([*resolved, component])
            target = entries.get(name)
            if target is None:
                raise ValueError("replay symlink target is missing")
            if target.link is not None:
                expansions += 1
                if expansions > 40:
                    raise ValueError("replay symlink cycle or excessive expansion")
                pending = target.link.split("/") + pending
                continue
            if pending and target.data is not None:
                raise ValueError("replay symlink traverses a non-directory")
            resolved.append(component)


def _decode_snapshot(raw, objects: dict[str, bytes], used: set[str]) -> list[SnapshotEntry]:
    if not isinstance(raw, list) or len(raw) > MAX_PROJECT_FILES:
        raise ValueError("replay snapshot exceeds its entry budget")
    entries: dict[str, SnapshotEntry] = {}
    total = 0
    for item in raw:
        if not isinstance(item, dict) or item.get("kind") not in {"file", "directory", "link"}:
            raise ValueError("invalid replay snapshot entry kind")
        kind = item["kind"]
        _bundle_keys(item, {"path", "mode", "kind"} | ({"blob"} if kind == "file"
                     else {"target"} if kind == "link" else set()), "snapshot entry")
        name = _canonical_test_path(item["path"], {".git"})
        if name in entries or type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o777:
            raise ValueError("duplicate replay path or invalid file mode")
        _ordinary_parents(entries, name)
        data = None
        target = None
        if kind == "file":
            digest = item["blob"]
            if not _digest_string(digest) or digest not in objects:
                raise ValueError("missing replay file object")
            data = objects[digest]
            total += len(data)
            if total > MAX_PROJECT_BYTES:
                raise ValueError("replay snapshot exceeds its byte budget")
            used.add(digest)
        elif kind == "link":
            target = _relative_link_target(item["target"])
        entries[name] = SnapshotEntry(path=name, mode=item["mode"], data=data, link=target)
    _validate_snapshot_links(entries)
    return list(entries.values())


def _validate_bundle_manifest(manifest: dict, objects: dict[str, bytes]) -> dict[str, list[SnapshotEntry]]:
    _bundle_keys(manifest, {"schema_version", "report", "snapshots", "observations",
                           "environment_sha256", "objects"}, "manifest")
    if manifest["schema_version"] != REPLAY_BUNDLE_SCHEMA:
        raise ValueError("unsupported replay bundle schema")
    _bundle_keys(manifest["snapshots"], {"baseline", "migration"}, "snapshots")
    used: set[str] = set()
    snapshots = {role: _decode_snapshot(raw, objects, used)
                 for role, raw in manifest["snapshots"].items()}
    report = manifest["report"]
    if (not isinstance(report, dict) or report.get("schema_version") != "migration-validation-v1"
            or not isinstance(report.get("inputs"), dict)):
        raise ValueError("invalid replay report")
    inventories = {role: captured_test_inventory(entries) for role, entries in snapshots.items()}
    matched_test_execution(inventories["baseline"], inventories["migration"],
        {entry.path: entry for entry in snapshots["baseline"]},
        {entry.path: entry for entry in snapshots["migration"]})
    tests = list(inventories["baseline"])
    if not tests or report.get("test_discovery", {}).get("test_files") != tests:
        raise ValueError("replay test inventory does not match captured inputs")
    summary = report.get("summary")
    counters = {"total_tests", "passed", "failed", "skipped", "errored"}
    _bundle_keys(summary, counters | {"verdict"}, "summary")
    if (any(type(summary[name]) is not int or not 0 <= summary[name] <= MAX_TEST_FILES for name in counters)
            or summary["total_tests"] != len(tests)
            or summary["verdict"] not in {"PASS", "FAIL", "ERROR"}
            or sum(summary[name] for name in counters - {"total_tests"}) != len(tests)):
        raise ValueError("invalid replay summary accounting")
    environments = manifest["environment_sha256"]
    if (not isinstance(environments, dict) or set(environments) != set(tests)
            or not all(_digest_string(value) for value in environments.values())):
        raise ValueError("invalid replay environment identities")
    for role, entries in snapshots.items():
        if snapshot_digest(entries) != report["inputs"].get(f"{role}_sha256"):
            raise ValueError("replay snapshot identity mismatch")
    rows = report.get("validation_results")
    if not isinstance(rows, list) or len(rows) > len(tests):
        raise ValueError("invalid replay observation rows")
    expected: dict[tuple[str, str], dict] = {}
    seen_tests: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("test"), str):
            raise ValueError("invalid replay test row")
        name = row["test"]
        if (name not in inventories["baseline"] or name in seen_tests
                or row.get("status") not in {"PASS", "FAIL", "ERROR"}
                or row.get("band") not in {"core", "high-value", "edge"}):
            raise ValueError("duplicate or unselected replay test row")
        seen_tests.add(name)
        for role in ("baseline", "migration"):
            if role in row:
                expected[name, role] = row[role]
    if (summary["skipped"] != len(tests) - len(rows)
            or any(summary[counter] != sum(row["status"] == status for row in rows)
                   for counter, status in (("passed", "PASS"), ("failed", "FAIL"), ("errored", "ERROR")))):
        raise ValueError("replay summary disagrees with recorded test outcomes")
    observations = manifest["observations"]
    if not isinstance(observations, list) or len(observations) != len(expected):
        raise ValueError("replay output inventory is incomplete")
    seen: set[tuple[str, str]] = set()
    for observation in observations:
        _bundle_keys(observation, {"test", "leg", "stdout", "stderr"}, "output")
        if not isinstance(observation["test"], str) or not isinstance(observation["leg"], str):
            raise ValueError("invalid replay output selector")
        key = observation["test"], observation["leg"]
        if key not in expected or key in seen:
            raise ValueError("duplicate or unexpected replay output")
        seen.add(key)
        capture = expected[key]
        if (not isinstance(capture, dict) or type(capture.get("exit_code")) is not int
                or capture.get("termination") not in {"exited", "signal", "timeout", "output_limit", "cancelled"}):
            raise ValueError("invalid replay process outcome")
        streams = capture.get("streams")
        _bundle_keys(streams, {"stdout", "stderr"}, "streams")
        for channel in ("stdout", "stderr"):
            digest = observation[channel]
            if not _digest_string(digest) or digest not in objects:
                raise ValueError("missing replay output object")
            used.add(digest)
            stream = streams[channel]
            _bundle_keys(stream, {"bytes_observed", "retained_bytes", "sha256", "complete"}, "stream")
            if (type(stream["retained_bytes"]) is not int or type(stream["bytes_observed"]) is not int
                    or type(stream["complete"]) is not bool or not _digest_string(stream["sha256"])
                    or not 0 <= stream["retained_bytes"] <= stream["bytes_observed"]
                    or stream["retained_bytes"] != len(objects[digest])
                    or len(objects[digest]) > MAX_OUTPUT_BYTES):
                raise ValueError("invalid replay stream accounting")
            if stream["complete"] and (stream["sha256"] != digest
                                        or stream["bytes_observed"] != len(objects[digest])):
                raise ValueError("complete replay stream digest mismatch")
    if used != set(objects):
        raise ValueError("replay archive contains unreferenced objects")
    return snapshots


def read_replay_bundle(path: Path, *, expected_sha256: str | None = None) -> ReplayBundle:
    """Bound and verify every byte and path before anything can be staged.

    No extractall(), imports, commands or guest execution occur in this reader.
    An external expected digest is mandatory for replay, optional for inspection.
    """
    if expected_sha256 is not None and not _digest_string(expected_sha256):
        raise ValueError("expected replay SHA-256 must be 64 lowercase hexadecimal characters")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 22 <= before.st_size <= MAX_REPLAY_BUNDLE_BYTES:
            raise ValueError("replay bundle is not a bounded regular archive")
        # Bound ZipFile's central-directory allocation before it parses entries.
        stream.seek(-22, os.SEEK_END)
        sig, disk, directory_disk, disk_count, count, directory_bytes, offset, comment = struct.unpack(
            "<4s4H2LH", stream.read(22))
        if (sig != b"PK\x05\x06" or disk or directory_disk or comment or disk_count != count
                or not 1 <= count <= MAX_REPLAY_OBJECTS + 1 or count == 65535
                or directory_bytes > MAX_REPLAY_MANIFEST_BYTES
                or offset + directory_bytes != before.st_size - 22):
            raise ValueError("invalid or over-budget replay ZIP directory")
        stream.seek(0)
        measured = hashlib.sha256()
        remaining = before.st_size
        deadline = time.monotonic() + 30
        while remaining:
            if time.monotonic() >= deadline:
                raise TimeoutError("replay archive verification deadline exceeded")
            chunk = stream.read(min(65536, remaining))
            if not chunk:
                raise ValueError("replay archive shrank during verification")
            measured.update(chunk)
            remaining -= len(chunk)
        digest = measured.hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise ValueError("replay bundle SHA-256 does not match the caller's trusted digest")
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) != count:
                raise ValueError("replay ZIP entry count mismatch")
            names: set[str] = set()
            total = 0
            for member in members:
                name = member.filename
                if (name in names or (name != "manifest.json" and
                        (not name.startswith("objects/") or not _digest_string(name[8:])))
                        or member.compress_type != zipfile.ZIP_STORED or member.flag_bits & 1
                        or member.compress_size != member.file_size):
                    raise ValueError("invalid, duplicate or compressed replay ZIP member")
                names.add(name)
                total += member.file_size
                if total > MAX_REPLAY_BUNDLE_BYTES:
                    raise ValueError("replay ZIP exceeds its uncompressed byte budget")
            if "manifest.json" not in names or archive.getinfo("manifest.json").file_size > MAX_REPLAY_MANIFEST_BYTES:
                raise ValueError("missing or oversized replay manifest")
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"),
                                  object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
            if not isinstance(manifest, dict) or not isinstance(manifest.get("objects"), dict):
                raise ValueError("invalid replay object index")
            index = manifest["objects"]
            if len(index) > MAX_REPLAY_OBJECTS or names != {"manifest.json"} | {f"objects/{name}" for name in index}:
                raise ValueError("replay object inventory mismatch")
            objects: dict[str, bytes] = {}
            for name, size in index.items():
                if time.monotonic() >= deadline:
                    raise TimeoutError("replay archive verification deadline exceeded")
                if (not _digest_string(name) or type(size) is not int or not 0 <= size <= MAX_PROJECT_BYTES
                        or archive.getinfo(f"objects/{name}").file_size != size):
                    raise ValueError("invalid replay object size or identity")
                data = archive.read(f"objects/{name}")
                if hashlib.sha256(data).hexdigest() != name:
                    raise ValueError("replay object content hash mismatch")
                objects[name] = data
        if (_file_version(before) != _file_version(os.fstat(stream.fileno()))
                or _file_version(before) != _file_version(Path(path).lstat())):
            raise ValueError("replay archive changed during verification")
    try:
        snapshots = _validate_bundle_manifest(manifest, objects)
    except (KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        raise ValueError("malformed replay manifest") from error
    return ReplayBundle(manifest=manifest, objects=objects, snapshots=snapshots, sha256=digest)


def _runtime_measurements(identities: dict) -> dict:
    _bundle_keys(identities, {"baseline", "migration"}, "runtime identities")
    measured = {}
    for role, identity in identities.items():
        _bundle_keys(identity, {"executable", "sha256", "bytes", "mode"}, "runtime identity")
        if (not isinstance(identity["executable"], str) or not _digest_string(identity["sha256"])
                or type(identity["bytes"]) is not int or not 0 < identity["bytes"] <= MAX_EXECUTABLE_BYTES
                or type(identity["mode"]) is not int or not 0 <= identity["mode"] <= 0o777):
            raise ValueError("invalid replay runtime measurement")
        measured[role] = {name: identity[name] for name in ("sha256", "bytes", "mode")}
    return measured


def _observation_projection(report: dict) -> dict:
    """Exclude timestamps, relocated paths and elapsed time, not observed bytes."""
    rows = []
    for row in report["validation_results"]:
        value = {name: row[name] for name in ("test", "band", "status", "divergences")}
        for role in ("baseline", "migration"):
            capture = row[role]
            value[role] = {name: capture[name] for name in ("exit_code", "termination", "streams")}
            if report["filesystem_comparison"]:
                value[role]["workspace_delta"] = capture["workspace_delta"]
        rows.append(value)
    return {"summary": report["summary"], "rows": rows}


def replay_captured_bundle(path: Path, *, expected_sha256: str,
                           baseline_command, migration_command,
                           cancellation: CancellationState | None = None) -> dict:
    """Re-execute verified captures with explicit operator-selected executables.

    Reproducing a failure is distinct from passing compatibility. This never
    launches a command merely because that command is stored in an archive.
    """
    outcome = {"schema_version": "franken-node/migration-reexecution/v1", "phase": "reexecution",
               "replay_outcome": "ERROR", "errors": [], "release_certification": False,
               "ambient_effects_replayable": False}
    try:
        check_cancellation(cancellation)
        if not _digest_string(expected_sha256):
            raise ValueError("re-execution requires the bundle SHA-256 from a trusted original report")
        bundle = read_replay_bundle(path, expected_sha256=expected_sha256)
        check_cancellation(cancellation)
        original = bundle.manifest["report"]
        outcome.update(bundle_sha256=bundle.sha256, original_verdict=original["summary"]["verdict"])
        if (original["summary"]["verdict"] not in {"PASS", "FAIL"}
                or original.get("runtime_identity_rechecked") is not True
                or original.get("errors") != []
                or len(original["validation_results"]) != len(bundle.manifest["environment_sha256"])):
            raise ValueError("incomplete or runtime-unverified evidence can be inspected, not certified as reproduced")
        _runtime_measurements(original["runtime_identities"])
        templates = {"baseline": resolve_command(baseline_command),
                     "migration": resolve_command(migration_command)}
        _bundle_keys(original["commands"], {"baseline", "migration"}, "commands")
        for role, template in templates.items():
            recorded = original["commands"][role]
            if not isinstance(recorded, list) or not recorded or template[1:] != recorded[1:]:
                raise ValueError("replay command arguments differ from the recorded execution")
        limits = original["limits"]
        _bundle_keys(limits, {"per_leg_seconds", "total_seconds", "per_stream_bytes"}, "limits")
        if (any(type(limits[name]) not in {int, float} for name in ("per_leg_seconds", "total_seconds"))
                or type(original["filesystem_comparison"]) is not bool):
            raise ValueError("invalid replay execution limits or filesystem mode")
        # Validate all fields later used in the comparison before any guest runs.
        expected = _observation_projection(original)
        band = original["validation_results"][0]["band"]
        if any(row["band"] != band for row in original["validation_results"]):
            raise ValueError("inconsistent replay compatibility bands")
        with tempfile.TemporaryDirectory(prefix="franken-reexecute-") as temporary:
            root = Path(temporary)
            staging_deadline = time.monotonic() + 30
            for role in ("baseline", "migration"):
                stage_project(bundle.snapshots[role], root / role, staging_deadline, cancellation=cancellation)
            result = validate_project(root / "baseline", migrated_project=root / "migration",
                baseline_command=templates["baseline"], migration_command=templates["migration"],
                timeout_seconds=limits["per_leg_seconds"], total_timeout_seconds=limits["total_seconds"],
                max_output_bytes=limits["per_stream_bytes"], band=band,
                compare_filesystem=original["filesystem_comparison"],
                cancellation=cancellation,
                _replay_constraints={"inputs": original["inputs"],
                    "runtime_identities": original["runtime_identities"],
                    "environment_sha256": bundle.manifest["environment_sha256"]})
        outcome["execution"] = result
        if result["summary"]["verdict"] not in {"PASS", "FAIL"}:
            outcome["errors"] = result["errors"]
        else:
            matches = _observation_projection(result) == expected
            outcome.update(observations_match=matches, replay_outcome="REPRODUCED" if matches else "CHANGED")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, RecursionError,
            zipfile.BadZipFile, zipfile.LargeZipFile, subprocess.SubprocessError) as error:
        outcome["errors"].append({"type": type(error).__name__, "message": str(error)})
    record_cancellation(outcome, cancellation)
    return outcome


def inspect_replay_bundle(path: Path, *, expected_sha256: str | None = None) -> dict:
    """Return metadata only; inspection never executes or prints raw evidence."""
    bundle = read_replay_bundle(path, expected_sha256=expected_sha256)
    report = bundle.manifest["report"]
    return {"schema_version": REPLAY_BUNDLE_SCHEMA, "bundle_sha256": bundle.sha256,
            "integrity_verified": True, "matches_expected_digest": expected_sha256 is not None,
            "authenticated": False, "executable": False,
            "original_summary": report["summary"],
            "tests": report["test_discovery"]["test_files"],
            "snapshots": {role: {"entries": len(entries),
                           "sha256": report["inputs"][f"{role}_sha256"]}
                          for role, entries in bundle.snapshots.items()},
            "retained_streams": len(bundle.manifest["observations"]) * 2,
            "objects": len(bundle.objects)}


def capture_project(project: Path, deadline: float, *,
                    cancellation: CancellationState | None = None) -> tuple[list[SnapshotEntry], str]:
    """Capture bounded regular files and contained symlinks before either leg.

    Dependencies and project configuration are included; .git is excluded.
    Internal links are preserved (absolute internal links become relative).
    External links and special files are refused rather than touching targets
    outside the disposable workspace. This is not an atomic filesystem snapshot.
    """
    entries = []
    total = 0
    for directory, names, files in os.walk(project, followlinks=False, onerror=raise_walk_error):
        names[:] = sorted(n for n in names if n != ".git")
        for name in sorted(names + [name for name in files if name != ".git"]):
            check_cancellation(cancellation)
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
                if metadata.st_nlink != 1:
                    raise ValueError(f"hard-linked workspace files require explicit isolation: {relative}")
                if metadata.st_size > MAX_PROJECT_BYTES - total:
                    raise ValueError(f"project exceeds {MAX_PROJECT_BYTES}-byte capture budget")
                flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                with os.fdopen(os.open(path, flags), "rb") as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError(f"nonregular project input refused: {relative}")
                    if _file_version(metadata) != _file_version(before):
                        raise ValueError(f"project input changed before capture: {relative}")
                    data = source.read(MAX_PROJECT_BYTES - total + 1)
                    after = os.fstat(source.fileno())
                if _file_version(before) != _file_version(after):
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
    return entries, snapshot_digest(entries)


def stage_project(entries: list[SnapshotEntry], destination: Path, deadline: float, *,
                  cancellation: CancellationState | None = None) -> None:
    """Materialize the captured input; no live source is reread between legs."""
    check_cancellation(cancellation)
    destination.mkdir()
    for entry in entries:
        check_cancellation(cancellation)
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


def runtime_identity(executable: str, deadline: float) -> dict:
    """Measure executable bytes with a deadline and size bound.

    This identifies a selected file, not a runtime brand or interpreter chain.
    Before/after-suite measurements detect persistent replacement; they do not
    pin executable descriptors at exec or detect a swap restored between checks.
    """
    path = Path(executable)
    if not path.is_absolute():
        raise ValueError("runtime identity requires an absolute executable path")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111 == 0:
            raise ValueError("runtime must be an executable regular file")
        if before.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError("runtime binary exceeds the 512 MiB limit")
        digest = hashlib.sha256()
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("validation budget exhausted while measuring runtime identity")
            chunk = stream.read(min(65536, MAX_EXECUTABLE_BYTES - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXECUTABLE_BYTES:
                raise ValueError("runtime binary grew beyond the 512 MiB limit")
            digest.update(chunk)
        if (_file_version(before) != _file_version(os.fstat(stream.fileno()))
                or _file_version(before) != _file_version(path.lstat())):
            raise ValueError("runtime executable changed during identity measurement")
    return {"executable": str(path), "sha256": digest.hexdigest(), "bytes": total,
            "mode": stat.S_IMODE(before.st_mode)}


def measure_runtime_identities(commands: dict[str, list[str]], deadline: float) -> dict:
    # A Node/Node test pair intentionally has one binary; avoid hashing it twice
    # in the same phase, without calling that evidence of runtime independence.
    measured = {}
    for command in commands.values():
        if command[0] not in measured:
            measured[command[0]] = runtime_identity(command[0], deadline)
    return {role: dict(measured[command[0]]) for role, command in commands.items()}


def run_command(command: list[str], cwd: Path, *, timeout: float,
                max_output_bytes: int, environment: dict[str, str], input_bytes: bytes | None = None,
                cancellation: CancellationState | None = None) -> dict:
    """Bound both pipes and process lifetime, including inherited child pipes.

    A new POSIX session lets timeout/overflow cleanup kill this leg's process
    group. Even identical failures never qualify as successful validation.
    """
    if input_bytes is not None and (not isinstance(input_bytes, bytes) or len(input_bytes) > MAX_INPUT_BYTES):
        raise ValueError("captured test stdin must be bytes of at most 1 MiB")
    check_cancellation(cancellation)
    started = time.monotonic()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    counts = {name: 0 for name in output}
    hashes = {name: hashlib.sha256() for name in output}
    reason = None
    with subprocess.Popen(command, cwd=cwd, env=environment,
                          stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process:
        try:
            with selectors.DefaultSelector() as selector:
                for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                input_offset = 0
                if process.stdin is not None:
                    if input_bytes:
                        os.set_blocking(process.stdin.fileno(), False)
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                    else:
                        process.stdin.close()
                while selector.get_map() or process.poll() is None:
                    if cancellation is not None and cancellation.signum is not None:
                        reason = "cancelled"
                        break
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        reason = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.05)):
                        if key.data == "stdin":
                            try:
                                count = os.write(key.fileobj.fileno(), input_bytes[input_offset:input_offset + 65536])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                # A test may legitimately finish without consuming stdin.
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                                continue
                            input_offset += count
                            if input_offset == len(input_bytes):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
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
            if cancellation is not None and cancellation.signum is not None:
                # Preserve an earlier timeout/overflow cause; cancellation still
                # stops the suite, but must not overwrite its first failure.
                reason = reason or "cancelled"
                # Drain already-written bytes after termination. An escaped
                # descendant can retain a pipe, so this best-effort drain has
                # both time and byte bounds and is not a no-survivor assertion.
                drain_deadline = time.monotonic() + 0.25
                with selectors.DefaultSelector() as drain:
                    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                        os.set_blocking(stream.fileno(), False)
                        drain.register(stream, selectors.EVENT_READ, name)
                    while drain.get_map() and time.monotonic() < drain_deadline:
                        for key, _ in drain.select(max(0, min(0.02, drain_deadline - time.monotonic()))):
                            try:
                                chunk = os.read(key.fileobj.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                drain.unregister(key.fileobj)
                                continue
                            name = key.data
                            counts[name] += len(chunk)
                            hashes[name].update(chunk)
                            room = max(0, max_output_bytes - len(output[name]))
                            output[name].extend(chunk[:room])
                            if counts[name] > max_output_bytes:
                                drain.unregister(key.fileobj)
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
                     compare_filesystem: bool = False, bundle_path: Path | None = None,
                     _replay_constraints: dict | None = None,
                     cancellation: CancellationState | None = None) -> dict:
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
    commands = {}
    identities = None
    deadline = None
    bundle = None
    try:
        check_cancellation(cancellation)
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
        if baseline_root != migration_root and (baseline_root.is_relative_to(migration_root)
                                               or migration_root.is_relative_to(baseline_root)):
            raise ValueError("distinct input projects must not be nested")
        if bundle_path is not None:
            bundle_path = _bundle_destination(bundle_path, (baseline_root, migration_root))
        # Capture before executing anything; every case starts from these bytes.
        baseline_entries, baseline_digest = capture_project(baseline_root, deadline, cancellation=cancellation)
        if migration_root == baseline_root:
            migration_entries, migration_digest = baseline_entries, baseline_digest
        else:
            migration_entries, migration_digest = capture_project(migration_root, deadline, cancellation=cancellation)
        with tempfile.TemporaryDirectory(prefix="franken-migration-") as temporary:
            root = Path(temporary)
            baseline_inventory = captured_test_inventory(baseline_entries)
            migration_inventory = captured_test_inventory(migration_entries)
            baseline_by_path = {entry.path: entry for entry in baseline_entries}
            migration_by_path = {entry.path: entry for entry in migration_entries}
            baseline_tests = set(baseline_inventory)
            migration_tests = set(migration_inventory)
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
            matched_test_execution(baseline_inventory, migration_inventory, baseline_by_path, migration_by_path)
            baseline = resolve_command(baseline_command)
            migration = resolve_command(migration_command)
            commands = {"baseline": baseline, "migration": migration}
            for command in commands.values():
                if any(Path(command[0]).is_relative_to(project) for project in (baseline_root, migration_root)):
                    raise ValueError("runtime executables must be outside both measured projects")
            identities = measure_runtime_identities(commands, deadline)
            report["commands"] = commands
            report["runtime_identities"] = identities
            report["runtime_identity_scope"] = "executable-bytes-before-and-after-suite"
            report["runtime_identity_rechecked"] = False
            report["limits"] = {"per_leg_seconds": timeout_seconds, "total_seconds": total_timeout_seconds,
                                "per_stream_bytes": max_output_bytes}
            environment = dict(os.environ)
            if _replay_constraints is not None:
                if report["inputs"] != _replay_constraints["inputs"]:
                    raise ValueError("recovered replay input identities changed before execution")
                if (_runtime_measurements(identities) !=
                        _runtime_measurements(_replay_constraints["runtime_identities"])):
                    raise ValueError("replay executable identity differs from the recorded runtime")
                effective = {test: environment_digest(_test_environment(environment, settings))
                             for test, settings in baseline_inventory.items()}
                if effective != _replay_constraints["environment_sha256"]:
                    raise ValueError("replay effective environment differs from the recorded execution")
            if bundle_path is not None:
                bundle = ReplayBundleWriter(bundle_path, baseline_entries, migration_entries,
                    {test: environment_digest(_test_environment(environment, settings))
                     for test, settings in baseline_inventory.items()})
            # Freeze a single inherited environment for both legs; do not invent
            # permissive policy, signing keys, or degraded-runtime overrides.
            for index, test in enumerate(tests):
                check_cancellation(cancellation)
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
                        stage_project(entries, workspace, deadline, cancellation=cancellation)
                        if not (workspace / test).is_file():
                            raise ValueError(f"{leg} project is missing test {test}")
                        settings = baseline_inventory[test] if leg == "baseline" else migration_inventory[test]
                        by_path = baseline_by_path if leg == "baseline" else migration_by_path
                        script = test[len(settings.cwd) + 1:] if settings.cwd else test
                        command = [f"./{script}" if arg == "{test}" else arg for arg in template]
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("total validation budget exhausted")
                        captures[leg] = run_command(command, workspace / settings.cwd,
                                                    timeout=min(timeout_seconds, remaining),
                                                    max_output_bytes=max_output_bytes,
                                                    environment=_test_environment(environment, settings),
                                                    input_bytes=_test_input(settings, by_path),
                                                    cancellation=cancellation)
                        # Keep completed-leg evidence even if the other leg
                        # encounters an infrastructure failure or total timeout.
                        row[leg] = {k: v for k, v in captures[leg].items() if k not in {"stdout", "stderr"}}
                        if bundle is not None:
                            bundle.record(test, leg, captures[leg])
                        check_cancellation(cancellation)
                        if compare_filesystem:
                            final_entries, _ = capture_project(workspace, deadline, cancellation=cancellation)
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
            check_cancellation(cancellation)
            summary["verdict"] = "FAIL" if summary["failed"] else "PASS"
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error)})
        summary["verdict"] = "ERROR"
    finally:
        # Recheck even after an execution/collection error. A completed case is
        # kept as evidence, but may not authorize a suite PASS on changed code.
        if identities is not None:
            try:
                after = measure_runtime_identities(commands, deadline)
                if after != identities:
                    raise ValueError("runtime executable changed during validation")
                report["runtime_identity_rechecked"] = True
            except (OSError, ValueError, RuntimeError, TimeoutError) as error:
                report["errors"].append({"type": type(error).__name__,
                                         "message": f"runtime identity recheck failed: {error}"})
                summary["verdict"] = "ERROR"
        record_cancellation(report, cancellation)
        if bundle is not None:
            try:
                report["replay_bundle"] = bundle.publish(report)
            except (OSError, ValueError, RuntimeError, zipfile.LargeZipFile) as error:
                report["errors"].append({"type": type(error).__name__,
                                         "message": f"replay bundle publication failed: {error}"})
                summary["verdict"] = "ERROR"
            finally:
                bundle.close()
        record_cancellation(report, cancellation)
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


def self_test(*, cancellation: CancellationState | None = None) -> dict:
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
                                     migration_command=[sys.executable, "{test}"],
                                     cancellation=cancellation)
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


def _command_argument(text: str) -> list:
    command = json.loads(text)
    if not isinstance(command, list):
        raise argparse.ArgumentTypeError("runtime command must be a JSON argv array")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", nargs="?", type=Path)
    parser.add_argument("--migrated-project", type=Path, help="post-rewrite tree (default: same input)")
    parser.add_argument("--baseline-command", type=_command_argument,
                        help='JSON argv, e.g. ["node", "--test", "{test}"]')
    parser.add_argument("--migration-command", type=_command_argument,
                        help='JSON argv, e.g. ["franken-node", "run", "--console-only", "{test}"]')
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--total-timeout-seconds", type=float)
    parser.add_argument("--max-output-bytes", type=int)
    parser.add_argument("--band", choices=("core", "high-value", "edge"))
    parser.add_argument("--out", type=Path, help="atomically write the JSON validation report")
    parser.add_argument("--bundle", type=Path,
                        help="opt in to a private replay bundle containing raw source, inputs and output; never overwrites")
    parser.add_argument("--compare-filesystem", action="store_true",
                        help="also compare persistent workspace file/link/mode changes; .git excluded")
    parser.add_argument("--json", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--inspect-bundle", type=Path, help="verify a bundle and show metadata without executing it")
    modes.add_argument("--replay-bundle", type=Path,
                       help="re-execute captured projects; requires both explicit commands and the trusted bundle digest")
    parser.add_argument("--expected-bundle-sha256", help="trusted digest from the original report, not from the archive itself")
    args = parser.parse_args()
    read_path = args.inspect_bundle or args.replay_bundle
    if not args.self_test and read_path is None and args.project_dir is None:
        parser.error("project_dir or a bundle operation is required")
    if read_path is not None and (args.project_dir is not None or args.migrated_project is not None
            or args.bundle is not None or args.compare_filesystem
            or any(value is not None for value in (args.timeout_seconds, args.total_timeout_seconds,
                                                   args.max_output_bytes, args.band))):
        parser.error("bundle operations use recorded projects and limits, not project execution options")
    if args.replay_bundle is not None and (args.baseline_command is None or args.migration_command is None
                                          or args.expected_bundle_sha256 is None):
        parser.error("replay requires --baseline-command, --migration-command and --expected-bundle-sha256")
    if args.inspect_bundle is not None and (args.baseline_command is not None or args.migration_command is not None):
        parser.error("inspection does not accept executable commands")
    if args.expected_bundle_sha256 is not None and read_path is None:
        parser.error("--expected-bundle-sha256 requires a bundle operation")
    evidence_path = read_path or args.bundle
    if evidence_path is not None and args.out is not None and evidence_path.resolve() == args.out.resolve():
        parser.error("--out must not overwrite the evidence bundle")
    cancellation = CancellationState()
    with termination_signals(cancellation):
        status = _execute_cli(args, cancellation)
        return 128 + cancellation.signum if cancellation.signum is not None else status


def _execute_cli(args: argparse.Namespace, cancellation: CancellationState) -> int:
    """Keep signal latching active through result publication, not just execution."""
    if args.self_test:
        result = self_test(cancellation=cancellation)
        verdict = result["verdict"]
    elif args.inspect_bundle is not None:
        try:
            result = inspect_replay_bundle(args.inspect_bundle, expected_sha256=args.expected_bundle_sha256)
            verdict = "PASS"
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError, RecursionError,
                zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            result = {"phase": "inspection", "errors": [{"type": type(error).__name__, "message": str(error)}]}
            verdict = "ERROR"
    elif args.replay_bundle is not None:
        result = replay_captured_bundle(args.replay_bundle, expected_sha256=args.expected_bundle_sha256,
            baseline_command=args.baseline_command, migration_command=args.migration_command,
            cancellation=cancellation)
        verdict = {"REPRODUCED": "PASS", "CHANGED": "FAIL", "ERROR": "ERROR"}[result["replay_outcome"]]
    else:
        result = validate_project(args.project_dir, migrated_project=args.migrated_project,
                                  baseline_command=args.baseline_command if args.baseline_command is not None else DEFAULT_BASELINE_COMMAND,
                                  migration_command=args.migration_command if args.migration_command is not None else DEFAULT_MIGRATION_COMMAND,
                                  timeout_seconds=30.0 if args.timeout_seconds is None else args.timeout_seconds,
                                  total_timeout_seconds=300.0 if args.total_timeout_seconds is None else args.total_timeout_seconds,
                                  max_output_bytes=1_048_576 if args.max_output_bytes is None else args.max_output_bytes,
                                  band="core" if args.band is None else args.band,
                                  compare_filesystem=args.compare_filesystem, bundle_path=args.bundle,
                                  cancellation=cancellation)
        verdict = result["summary"]["verdict"]
    record_cancellation(result, cancellation)
    if cancellation.signum is not None:
        verdict = "ERROR"
    if args.out is not None:
        try:
            write_report(result, args.out)
        except OSError as error:
            print(f"cannot write validation report: {error}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(result, indent=2, allow_nan=False))
    else:
        if args.replay_bundle is not None:
            print(f"Replay: {result['replay_outcome']}")
            print(json.dumps(result.get("execution", {}).get("summary", {}), indent=2))
        else:
            print(f"{'Integrity' if args.inspect_bundle is not None else 'Verdict'}: {verdict}")
            print(json.dumps(result.get("summary", result.get("original_summary", {})), indent=2))
        for error in result.get("errors", []):
            print(error["message"], file=sys.stderr)
        for row in result.get("validation_results", []):
            if row["status"] != "PASS":
                print(f"FAIL {row['test']}: {json.dumps(row['divergences'])}")
    return 0 if verdict == "PASS" else 1 if verdict == "FAIL" else 2


if __name__ == "__main__":
    sys.exit(main())
