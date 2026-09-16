#!/usr/bin/env python3
"""Capture and re-execute migration failures from portable, exact-input capsules.

Captures include source, dependencies and configuration: treat them as sensitive.
Checksums detect corruption, not malicious re-signing; pin --expected-sha256 from
an independently trusted channel. Replay requires --execute because project code
runs with the caller's authority. Workspace copies are NOT an OS sandbox.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import migration_validation_runner as runner

ROOT = Path(__file__).resolve().parent.parent
REPLAY_DIR = ROOT / "artifacts" / "replays"
CAPSULE_SCHEMA = "migration-failure-replay-v1"
NOTE_SCHEMA = "migration-failure-note-v1"
MAX_CAPSULE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"REPLAY-[a-zA-Z0-9-]{1,80}\Z")
LEGS = ("baseline", "migration")


def canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def content_digest(artifact: dict) -> str:
    payload = {key: value for key, value in artifact.items()
               if key not in {"content_sha256", "replay_id"}}
    return hashlib.sha256(b"franken-migration-replay-v1\0" + canonical_bytes(payload)).hexdigest()


def seal(artifact: dict) -> dict:
    digest = content_digest(artifact)
    return {**artifact, "content_sha256": digest, "replay_id": f"REPLAY-{digest}"}


def capture_failure(failure_source: str, fixture_id: str, input_data: dict,
                    expected: dict, actual: dict, env: dict | None = None) -> dict:
    """Capture a diagnostic note. Notes alone are explicitly NOT executable."""
    return {
        "schema_version": NOTE_SCHEMA,
        "replay_id": f"REPLAY-{uuid.uuid4().hex}",
        "failure_source": failure_source,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "context": {"fixture_id": fixture_id, "input": input_data,
                    "expected_output": expected, "actual_output": actual,
                    "environment": env or {}},
        "replay_command": None,
        "executable": False,
        "minimized": False,
        "diagnosis_hints": generate_hints(expected, actual),
    }


def generate_hints(expected: dict, actual: dict) -> list[str]:
    hints = []
    if expected.get("return_value") != actual.get("return_value"):
        hints.append("Return value divergence — check data types and encoding")
    if expected.get("error") != actual.get("error"):
        hints.append("Error behavior divergence — check error code and message")
    if expected.get("side_effects") != actual.get("side_effects"):
        hints.append("Side effect divergence — check file/network/state operations")
    return hints or ["No specific divergence pattern detected — manual investigation needed"]


def safe_path(value: str) -> list[str]:
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096
            or "\\" in value or "\0" in value):
        raise ValueError("invalid capsule path")
    parts = value.split("/")
    if len(parts) > 64 or any(part in {"", ".", "..", ".git"} for part in parts):
        raise ValueError(f"unsafe capsule path: {value!r}")
    return parts


def check_link(path: str, target: str, nodes: dict) -> None:
    """Resolve links against the manifest only; never consult the host filesystem."""
    def parts(value):
        if (not isinstance(value, str) or not value or value.startswith("/")
                or "\\" in value or "\0" in value or len(value.encode("utf-8")) > 4096):
            raise ValueError("unsafe capsule symlink target")
        return value.split("/")

    pending = path.split("/")[:-1] + parts(target)
    resolved = []
    links = steps = 0
    while pending:
        steps += 1
        if steps > 4096:
            raise ValueError("capsule symlink resolution budget exceeded")
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise ValueError("capsule symlink escapes workspace")
            resolved.pop()
            continue
        if part == ".git":
            raise ValueError("capsule symlink reaches excluded .git")
        candidate = "/".join([*resolved, part])
        node = nodes.get(candidate)
        if node is None:
            raise ValueError(f"dangling capsule symlink: {path!r}")
        if node["kind"] == "symlink":
            links += 1
            if links > 40:
                raise ValueError("capsule symlink cycle or depth exceeded")
            pending = parts(node["target"]) + pending
        else:
            if pending and node["kind"] != "directory":
                raise ValueError("capsule symlink traverses a regular file")
            resolved.append(part)


def encode_snapshots(snapshots: dict) -> tuple[dict, dict]:
    manifests, blobs = {}, {}
    for leg in LEGS:
        manifest = []
        for entry in snapshots[leg]:
            node = {"path": entry.path, "mode": entry.mode}
            if entry.link is not None:
                node.update(kind="symlink", target=entry.link)
            elif entry.data is None:
                node.update(kind="directory")
            else:
                digest = hashlib.sha256(entry.data).hexdigest()
                blobs.setdefault(digest, base64.b64encode(entry.data).decode("ascii"))
                node.update(kind="file", blob=digest)
            manifest.append(node)
        manifests[leg] = manifest
    return manifests, blobs


def decode_snapshots(manifests: dict, blobs: dict) -> dict:
    """Validate the complete path graph and content bounds before any staging."""
    if not isinstance(manifests, dict) or set(manifests) != set(LEGS):
        raise ValueError("capsule requires baseline and migration manifests")
    if not isinstance(blobs, dict) or len(blobs) > 2 * runner.MAX_PROJECT_FILES:
        raise ValueError("invalid capsule blob table")
    decoded, used = {}, set()
    unique_bytes = 0
    for digest, encoded in blobs.items():
        if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
            raise ValueError("invalid content blob hash")
        if not isinstance(encoded, str) or len(encoded) > (MAX_EXPANDED_BYTES + 2) // 3 * 4:
            raise ValueError("content blob exceeds capture limit")
        data = base64.b64decode(encoded, validate=True)
        unique_bytes += len(data)
        if unique_bytes > MAX_EXPANDED_BYTES:
            raise ValueError("capsule decoded bytes exceed limit")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("content blob hash mismatch")
        if base64.b64encode(data).decode("ascii") != encoded:
            raise ValueError("noncanonical content blob encoding")
        decoded[digest] = data
    snapshots = {}
    expanded_bytes = metadata_bytes = 0
    for leg in LEGS:
        manifest = manifests[leg]
        if not isinstance(manifest, list) or len(manifest) > runner.MAX_PROJECT_FILES:
            raise ValueError("capsule manifest entry bound exceeded")
        nodes = {}
        for node in manifest:
            if not isinstance(node, dict):
                raise ValueError("invalid capsule entry")
            safe_path(node.get("path"))
            path, kind, mode = node["path"], node.get("kind"), node.get("mode")
            if path in nodes or type(mode) is not int or not 0 <= mode <= 0o777:
                raise ValueError("duplicate capsule path or invalid permissions")
            fields = {"file": {"blob"}, "directory": set(), "symlink": {"target"}}
            if kind not in fields or set(node) != {"path", "kind", "mode"} | fields[kind]:
                raise ValueError("invalid capsule entry fields")
            metadata_bytes += len(canonical_bytes(node))
            if metadata_bytes > MAX_METADATA_BYTES:
                raise ValueError("capsule metadata byte bound exceeded")
            if kind == "file":
                digest = node["blob"]
                if not isinstance(digest, str) or digest not in decoded:
                    raise ValueError("missing content blob")
                expanded_bytes += len(decoded[digest])
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    raise ValueError("expanded workspace bytes exceed limit")
                used.add(digest)
            nodes[path] = node
        for path, node in nodes.items():
            components = path.split("/")
            for depth in range(1, len(components)):
                parent = nodes.get("/".join(components[:depth]))
                if parent is None or parent["kind"] != "directory":
                    raise ValueError("capsule parent must be a declared real directory")
            if node["kind"] == "symlink":
                check_link(path, node["target"], nodes)
        # Parent directories precede children, irrespective of untrusted input order.
        snapshots[leg] = [runner.SnapshotEntry(
            path, decoded[node["blob"]] if node["kind"] == "file" else None,
            node["mode"], node.get("target")) for path, node in sorted(nodes.items())]
    if used != set(decoded):
        raise ValueError("unreferenced content blobs are not allowed")
    return snapshots


def execution_observation(report: dict) -> dict:
    """Project only measured behavior; clocks and temporary roots are not behavior."""
    summary = report["summary"]
    if (summary["verdict"] not in {"PASS", "FAIL"} or not report["validation_results"]
            or summary["skipped"] or summary["errored"]):
        raise ValueError("replay requires a complete nonempty measured validation run")
    cases = []
    for row in report["validation_results"]:
        case = {key: row[key] for key in ("test", "band", "status", "severity", "divergences")}
        for leg in LEGS:
            case[leg] = {key: row[leg][key] for key in ("exit_code", "termination", "streams")}
            if report["filesystem_comparison"]:
                delta = row[leg]["workspace_delta"]
                case[leg]["workspace_delta"] = {key: delta[key] for key in ("sha256", "changed_paths")}
        cases.append(case)
    return {"inputs": report["inputs"], "validation_verdict": summary["verdict"], "cases": cases}


def checked_options(options: dict) -> dict:
    defaults = {"timeout_seconds": 30.0, "total_timeout_seconds": 300.0,
                "max_output_bytes": 1_048_576, "band": "core", "compare_filesystem": False}
    if not isinstance(options, dict) or options.keys() - defaults.keys():
        raise ValueError("unknown replay execution option")
    result = {**defaults, **options}
    for name, limit in (("timeout_seconds", 3600), ("total_timeout_seconds", 86400)):
        value = result[name]
        if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= limit:
            raise ValueError("invalid replay time budget")
    cap = result["max_output_bytes"]
    if type(cap) is not int or not 0 < cap <= runner.MAX_OUTPUT_BYTES:
        raise ValueError("invalid replay output limit")
    if result["band"] not in {"core", "high-value", "edge"} or type(result["compare_filesystem"]) is not bool:
        raise ValueError("invalid replay comparison policy")
    return result


def hash_regular_file(path: Path, deadline: float) -> str:
    """Bounded descriptor hash with before/after mutation detection, not a lock."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError("runtime/validator must be a bounded regular file")
        digest = hashlib.sha256()
        total = 0
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("runtime fingerprinting exhausted total execution budget")
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EXECUTABLE_BYTES:
                raise ValueError("runtime byte bound exceeded")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("runtime/validator changed during fingerprinting")
        return digest.hexdigest()


def runtime_bindings(baseline_command, migration_command, deadline: float) -> tuple[dict, dict]:
    """Resolve caller-owned commands; bind direct executables, argv and validators.

    Paths may relocate while bytes stay identical. Dynamic libraries, imported
    modules outside the snapshot and ambient environment remain outside this
    binding; it is not a hermetic executable-image or whole-machine claim.
    """
    commands = {"baseline": runner.resolve_command(baseline_command),
                "migration": runner.resolve_command(migration_command)}
    hashes = {}

    def hashed(path):
        path = Path(path).resolve(strict=True)
        if path not in hashes:
            hashes[path] = hash_regular_file(path, deadline)
        return hashes[path]

    bindings = {leg: {"executable_sha256": hashed(command[0]), "arguments": command[1:]}
                for leg, command in commands.items()}
    bindings["validators"] = {"replay_sha256": hashed(__file__), "runner_sha256": hashed(runner.__file__),
                              "python_sha256": hashed(sys.executable)}
    return commands, bindings


def check_runtime_binding_schema(bindings) -> None:
    if not isinstance(bindings, dict) or set(bindings) != {*LEGS, "validators"}:
        raise ValueError("missing runtime provenance bindings")
    validators = bindings["validators"]
    if (not isinstance(validators, dict)
            or set(validators) != {"replay_sha256", "runner_sha256", "python_sha256"}):
        raise ValueError("invalid validator provenance bindings")
    hashes = list(validators.values())
    for leg in LEGS:
        binding = bindings[leg]
        if not isinstance(binding, dict) or set(binding) != {"executable_sha256", "arguments"}:
            raise ValueError("invalid runtime binding")
        hashes.append(binding["executable_sha256"])
        args = binding["arguments"]
        if (not isinstance(args, list) or not 1 <= len(args) < 256
                or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in args)
                or args.count("{test}") != 1 or sum(len(arg.encode()) for arg in args) > 65536):
            raise ValueError("invalid bound runtime arguments")
    if any(not isinstance(value, str) or HASH_RE.fullmatch(value) is None for value in hashes):
        raise ValueError("invalid runtime/validator content digest")


def validate_capsule(artifact: dict, expected_sha256: str | None = None) -> dict:
    if not isinstance(artifact, dict) or artifact.get("schema_version") != CAPSULE_SCHEMA:
        raise ValueError("not an executable migration replay capsule")
    if len(canonical_bytes(artifact)) > MAX_CAPSULE_BYTES:
        raise ValueError("capsule exceeds serialized byte bound")
    digest = artifact.get("content_sha256")
    if not isinstance(digest, str) or HASH_RE.fullmatch(digest) is None:
        raise ValueError("missing capsule content hash")
    if not hmac.compare_digest(digest, content_digest(artifact)):
        raise ValueError("capsule content hash mismatch")
    if artifact.get("replay_id") != f"REPLAY-{digest}":
        raise ValueError("capsule replay identity mismatch")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or HASH_RE.fullmatch(expected_sha256) is None
            or not hmac.compare_digest(expected_sha256, digest)):
        raise ValueError("capsule does not match the independently pinned hash")
    checked_options(artifact.get("options"))
    check_runtime_binding_schema(artifact.get("runtime_bindings"))
    expected = artifact.get("expected")
    if (not isinstance(expected, dict) or expected.get("validation_verdict") not in {"PASS", "FAIL"}
            or not isinstance(expected.get("cases"), list)
            or not 0 < len(expected["cases"]) <= runner.MAX_TEST_FILES):
        raise ValueError("capsule has no complete expected observation")
    inputs = expected.get("inputs")
    if (not isinstance(inputs, dict) or set(inputs) != {f"{leg}_sha256" for leg in LEGS}
            or any(not isinstance(value, str) or HASH_RE.fullmatch(value) is None
                   for value in inputs.values())):
        raise ValueError("capsule is missing its executed input digest bindings")
    expected_verdict = "FAIL" if any(isinstance(case, dict) and case.get("status") == "FAIL"
                                     for case in expected["cases"]) else "PASS"
    if expected["validation_verdict"] != expected_verdict:
        raise ValueError("expected validation verdict disagrees with case outcomes")
    ids = set()
    for case in expected["cases"]:
        if not isinstance(case, dict):
            raise ValueError("invalid expected case")
        safe_path(case.get("test"))
        if case["test"] in ids or case.get("status") not in {"PASS", "FAIL"}:
            raise ValueError("duplicate or unmeasured expected case")
        ids.add(case["test"])
        for leg in LEGS:
            observed = case.get(leg)
            if not isinstance(observed, dict) or not isinstance(observed.get("streams"), dict):
                raise ValueError("missing expected runtime observation")
            for stream in ("stdout", "stderr"):
                value = observed["streams"].get(stream)
                if (not isinstance(value, dict) or not isinstance(value.get("sha256"), str)
                        or HASH_RE.fullmatch(value["sha256"]) is None):
                    raise ValueError("missing expected output digest")
    return decode_snapshots(artifact.get("snapshots"), artifact.get("blobs"))


def execute_snapshots(snapshots: dict, baseline_command, migration_command,
                      options: dict, expected_inputs: dict | None = None,
                      *, deadline: float | None = None) -> dict:
    options = checked_options(options)
    if deadline is None:
        deadline = time.monotonic() + options["total_timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="migration-replay-") as temporary:
        root = Path(temporary)
        digests = {}
        for leg in LEGS:
            runner.stage_project(snapshots[leg], root / leg, deadline)
            _, digest = runner.capture_project(root / leg, deadline)
            digests[f"{leg}_sha256"] = digest
        if expected_inputs is not None and digests != expected_inputs:
            raise ValueError("restored input digest mismatch; refusing execution")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("replay staging exhausted total execution budget")
        report = runner.validate_project(root / "baseline", migrated_project=root / "migration",
                                         baseline_command=baseline_command, migration_command=migration_command,
                                         **{**options, "total_timeout_seconds": remaining})
        if report.get("inputs") != digests:
            raise ValueError("executed inputs differ from the restored capsule")
        return report


def capture_migration(project: Path, *, migrated_project: Path | None = None,
                      baseline_command=runner.DEFAULT_BASELINE_COMMAND,
                      migration_command=runner.DEFAULT_MIGRATION_COMMAND, **options) -> dict:
    """Capture inputs FIRST, then measure exactly those inputs, never a later tree."""
    options = checked_options(options)
    deadline = time.monotonic() + options["total_timeout_seconds"]
    commands, bindings = runtime_bindings(baseline_command, migration_command, deadline)
    snapshots = {}
    captured_roots = {}
    for leg, directory in (("baseline", project), ("migration", migrated_project or project)):
        directory = Path(directory).resolve(strict=True)
        if not directory.is_dir():
            raise ValueError("capture source must be a directory")
        if directory not in captured_roots:
            captured_roots[directory], _ = runner.capture_project(directory, deadline)
        snapshots[leg] = captured_roots[directory]
    manifests, blobs = encode_snapshots(snapshots)
    snapshots = decode_snapshots(manifests, blobs)
    report = execute_snapshots(snapshots, commands["baseline"], commands["migration"], options, deadline=deadline)
    expected = execution_observation(report)
    _, after_bindings = runtime_bindings(commands["baseline"], commands["migration"], deadline)
    if after_bindings != bindings:
        raise ValueError("runtime or validator changed during capture")
    artifact = seal({
        "schema_version": CAPSULE_SCHEMA,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "failure_source": "migration_validation_runner",
        "snapshots": manifests, "blobs": blobs, "options": options,
        "recorded_commands": report["commands"],
        "runtime_bindings": bindings,
        "expected": expected,
        "scope": "exact-input re-execution; not deterministic runtime replay",
        "environment_captured": False, "release_certification": False,
    })
    if len(canonical_bytes(artifact)) > MAX_CAPSULE_BYTES:
        raise ValueError("capsule exceeds serialized byte bound")
    return artifact


def replay_migration(artifact: dict, *, execute: bool = False,
                     baseline_command=runner.DEFAULT_BASELINE_COMMAND,
                     migration_command=runner.DEFAULT_MIGRATION_COMMAND,
                     expected_sha256: str | None = None, verify_fix: bool = False) -> dict:
    """Re-execute, not self-compare. Never execute argv or environment from a capsule."""
    snapshots = validate_capsule(artifact, expected_sha256)
    if not execute:
        raise ValueError("replay requires explicit execute=True / --execute consent")
    options = checked_options(artifact["options"])
    deadline = time.monotonic() + options["total_timeout_seconds"]
    commands, bindings = runtime_bindings(baseline_command, migration_command, deadline)
    recorded_bindings = artifact["runtime_bindings"]
    required = ("baseline", "validators") if verify_fix else (*LEGS, "validators")
    if any(bindings[component] != recorded_bindings[component] for component in required):
        raise ValueError("runtime provenance mismatch; ordinary replay requires the recorded executables and arguments")
    if verify_fix and (artifact["expected"]["validation_verdict"] != "FAIL"
                      or any(case["baseline"].get("exit_code") != 0
                             or case["baseline"].get("termination") != "exited"
                             or not all(stream.get("complete") is True for stream in case["baseline"]["streams"].values())
                             for case in artifact["expected"]["cases"])):
        raise ValueError("fix verification requires an original failing migration with successful complete reference runs")
    report = execute_snapshots(snapshots, commands["baseline"], commands["migration"],
                               options, artifact["expected"]["inputs"], deadline=deadline)
    _, after_bindings = runtime_bindings(commands["baseline"], commands["migration"], deadline)
    if after_bindings != bindings:
        raise ValueError("runtime or validator changed during replay")
    result = {"schema_version": "migration-replay-result-v1", "replay_id": artifact["replay_id"],
              "content_sha256": artifact["content_sha256"], "verdict": "ERROR",
              "recorded_validation_verdict": artifact["expected"]["validation_verdict"],
              "observed_validation_verdict": report["summary"]["verdict"],
              "execution": report, "mismatched_tests": [],
              "mode": "fix-verification" if verify_fix else "replay",
              "runtime_bindings": bindings,
              "environment_reproduced": False, "release_certification": False}
    try:
        observed = execution_observation(report)
    except ValueError as error:
        result["error"] = str(error)
        return result
    expected_cases = {case["test"]: case for case in artifact["expected"]["cases"]}
    observed_cases = {case["test"]: case for case in observed["cases"]}
    result["mismatched_tests"] = [test for test in sorted(expected_cases.keys() | observed_cases.keys())
                                  if expected_cases.get(test) != observed_cases.get(test)]
    result["verdict"] = "REPRODUCED" if observed == artifact["expected"] else "DIVERGED"
    if verify_fix:
        result["reference_drift_tests"] = [test for test in sorted(expected_cases.keys() | observed_cases.keys())
                                           if expected_cases.get(test, {}).get("baseline")
                                           != observed_cases.get(test, {}).get("baseline")]
        if result["reference_drift_tests"]:
            result["verdict"] = "REFERENCE_DRIFT"
        else:
            result["verdict"] = "FIX_VERIFIED" if observed["validation_verdict"] == "PASS" else "FIX_NOT_VERIFIED"
    return result


def inspect_capsule(artifact: dict, expected_sha256: str | None = None) -> dict:
    """Offline validation and privacy-bounded summary; no commands are resolved."""
    snapshots = validate_capsule(artifact, expected_sha256)
    return {"verdict": "INTEGRITY_VALID", "replay_id": artifact["replay_id"],
            "content_sha256": artifact["content_sha256"],
            "independently_pinned": expected_sha256 is not None,
            "validation_verdict": artifact["expected"]["validation_verdict"],
            "test_count": len(artifact["expected"]["cases"]),
            "workspace_entries": {leg: len(entries) for leg, entries in snapshots.items()},
            "runtime_binding_present": True, "executed": False,
            "authentication": "external digest pin" if expected_sha256 else "checksum only; not authenticated"}


def validate_replay_artifact(artifact: dict) -> list[str]:
    try:
        if not isinstance(artifact, dict):
            raise ValueError("artifact must be an object")
        if artifact.get("schema_version") == CAPSULE_SCHEMA:
            validate_capsule(artifact)
        else:
            required = {"replay_id", "failure_source", "captured_at", "context", "replay_command"}
            if required - artifact.keys():
                raise ValueError("missing required diagnostic note fields")
            context = artifact["context"]
            if not isinstance(context, dict) or {"fixture_id", "input", "expected_output", "actual_output"} - context.keys():
                raise ValueError("missing diagnostic context fields")
        if not isinstance(artifact.get("replay_id"), str) or ID_RE.fullmatch(artifact["replay_id"]) is None:
            raise ValueError("unsafe replay identifier")
    except (ValueError, TypeError, KeyError, RecursionError, binascii.Error) as error:
        return [str(error)]
    return []


def write_capsule(artifact: dict, path: Path) -> None:
    errors = validate_replay_artifact(artifact)
    if errors:
        raise ValueError("; ".join(errors))
    payload = canonical_bytes(artifact) + b"\n"
    if len(payload) > MAX_CAPSULE_BYTES:
        raise ValueError("capsule exceeds serialized byte bound")
    # Content may include .env and private keys. Never use default file modes,
    # follow an existing symlink, or overwrite an earlier capture.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def save_replay(artifact: dict, replay_dir: Path | None = None) -> Path:
    errors = validate_replay_artifact(artifact)
    if errors:
        raise ValueError("; ".join(errors))
    directory = replay_dir or REPLAY_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{artifact['replay_id']}.json"
    write_capsule(artifact, path)
    return path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate capsule JSON field: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"nonfinite capsule JSON number: {value}")


def load_replay(path: Path) -> dict:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CAPSULE_BYTES:
            raise ValueError("capsule must be a bounded regular file")
        data = stream.read(MAX_CAPSULE_BYTES + 1)
    if len(data) > MAX_CAPSULE_BYTES:
        raise ValueError("capsule exceeds serialized byte bound")
    try:
        artifact = json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("invalid capsule JSON") from error
    errors = validate_replay_artifact(artifact)
    if errors:
        raise ValueError("; ".join(errors))
    return artifact


def self_test() -> dict:
    checks = []
    note = capture_failure("validation_runner", "fixture:fs:readFile:utf8-basic",
                           {"args": ["test.txt"]}, {"return_value": "hello"}, {"return_value": "HELLO"})
    checks.append({"id": "REPLAY-CAPTURE", "status": "PASS" if not validate_replay_artifact(note) else "FAIL"})
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        loaded = load_replay(save_replay(note, root))
        checks.append({"id": "REPLAY-ROUNDTRIP", "status": "PASS" if loaded == note else "FAIL"})
        before, after = root / "before", root / "after"
        before.mkdir()
        after.mkdir()
        (before / "probe.test.js").write_text("print('before')\n", encoding="utf-8")
        (after / "probe.test.js").write_text("print('after')\n", encoding="utf-8")
        command = [sys.executable, "{test}"]
        capsule = capture_migration(before, migrated_project=after, baseline_command=command, migration_command=command)
        result = replay_migration(capsule, execute=True, baseline_command=command, migration_command=command)
        reproduced = result["verdict"] == "REPRODUCED" and result["observed_validation_verdict"] == "FAIL"
        checks.append({"id": "REPLAY-EXECUTION", "status": "PASS" if reproduced else "FAIL"})
    failures = sum(check["status"] != "PASS" for check in checks)
    return {"gate": "failure_replay_verification", "section": "10.3",
            "verdict": "FAIL" if failures else "PASS", "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {"total_checks": len(checks), "passing_checks": len(checks) - failures, "failing_checks": failures}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--capture", type=Path, metavar="PROJECT")
    mode.add_argument("--replay", type=Path, metavar="CAPSULE")
    mode.add_argument("--inspect", type=Path, metavar="CAPSULE", help="verify integrity offline without executing any code")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--migrated-project", type=Path)
    parser.add_argument("--baseline-command", type=json.loads, default=list(runner.DEFAULT_BASELINE_COMMAND))
    parser.add_argument("--migration-command", type=json.loads, default=list(runner.DEFAULT_MIGRATION_COMMAND))
    parser.add_argument("--execute", action="store_true", help="approve executing trusted captured project code")
    parser.add_argument("--verify-fix", action="store_true", help="allow a new migration runtime; require unchanged reference evidence and all captured cases passing")
    parser.add_argument("--expected-sha256", help="capsule content hash obtained from an independent trusted channel")
    parser.add_argument("--compare-filesystem", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--total-timeout-seconds", type=float, default=300.0)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.verify_fix and not args.replay:
        parser.error("--verify-fix requires --replay")
    try:
        if args.self_test:
            result = self_test()
            code = 0 if result["verdict"] == "PASS" else 1
        elif args.inspect:
            result = inspect_capsule(load_replay(args.inspect), args.expected_sha256)
            code = 0
        elif args.capture:
            if args.out is None:
                parser.error("--capture requires --out; capsules contain sensitive project files")
            if os.path.lexists(args.out):
                raise ValueError("capture destination already exists; refusing to execute or overwrite it")
            artifact = capture_migration(args.capture, migrated_project=args.migrated_project,
                                         baseline_command=args.baseline_command, migration_command=args.migration_command,
                                         compare_filesystem=args.compare_filesystem, timeout_seconds=args.timeout_seconds,
                                         total_timeout_seconds=args.total_timeout_seconds)
            write_capsule(artifact, args.out)
            result = {"verdict": "CAPTURED", "path": str(args.out), "replay_id": artifact["replay_id"],
                      "content_sha256": artifact["content_sha256"],
                      "validation_verdict": artifact["expected"]["validation_verdict"]}
            code = 0 if result["validation_verdict"] == "PASS" else 1
        else:
            if not args.execute:
                parser.error("--replay requires --execute: captured programs run with your authority")
            artifact = load_replay(args.replay)
            result = replay_migration(artifact, execute=True, baseline_command=args.baseline_command,
                                      migration_command=args.migration_command, expected_sha256=args.expected_sha256,
                                      verify_fix=args.verify_fix)
            code = {"REPRODUCED": 0, "FIX_VERIFIED": 0, "DIVERGED": 1, "FIX_NOT_VERIFIED": 1,
                    "REFERENCE_DRIFT": 2, "ERROR": 2}[result["verdict"]]
            if args.out:
                if args.out.resolve() == args.replay.resolve():
                    raise ValueError("replay report must not overwrite its input capsule")
                runner.write_report(result, args.out)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        result, code = {"verdict": "ERROR", "error": str(error)}, 2
    print(json.dumps(result, indent=2, allow_nan=False) if args.json else f"{result['verdict']}: {json.dumps(result)}")
    return code


if __name__ == "__main__":
    sys.exit(main())
