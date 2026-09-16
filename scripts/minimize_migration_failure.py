#!/usr/bin/env python3
"""Reduce a trusted migration replay capsule using real dual-runtime execution.

Every accepted source reduction preserves ALL recorded case observations, not
just a failing exit code. The resulting ordinary replay capsule can be replayed
or used for fix verification without changing the existing replay tools.
Captured code executes with your authority; disposable copies are NOT a sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import failure_replay as replay

runner = replay.runner
MAX_SOURCE_FILES = 16
MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_LINES = 4096
MAX_EXECUTIONS = 4096
MAX_SECONDS = 3600


class ReductionBudgetExhausted(Exception):
    """Search stops without adopting the unfinished candidate."""


def behavior(observation: dict) -> dict:
    """Input hashes must change on reduction; measured behavior must not."""
    return {key: observation[key] for key in ("validation_verdict", "cases")}


def require_stable_failure(observation: dict) -> None:
    if observation["validation_verdict"] != "FAIL":
        raise ValueError("minimization requires a recorded failing migration")
    for case in observation["cases"]:
        for leg in replay.LEGS:
            outcome = case[leg]
            if (outcome.get("termination") != "exited"
                    or type(outcome.get("exit_code")) is not int
                    or outcome["exit_code"] < 0
                    or (leg == "baseline" and outcome["exit_code"] != 0)
                    or set(outcome["streams"]) != {"stdout", "stderr"}
                    or any(stream.get("complete") is not True
                           for stream in outcome["streams"].values())):
                raise ValueError("reduction needs successful reference runs and complete, non-timeout observations")


def selected_sources(snapshots: dict, observation: dict, source_files) -> list[tuple[str, int]]:
    if source_files is None:
        source_files = [case["test"] for case in observation["cases"] if case["status"] == "FAIL"]
    if (not isinstance(source_files, (list, tuple))
            or not 1 <= len(source_files) <= MAX_SOURCE_FILES):
        raise ValueError(f"select between 1 and {MAX_SOURCE_FILES} source files")
    paths = []
    for path in source_files:
        replay.safe_path(path)
        if Path(path).suffix not in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
            raise ValueError("only explicit JS/TS source files may be reduced, not configuration")
        if path in paths:
            raise ValueError("duplicate reduction source file")
        paths.append(path)
    selected = []
    for leg in replay.LEGS:
        index = {entry.path: i for i, entry in enumerate(snapshots[leg])}
        for path in sorted(paths):
            if path not in index:
                raise ValueError(f"selected source is missing from {leg}: {path}")
            entry = snapshots[leg][index[path]]
            if entry.data is None or entry.link is not None:
                raise ValueError("selected sources must be regular files, not directories or symlinks")
            if len(entry.data) > MAX_SOURCE_BYTES or len(entry.data.splitlines()) > MAX_SOURCE_LINES:
                raise ValueError("selected source exceeds the reduction byte/line bound")
            entry.data.decode("utf-8", errors="strict")
            selected.append((leg, index[path]))
    return selected


def reduce_lines(lines: list[bytes], interesting) -> list[bytes]:
    """Complement-based ddmin; syntax-breaking candidates simply fail the oracle.

    The oracle can raise ReductionBudgetExhausted. Its last accepted state is
    retained by the caller. A single remaining line is also tested for removal.
    """
    current = list(lines)
    granularity = min(2, len(current))
    while current:
        reduced = False
        for part in range(granularity):
            start = part * len(current) // granularity
            end = (part + 1) * len(current) // granularity
            candidate = current[:start] + current[end:]
            if interesting(candidate):
                current = candidate
                granularity = min(len(current), max(2, granularity - 1))
                reduced = True
                break
        if not reduced:
            if granularity == len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current


def validate_limits(max_executions: int, seconds: float, confirmations: int) -> None:
    if type(confirmations) is not int or not 2 <= confirmations <= 8:
        raise ValueError("confirmations must be an integer between 2 and 8")
    if type(max_executions) is not int or not 2 * confirmations <= max_executions <= MAX_EXECUTIONS:
        raise ValueError("execution budget must cover initial/final confirmations and stay within 4096")
    if type(seconds) not in {int, float} or not math.isfinite(seconds) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("reduction time budget must be finite, positive, and at most 3600 seconds")


def minimize_migration(artifact: dict, *, execute: bool = False,
                       baseline_command=runner.DEFAULT_BASELINE_COMMAND,
                       migration_command=runner.DEFAULT_MIGRATION_COMMAND,
                       source_files=None, expected_sha256: str | None = None,
                       max_executions: int = 128, seconds: float = 120,
                       confirmations: int = 2) -> dict:
    """Return a newly measured capsule; never mutate the supplied capsule.

    Execution budget counts complete-suite oracle invocations, not individual
    child processes. Reserve confirmations and 20% of wall time for fresh final
    verification. Budget exhaustion may yield a partial, verified reduction,
    but a failed final verification yields no capsule.
    """
    if not execute:
        raise ValueError("minimization requires execute=True / --execute consent")
    validate_limits(max_executions, seconds, confirmations)
    started = time.monotonic()
    deadline = started + seconds
    search_deadline = started + seconds * 0.8
    best = replay.validate_capsule(artifact, expected_sha256)
    original = artifact["expected"]
    require_stable_failure(original)
    selected = selected_sources(best, original, source_files)
    options = replay.checked_options(artifact["options"])
    commands, bindings = replay.runtime_bindings(baseline_command, migration_command, deadline)
    if bindings != artifact["runtime_bindings"]:
        raise ValueError("runtime provenance mismatch; reduction must use the captured runtimes and validators")
    implementation_hash = replay.hash_regular_file(Path(__file__), deadline)
    stats = {"executions": 0, "accepted": 0, "rejected": 0, "unresolved": 0, "cache_hits": 0}
    attempts = []
    rejected = set()
    budget_reason = None
    expected_behavior = behavior(original)
    initial_bytes = sum(len(best[leg][index].data) for leg, index in selected)

    def check_bindings():
        _, observed = replay.runtime_bindings(commands["baseline"], commands["migration"], deadline)
        if observed != bindings or replay.hash_regular_file(Path(__file__), deadline) != implementation_hash:
            raise ValueError("runtime or validator changed during minimization")

    def measure(snapshots, phase, expected_inputs=None):
        final = phase == "final"
        limit = max_executions if final else max_executions - confirmations
        phase_deadline = deadline if final else search_deadline
        if stats["executions"] >= limit:
            raise ReductionBudgetExhausted("execution_budget")
        if time.monotonic() >= phase_deadline:
            raise ReductionBudgetExhausted("wall_time_budget")
        check_bindings()
        stats["executions"] += 1
        run_deadline = min(phase_deadline, time.monotonic() + options["total_timeout_seconds"])
        try:
            report = replay.execute_snapshots(snapshots, commands["baseline"], commands["migration"],
                                              options, expected_inputs, deadline=run_deadline)
            observed = replay.execution_observation(report)
        except (OSError, ValueError, TimeoutError):
            observed = None
        check_bindings()
        return observed

    # Reproduce before touching any bytes. A checksum-valid but edited expected
    # result, stale ambient environment, or flaky original is not a reducer seed.
    for _ in range(confirmations):
        observed = measure(best, "initial", original["inputs"])
        if observed is None or observed != original:
            raise ValueError("original capsule does not reproduce; refusing to minimize a different failure")

    def candidate_key(snapshots):
        state = [(leg, snapshots[leg][index].path,
                  hashlib.sha256(snapshots[leg][index].data).hexdigest()) for leg, index in selected]
        return hashlib.sha256(replay.canonical_bytes(state)).hexdigest()

    def try_candidate(leg, index, lines):
        nonlocal best
        previous = best[leg][index]
        data = b"".join(lines)
        candidate = {name: list(entries) for name, entries in best.items()}
        candidate[leg][index] = replace(previous, data=data)
        key = candidate_key(candidate)
        if key in rejected:
            stats["cache_hits"] += 1
            return False
        if stats["executions"] + confirmations > max_executions - confirmations:
            raise ReductionBudgetExhausted("execution_budget")
        outcome = "accepted"
        for _ in range(confirmations):
            observed = measure(candidate, "candidate")
            if observed is None:
                outcome = "unresolved"
                break
            if behavior(observed) != expected_behavior:
                outcome = "rejected"
                break
        stats[outcome] += 1
        attempts.append({"candidate_sha256": key, "leg": leg, "path": previous.path,
                         "before_bytes": len(previous.data), "after_bytes": len(data), "outcome": outcome})
        if outcome == "accepted":
            best = candidate
            return True
        if outcome == "rejected":
            rejected.add(key)
        return False

    # Repeat the deterministic sweep: changing a later source can make a line
    # in an earlier source removable. Do not claim a fixed point after one pass.
    try:
        while True:
            accepted_before = stats["accepted"]
            for leg, index in selected:
                reduce_lines(best[leg][index].data.splitlines(keepends=True),
                             lambda lines, leg=leg, index=index: try_candidate(leg, index, lines))
            if stats["accepted"] == accepted_before:
                break
    except ReductionBudgetExhausted as error:
        budget_reason = str(error)

    # Never reuse a cached acceptance as final proof. Regenerate new input
    # bindings and recheck every original case using fresh real executions.
    final_observation = None
    for _ in range(confirmations):
        observed = measure(best, "final")
        if observed is None or behavior(observed) != expected_behavior:
            raise ValueError("final reduced capsule no longer reproduces the original behavior")
        if final_observation is not None and observed != final_observation:
            raise ValueError("final reduced capsule is unstable")
        final_observation = observed
    manifests, blobs = replay.encode_snapshots(best)
    final_bytes = sum(len(best[leg][index].data) for leg, index in selected)
    metadata = {
        "schema_version": "migration-minimization-v1",
        "parent_content_sha256": artifact["content_sha256"],
        "algorithm": "ddmin-line-complements-fixed-point-v1",
        "predicate": "all-recorded-case-observations-exact",
        "implementation_sha256": implementation_hash,
        "source_files": sorted({best[leg][index].path for leg, index in selected}),
        "initial_bytes": initial_bytes, "final_bytes": final_bytes,
        "confirmations": confirmations, "final_confirmations": confirmations,
        "max_executions": max_executions, "seconds": seconds,
        "budget_exhausted": budget_reason,
        "search_complete": budget_reason is None and stats["unresolved"] == 0,
        "global_minimum_claimed": False,
        "stats": stats, "attempts": attempts,
    }
    minimized = replay.seal({**artifact, "snapshots": manifests, "blobs": blobs,
                             "expected": final_observation, "recorded_commands": commands,
                             "captured_at": datetime.now(timezone.utc).isoformat(),
                             "minimized": final_bytes < initial_bytes, "minimization": metadata})
    replay.validate_capsule(minimized)
    return minimized


def export_capsule(artifact: dict, destination: Path, *, seconds: float = 60) -> dict:
    """Restore inspectable repro workspaces without executing captured commands.

    Only a new private directory is accepted. On an I/O error a partial export
    may remain, but no success manifest is written before both input hashes are
    checked. Source content and dependencies remain sensitive, even minimized.
    """
    if type(seconds) not in {int, float} or not math.isfinite(seconds) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("invalid export time budget")
    deadline = time.monotonic() + seconds
    snapshots = replay.validate_capsule(artifact)
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    digests = {}
    for leg in replay.LEGS:
        workspace = destination / leg
        runner.stage_project(snapshots[leg], workspace, deadline)
        _, digest = runner.capture_project(workspace, deadline)
        digests[f"{leg}_sha256"] = digest
    if digests != artifact["expected"]["inputs"]:
        raise ValueError("exported workspace input digest mismatch")
    manifest = {"schema_version": "migration-repro-workspaces-v1",
                "content_sha256": artifact["content_sha256"], "inputs": digests,
                "validation_verdict": artifact["expected"]["validation_verdict"],
                "commands_are_diagnostic_only": True, "executed": False,
                "recorded_commands": artifact["recorded_commands"],
                "runtime_bindings": artifact["runtime_bindings"]}
    descriptor = os.open(destination / "reproduction.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(replay.canonical_bytes(manifest) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capsule", type=Path, nargs="?")
    parser.add_argument("--capture", type=Path, help="capture, persist and reduce a live project failure")
    parser.add_argument("--migrated-project", type=Path)
    parser.add_argument("--capture-out", type=Path, help="save original capsule BEFORE reduction; required with --capture")
    parser.add_argument("--compare-filesystem", action="store_true", help="capture persistent filesystem effects")
    parser.add_argument("--timeout-seconds", type=float, default=30, help="per-leg timeout for capture")
    parser.add_argument("--export-dir", type=Path, help="new private directory for inspectable repro workspaces")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--out", type=Path, required=True, help="new private replay capsule; never overwrite")
    parser.add_argument("--source-file", action="append", help="shared JS/TS path; default: failing test files")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--baseline-command", type=json.loads, default=list(runner.DEFAULT_BASELINE_COMMAND))
    parser.add_argument("--migration-command", type=json.loads, default=list(runner.DEFAULT_MIGRATION_COMMAND))
    parser.add_argument("--max-executions", type=int, default=128)
    parser.add_argument("--seconds", type=float, default=120)
    parser.add_argument("--confirmations", type=int, default=2)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if (args.capsule is None) == (args.capture is None):
        parser.error("provide exactly one capsule path or --capture PROJECT")
    if args.capture and args.capture_out is None:
        parser.error("--capture requires --capture-out to retain the original before reduction")
    if not args.capture and (args.capture_out or args.migrated_project or args.compare_filesystem):
        parser.error("capture-only options cannot modify an existing capsule")
    preserved = {}
    try:
        if not args.execute:
            raise ValueError("--execute is required: captured programs run with your authority")
        validate_limits(args.max_executions, args.seconds, args.confirmations)
        destinations = [path for path in (args.out, args.capture_out, args.export_dir) if path is not None]
        if len({path.resolve() for path in destinations}) != len(destinations):
            raise ValueError("capture, reduction and export destinations must be distinct")
        for path in destinations:
            if os.path.lexists(path):
                raise ValueError("output already exists; refusing to execute or overwrite")
            if not path.parent.is_dir():
                raise ValueError("output parent directory must already exist")
        started = time.monotonic()
        if args.capture:
            if args.expected_sha256:
                raise ValueError("--expected-sha256 pins an existing capsule, not a new capture")
            artifact = replay.capture_migration(args.capture, migrated_project=args.migrated_project,
                                                 baseline_command=args.baseline_command,
                                                 migration_command=args.migration_command,
                                                 timeout_seconds=args.timeout_seconds,
                                                 total_timeout_seconds=args.seconds,
                                                 compare_filesystem=args.compare_filesystem)
            # Keep the full failing input even if reduction is interrupted,
            # exhausts its budget, or finds a non-reproducible original.
            replay.write_capsule(artifact, args.capture_out)
            preserved = {"captured_capsule": str(args.capture_out),
                         "captured_sha256": artifact["content_sha256"]}
        else:
            artifact = replay.load_replay(args.capsule)
        if args.capture and artifact["expected"]["validation_verdict"] == "PASS":
            result, code = {"verdict": "NO_FAILURE", "validation_verdict": "PASS", **preserved}, 0
        else:
            remaining = args.seconds - (time.monotonic() - started)
            artifact = minimize_migration(artifact, execute=True,
                                          baseline_command=args.baseline_command, migration_command=args.migration_command,
                                          source_files=args.source_file, expected_sha256=args.expected_sha256,
                                          max_executions=args.max_executions, seconds=remaining,
                                          confirmations=args.confirmations)
            replay.write_capsule(artifact, args.out)
            preserved.update(reduced_capsule=str(args.out), reduced_sha256=artifact["content_sha256"])
            result = {"verdict": "REDUCED" if artifact["minimized"] else "UNCHANGED",
                      "path": str(args.out), "content_sha256": artifact["content_sha256"],
                      "validation_verdict": artifact["expected"]["validation_verdict"],
                      "minimization": artifact["minimization"], **preserved}
            if args.export_dir:
                # Export has its own bounded, non-executing staging allowance.
                export_capsule(artifact, args.export_dir)
                result["export_dir"] = str(args.export_dir)
            code = 0 if result["verdict"] == "REDUCED" else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ReductionBudgetExhausted) as error:
        result, code = {"verdict": "ERROR", "error": str(error), **preserved}, 2
    print(json.dumps(result, indent=2, allow_nan=False) if args.json else f"{result['verdict']}: {json.dumps(result)}")
    return code


if __name__ == "__main__":
    sys.exit(main())
