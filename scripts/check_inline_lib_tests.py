#!/usr/bin/env python3
"""Gate cargo's inline library test harness for bd-rjc2m.21.

`cargo test -p frankenengine-node --lib -- --list` must discover at least
one test. This script keeps the CI check out of ad hoc shell grep so the
parser and exit behavior are unit-tested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TEST_LINE_RE = re.compile(r"^[^\s:].*: test$")
TEST_RESULT_RE = re.compile(r"^test (?P<name>.*?) \.\.\. (?P<status>ok|FAILED|ignored)$")
DEFAULT_OVERRIDE_CFG = "franken_node_inline_tests"
DEFAULT_MAX_TESTS_PER_SHARD = 500
DEFAULT_SHARD_TIMEOUT_SECONDS = 1800
DEFAULT_RECEIPT_JSONL = Path("artifacts/verification/inline-lib-test-shards.jsonl")
DEFAULT_SHARD_OUTPUT_DIR = Path("artifacts/verification/inline-lib-test-shards")
SCHEMA_LIST = "franken-node/inline-lib-test-gate/v1"
SCHEMA_PREFLIGHT = "franken-node/inline-lib-test-preflight/v1"
SCHEMA_SHARD_PLAN = "franken-node/inline-lib-test-shard-plan/v1"
SCHEMA_SHARD_RECEIPT = "franken-node/inline-lib-test-shard-receipt/v1"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def inline_test_names(cargo_list_output: str) -> list[str]:
    """Return test names from `cargo test --lib -- --list` output."""
    names: list[str] = []
    for raw_line in strip_ansi(cargo_list_output).splitlines():
        line = raw_line.strip()
        if not TEST_LINE_RE.match(line):
            continue
        names.append(line.rsplit(": test", 1)[0])
    return names


def evaluate(cargo_list_output: str, min_tests: int) -> dict[str, object]:
    if min_tests < 1:
        raise ValueError("min_tests must be at least 1")

    tests = inline_test_names(cargo_list_output)
    return {
        "schema_version": SCHEMA_LIST,
        "test_count": len(tests),
        "min_tests": min_tests,
        "passed": len(tests) >= min_tests,
        "sample_tests": tests[:10],
    }


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def target_hash(test_names: Sequence[str]) -> str:
    hasher = hashlib.sha256()
    for name in test_names:
        encoded = name.encode("utf-8")
        hasher.update(len(encoded).to_bytes(8, "little"))
        hasher.update(encoded)
    return f"sha256:{hasher.hexdigest()}"


def shell_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def common_test_prefix(test_names: Sequence[str]) -> str:
    split_names = [name.split("::") for name in test_names]
    prefix: list[str] = []
    for components in zip(*split_names):
        first = components[0]
        if any(component != first for component in components):
            break
        prefix.append(first)
    return "::".join(prefix)


def group_tests_by_prefix(
    test_names: Sequence[str],
    max_tests_per_shard: int,
    depth: int = 1,
) -> list[list[str]]:
    if max_tests_per_shard < 1:
        raise ValueError("max_tests_per_shard must be at least 1")

    names = sorted(test_names)
    if len(names) <= max_tests_per_shard:
        return [names] if names else []

    buckets: dict[str, list[str]] = {}
    for name in names:
        components = name.split("::")
        key = "::".join(components[: min(depth, len(components))])
        buckets.setdefault(key, []).append(name)

    groups: list[list[str]] = []
    for bucket in buckets.values():
        if len(bucket) <= max_tests_per_shard:
            groups.append(bucket)
            continue
        if all(len(name.split("::")) <= depth for name in bucket):
            groups.extend([[name] for name in bucket])
            continue
        groups.extend(group_tests_by_prefix(bucket, max_tests_per_shard, depth + 1))
    return groups


def shard_command(
    test_filter: str,
    exact: bool,
    rch_bin: str,
    override_cfg: str,
) -> list[str]:
    command = [
        rch_bin,
        "exec",
        "--",
        "env",
        "CARGO_INCREMENTAL=0",
        f"RUSTFLAGS=--cfg {override_cfg}",
        "cargo",
        "test",
        "-p",
        "frankenengine-node",
        "--lib",
        "--features",
        "extended-surfaces,test-support",
        test_filter,
    ]
    if exact:
        command.extend(["--", "--exact"])
    return command


def build_shard_plan(
    cargo_list_output: str,
    max_tests_per_shard: int = DEFAULT_MAX_TESTS_PER_SHARD,
    rch_bin: str = "rch",
    override_cfg: str = DEFAULT_OVERRIDE_CFG,
    timeout_seconds: int = DEFAULT_SHARD_TIMEOUT_SECONDS,
) -> dict[str, object]:
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be at least 1")

    tests = inline_test_names(cargo_list_output)
    groups = group_tests_by_prefix(tests, max_tests_per_shard)
    total_shards = len(groups)
    plan_id = target_hash(tests)
    shards: list[dict[str, object]] = []

    for index, group in enumerate(groups, start=1):
        exact = len(group) == 1
        test_filter = group[0] if exact else common_test_prefix(group)
        command = shard_command(test_filter, exact, rch_bin, override_cfg)
        shard_id = f"inline-lib-{index:04d}"
        shards.append(
            {
                "shard_id": shard_id,
                "shard_index": index,
                "total_shards": total_shards,
                "test_count": len(group),
                "test_filter": test_filter,
                "exact": exact,
                "target_hash": target_hash(group),
                "target_set": group,
                "command": command,
                "command_display": shell_command(command),
                "timeout_seconds": timeout_seconds,
            }
        )

    return {
        "schema_version": SCHEMA_SHARD_PLAN,
        "plan_id": plan_id,
        "generated_at": utc_timestamp(),
        "total_tests": len(tests),
        "total_shards": total_shards,
        "max_tests_per_shard": max_tests_per_shard,
        "override_cfg": override_cfg,
        "timeout_seconds": timeout_seconds,
        "shards": shards,
    }


def write_plan_jsonl(plan: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for shard in plan["shards"]:
            line = {
                "schema_version": SCHEMA_SHARD_PLAN,
                "plan_id": plan["plan_id"],
                "generated_at": plan["generated_at"],
                **shard,
            }
            handle.write(json.dumps(line, sort_keys=True) + "\n")


def test_results_from_run(output: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for raw_line in strip_ansi(output).splitlines():
        line = raw_line.strip()
        match = TEST_RESULT_RE.match(line)
        if match:
            results[match.group("name")] = match.group("status")
    return results


def stream_summary(text: str, max_chars: int = 1200) -> str:
    lines = [line.strip() for line in strip_ansi(text).splitlines() if line.strip()]
    priority_terms = (
        "error",
        "failed",
        "panic",
        "no space left",
        "os error",
        "could not compile",
        "timed out",
        "timeout",
    )
    selected = [
        line for line in lines if any(term in line.lower() for term in priority_terms)
    ]
    if not selected:
        selected = lines[:8]
    summary = "\n".join(selected)
    if len(summary) > max_chars:
        return summary[: max_chars - 3] + "..."
    return summary


def classify_outcome(exit_code: int, stdout: str, stderr: str) -> str:
    if exit_code == 0:
        return "passed"
    combined = f"{stdout}\n{stderr}".lower()
    if exit_code == 124 or "timed out" in combined or "timeout" in combined:
        return "timeout"
    if "no space left on device" in combined or "os error 28" in combined:
        return "rch_infra_failure"
    if "remote command failed" in combined and "rch" in combined:
        return "rch_infra_failure"
    if "could not compile" in combined:
        return "compile_failure"
    if "test result: failed" in combined or "failed" in combined:
        return "test_failure"
    return "unknown_failure"


def existing_passed_receipts(receipt_jsonl: Path) -> set[tuple[str, str]]:
    passed: set[tuple[str, str]] = set()
    if not receipt_jsonl.exists():
        return passed
    for raw_line in receipt_jsonl.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        try:
            receipt = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        passed_value = receipt.get("passed")
        if isinstance(passed_value, bool) and passed_value:
            passed.add((str(receipt.get("shard_id")), str(receipt.get("target_hash"))))
    return passed


Runner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


def default_runner(command: Sequence[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )


def timeout_stream(stream: str | bytes | None) -> str:
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream


def run_shards(
    plan: dict[str, object],
    receipt_jsonl: Path,
    output_dir: Path,
    resume: bool,
    fail_fast: bool,
    runner: Runner = default_runner,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    receipt_jsonl.parent.mkdir(parents=True, exist_ok=True)
    passed_receipts = existing_passed_receipts(receipt_jsonl) if resume else set()
    exit_status = 0

    with receipt_jsonl.open("a", encoding="utf-8") as handle:
        for shard in plan["shards"]:
            shard_id = str(shard["shard_id"])
            shard_target_hash = str(shard["target_hash"])
            if (shard_id, shard_target_hash) in passed_receipts:
                continue

            command = list(shard["command"])
            timeout_seconds = int(shard.get("timeout_seconds", DEFAULT_SHARD_TIMEOUT_SECONDS))
            started_at = utc_timestamp()
            try:
                completed = runner(command, timeout_seconds)
                returncode = completed.returncode
                stdout = completed.stdout or ""
                stderr = completed.stderr or ""
            except subprocess.TimeoutExpired as exc:
                returncode = 124
                stdout = timeout_stream(exc.stdout)
                stderr = timeout_stream(exc.stderr)
                if stderr:
                    stderr = f"{stderr}\n"
                stderr = f"{stderr}command timed out after {timeout_seconds} seconds"
            ended_at = utc_timestamp()
            stdout_path = output_dir / f"{shard_id}.stdout.txt"
            stderr_path = output_dir / f"{shard_id}.stderr.txt"
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            observed = test_results_from_run(stdout)
            outcome_class = classify_outcome(returncode, stdout, stderr)
            receipt = {
                "schema_version": SCHEMA_SHARD_RECEIPT,
                "plan_id": plan["plan_id"],
                "shard_id": shard_id,
                "shard_index": shard["shard_index"],
                "total_shards": shard["total_shards"],
                "target_hash": shard_target_hash,
                "target_set": shard["target_set"],
                "test_filter": shard["test_filter"],
                "exact": shard["exact"],
                "command": command,
                "command_display": shell_command(command),
                "timeout_seconds": timeout_seconds,
                "started_at": started_at,
                "ended_at": ended_at,
                "exit_code": returncode,
                "passed": returncode == 0,
                "outcome_class": outcome_class,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "stdout_summary": stream_summary(stdout),
                "stderr_summary": stream_summary(stderr),
                "observed_results": observed,
            }
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
            handle.flush()

            if returncode != 0:
                exit_status = 1
                if fail_fast or outcome_class in {"rch_infra_failure", "timeout"}:
                    break

    return exit_status


def cargo_lib_test_enabled(cargo_toml: Path) -> bool:
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    enabled = data.get("lib", {}).get("test")
    return isinstance(enabled, bool) and enabled


def cargo_lints_allow_override_cfg(cargo_toml: Path, override_cfg: str) -> bool:
    data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    check_cfgs = (
        data.get("lints", {})
        .get("rust", {})
        .get("unexpected_cfgs", {})
        .get("check-cfg", [])
    )
    return f"cfg({override_cfg})" in check_cfgs


def lib_rs_uses_override_gate(lib_rs: Path, override_cfg: str) -> bool:
    text = lib_rs.read_text(encoding="utf-8")
    gate = f"#![cfg(any(not(test), {override_cfg}))]"
    return gate in text and "#![cfg(not(test))]" not in text


def preflight(
    cargo_toml: Path,
    lib_rs: Path,
    override_cfg: str = DEFAULT_OVERRIDE_CFG,
) -> dict[str, object]:
    checks = {
        "cargo_lib_test_true": cargo_lib_test_enabled(cargo_toml),
        "lib_rs_override_gate": lib_rs_uses_override_gate(lib_rs, override_cfg),
        "cargo_lints_allow_override_cfg": cargo_lints_allow_override_cfg(
            cargo_toml, override_cfg
        ),
    }
    issues = [name for name, passed in checks.items() if not passed]
    return {
        "schema_version": SCHEMA_PREFLIGHT,
        "passed": not issues,
        "override_cfg": override_cfg,
        "checks": checks,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail if cargo test --lib -- --list discovers too few inline tests."
    )
    parser.add_argument(
        "list_output",
        nargs="?",
        type=Path,
        help="Path to captured cargo list output. Reads stdin when omitted.",
    )
    parser.add_argument("--min-tests", type=int, default=1)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Check that the dedicated inline-test override is wired.",
    )
    parser.add_argument(
        "--emit-shard-plan",
        action="store_true",
        help="Emit a resumable shard plan from captured `cargo test -- --list` output.",
    )
    parser.add_argument(
        "--run-shards",
        action="store_true",
        help="Run planned inline-lib shards through rch and emit JSONL receipts.",
    )
    parser.add_argument("--max-tests-per-shard", type=int, default=DEFAULT_MAX_TESTS_PER_SHARD)
    parser.add_argument(
        "--shard-timeout-seconds",
        type=int,
        default=DEFAULT_SHARD_TIMEOUT_SECONDS,
        help="Per-shard subprocess timeout for the RCH cargo command.",
    )
    parser.add_argument(
        "--plan-jsonl-out",
        type=Path,
        help="Optional path for one JSONL shard-plan record per shard.",
    )
    parser.add_argument("--receipt-jsonl", type=Path, default=DEFAULT_RECEIPT_JSONL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_SHARD_OUTPUT_DIR)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failing shard instead of collecting all failures.",
    )
    parser.add_argument("--rch-bin", default=os.environ.get("RCH_BIN", "rch"))
    parser.add_argument(
        "--cargo-toml",
        type=Path,
        default=Path("crates/franken-node/Cargo.toml"),
    )
    parser.add_argument(
        "--lib-rs",
        type=Path,
        default=Path("crates/franken-node/src/lib.rs"),
    )
    parser.add_argument("--override-cfg", default=DEFAULT_OVERRIDE_CFG)
    args = parser.parse_args(argv)

    if args.preflight:
        result = preflight(args.cargo_toml, args.lib_rs, args.override_cfg)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                "Inline library test override preflight: "
                f"{'passed' if result['passed'] else 'failed'}"
            )
            for issue in result["issues"]:
                print(f"failed check: {issue}", file=sys.stderr)
        return 0 if result["passed"] else 1

    if args.list_output:
        output = args.list_output.read_text(encoding="utf-8")
    else:
        output = sys.stdin.read()

    if args.emit_shard_plan or args.run_shards:
        plan = build_shard_plan(
            output,
            max_tests_per_shard=args.max_tests_per_shard,
            rch_bin=args.rch_bin,
            override_cfg=args.override_cfg,
            timeout_seconds=args.shard_timeout_seconds,
        )
        if args.plan_jsonl_out:
            write_plan_jsonl(plan, args.plan_jsonl_out)
        if args.emit_shard_plan:
            if args.json:
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                print(
                    "Inline library test shard plan: "
                    f"{plan['total_tests']} tests across {plan['total_shards']} shards"
                )
        if not args.run_shards:
            return 0 if plan["total_shards"] else 1
        return run_shards(
            plan,
            receipt_jsonl=args.receipt_jsonl,
            output_dir=args.output_dir,
            resume=args.resume,
            fail_fast=args.fail_fast,
        )

    result = evaluate(output, args.min_tests)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"Inline library tests discovered: {result['test_count']} "
            f"(minimum: {result['min_tests']})"
        )
        if not result["passed"]:
            print(
                "Expected cargo test --lib -- --list to discover inline tests; "
                "the library test harness may be disabled.",
                file=sys.stderr,
            )

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
