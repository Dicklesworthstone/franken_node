#!/usr/bin/env python3
"""bd-2fa verification: counterfactual replay mode for policy simulation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = ROOT / "crates" / "franken-node" / "src" / "tools" / "counterfactual_replay.rs"
MOD_RS = ROOT / "crates" / "franken-node" / "src" / "tools" / "mod.rs"
MAIN_RS = ROOT / "crates" / "franken-node" / "src" / "main.rs"
SPEC = ROOT / "docs" / "specs" / "section_10_5" / "bd-2fa_contract.md"
FIXTURE = ROOT / "fixtures" / "interop" / "interop_test_vectors.json"
EVIDENCE = ROOT / "artifacts" / "section_10_5" / "bd-2fa" / "verification_evidence.json"

REQUIRED_IMPL_PATTERNS = [
    "pub struct CounterfactualReplayEngine",
    "pub trait SandboxedExecutor",
    "pub enum SimulationMode",
    "pub struct CounterfactualResult",
    "pub struct DivergenceRecord",
    "pub struct SummaryStatistics",
    "max_replay_steps",
    "max_wall_clock_millis",
    "PureSandboxedExecutor",
    "ReplayExecutionBounds",
    "StepLimitExceeded",
    "WallClockExceeded",
    "partial_result",
    "to_canonical_json",
    "CounterfactualSimulationOutput",
]

REQUIRED_RUST_TESTS = [
    "single_policy_swap_diverges",
    "replay_is_deterministic",
    "parameter_sweep_runs_multiple_scenarios",
    "step_limit_returns_partial_result",
    "wall_clock_limit_returns_partial_result",
    "parse_sweep_override",
    "invalid_sweep_cardinality_rejected",
    "direct_sweep_mode_rejects_too_many_values",
    "summarize_output_works_for_single",
]

REQUIRED_EVIDENCE_FILES = [
    "crates/franken-node/src/tools/counterfactual_replay.rs",
    "crates/franken-node/src/tools/mod.rs",
    "crates/franken-node/src/main.rs",
    "docs/specs/section_10_5/bd-2fa_contract.md",
    "scripts/check_counterfactual.py",
    "tests/test_check_counterfactual.py",
]

REQUIRED_ACCEPTANCE_EVIDENCE = {
    "CounterfactualReplayEngine accepts replay bundle + alternate policy and re-executes timeline.": [
        "CounterfactualReplayEngine::replay",
        "counterfactual_replay.rs",
    ],
    "CounterfactualResult includes original/counterfactual outcomes, divergence points, summary stats.": [
        "CounterfactualResult",
        "DivergenceRecord",
        "SummaryStatistics",
    ],
    "Sandboxed deterministic evaluation with no side effects.": [
        "SandboxedExecutor",
        "PureSandboxedExecutor",
    ],
    "SinglePolicySwap and ParameterSweep modes are implemented.": [
        "SimulationMode",
        "simulate",
        "sweep",
    ],
    "Step and timeout bounds return structured errors with partial results.": [
        "StepLimitExceeded",
        "WallClockExceeded",
        "partial_result",
    ],
}


def load_fixture_vectors() -> list[dict[str, Any]]:
    if not FIXTURE.is_file():
        return []
    data = json.JSONDecoder().decode(FIXTURE.read_text(encoding="utf-8"))
    return data.get("test_vectors", [])


def load_evidence(data: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if data is not None:
        return data
    if not EVIDENCE.is_file():
        return None
    try:
        decoded = json.JSONDecoder().decode(EVIDENCE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if isinstance(decoded, dict):
        return decoded
    return None


def check_file(path: Path, label: str) -> dict[str, Any]:
    ok = path.is_file()
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {display_path(path)}" if ok else f"missing: {path}",
    }


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def read_rust_source(path: Path) -> str:
    return strip_rust_comments(read_text(path))


def strip_rust_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text.startswith("//", i):
            end = text.find("\n", i)
            if end == -1:
                break
            result.append("\n")
            i = end + 1
            continue

        if text.startswith("/*", i):
            i = rust_block_comment_end(text, i + 2)
            continue

        raw_end = rust_raw_string_end(text, i)
        if raw_end is not None:
            result.append(text[i:raw_end])
            i = raw_end
            continue

        if text[i] == '"':
            end = rust_quoted_literal_end(text, i)
            result.append(text[i:end])
            i = end
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def rust_raw_string_end(text: str, start: int) -> int | None:
    if text[start] != "r":
        return None

    cursor = start + 1
    hashes = 0
    while cursor < len(text) and text[cursor] == "#":
        hashes += 1
        cursor += 1

    if cursor >= len(text) or text[cursor] != '"':
        return None

    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, cursor + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def rust_quoted_literal_end(text: str, start: int) -> int:
    cursor = start + 1
    while cursor < len(text):
        if text[cursor] == "\\":
            cursor += 2
            continue
        if text[cursor] == '"':
            return cursor + 1
        cursor += 1
    return len(text)


def rust_block_comment_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) and depth:
        if text.startswith("/*", cursor):
            depth += 1
            cursor += 2
        elif text.startswith("*/", cursor):
            depth -= 1
            cursor += 2
        else:
            cursor += 1
    return cursor


def check_contains(path: Path, patterns: list[str], label: str, *, strip_comments: bool = False) -> list[dict[str, Any]]:
    if not path.is_file():
        return [{"check": f"{label}: {pattern}", "pass": False, "detail": "file missing"} for pattern in patterns]
    content = read_rust_source(path) if strip_comments else read_text(path)
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "check": f"{label}: {pattern}",
                "pass": pattern in content,
                "detail": "found" if pattern in content else "not found",
            }
        )
    return checks


def check_rust_tests() -> list[dict[str, Any]]:
    if not IMPL.is_file():
        return [{"check": "rust tests: implementation readable", "pass": False, "detail": "file missing"}]

    content = read_rust_source(IMPL)
    test_count = content.count("#[test]")
    checks = [
        {
            "check": "rust tests: counterfactual replay coverage count",
            "pass": test_count >= 20,
            "detail": f"{test_count} tests found",
        }
    ]
    for test_name in REQUIRED_RUST_TESTS:
        present = f"fn {test_name}" in content
        checks.append({
            "check": f"rust test: {test_name}",
            "pass": present,
            "detail": "found" if present else "missing",
        })
    return checks


def check_evidence(data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    evidence = load_evidence(data)
    if evidence is None:
        return [{"check": "evidence: readable json", "pass": False, "detail": f"missing/invalid: {EVIDENCE}"}]

    checks: list[dict[str, Any]] = [
        {"check": "evidence: bead id", "pass": evidence.get("bead_id") == "bd-2fa", "detail": "bd-2fa"},
        {
            "check": "evidence: completed status",
            "pass": str(evidence.get("status", "")).startswith("completed"),
            "detail": str(evidence.get("status", "")),
        },
    ]

    implementation = evidence.get("implementation", {})
    files = implementation.get("files", []) if isinstance(implementation, dict) else []
    if not isinstance(files, list):
        files = []
    for required in REQUIRED_EVIDENCE_FILES:
        present = required in files
        checks.append({
            "check": f"evidence file: {required}",
            "pass": present,
            "detail": "listed" if present else "missing",
        })

    highlights = "\n".join(str(item) for item in implementation.get("highlights", [])) if isinstance(implementation, dict) else ""
    for label, tokens in {
        "engine implemented": ["CounterfactualReplayEngine", "deterministic"],
        "modes implemented": ["SinglePolicySwap", "ParameterSweep"],
        "bounds implemented": ["max_replay_steps", "max_wall_clock_millis", "partial results"],
        "cli integrated": ["incident counterfactual", "CLI"],
    }.items():
        present = all(token in highlights for token in tokens)
        checks.append({
            "check": f"evidence highlight: {label}",
            "pass": present,
            "detail": "all markers present" if present else "missing marker",
        })

    verification = evidence.get("verification", {})
    commands = verification.get("commands", []) if isinstance(verification, dict) else []
    if not isinstance(commands, list):
        commands = []
    command_text = "\n".join(str(command.get("command", "")) + "\n" + str(command.get("result", "")) for command in commands if isinstance(command, dict))
    for command in [
        "python3 scripts/check_counterfactual.py --json",
        "python3 -m unittest tests/test_check_counterfactual.py",
        "rch exec -- cargo test --manifest-path crates/franken-node/Cargo.toml counterfactual_replay -- --nocapture",
    ]:
        checks.append({
            "check": f"evidence command recorded: {command}",
            "pass": command in command_text,
            "detail": "recorded" if command in command_text else "missing",
        })

    mapping = evidence.get("acceptance_criteria_mapping", [])
    if not isinstance(mapping, list):
        mapping = []
    mapping_by_criterion = {
        str(item.get("criterion", "")): str(item.get("evidence", ""))
        for item in mapping
        if isinstance(item, dict)
    }
    for criterion, tokens in REQUIRED_ACCEPTANCE_EVIDENCE.items():
        evidence_text = mapping_by_criterion.get(criterion, "")
        present = all(token in evidence_text for token in tokens)
        checks.append({
            "check": f"evidence acceptance: {criterion}",
            "pass": present,
            "detail": "all markers present" if present else "missing marker",
        })

    return checks


def run_checks() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.append(check_file(IMPL, "counterfactual replay implementation"))
    checks.append(check_file(SPEC, "contract"))
    checks.extend(check_contains(IMPL, REQUIRED_IMPL_PATTERNS, "impl", strip_comments=True))
    checks.extend(check_contains(MOD_RS, ["pub mod counterfactual_replay;"], "module wiring", strip_comments=True))
    checks.extend(
        check_contains(
            MAIN_RS,
            [
                "incident counterfactual",
                "CounterfactualReplayEngine",
                "counterfactual summary:",
            ],
            "cli wiring",
            strip_comments=True,
        )
    )
    checks.append(check_file(EVIDENCE, "verification evidence"))
    checks.extend(check_rust_tests())
    checks.extend(check_evidence())

    vectors = load_fixture_vectors()
    checks.append(
        {
            "check": "fixture vectors",
            "pass": len(vectors) > 0,
            "detail": f"vectors={len(vectors)}",
        }
    )

    passing = sum(1 for check in checks if check["pass"])
    total = len(checks)
    return {
        "bead_id": "bd-2fa",
        "title": "Counterfactual replay mode for policy simulation",
        "section": "10.5",
        "verdict": "PASS" if passing == total else "FAIL",
        "overall_pass": passing == total,
        "summary": {"passing": passing, "failing": total - passing, "total": total},
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_checks()
    return result["verdict"] == "PASS", result["checks"]


def main() -> None:
    configure_test_logging("check_counterfactual")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        print(f"self_test: {'PASS' if ok else 'FAIL'} ({len(checks)} checks)")
        raise SystemExit(0 if ok else 1)

    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print("=== bd-2fa: counterfactual replay verification ===")
        print(f"Verdict: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"  [{status}] {check['check']}: {check['detail']}")

    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
