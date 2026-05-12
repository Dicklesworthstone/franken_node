#!/usr/bin/env python3
"""Verification script for bd-v97o: Authenticated control channel."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL_PATH = ROOT / "crates/franken-node/src/connector/control_channel.rs"
VECTORS_PATH = ROOT / "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json"
INTEG_PATH = ROOT / "tests/integration/control_channel_replay.rs"
SPEC_PATH = ROOT / "docs/specs/section_10_13/bd-v97o_contract.md"
EVIDENCE_PATH = ROOT / "artifacts/section_10_13/bd-v97o/verification_evidence.json"
OPERATOR_E2E_PATH = ROOT / "tests/e2e/control_channel_operator_suite.sh"
REPLACEMENT_EVIDENCE_DIR = ROOT / "artifacts/replacement_gap/bd-3cvu"
REPLACEMENT_EVIDENCE_PATH = REPLACEMENT_EVIDENCE_DIR / "verification_evidence.json"
REPLACEMENT_SUMMARY_PATH = REPLACEMENT_EVIDENCE_DIR / "verification_summary.md"
OPERATOR_LOG_PATH = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_log.jsonl"
OPERATOR_SUMMARY_PATH = REPLACEMENT_EVIDENCE_DIR / "operator_e2e_summary.json"
PROTOCOL_VECTOR_INDEX_PATH = REPLACEMENT_EVIDENCE_DIR / "protocol_vector_index.json"
JSON_DECODER = json.JSONDecoder()

COMPLETION_DEBT_BEAD = "bd-3cvu.1"
REPLACEMENT_BEAD = "bd-3cvu"
COMPLETION_DEBT_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
}

REQUIRED_TRANSCRIPT_SOURCE_MARKERS = [
    "struct ChannelCredential",
    "struct TranscriptFields",
    "TRANSCRIPT_HMAC_PREFIX",
    "sign_channel_message",
    "compute_transcript_mac",
    "verify_transcript_mac",
    "constant_time::ct_eq_bytes",
    "regression_non_empty_string_is_not_sufficient",
    "reject_credential_signed_for_different_audience",
    "adversarial_wrong_direction_replay",
    "adversarial_payload_swap_under_reused_auth",
    "stale_authenticated_epoch_is_rejected_after_epoch_advances",
    "same_nonce_reuse_across_directions_is_rejected",
]

REQUIRED_UNIT_TEST_MARKERS = [
    "accept_valid_message",
    "reject_forged_credential",
    "adversarial_guessed_token_injection",
    "regression_non_empty_string_is_not_sufficient",
    "reject_credential_signed_for_different_audience",
    "adversarial_wrong_direction_replay",
    "immediate_same_sequence_replay_is_replay_not_sequence_regress",
    "same_nonce_reuse_across_directions_is_rejected",
    "prop_sign_verify_round_trip_for_random_valid_fields",
]

REQUIRED_INTEGRATION_TEST_MARKERS = [
    "inv_acc_authenticated",
    "inv_acc_monotonic",
    "inv_acc_replay_window",
    "inv_acc_auditable",
]

REQUIRED_E2E_SCENARIOS = [
    "valid_control_traffic",
    "guessed_token_injection_failure",
    "replay_failure_after_restart_boundary",
    "capability_attenuation_failure",
]

COMPLETION_DEBT_REQUIRED_PATHS = {
    "tests.unit.primary": [
        "crates/franken-node/src/connector/control_channel.rs",
        "tests/test_check_control_channel.py",
    ],
    "tests.integration.primary": [
        "tests/integration/control_channel_replay.rs",
        "artifacts/section_10_13/bd-v97o/control_channel_replay_vectors.json",
    ],
    "tests.e2e.primary": [
        "tests/e2e/control_channel_operator_suite.sh",
        "artifacts/replacement_gap/bd-3cvu/operator_e2e_log.jsonl",
        "artifacts/replacement_gap/bd-3cvu/operator_e2e_summary.json",
        "artifacts/replacement_gap/bd-3cvu/protocol_vector_index.json",
    ],
}

COMPLETION_DEBT_REQUIRED_TEST_NAMES = {
    "tests.unit.primary": REQUIRED_UNIT_TEST_MARKERS,
    "tests.integration.primary": REQUIRED_INTEGRATION_TEST_MARKERS,
    "tests.e2e.primary": REQUIRED_E2E_SCENARIOS,
}


def read_utf8(path: Path) -> str | None:
    """Read a UTF-8 text file and return None for missing/unreadable paths."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def load_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Load a JSON object and return an explanatory error for invalid evidence."""
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = JSON_DECODER.decode(raw)
    except OSError as exc:
        return None, f"unable to read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"

    if not isinstance(parsed, dict):
        return None, f"expected JSON object in {path}"
    return parsed, None


def load_jsonl(path: Path) -> tuple[list[dict[str, object]], str | None]:
    rows: list[dict[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return rows, f"unable to read {path}: {exc}"
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            parsed = JSON_DECODER.decode(line)
        except json.JSONDecodeError as exc:
            return rows, f"invalid JSONL in {path}:{lineno}: {exc}"
        if not isinstance(parsed, dict):
            return rows, f"expected JSON object in {path}:{lineno}"
        rows.append(parsed)
    return rows, None


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def record_check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    status: str,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    entry = {"id": check_id, "description": description, "status": status}
    if details:
        entry["details"] = details
    checks.append(entry)
    if emit_human:
        print(f"  [{status}] {check_id}: {description}")
        if details:
            print(f"         {details}")
    return status == "PASS"


def check(
    checks: list[dict[str, str]],
    check_id: str,
    description: str,
    passed: bool,
    details: str | None = None,
    *,
    emit_human: bool,
) -> bool:
    return record_check(
        checks,
        check_id,
        description,
        "PASS" if passed else "FAIL",
        details,
        emit_human=emit_human,
    )


def run_rust_tests() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["rch", "exec", "--", "cargo", "test", "-p", "frankenengine-node", "--", "connector::control_channel"],
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=ROOT / "crates/franken-node",
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, str(exc)

    test_output = result.stdout + result.stderr
    matches = re.findall(r"test result: ok\. (\d+) passed", test_output)
    rust_tests = sum(int(match) for match in matches)
    tests_pass = result.returncode == 0 and rust_tests > 0
    return tests_pass, f"{rust_tests} tests passed"


def build_evidence(checks: list[dict[str, str]], mode: str) -> dict[str, object]:
    passing = sum(1 for check_entry in checks if check_entry["status"] == "PASS")
    failing = sum(1 for check_entry in checks if check_entry["status"] == "FAIL")
    skipped = sum(1 for check_entry in checks if check_entry["status"] == "SKIP")
    total = len(checks)
    return {
        "gate": "control_channel_verification",
        "bead": "bd-v97o",
        "section": "10.13",
        "mode": mode,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "checks": checks,
        "summary": {
            "total_checks": total,
            "passing_checks": passing,
            "failing_checks": failing,
            "skipped_checks": skipped,
        },
    }


def _contains_all(content: str | None, markers: list[str]) -> tuple[bool, str]:
    if content is None:
        return False, "file missing"
    missing = [marker for marker in markers if marker not in content]
    return not missing, "all found" if not missing else "missing: " + ", ".join(missing)


def check_completion_debt_evidence(checks: list[dict[str, str]], *, emit_human: bool) -> None:
    data, error = load_json_object(REPLACEMENT_EVIDENCE_PATH)
    check(
        checks,
        "ACC-COMPLETION-EVIDENCE",
        "bd-3cvu.1 completion-debt evidence pack",
        data is not None,
        error or rel(REPLACEMENT_EVIDENCE_PATH),
        emit_human=emit_human,
    )
    if data is None:
        return

    check(
        checks,
        "ACC-COMPLETION-BEAD",
        "Completion-debt bead id recorded",
        data.get("completion_debt_bead_id") == COMPLETION_DEBT_BEAD
        and data.get("bead_id") == REPLACEMENT_BEAD,
        f"bead={data.get('bead_id')} completion={data.get('completion_debt_bead_id')}",
        emit_human=emit_human,
    )

    completion_debt = data.get("completion_debt", {})
    if not isinstance(completion_debt, dict):
        check(
            checks,
            "ACC-COMPLETION-SHAPE",
            "Completion-debt section is an object",
            False,
            "completion_debt missing or non-object",
            emit_human=emit_human,
        )
        return

    covered = set(completion_debt.get("covered_spec_items", []))
    check(
        checks,
        "ACC-COMPLETION-ITEMS",
        "All audit-missing test items are covered",
        COMPLETION_DEBT_ITEMS.issubset(covered),
        ", ".join(sorted(covered)) if covered else "none",
        emit_human=emit_human,
    )

    obligations = {
        item.get("spec_item"): item
        for item in completion_debt.get("obligations", [])
        if isinstance(item, dict)
    }
    for spec_item in sorted(COMPLETION_DEBT_ITEMS):
        obligation = obligations.get(spec_item)
        check(
            checks,
            f"ACC-COMPLETION-{spec_item}-OBLIGATION",
            f"{spec_item} obligation exists",
            obligation is not None,
            "present" if obligation else "missing",
            emit_human=emit_human,
        )
        if not isinstance(obligation, dict):
            continue

        evidence_paths = set(obligation.get("evidence_paths", []))
        required_paths = set(COMPLETION_DEBT_REQUIRED_PATHS[spec_item])
        check(
            checks,
            f"ACC-COMPLETION-{spec_item}-PATHS",
            f"{spec_item} cites required evidence paths",
            required_paths.issubset(evidence_paths),
            ", ".join(sorted(evidence_paths)) if evidence_paths else "none",
            emit_human=emit_human,
        )
        missing_paths = [path for path in evidence_paths if not (ROOT / path).exists()]
        check(
            checks,
            f"ACC-COMPLETION-{spec_item}-FILES",
            f"{spec_item} cited paths exist",
            not missing_paths,
            "all paths exist" if not missing_paths else ", ".join(missing_paths),
            emit_human=emit_human,
        )

        test_names = set(obligation.get("test_names", []))
        required_tests = set(COMPLETION_DEBT_REQUIRED_TEST_NAMES[spec_item])
        check(
            checks,
            f"ACC-COMPLETION-{spec_item}-TESTS",
            f"{spec_item} cites required test names",
            required_tests.issubset(test_names),
            ", ".join(sorted(test_names)) if test_names else "none",
            emit_human=emit_human,
        )


def check_operator_e2e(checks: list[dict[str, str]], *, emit_human: bool) -> None:
    e2e_content = read_utf8(OPERATOR_E2E_PATH)
    ok, details = _contains_all(e2e_content, REQUIRED_E2E_SCENARIOS)
    check(
        checks,
        "ACC-E2E-SCRIPT",
        "Operator E2E suite covers required scenarios",
        OPERATOR_E2E_PATH.is_file() and ok,
        details if OPERATOR_E2E_PATH.is_file() else f"missing {rel(OPERATOR_E2E_PATH)}",
        emit_human=emit_human,
    )

    summary, summary_error = load_json_object(OPERATOR_SUMMARY_PATH)
    check(
        checks,
        "ACC-E2E-SUMMARY",
        "Operator E2E summary passes",
        summary is not None and summary.get("verdict") == "PASS",
        summary_error or str(summary.get("verdict") if summary else "missing"),
        emit_human=emit_human,
    )

    rows, rows_error = load_jsonl(OPERATOR_LOG_PATH)
    scenarios = {row.get("scenario") for row in rows}
    required_fields = {
        "trace_id",
        "event",
        "scenario",
        "decision",
        "reason_code",
        "retryable",
        "channel_id",
        "subject_id",
        "audience",
        "direction",
        "sequence",
        "freshness_state",
    }
    fields_ok = all(required_fields.issubset(row.keys()) for row in rows)
    check(
        checks,
        "ACC-E2E-LOG",
        "Operator E2E JSONL has scenarios and structured fields",
        rows_error is None and set(REQUIRED_E2E_SCENARIOS).issubset(scenarios) and fields_ok,
        rows_error
        or f"scenarios={','.join(sorted(str(s) for s in scenarios))} rows={len(rows)}",
        emit_human=emit_human,
    )

    vector_index, vector_error = load_json_object(PROTOCOL_VECTOR_INDEX_PATH)
    covered = set(vector_index.get("operator_scenarios", [])) if vector_index else set()
    check(
        checks,
        "ACC-E2E-VECTOR-INDEX",
        "Protocol vector index references operator scenarios",
        vector_index is not None and set(REQUIRED_E2E_SCENARIOS).issubset(covered),
        vector_error or ", ".join(sorted(covered)),
        emit_human=emit_human,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit evidence JSON to stdout")
    parser.add_argument(
        "--run-rust-tests",
        action="store_true",
        help="run the expensive rch cargo test proof even in JSON mode",
    )
    parser.add_argument(
        "--structural-only",
        action="store_true",
        help="skip the expensive Rust test proof and only validate checked-in structure",
    )
    parser.add_argument(
        "--write-evidence",
        action="store_true",
        help="write artifacts/section_10_13/bd-v97o/verification_evidence.json; human mode writes by default",
    )
    args = parser.parse_args(argv)
    if args.run_rust_tests and args.structural_only:
        parser.error("--run-rust-tests and --structural-only are mutually exclusive")
    return args


def run_checks(*, run_tests: bool, emit_human: bool) -> dict[str, object]:
    checks: list[dict[str, str]] = []
    if emit_human:
        print("bd-v97o: Authenticated Control Channel - Verification\n")

    content = read_utf8(IMPL_PATH)
    impl_exists = content is not None
    if content is not None:
        has_config = "struct ChannelConfig" in content
        has_msg = "struct ChannelMessage" in content
        has_result = "struct AuthCheckResult" in content
        has_channel = "struct ControlChannel" in content
        has_process = "fn process_message" in content
        all_types = has_config and has_msg and has_result and has_channel and has_process
    else:
        all_types = False
    check(
        checks,
        "ACC-IMPL",
        "Implementation with all required types",
        impl_exists and all_types,
        emit_human=emit_human,
    )

    ok, details = _contains_all(content, REQUIRED_TRANSCRIPT_SOURCE_MARKERS)
    check(
        checks,
        "ACC-TRANSCRIPT-BINDING",
        "Transcript-bound capability verification markers",
        ok,
        details,
        emit_human=emit_human,
    )

    ok, details = _contains_all(content, REQUIRED_UNIT_TEST_MARKERS)
    check(
        checks,
        "ACC-UNIT-COVERAGE",
        "Unit/adversarial tests cover transcript and shortcut regressions",
        ok,
        details,
        emit_human=emit_human,
    )

    if content is not None:
        errors = ["ACC_AUTH_FAILED", "ACC_SEQUENCE_REGRESS", "ACC_REPLAY_DETECTED",
                  "ACC_INVALID_CONFIG", "ACC_CHANNEL_CLOSED"]
        found = [e for e in errors if e in content]
        check(
            checks,
            "ACC-ERRORS",
            "All 5 error codes present",
            len(found) == 5,
            f"found {len(found)}/5",
            emit_human=emit_human,
        )
    else:
        check(checks, "ACC-ERRORS", "Error codes", False, emit_human=emit_human)

    vectors_valid = False
    vectors_details = None
    vector_data, vector_error = load_json_object(VECTORS_PATH)
    if vector_data is not None:
        vectors = vector_data.get("vectors")
        vectors_valid = isinstance(vectors, list) and len(vectors) >= 3
        vectors_details = f"found {len(vectors) if isinstance(vectors, list) else 0} vectors"
    elif vector_error:
        vectors_details = vector_error
    check(
        checks,
        "ACC-VECTORS",
        "Control channel replay vectors",
        vectors_valid,
        vectors_details,
        emit_human=emit_human,
    )

    integration_content = read_utf8(INTEG_PATH)
    integ_exists = integration_content is not None
    if integration_content is not None:
        has_auth = "inv_acc_authenticated" in integration_content
        has_mono = "inv_acc_monotonic" in integration_content
        has_replay = "inv_acc_replay_window" in integration_content
        has_audit = "inv_acc_auditable" in integration_content
    else:
        has_auth = has_mono = has_replay = has_audit = False
    check(
        checks,
        "ACC-INTEG",
        "Integration tests cover all 4 invariants",
        integ_exists and has_auth and has_mono and has_replay and has_audit,
        emit_human=emit_human,
    )

    check_operator_e2e(checks, emit_human=emit_human)

    if run_tests:
        tests_pass, details = run_rust_tests()
        check(
            checks,
            "ACC-TESTS",
            "Rust unit tests pass",
            tests_pass,
            details,
            emit_human=emit_human,
        )
    else:
        record_check(
            checks,
            "ACC-TESTS",
            "Rust unit tests pass",
            "SKIP",
            "not run in structural mode; use --run-rust-tests for the full proof",
            emit_human=emit_human,
        )

    spec_content = read_utf8(SPEC_PATH)
    spec_exists = spec_content is not None
    if spec_content is not None:
        has_invariants = "INV-ACC" in spec_content
        has_types = "ChannelConfig" in spec_content and "ChannelMessage" in spec_content
    else:
        has_invariants = has_types = False
    check(
        checks,
        "ACC-SPEC",
        "Specification with invariants and types",
        spec_exists and has_invariants and has_types,
        emit_human=emit_human,
    )

    check_completion_debt_evidence(checks, emit_human=emit_human)

    evidence = build_evidence(checks, "full" if run_tests else "structural")
    if emit_human:
        summary = evidence["summary"]
        print(
            f"\nResult: {summary['passing_checks']}/{summary['total_checks']} checks passed"
            f" ({summary['skipped_checks']} skipped)"
        )
    return evidence


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    run_tests = args.run_rust_tests or (not args.json and not args.structural_only)
    write_artifact = args.write_evidence or not args.json
    logger = configure_test_logging("check_control_channel")
    logger.info(
        "starting verification",
        extra={"json_mode": args.json, "run_rust_tests": run_tests, "write_evidence": write_artifact},
    )

    evidence = run_checks(run_tests=run_tests, emit_human=not args.json)

    if write_artifact:
        write_evidence(EVIDENCE_PATH, evidence)

    if args.json:
        print(json.dumps(evidence, indent=2))

    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
