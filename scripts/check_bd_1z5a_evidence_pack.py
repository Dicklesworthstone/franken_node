#!/usr/bin/env python3
"""Deterministic coherence checker for the bd-1z5a replacement-gap evidence pack."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


PARENT_BEAD = "bd-1z5a"
SUPPORT_BEAD = "bd-1z5a.14"
TITLE = "bd-1z5a replacement-gap evidence pack coherence"

ARTIFACT_DIR = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD
VERIFICATION_EVIDENCE = ARTIFACT_DIR / "verification_evidence.json"
VERIFICATION_SUMMARY = ARTIFACT_DIR / "verification_summary.md"
REPLAY_FIXTURE_INDEX = ARTIFACT_DIR / "replay_fixture_index.json"
TRACTABILITY_BENCHMARKS = ARTIFACT_DIR / "rch_tractability_benchmarks.json"
OPERATOR_SUMMARY_JSON = ARTIFACT_DIR / "operator_e2e_summary.json"
OPERATOR_SUMMARY_MD = ARTIFACT_DIR / "operator_e2e_summary.md"
OPERATOR_BUNDLE = ARTIFACT_DIR / "operator_e2e_bundle.json"
OPERATOR_LOG = ARTIFACT_DIR / "operator_e2e_log.jsonl"
FRAUD_PROOF_BUNDLE = ARTIFACT_DIR / "fraud_proof_bundle.json"

REQUIRED_FIXTURE_IDS = {
    "capsule_certification_report",
    "capsule_conformance_test",
    "scoreboard_snapshot_report",
    "scoreboard_conformance_test",
    "verifier_economy_checker",
    "connector_verifier_sdk_checker",
    "operator_e2e_harness",
    "operator_e2e_checker",
    "operator_e2e_bundle",
    "fraud_proof_witness_bundle",
    "evidence_pack_coherence_checker",
    "rch_tractability_benchmarks",
}

REQUIRED_STAGE_IDS = [
    "capsule_verify_success",
    "capsule_verify_reject_tampered",
    "capsule_verify_fraud_proof",
    "capsule_verify_quarantine_replay",
    "verifier_score_update",
]

REQUIRED_BENCHMARK_IDS = {
    "external_replay_verification": "test_replay_capsule_match",
    "trust_score_update_publication": "test_events_contain_scoreboard_updated",
}

STALE_GAP_PHRASES = [
    "missing operator shell coverage",
    "missing capsule_verify_* / verifier_score_* markers",
    "missing fraud-proof bundle",
]

REQUIRED_OPERATOR_FIELDS = [
    "trace_id",
    "capsule_id",
    "verifier_id",
    "claim_id",
    "commitment_digest",
    "decision",
    "reason_code",
    "fraud_proof_id",
]

COMPLETION_DEBT_BEAD = "bd-1z5a.27"
COMPLETION_DEBT_REQUIRED_SPEC_ITEMS = {
    "tests.unit.primary",
    "tests.integration.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}

COMPLETION_DEBT_OBLIGATIONS = [
    {
        "spec_item": "tests.unit.primary",
        "category": "unit",
        "status": "covered",
        "description": "checker and shortcut-regression unit tests cover the replacement-gap evidence pack, verifier economy, verifier SDK, and operator E2E bundle contracts",
        "evidence_paths": [
            "tests/test_check_bd_1z5a_evidence_pack.py",
            "tests/test_check_verifier_economy.py",
            "tests/test_check_verifier_sdk.py",
            "tests/test_check_verifier_replay_operator_e2e.py",
        ],
        "commands": [
            "python3 -m unittest tests/test_check_bd_1z5a_evidence_pack.py tests/test_check_verifier_economy.py tests/test_check_verifier_sdk.py tests/test_check_verifier_replay_operator_e2e.py"
        ],
    },
    {
        "spec_item": "tests.integration.primary",
        "category": "integration",
        "status": "covered",
        "description": "conformance fixtures and rch tractability evidence exercise canonical capsule replay, scoreboard updates, and verifier SDK report artifacts",
        "evidence_paths": [
            "tests/conformance/verifier_sdk_capsule_replay.rs",
            "tests/conformance/claim_compiler_gate.rs",
            "artifacts/10.17/verifier_sdk_certification_report.json",
            "artifacts/10.17/public_trust_scoreboard_snapshot.json",
            "artifacts/replacement_gap/bd-1z5a/rch_tractability_benchmarks.json",
        ],
        "commands": [
            "rch exec -- env TMPDIR=/data/tmp CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/data/tmp/rch_target_navyriver_bd1z5a14_match_u2 cargo test -p frankenengine-node --features extended-surfaces test_replay_capsule_match --lib -- --nocapture",
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch_target_navyriver_bd1z5a14_score cargo test -p frankenengine-node test_events_contain_scoreboard_updated --lib -- --nocapture",
        ],
    },
    {
        "spec_item": "tests.e2e.primary",
        "category": "e2e",
        "status": "covered",
        "description": "operator E2E bundle reproduces successful replay verification, forged capsule rejection, fraud-proof extraction, quarantine replay, and scoreboard update logging",
        "evidence_paths": [
            "tests/e2e/verifier_replay_operator_suite.sh",
            "scripts/check_verifier_replay_operator_e2e.py",
            "artifacts/replacement_gap/bd-1z5a/operator_e2e_summary.json",
            "artifacts/replacement_gap/bd-1z5a/operator_e2e_bundle.json",
            "artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl",
            "artifacts/replacement_gap/bd-1z5a/fraud_proof_bundle.json",
        ],
        "commands": [
            "python3 scripts/check_verifier_replay_operator_e2e.py --json",
            "tests/e2e/verifier_replay_operator_suite.sh",
        ],
    },
    {
        "spec_item": "telemetry.primary",
        "category": "telemetry",
        "status": "covered",
        "description": "operator structured logs expose stable CAPSULE_VERIFY_* and VERIFIER_SCORE_* event families with required trace, capsule, verifier, claim, commitment, decision, reason, and fraud-proof fields",
        "evidence_paths": [
            "artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl",
            "artifacts/replacement_gap/bd-1z5a/stage_outputs/stage_results.jsonl",
            "scripts/check_verifier_replay_operator_e2e.py",
        ],
        "required_fields": REQUIRED_OPERATOR_FIELDS,
        "commands": [
            "python3 scripts/check_verifier_replay_operator_e2e.py --json"
        ],
    },
]


def _check(check: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": check, "passed": passed, "detail": detail}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(_read(path))


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in _read(path).splitlines():
        if not line.strip():
            continue
        rows.append(json.loads(line))
    return rows


def _ensure_file(root: Path, rel: str) -> dict[str, Any]:
    path = root / rel
    return _check(
        f"{rel} exists",
        path.is_file(),
        f"exists: {rel}" if path.is_file() else f"missing: {rel}",
    )


def _artifact_paths_from_evidence(evidence: dict[str, Any]) -> list[str]:
    artifacts = evidence.get("artifacts", {})
    if not isinstance(artifacts, dict):
        return []
    return [value for value in artifacts.values() if isinstance(value, str)]


def _fixture_reference_paths(entry: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("path",):
        value = entry.get(key)
        if isinstance(value, str):
            refs.append(value)
    for key in ("inputs", "outputs", "consumed_by", "paired_tests"):
        value = entry.get(key)
        if isinstance(value, list):
            refs.extend(item for item in value if isinstance(item, str))
    return refs


def _benchmark_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("benchmarks")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _benchmark_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for row in rows:
        summary.append(
            {
                "id": row.get("id"),
                "build_id": row.get("build_id"),
                "duration_ms": row.get("duration_ms"),
                "status": row.get("status"),
            }
        )
    return sorted(summary, key=lambda item: str(item.get("id", "")))


def _markdown_build_ids(summary_json: dict[str, Any]) -> str:
    build_ids = summary_json.get("build_ids")
    if not isinstance(build_ids, list) or not build_ids:
        return "`none-detected`"
    joined = ", ".join(str(build_id) for build_id in build_ids)
    return f"`{joined}`"


def _expected_summary_markdown(summary_json: dict[str, Any], bundle: dict[str, Any]) -> str:
    lines = [
        "# bd-1z5a.3 Operator E2E Summary",
        "",
        f"- Trace ID: `{summary_json['trace_id']}`",
        f"- Verdict: **{summary_json['verdict']}**",
        f"- Build IDs: {_markdown_build_ids(summary_json)}",
        "- Build ID Kind: `daemon_build_id` when retained by `rch status --jobs`; otherwise persisted `telemetry_test_run_id` from `~/.local/share/rch/telemetry/telemetry.db`",
        "",
        "| Stage | Event | Decision | Reason | Status | Exit | Build ID | Kind | Worker | Completed | Duration ms |",
        "|---|---|---|---|---|---:|---|---|---|---|---:|",
    ]
    for stage in bundle.get("stage_results", []):
        if not isinstance(stage, dict):
            continue
        build_id = "" if stage.get("build_id") is None else str(stage.get("build_id"))
        exit_code = "" if stage.get("exit_code") is None else str(stage.get("exit_code"))
        build_id_kind = "" if stage.get("build_id_kind") is None else str(stage.get("build_id_kind"))
        worker_id = "" if stage.get("worker_id") is None else str(stage.get("worker_id"))
        completed_at = "" if stage.get("completed_at") is None else str(stage.get("completed_at"))
        duration_ms = "" if stage.get("duration_ms") is None else str(stage.get("duration_ms"))
        lines.append(
            "| {stage_id} | `{event_code}` | `{decision}` | `{reason_code}` | {status} | {exit_code} | `{build_id}` | `{build_id_kind}` | `{worker_id}` | `{completed_at}` | {duration_ms} |".format(
                stage_id=stage.get("stage_id", ""),
                event_code=stage.get("event_code", ""),
                decision=stage.get("decision", ""),
                reason_code=stage.get("reason_code", ""),
                status=stage.get("status", ""),
                exit_code=exit_code,
                build_id=build_id,
                build_id_kind=build_id_kind,
                worker_id=worker_id,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )
        )
    return "\n".join(lines) + "\n"


def _completion_debt_contract() -> dict[str, Any]:
    return {
        "parent_bead": PARENT_BEAD,
        "completion_bead": COMPLETION_DEBT_BEAD,
        "required_spec_items": sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS),
        "coverage_obligations": COMPLETION_DEBT_OBLIGATIONS,
    }


def _completion_debt_coverage(root: Path, log_rows: list[dict[str, Any]]) -> dict[str, Any]:
    coverage_by_item = {
        obligation.get("spec_item"): obligation
        for obligation in COMPLETION_DEBT_OBLIGATIONS
        if isinstance(obligation, dict)
    }
    missing_items = sorted(COMPLETION_DEBT_REQUIRED_SPEC_ITEMS - set(coverage_by_item))
    missing_paths: list[str] = []
    noncovered_items: list[str] = []
    for item, obligation in coverage_by_item.items():
        if obligation.get("status") != "covered":
            noncovered_items.append(str(item))
        for rel_path in obligation.get("evidence_paths", []):
            if isinstance(rel_path, str) and not (root / rel_path).exists():
                missing_paths.append(rel_path)

    telemetry_missing_fields: list[str] = []
    telemetry_obligation = coverage_by_item.get("telemetry.primary")
    if isinstance(telemetry_obligation, dict):
        required_fields = [
            field
            for field in telemetry_obligation.get("required_fields", [])
            if isinstance(field, str)
        ]
        operator_rows = _operator_log_rows(log_rows)
        if not operator_rows:
            telemetry_missing_fields.append("operator_log_rows")
        else:
            for row in operator_rows:
                for field in required_fields:
                    if field not in row:
                        telemetry_missing_fields.append(
                            f"{row.get('event_code', '?')}:{field}"
                        )

    passed = (
        not missing_items
        and not missing_paths
        and not noncovered_items
        and not telemetry_missing_fields
    )
    detail = "all bd-1z5a.27 completion-debt obligations covered"
    if not passed:
        detail = json.dumps(
            {
                "missing_items": missing_items,
                "missing_paths": sorted(missing_paths),
                "noncovered_items": sorted(noncovered_items),
                "telemetry_missing_fields": sorted(set(telemetry_missing_fields)),
            },
            sort_keys=True,
        )
    return _check("completion_debt_bd_1z5a_27_coverage", passed, detail)


def _operator_log_rows(log_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in log_rows
        if isinstance(row, dict)
        and (
            str(row.get("event_code", "")).startswith("CAPSULE_VERIFY_")
            or str(row.get("event_code", "")).startswith("VERIFIER_SCORE_")
        )
    ]


def _stage_row_map(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = bundle.get("stage_results", [])
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("stage_id"), str):
            result[row["stage_id"]] = row
    return result


def _evaluate(root: Path) -> dict[str, Any]:
    tracked_files = [
        str(path.relative_to(ROOT))
        for path in (
            VERIFICATION_EVIDENCE,
            VERIFICATION_SUMMARY,
            REPLAY_FIXTURE_INDEX,
            TRACTABILITY_BENCHMARKS,
            OPERATOR_SUMMARY_JSON,
            OPERATOR_SUMMARY_MD,
            OPERATOR_BUNDLE,
            OPERATOR_LOG,
            FRAUD_PROOF_BUNDLE,
        )
    ]
    checks = [_ensure_file(root, rel) for rel in tracked_files]

    required_paths = [root / rel for rel in tracked_files]
    if not all(path.is_file() for path in required_paths):
        passed = sum(1 for item in checks if item["passed"])
        failed = len(checks) - passed
        return {
            "schema_version": "bd-1z5a-evidence-pack-check-v1.1",
            "bead_id": SUPPORT_BEAD,
            "parent_bead": PARENT_BEAD,
            "title": TITLE,
            "verdict": "FAIL",
            "total": len(checks),
            "passed": passed,
            "failed": failed,
            "checks": checks,
            "coherence_contract": {},
            "completion_debt": _completion_debt_contract(),
        }

    evidence = _read_json(root / VERIFICATION_EVIDENCE.relative_to(ROOT))
    fixture_index = _read_json(root / REPLAY_FIXTURE_INDEX.relative_to(ROOT))
    benchmark_report = _read_json(root / TRACTABILITY_BENCHMARKS.relative_to(ROOT))
    summary_json = _read_json(root / OPERATOR_SUMMARY_JSON.relative_to(ROOT))
    bundle = _read_json(root / OPERATOR_BUNDLE.relative_to(ROOT))
    fraud_bundle = _read_json(root / FRAUD_PROOF_BUNDLE.relative_to(ROOT))
    log_rows = _read_jsonl(root / OPERATOR_LOG.relative_to(ROOT))
    summary_md_text = _read(root / OPERATOR_SUMMARY_MD.relative_to(ROOT))
    verification_summary_text = _read(root / VERIFICATION_SUMMARY.relative_to(ROOT))

    evidence_artifact_paths = _artifact_paths_from_evidence(evidence)
    missing_artifact_refs = sorted(
        rel for rel in evidence_artifact_paths if not (root / rel).exists()
    )
    checks.append(
        _check(
            "verification_evidence artifact paths resolve",
            not missing_artifact_refs,
            "ok" if not missing_artifact_refs else ",".join(missing_artifact_refs),
        )
    )

    evidence_metadata_ok = (
        evidence.get("bead_id") == PARENT_BEAD and evidence.get("support_bead_id") == SUPPORT_BEAD
    )
    checks.append(
        _check(
            "verification evidence metadata matches current support shard",
            evidence_metadata_ok,
            json.dumps(
                {
                    "bead_id": evidence.get("bead_id"),
                    "support_bead_id": evidence.get("support_bead_id"),
                },
                sort_keys=True,
            ),
        )
    )
    checks.append(_completion_debt_coverage(root, log_rows))

    fixtures = fixture_index.get("fixtures", [])
    fixture_ids = {
        fixture.get("id")
        for fixture in fixtures
        if isinstance(fixture, dict) and isinstance(fixture.get("id"), str)
    }
    missing_fixture_ids = sorted(REQUIRED_FIXTURE_IDS - fixture_ids)
    checks.append(
        _check(
            "replay fixture index exposes required fixture ids",
            not missing_fixture_ids,
            "ok" if not missing_fixture_ids else ",".join(missing_fixture_ids),
        )
    )

    missing_fixture_paths: list[str] = []
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            continue
        for rel in _fixture_reference_paths(fixture):
            if not (root / rel).exists():
                missing_fixture_paths.append(rel)
    checks.append(
        _check(
            "replay fixture index reference paths resolve",
            not missing_fixture_paths,
            "ok" if not missing_fixture_paths else ",".join(sorted(set(missing_fixture_paths))),
        )
    )

    fixture_index_metadata_ok = (
        fixture_index.get("bead_id") == PARENT_BEAD
        and fixture_index.get("support_bead_id") == SUPPORT_BEAD
    )
    checks.append(
        _check(
            "replay fixture index metadata matches current support shard",
            fixture_index_metadata_ok,
            json.dumps(
                {
                    "bead_id": fixture_index.get("bead_id"),
                    "support_bead_id": fixture_index.get("support_bead_id"),
                },
                sort_keys=True,
            ),
        )
    )

    benchmark_rows = _benchmark_rows(benchmark_report)
    benchmark_metadata_ok = (
        benchmark_report.get("artifact_type") == "rch_tractability_benchmarks"
        and benchmark_report.get("bead_id") == PARENT_BEAD
        and benchmark_report.get("support_bead_id") == SUPPORT_BEAD
        and benchmark_report.get("verdict") == "PASS"
    )
    checks.append(
        _check(
            "tractability benchmark metadata matches current support shard",
            benchmark_metadata_ok,
            json.dumps(
                {
                    "artifact_type": benchmark_report.get("artifact_type"),
                    "bead_id": benchmark_report.get("bead_id"),
                    "support_bead_id": benchmark_report.get("support_bead_id"),
                    "verdict": benchmark_report.get("verdict"),
                },
                sort_keys=True,
            ),
        )
    )

    benchmark_ids = {
        row.get("id")
        for row in benchmark_rows
        if isinstance(row.get("id"), str)
    }
    missing_benchmark_ids = sorted(set(REQUIRED_BENCHMARK_IDS) - benchmark_ids)
    checks.append(
        _check(
            "tractability benchmark report exposes required lane ids",
            not missing_benchmark_ids,
            "ok" if not missing_benchmark_ids else ",".join(missing_benchmark_ids),
        )
    )

    measurement_policy = benchmark_report.get("measurement_policy")
    budget_ms = (
        measurement_policy.get("max_duration_ms")
        if isinstance(measurement_policy, dict)
        else None
    )
    budget_valid = isinstance(budget_ms, int) and budget_ms > 0
    checks.append(
        _check(
            "tractability benchmark report declares positive budget",
            budget_valid,
            json.dumps({"max_duration_ms": budget_ms}, sort_keys=True),
        )
    )

    command_mismatches: list[str] = []
    benchmark_failures: list[dict[str, Any]] = []
    benchmark_row_map = {
        row["id"]: row
        for row in benchmark_rows
        if isinstance(row.get("id"), str)
    }
    for benchmark_id, expected_probe in REQUIRED_BENCHMARK_IDS.items():
        row = benchmark_row_map.get(benchmark_id)
        if not isinstance(row, dict):
            continue
        command = row.get("command")
        if not isinstance(command, str) or expected_probe not in command:
            command_mismatches.append(benchmark_id)

        duration_ms = row.get("duration_ms")
        build_id = row.get("build_id")
        exit_code = row.get("exit_code")
        status = row.get("status")
        timing = row.get("timing")
        timing_total = timing.get("total") if isinstance(timing, dict) else None
        timing_total_matches = (
            timing_total is None
            or (
                isinstance(timing_total, int)
                and isinstance(duration_ms, int)
                and abs(timing_total - duration_ms) <= 1
            )
        )
        passed = (
            isinstance(build_id, int)
            and build_id > 0
            and status == "PASS"
            and exit_code == 0
            and isinstance(duration_ms, int)
            and duration_ms > 0
            and budget_valid
            and duration_ms <= budget_ms
            and timing_total_matches
        )
        if not passed:
            benchmark_failures.append(
                {
                    "id": benchmark_id,
                    "build_id": build_id,
                    "duration_ms": duration_ms,
                    "exit_code": exit_code,
                    "status": status,
                    "timing_total": timing_total,
                }
            )

    checks.append(
        _check(
            "tractability benchmark commands match expected probes",
            not command_mismatches,
            "ok" if not command_mismatches else ",".join(command_mismatches),
        )
    )
    checks.append(
        _check(
            "tractability benchmark lanes pass within declared budget",
            not benchmark_failures,
            "ok" if not benchmark_failures else json.dumps(benchmark_failures, sort_keys=True),
        )
    )

    fixture_benchmark_summary = fixture_index.get("rch_tractability_benchmarks")
    fixture_benchmark_summary_ok = isinstance(fixture_benchmark_summary, list) and _benchmark_summary(
        [row for row in fixture_benchmark_summary if isinstance(row, dict)]
    ) == _benchmark_summary(benchmark_rows)
    checks.append(
        _check(
            "fixture index benchmark summary matches benchmark report",
            fixture_benchmark_summary_ok,
            json.dumps(fixture_benchmark_summary, sort_keys=True),
        )
    )

    benchmark_summary_referenced = (
        "rch_tractability_benchmarks.json" in verification_summary_text
        and all(
            str(row.get("build_id")) in verification_summary_text
            for row in benchmark_rows
            if isinstance(row.get("build_id"), int)
        )
    )
    checks.append(
        _check(
            "verification summary references tractability benchmark artifact and build ids",
            benchmark_summary_referenced,
            "ok" if benchmark_summary_referenced else "verification_summary.md missing benchmark artifact path or build ids",
        )
    )

    bundle_stage_map = _stage_row_map(bundle)
    summary_stage_ids = summary_json.get("stage_ids", [])
    summary_stage_ids_ok = isinstance(summary_stage_ids, list) and summary_stage_ids == list(bundle_stage_map)
    checks.append(
        _check(
            "operator summary json stage ids match bundle order",
            summary_stage_ids_ok,
            json.dumps(summary_stage_ids),
        )
    )

    required_stages_missing = [stage_id for stage_id in REQUIRED_STAGE_IDS if stage_id not in bundle_stage_map]
    checks.append(
        _check(
            "operator bundle includes all required stage ids",
            not required_stages_missing,
            "ok" if not required_stages_missing else ",".join(required_stages_missing),
        )
    )

    trace_ids = {
        str(value)
        for value in (
            summary_json.get("trace_id"),
            bundle.get("trace_id"),
            fraud_bundle.get("trace_id"),
        )
        if isinstance(value, str)
    }
    operator_log_trace_ids = {str(row.get("trace_id", "")) for row in _operator_log_rows(log_rows)}
    trace_ok = len(trace_ids) == 1 and operator_log_trace_ids == trace_ids
    checks.append(
        _check(
            "replacement-gap trace binding is coherent across summary bundle log and fraud witness",
            trace_ok,
            json.dumps(
                {
                    "summary_bundle_fraud": sorted(trace_ids),
                    "operator_log": sorted(operator_log_trace_ids),
                },
                sort_keys=True,
            ),
        )
    )

    fraud_stage = bundle_stage_map.get("capsule_verify_fraud_proof")
    fraud_log_rows = [
        row
        for row in log_rows
        if row.get("stage_id") == "capsule_verify_fraud_proof"
        and row.get("trace_id") == fraud_bundle.get("trace_id")
    ]
    fraud_finish_row = next(
        (
            row
            for row in fraud_log_rows
            if row.get("event_code") == "CAPSULE_VERIFY_FRAUD_PROOF_EXTRACTED"
        ),
        None,
    )
    fraud_start_present = any(
        row.get("event_code") == "CAPSULE_VERIFY_FRAUD_PROOF_STARTED" for row in fraud_log_rows
    )
    fraud_links_ok = (
        isinstance(fraud_stage, dict)
        and isinstance(fraud_finish_row, dict)
        and fraud_start_present
        and fraud_bundle.get("stage_id") == "capsule_verify_fraud_proof"
        and fraud_bundle.get("event_code") == fraud_stage.get("event_code") == fraud_finish_row.get("event_code")
        and fraud_bundle.get("fraud_proof_id") == fraud_stage.get("fraud_proof_id") == fraud_finish_row.get("fraud_proof_id")
        and fraud_bundle.get("commitment_digest") == fraud_stage.get("commitment_digest") == fraud_finish_row.get("commitment_digest")
        and fraud_bundle.get("reason_code") == fraud_stage.get("reason_code") == fraud_finish_row.get("reason_code")
    )
    checks.append(
        _check(
            "fraud proof witness matches operator bundle and structured log",
            fraud_links_ok,
            json.dumps(
                {
                    "fraud_stage_present": isinstance(fraud_stage, dict),
                    "fraud_start_present": fraud_start_present,
                    "fraud_finish_present": isinstance(fraud_finish_row, dict),
                },
                sort_keys=True,
            ),
        )
    )

    missing_fraud_source_paths = sorted(
        rel
        for rel in fraud_bundle.get("source_artifacts", {}).values()
        if isinstance(rel, str) and not (root / rel).exists()
    )
    checks.append(
        _check(
            "fraud proof source artifact paths resolve",
            not missing_fraud_source_paths,
            "ok" if not missing_fraud_source_paths else ",".join(missing_fraud_source_paths),
        )
    )

    expected_summary_md = _expected_summary_markdown(summary_json, bundle)
    checks.append(
        _check(
            "operator summary markdown matches canonical bundle rendering",
            summary_md_text == expected_summary_md,
            "ok" if summary_md_text == expected_summary_md else "operator_e2e_summary.md drifted from bundle/json source of truth",
        )
    )

    markdown_stage_lines = [
        line
        for line in summary_md_text.splitlines()
        if line.startswith("| ")
        and not line.startswith("| Stage ")
        and not line.startswith("|---")
    ]
    markdown_stage_ids = [line.split("|")[1].strip() for line in markdown_stage_lines]
    summary_rows_ok = (
        markdown_stage_ids == REQUIRED_STAGE_IDS
        and len(markdown_stage_ids) == len(set(markdown_stage_ids))
    )
    checks.append(
        _check(
            "operator summary markdown has one canonical row per required stage",
            summary_rows_ok,
            json.dumps(markdown_stage_ids),
        )
    )

    stale_phrases_found = [
        phrase for phrase in STALE_GAP_PHRASES if phrase in verification_summary_text.lower()
    ]
    checks.append(
        _check(
            "verification summary does not reintroduce stale gap language",
            not stale_phrases_found,
            "ok" if not stale_phrases_found else ",".join(stale_phrases_found),
        )
    )

    coherence_contract = {
        "artifact_paths_resolve": not missing_artifact_refs,
        "completion_debt_coverage": checks[-1]["passed"],
        "fixture_index_resolves": not missing_fixture_paths and not missing_fixture_ids,
        "fraud_witness_links_consistent": fraud_links_ok and not missing_fraud_source_paths,
        "summary_markdown_matches_bundle": summary_md_text == expected_summary_md and summary_rows_ok,
        "stale_gap_language_absent": not stale_phrases_found,
        "tractability_benchmarks_resolve": (
            benchmark_metadata_ok
            and not missing_benchmark_ids
            and budget_valid
            and not command_mismatches
            and not benchmark_failures
            and fixture_benchmark_summary_ok
            and benchmark_summary_referenced
        ),
    }

    passed = sum(1 for item in checks if item["passed"])
    failed = len(checks) - passed
    return {
        "schema_version": "bd-1z5a-evidence-pack-check-v1.1",
        "bead_id": SUPPORT_BEAD,
        "parent_bead": PARENT_BEAD,
        "title": TITLE,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "coherence_contract": coherence_contract,
        "completion_debt": _completion_debt_contract(),
    }


def run_checks(root: Path = ROOT) -> dict[str, Any]:
    return _evaluate(root)


def _write_text(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _materialize_self_test_fixture(root: Path) -> None:
    evidence = _read_json(VERIFICATION_EVIDENCE)
    fixture_index = _read_json(REPLAY_FIXTURE_INDEX)
    benchmark_report = _read_json(TRACTABILITY_BENCHMARKS)
    summary_json = _read_json(OPERATOR_SUMMARY_JSON)
    bundle = _read_json(OPERATOR_BUNDLE)
    fraud_bundle = _read_json(FRAUD_PROOF_BUNDLE)
    log_text = _read(OPERATOR_LOG)
    verification_summary_text = _read(VERIFICATION_SUMMARY)

    _write_text(root, str(VERIFICATION_EVIDENCE.relative_to(ROOT)), json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(REPLAY_FIXTURE_INDEX.relative_to(ROOT)), json.dumps(fixture_index, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(TRACTABILITY_BENCHMARKS.relative_to(ROOT)), json.dumps(benchmark_report, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_SUMMARY_JSON.relative_to(ROOT)), json.dumps(summary_json, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_BUNDLE.relative_to(ROOT)), json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(FRAUD_PROOF_BUNDLE.relative_to(ROOT)), json.dumps(fraud_bundle, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_LOG.relative_to(ROOT)), log_text)
    _write_text(root, str(VERIFICATION_SUMMARY.relative_to(ROOT)), verification_summary_text)
    _write_text(root, str(OPERATOR_SUMMARY_MD.relative_to(ROOT)), _expected_summary_markdown(summary_json, bundle))

    synthetic_fixture_paths = set(_artifact_paths_from_evidence(evidence))
    synthetic_fixture_paths.update(
        rel
        for fixture in fixture_index.get("fixtures", [])
        if isinstance(fixture, dict)
        for rel in _fixture_reference_paths(fixture)
    )
    synthetic_fixture_paths.update(bundle.get("replay_inputs", []))
    synthetic_fixture_paths.update(
        value
        for value in fraud_bundle.get("source_artifacts", {}).values()
        if isinstance(value, str)
    )
    synthetic_fixture_paths.update(
        rel
        for obligation in COMPLETION_DEBT_OBLIGATIONS
        if isinstance(obligation, dict)
        for rel in obligation.get("evidence_paths", [])
        if isinstance(rel, str)
    )
    synthetic_fixture_paths.add(bundle.get("summary_path", ""))
    synthetic_fixture_paths.add(bundle.get("structured_log_path", ""))
    synthetic_fixture_paths.update(
        rel
        for stage in bundle.get("stage_results", [])
        if isinstance(stage, dict)
        for rel in (stage.get("stdout_path"), stage.get("stderr_path"))
        if isinstance(rel, str)
    )

    already_written = {
        str(VERIFICATION_EVIDENCE.relative_to(ROOT)),
        str(REPLAY_FIXTURE_INDEX.relative_to(ROOT)),
        str(TRACTABILITY_BENCHMARKS.relative_to(ROOT)),
        str(OPERATOR_SUMMARY_JSON.relative_to(ROOT)),
        str(OPERATOR_SUMMARY_MD.relative_to(ROOT)),
        str(OPERATOR_BUNDLE.relative_to(ROOT)),
        str(OPERATOR_LOG.relative_to(ROOT)),
        str(FRAUD_PROOF_BUNDLE.relative_to(ROOT)),
        str(VERIFICATION_SUMMARY.relative_to(ROOT)),
    }
    for rel in sorted(path for path in synthetic_fixture_paths if isinstance(path, str) and path):
        if rel in already_written:
            continue
        _write_text(root, rel, "synthetic evidence fixture\n")


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        _materialize_self_test_fixture(root)
        baseline = run_checks(root)
        if baseline["verdict"] != "PASS":
            return {"verdict": "FAIL", "detail": "baseline fixture did not pass", "baseline": baseline}

        summary_path = root / VERIFICATION_SUMMARY.relative_to(ROOT)
        summary_path.write_text(summary_path.read_text(encoding="utf-8") + "\nmissing fraud-proof bundle\n", encoding="utf-8")
        mutated = run_checks(root)
        return {
            "verdict": "PASS" if mutated["verdict"] == "FAIL" else "FAIL",
            "detail": "mutation produced FAIL as expected" if mutated["verdict"] == "FAIL" else "mutation did not fail",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="run internal consistency checks")
    args = parser.parse_args(argv)

    logger = configure_test_logging("check_bd_1z5a_evidence_pack", json_mode=args.json)

    if args.self_test:
        payload = self_test()
        logger.info("self-test complete", extra={"verdict": payload["verdict"]})
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(payload["detail"])
        return 0 if payload["verdict"] == "PASS" else 1

    payload = run_checks()
    logger.info(
        "evidence pack coherence scan complete",
        extra={"verdict": payload["verdict"], "passed": payload["passed"], "failed": payload["failed"]},
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"{SUPPORT_BEAD} evidence pack coherence: {payload['verdict']} "
            f"({payload['passed']}/{payload['total']} checks passed)"
        )
        for check in payload["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"- [{status}] {check['check']}: {check['detail']}")
    return 0 if payload["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
