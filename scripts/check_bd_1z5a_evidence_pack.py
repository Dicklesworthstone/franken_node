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
SUPPORT_BEAD = "bd-1z5a.9"
TITLE = "bd-1z5a replacement-gap evidence pack coherence"

ARTIFACT_DIR = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD
VERIFICATION_EVIDENCE = ARTIFACT_DIR / "verification_evidence.json"
VERIFICATION_SUMMARY = ARTIFACT_DIR / "verification_summary.md"
REPLAY_FIXTURE_INDEX = ARTIFACT_DIR / "replay_fixture_index.json"
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
}

REQUIRED_STAGE_IDS = [
    "capsule_verify_success",
    "capsule_verify_reject_tampered",
    "capsule_verify_fraud_proof",
    "capsule_verify_quarantine_replay",
    "verifier_score_update",
]

STALE_GAP_PHRASES = [
    "missing operator shell coverage",
    "missing capsule_verify_* / verifier_score_* markers",
    "missing fraud-proof bundle",
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
        "",
        "| Stage | Event | Decision | Reason | Status | Exit | Build ID |",
        "|---|---|---|---|---|---:|---|",
    ]
    for stage in bundle.get("stage_results", []):
        if not isinstance(stage, dict):
            continue
        build_id = "" if stage.get("build_id") is None else str(stage.get("build_id"))
        exit_code = "" if stage.get("exit_code") is None else str(stage.get("exit_code"))
        lines.append(
            "| {stage_id} | `{event_code}` | `{decision}` | `{reason_code}` | {status} | {exit_code} | `{build_id}` |".format(
                stage_id=stage.get("stage_id", ""),
                event_code=stage.get("event_code", ""),
                decision=stage.get("decision", ""),
                reason_code=stage.get("reason_code", ""),
                status=stage.get("status", ""),
                exit_code=exit_code,
                build_id=build_id,
            )
        )
    return "\n".join(lines) + "\n"


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
            "schema_version": "bd-1z5a-evidence-pack-check-v1.0",
            "bead_id": SUPPORT_BEAD,
            "parent_bead": PARENT_BEAD,
            "title": TITLE,
            "verdict": "FAIL",
            "total": len(checks),
            "passed": passed,
            "failed": failed,
            "checks": checks,
            "coherence_contract": {},
        }

    evidence = _read_json(root / VERIFICATION_EVIDENCE.relative_to(ROOT))
    fixture_index = _read_json(root / REPLAY_FIXTURE_INDEX.relative_to(ROOT))
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
        "fixture_index_resolves": not missing_fixture_paths and not missing_fixture_ids,
        "fraud_witness_links_consistent": fraud_links_ok and not missing_fraud_source_paths,
        "summary_markdown_matches_bundle": summary_md_text == expected_summary_md and summary_rows_ok,
        "stale_gap_language_absent": not stale_phrases_found,
    }

    passed = sum(1 for item in checks if item["passed"])
    failed = len(checks) - passed
    return {
        "schema_version": "bd-1z5a-evidence-pack-check-v1.0",
        "bead_id": SUPPORT_BEAD,
        "parent_bead": PARENT_BEAD,
        "title": TITLE,
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(checks),
        "passed": passed,
        "failed": failed,
        "checks": checks,
        "coherence_contract": coherence_contract,
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
    summary_json = _read_json(OPERATOR_SUMMARY_JSON)
    bundle = _read_json(OPERATOR_BUNDLE)
    fraud_bundle = _read_json(FRAUD_PROOF_BUNDLE)
    log_text = _read(OPERATOR_LOG)
    verification_summary_text = _read(VERIFICATION_SUMMARY)

    _write_text(root, str(VERIFICATION_EVIDENCE.relative_to(ROOT)), json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(REPLAY_FIXTURE_INDEX.relative_to(ROOT)), json.dumps(fixture_index, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_SUMMARY_JSON.relative_to(ROOT)), json.dumps(summary_json, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_BUNDLE.relative_to(ROOT)), json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(FRAUD_PROOF_BUNDLE.relative_to(ROOT)), json.dumps(fraud_bundle, indent=2, sort_keys=True) + "\n")
    _write_text(root, str(OPERATOR_LOG.relative_to(ROOT)), log_text)
    _write_text(root, str(VERIFICATION_SUMMARY.relative_to(ROOT)), verification_summary_text)
    _write_text(root, str(OPERATOR_SUMMARY_MD.relative_to(ROOT)), _expected_summary_markdown(summary_json, bundle))

    placeholder_paths = set(_artifact_paths_from_evidence(evidence))
    placeholder_paths.update(
        rel
        for fixture in fixture_index.get("fixtures", [])
        if isinstance(fixture, dict)
        for rel in _fixture_reference_paths(fixture)
    )
    placeholder_paths.update(bundle.get("replay_inputs", []))
    placeholder_paths.update(
        value
        for value in fraud_bundle.get("source_artifacts", {}).values()
        if isinstance(value, str)
    )
    placeholder_paths.add(bundle.get("summary_path", ""))
    placeholder_paths.add(bundle.get("structured_log_path", ""))
    placeholder_paths.update(
        rel
        for stage in bundle.get("stage_results", [])
        if isinstance(stage, dict)
        for rel in (stage.get("stdout_path"), stage.get("stderr_path"))
        if isinstance(rel, str)
    )

    already_written = {
        str(VERIFICATION_EVIDENCE.relative_to(ROOT)),
        str(REPLAY_FIXTURE_INDEX.relative_to(ROOT)),
        str(OPERATOR_SUMMARY_JSON.relative_to(ROOT)),
        str(OPERATOR_SUMMARY_MD.relative_to(ROOT)),
        str(OPERATOR_BUNDLE.relative_to(ROOT)),
        str(OPERATOR_LOG.relative_to(ROOT)),
        str(FRAUD_PROOF_BUNDLE.relative_to(ROOT)),
        str(VERIFICATION_SUMMARY.relative_to(ROOT)),
    }
    for rel in sorted(path for path in placeholder_paths if isinstance(path, str) and path):
        if rel in already_written:
            continue
        _write_text(root, rel, "placeholder\n")


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
