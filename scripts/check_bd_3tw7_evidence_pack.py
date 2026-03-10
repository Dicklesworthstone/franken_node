#!/usr/bin/env python3
"""Deterministic coherence checker for the bd-3tw7 truthfulness-gate evidence pack."""

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


PARENT_BEAD = "bd-3tw7"
SUPPORT_BEAD = "bd-3tw7.5"
TITLE = "bd-3tw7 truthfulness-gate evidence pack coherence"

ARTIFACT_DIR = ROOT / "artifacts" / "replacement_gap" / PARENT_BEAD
VERIFICATION_EVIDENCE = ARTIFACT_DIR / "verification_evidence.json"
VERIFICATION_SUMMARY = ARTIFACT_DIR / "verification_summary.md"
WITNESS_MATRIX = ARTIFACT_DIR / "witness_matrix.json"

EVIDENCE_PACK_CHECKER = "scripts/check_bd_3tw7_evidence_pack.py"
EVIDENCE_PACK_CHECKER_TESTS = "tests/test_check_bd_3tw7_evidence_pack.py"

EXPECTED_ARTIFACT_KEYS = {
    "checker",
    "checker_tests",
    "evidence_pack_checker",
    "evidence_pack_checker_tests",
    "verification_evidence",
    "verification_summary",
    "witness_matrix",
}

REQUIRED_NOTE_PHRASES = [
    "The witness matrix is a static seed for bd-3tw7, not a claim that the full parent dynamic/e2e truthfulness gate is complete.",
    "bd-3tw7.5 adds deterministic evidence-pack coherence coverage so artifact drift fails closed.",
]


def _check(check: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": check, "passed": passed, "detail": detail}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(_read(path))


def _write_text(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


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


def _source_paths_from_witnesses(witness_matrix: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for witness in witness_matrix:
        source_paths = witness.get("source_paths", [])
        if isinstance(source_paths, list):
            paths.extend(path for path in source_paths if isinstance(path, str))
    return paths


def _excluded_surface_paths(evidence: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for entry in evidence.get("excluded_surfaces", []):
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            paths.append(entry["path"])
    return paths


def _expected_summary_markdown(
    evidence: dict[str, Any],
    witness_matrix: list[dict[str, Any]],
) -> str:
    artifacts = evidence["artifacts"]
    support_beads = ", ".join(evidence["support_bead_ids"])
    lines = [
        "# bd-3tw7 Static Truthfulness Gate Seed",
        "",
        f"- Parent bead: `{evidence['bead_id']}`",
        f"- Support beads: `{support_beads}`",
        f"- Verdict: `{evidence['verdict']}`",
        f"- Scope: {evidence['artifact_scope']}",
        "- Static-seed disclaimer: this pack does not claim the full parent dynamic/e2e truthfulness gate is complete.",
        "",
        "## Guarded Witnesses",
        "",
    ]
    for entry in witness_matrix:
        lines.append(
            f"- `{entry['witness_id']}` ({entry['surface']}): "
            f"`{'PASS' if entry['pass'] else 'FAIL'}` via `{entry['reason_code']}`"
        )

    lines.extend(
        [
            "",
            "## Excluded Reserved Surfaces",
            "",
        ]
    )
    for entry in evidence["excluded_surfaces"]:
        lines.append(
            f"- `{entry['path']}` excluded because {entry['reason']} (`{entry['owner']}`)."
        )

    lines.extend(
        [
            "",
            "## Guard Checkers",
            "",
            f"- Primary seed checker: `{artifacts['checker']}`",
            f"- Primary seed tests: `{artifacts['checker_tests']}`",
            f"- Evidence-pack coherence checker: `{artifacts['evidence_pack_checker']}`",
            f"- Evidence-pack coherence tests: `{artifacts['evidence_pack_checker_tests']}`",
            "",
            "## Artifact Paths",
            "",
            f"- `{artifacts['verification_evidence']}`",
            f"- `{artifacts['verification_summary']}`",
            f"- `{artifacts['witness_matrix']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def _evaluate(root: Path) -> dict[str, Any]:
    tracked_files = [
        str(path.relative_to(ROOT))
        for path in (VERIFICATION_EVIDENCE, VERIFICATION_SUMMARY, WITNESS_MATRIX)
    ]
    checks = [_ensure_file(root, rel) for rel in tracked_files]

    required_paths = [root / rel for rel in tracked_files]
    if not all(path.is_file() for path in required_paths):
        passed = sum(1 for item in checks if item["passed"])
        failed = len(checks) - passed
        return {
            "schema_version": "bd-3tw7-evidence-pack-check-v1.0",
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
    summary_text = _read(root / VERIFICATION_SUMMARY.relative_to(ROOT))
    witness_matrix = _read_json(root / WITNESS_MATRIX.relative_to(ROOT))

    artifacts = evidence.get("artifacts", {})
    artifact_keys_ok = (
        isinstance(artifacts, dict)
        and EXPECTED_ARTIFACT_KEYS.issubset(artifacts)
        and artifacts.get("evidence_pack_checker") == EVIDENCE_PACK_CHECKER
        and artifacts.get("evidence_pack_checker_tests") == EVIDENCE_PACK_CHECKER_TESTS
    )
    checks.append(
        _check(
            "verification evidence exposes expected artifact checker keys",
            artifact_keys_ok,
            "ok"
            if artifact_keys_ok
            else json.dumps(sorted(artifacts.keys()) if isinstance(artifacts, dict) else [], sort_keys=True),
        )
    )

    artifact_paths = _artifact_paths_from_evidence(evidence)
    missing_artifact_paths = sorted(rel for rel in artifact_paths if not (root / rel).is_file())
    checks.append(
        _check(
            "verification evidence artifact paths resolve",
            not missing_artifact_paths,
            "ok" if not missing_artifact_paths else ",".join(missing_artifact_paths),
        )
    )

    witness_matrix_ok = isinstance(witness_matrix, list) and evidence.get("witness_matrix") == witness_matrix
    checks.append(
        _check(
            "witness matrix file matches verification evidence payload",
            witness_matrix_ok,
            "ok" if witness_matrix_ok else "verification_evidence.json and witness_matrix.json diverged",
        )
    )

    missing_source_paths = sorted(
        rel
        for rel in (
            _source_paths_from_witnesses(witness_matrix if isinstance(witness_matrix, list) else [])
            + _excluded_surface_paths(evidence)
        )
        if not (root / rel).exists()
    )
    checks.append(
        _check(
            "witness and excluded-surface source paths resolve",
            not missing_source_paths,
            "ok" if not missing_source_paths else ",".join(sorted(set(missing_source_paths))),
        )
    )

    witness_count = len(witness_matrix) if isinstance(witness_matrix, list) else 0
    passed_witnesses = sum(1 for witness in witness_matrix if witness.get("pass")) if isinstance(witness_matrix, list) else 0
    failed_witnesses = witness_count - passed_witnesses
    counts_ok = (
        evidence.get("total_witnesses") == witness_count
        and evidence.get("passed_witnesses") == passed_witnesses
        and evidence.get("failed_witnesses") == failed_witnesses
        and evidence.get("overall_pass") == (failed_witnesses == 0)
        and evidence.get("verdict") == ("PASS" if failed_witnesses == 0 else "FAIL")
    )
    checks.append(
        _check(
            "verification evidence counts and verdict align with witness matrix",
            counts_ok,
            json.dumps(
                {
                    "failed": failed_witnesses,
                    "passed": passed_witnesses,
                    "total": witness_count,
                    "verdict": evidence.get("verdict"),
                },
                sort_keys=True,
            ),
        )
    )

    witness_support_beads = sorted(
        {
            witness["support_bead"]
            for witness in witness_matrix
            if isinstance(witness, dict) and isinstance(witness.get("support_bead"), str)
        }
    )
    expected_support_beads = sorted(set(witness_support_beads) | {SUPPORT_BEAD})
    support_bead_ids = evidence.get("support_bead_ids")
    support_beads_ok = isinstance(support_bead_ids, list) and support_bead_ids == expected_support_beads
    checks.append(
        _check(
            "support bead ids include witness owners plus evidence-pack guard shard",
            support_beads_ok,
            json.dumps(
                {
                    "expected": expected_support_beads,
                    "observed": support_bead_ids,
                },
                sort_keys=True,
            ),
        )
    )

    note_phrases_found = [
        phrase
        for phrase in REQUIRED_NOTE_PHRASES
        if phrase in evidence.get("notes", [])
    ]
    notes_ok = len(note_phrases_found) == len(REQUIRED_NOTE_PHRASES)
    checks.append(
        _check(
            "verification evidence preserves required static-seed notes",
            notes_ok,
            "ok" if notes_ok else json.dumps(note_phrases_found, sort_keys=True),
        )
    )

    expected_summary = _expected_summary_markdown(evidence, witness_matrix)
    summary_ok = summary_text == expected_summary
    checks.append(
        _check(
            "verification summary markdown matches canonical evidence-pack rendering",
            summary_ok,
            "ok" if summary_ok else "verification_summary.md drifted from evidence/witness source of truth",
        )
    )

    witness_ids = [
        witness.get("witness_id")
        for witness in witness_matrix
        if isinstance(witness, dict)
    ]
    unique_ids_ok = len(witness_ids) == len(set(witness_ids))
    checks.append(
        _check(
            "witness ids remain unique",
            unique_ids_ok,
            "ok" if unique_ids_ok else json.dumps(witness_ids),
        )
    )

    coherence_contract = {
        "artifact_paths_resolve": not missing_artifact_paths,
        "witness_matrix_matches_evidence": witness_matrix_ok,
        "source_paths_resolve": not missing_source_paths,
        "support_bead_contract_consistent": support_beads_ok,
        "summary_markdown_matches_source": summary_ok,
        "static_seed_notes_present": notes_ok,
    }

    passed = sum(1 for item in checks if item["passed"])
    failed = len(checks) - passed
    return {
        "schema_version": "bd-3tw7-evidence-pack-check-v1.0",
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


def _materialize_self_test_fixture(root: Path) -> None:
    evidence = _read_json(VERIFICATION_EVIDENCE)
    witness_matrix = _read_json(WITNESS_MATRIX)

    _write_text(
        root,
        str(VERIFICATION_EVIDENCE.relative_to(ROOT)),
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
    )
    _write_text(
        root,
        str(WITNESS_MATRIX.relative_to(ROOT)),
        json.dumps(witness_matrix, indent=2, sort_keys=True) + "\n",
    )
    _write_text(
        root,
        str(VERIFICATION_SUMMARY.relative_to(ROOT)),
        _expected_summary_markdown(evidence, witness_matrix),
    )

    placeholder_paths = set(_artifact_paths_from_evidence(evidence))
    placeholder_paths.update(_source_paths_from_witnesses(witness_matrix))
    placeholder_paths.update(_excluded_surface_paths(evidence))
    already_written = {
        str(VERIFICATION_EVIDENCE.relative_to(ROOT)),
        str(VERIFICATION_SUMMARY.relative_to(ROOT)),
        str(WITNESS_MATRIX.relative_to(ROOT)),
    }
    for rel in sorted(path for path in placeholder_paths if path):
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

        evidence_path = root / VERIFICATION_EVIDENCE.relative_to(ROOT)
        evidence = _read_json(evidence_path)
        evidence["support_bead_ids"] = [bead for bead in evidence["support_bead_ids"] if bead != SUPPORT_BEAD]
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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

    logger = configure_test_logging("check_bd_3tw7_evidence_pack", json_mode=args.json)

    if args.self_test:
        payload = self_test()
        logger.info("self-test complete", extra={"verdict": payload["verdict"]})
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(payload["detail"])
        return 0 if payload["verdict"] == "PASS" else 1

    payload = run_checks()
    logger.info("checks complete", extra={"verdict": payload["verdict"], "failed": payload["failed"]})
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{payload['verdict']} ({payload['passed']}/{payload['total']} checks passed)")
        for check in payload["checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            print(f"- {status}: {check['check']} :: {check['detail']}")
    return 0 if payload["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
