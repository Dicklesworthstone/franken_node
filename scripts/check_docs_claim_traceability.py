#!/usr/bin/env python3
"""Validate README/docs claim-to-test traceability matrix (bd-38hez.8)."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

SCHEMA_VERSION = "franken-node/docs-claim-traceability/v1"
BEAD_ID = "bd-38hez.8"
DEFAULT_MATRIX = ROOT / "artifacts" / "docs_claim_traceability" / "claim_traceability_matrix.json"
DEFAULT_REPORT = ROOT / "artifacts" / "docs_claim_traceability" / "claim_traceability_report.md"

CLASSIFICATIONS = (
    "covered",
    "weakly_covered",
    "stale",
    "aspirational",
    "missing_proof",
)
PASSING_CLASSIFICATIONS = {"covered"}
EVIDENCE_COVERAGE = {"direct", "proxy"}
EVIDENCE_STATUS = {"fresh", "stale", "missing", "blocked"}
CLAIM_KINDS = {"current", "aspirational"}


def _safe_rel(path: Path, base_dir: Path = ROOT) -> str:
    try:
        return str(path.relative_to(base_dir))
    except ValueError:
        return str(path)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid matrix JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("matrix root must be an object")
    return payload


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str = "") -> None:
    checks.append(
        {
            "check": name,
            "pass": bool(passed),
            "detail": detail or ("ok" if passed else "failed"),
        }
    )


def _path_exists(path_value: Any, base_dir: Path) -> bool:
    return isinstance(path_value, str) and bool(path_value.strip()) and (base_dir / path_value).is_file()


def _validate_source(
    claim: dict[str, Any],
    base_dir: Path,
    checks: list[dict[str, Any]],
) -> None:
    claim_id = str(claim.get("claim_id", "<unknown>"))
    source = claim.get("source")
    if not isinstance(source, dict):
        _check(checks, f"{claim_id}: source object", False, "source must be object")
        return

    source_path = source.get("path")
    claim_text = source.get("claim_text")
    if not _path_exists(source_path, base_dir):
        _check(checks, f"{claim_id}: source path exists", False, str(source_path))
        return

    _check(checks, f"{claim_id}: source path exists", True, str(source_path))
    if not isinstance(claim_text, str) or not claim_text.strip():
        _check(checks, f"{claim_id}: claim text", False, "claim_text must be non-empty")
        return

    source_text = (base_dir / str(source_path)).read_text(encoding="utf-8")
    _check(
        checks,
        f"{claim_id}: claim text appears in source",
        claim_text in source_text,
        "found" if claim_text in source_text else str(source_path),
    )


def _evidence_path_status(evidence: dict[str, Any], base_dir: Path) -> str:
    declared_status = evidence.get("status")
    if declared_status == "missing":
        return "missing"
    path_value = evidence.get("path")
    if not _path_exists(path_value, base_dir):
        return "missing"
    return str(declared_status)


def classify_claim(claim: dict[str, Any], base_dir: Path = ROOT) -> str:
    claim_kind = claim.get("claim_kind", "current")
    evidence_refs = claim.get("evidence_refs")
    if claim_kind == "aspirational" and not evidence_refs:
        return "aspirational"
    if not isinstance(evidence_refs, list) or not evidence_refs:
        return "missing_proof"

    has_direct_fresh = False
    has_direct_stale = False
    has_direct_blocked = False
    has_direct_missing = False
    has_proxy_fresh = False

    for evidence in evidence_refs:
        if not isinstance(evidence, dict):
            has_direct_missing = True
            continue
        coverage = evidence.get("coverage")
        status = _evidence_path_status(evidence, base_dir)
        if coverage == "direct":
            if status == "fresh":
                has_direct_fresh = True
            elif status == "stale":
                has_direct_stale = True
            elif status == "blocked":
                has_direct_blocked = True
            else:
                has_direct_missing = True
        elif coverage == "proxy" and status == "fresh":
            has_proxy_fresh = True

    if has_direct_fresh:
        return "covered"
    if has_direct_stale:
        return "stale"
    if has_direct_blocked or has_direct_missing:
        return "missing_proof"
    if has_proxy_fresh:
        return "weakly_covered"
    if claim_kind == "aspirational":
        return "aspirational"
    return "missing_proof"


def _validate_evidence(
    claim: dict[str, Any],
    base_dir: Path,
    checks: list[dict[str, Any]],
) -> None:
    claim_id = str(claim.get("claim_id", "<unknown>"))
    evidence_refs = claim.get("evidence_refs")
    if not isinstance(evidence_refs, list):
        _check(checks, f"{claim_id}: evidence refs", False, "evidence_refs must be list")
        return

    for index, evidence in enumerate(evidence_refs):
        prefix = f"{claim_id}: evidence[{index}]"
        if not isinstance(evidence, dict):
            _check(checks, prefix, False, "evidence entry must be object")
            continue
        evidence_id = evidence.get("evidence_id")
        _check(
            checks,
            f"{prefix}: id",
            isinstance(evidence_id, str) and bool(evidence_id.strip()),
            str(evidence_id),
        )
        _check(
            checks,
            f"{prefix}: coverage",
            evidence.get("coverage") in EVIDENCE_COVERAGE,
            str(evidence.get("coverage")),
        )
        _check(
            checks,
            f"{prefix}: status",
            evidence.get("status") in EVIDENCE_STATUS,
            str(evidence.get("status")),
        )
        path_value = evidence.get("path")
        declared_status = evidence.get("status")
        if declared_status in {"fresh", "stale", "blocked"}:
            _check(
                checks,
                f"{prefix}: path exists",
                _path_exists(path_value, base_dir),
                str(path_value),
            )


def evaluate_matrix(payload: dict[str, Any], base_dir: Path = ROOT) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    _check(
        checks,
        "schema version",
        payload.get("schema_version") == SCHEMA_VERSION,
        str(payload.get("schema_version")),
    )
    _check(checks, "bead id", payload.get("bead_id") == BEAD_ID, str(payload.get("bead_id")))

    claims = payload.get("claims")
    if not isinstance(claims, list) or not claims:
        _check(checks, "claims present", False, "claims must be a non-empty list")
        claims = []
    else:
        _check(checks, "claims present", True, f"{len(claims)} claims")

    derived: dict[str, str] = {}
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            _check(checks, f"claim[{index}]", False, "claim must be object")
            continue
        claim_id = claim.get("claim_id")
        claim_id_text = str(claim_id) if isinstance(claim_id, str) and claim_id else f"claim[{index}]"
        _check(checks, f"{claim_id_text}: id", bool(claim_id_text.strip()), claim_id_text)
        _check(
            checks,
            f"{claim_id_text}: kind",
            claim.get("claim_kind", "current") in CLAIM_KINDS,
            str(claim.get("claim_kind", "current")),
        )
        _validate_source(claim, base_dir, checks)
        _validate_evidence(claim, base_dir, checks)
        classification = classify_claim(claim, base_dir)
        derived[claim_id_text] = classification
        _check(
            checks,
            f"{claim_id_text}: classification",
            claim.get("classification") == classification,
            f"declared={claim.get('classification')} derived={classification}",
        )
        _check(
            checks,
            f"{claim_id_text}: classification known",
            classification in CLASSIFICATIONS,
            classification,
        )

    counts = Counter(derived.values())
    expected_summary = {
        "total_claims": len(derived),
        "covered": counts["covered"],
        "weakly_covered": counts["weakly_covered"],
        "stale": counts["stale"],
        "aspirational": counts["aspirational"],
        "missing_proof": counts["missing_proof"],
    }
    expected_summary["verdict"] = (
        "PASS"
        if expected_summary["total_claims"] > 0
        and all(value in PASSING_CLASSIFICATIONS for value in derived.values())
        else "FAIL"
    )

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        _check(checks, "summary object", False, "summary must be object")
        summary = {}
    else:
        _check(checks, "summary object", True, "found")
    for key, expected in expected_summary.items():
        _check(
            checks,
            f"summary.{key}",
            summary.get(key) == expected,
            f"expected={expected} actual={summary.get(key)}",
        )

    failed_checks = [check for check in checks if not check["pass"]]
    verdict = "PASS" if expected_summary["verdict"] == "PASS" and not failed_checks else "FAIL"
    return {
        "bead_id": BEAD_ID,
        "schema_version": SCHEMA_VERSION,
        "verdict": verdict,
        "summary": expected_summary,
        "derived_classifications": derived,
        "total": len(checks),
        "passed": sum(1 for check in checks if check["pass"]),
        "failed": len(failed_checks),
        "checks": checks,
    }


def render_human(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# Docs Claim Traceability Report",
        "",
        f"- Schema: `{payload.get('schema_version', '')}`",
        f"- Bead: `{payload.get('bead_id', '')}`",
        f"- Verdict: `{summary.get('verdict', '')}`",
        (
            "- Claims: "
            f"`{summary.get('total_claims', 0)}` "
            f"covered=`{summary.get('covered', 0)}` "
            f"weakly_covered=`{summary.get('weakly_covered', 0)}` "
            f"stale=`{summary.get('stale', 0)}` "
            f"aspirational=`{summary.get('aspirational', 0)}` "
            f"missing_proof=`{summary.get('missing_proof', 0)}`"
        ),
        "",
        "## Claims",
        "",
        "| Claim | Source | Classification | Direct | Proxy | Required Action |",
        "|---|---|---:|---:|---:|---|",
    ]
    for claim in payload.get("claims", []):
        if not isinstance(claim, dict):
            continue
        evidence_refs = claim.get("evidence_refs", [])
        direct = 0
        proxy = 0
        if isinstance(evidence_refs, list):
            direct = sum(
                1
                for evidence in evidence_refs
                if isinstance(evidence, dict) and evidence.get("coverage") == "direct"
            )
            proxy = sum(
                1
                for evidence in evidence_refs
                if isinstance(evidence, dict) and evidence.get("coverage") == "proxy"
            )
        source = claim.get("source", {})
        source_path = source.get("path", "") if isinstance(source, dict) else ""
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                claim.get("claim_id", ""),
                source_path,
                claim.get("classification", ""),
                direct,
                proxy,
                claim.get("required_action", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)


def run_checks(
    matrix_path: Path = DEFAULT_MATRIX,
    report_path: Path = DEFAULT_REPORT,
    base_dir: Path = ROOT,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    _check(checks, "matrix file exists", matrix_path.is_file(), _safe_rel(matrix_path, base_dir))
    _check(checks, "human report exists", report_path.is_file(), _safe_rel(report_path, base_dir))
    if not matrix_path.is_file():
        return {
            "bead_id": BEAD_ID,
            "schema_version": SCHEMA_VERSION,
            "verdict": "FAIL",
            "summary": {},
            "total": len(checks),
            "passed": sum(1 for check in checks if check["pass"]),
            "failed": sum(1 for check in checks if not check["pass"]),
            "checks": checks,
        }

    payload = _load_json(matrix_path)
    result = evaluate_matrix(payload, base_dir)
    combined_checks = checks + result["checks"]
    if report_path.is_file():
        expected_report = render_human(payload)
        actual_report = report_path.read_text(encoding="utf-8")
        _check(
            combined_checks,
            "human report matches matrix",
            actual_report == expected_report,
            "exact match" if actual_report == expected_report else _safe_rel(report_path, base_dir),
        )
    failed_checks = [check for check in combined_checks if not check["pass"]]
    return {
        **result,
        "verdict": "PASS" if result["verdict"] == "PASS" and not failed_checks else "FAIL",
        "total": len(combined_checks),
        "passed": sum(1 for check in combined_checks if check["pass"]),
        "failed": len(failed_checks),
        "checks": combined_checks,
    }


def _write_fixture_files(base: Path) -> None:
    for rel, text in {
        "README.md": "franken-node migrate audit ./app emits JSON migration findings\n",
        "docs/install.md": "curl https://example.invalid/install.sh | sh installs the released CLI\n",
        "docs/vision.md": "franken-node automatically rewrites every Node API with zero manual review\n",
        "tests/direct.rs": "#[test]\nfn migrate_audit_json_contract() {}\n",
        "tests/proxy.rs": "#[test]\nfn smoke_proxy_contract() {}\n",
    }.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _fixture_matrix(claims: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(claim["classification"] for claim in claims)
    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": BEAD_ID,
        "generated_at_utc": "2026-05-09T00:00:00Z",
        "summary": {
            "total_claims": len(claims),
            "covered": counts["covered"],
            "weakly_covered": counts["weakly_covered"],
            "stale": counts["stale"],
            "aspirational": counts["aspirational"],
            "missing_proof": counts["missing_proof"],
            "verdict": "PASS" if all(claim["classification"] == "covered" for claim in claims) else "FAIL",
        },
        "claims": claims,
    }


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
        base = Path(tmp)
        _write_fixture_files(base)
        matrix = _fixture_matrix(
            [
                {
                    "claim_id": "FIX-COVERED",
                    "claim_kind": "current",
                    "source": {
                        "path": "README.md",
                        "line": 1,
                        "claim_text": "franken-node migrate audit ./app emits JSON migration findings",
                    },
                    "command_surfaces": ["franken-node migrate audit"],
                    "evidence_refs": [
                        {
                            "evidence_id": "direct-test",
                            "kind": "test",
                            "coverage": "direct",
                            "status": "fresh",
                            "path": "tests/direct.rs",
                            "description": "direct CLI contract",
                        }
                    ],
                    "classification": "covered",
                    "required_action": "none",
                }
            ]
        )
        return evaluate_matrix(matrix, base)["verdict"] == "PASS"


def main(argv: list[str] | None = None) -> int:
    logger = configure_test_logging("check_docs_claim_traceability")
    logger.info("starting %s verification", "check_docs_claim_traceability")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"self_test": ok}, sort_keys=True))
        else:
            print("self-test: PASS" if ok else "self-test: FAIL")
        return 0 if ok else 1

    result = run_checks(args.matrix, args.report)
    if args.json:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(f"docs claim traceability: {result['verdict']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"{status} {check['check']}: {check['detail']}")
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
