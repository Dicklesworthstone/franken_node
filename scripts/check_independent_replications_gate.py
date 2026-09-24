#!/usr/bin/env python3
"""Verify bd-whxp: concrete target gate for >=2 independent replications."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging

BEAD_ID = "bd-whxp"
SECTION = "13"
TITLE = "Concrete target gate: >=2 independent replications"

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-whxp_contract.md"
REPORT = ROOT / "artifacts" / "13" / "independent_replication_report.json"

REQUIRED_CLAIMS = {
    "migration_velocity_3x",
    "compromise_reduction_10x",
    "replay_coverage_100pct",
}

REQUIRED_EVENT_CODES = {
    "IRG-001",
    "IRG-002",
    "IRG-003",
    "IRG-004",
    "IRG-005",
    "IRG-006",
}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("ok" if passed else "failed"),
    }
    CHECKS.append(entry)
    return entry


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _trace_id(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# Hosts reserved for documentation and testing (RFC 2606, RFC 6761). A
# replication whose source or evidence lives on one of these is not evidence
# of anything, however well-formed the record around it is.
PLACEHOLDER_HOSTS = {"example.com", "example.net", "example.org", "localhost"}
PLACEHOLDER_HOST_SUFFIXES = (".example", ".test", ".invalid", ".localhost",
                             ".example.com", ".example.net", ".example.org")


def _evidence_ref_problem(ref: str, evidence_base: Path | None) -> str | None:
    """Why `ref` cannot be evidence, or None.

    A remote reference must not use a reserved placeholder host. A relative
    reference names evidence shipped with the report and must exist beside it.
    """
    parsed = urlparse(ref)
    if parsed.scheme in {"http", "https"}:
        host = (parsed.hostname or "").lower()
        if not host:
            return f"{ref}: no host"
        if host in PLACEHOLDER_HOSTS or host.endswith(PLACEHOLDER_HOST_SUFFIXES):
            return f"{ref}: placeholder host {host} (RFC 2606/6761) is not evidence"
        return None
    if parsed.scheme:
        return f"{ref}: unsupported scheme {parsed.scheme}"
    relative = Path(ref)
    if relative.is_absolute() or ".." in relative.parts:
        return f"{ref}: evidence path must be relative to the report"
    if evidence_base is not None and not (evidence_base / relative).is_file():
        return f"{ref}: evidence file not found beside the report"
    return None


def write_sample_evidence(directory: Path) -> None:
    """Create the evidence files `sample_report()` references (tests only)."""
    for replication in sample_report()["replications"]:
        refs = [replication["source_url"]] + [
            result["evidence_uri"] for result in replication["claim_results"].values()
        ]
        for ref in refs:
            path = directory / ref
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"ref": ref}) + "\n", encoding="utf-8")


def sample_report() -> dict[str, Any]:
    return {
        "bead_id": BEAD_ID,
        "generated_at_utc": "2026-02-21T01:30:00Z",
        "trace_id": "3f61deaf8a6a5ccf4d29a0bb2fdb68a7c09d98f554e6ff2d95cb3e8d968a31b2",
        "required_minimum_replications": 2,
        "required_claims": sorted(REQUIRED_CLAIMS),
        "replications": [
            {
                "replication_id": "rep-opensec-20260218",
                "organization": "OpenSec Labs",
                "independent": True,
                "executed_at_utc": "2026-02-18T16:45:00Z",
                "source_url": "evidence/opensec/replication.json",
                "source_commit": "0a6c9a8f71a8380dcf23cc9eb7ae4b06f2d64511",
                "evaluator_hash": "ba4515ec17b6e8f774f6fba6054b8b9f8e86c79940f9cf3d95b6c499f3c37c8b",
                "environment_fingerprint": "ubuntu-22.04|x86_64|python3.12|runner-v2",
                "disclosed_funding_conflict": False,
                "claim_results": {
                    "migration_velocity_3x": {"pass": True, "evidence_uri": "evidence/opensec/migration_velocity.json", "measured_value": "3.41x"},
                    "compromise_reduction_10x": {"pass": True, "evidence_uri": "evidence/opensec/compromise_reduction.json", "measured_value": "12.3x"},
                    "replay_coverage_100pct": {"pass": True, "evidence_uri": "evidence/opensec/replay_coverage.json", "measured_value": "100%"},
                },
            },
            {
                "replication_id": "rep-boundaryproofs-20260219",
                "organization": "Boundary Proofs Consortium",
                "independent": True,
                "executed_at_utc": "2026-02-19T10:12:00Z",
                "source_url": "evidence/bpc/replication.json",
                "source_commit": "0a6c9a8f71a8380dcf23cc9eb7ae4b06f2d64511",
                "evaluator_hash": "7f2fca1ab414035eb4d7fc1d7d2442be26d5eb44557af73f2ad8d2081f6f8d2d",
                "environment_fingerprint": "debian-12|x86_64|python3.11|runner-v4",
                "disclosed_funding_conflict": False,
                "claim_results": {
                    "migration_velocity_3x": {"pass": True, "evidence_uri": "evidence/bpc/migration_velocity.json", "measured_value": "3.22x"},
                    "compromise_reduction_10x": {"pass": True, "evidence_uri": "evidence/bpc/compromise_reduction.json", "measured_value": "10.9x"},
                    "replay_coverage_100pct": {"pass": True, "evidence_uri": "evidence/bpc/replay_coverage.json", "measured_value": "100%"},
                },
            },
            {
                "replication_id": "rep-deltaaudit-20260220",
                "organization": "Delta Audit Group",
                "independent": False,
                "executed_at_utc": "2026-02-20T08:05:00Z",
                "source_url": "evidence/delta/replication.json",
                "source_commit": "0a6c9a8f71a8380dcf23cc9eb7ae4b06f2d64511",
                "evaluator_hash": "7e20bc8f4328c2bcc3f950fe9ca58aa315f5715dfcf56240a68fc5a9a96cfc33",
                "environment_fingerprint": "macos-14|arm64|python3.12|runner-v3",
                "disclosed_funding_conflict": True,
                "claim_results": {
                    "migration_velocity_3x": {"pass": True, "evidence_uri": "evidence/delta/migration_velocity.json", "measured_value": "3.07x"},
                    "compromise_reduction_10x": {"pass": True, "evidence_uri": "evidence/delta/compromise_reduction.json", "measured_value": "10.2x"},
                    "replay_coverage_100pct": {"pass": True, "evidence_uri": "evidence/delta/replay_coverage.json", "measured_value": "100%"},
                },
            },
        ],
        "summary": {
            "replication_count": 3,
            "independent_replication_count": 2,
            "independent_replications_passing": 2,
            "verdict": "PASS",
        },
        "event_codes": sorted(REQUIRED_EVENT_CODES),
    }


def _evaluate_replications(
    replications: list[dict[str, Any]],
    required_claims: set[str],
    evidence_base: Path | None = None,
) -> dict[str, Any]:
    validation_errors: list[str] = []
    organizations: set[str] = set()
    evaluator_hashes: set[str] = set()
    duplicate_organizations: set[str] = set()
    duplicate_evaluators: set[str] = set()

    independent_count = 0
    independent_passing = 0
    independent_with_conflicts = 0
    missing_claim_records = 0

    for idx, repl in enumerate(replications):
        for field in (
            "replication_id",
            "organization",
            "independent",
            "executed_at_utc",
            "source_url",
            "source_commit",
            "evaluator_hash",
            "environment_fingerprint",
            "disclosed_funding_conflict",
            "claim_results",
        ):
            if field not in repl:
                validation_errors.append(f"replications[{idx}] missing field: {field}")

        organization = repl.get("organization")
        if not isinstance(organization, str) or not organization.strip():
            validation_errors.append(f"replications[{idx}].organization must be non-empty string")

        independent = repl.get("independent")
        if not isinstance(independent, bool):
            validation_errors.append(f"replications[{idx}].independent must be boolean")
            independent = False

        if isinstance(repl.get("executed_at_utc"), str):
            try:
                _parse_iso8601(repl["executed_at_utc"])
            except Exception:
                validation_errors.append(f"replications[{idx}].executed_at_utc must be valid RFC-3339 UTC")
        else:
            validation_errors.append(f"replications[{idx}].executed_at_utc must be string")

        source_commit = repl.get("source_commit")
        if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            validation_errors.append(f"replications[{idx}].source_commit must be 40-char lowercase hex")

        evaluator_hash = repl.get("evaluator_hash")
        if not isinstance(evaluator_hash, str) or re.fullmatch(r"[0-9a-f]{64}", evaluator_hash) is None:
            validation_errors.append(f"replications[{idx}].evaluator_hash must be 64-char lowercase hex")

        claim_results = repl.get("claim_results")
        claims_ok = isinstance(claim_results, dict)
        if not claims_ok:
            validation_errors.append(f"replications[{idx}].claim_results must be object")
            claim_results = {}

        missing_claims = sorted(required_claims - set(claim_results.keys()))
        if missing_claims:
            missing_claim_records += 1
            validation_errors.append(
                f"replications[{idx}] missing required claims: {', '.join(missing_claims)}"
            )

        replication_passes_all_claims = True
        source_url = repl.get("source_url")
        if isinstance(source_url, str) and source_url.strip():
            problem = _evidence_ref_problem(source_url, evidence_base)
            if problem:
                replication_passes_all_claims = False
                validation_errors.append(f"replications[{idx}].source_url {problem}")
        for claim in required_claims:
            claim_payload = claim_results.get(claim, {})
            if not isinstance(claim_payload, dict):
                replication_passes_all_claims = False
                validation_errors.append(f"replications[{idx}].claim_results.{claim} must be object")
                continue
            claim_pass = claim_payload.get("pass")
            evidence_uri = claim_payload.get("evidence_uri")
            measured_value = claim_payload.get("measured_value")
            if not isinstance(claim_pass, bool):
                replication_passes_all_claims = False
                validation_errors.append(f"replications[{idx}].claim_results.{claim}.pass must be boolean")
            if claim_pass is not True:
                replication_passes_all_claims = False
            if not isinstance(evidence_uri, str) or not evidence_uri.strip():
                replication_passes_all_claims = False
                validation_errors.append(f"replications[{idx}].claim_results.{claim}.evidence_uri required")
            else:
                problem = _evidence_ref_problem(evidence_uri, evidence_base)
                if problem:
                    replication_passes_all_claims = False
                    validation_errors.append(
                        f"replications[{idx}].claim_results.{claim}.evidence_uri {problem}"
                    )
            if not isinstance(measured_value, str) or not measured_value.strip():
                replication_passes_all_claims = False
                validation_errors.append(f"replications[{idx}].claim_results.{claim}.measured_value required")

        disclosed_conflict = repl.get("disclosed_funding_conflict")
        if not isinstance(disclosed_conflict, bool):
            validation_errors.append(f"replications[{idx}].disclosed_funding_conflict must be boolean")
            disclosed_conflict = True

        if independent:
            independent_count += 1
            if disclosed_conflict:
                independent_with_conflicts += 1

            if isinstance(organization, str):
                if organization in organizations:
                    duplicate_organizations.add(organization)
                organizations.add(organization)

            if isinstance(evaluator_hash, str):
                if evaluator_hash in evaluator_hashes:
                    duplicate_evaluators.add(evaluator_hash)
                evaluator_hashes.add(evaluator_hash)

            if replication_passes_all_claims and not disclosed_conflict:
                independent_passing += 1

    return {
        "validation_errors": validation_errors,
        "independent_count": independent_count,
        "independent_passing": independent_passing,
        "independent_with_conflicts": independent_with_conflicts,
        "duplicate_organizations": sorted(duplicate_organizations),
        "duplicate_evaluators": sorted(duplicate_evaluators),
        "missing_claim_records": missing_claim_records,
    }


def run_checks(spec_path: Path = SPEC, report_path: Path = REPORT) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: spec contract", spec_path.is_file(), _safe_rel(spec_path))
    _check("file: independent replication report", report_path.is_file(), _safe_rel(report_path))

    spec_text = ""
    if spec_path.is_file():
        spec_text = spec_path.read_text(encoding="utf-8")
    contract_tokens = [
        "INV-IRG-MIN-REPLICATIONS",
        "INV-IRG-REQUIRED-CLAIMS",
        "INV-IRG-INDEPENDENCE",
        "INV-IRG-CONFLICT-DISCLOSURE",
        "INV-IRG-EVIDENCE-LINKS",
        "INV-IRG-DETERMINISM",
        "INV-IRG-ADVERSARIAL",
    ]
    _check("spec invariants present", all(token in spec_text for token in contract_tokens))
    _check("spec event codes", all(code in spec_text for code in REQUIRED_EVENT_CODES))

    report: dict[str, Any] = {}
    parse_error = ""
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                parse_error = "report root must be object"
        except json.JSONDecodeError as exc:
            parse_error = f"invalid report JSON: {exc}"
    _check("report parse", parse_error == "", parse_error or "ok")

    if parse_error:
        total = len(CHECKS)
        passed = sum(1 for item in CHECKS if item["pass"])
        failed = total - passed
        return {
            "bead_id": BEAD_ID,
            "title": TITLE,
            "section": SECTION,
            "verdict": "FAIL",
            "total": total,
            "passed": passed,
            "failed": failed,
            "checks": CHECKS,
            "events": [],
        }

    required_top = (
        "bead_id",
        "generated_at_utc",
        "trace_id",
        "required_minimum_replications",
        "required_claims",
        "replications",
        "summary",
        "event_codes",
    )
    missing_top = [field for field in required_top if field not in report]
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )
    _check("report bead id", report.get("bead_id") == BEAD_ID)
    _check(
        "trace_id format",
        isinstance(report.get("trace_id"), str) and re.fullmatch(r"[0-9a-f]{64}", str(report.get("trace_id", ""))) is not None,
    )

    generated_at = report.get("generated_at_utc")
    timestamp_ok = False
    if isinstance(generated_at, str):
        try:
            _parse_iso8601(generated_at)
            timestamp_ok = True
        except Exception:
            timestamp_ok = False
    _check("generated_at_utc RFC-3339", timestamp_ok)

    required_claims = report.get("required_claims", [])
    _check("required_claims list", isinstance(required_claims, list))
    claim_set = {claim for claim in required_claims if isinstance(claim, str)}
    _check("required claims exact", claim_set == REQUIRED_CLAIMS, f"seen={sorted(claim_set)}")

    required_min = report.get("required_minimum_replications")
    required_min_ok = isinstance(required_min, int) and required_min >= 2
    _check("minimum required replications >=2", required_min_ok, f"value={required_min}")
    if not required_min_ok:
        required_min = 2

    replications_raw = report.get("replications", [])
    _check("replications list", isinstance(replications_raw, list))
    replications: list[dict[str, Any]] = [
        item for item in replications_raw if isinstance(item, dict)
    ] if isinstance(replications_raw, list) else []

    evaluation = _evaluate_replications(replications, REQUIRED_CLAIMS, report_path.parent)
    _check(
        "replication schema and claim result completeness",
        len(evaluation["validation_errors"]) == 0,
        "; ".join(evaluation["validation_errors"][:5]) if evaluation["validation_errors"] else "ok",
    )
    _check(
        "independent organizations unique",
        len(evaluation["duplicate_organizations"]) == 0,
        f"duplicates={evaluation['duplicate_organizations']}",
    )
    _check(
        "independent evaluator hashes unique",
        len(evaluation["duplicate_evaluators"]) == 0,
        f"duplicates={evaluation['duplicate_evaluators']}",
    )
    _check(
        "independent conflict disclosures clean",
        evaluation["independent_with_conflicts"] == 0,
        f"count={evaluation['independent_with_conflicts']}",
    )

    threshold_pass = evaluation["independent_passing"] >= int(required_min)
    _check(
        ">=2 independent passing replications",
        threshold_pass,
        f"independent_passing={evaluation['independent_passing']} required={required_min}",
    )

    summary = report.get("summary", {})
    summary_ok = isinstance(summary, dict)
    summary_fields_ok = summary_ok and all(
        field in summary
        for field in (
            "replication_count",
            "independent_replication_count",
            "independent_replications_passing",
            "verdict",
        )
    )
    _check("summary fields present", summary_fields_ok)
    if not summary_fields_ok:
        summary = {}

    _check(
        "summary counts match computed values",
        summary.get("replication_count") == len(replications)
        and summary.get("independent_replication_count") == evaluation["independent_count"]
        and summary.get("independent_replications_passing") == evaluation["independent_passing"],
        (
            f"summary={summary.get('replication_count')}/"
            f"{summary.get('independent_replication_count')}/"
            f"{summary.get('independent_replications_passing')} "
            f"computed={len(replications)}/{evaluation['independent_count']}/{evaluation['independent_passing']}"
        ),
    )

    computed_verdict = "PASS" if threshold_pass else "FAIL"
    _check(
        "summary verdict matches computed verdict",
        summary.get("verdict") == computed_verdict,
        f"summary={summary.get('verdict')} computed={computed_verdict}",
    )

    # Determinism check: order should not change computed threshold result.
    reversed_eval = _evaluate_replications(list(reversed(replications)), REQUIRED_CLAIMS)
    reversed_threshold_pass = reversed_eval["independent_passing"] >= int(required_min)
    _check(
        "determinism under replication reorder",
        reversed_threshold_pass == threshold_pass,
        f"forward={threshold_pass} reversed={reversed_threshold_pass}",
    )

    # Adversarial perturbation: reduce independent passing count below threshold.
    adversarial_ok = False
    if replications:
        perturbed = json.loads(json.dumps(replications))
        turned_off = 0
        for item in perturbed:
            if item.get("independent") is True and turned_off < int(required_min):
                item["independent"] = False
                turned_off += 1
        perturbed_eval = _evaluate_replications(perturbed, REQUIRED_CLAIMS)
        perturbed_pass = perturbed_eval["independent_passing"] >= int(required_min)
        adversarial_ok = not perturbed_pass
    _check("adversarial perturbation flips verdict", adversarial_ok)

    report_event_codes = set(report.get("event_codes", [])) if isinstance(report.get("event_codes"), list) else set()
    _check("report event code coverage", report_event_codes == REQUIRED_EVENT_CODES, f"seen={sorted(report_event_codes)}")

    trace = report.get("trace_id")
    if not isinstance(trace, str) or re.fullmatch(r"[0-9a-f]{64}", trace) is None:
        trace = _trace_id(report)

    events.append({"event_code": "IRG-001", "trace_id": trace, "message": "Replication report loaded."})
    events.append({"event_code": "IRG-002", "trace_id": trace, "message": "Required claims/schema validated."})
    events.append({"event_code": "IRG-003", "trace_id": trace, "message": "Independence checks validated."})
    events.append(
        {
            "event_code": "IRG-004" if threshold_pass else "IRG-005",
            "trace_id": trace,
            "message": "Threshold gate passed." if threshold_pass else "Threshold gate failed.",
        }
    )
    events.append({"event_code": "IRG-006", "trace_id": trace, "message": "Determinism/adversarial checks executed."})

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "trace_id": trace,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "required_minimum_replications": required_min,
            "replication_count": len(replications),
            "independent_replication_count": evaluation["independent_count"],
            "independent_replications_passing": evaluation["independent_passing"],
            "required_claims": sorted(REQUIRED_CLAIMS),
        },
        "checks": CHECKS,
        "events": events,
    }


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-whxp-self-test-") as tmp:
        root = Path(tmp)
        spec_path = root / "spec.md"
        report_path = root / "report.json"

        spec_path.write_text(
            "\n".join(
                [
                    "# test contract",
                    "INV-IRG-MIN-REPLICATIONS",
                    "INV-IRG-REQUIRED-CLAIMS",
                    "INV-IRG-INDEPENDENCE",
                    "INV-IRG-CONFLICT-DISCLOSURE",
                    "INV-IRG-EVIDENCE-LINKS",
                    "INV-IRG-DETERMINISM",
                    "INV-IRG-ADVERSARIAL",
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        passing = sample_report()
        report_path.write_text(json.dumps(passing, indent=2), encoding="utf-8")
        write_sample_evidence(root)
        pass_result = run_checks(spec_path=spec_path, report_path=report_path)
        if pass_result["verdict"] != "PASS":
            return False

        # The same record with its evidence on a placeholder host is rejected.
        placeholder = sample_report()
        placeholder["replications"][0]["claim_results"]["migration_velocity_3x"][
            "evidence_uri"
        ] = "https://example.org/evidence/migration_velocity.json"
        report_path.write_text(json.dumps(placeholder, indent=2), encoding="utf-8")
        if run_checks(spec_path=spec_path, report_path=report_path)["verdict"] != "FAIL":
            return False
        report_path.write_text(json.dumps(passing, indent=2), encoding="utf-8")

        failing = sample_report()
        failing["replications"][1]["independent"] = False
        failing["summary"]["independent_replication_count"] = 1
        failing["summary"]["independent_replications_passing"] = 1
        failing["summary"]["verdict"] = "FAIL"
        report_path.write_text(json.dumps(failing, indent=2), encoding="utf-8")
        fail_result = run_checks(spec_path=spec_path, report_path=report_path)
        return fail_result["verdict"] == "FAIL"


def main() -> int:
    logger = configure_test_logging("check_independent_replications_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic self-test and exit.")
    args = parser.parse_args()

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed"}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    result = run_checks()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {TITLE}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
