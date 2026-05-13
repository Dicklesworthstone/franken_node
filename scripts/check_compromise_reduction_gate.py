#!/usr/bin/env python3
"""Verify bd-3cpa: concrete target gate for >=10x compromise reduction."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

SPEC = ROOT / "docs" / "specs" / "section_13" / "bd-3cpa_contract.md"
REPORT = ROOT / "artifacts" / "13" / "compromise_reduction_report.json"
BENCHMARK_TEST_RELATIVE_PATH = "crates/franken-node/tests/compromise_reduction_baseline_bench.rs"
BENCHMARK_ARTIFACT_RELATIVE_PATH = "artifacts/adversarial/compromise_reduction_v2.json"
BENCHMARK_TEST_NAME = "compromise_reduction_v2_measures_raw_runtime_baseline_against_strict_policy"
EXPECTED_RAW_BASELINE_RUNTIMES = ["bun", "node"]
REQUIRED_BENCHMARK_ASSERTIONS = {
    "status != baseline_unavailable": "baseline_unavailable",
    "baseline_compromised == Some(20)": "baseline_compromised, Some(20)",
    "franken_compromised == Some(0)": "franken_compromised, Some(0)",
    "ratio == Some(20.0)": "ratio, Some(20.0)",
    "pass_criterion.passed": "pass_criterion.passed",  # nosec B105 - artifact field name
}

REQUIRED_ATTACK_CLASSES = {
    "rce_dependency",
    "prototype_pollution",
    "path_traversal",
    "ssrf",
    "deserialization",
    "supply_chain_injection",
    "privilege_escalation",
    "sandbox_escape",
    "memory_corruption",
    "command_injection",
}

REQUIRED_EVENT_CODES = {
    "CRG-001",
    "CRG-002",
    "CRG-003",
    "CRG-004",
    "CRG-005",
    "CRG-006",
    "CRG-007",
}

ALLOWED_BASELINE_OUTCOMES = {"compromised", "blocked"}
ALLOWED_HARDENED_OUTCOMES = {"compromised", "blocked", "contained"}

CHECKS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return entry


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _number_close(value: Any, expected: float) -> bool:
    return _is_number(value) and abs(float(value) - expected) <= 0.01


def _as_float(value: Any) -> float | None:
    if not _is_number(value):
        return None
    return float(value)


def _attack_required_fields() -> tuple[str, ...]:
    return (
        "attack_id",
        "attack_class",
        "attack_description",
        "baseline_outcome",
        "franken_node_outcome",
        "mitigation",
        "script_command",
        "containment_demonstrated",
    )


def _validate_attack_entry(entry: dict[str, Any], idx: int, errors: list[str]) -> None:
    for field in _attack_required_fields():
        if field not in entry:
            errors.append(f"attack_vectors[{idx}] missing field: {field}")

    for field in (
        "attack_id",
        "attack_class",
        "attack_description",
        "mitigation",
        "script_command",
    ):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"attack_vectors[{idx}].{field} must be non-empty string")

    baseline = entry.get("baseline_outcome")
    if baseline not in ALLOWED_BASELINE_OUTCOMES:
        errors.append(
            f"attack_vectors[{idx}].baseline_outcome invalid: {baseline}"
        )

    hardened = entry.get("franken_node_outcome")
    if hardened not in ALLOWED_HARDENED_OUTCOMES:
        errors.append(
            f"attack_vectors[{idx}].franken_node_outcome invalid: {hardened}"
        )

    containment = entry.get("containment_demonstrated")
    if not isinstance(containment, bool):
        errors.append(f"attack_vectors[{idx}].containment_demonstrated must be boolean")
    elif containment and hardened != "contained":
        errors.append(
            f"attack_vectors[{idx}] containment_demonstrated=true requires franken_node_outcome=contained"
        )

    command = entry.get("script_command")
    if isinstance(command, str) and not command.startswith("python3 "):
        errors.append(
            f"attack_vectors[{idx}].script_command must start with 'python3 '"
        )


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _count_compromised(vectors: list[dict[str, Any]]) -> tuple[int, int, int]:
    baseline = sum(1 for vector in vectors if vector.get("baseline_outcome") == "compromised")
    hardened = sum(1 for vector in vectors if vector.get("franken_node_outcome") == "compromised")
    contained = sum(1 for vector in vectors if vector.get("franken_node_outcome") == "contained")
    return baseline, hardened, contained


def _validate_benchmark_proof(report: dict[str, Any]) -> list[str]:
    proof = report.get("benchmark_proof")
    if not isinstance(proof, dict):
        return ["benchmark_proof must be an object"]

    errors: list[str] = []
    required_fields = (
        "rust_test",
        "rust_test_path",
        "measured_artifact",
        "expected_min_ratio",
        "measured_ratio",
        "baseline_compromised",
        "franken_compromised",
        "baseline_attempts",
        "franken_attempts",
        "raw_baseline_runtimes",
        "fail_closed_baseline_unavailable",
        "proof_assertions",
    )
    missing = [field for field in required_fields if field not in proof]
    if missing:
        errors.append("benchmark_proof missing fields: " + ", ".join(missing))

    if proof.get("rust_test") != BENCHMARK_TEST_NAME:
        errors.append(f"benchmark_proof.rust_test must be {BENCHMARK_TEST_NAME}")
    if proof.get("rust_test_path") != BENCHMARK_TEST_RELATIVE_PATH:
        errors.append(
            f"benchmark_proof.rust_test_path must be {BENCHMARK_TEST_RELATIVE_PATH}"
        )
    if proof.get("measured_artifact") != BENCHMARK_ARTIFACT_RELATIVE_PATH:
        errors.append(
            f"benchmark_proof.measured_artifact must be {BENCHMARK_ARTIFACT_RELATIVE_PATH}"
        )

    minimum_required = _as_float(report.get("minimum_required_ratio", 10.0))
    if minimum_required is None:
        errors.append("minimum_required_ratio must be numeric for benchmark proof")
    else:
        if not _number_close(proof.get("expected_min_ratio"), minimum_required):
            errors.append(
                "benchmark_proof.expected_min_ratio must match minimum_required_ratio"
            )
        measured_ratio = _as_float(proof.get("measured_ratio"))
        if measured_ratio is None or measured_ratio < minimum_required:
            errors.append(
                "benchmark_proof.measured_ratio must satisfy the minimum required ratio"
            )
    if proof.get("baseline_compromised") != 20:
        errors.append("benchmark_proof.baseline_compromised must be 20")
    if proof.get("franken_compromised") != 0:
        errors.append("benchmark_proof.franken_compromised must be 0")
    if proof.get("baseline_attempts") != 20:
        errors.append("benchmark_proof.baseline_attempts must be 20")
    if proof.get("franken_attempts") != 10:
        errors.append("benchmark_proof.franken_attempts must be 10")
    if proof.get("raw_baseline_runtimes") != EXPECTED_RAW_BASELINE_RUNTIMES:
        errors.append("benchmark_proof.raw_baseline_runtimes must be ['bun', 'node']")
    if proof.get("fail_closed_baseline_unavailable") is not True:
        errors.append("benchmark_proof.fail_closed_baseline_unavailable must be true")

    provided_assertions = proof.get("proof_assertions")
    if not isinstance(provided_assertions, list) or not all(
        isinstance(item, str) for item in provided_assertions
    ):
        errors.append("benchmark_proof.proof_assertions must be a string list")
        provided_assertion_set: set[str] = set()
    else:
        provided_assertion_set = set(provided_assertions)
        missing_assertions = sorted(
            set(REQUIRED_BENCHMARK_ASSERTIONS) - provided_assertion_set
        )
        if missing_assertions:
            errors.append(
                "benchmark_proof.proof_assertions missing: "
                + ", ".join(missing_assertions)
            )

    test_path = ROOT / BENCHMARK_TEST_RELATIVE_PATH
    if not test_path.is_file():
        errors.append(f"benchmark proof rust test missing: {_safe_rel(test_path)}")
    else:
        test_text = test_path.read_text(encoding="utf-8")
        if f"fn {BENCHMARK_TEST_NAME}" not in test_text:
            errors.append("benchmark proof rust test function not found in source")
        if f'const ARTIFACT_RELATIVE_PATH: &str = "{BENCHMARK_ARTIFACT_RELATIVE_PATH}"' not in test_text:
            errors.append("benchmark proof source does not write the cited artifact")
        for runtime in EXPECTED_RAW_BASELINE_RUNTIMES:
            if f'resolve_runtime("{runtime}")' not in test_text:
                errors.append(f"benchmark proof source does not resolve runtime {runtime}")
        for label, snippet in REQUIRED_BENCHMARK_ASSERTIONS.items():
            if label in provided_assertion_set and snippet not in test_text:
                errors.append(f"benchmark proof source missing assertion snippet: {label}")

    artifact_path = ROOT / BENCHMARK_ARTIFACT_RELATIVE_PATH
    if not artifact_path.is_file():
        errors.append(f"benchmark proof artifact missing: {_safe_rel(artifact_path)}")
    else:
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"benchmark proof artifact invalid JSON: {exc}")
            artifact = {}
        if not isinstance(artifact, dict):
            errors.append("benchmark proof artifact root must be an object")
            artifact = {}

        pass_criterion = artifact.get("pass_criterion")
        if not isinstance(pass_criterion, dict):
            errors.append("benchmark proof artifact pass_criterion must be an object")
            pass_criterion = {}
        if artifact.get("status") != "measured":
            errors.append("benchmark proof artifact status must be measured")
        if pass_criterion.get("criterion") != ">=10x":
            errors.append("benchmark proof artifact criterion must be >=10x")
        if pass_criterion.get("passed") is not True:
            errors.append("benchmark proof artifact must have passed criterion")
        if artifact.get("baseline_compromised") != proof.get("baseline_compromised"):
            errors.append("benchmark proof baseline_compromised must match artifact")
        if artifact.get("franken_compromised") != proof.get("franken_compromised"):
            errors.append("benchmark proof franken_compromised must match artifact")
        artifact_ratio = _as_float(artifact.get("ratio"))
        if artifact_ratio is None:
            errors.append("benchmark proof artifact ratio must be numeric")
        elif not _number_close(proof.get("measured_ratio"), artifact_ratio):
            errors.append("benchmark proof measured_ratio must match artifact ratio")
        if artifact.get("baseline_attempts") != proof.get("baseline_attempts"):
            errors.append("benchmark proof baseline_attempts must match artifact")
        if artifact.get("franken_attempts") != proof.get("franken_attempts"):
            errors.append("benchmark proof franken_attempts must match artifact")
        artifact_runtimes = [
            runtime.get("name")
            for runtime in artifact.get("runtimes", [])
            if isinstance(runtime, dict)
        ]
        if artifact_runtimes != EXPECTED_RAW_BASELINE_RUNTIMES:
            errors.append("benchmark proof artifact must cite bun and node raw runtimes")

    return errors


def run_checks(spec_path: Path = SPEC, report_path: Path = REPORT) -> dict[str, Any]:
    CHECKS.clear()
    events: list[dict[str, Any]] = []

    _check("file: spec contract", spec_path.is_file(), _safe_rel(spec_path))
    _check("file: compromise reduction report", report_path.is_file(), _safe_rel(report_path))

    spec_text = ""
    if spec_path.is_file():
        spec_text = spec_path.read_text(encoding="utf-8")
    _check("spec threshold >= 10x", ">=10x" in spec_text or ">= 10x" in spec_text)
    _check(
        "spec attack class coverage",
        all(name in spec_text for name in REQUIRED_ATTACK_CLASSES),
    )
    _check("spec event codes", all(code in spec_text for code in REQUIRED_EVENT_CODES))
    _check(
        "spec benchmark proof contract",
        all(
            token in spec_text
            for token in (
                "benchmark_proof",
                BENCHMARK_TEST_RELATIVE_PATH,
                BENCHMARK_ARTIFACT_RELATIVE_PATH,
            )
        ),
    )

    report: dict[str, Any] = {}
    report_errors: list[str] = []
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                report_errors.append("report root must be an object")
        except json.JSONDecodeError as exc:
            report_errors.append(f"invalid report JSON: {exc}")

    _check("report parse", len(report_errors) == 0, "; ".join(report_errors) if report_errors else "ok")
    if report_errors:
        total = len(CHECKS)
        passed = sum(1 for check in CHECKS if check["pass"])
        failed = total - passed
        return {
            "bead_id": "bd-3cpa",
            "title": "Compromise reduction gate (>= 10x)",
            "section": "13",
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
        "campaign_name",
        "campaign_version",
        "reproducible_command",
        "minimum_required_ratio",
        "baseline_compromised",
        "hardened_compromised",
        "compromise_reduction_ratio",
        "total_attack_vectors",
        "containment_vectors",
        "benchmark_proof",
        "attack_vectors",
    )
    missing_top = [field for field in required_top if field not in report]
    _check(
        "report required top-level fields",
        len(missing_top) == 0,
        "missing: " + ", ".join(missing_top) if missing_top else "ok",
    )

    _check("report bead id", report.get("bead_id") == "bd-3cpa")

    timestamp_ok = False
    generated_at = report.get("generated_at_utc")
    if isinstance(generated_at, str) and generated_at:
        try:
            _parse_iso8601(generated_at)
            timestamp_ok = True
        except Exception:
            timestamp_ok = False
    _check("report timestamp valid RFC3339 UTC", timestamp_ok)

    replay_command = report.get("reproducible_command")
    replay_ok = (
        isinstance(replay_command, str)
        and "--replay-campaign" in replay_command
        and replay_command.startswith("python3 scripts/check_compromise_reduction_gate.py")
    )
    _check("reproducible campaign command present", replay_ok)

    vectors = report.get("attack_vectors", [])
    vectors_list = isinstance(vectors, list)
    _check("attack_vectors is list", vectors_list)

    if not vectors_list:
        vectors = []

    _check("attack vector count >= 20", len(vectors) >= 20, f"count={len(vectors)}")
    _check(
        "total_attack_vectors matches list length",
        report.get("total_attack_vectors") == len(vectors),
        f"declared={report.get('total_attack_vectors')}, actual={len(vectors)}",
    )

    attack_errors: list[str] = []
    ids: set[str] = set()
    classes_seen: set[str] = set()
    parsed_vectors: list[dict[str, Any]] = []

    for idx, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            attack_errors.append(f"attack_vectors[{idx}] must be object")
            continue
        _validate_attack_entry(vector, idx, attack_errors)
        parsed_vectors.append(vector)

        attack_id = vector.get("attack_id")
        if isinstance(attack_id, str):
            if attack_id in ids:
                attack_errors.append(f"duplicate attack_id: {attack_id}")
            ids.add(attack_id)

        attack_class = vector.get("attack_class")
        if isinstance(attack_class, str):
            classes_seen.add(attack_class)

    _check(
        "attack entry schema",
        len(attack_errors) == 0,
        "; ".join(attack_errors[:5]) if attack_errors else "ok",
    )

    missing_classes = sorted(REQUIRED_ATTACK_CLASSES - classes_seen)
    _check(
        "required attack classes covered",
        len(missing_classes) == 0,
        "missing: " + ", ".join(missing_classes) if missing_classes else "ok",
    )

    baseline_compromised, hardened_compromised, contained_count = _count_compromised(parsed_vectors)

    _check(
        "baseline compromised count matches declared",
        report.get("baseline_compromised") == baseline_compromised,
        f"declared={report.get('baseline_compromised')}, computed={baseline_compromised}",
    )
    _check(
        "hardened compromised count matches declared",
        report.get("hardened_compromised") == hardened_compromised,
        f"declared={report.get('hardened_compromised')}, computed={hardened_compromised}",
    )
    _check(
        "containment count matches declared",
        report.get("containment_vectors") == contained_count,
        f"declared={report.get('containment_vectors')}, computed={contained_count}",
    )
    _check("containment vectors >= 3", contained_count >= 3, f"containment={contained_count}")

    threshold = report.get("minimum_required_ratio", 10.0)
    ratio = baseline_compromised / hardened_compromised if hardened_compromised > 0 else float("inf")

    declared_ratio = report.get("compromise_reduction_ratio")
    if ratio == float("inf"):
        ratio_matches = isinstance(declared_ratio, str) and declared_ratio.lower() == "infinite"
    else:
        ratio_matches = isinstance(declared_ratio, (int, float)) and abs(float(declared_ratio) - ratio) <= 0.01
    _check(
        "reduction ratio matches computed",
        ratio_matches,
        f"declared={declared_ratio}, computed={ratio if ratio != float('inf') else 'infinite'}",
    )

    threshold_ok = isinstance(threshold, (int, float)) and ratio >= float(threshold)
    _check(
        "compromise reduction threshold >= 10x",
        threshold_ok,
        f"ratio={ratio if ratio != float('inf') else 'infinite'}, threshold={threshold}",
    )

    benchmark_errors = _validate_benchmark_proof(report)
    _check(
        "benchmark proof directly cites measured 10x evidence",
        len(benchmark_errors) == 0,
        "; ".join(benchmark_errors[:8]) if benchmark_errors else "ok",
    )

    # Determinism: metrics must be order-invariant.
    reversed_baseline, reversed_hardened, reversed_contained = _count_compromised(list(reversed(parsed_vectors)))
    reversed_ratio = (
        reversed_baseline / reversed_hardened if reversed_hardened > 0 else float("inf")
    )
    determinism_ok = (
        reversed_baseline == baseline_compromised
        and reversed_hardened == hardened_compromised
        and reversed_contained == contained_count
        and (
            (ratio == float("inf") and reversed_ratio == float("inf"))
            or abs(reversed_ratio - ratio) <= 1e-9
        )
    )
    _check(
        "determinism under reordering",
        determinism_ok,
        (
            f"ratio={ratio if ratio != float('inf') else 'infinite'}, "
            f"reversed_ratio={reversed_ratio if reversed_ratio != float('inf') else 'infinite'}"
        ),
    )

    # Adversarial perturbation: a single additional hardened compromise should drop a borderline pass.
    perturbed_hardened = hardened_compromised + 1
    perturbed_ratio = baseline_compromised / perturbed_hardened if perturbed_hardened > 0 else float("inf")
    adversarial_expected_fail = perturbed_ratio < float(threshold) if isinstance(threshold, (int, float)) else False
    _check(
        "adversarial perturbation flips threshold",
        adversarial_expected_fail,
        f"perturbed_ratio={perturbed_ratio:.4f}, threshold={threshold}",
    )

    trace = report.get("trace_id")
    if not isinstance(trace, str) or not trace:
        trace = _trace_id(report)

    events.append(
        {
            "event_code": "CRG-001",
            "trace_id": trace,
            "message": (
                "Compromise metrics computed "
                f"(baseline={baseline_compromised}, hardened={hardened_compromised}, ratio={ratio:.4f})."
            ),
        }
    )

    events.append(
        {
            "event_code": "CRG-002" if threshold_ok else "CRG-003",
            "trace_id": trace,
            "message": "Compromise reduction gate passed." if threshold_ok else "Compromise reduction gate failed.",
        }
    )

    if len(vectors) < 20 or missing_classes:
        events.append(
            {
                "event_code": "CRG-004",
                "trace_id": trace,
                "message": "Attack vector coverage violation detected.",
            }
        )

    if contained_count < 3:
        events.append(
            {
                "event_code": "CRG-005",
                "trace_id": trace,
                "message": "Containment requirement violation detected.",
            }
        )

    events.append(
        {
            "event_code": "CRG-006",
            "trace_id": trace,
            "message": "Determinism validation executed.",
        }
    )
    events.append(
        {
            "event_code": "CRG-007",
            "trace_id": trace,
            "message": "Adversarial perturbation validation executed.",
        }
    )

    verdict = "PASS" if all(check["pass"] for check in CHECKS) else "FAIL"
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    failed = total - passed

    return {
        "bead_id": "bd-3cpa",
        "title": "Compromise reduction gate (>= 10x)",
        "section": "13",
        "trace_id": trace,
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": failed,
        "computed": {
            "minimum_required_ratio": threshold,
            "compromise_reduction_ratio": round(ratio, 4) if ratio != float("inf") else "infinite",
            "baseline_compromised": baseline_compromised,
            "hardened_compromised": hardened_compromised,
            "total_attack_vectors": len(vectors),
            "containment_vectors": contained_count,
            "missing_attack_classes": missing_classes,
        },
        "checks": CHECKS,
        "events": events,
    }


def replay_campaign(report_path: Path = REPORT) -> dict[str, Any]:
    """Replay aggregate campaign metrics from report artifact only."""
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "ok": False,
            "error": f"failed to load report: {exc}",
            "report": _safe_rel(report_path),
        }

    vectors = report.get("attack_vectors")
    if not isinstance(vectors, list):
        return {
            "ok": False,
            "error": "attack_vectors must be a list",
            "report": _safe_rel(report_path),
        }

    parsed_vectors = [vector for vector in vectors if isinstance(vector, dict)]
    baseline_compromised, hardened_compromised, contained_count = _count_compromised(parsed_vectors)
    ratio = baseline_compromised / hardened_compromised if hardened_compromised > 0 else float("inf")

    payload: dict[str, Any] = {
        "ok": True,
        "bead_id": report.get("bead_id"),
        "campaign_name": report.get("campaign_name"),
        "total_attack_vectors": len(parsed_vectors),
        "baseline_compromised": baseline_compromised,
        "hardened_compromised": hardened_compromised,
        "containment_vectors": contained_count,
        "compromise_reduction_ratio": round(ratio, 4) if ratio != float("inf") else "infinite",
        "trace_id": report.get("trace_id") or _trace_id(report),
    }
    return payload


def self_test() -> bool:
    with tempfile.TemporaryDirectory(prefix="bd-3cpa-self-test-") as tmp:
        root = Path(tmp)
        spec = root / "spec.md"
        report = root / "report.json"

        spec.write_text(
            "\n".join(
                [
                    "# test spec",
                    ">= 10x",
                    "benchmark_proof",
                    BENCHMARK_TEST_RELATIVE_PATH,
                    BENCHMARK_ARTIFACT_RELATIVE_PATH,
                    *sorted(REQUIRED_ATTACK_CLASSES),
                    *sorted(REQUIRED_EVENT_CODES),
                ]
            ),
            encoding="utf-8",
        )

        vectors = []
        classes = sorted(REQUIRED_ATTACK_CLASSES)
        for idx in range(20):
            attack_class = classes[idx % len(classes)]
            hardened_outcome = "blocked"
            contained = False
            if idx in (2, 7, 12):
                hardened_outcome = "contained"
                contained = True
            elif idx in (0, 1):
                hardened_outcome = "compromised"

            vectors.append(
                {
                    "attack_id": f"A{idx + 1:02d}",
                    "attack_class": attack_class,
                    "attack_description": f"attack {idx}",
                    "baseline_outcome": "compromised",
                    "franken_node_outcome": hardened_outcome,
                    "mitigation": "test mitigation",
                    "script_command": f"python3 scripts/check_compromise_reduction_gate.py --simulate-attack A{idx + 1:02d}",
                    "containment_demonstrated": contained,
                }
            )

        baseline, hardened, contained = _count_compromised(vectors)
        ratio = baseline / hardened

        report.write_text(
            json.dumps(
                {
                    "bead_id": "bd-3cpa",
                    "generated_at_utc": "2026-02-21T00:00:00Z",
                    "trace_id": "self-test-trace",
                    "campaign_name": "self-test-campaign",
                    "campaign_version": "1",
                    "reproducible_command": "python3 scripts/check_compromise_reduction_gate.py --replay-campaign --json",
                    "minimum_required_ratio": 10.0,
                    "baseline_compromised": baseline,
                    "hardened_compromised": hardened,
                    "compromise_reduction_ratio": ratio,
                    "total_attack_vectors": len(vectors),
                    "containment_vectors": contained,
                    "benchmark_proof": {
                        "rust_test": BENCHMARK_TEST_NAME,
                        "rust_test_path": BENCHMARK_TEST_RELATIVE_PATH,
                        "measured_artifact": BENCHMARK_ARTIFACT_RELATIVE_PATH,
                        "expected_min_ratio": 10.0,
                        "measured_ratio": 20.0,
                        "baseline_compromised": 20,
                        "franken_compromised": 0,
                        "baseline_attempts": 20,
                        "franken_attempts": 10,
                        "raw_baseline_runtimes": EXPECTED_RAW_BASELINE_RUNTIMES,
                        "fail_closed_baseline_unavailable": True,
                        "proof_assertions": sorted(REQUIRED_BENCHMARK_ASSERTIONS),
                    },
                    "attack_vectors": vectors,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        pass_result = run_checks(spec_path=spec, report_path=report)
        if pass_result["verdict"] != "PASS":
            return False

        # Perturb one additional hardened compromise to force threshold failure.
        data = json.loads(report.read_text(encoding="utf-8"))
        data["attack_vectors"][3]["franken_node_outcome"] = "compromised"
        data["attack_vectors"][3]["containment_demonstrated"] = False
        baseline, hardened, contained = _count_compromised(data["attack_vectors"])
        data["baseline_compromised"] = baseline
        data["hardened_compromised"] = hardened
        data["containment_vectors"] = contained
        data["compromise_reduction_ratio"] = round(baseline / hardened, 4)
        report.write_text(json.dumps(data, indent=2), encoding="utf-8")

        fail_result = run_checks(spec_path=spec, report_path=report)
        return fail_result["verdict"] == "FAIL"


def main() -> int:
    configure_test_logging("check_compromise_reduction_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
    parser.add_argument("--replay-campaign", action="store_true", help="Replay campaign aggregate metrics from report artifact.")
    parser.add_argument("--report", default=str(REPORT), help="Override report path.")
    args = parser.parse_args()

    report_path = Path(args.report)

    if args.self_test:
        ok = self_test()
        payload = {"ok": ok, "self_test": "passed" if ok else "failed"}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload["self_test"])
        return 0 if ok else 1

    if args.replay_campaign:
        payload = replay_campaign(report_path=report_path)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(payload)
        return 0 if payload.get("ok") else 1

    result = run_checks(report_path=report_path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[{result['verdict']}] {result['title']}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
