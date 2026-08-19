#!/usr/bin/env python3
"""Verification script for bd-28sz: >=95% compatibility corpus pass gate.

Usage:
    python3 scripts/check_compatibility_corpus_pass_gate.py
    python3 scripts/check_compatibility_corpus_pass_gate.py --json
    python3 scripts/check_compatibility_corpus_pass_gate.py --self-test --json
"""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging


BEAD_ID = "bd-28sz"
SECTION = "13"
TITLE = "Concrete target gate: >=95% compatibility corpus pass"

# bd-ihusm: the only corpus provenance the release gate accepts. Anything else
# (or absent) means the pass rate was not produced by a genuine oracle run, so
# the gate fails closed rather than consume synthesized totals as if real.
ONLINE_PROVENANCE = "lockstep-oracle-run"
# Must byte-match crates/franken-node/src/ops/close_condition.rs
# (CCG_RESULT_DIGEST_DOMAIN + compute_compatibility_corpus_result_digest).
_RESULT_DIGEST_DOMAIN = b"ccg_corpus_result_digest_v1:"
RUNTIME_OBSERVATIONS_SCHEMA_VERSION = "ccg-runtime-observations-v1"
_RUNTIME_OBSERVATIONS_DIGEST_DOMAIN = b"ccg_runtime_observations_digest_v1:"


def compute_result_digest(per_test_results: list[dict]) -> str:
    """Canonical content digest over per-test results. Domain-separated,
    field-separated (US=0x1f), record-separated (RS=0x1e), sorted by row."""
    rows = sorted(
        [
            str(r.get("test_id", "")),
            str(r.get("api_family", "")),
            str(r.get("band", "")),
            str(r.get("risk_band", "")),
            str(r.get("status", "")),
        ]
        for r in per_test_results
    )
    hasher = hashlib.sha256()
    hasher.update(_RESULT_DIGEST_DOMAIN)
    for row in rows:
        for field in row:
            hasher.update(field.encode("utf-8"))
            hasher.update(b"\x1f")
        hasher.update(b"\x1e")
    return f"sha256:{hasher.hexdigest()}"


def _canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def _u64(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= (2**64 - 1)


def compute_runtime_observations_digest(data: dict) -> str:
    """Validate and bind one concrete run's typed per-runtime observations.

    Elapsed time is intentionally included, so this digest is run-specific;
    the stable semantic result digest remains the five-field v1 projection.
    """
    corpus = data.get("corpus")
    if not isinstance(corpus, dict):
        raise ValueError("compatibility corpus metadata is missing")
    schema = corpus.get("runtime_observations_schema_version")
    if schema != RUNTIME_OBSERVATIONS_SCHEMA_VERSION:
        raise ValueError(f"unsupported runtime observations schema {schema!r}")
    result_digest = corpus.get("result_digest")
    if not isinstance(result_digest, str):
        raise ValueError("semantic result digest is missing")
    topology = corpus.get("lockstep_topology")
    expected_ids = {
        "dyad": {"bun", "franken-engine-native"},
        "triad": {"bun", "franken-engine-native", "node"},
    }.get(topology)
    if expected_ids is None:
        raise ValueError(f"unsupported runtime observation topology {topology!r}")

    runtime_versions: dict[str, str] = {}
    references = corpus.get("reference_runtimes")
    if not isinstance(references, list):
        raise ValueError("reference runtimes are missing")
    for runtime in references:
        if not isinstance(runtime, dict):
            raise ValueError("reference runtime is not an object")
        runtime_id = runtime.get("runtime_id")
        version = runtime.get("version")
        if not isinstance(runtime_id, str) or not runtime_id:
            raise ValueError("reference runtime_id is missing")
        if not isinstance(version, str) or not version:
            raise ValueError(f"reference runtime {runtime_id!r} version is missing")
        if runtime_id in runtime_versions:
            raise ValueError(f"duplicate runtime identity {runtime_id!r}")
        runtime_versions[runtime_id] = version
    product = corpus.get("product_runtime")
    if not isinstance(product, dict):
        raise ValueError("product runtime is missing")
    product_id = product.get("runtime_id")
    product_version = product.get("version")
    if not isinstance(product_id, str) or not product_id:
        raise ValueError("product runtime_id is missing")
    if not isinstance(product_version, str) or not product_version:
        raise ValueError("product runtime version is missing")
    if product_id in runtime_versions:
        raise ValueError(f"duplicate runtime identity {product_id!r}")
    runtime_versions[product_id] = product_version
    if set(runtime_versions) != expected_ids:
        raise ValueError(
            f"runtime observation versions {sorted(runtime_versions)} do not match "
            f"{topology} topology {sorted(expected_ids)}"
        )

    observation_keys = {
        "elapsed_ms",
        "exit_code",
        "stderr_bytes",
        "stderr_digest",
        "stderr_truncated",
        "stdout_bytes",
        "stdout_digest",
        "stdout_truncated",
        "termination_kind",
        "timed_out",
    }
    observations = []
    per_tests = data.get("per_test_results")
    if not isinstance(per_tests, list):
        raise ValueError("per_test_results are missing")
    for row in per_tests:
        if not isinstance(row, dict):
            raise ValueError("runtime observation row is not an object")
        test_id = row.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise ValueError("runtime observation row is missing test_id")
        runtime_observations = row.get("runtime_observations")
        if not isinstance(runtime_observations, dict):
            raise ValueError(f"runtime observation row {test_id!r} is missing an object")
        if set(runtime_observations) != expected_ids:
            raise ValueError(
                f"runtime observation row {test_id!r} keys "
                f"{sorted(runtime_observations)} do not match {topology} topology"
            )
        for runtime_id, observation in runtime_observations.items():
            if not isinstance(observation, dict) or set(observation) != observation_keys:
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} has invalid v1 keys"
                )
            stdout_digest = observation.get("stdout_digest")
            stderr_digest = observation.get("stderr_digest")
            if not _canonical_sha256(stdout_digest) or not _canonical_sha256(stderr_digest):
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} has noncanonical digest"
                )
            stdout_bytes = observation.get("stdout_bytes")
            stderr_bytes = observation.get("stderr_bytes")
            elapsed_ms = observation.get("elapsed_ms")
            if not all(_u64(value) for value in (stdout_bytes, stderr_bytes, elapsed_ms)):
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} has invalid u64 field"
                )
            stdout_truncated = observation.get("stdout_truncated")
            stderr_truncated = observation.get("stderr_truncated")
            timed_out = observation.get("timed_out")
            if not all(
                isinstance(value, bool)
                for value in (stdout_truncated, stderr_truncated, timed_out)
            ):
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} has invalid boolean field"
                )
            exit_code = observation.get("exit_code")
            if exit_code is not None and not (
                isinstance(exit_code, int)
                and not isinstance(exit_code, bool)
                and -(2**31) <= exit_code <= (2**31 - 1)
            ):
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} exit_code is invalid"
                )
            termination_kind = observation.get("termination_kind")
            consistent = (
                (termination_kind == "timed_out" and timed_out)
                or (termination_kind == "exited" and not timed_out and exit_code is not None)
                or (
                    termination_kind == "signal_or_unknown"
                    and not timed_out
                    and exit_code is None
                )
            )
            if not consistent:
                raise ValueError(
                    f"runtime observation {test_id!r}/{runtime_id!r} termination is inconsistent"
                )
            observations.append(
                (
                    test_id,
                    runtime_id,
                    stdout_digest,
                    stderr_digest,
                    stdout_bytes,
                    stderr_bytes,
                    stdout_truncated,
                    stderr_truncated,
                    exit_code,
                    termination_kind,
                    timed_out,
                    elapsed_ms,
                )
            )

    hasher = hashlib.sha256()
    hasher.update(_RUNTIME_OBSERVATIONS_DIGEST_DOMAIN)

    def hash_field(label: str, value: bytes) -> None:
        label_bytes = label.encode("utf-8")
        hasher.update(len(label_bytes).to_bytes(8, "big"))
        hasher.update(label_bytes)
        hasher.update(len(value).to_bytes(8, "big"))
        hasher.update(value)

    hash_field("schema_version", schema.encode("utf-8"))
    hash_field("result_digest", result_digest.encode("utf-8"))
    hash_field("topology", topology.encode("utf-8"))
    for runtime_id, version in sorted(runtime_versions.items()):
        hash_field("runtime_id", runtime_id.encode("utf-8"))
        hash_field("runtime_version", version.encode("utf-8"))
    for observation in sorted(observations, key=lambda item: (item[0], item[1])):
        (
            test_id,
            runtime_id,
            stdout_digest,
            stderr_digest,
            stdout_bytes,
            stderr_bytes,
            stdout_truncated,
            stderr_truncated,
            exit_code,
            termination_kind,
            timed_out,
            elapsed_ms,
        ) = observation
        hash_field("test_id", test_id.encode("utf-8"))
        hash_field("runtime_id", runtime_id.encode("utf-8"))
        hash_field("stdout_digest", stdout_digest.encode("utf-8"))
        hash_field("stderr_digest", stderr_digest.encode("utf-8"))
        hash_field("stdout_bytes", stdout_bytes.to_bytes(8, "big"))
        hash_field("stderr_bytes", stderr_bytes.to_bytes(8, "big"))
        hash_field("stdout_truncated", bytes([stdout_truncated]))
        hash_field("stderr_truncated", bytes([stderr_truncated]))
        encoded_exit = (
            bytes([0])
            if exit_code is None
            else bytes([1]) + exit_code.to_bytes(4, "big", signed=True)
        )
        hash_field("exit_code", encoded_exit)
        hash_field("termination_kind", termination_kind.encode("utf-8"))
        hash_field("timed_out", bytes([timed_out]))
        hash_field("elapsed_ms", elapsed_ms.to_bytes(8, "big"))
    return f"sha256:{hasher.hexdigest()}"

CONTRACT = ROOT / "docs" / "specs" / "section_13" / "bd-28sz_contract.md"
REPORT = ROOT / "artifacts" / "13" / "compatibility_corpus_results.json"
DEFAULT_MIN_CASES = 500

REQUIRED_EVENT_CODES = ["CCG-001", "CCG-002", "CCG-003", "CCG-004"]
REQUIRED_RISK_BANDS = {"critical", "high", "medium", "low"}
REQUIRED_BANDS = {"core", "high-value", "edge"}
REQUIRED_FAMILIES = {
    "fs",
    "http",
    "net",
    "crypto",
    "stream",
    "buffer",
    "path",
    "os",
    "child_process",
    "cluster",
    "events",
    "timers",
    "url",
    "querystring",
    "zlib",
    "tls",
}
REQUIRED_CONTRACT_TERMS = [
    "INV-CCG-OVERALL",
    "INV-CCG-BAND",
    "INV-CCG-FAMILY-FLOOR",
    "INV-CCG-CORPUS-SIZE",
    "INV-CCG-TRACKING",
    "INV-CCG-REPRODUCIBILITY",
    "INV-CCG-RATCHET",
    "INV-CCG-PROVENANCE",
    "INV-CCG-DIGEST-BINDING",
    "Scenario A",
    "Scenario B",
    "Scenario C",
    "Scenario D",
]


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    try:
        display_path = path.relative_to(ROOT)
    except ValueError:
        display_path = path
    return {
        "check": f"file: {label}",
        "pass": ok,
        "detail": f"exists: {display_path}" if ok else f"MISSING: {path}",
    }


def check_contract() -> list[dict]:
    checks = []
    if not CONTRACT.exists():
        checks.append({"check": "contract: exists", "pass": False, "detail": "MISSING"})
        return checks

    text = CONTRACT.read_text(encoding="utf-8")
    checks.append({"check": "contract: exists", "pass": True, "detail": "found"})

    for term in REQUIRED_CONTRACT_TERMS:
        present = term in text
        checks.append({
            "check": f"contract: term {term}",
            "pass": present,
            "detail": "present" if present else "MISSING",
        })
    return checks


def load_report(report_path: Path = REPORT) -> tuple[dict | None, list[dict]]:
    checks = []
    if not report_path.exists():
        checks.append({"check": "report: exists", "pass": False, "detail": "MISSING"})
        return None, checks

    checks.append({"check": "report: exists", "pass": True, "detail": "found"})

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        checks.append({"check": "report: valid json", "pass": False, "detail": "invalid"})
        return None, checks

    checks.append({"check": "report: valid json", "pass": True, "detail": "valid"})
    return data, checks


def pass_rate(passed: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((passed / total) * 100.0, 2)


def aggregate_by_key(per_tests: list[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for row in per_tests:
        k = str(row.get(key, ""))
        out.setdefault(k, {"total": 0, "passed": 0})
        out[k]["total"] += 1
        if row.get("status") == "pass":
            out[k]["passed"] += 1
    for value in out.values():
        value["pass_rate_pct"] = pass_rate(value["passed"], value["total"])
    return out


def evaluate_gate(data: dict) -> dict:
    per_tests = data.get("per_test_results", [])
    prev = data.get("previous_release", {})
    thresholds = data.get("thresholds", {})

    total = len(per_tests)
    passed = sum(1 for r in per_tests if r.get("status") == "pass")
    current_rate = pass_rate(passed, total)
    prev_rate = float(prev.get("overall_pass_rate_pct", 0.0))

    overall_threshold = float(thresholds.get("overall_pass_rate_min_pct", 95.0))
    family_floor = float(thresholds.get("per_family_pass_rate_min_pct", 80.0))
    band_thresholds = thresholds.get("band_pass_rate_min_pct", {})

    family_breakdown = aggregate_by_key(per_tests, "api_family")
    band_breakdown = aggregate_by_key(per_tests, "band")

    families_ok = all(v["pass_rate_pct"] >= family_floor for v in family_breakdown.values())
    bands_ok = all(
        band_breakdown.get(band, {"pass_rate_pct": -1.0})["pass_rate_pct"] >= float(req)
        for band, req in band_thresholds.items()
    )
    threshold_met = current_rate >= overall_threshold and families_ok and bands_ok
    regression = current_rate < prev_rate

    return {
        "current_rate": current_rate,
        "previous_rate": prev_rate,
        "overall_threshold": overall_threshold,
        "threshold_met": threshold_met,
        "regression_detected": regression,
        "release_blocked": (not threshold_met) or regression,
        "family_breakdown": family_breakdown,
        "band_breakdown": band_breakdown,
    }


def check_report(data: dict | None, minimum_cases: int = DEFAULT_MIN_CASES) -> list[dict]:
    if data is None:
        return []

    checks = []
    totals = data.get("totals", {})
    per_tests = data.get("per_test_results", [])
    families = data.get("api_families", [])
    failures = data.get("failing_tests_tracking", [])
    ci = data.get("ci_gate", {})
    reproducibility = data.get("reproducibility", {})

    total = int(totals.get("total_test_cases", 0))
    passed = int(totals.get("passed_test_cases", 0))
    failed = int(totals.get("failed_test_cases", 0))
    errored = int(totals.get("errored_test_cases", 0))
    skipped = int(totals.get("skipped_test_cases", 0))

    checks.append({
        "check": f"corpus: total test cases >= {minimum_cases}",
        "pass": total >= minimum_cases,
        "detail": f"total={total}",
    })

    checks.append({
        "check": "corpus: per_test_results count matches total",
        "pass": len(per_tests) == total,
        "detail": f"per_test={len(per_tests)} total={total}",
    })

    checks.append({
        "check": "totals: count partition is consistent",
        "pass": total == (passed + failed + errored + skipped),
        "detail": f"total={total} partition={passed + failed + errored + skipped}",
    })

    recomputed_overall = pass_rate(sum(1 for r in per_tests if r.get("status") == "pass"), len(per_tests))
    reported_overall = float(totals.get("overall_pass_rate_pct", -1.0))
    checks.append({
        "check": "totals: overall pass rate matches recomputation",
        "pass": abs(recomputed_overall - reported_overall) < 0.01,
        "detail": f"reported={reported_overall} computed={recomputed_overall}",
    })

    family_names = {str(f.get("family")) for f in families}
    checks.append({
        "check": "coverage: all required API families present",
        "pass": REQUIRED_FAMILIES.issubset(family_names),
        "detail": f"present={len(family_names)} required={len(REQUIRED_FAMILIES)}",
    })

    per_test_family_names = {str(r.get("api_family")) for r in per_tests}
    checks.append({
        "check": "coverage: per-test family coverage includes required set",
        "pass": REQUIRED_FAMILIES.issubset(per_test_family_names),
        "detail": f"present={len(per_test_family_names)} required={len(REQUIRED_FAMILIES)}",
    })

    tags_valid = all(
        isinstance(r.get("test_id"), str)
        and r.get("api_family") in REQUIRED_FAMILIES
        and r.get("band") in REQUIRED_BANDS
        and r.get("risk_band") in REQUIRED_RISK_BANDS
        and r.get("status") in {"pass", "fail", "error", "skip"}
        for r in per_tests
    )
    checks.append({
        "check": "per-test: required tags and enums valid",
        "pass": tags_valid,
        "detail": "valid" if tags_valid else "invalid tag/value detected",
    })

    observed_risk_bands = {r.get("risk_band") for r in per_tests}
    checks.append({
        "check": "per-test: all risk bands represented",
        "pass": REQUIRED_RISK_BANDS.issubset(observed_risk_bands),
        "detail": f"observed={sorted(observed_risk_bands)}",
    })

    # bd-ihusm: provenance honesty + digest binding. The pass rate is only real
    # if the corpus attests a genuine oracle run and its per-test results are
    # content-bound by a recomputable digest — a fabricated `result_digest` or
    # authored/synthesized provenance fails the gate closed.
    corpus_meta = data.get("corpus", {})
    provenance = corpus_meta.get("provenance")
    checks.append({
        "check": "provenance: corpus attests a genuine oracle run",
        "pass": provenance == ONLINE_PROVENANCE,
        "detail": f"provenance={provenance!r} expected={ONLINE_PROVENANCE!r}",
    })
    declared_digest = corpus_meta.get("result_digest")
    recomputed_digest = compute_result_digest(per_tests) if per_tests else None
    checks.append({
        "check": "provenance: result_digest recomputes from per_test_results",
        "pass": (
            recomputed_digest is not None
            and isinstance(declared_digest, str)
            and hmac.compare_digest(declared_digest, recomputed_digest)
        ),
        "detail": f"declared={declared_digest} computed={recomputed_digest}",
    })
    declared_runtime_observations_digest = corpus_meta.get("runtime_observations_digest")
    runtime_observations_error = None
    try:
        recomputed_runtime_observations_digest = compute_runtime_observations_digest(data)
    except (TypeError, ValueError) as error:
        recomputed_runtime_observations_digest = None
        runtime_observations_error = str(error)
    checks.append({
        "check": "provenance: runtime observations are topology-bound and digest-bound",
        "pass": (
            recomputed_runtime_observations_digest is not None
            and isinstance(declared_runtime_observations_digest, str)
            and hmac.compare_digest(
                declared_runtime_observations_digest,
                recomputed_runtime_observations_digest,
            )
        ),
        "detail": (
            f"error={runtime_observations_error}"
            if runtime_observations_error is not None
            else "declared="
            f"{declared_runtime_observations_digest} "
            f"computed={recomputed_runtime_observations_digest}"
        ),
    })

    gate_eval = evaluate_gate(data)
    checks.append({
        "check": "gate: overall threshold >=95 met",
        "pass": gate_eval["current_rate"] >= gate_eval["overall_threshold"],
        "detail": f"current={gate_eval['current_rate']} threshold={gate_eval['overall_threshold']}",
    })

    family_floor = float(data.get("thresholds", {}).get("per_family_pass_rate_min_pct", 80.0))
    low_families = [
        fam for fam, stat in gate_eval["family_breakdown"].items()
        if stat["pass_rate_pct"] < family_floor
    ]
    checks.append({
        "check": "gate: no family below 80%",
        "pass": len(low_families) == 0,
        "detail": "all pass" if len(low_families) == 0 else f"below-floor={low_families}",
    })

    band_thresholds = data.get("thresholds", {}).get("band_pass_rate_min_pct", {})
    for band, threshold in band_thresholds.items():
        observed = gate_eval["band_breakdown"].get(band, {}).get("pass_rate_pct", -1.0)
        checks.append({
            "check": f"gate: band {band} >= {threshold}%",
            "pass": observed >= float(threshold),
            "detail": f"observed={observed}",
        })

    failure_ids = {
        r.get("test_id") for r in per_tests if r.get("status") in {"fail", "error"}
    }
    tracking_ids = {f.get("test_id") for f in failures}
    checks.append({
        "check": "tracking: failing tests have bead tracking entries",
        "pass": failure_ids.issubset(tracking_ids),
        "detail": f"failing={len(failure_ids)} tracked={len(tracking_ids)}",
    })

    tracking_shape_ok = all(
        isinstance(f.get("investigation_bead_id"), str)
        and f.get("investigation_bead_id", "").startswith("bd-")
        and f.get("investigation_status") in {"open", "in_progress", "closed"}
        for f in failures
    )
    checks.append({
        "check": "tracking: bead ids and statuses valid",
        "pass": tracking_shape_ok,
        "detail": "valid" if tracking_shape_ok else "invalid tracking entry",
    })

    checks.append({
        "check": "ci gate: report reflects met threshold and non-blocked release",
        "pass": bool(ci.get("threshold_met", False)) and not bool(ci.get("release_blocked", True)),
        "detail": f"threshold_met={ci.get('threshold_met')} release_blocked={ci.get('release_blocked')}",
    })

    checks.append({
        "check": "regression: no pass-rate decrease vs previous release",
        "pass": not gate_eval["regression_detected"],
        "detail": f"current={gate_eval['current_rate']} previous={gate_eval['previous_rate']}",
    })

    report_codes = data.get("event_codes", [])
    for code in REQUIRED_EVENT_CODES:
        checks.append({
            "check": f"events: {code}",
            "pass": code in report_codes,
            "detail": "present" if code in report_codes else "MISSING",
        })

    repro_ok = (
        isinstance(reproducibility.get("deterministic_seed"), str)
        and bool(reproducibility.get("same_inputs_same_digest", False))
        and isinstance(reproducibility.get("external_repro_command"), str)
        and len(reproducibility.get("external_repro_command", "")) > 0
    )
    checks.append({
        "check": "reproducibility: deterministic metadata complete",
        "pass": repro_ok,
        "detail": "complete" if repro_ok else "missing deterministic fields",
    })

    recomputed_family = aggregate_by_key(list(per_tests), "api_family")
    recomputed_band = aggregate_by_key(list(per_tests), "band")
    reversed_family = aggregate_by_key(list(reversed(per_tests)), "api_family")
    reversed_band = aggregate_by_key(list(reversed(per_tests)), "band")
    deterministic = (recomputed_family == reversed_family) and (recomputed_band == reversed_band)
    checks.append({
        "check": "determinism: order-insensitive aggregates",
        "pass": deterministic,
        "detail": "stable" if deterministic else "unstable",
    })

    adversarial = json.loads(json.dumps(data))
    flips = 0
    for row in adversarial.get("per_test_results", []):
        if row.get("status") == "pass":
            row["status"] = "fail"
            flips += 1
        if flips >= 30:
            break
    adv_eval = evaluate_gate(adversarial)
    checks.append({
        "check": "adversarial: threshold drop blocks release",
        "pass": adv_eval["release_blocked"] and (not adv_eval["threshold_met"]),
        "detail": f"adversarial_rate={adv_eval['current_rate']} blocked={adv_eval['release_blocked']}",
    })

    return checks


def run_checks(
    report_path: Path = REPORT,
    minimum_cases: int = DEFAULT_MIN_CASES,
) -> dict:
    checks = []
    checks.append(check_file(CONTRACT, "contract doc"))
    checks.append(check_file(report_path, "compatibility corpus report"))
    checks.extend(check_contract())
    data, load_checks = load_report(report_path)
    checks.extend(load_checks)
    checks.extend(check_report(data, minimum_cases))

    passing = sum(1 for c in checks if c["pass"])
    failing = sum(1 for c in checks if not c["pass"])

    return {
        "bead_id": BEAD_ID,
        "title": TITLE,
        "section": SECTION,
        "report_path": str(report_path),
        "minimum_cases": minimum_cases,
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict]]:
    sample = {
        "totals": {"total_test_cases": 10, "passed_test_cases": 10},
        "per_test_results": [
            {"test_id": "a", "api_family": "fs", "band": "core", "risk_band": "critical", "status": "pass"},
            {"test_id": "b", "api_family": "http", "band": "core", "risk_band": "critical", "status": "pass"},
            {"test_id": "c", "api_family": "querystring", "band": "edge", "risk_band": "low", "status": "pass"},
        ],
        "thresholds": {
            "overall_pass_rate_min_pct": 95.0,
            "per_family_pass_rate_min_pct": 80.0,
            "band_pass_rate_min_pct": {"core": 99.0, "high-value": 95.0, "edge": 90.0},
        },
        "previous_release": {"overall_pass_rate_pct": 90.0},
    }
    checks = []
    checks.append({"check": "self: pass_rate helper", "pass": pass_rate(95, 100) == 95.0})
    checks.append({"check": "self: evaluate gate release blocked", "pass": evaluate_gate(sample)["release_blocked"]})
    # bd-ihusm: cross-language digest pin. This exact vector + digest is
    # asserted by the Rust gate test
    # (doctor_close_condition_e2e::ccg_result_digest_cross_language_pin_bd_ihusm);
    # if either implementation drifts, one side fails.
    digest_vector = [
        {"test_id": "tc::fs::0001", "api_family": "fs", "band": "core", "risk_band": "critical", "status": "pass"},
        {"test_id": "tc::http::0002", "api_family": "http", "band": "high-value", "risk_band": "high", "status": "fail"},
    ]
    expected_digest = "sha256:06e98e8bb825890faefa66f04c5e9682ed86738c3eac75725db7f636881257b0"
    checks.append({
        "check": "self: result_digest cross-language vector",
        "pass": hmac.compare_digest(compute_result_digest(digest_vector), expected_digest)
        and hmac.compare_digest(
            compute_result_digest(list(reversed(digest_vector))), expected_digest
        ),
    })
    return all(c["pass"] for c in checks), checks


def main() -> int:
    configure_test_logging("check_compatibility_corpus_pass_gate")
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument("--self-test", action="store_true", help="run internal checks")
    parser.add_argument(
        "--report",
        type=Path,
        default=REPORT,
        help="compatibility corpus report to validate",
    )
    parser.add_argument(
        "--min-cases",
        type=int,
        default=DEFAULT_MIN_CASES,
        help="minimum required per-test result count",
    )
    args = parser.parse_args()
    if args.min_cases <= 0:
        parser.error("--min-cases must be greater than zero")

    if args.self_test:
        ok, checks = self_test()
        result = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("PASS" if ok else "FAIL")
            for check in checks:
                status = "PASS" if check["pass"] else "FAIL"
                print(f"[{status}] {check['check']}")
        return 0 if ok else 1

    result = run_checks(args.report, args.min_cases)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        verdict = result["verdict"]
        summary = result["summary"]
        print(f"{verdict}: {result['title']} ({summary['passing']}/{summary['total']} checks passed)")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"[{status}] {check['check']}: {check['detail']}")
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
