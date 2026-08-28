#!/usr/bin/env python3
"""Verify the LIVE migration-velocity gate (CLAIM-002, >= 3x throughput).

Subject: the signed, live-measured pair
  artifacts/migration/throughput_delta.json          (signed summary)
  artifacts/migration/throughput_delta_evidence.json (measurement census)
produced by scripts/emit_migration_throughput_delta.py from real
`franken-node migrate audit/rewrite/validate` invocations against the frozen
cohort of checked-in fixtures plus the holdout fixture.

This gate is an INDEPENDENT verifier: it reimplements the canonicalization,
Ed25519 verification, corpus digest, median/basis-point math, and the
splitmix64 bootstrap rather than importing them from the producer, so a green
run is two implementations agreeing. It fails closed when:

* the artifacts are missing, malformed, or carry floats;
* the Ed25519 signature does not verify under the pinned throughput harness
  key (or an operator anchor);
* any census entry's declared medians/ratio disagree with its recorded runs;
* the pooled medians, velocity ratio, or bootstrap CI disagree with the
  census;
* the corpus digest does not commit to the census;
* the frozen fixture inputs no longer match the digests recorded at
  measurement time;
* the holdout contract (exactly one holdout fixture) is violated;
* any constructed Feb 2026 archetype ID (bd-3agp's fictional
  ``cohort-*-001`` cohort) appears in the cohort;
* the velocity ratio is below the signed 3.0x threshold.

The constructed Feb 2026 report (artifacts/13/migration_velocity_report.json)
is NOT evidence and is no longer read by this gate (bd-reality-20260820-w0fc6.2).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

SUMMARY = ROOT / "artifacts" / "migration" / "throughput_delta.json"
EVIDENCE = ROOT / "artifacts" / "migration" / "throughput_delta_evidence.json"

# Byte-compatibility constants — MUST match
# sdk/verifier/src/migration_throughput.rs and the emitter.
MIGTP_SCHEMA = "franken-node/migration-throughput/v1"
MIGTP_EVIDENCE_SCHEMA = "franken-node/migration-throughput-evidence/v1"
MIGTP_SIGNATURE_ALGORITHM = "ed25519"
MIGTP_HARNESS_KEY_ID = "franken-node-migration-throughput-harness-v1"
MIGTP_SIGNATURE_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-signature:v1:"
MIGTP_EVIDENCE_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-evidence:v1:"
MIGTP_CORPUS_DOMAIN = b"frankenengine-verifier-sdk:migration-throughput-corpus:v1:"
MIGTP_SEED_PREIMAGE = b"frankenengine-verifier-sdk:migration-throughput-harness-key:v1"
SHA256_PREFIX = "sha256:"
REQUIRED_VELOCITY_RATIO_BP = 30_000
MASK64 = (1 << 64) - 1

EVENT_CODES = {
    "MTP-001",
    "MTP-002",
    "MTP-003",
    "MTP-004",
}

CONSTRUCTED_COHORT_IDS = {
    "cohort-express-001",
    "cohort-fastify-001",
    "cohort-next-001",
    "cohort-nextjs-001",
    "cohort-cli-tool-001",
    "cohort-library-001",
    "cohort-worker-001",
    "cohort-websocket-001",
    "cohort-monorepo-001",
    "cohort-native-addons-001",
    "cohort-custom-build-001",
}

CHECKS: list[dict[str, Any]] = []
EVENTS: list[dict[str, Any]] = []


def _check(name: str, passed: bool, detail: str = "") -> bool:
    entry = {
        "check": name,
        "pass": bool(passed),
        "detail": detail or ("found" if passed else "NOT FOUND"),
    }
    CHECKS.append(entry)
    return bool(passed)


def _event(code: str, trace_id: str, message: str) -> None:
    EVENTS.append({"event_code": code, "trace_id": trace_id, "message": message})


def _trace_id(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Independent verification primitives
# --------------------------------------------------------------------------- #
def _reject_floats(value: Any, path: str = "$") -> str | None:
    if isinstance(value, float):
        return path
    if isinstance(value, list):
        for index, item in enumerate(value):
            hit = _reject_floats(item, f"{path}[{index}]")
            if hit:
                return hit
    elif isinstance(value, dict):
        for key, item in value.items():
            hit = _reject_floats(item, f"{path}.{key}")
            if hit:
                return hit
    return None


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_prefixed(domain: bytes, payload: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(len(payload).to_bytes(8, "little"))
    hasher.update(payload)
    return SHA256_PREFIX + hasher.hexdigest()


def _corpus_digest(pairs: list) -> str:
    hasher = hashlib.sha256()
    hasher.update(MIGTP_CORPUS_DOMAIN)
    for fixture_id, digest in sorted(pairs):
        fid = fixture_id.encode("utf-8")
        dig = digest.encode("utf-8")
        hasher.update(len(fid).to_bytes(8, "little"))
        hasher.update(fid)
        hasher.update(len(dig).to_bytes(8, "little"))
        hasher.update(dig)
    return SHA256_PREFIX + hasher.hexdigest()


def _signature_message(canonical_unsigned: bytes) -> bytes:
    return (
        MIGTP_SIGNATURE_DOMAIN
        + len(canonical_unsigned).to_bytes(8, "little")
        + canonical_unsigned
    )


def _harness_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(MIGTP_SEED_PREIMAGE).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public_hex = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return private, public_hex


def _verify_signature(unsigned: dict, signature: dict, private, public_hex: str) -> tuple[bool, str]:
    import hmac

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if signature.get("algorithm") != MIGTP_SIGNATURE_ALGORITHM:
        return False, "algorithm"
    if signature.get("signer_key_id") != MIGTP_HARNESS_KEY_ID:
        return False, "key id"
    embedded = str(signature.get("signer_public_key_hex", ""))
    if not hmac.compare_digest(embedded, public_hex):
        return False, "signer key mismatch"
    message = _signature_message(_canonical_bytes(unsigned))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(embedded)).verify(
            bytes.fromhex(str(signature.get("signature_hex", ""))), message
        )
    except (InvalidSignature, ValueError):
        return False, "signature invalid"
    return True, "ok"


def _median_int(values: list) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("median of empty list")
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) // 2


def _ratio_bp(numerator_ms: int, denominator_ms: int) -> int:
    if numerator_ms < 0 or denominator_ms <= 0:
        raise ValueError("ratio requires positive denominator")
    return (numerator_ms * 10_000 + denominator_ms // 2) // denominator_ms


def _splitmix64(state: int) -> tuple:
    state = (state + 0x9E3779B97F4A7C15) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return state, z ^ (z >> 31)


def _bootstrap_ci_bp(pairs: list, resamples: int, seed: int) -> dict:
    n = len(pairs)
    if n == 0 or resamples <= 0:
        raise ValueError("bootstrap requires samples")
    state = seed & MASK64
    ratios: list[int] = []
    for _ in range(resamples):
        tool_sample: list[int] = []
        baseline_sample: list[int] = []
        for _ in range(n):
            state, out = _splitmix64(state)
            index = out % n
            tool_sample.append(pairs[index][0])
            baseline_sample.append(pairs[index][1])
        tool_med = _median_int(tool_sample)
        if tool_med == 0:
            continue
        ratios.append(_ratio_bp(_median_int(baseline_sample), tool_med))
    if not ratios:
        raise ValueError("bootstrap produced no usable resamples")
    ratios.sort()
    lo = (2 * resamples) // 40
    hi = min(len(ratios) - 1, len(ratios) - 1 - (2 * resamples) // 40)
    return {
        "resamples": resamples,
        "seed": seed,
        "ci95_low_bp": ratios[lo],
        "ci95_high_bp": ratios[hi],
    }


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _strict_ints(text: str) -> Any:
    def no_float(raw: str) -> Any:
        raise ValueError(f"float value in signed payload: {raw}")

    return json.loads(text, parse_float=no_float, parse_constant=no_float)


def run_checks(summary_path: Path = SUMMARY, evidence_path: Path = EVIDENCE) -> dict:
    CHECKS.clear()
    EVENTS.clear()

    _check("file: signed summary", summary_path.is_file(), _rel(summary_path))
    _check("file: evidence census", evidence_path.is_file(), _rel(evidence_path))
    if not (summary_path.is_file() and evidence_path.is_file()):
        return _verdict(
            "FAIL",
            "MTP-004",
            "throughput_delta artifacts missing; run "
            "scripts/emit_migration_throughput_delta.py to measure live",
        )

    try:
        summary = _strict_ints(summary_path.read_text(encoding="utf-8"))
        evidence = _strict_ints(evidence_path.read_text(encoding="utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        return _verdict("FAIL", "MTP-004", f"artifact parse/float rejection: {exc}")

    _check("summary schema", summary.get("schema_version") == MIGTP_SCHEMA)
    _check("evidence schema", evidence.get("schema_version") == MIGTP_EVIDENCE_SCHEMA)
    if not (
        _check("summary is object", isinstance(summary, dict))
        and _check("evidence is object", isinstance(evidence, dict))
    ):
        return _verdict("FAIL", "MTP-004", "artifact roots must be objects")

    # Signature over the canonical unsigned payload.
    unsigned = {key: value for key, value in summary.items() if key != "signature"}
    private, public_hex = _harness_keys()
    signature_ok, signature_detail = _verify_signature(
        unsigned, summary.get("signature", {}), private, public_hex
    )
    _check("ed25519 signature under harness anchor", signature_ok, signature_detail)

    # Census structure + per-fixture recompute.
    fixtures = evidence.get("fixtures")
    if not _check("census fixtures list", isinstance(fixtures, list) and len(fixtures) > 0):
        return _verdict("FAIL", "MTP-004", "census fixtures missing or empty")

    corpus_pairs: list = []
    pooled: list = []
    per_fixture_ok = True
    fixture_ids: list = []
    holdout_ids: list = []
    for entry in fixtures:
        fixture_id = str(entry.get("fixture_id", ""))
        fixture_ids.append(fixture_id)
        if entry.get("role") == "holdout":
            holdout_ids.append(fixture_id)
        runs = entry.get("runs", [])
        tool_values = [int(run.get("tool_ms", 0)) for run in runs]
        baseline_values = [int(run.get("baseline_ms", 0)) for run in runs]
        entry_ok = len(runs) > 0
        if entry_ok:
            tool_median = _median_int(tool_values)
            baseline_median = _median_int(baseline_values)
            ratio = _ratio_bp(baseline_median, tool_median)
            entry_ok = (
                tool_median == int(entry.get("tool_median_ms", -1))
                and baseline_median == int(entry.get("baseline_median_ms", -1))
                and ratio == int(entry.get("ratio_bp", -1))
            )
            pooled.extend((tool, base) for tool, base in zip(tool_values, baseline_values))
        corpus_pairs.append((fixture_id, _sha256_prefixed(MIGTP_EVIDENCE_DOMAIN, _canonical_bytes(entry))))
        per_fixture_ok = per_fixture_ok and entry_ok
    _check(
        "per-fixture medians/ratios recompute from runs",
        per_fixture_ok,
        "" if per_fixture_ok else "declared aggregates disagree with recorded runs",
    )

    # Frozen-input binding: recorded digests must still match the tree.
    frozen_ok, frozen_detail = _check_frozen_inputs(fixtures)
    _check("frozen fixture inputs match recorded digests", frozen_ok, frozen_detail)

    # Corpus digest.
    declared_corpus = str(summary.get("corpus_digest", ""))
    recomputed_corpus = _corpus_digest(corpus_pairs)
    _check("corpus digest commits to census", declared_corpus == recomputed_corpus)

    # Fixture-set + holdout + constructed-ID contracts.
    declared_ids = sorted(
        [str(item) for item in summary.get("fixture_ids_cohort", [])]
        + [str(item) for item in summary.get("fixture_ids_holdout", [])]
    )
    _check("delta fixture ids match census", declared_ids == sorted(fixture_ids))
    _check("exactly one holdout fixture", len(holdout_ids) == 1, f"holdouts={holdout_ids}")
    constructed_hits = sorted(set(fixture_ids) & CONSTRUCTED_COHORT_IDS)
    _check(
        "constructed Feb 2026 archetype cohort rejected (bd-reality-20260820-w0fc6.2)",
        not constructed_hits,
        "constructed ids: " + ",".join(constructed_hits) if constructed_hits else "ok",
    )

    # Pooled aggregates + bootstrap.
    pooled_tool = _median_int([pair[0] for pair in pooled])
    pooled_baseline = _median_int([pair[1] for pair in pooled])
    recomputed_ratio = _ratio_bp(pooled_baseline, pooled_tool)
    _check("pooled medians recompute", pooled_tool == int(summary.get("median_tool_ms", -1)) and pooled_baseline == int(summary.get("median_baseline_ms", -1)))
    _check(
        "velocity ratio recomputes from census",
        recomputed_ratio == int(summary.get("velocity_ratio_bp", -1)),
        f"declared={summary.get('velocity_ratio_bp')}, recomputed={recomputed_ratio}",
    )
    try:
        ci = summary.get("bootstrap_ci95", {})
        recomputed_ci = _bootstrap_ci_bp(
            pooled, int(ci.get("resamples", 0)), int(ci.get("seed", 0))
        )
        ci_ok = (
            recomputed_ci["ci95_low_bp"] == int(ci.get("ci95_low_bp", -1))
            and recomputed_ci["ci95_high_bp"] == int(ci.get("ci95_high_bp", -1))
        )
        _check("bootstrap CI95 recomputes deterministically", ci_ok)
    except ValueError as exc:
        _check("bootstrap CI95 recomputes deterministically", False, str(exc))

    # Threshold + holdout ratio.
    required = int(summary.get("required_velocity_ratio_bp", 0))
    threshold_ok = _check(
        "required ratio pinned at 3x",
        required == REQUIRED_VELOCITY_RATIO_BP,
        f"required={required}",
    )
    ratio_ok = _check(
        "velocity threshold >= 3x",
        recomputed_ratio >= required,
        f"ratio_bp={recomputed_ratio}, required_bp={required}",
    )
    holdout_entry = next((entry for entry in fixtures if entry.get("role") == "holdout"), None)
    holdout_ok = _check(
        "holdout ratio matches census",
        bool(holdout_entry)
        and int(summary.get("holdout_ratio_bp", -1)) == int(holdout_entry.get("ratio_bp", -2)),
    )
    _check(
        "measured runs recorded",
        all(len(entry.get("runs", [])) == int(summary.get("measured_runs", -1)) for entry in fixtures),
    )
    _check("protocol documented", bool(str(summary.get("protocol", "")).strip()))

    trace = str(summary.get("corpus_digest", ""))[:16] or _trace_id(summary)
    _event("MTP-001", trace, f"Live velocity metrics recomputed (ratio_bp={recomputed_ratio}).")
    if ratio_ok and threshold_ok:
        _event("MTP-002", trace, "Velocity threshold met (>= 3x).")
    else:
        _event("MTP-003", trace, "Velocity threshold breached or mispinned (< 3x).")
    if signature_ok and frozen_ok and holdout_ok:
        _event("MTP-004", trace, "Signature, frozen-input, and holdout contracts verified.")
    else:
        _event("MTP-004", trace, "Signature/frozen-input/holdout contract violation detected.")

    computed = {
        "overall_velocity_ratio": recomputed_ratio / 10_000.0,
        "required_velocity_ratio": required / 10_000.0,
        "ratio_bp": recomputed_ratio,
        "required_ratio_bp": required,
    }
    return _verdict("PASS" if all(c["pass"] for c in CHECKS) else "FAIL", "", "", computed=computed)


def _check_frozen_inputs(fixtures: list) -> tuple[bool, str]:
    mismatches: list[str] = []
    for entry in fixtures:
        for item in entry.get("input_files", []):
            path = ROOT / str(item.get("path", ""))
            expected = str(item.get("sha256", ""))
            if not path.is_file():
                mismatches.append(f"missing:{item.get('path')}")
                continue
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                mismatches.append(f"drift:{item.get('path')}")
    return (not mismatches, "ok" if not mismatches else "; ".join(mismatches[:5]))


def _verdict(
    verdict: str,
    event_code: str,
    message: str,
    computed: dict | None = None,
) -> dict:
    if event_code:
        _event(event_code, "gate", message)
    total = len(CHECKS)
    passed = sum(1 for check in CHECKS if check["pass"])
    result = {
        "bead_id": "bd-reality-20260820-w0fc6.2",
        "title": "Live migration velocity gate (>= 3x, signed, census-recomputed)",
        "verdict": verdict,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "checks": CHECKS,
        "events": EVENTS,
    }
    if computed is not None:
        result["computed"] = computed
    return result


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def self_test() -> bool:
    """Build a synthetic signed delta+census in memory and verify both the
    PASS path and two tamper paths using this gate's own primitives."""
    import tempfile

    private, public_hex = _harness_keys()

    def make_pair(ratio_tool: int, ratio_baseline: int) -> tuple[dict, dict]:
        runs = [
            {
                "run_index": index,
                "tool_ms": ratio_tool + index,
                "tool_commands_ms": [ratio_tool, ratio_tool, ratio_tool],
                "tool_exit_codes": [0, 0, 0],
                "baseline_ms": ratio_baseline + index,
                "baseline_commands_ms": [ratio_baseline, ratio_baseline, ratio_baseline],
                "baseline_exit_codes": [0, 0, 0],
            }
            for index in range(5)
        ]
        tool_median = _median_int([run["tool_ms"] for run in runs])
        baseline_median = _median_int([run["baseline_ms"] for run in runs])
        entry = {
            "fixture_id": "self-test-fixture",
            "role": "cohort",
            "source_path_rel": "unused",
            "input_files": [],
            "expected_validate": "pass",
            "runs": runs,
            "tool_median_ms": tool_median,
            "baseline_median_ms": baseline_median,
            "ratio_bp": _ratio_bp(baseline_median, tool_median),
        }
        holdout = dict(entry)
        holdout["fixture_id"] = "self-test-holdout"
        holdout["role"] = "holdout"
        fixtures = [entry, holdout]
        pairs = [(run["tool_ms"], run["baseline_ms"]) for fixture in fixtures for run in fixture["runs"]]
        pooled_tool = _median_int([pair[0] for pair in pairs])
        pooled_baseline = _median_int([pair[1] for pair in pairs])
        unsigned = {
            "schema_version": MIGTP_SCHEMA,
            "generated_at": "1970-01-01T00:00:00Z",
            "protocol": "self-test",
            "required_velocity_ratio_bp": REQUIRED_VELOCITY_RATIO_BP,
            "velocity_ratio_bp": _ratio_bp(pooled_baseline, pooled_tool),
            "median_baseline_ms": pooled_baseline,
            "median_tool_ms": pooled_tool,
            "bootstrap_ci95": _bootstrap_ci_bp(pairs, 2000, 42),
            "holdout_ratio_bp": holdout["ratio_bp"],
            "fixture_ids_cohort": ["self-test-fixture"],
            "fixture_ids_holdout": ["self-test-holdout"],
            "warmup_runs": 1,
            "measured_runs": 5,
            "corpus_digest": _corpus_digest(
                [
                    (fixture["fixture_id"], _sha256_prefixed(MIGTP_EVIDENCE_DOMAIN, _canonical_bytes(fixture)))
                    for fixture in fixtures
                ]
            ),
        }
        message = _signature_message(_canonical_bytes(unsigned))
        unsigned["signature"] = {
            "algorithm": MIGTP_SIGNATURE_ALGORITHM,
            "signer_key_id": MIGTP_HARNESS_KEY_ID,
            "signer_public_key_hex": public_hex,
            "signature_hex": private.sign(message).hex(),
        }
        evidence = {
            "schema_version": MIGTP_EVIDENCE_SCHEMA,
            "generated_at": "1970-01-01T00:00:00Z",
            "protocol": "self-test",
            "fixtures": fixtures,
        }
        return unsigned, evidence

    with tempfile.TemporaryDirectory(prefix="migtp-gate-self-test-") as tmp:
        root = Path(tmp)
        summary_path = root / "delta.json"
        evidence_path = root / "evidence.json"

        # PASS path: 3.5x synthetic measurement.
        summary, evidence = make_pair(ratio_tool=100, ratio_baseline=350)
        summary_path.write_text(json.dumps(summary))
        evidence_path.write_text(json.dumps(evidence))
        if run_checks(summary_path, evidence_path)["verdict"] != "PASS":
            return False

        # Tamper 1: below-threshold measurement must FAIL.
        summary, evidence = make_pair(ratio_tool=100, ratio_baseline=250)
        summary_path.write_text(json.dumps(summary))
        evidence_path.write_text(json.dumps(evidence))
        if run_checks(summary_path, evidence_path)["verdict"] != "FAIL":
            return False

        # Tamper 2: flipped signed value must FAIL the signature check.
        summary, evidence = make_pair(ratio_tool=100, ratio_baseline=350)
        summary["velocity_ratio_bp"] = summary["velocity_ratio_bp"] + 1
        summary_path.write_text(json.dumps(summary))
        evidence_path.write_text(json.dumps(evidence))
        result = run_checks(summary_path, evidence_path)
        if result["verdict"] != "FAIL":
            return False
        signature_check = next(
            (check for check in result["checks"] if "signature" in check["check"]), None
        )
        if signature_check is None or signature_check["pass"]:
            return False

        # Tamper 3: float in the signed payload must FAIL.
        summary, evidence = make_pair(ratio_tool=100, ratio_baseline=350)
        summary["velocity_ratio_bp"] = 3.5
        summary_path.write_text(json.dumps(summary))
        evidence_path.write_text(json.dumps(evidence))
        if run_checks(summary_path, evidence_path)["verdict"] != "FAIL":
            return False

        # Tamper 4: constructed cohort ID must FAIL.
        summary, evidence = make_pair(ratio_tool=100, ratio_baseline=350)
        summary["fixture_ids_cohort"] = ["cohort-express-001"]
        summary["fixture_ids_holdout"] = ["self-test-holdout"]
        summary["corpus_digest"] = summary["corpus_digest"]
        evidence["fixtures"][0]["fixture_id"] = "cohort-express-001"
        summary_path.write_text(json.dumps(summary))
        evidence_path.write_text(json.dumps(evidence))
        if run_checks(summary_path, evidence_path)["verdict"] != "FAIL":
            return False

    return True


def main() -> int:
    configure_test_logging("check_migration_velocity_gate")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-test and exit.")
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
        print(f"[{result['verdict']}] {result['title']}")
        print(f"passed={result['passed']} failed={result['failed']} total={result['total']}")
        for check in result["checks"]:
            status = "PASS" if check["pass"] else "FAIL"
            print(f"- {status}: {check['check']} ({check['detail']})")

    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
