"""Unit tests for scripts/check_compromise_reduction_gate.py."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory, mkdtemp
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_compromise_reduction_gate",
    ROOT / "scripts" / "check_compromise_reduction_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _base_spec_text() -> str:
    return "\n".join(
        [
            "# test spec",
            ">= 10x",
            "benchmark_proof",
            mod.BENCHMARK_TEST_RELATIVE_PATH,
            mod.BENCHMARK_ARTIFACT_RELATIVE_PATH,
            *sorted(mod.REQUIRED_ATTACK_CLASSES),
            *sorted(mod.REQUIRED_EVENT_CODES),
            "INV-CRG-EQUAL-ATTEMPTS",
        ]
    )


def _benchmark_proof() -> dict:
    return {
        "rust_test": mod.BENCHMARK_TEST_NAME,
        "rust_test_path": mod.BENCHMARK_TEST_RELATIVE_PATH,
        "measured_artifact": mod.BENCHMARK_ARTIFACT_RELATIVE_PATH,
        "expected_min_ratio": 10.0,
        "measured_ratio": 20.0,
        "baseline_compromised": 20,
        "franken_compromised": 0,
        "baseline_attempts": 20,
        "franken_attempts": 10,
        "raw_baseline_runtimes": mod.EXPECTED_RAW_BASELINE_RUNTIMES,
        "fail_closed_baseline_unavailable": True,
        "proof_assertions": sorted(mod.REQUIRED_BENCHMARK_ASSERTIONS),
    }


def _make_vectors(
    *,
    total: int = 20,
    drop_class: str | None = None,
    hardened_compromised: int = 2,
    contained: int = 4,
) -> list[dict]:
    classes = [attack_class for attack_class in sorted(mod.REQUIRED_ATTACK_CLASSES) if attack_class != drop_class]
    vectors = []
    for idx in range(total):
        attack_class = classes[idx % len(classes)]
        hardened_outcome = "blocked"
        containment = False

        if idx < hardened_compromised:
            hardened_outcome = "compromised"
        elif idx < hardened_compromised + contained:
            hardened_outcome = "contained"
            containment = True

        vectors.append(
            {
                "attack_id": f"A{idx + 1:02d}",
                "attack_class": attack_class,
                "attack_description": f"attack {idx}",
                "baseline_outcome": "compromised",
                "franken_node_outcome": hardened_outcome,
                "mitigation": "mitigation",
                "script_command": f"python3 scripts/check_compromise_reduction_gate.py --simulate-attack A{idx + 1:02d}",
                "containment_demonstrated": containment,
            }
        )

    return vectors


def _make_report(
    *,
    total_vectors: int = 20,
    drop_class: str | None = None,
    hardened_compromised: int = 2,
    contained: int = 4,
) -> dict:
    vectors = _make_vectors(
        total=total_vectors,
        drop_class=drop_class,
        hardened_compromised=hardened_compromised,
        contained=contained,
    )
    baseline = sum(1 for vector in vectors if vector["baseline_outcome"] == "compromised")
    hardened = sum(1 for vector in vectors if vector["franken_node_outcome"] == "compromised")
    containment = sum(1 for vector in vectors if vector["franken_node_outcome"] == "contained")
    ratio = baseline / hardened if hardened > 0 else "infinite"

    return {
        "bead_id": "bd-3cpa",
        "generated_at_utc": "2026-02-21T00:00:00Z",
        "trace_id": "test-trace",
        "campaign_name": "test-campaign",
        "campaign_version": "1",
        "reproducible_command": "python3 scripts/check_compromise_reduction_gate.py --replay-campaign --json",
        "minimum_required_ratio": 10.0,
        "baseline_compromised": baseline,
        "hardened_compromised": hardened,
        "compromise_reduction_ratio": ratio,
        "total_attack_vectors": len(vectors),
        "containment_vectors": containment,
        "benchmark_proof": _benchmark_proof(),
        "attack_vectors": vectors,
    }


class TestCompromiseReductionGate(TestCase):
    def test_run_checks_passes_repo_artifacts(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-3cpa")
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(
            any(
                check["check"] == "equal attempts (baseline vs franken)" and check["pass"]
                for check in result["checks"]
            ),
            result["checks"],
        )
        event_codes = [event["event_code"] for event in result["events"]]
        self.assertIn("CRG-002", event_codes)
        self.assertNotIn("CRG-003", event_codes)

    def test_unequal_attempts_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            report = _make_report()
            report["benchmark_proof"]["baseline_attempts"] = 19
            report["benchmark_proof"]["franken_attempts"] = 20

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "equal attempts (baseline vs franken)" and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_attack_vector_count_below_twenty_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(_make_report(total_vectors=19), indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(check["check"] == "attack vector count >= 20" and not check["pass"] for check in result["checks"]))

    def test_ratio_below_threshold_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(
                json.dumps(_make_report(hardened_compromised=3, contained=3), indent=2),
                encoding="utf-8",
            )

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "compromise reduction threshold >= 10x" and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_containment_below_three_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(_make_report(contained=2), indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any(check["check"] == "containment vectors >= 3" and not check["pass"] for check in result["checks"]))

    def test_missing_required_attack_class_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(
                json.dumps(_make_report(drop_class="memory_corruption"), indent=2),
                encoding="utf-8",
            )

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "required attack classes covered" and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_missing_benchmark_proof_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            report = _make_report()
            del report["benchmark_proof"]

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "benchmark proof directly cites measured 10x evidence"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_benchmark_proof_wrong_test_name_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            report = _make_report()
            report["benchmark_proof"]["rust_test"] = "placeholder_benchmark"

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "benchmark proof directly cites measured 10x evidence"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_benchmark_proof_ratio_mismatch_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-3cpa-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            report = _make_report()
            report["benchmark_proof"]["measured_ratio"] = 10.0

            spec_path.write_text(_base_spec_text(), encoding="utf-8")
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "benchmark proof directly cites measured 10x evidence"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_replay_campaign_reports_metrics(self) -> None:
        payload = mod.replay_campaign()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["bead_id"], "bd-3cpa")
        self.assertGreaterEqual(payload["total_attack_vectors"], 20)

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


class TestHistoricalCampaignSignature(TestCase):
    """Public-fixture crypto conformance, never fresh campaign authentication."""

    def setUp(self) -> None:
        self.artifact = json.loads((ROOT / mod.BENCHMARK_ARTIFACT_RELATIVE_PATH).read_text())

    def test_genuine_frozen_signature_verifies_under_external_fixture_pin(self) -> None:
        self.assertEqual(mod.historical_fixture_signature_errors(self.artifact), [])

    def test_missing_invalid_truncated_or_foreign_signatures_are_rejected(self) -> None:
        missing = copy.deepcopy(self.artifact)
        missing.pop("signature")
        variants = [missing]
        for field, value in [
            ("value", "ed25519:" + "00" * 64),
            ("value", "ed25519:" + "ab" * 63),
            ("public_key", "00" * 32),
            ("algorithm", "ed25519-unrecognized"),
            ("key_id", "producer-selected-authority"),
            ("payload_sha256", "sha256:" + "00" * 32),
        ]:
            variant = copy.deepcopy(self.artifact)
            variant["signature"][field] = value
            variants.append(variant)
        for variant in variants:
            with self.subTest(signature=variant.get("signature", {}).get("key_id")):
                self.assertTrue(mod.historical_fixture_signature_errors(variant))

    def test_resealed_timestamp_tamper_still_requires_the_signature(self) -> None:
        self.artifact["generated_at_utc"] = "2026-10-24T00:00:00Z"
        self.assertEqual(mod.historical_fixture_signature_errors(self.artifact),
                         ["historical fixture signed payload digest mismatch"])
        unsigned = {key: value for key, value in self.artifact.items() if key != "signature"}
        payload = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":")).encode()
        self.artifact["signature"]["payload_sha256"] = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.assertEqual(mod.historical_fixture_signature_errors(self.artifact),
                         ["historical fixture Ed25519 signature does not verify"])

    def test_historical_success_is_explicitly_not_release_qualification(self) -> None:
        result = mod.run_checks()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["evidence_class"], "historical_fixture_conformance")
        self.assertIs(result["release_qualified"], False)
        replay = mod.replay_campaign()
        self.assertEqual(replay["evidence_class"], "unverified_report_aggregation")
        self.assertIs(replay["release_qualified"], False)

    def test_duplicate_alias_utf8_nesting_and_nonfinite_inputs_are_rejected(self) -> None:
        root = Path(mkdtemp(prefix="bd-3cpa-decode-controls-"))
        for name, raw in [
            ("duplicate", b'{"signature":{},"signature":{}}'),
            ("escaped_alias", b'{"signature":{},"\\u0073ignature":{}}'),
            ("nested_duplicate", b'{"x":{"a":1,"a":2}}'),
            ("utf8", b'\xff'),
            ("depth", b'[' * 2000 + b'0' + b']' * 2000),
            ("nonfinite", b'{"value":NaN}'),
            ("overflowing_float", b'{"value":1e9999}'),
            ("bounded_depth", b'{"value":' + b'[' * 129 + b'0' + b']' * 129 + b'}'),
        ]:
            path = root / name
            path.write_bytes(raw)
            with self.subTest(name=name), self.assertRaises((ValueError, UnicodeError, RecursionError)):
                mod._read_campaign_json(path)

    def test_oversize_input_is_refused_before_json_decoding(self) -> None:
        path = Path(mkdtemp(prefix="bd-3cpa-size-control-")) / "large.json"
        with path.open("wb") as stream:
            stream.truncate(mod.MAX_CAMPAIGN_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "exceeds 64 MiB"):
            mod._read_campaign_json(path)


if __name__ == "__main__":
    main()
