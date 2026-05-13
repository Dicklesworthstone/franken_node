"""Unit tests for scripts/check_compromise_reduction_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
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


if __name__ == "__main__":
    main()
