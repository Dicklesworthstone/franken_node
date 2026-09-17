"""Unit tests for scripts/check_compatibility_corpus_pass_gate.py."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_compatibility_corpus_pass_gate as mod  # noqa: E402


def successful_observation(elapsed_ms: int = 1) -> dict:
    empty_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    return {
        "stdout_digest": empty_digest,
        "stderr_digest": empty_digest,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "exit_code": 0,
        "termination_kind": "exited",
        "timed_out": False,
        "elapsed_ms": elapsed_ms,
    }


def refresh_runtime_observations_digest(report: dict) -> None:
    report["corpus"]["runtime_observations_digest"] = (
        mod.compute_runtime_observations_digest(report)
    )


def passing_report(total: int = 1000) -> dict:
    families = sorted(mod.REQUIRED_FAMILIES)
    bands = sorted(mod.REQUIRED_BANDS)
    risk_bands = sorted(mod.REQUIRED_RISK_BANDS)
    per_test_results = [
        {
            "test_id": f"synthetic::{index:04d}",
            "api_family": families[index % len(families)],
            "band": bands[index % len(bands)],
            "risk_band": risk_bands[index % len(risk_bands)],
            "status": "pass",
            "runtime_observations": {
                "bun": successful_observation(index + 1),
                "franken-engine-native": successful_observation(index + 2),
            },
        }
        for index in range(total)
    ]
    report = {
        "corpus": {
            "provenance": mod.ONLINE_PROVENANCE,
            "result_digest": mod.compute_result_digest(per_test_results),
            "runtime_observations_schema_version": (
                mod.RUNTIME_OBSERVATIONS_SCHEMA_VERSION
            ),
            "lockstep_topology": "dyad",
            "reference_runtimes": [
                {
                    "runtime_id": "bun",
                    "runtime_name": "bun",
                    "version": "1.3.14-test",
                    "is_reference": True,
                }
            ],
            "product_runtime": {
                "runtime_id": "franken-engine-native",
                "runtime_name": "franken-engine-native",
                "version": "0.1.0-test",
                "is_reference": False,
            },
        },
        "totals": {
            "total_test_cases": total,
            "passed_test_cases": total,
            "failed_test_cases": 0,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 100.0,
        },
        "per_test_results": per_test_results,
        "api_families": [{"family": family} for family in families],
        "bands": [{"band": band} for band in bands],
        "thresholds": {
            "overall_pass_rate_min_pct": 95.0,
            "per_family_pass_rate_min_pct": 80.0,
            "band_pass_rate_min_pct": {
                "core": 99.0,
                "high-value": 95.0,
                "edge": 90.0,
            },
        },
        "previous_release": {"overall_pass_rate_pct": 99.0},
        "ci_gate": {
            "threshold_met": True,
            "release_blocked": False,
            "regression_detected": False,
        },
        "failing_tests_tracking": [],
        "event_codes": list(mod.REQUIRED_EVENT_CODES),
        "reproducibility": {
            "deterministic_seed": "synthetic-release-gate",
            "same_inputs_same_digest": True,
            "external_repro_command": "synthetic fixture",
        },
    }
    refresh_runtime_observations_digest(report)
    return report


def write_report(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report), encoding="utf-8")


def named_check(result: dict, name: str) -> dict:
    return next(check for check in result["checks"] if check["check"] == name)


class TestSuccessfulRuntimeAdmission(unittest.TestCase):
    """Synthetic rule tests plus genuine failed Node process observations."""

    def observations(self, triad=False, exit_code=0):
        result = {"bun": successful_observation(1), "franken-engine-native": successful_observation(2)}
        if triad:
            result["node"] = successful_observation(3)
        for observation in result.values():
            observation["exit_code"] = exit_code
            observation["termination_kind"] = "exited" if exit_code is not None else "signal_or_unknown"
        return result

    def document(self, observations, status="pass"):
        rows = [{"test_id": "synthetic::0000", "api_family": "buffer", "band": "core",
                 "risk_band": "critical", "status": status, "runtime_observations": observations}]
        references = [{"runtime_id": "bun", "version": "1.3.14-test"}]
        if "node" in observations:
            references.append({"runtime_id": "node", "version": "v22.14.0-test"})
        return {"corpus": {"result_digest": mod.compute_result_digest(rows),
            "runtime_observations_schema_version": mod.RUNTIME_OBSERVATIONS_SCHEMA_VERSION,
            "lockstep_topology": "triad" if "node" in observations else "dyad",
            "reference_runtimes": references,
            "product_runtime": {"runtime_id": "franken-engine-native", "version": "0.1.0-test"}},
            "per_test_results": rows}

    def test_successful_dyad_and_triad_still_pass(self):
        for triad in (False, True):
            observed = self.observations(triad)
            mod._assert_passing_lockstep_observations("success", observed)
            self.assertTrue(mod.compute_runtime_observations_digest(self.document(observed)).startswith("sha256:"))

    def test_successful_digest_keeps_the_existing_cross_language_pin(self):
        self.assertEqual(mod.compute_runtime_observations_digest(self.document(self.observations())),
            "sha256:1ab42659e6407b492f5f57af96cf5fece52a61573d47e39c18c668c182ffe47e")

    def test_matching_nonzero_exits_cannot_be_declared_pass(self):
        for triad in (False, True):
            for code in (-2147483648, -1, 1, 7, 137, 2147483647):
                with self.subTest(triad=triad, code=code), self.assertRaises(ValueError):
                    mod.compute_runtime_observations_digest(self.document(self.observations(triad, code)))

    def test_matching_signal_exits_cannot_be_declared_pass(self):
        for triad in (False, True):
            with self.assertRaises(ValueError):
                mod.compute_runtime_observations_digest(self.document(self.observations(triad, None)))

    def test_matching_failures_are_still_valid_failure_evidence(self):
        for triad in (False, True):
            for code in (-1, 1, 7, None):
                report = self.document(self.observations(triad, code), "fail")
                self.assertTrue(mod.compute_runtime_observations_digest(report).startswith("sha256:"))
                self.assertEqual(report["per_test_results"][0]["status"], "fail")

    def test_reference_and_product_must_both_be_present(self):
        for triad in (False, True):
            for missing in ("bun", "franken-engine-native"):
                observations = self.observations(triad)
                del observations[missing]
                with self.assertRaises(ValueError):
                    mod._assert_passing_lockstep_observations("missing", observations)

    def test_unknown_or_nonobject_runtime_evidence_is_not_ignored(self):
        for identity, value in (("unknown", successful_observation()), ("node", None), ("node", []), ("bun", None)):
            observations = self.observations()
            observations[identity] = value
            with self.assertRaises(ValueError):
                mod._assert_passing_lockstep_observations("invalid", observations)

    def test_boolean_zero_is_not_a_successful_exit_code(self):
        for triad in (False, True):
            with self.assertRaises(ValueError):
                mod._assert_passing_lockstep_observations("boolean", self.observations(triad, False))

    def test_normal_termination_is_required_even_with_zero_exit(self):
        for termination in ("signal_or_unknown", "timed_out", "unknown", "", None):
            observations = self.observations()
            for observation in observations.values():
                observation["termination_kind"] = termination
            with self.assertRaises(ValueError):
                mod._assert_passing_lockstep_observations("termination", observations)

    def test_helper_requires_complete_evidence_without_the_outer_validator(self):
        for field in ("timed_out", "stdout_truncated", "stderr_truncated"):
            for value in (True, None, 0):
                observations = self.observations(True)
                for observation in observations.values():
                    observation[field] = value
                with self.assertRaises(ValueError):
                    mod._assert_passing_lockstep_observations("incomplete", observations)

    def test_bun_timeout_cannot_be_hidden_by_successful_node_product_pair(self):
        observations = self.observations(True)
        observations["bun"].update(timed_out=True, termination_kind="timed_out", exit_code=None)
        with self.assertRaises(ValueError):
            mod._assert_passing_lockstep_observations("bun-incomplete", observations)

    def test_complete_bun_failure_does_not_override_successful_node(self):
        observations = self.observations(True)
        observations["bun"]["exit_code"] = 7
        observations["bun"]["stdout_digest"] = "sha256:" + "b" * 64
        mod._assert_passing_lockstep_observations("node-canonical", observations)
        self.assertTrue(mod.compute_runtime_observations_digest(self.document(observations)).startswith("sha256:"))

    def test_matching_only_bun_is_not_node_canonical_success(self):
        observations = self.observations(True)
        observations["node"]["stdout_digest"] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "unless franken matches the node reference"):
            mod.compute_runtime_observations_digest(self.document(observations))

    def test_byte_counts_remain_part_of_equivalence(self):
        observations = self.observations()
        observations["bun"]["stdout_bytes"] = 1
        with self.assertRaises(ValueError):
            mod.compute_runtime_observations_digest(self.document(observations))

    def test_elapsed_time_is_not_semantic_equality_but_is_digest_bound(self):
        observations = self.observations()
        before = mod.compute_runtime_observations_digest(self.document(observations))
        observations["bun"]["elapsed_ms"] += 1000
        mod._assert_passing_lockstep_observations("timing", observations)
        self.assertNotEqual(before, mod.compute_runtime_observations_digest(self.document(observations)))

    def test_real_node_failure_cannot_be_laundered_into_a_dyad_pass(self):
        observations = {}
        for runtime_id in ("bun", "franken-engine-native"):
            completed = subprocess.run(["node", "-e", "process.stdout.write('same'); process.exit(7);"],
                capture_output=True, check=False, timeout=10)
            self.assertEqual(completed.returncode, 7)
            observation = successful_observation()
            observation.update(exit_code=completed.returncode,
                stdout_digest="sha256:" + hashlib.sha256(completed.stdout).hexdigest(), stdout_bytes=len(completed.stdout),
                stderr_digest="sha256:" + hashlib.sha256(completed.stderr).hexdigest(), stderr_bytes=len(completed.stderr))
            observations[runtime_id] = observation
        with self.assertRaises(ValueError):
            mod.compute_runtime_observations_digest(self.document(observations))
        self.assertTrue(mod.compute_runtime_observations_digest(self.document(observations, "fail")).startswith("sha256:"))


class TestSummaryReportBinding(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.report_path = self.root / "report.json"
        self.report = passing_report()
        write_report(self.report_path, self.report)
        self.summary_path = self.root / "summary.json"

    def summary(self, **metric_overrides):
        metric = {"observed_pct": 100.0, "details_ref": str(self.report_path)}
        metric.update(metric_overrides)
        write_report(self.summary_path, {"verdict": "GREEN", "timestamp": "2026-09-17T00:00:00Z", "metric": metric})

    def test_custom_report_does_not_assert_the_unrelated_canonical_summary(self):
        result = mod.run_checks(self.report_path, 1000)
        self.assertTrue(result["overall_pass"], result["checks"])
        self.assertIsNone(result["summary_path"])
        self.assertIn("no charter summary asserted", named_check(result, "summary: report scope")["detail"])

    def test_explicit_bound_summary_is_verified(self):
        self.summary()
        result = mod.run_checks(self.report_path, 1000, self.summary_path)
        self.assertTrue(result["overall_pass"], result["checks"])
        self.assertTrue(named_check(result, "summary: bound to selected report")["pass"])

    def test_equal_metrics_do_not_replace_a_report_binding(self):
        self.summary(details_ref=str(self.root / "different.json"))
        result = mod.run_checks(self.report_path, 1000, self.summary_path)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "summary: bound to selected report")["pass"])

    def test_explicit_summary_missing_or_invalid_never_passes(self):
        self.assertFalse(mod.run_checks(self.report_path, 1000, self.summary_path)["overall_pass"])
        for value in ([], None, "not an object"):
            write_report(self.summary_path, value)
            result = mod.run_checks(self.report_path, 1000, self.summary_path)
            self.assertFalse(result["overall_pass"])
            self.assertFalse(named_check(result, "summary: valid json")["pass"])

    def test_bound_but_wrong_summary_metric_still_fails(self):
        self.summary(observed_pct=99.0)
        result = mod.run_checks(self.report_path, 1000, self.summary_path)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "summary: consistent with measured results")["pass"])

    def test_canonical_report_alias_cannot_bypass_the_canonical_summary(self):
        alias = self.root / "canonical-alias.json"
        alias.symlink_to(mod.REPORT)
        self.summary(details_ref=str(mod.REPORT))
        checks = mod.check_summary(alias, self.report, None, self.summary_path)
        self.assertFalse(all(check["pass"] for check in checks))
        self.assertTrue(any(str(mod.SUMMARY) in check["detail"] for check in checks))
        self.assertFalse(any(check["check"] == "summary: report scope" for check in checks))

    def test_cli_explicit_summary_checks_the_same_bound_pair(self):
        self.summary()
        command = [sys.executable, str(ROOT / "scripts/check_compatibility_corpus_pass_gate.py"),
                   "--report", str(self.report_path), "--summary", str(self.summary_path), "--json"]
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary_path"], str(self.summary_path))
        self.summary(details_ref="wrong-report.json")
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads(result.stdout)["overall_pass"])


class TestConstants(unittest.TestCase):
    def test_bead_section_and_default_contract_size(self):
        self.assertEqual(mod.BEAD_ID, "bd-28sz")
        self.assertEqual(mod.SECTION, "13")
        self.assertEqual(mod.DEFAULT_MIN_CASES, 500)

    def test_required_event_codes(self):
        self.assertEqual(len(mod.REQUIRED_EVENT_CODES), 4)

    def test_required_families(self):
        self.assertEqual(len(mod.REQUIRED_FAMILIES), 16)

    def test_required_risk_bands(self):
        self.assertEqual(mod.REQUIRED_RISK_BANDS, {"critical", "high", "medium", "low"})


class TestFileAndContractChecks(unittest.TestCase):
    def test_checked_in_contract_and_report_exist(self):
        self.assertTrue(mod.check_file(mod.CONTRACT, "contract")["pass"])
        self.assertTrue(mod.check_file(mod.REPORT, "report")["pass"])

    def test_contract_passes(self):
        for check in mod.check_contract():
            self.assertTrue(check["pass"], f"Failed: {check['check']} -> {check['detail']}")


class TestHelpers(unittest.TestCase):
    def test_pass_rate(self):
        self.assertEqual(mod.pass_rate(95, 100), 95.0)
        self.assertEqual(mod.pass_rate(0, 0), 0.0)

    def test_aggregate_by_key(self):
        rows = [
            {"api_family": "fs", "status": "pass"},
            {"api_family": "fs", "status": "fail"},
            {"api_family": "http", "status": "pass"},
        ]
        aggregate = mod.aggregate_by_key(rows, "api_family")
        self.assertEqual(aggregate["fs"]["total"], 2)
        self.assertEqual(aggregate["fs"]["passed"], 1)
        self.assertEqual(aggregate["http"]["total"], 1)

    def test_runtime_observation_digest_cross_language_pin(self):
        report = passing_report(1)
        self.assertEqual(
            report["corpus"]["runtime_observations_digest"],
            "sha256:1ab42659e6407b492f5f57af96cf5fece52a61573d47e39c18c668c182ffe47e",
        )


class TestSyntheticReportGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.report_path = Path(self.temp_dir.name) / "compatibility-report.json"

    def run_report(self, report: dict, minimum_cases: int = 1000) -> dict:
        write_report(self.report_path, report)
        return mod.run_checks(self.report_path, minimum_cases)

    def test_complete_synthetic_report_passes_release_minimum(self):
        result = self.run_report(passing_report())
        self.assertTrue(result["overall_pass"])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["minimum_cases"], 1000)
        self.assertEqual(result["summary"]["failing"], 0)

    def test_missing_report_fails_closed(self):
        result = mod.run_checks(self.report_path, 1000)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "report: exists")["pass"])

    def test_malformed_report_fails_closed(self):
        self.report_path.write_text("{not-json", encoding="utf-8")
        result = mod.run_checks(self.report_path, 1000)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "report: valid json")["pass"])

    def test_wrong_provenance_fails_closed(self):
        report = passing_report()
        report["corpus"]["provenance"] = "authored-sample"
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(result, "provenance: corpus attests a genuine oracle run")["pass"]
        )

    def test_digest_mismatch_fails_closed(self):
        report = passing_report()
        report["corpus"]["result_digest"] = f"sha256:{'0' * 64}"
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: result_digest recomputes from per_test_results",
            )["pass"]
        )

    def test_release_minimum_rejects_999_cases(self):
        result = self.run_report(passing_report(999))
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "corpus: total test cases >= 1000")["pass"])

    def test_below_threshold_report_fails_closed(self):
        report = passing_report()
        for row in report["per_test_results"][:100]:
            row["status"] = "fail"
        report["totals"].update(
            passed_test_cases=900,
            failed_test_cases=100,
            overall_pass_rate_pct=90.0,
        )
        report["corpus"]["result_digest"] = mod.compute_result_digest(
            report["per_test_results"]
        )
        refresh_runtime_observations_digest(report)
        report["failing_tests_tracking"] = [
            {
                "test_id": row["test_id"],
                "investigation_bead_id": "bd-synthetic-failure",
                "investigation_status": "open",
            }
            for row in report["per_test_results"][:100]
        ]
        report["ci_gate"].update(threshold_met=False, release_blocked=True)
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(named_check(result, "gate: overall threshold >=95 met")["pass"])

    def test_runtime_observation_tamper_fails_closed(self):
        report = passing_report()
        report["per_test_results"][0]["runtime_observations"]["bun"][
            "elapsed_ms"
        ] += 1
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_runtime_observation_topology_gap_fails_closed(self):
        report = passing_report()
        del report["per_test_results"][0]["runtime_observations"]["bun"]
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_pass_row_with_timeout_fails_closed(self):
        report = passing_report()
        observation = report["per_test_results"][0]["runtime_observations"]["bun"]
        observation.update(
            exit_code=None,
            termination_kind="timed_out",
            timed_out=True,
        )
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_pass_row_with_divergent_runtime_digest_fails_closed(self):
        report = passing_report()
        report["per_test_results"][0]["runtime_observations"]["bun"][
            "stdout_digest"
        ] = f"sha256:{'1' * 64}"
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(
                result,
                "provenance: runtime observations are topology-bound and digest-bound",
            )["pass"]
        )

    def test_triad_pass_allows_bun_divergence_when_franken_matches_node(self):
        report = passing_report(total=1)
        bun_only = successful_observation(1)
        bun_only["stdout_digest"] = f"sha256:{'b' * 64}"
        node_match = successful_observation(2)
        report["corpus"]["lockstep_topology"] = "triad"
        report["corpus"]["reference_runtimes"].append(
            {
                "runtime_id": "node",
                "runtime_name": "node",
                "version": "v22.14.0-test",
                "is_reference": True,
            }
        )
        report["per_test_results"][0]["runtime_observations"] = {
            "bun": bun_only,
            "node": node_match,
            "franken-engine-native": successful_observation(3),
        }
        report["corpus"]["result_digest"] = mod.compute_result_digest(
            report["per_test_results"]
        )
        refresh_runtime_observations_digest(report)
        digest = mod.compute_runtime_observations_digest(report)
        self.assertTrue(digest.startswith("sha256:"))

    def test_triad_pass_refuses_when_franken_matches_only_bun(self):
        report = passing_report(total=1)
        bun_only = successful_observation(1)
        bun_only["stdout_digest"] = f"sha256:{'b' * 64}"
        report["corpus"]["lockstep_topology"] = "triad"
        report["corpus"]["reference_runtimes"].append(
            {
                "runtime_id": "node",
                "runtime_name": "node",
                "version": "v22.14.0-test",
                "is_reference": True,
            }
        )
        report["per_test_results"][0]["runtime_observations"] = {
            "bun": bun_only,
            "node": successful_observation(2),
            "franken-engine-native": copy.deepcopy(bun_only),
        }
        with self.assertRaisesRegex(
            ValueError, "unless franken matches the node reference"
        ):
            mod.compute_runtime_observations_digest(report)

    def test_over_cap_stream_without_truncation_fails_closed(self):
        report = passing_report()
        report["per_test_results"][0]["runtime_observations"]["bun"][
            "stdout_bytes"
        ] = mod.MAX_RUNTIME_OBSERVATION_STREAM_BYTES + 1
        with self.assertRaisesRegex(ValueError, "inconsistent stream truncation"):
            mod.compute_runtime_observations_digest(report)

    def test_duplicate_runtime_observation_test_id_fails_closed(self):
        report = passing_report()
        report["per_test_results"][1]["test_id"] = report["per_test_results"][0][
            "test_id"
        ]
        report["corpus"]["result_digest"] = mod.compute_result_digest(
            report["per_test_results"]
        )
        with self.assertRaisesRegex(ValueError, "duplicate runtime observation test_id"):
            mod.compute_runtime_observations_digest(report)

    def test_regression_fails_closed(self):
        report = passing_report()
        report["previous_release"]["overall_pass_rate_pct"] = 100.01
        result = self.run_report(report)
        self.assertFalse(result["overall_pass"])
        self.assertFalse(
            named_check(result, "regression: no pass-rate decrease vs previous release")["pass"]
        )

    def test_cli_accepts_explicit_report_and_minimum(self):
        write_report(self.report_path, passing_report())
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_compatibility_corpus_pass_gate.py"),
                "--report",
                str(self.report_path),
                "--min-cases",
                "1000",
                "--json",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["report_path"], str(self.report_path))
        self.assertEqual(payload["minimum_cases"], 1000)
        self.assertTrue(payload["overall_pass"])

    def test_adversarial_threshold_check_is_present(self):
        checks = mod.check_report(copy.deepcopy(passing_report()), 1000)
        item = next(
            check
            for check in checks
            if check["check"] == "adversarial: threshold drop blocks release"
        )
        self.assertTrue(item["pass"])


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok)
        self.assertGreater(len(checks), 0)


if __name__ == "__main__":
    unittest.main()
