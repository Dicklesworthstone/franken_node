"""Unit tests for scripts/check_compromise_reduction_gate.py."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone, timedelta
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


def _signed_current_fixture():
    """Synthetic wire/math conformance only; no experiment was executed.

    The ephemeral key is confined to this test process, never distributed or
    proposed as production measurement authority. Encoding is independent of
    the consumer's private canonicalizer/signature helpers.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    anchor = private.public_key().public_bytes_raw().hex()
    classes = ["rce_dependency", "prototype_pollution", "path_traversal", "ssrf", "deserialization",
               "supply_chain_injection", "privilege_escalation", "sandbox_escape", "memory_corruption",
               "command_injection"]
    digest = lambda text: "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    context = {
        "source_revisions": {name: hashlib.sha1(name.encode()).hexdigest() for name in
                             ["franken_node", "franken_engine", "fastapi_rust", "frankentui", "sqlmodel_rust"]},
        "binary_sha256": {name: digest(name) for name in ["node", "bun", "native"]},
        "runtime_versions": {"node": "v26.0.0", "bun": "1.3.8", "native": "0.2.0"},
        "corpus_sha256": "", "policy_sha256": digest("synthetic-policy"), "policy_profile": "strict",
    }
    context["source_selection"] = context["source_revisions"]["franken_node"] + "-overlay-" + hashlib.sha256(b"synthetic-source-selection").hexdigest()
    cases = []
    for i in range(20):
        name = f"synthetic-case-{i:02d}"
        records = {}
        for runtime in ["node", "bun", "native"]:
            records[runtime] = {
                "available": True, "binary_sha256": context["binary_sha256"][runtime],
                "input_sha256": digest(name + runtime), "stdout": "FN_CONTROL:" + name + "\n",
                "stderr": "", "exit_code": 0, "timed_out": False,
                "control_executed": True, "compromised": runtime != "native",
            }
        native = records["native"]
        native.update(outcome="capability_denied", evidence="synthetic capability refusal",
                      security_control="capability_gate", contained=True, exit_code=1)
        if i >= 3:
            native.update(outcome="blocked_at_lowering", security_control="ambient_authority_denied",
                          contained=False, control_executed=False, stdout="")
        cases.append({"case_id": name, "attack_class": classes[i % 10],
                      "template_sha256": digest(name), "observations": records})
    inventory = [{k: case[k] for k in ["case_id", "attack_class", "template_sha256"]} for case in cases]
    wire = json.dumps(inventory, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    context["corpus_sha256"] = "sha256:" + hashlib.sha256(b"franken-node:compromise-campaign-corpus:v3:" + wire).hexdigest()
    artifact = {
        "schema_version": "franken-node/compromise-campaign/v3", "campaign_id": "synthetic-conformance-only",
        "generated_at_utc": "2026-10-24T00:00:00Z", "context": copy.deepcopy(context), "cases": cases,
        "summary": {"baseline_attempts": 20, "franken_attempts": 20, "baseline_compromised": 20,
                    "franken_compromised": 0, "executed_containment": 3, "prevented_before_control": 17,
                    "ratio_numerator": 20, "ratio_denominator": 1, "minimum_required_ratio": 10},
    }
    return artifact, context, private, anchor


def _sign_current_test(artifact, private):
    unsigned = {k: v for k, v in artifact.items() if k != "signature"}
    wire = json.dumps(unsigned, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    artifact["signature"] = {
        "algorithm": "ed25519", "public_key_hex": private.public_key().public_bytes_raw().hex(),
        "statement_sha256": "sha256:" + hashlib.sha256(wire).hexdigest(),
        "signature_hex": private.sign(b"franken-node:compromise-campaign-signature:v3:" + len(wire).to_bytes(8, "little") + wire).hex(),
    }


class TestCurrentCampaignStatement(TestCase):
    def setUp(self):
        self.artifact, self.context, self.private, self.anchor = _signed_current_fixture()
        self.now = datetime(2026, 10, 24, 0, 1, tzinfo=timezone.utc)
        _sign_current_test(self.artifact, self.private)

    def verify(self, artifact=None, context=None, anchor=None, **kwargs):
        return mod.verify_current_campaign(artifact if artifact is not None else self.artifact,
            anchor if anchor is not None else self.anchor,
            context if context is not None else self.context, now=self.now, **kwargs)

    def test_positive_synthetic_statement_proves_verifier_contract_only(self):
        result = self.verify()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["evidence_class"], "authenticated_campaign_statement")
        self.assertIs(result["independently_reproduced"], False)
        self.assertEqual(result["computed"]["executed_containment"], 3)
        self.assertEqual(result["uncertainty"]["baseline_compromise_rate_bp"], [8389, 10000])
        self.assertEqual(result["uncertainty"]["native_compromise_rate_bp"], [0, 1611])
        self.assertIs(result["uncertainty"]["zero_observations_prove_zero_population_risk"], False)

    def test_signed_prevention_only_is_not_executed_containment(self):
        for case in self.artifact["cases"][:3]:
            case["observations"]["native"].update(outcome="blocked_at_lowering",
                security_control="ambient_authority_denied", contained=False, control_executed=False, stdout="")
        self.artifact["summary"].update(executed_containment=0, prevented_before_control=20)
        _sign_current_test(self.artifact, self.private)
        self.assertIn("CURRENT_EXECUTED_CONTAINMENT_BELOW_THREE", self.verify()["errors"])

    def test_signature_anchor_statement_and_context_mutations_fail(self):
        variants = []
        missing = copy.deepcopy(self.artifact); missing.pop("signature")
        variants.append((missing, "CURRENT_SCHEMA_INVALID"))
        invalid = copy.deepcopy(self.artifact); invalid["signature"]["signature_hex"] = "00" * 64
        variants.append((invalid, "CURRENT_SIGNATURE_INVALID"))
        changed = copy.deepcopy(self.artifact); changed["campaign_id"] = "changed"
        variants.append((changed, "CURRENT_STATEMENT_INVALID"))
        context = copy.deepcopy(self.artifact); context["context"]["binary_sha256"]["native"] = "sha256:" + "0" * 64
        _sign_current_test(context, self.private)
        variants.append((context, "CURRENT_CONTEXT_MISMATCH"))
        for artifact, error in variants:
            with self.subTest(error=error):
                self.assertIn(error, self.verify(artifact)["errors"])
        self.assertIn("CURRENT_SIGNATURE_INVALID", self.verify(anchor="1" * 64)["errors"])
        self.assertIn("CURRENT_MEASUREMENT_ANCHOR_REQUIRED", self.verify(anchor=mod.HISTORICAL_FIXTURE_KEY)["errors"])

    def test_expired_future_and_invalid_age_fail(self):
        for stamp in ["2026-10-22T00:00:00Z", "2026-10-24T00:02:00Z", "2026-10-24T00:00:00"]:
            changed = copy.deepcopy(self.artifact); changed["generated_at_utc"] = stamp
            _sign_current_test(changed, self.private)
            self.assertIn("CURRENT_CAMPAIGN_NOT_FRESH", self.verify(changed)["errors"])
        for age in [0, True, 86401, 10**1000]:
            self.assertIn("CURRENT_CAMPAIGN_NOT_FRESH", self.verify(max_age_seconds=age)["errors"])

    def test_signed_skips_harness_failures_and_false_controls_do_not_score(self):
        for runtime, field, value, error in [
            ("node", "available", False, "CURRENT_OBSERVATION_INVALID"),
            ("bun", "timed_out", True, "CURRENT_OBSERVATION_INVALID"),
            ("node", "compromised", False, "CURRENT_RAW_CONTROL_NOT_COMPROMISED"),
            ("native", "outcome", "invalid", "CURRENT_NATIVE_CLASSIFICATION_INVALID"),
            ("native", "outcome", "unsupported", "CURRENT_NATIVE_CLASSIFICATION_INVALID"),
            ("native", "stdout", "a source string FN_CONTROL:synthetic-case-00", "CURRENT_OBSERVATION_INVALID"),
        ]:
            changed = copy.deepcopy(self.artifact)
            changed["cases"][0]["observations"][runtime][field] = value
            _sign_current_test(changed, self.private)
            with self.subTest(runtime=runtime, field=field, value=value):
                self.assertIn(error, self.verify(changed)["errors"])

    def test_signed_missing_duplicate_or_changed_cases_fail(self):
        shorter = copy.deepcopy(self.artifact); shorter["cases"].pop()
        duplicate = copy.deepcopy(self.artifact); duplicate["cases"][-1] = copy.deepcopy(duplicate["cases"][0])
        unpaired = copy.deepcopy(self.artifact); unpaired["cases"][0]["observations"].pop("bun")
        altered = copy.deepcopy(self.artifact); altered["cases"][0]["template_sha256"] = "sha256:" + "a" * 64
        for changed, error in [(shorter, "CURRENT_CENSUS_SIZE_INVALID"), (duplicate, "CURRENT_CASE_INVALID"),
                               (unpaired, "CURRENT_ATTEMPTS_NOT_PAIRED"), (altered, "CURRENT_CORPUS_MISMATCH")]:
            _sign_current_test(changed, self.private)
            with self.subTest(error=error):
                self.assertIn(error, self.verify(changed)["errors"])

    def test_signed_declared_summary_cannot_override_census_or_integer_types(self):
        for field, value in [("franken_compromised", 2), ("ratio_denominator", True), ("minimum_required_ratio", 1)]:
            changed = copy.deepcopy(self.artifact); changed["summary"][field] = value
            _sign_current_test(changed, self.private)
            self.assertIn("CURRENT_SUMMARY_MISMATCH", self.verify(changed)["errors"])

    def test_case_order_does_not_change_counts_or_frozen_corpus(self):
        self.artifact["cases"].reverse()
        _sign_current_test(self.artifact, self.private)
        self.assertEqual(self.verify()["errors"], [])

    def test_signed_real_losses_are_counted_at_the_ten_x_boundary(self):
        for losses in [1, 2, 3]:
            changed = copy.deepcopy(self.artifact)
            for case in changed["cases"][3:3 + losses]:
                case["observations"]["native"].update(outcome="compromised", compromised=True,
                    contained=False, control_executed=True, stdout="FN_CONTROL:" + case["case_id"] + "\n",
                    exit_code=0, security_control="none", evidence="synthetic host-compromise oracle fired")
            changed["summary"].update(franken_compromised=losses, ratio_denominator=losses,
                                      prevented_before_control=17 - losses)
            _sign_current_test(changed, self.private)
            result = self.verify(changed)
            self.assertEqual(result["computed"]["franken_compromised"], losses)
            self.assertEqual(result["verdict"], "PASS" if losses <= 2 else "FAIL")
            self.assertEqual("CURRENT_REDUCTION_BELOW_TEN" in result["errors"], losses > 2)

    def test_malformed_signed_field_types_fail_without_an_untyped_exception(self):
        for field, value in [("attack_class", []), ("case_id", {}), ("template_sha256", True)]:
            changed = copy.deepcopy(self.artifact); changed["cases"][0][field] = value
            _sign_current_test(changed, self.private)
            self.assertIn("CURRENT_CASE_INVALID", self.verify(changed)["errors"])
        changed = copy.deepcopy(self.artifact); changed["cases"][0]["observations"]["native"]["outcome"] = []
        _sign_current_test(changed, self.private)
        self.assertIn("CURRENT_NATIVE_CLASSIFICATION_INVALID", self.verify(changed)["errors"])

    def test_raw_termination_after_fired_control_and_compromise_keeps_the_loss(self):
        for runtime in ["node", "bun"]:
            self.artifact["cases"][0]["observations"][runtime].update(timed_out=True, exit_code=None)
        _sign_current_test(self.artifact, self.private)
        self.assertEqual(self.verify()["errors"], [])
        self.assertEqual(self.verify()["computed"]["baseline_compromised"], 20)
        for runtime in ["node", "bun", "native"]:
            changed = copy.deepcopy(self.artifact)
            changed["cases"][0]["observations"][runtime].update(timed_out=True, exit_code=None, compromised=False)
            _sign_current_test(changed, self.private)
            self.assertEqual(self.verify(changed)["verdict"], "FAIL")

    def test_cli_default_refuses_to_promote_retained_conformance(self):
        output = subprocess.run([sys.executable, str(ROOT / "scripts/check_compromise_reduction_gate.py"),
                                 "--json"], capture_output=True, check=False)
        self.assertEqual(output.returncode, 1, output.stderr)
        result = json.loads(output.stdout)
        self.assertEqual(result["errors"], ["CURRENT_MEASUREMENT_INPUTS_REQUIRED"])
        self.assertIs(result["release_qualified"], False)
        legacy = subprocess.run([sys.executable, str(ROOT / "scripts/check_compromise_reduction_gate.py"),
                                 "--historical-conformance", "--json"], capture_output=True, check=False)
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        self.assertIs(json.loads(legacy.stdout)["release_qualified"], False)

    def test_cli_executes_current_statement_verification_with_separate_pins(self):
        root = Path(mkdtemp(prefix="bd-3cpa-current-cli-conformance-"))
        self.artifact["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
        _sign_current_test(self.artifact, self.private)
        campaign = root / "synthetic-statement.json"
        pins = root / "independent-test-pins.json"
        campaign.write_text(json.dumps(self.artifact))
        pins.write_text(json.dumps(self.context))
        argv = [sys.executable, str(ROOT / "scripts/check_compromise_reduction_gate.py"), "--json",
                "--campaign", str(campaign), "--expected-context", str(pins),
                "--trusted-measurement-key-hex", self.anchor]
        output = subprocess.run(argv, capture_output=True, check=False)
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertEqual(json.loads(output.stdout)["verdict"], "PASS")
        self.assertIs(json.loads(output.stdout)["independently_reproduced"], False)
        self.artifact["summary"]["franken_compromised"] = 2
        campaign.write_text(json.dumps(self.artifact))
        rejected = subprocess.run(argv, capture_output=True, check=False)
        self.assertEqual(rejected.returncode, 1, rejected.stderr)
        self.assertIs(json.loads(rejected.stdout)["release_qualified"], False)


if __name__ == "__main__":
    main()
