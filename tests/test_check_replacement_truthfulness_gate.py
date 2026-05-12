"""Unit tests for scripts/check_replacement_truthfulness_gate.py."""

from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_replacement_truthfulness_gate as mod


def _witness_spec(witness_id: str) -> mod.WitnessSpec:
    return next(spec for spec in mod.WITNESS_SPECS if spec.witness_id == witness_id)


def _materialize_spec_sources(spec: mod.WitnessSpec, root: Path) -> None:
    for rel in spec.source_paths:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")


class EvaluateWitnessTests(unittest.TestCase):
    def test_banned_marker_in_code_fails(self) -> None:
        spec = mod.WitnessSpec(
            witness_id="toy",
            surface="toy",
            witness_family="toy family",
            source_paths=("src/toy.rs",),
            required_markers=("fn anchor()",),
            banned_markers=("!token.is_empty()",),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "src" / "toy.rs"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "fn anchor() { let accepted = !token.is_empty(); }\n",
                encoding="utf-8",
            )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.SURROGATE_REINTRODUCED)

    def test_banned_marker_only_in_comment_is_ignored(self) -> None:
        spec = mod.WitnessSpec(
            witness_id="toy",
            surface="toy",
            witness_family="toy family",
            source_paths=("src/toy.rs",),
            required_markers=("fn anchor()",),
            banned_markers=("!token.is_empty()",),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "src" / "toy.rs"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fn anchor() {}\n// !token.is_empty()\n", encoding="utf-8")
            result = mod.evaluate_witness(spec, root)
        self.assertTrue(result["pass"])
        self.assertEqual(result["reason_code"], mod.STATIC_PASS)

    def test_missing_anchor_fails(self) -> None:
        spec = mod.WitnessSpec(
            witness_id="toy",
            surface="toy",
            witness_family="toy family",
            source_paths=("src/toy.rs",),
            required_markers=("fn anchor()",),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "src" / "toy.rs"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fn different() {}\n", encoding="utf-8")
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.MISSING_ANCHOR)

    def test_incrate_sdk_verifier_witness_fails_on_replacement_critical_import(self) -> None:
        spec = _witness_spec("incrate_sdk_verifier_structural_only_posture")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _materialize_spec_sources(spec, root)
            target = root / "crates/franken-node/src/sdk/verifier_sdk.rs"
            target.write_text(
                target.read_text(encoding="utf-8")
                + "\nuse crate::connector::verifier_sdk::verify_verification_result_signature;\n",
                encoding="utf-8",
            )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.SURROGATE_REINTRODUCED)
        self.assertEqual(result["offending_path"], "crates/franken-node/src/sdk/verifier_sdk.rs")

    def test_incrate_sdk_replay_capsule_witness_fails_on_missing_structural_marker(self) -> None:
        spec = _witness_spec("incrate_sdk_replay_capsule_structural_only_posture")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _materialize_spec_sources(spec, root)
            target = root / "crates/franken-node/src/sdk/replay_capsule.rs"
            target.write_text(
                target.read_text(encoding="utf-8").replace(
                    'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::SDK_REPLAY_CAPSULE";',
                    'pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::BROKEN";',
                ),
                encoding="utf-8",
            )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.MISSING_ANCHOR)
        self.assertIn("SDK_REPLAY_CAPSULE", result["detail"])

    def test_incrate_sdk_replay_capsule_witness_fails_on_retired_crypto_claim(self) -> None:
        spec = _witness_spec("incrate_sdk_replay_capsule_structural_only_posture")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _materialize_spec_sources(spec, root)
            target = root / "crates/franken-node/src/sdk/replay_capsule.rs"
            target.write_text(
                target.read_text(encoding="utf-8")
                + '\npub const BAD_POSTURE: &str = "cryptographic_ed25519_authenticated";\n',
                encoding="utf-8",
            )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.SURROGATE_REINTRODUCED)
        self.assertEqual(
            result["offending_path"],
            "crates/franken-node/src/sdk/replay_capsule.rs",
        )

    def test_migration_prefix_surrogate_detection_stays_production_specific(self) -> None:
        spec = _witness_spec("migration_placeholder_prefix_shortcuts")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _materialize_spec_sources(spec, root)
            baseline = mod.evaluate_witness(spec, root)
            self.assertTrue(baseline["pass"], baseline)

            target = root / "crates/franken-node/src/connector/migration_pipeline.rs"
            target.write_text(
                target.read_text(encoding="utf-8")
                + '\nfn regression_placeholder_prefix(name: &str) -> bool { name.starts_with("blocked_") }\n',
                encoding="utf-8",
            )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.SURROGATE_REINTRODUCED)

    def test_workspace_sdk_witness_fails_on_missing_crypto_posture(self) -> None:
        spec = _witness_spec("workspace_verifier_sdk_cryptographic_bundle_posture")
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            _materialize_spec_sources(spec, root)
            for rel in ("sdk/verifier/src/lib.rs", "sdk/verifier/src/capsule.rs"):
                target = root / rel
                target.write_text(
                    target.read_text(encoding="utf-8").replace(
                        'pub const CRYPTOGRAPHIC_SECURITY_POSTURE: &str = "cryptographic_ed25519_authenticated";',
                        'pub const CRYPTOGRAPHIC_SECURITY_POSTURE: &str = "unknown";',
                    ),
                    encoding="utf-8",
                )
            result = mod.evaluate_witness(spec, root)
        self.assertFalse(result["pass"])
        self.assertEqual(result["reason_code"], mod.MISSING_ANCHOR)


class RealRepoTests(unittest.TestCase):
    def test_run_all_passes_on_shared_tree(self) -> None:
        payload = mod.run_all()
        failures = [item for item in payload["witness_matrix"] if not item["pass"]]
        self.assertTrue(payload["overall_pass"], failures[:3])
        self.assertEqual(payload["total_witnesses"], len(mod.WITNESS_SPECS))
        self.assertEqual(payload["failed_witnesses"], 0)

    def test_expected_witness_ids_present(self) -> None:
        payload = mod.run_all()
        witness_ids = {item["witness_id"] for item in payload["witness_matrix"]}
        self.assertIn("migration_placeholder_prefix_shortcuts", witness_ids)
        self.assertIn("session_auth_opaque_signature_regression", witness_ids)
        self.assertIn("certification_evidence_binding", witness_ids)
        self.assertIn("workspace_verifier_sdk_cryptographic_bundle_posture", witness_ids)
        self.assertIn("incrate_sdk_verifier_structural_only_posture", witness_ids)
        self.assertIn("incrate_sdk_replay_capsule_structural_only_posture", witness_ids)

    def test_support_bead_ids_include_sdk_follow_on(self) -> None:
        payload = mod.run_all()
        self.assertEqual(
            payload["support_bead_ids"],
            ["bd-3tw7.1", "bd-3tw7.2", "bd-3tw7.4", "bd-3tw7.5", "bd-3tw7.6", "bd-3tw7.8", "bd-3tw7.9"],
        )

    def test_artifact_checker_refs_include_evidence_pack_guard(self) -> None:
        payload = mod.run_all()
        self.assertEqual(
            payload["artifacts"]["evidence_pack_checker"],
            "scripts/check_bd_3tw7_evidence_pack.py",
        )
        self.assertEqual(
            payload["artifacts"]["evidence_pack_checker_tests"],
            "tests/test_check_bd_3tw7_evidence_pack.py",
        )
        self.assertEqual(
            payload["artifacts"]["operator_e2e_suite"],
            "tests/e2e/replacement_truthfulness_gate_suite.sh",
        )

    def test_operator_e2e_metadata_is_present(self) -> None:
        payload = mod.run_all()
        self.assertEqual(
            payload["operator_e2e"]["suite"],
            "tests/e2e/replacement_truthfulness_gate_suite.sh",
        )
        self.assertEqual(
            payload["operator_e2e"]["default_trace_id"],
            "trace-bd-3tw7-operator-e2e",
        )
        self.assertEqual(
            payload["operator_e2e"]["verification_method"],
            "TRACE_ID=trace-bd-3tw7-operator-e2e tests/e2e/replacement_truthfulness_gate_suite.sh",
        )

    def test_operator_e2e_suite_exists(self) -> None:
        payload = mod.run_all()
        suite_path = ROOT / payload["operator_e2e"]["suite"]
        self.assertTrue(suite_path.is_file())

    def test_workspace_sdk_witness_owned_by_follow_on_bead(self) -> None:
        payload = mod.run_all()
        sdk_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "workspace_verifier_sdk_cryptographic_bundle_posture"
        )
        self.assertEqual(sdk_witness["support_bead"], "bd-3tw7.2")
        self.assertIn("sdk/verifier/src/bundle.rs", sdk_witness["source_paths"])

    def test_workspace_sdk_metadata_witness_owned_by_metadata_follow_on(self) -> None:
        payload = mod.run_all()
        metadata_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "workspace_verifier_sdk_package_metadata_truthfulness"
        )
        self.assertEqual(metadata_witness["support_bead"], "bd-3tw7.4")
        self.assertEqual(metadata_witness["source_paths"], ["sdk/verifier/Cargo.toml"])

    def test_incrate_sdk_witnesses_owned_by_follow_on_bead(self) -> None:
        payload = mod.run_all()
        verifier_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "incrate_sdk_verifier_structural_only_posture"
        )
        replay_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "incrate_sdk_replay_capsule_structural_only_posture"
        )
        self.assertEqual(verifier_witness["support_bead"], "bd-3tw7.6")
        self.assertEqual(
            verifier_witness["source_paths"],
            ["crates/franken-node/src/sdk/verifier_sdk.rs"],
        )
        self.assertEqual(replay_witness["support_bead"], "bd-3tw7.6")
        self.assertEqual(
            replay_witness["source_paths"],
            ["crates/franken-node/src/sdk/replay_capsule.rs"],
        )

    def test_excluded_verifier_surfaces_listed(self) -> None:
        payload = mod.run_all()
        excluded = {entry["path"] for entry in payload["excluded_surfaces"]}
        self.assertIn("crates/franken-node/src/verifier_economy/mod.rs", excluded)
        self.assertIn("crates/franken-node/src/connector/verifier_sdk.rs", excluded)
        self.assertNotIn("crates/franken-node/src/sdk/verifier_sdk.rs", excluded)
        self.assertNotIn("crates/franken-node/src/sdk/replay_capsule.rs", excluded)

    def test_completion_debt_coverage_obligations_present(self) -> None:
        payload = mod.run_all()
        coverage = {item["spec_item"]: item for item in payload["coverage_obligations"]}
        self.assertEqual(
            set(coverage),
            {"tests.e2e.primary", "migrations.primary", "telemetry.primary"},
        )
        self.assertEqual(coverage["migrations.primary"]["status"], "covered")
        self.assertIn(
            "migration_artifact_real_signature_verification",
            coverage["migrations.primary"]["witness_ids"],
        )

    def test_witness_telemetry_fields_present(self) -> None:
        payload = mod.run_all()
        required_fields = set(mod.TELEMETRY_REQUIRED_FIELDS)
        self.assertEqual(
            set(payload["structured_log_contract"]["required_fields"]),
            required_fields,
        )
        for witness in payload["witness_matrix"]:
            self.assertTrue(required_fields.issubset(witness), witness["witness_id"])
            self.assertEqual(witness["trace_id"], mod.STATIC_GATE_TRACE_ID)
            self.assertEqual(witness["evidence_bundle_id"], mod.EVIDENCE_BUNDLE_ID)
            self.assertEqual(witness["decision"], "PASS")


class ArtifactWriteTests(unittest.TestCase):
    def test_write_artifacts_creates_expected_files(self) -> None:
        payload = mod.run_all()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mod.write_artifacts(payload, root)
            artifact_dir = root / "artifacts" / "replacement_gap" / mod.PARENT_BEAD
            self.assertTrue((artifact_dir / "verification_evidence.json").exists())
            self.assertTrue((artifact_dir / "verification_summary.md").exists())
            self.assertTrue((artifact_dir / "witness_matrix.json").exists())


class SelfTestTests(unittest.TestCase):
    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
