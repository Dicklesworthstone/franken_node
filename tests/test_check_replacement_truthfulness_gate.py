"""Unit tests for scripts/check_replacement_truthfulness_gate.py."""

from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_replacement_truthfulness_gate as mod


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
        self.assertIn("workspace_verifier_sdk_structural_only_posture", witness_ids)

    def test_support_bead_ids_include_sdk_follow_on(self) -> None:
        payload = mod.run_all()
        self.assertEqual(
            payload["support_bead_ids"],
            ["bd-3tw7.1", "bd-3tw7.2", "bd-3tw7.4", "bd-3tw7.5"],
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

    def test_workspace_sdk_witness_owned_by_follow_on_bead(self) -> None:
        payload = mod.run_all()
        sdk_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "workspace_verifier_sdk_structural_only_posture"
        )
        self.assertEqual(sdk_witness["support_bead"], "bd-3tw7.2")

    def test_workspace_sdk_metadata_witness_owned_by_metadata_follow_on(self) -> None:
        payload = mod.run_all()
        metadata_witness = next(
            item
            for item in payload["witness_matrix"]
            if item["witness_id"] == "workspace_verifier_sdk_package_metadata_truthfulness"
        )
        self.assertEqual(metadata_witness["support_bead"], "bd-3tw7.4")
        self.assertEqual(metadata_witness["source_paths"], ["sdk/verifier/Cargo.toml"])

    def test_excluded_verifier_surfaces_listed(self) -> None:
        payload = mod.run_all()
        excluded = {entry["path"] for entry in payload["excluded_surfaces"]}
        self.assertIn("crates/franken-node/src/verifier_economy/mod.rs", excluded)
        self.assertIn("crates/franken-node/src/sdk/replay_capsule.rs", excluded)


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
