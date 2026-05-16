"""Unit tests for scripts/check_bounded_masking.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_bounded_masking",
    ROOT / "scripts" / "check_bounded_masking.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _write_minimal_fixture(root: Path, *, include_mod_wire: bool) -> None:
    impl_path = root / "crates" / "franken-node" / "src" / "runtime" / "bounded_mask.rs"
    mod_path = root / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
    spec_path = root / "docs" / "specs" / "section_10_11" / "bd-24k_contract.md"
    evidence_path = root / "artifacts" / "section_10_11" / "bd-24k" / "verification_evidence.json"
    summary_path = root / "artifacts" / "section_10_11" / "bd-24k" / "verification_summary.md"

    impl_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    impl_lines = []
    impl_lines.extend(mod.REQUIRED_CONSTANTS)
    impl_lines.extend(mod.REQUIRED_EVENT_CODES)
    impl_lines.extend(mod.REQUIRED_TYPES)
    impl_lines.extend(mod.REQUIRED_FUNCTIONS)
    impl_lines.extend(mod.REQUIRED_TEST_NAMES)
    impl_lines.append("pub fn bounded_mask<T, F>() {}")
    impl_lines.append("pub fn bounded_mask_with_report<T, F>() {}")
    impl_lines.append("pub fn bounded_mask_with_policy<T, F>() {}")
    impl_path.write_text("\n".join(impl_lines) + "\n", encoding="utf-8")

    mod_text = "pub mod bounded_mask;\n" if include_mod_wire else "pub mod safe_mode;\n"
    mod_path.write_text(mod_text, encoding="utf-8")

    spec_path.write_text("## Invariants\nINV-BM-CANCEL-DEFERRED\n", encoding="utf-8")
    summary_path.write_text("FN-BM-001\nFN-BM-006\n", encoding="utf-8")
    evidence_path.write_text(
        json.dumps(
            {
                "verification_metrics": {
                    "invocations_total": 1,
                    "completed_within_bound": 1,
                    "mask_timeout_exceeded": 0,
                    "deferred_cancels_delivered": 0,
                    "avg_mask_duration_us": 1,
                }
            }
        ),
        encoding="utf-8",
    )


def _write_comment_only_fixture(root: Path) -> None:
    impl_path = root / "crates" / "franken-node" / "src" / "runtime" / "bounded_mask.rs"
    mod_path = root / "crates" / "franken-node" / "src" / "runtime" / "mod.rs"
    spec_path = root / "docs" / "specs" / "section_10_11" / "bd-24k_contract.md"
    evidence_path = root / "artifacts" / "section_10_11" / "bd-24k" / "verification_evidence.json"
    summary_path = root / "artifacts" / "section_10_11" / "bd-24k" / "verification_summary.md"

    impl_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    impl_markers = (
        mod.REQUIRED_CONSTANTS
        + mod.REQUIRED_EVENT_CODES
        + mod.REQUIRED_TYPES
        + mod.REQUIRED_FUNCTIONS
        + mod.REQUIRED_TEST_NAMES
        + [
            "pub fn bounded_mask<T, F>() {}",
            "pub fn bounded_mask_with_report<T, F>() {}",
            "pub fn bounded_mask_with_policy<T, F>() {}",
        ]
    )
    impl_path.write_text(
        "\n".join(f"// {marker}" for marker in impl_markers)
        + "\n/*\npub fn bounded_mask<T, F>() {}\n*/\n",
        encoding="utf-8",
    )
    mod_path.write_text("// pub mod bounded_mask;\n", encoding="utf-8")

    spec_path.write_text("## Invariants\nINV-BM-CANCEL-DEFERRED\n", encoding="utf-8")
    summary_path.write_text("FN-BM-001\nFN-BM-006\n", encoding="utf-8")
    evidence_path.write_text(
        json.dumps(
            {
                "verification_metrics": {
                    "invocations_total": 1,
                    "completed_within_bound": 1,
                    "mask_timeout_exceeded": 0,
                    "deferred_cancels_delivered": 0,
                    "avg_mask_duration_us": 1,
                }
            }
        ),
        encoding="utf-8",
    )


class TestCheckBoundedMasking(TestCase):
    def test_preserves_string_literals_while_stripping_comments(self) -> None:
        source = "\n".join(
            [
                'pub const URL: &str = "https://example.test//kept"; // pub struct CapabilityContext',
                'pub const BLOCKY: &str = "not /* a comment */"; /* pub fn bounded_mask<T, F>() {} */',
                'pub const RAW: &str = r#"raw // kept /* kept */"#;',
                "/* outer /* nested */ still comment */ pub struct RealMarker;",
            ]
        )

        stripped = mod._strip_rust_comments(source)

        self.assertIn('"https://example.test//kept"', stripped)
        self.assertIn('"not /* a comment */"', stripped)
        self.assertIn('r#"raw // kept /* kept */"#', stripped)
        self.assertIn("pub struct RealMarker;", stripped)
        self.assertNotIn("pub struct CapabilityContext", stripped)
        self.assertNotIn("pub fn bounded_mask<T, F>() {}", stripped)
        self.assertNotIn("nested", stripped)

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")
        self.assertTrue(payload["strip_check_ok"])

    def test_run_checks_passes_on_real_repo(self) -> None:
        ok, payload = mod.run_checks(ROOT)
        self.assertTrue(ok)
        self.assertEqual(payload["bead_id"], "bd-24k")

    def test_run_checks_passes_with_minimal_fixture(self) -> None:
        with TemporaryDirectory(prefix="check-bounded-mask-pass-") as tmp:
            root = Path(tmp)
            _write_minimal_fixture(root, include_mod_wire=True)
            ok, payload = mod.run_checks(root)

        self.assertTrue(ok)
        self.assertTrue(all(entry["passed"] for entry in payload["results"]))

    def test_run_checks_fails_when_module_not_wired(self) -> None:
        with TemporaryDirectory(prefix="check-bounded-mask-fail-") as tmp:
            root = Path(tmp)
            _write_minimal_fixture(root, include_mod_wire=False)
            ok, payload = mod.run_checks(root)

        self.assertFalse(ok)
        failures = [row for row in payload["results"] if not row["passed"]]
        self.assertTrue(any(row["name"] == "runtime_mod_wiring" for row in failures))

    def test_comment_only_rust_markers_fail_closed(self) -> None:
        with TemporaryDirectory(prefix="check-bounded-mask-comments-") as tmp:
            root = Path(tmp)
            _write_comment_only_fixture(root)
            ok, payload = mod.run_checks(root)

        self.assertFalse(ok)
        by_name = {row["name"]: row for row in payload["results"]}
        self.assertTrue(by_name["impl_exists"]["passed"])
        self.assertTrue(by_name["module_exists"]["passed"])
        self.assertTrue(by_name["spec_mentions_invariants"]["passed"])
        self.assertTrue(by_name["summary_mentions_event_codes"]["passed"])
        self.assertTrue(by_name["evidence_metrics_fields"]["passed"])

        rust_backed_checks = [
            "required_constants",
            "required_event_codes",
            "required_types",
            "required_functions",
            "signature_patterns",
            "unit_test_presence",
            "runtime_mod_wiring",
        ]
        for name in rust_backed_checks:
            self.assertFalse(by_name[name]["passed"], name)


if __name__ == "__main__":
    main()
