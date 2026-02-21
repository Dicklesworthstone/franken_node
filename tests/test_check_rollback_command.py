"""Unit tests for scripts/check_rollback_command.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_rollback_command",
    ROOT / "scripts" / "check_rollback_command.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _make_valid_summary(evidence_path: str) -> dict:
    return {
        "summary_id": "chg-rollback-test",
        "contract_version": "1.0",
        "change_summary": {
            "rollback_command": {
                "command": (
                    "franken-node rollback apply "
                    "--receipt artifacts/section_11/bd-nglx/rollback_command_ci_test.json "
                    "--force-safe"
                ),
                "idempotent": True,
                "tested_in_ci": True,
                "test_evidence_artifact": evidence_path,
                "rollback_scope": {
                    "reverts": ["runtime policy override state"],
                    "does_not_revert": ["already-emitted audit events"],
                },
                "estimated_duration": "2m30s",
            }
        },
    }


class TestRollbackCommandChecker(TestCase):
    def test_required_event_codes_present(self) -> None:
        self.assertIn("CONTRACT_ROLLBACK_COMMAND_VALIDATED", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_ROLLBACK_COMMAND_MISSING", mod.REQUIRED_EVENT_CODES)
        self.assertIn("CONTRACT_ROLLBACK_COMMAND_INCOMPLETE", mod.REQUIRED_EVENT_CODES)

    def test_run_checks_passes_with_valid_summary(self) -> None:
        with TemporaryDirectory(prefix="rollback-contract-pass-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)

            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            evidence_rel = "artifacts/section_11/bd-nglx/rollback_command_ci_test.json"
            (root / evidence_rel).write_text("{\"ok\":true}\n", encoding="utf-8")

            summary = _make_valid_summary(evidence_rel)
            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertTrue(ok)
        self.assertEqual(report["bead_id"], "bd-nglx")
        self.assertIn("docs/change_summaries/candidate.json", report["summary_files_checked"])

    def test_missing_rollback_field_fails(self) -> None:
        with TemporaryDirectory(prefix="rollback-contract-missing-field-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            summary = {"summary_id": "x", "contract_version": "1.0", "change_summary": {}}
            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("rollback_command must be an object" in err for err in report["errors"]))

    def test_placeholder_command_fails(self) -> None:
        with TemporaryDirectory(prefix="rollback-contract-placeholder-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            evidence_rel = "artifacts/section_11/bd-nglx/rollback_command_ci_test.json"
            (root / evidence_rel).write_text("{\"ok\":true}\n", encoding="utf-8")
            summary = _make_valid_summary(evidence_rel)
            summary["change_summary"]["rollback_command"]["command"] = (
                "franken-node rollback apply --receipt <receipt-path>"
            )

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("contains unresolved placeholders" in err for err in report["errors"]))

    def test_untested_command_fails(self) -> None:
        with TemporaryDirectory(prefix="rollback-contract-untested-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "artifacts" / "section_11" / "bd-nglx").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )

            evidence_rel = "artifacts/section_11/bd-nglx/rollback_command_ci_test.json"
            (root / evidence_rel).write_text("{\"ok\":true}\n", encoding="utf-8")
            summary = _make_valid_summary(evidence_rel)
            summary["change_summary"]["rollback_command"]["tested_in_ci"] = False

            example = root / "docs" / "change_summaries" / "example_change_summary.json"
            example.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            candidate = root / "docs" / "change_summaries" / "candidate.json"
            candidate.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            ok, report = mod.run_checks(
                changed_files=[
                    "crates/franken-node/src/connector/mock.rs",
                    "docs/change_summaries/candidate.json",
                ],
                project_root=root,
            )

        self.assertFalse(ok)
        self.assertTrue(any("tested_in_ci must be true" in err for err in report["errors"]))

    def test_non_subsystem_change_does_not_require_summary(self) -> None:
        with TemporaryDirectory(prefix="rollback-contract-non-subsystem-") as tmp:
            root = Path(tmp)
            (root / "docs" / "templates").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "change_summaries").mkdir(parents=True, exist_ok=True)
            (root / "docs" / "templates" / "change_summary_template.md").write_text(
                "# template\n",
                encoding="utf-8",
            )
            (root / "docs" / "change_summaries" / "example_change_summary.json").write_text(
                json.dumps(_make_valid_summary("docs/change_summaries/example_change_summary.json"), indent=2),
                encoding="utf-8",
            )

            ok, report = mod.run_checks(changed_files=["README.md"], project_root=root)

        self.assertTrue(ok)
        self.assertFalse(report["requires_contract"])
        self.assertEqual(report["summary_files_checked"], [])

    def test_self_test_passes(self) -> None:
        ok, payload = mod.self_test()
        self.assertTrue(ok)
        self.assertEqual(payload["self_test"], "passed")


if __name__ == "__main__":
    main()
