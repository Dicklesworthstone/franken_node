"""Unit tests for scripts/check_independent_replications_gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_independent_replications_gate",
    ROOT / "scripts" / "check_independent_replications_gate.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def _spec_text() -> str:
    return "\n".join(
        [
            "# test contract",
            "INV-IRG-MIN-REPLICATIONS",
            "INV-IRG-REQUIRED-CLAIMS",
            "INV-IRG-INDEPENDENCE",
            "INV-IRG-CONFLICT-DISCLOSURE",
            "INV-IRG-EVIDENCE-LINKS",
            "INV-IRG-DETERMINISM",
            "INV-IRG-ADVERSARIAL",
            *sorted(mod.REQUIRED_EVENT_CODES),
        ]
    )


class TestIndependentReplicationsGate(TestCase):
    def test_repo_report_is_rejected_for_placeholder_evidence(self) -> None:
        # The committed report's "replications" cite evidence on example.org
        # (RFC 2606 documentation hosts): no independent replication exists.
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-whxp")
        self.assertEqual(result["verdict"], "FAIL")
        schema = next(
            check
            for check in result["checks"]
            if check["check"] == "replication schema and claim result completeness"
        )
        self.assertFalse(schema["pass"])
        self.assertIn("placeholder host example.org", schema["detail"])

    def test_placeholder_evidence_host_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            spec_path.write_text(_spec_text(), encoding="utf-8")
            mod.write_sample_evidence(root)
            payload = mod.sample_report()
            for replication in payload["replications"]:
                replication["source_url"] = "https://replicator.example/report"
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")

    def test_missing_relative_evidence_file_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"
            spec_path.write_text(_spec_text(), encoding="utf-8")
            # No evidence files written beside the report.
            report_path.write_text(json.dumps(mod.sample_report(), indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")

    def test_insufficient_independent_replications_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            mod.write_sample_evidence(root)
            payload = mod.sample_report()
            payload["replications"][1]["independent"] = False
            payload["summary"]["independent_replication_count"] = 1
            payload["summary"]["independent_replications_passing"] = 1
            payload["summary"]["verdict"] = "FAIL"
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == ">=2 independent passing replications"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_duplicate_independent_org_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            mod.write_sample_evidence(root)
            payload = mod.sample_report()
            payload["replications"][1]["organization"] = payload["replications"][0]["organization"]
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == "independent organizations unique"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_claim_failure_in_independent_replication_fails(self) -> None:
        with TemporaryDirectory(prefix="bd-whxp-test-") as tmp:
            root = Path(tmp)
            spec_path = root / "spec.md"
            report_path = root / "report.json"

            spec_path.write_text(_spec_text(), encoding="utf-8")
            mod.write_sample_evidence(root)
            payload = mod.sample_report()
            payload["replications"][0]["claim_results"]["compromise_reduction_10x"]["pass"] = False
            payload["summary"]["independent_replications_passing"] = 1
            payload["summary"]["verdict"] = "FAIL"
            report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

            result = mod.run_checks(spec_path=spec_path, report_path=report_path)

        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(
                check["check"] == ">=2 independent passing replications"
                and not check["pass"]
                for check in result["checks"]
            )
        )

    def test_self_test_passes(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    main()
