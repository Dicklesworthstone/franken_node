"""Tests for scripts/check_docs_claim_traceability.py (bd-38hez.8)."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location(
    "check_docs_claim_traceability",
    ROOT / "scripts" / "check_docs_claim_traceability.py",
)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def write_fixture_files(base: Path) -> None:
    fixtures = {
        "README.md": "franken-node migrate audit ./app emits JSON migration findings\n",
        "docs/install.md": "curl https://example.invalid/install.sh | sh installs the released CLI\n",
        "docs/vision.md": "franken-node automatically rewrites every Node API with zero manual review\n",
        "tests/direct.rs": "#[test]\nfn migrate_audit_json_contract() {}\n",
        "tests/proxy.rs": "#[test]\nfn smoke_proxy_contract() {}\n",
    }
    for rel, text in fixtures.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def claim(
    *,
    claim_id: str,
    source_path: str,
    claim_text: str,
    evidence_refs: list[dict[str, str]],
    classification: str,
    claim_kind: str = "current",
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "claim_kind": claim_kind,
        "source": {
            "path": source_path,
            "line": 1,
            "claim_text": claim_text,
        },
        "command_surfaces": ["franken-node migrate audit"],
        "evidence_refs": evidence_refs,
        "classification": classification,
        "required_action": "none" if classification == "covered" else "replace_with_direct_fresh_evidence",
    }


def matrix(claims: list[dict[str, object]]) -> dict[str, object]:
    counts = {status: 0 for status in mod.CLASSIFICATIONS}
    for entry in claims:
        counts[str(entry["classification"])] += 1
    return {
        "schema_version": mod.SCHEMA_VERSION,
        "bead_id": mod.BEAD_ID,
        "generated_at_utc": "2026-05-09T00:00:00Z",
        "summary": {
            "total_claims": len(claims),
            "covered": counts["covered"],
            "weakly_covered": counts["weakly_covered"],
            "stale": counts["stale"],
            "aspirational": counts["aspirational"],
            "missing_proof": counts["missing_proof"],
            "verdict": "PASS" if all(entry["classification"] == "covered" for entry in claims) else "FAIL",
        },
        "claims": claims,
    }


class TestDocsClaimTraceability(unittest.TestCase):
    def test_repo_matrix_passes(self) -> None:
        report = mod.run_checks()
        self.assertEqual(report["bead_id"], "bd-38hez.8")
        self.assertEqual(report["verdict"], "PASS")

    def test_covered_command_claim_passes_with_direct_fresh_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-COVERED",
                        source_path="README.md",
                        claim_text="franken-node migrate audit ./app emits JSON migration findings",
                        evidence_refs=[
                            {
                                "evidence_id": "direct-test",
                                "kind": "test",
                                "coverage": "direct",
                                "status": "fresh",
                                "path": "tests/direct.rs",
                                "description": "direct CLI contract",
                            }
                        ],
                        classification="covered",
                    )
                ]
            )
            report = mod.evaluate_matrix(payload, base)

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["derived_classifications"]["FIX-COVERED"], "covered")

    def test_stale_install_claim_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-STALE-INSTALL",
                        source_path="docs/install.md",
                        claim_text="curl https://example.invalid/install.sh | sh installs the released CLI",
                        evidence_refs=[
                            {
                                "evidence_id": "stale-install-check",
                                "kind": "gate",
                                "coverage": "direct",
                                "status": "stale",
                                "path": "tests/direct.rs",
                                "description": "old installer check",
                            }
                        ],
                        classification="stale",
                    )
                ]
            )
            report = mod.evaluate_matrix(payload, base)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["derived_classifications"]["FIX-STALE-INSTALL"], "stale")

    def test_docs_only_aspirational_claim_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-ASPIRATIONAL",
                        claim_kind="aspirational",
                        source_path="docs/vision.md",
                        claim_text="franken-node automatically rewrites every Node API with zero manual review",
                        evidence_refs=[],
                        classification="aspirational",
                    )
                ]
            )
            report = mod.evaluate_matrix(payload, base)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["derived_classifications"]["FIX-ASPIRATIONAL"], "aspirational")

    def test_proxy_only_claim_is_weakly_covered_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-PROXY",
                        source_path="README.md",
                        claim_text="franken-node migrate audit ./app emits JSON migration findings",
                        evidence_refs=[
                            {
                                "evidence_id": "proxy-test",
                                "kind": "test",
                                "coverage": "proxy",
                                "status": "fresh",
                                "path": "tests/proxy.rs",
                                "description": "proxy-only smoke check",
                            }
                        ],
                        classification="weakly_covered",
                    )
                ]
            )
            report = mod.evaluate_matrix(payload, base)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["derived_classifications"]["FIX-PROXY"], "weakly_covered")

    def test_missing_direct_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-MISSING-DIRECT",
                        source_path="README.md",
                        claim_text="franken-node migrate audit ./app emits JSON migration findings",
                        evidence_refs=[
                            {
                                "evidence_id": "missing-direct-test",
                                "kind": "test",
                                "coverage": "direct",
                                "status": "fresh",
                                "path": "tests/missing.rs",
                                "description": "missing direct CLI test",
                            }
                        ],
                        classification="missing_proof",
                    )
                ]
            )
            report = mod.evaluate_matrix(payload, base)

        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["derived_classifications"]["FIX-MISSING-DIRECT"], "missing_proof")

    def test_human_report_is_stable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bd-38hez-8-") as tmp:
            base = Path(tmp)
            write_fixture_files(base)
            payload = matrix(
                [
                    claim(
                        claim_id="FIX-COVERED",
                        source_path="README.md",
                        claim_text="franken-node migrate audit ./app emits JSON migration findings",
                        evidence_refs=[
                            {
                                "evidence_id": "direct-test",
                                "kind": "test",
                                "coverage": "direct",
                                "status": "fresh",
                                "path": "tests/direct.rs",
                                "description": "direct CLI contract",
                            }
                        ],
                        classification="covered",
                    )
                ]
            )

        first = mod.render_human(payload)
        second = mod.render_human(payload)
        self.assertEqual(first, second)
        self.assertIn("| `FIX-COVERED` | `README.md` | `covered` | `1` | `0` | `none` |", first)

    def test_self_test(self) -> None:
        self.assertTrue(mod.self_test())


if __name__ == "__main__":
    unittest.main()
