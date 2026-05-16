"""Unit tests for scripts/check_signed_extension_registry.py."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_signed_extension_registry as checker  # noqa: E402


def write_comment_only_fixture(root: Path) -> dict[str, Path]:
    src = root / "crates/franken-node/src/supply_chain/extension_registry.rs"
    mod_rs = root / "crates/franken-node/src/supply_chain/mod.rs"
    src.parent.mkdir(parents=True)

    markers = [
        "struct ExtensionSignature",
        "ProvenanceAttestation",
        "struct VersionEntry",
        "struct RevocationRecord",
        "struct SignedExtension",
        "struct RegistryAuditRecord",
        "struct RegistrationRequest",
        "struct RegistryResult",
        "struct RegistryConfig",
        "struct SignedExtensionRegistry",
        "enum ExtensionStatus",
        *checker.EXTENSION_STATUSES,
        "enum RevocationReason",
        *checker.REVOCATION_REASONS,
        "fn register(",
        "fn add_version(",
        "fn deprecate(",
        "fn revoke(",
        "fn query(",
        "fn list(",
        "fn version_lineage(",
        "artifact_signing::verify_signature(",
        "KeyRing",
        "signature.signature_bytes",
        "SER_ERR_INVALID_SIGNATURE",
        "prov::verify_attestation_chain(",
        "VerificationPolicy",
        "provenance.vcs_commit_sha",
        "provenance.build_system_identifier",
        "provenance.output_hash",
        "SER_ERR_PROVENANCE_CHAIN_INVALID",
        "pub struct AdmissionKernel",
        "compute_admission_digest(",
        "extension_registry_admission_v1:",
        "canonical_registration_manifest_bytes",
        "registration_manifest_divergence",
        "tv::verify_inclusion(",
        "NegativeWitness",
        "admission_receipts",
        "revocation_sequence",
        "is_terminal",
        "content_hash",
        "Sha256",
        "hex::encode",
        "audit_log",
        "export_audit_log_jsonl",
        *[f'"{code}"' for code in checker.EVENT_CODES],
        *checker.INVARIANTS,
        *["#[test]" for _ in range(30)],
    ]
    src.write_text(
        "// " + "\n// ".join(markers[:40]) + "\n/*\n" + "\n".join(markers[40:]) + "\n*/\n",
        encoding="utf-8",
    )
    mod_rs.write_text("// pub mod extension_registry;\n", encoding="utf-8")
    return {"src": src, "mod": mod_rs}


def run_main(args: list[str]) -> tuple[int, str]:
    old_argv = sys.argv
    stdout = io.StringIO()
    try:
        sys.argv = ["check_signed_extension_registry.py", *args]
        with contextlib.redirect_stdout(stdout):
            try:
                checker.main()
            except SystemExit as exc:
                return int(exc.code), stdout.getvalue()
    finally:
        sys.argv = old_argv
    return 0, stdout.getvalue()


class TestSignedExtensionRegistryChecker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = checker
        cls.results = cls.mod.run_all()

    def test_self_test(self):
        self.assertTrue(self.mod.self_test())

    def test_json_output(self):
        returncode, stdout = run_main(["--json"])
        self.assertEqual(returncode, 0)
        data = json.JSONDecoder().decode(stdout)
        self.assertEqual(data["bead_id"], "bd-209w")
        self.assertEqual(data["replacement_bead_id"], "bd-3hdn")
        self.assertEqual(data["verdict"], "PASS")
        self.assertEqual(data["summary"]["failing"], 0)
        self.assertIsInstance(data["checks"], list)
        self.assertEqual(data["completion_debt"]["completion_bead"], "bd-3hdn.1")

    def test_source_exists(self):
        name, ok, _ = self.mod.check_source_exists()
        self.assertEqual(name, "source_exists")
        self.assertTrue(ok)

    def test_module_wiring(self):
        name, ok, _ = self.mod.check_module_wiring()
        self.assertEqual(name, "module_wiring")
        self.assertTrue(ok)

    def test_structs(self):
        name, ok, _ = self.mod.check_structs()
        self.assertEqual(name, "structs")
        self.assertTrue(ok)

    def test_extension_statuses(self):
        name, ok, _ = self.mod.check_extension_statuses()
        self.assertEqual(name, "extension_statuses")
        self.assertTrue(ok)

    def test_revocation_reasons(self):
        name, ok, _ = self.mod.check_revocation_reasons()
        self.assertEqual(name, "revocation_reasons")
        self.assertTrue(ok)

    def test_registry_operations(self):
        name, ok, _ = self.mod.check_registry_operations()
        self.assertEqual(name, "registry_operations")
        self.assertTrue(ok)

    def test_signature_verification(self):
        name, ok, _ = self.mod.check_signature_verification()
        self.assertEqual(name, "signature_verification")
        self.assertTrue(ok)

    def test_provenance_validation(self):
        name, ok, _ = self.mod.check_provenance_validation()
        self.assertEqual(name, "provenance_validation")
        self.assertTrue(ok)

    def test_admission_kernel(self):
        name, ok, _ = self.mod.check_admission_kernel()
        self.assertEqual(name, "admission_kernel")
        self.assertTrue(ok)

    def test_monotonic_revocation(self):
        name, ok, _ = self.mod.check_monotonic_revocation()
        self.assertEqual(name, "monotonic_revocation")
        self.assertTrue(ok)

    def test_event_codes(self):
        name, ok, _ = self.mod.check_event_codes()
        self.assertEqual(name, "event_codes")
        self.assertTrue(ok)

    def test_invariants(self):
        name, ok, _ = self.mod.check_invariants()
        self.assertEqual(name, "invariants")
        self.assertTrue(ok)

    def test_content_hash(self):
        name, ok, _ = self.mod.check_content_hash()
        self.assertEqual(name, "content_hash")
        self.assertTrue(ok)

    def test_audit_logging(self):
        name, ok, _ = self.mod.check_audit_logging()
        self.assertEqual(name, "audit_logging")
        self.assertTrue(ok)

    def test_spec_alignment(self):
        name, ok, _ = self.mod.check_spec_alignment()
        self.assertEqual(name, "spec_alignment")
        self.assertTrue(ok)

    def test_test_coverage(self):
        name, ok, _ = self.mod.check_test_coverage()
        self.assertEqual(name, "test_coverage")
        self.assertTrue(ok)

    def test_replacement_evidence_files(self):
        name, ok, _ = self.mod.check_replacement_evidence_files()
        self.assertEqual(name, "bd_3hdn_evidence_files")
        self.assertTrue(ok)

    def test_telemetry_contract(self):
        name, ok, _ = self.mod.check_telemetry_contract()
        self.assertEqual(name, "bd_3hdn_telemetry_contract")
        self.assertTrue(ok)

    def test_completion_debt_obligations_present(self):
        contract = self.mod.completion_debt_contract()
        self.assertEqual(contract["completion_bead"], "bd-3hdn.1")
        obligations = {
            obligation["spec_item"]: obligation
            for obligation in contract["coverage_obligations"]
        }
        self.assertEqual(
            set(obligations),
            {
                "tests.unit.primary",
                "tests.integration.primary",
                "tests.e2e.primary",
                "tests.golden.primary",
                "telemetry.primary",
            },
        )
        self.assertIn(
            "tests/e2e/extension_registry_operator_suite.sh",
            obligations["tests.e2e.primary"]["evidence_paths"],
        )
        self.assertIn(
            "artifacts/golden/supply_chain_attestation_manifest.json",
            obligations["tests.golden.primary"]["evidence_paths"],
        )
        self.assertIn("trace_id", obligations["telemetry.primary"]["required_fields"])

    def test_completion_debt_missing_spec_item_fails(self):
        original = self.mod.COMPLETION_DEBT_OBLIGATIONS
        self.mod.COMPLETION_DEBT_OBLIGATIONS = [
            obligation
            for obligation in original
            if obligation["spec_item"] != "telemetry.primary"
        ]
        try:
            name, ok, detail = self.mod.check_completion_debt_coverage()
        finally:
            self.mod.COMPLETION_DEBT_OBLIGATIONS = original
        self.assertEqual(name, "bd_3hdn_1_completion_debt")
        self.assertFalse(ok)
        self.assertIn("telemetry.primary", detail)

    def test_completion_debt_missing_evidence_path_fails(self):
        original = self.mod.COMPLETION_DEBT_OBLIGATIONS
        mutated = [dict(obligation) for obligation in original]
        mutated[0] = dict(mutated[0])
        mutated[0]["evidence_paths"] = list(mutated[0]["evidence_paths"]) + [
            "artifacts/replacement_gap/bd-3hdn/missing-completion-debt.json"
        ]
        self.mod.COMPLETION_DEBT_OBLIGATIONS = mutated
        try:
            name, ok, detail = self.mod.check_completion_debt_coverage()
        finally:
            self.mod.COMPLETION_DEBT_OBLIGATIONS = original
        self.assertEqual(name, "bd_3hdn_1_completion_debt")
        self.assertFalse(ok)
        self.assertIn("missing-completion-debt.json", detail)

    def test_all_checks_pass(self):
        failures = [r for r in self.results if not r["passed"]]
        self.assertEqual(failures, [])

    def test_verdict_is_pass(self):
        self.assertTrue(all(r["passed"] for r in self.results))

    def test_human_output(self):
        returncode, stdout = run_main([])
        self.assertEqual(returncode, 0)
        self.assertIn("PASS", stdout)

    def test_comment_only_rust_markers_fail_closed(self):
        rust_checks = [
            self.mod.check_module_wiring,
            self.mod.check_structs,
            self.mod.check_extension_statuses,
            self.mod.check_revocation_reasons,
            self.mod.check_registry_operations,
            self.mod.check_signature_verification,
            self.mod.check_provenance_validation,
            self.mod.check_admission_kernel,
            self.mod.check_monotonic_revocation,
            self.mod.check_event_codes,
            self.mod.check_invariants,
            self.mod.check_content_hash,
            self.mod.check_audit_logging,
            self.mod.check_test_coverage,
        ]
        with tempfile.TemporaryDirectory(prefix="ser-comment-only-") as tmpdir:
            paths = write_comment_only_fixture(Path(tmpdir))
            with (
                patch.object(self.mod, "SRC", paths["src"]),
                patch.object(self.mod, "MOD_RS", paths["mod"]),
            ):
                source_exists = self.mod.check_source_exists()
                results = [fn() for fn in rust_checks]

        self.assertTrue(source_exists[1])
        self.assertEqual(
            [name for name, ok, _ in results if ok],
            [],
        )

    def test_strip_rust_comments_preserves_event_code_strings(self):
        source = (
            'pub const KEEP: &str = "SER-001 // literal"; // "SER-002"\n'
            'pub const RAW: &str = r#"INV-SER-SIGNED /* literal */"#;\n'
            "pub/* hidden */ struct SignedExtensionRegistry;\n"
        )

        stripped = self.mod._strip_rust_comments(source)

        self.assertIn('"SER-001 // literal"', stripped)
        self.assertIn('r#"INV-SER-SIGNED /* literal */"#', stripped)
        self.assertIn("pub  struct SignedExtensionRegistry;", stripped)
        self.assertNotIn('"SER-002"', stripped)


if __name__ == "__main__":
    unittest.main()
