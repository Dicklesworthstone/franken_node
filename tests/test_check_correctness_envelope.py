#!/usr/bin/env python3
"""Unit tests for check_correctness_envelope.py verification script."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_correctness_envelope.py"
spec = importlib.util.spec_from_file_location("check_correctness_envelope_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


def run_check(*extra_args: str) -> subprocess.CompletedProcess:
    """Run the verification script."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *extra_args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=30,
    )


def write_comment_only_fixture(root: Path) -> dict[str, Path]:
    policy_dir = root / "crates/franken-node/src/policy"
    spec_dir = root / "docs/specs/section_10_14"
    artifact_dir = root / "artifacts/10.14"
    policy_dir.mkdir(parents=True)
    spec_dir.mkdir(parents=True)
    artifact_dir.mkdir(parents=True)

    paths = {
        "impl": policy_dir / "correctness_envelope.rs",
        "mod": policy_dir / "mod.rs",
        "spec": spec_dir / "bd-sddz_contract.md",
        "manifest": artifact_dir / "correctness_envelope_manifest.json",
    }

    inv_ids = [f"INV-{idx:03}-COMMENT-ONLY" for idx in range(1, 13)]
    rust_markers = [
        "pub struct CorrectnessEnvelope",
        "pub fn is_within_envelope(",
        "fn canonical_invariants()",
        "EVD-ENVELOPE-001",
        "EVD-ENVELOPE-002",
        "EVD-ENVELOPE-003",
        *[f'InvariantId::new("{inv_id}")' for inv_id in inv_ids],
        "INV-001",
        "INV-002",
        "INV-003",
        "INV-004",
        "INV-005",
        "INV-006",
        "INV-007",
        "INV-008",
        "INV-009",
        "INV-010",
        "INV-011",
        "INV-012",
    ]
    paths["impl"].write_text(
        "// " + "\n// ".join(rust_markers[:10]) + "\n/*\n" + "\n".join(rust_markers[10:]) + "\n*/\n",
        encoding="utf-8",
    )
    paths["mod"].write_text("// pub mod correctness_envelope;\n", encoding="utf-8")
    paths["spec"].write_text("INV-001\n", encoding="utf-8")
    paths["manifest"].write_text(
        json.dumps({"invariants": [{"id": inv_id} for inv_id in inv_ids]}),
        encoding="utf-8",
    )
    return paths


def test_human_output_passes():
    """Human-readable output succeeds and mentions PASS."""
    result = run_check()
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    assert "PASS" in result.stdout


def test_json_output_is_valid():
    """JSON output is valid and has expected structure."""
    result = run_check("--json")
    assert result.returncode == 0, f"script failed:\n{result.stdout}\n{result.stderr}"
    data = json.loads(result.stdout)
    assert data["bead_id"] == "bd-sddz"
    assert data["overall_pass"] is True
    assert isinstance(data["checks"], list)
    assert data["invariant_count"] >= 10


def test_json_all_checks_pass():
    """Every individual check passes."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    for check in data["checks"]:
        assert check["pass"], f"check '{check['check']}' failed: {check['detail']}"


def test_json_has_artifact_paths():
    """JSON output includes artifact path references."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    assert "implementation" in data["artifacts"]
    assert "spec" in data["artifacts"]
    assert "manifest" in data["artifacts"]


def test_invariant_count_at_least_10():
    """At least 10 invariants are verified."""
    result = run_check("--json")
    data = json.loads(result.stdout)
    assert data["invariant_count"] >= 10


def test_self_test_function():
    """Import and run self_test directly."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import check_correctness_envelope as mod
    all_pass, results = mod.self_test()
    assert all_pass
    check_names = {r["check"] for r in results}
    expected = {
        "impl_exists", "mod_rs", "invariant_count", "unique_ids",
        "no_enforcement_none", "is_within_envelope", "log_codes",
        "spec_exists", "manifest", "test_coverage",
    }
    assert expected <= check_names, f"missing checks: {expected - check_names}"
    sys.path.pop(0)


def test_preserves_string_literals_while_stripping_comments():
    """Comment stripping preserves quoted and raw Rust string literals."""
    source = (
        'pub const KEEP: &str = "EVD-ENVELOPE-001 // literal"; // "EVD-ENVELOPE-002"\n'
        'pub const RAW: &str = r#"INV-001-MONOTONIC-HARDENING /* literal */"#; '
        '/* "EVD-ENVELOPE-003" */\n'
        "pub/* hidden */ struct CorrectnessEnvelope;\n"
    )

    stripped = check_mod.strip_rust_comments(source)

    assert '"EVD-ENVELOPE-001 // literal"' in stripped
    assert 'r#"INV-001-MONOTONIC-HARDENING /* literal */"#' in stripped
    assert "pub  struct CorrectnessEnvelope" in stripped
    assert all(marker not in stripped for marker in ('"EVD-ENVELOPE-002"', '"EVD-ENVELOPE-003"'))


def test_comment_only_rust_markers_fail_closed(tmp_path, monkeypatch):
    """Rust-backed checks reject markers that appear only in comments."""
    paths = write_comment_only_fixture(tmp_path)
    evidence_path = tmp_path / "artifacts/section_10_14/bd-sddz/verification_evidence.json"

    monkeypatch.setattr(check_mod, "ROOT", tmp_path)
    monkeypatch.setattr(check_mod, "IMPL_PATH", paths["impl"])
    monkeypatch.setattr(check_mod, "MOD_PATH", paths["mod"])
    monkeypatch.setattr(check_mod, "SPEC_PATH", paths["spec"])
    monkeypatch.setattr(check_mod, "MANIFEST_PATH", paths["manifest"])
    monkeypatch.setattr(check_mod, "EVIDENCE_PATH", evidence_path)

    all_pass, results = check_mod.self_test()

    by_name = {result["check"]: result for result in results}
    assert not all_pass
    assert by_name["spec_exists"]["pass"]
    assert by_name["manifest"]["pass"]
    for check_name in [
        "impl_exists",
        "mod_rs",
        "invariant_count",
        "unique_ids",
        "is_within_envelope",
        "log_codes",
        "test_coverage",
    ]:
        assert not by_name[check_name]["pass"], check_name


if __name__ == "__main__":
    test_human_output_passes()
    test_json_output_is_valid()
    test_json_all_checks_pass()
    test_json_has_artifact_paths()
    test_invariant_count_at_least_10()
    test_self_test_function()
    print("All tests passed.")
