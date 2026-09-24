"""Tests for scripts/check_claim_language.py."""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_claim_language import parse_claims, _extract_field


# ── parse_claims ─────────────────────────────────────────────


def test_parse_no_claims():
    text = "# Claims Registry\n\n## Registered Claims\n\n_None yet._\n"
    assert parse_claims(text) == []


def test_parse_single_claim():
    text = textwrap.dedent("""\
        ## Registered Claims

        ### CLAIM-001: Test Claim
        - **Category**: compatibility
        - **Claim**: We pass 95% of tests.
        - **Evidence artifacts**: artifacts/test/evidence.json
        - **Verification command**: python3 check.py
        - **Last verified**: 2025-01-15T00:00:00+00:00
        - **Status**: verified
    """)
    claims = parse_claims(text)
    assert len(claims) == 1
    assert claims[0]["id"] == "CLAIM-001"
    assert claims[0]["title"] == "Test Claim"
    assert claims[0]["category"] == "compatibility"
    assert claims[0]["evidence_artifacts"] == "artifacts/test/evidence.json"
    assert claims[0]["status"] == "verified"


def test_parse_multiple_claims():
    text = textwrap.dedent("""\
        ## Registered Claims

        ### CLAIM-001: First
        - **Category**: security
        - **Claim**: Secure.
        - **Evidence artifacts**: a.json
        - **Status**: verified

        ### CLAIM-002: Second
        - **Category**: performance
        - **Claim**: Fast.
        - **Evidence artifacts**: b.json
        - **Status**: pending
    """)
    claims = parse_claims(text)
    assert len(claims) == 2
    assert claims[0]["id"] == "CLAIM-001"
    assert claims[1]["id"] == "CLAIM-002"


def test_parse_ignores_code_fences():
    text = textwrap.dedent("""\
        ## Format
        ```
        ### CLAIM-<ID>: <Title>
        - **Evidence artifacts**: <path>
        ```

        ## Registered Claims
        _None._
    """)
    claims = parse_claims(text)
    assert len(claims) == 0


def test_parse_ignores_html_comments():
    text = textwrap.dedent("""\
        ## Registered Claims

        <!--
        ### CLAIM-001: Commented Out
        - **Evidence artifacts**: does/not/exist.json
        -->
    """)
    claims = parse_claims(text)
    assert len(claims) == 0


# ── _extract_field ───────────────────────────────────────────


def test_extract_field_present():
    block = "- **Category**: security\n- **Claim**: Secure.\n"
    assert _extract_field(block, "Category") == "security"
    assert _extract_field(block, "Claim") == "Secure."


def test_extract_field_missing():
    block = "- **Category**: security\n"
    assert _extract_field(block, "Evidence artifacts") == ""


# ── Integration: check functions against real registry ───────


def test_check_registry_exists():
    from check_claim_language import check_registry_exists
    result = check_registry_exists()
    assert result["status"] == "PASS"
    assert result["id"] == "CLAIM-REGISTRY"


def test_check_registry_format():
    from check_claim_language import check_registry_format
    result = check_registry_format()
    assert result["status"] == "PASS"
    assert result["details"]["well_formed"]


def test_check_policy_doc_exists():
    from check_claim_language import check_policy_doc_exists
    result = check_policy_doc_exists()
    assert result["status"] == "PASS"


def test_check_claims_have_artifacts_empty_registry(tmp_path, monkeypatch):
    import check_claim_language
    registry = tmp_path / "CLAIMS_REGISTRY.md"
    registry.write_text("# Claims Registry\n\n## Registered Claims\n")
    monkeypatch.setattr(check_claim_language, "REGISTRY_PATH", registry)
    result = check_claim_language.check_claims_have_artifacts()
    # With no active claims, there's nothing to fail
    assert result["status"] == "PASS"
    assert result["details"]["claim_count"] == 0


def test_artifact_paths_documented_code_span_form():
    from check_claim_language import _extract_evidence_field, artifact_paths
    block = (
        "- **Evidence artifact**: `crates/a/src/x.rs` (`fn helper`);\n"
        "  `sdk/v/src/lib.rs::verify`, `crates/a/tests/t.rs:12-40`,\n"
        "  `.franken-node/state/incidents/<id>/`, `cargo test -p x`\n"
        "- **Verification command**: `cargo test`\n"
    )
    value = _extract_evidence_field(block)
    assert artifact_paths(value) == [
        "crates/a/src/x.rs",
        "sdk/v/src/lib.rs",
        "crates/a/tests/t.rs",
    ]


def test_prose_only_evidence_cites_no_path():
    from check_claim_language import artifact_paths
    assert artifact_paths("60+ files per memory; grep `rg -n 'x' src/`") == []


def test_claim_language_checker_e2e_json_passes():
    result = subprocess.run(  # nosec B603 - fixed checker command under repo root.
        [sys.executable, "scripts/check_claim_language.py", "--json"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["gate"] == "claim_language_policy"
    assert payload["verdict"] == "PASS"
    assert payload["summary"]["total_checks"] == 5
    assert payload["summary"]["failing_checks"] == 0
