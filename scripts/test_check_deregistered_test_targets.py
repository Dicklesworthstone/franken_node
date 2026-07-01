#!/usr/bin/env python3
"""Unit tests for check_deregistered_test_targets.py (.G2 orphan census, bd-romfp).

Run: python3 scripts/test_check_deregistered_test_targets.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_deregistered_test_targets as g  # noqa: E402


def test_parse_registered_name_and_path():
    toml = (
        '[[test]]\n'
        'name = "migrate_cli_e2e"\n'
        'path = "tests/migrate_cli_e2e.rs"\n'
        'required-features = ["test-support"]\n'
    )
    assert g.parse_registered_targets(toml) == [("migrate_cli_e2e", "tests/migrate_cli_e2e.rs")]


def test_parse_registered_name_only_defaults_path():
    toml = '[[test]]\nname = "incident_cli_e2e"\n'
    assert g.parse_registered_targets(toml) == [("incident_cli_e2e", "tests/incident_cli_e2e.rs")]


def test_parse_registered_workspace_root_path_and_block_termination():
    toml = (
        "[package]\n"
        'name = "frankenengine-node"\n'
        "[[test]]\n"
        'name = "a"\n'
        'path = "../../tests/conformance/a.rs"\n'
        "[dependencies]\n"
        'serde = "1"\n'
        "[[test]]\n"
        'name = "b"\n'
    )
    got = g.parse_registered_targets(toml)
    assert ("a", "../../tests/conformance/a.rs") in got
    assert ("b", "tests/b.rs") in got
    assert len(got) == 2  # the [dependencies]/[package] tables must not leak in


def test_extract_includes_path_include_and_mod():
    rs = (
        '#[path = "cli_golden_helpers.rs"]\n'
        "mod helpers;\n"                       # suppressed: it follows a #[path] line
        "mod plain_child;\n"
        'include!("shared/vectors.rs");\n'
    )
    refs = g.extract_includes(rs)
    assert ("path", "cli_golden_helpers.rs") in refs
    assert ("path", "shared/vectors.rs") in refs
    assert ("mod", "plain_child") in refs
    # the `mod helpers;` right after the #[path] must NOT double-count as a mod ref
    assert ("mod", "helpers") not in refs


def test_classify_allowlist_and_flags():
    assert g.classify("canonical_serializer_fuzz_harness") == ("fuzz", False)
    assert g.classify("anti_entropy_reconciliation_loom") == ("loom", False)
    assert g.classify("migrate_throughput_bench") == ("bench", False)
    assert g.classify("trust_osv_e2e_no_mocks") == ("real-service", False)
    assert g.classify("api_session_auth_real_service_integration") == ("real-service", False)
    assert g.classify("cli_golden_helpers") == ("helper", False)
    # flagged coverage-hole categories
    assert g.classify("decision_receipt_golden_vectors_conformance") == ("conformance", True)
    assert g.classify("trust_card_field_reorder_metamorphic") == ("metamorphic", True)
    assert g.classify("migrate_audit_goldens") == ("golden", True)
    assert g.classify("doctor_policy_activation_e2e") == ("e2e", True)
    # unknown -> review, not flagged
    assert g.classify("supervision_temporal_kernel") == ("review", False)


def test_resolve_reference_variants():
    root = os.path.join(os.sep, "repo", "crates", "fn", "tests", "wrap.rs")
    assert g.resolve_reference("path", "helper.rs", root) == [
        os.path.normpath(os.path.join(os.sep, "repo", "crates", "fn", "tests", "helper.rs"))
    ]
    mod_cands = g.resolve_reference("mod", "child", root)
    assert os.path.normpath(os.path.join(os.sep, "repo", "crates", "fn", "tests", "child.rs")) in mod_cands
    assert os.path.normpath(os.path.join(os.sep, "repo", "crates", "fn", "tests", "child", "mod.rs")) in mod_cands


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_compute_reachable_transitive_closure():
    with tempfile.TemporaryDirectory() as d:
        tests = os.path.join(d, "tests")
        _write(os.path.join(tests, "root.rs"), '#[path = "helper.rs"]\nmod helper;\n')
        _write(os.path.join(tests, "helper.rs"), 'include!("deep/leaf.rs");\n')
        _write(os.path.join(tests, "deep", "leaf.rs"), "// leaf\n")
        _write(os.path.join(tests, "unrelated.rs"), "// nobody includes me\n")
        reach = g.compute_reachable([os.path.join(tests, "root.rs")])
        assert os.path.join(tests, "root.rs") in reach
        assert os.path.join(tests, "helper.rs") in reach
        assert os.path.normpath(os.path.join(tests, "deep", "leaf.rs")) in reach
        assert os.path.join(tests, "unrelated.rs") not in reach


def test_find_orphans_end_to_end():
    with tempfile.TemporaryDirectory() as repo:
        crate = os.path.join(repo, "crates", "franken-node")
        tests = os.path.join(crate, "tests")
        # Cargo.toml registers only `wrapper` (which #[path]-includes wired_conf.rs)
        _write(os.path.join(crate, "Cargo.toml"),
               '[package]\nname = "frankenengine-node"\n'
               '[[test]]\nname = "wrapper"\npath = "tests/wrapper.rs"\n')
        _write(os.path.join(tests, "wrapper.rs"), '#[path = "wired_conf.rs"]\nmod wired;\n')
        _write(os.path.join(tests, "wired_conf.rs"), "#[test] fn t() {}\n")          # reached -> not orphan
        _write(os.path.join(tests, "orphan_conformance.rs"), "#[test] fn t() {}\n")  # flagged
        _write(os.path.join(tests, "some_fuzz_harness.rs"), "fn main() {}\n")        # allowlisted
        _write(os.path.join(tests, "shared_helpers.rs"), "pub fn h() {}\n")          # helper (not flagged)

        orphans = g.find_orphans(repo, crate)
        names = {o["target"]: o for o in orphans}
        assert "wired_conf" not in names, "reached-via-#[path] file must not be an orphan"
        assert names["orphan_conformance"]["flagged"] is True
        assert names["some_fuzz_harness"]["flagged"] is False
        assert names["shared_helpers"]["flagged"] is False
        assert "wrapper" not in names, "the registered target itself is not an orphan"


def test_gate_exit_codes():
    with tempfile.TemporaryDirectory() as repo:
        crate = os.path.join(repo, "crates", "franken-node")
        tests = os.path.join(crate, "tests")
        _write(os.path.join(crate, "Cargo.toml"), '[package]\nname = "x"\n')
        _write(os.path.join(tests, "lonely_conformance.rs"), "#[test] fn t() {}\n")
        out = os.path.join(repo, "artifacts")
        # blocking mode -> nonzero because there is a flagged orphan
        rc = g.main(["--repo-root", repo, "--crate-dir", "crates/franken-node", "--out", out, "--ts", "2026-07-01T00:00:00Z"])
        assert rc == 1
        # warn-only -> zero
        rc = g.main(["--repo-root", repo, "--crate-dir", "crates/franken-node", "--out", out, "--warn-only", "--ts", "2026-07-01T00:00:00Z"])
        assert rc == 0


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"ok   {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
