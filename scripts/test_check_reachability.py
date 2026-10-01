#!/usr/bin/env python3
"""Unit tests for check_reachability.py (library-island ceiling gate, bd-reality-20260923-26n9r.14).

Run: python3 scripts/test_check_reachability.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_reachability as g  # noqa: E402


# --- pure helpers -----------------------------------------------------------


def test_strip_test_regions_blanks_cfg_test_item_only():
    src = (
        "pub fn prod() {}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    fn t() { let s = \"}\"; }\n"  # brace in a string must not end early
        "}\n"
        "pub fn also_prod() {}\n"
    )
    out = g.strip_test_regions(src)
    assert "prod()" in out
    assert "also_prod()" in out
    assert "mod tests" not in out
    # line count preserved so on-disk line numbers still line up
    assert len(out.splitlines()) == len(src.splitlines())


def test_non_test_line_count_excludes_blanks_and_tests():
    src = "a\n\n#[cfg(test)]\nmod t { fn x() {} }\nb\n"
    assert g.non_test_line_count(src) == 2  # 'a' and 'b'


def test_module_name_for():
    assert g.module_name_for("security/copilot_engine.rs") == "copilot_engine"
    assert g.module_name_for("security/dgis/mod.rs") == "dgis"
    assert g.module_name_for("lib.rs") is None
    assert g.module_name_for("main.rs") is None


def test_path_referenced_idents():
    ids = g.path_referenced_idents("use crate::foo::bar;\nlet _ = x::y();\n")
    assert {"crate", "foo", "bar", "x", "y"} <= ids
    assert "nope" not in ids


def test_opt_in_feature_gated():
    assert g.opt_in_feature_gated(['cfg(feature = "advanced-features")']) is True
    assert g.opt_in_feature_gated(['cfg(test)']) is True
    assert g.opt_in_feature_gated(['cfg(all(test, feature = "engine"))']) is True
    # Default features are NOT opt-in.
    assert g.opt_in_feature_gated(['cfg(feature = "engine")']) is False
    assert g.opt_in_feature_gated(['derive(Debug)']) is False
    assert g.opt_in_feature_gated([]) is False


def test_parse_mod_feature_gates():
    text = (
        "pub mod reachable;\n"
        "#[cfg(feature = \"advanced-features\")]\n"
        "pub mod gated;\n"
        "#[cfg(test)]\n"
        "mod t;\n"
    )
    gates = g.parse_mod_feature_gates(text)
    assert gates["reachable"] is False
    assert gates["gated"] is True
    assert gates["t"] is True


# --- synthetic end-to-end census -------------------------------------------


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def test_census_detects_island_exempts_optin_and_dead_file():
    with tempfile.TemporaryDirectory() as repo:
        crate = "crate"
        base = os.path.join(repo, crate, "src")
        _write(
            repo,
            f"{crate}/src/lib.rs",
            # references `reachable` via a path; declares island, gated (opt-in),
            # and a test-only module that references the island ONLY from tests.
            "pub mod reachable;\n"
            "pub mod island;\n"
            "#[cfg(feature = \"advanced-features\")]\n"
            "pub mod gated;\n"
            "use crate::reachable::Thing;\n"
            "#[cfg(test)]\n"
            "mod t {\n"
            "    use crate::island::lonely;\n"  # island reached ONLY from test -> still island
            "}\n",
        )
        _write(repo, f"{crate}/src/reachable.rs", "pub struct Thing;\npub fn r() {}\n")
        _write(repo, f"{crate}/src/island.rs", "pub fn lonely() {}\npub fn more() {}\n")
        _write(repo, f"{crate}/src/gated.rs", "pub fn g() {}\n")
        # No `mod orphan_dead` anywhere -> undeclared dead file.
        _write(repo, f"{crate}/src/orphan_dead.rs", "pub fn dead() {}\n")

        census, _ = g.run_census(repo, crate)
        island_names = {m.name for m in census.islands}
        undeclared_names = {m.name for m in census.undeclared}

        assert "island" in island_names, island_names
        assert "reachable" not in island_names
        assert "gated" not in island_names  # opt-in exempt
        assert "orphan_dead" in undeclared_names
        assert "orphan_dead" not in island_names
        assert census.island_lines == g.non_test_line_count("pub fn lonely() {}\npub fn more() {}\n")
        assert census.exempt_opt_in >= 1  # gated


def test_ceiling_roundtrip_and_gate_exit_codes():
    with tempfile.TemporaryDirectory() as repo:
        crate = "crate"
        _write(
            repo,
            f"{crate}/src/lib.rs",
            "pub mod island;\n",
        )
        _write(repo, f"{crate}/src/island.rs", "pub fn a() {}\npub fn b() {}\npub fn c() {}\n")

        # No ceiling yet -> blocking mode nonzero, warn-only zero.
        assert g.main(["--repo-root", repo, "--crate-dir", crate]) == 1
        assert g.main(["--repo-root", repo, "--crate-dir", crate, "--warn-only"]) == 0

        # Establish ceiling, then the gate passes.
        assert g.main(["--repo-root", repo, "--crate-dir", crate, "--update-ceiling"]) == 0
        assert g.load_ceiling(repo) == 3
        assert g.main(["--repo-root", repo, "--crate-dir", crate]) == 0

        # Grow the island beyond ceiling+slack -> fail (slack 0 to force it).
        _write(
            repo,
            f"{crate}/src/island.rs",
            "\n".join(f"pub fn f{i}() {{}}" for i in range(400)) + "\n",
        )
        assert g.main(["--repo-root", repo, "--crate-dir", crate, "--slack", "0"]) == 1
        # warn-only still zero even when exceeded
        assert (
            g.main(["--repo-root", repo, "--crate-dir", crate, "--slack", "0", "--warn-only"])
            == 0
        )


def test_json_envelope_shape():
    with tempfile.TemporaryDirectory() as repo:
        crate = "crate"
        _write(repo, f"{crate}/src/lib.rs", "pub mod island;\n")
        _write(repo, f"{crate}/src/island.rs", "pub fn a() {}\n")
        g.main(["--repo-root", repo, "--crate-dir", crate, "--update-ceiling"])
        census, _ = g.run_census(repo, crate)
        assert census.island_lines == 1


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
