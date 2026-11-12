"""Tests for scripts/check_verifier_sdk_independence.py (bd-tenx3.5 & .16)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "scripts" / "check_verifier_sdk_independence.py"

spec = importlib.util.spec_from_file_location(
    "check_verifier_sdk_independence", SCRIPT_PATH
)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_live_repo_verifier_sdk_independence_passes() -> None:
    report = mod.run_checks()
    assert report["all_passed"] is True, report
    by_name = {c["name"]: c for c in report["checks"]}
    assert by_name["cargo_toml_independence"]["passed"] is True
    assert by_name["isolated_cargo_metadata"]["passed"] is True
    assert by_name["isolated_cargo_metadata"]["own_workspace_root"] is True
    assert by_name["isolated_cargo_metadata"]["forbidden_crates_found"] == []
    assert by_name["isolated_cargo_metadata"]["resolved_crate_count"] >= 10


def test_cargo_toml_rejects_product_dependency_and_workspace_inheritance(
    tmp_path: Path,
) -> None:
    bad_dep = tmp_path / "bad_dep.toml"
    bad_dep.write_text(
        '[package]\nname = "frankenengine-verifier-sdk"\nversion = "0.1.0"\nedition = "2024"\n\n'
        '[dependencies]\nfrankenengine-node = { path = "../../crates/franken-node", optional = true }\n',
        encoding="utf-8",
    )
    res_dep = mod.check_cargo_toml_independence(bad_dep)
    assert res_dep["passed"] is False
    assert res_dep["no_product_dep"] is False

    bad_ws = tmp_path / "bad_ws.toml"
    bad_ws.write_text(
        '[package]\nname = "frankenengine-verifier-sdk"\nversion.workspace = true\nedition = "2024"\n',
        encoding="utf-8",
    )
    res_ws = mod.check_cargo_toml_independence(bad_ws)
    assert res_ws["passed"] is False
    assert res_ws["no_workspace_inheritance"] is False
