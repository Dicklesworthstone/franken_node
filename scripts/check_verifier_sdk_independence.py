#!/usr/bin/env python3
"""Verification script for bd-tenx3.5 & bd-reality-20260923-26n9r.16: Verifier SDK Independence.

Verifies that:
1. sdk/verifier/Cargo.toml parses cleanly via tomllib with zero workspace inheritance
   (`workspace = true` forbidden) and zero dependencies on any franken-node/franken-engine
   product crate across dependencies, dev-dependencies, build-dependencies, and features.
2. Staging sdk/verifier/ plus committed recompute evidence into a clean temporary directory
   with NO root Cargo.toml and NO crates/ directory resolves cleanly via
   `cargo metadata --manifest-path <staged>/sdk/verifier/Cargo.toml --format-version 1 --offline`
   as its own standalone workspace root with zero forbidden product/engine crates in the
   resolved dependency graph.
3. Independent conformance test lane (sdk/verifier/tests/independent_conformance.rs) and
   standalone CI workflow (.github/workflows/verifier-sdk-standalone.yml) are intact.
4. README.md and docs/CLAIMS_REGISTRY.md (CLAIM-011) document standalone SDK verification
   (unless --sparse-checkout is explicitly passed inside the sparse CI checkout).
5. Emits structured evidence at artifacts/verifier/sdk_independence_evidence.json.

Usage:
    python3 scripts/check_verifier_sdk_independence.py
    python3 scripts/check_verifier_sdk_independence.py --json
    python3 scripts/check_verifier_sdk_independence.py --sparse-checkout
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SDK_DIR = ROOT / "sdk" / "verifier"
SDK_CARGO_TOML = SDK_DIR / "Cargo.toml"
INDEPENDENT_TEST_FILE = SDK_DIR / "tests" / "independent_conformance.rs"
STANDALONE_WORKFLOW_FILE = ROOT / ".github" / "workflows" / "verifier-sdk-standalone.yml"
CLAIMS_REGISTRY_FILE = ROOT / "docs" / "CLAIMS_REGISTRY.md"
README_FILE = ROOT / "README.md"
EVIDENCE_PATH = ROOT / "artifacts" / "verifier" / "sdk_independence_evidence.json"

FORBIDDEN_CRATES = frozenset(
    {
        "frankenengine-node",
        "franken-security-macros",
        "frankenengine-engine",
        "frankenengine-extension-host",
    }
)


def _find_workspace_inheritance(node: object, prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if k == "workspace" and v is True:
                hits.append(path)
            else:
                hits.extend(_find_workspace_inheritance(v, path))
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            hits.extend(_find_workspace_inheritance(item, f"{prefix}[{idx}]"))
    return hits


def check_cargo_toml_independence(cargo_toml_path: Path = SDK_CARGO_TOML) -> dict:
    if not cargo_toml_path.is_file():
        return {
            "name": "cargo_toml_independence",
            "passed": False,
            "detail": f"Missing {cargo_toml_path}",
        }

    raw = cargo_toml_path.read_text(encoding="utf-8")
    try:
        manifest = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        return {
            "name": "cargo_toml_independence",
            "passed": False,
            "detail": f"Invalid TOML in {cargo_toml_path}: {exc}",
        }

    workspace_inheritance = _find_workspace_inheritance(manifest)
    forbidden_refs: list[str] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        deps = manifest.get(section, {})
        if isinstance(deps, dict):
            for dep_name, spec in deps.items():
                pkg_name = (
                    spec.get("package", dep_name)
                    if isinstance(spec, dict)
                    else dep_name
                )
                if dep_name in FORBIDDEN_CRATES or pkg_name in FORBIDDEN_CRATES:
                    forbidden_refs.append(f"{section}.{dep_name}")

    features = manifest.get("features", {})
    if isinstance(features, dict):
        for feat_name, items in features.items():
            if isinstance(items, list):
                for item in items:
                    token = str(item).split("/")[0].removeprefix("dep:")
                    if token in FORBIDDEN_CRATES:
                        forbidden_refs.append(f"features.{feat_name}:{item}")

    passed = not workspace_inheritance and not forbidden_refs
    if passed:
        detail = (
            "sdk/verifier/Cargo.toml is TOML-verified standalone: zero workspace inheritance "
            "and zero product/engine crate references"
        )
    else:
        detail = (
            f"TOML independence violation: workspace_inheritance={workspace_inheritance}, "
            f"forbidden_refs={forbidden_refs}"
        )
    return {
        "name": "cargo_toml_independence",
        "passed": passed,
        "detail": detail,
        "no_product_dep": not forbidden_refs,
        "no_workspace_inheritance": not workspace_inheritance,
    }


def stage_standalone_sdk_tree(dest_root: Path, repo_root: Path = ROOT) -> Path:
    """Copy ONLY the sparse-checkoutverifier SDK files into dest_root (no root Cargo.toml, no crates/)."""
    staged_sdk = dest_root / "sdk" / "verifier"
    shutil.copytree(
        repo_root / "sdk" / "verifier",
        staged_sdk,
        ignore=shutil.ignore_patterns("target"),
    )
    for rel_dir in ("artifacts/migration",):
        src_dir = repo_root / rel_dir
        if src_dir.is_dir():
            shutil.copytree(src_dir, dest_root / rel_dir)
    for rel_file in (
        "docs/honesty_manifest.json",
        "docs/honesty_manifest_evidence.json",
        "LICENSE",
    ):
        src_file = repo_root / rel_file
        if src_file.is_file():
            target = dest_root / rel_file
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, target)

    # Seed Cargo.lock inside staged sdk/verifier if root Cargo.lock exists so offline
    # dependency resolution uses pinned versions without touching network or root Cargo.toml.
    root_lock = repo_root / "Cargo.lock"
    sdk_lock = staged_sdk / "Cargo.lock"
    if root_lock.is_file() and not sdk_lock.exists():
        shutil.copy2(root_lock, sdk_lock)

    return staged_sdk


def check_isolated_cargo_metadata(repo_root: Path = ROOT) -> dict:
    sdk_dir = repo_root / "sdk" / "verifier"
    if not (sdk_dir / "Cargo.toml").is_file():
        return {
            "name": "isolated_cargo_metadata",
            "passed": False,
            "detail": f"Missing {sdk_dir / 'Cargo.toml'}",
        }

    with tempfile.TemporaryDirectory(prefix="verifier-sdk-standalone-") as tmp:
        tmp_root = Path(tmp)
        staged_sdk = stage_standalone_sdk_tree(tmp_root, repo_root=repo_root)

        if (tmp_root / "Cargo.toml").exists() or (tmp_root / "crates").exists():
            return {
                "name": "isolated_cargo_metadata",
                "passed": False,
                "detail": "Staging invariant violated: root Cargo.toml or crates/ present",
            }

        cmd = [
            "cargo",
            "metadata",
            "--manifest-path",
            str(staged_sdk / "Cargo.toml"),
            "--format-version",
            "1",
            "--offline",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return {
                "name": "isolated_cargo_metadata",
                "passed": False,
                "detail": f"Standalone cargo metadata failed (rc={proc.returncode}): {proc.stderr.strip()[:400]}",
            }

        meta = json.loads(proc.stdout)
        ws_root = Path(meta.get("workspace_root", "")).resolve()
        expected_ws_root = staged_sdk.resolve()
        own_workspace_root = ws_root == expected_ws_root

        resolved_names = sorted({pkg["name"] for pkg in meta.get("packages", [])})
        forbidden_found = sorted(FORBIDDEN_CRATES.intersection(resolved_names))

        passed = own_workspace_root and not forbidden_found
        detail = (
            f"Standalone sparse tree resolved {len(resolved_names)} crates under isolated "
            f"workspace_root with 0 franken-node/franken-engine dependencies"
            if passed
            else (
                f"Isolated metadata failure: own_workspace_root={own_workspace_root} "
                f"({ws_root} vs {expected_ws_root}), forbidden_found={forbidden_found}"
            )
        )
        return {
            "name": "isolated_cargo_metadata",
            "passed": passed,
            "detail": detail,
            "own_workspace_root": own_workspace_root,
            "resolved_crate_count": len(resolved_names),
            "resolved_crates": resolved_names,
            "forbidden_crates_found": forbidden_found,
        }


def check_independent_test_suite() -> dict:
    if not INDEPENDENT_TEST_FILE.is_file():
        return {
            "name": "independent_test_suite",
            "passed": False,
            "detail": f"Missing {INDEPENDENT_TEST_FILE}",
        }

    content = INDEPENDENT_TEST_FILE.read_text(encoding="utf-8")

    checks = [
        ("signature_verification", "independent_sdk_verifies_valid_signature"),
        ("payload_tampering", "independent_sdk_detects_payload_tampering"),
        ("signature_corruption", "independent_sdk_detects_signature_corruption"),
        ("wrong_key_rejection", "independent_sdk_rejects_wrong_key"),
        ("schema_rejection", "independent_sdk_rejects_unknown_schema_version"),
        (
            "counterfactual_fail_closed",
            "independent_sdk_verifies_counterfactual_receipt_pass_and_fail_closed",
        ),
    ]

    missing = [name for name, symbol in checks if symbol not in content]
    passed = len(missing) == 0
    detail = (
        "Independent conformance tests cover signatures, tampering, schemas, and counterfactuals"
        if passed
        else f"Missing independent test cases: {missing}"
    )
    return {
        "name": "independent_test_suite",
        "passed": passed,
        "detail": detail,
        "tested_capabilities": [c[0] for c in checks],
    }


def check_standalone_ci_workflow(sparse_checkout: bool = False) -> dict:
    if sparse_checkout and not STANDALONE_WORKFLOW_FILE.is_file():
        return {
            "name": "standalone_ci_workflow",
            "passed": True,
            "detail": "Skipped workflow file inspection inside sparse checkout",
        }
    if not STANDALONE_WORKFLOW_FILE.is_file():
        return {
            "name": "standalone_ci_workflow",
            "passed": False,
            "detail": f"Missing {STANDALONE_WORKFLOW_FILE}",
        }
    text = STANDALONE_WORKFLOW_FILE.read_text(encoding="utf-8")
    required = [
        "sparse-checkout:",
        "test ! -e Cargo.toml",
        "test ! -e crates",
        "cargo tree --manifest-path sdk/verifier/Cargo.toml",
        "cargo test --manifest-path sdk/verifier/Cargo.toml --all-features",
    ]
    missing = [token for token in required if token not in text]
    passed = not missing
    return {
        "name": "standalone_ci_workflow",
        "passed": passed,
        "detail": (
            "verifier-sdk-standalone.yml enforces sparse checkout, absent workspace/crates, "
            "dependency-tree exclusion, and --all-features test execution"
            if passed
            else f"verifier-sdk-standalone.yml missing required clauses: {missing}"
        ),
    }


def check_documentation_alignment(sparse_checkout: bool = False) -> dict:
    if sparse_checkout and (
        not CLAIMS_REGISTRY_FILE.is_file() or not README_FILE.is_file()
    ):
        return {
            "name": "documentation_alignment",
            "passed": True,
            "detail": "Skipped full-repo README/CLAIMS_REGISTRY check inside sparse checkout",
        }
    if not CLAIMS_REGISTRY_FILE.is_file() or not README_FILE.is_file():
        return {
            "name": "documentation_alignment",
            "passed": False,
            "detail": "Missing README.md or docs/CLAIMS_REGISTRY.md",
        }

    claims_text = CLAIMS_REGISTRY_FILE.read_text(encoding="utf-8")
    readme_text = README_FILE.read_text(encoding="utf-8")

    has_claim_11 = "CLAIM-011" in claims_text and "verifier-sdk-standalone.yml" in claims_text
    has_verifier_section = "Verifier SDK" in readme_text

    passed = has_claim_11 and has_verifier_section
    return {
        "name": "documentation_alignment",
        "passed": passed,
        "detail": (
            "CLAIM-011 (referencing verifier-sdk-standalone.yml) and Verifier SDK documentation present"
            if passed
            else "Missing CLAIM-011 standalone reference or Verifier SDK section"
        ),
    }


def run_checks(sparse_checkout: bool = False) -> dict:
    results = [
        check_cargo_toml_independence(),
        check_isolated_cargo_metadata(),
        check_independent_test_suite(),
        check_standalone_ci_workflow(sparse_checkout=sparse_checkout),
        check_documentation_alignment(sparse_checkout=sparse_checkout),
    ]
    all_passed = all(r["passed"] for r in results)

    return {
        "schema_version": "franken-node/verifier-sdk-independence-evidence/v2",
        "bead_id": "bd-tenx3.5",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "all_passed": all_passed,
        "verdict": "PASS" if all_passed else "FAIL",
        "checks": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Verifier SDK Independence (bd-tenx3.5)")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--sparse-checkout",
        action="store_true",
        help="Allow running inside verifier-sdk-standalone.yml sparse checkout",
    )
    parser.add_argument(
        "--no-write-evidence",
        action="store_true",
        help="Do not write artifacts/verifier/sdk_independence_evidence.json",
    )
    args = parser.parse_args()

    report = run_checks(sparse_checkout=args.sparse_checkout)

    if not args.no_write_evidence and not args.sparse_checkout:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report["all_passed"] else "FAIL"
        print(f"Verifier SDK Independence Gate: {status}")
        for c in report["checks"]:
            mark = "✓" if c["passed"] else "✗"
            print(f"  {mark} {c['name']}: {c['detail']}")

    sys.exit(0 if report["all_passed"] else 1)


if __name__ == "__main__":
    main()
