#!/usr/bin/env python3
"""Verify sibling pin lock coherence, Cargo.lock generation bounds, and main-branch CI gates."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIBLINGS_TSV = ROOT / "packaging" / "source-siblings.tsv"
DEFAULT_CARGO_LOCK = ROOT / "Cargo.lock"
DEFAULT_WORKFLOWS_DIR = ROOT / ".github" / "workflows"
DEFAULT_ACTION_YML = ROOT / ".github" / "actions" / "franken-siblings" / "action.yml"

REQUIRED_SIBLINGS = ("frankentui", "fastapi_rust", "sqlmodel_rust")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
ENGINE_REF_FLAG_RE = re.compile(r"--engine-ref\s+([^\s\\]+)")

MAX_CRATE_GENERATIONS = {
    # 0.3.x (transitive fsqlite 0.1.19), 0.5.0 (sqlmodel dev-deps only; zero normal edges),
    # 0.6.2 (converged frankenengine-node + fastapi-rust). Must never sprawl to 4+.
    "asupersync": 3,
    "fastapi-core": 1,
    "franken-kernel": 3,
    "franken-decision": 3,
    "franken-evidence": 3,
    "fsqlite-error": 1,
}

REQUIRED_MAIN_PUSH_WORKFLOWS = (
    "coverage-report.yml",
    "mutants-gate.yml",
    "perf-bead-tests.yml",
    "verification-target-compile-gate.yml",
)

ENGINE_PINNED_WORKFLOWS = (
    "mutants-gate.yml",
    "inline-lib-tests-gate.yml",
    "module-graph.yml",
    "native-egress.yml",
)


def check_siblings_tsv(siblings_tsv: Path, check_local_git: bool = True) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not siblings_tsv.is_file():
        return [{"check": "siblings_tsv_exists", "pass": False, "detail": f"missing {siblings_tsv}"}]

    rows: dict[str, str] = {}
    malformed: list[str] = []
    for lineno, raw_line in enumerate(siblings_tsv.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2 or not SHA40_RE.match(parts[1]):
            malformed.append(f"L{lineno}:{raw_line}")
            continue
        rows[parts[0]] = parts[1]

    checks.append(
        {
            "check": "siblings_tsv_well_formed",
            "pass": len(malformed) == 0,
            "detail": "all rows valid 40-hex SHAs" if not malformed else f"malformed={malformed}",
        }
    )

    for repo in REQUIRED_SIBLINGS:
        sha = rows.get(repo)
        checks.append(
            {
                "check": f"sibling_pinned:{repo}",
                "pass": sha is not None,
                "detail": sha or "MISSING",
            }
        )
        if sha and check_local_git:
            sibling_dir = siblings_tsv.parent.parent.parent / repo
            if (sibling_dir / ".git").exists():
                proc = subprocess.run(
                    ["git", "-C", str(sibling_dir), "cat-file", "-t", sha],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                is_commit = proc.returncode == 0 and proc.stdout.strip() == "commit"
                checks.append(
                    {
                        "check": f"sibling_commit_resolvable:{repo}",
                        "pass": is_commit,
                        "detail": f"{sha} ({proc.stdout.strip() or proc.stderr.strip()})",
                    }
                )
    return checks


def check_cargo_lock(cargo_lock: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not cargo_lock.is_file():
        return [{"check": "cargo_lock_exists", "pass": False, "detail": f"missing {cargo_lock}"}]

    parsed = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
    packages = parsed.get("package", [])
    versions_by_name: dict[str, set[str]] = {}
    node_deps: list[str] = []
    fastapi_http_deps: list[str] = []
    for pkg in packages:
        name = pkg.get("name")
        ver = pkg.get("version")
        if isinstance(name, str) and isinstance(ver, str):
            versions_by_name.setdefault(name, set()).add(ver)
        if name == "frankenengine-node":
            node_deps = [d for d in pkg.get("dependencies", []) if isinstance(d, str)]
        elif name == "fastapi-http" and ver == "0.5.0":
            fastapi_http_deps = [d for d in pkg.get("dependencies", []) if isinstance(d, str)]

    asupersync_versions = sorted(versions_by_name.get("asupersync", set()))
    node_asupersync = [d for d in node_deps if d == "asupersync" or d.startswith("asupersync ")]
    fastapi_asupersync = [
        d for d in fastapi_http_deps if d == "asupersync" or d.startswith("asupersync ")
    ]
    node_uses_06 = any("0.6." in d for d in node_asupersync) or (
        node_asupersync == ["asupersync"]
        and len(asupersync_versions) == 1
        and asupersync_versions[0].startswith("0.6.")
    )
    checks.append(
        {
            "check": "cargo_lock:frankenengine_node_asupersync_0_6",
            "pass": node_uses_06,
            "detail": f"node_dep={node_asupersync} all_versions={asupersync_versions}",
        }
    )

    same_asupersync_as_fastapi = bool(node_asupersync) and (
        not fastapi_asupersync or node_asupersync == fastapi_asupersync
    )
    checks.append(
        {
            "check": "cargo_lock:node_and_fastapi_share_asupersync",
            "pass": same_asupersync_as_fastapi,
            "detail": f"node={node_asupersync} fastapi_http={fastapi_asupersync}",
        }
    )

    for crate_name, max_gens in MAX_CRATE_GENERATIONS.items():
        vers = sorted(versions_by_name.get(crate_name, set()))
        checks.append(
            {
                "check": f"cargo_lock:generation_bound:{crate_name}",
                "pass": 1 <= len(vers) <= max_gens,
                "detail": f"count={len(vers)} max={max_gens} versions={vers}",
            }
        )
    return checks


def check_workflows(workflows_dir: Path) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for wf_name in REQUIRED_MAIN_PUSH_WORKFLOWS:
        wf_path = workflows_dir / wf_name
        if not wf_path.is_file():
            checks.append({"check": f"workflow_exists:{wf_name}", "pass": False, "detail": "MISSING"})
            continue

        raw = wf_path.read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            checks.append(
                {
                    "check": f"workflow_yaml_valid:{wf_name}",
                    "pass": False,
                    "detail": str(exc),
                }
            )
            continue
        # PyYAML 1.1 parses bare `on:` as boolean True.
        triggers = data.get("on") if isinstance(data, dict) and "on" in data else data.get(True, {})
        push_cfg = triggers.get("push") if isinstance(triggers, dict) else None
        branches = push_cfg.get("branches", []) if isinstance(push_cfg, dict) else []
        has_main_push = "main" in branches
        checks.append(
            {
                "check": f"workflow_main_push_trigger:{wf_name}",
                "pass": has_main_push,
                "detail": f"push.branches={branches}",
            }
        )

        if wf_name == "coverage-report.yml":
            steps = (
                data.get("jobs", {})
                .get("coverage-report", {})
                .get("steps", [])
            )
            uses_siblings = any(
                isinstance(s, dict)
                and s.get("uses") == "./.github/actions/franken-siblings"
                for s in steps
            )
            gen_steps = [
                s.get("run", "")
                for s in steps
                if isinstance(s, dict) and "llvm-cov" in str(s.get("run", ""))
            ]
            gen_script = "\n".join(gen_steps).strip()
            unconditional_exit_zero = bool(
                re.search(r"(?:^|\n)\s*exit\s+0\s*$", gen_script)
            )
            checks.append(
                {
                    "check": "coverage_report:uses_franken_siblings",
                    "pass": uses_siblings,
                    "detail": "uses ./.github/actions/franken-siblings"
                    if uses_siblings
                    else "missing franken-siblings step",
                }
            )
            checks.append(
                {
                    "check": "coverage_report:no_exit_zero_masking",
                    "pass": bool(gen_script) and not unconditional_exit_zero,
                    "detail": "fails closed on nonzero status or empty lcov"
                    if (gen_script and not unconditional_exit_zero)
                    else "masked by trailing exit 0",
                }
            )

        if wf_name == "verification-target-compile-gate.yml":
            env_map = data.get("env", {}) if isinstance(data, dict) else {}
            blocking_val = str(env_map.get("BLOCKING", ""))
            steps = (
                data.get("jobs", {})
                .get("compile-census", {})
                .get("steps", [])
            )
            uses_siblings = any(
                isinstance(s, dict)
                and s.get("uses") == "./.github/actions/franken-siblings"
                for s in steps
            )
            checks.append(
                {
                    "check": "verification_target_compile_gate:blocking_enabled",
                    "pass": blocking_val == "1",
                    "detail": f"BLOCKING={blocking_val!r}",
                }
            )
            checks.append(
                {
                    "check": "verification_target_compile_gate:uses_franken_siblings",
                    "pass": uses_siblings,
                    "detail": "uses ./.github/actions/franken-siblings"
                    if uses_siblings
                    else "missing franken-siblings step",
                }
            )

    return checks


def _extract_engine_refs(path: Path) -> list[str]:
    if not path.is_file():
        return []
    raw = path.read_text(encoding="utf-8")
    refs = [m.group(1) for m in ENGINE_REF_FLAG_RE.finditer(raw) if not m.group(1).startswith("$")]
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        data = None
    if isinstance(data, dict):
        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    with_cfg = step.get("with", {})
                    if (
                        isinstance(with_cfg, dict)
                        and with_cfg.get("repository") == "Dicklesworthstone/franken_engine"
                    ):
                        ref = str(with_cfg.get("ref", "")).strip()
                        if ref:
                            refs.append(ref)
    return refs


def check_engine_pin_coherence(
    workflows_dir: Path,
    action_yml: Path = DEFAULT_ACTION_YML,
    check_local_git: bool = True,
) -> tuple[list[dict[str, Any]], str | None]:
    checks: list[dict[str, Any]] = []
    action_refs = _extract_engine_refs(action_yml)
    canonical_ref = action_refs[0] if len(action_refs) == 1 and SHA40_RE.match(action_refs[0]) else None
    checks.append(
        {
            "check": "engine_pin:franken_siblings_action_sha40",
            "pass": canonical_ref is not None,
            "detail": f"refs={action_refs}",
        }
    )

    for wf_name in ENGINE_PINNED_WORKFLOWS:
        wf_path = workflows_dir / wf_name
        if not wf_path.is_file():
            continue
        wf_refs = _extract_engine_refs(wf_path)
        coherent = (
            bool(wf_refs)
            and canonical_ref is not None
            and all(r == canonical_ref and SHA40_RE.match(r) for r in wf_refs)
        )
        checks.append(
            {
                "check": f"engine_pin:workflow_matches_action:{wf_name}",
                "pass": coherent,
                "detail": f"refs={wf_refs} expected={canonical_ref}",
            }
        )

    if canonical_ref and check_local_git:
        engine_dir = action_yml.parent.parent.parent.parent.parent / "franken_engine"
        if (engine_dir / ".git").exists():
            proc = subprocess.run(
                ["git", "-C", str(engine_dir), "cat-file", "-t", canonical_ref],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            is_commit = proc.returncode == 0 and proc.stdout.strip() == "commit"
            checks.append(
                {
                    "check": "sibling_commit_resolvable:franken_engine",
                    "pass": is_commit,
                    "detail": f"{canonical_ref} ({proc.stdout.strip() or proc.stderr.strip()})",
                }
            )

    return checks, canonical_ref


def run_checks(
    siblings_tsv: Path = DEFAULT_SIBLINGS_TSV,
    cargo_lock: Path = DEFAULT_CARGO_LOCK,
    workflows_dir: Path = DEFAULT_WORKFLOWS_DIR,
    action_yml: Path = DEFAULT_ACTION_YML,
    check_local_git: bool = True,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    checks.extend(check_siblings_tsv(siblings_tsv, check_local_git=check_local_git))
    checks.extend(check_cargo_lock(cargo_lock))
    checks.extend(check_workflows(workflows_dir))
    engine_checks, canonical_engine_ref = check_engine_pin_coherence(
        workflows_dir=workflows_dir,
        action_yml=action_yml,
        check_local_git=check_local_git,
    )
    checks.extend(engine_checks)

    repo_pins: dict[str, str] = {}
    if siblings_tsv.is_file():
        for raw_line in siblings_tsv.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) == 2 and SHA40_RE.match(parts[1]):
                repo_pins[parts[0]] = parts[1]
    if canonical_engine_ref:
        repo_pins["franken_engine"] = canonical_engine_ref

    duplicate_crates: dict[str, list[str]] = {}
    if cargo_lock.is_file():
        parsed = tomllib.loads(cargo_lock.read_text(encoding="utf-8"))
        versions_by_name: dict[str, set[str]] = {}
        for pkg in parsed.get("package", []):
            name = pkg.get("name")
            ver = pkg.get("version")
            if isinstance(name, str) and isinstance(ver, str):
                versions_by_name.setdefault(name, set()).add(ver)
        for crate_name in sorted(MAX_CRATE_GENERATIONS):
            vers = sorted(versions_by_name.get(crate_name, set()))
            if len(vers) > 1:
                duplicate_crates[crate_name] = vers

    passing = sum(1 for c in checks if c["pass"])
    failing = len(checks) - passing
    overall = failing == 0 and len(checks) > 0
    first_failed = next((c["check"] for c in checks if not c["pass"]), None)
    return {
        "schema_version": "franken-node/sibling-lock-coherence/v1",
        "bead_id": "bd-reality-20260923-26n9r.32",
        "gate": "sibling_lock_coherence",
        "overall_pass": overall,
        "verdict": "PASS" if overall else "FAIL",
        "locked_metadata_status": "coherent" if overall else "drift_detected",
        "failure_code": None if overall else f"ERR_SIBLING_LOCK_COHERENCE:{first_failed}",
        "repo_pins": repo_pins,
        "duplicate_crates": duplicate_crates,
        "summary": {
            "passing": passing,
            "failing": failing,
            "total": len(checks),
        },
        "checks": checks,
    }


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    report = run_checks()
    return report["overall_pass"], report["checks"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--siblings-tsv", type=Path, default=DEFAULT_SIBLINGS_TSV)
    parser.add_argument("--cargo-lock", type=Path, default=DEFAULT_CARGO_LOCK)
    parser.add_argument("--workflows-dir", type=Path, default=DEFAULT_WORKFLOWS_DIR)
    parser.add_argument("--no-local-git", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument("--self-test", action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.self_test:
        ok, checks = self_test()
        payload = {
            "self_test_passed": ok,
            "checks_total": len(checks),
            "checks_passing": sum(1 for c in checks if c["pass"]),
            "checks_failing": sum(1 for c in checks if not c["pass"]),
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("PASS" if ok else "FAIL")
        return 0 if ok else 1

    report = run_checks(
        siblings_tsv=args.siblings_tsv,
        cargo_lock=args.cargo_lock,
        workflows_dir=args.workflows_dir,
        check_local_git=not args.no_local_git,
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"sibling_lock_coherence: {report['verdict']} "
            f"({report['summary']['passing']}/{report['summary']['total']})"
        )
        for check in report["checks"]:
            if not check["pass"]:
                print(f"  [FAIL] {check['check']}: {check['detail']}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
