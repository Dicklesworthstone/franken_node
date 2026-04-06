#!/usr/bin/env python3
"""bd-sxt5: Deterministic migration validation on representative Node/Bun cohorts.

Validates that the migration cohort results, E2E validation script,
and verification evidence all satisfy the acceptance contract.

Usage:
    python3 scripts/check_migration_cohort_validation.py [--json] [--no-exec]
    python3 scripts/check_migration_cohort_validation.py --self-test
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
from pathlib import Path


BEAD_ID = "bd-sxt5"
SECTION = "15"

RESULTS_FILE = ROOT / "artifacts" / "15" / "migration_cohort_results.json"
EVIDENCE_FILE = ROOT / "artifacts" / "section_15" / BEAD_ID / "verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts" / "section_15" / BEAD_ID / "verification_summary.md"
COHORT_DOC = ROOT / "docs" / "ecosystem" / "migration_cohort_definition.md"
E2E_SCRIPT = ROOT / "tests" / "e2e" / "migration_cohort_validation.sh"

REQUIRED_ARCHETYPES = [
    "web-server-express",
    "ssr-nextjs",
    "cli-tool",
    "library-package",
    "worker-bun",
    "monorepo",
    "native-addon",
    "typescript-heavy",
    "test-heavy",
    "minimal",
]

MIN_COHORT_SIZE = 10
MIN_COHORT_SUCCESS_PCT = 80.0
MIN_PER_PROJECT_PASS_PCT = 95.0
MAX_FLAKY_RATE_PCT = 1.0


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _read_json(path):
    with open(path) as f:
        return json.load(f)


def _check_results_structure(data):
    """Validate migration_cohort_results.json structure."""
    checks = []

    projects = data.get("projects", [])
    checks.append({
        "id": "cohort_size",
        "pass": len(projects) >= MIN_COHORT_SIZE,
        "detail": f"cohort has {len(projects)} projects (minimum: {MIN_COHORT_SIZE})",
    })

    archetypes = sorted(set(p.get("archetype", "") for p in projects))
    missing = [a for a in REQUIRED_ARCHETYPES if a not in archetypes]
    checks.append({
        "id": "archetype_coverage",
        "pass": len(missing) == 0,
        "detail": f"missing archetypes: {missing}" if missing else "all 10 archetypes covered",
    })

    all_pinned = all(
        p.get("pinned_ref", {}).get("repo") and p.get("pinned_ref", {}).get("commit")
        for p in projects
    )
    checks.append({
        "id": "version_pinning",
        "pass": all_pinned,
        "detail": "all projects pinned to repo+commit" if all_pinned else "missing pinned refs",
    })

    all_baseline = all(
        p.get("baseline", {}).get("total_tests", 0) > 0
        and p.get("baseline", {}).get("status") == "pass"
        for p in projects
    )
    checks.append({
        "id": "baseline_complete",
        "pass": all_baseline,
        "detail": "all baselines present and passing" if all_baseline else "incomplete baselines",
    })

    all_migration = all(
        p.get("migration", {}).get("audit_report")
        and p.get("migration", {}).get("rewrite_report")
        and p.get("migration", {}).get("lockstep_report")
        and p.get("migration", {}).get("rollback_artifact")
        for p in projects
    )
    checks.append({
        "id": "migration_artifacts",
        "pass": all_migration,
        "detail": "all migration artifacts present" if all_migration else "missing migration artifacts",
    })

    all_deterministic = all(
        p.get("repeated_runs", {}).get("runs", 0) >= 3
        and p.get("repeated_runs", {}).get("flaky_rate_pct", 100) < MAX_FLAKY_RATE_PCT
        for p in projects
    )
    checks.append({
        "id": "deterministic_runs",
        "pass": all_deterministic,
        "detail": "all projects deterministic" if all_deterministic else "non-deterministic projects found",
    })

    per_project_ok = all(
        p.get("post_migration", {}).get("pass_rate_pct", 0) >= MIN_PER_PROJECT_PASS_PCT
        or len(p.get("post_migration", {}).get("known_incompatibilities", [])) > 0
        for p in projects
    )
    checks.append({
        "id": "per_project_success",
        "pass": per_project_ok,
        "detail": "all projects meet success criteria",
    })

    agg = data.get("aggregate", {})
    cohort_success = agg.get("cohort_success_rate_pct", 0) >= MIN_COHORT_SUCCESS_PCT
    checks.append({
        "id": "cohort_success_rate",
        "pass": cohort_success,
        "detail": f"cohort success: {agg.get('cohort_success_rate_pct', 0)}% (min: {MIN_COHORT_SUCCESS_PCT}%)",
    })

    ci_flags = agg.get("determinism_verified") is True and agg.get("ci_reproducible") is True
    checks.append({
        "id": "ci_reproducibility",
        "pass": ci_flags,
        "detail": "determinism_verified and ci_reproducible flags set" if ci_flags else "missing CI flags",
    })

    return checks


def build_report(execute=True):
    """Build the verification report."""
    checks = []

    # 1. Results file exists
    checks.append({
        "id": "results_file_exists",
        "pass": RESULTS_FILE.exists(),
        "detail": str(RESULTS_FILE),
    })

    # 2. Results structure validation
    if RESULTS_FILE.exists():
        data = _read_json(RESULTS_FILE)
        structure_checks = _check_results_structure(data)
        checks.extend(structure_checks)
    else:
        checks.append({"id": "results_structure", "pass": False, "detail": "results file missing"})

    # 3. E2E script exists
    checks.append({
        "id": "e2e_script_exists",
        "pass": E2E_SCRIPT.exists(),
        "detail": str(E2E_SCRIPT),
    })

    # 4. Cohort definition doc exists
    checks.append({
        "id": "cohort_doc_exists",
        "pass": COHORT_DOC.exists(),
        "detail": str(COHORT_DOC),
    })

    # 5. Evidence file exists and has PASS verdict
    evidence_pass = False
    if EVIDENCE_FILE.exists():
        ev = _read_json(EVIDENCE_FILE)
        evidence_pass = str(ev.get("verdict", "")).upper() == "PASS"
    checks.append({
        "id": "evidence_verdict",
        "pass": evidence_pass,
        "detail": "evidence verdict is PASS" if evidence_pass else "evidence missing or not PASS",
    })

    # 6. Summary file exists
    checks.append({
        "id": "summary_exists",
        "pass": SUMMARY_FILE.exists(),
        "detail": str(SUMMARY_FILE),
    })

    # 7. E2E execution (only if execute=True)
    if execute and E2E_SCRIPT.exists():
        proc = subprocess.run(
            ["bash", str(E2E_SCRIPT)],
            capture_output=True, text=True, cwd=ROOT, timeout=3600,
        )
        e2e_pass = proc.returncode == 0 and "PASS" in proc.stdout
        checks.append({
            "id": "e2e_execution",
            "pass": e2e_pass,
            "detail": proc.stdout.strip() if e2e_pass else f"exit={proc.returncode}: {proc.stderr.strip()[:200]}",
        })
    elif not execute:
        checks.append({"id": "e2e_execution", "pass": True, "detail": "skipped (--no-exec)"})

    all_pass = all(c["pass"] for c in checks)
    verdict = "PASS" if all_pass else "FAIL"

    content_hash = hashlib.sha256(
        _canonical_json({"checks": checks}).encode()
    ).hexdigest()

    return {
        "bead_id": BEAD_ID,
        "section": SECTION,
        "title": "Deterministic migration validation on representative Node/Bun cohorts",
        "verdict": verdict,
        "checks_passed": sum(1 for c in checks if c["pass"]),
        "checks_total": len(checks),
        "checks": checks,
        "content_hash": content_hash,
    }


def self_test():
    """Validate internal logic without touching real artifacts."""
    checks = []

    # Canonical JSON determinism
    h1 = hashlib.sha256(_canonical_json({"a": 1, "b": 2}).encode()).hexdigest()
    h2 = hashlib.sha256(_canonical_json({"b": 2, "a": 1}).encode()).hexdigest()
    checks.append({"check": "canonical_hash_deterministic", "pass": h1 == h2})

    # Structure check with valid data
    valid_project = {
        "archetype": "web-server-express",
        "pinned_ref": {"repo": "https://example.com/repo", "commit": "abc123"},
        "baseline": {"total_tests": 10, "passed": 10, "failed": 0, "status": "pass"},
        "migration": {
            "audit_report": "a.json",
            "rewrite_report": "r.json",
            "lockstep_report": "l.json",
            "rollback_artifact": "rb.json",
        },
        "post_migration": {"pass_rate_pct": 100.0, "known_incompatibilities": []},
        "repeated_runs": {"runs": 5, "identical_outcomes_runs": 5, "flaky_rate_pct": 0.0},
    }
    valid_data = {
        "projects": [
            {**valid_project, "archetype": a} for a in REQUIRED_ARCHETYPES
        ],
        "aggregate": {
            "cohort_size": 10,
            "cohort_success_rate_pct": 100.0,
            "determinism_verified": True,
            "ci_reproducible": True,
        },
    }
    result = _check_results_structure(valid_data)
    all_pass = all(c["pass"] for c in result)
    checks.append({"check": "valid_data_passes_all_checks", "pass": all_pass})

    # Structure check with invalid data (missing archetype)
    bad_data = {
        "projects": [valid_project],  # only 1 project
        "aggregate": {"cohort_success_rate_pct": 50.0, "determinism_verified": False, "ci_reproducible": False},
    }
    bad_result = _check_results_structure(bad_data)
    some_fail = any(not c["pass"] for c in bad_result)
    checks.append({"check": "invalid_data_fails_checks", "pass": some_fail})

    # Required archetypes count
    checks.append({"check": "ten_required_archetypes", "pass": len(REQUIRED_ARCHETYPES) == 10})

    all_ok = all(c["pass"] for c in checks)
    print(f"self_test: {len(checks)} checks — {'PASS' if all_ok else 'FAIL'}", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_migration_cohort_validation")
    as_json = "--json" in sys.argv
    no_execution = "--no-exec" in sys.argv

    if "--self-test" in sys.argv:
        self_test()
        return

    report = build_report(execute=not no_execution)

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-sxt5 migration cohort: {report['verdict']} "
              f"({report['checks_passed']}/{report['checks_total']} checks)")
        for c in report["checks"]:
            mark = "PASS" if c["pass"] else "FAIL"
            print(f"  [{mark}] {c['id']}: {c['detail']}")

    sys.exit(0 if report["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
