#!/usr/bin/env python3
"""bd-wpck: Migration kit ecosystem — verification gate.

Usage:
    python3 scripts/check_migration_kit.py [--json]
"""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "supply_chain",
                     "migration_kit.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "supply_chain", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-wpck_contract.md")

BEAD = "bd-wpck"
SECTION = "15"

REQUIRED_ARCHETYPES = ["Express", "Fastify", "Koa", "NextJs", "BunNative"]
REQUIRED_PHASES = [
    "Assessment", "DependencyAudit", "CodeAdaptation",
    "TestValidation", "Deployment",
]
REQUIRED_EVENT_CODES = [
    "MKE-001", "MKE-002", "MKE-003", "MKE-004", "MKE-005",
    "MKE-006", "MKE-007", "MKE-008", "MKE-009", "MKE-010",
    "MKE-ERR-001", "MKE-ERR-002", "MKE-ERR-003",
]
REQUIRED_INVARIANTS = [
    "INV-MKE-COMPLETE", "INV-MKE-REVERSIBLE", "INV-MKE-GATED",
    "INV-MKE-DETERMINISTIC", "INV-MKE-AUDITABLE", "INV-MKE-VERSIONED",
]


def _read(path):
    with open(path) as f:
        return f.read()


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    # 1. Source exists
    ok("source_exists", os.path.isfile(IMPL), IMPL)

    # 2. Module wiring
    mod_src = _read(MOD_RS)
    ok("module_wiring",
       "pub mod migration_kit;" in mod_src,
       "supply_chain/mod.rs")

    # 3. Archetypes (5)
    found_arch = [a for a in REQUIRED_ARCHETYPES if a in src]
    ok("archetypes",
       len(found_arch) >= 5,
       f"{len(found_arch)}/5 archetypes")

    # 4. Migration phases (5)
    found_phases = [p for p in REQUIRED_PHASES if p in src]
    ok("migration_phases",
       len(found_phases) >= 5,
       f"{len(found_phases)}/5 phases")

    # 5. Core structs
    for st in ["MigrationStep", "CompatibilityMapping", "MigrationKit",
               "MigrationReport", "MkeAuditRecord", "MigrationKitEcosystem"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    # 6. Compatibility gating
    ok("compatibility_gating",
       "min_api_coverage_pct" in src and "api_coverage_pct" in src,
       "API coverage threshold enforcement")

    # 7. Step management
    ok("step_management",
       "start_step" in src and "complete_step" in src and "rollback_step" in src,
       "Start, complete, rollback operations")

    # 8. Deterministic hashing
    ok("deterministic_hashing",
       "content_hash" in src and "Sha256" in src,
       "SHA-256 content hashing")

    # 8b. content_hash covers compatibility mapping surface (bd-fd5ox)
    compat_hash_fields = [
        "supported_versions", "api_coverage_pct",
        "known_incompatibilities", "migration_complexity",
    ]
    # Extract the first hash_input block (kit hash in load_kit)
    hash_start = src.find("let hash_input = serde_json")
    if hash_start >= 0:
        hash_end = src.find(".to_string();", hash_start)
        hash_section = src[hash_start:hash_end] if hash_end > hash_start else ""
    else:
        hash_section = ""
    found_hash_fields = [f for f in compat_hash_fields if f in hash_section]
    ok("content_hash_surface",
       len(found_hash_fields) == len(compat_hash_fields),
       f"{len(found_hash_fields)}/{len(compat_hash_fields)} compat fields in kit hash")

    # 8c. NaN/Inf guard on api_coverage_pct (bd-fd5ox)
    ok("nan_inf_guard",
       "is_finite()" in src and "api_coverage_pct" in src,
       "Non-finite api_coverage_pct rejection")

    # 9. Kit versioning
    ok("kit_versioning",
       "KIT_VERSION" in src and "mke-v1.0" in src,
       "mke-v1.0")

    # 10. Report generation
    ok("report_generation",
       "generate_report" in src and "MigrationReport" in src,
       "Progress report with status")

    # 11. Event codes (13)
    found_codes = [c for c in REQUIRED_EVENT_CODES if c in src]
    ok("event_codes",
       len(found_codes) >= 13,
       f"{len(found_codes)}/13 codes")

    # 12. Invariants (6)
    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants",
       len(found_invs) >= 6,
       f"{len(found_invs)}/6 invariants")

    # 13. Audit log
    ok("audit_log",
       "MkeAuditRecord" in src and "export_audit_log_jsonl" in src,
       "JSONL audit export")

    # 14. Spec alignment
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    # 15. Test coverage (count #[test])
    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage",
       test_count >= 29,
       f"{test_count} tests (>=29)")

    return results


def self_test():
    """Smoke-test that all checks produce output."""
    results = _checks()
    assert len(results) >= 17, f"Expected >=17 checks, got {len(results)}"
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_migration_kit")
    as_json = "--json" in sys.argv

    if "--self-test" in sys.argv:
        self_test()
        return

    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"

    if as_json:
        print(json.dumps({
            "bead_id": BEAD,
            "section": SECTION,
            "gate_script": os.path.basename(__file__),
            "checks_passed": passed,
            "checks_total": total,
            "verdict": verdict,
            "checks": results,
        }, indent=2))
    else:
        for r in results:
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"  [{mark}] {r['check']}: {r['detail']}")
        print(f"\n{BEAD}: {passed}/{total} checks — {verdict}")

    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
