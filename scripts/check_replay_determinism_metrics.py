#!/usr/bin/env python3
"""bd-jbp1: Replay determinism and artifact completeness — verification gate.

Usage:
    python3 scripts/check_replay_determinism_metrics.py [--json]
"""

import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools",
                     "replay_determinism_metrics.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_14", "bd-jbp1_contract.md")

BEAD = "bd-jbp1"
SECTION = "14"

REQUIRED_CATEGORIES = [
    "VerificationEvidence", "SpecContract", "GateScript",
    "UnitTests", "CheckReport",
]
REQUIRED_EVENT_CODES = [
    "RDM-001", "RDM-002", "RDM-003", "RDM-004", "RDM-005",
    "RDM-006", "RDM-007", "RDM-008", "RDM-009", "RDM-010",
    "RDM-ERR-001", "RDM-ERR-002",
]
REQUIRED_INVARIANTS = [
    "INV-RDM-HASH", "INV-RDM-COMPLETE", "INV-RDM-DETERMINISTIC",
    "INV-RDM-GATED", "INV-RDM-VERSIONED", "INV-RDM-AUDITABLE",
]


def _read(path):
    with open(path) as f:
        return f.read()


def _checks():
    results = []

    def ok(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    src = _read(IMPL)

    ok("source_exists", os.path.isfile(IMPL), IMPL)

    mod_src = _read(MOD_RS)
    ok("module_wiring",
       "pub mod replay_determinism_metrics;" in mod_src,
       "tools/mod.rs")

    found_cats = [c for c in REQUIRED_CATEGORIES if c in src]
    ok("artifact_categories",
       len(found_cats) >= 5,
       f"{len(found_cats)}/5 categories")

    for st in ["ReplayRun", "ComparisonResult", "ArtifactCompleteness",
               "DeterminismReport", "RdmAuditRecord", "ReplayDeterminismMetrics"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)

    ok("hash_comparison",
       "output_hash" in src and "output_match" in src,
       "Hash-based output comparison")

    ok("divergence_detection",
       "DivergenceSeverity" in src and "divergence_count" in src,
       "Divergence severity classification")

    ok("artifact_tracking",
       "track_artifact" in src and "ArtifactCompleteness" in src,
       "Artifact completeness tracking")

    ok("report_generation",
       "generate_report" in src and "DeterminismReport" in src,
       "Report with determinism rate and completeness")

    ok("artifact_completeness_hash_surface",
       all(snippet in src for snippet in [
           "h.update((completeness.len() as u64).to_le_bytes())",
           "for entry in &completeness",
           "entry.category.label()",
           "entry.expected",
           "entry.found",
           "u8::from(entry.complete)",
       ]),
       "content_hash binds per-category completeness payload")

    ok("metric_versioning",
       "METRIC_VERSION" in src and "rdm-v1.0" in src,
       "rdm-v1.0")

    found_codes = [c for c in REQUIRED_EVENT_CODES if c in src]
    ok("event_codes",
       len(found_codes) >= 12,
       f"{len(found_codes)}/12 codes")

    found_invs = [i for i in REQUIRED_INVARIANTS if i in src]
    ok("invariants",
       len(found_invs) >= 6,
       f"{len(found_invs)}/6 invariants")

    ok("audit_log",
       "RdmAuditRecord" in src and "export_audit_log_jsonl" in src,
       "JSONL audit export")

    ok("spec_alignment", os.path.isfile(SPEC), SPEC)

    test_count = len(re.findall(r"#\[test\]", src))
    ok("test_coverage",
       test_count >= 24,
       f"{test_count} tests (>=24)")

    return results


def self_test():
    results = _checks()
    assert len(results) >= 15, f"Expected >=15 checks, got {len(results)}"
    for r in results:
        assert "check" in r and "passed" in r
    print(f"self_test: {len(results)} checks OK", file=sys.stderr)
    return True


def main():
    logger = configure_test_logging("check_replay_determinism_metrics")
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
