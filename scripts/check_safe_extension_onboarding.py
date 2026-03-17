#!/usr/bin/env python3
"""bd-elog: Safe extension onboarding — verification gate."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "safe_extension_onboarding.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_15", "bd-elog_contract.md")
BEAD, SECTION = "bd-elog", "15"

CODES = [f"SEO-{str(i).zfill(3)}" for i in range(1, 11)] + ["SEO-ERR-001", "SEO-ERR-002"]
INVS = ["INV-SEO-PHASED", "INV-SEO-VALIDATED", "INV-SEO-DETERMINISTIC", "INV-SEO-GATED", "INV-SEO-VERSIONED", "INV-SEO-AUDITABLE"]

def _read(p):
    with open(p) as f: return f.read()

def _checks():
    r = []
    def ok(n, p, d=""): r.append({"check": n, "passed": p, "detail": d})
    src = _read(IMPL)
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", "pub mod safe_extension_onboarding;" in _read(MOD_RS))
    ok("onboarding_phases", all(t in src for t in ["Install", "Configure", "Validate", "Activate", "Monitor"]), "5 phases")
    for st in ["OnboardingStep", "PhaseStats", "OnboardingReport", "SafeExtensionOnboarding"]:
        ok(f"struct_{st}", f"struct {st}" in src, st)
    ok("phase_enum", "enum OnboardingPhase" in src, "OnboardingPhase enum")
    ok("gate_result", "GateResult" in src, "Gate result tracking")
    ok("report_generation", "generate_report" in src and "OnboardingReport" in src, "Report generation")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok(
        "phase_stats_hash_surface",
        "ps.avg_duration_seconds" in src and "ps.gate_pass_rate" in src,
        "phase stats hash covers avg_duration_seconds + gate_pass_rate",
    )
    ok("event_codes", sum(1 for c in CODES if c in src) >= 12, f"{sum(1 for c in CODES if c in src)}/12")
    ok("invariants", sum(1 for i in INVS if i in src) >= 6, f"{sum(1 for i in INVS if i in src)}/6")
    ok("audit_log", "SeoAuditRecord" in src and "export_audit_log_jsonl" in src, "JSONL export")
    ok("schema_version", "seo-v1.0" in src, "seo-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    ok("test_coverage", len(re.findall(r"#\[test\]", src)) >= 20, f"{len(re.findall(r'#[test]', src))} tests")
    return r

def self_test():
    r = _checks()
    assert len(r) >= 14
    for x in r:
        assert "check" in x and "passed" in x
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True

def main():
    logger = configure_test_logging("check_safe_extension_onboarding")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv: self_test(); return
    results = _checks(); p = sum(1 for x in results if x["passed"]); t = len(results); v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({"bead_id": BEAD, "section": SECTION, "gate_script": os.path.basename(__file__), "checks_passed": p, "checks_total": t, "verdict": v, "checks": results}, indent=2))
    else:
        for x in results: print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    sys.exit(0 if v == "PASS" else 1)

if __name__ == "__main__": main()
