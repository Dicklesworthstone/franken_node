#!/usr/bin/env python3
"""bd-ac83: Verify remote computation registry implementation."""
import json
import os
import re
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "computation_registry.rs")

def _read(path):
    with open(path) as f:
        return f.read()

def _checks():
    results = []
    
    def check(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})
    
    if not os.path.isfile(SRC):
        check("SOURCE_EXISTS", False, f"missing {SRC}")
        return results
    
    src = _read(SRC)
    check("SOURCE_EXISTS", True, SRC)
    
    # Event codes
    event_codes = ["CR_REGISTRY_LOADED", "CR_LOOKUP_SUCCESS", "CR_LOOKUP_UNKNOWN",
                   "CR_LOOKUP_MALFORMED", "CR_VERSION_UPGRADED", "CR_DISPATCH_GATED",
                   "CR_REGISTRY_REJECTED"]
    missing_events = [c for c in event_codes if c not in src]
    check("EVENT_CODES", len(missing_events) == 0,
          f"{len(event_codes) - len(missing_events)}/{len(event_codes)} event codes" +
          (f" missing: {missing_events}" if missing_events else ""))
    
    # Error codes
    error_codes = ["ERR_UNKNOWN_COMPUTATION", "ERR_MALFORMED_COMPUTATION_NAME",
                   "ERR_DUPLICATE_COMPUTATION", "ERR_REGISTRY_VERSION_REGRESSION",
                   "ERR_INVALID_COMPUTATION_ENTRY"]
    missing_errors = [c for c in error_codes if c not in src]
    check("ERROR_CODES", len(missing_errors) == 0,
          f"{len(error_codes) - len(missing_errors)}/{len(error_codes)} error codes" +
          (f" missing: {missing_errors}" if missing_errors else ""))
    
    # Canonical name validator
    check("CANONICAL_NAME_VALIDATOR", "is_canonical_computation_name" in src,
          "is_canonical_computation_name function present")
    
    # Core types
    types = ["ComputationEntry", "ComputationRegistry", "ComputationRegistryError"]
    missing_types = [t for t in types if f"pub struct {t}" not in src and f"pub enum {t}" not in src]
    check("CORE_TYPES", len(missing_types) == 0,
          f"{len(types) - len(missing_types)}/{len(types)} types" +
          (f" missing: {missing_types}" if missing_types else ""))
    
    # RemoteCap gating
    check("REMOTECAP_GATING", "authorize_dispatch" in src and "RemoteCap" in src,
          "authorize_dispatch with RemoteCap integration")
    
    # Catalog round-trip
    check("CATALOG_ROUNDTRIP", "from_catalog" in src and "to_catalog" in src,
          "catalog serialization methods present")
    
    # Audit trail
    check("AUDIT_TRAIL", "RegistryAuditEvent" in src and "audit_events" in src,
          "audit event recording present")
    
    # Test coverage
    test_count = len(re.findall(r'#\[test\]', src))
    check("TEST_COVERAGE", test_count >= 6, f"{test_count} tests found")
    
    return results

def self_test():
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"self_test: {passed}/{total} checks passed")
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['check']}: {r['detail']}")
    return passed == total

def main():
    logger = configure_test_logging("check_computation_registry")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    
    report = {
        "bead": "bd-ac83",
        "title": "Remote Computation Registry",
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "checks": results,
    }
    
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-ac83 computation_registry: {verdict} ({passed}/{total})")
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
    
    sys.exit(0 if verdict == "PASS" else 1)

if __name__ == "__main__":
    main()
