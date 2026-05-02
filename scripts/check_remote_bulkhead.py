#!/usr/bin/env python3
"""bd-v4l0: Verify remote bulkhead implementation."""
import json
import os
import re
import sys
from pathlib import Path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402
SRC = os.path.join(ROOT, "crates", "franken-node", "src", "remote", "remote_bulkhead.rs")


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def _checks():
    results = []

    def check(name, passed, detail=""):
        results.append({"check": name, "passed": passed, "detail": detail})

    # 1. Source file exists
    if not os.path.isfile(SRC):
        check("SOURCE_EXISTS", False, f"missing {SRC}")
        return results
    src = _read(SRC)
    if src is None:
        check("SOURCE_EXISTS", False, f"unreadable {SRC}")
        return results
    check("SOURCE_EXISTS", True, SRC)

    # 2. Event codes (8 codes in event_codes module)
    events = [
        "RB_PERMIT_ACQUIRED",
        "RB_PERMIT_RELEASED",
        "RB_AT_CAPACITY",
        "RB_REQUEST_QUEUED",
        "RB_REQUEST_REJECTED",
        "RB_CAP_CHANGED",
        "RB_DRAIN_ACTIVE",
        "RB_LATENCY_REPORT",
    ]
    missing = [e for e in events if e not in src]
    check(
        "EVENT_CODES",
        len(missing) == 0,
        f"{len(events) - len(missing)}/{len(events)} event codes"
        + (f" (missing: {', '.join(missing)})" if missing else ""),
    )

    # 3. Event codes module structure
    has_event_mod = "pub mod event_codes" in src or "mod event_codes" in src
    check(
        "EVENT_CODES_MODULE",
        has_event_mod,
        "event_codes module present" if has_event_mod else "event_codes module missing",
    )

    # 4. Error codes (11 stable error codes on BulkheadError)
    error_codes = [
        "RB_ERR_NO_REMOTECAP",
        "RB_ERR_AT_CAPACITY",
        "RB_ERR_QUEUE_SATURATED",
        "RB_ERR_QUEUED",
        "RB_ERR_QUEUE_TIMEOUT",
        "RB_ERR_UNKNOWN_REQUEST",
        "RB_ERR_DUPLICATE_REQUEST",
        "RB_ERR_UNKNOWN_PERMIT",
        "RB_ERR_INVALID_REQUEST_ID",
        "RB_ERR_DRAINING",
        "RB_ERR_INVALID_CONFIG",
    ]
    missing_ec = [e for e in error_codes if e not in src]
    check(
        "ERROR_CODES",
        len(missing_ec) == 0,
        f"{len(error_codes) - len(missing_ec)}/{len(error_codes)} error codes"
        + (f" (missing: {', '.join(missing_ec)})" if missing_ec else ""),
    )

    # 5. Core types
    types = [
        "RemoteBulkhead",
        "BackpressurePolicy",
        "BulkheadPermit",
        "BulkheadEvent",
        "BulkheadError",
        "ForegroundLatencySample",
    ]
    missing_t = [t for t in types if t not in src]
    check(
        "CORE_TYPES",
        len(missing_t) == 0,
        f"{len(types) - len(missing_t)}/{len(types)} types"
        + (f" (missing: {', '.join(missing_t)})" if missing_t else ""),
    )

    # 6. RemoteCap gating
    has_remote_cap_lookup = "RemoteCapLookup" in src
    has_remote_cap_required = "RemoteCapRequired" in src
    rejects_missing_or_denied = (
        "RemoteCapLookup::Denied | RemoteCapLookup::NotPresent" in src
    )
    returns_cap_required = "Err(BulkheadError::RemoteCapRequired)" in src
    has_queue_regression = (
        "remote_cap_missing_under_queue_policy_does_not_enqueue" in src
        and "missing RemoteCap should reject before queue admission" in src
    )
    check(
        "REMOTECAP_GATING",
        has_remote_cap_lookup
        and has_remote_cap_required
        and rejects_missing_or_denied
        and returns_cap_required
        and has_queue_regression,
        "RemoteCapLookup fail-closed acquire gate with queue admission regression"
        if (
            has_remote_cap_lookup
            and has_remote_cap_required
            and rejects_missing_or_denied
            and returns_cap_required
            and has_queue_regression
        )
        else "missing RemoteCapLookup denial handling, RemoteCapRequired return, or queue regression",
    )

    # 7. Drain mode
    has_draining = "draining_target" in src
    has_set_max = "set_max_in_flight" in src
    check(
        "DRAIN_MODE",
        has_draining and has_set_max,
        "drain mode on cap reduction"
        if (has_draining and has_set_max)
        else "missing draining_target or set_max_in_flight",
    )

    # 8. Latency tracking
    has_p99 = "p99_foreground_latency_ms" in src
    has_within = "latency_within_target" in src
    has_record = "record_foreground_latency" in src
    check(
        "LATENCY_TRACKING",
        has_p99 and has_within and has_record,
        "p99 latency tracking with target gate"
        if (has_p99 and has_within and has_record)
        else "missing latency functions",
    )

    has_latency_timestamp_param = re.search(
        r"fn\s+record_foreground_latency\(\s*&mut self,\s*latency_ms:\s*u64,\s*now_ms:\s*u64\s*\)",
        src,
    )
    uses_placeholder_latency_timestamp = re.search(
        r"RB_LATENCY_REPORT,\s*0,",
        src,
    )
    check(
        "LATENCY_EVENT_TIMESTAMP",
        bool(has_latency_timestamp_param) and uses_placeholder_latency_timestamp is None,
        "latency events use caller-supplied now_ms"
        if bool(has_latency_timestamp_param) and uses_placeholder_latency_timestamp is None
        else "missing now_ms parameter or latency event still uses placeholder timestamp",
    )

    # 9. Backpressure policy variants
    has_reject = "Reject" in src
    has_queue = "Queue" in src and "max_depth" in src and "timeout_ms" in src
    check(
        "BACKPRESSURE_POLICY",
        has_reject and has_queue,
        "Reject and Queue policies implemented"
        if (has_reject and has_queue)
        else "missing backpressure policy variants",
    )

    # 10. Acquire/release/poll operations
    ops = ["fn acquire(", "fn release(", "fn poll_queued("]
    missing_ops = [o for o in ops if o not in src]
    check(
        "CORE_OPERATIONS",
        len(missing_ops) == 0,
        f"{len(ops) - len(missing_ops)}/{len(ops)} operations"
        + (f" (missing: {', '.join(missing_ops)})" if missing_ops else ""),
    )

    # 11. Permit lifecycle (issue + outstanding tracking)
    has_issue_permit = "issue_permit" in src
    has_outstanding = "outstanding_permits" in src
    check(
        "PERMIT_LIFECYCLE",
        has_issue_permit and has_outstanding,
        "permit issuance and tracking"
        if (has_issue_permit and has_outstanding)
        else "missing permit lifecycle internals",
    )

    # 12. Queue timeout eviction
    has_evict = "evict_expired_queue_entries" in src or "expires_at_ms" in src
    check(
        "QUEUE_TIMEOUT",
        has_evict,
        "queue timeout eviction implemented"
        if has_evict
        else "missing queue timeout eviction",
    )

    # 13. Serde derives
    has_serde = "Serialize" in src and "Deserialize" in src
    check(
        "SERDE_DERIVES",
        has_serde,
        "Serialize/Deserialize on public types"
        if has_serde
        else "missing serde derives",
    )

    # 14. Test coverage (>= 10 tests)
    test_count = len(re.findall(r"#\[test\]", src))
    check("TEST_COVERAGE", test_count >= 10, f"{test_count} tests found (minimum 10)")

    # 15. Spec contract exists
    spec = os.path.join(ROOT, "docs", "specs", "section_10_14", "bd-v4l0_contract.md")
    check(
        "SPEC_CONTRACT",
        os.path.isfile(spec),
        "exists" if os.path.isfile(spec) else f"missing {spec}",
    )

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
    configure_test_logging("check_remote_bulkhead")
    if "--self-test" in sys.argv:
        ok = self_test()
        sys.exit(0 if ok else 1)
    results = _checks()
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    verdict = "PASS" if passed == total else "FAIL"
    report = {
        "bead": "bd-v4l0",
        "title": "Remote Bulkhead",
        "section": "10.14",
        "verdict": verdict,
        "passed": passed,
        "total": total,
        "checks": results,
    }
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
    else:
        print(f"bd-v4l0 remote_bulkhead: {verdict} ({passed}/{total})")
        for r in results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  [{status}] {r['check']}: {r['detail']}")
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
