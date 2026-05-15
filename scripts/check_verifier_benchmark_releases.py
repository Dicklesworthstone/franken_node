#!/usr/bin/env python3
"""bd-33u2: Verifier/benchmark releases — verification gate."""
import json
import os
import re
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402

IMPL = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "verifier_benchmark_releases.rs")
MOD_RS = os.path.join(ROOT, "crates", "franken-node", "src", "tools", "mod.rs")
SPEC = os.path.join(ROOT, "docs", "specs", "section_16", "bd-33u2_contract.md")
BEAD, SECTION = "bd-33u2", "16"

CODES = [f"VBR-{str(i).zfill(3)}" for i in range(1, 11)] + ["VBR-ERR-001", "VBR-ERR-002"]
INVS = ["INV-VBR-TYPED", "INV-VBR-TRACKED", "INV-VBR-DETERMINISTIC", "INV-VBR-GATED", "INV-VBR-VERSIONED", "INV-VBR-AUDITABLE"]


def _read(p):
    return Path(p).read_text(encoding="utf-8")


def _strip_rust_comments(src):
    without_block_comments = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block_comments)


def _impl_source():
    return _read(IMPL) if os.path.isfile(IMPL) else ""


def _impl_code():
    return _strip_rust_comments(_impl_source())


def _mod_code():
    return _strip_rust_comments(_read(MOD_RS) if os.path.isfile(MOD_RS) else "")


def _rust_module_decl_present(src, module_name):
    return bool(re.search(rf"\bpub\s+mod\s+{re.escape(module_name)}\s*;", src))


def _rust_pub_item_present(src, item_kind, name):
    return bool(re.search(rf"\bpub\s+{item_kind}\s+{re.escape(name)}\b", src))


def _rust_pub_fn_present(src, name):
    return bool(re.search(rf"\bpub\s+fn\s+{re.escape(name)}\s*\(", src))


def _rust_pub_const_str_present(src, name, value=None):
    expected_value = value or name
    return bool(
        re.search(
            rf"\bpub\s+const\s+{re.escape(name)}\s*:\s*&str\s*=\s*\"{re.escape(expected_value)}\"\s*;",
            src,
        )
    )


def _rust_enum_body(src, enum_name):
    match = re.search(rf"\bpub\s+enum\s+{re.escape(enum_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_enum_variant_present(src, enum_name, variant):
    return bool(re.search(rf"\b{re.escape(variant)}\b", _rust_enum_body(src, enum_name)))


def _rust_test_count(src):
    return len(re.findall(r"#\s*\[\s*test\s*\]", src))


def _checks():
    r = []

    def ok(n, p, d=""):
        r.append({"check": n, "passed": bool(p), "detail": d})

    src = _impl_code()
    ok("source_exists", os.path.isfile(IMPL), IMPL)
    ok("module_wiring", _rust_module_decl_present(_mod_code(), "verifier_benchmark_releases"))
    ok("release_types", all(_rust_enum_variant_present(src, "ReleaseType", t) for t in ["VerifierTool", "BenchmarkSuite", "TestHarness", "ComplianceChecker", "DocumentationKit"]), "5 types")
    ok("release_lifecycle", all(_rust_enum_variant_present(src, "ReleaseStatus", s) for s in ["Draft", "Published", "Deprecated", "Archived"]), "4 statuses")
    for st in ["ToolRelease", "ReleaseArtifact", "DownloadRecord", "AdoptionMetrics", "VerifierBenchmarkReleases"]:
        ok(f"struct_{st}", _rust_pub_item_present(src, "struct", st), st)
    ok("download_tracking", _rust_pub_fn_present(src, "record_download") and "download_count" in src, "Download tracking")
    ok("quality_gating", _rust_pub_fn_present(src, "publish_release") and "MIN_QUALITY_SCORE" in src, "Quality threshold")
    ok("changelog_support", _rust_pub_fn_present(src, "update_changelog") and "changelog" in src, "Changelog management")
    ok("content_hash", "content_hash" in src and "Sha256" in src, "SHA-256 hashing")
    ok("metrics_hashing", _rust_pub_fn_present(src, "generate_metrics") and all(t in src for t in ["compute_metrics_content_hash", "downloads_by_type", "total_downloads"]), "Metrics hash seals downloads_by_type surface")
    event_found = sum(1 for c in CODES if re.search(rf"\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*\"{re.escape(c)}\"\s*;", src))
    ok("event_codes", event_found >= 12, f"{event_found}/12")
    inv_found = sum(1 for i in INVS if re.search(rf"\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*\"{re.escape(i)}\"\s*;", src))
    ok("invariants", inv_found >= 6, f"{inv_found}/6")
    ok("audit_log", _rust_pub_item_present(src, "struct", "VbrAuditRecord") and _rust_pub_fn_present(src, "export_audit_log_jsonl"), "JSONL export")
    ok("schema_version", _rust_pub_const_str_present(src, "SCHEMA_VERSION", "vbr-v1.0"), "vbr-v1.0")
    ok("spec_alignment", os.path.isfile(SPEC), SPEC)
    test_count = _rust_test_count(src)
    ok("test_coverage", test_count >= 22, f"{test_count} tests")
    return r


def self_test():
    r = _checks()
    if len(r) < 16:
        raise AssertionError(f"expected at least 16 checks, got {len(r)}")
    for x in r:
        if "check" not in x or "passed" not in x:
            raise AssertionError(f"malformed check row: {x!r}")
    print(f"self_test: {len(r)} checks OK", file=sys.stderr)
    return True


def main():
    configure_test_logging("check_verifier_benchmark_releases")
    as_json = "--json" in sys.argv
    if "--self-test" in sys.argv:
        self_test()
        return
    results = _checks()
    p = sum(1 for x in results if x["passed"])
    t = len(results)
    v = "PASS" if p == t else "FAIL"
    if as_json:
        print(json.dumps({"bead_id": BEAD, "section": SECTION, "gate_script": os.path.basename(__file__), "checks_passed": p, "checks_total": t, "verdict": v, "checks": results}, indent=2))
    else:
        for x in results:
            print(f"  [{'PASS' if x['passed'] else 'FAIL'}] {x['check']}: {x['detail']}")
        print(f"\n{BEAD}: {p}/{t} checks — {v}")
    sys.exit(0 if v == "PASS" else 1)


if __name__ == "__main__":
    main()
