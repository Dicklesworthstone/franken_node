#!/usr/bin/env python3
"""bd-4jh9: Verification script for VEF degraded-mode policy with proof lag/outage SLOs.

Usage:
    python3 scripts/check_vef_degraded_mode.py            # human-readable
    python3 scripts/check_vef_degraded_mode.py --json      # machine-readable
    python3 scripts/check_vef_degraded_mode.py --self-test  # internal consistency
"""

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.lib.test_logger import configure_test_logging  # noqa: E402


# ── File paths ─────────────────────────────────────────────────────────────

IMPL_FILE = ROOT / "crates/franken-node/src/security/vef_degraded_mode.rs"
MOD_FILE = ROOT / "crates/franken-node/src/security/mod.rs"
SPEC_FILE = ROOT / "docs/specs/section_10_18/bd-4jh9_contract.md"
POLICY_FILE = ROOT / "docs/policy/vef_degraded_mode_policy.md"
EVIDENCE_FILE = ROOT / "artifacts/section_10_18/bd-4jh9/verification_evidence.json"
SUMMARY_FILE = ROOT / "artifacts/section_10_18/bd-4jh9/verification_summary.md"

ALL_CHECKS: list[dict[str, Any]] = []
RESULTS: dict[str, Any] = {}

# ── Required elements ──────────────────────────────────────────────────────

REQUIRED_TYPES = [
    "pub enum VefMode",
    "pub struct ProofLagSlo",
    "pub struct VefDegradedModeConfig",
    "pub struct ProofLagMetrics",
    "pub enum ActionRisk",
    "pub struct VefActionDecision",
    "pub struct VefModeTransitionEvent",
    "pub struct VefSloBreachEvent",
    "pub struct VefRecoveryInitiatedEvent",
    "pub struct VefRecoveryReceipt",
    "pub enum VefDegradedModeEvent",
    "pub struct VefTransitionErrorEvent",
    "pub struct VefDegradedModeEngine",
]

REQUIRED_EVENT_CODES = [
    "VEF-DEGRADE-001",
    "VEF-DEGRADE-002",
    "VEF-DEGRADE-003",
    "VEF-DEGRADE-004",
    "VEF-DEGRADE-ERR-001",
]

REQUIRED_MODES = [
    "Normal",
    "Restricted",
    "Quarantine",
    "Halt",
]

REQUIRED_FUNCTIONS = [
    "fn observe_metrics",
    "fn evaluate_action",
    "fn target_mode_for_metrics",
    "fn escalate",
    "fn maybe_deescalate",
    "fn find_breach_details",
]

REQUIRED_METRICS = [
    "proof_lag_secs",
    "backlog_depth",
    "error_rate",
    "heartbeat_age_secs",
]

REQUIRED_INVARIANTS_SPEC = [
    "INV-VEF-DM-DETERMINISTIC",
    "INV-VEF-DM-AUDIT",
    "INV-VEF-DM-ESCALATE-IMMEDIATE",
    "INV-VEF-DM-DEESCALATE-STABILIZED",
    "INV-VEF-DM-RECOVERY-RECEIPT",
]

REAL_EVIDENCE_REQUIREMENTS = [
    (
        "real evidence: tier escalation paths",
        IMPL_FILE,
        [
            "fn restricted_on_proof_lag_breach",
            "fn quarantine_on_slo_breach",
            "fn halt_on_critical_lag",
            "fn halt_on_heartbeat_timeout",
            "fn normal_to_restricted_to_quarantine_escalation",
            "fn skip_to_halt_directly",
        ],
    ),
    (
        "real evidence: deterministic metric sequences",
        IMPL_FILE,
        [
            "fn deterministic_identical_metric_sequences",
            "run1.observe_metrics(m, *t, \"det-1\")",
            "run2.observe_metrics(m, *t, \"det-2\")",
            "assert_eq!(run1.mode(), run2.mode())",
            "assert_eq!(e1.code(), e2.code())",
        ],
    ),
    (
        "real evidence: action gating by mode",
        IMPL_FILE,
        [
            "fn normal_permits_all",
            "fn restricted_permits_with_annotation",
            "fn quarantine_blocks_high_risk",
            "fn halt_blocks_all_except_health_check",
            "pub fn evaluate_action(",
            "vef_halt: action",
        ],
    ),
    (
        "real evidence: stabilization-window deescalation",
        IMPL_FILE,
        [
            "fn deescalation_requires_stabilization_window",
            "fn deescalation_resets_on_metric_regression",
            "fn halt_deescalates_through_quarantine_restricted",
            "engine.observe_metrics(&good, 1169",
            "engine.observe_metrics(&good, 1170",
            "stabilization_window_secs",
        ],
    ),
    (
        "real evidence: recovery receipts and audit events",
        IMPL_FILE,
        [
            "fn escalation_emits_slo_breach_and_transition_events",
            "fn deescalation_emits_recovery_receipt",
            "fn transition_event_has_required_fields",
            "VefDegradedModeEvent::RecoveryComplete",
            "VEF_DEGRADE_003",
            "VEF_DEGRADE_004",
        ],
    ),
    (
        "real evidence: fail-closed thresholds",
        IMPL_FILE,
        [
            "fn nan_error_rate_escalates_engine_to_halt",
            "fn negative_error_rate_escalates_engine_to_halt",
            "fn exact_restricted_threshold_escalates_fail_closed",
            "fn exact_halt_heartbeat_timeout_escalates_fail_closed",
            "fn nan_halt_error_rate_escalates_engine_to_halt",
            "fn zero_heartbeat_timeout_escalates_healthy_metrics_to_halt",
        ],
    ),
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _read(path: Path) -> str:
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def _strip_rust_comments(src: str) -> str:
    without_block_comments = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//.*", "", without_block_comments)


def _rust_code(path: Path) -> str:
    return _strip_rust_comments(_read(path))


def _impl_code() -> str:
    return _rust_code(IMPL_FILE)


def _mod_code() -> str:
    return _rust_code(MOD_FILE)


def _rust_module_decl_present(src: str, module_name: str) -> bool:
    return bool(re.search(rf"\bpub\s+mod\s+{re.escape(module_name)}\s*;", src))


def _rust_item_present(src: str, item_kind: str, name: str, *, public: bool = False) -> bool:
    visibility = r"pub\s+" if public else r"(?:pub\s+)?"
    return bool(re.search(rf"\b{visibility}{item_kind}\s+{re.escape(name)}\b", src))


def _rust_fn_present(src: str, name: str, *, public: bool | None = None) -> bool:
    if public:
        visibility = r"pub\s+"
    elif public is None:
        visibility = r"(?:pub\s+)?"
    else:
        visibility = r""
    return bool(re.search(rf"\b{visibility}fn\s+{re.escape(name)}\s*\(", src))


def _rust_pub_const_str_value_present(src: str, value: str) -> bool:
    return bool(
        re.search(
            rf"\bpub\s+const\s+\w+\s*:\s*&str\s*=\s*\"{re.escape(value)}\"\s*;",
            src,
        )
    )


def _rust_enum_body(src: str, enum_name: str) -> str:
    match = re.search(rf"\bpub\s+enum\s+{re.escape(enum_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_enum_variant_present(src: str, enum_name: str, variant: str) -> bool:
    return bool(re.search(rf"\b{re.escape(variant)}\b", _rust_enum_body(src, enum_name)))


def _rust_struct_body(src: str, struct_name: str) -> str:
    match = re.search(rf"\bpub\s+struct\s+{re.escape(struct_name)}\s*\{{(?P<body>.*?)\n\}}", src, re.DOTALL)
    return match.group("body") if match else ""


def _rust_pub_struct_field_present(src: str, struct_name: str, field: str) -> bool:
    return bool(re.search(rf"\bpub\s+{re.escape(field)}\s*:", _rust_struct_body(src, struct_name)))


def _rust_test_count(src: str) -> int:
    return len(re.findall(r"#\s*\[\s*test\s*\]", src))


def _rust_test_fn_present(src: str, name_or_prefix: str) -> bool:
    return bool(re.search(rf"#\s*\[\s*test\s*\]\s*fn\s+{re.escape(name_or_prefix)}\w*\s*\(", src))


def _required_type_present(src: str, type_decl: str) -> bool:
    parts = type_decl.split()
    if len(parts) == 3 and parts[0] == "pub" and parts[1] in {"struct", "enum"}:
        return _rust_item_present(src, parts[1], parts[2], public=True)
    return type_decl in src


def _required_function_present(src: str, fn_decl: str) -> bool:
    name = fn_decl.strip().removeprefix("pub ").removeprefix("fn ").split("(", 1)[0].strip()
    return _rust_fn_present(src, name)


def _check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    entry = {"check": name, "pass": ok, "detail": detail or ("ok" if ok else "FAIL")}
    ALL_CHECKS.append(entry)
    return entry


# ── Check groups ───────────────────────────────────────────────────────────

def check_file_existence() -> None:
    _check("implementation exists", IMPL_FILE.exists(), _safe_rel(IMPL_FILE))
    _check("module wired in mod.rs", _rust_module_decl_present(_mod_code(), "vef_degraded_mode"), _safe_rel(MOD_FILE))
    _check("spec document exists", SPEC_FILE.exists(), _safe_rel(SPEC_FILE))
    _check("policy document exists", POLICY_FILE.exists(), _safe_rel(POLICY_FILE))
    _check("evidence artifact exists", EVIDENCE_FILE.exists(), _safe_rel(EVIDENCE_FILE))
    _check("summary artifact exists", SUMMARY_FILE.exists(), _safe_rel(SUMMARY_FILE))


def check_types() -> None:
    src = _impl_code()
    for t in REQUIRED_TYPES:
        _check(f"type: {t}", _required_type_present(src, t))


def check_event_codes() -> None:
    src = _impl_code()
    for code in REQUIRED_EVENT_CODES:
        _check(f"event code: {code}", _rust_pub_const_str_value_present(src, code))


def check_modes() -> None:
    src = _impl_code()
    for mode in REQUIRED_MODES:
        _check(f"mode variant: {mode}", _rust_enum_variant_present(src, "VefMode", mode))


def check_functions() -> None:
    src = _impl_code()
    for fn_name in REQUIRED_FUNCTIONS:
        _check(f"function: {fn_name}", _required_function_present(src, fn_name))


def check_metrics() -> None:
    src = _impl_code()
    for metric in REQUIRED_METRICS:
        _check(f"metric field: {metric}", _rust_pub_struct_field_present(src, "ProofLagMetrics", metric))


def check_slo_defaults() -> None:
    src = _impl_code()
    # Restricted: 300, 100, 0.10
    _check("restricted SLO proof_lag default 300", "300" in src and "restricted_slo" in src)
    # Quarantine: 900, 500, 0.30
    _check("quarantine SLO proof_lag default 900", "900" in src and "quarantine_slo" in src)
    # Halt multiplier 2.0
    _check("halt multiplier 2.0", "2.0" in src and "halt_multiplier" in src)
    # Stabilization window 120
    _check("stabilization window 120", "120" in src and "stabilization_window_secs" in src)


def check_spec_invariants() -> None:
    src = _read(SPEC_FILE)
    for inv in REQUIRED_INVARIANTS_SPEC:
        _check(f"spec invariant: {inv}", inv in src)


def check_spec_content() -> None:
    src = _read(SPEC_FILE)
    _check("spec: restricted tier", "restricted" in src.lower() and "Restricted" in src)
    _check("spec: quarantine tier", "quarantine" in src.lower() and "Quarantine" in src)
    _check("spec: halt tier", "halt" in src.lower() and "Halt" in src)
    _check("spec: SLO thresholds", "SLO" in src)
    _check("spec: transition rules", "Transition" in src)
    _check("spec: recovery receipts", "recovery" in src.lower())
    _check("spec: audit events", "VEF-DEGRADE-001" in src)


def check_policy_content() -> None:
    src = _read(POLICY_FILE)
    _check("policy: restricted tier", "Restricted" in src)
    _check("policy: quarantine tier", "Quarantine" in src)
    _check("policy: halt tier", "Halt" in src)
    _check("policy: SLO thresholds", "SLO" in src)
    _check("policy: VEF-DEGRADE event codes", "VEF-DEGRADE-001" in src)
    _check("policy: recovery receipts", "receipt" in src.lower())
    _check("policy: operator guidance", "Operator" in src)


def check_tests() -> None:
    src = _impl_code()
    test_count = _rust_test_count(src)
    _check(f"Rust unit tests >= 20 ({test_count})", test_count >= 20, f"{test_count} tests")

    test_categories = [
        ("normal default", "normal_mode_by_default"),
        ("restricted breach", "restricted_on_proof_lag_breach"),
        ("quarantine breach", "quarantine_on_slo_breach"),
        ("halt critical lag", "halt_on_critical_lag"),
        ("halt heartbeat", "halt_on_heartbeat_timeout"),
        ("escalation path", "normal_to_restricted_to_quarantine"),
        ("skip-tier escalation", "skip_restricted_direct_to_quarantine"),
        ("deescalation stabilization", "deescalation_requires_stabilization"),
        ("deescalation reset", "deescalation_resets_on_metric_regression"),
        ("step-down through tiers", "halt_deescalates_through_quarantine"),
        ("determinism", "deterministic_identical_metric_sequences"),
        ("audit events", "escalation_emits_slo_breach"),
        ("recovery receipt", "deescalation_emits_recovery_receipt"),
        ("transition fields", "transition_event_has_required_fields"),
        ("action normal", "normal_permits_all"),
        ("action quarantine", "quarantine_blocks_high_risk"),
        ("action halt", "halt_blocks_all_except_health_check"),
        ("custom SLO", "custom_slo_thresholds"),
        ("no silent transitions", "no_silent_transitions"),
    ]
    for name, pattern in test_categories:
        _check(f"test: {name}", _rust_test_fn_present(src, pattern))


def check_determinism_invariant() -> None:
    src = _impl_code()
    _check(
        "INV: deterministic function/test coverage",
        _rust_fn_present(src, "target_mode_for_metrics", public=True)
        and _rust_test_fn_present(src, "deterministic_identical_metric_sequences"),
    )
    _check("INV: pure function target_mode", "pure function" in src.lower() or "target_mode_for_metrics" in src)


def check_action_evaluation() -> None:
    src = _impl_code()
    _check("action: HighRisk variant", _rust_enum_variant_present(src, "ActionRisk", "HighRisk"))
    _check("action: LowRisk variant", _rust_enum_variant_present(src, "ActionRisk", "LowRisk"))
    _check("action: HealthCheck variant", _rust_enum_variant_present(src, "ActionRisk", "HealthCheck"))
    _check("action: VefActionDecision result", _rust_item_present(src, "struct", "VefActionDecision", public=True))


def check_recovery_receipt_fields() -> None:
    src = _impl_code()
    _check(
        "receipt: degraded_mode_duration_secs",
        _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "degraded_mode_duration_secs"),
    )
    _check("receipt: actions_affected", _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "actions_affected"))
    _check("receipt: recovery_trigger", _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "recovery_trigger"))
    _check(
        "receipt: pipeline_health_at_recovery",
        _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "pipeline_health_at_recovery"),
    )
    _check("receipt: from_mode", _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "from_mode"))
    _check("receipt: to_mode", _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "to_mode"))
    _check("receipt: correlation_id", _rust_pub_struct_field_present(src, "VefRecoveryReceipt", "correlation_id"))


def _missing_patterns(path: Path, patterns: list[str]) -> list[str]:
    if not path.is_file():
        return patterns
    content = _rust_code(path) if path.suffix == ".rs" else _read(path)
    return [pattern for pattern in patterns if pattern not in content]


def check_real_vef_evidence() -> None:
    for name, path, patterns in REAL_EVIDENCE_REQUIREMENTS:
        missing = _missing_patterns(path, patterns)
        _check(
            name,
            not missing,
            "ok" if not missing else f"missing in {_safe_rel(path)}: {missing}",
        )


# ── Main ───────────────────────────────────────────────────────────────────

def run_all() -> dict[str, Any]:
    ALL_CHECKS.clear()
    RESULTS.clear()

    check_file_existence()
    check_types()
    check_event_codes()
    check_modes()
    check_functions()
    check_metrics()
    check_slo_defaults()
    check_spec_invariants()
    check_spec_content()
    check_policy_content()
    check_tests()
    check_determinism_invariant()
    check_action_evaluation()
    check_recovery_receipt_fields()
    check_real_vef_evidence()

    passed = sum(1 for c in ALL_CHECKS if c["pass"])
    failed = sum(1 for c in ALL_CHECKS if not c["pass"])

    result = {
        "bead_id": "bd-4jh9",
        "title": "VEF degraded-mode policy for proof lag/outage with explicit SLOs",
        "section": "10.18",
        "verdict": "PASS" if failed == 0 else "FAIL",
        "total": len(ALL_CHECKS),
        "passed": passed,
        "failed": failed,
        "checks": list(ALL_CHECKS),
    }
    RESULTS.update(result)
    return result


def self_test() -> tuple[bool, list[dict[str, Any]]]:
    result = run_all()
    return result["verdict"] == "PASS", result["checks"]


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    configure_test_logging("check_vef_degraded_mode")
    if "--self-test" in sys.argv:
        ok, checks = self_test()
        passed = sum(1 for c in checks if c["pass"])
        total = len(checks)
        for c in checks:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}")
        print(f"\nself-test: {passed}/{total} {'PASS' if ok else 'FAIL'}")
        sys.exit(0 if ok else 1)

    result = run_all()

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(f"# {result['bead_id']}: {result['title']}")
        print(f"Section: {result['section']} | Verdict: {result['verdict']}")
        print(f"Checks: {result['passed']}/{result['total']} passing\n")
        for c in result["checks"]:
            status = "PASS" if c["pass"] else "FAIL"
            print(f"  [{status}] {c['check']}: {c['detail']}")
        if result["failed"] > 0:
            print(f"\n{result['failed']} check(s) failed.")

    sys.exit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
