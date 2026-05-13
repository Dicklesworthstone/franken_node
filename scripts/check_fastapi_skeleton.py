#!/usr/bin/env python3
"""Verification script for bd-2f5l: control-plane catalog boundary."""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.lib.test_logger import configure_test_logging

IMPL = ROOT / "crates" / "franken-node" / "src" / "api" / "service.rs"
ROUTE_FILES = [
    ROOT / "crates" / "franken-node" / "src" / "api" / "operator_routes.rs",
    ROOT / "crates" / "franken-node" / "src" / "api" / "verifier_routes.rs",
    ROOT / "crates" / "franken-node" / "src" / "api" / "fleet_control_routes.rs",
]
REPORT = ROOT / "artifacts" / "10.16" / "fastapi_endpoint_report.json"
SPEC = ROOT / "docs" / "specs" / "section_10_16" / "bd-2f5l_contract.md"
CARGO_INTEGRATION = (
    ROOT / "crates" / "franken-node" / "tests" / "fastapi_rust_control_plane_integration.rs"
)
CONTROL_PLANE_CATALOG_ARTIFACT = (
    ROOT / "artifacts" / "replacement_gap" / "bd-2fqyv.5.3" / "control_plane_catalog.json"
)
REPLACEMENT_EVIDENCE_DIR = ROOT / "artifacts" / "replacement_gap" / "bd-2fqyv.5.2"
REPLACEMENT_EVIDENCE = REPLACEMENT_EVIDENCE_DIR / "verification_evidence.json"
REPLACEMENT_SUMMARY = REPLACEMENT_EVIDENCE_DIR / "verification_summary.md"
REPLACEMENT_BEAD_ID = "bd-2fqyv.5.2"
COMPLETION_DEBT_BEAD = "bd-2fqyv.5.2.1"
COMPLETION_DEBT_ITEMS = ["tests.integration.primary"]
PERF_BASELINE_BEAD_ID = "bd-2fqyv.5.3"

ENDPOINTS = [
    ("GET", "/v1/operator/status"),
    ("GET", "/v1/operator/health"),
    ("GET", "/v1/operator/config"),
    ("GET", "/v1/operator/rollout"),
    ("POST", "/v1/verifier/conformance"),
    ("GET", "/v1/verifier/evidence/{check_id}"),
    ("GET", "/v1/verifier/audit-log"),
    ("GET", "/v1/fleet/leases"),
    ("POST", "/v1/fleet/leases"),
    ("DELETE", "/v1/fleet/leases/{lease_id}"),
    ("POST", "/v1/fleet/fence"),
    ("POST", "/v1/fleet/coordinate"),
]
ENDPOINT_PATHS = [path for _, path in ENDPOINTS]

REQUIRED_TYPES = [
    "ServiceConfig",
    "EndpointCatalogEntry",
    "MiddlewareCoverage",
    "TransportBoundaryKind",
    "TransportBoundaryStatus",
    "PerformanceBaselineStatus",
    "PerformanceBaseline",
    "RequestLifecycleProvenance",
    "EndpointReport",
    "ControlPlaneService",
]

REQUIRED_METHODS = [
    "pub fn build_endpoint_catalog()",
    "pub fn all_route_metadata()",
    "pub fn check_middleware_coverage()",
    "pub fn generate_endpoint_report(",
    "pub fn new(",
    "pub fn config(",
    "pub fn metrics(",
    "pub fn request_count(",
    "pub fn limiter_for_group(",
    "pub fn record(",
    "pub fn request_lifecycle_provenance(",
    "pub fn request_lifecycle_events(",
    "pub fn catalog(",
    "pub fn transport_boundary(",
    "pub fn report(",
]

REQUIRED_TESTS = [
    "all_route_metadata_collects_all_groups",
    "endpoint_catalog_has_all_routes",
    "middleware_coverage_all_pass",
    "endpoint_report_generation",
    "service_default_construction",
    "service_report_carries_configured_bind_target_hint",
    "service_record_captures_request_lifecycle_provenance",
    "request_lifecycle_provenance_explains_transport_state",
    "fleet_mutations_have_fail_closed_rate_limit",
    "operator_health_endpoint_unauthenticated",
    "all_routes_versioned_v1",
]

REQUIRED_INTEGRATION_TESTS = [
    "canonical_api_service_builder_exposes_truthful_in_process_boundary",
    "control_plane_service_record_captures_in_process_lifecycle_provenance",
]

INTEGRATION_MARKERS = [
    "TransportBoundaryKind::InProcessCatalog",
    "PerformanceBaselineStatus::UnavailablePendingTransport",
    "caller-owned in-process dispatch only",
    "no transport-owned cancellation boundary",
    "No live async HTTP/gRPC transport boundary is owned",
]

SPEC_MARKERS = [
    "12 base-catalog endpoints",
    "in-process control-plane catalog boundary",
    "unavailable pending transport",
    "feature/test-only quarantine routes",
    "transport boundary status",
    "performance baselines",
    "request lifecycle provenance",
]

CANONICAL_API_ROOT = "crates/franken-node/src/api/"
CANONICAL_SERVICE_PATH = f"{CANONICAL_API_ROOT}service.rs"
OBSOLETE_SERVICE_PATHS = (
    "services/control_plane_fastapi_rust/",
    "services/control_plane_fastapi_rust",
)

MIN_IMPL_TESTS = 30
BASELINE_PROVENANCE = (
    "No live async HTTP/gRPC transport boundary is owned; load-test baselines "
    "are intentionally unavailable until that trigger exists."
)


def safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_file(path: Path, label: str) -> dict:
    ok = path.exists()
    return {
        "check": f"File exists: {label}",
        "pass": ok,
        "detail": str(path.relative_to(ROOT)) if ok else f"Missing: {path}",
    }


def check_content(path: Path, needles: list[str], category: str) -> list[dict]:
    results = []
    if not path.exists():
        for needle in needles:
            results.append(
                {"check": f"{category}: {needle}", "pass": False, "detail": "file missing"}
            )
        return results

    text = path.read_text(encoding="utf-8")
    for needle in needles:
        found = needle in text
        results.append(
            {
                "check": f"{category}: {needle}",
                "pass": found,
                "detail": "found" if found else "not found",
            }
        )
    return results


def check_impl_test_count() -> dict:
    if not IMPL.exists():
        return {
            "check": f"Rust test count >= {MIN_IMPL_TESTS}",
            "pass": False,
            "detail": "file missing",
        }
    text = IMPL.read_text(encoding="utf-8")
    count = len(re.findall(r"#\[test\]", text))
    return {
        "check": f"Rust test count >= {MIN_IMPL_TESTS}",
        "pass": count >= MIN_IMPL_TESTS,
        "detail": f"{count} tests found",
    }


def check_route_sources() -> list[dict]:
    results = []
    texts = []
    for route_file in ROUTE_FILES:
        if not route_file.exists():
            results.append(
                {
                    "check": f"Route source exists: {route_file.name}",
                    "pass": False,
                    "detail": "file missing",
                }
            )
            continue
        results.append(
            {
                "check": f"Route source exists: {route_file.name}",
                "pass": True,
                "detail": str(route_file.relative_to(ROOT)),
            }
        )
        texts.append(route_file.read_text(encoding="utf-8"))

    combined = "\n".join(texts)
    for path in ENDPOINT_PATHS:
        found = path in combined
        results.append(
            {
                "check": f"Source route path: {path}",
                "pass": found,
                "detail": "found" if found else "missing",
            }
        )
    return results


def _endpoint_lookup(endpoints: list[dict], method: str, path: str) -> dict | None:
    for endpoint in endpoints:
        if endpoint.get("method") == method and endpoint.get("path") == path:
            return endpoint
    return None


def _is_json_false(value: object) -> bool:
    return isinstance(value, bool) and not value


def check_report() -> list[dict]:
    results = []
    if not REPORT.exists():
        return [{"check": "Report exists", "pass": False, "detail": "file missing"}]

    data = json.loads(REPORT.read_text(encoding="utf-8"))
    endpoints = data.get("endpoints", [])
    baselines = data.get("performance_baselines", [])
    middleware = data.get("middleware_coverage", {})
    transport = data.get("transport_boundary", {})

    for key in [
        "endpoints",
        "middleware_coverage",
        "transport_boundary",
        "performance_baselines",
        "generated_at",
    ]:
        results.append(
            {
                "check": f"Report key: {key}",
                "pass": key in data,
                "detail": "present" if key in data else "missing",
            }
        )

    results.append(
        {
            "check": "Report: 12 base endpoints",
            "pass": len(endpoints) == 12,
            "detail": f"{len(endpoints)} endpoints",
        }
    )
    results.append(
        {
            "check": "Report: 12 performance baselines",
            "pass": len(baselines) == 12,
            "detail": f"{len(baselines)} baselines",
        }
    )

    groups: dict[str, int] = {}
    for endpoint in endpoints:
        group = endpoint.get("group", "unknown")
        groups[group] = groups.get(group, 0) + 1

    results.append(
        {
            "check": "Report: 4 operator endpoints",
            "pass": groups.get("operator") == 4,
            "detail": f"{groups.get('operator', 0)} operator",
        }
    )
    results.append(
        {
            "check": "Report: 3 verifier endpoints",
            "pass": groups.get("verifier") == 3,
            "detail": f"{groups.get('verifier', 0)} verifier",
        }
    )
    results.append(
        {
            "check": "Report: 5 fleet_control endpoints",
            "pass": groups.get("fleet_control") == 5,
            "detail": f"{groups.get('fleet_control', 0)} fleet_control",
        }
    )

    results.append(
        {
            "check": "Report: all conformance pass",
            "pass": all(endpoint.get("conformance_status") == "pass" for endpoint in endpoints),
            "detail": "all pass"
            if all(endpoint.get("conformance_status") == "pass" for endpoint in endpoints)
            else "some fail",
        }
    )
    results.append(
        {
            "check": "Report: all endpoints traced",
            "pass": all(endpoint.get("trace_propagation") is True for endpoint in endpoints),
            "detail": "all traced"
            if all(endpoint.get("trace_propagation") is True for endpoint in endpoints)
            else "some untraced",
        }
    )
    results.append(
        {
            "check": "Report: all paths versioned /v1/",
            "pass": all(endpoint.get("path", "").startswith("/v1/") for endpoint in endpoints),
            "detail": "all versioned"
            if all(endpoint.get("path", "").startswith("/v1/") for endpoint in endpoints)
            else "some unversioned",
        }
    )
    results.append(
        {
            "check": "Report: all endpoints have status codes",
            "pass": all(len(endpoint.get("status_codes", [])) > 0 for endpoint in endpoints),
            "detail": "all have codes"
            if all(len(endpoint.get("status_codes", [])) > 0 for endpoint in endpoints)
            else "some empty",
        }
    )

    for method, path in ENDPOINTS:
        found = _endpoint_lookup(endpoints, method, path) is not None
        results.append(
            {
                "check": f"Report: endpoint {method} {path}",
                "pass": found,
                "detail": "found" if found else "missing",
            }
        )

    results.append(
        {
            "check": "Report: transport boundary kind in_process_catalog",
            "pass": transport.get("kind") == "in_process_catalog",
            "detail": transport.get("kind", "missing"),
        }
    )
    results.append(
        {
            "check": "Report: transport boundary owns_listener false",
            "pass": transport.get("owns_listener") is False,
            "detail": str(transport.get("owns_listener")),
        }
    )
    results.append(
        {
            "check": "Report: transport boundary bind target hint",
            "pass": transport.get("bind_target_hint") == "127.0.0.1:9090",
            "detail": transport.get("bind_target_hint", "missing"),
        }
    )
    results.append(
        {
            "check": "Report: request lifecycle caller-owned",
            "pass": transport.get("request_lifecycle")
            == "caller-owned in-process dispatch only",
            "detail": transport.get("request_lifecycle", "missing"),
        }
    )
    results.append(
        {
            "check": "Report: cancellation semantics non-transport-owned",
            "pass": transport.get("cancellation_semantics")
            == "no transport-owned cancellation boundary",
            "detail": transport.get("cancellation_semantics", "missing"),
        }
    )

    for key in [
        "auth_coverage",
        "policy_hook_coverage",
        "error_formatting_coverage",
        "tracing_coverage",
        "rate_limiting_coverage",
    ]:
        results.append(
            {
                "check": f"Report: middleware {key}",
                "pass": middleware.get(key) is True,
                "detail": str(middleware.get(key)),
            }
        )

    results.append(
        {
            "check": "Report: baselines explicitly unavailable pending transport",
            "pass": all(
                baseline.get("status") == "unavailable_pending_transport"
                for baseline in baselines
            ),
            "detail": "all unavailable"
            if all(
                baseline.get("status") == "unavailable_pending_transport"
                for baseline in baselines
            )
            else "status drift",
        }
    )
    results.append(
        {
            "check": "Report: baselines omit fake numeric latencies",
            "pass": all(
                baseline.get("p50_ms") is None
                and baseline.get("p95_ms") is None
                and baseline.get("p99_ms") is None
                for baseline in baselines
            ),
            "detail": "all null" if all(
                baseline.get("p50_ms") is None
                and baseline.get("p95_ms") is None
                and baseline.get("p99_ms") is None
                for baseline in baselines
            ) else "numeric drift",
        }
    )
    results.append(
        {
            "check": "Report: baselines carry truthful provenance",
            "pass": all(baseline.get("provenance") == BASELINE_PROVENANCE for baseline in baselines),
            "detail": "all match" if all(
                baseline.get("provenance") == BASELINE_PROVENANCE for baseline in baselines
            ) else "provenance drift",
        }
    )

    operator_health = _endpoint_lookup(endpoints, "GET", "/v1/operator/health")
    results.append(
        {
            "check": "Report: operator health is unauthenticated",
            "pass": operator_health is not None and operator_health.get("auth_method") == "None",
            "detail": operator_health.get("auth_method", "missing")
            if operator_health
            else "missing endpoint",
        }
    )

    operator_api_key_paths = [
        "/v1/operator/status",
        "/v1/operator/config",
        "/v1/operator/rollout",
    ]
    results.append(
        {
            "check": "Report: operator read endpoints use ApiKey",
            "pass": all(
                (_endpoint_lookup(endpoints, "GET", path) or {}).get("auth_method") == "ApiKey"
                for path in operator_api_key_paths
            ),
            "detail": "all ApiKey"
            if all(
                (_endpoint_lookup(endpoints, "GET", path) or {}).get("auth_method") == "ApiKey"
                for path in operator_api_key_paths
            )
            else "auth drift",
        }
    )

    verifier_paths = [
        ("POST", "/v1/verifier/conformance"),
        ("GET", "/v1/verifier/evidence/{check_id}"),
        ("GET", "/v1/verifier/audit-log"),
    ]
    results.append(
        {
            "check": "Report: verifier endpoints use BearerToken",
            "pass": all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "BearerToken"
                for method, path in verifier_paths
            ),
            "detail": "all BearerToken"
            if all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "BearerToken"
                for method, path in verifier_paths
            )
            else "auth drift",
        }
    )

    bearer_fleet_paths = [
        ("GET", "/v1/fleet/leases"),
        ("POST", "/v1/fleet/leases"),
        ("DELETE", "/v1/fleet/leases/{lease_id}"),
    ]
    results.append(
        {
            "check": "Report: lease endpoints use BearerToken",
            "pass": all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "BearerToken"
                for method, path in bearer_fleet_paths
            ),
            "detail": "all BearerToken"
            if all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "BearerToken"
                for method, path in bearer_fleet_paths
            )
            else "auth drift",
        }
    )

    mtls_fleet_paths = [
        ("POST", "/v1/fleet/fence"),
        ("POST", "/v1/fleet/coordinate"),
    ]
    results.append(
        {
            "check": "Report: fence and coordinate use MtlsClientCert",
            "pass": all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "MtlsClientCert"
                for method, path in mtls_fleet_paths
            ),
            "detail": "all MtlsClientCert"
            if all(
                (_endpoint_lookup(endpoints, method, path) or {}).get("auth_method")
                == "MtlsClientCert"
                for method, path in mtls_fleet_paths
            )
            else "auth drift",
        }
    )

    return results


def check_control_plane_catalog_artifact(
    artifact_path: Path = CONTROL_PLANE_CATALOG_ARTIFACT,
    report_path: Path = REPORT,
) -> list[dict]:
    results = []
    if not artifact_path.exists():
        return [
            {
                "check": "Control-plane catalog artifact exists",
                "pass": False,
                "detail": f"missing: {safe_rel(artifact_path)}",
            }
        ]

    if not report_path.exists():
        return [
            {
                "check": "Control-plane catalog canonical report exists",
                "pass": False,
                "detail": f"missing: {safe_rel(report_path)}",
            }
        ]

    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            {
                "check": "Control-plane catalog artifact JSON parses",
                "pass": False,
                "detail": str(exc),
            }
        ]

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            {
                "check": "Control-plane catalog canonical report JSON parses",
                "pass": False,
                "detail": str(exc),
            }
        ]

    endpoints = report.get("endpoints", [])
    baselines = report.get("performance_baselines", [])
    group_counts: dict[str, int] = {}
    for endpoint in endpoints:
        group = endpoint.get("group", "unknown")
        group_counts[group] = group_counts.get(group, 0) + 1

    expected_report_rel = safe_rel(report_path)
    artifact_boundary = artifact.get("transport_boundary", {})
    report_boundary = report.get("transport_boundary", {})
    expected_group_counts = {"operator": 4, "verifier": 3, "fleet_control": 5}

    results.extend(
        [
            {
                "check": "Control-plane catalog artifact: bead id",
                "pass": artifact.get("bead_id") == PERF_BASELINE_BEAD_ID,
                "detail": str(artifact.get("bead_id")),
            },
            {
                "check": "Control-plane catalog artifact: stable artifact id",
                "pass": artifact.get("artifact_id") == "control_plane_catalog",
                "detail": str(artifact.get("artifact_id")),
            },
            {
                "check": "Control-plane catalog artifact: canonical report linked",
                "pass": artifact.get("canonical_endpoint_report") == expected_report_rel,
                "detail": str(artifact.get("canonical_endpoint_report")),
            },
            {
                "check": "Control-plane catalog artifact: endpoint count matches report",
                "pass": artifact.get("endpoint_count") == len(endpoints) == 12,
                "detail": f"artifact={artifact.get('endpoint_count')} report={len(endpoints)}",
            },
            {
                "check": "Control-plane catalog artifact: group counts match report",
                "pass": artifact.get("group_counts") == group_counts == expected_group_counts,
                "detail": f"artifact={artifact.get('group_counts')} report={group_counts}",
            },
            {
                "check": "Control-plane catalog artifact: boundary kind matches report",
                "pass": artifact_boundary.get("kind") == report_boundary.get("kind")
                == "in_process_catalog",
                "detail": f"artifact={artifact_boundary.get('kind')} report={report_boundary.get('kind')}",
            },
            {
                "check": "Control-plane catalog artifact: listener ownership matches report",
                "pass": _is_json_false(artifact_boundary.get("owns_listener"))
                and _is_json_false(report_boundary.get("owns_listener")),
                "detail": (
                    f"artifact={artifact_boundary.get('owns_listener')} "
                    f"report={report_boundary.get('owns_listener')}"
                ),
            },
            {
                "check": "Control-plane catalog artifact: baseline status matches report",
                "pass": artifact.get("performance_baseline_status")
                == "unavailable_pending_transport"
                and all(
                    baseline.get("status") == "unavailable_pending_transport"
                    for baseline in baselines
                ),
                "detail": str(artifact.get("performance_baseline_status")),
            },
            {
                "check": "Control-plane catalog artifact: fake numeric latencies absent",
                "pass": _is_json_false(artifact.get("numeric_latency_baselines_present"))
                and all(
                    baseline.get("p50_ms") is None
                    and baseline.get("p95_ms") is None
                    and baseline.get("p99_ms") is None
                    for baseline in baselines
                ),
                "detail": str(artifact.get("numeric_latency_baselines_present")),
            },
        ]
    )

    evidence_paths = set(artifact.get("evidence_paths", []))
    required_paths = {
        expected_report_rel,
        safe_rel(IMPL),
        safe_rel(SPEC),
        safe_rel(Path(__file__).resolve()),
    }
    results.append(
        {
            "check": "Control-plane catalog artifact: evidence paths cited",
            "pass": required_paths.issubset(evidence_paths),
            "detail": ", ".join(sorted(evidence_paths)) if evidence_paths else "none",
        }
    )

    return results


def check_spec() -> list[dict]:
    results = []
    if not SPEC.exists():
        return [{"check": "Spec doc exists", "pass": False, "detail": "file missing"}]

    text = SPEC.read_text(encoding="utf-8")
    for section in [
        "Purpose",
        "Scope",
        "Types",
        "Methods",
        "Report Contract",
        "Acceptance Criteria",
    ]:
        results.append(
            {
                "check": f"Spec: has {section}",
                "pass": f"## {section}" in text,
                "detail": "found" if f"## {section}" in text else "missing",
            }
        )

    for marker in SPEC_MARKERS:
        results.append(
            {
                "check": f"Spec marker: {marker}",
                "pass": marker in text,
                "detail": "found" if marker in text else "missing",
            }
        )

    return results


def _path_truth_checks(text: str, label: str) -> list[dict]:
    obsolete_matches = sorted(
        {obsolete_path for obsolete_path in OBSOLETE_SERVICE_PATHS if obsolete_path in text}
    )
    return [
        {
            "check": f"Path truth: {label} names canonical API service path",
            "pass": CANONICAL_SERVICE_PATH in text,
            "detail": CANONICAL_SERVICE_PATH
            if CANONICAL_SERVICE_PATH in text
            else "canonical path missing",
        },
        {
            "check": f"Path truth: {label} omits obsolete service skeleton path",
            "pass": not obsolete_matches,
            "detail": "absent" if not obsolete_matches else ", ".join(obsolete_matches),
        },
    ]


def check_path_truth() -> list[dict]:
    if not SPEC.exists():
        return [{"check": "Path truth: spec doc exists", "pass": False, "detail": "file missing"}]
    return _path_truth_checks(SPEC.read_text(encoding="utf-8"), safe_rel(SPEC))


def check_completion_debt_evidence() -> list[dict]:
    results = []
    if not REPLACEMENT_EVIDENCE.exists():
        return [
            {
                "check": "Completion debt evidence exists",
                "pass": False,
                "detail": f"missing: {safe_rel(REPLACEMENT_EVIDENCE)}",
            }
        ]

    try:
        data = json.loads(REPLACEMENT_EVIDENCE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [
            {
                "check": "Completion debt evidence JSON parses",
                "pass": False,
                "detail": str(exc),
            }
        ]

    results.append(
        {
            "check": "Completion debt evidence: replacement bead id",
            "pass": data.get("bead_id") == REPLACEMENT_BEAD_ID,
            "detail": str(data.get("bead_id")),
        }
    )
    results.append(
        {
            "check": "Completion debt evidence: debt bead id",
            "pass": data.get("completion_debt_bead_id") == COMPLETION_DEBT_BEAD,
            "detail": str(data.get("completion_debt_bead_id")),
        }
    )

    covered = set(data.get("completion_debt", {}).get("covered_spec_items", []))
    results.append(
        {
            "check": "Completion debt evidence: integration item covered",
            "pass": set(COMPLETION_DEBT_ITEMS).issubset(covered),
            "detail": ", ".join(sorted(covered)) if covered else "none",
        }
    )

    obligations = {
        obligation.get("spec_item"): obligation
        for obligation in data.get("completion_debt", {}).get("obligations", [])
    }
    integration = obligations.get("tests.integration.primary", {})
    evidence_paths = set(integration.get("evidence_paths", []))
    results.append(
        {
            "check": "Completion debt evidence: cargo integration test cited",
            "pass": str(CARGO_INTEGRATION.relative_to(ROOT)) in evidence_paths,
            "detail": ", ".join(sorted(evidence_paths)) if evidence_paths else "none",
        }
    )

    test_names = set(integration.get("test_names", []))
    results.append(
        {
            "check": "Completion debt evidence: integration test names cited",
            "pass": set(REQUIRED_INTEGRATION_TESTS).issubset(test_names),
            "detail": ", ".join(sorted(test_names)) if test_names else "none",
        }
    )

    return results


def run_checks() -> dict:
    checks = []

    checks.append(check_file(IMPL, "control-plane service implementation"))
    for route_file in ROUTE_FILES:
        checks.append(check_file(route_file, route_file.name))
    checks.append(check_file(REPORT, "endpoint report"))
    checks.append(check_file(CONTROL_PLANE_CATALOG_ARTIFACT, "control-plane catalog artifact"))
    checks.append(check_file(SPEC, "spec doc"))
    checks.append(check_file(CARGO_INTEGRATION, "cargo-visible integration test"))
    checks.append(check_file(REPLACEMENT_EVIDENCE, "completion-debt evidence"))
    checks.append(check_file(REPLACEMENT_SUMMARY, "completion-debt summary"))

    checks.append(check_impl_test_count())
    checks.extend(check_content(IMPL, REQUIRED_TYPES, "type"))
    checks.extend(check_content(IMPL, REQUIRED_METHODS, "method"))
    checks.extend(check_content(IMPL, REQUIRED_TESTS, "test"))
    checks.extend(check_content(CARGO_INTEGRATION, REQUIRED_INTEGRATION_TESTS, "integration test"))
    checks.extend(check_content(CARGO_INTEGRATION, INTEGRATION_MARKERS, "integration marker"))
    checks.extend(check_route_sources())
    checks.extend(check_report())
    checks.extend(check_control_plane_catalog_artifact())
    checks.extend(check_spec())
    checks.extend(check_path_truth())
    checks.extend(check_completion_debt_evidence())

    passing = sum(1 for check in checks if check["pass"])
    failing = sum(1 for check in checks if not check["pass"])

    return {
        "bead_id": "bd-2f5l",
        "title": "control-plane catalog boundary",
        "section": "10.16",
        "overall_pass": failing == 0,
        "verdict": "PASS" if failing == 0 else "FAIL",
        "summary": {"passing": passing, "failing": failing, "total": len(checks)},
        "checks": checks,
    }


def self_test() -> tuple[bool, str]:
    result = run_checks()
    if result["overall_pass"]:
        return True, f"All {result['summary']['total']} checks pass"
    fails = [check["check"] for check in result["checks"] if not check["pass"]]
    return False, f"{len(fails)} failing: {'; '.join(fails[:5])}"


if __name__ == "__main__":
    logger = configure_test_logging("check_fastapi_skeleton")
    logger.info("starting %s verification", "check_fastapi_skeleton")
    result = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        for check in result["checks"]:
            mark = "PASS" if check["pass"] else "FAIL"
            print(f"  [{mark}] {check['check']}: {check['detail']}")
        print()
        summary = result["summary"]
        print(f"Result: {result['verdict']} ({summary['passing']}/{summary['total']} checks pass)")

    sys.exit(0 if result["overall_pass"] else 1)
