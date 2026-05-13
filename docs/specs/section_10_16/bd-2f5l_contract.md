# bd-2f5l: Control-Plane Catalog Boundary

**Section:** 10.16 — Adjacent Substrate Integration  
**Status:** Truthful deferred boundary

## Purpose

Document and verify the in-process control-plane catalog boundary exposed by
`crates/franken-node/src/api/service.rs`.

This surface assembles operator, verifier, and fleet-control route metadata,
middleware coverage, and endpoint reporting. It is not a live HTTP/gRPC server,
must not claim transport-owned lifecycle semantics, and must not emit fake
performance baselines.

## Scope

- 12 base-catalog endpoints across 3 groups:
  - operator: 4
  - verifier: 3
  - fleet_control: 5
- Middleware coverage reporting for the assembled catalog
- Explicit transport boundary status for the in-process control-plane catalog boundary
- Performance baselines marked unavailable pending transport ownership
- Structured request lifecycle provenance capture for recorded dispatches
- Truthful artifact output in `artifacts/10.16/fastapi_endpoint_report.json`

feature/test-only quarantine routes remain out of scope for the base artifact.
Those extra routes are compiled under `cfg(test)` or `extended-surfaces` and
must not be counted as part of the non-test live catalog boundary.

## Types

| Type | Kind | Description |
|------|------|-------------|
| `ServiceConfig` | struct | Bind hint, rate-limit overrides, telemetry flag, service name, runtime config snapshot |
| `EndpointCatalogEntry` | struct | Catalog row with group, path, method, auth method, policy hook, lifecycle, trace flag, status codes, and conformance status |
| `MiddlewareCoverage` | struct | Coverage booleans for auth, policy hooks, error formatting, tracing, and rate limiting |
| `TransportBoundaryKind` | enum | `in_process_catalog` or `live_transport` |
| `TransportBoundaryStatus` | struct | Truthful statement of listener ownership, bind hint, request lifecycle, and cancellation semantics |
| `PerformanceBaselineStatus` | enum | `measured` or `unavailable_pending_transport` |
| `PerformanceBaseline` | struct | Endpoint baseline record with status, optional p50/p95/p99 metrics, and provenance |
| `RequestLifecycleProvenance` | struct | Structured request event record tying a recorded dispatch to truthful transport ownership and perf-baseline provenance |
| `EndpointReport` | struct | Full report artifact containing endpoints, coverage, transport boundary, baselines, and generation timestamp |
| `ControlPlaneService` | struct | In-process catalog/dispatch assembly layer with metrics and rate limiters |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `build_endpoint_catalog()` | Service surface | Assemble the base route catalog from operator, verifier, and fleet-control metadata |
| `all_route_metadata()` | Service surface | Collect route metadata from authoritative route modules |
| `check_middleware_coverage()` | Service surface | Report whether every route carries the required middleware wiring |
| `generate_endpoint_report(config)` | Service surface | Produce the truthful endpoint report artifact |
| `ControlPlaneService::new(config)` | Service surface | Initialize the in-process catalog/dispatch layer |
| `ControlPlaneService::config()` | Service surface | Return the stored service configuration |
| `ControlPlaneService::metrics()` | Service surface | Return collected service metrics |
| `ControlPlaneService::request_count()` | Service surface | Return the recorded request count |
| `ControlPlaneService::limiter_for_group(group)` | Service surface | Access the limiter for an endpoint group |
| `ControlPlaneService::record(log)` | Service surface | Record a request log into service metrics and capture request lifecycle provenance |
| `ControlPlaneService::request_lifecycle_provenance(endpoint_group, route_path)` | Service surface | Build the truthful transport/perf provenance record for one dispatch |
| `ControlPlaneService::request_lifecycle_events()` | Service surface | Return the structured request lifecycle provenance captured by `record(log)` |
| `ControlPlaneService::catalog()` | Service surface | Return the endpoint catalog |
| `ControlPlaneService::transport_boundary()` | Service surface | Return truthful boundary ownership status |
| `ControlPlaneService::report()` | Service surface | Return the endpoint report |

## Report Contract

`artifacts/10.16/fastapi_endpoint_report.json` is the current artifact contract.
It must serialize the same structural truth that `EndpointReport` exposes:

- `endpoints`
- `middleware_coverage`
- `transport_boundary`
- `performance_baselines`
- `generated_at`

The report must satisfy all of the following:

1. The transport boundary kind is `in_process_catalog`.
2. `owns_listener` is `false`.
3. `request_lifecycle` is `caller-owned in-process dispatch only`.
4. `cancellation_semantics` is `no transport-owned cancellation boundary`.
5. Every performance baseline row is `unavailable_pending_transport`.
6. `p50_ms`, `p95_ms`, and `p99_ms` are `null` until a real transport exists.
7. Provenance text states that baselines are intentionally unavailable pending transport ownership.
8. No fake gate verdict or synthetic `0.0` latency numbers appear in the artifact.

`artifacts/replacement_gap/bd-2fqyv.5.3/control_plane_catalog.json` is the
bead-local discoverability index for the same control-plane catalog boundary.
It must point at the canonical endpoint report above and repeat only the summary
facts needed to find and validate the boundary: endpoint count, group counts,
transport ownership, and unavailable-baseline semantics.

## Acceptance Criteria

1. The base artifact contains 12 endpoints across operator (4), verifier (3), and fleet_control (5).
2. `GET /v1/operator/health` is explicitly unauthenticated.
3. The remaining operator read endpoints use `ApiKey`.
4. All verifier endpoints use `BearerToken`.
5. Fleet lease endpoints use `BearerToken`, while fence/coordinate use `MtlsClientCert`.
6. All endpoints remain versioned under `/v1/` and declare non-empty status-code sets.
7. Middleware coverage booleans are all `true`.
8. The artifact declares an in-process control-plane catalog boundary rather than a live service.
9. Performance baselines are unavailable pending transport and never encoded as fake numeric measurements.
10. `scripts/check_fastapi_skeleton.py --json` passes against the live artifact and `tests/test_check_fastapi_skeleton.py` passes.
11. `ControlPlaneService::record(log)` captures request lifecycle provenance that remains truthful about in-process dispatch and unavailable transport baselines.

## Artifacts

| File | Description |
|------|-------------|
| `crates/franken-node/src/api/service.rs` | Authoritative control-plane catalog/report implementation |
| `crates/franken-node/src/api/operator_routes.rs` | Operator route metadata source |
| `crates/franken-node/src/api/verifier_routes.rs` | Verifier route metadata source |
| `crates/franken-node/src/api/fleet_control_routes.rs` | Fleet-control route metadata source |
| `artifacts/10.16/fastapi_endpoint_report.json` | Truthful base-catalog endpoint report |
| `artifacts/replacement_gap/bd-2fqyv.5.3/control_plane_catalog.json` | Bead-local discoverability index for the control-plane catalog artifact |
| `scripts/check_fastapi_skeleton.py` | Verification script for the live catalog boundary |
| `tests/test_check_fastapi_skeleton.py` | Python unit tests for the verification script |
