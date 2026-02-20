# bd-2f5l: fastapi_rust Service Skeleton

**Section:** 10.16 — Adjacent Substrate Integration
**Status:** Implementation Complete

## Purpose

Build the HTTP service skeleton for control-plane endpoints required by
operator, verifier, and fleet-control consumers. Endpoint groups, middleware
pipeline, auth methods, and error mapping follow the bd-3ndj integration
contract.

## Scope

- 10 canonical endpoints across 3 groups (operator, verifier, fleet_control)
- 6-layer middleware pipeline (trace → auth → authz → rate-limit → error → telemetry)
- 3 auth methods (API key, mTLS cert, bearer token) mapped per group
- Versioned paths under `/v1/` with trace propagation on all endpoints
- Gate blocking on missing groups, incomplete middleware, or untraced endpoints

## Types

| Type | Kind | Description |
|------|------|-------------|
| `EndpointLifecycle` | enum | Experimental, Stable, Deprecated, Removed |
| `EndpointGroup` | enum | Operator, Verifier, FleetControl |
| `HttpMethod` | enum | Get, Post, Put, Delete |
| `AuthMethod` | enum | ApiKey, MtlsCert, BearerToken |
| `MiddlewareLayer` | enum | TraceContext, Authentication, Authorization, RateLimit, ErrorFormatting, Telemetry |
| `EndpointDef` | struct | Group, path, method, auth, policy hook, lifecycle, status codes, trace flag |
| `ServiceEvent` | struct | Code, endpoint, detail |
| `FastapiSkeletonGate` | struct | Gate engine with endpoints, middleware, events |
| `SkeletonSummary` | struct | Aggregate counts by group and middleware |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `EndpointLifecycle::all()` | Lifecycle | All four variants |
| `EndpointLifecycle::label()` | Lifecycle | Human-readable label |
| `EndpointLifecycle::is_active()` | Lifecycle | True for experimental, stable, deprecated |
| `EndpointGroup::all()` | Group | All three variants |
| `EndpointGroup::label()` | Group | Human-readable label |
| `HttpMethod::label()` | Method | HTTP verb string |
| `AuthMethod::label()` | Auth | Auth method identifier |
| `MiddlewareLayer::all()` | Middleware | All six layers |
| `MiddlewareLayer::label()` | Middleware | Layer identifier |
| `FastapiSkeletonGate::new()` | Gate | Initialize with INIT event |
| `FastapiSkeletonGate::register_endpoint()` | Gate | Register endpoint definition |
| `FastapiSkeletonGate::wire_middleware()` | Gate | Wire middleware layer |
| `FastapiSkeletonGate::gate_pass()` | Gate | True if all groups covered, all middleware wired, all traced |
| `FastapiSkeletonGate::summary()` | Gate | Aggregate counts |
| `FastapiSkeletonGate::endpoints()` | Gate | Borrow endpoint list |
| `FastapiSkeletonGate::events()` | Gate | Borrow event log |
| `FastapiSkeletonGate::take_events()` | Gate | Drain event log |
| `FastapiSkeletonGate::to_report()` | Gate | Structured JSON report |

## Event Codes

| Code | Level | Trigger |
|------|-------|---------|
| `FASTAPI_SKELETON_INIT` | info | Service skeleton initialized |
| `FASTAPI_ENDPOINT_REGISTERED` | info | Endpoint registered |
| `FASTAPI_MIDDLEWARE_WIRED` | info | Middleware layer wired |
| `FASTAPI_AUTH_REJECT` | error | Authentication rejected |
| `FASTAPI_RATE_LIMIT_HIT` | warn | Rate limit exceeded |
| `FASTAPI_ERROR_RESPONSE` | error | Error response emitted |

## Invariants

| ID | Rule |
|----|------|
| `INV-FAS-ENDPOINTS` | All three endpoint groups have at least one endpoint |
| `INV-FAS-MIDDLEWARE` | All six middleware layers are wired |
| `INV-FAS-AUTH` | Each group uses its designated auth method |
| `INV-FAS-ERRORS` | All endpoints declare status codes |

## Artifacts

| File | Description |
|------|-------------|
| `tests/integration/fastapi_control_plane_endpoints.rs` | 38 Rust conformance tests |
| `artifacts/10.16/fastapi_endpoint_report.json` | 10 endpoint conformance results |
| `scripts/check_fastapi_skeleton.py` | Verification script |
| `tests/test_check_fastapi_skeleton.py` | Python unit tests |

## Acceptance Criteria

1. All 10 endpoints from bd-3ndj contract have definitions
2. 4 operator endpoints use ApiKey auth
3. 3 verifier endpoints use BearerToken auth
4. 3 fleet-control endpoints use MtlsCert auth
5. All 6 middleware layers wired
6. All endpoints have trace propagation enabled
7. All endpoints under `/v1/` versioned paths
8. All endpoints declare non-empty status code sets
9. At least 35 Rust conformance tests
10. Verification script passes all checks with `--json` output
