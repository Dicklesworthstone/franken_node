# fastapi_rust Integration Contract (`bd-3ndj`)

## Purpose

This contract defines how `franken_node` exposes control-plane HTTP surfaces through `fastapi_rust` with consistent lifecycle, authentication/authorization hooks, error mapping, observability, and rate limiting.

## Scope

- Applies to operator, verifier, and fleet-control service surfaces.
- Governs endpoint registration lifecycle and cross-cutting middleware behavior.
- Defines canonical mapping from connector error codes to HTTP problem responses.

## Endpoint Lifecycle Definition

Lifecycle states:
- `experimental`
- `stable`
- `deprecated`
- `removed`

Transition rules:
- `experimental -> stable`: requires contract tests and telemetry baselines.
- `stable -> deprecated`: requires operator notice and migration path.
- `deprecated -> removed`: requires minimum deprecation period of 90 days.
- Direct `stable -> removed` is forbidden.

Versioning rule:
- Endpoint path versions are explicit (`/v1/...`, `/v2/...`).
- Breaking response-shape changes require new major endpoint version.

## Endpoint Groups

Required groups:
- Operator endpoints: node status, health, configuration, rollout state.
- Verifier endpoints: conformance trigger, evidence retrieval, audit-log query.
- Fleet-control endpoints: lease management, fencing operations, multi-node coordination.

All groups must define:
- lifecycle state
- auth method
- policy hook

## Auth and Policy Hooks

Middleware order:
1. Trace context extraction
2. Authentication (mTLS/API key/token)
3. Authorization (RBAC + policy hook)
4. Rate-limit / anti-amplification guard
5. Handler execution
6. Structured response + telemetry emission

Policy hook registration:
- Each route binds a named policy hook ID from control-plane policy modules.
- Hook result must be explicit allow/deny with reason code.
- Deny responses must include a stable problem code and trace ID.

## Error Contract Mapping

- Source registry: `crates/franken-node/src/connector/error_code_registry.rs`
- Response schema: RFC 7807 Problem Details (`application/problem+json`)
- Required fields: `type`, `title`, `status`, `detail`, `instance`, `code`, `trace_id`
- All known `FRANKEN_*` registry codes must have explicit HTTP mapping.

## Observability Requirements

- Trace context propagation via `crates/franken-node/src/connector/trace_context.rs`
- Structured request/response logs (method, route, status, latency_ms, trace_id)
- Latency metrics at p50/p95/p99 by endpoint group and route
- OpenTelemetry export for spans and metrics
- Error cardinality metrics by `FRANKEN_*` code

## Rate Limiting and Anti-Amplification

- Endpoint throttling integrates with `crates/franken-node/src/connector/anti_amplification.rs`.
- Limits are group-specific and fail-closed for dangerous/fleet-control mutations.
- Burst + sustained controls required for operator and verifier APIs.

## Event Codes

- `FASTAPI_CONTRACT_LOADED` (info)
- `FASTAPI_ENDPOINT_UNMAPPED` (error)
- `FASTAPI_ERROR_MAPPING_INCOMPLETE` (error)
- `FASTAPI_AUTH_UNDEFINED` (error)

All contract events include `trace_correlation` as SHA-256 of canonical checklist JSON.

## Artifact Linkage

- `artifacts/10.16/fastapi_contract_checklist.json`
- `scripts/check_fastapi_contract.py`
- `tests/test_check_fastapi_contract.py`
- `artifacts/section_10_16/bd-3ndj/verification_evidence.json`
- `artifacts/section_10_16/bd-3ndj/verification_summary.md`
