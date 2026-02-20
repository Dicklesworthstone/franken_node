# RemoteCap Contract (bd-1nfu)

## Purpose

`RemoteCap` is the mandatory authorization primitive for **network-bound trust/control operations**.
It keeps local-only behavior functional while enforcing explicit, auditable grants for remote effects.

## Core Types

### `RemoteCap`

Signed token with:

- `token_id` (deterministic identifier)
- `issuer_identity` (operator/service identity)
- `issued_at_epoch_secs`
- `expires_at_epoch_secs`
- `scope.operations` (allowed remote operations)
- `scope.endpoint_prefixes` (allowed endpoint prefixes)
- `signature` (keyed SHA-256 over canonical payload)
- `single_use` (replay-protected one-shot token)

### `CapabilityProvider`

Only issuance path for `RemoteCap`.

- Requires explicit operator authorization.
- Produces `REMOTECAP_ISSUED` (`RC_CAP_GRANTED`) audit event.
- Rejects zero/invalid TTL.

### `CapabilityGate`

Single enforcement point for remote operations.

- Validates presence, signature, expiry, scope, replay, revocation.
- Emits `REMOTECAP_CONSUMED` / `REMOTECAP_DENIED` events.
- Supports `LocalOnly` mode logging via `REMOTECAP_LOCAL_MODE_ACTIVE`.

## Invariants

- `INV-REMOTECAP-REQUIRED`: Every network-bound operation must pass `CapabilityGate::authorize_network`.
- `INV-REMOTECAP-UNFORGEABLE`: No public constructor exists for `RemoteCap`; issuance is provider-only.
- `INV-REMOTECAP-FAIL-CLOSED`: Missing/invalid/expired/out-of-scope/replayed/revoked tokens deny operation.
- `INV-REMOTECAP-SINGLE-CHECKPOINT`: Validation logic is centralized; no scattered ad-hoc checks.
- `INV-REMOTECAP-LOCAL-OPERABILITY`: Local-only operations can run without `RemoteCap`.
- `INV-REMOTECAP-AUDIT`: Every issue/check/revoke path emits structured audit entries with trace IDs.

## Error Codes

- `REMOTECAP_MISSING` (compatibility alias: `ERR_REMOTE_CAP_REQUIRED`)
- `REMOTECAP_OPERATOR_AUTH_REQUIRED`
- `REMOTECAP_TTL_INVALID`
- `REMOTECAP_EXPIRED`
- `REMOTECAP_INVALID`
- `REMOTECAP_SCOPE_DENIED`
- `REMOTECAP_REVOKED`
- `REMOTECAP_REPLAY`

## Event Codes

### Canonical

- `REMOTECAP_ISSUED`
- `REMOTECAP_CONSUMED`
- `REMOTECAP_DENIED`
- `REMOTECAP_REVOKED`
- `REMOTECAP_LOCAL_MODE_ACTIVE`

### Legacy compatibility

- `RC_CAP_GRANTED`
- `RC_CHECK_PASSED`
- `RC_CHECK_DENIED`
- `RC_CAP_REVOKED`
- `RC_LOCAL_MODE_ACTIVE`

## Enforcement Surface

### Network Guard Integration

`security/network_guard.rs::NetworkGuard::process_egress(...)` now requires:

- `remote_cap: Option<&RemoteCap>`
- `capability_gate: &mut CapabilityGate`
- `now_epoch_secs`

Capability validation runs **before** policy allow/deny evaluation.

## CLI Contract

Required operator flow:

```bash
franken-node remotecap issue --scope <scope> --ttl <duration> --operator-approved
```

Current implementation exposes issuance primitives in Rust (`CapabilityProvider::issue`) and keeps this CLI contract as the normative command surface.

