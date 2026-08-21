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
# Issue a capability token
franken-node remotecap issue \
  --scope network_egress,federation_sync,telemetry_export \
  --endpoint https://api.example.com \
  --endpoint federation://trusted-node \
  --ttl 15m \
  --issuer operator-cli \
  --operator-approved \
  --single-use \
  --json > capability.json

# Verify the token (without consuming single-use tokens)
franken-node remotecap verify \
  --token-file capability.json \
  --operation network_egress \
  --endpoint https://api.example.com/v1/status \
  --json

# Use the token for a network operation (consumes single-use tokens).
# Current CLI is dry-run: it authorizes and may consume the token, but does
# not send HTTP. JSON reports dry_run=true, request_executed=false.
franken-node remotecap use \
  --token-file capability.json \
  --operation network_egress \
  --endpoint https://api.example.com/v1/status \
  --json

# Revoke the token when done
franken-node remotecap revoke \
  --token-file capability.json \
  --json
```

The CLI uses `CapabilityProvider::issue` and enforces explicit operator authorization.
Token signing secret is read from `FRANKEN_NODE_REMOTECAP_KEY` (falls back to
a development default only in test/dev-key builds).

### Security Considerations

- Use `--single-use` for replay protection when tokens are used in untrusted environments
- The `--issuer` field defaults to "operator-cli" but can be customized for audit trails
- Verification with `remotecap verify` rechecks the requested `--operation` and
  `--endpoint` scope without consuming single-use tokens
- `remotecap use` currently authorizes the scoped operation and may consume a
  single-use token; it does not send the HTTP request (`dry_run=true`,
  `request_executed=false` on `--json`)
