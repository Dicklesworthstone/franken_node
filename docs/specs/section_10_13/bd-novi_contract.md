# bd-novi — Stable Error Code Namespace

## Overview

Defines a namespaced, machine-readable error code registry.  Every non-fatal
error carries structured recovery metadata: `retryable` (bool),
`retry_after_ms` (optional backoff hint), and `recovery_hint` (human-readable
guidance).  Error codes are unique, namespaced by subsystem, and frozen once
registered — compatibility tests prevent breaking changes.

## Error Code Format

```
FRANKEN_{SUBSYSTEM}_{CODE}
```

Examples: `FRANKEN_PROTOCOL_AUTH_FAILED`, `FRANKEN_EGRESS_TIMEOUT`.

## Invariants

- **INV-ECR-NAMESPACED** — Every error code starts with `FRANKEN_` followed by a
  valid subsystem prefix; the registry rejects codes outside the namespace.
- **INV-ECR-UNIQUE** — No two errors share the same code; duplicate registration
  is rejected.
- **INV-ECR-RECOVERY** — Every non-fatal error carries `retryable`,
  `retry_after_ms`, and `recovery_hint` fields.  Fatal errors have
  `retryable=false` and no retry hint.
- **INV-ECR-FROZEN** — Once an error code is frozen its semantics (retryable,
  severity) cannot change; attempts to re-register with different recovery
  metadata are rejected.

## Types

- `Severity` — Fatal / Degraded / Transient
- `RecoveryInfo` — retryable, retry_after_ms, recovery_hint
- `ErrorCodeEntry` — code, subsystem, severity, recovery, description, version, frozen
- `ErrorCodeRegistry` — in-memory store enforcing all four invariants
- `RegistryError` — error codes for contract violations

## Error Codes

| Code | Meaning |
|------|---------|
| `ECR_INVALID_NAMESPACE` | Code does not match FRANKEN_{SUBSYSTEM}_ pattern |
| `ECR_DUPLICATE_CODE` | Code already registered |
| `ECR_MISSING_RECOVERY` | Non-fatal error missing recovery fields |
| `ECR_FROZEN_CONFLICT` | Re-registration conflicts with frozen entry |
| `ECR_NOT_FOUND` | Code not in registry |
