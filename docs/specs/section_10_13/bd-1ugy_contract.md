# bd-1ugy — Stable Telemetry Namespace

## Overview

Defines a versioned, frozen telemetry namespace for the four instrumentation
planes (protocol, capability, egress, security).  Metric names and labels are
governed by a compatibility policy: once frozen they cannot be renamed or
removed, only deprecated through a documented cycle.  A schema validator
enforces namespace rules at registration time.

## Planes

| Plane | Prefix | Example metric |
|-------|--------|----------------|
| Protocol | `franken.protocol.*` | `franken.protocol.messages_received_total` |
| Capability | `franken.capability.*` | `franken.capability.invocations_total` |
| Egress | `franken.egress.*` | `franken.egress.bytes_sent_total` |
| Security | `franken.security.*` | `franken.security.auth_failures_total` |

## Invariants

- **INV-TNS-VERSIONED** — Every registered metric carries a schema version;
  the registry rejects metrics without one.
- **INV-TNS-FROZEN** — Once a metric is frozen its name, label set, and type
  cannot change; attempts to re-register with different shape are rejected.
- **INV-TNS-DEPRECATED** — Deprecated metrics remain queryable for at least
  one compatibility window; the registry tracks deprecation reason and version.
- **INV-TNS-NAMESPACE** — Every metric name must start with a valid plane
  prefix (`franken.{protocol,capability,egress,security}.`); the validator
  rejects names outside these namespaces.

## Types

- `MetricType` — Counter / Gauge / Histogram
- `MetricSchema` — name, plane, metric_type, labels, version, frozen, deprecated info
- `SchemaRegistry` — in-memory store enforcing all four invariants
- `ValidationError` — error codes for contract violations

## Error Codes

| Code | Meaning |
|------|---------|
| `TNS_INVALID_NAMESPACE` | Name does not match any plane prefix |
| `TNS_VERSION_MISSING` | Schema version not provided |
| `TNS_FROZEN_CONFLICT` | Re-registration conflicts with frozen schema |
| `TNS_ALREADY_DEPRECATED` | Metric already deprecated |
| `TNS_NOT_FOUND` | Metric not in registry |
