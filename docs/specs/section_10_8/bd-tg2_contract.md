# bd-tg2 Contract: Fleet Control API for Quarantine/Revocation Operations

**Bead:** bd-tg2
**Section:** 10.8 (Operational Readiness)
**Status:** In Progress
**Owner:** CrimsonCrane
**Priority:** P2

## Overview

The fleet control API is the programmatic interface that turns engine-level
quarantine and revocation primitives into operator-accessible operations. It is
the backbone of the fleet quarantine UX (10.0 Initiative #6) and supports all
operational incident response workflows. Without a well-defined fleet control
surface, operators have no structured way to quarantine compromised extensions,
revoke trust across zones, track convergence of fleet-wide actions, or roll back
quarantine state after investigation.

This bead implements the fleet control API that enables quarantine and revocation
operations with zone/tenant scoping, convergence tracking, and rollback
capabilities. All operations produce signed decision receipts (10.5), adopt the
canonical structured observability and stable error taxonomy contracts from
10.13, and start in deterministic safe-mode (read-only) until explicitly
activated.

## Dependencies

- **Upstream:** bd-1ta (10.13 FCP Deep-Mined -- canonical error taxonomy and observability contracts)
- **Upstream:** bd-20a (10.5 Security + Policy Product Surfaces -- signed decision receipts, incident bundle system)
- **Upstream:** bd-cda (10.N Execution Normalization Contract -- canonical ownership rules)
- **Downstream:** bd-1fi2 (10.8 section-wide verification gate)
- **Downstream:** bd-yqz (fleet quarantine UX + control plane, 10.0 Initiative #6)
- **Downstream:** bd-c4f (10.8 Operational Readiness rollup)

## API Endpoints

| Method | Path                                  | Description                                              | Auth              |
|--------|---------------------------------------|----------------------------------------------------------|-------------------|
| POST   | `/v1/fleet/quarantine`                | Quarantine an extension within a scope                   | mTLS + fleet-admin|
| POST   | `/v1/fleet/revoke`                    | Revoke trust for an extension within a scope             | mTLS + fleet-admin|
| POST   | `/v1/fleet/release/{incident_id}`     | Release quarantine and roll back quarantine state         | mTLS + fleet-admin|
| GET    | `/v1/fleet/status/{zone}`             | Query fleet status for a zone                            | Bearer + operator |
| POST   | `/v1/fleet/reconcile`                 | Trigger fleet-wide reconciliation of quarantine state    | mTLS + fleet-admin|

All mutation endpoints (POST) require the `fleet-admin` role and mTLS client
certificate authentication. The read-only status endpoint allows the broader
`operator` role with bearer token authentication. All endpoints propagate
W3C trace context headers.

### POST /v1/fleet/quarantine

Request body:

```json
{
  "extension_id": "ext-abc123",
  "scope": {
    "scope_type": "zone",
    "zone_ids": ["zone-us-east-1", "zone-us-west-2"],
    "tenant_ids": null
  },
  "reason": "CVE-2026-1234 active exploitation",
  "trace_id": "trace-abc-001"
}
```

Response: `FleetActionResult` with `action_type: "quarantine"`, incident handle,
convergence state, and signed decision receipt.

### POST /v1/fleet/revoke

Request body:

```json
{
  "extension_id": "ext-abc123",
  "scope": {
    "scope_type": "tenant",
    "zone_ids": null,
    "tenant_ids": ["tenant-acme", "tenant-globex"]
  },
  "reason": "Trust revocation after forensic analysis",
  "trace_id": "trace-abc-002"
}
```

Response: `FleetActionResult` with `action_type: "revocation"`, signed decision
receipt, and convergence tracking handle.

### POST /v1/fleet/release/{incident_id}

Deterministically rolls back the quarantine state associated with the given
incident. The rollback is verified -- the API confirms that all nodes in the
original scope have returned to pre-quarantine state before reporting success.

Response: `FleetActionResult` with `action_type: "release"`, rollback
verification report, and signed decision receipt.

### GET /v1/fleet/status/{zone}

Returns the current fleet status for the specified zone, including active
quarantines, pending revocations, convergence progress, and node health summary.

Response: `FleetStatus` with zone summary, active actions, and convergence
states.

### POST /v1/fleet/reconcile

Triggers a full fleet-wide reconciliation pass. Compares desired quarantine
and revocation state against actual node state across all zones. Reports
divergences and initiates corrective actions for any drift detected.

Response: `FleetActionResult` with `action_type: "reconcile"`, divergence
report, and corrective action summary.

## Data Model

### QuarantineScope (struct)

Defines the blast radius of a quarantine or revocation operation:

| Field       | Type              | Description                                           |
|-------------|-------------------|-------------------------------------------------------|
| scope_type  | ScopeType         | Whether scoping is by zone, tenant, or global         |
| zone_ids    | Option\<Vec\<String\>\> | Zone identifiers (when scope_type is Zone or Global)  |
| tenant_ids  | Option\<Vec\<String\>\> | Tenant identifiers (when scope_type is Tenant)        |

Implements `Clone`, `Debug`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`.

### ScopeType (enum)

| Variant | Description                                              |
|---------|----------------------------------------------------------|
| Zone    | Operation scoped to specific zone(s)                     |
| Tenant  | Operation scoped to specific tenant(s) within zone(s)    |
| Global  | Operation applies fleet-wide across all zones            |

### RevocationScope (struct)

Extends `QuarantineScope` with revocation-specific metadata:

| Field            | Type             | Description                                         |
|------------------|------------------|-----------------------------------------------------|
| base_scope       | QuarantineScope  | Underlying quarantine scope                         |
| revocation_depth | RevocationDepth  | How deep the revocation cascades                    |
| cascade_policy   | CascadePolicy    | Whether to cascade to dependent extensions          |

### RevocationDepth (enum)

| Variant   | Description                                                    |
|-----------|----------------------------------------------------------------|
| Shallow   | Revoke only the named extension                                |
| Deep      | Revoke the extension and all transitive dependents             |

### CascadePolicy (enum)

| Variant   | Description                                                    |
|-----------|----------------------------------------------------------------|
| None      | No cascade -- only the named extension is affected             |
| Direct    | Cascade to direct dependents only                              |
| Transitive| Cascade to all transitive dependents                           |

### FleetAction (enum)

Represents the type of fleet control action:

| Variant     | Description                                              |
|-------------|----------------------------------------------------------|
| Quarantine  | Quarantine an extension in scope                         |
| Revoke      | Revoke trust for an extension in scope                   |
| Release     | Release a previous quarantine (rollback)                 |
| Status      | Query fleet status (read-only)                           |
| Reconcile   | Fleet-wide state reconciliation                          |

### FleetActionResult (struct)

Returned by all mutation endpoints:

| Field               | Type                    | Description                                          |
|---------------------|-------------------------|------------------------------------------------------|
| action_id           | String                  | Unique identifier for this action                    |
| action_type         | FleetAction             | Type of action performed                             |
| extension_id        | Option\<String\>        | Target extension (None for reconcile)                |
| scope               | Option\<QuarantineScope\>| Scope of the action (None for status)               |
| incident_handle     | Option\<IncidentHandle\>| Handle for incident bundle integration               |
| convergence         | ConvergenceState        | Current convergence state                            |
| decision_receipt    | String                  | Signed decision receipt (opaque, base64-encoded)     |
| trace_id            | String                  | Correlation trace identifier                         |
| timestamp           | String                  | ISO 8601 timestamp of the action                     |

Implements `Clone`, `Debug`, `PartialEq`, `Eq`, `Serialize`, `Deserialize`.

### FleetStatus (struct)

Fleet status for a zone, returned by the status endpoint:

| Field               | Type                       | Description                                       |
|---------------------|----------------------------|---------------------------------------------------|
| zone_id             | String                     | Zone identifier                                   |
| active_quarantines  | Vec\<ActiveQuarantine\>    | Currently active quarantine actions                |
| pending_revocations | Vec\<PendingRevocation\>   | Revocations not yet fully converged                |
| convergence_summary | ConvergenceState           | Aggregate convergence for the zone                 |
| node_count          | u32                        | Total nodes in zone                                |
| healthy_nodes       | u32                        | Nodes reporting healthy                            |
| last_reconcile      | Option\<String\>           | Timestamp of last reconciliation                   |
| activated           | bool                       | Whether fleet control is activated (not read-only) |

### ActiveQuarantine (struct)

| Field          | Type   | Description                                          |
|----------------|--------|------------------------------------------------------|
| action_id      | String | The quarantine action identifier                     |
| extension_id   | String | Quarantined extension                                |
| initiated_at   | String | ISO 8601 timestamp                                   |
| incident_id    | String | Associated incident handle identifier                |

### PendingRevocation (struct)

| Field          | Type              | Description                                    |
|----------------|-------------------|------------------------------------------------|
| action_id      | String            | The revocation action identifier               |
| extension_id   | String            | Revoked extension                              |
| convergence    | ConvergenceState  | Per-revocation convergence progress            |
| initiated_at   | String            | ISO 8601 timestamp                             |

### FleetControlError (enum)

| Variant                    | Error Code                    | Description                                                          |
|----------------------------|-------------------------------|----------------------------------------------------------------------|
| ScopeInvalid               | FLEET_SCOPE_INVALID           | Scope specification is malformed or references unknown zones/tenants |
| ZoneUnreachable            | FLEET_ZONE_UNREACHABLE        | One or more zones in the scope are unreachable                       |
| ConvergenceTimeout         | FLEET_CONVERGENCE_TIMEOUT     | Fleet action did not converge within the configured timeout          |
| RollbackFailed             | FLEET_ROLLBACK_FAILED         | Release/rollback could not restore pre-quarantine state              |
| NotActivated               | FLEET_NOT_ACTIVATED           | Fleet control API is in safe-mode (read-only) and has not been activated |
| OperationIdExhausted       | FLEET_OPERATION_ID_EXHAUSTED  | Fleet operation ID space is exhausted; mutations fail closed         |

Each variant exposes a `code() -> &'static str` method returning the
machine-readable error code, and implements `Display` with a human-readable
message including relevant context (scope details, zone IDs, timeout duration,
rollback failure reason, etc.).

### FleetControlEvent (struct)

Structured audit event emitted by fleet control operations:

| Field        | Type        | Description                                          |
|--------------|-------------|------------------------------------------------------|
| event_code   | String      | One of the defined event codes (FLEET-001..005)      |
| event_name   | String      | Human-readable event name                            |
| trace_id     | String      | Correlation trace identifier                         |
| action_id    | String      | Fleet action identifier                              |
| extension_id | Option\<String\> | Target extension (if applicable)                |
| scope        | Option\<QuarantineScope\> | Scope of the action (if applicable)       |
| zone_ids     | Vec\<String\>| Zones affected                                      |
| detail       | String      | Additional detail or progress information            |
| timestamp    | String      | ISO 8601 timestamp                                   |

### ConvergenceState (struct)

Tracks propagation progress of a fleet action across nodes:

| Field               | Type   | Description                                           |
|---------------------|--------|-------------------------------------------------------|
| total_nodes         | u32    | Total nodes that must acknowledge the action          |
| converged_nodes     | u32    | Nodes that have confirmed the action                  |
| failed_nodes        | u32    | Nodes that failed to apply the action                 |
| pending_nodes       | u32    | Nodes that have not yet responded                     |
| progress_pct        | f64    | Convergence percentage (converged / total * 100)      |
| estimated_completion| Option\<String\> | ISO 8601 estimated completion timestamp      |
| is_complete         | bool   | Whether convergence has reached 100%                  |

### IncidentHandle (struct)

Handle linking a fleet action to the incident bundle system (10.5):

| Field          | Type   | Description                                            |
|----------------|--------|--------------------------------------------------------|
| incident_id    | String | Unique incident identifier                             |
| bundle_ref     | String | Reference to the incident bundle in the retention system|
| created_at     | String | ISO 8601 timestamp of incident creation                |
| status         | IncidentStatus | Current status of the incident                  |

### IncidentStatus (enum)

| Variant    | Description                                              |
|------------|----------------------------------------------------------|
| Open       | Incident is active, evidence collection ongoing          |
| Mitigated  | Quarantine/revocation applied, awaiting resolution       |
| Resolved   | Incident resolved, bundle sealed                         |
| Released   | Quarantine released, post-incident review complete       |

### FleetControlManager (struct)

Central manager for fleet quarantine/revocation operations.  Starts in
read-only mode (INV-FLEET-SAFE-START) and must be explicitly activated
before mutation operations are allowed.

| Field            | Type                              | Description                           |
|------------------|-----------------------------------|---------------------------------------|
| activated        | bool                              | Whether API is activated              |
| incidents        | HashMap\<String, IncidentHandle\> | Active incidents by ID                |
| zone\_status     | HashMap\<String, FleetStatus\>    | Per-zone status                       |
| events           | Vec\<FleetControlEvent\>          | Audit trail events                    |

## Invariants

| Invariant ID            | Statement                                                                                     |
|-------------------------|-----------------------------------------------------------------------------------------------|
| INV-FLEET-ZONE-SCOPE    | Every quarantine and revocation operation must specify a valid scope. The scope must reference at least one existing zone or tenant. Global scope requires explicit confirmation. `ScopeInvalid` is returned for empty or malformed scopes. Scope validation occurs before any state mutation. |
| INV-FLEET-RECEIPT        | Every mutation (quarantine, revoke, release, reconcile) produces a signed decision receipt before returning to the caller. The receipt includes the action ID, scope, timestamp, operator identity, and a cryptographic signature. Receipts are persisted in the incident bundle system (10.5). No mutation completes without a receipt. |
| INV-FLEET-CONVERGENCE    | Every fleet action tracks propagation progress via `ConvergenceState`. The API reports the number of converged, failed, and pending nodes along with an estimated completion time. A `ConvergenceTimeout` error is raised if convergence does not complete within the configured timeout (default: 300 seconds). |
| INV-FLEET-SAFE-START     | The fleet control API starts in read-only safe mode. All mutation endpoints return `FleetNotActivated` until explicit activation. The status endpoint is always available regardless of activation state. Activation requires the `fleet-admin` role and produces a signed activation receipt. |
| INV-FLEET-ROLLBACK       | The release command deterministically rolls back quarantine state. Rollback is verified -- the API confirms that all nodes in the original scope have returned to pre-quarantine state. If rollback fails on any node, the operation returns `RollbackFailed` with details of which nodes could not be restored. Partial rollback state is explicitly reported, never silently swallowed. |

## Event Codes

| Code     | Event Name              | Severity | Description                                                                    |
|----------|-------------------------|----------|--------------------------------------------------------------------------------|
| FLEET-001| QUARANTINE_INITIATED    | WARN     | Quarantine action initiated (extension_id, scope, zone_ids, trace_id)          |
| FLEET-002| REVOCATION_ISSUED       | WARN     | Revocation issued (extension_id, scope, revocation_depth, cascade_policy)      |
| FLEET-003| CONVERGENCE_PROGRESS    | INFO     | Convergence progress update (action_id, converged/total, progress_pct, ETA)    |
| FLEET-004| FLEET_RELEASED          | INFO     | Quarantine released and rollback verified (incident_id, scope, nodes_restored) |
| FLEET-005| RECONCILE_COMPLETED     | INFO     | Fleet-wide reconciliation completed (divergences_found, corrective_actions)    |

All events carry a non-empty `trace_id` for distributed tracing correlation.
Events are emitted on both success and failure paths. The event structure
follows the canonical structured observability contracts from 10.13 (bd-1ta).

## Error Codes

| Code                         | Description                                                              |
|------------------------------|--------------------------------------------------------------------------|
| FLEET_SCOPE_INVALID          | Scope references unknown zone/tenant IDs, is empty, or is malformed     |
| FLEET_ZONE_UNREACHABLE       | One or more zones in the scope cannot be contacted                       |
| FLEET_CONVERGENCE_TIMEOUT    | Fleet action did not converge within the configured timeout              |
| FLEET_ROLLBACK_FAILED        | Release/rollback could not restore pre-quarantine state on all nodes     |
| FLEET_NOT_ACTIVATED          | Fleet control API is in safe-mode and requires explicit activation       |
| FLEET_OPERATION_ID_EXHAUSTED | Fleet operation identifier space is exhausted; new mutations are blocked |

Error codes follow the stable error taxonomy contracts from 10.13. Each error
code is a `&'static str` constant and is included in both the API response body
and the structured log event. Error responses include the error code, a
human-readable message, and contextual fields (scope, zone IDs, timeout
duration, failed node list, etc.).

## Acceptance Criteria

1. **API endpoints implemented:** All five fleet control endpoints are
   implemented: `quarantine(extension_id, scope)`, `revoke(extension_id, scope)`,
   `release(incident_id)`, `status(zone)`, `reconcile()`. Each endpoint accepts
   the documented request schema and returns the documented response type.
   Route metadata is registered with correct HTTP methods, paths, auth methods,
   and policy hooks.

2. **Scope control with blast-radius metadata:** Quarantine and revocation
   operations accept a `QuarantineScope` that scopes to zones and/or tenants.
   Invalid scopes (empty zone list, unknown zone IDs) are rejected with
   `FLEET_SCOPE_INVALID`. Blast-radius metadata (affected node count, zone
   count) is included in the `FleetActionResult`.

3. **Convergence tracking with estimated completion:** The API reports
   propagation progress via `ConvergenceState` in every `FleetActionResult`.
   Progress includes converged/total node counts, a percentage, and an estimated
   completion time. `CONVERGENCE_PROGRESS` events (FLEET-003) are emitted as
   nodes acknowledge the action. `FLEET_CONVERGENCE_TIMEOUT` is raised if the
   configured timeout (default 300s) is exceeded.

4. **Deterministic rollback with verification:** The `release` command rolls
   back quarantine state for all nodes in the original scope. Rollback is
   verified -- the API confirms pre-quarantine state restoration on every node
   before returning success. `FLEET_ROLLBACK_FAILED` is returned if any node
   cannot be restored, with a list of failed nodes. The `FLEET_RELEASED` event
   (FLEET-004) includes the count of nodes restored.

5. **Signed decision receipts:** Every mutation (quarantine, revoke, release,
   reconcile) produces a signed decision receipt conforming to the 10.5 receipt
   format. The receipt is included in the `FleetActionResult` response and
   persisted in the incident bundle system. Receipts include action ID, scope,
   operator identity, timestamp, and cryptographic signature.

6. **Canonical structured observability:** All five event codes (FLEET-001
   through FLEET-005) are emitted with the 10.13 canonical event structure
   including non-empty `trace_id`, `action_id`, zone metadata, and ISO 8601
   timestamps. All six error codes follow the stable error taxonomy with
   machine-readable codes and structured context fields.

7. **Deterministic safe-mode startup:** The fleet control API starts in
   read-only mode. All mutation endpoints return `FLEET_NOT_ACTIVATED`
   (FleetControlError::NotActivated) until explicit activation. The `status`
   endpoint is always available. Activation requires `fleet-admin` role and
   produces a signed activation receipt. Unit tests verify that mutations are
   rejected before activation and succeed after activation.

8. **Integration with incident bundle system:** Quarantine and revocation
   actions create an `IncidentHandle` that references the incident bundle
   retention system (10.5, bd-20a). The `release` endpoint accepts an
   `incident_id` from the handle. Post-incident evidence (action log,
   convergence timeline, decision receipts) is collected in the incident bundle
   for retention.

## Test Scenarios

| Scenario                                  | Description                                                                          |
|-------------------------------------------|--------------------------------------------------------------------------------------|
| Quarantine single zone                    | Quarantine an extension in one zone; verify action result, convergence, and receipt   |
| Quarantine multi-zone                     | Quarantine across 3 zones; verify all zones appear in convergence tracking            |
| Quarantine with tenant scope              | Quarantine scoped to specific tenants; verify tenant-level isolation                  |
| Quarantine global scope                   | Global quarantine across all zones; verify confirmation requirement                   |
| Revoke with shallow depth                 | Revoke only the named extension; no cascade                                          |
| Revoke with deep cascade                  | Revoke extension and transitive dependents; verify cascade propagation                |
| Release and verify rollback               | Release quarantine; verify all nodes return to pre-quarantine state                  |
| Release with partial failure              | Simulate node failure during rollback; verify FLEET_ROLLBACK_FAILED with node list   |
| Status read-only in safe mode             | Status endpoint works before activation; mutation endpoints reject                   |
| Explicit activation                       | Activate fleet control; verify mutations succeed after activation                    |
| Invalid scope rejection                   | Empty zone list returns FLEET_SCOPE_INVALID                                          |
| Unknown zone rejection                    | Scope with nonexistent zone ID returns FLEET_SCOPE_INVALID                           |
| Zone unreachable                          | Simulate unreachable zone; verify FLEET_ZONE_UNREACHABLE                             |
| Convergence timeout                       | Simulate slow convergence; verify FLEET_CONVERGENCE_TIMEOUT after deadline           |
| Convergence progress events               | Verify FLEET-003 events emitted as nodes converge                                    |
| Reconcile detects drift                   | Introduce state drift; reconcile detects and reports divergences                     |
| Reconcile no drift                        | Clean fleet state; reconcile reports zero divergences                                |
| Decision receipt on every mutation        | Verify non-empty signed receipt in every mutation response                            |
| Incident handle creation                  | Quarantine creates IncidentHandle with valid bundle reference                        |
| Event emission on quarantine              | FLEET-001 event emitted with correct fields                                          |
| Event emission on revocation              | FLEET-002 event emitted with correct fields                                          |
| Event emission on release                 | FLEET-004 event emitted with node restoration count                                  |
| Event emission on reconcile               | FLEET-005 event emitted with divergence summary                                      |
| Trace ID propagation                      | All events and responses carry the request trace ID                                  |
| Send + Sync                               | All public types are Send + Sync for safe concurrent access                          |
| Serde round-trip for all types            | All public types survive JSON serialize/deserialize round-trip                        |

## Invariant Enforcement Summary

| Invariant              | Enforced At                        | Verified By                            |
|------------------------|------------------------------------|----------------------------------------|
| INV-FLEET-ZONE-SCOPE   | Scope validation in each handler   | Invalid scope tests, unknown zone tests|
| INV-FLEET-RECEIPT       | Receipt generation after mutation  | Receipt presence in every mutation test|
| INV-FLEET-CONVERGENCE   | ConvergenceState in action result  | Convergence tracking and timeout tests |
| INV-FLEET-SAFE-START    | Activation guard on mutation paths | Safe mode test, activation test        |
| INV-FLEET-ROLLBACK      | Verified rollback in release path  | Rollback success and failure tests     |

## Verification

- Script: `scripts/check_fleet_control.py --json`
- Tests: `tests/test_check_fleet_control.py`
- Evidence: `artifacts/section_10_8/bd-tg2/verification_evidence.json`
- Summary: `artifacts/section_10_8/bd-tg2/verification_summary.md`

## Artifacts

| Artifact                                                        | Purpose                        |
|-----------------------------------------------------------------|--------------------------------|
| `docs/specs/section_10_8/bd-tg2_contract.md`                    | This specification document    |
| `crates/franken-node/src/api/fleet_quarantine.rs`               | Rust implementation            |
| `scripts/check_fleet_control.py`                                | Verification script (--json)   |
| `tests/test_check_fleet_control.py`                             | Unit tests for verifier        |
| `artifacts/section_10_8/bd-tg2/verification_evidence.json`      | Machine-readable evidence      |
| `artifacts/section_10_8/bd-tg2/verification_summary.md`         | Human-readable summary         |
