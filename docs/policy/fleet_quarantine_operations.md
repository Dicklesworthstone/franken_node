# Fleet Quarantine and Revocation Operations

**Section:** 10.8 | **Bead:** bd-tg2

The default CLI fleet path is a **local file-transport JSONL log**
(`live_control_plane=false`). `franken-node fleet status` / `reconcile` /
`release` / `agent` inspect or append that log; they are not a live
multi-node heartbeat. The policy below is the in-library quarantine
state machine and target operational contract.

## Purpose

Defines the operational policy for fleet-wide quarantine and revocation of nodes, tenants, or zones. These operations are used during security incidents, trust violations, or compliance breaches that require coordinated isolation of affected fleet segments.

## Scope Model

All fleet control operations are scoped to a zone and optional tenant:

- **Zone ID**: Required. Identifies the deployment zone (e.g., `us-east-1`, `eu-west-2`).
- **Tenant ID**: Optional. Narrows the operation to a specific tenant within the zone.
- **Blast radius metadata**: Each operation records `affected_nodes` to track the scope of impact.

**Invariant INV-FLEET-ZONE-SCOPE**: Every quarantine and revocation operation must be scoped to at least one zone.

## Operations

### Quarantine

Isolates a zone/tenant from the fleet. Quarantined nodes continue running but are excluded from trust computations and cannot participate in consensus.

- Produces event `FLEET-001 (FLEET_QUARANTINE_INITIATED)`
- Creates an `IncidentHandle` with status `Active`
- Returns a `DecisionReceipt` with deterministic hash

### Revocation

Permanently revokes trust credentials for a zone/tenant. Three severity levels:

| Severity | Description |
|----------|-------------|
| Advisory | Logged, no enforcement. Operators notified. |
| Mandatory | Credentials revoked. Requires re-enrollment. |
| Emergency | Immediate isolation + credential revocation. |

- Produces event `FLEET-002 (FLEET_REVOCATION_ISSUED)`
- Creates an `IncidentHandle` with status `Active`

### Release

Rolls back a quarantine or revocation, restoring the affected zone/tenant to normal operations.

- Produces event `FLEET-004 (FLEET_RELEASED)`
- Sets `IncidentHandle` status to `Released`
- **Invariant INV-FLEET-ROLLBACK**: Release deterministically rolls back all quarantine/revocation state.

### Status

Returns per-zone fleet health including active incidents, convergence state, and node counts.

### Reconcile

Cleans up released incidents and verifies convergence state consistency across zones.

- Produces event `FLEET-005 (FLEET_RECONCILE_COMPLETED)`

## Convergence Tracking

All fleet operations track propagation convergence:

- `converged_nodes` / `total_nodes` = `progress_pct`
- `eta_seconds` estimated from propagation rate
- Phases: Pending, Propagating, Converged, TimedOut

**Invariant INV-FLEET-CONVERGENCE**: Every operation that affects fleet state must track convergence with progress percentage and ETA.

## Decision Receipts

**Invariant INV-FLEET-RECEIPT**: Every fleet control operation produces a signed `DecisionReceipt` containing:

- Operation ID
- Operator identity
- Scope (zone/tenant)
- Timestamp
- Deterministic SHA-256 hash of the operation payload

Receipts provide an immutable audit trail for all fleet control decisions.

## Safe-Start Mode

**Invariant INV-FLEET-SAFE-START**: The fleet control API starts in read-only mode. Write operations (quarantine, revoke, release, reconcile) are rejected with error `FLEET_NOT_ACTIVATED` until an operator explicitly calls `activate()`.

This prevents accidental fleet-wide operations during startup or failover scenarios.

## Error Taxonomy

| Code | Description |
|------|-------------|
| FLEET_SCOPE_INVALID | Zone ID is empty or malformed |
| FLEET_ZONE_UNREACHABLE | Target zone cannot be contacted |
| FLEET_CONVERGENCE_TIMEOUT | Propagation did not converge within deadline |
| FLEET_ROLLBACK_FAILED | Release could not fully restore prior state |
| FLEET_NOT_ACTIVATED | Write operation attempted before activation |

## Event Codes

| Code | Name | Description |
|------|------|-------------|
| FLEET-001 | FLEET_QUARANTINE_INITIATED | Quarantine operation started |
| FLEET-002 | FLEET_REVOCATION_ISSUED | Revocation operation started |
| FLEET-003 | FLEET_CONVERGENCE_PROGRESS | Convergence state updated |
| FLEET-004 | FLEET_RELEASED | Quarantine/revocation released |
| FLEET-005 | FLEET_RECONCILE_COMPLETED | Reconciliation sweep completed |
