# Fleet Quarantine and Revocation Operations

**Section:** 10.8 | **Bead:** bd-tg2

The CLI uses a local FrankenSQLite durable store by default
(`live_control_plane=false`). Configuring `[fleet] control_plane_url` routes
`status`, `reconcile`, `release`, `agent`, and `trust quarantine` through the live
authenticated HTTP coordinator served by `franken-node fleet serve`. The explicit
file transport remains available through the library.

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

The CLI retires the selected quarantine incident. A release does not clear a
mandatory revocation or another active fleet incident affecting the same target.
Incident IDs are scoped by zone: use `fleet release --incident <id> --zone <zone>`
when an ID exists in several zones. `--zone all` selects a fleet-wide incident;
an omitted zone is accepted only when the incident is unambiguous.
Releasing the `all` incident preserves a separately scoped incident with the
same ID, and releasing a specific zone preserves the fleet-wide incident.

- Produces event `FLEET-004 (FLEET_RELEASED)`
- Sets `IncidentHandle` status to `Released`
- **Invariant INV-FLEET-ROLLBACK**: Release reconciles the selected incident's quarantine state while retaining independent containment.

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

CLI convergence requires a fresh, healthy node heartbeat carrying an
`applied_actions` checkpoint. Its domain-separated SHA-256 digest and record count
bind the complete immutable action snapshot relevant to that node's zone,
including `all` actions. High quarantine counters, later timestamps, and older
checkpoints cannot prove application of a new action. Historical heartbeats
without a checkpoint remain readable and do not count as converged. A zone with
no registered nodes remains pending.

Reconcile and status roll up the whole relevant snapshot, including policy-only,
revocation-only, and release-only histories. Each applicable node is counted
once, and every explicitly targeted zone must contain an applying node. Missing
zone coverage remains pending with unknown progress; unrelated zones do not
block a scoped history. Only an empty relevant action history is a no-op.

The agent reconciles active quarantines and mandatory revocations on every poll.
Targets absent from the local trust registry remain pending and are retried when
they appear. Action delivery does not use issuer timestamps as a cursor, so a
slow issuer clock cannot hide a newly delivered independent incident. Conflicting
records for the same scoped incident retain the protocol's deterministic
`(emitted_at, action_id)` ordering. Unsupported
`PolicyUpdate` records contain field names without executable policy contents;
the agent reports degraded health and publishes no checkpoint instead of
acknowledging a log message as a policy change. Independent containment actions
still proceed.

Each registry effect is durably persisted before its checkpoint heartbeat. A
crash between those writes causes idempotent desired-state reconciliation on
restart; a failed poll clears an earlier checkpoint. The checkpoint represents
the entire applied snapshot, so partial application conservatively remains
non-converged. It is an authenticated agent claim through the existing transport,
not a cryptographic attestation tied to an independently identified node: HTTP
currently authenticates a shared bearer token.

Compaction retains unresolved quarantine history and unexpired incident history;
revocations have no age-based expiry. A full in-memory action log refuses new
publication rather than discarding older containment decisions. Source ownership
for an independent local quarantine is not represented by the trust card's single
quarantine boolean; the snapshot checkpoint covers the fleet incident state and
does not establish separate local quarantine provenance.

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
