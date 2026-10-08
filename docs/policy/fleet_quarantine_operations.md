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
mandatory revocation, a local operator's quarantine, or another active fleet
incident affecting the same target. Trust cards persist a signed
`quarantine_sources` set containing local ownership and each fleet incident's
`(zone_id, incident_id)`. The aggregate `active_quarantine` flag stays true while
any source remains. Ordinary trust-card quarantine mutations affect only local
ownership; they cannot clear a fleet source.
Incident IDs are scoped by zone: use `fleet release --incident <id> --zone <zone>`
when an ID exists in several zones. `--zone all` selects a fleet-wide incident;
an omitted zone is accepted only when the incident is unambiguous.
Releasing the `all` incident preserves a separately scoped incident with the
same ID, and releasing a specific zone preserves the fleet-wide incident.

Local trust-card containment is released separately with an attributed operator
decision:

```bash
franken-node trust release --artifact npm:package-name \
  --operator-id operator-security --reason "local remediation verified" --json
```

`--artifact` also accepts a `sha256:` prefix of at least eight hexadecimal
characters and is mutually exclusive with sentinel `--app`. The release stores
the operator and rationale in the signed card history. Its JSON report identifies
how many local holds changed, how many cards remain quarantined by other owners,
and how many remain revoked. Repeating it is idempotent. It does not publish a
fleet release; use `fleet release` for the separately scoped incident.

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
`(emitted_at, action_id)` ordering. Executable `PolicyUpdate` records carry
validated policy contents and a monotonic revision; policy selection is
independent of producer clocks. Historical records containing only field names
remain unsupported: the agent reports degraded health and publishes no
checkpoint. Independent containment actions still proceed.

Each registry effect is durably persisted before its checkpoint heartbeat. A
crash between those writes causes idempotent desired-state reconciliation on
restart; a failed poll clears an earlier checkpoint. The checkpoint represents
the entire applied snapshot, so partial application conservatively remains
non-converged. It is an authenticated agent claim through the existing transport,
not a cryptographic attestation tied to an independently identified node: HTTP
currently authenticates a shared bearer token.

Compaction retains unresolved quarantine history and unexpired incident history;
revocations have no age-based expiry. A full in-memory action log refuses new
publication rather than discarding older containment decisions. Signed ownership
on each trust card lets release find its affected cards after restart, target
metadata changes, or removal of the original action from retained history.
Historical active cards without ownership metadata are treated as locally
quarantined, so a fleet release cannot silently clear an unattributed decision.
Creating a replacement card retains existing quarantine sources and permanent
revocation. A card accepts at most 1,024 independent quarantine sources; reaching
that limit rejects the new mutation without evicting an existing decision.

## Executable Fleet Runtime Policy

`fleet policy publish` distributes restrictions through the configured durable
store or live HTTP coordinator. The policy file contains only executable policy
fields; it cannot select a runtime binary, grant guest write or process
capabilities, replace signing keys, or name a destination path on agents.

For example, save this as `runtime-policy.json`:

```json
{
  "minimum_profile": "strict",
  "max_instructions": 200000000,
  "max_parse_source_bytes": 256000,
  "max_parse_tokens": 32768,
  "block_private_network": true
}
```

Publish and inspect it with:

```bash
franken-node fleet policy publish --zone production --revision 1 --file runtime-policy.json --json
franken-node fleet agent --node-id production-1 --zone production --once --json
franken-node fleet policy status --json
franken-node fleet reconcile --json
```

Run the agent from the managed project's root, where its local trust cards and
runtime policy belong. `--zone all` publishes a fleet-wide floor. A project's
first activation pins its agent zone; changing the agent's zone cannot silently
discard that project's earlier restrictions. Policy publication reports
`activated: false`; the command has published intent and does not claim that an
agent has applied it. Local `fleet policy status` reads the durable activation,
and reconciliation requires the existing exact-snapshot application checkpoint.

The effective rules are:

| Policy field | Runtime behavior |
|---|---|
| `minimum_profile` | Refuse `run` when the selected profile is weaker. The order is `legacy-risky`, `balanced`, `strict`. An explicit `--policy` or external config cannot bypass the floor. |
| `max_instructions` | Intersect with the local explicit or profile instruction budget on both native execution lanes. |
| `max_parse_source_bytes`, `max_parse_tokens` | Intersect with the local effective per-module parser limits. |
| `block_private_network` | Enforce SSRF blocking, cloud-metadata blocking, and audit emission; remove local network allowlist exceptions. |

Only positive supported budgets are accepted. Unknown fields, invalid profile
names, empty policies, and a digest that does not match the revision and contents
are rejected. These checks also apply to direct HTTP and transport publications.
The SHA-256 content commitment is an integrity binding; it is not an independent
publisher signature. The HTTP coordinator continues to use its configured shared
bearer authentication.

Revisions increase within each exact action zone. Higher revisions must preserve
or tighten every previously published restriction. Same-revision conflicting
content, rollback, and weakening updates are rejected inside the durable
publication transaction, including concurrent publishers. An exact historical
retry remains idempotent. Global and zone-specific rules intersect; neither can
erase the other's restrictions. There is no policy-relaxation or policy-removal
command in this restrictive distribution path.

On Unix the agent uses bounded, regular metadata files opened through pinned
directory descriptors with symlink following disabled. It commits
`.franken-node/state/fleet-policy-required.json` as a durable write-ahead
high-water mark before atomically replacing `fleet-policy.json`. Both files are
read under the same advisory lock and must agree before execution. A crash
between writes, a missing active document, corruption, or disappearing policy
history blocks new admission. An intact required document plus the same or a
stricter coordinator snapshot allows the agent to repair an interrupted
activation. Existing restrictions remain stored when a coordinator presents
older or missing history. If both documents disappear while the durable
enrollment lock remains, admission and automatic recovery both refuse: an agent
cannot prove the previous high-water mark from replacement coordinator history.
Restore the retained documents from trusted recovery material. Activation is
refused on platforms without this descriptor-relative storage implementation.

The enforcement scope is **new run admission**. `run` applies the policy before
trust preflight, the dispatcher binds that activation to the native worker
request, and the worker checks it again before constructing runtime controls.
An enrolled worker cannot start after the expected policy disappears or rolls
back. An already executing guest retains its admitted policy; this command does
not claim to hot-reload budgets or stop existing guests. Use existing incident
containment operations when an immediate response for running workloads is
required.

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
