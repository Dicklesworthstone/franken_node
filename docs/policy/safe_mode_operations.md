# Safe-Mode Operations Governance Policy

The live CLI persists **unsigned JSON** via `serde_json::to_vec_pretty`
at `.franken-node/safe-mode/state.json` (or `--state-dir`; not
Ed25519-signed). `safe-mode exit` `--trust-state-consistent`,
`--no-unresolved-incidents`, and `--evidence-ledger-intact` are
**operator attestations**, not independently verified checks. HTTP
`/api/v1/control/safe-mode/*` routes exist in-library; the default
binary does not start a live control-plane daemon.

## Purpose

This policy governs the lifecycle of safe-mode operation in franken_node:
when to enter safe mode, what capability restrictions apply, how flag
precedence is resolved, and the required recovery procedures to exit.

## Scope

Applies to all franken_node deployments -- standalone, fleet-managed, and
development instances.  No deployment may override the core invariants
(INV-SMO-DETERMINISTIC, INV-SMO-RESTRICTED, INV-SMO-FLAGPARSE,
INV-SMO-RECOVERY) defined in the bd-k6o contract.

## When to Enter Safe Mode

### Mandatory Entry

Safe mode MUST be entered under any of these conditions:

1. **Explicit operator request**: The runtime operation flag `--safe-mode`, the
   `FRANKEN_SAFE_MODE=1` environment variable, or the `safe_mode: true`
   configuration field activates safe mode unconditionally when the deployment
   integration wires those inputs into `runtime::safe_mode::SafeModeController`.

2. **Trust state corruption**: When the trust re-verification detects
   inconsistencies between the trust state and the evidence ledger, safe
   mode activates automatically.  This is a non-negotiable safety
   mechanism.

3. **Crash loop detection**: When the crash loop detector records 3 or more
   crashes within a 60-second window (configurable), safe mode activates
   to prevent cascading failures.

4. **Epoch mismatch**: When the local control epoch does not match the
   federation epoch, safe mode activates to prevent stale-state operations.

### Advisory Entry

Operators SHOULD consider entering safe mode during:

- Planned maintenance windows affecting trust infrastructure.
- Investigation of anomalous extension behavior.
- Post-incident recovery before full operational restoration.

## Capability Restrictions

### Restricted Capabilities (Safe Mode Active)

| Capability | Restriction | Recovery Hint |
|------------|-------------|---------------|
| Extension loading (non-essential) | Blocked | Exit safe mode and restart with extensions enabled |
| Trust delegation issuance | Blocked | Resolve trust state inconsistencies first |
| Trust ledger writes | Requires explicit operator confirmation | Confirm write via `--force-write` flag |
| Outbound network (non-health) | Blocked | Use `--no-network` to explicitly control |
| Scheduled tasks | Suspended | Tasks resume after safe-mode exit |
| Network listeners (non-essential) | Suspended | Only health and admin endpoints active |

### Unrestricted Capabilities (Always Available)

- Health check endpoints.
- Admin/diagnostic endpoints.
- Read access to trust state and evidence ledger.
- CLI status and diagnostic commands.
- Structured logging and telemetry emission.

## Flag Precedence

When multiple operation flags are specified, precedence is resolved as:

1. `--safe-mode` (highest) -- activates all safe-mode restrictions.
2. `--read-only` -- prohibits all write operations.
3. `--no-network` -- disables outbound network access.
4. `--degraded` (lowest) -- enters degraded-capability mode.

A higher-precedence flag subsumes the restrictions of lower-precedence flags
where they overlap.  For example, `--safe-mode` already implies read-only
behavior for trust ledger writes, so `--read-only` is redundant for that
specific capability but still applies to other write operations.

### Conflict Resolution

- `--safe-mode` combined with `--degraded` emits SMO-003 (advisory: safe mode
  already restricts more than degraded mode).
- No flag combination is treated as an error.  All flags are applied
  additively.

## Current Shipped Operator Surface

The shipped tree contains the deterministic runtime safe-mode model in
`crates/franken-node/src/runtime/safe_mode.rs` and first-class operator
surfaces for the same lifecycle:

- CLI: `franken-node safe-mode enter`, `franken-node safe-mode status`, and
  `franken-node safe-mode exit`.
- API catalog/handlers: `POST /api/v1/control/safe-mode/enter`,
  `GET /api/v1/control/safe-mode/status`, and
  `POST /api/v1/control/safe-mode/exit`.

Both surfaces use `SafeModeController` rather than a parallel state model. The
CLI persists unsigned JSON controller state under
`.franken-node/safe-mode/state.json` by default, or under the directory passed
with `--state-dir`. Exit requests fail closed unless `--operator-id`,
`--confirm`, and the three operator attestation flags are present; the CLI
does not independently re-verify trust state, incidents, or the evidence ledger.

## Recovery Procedures

### Pre-Exit Checklist

The live CLI requires these as **operator attestation flags**. It does
not independently re-verify them:

1. **Trust state consistency**: `--trust-state-consistent`
2. **No unresolved incidents**: `--no-unresolved-incidents`
3. **Evidence ledger intact**: `--evidence-ledger-intact`
4. **Operator confirmation**: `--confirm` plus `--operator-id`

### Exit Procedure

1. Operator requests exit through `franken-node safe-mode exit` or
   `POST /api/v1/control/safe-mode/exit`.
2. CLI requires `--confirm` plus operator attestation flags
   (`--trust-state-consistent`, `--no-unresolved-incidents`,
   `--evidence-ledger-intact`); it does not independently re-run those checks.
3. If the flags are present and the controller accepts the exit, persist updates.
4. Operator confirmation is the `--confirm` flag, not an interactive prompt.
5. System restores suspended capabilities in deterministic order.
6. System logs exit event with operator identity and timestamp.
7. System emits SMO-005 and SMO-007 events for deactivation and exit clearance.

### Failed Exit

If the pre-exit checklist fails:

- The system remains in safe mode.
- A detailed report of failing checks is emitted.
- The operator may choose to resolve the issues and retry, or to
  force-exit (which is logged as a policy override and triggers an
  escalation alert).

## Audit and Evidence

- Every safe-mode entry and exit is logged as an auditable event.
- Safe-mode entry receipts are persisted with: timestamp, entry reason,
  trust state hash, and inconsistency list.
- All operations performed during safe mode are logged at TRACE level.
- Evidence artifacts are retained for the configured retention period
  (minimum 90 days).

## Monitoring and Alerting

- Dashboard integration: safe-mode state is surfaced on the operator
  dashboard with entry reason and duration.
- Alert pipeline: safe-mode entry from automatic triggers (trust
  corruption, crash loop, epoch mismatch) generates an immediate alert
  to the on-call operator.
- Velocity metric: safe-mode entry frequency is tracked as a health
  indicator.  More than 2 entries per 24-hour period triggers an
  escalation review.

## Review Cadence

This policy is reviewed quarterly or after any incident that reveals
gaps in safe-mode coverage.  Changes require approval from the platform
security team and the operations team lead.
