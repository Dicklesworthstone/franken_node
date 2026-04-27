# Runbook RB-003: Fleet Quarantine Activation

**Category**: fleet_quarantine_activation
**Severity**: High
**Estimated Recovery Time**: 45 minutes
**Required Permissions**: operator, fleet_admin
**Operator Privilege Level**: P2
**Last Reviewed**: 2026-02-21
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `fleet_quarantine_active == 1`
- `quarantined_nodes_total > 0`

### Log Patterns
- `FLEET_QUARANTINE_ACTIVATED`
- `node_quarantine_enforced`

## Containment

1. Confirm quarantine scope (partial fleet vs. full fleet).
2. Isolate quarantined nodes from non-quarantined fleet segments.
3. Disable automatic workload scheduling to quarantined nodes.
4. Preserve quarantine trigger evidence for post-incident review.

## Investigation

1. Identify quarantine trigger condition (health check failure, trust violation, policy breach).
2. Review health gate status for affected nodes.
3. Check for correlated infrastructure events (network partition, storage failure).
4. Determine whether quarantine is due to a single root cause or multiple independent failures.
5. Assess operator workload impact and SLA implications.

## Repair

1. Address root cause on quarantined nodes (patch, configuration fix, restart).
2. Clear quarantine flags on nodes that pass health verification.
3. Gradually re-admit nodes to fleet (canary pattern: 10%, 25%, 50%, 100%).
4. Update quarantine trigger thresholds if they were too sensitive.

## Verification

1. Run fleet health check: `franken-node fleet status --verbose`.
2. Confirm all re-admitted nodes pass trust verification.
3. Validate workload scheduling resumes normally.
4. Verify no residual quarantine flags on healthy nodes.

## Rollback

1. If repair causes further degradation, re-quarantine affected nodes.
2. Restore workload to known-good node subset.
3. Escalate if quarantine cannot be lifted within estimated recovery time.
4. Consider fleet-wide safe mode if quarantine scope exceeds 50% of nodes.

## Drill Scenario

Trigger quarantine on a staging fleet subset (3 nodes) by injecting a health
check failure.  Verify quarantine activation, investigate root cause, repair
the simulated failure, and re-admit nodes through the graduated process.

## Command References

- `franken-node fleet status --zone <zone> --json`
- `franken-node fleet release --incident <incident-id>`
- `POST /api/v1/fleet/quarantine/activate`

## Cross-References

- bd-3o6: Fleet quarantine operations
- quarantine_store.rs: Quarantine state transitions
- health_gate.rs: Health gate infrastructure
- rollout_state.rs: Fleet rollout state management
