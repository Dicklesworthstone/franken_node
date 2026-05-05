# Runbook RB-002: Mass Revocation Event

**Category**: mass_revocation_event
**Severity**: Critical
**Estimated Recovery Time**: 1 hour
**Required Permissions**: operator, security_admin, revocation_authority
**Operator Privilege Level**: P1
**Last Reviewed**: 2026-05-01
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `trust_revocations_per_minute > 100`
- `active_trust_delegations_delta < -50`

### Log Patterns
- `MASS_REVOCATION_EVENT_TRIGGERED`
- `revocation_rate_threshold_exceeded`

## Containment

1. Throttle revocation processing to prevent cascade.
2. Activate fleet-wide revocation pause if rate exceeds 500/min.
3. Snapshot current revocation state before further processing.
4. Alert security operations center.

## Investigation

1. Identify revocation source (automated policy vs. manual operator action).
2. Audit revocation requests for unauthorized or anomalous patterns.
3. Check whether revocation trigger was a compromised signing key.
4. Determine blast radius: how many nodes and delegations are affected.
5. Review recent CRL (Certificate Revocation List) updates.

## Repair

1. If revocations are legitimate, resume processing at controlled rate.
2. If revocations are illegitimate, revert revocation batch from snapshot.
3. Re-issue trust delegations for incorrectly revoked entities.
4. If a signing key is compromised, follow the governed signer-config and
   evidence-ledger rotation procedure. This release intentionally exposes no
   emergency key-rotation subcommand until that procedure can apply a real
   rotation.
5. Update revocation policy to prevent recurrence.

## Verification

1. Confirm revocation list consistency across all fleet nodes.
2. Validate that legitimate revocations are honored fleet-wide.
3. Verify that incorrectly revoked entities have restored access.
4. For any key-rotation emergency, verify that the applied signer-config and
   evidence-ledger entries identify the old key, new key, approval trace, and
   rotation timestamp before considering remediation complete.
5. Run trust state audit: `franken-node trust scan --deep --audit`.

## Rollback

1. Restore pre-revocation trust state from snapshot.
2. Re-process revocations selectively (legitimate only).
3. If full rollback needed, coordinate fleet-wide epoch reset.
4. Escalate to governance board if policy-level changes required.

## Drill Scenario

Simulate mass revocation by issuing 200 test revocations against a staging
fleet.  Verify that rate-limiting engages, containment procedures activate,
and selective rollback restores test delegations correctly.

## Command References

- `franken-node trust revoke --batch fixtures/revocations/test_batch.json`
- `franken-node trust sync --restore-from snapshots/pre_revocation.json` (restore trust state from snapshot)
- `POST /api/v1/trust/revocations/pause`

## Cross-References

- bd-f2y: Structured observability
- revocation.rs: Revocation processing
- trust delegation policy
