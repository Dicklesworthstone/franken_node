# Runbook RB-001: Trust State Corruption

**Category**: trust_state_corruption
**Severity**: Critical
**Estimated Recovery Time**: 30 minutes
**Required Permissions**: operator, security_admin
**Operator Privilege Level**: P1
**Last Reviewed**: 2026-02-21
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `trust_integrity_check_failures > 0`
- `trust_state_hash_mismatch_total > 0`

### Log Patterns
- `TRUST_STATE_CORRUPTION_DETECTED`
- `trust_state_integrity_check failed`

## Containment

1. Activate safe mode via `POST /api/v1/control/safe-mode/enter` (CLI safe-mode command not yet implemented).
2. Freeze all trust delegation operations.
3. Block new trust chain extensions.
4. Notify on-call security team via incident channel.

## Investigation

1. Diff current trust state against last known-good snapshot.
2. Identify divergence point in evidence ledger.
3. Check for unauthorized trust mutations in audit log.
4. Correlate with recent deployments or configuration changes.
5. Determine scope of corruption (single node vs. fleet-wide).

## Repair

1. Restore trust state from last verified snapshot.
2. Re-derive trust chain from verified root of trust.
3. Re-validate all trust delegations against policy.
4. Replay evidence ledger entries from verified checkpoint.

## Verification

1. Run full trust re-verification pass: `franken-node trust scan --deep --audit`.
2. Confirm trust state hash matches expected value.
3. Validate evidence ledger consistency end-to-end.
4. Verify all trust delegations are policy-compliant.

## Rollback

1. If repair fails, revert to previous epoch.
2. Restore pre-corruption trust state from backup.
3. Invalidate any trust tokens issued during corruption window.
4. Escalate to security incident team if rollback also fails.

## Drill Scenario

Inject trust artifact integrity failure by modifying a trust state entry's
hash to an invalid value.  Verify that detection fires within 60 seconds,
safe mode activates automatically, and the full containment-through-verification
pipeline completes successfully in a staging environment.

## Command References

- `franken-node trust scan --deep --audit`
- `franken-node ops health-check --json`
- `POST /api/v1/control/safe-mode/enter`

## Cross-References

- bd-k6o: Safe mode operations
- safe_mode.rs: Safe mode controller
- state_model.rs: Trust state model
