# Runbook RB-004: Epoch Transition Failure

**Category**: epoch_transition_failure
**Severity**: Critical
**Estimated Recovery Time**: 1 hour
**Required Permissions**: operator, security_admin, epoch_authority
**Operator Privilege Level**: P1
**Last Reviewed**: 2026-02-21
**Review Cadence**: per_release_cycle

## Detection

### Metrics
- `epoch_transition_failures_total > 0`
- `epoch_transition_duration_seconds > 300`

### Log Patterns
- `EPOCH_TRANSITION_FAILURE`
- `epoch_finalization_timeout`

## Containment

1. Halt epoch transition to prevent partial state.
2. Activate safe mode if trust state is in an inconsistent epoch boundary.
3. Freeze all trust delegations that depend on the new epoch.
4. Notify epoch governance authority.

## Investigation

1. Identify failure point in epoch transition sequence (preparation, commit, finalization).
2. Check epoch boundary conditions: all prerequisites met, quorum achieved.
3. Verify epoch transition signatures from all required signatories.
4. Review evidence ledger for incomplete epoch boundary entries.
5. Determine whether failure is transient (timeout) or permanent (state corruption).

## Repair

1. If transient: retry epoch transition with extended timeout.
2. If signature missing: request re-signing from absent signatory.
3. If state corruption: restore pre-transition epoch state from checkpoint.
4. Re-execute epoch transition with corrected preconditions.

## Verification

1. Confirm new epoch is fully committed and finalized.
2. Validate epoch transition receipt with all required signatures.
3. Verify trust state is consistent with new epoch parameters.
4. Run epoch consistency check: `franken-node runtime epoch --local-epoch <current>`.

## Rollback

1. Revert to previous epoch state from pre-transition checkpoint.
2. Invalidate any partial epoch state artifacts.
3. Reset epoch transition sequence to initial state.
4. If repeated failures, escalate to epoch governance for manual resolution.

## Drill Scenario

Simulate epoch transition failure by withholding one signatory's approval
in a staging environment.  Verify that the timeout fires, containment
activates, and the retry-with-re-signing path completes successfully.

## Command References

- `franken-node runtime epoch --local-epoch <current> --json`
- `POST /api/v1/control/epoch/retry`
- `franken-node ops health-check --json`

## Cross-References

- bd-k6o: Safe mode operations
- fencing.rs: Epoch fencing and transitions
- state_model.rs: Trust state model
