# Obligation Leak Incident — Incident Runbook

**Invariant:** #4 (Obligation Tracking)
**Severity:** CRITICAL
**Alert:** `ObligationLeak` (bd-3gnh)
**Bead:** bd-1f8m | Section: 10.15

## Detection Signature

### Metrics (from bd-3gnh dashboard)

| Metric | Condition | Panel |
|--------|-----------|-------|
| `fn_obligation_leaked_total` | increase > 0 | Obligation Health |
| `fn_obligation_active_gauge` | sustained high count, not decreasing | Obligation Health |
| `fn_obligation_reserved_total` - `fn_obligation_committed_total` | gap widening over time | Obligation Health |

### Log Event Codes

| Code | Meaning |
|------|---------|
| `OBL-004` | Obligation leak detected — reserved obligation was not committed or released within TTL |
| `EVD-001` | Evidence emission for the obligation decision |

### Identification Steps

1. Alert fires on `ObligationLeak`.
2. Check `fn_obligation_leaked_total` dashboard panel for affected `obligation_type`.
3. Search logs for `OBL-004` with the matching `obligation_type` and `trace_id`.
4. Identify the flow and connector associated with the leaked obligation.
5. Check whether the leak is a single event or a pattern (multiple leaks in the same flow type).

## Immediate Containment

**Goal:** Stop the leaked obligation from accumulating resources and prevent cascading leaks.

1. **Identify leaked obligations:** List all obligations in `reserved` state past their TTL.
   ```
   franken-node ctl obligation list --state reserved --past-ttl
   ```
2. **Force-rollback associated flows:** Roll back any in-flight flows that hold the leaked obligation.
   ```
   franken-node ctl flow rollback --obligation-id <OBLIGATION_ID>
   ```
3. **Clear leaked obligations from tracker:**
   ```
   franken-node ctl obligation force-release --obligation-id <OBLIGATION_ID>
   ```
4. **Verify containment:** Confirm `fn_obligation_active_gauge` has returned to expected levels and no new `OBL-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the leak in a deterministic lab environment for root-cause analysis.

1. **Capture obligation tracker state:**
   ```
   franken-node ctl obligation export-state --output obligation_state.json
   ```
2. **Export flow trace:** Extract the structured trace log for the leaking flow.
   ```
   franken-node ctl trace export --trace-id <TRACE_ID> --output flow_trace.jsonl
   ```
3. **Replay in deterministic lab runtime (bd-145n):**
   ```
   franken-lab replay --state obligation_state.json --trace flow_trace.jsonl --seed <ORIGINAL_SEED>
   ```
4. **Verify reproduction:** The lab replay should reproduce the `OBL-004` event, showing the obligation transitions that led to the leak.
5. **Identify root cause:** Common causes:
   - Flow was cancelled but obligation release handler was not invoked.
   - Exception in commit path left obligation in reserved state.
   - TTL was set too short for the actual flow duration.

## Rollback Procedure

**Goal:** Revert state mutations caused by the leaked obligation and confirm no side-effects persisted.

1. **Revert affected state mutations:** Identify all state changes made under the leaked obligation's scope.
   ```
   franken-node ctl obligation audit --obligation-id <OBLIGATION_ID>
   ```
2. **Revert each mutation:**
   ```
   franken-node ctl state revert --mutation-ids <ID1>,<ID2>,...
   ```
3. **Verify no side-effects:** Run the integration test suite for obligation tracking (bd-1n5p) against the affected connector.
   ```
   franken-node test --suite obligation-tracking --connector-id <CONNECTOR_ID>
   ```
4. **Confirm obligation tracker is clean:**
   ```
   franken-node ctl obligation list --state reserved --past-ttl
   ```
   Expected: empty list.
5. **Monitor:** Watch `fn_obligation_leaked_total` for 15 minutes to confirm no recurrence.

## Post-Incident

- File a root-cause analysis referencing the replay results.
- If the leak pattern is caused by a missing release handler, add the handler and regression test.
- If TTL is the cause, propose a TTL adjustment with justification.
- Update this runbook if new containment steps are discovered.
