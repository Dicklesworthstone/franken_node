# Region Quiescence Breach — Incident Runbook

**Invariant:** #2 (Region Quiescence)
**Severity:** CRITICAL
**Alert:** `RegionQuiescenceFailure` (bd-3gnh)
**Bead:** bd-1f8m | Section: 10.15

## Detection Signature

### Metrics (from bd-3gnh dashboard)

| Metric | Condition | Panel |
|--------|-----------|-------|
| `fn_region_quiescence_failures` | increase > 0 in 5min | Region Health |
| `fn_region_close_total{outcome="failure"}` | rate > 0.01 | Region Health |
| `fn_region_active_gauge` | unexpected increase during drain | Region Health |

### Log Event Codes

| Code | Meaning |
|------|---------|
| `RGN-004` | Region quiescence timeout — region failed to reach quiescent state within deadline |
| `RGN-005` | Region force-close initiated — operator or watchdog escalated to forced termination |
| `EVD-001` | Evidence emission for the quiescence decision |

### Identification Steps

1. Alert fires on `RegionQuiescenceFailure`.
2. Check `fn_region_quiescence_failures` dashboard panel for affected `region_id`.
3. Search logs for `RGN-004` with the matching `region_id` and `trace_id`.
4. Identify the connector and lifecycle state at time of failure.

## Immediate Containment

**Goal:** Stop the breach from propagating to other regions or connectors.

1. **Isolate the region:** Mark the failing region as `Failed` in the lifecycle FSM.
   ```
   franken-node ctl region isolate --region-id <REGION_ID>
   ```
2. **Force-close child tasks:** Escalate all child tasks in the stuck region to forced termination.
   ```
   franken-node ctl region force-close --region-id <REGION_ID> --escalate-children
   ```
3. **Release held fencing tokens:** Any fencing tokens held by the failing region must be released to prevent downstream stalls.
   ```
   franken-node ctl fencing release --holder-id <REGION_ID>
   ```
4. **Verify containment:** Confirm `fn_region_active_gauge` has decreased and no new `RGN-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the failure in a deterministic lab environment for root-cause analysis.

1. **Capture region tree state:**
   ```
   franken-node ctl region export-state --region-id <REGION_ID> --output region_state.json
   ```
2. **Export trace log:** Extract the structured trace log covering the quiescence window.
   ```
   franken-node ctl trace export --trace-id <TRACE_ID> --output trace_log.jsonl
   ```
3. **Replay in deterministic lab runtime (bd-145n):**
   ```
   franken-lab replay --state region_state.json --trace trace_log.jsonl --seed <ORIGINAL_SEED>
   ```
4. **Verify reproduction:** The lab replay should reproduce the `RGN-004` event with identical timing.
5. **Bisect the cause:** Use `--inject-delay` and `--skip-task` flags to identify which child task or resource hold caused the quiescence timeout.

## Rollback Procedure

**Goal:** Restore the connector and region to a known-good state.

1. **Revert connector state:** Roll back the connector to its last persisted known-good `RolloutState`.
   ```
   franken-node ctl rollout revert --connector-id <CONNECTOR_ID> --to-version <LAST_GOOD_VERSION>
   ```
2. **Release fencing tokens:** Confirm all fencing tokens from the affected epoch are released.
3. **Verify rollback:** Run the health gate evaluation to confirm the connector returns to `Active` state.
   ```
   franken-node ctl health-gate evaluate --connector-id <CONNECTOR_ID>
   ```
4. **Re-enable region:** Once health gate passes, re-open the region.
   ```
   franken-node ctl region reopen --region-id <REGION_ID>
   ```
5. **Monitor:** Watch `fn_region_quiescence_failures` for 15 minutes to confirm no recurrence.

## Post-Incident

- File a root-cause analysis referencing the replay results.
- If the quiescence timeout is too aggressive, propose a budget adjustment via bd-1xwz.
- Update this runbook if new containment steps are discovered.
