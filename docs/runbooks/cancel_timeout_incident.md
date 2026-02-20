# Cancel Timeout Incident — Incident Runbook

**Invariant:** #3 (Cancellation Protocol)
**Severity:** WARNING → CRITICAL (if unresolved)
**Alert:** `CancelLatencyBudgetExceeded` (bd-3gnh)
**Bead:** bd-1f8m | Section: 10.15

## Detection Signature

### Metrics (from bd-3gnh dashboard)

| Metric | Condition | Panel |
|--------|-----------|-------|
| `fn_cancel_total_duration_ms` | p99 > budget_ms | Cancel Latency |
| `fn_cancel_drain_duration_ms` | p99 > expected drain budget | Cancel Latency |
| `fn_cancel_finalize_duration_ms` | sustained high values | Cancel Latency |
| `fn_cancel_request_duration_ms` | p95 above baseline | Cancel Latency |

### Log Event Codes

| Code | Meaning |
|------|---------|
| `CAN-004` | Cancel timeout — cancellation workflow did not complete within the deadline |
| `EVD-001` | Evidence emission for the cancellation decision |

### Identification Steps

1. Alert fires on `CancelLatencyBudgetExceeded`.
2. Check `fn_cancel_total_duration_ms` dashboard panel — look at p99 trend.
3. Search logs for `CAN-004` with matching `workflow` and `trace_id`.
4. Determine which cancellation phase is the bottleneck:
   - **Request phase** (`fn_cancel_request_duration_ms`): The initial cancel signal is slow to propagate.
   - **Drain phase** (`fn_cancel_drain_duration_ms`): In-flight work is slow to drain.
   - **Finalize phase** (`fn_cancel_finalize_duration_ms`): Cleanup and resource release is slow.
5. Correlate with region and obligation health — a cancel timeout often co-occurs with region quiescence issues.

## Immediate Containment

**Goal:** Complete the stalled cancellation and release held resources.

1. **Force-finalize the timed-out workflow:**
   ```
   franken-node ctl cancel force-finalize --workflow-id <WORKFLOW_ID>
   ```
2. **Release held resources:** Any obligations, fencing tokens, or region locks held by the cancelled workflow must be freed.
   ```
   franken-node ctl obligation force-release --workflow-id <WORKFLOW_ID>
   franken-node ctl fencing release --holder-id <WORKFLOW_ID>
   ```
3. **Log incomplete drain:** Record which tasks were not drained before force-finalize for post-incident audit.
   ```
   franken-node ctl cancel audit --workflow-id <WORKFLOW_ID> --output cancel_audit.json
   ```
4. **Verify containment:** Confirm `fn_cancel_total_duration_ms` p99 has returned below budget and no new `CAN-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the timeout in a deterministic lab environment for root-cause analysis.

1. **Capture cancel protocol state:**
   ```
   franken-node ctl cancel export-state --workflow-id <WORKFLOW_ID> --output cancel_state.json
   ```
2. **Export phase timing log:** Extract the per-phase timing data.
   ```
   franken-node ctl trace export --trace-id <TRACE_ID> --output phase_timing.jsonl
   ```
3. **Replay in deterministic lab runtime (bd-145n):**
   ```
   franken-lab replay --state cancel_state.json --trace phase_timing.jsonl --seed <ORIGINAL_SEED>
   ```
4. **Verify reproduction:** The lab replay should reproduce the `CAN-004` event with matching phase durations.
5. **Identify bottleneck phase:** Use `--phase-breakdown` to see time spent in request/drain/finalize phases.
   ```
   franken-lab analyze --input phase_timing.jsonl --phase-breakdown
   ```

## Rollback Procedure

**Goal:** Revert any partially-committed state from the timed-out cancellation and verify region quiescence.

1. **Revert partially-committed state:** Check if the cancel workflow made any partial commits before timing out.
   ```
   franken-node ctl cancel audit --workflow-id <WORKFLOW_ID> --show-commits
   ```
2. **Revert each partial commit:**
   ```
   franken-node ctl state revert --mutation-ids <ID1>,<ID2>,...
   ```
3. **Verify region quiescence:** The affected region must reach quiescent state after rollback.
   ```
   franken-node ctl region check-quiescence --region-id <REGION_ID>
   ```
4. **Run integration tests (bd-1cs7):** Verify the cancellation protocol is functional after rollback.
   ```
   franken-node test --suite cancel-protocol --connector-id <CONNECTOR_ID>
   ```
5. **Monitor:** Watch `fn_cancel_total_duration_ms` p99 and `fn_region_quiescence_failures` for 15 minutes.

## Post-Incident

- File a root-cause analysis identifying the bottleneck phase.
- If the drain phase is the bottleneck, check for resource contention or slow task completion.
- If the finalize phase is slow, check for excessive cleanup work or blocking I/O.
- Consider adjusting the cancel timeout budget if the current value is unrealistic for the workload.
- Update this runbook if new containment steps are discovered.
