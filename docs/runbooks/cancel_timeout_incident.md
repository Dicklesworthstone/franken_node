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

**Goal:** Complete the stalled cancellation, freeze further risky rollouts, and contain held resources.

> **CLI Reality Note:** In-process `CancellationProtocol`, `ObligationTracker`, and `EpochFence` state machines live in the Rust library (`crates/franken-node/src/control_plane/` and `crates/franken-node/src/connector/`); there is no external `ctl` subcommand or standalone lab binary. Operator CLI containment uses `safe-mode`, `fleet`, `incident`, `migrate rollout`, and `ops`.

1. **Enter operator safe mode to halt new risky workflow admissions:**
   ```bash
   franken-node safe-mode enter --reason cancel-timeout --operator-id <OPERATOR_ID> --trust-state-hash <CURRENT_TRUST_HASH> --json
   ```
2. **Place a fleet hold on the affected zone while in-flight cancellation drains or the host supervisor restarts the stuck worker:**
   ```bash
   franken-node fleet hold --zone <ZONE_ID> --reason "CAN-004 cancel timeout on <WORKFLOW_ID>" --json
   ```
3. **Capture runtime metrics and health posture for post-incident audit:**
   ```bash
   franken-node ops metrics --json > cancel_audit.json
   franken-node ops health-check --json
   ```
4. **Verify containment:** Confirm `fn_cancel_total_duration_ms` p99 has returned below budget and no new `CAN-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the timeout in the deterministic lab environment (`bd-145n`) for root-cause analysis.

1. **Export and verify the recorded incident bundle:**
   ```bash
   franken-node incident bundle --id <INCIDENT_ID> --verify --json
   ```
2. **Replay the recorded incident bundle with signature verification:**
   ```bash
   franken-node incident replay --bundle <INCIDENT_ID>.fnbundle --trusted-public-key <PUBKEY_HEX> --json
   ```
3. **Reproduce in the deterministic lab runtime (`bd-145n`) with `--seed <ORIGINAL_SEED>`:**
   ```bash
   FRANKEN_LAB_SEED=<ORIGINAL_SEED> rch exec -- cargo test -p frankenengine-node --features extended-surfaces,test-support --test asupersync_control_lane_integration -- --nocapture
   ```
   *(Pass `--seed <ORIGINAL_SEED>` when invoking deterministic lab harnesses directly in library tests.)*
4. **Verify reproduction:** The deterministic lab replay and `franken-node debug trace` inspection should reproduce `CAN-004` with matching phase durations.
5. **Inspect trace breakdown:**
   ```bash
   franken-node debug evidence <EVIDENCE_JSONL> --json
   ```

## Rollback Procedure

**Goal:** Revert any partially-rolled-out connector/release state from the timed-out cancellation and verify quiescence.

1. **Roll back active migration/connector rollout state:**
   ```bash
   franken-node migrate rollout rollback --reason "CAN-004 cancel timeout <WORKFLOW_ID>" --json
   ```
2. **Inspect deployment and safe-mode status:**
   ```bash
   franken-node deploy status --deployment <DEPLOYMENT_NAME> --json
   franken-node safe-mode status --json
   ```
3. **Release the fleet hold once region quiescence is restored:**
   ```bash
   franken-node fleet resume --zone <ZONE_ID> --json
   ```
4. **Run integration tests (`bd-1cs7`):** Verify the cancellation protocol is functional after rollback.
   ```bash
   rch exec -- cargo test -p frankenengine-node --features extended-surfaces,test-support --test asupersync_control_lane_integration
   ```
5. **Monitor:** Watch `fn_cancel_total_duration_ms` p99 and `fn_region_quiescence_failures` for 15 minutes.

## Post-Incident

- File a root-cause analysis identifying the bottleneck phase.
- If the drain phase is the bottleneck, check for resource contention or slow task completion.
- If the finalize phase is slow, check for excessive cleanup work or blocking I/O.
- Consider adjusting the cancel timeout budget if the current value is unrealistic for the workload.
- Update this runbook if new containment steps are discovered.
