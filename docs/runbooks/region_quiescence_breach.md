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

> **CLI Reality Note:** Direct region-tree isolation, child force-close, and `EpochFence` token release are library-level `asupersync` / `control_plane` operations (`crates/franken-node/src/control_plane/`), not an external `ctl` subcommand or standalone lab binary. Use `safe-mode`, `fleet`, `incident`, `migrate rollout`, and `ops` for operator containment.

1. **Enter safe mode to block new region admissions:**
   ```bash
   franken-node safe-mode enter --reason region-quiescence-breach --operator-id <OPERATOR_ID> --trust-state-hash <CURRENT_TRUST_HASH> --json
   ```
2. **Hold fleet scheduling in the affected zone while the supervisor terminates stuck region workers:**
   ```bash
   franken-node fleet hold --zone <ZONE_ID> --reason "RGN-004 region quiescence breach <REGION_ID>" --json
   ```
3. **Snapshot local health and metrics:**
   ```bash
   franken-node ops health-check --json
   franken-node ops metrics --json > region_metrics.json
   ```
4. **Verify containment:** Confirm `fn_region_active_gauge` has decreased and no new `RGN-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the failure in the deterministic lab environment (`bd-145n`) for root-cause analysis.

1. **Verify and inspect the captured incident bundle:**
   ```bash
   franken-node incident bundle --id <INCIDENT_ID> --verify --json
   ```
2. **Replay the recorded incident trace:**
   ```bash
   franken-node incident replay --bundle <INCIDENT_ID>.fnbundle --trusted-public-key <PUBKEY_HEX> --json
   ```
3. **Replay in the deterministic lab runtime (`bd-145n`) using `--seed <ORIGINAL_SEED>`:**
   ```bash
   FRANKEN_LAB_SEED=<ORIGINAL_SEED> rch exec -- cargo test -p frankenengine-node --features extended-surfaces,test-support --test asupersync_control_lane_integration -- --nocapture
   ```
4. **Verify reproduction:** The deterministic lab replay should reproduce the `RGN-004` event with identical logical timing.
5. **Bisect the cause:** Inspect evidence entries via `franken-node debug evidence <EVIDENCE_JSONL> --json` to identify which child task or resource hold caused the quiescence timeout.

## Rollback Procedure

**Goal:** Restore the connector and region to a known-good state.

1. **Revert rollout state:** Roll back the active rollout to its known-good state (and sync `--deployment <DEPLOYMENT_NAME>` if bound).
   ```bash
   franken-node migrate rollout rollback --reason "RGN-004 region quiescence breach <REGION_ID>" --json
   ```
2. **Release fencing tokens:** Confirm via host logs that fencing tokens from the affected epoch were dropped on worker restart.
3. **Verify rollback:** Run the health check to confirm the node returns to healthy status.
   ```bash
   franken-node ops health-check --json
   ```
4. **Resume fleet zone and exit safe mode once clean:**
   ```bash
   franken-node fleet resume --zone <ZONE_ID> --json
   franken-node safe-mode exit --operator-id <OPERATOR_ID> --confirm --trust-state-consistent --no-unresolved-incidents --evidence-ledger-intact --json
   ```
5. **Monitor:** Watch `fn_region_quiescence_failures` for 15 minutes to confirm no recurrence.

## Post-Incident

- File a root-cause analysis referencing the replay results.
- If the quiescence timeout is too aggressive, propose a budget adjustment via bd-1xwz.
- Update this runbook if new containment steps are discovered.
