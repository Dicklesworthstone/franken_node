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

> **CLI Reality Note:** Live `ObligationTracker` reservation tables live in-memory inside the Rust runtime (`crates/franken-node/src/connector/obligation_tracker.rs`), not behind an external `ctl` subcommand or standalone lab binary. Operator containment uses `safe-mode`, `fleet`, `incident`, `migrate rollout`, and `ops`.

1. **Inspect current obligation metrics and health posture:**
   ```bash
   franken-node ops metrics --json > obligation_metrics.json
   franken-node ops health-check --json
   ```
2. **Enter safe mode to halt new obligation-reserving workflows:**
   ```bash
   franken-node safe-mode enter --reason obligation-leak --operator-id <OPERATOR_ID> --trust-state-hash <CURRENT_TRUST_HASH> --json
   ```
3. **Hold affected fleet zone while draining/restarting the leaking worker:**
   ```bash
   franken-node fleet hold --zone <ZONE_ID> --reason "OBL-004 obligation leak <OBLIGATION_ID>" --json
   ```
4. **Verify containment:** Confirm `fn_obligation_active_gauge` has returned to expected levels and no new `OBL-004` events are firing.

## Replay Procedure

**Goal:** Reproduce the leak in the deterministic lab environment (`bd-145n`) for root-cause analysis.

1. **Verify the captured incident bundle:**
   ```bash
   franken-node incident bundle --id <INCIDENT_ID> --verify --json
   ```
2. **Replay the incident bundle and inspect counterfactual policy behavior:**
   ```bash
   franken-node incident replay --bundle <INCIDENT_ID>.fnbundle --trusted-public-key <PUBKEY_HEX> --json
   ```
3. **Replay in the deterministic lab runtime (`bd-145n`) with `--seed <ORIGINAL_SEED>`:**
   ```bash
   FRANKEN_LAB_SEED=<ORIGINAL_SEED> rch exec -- cargo test -p frankenengine-node --features extended-surfaces,test-support --test asupersync_control_lane_integration -- --nocapture
   ```
4. **Verify reproduction:** The deterministic lab replay should reproduce the `OBL-004` event, showing the obligation transitions that led to the leak.
5. **Identify root cause:** Common causes:
   - Flow was cancelled but obligation release handler was not invoked.
   - Exception in commit path left obligation in reserved state.
   - TTL was set too short for the actual flow duration.

## Rollback Procedure

**Goal:** Revert rollout/deployment mutations associated with the leaking connector and confirm no side-effects persisted.

1. **Audit evidence entries emitted under the leaked obligation's trace:**
   ```bash
   franken-node debug evidence <EVIDENCE_JSONL> --json
   ```
2. **Roll back the active rollout (and bound deployment release if configured):**
   ```bash
   franken-node migrate rollout rollback --reason "OBL-004 obligation leak <OBLIGATION_ID>" --json
   ```
3. **Verify no side-effects (`bd-1n5p`):** Run the obligation-tracking conformance tests via RCH.
   ```bash
   rch exec -- cargo test -p frankenengine-node --features extended-surfaces,test-support --test asupersync_control_lane_integration
   ```
4. **Confirm health and metrics are clean:**
   ```bash
   franken-node ops metrics --json
   ```
5. **Monitor:** Watch `fn_obligation_leaked_total` for 15 minutes to confirm no recurrence.

## Post-Incident

- File a root-cause analysis referencing the replay results.
- If the leak pattern is caused by a missing release handler, add the handler and regression test.
- If TTL is the cause, propose a TTL adjustment with justification.
- Update this runbook if new containment steps are discovered.
