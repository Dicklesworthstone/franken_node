# Telemetry Bridge Operator Troubleshooting Guide

Reference for operators and contributors working with the refactored telemetry
bridge lifecycle (bd-1now.4 cluster).

## Lifecycle States

| State | Value | Meaning | Normal? |
|-------|-------|---------|---------|
| Cold | 0 | Bridge created but not started | Yes (pre-start) |
| Starting | 1 | Binding socket, spawning workers | Transient |
| Running | 2 | Accepting connections and events | Yes |
| Degraded | 3 | Running, but non-fatal errors occurred (accept failures) | Investigate |
| Draining | 4 | Stop requested; no new admission, flushing queued work | Yes (shutdown) |
| Stopped | 5 | Clean stop and drain completed | Yes (terminal) |
| Failed | 6 | Fatal start/runtime/drain failure | Investigate |

**Terminal states**: Only `Stopped` and `Failed` are terminal. A bridge in any
other state still has active workers.

**State transitions**: Every transition is recorded as a `TELEMETRY_BRIDGE_STATE_TRANSITION`
event in the recent events buffer.

## Event Codes

| Code | Meaning |
|------|---------|
| `TELEMETRY_BRIDGE_STATE_STARTED` | Listener bound and ready |
| `TELEMETRY_BRIDGE_STATE_TRANSITION` | Lifecycle state changed |
| `TELEMETRY_BRIDGE_CONNECTION_ACCEPTED` | New engine connection accepted |
| `TELEMETRY_BRIDGE_CONNECTION_REJECTED` | Connection refused (at cap) |
| `TELEMETRY_BRIDGE_CONNECTION_CLOSED` | Connection closed normally |
| `TELEMETRY_BRIDGE_CONNECTION_READ_FAILED` | Connection read error |
| `TELEMETRY_BRIDGE_ADMISSION_ACCEPTED` | Event enqueued for persistence |
| `TELEMETRY_BRIDGE_ADMISSION_SHED` | Event dropped (queue full or oversized) |
| `TELEMETRY_BRIDGE_PERSIST_SUCCESS` | Event written to adapter |
| `TELEMETRY_BRIDGE_PERSIST_FAILURE` | Adapter write failed |
| `TELEMETRY_BRIDGE_DRAIN_STARTED` | Shutdown drain initiated |
| `TELEMETRY_BRIDGE_DRAIN_COMPLETE` | All queued work flushed |
| `TELEMETRY_BRIDGE_DRAIN_TIMEOUT` | Drain did not finish in time |

## Reason Codes

| Code | Meaning | Operator Action |
|------|---------|-----------------|
| `allowed` | Normal operation | None |
| `queue_full_shed` | Bounded queue at capacity, event shed | Check persistence throughput; consider increasing `PERSIST_QUEUE_CAPACITY` |
| `persist_failed` | Adapter write error | Check storage backend health |
| `queue_disconnected` | Persistence worker gone before enqueue | Internal error; check logs for panic |
| `reader_failed` | Stream read error | Transient; engine may have disconnected |
| `event_too_large` | Event exceeded 64 KB limit | Engine sending oversized payloads; fix upstream |
| `connection_cap` | 64 concurrent connections reached | Normal under heavy load; connections will be served when slots free |
| `shutdown_requested` | Explicit shutdown via stop() | Normal |
| `drain_timeout` | Drain exceeded 5000 ms budget | Large queued backlog; check persistence latency |
| `engine_exit` | Engine process exited | Normal; check exit code for errors |

## Accounting Fields

Every snapshot and report includes these counters:

| Field | Meaning |
|-------|---------|
| `accepted_total` | Events successfully enqueued for persistence |
| `persisted_total` | Events written to the storage adapter |
| `shed_total` | Events dropped due to full queue or oversized payload |
| `dropped_total` | Events lost due to persistence failure or disconnected queue |
| `retry_total` | Enqueue retries before acceptance or shedding |
| `queue_depth` | Current number of events in the persistence queue |
| `queue_capacity` | Maximum queue depth (256 by default) |
| `active_connections` | Currently open engine connections |

**Invariant**: After a clean drain, `persisted_total == accepted_total` and
`queue_depth == 0`. If `drain_completed == false`, some accepted events may not
have been persisted.

**Accounting check**: `accepted_total + shed_total + dropped_total` should equal
the total number of events the engine attempted to send.

## Design Budgets

| Parameter | Value | Source |
|-----------|-------|--------|
| Queue capacity | 256 events | `PERSIST_QUEUE_CAPACITY` |
| Max event size | 64 KB | `MAX_EVENT_BYTES` |
| Max connections | 64 | `MAX_ACTIVE_CONNECTIONS` |
| Enqueue timeout | 50 ms | `ENQUEUE_TIMEOUT_MS` |
| Drain timeout | 5000 ms | `DEFAULT_DRAIN_TIMEOUT_MS` |
| Accept poll | 100 ms | `ACCEPT_POLL_INTERVAL_MS` |

## Common Failure Modes

### 1. Drain did not complete (report.drain_completed == false)

**Symptoms**: Warning message at shutdown:
```
Warning: telemetry drain did not complete within 5000ms
(N events persisted, M shed, K dropped)
```

**Diagnosis**:
1. Check `persisted_total` vs `accepted_total` — the gap is events lost
2. Check if persistence adapter was slow (storage I/O pressure)
3. Check `recent_events` for `TELEMETRY_BRIDGE_DRAIN_TIMEOUT`

**Resolution**: If recurring, investigate storage latency. The 5-second drain
budget is generous; timeouts indicate systemic persistence issues.

### 2. High shed_total

**Symptoms**: `shed_total >> 0` in the runtime report.

**Diagnosis**:
1. Check for `ADMISSION_SHED` events with `queue_full_shed` reason
2. Check for `ADMISSION_SHED` events with `event_too_large` reason
3. Check `retry_total` — high retries suggest borderline capacity

**Resolution**:
- If `queue_full_shed`: Engine is producing events faster than persistence
  can write. Check storage throughput. Consider if all events are necessary.
- If `event_too_large`: Engine is sending payloads over 64 KB. Fix the
  event source to produce smaller payloads.

### 3. Connection rejected (connection_cap)

**Symptoms**: `CONNECTION_REJECTED` events with `connection_cap` reason.

**Diagnosis**: 64 concurrent connections reached. This is unusual for a
single engine but could happen with connection leaks.

**Resolution**: Check if the engine is opening connections without closing
them. Each connection should be short-lived.

### 4. Bridge stuck in Degraded state

**Symptoms**: Lifecycle state is `Degraded` instead of `Running`.

**Diagnosis**: A non-fatal accept() error occurred. Check `recent_events`
for `CONNECTION_READ_FAILED` with detail.

**Resolution**: Usually transient. The bridge continues accepting connections.
If persistent, check the socket file and filesystem permissions.

### 5. Bridge failed to start

**Symptoms**: `start()` returns an error.

**Diagnosis**:
- "telemetry bridge listener already started" — double-start attempt
- Socket bind error — check file permissions and path
- "telemetry adapter lock poisoned" — internal panic in a prior operation

**Resolution**: Ensure only one `start()` call per bridge instance. Check that
the socket directory exists and is writable.

## Artifact Locations

| Artifact | Path | Contents |
|----------|------|----------|
| E2E lifecycle suite | `tests/e2e/telemetry_lifecycle_e2e_suite.sh` | 13-stage lifecycle verification |
| E2E lifecycle results | `artifacts/asupersync/bd-1now.4.6/` | JSONL logs, JSON summary, markdown |
| Performance harness | `tests/e2e/telemetry_perf_characterization.sh` | 6 perf characterization tests |
| Performance results | `artifacts/asupersync/bd-1now.4.7/` | Throughput, latency, burst evidence |
| Unit/integration tests | `crates/franken-node/src/ops/telemetry_bridge.rs` | 42 tests in `mod tests` |
| Implementation | `crates/franken-node/src/ops/telemetry_bridge.rs` | Bridge, handle, lifecycle |
| EngineDispatcher wiring | `crates/franken-node/src/ops/engine_dispatcher.rs` | Lifecycle integration |

## Quick Diagnostic Steps

1. **Check the report**: After `stop_and_join()`, inspect `TelemetryRuntimeReport`:
   - `drain_completed` — did all queued work finish?
   - `final_state` — `Stopped` is good, `Failed` needs investigation
   - `accepted_total == persisted_total` — all accepted work committed?

2. **Check recent events**: The report includes the last 256 structured events.
   Filter by event code to find the relevant failure.

3. **Re-run E2E suite**: `bash tests/e2e/telemetry_lifecycle_e2e_suite.sh` to
   verify the lifecycle is healthy. Check `artifacts/asupersync/bd-1now.4.6/`
   for results.

4. **Re-run perf characterization**: `bash tests/e2e/telemetry_perf_characterization.sh`
   to check if throughput or latency has regressed. Compare against the baseline
   in `artifacts/asupersync/bd-1now.4.7/`.
