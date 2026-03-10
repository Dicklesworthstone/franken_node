# Asupersync Control Surface Migration Plan

**Bead:** bd-2h2s | **Section:** 10.15 | **Version:** mig-v1.0
**Date:** 2026-02-21 | **Owner:** franken-node control-plane team

## Overview

This document defines the migration plan for existing non-asupersync control surfaces
in the `connector/` and `conformance/` modules. The asupersync pattern requires that all
control surfaces participating in epoch-scoped state transitions use the canonical
asupersync protocol: deterministic serialization, epoch-bounded validity, idempotent
replay, and fail-closed rejection of stale artifacts.

Modules that predate the asupersync contract must be migrated or granted a time-boxed
exception with owner and expiry.

## Inventory of Non-Asupersync Control Surfaces

### connector/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 1 | connector/lifecycle.rs | `transition()` | INV-MIG-EPOCH-SCOPED | Epoch-bounded transition validation | bd-1cs7 | completed | Transition calls check_artifact_epoch before state change |
| 2 | connector/rollout_state.rs | `persist_state()` | INV-MIG-DETERMINISTIC-SER | Canonical deterministic serialization | bd-1cwp | completed | Uses canonical_serializer for all persisted state |
| 3 | connector/health_gate.rs | `evaluate()` | INV-MIG-EPOCH-SCOPED | Epoch-bounded health evaluation | bd-145n | in_progress | Health gate results carry epoch scope tags |
| 4 | connector/fencing.rs | `validate_fence()` | INV-MIG-IDEMPOTENT | Idempotent fence token validation | bd-3h63 | in_progress | Fence validation is idempotent across replays |
| 5 | connector/repair_controller.rs | `run_cycle()` | INV-MIG-FAIL-CLOSED | Fail-closed on stale repair directives | bd-3014 | not_started | Repair cycles reject stale-epoch directives |
| 6 | connector/retention_policy.rs | `enforce()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped retention enforcement | bd-25oa | not_started | Retention decisions are epoch-bounded |
| 7 | connector/snapshot_policy.rs | `should_snapshot()` | INV-MIG-DETERMINISTIC-SER | Deterministic snapshot trigger evaluation | bd-3tpg | in_progress | Snapshot decisions use canonical serialization |
| 8 | connector/activation_pipeline.rs | `activate()` | INV-MIG-FAIL-CLOSED | Fail-closed activation with epoch check | bd-3u6o | not_started | Activation rejects artifacts from wrong epoch |
| 9 | connector/quarantine_promotion.rs | `promote()` | INV-MIG-IDEMPOTENT | Idempotent promotion with replay safety | bd-cuut | completed | Promotion is idempotent; replays produce same result |

### conformance/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 10 | conformance/protocol_harness.rs | `run_harness()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped conformance evaluation | bd-1hbw | in_progress | Harness results carry epoch metadata |
| 11 | conformance/connector_method_validator.rs | `validate_contract()` | INV-MIG-DETERMINISTIC-SER | Deterministic validation report output | bd-3014 | not_started | Validation reports use canonical serialization |

### supply_chain/ Module Surfaces

| # | Module | Function | Invariant Violated | Target Pattern | Target Bead | Status | Closure Criteria |
|---|--------|----------|--------------------|----------------|-------------|--------|------------------|
| 12 | supply_chain/artifact_signing.rs | `sign_artifact()` | INV-MIG-EPOCH-SCOPED | Epoch-scoped signing with validity window | bd-1cwp | completed | Signatures include epoch scope in signed payload |
| 13 | supply_chain/manifest.rs | `validate()` | INV-MIG-FAIL-CLOSED | Fail-closed manifest validation | bd-3h63 | in_progress | Manifest validation rejects stale-epoch manifests |
| 14 | supply_chain/provenance_gate.rs | `check_provenance()` | INV-MIG-IDEMPOTENT | Idempotent provenance checks | bd-25oa | not_started | Provenance checks produce identical results on replay |

## Exception Surfaces

The following surfaces are granted time-boxed exceptions from the asupersync migration.
Each exception has a documented justification, designated owner, and hard expiry date.

| # | Module | Function | Justification | Owner | Expiry |
|---|--------|----------|---------------|-------|--------|
| E1 | connector/repair_controller.rs | `emergency_repair()` | Emergency repair path must bypass epoch checks for disaster recovery; gated by operator escalation token | @infra-oncall | 2026-06-30 |
| E2 | conformance/connector_method_validator.rs | `validate_legacy_v0()` | Legacy v0 connectors do not support epoch metadata; scheduled for deprecation in v2.0 | @connector-team | 2026-09-30 |

## Burn-Down Schedule

### Milestone 1: Foundation (2026-02-28)
- Complete migration of all `completed` surfaces (lifecycle, rollout_state, quarantine_promotion, artifact_signing)
- Verify epoch-scoped tags in completed modules

### Milestone 2: In-Progress Closure (2026-03-31)
- Close all `in_progress` surfaces (health_gate, fencing, snapshot_policy, protocol_harness, manifest)
- Integration tests for epoch-bounded behavior in each module

### Milestone 3: Remaining Surfaces (2026-05-31)
- Migrate all `not_started` surfaces (repair_controller, retention_policy, activation_pipeline, connector_method_validator, provenance_gate)
- Exceptions reviewed and renewed or closed

### Milestone 4: Full Closure (2026-06-30)
- All non-excepted surfaces migrated
- Exception E1 reviewed for renewal or closure
- Burn-down CSV shows 100% completion (excluding active exceptions)

## Tracking

The burn-down CSV at `artifacts/10.15/control_surface_burndown.csv` is the machine-readable
source of truth. The gate script `scripts/check_control_surface_burndown.py` validates
consistency between this CSV and the migration plan.

## Invariants

| ID | Statement |
|----|-----------|
| INV-MIG-INVENTORIED | Every non-asupersync control surface is inventoried in the burn-down CSV |
| INV-MIG-STATUS-VERIFIED | Migration status in CSV matches implementation state |
| INV-MIG-EXPIRY-ENFORCED | No exception surface has an expired exception date |
| INV-MIG-EPOCH-SCOPED | Migrated surfaces use epoch-bounded validity |
| INV-MIG-DETERMINISTIC-SER | Migrated surfaces use canonical deterministic serialization |
| INV-MIG-IDEMPOTENT | Migrated surfaces support idempotent replay |
| INV-MIG-FAIL-CLOSED | Migrated surfaces fail closed on stale artifacts |

## Event Codes

| Code | Description |
|------|-------------|
| MIG-001 | Surface migration completed successfully |
| MIG-002 | Surface migration in progress |
| MIG-003 | Exception granted for surface |
| MIG-004 | Exception expired; surface must be migrated |
| MIG-005 | Burn-down milestone reached |

## Selective Runtime Seam Contract (`bd-1now.4.1`)

This appendix records the design contract for the telemetry ingestion seam
identified in the selective Asupersync audit. It is intentionally grounded in
the current implementation:

- `crates/franken-node/src/ops/engine_dispatcher.rs` creates the telemetry
  socket path, starts `TelemetryBridge` as a side effect, then waits only on
  the engine child process.
- `crates/franken-node/src/ops/telemetry_bridge.rs` binds a Unix socket,
  detaches one listener thread, detaches one thread per accepted connection,
  and writes telemetry through a shared `Arc<Mutex<FrankensqliteAdapter>>`.
- Errors are emitted with `eprintln!`, not a structured lifecycle or
  accounting surface.

The goal is not a crate-wide runtime rewrite. The goal is to turn this one seam
into an explicit, owned, diagnosable runtime surface.

### Decision

`franken_node` SHOULD implement this seam with a local owned-worker design that
mirrors Asupersync semantics rather than introducing a new direct native
Asupersync dependency right now.

Why:

- the seam needs owned work, bounded admission, deterministic drain, and
  explicit failure reasoning immediately;
- the crate still does not own a broader async service boundary that would
  justify pulling native request-region or scheduler ownership deeper into the
  product crate;
- the implementation beads that follow (`bd-1now.4.2` through `.4.4`) need a
  clear contract more than they need a symbolic substrate migration.

If `franken_node` later grows a real async network boundary or requires shared
ownership with upstream scheduler/cancellation services, that is the time to
re-evaluate direct native Asupersync primitives.

### Ownership Topology

| Component | Owns | Must Not Own |
|---|---|---|
| `EngineDispatcher` | engine child lifecycle, telemetry runtime handle, final stop/join/error propagation | socket accept loop internals, adapter mutation |
| Telemetry listener owner | socket bind, accept loop, connection admission, socket cleanup | persistence writes, child process lifecycle |
| Connection reader workers | one accepted stream each, line framing, enqueue into bounded admission queue | direct adapter access, lifecycle decisions for the whole bridge |
| Persistence owner | sole mutable `FrankensqliteAdapter`, audit-log key generation, persistence sequencing, final write verdicts | socket accept/read ownership |
| Shared metrics/state | atomics or immutable snapshots for counters/state publication | mutable shared adapter access via `Mutex` |

Required consequence:

- `FrankensqliteAdapter` becomes single-owner inside the telemetry runtime.
- `Arc<Mutex<FrankensqliteAdapter>>` is replaced by a bounded handoff to the
  persistence owner.
- `EngineDispatcher` receives a real telemetry runtime handle instead of
  fire-and-forget background work.

### Admission And Backpressure Policy

The admission unit is one parsed newline-delimited telemetry event.

| Surface | Policy |
|---|---|
| Connection admission | bounded by `max_active_connections`; excess connections are rejected immediately with a stable reason code |
| Event admission | bounded by `event_queue_capacity`; readers attempt enqueue for at most `enqueue_timeout_ms` |
| Overflow behavior | if the queue stays full past the timeout, the current event is shed explicitly, counters advance, and a structured overflow event is emitted |
| Persistence ownership | one persistence owner drains the queue FIFO and performs all writes |
| Bridge shutdown | once shutdown begins, no new events are accepted; already accepted events must drain to a terminal outcome before join returns |

The contract explicitly chooses "bounded wait, then shed newest admission"
instead of unbounded blocking. That preserves operator-visible determinism and
prevents hidden engine stalls caused by implicit socket or mutex backpressure.

### Lifecycle API Exposed To `EngineDispatcher`

The target API surface is:

```rust
TelemetryBridge::start(config) -> Result<TelemetryRuntimeHandle, TelemetryStartError>

TelemetryRuntimeHandle::socket_path(&self) -> &Path
TelemetryRuntimeHandle::snapshot(&self) -> TelemetryRuntimeSnapshot
TelemetryRuntimeHandle::stop(&self, reason: ShutdownReason)
TelemetryRuntimeHandle::join(self, deadline: Duration) -> Result<TelemetryRuntimeReport, TelemetryJoinError>
```

`EngineDispatcher::dispatch_run()` must follow this ownership sequence:

1. create the telemetry runtime and obtain the handle,
2. pass the socket path to the engine child,
3. wait for engine child exit,
4. call `stop()` with the child-exit reason,
5. call `join()` and surface any runtime failure or drain timeout as an
   explicit dispatcher error.

Startup failure is fatal. Runtime failure is not allowed to disappear into
stderr: it must transition the telemetry runtime to a terminal `Failed` state
and be observable from `join()`.

### Lifecycle States

| State | Meaning | Terminal |
|---|---|---|
| `Cold` | handle not started yet | no |
| `Starting` | binding socket and starting owned workers | no |
| `Running` | accepting connections and events normally | no |
| `Degraded` | still running, but non-fatal overflow/shedding or reader loss has occurred | no |
| `Draining` | shutdown requested; no new admission, accepted work flushing to terminal outcomes | no |
| `Stopped` | clean stop and drain completed | yes |
| `Failed` | fatal start/runtime/drain failure | yes |

Allowed transitions:

- `Cold -> Starting -> Running`
- `Running -> Degraded`
- `Running -> Draining -> Stopped`
- `Degraded -> Draining -> Stopped`
- `Starting -> Failed`
- `Running -> Failed`
- `Degraded -> Failed`
- `Draining -> Failed`

### Structured Event Families

The implementation must replace ad hoc `eprintln!` diagnostics with stable
event families:

| Family | Purpose |
|---|---|
| `TELEMETRY_BRIDGE_STATE_*` | lifecycle transitions and terminal state summaries |
| `TELEMETRY_BRIDGE_CONNECTION_*` | accept/reject/close/failure for each connection |
| `TELEMETRY_BRIDGE_ADMISSION_*` | enqueue success, queue-full shedding, drain refusal |
| `TELEMETRY_BRIDGE_PERSIST_*` | write success/failure and retry verdicts |
| `TELEMETRY_BRIDGE_DRAIN_*` | stop requested, drain start, drain complete, drain timeout |

Every emitted event must carry these fields where applicable:

- `bridge_id`
- `run_id`
- `state`
- `reason_code`
- `socket_path`
- `queue_depth`
- `queue_capacity`
- `active_connections`
- `accepted_total`
- `persisted_total`
- `shed_total`
- `dropped_total`
- `retry_total`
- `connection_id`
- `bridge_seq`
- `engine_pid`

`reason_code` must use a stable vocabulary, including at least:

- `bind_failed`
- `connection_cap`
- `queue_full_shed`
- `reader_failed`
- `persist_failed`
- `shutdown_requested`
- `drain_timeout`
- `socket_cleanup_failed`
- `engine_exit`

### Event-Accounting Semantics

| Counter / term | Meaning |
|---|---|
| `accepted` | event parsed successfully and admitted into the bounded queue |
| `persisted` | accepted event written successfully by the persistence owner |
| `shed` | event rejected before acceptance because admission was closed or queue wait expired |
| `dropped` | previously accepted event could not be persisted because the bridge entered terminal failure during drain |
| `retried` | second or later persistence attempt for an already accepted event |
| `drained` | accepted event reached a terminal outcome (`persisted` or `dropped`) before `join()` returned |

Required invariants:

- `INV-TB-SINGLE-WRITER`: only the persistence owner mutates
  `FrankensqliteAdapter`.
- `INV-TB-TERMINAL-BUCKET`: every accepted event ends in exactly one terminal
  bucket: `persisted` or `dropped`.
- `INV-TB-SHED-EXPLICIT`: every shed event advances counters and emits a stable
  admission event with a reason code.
- `INV-TB-DRAIN-CLOSED`: after `stop()`, `join()` returns only after all
  accepted events are terminalized or a drain timeout is reported.
- `INV-TB-PERSIST-IMPLIES-ACCEPTED`: `persisted_total <= accepted_total` always.
- `INV-TB-PER-CONNECTION-ORDER`: within a single connection, accepted events
  preserve parse order; if shedding creates a gap, the gap is reported before
  later persisted events for that connection.
- `INV-TB-GLOBAL-SEQUENCE`: every accepted event receives a monotonic
  `bridge_seq` so replay artifacts can reconstruct bridge-observed ordering even
  when multiple connections interleave.

### Ordering And Failure Semantics

- Global total order across connections is not guaranteed by wall-clock arrival.
  It is guaranteed only by the bridge-assigned `bridge_seq`.
- Per-connection ordering is strict for all persisted events that survive
  admission.
- Persistence failures are fail-closed for the runtime handle: the bridge moves
  to `Failed`, stops accepting new work, and returns the failure through
  `join()`.
- Overflow is non-fatal but must move the runtime to `Degraded` and remain
  visible in the final report.

### Proof Obligations For Follow-On Beads

`bd-1now.4.2` through `.4.8` must prove this contract with:

- deterministic unit tests for state transitions, admission limits,
  single-writer persistence ownership, and terminal accounting;
- integration tests covering child-exit drain, persistence failure, connection
  rejection, and queue-full shedding;
- at least one end-to-end harness that exercises successful drain, overflow,
  and terminal failure with artifact-rich logs;
- structured machine-readable closeout artifacts carrying the final counters,
  state transitions, reason codes, and any gap receipts;
- throughput and shutdown-envelope evidence collected with heavy cargo
  validation routed through `rch`, not local cargo execution.

### Baseline Comparison Requirements

Future performance and closeout evidence must compare against the current
pre-refactor behavior of:

- detached listener thread with no handle,
- detached per-connection threads,
- shared `Arc<Mutex<FrankensqliteAdapter>>` persistence,
- no explicit connection cap,
- no bounded event queue,
- no structured overflow accounting,
- no dispatcher-visible stop/join/error surface.

At minimum, the closeout gate must compare:

- telemetry startup latency,
- engine-exit-to-bridge-drain latency,
- sustained events/sec until first shed,
- `p95` persistence latency,
- shed/dropped totals under overload,
- socket cleanup/rebind determinism,
- completeness of structured lifecycle/error reporting.

### Fixed, Tunable, And Auto-Derived Budgets

| Class | Items | Why |
|---|---|---|
| Fixed | lifecycle state names, reason-code vocabulary, single-writer persistence rule, terminal accounting invariants | these must stay stable so tests, logs, and operator references do not drift |
| Tunable | `max_active_connections`, `event_queue_capacity`, `enqueue_timeout_ms`, `drain_timeout_ms`, `max_event_bytes` | these are deployment- and workload-sensitive knobs that operators may need to tune explicitly |
| Fixed for v1 | `persist_retry_limit = 0` | persistence failure reasoning stays deterministic; retries can be introduced later only with explicit accounting changes |
| Auto-derived | queue warning threshold as a percentage of capacity, drain deadline extension from pending accepted work, periodic degraded-state summaries | these are safer as derived values because they should track live workload shape rather than force operators to hand-compute every threshold |

This contract intentionally gives `EngineDispatcher` explicit ownership, gives
the telemetry runtime bounded admission and explicit degradation semantics, and
keeps the implementation local until the crate grows a broader async boundary
that justifies a deeper native Asupersync migration.
