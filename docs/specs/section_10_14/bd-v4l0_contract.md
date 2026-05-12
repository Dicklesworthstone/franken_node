# bd-v4l0: Global Remote Bulkhead with Deterministic Backpressure

## Purpose

Implement a capability-gated concurrency limiter (bulkhead) for network-bound
remote operations. The bulkhead enforces a hard cap on in-flight permits,
supports configurable backpressure policy (reject or bounded queue), runtime cap
changes with drain semantics, foreground latency tracking, and structured event
telemetry.

## Invariants

- **INV-RB-CAPPED**: The number of outstanding permits never exceeds `max_in_flight`.
- **INV-RB-BACKPRESSURE**: When at capacity, the configured `BackpressurePolicy` (Reject or Queue) is applied deterministically; no request is silently dropped.
- **INV-RB-SAFE-DRAIN**: When `set_max_in_flight()` reduces the cap below the current in-flight count, the bulkhead enters draining mode and rejects new acquires until in-flight drops below the target.
- **INV-RB-GATED**: Every `acquire()` call requires `RemoteCapLookup::Granted`; denied or missing capability yields `RemoteCapRequired` immediately.
- **INV-RB-AUDITABLE**: All significant state transitions emit a `BulkheadEvent` with a stable event code, enabling external audit.
- **INV-RB-DETERMINISTIC**: Latency percentile computation (p99) is deterministic: given the same sample set, the result is always identical.

## Types

### BackpressurePolicy

Enum selecting backpressure strategy when the bulkhead is full:
- `Reject` -- reject immediately
- `Queue { max_depth, timeout_ms }` -- enqueue with bounded wait

### BulkheadPermit

Issued permit representing one in-flight remote operation:
- `permit_id: u64` -- monotonic unique ID
- `issued_at_ms: u64` -- wall-clock timestamp at issuance
- `cap_snapshot: usize` -- max_in_flight at the moment of issuance

### BulkheadEvent

Structured telemetry record:
- `event_code: String` -- stable event code (see below)
- `now_ms: u64` -- event timestamp
- `in_flight: usize` -- current in-flight count
- `max_in_flight: usize` -- current cap
- `detail: String` -- human-readable context

### ForegroundLatencySample

Latency observation under load:
- `in_flight: usize`
- `latency_ms: u64`

### BulkheadError

Error type with stable error codes:
- `RemoteCapRequired` -- `RB_ERR_NO_REMOTECAP`
- `AtCapacity { cap, in_flight }` -- `RB_ERR_AT_CAPACITY`
- `QueueSaturated { max_depth }` -- `RB_ERR_QUEUE_SATURATED`
- `Queued { request_id, position, timeout_ms }` -- `RB_ERR_QUEUED`
- `QueueTimeout { request_id }` -- `RB_ERR_QUEUE_TIMEOUT`
- `UnknownRequest { request_id }` -- `RB_ERR_UNKNOWN_REQUEST`
- `DuplicateRequest { request_id }` -- `RB_ERR_DUPLICATE_REQUEST`
- `UnknownPermit { permit_id }` -- `RB_ERR_UNKNOWN_PERMIT`
- `InvalidPermit { permit_id }` -- `RB_ERR_INVALID_PERMIT`
- `PermitIdExhausted { request_id }` -- `RB_ERR_PERMIT_ID_EXHAUSTED`
- `InvalidRequestId { detail }` -- `RB_ERR_INVALID_REQUEST_ID`
- `Draining { in_flight, target_cap }` -- `RB_ERR_DRAINING`
- `InvalidConfig { reason }` -- `RB_ERR_INVALID_CONFIG`

### RemoteBulkhead

Global concurrency limiter:
- `max_in_flight: usize` -- configurable cap
- `in_flight: usize` -- current outstanding permits
- `policy: BackpressurePolicy` -- backpressure strategy
- `queue: VecDeque<QueuedRequest>` -- bounded wait queue
- `outstanding_permits: BTreeSet<u64>` -- active permit IDs
- `draining_target: Option<usize>` -- drain target when cap is reduced
- `p99_target_ms: u64` -- latency SLO target
- `latency_samples: Vec<ForegroundLatencySample>` -- recorded observations
- `events: Vec<BulkheadEvent>` -- audit log

## Operations

### `new(max_in_flight, policy, p99_target_ms) -> Result<Self, BulkheadError>`

Construct a new bulkhead. Validates that `max_in_flight > 0`,
`p99_target_ms > 0`, and the backpressure policy configuration.

### `acquire(remote_cap, request_id, now_ms) -> Result<BulkheadPermit, BulkheadError>`

Acquire a permit for a remote operation. Rejects unless `remote_cap` is
`RemoteCapLookup::Granted`. Applies backpressure policy when at capacity.
Blocks during drain.

### `release(permit, now_ms) -> Result<(), BulkheadError>`

Release a previously issued permit. Decrements in-flight count and may
clear draining state if in-flight drops below target.

### `poll_queued(request_id, now_ms) -> Result<BulkheadPermit, BulkheadError>`

Retry admission for a queued request. Promotes the front-of-queue request
when capacity becomes available.

### `set_max_in_flight(new_cap, now_ms) -> Result<(), BulkheadError>`

Hot-reload max concurrency cap. If cap is reduced below current in-flight
count, activates drain mode.

### `record_foreground_latency(latency_ms, now_ms)`

Record a foreground latency observation under current load and emit an
`RB_LATENCY_REPORT` event with the supplied timestamp.

### `p99_foreground_latency_ms() -> Option<u64>`

Compute the p99 latency from the current sample set. Deterministic.

### `latency_within_target() -> bool`

Returns true if measured p99 is at or below `p99_target_ms`.

## Event Codes

| Code | Trigger |
|------|---------|
| `RB_PERMIT_ACQUIRED` | Permit successfully issued |
| `RB_PERMIT_RELEASED` | Permit returned |
| `RB_AT_CAPACITY` | Acquire attempted while at max capacity |
| `RB_REQUEST_QUEUED` | Request enqueued under Queue policy |
| `RB_REQUEST_REJECTED` | Request rejected (policy, cap check, or missing capability) |
| `RB_CAP_CHANGED` | `set_max_in_flight()` changed the cap |
| `RB_DRAIN_ACTIVE` | Drain mode activated or continuing |
| `RB_LATENCY_REPORT` | Foreground latency sample recorded |

## Error Codes

| Code | Variant |
|------|---------|
| `RB_ERR_NO_REMOTECAP` | RemoteCapRequired |
| `RB_ERR_AT_CAPACITY` | AtCapacity |
| `RB_ERR_QUEUE_SATURATED` | QueueSaturated |
| `RB_ERR_QUEUED` | Queued |
| `RB_ERR_QUEUE_TIMEOUT` | QueueTimeout |
| `RB_ERR_UNKNOWN_REQUEST` | UnknownRequest |
| `RB_ERR_DUPLICATE_REQUEST` | DuplicateRequest |
| `RB_ERR_UNKNOWN_PERMIT` | UnknownPermit |
| `RB_ERR_INVALID_PERMIT` | InvalidPermit |
| `RB_ERR_PERMIT_ID_EXHAUSTED` | PermitIdExhausted |
| `RB_ERR_INVALID_REQUEST_ID` | InvalidRequestId |
| `RB_ERR_DRAINING` | Draining |
| `RB_ERR_INVALID_CONFIG` | InvalidConfig |

## Acceptance Criteria

1. `acquire()` never issues a permit when `in_flight >= max_in_flight` (INV-RB-CAPPED).
2. Under `BackpressurePolicy::Reject`, at-capacity requests receive `AtCapacity` error immediately.
3. Under `BackpressurePolicy::Queue`, at-capacity requests are enqueued up to `max_depth`; deeper requests get `QueueSaturated`.
4. Queue entries expire after `timeout_ms`; expired entries are evicted on the next `acquire()` or `poll_queued()` call.
5. `acquire()` with `RemoteCapLookup::Denied` or `RemoteCapLookup::NotPresent` returns `RemoteCapRequired` without modifying state or queueing work (INV-RB-GATED).
6. `set_max_in_flight()` below current in-flight activates drain mode (INV-RB-SAFE-DRAIN).
7. Drain mode blocks new acquires until in-flight drops below target.
8. `release()` of an unknown permit returns `UnknownPermit` (fail-closed).
9. `p99_foreground_latency_ms()` is deterministic (INV-RB-DETERMINISTIC).
10. All state transitions emit a `BulkheadEvent` with stable event codes (INV-RB-AUDITABLE).
11. At least 10 unit tests covering happy path, reject, queue, drain, latency, and error cases.

## Artifacts

- Implementation: `crates/franken-node/src/remote/remote_bulkhead.rs`
- Verification script: `scripts/check_remote_bulkhead.py`
- Unit tests: `tests/test_check_remote_bulkhead.py`
- Cargo load/integration test: `tests/perf/remote_bulkhead_under_load.rs`
- Evidence: `artifacts/section_10_14/bd-v4l0/verification_evidence.json`
- Summary: `artifacts/section_10_14/bd-v4l0/verification_summary.md`
