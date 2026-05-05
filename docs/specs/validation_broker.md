# bd-1khdi Contract: Validation Broker Receipt and Queue Contract

**Bead:** bd-1khdi
**Status:** Active
**Owner:** PinkFern
**Schema:** validation-broker-v1.0

## Overview

The validation broker is the product contract for coordinating expensive or
blocked validation work across agents. It turns requested commands into
deduplicated queue entries, records RCH and local-source-only outcomes, and
emits receipts that Beads closeout, doctor readiness, and CI gates can consume
without reading chat history.

This contract is intentionally cargo-free. The schema catalog and fixtures under
`artifacts/validation_broker/` plus `scripts/check_validation_broker_contract.py`
must be enough to validate the receipt format on a busy machine.

## Data Model

### ValidationBrokerRequest

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | String | Yes | `franken-node/validation-broker/request/v1` |
| `request_id` | String | Yes | Stable request ID, preferably `vbreq-<uuid-or-hash>` |
| `bead_id` | String | Yes | Beads issue ID that owns the validation request |
| `thread_id` | String | Yes | Agent Mail thread ID, normally equal to `bead_id` |
| `requester_agent` | String | Yes | Agent identity that requested the work |
| `created_at` | RFC3339 String | Yes | UTC request timestamp |
| `priority` | Enum | Yes | `low`, `normal`, `high`, or `urgent` |
| `command` | Object | Yes | Command program, argv, cwd, env policy, and target-dir policy |
| `inputs` | Object | Yes | Git commit, dirty-state policy, changed paths, and content digests |
| `dedupe_key` | Object | Yes | Deterministic SHA-256 digest over command, inputs, feature flags, and bead ID |
| `output_policy` | Object | Yes | Paths and retention policy for stdout, stderr, summaries, and receipts |
| `fallback_policy` | Object | Yes | Whether source-only fallback is allowed and which reasons are accepted |

### BrokerQueueEntry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `queue_id` | String | Yes | Stable queue entry ID |
| `request` | ValidationBrokerRequest | Yes | Request payload being scheduled |
| `queue_state` | Enum | Yes | `queued`, `leased`, `running`, `completed`, `failed`, or `cancelled` |
| `dedupe_key` | Object | Yes | Copy of the request dedupe key used for coalescing |
| `lease` | Object | Yes | Lease holder, lease start, expiration, and renew count |
| `worker_requirements` | Object | Yes | RCH requirement, cargo toolchain, feature flags, and max wall time |
| `observations` | Array | Yes | Worker capability observations collected while scheduling |

### WorkerCapabilityObservation

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `observation_id` | String | Yes | Stable observation ID |
| `worker_id` | String | Yes | RCH worker name, host alias, or `local` |
| `observed_at` | RFC3339 String | Yes | UTC observation timestamp |
| `rch_mode` | Enum | Yes | `remote`, `local_fallback`, `not_used`, or `unavailable` |
| `reachable` | Boolean | Yes | Whether the worker accepted a control operation |
| `capabilities` | Object | Yes | Toolchain, CPU, disk, and supported cargo feature notes |
| `failure` | Object or null | Yes | Error class and detail when capability probing failed |

### ValidationReceipt

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | String | Yes | `franken-node/validation-broker/receipt/v1` |
| `receipt_id` | String | Yes | Stable receipt ID |
| `request_id` | String | Yes | ValidationBrokerRequest ID |
| `bead_id` | String | Yes | Bead proved or blocked by the receipt |
| `thread_id` | String | Yes | Agent Mail thread where the receipt is announced |
| `request_ref` | Object | Yes | At minimum `request_id`, `bead_id`, `thread_id`, and `dedupe_key` |
| `command` | Object | Yes | Program, argv, cwd, env policy ID, target-dir policy ID |
| `command_digest` | Object | Yes | SHA-256 digest over canonical command material |
| `environment_policy` | Object | Yes | Allowed env vars, redacted vars, remote requirement, and network policy |
| `target_dir_policy` | Object | Yes | Off-repo or repo-local target-dir policy and digest |
| `input_digests` | Array | Yes | Non-empty content digests for source/spec/artifact inputs |
| `rch` | Object | Yes | RCH mode, worker identity when known, and capability observation link |
| `timing` | Object | Yes | `started_at`, `finished_at`, `duration_ms`, and `freshness_expires_at` |
| `exit` | Object | Yes | Outcome kind, exit code, error class, timeout class, and retryability |
| `artifacts` | Object | Yes | stdout, stderr, summary, and receipt artifact paths plus content digests |
| `trust` | Object | Yes | Generator, git commit, dirty-state policy, freshness, and signature status |
| `classifications` | Object | Yes | Source-only fallback, doctor readiness, and CI consumption status |

## Required Enumerations

### Timeout Classes

| Value | Meaning |
|-------|---------|
| `none` | Command completed without timeout classification |
| `queue_wait` | Waited too long before a worker lease began |
| `rch_dispatch` | RCH dispatch failed before command execution |
| `ssh_command` | Remote SSH command timed out |
| `cargo_test_timeout` | Cargo test process hit its configured timeout |
| `process_idle` | Process made no observable progress for the idle budget |
| `process_wall` | Process exceeded total wall-clock budget |
| `worker_unreachable` | Worker could not be reached or probed |
| `unknown` | Timeout occurred but cannot be narrowed further |

### Error Classes

`none`, `compile_error`, `test_failure`, `clippy_warning`, `format_failure`,
`transport_timeout`, `worker_infra`, `environment_contention`, `disk_pressure`,
`source_only`, and `unknown`.

### Source-Only Fallback Reasons

`cargo_contention`, `rch_unavailable`, `sibling_dependency_blocker`,
`disk_pressure`, `reserved_surface`, `no_cargo_requested`, and `docs_only`.

## Invariants

- **INV-VB-RECEIPT-REQUIRED** - Any validation result used for Beads closeout,
  doctor readiness, or CI gate consumption has a ValidationReceipt.
- **INV-VB-DEDUPE-DETERMINISTIC** - Queue dedupe keys are SHA-256 digests over
  canonical request material and do not depend on wall-clock order.
- **INV-VB-COMMAND-DIGEST** - A receipt is invalid if `command_digest.hex` is
  missing, malformed, or does not match `command_digest.canonical_material`.
- **INV-VB-BEAD-THREAD-MATCH** - `bead_id`, `thread_id`, and `request_ref.bead_id`
  must match the owning Beads issue unless an explicit cross-thread waiver is
  present in `request_ref.cross_thread_waiver`.
- **INV-VB-RCH-CLASSIFIED** - RCH execution, local fallback, unavailability, and
  worker capability observations are represented explicitly.
- **INV-VB-TIME-BOUNDED** - Receipts include start, finish, duration, and
  freshness-expiration timestamps; stale receipts cannot satisfy closeout.
- **INV-VB-ARTIFACT-PATHS** - stdout, stderr, summary, and receipt artifact paths
  are stable repo-relative paths with content digests.
- **INV-VB-SOURCE-ONLY-EXPLICIT** - Source-only fallback must set
  `classifications.source_only_fallback=true` and use an allowed fallback reason.
- **INV-VB-DOCTOR-READY** - Doctor readiness can be derived from queue depth,
  oldest queued age, active leases, worker reachability, and blocked classes.
- **INV-VB-CI-CONSUMABLE** - CI gate consumers can fail closed by reading only
  schema version, bead ID, command digest, timing, exit, artifact paths, and
  trust freshness.

## Error Codes

| Code | Description |
|------|-------------|
| `ERR_VB_INVALID_SCHEMA_VERSION` | Unknown request, queue, observation, or receipt schema version |
| `ERR_VB_MALFORMED_RECEIPT` | Receipt is not an object or required object structure is missing |
| `ERR_VB_MISSING_COMMAND_DIGEST` | Receipt lacks a valid SHA-256 command digest |
| `ERR_VB_STALE_RECEIPT` | Receipt freshness has expired for the validation consumer |
| `ERR_VB_BEAD_MISMATCH` | Receipt Beads ID, thread ID, or request reference do not match |
| `ERR_VB_INVALID_TIMEOUT_CLASS` | Timeout class is absent or outside the allowed enum |
| `ERR_VB_MISSING_ARTIFACT_PATH` | Required stdout, stderr, summary, or receipt path is missing |
| `ERR_VB_UNDECLARED_SOURCE_ONLY` | Source-only fallback was used without an allowed reason |

## Event Codes

| Code | Event |
|------|-------|
| `VB-001` | Request accepted |
| `VB-002` | Queue entry deduplicated |
| `VB-003` | Worker capability observed |
| `VB-004` | Validation command started |
| `VB-005` | Validation command completed |
| `VB-006` | Timeout or transport failure classified |
| `VB-007` | Source-only fallback recorded |
| `VB-008` | Receipt emitted |
| `VB-009` | Doctor readiness snapshot emitted |
| `VB-010` | CI gate consumed receipt |

## Consumer Requirements

### Beads Closeout

Beads closeout must require `receipt_id`, `bead_id`, `thread_id`,
`command_digest`, `timing.started_at`, `timing.finished_at`, `exit.kind`,
`artifacts.receipt_path`, `trust.git_commit`, and `trust.freshness`. If
`exit.kind` is not `success`, closeout must also include `exit.error_class`,
`exit.timeout_class`, and the accepted blocker or fallback reason.

### Doctor Readiness

Doctor readiness reports must derive:

- Queue depth and oldest queued request age.
- Active and expired leases.
- Worker reachability counts and last observed RCH mode.
- Counts by timeout class and error class.
- Whether source-only fallbacks are fresh enough to unblock documentation-only
  or source-inspection beads.

### CI Gate Consumption

CI gates must fail closed unless the receipt schema version is supported, the
command digest verifies, the bead ID matches the changed Beads entry, the
receipt is fresh, artifact paths are present, and `exit.kind` is `success` or an
explicitly accepted source-only/blocker class for that gate.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/validation_broker.md` |
| Schema catalog | `artifacts/validation_broker/validation_broker_contract.schema.json` |
| Golden fixtures | `artifacts/validation_broker/validation_broker_fixtures.v1.json` |
| Gate script | `scripts/check_validation_broker_contract.py` |
| Gate tests | `tests/test_check_validation_broker_contract.py` |
