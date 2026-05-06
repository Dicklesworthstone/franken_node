# Validation Flight Recorder Contract

**Bead:** bd-x78mf
**Attempt schema:** `franken-node/validation-flight-recorder/attempt/v1`
**Observation schema:** `franken-node/validation-flight-recorder/observation/v1`
**Recovery schema:** `franken-node/validation-flight-recorder/recovery/v1`

## Purpose

The validation flight recorder is the post-admission evidence contract for RCH
validation attempts. It records what actually happened after a validation broker
request or proof coalescer lease was admitted: which command ran, which worker
or fallback path was observed, which outputs were produced, why the attempt
ended, and what deterministic recovery action should happen next.

This contract does not replace the validation broker, RCH adapter, proof cache,
or proof coalescer. It links them:

- `validation_broker` owns requests, queue state, receipts, proof status, and
  closeout/readiness consumers.
- `rch_adapter` classifies command output and worker failures.
- `validation_proof_coalescer` decides whether equivalent proof work should
  start, join, wait, reuse, or fence stale leases before execution.
- `validation_flight_recorder` captures the attempt timeline and recovery plan
  once execution has been admitted or observed.

The recorder exists so Beads closeout, doctor readiness, CI gates, and Agent
Mail handoff text can point at stable artifacts instead of terminal scrollback
or chat history.

## Artifact Family

Flight recorder artifacts live under:

```text
artifacts/validation_broker/<bead-id>/flight-recorder/
```

Recommended files:

| Artifact | Purpose |
|----------|---------|
| `attempt.<attempt-id>.json` | One validation attempt capsule and timeline |
| `recovery.<attempt-id>.json` | Deterministic next-action decision |
| `stdout.<attempt-id>.txt` | Optional bounded stdout excerpt |
| `stderr.<attempt-id>.txt` | Optional bounded stderr excerpt |
| `summary.<attempt-id>.md` | Human-readable triage summary |

All paths embedded in recorder JSON must be repo-relative, non-empty, and free
of NUL bytes. Absolute paths and `..` path traversal segments are invalid.

## Attempt Capsule

`ValidationFlightRecorderAttempt` is the top-level attempt artifact.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | String | Yes | `franken-node/validation-flight-recorder/attempt/v1` |
| `attempt_id` | String | Yes | Stable ID, preferably `vfr-attempt-<hash-or-uuid>` |
| `trace_id` | String | Yes | Operator trace correlation ID |
| `bead_id` | String | Yes | Owning Beads issue ID |
| `thread_id` | String | Yes | Agent Mail thread, normally equal to bead ID |
| `request_id` | String or null | Yes | Validation broker request ID when available |
| `queue_id` | String or null | Yes | Validation broker queue entry ID when available |
| `coalescer_lease_id` | String or null | Yes | Proof coalescer lease ID when available |
| `proof_cache_key_hex` | String or null | Yes | SHA-256 proof work/cache key when available |
| `created_at` | RFC3339 String | Yes | Attempt artifact creation time |
| `started_at` | RFC3339 String or null | Yes | RCH/cargo execution start time when known |
| `finished_at` | RFC3339 String or null | Yes | Terminal attempt time when known |
| `freshness_expires_at` | RFC3339 String | Yes | Last time this attempt can inform closeout/readiness |
| `command` | Object | Yes | Canonical command material and digest |
| `environment` | Object | Yes | Allowed/redacted env policy and remote requirement |
| `target_dir` | Object | Yes | Target-dir policy and hygiene classification |
| `input_digests` | Array | Yes | Non-empty source/spec/artifact input digests |
| `observations` | Array | Yes | Bounded ordered observation timeline |
| `adapter_outcome` | Object or null | Yes | RCH adapter outcome if classification has run |
| `exit` | Object | Yes | Terminal kind, error class, timeout class, retryability |
| `artifacts` | Object | Yes | stdout/stderr/summary/receipt/recorder paths and digests |
| `recovery_ref` | Object or null | Yes | Link to recovery decision artifact when emitted |
| `trust` | Object | Yes | Git commit, dirty-state policy, freshness, generator |

### Command Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `program` | String | Yes | Usually `rch` or `cargo` for source-only evidence |
| `argv` | Array[String] | Yes | Exact argv, including `exec --` and cargo args |
| `cwd` | String | Yes | Repo-relative or canonical workspace path |
| `command_digest` | Object | Yes | SHA-256 digest over canonical command material |
| `environment_policy_id` | String | Yes | Policy used to allow/redact env vars |
| `target_dir_policy_id` | String | Yes | Policy used to classify target-dir behavior |

`command_digest.canonical_material` must verify against `program`, `argv`,
`cwd`, `environment_policy_id`, and `target_dir_policy_id`.

### Target-Dir Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `class` | Enum | Yes | `off_repo`, `repo_local_guarded`, `repo_local_writable`, `unwritable`, `missing`, `unknown` |
| `path` | String or null | Yes | Target directory path when known |
| `path_digest` | Object or null | Yes | SHA-256 digest of normalized path when known |
| `repo_local` | Boolean | Yes | Whether the target dir is inside repo root |
| `guarded_placeholder` | Boolean | Yes | Whether an immutable/protected placeholder was observed |
| `writable_parent` | Boolean or null | Yes | Parent writability when checked |
| `sync_root_digest` | Object or null | Yes | Optional digest of the RCH sync root summary |
| `diagnostic` | String | Yes | Human-readable bounded target-dir note |

The recorder must distinguish an intentional guarded repo-local `target/`
placeholder from stale build output. It must not delete or clean target
directories.

## Observation Timeline

Each observation uses
`franken-node/validation-flight-recorder/observation/v1`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | String | Yes | Observation schema version |
| `observation_id` | String | Yes | Stable observation ID |
| `observed_at` | RFC3339 String | Yes | UTC observation timestamp |
| `phase` | Enum | Yes | Attempt phase |
| `event_code` | String | Yes | Stable event code |
| `worker_id` | String or null | Yes | RCH worker, host alias, `local`, or null |
| `rch_mode` | Enum | Yes | `remote`, `local_fallback`, `not_used`, `unavailable`, `unknown` |
| `queue_state` | Enum or null | Yes | Broker queue state when known |
| `message` | String | Yes | Bounded operator diagnostic |
| `details` | Object | Yes | Bounded structured details |

### Observation Phases

| Phase | Meaning |
|-------|---------|
| `request_enqueued` | Broker request accepted or deduplicated |
| `lease_acquired` | Proof coalescer or broker lease acquired |
| `capacity_observed` | RCH capacity/worker state sampled |
| `dispatch_started` | RCH command dispatched |
| `worker_selected` | A remote worker was selected or inferred |
| `progress_observed` | Output, heartbeat, or progress marker observed |
| `progress_stale` | No progress for the idle budget |
| `attempt_cancelled` | Attempt cancelled by operator or policy |
| `adapter_classified` | RCH adapter outcome produced |
| `receipt_emitted` | Validation broker receipt written |
| `recovery_planned` | Recovery decision emitted |

Observation arrays must be sorted by `observed_at`, then `observation_id`.
Implementations must cap observations at a documented maximum. Recommended cap:
256 observations per attempt.

## Adapter Outcome Mapping

The flight recorder consumes the RCH adapter outcome without changing its green
proof rule.

| RCH adapter outcome | Recorder exit kind | Timeout class | Product failure | Retryable |
|---------------------|-------------------|---------------|-----------------|-----------|
| `passed` | `success` | `none` | false | false |
| `command_failed` | `failure` | adapter value | true | false |
| `compile_failed` | `failure` | `none` | true | false |
| `test_failed` | `failure` | `none` | true | false |
| `worker_timeout` | `timeout` | adapter value, e.g. `ssh_command` | false | true |
| `worker_missing_toolchain` | `worker_infra` | `worker_unreachable` or `unknown` | false | true |
| `worker_filesystem_error` | `worker_infra` | `none` | false | true |
| `local_fallback_refused` | `worker_infra` | `none` | false | true |
| `contention_deferred` | `deferred` | `queue_wait` or `none` | false | true |
| `broker_internal_error` | `failure` | `unknown` | false | false |

`[RCH-E104] SSH command timed out (no local fallback)` must map to
`worker_timeout` and `ssh_command`. It is retryable worker infrastructure, not a
product failure and not green proof.

## Recovery Decision

`ValidationFlightRecorderRecovery` records the deterministic next action for one
attempt.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | String | Yes | `franken-node/validation-flight-recorder/recovery/v1` |
| `decision_id` | String | Yes | Stable recovery decision ID |
| `attempt_id` | String | Yes | Attempt being evaluated |
| `bead_id` | String | Yes | Owning bead |
| `thread_id` | String | Yes | Owning mail thread |
| `decided_at` | RFC3339 String | Yes | UTC decision time |
| `input_digest` | Object | Yes | SHA-256 digest over attempt + policy inputs |
| `decision` | Enum | Yes | Recovery decision |
| `reason_code` | String | Yes | Stable reason code |
| `event_code` | String | Yes | Stable event code |
| `required_action` | Enum | Yes | Operator/agent action |
| `fail_closed` | Boolean | Yes | Whether closeout must fail closed |
| `retryable` | Boolean | Yes | Whether a future attempt may retry |
| `freshness_expires_at` | RFC3339 String | Yes | Decision freshness bound |
| `operator_message` | String | Yes | Bounded human message |
| `diagnostics` | Object | Yes | Bounded structured diagnostic context |

### Recovery Decisions

| Decision | Required action | Meaning |
|----------|-----------------|---------|
| `accept_success` | `use_receipt` | Fresh remote success is usable proof |
| `retry_remote_same_worker` | `retry_rch` | Same worker retry is allowed |
| `retry_remote_different_worker` | `retry_rch_different_worker` | Worker-specific infra failure should move |
| `queue_until_capacity` | `wait_for_capacity` | Capacity or contention is the blocker |
| `drain_worker_then_retry` | `drain_worker` | Worker should be drained before retry |
| `wait_for_existing_proof` | `wait_for_proof` | Equivalent proof is already running |
| `retry_with_new_fence` | `fence_stale_lease` | Stale coalescer lease needs fencing first |
| `reuse_receipt` | `reuse_receipt` | Proof cache or completed lease can be reused |
| `use_source_only_blocker` | `record_source_only` | Cargo/RCH proof is unavailable but source-only evidence is allowed |
| `fail_closed_product` | `fix_product_failure` | Compile/test/format/clippy failure is product work |
| `fail_closed_invalid` | `repair_artifact_or_contract` | Recorder/receipt/lease state is malformed |

Recovery decisions must be deterministic for identical inputs. Retry loops must
be bounded by attempt count, worker diversity, timeout budget, queue depth, and
oldest queued age.

## Reason Codes and Event Codes

Reason codes are stable strings intended for Beads closeout, doctor, CI, and
Agent Mail.

| Reason code | Typical event | Meaning |
|-------------|---------------|---------|
| `VFR_SUCCESS_REMOTE` | `VFR-001` | Remote proof succeeded |
| `VFR_RETRY_SSH_TIMEOUT` | `VFR-002` | RCH SSH timeout, retryable |
| `VFR_RETRY_MISSING_TOOLCHAIN` | `VFR-003` | Worker lacks requested toolchain |
| `VFR_RETRY_WORKER_FS` | `VFR-004` | Worker filesystem/tempdir blocked proof |
| `VFR_QUEUE_CONTENTION` | `VFR-005` | Local or remote contention requires wait |
| `VFR_REJECT_LOCAL_FALLBACK` | `VFR-006` | Remote proof required but local fallback occurred |
| `VFR_SOURCE_ONLY_ALLOWED` | `VFR-007` | Explicit source-only fallback may be recorded |
| `VFR_PRODUCT_FAILURE` | `VFR-008` | Product compile/test/format/clippy failure |
| `VFR_STALE_PROGRESS` | `VFR-009` | Attempt made no progress for idle budget |
| `VFR_STALE_LEASE_FENCE` | `VFR-010` | Proof coalescer lease must be fenced |
| `VFR_REUSE_RECEIPT` | `VFR-011` | Existing receipt can be reused |
| `VFR_INVALID_ARTIFACT` | `VFR-012` | Recorder or linked artifact is malformed |

## Validation Rules

Implementations and checkers must fail closed when:

- schema version is unknown;
- bead ID, thread ID, request ID, queue ID, or receipt reference mismatches;
- command digest is missing, malformed, or does not verify;
- input digest list is empty for proof-bearing attempts;
- timestamps are out of order or freshness has expired;
- observation array is unsorted or exceeds the cap;
- timeout/error class is outside the supported enum;
- output snippets exceed the bounded snippet size;
- artifact paths are empty, absolute, contain NUL, or traverse outside the repo;
- environment includes unredacted values outside the allowlist;
- retryable worker infrastructure is marked as green proof;
- product compile/test failure is marked as retryable worker infrastructure;
- source-only fallback lacks an allowed reason.

## Required Fixture Matrix

The initial fixture suite must cover:

| Case | Expected recovery |
|------|-------------------|
| Remote success with `[RCH] remote <worker>` marker | `accept_success` |
| `[RCH-E104] SSH command timed out (no local fallback)` | `retry_remote_different_worker` or `queue_until_capacity` |
| Worker missing requested Rust toolchain | `retry_remote_different_worker` |
| Worker filesystem pressure, including `No space left on device` | `drain_worker_then_retry` or `retry_remote_different_worker` |
| Remote proof required but local fallback occurred | `retry_remote_different_worker` or `fail_closed_invalid` |
| Active cargo/rustc contention exceeded policy | `queue_until_capacity` |
| Progress stale before wall timeout | `retry_remote_different_worker` or `drain_worker_then_retry` |
| Product compile error | `fail_closed_product` |
| Product test failure | `fail_closed_product` |
| Source-only allowed because cargo/RCH is unavailable | `use_source_only_blocker` |
| Proof cache hit or completed coalescer lease | `reuse_receipt` |

## Consumer Requirements

### Validation Broker

Validation broker receipts and proof statuses may link to recorder artifacts.
When they do, the link must include recorder path, attempt ID, schema version,
and digest. Timeout/source-only/blocked receipts should include recorder context
when available so closeout does not depend on terminal history.

### RCH Adapter

RCH adapter outcomes are the authoritative classification source for command
output. The flight recorder stores that classification and adds timeline,
target-dir, broker/coalescer, and recovery context. It must not loosen the
adapter command policy or green proof rule.

### Doctor and Closeout

Doctor readiness and closeout surfaces should show:

- latest recorder artifact path;
- worker ID and RCH mode;
- timeout class and error class;
- retryability and product-failure status;
- recovery decision and required action;
- freshness and fail-closed state.

Human output should be concise. JSON output should preserve stable field names
for automation.
