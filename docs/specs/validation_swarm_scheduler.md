# Validation Swarm Scheduler Contract

**Bead:** `bd-4iy4h`
**Schema catalog:** `franken-node/validation-swarm-scheduler/schema-catalog/v1`
**Status:** Draft contract for follow-on scheduler implementation beads

## Purpose

The validation swarm scheduler is the decision layer above validation proof
coalescing, flight recorder artifacts, proof debt, and RCH capacity snapshots.
It decides whether an agent should run a validation proof, join an existing
proof, wait for capacity, steal stale producer work behind a fresh fence, defer
low-priority work, record a source-only blocker, or fail closed.

This contract is intentionally cargo-free. The schema catalog, fixtures, and
`scripts/check_validation_swarm_scheduler_contract.py` must be enough to verify
the scheduler plan on a busy machine without launching RCH or compiling Rust.

## ValidationSwarmSchedulerInput

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-swarm-scheduler/input/v1` |
| `input_id` | String | Yes | Stable input identifier |
| `bead_id` | String | Yes | Bead requesting validation proof work |
| `agent_name` | String | Yes | Agent receiving the scheduler decision |
| `proof_work_key` | DigestRef | Yes | Coalescer-compatible proof work key |
| `command_digest` | DigestRef | Yes | Digest of the validation command |
| `dirty_state_policy` | Enum | Yes | `clean_required`, `dirty_allowed_with_digest`, or `source_only_documented` |
| `target_dir_class` | Enum | Yes | Target-dir class from recorder/admission evidence |
| `capacity_snapshot` | Object | Yes | RCH worker/queue/capacity summary |
| `coalescer_state` | Enum | Yes | Existing coalescer state for this proof key |
| `flight_recorder_state` | Enum | Yes | Last recorded attempt state |
| `proof_debt_class` | Enum | Yes | Proof debt grouping for operator ledgers |
| `queue_age_ms` | Integer | Yes | How long this work has waited |
| `priority` | Enum | Yes | `P0`, `P1`, `P2`, `P3`, or `P4` |
| `timeout_budget_ms` | Integer | Yes | Remaining validation timeout budget |
| `source_only_allowed` | Boolean | Yes | Whether source-only blocker evidence may be recorded |
| `product_failure` | Boolean | Yes | Whether evidence says the product command failed |
| `worker_infra_retryable` | Boolean | Yes | Whether the blocker is retryable worker infrastructure |
| `artifact_valid` | Boolean | Yes | Whether referenced recorder/coalescer artifacts validated |

## ValidationSwarmSchedulerPolicy

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-swarm-scheduler/policy/v1` |
| `policy_id` | String | Yes | Stable policy identifier |
| `max_running_proofs` | Integer | Yes | Maximum concurrent producer validations |
| `max_waiters_per_work_key` | Integer | Yes | Maximum waiters allowed per proof key |
| `queue_high_watermark` | Integer | Yes | Queue depth where lower-priority work is deferred or rejected |
| `starvation_after_ms` | Integer | Yes | Queue age where starvation risk escalates |
| `aging_step_ms` | Integer | Yes | Queue age step for priority aging |
| `min_available_worker_slots` | Integer | Yes | Minimum slots needed before admitting a new producer |
| `allow_work_stealing` | Boolean | Yes | Whether stale producer theft is enabled |
| `fairness_buckets` | Array | Yes | Ordered fairness buckets used by decisions |

Fairness buckets are stable strings: `emergency`, `high`, `normal`, `low`,
`aging`, and `blocked`. Implementations may add rendering details later, but
they must preserve these bucket names for fixtures and operator output.

## ValidationSwarmSchedulerDecision

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-swarm-scheduler/decision/v1` |
| `decision_id` | String | Yes | Stable decision identifier |
| `input_ref` | String | Yes | `ValidationSwarmSchedulerInput.input_id` considered |
| `bead_id` | String | Yes | Bead receiving the decision |
| `agent_name` | String | Yes | Agent receiving the decision |
| `trace_id` | String | Yes | Stable trace ID for logs and Agent Mail closeout |
| `decided_at` | RFC3339 | Yes | UTC decision timestamp |
| `freshness_expires_at` | RFC3339 | Yes | UTC decision freshness deadline |
| `decision` | Enum | Yes | Scheduler decision kind |
| `reason_code` | Enum | Yes | Stable reason code |
| `event_code` | Enum | Yes | Stable event code |
| `required_action` | Enum | Yes | Next action the agent must take |
| `fairness_bucket` | Enum | Yes | Fairness bucket used for the decision |
| `starvation_risk` | Enum | Yes | `none`, `watch`, `elevated`, or `breached` |
| `retryable` | Boolean | Yes | Whether retry/wait is valid |
| `fail_closed` | Boolean | Yes | Whether this is a fail-closed blocker |
| `green_proof_eligible` | Boolean | Yes | Whether this can count as green validation proof |
| `operator_message` | String | Yes | Bounded human-readable explanation |
| `diagnostics` | Object | Yes | Machine-readable decision diagnostics |

Decision kinds:

- `run_now`
- `join_existing`
- `wait_for_capacity`
- `steal_stale_work`
- `reject_low_priority`
- `record_source_only_blocker`
- `fail_closed_product`
- `fail_closed_invalid_artifact`

Reason code, event code, and required action pairs are fixed:

| Decision | Reason | Event | Required action |
|----------|--------|-------|-----------------|
| `run_now` | `VSS_RUN_READY` | `VSS-001` | `start_rch_validation` |
| `join_existing` | `VSS_JOIN_IDENTICAL` | `VSS-002` | `join_existing_proof` |
| `wait_for_capacity` | `VSS_WAIT_CAPACITY` | `VSS-003` | `wait_for_capacity` |
| `steal_stale_work` | `VSS_STEAL_STALE` | `VSS-004` | `steal_with_new_fence` |
| `reject_low_priority` | `VSS_REJECT_LOW_PRIORITY` | `VSS-005` | `defer_low_priority` |
| `record_source_only_blocker` | `VSS_SOURCE_ONLY_BLOCKER` | `VSS-006` | `record_source_only_blocker` |
| `fail_closed_product` | `VSS_FAIL_PRODUCT` | `VSS-007` | `surface_product_failure` |
| `fail_closed_invalid_artifact` | `VSS_FAIL_INVALID_ARTIFACT` | `VSS-008` | `reject_artifact` |

## Structured Fields

Every scheduler input, decision, and log record must carry enough structure for
another agent to diagnose the outcome without reading terminal scrollback:

- `trace_id`
- `bead_id`
- `agent_name`
- `proof_work_key`
- `command_digest`
- `queue_age_ms`
- `priority`
- `fairness_bucket`
- `starvation_risk`
- `coalescer_state`
- `flight_recorder_state`
- `proof_debt_class`
- `capacity_snapshot`
- `target_dir_class`
- `decision`
- `reason_code`
- `event_code`
- `required_action`
- `fencing_token_digest`
- `recorder_path`

## Invariants

- **INV-VSS-WORK-KEY-COMPATIBLE** - Scheduler inputs consume the proof
  coalescer/cache work key and do not introduce another proof identity format.
- **INV-VSS-DETERMINISTIC-DECISION** - Identical input and policy produce the
  same decision, reason code, event code, required action, fairness bucket, and
  starvation risk.
- **INV-VSS-BOUNDED-QUEUE** - Queue and waiter growth are bounded before any
  new RCH producer is admitted.
- **INV-VSS-AGING-NO-STARVATION** - Low-priority work ages into explicit
  starvation-risk buckets instead of disappearing behind P0/P1 work forever.
- **INV-VSS-EXACT-JOIN** - Agents join only byte-identical proof work keys.
- **INV-VSS-FENCED-STEAL** - Stale producer work can be stolen only with a new
  fence token; late stale output cannot satisfy the new fence.
- **INV-VSS-SOURCE-ONLY-EXPLICIT** - Source-only fallback is recorded as a
  bounded blocker and never counted as green proof.
- **INV-VSS-PRODUCT-FAIL-CLOSED** - Product compile/test failures are surfaced
  as product failures and are never retried as worker infrastructure.
- **INV-VSS-WORKER-INFRA-NOT-GREEN** - Retryable worker infrastructure failures
  cannot be marked `green_proof_eligible`.
- **INV-VSS-INVALID-ARTIFACT-FAIL-CLOSED** - Malformed recorder, coalescer, or
  debt artifacts produce `fail_closed_invalid_artifact`.
- **INV-VSS-AUDITABLE-OUTPUT** - Every decision carries trace, bead, agent,
  proof key, reason, event, action, and operator message fields.

## Error Codes

| Code | Meaning |
|------|---------|
| `ERR_VSS_INVALID_SCHEMA_VERSION` | Unknown scheduler schema version |
| `ERR_VSS_MALFORMED_INPUT` | Input missing required fields or malformed scalar values |
| `ERR_VSS_BAD_WORK_KEY` | Proof work key digest is missing or inconsistent |
| `ERR_VSS_COMMAND_DIGEST_MISMATCH` | Command digest is missing or inconsistent |
| `ERR_VSS_MALFORMED_POLICY` | Policy missing bounds or fairness buckets |
| `ERR_VSS_MALFORMED_DECISION` | Decision, reason, event, or action does not match the contract |
| `ERR_VSS_STALE_DECISION` | Decision freshness is expired |
| `ERR_VSS_WORKER_INFRA_GREEN` | Retryable worker infrastructure was marked as green proof |
| `ERR_VSS_PRODUCT_RETRIED_AS_INFRA` | Product failure was routed as retryable worker infrastructure |
| `ERR_VSS_INVALID_ARTIFACT_ACCEPTED` | Invalid artifact was accepted instead of rejected |

## Required Fixture Matrix

The checked fixture catalog must include at least these scenarios:

- `healthy_fleet_run`
- `saturated_fleet_wait`
- `degraded_worker_join`
- `stale_queue_aging`
- `stale_producer_steal`
- `proof_cache_hit_join`
- `source_only_blocker`
- `product_failure`
- `invalid_artifact`

The fixture matrix must include both valid decisions and invalid mutations for
bad work-key digest, reason/action mismatch, stale freshness, worker-infra green
proof, product failure retried as infra, and invalid artifact accepted.

## Doctor and Closeout

Follow-on implementation beads should make doctor/readiness/closeout able to
answer these questions from machine-readable fields:

1. Which bead and agent own the proof work?
2. Is this proof ready to run, waiting, joined, stolen, deferred, or failed
   closed?
3. Is the blocker product failure, worker infrastructure, source-only, capacity,
   stale producer, or invalid artifact?
4. What exact next action should the agent take?
5. Which recorder/coalescer/debt artifact path explains the decision?
