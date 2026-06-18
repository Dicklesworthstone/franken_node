# Swarm Validation Admission Contract

**Bead:** `bd-0x4fy.1`
**Schema catalog:** `franken-node/swarm-validation-admission/schema-catalog/v1`
**Status:** Draft contract for follow-on implementation beads

## Purpose

Swarm validation admission is the operator-facing decision layer that tells an
agent whether to launch validation work, join existing proof work, wait, hand
work off, or stop with a bounded blocker.

This layer sits above the lower-level validation contracts:

- `docs/specs/resource_governor.md` for local workspace pressure.
- `docs/specs/validation_proof_coalescer.md` for identical proof work and
  producer/waiter leases.
- `docs/specs/validation_swarm_scheduler.md` for fairness, stale producer
  recovery, source-only blockers, and proof-debt decisions.
- `docs/specs/validation_broker.md` for validation requests, receipts, and
  closeout evidence.
- `docs/specs/validation_flight_recorder.md` for per-attempt RCH evidence.
- `docs/specs/rch_adapter.md` for RCH outcome classification.
- `docs/specs/proof_lane_readiness.md` for preflight proof-lane blockers.

The admission decision is intentionally higher level than those contracts. It
normalizes their outputs into five stable states that an agent can act on
without reading terminal scrollback or inventing local rules.

## Non-Goals

- This contract does not run Cargo, RCH, Python gates, or Beads commands.
- This contract does not replace the validation proof coalescer, scheduler,
  broker, RCH adapter, proof cache, workspace pressure policy, or handoff
  readiness surfaces.
- This contract does not make source-only evidence count as green proof.
- This contract does not authorize destructive cleanup, force-release of active
  reservations, or takeover of a live agent's work.

## Existing Implementation Seams

Follow-on implementation beads should compose existing `ops` modules rather than
creating a parallel orchestration subsystem:

| Surface | Role in admission |
|---------|-------------------|
| `ops::workspace_pressure_policy` | Local process, target-dir, disk, and workspace pressure input |
| `ops::validation_planner` | Changed-path validation plan, RCH shard plan, source-only checks, and proof-cache/coalescer lookups |
| `ops::validation_proof_coalescer` | Identical proof work, producer/waiter lease state, capacity policy, and proof-cache handoff |
| `ops::rch_adapter` | RCH result classification, local fallback refusal, worker infrastructure, and product failure separation |
| `ops::validation_readiness` | Operator readiness and validation handoff summaries |
| `ops::swarm_handoff` | Stale, abandoned, contested, and dependency-blocked work handoff evidence |
| `ops::swarm_bead_templates` | Recurring blocker observations and deterministic follow-up bead suggestions |

## SwarmValidationAdmissionInput

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/swarm-validation-admission/input/v1` |
| `input_id` | String | Yes | Stable input identifier, preferably `sva-input-<sha256-prefix>` |
| `trace_id` | String | Yes | Trace ID shared by logs, Agent Mail, and closeout evidence |
| `bead_id` | String | Yes | Beads issue requesting or considering validation work |
| `thread_id` | String | Yes | Agent Mail thread, normally equal to `bead_id` |
| `agent_name` | String | Yes | Agent receiving the admission decision |
| `requested_action` | Enum | Yes | `source_check`, `cargo_check`, `cargo_test`, `cargo_clippy`, `cargo_fmt`, `python_gate`, `evidence_gate`, or `closeout` |
| `priority` | Enum | Yes | `P0`, `P1`, `P2`, `P3`, or `P4` |
| `changed_paths` | Array | Yes | Repo-relative paths considered by the validation planner |
| `acceptance_ref` | Object | Yes | Bead acceptance text digest or source-only contract reference |
| `proof_work_key` | DigestRef or null | Yes | Coalescer-compatible proof key when expensive proof work is in scope |
| `command_digest` | DigestRef or null | Yes | Canonical command digest when a command is planned |
| `workspace_pressure` | Object | Yes | Resource-governor or workspace-pressure summary |
| `validation_plan` | Object | Yes | Planner summary with source-only, cargo/RCH, and gate decisions |
| `coalescer_snapshot` | Object or null | Yes | Existing coalescer lease/decision for the proof key |
| `proof_cache_snapshot` | Object or null | Yes | Fresh proof-cache hit/miss evidence when available |
| `rch_snapshot` | Object or null | Yes | Queue, worker, and remote-requirement state when command work is planned |
| `proof_lane_readiness` | Object or null | Yes | Proof-lane readiness capsule when a lane was preflighted |
| `handoff_snapshot` | Object or null | Yes | Swarm handoff evidence for current owner, reservations, blockers, and stale work |
| `flight_recorder_ref` | Object or null | Yes | Most recent attempt evidence when retry or handoff is being considered |
| `dirty_state_policy` | Enum | Yes | `clean_required`, `dirty_allowed_with_digest`, or `source_only_documented` |
| `source_only_allowed` | Boolean | Yes | Whether source-only blocker closeout may be recorded |
| `freshness_expires_at` | RFC3339 String | Yes | Last instant this input can be used for a decision |

Input objects must be bounded and deterministic. Missing optional references
use explicit `null`, never absent fields. If an expected upstream artifact is
malformed, stale, or missing where the requested action requires it, admission
must fail closed with `decision = "blocked"`.

## SwarmValidationAdmissionPolicy

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/swarm-validation-admission/policy/v1` |
| `policy_id` | String | Yes | Stable policy identifier |
| `max_running_proofs` | Integer | Yes | Upper bound for concurrent producer validation proofs |
| `max_waiters_per_work_key` | Integer | Yes | Upper bound for agents joining the same proof key |
| `max_defer_ms` | Integer | Yes | Largest bounded wait before a fresh decision is required |
| `stale_handoff_after_ms` | Integer | Yes | Owner inactivity window before handoff can be recommended |
| `freshness_grace_ms` | Integer | Yes | Accepted clock-skew window for freshness checks |
| `require_rch_for_cargo` | Boolean | Yes | Cargo work must use `rch exec -- ...` when true |
| `allow_source_only_docs_closeout` | Boolean | Yes | Docs/spec-only beads may close with source-only validation |
| `dirty_state_policy` | Enum | Yes | Highest dirty-state mode allowed by policy |
| `fail_closed_on_telemetry_gap` | Boolean | Yes | Missing pressure/RCH/coalescer/handoff telemetry blocks launch when true |

The default policy for this repository is expected to require RCH for cargo and
to fail closed on telemetry gaps for cargo/RCH proof work. Source-only docs and
spec beads may use source-only closeout only when no Rust-consumed schema,
fixture, generated artifact, or command behavior changed.

## SwarmValidationAdmissionDecision

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/swarm-validation-admission/decision/v1` |
| `decision_id` | String | Yes | Stable decision identifier, preferably `sva-decision-<sha256-prefix>` |
| `input_ref` | String | Yes | `SwarmValidationAdmissionInput.input_id` |
| `policy_id` | String | Yes | Policy used for the decision |
| `trace_id` | String | Yes | Trace ID shared by logs, Agent Mail, and closeout evidence |
| `bead_id` | String | Yes | Beads issue receiving the decision |
| `thread_id` | String | Yes | Agent Mail thread receiving the decision |
| `agent_name` | String | Yes | Agent receiving the decision |
| `decided_at` | RFC3339 String | Yes | UTC timestamp for the decision |
| `freshness_expires_at` | RFC3339 String | Yes | Last instant this decision can be acted on |
| `decision` | Enum | Yes | One of `run`, `coalesce`, `defer`, `handoff`, or `blocked` |
| `reason_code` | Enum | Yes | Stable machine reason |
| `event_code` | Enum | Yes | Stable event code |
| `required_action` | Enum | Yes | Next action the agent should take |
| `green_proof_eligible` | Boolean | Yes | Whether the action can produce or reuse green proof |
| `retryable` | Boolean | Yes | Whether a later refreshed decision may proceed |
| `fail_closed` | Boolean | Yes | Whether this decision blocks proof/closeout until repaired |
| `source_only_closeout_allowed` | Boolean | Yes | Whether source-only closeout is acceptable for this bead |
| `operator_summary` | String | Yes | Bounded human-readable summary |
| `evidence_refs` | Array | Yes | Repo-relative or stable external references used by the decision |
| `diagnostics` | Object | Yes | Machine-readable upstream state used for audit |

Decision states:

| Decision | Meaning |
|----------|---------|
| `run` | Start the planned validation action now. Cargo/RCH work must be launched through `rch exec -- ...` when policy requires remote execution. |
| `coalesce` | Join or wait on an existing byte-identical proof, or reuse a fresh proof-cache receipt. |
| `defer` | Wait for capacity, freshness, queue, target-dir, or pressure conditions to improve, then refresh admission. |
| `handoff` | Ask for or record ownership transfer because current work is stale, abandoned, explicitly delegated, or ready for claim after evidence refresh. |
| `blocked` | Do not launch or close out. A malformed input, product failure, unsafe fallback, hard reservation conflict, stale artifact, or policy violation must be repaired or recorded as a blocker. |

## Reason, Event, and Action Matrix

| Decision | Reason code | Event | Required action | Green proof eligible |
|----------|-------------|-------|-----------------|----------------------|
| `run` | `SVA_RUN_SOURCE_ONLY_READY` | `SVA-001` | `run_source_only_checks` | No |
| `run` | `SVA_RUN_RCH_READY` | `SVA-002` | `start_rch_validation` | Yes |
| `run` | `SVA_RUN_PYTHON_GATE_READY` | `SVA-003` | `run_python_gate` | No |
| `coalesce` | `SWARM-COALESCE-IN-FLIGHT` | `SVA-004` | `join_existing_proof` | Yes |
| `coalesce` | `SWARM-CACHE-HIT` | `SVA-005` | `reuse_fresh_receipt` | Yes |
| `defer` | `SVA_DEFER_WORKSPACE_PRESSURE` | `SVA-006` | `refresh_pressure_after_backoff` | No |
| `defer` | `SVA_DEFER_RCH_QUEUE` | `SVA-007` | `wait_for_rch_capacity` | No |
| `defer` | `SVA_DEFER_TARGET_DIR_SERIALIZED` | `SVA-008` | `wait_for_target_dir_lease` | No |
| `defer` | `SVA_DEFER_TARGET_DIR_DISK_PRESSURE` | `SVA-020` | `free_target_dir_space_or_reuse_existing_proof` | No |
| `handoff` | `SWARM-STALE-LEASE` | `SVA-009` | `request_agent_handoff` | No |
| `handoff` | `SVA_HANDOFF_READY_TO_REOPEN` | `SVA-010` | `claim_after_handoff_window` | No |
| `blocked` | `SVA_BLOCKED_MISSING_INPUT` | `SVA-011` | `repair_admission_input` | No |
| `blocked` | `SVA_BLOCKED_MALFORMED_INPUT` | `SVA-011` | `repair_admission_input` | No |
| `blocked` | `SVA_BLOCKED_PRODUCT_FAILURE` | `SVA-012` | `surface_product_failure` | No |
| `blocked` | `SVA_BLOCKED_LOCAL_FALLBACK` | `SVA-013` | `restore_remote_execution_or_record_blocker` | No |
| `blocked` | `SVA_BLOCKED_ACTIVE_RESERVATION` | `SVA-014` | `coordinate_with_reservation_holder` | No |
| `blocked` | `SVA_BLOCKED_STALE_OR_INVALID_ARTIFACT` | `SVA-015` | `regenerate_evidence` | No |
| `blocked` | `SVA_BLOCKED_TELEMETRY_GAP` | `SVA-016` | `refresh_required_telemetry` | No |
| `blocked` | `SWARM-INCOMPATIBLE-PROOF` | `SVA-017` | `start_distinct_proof_or_rebuild_key` | No |
| `blocked` | `SWARM-STALE-CACHE` | `SVA-018` | `refresh_validation_evidence` | No |
| `blocked` | `SWARM-CORRUPTED-PROOF-STATE` | `SVA-019` | `repair_proof_coalescer_state` | No |

The planner test suite asserts that every emitted version 1 reason code appears
in this matrix. Reserved rows may be used by higher-level admission wrappers,
but adding new pure-planner reason codes requires updating this table and the
focused invariant tests.

## Human Summary Rules

`operator_summary` is the bounded text agents copy into Agent Mail and Beads
comments. It must:

- name the `bead_id`, `decision`, `reason_code`, and `required_action`;
- name the proof source when proof is reused: `fresh_execution`,
  `coalescer_waiter`, or `proof_cache_hit`;
- preserve exact blocker strings for cargo/RCH failures when a blocker exists;
- include the first actionable evidence reference;
- fit within 512 bytes after UTF-8 validation;
- contain no NUL bytes;
- avoid terminal scrollback dumps.

For `run` decisions that launch cargo work, the summary must include the exact
`rch exec -- ...` command or a command digest plus an artifact path that contains
the full command. For docs/spec-only `run` decisions, the summary must state
that no cargo-heavy validation is required and name the source-only checks used.

## Fail-Closed Rules

Admission must return `blocked` when any of these conditions hold:

- Required schema version is unknown.
- Required input, policy, or decision field is missing or malformed.
- Decision freshness has expired.
- Cargo/RCH work is requested without a command digest.
- Cargo work would run locally while policy requires RCH.
- RCH reports local fallback, missing remote proof, worker timeout without
  retry budget, or an unclassified worker failure.
- Product compile, test, clippy, or format failure is present.
- Coalescer work keys differ by any byte.
- Proof-cache receipt is stale, missing, or not bound to the requested bead and
  command digest.
- Handoff evidence says another active agent or reservation still owns the
  surface.
- Workspace pressure telemetry is missing and policy requires fail-closed
  telemetry.
- Source-only closeout is requested for a Rust-consumed schema, fixture,
  generated artifact, or command-behavior change without matching proof.

## Determinism and Ordering

The decision function must be deterministic for identical input and policy. If
multiple decision states could apply, choose the first matching state in this
order:

1. `blocked`
2. `handoff`
3. `coalesce`
4. `defer`
5. `run`

This order prevents agents from launching new validation work when another
agent owns the surface, a proof can be reused, or telemetry is unsafe.

## Structured Log Fields

Every admission decision and log record must include:

- `trace_id`
- `bead_id`
- `thread_id`
- `agent_name`
- `decision`
- `reason_code`
- `event_code`
- `required_action`
- `proof_work_key`
- `command_digest`
- `proof_source`
- `coalescer_lease_id`
- `proof_cache_receipt_ref`
- `rch_worker_id`
- `target_dir_policy_id`
- `handoff_owner_agent`
- `reservation_refs`
- `freshness_expires_at`

Fields without a value use explicit `null` in JSON and are omitted from compact
human rendering only when the omission cannot hide the reason for the decision.

## Invariants

- **INV-SVA-DETERMINISTIC** - Identical input and policy produce the same
  decision, reason code, event code, required action, and proof eligibility.
- **INV-SVA-FIVE-STATES** - Version 1 emits only `run`, `coalesce`, `defer`,
  `handoff`, or `blocked`.
- **INV-SVA-RCH-ONLY-CARGO** - Cargo build, check, clippy, test, and fmt proof
  work is admitted only through `rch exec -- ...` when the policy requires RCH.
- **INV-SVA-NO-DUPLICATE-PROOFS** - A fresh identical proof in the coalescer or
  proof cache produces `coalesce`, not a new producer `run`.
- **INV-SVA-HANDOFF-BEFORE-CLAIM** - Stale or abandoned work produces `handoff`
  before any new claim or reservation takeover is recommended.
- **INV-SVA-SOURCE-ONLY-EXPLICIT** - Source-only validation is never green
  proof and must state why cargo/RCH proof was not required or not available.
- **INV-SVA-PRODUCT-FAIL-CLOSED** - Product failures cannot be retried as worker
  infrastructure or hidden behind source-only closeout.
- **INV-SVA-RESERVATION-AWARE** - Active reservations held by another agent
  block overlapping edits or validation ownership transfer.
- **INV-SVA-BOUNDED-HUMAN-TEXT** - Human summaries are bounded, sanitized, and
  carry enough evidence references to avoid chat-history archaeology.
- **INV-SVA-AUDITABLE-CLOSEOUT** - A Beads closeout can cite the decision only
  when the decision is fresh and its evidence references still validate.

## Error Codes

| Code | Meaning |
|------|---------|
| `ERR_SVA_INVALID_SCHEMA_VERSION` | Unknown input, policy, or decision schema |
| `ERR_SVA_MALFORMED_INPUT` | Input is missing required fields or has malformed scalar values |
| `ERR_SVA_MALFORMED_POLICY` | Policy is missing bounds or contains unsafe values |
| `ERR_SVA_MALFORMED_DECISION` | Decision does not match the reason/event/action matrix |
| `ERR_SVA_STALE_INPUT` | Input freshness expired before admission |
| `ERR_SVA_STALE_DECISION` | Decision freshness expired before action |
| `ERR_SVA_BAD_WORK_KEY` | Proof work key is missing, malformed, or mismatched |
| `ERR_SVA_BAD_COMMAND_DIGEST` | Command digest is missing, malformed, or mismatched |
| `ERR_SVA_UNSAFE_LOCAL_CARGO` | Cargo proof would run locally under an RCH-required policy |
| `ERR_SVA_ACTIVE_RESERVATION` | Another active reservation owns the surface |
| `ERR_SVA_TELEMETRY_GAP` | Required pressure, RCH, coalescer, or handoff telemetry is absent |

## Required Fixture Matrix

Follow-on implementation beads must provide deterministic source-only fixtures
for every decision state:

| Fixture | Expected decision | Required condition |
|---------|-------------------|--------------------|
| `docs_only_source_checks` | `run` | Docs/spec-only bead with source-only checks and no Rust-consumed artifact |
| `cargo_remote_ready` | `run` | RCH available, command digest valid, no coalescer hit, no pressure blocker |
| `proof_in_flight_join` | `coalesce` | Byte-identical coalescer lease is running and fresh |
| `proof_cache_receipt_reuse` | `coalesce` | Fresh proof-cache receipt matches bead, command, and proof key |
| `workspace_pressure_backoff` | `defer` | Pressure policy requires bounded backoff |
| `rch_queue_saturated` | `defer` | RCH queue is saturated and retry budget remains |
| `stale_owner_handoff` | `handoff` | Handoff evidence says owner is abandoned or ready to reopen |
| `active_reservation_block` | `blocked` | Another active reservation owns the path |
| `local_fallback_refused` | `blocked` | Cargo proof attempted or planned local fallback under RCH-required policy |
| `product_failure_visible` | `blocked` | RCH adapter or broker reports compile/test/clippy/format product failure |
| `telemetry_gap_fail_closed` | `blocked` | Required telemetry is absent under fail-closed policy |
| `invalid_artifact_rejected` | `blocked` | Coalescer, broker, proof-cache, or handoff artifact is malformed or stale |

The fixture set must include invalid mutations for reason/action mismatch,
expired freshness, coalescer work-key mismatch, source-only green proof,
missing command digest for cargo work, and local cargo execution without
`rch exec -- ...`.

## Mock-Free Transcript Harness

The focused Rust test
`mock_free_e2e_swarm_validation_transcript_emits_stable_jsonl` exercises the
version 1 multi-agent transcript shape without shell-script success mocks. It
builds deterministic admission inputs from the live planner fixture catalog and
emits one JSONL row per agent intent:

- producer starts an RCH validation lane;
- waiter joins the same proof key through coalescing;
- conflicting reservation blocks with holder evidence;
- stale proof lease requests handoff with build-slot evidence;
- saturated RCH queue defers without a local cargo fallback.

Each row carries `command`, `bead_id`, `thread_id`, `trace_id`, `agent_name`,
`decision`, `reason_code`, `event_code`, `required_action`, `proof_key`,
reservation/build-slot evidence, an RCH status class, and a closeout
recommendation. Commands are explicit `null` when no command is safe to run,
and cargo rows must start with `rch exec --`.

## Evidence-Pack Checker

`scripts/check_swarm_validation_evidence_pack.py` is the source-only checker for
the transcript closeout contract:

```bash
python3 scripts/check_swarm_validation_evidence_pack.py \
  --transcript artifacts/validation_broker/swarm_validation_admission/swarm_validation_transcript.v1.jsonl \
  --expected-bead-id bd-0x4fy.9 \
  --json
```

The checker does not run Cargo and does not require RCH for its own execution.
Any Rust-side companion test, benchmark, or proof that a transcript row cites
still has to use the exact captured `rch exec -- ...` command.

It fails closed when:

- the transcript path resolves outside the project root;
- JSONL is missing, empty, malformed, or contains non-object rows;
- required fields are absent;
- `bead_id` or `thread_id` is missing, inconsistent, or does not match the
  expected Beads issue / Agent Mail thread when those expectations are passed;
- a cargo proof command is absent or does not start with `rch exec --`;
- a `run` or `coalesce` row is missing the proof key;
- a `coalesce` row lacks the owning agent or attempts to launch another
  command;
- `defer`, `handoff`, or `blocked` rows try to run a command or omit the first
  actionable blocker evidence / retry guidance;
- the closeout recommendation does not match the decision state.

Closeout text may cite a transcript only after this checker passes for the
matching Beads issue and Agent Mail thread. A passing checker result is not a
green proof by itself for `defer`, `handoff`, or `blocked`; those states still
require follow-up coordination, evidence refresh, or blocker recording before a
Bead can close.

## Consumer Rules

### Agent Mail

Start and completion messages should include `decision`, `reason_code`, and the
first evidence reference. `handoff` and `blocked` decisions should include the
required action and the current holder or blocker when known.

### Beads

Beads comments and closeout should cite a fresh admission decision only when it
matches the bead ID and Agent Mail thread ID. `run` and `coalesce` decisions can
support closeout only when the downstream source-only checks, receipt, or proof
cache evidence also validates. `defer`, `handoff`, and `blocked` decisions are
not closeout proof by themselves.

### Doctor and Readiness

Doctor and readiness output should render the five decision states without
exposing lower-level scheduler/coalescer vocabulary as the primary action. The
lower-level fields remain available in JSON diagnostics.

### CI and Gates

Source-only contract checks should validate schema versions, reason/event/action
pairs, fixture coverage, bounded summaries, and fail-closed mutations. Live
cargo or benchmark validation is optional and must use explicit
`rch exec -- ...` commands with an off-repo target-dir policy.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec | `docs/specs/swarm_validation_admission.md` |
| Schema catalog | `artifacts/validation_broker/swarm_validation_admission/swarm_validation_admission_contract.schema.json` |
| Fixtures | `artifacts/validation_broker/swarm_validation_admission/swarm_validation_admission_fixtures.v1.json` |
| Gate script | `scripts/check_swarm_validation_admission_contract.py` |

The artifact, fixture, and checker paths are reserved for follow-on beads. This
design bead establishes the stable version 1 contract they must implement.
