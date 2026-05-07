# Proof-Lane Readiness Capsule Contract

**Bead:** bd-yyl6t.1
**Capsule schema:** `franken-node/proof-lane-readiness/capsule/v1`
**Decision schema:** `franken-node/proof-lane-readiness/decision/v1`

## Purpose

Proof-lane readiness capsules record whether an expensive validation proof may
be launched on the requested RCH lane. They sit before `rch exec -- cargo ...`
and before validation-broker receipts: their job is to prove that a proof lane
is safe to use, or to fail closed with a source-only blocker that later
consumers can read without terminal history.

This contract exists for swarm operation. Many agents can see generic RCH
status, but a proof may still be invalid when the selected worker differs from
the requested same-toolchain worker, when a worker has no capability snapshot,
or when credential drift prevents access to the only acceptable worker. A
capsule makes that preflight state durable, bounded, and machine-readable.

## Non-Goals

- A readiness capsule is not a validation receipt and cannot satisfy a proof
  requirement by itself.
- A readiness capsule does not classify cargo compile, test, clippy, or format
  output. That remains the RCH adapter and validation broker's responsibility.
- A readiness capsule does not replace resource-governor pressure reports,
  flight-recorder attempts, or recovery-planner decisions. It can be cited by
  those surfaces when a proof was not launched.
- A readiness capsule must not run live cargo from unit tests. Live RCH probes,
  if added, must be narrow adapters around deterministic data models.

## Producers

A producer may be a CLI command, a validation-broker preflight step, a doctor
readiness check, or a source-only closeout helper. Producers must bind each
capsule to the intended command and Bead:

- `bead_id` and `thread_id` identify the owning Bead and Agent Mail thread.
- `command_digest` is the canonical SHA-256 digest of the command that would
  have been launched.
- `requested_workers` records explicit worker preference such as `RCH_WORKER`
  or `RCH_WORKERS`.
- `selected_worker` records what RCH dry-run or scheduler selection returned.
- `local_fallback_allowed` and `local_fallback_refused` make fail-open behavior
  explicit.

If a producer observes no selected worker, it must still emit a capsule with a
reason code such as `worker_capability_unknown`, `same_toolchain_missing`, or
`local_fallback_refused`.

## Capsule Shape

```json
{
  "schema_version": "franken-node/proof-lane-readiness/capsule/v1",
  "capsule_id": "plr-20260507-bd-yyl6t-1",
  "trace_id": "trace-proof-lane-readiness",
  "bead_id": "bd-yyl6t.1",
  "thread_id": "bd-yyl6t.1",
  "created_at": "2026-05-07T00:00:00Z",
  "freshness_expires_at": "2026-05-07T00:30:00Z",
  "producer": {
    "name": "franken-node ops validation-readiness",
    "agent_name": "PurpleLeopard",
    "git_commit": "unknown-or-hex",
    "dirty_worktree": false
  },
  "command": {
    "program": "cargo",
    "argv": ["test", "-p", "frankenengine-node", "resource_governor", "--", "--nocapture"],
    "cwd": "/data/projects/franken_node",
    "digest": {
      "algorithm": "sha256",
      "hex": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  },
  "rch": {
    "daemon_source": "installed",
    "daemon_version": "1.0.24",
    "socket_path": "/run/user/1000/rch.sock",
    "require_remote": true,
    "local_fallback_allowed": false,
    "local_fallback_refused": true
  },
  "worker_selection": {
    "requested_workers": ["ts2"],
    "selected_worker": "vmi1153651",
    "override_effective": false,
    "selection_source": "dry_run",
    "selection_observed_at": "2026-05-07T00:00:00Z"
  },
  "toolchain": {
    "local_rustc": "rustc 1.97.0-nightly",
    "required_toolchain": "nightly",
    "selected_worker_rustc": "1.95.0-nightly",
    "same_toolchain": false
  },
  "worker_access": {
    "auth_status": "unknown",
    "capability_status": "fresh",
    "pressure_status": "healthy",
    "detail": "selected worker does not match requested same-toolchain worker"
  },
  "decision": {
    "schema_version": "franken-node/proof-lane-readiness/decision/v1",
    "decision": "source_only_blocker",
    "reason_code": "PLR_OVERRIDE_NOT_HONORED",
    "event_code": "PLR-002",
    "retryable": true,
    "fail_closed": true,
    "required_action": "fix_rch_worker_selection_or_use_valid_same_toolchain_worker",
    "operator_summary": "RCH selected vmi1153651 even though ts2 was requested; do not launch this proof as green evidence."
  }
}
```

All strings in a capsule are bounded diagnostic fields. Implementations should
reuse existing path, digest, timestamp, and NUL-byte validation patterns from
validation-broker and resource-governor code.

## Required Fields

| Field | Required | Description |
|-------|----------|-------------|
| `schema_version` | Yes | Must equal `franken-node/proof-lane-readiness/capsule/v1`. |
| `capsule_id` | Yes | Stable capsule identifier. |
| `trace_id` | Yes | Trace that links preflight, closeout, and logs. |
| `bead_id` | Yes | Owning Bead. |
| `thread_id` | Yes | Agent Mail thread, normally equal to the Bead ID. |
| `created_at` | Yes | RFC 3339 UTC timestamp. |
| `freshness_expires_at` | Yes | After this time the capsule cannot be used for closeout. |
| `producer` | Yes | Tool or agent that generated the capsule. |
| `command` | Yes | Canonical command intent and digest. |
| `rch` | Yes | RCH daemon, remote requirement, and fallback policy. |
| `worker_selection` | Yes | Requested and selected worker evidence. |
| `toolchain` | Yes | Local and selected-worker toolchain compatibility. |
| `worker_access` | Yes | Authentication, capability, and pressure observations. |
| `decision` | Yes | Stable machine decision and operator action. |

## Enumerations

### Decisions

| Value | Meaning |
|-------|---------|
| `ready_to_launch` | Proof lane is suitable for the intended command. |
| `queue_until_ready` | Lane is valid but capacity or freshness requires waiting. |
| `retry_preflight` | Transient readiness probe failed; retry is bounded. |
| `source_only_blocker` | Proof must not launch; source-only closeout may cite the capsule. |
| `fail_closed` | Input is malformed or unsafe; do not launch or claim a valid blocker. |

### Worker Auth Status

| Value | Meaning |
|-------|---------|
| `not_checked` | No auth probe was attempted. |
| `ok` | Worker accepted an authenticated control operation. |
| `permission_denied` | Worker rejected authentication, for example public-key denial. |
| `timeout` | Worker auth/control probe timed out. |
| `unreachable` | Worker could not be contacted. |
| `unknown` | Producer cannot classify the failure. |

### Capability Status

| Value | Meaning |
|-------|---------|
| `fresh` | Capability observation is present and within freshness. |
| `stale` | Observation exists but freshness expired. |
| `missing` | No capability snapshot exists for the worker. |
| `malformed` | Capability snapshot cannot be parsed or validated. |
| `unknown` | Producer cannot distinguish missing from stale or malformed. |

### Pressure Status

| Value | Meaning |
|-------|---------|
| `healthy` | No pressure blocks the proof lane. |
| `warning` | Lane may be usable but should include diagnostics. |
| `blocked` | Pressure policy blocks launch. |
| `telemetry_gap` | Pressure telemetry is unavailable or stale. |
| `unknown` | Producer cannot classify pressure. |

## Reason and Event Codes

| Reason code | Event | Decision | Retryable | Required action |
|-------------|-------|----------|-----------|-----------------|
| `PLR_HEALTHY_SAME_TOOLCHAIN_LANE` | `PLR-001` | `ready_to_launch` | No | `launch_remote_proof` |
| `PLR_OVERRIDE_NOT_HONORED` | `PLR-002` | `source_only_blocker` | Yes | `fix_rch_worker_selection_or_use_valid_same_toolchain_worker` |
| `PLR_SAME_TOOLCHAIN_MISSING` | `PLR-003` | `source_only_blocker` | Yes | `sync_toolchain_or_wait_for_matching_worker` |
| `PLR_WORKER_AUTH_FAILED` | `PLR-004` | `source_only_blocker` | Yes | `repair_worker_credentials_before_retry` |
| `PLR_WORKER_CAPABILITY_UNKNOWN` | `PLR-005` | `retry_preflight` | Yes | `refresh_worker_capabilities` |
| `PLR_WORKER_PRESSURE_BLOCKED` | `PLR-006` | `queue_until_ready` | Yes | `wait_for_pressure_to_clear_or_select_another_valid_worker` |
| `PLR_LOCAL_FALLBACK_REFUSED` | `PLR-007` | `source_only_blocker` | Yes | `restore_remote_execution_before_cargo_proof` |
| `PLR_STALE_READINESS_CAPSULE` | `PLR-008` | `fail_closed` | Yes | `regenerate_readiness_capsule` |
| `PLR_MALFORMED_READINESS_INPUT` | `PLR-009` | `fail_closed` | No | `fix_readiness_input_schema` |

## Invariants

- **INV-PLR-NO-PROXY-GREEN** - A readiness capsule can never be used as green
  validation proof. It can only allow launch or record why launch was refused.
- **INV-PLR-REQUESTED-WORKER-BINDING** - If a requested worker list is present,
  the selected worker must be one of those workers before a same-worker proof
  lane is ready.
- **INV-PLR-SAME-TOOLCHAIN** - A cargo proof that requires a specific toolchain
  is not ready unless the selected worker has a fresh matching capability
  observation.
- **INV-PLR-AUTH-FAIL-CLOSED** - `permission_denied`, `timeout`, and
  `unreachable` auth statuses cannot produce `ready_to_launch`.
- **INV-PLR-FALLBACK-VISIBLE** - Local fallback must be explicit. When remote
  proof is required, local fallback is a blocker, not a proof.
- **INV-PLR-FRESHNESS-BOUNDED** - Consumers must reject capsules whose
  `freshness_expires_at` is earlier than the consumer time.
- **INV-PLR-PRODUCT-FAILURE-SEPARATION** - Product compile, test, clippy, and
  format failures are outside this capsule and must not be rewritten as worker
  readiness failures.
- **INV-PLR-BOUNDED-DIAGNOSTICS** - Worker lists, paths, summaries, details,
  and snippets must have explicit size caps and reject NUL bytes.

## Consumer Rules

### Validation Broker

The validation broker may attach a `readiness_ref` to status, receipt, or
flight-recorder structures when the proof was not launched because readiness
failed. A `readiness_ref` must include:

- `schema_version`
- repo-relative `path`
- SHA-256 `digest`
- `reason_code`
- `event_code`
- `generated_at`
- `freshness_expires_at`

Broker closeout must reject stale, missing, path-traversal, NUL-containing, or
digest-invalid readiness references.

### Validation Readiness

`ops validation-readiness` may summarize the latest capsule using stable JSON
fields:

- `proof_lane_readiness.decision`
- `proof_lane_readiness.reason_code`
- `proof_lane_readiness.requested_workers`
- `proof_lane_readiness.selected_worker`
- `proof_lane_readiness.same_toolchain`
- `proof_lane_readiness.auth_status`
- `proof_lane_readiness.capability_status`
- `proof_lane_readiness.required_action`
- `proof_lane_readiness.capsule_path`

Human output must state whether cargo was launched. Preflight-only capsules
must not read like completed proof evidence.

### Beads and Agent Mail

When a source-only blocker cites a capsule, Beads comments and Agent Mail
messages should include:

- Bead ID and thread ID.
- Command digest or a bounded command summary.
- Requested worker and selected worker.
- Local and worker toolchain summaries.
- Auth and capability status.
- `reason_code`, `event_code`, and `required_action`.
- Capsule path/digest when an artifact exists.
- Whether cargo/RCH proof was launched.

## Fixture Obligations

The first implementation must add deterministic fixtures for these scenarios:

1. Healthy same-toolchain remote lane.
2. Requested worker override not honored by the installed RCH daemon.
3. Same-toolchain worker missing from the healthy worker set.
4. Worker authentication failure such as `Permission denied (publickey,password)`.
5. Worker capability snapshot missing or stale.
6. Worker pressure blocks launch while another valid worker is unavailable.
7. Remote proof required and local fallback refused.
8. Stale readiness capsule rejected by a consumer.

The current `bd-agpdg` evidence should be representable as fixture data:

- installed RCH dry-run selected `vmi1153651` while `RCH_WORKER=ts2` was set;
- temporary patched daemon saw `ts2` with empty capabilities or unreachable
  status;
- direct SSH to `ubuntu@100.96.111.98` failed with
  `Permission denied (publickey,password)`;
- no cargo proof was launched because that would fall open locally or use a
  mismatched worker.

## Validation

Source-only changes to this contract require:

```bash
git diff --check docs/specs/proof_lane_readiness.md
br ready --json
bv --recipe actionable --robot-plan
```

Rust implementation changes must additionally use:

```bash
rch exec -- cargo test -p frankenengine-node <proof-lane-readiness-target>
ubs <changed-rust-files>
```

If RCH cannot provide a valid remote proof lane, the implementer must record the
exact readiness reason and leave the cargo proof blocked. A local cargo fallback
is not acceptable proof in this repository.
