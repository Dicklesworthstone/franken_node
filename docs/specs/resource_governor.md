# Resource Governor Telemetry

`franken-node ops resource-governor` emits a deterministic advisory report before agents launch expensive validation proof work. The same contract also governs workspace-wide generated artifact pressure: target directories, RCH target directories, temporary build outputs, generated evidence, and pinned cache entries.

This contract complements `docs/specs/validation_broker.md` and
`docs/specs/bootstrap_doctor_contract.md`. The validation broker decides how
proof work is queued and recorded. The resource governor decides whether the
workspace is healthy enough to start work, whether proof work must be offloaded,
and which generated artifacts are safe cleanup candidates. Doctor/readiness
surfaces consume this report; they do not infer resource state from terminal
history or chat messages.

The command supports live process observation through `/proc` and fixture-driven replay through `--process-snapshot <path>`. Snapshot JSON uses the same observation fields as the report:

```json
{
  "observed_at": "2026-05-05T12:00:00Z",
  "source": "fixture",
  "processes": [
    {"pid": 31, "command": "cargo check -p frankenengine-node"},
    {"pid": 32, "command": "rustc --crate-name frankenengine_node"}
  ],
  "rch_queue_depth": 2,
  "active_proof_classes": ["cargo-check"],
  "target_dir_usage_mb": 8192,
  "memory_used_mb": 64000,
  "cpu_load_permyriad": 7500,
  "artifact_inventory": [
    {
      "path": "/data/projects/franken_node/target",
      "repo_key": "/data/projects/franken_node",
      "kind": "cargo-target-dir",
      "safety_class": "rebuildable-build-output",
      "bytes": 8589934592,
      "pin": null
    }
  ]
}
```

Typical agent preflight:

```bash
franken-node ops resource-governor \
  --requested-proof-class cargo-check \
  --active-proof-class cargo-test \
  --rch-queue-depth 2 \
  --source-only-allowed \
  --trace-id bd-ksb41 \
  --json
```

The JSON report schema is `franken-node/resource-governor/report/v1`. The decision is one of:

| Decision | Meaning |
|---|---|
| `allow` | Cargo/RCH validation may run. |
| `allow_low_priority` | Validation may run only as low-priority remote work or after the reported backoff. |
| `require_rch` | Local execution is refused; the caller must offload through RCH or wait. |
| `queue` | Proof work must enter the validation broker queue instead of launching directly. |
| `dedupe_only` | An equivalent proof class is already active; wait for or reuse that receipt. |
| `source_only` | Validation pressure is high, but source-only work may continue with the emitted reason code. |
| `wait` | Do not start work until the emitted retry-after window elapses. |
| `defer` | Do not start cargo/RCH validation until the reported backoff has elapsed and telemetry has been refreshed. |
| `refuse_local_fallback` | RCH is unavailable or unsafe and local fallback is refused under current pressure. |
| `propose_cleanup` | Cleanup candidates are available, but execution requires explicit approved cleanup mode. |
| `cleanup_candidates_only_after_confirmed_eligibility` | Approved cleanup mode may touch only candidates that pass safety class, pin, age, reservation, and open-file checks. |
| `refuse_cleanup` | Cleanup is unsafe because every candidate is protected, pinned, active, too young, or unclassified. |

Every report includes `trace_id`, process counts, optional RCH queue depth,
active proof classes, thresholds, `recommended_backoff_ms`, optional
`retry_after_ms`, and a structured log object with event code `RG-002` and the
decision reason code. Operator shorthand such as "allow-local",
"wait-with-retry-after", and "clean-candidates-only-after-confirmed-eligibility"
maps to the JSON decisions above.

## Report State Examples

Green, local validation allowed:

```json
{"schema":"franken-node/resource-governor/report/v1","state":"green","decision":"allow","reason_code":"RG_ALLOW_HEALTHY","artifact_inventory":[]}
```

Yellow, local cargo contention requires offload or queueing:

```json
{"schema":"franken-node/resource-governor/report/v1","state":"yellow","decision":"require_rch","retry_after_ms":30000,"reason_code":"RG_REQUIRE_RCH_CARGO_CONTENTION","cargo_process_count":8}
```

Red, disk pressure has no safe cleanup candidates:

```json
{"schema":"franken-node/resource-governor/report/v1","state":"red","decision":"refuse_cleanup","reason_code":"RG_FAIL_CLOSED_UNCLASSIFIED","disk_free_percent":3,"cleanup_candidates":[]}
```

Corrupt coordination state, cleanup fails closed while source-only work may
continue:

```json
{"schema":"franken-node/resource-governor/report/v1","state":"corrupt-coordination","decision":"source_only","reason_code":"RG_SOURCE_ONLY_ALLOWED","coordination_health":"corrupt","cleanup_allowed":false}
```

## Artifact Safety Classes

The governor must classify every inventory entry before policy uses it. Unknown
classes fail closed and are not cleanup candidates.

| Safety class | Cleanup eligible | Meaning |
|---|---:|---|
| `source-never-delete` | No | Repository source, manifests, tests, scripts, docs, and checked-in artifacts. |
| `user-data-never-delete` | No | Inputs, operator data, or externally supplied state. |
| `logs-session-history-never-delete` | No | Logs, terminal transcripts, session history, memory stores, and mailbox archives. |
| `beads-mail-never-delete` | No | `.beads`, Agent Mail archives, lock files, reservations, messages, and profiles. |
| `pinned-generated-artifact` | No | Generated output retained by an explicit pin, TTL, bead, or operator reason. |
| `generated-evidence` | Only when expired and unpinned | Reports, summaries, or receipts generated from reproducible commands. |
| `rebuildable-build-output` | Yes, with age/open-file checks | Cargo targets, RCH target dirs, build scratch space, and cache entries. |
| `disposable-temp-output` | Yes, with age/open-file checks | Temporary generated files with no durable evidence role. |

Cleanup decisions are report-only unless a caller enters explicit approved
cleanup mode. The report must never recommend deleting source, Beads, Mail,
logs, session history, memory stores, or user data.

## Artifact Inventory Fields

Inventory entries use schema `franken-node/resource-governor/artifact/v1`.

| Field | Required | Description |
|---|---:|---|
| `path` | Yes | Absolute canonical path or stable repo-relative path when canonicalization is unavailable. |
| `repo_key` | Yes | Absolute project root or product workspace key. |
| `kind` | Yes | `cargo-target-dir`, `rch-target-dir`, `generated-evidence`, `temp-output`, `cache-entry`, or `unknown`. |
| `safety_class` | Yes | One of the safety classes above. |
| `bytes` | Yes | Non-negative size estimate. Unknown sizes use `null` and are not cleanup candidates. |
| `mtime` | No | Last modification timestamp when available. |
| `owner_agent` | No | Agent identity associated with the artifact. |
| `bead_id` | No | Bead that produced or pinned the artifact. |
| `producer_command_digest` | No | SHA-256 digest of canonical command material. |
| `content_digest` | No | SHA-256 digest for small durable artifacts or manifest roots. |
| `pin` | No | Pin reason, owner, and expiry. Non-null pins block cleanup. |
| `open_file_status` | No | `unknown`, `open`, or `not_open`; `open` blocks cleanup. |
| `minimum_age_secs` | No | Required age before cleanup is eligible. |
| `cleanup_eligible` | Yes | Boolean derived from safety class, pin, age, open-file status, and path policy. |

Path strings containing NUL bytes, parent traversal that escapes the repo root,
or protected path prefixes must be rejected with a stable error code.

## Pressure Inputs

The live sampler may use `/proc`, filesystem metadata, RCH status, and optional
NUMA information. Unit tests must inject fixture snapshots instead of shelling
out. Pressure reports include:

- Disk free bytes and free percentage for project, temp, target, and cache roots.
- Target-dir and RCH target-dir byte totals by repo.
- Cargo/rustc process count, with documented handling for command self-matches.
- RCH queue depth, active leases, worker availability, and local-fallback policy.
- RAM available bytes, swap used percentage, and optional NUMA node pressure.
- CPU load permyriad and configured build job caps.
- Agent Mail and Beads health, including corrupt recovery mode or stale locks.
- Active file reservations that overlap proposed cleanup candidates.

## Reason Codes and Events

| Code | Meaning |
|---|---|
| `RG_ALLOW_HEALTHY` | All pressure signals are below thresholds. |
| `RG_REQUIRE_RCH_CARGO_CONTENTION` | Local cargo/rustc contention is above the configured threshold. |
| `RG_DEDUPE_ACTIVE_PROOF_CLASS` | Equivalent proof work is already active. |
| `RG_WAIT_RCH_QUEUE` | RCH is reachable but queue pressure requires waiting. |
| `RG_SOURCE_ONLY_ALLOWED` | Heavy validation is deferred but source-only work may proceed. |
| `RG_CLEANUP_CANDIDATES_AVAILABLE` | Eligible generated artifacts are available for approved cleanup. |
| `RG_CLEANUP_BLOCKED_PROTECTED_PATH` | Candidate path is protected by safety class or policy. |
| `RG_CLEANUP_BLOCKED_PINNED` | Candidate has a live pin. |
| `RG_CLEANUP_BLOCKED_OPEN_FILE` | Candidate appears open by a live process. |
| `RG_FAIL_CLOSED_UNCLASSIFIED` | Input could not be classified safely. |

Structured events:

| Event | Description |
|---|---|
| `RG-001` | Pressure snapshot accepted. |
| `RG-002` | Admission decision emitted. |
| `RG-003` | Cleanup candidates proposed. |
| `RG-004` | Cleanup refused for protected, pinned, active, or unclassified path. |
| `RG-005` | Approved cleanup receipt emitted. |
| `RG-006` | Doctor/readiness resource snapshot emitted. |

## Doctor and Readiness Output Contract

The resource governor integrates with `franken-node doctor` and `franken-node ops readiness` to provide actionable workspace pressure governance output. Doctor emits warnings when coordination state is corrupt or cleanup is needed; readiness provides structured status for automation.

### Doctor Output

Doctor output includes a "Workspace Pressure" section that summarizes state and recommends next actions:

**Human output format:**
```
Workspace Pressure: GREEN
  Protected: 2.1 GB (source, beads, mail, logs)
  Rebuildable: 8.2 GB (cargo targets, temp outputs)
  RCH: Available (queue depth: 2)
  Action: Ready for local builds
```

**Structured warnings for yellow/red states:**
```
Workspace Pressure: YELLOW
  Protected: 2.1 GB (source, beads, mail, logs)
  Rebuildable: 47.8 GB (cargo targets exceeding threshold)
  RCH: Available (queue depth: 8)
  Action: Use RCH for validation, cleanup candidates available
  Warning: 12 cleanup candidates found, run with --cleanup-mode to review
```

**Corrupt coordination state:**
```
Workspace Pressure: CORRUPT
  Protected: 2.1 GB (source, beads, mail, logs)
  Coordination: Agent Mail state inconsistent
  Action: Source-only work allowed, avoid cleanup until coordination restored
  Error: Detected stale file reservations, corrupted lease metadata
```

### Readiness JSON Contract

Readiness output includes a `workspace_pressure` section using schema `franken-node/doctor-readiness/workspace-pressure/v1`:

```json
{
  "workspace_pressure": {
    "schema": "franken-node/doctor-readiness/workspace-pressure/v1",
    "state": "green|yellow|red|corrupt-coordination",
    "decision": "allow|require_rch|propose_cleanup|refuse_cleanup|source_only",
    "reason_code": "RG_ALLOW_HEALTHY|RG_REQUIRE_RCH_CARGO_CONTENTION|...",
    "inventory_summary": {
      "protected_bytes": 2147483648,
      "rebuildable_bytes": 8589934592,
      "cleanup_candidates_count": 0,
      "cleanup_candidates_bytes": 0
    },
    "infrastructure_state": {
      "cargo_processes": 2,
      "rch_available": true,
      "rch_queue_depth": 2,
      "coordination_health": "healthy|degraded|corrupt"
    },
    "recommendations": {
      "next_action": "ready|use_rch|review_cleanup|source_only|wait",
      "retry_after_ms": null,
      "cleanup_mode_required": false,
      "commands": []
    },
    "warnings": [
      {
        "code": "WP_CLEANUP_CANDIDATES_AVAILABLE",
        "message": "12 cleanup candidates found",
        "severity": "info"
      }
    ]
  }
}
```

### Event Code Details

Doctor/readiness workspace pressure events:

| Event Code | Severity | Description |
|---|---|---|
| `WP_STATE_GREEN` | info | Workspace pressure is healthy, local builds allowed |
| `WP_STATE_YELLOW` | warning | Workspace pressure elevated, RCH or cleanup recommended |
| `WP_STATE_RED` | error | Workspace pressure critical, cleanup or deferral required |
| `WP_COORDINATION_CORRUPT` | error | Agent Mail/Beads coordination state is inconsistent |
| `WP_CLEANUP_CANDIDATES_AVAILABLE` | info | Cleanup candidates found, approved cleanup mode available |
| `WP_CLEANUP_BLOCKED_ALL_PROTECTED` | warning | All artifacts are protected/pinned, cleanup unavailable |
| `WP_RCH_UNAVAILABLE` | warning | Remote compilation unavailable, local fallback policy applies |

### Required Fields

Doctor output must include:
- State summary (GREEN/YELLOW/RED/CORRUPT)
- Protected byte count with breakdown
- Rebuildable byte count
- RCH availability and queue depth
- Clear next action recommendation
- Structured warnings for automation parsing

Readiness JSON must include:
- `state`, `decision`, `reason_code` (required)
- `inventory_summary` with protected/rebuildable byte counts
- `infrastructure_state` with cargo/RCH status
- `recommendations` with next action and any retry timing
- `warnings` array with structured warning details

No output may recommend destructive actions without explicit approved cleanup mode context.

## Required Fixture Scenarios

Fixture replay must cover at least:

| Scenario | Expected decision |
|---|---|
| `green_idle` | `allow` |
| `cargo_contention` | `require_rch` or `source_only` depending on request class |
| `rch_unavailable` | `defer` or `source_only` when source-only fallback is allowed |
| `disk_warning_with_candidates` | `propose_cleanup` |
| `disk_red_no_safe_candidates` | `refuse_cleanup` |
| `pinned_target_hotset` | `wait` or `require_rch`, no cleanup candidate for the pin |
| `corrupt_coordination_state` | fail closed for cleanup, source-only work may continue |
| `numa_node_pressure` | `allow_low_priority` or `defer` based on thresholds |

## Test Obligations

- Unit tests for safety-class classification, bounded inventory growth, protected
  path rejection, pin handling, age thresholds, open-file handling, and policy
  decisions.
- Golden JSON and human output for green, yellow, red, and corrupt-coordination
  scenarios.
- Mock-free E2E over temporary target-like trees that proves protected paths are
  preserved and only eligible generated artifacts are proposed or removed in
  approved cleanup mode.
- A checker script should validate fixture schemas, reason codes, event codes,
  non-deletion guarantees, and golden-output determinism without running cargo.
- Any Rust/CLI cargo validation must be run through `rch exec -- ...` and skipped
  or marked blocked when the repository contention threshold is exceeded.
