# Validation Autopilot Contract

**Bead:** `bd-k599n`
**Schema catalog:** `franken-node/validation-autopilot/schema-catalog/v1`
**Status:** Draft contract for follow-on implementation beads

## Purpose

Validation autopilot is the no-ready decision layer for agent swarms. It
consumes tracker, graph, blocker, RCH, and Agent Mail evidence and emits one
bounded next action:

- claim a genuinely ready Bead;
- refresh stale blocker evidence;
- create a narrow follow-up Bead proposal;
- retry RCH under a bounded remote-only policy;
- coordinate with an owner or reservation holder;
- hand the state to an operator without mutating anything.

The contract exists to keep agents moving when `br ready --json` is empty but
`bv --recipe actionable --robot-plan` still surfaces blocked epics, parent
work, or external blockers. It does not make blocked work claimable.

## Relationship to Existing Contracts

Validation autopilot is a coordinator above existing source-only and validation
surfaces:

| Surface | Role |
|---------|------|
| `docs/runbooks/no_ready_swarm_recovery.md` | Human runbook and Agent Mail handoff template |
| `docs/specs/swarm_validation_admission.md` | Admission semantics for validation work once a concrete Bead exists |
| `docs/specs/proof_lane_readiness.md` | Preflight proof-lane capsule before cargo/RCH validation launches |
| `docs/specs/rch_adapter.md` | RCH outcome classification and product-vs-worker separation |
| `scripts/check_tracker_actionability.py` | `br`/`bv` claimability reconciliation |
| `scripts/check_blocked_bead_freshness.py` | Blocked-Bead first-blocker freshness audit |
| `scripts/normalize_rch_evidence.py` | RCH timeout, stale-progress, dependency, product, and success normalization |

Follow-on implementation must compose those surfaces. It must not duplicate
their parsers in a separate unchecked path.

## Non-Goals

- Validation autopilot does not run Cargo, RCH, Python gates, Beads commands,
  or Agent Mail sends by default.
- Validation autopilot does not auto-close, auto-reopen, or auto-claim Beads.
- Validation autopilot does not bypass active file reservations or active
  Agent Mail ownership.
- Validation autopilot does not convert source-only evidence into green cargo
  proof.
- Validation autopilot does not create compatibility shims for product code.

## Input Schema

`ValidationAutopilotInput` is the canonical input to a planner.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-autopilot/input/v1` |
| `trace_id` | String | Yes | Trace shared by Beads comments, Agent Mail, and artifacts |
| `agent_name` | String | Yes | Agent requesting the decision |
| `generated_at` | RFC3339 String | Yes | UTC input generation time |
| `worktree_status` | Object | Yes | `git status --short` summary, never used to revert files |
| `active_agents` | Array | Yes | Current Agent Mail agent names and last-active timestamps |
| `inbox_summary` | Object | Yes | New actionable messages, ack-required status, and stale artifact notes |
| `br_ready` | Object | Yes | JSON from `br ready --json` |
| `br_active` | Object | Yes | Active open/blocked/in-progress Beads from `br list --json` |
| `bv_plan` | Object | Yes | JSON from `bv --recipe actionable --robot-plan` |
| `bv_priority` | Object or null | Yes | JSON from `bv --robot-priority`, or null when unavailable |
| `bv_insights` | Object or null | Yes | JSON from `bv --robot-insights`, or null when unavailable |
| `tracker_actionability` | Object | Yes | Output of `scripts/check_tracker_actionability.py` |
| `blocked_freshness` | Object | Yes | Output of `scripts/check_blocked_bead_freshness.py` |
| `rch_evidence` | Array | Yes | Zero or more normalized RCH evidence records |
| `handoff_context` | Object | Yes | Existing owner, reservation, and Agent Mail context |
| `policy` | Object | Yes | `ValidationAutopilotPolicy` |

All optional upstream data uses explicit `null`; fields are never silently
omitted. Inputs are stale after `policy.input_freshness_seconds`.

## Policy Schema

`ValidationAutopilotPolicy` controls which actions are allowed.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-autopilot/policy/v1` |
| `input_freshness_seconds` | Integer | Yes | Maximum age of tracker/mail/RCH evidence |
| `blocked_freshness_hours` | Integer | Yes | Maximum age before blocker refresh is recommended |
| `require_rch_for_cargo` | Boolean | Yes | Cargo build/test/check/clippy/fmt commands require `rch exec -- ...` |
| `max_rch_retries_per_blocker` | Integer | Yes | Bounded retries before handoff or blocker preservation |
| `worker_quarantine_failure_threshold` | Integer | Yes | Same-worker infrastructure failures before quarantine/drain advice |
| `allow_bead_creation` | Boolean | Yes | Planner may propose a new Bead body |
| `allow_tracker_mutation` | Boolean | Yes | Must default false for agent dry-runs |
| `fail_closed_on_mail_gap` | Boolean | Yes | Missing Agent Mail state blocks ownership-changing actions |
| `fail_closed_on_reservation_conflict` | Boolean | Yes | Active conflicting reservations block claims and edits |

This repository's default policy should set `allow_tracker_mutation = false`.
Follow-on tooling may print exact `br create` or `br comment` commands, but it
must not execute them unless a later explicitly approved bead adds an apply
mode.

## Decision Schema

`ValidationAutopilotDecision` is the planner output.

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-autopilot/decision/v1` |
| `decision_id` | String | Yes | Stable id, preferably `valauto-decision-<sha256-prefix>` |
| `trace_id` | String | Yes | Copied from input |
| `decided_at` | RFC3339 String | Yes | UTC decision time |
| `decision` | Enum | Yes | One of the decision values below |
| `reason_code` | Enum | Yes | Stable reason code |
| `event_code` | Enum | Yes | Stable event code |
| `selected_bead_id` | String or null | Yes | Existing Bead selected by the decision |
| `proposed_bead` | Object or null | Yes | New Bead proposal when `decision=create_followup_bead` |
| `recommended_command` | Array or null | Yes | Exact command argv when a command is recommended |
| `recommended_rch_command` | Array or null | Yes | Exact `rch exec -- ...` argv when bounded RCH retry is recommended |
| `requires_rch` | Boolean | Yes | True for cargo-heavy recommended commands |
| `mutation_allowed` | Boolean | Yes | False unless policy explicitly allows mutation |
| `retry_allowed` | Boolean | Yes | Whether a later retry may proceed |
| `retry_budget_remaining` | Integer | Yes | Remaining retries for the normalized blocker |
| `worker_action` | String or null | Yes | Deterministic worker advice such as `retry_different_worker`, `retry_after_clean_cancellation`, `quarantine_or_drain_worker`, or `none` |
| `stop_reason` | String or null | Yes | Deterministic stop label such as `retry_budget_exhausted`, `worker_quarantine_recommended`, `dependency_convergence_required`, `product_diagnostic_reached`, or `clean_success` |
| `operator_summary` | String | Yes | Bounded human summary for Agent Mail and Beads |
| `first_blocker` | String or null | Yes | Exact first blocker string when one exists |
| `evidence_refs` | Array | Yes | Repo-relative files, commands, or stable external refs |
| `diagnostics` | Object | Yes | Machine-readable classification details |

## Decision Values

| Decision | Meaning |
|----------|---------|
| `claim_ready` | `br ready --json` contains a task that is open, unblocked, unassigned or assigned to this agent, and not covered by a conflicting reservation. |
| `refresh_blocker` | A blocked Bead has missing, incomplete, or stale first-blocker evidence. |
| `create_followup_bead` | No existing Bead is claimable and a narrow, non-duplicative task would unblock progress. |
| `retry_rch_bounded` | RCH evidence is retryable infrastructure failure and retry budget remains. |
| `coordinate_owner` | Active owner, reservation holder, or cross-repo owner must be contacted before action. |
| `handoff_only` | No mutation or retry is safe; emit a complete operator handoff. |
| `blocked` | Required input is malformed, stale, missing, or unsafe. |

## Reason and Event Codes

| Decision | Reason code | Event | Required action |
|----------|-------------|-------|-----------------|
| `claim_ready` | `VALAUTO_READY_CLAIMABLE` | `VALAUTO-001` | `claim_selected_bead` |
| `refresh_blocker` | `VALAUTO_BLOCKER_STALE` | `VALAUTO-002` | `add_blocker_refresh_comment` |
| `refresh_blocker` | `VALAUTO_BLOCKER_INCOMPLETE` | `VALAUTO-003` | `record_exact_first_blocker` |
| `create_followup_bead` | `VALAUTO_NO_READY_CREATE_CHILD` | `VALAUTO-004` | `create_narrow_followup_bead` |
| `retry_rch_bounded` | `VALAUTO_RCH_TIMEOUT_RETRY` | `VALAUTO-005` | `retry_remote_validation_once` |
| `retry_rch_bounded` | `VALAUTO_RCH_STALE_PROGRESS_RETRY` | `VALAUTO-006` | `retry_after_clean_cancellation` |
| `coordinate_owner` | `VALAUTO_ACTIVE_OWNER` | `VALAUTO-007` | `message_owner_or_holder` |
| `coordinate_owner` | `VALAUTO_EXTERNAL_BLOCKER` | `VALAUTO-008` | `coordinate_external_repo_or_worker` |
| `handoff_only` | `VALAUTO_NO_SAFE_MUTATION` | `VALAUTO-009` | `send_operator_handoff` |
| `blocked` | `VALAUTO_MALFORMED_INPUT` | `VALAUTO-010` | `repair_autopilot_input` |
| `blocked` | `VALAUTO_STALE_INPUT` | `VALAUTO-011` | `refresh_tracker_mail_and_rch_evidence` |
| `blocked` | `VALAUTO_UNSAFE_LOCAL_CARGO` | `VALAUTO-012` | `replace_with_rch_prefixed_command` |

Follow-on tests must assert every emitted reason code is present in this table.

## Decision Precedence

When several decisions could apply, choose the first matching decision:

1. `blocked`
2. `coordinate_owner`
3. `claim_ready`
4. `refresh_blocker`
5. `retry_rch_bounded`
6. `create_followup_bead`
7. `handoff_only`

This ordering prevents action when inputs are unsafe, avoids ownership
conflicts, prefers real ready work over planning work, and only creates new
Beads after existing work is proven unavailable.

## Fail-Closed Rules

Validation autopilot must emit `blocked` when any condition holds:

- Required schema version is unknown.
- Required input field is absent or malformed.
- Tracker, mail, blocked freshness, or RCH evidence is older than policy.
- `br_ready` and `tracker_actionability` disagree in a way the planner cannot
  classify.
- A cargo-heavy recommended command lacks an explicit `rch exec -- ...` prefix.
- RCH evidence reports product diagnostics; retries must stop and the product
  failure must be preserved.
- RCH retry budget is exhausted.
- Agent Mail reports a current conflicting reservation or active owner.
- A proposed Bead overlaps an existing open or blocked Bead without an explicit
  dedupe note.
- A parent epic or blocked Bead is selected as if it were claimable.

## Proposed Bead Shape

When `decision=create_followup_bead`, `proposed_bead` must include:

- `title`
- `issue_type`
- `priority`
- `labels`
- `description`
- `dependency_suggestions`
- `overlap_search_terms`
- `reserved_paths_hint`
- `validation_plan`

The generated description must be self-contained and answer: what, why, how,
risks, and success criteria. It must preserve exact blocker strings and
commands when the proposal derives from blocker evidence.

## RCH Retry Policy

`retry_rch_bounded` is only valid for infrastructure-classified RCH outcomes:

| Normalized condition | Retry allowed | Worker action | Stop reason | Notes |
|----------------------|---------------|---------------|-------------|-------|
| `[RCH-E104] SSH command timed out` | Yes, within budget | `retry_different_worker` | null | Use fresh `CARGO_TARGET_DIR`, low priority, and preserve worker id |
| Stale progress with fresh heartbeat and clean cancellation | Yes, within budget | `retry_after_clean_cancellation` | null | Retry after cancellation evidence is recorded |
| Repeated same-worker infrastructure failure | No direct retry | `quarantine_or_drain_worker` | `worker_quarantine_recommended` | Coordinate worker quarantine/drain before more proof traffic |
| Retry budget exhausted | No | `none` | `retry_budget_exhausted` | Preserve first blocker and hand off |
| Dependency resolver mismatch | No direct retry | `none` | `dependency_convergence_required` | Create or refresh dependency-convergence Bead |
| Product compile/test/clippy/fmt diagnostic | No | `none` | `product_diagnostic_reached` | Preserve diagnostic as product blocker |
| Clean success | No | `none` | `clean_success` | Use as validation evidence, not retry input |

Retries must remain remote-only. The planner may recommend a command but must
not launch it.

## Agent Mail Handoff Shape

Every non-claim decision must be renderable as Markdown with:

- `ready_count`
- `selected_bead_id`
- `decision`
- `reason_code`
- `active_agents`
- `inbox_status`
- `exact_blockers`
- `proposed_next_action`
- `reserved_paths_hint`
- `validation_policy`

The handoff text must be bounded and must not include terminal scrollback
dumps. It may include command snippets only when they are the exact command
needed for audit.

## Example Decisions

### Ready Claim

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "claim_ready",
  "reason_code": "VALAUTO_READY_CLAIMABLE",
  "event_code": "VALAUTO-001",
  "selected_bead_id": "bd-k599n",
  "proposed_bead": null,
  "recommended_command": null,
  "recommended_rch_command": null,
  "requires_rch": false,
  "mutation_allowed": false,
  "retry_allowed": false,
  "retry_budget_remaining": 0,
  "worker_action": null,
  "stop_reason": null,
  "first_blocker": null
}
```

### No-Ready Follow-Up

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "create_followup_bead",
  "reason_code": "VALAUTO_NO_READY_CREATE_CHILD",
  "event_code": "VALAUTO-004",
  "selected_bead_id": null,
  "proposed_bead": {
    "title": "Refresh RCH timeout evidence for validation_proof_cache",
    "issue_type": "task",
    "priority": 2,
    "labels": ["rch", "validation", "blocked-refresh"],
    "overlap_search_terms": ["validation_proof_cache", "RCH-E104"]
  },
  "recommended_command": null,
  "recommended_rch_command": null,
  "requires_rch": false,
  "mutation_allowed": false,
  "retry_allowed": false,
  "retry_budget_remaining": 0,
  "worker_action": null,
  "stop_reason": null,
  "first_blocker": "[RCH] remote vmi1149989 failed [RCH-E104] SSH command timed out (no local fallback)"
}
```

### Stale Blocker Refresh

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "refresh_blocker",
  "reason_code": "VALAUTO_BLOCKER_STALE",
  "event_code": "VALAUTO-002",
  "selected_bead_id": "bd-famte",
  "proposed_bead": null,
  "recommended_command": ["br", "comment", "bd-famte", "--stdin"],
  "recommended_rch_command": null,
  "requires_rch": false,
  "mutation_allowed": false,
  "retry_allowed": false,
  "retry_budget_remaining": 0,
  "worker_action": null,
  "stop_reason": null,
  "first_blocker": "RCH proof timed out before a product diagnostic was reached"
}
```

### RCH Timeout Retry

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "retry_rch_bounded",
  "reason_code": "VALAUTO_RCH_TIMEOUT_RETRY",
  "event_code": "VALAUTO-005",
  "selected_bead_id": "bd-4gslh",
  "proposed_bead": null,
  "recommended_command": [
    "rch",
    "exec",
    "--",
    "env",
    "CARGO_TARGET_DIR=/tmp/rch_target_valauto_retry",
    "cargo",
    "test",
    "-p",
    "frankenengine-node",
    "validation_autopilot"
  ],
  "recommended_rch_command": [
    "rch",
    "exec",
    "--",
    "env",
    "CARGO_TARGET_DIR=/tmp/rch_target_valauto_retry",
    "cargo",
    "test",
    "-p",
    "frankenengine-node",
    "validation_autopilot"
  ],
  "requires_rch": true,
  "mutation_allowed": false,
  "retry_allowed": true,
  "retry_budget_remaining": 1,
  "worker_action": "retry_different_worker",
  "stop_reason": null,
  "first_blocker": "[RCH-E104] SSH command timed out"
}
```

### External Cross-Repo Blocker

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "coordinate_owner",
  "reason_code": "VALAUTO_EXTERNAL_BLOCKER",
  "event_code": "VALAUTO-008",
  "selected_bead_id": "bd-f5b04.2.6",
  "proposed_bead": null,
  "recommended_command": null,
  "recommended_rch_command": null,
  "requires_rch": false,
  "mutation_allowed": false,
  "retry_allowed": false,
  "retry_budget_remaining": 0,
  "worker_action": "none",
  "stop_reason": null,
  "first_blocker": "Blocked on sibling franken_engine backend wiring for QuickJsLane"
}
```

### Parent Epic Candidate

```json
{
  "schema_version": "franken-node/validation-autopilot/decision/v1",
  "decision": "handoff_only",
  "reason_code": "VALAUTO_NO_SAFE_MUTATION",
  "event_code": "VALAUTO-009",
  "selected_bead_id": "bd-rjs89",
  "proposed_bead": null,
  "recommended_command": null,
  "recommended_rch_command": null,
  "requires_rch": false,
  "mutation_allowed": false,
  "retry_allowed": false,
  "retry_budget_remaining": 0,
  "worker_action": "none",
  "stop_reason": "parent_epic_not_claimable",
  "first_blocker": "Candidate is a parent epic and cannot be claimed as implementation work"
}
```

## Invariants

- **INV-VALAUTO-NO-FALSE-CLAIM** - Blocked Beads, parent epics, and
  assigned-elsewhere Beads cannot produce `claim_ready`.
- **INV-VALAUTO-RCH-ONLY-CARGO** - Cargo-heavy commands must include
  `rch exec -- ...` when policy requires RCH.
- **INV-VALAUTO-FIRST-BLOCKER-PRESERVED** - Blocker-derived decisions preserve
  the exact first blocker string.
- **INV-VALAUTO-DRY-RUN-DEFAULT** - Default operation emits plans only and does
  not mutate Beads, Agent Mail, or files.
- **INV-VALAUTO-DEDUPE-BEFORE-CREATE** - New Bead proposals include overlap
  search terms and a dedupe rationale.
- **INV-VALAUTO-FRESHNESS-BOUNDED** - Stale tracker, mail, blocker, or RCH
  evidence cannot authorize mutation.
- **INV-VALAUTO-DETERMINISTIC** - Identical input and policy produce identical
  decision fields except `decision_id` and `decided_at`.

## Required Fixture Coverage

Follow-on implementation must include fixture coverage for:

1. ready Bead selected over all other planning actions;
2. `br ready` empty with only blocked parent/epic `bv` candidates;
3. stale blocked-Bead evidence requiring blocker refresh;
4. RCH timeout with retry budget remaining;
5. RCH product diagnostic with retry refused;
6. cross-repo external blocker requiring coordination;
7. malformed input failing closed;
8. proposed Bead dedupe terms present before create-followup output.

## Self-Test Plan

Before any implementation bead closes, its source-only checker must:

- parse every JSON example in this contract;
- assert every emitted `reason_code` and `event_code` is listed in the
  decision table;
- reject a cargo-heavy `recommended_command` that does not start with
  `rch exec --`;
- prove parent epics and blocked Beads never produce `claim_ready`;
- prove follow-up Bead proposals include `overlap_search_terms` and a dedupe
  rationale before any apply mode can be considered.

## Closeout Expectations

A Bead implementing this contract may close only after:

- the contract examples remain valid JSON;
- source-only tests cover the decision matrix and invariants;
- any cargo-heavy validation used for implementation runs through
  `rch exec -- ...`;
- Agent Mail receives a start and completion or blocker note;
- the close reason cites a commit or file:line and the exact validation
  commands.
