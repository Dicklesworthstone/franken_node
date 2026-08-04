# Runbook VAL-002: No-Ready Swarm Recovery

**Category**: validation_no_ready_swarm_recovery
**Severity**: Medium
**Estimated Recovery Time**: 15 minutes
**Required Permissions**: repo_write, agent_mail, beads_operator
**Operator Privilege Level**: P2
**Last Reviewed**: 2026-06-18
**Review Cadence**: per_release_cycle

## Purpose

Use this runbook when `br ready --json` returns no claimable Beads while `bv`
robot output still surfaces blocked epics, stale parent work, or external
blockers. The goal is to keep agents moving without hiding real blockers,
duplicating another agent's lane, or waiting in Agent Mail when useful work can
be created safely.

This runbook is about coordination and tracker hygiene. It does not make a
blocked issue unblocked, and it does not turn source-only evidence into green
Cargo proof. The validation-autopilot helper is a dry-run planner for this
runbook; it prints the next safe action and handoff text but does not mutate
Beads, Agent Mail, reservations, or files.

## Happy Path

1. Confirm the repo context and coordination state:

   ```bash
   git status --short
   br ready --json
   bv --recipe actionable --robot-plan
   bv --robot-priority
   bv --robot-insights
   ```

2. Refresh Agent Mail and active-agent awareness:

   ```text
   fetch_inbox(project_key=/data/projects/franken_node, agent_name=<agent>)
   list_agents(project_key=/data/projects/franken_node)
   ```

3. If `br ready --json` lists an open task, claim the highest useful task that
   is not owned by another active agent:

   ```bash
   br update <bead-id> --claim --actor <agent> --json
   ```

   Reserve the smallest edit surface in Agent Mail before editing, then send a
   `[<bead-id>] Start:` message in the Bead thread.

4. If `br ready --json` is empty, inspect `bv` output as advisory only. Confirm
   claimability with `br show <id> --json`; do not claim blocked parents or
   epics just because `bv` lists them.

5. Run the source-only helpers when they apply:

   ```bash
   python3 scripts/check_tracker_actionability.py --self-test --json
   python3 scripts/check_blocked_bead_freshness.py --self-test --json
   python3 scripts/normalize_rch_evidence.py --self-test --json
   ```

6. Run validation autopilot in dry-run mode after collecting the current
   tracker, graph, blocker, RCH, and Agent Mail evidence. The most auditable
   input is a complete `ValidationAutopilotInput` JSON file:

   ```bash
   python3 scripts/check_validation_autopilot.py --input <validation-autopilot-input.json> --json --now <utc-rfc3339>
   python3 scripts/check_validation_autopilot.py --input <validation-autopilot-input.json> --now <utc-rfc3339>
   ```

   For live triage, compose that input from:

   - `git status --short`;
   - `br ready --json` and `br show <id> --json` or `br list --json` issue
     records;
   - `bv --recipe actionable --robot-plan`, `bv --robot-priority`, and
     `bv --robot-insights`;
   - `scripts/check_tracker_actionability.py`,
     `scripts/check_blocked_bead_freshness.py`, and normalized RCH evidence;
   - Agent Mail inbox, active-agent names, and reservation-holder context.

   `--dry-run` is the default and only supported mode. `--apply` is reserved
   and must fail closed. Apply the printed Beads or Agent Mail actions manually
   only after checking ownership and reservations.

7. Choose one of the decision-boundary actions below, record the decision in
   Agent Mail, and then act immediately. Do not wait for acknowledgements unless
   another agent owns the same files or the message explicitly requires a reply.

## Decision Boundary

| Evidence | Next action | Do not do |
|---|---|---|
| `br ready --json` has a task and `br show` has no blocking dependency | Claim it, reserve files, announce start | Claim a broader parent epic |
| `bv` lists blocked items and `br ready --json` is empty | Refresh blocker evidence or create a narrow child Bead | Treat `bv` advisory output as claim permission |
| Blocker has fresh command, first error, owner, and timestamp | Leave it blocked and work elsewhere | Reopen or unblock without proof |
| Blocker is stale or incomplete | Add a Beads comment preserving exact command and first blocker | Replace the blocker with a vague summary |
| Existing Beads do not cover the obvious recovery work | Create a small task/test/doc Bead with dependencies | Do untracked work with no Bead |
| Agent Mail archive has stale/self ack artifacts only | Mention the artifact and proceed | Block progress on non-actionable mail state |
| Cargo, clippy, build, or test validation is needed | Run it through `rch exec -- ...` | Run bare local `cargo` |

## Failure Table

| Symptom | Required evidence | Safe response |
|---|---|---|
| `br update <id> --claim` fails with `cannot claim blocked issue` | Exact claim command and error text | Add or refresh a blocker comment; pick another ready task |
| `bv --recipe actionable --robot-plan` lists a blocked Bead | `br show <id> --json` status and dependencies | Treat the item as advisory; do not claim it |
| RCH proof stalls with fresh heartbeat and no output | Command, worker/job, first stale-progress line, cancellation state | Normalize with `scripts/normalize_rch_evidence.py` and record retry action |
| RCH reaches a Rust/cargo diagnostic | Exact diagnostic line and command | Classify as product work, not worker infrastructure |
| All useful existing work is blocked | Ready count, active agents, exact blockers, proposed child Bead | Create a narrow Bead and start it |
| File reservation conflict with active agent | Conflicting path, holder, expiry, and latest activity | Coordinate or choose a disjoint task |
| `check_validation_autopilot.py --apply` returns fail-closed | Exact stderr and exit code | Use dry-run output only; choose manual Beads or Agent Mail actions |
| Validation autopilot emits `VALAUTO_UNSAFE_LOCAL_CARGO` | Unsafe command text from the decision | Replace it with an explicit `rch exec -- ...` command before proceeding |
| Validation autopilot emits `VALAUTO_STALE_INPUT` | Generated-at timestamps and policy freshness window | Refresh tracker, `bv`, Agent Mail, reservation, and RCH evidence |

## Validation Autopilot Interpretation

Treat `scripts/check_validation_autopilot.py` as a source-only planner. Its
decision is advisory until the agent manually confirms the current tracker and
reservation state.

| Decision | Safe operator action |
|---|---|
| `claim_ready` | Confirm `br show <id> --json`, reserve the exact edit surface, claim with `br update <id> --claim --actor <agent> --json`, and announce start in Agent Mail. |
| `refresh_blocker` | Add a Beads comment preserving the exact command, timestamp, and first blocker string. Do not unblock unless fresh validation proves the blocker is gone. |
| `create_followup_bead` | Search the `overlap_search_terms`, then create only the narrow proposed child if no duplicate exists. |
| `retry_rch_bounded` | Run only the printed `rch exec -- ...` command if the retry budget, worker advice, and current reservations still allow it. |
| `coordinate_owner` | Send the generated handoff to the owner, reservation holder, or external project owner and wait only when that owner controls the same surface. |
| `handoff_only` | Preserve the handoff text in Agent Mail or Beads and choose unrelated ready work. |
| `blocked` | Repair the malformed, stale, missing, or unsafe input before taking any ownership-changing action. |

## Agent Mail Handoff Template

Send this to active agents before starting newly created recovery work or after
deciding that no existing Bead is claimable.

```markdown
`<thread-or-bead-id>` no-ready triage update from `<agent>`.

Snapshot:
- ready_count: `<count from br ready --json>`
- bv_command: `bv --recipe actionable --robot-plan`
- active_agents: `<agent names checked>`
- inbox_status: `<new messages or none>`
- worktree_status: `<git status --short summary>`

Blockers:
- `<bead-id>`: `<exact command or claim command>` -> `<first blocker string>`
- `<bead-id>`: `<external owner/repo/worker if applicable>`

Decision:
- next_action: `<claim-ready | refresh-blocker | create-child-bead | coordinate>`
- selected_bead: `<bead-id or none>`
- reserved_paths: `<paths or planned paths>`
- validation_policy: `cargo/build/test commands use rch exec -- ...`

I am proceeding with `<selected action>` now unless an active holder reports a
conflicting reservation or ownership issue.
```

## Closeout Requirements

Before closing a no-ready recovery Bead:

1. Beads status reflects the real state: claimed while working, closed only
   after the diff and validation are present.
2. Agent Mail has a start or decision note and a completion or blocker note.
3. File reservations are released after commit or explicit blocker recording.
4. Validation is scoped to touched files. Use source-only Python/doc checks for
   docs and scripts; use `rch exec -- cargo ...` for any Cargo-heavy work.
5. The close reason names the exact validation commands and the first external
   blocker if validation could not reach product diagnostics.
6. Validation-autopilot closeout cites the evidence pack below when the Bead
   depends on the planner:

   | Evidence | Required path or command |
   |---|---|
   | Contract | `docs/specs/validation_autopilot.md` |
   | Planner | `scripts/check_validation_autopilot.py` |
   | Focused tests | `tests/test_check_validation_autopilot.py` |
   | Transcript fixture | `tests/fixtures/validation_autopilot/transcript_cases.json` |
   | Semantic golden | `tests/golden/validation_autopilot/transcript_golden.json` |
   | Fixture provenance | `artifacts/validation_autopilot/bd-dy7vu/provenance.json` |
   | Syntax check | `python3 -m py_compile scripts/check_validation_autopilot.py tests/test_check_validation_autopilot.py` |
   | Focused unit gate | `python3 -m unittest tests.test_check_validation_autopilot` |
   | Planner self-test | `python3 scripts/check_validation_autopilot.py --self-test --json --now 2026-06-18T15:45:00+00:00` |
   | JSON fixture checks | `python3 -m json.tool <fixture-or-provenance-json>` |
   | Diff hygiene | `git diff --check` |

## Cross-References

- `AGENTS.md`
- `docs/runbooks/proof_lane_readiness_blockers.md`
- `docs/specs/validation_autopilot.md`
- `scripts/check_tracker_actionability.py`
- `scripts/check_blocked_bead_freshness.py`
- `scripts/normalize_rch_evidence.py`
- `scripts/check_validation_autopilot.py`
- `tests/fixtures/validation_autopilot/transcript_cases.json`
- `tests/golden/validation_autopilot/transcript_golden.json`
- `artifacts/validation_autopilot/bd-dy7vu/provenance.json`
- `bd-bc679`: tracker actionability checker
- `bd-8igw1`: blocked-bead freshness audit
- `bd-cucoo`: RCH evidence normalizer
- `bd-k599n`: validation-autopilot contract
- `bd-k4pg9`: validation-autopilot planner
- `bd-4gslh`: validation-autopilot RCH retry advice
- `bd-thge9`: validation-autopilot action previews and handoff text
- `bd-93z2i`: validation-autopilot dry-run handoff gate
- `bd-dy7vu`: validation-autopilot transcript fixture and golden pack
