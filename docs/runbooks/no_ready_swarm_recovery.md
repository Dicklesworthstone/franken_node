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
Cargo proof.

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

6. Choose one of the decision-boundary actions below, record the decision in
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

## Cross-References

- `AGENTS.md`
- `docs/runbooks/proof_lane_readiness_blockers.md`
- `docs/specs/validation_flight_recorder.md`
- `scripts/check_tracker_actionability.py`
- `scripts/check_blocked_bead_freshness.py`
- `scripts/normalize_rch_evidence.py`
- `bd-bc679`: tracker actionability checker
- `bd-8igw1`: blocked-bead freshness audit
- `bd-cucoo`: RCH evidence normalizer
