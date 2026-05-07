# Runbook VAL-001: Proof-Lane Readiness Blockers

**Category**: validation_proof_lane_readiness
**Severity**: High
**Estimated Recovery Time**: 20 minutes
**Required Permissions**: repo_write, agent_mail, rch_observer
**Operator Privilege Level**: P2
**Last Reviewed**: 2026-05-07
**Review Cadence**: per_release_cycle

## Purpose

Use this runbook when proof-lane readiness refuses to launch a cargo/RCH proof.
The goal is a deterministic source-only closeout record that future agents can
read without terminal history. A readiness capsule is not green validation
evidence; it only records why a proof lane was unsafe or unavailable.

This runbook covers the source-only blocker path for:

- `PLR_OVERRIDE_NOT_HONORED`
- `PLR_WORKER_AUTH_FAILED`
- `PLR_SAME_TOOLCHAIN_MISSING`
- `PLR_LOCAL_FALLBACK_REFUSED`

## Hard Rules

1. Do not run bare `cargo` in `franken_node`.
2. Do not accept local fallback as proof when remote cargo proof is required.
3. Do not rewrite product compile, test, clippy, or format failures as readiness
   infrastructure failures.
4. Do not claim a passing proof from generic `rch status` alone. The selected
   worker, toolchain, auth, capability, fallback policy, and freshness must
   match the readiness capsule.
5. If a source-only blocker is recorded, state whether cargo was launched. For
   this runbook the expected answer is `cargo_launched=false`.

## Detection

Start here when `franken-node ops validation-readiness` reports
`VR-PROOF-LANE-008` as `FAIL` or `WARN`, or when an agent observes that an RCH
proof would run on an invalid lane.

Required capsule fields:

| Field | Required evidence |
|---|---|
| `bead_id` | Owning Bead, also used as the Agent Mail thread. |
| `command.digest` | SHA-256 digest for the command that would have launched. |
| `worker_selection.requested_workers` | Explicit requested worker list, for example `ts2`. |
| `worker_selection.selected_worker` | Worker selected by dry-run or scheduler observation. |
| `toolchain.local_rustc` | Local Rust toolchain summary. |
| `toolchain.selected_worker_rustc` | Selected worker Rust toolchain summary, or `unknown`. |
| `worker_access.auth_status` | `ok`, `permission_denied`, `timeout`, `unreachable`, or `unknown`. |
| `worker_access.capability_status` | `fresh`, `stale`, `missing`, `malformed`, or `unknown`. |
| `decision.reason_code` | Stable `PLR_*` reason code. |
| `decision.required_action` | Next action before any retry can count as proof. |
| `freshness_expires_at` | Time after which the capsule cannot be cited. |
| `capsule_path` and digest | Repo-relative path and SHA-256 digest when the capsule is persisted. |
| `cargo_launched` | `false` for source-only blockers. |

## Evidence Collection

Collect evidence in this order. If a command is unsafe in the current
environment, record `not_run` and the reason instead of improvising.

1. Capture the live RCH control-plane state:

   ```bash
   rch status
   rch queue --json
   rch workers capabilities --json
   ```

2. Capture dry-run worker selection for the exact command. Preserve the
   requested worker environment and the selected worker:

   ```bash
   RCH_WORKER=ts2 rch diagnose --dry-run \
     "env RUSTUP_TOOLCHAIN=nightly cargo test -p frankenengine-node <target> -- --nocapture"
   ```

3. Capture a direct auth probe only when it is safe and non-mutating. Do not
   brute force credentials and do not change remote state:

   ```bash
   ssh -o BatchMode=yes -o ConnectTimeout=5 ubuntu@<worker-host> "echo ok"
   ```

4. Persist or cite the readiness capsule. If the capsule is checked in, record:

   ```text
   capsule_path=artifacts/validation_broker/<bead-id>/proof-lane/readiness.json
   capsule_digest=sha256:<64-hex-digest>
   freshness_expires_at=<RFC3339 UTC timestamp>
   ```

5. If the proof was not launched, do not run `rch exec -- cargo ...` just to
   satisfy a ritual. Record the source-only blocker in Beads and Agent Mail.

## Reason-Code Examples

### `PLR_OVERRIDE_NOT_HONORED`

Use this when an explicit worker request was ignored or the selected worker is
not in the requested worker set.

Required facts:

- `requested_worker=ts2`
- `selected_worker=<non-ts2-worker>`
- `selection_source=dry_run` or scheduler observation
- `override_effective=false`
- `required_action=fix_rch_worker_selection_or_use_valid_same_toolchain_worker`
- `cargo_launched=false`

Current blocker example: `bd-agpdg` recorded installed RCH dry-run selecting
`vmi1153651` while `RCH_WORKER=ts2` was requested. That cannot be counted as
green proof for a same-toolchain lane.

### `PLR_WORKER_AUTH_FAILED`

Use this when the requested or selected same-toolchain worker cannot be reached
with valid credentials.

Required facts:

- `auth_status=permission_denied`, `timeout`, or `unreachable`
- direct auth probe result when safe, for example
  `Permission denied (publickey,password)`
- capability freshness if available
- `required_action=repair_worker_credentials_before_retry`
- `cargo_launched=false`

Current blocker example: `bd-agpdg` recorded direct SSH to
`ubuntu@100.96.111.98` failing with `Permission denied (publickey,password)`.

### `PLR_SAME_TOOLCHAIN_MISSING`

Use this when no fresh worker capability observation proves the selected worker
has the required toolchain.

Required facts:

- `local_rustc=<local rustc summary>`
- `required_toolchain=<toolchain requested by the proof>`
- `selected_worker_rustc=unknown` or a non-matching rustc summary
- `capability_status=missing`, `stale`, or `malformed`
- `required_action=sync_toolchain_or_wait_for_matching_worker`
- `cargo_launched=false`

This reason is about the proof lane. It is not a product compile failure.

### `PLR_LOCAL_FALLBACK_REFUSED`

Use this when remote proof is required and RCH would fall open locally or cannot
select a remote worker.

Required facts:

- `rch.require_remote=true`
- `local_fallback_allowed=false`
- `local_fallback_refused=true`
- no valid selected remote worker
- `required_action=restore_remote_execution_before_cargo_proof`
- `cargo_launched=false`

If local fallback occurred, discard that output as validation proof and record
the fallback as the blocker.

## Source-Only Beads Comment Template

Use this template in `br comments add <bead-id> --message ...` before closing or
blocking a Bead with source-only evidence.

```text
Proof-lane readiness source-only blocker:
- bead_id: {bead_id}
- thread_id: {thread_id}
- command_digest: sha256:{command_digest}
- command_summary: {program_and_args}
- requested_worker: {requested_worker}
- selected_worker: {selected_worker_or_none}
- local_toolchain: {local_rustc_or_toolchain}
- worker_toolchain: {worker_rustc_or_unknown}
- auth_status: {auth_status}
- capability_status: {capability_status}
- pressure_status: {pressure_status}
- reason_code: {reason_code}
- event_code: {event_code}
- required_action: {required_action}
- capsule_path: {repo_relative_capsule_path_or_not_persisted}
- capsule_digest: sha256:{capsule_digest_or_not_persisted}
- freshness_expires_at: {freshness_expires_at}
- cargo_launched: false
- product_failure_observed: false
- operator_summary: {bounded_summary}
```

Close reason suffix:

```text
source-only proof-lane blocker: reason_code={reason_code} required_action={required_action} capsule={capsule_path} cargo_launched=false
```

## Agent Mail Template

Send this in the Bead thread after the Beads comment is recorded.

```markdown
`{bead_id}` is source-only blocked by proof-lane readiness.

Evidence:
- command_digest: `sha256:{command_digest}`
- requested_worker: `{requested_worker}`
- selected_worker: `{selected_worker_or_none}`
- local_toolchain: `{local_rustc_or_toolchain}`
- worker_toolchain: `{worker_rustc_or_unknown}`
- auth_status: `{auth_status}`
- capability_status: `{capability_status}`
- reason_code: `{reason_code}`
- event_code: `{event_code}`
- required_action: `{required_action}`
- capsule_path: `{repo_relative_capsule_path_or_not_persisted}`
- capsule_digest: `sha256:{capsule_digest_or_not_persisted}`
- freshness_expires_at: `{freshness_expires_at}`
- cargo_launched: `false`

No cargo proof was launched. This is not product-green evidence.
```

## Verification Before Closeout

Before closing a runbook-only Bead, verify:

1. `git diff --check` passes.
2. Any touched runbook index or link checker passes.
3. Beads has a comment with the source-only blocker fields.
4. Agent Mail has a thread update with the same fields.
5. If a capsule was persisted, its path is repo-relative and its digest is
   SHA-256.
6. The freshness timestamp is still valid at closeout time. If not, regenerate
   or record `PLR_STALE_READINESS_CAPSULE`.

Cargo is not required for this runbook unless implementation code changes. If
cargo validation is required, it must run through `rch exec --`.

## Cross-References

- `docs/specs/proof_lane_readiness.md`
- `docs/specs/validation_readiness.md`
- `docs/runbooks/proof_pipeline_outage.md`
- `artifacts/validation_broker/bd-yyl6t/proof_lane_readiness_fixtures.v1.json`
- `crates/franken-node/src/ops/validation_readiness.rs`
- `crates/franken-node/src/ops/validation_broker.rs`
- `crates/franken-node/src/ops/validation_closeout.rs`
- `bd-yyl6t`: proof-lane readiness and credential drift capsule epic
- `bd-yyl6t.1`: capsule schema and reason taxonomy
- `bd-yyl6t.2`: deterministic classifier
- `bd-yyl6t.3`: fixture and golden replay catalog
- `bd-yyl6t.4`: validation broker and flight-recorder closeout refs
- `bd-yyl6t.5`: readiness JSON and human output surfacing
- `bd-agpdg`: RCH remote execution stall and ts2 readiness blocker
- `bd-p9mpd`: workspace artifact cache and build-pressure governor epic
