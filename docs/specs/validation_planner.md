# Validation Planner Contract

**Bead:** bd-7ik2n
**Schema:** `franken-node/validation-planner/plan/v1`

## Purpose

The validation planner maps changed files and Beads acceptance text to the
smallest defensible validation plan. It emits exact commands for source-only
checks, Python contract gates, and RCH-backed Cargo checks, plus the gates it
intentionally skips and the conditions that require escalation.

The planner is not a green-light system. It is a deterministic command selector:
closeout evidence still comes from command output, validation broker receipts,
and RCH adapter classifications.

## Inputs

| Field | Description |
|-------|-------------|
| `bead_id` | Beads issue that owns the plan. |
| `thread_id` | Agent Mail thread, normally the same as `bead_id`. |
| `changed_paths` | Repo-relative changed files or sibling paths. |
| `labels` | Beads labels used as planning hints. |
| `acceptance` | Beads acceptance text used as planning context. |
| `registered_tests` | Structured `[[test]]` entries parsed from `crates/franken-node/Cargo.toml`. |
| `workspace_root` | Expected workspace root for rendered commands. |
| `package` | Cargo package, default `frankenengine-node`. |
| `cargo_toolchain` | Rust toolchain, default `nightly-2026-02-19`. |
| `target_dir` | Off-repo Cargo target directory. |

## Output Rules

- Every plan includes `git diff --check -- <changed-paths>` for the exact patch
  surface.
- JSON artifacts add `python3 -m json.tool <artifact>`.
- Validation broker docs or artifacts add
  `python3 scripts/check_validation_broker_contract.py --json`.
- Direct `crates/franken-node/tests/*.rs` changes map to the matching
  registered `--test <name>` target.
- Feature-gated `[[test]]` entries preserve `required-features` by emitting
  `--no-default-features --features <features>`.
- CLI entry surfaces start with `cli_arg_validation`; broader subcommand E2E
  targets require a specific changed test path or escalation.
- Sibling `franken_engine` paths add an RCH package check and require a sibling
  blocker bead if the failure remains outside `franken_node`.
- Docs and contract-artifact-only changes may be source-only when the relevant
  source-only and Python gates are present.

## RCH Command Shape

Cargo-heavy recommendations are rendered as:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PRIORITY=low \
  rch exec -- env \
  CARGO_TARGET_DIR=/data/tmp/franken_node-<bead>-validation-planner-target \
  CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  cargo +nightly-2026-02-19 <action> -p frankenengine-node ...
```

The plan carries both shell text and structured `env`/`argv` fields so later
broker code can consume the command without reparsing shell text.

## Skip Semantics

Skipped gates are part of the contract. A skipped broad gate must include a
reason such as:

- docs or contract artifacts only;
- a focused registered test covers the patch;
- a broad clippy/check pass should wait until focused proof fails or a shared
  API changes.

Closeout must not cite a skipped gate as passing evidence.

## Fixtures

Golden fixtures live at:

`artifacts/validation_broker/bd-7ik2n/validation_planner_fixtures.v1.json`

They cover:

- single registered test file changes;
- docs plus validation broker artifact changes;
- feature-gated integration tests;
- sibling dependency drift.

## Adaptive Shard Planner

**Schema:** `franken-node/validation-planner/shards/v1`

The shard planner consumes a `ValidationPlan` after command selection and groups
the commands into deterministic execution lanes. It does not mark validation as
passed. It decides whether each command should run now, wait, reuse proof, or
block because the required execution lane is unavailable.

Shard decisions consider:

- source-only, Python, proof-cache, and proof-coalescer commands as the local
  source lane;
- RCH cargo commands by target directory, so commands sharing a target directory
  are serialized rather than run concurrently;
- RCH queue state, including unavailable workers and saturated queues;
- proof-cache hits and proof-coalescer in-flight evidence;
- command budget limits for local source work and maximum parallel RCH shards.

Stable shard reason codes include:

- `VSP_SOURCE_ONLY_READY`;
- `VSP_SOURCE_LANE_SATURATED`;
- `VSP_PROOF_CACHE_HIT`;
- `VSP_PROOF_COALESCER_IN_FLIGHT`;
- `VSP_RCH_FOCUSED_READY`;
- `VSP_RCH_QUEUE_SATURATED`;
- `VSP_RCH_UNAVAILABLE`;
- `VSP_SHARED_TARGET_DIR_SERIALIZED`.

Every report includes a `decision_log` entry per planned command, with the
selected shard ID, reason code, and compact detail text suitable for Agent Mail
or Beads comments. A reused proof or ready shard is still only scheduling
evidence; closeout must cite the concrete proof receipt or command output.
