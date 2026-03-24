# AGENTS.md — franken_node

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Repository Reality Check (Authoritative)

This repository is **franken_node** (trust-native runtime platform), not the standalone `dcg` codebase.

- **Workspace layout:** Root `Cargo.toml` is a workspace manifest.
- **Primary crate path:** `crates/franken-node/`
- **Main Rust sources:** `crates/franken-node/src/`
- **Primary binary entrypoint:** `crates/franken-node/src/main.rs`
- **Primary library exports:** `crates/franken-node/src/lib.rs`

If any later section mentions legacy `dcg` paths like `src/main.rs` at repo root, treat this section and the on-disk tree as authoritative for implementation work in this repository.

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

> **Note:** This project exists specifically to block these dangerous commands for AI agents. Practice what we preach.

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**Why this matters:** Historical installer/docs links and raw GitHub URLs can still point at `master`. If `master` falls behind `main`, users get stale `franken_node` code or stale setup instructions.

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (the current tree does not pin a `rust-toolchain.toml`; use a compatible stable toolchain unless a specific task proves otherwise)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Workspace at root `Cargo.toml`, with primary crate under `crates/franken-node/`
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | Structured config, reports, bundle payloads, and CLI/API JSON |
| `toml` | Loading `franken_node.toml` and merge-layer configuration data |
| `clap` | CLI argument parsing for `init`, `run`, `migrate`, `verify`, `trust`, `fleet`, `incident`, `bench`, and `doctor` |
| `chrono` | RFC 3339 timestamps |
| `uuid` | Stable identifiers for bundles, operations, incidents, and receipts |
| `sha2` + `hmac` + `hkdf` | Hashing, signing helpers, and derivation material across trust/replay/capability surfaces |
| `ed25519-dalek` + `zeroize` + `serde_cbor` | Key material handling and signed/canonical payload support |
| `base64` + `hex` | Binary/text encoding for signatures, digests, and artifacts |
| `flate2` | Gzip compression for replay bundle chunking/export |
| `tokio` | Async runtime for MCP server mode |
| `tracing` + `tracing-subscriber` | Structured logging and diagnostics |
| `subtle` | Constant-time comparisons in security-sensitive paths |
| `tempfile` | Temp artifact handling in tests and validation paths |
| `frankenengine-engine` + `frankenengine-extension-host` | Sibling engine/runtime crates from `../franken_engine` |

### Release Profile

The current checked-in workspace manifest does **not** define a custom `[profile.release]`. Inspect the on-disk `Cargo.toml` files before making release-profile changes instead of assuming historical settings still apply.

### Feature Flags

```toml
[features]
extended-surfaces = [] # Expose broader product/API surfaces from the library build
test-support = []      # Enable testing-only helpers and modules
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
rch exec -- cargo check --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
rch exec -- cargo clippy --all-targets -- -D warnings

# Verify formatting
rch exec -- cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every module includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

The checked-in integration and end-to-end style coverage lives primarily in `crates/franken-node/tests/*.rs`, with additional Python/report gate tooling under `scripts/` and contract artifacts under `artifacts/` / `docs/`.

### Unit Tests

This repository is extremely test-heavy. There are thousands of Rust `#[test]` cases across inline module tests plus the standalone integration/conformance suite under `crates/franken-node/tests/`.

```bash
# Run all tests
rch exec -- cargo test -p frankenengine-node

# Run with output
rch exec -- cargo test -p frankenengine-node -- --nocapture

# Run representative focused suites
rch exec -- cargo test -p frankenengine-node doctor_policy_activation_e2e
rch exec -- cargo test -p frankenengine-node fleet_cli_e2e
rch exec -- cargo test -p frankenengine-node verify_release_cli_e2e
```

### End-to-End Testing

```bash
# Representative CLI/integration surfaces
rch exec -- cargo test -p frankenengine-node migrate_cli_e2e
rch exec -- cargo test -p frankenengine-node trust_cli_e2e
rch exec -- cargo test -p frankenengine-node fleet_cli_e2e
rch exec -- cargo test -p frankenengine-node verify_release_cli_e2e
```

### Test Categories

| Module | Tests | Purpose |
|--------|-------|---------|
| `doctor_policy_activation_e2e` | CLI/integration | Doctor output contract and policy-activation telemetry |
| `fleet_cli_e2e`, `trust_cli_e2e`, `migrate_cli_e2e`, `verify_release_cli_e2e` | CLI/integration | Product command surfaces and human/JSON output behavior |
| `control_lane_policy`, `control_epoch_validity`, `epoch_key_derivation` | Runtime/control-plane | Scheduling, epoch safety, and deterministic control invariants |
| `bayesian_risk_quarantine`, `ambient_authority_gate`, `adjacent_*_gate` | Policy/security | Risk gates, authority boundaries, and compatibility/policy contracts |
| `vef_*` suites | Verifier/evidence | Proof scheduling, proof services, adversarial and receipt integrity surfaces |
| `frankensqlite_adapter_conformance`, `frankentui_surface_migration` | Adapters/migration | Storage and surface migration conformance |
| Inline `#[cfg(test)]` modules across `src/**` | Unit/property-style | Local invariants for the domain module being edited |

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## franken_node Architecture Reference

This repository is `franken_node`, a product-layer Rust workspace over sibling `franken_engine`, not the older standalone tool previously described here.

### What It Does

`franken-node` is a trust-native JavaScript/TypeScript runtime platform. The product surface combines migration workflows, runtime and control-plane primitives, trust and supply-chain policy, fleet quarantine/release controls, replay and incident tooling, remote capability issuance, and verifier-facing evidence generation around the sibling `franken_engine` substrate.

### Workspace Shape

| Path | Purpose |
|------|---------|
| `Cargo.toml` | Workspace manifest for `crates/franken-node` and `sdk/verifier` |
| `crates/franken-node/src/main.rs` | Primary binary entrypoint and CLI dispatch |
| `crates/franken-node/src/lib.rs` | Primary library exports and feature-gated module surface |
| `crates/franken-node/src/cli.rs` | Command-line contract and subcommand definitions |
| `crates/franken-node/src/config.rs` | Config discovery, profile selection, and CLI override resolution |
| `sdk/verifier/src/lib.rs` | Small public verifier SDK crate |
| `crates/franken-node/tests/` | Broad integration, conformance, and CLI/e2e-style coverage |
| `docs/specs/`, `artifacts/`, `scripts/` | Product contracts, evidence, and gate/orchestration helpers |

### Architectural Shape

```
CLI / config / profiles
    -> domain modules in crates/franken-node/src/**
    -> runtime + control_plane + security + supply_chain + replay + remote
    -> receipts, trust cards, replay bundles, conformance evidence, and operator-facing output
```

### Key Entry Surfaces

| Surface | What Lives There |
|---------|------------------|
| `main.rs` | Top-level command execution for `init`, `run`, `migrate`, `verify`, `trust`, `remotecap`, `trust-card`, `fleet`, `incident`, `registry`, `bench`, and `doctor` |
| `lib.rs` | Domain exports such as `connector`, `control_plane`, `remote`, `runtime`, `security`, `supply_chain`, `storage`, `tools`, `replay`, and feature-gated API/policy/conformance surfaces |
| `cli.rs` | Stable CLI argument shapes and JSON/human output contracts that downstream tests assert |
| `config.rs` | Runtime profile and config loading, including local/dev/enterprise profile behavior |
| `sdk/verifier/src/lib.rs` | Public verifier-facing API kept smaller and more stable than the main product crate |

### Main Product Domains

| Domain | Representative Modules / Surfaces |
|--------|-----------------------------------|
| Migration | `migration`, `verify migration`, rewrite/rollback validation flows |
| Trust and supply chain | `supply_chain`, trust-card routes and registries, decision receipts, extension registry admission |
| Fleet control | `api/fleet_quarantine.rs`, `control_plane`, `runtime`, fleet status/reconcile/release commands |
| Replay and incidents | `replay`, `tools/replay_bundle.rs`, incident bundle generation and integrity validation |
| Runtime/control-plane primitives | `runtime`, `control_plane`, lane scheduling, epoch validity, profile-governed execution |
| Remote execution surfaces | `remote`, `security::remote_cap`, connector-facing capability and scope controls |
| Verifier/evidence surfaces | `verify` commands, `sdk/verifier`, conformance modules, receipts, artifacts, and specs |
| Observability and operations | `observability`, `ops`, `doctor`, benchmark and diagnostic tooling |

### Feature Flags and Packaging Reality

- `extended-surfaces` enables heavier product surfaces such as `api`, `claims`, `conformance`, `extensions`, `federation`, `policy`, `registry`, `sdk`, and `verifier_economy`.
- `test-support` enables shared testing helpers and harness-facing modules.
- Deployment/profile defaults live in `packaging/profiles.toml`, which currently defines `local`, `dev`, and `enterprise` profiles selected by `--profile <name>` or `FRANKEN_NODE_PROFILE`.

### Working Assumptions for Agents

- Treat `docs/specs/**`, `artifacts/**`, and `crates/franken-node/tests/**` as part of the product contract, not as optional documentation.
- When command output changes, update both human-readable and JSON-facing expectations in the relevant tests.
- Many flows depend on sibling `franken_engine` code and checked-in spec artifacts; inspect those inputs before assuming a bug is isolated to `franken_node`.
- Prefer editing the authoritative product module directly instead of building compatibility shims or wrapper layers.

---

## CI/CD Pipeline

The checked-in CI for this repository is gate-oriented and path-scoped. Do **not** assume an old monolithic `check` / `coverage` / `dist` pipeline exists here; the authoritative source is the live set of workflow files under `.github/workflows/`.

### Workflow Families

| Workflow family | Examples in this repo | Purpose |
|----------------|-----------------------|---------|
| Contract/change-summary gates | `no-contract-no-merge-gate.yml`, `change-summary-contract-gate.yml` | Ensure product changes carry the required contract/evidence narrative |
| Claim/evidence gates | `atc-claim-gate.yml`, `bpet-claim-gate.yml`, `dgis-claim-gate.yml`, `vef-claim-gate.yml` | Validate claim-specific artifacts and proofs |
| Replay/benchmark/vector gates | `replay-coverage-gate.yml`, `benchmark-correctness-artifacts-gate.yml`, `benchmark-specs-package-gate.yml`, `canonical-vector-gate.yml` | Check replay evidence, benchmark packages, and canonical vectors |
| Risk/reduction gates | `compatibility-threat-evidence-gate.yml`, `compromise-reduction-gate.yml`, `migration-velocity-gate.yml`, `rollback-command-gate.yml` | Enforce operational, compatibility, migration, and rollback safety contracts |
| Cross-substrate/conformance gates | `adjacent-substrate-gate.yml`, `asupersync-integration-gate.yml`, `connector-conformance.yml`, `independent-replication-gate.yml`, `proof-carrying-execution-ledger-gate.yml` | Validate connector behavior, replication, substrate compatibility, and ledger evidence |

### Representative Workflow Behavior

- `connector-conformance.yml` runs targeted Rust tests for `conformance::` and `connector::` plus Python gate scripts such as `check_connector_lifecycle.py` and `check_conformance_harness.py`.
- `replay-coverage-gate.yml` validates replay coverage artifacts and uploads the resulting JSON evidence.
- `no-contract-no-merge-gate.yml` diffs changed files, inspects labels, and enforces contract coverage via `scripts/check_no_contract_no_merge.py`.

### Local Verification Expectations

- Run formatting, `check`, `clippy`, and targeted Rust tests against touched surfaces.
- Per repository practice, send cargo-heavy work through `rch` rather than running local cargo directly.
- Reproduce any triggered Python gate script under `scripts/` and its companion tests under `tests/` when a workflow failure references artifacts or contract JSON.
- If you touched `docs/specs/**` or `artifacts/**`, verify the corresponding gate because these files are part of the product contract.

### Recommended Local Command Pattern

```bash
rch exec -- cargo fmt --check
rch exec -- cargo check --all-targets
rch exec -- cargo clippy --all-targets -- -D warnings
rch exec -- cargo test -p frankenengine-node <targeted-test-or-suite>
python3 scripts/<relevant-gate>.py --json
```

### Debugging CI Failures

1. Identify which workflow file in `.github/workflows/` fired for the changed paths.
2. Reproduce the exact Rust test target or Python gate script locally.
3. If the failure is artifact- or spec-driven, inspect `docs/specs/**`, `artifacts/**`, and sibling-repo inputs before patching code blindly.
4. If `rch` offload is part of the reproduction path, use `rch diagnose` and inspect sync roots, worker selection, and remote execution logs before assuming the product code is broken.

---

## Release Process

Do **not** assume historical release automation details still apply here. This checkout currently exposes product packaging and release-adjacent surfaces through:

- `Cargo.toml` versioning for the Rust workspace
- `packaging/profiles.toml` for `local`, `dev`, and `enterprise` packaging defaults
- README install channels such as the one-line installer URL and Homebrew tap
- `franken-node verify release` for release-directory checksum/signature verification

### Release Reality Check

- Before editing release docs or automation, inspect the live `.github/workflows/` directory and current tags rather than assuming a `release-automation.yml` or `dist.yml` pipeline exists.
- Before changing installer or packaging behavior, reconcile the README, `packaging/profiles.toml`, CLI flags, and any release verification tests.
- If a task requires publishing, keep `main` authoritative and sync `main:master` only because this repository still preserves `master` for legacy URL compatibility.

### Minimum Release Verification

```bash
rch exec -- cargo fmt --check
rch exec -- cargo clippy --all-targets -- -D warnings
rch exec -- cargo test -p frankenengine-node <relevant-release-tests>
franken-node verify release <release-dir> --json
```

### Common Release Pitfalls

- README/install instructions drifting away from actual packaged profiles or artifact layout
- Verifier/release checksums or signature expectations changing without corresponding test updates
- Assuming release asset names from another repository instead of checking the current `franken_node` contract

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Never run bare `bv` in agent sessions.** Bare `bv` launches an interactive TUI that blocks your session.

Use robot-mode flags only, and verify supported commands in your installed version:

```bash
bv --robot-help
```

### The Workflow: Start With Triage

Start with this sequence:
- `bv --recipe actionable --robot-plan` to get immediately actionable work tracks
- `bv --robot-priority` to detect priority/impact mismatches
- `bv --robot-insights` for deep graph bottleneck analysis

```bash
bv --recipe actionable --robot-plan
bv --robot-priority
bv --robot-insights
```

### Command Reference

**Planning & Priority:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |
| `--as-of <ref>` | Point-in-time graph view at a historical revision/date |

**Recipes & Reporting:**
| Command | Returns |
|---------|---------|
| `--robot-recipes` | Available built-in/user/project recipe names |
| `--recipe <name>` / `-r <name>` | Apply recipe prefilter before robot command |
| `--export-md <file>` | Markdown report export with Mermaid visualizations |

### Scoping & Filtering

```bash
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-plan         # Pre-filter: top PageRank
bv --diff-since HEAD~30 --robot-diff         # Graph delta since historical ref
```

### Understanding Robot Output

**`--robot-plan` output:**
- `tracks` — independent work streams safe for parallel execution
- `items` — actionable issues in each track
- `summary.highest_impact` — best first target

**`--robot-priority` output:**
- `recommendations` — may be `null` when no reprioritization is needed
- `summary` — total issues scanned and recommendation counts

**`--robot-insights` output:**
- `Bottlenecks` / `CriticalPath` / `Cycles` — structural blockers
- `Stats.PageRank` / `Stats.Betweenness` / `Stats.TopologicalOrder` — ranking + traversal signals

### jq Quick Reference

```bash
bv --recipe actionable --robot-plan | jq '.plan.summary'   # Action summary
bv --robot-priority | jq '.recommendations[0]'             # Top reprioritization suggestion
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.Bottlenecks[:5]'                # Top graph bottlenecks
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
bv --diff-since HEAD~30 --robot-diff | jq '.summary'       # Health trend and churn
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
Warning  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix hint -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of remote workers instead of building locally. This prevents compilation storms from overwhelming the shared machine when many agents run simultaneously.

**Use `rch exec -- ...` explicitly for cargo-heavy work in this repository.** Do not rely on implicit interception when the instruction is "all cargo builds/tests must go through `rch`."

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does fleet quarantine reconciliation work?" | `warp_grep` | Exploratory; need the cross-module flow before reading files manually |
| "Where is trust-card comparison implemented?" | `warp_grep` | Need to discover the authoritative module and call sites |
| "Find all uses of `Regex::new`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/data/projects/franken_node",
  query: "How do replay bundle generation and incident export fit together?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run `rch exec -- cargo test --all`.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurrence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
