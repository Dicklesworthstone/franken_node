# Reality Check and Bridge Plan: franken_node

**Reality check date:** 2026-08-20
**Follow-up (2026-08-21):** scoreboard bound to corpus 86.43% RED; `run` e2e written; installer/CLI/revocation/10x-equal-attempts honesty landed. 95% corpus still open (`bd-28sz`: 76 remaining). Need 48 more passes (532/560). Do **not** recategorize `child_process` deny as pass. Residual mix: `child_process` 30 native-eval aborts (exit 1, 0 stdout); `crypto` 13 / `stream` 12 / `zlib` 3 / `tls` 5 / `cluster` 2 mostly franken-engine crash (exit 1); `events::0022` is franken_engine missing arrow lexical-`this` (29 vs 30 bytes: `arrow-this:true` vs node/bun `false`); `net::0005`/`net::0024` are **node vs bun reference disagreement** (franken matches node). Orchestrator cadence locked at **4 minutes**. Spawn note: signed Bubblewrap + aliases were already in the 2026-08-20 measurement (`e22e89fc4` ancestor of `cbc7a7bfb`). The 30 distinct stderr digests are the CLI wrapper plus **fixture filename** (`Engine execution failed… fix_command=…/<case>.js`), not 30 policy texts. Length bands ≈ 181/198/208 + filename. Guest JS never ran `console.log`. Product already grants `process_spawn` when admission is present (`resolve_capabilities_for_execution`) and maps spawnSync failures to a result object — so the measured abort is **before** that object is returned (HostCall `?` on `process_spawn`, capability/IFC/attempt, or facade holes: `stdin` is `Undefined`, `pid` hardcoded 1). PATH skip-insecure is landed; it does not recategorize deny as pass. Next honest engine cut: do not `?` `dispatch_process_spawn_hostcall` out of the eval (`baseline_interpreter.rs:41072-41073`); route HostProcess like builtins so spawnSync can return `{error}` and execSync `try/catch` can catch.
**Git HEAD:** `f74fa63b7` (`v0.1.0-709-gf74fa63b7`)
**Shipped GitHub release:** `v0.1.0` (2026-05-29) — **709 commits behind HEAD**
**PATH binary probed:** `/home/ubuntu/.local/bin/franken-node` (26 MB, BuildID `a3d9be2d`, dated 2026-06-08)
**Beads at check:** 4317 issues in `.beads/issues.jsonl` — 4269 closed / 13 open / 9 in_progress / 5 blocked (~98.8% closed)
**Method:** README + AGENTS.md + PRODUCT_CHARTER + PLAN_TO_CREATE_FRANKEN_NODE + CLAIMS_REGISTRY as the measuring stick; `crates/franken-node/src/**`, live CLI, oracle artifacts, and remaining beads as ground truth.

This document is the single in-place artifact for this reality check. Later ambition/refinement rounds revise this file; they do not spawn sibling plan docs.

---

## Executive answer

franken_node is a **real, large, fail-closed product-layer codebase** sitting on sibling `franken_engine`. It is **not** delivering the charter’s category-creation floor.

What exists today is an **evidence-producing operator shell**: trust cards, revocation gates, signed receipts, incident bundle integrity, local fleet state machines, a verifier SDK, a tree-sitter migration pipeline, and a native `run` path that *can* execute JS through franken_engine when the engine feature is present. That is substantial software.

What the README and charter use to claim a new runtime category is **not closed**:

| Charter floor | Reality on 2026-08-20 |
|---|---|
| ≥95% targeted compatibility corpus | Close-condition receipt: **2.5% (14/560)**. `artifacts/compat/corpus_pass.json` still `pending` with `observed_pct: null`. Bead `bd-28sz` is still **open**. |
| ≥3× migration throughput/confidence | Pipeline exists. The checked-in “3.15×” report is a **constructed 10-project cohort from 2026-02-21**, not a live measured gate. `CLAIM-002` is **pending**. Bead `bd-3agp` was **closed**. |
| ≥10× host-compromise reduction | Adversarial harness + `artifacts/13/compromise_reduction_report.json` exist; bead `bd-3cpa` is still **open**. Not an independently audited production campaign. |
| 100% deterministic replay for high-severity incidents | **Conformance-level integrity replay of recorded traces is real.** Live JS re-execution is explicitly *not* what `incident replay` does (README Limitations). |
| ≥3 impossible-by-default capabilities adopted by production users | **Zero production users** (AGENTS.md: early development, no users). Bead `bd-2hrg` was **closed with reason `done`**. |
| Dual-oracle close condition all GREEN | **Contradictory artifacts.** `close_condition_receipt.json` L1=**RED** (2.5%). `l1_product_verdict.json` L1=**GREEN** from a 3-effect proof-carrying chain, not the corpus. L2/release_policy GREEN files were **backfilled 2026-05-21** by a previous reality-check. |
| Install → first safe JS workload | `init` works. `doctor` runs. The probed PATH binary **refused `run ./app.js`** with `trust-native runtime unavailable` unless `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK=1`. Bead `bd-34d5` is still **open**. |

**Bead-completion illusion:** closing the remaining 27 open/in_progress/blocked beads would move the *tracked* charter gates if they are implemented honestly. It would **not** close the vision. Several load-bearing charter beads are already closed (`bd-2hrg`, `bd-1ps`, `bd-2tua`, `bd-26ux`, `bd-3agp`, `bd-1oyt`) while the corresponding product reality is still a model, a pending claim, or a contradictory artifact.

---

## Source documents (the promise)

| Document | Role |
|---|---|
| `README.md` (3330 lines) | Public operator promise: trust-native JS/TS runtime, installer, CLI, primitives, honesty manifest |
| `docs/PRODUCT_CHARTER.md` | Scope, 10 IBD capabilities, success metrics, substrate non-negotiables |
| `docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md` | Canonical ambition plan (22 tracks) |
| `docs/ROADMAP.md` | Supporting summary; engine-heavy; Phase 0 “in progress” |
| `docs/CLAIMS_REGISTRY.md` | Explicit pending vs verified claims (backfilled 2026-05-20) |
| `docs/honesty_manifest.json` | Census of test/fuzz/validator *counts*, not charter KPIs |
| `AGENTS.md` | Workspace/layout/process; confirms no-users, default features, rch, beads |

README Limitations (L3126–3170) is more honest than the Comparison table. The gap analysis treats **both** as part of the promise, and flags where they disagree.

---

## Architecture (what the code actually is)

```
CLI (crates/franken-node/src/main.rs, ~29k lines, #[cfg(not(test))])
  → Config::resolve (CLI > env > profile TOML > defaults)
  → domain modules in crates/franken-node/src/**
  → optional native franken_engine session (ops::engine_dispatcher)
  → signed receipts / trust-card JSON / replay bundles / run receipts
  → JSON or frankentui::Buffer-wrapped human text
```

**Workspace:** `crates/franken-node` (product), `crates/franken-security-macros`, `sdk/verifier`.

**Default features:** `engine` + `http-client` + `external-commands` only. Library modules `api`, `claims`, `federation`, `registry`, `verifier_economy`, `migration` (lib), `extensions` are feature-gated. The **binary still lists the whole CLI tree**; it `#[path]`-includes a subset of `api`/`policy`/`security` so default `franken-node` is usable without `--features extended-surfaces`.

**Core types:** `Config`/`Profile`, `TrustCard`, `Receipt`/`SignedReceipt`, `ControlEpoch`, `RemoteCap`, `ReplayBundle`, `EffectReceipt`, connector FSM.

**Substrate honesty vs charter §4:**

| Substrate (charter: mandatory) | Code reality |
|---|---|
| `franken_engine` | **Real, default-on** path deps. Native `run` uses `ExecutionOrchestrator`. |
| `asupersync` Cx-first control | **Optional** `asupersync-transport`. Default fleet transport is **file JSONL**. Product `run` is sync threads/processes. |
| `frankensqlite` for durable state | **In-memory adapter model** (`storage/frankensqlite_adapter.rs:1-6`). Live state is JSON/JSONL under `.franken-node/state/`. `fsqlite` is a **dev-dependency**. Beads `bd-2tua`/`bd-26ux` **closed**. |
| `frankentui` as console substrate | **Cosmetic:** copy already-rendered lines into `frankentui::Buffer` and read them back (`main.rs` `render_operator_surface_with_frankentui`). Not an interactive TUI. |
| `fastapi_rust` for HTTP control plane | **Dev-only.** `api/service.rs` is an in-process catalog; **does not bind a socket**. |

---

## Vision checklist

Status key: `WORKING` / `PARTIAL` / `STUB` / `UNPROVEN` / `NOT_STARTED` / `REGRESSED` / `WRONG_APPROACH`. Bead coverage is against **currently open/in_progress/blocked** beads, not historically closed ones.

| # | Goal | Source | Priority | Status | Bead coverage | Evidence |
|---|------|--------|----------|--------|---------------|----------|
| V1 | Trust-native JS/TS runtime that executes guest JS under policy | README TL;DR, Limitations L3153 | Core | PARTIAL | `bd-f5b04` (TNR epic, open) | Current source: `EngineDispatcher::dispatch_run` native path. PATH `v0.1.0` binary: `run ./app.js` failed closed (`trust-native runtime unavailable`). Host-effect runtime-of-record still incomplete. |
| V2 | Revocation-first execution before risky actions | README L109, CLAIM-006 | Core | PARTIAL | none remaining (impl exists) | Real modules `revocation_freshness` **and** `revocation_freshness_gate` with **two incompatible SafetyTier models**. |
| V3 | Per-extension trust cards (provenance, camouflage, revocation) | README L128, IBD-06 | Core | WORKING | none remaining | `supply_chain::trust_card`; live `init` wrote `trust-card-registry.v1.json`; CLAIM-005 verified. JSON files, not SQLite. |
| V4 | Deterministic incident replay + counterfactual | README L114–116, IBD-04 | Core | PARTIAL | none remaining for integrity; TNR for live re-exec | Integrity replay is load-bearing. Counterfactual default executor is **synthetic**. README admits this. |
| V5 | Migration autopilot audit→rewrite→validate→rollout | README L117, IBD-02 | Core | PARTIAL | no open 3× gate (`bd-3agp` closed) | Real CLI + tree-sitter. Not autonomous fleet rollout. 3× number is a constructed cohort. |
| V6 | Lockstep compatibility oracle ≥95% targeted corpus | Charter §5, IBD-07, `bd-28sz` | Core | UNPROVEN / far from target | `bd-28sz`, `bd-2djfa`, corpus residuals | Close-condition 2.5%. corpus_pass.json pending. Lockstep harness needs `strace` + Node/Bun. |
| V7 | Fleet quarantine with bounded convergence | README L136, IBD-05 | Important | PARTIAL | none remaining | Real SM + signed receipts over **local file transport**. Not a live multi-node HTTP/asupersync mesh unless opted in. |
| V8 | Signed extension registry (Ed25519 + provenance) | README L137, CLAIM-009 | Important | WORKING (local) | none remaining | Local FS registry. Not a public ecosystem registry. |
| V9 | Remote capability tokens | README L138 | Important | WORKING (local) | none remaining | Real Ed25519 tokens; local revoke set, not a remote cap service. |
| V10 | Verifier SDK independent of producer | README L139, IBD-10 | Core | PARTIAL | none remaining | Real crate; verifies artifacts, not guest JS / ZK. Honesty signer is harness key; `generated_at` is Unix epoch. |
| V11 | Operator doctor + workspace pressure | README L139 | Important | WORKING | none remaining | Live doctor after `init`: 9 pass / 1 warn / 1 fail (workspace pressure CRITICAL + RCH unavailable). |
| V12 | VEF / ATC / DGIS / BPET as production differentiators | README primitives table | Important | PARTIAL | residuals under TNR/compat | Real in-process models. ATC `atc/mod.rs` is a name fingerprint; VEF uses SHA-256 attestation backends (“future ZK”). |
| V13 | SSRF/egress policy as runtime default | README Network Egress | Important | WORKING on native `run` | `bd-y4t2i` crypto/egress residuals | Load-bearing `ssrf_gated_host_io` on engine host I/O. |
| V14 | Child-process spawn impossible-by-default + Bubblewrap | README Runtime Profiles | Important | PARTIAL | `bd-91tpy`, `bd-at11s` | Real signed opt-in. Linux-only. PATH binary process-spawn-readiness exists. |
| V15 | No `unsafe` | README L141 | Core | WORKING | honesty manifest | `#![forbid(unsafe_code)]`; honesty `unsafe_blocks=0`. |
| V16 | ≥3× migration velocity vs baseline | Charter §5, CLAIM-002 | Core | MEASURED 2.30×, PENDING | `bd-reality-20260820-w0fc6.2` (live gate landed) | Live signed gate (`artifacts/migration/throughput_delta.json`, target-release, 2026-08-22): pooled median 2.30x, CI95 [1.90x, 3.30x] — below 3x. Constructed `bd-3agp` cohort rejected by the gate. |
| V17 | ≥10× compromise reduction | Charter §5, CLAIM-003 | Core | UNPROVEN | `bd-3cpa` open | Report exists; gate bead still open. Not production-campaign evidence. |
| V18 | ≥2 independent replications | Charter / `bd-whxp` | Important | NOT_STARTED | `bd-whxp` open | Still ready-work. |
| V19 | Friction-minimized install → first safe production | Charter §5, `bd-34d5` | Core | PARTIAL | `bd-34d5` open | Installer exists. Homebrew unpublished (README honest). Shipped binary 709 commits stale. Live `run` failed without engine/fallback. |
| V20 | Dual-oracle close GREEN (L1 ∧ L2 ∧ release policy) | Charter §7, README Close-Condition | Core | WRONG_APPROACH (artifact theater) | `bd-1oyt` closed; `bd-3c2ie` exists as test drift | Conflicting GREEN/RED artifacts. L1 GREEN is not the corpus. |
| V21 | asupersync Cx-first for high-impact async | Charter §4 | Important | STUB/optional | no remaining bead | Optional feature; default file transport. |
| V22 | frankensqlite as the durable store | Charter §4 | Important | STUB | **NO open bead** (`bd-2tua`/`bd-26ux` closed `done`) | Adapter header says not the live store. |
| V23 | fastapi_rust live HTTP control plane | Charter §4 | Nice-to-have vs README fleet | NOT_STARTED | no remaining bead | In-process catalog only. |
| V24 | frankentui as operator surface | Charter §4 | Nice-to-have | STUB | `bd-e16uf` clippy blocker only | Buffer round-trip. |
| V25 | Public installer + current release | README Installation | Core | PARTIAL / REGRESSED vs HEAD | **NO open bead** | `v0.1.0` is Latest; HEAD is +709. PATH binary lacks `ltv`. Absolute `--out-dir` rejected. |
| V26 | CLI command surface matches README and does real work | README Command Reference | Important | PARTIAL | **NO open bead for honesty** | No `todo!()`. README now labels `verify module` as crate-src (not guest JS), `runtime lane/epoch` as ephemeral, `proofs workers restart` as request-unless-`--execute`, `ops health-check` as persisted session files. Remaining thin: live HTTP fleet (`activated:false` on file transport) and substrate stubs (frankensqlite/fastapi/frankentui). |
| V27 | Effective test coverage (not raw count) | README Testing, honesty manifest | Important | PARTIAL | `bd-rjc2m.21` in_progress; `bd-o776s` | ~3.8k default cargo tests. ~21k inline tests compiled **out** of default `cargo test`. |
| V28 | ≥3 IBD capabilities in production use | Charter §5 | Core | NOT_STARTED | **NO open bead** (`bd-2hrg` closed `done`) | No users. |

**Vision delivery (strict):** **3 of 28** fully `WORKING` (V3 trust cards, V11 doctor, V15 no-unsafe). Several more are `WORKING` at *local-library* fidelity but not at the charter’s production meaning.

---

## Live software probes (this session)

### PATH binary (`franken-node 0.1.0`, June 8 2026)

1. `franken-node --help` — full command tree **except `ltv`** (present in current `cli.rs`, absent from this binary).
2. `franken-node doctor --json` in empty cwd — fail-closed: `trust.registry_signing_key must be configured`.
3. `franken-node init --profile balanced --json --out-dir ws` (relative) — **success**. Wrote `franken_node.toml`, state dirs, synthesized registry signing key + API key, created `trust-card-registry.v1.json`.
4. `franken-node doctor --json` in that workspace — `overall_status=fail` (workspace pressure CRITICAL; RCH unavailable; bench summary missing). Config resolve **passed**.
5. `franken-node run ./app.js --policy balanced --json` with `console.log(...)` — preflight skipped (no package.json), then:
   ```
   Error: trust-native runtime unavailable: auto-mode fallback to node/bun requires
   explicit reduced-guarantee opt-in via FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK=1
   ```
   **No JS executed.**
6. `franken-node ltv --help` — `unrecognized subcommand`.
7. Absolute `--out-dir /tmp/...` — rejected (`Absolute paths not allowed for user content`).

### Source vs shipped

- GitHub Latest release = `v0.1.0` (2026-05-29).
- `git rev-list --count v0.1.0..HEAD` = **709**.
- One-line installer therefore cannot deliver current `run`/LTV/`--compat-preflight` behavior.

---

## Artifact theater (must not be treated as GREEN)

| Artifact | What it says | What’s wrong |
|---|---|---|
| `artifacts/oracle/l1_product_verdict.json` | L1 **GREEN**, 1538 tests passed (2026-07-12) | Evidence is 3 proof-carrying host effects (`fs.read`/`fs.write`/`http.request`), **not** the compatibility corpus. |
| `artifacts/oracle/close_condition_receipt.json` | L1 **RED**, 14/560 = 2.5% (2026-07-12) | This is the honest corpus number. Contradicts the GREEN file above. |
| `artifacts/oracle/l2_engine_verdict.json` | GREEN, 266 tests | Notes: created 2026-05-21 as README alias; timestamp `2026-05-21T00:00:00Z`. |
| `artifacts/oracle/release_policy_verdict.json` | GREEN | Notes: **“Backfilled 2026-05-21 from the reality-check bridge plan.”** |
| `artifacts/compat/corpus_pass.json` | `verdict: pending`, `observed_pct: null` | Still the May 21 backfill. Charter metric has no signed observed rate. |
| `artifacts/13/migration_velocity_report.json` | 3.15× on 10 archetypes | Constructed cohort timestamps in Feb 2026; CLAIM-002 still pending. |
| `docs/honesty_manifest.json` | Counts match README ±tolerance | Does **not** attest 95%/3×/10×. `generated_at` is `1970-01-01`. Signer is harness key. |

Previous reality-check (2026-05-20/21) made the gap *visible* in CLAIMS_REGISTRY and then **backfilled GREEN-looking oracle files**. That is the failure mode this skill exists to catch.

---

## Remaining beads vs vision (would completing them close it?)

**Currently incomplete (open / in_progress / blocked): 27.** Ready set includes the actual charter KPIs that were *not* false-closed:

| Bead | Tracks |
|---|---|
| `bd-28sz` | ≥95% compat |
| `bd-3cpa` | ≥10× compromise |
| `bd-whxp` | ≥2 independent replications |
| `bd-34d5` | install → first safe production |
| `bd-f5b04` | TNR runtime-of-record |
| `bd-2djfa` | lockstep executable + release-gated |
| `bd-y4t2i`, `bd-at11s`, `bd-zyp0c`, `bd-m8vaa.1`, `bd-387cw`, `bd-sul35` | corpus family residuals |
| `bd-rjc2m*` | verification scaffolding / inline tests / e2e |
| `bd-gc0ze`, `bd-famte`, `bd-pnmnu` | RCH/clippy/fmt farm health |

**If those 27 were implemented honestly:** V6, V17, V18, V19, V1 (TNR), V27 (inline tests) would get *a chance* to close. Compat residuals would raise the 2.5% floor; they would not magically hit 95% unless `bd-28sz` is treated as a hard release gate rather than another closed-with-artifact event.

**Would not close even if all 27 finish:**

| Gap | Why remaining beads don’t cover it |
|---|---|
| V16 3× migration | `bd-3agp` already closed |
| V20 dual-oracle contradiction | `bd-1oyt` closed; GREEN files are backfills |
| V22 frankensqlite live store | `bd-2tua`/`bd-26ux` closed `done` while adapter is in-memory |
| V21 asupersync default | optional feature, no remaining bead |
| V23 fastapi HTTP | not started; no remaining bead |
| V25 current release / installer freshness | no remaining bead |
| V26 CLI honesty (thin commands) | no remaining bead |
| V28 production IBD adoption | `bd-2hrg` closed `done`; no users |
| Dual revocation-tier models | no remaining bead |

**False-closed load-bearing beads (close_reason `done` or equivalent):** `bd-2hrg`, `bd-1ps`, `bd-2tua`, `bd-26ux`. `bd-3agp` has a longer close_reason citing artifacts that CLAIMS_REGISTRY still calls pending.

---

## CLI honesty (default binary, current source)

Every README family is in clap and dispatched. Zero `todo!()` / `unimplemented!()` in `src/`. The lie is **kind of work**, not missing handlers.

| Family | Verdict |
|---|---|
| `init`, `run` (engine), `doctor*`, `migrate*`, `trust*`, `remotecap`, `fleet` (file transport), `incident*`, `ltv*` (HEAD), `registry*`, `bench run`, `debug explain/evidence/trace` | Real local implementations + e2e in various feature sets |
| `verify lockstep`, `verify release`, `verify corpus` | Real |
| `verify module` | Looks up **this crate’s** `src/` module ids. Not JS module conformance |
| `verify compatibility` | Profile name parse **auto-PASS** |
| `runtime lane status/assign` | Fresh in-memory scheduler; discarded |
| `runtime epoch` | Two `u64` compare; not `ControlEpoch` |
| `proofs workers restart` | Emits `dispatch_restart_to_deployment_supervisor`; restarts nothing |
| `proofs queue status` | Snapshot/receipt report, not a live queue |
| `ops health-check` | New empty `SessionManager` → `active_session_count=0`; `pass` depends on compile-time git sha + ledger file |
| `trust scan --json` | Flag accepted, ignored |

Fleet/proofs/control-plane commands are **local-file or snapshot tools**. Implemented, not distributed SaaS.

---

## Gap report (actionable)

### Critical (vision undeliverable without these)

**G1 — Compatibility corpus far below 95% (V6)**
- Promise: Charter §5; README lockstep story.
- Reality: 2.5% in close-condition receipt; corpus_pass pending.
- Beads: `bd-28sz`, `bd-2djfa`, family residuals. **Partially covered.**
- Close condition: a **new** signed `artifacts/compat/corpus_pass.json` with `observed_pct >= 95` from a lockstep run that actually executed Bun + franken-engine (Node opt-in when real), plus release gate that fails closed on RED. Must **overwrite** the contradictory L1 GREEN file or stop treating it as the close-condition input.

**G2 — `run` is not a working “first JS workload” on the shipped path (V1, V19)**
- Promise: Quick Example step 7; Charter install-to-safe-workload.
- Reality: PATH binary cannot execute `app.js` without degraded fallback. TNR epic still open.
- Beads: `bd-f5b04`, `bd-34d5` cover product work; **no bead covers installer/release freshness**.
- Close condition: `franken-node run` on a machine that followed README install executes a fixture JS file through franken_engine, prints stdout, writes a run receipt, exit 0 — without `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK`.

**G3 — Dual-oracle artifacts disagree; GREEN files are not the corpus (V20)**
- Promise: README Close-Condition; `doctor close-condition`.
- Reality: RED 2.5% vs GREEN 3-effect chain vs May 21 backfills.
- Beads: **NO_BEAD** (gate bead closed).
- Close condition: one conjunctive receipt; L1 **must** be the corpus metric; any GREEN L1 without `observed_pct` is a gate failure.

**G4 — Category metrics 3× / 10× / production IBD (V16, V17, V28)**
- 3×: closed bead + constructed cohort + pending claim.
- 10×: open bead + harness artifacts; not an external replication.
- Production IBD: closed `done`, zero users.
- Close condition: live measured gates with Wilson intervals (honesty manifest already has the interval helper) and fail-closed CI. No constructed archetypes.

### Major

**G5 — frankensqlite not the live store (V22)** — false-closed `bd-2tua`/`bd-26ux`. Trust/fleet/evidence still JSON.

**G6 — asupersync not the control substrate (V21)** — charter non-negotiable, optional feature.

**G7 — CLI / README mismatches (V26)** — thin commands listed as first-class operator tools.

**G8 — Dual revocation freshness models (V2)** — two enums, two clocks (seconds vs epochs).

**G9 — Default cargo test hides ~21k inline tests (V27)** — `bd-rjc2m.21` already tracks this.

**G10 — Release channel stale (V25)** — installer → v0.1.0; HEAD +709; no `ltv` on PATH binary.

### Minor / polish

**G11 — frankentui Buffer round-trip.** **G12 — fastapi not a server.** **G13 — Homebrew unpublished (README already honest).** **G14 — ATC module is a fingerprint.** **G15 — VEF is hash attestation, not ZK.**

---

## Bridge plan (close every gap)

Priority is **vision impact**, not ease.

### Gap #1: Compatibility floor — PARTIAL → WORKING

**Current:** 2.5% corpus; pending artifact; lockstep needs strace; L1 GREEN file is the wrong metric.
**Target:** Targeted high-value Node/Bun bands ≥95% on the lockstep oracle; `corpus_pass.json` has a real `observed_pct`; close-condition L1 reads that file only.
**Success criteria:**
- [ ] `franken-node verify lockstep` (or `ops compat-corpus-run`) produces a signed corpus result consumed by `scripts/check_compatibility_corpus_pass_gate.py`
- [ ] `artifacts/compat/corpus_pass.json` `verdict` is GREEN or honestly RED with `observed_pct` set
- [ ] `l1_product_verdict.json` cannot be GREEN while corpus < 95%
- [ ] Residual family beads (`bd-y4t2i` etc.) are either closed with passing families or explicitly excluded from the “targeted” denominator with a published exclusion list
**Depends on:** `bd-2djfa`, engine corpus work, `bd-28sz`.
**Would existing beads close it?** Partially. Need a new bead to **kill L1 artifact contradiction** (Gap #3).
**Complexity:** XL

### Gap #2: Install → `run` JS — PARTIAL → WORKING

**Current:** `init`/`doctor` work. Shipped `run` does not execute JS. TNR incomplete vs Node host APIs.
**Target:** README Quick Example steps 1–7 work on a clean Linux box from the installer **or** the README must stop implying that.
**Success criteria:**
- [ ] Hermetic e2e: install or `cargo build --release -p frankenengine-node`, `init --scan`, `run` fixture `console.log`, assert stdout + receipt
- [ ] Fail closed if engine missing; **no** silent Node fallback
- [ ] New release (or documented “source-only until v0.2”) so installer ≠ 709-commit-old binary
**Depends on:** `bd-f5b04`, `bd-34d5`, new release-freshness bead.
**Would existing beads close it?** Partially (TNR + install path). Not the stale release.
**Complexity:** XL

### Gap #3: Dual-oracle truth — WRONG_APPROACH → WORKING

**Current:** Three files, two L1 answers.
**Target:** Single definition: L1 = targeted corpus pass rate; L2 = engine-split + verifier independence; release policy = both consumed fail-closed.
**Success criteria:**
- [ ] Regenerating close-condition fails if L1 GREEN file and corpus_pass disagree
- [ ] May 21 backfill notes cannot satisfy `doctor close-condition` happy path
- [ ] `doctor_close_condition_e2e` expected GREEN only on a fixture that includes corpus ≥95% **and** proof-carrying effects (see `bd-3c2ie` drift)
**Would existing beads close it?** No.
**Complexity:** M

### Gap #4: 3× migration as a live gate — UNPROVEN → WORKING or honest pending

**Current:** Closed bead + constructed 3.15× JSON.
**Target:** Either (a) a real before/after study on N real repos with signed timing/confidence, or (b) CLAIMS_REGISTRY + README stop implying the number is earned.
**Success criteria:**
- [ ] `artifacts/migration/throughput_delta.json` emitted by a runner that times `migrate audit/rewrite/validate` vs a documented manual baseline on checked-in fixtures
- [ ] Gate fails if ratio < 3.0 **or** if inputs are the Feb 2026 archetype list
- [ ] Reopen/replace `bd-3agp` rather than cite it
**Would existing beads close it?** No.
**Complexity:** L

### Gap #5: 10× compromise — UNPROVEN → WORKING

**Current:** Harness + reports; `bd-3cpa` still open. Good.
**Target:** Keep `bd-3cpa` honest: ratio computed from a replayable campaign; Wilson lower bound; fail if baseline runtime unavailable (`fail_closed_baseline_unavailable` already in v2 artifact).
**Success criteria:** listed on `bd-3cpa`. Do not close on constructed 20/2 arithmetic alone.
**Would existing beads close it?** Yes, if not false-closed.
**Complexity:** L

### Gap #6: Live frankensqlite — STUB → WORKING

**Current:** In-memory model; JSON trust/fleet/evidence.
**Target:** Trust-card registry, fleet action log, and evidence-ledger spill go through `fsqlite` with crash-safe WAL (Tier 1), with a documented migration from JSON.
**Success criteria:**
- [ ] Adapter header no longer says “not the live store”
- [ ] `franken-node init` creates an fsqlite file; `trust scan` persists there
- [ ] Kill -9 mid-write leaves previous consistent snapshot (existing TempFileGuard semantics must hold on the DB)
- [ ] Conformance tests use the real engine, not only the model
**Would existing beads close it?** No (false-closed).
**Complexity:** XL

### Gap #7: CLI honesty pass — PARTIAL → WORKING

Fix or relabel: `verify module`, `verify compatibility`, `runtime lane/epoch`, `proofs workers restart`, `ops health-check` session count, `trust scan --json`.
**Success criteria:** each command’s `--help` and README row match the actual work; e2e asserts JSON fields that would have caught auto-PASS and ignored `--json`.
**Would existing beads close it?** No.
**Complexity:** M

### Gap #8: Unify revocation freshness — PARTIAL → WORKING

One `SafetyTier`, one clock, one gate on the `run` path and capability issuance.
**Would existing beads close it?** No.
**Complexity:** M

### Gap #9: Release freshness — PARTIAL → WORKING

Cut a release from current `main` **or** README installer section must say “prebuilt is historical; build from source.” Prefer a real release: checksums, cosign if claimed, `verify release` e2e against that dir.
**Would existing beads close it?** No.
**Complexity:** L (process) + M (docs/CI)

### Gap #10: asupersync / fastapi / frankentui substrate doctrine

Charter says mandatory. Code says optional/model/cosmetic.
**Target (ambitious, in-charter):** default fleet transport on `asupersync-transport` with file transport as explicit degraded fallback; fastapi binds a real control-plane socket behind `control-plane`; frankentui owns interactive doctor/fleet status, not a Buffer echo.
If the owner wants to de-scope, that is **off-charter unless the owner says so**. This plan does not de-scope.
**Would existing beads close it?** No.
**Complexity:** XL

### Gap #11: Inline tests + verification scaffolding

Already `bd-rjc2m*`. Execute, don’t replace.

---

## Ambition constraints (do not “simplify” the charter)

- Compatibility remains a **wedge**, not the destination. Hitting 95% without TNR host-effect receipts is still off-charter.
- 3× and 10× must be **measured with uncertainty** (Wilson interval already in verifier SDK). Point ratios of 3.15 and 10.0 with constructed denominators are not claims.
- Dual-oracle is conjunctive. Partial GREEN is a failed close, not a vibe.
- Substrate doctrine (asupersync, frankensqlite, frankentui, fastapi_rust) is not optional documentation. Either implement or the owner must amend the charter.
- Do not add compatibility shims. Do not wrap Node and call it franken-node `run`.

### Measurement design (charter KPIs)

Use the honesty-manifest pattern for **KPI** claims, not just test counts:

1. **Census** of the raw runs (per-case lockstep verdicts, per-repo migration timings, per-vector compromise outcomes).
2. **Signed manifest** binding recomputed ratio, README number, tolerance, evidence digest.
3. **Independent verify** via `frankenengine-verifier-sdk` with a non-harness trust anchor for anything published as a headline.

For 95% lockstep: Wilson lower bound of pass rate at 95% confidence must itself be ≥95% **or** the README must quote the interval, not a point. (95/100 is not enough; ~88.8% lower bound — the README already explains this.)

For 3× migration: ratio of medians on a frozen fixture set, plus a holdout repo not used to tune rewrites.

For 10× compromise: baseline must be **real Node or Bun** with the same payload; `franken_compromised=0` with `franken_attempts < baseline_attempts` is an apples-to-oranges trap already visible in v2 (`20` vs `10` attempts).

---

## Verification plan (after bridge work)

- [ ] V1: `run` fixture JS via engine, no degraded fallback
- [ ] V3: `trust scan` + `trust list --json` on a real package.json
- [ ] V4: `incident bundle --verify` + `incident replay` + counterfactual labeled executor
- [ ] V5: migrate audit/rewrite/validate on a fixture app with rollback
- [ ] V6: corpus_pass observed_pct ≥95 or honest RED
- [ ] V7: fleet quarantine/release/reconcile on file transport **and** documented multi-node path
- [ ] V10: `cargo test -p frankenengine-verifier-sdk` + honesty recompute
- [ ] V15: forbid(unsafe) still holds
- [ ] V16–V18: KPI manifests verify
- [ ] V20: close-condition conjunctive and consistent
- [ ] V22: fsqlite file survives kill -9
- [ ] V25: installer binary `--version` matches a tag within N commits of `main`
- [ ] V26: CLI honesty e2e
- [ ] V27: inline lane green or default `cargo test` runs them

---

## Dependency graph (new beads + existing)

```
existing: bd-2djfa ─┐
existing: residuals─┼─► bd-28sz (95%) ─┐
                    ┘                  │
G3 dual-oracle truth ──────────────────┼─► dual-oracle GREEN
existing: bd-f5b04 (TNR) ─┐            │
G2/G10 run+release ───────┴─► bd-34d5 ─┤
existing: bd-3cpa (10×) ───────────────┤
G4 3× live gate ───────────────────────┤
G6 frankensqlite live ─────────────────┤
G7 CLI honesty ────────────────────────┤
G8 revocation unify ───────────────────┘
existing: bd-rjc2m* (proof the proofs work)
```

Existing beads are **not** duplicated. New beads exist only for NO_BEAD / false-closed vision gaps.

**Created 2026-08-20 (epic `bd-reality-20260820-w0fc6`):**

| ID | Gap | Vision |
|---|---|---|
| `bd-reality-20260820-w0fc6.1` | G3 dual-oracle contradiction | V20 |
| `bd-reality-20260820-w0fc6.2` | G4 live 3× migration gate (`bd-3agp` false-closed) | V16 |
| `bd-reality-20260820-w0fc6.3` | G6 live frankensqlite (`bd-2tua`/`bd-26ux` false-closed) | V22 |
| `bd-reality-20260820-w0fc6.4` | G10 release/installer 709 commits stale | V25 |
| `bd-reality-20260820-w0fc6.5` | G7 CLI honesty | V26 |
| `bd-reality-20260820-w0fc6.6` | G8 unify revocation freshness models | V2 |
| `bd-reality-20260820-w0fc6.7` | G2 prove `run` executes JS without degraded fallback | V1 |
| `bd-reality-20260820-w0fc6.8` | IBD production-adoption KPI (`bd-2hrg` false-closed) | V28 |
| `bd-reality-20260820-w0fc6.9` | Charter substrates: asupersync / fastapi HTTP / frankentui (not Buffer echo) | V21, V23, V24 |

---

## What this reality check is not

It is not a claim that the last 4,269 closed beads were wasted. The product layer is dense, fail-closed, and unusually serious about receipts. It *is* a claim that **bead percentage is not vision percentage**, that **May 21 GREEN backfills are not close conditions**, and that **a 2.5% corpus with a GREEN L1 file is the central honesty failure**.

---

## Refresh 2026-08-23 (second full reality check — delta pass)

**Method:** same measuring stick (README + charter + CLAIMS_REGISTRY), fresh live probes only; no re-litigation of closed work without evidence. HEAD `v0.1.0-799-g457580b58` (branch `main`). Beads: 15 open / 10 in_progress / 5 blocked / 4,302 closed. Honesty manifest recomputed this session: **9 ok, 0 drifted** (`scripts/check_claims_manifest.py --check-honesty`; integration census 3,756→live 4,009; inline census 21,621→live 21,868; fuzz targets 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Velocity (bv): 22 closed last 7d, avg 1.27 days to close.

### What moved since the 2026-08-20 check (verified this session)

| Aug-20 gap | State today | Evidence |
|---|---|---|
| G3 dual-oracle contradiction (V20) | **CLOSED** (`w0fc6.1`). L1 is now bound to the measured corpus and honestly RED | `artifacts/oracle/l1_product_verdict.json` verdict=RED; `artifacts/compat/corpus_pass.json` verdict=RED, `observed_pct=86.43`, timestamp 2026-08-20T17:40Z |
| G4 constructed 3.15× cohort (V16) | **CLOSED as a live signed gate** (`w0fc6.2`). KPI itself still **unmet** | `artifacts/migration/throughput_delta.json`: pooled median 2.30×, bootstrap CI95 [1.90×, 3.30×], holdout 1.90×; CLAIM-002 pending (measured below 3.0×) |
| G6 frankensqlite in-memory model (V22) | **CLOSED** (`w0fc6.3`). Tier-1 WAL store live (trust-card registry authority switch + evidence-ledger durability) | close_reason cites `trust_card_registry_store.rs`, `trust_card.rs:1271-1427`; README State Layout now lists `trust-card-registry.v1.db` |
| G7 CLI honesty (V26) | **CLOSED** (`w0fc6.5`) | `verify compatibility` no longer auto-PASSes profile names; e2e regression anchors named in close_reason |
| G8 dual revocation models (V2) | **CLOSED** (`w0fc6.6`) | product SafetyTier canonical for run/remotecap; control-plane EpochFreshnessTier separated |
| G2 `run` cannot execute JS (V1) | **CLOSED at fixture level** (`w0fc6.7`) | `default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback`; host-effect runtime-of-record remains TNR (`bd-f5b04`) |
| IBD adoption false-close (V28) | **CLOSED as honest-pending KPI** (`w0fc6.8`) | `artifacts/adoption/ibd_production_use.json`: production_operator_count=0, verdict pending |
| Release staleness (V25) | Documented honestly (`w0fc6.4`); **not fixed** — Latest is still v0.1.0, now **799 commits** behind HEAD (was 709 on Aug-20) | `git describe` → `v0.1.0-799-g457580b58`; PATH binary still Jun-8 v0.1.0 |

Strict WORKING count moves **3/28 → ~7/28**: V3, V11, V15 (unchanged) + V20 (mechanism honest, verdict RED until corpus ≥95%), V22 (fsqlite store live), V26 (CLI honesty restored), V1 (fixture-level run proven from source; full host-effect TNR still open).

### Current corpus residual mix (76 failures; 484/560 = 86.43%; need 532/560 for 95%)

child_process 30 · crypto 13 · stream 12 · fs 6 · tls 5 · zlib 3 · net 3 · events 2 · cluster 2
(`artifacts/13/compatibility_corpus_results.json.failing_tests_tracking`).

Family bead coverage: child_process `bd-at11s`, crypto `bd-y4t2i`, stream `bd-m8vaa.1`, tls `bd-387cw`, net `bd-sul35` (37/40; incl. node-vs-bun reference disagreement 0005/0024 where franken matches node), cluster `bd-zyp0c`. **fs / zlib / events had zero dedicated beads anywhere (product or engine)** → created this session (see bead table below). zlib engine breadth exists as franken_engine `bd-znj5l` (Brotli) but no product-side residual tracking; events::0022 (arrow lexical-`this`) falls only under the broad franken_engine BRIDGE-14.11 umbrella.

### New regressions / risks found this session

1. **`bd-c6qum` (open, P1): 18 `fleet_cli_e2e` failures at HEAD** after the durable-transport switch (tests seed via `FileFleetTransport` while CLI now uses `DurableFleetTransport`). Active fix in flight by another agent (layers 2b–2d landed Aug 22–23; snapshot files modified in working tree).
2. **P0 inline-test hole persists:** `[lib] test=false` keeps ~21.9k inline tests out of default `cargo test` (`bd-rjc2m.21`, P0 in_progress). The dedicated lane now compiles but has runtime behavior-drift failures (`bd-o776s`).
3. Verification-scaffolding API-drift epic `bd-rjc2m` (~68 targets) with `.38`/`.39` G2G restore items in_progress and children `.7` (conformance cluster), `.17` (cargo-deny license) blocked.
4. RCH/farm health drags on validation: `bd-gc0ze` (stale fastapi-http dependency sync blocks validation), `bd-famte`/`bd-pnmnu` (clippy/fmt blockers).

### Beads created by this refresh (Phase 3a)

| ID | Gap | Vision |
|---|---|---|
| `bd-reality-20260823-fs-residual-yxlxu` | fs corpus residuals 6 (0021/0022/0023/0044/0045 engine crashes; 0030 output mismatch) | V6 |
| `bd-reality-20260823-zlib-residual-l6ev2` | zlib corpus residuals 3 (0004/0009/0016 engine crashes; cross-ref engine `bd-znj5l`) | V6 |
| `bd-reality-20260823-events-residual-uopqy` | events corpus residuals 2 (0017 engine crash; 0022 arrow lexical-`this` output mismatch) | V6 |

All three block `bd-28sz` (the ≥95% gate). No other NO_BEAD vision gaps found this pass: every other open gap maps to an existing bead (see tables above).

### Refinement notes (plan-space pass over this refresh)

* Do **not** reopen closed `w0fc6.*` items without new evidence; their close_reasons carry file:line + commit citations that checked out against the tree today.
* The release-freshness decision stands as documented-honesty (`README.md:286-294` warns Latest lags main). If the owner wants a real channel fix, cut v0.2.0 after `bd-c6qum` clears and corpus ≥95% — do not cut earlier just to shrink the number.
* `net::0005`/`net::0024` are reference-leg disagreement (franken matches Node); resolution is spec adjudication inside `bd-sul35`, not engine work.
* Keep the orchestrator cadence (4 min) and do not recategorize `child_process` native-eval aborts as pass — both reaffirmed by the Aug-21 follow-up and unchanged today.

### Live binary probes (2026-08-23/24, fresh release build)

Build: `cargo build --release -p frankenengine-node` → `/data/tmp/cargo-target/release/franken-node` (`CARGO_TARGET_DIR` is set workspace-wide; there is no in-repo `target/`). Binary `--version` → `franken-node 0.1.0`.

| Probe | Result |
|---|---|
| `init --profile balanced --json --out-dir .` | exit 0; state dirs + keys bootstrapped |
| `run ./hello.js --policy balanced` (auto) | **exit 1, fails closed**: resolves external `node`, refuses it ("cannot enforce franken-node's capability contract"). Correct refusal — but auto does **not** discover a sibling-built engine |
| same + `FRANKEN_NODE_ENGINE_BINARY_PATH=<target>/frankenctl` | **exit 0**, stdout `hello-from-engine`, run receipt written (`runtime=franken_engine exit_code=0 violations=0`) |
| `run … --runtime franken-engine` without engine bin configured | fail-closed: "requested runtime was not found; fix --engine-bin / FRANKEN_NODE_ENGINE_BINARY_PATH / [engine].binary_path" |
| `doctor close-condition --json` | **bug filed** `bd-9zrqh`: unconditional signing-key demand; its own fix_command then fails with "failed generating close-condition receipt" and empty stderr |

Interpretation: `w0fc6.7`'s closure is accurate for its tested scope (harness provisions the engine authority); the clean-room operator path still requires an explicit engine-binary handoff that README's "First safe workload (current source)" does not mention. That gap belongs to open `bd-34d5` (install → first safe production), not a reopen.

## Refresh 2026-08-29 (third full reality check — delta pass)

**Method:** same measuring stick (README + AGENTS.md + PRODUCT_CHARTER + CLAIMS_REGISTRY + the Aug-20/23 sections of this file), fresh live probes only; no re-litigation of closed work without new evidence. HEAD `v0.1.0-860-g77a8d48cc` (2026-08-28). Beads: 4,342 issues — 14 open / 11 in_progress / 4 blocked (~99.3% closed). Honesty manifest recomputed this session: **9 ok, 0 drifted** (integration census 3,756→live 4,014; inline 21,621→21,871; fuzz 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Release drift grew again: Latest `v0.1.0` is now **860 commits** behind HEAD (709 at Aug-20, 799 at Aug-23).

### Headline: the compatibility corpus REGRESSED 86.43% → 69.82%

`artifacts/13/compatibility_corpus_results.json`, regenerated 2026-08-24 (f50be1135) and 2026-08-26 (10ae1ddcd), now measures **391/560 = 69.82%** (bands: core 74.41%, high-value 62.40%, edge 82.14% — all below their 99/95/90 floors). The Aug-20/23 measurements recorded 484/560 = 86.43% with a 76-failure mix containing **no IFC failure class at all**. The current artifact has 169 failures; **97 of them share one new signature**: the franken-engine leg refuses at the lowering stage with `unauthorized flow detected at op N: TopSecret -> Internal` (information-flow-control / taint enforcement). Class census: engine_crash 120 (97 = IFC refusals), native_eval_abort 30 (child_process, unchanged), output_mismatch 18, reference_disagree 1. IFC refusals span ≥12 families (buffer 14, url 8, querystring 7, os ~5, cluster ~5, crypto ~12, events ~13, fs ~13, stream ~8, http ~3, timers 1, tls ~1, zlib ~5). Same-corpus-hash anchor: v0.1.0 scores 68.21% — the regression puts main ~1.6 points above the May baseline, erasing ~6 weeks of measured compatibility progress. Suspected cause: default-on IFC enforcement landed engine-side between the two measurement windows. This is the charter's central collision (security hardening vs the ≥95% floor); per the Aug-21 reaffirmation these failures must NOT be recategorized — benign flows must declassify correctly, malicious flows must still refuse.

**Beads created this pass (all three block `bd-28sz`):**

| ID | Gap | Vision |
|---|---|---|
| `bd-kx70h` (P0, bug) | IFC lowering-refusal regression: 97 corpus cases; triage incl. measurement-protocol hygiene; engine-first fix per split contract + CI class tripwire | V6 |
| `bd-bwa93` (P2, task) | Failure-ownership sweep: os/http non-IFC residuals (4 known) + durable "every corpus failure has an owner" invariant | V6 |
| `bd-klpse` (P2, bug) | `artifacts/compat/corpus_pass.json` (86.43 @ Aug-20) + CLAIMS_REGISTRY CLAIM-001 stale vs 69.82 measured; `check_compatibility_corpus_pass_gate.py` never reads `corpus_pass.json` — zero drift detection | V6/V20 |

### What else moved since 2026-08-23 (verified this session)

| Aug-23 item | State today | Evidence |
|---|---|---|
| fleet_cli_e2e 18 failures (`bd-c6qum`) | CLOSED; close-reason quality high | 50/50 green at HEAD d9c0973b4, serial + -j4, verified 10+ runs |
| doctor close-condition keyless bug (`bd-9zrqh`) | CLOSED | 22fbc4f7b; `close_condition.rs:709-746` + `main.rs:6685-6731`; regression test named |
| 10× compromise gate (`bd-3cpa`) | CLOSED as gate implementation; CLAIM-003 correctly still pending | c3dddc6f1: bench targets registered, gate 27/27 PASS; v2 artifact uses raw bun/node baselines (20 attempts each) with `fail_closed_baseline_unavailable=true`; registry retains "do not treat 20.0× as verified" — gate-vs-claim separation coherent, no reopen |
| Inline-test hole (`bd-rjc2m.21`, P0) | Still open; dedicated lane now compiles but has runtime behavior-drift failures (`bd-o776s`) | V27 remains PARTIAL: ~21.9k inline tests still not effectively executed anywhere |
| Migration 3× (`bd-v0lgc`) | Still open | live gate measured 2.30× (CI95 [1.90×, 3.30×]) vs ≥3.0× charter floor |
| CLI honesty (`w0fc6.5`) | **Re-verified HOLDS** by a fresh static audit this session | zero `todo!`/`unimplemented!`/`TODO` in src; `verify compatibility` profile targets fail closed (`main.rs:28186-28203`); proofs restart paper-labeled with `ERR_PROOF_RESTART_NO_EXECUTOR` (`ops/proof_pipeline.rs:486-497`, `main.rs:8775-8782`); counterfactual `--model production` bails (`main.rs:20008-20015`); `trust sync` performs a real OSV POST with offline warnings; all six spot-checked primitives 1,289–6,977 lines, REAL |
| Release channel (`w0fc6.4`, documented honesty) | Drift worsened 799 → 860 commits; correctly still blocked on corpus ≥95% per the Aug-23 decision | `git describe` |

### Vision checklist deltas (Aug-20 numbering)

- **V6 (compat ≥95%): REGRESSED** — 86.43% → 69.82%. Honest RED everywhere: `l1_product_verdict.json` RED, close-condition receipt `failing_dimensions=[L1_product_oracle]`, `corpus_pass.json` RED-but-stale (bd-klpse).
- V1 (`run` executes JS): fixture-level proof stands (`w0fc6.7`); this session re-ran the named e2e via rch — result recorded below. Clean-room operator path still owned by `bd-34d5`.
- V20 (dual-oracle truth): mechanism still honest; summary-artifact staleness is the one new crack (bd-klpse).
- V27 (effective coverage): unchanged PARTIAL; the P0 remains the single largest coverage hole in the repo.
- Strict WORKING count: **~7/28, unchanged** (V3, V11, V15, V20-mechanism, V22, V26, V1-fixture-level). The corpus regression blocks any further climb until the IFC class is resolved.

### Run-proof re-verification (2026-08-29 session)

**Live operator probe PASS (new positive delta vs 2026-08-23).** Using the shared debug binary built 2026-08-29 03:28 (`/data/tmp/cargo-target/debug/franken-node`, newer than HEAD 77a8d48cc) in a clean `/tmp` workspace with the standard sibling `franken_engine` checkout:

1. `franken-node init --profile balanced --json --out-dir .` → `franken-node/init-cli/v1`, exit 0.
2. `franken-node run ./hello.js --policy balanced` (auto runtime) → **exit 0, stdout `hello-from-engine`, `runtime=franken_engine exit_code=0 violations=0 auto_quarantined=0`**, signed run receipt written under `.franken-node/state/execution-receipts/2026-08-29/…`. **No `FRANKEN_NODE_ENGINE_BINARY_PATH` and no degraded-fallback env were needed** — auto mode discovered the sibling engine, which FAILED on the identical probe 2026-08-23. The clean-room gap that `bd-34d5` tracks has narrowed to release-channel freshness (debug/source builds auto-discover; the shipped v0.1.0 installer artifact still cannot).
3. `doctor close-condition` keyless in that workspace → no signing-key demand (bd-9zrqh fix live); fails with a precise missing-artifact path (`artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json`) plus a fix_command naming the checkout requirement.
4. `verify compatibility balanced` → **fail closed**, `status=fail exit_code=1`, contract_version 3.0.0, message: profile is not a compatibility claim (w0fc6.5 behavior confirmed live).

The named regression e2e (`default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback`) was re-launched this session via `rch` and produced **no verdict**: the remote build was SIGKILLed (`exit=137`, rch "likely resource exhaustion") on worker hz4 after a 60-minute cold compile, with no higher-capacity worker available — an infrastructure failure, not a product regression. V1 fixture-level evidence for this refresh therefore rests on the live probe above (newer-than-HEAD binary, full operator path, auto-discovered engine) plus the standing `w0fc6.7` proof; the named test should be re-run once a warm target or a larger worker is available.

### Refinement notes (Phase 5 pass, this session)

- `bd-kx70h` amended after review: triage must first confirm the Aug-20 run's measurement protocol (policy_mode, reference runtime, corpus hash) before attributing the drop to engine code; only the code-delta component is engine work. Same-corpus-hash v0.1.0 anchor suggests protocol comparability, but verify from the Aug-20 run record.
- Generalization candidate noted, deliberately not bead-ed yet: the IFC tripwire (bd-kx70h task 3) could become a generic failure-class-census tripwire (any class-census shift beyond a registered floor fails CI). Decide when the IFC tripwire lands.
- Known-and-accepted (again): `docs/TODO_ULTRA_DETAILED.md` sections 1–5 are stale (QuickJS-evaluator TODOs contradict the no-bindings rule; ROADMAP "Phase 0 In Progress" is wrong). Flagged Aug-20; still not worth a bead against the P0 — a 10-minute truth pass is warranted once the corpus is green.
- Cross-repo bead references: `failing_tests_tracking.investigation_bead_id` `bd-8qvy6` lives in the franken_engine bead store, not this one — intentional, but triagers must look there.
- Beads-store transient corruption during this session's concurrent creation: auto-export hit `database disk image is malformed` plus a JSONL write-lock timeout; the first bd-kx70h write was lost and re-created. Store now verifies clean: 4,342/4,342 coverage, dirty 0 (pre-repair snapshot in `.beads/recovery_20260829_realitycheck/`).

### Work-session addendum (2026-08-30, gap-closure pass)

- **IFC regression is PARTIALLY healed at HEAD.** Probing formerly-failing fixtures through the exact corpus franken-leg command (`run --console-only --policy legacy-risky --runtime franken-engine --engine-bin <self>`): buffer/0005, fs/0021, url/0003, zlib/0004 now PASS; **events/0017 and querystring/0002 still refuse** with `unauthorized flow detected at op N: TopSecret -> Internal (reason=no_lattice_or_declassification_path)` — confirmed live, residual class is real and owned by `bd-kx70h`/`bd-bwa93`. Both residual fixtures share the shape `require(<builtin>)` + method calls.
- **Reproduction gap (measurement provenance):** `ops compat-corpus-run --require-node-reference` with real node v22.2.0 + bun 1.4.0 (same corpus hash `compat-corpus-v2-7b86e9d2…`) on this host measured **60.36% (338/560)**; dyad (bun-only) 60.0% — the committed 69.82% (Aug-26) does NOT reproduce. The artifact pins no host, engine build, node/bun versions, or fixture-tree revision, so cross-host reproduction is unverifiable. Probe evidence: `artifacts/13/compatibility_corpus_results.repro-probe-20260830.json` (untracked by the gate; canonical artifact unchanged). Until provenance is pinned (bd-kx70h), treat single-run corpus deltas of ~±10 points as measurement uncertainty, not engineering signal.
- **bd-klpse delivered:** `scripts/check_compatibility_corpus_pass_gate.py` now fail-closes on `SUMMARY_OBSERVED_PCT_MISSING/_MISMATCH`, `SUMMARY_STALE_VS_RESULTS`, `SUMMARY_TIMESTAMP_UNPARSEABLE`, `SUMMARY_GREEN_BELOW_FLOOR`, `SUMMARY_VERDICT_INCONSISTENT` (self-test 6/6 incl. stale/mismatch/GREEN-below-floor vectors). `artifacts/compat/corpus_pass.json` synced to the measured 69.82 (honest RED, Aug-26 provenance); CLAIMS_REGISTRY CLAIM-001 synced with the reproduction caveat. Gate already wired into CI (`.github/workflows/dist.yml`) and imported by `scripts/check_oracle_close_condition.py` (which re-derives L1 from the results artifact, unaffected).

## Refresh 2026-09-22 (fourth full reality check — delta pass)

**Method:** same measuring stick (README + AGENTS.md + PRODUCT_CHARTER + CLAIMS_REGISTRY + prior sections of this file), fresh live probes and verification runs. HEAD `v0.1.0-1114-g08447a0aa` (branch `main`). Beads: 4,349 total issues — 4,314 closed (99.20%), 12 in_progress, 19 open, 4 blocked (35 active/non-closed). Honesty manifest recomputed this session: **9 ok, 0 drifted** (`scripts/check_claims_manifest.py --check-honesty`; integration census 3,756→live 4,106; inline census 21,621→live 22,421; fuzz targets 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Release drift reached **1,114 commits** past `v0.1.0`.

### What moved since 2026-08-29 (past 254 commits)

1. **Captured Migration Execution & Failure Reducer Landed:** Pinned manifest-selected test execution (`docs/MIGRATION_CAPTURED_EXECUTION.md`, `scripts/migration_validation_runner.py`), pipe transport binding, and execution-backed line reduction (`scripts/minimize_migration_failure.py`, 58/58 unit tests passing).
2. **Supervised Invocation Watchdog:** External process execution supervision with fail-closed timeout evidence and bounded binary stdin/stdout streaming (`test_runtime_invoke_watchdog.py`).
3. **Supply-Chain Dependency Graph Capture:** Entrypoint-wide JavaScript/TypeScript source dependency graphs, package-map target selection (`package.json` `exports`/`imports`), contained package symlink resolution, and TypeScript erasure verification without loading erased types.
4. **Closed-World Offline Replay:** Pinned closed-world module source registry and private source capsules for replay exclusively from captured observations.

### Standing Vision Gaps (Status at 2026-09-22)

- **V6 (Targeted Compatibility Floor ≥95%): REGRESSED at 69.82%.** Canonical artifact records 391/560 (69.82%); 97 cases fail on engine IFC lowering refusals (`bd-kx70h`, P0). Cross-host reproduction measured 60.36%. Dual-oracle close condition is honestly RED (FAIL).
- **V16 (Migration Velocity ≥3×): UNMET at 2.30×.** Live signed gate (`artifacts/migration/throughput_delta.json`) measures pooled median 2.30× (CI95 [1.90×, 3.30×]), holdout 1.90× (`bd-v0lgc`).
- **V25 (Release Distribution Freshness): REGRESSED.** Latest tag `v0.1.0` is 1,114 commits behind HEAD. Promised Windows x86_64 prebuilt is not built in CI (`bd-tenx3.4`).
- **V27 (Inline Test Hole): PARTIAL.** ~22,421 inline tests remain disabled from default `cargo test` (`[lib] test=false`, `bd-rjc2m.21`, P0); dedicated inline lane compiles but has behavior drift (`bd-o776s`).
- **Charter Substrates (Charter §4): PARTIAL.** `asupersync` remains opt-in, `fastapi_rust` is an in-process catalog, `frankentui` is a Buffer copy-echo (`bd-tenx3.1`).
- **V28 (Production IBD Adoption): NOT_STARTED.** 0 production operators (`artifacts/adoption/ibd_production_use.json`).

## Same-day verification pass (2026-09-22, independent delta pass)

**Method:** fresh-eyes audit layered on the refresh above, same measuring stick; four parallel read-only code investigations (CLI surface, run/engine path, test reality, stub scan) plus live probes (honesty manifest recompute, beads DB read-only, oracle artifacts, corpus census, git-history forensics). Every headline number in the refresh above was **independently re-verified and confirmed**: honesty manifest 9 ok / 0 drifted live; corpus 391/560 = 69.82% with failure census 120 engine_crash (~97 IFC `TopSecret -> Internal`) / 30 native_eval_abort / 18 output_mismatch / 1 reference_disagree; L1 RED, L2 + release-policy GREEN-by-backfill; release drift 1,114 commits; 35 active beads; ~7/28 strict WORKING.

### New findings (all bead-ed or fixed this pass)

1. **bd-kx70h task-1 forensics COMPLETE — the 86.43 → 69.82 comparison is confounded.** Git history of `artifacts/13/compatibility_corpus_results.json`: the Aug-20 run (f74fa63b7, 86.43%) used reference legs **node v20.19.4 + bun 1.3.14**; the Aug-24/26 runs (f50be1135, 10ae1ddcd, 69.82%) used **node v22.2.0 + bun 1.4.0**. Corpus hash, policy mode, topology, and product runtime id are identical; only the reference legs changed. Scope limit: the confound can only affect output_mismatch (18) + reference_disagree (1) classes — the 97 IFC refusals + 30 native_eval_abort cases (≥150/169) are franken-leg intrinsic and stand regardless. Combined with the 2026-08-30 same-protocol repro at 60.36%, provenance pinning in the artifact is mandatory before any delta is treated as signal. Recorded as a bead comment on `bd-kx70h`.
2. **`api/service.rs` fabricated-claims fix landed (bd-svc-honesty-v4yy9).** `http_server::dispatch_http_request` hardcoded `"live_control_plane": true` on `/v1/fleet/status` and returned a canned empty `/v1/trust/cards` 200. Fixed: fleet status now reports the fleet-CLI contract vocabulary (`transport=file live_control_plane=false activated_source=file_transport_not_live`); trust cards now load the real durable registry (`TrustCardRegistry::load_authoritative_state`, `TrustedFile`) relative to the workspace and fail closed with a typed `urn:franken-node:error:trust-registry-unavailable` 503 when absent — never a fabricated list. Three inline tests pin the markers (`http_server_fleet_status_reports_file_transport_not_live`, `http_server_trust_cards_fail_closed_without_registry`, `http_server_trust_cards_read_real_registry_store`).
3. **README/CLI drift fixed (bd-readme-cli-drift-4l0ex).** Command Reference rows added for `migrate rollback`, `migrate rollout` (both real at `cli.rs:652/658`, handlers `main.rs:30944/31025`), and `doctor process-spawn-readiness` — CLI is now 72/72 documented. The "run by a default `cargo test`" claim corrected in three places: flagship CLI e2e need `--features test-support`, most `bd_*` conformance families `--features advanced-features`, so a default-feature run executes only the ungated subset; counts updated to the live census (~4,100 registered / ~22k inline).
4. **`docs/TODO_ULTRA_DETAILED.md` sections 1–5 banner added** (the 10-minute truth pass flagged since Aug-20): marked as historical pre-engine-split notes; QuickJS/V8 items contradict the charter no-bindings rule; delivered §5 items (CLI, structured logging, release pipeline) called out as stale-unchecked.
5. **`fuzz/regression/` thinness bead-ed (bd-fuzz-regression-corpus-f28ac):** 5 crash inputs vs 146 registered targets; the "regression case forever" claim is thin — corpus workflow + CI rot-check + seed campaign tracked there.

### Infrastructure notes this pass

- The named `default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback` re-run and a fresh binary build were **RCH-blocked** (queue 0/16 slots; one worker failed with missing `rustc`; local fallback refused by policy). V1 evidence therefore still rests on the 2026-08-29 live probe + the standing `w0fc6.7` proof; re-run when the farm drains.
- A second verification attempt (canonical inline lane for the `api/service.rs` honesty tests, `bd-svc-honesty-v4yy9`) also failed **before reaching this crate**: the sibling `franken_engine` lib itself did not compile (concurrent `fetch_update` → `try_update` API migration in flight engine-side) and the worker additionally SIGKILLed rustc (OOM) on the debug lib compile. The service.rs changes are fmt-clean but their three new inline tests are **written, not yet executed**; the bead carries the exact lane command to run once the engine tree compiles again.
- `br` was mid schema-migration (v17→v19) by a concurrent agent during part of this pass; beads were read directly from SQLite read-only and mutated only after the migration settled.


## Refresh 2026-09-23 (fifth full reality check — first LIVE-BINARY pass)

**Method.** Earlier passes mostly read code and artifacts, and the Sep-22 pass could not build a binary because RCH was blocked. This pass **built a fresh release binary** and ran it:
- **Builds:**
  - release build via `rch exec` (fell back to local), 19 min;
  - franken_node HEAD `8b8b45311` (`v0.1.0-1136`);
  - franken_engine `0dce0e734`, 2026-09-23;
  - a scratch crate that depends *only* on `sdk/verifier`.
- **Probes run against the binary:**
  - 20 realistic programs, 8 real npm packages (installed with bun), and ~30 language/runtime micro-probes, all compared against node v22.2.0;
  - the adversarial payloads;
  - the incident pipeline into the SDK;
  - hyperfine timings against node and bun;
  - a fresh full compatibility-corpus triad run.
- **Parallel read-only audits (7):**
  - plan-vision extraction;
  - trust-gate wiring;
  - incident/replay/SDK provenance;
  - the host-API surface;
  - CI/release reality (gh API);
  - a bead-compliance audit of closures since Aug-19;
  - a module-reachability census.
- **Artifact handling:** all probe artifacts live in the session scratchpad. **No committed artifact was regenerated.**

Beads: 4,352 total, 4,319 closed (99.2%).

### Executive answer

franken_node is a large, carefully fail-closed **trust/verification control plane** attached to a **native JS runtime that today can execute only single-file, self-contained, small programs**. Specifically:
- no module loading;
- a 100k-instruction budget on the default profile;
- a frozen clock;
- several silent miscompiles.

The strongest claims made since Aug-29 do not survive running the software:
- the ≥3× migration pass traded away crash durability;
- the ≥10× compromise campaign never executed franken-node;
- the revocation freshness gate is dead on every default install;
- the independent SDK cannot read the CLI's incident bundles;
- CI has never produced a green `cargo test` of the crate.

One real positive: **compatibility on the corpus recovered to 87.32%** (from 69.82% in the stale committed artifact). The containment primitives (fs write, SSRF, eval, sandbox escape) genuinely block when a payload actually runs.

### Live probes (release binary; `FRANKEN_NODE_ENGINE_BINARY_PATH` set, because default auto mode fails — see G-C below)

**Runtime surface.** Of 20 realistic programs under balanced `--console-only`, 3 matched node cleanly, 2 more exited 0 with divergent output, and 15 failed.

| Probe | node | franken-node |
|---|---|---|
| `console.log("hello")` | ok | ok (strict: exit **92**, verdict `Sandbox`) |
| `require("./lib/math")` | `rel:5` | `ambient authority violation: access to 'require' requires effect 'fs.read'` |
| lodash / ms+semver / dayjs / uuid / commander / express (node_modules) | all ok | **0/8**, same ambient-authority violation |
| `const EventEmitter=require("events"); new EventEmitter()` | ok | refused (only the destructured `{EventEmitter}` pattern works) |
| `.mjs` importing `./lib/esm_math.mjs` + `fs` | ok | `unauthorized flow … TopSecret -> Internal` |
| `run dirapp` (package.json main) | — | `Failed to read application source … Is a directory` |
| `(async()=>{ await null; … })()` | ok | `type error: expected function, got string` |
| `[...generator()]` | `1+2` | `expected iterable, got object` |
| `class A{#x=1; get x(){return this.#x}}` | `class:1` | **`class:this.#x`** (silent wrong answer, exit 0) |
| `for(i<20000) s+=i` (balanced) | ok | `instruction budget exhausted: 100000/100000` (legacy-risky: 50k iterations ok, 100k fail) |
| `Date.now()` | real time | `1767225600000` every run |
| 1,500 × `console.log` | 1,500 lines | last 1,000 only (first 500 silently dropped) |
| `console.log("before"); throw …` | prints `before` | stdout empty |
| `console.log({a:1},[1,2,3])` | `{ a: 1 } [ 1, 2, 3 ]` | `[object Object] 1,2,3` |
| `const s="password"; console.log(s.length)` | `8` | IFC refusal `Secret -> Internal` |
| `process.env.HOME` / `process.exit(3)` (legacy-risky) | ok | ambient-authority violation (every profile) |
| strict: `JSON.stringify` / `path.join` | ok | `capability denied: builtin:JsonStringify` / `builtin:PathJoin` |
| `TextEncoder`, `structuredClone`, `globalThis` | defined | `undefined` ×3 |
| fetch `169.254.169.254` metadata | blocked | blocked (strict `capability denied: net:request`; balanced SSRF) ✓ |

**Security gates.**
- **Revocation freshness (G-A).** Aging the `.db` registry 400 days still passes `--policy strict`. Adding a 400-day-old legacy `.json` makes the same run block (`RF_STALE_FRONTIER … age 34560000s > max 300s`). The gate reads the mtime of a file `init` never writes (`main.rs:294`, `:18566`).
- **Adversarial payloads run directly.**
  - `fs.writeFileSync`: denied under strict/balanced, **PWNED under legacy-risky**.
  - metadata SSRF: blocked.
  - `/etc/passwd`: refused under all profiles.
  - `eval`: denied under all profiles.
  - The containment is real.
- **The ≥10× bench's franken leg reproduced exactly** (`run --policy strict --json .`): "cannot launch external runtime node", or with the engine configured "Is a directory". **It never executes guest code** (G-D).

**Incident pipeline.**
- A **hand-authored** `evidence.v1.json` produced a signed bundle.
- `incident replay` → `matched=true`.
- `incident counterfactual --policy strict` → executor `synthetic`, `changed_decisions=1, severity_delta=-47`.
- The scratch crate using only `frankenengine-verifier-sdk` → `bundle::deserialize`/`verify`/`validate_bundle` all fail: `missing field artifact_path`. **The SDK cannot read CLI bundles** (G-E).

**First run (G-C).**
- A fresh build's default `run hello.js` fails. Auto mode finds no sidecar `franken-engine`/`frankenctl` binary, falls back to node, and refuses node. Yet the sidecar is never executed; it is a pure presence gate.
- `trust scan --deep --audit` needs `FRANKEN_NODE_REMOTECAP_KEY` **and** a `remotecap issue` token in `FRANKEN_NODE_TRUST_SCAN_REMOTECAP_TOKEN`, neither documented.
- `incident bundle` needs a hand-generated fleet signing key.
- `doctor` detects none of these, and exits 0 while reporting `overall_status: fail`.

**Performance (never measured before).** hyperfine, same host (load average ≈ 50):
- `run hello.js`: **164.3 ms ± 6.0**.
- node: 36.7 ms ± 1.9, so franken-node is **4.5× slower**.
- bun: 188 ms (this host's bun is anomalous).
- The ~130 ms fixed per-run overhead dominates: a 50k-iteration loop costs the same as hello.
- HC-003 ("within 10% of Node") is "verified" by `scripts/check_latency_gates.py`, which only greps spec keywords.

**Compatibility corpus (fresh, scratch).**
- `ops compat-corpus-run --require-node-reference`: node v22.2.0 + bun 1.4.2 + engine `0dce0e734`, `legacy-risky`, 9m42s.
- **489/560 = 87.32%** (committed artifact: 69.82% @ 2026-08-26).
- Remaining failures:

| Family | Failures | Cause |
|---|---|---|
| child_process | 30 | Bubblewrap containment-unit abort |
| crypto | 14 | 13 IFC `Secret -> Internal` |
| stream | 21 | 12 IFC `TopSecret`, 3 output mismatch, rest type errors / `require` |
| cluster | 2 | |
| fs | 2 | |
| http | 1 | |
| net | 1 | |

- IFC refusals: 97 → 26.
- Bands: core 88.98 (floor 99), high-value 84.0 (95), edge 94.64 (90).
- **+43 passes are needed for 95%.** child_process (30) + crypto IFC (13) is exactly that minimum.
- Caveat: the corpus is 540 single-file micro-probes averaging 8.8 lines, with **zero** module/package usage, measured under `legacy-risky`. It **cannot detect** any of the ecosystem failures above.

### Audits (agents; each finding spot-verified by hand where marked ✓)

- **G-B ✓ Migration ≥3× bought with durability.** `rewrite_transaction.rs` `sync_all` count went 7 (35881aa36) → 1 (608f2088d) → 0 (318ac9360), while the ratio went 0.45× → 2.50× → 5.67×. 608f2088d's message describes `touched_dirs` batching that **does not exist** (`rg touched_dirs` → 0). The header still promises a durable journal. bd-v0lgc closed on it. CLAIMS_REGISTRY CLAIM-002 still says 2.30× pending; the section-13 artifacts say 5.56/5.67×.
- **G-D ✓ ≥10× campaign invalid.** All 20 franken cases in `compromise_reduction_v2.json`: `exit_code:1, blocked:false, contained:false, typed_errors:[]`.
- **G-F ✓ CI.**
  - Last 7 days: 1,924 runs on main, 14.3% success, **82% failure**. No run has ever compiled and tested the crate successfully, and none runs `franken-node run`.
  - 10 PR-only gates (claims-manifest, mutants, inline-lib-tests, no-self-compare, verification-target-compile, …) have **never run**: the repo has **0 PRs**.
  - `connector-conformance.yml` has had invalid YAML since Feb (0/3,468). README Quick Example Smoke: 0/1,340.
  - `dist.yml` never succeeded; the v0.1.0 assets were hand-uploaded. `install.sh --method source` never clones frankentui.
- **G-G Reachability.**
  - About **42.7%** of 360,816 non-test product lines is reachable from the default binary (module-level upper bound); 35.2% is compiled-but-unreachable; 22.1% is opt-in only.
  - Unreachable: DGIS, BPET, VEF (except evidence_capsule), `replay::time_travel_engine` (referenced by nothing), and `control_plane::{audience_token, fork_detection, control_epoch, epoch_transition_barrier, divergence_gate, key_role_separation}`.
  - Also unreachable: `security::copilot_engine` (IBD-8) and `tools::reputation_graph_apis` (IBD-9).
  - bd-137 compat-gate APIs are implemented **three times**.
- **G-H README scenario is fiction on CLI paths.**
  - No typosquat or publisher-age computation anywhere.
  - Camouflage/GradualCreep is reached only from tests.
  - `migrate audit` never runs `trust scan`.
  - No CLI path writes the evidence ledger; `run` receipts are hash-only.
  - The per-profile camouflage threshold is a constant.
  - Safe-mode crash-loop auto-entry has no callers.
  - SSRF `monitor` blocks like `block`, and the FAQ's `mode = enforced|report-only` key does not exist (silently ignored).
- **G-I Bead compliance** (load-bearing closures since Aug-19): 3 FALSE-CLOSED (w0fc6.9, bd-3cpa, tenx3.3) and 4 OVER-CLAIMED (w0fc6.7, tenx3.4, tenx3.5, v0lgc; v0lgc is effectively false-closed per G-B); the rest (w0fc6.1/.2/.3/.4/.5/.6/.8, bd-klpse, bd-9zrqh, readme-cli-drift) VERIFIED statically.
  - tenx3.3 rollout: `lockstep_verified = true` hard-coded (`migration/rollout.rs:415`); confidence never computed; the "signature" is a SHA-256 digest.
- **G-J Unmapped plan goals** (never assessed by V1–V28):
  - performance budgets and HC-003;
  - benign false-positive rate;
  - engine pinning (a bare path dependency, which contradicts charter §2 rule 4; README:2506 claims "pinned");
  - L2 as a differential oracle (today a GREEN backfill; engine Test262 is 3 precomputed vectors);
  - IBD-8/IBD-9;
  - isolation tiers;
  - confidence half of 3×;
  - per-band floors;
  - convergence latency.

### Vision checklist deltas (Aug-20 numbering + new items)

| # | Goal | 2026-09-22 | **2026-09-23 (live)** |
|---|---|---|---|
| V1 | `run` executes guest JS | WORKING (fixture) | **PARTIAL.** Single-file only; 0/8 npm; 100k budget; default auto fails on a fresh build |
| V2 | Revocation-first execution | "unified" (w0fc6.6) | **REGRESSED.** Gate dead on default installs; fails open |
| V3 | Trust cards | WORKING | **PARTIAL.** Cards seeded; deep/audit fails by default; all `medium`; re-scan never refreshes |
| V4 | Replay + counterfactual | PARTIAL | **INTEGRITY-ONLY.** Certifies hand-authored evidence; counterfactual synthetic; no run→incident capture |
| V6 | ≥95% corpus | REGRESSED 69.82% | **RED 87.32%** (fresh, legacy-risky, single-file corpus) |
| V10 | Verifier SDK independent | PARTIAL | **BROKEN for bundles.** Cannot parse CLI `.fnbundle`; unkeyed "signature" |
| V11 | Doctor | WORKING | **PARTIAL.** Misses every first-run blocker; exit 0 on fail |
| V16 | ≥3× migration | UNMET 2.30× | **WRONG_APPROACH.** "Pass" via fsync removal; proxy metric |
| V17 | ≥10× compromise | UNPROVEN | **INVALID MEASUREMENT.** Franken leg never executes |
| V25 | Release freshness | REGRESSED | **REGRESSED.** 1,136 commits; `--method source` broken; dist never green |
| V27 | Effective coverage | PARTIAL | **NOT PROVEN.** No green CI `cargo test` ever; 10 gates never ran |
| V29 | Performance vs Node / budgets | *unassessed* | **FAIL.** 4.5× node on hello; HC-003 keyword gate |
| V30 | Module loading / ecosystem | *unassessed* | **NOT_STARTED** on the run path |
| V31 | Language correctness | *unassessed* | **FAIL.** Silent miscompile + async/generator failures; no Test262 |
| V32 | Primitives reachable from product | *unassessed* | **~43%** reachable; flagship primitives are islands |
| V33 | Engine pinning + corpus provenance | *unassessed* | **ABSENT** |
| V34 | Evidence ledger written by decisions | *unassessed* | **ABSENT** on CLI paths |

**Strict WORKING count:** V15 (no unsafe) still holds. V13 (SSRF on the native path) and the containment primitives are verified live. V1, V3 and V11 are downgraded from the Sep-22 count, and V2 has regressed. The honest summary: the *verification/trust machinery* is broad and often real, but the *runtime it is supposed to govern* cannot yet run the ecosystem the charter targets.

### Answers to the reality-check questions

1. **What works today.**
   - Single-file programs using a pattern-matched subset of 16 builtins, with real SSRF, capability, sandbox and eval containment and signed host-effect ledgers.
   - `init`, `migrate audit`, plain `trust scan`, `incident bundle`/`replay` as integrity tools, and `doctor`.
   - A recovered 87% single-file micro-corpus.
2. **What does not work.**
   - Module loading and npm packages; non-trivial compute (instruction budget); a real clock; several ES2015+ features.
   - The strict profile for ordinary code.
   - Revocation freshness on default installs.
   - CLI→SDK bundle verification; run→incident capture.
   - Deep trust intelligence (typosquat, publisher age, camouflage); the evidence ledger.
   - CI.
   - The fresh-build first run.
3. **What is blocking.**
   - The engine execution model: `require` is a compile-time recognizer, there is a deterministic-lane budget, and IFC is fail-high with no declassification. These are engine-first changes under the split contract.
   - A measurement culture that closes KPI beads on artifacts that were never executed end to end: fsync removal, a directory passed to `run`, keyword gates, PR-only gates.
   - Zero functioning CI to catch either problem.
4. **Would the open/in-progress beads close the gap?** **No.**
   - bd-28sz/bd-kx70h/family residuals can plausibly reach 95% **on this corpus**, which cannot see the module-loading, language or limits failures.
   - bd-f5b04 (TNR) does not name module loading, execution limits or language correctness.
   - bd-34d5 does not name the sidecar presence gate or the undocumented trust-scan env.
   - No open bead covered the freshness-gate regression, the fsync durability trade, the invalid 10× campaign, the SDK/CLI format split, run→incident capture, CI trigger reality, performance, reachability, or engine pinning.
5. **Vision goals with no bead before this pass:** all of V29–V34 plus G-A/G-B/G-D/G-E/G-F/G-H/G-I. They are now covered by the new epic below.

### Beads created (Phase 3a) — epic `bd-reality-20260923-26n9r` (P0)

| ID | P | Gap |
|---|---|---|
| `.1` | P0 bug | Revocation freshness gate dead/fail-open on default installs; needs a real signed revocation frontier (not file mtime) |
| `.2` | P0 bug | Restore rewrite-transaction durability (7→0 fsyncs); barrier-count test; honest re-measure; reconcile CLAIM-002 |
| `.3` | P1 bug | ≥10× campaign never executes the franken leg; positive controls, typed outcomes, Wilson bounds |
| `.4` | P0 feature | Module loading on `run`: CJS/ESM resolution, node_modules, `run <dir>`, missing builtins (engine-first) |
| `.5` | P1 feature | Execution-limits contract: instruction budget, virtual clock, console truncation, lost output, strict semantics, `process` |
| `.6` | P1 bug | Language correctness (private fields, async IIFE, generator spread, inspect formatting, globals) + executed Test262 |
| `.7` | P1 bug | SDK cannot parse CLI bundles; unkeyed SDK "signature"; CLI→SDK round-trip test |
| `.8` | P1 feature | Product run→incident capture; stop certifying hand-authored evidence; coverage metric for "100% replay" |
| `.9` | P1 bug | CI: PR-only gates never run, sibling checkout broken, invalid YAML, one honest canary job, dynamic badges |
| `.10` | P2 task | Performance vs node, measured (replace HC-003 keyword gate); cut ~130 ms fixed overhead |
| `.11` | P1 bug | First-run blockers: sidecar presence gate, undocumented trust-scan env/token, bundle key, doctor gaps |
| `.12` | P1 task | Corpus v3 (ecosystem + language + per-profile) + provenance + engine revision pinning |
| `.13` | P1 task | IFC benign false-positive rate + declassification surface |
| `.14` | P2 task | Library islands: disposition (wire/gate/retire), dedupe bd-137, reachability gate |
| `.15` | P2 feature | Make the README scenario real: typosquat, publisher age, camouflage on real data, evidence ledger writes |
| `.16` | P1 task | False-closed/over-claimed follow-ups: tenx3.3, tenx3.4, tenx3.5, w0fc6.7, w0fc6.9, closer-gate hardening |
| `.17` | P2 docs | README/CLAIMS_REGISTRY truth pass for all of the above |

Related links point to bd-f5b04, bd-28sz, bd-kx70h, bd-34d5, bd-tenx3.1/.2/.3/.4/.5, bd-v0lgc, bd-3cpa, bd-rjc2m.21 and w0fc6.6/.7/.9, so existing owners see the new evidence. Blocking edges: `.15`←`.11`, `.8`←`.7`. `br dep cycles` is clean. Evidence comments were added to bd-kx70h (fresh 87.32% breakdown), bd-v0lgc and bd-3cpa.

### Recommended order (bridge plan, highest vision impact first)

1. `.1` and `.2`: correctness and security regressions. Small, surgical, and they stop the bleeding.
2. `.9` (CI) and `.11` (first run): without them no other claim can be checked by anyone but an agent with a warm target dir.
3. `.4` → `.5` → `.6`: turn the engine into something that runs npm code. This is the product.
4. `.12` + `.13`: make the compatibility metric able to see (3), then chase 95% on a corpus that means something.
5. `.7` → `.8`: make the verifier/incident story true end to end.
6. `.3`, `.10`: re-measure the 10× and performance claims honestly.
7. `.14`, `.15`, `.16`, `.17`: wire or retire the islands, make the README scenario real, clean up the false closes, align the docs.

### Probe reproduction

- **Build:** `rch exec -- env CARGO_TARGET_DIR=<scratch>/target CARGO_PROFILE_RELEASE_DEBUG=0 cargo build --release -p frankenengine-node --bin franken-node`.
- **Probe workspace:** `init --profile balanced --out-dir .` in a scratch dir with `bun install` of lodash@4.17.21, ms@2.1.3, semver@7.6.3, minimist@1.2.8, dayjs@1.11.13, uuid@9.0.1, commander@12.1.0, express@4.21.2.
- **Run each probe with:** `FRANKEN_NODE_ENGINE_BINARY_PATH=<binary> franken-node run <file> --policy balanced --console-only`, and compare with `node <file>`.
- **Corpus:** `ops compat-corpus-run --corpus-root <copy of crates/franken-node/tests/fixtures/compat_corpus> --out <scratch>/results.json --require-node-reference`.
- **Probe programs:** the one-liners in the tables above are complete. The beads `.4`/`.5`/`.6`/`.11` specify the checked-in probe scripts that will make these runs permanent.
