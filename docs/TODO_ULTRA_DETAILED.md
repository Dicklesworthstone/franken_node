# Ultra Detailed TODO

> **STATUS (2026-09-22, reality-check truth pass):** Sections 1–5 below are
> **historical pre-engine-split planning notes**, preserved for provenance only.
> They do NOT reflect current reality and several items contradict adopted
> doctrine:
> - Section 2's "QuickJS/V8 backend lane" items violate the charter's
>   no-bindings rule (`docs/PRODUCT_CHARTER.md` §1: "Not a binding/wrapper
>   around V8, QuickJS, or any existing engine"). The engine executes native
>   Rust (IR0→IR3 lowering + baseline interpreter); no QuickJS/V8 evaluator
>   will be implemented.
> - Section 5's "command-line interface", "structured logging", and "release
>   pipeline" items are delivered (72-leaf CLI, `--structured-logs-jsonl`,
>   packaging/release surfaces) — the unchecked boxes are stale, not open work.
> - Sections 3/4 (Node/Bun parity, conformance) are now owned by the
>   compatibility-corpus program (section 13 of the master plan; gate bead
>   `bd-28sz`), not this list.
>
> The authoritative work surfaces are `.beads` (via `br`/`bv`),
> `docs/progress/REALITY_CHECK_AND_BRIDGE_PLAN.md`, `docs/CLAIMS_REGISTRY.md`,
> and `docs/TODO_ULTRA_DETAILED.md` section 6+ where marked current. Do not
> pick up unchecked items from sections 1–5 as real work.

## 0. Transplant Integrity
- [x] Create standalone workspace in `/dp/franken_node`.
- [x] Create dedicated extension-host crate in `/dp/franken_engine/crates/franken-extension-host`.
- [x] Copy extension-host-related Pi Rust source/docs/tests snapshot into `transplant/pi_agent_rust`.
- [x] Generate transplant manifest with deterministic file list (`transplant_manifest.txt`).
- [x] Hash each transplanted file and persist a lockfile for tamper detection.
- [x] Add replay script to re-sync from upstream `pi_agent_rust` and detect drift (`transplant/resync.sh` + `transplant/drift_detect.sh`).

## 1. Extension Host Core Assimilation
- [ ] Define stable `ExtensionHost` trait in `/dp/franken_engine/crates/franken-extension-host`.
- [ ] Define typed hostcall request/response model independent of source project internals.
- [ ] Port policy evaluation path from transplanted code into compile-active modules.
- [ ] Port extension manifest parsing/validation into compile-active modules.
- [ ] Port extension lifecycle orchestration (discover/load/enable/disable/unload).
- [ ] Port extension event wiring and session/event bridge.
- [ ] Port extension tool registration + execution bridge.
- [ ] Port security controls for capability scoping and denials.

## 2. JS Runtime Engine Program
- [x] Create engine abstraction crate (`/dp/franken_engine/crates/franken-engine`).
- [x] Add QuickJS/V8 backend lane placeholders and hybrid router.
- [ ] Implement QuickJS-backed real evaluator and context lifecycle.
- [ ] Implement V8-backed real evaluator and isolate lifecycle.
- [ ] Standardize cross-engine value translation and error model.
- [ ] Implement module resolver interface shared by both lanes.
- [ ] Implement hostcall bridge ABI usable by both lanes.
- [ ] Add deterministic execution mode for conformance replay.

## 3. Node/Bun Replacement Roadmap
- [ ] Implement runtime globals: `globalThis`, `console`, timers.
- [ ] Implement process surface: env, argv, cwd, exit, signals.
- [ ] Implement file system APIs parity layer.
- [ ] Implement networking APIs parity layer.
- [ ] Implement subprocess/child process APIs parity layer.
- [ ] Implement package/module resolution compatibility modes.
- [ ] Implement npm-style and bare module loading strategy.
- [ ] Add compatibility test harness against representative Node/Bun fixtures.

## 4. Parity + Conformance
- [ ] Bring over extension conformance harness as runnable suite in this workspace.
- [ ] Wire CI gates for extension host behavior parity.
- [ ] Add regression matrix per capability/provider/runtime mode.
- [ ] Add performance baseline for cold start, throughput, memory.
- [ ] Add fuzzing/property tests for hostcall and policy boundaries.

## 5. Delivery and Operational Readiness
- [ ] Add command-line interface for runtime execution and extension management.
- [ ] Add structured logging and trace exports.
- [ ] Add crash recovery and persistent session snapshots.
- [ ] Add release pipeline with checksums and signatures.
- [ ] Add installer/uninstaller lifecycle for local deployment.

## 6. franken_engine Integration (Roadmap)
- [x] **Execution Dispatcher** (`franken-node run`):
  - [x] Create `ops::engine_dispatcher` to spawn the `/dp/franken_engine` process securely.
  - [x] Implement IPC serialization of policy payloads and application limits.
  - [x] Wire up `Command::Run` in `src/main.rs`.
  - [x] Implement non-blocking bidirectional IPC for robust telemetry flow via Unix Domain Sockets.
- [x] **N-Version Oracle Harness** (`franken-node verify lockstep`):
  - [x] Create `runtime::lockstep_harness` to concurrently spawn `node`, `bun`, and `franken_engine`.
  - [x] Intercept outputs (stdout, stderr) from runtimes.
  - [x] Wire into `RuntimeOracle::run_cross_check` to detect divergence.
  - [x] Implement robust file system and network mutation tracking via `strace` wrappers and deterministic sanitization.
- [x] **Replay and Telemetry Bridge**:
  - [x] Stream execution boundaries back to `franken_node`.
  - [x] Persist real-time logs to `frankensqlite` for `time_travel_engine.rs` replay.
