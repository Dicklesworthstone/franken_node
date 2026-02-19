# Ultra Detailed TODO

## 0. Transplant Integrity
- [x] Create standalone workspace in `/dp/franken_node`.
- [x] Create dedicated extension-host crate in `/dp/franken_engine/crates/franken-extension-host`.
- [x] Copy extension-host-related Pi Rust source/docs/tests snapshot into `transplant/pi_agent_rust`.
- [x] Generate transplant manifest with deterministic file list (`transplant_manifest.txt`).
- [ ] Hash each transplanted file and persist a lockfile for tamper detection.
- [ ] Add replay script to re-sync from upstream `pi_agent_rust` and detect drift.

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
