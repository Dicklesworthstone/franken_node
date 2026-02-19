# FrankenEngine Roadmap

## Source Of Truth

- Canonical product plan for this repository: `/dp/franken_node/PLAN_TO_CREATE_FRANKEN_NODE.md`
- Canonical engine plan: `/dp/franken_engine/PLAN_TO_CREATE_FRANKEN_ENGINE.md`

This roadmap is a supporting summary. If any content here conflicts with either canonical plan, the canonical plan wins.

## Context And Purpose
FrankenEngine is an offgrowth of `pi_agent_rust`.

`pi_agent_rust` validated the host/runtime-control pattern at the agent layer. FrankenEngine extends that into full end-to-end runtime ownership so `franken_node` is not constrained by external JS engine behavior.

Program intent:
- Own the full execution stack in native Rust.
- Push alien-artifact-level performance using advanced math + systems design.
- Build a security-first extension runtime that can probabilistically detect and contain malicious untrusted JS/TS behavior before host damage.

FrankenEngine is the core substrate.
`franken_node` is the runtime and compatibility surface built on top.

## Strategic Outcomes
1. De novo native Rust execution engines inspired by QuickJS and V8 design ideas (not bindings/wrappers).
2. Runtime-level supply-chain attack resistance for untrusted extensions through Bayesian/probabilistic monitoring and automatic containment.
3. Artifact-backed performance and safety claims with reproducible evidence.
4. Practical Node/Bun replacement path for extension-heavy agentic workloads.

## Non-Negotiable Rules
- No `rusty_v8`, `rquickjs`, or equivalent binding-based core execution path.
- `/dp/franken_engine/legacy_quickjs/` and `/dp/franken_engine/legacy_v8/` are reference corpora only.
- All adaptive systems must have deterministic fallback mode.
- Every significant optimization or security action policy must include evidence artifacts.

## Methodology Stack
FrankenEngine development is explicitly driven by:

1. `$extreme-software-optimization`
- Profile first, optimize one lever at a time.
- Require baseline/profile/verify loop for each change.

2. `$alien-artifact-coding`
- Use formal decision systems (posterior inference, expected-loss minimization, calibration).
- Require evidence ledger explainability for non-trivial runtime decisions.

3. `$alien-graveyard`
- Select implementation primitives via EV scoring and risk gating.
- Prefer high-EV, fallback-safe techniques over novelty.

## Security Roadmap: Untrusted Extension Containment
### Security Vision
Create a runtime where untrusted JS/TS extensions are continuously scored for malicious likelihood and are automatically constrained or stopped before host compromise.

### Security Core
- Bayesian runtime sentinel with online posterior updates.
- Sequential/anytime-valid safety decisioning for live streams of extension behavior.
- Expected-loss action policy over actions:
  - allow
  - warn
  - challenge
  - sandbox
  - suspend
  - terminate
  - quarantine
- Full evidence ledger and replay artifacts for every containment decision.

### Security Milestones
1. Telemetry layer: hostcall intent/event capture + normalized evidence stream.
2. Inference layer: posterior update engine + calibration harness.
3. Action layer: policy actions and deterministic fallback semantics.
4. Assurance layer: benign/malicious corpus testing + false-positive/false-negative bounds.

## Performance Roadmap: Alien-Artifact Execution
### Performance Vision
Make performance a proof-carrying property, not anecdotal tuning.

### Performance Core
- Cache-aware data structures and low-allocation execution paths.
- Hot-path dispatch improvements (candidate: superinstructions).
- Hostcall pipeline optimization (candidate: lock-free queueing where profile-justified).
- Strict p95/p99 guardrails under extension churn.

### Performance Milestones
1. Baseline suite and golden outputs.
2. Hotspot profiler integration and artifact capture.
3. High-EV optimization rounds (one lever per change).
4. Regression dashboard with latency/throughput/memory budgets.

## Phased Delivery Plan
### Phase 0: Foundation (In Progress)
- Standalone split repositories: `/dp/franken_engine` (engine) + `/dp/franken_node` (product)
- Engine abstraction scaffold in `/dp/franken_engine`
- Extension-host transplant snapshot from `pi_agent_rust`

Exit gate:
- Workspace compiles, lint-clean, and reproducible scaffolding validated.

### Phase 1: Native VM Core
- Parser, AST lowering, IR, verifier
- Interpreter + object/prototype/closure model
- Initial native GC strategy

Exit gate:
- Deterministic conformance seed suite green.

### Phase 2: Security-First Extension Runtime
- Capability policy and hostcall ABI hardening
- Bayesian sentinel v1 and containment actions
- Evidence ledger + replay path

Exit gate:
- Simulated supply-chain attack scenarios are detected and contained without host compromise in harnessed tests.

### Phase 3: Performance Uplift
- Profile-driven hot-path optimization rounds
- Tail-latency stabilization under mixed extension loads
- Execution-lane routing policy maturation

Exit gate:
- Measured p95/p99 improvements vs phase baseline with behavior parity artifacts.

### Phase 4: franken_node Compatibility Surface
- Module resolution modes and runtime ergonomics
- Node/Bun compatibility layers (`process`, `fs`, `net`, subprocesses, timers)
- Operational tooling for runtime users

Exit gate:
- Targeted compatibility suite reaches release threshold.

### Phase 5: Production Readiness
- Security regression matrix
- Fuzz/property/metamorphic testing
- Progressive rollout framework (shadow -> canary -> ramp -> default)

Exit gate:
- Evidence-backed readiness report and release approval checklist complete.

## Required Evidence Artifacts
Per significant subsystem change:
- baseline benchmark report
- profile artifact (flamegraph/equivalent)
- golden output checksums
- isomorphism note
- decision contract (loss model + fallback trigger)
- reproducibility pack (`env.json`, `manifest.json`, `repro.lock`)

## Program-Level Risks And Countermeasures
- Scope explosion:
  - Countermeasure: strict phase gates and one-lever optimization discipline.
- Over-hardening performance collapse:
  - Countermeasure: profile-governed tuning with tail budgets.
- Security model drift:
  - Countermeasure: calibration audits and decision-ledger verification.
- Operability complexity:
  - Countermeasure: deterministic fallback mode and replay-first observability.

## North-Star Definition Of Done
FrankenEngine + franken_node are successful when:
- core execution is fully native Rust (no binding-led core runtime dependence)
- untrusted extensions are monitored and automatically contained under attack tests
- security and performance claims are reproducible and artifact-backed
- compatibility/reliability gates support production adoption
