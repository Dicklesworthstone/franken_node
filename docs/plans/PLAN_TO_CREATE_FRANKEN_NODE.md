# PLAN_TO_CREATE_FRANKEN_NODE

> Canonical name: **franken_node**
> Engine dependency: **franken_engine** (`/dp/franken_engine`)
> Status: Product-layer architecture charter + execution plan

## CAVEAT: Ambition-First Operating Rule
This plan is intentionally extreme. It targets category creation, not incremental tooling.

Out-of-charter behavior:
- Framing de-scoping as the default answer.
- Recommending parity-only outcomes as acceptable end state.
- Treating compatibility as the mission rather than the wedge.

In-charter behavior:
- Increase disruptive capability while preserving proof discipline.
- Make migration friction collapse while security posture increases.
- Convert every major claim into externally verifiable artifacts.

Directive alignment statement:
> The goal is to make this more ambitious, more radically innovative, and more disruptive. Contributions that reduce ambition without explicit owner direction are not helpful.

## 1. Background And Role
`franken_node` is the product and ecosystem surface built on top of `franken_engine`.

`franken_engine` owns native runtime internals, policy semantics, and trust primitives.
`franken_node` owns:
- compatibility capture from Node/Bun ecosystems
- migration and operator experience
- extension ecosystem and trust distribution surfaces
- packaging, rollout, and enterprise control planes

The strategic role of `franken_node` is to turn engine breakthroughs into mass adoption and category capture.

## 2. Core Thesis
`franken_node` must become the default choice for extension-heavy JavaScript/TypeScript execution where teams need all of the following at once:
- Node/Bun-level developer ergonomics
- materially stronger security outcomes
- deterministic explainability for high-impact decisions
- operational confidence at fleet scale

Core proposition:
- compatibility is table stakes
- trust-native operations are the differentiator
- migration velocity is the growth engine

## 3. Strategic Objective
Build `franken_node` into the category-defining runtime product layer that functionally obsoletes Node/Bun for high-trust extension ecosystems.

Category-defining disruptive floor (non-optional):
- `>= 95%` pass on targeted compatibility corpus for high-value Node/Bun usage bands.
- `>= 3x` migration throughput and confidence quality versus baseline migration patterns.
- `>= 10x` reduction in successful host compromise under adversarial extension campaigns versus baseline Node/Bun default posture.
- friction-minimized, automation-first path from install to policy-governed safe extension workloads.
- `100%` deterministic replay artifact availability for high-severity security and policy incidents.
- `>= 3` impossible-by-default product capabilities broadly adopted by production users.

If outcomes are parity-only or migration-hostile, the program is off-charter.

## 3.1 Category-Creation Doctrine
`franken_node` is not a "better Node clone". It is the category bridge between JS/TS ecosystem scale and zero-illusion trust operations.

Doctrine:
- Treat compatibility as a strategic wedge, not final destination.
- Ship trust-native workflows that incumbents cannot provide by default.
- Define benchmark language and verification standards for the category.
- Own migration ergonomics so adoption feels inevitable, not costly.
- Turn operator trust from intuition into cryptographically and statistically grounded evidence.

Category-creation test:
- If users can get the same outcomes with a thin wrapper around Node/Bun defaults, the feature is insufficient.
- If claims cannot be independently verified, the feature is insufficient.
- If migration cost remains high for real teams, the feature is insufficient.

## 3.2 Impossible-by-Default Capability Index
`franken_node` MUST productionize the following capabilities that incumbents do not offer by default:

1. Policy-visible compatibility behavior with explicit divergence receipts.
2. One-command migration audit and risk map for Node/Bun projects.
3. Signed policy checkpoints and revocation-aware execution gates.
4. Deterministic incident replay with counterfactual policy simulation.
5. Fleet quarantine propagation with bounded convergence guarantees.
6. Extension trust cards combining provenance, behavior, and revocation state.
7. Compatibility lockstep oracle across Node/Bun/franken_node.
8. Control-plane recommended actions with expected-loss rationale.
9. Ecosystem reputation graph with explainable trust transitions.
10. Public verifier toolkit for benchmark and security claims.

## 3.3 Baseline Build Strategy Decision (Hybrid, Spec-First)
`franken_node` will **not** begin with a full clean-room Bun reimplementation as the initial baseline move.

Canonical strategy:
- Use Node/Bun as behavioral reference systems and oracle targets, not as architecture templates.
- Execute spec-first compatibility capture (Essence Extraction) for prioritized high-value API/runtime bands.
- Implement product/runtime behavior natively on `franken_engine` + `asupersync` with `franken_node` trust/migration architecture from day one.
- Reuse proven implementation patterns from `/dp/pi_agent_rust` where directly accretive (policy surfaces, deterministic replay discipline, conformance-first workflows), while avoiding architecture lock-in to legacy runtimes.

Decision rationale:
- A Bun-first clone path creates architecture lock-in and delays category-defining differentiators.
- A spec-first hybrid path delivers a strong compatibility baseline quickly while preserving the trust-native design required for ATC, DGIS, BPET, VEF, and verifier economy outcomes.

## 4. Non-Negotiable Constraints
- `franken_node` depends on `/dp/franken_engine`; it does not fork engine internals.
- No local reintroduction of engine core crates in this repository.
- `franken_node` depends on `/dp/asupersync` as the control/correctness substrate for orchestration, lifecycle, and distributed control workflows.
- High-impact async control paths MUST be `Cx`-first, region-owned, cancel-correct, and obligation-tracked; ad hoc detached task patterns are off-charter.
- Console/TUI surfaces relevant to this project MUST use `/dp/frankentui` as the canonical presentation substrate.
- Any feature needing or materially benefiting from SQLite persistence MUST use `/dp/frankensqlite` as the storage substrate.
- `/dp/sqlmodel_rust` SHOULD be used for typed schema/model/query integration where it improves safety, clarity, or migration velocity.
- `/dp/fastapi_rust` SHOULD be used for service/API control surfaces where HTTP control-plane exposure is required.
- Any deviation from these substrate rules requires an explicit, signed waiver artifact with rationale, risk analysis, and expiry.
- Compatibility shims must be explicit, typed, and policy-visible.
- Line-by-line translation from Bun/Node implementations is off-charter; legacy runtimes may be used for spec extraction and conformance fixture capture only.
- Dangerous compatibility behavior must be gated by policy and auditable receipts.
- Every major claim ships with reproducible benchmark/security artifacts.
- Migration tooling must be deterministic and replayable for high-severity failures.
- Product defaults prioritize safe operation while preserving practical adoption velocity.

## 5. Method Stack (Required)
This program is intentionally driven by four complementary methodologies.

### 5.1 extreme-software-optimization (Execution Discipline)
Mandatory loop:
1. Baseline (`p50/p95/p99`, throughput, memory, cold start)
2. Profile (top hotspots only)
3. Prove behavior invariance and compatibility envelopes
4. Implement one lever
5. Verify compatibility/security artifacts
6. Re-profile

No optimization lands without artifact-backed regression safety.

### 5.2 alien-artifact-coding (Mathematical Decision Core)
Use formal decision systems for product control surfaces:
- expected-loss rollout choices
- posterior trust state updates
- confidence-aware migration recommendations
- explainable policy decisions and receipts

### 5.3 alien-graveyard (High-EV Primitive Selection)
Adopt only high-EV disruptive primitives with fallback contracts:
- EV thresholding (`EV >= 2.0`)
- failure-mode predesign
- deterministic degraded operation pathways

### 5.4 porting-to-rust (Spec-First Essence Extraction Protocol)
For compatibility surfaces, apply the porting discipline as an extraction-and-proof method:
- extract behavior into explicit specs (data shapes, invariants, defaults, errors, edge cases)
- capture Node/Bun fixture outputs as conformance baselines
- implement from spec and fixture contracts, not legacy source structure
- enforce parity and divergence visibility via lockstep oracle + artifact gates

Rule: legacy code is input to specification and oracle generation, not implementation blueprint.

## 6. Security And Trust Product Doctrine
### 6.1 Problem Statement
Developers need Node ecosystem speed, but untrusted extension supply chains remain a catastrophic risk surface.

### 6.2 Product Goal
Make high-trust runtime operation the default workflow without forcing teams to abandon JS/TS ecosystem velocity.

### 6.3 Threat Model
Adversary classes:
- malicious extension updates and maintainer compromises
- credential exfiltration and lateral movement attempts
- policy evasion via compatibility edge cases
- delayed payload activation and long-tail persistence
- operational confusion attacks exploiting non-deterministic incident handling

### 6.4 Trust-Native Product Surfaces
- extension trust cards and provenance scoring
- policy-visible compatibility mode gates
- revocation-first execution prechecks
- signed incident receipts and deterministic replay export
- autonomous containment recommendations with explicit rationale

### 6.5 Safety Guarantees Target
- bounded false-negative rate under adversarial extension corpora
- bounded false-positive rate for benign migration workloads
- deterministic replay for high-severity security events
- auditable degraded-mode semantics when trust state is stale

## 7. Performance And Developer Velocity Doctrine
Performance is a product feature, not a benchmark vanity metric.

### 7.1 Core Principles
- low startup overhead for migration and CI loops
- predictable p99 under extension churn
- bounded overhead from security instrumentation
- fast feedback for migration diagnostics and compatibility diffs

### 7.2 Candidate High-EV Product Levers (Profile-Gated)
- compatibility cache with deterministic invalidation
- lockstep differential harness acceleration
- zero-copy hostcall bridge paths where safe
- batch policy evaluation for high-frequency operations
- multi-lane scheduler tuning for cancel/timed/ready workloads

### 7.3 Required Performance Artifacts
- baseline reports with reproducible configs
- profile artifacts (flamegraphs/traces)
- before/after comparison tables
- compatibility correctness proofs for tuned paths
- tail-latency impact notes for security instrumentation

## 8. Architecture Blueprint
### 8.1 Repository And Package Topology
- Engine repository: `/dp/franken_engine`
  - `/dp/franken_engine/crates/franken-engine`
  - `/dp/franken_engine/crates/franken-extension-host`
- Product repository: `/dp/franken_node`
  - `/dp/franken_node/crates/franken-node`
- Strategic adjacent substrates:
  - TUI/console substrate: `/dp/frankentui`
  - SQLite/persistence substrate: `/dp/frankensqlite`
  - Typed SQL model substrate: `/dp/sqlmodel_rust`
  - Service/API substrate: `/dp/fastapi_rust`

### 8.2 Product Planes
- compatibility plane: Node/Bun behavior surfaces and divergence governance
- migration plane: discovery, risk scoring, automated rewrites, rollout guidance
- trust plane: policy controls, trust cards, revocation and quarantine UX
- ecosystem plane: registry, reputation graph, certification channels
- operations plane: fleet control, audit/replay export, benchmark verifier interfaces

### 8.3 Control Planes
- release control plane: staged rollout, rollback, feature-policy gating
- incident control plane: replay, counterfactual simulation, response automation
- economics control plane: expected-loss and attack-cost aware policy guidance

### 8.4 Asupersync-First Integration Doctrine
`franken_node` adopts a three-kernel architecture:
- execution kernel: `/dp/franken_engine` (language/runtime internals)
- correctness/control kernel: `/dp/asupersync` (concurrency, cancellation, remote effects, epochs, evidence)
- product kernel: `/dp/franken_node` (compatibility, migration, trust UX, ecosystem capture)

This separation is intentional: `franken_node` should not reinvent control semantics already solved by asupersync. Instead, it should map product workflows onto asupersync primitives and prove that mapping with deterministic artifacts.

### 8.5 Hard Runtime Invariants (Asupersync-Backed, Non-Negotiable)
1. **Cx-first control APIs**  
   All high-impact async operations (publish, revoke, quarantine, migrate, rollout) MUST take `&Cx` and derive effects from explicit capabilities.
2. **Region-owned lifecycle execution**  
   Control-plane services and operation trees MUST run inside owned regions; region close MUST imply quiescence.
3. **Cancellation protocol semantics**  
   Cancellation is `request -> drain -> finalize`, not task-drop behavior. Bounded cleanup must be demonstrable.
4. **Two-phase effects for high-impact operations**  
   High-impact side effects MUST be reserve/commit style with obligation resolution guarantees.
5. **Scheduler lane discipline**  
   Control-plane work MUST map to Cancel/Timed/Ready lanes with explicit starvation and p99 protection policies.
6. **Remote effects contract**  
   Remote operations MUST be capability-gated, named, idempotent, and saga-safe.
7. **Epoch and transition barriers**  
   Correctness-critical policy/key/durability transitions MUST be epoch-scoped and barrier-mediated.
8. **Evidence-by-default decisions**  
   Policy-influenced decisions MUST emit deterministic evidence ledger entries with trace witnesses.
9. **Deterministic protocol verification gates**  
   High-impact protocol paths MUST ship with deterministic lab, cancellation injection, and schedule-exploration coverage.
10. **No ambient authority pathways**  
    Any ambient network, spawn, or privileged side effect path in control-plane code is a correctness/security defect.

### 8.6 Asupersync Integration Adoption Tracks (Mandatory, Parallel Program)
**AS-A: Boundary codification and policy baseline**
- define franken_engine/asupersync/franken_node ownership map
- enumerate high-impact workflows and required asupersync primitives
- install static guardrails against ambient side effects

Exit gate:
- ownership map published
- guardrails active in CI
- baseline capability map complete

**AS-B: Control-plane execution migration**
- migrate lifecycle/rollout/revocation/quarantine orchestration to region-owned tasks
- enforce Cx-first entrypoints and cancellation protocol behavior
- replace unsafe ad hoc channels with obligation-tracked patterns for critical flows

Exit gate:
- migrated critical workflows pass deterministic replay tests
- no detached-orphan task paths on critical flows
- no obligation leaks in lab scenarios

**AS-C: Distributed control semantics**
- integrate remote named computations, idempotency, and saga semantics
- add epoch-scoped validity and transition barriers
- implement remote bulkheads and lane-aware scheduling for control traffic

Exit gate:
- degraded remote dependencies preserve p99/control liveness targets
- epoch transitions are deterministic and auditable
- idempotency/saga conformance green

**AS-D: Evidence and verification industrialization**
- make evidence ledger mandatory for policy-driven decisions
- add evidence replay validator and deterministic incident bundle export
- add virtual fault harness + cancellation injection + schedule exploration gates

Exit gate:
- policy decision replay determinism proven on canonical corpus
- deterministic fault scenarios reproducibly replayed from seed artifacts
- protocol gate suite required in release pipeline

**AS-E: Production hardening and autonomy**
- bind policy controller actions to invariant guardrails with hard precedence
- operationalize region/obligation/cancellation observability dashboards
- enforce release claims on asupersync-backed conformance artifacts

Exit gate:
- controller cannot mutate correctness envelope
- all high-impact claims backed by evidence + conformance artifacts
- production runbooks cover invariant breach/containment workflows

### 8.7 Adjacent Substrate Integration Doctrine (Mandatory)
`franken_node` must compose adjacent repositories as force multipliers, not optional experiments:

1. **Presentation stack rule (`frankentui`)**  
   Any interactive console/TUI capability that is relevant to `franken_node` must use `/dp/frankentui` components, styling primitives, and rendering discipline.
2. **Persistence stack rule (`frankensqlite`)**  
   Any feature that requires SQLite-backed persistence, replay storage, index/state catalogs, or audit/event durability must default to `/dp/frankensqlite`.
3. **Typed model stack rule (`sqlmodel_rust`)**  
   Where typed schema/query models are needed for correctness and migration safety, `/dp/sqlmodel_rust` should provide model definitions and query-shape contracts.
4. **Service stack rule (`fastapi_rust`)**  
   For exposed control-plane service endpoints (operator APIs, verifier endpoints, fleet controls), `/dp/fastapi_rust` should be the preferred API/service substrate.
5. **Waiver discipline**  
   If any feature cannot use the required substrate, a waiver must be approved with explicit threat/perf/migration rationale, bounded scope, and expiry.

Integration stance:
- We do not chase novelty by reimplementing mature adjacent capabilities in `franken_node`.
- We integrate deeply and prove cross-repo behavior with conformance, performance, and reproducibility artifacts.
- Substrate choice is policy, not preference.

### 8.8 Alignment Contracts (Scope, Terminology, Oracle, Paths, KPIs)
1. **Scope boundary contract (no ambition loss, no scope confusion)**  
   `franken_node` may define policy, orchestration, verification, and operator surfaces for advanced runtime capabilities, but native execution internals remain in `franken_engine`.  
   Translation rule: product-level optimization governance in this repo is allowed; local reimplementation of engine core execution internals is not.
2. **Terminology contract (`extension` primary, `connector/provider` mapped)**  
   Primary term for ecosystem artifacts is `extension`.  
   `connector/provider` in deep-mined sections denotes a specific extension integration class, not a separate architecture plane.
3. **Dual-oracle contract (resolve tri-runtime vs engine-reference drift)**  
   - `L1 Product Oracle`: Node/Bun/franken_node lockstep for externally visible compatibility and migration claims.  
   - `L2 Engine Boundary Oracle`: franken_engine + reference microcorpus checks for semantic boundary integrity used by product safety gates.  
   Both oracles are required; neither replaces the other.
4. **Path convention contract (resolve crate-root ambiguity)**  
   - Code paths (`src/...`, `tests/...`, `benchmarks/...`, `fuzz/...`, `fixtures/...`) are crate-root relative to `/dp/franken_node/crates/franken-node/` unless explicitly absolute.  
   - Repository program paths (`docs/...`, `artifacts/...`, `spec/...`, `vectors/...`, `.github/...`, `config/...`, `tools/...`) are repo-root relative to `/dp/franken_node/` unless explicitly absolute.  
   - `services/...` must declare scope in the owning task: repo-root service package or crate-local service module.
5. **KPI clarity contract (capability-and-evidence framing)**  
   Primary category KPI is migration-friction collapse with strong safety and verifier-backed trust guarantees.  
   Delivery framing is capability-gated and evidence-gated, not sequence-date constrained.

## 9. Multi-Track Build Program
### Track A: Product Substrate And Split Governance
- enforce engine/product split contract in CI
- establish compatibility harness skeleton
- establish migration diagnostics foundation
- establish product policy visibility surfaces

Exit gate:
- split contract enforced by CI
- deterministic baseline compatibility harness green on seed corpus
- initial migration report artifacts reproducible

### Track B: Compatibility Superset + Migration Singularity
- implement high-value Node/Bun API compatibility bands
- ship zero-to-first-safe-run migration pipeline
- add dual-layer lockstep oracle (L1 Node/Bun/franken_node + L2 engine-boundary reference checks)
- add divergence ledger with explicit policy rationale

Exit gate:
- targeted compatibility threshold met
- migration pipeline produces actionable reports + rewrite plans on representative projects
- divergence receipts generated and reproducible

### Track C: Trust-Native Ecosystem Layer
- ship signed extension registry and provenance verification flow
- ship trust cards and reputation graph v1
- ship revocation/quarantine operator workflows
- ship deterministic replay + incident bundle export

Exit gate:
- trust-native workflows operational in canary environments
- replay and audit bundle pass external verifier checks
- revocation/quarantine drills meet latency and correctness gates

### Track D: Category Benchmark + Market Capture
- publish benchmark + verifier toolkit
- run public Node/Bun/franken_node comparison campaigns
- ship enterprise governance integration surfaces
- ship operator copilot recommendations with expected-loss rationale

Exit gate:
- benchmark and verifier publicly consumable
- at least one independent external replication of headline claims
- enterprise pilot adoption shows measurable security/velocity lift

### Track E: Frontier Industrialization
- ship frontier programs at production reliability
- harden ecosystem network effects and adoption funnels
- scale global support and compliance evidence channels

Exit gate:
- multiple impossible-by-default capabilities adopted in production
- category benchmark adoption outside project core team
- sustained red-team delta and migration velocity advantages

## 9A. Idea-Wizard Top 10 Initiatives (Adopted)
1. **Compatibility Envelope With Explicit Divergence Ledger**  
   Build a deterministic compatibility envelope that covers high-value Node/Bun behavior while making intentional divergences first-class, policy-visible, and signed. This keeps trust boundaries explicit and avoids silent behavior drift.

2. **Migration Autopilot (Audit -> Rewrite -> Validate -> Rollout)**  
   Provide one-command migration workflows that inventory APIs, detect risk hotspots, propose transformations, run compatibility validation, and emit rollout guidance with confidence grades.

3. **Trust Cards For Extensions And Publishers**  
   Surface provenance, behavioral telemetry, revocation status, and policy constraints in a single explainable trust model consumable by both humans and automation.

4. **Dual-Layer Lockstep Oracle (L1 Product + L2 Engine Boundary)**  
   Run Node, Bun, and franken_node in synchronized scenarios for externally visible behavior (L1), and run franken_engine boundary corpora against reference semantics for runtime-integrity guardrails (L2).

5. **Policy-Visible Compatibility Shims**  
   Any behavior shim must be typed, auditable, and policy-gated, so operators can choose compatibility level by risk appetite with full traceability.

6. **Fleet Quarantine UX + Control Plane**  
   Turn engine-level containment into operator-grade workflows with global scope, blast-radius views, convergence indicators, and rollback controls.

7. **Secure Extension Distribution Network**  
   Build a signed registry and distribution model with revocation propagation and reputation linkage to reduce supply-chain compromise windows.

8. **Operator Safety Copilot**  
   Offer live recommended actions with expected-loss rationale, confidence context, and deterministic rollback commands.

9. **Economic Trust Layer**  
   Quantify attack-cost amplification and privilege-risk pricing so trust policy tuning is economically grounded instead of threshold folklore.

10. **Category Benchmark And Standard Ownership**  
    Define and maintain the benchmark and verification standards for secure extension runtime quality, then make external adoption part of product strategy.

Recommended dependency order:
1. Compatibility envelope + divergence ledger
2. Migration autopilot
3. Dual-layer lockstep oracle (L1 + L2)
4. Policy-visible compatibility shims
5. Trust cards
6. Secure extension distribution network
7. Fleet quarantine UX + control plane
8. Operator safety copilot
9. Economic trust layer
10. Category benchmark and standard ownership

## 9B. Alien-Graveyard Enhancement Map (Per Top 10)
1. **Compatibility envelope**  
   Apply typed-state transition primitives and session-type protocol checks to compatibility pathways so every shim has legality proofs and deterministic failure modes.

2. **Migration autopilot**  
   Use incremental/self-adjusting computation and deterministic artifact graphs so large project migrations re-run quickly and reproducibly.

3. **Trust cards**  
   Add authenticated data structures and transparency-style append-only proofs for trust evidence lineage.

4. **Lockstep oracle**  
   Use deterministic simulation and delta-debugging reductions to converge quickly on minimal divergence fixtures.

5. **Policy-visible shims**  
   Use policy-as-data signatures and attenuation semantics so shim activation is cryptographically constrained and auditable.

6. **Fleet quarantine control**  
   Use anti-entropy reconciliation and bounded degraded-mode semantics under partition.

7. **Secure extension distribution**  
   Use key-transparency and threshold-signing flows for high-impact trust operations.

8. **Operator safety copilot**  
   Apply VOI-based ranking for recommendations so operator attention goes to highest expected impact actions.

9. **Economic trust layer**  
   Use decision-theoretic expected-loss and robust posterior updates for pricing and policy recommendations.

10. **Benchmark ownership**  
    Use conformance vectors + external verifier contracts to force reproducible claim standards.

## 9C. Alien-Artifact Enhancement Map (Per Top 10)
1. **Compatibility envelope**  
   Add proof-carrying compatibility claims where each shim publishes invariance evidence and explicit divergence rationale.

2. **Migration autopilot**  
   Turn rewrite suggestions into hypothesis-tested transformations with confidence intervals and rollback receipts.

3. **Trust cards**  
   Decompose trust deltas into posterior components and expose counterfactual action impacts.

4. **Lockstep oracle**  
   Require causal trace equivalence reports and deterministic replay envelopes for each divergence decision.

5. **Policy-visible shims**  
   Encode non-interference and monotonicity checks as machine-verifiable policy compiler outputs.

6. **Fleet quarantine control**  
   Attach probabilistic SLO proofs for containment latency and convergence quality.

7. **Secure distribution network**  
   Emit cryptographic decision receipts and inclusion proofs for trust transitions.

8. **Operator copilot**  
   Provide expected-loss vectors and uncertainty bands for each recommended action.

9. **Economic trust layer**  
   Maintain posterior attacker ROI models and publish calibration diagnostics.

10. **Benchmark ownership**  
    Require statistical rigor (confidence intervals, reproducibility guarantees, verifier receipts) for headline claims.

## 9D. Extreme-Software-Optimization Enhancement Map (Per Top 10)
Global rule:
- Baseline first
- Profile top hotspots
- Implement one lever per change
- Validate compatibility + security invariance
- Re-measure with tail metrics

1. **Compatibility envelope**  
   Profile shim dispatch overhead and reduce with precompiled decision DAGs where safe.

2. **Migration autopilot**  
   Optimize scan and transform throughput with deterministic batching and cache reuse.

3. **Trust cards**  
   Optimize trust-card materialization with incremental updates and bounded recomputation.

4. **Lockstep oracle**  
   Reduce differential harness cost with streaming normalization and parallel fixture evaluation.

5. **Policy-visible shims**  
   Optimize policy evaluation path while preserving deterministic rule order.

6. **Fleet quarantine control**  
   Optimize propagation path latency and conflict reconciliation fast paths.

7. **Secure distribution network**  
   Optimize signature/provenance verification at scale with batched pipelines.

8. **Operator copilot**  
   Optimize recommendation latency for interactive operation budgets.

9. **Economic trust layer**  
   Optimize model update and scoring hot paths under heavy event streams.

10. **Benchmark ownership**  
    Optimize benchmark runner determinism and throughput without weakening rigor.

## 9E. FCP-Spec-Inspired Additions (Product-Layer Adaptation)
1. Canonical object identity discipline for product trust artifacts.
2. Deterministic serialization and signature preimage contracts for operator receipts.
3. Checkpointed policy frontier for release channels and rollback resistance.
4. Capability token delegation chains for migration and control-plane actions.
5. Key-role separation and owner-signed operational attestations.
6. Session-authenticated data plane for high-throughput control traffic.
7. Revocation freshness semantics for product-level execution gates.
8. Zone-style trust segmentation for team/project/tenant boundaries.
9. Stable observability and error taxonomy across product surfaces.
10. Conformance/golden-vector migration gates for interop stability.

## 9F. Moonshot Bets: Top 15 Category-Shift Initiatives
1. Migration singularity engine (automation-first, low-friction execution).
2. Continuous compatibility theorem prover for high-value surfaces.
3. Live exploit market simulator for policy stress-testing.
4. Enterprise policy autopilot with formal override governance.
5. Distributed trust ledger with external notarization hooks.
6. Autonomous incident commander with deterministic action replay.
7. Cross-runtime semantic compiler producing compatibility adapters with proofs.
8. Runtime insurance mode with quantified blast-radius caps.
9. One-click fleet hardening with signed rollout proofs.
10. Public adversarial olympiad benchmark infrastructure.
11. Extension provenance exchange protocol with third-party attesters.
12. Instant rollback mesh with global monotonic safety guarantees.
13. Adaptive reputational throttling for suspicious artifact publishers.
14. Self-healing migration pipeline using counterfactual failure analysis.
15. Universal verifier SDK used by customers, auditors, and researchers.

## 9G. FrankenSQLite-Spec-Inspired Additions (Product-Layer Adaptation)
1. Capability-context-first product runtime APIs.
2. Cancellation as a strict protocol for all long-running orchestration tasks.
3. Obligation-tracked two-phase workflows for critical publish/rollback paths.
4. Deterministic lab runtime for migration/control-plane race exploration.
5. Expected-loss policy controller guarded by anytime-valid monitors.
6. Epoch-scoped validity windows and key derivation for trust transitions.
7. Explicit remote-effects contracts with idempotency and sagas.
8. Scheduler lanes + bulkheads for p99 stability.
9. Three-tier integrity strategy + append-only tamper-evident decision stream.
10. O(delta) anti-entropy reconciliation + proof-carrying recovery artifacts.

## 9H. Frontier Programs (Adopted, Category-Defining)
1. **Migration Singularity Program**  
   Drive mass migration by converting compatibility uncertainty into deterministic, machine-checked migration plans with rollback receipts.

2. **Trust Fabric Program**  
   Operationalize signed trust artifacts, revocation-first execution, and rapid global containment in product workflows.

3. **Verifier Economy Program**  
   Make external verification easy and default so product claims are constantly audited by independent actors.

4. **Operator Intelligence Program**  
   Ship expected-loss-aware control recommendations with deterministic action replays.

5. **Ecosystem Network Effects Program**  
   Build registry + reputation + compliance evidence loops that compound adoption and lock in trust advantages.

## 9I. FCP Deep-Mined Expansion Set (Accretive + Complementary)
Terminology mapping for this section:
- `connector/provider` means extension integration class within the `franken_node` ecosystem model.
- all trust/lifecycle controls here apply to extension artifacts and their integration runtimes.

1. **Connector lifecycle state machine as product contract**  
   **Entails:** Define a strict lifecycle contract for every connector/provider instance (`discovered -> verified -> installed -> configured -> active`) with explicit non-happy-path states (`failed`, `paused`, `stopped`) and transition invariants.  
   **How It Works:** Persist lifecycle state in control-plane objects, enforce transition guards in one central state machine engine, and require every operational API to validate lifecycle preconditions before execution.  
   **Why Compelling:** Incidents become mechanically diagnosable because operator and automation tooling can reason about exact state and legal next actions instead of inferring behavior from logs.  
   **Rationale:** FCP-style lifecycle formalization collapses operational ambiguity and makes restart, rollback, and quarantine workflows deterministic and automatable.

2. **Required connector method surface and compliance harness**  
   **Entails:** Standardize a non-optional method contract (`handshake`, `describe`, `introspect`, `capabilities`, `configure`, `simulate`, `invoke`, `health`, `shutdown`) with versioned schemas and behavior-level expectations.  
   **How It Works:** Build a protocol conformance harness that runs fixture suites against every connector build and blocks registry publication unless all required methods and semantics pass.  
   **Why Compelling:** Ecosystem quality scales without manual review bottlenecks because baseline reliability becomes a machine-enforced gate.  
   **Rationale:** A hard method contract eliminates adapter drift and turns "compatible in practice" claims into verifiable, repeatable outcomes.

3. **Canonical externalized connector state with explicit model type**  
   **Entails:** Promote connector state to canonical objects with explicit state model declaration (`stateless`, `singleton_writer`, `crdt`) and stable sequence semantics.  
   **How It Works:** Persist state roots and append updates as content-addressed objects; treat local process memory as cache only; route failover/migration/resume through canonical state reads.  
   **Why Compelling:** Recovery, migration, and debugging no longer depend on hidden local files or in-memory cursors that disappear on restart.  
   **Rationale:** Externalized state is the foundation for deterministic operations, auditable replay, and true multi-node continuity.

4. **Lease-fenced single-writer state updates**  
   **Entails:** Require fencing tokens (`lease_seq`, `lease_object_id`) for all single-writer state mutations and reject stale or unfenced writes.  
   **How It Works:** A lease service issues monotonic writer leases; state verifiers compare incoming fence sequence against latest known lease and fail closed on regression.  
   **Why Compelling:** Duplicate side effects and race-induced corruption become structurally impossible rather than "rare bugs."  
   **Rationale:** Lease fencing is the clean, distributed primitive for enforcing write exclusivity without brittle lock coupling.

5. **State snapshotting and schema-versioned migration hints**  
   **Entails:** Add snapshot policies and explicit state schema versions for long connector-state chains, plus declarative migration hints between schema generations.  
   **How It Works:** Trigger snapshots at update/byte thresholds, keep append-only delta history for audit, and execute versioned migration routines during connector upgrade paths with receipts.  
   **Why Compelling:** Cold-start replay stays bounded while preserving full forensic history and upgrade determinism.  
   **Rationale:** Unbounded chains eventually become an operational tax; snapshot + schema versioning keeps scale and safety aligned.

6. **Four-tier sandbox profiles with strict-plus isolation lane**  
   **Entails:** Define profile tiers (`strict`, `strict_plus`, `moderate`, `permissive`) with explicit resource and syscall budgets, filesystem scopes, and process controls.  
   **How It Works:** Compile profile policy into OS-native or microVM isolation backends, then bind connector classes to minimum required profile by declared risk category.  
   **Why Compelling:** Security posture becomes configurable without being vague; teams can adopt strong defaults while preserving practical rollout options.  
   **Rationale:** A tiered model prevents lowest-common-denominator security and makes high-risk connectors pay an isolation tax by design.

7. **Network Guard as mandatory egress choke point**  
   **Entails:** Route connector egress through a first-class policy engine that controls HTTP and TCP destinations, DNS resolution, and identity pinning.  
   **How It Works:** Connectors request outbound access via signed egress intents; guard applies host/port/cidr/SNI/SPKI policy and records allow/deny decisions as audit artifacts.  
   **Why Compelling:** SSRF and lateral-movement paths are mechanically constrained, and post-incident network forensics are complete.  
   **Rationale:** Centralized egress control is the highest-leverage runtime defense against compromised extension behavior.

8. **Fail-closed manifest negotiation and interface-hash binding**  
   **Entails:** Treat connector admission as protocol negotiation with SemVer validation, required-feature checks, bounded transport declarations, and interface-hash identity binding.  
   **How It Works:** Admission verifier resolves compatibility contracts before activation; unknown required features or invalid interface hash immediately hard-fail connector startup.  
   **Why Compelling:** Incompatibility failures are surfaced at install/activation time instead of appearing later as runtime surprises.  
   **Rationale:** Fail-closed negotiation preserves trust and eliminates silent behavior drift across versions.

9. **Supply-chain policy beyond signature-valid checks**  
   **Entails:** Extend artifact trust from simple signatures to threshold signing, transparency inclusion, provenance attestations, and trusted-builder policies.  
   **How It Works:** Installation pipeline verifies signature quorum and policy-required provenance claims, then binds accepted trust evidence into connector trust cards and revocation graph state.  
   **Why Compelling:** Compromise resistance improves materially because attacker success now requires defeating multiple independent trust controls, not one key.  
   **Rationale:** Signature validity is necessary but insufficient; robust supply-chain trust requires multi-signal verification.

10. **Activation pipeline and crash-loop rollback automaton**  
    **Entails:** Standardize activation as a deterministic protocol with explicit startup stages and automatic rollback behavior when health gates fail repeatedly.  
    **How It Works:** Orchestrator executes sandbox creation, ephemeral secret injection, handshake, capability issuance, and health stabilization checks; crash-loop detector reverts to pinned known-good artifact.  
    **Why Compelling:** Operators get safe self-healing behavior under bad releases without manual firefighting.  
    **Rationale:** Deterministic activation + rollback reduces MTTR and prevents cascading instability during ecosystem updates.

11. **Revocation chain + safety-tier freshness semantics**  
    **Entails:** Model revocations as monotonic chain heads and define freshness requirements by safety tier (`safe`, `risky`, `dangerous`) with explicit degraded-mode policy.  
    **How It Works:** Execution gate checks token revocation sequence against local head freshness; risky/dangerous actions fail unless freshness policy is satisfied or explicitly overridden under audited rules.  
    **Why Compelling:** Offline/degraded operation stays practical while never pretending trust state is fresher than it is.  
    **Rationale:** Freshness semantics turn revocation from a best-effort signal into a hard security contract.

12. **Generic leased execution for risky side effects and migration**  
    **Entails:** Apply lease-backed ownership to risky operation execution, state writes, and migration transfers to prevent split-brain execution.  
    **How It Works:** Deterministic coordinator selection issues short-lived leases with quorum signatures; workers must present current lease evidence for execution and handoff transitions.  
    **Why Compelling:** Duplicate execution and thrash migration loops are prevented by protocol, not timing luck.  
    **Rationale:** Leases are the minimal distributed primitive that gives deterministic ownership in partially connected fleets.

13. **Device-aware execution planner**  
    **Entails:** Introduce explicit device profiles and placement policies so workload routing can account for capability, latency, risk class, and resource pressure.  
    **How It Works:** Planner scores candidate nodes using deterministic policy weights and chooses best-fit targets with transparent tie-breakers and fallback policies.  
    **Why Compelling:** Heavy and security-sensitive tasks land on the right hardware automatically, improving performance and reducing risk.  
    **Rationale:** Static placement assumptions break at scale; policy-driven placement is required for predictable fleet behavior.

14. **Offline capability SLO with predictive pre-staging and repair**  
    **Entails:** Define measurable offline-recoverability objectives and operationalize them with pre-staging and background repair loops.  
    **How It Works:** Continuously track per-object local coverage, pre-stage likely-needed artifacts from usage priors, and run bounded repair cycles to restore policy targets.  
    **Why Compelling:** "Works offline" becomes a measurable reliability commitment instead of marketing language.  
    **Rationale:** Quantified offline SLOs create product differentiation and force disciplined resilience engineering.

15. **Admission control and quarantine-by-default object pipeline**  
    **Entails:** Add per-peer resource budgets, anti-amplification limits, and quarantine-first treatment for unreferenced/unproven objects.  
    **How It Works:** Ingress checks bytes/symbol/auth/decode budgets before parsing; unknown objects enter bounded quarantine and are promoted only via authenticated reachability or policy pin with schema validation.  
    **Why Compelling:** DoS, amplification, and storage-pollution attacks become much harder while preserving safe ingest paths.  
    **Rationale:** Early admission gating is cheaper and safer than downstream cleanup after malicious amplification succeeds.

16. **Control-plane retention classes and replay-ready object model**  
    **Entails:** Classify control-plane artifacts into `required` and `ephemeral` retention classes with explicit persistence obligations.  
    **How It Works:** Persist all safety-critical request/decision/receipt/revocation/audit objects in canonical envelopes; allow health/status chatter to remain ephemeral by policy.  
    **Why Compelling:** Forensics and replay remain complete without paying full storage cost for low-value noise.  
    **Rationale:** Retention classing aligns audit completeness with cost discipline and avoids accidental evidence loss.

17. **Session-authenticated control channel with replay windows**  
    **Entails:** Establish a dedicated authenticated control channel with ordered framing, monotonic sequencing, bounded replay windows, and parser hard limits.  
    **How It Works:** Bind channel security to session key schedule, reject out-of-window or non-monotonic frames, and enforce per-connection decode budgets.  
    **Why Compelling:** High-frequency control traffic remains robust under replay and parser-exhaustion attack patterns.  
    **Rationale:** Control-plane integrity is non-negotiable; weak framing is a systemic failure domain.

18. **Stable telemetry namespace and AI-recovery error contract**  
    **Entails:** Publish strict metrics/error schema with stable names, code ranges, trace correlation IDs, and machine-readable recovery hints.  
    **How It Works:** Enforce schema in CI and runtime validators; errors include retryability and backoff guidance; dashboards and agents consume one canonical vocabulary.  
    **Why Compelling:** Autonomous operators can react safely and consistently across versions and environments.  
    **Rationale:** If telemetry and errors are unstable, automation regresses and incident response quality collapses.

19. **Profile-based conformance claims plus adversarial corpus requirements**  
    **Entails:** Define conformance profiles (MVP/Full) with mandatory test suites, interop expectations, and adversarial fuzz corpus gates for release claims.  
    **How It Works:** Release pipeline maps each artifact to profile checklist evidence; unsupported claims are automatically blocked from publication metadata.  
    **Why Compelling:** Market-facing trust claims become defendable and independently verifiable.  
    **Rationale:** Profile-based claims prevent overstatement and keep ambition tied to demonstrated capability.

20. **CDDL-like schema contracts plus golden vectors for cross-impl parity**  
    **Entails:** Ship formal object schemas and canonical golden vectors for serialization, object ID derivation, signatures, and framing.  
    **How It Works:** Cross-language test harnesses validate byte-level equivalence against published vectors on every implementation update.  
    **Why Compelling:** Third-party verifiers and alternative implementations can check behavior without source-code trust assumptions.  
    **Rationale:** Interoperability and verifier economy require normative byte contracts, not prose-only specifications.

## 9J. FrankenSQLite Deep-Mined Expansion Set (Accretive + Complementary)
1. **Deterministic evidence ledger for every policy-influenced decision**  
   **Entails:** Capture every high-impact policy decision as a structured evidence entry containing candidates considered, constraints applied, selected action, and trace witnesses.  
   **How It Works:** Emit deterministic ledger records from control-plane decision points, keep ordering stable, and include replay pointers so a verifier can recompute why the same choice was made.  
   **Why Compelling:** You get explainable autonomy where operators can audit why the system acted, not just what happened.  
   **Rationale:** FrankenSQLite's evidence-ledger concept is the missing bridge between advanced policy automation and production trust.

2. **Hard separation between correctness invariants and tunable policy knobs**  
   **Entails:** Define an immutable correctness envelope (security/isolation/trust semantics) and a separate tunable policy surface (throughput/latency/cost knobs).  
   **How It Works:** Controller APIs are constrained by capability boundaries and schema validation so performance tuners cannot alter correctness rules even accidentally.  
   **Why Compelling:** Teams can pursue aggressive optimization without risking silent erosion of core safety guarantees.  
   **Rationale:** Explicit separation prevents "smart controller drift" from turning reliability tuning into hidden correctness regressions.

3. **Dual-statistics control model (Bayesian for ranking, anytime-valid for guarantees)**  
   **Entails:** Run two statistical tracks: Bayesian posteriors for decision ranking and anytime-valid bounds for guarantee-bearing gates.  
   **How It Works:** Recommendation engines consume posterior expectations, but safety-critical approvals must pass anytime-valid guardrails that remain valid under optional stopping.  
   **Why Compelling:** You get fast, adaptive policy optimization without sacrificing mathematically defensible guarantees.  
   **Rationale:** This fusion preserves both practical intelligence and formal safety discipline under dynamic workloads.

4. **Monotonic hardening autopilot for trust artifacts**  
   **Entails:** Build an autopilot that escalates hardening when evidence worsens and only relaxes through explicit, audited governance paths.  
   **How It Works:** Guardrail rejection triggers one-way elevation of redundancy/verification policy; hardening actions append protection artifacts and never rewrite canonical trust history.  
   **Why Compelling:** The system self-defends under stress instead of dithering around static thresholds.  
   **Rationale:** Monotonic safety pressure is a strong anti-fragility property and directly supports category-defining security claims.

5. **Proof-carrying repair and reject semantics**  
   **Entails:** Require proof artifacts for reconstruction, repair, and suspicious-object rejection/promotions in high-assurance paths.  
   **How It Works:** Decode/repair pipeline emits machine-checkable proof bundles; admission and promotion logic can require proofs before state transitions.  
   **Why Compelling:** Operators and external verifiers can independently validate remediation correctness during incidents.  
   **Rationale:** Proof-carrying operations convert opaque repair heuristics into auditable, reproducible trust decisions.

6. **Content-derived deterministic encoding for distributed artifact regeneration**  
   **Entails:** Derive encoding/repair schedule seeds directly from object identity and policy version, not coordinator-local randomness.  
   **How It Works:** Any compliant node can regenerate the same protection artifacts for identical content/config and validate equivalence via conformance tests.  
   **Why Compelling:** Distributed repair gets simpler, more robust, and coordination-light under outages or node churn.  
   **Rationale:** Deterministic regeneration is a compounding resilience lever for large fleets.

7. **Object-class-specific coding and transport profiles**  
   **Entails:** Define policy classes with distinct symbol sizes, overhead budgets, and fetch strategies for critical markers versus bulk artifacts.  
   **How It Works:** Profile registry maps object class to transport/coding defaults; benchmark evidence drives profile tuning and publication updates.  
   **Why Compelling:** Critical trust objects can be over-protected while high-volume telemetry stays efficient, avoiding one-size performance penalties.  
   **Rationale:** Workload-specific policy is necessary for both safety and performance at scale.

8. **Bottomless trust history via tiered storage contracts (L1/L2/L3)**  
   **Entails:** Maintain unlimited historical trust/replay evidence through hot/warm/cold tiering with explicit retrievability contracts.  
   **How It Works:** Keep active artifacts local, offload cold history to remote tier, and enforce retrievability-before-eviction proofs for any local retirement step.  
   **Why Compelling:** You preserve deep forensic and replay value without forcing hot-path storage bloat.  
   **Rationale:** Durable long-horizon evidence is a strategic moat for security-focused platform adoption.

9. **Durability modes as explicit product behavior (`local` vs `quorum`)**  
   **Entails:** Expose durability mode as a first-class operator control with explicit semantics and claim boundaries.  
   **How It Works:** `local` mode validates local persistence contracts; `quorum(M)` mode requires remote/peer acknowledgements before durable success claims are allowed.  
   **Why Compelling:** Teams can choose velocity or assurance intentionally instead of relying on implicit defaults.  
   **Rationale:** Explicit durability tiers align runtime behavior with business risk tolerance and trust posture.

10. **Remote effects must be capability-gated, named, idempotent, and saga-safe**  
    **Entails:** Forbid ambient network behavior; every remote operation must be declared, capability-authorized, idempotent under retry, and compensation-aware for multi-step flows.  
    **How It Works:** Remote registry accepts only named computations; requests carry idempotency keys and epoch context; multi-step workflows execute as deterministic sagas with compensations.  
    **Why Compelling:** Retry storms and partial-failure edge cases become manageable and auditable instead of chaotic.  
    **Rationale:** Remote side effects are the biggest hidden complexity in distributed control planes; strict contracts are mandatory.

11. **Global remote bulkhead to prevent retry-storm self-DoS**  
    **Entails:** Run all remote fetch/upload/anti-entropy operations behind a global in-flight budget and backpressure policy.  
    **How It Works:** Scheduler enforces remote caps and queueing strategy; degraded dependencies trigger bounded concurrency instead of unbounded retry fan-out.  
    **Why Compelling:** Core runtime responsiveness survives upstream outages and network turbulence.  
    **Rationale:** Bulkhead isolation is a proven high-EV pattern for preserving system liveness under partial failure.

12. **Epoch-scoped validity windows for trust artifacts and remote config**  
    **Entails:** Bind artifact validity and remote durability contracts to monotonic epochs with fail-closed checks for future-epoch inputs.  
    **How It Works:** Control plane maintains epoch pointer in canonical manifest state; validators reject artifacts outside valid window and prevent mixed-epoch request acceptance.  
    **Why Compelling:** Configuration/key transitions remain coherent across distributed participants, preventing split-policy ambiguity.  
    **Rationale:** Epoch discipline is the clean mechanism for safe rolling transitions in trust-sensitive systems.

13. **Epoch transition barriers with participant quiescence**  
    **Entails:** Treat epoch changes as coordinated barriers across core services with drain requirements and explicit abort semantics.  
    **How It Works:** Coordinator requests barrier arrival from critical participants, verifies quiescence, commits epoch advance atomically, or aborts transition on timeout/cancellation.  
    **Why Compelling:** No high-impact action can straddle incompatible trust epochs, eliminating a common distributed correctness hazard.  
    **Rationale:** Barriered transitions are required for deterministic reconfiguration under load.

14. **Append-only marker stream as the atomic truth of control history**  
    **Entails:** Store high-impact control events in fixed-record append-only marker streams with dense sequence invariants and tamper-evident chaining.  
    **How It Works:** Marker IDs are domain-separated hashes over canonical record prefixes; readers gain O(1) sequence lookup and deterministic replay anchor points.  
    **Why Compelling:** Incident event sequences and rollback boundaries become precise, fast to query, and cryptographically checkable.  
    **Rationale:** A clear atomic truth stream is foundational for robust audit, replay, and fleet consistency checks.

15. **MMR-backed prefix/inclusion proofs for fleet history equivalence**  
    **Entails:** Add optional Merkle Mountain Range checkpoints over marker streams to support compact history proofs.  
    **How It Works:** Nodes exchange MMR roots and proof paths to verify shared prefixes or locate divergence in logarithmic time and proof size.  
    **Why Compelling:** Large fleets can verify consistency rapidly without expensive full-history scans.  
    **Rationale:** Compact cryptographic proofs are essential for scalable verifier-economy workflows.

16. **Single mutable root pointer + crash-safe atomic publication protocol**  
    **Entails:** Constrain mutable authority to one root pointer and enforce crash-safe update protocol (`write temp -> fsync temp -> rename -> fsync dir`).  
    **How It Works:** All state transitions publish new immutable objects, then atomically switch root pointer; bootstrap checks verify root authenticity before adoption.  
    **Why Compelling:** Failure recovery is cleaner because partial writes cannot create ambiguous multi-root authority states.  
    **Rationale:** Minimal mutability is a strong architectural simplifier and reliability amplifier.

17. **Rebuildable-cache doctrine for product state materializations**  
    **Entails:** Explicitly mark caches as derived state and require deterministic rebuild paths from canonical trust artifacts.  
    **How It Works:** Recovery and integrity tooling can discard and regenerate caches on demand; no cache value is permitted to become irrecoverable source-of-truth state.  
    **Why Compelling:** Operational repair and corruption response become simpler and safer.  
    **Rationale:** Source/derived discipline avoids hidden coupling and prevents subtle data-authority drift.

18. **Deterministic virtual-network fault labs for protocol hardening**  
    **Entails:** Add deterministic virtual transport testing with seeded drop/reorder/corrupt behaviors for control and replication workflows.  
    **How It Works:** Lab runtime replays identical fault schedules from seed artifacts and supports schedule exploration for concurrency/failure edge cases.  
    **Why Compelling:** Hard distributed bugs become reproducible and fixable, dramatically improving engineering velocity on reliability features.  
    **Rationale:** Deterministic fault labs are a prerequisite for confidence in ambitious distributed control logic.

19. **Cancellation-complete protocol discipline with obligation closure proofs**  
    **Entails:** Enforce request -> drain -> finalize cancellation protocol and treat unresolved obligations as correctness incidents with deterministic evidence.  
    **How It Works:** Critical workflows use two-phase tracked channels and obligation ledgers; cancellation injection tests verify no leaks, no ghost state, no half-commit outcomes.  
    **Why Compelling:** Operational interrupts and failures become safe routine events instead of latent corruption vectors.  
    **Rationale:** Cancel correctness is core infrastructure quality, not a nicety, in highly concurrent systems.

20. **Lane-aware scheduling as a formal product SLA mechanism**  
    **Entails:** Formalize Cancel/Timed/Ready lanes as explicit SLA controls tied to p99 latency, cleanup responsiveness, and background fairness budgets.  
    **How It Works:** Task classes map to lanes with required checkpoint frequency and bulkhead/rate-limit controls; telemetry reports lane health and starvation regressions.  
    **Why Compelling:** Foreground priority guarantees and safety-critical cleanup remain reliable even during heavy background churn.  
    **Rationale:** Lane semantics convert scheduler internals into product-grade operational guarantees.

## 9K. Idea-Wizard x Alien-Artifact x Alien-Graveyard Radical Expansion Set (Top 15)
1. **Proof-carrying speculative execution fabric for extension code paths**  
   **Entails:** Build a product-side speculative execution governance subsystem that can aggressively optimize extension-host hot paths through franken_engine-exposed controls while requiring proof artifacts that every speculative transform preserves declared semantics and policy boundaries.  
   **How It Works:** The optimizer governor emits transform plans plus proof receipts (invariants, preconditions, fallback guards) and activates only through approved franken_engine interfaces when runtime validators confirm guard satisfaction; on guard failure, execution degrades to safe baseline paths with deterministic receipts.  
   **Why Compelling:** This creates a rare combination of "faster than baseline under normal load" and "never silently wrong under edge conditions," which directly addresses the usual speed-vs-safety tradeoff.  
   **Rationale:** Alien-artifact-level performance claims are strongest when every aggressive optimization is accompanied by machine-checkable correctness contracts, not informal confidence.

2. **Bayesian adversary graph with pre-incident quarantine orchestration**  
   **Entails:** Model extension publishers, artifacts, dependency edges, behavior signals, and runtime actions as a continuously updated adversary graph with Bayesian risk propagation.  
   **How It Works:** The graph ingests provenance, telemetry, and behavior anomalies, then computes posterior compromise probabilities per artifact and per actor; risk scores automatically trigger progressive controls (throttle, isolate, revoke, quarantine) via policy thresholds and signed control decisions.  
   **Why Compelling:** Instead of waiting for known-bad signatures, the platform can proactively contain likely threats before blast radius expands.  
   **Rationale:** Supply-chain defense is fundamentally probabilistic and graph-structured; explicit Bayesian graph control is the mathematically coherent way to operationalize that reality.

3. **Deterministic time-travel runtime for extension host incidents**  
   **Entails:** Introduce full-fidelity deterministic capture and replay for extension-host execution, including scheduler decisions, capability checks, I/O intents, and policy outcomes.  
   **How It Works:** Runtime emits canonical event streams into `frankensqlite` with strict sequencing and replay tokens; incident tooling can reconstruct exact execution event sequences and step backward/forward through decision points with state snapshots.  
   **Why Compelling:** Root-cause analysis shifts from guesswork to deterministic forensic reconstruction, slashing MTTR and improving confidence in fixes.  
   **Rationale:** Category-defining security platforms need replay as a first-class primitive; without deterministic time travel, high-stakes reliability claims remain weak.

4. **Capability-carrying extension artifact format (policy as code, not metadata)**  
   **Entails:** Replace loose manifest semantics with a signed artifact format that embeds capability intent, resource envelopes, remote-effects declarations, and trust policy references as enforceable contracts.  
   **How It Works:** Admission validates signatures, schema, capability scopes, and policy bindings; runtime then enforces the same embedded contracts at execution boundaries, ensuring install-time and run-time guarantees remain aligned.  
   **Why Compelling:** Extension trust becomes auditable and mechanically enforceable, reducing ambiguity between "what was promised" and "what was allowed to run."  
   **Rationale:** Strong ecosystems are built on artifact contracts that are executable by machines, not just readable by humans.

5. **Adaptive multi-rail isolation mesh with risk-aware placement**  
   **Entails:** Implement multiple isolation rails (in-process restricted, out-of-process sandbox, hardened jail, microVM lane) and dynamically map workloads to rails based on risk, behavior, and performance sensitivity.  
   **How It Works:** Policy engine continuously scores execution contexts and can hot-elevate isolation level when risk rises; low-risk workloads stay on high-performance lanes, while suspicious paths are moved to stricter containment without full system interruption.  
   **Why Compelling:** You get strong containment for risky code while preserving top-tier latency for trusted workloads, avoiding a one-size-fits-all penalty.  
   **Rationale:** Security posture should be elastic and data-driven; static sandbox choices either overpay performance or underpay risk.

6. **Zero-knowledge attestation layer for privacy-preserving trust proofs**  
   **Entails:** Add selective-disclosure trust proofs so publishers and operators can prove compliance properties (build origin, test profile pass, policy class) without revealing unnecessary sensitive internals.  
   **How It Works:** Artifact pipeline generates attestations and compact proof bundles; verifier tooling checks claims against public verification keys and policy predicates before allowing installation or promotion.  
   **Why Compelling:** Enterprises and regulated users gain stronger trust validation with less forced data exposure, improving adoption in strict environments.  
   **Rationale:** The most credible trust systems maximize verifiability while minimizing data leakage; zero-knowledge patterns provide that balance.

7. **Dual-layer N-version semantic oracle (L1 product + L2 engine boundary)**  
   **Entails:** Expand compatibility assurance into an always-on differential oracle with two synchronized layers: L1 runs Node/Bun/franken_node external behavior lockstep, and L2 runs franken_engine boundary corpora against selected references.  
   **How It Works:** Conformance harness executes canonical corpora and adversarial edge cases in both layers, records structured deltas, and automatically decides whether to auto-fix, quarantine feature flags, or block release based on risk policy.  
   **Why Compelling:** Semantic drift is detected early and with context, preventing silent compatibility erosion as performance and security subsystems evolve quickly.  
   **Rationale:** Radical runtime innovation only succeeds if divergence is continuously measured and governed, not discovered late by users.

8. **Security staking and slashing economics for extension publishers**  
   **Entails:** Introduce optional/required publisher staking where security posture and incident history affect stake requirements, distribution visibility, and penalties for validated malicious behavior.  
   **How It Works:** Registry maintains publisher trust accounts, evidence-linked slashing rules, and recovery pathways; policy can gate high-impact capabilities on stake tier and independent attestation level.  
   **Why Compelling:** Incentives shift from "ship fast and externalize risk" to "maintain long-term trust quality," improving ecosystem behavior at scale.  
   **Rationale:** Technical controls alone do not solve ecosystem risk; economic alignment is a powerful additional control plane.

9. **Self-evolving optimization governor with safety envelopes**  
   **Entails:** Build a product-plane optimizer governor that continuously tunes exposed runtime knobs (JIT/caching/scheduling/memory policies) via franken_engine interfaces using online learning while obeying non-negotiable safety and correctness envelopes.  
   **How It Works:** Governor evaluates candidate policy shifts through shadow execution and anytime-valid guardrails, promoting only changes with statistically valid benefit and zero invariant breaches; unsafe shifts auto-revert with evidence.  
   **Why Compelling:** Performance improves continuously in production conditions without exposing users to uncontrolled optimization experiments.  
   **Rationale:** Extreme optimization needs disciplined adaptive control, not manual one-off tuning cycles.

10. **Intent-aware remote effects firewall for extension-originated actions**  
    **Entails:** Move beyond endpoint allowlists by classifying remote actions by inferred intent category (read, mutate, exfiltrate risk, lateral movement risk, financial risk) and gating by policy tier.  
    **How It Works:** Requests are normalized into structured intent frames, scored by contextual Bayesian models, and enforced with progressive challenge modes (allow, require attestation, simulate only, deny, quarantine).  
    **Why Compelling:** This catches sophisticated malicious behavior that hides inside technically "allowed" network endpoints.  
    **Rationale:** Attackers exploit semantic blind spots; intent-level controls close those blind spots while retaining operational flexibility.

11. **Information-flow and exfiltration sentinel with probabilistic inference**  
    **Entails:** Add runtime-level data lineage tracking for sensitive sources/sinks and a probabilistic detector that identifies likely covert exfiltration patterns across command, network, and storage channels.  
    **How It Works:** Capability tags propagate through execution traces, and sentinel models evaluate sequence-level anomalies (encoding bursts, unusual fan-out, staged chunking) before applying automatic containment actions.  
    **Why Compelling:** This provides active defense against stealthy supply-chain payloads that pass static scanning and signature checks.  
    **Rationale:** Real attackers adapt quickly; only dynamic inference over information flow can reliably detect high-skill covert behavior.

12. **Universal verifier SDK with portable replay capsules**  
    **Entails:** Ship a verifier SDK that lets customers, auditors, and researchers independently validate claims using portable replay capsules containing canonical traces, trust artifacts, and expected outputs.  
    **How It Works:** Build pipeline emits signed capsule bundles; SDK provides deterministic replay and evidence validation APIs in multiple languages and exposes machine-readable verdict contracts.  
    **Why Compelling:** Trust stops being centralized in vendor assertions and becomes independently checkable by any serious stakeholder.  
    **Rationale:** A verifier economy is a strategic moat: transparent, reproducible proof workflows are hard for competitors to copy quickly.

13. **Heterogeneous hardware execution planner for secure performance scaling**  
   **Entails:** Create a hardware-aware product planner that maps workloads across CPU classes, memory tiers, and optional accelerators while preserving deterministic policy behavior and auditability.  
   **How It Works:** Planner computes placements using capability constraints, risk classes, cache locality, and latency budgets; decisions are persisted as evidence, validated against policy invariants, and executed through franken_engine/runtime interfaces rather than local engine-core reimplementation.  
   **Why Compelling:** The platform can extract large performance gains from hardware diversity without introducing opaque, non-reproducible runtime behavior.  
   **Rationale:** Next-generation runtime platforms must treat hardware heterogeneity as a first-class optimization surface, not an afterthought.

14. **Counterfactual incident lab and autonomous mitigation design loop**  
    **Entails:** Add a simulation-first incident program that can replay real incidents, generate counterfactual mitigation plans, and evaluate expected-loss reduction before production rollout.  
    **How It Works:** Incident traces feed deterministic lab scenarios; mitigation candidates are synthesized, scored, and proven against safety contracts, then promoted through gated rollout workflows with rollback receipts.  
    **Why Compelling:** Incident response evolves from reactive patching to engineered, evidence-backed resilience upgrades.  
    **Rationale:** Systems with ambitious autonomy need equally ambitious validation loops to avoid compounding unseen risk.

15. **Claim compiler and public trust scoreboard**  
    **Entails:** Convert all external product claims (security, compatibility, performance, resilience) into executable claim specs that must map to measurable artifacts and verifier-checkable outputs.  
    **How It Works:** Claim compiler parses claim definitions, binds them to tests/benchmarks/proofs, blocks unverifiable language in docs/releases, and publishes a continuously updated public scoreboard with evidence links.  
    **Why Compelling:** Market messaging gains exceptional credibility because every major claim is coupled to living evidence, not one-time marketing snapshots.  
    **Rationale:** In disruptive category creation, trust leadership depends on making truth operational and continuously measurable.

## 9L. Verifiable Execution Fabric (VEF): Proof-Carrying Runtime Compliance
1. **Proof-carrying execution compliance fabric for high-risk extension actions**  
   **Entails:** Add a runtime-compliance fabric where high-risk extension actions (network, filesystem, process, secret access, policy transitions, artifact promotion) emit deterministic canonical receipts, and those receipts are mapped to machine-verifiable policy constraints.  
   **How It Works:** A policy-constraint compiler translates runtime policy into proof-checkable predicates; execution emits hash-chained receipt streams plus commitment checkpoints; proof workers generate compact compliance proofs over bounded receipt windows; verifiers validate proofs before claims are elevated and before sensitive control transitions remain in high-trust mode.  
   **Why Compelling:** This upgrades trust from "we logged and replayed it" to "we can cryptographically demonstrate policy compliance for what actually executed," which is a major category-level differentiation over wrapper-style security tooling.  
   **Rationale:** `franken_node` already has evidence ledger, replay, verifier SDK, and claim compiler primitives; VEF is the highest-EV accretive layer because it fuses those primitives into a single verifiable runtime-trust loop that external stakeholders can independently validate.

## 9M. Adversarial Trust Commons (ATC): Federated Behavioral Intelligence
1. **Privacy-preserving federated trust intelligence across participating deployments**  
   **Entails:** Add a federated intelligence layer where participating `franken_node` deployments contribute behavioral trust signals (anomaly fingerprints, trust-state transitions, revocation/quarantine triggers, attack-pattern sketches) without exposing raw sensitive telemetry.  
   **How It Works:** Each participant computes local summaries and submits cryptographically protected updates using secure aggregation, differential-privacy budgets, and mergeable sketches; global services compute ecosystem priors and emerging threat indicators; local control planes consume signed federation outputs to update risk posture and preemptive controls.  
   **Why Compelling:** This converts defense from isolated fortress mode into collective network defense, where high-quality detections in one environment improve prevention quality in all others while preserving privacy boundaries.  
   **Rationale:** The plan already includes adversary graphs, trust cards, verifier systems, and quarantine propagation; ATC is the highest-leverage next layer because it transforms those local capabilities into ecosystem-scale compounding intelligence that is structurally hard for incumbent runtimes to replicate.

## 9N. Dependency Graph Immune System (DGIS): Topological Contagion Modeling + Preemptive Containment
1. **Topology-aware dependency immunization and cascade preemption**  
   **Entails:** Treat the full dependency graph (direct + transitive packages, extension supply roots, publisher/maintainer trust signals, build-time/runtime edges) as a first-class attack surface and build a continuous immune system that predicts catastrophic cascade paths before compromise occurs.  
   **How It Works:** Maintain a canonical signed graph model; compute centrality/percolation/fan-out risk metrics; run adversarial contagion simulations over likely campaign classes (slow-burn maintainer takeover, staged typosquat pivot, delayed payload activation, build-pipeline poisoning); generate preemptive containment plans that insert trust barriers at topological choke points (behavioral sandboxes, composition firewalls, forced verified-fork pinning, constrained update windows); continuously fold ATC-derived global topology indicators into local posterior risk and re-plan barrier placement under policy and performance budgets.  
   **Why Compelling:** This changes security economics from reactive node-level defense to proactive graph-level immunization, shrinking blast radius before attackers can exploit high-leverage positions in the supply chain and making xz-style campaigns materially harder to execute at scale.  
   **Rationale:** Existing trust cards, adversary graph inference, quarantine, VEF proof gates, and ATC federation become multiplicatively stronger when topology is explicit in risk inference and containment policy; DGIS is the missing structural layer that converts these components into a coherent preemptive defense fabric.

## 9O. Behavioral Phenotype Evolution Tracker (BPET): Longitudinal Trust Genetics For Extensions
1. **Pre-compromise behavioral trajectory detection across extension lifecycles**  
   **Entails:** Model every extension as a longitudinal behavioral genome rather than a sequence of disconnected point-in-time snapshots, tracking phenotype evolution across versions, maintainer transitions, dependency rewrites, build-pipeline changes, capability usage shifts, API-surface growth, runtime resource envelopes, network behavior, and structural complexity trends.  
   **How It Works:** Build canonical per-version phenotype vectors and signed lineage chains; compute time-series drift features and regime-shift signals using changepoint detection, Hidden Markov behavioral-state inference, and survival-style hazard estimation for compromise-propensity progression risk; fuse trajectory risk with DGIS topological criticality and ATC federated priors; emit calibrated evolution-risk scores plus explanation traces that distinguish normal growth/refactor behavior from suspicious mutation patterns (capability creep, obfuscation ramps, dormant-to-active bursts, handoff-then-pivot sequences).  
   **Why Compelling:** This shifts detection from reactive mutation catching to predictive compromise precursors, allowing containment before malicious payloads are fully expressed and significantly reducing attacker dwell-time advantage in slow-burn campaigns.  
   **Rationale:** Trust cards, adversary graph scoring, migration gates, and operator decisions all gain major signal quality when temporal evolution becomes explicit; BPET adds the missing time dimension that converts a strong trust stack into a predictive trust stack.

## 10. Ultra-Detailed TODO (Program Level)
### 10.N Execution Normalization Contract (No Duplicate Implementations)
- `10.0` through `10.12` are strategic epics and coverage gates.
- `10.13` through `10.21` are canonical implementation-level work breakdowns.
- If the same capability appears in multiple tracks, exactly one canonical implementation path owns the protocol/code semantics; all other appearances are integration, adoption, policy, or release gating layers.
- Duplicate implementation of the same protocol semantics in parallel tracks is explicitly off-charter.
- Oracle delivery close condition: dual-layer oracle is only complete when L1 (`10.2`) + L2 (`10.17`) + release policy linkage (`10.2`) are all green.

Canonical ownership map (non-reductive, full-feature):
- remote registry/idempotency/saga semantics: canonical in `10.14`, integrated and policy-gated in `10.15`.
- epoch validity + transition barriers: canonical in `10.14`, integrated into control workflows in `10.15`.
- evidence ledger + replay validator: canonical in `10.14`, mandatory adoption and release gating in `10.15`.
- fault harness/cancellation injection/DPOR exploration: canonical harness in `10.14`, control-plane enforcement gate in `10.15`.
- verifier SDK/replay capsules/claim compiler + trust scoreboard: canonical in `10.17`, ecosystem distribution/adoption in `10.9` + `10.12`.
- semantic oracle: L1 product oracle owned in `10.2`, L2 engine-boundary oracle owned in `10.17`.
- authenticated control channel + anti-replay framing: canonical protocol in `10.13`, adoption and policy rollout in `10.10` + `10.15`.
- revocation freshness semantics: canonical enforcement in `10.13`, ecosystem/policy adoption in `10.4` + `10.10`.
- stable error taxonomy and recovery contract: canonical definition in `10.13`, operations and product-surface adoption in `10.8` + `10.10`.
- trust protocol vectors/golden fixtures: canonical generation in `10.13` + `10.14`, release and publication gates in `10.7` + `10.10`.
- verifiable execution fabric (policy-constraint compiler + receipt commitments + proof generation/verification): canonical in `10.18`, consumed by `10.17` verifier/claim surfaces and enforced through `10.15` control-plane gates.
- adversarial trust commons federation (privacy-preserving signal sharing + global priors + incentive weighting): canonical in `10.19`, consumed by `10.17` adversary graph/reputation surfaces and enforced through `10.15` + `10.4` trust controls.
- dependency graph immune system (topological risk model + contagion simulator + preemptive barrier planner): canonical in `10.20`, consumed by `10.17` adversary/economic scoring, `10.15` control-plane containment, and `10.19` federated threat-intelligence enrichment.
- behavioral phenotype evolution tracker (longitudinal genome modeling + drift/regime-shift detection + hazard scoring): canonical in `10.21`, consumed by `10.17` adversary/trust scoring, `10.20` topological prioritization, `10.19` federated temporal intelligence, and `10.2`/`10.15` migration-control gating.
- spec-first Node/Bun compatibility extraction and fixture-oracle baselining: canonical in `10.2`, consumed by `10.3` migration automation and `10.7` release verification.

### 10.0 Top 10 Initiative Tracking
- [ ] Implement compatibility envelope + divergence ledger.
- [ ] Implement migration autopilot pipeline.
- [ ] Implement trust cards for extensions and publishers.
- [ ] Deliver dual-layer lockstep oracle program (L1 product + L2 engine boundary + release-policy linkage).
- [ ] Implement policy-visible compatibility shim system.
- [ ] Implement fleet quarantine UX + control plane.
- [ ] Implement secure extension distribution network.
- [ ] Implement operator safety copilot.
- [ ] Implement economic trust layer.
- [ ] Implement benchmark + standard ownership stack.

### 10.1 Charter + Split Governance
- [ ] Add explicit product charter document aligned to `/dp/franken_engine/PLAN_TO_CREATE_FRANKEN_ENGINE.md`.
- [ ] Enforce repository split contract checks in CI.
- [ ] Add dependency-direction guard preventing local engine crate reintroduction.
- [ ] Add reproducibility contract templates (`env.json`, `manifest.json`, `repro.lock`).
- [ ] Add claim-language policy requiring verifier artifacts for external claims.
- [ ] Add ADR: "Hybrid Baseline Strategy" codifying no Bun-first clone, spec-first compatibility extraction, and native franken architecture from day one.
- [ ] Add implementation-governance policy that forbids line-by-line legacy translation and requires spec+fixture references in compatibility PRs.

### 10.2 Compatibility Core
- [ ] Define compatibility bands (`core`, `high-value`, `edge`, `unsafe`) with policy defaults.
- [ ] Implement compatibility behavior registry with typed shim metadata.
- [ ] Implement divergence ledger with signed rationale entries.
- [ ] Implement compatibility mode selection policy (`strict`, `balanced`, `legacy-risky`).
- [ ] Implement deterministic compatibility fixture runner and result canonicalizer.
- [ ] Implement L1 lockstep runner integration for Node/Bun/franken_node.
- [ ] Implement minimized divergence fixture generation.
- [ ] Implement L2 engine-boundary semantic oracle integration policy and release gate linkage.
- [ ] Implement compatibility regression dashboard by API family.
- [ ] Create the four-doc spec pack for compatibility extraction (`PLAN_TO_PORT_NODE_BUN_SURFACES_TO_RUST.md`, `EXISTING_NODE_BUN_STRUCTURE.md`, `PROPOSED_ARCHITECTURE.md`, `FEATURE_PARITY.md`) and keep it release-gated.
- [ ] Build prioritized Node/Bun reference capture programs and fixture corpora per API band (CLI/process/fs/network/module/tooling).
- [ ] Add CI gate: compatibility implementations must cite spec section + fixture IDs; missing references fail review gates.

### 10.3 Migration System
- [ ] Build project scanner for API/runtime/dependency risk inventory.
- [ ] Build migration risk scoring model with explainable features.
- [ ] Build automated rewrite suggestion engine with rollback plan artifacts.
- [ ] Build migration validation runner with lockstep checks.
- [ ] Build rollout planner (`shadow -> canary -> ramp -> default`) per project.
- [ ] Build migration confidence report with uncertainty bands.
- [ ] Build one-command migration report export for enterprise review.
- [ ] Build deterministic migration failure replay tooling.

### 10.4 Extension Ecosystem + Registry
- [ ] Define signed extension package manifest schema.
- [ ] Define provenance attestation requirements and verification chain.
- [ ] Integrate revocation propagation with canonical freshness checks (from `10.13`) in extension workflows.
- [ ] Implement extension trust-card API and CLI surfaces.
- [ ] Implement publisher reputation model with explainable transitions.
- [ ] Implement fast quarantine/recall workflow for compromised artifacts.
- [ ] Implement extension certification levels tied to policy controls.
- [ ] Implement ecosystem telemetry for trust and adoption metrics.

### 10.5 Security + Policy Product Surfaces
- [ ] Implement policy-visible compatibility gate APIs.
- [ ] Implement signed decision receipt export for high-impact actions.
- [ ] Implement deterministic incident replay bundle generation.
- [ ] Implement counterfactual replay mode for policy simulation.
- [ ] Implement operator copilot action recommendation API.
- [ ] Implement expected-loss action scoring with explicit loss matrices.
- [ ] Implement degraded-mode policy behavior with mandatory audit events.
- [ ] Implement policy change approval workflows with cryptographic audit trail.

### 10.6 Performance + Packaging
- [ ] Build product-level benchmark suite with secure-extension scenarios.
- [ ] Add cold-start and p99 latency gates for core workflows.
- [ ] Optimize lockstep harness throughput and memory profile.
- [ ] Optimize migration scanner throughput for large monorepos.
- [ ] Add packaging profiles for local/dev/enterprise deployments.
- [ ] Add artifact signing and checksum verification for releases.
- [ ] Add release rollback bundles with deterministic restore checks.

### 10.7 Conformance + Verification
- [ ] Build compatibility golden corpus and fixture metadata schema.
- [ ] Adopt canonical trust protocol vectors from `10.13` + `10.14` and enforce release/publication gates on those vectors.
- [ ] Add fuzz/adversarial tests for migration and shim logic.
- [ ] Add metamorphic tests for compatibility invariants.
- [ ] Add verifier CLI conformance contract tests.
- [ ] Add external-reproduction playbook and automation scripts.

### 10.8 Operational Readiness
- [ ] Implement fleet control API for quarantine/revocation operations.
- [ ] Adopt canonical structured observability + stable error taxonomy contracts (from `10.13`) across operational surfaces.
- [ ] Implement deterministic safe-mode startup and operation flags.
- [ ] Implement incident bundle retention and export policy.
- [ ] Implement operator runbooks for high-severity trust incidents.
- [ ] Implement disaster-recovery drills for control-plane failures.

### 10.9 Moonshot Disruption Track
- [ ] Build public Node/Bun/franken_node benchmark campaign infrastructure.
- [ ] Build autonomous adversarial campaign runner with continuous updates.
- [ ] Build migration singularity demo pipeline for flagship repositories.
- [ ] Build verifier economy portal and external attestation publishing flow.
- [ ] Build trust economics dashboard with attacker-ROI deltas.
- [ ] Build category-shift reporting pipeline with reproducible artifacts.

### 10.10 FCP-Inspired Hardening + Interop Integration Track
- [ ] Define canonical product trust object IDs with domain separation.
- [ ] Enforce product-level adoption of canonical deterministic serialization and signature preimage rules (from `10.13` + `10.14`).
- [ ] Implement policy checkpoint chain for product release channels.
- [ ] Implement rollback/fork detection in control-plane state propagation using canonical divergence and marker proofs (from `10.14`).
- [ ] Implement audience-bound token chains for control actions.
- [ ] Implement key-role separation for control-plane signing/encryption/issuance.
- [ ] Integrate canonical session-authenticated control channel + monotonic anti-replay framing (from `10.13`) across product control APIs.
- [ ] Integrate canonical revocation freshness semantics (from `10.13`) before risky and dangerous product actions.
- [ ] Implement zone/tenant trust segmentation policies.
- [ ] Adopt canonical stable error namespace and compatibility policy (from `10.13`) across product surfaces.
- [ ] Adopt canonical trust protocol vectors/golden fixtures (from `10.13` + `10.14`) as product publication and release gates.

### 10.11 FrankenSQLite-Inspired Runtime Systems Integration Track
- [ ] Define capability profiles for product subsystems and enforce narrowing.
- [ ] Add ambient-authority audit gate for product security-critical modules.
- [ ] Add checkpoint-placement contract in all long orchestration loops.
- [ ] Adopt canonical cancel -> drain -> finalize protocol contracts (from `10.15`) for product services.
- [ ] Implement bounded masking helper for tiny atomic product operations.
- [ ] Adopt canonical obligation-tracked two-phase channel contracts (from `10.15`) for critical flows.
- [ ] Implement supervision tree with restart budgets and escalation policies.
- [ ] Adopt canonical deterministic lab runtime and protocol scenario suites (from `10.14` + `10.15`) for product control-plane logic.
- [ ] Implement BOCPD regime detector for workload/incident stream shifts.
- [ ] Implement VOI-budgeted monitor scheduling for expensive diagnostics.
- [ ] Integrate canonical monotonic security epochs and transition barriers (from `10.14`) across product services.
- [ ] Integrate canonical remote idempotency + saga semantics (from `10.14`) for multi-step workflows.
- [ ] Integrate canonical scheduler lane and global bulkhead policies (from `10.14` + `10.15`) for product operations.
- [ ] Implement anti-entropy reconciliation for distributed product trust state.

### 10.12 Frontier Programs Execution Track (9H)
- [ ] Define migration singularity artifact contract and verifier format.
- [ ] Implement end-to-end migration singularity pipeline for pilot cohorts.
- [ ] Implement trust fabric convergence protocol and degraded-mode semantics.
- [ ] Implement verifier-economy SDK with independent validation workflows.
- [ ] Implement operator intelligence recommendation engine with rollback proofs.
- [ ] Implement ecosystem network-effect APIs (registry/reputation/compliance evidence).
- [ ] Add frontier demo gates with external reproducibility requirements.

### 10.13 FCP Deep-Mined Expansion Execution Track (9I)
- In this track, `connector/provider` denotes extension integration class per `8.8` terminology contract.
- [ ] Implement connector lifecycle enum, transition table, and illegal-transition rejection tests.
  `Acceptance Criteria:` FSM is complete and deterministic for all states; illegal transitions return stable codes; full transition matrix tests pass.
  `Artifacts:` `docs/specs/connector_lifecycle.md`, `tests/conformance/connector_lifecycle_transitions.rs`, `artifacts/10.13/lifecycle_transition_matrix.json`.
- [ ] Add lifecycle-aware health gating and rollout-state persistence for every connector instance.
  `Acceptance Criteria:` Activation requires lifecycle + health gate satisfaction; rollout state survives restart and failover; recovery replay reproduces same state.
  `Artifacts:` `docs/specs/rollout_state_machine.md`, `tests/integration/lifecycle_health_gate.rs`, `artifacts/10.13/rollout_state_replay.log`.
- [ ] Implement standard connector method contract validator (`handshake/describe/introspect/capabilities/configure/simulate/invoke/health/shutdown`).
  `Acceptance Criteria:` Validator rejects missing or schema-invalid methods; method schemas are versioned and pinned; contract report is machine-readable.
  `Artifacts:` `src/conformance/connector_method_validator.rs`, `docs/specs/connector_method_contract.md`, `artifacts/10.13/connector_method_contract_report.json`.
- [ ] Build connector protocol conformance harness and block registry publication on failures.
  `Acceptance Criteria:` CI gate fails publication for non-conformant connectors; harness emits deterministic pass/fail reasons; bypass requires explicit policy override artifact.
  `Artifacts:` `tests/conformance/connector_protocol_harness.rs`, `.github/workflows/connector-conformance.yml`, `artifacts/10.13/publication_gate_evidence.json`.
- [ ] Implement canonical connector state root/object model with explicit state model tagging.
  `Acceptance Criteria:` All connectors declare state model type; canonical root/head objects are persisted; local cache divergence is detectable and repairable.
  `Artifacts:` `docs/specs/connector_state_model.md`, `tests/integration/connector_state_persistence.rs`, `artifacts/10.13/state_model_samples.json`.
- [ ] Add singleton-writer fencing validation using `lease_seq` + lease-object linkage.
  `Acceptance Criteria:` Unfenced or stale-fenced writes are rejected; fence checks are monotonic; stale writer test cases fail deterministically.
  `Artifacts:` `tests/conformance/singleton_writer_fencing.rs`, `docs/specs/fencing_rules.md`, `artifacts/10.13/fencing_rejection_receipts.json`.
- [ ] Add CRDT state mode scaffolding (lww-map/or-set/gcounter/pncounter) with merge conformance fixtures.
  `Acceptance Criteria:` Each CRDT type has merge laws covered by fixtures; merge output is deterministic across replicas; schema tags prevent type confusion.
  `Artifacts:` `tests/conformance/crdt_merge_fixtures.rs`, `fixtures/crdt/*.json`, `docs/specs/crdt_state_mode.md`.
- [ ] Implement snapshot policy (`every_updates`, `every_bytes`) and bounded replay targets for connector state.
  `Acceptance Criteria:` Replay cost is bounded by configured thresholds; snapshots are validated against chain heads; snapshot policy changes are audited.
  `Artifacts:` `docs/specs/state_snapshot_policy.md`, `tests/perf/state_replay_bound.rs`, `artifacts/10.13/snapshot_policy_benchmark.csv`.
- [ ] Add state schema version contracts and deterministic migration hint execution checks.
  `Acceptance Criteria:` Version transitions require declared migration path; migrations are idempotent and replay-stable; failed migrations rollback cleanly.
  `Artifacts:` `docs/specs/state_schema_migrations.md`, `tests/integration/state_migration_contract.rs`, `artifacts/10.13/state_migration_receipts.json`.
- [ ] Implement sandbox profile system (`strict`, `strict_plus`, `moderate`, `permissive`) with policy compiler.
  `Acceptance Criteria:` Profile compiler emits enforceable low-level policy for each tier; profile downgrade attempts are blocked by policy; profile selection is auditable.
  `Artifacts:` `src/security/sandbox_policy_compiler.rs`, `docs/specs/sandbox_profiles.md`, `artifacts/10.13/sandbox_profile_compiler_output.json`.
- [ ] Add strict-plus isolation backend (microVM when available, hardened fallback otherwise).
  `Acceptance Criteria:` `strict_plus` maps to microVM isolation where supported; unsupported platforms use hardened fallback with equivalent policy guarantees; compatibility tests pass across OS targets.
  `Artifacts:` `docs/specs/strict_plus_backend_matrix.md`, `tests/integration/strict_plus_isolation.rs`, `artifacts/10.13/strict_plus_runtime_matrix.csv`.
- [ ] Implement Network Guard egress layer with HTTP+TCP policy enforcement and audit emission.
  `Acceptance Criteria:` All connector egress traverses guard path; allow/deny enforcement matches policy semantics; every decision emits structured audit event.
  `Artifacts:` `src/security/network_guard.rs`, `tests/conformance/network_guard_policy.rs`, `artifacts/10.13/network_guard_audit_samples.jsonl`.
- [ ] Add SSRF-deny default policy template (localhost/tailnet/private CIDR denied unless explicitly allowed).
  `Acceptance Criteria:` Default templates block unsafe internal destinations; explicit allowlist exceptions require policy receipts; regression tests cover common SSRF patterns.
  `Artifacts:` `config/policies/network_guard_default.toml`, `tests/security/ssrf_default_deny.rs`, `artifacts/10.13/ssrf_policy_test_report.json`.
- [ ] Implement fail-closed manifest negotiation (SemVer-aware version checks, required-feature resolution, transport cap checks).
  `Acceptance Criteria:` Unsupported major versions and missing required features hard-fail activation; version comparisons are semantic, not lexical; negotiation decisions are logged.
  `Artifacts:` `docs/specs/manifest_negotiation.md`, `tests/conformance/manifest_negotiation_fail_closed.rs`, `artifacts/10.13/manifest_negotiation_trace.json`.
- [ ] Add domain-separated interface-hash verification and admission failure telemetry.
  `Acceptance Criteria:` Interface hash uses domain-separated derivation; invalid hashes block admission; telemetry exposes rejection code distribution.
  `Artifacts:` `src/security/interface_hash.rs`, `tests/conformance/interface_hash_verification.rs`, `artifacts/10.13/interface_hash_rejection_metrics.csv`.
- [ ] Implement threshold signature verification for connector publication artifacts.
  `Acceptance Criteria:` Publication requires configured threshold quorum; partial signature sets are rejected; verification failures produce stable failure reasons.
  `Artifacts:` `docs/specs/threshold_signatures.md`, `tests/security/threshold_signature_verification.rs`, `artifacts/10.13/threshold_signature_vectors.json`.
- [ ] Implement transparency-log inclusion proof checks in install/update pipelines.
  `Acceptance Criteria:` Install/update fails if required inclusion proof is missing/invalid; log roots are pinned per policy; verification path is replayable.
  `Artifacts:` `src/supply_chain/transparency_verifier.rs`, `tests/security/transparency_inclusion.rs`, `artifacts/10.13/transparency_proof_receipts.json`.
- [ ] Implement provenance/attestation policy gates (required attestation types, minimum build assurance, trusted builders).
  `Acceptance Criteria:` Policy engine enforces required attestations and builder trust constraints; non-compliant artifacts are blocked pre-activation; gate results are signed.
  `Artifacts:` `docs/specs/provenance_policy.md`, `tests/security/attestation_gate.rs`, `artifacts/10.13/provenance_gate_decisions.json`.
- [ ] Implement deterministic activation pipeline: sandbox -> ephemeral secret mount -> capability issue -> health-ready transition.
  `Acceptance Criteria:` Stage order is fixed and enforced; partial activation cannot leak persistent secrets; restart replay reproduces identical activation transcript.
  `Artifacts:` `docs/specs/activation_pipeline.md`, `tests/integration/activation_pipeline_determinism.rs`, `artifacts/10.13/activation_stage_transcript.jsonl`.
- [ ] Implement crash-loop detector with automatic rollback and known-good pin fallback.
  `Acceptance Criteria:` Crash-loop thresholds are configurable and enforced; rollback to known-good pin is automatic and auditable; rollback cannot bypass trust policy.
  `Artifacts:` `src/runtime/crash_loop_detector.rs`, `tests/integration/crash_loop_rollback.rs`, `artifacts/10.13/crash_loop_incident_bundle.json`.
- [ ] Implement revocation registry with monotonic revocation-head checkpoints.
  `Acceptance Criteria:` Revocation heads are monotonic per zone/tenant; stale head updates are rejected; head state is recoverable from canonical storage.
  `Artifacts:` `docs/specs/revocation_registry.md`, `tests/conformance/revocation_head_monotonicity.rs`, `artifacts/10.13/revocation_head_history.json`.
- [ ] Enforce revocation freshness per safety tier before risky and dangerous actions.
  `Acceptance Criteria:` Safety-tier gate denies stale-frontier risky/dangerous actions; override behavior follows policy and is receipt-backed; gate latency meets SLO.
  `Artifacts:` `tests/security/revocation_freshness_gate.rs`, `docs/specs/safety_tier_freshness.md`, `artifacts/10.13/revocation_freshness_decisions.json`.
- [ ] Emit explicit degraded-mode audit events whenever stale revocation frontier overrides are used.
  `Acceptance Criteria:` Every degraded-mode override emits required audit schema fields; missing event is a hard failure in conformance tests; events correlate to action IDs.
  `Artifacts:` `tests/conformance/degraded_mode_audit_events.rs`, `docs/specs/degraded_mode_audit_schema.md`, `artifacts/10.13/degraded_mode_events.jsonl`.
- [ ] Implement generic lease service for operation execution, state writes, and migration handoff.
  `Acceptance Criteria:` Lease API supports all required purposes with shared semantics; lease expiry and renewal behavior is deterministic; stale lease usage is rejected.
  `Artifacts:` `src/control_plane/lease_service.rs`, `docs/specs/generic_leases.md`, `artifacts/10.13/lease_service_contract.json`.
- [ ] Implement deterministic lease coordinator selection and quorum signature verification.
  `Acceptance Criteria:` Coordinator selection is deterministic for identical inputs; quorum requirements vary by safety tier and are enforced; verification failures are classified.
  `Artifacts:` `tests/conformance/lease_coordinator_selection.rs`, `docs/specs/lease_quorum_rules.md`, `artifacts/10.13/lease_quorum_vectors.json`.
- [ ] Implement overlapping-lease conflict policy and deterministic fork handling logs.
  `Acceptance Criteria:` Overlapping lease conflicts resolve via documented deterministic rule; dangerous conflicts halt and alert; fork logs contain reproducible evidence.
  `Artifacts:` `docs/specs/lease_conflict_policy.md`, `tests/integration/overlapping_lease_conflicts.rs`, `artifacts/10.13/lease_fork_log_samples.json`.
- [ ] Implement device profile registry and placement policy schema for execution targeting.
  `Acceptance Criteria:` Device profiles have validated schema and freshness checks; placement policies reject invalid constraints; policy evaluation is deterministic.
  `Artifacts:` `docs/specs/device_profile_schema.md`, `tests/conformance/placement_policy_schema.rs`, `artifacts/10.13/device_profile_examples.json`.
- [ ] Build execution planner scorer (latency/risk/capability-aware) with deterministic tie-breakers.
  `Acceptance Criteria:` Scorer output is stable for identical inputs; tie-breakers are explicit and tested; planner decisions include explainable factor weights.
  `Artifacts:` `src/planner/execution_scorer.rs`, `tests/integration/execution_planner_determinism.rs`, `artifacts/10.13/planner_decision_explanations.json`.
- [ ] Implement predictive pre-staging engine for high-probability offline artifacts.
  `Acceptance Criteria:` Pre-staging model raises offline coverage on benchmark scenarios; budget limits prevent prefetch storms; prediction quality is measured and reported.
  `Artifacts:` `docs/specs/predictive_prestaging.md`, `tests/perf/prestaging_coverage_improvement.rs`, `artifacts/10.13/prestaging_model_report.csv`.
- [ ] Implement offline coverage tracker and SLO dashboards (`coverage`, `availability`, `repair debt`).
  `Acceptance Criteria:` Coverage metrics are computed continuously and per policy scope; SLO breach alerts trigger automatically; dashboard values are traceable to raw events.
  `Artifacts:` `docs/observability/offline_slo_metrics.md`, `tests/integration/offline_coverage_metrics.rs`, `artifacts/10.13/offline_slo_dashboard_snapshot.json`.
- [ ] Implement background repair controller with bounded work-per-cycle and fairness controls.
  `Acceptance Criteria:` Repair loop respects per-cycle work caps and fairness constraints; no tenant starvation under synthetic load; controller decisions are auditable.
  `Artifacts:` `src/repair/background_repair_controller.rs`, `tests/perf/repair_fairness.rs`, `artifacts/10.13/repair_cycle_telemetry.csv`.
- [ ] Implement per-peer admission budgets (bytes/symbols/failed-auth/inflight-decode/decode-cpu).
  `Acceptance Criteria:` Admission checks enforce all budget dimensions; limit breaches are rate-limited and logged; budgets can be tuned without code changes.
  `Artifacts:` `docs/specs/admission_budget_model.md`, `tests/security/per_peer_budget_enforcement.rs`, `artifacts/10.13/admission_budget_violation_report.json`.
- [ ] Implement anti-amplification response bounds for retrieval/sync traffic and test with adversarial traffic harness.
  `Acceptance Criteria:` Response payloads never exceed request-declared bounds under adversarial inputs; unauthenticated limits are stricter and enforced; harness reproduces attacks deterministically.
  `Artifacts:` `tests/security/anti_amplification_harness.rs`, `docs/specs/anti_amplification_rules.md`, `artifacts/10.13/anti_amplification_test_results.json`.
- [ ] Implement quarantine-by-default store for unreferenced objects with quota + TTL enforcement.
  `Acceptance Criteria:` Unknown objects enter quarantine class by default; quota and TTL eviction enforce hard caps; quarantined objects are excluded from primary gossip state.
  `Artifacts:` `src/admission/quarantine_store.rs`, `tests/integration/quarantine_retention.rs`, `artifacts/10.13/quarantine_usage_metrics.csv`.
- [ ] Implement schema-gated quarantine promotion rules and promotion provenance receipts.
  `Acceptance Criteria:` Promotion requires reachability/authenticated request/pin plus schema validation; promotion emits provenance receipt with promotion reason; invalid promotions fail closed.
  `Artifacts:` `docs/specs/quarantine_promotion_rules.md`, `tests/security/quarantine_promotion_gate.rs`, `artifacts/10.13/quarantine_promotion_receipts.json`.
- [ ] Implement control-plane retention policy (`required` vs `ephemeral`) and storage enforcement.
  `Acceptance Criteria:` Retention class is mandatory per control-plane message type; required objects are durably stored; ephemeral objects can be dropped only under policy.
  `Artifacts:` `docs/specs/control_plane_retention.md`, `tests/conformance/retention_class_enforcement.rs`, `artifacts/10.13/retention_policy_matrix.json`.
- [ ] Persist required artifacts (`invoke/response/receipt/approval/revocation/audit`) with deterministic replay hooks.
  `Acceptance Criteria:` Required artifact families are persisted and indexable; replay hook reconstructs high-impact event sequence deterministically; missing required artifacts fail integrity checks.
  `Artifacts:` `tests/integration/required_artifact_replay.rs`, `docs/specs/replay_hook_contract.md`, `artifacts/10.13/replay_integrity_report.json`.
- [ ] Implement authenticated control channel with per-direction sequence monotonicity and replay-window checks.
  `Acceptance Criteria:` Channel rejects out-of-window and non-monotonic frames; per-direction sequence state survives restart safely; replay attack fixtures are blocked.
  `Artifacts:` `src/protocol/control_channel.rs`, `tests/security/control_channel_replay_window.rs`, `artifacts/10.13/control_channel_security_trace.jsonl`.
- [ ] Add bounded parser/resource-accounting guardrails on control-channel frame decode.
  `Acceptance Criteria:` Decode path enforces byte/CPU/allocation ceilings; oversized/malformed frames fail fast; parse budgets are reflected in telemetry.
  `Artifacts:` `docs/specs/control_channel_parser_limits.md`, `tests/security/parser_budget_guardrails.rs`, `artifacts/10.13/parser_guardrail_metrics.csv`.
- [ ] Define stable telemetry namespace for protocol/capability/egress/security planes.
  `Acceptance Criteria:` Metric names and labels are versioned and frozen by contract; deprecations follow compatibility policy; schema validator enforces namespace rules.
  `Artifacts:` `docs/observability/telemetry_namespace.md`, `tests/conformance/metric_schema_stability.rs`, `artifacts/10.13/telemetry_schema_catalog.json`.
- [ ] Define stable error code namespace and machine-readable `retryable/retry_after/recovery_hint` contract.
  `Acceptance Criteria:` Error codes are unique and namespaced; machine-readable recovery fields are present for all non-fatal errors; compatibility tests catch breaking changes.
  `Artifacts:` `docs/specs/error_code_contract.md`, `tests/conformance/error_contract_stability.rs`, `artifacts/10.13/error_code_registry.json`.
- [ ] Require distributed trace correlation IDs across connector execution and control-plane artifacts.
  `Acceptance Criteria:` All high-impact flows carry trace correlation fields end-to-end; missing trace context is surfaced as conformance failure; traces can be stitched across services.
  `Artifacts:` `tests/integration/trace_correlation_end_to_end.rs`, `docs/specs/trace_context_contract.md`, `artifacts/10.13/distributed_trace_sample.json`.
- [ ] Define MVP vs Full conformance profile matrix and publication claim rules.
  `Acceptance Criteria:` Profile matrix maps required capabilities to claim language; publication metadata is generated from measured profile results; unsupported claims are blocked.
  `Artifacts:` `docs/conformance/profile_matrix.md`, `tests/conformance/profile_claim_gate.rs`, `artifacts/10.13/profile_claim_report.json`.
- [ ] Build mandatory serialization/object-id/signature/revocation/source-diversity interop suites.
  `Acceptance Criteria:` Interop suite covers all mandatory classes and passes across independent implementations; failures include minimal reproducer fixtures.
  `Artifacts:` `tests/interop/*.rs`, `fixtures/interop/*.json`, `artifacts/10.13/interop_results_matrix.csv`.
- [ ] Build adversarial fuzz corpus gates, including decode-DoS and replay/splice handshake scenarios.
  `Acceptance Criteria:` Fuzz targets include parser, handshake, token validation, and decode-DoS corpora; CI gate enforces minimum fuzz health budget; regressions are triaged with seeds.
  `Artifacts:` `fuzz/targets/*`, `docs/security/adversarial_fuzzing.md`, `artifacts/10.13/fuzz_campaign_summary.json`.
- [ ] Publish formal schema spec files and golden vectors for serialization, signatures, and control-channel frames.
  `Acceptance Criteria:` Normative schema files and golden vectors are versioned and release-published; verification CLI passes full vector suite; vector changes require explicit changelog entry.
  `Artifacts:` `spec/FNODE_TRUST_SCHEMA_V1.cddl`, `vectors/fnode_trust_vectors_v1.json`, `artifacts/10.13/vector_verification_report.json`.

### 10.14 FrankenSQLite Deep-Mined Expansion Execution Track (9J)
- [ ] Define `EvidenceEntry` schema for product control decisions with deterministic field and candidate ordering.
  `Acceptance Criteria:` Schema covers decision kind, candidates, constraints, chosen action, and witness references; field ordering is canonical; schema validation is enforced in CI.
  `Artifacts:` `docs/specs/evidence_entry_schema.md`, `spec/evidence_entry_v1.json`, `artifacts/10.14/evidence_schema_validation_report.json`.
- [ ] Implement bounded evidence ledger ring buffer plus lab spill-to-artifacts mode.
  `Acceptance Criteria:` Production ledger memory stays within configured bound; overflow policy is deterministic; lab mode writes full spill artifacts for failing scenarios.
  `Artifacts:` `src/observability/evidence_ledger.rs`, `tests/integration/evidence_ledger_bounds.rs`, `artifacts/10.14/evidence_spill_example.jsonl`.
- [ ] Require evidence emission for policy-driven commit/abort/quarantine/release actions.
  `Acceptance Criteria:` All policy-driven control decisions emit mandatory evidence entries; missing entry causes conformance failure; evidence links to action IDs.
  `Artifacts:` `tests/conformance/policy_decision_evidence.rs`, `docs/specs/policy_evidence_requirements.md`, `artifacts/10.14/policy_decision_evidence_matrix.json`.
- [ ] Attach trace-witness references to every high-impact ledger entry.
  `Acceptance Criteria:` High-impact evidence entries include stable trace witness IDs; witness references resolve in replay bundles; broken references fail integrity check.
  `Artifacts:` `tests/integration/evidence_trace_witness_linking.rs`, `docs/specs/witness_reference_contract.md`, `artifacts/10.14/witness_link_audit.json`.
- [ ] Add evidence-ledger replay validator that reproduces chosen action from captured inputs.
  `Acceptance Criteria:` Validator deterministically replays recorded decision contexts; mismatches are reported with minimal diff; replay passes on canonical fixtures.
  `Artifacts:` `src/tools/evidence_replay_validator.rs`, `tests/conformance/evidence_replay_validator.rs`, `artifacts/10.14/evidence_replay_results.json`.
- [ ] Define immutable correctness envelope that policy controllers are forbidden to modify.
  `Acceptance Criteria:` Envelope enumerates non-tunable invariants; controller API rejects writes outside allowed policy set; governance doc maps invariant ownership.
  `Artifacts:` `docs/specs/correctness_envelope.md`, `tests/security/controller_envelope_enforcement.rs`, `artifacts/10.14/correctness_envelope_manifest.json`.
- [ ] Implement controller boundary checks rejecting any attempted correctness-semantic mutation.
  `Acceptance Criteria:` Boundary checks run pre-apply for every policy proposal; violation attempts return stable error class; audit trail records rejected mutation intent.
  `Artifacts:` `src/policy/controller_boundary_checks.rs`, `tests/security/controller_mutation_rejection.rs`, `artifacts/10.14/controller_boundary_rejections.json`.
- [ ] Implement anytime-valid guardrail monitor set for security/durability-critical budgets.
  `Acceptance Criteria:` Guardrails are always-on for critical budgets; monitor outputs remain valid under optional stopping; alert thresholds are policy-configurable.
  `Artifacts:` `docs/specs/anytime_valid_guardrails.md`, `tests/conformance/anytime_guardrail_monitors.rs`, `artifacts/10.14/guardrail_monitor_telemetry.csv`.
- [ ] Implement Bayesian posterior diagnostics for explainable policy ranking.
  `Acceptance Criteria:` Posterior metrics are surfaced for ranking diagnostics; diagnostics do not bypass hard guardrails; posterior updates are reproducible from stored observations.
  `Artifacts:` `src/policy/bayesian_diagnostics.rs`, `tests/integration/bayesian_policy_ranking.rs`, `artifacts/10.14/posterior_diagnostics_report.json`.
- [ ] Enforce guardrail precedence: anytime-valid bounds override Bayesian recommendations.
  `Acceptance Criteria:` Decision engine always checks guardrail before recommendation apply; blocked recommendations emit explicit reason; precedence covered by conformance tests.
  `Artifacts:` `tests/conformance/guardrail_precedence.rs`, `docs/specs/decision_precedence_rules.md`, `artifacts/10.14/guardrail_override_events.json`.
- [ ] Add policy action explainer that distinguishes diagnostic confidence from guarantee confidence.
  `Acceptance Criteria:` Explainer output contains separate sections for heuristic confidence and guarantee confidence; UI/API contracts expose both values; ambiguity-free wording validated.
  `Artifacts:` `docs/specs/policy_explainer_contract.md`, `tests/integration/policy_explainer_output.rs`, `artifacts/10.14/policy_explainer_examples.json`.
- [ ] Implement monotonic hardening mode state machine with one-way escalation semantics.
  `Acceptance Criteria:` Hardening transitions are monotonic unless explicit governance rollback artifact is present; state transitions are durable and replayable; illegal regressions are rejected.
  `Artifacts:` `src/policy/hardening_state_machine.rs`, `tests/security/monotonic_hardening.rs`, `artifacts/10.14/hardening_state_history.json`.
- [ ] Implement automatic hardening trigger on guardrail rejection evidence.
  `Acceptance Criteria:` Guardrail rejection triggers hardening within configured latency bound; trigger path is idempotent; trigger events include causal evidence pointer.
  `Artifacts:` `tests/integration/hardening_auto_trigger.rs`, `docs/specs/hardening_trigger_policy.md`, `artifacts/10.14/hardening_trigger_events.jsonl`.
- [ ] Implement overhead/rate clamp policy for hardening escalations with configured ceilings.
  `Acceptance Criteria:` Escalation clamps respect min/max bounds and policy budget; clamp calculations are deterministic; clamp hits are visible in telemetry.
  `Artifacts:` `src/policy/hardening_clamps.rs`, `tests/conformance/hardening_clamp_bounds.rs`, `artifacts/10.14/hardening_clamp_metrics.csv`.
- [ ] Implement retroactive hardening pipeline that appends additional protection artifacts without rewriting canonical objects.
  `Acceptance Criteria:` Retroactive hardening adds union-only artifacts; canonical object identity remains stable; repairability improvement is measurable on target corpus.
  `Artifacts:` `docs/specs/retroactive_hardening.md`, `tests/integration/retroactive_hardening_union_only.rs`, `artifacts/10.14/retroactive_hardening_report.json`.
- [ ] Implement integrity sweep escalation/de-escalation policy driven by evidence trajectories.
  `Acceptance Criteria:` Sweep cadence adjusts according to policy evidence bands; escalation/de-escalation hysteresis prevents oscillation; decisions are ledgered.
  `Artifacts:` `src/policy/integrity_sweep_scheduler.rs`, `tests/perf/integrity_sweep_adaptation.rs`, `artifacts/10.14/sweep_policy_trajectory.csv`.
- [ ] Emit "durability contract violated" diagnostic bundles when hardening cannot restore verifiability.
  `Acceptance Criteria:` Violation bundles include causal event sequence, failed artifacts, and proof context; bundle generation is deterministic; gating operations are halted per policy.
  `Artifacts:` `docs/runbooks/durability_contract_violated.md`, `tests/integration/durability_violation_bundle.rs`, `artifacts/10.14/durability_violation_bundle_example.json`.
- [ ] Gate durable-claiming operations on verifiable marker/proof availability.
  `Acceptance Criteria:` Durable claims fail closed when marker/proof verification is incomplete; claim API exposes reason codes; false-claim path is blocked in tests.
  `Artifacts:` `tests/security/durable_claim_gate.rs`, `docs/specs/durable_claim_requirements.md`, `artifacts/10.14/durable_claim_gate_results.json`.
- [ ] Integrate proof-carrying repair artifacts into decode/reconstruction paths.
  `Acceptance Criteria:` Repair operations emit proof metadata in required modes; proof verification API validates emitted artifacts; missing proofs are flagged where mandatory.
  `Artifacts:` `src/repair/proof_carrying_decode.rs`, `tests/conformance/proof_carrying_repair.rs`, `artifacts/10.14/repair_proof_samples.json`.
- [ ] Add suspicious-artifact challenge flow that requests proof artifacts before trust promotion.
  `Acceptance Criteria:` Challenge workflow can defer promotion pending proof response; unresolved challenges timeout to deny by default; challenge states are auditable.
  `Artifacts:` `docs/specs/suspicious_artifact_challenge.md`, `tests/security/challenge_flow_before_promotion.rs`, `artifacts/10.14/challenge_flow_transcript.json`.
- [ ] Add proof-presence requirement for quarantine promotion in high-assurance modes.
  `Acceptance Criteria:` High-assurance mode promotion fails without required proof bundle; mode toggle is policy-controlled; conformance covers both assurance modes.
  `Artifacts:` `tests/conformance/high_assurance_quarantine_promotion.rs`, `docs/specs/high_assurance_promotion.md`, `artifacts/10.14/high_assurance_promotion_matrix.json`.
- [ ] Implement content-derived deterministic seed derivation for encoding/repair schedules.
  `Acceptance Criteria:` Seed derivation is domain-separated and stable; identical content/config produces identical schedule; schedule changes require version bump artifact.
  `Artifacts:` `src/encoding/deterministic_seed.rs`, `tests/conformance/deterministic_seed_derivation.rs`, `artifacts/10.14/seed_derivation_vectors.json`.
- [ ] Add determinism conformance tests ensuring identical artifacts across replicas for identical content/config.
  `Acceptance Criteria:` Multi-replica fixture run yields byte-identical artifact sets; divergence test reports first mismatch and root cause; tests run in CI.
  `Artifacts:` `tests/conformance/replica_artifact_determinism.rs`, `fixtures/determinism/*`, `artifacts/10.14/determinism_conformance_results.csv`.
- [ ] Define object-class profile registry (critical marker, trust receipt, replay bundle, telemetry artifact).
  `Acceptance Criteria:` Registry includes required classes and default policies; unknown class usage fails validation; class definitions are versioned.
  `Artifacts:` `docs/specs/object_class_profiles.md`, `config/object_class_profiles.toml`, `artifacts/10.14/object_class_registry.json`.
- [ ] Implement per-class symbol-size/overhead/fetch policy with benchmark-derived defaults.
  `Acceptance Criteria:` Policy engine applies class-specific defaults at runtime; defaults are justified by benchmark data; policy override path is audited.
  `Artifacts:` `src/policy/object_class_tuning.rs`, `benchmarks/object_class_tuning/*`, `artifacts/10.14/object_class_policy_report.csv`.
- [ ] Add profile tuning harness and publish benchmark-driven policy updates as signed artifacts.
  `Acceptance Criteria:` Harness recomputes candidate policy updates reproducibly; updates are signed and linked to benchmark provenance; unsafe regressions are auto-rejected.
  `Artifacts:` `tools/profile_tuning_harness.rs`, `docs/specs/policy_update_signing.md`, `artifacts/10.14/signed_policy_update_bundle.json`.
- [ ] Implement L1/L2/L3 trust artifact storage abstraction with explicit source-of-truth designation.
  `Acceptance Criteria:` Tier abstraction exposes clear authority boundaries; source-of-truth is explicit and immutable by class; recovery path reconstructs derived tiers.
  `Artifacts:` `docs/specs/tiered_trust_storage.md`, `tests/integration/tiered_storage_recovery.rs`, `artifacts/10.14/tiered_storage_authority_map.json`.
- [ ] Implement `durability=local` and `durability=quorum(M)` semantics for control/trust artifacts.
  `Acceptance Criteria:` Mode semantics are enforced end-to-end; mode switches are auditable and policy-gated; claim language mapping is deterministic.
  `Artifacts:` `docs/specs/durability_modes.md`, `tests/conformance/durability_mode_semantics.rs`, `artifacts/10.14/durability_mode_claim_matrix.json`.
- [ ] Implement retrievability-before-eviction proofs for L2->L3 lifecycle transitions.
  `Acceptance Criteria:` Eviction requires successful retrievability proof check; failed proofs block eviction; proof records tie to retired segment IDs.
  `Artifacts:` `src/storage/retrievability_gate.rs`, `tests/integration/retrievability_before_eviction.rs`, `artifacts/10.14/retrievability_proof_receipts.json`.
- [ ] Implement cancel-safe eviction saga (upload -> verify -> retire) with deterministic compensations.
  `Acceptance Criteria:` Saga guarantees no partial retire on cancellation/crash; compensation path is deterministic; leak tests confirm zero orphan states.
  `Artifacts:` `docs/specs/eviction_saga.md`, `tests/integration/eviction_saga_cancel_safety.rs`, `artifacts/10.14/eviction_saga_trace.jsonl`.
- [ ] Require `RemoteCap` (or equivalent) for all network-bound trust/control operations.
  `Acceptance Criteria:` Network-bound operations fail without capability token; capability checks are centralized and auditable; local-only mode remains functional.
  `Artifacts:` `tests/security/remote_cap_enforcement.rs`, `docs/specs/remote_cap_contract.md`, `artifacts/10.14/remote_cap_denials.json`.
- [ ] Implement named remote computation registry and reject unknown computation identifiers.
  `Acceptance Criteria:` Remote execution accepts only registered computation names; unknown or malformed names are rejected with stable codes; registry is versioned.
  `Artifacts:` `src/remote/computation_registry.rs`, `tests/conformance/remote_name_registry.rs`, `artifacts/10.14/remote_registry_catalog.json`.
- [ ] Implement idempotency key derivation from request bytes with epoch binding.
  `Acceptance Criteria:` Key derivation is deterministic, domain-separated, and epoch-bound; collisions on distinct requests are empirically negligible; derivation vectors are published.
  `Artifacts:` `src/remote/idempotency.rs`, `tests/conformance/idempotency_key_derivation.rs`, `artifacts/10.14/idempotency_vectors.json`.
- [ ] Implement idempotency dedupe store semantics (same key/same payload returns cached outcome; mismatch conflicts).
  `Acceptance Criteria:` Duplicate same-payload requests are safely deduped; same-key different-payload conflicts hard-fail; dedupe state handles restart recovery.
  `Artifacts:` `tests/integration/idempotency_dedupe_store.rs`, `docs/specs/idempotency_store_semantics.md`, `artifacts/10.14/idempotency_conflict_report.json`.
- [ ] Enforce global remote bulkhead with configurable `remote_max_in_flight` and overload backpressure.
  `Acceptance Criteria:` In-flight remote operations never exceed cap; overload applies deterministic backpressure policy; p99 foreground latency remains within target under degradation.
  `Artifacts:` `src/remote/remote_bulkhead.rs`, `tests/perf/remote_bulkhead_under_load.rs`, `artifacts/10.14/remote_bulkhead_latency_report.csv`.
- [ ] Map remote/control tasks to lane-aware scheduler classes with priority policies.
  `Acceptance Criteria:` Task classes are mapped to lanes by policy; lane starvation and misclassification checks are enforced; lane telemetry is exposed.
  `Artifacts:` `docs/specs/lane_mapping_policy.md`, `tests/conformance/lane_mapping_enforcement.rs`, `artifacts/10.14/lane_mapping_metrics.csv`.
- [ ] Define monotonic control epoch in canonical manifest state.
  `Acceptance Criteria:` Epoch value is monotonic and durable; regressions are rejected; epoch changes produce signed control events.
  `Artifacts:` `docs/specs/control_epoch_contract.md`, `tests/conformance/control_epoch_monotonicity.rs`, `artifacts/10.14/control_epoch_history.json`.
- [ ] Implement fail-closed validity window check rejecting future-epoch artifacts.
  `Acceptance Criteria:` Future-epoch artifacts are rejected before use; validity window policy is explicit and test-covered; rejection telemetry includes epoch context.
  `Artifacts:` `tests/security/future_epoch_rejection.rs`, `docs/specs/validity_window_rules.md`, `artifacts/10.14/epoch_rejection_events.json`.
- [ ] Implement epoch-scoped key derivation for trust artifact authentication.
  `Acceptance Criteria:` Authentication key derivation binds to epoch and domain; cross-epoch key reuse is impossible by construction; verification vectors are published.
  `Artifacts:` `src/security/epoch_scoped_keys.rs`, `tests/conformance/epoch_key_derivation.rs`, `artifacts/10.14/epoch_key_vectors.json`.
- [ ] Implement epoch transition barrier protocol across core services with drain requirements.
  `Acceptance Criteria:` Barrier requires participant drain acknowledgements; transition commits only on full barrier success; timeout path aborts safely with evidence.
  `Artifacts:` `docs/specs/epoch_barrier_protocol.md`, `tests/integration/epoch_transition_barrier.rs`, `artifacts/10.14/epoch_barrier_transcripts.json`.
- [ ] Implement transition abort semantics on timeout/cancellation unless explicit force policy is provided.
  `Acceptance Criteria:` Default behavior aborts transition on timeout/cancel; force policy is explicit, scoped, and audited; partial transition state is impossible.
  `Artifacts:` `tests/security/epoch_transition_abort_semantics.rs`, `docs/specs/force_transition_policy.md`, `artifacts/10.14/transition_abort_events.json`.
- [ ] Implement append-only marker stream for high-impact control events with dense sequence invariant checks.
  `Acceptance Criteria:` Marker stream is append-only with dense sequence and hash-chain invariants; torn-tail recovery is deterministic; invariant breaks trigger hard alert.
  `Artifacts:` `src/control_plane/marker_stream.rs`, `tests/conformance/marker_stream_invariants.rs`, `artifacts/10.14/marker_stream_integrity_report.json`.
- [ ] Implement O(1) marker lookup by sequence and O(log N) timestamp-to-sequence search.
  `Acceptance Criteria:` Sequence lookup performs O(1) slot math; timestamp lookup uses bounded O(log N) search; performance targets are met on large history sets.
  `Artifacts:` `tests/perf/marker_lookup_complexity.rs`, `docs/specs/marker_lookup_algorithms.md`, `artifacts/10.14/marker_lookup_benchmarks.csv`.
- [ ] Implement fork/divergence detection via marker-id prefix comparison and binary search.
  `Acceptance Criteria:` Divergence finder returns greatest common prefix deterministically; fork detection scales logarithmically; mismatch evidence includes exact divergence point.
  `Artifacts:` `tests/integration/marker_divergence_detection.rs`, `docs/specs/divergence_detection.md`, `artifacts/10.14/divergence_detection_examples.json`.
- [ ] Implement optional MMR checkpoints and inclusion/prefix proof APIs for external verifiers.
  `Acceptance Criteria:` MMR checkpoints can be enabled/disabled without corrupting marker truth; proof APIs verify inclusion and prefix claims; verifier examples pass.
  `Artifacts:` `src/control_plane/mmr_proofs.rs`, `tests/conformance/mmr_proof_verification.rs`, `artifacts/10.14/mmr_proof_vectors.json`.
- [ ] Implement root pointer atomic publication protocol (`write temp -> fsync temp -> rename -> fsync dir`).
  `Acceptance Criteria:` Publication protocol survives crash-injection tests without ambiguous root; missing fsync steps are detected by tests; root switch is atomic.
  `Artifacts:` `docs/specs/root_publication_protocol.md`, `tests/integration/root_pointer_crash_safety.rs`, `artifacts/10.14/root_publication_crash_matrix.csv`.
- [ ] Implement root-auth fail-closed bootstrap checks before accepting manifest updates.
  `Acceptance Criteria:` Bootstrap rejects unauthenticated or malformed root pointers; acceptance requires valid auth material and version checks; failures are diagnosable.
  `Artifacts:` `tests/security/root_bootstrap_fail_closed.rs`, `docs/specs/root_bootstrap_auth.md`, `artifacts/10.14/root_bootstrap_validation_report.json`.
- [ ] Implement deterministic repro bundle export for control-plane failures and policy incidents.
  `Acceptance Criteria:` Repro bundles include seed, config, event-sequence trace, and evidence references; replay tool re-executes incident deterministically; bundle schema is versioned.
  `Artifacts:` `src/tools/repro_bundle_export.rs`, `tests/integration/repro_bundle_replay.rs`, `artifacts/10.14/repro_bundle_schema_v1.json`.
- [ ] Implement virtual transport fault harness (drop/reorder/corrupt) for remote-control protocol testing.
  `Acceptance Criteria:` Harness supports deterministic fault schedules from seed; scenarios cover drop/reorder/corrupt classes; reproductions include exact fault sequence.
  `Artifacts:` `tests/harness/virtual_transport_faults.rs`, `docs/testing/virtual_transport_harness.md`, `artifacts/10.14/virtual_fault_campaign_results.json`.
- [ ] Add cancellation injection at all await points for critical control workflows in lab tests.
  `Acceptance Criteria:` Critical workflows are instrumented for all-point cancellation injection; leak-free and half-commit-free invariants hold under injected cancellations.
  `Artifacts:` `tests/lab/cancellation_injection_control_workflows.rs`, `docs/testing/cancel_injection_matrix.md`, `artifacts/10.14/cancel_injection_report.json`.
- [ ] Add DPOR-style schedule exploration gates for control/epoch/remote protocols.
  `Acceptance Criteria:` DPOR explorer covers targeted protocol classes; minimal counterexample traces are emitted on failure; gate runs within bounded CI budget.
  `Artifacts:` `tests/lab/dpor_protocol_exploration.rs`, `docs/testing/dpor_gate_scope.md`, `artifacts/10.14/dpor_exploration_summary.json`.
- [ ] Add conformance suite for ledger determinism, idempotency, epoch validity, and marker/MMR proof correctness.
  `Acceptance Criteria:` Suite includes normative fixtures for all four domains; suite is required for release profile claim; failures map to stable conformance IDs.
  `Artifacts:` `tests/conformance/fsqlite_inspired_suite.rs`, `fixtures/conformance/fsqlite_inspired/*`, `artifacts/10.14/fsqlite_inspired_conformance_report.json`.

### 10.15 Asupersync-First Integration Execution Track (8.4-8.6)
- [ ] Publish tri-kernel ownership contract (`franken_engine`, `asupersync`, `franken_node`) with explicit interface boundaries.
  `Acceptance Criteria:` Contract names owners for execution, correctness, and product planes; boundary violations have deterministic CI failures; exceptions require signed waiver artifact.
  `Artifacts:` `docs/architecture/tri_kernel_ownership_contract.md`, `tests/conformance/ownership_boundary_checks.rs`, `artifacts/10.15/ownership_boundary_report.json`.
- [ ] Define high-impact workflow inventory mapped to required asupersync primitives.
  `Acceptance Criteria:` Every critical workflow is mapped to `Cx`, region, cancellation, obligation, remote, epoch, and evidence requirements; unmapped workflows fail planning gate.
  `Artifacts:` `docs/architecture/high_impact_workflow_map.md`, `artifacts/10.15/workflow_primitive_matrix.json`.
- [ ] Enforce Cx-first signature policy for control-plane async entrypoints.
  `Acceptance Criteria:` Lint/gate rejects new high-impact async APIs missing `&Cx`; existing exceptions are enumerated and time-bounded.
  `Artifacts:` `tools/lints/cx_first_policy.rs`, `tests/conformance/cx_first_api_gate.rs`, `artifacts/10.15/cx_first_compliance.csv`.
- [ ] Add ambient-authority audit gate for control-plane modules.
  `Acceptance Criteria:` Ambient network/spawn/time effects in restricted modules fail CI; allowlist is explicit and signed.
  `Artifacts:` `tools/lints/ambient_authority_gate.rs`, `docs/specs/ambient_authority_policy.md`, `artifacts/10.15/ambient_authority_findings.json`.
- [ ] Migrate lifecycle/rollout orchestration to region-owned execution trees.
  `Acceptance Criteria:` Lifecycle orchestration runs under region ownership; region close implies quiescence in conformance tests.
  `Artifacts:` `tests/integration/region_owned_lifecycle.rs`, `docs/specs/region_tree_topology.md`, `artifacts/10.15/region_quiescence_trace.jsonl`.
- [ ] Implement request -> drain -> finalize cancellation protocol across high-impact workflows.
  `Acceptance Criteria:` Cancellation transitions are explicit and deterministic; cleanup budget bounds are documented and tested.
  `Artifacts:` `docs/specs/cancellation_protocol_contract.md`, `tests/conformance/cancel_drain_finalize.rs`, `artifacts/10.15/cancel_protocol_timing.csv`.
- [ ] Replace critical ad hoc messaging with obligation-tracked two-phase channels.
  `Acceptance Criteria:` Publish/revoke/quarantine/migration critical paths use reserve/commit semantics; leak oracle remains green under cancellation injection.
  `Artifacts:` `tests/security/obligation_tracked_channels.rs`, `docs/specs/two_phase_effects.md`, `artifacts/10.15/obligation_leak_oracle_report.json`.
- [ ] Define lane mapping policy for control-plane workloads (Cancel/Timed/Ready).
  `Acceptance Criteria:` Every control task class has lane assignment and budget policy; starvation checks are automated.
  `Artifacts:` `docs/specs/control_lane_mapping.md`, `tests/conformance/control_lane_policy.rs`, `artifacts/10.15/lane_starvation_metrics.csv`.
- [ ] Integrate canonical remote named-computation registry (from `10.14`) for control-plane distributed actions.
  `Acceptance Criteria:` Control-plane paths use the same canonical registry semantics as `10.14`; unknown names fail closed with stable error class; no divergent registry behavior is introduced.
  `Artifacts:` `docs/integration/control_remote_registry_adoption.md`, `tests/conformance/named_remote_computations.rs`, `artifacts/10.15/remote_registry_adoption_report.json`.
- [ ] Enforce canonical idempotency-key contracts (from `10.14`) on all retryable remote control requests.
  `Acceptance Criteria:` Control-plane requests inherit canonical idempotency semantics; duplicate same-payload requests dedupe safely; same-key/payload-mismatch hard-fails.
  `Artifacts:` `tests/integration/control_remote_idempotency.rs`, `docs/integration/control_idempotency_adoption.md`, `artifacts/10.15/control_idempotency_report.json`.
- [ ] Add saga wrappers with deterministic compensations for multi-step remote+local workflows.
  `Acceptance Criteria:` Cancellation/crash at any step leaves equivalent "never happened" state or committed terminal state; compensation traces are replay-stable.
  `Artifacts:` `docs/specs/control_sagas.md`, `tests/integration/control_saga_compensation.rs`, `artifacts/10.15/control_saga_traces.jsonl`.
- [ ] Integrate canonical epoch-scoped validity windows (from `10.14`) for control artifacts and remote contracts.
  `Acceptance Criteria:` Control-plane operations use canonical epoch-validity semantics; future-epoch artifacts are rejected fail-closed; epoch scope is logged for accepted high-impact operations.
  `Artifacts:` `tests/security/control_epoch_validity.rs`, `docs/integration/control_epoch_validity_adoption.md`, `artifacts/10.15/epoch_validity_decisions.json`.
- [ ] Integrate canonical epoch transition barriers (from `10.14`) across control services with explicit abort semantics.
  `Acceptance Criteria:` Control transitions use canonical barrier protocol; transition commits only with full participant arrival/drain; timeout/cancel abort behavior remains deterministic.
  `Artifacts:` `docs/integration/control_epoch_barrier_adoption.md`, `tests/integration/control_epoch_barrier.rs`, `artifacts/10.15/control_epoch_barrier_transcript.json`.
- [ ] Make canonical evidence-ledger emission (from `10.14`) mandatory for policy-influenced control decisions.
  `Acceptance Criteria:` Missing evidence entry for policy-influenced decision is a conformance failure; control-plane entries align with canonical schema and ordering.
  `Artifacts:` `tests/conformance/control_policy_evidence_required.rs`, `docs/integration/control_evidence_contract.md`, `artifacts/10.15/control_evidence_samples.jsonl`.
- [ ] Integrate canonical evidence replay validator (from `10.14`) into control-plane decision gates.
  `Acceptance Criteria:` Given evidence + inputs, canonical replay validator reproduces chosen decision or emits minimal deterministic diff; control-plane gate consumes verdict.
  `Artifacts:` `tests/conformance/control_evidence_replay.rs`, `docs/integration/control_evidence_replay_adoption.md`, `artifacts/10.15/control_evidence_replay_report.json`.
- [ ] Integrate deterministic lab runtime scenarios for all high-impact control protocols.
  `Acceptance Criteria:` Canonical control scenarios replay identically by seed; protocol invariants are asserted with deterministic failure artifacts.
  `Artifacts:` `tests/lab/control_protocol_scenarios.rs`, `docs/testing/control_lab_scenarios.md`, `artifacts/10.15/control_lab_seed_matrix.json`.
- [ ] Enforce canonical all-point cancellation injection gate (from `10.14`) for critical control workflows.
  `Acceptance Criteria:` Canonical cancellation injection runs on every critical protocol flow; no obligation leaks, no half-commit outcomes, no quiescence violations.
  `Artifacts:` `tests/lab/control_cancellation_injection.rs`, `artifacts/10.15/control_cancel_injection_report.json`.
- [ ] Enforce canonical virtual transport fault harness (from `10.14`) for distributed control protocols.
  `Acceptance Criteria:` Canonical harness scenarios are deterministic by seed, adopted by control-plane gates, and reproduce distributed protocol decisions and failures.
  `Artifacts:` `tests/harness/control_virtual_transport_faults.rs`, `docs/testing/control_virtual_transport_faults.md`, `artifacts/10.15/control_fault_harness_summary.json`.
- [ ] Enforce canonical DPOR-style schedule exploration (from `10.14`) for epoch/lease/remote/evidence interactions.
  `Acceptance Criteria:` Canonical explorer covers targeted protocol classes with bounded CI budget; minimal counterexample traces are emitted on violations and consumed by control-plane release gates.
  `Artifacts:` `tests/lab/control_dpor_exploration.rs`, `docs/testing/control_dpor_scope.md`, `artifacts/10.15/control_dpor_results.json`.
- [ ] Add release gate requiring asupersync-backed conformance on high-impact features.
  `Acceptance Criteria:` Release pipeline blocks claims/features lacking required conformance artifacts; gate output is machine-readable and signed.
  `Artifacts:` `.github/workflows/asupersync-integration-gate.yml`, `docs/conformance/asupersync_release_gate.md`, `artifacts/10.15/release_gate_report.json`.
- [ ] Add observability dashboards for region health, obligation health, lane pressure, and cancel latency.
  `Acceptance Criteria:` Dashboards expose core runtime health invariants with alert thresholds; metrics are mapped to runbook actions.
  `Artifacts:` `docs/observability/asupersync_control_dashboards.md`, `artifacts/10.15/dashboard_snapshot.json`, `artifacts/10.15/alert_policy_map.json`.
- [ ] Add invariant-breach runbooks for region-quiescence failure, obligation leak, and cancel-timeout incidents.
  `Acceptance Criteria:` Runbooks include detection signature, immediate containment steps, replay procedure, and rollback procedure.
  `Artifacts:` `docs/runbooks/region_quiescence_breach.md`, `docs/runbooks/obligation_leak_incident.md`, `docs/runbooks/cancel_timeout_incident.md`.
- [ ] Add migration plan for existing non-asupersync control surfaces with scope burn-down tracking.
  `Acceptance Criteria:` Legacy control paths are inventoried with migration status and closure criteria; remaining exceptions are explicitly justified.
  `Artifacts:` `docs/migration/asupersync_control_surface_migration.md`, `artifacts/10.15/control_surface_burndown.csv`.
- [ ] Add performance budget guard for asupersync integration overhead in control-plane hot paths.
  `Acceptance Criteria:` Integration overhead remains within agreed p95/p99/cold-start budgets; regressions fail CI and include flamegraph evidence.
  `Artifacts:` `benchmarks/asupersync_integration_overhead/*`, `tests/perf/control_plane_overhead_gate.rs`, `artifacts/10.15/integration_overhead_report.csv`.
- [ ] Define claim-language policy tying trust/replay claims to asupersync-backed invariant evidence.
  `Acceptance Criteria:` Public claim templates enforce evidence references; unverifiable claim text is blocked by documentation gate.
  `Artifacts:` `docs/policy/claim_language_asupersync_requirements.md`, `tests/conformance/claim_language_gate.rs`, `artifacts/10.15/claim_language_gate_report.json`.

### 10.16 Adjacent Substrate Integration Execution Track (8.7)
- [ ] Publish substrate policy contract for `frankentui`, `frankensqlite`, `sqlmodel_rust`, and `fastapi_rust`.
  `Acceptance Criteria:` Policy contract defines mandatory/should-use scopes, exceptions, and waiver process; CI can parse contract metadata.
  `Artifacts:` `docs/architecture/adjacent_substrate_policy.md`, `artifacts/10.16/adjacent_substrate_policy_manifest.json`.
- [ ] Add architecture dependency map showing where each adjacent substrate is required in `franken_node`.
  `Acceptance Criteria:` Map covers presentation, persistence, model, and service planes; unmapped relevant modules fail architecture review gate.
  `Artifacts:` `docs/architecture/adjacent_substrate_dependency_map.md`, `artifacts/10.16/substrate_dependency_matrix.json`.
- [ ] Define `frankentui` integration contract for all relevant console/TUI surfaces.
  `Acceptance Criteria:` Contract specifies component boundaries, styling/token strategy, and rendering/event-loop integration expectations.
  `Artifacts:` `docs/specs/frankentui_integration_contract.md`, `artifacts/10.16/frankentui_contract_checklist.json`.
- [ ] Migrate existing or planned relevant TUI workflows to `frankentui` primitives.
  `Acceptance Criteria:` Relevant workflows use `frankentui` abstraction points; no duplicate homegrown TUI stack remains in migrated surfaces.
  `Artifacts:` `tests/integration/frankentui_surface_migration.rs`, `artifacts/10.16/frankentui_surface_inventory.csv`.
- [ ] Add deterministic visual/snapshot and interaction tests for `frankentui`-backed surfaces.
  `Acceptance Criteria:` Snapshot suite runs in CI and catches visual regressions; keyboard-interaction paths are replayable and stable.
  `Artifacts:` `tests/tui/frankentui_snapshots.rs`, `artifacts/10.16/frankentui_snapshot_report.json`.
- [ ] Define `frankensqlite` persistence integration contract for control/audit/replay state.
  `Acceptance Criteria:` Contract enumerates required persistence classes and durability modes; storage semantics map to product safety tiers.
  `Artifacts:` `docs/specs/frankensqlite_persistence_contract.md`, `artifacts/10.16/frankensqlite_persistence_matrix.json`.
- [ ] Implement `frankensqlite` adapter layer for required `franken_node` persistence surfaces.
  `Acceptance Criteria:` Required persistence APIs route through adapter; conformance tests validate deterministic read/write/replay semantics.
  `Artifacts:` `src/storage/frankensqlite_adapter.rs`, `tests/integration/frankensqlite_adapter_conformance.rs`, `artifacts/10.16/frankensqlite_adapter_report.json`.
- [ ] Add migration path from interim/local stores to `frankensqlite` for relevant state domains.
  `Acceptance Criteria:` Migration tooling is deterministic and idempotent; rollback path exists; migrated data matches source invariants.
  `Artifacts:` `docs/migration/to_frankensqlite.md`, `tests/migration/frankensqlite_migration_idempotence.rs`, `artifacts/10.16/frankensqlite_migration_report.json`.
- [ ] Define `sqlmodel_rust` usage policy and typed model boundaries.
  `Acceptance Criteria:` Policy defines where typed models are mandatory vs optional; model ownership and codegen/versioning expectations are explicit.
  `Artifacts:` `docs/specs/sqlmodel_rust_usage_policy.md`, `artifacts/10.16/sqlmodel_policy_matrix.json`.
- [ ] Integrate `sqlmodel_rust` in domains where typed schema/query safety is high-EV.
  `Acceptance Criteria:` Selected domains use typed models and query contracts; schema drift is caught by conformance checks.
  `Artifacts:` `tests/conformance/sqlmodel_contracts.rs`, `artifacts/10.16/sqlmodel_integration_domains.csv`.
- [ ] Define `fastapi_rust` control-plane service integration contract.
  `Acceptance Criteria:` Contract defines endpoint lifecycle, auth/policy hooks, error contract mapping, and observability requirements.
  `Artifacts:` `docs/specs/fastapi_rust_integration_contract.md`, `artifacts/10.16/fastapi_contract_checklist.json`.
- [ ] Build `fastapi_rust` service skeleton for required operator/verifier/fleet-control endpoints.
  `Acceptance Criteria:` Skeleton exposes required endpoint groups with policy and trace correlation hooks; service conformance tests pass.
  `Artifacts:` `services/control_plane_fastapi_rust/*`, `tests/integration/fastapi_control_plane_endpoints.rs`, `artifacts/10.16/fastapi_endpoint_report.json`.
- [ ] Add cross-substrate contract tests validating end-to-end behavior (`frankentui` -> service -> persistence).
  `Acceptance Criteria:` End-to-end tests cover representative operator flows and replay determinism; failure includes cross-layer trace.
  `Artifacts:` `tests/e2e/adjacent_substrate_flow.rs`, `artifacts/10.16/adjacent_substrate_e2e_report.json`.
- [ ] Add substrate conformance gate in CI to block non-compliant feature merges.
  `Acceptance Criteria:` CI detects relevant-feature noncompliance with substrate policy; failures include remediation hints and waiver path.
  `Artifacts:` `.github/workflows/adjacent-substrate-gate.yml`, `tests/conformance/adjacent_substrate_gate.rs`, `artifacts/10.16/adjacent_substrate_gate_report.json`.
- [ ] Add waiver workflow for justified substrate exceptions.
  `Acceptance Criteria:` Waivers require risk analysis, bounded scope, owner signoff, and expiry date; expired waivers fail compliance gate.
  `Artifacts:` `docs/policy/adjacent_substrate_waiver_process.md`, `artifacts/10.16/waiver_registry.json`.
- [ ] Add performance overhead guardrails for adjacent substrate integrations.
  `Acceptance Criteria:` Integration overhead budgets are defined and enforced; regressions fail perf gate with before/after evidence.
  `Artifacts:` `tests/perf/adjacent_substrate_overhead_gate.rs`, `artifacts/10.16/adjacent_substrate_overhead_report.csv`.
- [ ] Add claim-language gate tying UI/service/storage claims to substrate-backed evidence.
  `Acceptance Criteria:` Documentation and release claims about TUI/API/storage behavior require linked substrate conformance artifacts; unlinked claims are blocked.
  `Artifacts:` `docs/policy/adjacent_substrate_claim_language.md`, `tests/conformance/adjacent_claim_language_gate.rs`, `artifacts/10.16/adjacent_claim_language_gate_report.json`.

### 10.17 Radical Expansion Execution Track (9K)
- [ ] Build proof-carrying speculative execution governance framework for extension-host hot paths.
  `Acceptance Criteria:` Speculative transforms cannot activate without proof receipts and guard checks; guard failure always degrades to deterministic safe baseline with no correctness regression; activation occurs only via approved franken_engine interfaces.
  `Artifacts:` `docs/specs/proof_carrying_speculation.md`, `src/runtime/speculation/proof_executor.rs`, `tests/conformance/proof_speculation_guards.rs`, `artifacts/10.17/speculation_proof_report.json`.
- [ ] Implement Bayesian adversary graph and automated quarantine controller.
  `Acceptance Criteria:` Risk posterior updates are deterministic from identical evidence; policy thresholds trigger reproducible control actions (throttle/isolate/revoke/quarantine) with signed evidence entries.
  `Artifacts:` `src/security/adversary_graph.rs`, `src/security/quarantine_controller.rs`, `tests/integration/bayesian_risk_quarantine.rs`, `artifacts/10.17/adversary_graph_state.json`.
- [ ] Add deterministic time-travel runtime capture/replay for extension-host workflows.
  `Acceptance Criteria:` Captured executions replay byte-for-byte equivalent control decisions under same seed/input; incident replay includes stepwise state navigation and divergence explanation.
  `Artifacts:` `docs/specs/time_travel_runtime.md`, `src/replay/time_travel_engine.rs`, `tests/lab/time_travel_replay_equivalence.rs`, `artifacts/10.17/time_travel_replay_report.json`.
- [ ] Define and enforce capability-carrying extension artifact format.
  `Acceptance Criteria:` Artifact admission fails closed on missing/invalid capability contracts; runtime enforcement matches admitted capability envelope without drift.
  `Artifacts:` `docs/specs/capability_artifact_format.md`, `src/extensions/artifact_contract.rs`, `tests/conformance/capability_artifact_admission.rs`, `artifacts/10.17/capability_artifact_vectors.json`.
- [ ] Ship adaptive multi-rail isolation mesh with hot-elevation policy.
  `Acceptance Criteria:` Workloads can be promoted to stricter rails at runtime without losing policy continuity; latency-sensitive trusted workloads remain on high-performance rails within budget.
  `Artifacts:` `docs/architecture/isolation_mesh.md`, `src/security/isolation_rail_router.rs`, `tests/integration/isolation_hot_elevation.rs`, `artifacts/10.17/isolation_mesh_profile_report.json`.
- [ ] Add zero-knowledge attestation support for selective compliance verification.
  `Acceptance Criteria:` Verifiers can validate compliance predicates without privileged disclosure of full private metadata; invalid/forged proofs fail admission.
  `Artifacts:` `docs/specs/zk_attestation_contract.md`, `src/trust/zk_attestation.rs`, `tests/security/zk_attestation_verification.rs`, `artifacts/10.17/zk_attestation_vectors.json`.
- [ ] Implement L2 engine-boundary N-version semantic oracle across franken_engine and reference runtimes.
  `Acceptance Criteria:` Differential harness classifies boundary divergences by risk tier and blocks release on high-risk unresolved deltas; low-risk deltas require explicit policy receipts and link back to L1 product-oracle results.
  `Artifacts:` `tests/oracle/n_version_semantic_oracle.rs`, `docs/testing/semantic_oracle_policy.md`, `artifacts/10.17/semantic_oracle_divergence_matrix.csv`.
- [ ] Implement security staking and slashing framework for publisher trust governance.
  `Acceptance Criteria:` High-risk capabilities enforce stake policy gates; validated malicious behavior triggers deterministic slashing workflow with appeal/audit trail artifacts.
  `Artifacts:` `docs/policy/security_staking_and_slashing.md`, `src/registry/staking_governance.rs`, `tests/integration/staking_slashing_flows.rs`, `artifacts/10.17/staking_ledger_snapshot.json`.
- [ ] Build self-evolving optimization governor with safety-envelope enforcement.
  `Acceptance Criteria:` Candidate optimizations require shadow evaluation plus anytime-valid safety checks; unsafe or non-beneficial policies auto-reject or auto-revert with evidence; governor can only adjust exposed runtime knobs, not local engine-core internals.
  `Artifacts:` `docs/specs/optimization_governor.md`, `src/perf/optimization_governor.rs`, `tests/perf/governor_safety_envelope.rs`, `artifacts/10.17/governor_decision_log.jsonl`.
- [ ] Ship intent-aware remote effects firewall for extension-originated traffic.
  `Acceptance Criteria:` Requests receive stable intent classification and policy verdicts; risky intent categories trigger challenge/simulate/deny/quarantine pathways with deterministic receipts.
  `Artifacts:` `src/security/intent_firewall.rs`, `docs/specs/intent_effects_policy.md`, `tests/security/intent_firewall_conformance.rs`, `artifacts/10.17/intent_firewall_eval_report.json`.
- [ ] Implement information-flow lineage and exfiltration sentinel.
  `Acceptance Criteria:` Sensitive lineage tags persist across supported execution flows; simulated covert exfiltration scenarios are detected and auto-contained above defined recall/precision thresholds.
  `Artifacts:` `docs/specs/information_flow_sentinel.md`, `src/security/lineage_tracker.rs`, `tests/security/exfiltration_sentinel_scenarios.rs`, `artifacts/10.17/exfiltration_detector_metrics.csv`.
- [ ] Publish universal verifier SDK and replay capsule format.
  `Acceptance Criteria:` External verifiers can replay signed capsules and reproduce claim verdicts without privileged internal access; capsule schema and verification APIs are stable and versioned.
  `Artifacts:` `sdk/verifier/*`, `docs/specs/replay_capsule_format.md`, `tests/conformance/verifier_sdk_capsule_replay.rs`, `artifacts/10.17/verifier_sdk_certification_report.json`.
- [ ] Implement heterogeneous hardware planner with policy-evidenced placements.
  `Acceptance Criteria:` Placement decisions satisfy capability/risk constraints and remain reproducible from identical inputs; planner reports policy reasoning and fallback path on resource contention; dispatch executes through approved runtime/engine interfaces.
  `Artifacts:` `docs/architecture/hardware_execution_planner.md`, `src/runtime/hardware_planner.rs`, `tests/perf/hardware_planner_policy_conformance.rs`, `artifacts/10.17/hardware_placement_trace.json`.
- [ ] Build counterfactual incident lab and mitigation synthesis workflow.
  `Acceptance Criteria:` Real incident traces can be replayed and compared against synthesized mitigations with expected-loss deltas; promoted mitigations require signed rollout and rollback contracts.
  `Artifacts:` `docs/specs/counterfactual_incident_lab.md`, `tests/lab/counterfactual_mitigation_eval.rs`, `src/ops/mitigation_synthesis.rs`, `artifacts/10.17/counterfactual_eval_report.json`.
- [ ] Implement claim compiler and public trust scoreboard pipeline.
  `Acceptance Criteria:` External claims must compile to executable evidence contracts; unverifiable claim text is blocked and scoreboard updates publish signed evidence links.
  `Artifacts:` `docs/specs/claim_compiler.md`, `src/claims/claim_compiler.rs`, `tests/conformance/claim_compiler_gate.rs`, `artifacts/10.17/public_trust_scoreboard_snapshot.json`.

### 10.18 Verifiable Execution Fabric Execution Track (9L)
- [ ] Define VEF policy-constraint language and compiler contract for high-risk action classes.
  `Acceptance Criteria:` Constraint language maps runtime policy to proof-checkable predicates for required action classes; compiler outputs are deterministic and versioned.
  `Artifacts:` `docs/specs/vef_policy_constraint_language.md`, `spec/vef_policy_constraints_v1.json`, `artifacts/10.18/vef_constraint_compiler_report.json`.
- [ ] Define canonical `ExecutionReceipt` schema and deterministic serialization rules.
  `Acceptance Criteria:` Receipt schema includes action type, capability context, actor/artifact identity, policy snapshot hash, timestamp/sequence, and witness references; serialization is canonical and hash-stable.
  `Artifacts:` `docs/specs/vef_execution_receipt.md`, `spec/vef_execution_receipt_v1.json`, `artifacts/10.18/vef_receipt_schema_vectors.json`.
- [ ] Implement hash-chained receipt stream with periodic commitment checkpoints.
  `Acceptance Criteria:` Receipt stream is append-only with deterministic chain linkage; checkpoint commitments are reproducible; tamper detection is fail-closed.
  `Artifacts:` `src/trust/vef_receipt_chain.rs`, `tests/conformance/vef_receipt_chain_integrity.rs`, `artifacts/10.18/vef_receipt_commitment_log.jsonl`.
- [ ] Implement receipt-window selection and proof-job scheduler with bounded latency budgets.
  `Acceptance Criteria:` Proof windows are deterministic by policy and workload class; scheduler respects latency/resource budgets; backlog health is observable.
  `Artifacts:` `src/trust/vef_proof_scheduler.rs`, `tests/perf/vef_scheduler_latency_budget.rs`, `artifacts/10.18/vef_scheduler_metrics.csv`.
- [ ] Implement proof-generation service interface (backend-agnostic) for receipt-window compliance proofs.
  `Acceptance Criteria:` Proof service supports deterministic input envelope and output proof envelope; backend selection is pluggable without semantic drift.
  `Artifacts:` `docs/specs/vef_proof_service_contract.md`, `src/trust/vef_proof_service.rs`, `artifacts/10.18/vef_proof_service_matrix.json`.
- [ ] Implement proof-verification gate API for control-plane trust decisions.
  `Acceptance Criteria:` Verification gate validates proof, receipt-window commitment, and policy hash binding; invalid/missing proofs return stable fail-closed verdict classes.
  `Artifacts:` `src/trust/vef_verification_gate.rs`, `tests/security/vef_verification_gate.rs`, `artifacts/10.18/vef_verification_gate_report.json`.
- [ ] Integrate VEF verification state into high-risk control transitions and action authorization.
  `Acceptance Criteria:` High-risk actions require configured VEF verification state; policy can enforce strict/graded modes; gate decisions are auditable and replayable.
  `Artifacts:` `docs/integration/vef_control_plane_integration.md`, `tests/integration/vef_high_risk_action_gating.rs`, `artifacts/10.18/vef_control_gate_decisions.json`.
- [ ] Implement degraded-mode policy for proof lag/outage (`restricted`, `quarantine`, `halt`) with explicit SLOs.
  `Acceptance Criteria:` Proof pipeline lag/outage triggers deterministic degraded mode by policy tier; mode transitions emit mandatory audit events and recovery receipts.
  `Artifacts:` `docs/specs/vef_degraded_mode_policy.md`, `tests/security/vef_degraded_mode_transitions.rs`, `artifacts/10.18/vef_degraded_mode_events.jsonl`.
- [ ] Integrate VEF evidence into verifier SDK replay capsules and external verification APIs.
  `Acceptance Criteria:` Replay capsules include receipt commitments, proof references, and verifier-friendly validation metadata; external verifiers can independently validate VEF claims.
  `Artifacts:` `docs/specs/vef_capsule_extension.md`, `tests/conformance/vef_verifier_sdk_integration.rs`, `artifacts/10.18/vef_external_verification_report.json`.
- [ ] Integrate VEF coverage and proof-validity metrics into claim compiler and public trust scoreboard.
  `Acceptance Criteria:` Claim compiler can require VEF-backed evidence for security/compliance claims; scoreboard publishes VEF coverage/validity stats with signed evidence links.
  `Artifacts:` `docs/specs/vef_claim_integration.md`, `tests/conformance/vef_claim_gate.rs`, `artifacts/10.18/vef_claim_coverage_snapshot.json`.
- [ ] Add adversarial test suite for receipt tampering, proof replay, stale-policy proofs, and commitment mismatch.
  `Acceptance Criteria:` Adversarial scenarios are deterministic and fail closed; mismatch classes map to stable error codes and remediation hints.
  `Artifacts:` `tests/security/vef_adversarial_suite.rs`, `docs/security/vef_adversarial_testing.md`, `artifacts/10.18/vef_adversarial_results.json`.
- [ ] Add performance budget gates for VEF overhead in p95/p99 control and extension-host hot paths.
  `Acceptance Criteria:` VEF overhead remains within agreed budgets by mode; regressions fail CI with reproducible profiling evidence.
  `Artifacts:` `tests/perf/vef_overhead_budget_gate.rs`, `benchmarks/vef_overhead/*`, `artifacts/10.18/vef_overhead_report.csv`.
- [ ] Add release gate requiring VEF-backed evidence for designated high-impact security and compliance claims.
  `Acceptance Criteria:` Release pipeline blocks designated claims without VEF evidence coverage; gate output is machine-readable, signed, and externally verifiable.
  `Artifacts:` `.github/workflows/vef-claim-gate.yml`, `docs/conformance/vef_release_claim_gate.md`, `artifacts/10.18/vef_release_gate_report.json`.

### 10.19 Adversarial Trust Commons Execution Track (9M)
- [ ] Define ATC federation trust model, participant identity contracts, and governance boundaries.
  `Acceptance Criteria:` Participant roles, identity requirements, trust zones, and governance controls are explicit and machine-readable; unauthorized participants fail closed.
  `Artifacts:` `docs/specs/atc_federation_trust_model.md`, `spec/atc_participant_contract_v1.json`, `artifacts/10.19/atc_participant_registry_snapshot.json`.
- [ ] Define canonical federated signal schema for anomaly/trust/revocation/quarantine intelligence.
  `Acceptance Criteria:` Schema covers required signal classes with stable typing, provenance fields, confidence semantics, and expiry windows; schema validation is enforced in CI.
  `Artifacts:` `docs/specs/atc_signal_schema.md`, `spec/atc_signal_schema_v1.json`, `artifacts/10.19/atc_signal_vectors.json`.
- [ ] Implement local signal extraction pipeline from trust cards, adversary graph, and control-plane events.
  `Acceptance Criteria:` Extraction is deterministic for identical inputs; sensitive raw payloads are excluded by policy; extraction outputs are replay-auditable.
  `Artifacts:` `src/federation/atc_signal_extractor.rs`, `tests/conformance/atc_signal_extraction.rs`, `artifacts/10.19/atc_local_signal_samples.jsonl`.
- [ ] Implement privacy envelope layer: secure aggregation + differential-privacy budget enforcement.
  `Acceptance Criteria:` Participant contributions are aggregated without exposing per-participant raw values; privacy budget accounting is deterministic and policy-gated.
  `Artifacts:` `docs/specs/atc_privacy_envelope.md`, `src/federation/atc_secure_aggregation.rs`, `artifacts/10.19/atc_privacy_budget_report.json`.
- [ ] Implement mergeable sketch system for scalable ecosystem pattern sharing.
  `Acceptance Criteria:` Sketch merge semantics are deterministic and bounded-error; bandwidth and compute costs stay within configured budgets under large participant counts.
  `Artifacts:` `src/federation/atc_sketches.rs`, `tests/perf/atc_sketch_scaling.rs`, `artifacts/10.19/atc_sketch_accuracy_report.csv`.
- [ ] Implement poisoning-resilient aggregation and outlier-robust global prior updates.
  `Acceptance Criteria:` Aggregation resists bounded adversarial submissions per policy assumptions; poisoning test suites show bounded degradation and fail-closed behavior on threshold breach.
  `Artifacts:` `docs/security/atc_poisoning_resilience.md`, `tests/security/atc_poisoning_attack_suite.rs`, `artifacts/10.19/atc_poisoning_resilience_results.json`.
- [ ] Implement Sybil-resistant participation controls tied to attestation/staking/reputation evidence.
  `Acceptance Criteria:` Participation weighting rejects untrusted identity inflation; weighting policy is auditable and deterministic; attack simulations validate resistance properties.
  `Artifacts:` `src/federation/atc_participation_weighting.rs`, `tests/security/atc_sybil_resistance.rs`, `artifacts/10.19/atc_weighting_audit_report.json`.
- [ ] Implement contribution-weighted intelligence access policy and reciprocity controls.
  `Acceptance Criteria:` Intelligence access tiers map to measured contribution quality/quantity by policy; free-rider limits and exception paths are explicit and auditable.
  `Artifacts:` `docs/specs/atc_reciprocity_policy.md`, `tests/conformance/atc_reciprocity_enforcement.rs`, `artifacts/10.19/atc_reciprocity_matrix.json`.
- [ ] Integrate ATC global priors into Bayesian adversary graph and risk scoring pipelines.
  `Acceptance Criteria:` Global priors influence local posterior updates under explicit weighting policy; local-vs-global attribution is explainable in evidence outputs.
  `Artifacts:` `src/security/adversary_graph_federated_priors.rs`, `tests/integration/atc_bayesian_prior_integration.rs`, `artifacts/10.19/atc_prior_influence_report.json`.
- [ ] Integrate privacy-preserving urgent routing for revocation/quarantine signals.
  `Acceptance Criteria:` High-severity signals propagate within policy SLO while preserving privacy envelopes; urgent route decisions are signed and replayable.
  `Artifacts:` `docs/specs/atc_urgent_signal_routing.md`, `tests/integration/atc_urgent_routing_latency.rs`, `artifacts/10.19/atc_urgent_routing_telemetry.csv`.
- [ ] Add verifier APIs and proof artifacts for ATC computations and published ecosystem metrics.
  `Acceptance Criteria:` External verifiers can validate federation computation integrity and metric provenance without private raw participant data; verifier outputs are deterministic.
  `Artifacts:` `docs/specs/atc_verifier_contract.md`, `tests/conformance/atc_verifier_apis.rs`, `artifacts/10.19/atc_verifier_report.json`.
- [ ] Define ATC degraded/offline modes and local-first fallback behavior.
  `Acceptance Criteria:` Federation outage or partition triggers deterministic fallback policy; local risk controls remain functional; rejoin/reconciliation is audited.
  `Artifacts:` `docs/specs/atc_degraded_mode.md`, `tests/integration/atc_partition_fallback.rs`, `artifacts/10.19/atc_degraded_mode_events.jsonl`.
- [ ] Add release gate requiring ATC-backed evidence for designated ecosystem-level trust claims.
  `Acceptance Criteria:` Release and public claims about collective intelligence are blocked without required ATC coverage/provenance artifacts; gate output is signed and machine-readable.
  `Artifacts:` `.github/workflows/atc-claim-gate.yml`, `docs/conformance/atc_release_claim_gate.md`, `artifacts/10.19/atc_release_gate_report.json`.

### 10.20 Dependency Graph Immune System Execution Track (9N)
- [ ] Define canonical dependency/topology graph schema covering packages, extensions, publishers, maintainers, and transitive edge semantics.
  `Acceptance Criteria:` Schema captures runtime/build/provenance edge types, trust metadata, update cadence, and policy annotations; identical inputs yield hash-stable graph serialization and signed snapshots.
  `Artifacts:` `docs/specs/dgis_graph_schema.md`, `spec/dgis_graph_schema_v1.json`, `artifacts/10.20/dgis_graph_schema_vectors.json`.
- [ ] Implement deterministic graph ingestion pipeline from lockfiles, extension manifests, registry metadata, and local execution evidence.
  `Acceptance Criteria:` Ingestion reproducibly resolves graph state from the same source set; stale/missing provenance is explicitly surfaced as typed risk signals; ingestion supports replay.
  `Artifacts:` `src/security/dgis/graph_ingestion.rs`, `tests/conformance/dgis_graph_ingestion.rs`, `artifacts/10.20/dgis_ingestion_replay_report.json`.
- [ ] Implement topological risk metric engine (fan-out, betweenness, articulation points, percolation thresholds, trust bottleneck scores).
  `Acceptance Criteria:` Metric computation is deterministic, versioned, and scalable for representative ecosystem graph sizes; output includes explainable feature attribution for each high-risk node.
  `Artifacts:` `src/security/dgis/topology_metrics.rs`, `tests/security/dgis_topology_metrics.rs`, `artifacts/10.20/dgis_topology_risk_snapshot.csv`.
- [ ] Implement maintainer/publisher fragility model and single-point-of-failure detector.
  `Acceptance Criteria:` Graph nodes with concentrated maintainer or provenance risk are flagged with stable severity classes; false-negatives against seeded risk fixtures remain below defined threshold.
  `Artifacts:` `docs/specs/dgis_maintainer_fragility.md`, `src/security/dgis/fragility_model.rs`, `artifacts/10.20/dgis_fragility_findings.json`.
- [ ] Implement adversarial contagion simulator for xz-style and multi-stage supply-chain campaigns.
  `Acceptance Criteria:` Simulator supports campaign templates, probabilistic branching, and policy-conditioned propagation; runs are reproducible via fixed seeds and canonical scenario descriptors.
  `Artifacts:` `src/security/dgis/contagion_simulator.rs`, `tests/security/dgis_contagion_scenarios.rs`, `artifacts/10.20/dgis_contagion_simulation_report.json`.
- [ ] Implement critical-node immunization planner and choke-point barrier synthesis engine.
  `Acceptance Criteria:` Planner proposes minimum-cost barrier sets that reduce expected cascade loss under policy/performance constraints; recommendation rationale is machine-readable and replayable.
  `Artifacts:` `docs/specs/dgis_immunization_planner.md`, `src/security/dgis/immunization_planner.rs`, `artifacts/10.20/dgis_barrier_plan_catalog.json`.
- [ ] Implement trust barrier primitives and policy wiring (behavioral sandbox escalation, composition firewall, verified-fork pinning, staged rollout fences).
  `Acceptance Criteria:` Barrier primitives are independently testable and composable; policy engine can enforce barrier sets at designated choke points with deterministic overrides and audit receipts.
  `Artifacts:` `src/security/dgis/barrier_primitives.rs`, `tests/integration/dgis_barrier_enforcement.rs`, `artifacts/10.20/dgis_barrier_enforcement_trace.jsonl`.
- [ ] Integrate DGIS topological context into trust cards, adversary graph posterior updates, and extension risk UI.
  `Acceptance Criteria:` Risk surfaces show node-level topological blast-radius context and delta impact from planned updates; posterior scoring incorporates topology features with explicit attribution.
  `Artifacts:` `src/security/dgis/risk_surface_integration.rs`, `tests/integration/dgis_trust_card_integration.rs`, `artifacts/10.20/dgis_risk_ui_snapshot.json`.
- [ ] Integrate graph-aware quarantine and rollback orchestration with choke-point-first containment strategy.
  `Acceptance Criteria:` Quarantine plans can target upstream choke points and downstream blast zones deterministically; rollback sequencing avoids reintroducing known high-risk paths.
  `Artifacts:` `docs/specs/dgis_quarantine_orchestration.md`, `tests/security/dgis_quarantine_containment.rs`, `artifacts/10.20/dgis_quarantine_drill_results.json`.
- [ ] Add ATC interoperability for topology indicators and federated cascade priors.
  `Acceptance Criteria:` DGIS emits privacy-preserving topology indicators to ATC and consumes federated priors without raw dependency disclosure; ingestion/output contracts are versioned and verifier-checkable.
  `Artifacts:` `src/federation/dgis_atc_bridge.rs`, `tests/integration/dgis_atc_interop.rs`, `artifacts/10.20/dgis_atc_exchange_report.json`.
- [ ] Implement expected-loss cascade economics and ROI-aware mitigation ranking.
  `Acceptance Criteria:` Each candidate mitigation includes expected-loss delta, residual risk, and operational cost estimates; rankings are stable under fixed assumptions and sensitivity-tested.
  `Artifacts:` `src/security/dgis/cascade_economics.rs`, `docs/specs/dgis_expected_loss_model.md`, `artifacts/10.20/dgis_economic_rankings.csv`.
- [ ] Add operator copilot guidance for dependency updates with topology-aware risk deltas and mitigation playbooks.
  `Acceptance Criteria:` Update proposals include pre/post topology risk scores, containment recommendations, and verifier-backed confidence outputs; high-risk updates require explicit policy acknowledgements.
  `Artifacts:` `src/ops/dgis_update_copilot.rs`, `tests/integration/dgis_update_recommendations.rs`, `artifacts/10.20/dgis_operator_recommendation_log.jsonl`.
- [ ] Integrate DGIS health scoring into migration autopilot admission and progression gates.
  `Acceptance Criteria:` Migration plans include graph-health baselines and target thresholds; migrations that worsen cascade risk beyond policy budgets are blocked or auto-replanned.
  `Artifacts:` `src/migration/dgis_migration_gate.rs`, `tests/integration/dgis_migration_gate.rs`, `artifacts/10.20/dgis_migration_health_report.json`.
- [ ] Add adversarial validation suite (graph poisoning, edge-obfuscation, fake-low-risk pivots, delayed activation) with fail-closed semantics.
  `Acceptance Criteria:` Adversarial campaigns are encoded as deterministic fixtures; DGIS detects or bounds damage within defined limits; bypass attempts emit stable error classes and remediation hints.
  `Artifacts:` `tests/security/dgis_adversarial_suite.rs`, `docs/security/dgis_attack_playbook.md`, `artifacts/10.20/dgis_adversarial_results.json`.
- [ ] Add performance/scale budgets and release claim gates for DGIS-derived security assertions.
  `Acceptance Criteria:` DGIS computation overhead and decision latency remain within p95/p99 budgets at target graph scales; release pipeline blocks topology-security claims lacking signed DGIS evidence artifacts.
  `Artifacts:` `tests/perf/dgis_budget_gate.rs`, `.github/workflows/dgis-claim-gate.yml`, `artifacts/10.20/dgis_release_gate_report.json`.

### 10.21 Behavioral Phenotype Evolution Tracker Execution Track (9O)
- [ ] Define canonical `BehavioralGenome` schema and version-lineage contract for extension phenotypes.
  `Acceptance Criteria:` Schema encodes capability usage, dependency reach, API-surface traits, resource/network envelopes, complexity signals, maintainer/build events, and provenance bindings; serialization is deterministic and signed.
  `Artifacts:` `docs/specs/bpet_behavioral_genome_schema.md`, `spec/bpet_behavioral_genome_v1.json`, `artifacts/10.21/bpet_genome_schema_vectors.json`.
- [ ] Implement deterministic phenotype feature extraction per version from runtime evidence, manifests, and code metadata.
  `Acceptance Criteria:` Identical inputs produce identical phenotype vectors; extraction records feature provenance and uncertainty; missing fields are typed rather than silently dropped.
  `Artifacts:` `src/security/bpet/phenotype_extractor.rs`, `tests/conformance/bpet_feature_extraction.rs`, `artifacts/10.21/bpet_feature_samples.jsonl`.
- [ ] Implement signed lineage graph builder linking versions, maintainers, dependency graph deltas, and build pipeline transitions.
  `Acceptance Criteria:` Lineage graph is replayable and tamper-evident; version ancestry, handoff events, and dependency pivot points are queryable with stable identifiers.
  `Artifacts:` `src/security/bpet/lineage_graph.rs`, `docs/specs/bpet_lineage_contract.md`, `artifacts/10.21/bpet_lineage_snapshot.json`.
- [ ] Implement cohort-aware baseline modeling for expected phenotype evolution patterns.
  `Acceptance Criteria:` Baselines are generated for comparable extension cohorts (domain, maturity, release cadence, dependency class) and include confidence envelopes; model recalibration is deterministic and versioned.
  `Artifacts:` `src/security/bpet/cohort_baselines.rs`, `tests/security/bpet_baseline_calibration.rs`, `artifacts/10.21/bpet_cohort_baseline_report.json`.
- [ ] Implement temporal drift feature engine (velocity, acceleration, entropy, novelty, capability-creep gradient).
  `Acceptance Criteria:` Drift features are numerically stable and reproducible; feature-store interfaces support historical replay and windowed recomputation.
  `Artifacts:` `src/security/bpet/drift_features.rs`, `tests/security/bpet_drift_feature_stability.rs`, `artifacts/10.21/bpet_drift_feature_matrix.csv`.
- [ ] Implement changepoint and regime-shift detection layer (Bayesian changepoint + HMM state transitions).
  `Acceptance Criteria:` Regime shifts are detected with calibrated false-positive/false-negative bounds on historical and synthetic trajectories; shift explanations include dominant contributing dimensions.
  `Artifacts:` `src/security/bpet/regime_shift_detector.rs`, `tests/security/bpet_regime_shift_suite.rs`, `artifacts/10.21/bpet_regime_shift_eval.json`.
- [ ] Implement survival/hazard model for compromise-propensity progression under observed trajectory patterns.
  `Acceptance Criteria:` Hazard outputs are calibrated and monotonic under defined risk assumptions; censoring handling and covariate drift strategy are explicit and test-covered.
  `Artifacts:` `src/security/bpet/hazard_model.rs`, `docs/specs/bpet_time_to_compromise_model.md`, `artifacts/10.21/bpet_hazard_calibration_report.json`.
- [ ] Implement unified evolution-risk scorer with explainability contract and confidence decomposition.
  `Acceptance Criteria:` Scorer combines drift, regime, hazard, and provenance features under a documented weighting policy; output includes stable explanation vectors and confidence intervals.
  `Artifacts:` `src/security/bpet/evolution_risk_scorer.rs`, `tests/conformance/bpet_risk_score_explainability.rs`, `artifacts/10.21/bpet_risk_score_catalog.json`.
- [ ] Integrate BPET trajectory signals into trust cards and adversary graph posterior updates.
  `Acceptance Criteria:` Trust surfaces show "current state + trajectory path" with interpretable risk deltas; adversary posteriors account for evolution velocity and suspicious sequence motifs.
  `Artifacts:` `src/security/bpet/trust_surface_integration.rs`, `tests/integration/bpet_trust_card_integration.rs`, `artifacts/10.21/bpet_trust_surface_snapshot.json`.
- [ ] Integrate BPET with DGIS for topology-amplified early warning prioritization.
  `Acceptance Criteria:` Trajectory anomalies at high-centrality nodes are escalated by policy with explicit expected-loss context; prioritization logic is deterministic and replayable.
  `Artifacts:` `src/security/bpet/dgis_fusion.rs`, `tests/integration/bpet_dgis_priority_escalation.rs`, `artifacts/10.21/bpet_dgis_escalation_report.json`.
- [ ] Integrate BPET with ATC for privacy-preserving federated temporal intelligence exchange.
  `Acceptance Criteria:` BPET exports anonymized trajectory summaries and consumes federated temporal priors without raw longitudinal leakage; contracts are verifier-checkable and versioned.
  `Artifacts:` `src/federation/bpet_atc_bridge.rs`, `tests/integration/bpet_atc_temporal_interop.rs`, `artifacts/10.21/bpet_atc_exchange_report.json`.
- [ ] Integrate evolution stability scoring into migration autopilot dependency admission and rollback gates.
  `Acceptance Criteria:` Migration planner includes trajectory-stability constraints; upgrades crossing risk thresholds require additional evidence or staged rollout with automated fallback plans.
  `Artifacts:` `src/migration/bpet_migration_gate.rs`, `tests/integration/bpet_migration_stability_gate.rs`, `artifacts/10.21/bpet_migration_gate_results.json`.
- [ ] Integrate BPET risk into economic trust layer and operator copilot recommendation engine.
  `Acceptance Criteria:` Economic models price trajectory-derived compromise propensity and intervention ROI; operator guidance includes historical motif matches and mitigation playbooks.
  `Artifacts:` `src/security/bpet/economic_integration.rs`, `src/ops/bpet_operator_copilot.rs`, `artifacts/10.21/bpet_economic_guidance_report.csv`.
- [ ] Implement adversarial evaluation suite for slow-roll mimicry, staged camouflage, and dormant-then-burst mutation campaigns.
  `Acceptance Criteria:` Simulated adversaries test resilience to trajectory-gaming tactics; bypasses emit typed failure classes and trigger policy hardening recommendations.
  `Artifacts:` `tests/security/bpet_adversarial_evolution_suite.rs`, `docs/security/bpet_adversarial_playbook.md`, `artifacts/10.21/bpet_adversarial_results.json`.
- [ ] Define BPET governance policy for thresholding, appeals, and evidence-backed override workflows.
  `Acceptance Criteria:` False-positive handling, human override, and appeal lifecycle are explicit, auditable, and bounded by safety constraints; every override emits signed rationale.
  `Artifacts:` `docs/policy/bpet_governance_policy.md`, `tests/policy/bpet_override_audit.rs`, `artifacts/10.21/bpet_governance_audit_log.jsonl`.
- [ ] Add performance budgets and release claim gates for predictive pre-compromise trajectory assertions.
  `Acceptance Criteria:` BPET scoring latency and storage overhead meet p95/p99 budgets; release claims about predictive detection are blocked without signed calibration/provenance artifacts.
  `Artifacts:` `tests/perf/bpet_budget_gate.rs`, `.github/workflows/bpet-claim-gate.yml`, `artifacts/10.21/bpet_release_gate_report.json`.

## 11. Evidence And Decision Contracts (Mandatory)
Every major subsystem proposal must include:
- change summary
- compatibility and threat evidence
- EV score and tier
- expected-loss model
- fallback trigger
- rollout wedge
- rollback command
- benchmark and correctness artifacts

No contract, no merge.

## 12. Risk Register
- Compatibility illusion risk:
  - Countermeasure: lockstep oracle + divergence receipts.
- Scope explosion:
  - Countermeasure: capability gates + artifact-gated delivery.
- Trust-system complexity:
  - Countermeasure: deterministic replay and explicit degraded-mode contracts.
- Migration friction persistence:
  - Countermeasure: migration autopilot and confidence reporting.
- Performance regressions from hardening:
  - Countermeasure: profile-governed tuning and p99 gates.
- Federated privacy leakage risk:
  - Countermeasure: strict privacy budgets + secure aggregation + external verifier checks on federation outputs.
- Federated signal poisoning/Sybil risk:
  - Countermeasure: robust aggregation + participation attestation/stake weighting + adversarial federation test gates.
- Dependency topology blind-spot risk:
  - Countermeasure: mandatory graph ingestion coverage + topology-metric baselines + unresolved-edge risk escalation.
- Over-hardening false-positive risk at topological choke points:
  - Countermeasure: counterfactual simulation validation + expected-loss calibration + staged barrier rollout with automatic rollback receipts.
- Temporal concept-drift risk in evolution models:
  - Countermeasure: continuous recalibration windows + cohort-specific drift audits + mandatory calibration regression gates before threshold updates.
- Longitudinal trajectory privacy/re-identification risk:
  - Countermeasure: privacy-preserving trajectory sketching + minimum cohort-size publication thresholds + federated temporal verifier checks.
- Trajectory-gaming adversarial camouflage risk:
  - Countermeasure: adversarial mimicry test corpus + motif randomization stress tests + hybrid static/dynamic/provenance signal fusion.

## 13. Program Success Criteria
`franken_node` is successful when:
- it delivers practical Node/Bun migration pathways with low operational risk
- compatibility claims are continuously validated by lockstep differential harnesses
- trust and security claims are externally verifiable and reproducible
- operator workflows can contain and explain high-severity incidents deterministically
- impossible-by-default capabilities are production-grade and adopted
- benchmark and verifier standards gain external usage

Concrete targets:
- `>= 95%` pass on targeted compatibility corpus
- `>= 3x` migration velocity improvement
- `>= 10x` host-compromise reduction under adversarial campaigns
- friction-minimized install-to-first-safe-production pathway for representative setups
- `100%` high-severity replay artifact coverage
- `>= 2` independent external reproductions of core headline claims

## 14. Public Benchmark + Standardization Strategy
`franken_node` will define and own public benchmark and verification standards for secure extension runtime products.

Commitments:
- publish benchmark specs, harness, datasets, scoring formulas
- include security and operational trust co-metrics (not speed-only)
- publish verifier toolkit for independent claim validation
- version standards with explicit migration guidance

Metric families:
- compatibility correctness by API family and risk band
- performance (`p50/p95/p99`, cold start, overhead under hardening)
- containment and revocation latency and convergence
- replay determinism and artifact completeness
- adversarial resilience under evolving campaign corpora
- migration speed and failure-rate improvements

## 15. Ecosystem Capture Strategy
`franken_node` must build durable network effects around trust-native extension operations.

Execution pillars:
- signed extension registry with strict provenance and revocation controls
- migration kit ecosystem for major Node/Bun project archetypes
- enterprise governance integrations (policy pipelines, audit export, compliance evidence)
- reputation graph APIs powering ecosystem-level trust and incident response
- partner and lighthouse programs proving category-shift outcomes in production

Adoption targets:
- friction-minimized path to first safe extension with automation-first onboarding and deterministic validation
- deterministic migration validation on representative Node/Bun project cohorts
- published case studies with measurable security and operational improvements

## 16. Scientific Contribution Targets
`franken_node` is an engineering program that should also produce reusable technical knowledge.

Required contributions:
- open specifications for product-layer trust and compatibility primitives
- reproducible migration and incident datasets
- publishable methodology for benchmark and verifier design
- external red-team and independent evaluation reports
- transparent technical reports including failures and corrective actions

Program output contract:
- multiple publishable technical reports with reproducible artifact bundles
- externally replicated high-impact claims
- widely used open verifier or benchmark tool releases
