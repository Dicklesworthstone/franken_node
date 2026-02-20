# Strategic Foundations

**Bead:** bd-3hyk | **Sections:** 1, 2, 3

## Section 1: Background and Role

franken_node is the product and ecosystem surface built on franken_engine. It
occupies the critical position between raw runtime capabilities and developer
adoption.

### Three-Kernel Architecture

| Kernel | Responsibility |
|--------|---------------|
| franken_engine | Native runtime internals, policy semantics, trust primitives |
| asupersync | Async scheduling, cancellation, concurrency primitives |
| franken_node | Compatibility capture, migration/operator experience, extension ecosystem, packaging/rollout, enterprise control planes |

### Strategic Role

franken_node turns engine breakthroughs into mass adoption and category capture.
Without franken_node, franken_engine remains an impressive but inaccessible
technical achievement. franken_node is where the value proposition becomes
tangible to developers and operators.

## Section 2: Core Thesis

franken_node must become the default choice for extension-heavy JS/TS execution
where teams need ALL of these four pillars simultaneously:

### The Four Pillars

1. **Ergonomics:** Node/Bun-level developer experience. Developers should not feel
   like they are paying a tax for security or trust features.

2. **Security:** Materially stronger security outcomes. Not incremental improvement —
   a step change in what is possible by default.

3. **Explainability:** Deterministic explainability for high-impact decisions.
   Every policy decision, containment action, and trust evaluation must be
   reproducible and auditable.

4. **Operations:** Operational confidence at fleet scale. Operators must be able
   to reason about the behavior of hundreds of instances with the same confidence
   they have for a single instance.

### Core Proposition

- **Compatibility is table stakes.** Without it, adoption is impossible.
  But compatibility alone does not win.
- **Trust-native operations are the differentiator.** This is what incumbents
  cannot provide by default.
- **Migration velocity is the growth engine.** The easier it is to migrate,
  the faster the category grows.

## Section 3: Strategic Objective

Build franken_node into the category-defining runtime product layer that
functionally obsoletes Node/Bun for high-trust extension ecosystems.

### Disruptive Floor

These are non-optional targets. They define the minimum bar for category creation:

#### DF-01: Compatibility Corpus Pass Rate

**Target:** >= 95% pass rate on targeted compatibility corpus for high-value
Node/Bun usage bands.

**Why:** Below 95%, migration friction overwhelms the trust-native value proposition.
The compatibility corpus must focus on high-value patterns (the 20% of APIs that
cover 80% of real-world usage), not exhaustive coverage of rarely-used edge cases.

#### DF-02: Migration Throughput

**Target:** >= 3x migration throughput and confidence quality versus baseline
migration patterns (manual compatibility testing, ad-hoc migration scripts).

**Why:** If migration is painful, adoption stalls regardless of the destination's
quality. 3x improvement makes migration a strategic advantage, not a cost.

#### DF-03: Host Compromise Reduction

**Target:** >= 10x reduction in successful host compromise under adversarial
extension campaigns.

**Why:** This is the headline security metric. A 10x improvement is large enough
to change organizational risk calculus and justify migration effort.

#### DF-04: Install-to-Safe-Operation Friction

**Target:** Friction-minimized, automation-first path from install to
policy-governed safe extension workloads.

**Why:** First-run experience determines adoption momentum. If the path from
install to "my extensions are running under policy governance" requires manual
configuration, adoption dies.

#### DF-05: Incident Replay Availability

**Target:** 100% deterministic replay artifact availability for high-severity
incidents.

**Why:** Post-incident analysis must be reproducible. "It worked on my machine"
is unacceptable for security incidents.

#### DF-06: Impossible-by-Default Capabilities

**Target:** >= 3 impossible-by-default product capabilities broadly adopted by
production users.

**Why:** These are features that literally cannot exist in incumbent runtimes
without franken_node's trust-native architecture. They prove the category is real.

## Section 3.1: Category-Creation Doctrine

franken_node is NOT a "better Node clone." It is the category bridge between
JS/TS ecosystem scale and zero-illusion trust operations.

### CCD-01: Compatibility as Strategic Wedge

Treat compatibility as a strategic wedge, not final destination. Compatibility
enables adoption; trust-native features retain and expand usage.

### CCD-02: Ship Trust-Native Workflows

Ship trust-native workflows that incumbents cannot provide by default. These
workflows must be zero-configuration for the common case.

### CCD-03: Define Benchmark Language

Define benchmark language and verification standards for the category. Own the
vocabulary of evaluation so competitors must respond on our terms.

### CCD-04: Own Migration Ergonomics

Own migration ergonomics so adoption feels inevitable, not costly. Migration
tooling is first-class product, not afterthought.

### CCD-05: Evidence-Based Trust

Turn operator trust from intuition into cryptographically and statistically
grounded evidence. Every trust decision must be backed by verifiable artifacts.

## Section 3.3: Baseline Build Strategy

**DECISION:** franken_node will NOT begin with a full clean-room Bun reimplementation.

### BST-01: Behavioral Reference

Use Node/Bun as behavioral reference systems and oracle targets, not architecture
templates. We learn WHAT they do, not HOW they do it.

### BST-02: Spec-First Capture

Execute spec-first compatibility capture (Essence Extraction, MS-04) for
prioritized API/runtime bands. Specs are the source of truth, not legacy code.

### BST-03: Native Implementation

Implement natively on franken_engine + asupersync with trust/migration
architecture from day one. Trust is not bolted on after the fact.

### BST-04: Pattern Reuse

Reuse patterns from /dp/pi_agent_rust where accretive, avoiding architecture
lock-in. Proven patterns accelerate delivery; architecture coupling kills agility.

**Rationale:** A Bun-first clone path creates architecture lock-in and delays
category-defining differentiators. Spec-first extraction preserves the freedom
to innovate on architecture while maintaining behavioral compatibility.

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| STR-001 | info | Strategic foundations compliance verified |
| STR-002 | error | Implementation missing strategic linkage |
| STR-003 | info | Category-creation doctrine check passed |
| STR-004 | error | Disruptive floor target not addressed |

## Invariants

| ID | Statement |
|----|-----------|
| INV-STR-THESIS | Core thesis is documented and referenced by all execution tracks |
| INV-STR-FLOOR | All 6 disruptive floor targets are measurable and tracked |
| INV-STR-DOCTRINE | Category-creation doctrine rules are enforceable in planning/review |
| INV-STR-STRATEGY | Build strategy is spec-first, not clone-first |
