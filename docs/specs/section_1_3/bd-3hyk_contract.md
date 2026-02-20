# bd-3hyk: Strategic Foundations

**Section:** 1-3 — Mission, Thesis, Category-Creation
**Type:** Epic (Strategic Foundation)
**Status:** In Progress

## Section 1: Background and Role

franken_node is the product and ecosystem surface built on franken_engine.

| Component | Responsibility |
|-----------|---------------|
| franken_engine | Native runtime internals, policy semantics, trust primitives |
| asupersync | Async scheduling, cancellation, concurrency primitives |
| franken_node | Compatibility, migration, extensions, packaging, control planes |

**Strategic role:** Turn engine breakthroughs into mass adoption and category capture.

## Section 2: Core Thesis

franken_node must become the default choice for extension-heavy JS/TS execution
where teams need ALL of:

| Pillar | Description |
|--------|-------------|
| Ergonomics | Node/Bun-level developer experience |
| Security | Materially stronger security outcomes |
| Explainability | Deterministic explainability for high-impact decisions |
| Operations | Operational confidence at fleet scale |

**Core proposition:**
- Compatibility is table stakes
- Trust-native operations are the differentiator
- Migration velocity is the growth engine

## Section 3: Strategic Objective

Build franken_node into the category-defining runtime product layer that
functionally obsoletes Node/Bun for high-trust extension ecosystems.

### Disruptive Floor (non-optional)

| ID | Target | Threshold |
|----|--------|-----------|
| DF-01 | Compatibility corpus pass rate | >= 95% |
| DF-02 | Migration throughput vs baseline | >= 3x |
| DF-03 | Host compromise reduction | >= 10x |
| DF-04 | Install-to-safe-operation friction | Automation-first |
| DF-05 | Incident replay availability | 100% deterministic |
| DF-06 | Impossible-by-default capabilities | >= 3 broadly adopted |

## Section 3.1: Category-Creation Doctrine

| ID | Rule |
|----|------|
| CCD-01 | Compatibility is a strategic wedge, not final destination |
| CCD-02 | Ship trust-native workflows incumbents cannot provide |
| CCD-03 | Define benchmark language and verification standards |
| CCD-04 | Own migration ergonomics for inevitable adoption |
| CCD-05 | Turn operator trust into cryptographic/statistical evidence |

## Section 3.3: Build Strategy

**DECISION:** No full clean-room Bun reimplementation.

| Principle | Description |
|-----------|-------------|
| BST-01 | Node/Bun as behavioral reference, not architecture template |
| BST-02 | Spec-first compatibility capture (Essence Extraction) |
| BST-03 | Native implementation on franken_engine + asupersync |
| BST-04 | Reuse pi_agent_rust patterns where accretive |

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
| INV-STR-THESIS | Core thesis is documented and referenced by all tracks |
| INV-STR-FLOOR | All 6 disruptive floor targets are measurable |
| INV-STR-DOCTRINE | Category-creation doctrine rules are enforceable |
| INV-STR-STRATEGY | Build strategy is spec-first, not clone-first |

## Artifacts

- Strategic foundations doc: `docs/doctrine/strategic_foundations.md`
- Spec contract: `docs/specs/section_1_3/bd-3hyk_contract.md`
- Verification: `scripts/check_strategic_foundations.py`
- Tests: `tests/test_check_strategic_foundations.py`
