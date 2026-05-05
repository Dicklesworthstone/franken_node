# Implementation Governance Policy

> Enforces spec-first discipline for all compatibility work. Forbids line-by-line legacy translation. Requires spec and fixture references in every compatibility PR.

**Effective Date:** 2025-01-15
**Authority:** [ADR-001: Hybrid Baseline Strategy](adr/ADR-001-hybrid-baseline-strategy.md)
**Charter Reference:** [PRODUCT_CHARTER.md](PRODUCT_CHARTER.md) Section 10 (Off-Charter Behaviors)

---

## 1. Scope

This policy applies to all pull requests that implement, modify, or extend **compatibility behavior** — any code that aims to match Node.js, Bun, or Deno API behavior, event semantics, or runtime contracts.

## 2. Rules

### 2.1 No Line-by-Line Legacy Translation

Compatibility implementations must not be line-by-line translations of Node.js, Bun, Deno, or any existing runtime source code. Legacy runtime source code may only be used for:

- **Specification extraction**: Understanding behavioral contracts, edge cases, and invariants
- **Fixture generation**: Capturing runtime output as conformance baselines
- **Oracle validation**: Comparing franken_node behavior against known-good results

Violations include:
- Copying function structure, variable names, or control flow from legacy source
- Translating JavaScript/C++ source directly to Rust without independent specification
- PR descriptions that reference legacy source lines instead of specification sections

### 2.2 Spec References Required

Every compatibility PR must include references to the specification it implements. Acceptable spec references:

- Specification document path and section (e.g., `docs/specs/node_fs/read_file.md#error-semantics`)
- WinterCG or WHATWG spec section (e.g., `WHATWG Streams §4.2`)
- Node.js documentation section (e.g., `Node.js docs: fs.readFile`)
- TC39 proposal or ECMAScript section

PRs without spec references fail governance review.

### 2.3 Fixture References Required

Every compatibility PR must include references to the conformance fixtures it validates against. Acceptable fixture references:

- Fixture file path (e.g., `tests/fixtures/node_fs/read_file_utf8.json`)
- Test vector ID (e.g., `fixture:fs-readfile-001`)
- Oracle capture reference (e.g., `oracle:node-20.x:fs.readFile`)

PRs without fixture references fail governance review.

### 2.4 PR Description Format

Compatibility PRs must include a structured governance section in the PR description:

```
## Governance
- Spec-Ref: <specification document and section>
- Fixture-Ref: <fixture ID or test vector path>
- Oracle: <runtime(s) used as behavioral oracle>
```

All three fields are required. The `Oracle` field identifies which runtime(s) (Node.js version, Bun version) were used to generate conformance fixtures.

## 3. Enforcement

### CI Gate
A CI check validates that compatibility PRs contain the required governance section. PRs touching files in compatibility-related paths (`crates/franken-node/src/compat/`, `crates/franken-node/src/api/`) without governance metadata are flagged.

### Review Checklist
Reviewers must verify:
- [ ] No line-by-line translation from legacy source
- [ ] Spec reference points to real specification
- [ ] Fixture reference points to existing test vectors
- [ ] Oracle runtime version is documented

## 4. Exceptions

No exceptions. The hybrid baseline strategy (ADR-001) is a foundational architectural decision. If a compatibility feature cannot be specified independently of legacy source structure, the specification must be created first before implementation begins.

## 5. References

- [ADR-001: Hybrid Baseline Strategy](adr/ADR-001-hybrid-baseline-strategy.md)
- [PRODUCT_CHARTER.md](PRODUCT_CHARTER.md)
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 5.4 — Spec-First Essence Extraction Protocol
