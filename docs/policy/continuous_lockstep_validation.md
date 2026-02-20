# Policy: Continuous Lockstep Validation

**Bead:** bd-1w78
**Section:** 13 — Success Criterion
**Effective:** 2026-02-20

## 1. Overview

This policy governs the continuous lockstep validation system that compares
franken_node runtime behavior against upstream Node.js and Bun on every CI
push. The goal is to guarantee behavioral parity, catch regressions before they
merge, and provide transparent compatibility scoring to stakeholders.

## 2. Lockstep Oracle Architecture

### 2.1 L1 Product Layer

The L1 layer is responsible for execution:

- Spawns three runtime processes (Node.js, Bun, franken_node) for each test
  case in the compatibility corpus.
- Captures structured output: stdout, stderr, exit code, wall-clock timing,
  and observable filesystem/network side-effects.
- Enforces a per-test timeout ceiling of 100 ms for divergence detection. Any
  test exceeding this budget is flagged as a timing anomaly.

### 2.2 L2 Engine Layer

The L2 layer is responsible for comparison and classification:

- Applies structured diff rules to the L1 output triples.
- Classifies each divergence into one of three categories (see Section 5).
- Emits event codes (CLV-001 through CLV-004) to the telemetry pipeline.
- Produces a per-API-family compatibility score matrix.

## 3. CI Integration

### 3.1 Trigger

Lockstep validation runs on every `git push` to any branch that targets the
main integration branch. This is non-negotiable (INV-CLV-CONTINUOUS).

### 3.2 Gate Behavior

- If any divergence is classified as **blocking**, the CI gate fails and the
  merge is prevented. Event CLV-003 is emitted.
- If all divergences are **harmless** or **acceptable** (with receipt), the
  gate passes. Event CLV-001 is emitted.
- The overall corpus pass rate must be >= 95%. If it drops below this
  threshold, the gate fails regardless of individual classifications.

### 3.3 Reporting

After each run the system publishes:

- Per-API-family compatibility scores (e.g., `fs: 98.2%`, `http: 96.1%`).
- Trend graphs comparing the current score to the previous 30 runs.
- A summary of all newly detected divergences.

### 3.4 Alerting

Score drops of >= 2 percentage points in any API family trigger an alert to
the on-call engineer and the relevant track owner (as defined in the Section
10.N ownership map). The alert references the commit that caused the drop and
the specific failing test cases.

## 4. Corpus Management

### 4.1 Version Control

The compatibility corpus is stored in-repo under a dedicated directory and is
subject to the same review process as production code. Every modification emits
CLV-004.

### 4.2 Minimum Size

The corpus MUST contain at least 1000 test cases (INV-CLV-CORPUS). If the
count drops below this threshold (e.g., due to a cleanup), the CI gate fails
until the count is restored.

### 4.3 Community Contributions

External contributors may submit new test cases via pull request. Each
submitted case must include:

- A description of the behavior being tested.
- Expected output for at least Node.js (Bun and franken_node outputs may be
  derived during review).
- An API-family tag for classification.

### 4.4 Corpus Coverage

The corpus must cover at least 95% of the public API surface enumerated in the
franken_node capability map (Sections 10.2 through 10.13). Coverage gaps are
tracked as beads and prioritized during sprint planning.

## 5. Divergence Classification

Every detected divergence is assigned one of three classes:

### 5.1 Harmless

The divergence has no user-observable impact. Examples: different internal
object identity, different error message phrasing with identical error code,
ordering differences in unordered collections.

**Action:** Logged. No gate impact.

### 5.2 Acceptable (with Receipt)

The divergence is user-observable but intentional or tolerated. Examples:
performance characteristics outside the comparison scope, known upstream bugs
that franken_node intentionally does not replicate.

**Action:** A signed divergence receipt must be created and committed to the
repository before the merge proceeds. The receipt includes the divergence
description, justification, author, and timestamp.

### 5.3 Blocking

The divergence represents a behavioral regression or incompatibility that would
break user code. Examples: different return values, missing events, changed
error types.

**Action:** The merge is blocked (CLV-003). The developer must fix the
regression or, if the divergence is intentional, re-classify it as acceptable
with a receipt and approval from the track owner.

## 6. Event Lifecycle

| Event | When Emitted |
|---|---|
| CLV-001 | Lockstep run completes without blocking divergences. |
| CLV-002 | Any divergence detected (all classes). |
| CLV-003 | A merge is blocked due to a blocking divergence. |
| CLV-004 | The compatibility corpus is modified. |

## 7. Revision History

| Date | Change |
|---|---|
| 2026-02-20 | Initial policy created for bd-1w78. |
