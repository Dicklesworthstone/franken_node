# bd-s4cu: Risk Control — Compatibility Illusion

## Section
12 — Risk Control

## Bead ID
bd-s4cu

## Risk
**Compatibility Illusion** — The system appears compatible with upstream Node.js
behaviour but diverges subtly in edge cases, leading to silent data corruption,
incorrect control-flow, or security-relevant behavioural differences that are
not caught by standard test suites.

## Impact
- Silent breakage in downstream consumers relying on exact Node.js semantics.
- Security regressions where divergent behaviour bypasses validation logic.
- Erosion of user trust once divergences surface in production.

## Countermeasures

### 1. Lockstep Oracle
A lockstep oracle runs the franken_node implementation side-by-side with a
reference Node.js instance on the **compatibility corpus** — a curated suite of
inputs covering documented and undocumented behavioural contracts. Any output
or side-effect divergence is flagged immediately.

### 2. Divergence Receipts
Every divergence detected by the lockstep oracle produces a **divergence
receipt** — a structured JSON record containing:
- Input that triggered divergence
- Expected (reference) output
- Actual (franken_node) output
- Timestamp and corpus revision
- Severity classification (critical / major / minor / cosmetic)

Receipts are persisted and form the audit trail for risk-mitigation reviews.

### 3. Threshold Enforcement
The compatibility corpus pass rate must be **>= 95%** at all times. A drop
below this threshold triggers an automatic build gate failure and an alert to
the on-call engineer.

### 4. Continuous Monitoring
A monitoring pipeline tracks the pass-rate trend over time and fires alerts
when the rate approaches the threshold boundary (warning at 97%, critical at
95%).

## Threshold
>= 95% compatibility corpus pass rate.

## Event Codes

| Code     | Name                  | Description                                                    |
|----------|-----------------------|----------------------------------------------------------------|
| RCR-001  | Risk Checked          | Lockstep oracle executed a compatibility corpus run.           |
| RCR-002  | Divergence Detected   | Oracle found at least one divergence in the current run.       |
| RCR-003  | Threshold Breached    | Compatibility corpus pass rate dropped below 95%.              |
| RCR-004  | Countermeasure Active | A countermeasure (oracle, receipt, gate) is actively enforced. |

## Invariants

| ID                  | Statement                                                                                  |
|---------------------|--------------------------------------------------------------------------------------------|
| INV-RCR-ORACLE      | The lockstep oracle must execute on every CI run against the full compatibility corpus.     |
| INV-RCR-RECEIPTS    | Every detected divergence must produce a persisted divergence receipt.                      |
| INV-RCR-THRESHOLD   | The build gate must fail when the compatibility corpus pass rate falls below 95%.           |
| INV-RCR-MONITOR     | The monitoring pipeline must emit RCR-003 within 60 seconds of a threshold breach.         |

## Acceptance Criteria
1. Lockstep oracle infrastructure is documented and wired into CI.
2. Divergence receipt schema is defined and receipts are persisted.
3. 95% threshold is enforced as a build gate.
4. Event codes RCR-001 through RCR-004 are emitted at the appropriate points.
5. All four invariants (INV-RCR-ORACLE, INV-RCR-RECEIPTS, INV-RCR-THRESHOLD, INV-RCR-MONITOR) hold.
6. Risk policy document exists and covers impact, likelihood, escalation, and evidence requirements.
7. Alert pipeline is documented with warning (97%) and critical (95%) thresholds.
