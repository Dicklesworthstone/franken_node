# Risk Policy: Compatibility Illusion

**Bead:** bd-s4cu
**Section:** 12 — Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Risk Description

The **Compatibility Illusion** risk arises when franken_node appears to behave
identically to upstream Node.js but in reality diverges on subtle edge cases.
These divergences are invisible to standard test suites and may only manifest
under production workloads, making them particularly dangerous.

Examples of compatibility illusion:
- Floating-point rounding differences in `Buffer` or `TypedArray` paths.
- Timing variations in event-loop scheduling that alter callback ordering.
- Subtle differences in error message strings that break downstream parsers.
- Missing or extra properties on objects returned by built-in APIs.

## 2. Impact

| Dimension       | Rating   | Detail                                                        |
|-----------------|----------|---------------------------------------------------------------|
| Correctness     | High     | Silent data corruption when semantics diverge.                |
| Security        | High     | Validation bypasses if error paths differ.                    |
| Trust           | Critical | Users lose confidence once a divergence surfaces in prod.     |
| Remediation     | Medium   | Divergences can be patched once identified, but detection lag is costly. |

## 3. Likelihood

| Factor              | Assessment |
|---------------------|------------|
| Code surface area   | Large — franken_node reimplements substantial Node.js surface. |
| Change velocity     | Medium — upstream Node.js ships ~2 minor releases per month.   |
| Historical evidence | Multiple divergences found during Section 10.2 compat work.   |
| Overall likelihood  | **High**                                                        |

## 4. Countermeasure Details

### 4.1 Lockstep Oracle

The lockstep oracle is a differential-testing harness that:
1. Accepts an input from the compatibility corpus.
2. Executes the input against both the reference Node.js runtime and
   franken_node.
3. Compares outputs, side effects, exit codes, and error messages.
4. Emits event code **RCR-001** on each run.
5. Emits event code **RCR-002** for every detected divergence.

The oracle runs in CI on every pull request and nightly against the full corpus.

### 4.2 Divergence Receipts

Each divergence produces a receipt with this schema:

```json
{
  "receipt_id": "string (UUID)",
  "timestamp": "ISO-8601",
  "corpus_revision": "string (git SHA)",
  "input_hash": "string (SHA-256 of input)",
  "expected_output_hash": "string",
  "actual_output_hash": "string",
  "severity": "critical | major | minor | cosmetic",
  "description": "string",
  "resolved": false
}
```

Receipts are stored in `artifacts/risk_control/divergence_receipts/` and
indexed for querying.

### 4.3 Monitoring

The monitoring pipeline:
- Computes the corpus pass rate after every oracle run.
- Emits **RCR-004** when any countermeasure (oracle, receipt persistence,
  build gate) is actively enforced.
- Fires a **warning** alert at 97% pass rate.
- Fires a **critical** alert and emits **RCR-003** at 95% pass rate.

## 5. Threshold Enforcement

| Level    | Pass Rate | Action                                           |
|----------|-----------|--------------------------------------------------|
| Green    | >= 97%    | No action required.                              |
| Warning  | 95%–97%   | Alert on-call engineer; investigate trend.        |
| Critical | < 95%     | Build gate fails; merge blocked; escalation triggered. |

The **hard threshold** is **>= 95%** compatibility corpus pass rate. This is
enforced as a CI build gate. No code may merge while the pass rate is below
this value.

## 6. Alert Pipeline

```
Oracle Run
  |
  v
Compute pass rate
  |
  +-- >= 97% --> log RCR-001, continue
  |
  +-- 95%-97% --> log RCR-001 + RCR-004, fire WARNING alert
  |
  +-- < 95% --> log RCR-001 + RCR-003 + RCR-004, fire CRITICAL alert
                 block merge gate
```

Alerts are delivered via:
1. CI status check (GitHub required check).
2. Slack notification to `#franken-risk-alerts`.
3. PagerDuty escalation for critical-severity breaches.

## 7. Escalation Procedures

| Trigger                        | Escalation                                          |
|--------------------------------|-----------------------------------------------------|
| Pass rate < 95%                | On-call engineer paged; merge gate blocked.         |
| Pass rate < 95% for > 24h     | Engineering lead notified; incident opened.         |
| Critical-severity divergence   | Security team notified within 1 hour.               |
| Divergence in security path    | Immediate patch; post-mortem within 48 hours.       |

## 8. Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires the following evidence:
1. **Oracle run log** — Full output of the most recent lockstep oracle run.
2. **Divergence receipts** — All open (unresolved) receipts.
3. **Pass-rate trend** — 30-day trend chart of corpus pass rate.
4. **Countermeasure status** — Confirmation that all four invariants
   (INV-RCR-ORACLE, INV-RCR-RECEIPTS, INV-RCR-THRESHOLD, INV-RCR-MONITOR)
   are satisfied.
5. **Escalation log** — Record of any escalations triggered since last review.

Reviews are conducted monthly or after any critical-severity divergence,
whichever comes first.
