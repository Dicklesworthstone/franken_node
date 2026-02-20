# Verification Summary: bd-s4cu — Risk Control: Compatibility Illusion

**Bead:** bd-s4cu
**Section:** 12 — Risk Control
**Date:** 2026-02-20
**Result:** PASS (13/13 checks)

## Overview

This bead establishes the risk control framework for the **Compatibility
Illusion** risk — the danger that franken_node appears compatible with
upstream Node.js but diverges subtly in edge cases.

## Artefacts Delivered

| Artefact                         | Path                                                       |
|----------------------------------|------------------------------------------------------------|
| Spec / contract                  | `docs/specs/section_12/bd-s4cu_contract.md`                |
| Risk policy                      | `docs/policy/risk_compatibility_illusion.md`               |
| Verification script              | `scripts/check_risk_compatibility.py`                      |
| Unit tests                       | `tests/test_check_risk_compatibility.py`                   |
| Verification evidence            | `artifacts/section_12/bd-s4cu/verification_evidence.json`  |
| Verification summary (this file) | `artifacts/section_12/bd-s4cu/verification_summary.md`     |

## Checks Performed

| #  | Check                   | Result |
|----|-------------------------|--------|
| 1  | spec_exists             | PASS   |
| 2  | risk_policy_exists      | PASS   |
| 3  | risk_documented         | PASS   |
| 4  | countermeasures         | PASS   |
| 5  | threshold               | PASS   |
| 6  | event_codes             | PASS   |
| 7  | invariants              | PASS   |
| 8  | alert_pipeline          | PASS   |
| 9  | spec_keywords           | PASS   |
| 10 | escalation              | PASS   |
| 11 | evidence_requirements   | PASS   |
| 12 | verification_evidence   | PASS   |
| 13 | verification_summary    | PASS   |

## Key Risk Controls

- **Lockstep Oracle:** Differential testing against reference Node.js on every CI run.
- **Divergence Receipts:** Structured JSON records for every detected divergence.
- **Threshold:** >= 95% compatibility corpus pass rate enforced as build gate.
- **Monitoring:** Warning at 97%, critical at 95%, with PagerDuty escalation.
- **Event Codes:** RCR-001 (risk checked), RCR-002 (divergence detected), RCR-003 (threshold breached), RCR-004 (countermeasure active).
- **Invariants:** INV-RCR-ORACLE, INV-RCR-RECEIPTS, INV-RCR-THRESHOLD, INV-RCR-MONITOR.
