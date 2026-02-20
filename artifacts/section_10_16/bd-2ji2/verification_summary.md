# bd-2ji2: Claim Language Gate for Substrate-Backed Evidence

**Section:** 10.16 | **Verdict:** PASS | **Date:** 2026-02-20

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Rust conformance tests | 39 | 39 |
| Python verification checks | 86 | 86 |
| Python unit tests | 41 | 41 |

## Implementation

`tests/conformance/adjacent_claim_language_gate.rs`

- **Types:** ClaimCategory (4 variants), ClaimStatus (3 variants), Claim, ClaimGateEvent, ClaimGateSummary, ClaimLanguageGate
- **Event codes:** CLAIM_GATE_SCAN_START, CLAIM_LINKED, CLAIM_UNLINKED, CLAIM_LINK_BROKEN, CLAIM_GATE_PASS, CLAIM_GATE_FAIL
- **Invariants:** INV-CLG-LINKED, INV-CLG-VERIFIED, INV-CLG-COMPLETE, INV-CLG-BLOCKING
- **Methods:** scan_claim, scan_batch, gate_pass, summary, claims, events, take_events, to_report, label, all, is_pass

## Gate Report

- 8 claims across all 4 categories (TUI, API, Storage, Model)
- All claims linked to valid artifacts
- Zero unlinked, zero broken links
- Gate verdict: PASS

## Verification Coverage

- File existence (conformance test, policy doc, gate report)
- Rust test count (39, minimum 30)
- Serde derives present
- All 6 types, 11 methods, 6 event codes, 4 invariants verified
- All 39 conformance test names verified
- Report JSON: valid, PASS verdict, 8 claims, all categories, zero unlinked, zero broken
- Policy doc: exists, all 4 categories, Evidence Linking / Blocking Behavior / Language Standards sections
