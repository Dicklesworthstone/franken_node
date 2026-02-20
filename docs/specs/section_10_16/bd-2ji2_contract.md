# bd-2ji2: Claim Language Gate for Substrate-Backed Evidence

**Section:** 10.16 — Adjacent Substrate Integration
**Status:** Implementation Complete

## Purpose

Every claim about franken_node capabilities (TUI, API, storage, model) in
documentation must be linked to a verifiable substrate conformance artifact.
The claim language gate scans documentation, verifies artifact links, and
blocks releases containing unlinked or broken claims.

## Scope

- Claim scanning across markdown documentation
- Four claim categories: TUI, API, Storage, Model
- Artifact link verification (existence check)
- Gate blocking on unlinked or broken claims
- Structured JSON reporting

## Types

| Type | Kind | Description |
|------|------|-------------|
| `ClaimCategory` | enum | Tui, Api, Storage, Model |
| `ClaimStatus` | enum | Linked, Unlinked, BrokenLink |
| `Claim` | struct | Individual claim with category, status, linked artifact |
| `ClaimGateEvent` | struct | Timestamped event with code and claim hash |
| `ClaimGateSummary` | struct | Aggregate counts: total, linked, unlinked, broken |
| `ClaimLanguageGate` | struct | Gate engine holding claims and events |

## Methods

| Method | Owner | Description |
|--------|-------|-------------|
| `ClaimCategory::all()` | ClaimCategory | Returns all four categories |
| `ClaimCategory::label()` | ClaimCategory | Human-readable label |
| `ClaimStatus::is_pass()` | ClaimStatus | True only for Linked |
| `ClaimLanguageGate::scan_claim()` | Gate | Scan a single claim |
| `ClaimLanguageGate::scan_batch()` | Gate | Scan multiple claims |
| `ClaimLanguageGate::gate_pass()` | Gate | True if all claims linked |
| `ClaimLanguageGate::summary()` | Gate | Aggregate counts |
| `ClaimLanguageGate::claims()` | Gate | Borrow claim list |
| `ClaimLanguageGate::events()` | Gate | Borrow event log |
| `ClaimLanguageGate::take_events()` | Gate | Drain event log |
| `ClaimLanguageGate::to_report()` | Gate | Structured JSON report |

## Event Codes

| Code | Level | Trigger |
|------|-------|---------|
| `CLAIM_GATE_SCAN_START` | info | Gate scan initiated |
| `CLAIM_LINKED` | debug | Claim successfully linked to artifact |
| `CLAIM_UNLINKED` | error | Claim has no artifact reference |
| `CLAIM_LINK_BROKEN` | error | Claim references non-existent artifact |
| `CLAIM_GATE_PASS` | info | All claims verified |
| `CLAIM_GATE_FAIL` | error | Gate blocked: unlinked or broken claims |

## Invariants

| ID | Rule |
|----|------|
| `INV-CLG-LINKED` | Every claim must reference at least one artifact |
| `INV-CLG-VERIFIED` | Referenced artifacts must exist on disk |
| `INV-CLG-COMPLETE` | All four categories must have at least one claim |
| `INV-CLG-BLOCKING` | Gate fails if any claim is unlinked or broken |

## Artifacts

| File | Description |
|------|-------------|
| `tests/conformance/adjacent_claim_language_gate.rs` | 39 Rust conformance tests |
| `docs/policy/adjacent_substrate_claim_language.md` | Claim language policy document |
| `artifacts/10.16/adjacent_claim_language_gate_report.json` | Gate report (8 claims, all linked) |
| `scripts/check_claim_language_gate.py` | Verification script (86 checks) |
| `tests/test_check_claim_language_gate.py` | Python unit tests |

## Acceptance Criteria

1. ClaimCategory enum covers all four substrate categories (TUI, API, Storage, Model)
2. ClaimStatus enum distinguishes Linked, Unlinked, and BrokenLink states
3. Gate scanning produces structured events with claim hashes
4. Gate blocks (returns false) when any claim is unlinked or has a broken link
5. Gate passes only when all claims are linked to existing artifacts
6. Report JSON contains gate_verdict, summary counts, and per-claim details
7. All types implement Serialize + Deserialize for JSON round-trip
8. At least 30 Rust conformance tests covering all types, methods, events, and invariants
9. Policy document defines categories, linking rules, blocking behavior, and language standards
10. Verification script passes all checks with `--json` machine-readable output
