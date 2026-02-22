# bd-3l2p: Intent-Aware Remote Effects Firewall - Verification Summary

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-3l2p |
| Section | 10.17 |
| Title | Intent-Aware Remote Effects Firewall |
| Status | PASS |

## Implementation

The intent-aware remote effects firewall is implemented in
`crates/franken-node/src/security/intent_firewall.rs` and registered in
`security/mod.rs`. The module classifies every extension-originated outbound
remote effect by intent category, applies traffic policy rules per-category,
and issues deterministic decision receipts for audit and replay.

### Key Characteristics

- **10 intent classifications**: DataFetch, DataMutation, WebhookDispatch,
  AnalyticsExport, Exfiltration, CredentialForward, SideChannel,
  ServiceDiscovery, HealthCheck, ConfigSync.
- **5 verdict pathways**: Allow, Challenge, Simulate, Deny, Quarantine.
- **3 risky categories**: Exfiltration, CredentialForward, SideChannel
  (default to Deny).
- **10 event codes** (FW_001 through FW_010) with semantic aliases.
- **8 error codes** (ERR_FW_UNCLASSIFIED through ERR_FW_QUARANTINE_FULL).
- **5 invariants** enforced: fail-closed, receipt-every-decision,
  risky-default-deny, deterministic, extension-scoped.

### Invariant Enforcement

| Invariant | Enforcement |
|-----------|-------------|
| INV-FW-FAIL-CLOSED | Unclassifiable traffic returns Deny verdict |
| INV-FW-RECEIPT-EVERY-DECISION | Every evaluate() call produces FirewallDecision with receipt_id |
| INV-FW-RISKY-DEFAULT-DENY | Risky categories default to Deny in TrafficPolicy::default_policy() |
| INV-FW-DETERMINISTIC | BTreeMap/BTreeSet for stable iteration; identical inputs yield identical outputs |
| INV-FW-EXTENSION-SCOPED | NodeInternal traffic bypasses the firewall with separate audit trail |

## Testing

- **37 inline Rust unit tests** covering all verdict pathways, error variants,
  invariant enforcement, and classification logic.
- **Python check script** (`scripts/check_intent_firewall.py`) validates
  event codes, invariants, error codes, core types, methods, and coverage.
- **Python test suite** (`tests/test_check_intent_firewall.py`) validates
  the check script itself.

## Evidence Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-3l2p_contract.md` |
| Spec doc | `docs/specs/intent_effects_policy.md` |
| Rust module | `crates/franken-node/src/security/intent_firewall.rs` |
| Conformance test | `tests/security/intent_firewall_conformance.rs` |
| Check script | `scripts/check_intent_firewall.py` |
| Test suite | `tests/test_check_intent_firewall.py` |
| Eval report | `artifacts/10.17/intent_firewall_eval_report.json` |
| Evidence | `artifacts/section_10_17/bd-3l2p/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-3l2p/verification_summary.md` |

## Acceptance Criteria

1. Requests receive stable intent classification and policy verdicts. -- MET
2. Risky intent categories trigger challenge/simulate/deny/quarantine pathways
   with deterministic receipts. -- MET
3. Unclassifiable traffic is denied (fail-closed) with a receipt. -- MET
4. Every decision produces a structured receipt with trace correlation ID. -- MET
5. Policy rules are matched deterministically with BTreeMap ordering. -- MET
6. Extension-scoped filtering distinguishes extension vs. node-internal traffic. -- MET
7. All event and error codes are defined as constants. -- MET
8. Minimum 20 inline unit tests covering all verdicts, error paths, and invariants. -- MET (37 tests)
9. Check script produces machine-readable JSON evidence. -- MET
