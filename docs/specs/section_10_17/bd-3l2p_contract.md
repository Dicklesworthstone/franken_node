# bd-3l2p: Intent-Aware Remote Effects Firewall

## Bead Identity

| Field | Value |
|-------|-------|
| Bead ID | bd-3l2p |
| Section | 10.17 |
| Title | Ship intent-aware remote effects firewall for extension-originated traffic |
| Type | task |

## Purpose

Extension-originated traffic in the franken_node radical expansion track must be
filtered through an intent-aware remote effects firewall before reaching external
systems. This bead implements a firewall that classifies every outbound request by
intent category, applies traffic policy rules per-category, and issues deterministic
decision receipts for audit and replay.

The firewall enables:
- Stable intent classification of extension-originated remote effects.
- Policy-driven verdicts: allow, challenge, simulate, deny, quarantine.
- Deterministic decision receipts with trace correlation for every verdict.
- Risky intent categories (data exfiltration, credential forwarding, side-channel
  probing) trigger non-allow pathways by default.
- Fail-closed behaviour: unclassifiable traffic is denied with a receipt.

## Deliverables

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_17/bd-3l2p_contract.md` |
| Rust module | `crates/franken-node/src/security/intent_firewall.rs` |
| Check script | `scripts/check_effects_firewall.py` |
| Test suite | `tests/test_check_effects_firewall.py` |
| Evidence | `artifacts/section_10_17/bd-3l2p/verification_evidence.json` |
| Summary | `artifacts/section_10_17/bd-3l2p/verification_summary.md` |

## Invariants

- **INV-FW-FAIL-CLOSED**: Any request that cannot be classified or matched to a
  policy rule is denied. The firewall never permits unclassified traffic.
- **INV-FW-RECEIPT-EVERY-DECISION**: Every firewall decision (allow, challenge,
  simulate, deny, quarantine) produces a deterministic receipt with trace_id,
  timestamp, intent category, and matched rule.
- **INV-FW-RISKY-DEFAULT-DENY**: Intent categories classified as risky
  (exfiltration, credential_forward, side_channel) default to deny/quarantine
  unless an explicit policy override with justification exists.
- **INV-FW-DETERMINISTIC**: Given identical inputs (request, policy, timestamp),
  the firewall produces identical outputs. All collections use BTreeMap/BTreeSet.
- **INV-FW-EXTENSION-SCOPED**: The firewall only applies to extension-originated
  traffic. Node-internal traffic bypasses the firewall with a separate audit trail.

## Event Codes

| Code | Meaning |
|------|---------|
| FW_001 | Remote effect request received for classification |
| FW_002 | Intent classification completed |
| FW_003 | Traffic policy matched; verdict issued |
| FW_004 | Decision receipt generated |
| FW_005 | Risky intent category detected; non-allow pathway triggered |
| FW_006 | Challenge pathway initiated for ambiguous intent |
| FW_007 | Simulate pathway initiated for sandboxed evaluation |
| FW_008 | Quarantine pathway initiated for suspicious traffic |
| FW_009 | Unclassifiable traffic denied (fail-closed) |
| FW_010 | Policy override applied with justification |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_FW_UNCLASSIFIED | Request could not be classified into any intent category |
| ERR_FW_NO_POLICY | No traffic policy found for the classified intent category |
| ERR_FW_INVALID_EFFECT | Remote effect descriptor is malformed or missing fields |
| ERR_FW_RECEIPT_FAILED | Decision receipt generation failed |
| ERR_FW_POLICY_CONFLICT | Conflicting policy rules for the same intent category |
| ERR_FW_EXTENSION_UNKNOWN | Extension origin identifier is not registered |
| ERR_FW_OVERRIDE_UNAUTHORIZED | Policy override lacks required justification |
| ERR_FW_QUARANTINE_FULL | Quarantine capacity exceeded; traffic denied |

## Acceptance Criteria

1. Requests receive stable intent classification and policy verdicts.
2. Risky intent categories trigger challenge/simulate/deny/quarantine pathways
   with deterministic receipts.
3. Unclassifiable traffic is denied (fail-closed) with a receipt.
4. Every decision produces a structured receipt with trace correlation ID.
5. Policy rules are matched deterministically with BTreeMap ordering.
6. Extension-scoped filtering distinguishes extension vs. node-internal traffic.
7. All event and error codes are defined as constants.
8. Minimum 20 inline unit tests covering all verdicts, error paths, and invariants.
9. Check script produces machine-readable JSON evidence.

## Testing Requirements

- Unit tests for every verdict pathway (allow, challenge, simulate, deny, quarantine).
- Unit tests for every error variant.
- Invariant enforcement tests (fail-closed, risky-default-deny, deterministic).
- Deterministic replay: given the same inputs, identical output.
- Structured log entries with stable event codes for triage.
