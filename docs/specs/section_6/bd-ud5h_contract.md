# bd-ud5h: Security and Trust Product Doctrine

**Section:** 6 — Security Doctrine
**Type:** Doctrine Document
**Status:** In Progress

## Purpose

Defines the security and trust product doctrine governing all security-related
implementation in franken_node. Establishes the threat model, trust-native
product surfaces, and safety guarantee targets.

## Threat Model — 5 Adversary Classes

| ID | Class | Description |
|----|-------|-------------|
| ADV-01 | Supply-chain compromise | Malicious extension updates and maintainer compromises |
| ADV-02 | Credential exfiltration | Credential theft and lateral movement attempts |
| ADV-03 | Policy evasion | Exploiting compatibility edge cases to bypass policy |
| ADV-04 | Delayed payload | Long-tail persistence and delayed payload activation |
| ADV-05 | Operational confusion | Non-deterministic incident handling exploitation |

## Trust-Native Product Surfaces

| ID | Surface | Owner Tracks |
|----|---------|-------------|
| TNS-01 | Extension trust cards and provenance scoring | 10.4, 10.13 |
| TNS-02 | Policy-visible compatibility mode gates | 10.5, 10.2 |
| TNS-03 | Revocation-first execution prechecks | 10.4, 10.8 |
| TNS-04 | Signed incident receipts and deterministic replay | 10.17 |
| TNS-05 | Autonomous containment with explicit rationale | 10.5, 10.17 |

## Safety Guarantee Targets

| ID | Target | Metric |
|----|--------|--------|
| SGT-01 | Bounded false-negative rate | < 0.1% under adversarial extension corpus |
| SGT-02 | Bounded false-positive rate | < 1.0% for benign migration workloads |
| SGT-03 | Deterministic replay | 100% of high-severity events replayable |
| SGT-04 | Auditable degraded-mode | Documented semantics when trust state is stale |

## Event Codes

| Code | Level | Meaning |
|------|-------|---------|
| SEC-001 | info | Threat model review completed |
| SEC-002 | error | Adversary class without test scenario |
| SEC-003 | info | Trust surface operational |
| SEC-004 | error | Safety guarantee target not met |
| SEC-005 | info | Security doctrine compliance verified |

## Invariants

| ID | Statement |
|----|-----------|
| INV-SEC-THREAT | All 5 adversary classes have test scenarios |
| INV-SEC-SURFACE | All 5 trust-native surfaces are implemented |
| INV-SEC-SAFETY | All 4 safety guarantee targets are measurable |
| INV-SEC-REVIEW | Threat model reviewed with each major release |

## Artifacts

- Doctrine doc: `docs/doctrine/security_and_trust.md`
- Spec contract: `docs/specs/section_6/bd-ud5h_contract.md`
- Verification: `scripts/check_security_doctrine.py`
- Tests: `tests/test_check_security_doctrine.py`
