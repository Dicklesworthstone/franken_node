# Security and Trust Product Doctrine

**Bead:** bd-ud5h | **Section:** 6

## 6.1 Problem Statement

Developers need Node ecosystem speed, but untrusted extension supply chains remain
a catastrophic risk surface. The JS/TS ecosystem's open-package model creates
attack surfaces that traditional runtime security cannot address without destroying
developer velocity.

## 6.2 Product Goal

Make high-trust runtime operation the default workflow without forcing teams to
abandon JS/TS ecosystem velocity. Security must be a product feature, not a
compliance burden.

## 6.3 Threat Model

### Adversary Classes

All security implementations in franken_node must address these five adversary classes:

#### ADV-01: Supply-Chain Compromise

**Description:** Malicious extension updates and maintainer compromises.

**Attack vectors:**
- Typosquatting on popular package names
- Account takeover of legitimate maintainers
- Injection of malicious postinstall scripts
- Dependency confusion between internal and public registries

**Mitigations required:**
- Provenance scoring for all extensions
- Trust card generation with supply-chain metadata
- Signature verification for extension artifacts
- Revocation-first execution prechecks

#### ADV-02: Credential Exfiltration

**Description:** Credential theft and lateral movement attempts.

**Attack vectors:**
- Environment variable harvesting
- File system scanning for secrets and tokens
- Network exfiltration via DNS or HTTP
- Memory scraping for in-process credentials

**Mitigations required:**
- Capability-based execution sandboxing
- Network egress policy enforcement
- Credential isolation between extension boundaries
- Audit logging for all credential access patterns

#### ADV-03: Policy Evasion

**Description:** Exploiting compatibility edge cases to bypass security policy.

**Attack vectors:**
- Using compatibility mode quirks to circumvent restrictions
- Exploiting mode transitions to escalate privileges
- Leveraging undocumented behavior differences between Node and franken_node
- Chaining benign operations to achieve restricted outcomes

**Mitigations required:**
- Policy-visible compatibility mode gates
- Formal verification of mode transition security properties
- Compatibility gap analysis with security implications
- Gate-level enforcement at every mode boundary

#### ADV-04: Delayed Payload Activation

**Description:** Long-tail persistence and delayed payload activation.

**Attack vectors:**
- Time-bombed payloads that activate after trust establishment
- Version-dependent activation triggered by dependency updates
- Event-driven activation on specific runtime conditions
- Staged multi-package payloads that assemble over time

**Mitigations required:**
- Continuous runtime monitoring beyond initial trust check
- Behavioral anomaly detection for established extensions
- Historical audit trails for all extension behavior changes
- Periodic re-verification of previously trusted artifacts

#### ADV-05: Operational Confusion

**Description:** Non-deterministic incident handling exploitation.

**Attack vectors:**
- Exploiting inconsistent alert handling across environments
- Creating alert fatigue to hide genuine incidents
- Manipulating incident severity classification
- Exploiting race conditions in containment procedures

**Mitigations required:**
- Deterministic replay for all high-severity events
- Signed incident receipts with tamper evidence
- Autonomous containment with explicit, auditable rationale
- Standardized incident response procedures with formal verification

## 6.4 Trust-Native Product Surfaces

### TNS-01: Extension Trust Cards and Provenance Scoring

Trust cards provide a standardized, machine-readable summary of an extension's
provenance, build reproducibility, maintainer history, and known vulnerabilities.

**Requirements:**
- Every extension has a trust card before execution
- Provenance score computed from verifiable signals (signatures, build logs, maintainer tenure)
- Trust cards are immutable once generated; updates create new versions
- Score thresholds are configurable per deployment profile

**Owner tracks:** 10.4, 10.13

### TNS-02: Policy-Visible Compatibility Mode Gates

Compatibility mode transitions (Node compat, strict, franken-native) are security-relevant
events. Every mode gate is visible to the policy engine.

**Requirements:**
- Mode transitions emit policy events with full context
- Compatibility gaps are annotated with security implications
- Mode-specific capability restrictions are enforced at the gate level
- Policy can block mode transitions based on trust state

**Owner tracks:** 10.5, 10.2

### TNS-03: Revocation-First Execution Prechecks

Before any extension executes, the runtime checks revocation status. This is
"revocation-first" — the default is to deny execution unless trust is confirmed.

**Requirements:**
- Revocation check happens before any extension code runs
- Stale revocation data triggers degraded mode, not silent bypass
- Revocation lists are signed and freshness-checked
- Failed revocation checks are logged with full context

**Owner tracks:** 10.4, 10.8

### TNS-04: Signed Incident Receipts and Deterministic Replay

Every security incident produces a signed receipt that can be deterministically
replayed for forensic analysis.

**Requirements:**
- Receipts are cryptographically signed with server identity
- Receipts contain all inputs needed for deterministic replay
- Replay produces identical output given identical inputs
- Receipt chain is tamper-evident (hash-linked)

**Owner tracks:** 10.17

### TNS-05: Autonomous Containment with Explicit Rationale

When a security event triggers containment, the system provides machine-readable
rationale for every containment action.

**Requirements:**
- Containment decisions include formal rationale (threat class, confidence, evidence)
- Rationale is stored alongside the containment action in the audit log
- Human operators can review and override with documented justification
- Containment actions are reversible with audit trail

**Owner tracks:** 10.5, 10.17

## 6.5 Safety Guarantee Targets

### SGT-01: Bounded False-Negative Rate

**Target:** < 0.1% false-negative rate under adversarial extension corpora.

**Measurement:** Run adversarial test corpus (minimum 1000 samples per adversary class)
through the trust pipeline. Count missed detections. Rate = missed / total.

**CI gate:** Automated adversarial corpus test suite with threshold enforcement.

### SGT-02: Bounded False-Positive Rate

**Target:** < 1.0% false-positive rate for benign migration workloads.

**Measurement:** Run benign migration test suite (representative real-world workloads)
through the trust pipeline. Count incorrect blocks. Rate = blocked / total.

**CI gate:** Benign workload regression suite with threshold enforcement.

### SGT-03: Deterministic Replay

**Target:** 100% of high-severity security events are deterministically replayable.

**Measurement:** For every high-severity event in the test suite, export the incident
receipt and replay it. Verify identical output.

**CI gate:** Replay verification in security test suite.

### SGT-04: Auditable Degraded-Mode Semantics

**Target:** Documented, tested semantics for every degraded-mode scenario when
trust state is stale or unavailable.

**Measurement:** For each degraded-mode entry condition, verify that:
- The system enters degraded mode (not silent bypass)
- Degraded-mode behavior is documented and matches implementation
- Audit log captures the degraded-mode transition with reason

**CI gate:** Degraded-mode scenario tests with audit log verification.

## 6.6 Cross-Section Applicability

This doctrine governs security decisions across all implementation tracks:

| Track | Security Applicability |
|-------|----------------------|
| 10.2 | Compatibility surfaces: policy-visible mode gates |
| 10.3 | Migration system: benign workload false-positive bounds |
| 10.4 | Extension registry: trust cards, provenance, revocation |
| 10.5 | Security policy: all surfaces and guarantee targets |
| 10.8 | Runtime integrity: revocation prechecks |
| 10.13 | Protocol conformance: provenance in connector protocol |
| 10.14 | Trust artifacts: epoch-scoped key derivation |
| 10.17 | Incident management: receipts, replay, containment |

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
| INV-SEC-THREAT | All 5 adversary classes have dedicated test scenarios |
| INV-SEC-SURFACE | All 5 trust-native product surfaces are implemented |
| INV-SEC-SAFETY | All 4 safety guarantee targets are measurable with CI gates |
| INV-SEC-REVIEW | Threat model is reviewed and updated with each major release |
