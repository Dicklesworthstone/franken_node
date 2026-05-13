# Cross-Section Integration Journey Matrix

**Owner bead:** bd-295v
**Dependents:** bd-2nlu (program-wide e2e/chaos orchestration)
**Policy version:** 1.0

## Purpose

Section-level verification gates validate correctness within a single track.
Users experience the product through multi-section flows where migration, compatibility,
trust policy, incident handling, and ecosystem controls intersect. This matrix
enumerates all critical cross-section user/operator journeys and maps them to
owning beads, fixtures, and failure taxonomies.

## Journey Catalog

### J-001: Package Install + Trust Verification Journey

**Sections crossed:** 10.2 → 10.7 → 10.13 → 10.17
**User story:** User installs a package, runtime verifies trust chain, checks revocation freshness, validates engine-boundary claims.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Spec resolution | 10.2 | CAP-015 | `fixture:J-001:spec-resolution` |
| Compatibility check | 10.7 | CAP-010 | `fixture:J-001:compatibility-check` |
| Trust verification | 10.13 | CAP-007, CAP-008 | `fixture:J-001:trust-verification`, `fixture:J-001:revocation-freshness` |
| Engine validation | 10.17 | CAP-005, CAP-006b | `fixture:J-001:engine-validation` |

**Happy path assertion:** Package installs, trust chain GREEN, revocation fresh, engine claims valid.
**Edge case:** Package with expired cert but valid grace period.
**Adversarial:** Revoked package with stale CRL and forged timestamp.
**Failure taxonomy:** TRUST_CHAIN_BROKEN, REVOCATION_STALE, ENGINE_CLAIM_INVALID, SPEC_MISMATCH.

**Seam conflicts:** 10.13 trust verdict may lag 10.7 compatibility decision; resolution: trust verdict is authoritative, compatibility check waits.

---

### J-002: Migration + Control Plane Integration Journey

**Sections crossed:** 10.2 → 10.3 → 10.14 → 10.15
**User story:** Operator migrates Node.js project, migration automation applies transforms, control plane enforces epoch barriers and idempotency.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Baseline extraction | 10.2 | CAP-015 | `fixture:J-002:baseline-extraction` |
| Migration transforms | 10.3 | CAP-015 | `fixture:J-002:migration-transforms` |
| Epoch + idempotency | 10.14 | CAP-001, CAP-002 | `fixture:J-002:epoch-state`, `fixture:J-002:saga-contracts` |
| Control enforcement | 10.15 | CAP-001-004 | `fixture:J-002:control-enforcement` |

**Happy path assertion:** Migration completes, epoch transitions clean, saga rollback never triggered.
**Edge case:** Migration with partial transform requiring saga compensation.
**Adversarial:** Concurrent migration with conflicting epoch claims on same resource.
**Failure taxonomy:** EPOCH_CONFLICT, SAGA_COMPENSATION_FAILED, MIGRATION_TRANSFORM_REJECTED, IDEMPOTENCY_VIOLATION.

**Seam conflicts:** 10.14 epoch state may be ahead of 10.15 control-plane view; resolution: 10.14 epoch is source of truth, 10.15 must poll before enforcement.

---

### J-003: Fault Injection + Evidence Replay Journey

**Sections crossed:** 10.14 → 10.15 → 10.17 → 10.18
**User story:** Operator injects fault, system records evidence, verifier replays and validates, execution fabric confirms proof.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Fault injection | 10.14 | CAP-004 | `fixture:J-003:fault-injection` |
| Evidence capture | 10.14 -> 10.15 | CAP-003 | `fixture:J-003:evidence-capture` |
| Verifier replay | 10.17 | CAP-005 | `fixture:J-003:verifier-replay` |
| Proof verification | 10.18 | CAP-011 | `fixture:J-003:proof-verification` |

**Happy path assertion:** Fault triggers cancellation, evidence captured, replay succeeds, proof verifies.
**Edge case:** Fault during epoch transition boundary.
**Adversarial:** Tampered evidence ledger entry with valid-looking signature.
**Failure taxonomy:** EVIDENCE_TAMPERED, REPLAY_DIVERGENCE, PROOF_INVALID, CANCELLATION_INCOMPLETE.

**Seam conflicts:** 10.14 evidence may be emitted before 10.18 proof context exists; resolution: evidence ledger includes pending-proof markers, proof backfill allowed within epoch window.

---

### J-004: Adversarial Trust + Dependency Immune System Journey

**Sections crossed:** 10.19 → 10.20 → 10.17 → 10.21
**User story:** Federated trust signal arrives, dependency graph immune system scores topology, verifier integrates score, behavioral phenotype tracker updates longitudinal model.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Trust signal ingest | 10.19 | CAP-012 | `fixture:J-004:trust-signal-ingest` |
| Topological scoring | 10.20 | CAP-013 | `fixture:J-004:topological-scoring` |
| Verifier integration | 10.17 | CAP-005 | `fixture:J-004:verifier-integration` |
| Phenotype update | 10.21 | CAP-014 | `fixture:J-004:phenotype-update` |

**Happy path assertion:** Signal ingested, topology risk scored, verifier scorecard updated, phenotype model stable.
**Edge case:** Conflicting trust signals from multiple federations with different priors.
**Adversarial:** Poisoned global prior designed to suppress legitimate risk signal.
**Failure taxonomy:** SIGNAL_POISONED, TOPOLOGY_CONFLICT, PHENOTYPE_REGIME_SHIFT, SCORE_DIVERGENCE.

**Seam conflicts:** 10.19 global priors may disagree with 10.20 local topology; resolution: topology-local evidence overrides federation priors with logged justification.

---

### J-005: Incident Response + Recovery Journey

**Sections crossed:** 10.8 → 10.13 → 10.10 → 10.20
**User story:** Incident detected, error taxonomy classifies it, control-plane propagates state, dependency graph triggers quarantine.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Error classification | 10.8 -> 10.13 | CAP-009 | `fixture:J-005:error-classification` |
| State propagation | 10.10 | CAP-007, CAP-010 | `fixture:J-005:state-propagation` |
| Anti-replay framing | 10.13 | CAP-007 | `fixture:J-005:anti-replay-framing` |
| Quarantine + rollback | 10.20 | CAP-013 | `fixture:J-005:quarantine-rollback` |

**Happy path assertion:** Incident classified, state propagated with anti-replay, quarantine scoped and executed.
**Edge case:** Incident during active migration with in-flight epochs.
**Adversarial:** Replay attack on state propagation channel during incident response.
**Failure taxonomy:** CLASSIFICATION_AMBIGUOUS, PROPAGATION_REPLAYED, QUARANTINE_SCOPE_ERROR, ROLLBACK_PARTIAL.

**Seam conflicts:** 10.10 state propagation and 10.13 anti-replay may race under incident load; resolution: anti-replay framing is applied before propagation, never after.

---

### J-006: Release Gate Aggregation Journey

**Sections crossed:** 10.2 → 10.17 → all section gates → program gate
**User story:** Release candidate assembled, L1 and L2 oracles evaluated, all section gates checked, program-wide gate renders final verdict.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| L1 product oracle | 10.2 | CAP-006a | `fixture:J-006:l1-product-oracle` |
| L2 engine oracle | 10.17 | CAP-006b | `fixture:J-006:l2-engine-oracle` |
| Section gates | 10.0-10.21, 11-16 | all | `fixture:J-006:section-gates` |
| Program gate | program | rch policy, xref lint | `fixture:J-006:program-gate` |

**Happy path assertion:** All oracles GREEN, all section gates PASS, release approved.
**Edge case:** One section YELLOW with waiver, all others GREEN.
**Adversarial:** Stale section gate artifact with timestamp older than latest code change.
**Failure taxonomy:** ORACLE_NOT_GREEN, SECTION_GATE_FAIL, STALE_EVIDENCE, POLICY_VIOLATION.

**Seam conflicts:** Section gate verdicts may be produced at different times; resolution: release gate requires all verdicts within the same epoch window (configurable, default 24h).

---

### J-007: Ecosystem Telemetry + Publication Journey

**Sections crossed:** 10.4 → 10.7 → 10.9 → 10.13
**User story:** Ecosystem telemetry collected, compatibility verified, package published to ecosystem, trust credentials attached.

| Phase | Section | Capability | Fixtures needed |
|---|---|---|---|
| Telemetry collection | 10.4 | CAP-008 | `fixture:J-007:telemetry-collection` |
| Compatibility verification | 10.7 | CAP-010, CAP-015 | `fixture:J-007:compatibility-verification` |
| Ecosystem distribution | 10.9 | CAP-005 | `fixture:J-007:ecosystem-distribution` |
| Trust credential binding | 10.13 | CAP-007, CAP-008 | `fixture:J-007:trust-credential-binding` |

**Happy path assertion:** Telemetry clean, compatibility verified, package published with valid trust credentials.
**Edge case:** Package passes compat but revocation check pending.
**Adversarial:** Telemetry injection to inflate adoption metrics.
**Failure taxonomy:** TELEMETRY_INVALID, COMPAT_FAILURE, DISTRIBUTION_BLOCKED, CREDENTIAL_EXPIRED.

**Seam conflicts:** 10.9 distribution may proceed before 10.13 trust credential is fully bound; resolution: distribution waits for credential binding confirmation.

---

## Fixture Contract

All journey fixtures live in `docs/verification/cross_section_fixture_suite.json`
and are validated by `scripts/validate_journey_matrix.py`. The replay path is:

```bash
python3 scripts/program_e2e_orchestrator.py --json --live --journey J-001
```

All journey fixtures follow these rules:

1. **Deterministic:** Same input always produces same output. No system clock, no randomness.
2. **Self-contained:** Each fixture pack includes all inputs, expected outputs, and assertion schemas.
3. **Machine-indexed:** Every fixture references its journey ID, phase, and owning bead.
4. **Replayable:** `scripts/program_e2e_orchestrator.py --live --journey J-NNN` re-executes the journey from fixtures.
5. **Versioned:** Fixtures carry a `fixture_version` field; breaking changes bump major version.

## Failure Taxonomy Rules

Each failure category:
- Has a stable string identifier (SCREAMING_SNAKE_CASE)
- Maps to a remediation hint
- Maps to owning section and capability
- Is machine-parseable in evidence artifacts
