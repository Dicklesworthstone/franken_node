### Thesis
franken_node's supply-chain verification architecture is driven by one fundamental cause: extension-heavy JavaScript ecosystems make third-party code admission a runtime safety problem, not a packaging detail. The design choices in `crates/franken-node/src/supply_chain/` trace back to that pressure: compact transparency evidence for distributed install/update paths, canonical signed material for replay and independent verification, trust cards as operational decision records, Ed25519 as the small fixed-shape signature primitive used across manifests/provenance/artifacts, and monotonic revocation/quarantine semantics because compromised extensions must not regain trust through stale or partial state.

### Top Findings
- **§F1**
  - **Root Cause**: Supply-chain trust is treated as a runtime admission gate because Node/Bun-style extension velocity leaves security and incident handling external unless the runtime owns them.
  - **Evidence**: `README.md:26-30` states that external policy glue is the problem and trust/migration/replay become first-class runtime behavior; `README.md:34-42` lists trust cards, revocation-first execution, deterministic replay, fleet quarantine, and verifier tooling as core capabilities; `AGENTS.md:254-257` frames the product as trust/supply-chain policy plus quarantine/release, replay/incident tooling, and verifier evidence generation.
  - **Reasoning**: The supply-chain modules are not isolated release utilities. `supply_chain/mod.rs:1-16` groups artifact signing, manifests, provenance, quarantine, revocation, transparency verification, and trust cards under one product boundary. That grouping is the manifestation of the deeper design driver: admission decisions must be made with evidence at runtime.
  - **Severity**: critical
  - **Confidence**: 0.95
  - **So What**: Improvements should preserve the admission-gate model. Treating these modules as passive metadata or CLI reporting would cut against the core architecture.

- **§F2**
  - **Root Cause**: Merkle transparency proofs are used because install/update paths need compact, non-interactive proof that a specific artifact was included under an accepted log checkpoint, without replaying the whole log.
  - **Evidence**: `transparency_verifier.rs:1-5` says install/update fails when required inclusion proof is missing or invalid and roots are pinned by policy; `transparency_verifier.rs:76-83` defines `leaf_index`, `tree_size`, `leaf_hash`, and `audit_path`; `transparency_verifier.rs:175-223` recomputes the root from a leaf and bounded audit path; `transparency_verifier.rs:349-367` accepts only when the recomputed root is pinned.
  - **Reasoning**: A central lookup or signed allowlist would either require online availability or larger state distribution. The Merkle path supplies logarithmic proof size and lets the runtime verify locally against pinned roots. The root cause is distributed, deterministic install-time verification.
  - **Severity**: critical
  - **Confidence**: 0.9
  - **So What**: The current root pinning proves inclusion relative to accepted checkpoints, not global log consistency. Split-view resistance needs an explicit consistency/gossip story if the transparency log becomes a stronger trust claim.

- **§F3**
  - **Root Cause**: Canonical serialization and domain-separated hashing exist because the same evidence must survive replay, signing, comparison, and independent verification without ambiguity or cross-protocol collision.
  - **Evidence**: `README.md:84-87` says claims require reproducible artifacts and replay depends on stable ordering/schemas/contracts; `transparency_verifier.rs:18-51` uses SHA-256 with domain separators and length prefixes for leaves and interior nodes; `artifact_signing.rs:212-223` signs a domain-separated, length-prefixed release manifest payload; `trust_card.rs:2274-2302` hashes canonical trust-card JSON under `trust_card_hash_v1`; `provenance.rs:1047-1129` canonicalizes the signable attestation payload by sorted object keys.
  - **Reasoning**: These repeated patterns are not incidental implementation style. They solve the same causal problem in multiple modules: evidence must mean exactly one byte sequence to signers, verifiers, replay tools, and future auditors.
  - **Severity**: high
  - **Confidence**: 0.92
  - **So What**: Any new supply-chain field should enter the canonical payload deliberately. Ad hoc JSON signing or serializer-default hashing would create replay and verification drift.

- **§F4**
  - **Root Cause**: Ed25519 is the default signature primitive because the architecture needs deterministic, small, fixed-size detached signatures for manifests, artifacts, and provenance links, with simple key handling and mature Rust support.
  - **Evidence**: `AGENTS.md:85-91` lists SHA/HMAC/HKDF, `ed25519-dalek`, `zeroize`, and constant-time comparison as core dependencies; `README.md:191-205` makes registry publishing fail closed without an Ed25519 signing key; `artifact_signing.rs:1-5` defines Ed25519 signing, checksums, key rotation, and M-of-N support; `artifact_signing.rs:456-471` signs/verifies Ed25519; `artifact_signing.rs:514-530` generates keys from OS CSPRNG and zeroizes seed material; `manifest.rs:107-128` models Ed25519 and threshold Ed25519 signature schemes; `provenance.rs:952-990` signs and verifies attestation links with Ed25519.
  - **Reasoning**: Ed25519 fits the architecture's causal constraints: detached artifacts, reproducible canonical payloads, public verification, fixed public-key/signature sizes, and low operational complexity. The threshold path is built as M-of-N valid Ed25519 partial signatures, not as an opaque external PKI.
  - **Severity**: high
  - **Confidence**: 0.88
  - **So What**: The naming around `ThresholdEd25519` should stay precise. If it means collected M-of-N detached Ed25519 signatures, specs and receipts should say so; if aggregate threshold signatures are intended, the implementation needs a different cryptographic contract.

- **§F5**
  - **Root Cause**: Trust cards are broad aggregate records because operators need one deterministic object that joins provenance, behavior, revocation, reputation, quarantine, dependency trust, and audit history for admission and CLI/API decisions.
  - **Evidence**: `README.md:38-39` defines trust cards as per-extension provenance, behavior risk, revocation state, and policy posture; `trust_card.rs:1-5` says trust cards aggregate provenance, certification, reputation, and revocation into deterministic signed profiles; `trust_card.rs:530-553` includes version linkage, extension/publisher identity, certification, capabilities, behavior profile, revocation, provenance, reputation, quarantine, dependency trust, risk assessment, audit history, derivation evidence, hash, and signature; `trust_card.rs:2162-2198` renders the same fields for operator-facing CLI output.
  - **Reasoning**: The trust card's size is explained by its role. It is not a display card first; it is a decision cache plus audit artifact for a runtime that must make fast, explainable trust decisions.
  - **Severity**: high
  - **Confidence**: 0.91
  - **So What**: Splitting trust-card fields into unrelated services would weaken traceability unless the derived card remains the signed decision record.

- **§F6**
  - **Root Cause**: Evidence requirements and version chaining exist because trust must be monotonic and attributable; claims cannot silently improve without verified upstream receipts.
  - **Evidence**: `trust_card.rs:94-123` computes a derivation hash from verified evidence references; `trust_card.rs:1134-1186` requires evidence to create a card and signs the resulting version; `trust_card.rs:1251-1257` rejects certification upgrades without evidence; `trust_card.rs:1266-1274` refreshes derivation evidence when mutations carry new references; `trust_card.rs:1311-1322` appends audit history and re-signs the card.
  - **Reasoning**: The deeper cause is not just audit logging. The system is trying to prevent trust inflation: a better certification level must be causally tied to evidence, and each new card version must chain back to the previous signed state.
  - **Severity**: high
  - **Confidence**: 0.9
  - **So What**: Future scoring/reputation updates should follow the same causal chain rule. Any field that improves trust posture should require evidence references, not just a mutable operator update.

- **§F7**
  - **Root Cause**: Revocation and quarantine are monotonic because compromise containment is more important than convenience; a stale or evicted revocation can re-admit a bad artifact.
  - **Evidence**: `README.md:229-234` configures fresh revocation requirements and high-risk quarantine defaults; `trust_card.rs:1275-1284` forbids `Revoked` to `Active` transitions; `trust_card.rs:1375-1401` re-verifies cached cards before serving them; `revocation_registry.rs:1-5` defines monotonic revocation heads recoverable from a canonical log; `revocation_registry.rs:117-120` avoids evicting revoked artifacts; `revocation_registry.rs:253-289` rejects duplicate/capacity cases before advancing the head; `revocation_registry.rs:313-342` checks revocation through the non-evicting set.
  - **Reasoning**: The root cause is an asymmetric safety requirement: false re-admission after compromise is worse than operational friction. This explains irreversible trust-card revocation and fail-closed revocation capacity behavior.
  - **Severity**: critical
  - **Confidence**: 0.93
  - **So What**: Capacity exhaustion in revocation paths should be handled as an operator incident, not by evicting old entries or allowing partial progress.

- **§F8**
  - **Root Cause**: Pervasive bounds and fail-closed validation exist because supply-chain inputs are attacker-controlled and can attack both correctness and availability.
  - **Evidence**: `AGENTS.md:91-96` names constant-time comparison and fuzz/property input generation as project dependencies; `artifact_signing.rs:25-32` caps artifact names, manifest entries, partial signatures, and per-key attempts; `artifact_signing.rs:226-233` rejects traversal, malformed, duplicate, and non-canonical manifest lines; `manifest.rs:24-31` caps manifest collections and signature envelope sizes; `manifest.rs:255-311` rejects empty, oversized, duplicate, missing-attestation, invalid engine, and path-traversal manifests; `trust_card.rs:44-52` caps telemetry, card versions, audit history, extension ID length, and untrusted JSON size; `provenance.rs:16-23` caps chain issues, links, custom claims, and canonical custom-claim bytes.
  - **Reasoning**: These bounds repeatedly appear at ingress, parsing, verification, and persistence. The causal driver is not performance polish; it is adversarial resilience and predictable failure under untrusted metadata.
  - **Severity**: high
  - **Confidence**: 0.94
  - **So What**: New supply-chain surfaces should define caps before parsing/signing and should fail before mutating state when capacity is exceeded.

### Risks Identified
- Merkle inclusion may be overinterpreted as full transparency-log consistency. The code pins roots and checks inclusion, but I did not find a consistency-proof or gossip mechanism in the inspected path.
- `ThresholdEd25519` can be misunderstood as aggregate threshold cryptography. The artifact path currently collects unique valid Ed25519 partial signatures, which is useful M-of-N multisig but a different contract.
- Trust-card registry signatures use HMAC (`trust_card.rs:2231-2261`), which is strong for an internal shared-key registry boundary but not naturally public-verifiable. That matters if trust cards are intended to cross organizational trust boundaries.
- Broad trust cards can become stale authority if refresh, signature verification, and revocation freshness are not enforced uniformly across every read path.
- Custom canonicalization is necessary, but every custom canonical form creates drift risk unless golden vectors and cross-version tests cover it.
- Fail-closed capacity limits can become availability incidents. That is the right safety default, but operators need clear remediation and observability when a cap is hit.

### Recommendations
- **P1, 2-4 days**: Add an explicit transparency consistency model: either implement Merkle consistency proof validation and checkpoint evolution, or document that current proofs are inclusion-only under pinned roots.
- **P1, 1-2 days**: Clarify `ThresholdEd25519` semantics in code comments, specs, and receipts. Rename to M-of-N Ed25519 multisig if aggregation is not intended.
- **P1, 2-3 days**: Define the trust-card trust boundary. If cards are externally verifiable artifacts, add or plan public-key signatures alongside the internal HMAC registry signature.
- **P2, 2-4 days**: Add a causal end-to-end test path from signed manifest -> provenance verification -> transparency receipt -> trust-card derivation -> revocation/quarantine decision.
- **P2, 1-2 days**: Expand golden canonical vectors for trust cards, provenance attestations, release manifests, and transparency leaves/interior nodes.
- **P2, 1 day**: Add operator-facing cap-exhaustion remediation docs for revocation logs, trust-card snapshots, manifests, and provenance custom claims.
- **P3, 1 day**: Add a short supply-chain architecture note explaining the root causal chain: runtime admission risk -> deterministic evidence -> signed receipts -> monotonic revocation.

### New Root Cause Ideas and Extensions
- The architecture is converging on a "local verifier, global evidence" model: runtime nodes should not need to trust live services if they have signed/canonical evidence and pinned roots.
- Trust cards act as a materialized view over slower verification systems. That explains the cache and snapshot work, but also implies the card must carry enough derivation metadata to be recomputed and challenged.
- The revocation system is closer to safety-critical state than reputation scoring. This justifies separate invariants for revocation even when other trust-card fields can be bounded and evicted.
- The manifest projection into `frankenengine_extension_host` (`manifest.rs:161-180`, `manifest.rs:301-305`) suggests a compatibility root cause: franken_node is adding policy around an existing engine contract rather than replacing it.
- The repeated use of event codes and receipts indicates that auditability is a first-order requirement, not a logging afterthought.

### Assumptions Ledger
- I assume Merkle trees were selected for compact local verification in distributed install/update paths because the implementation verifies inclusion from an audit path against pinned roots and does not require full log replay.
- I assume trust cards are intended to be operational decision records because they combine runtime-relevant fields and are signed, versioned, cached, rendered, and queried.
- I assume Ed25519 was chosen for deterministic detached signature workflows because it is used consistently across manifests, artifact signing, and provenance attestations.
- I assume HMAC trust-card signatures reflect an internal registry integrity boundary unless a separate public-verification layer exists outside the inspected files.
- I assume historical bead IDs in comments explain delivery sequencing, not necessarily the original product rationale.

### Questions for Project Owner
- Should transparency verification eventually protect against split views with consistency proofs or gossip, or is pinned-root inclusion sufficient for the current threat model?
- Is `ThresholdEd25519` intended to be M-of-N independent Ed25519 signatures, or should it become true threshold/aggregate signature cryptography?
- Are trust cards meant to be externally portable/verifiable outside one registry authority? If yes, should HMAC remain only an internal snapshot integrity mechanism?
- Which trust-card mutations besides certification upgrades should require evidence references because they improve admission posture?
- What is the intended operator response when revocation or trust-card capacity limits are reached in production?

### Points of Uncertainty
- I did not inspect every CLI path that consumes these supply-chain modules, so some admission behavior may be enforced outside `crates/franken-node/src/supply_chain/`.
- I did not find a transparency consistency-proof path during this pass, but it may exist in another module or artifact gate.
- The trust-card HMAC design may be intentionally scoped to local registry snapshots; public verification requirements may live in a separate verifier surface.
- Historical design rationale may exist in bead descriptions or specs not inspected here, so some causal conclusions are inferred from code and README contracts rather than explicit design records.

### Agreements and Tensions with Other Perspectives
- Expected agreement with Failure Mode analysis: fail-closed, monotonic revocation, canonicalization, and bounded parsing are the key risk-control mechanisms.
- Expected agreement with Systems-Thinking analysis: the supply-chain surface is a coupled admission system spanning registry, provenance, transparency, trust cards, revocation, fleet quarantine, and verifier artifacts.
- Expected tension with Decision Analysis: Ed25519 and HMAC choices are pragmatic and simple, but may need sharper trade-off documentation if external verification and threshold semantics become product claims.
- Expected tension with performance analysis: capacity caps and repeated signature verification protect safety but can create throughput and availability pressure during large fleet or registry operations.

### Confidence: 0.88
Confidence is high for the central causal chain because the README, AGENTS architecture notes, and supply-chain modules repeatedly encode the same design drivers. Confidence is lower for historical intent behind specific cryptographic choices because I inferred rationale from implementation patterns rather than reading original design discussions.
