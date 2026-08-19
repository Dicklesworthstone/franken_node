### Thesis

franken_node's supply-chain verification design is optimized around a security-first decision function: admit or execute extensions only when cryptographic identity, provenance, transparency, revocation freshness, and operator-readable evidence all align. The dominant trade-off is not simply security versus performance; it is deterministic, auditable, fail-closed control versus implementation complexity, operator friction, and capped evidence retention. The architecture repeatedly chooses canonical data, bounded collections, monotonic state, real Ed25519 verification, SHA-256 domain separation, and negative receipts over permissive compatibility shortcuts. That matches the project values, but it creates a coordination burden: each verifier surface must keep its evidence model, freshness policy, and overflow behavior explicitly synchronized.

### Top Findings

- **§F1**
  - **Decision Trade-off**: Fail-closed evidence admission is preferred over developer convenience and permissive extension onboarding.
  - **Evidence**: `README.md:78-89` states that security controls must be operational, claims require evidence, and determinism drives incident quality. `crates/franken-node/src/supply_chain/extension_registry.rs:8-14` rejects shape-only checks in favor of cryptographic verification. `crates/franken-node/src/supply_chain/extension_registry.rs:612-807` requires Ed25519 signature verification, provenance chain validation, and transparency proof validation before returning an admitted receipt. `crates/franken-node/src/supply_chain/manifest.rs:222-305` requires schema, provenance, trust references, signature validation, and engine-level validation.
  - **Reasoning**: The system chooses a multi-gate admission function rather than a lightweight package registry model. This improves correctness and auditability but increases producer burden and the number of ways a legitimate extension can be blocked.
  - **Severity**: critical
  - **Confidence**: 0.94
  - **So What**: This is the right default for a trust-native runtime, but it needs a single documented admission matrix mapping each lifecycle operation to required evidence, failure mode, and override policy.

- **§F2**
  - **Decision Trade-off**: Real cryptographic verification is favored over syntactic validation, but the design splits public authenticity and internal registry integrity across different primitives.
  - **Evidence**: `crates/franken-node/src/supply_chain/artifact_signing.rs:461-471` verifies Ed25519 signatures through the shared crypto verifier. `crates/franken-node/src/supply_chain/extension_registry.rs:680-714` verifies canonical manifest bytes with the publisher key before admission. `crates/franken-node/src/supply_chain/artifact_signing.rs:619-628` requires detached artifact signatures in addition to checksum matches. `crates/franken-node/src/supply_chain/trust_card.rs:2231-2261` verifies trust-card hash and registry HMAC signature with constant-time comparisons.
  - **Reasoning**: The architecture rejects "looks signed" decisions and requires actual signature verification where public authenticity matters. Trust-card snapshots use keyed internal integrity rather than Ed25519, which is cheaper and simpler for local registry state but less naturally portable as a public transparency artifact.
  - **Severity**: high
  - **Confidence**: 0.88
  - **So What**: Keep Ed25519 for externally verifiable artifacts and explicitly label HMAC-backed trust-card signatures as internal registry integrity, or add an Ed25519 export signature for public trust-card distribution.

- **§F3**
  - **Decision Trade-off**: Deterministic canonicalization is chosen over raw throughput and schema flexibility.
  - **Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:18-52` domain-separates leaf and interior SHA-256 hashing with length prefixes. `crates/franken-node/src/supply_chain/artifact_signing.rs:176-224` signs a canonical checksum manifest sorted by filename and bound to a domain-separated payload. `crates/franken-node/src/supply_chain/trust_card.rs:2264-2302` computes canonical trust-card hashes from deterministic JSON. `crates/franken-node/src/supply_chain/trust_card.rs:2781-2814` sorts capability/dependency/object fields for stable output.
  - **Reasoning**: Canonical bytes make replay, comparison, signatures, and receipts reproducible across agents and machines. The cost is more custom serialization code and more test burden around field ordering, schema evolution, and nested JSON behavior.
  - **Severity**: high
  - **Confidence**: 0.91
  - **So What**: This choice is valid, but the project should centralize canonical serialization helpers so supply-chain modules do not each maintain subtly different canonicalization rules.

- **§F4**
  - **Decision Trade-off**: Bounded data structures are used as a first-class DoS control, with different retention policies for security state versus telemetry.
  - **Evidence**: `crates/franken-node/src/supply_chain/manifest.rs:24-31` caps manifest fields and signature envelopes. `crates/franken-node/src/supply_chain/trust_card.rs:44-52` caps telemetry, card versions, audit history, extension IDs, and untrusted JSON size. `crates/franken-node/src/supply_chain/revocation_registry.rs:16-29` caps logs, audit entries, revoked sets, and input strings. `crates/franken-node/src/supply_chain/revocation_registry.rs:253-289` rejects revocation capacity overflow before advancing the head. `crates/franken-node/src/supply_chain/extension_registry.rs:49-85` uses capped audit/receipt/version vectors with oldest-entry eviction.
  - **Reasoning**: The design distinguishes permanent safety state from operational history. Revocations are monotonic and cannot be evicted because eviction would re-admit bad artifacts. Telemetry and audit buffers are bounded rings, which preserves availability under load but can lose forensic detail.
  - **Severity**: high
  - **Confidence**: 0.93
  - **So What**: Add overflow summary receipts for every evicting bounded buffer so operators can distinguish "no evidence" from "evidence was intentionally summarized under cap pressure."

- **§F5**
  - **Decision Trade-off**: Threshold signing is supported for governance resilience, but schema-level threshold support must not be mistaken for full aggregate-signature semantics.
  - **Evidence**: `crates/franken-node/src/supply_chain/manifest.rs:108-127` models `Ed25519` and `ThresholdEd25519`. `crates/franken-node/src/supply_chain/manifest.rs:407-478` enforces threshold policy presence, nonzero signer counts, signer uniqueness, and decoded-size limits. `crates/franken-node/src/supply_chain/artifact_signing.rs:725-786` collects unique valid partial signatures and rejects missing threshold or oversized partial sets.
  - **Reasoning**: M-of-N signing reduces single-key operational risk and fits critical supply-chain governance. It increases cognitive load, test burden, and failure cases around duplicate signers, partial-signature spam, quorum semantics, and compatibility with simple Ed25519 paths.
  - **Severity**: high
  - **Confidence**: 0.84
  - **So What**: Make threshold verification levels explicit in receipts: structural threshold policy valid, partial signatures verified, quorum met, and aggregate or envelope accepted.

- **§F6**
  - **Decision Trade-off**: Runtime revocation and quarantine optimize containment over availability and frictionless execution.
  - **Evidence**: `crates/franken-node/src/supply_chain/revocation_integration.rs:55-82` maps freshness windows by safety tier, with high-tier operations capped at a short age. `crates/franken-node/src/supply_chain/revocation_integration.rs:296-460` denies unavailable, regressed, revoked, or stale high/medium-tier revocation state while allowing only low-tier stale warnings. `crates/franken-node/src/supply_chain/quarantine.rs:600-692` fast-paths critical quarantine orders to enforcement. `crates/franken-node/src/supply_chain/quarantine.rs:1129-1199` requires explicit clearance before lift and treats active quarantine as blocking state.
  - **Reasoning**: The operational decision is to prevent risky execution under uncertainty rather than maximize liveness. This is appropriate for high-risk extension ecosystems, but it will amplify false positives, stale-registry outages, and operator intervention unless observability is excellent.
  - **Severity**: critical
  - **Confidence**: 0.90
  - **So What**: Treat revocation-data availability as a production SLO with alerting, because the security policy deliberately converts freshness failures into runtime denial for important operations.

- **§F7**
  - **Decision Trade-off**: Deterministic ordered maps and sets are preferred over maximum lookup throughput.
  - **Evidence**: `crates/franken-node/src/supply_chain/revocation_registry.rs:12-23` uses `BTreeMap` and `BTreeSet` for per-zone state and permanent revoked artifacts. `crates/franken-node/src/supply_chain/trust_card.rs:687-696` stores snapshot cards in `BTreeMap`. `crates/franken-node/src/supply_chain/trust_card.rs:758-768` uses `BTreeMap` for card and cache state. `crates/franken-node/src/supply_chain/manifest.rs:323-328` checks capability uniqueness through `BTreeSet`.
  - **Reasoning**: Stable ordering is valuable for canonical hashes, deterministic replay, and cross-agent reproducibility. The implicit rejection is a `HashMap`-first design that would be faster in some hot paths but require additional sorting before every signed or hashed output.
  - **Severity**: medium
  - **Confidence**: 0.86
  - **So What**: Keep ordered structures on signed/canonical paths, but benchmark whether hot read paths need secondary non-authoritative indexes.

- **§F8**
  - **Decision Trade-off**: Operator-readable receipts and negative witnesses are made first-class, increasing transparency at the cost of more public contract surface.
  - **Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:115-138` returns proof receipts with failure reasons. `crates/franken-node/src/supply_chain/extension_registry.rs:570-591` defines negative witnesses and admission receipts. `crates/franken-node/src/supply_chain/extension_registry.rs:1139-1177` stores admission receipts and turns rejection witnesses into operator-facing failure details. `crates/franken-node/src/supply_chain/quarantine.rs:1239-1268` verifies hash-chained quarantine audit integrity. `crates/franken-node/src/supply_chain/revocation_integration.rs:517-552` records revocation decisions in a bounded evidence ledger and event stream.
  - **Reasoning**: The system optimizes for explainable denial and post-incident reconstruction rather than a simple boolean allow/deny API. This strengthens operations and external verification, but every receipt becomes a compatibility and privacy boundary.
  - **Severity**: high
  - **Confidence**: 0.89
  - **So What**: Version receipt schemas explicitly and define redaction rules per receipt type so negative witnesses remain useful without leaking sensitive hashes, keys, or internal topology.

### Risks Identified

- Receipt and evidence schema drift: transparency receipts, admission receipts, revocation ledger entries, trust-card telemetry, and quarantine audit records are strong individually but do not appear governed by one shared schema/version matrix.
- HMAC-backed trust-card signatures may be misread as public authenticity signatures unless the boundary between internal registry integrity and external publication is documented.
- Evicting bounded audit, telemetry, and receipt buffers can erase operational context unless overflow summaries are persisted.
- Threshold-signature support spans manifest schema and artifact partial-signature collection, but consumers may not know which verification level was actually reached.
- The fail-closed revocation policy can produce availability incidents if registry freshness or propagation monitoring is not as mature as the enforcement path.
- Feature-gating `supply_chain::manifest` behind `engine` means admission validation intentionally reuses engine validation, but it can complicate verifier-only or registry-only deployments.
- Multiple local canonicalization implementations increase the chance of a future field-ordering or redaction mismatch.
- Negative witnesses improve operator remediation, but their text and checked-field lists become user-facing contracts that need privacy review.

### Recommendations

- **P0, 2-3 days**: Create a supply-chain admission decision matrix covering publish, install, update, load, invoke, revoke, quarantine, trust-card export, and incident replay. For each operation, list required evidence, cryptographic level, freshness window, fail-open/fail-closed behavior, receipt schema, and override policy.
- **P1, 4-6 days**: Introduce a shared receipt schema registry or trait family for proof receipts, admission receipts, revocation ledger entries, trust-card audit entries, and quarantine audit entries. Require schema version, redaction policy, trace ID, timestamp, and invariant ID.
- **P1, 2-4 days**: Add bounded-buffer overflow summary receipts for telemetry, admission receipts, audit logs, and event streams. Summaries should preserve count, first/last evicted timestamp, and reason for eviction without unbounded growth.
- **P1, 3-5 days**: Separate verification-level labels in outputs: schema valid, signature verified, threshold quorum met, transparency included, provenance chain valid, revocation fresh, and engine manifest accepted.
- **P2, 2 days**: Benchmark ordered authoritative structures against optional read indexes. Preserve `BTreeMap`/`BTreeSet` on canonical paths, but identify whether registry lookup paths need cached indexes.
- **P2, 2-3 days**: Document internal versus external signature semantics. Trust-card HMAC integrity, Ed25519 publisher authenticity, threshold governance, and release artifact detached signatures should have separate threat models.
- **P3, 2-3 days**: Add a freshness policy calibration doc and tests that map extension safety tiers to real operator consequences and expected outage behavior.
- **P4, ongoing**: Add a quarterly decision calibration report from incidents and near misses: false denial rate, stale revocation rate, bounded-buffer eviction rate, and operator remediation time.

### New Decision Ideas and Extensions

- Add an "evidence budget" score to each admission decision: a compact summary of which evidence categories were present, stale, missing, or evicted.
- Introduce signed overflow receipts for bounded logs so tail retention remains bounded while forensic completeness is preserved at the summary level.
- Use a two-layer data model for hot registries: ordered canonical state as the source of truth plus ephemeral hash/index caches for read-heavy paths.
- Add policy profiles that make trade-offs explicit: strict production, balanced staging, local development, and verifier replay. Each profile should differ only by a documented decision matrix.
- Add decision provenance to receipts: include the policy version and invariant IDs that caused rejection, not just the immediate failure code.
- Consider an Ed25519-signed trust-card export bundle for external consumers while retaining HMAC snapshots for internal persistence.
- Add a formal "irreversible state" marker for revocation and terminal quarantine records, making the reject-at-capacity policy mechanically visible to maintainers.
- Add cross-module canonicalization golden tests that hash the same semantic payload through the relevant supply-chain modules and verify stable, documented output boundaries.

### Assumptions Ledger

- Assumption: The project values correctness, auditability, and fail-closed behavior over raw extension onboarding throughput, based on README design philosophy and repo guidance.
- Assumption: Supply-chain artifacts are meant to be independently inspected by operators and verifier tooling, not only consumed internally.
- Assumption: Ed25519 is the preferred public authenticity primitive; HMAC usage in trust-card snapshots is intended for local registry integrity.
- Assumption: Bounded growth is a non-negotiable constraint because the runtime handles attacker-influenced extension metadata, manifests, and receipts.
- Assumption: Deterministic replay and incident quality are central enough to justify ordered maps, canonical JSON, and domain-separated hashes.
- Assumption: Revocation and quarantine false positives are acceptable only if they are explainable, observable, and recoverable by explicit clearance.
- Assumption: Threshold signing is intended for higher-assurance governance paths, not as the universal signing mode for every artifact.
- Assumption: The sibling engine validation dependency is intentional because the product layer wants supply-chain admission to match runtime manifest semantics.

### Questions for Project Owner

- Should trust cards be externally verifiable public artifacts, or are they primarily internal registry state with operator-facing export?
- What is the acceptable false-denial rate for high-tier extension operations when revocation data is stale or unavailable?
- Are bounded-buffer evictions acceptable for audit and receipt streams, or should every evicting stream emit a durable overflow summary?
- Which receipts are stable public contracts versus internal diagnostics that can change freely?
- Should threshold signatures be mandatory for critical certification levels, high-risk capabilities, or only release artifacts?
- Does registry admission need a break-glass override, and if so what receipt and approval chain must it produce?
- Which canonicalization implementation is authoritative when modules disagree or evolve independently?
- Should verifier-only deployments be able to validate manifests without enabling the engine feature?

### Points of Uncertainty

- The analysis did not prove whether every CLI and API entry point uses the same admission kernel; the supply-chain module architecture strongly suggests reuse, but call-site coverage should be checked separately.
- The trust-card HMAC boundary may already be documented elsewhere; within the inspected files it is implicit in implementation rather than expressed as a design decision.
- Threshold signing semantics may be more fully specified in tests or docs outside the inspected line ranges.
- Bounded-buffer eviction policies are clear in code, but the long-term evidence-retention requirements are not visible from the supply-chain module alone.
- Revocation and quarantine policies are security-coherent, but the product owner's availability tolerance is not quantified.
- Privacy constraints for negative witnesses and receipts are visible through redaction behavior in some modules, but not as a unified policy.

### Agreements and Tensions with Other Perspectives

- Root Cause analysis should agree that many choices are reactions to earlier failure classes: shape-only signature checks, unbounded collections, stale revocation heads, and non-deterministic evidence.
- Perspective-Taking analysis may emphasize operator burden, publisher onboarding friction, and debugging needs more strongly than this decision analysis.
- Type-Theoretic analysis should align with the explicit state machines, monotonic revocation, bounded collections, and verification-level separation, but may push for stronger type encoding of admission states.
- Security analysis should agree with fail-closed defaults, constant-time comparisons, domain-separated hashing, and no shape-only signatures.
- Performance analysis may push back on repeated canonicalization, BTree structures, and receipt generation, but those costs are tied to explicit auditability goals.
- Product strategy analysis may question whether strict admission defaults should apply equally to early adopters, local development, and production fleets.

### Confidence: 0.87

Confidence is high for the architectural trade-offs directly evidenced in `supply_chain/` and README design philosophy. It is lower for deployment-level recommendations because I inspected the supply-chain modules and project docs, not every CLI/API call path or all external specs.
