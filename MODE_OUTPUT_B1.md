### Thesis

franken_node's supply-chain verification code repeatedly converges on a small set of trust-native implementation patterns: bound attacker-controlled inputs before doing expensive work, bind evidence through domain-separated canonical digests, treat trust state as monotonic and auditable, and return structured receipts or stable error codes instead of ambiguous booleans. The strongest positive trend is that independent modules such as manifests, registry admission, provenance, transparency proofs, trust cards, quarantine, revocation, and artifact signing all encode the same fail-closed security instincts. The main negative inductive signal is that several micro-patterns are reimplemented locally, which raises drift risk even though the current implementations mostly point in the same direction.

### Top Findings

- **§F1**
  - **Pattern Identified**: Bounded admission is the dominant first line of defense.
  - **Evidence**: `crates/franken-node/src/supply_chain/manifest.rs:24-31` defines manifest collection and field caps; `crates/franken-node/src/supply_chain/manifest.rs:255-282` enforces capability, network-zone, reproducibility-marker, and attestation-chain limits; `crates/franken-node/src/supply_chain/revocation_registry.rs:16-29` caps logs, audit trails, revoked sets, and string inputs; `crates/franken-node/src/supply_chain/extension_registry.rs:55-69` defines registry input caps and `crates/franken-node/src/supply_chain/extension_registry.rs:932-1072` rejects oversized names, descriptions, publisher IDs, tags, and manifest bytes before admission proceeds.
  - **Reasoning**: These limits recur across modules that handle different external surfaces, which suggests an architectural convention rather than isolated defensive coding. The code tends to reject at the boundary instead of normalizing or truncating untrusted trust inputs.
  - **Severity**: high
  - **Confidence**: 0.95
  - **So What**: Keep adding new supply-chain surfaces behind explicit caps, and require every new collection or free-form string field to document its capacity reason.

- **§F2**
  - **Pattern Identified**: Cryptographic binding generally uses domain separation plus length-prefixing.
  - **Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:20-28` and `crates/franken-node/src/supply_chain/transparency_verifier.rs:33-41` hash Merkle interiors with a domain tag and lengths; `crates/franken-node/src/supply_chain/transparency_verifier.rs:45-51` does the same for leaves; `crates/franken-node/src/supply_chain/quarantine.rs:486-516` hash-chains audit entries with a domain tag and length-prefixed string fields; `crates/franken-node/src/supply_chain/trust_card.rs:94-120` derives trust-card evidence hashes with explicit field lengths; `crates/franken-node/src/supply_chain/extension_registry.rs:810-830` binds admission fields under `extension_registry_admission_v1`; `crates/franken-node/src/supply_chain/artifact_signing.rs:212-224` signs a domain-separated, length-prefixed manifest payload.
  - **Reasoning**: The same anti-ambiguity shape appears in unrelated digest contexts. Inductively, this is the codebase's preferred answer to concatenation ambiguity and cross-protocol hash reuse.
  - **Severity**: critical
  - **Confidence**: 0.90
  - **So What**: Promote this to a small shared supply-chain digest builder or checklist so future hashing code does not silently regress to raw concatenation.

- **§F3**
  - **Pattern Identified**: Mutable trust state is modeled as monotonic history, not as a freely editable cache.
  - **Evidence**: `crates/franken-node/src/supply_chain/revocation_registry.rs:1-10` declares monotonic revocation heads and input validation; `crates/franken-node/src/supply_chain/revocation_registry.rs:231-250` rejects stale revocation heads and records an audit entry; `crates/franken-node/src/supply_chain/revocation_registry.rs:377-407` rejects non-monotonic or duplicate entries during recovery; `crates/franken-node/src/supply_chain/trust_card.rs:840-850` advances snapshot epochs with previous snapshot hashes; `crates/franken-node/src/supply_chain/trust_card.rs:1247-1284` requires evidence for upgrades and prevents Revoked -> Active transitions; `crates/franken-node/src/supply_chain/trust_card.rs:2463-2499` validates version monotonicity and previous-hash linkage in snapshot history.
  - **Reasoning**: The repeated shape is "advance only, reject rollback, prove history linkage." That pattern appears in revocation, trust-card snapshots, and extension lineage, so rollback resistance is a product-level invariant.
  - **Severity**: critical
  - **Confidence**: 0.92
  - **So What**: Centralize monotonic-frontier tests across revocation heads, trust-card snapshot epochs, and extension versions; these are high-value regression targets.

- **§F4**
  - **Pattern Identified**: Evidence and receipts are first-class data, not logging afterthoughts.
  - **Evidence**: `README.md:82-89` states that operational controls need measurable behavior and claims require evidence; `crates/franken-node/src/supply_chain/manifest.rs:75-96` embeds provenance and trust metadata into signed manifests; `crates/franken-node/src/supply_chain/transparency_verifier.rs:115-126` returns a `ProofReceipt` with verification flags, failure reason, trace ID, and timestamp; `crates/franken-node/src/supply_chain/extension_registry.rs:579-590` defines an admission receipt with negative witness support; `crates/franken-node/src/supply_chain/artifact_signing.rs:792-833` emits structured audit log entries; `crates/franken-node/src/supply_chain/quarantine.rs:461-484` records hash-chained lifecycle audit entries.
  - **Reasoning**: Each verification domain returns operator-usable evidence rather than just pass/fail. The recurring inclusion of trace IDs, event codes, timestamps, reasons, and remediation points to an evidence-driven design convention.
  - **Severity**: high
  - **Confidence**: 0.94
  - **So What**: Treat any new verifier that returns only `bool` as a design smell unless it is a tiny private predicate feeding a structured receipt.

- **§F5**
  - **Pattern Identified**: Admission composes local shape checks with real cryptographic and upstream semantic checks.
  - **Evidence**: `crates/franken-node/src/supply_chain/manifest.rs:299-309` validates signatures, projects into the engine manifest, runs engine validation, and only then applies the path-traversal guard; `crates/franken-node/src/supply_chain/extension_registry.rs:597-611` documents a shared admission kernel with no shape-only shortcuts; `crates/franken-node/src/supply_chain/extension_registry.rs:650-714` verifies key presence and Ed25519 signatures; `crates/franken-node/src/supply_chain/extension_registry.rs:716-755` verifies provenance; `crates/franken-node/src/supply_chain/extension_registry.rs:757-807` verifies transparency inclusion when policy requires it; `crates/franken-node/src/supply_chain/provenance.rs:333-394` derives deterministic reports from required fields, depth, order, freshness, link verification, and sorted issues.
  - **Reasoning**: The recurring strategy is layered verification: cheap bounds and schema constraints narrow the input, then cryptographic, provenance, transparency, and engine-specific checks decide trust. This reduces single-check bypass risk.
  - **Severity**: critical
  - **Confidence**: 0.88
  - **So What**: Preserve the staged admission order in reviews; moving expensive or semantic checks before input caps, or replacing cryptographic checks with format checks, should be treated as a high-risk regression.

- **§F6**
  - **Pattern Identified**: Security-sensitive equality and debug output receive explicit hygiene.
  - **Evidence**: `AGENTS.md:85-91` lists hashing/signing and constant-time comparisons as core dependencies; `crates/franken-node/src/supply_chain/transparency_verifier.rs:67-93` redacts log-root hashes and summarizes audit paths in `Debug`; `crates/franken-node/src/supply_chain/transparency_verifier.rs:103-112` checks pinned roots in constant time; `crates/franken-node/src/supply_chain/transparency_verifier.rs:332-347` compares leaf hashes in constant time; `crates/franken-node/src/supply_chain/trust_card.rs:555-585` redacts card hashes and registry signatures in `Debug`; `crates/franken-node/src/supply_chain/trust_card.rs:2231-2261` verifies card hashes and signatures with constant-time comparison; `crates/franken-node/src/supply_chain/artifact_signing.rs:590-617` uses constant-time checksum comparison and avoids leaking raw signature detail as the public error.
  - **Reasoning**: Similar hygiene appears in independently developed modules, suggesting the team has internalized side-channel and log-disclosure concerns for trust data.
  - **Severity**: high
  - **Confidence**: 0.86
  - **So What**: Add static review guidance or UBS-style checks for new `Debug` impls and equality checks near signatures, hashes, tokens, and revocation identifiers.

- **§F7**
  - **Pattern Identified**: Tests trend adversarial and golden, but coverage style is uneven.
  - **Evidence**: `crates/franken-node/src/supply_chain/mod.rs:414-705` contains adversarial manifest tests for traversal, Unicode spoofing, URL injection, memory exhaustion, signature manipulation, script injection, complexity, and concurrency; `crates/franken-node/src/supply_chain/extension_registry.rs:1974-2303` contains adversarial registry tests for forged signatures, swapped manifests, unsigned divergence, unknown keys, truncated signatures, missing transparency proofs, revoked links, stale attestations, and tampered provenance signatures; `crates/franken-node/src/supply_chain/trust_card.rs:5291-5475` freezes trust-card integrity, human rendering, canonical JSON, complex scenarios, empty collections, and canonical stability with snapshot tests; `crates/franken-node/src/supply_chain/trust_card_fuzz_test.rs:10-99` smoke-tests malformed, binary, large, and deeply nested snapshot input.
  - **Reasoning**: The repeated test language is "attack", "golden", "canonical", and "no panic." That is a strong security-testing culture, but the locations mix inline module tests, path-included fuzz smoke, and snapshot tests, which may make harness rigor harder to audit uniformly.
  - **Severity**: medium
  - **Confidence**: 0.82
  - **So What**: Build a supply-chain test matrix that maps each invariant to at least one unit, adversarial, golden, and integration/conformance proof; use it to find mock-only or one-direction coverage.

- **§F8**
  - **Pattern Identified**: Local reimplementation of shared primitives is the main drift signal.
  - **Evidence**: `crates/franken-node/src/lib.rs:8-19` defines the crate-level `push_bounded`, while `crates/franken-node/src/supply_chain/mod.rs:27-37` and `crates/franken-node/src/supply_chain/extension_registry.rs:71-90` define local versions or local length helpers; `crates/franken-node/src/supply_chain/transparency_verifier.rs:54-56`, `crates/franken-node/src/supply_chain/quarantine.rs:29-31`, and `crates/franken-node/src/supply_chain/extension_registry.rs:88-90` each define `len_to_u64`; error-code mapping is repeated in `crates/franken-node/src/supply_chain/manifest.rs:552-569`, `crates/franken-node/src/supply_chain/revocation_registry.rs:63-72`, `crates/franken-node/src/supply_chain/quarantine.rs:73-84`, and `crates/franken-node/src/supply_chain/extension_registry.rs:301-334`.
  - **Reasoning**: The repeated primitives are individually simple, but the pattern indicates multiple modules are solving the same bounded-growth, length-prefix, and error taxonomy problems independently. In a security subsystem, duplicated micro-semantics tend to diverge under future patch pressure.
  - **Severity**: medium
  - **Confidence**: 0.89
  - **So What**: Refactor only when touching adjacent code: introduce shared helpers for domain-separated length encoding and bounded audit append semantics, then migrate opportunistically with focused tests.

### Risks Identified

- The strongest negative pattern is semantic duplication of tiny security helpers. Local `len_to_u64`, local `push_bounded`, and module-local event/error-code maps are easy to keep correct today, but they are likely future drift points.
- Trust-card logic is unusually large and accumulates snapshot loading, high-water validation, cache behavior, signing, canonicalization, rendering, mutations, persistence, and tests in one file. The pattern is coherent but dense, which raises review-risk and missed-invariant risk.
- Feature gating can hide supply-chain paths. `manifest.rs` is behind `#[cfg(feature = "engine")]`, so test and audit commands must explicitly cover the engine-enabled surface when manifest behavior matters.
- The test pattern is strong but heterogeneous. Inline adversarial tests, golden snapshots, fuzz smoke, and registry tests each prove different properties; without a coverage matrix, it is hard to tell which invariants are actually covered end to end.
- Some structures intentionally evict bounded history, while others reject at capacity to preserve security state. That distinction is important but locally encoded; applying the wrong bounded-growth pattern could become a latent security bug.

### Recommendations

- **P0, effort M**: Define a short supply-chain hashing rule: every trust-bound digest needs a domain string, field count or schema version, length prefixes for variable fields, and a regression test that swaps fields. Use §F2 as the baseline.
- **P1, effort M**: Add a shared `DomainSeparatedHasher` or equivalent internal helper for length-prefixed digest construction. Migrate only newly touched supply-chain code first to avoid a broad churn patch.
- **P1, effort M**: Add a monotonic-frontier regression suite covering revocation heads, trust-card version/hash linkage, snapshot high-water files, extension lineage, and quarantine audit chains.
- **P1, effort S**: Add review checks for `Sha256::new`, `HmacSha256::new_from_slice`, and `==` near hash/signature fields so reviewers confirm domain separation and constant-time comparison.
- **P2, effort M**: Build `docs/specs/supply_chain_invariant_matrix.md` mapping invariants to code modules and tests. Include columns for bounds, canonicalization, signature/proof verification, rollback resistance, audit receipt, and adversarial/golden coverage.
- **P2, effort M**: Normalize event/error-code conventions across supply-chain modules. The goal is not one giant enum, but consistent fields: stable code, human detail, trace ID, remediation, and redaction policy.
- **P3, effort L**: Gradually split trust-card internals by responsibility only if adjacent work already touches those sections. Because the repo discourages file proliferation, prefer section-level cleanup and test-matrix clarity before creating new modules.
- **P3, effort S**: Make test naming encode the property type: `adversarial_*`, `golden_*`, `metamorphic_*`, `conformance_*`, or `persistence_*`. This will make future audit passes faster.

### New Pattern Ideas and Extensions

- **Evidence Kernel Pattern**: A shared internal shape for receipts with `schema_version`, `trace_id`, `timestamp`, `subject_id`, `decision`, `reason_code`, `negative_witness`, `digest`, and `remediation`. This generalizes `ProofReceipt`, `AdmissionReceipt`, audit records, and provenance reports.
- **Monotonic Frontier Pattern**: A small abstraction for state that may only advance: current sequence, previous hash, high-water marker, persistence proof, and rollback rejection. Revocation heads, trust-card snapshots, and extension lineage already implement variants.
- **Bounded Security Collection Pattern**: Distinguish "evictable telemetry" from "non-evictable security fact" at the type level. Audit history can evict with anchors; revocation sets must reject at capacity.
- **Trust Source Strategy Pattern**: Formalize `TrustedFile` versus `UntrustedNetwork` validation plans, including parse order, size limits, signature-before-parse behavior, and sanitized errors.
- **Pattern Coverage Matrix**: Treat every recurring security pattern as an invariant family and require at least one local test plus one end-to-end or conformance test for production-facing trust decisions.

### Assumptions Ledger

- I assume repeated implementations across manifest, registry, transparency, provenance, trust-card, quarantine, revocation, and artifact-signing modules represent intentional conventions, not coincidence.
- I assume the module comments and README philosophy accurately describe project direction because the code frequently implements the same stated principles.
- I assume line-local tests are meaningful evidence of intended behavior, but not proof that every path is covered by the workspace test runner under every feature combination.
- I assume domain-separated hashing should be treated as mandatory for any trust-bound digest, based on the number of existing examples.
- I assume bounded telemetry and bounded security facts require different semantics: eviction can be acceptable for audit visibility, while revocation/security membership should reject at capacity.
- I assume the current worktree may contain unrelated agent changes, so this analysis avoids inferring project health from dirty status.

### Questions for Project Owner

- Should supply-chain modules standardize on one shared digest builder now, or continue opportunistic migration to avoid broad churn?
- Which security histories are allowed to evict with chain anchors, and which must reject at capacity forever?
- Should the trust-card registry remain a single dense module for locality, or is there appetite for a carefully staged internal decomposition?
- Do you want a supply-chain invariant matrix artifact as a follow-up, or should that be captured as beads only when a concrete coverage gap is found?
- Should untrusted-source validation require signature-before-parse everywhere, or only for snapshot-style payloads where raw verification is possible?

### Points of Uncertainty

- I did not run the supply-chain test suite; this was a reasoning-mode code analysis artifact, not a validation pass.
- I did not inspect every line of all 19 supply-chain files. The conclusions are induced from repeated high-signal modules and may miss exceptions in less central files.
- Some adversarial tests in `mod.rs` name broad attack classes and historical error variants; I did not verify whether every one is currently registered and passing under the active feature set.
- The best abstraction boundary for shared security helpers is unclear. Over-centralizing could make simple modules harder to reason about, while under-centralizing preserves drift risk.
- The source-context validation pattern in trust cards is strong, but I did not trace all callers to confirm they pass the right `SnapshotSourceContext`.

### Agreements and Tensions with Other Perspectives

- Expected agreement with Type-Theoretic analysis: bounded types, enum-coded states, monotonic versions, and explicit receipt structs should look like strong domain modeling.
- Expected agreement with Failure Mode analysis: rollback, replay, oversized input, ambiguous digest input, shape-only admission, cache poisoning, and audit-chain breakage are the natural failure families.
- Expected agreement with Systems-Thinking analysis: trust decisions compose across manifest, registry, provenance, transparency, artifact signing, revocation, quarantine, and trust-card state.
- Expected tension with Pure Deductive analysis: several findings are probabilistic pattern generalizations, not formal proofs; exceptions in uninspected modules could weaken them.
- Expected tension with Refactoring-oriented analysis: the duplicated helper pattern suggests cleanup, but repo discipline favors tight, bead-sized changes over broad speculative refactors.
- Expected tension with Performance analysis: strict canonicalization, signature verification, constant-time comparisons, and high-water persistence add overhead by design; performance work must preserve these semantics.

### Confidence: 0.86

The confidence level is high enough for architecture and review guidance because the same patterns appear across many independent supply-chain modules and match the README/AGENTS security posture. It is not higher because this was an inductive static pass, not a full execution or coverage proof, and because several conclusions generalize from representative high-signal files rather than exhaustive inspection of every supply-chain path.
