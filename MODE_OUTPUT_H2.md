# MODE_OUTPUT_H2.md - Adversarial Review Analysis

## Thesis

The franken_node supply chain verification system demonstrates strong defensive programming with domain-separated hashing, constant-time comparisons, and bounded collections. However, as an adversary I would target: (1) the trust boundary between file-backed state and network-sourced data where SnapshotSourceContext distinctions create asymmetric validation depth, (2) the revocation registry's capacity limits which could enable DoS-assisted bypass where an attacker fills the revocation log then exploits subsequent artifacts that cannot be revoked, (3) threshold signature collection where partial signature submission ordering and timing could leak key validity information, and (4) the attestation chain verification where stale cached trust windows combined with time-of-check/time-of-use gaps could allow expired or revoked attestations to pass validation.

---

## Top Findings

### §F1: Revocation Registry Capacity Exhaustion Enables Bypass

**Attack Vector**: Adversary registers thousands of malicious artifacts across zones, triggers revocations for each (potentially via induced security incidents), exhausting the `MAX_REVOKED_PER_ZONE = 4096` and `MAX_LOG_ENTRIES = 4096` limits. Once capacity is reached, new legitimate revocations fail with `RevocationError::InvalidInput`, leaving truly dangerous artifacts unrevocable.

**Evidence**: `crates/franken-node/src/supply_chain/revocation_registry.rs:270-285` — capacity rejection at lines 270-285 returns error but does not escalate or alert.

**Reasoning**: Adversarial thinking: "If I can't prevent detection, I'll prevent remediation." The bounded collection is correct for DoS prevention, but the fail mode leaves critical safety operations unavailable rather than triggering emergency procedures.

**Severity**: critical

**Confidence**: 0.85

**So What**: Add capacity-warning thresholds (e.g., at 80%) that trigger operator alerts and emergency rotation procedures. Consider zone-scoped hard quotas with automatic oldest-inactive-artifact pruning for non-critical zones.

---

### §F2: Trusted vs Untrusted Source Bifurcation Creates Validation Gap

**Attack Vector**: Adversary compromises a "trusted file" source (e.g., local filesystem write via path traversal, symlink attack, or writable mount) and injects a malicious trust card registry snapshot. Because `SnapshotSourceContext::TrustedFile` uses "lazy validation" (parse first, basic bounds only), sophisticated attacks that would be caught by `validate_comprehensive()` pass through.

**Evidence**: `crates/franken-node/src/supply_chain/trust_card.rs:33-42` defines `SnapshotSourceContext` with distinct validation paths; `trust_card.rs:173-204` shows `validate_basic_bounds()` lacks signature verification.

**Reasoning**: The "trusted file" assumption creates a privilege escalation path. Any write primitive to the state directory becomes a trust card injection vector. The distinction made sense for performance, but violates the principle of defense in depth.

**Severity**: high

**Confidence**: 0.80

**So What**: Remove the bifurcated validation path. Always verify signatures regardless of source. Use OS-level integrity mechanisms (MAC labels, IMA signatures) for truly trusted paths rather than code-level trust assumptions.

---

### §F3: Transparency Log Root Pinning Stale State Attack

**Attack Vector**: Adversary exploits a time window between transparency log updates. Organization pins root checkpoint A at tree_size=1000. Adversary publishes malicious artifact at position 1001. Root A verification passes (artifact exists in future state not yet pinned), but if policy doesn't require "pinned root covers this specific artifact," inclusion proof for position 1001 validates against a forward-compatible tree.

**Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:104-113` — `is_checkpoint_pinned()` checks `tree_size == tree_size`, but inclusion proofs for indices near tree boundaries could pass validation against roots that predate the artifact's addition.

**Reasoning**: Merkle inclusion proofs are valid for any root that includes the leaf. An attacker who knows upcoming artifacts can pre-compute proofs that will validate against multiple future roots.

**Severity**: medium

**Confidence**: 0.70

**So What**: Require artifacts to have been included before the pinned root's tree_size (leaf_index < tree_size is checked, but timing attacks on root publication remain). Add signed timestamps from transparency log operator.

---

### §F4: Threshold Signature Timing Oracle

**Attack Vector**: Adversary submits partial signatures for threshold verification and measures response timing to identify which key_ids are valid vs invalid. Even with constant-time signature verification, the key lookup path (`lookup_verifying_key()`) may leak timing through hash table operations or the `VerifyingKeyLookupResult` enum construction.

**Evidence**: `crates/franken-node/src/security/threshold_sig.rs:289-300` — `VerifyingKeyLookup` trait returns enum with three variants; HashMap lookup timing varies with hash collisions and key existence.

**Reasoning**: Threshold systems leak the most information at the "is this key valid?" boundary. An attacker probing key validity can narrow down the signing quorum composition over many requests.

**Severity**: medium

**Confidence**: 0.65

**So What**: Normalize all key lookup paths to constant time. Return the same error structure regardless of whether key_id is unknown or signature is invalid. Add rate limiting on partial signature submissions per trace_id.

---

### §F5: HMAC Key Recovery via Registry Snapshot Differential

**Attack Vector**: Adversary obtains multiple trust card registry snapshots over time, observes the relationship between `snapshot_hash` changes and `registry_signature` changes. With enough samples and knowledge of the signing algorithm (`trust_card_registry_snapshot_sig_v1:` domain), statistical analysis might narrow down HMAC key candidates.

**Evidence**: `crates/franken-node/src/supply_chain/trust_card.rs:282-288` — HMAC computation uses `HmacSha256` with domain prefix. The signature is hex-encoded, preserving all bits.

**Reasoning**: HMAC-SHA256 is cryptographically strong, but the attack surface is the key management. If `registry_signing_key` comes from config files that may be version-controlled, backed up, or logged, the secret exposure risk increases.

**Severity**: low (cryptographically, HMAC is secure; risk is operational)

**Confidence**: 0.50

**So What**: Ensure registry_signing_key is derived from a HSM or secrets manager, not stored in plaintext config. Add key rotation mechanism with overlapping validity windows.

---

### §F6: Provenance Attestation Chain Depth Bypass via Self-Signed Loophole

**Attack Vector**: In development mode (`development_profile()`), `allow_self_signed: true` permits single-link attestation chains. Adversary social-engineers a dev environment config into production, or exploits config inheritance where dev settings leak to production paths.

**Evidence**: `crates/franken-node/src/supply_chain/provenance.rs:161-172` — `development_profile()` sets `allow_self_signed: true`, `required_chain_depth: 1`, and enables `CachedTrustWindow` mode with 30-minute window.

**Reasoning**: The "dev mode" attack is a classic privilege confusion. Developers need relaxed policies, but the boundary between dev and prod is often porous in containerized or CI/CD environments.

**Severity**: medium

**Confidence**: 0.75

**So What**: Add explicit runtime environment detection that fails closed if dev policy is detected in production contexts. Log warnings when self-signed attestations are accepted. Consider requiring out-of-band approval for self-signed acceptance.

---

### §F7: Bounded Collection Eviction Creates Log Integrity Gap

**Attack Vector**: Adversary triggers many audit events (legitimate-looking operations) to fill `audits` vector. With `push_bounded()` evicting oldest entries, the adversary can then perform malicious actions whose audit trail gets pushed out by subsequent high-volume legitimate traffic, creating an undetectable window.

**Evidence**: `crates/franken-node/src/supply_chain/revocation_registry.rs:234-245` and throughout the codebase — `push_bounded()` silently evicts oldest entries.

**Reasoning**: Bounded collections protect against memory exhaustion but create a forensic blind spot. An adversary who controls traffic volume can weaponize the bounds against the audit trail.

**Severity**: medium

**Confidence**: 0.80

**So What**: For security-critical audit trails, use append-only persistence (write to disk immediately) rather than in-memory bounded vectors. Alert when bounds are approached, not just when exceeded.

---

### §F8: Merkle Proof Panic Path via Malformed Hex Input

**Attack Vector**: Adversary provides malformed hex strings in `leaf_hash` or `audit_path` entries. The `recompute_root_bytes()` function panics on invalid hex: `panic!("Invalid leaf hash hex: {}", e)` and `panic!("Audit path entry must be exactly 32 bytes")`.

**Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:183-193` — explicit `panic!()` calls in production code path.

**Reasoning**: Any panic in verification code is a DoS vector. An attacker can craft proofs that crash the verification service rather than returning a clean rejection.

**Severity**: high

**Confidence**: 0.95

**So What**: Replace all `panic!()` in verification paths with `Result` returns. Never panic on attacker-controlled input. Use `hex::decode()` with proper error handling.

---

## Risks Identified

| Rank | Threat | Severity | Likelihood | Notes |
|------|--------|----------|------------|-------|
| 1 | Revocation capacity exhaustion bypass | Critical | Medium | Requires coordinated artifact spam |
| 2 | Merkle proof panic DoS | High | High | Trivial to trigger with malformed input |
| 3 | TrustedFile validation gap exploitation | High | Medium | Requires filesystem write primitive |
| 4 | Provenance dev-mode leak to production | Medium | Medium | Config management error |
| 5 | Audit log eviction forensic gap | Medium | Medium | Requires traffic volume control |
| 6 | Threshold signature timing oracle | Medium | Low | Requires many observations |
| 7 | Transparency root staleness attack | Medium | Low | Narrow timing window |
| 8 | HMAC key exposure via config | Low | Low | Operational, not cryptographic |

---

## Recommendations

### P0 (Fix immediately)

1. **§F8**: Replace all `panic!()` in `transparency_verifier.rs:183-193` with `Result<_, ProofFailure>` returns. Malformed hex should return `ProofFailure::PathInvalid`, not crash.

### P1 (Fix this sprint)

2. **§F1**: Add revocation capacity monitoring with operator alerts at 80% and 95% thresholds. Document emergency procedures for capacity scenarios.

3. **§F2**: Remove `SnapshotSourceContext` bifurcation — always run full signature verification. Performance cost is minimal compared to security gap.

### P2 (Fix this quarter)

4. **§F6**: Add runtime environment assertion that rejects `allow_self_signed: true` when `FRANKEN_NODE_PROFILE != "dev"`.

5. **§F7**: Persist audit entries to append-only log before memory collection. Use bounded collection only as recent-access cache.

### P3 (Backlog)

6. **§F3**: Add signed timestamps from transparency log operators to bound the "artifact added after root pinned" window.

7. **§F4**: Normalize threshold signature key lookup timing with fixed-iteration loops.

### P4 (Nice to have)

8. **§F5**: Integrate HSM support for registry_signing_key derivation.

---

## New Attack Ideas and Extensions

1. **Extension Collision Attack**: Two extensions with carefully crafted names that hash to adjacent leaf positions could exploit Merkle proof reuse vulnerabilities if proof deduplication is attempted.

2. **Threshold Key Rotation Race**: During key rotation transition windows, an attacker might exploit the overlap period where both old and new keys are valid to create conflicting signed states.

3. **Trust Card Version Exhaustion**: The `next_trust_card_version()` uses `checked_add(1)` which will fail at `u64::MAX`. While practically unreachable, a long-lived deployment with automated trust card updates might be vulnerable to version number manipulation.

4. **Quarantine Timing Attack**: If fleet quarantine convergence has observable external effects (network traffic patterns, API availability), an attacker can infer internal security state without direct access.

5. **Provenance Chain Cycle**: Can an attacker create circular attestation chains where A attests B attests A? The `ChainLinkRole::EXPECTED_ORDER` constraint may not fully prevent cycles across multiple attestations.

---

## Assumptions Ledger

### Security Assumptions That Adversaries Could Violate

| Assumption | How It Could Be Violated | Impact |
|------------|--------------------------|--------|
| Local filesystem is trusted | Container escape, shared volume, symlink attack | Bypasses signature verification |
| Revocation log never fills | Coordinated malicious artifact registration | Blocks future revocations |
| HMAC key remains secret | Config file exposure, backup leak, memory dump | Registry snapshot forgery |
| Clock is monotonic and accurate | NTP spoofing, VM time manipulation | Expiry/freshness checks bypassed |
| Ed25519 signatures are unforgeable | Key compromise, quantum computing (long-term) | Complete trust model breakdown |

### Trust Model Assumptions That May Not Hold Under Attack

| Assumption | Attack Scenario |
|------------|-----------------|
| Transparency log operator is honest | Malicious log operator issues backdated proofs |
| Attestation chain signers are distinct entities | Sybil attack where one actor controls multiple "signers" |
| Zone isolation prevents cross-zone attacks | Admin with multi-zone access can bypass isolation |
| Threshold signers don't collude | K signers conspire to sign malicious artifact |

---

## Questions for Project Owner

1. **Revocation capacity design intent**: Is the 4096 limit intentional for memory constraints, or could it be raised with persistent storage? What's the expected revocation volume per zone per year?

2. **TrustedFile source guarantee**: What mechanisms ensure the "trusted file" path cannot be written by unprivileged processes? Is there mandatory access control (SELinux, AppArmor) in deployment?

3. **Panic tolerance in verification**: Are the `panic!()` calls in transparency verification intentional fail-fast behavior, or artifacts of early development? What's the expected behavior when receiving malformed proofs?

4. **Threshold quorum composition**: How are threshold signing keys distributed? Are they held by independent parties, or is there organizational overlap that could enable k-party collusion?

5. **Attestation chain depth justification**: Why is `required_chain_depth: 3` the production default? Is there a threat model document specifying what attacks each chain link prevents?

6. **Cached trust window use cases**: Under what operational scenarios is `CachedTrustWindow` mode acceptable in production? What's the exposure during the 30-minute window?

---

## Points of Uncertainty

1. **§F3 confidence is 0.70**: I'm uncertain about the exact semantics of Merkle proof validation against roots with different tree sizes. Need to verify if `leaf_index < tree_size` is sufficient to prevent forward-proof attacks.

2. **§F4 confidence is 0.65**: Timing oracle attacks depend heavily on implementation details I haven't fully traced. The HashMap implementation's timing characteristics under adversarial input patterns need empirical validation.

3. **External dependencies**: I haven't audited `ed25519-dalek`, `subtle`, or `sha2` crates. Supply chain attacks on these dependencies would completely compromise the security model.

4. **Runtime context**: Many attacks depend on deployment context (network segmentation, file permissions, config management) that I can't assess from code alone.

5. **State persistence**: I haven't traced how in-memory state (revocation registry, audit logs) persists across restarts. Restart-based attacks might reset security state.

---

## Agreements and Tensions with Other Perspectives

### Expected Agreements

- **Type-Theoretic (A7)**: Will likely validate the Result/Error handling patterns and enum exhaustiveness, but may flag the panic paths as type safety violations.
- **Systems-Thinking (F7)**: Will appreciate the bounded collection approach for resource management but may identify emergent capacity exhaustion scenarios I've outlined.
- **Trust-building (I4)**: Will likely support the fail-closed defaults and explicit trust configuration requirements.

### Expected Tensions

- **Type-Theoretic (A7)**: May argue that the `SnapshotSourceContext` enum is actually a correct modeling of the trust boundary, where I see it as a security gap.
- **Systems-Thinking (F7)**: May view the capacity limits as appropriate system constraints, where I see them as weaponizable limits.
- **Trust-building (I4)**: May prioritize the user experience of fast TrustedFile loading, where I prioritize consistent security verification regardless of performance cost.

---

## Confidence: 0.78

This analysis is based on static code review of approximately 15,000 lines across 8 core modules. Confidence is moderate-high because:

- (+) Clear code patterns and well-documented invariants made attack surface identification tractable
- (+) Existing hardening measures (constant-time, bounded collections, domain separation) indicate mature security thinking
- (-) No runtime testing or fuzzing was performed
- (-) Dependency audit not included
- (-) Deployment context and operational procedures unknown
- (-) Some attack scenarios require empirical validation (timing oracles, capacity exhaustion rates)

The most confident findings (§F8 panic paths, §F1 capacity exhaustion) are directly observable in code. The lower-confidence findings (§F4 timing oracle, §F5 HMAC exposure) depend on implementation details and operational context I cannot fully verify from code review alone.
