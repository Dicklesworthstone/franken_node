### Thesis

The supply-chain verification system is mostly structured around fail-closed decisions, bounded collections, and explicit receipts, but its highest-risk failure modes appear where state transitions and receipt booleans can overstate what was actually proven. The most important failures are not exotic cryptographic breaks; they are degraded-mode ambiguity, schema validation being mistaken for authentication, panic-on-invalid-proof paths, default-key escape hatches, and incident-response APIs that accept signed-looking directives without enforcing signature verification at the mutating boundary. These can cascade from a single malformed proof, stale revocation feed, or operator/control-plane mistake into false admission, false recall completion, or avoidable denial of service.

### Top Findings

- **§F1**: Malformed transparency proof panic
- **Failure Mode**: Malformed Merkle audit-path data can panic the transparency verifier instead of producing a failed `ProofReceipt`.
- **Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:181-193` decodes `proof.leaf_hash` and each `proof.audit_path` entry with `unwrap_or_else(|e| panic!(...))`; `verify_inclusion` calls `recompute_root(proof)` after leaf-hash equality and path-length checks at `crates/franken-node/src/supply_chain/transparency_verifier.rs:291-350`.
- **Reasoning**: Failure mode analysis asks what happens when invalid data enters a security boundary. Here, invalid sibling hex is not converted into `ProofFailure::PathInvalid`; it can crash the verifier process. The failure propagates as availability loss at exactly the point where untrusted proof material is being evaluated.
- **Severity**: high
- **Confidence**: 0.90
- **So What**: Replace panic-based decoding with a `Result<[u8; 32], ProofFailure>` path and add negative tests for malformed sibling hex, wrong sibling length, and non-hex leaf data. The desired behavior is a structured failed receipt, never a process abort.

- **§F2**: Absent transparency proof reported as verified
- **Failure Mode**: Optional transparency proof mode collapses "proof was not required and absent" into the same successful booleans as a verified proof.
- **Evidence**: `crates/franken-node/src/supply_chain/transparency_verifier.rs:261-288` returns `verified: true`, `log_root_matched: true`, and `proof_valid: true` when `proof` is `None` and `policy.required` is false. `crates/franken-node/src/supply_chain/extension_registry.rs:757-793` then admits based on `proof_receipt.verified`.
- **Reasoning**: Degraded operation should preserve provenance of the decision. This path loses the distinction between "cryptographically included in a pinned transparency log" and "not checked because policy did not require it." Downstream tools that aggregate booleans can report a stronger safety property than the verifier established.
- **Severity**: medium
- **Confidence**: 0.86
- **So What**: Introduce an explicit proof state such as `Verified`, `NotRequiredMissing`, `RequiredMissing`, `Malformed`, and `RootUnpinned`, or add a `proof_source`/`verification_mode` field. Do not set `proof_valid` and `log_root_matched` to true when no proof was supplied.

- **§F3**: Signed manifest schema validation mistaken for authentication
- **Failure Mode**: `SignedExtensionManifest::validate` validates schema and signature shape, but not cryptographic authenticity.
- **Evidence**: `crates/franken-node/src/supply_chain/manifest.rs:38-49` includes a manifest signature; `crates/franken-node/src/supply_chain/manifest.rs:222-305` calls `validate_signature` during `validate_signed_manifest`; `crates/franken-node/src/supply_chain/manifest.rs:407-475` checks base64-like encoding, decoded length, and threshold configuration but does not verify the signature against `publisher_key_id` or a key ring.
- **Reasoning**: A common failure mode is semantic drift between API names and actual guarantees. A caller can reasonably read `SignedExtensionManifest::validate` as authentication, while the function only proves that fields are well-formed enough for projection into the engine manifest.
- **Severity**: high
- **Confidence**: 0.82
- **So What**: Split schema validation from authentication by renaming this path to schema validation, or require a trusted key source and return a distinct authenticated type such as `VerifiedExtensionManifest`. Tests should prove that random 64-byte Ed25519-shaped signatures are rejected by any admission path that claims authentication.

- **§F4**: Raw quarantine directives mutate state without signature enforcement
- **Failure Mode**: Quarantine, recall, and clearance records carry signature fields, but mutating state-machine methods do not verify those signatures.
- **Evidence**: `crates/franken-node/src/supply_chain/quarantine.rs:216-308` documents quarantine orders as cryptographically signed and stores `signature`; `initiate_quarantine` at `crates/franken-node/src/supply_chain/quarantine.rs:604-692` mutates records and can immediately enforce critical quarantines without signature verification. `trigger_recall` at `crates/franken-node/src/supply_chain/quarantine.rs:945-1001` and `lift_quarantine` at `crates/franken-node/src/supply_chain/quarantine.rs:1128-1193` likewise transition state without verifying the recall or clearance signature.
- **Reasoning**: This is a single point of failure. The state machine assumes authentication already happened elsewhere, but the public mutating boundary accepts raw signed-looking structs. Any bypass, test helper promoted to production, or integration mistake can turn unauthenticated data into fleet-control action.
- **Severity**: critical
- **Confidence**: 0.88
- **So What**: Make mutating methods accept `VerifiedQuarantineOrder`, `VerifiedRecallOrder`, and `VerifiedQuarantineClearance` wrappers, or require an authority verifier at the state-machine boundary. Add tests that unsigned or tampered directives cannot initiate, recall, or lift quarantine.

- **§F5**: Recall completion can outpace fleet removal evidence
- **Failure Mode**: Recall completion can be marked complete without proving all expected nodes removed the artifact.
- **Evidence**: `record_recall_receipt` only checks receipt existence and recall-id match at `crates/franken-node/src/supply_chain/quarantine.rs:1004-1066`. `complete_recall` at `crates/franken-node/src/supply_chain/quarantine.rs:1069-1125` transitions to `RecallCompleted`, removes the active quarantine, and emits "Recall completed: all artifacts removed" without checking expected node count or `removed == true` for all nodes. `recall_completion_pct` separately computes completion from `removed` receipts at `crates/franken-node/src/supply_chain/quarantine.rs:1217-1237`, proving the model has the data concept but the completion gate does not enforce it.
- **Reasoning**: Incident-response systems fail dangerously when operator status and actual distributed state diverge. A single premature control-plane call can remove active quarantine while compromised artifacts remain deployed.
- **Severity**: high
- **Confidence**: 0.91
- **So What**: Require an expected node set or expected node count at recall creation and refuse completion until every expected node has a matching `removed: true` receipt. If partial completion is valid, model it as a separate state and keep quarantine active.

- **§F6**: Stale low-tier revocation data remains allowed
- **Failure Mode**: Low-safety extensions are allowed to proceed on stale revocation data, making tier classification and clock/feed health a security-critical dependency.
- **Evidence**: `crates/franken-node/src/supply_chain/revocation_integration.rs:384-402` returns `status: WarnStale`, `allowed: true`, and no error code for low-tier stale revocation data. The medium/high path at `crates/franken-node/src/supply_chain/revocation_integration.rs:422-479` fails closed when freshness evaluation fails.
- **Reasoning**: Failure modes interact. A stale revocation feed alone is survivable if all risky paths fail closed; a stale feed plus an incorrect low-tier classification becomes a bypass. The system can degrade silently from "revocation checked" into "warned but allowed."
- **Severity**: medium
- **Confidence**: 0.80
- **So What**: Make the low-tier stale-allow behavior a named policy with telemetry and a maximum consecutive stale window. Escalate prolonged stale low-tier decisions to fail-closed or require an operator override receipt.

- **§F7**: Revocation capacity exhaustion blocks emergency updates
- **Failure Mode**: Revocation registry capacity can freeze future revocation propagation during an incident wave.
- **Evidence**: `crates/franken-node/src/supply_chain/revocation_registry.rs:16-23` sets `MAX_LOG_ENTRIES` and `MAX_REVOKED_PER_ZONE` to 4096. `advance_head` rejects new revocations once a zone or canonical log reaches capacity at `crates/franken-node/src/supply_chain/revocation_registry.rs:270-285`, then only advances state after those checks at `crates/franken-node/src/supply_chain/revocation_registry.rs:287-310`.
- **Reasoning**: The capacity check is correctly fail-closed for integrity, but the degraded mode is an availability and incident-response failure. An attacker or large compromise can exhaust the revocation budget, after which legitimate emergency revocations cannot be recorded.
- **Severity**: high
- **Confidence**: 0.84
- **So What**: Add near-capacity alarms, zone/time partitioning, and an emergency checkpoint/compaction path that preserves cryptographic continuity while freeing live revocation capacity. Treat capacity exhaustion as an operational incident with a first-class error code.

- **§F8**: Default trust-card registry key remains reachable
- **Failure Mode**: Trust-card registry still exposes a default static signing key path alongside the safer configured-key path.
- **Evidence**: `crates/franken-node/src/supply_chain/trust_card.rs:137-170` defines `DEFAULT_REGISTRY_KEY` but also has a fail-closed configured-key loader. `impl Default` uses the static key at `crates/franken-node/src/supply_chain/trust_card.rs:770-773`. `load_authoritative_state` verifies and persists high-water state using `DEFAULT_REGISTRY_KEY` at `crates/franken-node/src/supply_chain/trust_card.rs:922-976`, while `load_authoritative_state_from_config` uses configured key material at `crates/franken-node/src/supply_chain/trust_card.rs:989-1048`. Current non-test call sites still include `TrustCardRegistry::load_authoritative_state` in `crates/franken-node/src/main.rs:27457` and `crates/franken-node/src/main.rs:27856`.
- **Reasoning**: Static keys are latent failure multipliers. Even if most production paths use configuration, one legacy path that accepts the default key can make forged snapshots look authoritative to that path.
- **Severity**: high
- **Confidence**: 0.72
- **So What**: Gate default-key constructors/loaders behind tests or explicit fixture APIs, and make non-config authoritative loading private or deprecated by construction. Add a scanner or compile-time guard preventing `DEFAULT_REGISTRY_KEY` use in non-test call sites.

### Risks Identified

| Risk | Likelihood | Impact | Failure Cascade |
| --- | --- | --- | --- |
| Malformed transparency proof causes panic | medium | high | Untrusted proof input reaches verifier, process aborts, admission/doctor workflow becomes unavailable. |
| Optional transparency checks report as verified | medium | medium | Relaxed policy emits success booleans, aggregators overstate trust, later audit cannot separate absence from proof. |
| Manifest schema validation mistaken for signature authentication | medium | high | Integration code accepts shape-valid signatures, forged manifest enters downstream admission path. |
| Unverified quarantine/clearance directives mutate fleet state | low to medium | critical | Raw directive bypasses auth boundary, critical quarantine or clearance changes active runtime state. |
| Premature recall completion removes active quarantine | medium | high | Incomplete node receipts are ignored, operator sees "all artifacts removed," compromised artifact remains live. |
| Stale low-tier revocation data allows operation | medium | medium | Feed outage plus tier misclassification allows a revoked extension until refresh or manual intervention. |
| Revocation capacity exhaustion blocks emergency response | low to medium | high | Incident wave fills zone/log caps, later revocations fail, high-tier checks degrade into broad denial. |
| Default trust-card key path accepts forged snapshots | low | high | Legacy loader path uses source-known key, forged trust-card state can pass validation on that path. |

### Recommendations

| Priority | Recommendation | Effort | Target Failure Modes |
| --- | --- | --- | --- |
| P0 | Remove panics from transparency proof verification and return structured `ProofFailure` for every malformed proof component. | small | §F1 |
| P0 | Enforce signature verification at quarantine, recall, and clearance state-machine boundaries with verified wrapper types or an authority verifier. | medium | §F4 |
| P1 | Add recall completion invariants: expected node set, `removed: true` quorum/all-of policy, and separate partial-completion state. | medium | §F5 |
| P1 | Replace transparency receipt booleans with an explicit verification-state enum and preserve source distinctions in admission/doctor/closeout output. | medium | §F2 |
| P1 | Split manifest schema validation from manifest authentication in API naming and return types. | medium | §F3 |
| P2 | Move default trust-card registry key use behind test-only or fixture-only APIs; require configured key material for production loaders. | small to medium | §F8 |
| P2 | Add revocation capacity SLOs, alarms, and emergency compaction/checkpoint support before caps are reached. | medium to large | §F7 |
| P3 | Add stale-revocation policy telemetry for low-tier `WarnStale` decisions and escalate after a bounded duration or count. | small | §F6 |
| P3 | Add failure-injection tests for feed outage, disk-full persistence failure, malformed proofs, partial recall, and stale clocks. | medium | §F1, §F5, §F6, §F7 |
| P4 | Build an operator-facing failure-mode matrix in docs/specs that maps every degraded state to its allowed action, required receipt, and recovery path. | small | all |

### New Failure Prevention Ideas and Extensions

- Add a `VerificationStrength` enum carried through receipts: `CryptographicProof`, `PolicyNotRequired`, `CachedTrust`, `OfflineGrace`, `OperatorOverride`, `FailedClosed`. This makes degraded operation machine-readable.
- Use type-state wrappers for security boundaries: `SchemaValidManifest`, `SignatureVerifiedManifest`, `VerifiedQuarantineOrder`, and `RecallCompletionProof`. State transitions should consume the stronger type, not a raw struct.
- Add a "negative proof corpus" under golden or conformance tests: malformed hex, wrong Merkle path length, stale revocation head, forged trust-card snapshot, unsigned quarantine order, partial recall receipts.
- Add incident-pressure tests that intentionally fill bounded structures to one below capacity and at capacity, then assert the emitted error code, operator guidance, and recovery path.
- Add a periodic "truth audit" that compares human messages such as "all artifacts removed" against the state predicates that justify them.
- Add chaos-style local harnesses for storage failure: read-only directory, disk-full tempdir, interrupted high-water persistence, and truncated snapshot recovery.
- Add a build-time lint or UBS rule for security modules that flags `panic!`, `unwrap`, default keys, and methods named `validate` that accept signatures but no verifier/key material.

### Assumptions Ledger

- The failure modes are not fully independent. Stale revocation data, incorrect safety-tier classification, and relaxed transparency policy can combine into a stronger bypass than any single degraded state.
- I assume public or integration-level callers can reach the cited APIs unless they are type-private or feature-gated in a way visible at the cited call boundary.
- I assume fail-closed availability failures are acceptable for high-risk security operations, but only if the system emits precise recovery guidance and does not lose authoritative state.
- I assume warning-only behavior for low-tier extensions is acceptable only when the tier classifier is trustworthy, the stale window is bounded, and telemetry makes the degraded state visible.
- I assume source-known static keys are unacceptable for production trust boundaries, even when they are convenient for tests and fixtures.
- I assume receipt truthfulness is a safety property: a "passed" or "completed" receipt must mean the system actually established the predicate it names.

### Questions for Project Owner

- Should transparency policy ever allow absent proofs in production, or should `policy.required = false` be limited to development/test profiles?
- Is `validate_signed_manifest` intended to be only schema validation, or is any caller currently treating it as signature authentication?
- Where is quarantine order signature verification expected to happen today, and can the raw mutating APIs be made private to prevent bypass?
- What is the authoritative node set for recall completion, and should completion require all nodes or a policy-specific quorum?
- What is the intended recovery path when revocation registry capacity is exhausted during an active incident?
- Are the `main.rs` call sites for `TrustCardRegistry::load_authoritative_state` production paths, migration tools, or tests hidden in CLI plumbing?
- Should low-tier stale revocation decisions remain allowed indefinitely, or should they escalate after repeated stale checks?

### Points of Uncertainty

- I did not run end-to-end exploit reproductions; this is a static failure-mode analysis grounded in code references.
- Some signature verification may happen in upstream call paths not inspected in this report. The failure remains that the mutating APIs and validation names do not encode that precondition.
- The actual deployment profile may always require transparency proofs, reducing §F2 likelihood but not removing the receipt-truthfulness problem.
- Revocation capacity exhaustion impact depends on fleet scale and whether external archival/compaction exists outside the inspected module.
- Trust-card default-key risk depends on whether the cited `main.rs` call sites are reachable in production commands.

### Agreements and Tensions with Other Perspectives

- An adversarial analysis mode should agree that panic-on-proof-input, default keys, and raw quarantine directives are attackable seams.
- A systems-thinking mode should agree that stale revocation, capacity exhaustion, and partial recall are cascade risks across control plane, storage, and operator workflows.
- A decision-analysis mode may push back on failing closed for low-tier stale revocation because availability loss has product cost; the compromise is bounded warning mode with explicit SLO escalation.
- A performance mode may push back on richer receipt state and capacity checks if they add overhead, but these changes are on security/control paths where truthfulness is more important than micro-optimization.
- A conformance-testing mode should align with the recommendation to add negative fixtures that prove invalid inputs fail for the right reason.

### Confidence: 0.84

Confidence is high for the cited local failure mechanics because each top finding points to concrete code paths. Confidence is lower for production reachability and operational likelihood because I did not trace every CLI/API caller or run failure-injection tests in this pass.
