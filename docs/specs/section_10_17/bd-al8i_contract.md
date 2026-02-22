# bd-al8i Contract: L2 Engine-Boundary N-Version Semantic Oracle

**Bead:** bd-al8i
**Section:** 10.17 (Radical Expansion Execution Track)

## Summary

Implement L2 engine-boundary N-version semantic oracle across franken_engine
and reference runtimes. A differential harness classifies boundary divergences
by risk tier and blocks release on high-risk unresolved deltas. Low-risk deltas
require explicit policy receipts and link back to L1 product-oracle results.

## Scope

- Runtime module: `crates/franken-node/src/runtime/nversion_oracle.rs`
- Runtime module wiring: `crates/franken-node/src/runtime/mod.rs`
- Verification script: `scripts/check_nversion_oracle.py`
- Test suite: `tests/test_check_nversion_oracle.py`

## Dependencies

| Dependency | Bead | Description |
|------------|------|-------------|
| ZK Attestation (upstream) | bd-kcg9 | Zero-knowledge attestation support for selective compliance verification |

## Invariants

| ID | Name | Description |
|----|------|-------------|
| INV-NVO-QUORUM | Quorum Voting | Every cross-runtime check requires quorum agreement from participating runtimes |
| INV-NVO-RISK-TIERED | Risk Tiering | Every semantic divergence is classified into a risk tier (Critical, High, Medium, Low, Info) |
| INV-NVO-BLOCK-HIGH | Block on High Risk | High-risk and critical unresolved divergences block release |
| INV-NVO-POLICY-RECEIPT | Policy Receipt | Low-risk deltas require an explicit policy receipt before proceeding |
| INV-NVO-L1-LINKAGE | L1 Oracle Linkage | Low-risk policy receipts must link back to L1 product-oracle results |
| INV-NVO-DETERMINISTIC | Deterministic Output | Oracle results are deterministic for the same inputs; BTreeMap used for ordered output |

## Event Codes

| Code | Name | Description |
|------|------|-------------|
| FN-NV-001 | Oracle Created | N-version oracle instance created |
| FN-NV-002 | Runtime Registered | Reference runtime registered with oracle |
| FN-NV-003 | Cross Check Started | Cross-runtime semantic check initiated |
| FN-NV-004 | Divergence Detected | Semantic divergence detected between runtimes |
| FN-NV-005 | Divergence Classified | Divergence classified by risk tier |
| FN-NV-006 | Quorum Reached | Quorum agreement reached for a check |
| FN-NV-007 | Quorum Failed | Quorum agreement failed for a check |
| FN-NV-008 | Release Blocked | Release blocked due to unresolved high-risk divergence |
| FN-NV-009 | Policy Receipt Issued | Policy receipt issued for low-risk divergence |
| FN-NV-010 | L1 Linkage Verified | L1 product-oracle linkage verified for policy receipt |
| FN-NV-011 | Voting Completed | Voting round completed across runtimes |
| FN-NV-012 | Oracle Report Generated | Comprehensive oracle divergence report generated |

## Error Codes

| Code | Description |
|------|-------------|
| ERR_NVO_NO_RUNTIMES | No reference runtimes registered |
| ERR_NVO_QUORUM_FAILED | Quorum threshold not reached |
| ERR_NVO_RUNTIME_NOT_FOUND | Runtime ID not found in registry |
| ERR_NVO_CHECK_ALREADY_RUNNING | Cross-runtime check already in progress for this boundary |
| ERR_NVO_DIVERGENCE_UNRESOLVED | High-risk divergence has not been resolved |
| ERR_NVO_POLICY_MISSING | Required policy receipt not provided for low-risk delta |
| ERR_NVO_INVALID_RECEIPT | Policy receipt is invalid or expired |
| ERR_NVO_L1_LINKAGE_BROKEN | L1 product-oracle linkage could not be verified |
| ERR_NVO_VOTING_TIMEOUT | Voting round timed out waiting for runtime responses |
| ERR_NVO_DUPLICATE_RUNTIME | Runtime with this ID is already registered |

## Types

| Type | Kind | Description |
|------|------|-------------|
| `RuntimeOracle` | struct | Central N-version oracle coordinating checks across runtimes |
| `SemanticDivergence` | struct | Recorded divergence between runtimes with classification |
| `CrossRuntimeCheck` | struct | A single cross-runtime semantic boundary check |
| `VotingResult` | struct | Result of a quorum voting round |
| `RiskTier` | enum | Risk classification: Critical, High, Medium, Low, Info |
| `PolicyReceipt` | struct | Explicit acknowledgment for low-risk divergences |
| `OracleVerdict` | enum | Overall verdict: Pass, BlockRelease, RequiresReceipt |
| `RuntimeEntry` | struct | Metadata about a registered reference runtime |
| `L1LinkageProof` | struct | Proof linking a policy receipt to L1 product-oracle results |
| `DivergenceReport` | struct | Comprehensive report of all divergences from an oracle run |
| `CheckOutcome` | enum | Outcome of a single cross-runtime check: Agree, Diverge |
| `BoundaryScope` | enum | Engine boundary scope: TypeSystem, Memory, IO, Concurrency, Security |

## Key Methods

| Method | Type | Description |
|--------|------|-------------|
| `register_runtime` | `RuntimeOracle` | Register a reference runtime for comparison |
| `remove_runtime` | `RuntimeOracle` | Remove a runtime from the registry |
| `run_cross_check` | `RuntimeOracle` | Execute a cross-runtime semantic check |
| `classify_divergence` | `RuntimeOracle` | Classify a detected divergence by risk tier |
| `vote` | `RuntimeOracle` | Submit a runtime's vote for a cross-check |
| `tally_votes` | `RuntimeOracle` | Tally votes and determine quorum result |
| `issue_policy_receipt` | `RuntimeOracle` | Issue a policy receipt for a low-risk divergence |
| `verify_l1_linkage` | `RuntimeOracle` | Verify L1 product-oracle linkage for a receipt |
| `generate_report` | `RuntimeOracle` | Generate the comprehensive divergence report |
| `check_release_gate` | `RuntimeOracle` | Evaluate whether release is blocked |
| `resolve_divergence` | `RuntimeOracle` | Mark a divergence as resolved |

## Release Gate Semantics

1. **Critical / High-risk divergences** that are unresolved block the release gate.
2. **Medium-risk divergences** generate warnings but do not block.
3. **Low-risk divergences** require a `PolicyReceipt` with verified `L1LinkageProof`.
4. **Info-level divergences** are recorded but require no action.
5. The oracle report includes a machine-readable `OracleVerdict` field.

## Schema Version

`nvo-v1.0`

## Acceptance Criteria

- Differential harness classifies boundary divergences by risk tier and blocks
  release on high-risk unresolved deltas.
- Low-risk deltas require explicit policy receipts and link back to L1
  product-oracle results.
- At least 20 inline unit tests covering all invariants and error paths.
- Machine-readable verification evidence at
  `artifacts/section_10_17/bd-al8i/verification_evidence.json`.
