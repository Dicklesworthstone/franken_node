# bd-1dar: Optional MMR Checkpoints + Inclusion/Prefix Proof APIs

## Purpose

Add externally verifiable proof primitives for the append-only control-plane marker stream
(`bd-126h`). The checkpoint stores a deterministic Merkle accumulator over marker hashes and
exposes proof-generation APIs for:

- membership (`inclusion`) of a specific marker hash
- prefix consistency (`prefix`) between two checkpoints

Checkpointing is optional/togglable and must fail closed when disabled.

## Scope

- Module: `crates/franken-node/src/control_plane/mmr_proofs.rs`
- Conformance tests: `tests/conformance/mmr_proof_verification.rs`
- Proof vectors: `artifacts/10.14/mmr_proof_vectors.json`

## Data Types

### `MmrRoot`

- `tree_size: u64`
- `root_hash: String`

### `InclusionProof`

- `leaf_index: u64`
- `tree_size: u64`
- `leaf_hash: String`
- `audit_path: Vec<String>`

### `PrefixProof`

- `prefix_size: u64`
- `super_tree_size: u64`
- `prefix_root_hash: String`
- `super_root_hash: String`
- `prefix_root_from_super: String`

### `MmrCheckpoint`

- `enabled: bool` (optional/togglable mode)
- `leaf_hashes: Vec<String>`
- `latest_root: Option<MmrRoot>`

## Operations

### Checkpoint Lifecycle

- `MmrCheckpoint::enabled()` / `MmrCheckpoint::disabled()`
- `set_enabled(bool)` (toggle without mutating marker truth)
- `append_marker_hash(marker_hash)` (incremental update)
- `rebuild_from_stream(stream)` (deterministic full rebuild)
- `sync_from_stream(stream)` (reconcile with current stream size)

### Proof APIs

- `mmr_inclusion_proof(stream, checkpoint, seq) -> Result<InclusionProof, ProofError>`
- `verify_inclusion(proof, root, marker_hash) -> Result<(), ProofError>`
- `mmr_prefix_proof(checkpoint_a, checkpoint_b) -> Result<PrefixProof, ProofError>`
- `verify_prefix(proof, root_a, root_b) -> Result<(), ProofError>`

## Determinism + Safety Rules

- Hashing uses SHA-256 over canonical domain-separated preimages:
  - leaf: `leaf:{marker_hash}`
  - parent: `node:{left}:{right}`
- For odd levels, the final node is duplicated before parent hashing.
- Disabled checkpoints are fail-closed (`MMR_DISABLED`).
- Stale checkpoint vs stream length is fail-closed (`MMR_CHECKPOINT_STALE`).
- Prefix proofs require `prefix_size <= super_tree_size`.

## Complexity Targets

- Inclusion proof size: `O(log N)`
- Inclusion verification: `O(log N)`
- Prefix verification: `O(1)` against provided roots/proof payload

## Error Codes

- `MMR_DISABLED`
- `MMR_EMPTY_CHECKPOINT`
- `MMR_SEQUENCE_OUT_OF_RANGE`
- `MMR_CHECKPOINT_STALE`
- `MMR_PREFIX_SIZE_INVALID`
- `MMR_INVALID_PROOF`
- `MMR_LEAF_MISMATCH`
- `MMR_ROOT_MISMATCH`

## Verification Artifacts

- `artifacts/10.14/mmr_proof_vectors.json`
- `artifacts/section_10_14/bd-1dar/verification_evidence.json`
- `artifacts/section_10_14/bd-1dar/verification_summary.md`
