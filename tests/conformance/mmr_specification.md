# MMR Proof Verification Specification

## Overview

This document specifies the requirements for the Merkle Mountain Range (MMR) proof verification system as implemented in franken_node. This system provides cryptographic proofs for marker stream integrity and verifiable checkpointing.

## Core Components

### 1. MmrCheckpoint
- **Purpose**: Optional checkpoint state for marker-stream Merkle roots
- **States**: Enabled or disabled (fail-closed when disabled)
- **Capacity**: Maximum 4096 leaf hashes before eviction

### 2. Inclusion Proofs
- **Purpose**: Prove a specific marker hash exists in a checkpoint
- **Components**: leaf_index, tree_size, leaf_hash, audit_path

### 3. Prefix Proofs  
- **Purpose**: Prove one checkpoint is an initial segment of another
- **Components**: prefix_size, super_tree_size, root hashes

## Requirements Matrix

### R1: Checkpoint Management (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R1.1 | MUST maintain enabled/disabled state | ✓ |
| R1.2 | MUST fail closed when disabled (reject all operations) | ✓ |
| R1.3 | MUST rebuild deterministically from marker streams | ✓ |
| R1.4 | MUST maintain capacity limit (4096 leaf hashes max) | ✓ |
| R1.5 | MUST evict oldest entries when capacity exceeded | ✓ |
| R1.6 | MUST preserve tree_size across rebuilds | ✓ |

### R2: Inclusion Proof Generation (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R2.1 | MUST generate valid inclusion proofs for retained sequences | ✓ |
| R2.2 | MUST reject requests for evicted sequences | ✓ |
| R2.3 | MUST reject requests for out-of-range sequences | ✓ |
| R2.4 | MUST reject requests when checkpoint is stale | ✓ |
| R2.5 | MUST reject requests when checkpoint is disabled | ✓ |
| R2.6 | MUST generate deterministic proofs for identical inputs | ✓ |
| R2.7 | MUST limit audit path length to log(tree_size) | ✓ |

### R3: Inclusion Proof Verification (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R3.1 | MUST verify valid inclusion proofs successfully | ✓ |
| R3.2 | MUST reject proofs with wrong marker hash | ✓ |
| R3.3 | MUST reject proofs with wrong root hash | ✓ |
| R3.4 | MUST reject proofs with tree size mismatch | ✓ |
| R3.5 | MUST reject proofs with leaf_index >= tree_size | ✓ |
| R3.6 | MUST reject proofs with oversized audit paths | ✓ |
| R3.7 | MUST use constant-time hash comparisons | ✓ |

### R4: Prefix Proof Generation (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R4.1 | MUST generate valid prefix proofs for proper ordering | ✓ |
| R4.2 | MUST reject when prefix_size > super_tree_size | ✓ |
| R4.3 | MUST reject when checkpoints are disabled | ✓ |
| R4.4 | MUST validate prefix relationship in super checkpoint | ✓ |

### R5: Prefix Proof Verification (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R5.1 | MUST verify valid prefix proofs successfully | ✓ |
| R5.2 | MUST reject proofs with invalid size relationships | ✓ |
| R5.3 | MUST reject proofs with mismatched root sizes | ✓ |
| R5.4 | MUST validate all three root relationships | ✓ |
| R5.5 | MUST use constant-time comparisons for root validation | ✓ |

### R6: Error Handling (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R6.1 | MUST return specific error codes for each failure type | ✓ |
| R6.2 | MUST provide structured error information | ✓ |
| R6.3 | MUST fail closed on empty checkpoints | ✓ |
| R6.4 | MUST fail closed on disabled operations | ✓ |

### R7: Cryptographic Security (MUST Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R7.1 | MUST use domain-separated hashing | ✓ |
| R7.2 | MUST use length-prefixed hash inputs | ✓ |
| R7.3 | MUST prevent hash collision attacks | ✓ |
| R7.4 | MUST use constant-time comparisons for security-sensitive operations | ✓ |
| R7.5 | MUST generate deterministic hashes for identical inputs | ✓ |

### R8: Serialization (SHOULD Requirements)

| Req ID | Description | Test Coverage |
|--------|-------------|---------------|
| R8.1 | SHOULD support JSON serialization/deserialization | ✓ |
| R8.2 | SHOULD preserve all proof fields through round-trip | ✓ |
| R8.3 | SHOULD reject malformed serialized proofs | ✓ |

## Error Codes Specification

The system MUST return these specific error codes:

| Error Code | Condition | Required Fields |
|------------|-----------|-----------------|
| `MMR_DISABLED` | Checkpoint is disabled | none |
| `MMR_EMPTY_CHECKPOINT` | No markers in checkpoint | none |
| `MMR_SEQUENCE_OUT_OF_RANGE` | Sequence outside retained window | sequence, tree_size |
| `MMR_CHECKPOINT_STALE` | Checkpoint doesn't match stream | checkpoint_tree_size, stream_tree_size |
| `MMR_PREFIX_SIZE_INVALID` | Invalid prefix size relationship | prefix_size, super_tree_size |
| `MMR_INVALID_PROOF` | Generic proof validation failure | reason |
| `MMR_LEAF_MISMATCH` | Leaf hash doesn't match expected | expected, actual |
| `MMR_ROOT_MISMATCH` | Root hash doesn't match expected | expected, actual |

## Security Considerations

### Domain Separation
Hash functions MUST use distinct domain separators:
- Leaf hashes: `"mmr_proofs_leaf_v1:"`
- Node hashes: `"mmr_proofs_node_v1:"`

### Length Prefixing
All variable-length inputs MUST be length-prefixed to prevent collision attacks:
```rust
hasher.update((input.len() as u64).to_le_bytes());
hasher.update(input.as_bytes());
```

### Constant-Time Comparisons
Hash and signature comparisons MUST use constant-time operations to prevent timing attacks.

## Performance Requirements

### Audit Path Limits
- Audit path length MUST be ≤ log₂(tree_size)
- Maximum audit path entries: 64
- Implementation MUST reject oversized audit paths

### Memory Limits
- Maximum retained leaf hashes: 4096
- Oldest-first eviction when capacity exceeded

## Determinism Requirements

The implementation MUST be deterministic:
- Same marker stream → same checkpoint root
- Same proof inputs → identical proof structure
- Same hash inputs → identical hash outputs