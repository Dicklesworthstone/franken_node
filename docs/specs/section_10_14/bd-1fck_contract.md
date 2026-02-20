# bd-1fck: Retrievability-Before-Eviction Proofs — Specification Contract

## Overview

When trust artifacts transition from L2 (warm) to L3 (archive), the L2 copy must
not be evicted until a positive retrievability proof demonstrates the L3 copy is
intact and fetchable. This is the safety interlock between tiered storage and eviction.

## Storage Tiers

| Tier | Label | Purpose |
|------|-------|---------|
| L1Hot | `L1_hot` | Active working set |
| L2Warm | `L2_warm` | Warm cache, eviction candidate |
| L3Archive | `L3_archive` | Long-term archive |

## Types

| Type | Kind | Purpose |
|------|------|---------|
| `ArtifactId` | struct | Unique artifact identifier |
| `SegmentId` | struct | Storage segment being retired |
| `StorageTier` | enum | L1Hot, L2Warm, L3Archive |
| `ProofFailureReason` | enum | HashMismatch, LatencyExceeded, TargetUnreachable |
| `RetrievabilityProof` | struct | Successful proof with hash, timestamp, latency |
| `RetrievabilityError` | struct | Failed proof with error code and reason |
| `RetrievabilityConfig` | struct | Gate configuration (max_latency_ms, require_hash_match) |
| `ProofReceipt` | struct | Persistent audit record of proof attempt |
| `GateEvent` | struct | Structured event (code, artifact_id, segment_id, detail) |
| `EvictionPermit` | struct | Permit returned on successful eviction gate check |
| `RetrievabilityGate` | struct | Gate enforcing retrievability before eviction |
| `TargetTierState` | struct | Simulated target tier for proof checking |

## Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `check_retrievability` | `(&mut self, artifact, segment, source, target, hash) -> Result<Proof, Error>` | Core proof check |
| `attempt_eviction` | `(&mut self, artifact, segment, hash) -> Result<EvictionPermit, Error>` | Gated eviction entry |
| `register_target` | `(&mut self, artifact, tier, state)` | Register target state |
| `receipts` | `(&self) -> &[ProofReceipt]` | All proof receipts |
| `events` | `(&self) -> &[GateEvent]` | All gate events |
| `config` | `(&self) -> &RetrievabilityConfig` | Gate configuration |
| `passed_count` | `(&self) -> usize` | Count of passed proofs |
| `failed_count` | `(&self) -> usize` | Count of failed proofs |
| `receipts_json` | `(&self) -> String` | Export receipts as JSON |
| `content_hash` | `(data: &[u8]) -> String` | SHA-256 content hash |

## Config Defaults

| Parameter | Default |
|-----------|---------|
| `max_latency_ms` | 5000 |
| `require_hash_match` | true |

## Proof Checks (in order)

1. Target reachability: tier must be registered and reachable
2. Fetch latency: must not exceed `max_latency_ms`
3. Content hash: must match expected hash (if `require_hash_match`)

## Event Codes

| Code | When |
|------|------|
| `RG_GATE_INITIALIZED` | Gate created |
| `RG_PROOF_PASSED` | Proof succeeds |
| `RG_PROOF_FAILED` | Proof fails |
| `RG_EVICTION_BLOCKED` | Eviction blocked by failed proof |
| `RG_EVICTION_PERMITTED` | Eviction permitted after proof |

## Error Codes

| Code | When |
|------|------|
| `ERR_HASH_MISMATCH` | Target hash differs from expected |
| `ERR_LATENCY_EXCEEDED` | Fetch latency exceeds limit |
| `ERR_TARGET_UNREACHABLE` | Target tier not reachable |
| `ERR_EVICTION_BLOCKED` | Eviction blocked (no proof) |

## Invariants

| Tag | Statement |
|-----|-----------|
| `INV-RG-BLOCK-EVICTION` | Eviction requires successful proof; no code path allows eviction without proof |
| `INV-RG-PROOF-BINDING` | Each proof bound to specific (artifact_id, segment_id, target_tier) |
| `INV-RG-FAIL-CLOSED` | Failed proofs block eviction unconditionally; no bypass |
| `INV-RG-AUDIT-TRAIL` | Every proof attempt (pass or fail) logged with structured diagnostics |

## Artifacts

| Artifact | Path |
|----------|------|
| Implementation | `crates/franken-node/src/storage/retrievability_gate.rs` |
| Proof receipts | `artifacts/10.14/retrievability_proof_receipts.json` |
