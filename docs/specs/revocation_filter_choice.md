# Revocation Filter Architecture Decision Record

**Task Reference**: bd-98xo5.3.3 (T3.3)  
**Decision Date**: 2026-05-24  
**Status**: DECIDED  

## Context

The franken_node revocation filter is a critical security component that tracks revoked certificates/tokens to prevent replay attacks. Performance profiling (rounds 1+2) identified the cuckoo filter insertion cliff as a hotspot when production workloads exceed ~30,000 entries.

This ADR analyzes production telemetry and benchmark data to choose between:
- (A) Keep cuckoo filter with operational bounds
- (B) Switch to BTree-based filter 
- (C) Hybrid cuckoo/BTree approach

## Production N Distribution Summary (T3.2 Data)

**Collection Window**: 2026-05-17 to 2026-05-24 (168 hours, 8 samples)

| Metric | Value |
|--------|--------|
| **p50** | 30,250 entries |
| **p95** | 37,200 entries |
| **p99** | 37,200 entries |
| **Max observed** | 37,200 entries |
| **Cuckoo cliff crossings** | 4 instances ≥30,000 entries |
| **Max growth rate** | 8.75 entries/minute |

**Key Finding**: Production workloads routinely exceed 30,000 entries, triggering cuckoo filter performance degradation.

## Benchmark Performance Data (Round 1)

### Lookup Performance
| Size | Cuckoo Filter | BTree | Cuckoo Advantage |
|------|---------------|-------|------------------|
| 1,000 | 57.5 ns | 61.1 ns | 6% faster |
| 10,000 | 54.9 ns | 85.7 ns | 36% faster |
| 100,000 | 54.9 ns | 138.4 ns | 60% faster |
| 500,000 | 55.0 ns | 178.3 ns | 69% faster |

### Insertion Performance  
| Size | Cuckoo Filter | BTree | BTree Advantage |
|------|---------------|-------|-----------------|
| 10,000 | 1.67 ms | 2.47 ms | Cuckoo 32% faster |
| 50,000 | 24.8 ms | 13.5 ms | **BTree 45% faster** |

### Memory Usage
| Size | Cuckoo Filter | BTree | Cuckoo Advantage |
|------|---------------|-------|------------------|
| 10,000 | 32 KB | 468 KB | 14.6x more compact |
| 100,000 | 256 KB | 4,687 KB | 18.3x more compact |
| 500,000 | 1,024 KB | 23,437 KB | 22.9x more compact |

## Decision Evaluation

### Option A: Keep Cuckoo Filter ❌ RULED OUT
**Requirements**: p99 < 20,000 AND max-observed < 28,000

**Analysis**:
- ❌ p99 = 37,200 > 20,000 (requirement violation)
- ❌ max-observed = 37,200 > 28,000 (requirement violation)
- Production data clearly exceeds safe operational bounds

### Option B: Switch to BTree ✅ SELECTED  
**Requirements**: Any node crossed 30,000 OR growth rate suggests cliff risk

**Analysis**:
- ✅ 4 production instances crossed 30,000 entries
- ✅ Production p99 (37,200) routinely in cliff territory
- ✅ BTree shows superior insertion performance at scale (45% faster at 50K)
- ⚠️ Trade-off: 36-69% slower lookups, 14.6x-22.9x memory overhead

### Option C: Hybrid Cuckoo/BTree ⚠️ CONSIDERED BUT REJECTED
**Requirements**: Cuckoo wins lookup AND workload crosses 30,000

**Analysis**:
- ✅ Cuckoo wins lookup (36-69% faster)
- ✅ Production workload crosses 30,000 (4 instances)  
- ❌ Implementation complexity not justified
- ❌ Memory overhead still problematic (two data structures)

## DECISION: Switch to BTree (Option B)

**Rationale**: Production telemetry provides definitive evidence that revocation filter workloads routinely exceed cuckoo filter performance cliffs. The 45% insertion performance improvement at 50K entries outweighs the lookup performance penalty for this security-critical path.

### Operational Invariant Being Committed
- **Maximum expected N**: 50,000 entries per node
- **Performance SLO**: <20ms p99 insertion latency 
- **Memory budget**: <50MB per revocation filter instance

### Implementation Changes Required
**File**: `crates/franken-node/src/security/revocation_freshness.rs`  
**Change**: Replace `CuckooFilter<RevocationEntry>` with `BTreeSet<RevocationEntry>`  
**Scope**: Backend swap behind existing trait interface  
**Estimated effort**: 2-4 hours (low-risk change)

## Revisit Conditions

**Reopen this decision if**:
1. **Production N distribution changes**: If max-observed N drops below 25,000 and stays there for 30+ days, reconsider cuckoo filter
2. **Performance regression**: If BTree p99 insertion latency exceeds 25ms in production monitoring
3. **Memory pressure**: If revocation filter memory usage causes OOM incidents
4. **New benchmark data**: If cuckoo filter implementation improves insertion cliff performance by >50%

## Monitoring Requirements

Post-implementation monitoring must track:
- `franken_node_revocation_filter_entries` gauge (existing)
- `franken_node_revocation_insert_latency_ms` histogram (new)  
- `franken_node_revocation_lookup_latency_ms` histogram (new)
- `franken_node_revocation_memory_bytes` gauge (new)

## References

- **T3.2 Production Data**: `tests/artifacts/perf/cuckoo_n_distribution/20260524.json`
- **Round 1 Benchmarks**: `tests/artifacts/perf/20260520T214003Z_franken_node_perf/criterion_raw/cuckoo_revocation.txt` 
- **Performance Epic**: bd-98xo5 "franken_node performance optimization"
- **Implementation Task**: T3.4 (TBD) "BTree revocation filter swap"

---

**Approved by**: cc_5 (CrimsonCrane)  
**Implementation Target**: Sprint 2026-W22  
**Risk Level**: LOW (backend swap, existing test coverage)