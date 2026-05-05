# Hash Operations Optimization Audit - Swiss Tables (bd-pah1s)

## Summary

Audit of hash-heavy operations across franken_node codebase focusing on SIMD-accelerated Swiss Tables optimization opportunities in trust cards, evidence ledgers, and fleet state management.

## Key Findings

### 1. Runtime Lane Scheduler (HIGH IMPACT)
**File**: `crates/franken-node/src/runtime/lane_scheduler.rs`

Critical BTreeMap structures that perform frequent lookups:
- `lane_configs: BTreeMap<String, LaneConfig>` - Task type to lane mapping
- `mapping_rules: BTreeMap<String, SchedulerLane>` - Configuration lookups
- `counters: BTreeMap<String, LaneCounters>` - Per-lane performance tracking
- `active_tasks: BTreeMap<String, TaskAssignment>` - Running task management
- `queued_tasks: BTreeMap<String, VecDeque<QueuedTaskAssignment>>` - Queue management

**Optimization Potential**: HIGH
- Frequent string-key lookups during task scheduling
- Hot path operations in control plane
- Would benefit significantly from SIMD-accelerated group matching

### 2. Fleet Transport State Management
**File**: `crates/franken-node/src/control_plane/fleet_transport.rs`

Example pattern (from documentation comments):
```rust
nodes: HashMap<String, NodeStatus>,
let key = format!("{}-{}", status.zone_id, status.node_id);
self.nodes.insert(key, status.clone());
```

Current implementation uses BTreeSet for registry tracking:
- `fleet_action_compaction_registry()` uses `BTreeSet<String>`

**Optimization Potential**: MEDIUM
- Node state lookups by composite keys
- Fleet coordination hot paths

### 3. Security Policy Maps
**File**: `crates/franken-node/src/security/degraded_mode_policy.rs`

BTreeSet/BTreeMap structures:
- `permitted_actions: BTreeSet<String>`
- `denied_actions: BTreeSet<String>`
- `healthy_gates: BTreeSet<String>`
- `available_capabilities: BTreeSet<String>`
- `acknowledged_operators: BTreeSet<String>`
- `mandatory_event_last_emitted: BTreeMap<String, u64>`

**Optimization Potential**: MEDIUM
- Security decision hot paths
- Action permission checks

### 4. Storage Adapter
**File**: `crates/franken-node/src/storage/frankensqlite_adapter.rs`

Key structures:
- `store: BTreeMap<(PersistenceClass, String), Vec<u8>>` - Primary storage
- `writes_by_tier: BTreeMap<DurabilityTier, usize>` - Write tracking
- Event codes tracking with `BTreeSet<String>`

**Optimization Potential**: HIGH
- Primary storage lookups by composite keys
- Frequent read/write operations

### 5. Evidence/Replay Operations
**File**: `crates/franken-node/src/replay/replay_conformance_tests.rs`

- `HashSet<String>` for digest uniqueness checking
- Collision detection in replay validation

**Optimization Potential**: LOW-MEDIUM
- Test-focused, but indicates evidence processing patterns

## Swiss Tables Optimization Recommendations

### 1. Lane Scheduler Conversion (Priority 1)
**Target**: `crates/franken-node/src/runtime/lane_scheduler.rs`

Convert BTreeMap to HashMap for:
- String-keyed lane lookups (hot path)
- Task ID lookups (frequent operations)
- Counter tracking (telemetry hot path)

Benefits:
- SIMD-accelerated 16-byte control bytes matching
- Reduced cache misses in scheduling loops
- Better performance for string key operations

### 2. Storage Adapter Optimization (Priority 2)
**Target**: `crates/franken-node/src/storage/frankensqlite_adapter.rs`

Optimize composite key lookups:
- Consider hash-optimized key serialization
- Profile probe path performance
- Ensure optimal 7-bit hash distribution

### 3. Security Policy Lookups (Priority 3)
**Target**: `crates/franken-node/src/security/degraded_mode_policy.rs`

Convert action/capability sets to HashMap where:
- Lookup frequency > insertion order importance
- String-based permission checks in hot paths

## Implementation Strategy

1. **Profile Current Performance**
   - Flamegraph analysis of hash-heavy code paths
   - Benchmark current BTreeMap vs HashMap performance
   - Measure cache miss rates

2. **Selective Migration**
   - Start with runtime/lane_scheduler.rs (highest impact)
   - Preserve BTreeMap where ordering matters (config serialization)
   - Use HashMap for pure lookup operations

3. **SIMD Optimization**
   - Ensure string keys follow hashbrown's optimal patterns
   - Profile 7-bit hash effectiveness
   - Optimize key structures for group matching

4. **Validation**
   - Benchmark improvements in task scheduling latency
   - Verify cache locality improvements
   - Monitor probe path efficiency

## Success Metrics

- [ ] Flamegraph shows improved hash probe efficiency
- [ ] Reduced cache misses in lane scheduling hot paths
- [ ] Benchmark improvements in task assignment latency
- [ ] Fleet state lookup performance gains
- [ ] Maintained correctness in all conversion cases

## Risk Assessment

**LOW RISK**: Most identified BTreeMap usage is for performance, not ordering requirements
**MEDIUM RISK**: Storage composite keys need careful validation
**HIGH REWARD**: Lane scheduler optimization will impact all control plane operations

## Next Steps

1. Implement lane scheduler HashMap conversion
2. Add benchmarks for before/after comparison
3. Profile cache behavior improvements
4. Validate correctness with existing test suite
5. Measure end-to-end performance gains