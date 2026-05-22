# T9.3 — Tree-sitter Migration Audit Performance Analysis

**Parent task**: bd-98xo5.9.3  
**Scope**: Profile migrate_tree_sitter_bench on large corpus to determine if migration audit is a performance hotspot  
**Date**: 2026-05-22

## Methodology

This run profiles the newly created `migrate_tree_sitter_bench` benchmark using both perf and heaptrack to understand the performance characteristics of tree-sitter JavaScript parsing in the migration audit pipeline.

### Target workloads

1. **Small corpus**: `commander_command_v12_1_0.js` (~2.5k LOC, 76KB)
2. **Large corpus**: `babel_standalone_v7_12_0.js` (~102k LOC, 3.0MB)

### Measurement approach

- **Criterion benchmarks**: p50/p95/p99 timing analysis for both corpora
- **perf record**: Call-graph sampling to identify hot symbols and functions  
- **heaptrack**: Memory allocation profiling to detect allocation-heavy paths

### Decision criteria

Based on profiling results, classify the migration audit workload:

**(A) Parse-bound**: tree-sitter parsing dominates CPU time  
→ Log as a non-optimization finding with production SLO expectations

**(B) Visitor-bound**: AST traversal/analysis dominates  
→ File optimization bead for visitor patterns  

**(C) Allocation-bound**: Memory allocation dominates  
→ File allocation-reduction bead

## Build configuration

- **Profile**: `release-perf` (opt-level=3, lto="thin", codegen-units=1, debug="line-tables-only")
- **RUSTFLAGS**: `-C force-frame-pointers=yes` (for accurate perf call graphs)
- **Target**: `migrate_tree_sitter_bench` binary from bd-98xo5.9.2 registration

## Expected hotspot candidates

- `tree_sitter::Parser::parse` - Core parsing engine
- `analyze_js_with_tree_sitter` - Custom benchmark analysis function  
- `count_nodes` - AST traversal function
- Memory allocation in Node/Tree creation

## Baseline hypothesis

Tree-sitter is a native incremental parser optimized for speed. For reasonably sized files (< 100k LOC), parsing should be fast. If parsing dominates, this indicates the workload is fundamentally I/O and parse-bound rather than algorithmic.