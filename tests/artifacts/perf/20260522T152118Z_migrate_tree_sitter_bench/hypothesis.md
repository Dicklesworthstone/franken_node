# Performance Hypothesis — migrate_tree_sitter_bench

## Background context

Migration audit (`franken-node migrate audit`) performs JavaScript AST analysis to identify CommonJS→ESM migration risks. The core pipeline:

1. **File I/O**: Read JavaScript source files
2. **Parsing**: tree-sitter JavaScript parser creates AST  
3. **Analysis**: Custom visitor traverses AST looking for require/export patterns
4. **Reporting**: Generate migration risk findings

The T9 round-3 measurement aims to determine if this pipeline is a performance hotspot for large-scale migration audits.

## Hypothesis A: Parse-bound workload

**Prediction**: tree-sitter parsing dominates CPU time (>50% cycles)

**Evidence**: 
- tree-sitter is a native incremental parser with optimized C implementation
- Large files (100k LOC) stress the parser's input handling and tokenization
- Parsing is inherently O(n) in file size

**Outcome**: Log SLO expectation, not an optimization target

## Hypothesis B: Visitor-bound workload  

**Prediction**: AST traversal and pattern matching dominates CPU time

**Evidence**:
- `count_nodes()` recursive traversal touches every AST node
- `analyze_js_with_tree_sitter()` performs custom analysis on top of raw parsing
- Pattern matching against CommonJS require/export structures

**Outcome**: File optimization bead for visitor algorithm improvements

## Hypothesis C: Allocation-bound workload

**Prediction**: Memory allocation/deallocation dominates CPU time

**Evidence**:
- Large ASTs create many heap-allocated Node objects
- String allocations for identifier/literal content  
- Temporary collections during traversal

**Outcome**: File allocation-reduction bead (arena allocators, object pooling)

## Expected baselines

Based on tree-sitter benchmarks and typical parsing performance:

- **Small corpus (2.5k LOC)**: < 5ms parse time, minimal GC pressure
- **Large corpus (102k LOC)**: 50-200ms parse time, moderate allocation

## Key metrics to capture

1. **Hot symbols**: Top 20 functions by CPU percentage
2. **Allocation rate**: Objects/second and peak memory usage  
3. **Parse vs visitor split**: % time in tree_sitter vs analysis functions
4. **Throughput**: Files/second, MB/second processing rates