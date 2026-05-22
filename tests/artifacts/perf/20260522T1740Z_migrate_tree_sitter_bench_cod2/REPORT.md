# bd-98xo5.9.3 corpus profile

Run id: `20260522T1740Z_migrate_tree_sitter_bench_cod2`

Source HEAD before artifact commit: `862e66d7`

Bench target: `crates/franken-node/benches/migrate_tree_sitter_bench.rs`

## Commands

Build:

```text
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,RUSTFLAGS rch exec -- env CARGO_TARGET_DIR=/tmp/franken-tgt-cod2-r27-bd98xo593 RUSTFLAGS='-C force-frame-pointers=yes' cargo build --profile release-perf -p frankenengine-node --no-default-features --bench migrate_tree_sitter_bench
```

Criterion:

```text
/tmp/franken-tgt-cod2-r27-bd98xo593/release-perf/deps/migrate_tree_sitter_bench-58f219a6ceb4237a large --bench --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot --save-baseline cod2_r27_large
/tmp/franken-tgt-cod2-r27-bd98xo593/release-perf/deps/migrate_tree_sitter_bench-58f219a6ceb4237a small --bench --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot --save-baseline cod2_r27_small
```

Perf and heaptrack:

```text
perf record -F 999 -g -o tests/artifacts/perf/20260522T1740Z_migrate_tree_sitter_bench_cod2/profiles/migrate_tree_sitter_large.perf.data -- /tmp/franken-tgt-cod2-r27-bd98xo593/release-perf/deps/migrate_tree_sitter_bench-58f219a6ceb4237a large --profile-time 5 --noplot
perf report -i tests/artifacts/perf/20260522T1740Z_migrate_tree_sitter_bench_cod2/profiles/migrate_tree_sitter_large.perf.data --stdio --sort=symbol --no-children --no-call-graph --percent-limit 0
heaptrack -o tests/artifacts/perf/20260522T1740Z_migrate_tree_sitter_bench_cod2/profiles/migrate_tree_sitter_large.heaptrack -- /tmp/franken-tgt-cod2-r27-bd98xo593/release-perf/deps/migrate_tree_sitter_bench-58f219a6ceb4237a large --profile-time 5 --noplot
heaptrack_print -f tests/artifacts/perf/20260522T1740Z_migrate_tree_sitter_bench_cod2/profiles/migrate_tree_sitter_large.heaptrack.zst -a
```

## Criterion percentiles

The percentile table normalizes each Criterion sample time by its matching iteration count.

| Scenario | Corpus | Samples | p50 | p95 | p99 |
|----------|--------|--------:|----:|----:|----:|
| `migrate_tree_sitter/analyze_js/small_78147bytes` | 78,147 bytes / 2,509 lines | 20 | 9.5067 ms | 10.1456 ms | 10.1456 ms |
| `migrate_tree_sitter/analyze_js/large_3099814bytes` | 3,099,814 bytes / 102,253 lines | 20 | 590.9579 ms | 603.1711 ms | 603.1711 ms |
| `migrate_tree_sitter_parse_only/parse/small_78147bytes` | 78,147 bytes / 2,509 lines | 20 | 8.4045 ms | 8.8130 ms | 8.8130 ms |
| `migrate_tree_sitter_parse_only/parse/large_3099814bytes` | 3,099,814 bytes / 102,253 lines | 20 | 513.1815 ms | 657.2693 ms | 657.2693 ms |

## Perf top symbols

`perf report` captured 1,183 samples with zero lost samples. Top 30 self symbols:

| Rank | Self | Symbol |
|-----:|-----:|--------|
| 1 | 12.95% | `ts_parser_parse` |
| 2 | 11.22% | `ts_lex` |
| 3 | 6.87% | `ts_language_table_entry` |
| 4 | 6.61% | `stack_node_new` |
| 5 | 6.45% | `ts_parser__lex` |
| 6 | 4.25% | `stack__iter.constprop.0` |
| 7 | 4.11% | `ts_subtree_summarize_children` |
| 8 | 3.66% | `ts_subtree_release` |
| 9 | 2.93% | `ts_lexer__advance` |
| 10 | 2.66% | `malloc_consolidate` |
| 11 | 2.63% | `_int_malloc` |
| 12 | 2.63% | `ts_tree_cursor_goto_sibling_internal.constprop.0` |
| 13 | 2.33% | `ts_lexer__get_lookahead` |
| 14 | 1.72% | `stack_node_release` |
| 15 | 1.65% | `cfree@GLIBC_2.2.5` |
| 16 | 1.46% | `ts_tree_cursor_goto_first_child_internal` |
| 17 | 1.37% | `ts_subtree_array_remove_trailing_extras` |
| 18 | 1.30% | `ts_subtree_new_leaf` |
| 19 | 1.21% | `ts_stack__add_slice` |
| 20 | 1.21% | `clear_page_rep` |
| 21 | 1.19% | `ts_lex_keywords` |
| 22 | 1.11% | `migrate_tree_sitter_bench::count_nodes` |
| 23 | 1.04% | `tree_sitter_javascript_external_scanner_scan` |
| 24 | 0.92% | `_int_free_chunk` |
| 25 | 0.87% | `ts_subtree_new_node` |
| 26 | 0.76% | `ts_language_next_state` |
| 27 | 0.76% | `unlink_chunk.isra.0` |
| 28 | 0.69% | `__libc_malloc2` |
| 29 | 0.68% | `ts_parser__version_status.isra.0` |
| 30 | 0.68% | `ts_lexer_start` |

The call graph splits the two large-corpus profile loops as 54.42% for `analyze_js` and 41.24% for `parse_only`. Within `analyze_js`, `ts_parser_parse_with_options` contributes 45.01% and `count_nodes` contributes 7.09%.

## Heaptrack summary

```text
total runtime: 4.58s
calls to allocation functions: 2210742 (482694/s)
temporary memory allocations: 222817 (48650/s)
peak heap memory consumption: 83.23M
peak RSS including heaptrack overhead: 100.48M
total memory leaked: 560B
```

Dominant allocator path: `ts_malloc_default` produced 2,202,002 allocation calls with 79.98M peak consumption. The largest nested path is tree-sitter parser stack growth under `stack__iter::_array__reserve`.

## Decision

Classification: case A, parse dominates.

The visitor/output side is not the leading cost: large-corpus `count_nodes` is 7.09% in the call graph, while the parse path is 45.01% under `analyze_js` and 38.96% under `parse_only`. Allocator traffic is significant, but it is coupled to tree-sitter parser stack construction and does not show up as a standalone product-layer allocator hotspot in the flat CPU profile.

SLO logged as non-optimization finding: a 102k-line JavaScript corpus should keep `migrate_tree_sitter/analyze_js` p99 at or below 750 ms on the release-perf profile. This run measured p99 603.1711 ms, so no new visitor/output or allocator optimization bead is filed.
