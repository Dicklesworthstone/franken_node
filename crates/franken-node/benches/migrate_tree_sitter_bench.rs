use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::fs;
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser as JsParser};

/// Test corpus information (name, relative_path, expected_size_category)
const CORPORA: &[(&str, &str, &str)] = &[
    (
        "small",
        "tests/fixtures/migrate_corpora/commander_command_v12_1_0.js",
        "~2.5k LOC",
    ),
    (
        "large",
        "tests/fixtures/migrate_corpora/babel_standalone_v7_12_0.js",
        "~102k LOC",
    ),
];

fn load_corpus(corpus_path: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../"); // Go up from crates/franken-node to project root
    path.push(corpus_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("Failed to load corpus at {}: {err}", path.display()))
}

/// Analyze the CommonJS patterns in JavaScript source using tree-sitter.
/// This mimics the core logic of `analyze_commonjs_with_js_parser`.
fn analyze_js_with_tree_sitter(source: &str) -> Result<usize, String> {
    let mut parser = JsParser::new();
    let language: Language = tree_sitter_javascript::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|err| format!("JavaScript parser unavailable: {err}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "JavaScript parser produced no syntax tree".to_string())?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("JavaScript parser rejected source; manual migration required".to_string());
    }

    // Simple visitor count for measurement purposes
    Ok(count_nodes(root))
}

/// Count total AST nodes - representative of visitor traversal cost.
fn count_nodes(node: Node<'_>) -> usize {
    let mut count = 1;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        count += count_nodes(child);
    }
    count
}

/// Benchmark the tree-sitter analysis pipeline.
/// This captures the cost similar to what `franken-node migrate audit` does.
fn bench_js_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("migrate_tree_sitter");

    for &(name, corpus_path, size_info) in CORPORA {
        let source = load_corpus(corpus_path);
        let source_len = source.len();
        let line_count = source.lines().count();

        println!(
            "Loaded {} corpus: {} bytes, {} lines ({})",
            name, source_len, line_count, size_info
        );

        group.bench_with_input(
            BenchmarkId::new("analyze_js", format!("{}_{}bytes", name, source_len)),
            &source,
            |b, source| {
                b.iter(|| black_box(analyze_js_with_tree_sitter(black_box(source)).unwrap_or(0)))
            },
        );
    }

    group.finish();
}

/// Micro-benchmark just the tree-sitter parsing component for hotspot analysis.
/// This isolates parser cost from visitor traversal and rewrite logic.
fn bench_tree_sitter_parse_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("migrate_tree_sitter_parse_only");

    for &(name, corpus_path, _) in CORPORA {
        let source = load_corpus(corpus_path);
        let source_len = source.len();

        group.bench_with_input(
            BenchmarkId::new("parse", format!("{}_{}bytes", name, source_len)),
            &source,
            |b, source| {
                b.iter(|| {
                    let mut parser = JsParser::new();
                    let language: Language = tree_sitter_javascript::LANGUAGE.into();
                    parser
                        .set_language(&language)
                        .expect("JavaScript parser available");

                    let tree = parser
                        .parse(black_box(source), None)
                        .expect("Parser produces syntax tree");

                    black_box(tree)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_js_analysis, bench_tree_sitter_parse_only);
criterion_main!(benches);
