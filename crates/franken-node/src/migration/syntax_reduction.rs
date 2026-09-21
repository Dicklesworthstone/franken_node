//! Structural reduction proposals for JavaScript/JSX, including single-line
//! bundles. Parsing is a proposal filter, NEVER an equivalence oracle. Every
//! accepted edit must still be admitted by the parent's full-suite executor.
//!
//! Edits use original byte ranges, not source regeneration. Statements, nested
//! bodies, declarators, call arguments and collection members can be removed;
//! literals can shrink and expressions can be replaced by their subexpressions.
//! Every proposal is parsed before behavioral execution. Expression proposals
//! are not claims that a discarded call or assignment is free of side effects.
//! Unsupported grammar (including typed TypeScript) is reported as incomplete
//! syntax coverage, not silently declared syntactically minimal.

use super::Trial;
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::{ControlFlow, Range};
use std::time::{Duration, Instant};
use tree_sitter::{Node, ParseOptions, Parser, Tree};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_NODES: usize = 100_000;
const MAX_PROPOSALS: usize = 4096;
const MAX_SIBLINGS: usize = 4096;
const PARSE_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Serialize)]
pub struct SyntaxStatistics {
    pub passes: usize,
    pub proposals: usize,
    pub candidates_checked: usize,
    pub parse_rejections: usize,
    pub accepted: usize,
    pub skipped: usize,
    pub truncated_passes: usize,
    pub last_skip: Option<String>,
}

impl SyntaxStatistics {
    pub(super) fn merge(&mut self, other: Self) {
        self.passes += other.passes;
        self.proposals += other.proposals;
        self.candidates_checked += other.candidates_checked;
        self.parse_rejections += other.parse_rejections;
        self.accepted += other.accepted;
        self.skipped += other.skipped;
        self.truncated_passes += other.truncated_passes;
        if other.last_skip.is_some() { self.last_skip = other.last_skip; }
    }
}

pub(super) struct Progress {
    pub complete: bool,
    pub stopped: bool,
    pub statistics: SyntaxStatistics,
}

impl Progress {
    fn skip(mut self, reason: String, deadline: Instant) -> Self {
        self.complete = false;
        self.stopped = Instant::now() >= deadline;
        self.statistics.skipped += 1;
        self.statistics.last_skip = Some(reason);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Replacement {
    Literal(&'static str),
    // Retain coordinates, not copied expression strings. A 1 MiB expression
    // must not be cloned into each of the 4,096 possible proposals.
    Source { start: usize, end: usize, parenthesized: bool },
}

impl Replacement {
    fn len(&self) -> usize {
        match self {
            Self::Literal(text) => text.len(),
            Self::Source { start, end, parenthesized } => end - start + if *parenthesized { 2 } else { 0 },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Edit { start: usize, end: usize, replacement: Replacement }

impl Edit {
    fn saving(&self) -> usize { self.end - self.start - self.replacement.len() }

    fn apply(&self, source: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(source.len() - self.saving());
        output.extend_from_slice(&source[..self.start]);
        match &self.replacement {
            Replacement::Literal(text) => output.extend_from_slice(text.as_bytes()),
            Replacement::Source { start, end, parenthesized } => {
                if *parenthesized { output.push(b'('); }
                output.extend_from_slice(&source[*start..*end]);
                if *parenthesized { output.push(b')'); }
            }
        }
        output.extend_from_slice(&source[self.end..]);
        output
    }
}

struct Plan { edits: Vec<Edit>, complete: bool }

fn parser() -> Result<Parser> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_javascript::LANGUAGE.into())?;
    Ok(parser)
}

// None means a completed parse rejected the syntax. Err means no completed
// parse, so it must not be cached or counted as a syntactic rejection.
fn parse(parser: &mut Parser, source: &[u8], deadline: Instant) -> Result<Option<Tree>> {
    ensure!(source.len() <= MAX_BYTES, "syntax source exceeds 1 MiB");
    ensure!(Instant::now() < deadline, "syntax parsing budget exhausted");
    // A cancelled Tree-sitter parse can retain continuation state. Every
    // candidate is independent; never resume an earlier candidate's parse.
    parser.reset();
    let mut progress = |_: &tree_sitter::ParseState| {
        if Instant::now() >= deadline { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    };
    let mut input = |offset: usize, _| source.get(offset..).unwrap_or_default();
    let tree = parser.parse_with_options(&mut input, None,
        Some(ParseOptions::new().progress_callback(&mut progress)))
        .ok_or_else(|| anyhow::anyhow!("syntax parsing budget exhausted"))?;
    ensure!(Instant::now() < deadline, "syntax parsing budget exhausted");
    Ok((!tree.root_node().has_error()).then_some(tree))
}

fn insert(edits: &mut BTreeSet<Edit>, range: Range<usize>, replacement: &'static str) -> bool {
    insert_replacement(edits, range, Replacement::Literal(replacement))
}

fn insert_replacement(edits: &mut BTreeSet<Edit>, range: Range<usize>, replacement: Replacement) -> bool {
    if range.len() <= replacement.len() { return true; }
    let edit = Edit { start: range.start, end: range.end, replacement };
    if edits.contains(&edit) { return true; }
    if edits.len() == MAX_PROPOSALS { return false; }
    edits.insert(edit);
    true
}

// Coarse-to-fine sibling complements permit jointly removing dependent dead
// statements. Declarator deletions consume an adjacent comma while retaining
// at least one binding and the declaration keyword, including inside for(...).
fn siblings(node: Node<'_>, bindings: bool, edits: &mut BTreeSet<Edit>) -> bool {
    let mut cursor = node.walk();
    let mut ranges = Vec::new();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "comment" || child.kind() == "hash_bang_line"
            || (bindings && child.kind() != "variable_declarator") { continue; }
        if ranges.len() == MAX_SIBLINGS { return false; }
        ranges.push(child.byte_range());
    }
    if ranges.is_empty() { return true; }
    if !bindings && !insert(edits, ranges[0].start..ranges[ranges.len() - 1].end, "") { return false; }
    let mut granularity = 2_usize.min(ranges.len());
    loop {
        for part in 0..granularity {
            let first = part * ranges.len() / granularity;
            let last = (part + 1) * ranges.len() / granularity;
            let range = if !bindings { ranges[first].start..ranges[last - 1].end }
                else if last < ranges.len() { ranges[first].start..ranges[last].start }
                else if first > 0 { ranges[first - 1].end..ranges[last - 1].end }
                else { continue; };
            if !insert(edits, range, "") { return false; }
        }
        if granularity == ranges.len() { break; }
        granularity = (granularity * 2).min(ranges.len());
    }
    true
}

// Remove whole elements, never commas found by scanning raw source. The
// parser's direct children distinguish a separator from commas inside strings,
// regular expressions, nested calls, computed properties or spread operands.
// Keep the delimiters so a call cannot accidentally become a bare expression.
// Empty lists are useful proposals too, but the full-suite oracle still decides
// whether deleting an argument, accessor, spread or array hole is admissible.
fn list_elements(node: Node<'_>, edits: &mut BTreeSet<Edit>) -> bool {
    let Some(open) = node.child(0) else { return true; };
    let Ok(last) = u32::try_from(node.child_count().saturating_sub(1)) else { return false; };
    let Some(close) = node.child(last) else { return false; };
    if !matches!((open.kind(), close.kind()), ("(", ")") | ("[", "]") | ("{", "}")) {
        return true;
    }
    if !insert(edits, open.end_byte()..close.start_byte(), "") { return false; }

    let mut cursor = node.walk();
    let mut ranges = Vec::new();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "comment" { continue; }
        if ranges.len() == MAX_SIBLINGS { return false; }
        ranges.push(child.byte_range());
    }
    if ranges.is_empty() { return true; }

    // As with statements, attempt groups before individual elements. Keeping
    // every non-selected element allows reductions when emptying the entire
    // collection would lose the failure's essential data.
    let mut granularity = 2_usize.min(ranges.len());
    loop {
        for part in 0..granularity {
            let first = part * ranges.len() / granularity;
            let last = (part + 1) * ranges.len() / granularity;
            let range = if last < ranges.len() {
                ranges[first].start..ranges[last].start
            } else if first > 0 {
                ranges[first - 1].end..ranges[last - 1].end
            } else {
                ranges[first].start..ranges[last - 1].end
            };
            if !insert(edits, range, "") { return false; }
        }
        if granularity == ranges.len() { break; }
        granularity = (granularity * 2).min(ranges.len());
    }
    true
}

fn lift_expression(outer: Node<'_>, inner: Node<'_>, edits: &mut BTreeSet<Edit>) -> bool {
    // Primary expressions already bind tightly. Compound expressions need
    // parentheses so lifting a+b out of a larger operand does not turn its
    // surrounding multiplication into a+b*c. Object/function/class literals
    // also need parentheses when moved into statement position.
    let parenthesized = !matches!(inner.kind(),
        "identifier" | "number" | "string" | "regex" | "true" | "false"
        | "null" | "this" | "array" | "parenthesized_expression");
    let retained = inner.byte_range();
    let replaced = outer.byte_range();
    if retained.start < replaced.start || retained.end > replaced.end
        || retained.start >= retained.end { return true; }
    insert_replacement(edits, replaced, Replacement::Source {
        start: retained.start, end: retained.end, parenthesized,
    })
}

// These are reduction proposals, not optimizer identities. Removing a call,
// short-circuit branch, getter, await or assignment can change observable work;
// only the existing process-backed full-suite predicate can authorize it.
fn expressions(node: Node<'_>, edits: &mut BTreeSet<Edit>) -> bool {
    let fields: &[&str] = match node.kind() {
        "binary_expression" => &["left", "right"],
        "ternary_expression" => &["condition", "consequence", "alternative"],
        "assignment_expression" | "augmented_assignment_expression" => &["right"],
        "member_expression" => &["object"],
        "subscript_expression" => &["object", "index"],
        "unary_expression" | "update_expression" => &["argument"],
        "call_expression" | "new_expression" => {
            let Some(arguments) = node.child_by_field_name("arguments") else { return true; };
            // Tagged templates are not a parenthesized argument list.
            if arguments.kind() != "arguments" { return true; }
            let mut cursor = arguments.walk();
            let mut count = 0;
            for argument in arguments.named_children(&mut cursor) {
                if matches!(argument.kind(), "comment" | "spread_element") { continue; }
                count += 1;
                if count > MAX_SIBLINGS || !lift_expression(node, argument, edits) { return false; }
            }
            return true;
        }
        "parenthesized_expression" | "sequence_expression" | "await_expression" => {
            let mut cursor = node.walk();
            let mut count = 0;
            for child in node.named_children(&mut cursor) {
                if child.kind() == "comment" { continue; }
                count += 1;
                if count > MAX_SIBLINGS || !lift_expression(node, child, edits) { return false; }
            }
            return true;
        }
        _ => return true,
    };
    for field in fields {
        if let Some(child) = node.child_by_field_name(*field)
            && !lift_expression(node, child, edits) { return false; }
    }
    true
}

fn plan(tree: &Tree, deadline: Instant) -> Result<Plan> {
    let mut edits = BTreeSet::new();
    let mut cursor = tree.walk();
    let mut visited = 0;
    let mut complete = true;
    'walk: loop {
        ensure!(Instant::now() < deadline, "syntax traversal budget exhausted");
        visited += 1;
        if visited > MAX_NODES { complete = false; break; }
        let node = cursor.node();
        let within_limit = match node.kind() {
            "program" | "statement_block" | "class_body" => siblings(node, false, &mut edits),
            "lexical_declaration" | "variable_declaration" => siblings(node, true, &mut edits),
            "string" => insert(&mut edits, node.byte_range(), "''"),
            "template_string" => insert(&mut edits, node.byte_range(), "``"),
            "number" => insert(&mut edits, node.byte_range(), "0"),
            "arguments" => list_elements(node, &mut edits),
            "array" => insert(&mut edits, node.byte_range(), "[]")
                && list_elements(node, &mut edits),
            "object" => insert(&mut edits, node.byte_range(), "{}")
                && list_elements(node, &mut edits),
            _ => true,
        };
        if !within_limit || !expressions(node, &mut edits) { complete = false; break; }
        if cursor.goto_first_child() { continue; }
        loop {
            if cursor.goto_next_sibling() { break; }
            if !cursor.goto_parent() { break 'walk; }
        }
    }
    let mut edits: Vec<_> = edits.into_iter().collect();
    // Largest byte savings first; exact byte coordinates break ties. Neither
    // filesystem enumeration order nor randomized hash iteration affects it.
    edits.sort_by(|left, right| right.saving().cmp(&left.saving()).then_with(|| left.cmp(right)));
    Ok(Plan { edits, complete })
}

/// Repeat structural search from the newly accepted bytes. Stale syntax-node
/// offsets are never reused. A skipped/limited parse marks search incomplete;
/// the caller still owns mandatory fresh final behavioral confirmations.
pub(super) fn reduce(mut source: Vec<u8>, search_deadline: Instant,
    mut evaluate: impl FnMut(Vec<u8>) -> Result<Trial>) -> Result<Progress> {
    let mut progress = Progress { complete: true, stopped: false, statistics: SyntaxStatistics::default() };
    let mut parser = match parser() {
        Ok(parser) => parser,
        Err(error) => return Ok(progress.skip(format!("syntax parser unavailable: {error:#}"), search_deadline)),
    };
    while !source.is_empty() {
        let phase_deadline = search_deadline.min(Instant::now() + PARSE_BUDGET);
        progress.statistics.passes += 1;
        let tree = match parse(&mut parser, &source, phase_deadline) {
            Ok(Some(tree)) => tree,
            Ok(None) => return Ok(progress.skip(
                "JavaScript/JSX grammar rejected this source; syntax search is incomplete (typed TypeScript is unsupported)".into(), search_deadline)),
            Err(error) => return Ok(progress.skip(format!("{error:#}"), search_deadline)),
        };
        let proposals = match plan(&tree, phase_deadline) {
            Ok(plan) => plan,
            Err(error) => return Ok(progress.skip(format!("{error:#}"), search_deadline)),
        };
        drop(tree);
        if !proposals.complete {
            progress.complete = false;
            progress.statistics.truncated_passes += 1;
        }
        progress.statistics.proposals += proposals.edits.len();
        let mut accepted = false;
        for edit in proposals.edits {
            let candidate = edit.apply(&source);
            progress.statistics.candidates_checked += 1;
            match parse(&mut parser, &candidate, search_deadline.min(Instant::now() + PARSE_BUDGET)) {
                Ok(Some(_)) => {}
                Ok(None) => { progress.statistics.parse_rejections += 1; continue; }
                Err(error) => return Ok(progress.skip(format!("{error:#}"), search_deadline)),
            }
            match evaluate(candidate.clone())? {
                Trial::Accept => {
                    source = candidate;
                    progress.statistics.accepted += 1;
                    accepted = true;
                    break;
                }
                Trial::Reject => {}
                Trial::Stop => { progress.complete = false; progress.stopped = true; return Ok(progress); }
            }
        }
        if !accepted { break; }
    }
    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }
    fn proposals(source: &str) -> Plan {
        let tree = parse(&mut parser().unwrap(), source.as_bytes(), deadline()).unwrap().unwrap();
        plan(&tree, deadline()).unwrap()
    }
    fn includes_edit(source: &str, expected: &str) -> bool {
        proposals(source).edits.iter().any(|edit| edit.apply(source.as_bytes()) == expected.as_bytes())
    }

    #[test]
    fn minified_statements_and_nested_function_bodies_have_structural_candidates() {
        assert!(includes_edit("const unused=123;console.log(42);", "console.log(42);"));
        assert!(includes_edit("(()=>{const unused=123;console.log(42);})();", "(()=>{console.log(42);})();"));
        assert!(includes_edit("class A{unused(){return 1;}live(){return 42;}}", "class A{live(){return 42;}}"));
    }

    #[test]
    fn declarators_consume_commas_without_removing_the_live_declaration_keyword() {
        assert!(includes_edit("const unused=1,live=42;console.log(live);", "const live=42;console.log(live);"));
        assert!(includes_edit("let live=42,unused=1;console.log(live);", "let live=42;console.log(live);"));
        assert!(includes_edit("for(let unused=1,i=0;i<2;i++)work(i);", "for(let i=0;i<2;i++)work(i);"));
    }

    #[test]
    fn literal_reductions_are_typed_syntax_nodes_not_textual_replacements() {
        assert!(includes_edit("const a=12345;", "const a=0;"));
        assert!(includes_edit("const a='long';", "const a='';"));
        assert!(includes_edit("const a=[1,2];", "const a=[];"));
        assert!(includes_edit("const a={x:42};", "const a={};"));
        let source = "const a=/const unused=1;console.log(42);/;const b='const unused=1;';";
        for edit in proposals(source).edits {
            let removed = &source[edit.start..edit.end];
            assert_ne!(removed, "unused=1");
        }
    }

    #[test]
    fn byte_ranges_preserve_hashbang_unicode_crlf_and_unterminated_suffix() {
        let source = "#!/usr/bin/env node\r\nconst unused='π';console.log('🦀')";
        assert!(includes_edit(source, "#!/usr/bin/env node\r\nconsole.log('🦀')"));
        for edit in proposals(source).edits {
            let output = edit.apply(source.as_bytes());
            assert!(output.starts_with(b"#!/usr/bin/env node\r\n"));
            assert!(std::str::from_utf8(&output).is_ok());
            assert!(output.len() < source.len());
        }
    }

    #[test]
    fn edits_are_deterministic_unique_and_strictly_smaller() {
        let source = "function unused(){const x=123;return x;}const a=1,b=2;console.log(b);";
        let first = proposals(source);
        assert_eq!(first.edits, proposals(source).edits);
        assert!(first.complete);
        assert_eq!(first.edits.iter().collect::<BTreeSet<_>>().len(), first.edits.len());
        assert!(first.edits.windows(2).all(|pair| pair[0].saving() >= pair[1].saving()));
    }

    #[test]
    fn accepted_offsets_are_rebuilt_and_every_evaluated_candidate_parses() {
        let mut best = b"const unused=123;(()=>{const dead=456;console.log(42);})();".to_vec();
        let result = reduce(best.clone(), deadline(), |candidate| {
            assert!(parse(&mut parser().unwrap(), &candidate, deadline()).unwrap().is_some());
            if candidate.windows(b"console.log(42)".len()).any(|bytes| bytes == b"console.log(42)") {
                best = candidate;
                Ok(Trial::Accept)
            } else { Ok(Trial::Reject) }
        }).unwrap();
        assert!(result.complete && !result.stopped);
        assert!(result.statistics.accepted >= 2);
        assert!(!String::from_utf8(best).unwrap().contains("const"));
    }

    #[test]
    fn unsupported_syntax_and_expired_deadlines_never_invoke_the_behavioral_oracle() {
        for source in ["const x: number=1;", "const x=;"] {
            let result = reduce(source.as_bytes().to_vec(), deadline(), |_| panic!("unsupported source")).unwrap();
            assert!(!result.complete);
            assert_eq!(result.statistics.skipped, 1);
            assert_eq!(result.statistics.candidates_checked, 0);
        }
        let result = reduce(b"console.log(42);".to_vec(), Instant::now(), |_| panic!("expired budget")).unwrap();
        assert!(result.stopped && !result.complete);
        assert_eq!(result.statistics.skipped, 1);
    }

    #[test]
    fn proposal_and_sibling_limits_cannot_claim_complete_search() {
        let source = "work();".repeat(MAX_SIBLINGS + 1);
        let result = proposals(&source);
        assert!(!result.complete);
        assert!(result.edits.len() <= MAX_PROPOSALS);
        let oversized = vec![b' '; MAX_BYTES + 1];
        assert!(parse(&mut parser().unwrap(), &oversized, deadline()).is_err());
    }

    #[test]
    fn stopped_or_fatal_evaluations_are_never_adopted() {
        let source = b"console.log(42);".to_vec();
        let mut calls = 0;
        let result = reduce(source.clone(), deadline(), |_| { calls += 1; Ok(Trial::Stop) }).unwrap();
        assert_eq!(calls, 1);
        assert!(result.stopped && !result.complete);
        assert_eq!(result.statistics.accepted, 0);
        assert!(reduce(source, deadline(), |_| anyhow::bail!("runtime identity changed"))
            .err().unwrap().to_string().contains("runtime identity changed"));
    }

    #[test]
    fn argument_reduction_keeps_the_call_and_each_surviving_argument() {
        for expected in ["work();", "work(b,c);", "work(a,c);", "work(a,b);"] {
            assert!(includes_edit("work(a,b,c);", expected), "{expected}");
        }
        assert!(includes_edit("new Worker(a,b);", "new Worker(a);"));
        assert!(includes_edit("obj?.work?.(a,b);", "obj?.work?.(b);"));
    }

    #[test]
    fn collection_reduction_can_retain_the_one_member_needed_by_the_failure() {
        for (source, expected) in [
            ("const xs=[first,second,third];", "const xs=[second,third];"),
            ("const xs=[first,second,third];", "const xs=[first,third];"),
            ("const xs=[first,second,third];", "const xs=[first,second];"),
            ("const xs={dead:1,live:42};", "const xs={live:42};"),
            ("const xs={live:42,dead:1};", "const xs={live:42};"),
            ("const xs={get live(){return 42},dead:1};", "const xs={get live(){return 42}};"),
        ] {
            assert!(includes_edit(source, expected), "{source} -> {expected}");
        }
    }

    #[test]
    fn list_edits_understand_nested_commas_comments_spreads_and_trailing_commas() {
        for (source, expected) in [
            ("work('a,b',nested(x,y),tail);", "work('a,b',tail);"),
            ("work(/a,b/,tail);", "work(/a,b/);"),
            ("work(head, /* comma , */ ...tail,);", "work(head,);"),
            ("work(head,// comment ,\n tail);", "work(head);"),
            ("const xs=[first,,second,,third,];", "const xs=[first,,third,];"),
            ("const xs=[,,];", "const xs=[];"),
            ("const xs={['a,b']:1,...tail,};", "const xs={['a,b']:1,};"),
            ("work(/* before */ only /* after */);", "work();"),
        ] {
            assert!(includes_edit(source, expected), "{source} -> {expected}");
            assert!(parse(&mut parser().unwrap(), expected.as_bytes(), deadline()).unwrap().is_some());
        }
    }

    #[test]
    fn list_reduction_does_not_treat_patterns_as_collection_literals() {
        let source = "const [first,second]=input;const {a,b}=object;";
        assert!(!includes_edit(source, "const [second]=input;const {a,b}=object;"));
        assert!(!includes_edit(source, "const [first,second]=input;const {b}=object;"));
    }

    #[test]
    fn oversized_lists_mark_the_search_incomplete_without_exceeding_the_edit_cap() {
        let source = format!("work({});", vec!["value"; MAX_SIBLINGS + 1].join(","));
        let result = proposals(&source);
        assert!(!result.complete);
        assert!(result.edits.len() <= MAX_PROPOSALS);
    }

    #[test]
    fn list_reductions_are_only_adopted_after_real_node_execution() {
        // Execute pure, finite programs with no filesystem/network effects.
        // This is the actual Rust reducer with a process-backed test oracle,
        // not a claim about Franken/Node parity or the product's full oracle.
        let run = |source: &[u8]| std::process::Command::new("node")
            .args(["--input-type=commonjs", "-e", std::str::from_utf8(source).unwrap()])
            .output().expect("Node is required for the process-backed reducer test");
        let mut best = b"function keep(value){console.log(value)}keep(42,400,500);".to_vec();
        let expected = run(&best);
        assert!(expected.status.success());
        assert_eq!(expected.stdout, b"42\n");
        let result = reduce(best.clone(), Instant::now() + Duration::from_secs(30), |candidate| {
            let observed = run(&candidate);
            if observed.status == expected.status && observed.stdout == expected.stdout
                && observed.stderr == expected.stderr {
                best = candidate;
                Ok(Trial::Accept)
            } else { Ok(Trial::Reject) }
        }).unwrap();
        assert!(result.complete && !result.stopped);
        assert!(result.statistics.accepted > 0);
        assert!(!best.contains(&b','), "{}", String::from_utf8_lossy(&best));
        assert_eq!(run(&best).stdout, expected.stdout);
    }

    #[test]
    fn expression_lifting_keeps_compound_grouping_and_literal_bytes() {
        for (source, expected) in [
            ("const x=a+b+unused;", "const x=(a+b);"),
            ("const x=(a+b)+unused;", "const x=(a+b);"),
            ("const x=choose?leftValue:rightValue;", "const x=leftValue;"),
            ("const x=choose?leftValue:rightValue;", "const x=rightValue;"),
            ("const x=identity('🦀,\\u03c0');", "const x='🦀,\\u03c0';"),
            ("const x=identity({live:42});", "const x=({live:42});"),
            ("const x=new Box(value);", "const x=value;"),
        ] {
            assert!(includes_edit(source, expected), "{source} -> {expected}");
            assert!(parse(&mut parser().unwrap(), expected.as_bytes(), deadline()).unwrap().is_some());
        }
    }

    #[test]
    fn assignments_sequences_accesses_and_await_have_retained_expression_candidates() {
        for (source, expected) in [
            ("let n;const x=(n=42);", "let n;const x=(42);"),
            ("const x=(first,second);", "const x=(second);"),
            ("const x=object.property;", "const x=object;"),
            ("const x=object[index];", "const x=index;"),
            ("const x=void payload;", "const x=payload;"),
            ("async function f(){return await value;}", "async function f(){return value;}"),
            ("const x=(42);", "const x=42;"),
        ] {
            assert!(includes_edit(source, expected), "{source} -> {expected}");
        }
    }

    #[test]
    fn lifted_source_is_not_regenerated_and_cannot_escape_its_parent_span() {
        let source = "#!/usr/bin/env node\r\nconst x=call(/*keep*/'π\\n🦀');";
        assert!(includes_edit(source, "#!/usr/bin/env node\r\nconst x='π\\n🦀';"));
        let plan = proposals(source);
        assert!(plan.edits.iter().any(|edit| matches!(edit.replacement, Replacement::Source { .. })));
        for edit in &plan.edits {
            if let Replacement::Source { start, end, .. } = edit.replacement {
                assert!(edit.start <= start && start < end && end <= edit.end);
            }
            let candidate = edit.apply(source.as_bytes());
            assert!(candidate.len() < source.len());
            assert!(std::str::from_utf8(&candidate).is_ok());
            assert!(candidate.starts_with(b"#!/usr/bin/env node\r\n"));
        }
        assert_eq!(plan.edits, proposals(source).edits);
    }

    #[test]
    fn lifted_expressions_store_ranges_instead_of_copies_of_large_inputs() {
        let source = format!("consume({},{});", "name".repeat(40_000), "value".repeat(40_000));
        let plan = proposals(&source);
        assert!(plan.complete);
        assert!(std::mem::size_of::<Edit>() <= 128);
        assert!(plan.edits.iter().any(|edit| matches!(edit.replacement, Replacement::Source { .. })));
        for edit in plan.edits { assert!(edit.apply(source.as_bytes()).len() < source.len()); }
    }

    #[test]
    fn real_execution_reduces_nested_expressions_but_rejects_lost_side_effects() {
        let run = |source: &[u8]| std::process::Command::new("node")
            .args(["--input-type=commonjs", "-e", std::str::from_utf8(source).unwrap()])
            .output().expect("Node is required for the process-backed reducer test");
        for source in [
            b"console.log((false?300:42)+0);".as_slice(),
            b"let n=0;console.log((n=7,42),n);".as_slice(),
        ] {
            let expected = run(source);
            assert!(expected.status.success());
            let mut best = source.to_vec();
            let result = reduce(best.clone(), Instant::now() + Duration::from_secs(30), |candidate| {
                let observed = run(&candidate);
                if observed.status == expected.status && observed.stdout == expected.stdout
                    && observed.stderr == expected.stderr {
                    best = candidate;
                    Ok(Trial::Accept)
                } else { Ok(Trial::Reject) }
            }).unwrap();
            assert!(result.complete && !result.stopped);
            if expected.stdout == b"42\n" {
                assert_eq!(best, b"console.log(42);");
            } else {
                assert_eq!(expected.stdout, b"42 7\n");
                assert!(String::from_utf8_lossy(&best).contains("n=7"));
            }
            let observed = run(&best);
            assert_eq!(observed.stdout, expected.stdout);
            assert_eq!(observed.stderr, expected.stderr);
            assert_eq!(observed.status, expected.status);
        }
    }
}
