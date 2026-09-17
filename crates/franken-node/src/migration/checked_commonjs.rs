//! Refine proposed CommonJS conversions before checked candidate preparation.
//!
//! Renaming no files and changing no package type means that emitting ESM is
//! not a valid conversion. Keep CommonJS exports, wrapper bindings, cycles and
//! load sites intact; change only recognized builtin-specifier literal bytes.
//! This is a candidate transformation, not an equivalence proof: node:-prefixed
//! builtins bypass require.cache, so the captured runtime comparison is still
//! mandatory. Obvious loader rebinding/cache use fails closed before execution.

use super::{MigrationRewriteAction as Action, MigrationRewriteReport};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{ControlFlow, Range};
use std::time::{Duration, Instant};
use tree_sitter::{Node, ParseOptions, Parser};

const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_EDITS: usize = 65_536;
const PARSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Refine only the legacy planner's proposed CommonJS file edits. Manifest and
/// ESM plans, and ALL existing manual-review barriers, remain authoritative.
/// The dry-run preimages are captured bytes, never newly read mutable sources.
/// No proposed CommonJS-to-ESM bytes may survive this stage into checked apply.
pub(super) fn refine(plan: &mut MigrationRewriteReport, deadline: Instant) -> Result<()> {
    ensure!(!plan.apply_mode && plan.rewrites_applied == 0
        && plan.entries.iter().all(|entry| !entry.applied), "cannot refine an applied rewrite plan");
    ensure!(plan.rewrites_planned == plan.rollback_entries.len(), "rewrite plan and preimage inventory disagree");
    let mut paths = BTreeSet::new();
    for entry in &plan.entries {
        if entry.action == Action::RewriteCommonJsRequire {
            let path = entry.path.as_ref().context("CommonJS rewrite has no source path")?;
            ensure!(paths.insert(path.clone()), "duplicate CommonJS rewrite plan entry");
        }
    }
    let preimages: BTreeMap<_, _> = plan.rollback_entries.iter().map(|entry| (&entry.path, entry)).collect();
    ensure!(preimages.len() == plan.rollback_entries.len(), "duplicate rewrite preimage path");
    // Finish every analysis before mutating the plan, including deadline errors.
    let mut rewritten = BTreeMap::new();
    for path in paths {
        ensure!(Instant::now() < deadline, "checked CommonJS planning budget exhausted");
        let before = &preimages.get(&path).context("CommonJS rewrite preimage missing")?.original_content;
        rewritten.insert(path, rewrite(before, deadline.min(Instant::now() + PARSE_TIMEOUT)));
    }
    let mut omitted = BTreeSet::new();
    for entry in &mut plan.entries {
        if entry.action != Action::RewriteCommonJsRequire { continue; }
        let path = entry.path.as_ref().context("CommonJS rewrite path missing")?;
        match &rewritten[path] {
            Ok((_, count)) if *count > 0 => {
                entry.detail = format!("normalized {count} CommonJS builtin specifier(s) without changing module format or load order");
            }
            Ok(_) => { omitted.insert(path.clone()); }
            Err(reason) => {
                entry.action = Action::ManualModuleReview;
                entry.detail = reason.clone();
                plan.manual_review_items += 1;
                omitted.insert(path.clone());
            }
        }
    }
    plan.entries.retain(|entry| entry.action != Action::RewriteCommonJsRequire
        || entry.path.as_ref().is_none_or(|path| !omitted.contains(path)));
    plan.rollback_entries.retain(|entry| !omitted.contains(&entry.path));
    for entry in &mut plan.rollback_entries {
        if let Some(Ok((source, _))) = rewritten.get(&entry.path) {
            entry.rewritten_content.clone_from(source);
        }
    }
    plan.rewrites_planned = plan.rollback_entries.len();
    plan.entries.sort_by(|left, right| left.path.cmp(&right.path)
        .then_with(|| left.action.cmp(&right.action)).then_with(|| left.detail.cmp(&right.detail)));
    for (index, entry) in plan.entries.iter_mut().enumerate() {
        entry.id = format!("mig-rewrite-{:03}", index + 1);
    }
    Ok(())
}

fn text<'a>(source: &'a str, node: Node<'_>) -> &'a str { &source[node.byte_range()] }

fn rewrite(source: &str, deadline: Instant) -> std::result::Result<(String, usize), String> {
    if source.len() > MAX_SOURCE_BYTES || Instant::now() >= deadline {
        return Err("CommonJS source size or planning budget exceeded; manual migration required".into());
    }
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|error| format!("CommonJS parser unavailable: {error}"))?;
    let bytes = source.as_bytes();
    let mut input = |offset: usize, _| bytes.get(offset..).unwrap_or_default();
    let mut progress = |_: &tree_sitter::ParseState| {
        if Instant::now() >= deadline { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    };
    let tree = parser.parse_with_options(&mut input, None,
        Some(ParseOptions::new().progress_callback(&mut progress)))
        .ok_or_else(|| "CommonJS parsing budget exhausted; manual migration required".to_owned())?;
    if tree.root_node().has_error() {
        return Err("CommonJS parser rejected source; no partial source rewrite applied".into());
    }
    let mut cursor = tree.walk();
    let mut visited = 0;
    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    loop {
        visited += 1;
        if visited > MAX_NODES || Instant::now() >= deadline {
            return Err("CommonJS traversal budget exhausted; manual migration required".into());
        }
        let node = cursor.node();
        match node.kind() {
            "import_statement" | "export_statement" | "with_statement" => {
                return Err("mixed module syntax or dynamic lexical scope requires manual CommonJS migration".into());
            }
            "identifier" | "shorthand_property_identifier" | "shorthand_property_identifier_pattern" => {
                let name = text(source, node);
                if name.contains('\\') {
                    return Err("escaped identifier prevents proving the CommonJS loader binding; manual migration required".into());
                }
                if name == "require" {
                    let direct_call = node.parent().is_some_and(|parent| parent.kind() == "call_expression"
                        && parent.child_by_field_name("function").is_some_and(|function| function.id() == node.id()));
                    if !direct_call {
                        return Err("require rebinding, aliasing or property/cache access requires manual migration; no partial source rewrite applied".into());
                    }
                }
            }
            "call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    let name = text(source, function);
                    if (function.kind() == "identifier" && name == "eval")
                        || name == "createRequire" || name.ends_with(".createRequire") {
                        return Err("dynamic loader construction or eval requires manual CommonJS migration".into());
                    }
                    if function.kind() == "identifier" && name == "require" {
                        let arguments = node.child_by_field_name("arguments")
                            .ok_or_else(|| "CommonJS require arguments missing".to_owned())?;
                        let mut argument_cursor = arguments.walk();
                        let mut actual = arguments.named_children(&mut argument_cursor)
                            .filter(|child| child.kind() != "comment");
                        let literal = actual.next().ok_or_else(|| "empty require call requires manual migration".to_owned())?;
                        if actual.next().is_some() || !matches!(literal.kind(), "string" | "template_string") {
                            return Err("computed or unsupported require call requires manual migration; no partial source rewrite applied".into());
                        }
                        let raw = text(source, literal);
                        if raw.len() < 2 || raw.contains('\\') || (literal.kind() == "template_string" && raw.contains("${")) {
                            return Err("escaped or interpolated require specifier requires manual migration; no partial source rewrite applied".into());
                        }
                        let name = &raw[1..raw.len() - 1];
                        // Reuse the production exact builtin allowlist through
                        // the ESM normalizer, supplied below without guessing
                        // arbitrary package subpaths or prefix-only builtins.
                        let normalized = normalize(name);
                        if normalized != name {
                            if edits.len() == MAX_EDITS { return Err("CommonJS edit limit exceeded".into()); }
                            edits.push((literal.start_byte() + 1..literal.end_byte() - 1, normalized));
                        }
                    }
                }
            }
            _ => {}
        }
        if cursor.goto_first_child() { continue; }
        loop {
            if cursor.goto_next_sibling() { break; }
            if !cursor.goto_parent() {
                edits.sort_by_key(|(range, _)| range.start);
                let mut output = String::with_capacity(source.len());
                let mut previous = 0;
                for (range, replacement) in &edits {
                    if range.start < previous { return Err("overlapping CommonJS specifier edits refused".into()); }
                    output.push_str(&source[previous..range.start]);
                    output.push_str(replacement);
                    previous = range.end;
                }
                output.push_str(&source[previous..]);
                return Ok((output, edits.len()));
            }
        }
    }
}

// This module is compiled both under the primary migration module and under
// its focused test host. Keep one canonical builtin list, not a copied table.
fn normalize(name: &str) -> String { super::normalize_import_specifier(name) }

#[cfg(test)]
mod tests {
    use super::*;

    fn transformed(source: &str, expected: &str, count: usize) {
        let (actual, edits) = rewrite(source, Instant::now() + Duration::from_secs(10)).unwrap();
        assert_eq!((actual.as_str(), edits), (expected, count));
        assert_eq!(rewrite(&actual, Instant::now() + Duration::from_secs(10)).unwrap(), (actual, 0));
    }

    #[test]
    fn multiline_require_mutable_exports_and_wrapper_bindings_are_preserved() {
        transformed("#!/usr/bin/env node\r\n'use strict';\r\nconst {\r\n basename: name\r\n} = require(/* kept */ 'path');\r\nmodule.exports = function (p) { return name(p); };\r\nexports.old = __filename;\n",
            "#!/usr/bin/env node\r\n'use strict';\r\nconst {\r\n basename: name\r\n} = require(/* kept */ 'node:path');\r\nmodule.exports = function (p) { return name(p); };\r\nexports.old = __filename;\n", 1);
    }

    #[test]
    fn conditional_and_nested_load_sites_are_not_hoisted() {
        transformed("console.log('before');\nfunction lazy(on) { if (on) { const fs = require('fs'); return fs; } }\nmodule.exports = {lazy};\n",
            "console.log('before');\nfunction lazy(on) { if (on) { const fs = require('node:fs'); return fs; } }\nmodule.exports = {lazy};\n", 1);
    }

    #[test]
    fn comments_strings_regexes_templates_and_other_require_methods_are_not_calls() {
        transformed("/* require('fs') */ const s=\"require('path')\"; const r=/require('os')/; const t=`require('net')`; obj.require('crypto');\nconst actual=require('fs/promises');",
            "/* require('fs') */ const s=\"require('path')\"; const r=/require('os')/; const t=`require('net')`; obj.require('crypto');\nconst actual=require('node:fs/promises');", 1);
    }

    #[test]
    fn exact_builtin_aliases_only_and_no_export_conversion() {
        let source = "const a=require('test');const b=require('fs/custom');const c=require('./local');const d=require('@org/fs');module.exports={a,b,c,d};";
        transformed(source, source, 0);
        transformed("const p=require(`path/posix`);const b=require('node:buffer');exports.p=p;",
            "const p=require(`node:path/posix`);const b=require('node:buffer');exports.p=p;", 1);
    }

    #[test]
    fn loader_rebinding_cache_aliasing_and_dynamic_scope_refuse_every_edit() {
        for suffix in ["const require = custom;", "function f(require) { return require('os'); }",
            "const {require} = obj;", "const load=require;", "require.cache.path={exports:{}};",
            "require.resolve('path');", "require(name);", "require(`fs/${part}`);", r"require('p\x61th');",
            "eval('var require=custom');", "with (obj) { require('os'); }", "export const value=1;",
            r"const requ\u0069re=custom;", "createRequire('/tmp/a.cjs');"] {
            let source = format!("const path=require('path');{suffix}");
            assert!(rewrite(&source, Instant::now() + Duration::from_secs(10)).is_err(), "{suffix}");
        }
    }

    #[test]
    fn parse_and_budget_failures_never_produce_partial_candidates() {
        assert!(rewrite("const p=require('path');const broken=;", Instant::now() + Duration::from_secs(10)).is_err());
        assert!(rewrite("require('path');", Instant::now()).is_err());
        assert!(rewrite(&" ".repeat(MAX_SOURCE_BYTES + 1), Instant::now() + Duration::from_secs(10)).is_err());
    }
}
