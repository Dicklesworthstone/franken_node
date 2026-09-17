//! Syntax-aware ESM specifier migration. No module-format conversion or
//! declaration hoisting: only the contents of recognized specifier literals
//! may change. The exact allowlist deliberately excludes prefix-only builtins
//! and arbitrary subpaths of packages with builtin-like names.

use std::collections::BTreeSet;
use std::ops::{ControlFlow, Range};
use std::time::{Duration, Instant};
use tree_sitter::{Node, ParseOptions, Parser};

const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;
const MAX_EDITS: usize = 65_536;
const REWRITE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct Rewrite {
    pub rewritten_content: String,
    pub rewrite_count: usize,
    pub manual_findings: Vec<String>,
}

/// Public, unprefixed builtins in the Node 20/22 migration baseline. This is
/// intentionally not a prefix test: `fs/custom` may be a third-party package
/// export. New prefix-only APIs (`test`, `sqlite`, `sea`, etc.) are NOT aliases
/// for packages with those names. Unknown names are left untouched.
pub(super) fn normalize_import_specifier(specifier: &str) -> String {
    if matches!(specifier,
        "assert" | "assert/strict" | "async_hooks" | "buffer" | "child_process"
        | "cluster" | "console" | "constants" | "crypto" | "dgram"
        | "diagnostics_channel" | "dns" | "dns/promises" | "domain" | "events"
        | "fs" | "fs/promises" | "http" | "http2" | "https" | "inspector"
        | "inspector/promises" | "module" | "net" | "os" | "path" | "path/posix"
        | "path/win32" | "perf_hooks" | "process" | "punycode" | "querystring"
        | "readline" | "readline/promises" | "repl" | "stream" | "stream/consumers"
        | "stream/promises" | "stream/web" | "string_decoder" | "sys" | "timers"
        | "timers/promises" | "tls" | "tty" | "url" | "util" | "util/types"
        | "v8" | "vm" | "wasi" | "worker_threads" | "zlib") {
        format!("node:{specifier}")
    } else {
        specifier.to_owned()
    }
}

pub(super) fn rewrite_esm(source: &str) -> Rewrite {
    match plan(source, Instant::now() + REWRITE_TIMEOUT) {
        Ok(edits) => {
            // Construct forward in one pass; repeated replace_range would be
            // quadratic for files containing many imports. All edits were
            // validated before output construction, so refusal is all-or-none.
            let mut output = String::with_capacity(source.len());
            let mut previous = 0;
            for (range, replacement) in &edits {
                output.push_str(&source[previous..range.start]);
                output.push_str(replacement);
                previous = range.end;
            }
            output.push_str(&source[previous..]);
            Rewrite { rewritten_content: output, rewrite_count: edits.len(), manual_findings: Vec::new() }
        }
        Err(reason) => Rewrite { rewritten_content: source.to_owned(), rewrite_count: 0,
            manual_findings: vec![reason] },
    }
}

fn plan(source: &str, deadline: Instant) -> Result<Vec<(Range<usize>, String)>, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err("ESM rewrite source exceeds the 10 MiB limit; manual migration required".into());
    }
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|error| format!("JavaScript parser unavailable: {error}"))?;
    let mut progress = |_: &tree_sitter::ParseState| {
        if Instant::now() >= deadline { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    };
    let bytes = source.as_bytes();
    let mut input = |offset: usize, _| bytes.get(offset..).unwrap_or_default();
    let tree = parser.parse_with_options(&mut input, None,
        Some(ParseOptions::new().progress_callback(&mut progress)))
        .ok_or_else(|| "ESM rewrite parsing budget exhausted; manual migration required".to_owned())?;
    if tree.root_node().has_error() {
        return Err("JavaScript/JSX parser rejected source; unsupported syntax (including typed TypeScript) requires manual migration".into());
    }
    let mut cursor = tree.walk();
    let mut count = 0_usize;
    let mut edits = Vec::new();
    let mut findings = BTreeSet::new();
    loop {
        count += 1;
        if count > MAX_NODES || Instant::now() >= deadline {
            return Err("ESM rewrite traversal budget exhausted; manual migration required".into());
        }
        let node = cursor.node();
        match node.kind() {
            "import_statement" | "export_statement" => {
                if let Some(literal) = node.child_by_field_name("source") {
                    add_literal(source, literal, &mut edits, &mut findings)?;
                }
            }
            "call_expression" => {
                if let Some(function) = node.child_by_field_name("function") {
                    if function.kind() == "import" {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            let mut arguments_cursor = arguments.walk();
                            let argument = arguments.named_children(&mut arguments_cursor)
                                .find(|child| child.kind() != "comment");
                            if let Some(argument) = argument {
                                add_literal(source, argument, &mut edits, &mut findings)?;
                            }
                        }
                    } else if function.kind() == "identifier" && text(source, function) == "require" {
                        findings.insert("ESM/CJS module mixing detected; automatic import rewrite skipped".to_owned());
                    }
                }
            }
            "assignment_expression" | "augmented_assignment_expression" | "update_expression" => {
                if let Some(target) = node.child_by_field_name("left").or_else(|| node.child_by_field_name("argument"))
                    && commonjs_target(source, target) {
                    findings.insert("ESM/CJS module mixing detected; CommonJS export assignment requires manual migration".to_owned());
                }
            }
            _ => {}
        }
        // Cursor traversal is iterative and bounded; guest nesting never
        // recurses through the Rust call stack or allocates a child-node list.
        if cursor.goto_first_child() { continue; }
        loop {
            if cursor.goto_next_sibling() { break; }
            if !cursor.goto_parent() {
                if !findings.is_empty() { return Err(findings.into_iter().collect::<Vec<_>>().join("; ")); }
                edits.sort_by_key(|(range, _)| range.start);
                for pair in edits.windows(2) {
                    if pair[0].0.end > pair[1].0.start {
                        return Err("overlapping ESM specifier edits refused".into());
                    }
                }
                return Ok(edits);
            }
        }
    }
}

fn text<'a>(source: &'a str, node: Node<'_>) -> &'a str {
    &source[node.byte_range()]
}

fn commonjs_target(source: &str, mut target: Node<'_>) -> bool {
    // Whitespace and comments around dots/brackets do not change the target.
    while matches!(target.kind(), "member_expression" | "subscript_expression") {
        let Some(object) = target.child_by_field_name("object") else { return false; };
        if text(source, object) == "module" {
            if let Some(property) = target.child_by_field_name("property") {
                return text(source, property) == "exports";
            }
            if let Some(index) = target.child_by_field_name("index") {
                return matches!(text(source, index), "'exports'" | "\"exports\"");
            }
        }
        target = object;
    }
    target.kind() == "identifier" && text(source, target) == "exports"
}

fn add_literal(source: &str, literal: Node<'_>, edits: &mut Vec<(Range<usize>, String)>,
    findings: &mut BTreeSet<String>) -> Result<(), String> {
    let raw = text(source, literal);
    if literal.kind() != "string" && literal.kind() != "template_string" {
        findings.insert("computed import() specifier requires manual migration; no partial source rewrite applied".into());
        return Ok(());
    }
    if raw.contains('\\') || (literal.kind() == "template_string" && raw.contains("${")) {
        findings.insert("escaped or interpolated module specifier requires manual migration; no partial source rewrite applied".into());
        return Ok(());
    }
    if raw.len() < 2 { return Err("invalid module specifier literal".into()); }
    let specifier = &raw[1..raw.len() - 1];
    let normalized = normalize_import_specifier(specifier);
    if normalized != specifier {
        if edits.len() == MAX_EDITS {
            return Err("ESM rewrite edit limit exceeded; no partial source rewrite applied".into());
        }
        edits.push((literal.start_byte() + 1..literal.end_byte() - 1, normalized));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Command, Output};

    fn changed(source: &str, expected: &str, count: usize) {
        let result = rewrite_esm(source);
        assert!(result.manual_findings.is_empty(), "{result:?}");
        assert_eq!(result.rewrite_count, count);
        assert_eq!(result.rewritten_content, expected);
        let repeated = rewrite_esm(&result.rewritten_content);
        assert_eq!(repeated.rewrite_count, 0);
        assert_eq!(repeated.rewritten_content, expected);
    }

    #[test]
    fn multiline_imports_reexports_and_multiple_declarations_keep_exact_trivia() {
        changed("import {\r\n readFile\r\n} /* before from */ from /* spec */ 'fs/promises'; import p from 'path';\r\nexport {\n readFile as read\n} from 'fs/promises';\n",
            "import {\r\n readFile\r\n} /* before from */ from /* spec */ 'node:fs/promises'; import p from 'node:path';\r\nexport {\n readFile as read\n} from 'node:fs/promises';\n", 3);
    }

    #[test]
    fn side_effect_star_namespace_and_compact_declarations() {
        changed("import'fs';export*from'path';export * as os from 'os';import{Buffer}from'buffer';",
            "import'node:fs';export*from'node:path';export * as os from 'node:os';import{Buffer}from'node:buffer';", 4);
    }

    #[test]
    fn literal_dynamic_imports_keep_timing_comments_and_options() {
        changed("const a = () => import( /* reason */ 'fs', { with: { type: 'json' } });\nconst b=import(`path`);",
            "const a = () => import( /* reason */ 'node:fs', { with: { type: 'json' } });\nconst b=import(`node:path`);", 2);
    }

    #[test]
    fn hashbang_unicode_crlf_and_no_final_newline_are_preserved() {
        changed("#!/usr/bin/env node\r\n// π\r\nimport fs from 'fs';\r\nconsole.log('🦀');",
            "#!/usr/bin/env node\r\n// π\r\nimport fs from 'node:fs';\r\nconsole.log('🦀');", 1);
    }

    #[test]
    fn comments_strings_regexes_and_template_raw_text_are_never_rewritten() {
        let source = "/*\nimport fs from 'fs';\n*/\nconst s=\"import p from 'path'\";\nconst r=/import os from 'os'/;\nconst t=`first\nimport c from 'crypto';\nlast`;\nimport fs from 'fs';\n";
        let expected = source.strip_suffix("import fs from 'fs';\n").unwrap().to_owned() + "import fs from 'node:fs';\n";
        changed(source, &expected, 1);
    }

    #[test]
    fn executable_dynamic_import_inside_template_substitution_is_rewritten() {
        changed("const t = `raw import('path') ${typeof (await import('fs')).readFile}`;",
            "const t = `raw import('path') ${typeof (await import('node:fs')).readFile}`;", 1);
    }

    #[test]
    fn builtin_subpaths_are_exact_not_package_prefixes() {
        for name in ["fs/custom", "fs/promises/custom", "path/custom", "stream/unknown", "test", "test/reporters", "sqlite", "sea", "ffi", "@org/fs", "./fs", "https://x/fs", "node:fs", "fs?query"] {
            assert_eq!(normalize_import_specifier(name), name, "{name}");
        }
        for name in ["fs", "fs/promises", "path/posix", "stream/web", "util/types", "assert/strict", "timers/promises", "dns/promises"] {
            assert_eq!(normalize_import_specifier(name), format!("node:{name}"));
        }
    }

    #[test]
    fn builtin_named_package_subpaths_and_prefix_only_names_are_preserved() {
        changed("import custom from 'fs/custom';import tests from 'test';export * from 'stream/adapter';",
            "import custom from 'fs/custom';import tests from 'test';export * from 'stream/adapter';", 0);
    }

    #[test]
    fn import_attributes_and_import_like_property_names_are_preserved() {
        changed("import fs from 'fs' with { type: 'json' }; const o={import(x){return x;}};o.import('path');",
            "import fs from 'node:fs' with { type: 'json' }; const o={import(x){return x;}};o.import('path');", 1);
    }

    #[test]
    fn commonjs_spelling_inside_literals_does_not_block_real_esm() {
        changed("import fs from 'fs';const text=`require('path')\nmodule.exports = 1;`;/* require('fs') */",
            "import fs from 'node:fs';const text=`require('path')\nmodule.exports = 1;`;/* require('fs') */", 1);
    }

    #[test]
    fn actual_mixed_module_forms_refuse_all_edits() {
        for suffix in ["const x=require('path');", "module /*a*/ . exports = {};", "module['exports'].x=1;", "exports.x += 1;", "exports.x++;"] {
            let source = format!("import fs from 'fs';{suffix}");
            let result = rewrite_esm(&source);
            assert_eq!(result.rewrite_count, 0, "{suffix}");
            assert_eq!(result.rewritten_content, source);
            assert!(result.manual_findings.iter().any(|m| m.contains("ESM/CJS module mixing")), "{result:?}");
        }
    }

    #[test]
    fn malformed_or_typed_source_is_not_partially_rewritten() {
        for source in ["import fs from 'fs'; const x = ;", "import fs from 'fs'; const x: number=1;"] {
            let result = rewrite_esm(source);
            assert_eq!(result.rewritten_content, source);
            assert_eq!(result.rewrite_count, 0);
            assert!(!result.manual_findings.is_empty());
        }
    }

    #[test]
    fn computed_and_escaped_specifiers_require_review_without_partial_edits() {
        for suffix in ["import(name);", "import(`fs/${part}`);", r"import('f\x73');"] {
            let source = format!("import fs from 'fs';{suffix}");
            let result = rewrite_esm(&source);
            assert_eq!(result.rewritten_content, source);
            assert_eq!(result.rewrite_count, 0);
            assert!(!result.manual_findings.is_empty());
        }
    }

    #[test]
    fn traversal_deadline_and_source_size_limits_refuse_without_partial_plan() {
        assert!(plan("import fs from 'fs';", Instant::now()).is_err());
        let source = " ".repeat(MAX_SOURCE_BYTES + 1);
        assert!(plan(&source, Instant::now() + REWRITE_TIMEOUT).unwrap_err().contains("10 MiB"));
    }

    fn execute(root: &std::path::Path, source: &str) -> Output {
        fs::write(root.join("case.mjs"), source).unwrap();
        Command::new("node").arg("case.mjs").current_dir(root).output().expect("real Node required")
    }

    #[test]
    fn real_node_multiline_static_dynamic_and_reexport_outputs_remain_equal() {
        let root = tempfile::tempdir().unwrap();
        let source = "import {\n basename\n} from 'path';\nexport {\n sep\n} from 'path';\nconst os=await import(\n'os'\n);\nconsole.log(basename('/a/b'), typeof os.platform);\n";
        let before = execute(root.path(), source);
        let rewritten = rewrite_esm(source);
        assert_eq!(rewritten.rewrite_count, 3, "{rewritten:?}");
        let after = execute(root.path(), &rewritten.rewritten_content);
        assert!(before.status.success(), "{:?}", before.stderr);
        assert!(after.status.success(), "{:?}", after.stderr);
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
    }

    #[test]
    fn real_node_preserves_import_text_in_multiline_template_output() {
        let root = tempfile::tempdir().unwrap();
        let source = "import fs from 'fs';\nconsole.log(`literal\nimport path from 'path';\nend`,typeof fs.readFile);";
        let before = execute(root.path(), source);
        let rewritten = rewrite_esm(source);
        assert_eq!(rewritten.rewrite_count, 1);
        let after = execute(root.path(), &rewritten.rewritten_content);
        assert!(before.status.success() && after.status.success());
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
    }

    #[test]
    fn real_node_still_resolves_user_package_with_builtin_named_subpath() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("node_modules/fs")).unwrap();
        fs::write(root.path().join("node_modules/fs/package.json"), r#"{"name":"fs","type":"module","exports":{"./custom":"./custom.mjs"}}"#).unwrap();
        fs::write(root.path().join("node_modules/fs/custom.mjs"), "export default 'user-package';").unwrap();
        let source = "import custom from 'fs/custom';import {basename} from 'path';console.log(custom,basename('/a/b'));";
        let rewritten = rewrite_esm(source);
        assert_eq!(rewritten.rewrite_count, 1);
        let before = execute(root.path(), source);
        let after = execute(root.path(), &rewritten.rewritten_content);
        assert!(before.status.success(), "{:?}", before.stderr);
        assert!(after.status.success(), "{:?}", after.stderr);
        assert_eq!(before.stdout, after.stdout);
        assert_eq!(before.stderr, after.stderr);
    }
}
