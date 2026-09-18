//! Complete-program parsing for migration specifier edits.
//!
//! JavaScript remains the first grammar. A completed syntax rejection can be
//! retried as TypeScript and then TSX; cancellation never triggers another
//! grammar with a fresh allowance. No type erasure, source preprocessing or
//! recovery-tree rewriting is permitted. Parsing establishes syntax, not type
//! correctness or behavioral equivalence.

use std::ops::ControlFlow;
use std::time::Instant;
use tree_sitter::{Language, ParseOptions, Parser, Tree};

const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;

pub(super) fn parse(source: &str, deadline: Instant) -> Result<Tree, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err("migration syntax source exceeds the 10 MiB limit".into());
    }
    // One deadline for the entire operation, including all grammar attempts.
    let languages: [(&str, Language); 3] = [
        ("JavaScript/JSX", tree_sitter_javascript::LANGUAGE.into()),
        ("TypeScript", tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        ("TSX", tree_sitter_typescript::LANGUAGE_TSX.into()),
    ];
    let mut parser = Parser::new();
    for (name, language) in languages {
        if Instant::now() >= deadline {
            return Err("migration syntax parsing budget exhausted".into());
        }
        parser.reset();
        parser.set_language(&language)
            .map_err(|error| format!("{name} migration parser unavailable: {error}"))?;
        let bytes = source.as_bytes();
        let mut input = |offset: usize, _| bytes.get(offset..).unwrap_or_default();
        let mut progress = |_: &tree_sitter::ParseState| {
            if Instant::now() >= deadline { ControlFlow::Break(()) }
            else { ControlFlow::Continue(()) }
        };
        let tree = parser.parse_with_options(&mut input, None,
            Some(ParseOptions::new().progress_callback(&mut progress)))
            .ok_or_else(|| "migration syntax parsing budget exhausted".to_owned())?;
        if Instant::now() >= deadline {
            return Err("migration syntax parsing budget exhausted".into());
        }
        if !tree.root_node().has_error() {
            return Ok(tree);
        }
    }
    Err("JavaScript, TypeScript and TSX parsers rejected source; no partial source rewrite applied".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(5) }

    #[test]
    fn complete_typed_programs_parse_without_erasing_source_bytes() {
        for source in [
            "import type {Stats} from 'fs'; interface Input {path:string}; const n: number = 42;",
            "type Result<T> = T extends string ? T[] : never; const f = <T>(x:T):T => x;",
            "import {sep} from 'path'; type Props={name:string}; const el=<span title='fs'>{sep}</span>;",
            "const n = <number>42; namespace Local { export interface Shape {value:number} }",
            "import fs = require('fs'); export = fs;",
        ] {
            let tree = parse(source, deadline()).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            assert_eq!(tree.root_node().end_byte(), source.len());
        }
    }

    #[test]
    fn recovery_trees_are_never_returned_as_successful_parses() {
        for source in ["import fs from 'fs';const n = ;", "interface X { value: }", "const el=<div>"] {
            assert!(parse(source, deadline()).is_err(), "{source}");
        }
    }

    #[test]
    fn expired_and_oversized_inputs_are_refused_before_grammar_fallback() {
        assert!(parse("const n: number=42;", Instant::now()).unwrap_err().contains("budget"));
        assert!(parse(&" ".repeat(MAX_SOURCE_BYTES + 1), deadline()).unwrap_err().contains("10 MiB"));
    }

    #[test]
    fn javascript_tree_and_byte_coordinates_remain_unchanged() {
        let source = "#!/usr/bin/env node\r\n// π\r\nimport fs from 'fs';const view=<span>fs</span>;";
        let mut original = Parser::new();
        original.set_language(&tree_sitter_javascript::LANGUAGE.into()).unwrap();
        let expected = original.parse(source, None).unwrap();
        let actual = parse(source, deadline()).unwrap();
        assert_eq!(actual.root_node().to_sexp(), expected.root_node().to_sexp());
        assert_eq!(actual.root_node().byte_range(), expected.root_node().byte_range());
    }
}
