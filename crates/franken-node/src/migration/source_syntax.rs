//! Complete-program parsing for migration specifier edits.
//!
//! The caller selects a grammar from the source extension. A syntax failure
//! must never reinterpret JavaScript as TypeScript or a TSX assertion as JSX.
//! No type erasure, preprocessing or recovery-tree rewriting is permitted.
//! Parsing establishes syntax, not type correctness or behavioral equivalence.

use std::ops::ControlFlow;
use std::time::Instant;
use tree_sitter::{Language, ParseOptions, Parser, Tree};

const MAX_SOURCE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Syntax { JavaScript, TypeScript, Tsx }

impl Syntax {
    fn language(self) -> Language {
        match self {
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::JavaScript => "JavaScript/JSX",
            Self::TypeScript => "TypeScript",
            Self::Tsx => "TSX",
        }
    }
}

pub(super) fn parse(source: &str, syntax: Syntax, deadline: Instant) -> Result<Tree, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err("migration syntax source exceeds the 10 MiB limit".into());
    }
    if Instant::now() >= deadline {
        return Err("migration syntax parsing budget exhausted".into());
    }
    let mut parser = Parser::new();
    parser.set_language(&syntax.language())
        .map_err(|error| format!("{} migration parser unavailable: {error}", syntax.name()))?;
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
    if tree.root_node().has_error() {
        return Err(format!("{} parser rejected source; no partial source rewrite applied", syntax.name()));
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(5) }

    #[test]
    fn complete_typed_programs_parse_without_erasing_source_bytes() {
        for (syntax, source) in [
            (Syntax::TypeScript, "import type {Stats} from 'fs'; interface Input {path:string}; const n: number = 42;"),
            (Syntax::TypeScript, "type Result<T> = T extends string ? T[] : never; const f = <T>(x:T):T => x;"),
            (Syntax::Tsx, "import {sep} from 'path'; type Props={name:string}; const el=<span title='fs'>{sep}</span>;"),
            (Syntax::TypeScript, "const n = <number>42; namespace Local { export interface Shape {value:number} }"),
            (Syntax::TypeScript, "import fs = require('fs'); export = fs;"),
        ] {
            let tree = parse(source, syntax, deadline()).unwrap();
            assert!(!tree.root_node().has_error(), "{source}");
            assert_eq!(tree.root_node().end_byte(), source.len());
        }
    }

    #[test]
    fn recovery_trees_are_never_returned_as_successful_parses() {
        for syntax in [Syntax::JavaScript, Syntax::TypeScript, Syntax::Tsx] {
            for source in ["import fs from 'fs';const n = ;", "interface X { value: }", "const el=<div>"] {
                assert!(parse(source, syntax, deadline()).is_err(), "{source}");
            }
        }
    }

    #[test]
    fn expired_and_oversized_inputs_are_refused_before_parsing() {
        for syntax in [Syntax::JavaScript, Syntax::TypeScript, Syntax::Tsx] {
            assert!(parse("const n: number=42;", syntax, Instant::now()).unwrap_err().contains("budget"));
            assert!(parse(&" ".repeat(MAX_SOURCE_BYTES + 1), syntax, deadline()).unwrap_err().contains("10 MiB"));
        }
    }

    #[test]
    fn javascript_tree_and_byte_coordinates_remain_unchanged() {
        let source = "#!/usr/bin/env node\r\n// π\r\nimport fs from 'fs';const view=<span>fs</span>;";
        let mut original = Parser::new();
        original.set_language(&tree_sitter_javascript::LANGUAGE.into()).unwrap();
        let expected = original.parse(source, None).unwrap();
        let actual = parse(source, Syntax::JavaScript, deadline()).unwrap();
        assert_eq!(actual.root_node().to_sexp(), expected.root_node().to_sexp());
        assert_eq!(actual.root_node().byte_range(), expected.root_node().byte_range());
    }

    #[test]
    fn grammar_failures_never_switch_dialects() {
        let typed = "import fs from 'fs';const n:number=42;";
        assert!(parse(typed, Syntax::JavaScript, deadline()).is_err());
        assert!(parse(typed, Syntax::TypeScript, deadline()).is_ok());
        let assertion = "const n = <number>42;";
        assert!(parse(assertion, Syntax::TypeScript, deadline()).is_ok());
        assert!(parse(assertion, Syntax::Tsx, deadline()).is_err());
        let jsx = "const node=<div/>;";
        assert!(parse(jsx, Syntax::TypeScript, deadline()).is_err());
        assert!(parse(jsx, Syntax::Tsx, deadline()).is_ok());
    }
}
