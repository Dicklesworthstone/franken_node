//! Bounded import attribute capture, independent of the optional engine crate.
//!
//! The pinned tree-sitter grammars accept import attributes but not reexport
//! attributes. Only a validated, literal reexport clause may be replaced with
//! equal-length whitespace for parsing. Original bytes, locations and pins
//! remain authoritative, and the resulting source must parse without errors.

use super::{Budget, ImportAttributes, MAX_AST_NODES, Result, error, limit};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::{Node, Parser, Tree};

const MAX_ATTRIBUTES: usize = 16;
const MAX_KEY_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_TOTAL_BYTES: usize = 4096;
const MAX_CLAUSE_BYTES: usize = 64 * 1024;

pub(super) struct ReexportAttributes {
    pub attributes: ImportAttributes,
    pub end_byte: usize,
}

pub(super) fn validate(attributes: &ImportAttributes) -> Result<()> {
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(invalid());
    }
    let mut total = 0_usize;
    for (key, value) in attributes {
        total = total
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(invalid)?;
        if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES || total > MAX_TOTAL_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}

fn invalid() -> super::ResolutionError {
    error(
        "ERR_MODULE_GRAPH_IMPORT_ATTRIBUTES",
        "static import attributes require bounded unique identifier or string keys and string literal values",
    )
}

fn charge(budget: &mut Budget) -> Result<()> {
    budget.ast_nodes = budget.ast_nodes.checked_add(1).ok_or_else(limit)?;
    if budget.ast_nodes > MAX_AST_NODES {
        return Err(limit());
    }
    Ok(())
}

pub(super) fn capture(
    node: Node<'_>,
    source: &str,
    budget: &mut Budget,
) -> Result<ImportAttributes> {
    let mut cursor = node.walk();
    let mut clauses = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "import_attribute");
    let Some(clause) = clauses.next() else {
        return Ok(ImportAttributes::new());
    };
    if clauses.next().is_some() || clause.end_byte() - clause.start_byte() > MAX_CLAUSE_BYTES {
        return Err(invalid());
    }
    let mut cursor = clause.walk();
    let mut children = clause
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    let object = children.next().ok_or_else(invalid)?;
    if object.kind() != "object" || children.next().is_some() {
        return Err(invalid());
    }
    capture_object(object, source, budget, false)
}

/// Capture only fresh literal option/attribute objects. The engine evaluates
/// the original call and supplies the resulting attributes on every load;
/// capture does not evaluate getters, follow aliases or grant an untyped route.
/// Unknown options and prototype setters remain explicit analysis gaps.
pub(super) fn capture_dynamic(
    node: Node<'_>,
    source: &str,
    budget: &mut Budget,
) -> Result<ImportAttributes> {
    let arguments = node.child_by_field_name("arguments").ok_or_else(invalid)?;
    let mut cursor = arguments.walk();
    let mut arguments = arguments
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    arguments.next().ok_or_else(invalid)?;
    let Some(options) = arguments.next() else {
        return Ok(ImportAttributes::new());
    };
    if arguments.next().is_some() || options.end_byte() - options.start_byte() > MAX_CLAUSE_BYTES {
        return Err(invalid());
    }
    let options = super::runtime_operand(options);
    if options.kind() != "object" {
        return Err(invalid());
    }
    let mut cursor = options.walk();
    let mut properties = options
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    let Some(property) = properties.next() else {
        return Ok(ImportAttributes::new());
    };
    charge(budget)?;
    // An own data property shadows a polluted Object.prototype.with. Reject
    // spreads, accessors, duplicate with keys and every computed origin.
    if properties.next().is_some() || property.kind() != "pair" {
        return Err(invalid());
    }
    let key = property.child_by_field_name("key").ok_or_else(invalid)?;
    let value = property.child_by_field_name("value").ok_or_else(invalid)?;
    if property_key(key, source)? != "with" {
        return Err(invalid());
    }
    capture_object(super::runtime_operand(value), source, budget, true)
}

fn property_key(key: Node<'_>, source: &str) -> Result<String> {
    match key.kind() {
        "string" => super::literal(key, source).ok_or_else(invalid),
        "property_identifier" => {
            let mut units = Vec::new();
            super::append_string_segment(
                &source[key.byte_range()],
                false,
                &mut units,
                &mut super::StringExpressionBudget::default(),
            )
            .ok_or_else(invalid)?;
            String::from_utf16(&units).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}

fn capture_object(
    object: Node<'_>,
    source: &str,
    budget: &mut Budget,
    dynamic: bool,
) -> Result<ImportAttributes> {
    if object.kind() != "object" || object.end_byte() - object.start_byte() > MAX_CLAUSE_BYTES {
        return Err(invalid());
    }
    let mut attributes = ImportAttributes::new();
    let mut cursor = object.walk();
    for property in object
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
    {
        charge(budget)?;
        if property.kind() != "pair" {
            return Err(invalid());
        }
        let key = property.child_by_field_name("key").ok_or_else(invalid)?;
        let value = property.child_by_field_name("value").ok_or_else(invalid)?;
        let key = property_key(key, source)?;
        // Unlike static attributes, an object-literal __proto__ pair is a
        // prototype setter, not an enumerable own attribute. Never relabel it.
        if dynamic && key == "__proto__" {
            return Err(invalid());
        }
        if value.kind() != "string" {
            return Err(invalid());
        }
        let value = super::literal(value, source).ok_or_else(invalid)?;
        if attributes.insert(key, value).is_some() {
            return Err(invalid());
        }
        validate(&attributes)?;
    }
    Ok(attributes)
}

/// Recover only clauses that become the source of a real export declaration
/// after reparsing. Error-recovery strings in expressions cannot borrow this
/// grammar bridge. Every extra syntax walk is charged to the graph's budget.
pub(super) fn recover_reexports(
    parser: &mut Parser,
    original: &Tree,
    source: &str,
    budget: &mut Budget,
) -> Result<Option<(Tree, BTreeMap<usize, ReexportAttributes>)>> {
    let mut spans = Vec::new();
    let mut clauses = BTreeMap::new();
    let mut clause_parser = Parser::new();
    clause_parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|e| error("ERR_MODULE_GRAPH_PARSER", e.to_string()))?;
    let mut cursor = original.walk();
    loop {
        charge(budget)?;
        let node = cursor.node();
        if node.kind() == "string"
            && !node
                .parent()
                .is_some_and(|parent| parent.kind() == "import_statement")
            && let Some(start) = skip_trivia(source, node.end_byte())
            && source[start..].starts_with("with")
            && let Some(open) = skip_trivia(source, start + 4)
            && source.as_bytes().get(open) == Some(&b'{')
        {
            let end = clause_end(source, open).ok_or_else(invalid)?;
            if end - start > MAX_CLAUSE_BYTES {
                return Err(invalid());
            }
            let fragment = format!("import '__attributes__' {} ;", &source[start..end]);
            let parsed = clause_parser.parse(&fragment, None).ok_or_else(|| {
                error(
                    "ERR_MODULE_GRAPH_PARSER",
                    "attribute parser returned no tree",
                )
            })?;
            if parsed.root_node().has_error() {
                return Err(invalid());
            }
            let statement = parsed.root_node().named_child(0).ok_or_else(invalid)?;
            if statement.kind() != "import_statement" {
                return Err(invalid());
            }
            let attributes = capture(statement, &fragment, budget)?;
            spans.push((start, end));
            clauses.insert(
                node.start_byte(),
                ReexportAttributes {
                    attributes,
                    end_byte: end,
                },
            );
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                if clauses.is_empty() {
                    return Ok(None);
                }
                let mut masked = source.as_bytes().to_vec();
                for (start, end) in spans {
                    for byte in &mut masked[start..end] {
                        if !matches!(*byte, b'\r' | b'\n') {
                            *byte = b' ';
                        }
                    }
                }
                let tree = parser
                    .parse(&masked, None)
                    .ok_or_else(|| error("ERR_MODULE_GRAPH_PARSER", "parser returned no tree"))?;
                if tree.root_node().has_error() {
                    return Ok(None);
                }
                let mut accepted = BTreeSet::new();
                let mut walk = tree.walk();
                loop {
                    charge(budget)?;
                    let statement = walk.node();
                    if statement.kind() == "export_statement"
                        && let Some(source) = statement.child_by_field_name("source")
                        && clauses.contains_key(&source.start_byte())
                    {
                        accepted.insert(source.start_byte());
                    }
                    if walk.goto_first_child() {
                        continue;
                    }
                    loop {
                        if walk.goto_next_sibling() {
                            break;
                        }
                        if !walk.goto_parent() {
                            if accepted.len() != clauses.len() {
                                return Ok(None);
                            }
                            drop(walk);
                            return Ok(Some((tree, clauses)));
                        }
                    }
                }
            }
        }
    }
}

fn whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn skip_trivia(source: &str, mut offset: usize) -> Option<usize> {
    loop {
        let tail = source.get(offset..)?;
        if tail.starts_with("//") {
            offset += tail.find(['\n', '\r', '\u{2028}', '\u{2029}'])?;
        } else if let Some(comment) = tail.strip_prefix("/*") {
            offset += 2 + comment.find("*/")? + 2;
        } else if let Some(c) = tail.chars().next().filter(|c| whitespace(*c)) {
            offset += c.len_utf8();
        } else {
            return Some(offset);
        }
    }
}

fn clause_end(source: &str, start: usize) -> Option<usize> {
    let mut offset = start;
    let mut depth = 0_usize;
    let mut quote = None;
    let mut escaped = false;
    while let Some(&byte) = source.as_bytes().get(offset) {
        if offset - start > MAX_CLAUSE_BYTES {
            return None;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
        } else if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'/' && matches!(source.as_bytes().get(offset + 1), Some(b'/' | b'*')) {
            offset = skip_trivia(source, offset)?;
            continue;
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(offset + 1);
            }
        }
        offset += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::{LoadKind, SourceLanguage, scan};
    use super::*;

    fn scanned(source: &str) -> super::super::Scan {
        scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap()
    }

    #[test]
    fn static_imports_preserve_decoded_attributes_without_evaluating_values() {
        for head in [
            "import data from",
            "import * as data from",
            "import",
            "import {default as data} from",
        ] {
            let source = format!(
                r#"{head} './data.json' with {{ t\u0079pe: 'j\u0073on', 'extra': 'a,b:c from x', }};"#
            );
            let (loads, notices, analyzed) = scanned(&source);
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 1);
            assert_eq!(loads[0].kind, LoadKind::StaticImport);
            assert_eq!(
                loads[0].import_attributes,
                ImportAttributes::from([
                    ("extra".into(), "a,b:c from x".into()),
                    ("type".into(), "json".into()),
                ])
            );
        }
    }

    #[test]
    fn reexport_bridge_preserves_original_spans_and_attributes_in_mixed_sources() {
        for head in [
            "export {default as data} from",
            "export * from",
            "export * as data from",
        ] {
            let declaration =
                format!("{head} './data.json' /* origin */ with {{ type: 'json', }};");
            let source = format!(
                "import './other.json' with {{type:'json'}};\n{declaration}\nconsole.log('unchanged');"
            );
            let (loads, notices, analyzed) = scanned(&source);
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 2);
            assert_eq!(loads[1].kind, LoadKind::Reexport);
            assert_eq!(loads[1].site.line, 2);
            assert_eq!(
                &source[loads[1].site.start_byte..loads[1].site.end_byte],
                declaration
            );
            assert_eq!(loads[0].import_attributes, loads[1].import_attributes);
            assert_eq!(
                loads[1].import_attributes.get("type").map(String::as_str),
                Some("json")
            );
        }
        let source = "export {default as first} from './a.json' with {type:'json'}\nexport {default as second} from './b.json' with {type:'json'}";
        let (loads, notices, analyzed) = scanned(source);
        assert!(analyzed && notices.is_empty(), "{notices:?}");
        assert_eq!(loads.len(), 2);
        assert!(
            source[loads[0].site.start_byte..loads[0].site.end_byte].ends_with("{type:'json'}")
        );
        assert_eq!(loads[1].site.end_byte, source.len());
    }

    #[test]
    fn malformed_or_unrepresentable_clauses_never_become_empty_authority() {
        for attributes in [
            "{type:'json',type:'json'}",
            r#"{type:'json','t\u0079pe':'json'}"#,
            "{type:42}",
            "{type:kind}",
            "{type:'j'+'son'}",
            "{type:`json`}",
            "{['type']:'json'}",
            "{...other}",
            "{get type(){return 'json'}}",
            "{type}",
            r#"{type:'\ud800'}"#,
            "{type(){}}",
            "{type='json'}",
        ] {
            for head in ["import data from", "export {default} from"] {
                let source = format!("{head} './data.json' with {attributes};");
                let (_, notices, analyzed) = scanned(&source);
                assert!(!analyzed || !notices.is_empty(), "accepted {source}");
            }
        }
        for source in [
            "'./data.json' with {type:'json'};",
            "const value='./data.json' with {type:'json'};",
            "export {default} from './data.json' with {type:'json'}; const = ;",
        ] {
            let (_, notices, analyzed) = scanned(source);
            assert!(!analyzed && !notices.is_empty(), "accepted {source}");
        }
    }

    #[test]
    fn attribute_limits_and_masked_syntax_work_remain_bounded() {
        let pairs = (0..17)
            .map(|n| format!("key{n}:'value'"))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!("import './data.json' with {{{pairs}}};");
        assert!(!scanned(&source).1.is_empty());
        let source = "export {default} from './data.json' with {type:'json'};";
        let mut budget = Budget {
            ast_nodes: MAX_AST_NODES - 1,
            ..Budget::default()
        };
        assert_eq!(
            scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut budget
            )
            .unwrap_err()
            .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
    }

    #[test]
    fn dynamic_literal_attributes_preserve_decoded_keys_and_exact_load_routes() {
        for options in [
            "{with:{type:'json'}}",
            "({ /* before */ with: ({type:'json',}) })",
            r#"{'w\u0069th':{t\u0079pe:'j\u0073on'}}"#,
        ] {
            let source = format!("import('./data.json', {options});");
            let (loads, notices, analyzed) = scanned(&source);
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 1);
            assert_eq!(loads[0].kind, LoadKind::DynamicImport);
            assert_eq!(loads[0].specifier.as_deref(), Some("./data.json"));
            assert_eq!(
                loads[0].import_attributes,
                ImportAttributes::from([("type".into(), "json".into())])
            );
            assert_eq!(
                &source[loads[0].site.start_byte..loads[0].site.end_byte],
                source.trim_end_matches(';')
            );
        }
        for source in [
            "import('./plain.mjs');",
            "import('./plain.mjs', {});",
            "import('./plain.mjs', {with:{}});",
        ] {
            let (loads, notices, analyzed) = scanned(source);
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            assert!(loads[0].import_attributes.is_empty());
        }
    }

    #[test]
    fn dynamic_attribute_objects_cannot_borrow_computed_mutable_or_prototype_authority() {
        for options in [
            "options",
            "undefined",
            "null",
            "{with: attributes}",
            "{with: {type: kind}}",
            "{with: {type: 'j'+'son'}}",
            "{with: {type: `json`}}",
            "{with: {type: 42}}",
            "{with: {type: 'json', type: 'text'}}",
            r#"{with: {type:'json', 't\u0079pe':'json'}}"#,
            "{with: {['type']: 'json'}}",
            "{with: {get type(){ return 'json'; }}}",
            "{get with(){ return {type:'json'}; }}",
            "{['with']: {type:'json'}}",
            "{with: {type:'json'}, with: {type:'text'}}",
            "{with: {type:'json'}, ...options}",
            "{with: {type:'json', ...attributes}}",
            "{__proto__: {with:{type:'json'}}}",
            "{with: {__proto__: 'json'}}",
            r#"{with: {'__pr\u006fto__': 'json'}}"#,
            "{with: {type:'json'}, ignored: effect()}",
            "{assert: {type:'json'}}",
            r#"{with: {type:'\ud800'}}"#,
        ] {
            let source = format!("import('./data.json', {options});");
            let (loads, notices, _) = scanned(&source);
            assert_eq!(loads.len(), 1, "{source}");
            assert!(loads[0].import_attributes.is_empty(), "{source}");
            assert!(
                notices
                    .iter()
                    .any(|notice| notice.code == "DYNAMIC_IMPORT_ATTRIBUTES_UNSUPPORTED"),
                "accepted {source}"
            );
        }
    }

    #[test]
    fn dynamic_attribute_capture_preserves_unknown_keys_and_enforces_shared_limits() {
        let (loads, notices, _) = scanned("import('./data.json', {with:{unknown:'value'}});");
        assert!(notices.is_empty());
        assert_eq!(
            loads[0].import_attributes,
            ImportAttributes::from([("unknown".into(), "value".into())])
        );
        for attributes in [
            (0..17)
                .map(|n| format!("key{n}:'value'"))
                .collect::<Vec<_>>()
                .join(","),
            format!("'{}':'value'", "k".repeat(MAX_KEY_BYTES + 1)),
            format!("type:'{}'", "v".repeat(MAX_VALUE_BYTES + 1)),
            (0..5)
                .map(|n| format!("key{n}:'{}'", "v".repeat(1000)))
                .collect::<Vec<_>>()
                .join(","),
        ] {
            let source = format!("import('./data.json', {{with:{{{attributes}}}}});");
            let (loads, notices, _) = scanned(&source);
            assert!(loads[0].import_attributes.is_empty());
            assert!(
                notices
                    .iter()
                    .any(|n| n.code == "DYNAMIC_IMPORT_ATTRIBUTES_UNSUPPORTED")
            );
        }
        let source = "import('./data.json', {with:{type:'json'}});";
        let mut budget = Budget {
            ast_nodes: MAX_AST_NODES - 2,
            ..Budget::default()
        };
        assert_eq!(
            scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut budget
            )
            .unwrap_err()
            .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
    }
}
