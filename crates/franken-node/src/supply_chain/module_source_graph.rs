//! Entrypoint-wide capture of static and literal JavaScript/TypeScript requests.
//!
//! One resolver owns every source, manifest, link and negative probe for the
//! whole graph. This is a conservative source graph, not execution or proof of
//! all runtime dependencies: literal deferred loads are included even in dead
//! branches; computed/indirect loaders and unsupported syntax stay explicit.
//! TypeScript follows explicit runtime syntax, not tsconfig-dependent emit.
//! Whole-declaration type imports and import types are recorded but never read;
//! inline type specifiers retain their declaration's side-effect dependency.
//! Spec: https://www.typescriptlang.org/tsconfig/verbatimModuleSyntax.html

use super::{Entry, Mapping, Probe, ResolutionError, ResolutionMode, Resolver,
    SymlinkPolicy, error, io_error, parent, validate_path};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::rc::Rc;
use tree_sitter::{Node, Parser};

const MAX_MODULES: usize = 256;
const MAX_SITES: usize = 4096;
const MAX_AST_NODES: usize = 262_144;
const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
const HASH_DOMAIN: &[u8] = b"franken-node/module-source-graph/v2\0";
type Result<T> = std::result::Result<T, ResolutionError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ModuleId {
    pub path: String,
    pub url_suffix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSite {
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub column: usize,
}

impl SourceSite {
    fn of(node: Node<'_>) -> Self {
        Self { start_byte: node.start_byte(), end_byte: node.end_byte(),
            line: node.start_position().row + 1, column: node.start_position().column + 1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadKind { StaticImport, Reexport, Require, DynamicImport }

impl LoadKind {
    fn mode(self) -> ResolutionMode {
        if self == Self::Require { ResolutionMode::Require } else { ResolutionMode::Import }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState { Resolved, Unresolved, RuntimeRequired, NonLiteral, TypeOnly }

/// Source grammar is independent of the resolver's runtime format hint.
/// Recognizing TypeScript is not a claim that the engine can execute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage { JavaScript, TypeScript, Tsx, Declaration, Json, Unsupported }

impl SourceLanguage {
    fn for_module(path: &str, format: &str) -> Self {
        if [".d.ts", ".d.mts", ".d.cts"].iter().any(|suffix| path.ends_with(suffix)) {
            return Self::Declaration;
        }
        match Path::new(path).extension().and_then(|e| e.to_str()) {
            Some("ts" | "mts" | "cts") => Self::TypeScript,
            Some("tsx") => Self::Tsx,
            _ if format == "json" => Self::Json,
            _ if matches!(format, "module" | "commonjs" | "javascript_unspecified") => Self::JavaScript,
            _ => Self::Unsupported,
        }
    }
    fn is_typescript(self) -> bool { matches!(self, Self::TypeScript | Self::Tsx) }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceEdge {
    pub importer: ModuleId,
    pub site: SourceSite,
    pub kind: LoadKind,
    /// Potential loads only; the scanner does not evaluate control flow.
    pub deferred_or_conditional: bool,
    pub specifier: Option<String>,
    pub conditions: Vec<String>,
    pub state: EdgeState,
    pub target: Option<ModuleId>,
    pub error: Option<ResolutionError>,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceModule {
    pub id: ModuleId,
    pub content_sha256: String,
    pub content_bytes: usize,
    pub format_hint: String,
    pub source_language: SourceLanguage,
    pub analyzed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceDiagnostic {
    pub module: ModuleId,
    pub site: Option<SourceSite>,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphOptions {
    pub symlink_policy: SymlinkPolicy,
    /// None uses node+import or node+require per load site. Some replaces the
    /// complete active condition set for every edge, including an empty set.
    pub conditions: Option<Vec<String>>,
}

impl Default for GraphOptions {
    fn default() -> Self { Self { symlink_policy: SymlinkPolicy::Reject, conditions: None } }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceGraphReport {
    pub schema_version: String,
    pub scope: String,
    pub entrypoint: String,
    pub resolved_entrypoint: ModuleId,
    pub options: GraphOptions,
    pub modules: Vec<SourceModule>,
    pub edges: Vec<SourceEdge>,
    pub diagnostics: Vec<SourceDiagnostic>,
    pub probes: Vec<Probe>,
    pub input_hash: String,
    /// True only for this scanner's declared static/literal-site scope.
    pub fully_resolved: bool,
    pub runtime_completeness: bool,
    /// Erased references are inventoried, not resolved or type-checked.
    pub type_resolution_performed: bool,
    pub execution_performed: bool,
    pub release_certification: bool,
}

/// No Debug/Serialize on the owner: private source bytes are not report data.
/// The report is read-only, so a consumer cannot relabel an incomplete capture.
pub struct CapturedModuleGraph {
    report: SourceGraphReport,
    sources: BTreeMap<ModuleId, Rc<Entry>>,
}

impl CapturedModuleGraph {
    pub fn report(&self) -> &SourceGraphReport { &self.report }
    pub fn source_bytes(&self, module: &ModuleId) -> Option<&[u8]> {
        match self.sources.get(module)?.as_ref() {
            Entry::File { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Budget { sites: usize, ast_nodes: usize, evidence_bytes: usize }

fn limit() -> ResolutionError {
    error("ERR_MODULE_GRAPH_LIMIT", "source graph exceeds its module, syntax, site or evidence bound")
}

impl Budget {
    fn site(&mut self) -> Result<()> {
        self.sites += 1;
        if self.sites > MAX_SITES { return Err(limit()); }
        Ok(())
    }
    fn retain(&mut self, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|e| io_error("<source graph>", e))?;
        self.evidence_bytes = self.evidence_bytes.checked_add(bytes.len()).ok_or_else(limit)?;
        if self.evidence_bytes > MAX_EVIDENCE_BYTES { return Err(limit()); }
        Ok(())
    }
}

/// Capture one entrypoint and its supported literal dependency closure without
/// evaluating project code. Safety/resource failures return no successful graph;
/// missing imports, runtime modules and unanalyzable code remain in the report.
pub fn capture(project: &Path, entrypoint: &str, mut options: GraphOptions) -> Result<CapturedModuleGraph> {
    validate_path(entrypoint)?;
    let resolver = Resolver::new(project, options.conditions.as_deref().unwrap_or(&[]), options.symlink_policy)?;
    if options.conditions.is_some() { options.conditions = Some(resolver.conditions.clone()); }
    build(resolver, entrypoint, options)
}

fn build(mut resolver: Resolver, entrypoint: &str, options: GraphOptions) -> Result<CapturedModuleGraph> {
    let (path, entry) = resolver.locate(entrypoint)?;
    if !entry.is_file() { return Err(ResolutionMode::Import.missing(entrypoint)); }
    let first = ModuleId { path, url_suffix: String::new() };
    let mut sources = BTreeMap::from([(first.clone(), entry)]);
    let mut pending = VecDeque::from([first.clone()]);
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    let mut diagnostics = Vec::new();
    let mut budget = Budget::default();
    let mut parser = Parser::new();

    while let Some(id) = pending.pop_front() {
        let source = Rc::clone(sources.get(&id).expect("queued source is captured"));
        let Entry::File { bytes, sha256 } = source.as_ref() else { unreachable!("ordinary source") };
        let format_hint = resolver.format(&id.path)?;
        let source_language = SourceLanguage::for_module(&id.path, &format_hint);
        let (loads, notices, analyzed) = scan(&mut parser, bytes, source_language, &mut budget)?;
        let module = SourceModule { id: id.clone(), content_sha256: sha256.clone(),
            content_bytes: bytes.len(), format_hint, source_language, analyzed };
        budget.retain(&module)?;
        modules.push(module);
        for notice in notices {
            let diagnostic = SourceDiagnostic { module: id.clone(), site: notice.site,
                code: notice.code, message: notice.message.into() };
            budget.retain(&diagnostic)?;
            diagnostics.push(diagnostic);
        }
        for load in loads {
            let mode = load.kind.mode();
            let conditions = if load.type_only { Vec::new() }
                else { options.conditions.clone().unwrap_or_else(|| mode.default_conditions()) };
            resolver.conditions = conditions.clone();
            resolver.mappings.clear();
            let mut edge = SourceEdge { importer: id.clone(), site: load.site, kind: load.kind,
                deferred_or_conditional: !load.type_only && matches!(load.kind, LoadKind::Require | LoadKind::DynamicImport),
                specifier: load.specifier, conditions,
                state: if load.type_only { EdgeState::TypeOnly } else { EdgeState::NonLiteral },
                target: None, error: None, mappings: Vec::new() };
            // Type-only references grant no filesystem authority. In particular,
            // an erased outside-root path or runtime name must not be resolved.
            if let Some(request) = edge.specifier.as_ref().filter(|_| !load.type_only) {
                match resolver.request(parent(&id.path), request, mode, 0) {
                    Ok((path, url_suffix)) => {
                        let (path, source) = resolver.locate(&path)?;
                        if !source.is_file() { return Err(mode.missing(&path)); }
                        let target = ModuleId { path, url_suffix };
                        if !sources.contains_key(&target) {
                            if sources.len() >= MAX_MODULES { return Err(limit()); }
                            sources.insert(target.clone(), source);
                            pending.push_back(target.clone());
                        }
                        edge.state = EdgeState::Resolved;
                        edge.target = Some(target);
                    }
                    Err(e) if fatal(&e) => return Err(e),
                    Err(e) => {
                        edge.state = if e.code == "ERR_RUNTIME_MODULE_REQUIRED" { EdgeState::RuntimeRequired }
                            else { EdgeState::Unresolved };
                        edge.error = Some(e);
                    }
                }
            }
            edge.mappings = std::mem::take(&mut resolver.mappings);
            budget.retain(&edge)?;
            edges.push(edge);
        }
    }
    modules.sort_by(|a, b| a.id.cmp(&b.id));
    edges.sort_by(|a, b| (&a.importer, a.site.start_byte).cmp(&(&b.importer, b.site.start_byte)));
    diagnostics.sort_by(|a, b| (&a.module, a.site.as_ref().map(|s| s.start_byte), a.code)
        .cmp(&(&b.module, b.site.as_ref().map(|s| s.start_byte), b.code)));
    let probes = resolver.probes();
    budget.retain(&probes)?;
    let mut report = SourceGraphReport {
        schema_version: "franken-node/module-source-graph/v2".into(),
        scope: "static-and-literal-module-requests".into(), entrypoint: entrypoint.into(),
        resolved_entrypoint: first, options, fully_resolved: diagnostics.is_empty()
            && edges.iter().all(|e| matches!(e.state, EdgeState::Resolved | EdgeState::TypeOnly)),
        modules, edges, diagnostics, probes, input_hash: String::new(),
        runtime_completeness: false, type_resolution_performed: false,
        execution_performed: false, release_certification: false,
    };
    let encoded = serde_json::to_vec(&report).map_err(|e| io_error("<source graph>", e))?;
    if encoded.len() > MAX_EVIDENCE_BYTES { return Err(limit()); }
    let mut hash = Sha256::new(); hash.update(HASH_DOMAIN); hash.update(encoded);
    report.input_hash = format!("sha256:{}", hex::encode(hash.finalize()));
    Ok(CapturedModuleGraph { report, sources })
}

fn fatal(e: &ResolutionError) -> bool {
    matches!(e.code, "ERR_MODULE_CAPTURE" | "ERR_MODULE_INPUT_CHANGED" | "ERR_MODULE_OUTSIDE_PROJECT"
        | "ERR_MODULE_RESOLUTION_LIMIT" | "ERR_MODULE_SYMLINK_LOOP" | "ERR_INVALID_MODULE_SYMLINK"
        | "ERR_UNSUPPORTED_MODULE_FILE" | "ERR_PACKAGE_MAP_LIMIT")
}

struct Load { site: SourceSite, kind: LoadKind, specifier: Option<String>, type_only: bool }
struct Notice { site: Option<SourceSite>, code: &'static str, message: &'static str }
type Scan = (Vec<Load>, Vec<Notice>, bool);

fn scan(parser: &mut Parser, bytes: &[u8], language: SourceLanguage, budget: &mut Budget) -> Result<Scan> {
    let notice = |code, message| Notice { site: None, code, message };
    if language == SourceLanguage::Json {
        return if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
            Ok((Vec::new(), Vec::new(), true))
        } else {
            budget.site()?;
            Ok((Vec::new(), vec![notice("INVALID_JSON_MODULE", "captured JSON module could not be parsed")], false))
        };
    }
    if language == SourceLanguage::Declaration {
        budget.site()?;
        return Ok((Vec::new(), vec![notice("DECLARATION_FILE_NOT_RUNTIME", "a declaration file is not a runtime implementation")], false));
    }
    if language == SourceLanguage::Unsupported {
        budget.site()?;
        return Ok((Vec::new(), vec![notice("UNSUPPORTED_MODULE_FORMAT", "source extraction does not cover this format")], false));
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            budget.site()?;
            return Ok((Vec::new(), vec![notice("NON_UTF8_JAVASCRIPT", "JavaScript source is not UTF-8")], false));
        }
    };
    let grammar = match language {
        SourceLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        SourceLanguage::Tsx => tree_sitter_typescript::LANGUAGE_TSX,
        _ => tree_sitter_javascript::LANGUAGE,
    };
    parser.set_language(&grammar.into()).map_err(|e| error("ERR_MODULE_GRAPH_PARSER", e.to_string()))?;
    let tree = parser.parse(bytes, None).ok_or_else(|| error("ERR_MODULE_GRAPH_PARSER", "parser did not return a tree"))?;
    if tree.root_node().has_error() {
        budget.site()?;
        let code = if language.is_typescript() { "TYPESCRIPT_PARSE_ERROR" } else { "JAVASCRIPT_PARSE_ERROR" };
        return Ok((Vec::new(), vec![notice(code, "source has syntax errors; no dependency completeness asserted")], false));
    }
    let mut loads = Vec::new();
    let mut notices = Vec::new();
    let mut cursor = tree.walk();
    // One inherited bit per cursor depth, not an ancestor scan at every node.
    // All syntax still consumes the global budget, including erased subtrees.
    let mut type_context = vec![false];
    loop {
        budget.ast_nodes += 1;
        if budget.ast_nodes > MAX_AST_NODES { return Err(limit()); }
        let node = cursor.node();
        let erased = language.is_typescript() && (*type_context.last().expect("root context")
            || erased_region(node));
        let mut issue = None;
        let request = match node.kind() {
            "import_statement" => node.child_by_field_name("source").map(|s| (LoadKind::StaticImport, s)),
            "export_statement" => node.child_by_field_name("source").map(|s| (LoadKind::Reexport, s)),
            "import_require_clause" if language.is_typescript() => {
                if !erased {
                    issue = Some(("TYPESCRIPT_TRANSFORM_REQUIRED", "import-equals requires a configured TypeScript transform"));
                }
                node.child_by_field_name("source").map(|s| (LoadKind::Require, s))
            }
            "call_expression" => {
                let kind = node.child_by_field_name("function").and_then(|f| {
                    if f.kind() == "import" { Some(LoadKind::DynamicImport) }
                    else if is_require(f, bytes) { Some(LoadKind::Require) } else { None }
                });
                kind.map(|kind| {
                    let arg = node.child_by_field_name("arguments").and_then(|a| {
                        let mut walk = a.walk();
                        a.named_children(&mut walk).find(|n| n.kind() != "comment")
                    }).unwrap_or(node);
                    (kind, arg)
                })
            }
            "identifier" if !erased => {
                let spelling = node.utf8_text(bytes).unwrap_or("");
                if spelling == "require" && !direct_callee(node) {
                    issue = Some(("INDIRECT_REQUIRE", "require is bound, passed or used indirectly; scope/alias analysis is not implemented"));
                } else if matches!(spelling, "eval" | "Function" | "createRequire") {
                    issue = Some(("DYNAMIC_CODE_OR_LOADER", "dynamic code or loader factory requires runtime analysis"));
                }
                None
            }
            "member_expression" if !erased && is_require(node, bytes) && !direct_callee(node) => {
                issue = Some(("INDIRECT_REQUIRE", "module.require is used indirectly")); None
            }
            "jsx_element" | "jsx_self_closing_element" | "with_statement" if !erased => {
                issue = Some(("UNSUPPORTED_JAVASCRIPT_SURFACE", "JSX or dynamic scope requires a separate analysis")); None
            }
            _ => None,
        };
        if language.is_typescript() && !erased && requires_typescript_transform(node) {
            issue = Some(("TYPESCRIPT_TRANSFORM_REQUIRED", "non-erasable TypeScript or decorators require a configured transform; injected dependencies are not inferred"));
        }
        if let Some((kind, argument)) = request {
            budget.site()?;
            loads.push(Load { site: SourceSite::of(node), kind,
                specifier: literal(argument, text), type_only: erased });
        }
        if let Some((code, message)) = issue {
            budget.site()?;
            notices.push(Notice { site: Some(SourceSite::of(node)), code, message });
        }
        if cursor.goto_first_child() { type_context.push(erased); continue; }
        loop {
            if cursor.goto_next_sibling() { break; }
            if !cursor.goto_parent() { return Ok((loads, notices, true)); }
            type_context.pop();
        }
    }
}

/// Only a direct anonymous keyword is a modifier. A default binding named
/// `type` (import type from './x') is an identifier and remains a runtime load.
fn keyword(node: Node<'_>, word: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|n| !n.is_named() && n.kind() == word)
}

fn erased_region(node: Node<'_>) -> bool {
    match node.kind() {
        "type_alias_declaration" | "interface_declaration" | "type_annotation"
        | "type_arguments" | "type_parameters" | "type_query" | "implements_clause"
        | "ambient_declaration" | "function_signature" | "method_signature"
        | "abstract_method_signature" | "index_signature" => true,
        "import_statement" | "export_statement" | "import_specifier" | "export_specifier" => keyword(node, "type"),
        "public_field_definition" => keyword(node, "declare"),
        _ => node.parent().is_some_and(|p| matches!(p.kind(), "as_expression" | "satisfies_expression")
            && p.named_child(0).is_some_and(|first| first.id() != node.id())),
    }
}

fn requires_typescript_transform(node: Node<'_>) -> bool {
    match node.kind() {
        "enum_declaration" | "internal_module" | "module" | "import_alias" | "decorator" => true,
        "export_statement" => keyword(node, "="),
        "required_parameter" | "optional_parameter" => {
            let mut cursor = node.walk();
            keyword(node, "readonly") || node.named_children(&mut cursor)
                .any(|n| matches!(n.kind(), "accessibility_modifier" | "override_modifier"))
        }
        _ => false,
    }
}

fn direct_callee(node: Node<'_>) -> bool {
    node.parent().is_some_and(|p| p.kind() == "call_expression"
        && p.child_by_field_name("function").is_some_and(|f| f.id() == node.id()))
}

fn is_require(node: Node<'_>, bytes: &[u8]) -> bool {
    (node.kind() == "identifier" && node.utf8_text(bytes) == Ok("require"))
        || (node.kind() == "member_expression"
            && node.child_by_field_name("object").is_some_and(|n| n.utf8_text(bytes) == Ok("module"))
            && node.child_by_field_name("property").is_some_and(|n| n.utf8_text(bytes) == Ok("require")))
}

/// Decode JS literal spelling, never run JavaScript or guess computed strings.
/// UTF-16 accumulation handles surrogate pairs. Legacy octal and lone surrogate
/// escapes remain opaque, rather than selecting the wrong filesystem path.
fn literal(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(node.kind(), "string" | "template_string") { return None; }
    if node.kind() == "template_string" {
        let mut walk = node.walk();
        if node.named_children(&mut walk).any(|n| n.kind() == "template_substitution") { return None; }
    }
    decode_literal(source.get(node.byte_range())?)
}

fn decode_literal(text: &str) -> Option<String> {
    let quote = text.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') || !text.ends_with(quote) || text.len() < 2 { return None; }
    let mut chars = text[1..text.len() - 1].chars().peekable();
    let mut units = Vec::new();
    while let Some(c) = chars.next() {
        let c = if c != '\\' { c } else {
            match chars.next()? {
                '\n' => continue,
                '\r' => { if chars.peek() == Some(&'\n') { chars.next(); } continue; }
                '\u{2028}' | '\u{2029}' => continue,
                'n' => '\n', 'r' => '\r', 't' => '\t', 'b' => '\u{0008}',
                'f' => '\u{000c}', 'v' => '\u{000b}',
                '0' if !chars.peek().is_some_and(char::is_ascii_digit) => '\0',
                '0'..='9' => return None,
                'x' => char::from_u32(read_hex(&mut chars, 2)?)?,
                'u' => {
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        let mut value = 0_u32; let mut count = 0;
                        loop {
                            let c = chars.next()?;
                            if c == '}' { break; }
                            count += 1; if count > 6 { return None; }
                            value = value.checked_mul(16)?.checked_add(c.to_digit(16)?)?;
                        }
                        if count == 0 { return None; }
                        char::from_u32(value)?
                    } else {
                        units.push(read_hex(&mut chars, 4)? as u16);
                        continue;
                    }
                }
                escaped => escaped,
            }
        };
        units.extend(c.encode_utf16(&mut [0_u16; 2]).iter().copied());
    }
    let result = String::from_utf16(&units).ok()?;
    if result.len() > super::MAX_PATH { return None; }
    Some(result)
}

fn read_hex(chars: &mut impl Iterator<Item = char>, count: usize) -> Option<u32> {
    let mut value = 0;
    for _ in 0..count { value = value * 16 + chars.next()?.to_digit(16)?; }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(root: &Path, path: &str, text: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    fn graph(root: &Path) -> CapturedModuleGraph { capture(root, "app.mjs", GraphOptions::default()).unwrap() }
    fn paths(g: &CapturedModuleGraph) -> Vec<&str> { g.report.modules.iter().map(|n| n.id.path.as_str()).collect() }

    #[test]
    fn static_import_reexport_cycles_and_diamonds_capture_each_identity_once() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './a.mjs'; export * from './b.mjs';");
        put(root.path(), "a.mjs", "export {x} from './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs'; export const x=1;");
        let g = graph(root.path());
        assert_eq!(paths(&g), ["a.mjs", "app.mjs", "b.mjs", "shared.mjs"]);
        assert_eq!(g.report.edges.len(), 5);
        assert!(g.report.fully_resolved);
        assert!(!g.report.runtime_completeness);
    }

    #[test]
    fn mixed_import_and_require_use_their_own_conditions() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'dual'; import './bridge.cjs';");
        put(root.path(), "bridge.cjs", "module.exports=require('dual');");
        put(root.path(), "node_modules/dual/package.json", r#"{"exports":{"import":"./esm.mjs","require":"./cjs.cjs"}}"#);
        put(root.path(), "node_modules/dual/esm.mjs", "export default 1;");
        put(root.path(), "node_modules/dual/cjs.cjs", "module.exports=1;");
        let g = graph(root.path());
        assert_eq!(g.report.modules.len(), 4);
        assert!(g.report.fully_resolved);
        assert_eq!(g.report.edges.iter().filter(|e| !e.mappings.is_empty()).count(), 2);
    }

    #[test]
    fn literals_are_decoded_but_comments_and_string_decoys_are_not_edges() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "// import 'missing'\nconst s=\"require('missing')\"; import './li\\u0062.mjs'; import(`./other.mjs`);");
        put(root.path(), "lib.mjs", "export default 1;");
        put(root.path(), "other.mjs", "");
        let g = graph(root.path());
        assert_eq!(g.report.edges.len(), 2);
        assert!(g.report.fully_resolved);
        assert_eq!(g.report.edges[1].kind, LoadKind::DynamicImport);
    }

    #[test]
    fn computed_loads_and_loader_aliases_never_look_complete() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import(name); const load=require; load('hidden'); const f=eval;");
        let g = graph(root.path());
        assert_eq!(g.report.edges[0].state, EdgeState::NonLiteral);
        assert!(g.report.diagnostics.iter().any(|d| d.code == "INDIRECT_REQUIRE"));
        assert!(g.report.diagnostics.iter().any(|d| d.code == "DYNAMIC_CODE_OR_LOADER"));
        assert!(!g.report.fully_resolved);
    }

    #[test]
    fn runtime_modules_and_missing_files_remain_distinct_while_other_edges_continue() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'node:fs'; import './absent.mjs'; import './ok.mjs';");
        put(root.path(), "ok.mjs", "");
        let g = graph(root.path());
        assert_eq!(g.report.edges.iter().map(|e| e.state).collect::<Vec<_>>(),
            [EdgeState::RuntimeRequired, EdgeState::Unresolved, EdgeState::Resolved]);
        assert_eq!(paths(&g), ["app.mjs", "ok.mjs"]);
        assert!(!g.report.fully_resolved);
    }

    #[test]
    fn syntax_errors_and_unsupported_formats_preserve_source_without_claiming_analysis() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './broken.mjs'; import './addon.node';");
        put(root.path(), "broken.mjs", "export const = ;");
        put(root.path(), "addon.node", "not executable");
        let g = graph(root.path());
        assert_eq!(g.report.diagnostics.len(), 2);
        assert_eq!(g.report.modules.iter().filter(|n| n.analyzed).count(), 1);
        assert!(!g.report.fully_resolved);
    }

    #[test]
    fn json_modules_are_data_not_javascript_dependency_text() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './data.json';");
        put(root.path(), "data.json", r#"{"text":"require('missing')"}"#);
        let g = graph(root.path());
        assert!(g.report.fully_resolved);
        assert_eq!(g.report.edges.len(), 1);
    }

    #[test]
    fn one_capture_keeps_cached_source_and_negative_probes_across_all_edges() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './cached.mjs'; import './missing.mjs';");
        put(root.path(), "cached.mjs", "export const captured=1;");
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        resolver.locate("cached.mjs").unwrap();
        resolver.locate("missing.mjs").unwrap();
        put(root.path(), "cached.mjs", "import './never-captured.mjs';");
        put(root.path(), "missing.mjs", "export const late=1;");
        let g = build(resolver, "app.mjs", GraphOptions::default()).unwrap();
        let id = ModuleId { path: "cached.mjs".into(), url_suffix: String::new() };
        assert_eq!(g.source_bytes(&id).unwrap(), b"export const captured=1;");
        assert_eq!(g.report.edges[1].state, EdgeState::Unresolved);
        assert_eq!(g.report.edges.len(), 2);
    }

    #[test]
    fn graph_hash_is_relocatable_and_binds_transitive_bytes_and_query_suffixes() {
        let a = tempfile::tempdir().unwrap(); let b = tempfile::tempdir().unwrap();
        for root in [a.path(), b.path()] {
            put(root, "app.mjs", "import './lib.mjs?one'; import './lib.mjs?two';");
            put(root, "lib.mjs", "export default 1;");
        }
        let first = graph(a.path());
        assert_eq!(first.report.input_hash, graph(b.path()).report.input_hash);
        assert_eq!(first.report.modules.len(), 3);
        put(b.path(), "lib.mjs", "export default 2;");
        assert_ne!(first.report.input_hash, graph(b.path()).report.input_hash);
    }

    #[test]
    fn contained_workspace_importer_uses_physical_dependency_context() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'workspace';");
        put(root.path(), "packages/workspace/package.json", r#"{"main":"main.cjs"}"#);
        put(root.path(), "packages/workspace/main.cjs", "require('dep');");
        put(root.path(), "packages/workspace/node_modules/dep/index.js", "");
        std::fs::create_dir_all(root.path().join("node_modules")).unwrap();
        std::os::unix::fs::symlink("../packages/workspace", root.path().join("node_modules/workspace")).unwrap();
        assert!(capture(root.path(), "app.mjs", GraphOptions::default()).is_err());
        let g = capture(root.path(), "app.mjs", GraphOptions { symlink_policy: SymlinkPolicy::Contained, conditions: None }).unwrap();
        assert!(g.report.fully_resolved);
        assert!(paths(&g).contains(&"packages/workspace/node_modules/dep/index.js"));
    }

    #[test]
    fn safety_failures_do_not_return_partial_graphs() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import '../outside.mjs';");
        let e = capture(root.path(), "app.mjs", GraphOptions::default()).err().unwrap();
        assert_eq!(e.code, "ERR_MODULE_OUTSIDE_PROJECT");
    }

    #[test]
    fn source_and_site_bounds_refuse_truncated_success() {
        let root = tempfile::tempdir().unwrap();
        let imports = (0..MAX_MODULES).map(|i| format!("import './m{i}.mjs';")).collect::<String>();
        put(root.path(), "app.mjs", &imports);
        for i in 0..MAX_MODULES { put(root.path(), &format!("m{i}.mjs"), ""); }
        assert_eq!(capture(root.path(), "app.mjs", GraphOptions::default()).err().unwrap().code, "ERR_MODULE_GRAPH_LIMIT");
        put(root.path(), "app.mjs", &"import './m0.mjs';".repeat(MAX_SITES + 1));
        assert_eq!(capture(root.path(), "app.mjs", GraphOptions::default()).err().unwrap().code, "ERR_MODULE_GRAPH_LIMIT");
    }

    #[test]
    fn escaped_js_literals_preserve_utf16_and_refuse_computed_or_legacy_octal() {
        assert_eq!(decode_literal(r#"'./\x61\u0062\u{63}.mjs'"#).as_deref(), Some("./abc.mjs"));
        assert_eq!(decode_literal(r#"'./\uD83D\uDE00.mjs'"#).as_deref(), Some("./😀.mjs"));
        assert!(decode_literal(r#"'./\uD800.mjs'"#).is_none());
        assert!(decode_literal(r#"'./\141.mjs'"#).is_none());
    }

    #[test]
    fn graph_report_does_not_serialize_source_and_snapshot_survives_later_mutation() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "const private_source_marker='secret';");
        let g = graph(root.path());
        put(root.path(), "app.mjs", "changed after capture");
        assert!(std::str::from_utf8(g.source_bytes(&g.report.resolved_entrypoint).unwrap()).unwrap().contains("private_source_marker"));
        assert!(!serde_json::to_string(g.report()).unwrap().contains("private_source_marker"));
        assert!(g.report.fully_resolved);
    }

    fn typed_graph(root: &Path, entry: &str) -> CapturedModuleGraph {
        capture(root, entry, GraphOptions::default()).unwrap()
    }

    #[test]
    fn typescript_mts_cts_and_javascript_switch_grammars_per_captured_module() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import './a.mts'; import './b.cts'; import './plain.mjs'; const n: number = 1;");
        put(root.path(), "a.mts", "export const n: number = 2;");
        put(root.path(), "b.cts", "const n: number = require('./data.json'); module.exports=n;");
        put(root.path(), "plain.mjs", "export const n = 3;");
        put(root.path(), "data.json", "1");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.modules.len(), 5);
        assert_eq!(g.report.modules.iter().filter(|m| m.source_language == SourceLanguage::TypeScript).count(), 3);
        assert!(!g.report.type_resolution_performed);
    }

    #[test]
    fn whole_type_declarations_never_probe_erased_paths_or_runtime_modules() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import type {T} from '../outside'; export type {U} from './absent.d.ts'; type S = import('node:fs').Stats;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 3);
        assert!(g.report.edges.iter().all(|e| e.state == EdgeState::TypeOnly
            && e.conditions.is_empty() && e.target.is_none() && !e.deferred_or_conditional));
        assert!(g.report.probes.iter().all(|p| !p.path.contains("absent") && !p.path.contains("outside")));
        assert_eq!(paths(&g), ["app.ts"]);
    }

    #[test]
    fn inline_type_specifiers_preserve_empty_runtime_imports_and_reexports() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import {type T} from './side.mts'; export {type T} from './side.mts'; import type from './side.mts';");
        put(root.path(), "side.mts", "export type T = string; export default 1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 3);
        assert!(g.report.edges.iter().all(|e| e.state == EdgeState::Resolved));
        assert_eq!(paths(&g), ["app.ts", "side.mts"]);
    }

    #[test]
    fn nested_import_types_are_erased_without_erasing_adjacent_runtime_expressions() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", r#"
type T = typeof import('type-a');
interface Shape { value: import('type-b').Value; }
let p: Promise<typeof import('type-c')> = import('./live.mts');
const v = p as Promise<typeof import('type-d')>;
const ok = v satisfies Promise<typeof import('type-e')>;
type Factory = typeof require;
interface Names { eval: Function; }
"#);
        put(root.path(), "live.mts", "export const value: number = 1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.iter().filter(|e| e.state == EdgeState::TypeOnly).count(), 5);
        assert_eq!(g.report.edges.iter().filter(|e| e.state == EdgeState::Resolved).count(), 1);
        assert_eq!(paths(&g), ["app.ts", "live.mts"]);
    }

    #[test]
    fn ambient_module_imports_have_no_runtime_lookup_authority() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "declare module 'virtual' { import X from '../outside'; export {X}; } declare namespace N { type T = import('types').T; } const live: number = 1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 2);
        assert!(g.report.edges.iter().all(|e| e.state == EdgeState::TypeOnly));
    }

    #[test]
    fn import_equals_uses_require_conditions_and_reports_transform_boundary() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cts", "import dep = require('dual'); export = dep;");
        put(root.path(), "node_modules/dual/package.json", r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#);
        put(root.path(), "node_modules/dual/right.cjs", "module.exports=1;");
        let g = typed_graph(root.path(), "app.cts");
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.edges.len(), 1, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges[0].kind, LoadKind::Require);
        assert_eq!(g.report.edges[0].target.as_ref().unwrap().path, "node_modules/dual/right.cjs");
        assert!(g.report.diagnostics.iter().all(|d| d.code == "TYPESCRIPT_TRANSFORM_REQUIRED"));
    }

    #[test]
    fn type_only_import_equals_does_not_request_transform_or_require_a_package() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cts", "import type Shape = require('absent'); const x: number = 1;");
        let g = typed_graph(root.path(), "app.cts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 1);
        assert_eq!(g.report.edges[0].state, EdgeState::TypeOnly);
    }

    #[test]
    fn tsx_retains_explicit_edges_but_does_not_invent_implicit_jsx_dependencies() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.tsx", "import type {Props} from 'types'; import {X} from './component.ts'; export const view = <X>{import('./deferred.ts')}</X>;");
        put(root.path(), "component.ts", "export const X: any = null;");
        put(root.path(), "deferred.ts", "export default 1;");
        let g = typed_graph(root.path(), "app.tsx");
        assert!(!g.report.fully_resolved);
        assert_eq!(paths(&g), ["app.tsx", "component.ts", "deferred.ts"]);
        assert!(g.report.diagnostics.iter().any(|d| d.code == "UNSUPPORTED_JAVASCRIPT_SURFACE"));
        assert!(!g.report.probes.iter().any(|p| p.path.contains("jsx-runtime")));
    }

    #[test]
    fn nonerasable_typescript_keeps_real_loads_but_requires_transform_analysis() {
        let root = tempfile::tempdir().unwrap();
        for source in ["enum E { A = require('./value.cjs') }",
            "namespace N { export const x = require('./value.cjs'); }",
            "class C { constructor(public value = require('./value.cjs')) {} }"] {
            put(root.path(), "app.ts", source);
            put(root.path(), "value.cjs", "module.exports=1;");
            let g = typed_graph(root.path(), "app.ts");
            assert!(!g.report.fully_resolved, "{source}");
            assert!(paths(&g).contains(&"value.cjs"), "{source}: {:?}", g.report.diagnostics);
            assert!(g.report.diagnostics.iter().any(|d| d.code == "TYPESCRIPT_TRANSFORM_REQUIRED"));
        }
    }

    #[test]
    fn declaration_files_are_not_accepted_as_runtime_implementations() {
        let root = tempfile::tempdir().unwrap();
        for path in ["types.d.ts", "types.d.mts", "types.d.cts"] {
            put(root.path(), path, "export interface T { value: string }");
            let g = typed_graph(root.path(), path);
            assert!(!g.report.fully_resolved);
            assert_eq!(g.report.modules[0].source_language, SourceLanguage::Declaration);
            assert!(!g.report.modules[0].analyzed);
            assert_eq!(g.report.diagnostics[0].code, "DECLARATION_FILE_NOT_RUNTIME");
        }
    }

    #[test]
    fn typescript_does_not_enable_tsconfig_aliases_or_js_to_ts_substitution() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import './helper.js'; import './helper'; import '@app/helper';");
        put(root.path(), "helper.ts", "export default 1;");
        put(root.path(), "tsconfig.json", r#"{"compilerOptions":{"paths":{"@app/*":["./*"]}}}"#);
        let g = typed_graph(root.path(), "app.ts");
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.edges.len(), 3);
        assert!(g.report.edges.iter().all(|e| e.state == EdgeState::Unresolved));
        assert_eq!(paths(&g), ["app.ts"]);
        assert!(!g.report.probes.iter().any(|p| p.path == "tsconfig.json"));
    }

    #[test]
    fn erased_references_consume_the_same_global_site_budget() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", &"import type {T} from 'types';".repeat(MAX_SITES + 1));
        assert_eq!(capture(root.path(), "app.ts", GraphOptions::default()).err().unwrap().code, "ERR_MODULE_GRAPH_LIMIT");
    }

    #[test]
    fn typescript_syntax_does_not_relax_the_javascript_grammar() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './typed.ts'; import './not-typed.js';");
        put(root.path(), "typed.ts", "export const n: number = 1;");
        put(root.path(), "not-typed.js", "export const n: number = 1;");
        let g = graph(root.path());
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.diagnostics.len(), 1);
        assert_eq!(g.report.diagnostics[0].code, "JAVASCRIPT_PARSE_ERROR");
        assert_eq!(g.report.diagnostics[0].module.path, "not-typed.js");
    }

    #[test]
    fn type_references_bind_source_spelling_not_unread_type_dependency_contents() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "import type {T} from './types.d.ts'; const private_value: number = 1;");
        put(root.path(), "types.d.ts", "export interface T {}");
        let first = typed_graph(root.path(), "app.ts");
        put(root.path(), "types.d.ts", "export interface T {changed: true}");
        assert_eq!(first.report.input_hash, typed_graph(root.path(), "app.ts").report.input_hash);
        put(root.path(), "app.ts", "import type {T} from './different.d.ts';");
        assert_ne!(first.report.input_hash, typed_graph(root.path(), "app.ts").report.input_hash);
        assert!(std::str::from_utf8(first.source_bytes(&first.report.resolved_entrypoint).unwrap()).unwrap().contains("private_value"));
        assert!(!serde_json::to_string(first.report()).unwrap().contains("private_value"));
    }
}
