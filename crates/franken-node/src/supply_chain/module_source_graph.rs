//! Entrypoint-wide capture of static and exact-string JavaScript/TypeScript requests.
//!
//! One resolver owns every source, manifest, link and negative probe for the
//! whole graph. This is a conservative source graph, not execution or proof of
//! all runtime dependencies: literal deferred loads are included even in dead
//! branches; exact string concatenations, templates, proven lexical constants
//! and bounded conditional string choices add no runtime lookup authority.
//! Dynamic/indirect loaders and unsupported syntax stay explicit.
//! TypeScript follows explicit runtime syntax, not tsconfig-dependent emit.
//! Whole-declaration type imports and import types are recorded but never read;
//! inline type specifiers retain their declaration's side-effect dependency.
//! Enum initializers are scanned as runtime syntax. Their execution still
//! requires engine normalization with an unchanged captured
//! dependency surface; dependency capture alone does not authorize a transform.
//! Spec: https://www.typescriptlang.org/tsconfig/verbatimModuleSyntax.html

use super::{
    Entry, Mapping, Probe, ResolutionError, ResolutionMode, Resolver, SymlinkPolicy, error,
    io_error, parent, validate_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::rc::Rc;
use tree_sitter::{Node, Parser};

#[path = "module_graph_capsule.rs"]
pub mod capsule;

#[path = "module_json_syntax.rs"]
mod json_syntax;

#[path = "module_source_registry.rs"]
pub mod registry;

#[path = "module_source_scan_cache.rs"]
mod scan_cache;

#[cfg(feature = "engine")]
#[path = "module_engine_resolver.rs"]
pub mod engine_resolver;

#[cfg(test)]
#[path = "module_require_resolve_tests.rs"]
mod require_resolve_tests;

const MAX_MODULES: usize = 256;
const MAX_SITES: usize = 4096;
const MAX_AST_NODES: usize = 262_144;
const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_STRING_EXPRESSION_DEPTH: usize = 64;
const MAX_STRING_EXPRESSION_NODES: usize = 4096;
const MAX_STRING_EXPRESSION_BYTES: usize = 16 * super::MAX_PATH;
const MAX_STRING_ALTERNATIVES: usize = 32;
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
        Self {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadKind {
    StaticImport,
    Reexport,
    /// CommonJS-resolution requests, including direct require.resolve calls.
    /// Capturing this route never asserts that the target will be evaluated.
    Require,
    DynamicImport,
}

impl LoadKind {
    fn mode(self) -> ResolutionMode {
        if self == Self::Require {
            ResolutionMode::Require
        } else {
            ResolutionMode::Import
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState {
    Resolved,
    Unresolved,
    RuntimeRequired,
    NonLiteral,
    TypeOnly,
}

/// Source grammar is independent of the resolver's runtime format hint.
/// Recognizing TypeScript is not a claim that the engine can execute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage {
    #[serde(rename = "javascript")]
    JavaScript,
    #[serde(rename = "typescript")]
    TypeScript,
    Tsx,
    Declaration,
    Json,
    Unsupported,
}

impl SourceLanguage {
    fn for_module(path: &str, format: &str) -> Self {
        if [".d.ts", ".d.mts", ".d.cts"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
        {
            return Self::Declaration;
        }
        match Path::new(path).extension().and_then(|e| e.to_str()) {
            Some("ts" | "mts" | "cts") => Self::TypeScript,
            Some("tsx") => Self::Tsx,
            _ if format == "json" => Self::Json,
            _ if matches!(format, "module" | "commonjs" | "javascript_unspecified") => {
                Self::JavaScript
            }
            _ => Self::Unsupported,
        }
    }
    fn is_typescript(self) -> bool {
        matches!(self, Self::TypeScript | Self::Tsx)
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphOptions {
    pub symlink_policy: SymlinkPolicy,
    /// None uses node+import or node+require per load site. Some replaces the
    /// complete active condition set for every edge, including an empty set.
    pub conditions: Option<Vec<String>>,
}

impl Default for GraphOptions {
    fn default() -> Self {
        Self {
            symlink_policy: SymlinkPolicy::Reject,
            conditions: None,
        }
    }
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
    // Retain every consulted byte and negative observation for durable replay.
    // Directory descriptors are released when capture finishes.
    inputs: BTreeMap<String, Rc<Entry>>,
}

impl CapturedModuleGraph {
    pub fn report(&self) -> &SourceGraphReport {
        &self.report
    }
    pub fn source_bytes(&self, module: &ModuleId) -> Option<&[u8]> {
        match self.sources.get(module)?.as_ref() {
            Entry::File { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Budget {
    sites: usize,
    ast_nodes: usize,
    evidence_bytes: usize,
}

fn limit() -> ResolutionError {
    error(
        "ERR_MODULE_GRAPH_LIMIT",
        "source graph exceeds its module, syntax, site or evidence bound",
    )
}

impl Budget {
    fn site(&mut self) -> Result<()> {
        self.sites += 1;
        if self.sites > MAX_SITES {
            return Err(limit());
        }
        Ok(())
    }
    fn retain(&mut self, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec(value).map_err(|e| io_error("<source graph>", e))?;
        self.evidence_bytes = self
            .evidence_bytes
            .checked_add(bytes.len())
            .ok_or_else(limit)?;
        if self.evidence_bytes > MAX_EVIDENCE_BYTES {
            return Err(limit());
        }
        Ok(())
    }
}

/// Capture one entrypoint and its supported literal dependency closure without
/// evaluating project code. Safety/resource failures return no successful graph;
/// missing imports, runtime modules and unanalyzable code remain in the report.
pub fn capture(
    project: &Path,
    entrypoint: &str,
    mut options: GraphOptions,
) -> Result<CapturedModuleGraph> {
    validate_path(entrypoint)?;
    let resolver = Resolver::new(
        project,
        options.conditions.as_deref().unwrap_or(&[]),
        options.symlink_policy,
    )?;
    if options.conditions.is_some() {
        options.conditions = Some(resolver.conditions.clone());
    }
    build(resolver, entrypoint, options)
}

fn build(
    mut resolver: Resolver,
    entrypoint: &str,
    options: GraphOptions,
) -> Result<CapturedModuleGraph> {
    let (path, entry) = resolver.locate(entrypoint)?;
    if !entry.is_file() {
        return Err(ResolutionMode::Import.missing(entrypoint));
    }
    let first = ModuleId {
        path,
        url_suffix: String::new(),
    };
    let mut sources = BTreeMap::from([(first.clone(), entry)]);
    let mut pending = VecDeque::from([first.clone()]);
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    let mut diagnostics = Vec::new();
    let mut budget = Budget::default();
    let mut parser = Parser::new();
    let mut scan_cache = scan_cache::ScanCache::default();
    scan_cache.observe_module(&first.path);

    while let Some(id) = pending.pop_front() {
        let source = Rc::clone(sources.get(&id).expect("queued source is captured"));
        let Entry::File { bytes, sha256 } = source.as_ref() else {
            unreachable!("ordinary source")
        };
        let format_hint = resolver.format(&id.path)?;
        let source_language = SourceLanguage::for_module(&id.path, &format_hint);
        let (loads, notices, analyzed) = scan_cache.scan(
            &mut parser,
            &id.path,
            source.as_ref(),
            source_language,
            &mut budget,
        )?;
        let module = SourceModule {
            id: id.clone(),
            content_sha256: sha256.clone(),
            content_bytes: bytes.len(),
            format_hint,
            source_language,
            analyzed,
        };
        budget.retain(&module)?;
        modules.push(module);
        for notice in notices {
            let diagnostic = SourceDiagnostic {
                module: id.clone(),
                site: notice.site,
                code: notice.code,
                message: notice.message.into(),
            };
            budget.retain(&diagnostic)?;
            diagnostics.push(diagnostic);
        }
        for load in loads {
            let mode = load.kind.mode();
            let conditions = if load.type_only {
                Vec::new()
            } else {
                options
                    .conditions
                    .clone()
                    .unwrap_or_else(|| mode.default_conditions())
            };
            resolver.conditions = conditions.clone();
            resolver.mappings.clear();
            let mut edge = SourceEdge {
                importer: id.clone(),
                site: load.site,
                kind: load.kind,
                deferred_or_conditional: !load.type_only
                    && matches!(load.kind, LoadKind::Require | LoadKind::DynamicImport),
                specifier: load.specifier,
                conditions,
                state: if load.type_only {
                    EdgeState::TypeOnly
                } else {
                    EdgeState::NonLiteral
                },
                target: None,
                error: None,
                mappings: Vec::new(),
            };
            // Type-only references grant no filesystem authority. In particular,
            // an erased outside-root path or runtime name must not be resolved.
            if let Some(request) = edge.specifier.as_ref().filter(|_| !load.type_only) {
                match resolver.request(parent(&id.path), request, mode, 0) {
                    Ok((path, url_suffix)) => {
                        let (path, source) = resolver.locate(&path)?;
                        if !source.is_file() {
                            return Err(mode.missing(&path));
                        }
                        let target = ModuleId { path, url_suffix };
                        if !sources.contains_key(&target) {
                            if sources.len() >= MAX_MODULES {
                                return Err(limit());
                            }
                            scan_cache.observe_module(&target.path);
                            sources.insert(target.clone(), source);
                            pending.push_back(target.clone());
                        }
                        edge.state = EdgeState::Resolved;
                        edge.target = Some(target);
                    }
                    Err(e) if fatal(&e) => return Err(e),
                    Err(e) => {
                        edge.state = if e.code == "ERR_RUNTIME_MODULE_REQUIRED" {
                            EdgeState::RuntimeRequired
                        } else {
                            EdgeState::Unresolved
                        };
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
    diagnostics.sort_by(|a, b| {
        (&a.module, a.site.as_ref().map(|s| s.start_byte), a.code).cmp(&(
            &b.module,
            b.site.as_ref().map(|s| s.start_byte),
            b.code,
        ))
    });
    let probes = resolver.probes();
    budget.retain(&probes)?;
    let mut report = SourceGraphReport {
        schema_version: "franken-node/module-source-graph/v2".into(),
        scope: "static-and-literal-module-requests".into(),
        entrypoint: entrypoint.into(),
        resolved_entrypoint: first,
        options,
        fully_resolved: diagnostics.is_empty()
            && edges
                .iter()
                .all(|e| matches!(e.state, EdgeState::Resolved | EdgeState::TypeOnly)),
        modules,
        edges,
        diagnostics,
        probes,
        input_hash: String::new(),
        runtime_completeness: false,
        type_resolution_performed: false,
        execution_performed: false,
        release_certification: false,
    };
    let encoded = serde_json::to_vec(&report).map_err(|e| io_error("<source graph>", e))?;
    if encoded.len() > MAX_EVIDENCE_BYTES {
        return Err(limit());
    }
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update(encoded);
    report.input_hash = format!("sha256:{}", hex::encode(hash.finalize()));
    let inputs = resolver
        .entries
        .into_iter()
        .map(|(path, entry)| {
            let entry = if entry.is_dir() {
                Rc::new(Entry::Directory(None))
            } else {
                entry
            };
            (path, entry)
        })
        .collect();
    Ok(CapturedModuleGraph {
        report,
        sources,
        inputs,
    })
}

fn fatal(e: &ResolutionError) -> bool {
    matches!(
        e.code,
        "ERR_MODULE_CAPTURE"
            | "ERR_MODULE_INPUT_CHANGED"
            | "ERR_MODULE_OUTSIDE_PROJECT"
            | "ERR_MODULE_RESOLUTION_LIMIT"
            | "ERR_MODULE_SYMLINK_LOOP"
            | "ERR_INVALID_MODULE_SYMLINK"
            | "ERR_UNSUPPORTED_MODULE_FILE"
            | "ERR_PACKAGE_MAP_LIMIT"
            | "ERR_MODULE_CAPSULE_INPUT_MISSING"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Load {
    site: SourceSite,
    kind: LoadKind,
    specifier: Option<String>,
    type_only: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Notice {
    site: Option<SourceSite>,
    code: &'static str,
    message: &'static str,
}
type Scan = (Vec<Load>, Vec<Notice>, bool);

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateRequireFactory {
    Named,
    Namespace,
}

/// A deliberately narrow binding proof, not general JavaScript scope analysis.
/// Only immutable top-level imports and proved declarations participate. Native
/// CommonJS require and proved createRequire results may also flow through an
/// ordered chain of aliases, retaining their original importer authority.
/// Every other occurrence of their names is checked by the ordinary bounded
/// walk; shadowing, mutation and escape make the graph incomplete instead of
/// lending an unrelated function the captured importer's require authority.
/// Bundlers commonly emit `var` for immutable loaders. Those declarations also
/// need an uninterrupted initialization prelude and reads after initialization;
/// a hoisted function must not run before the loader it closes over exists.
#[derive(Default)]
struct CreateRequireBindings<'source> {
    factories: BTreeMap<&'source str, CreateRequireFactory>,
    commonjs_factories: BTreeMap<&'source str, usize>,
    origin_converters: BTreeMap<&'source str, CreateRequireFactory>,
    filename_aliases: BTreeMap<&'source str, CreateRequireFilename<'source>>,
    used_origin_converters: BTreeSet<&'source str>,
    used_filename_aliases: BTreeSet<&'source str>,
    loaders: BTreeSet<&'source str>,
    created_loaders: BTreeMap<&'source str, usize>,
    commonjs_aliases: BTreeSet<&'source str>,
    allowed_identifiers: BTreeSet<usize>,
    factory_members: BTreeSet<usize>,
    factory_patterns: BTreeSet<usize>,
    declarations: BTreeSet<usize>,
    mutable_bindings: BTreeMap<&'source str, LoaderInitialization>,
    filename_origin: bool,
}

struct CreateRequireFilename<'source> {
    available_after: usize,
    declaration: usize,
    converter: &'source str,
    previous: Option<&'source str>,
}

struct LoaderInitialization {
    declaration_name: usize,
    available_after: usize,
    in_prelude: bool,
}

impl<'source> CreateRequireBindings<'source> {
    fn discover(root: Node<'_>, source: &'source str) -> Result<Self> {
        let mut bindings = Self::default();
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if loader_declaration(statement) {
                bindings.discover_commonjs_factories(statement, source)?;
                continue;
            }
            if statement.kind() != "import_statement" || keyword(statement, "type") {
                continue;
            }
            let imported_module = statement
                .child_by_field_name("source")
                .and_then(|node| literal(node, source));
            let origin_converter = match imported_module.as_deref() {
                Some("module" | "node:module") => false,
                Some("url" | "node:url") => true,
                _ => continue,
            };
            let mut children = statement.walk();
            for clause in statement.named_children(&mut children) {
                if clause.kind() != "import_clause" {
                    continue;
                }
                let mut parts = clause.walk();
                for part in clause.named_children(&mut parts) {
                    if part.kind() == "identifier" {
                        // Node's default export is its native module object.
                        // Prove every use exactly as for a namespace import;
                        // importing it does not grant arbitrary loader access.
                        bindings.add_import_binding(
                            part,
                            None,
                            CreateRequireFactory::Namespace,
                            origin_converter,
                            source,
                        )?;
                    } else if part.kind() == "namespace_import" {
                        if let Some(name) = part.named_child(0) {
                            bindings.add_import_binding(
                                name,
                                None,
                                CreateRequireFactory::Namespace,
                                origin_converter,
                                source,
                            )?;
                        }
                    } else if part.kind() == "named_imports" {
                        let mut specifiers = part.walk();
                        for specifier in part.named_children(&mut specifiers) {
                            if specifier.kind() != "import_specifier" || keyword(specifier, "type")
                            {
                                continue;
                            }
                            let Some(imported) = specifier.child_by_field_name("name") else {
                                continue;
                            };
                            let function = if origin_converter { "fileURLToPath" } else { "createRequire" };
                            if imported.kind() == "identifier"
                                && imported.utf8_text(source.as_bytes()) == Ok(function)
                            {
                                let local =
                                    specifier.child_by_field_name("alias").unwrap_or(imported);
                                bindings.add_import_binding(
                                    local,
                                    Some(imported),
                                    CreateRequireFactory::Named,
                                    origin_converter,
                                    source,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        if bindings.factories.is_empty() {
            bindings.discover_commonjs_aliases(root, source)?;
            bindings.prove_initialization_prelude(root);
            return Ok(bindings);
        }
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if !loader_declaration(statement) {
                continue;
            }
            let mut declarations = statement.walk();
            for declaration in statement.named_children(&mut declarations) {
                if declaration.kind() != "variable_declarator" {
                    continue;
                }
                if bindings.discover_filename_alias(declaration, source)? {
                    continue;
                }
                let Some(name) = declaration.child_by_field_name("name") else {
                    continue;
                };
                if name.kind() != "identifier" {
                    continue;
                }
                let Some(value) = declaration.child_by_field_name("value") else {
                    continue;
                };
                let value = runtime_operand(value);
                if value.kind() != "call_expression" {
                    continue;
                }
                let Some(function) = value.child_by_field_name("function") else {
                    continue;
                };
                let Some(factory) = bindings.factory_identifier(function, source) else {
                    continue;
                };
                let Some(arguments) = value.child_by_field_name("arguments") else {
                    continue;
                };
                let mut children = arguments.walk();
                let mut arguments = arguments
                    .named_children(&mut children)
                    .filter(|node| node.kind() != "comment");
                let commonjs = factory.utf8_text(source.as_bytes())
                    .is_ok_and(|name| bindings.commonjs_factories.contains_key(name));
                let own_origin = arguments.next().is_some_and(|argument| {
                    let argument = runtime_operand(argument);
                    if commonjs {
                        return argument.kind() == "identifier"
                            && argument.utf8_text(source.as_bytes()) == Ok("__filename");
                    }
                    bindings.prove_esm_origin(argument, source)
                });
                if !own_origin || arguments.next().is_some() {
                    continue;
                }
                let spelling = name.utf8_text(source.as_bytes()).unwrap_or("");
                if spelling.contains('\\')
                    || bindings.factories.contains_key(spelling)
                    || bindings.loaders.contains(spelling)
                {
                    continue;
                }
                bindings.reserve_binding()?;
                bindings.loaders.insert(spelling);
                bindings
                    .created_loaders
                    .insert(spelling, declaration.end_byte());
                bindings.filename_origin |= commonjs;
                bindings.allowed_identifiers.insert(name.id());
                bindings.allowed_identifiers.insert(factory.id());
                bindings
                    .factory_members
                    .insert(runtime_operand(function).id());
                bindings.record_declaration(name, declaration, source);
            }
        }
        bindings.discover_commonjs_aliases(root, source)?;
        bindings.prove_initialization_prelude(root);
        Ok(bindings)
    }

    /// An ESM URL converter is only trusted at the exact call sites used to
    /// prove this module's filename. Its namespace cannot escape or be mutated.
    fn add_import_binding(
        &mut self,
        local: Node<'_>,
        imported: Option<Node<'_>>,
        kind: CreateRequireFactory,
        origin_converter: bool,
        source: &'source str,
    ) -> Result<()> {
        if !origin_converter {
            return self.add_factory(local, imported, kind, source);
        }
        if local.kind() != "identifier" {
            return Ok(());
        }
        let spelling = local.utf8_text(source.as_bytes()).unwrap_or("");
        if spelling.contains('\\')
            || matches!(
                spelling,
                "require" | "createRequire" | "__filename" | "eval" | "Function"
            )
            || self.factories.contains_key(spelling)
            || self.origin_converters.contains_key(spelling)
        {
            return Ok(());
        }
        self.reserve_binding()?;
        self.origin_converters.insert(spelling, kind);
        self.allowed_identifiers.insert(local.id());
        if let Some(imported) = imported {
            self.allowed_identifiers.insert(imported.id());
        }
        Ok(())
    }

    fn filename_conversion<'tree>(&self, node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
        let node = runtime_operand(node);
        if node.kind() != "call_expression" {
            return None;
        }
        let function = runtime_operand(node.child_by_field_name("function")?);
        let converter = if function.kind() == "identifier"
            && self
                .origin_converters
                .get(function.utf8_text(source.as_bytes()).ok()?)
                == Some(&CreateRequireFactory::Named)
        {
            function
        } else if named_member(function, "fileURLToPath", source) {
            let object = runtime_operand(function.child_by_field_name("object")?);
            if object.kind() != "identifier"
                || self
                    .origin_converters
                    .get(object.utf8_text(source.as_bytes()).ok()?)
                    != Some(&CreateRequireFactory::Namespace)
            {
                return None;
            }
            object
        } else {
            return None;
        };
        let arguments = node.child_by_field_name("arguments")?;
        let mut cursor = arguments.walk();
        let mut arguments = arguments
            .named_children(&mut cursor)
            .filter(|argument| argument.kind() != "comment");
        if !arguments
            .next()
            .is_some_and(|argument| own_import_meta_url(argument, source))
            || arguments.next().is_some()
        {
            return None;
        }
        Some(converter)
    }

    /// Filename strings may flow through earlier top-level const aliases.
    /// Activation is deferred until a createRequire origin uses the chain:
    /// unrelated URL imports and filename declarations gain no new restrictions.
    fn discover_filename_alias(
        &mut self,
        declaration: Node<'_>,
        source: &'source str,
    ) -> Result<bool> {
        if !declaration
            .parent()
            .is_some_and(|parent| keyword(parent, "const"))
        {
            return Ok(false);
        }
        let (Some(name), Some(value)) = (
            declaration.child_by_field_name("name"),
            declaration.child_by_field_name("value"),
        ) else {
            return Ok(false);
        };
        if name.kind() != "identifier" {
            return Ok(false);
        }
        let spelling = name.utf8_text(source.as_bytes()).unwrap_or("");
        if spelling.contains('\\')
            || matches!(spelling, "require" | "createRequire" | "eval" | "Function")
            || self.factories.contains_key(spelling)
            || self.origin_converters.contains_key(spelling)
            || self.filename_aliases.contains_key(spelling)
            || self.loaders.contains(spelling)
        {
            return Ok(false);
        }
        let value = runtime_operand(value);
        let previous = value.utf8_text(source.as_bytes()).unwrap_or("");
        let (converter, previous, used_identifier) =
            if let Some(converter) = self.filename_conversion(value, source) {
                (
                    converter.utf8_text(source.as_bytes()).unwrap_or(""),
                    None,
                    converter.id(),
                )
            } else if value.kind() == "identifier"
                && let Some(origin) = self.filename_aliases.get(previous)
                && origin.available_after <= value.start_byte()
            {
                (origin.converter, Some(previous), value.id())
            } else {
                return Ok(false);
            };
        self.reserve_binding()?;
        self.filename_aliases.insert(
            spelling,
            CreateRequireFilename {
                available_after: declaration.end_byte(),
                declaration: declaration.id(),
                converter,
                previous,
            },
        );
        self.allowed_identifiers.insert(name.id());
        self.allowed_identifiers.insert(used_identifier);
        Ok(true)
    }

    fn prove_esm_origin(&mut self, node: Node<'_>, source: &'source str) -> bool {
        let node = runtime_operand(node);
        if own_import_meta_url(node, source) {
            return true;
        }
        if let Some(converter) = self.filename_conversion(node, source) {
            self.used_origin_converters
                .insert(converter.utf8_text(source.as_bytes()).unwrap_or(""));
            self.allowed_identifiers.insert(converter.id());
            return true;
        }
        if node.kind() != "identifier" {
            return false;
        }
        let mut spelling = node.utf8_text(source.as_bytes()).unwrap_or("");
        if !self
            .filename_aliases
            .get(spelling)
            .is_some_and(|origin| origin.available_after <= node.start_byte())
        {
            return false;
        }
        self.allowed_identifiers.insert(node.id());
        // Chains point strictly backwards in source order. Each name is
        // activated at most once for the whole module, even with many loaders.
        while self.used_filename_aliases.insert(spelling) {
            let origin = &self.filename_aliases[spelling];
            self.declarations.insert(origin.declaration);
            self.used_origin_converters.insert(origin.converter);
            let Some(previous) = origin.previous else {
                break;
            };
            spelling = previous;
        }
        true
    }

    /// An alias retains exactly this module's require origin. Only earlier
    /// loaders in top-level initializers may supply a later alias; no
    /// fixed-point inference, nested binding, property read or executable
    /// expression can manufacture another loader. Created loaders retain their
    /// own classification rather than gaining CommonJS wrapper authority. The
    /// full scan still rejects every unproved occurrence, including shadowing.
    fn discover_commonjs_aliases(&mut self, root: Node<'_>, source: &'source str) -> Result<()> {
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if !loader_declaration(statement) {
                continue;
            }
            let mut declarations = statement.walk();
            for declaration in statement.named_children(&mut declarations) {
                if declaration.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name) = declaration.child_by_field_name("name") else {
                    continue;
                };
                let Some(value) = declaration.child_by_field_name("value") else {
                    continue;
                };
                let value = runtime_operand(value);
                if name.kind() != "identifier" || value.kind() != "identifier" {
                    continue;
                }
                let origin = value.utf8_text(source.as_bytes()).unwrap_or("");
                // Factory discovery precedes this ordered alias pass. Do not
                // let a later createRequire declaration prove an earlier read
                // from its temporal dead zone, even if the name is require.
                let created = self
                    .created_loaders
                    .get(origin)
                    .is_some_and(|end| *end <= value.start_byte());
                let commonjs = self.commonjs_aliases.contains(origin)
                    || (origin == "require"
                        && !self.factories.contains_key("require")
                        && !self.loaders.contains("require"));
                if !created && !commonjs {
                    continue;
                }
                let spelling = name.utf8_text(source.as_bytes()).unwrap_or("");
                if spelling == "require"
                    || spelling.contains('\\')
                    || self.factories.contains_key(spelling)
                    || self.loaders.contains(spelling)
                {
                    continue;
                }
                self.reserve_binding()?;
                if created {
                    self.created_loaders
                        .insert(spelling, declaration.end_byte());
                } else {
                    self.commonjs_aliases.insert(spelling);
                }
                self.loaders.insert(spelling);
                self.allowed_identifiers.insert(name.id());
                self.allowed_identifiers.insert(value.id());
                self.record_declaration(name, declaration, source);
            }
        }
        Ok(())
    }

    /// Keep the ordinary require('node:module') edge in the graph. Only a
    /// direct builtin load into a top-level declaration proves a factory. Defaults,
    /// rest patterns, computed properties and other origins remain opaque.
    fn discover_commonjs_factories(
        &mut self,
        statement: Node<'_>,
        source: &'source str,
    ) -> Result<()> {
        let mut declarations = statement.walk();
        for declaration in statement.named_children(&mut declarations) {
            if declaration.kind() != "variable_declarator"
                || !declaration
                    .child_by_field_name("value")
                    .is_some_and(|value| commonjs_module_source(value, source))
            {
                continue;
            }
            let Some(name) = declaration.child_by_field_name("name") else {
                continue;
            };
            if name.kind() == "identifier" {
                self.add_commonjs_factory(
                    name,
                    CreateRequireFactory::Namespace,
                    declaration.end_byte(),
                    source,
                )?;
                if self.allowed_identifiers.contains(&name.id()) {
                    self.record_declaration(name, declaration, source);
                }
            } else if name.kind() == "object_pattern" {
                let mut properties = name.walk();
                for property in name.named_children(&mut properties) {
                    if property.kind() == "shorthand_property_identifier_pattern"
                        && property.utf8_text(source.as_bytes()) == Ok("createRequire")
                    {
                        self.add_commonjs_factory(
                            property,
                            CreateRequireFactory::Named,
                            declaration.end_byte(),
                            source,
                        )?;
                        if self.allowed_identifiers.contains(&property.id()) {
                            self.record_declaration(property, declaration, source);
                        }
                    } else if property.kind() == "pair_pattern"
                        && property.child_by_field_name("key").is_some_and(|key| {
                            key.utf8_text(source.as_bytes()) == Ok("createRequire")
                                || literal(key, source).as_deref() == Some("createRequire")
                        })
                        && let Some(local) = property.child_by_field_name("value")
                    {
                        self.add_commonjs_factory(
                            local,
                            CreateRequireFactory::Named,
                            declaration.end_byte(),
                            source,
                        )?;
                        if self.allowed_identifiers.contains(&local.id()) {
                            self.factory_patterns.insert(property.id());
                            self.record_declaration(local, declaration, source);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn record_declaration(&mut self, name: Node<'_>, declaration: Node<'_>, source: &'source str) {
        self.declarations.insert(declaration.id());
        if declaration
            .parent()
            .is_some_and(|parent| keyword(parent, "const"))
        {
            return;
        }
        self.mutable_bindings.insert(
            name.utf8_text(source.as_bytes()).unwrap_or(""),
            LoaderInitialization {
                declaration_name: name.id(),
                available_after: declaration.end_byte(),
                in_prelude: false,
            },
        );
    }

    /// A source-order read check alone cannot see `invoke(); var load=...;
    /// function invoke(){load('x')}`. Require mutable-syntax loaders to finish
    /// initialization before any top-level execution other than the exact
    /// proved loader declarations. Imports, directives and function declarations
    /// do not invoke local functions. Unknown initializers end the prelude too;
    /// general control-flow or effect inference is intentionally not attempted.
    fn prove_initialization_prelude(&mut self, root: Node<'_>) {
        if self.mutable_bindings.is_empty() {
            return;
        }
        let mut end = 0;
        let mut cursor = root.walk();
        for statement in root.named_children(&mut cursor) {
            let admitted = match statement.kind() {
                "import_statement"
                | "comment"
                | "empty_statement"
                | "function_declaration"
                | "generator_function_declaration" => true,
                "expression_statement" => statement
                    .named_child(0)
                    .is_some_and(|expression| expression.kind() == "string"),
                _ if loader_declaration(statement) => {
                    let mut declarations = statement.walk();
                    statement
                        .named_children(&mut declarations)
                        .all(|declaration| {
                            declaration.kind() == "comment"
                                || self.declarations.contains(&declaration.id())
                        })
                }
                _ => false,
            };
            if !admitted {
                break;
            }
            end = statement.end_byte();
        }
        for binding in self.mutable_bindings.values_mut() {
            binding.in_prelude = binding.available_after <= end;
        }
    }

    fn initialized_use(&self, node: Node<'_>, spelling: &str) -> bool {
        self.mutable_bindings.get(spelling).is_none_or(|binding| {
            binding.in_prelude
                && (binding.declaration_name == node.id()
                    || node.start_byte() >= binding.available_after)
        })
    }

    fn add_commonjs_factory(
        &mut self,
        local: Node<'_>,
        kind: CreateRequireFactory,
        available_after: usize,
        source: &'source str,
    ) -> Result<()> {
        let spelling = local.utf8_text(source.as_bytes()).unwrap_or("");
        // Do not replace the wrapper bindings authenticating the import and
        // origin. The ordinary scan rejects the unproved declaration/use.
        if matches!(spelling, "require" | "__filename") {
            return Ok(());
        }
        self.add_factory(local, None, kind, source)?;
        if self.allowed_identifiers.contains(&local.id()) {
            self.commonjs_factories.insert(spelling, available_after);
        }
        Ok(())
    }

    fn reserve_binding(&self) -> Result<()> {
        if self.factories.len()
            + self.loaders.len()
            + self.origin_converters.len()
            + self.filename_aliases.len()
            >= MAX_SITES
        {
            return Err(limit());
        }
        Ok(())
    }

    fn add_factory(
        &mut self,
        local: Node<'_>,
        imported: Option<Node<'_>>,
        kind: CreateRequireFactory,
        source: &'source str,
    ) -> Result<()> {
        if !matches!(
            local.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) {
            return Ok(());
        }
        let spelling = local.utf8_text(source.as_bytes()).unwrap_or("");
        if spelling.contains('\\')
            || self.factories.contains_key(spelling)
            || self.origin_converters.contains_key(spelling)
        {
            return Ok(());
        }
        self.reserve_binding()?;
        self.factories.insert(spelling, kind);
        self.allowed_identifiers.insert(local.id());
        if let Some(imported) = imported {
            self.allowed_identifiers.insert(imported.id());
        }
        Ok(())
    }

    fn factory_identifier<'tree>(&self, node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
        if self.factories.is_empty() {
            return None;
        }
        let node = runtime_operand(node);
        if node.kind() == "identifier"
            && self.factories.get(node.utf8_text(source.as_bytes()).ok()?)
                == Some(&CreateRequireFactory::Named)
            && self.factory_initialized(node, source)
        {
            return Some(node);
        }
        if named_member(node, "createRequire", source) {
            let object = runtime_operand(node.child_by_field_name("object")?);
            if object.kind() == "identifier"
                && self
                    .factories
                    .get(object.utf8_text(source.as_bytes()).ok()?)
                    == Some(&CreateRequireFactory::Namespace)
                && self.factory_initialized(object, source)
            {
                return Some(object);
            }
        }
        None
    }

    fn factory_initialized(&self, node: Node<'_>, source: &str) -> bool {
        // ESM imports are initialized as module bindings. CommonJS factories
        // come from executed declarations, including const; discovery of a
        // later declaration must not prove a call from its TDZ or var hoist.
        node.utf8_text(source.as_bytes()).is_ok_and(|name| {
            self.commonjs_factories
                .get(name)
                .is_none_or(|end| node.start_byte() >= *end)
        })
    }

    fn is_loader(&self, node: Node<'_>, source: &str) -> bool {
        let node = runtime_operand(node);
        node.kind() == "identifier"
            && node
                .utf8_text(source.as_bytes())
                .is_ok_and(|name| self.loaders.contains(name))
    }

    fn is_resolve(&self, node: Node<'_>, source: &str) -> bool {
        if self.loaders.is_empty() {
            return false;
        }
        let node = runtime_operand(node);
        named_member(node, "resolve", source)
            && node
                .child_by_field_name("object")
                .is_some_and(|object| self.is_loader(object, source))
    }

    fn direct_loader_use(&self, mut node: Node<'_>, source: &str) -> bool {
        while let Some(parent) = node.parent() {
            if parent.kind() == "call_expression" {
                return parent
                    .child_by_field_name("function")
                    .is_some_and(|function| function.id() == node.id());
            }
            if wrapper_operand(parent).is_some_and(|operand| operand.id() == node.id())
                || (self.is_resolve(parent, source)
                    && parent
                        .child_by_field_name("object")
                        .is_some_and(|object| object.id() == node.id()))
            {
                node = parent;
            } else {
                return false;
            }
        }
        false
    }
}

fn own_import_meta_url(node: Node<'_>, source: &str) -> bool {
    let node = runtime_operand(node);
    named_member(node, "url", source)
        && node.child_by_field_name("object").is_some_and(|object| {
            let object = runtime_operand(object);
            object.kind() == "meta_property"
                && object.utf8_text(source.as_bytes()) == Ok("import.meta")
        })
}

fn loader_declaration(node: Node<'_>) -> bool {
    node.kind() == "variable_declaration"
        || (node.kind() == "lexical_declaration"
            && (keyword(node, "const") || keyword(node, "let")))
}

/// Immutable primitive values may flow into module requests, but a matching
/// spelling alone is not a binding proof. Reject a name if any runtime use is
/// a second declaration, a write, or a context we cannot classify. This is
/// deliberately stricter than full lexical scope resolution: even an unrelated
/// inner shadow prevents inference for that name throughout the module. A
/// unique const may belong to a program or statement block, including function
/// bodies. Its value is available only after its initializer and inside that
/// exact lexical scope; it never supplies routes to a sibling or outer scope.
#[derive(Default)]
struct ConstStringBindings<'source> {
    values: BTreeMap<&'source str, ConstStringValue>,
}

struct ConstStringValue {
    alternatives: StringAlternatives,
    available_after: usize,
    scope_end: usize,
}

impl<'source> ConstStringBindings<'source> {
    fn discover(
        root: Node<'_>,
        source: &'source str,
        language: SourceLanguage,
        budget: &mut Budget,
    ) -> Result<Self> {
        let mut candidates = Vec::new();
        // Remember the sole non-read occurrence of each name. A second
        // declaration, mutation or unknown use makes it unproved regardless of
        // which one appears first. Borrowed names and entries are bounded by
        // the shared AST budget. This combines nested-declaration discovery
        // and binding proof in one walk instead of adding a separate pass.
        let mut non_reads = BTreeMap::new();

        // This proof walk shares the capture's syntax budget. It cannot hide
        // work in a separate, unbounded traversal before the ordinary scanner.
        let mut cursor = root.walk();
        let mut type_context = vec![false];
        loop {
            budget.ast_nodes += 1;
            if budget.ast_nodes > MAX_AST_NODES {
                return Err(limit());
            }
            let node = cursor.node();
            let erased = language.is_typescript()
                && (*type_context.last().expect("root context") || erased_region(node));
            if !erased
                && node.kind() == "variable_declarator"
                && let Some(scope) = const_string_scope(node)
                && let (Some(name), Some(value)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                )
                && name.kind() == "identifier"
                && matches!(
                    runtime_operand(value).kind(),
                    "string"
                        | "template_string"
                        | "identifier"
                        | "ternary_expression"
                        | "binary_expression"
                )
            {
                if candidates.len() >= MAX_SITES {
                    return Err(limit());
                }
                candidates.push((
                    name.utf8_text(source.as_bytes()).unwrap_or(""),
                    value,
                    node.end_byte(),
                    scope.end_byte(),
                    name.id(),
                ));
            }
            if !erased
                && matches!(
                    node.kind(),
                    "identifier"
                        | "shorthand_property_identifier"
                        | "shorthand_property_identifier_pattern"
                )
            {
                let spelling = node.utf8_text(source.as_bytes()).unwrap_or("");
                // An escaped declaration could shadow an unescaped use. Do
                // not infer binding identity without decoding all such names.
                if spelling.contains('\\') {
                    return Ok(Self::default());
                }
                if !const_string_read(node) {
                    non_reads
                        .entry(spelling)
                        .and_modify(|id| *id = None)
                        .or_insert(Some(node.id()));
                }
            }
            if cursor.goto_first_child() {
                type_context.push(erased);
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    let mut bindings = Self::default();
                    // Bound the total retained values and alias-copy work for
                    // all constants, not merely each initializer in isolation.
                    let mut inference_budget = FiniteStringBudget::default();
                    for (spelling, value, available_after, scope_end, declaration) in candidates {
                        if non_reads.get(spelling) == Some(&Some(declaration))
                            && let Some(alternatives) =
                                finite_strings(value, source, &bindings, &mut inference_budget, 0)
                        {
                            bindings.values.insert(
                                spelling,
                                ConstStringValue {
                                    alternatives,
                                    available_after,
                                    scope_end,
                                },
                            );
                        }
                    }
                    return Ok(bindings);
                }
                type_context.pop();
            }
        }
    }
}

/// Only a lexical declaration directly owned by a block or the program gives
/// us a source-range scope. For-loop headers, switch clauses and destructuring
/// need their own binding model and remain opaque. Exporting a const does not
/// change the surrounding program scope or allow later mutation.
fn const_string_scope(declaration: Node<'_>) -> Option<Node<'_>> {
    let statement = declaration.parent()?;
    if statement.kind() != "lexical_declaration" || !keyword(statement, "const") {
        return None;
    }
    let mut scope = statement.parent()?;
    if scope.kind() == "export_statement" {
        scope = scope.parent()?;
    }
    matches!(scope.kind(), "program" | "statement_block").then_some(scope)
}

/// Classify expression reads, not declarations by exclusion. Unknown syntax
/// remains unproved, including nested parameter/destructuring binding forms.
fn const_string_read(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if wrapper_operand(parent).is_some_and(|operand| operand.id() == node.id()) {
            node = parent;
            continue;
        }
        let field_is = |field| {
            parent
                .child_by_field_name(field)
                .is_some_and(|child| child.id() == node.id())
        };
        return match parent.kind() {
            "arguments"
            | "array"
            | "binary_expression"
            | "ternary_expression"
            | "sequence_expression"
            | "return_statement"
            | "throw_statement"
            | "expression_statement"
            | "unary_expression"
            | "await_expression"
            | "yield_expression"
            | "spread_element"
            | "template_substitution"
            | "computed_property_name"
            | "subscript_expression"
            | "if_statement"
            | "while_statement"
            | "do_statement"
            | "switch_statement"
            | "switch_case"
            | "for_statement" => true,
            "object" => node.kind() == "shorthand_property_identifier",
            "call_expression" => field_is("function"),
            "new_expression" => field_is("constructor"),
            "member_expression" => field_is("object"),
            "variable_declarator" | "pair" | "required_parameter" | "optional_parameter" => {
                field_is("value")
            }
            "assignment_expression"
            | "augmented_assignment_expression"
            | "assignment_pattern"
            | "object_assignment_pattern"
            | "for_in_statement" => field_is("right"),
            "arrow_function" => field_is("body"),
            "export_specifier" => field_is("name"),
            _ => false,
        };
    }
    false
}

fn scan(
    parser: &mut Parser,
    bytes: &[u8],
    language: SourceLanguage,
    budget: &mut Budget,
) -> Result<Scan> {
    let notice = |code, message| Notice {
        site: None,
        code,
        message,
    };
    if language == SourceLanguage::Json {
        return if json_syntax::valid(bytes) {
            Ok((Vec::new(), Vec::new(), true))
        } else {
            budget.site()?;
            Ok((
                Vec::new(),
                vec![notice(
                    "INVALID_JSON_MODULE",
                    "captured JSON module could not be parsed",
                )],
                false,
            ))
        };
    }
    if language == SourceLanguage::Declaration {
        budget.site()?;
        return Ok((
            Vec::new(),
            vec![notice(
                "DECLARATION_FILE_NOT_RUNTIME",
                "a declaration file is not a runtime implementation",
            )],
            false,
        ));
    }
    if language == SourceLanguage::Unsupported {
        budget.site()?;
        return Ok((
            Vec::new(),
            vec![notice(
                "UNSUPPORTED_MODULE_FORMAT",
                "source extraction does not cover this format",
            )],
            false,
        ));
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            budget.site()?;
            return Ok((
                Vec::new(),
                vec![notice(
                    "NON_UTF8_JAVASCRIPT",
                    "JavaScript source is not UTF-8",
                )],
                false,
            ));
        }
    };
    let grammar = match language {
        SourceLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        SourceLanguage::Tsx => tree_sitter_typescript::LANGUAGE_TSX,
        _ => tree_sitter_javascript::LANGUAGE,
    };
    parser
        .set_language(&grammar.into())
        .map_err(|e| error("ERR_MODULE_GRAPH_PARSER", e.to_string()))?;
    let tree = parser
        .parse(bytes, None)
        .ok_or_else(|| error("ERR_MODULE_GRAPH_PARSER", "parser did not return a tree"))?;
    if tree.root_node().has_error() {
        budget.site()?;
        let code = if language.is_typescript() {
            "TYPESCRIPT_PARSE_ERROR"
        } else {
            "JAVASCRIPT_PARSE_ERROR"
        };
        return Ok((
            Vec::new(),
            vec![notice(
                code,
                "source has syntax errors; no dependency completeness asserted",
            )],
            false,
        ));
    }
    let bindings = CreateRequireBindings::discover(tree.root_node(), text)?;
    let mut strings = ConstStringBindings::default();
    let mut strings_discovered = false;
    let mut loads = Vec::new();
    let mut notices = Vec::new();
    let mut cursor = tree.walk();
    // One inherited bit per cursor depth, not an ancestor scan at every node.
    // All syntax still consumes the global budget, including erased subtrees.
    let mut type_context = vec![false];
    let mut enum_context = vec![false];
    loop {
        budget.ast_nodes += 1;
        if budget.ast_nodes > MAX_AST_NODES {
            return Err(limit());
        }
        let node = cursor.node();
        let erased = language.is_typescript()
            && (*type_context.last().expect("root context") || erased_region(node));
        let in_enum =
            *enum_context.last().expect("root context") || node.kind() == "enum_declaration";
        let mut issue = None;
        let request = match node.kind() {
            "import_statement" => node
                .child_by_field_name("source")
                .map(|s| (LoadKind::StaticImport, s)),
            "export_statement" => node
                .child_by_field_name("source")
                .map(|s| (LoadKind::Reexport, s)),
            "import_require_clause" if language.is_typescript() => {
                if !erased {
                    issue = Some((
                        "TYPESCRIPT_TRANSFORM_REQUIRED",
                        "import-equals requires a configured TypeScript transform",
                    ));
                }
                node.child_by_field_name("source")
                    .map(|s| (LoadKind::Require, s))
            }
            "call_expression" => {
                let resolve = node
                    .child_by_field_name("function")
                    .is_some_and(|f| is_require_resolve(f, text) || bindings.is_resolve(f, text));
                let kind = node.child_by_field_name("function").and_then(|f| {
                    if bindings.factory_identifier(f, text).is_some() {
                        // A factory alias may itself be named `require`.
                        // The origin argument is not a module request.
                        None
                    } else if f.kind() == "import" {
                        Some(LoadKind::DynamicImport)
                    } else if is_require(f, bytes) || bindings.is_loader(f, text) || resolve {
                        Some(LoadKind::Require)
                    } else {
                        None
                    }
                });
                kind.map(|kind| {
                    let arg = node
                        .child_by_field_name("arguments")
                        .and_then(|a| {
                            let mut walk = a.walk();
                            let mut args = a
                                .named_children(&mut walk)
                                .filter(|n| n.kind() != "comment");
                            let first = args.next();
                            if resolve && args.next().is_some() {
                                // `paths` changes the lookup origin. Do not
                                // guess a route from just the first argument.
                                if !erased {
                                    issue = Some((
                                        "REQUIRE_RESOLVE_OPTIONS",
                                        "require.resolve options need a captured search-path contract",
                                    ));
                                }
                                None
                            } else {
                                first
                            }
                        })
                        .unwrap_or(node);
                    (kind, arg)
                })
            }
            "identifier"
            | "type_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
                if !erased =>
            {
                let spelling = node.utf8_text(bytes).unwrap_or("");
                if !bindings.commonjs_aliases.is_empty()
                    && spelling == "arguments"
                    && commonjs_wrapper_arguments(node)
                {
                    issue = Some((
                        "MUTABLE_REQUIRE_ORIGIN",
                        "CommonJS wrapper arguments may replace the aliased require binding",
                    ));
                } else if bindings.filename_origin && spelling == "arguments"
                    && commonjs_wrapper_arguments(node)
                {
                    issue = Some((
                        "MUTABLE_CREATE_REQUIRE_ORIGIN",
                        "CommonJS wrapper arguments may alias the createRequire __filename origin",
                    ));
                } else if bindings.filename_origin && spelling == "__filename"
                    && !immutable_filename_use(node)
                {
                    issue = Some((
                        "MUTABLE_CREATE_REQUIRE_ORIGIN",
                        "createRequire capture requires the unchanged CommonJS __filename binding",
                    ));
                } else if !bindings.initialized_use(node, spelling) {
                    issue = Some((
                        "UNPROVED_LOADER_INITIALIZATION",
                        "var/let loaders require an uninterrupted initialization prelude and reads after initialization",
                    ));
                } else if bindings.allowed_identifiers.contains(&node.id()) {
                    // Exactly the immutable import, proved declaration and
                    // factory callee proved by discovery above.
                } else if !bindings.factories.is_empty() && spelling.contains('\\') {
                    issue = Some((
                        "UNSUPPORTED_CREATE_REQUIRE_BINDING",
                        "escaped identifiers need decoded scope analysis before createRequire capture",
                    ));
                } else if !bindings.commonjs_aliases.is_empty() && spelling.contains('\\') {
                    issue = Some((
                        "UNSUPPORTED_REQUIRE_ALIAS_BINDING",
                        "escaped identifiers need decoded scope analysis before require alias capture",
                    ));
                } else if bindings.used_origin_converters.contains(spelling) {
                    issue = Some((
                        "UNSUPPORTED_CREATE_REQUIRE_ORIGIN",
                        "fileURLToPath origin converters require immutable imports and exact captured origin calls",
                    ));
                } else if bindings.used_filename_aliases.contains(spelling)
                    && (!const_string_read(node)
                        || bindings.filename_aliases.get(spelling)
                            .is_some_and(|origin| node.start_byte() < origin.available_after))
                {
                    issue = Some((
                        "MUTABLE_CREATE_REQUIRE_ORIGIN",
                        "createRequire filename aliases require unchanged const bindings without shadowing or early reads",
                    ));
                } else if bindings.factories.contains_key(spelling) {
                    issue = Some((
                        "INDIRECT_CREATE_REQUIRE",
                        "createRequire factory must initialize a proved top-level binding from this module's unchanged origin",
                    ));
                } else if bindings.loaders.contains(spelling) {
                    if !bindings.direct_loader_use(node, text)
                        && !loader_typeof_probe(node)
                        && !(bindings.commonjs_aliases.contains(spelling)
                            && commonjs_main_guard(node, text))
                    {
                        issue = Some(if bindings.commonjs_aliases.contains(spelling) {
                            (
                                "INDIRECT_REQUIRE_ALIAS",
                                "require alias is shadowed, mutated or escapes its captured direct calls",
                            )
                        } else {
                            (
                                "INDIRECT_CREATED_REQUIRE",
                                "created require is shadowed, mutated or escapes its captured direct calls",
                            )
                        });
                    }
                } else if spelling == "require"
                    && !direct_callee(node, text)
                    && !loader_typeof_probe(node)
                    && !commonjs_main_guard(node, text)
                {
                    issue = Some((
                        "INDIRECT_REQUIRE",
                        "require is bound, passed or used indirectly; scope/alias analysis is not implemented",
                    ));
                } else if matches!(spelling, "eval" | "Function" | "createRequire") {
                    issue = Some((
                        "DYNAMIC_CODE_OR_LOADER",
                        "dynamic code or loader factory requires runtime analysis",
                    ));
                }
                None
            }
            "member_expression" | "subscript_expression"
                if !erased
                    && named_member(node, "createRequire", text)
                    && !bindings.factory_members.contains(&node.id()) =>
            {
                issue = Some((
                    "INDIRECT_CREATE_REQUIRE",
                    "createRequire member is not a captured immutable namespace factory call",
                ));
                None
            }
            "meta_property"
                if !erased
                    && !bindings.loaders.is_empty()
                    && node.utf8_text(bytes) == Ok("import.meta")
                    && !immutable_import_meta_use(node, text) =>
            {
                issue = Some((
                    "MUTABLE_CREATE_REQUIRE_ORIGIN",
                    "createRequire capture requires unescaped import.meta and read-only origin members",
                ));
                None
            }
            "object_pattern"
                if !erased
                    && node.parent().is_some_and(|parent| {
                        parent.kind() == "variable_declarator"
                            && parent.child_by_field_name("value")
                                .is_some_and(|value| commonjs_module_source(value, text))
                    }) =>
            {
                let mut properties = node.walk();
                if node.named_children(&mut properties).any(|property| {
                    property.kind() != "comment"
                        && !bindings.allowed_identifiers.contains(&property.id())
                        && !bindings.factory_patterns.contains(&property.id())
                }) {
                    issue = Some((
                        "INDIRECT_CREATE_REQUIRE",
                        "module factory destructuring requires immutable, exact createRequire bindings",
                    ));
                }
                None
            }
            "pair_pattern"
                if !erased
                    && !bindings.factory_patterns.contains(&node.id())
                    && node.child_by_field_name("key").is_some_and(|key| {
                        key.utf8_text(bytes) == Ok("createRequire")
                            || literal(key, text).as_deref() == Some("createRequire")
                    }) =>
            {
                issue = Some((
                    "INDIRECT_CREATE_REQUIRE",
                    "destructured loader factories need a separate immutable-origin contract",
                ));
                None
            }
            "member_expression"
                if !erased
                    && is_require(node, bytes)
                    && !direct_callee(node, text)
                    && !loader_typeof_probe(node) =>
            {
                issue = Some(("INDIRECT_REQUIRE", "module.require is used indirectly"));
                None
            }
            "jsx_element" | "jsx_self_closing_element" | "with_statement" if !erased => {
                issue = Some((
                    "UNSUPPORTED_JAVASCRIPT_SURFACE",
                    "JSX or dynamic scope requires a separate analysis",
                ));
                None
            }
            _ => None,
        };
        if language.is_typescript() && !erased && requires_typescript_transform(node) {
            issue = Some((
                "TYPESCRIPT_TRANSFORM_REQUIRED",
                "non-erasable TypeScript or decorators require a configured transform; injected dependencies are not inferred",
            ));
        }
        if language.is_typescript() && !erased && in_enum {
            if enum_member_name(node)
                && (node.kind() != "property_identifier"
                    || !text[node.byte_range()]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')))
            {
                issue = Some((
                    "TYPESCRIPT_TRANSFORM_REQUIRED",
                    "quoted, escaped or non-ASCII enum member names require decoded engine member bindings",
                ));
            } else if enum_helper_capture(node, text) {
                issue = Some((
                    "TYPESCRIPT_TRANSFORM_REQUIRED",
                    "enum binding may capture a normalization helper; hygienic engine normalization is required",
                ));
            }
        }
        if let Some((kind, argument)) = request {
            let mut specifiers = request_literals(argument, text, &strings);
            if specifiers.is_none() && !erased && !strings_discovered {
                // Keep ordinary literal/finite-expression graphs on their
                // existing single-walk path. Prove constants only when an
                // otherwise opaque runtime request actually needs them.
                strings = ConstStringBindings::discover(tree.root_node(), text, language, budget)?;
                strings_discovered = true;
                specifiers = request_literals(argument, text, &strings);
            }
            let unresolved = specifiers.is_none();
            // A finite choice is a set of potential routes at the same source
            // site, not a prediction of the branch that execution will take.
            // Charge each route before publishing any scan output. An unknown
            // branch remains one opaque load, never a partially admitted set.
            for specifier in specifiers
                .into_iter()
                .flatten()
                .map(Some)
                .chain(unresolved.then_some(None))
            {
                budget.site()?;
                loads.push(Load {
                    site: SourceSite::of(node),
                    kind,
                    specifier,
                    type_only: erased,
                });
            }
        }
        if let Some((code, message)) = issue {
            budget.site()?;
            notices.push(Notice {
                site: Some(SourceSite::of(node)),
                code,
                message,
            });
        }
        if cursor.goto_first_child() {
            type_context.push(erased);
            enum_context.push(in_enum);
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok((loads, notices, true));
            }
            type_context.pop();
            enum_context.pop();
        }
    }
}

/// The engine's current enum lowering has fixed helper bindings. Until it
/// allocates fresh names, their capture must not change a source initializer's
/// meaning. Property accesses and string values do not bind those helpers.
fn enum_helper_capture(node: Node<'_>, source: &str) -> bool {
    let binding = match node.kind() {
        "identifier"
        | "type_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => true,
        "property_identifier" => enum_member_name(node),
        _ => false,
    };
    if !binding {
        return false;
    }
    let spelling = &source[node.byte_range()];
    let helper = |name: &str| matches!(name, "__enum" | "__enum_next" | "__value");
    if !spelling.contains('\\') {
        return helper(spelling);
    }
    // The syntax tree already validated the identifier. Reuse the bounded
    // Unicode decoder so escaped spellings cannot evade the same refusal.
    let mut units = Vec::new();
    if append_string_segment(
        spelling,
        false,
        &mut units,
        &mut StringExpressionBudget::default(),
    )
    .is_none()
    {
        return true;
    }
    String::from_utf16(&units).map_or(true, |name| helper(&name))
}

fn enum_member_name(node: Node<'_>) -> bool {
    node.is_named()
        && node.parent().is_some_and(|parent| {
            (parent.kind() == "enum_body" && !matches!(node.kind(), "enum_assignment" | "comment"))
                || (parent.kind() == "enum_assignment"
                    && parent
                        .child_by_field_name("name")
                        .is_some_and(|name| name.id() == node.id()))
        })
}

/// Only a direct anonymous keyword is a modifier. A default binding named
/// `type` (import type from './x') is an identifier and remains a runtime load.
fn keyword(node: Node<'_>, word: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|n| !n.is_named() && n.kind() == word)
}

fn erased_region(node: Node<'_>) -> bool {
    match node.kind() {
        "type_alias_declaration"
        | "interface_declaration"
        | "type_annotation"
        | "type_arguments"
        | "type_parameters"
        | "type_query"
        | "implements_clause"
        | "ambient_declaration"
        | "function_signature"
        | "method_signature"
        | "abstract_method_signature"
        | "index_signature" => true,
        "import_statement" | "export_statement" | "import_specifier" | "export_specifier" => {
            keyword(node, "type")
        }
        "public_field_definition" => keyword(node, "declare"),
        _ => node.parent().is_some_and(|p| {
            matches!(p.kind(), "as_expression" | "satisfies_expression")
                && p.named_child(0)
                    .is_some_and(|first| first.id() != node.id())
        }),
    }
}

fn requires_typescript_transform(node: Node<'_>) -> bool {
    match node.kind() {
        // Enum initializers have explicit runtime loads, all visited by the
        // ordinary walk. The engine owns their bounded
        // normalization and rescans its output before registry admission; it
        // must preserve every captured route. Other transforms still lack that
        // contract, including namespaces, legacy `module` declarations and
        // import aliases.
        "internal_module" | "module" | "import_alias" | "decorator" | "type_assertion" => true,
        "export_statement" => keyword(node, "="),
        "required_parameter" | "optional_parameter" => {
            let mut cursor = node.walk();
            keyword(node, "readonly")
                || node
                    .named_children(&mut cursor)
                    .any(|n| matches!(n.kind(), "accessibility_modifier" | "override_modifier"))
        }
        _ => false,
    }
}

/// These wrappers preserve the callable after erasure. Do not unwrap sequence,
/// conditional, assignment or other executable expressions and guess a loader.
fn wrapper_operand(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "parenthesized_expression"
            | "as_expression"
            | "satisfies_expression"
            | "non_null_expression"
            | "instantiation_expression"
            | "type_assertion"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|n| !matches!(n.kind(), "comment" | "type_arguments"))
}

fn runtime_operand(mut node: Node<'_>) -> Node<'_> {
    while let Some(inner) = wrapper_operand(node) {
        node = inner;
    }
    node
}

fn direct_callee(mut node: Node<'_>, source: &str) -> bool {
    while let Some(p) = node.parent() {
        if p.kind() == "call_expression" {
            return p
                .child_by_field_name("function")
                .is_some_and(|f| f.id() == node.id());
        }
        if wrapper_operand(p).is_some_and(|operand| operand.id() == node.id())
            || (is_require_resolve(p, source)
                && p.child_by_field_name("object")
                    .is_some_and(|object| object.id() == node.id()))
        {
            node = p;
        } else {
            return false;
        }
    }
    false
}

/// UMD packages commonly inspect `typeof require` before a literal load.
/// `typeof` returns only a type-name string; it cannot return, store or invoke
/// the loader. Recognize only that immediate observation through transparent
/// wrappers. In particular, do not unwrap sequences, assignments, conditionals,
/// property accesses or calls: their operands may escape the loader or perform
/// a load. The normal AST walk still visits every binding, mutation and load in
/// the enclosing expression, regardless of the guard's possible outcome.
fn loader_typeof_probe(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "unary_expression" {
            return keyword(parent, "typeof")
                && parent
                    .child_by_field_name("argument")
                    .is_some_and(|argument| argument.id() == node.id());
        }
        if wrapper_operand(parent).is_some_and(|operand| operand.id() == node.id()) {
            node = parent;
        } else {
            return false;
        }
    }
    false
}

/// CommonJS CLI modules commonly compare their require's entry-module object
/// with their own module. Permit only that immediate strict identity observation:
/// unlike loose equality it cannot invoke an object coercion hook that exposes
/// the entry module. Aliases must already have a proved CommonJS origin;
/// createRequire results keep their separate contract. All source branches and
/// loader mutations remain scanned normally.
fn commonjs_main_guard(mut node: Node<'_>, source: &str) -> bool {
    let mut main_found = false;
    for _ in 0..MAX_STRING_EXPRESSION_DEPTH {
        let Some(parent) = node.parent() else {
            return false;
        };
        if wrapper_operand(parent).is_some_and(|operand| operand.id() == node.id()) {
            node = parent;
            continue;
        }
        if !main_found {
            if !named_member(parent, "main", source)
                || !parent
                    .child_by_field_name("object")
                    .is_some_and(|object| object.id() == node.id())
            {
                return false;
            }
            main_found = true;
            node = parent;
            continue;
        }
        if parent.kind() != "binary_expression"
            || !parent
                .child_by_field_name("operator")
                .is_some_and(|operator| matches!(operator.kind(), "===" | "!=="))
        {
            return false;
        }
        let (Some(left), Some(right)) = (
            parent.child_by_field_name("left"),
            parent.child_by_field_name("right"),
        ) else {
            return false;
        };
        let other = if left.id() == node.id() {
            right
        } else if right.id() == node.id() {
            left
        } else {
            return false;
        };
        let other = runtime_operand(other);
        return other.kind() == "identifier" && other.utf8_text(source.as_bytes()) == Ok("module");
    }
    false
}

fn named_member(node: Node<'_>, name: &str, source: &str) -> bool {
    let node = runtime_operand(node);
    match node.kind() {
        "member_expression" => node
            .child_by_field_name("property")
            .is_some_and(|property| property.utf8_text(source.as_bytes()) == Ok(name)),
        "subscript_expression" => node
            .child_by_field_name("index")
            .and_then(|index| literal(index, source))
            .is_some_and(|property| property == name),
        _ => false,
    }
}

fn commonjs_module_source(node: Node<'_>, source: &str) -> bool {
    let node = runtime_operand(node);
    if node.kind() != "call_expression"
        || !node
            .child_by_field_name("function")
            .is_some_and(|function| {
                let function = runtime_operand(function);
                function.kind() == "identifier"
                    && function.utf8_text(source.as_bytes()) == Ok("require")
            })
    {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let mut arguments = arguments
        .named_children(&mut cursor)
        .filter(|node| node.kind() != "comment");
    arguments
        .next()
        .and_then(|node| literal(node, source))
        .is_some_and(|name| matches!(name.as_str(), "module" | "node:module"))
        && arguments.next().is_none()
}

/// A sloppy CommonJS wrapper maps arguments[1] to require and arguments[3] to
/// __filename. Arrow functions inherit that object, while ordinary functions
/// own theirs. Computed method names still execute in the enclosing scope.
/// Do not allow the wrapper object to escape this immutable-origin proof.
fn commonjs_wrapper_arguments(mut node: Node<'_>) -> bool {
    for _ in 0..MAX_STRING_EXPRESSION_DEPTH {
        let Some(parent) = node.parent() else {
            return true;
        };
        let method_name = parent.kind() == "method_definition"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == node.id());
        if !method_name
            && matches!(
                parent.kind(),
                "function_declaration"
                    | "function_expression"
                    | "generator_function"
                    | "generator_function_declaration"
                    | "method_definition"
            )
        {
            return false;
        }
        node = parent;
    }
    // An unproved deeply nested reference cannot establish a separate owner.
    true
}

/// The CommonJS filename is a string, so ordinary reads may escape safely.
/// Any binding or write (including one in an unrelated nested scope) prevents
/// this deliberately narrow proof. Dynamic scopes and escaped identifiers
/// are rejected independently by the main scanner.
fn immutable_filename_use(mut node: Node<'_>) -> bool {
    let origin = node;
    if node.kind() == "shorthand_property_identifier_pattern" {
        return false;
    }
    for _ in 0..MAX_STRING_EXPRESSION_DEPTH {
        let Some(parent) = node.parent() else {
            return true;
        };
        let contains = |field: &str| {
            parent.child_by_field_name(field).is_some_and(|value| {
                value.start_byte() <= origin.start_byte() && origin.end_byte() <= value.end_byte()
            })
        };
        if matches!(
            parent.kind(),
            "import_clause" | "import_specifier" | "namespace_import"
        ) || (parent.kind() == "variable_declarator" && contains("name"))
            || (matches!(
                parent.kind(),
                "function_declaration"
                    | "function_expression"
                    | "generator_function"
                    | "generator_function_declaration"
                    | "arrow_function"
                    | "method_definition"
            ) && (contains("name") || contains("parameters") || contains("parameter")))
            || (matches!(
                parent.kind(),
                "class_declaration" | "abstract_class_declaration" | "class"
            ) && contains("name"))
            || (parent.kind() == "catch_clause" && contains("parameter"))
            || (matches!(
                parent.kind(),
                "assignment_expression"
                    | "augmented_assignment_expression"
                    | "assignment_pattern"
                    | "object_assignment_pattern"
                    | "for_in_statement"
            ) && contains("left"))
            || parent.kind() == "update_expression"
            || (parent.kind() == "unary_expression" && keyword(parent, "delete"))
        {
            return false;
        }
        node = parent;
    }
    false
}

/// import.meta is mutable in JavaScript. Reading its origin strings is safe;
/// letting the object escape or assigning any of those members would make a
/// later factory call's base depend on runtime state. Bound the ancestor walk
/// and reject assignment patterns as well as plain writes/delete/update.
fn immutable_import_meta_use(mut node: Node<'_>, source: &str) -> bool {
    let mut member_found = false;
    for _ in 0..MAX_STRING_EXPRESSION_DEPTH {
        let Some(parent) = node.parent() else {
            return false;
        };
        if wrapper_operand(parent).is_some_and(|operand| operand.id() == node.id()) {
            node = parent;
            continue;
        }
        if !parent
            .child_by_field_name("object")
            .is_some_and(|object| object.id() == node.id())
            || !["url", "filename", "dirname"]
                .iter()
                .any(|name| named_member(parent, name, source))
        {
            return false;
        }
        node = parent;
        member_found = true;
        break;
    }
    if !member_found {
        return false;
    }
    let origin = node;
    for _ in 0..MAX_STRING_EXPRESSION_DEPTH {
        let Some(parent) = node.parent() else {
            return true;
        };
        if matches!(
            parent.kind(),
            "assignment_expression" | "augmented_assignment_expression" | "for_in_statement"
        ) && parent.child_by_field_name("left").is_some_and(|left| {
            left.start_byte() <= origin.start_byte() && origin.end_byte() <= left.end_byte()
        }) {
            return false;
        }
        if parent.kind() == "update_expression"
            || (parent.kind() == "unary_expression" && keyword(parent, "delete"))
        {
            return false;
        }
        node = parent;
    }
    false
}

/// Recognize the actual CommonJS resolve member, not aliases, call/apply,
/// user-provided loaders, or arbitrary computed property expressions. Reuse
/// the ordinary require route/condition set: the engine already implements
/// resolve-only execution and policy checks over that same route. Capturing
/// the full source closure remains conservative (this is not asset discovery).
fn is_require_resolve(node: Node<'_>, source: &str) -> bool {
    let node = runtime_operand(node);
    if !matches!(node.kind(), "member_expression" | "subscript_expression") {
        return false;
    }
    if !node.child_by_field_name("object").is_some_and(|object| {
        let object = runtime_operand(object);
        object.kind() == "identifier" && object.utf8_text(source.as_bytes()) == Ok("require")
    }) {
        return false;
    }
    match node.kind() {
        "member_expression" => node
            .child_by_field_name("property")
            .is_some_and(|property| property.utf8_text(source.as_bytes()) == Ok("resolve")),
        "subscript_expression" => {
            node.child_by_field_name("index")
                .and_then(|index| literal(runtime_operand(index), source))
                .as_deref()
                == Some("resolve")
        }
        _ => false,
    }
}

fn is_require(node: Node<'_>, bytes: &[u8]) -> bool {
    let node = runtime_operand(node);
    (node.kind() == "identifier" && node.utf8_text(bytes) == Ok("require"))
        || (node.kind() == "member_expression"
            && node
                .child_by_field_name("object")
                .is_some_and(|n| runtime_operand(n).utf8_text(bytes) == Ok("module"))
            && node
                .child_by_field_name("property")
                .is_some_and(|n| n.utf8_text(bytes) == Ok("require")))
}

/// Evaluate only exact strings, without executing code, coercing a value or
/// consulting bindings. Every accepted operand is a string, so concatenation
/// and untagged template substitution cannot invoke user-defined behavior.
/// Keep UTF-16 until the complete value is assembled: surrogate halves may
/// join across operands, while a final lone surrogate is not a host path.
fn literal(node: Node<'_>, source: &str) -> Option<String> {
    let mut units = Vec::new();
    let mut budget = StringExpressionBudget::default();
    append_exact_string(node, source, &mut units, &mut budget, 0)?;
    let value = String::from_utf16(&units).ok()?;
    (value.len() <= super::MAX_PATH).then_some(value)
}

/// Enumerate only a bounded set of literal request results. Conditions are
/// never evaluated, and an unproved binding, call, coercion or unknown branch
/// invalidates the entire set. The ordinary AST walk still examines
/// every condition for nested loads, loader mutations and dynamic code.
/// Keep `literal` narrower: loader/factory identity must remain an exact
/// spelling, not a conditional expression with executable tests.
fn request_literals(
    node: Node<'_>,
    source: &str,
    bindings: &ConstStringBindings<'_>,
) -> Option<Vec<String>> {
    // Preserve the existing single-buffer path for ordinary package imports.
    if let Some(value) = literal(node, source) {
        return Some(vec![value]);
    }
    let mut budget = FiniteStringBudget::default();
    finite_strings(node, source, bindings, &mut budget, 0)?
        .into_iter()
        .map(|units| {
            let value = String::from_utf16(&units).ok()?;
            (value.len() <= super::MAX_PATH).then_some(value)
        })
        .collect()
}

struct FiniteStringBudget {
    expression: StringExpressionBudget,
    // Bound intermediate Cartesian-product copying independently of source
    // size and final unique values (many concatenations can deduplicate).
    copied_units: usize,
}

impl Default for FiniteStringBudget {
    fn default() -> Self {
        Self {
            expression: StringExpressionBudget::default(),
            copied_units: MAX_STRING_EXPRESSION_BYTES,
        }
    }
}

type StringAlternatives = BTreeSet<Vec<u16>>;

fn concatenate_strings(
    left: StringAlternatives,
    right: StringAlternatives,
    budget: &mut FiniteStringBudget,
) -> Option<StringAlternatives> {
    let mut result = BTreeSet::new();
    for prefix in &left {
        for suffix in &right {
            let size = prefix.len().checked_add(suffix.len())?;
            if size > super::MAX_PATH {
                return None;
            }
            budget.copied_units = budget.copied_units.checked_sub(size)?;
            let mut value = Vec::with_capacity(size);
            value.extend_from_slice(prefix);
            value.extend_from_slice(suffix);
            result.insert(value);
            if result.len() > MAX_STRING_ALTERNATIVES {
                return None;
            }
        }
    }
    Some(result)
}

fn finite_strings(
    node: Node<'_>,
    source: &str,
    bindings: &ConstStringBindings<'_>,
    budget: &mut FiniteStringBudget,
    depth: usize,
) -> Option<StringAlternatives> {
    if depth > MAX_STRING_EXPRESSION_DEPTH {
        return None;
    }
    budget.expression.nodes = budget.expression.nodes.checked_sub(1)?;
    match node.kind() {
        "parenthesized_expression"
        | "as_expression"
        | "satisfies_expression"
        | "non_null_expression" => {
            finite_strings(wrapper_operand(node)?, source, bindings, budget, depth + 1)
        }
        "identifier" => {
            let value = bindings
                .values
                .get(node.utf8_text(source.as_bytes()).ok()?)?;
            if node.start_byte() < value.available_after || node.end_byte() > value.scope_end {
                return None;
            }
            let mut alternatives = BTreeSet::new();
            for units in &value.alternatives {
                budget.expression.nodes = budget.expression.nodes.checked_sub(1)?;
                budget.copied_units = budget.copied_units.checked_sub(units.len())?;
                alternatives.insert(units.clone());
            }
            Some(alternatives)
        }
        "ternary_expression" => {
            let mut values = finite_strings(
                node.child_by_field_name("consequence")?,
                source,
                bindings,
                budget,
                depth + 1,
            )?;
            let alternative = finite_strings(
                node.child_by_field_name("alternative")?,
                source,
                bindings,
                budget,
                depth + 1,
            )?;
            values.extend(alternative);
            (values.len() <= MAX_STRING_ALTERNATIVES).then_some(values)
        }
        "binary_expression"
            if node
                .child_by_field_name("operator")
                .is_some_and(|operator| operator.kind() == "+") =>
        {
            let left = finite_strings(
                node.child_by_field_name("left")?,
                source,
                bindings,
                budget,
                depth + 1,
            )?;
            let right = finite_strings(
                node.child_by_field_name("right")?,
                source,
                bindings,
                budget,
                depth + 1,
            )?;
            concatenate_strings(left, right, budget)
        }
        "string" => {
            let spelling = source.get(node.byte_range())?;
            let quote = spelling.chars().next()?;
            if !matches!(quote, '\'' | '"') || !spelling.ends_with(quote) || spelling.len() < 2 {
                return None;
            }
            let mut units = Vec::new();
            append_string_segment(
                &spelling[1..spelling.len() - 1],
                false,
                &mut units,
                &mut budget.expression,
            )?;
            Some(BTreeSet::from([units]))
        }
        "template_string" => {
            let spelling = source.get(node.byte_range())?;
            if !spelling.starts_with('`') || !spelling.ends_with('`') || spelling.len() < 2 {
                return None;
            }
            let mut values = BTreeSet::from([Vec::new()]);
            let mut start = node.start_byte() + 1;
            let mut cursor = node.walk();
            for part in node.named_children(&mut cursor) {
                budget.expression.nodes = budget.expression.nodes.checked_sub(1)?;
                match part.kind() {
                    "string_fragment" | "escape_sequence" => {}
                    "template_substitution" => {
                        values = concatenate_segment(
                            values,
                            source.get(start..part.start_byte())?,
                            budget,
                        )?;
                        let mut children = part.walk();
                        let mut expression = None;
                        for child in part.named_children(&mut children) {
                            budget.expression.nodes = budget.expression.nodes.checked_sub(1)?;
                            if child.kind() != "comment" && expression.replace(child).is_some() {
                                return None;
                            }
                        }
                        let choices =
                            finite_strings(expression?, source, bindings, budget, depth + 1)?;
                        values = concatenate_strings(values, choices, budget)?;
                        start = part.end_byte();
                    }
                    _ => return None,
                }
            }
            concatenate_segment(values, source.get(start..node.end_byte() - 1)?, budget)
        }
        _ => None,
    }
}

fn concatenate_segment(
    values: StringAlternatives,
    text: &str,
    budget: &mut FiniteStringBudget,
) -> Option<StringAlternatives> {
    let mut units = Vec::new();
    append_string_segment(text, true, &mut units, &mut budget.expression)?;
    concatenate_strings(values, BTreeSet::from([units]), budget)
}

struct StringExpressionBudget {
    nodes: usize,
    bytes: usize,
}

impl Default for StringExpressionBudget {
    fn default() -> Self {
        Self {
            nodes: MAX_STRING_EXPRESSION_NODES,
            bytes: MAX_STRING_EXPRESSION_BYTES,
        }
    }
}

fn append_exact_string(
    node: Node<'_>,
    source: &str,
    units: &mut Vec<u16>,
    budget: &mut StringExpressionBudget,
    depth: usize,
) -> Option<()> {
    if depth > MAX_STRING_EXPRESSION_DEPTH {
        return None;
    }
    budget.nodes = budget.nodes.checked_sub(1)?;
    match node.kind() {
        "parenthesized_expression"
        | "as_expression"
        | "satisfies_expression"
        | "non_null_expression" => {
            append_exact_string(wrapper_operand(node)?, source, units, budget, depth + 1)
        }
        "binary_expression"
            if node
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "+") =>
        {
            append_exact_string(
                node.child_by_field_name("left")?,
                source,
                units,
                budget,
                depth + 1,
            )?;
            append_exact_string(
                node.child_by_field_name("right")?,
                source,
                units,
                budget,
                depth + 1,
            )
        }
        "string" => {
            let spelling = source.get(node.byte_range())?;
            let quote = spelling.chars().next()?;
            if !matches!(quote, '\'' | '"') || !spelling.ends_with(quote) || spelling.len() < 2 {
                return None;
            }
            append_string_segment(&spelling[1..spelling.len() - 1], false, units, budget)
        }
        "template_string" => {
            let spelling = source.get(node.byte_range())?;
            if !spelling.starts_with('`') || !spelling.ends_with('`') || spelling.len() < 2 {
                return None;
            }
            let mut start = node.start_byte() + 1;
            let mut cursor = node.walk();
            for part in node.named_children(&mut cursor) {
                budget.nodes = budget.nodes.checked_sub(1)?;
                match part.kind() {
                    "string_fragment" | "escape_sequence" => {}
                    "template_substitution" => {
                        append_string_segment(
                            source.get(start..part.start_byte())?,
                            true,
                            units,
                            budget,
                        )?;
                        let mut children = part.walk();
                        let mut expression = None;
                        for child in part.named_children(&mut children) {
                            budget.nodes = budget.nodes.checked_sub(1)?;
                            if child.kind() != "comment" && expression.replace(child).is_some() {
                                return None;
                            }
                        }
                        append_exact_string(expression?, source, units, budget, depth + 1)?;
                        start = part.end_byte();
                    }
                    _ => return None,
                }
            }
            append_string_segment(source.get(start..node.end_byte() - 1)?, true, units, budget)
        }
        _ => None,
    }
}

// A small decoder fixture used below; production assembles all expression
// fragments before requiring a valid Unicode path.
#[cfg(test)]
fn decode_literal(text: &str) -> Option<String> {
    let quote = text.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') || !text.ends_with(quote) || text.len() < 2 {
        return None;
    }
    let mut units = Vec::new();
    append_string_segment(
        &text[1..text.len() - 1],
        quote == '`',
        &mut units,
        &mut StringExpressionBudget::default(),
    )?;
    let value = String::from_utf16(&units).ok()?;
    (value.len() <= super::MAX_PATH).then_some(value)
}

/// Decode a cooked string/template fragment with bounded work and storage.
/// Template CR and CRLF normalize to LF; escape-produced CR does not. Legacy
/// octal remains opaque. Code-point escapes may contain leading zeroes and
/// surrogate code units, as JavaScript permits.
fn append_string_segment(
    text: &str,
    template: bool,
    units: &mut Vec<u16>,
    budget: &mut StringExpressionBudget,
) -> Option<()> {
    budget.bytes = budget.bytes.checked_sub(text.len())?;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let value = if c != '\\' {
            if c == '\r' && template {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                u32::from('\n')
            } else if matches!(c, '\n' | '\r') && !template {
                return None;
            } else {
                u32::from(c)
            }
        } else {
            match chars.next()? {
                '\n' => continue,
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    continue;
                }
                '\u{2028}' | '\u{2029}' => continue,
                'n' => u32::from('\n'),
                'r' => u32::from('\r'),
                't' => u32::from('\t'),
                'b' => 8,
                'f' => 12,
                'v' => 11,
                '0' if !chars.peek().is_some_and(char::is_ascii_digit) => 0,
                '0'..='9' => return None,
                'x' => read_hex(&mut chars, 2)?,
                'u' => {
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        let mut value = 0_u32;
                        let mut count = 0;
                        loop {
                            let c = chars.next()?;
                            if c == '}' {
                                break;
                            }
                            count += 1;
                            value = value.checked_mul(16)?.checked_add(c.to_digit(16)?)?;
                        }
                        if count == 0 {
                            return None;
                        }
                        value
                    } else {
                        read_hex(&mut chars, 4)?
                    }
                }
                escaped => u32::from(escaped),
            }
        };
        if let Ok(unit) = u16::try_from(value) {
            if units.len() >= super::MAX_PATH {
                return None;
            }
            units.push(unit);
        } else {
            let c = char::from_u32(value)?;
            if units.len().checked_add(c.len_utf16())? > super::MAX_PATH {
                return None;
            }
            units.extend(c.encode_utf16(&mut [0_u16; 2]).iter().copied());
        }
    }
    Some(())
}

fn read_hex(chars: &mut impl Iterator<Item = char>, count: usize) -> Option<u32> {
    let mut value = 0;
    for _ in 0..count {
        value = value * 16 + chars.next()?.to_digit(16)?;
    }
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
    fn graph(root: &Path) -> CapturedModuleGraph {
        capture(root, "app.mjs", GraphOptions::default()).unwrap()
    }
    fn paths(g: &CapturedModuleGraph) -> Vec<&str> {
        g.report
            .modules
            .iter()
            .map(|n| n.id.path.as_str())
            .collect()
    }

    #[test]
    fn static_import_reexport_cycles_and_diamonds_capture_each_identity_once() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './a.mjs'; export * from './b.mjs';",
        );
        put(root.path(), "a.mjs", "export {x} from './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(
            root.path(),
            "shared.mjs",
            "import './app.mjs'; export const x=1;",
        );
        let g = graph(root.path());
        assert_eq!(paths(&g), ["a.mjs", "app.mjs", "b.mjs", "shared.mjs"]);
        assert_eq!(g.report.edges.len(), 5);
        assert!(g.report.fully_resolved);
        assert!(!g.report.runtime_completeness);
    }

    #[test]
    fn mixed_import_and_require_use_their_own_conditions() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import 'dual'; import './bridge.cjs';",
        );
        put(root.path(), "bridge.cjs", "module.exports=require('dual');");
        put(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{"import":"./esm.mjs","require":"./cjs.cjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/dual/esm.mjs",
            "export default 1;",
        );
        put(
            root.path(),
            "node_modules/dual/cjs.cjs",
            "module.exports=1;",
        );
        let g = graph(root.path());
        assert_eq!(g.report.modules.len(), 4);
        assert!(g.report.fully_resolved);
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| !e.mappings.is_empty())
                .count(),
            2
        );
    }

    #[test]
    fn literals_are_decoded_but_comments_and_string_decoys_are_not_edges() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "// import 'missing'\nconst s=\"require('missing')\"; import './li\\u0062.mjs'; import(`./other.mjs`);",
        );
        put(root.path(), "lib.mjs", "export default 1;");
        put(root.path(), "other.mjs", "");
        let g = graph(root.path());
        assert_eq!(g.report.edges.len(), 2);
        assert!(g.report.fully_resolved);
        assert_eq!(g.report.edges[1].kind, LoadKind::DynamicImport);
    }

    fn scan_string_request(expression: &str, language: SourceLanguage) -> Option<String> {
        let mut values = scan_string_requests(expression, language);
        assert_eq!(values.len(), 1, "{expression}: {values:?}");
        values.pop().unwrap()
    }

    fn scan_string_requests(expression: &str, language: SourceLanguage) -> Vec<Option<String>> {
        let source = format!("require({expression});");
        scan_source_requests(&source, language)
    }

    fn scan_source_requests(source: &str, language: SourceLanguage) -> Vec<Option<String>> {
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            language,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed, "{source}: {notices:?}");
        assert!(notices.is_empty(), "{source}: {notices:?}");
        loads.into_iter().map(|load| load.specifier).collect()
    }

    #[test]
    fn const_request_strings_capture_prior_primitives_through_all_load_consumers() {
        for (source, language, expected) in [
            (
                "const prefix='./', leaf='dep', suffix='.cjs'; const target=prefix+leaf+suffix; const alias=(target); require(alias); require.resolve(target); import(target);",
                SourceLanguage::JavaScript,
                vec!["./dep.cjs", "./dep.cjs", "./dep.cjs"],
            ),
            (
                "const leaf=flag?'one':'two'; const target=`./${leaf}.cjs`; require(target);",
                SourceLanguage::JavaScript,
                vec!["./one.cjs", "./two.cjs"],
            ),
            (
                "const target='./dep.cjs'; const load=require; function nested(){return load(target);} console.log(target.length, {target});",
                SourceLanguage::JavaScript,
                vec!["./dep.cjs"],
            ),
            (
                "import {createRequire as make} from 'node:module'; const load=make(import.meta.url); const target='./dep.cjs'; load(target); load.resolve(target);",
                SourceLanguage::JavaScript,
                vec!["node:module", "./dep.cjs", "./dep.cjs"],
            ),
            (
                "type target = string; const target=('./dep.cjs' as const); require((target satisfies string)!); export {target};",
                SourceLanguage::TypeScript,
                vec!["./dep.cjs"],
            ),
            (
                "const high='\\uD83D', low='\\uDE00'; const target='./'+high+low+'.cjs'; require(target);",
                SourceLanguage::JavaScript,
                vec!["./😀.cjs"],
            ),
        ] {
            assert_eq!(
                scan_source_requests(source, language),
                expected
                    .into_iter()
                    .map(|value| Some(value.to_owned()))
                    .collect::<Vec<_>>(),
                "{source}",
            );
        }
    }

    #[test]
    fn lexical_const_request_strings_capture_function_blocks_and_exports() {
        for (source, language, expected) in [
            (
                "{const target='./dep.cjs'; require(target); require.resolve(target);}",
                SourceLanguage::JavaScript,
                vec!["./dep.cjs", "./dep.cjs"],
            ),
            (
                "function nested(){const target='./dep.cjs'; return require(target);}",
                SourceLanguage::JavaScript,
                vec!["./dep.cjs"],
            ),
            (
                "const prefix='./'; function nested(){const leaf=flag?'one':'two'; const target=`${prefix}${leaf}.cjs`; return ()=>require(target);}",
                SourceLanguage::JavaScript,
                vec!["./one.cjs", "./two.cjs"],
            ),
            (
                "const loader={load(){const target='./dep.cjs'; return require(target);}};",
                SourceLanguage::JavaScript,
                vec!["./dep.cjs"],
            ),
            (
                "async function load(){const target='./dep.mjs'; return import(target);}",
                SourceLanguage::JavaScript,
                vec!["./dep.mjs"],
            ),
            (
                "import {createRequire} from 'node:module'; const load=createRequire(import.meta.url); function nested(){const target='./dep.cjs'; return load(target);}",
                SourceLanguage::JavaScript,
                vec!["node:module", "./dep.cjs"],
            ),
            (
                "export const target='./dep.mjs'; import(target);",
                SourceLanguage::JavaScript,
                vec!["./dep.mjs"],
            ),
            (
                "function load(){type target=string; const target=('./dep.cjs' as const); return require((target satisfies string)!);}",
                SourceLanguage::TypeScript,
                vec!["./dep.cjs"],
            ),
        ] {
            assert_eq!(
                scan_source_requests(source, language),
                expected.into_iter().map(|value| Some(value.to_owned())).collect::<Vec<_>>(),
                "{source}",
            );
        }
    }

    #[test]
    fn lexical_const_request_strings_never_escape_scope_or_skip_binding_proof() {
        for source in [
            "{const target='./dep.cjs';} require(target);",
            "{const target='./dep.cjs';} {require(target);}",
            "function first(){const target='./dep.cjs';} function second(){return require(target);}",
            "function nested(){const target='./dep.cjs';} require(target);",
            "{const target='./dep.cjs';} const alias=target; require(alias);",
            "{require(target); const target='./dep.cjs';}",
            "function nested(){const first=second; const second='./dep.cjs'; return require(first);}",
            "function nested(){const target='./dep.cjs'; target='./other.cjs'; return require(target);}",
            "function nested(target){{const target='./dep.cjs'; return require(target);}}",
            "function nested(){const target='./dep.cjs'; function shadow(target){} return require(target);}",
            "function nested(){const target=flag?'./dep.cjs':unknown; return require(target);}",
            "function first(){const target='./dep.cjs'; return require(target);} function second(){const target='./other.cjs';}",
            "for(const target of ['./dep.cjs']){require(target);}",
            "switch(flag){case 1: const target='./dep.cjs'; require(target);}",
        ] {
            assert_eq!(
                scan_source_requests(source, SourceLanguage::JavaScript),
                vec![None],
                "unproved lexical binding: {source}",
            );
        }
    }

    #[test]
    fn const_request_strings_reject_shadowing_mutation_and_unknown_bindings() {
        for interference in [
            "target='./other.cjs';",
            "target += '.cjs';",
            "++target;",
            "(target)='./other.cjs';",
            "[target]=values;",
            "({target}=values);",
            "({key:target}=values);",
            "({target='./other.cjs'}=values);",
            "for(target of values){}",
            "for(target in values){}",
            "{ const target='./other.cjs'; }",
            "{ let target; }",
            "function nested(target){}",
            "function nested({target}){}",
            "function nested(...target){}",
            "function nested(target='./other.cjs'){}",
            "const nested=target=>0;",
            "const nested=({target})=>0;",
            "const nested=function target(){};",
            "const nested=class target{};",
            "try{}catch(target){}",
            "try{}catch({target}){}",
            "function nested(){var target;}",
            "function nested(targ\\u0065t){}",
        ] {
            let source = format!("const target='./dep.cjs'; {interference} require(target);");
            assert_eq!(
                scan_source_requests(&source, SourceLanguage::JavaScript),
                vec![None],
                "unproved binding: {source}",
            );
        }
        for source in [
            "let target='./dep.cjs'; require(target);",
            "var target='./dep.cjs'; require(target);",
            "const target=runtimeName; require(target);",
            "const target=getName(); require(target);",
            "const target=names.path; require(target);",
            "const {target}=names; require(target);",
            "const targ\\u0065t='./dep.cjs'; require(target);",
        ] {
            assert_eq!(
                scan_source_requests(source, SourceLanguage::JavaScript),
                vec![None],
                "{source}",
            );
        }
    }

    #[test]
    fn const_request_strings_keep_choices_atomic_and_bindings_in_source_order() {
        for source in [
            "require(target); const target='./dep.cjs';",
            "const first=second; const second='./dep.cjs'; require(first);",
            "const target=target; require(target);",
            "function nested(){return require(target);} const target='./dep.cjs'; nested();",
            "const target='./dep.cjs'; function nested(target){} const alias=target; require(alias);",
            "const target=flag?'./dep.cjs':unknown; require(target);",
            "const target='./dep.cjs'; require(flag?target:unknown);",
            "const target=flag?'./dep.cjs':('./other.cjs', './dep.cjs'); require(target);",
            "const target=flag?'./dep.cjs':1; require(target);",
            "const target=flag?'./dep.cjs':'\\uD800'; require(target);",
            "const target='./dep.cjs'; const alias=target; target='./other.cjs'; require(alias);",
        ] {
            assert_eq!(
                scan_source_requests(source, SourceLanguage::JavaScript),
                vec![None],
                "partial or reordered inference: {source}",
            );
        }
    }

    #[test]
    fn const_request_strings_preserve_literal_edges_and_dynamic_code_diagnostics() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "dep.cjs", "module.exports=42;");
        put(
            root.path(),
            "app.cjs",
            "const target='./dep.cjs'; function nested(target){} require('./dep.cjs'); require(target);",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_eq!(paths(&graph), ["app.cjs", "dep.cjs"]);
        assert_eq!(graph.report().edges[0].state, EdgeState::Resolved);
        assert_eq!(graph.report().edges[1].state, EdgeState::NonLiteral);
        assert!(!graph.report().fully_resolved);
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            registry::PinnedModuleRegistry::new(graph, &pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE",
        );
        for dynamic in ["eval('target');", "Function('return 1');", "with(scope){}"] {
            put(
                root.path(),
                "app.cjs",
                &format!("const target='./dep.cjs'; {dynamic} require(target);"),
            );
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(!graph.report().fully_resolved, "{dynamic}");
            assert!(!graph.report().diagnostics.is_empty(), "{dynamic}");
        }
    }

    #[test]
    fn const_request_strings_bound_alternatives_and_total_alias_copy_work() {
        let variants = (0..MAX_STRING_ALTERNATIVES)
            .map(|index| format!("./variant-{index:02}.cjs"))
            .collect::<Vec<_>>();
        let mut expression = format!("'{}'", variants.last().unwrap());
        for value in variants.iter().rev().skip(1) {
            expression = format!("flag ? '{value}' : ({expression})");
        }
        assert_eq!(
            scan_source_requests(
                &format!("const target={expression}; require(target);"),
                SourceLanguage::JavaScript,
            ),
            variants.into_iter().map(Some).collect::<Vec<_>>(),
        );
        assert_eq!(
            scan_source_requests(
                &format!("const target=flag?'./overflow.cjs':({expression}); require(target);"),
                SourceLanguage::JavaScript,
            ),
            vec![None],
        );
        let path = "a".repeat(super::super::MAX_PATH);
        let mut source = format!("const name0='{path}';");
        for index in 1..=MAX_STRING_EXPRESSION_BYTES / path.len() + 1 {
            source.push_str(&format!("const name{index}=name{};", index - 1));
        }
        let last = MAX_STRING_EXPRESSION_BYTES / path.len() + 1;
        source.push_str(&format!("require(name{last});"));
        assert_eq!(
            scan_source_requests(&source, SourceLanguage::JavaScript),
            vec![None]
        );
        assert_eq!(
            scan_source_requests(
                &format!(
                    "const target='{}'; require(target);",
                    "é".repeat(super::super::MAX_PATH)
                ),
                SourceLanguage::JavaScript,
            ),
            vec![None],
        );
    }

    #[test]
    fn const_request_strings_share_capture_syntax_and_site_limits() {
        let source = "const target=flag?'./one.cjs':'./two.cjs'; require(target);";
        for mut budget in [
            Budget {
                ast_nodes: MAX_AST_NODES - 1,
                ..Budget::default()
            },
            Budget {
                sites: MAX_SITES - 1,
                ..Budget::default()
            },
        ] {
            assert_eq!(
                scan(
                    &mut Parser::new(),
                    source.as_bytes(),
                    SourceLanguage::JavaScript,
                    &mut budget
                )
                .unwrap_err()
                .code,
                "ERR_MODULE_GRAPH_LIMIT",
            );
        }
        let mut source = (0..=MAX_SITES)
            .map(|index| format!("const target{index}='./dep.cjs';"))
            .collect::<String>();
        source.push_str("require(target0);");
        assert_eq!(
            scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap_err()
            .code,
            "ERR_MODULE_GRAPH_LIMIT",
        );
    }

    #[test]
    fn const_request_routes_preserve_capsule_sources_absence_context_and_pin() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let source = "const name='pkg'; const optional='optional'; require(name); try{require(optional)}catch(error){}";
        put(root.path(), "app.cjs", source);
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        let package_source = "const leaf=flag?'one':'two'; const target=`./${leaf}.cjs`; module.exports=require(target);";
        put(root.path(), "node_modules/pkg/index.cjs", package_source);
        put(root.path(), "node_modules/pkg/one.cjs", "module.exports=1;");
        put(root.path(), "node_modules/pkg/two.cjs", "module.exports=2;");
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().diagnostics.is_empty());
        assert_eq!(captured.report().modules.len(), 4);
        assert_eq!(captured.report().edges.len(), 4);
        assert!(
            !captured.report().fully_resolved,
            "captured optional absence stays explicit"
        );
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "app.cjs",
            "throw new Error('live entry changed');",
        );
        put(
            root.path(),
            "node_modules/pkg/index.cjs",
            "throw new Error('live package changed');",
        );
        put(
            root.path(),
            "node_modules/pkg/one.cjs",
            "module.exports=100;",
        );
        put(
            root.path(),
            "node_modules/pkg/extra.cjs",
            "module.exports=999;",
        );
        put(
            root.path(),
            "node_modules/optional/index.js",
            "module.exports='new live package';",
        );
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Require)
            .unwrap();
        assert_eq!(entry.source(), source);
        let package = registry
            .lookup(Some(entry.id()), "pkg", RequestStyle::Require)
            .unwrap();
        assert_eq!(package.source(), package_source);
        for (request, expected) in [
            ("./one.cjs", "module.exports=1;"),
            ("./two.cjs", "module.exports=2;"),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(package.id()), request, RequestStyle::Require)
                    .unwrap()
                    .source(),
                expected
            );
        }
        assert_eq!(
            registry
                .lookup(Some(entry.id()), "optional", RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "MODULE_NOT_FOUND",
        );
        for (from, request, style) in [
            (entry.id(), "./one.cjs", RequestStyle::Require),
            (package.id(), "./one.cjs", RequestStyle::Import),
            (package.id(), "./extra.cjs", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(from), request, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE",
            );
        }
        put(root.path(), "app.cjs", source);
        put(root.path(), "node_modules/pkg/index.cjs", package_source);
        let changed = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_ne!(changed.report().input_hash, pin);
        assert!(PinnedModuleRegistry::new(changed, &pin).is_err());
    }

    #[test]
    fn lexical_const_npm_graph_replays_sources_absence_and_exact_routes() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};

        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "module.exports=require('scoped-fixture');");
        put(root.path(), "node_modules/scoped-fixture/package.json", r#"{"main":"index.cjs"}"#);
        let package_source = r#"
const prefix='./';
function load(flag) {
    const leaf=flag?'one':'two';
    { const target=prefix+leaf+'.cjs'; return require(target); }
}
function lookup() { const selected='./one.cjs'; return require.resolve(selected); }
function optional() {
    const absent='optional-addon';
    try { return require(absent); } catch(error) { return error.code; }
}
module.exports={load,lookup,optional};
"#;
        put(root.path(), "node_modules/scoped-fixture/index.cjs", package_source);
        put(root.path(), "node_modules/scoped-fixture/one.cjs", "module.exports=41;");
        put(root.path(), "node_modules/scoped-fixture/two.cjs", "module.exports=42;");
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().diagnostics.is_empty());
        assert_eq!(captured.report().modules.len(), 4);
        assert_eq!(captured.report().edges.len(), 5);
        assert!(!captured.report().fully_resolved, "optional absence remains explicit");
        let pin = captured.report().input_hash.clone();
        let encoded = super::capsule::encode(&captured).unwrap();
        std::fs::rename(root.path().join("node_modules"), root.path().join("original_packages")).unwrap();
        put(root.path(), "node_modules/scoped-fixture/index.js", "throw new Error('live package');");
        put(root.path(), "node_modules/optional-addon/index.js", "module.exports=999;");

        let replayed = super::capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        assert_eq!(registry.summary().routes, 4);
        assert_eq!(registry.summary().missing_routes, 1);
        let package = registry.lookup(Some(registry.entrypoint()), "scoped-fixture", RequestStyle::Require).unwrap();
        assert_eq!(package.source(), package_source);
        for (request, expected) in [("./one.cjs", "module.exports=41;"), ("./two.cjs", "module.exports=42;")] {
            assert_eq!(registry.lookup(Some(package.id()), request, RequestStyle::Require).unwrap().source(), expected);
        }
        assert_eq!(registry.lookup(Some(package.id()), "optional-addon", RequestStyle::Require).err().unwrap().code,
            "MODULE_NOT_FOUND");
        for (importer, request, style) in [
            (registry.entrypoint(), "./one.cjs", RequestStyle::Require),
            (package.id(), "./one.cjs", RequestStyle::Import),
            (package.id(), "./extra.cjs", RequestStyle::Require),
        ] {
            assert_eq!(registry.lookup(Some(importer), request, style).err().unwrap().code,
                "ERR_MODULE_REGISTRY_ROUTE");
        }
        let changed = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_eq!(PinnedModuleRegistry::new(changed, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_PIN_MISMATCH");
    }

    #[test]
    fn commonjs_require_const_aliases_capture_exact_calls_and_resolve_routes() {
        for (source, language) in [
            (
                "const load=require; load('./dep.cjs'); load.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const first=(require), second=((first)); const third=second; third('./' + 'dep.cjs'); third['res' + 'olve'](`./${'dep'}.cjs`);",
                SourceLanguage::JavaScript,
            ),
            (
                "const load=require; function nested(){return load('./dep.cjs');} const later=()=>load.resolve('./dep.cjs'); if(typeof load==='function') nested(); function ownArguments(){return arguments.length;}",
                SourceLanguage::JavaScript,
            ),
            (
                "const load=require; load?.('./dep.cjs'); load?.resolve?.('./dep.cjs'); function ownArguments(){return {[arguments.length](){return arguments.length;}};}",
                SourceLanguage::JavaScript,
            ),
            (
                "type load=unknown; interface next {} const load: Loader=(require as Loader); const next: Loader=load!; (next as Loader)('./dep.cjs'); (next.resolve as Resolver)('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 2, "{source}: {loads:?}");
            for load in loads {
                assert_eq!(load.kind, LoadKind::Require, "{source}");
                assert_eq!(load.specifier.as_deref(), Some("./dep.cjs"), "{source}");
                assert!(!load.type_only);
            }
        }
    }

    #[test]
    fn single_assignment_loader_declarations_capture_bundled_npm_requests() {
        for (source, language) in [
            (
                "var load=require, next=load; next('./dep.cjs'); next.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "'use strict'; function unused(){} let load=require; const next=load; function run(){return next('./dep.cjs');} next.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire} from 'module'; var __require = /* @__PURE__ */ createRequire(import.meta.url); try{__require.resolve('./dep.cjs'); __require('./dep.cjs');}catch(error){}",
                SourceLanguage::JavaScript,
            ),
            (
                "import * as mod from 'node:module'; let local=mod.createRequire(import.meta.url); var next=local; next('./dep.cjs'); next['resolve']('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "var mod=require('node:module'), local=mod.createRequire(__filename), next=local; next('./dep.cjs'); next.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "let {createRequire:make}=require('node:module'); var local=make(__filename); let next=local; next('./dep.cjs'); next.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire as make} from 'node:module'; var local: Loader=(make(import.meta.url) as Loader); let next: Loader=local!; (next as Loader)('./dep.cjs'); next.resolve('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
            let requests: Vec<_> = loads
                .iter()
                .filter(|load| load.specifier.as_deref() == Some("./dep.cjs"))
                .collect();
            assert_eq!(requests.len(), 2, "{source}: {loads:?}");
            assert!(
                requests
                    .iter()
                    .all(|load| load.kind == LoadKind::Require && !load.type_only)
            );
        }
    }

    #[test]
    fn single_assignment_loaders_reject_mutation_shadowing_escape_and_early_execution() {
        for declaration in ["var", "let"] {
            for body in [
                "load=other;",
                "load+=other;",
                "load++;",
                "({load}=other);",
                "for(load of values){}",
                "for(load in values){}",
                "load.resolve=other;",
                "Object.assign(load,{resolve:other});",
                "Object.defineProperty(load,'resolve',{value:other});",
                "const escaped={load};",
                "consume(load);",
                "export {load};",
                "function shadow(load){load('./outside.cjs');}",
                "{let load=other; load('./outside.cjs');}",
                "try{}catch(load){load('./outside.cjs');}",
                "var load;",
                "load.call(null,'./dep.cjs');",
                "load.apply(null,['./dep.cjs']);",
                "const resolve=load.resolve; resolve('./dep.cjs');",
                "require=other;",
                "arguments[1]=other;",
                "(()=>{arguments[1]=other;})();",
                "eval('load=other');",
                "function shadow(lo\\u0061d){}",
            ] {
                let source = format!("{declaration} load=require; {body} load('./dep.cjs');");
                let (_, notices, analyzed) = scan(
                    &mut Parser::new(),
                    source.as_bytes(),
                    SourceLanguage::JavaScript,
                    &mut Budget::default(),
                )
                .unwrap();
                assert!(analyzed, "{source}: {notices:?}");
                assert!(
                    !notices.is_empty(),
                    "unproved loader became complete: {source}"
                );
            }
            for source in [
                format!("load('./dep.cjs'); {declaration} load=require;"),
                format!("function run(){{load('./dep.cjs');}} {declaration} load=require; run();"),
                format!("run(); {declaration} load=require; function run(){{load('./dep.cjs');}}"),
                format!(
                    "const value=run(); {declaration} load=require; function run(){{load('./dep.cjs');}}"
                ),
                format!(
                    "{declaration} load=require, value=run(); function run(){{load('./dep.cjs');}}"
                ),
                format!("{declaration} first=second, second=require; first('./dep.cjs');"),
                format!("{declaration} load; load=require; load('./dep.cjs');"),
                format!("function nested(){{{declaration} load=require; load('./dep.cjs');}}"),
            ] {
                let (_, notices, analyzed) = scan(
                    &mut Parser::new(),
                    source.as_bytes(),
                    SourceLanguage::JavaScript,
                    &mut Budget::default(),
                )
                .unwrap();
                assert!(analyzed, "{source}: {notices:?}");
                assert!(
                    !notices.is_empty(),
                    "unproved initialization became complete: {source}"
                );
            }
            let factory = "import {createRequire as make} from 'node:module';";
            for body in [
                format!("{declaration} load=make(import.meta.url); load=other; load('./dep.cjs');"),
                format!(
                    "run(); {declaration} load=make(import.meta.url); function run(){{load('./dep.cjs');}}"
                ),
                format!(
                    "{declaration} load=make(import.meta.url); import.meta.url='file:///other.mjs'; load('./dep.cjs');"
                ),
                format!("{declaration} load=make('/other.mjs'); load('./dep.cjs');"),
                format!(
                    "{declaration} load=make(import.meta.url); function shadow(make){{}} load('./dep.cjs');"
                ),
            ] {
                let source = format!("{factory}{body}");
                let (_, notices, analyzed) = scan(
                    &mut Parser::new(),
                    source.as_bytes(),
                    SourceLanguage::JavaScript,
                    &mut Budget::default(),
                )
                .unwrap();
                assert!(analyzed, "{source}: {notices:?}");
                assert!(
                    !notices.is_empty(),
                    "unproved factory became complete: {source}"
                );
            }
        }
    }

    #[test]
    fn single_assignment_factories_cannot_hoist_initialization_or_hide_executable_defaults() {
        for factory in ["const", "let", "var"] {
            for loader in ["const", "let", "var"] {
                for source in [
                    format!(
                        "{loader} load=make(__filename); {factory} {{createRequire:make}}=require('node:module'); load('./dep.cjs');"
                    ),
                    format!(
                        "{loader} load=mod.createRequire(__filename); {factory} mod=require('node:module'); load('./dep.cjs');"
                    ),
                    format!(
                        "{factory} {{createRequire:make, missing=invoke()}}=require('node:module'); {loader} load=make(__filename); function invoke(){{return load('./dep.cjs');}} load('./dep.cjs');"
                    ),
                ] {
                    let (_, notices, analyzed) = scan(
                        &mut Parser::new(),
                        source.as_bytes(),
                        SourceLanguage::JavaScript,
                        &mut Budget::default(),
                    )
                    .unwrap();
                    assert!(analyzed, "{source}: {notices:?}");
                    assert!(
                        !notices.is_empty(),
                        "unproved factory initialization became complete: {source}"
                    );
                }
            }
        }
    }

    #[test]
    fn bundled_loader_graph_replays_exact_sources_missing_packages_and_route_authority() {
        use super::registry::{ModuleKind, PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        // fdir 6.5.0's Rolldown prelude uses var, then resolve + require for
        // an optional package. Capture both operations without running either.
        let source = "import {createRequire} from 'node:module'; var load=createRequire(import.meta.url), next=load; next.resolve('matcher'); next('matcher'); try{next('optional')}catch(error){}";
        put(root.path(), "app.mjs", source);
        put(
            root.path(),
            "node_modules/matcher/package.json",
            r#"{"exports":{"require":"./index.cjs","import":"./wrong.mjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/matcher/index.cjs",
            "var load=require; module.exports=load('./leaf.cjs');",
        );
        put(
            root.path(),
            "node_modules/matcher/leaf.cjs",
            "module.exports=42;",
        );
        put(
            root.path(),
            "node_modules/matcher/wrong.mjs",
            "throw Error('wrong conditions');",
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(graph.report().diagnostics.is_empty());
        assert_eq!(
            paths(&graph),
            [
                "app.mjs",
                "node_modules/matcher/index.cjs",
                "node_modules/matcher/leaf.cjs"
            ]
        );
        let pin = graph.report().input_hash.clone();
        let capsule = super::capsule::encode(&graph).unwrap();
        std::fs::rename(
            root.path().join("node_modules"),
            root.path().join("original_packages"),
        )
        .unwrap();
        put(root.path(), "app.mjs", "throw Error('live entry changed');");
        put(
            root.path(),
            "node_modules/optional/index.js",
            "module.exports='new';",
        );
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), graph.report());
        let registry = PinnedModuleRegistry::new_with_kind_resolver(
            replayed,
            &pin,
            |module, _, _| match (module.source_language, module.format_hint.as_str()) {
                (SourceLanguage::JavaScript, "commonjs") => Ok(ModuleKind::CommonJs),
                (SourceLanguage::JavaScript, "module") => Ok(ModuleKind::EsModule),
                _ => Err(error("ERR_TEST_MODULE_KIND", "unexpected fixture format")),
            },
            |specifier, style| {
                (specifier == "node:module" && style == RequestStyle::Import)
                    .then_some("node:module")
            },
        )
        .unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Import)
            .unwrap();
        assert_eq!(entry.source(), source);
        let package = registry
            .lookup(Some(entry.id()), "matcher", RequestStyle::Require)
            .unwrap();
        assert_eq!(
            package.source(),
            "var load=require; module.exports=load('./leaf.cjs');"
        );
        assert_eq!(
            registry
                .lookup(Some(package.id()), "./leaf.cjs", RequestStyle::Require)
                .unwrap()
                .source(),
            "module.exports=42;"
        );
        assert_eq!(
            registry
                .lookup(Some(entry.id()), "optional", RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "MODULE_NOT_FOUND"
        );
        for (from, request, style) in [
            (entry.id(), "matcher", RequestStyle::Import),
            (entry.id(), "./leaf.cjs", RequestStyle::Require),
            (package.id(), "optional", RequestStyle::Require),
            (package.id(), "./new.cjs", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(from), request, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
        put(
            root.path(),
            "app.mjs",
            "var load=require; load=other; load('matcher');",
        );
        let mutable = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let mutable_pin = mutable.report().input_hash.clone();
        assert_eq!(
            PinnedModuleRegistry::new(mutable, &mutable_pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );
    }

    #[test]
    fn commonjs_require_aliases_refuse_shadowing_mutation_and_escaped_origins() {
        for body in [
            "load=replacement;",
            "load.resolve=replacement;",
            "Object.assign(load, {resolve:replacement});",
            "const escaped={load};",
            "consume(load);",
            "export {load};",
            "let next=load; next=other; next('./dep.cjs');",
            "function nested(){const next=load; next('./dep.cjs');}",
            "function shadow(load){load('./dep.cjs');}",
            "const shadow=(load)=>load('./dep.cjs');",
            "function load(){}",
            "{const load=replacement; load('./dep.cjs');}",
            "try {} catch(load) {load('./dep.cjs');}",
            "const {load}=replacement;",
            "({load}=replacement);",
            "for(load of values){}",
            "load.call(null, './dep.cjs');",
            "load.apply(null, ['./dep.cjs']);",
            "const resolve=load.resolve; resolve('./dep.cjs');",
            "load.resolve('./dep.cjs', {paths:['other']});",
            "load[property]('./dep.cjs');",
            "eval('require=replacement');",
            "(eval)('load=replacement');",
            "with(context){load('./dep.cjs');}",
            "require=replacement;",
            "function shadow(require){}",
            "arguments[1]=replacement;",
            "const escapedArguments=arguments;",
            "(()=>{arguments[1]=replacement;})();",
            "lo\\u0061d=replacement;",
            "function shadow(lo\\u0061d){}",
            "\\u0072equire=replacement;",
        ] {
            let source = format!("const load=require; {body} load('./dep.cjs');");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                !notices.is_empty(),
                "unproved alias became complete: {source}"
            );
        }
        for source in [
            "let load; load=require; load('./dep.cjs');",
            "var load; load=require; load('./dep.cjs');",
            "const first=second; const second=require; first('./dep.cjs');",
            "const load=(0, require); load('./dep.cjs');",
            "const load=condition ? require : other; load('./dep.cjs');",
            "const load=module.require; load('./dep.cjs');",
            "const {load}=require; load('./dep.cjs');",
            "function nested(){const load=require; load('./dep.cjs');}",
            "import {createRequire as require} from 'node:module'; const load=require; load('./dep.cjs');",
            "import {createRequire} from 'node:module'; const load=require; const require=createRequire(import.meta.url); load('./dep.cjs');",
            "({[arguments[1]=replacement](){}}); const load=require; load('./dep.cjs');",
            "class Example {[arguments[1]=replacement](){}} const load=require; load('./dep.cjs');",
        ] {
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                !notices.is_empty(),
                "unsupported alias became complete: {source}"
            );
        }
    }

    #[test]
    fn commonjs_require_aliases_preserve_nonliteral_requests_and_binding_bounds() {
        let source =
            "const load=require; const next=load; next(request); next.resolve(`./${name}.cjs`);";
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed);
        assert!(notices.is_empty(), "{notices:?}");
        assert_eq!(loads.len(), 2);
        assert!(
            loads
                .iter()
                .all(|load| load.kind == LoadKind::Require && load.specifier.is_none())
        );

        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", source);
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved);
        assert!(
            captured
                .report()
                .edges
                .iter()
                .all(|edge| edge.state == EdgeState::NonLiteral)
        );
        let pin = captured.report().input_hash.clone();
        assert_eq!(
            registry::PinnedModuleRegistry::new(captured, &pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );

        let source = (0..=MAX_SITES)
            .map(|index| format!("const load{index}=require;"))
            .collect::<String>();
        let failure = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.code, "ERR_MODULE_GRAPH_LIMIT");
    }

    #[test]
    fn commonjs_require_alias_capsules_preserve_importer_routes_and_optional_absence() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let source = "const load=require; const next=load; next('pkg'); next('./value.cjs'); try{next('optional')}catch(error){}";
        put(root.path(), "app.cjs", source);
        put(root.path(), "value.cjs", "module.exports=42;");
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/pkg/index.cjs",
            "const read=require; module.exports=read('./value.cjs');",
        );
        put(
            root.path(),
            "node_modules/pkg/value.cjs",
            "module.exports=17;",
        );
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().diagnostics.is_empty());
        assert_eq!(captured.report().edges.len(), 4);
        assert!(
            !captured.report().fully_resolved,
            "missing optional route remains explicit"
        );
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "value.cjs",
            "throw new Error('live source changed');",
        );
        put(
            root.path(),
            "node_modules/pkg/value.cjs",
            "throw new Error('live package changed');",
        );
        put(
            root.path(),
            "node_modules/optional/index.js",
            "module.exports='new live dependency';",
        );
        put(root.path(), "uncaptured.cjs", "module.exports=99;");
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Require)
            .unwrap();
        assert_eq!(entry.source(), source);
        let local = registry
            .lookup(Some(entry.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(local.source(), "module.exports=42;");
        let package = registry
            .lookup(Some(entry.id()), "pkg", RequestStyle::Require)
            .unwrap();
        let nested = registry
            .lookup(Some(package.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(nested.source(), "module.exports=17;");
        assert_ne!(nested.id(), local.id());
        assert_eq!(registry.summary().missing_routes, 1);
        assert_eq!(
            registry
                .lookup(Some(entry.id()), "optional", RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "MODULE_NOT_FOUND"
        );
        for (importer, specifier, style) in [
            (entry.id(), "./uncaptured.cjs", RequestStyle::Require),
            (entry.id(), "./value.cjs", RequestStyle::Import),
            (package.id(), "pkg", RequestStyle::Require),
            (package.id(), "optional", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(importer), specifier, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE",
                "{importer} {specifier} {style:?}"
            );
        }
    }

    #[test]
    fn create_require_immutable_named_namespace_and_typescript_bindings_capture_direct_routes() {
        for (source, language) in [
            (
                "import {createRequire} from 'node:module'; const require=createRequire(import.meta.url); require('./dep.cjs'); require.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire as make} from 'module'; const local=make(import.meta.url); local('./dep' + '.cjs'); local['res' + 'olve']('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import * as mod from 'node:module'; const local=mod.createRequire(import.meta.url); if (typeof local === 'function') local('./dep.cjs'); local.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import mod from 'node:module'; const local=mod.createRequire(import.meta.url); local('./dep.cjs'); local.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import mod from 'module'; const local=(mod['createRequire']((import.meta).url)); (local)('./dep.cjs'); (local.resolve)('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import mod from 'node:module'; const local: Loader=mod.createRequire(import.meta.url as string); (local!)('./dep.cjs'); (local.resolve as Resolver)('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
            (
                "import * as module from 'module'; const local=(module['createRequire']((import.meta).url)); (local)('./dep.cjs'); (local.resolve)('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire as make} from 'node:module'; const local: Loader=(make((import.meta.url as string))) as Loader; (local!)('./dep.cjs'); (local.resolve as Resolver)('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
            (
                "import {createRequire as require} from 'node:module'; const local=require(import.meta.url); local('./dep.cjs'); local.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire as make} from 'node:module'; const first=make(import.meta.url), second=make(import.meta.url); first('./dep.cjs'); second.resolve('./dep.cjs'); console.log(import.meta.dirname, import.meta.filename, import.meta.url);",
                SourceLanguage::JavaScript,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 3, "{source}: {loads:?}");
            assert_eq!(loads[0].kind, LoadKind::StaticImport);
            for load in &loads[1..] {
                assert_eq!(load.kind, LoadKind::Require, "{source}");
                assert_eq!(load.specifier.as_deref(), Some("./dep.cjs"), "{source}");
                assert!(!load.type_only);
            }
        }
    }

    #[test]
    fn create_require_file_url_origins_capture_exact_commonjs_routes() {
        for (imports, initializer, language) in [
            (
                "import {fileURLToPath} from 'node:url';",
                "const local=make(fileURLToPath(import.meta.url));",
                SourceLanguage::JavaScript,
            ),
            (
                "import {fileURLToPath as toPath} from 'url';",
                "const __filename=toPath(import.meta.url); const local=make(__filename);",
                SourceLanguage::JavaScript,
            ),
            (
                "import * as urls from 'node:url';",
                "const filename=urls.fileURLToPath(import.meta.url), next=filename; const local=make(next); console.log(filename, {next});",
                SourceLanguage::JavaScript,
            ),
            (
                "import urls from 'url';",
                "const local=make(urls['fileURLToPath']((import.meta).url));",
                SourceLanguage::JavaScript,
            ),
            (
                "import {fileURLToPath as toPath} from 'node:url';",
                "const filename=toPath(import.meta.url), next=filename; var local=make(next);",
                SourceLanguage::JavaScript,
            ),
            (
                "import {fileURLToPath as toPath} from 'node:url';",
                "const filename: string=toPath(import.meta.url as string); const local: Loader=make(filename as string);",
                SourceLanguage::TypeScript,
            ),
        ] {
            let source = format!(
                "import {{createRequire as make}} from 'node:module'; {imports} {initializer} \
                 local('./dep.cjs'); local.resolve('./asset.cjs');"
            );
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 4, "{source}: {loads:?}");
            assert_eq!(loads[0].kind, LoadKind::StaticImport);
            assert_eq!(loads[1].kind, LoadKind::StaticImport);
            assert_eq!(loads[2].kind, LoadKind::Require);
            assert_eq!(loads[2].specifier.as_deref(), Some("./dep.cjs"));
            assert_eq!(loads[3].kind, LoadKind::Require);
            assert_eq!(loads[3].specifier.as_deref(), Some("./asset.cjs"));
        }
    }

    #[test]
    fn create_require_file_url_origins_reject_unproved_binding_and_origin_changes() {
        let imports = "import {createRequire as make} from 'node:module'; \
            import {fileURLToPath as toPath} from 'node:url';";
        for initializer in [
            "const local=make(toPath('file:///other.mjs'));",
            "const local=make(toPath(new URL(import.meta.url)));",
            "const local=make(toPath(import.meta.url, {windows:false}));",
            "const local=make(toPath(...[import.meta.url]));",
            "const local=make((0,toPath)(import.meta.url));",
            "const local=make(toPath.call(null, import.meta.url));",
            "const convert=toPath; const local=make(convert(import.meta.url));",
            "const local=make(filename); const filename=toPath(import.meta.url);",
            "let filename=toPath(import.meta.url); const local=make(filename);",
            "var filename=toPath(import.meta.url); const local=make(filename);",
            "{ const filename=toPath(import.meta.url); const local=make(filename); }",
        ] {
            let source = format!("{imports} {initializer} local('./dep.cjs');");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed && !notices.is_empty(), "{source}: {notices:?}");
        }
        for mutation in [
            "toPath=other;",
            "function shadow(toPath){}",
            "const escaped=toPath;",
            "filename=other;",
            "filename+='x';",
            "filename++;",
            "({filename}=other);",
            "for(filename of other){}",
            "function shadow(filename){}",
            "import.meta.url='file:///other.mjs';",
            "Object.assign(import.meta, {url:'file:///other.mjs'});",
            "function shadow(file\\u006eame){}",
            "function shadow(toPa\\u0074h){}",
        ] {
            let source = format!(
                "{imports} const filename=toPath(import.meta.url); const local=make(filename); \
                 {mutation} local('./dep.cjs');"
            );
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed && !notices.is_empty(), "{source}: {notices:?}");
        }
        for mutation in [
            "urls.fileURLToPath=other;",
            "urls['fileURLToPath']=other;",
            "Object.assign(urls, {fileURLToPath:other});",
            "Object.defineProperty(urls, 'fileURLToPath', {value:other});",
            "const escaped=urls;",
            "function shadow(urls){}",
        ] {
            let source = format!(
                "import {{createRequire as make}} from 'node:module'; import * as urls from 'node:url'; \
                 const local=make(urls.fileURLToPath(import.meta.url)); {mutation} local('./dep.cjs');"
            );
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed && !notices.is_empty(), "{source}: {notices:?}");
        }
        let source = "import {createRequire as make} from 'node:module'; \
            import {fileURLToPath as toPath} from './untrusted.mjs'; \
            const local=make(toPath(import.meta.url)); local('./dep.cjs');";
        let (_, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed && !notices.is_empty(), "{notices:?}");
    }

    #[test]
    fn unused_file_url_origin_candidates_do_not_restrict_ordinary_url_code() {
        let source = "import {createRequire as make} from 'node:module'; \
            import {fileURLToPath as toPath} from 'node:url'; \
            const filename=toPath(import.meta.url); const local=make(import.meta.url); \
            function display(filename){return filename;} \
            console.log(display(filename), toPath('file:///another.mjs')); local('./dep.cjs');";
        let (_, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed && notices.is_empty(), "{notices:?}");

        // An inactive conversion is still an arbitrary initializer for the
        // existing var/let loader prelude proof; it must not become a grant.
        let source = source.replace("const local=", "var local=");
        let (_, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed);
        assert!(
            notices
                .iter()
                .any(|notice| notice.code == "UNPROVED_LOADER_INITIALIZATION"),
            "{notices:?}"
        );
    }

    #[test]
    fn create_require_commonjs_factories_capture_exact_filename_routes() {
        for (source, language) in [
            (
                "const {createRequire}=require('node:module'); const local=createRequire(__filename); local('./dep.cjs'); local.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const {'createRequire':make}=require('module'); const local=make((__filename)); local('./dep' + '.cjs'); local['resolve']('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const mod=require('node:module'); const local=(mod.createRequire)(__filename); local('./dep.cjs'); local.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const mod=(require)('module'); const local=mod['cre' + 'ateRequire'](__filename); (local)('./dep.cjs'); (local.resolve)('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const {createRequire:make}=(require as Loader)('node:module'); const local: Loader=make(__filename as string) as Loader; (local!)('./dep.cjs'); (local.resolve as Resolver)('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
            (
                "const {createRequire:make}=require('node:module'); const first=make(__filename), second=make(__filename); first('./dep.cjs'); second.resolve('./dep.cjs'); console.log(__filename); function origin(){return __filename;} function ownArguments(){return arguments.length;} const metadata={__filename};",
                SourceLanguage::JavaScript,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 3, "{source}: {loads:?}");
            assert!(matches!(
                loads[0].specifier.as_deref(),
                Some("module" | "node:module")
            ));
            for load in &loads {
                assert_eq!(load.kind, LoadKind::Require, "{source}");
                assert!(!load.type_only);
            }
            for load in &loads[1..] {
                assert_eq!(load.specifier.as_deref(), Some("./dep.cjs"), "{source}");
            }
        }
    }

    #[test]
    fn create_require_commonjs_origin_factory_and_require_bindings_remain_immutable() {
        let factory = "const {createRequire:make}=require('node:module');";
        let loader = "const local=make(__filename); local('./dep.cjs');";
        for mutation in [
            "__filename='/other.cjs';",
            "__filename += '/other.cjs';",
            "var __filename;",
            "let __filename='/other.cjs';",
            "const __filename='/other.cjs';",
            "function __filename(){}",
            "function shadow(__filename){}",
            "const shadow=(__filename)=>0;",
            "try {} catch(__filename) {}",
            "({__filename}=value);",
            "({value:__filename}=value);",
            "[__filename]=value;",
            "for(__filename of values){}",
            "for(__filename in values){}",
            "__filename++;",
            "delete __filename;",
            "const {__filename}=value;",
            "arguments[3]='/other.cjs';",
            "const wrapper=arguments;",
            "(()=>{arguments[3]='/other.cjs';})();",
            "function shadow(require){}",
            "require=replacement;",
            "const escaped={make};",
            "consume(make);",
            "make=other;",
            "function shadow(make){}",
            "local=other;",
            "local.resolve=other;",
            "const escapedLoader={local};",
            "function shadow(local){}",
        ] {
            let source = format!("{factory}{loader}{mutation}");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                !notices.is_empty(),
                "mutable binding became complete: {source}"
            );
        }
        for source in [
            "const {createRequire:make}=require('node:module'); const local=make(__dirname); local('./dep.cjs');",
            "const {createRequire:make}=require('node:module'); const local=make('/other.cjs'); local('./dep.cjs');",
            "const {createRequire:make}=require('node:module'); const origin=__filename; const local=make(origin); local('./dep.cjs');",
            "const {createRequire:make}=require('node:module'); const local=make(__filename, extra); local('./dep.cjs');",
            "let {createRequire:make}=require('node:module'); make=other; const local=make(__filename); local('./dep.cjs');",
            "const {createRequire:make=other}=require('node:module'); const local=make(__filename); local('./dep.cjs');",
            "const {['createRequire']:make}=require('node:module'); const local=make(__filename); local('./dep.cjs');",
            "const {[property]:make}=require('node:module'); const local=make(__filename); local('./dep.cjs');",
            "const {...mod}=require('node:module'); const local=mod.createRequire(__filename); local('./dep.cjs');",
            "const {createRequire:require}=require('node:module'); const local=require(__filename); local('./dep.cjs');",
            "const {createRequire:__filename}=require('node:module'); const local=__filename(__filename); local('./dep.cjs');",
            "const {createRequire:make}=require('lookalike'); const local=make(__filename); local('./dep.cjs');",
            "function nested(){const {createRequire:make}=require('node:module'); const local=make(__filename); local('./dep.cjs');}",
        ] {
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                !notices.is_empty(),
                "unproved factory became complete: {source}"
            );
        }
        for import in [
            "import mod from 'node:module'; const local=mod.createRequire(import.meta.url);",
            "const mod=require('node:module'); const local=mod.createRequire(__filename);",
        ] {
            for mutation in [
                "mod.createRequire=other;",
                "mod['createRequire']=other;",
                "Object.assign(mod, {createRequire:other});",
                "Object.defineProperty(mod, 'createRequire', {value:other});",
                "const alias=mod;",
                "consume(mod);",
                "function shadow(mod){}",
            ] {
                let source = format!("{import}{mutation}local('./dep.cjs');");
                let (_, notices, analyzed) = scan(
                    &mut Parser::new(),
                    source.as_bytes(),
                    SourceLanguage::JavaScript,
                    &mut Budget::default(),
                )
                .unwrap();
                assert!(analyzed, "{source}: {notices:?}");
                assert!(
                    !notices.is_empty(),
                    "mutable namespace became complete: {source}"
                );
            }
        }
    }

    #[test]
    fn create_require_typescript_runtime_binding_names_are_not_erased() {
        let factory = "const {createRequire:make}=require('node:module');";
        let loader = "const local=make(__filename); local('./dep.cjs');";
        for binding in [
            "class __filename {}",
            "abstract class __filename {}",
            "const Example=class __filename {};",
            "class make {}",
            "class local {}",
            "function * __filename() {}",
            "function shadow(__filename: string) {}",
            "const shadow=(__filename: string)=>0;",
        ] {
            let source = format!("{factory}{binding}{loader}");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::TypeScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                notices.iter().any(|notice| matches!(
                    notice.code,
                    "MUTABLE_CREATE_REQUIRE_ORIGIN"
                        | "INDIRECT_CREATE_REQUIRE"
                        | "INDIRECT_CREATED_REQUIRE"
                )),
                "runtime binding must not be treated as an erased type: {source}: {notices:?}"
            );
        }
        let source = format!(
            "type __filename=string; interface make {{}} type local=unknown; {factory}{loader}"
        );
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::TypeScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed);
        assert!(
            notices.is_empty(),
            "type-only names do not replace runtime bindings: {notices:?}"
        );
        assert_eq!(loads.len(), 2);
    }

    #[test]
    fn create_require_factory_forms_replay_nested_require_conditions_from_captured_bytes() {
        for (entrypoint, factory, origin) in [
            (
                "nested/app.mjs",
                "import mod from 'node:module';",
                "mod.createRequire(import.meta.url)",
            ),
            (
                "nested/app.mjs",
                "import {createRequire as make} from 'node:module'; import {fileURLToPath as toPath} from 'node:url'; const filename=toPath(import.meta.url), origin=filename;",
                "make(origin)",
            ),
            (
                "nested/app.mjs",
                "import {createRequire} from 'node:module'; import * as urls from 'node:url';",
                "createRequire(urls.fileURLToPath(import.meta.url))",
            ),
            (
                "nested/app.cjs",
                "const {createRequire}=require('node:module');",
                "createRequire(__filename)",
            ),
            (
                "nested/app.cjs",
                "const {createRequire:make}=require('module');",
                "make(__filename)",
            ),
            (
                "nested/app.cjs",
                "const mod=require('node:module');",
                "mod.createRequire(__filename)",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let source = format!(
                "{factory} const local={origin}; local('dual'); local.resolve('./asset.cjs');"
            );
            put(root.path(), entrypoint, &source);
            put(
                root.path(),
                "nested/asset.cjs",
                "throw new Error('resolve-only asset');",
            );
            put(
                root.path(),
                "node_modules/dual/package.json",
                r#"{"exports":{"import":"./imported.mjs","require":"./required.cjs"}}"#,
            );
            put(
                root.path(),
                "node_modules/dual/required.cjs",
                "module.exports=42;",
            );
            put(
                root.path(),
                "node_modules/dual/imported.mjs",
                "export default 0;",
            );
            let captured = capture(root.path(), entrypoint, GraphOptions::default()).unwrap();
            assert!(
                captured.report().diagnostics.is_empty(),
                "{:?}",
                captured.report()
            );
            let dependency = captured
                .report()
                .edges
                .iter()
                .find(|edge| edge.specifier.as_deref() == Some("dual"))
                .unwrap();
            assert_eq!(dependency.kind, LoadKind::Require);
            assert_eq!(dependency.state, EdgeState::Resolved);
            assert_eq!(dependency.importer.path, entrypoint);
            assert_eq!(
                dependency.target.as_ref().unwrap().path,
                "node_modules/dual/required.cjs"
            );
            assert!(captured.report().edges.iter().any(|edge| {
                edge.specifier.as_deref() == Some("./asset.cjs")
                    && edge.kind == LoadKind::Require
                    && edge
                        .target
                        .as_ref()
                        .is_some_and(|target| target.path == "nested/asset.cjs")
            }));
            assert!(
                !captured
                    .report()
                    .modules
                    .iter()
                    .any(|module| module.id.path == "node_modules/dual/imported.mjs")
            );
            let capsule = super::capsule::encode(&captured).unwrap();
            put(root.path(), entrypoint, "throw new Error('changed entry');");
            put(
                root.path(),
                "node_modules/dual/package.json",
                r#"{"exports":{}}"#,
            );
            put(
                root.path(),
                "node_modules/dual/required.cjs",
                "module.exports=0;",
            );
            put(
                root.path(),
                "nested/asset.cjs",
                "throw new Error('changed asset');",
            );
            let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
            assert_eq!(replayed.report(), captured.report());
            assert_eq!(
                replayed.source_bytes(&replayed.report().resolved_entrypoint),
                Some(source.as_bytes()),
            );
            assert_eq!(
                replayed.source_bytes(dependency.target.as_ref().unwrap()),
                Some(b"module.exports=42;".as_slice()),
            );
        }
    }

    #[test]
    fn create_require_rejects_factory_loader_and_origin_mutation_shadowing_and_escape() {
        let import = "import {createRequire as make} from 'node:module';";
        let binding = "const local=make(import.meta.url);";
        for body in [
            "let local=make(import.meta.url); local=other; local('./dep.cjs');",
            "function initialize(){ const local=make(import.meta.url); local('./dep.cjs'); }",
            "const local=make('./other.mjs'); local('./dep.cjs');",
            "const local=make(import.meta.filename); local('./dep.cjs');",
            "const local=make(new URL('./other.mjs', import.meta.url)); local('./dep.cjs');",
            "const origin=import.meta.url; const local=make(origin); local('./dep.cjs');",
            "const local=make(import.meta.url, 'extra'); local('./dep.cjs');",
            "const local=make(...[import.meta.url]); local('./dep.cjs');",
            "const local=make(); local('./dep.cjs');",
            "const local=(0, make)(import.meta.url); local('./dep.cjs');",
            "const local=condition ? make(import.meta.url) : other; local('./dep.cjs');",
            "const alias=make; const local=alias(import.meta.url); local('./dep.cjs');",
            "function shadow(make){const local=make(import.meta.url); local('./dep.cjs');}",
        ] {
            let source = format!("{import}{body}");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(
                !notices.is_empty(),
                "unsupported factory became complete: {source}"
            );
        }
        for body in [
            "make=other;",
            "const exportedFactory={make};",
            "export {make};",
            "function shadow(make){}",
            "function shadow(local){local('./dep.cjs');}",
            "{const local=other; local('./dep.cjs');}",
            "try {} catch(local) {local('./dep.cjs');}",
            "local=other;",
            "local.resolve=other;",
            "Object.defineProperty(local, 'resolve', {value:other});",
            "let alias=local; consume(alias);",
            "const escaped={local};",
            "export {local};",
            "consume(local);",
            "local.call(null, './dep.cjs');",
            "const resolve=local.resolve; resolve('./dep.cjs');",
            "local.resolve('./dep.cjs', {paths:['other']});",
            "function shadow(lo\\u0063al){local('./dep.cjs');}",
            "import.meta.url='file:///other.mjs';",
            "import.meta.url += '/other.mjs';",
            "delete import.meta.url;",
            "import.meta.url++;",
            "({value:import.meta.url}={value:'file:///other.mjs'});",
            "for(import.meta.url of values){}",
            "const escapedOrigin=import.meta;",
            "Object.assign(import.meta, {url:'file:///other.mjs'});",
            "Object.defineProperty(import.meta, 'url', {get:other});",
            "console.log(import.meta[property]);",
        ] {
            let source = format!("{import}{binding}{body}local('./dep.cjs');");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(
                !notices.is_empty(),
                "unsafe binding became complete: {source}"
            );
        }
        for source in [
            "import * as mod from 'node:module'; const local=mod.createRequire(other); local('./dep.cjs');",
            "import * as mod from 'node:module'; const local=mod.createRequire(import.meta.url); consume(mod); local('./dep.cjs');",
            "import * as mod from 'node:module'; const local=mod.createRequire(import.meta.url); function shadow(mod){} local('./dep.cjs');",
            "import mod from 'node:module'; const local=mod.createRequire(other); local('./dep.cjs');",
            "const {createRequire:make}=require('node:module'); const local=make(__dirname); local('./dep.cjs');",
            "const {createRequire}=require('node:module'); const local=createRequire(__filename); createRequire=other; local('./dep.cjs');",
        ] {
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(
                !notices.is_empty(),
                "unsupported factory became complete: {source}"
            );
        }
    }

    #[test]
    fn create_require_keeps_dynamic_requests_nonliteral_and_bounds_binding_discovery() {
        let source = "import {createRequire} from 'node:module'; const local=createRequire(import.meta.url); local(request); local.resolve(`./${name}.cjs`);";
        let (loads, notices, _) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(notices.is_empty());
        assert_eq!(loads.len(), 3);
        assert!(
            loads[1..]
                .iter()
                .all(|load| load.kind == LoadKind::Require && load.specifier.is_none())
        );

        let factories = (0..MAX_SITES)
            .map(|index| format!("createRequire as make{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let source = format!(
            "import {{{factories}}} from 'node:module'; const local=make0(import.meta.url);"
        );
        let failure = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.code, "ERR_MODULE_GRAPH_LIMIT");
    }

    #[test]
    fn create_require_captured_query_origins_replay_exact_commonjs_routes_after_live_changes() {
        use super::registry::{ModuleKind, PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './bridge.mjs?one#tag'; import './bridge.mjs?two#tag'; import 'dual';",
        );
        let bridge = "import {createRequire as make} from 'node:module'; const local=make(import.meta.url); local('dual'); local.resolve('./asset.cjs');";
        put(root.path(), "bridge.mjs", bridge);
        put(
            root.path(),
            "asset.cjs",
            "throw new Error('resolve does not execute');",
        );
        put(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{"import":"./esm.mjs","require":"./cjs.cjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/dual/esm.mjs",
            "export default 'import';",
        );
        put(
            root.path(),
            "node_modules/dual/cjs.cjs",
            "module.exports='require';",
        );
        let captured = graph(root.path());
        assert!(
            captured.report().diagnostics.is_empty(),
            "{:?}",
            captured.report()
        );
        assert!(
            captured
                .report()
                .modules
                .iter()
                .all(|module| module.analyzed)
        );
        assert_eq!(
            captured
                .report()
                .edges
                .iter()
                .filter(|edge| edge.kind == LoadKind::Require)
                .count(),
            4
        );
        assert!(!captured.report().execution_performed);
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "bridge.mjs",
            "throw new Error('live bridge changed');",
        );
        put(
            root.path(),
            "asset.cjs",
            "throw new Error('live asset changed');",
        );
        put(
            root.path(),
            "node_modules/dual/cjs.cjs",
            "module.exports='live replacement';",
        );
        put(
            root.path(),
            "uncaptured.cjs",
            "module.exports='unapproved';",
        );
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new_with_kind_resolver(
            replayed,
            &pin,
            |module, _, _| {
                Ok(if module.format_hint == "commonjs" {
                    ModuleKind::CommonJs
                } else {
                    ModuleKind::EsModule
                })
            },
            |specifier, _| match specifier {
                "module" | "node:module" => Some("node:module"),
                _ => None,
            },
        )
        .ok()
        .unwrap();
        let entry = registry.entrypoint();
        let imported = registry
            .lookup(Some(entry), "dual", RequestStyle::Import)
            .unwrap();
        assert_eq!(imported.source(), "export default 'import';");
        assert!(
            registry
                .lookup(Some(entry), "dual", RequestStyle::Require)
                .is_err()
        );
        let mut bridge_ids = Vec::new();
        for (request, suffix) in [
            ("./bridge.mjs?one#tag", "?one#tag"),
            ("./bridge.mjs?two#tag", "?two#tag"),
        ] {
            let loaded = registry
                .lookup(Some(entry), request, RequestStyle::Import)
                .unwrap();
            assert_eq!(loaded.source(), bridge);
            assert_eq!(loaded.origin().url_suffix, suffix);
            bridge_ids.push(loaded.id().to_owned());
            let required = registry
                .lookup(Some(loaded.id()), "dual", RequestStyle::Require)
                .unwrap();
            assert_eq!(required.source(), "module.exports='require';");
            let asset = registry
                .lookup(Some(loaded.id()), "./asset.cjs", RequestStyle::Require)
                .unwrap();
            assert_eq!(
                asset.source(),
                "throw new Error('resolve does not execute');"
            );
            assert!(
                registry
                    .lookup(Some(loaded.id()), "dual", RequestStyle::Import)
                    .is_err()
            );
            assert!(
                registry
                    .lookup(Some(loaded.id()), "./uncaptured.cjs", RequestStyle::Require)
                    .is_err()
            );
            assert!(
                registry
                    .lookup(
                        Some(loaded.id()),
                        "./asset.cjs?uncaptured",
                        RequestStyle::Require
                    )
                    .is_err()
            );
        }
        assert_ne!(bridge_ids[0], bridge_ids[1]);
    }

    #[test]
    fn exact_string_loads_capture_and_replay_only_their_pinned_routes() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let source = r#"
const value = require(('./value' + '.cjs'));
const resolved = require['re' + 'solve'](`./${'other'}.cjs`);
import(`./${'dynamic' + '.mjs'}`);
const fromPackage = require('string-' + 'fixture');
"#;
        put(root.path(), "app.cjs", source);
        put(root.path(), "value.cjs", "module.exports = 42;");
        put(
            root.path(),
            "other.cjs",
            "throw new Error('resolve does not execute');",
        );
        put(root.path(), "dynamic.mjs", "export default 7;");
        put(
            root.path(),
            "node_modules/string-fixture/package.json",
            r#"{"exports":"./index.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/string-fixture/index.cjs",
            "module.exports = require('./' + 'value.cjs');",
        );
        put(
            root.path(),
            "node_modules/string-fixture/value.cjs",
            "module.exports = 17;",
        );
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved, "{:?}", captured.report());
        assert!(!captured.report().execution_performed);
        assert_eq!(
            paths(&captured),
            [
                "app.cjs",
                "dynamic.mjs",
                "node_modules/string-fixture/index.cjs",
                "node_modules/string-fixture/value.cjs",
                "other.cjs",
                "value.cjs",
            ]
        );
        assert_eq!(
            captured
                .report()
                .edges
                .iter()
                .map(|edge| edge.specifier.as_deref().unwrap())
                .collect::<Vec<_>>(),
            [
                "./value.cjs",
                "./other.cjs",
                "./dynamic.mjs",
                "string-fixture",
                "./value.cjs",
            ]
        );
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "value.cjs",
            "throw new Error('live source changed');",
        );
        put(root.path(), "uncaptured.cjs", "module.exports = 99;");
        put(
            root.path(),
            "node_modules/string-fixture/value.cjs",
            "throw new Error('live package changed');",
        );
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Require)
            .unwrap();
        assert_eq!(
            entry.source(),
            source,
            "capture must not rewrite guest code"
        );
        let value = registry
            .lookup(Some(entry.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(value.source(), "module.exports = 42;");
        let package = registry
            .lookup(Some(entry.id()), "string-fixture", RequestStyle::Require)
            .unwrap();
        let package_value = registry
            .lookup(Some(package.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(package_value.source(), "module.exports = 17;");
        assert!(
            registry
                .lookup(Some(entry.id()), "./other.cjs", RequestStyle::Require)
                .is_ok()
        );
        assert!(
            registry
                .lookup(Some(entry.id()), "./dynamic.mjs", RequestStyle::Import)
                .is_ok()
        );
        for (specifier, style) in [
            ("./uncaptured.cjs", RequestStyle::Require),
            ("./value.cjs", RequestStyle::Import),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(entry.id()), specifier, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
    }

    #[test]
    fn exact_string_values_preserve_cooked_escapes_and_cross_operand_utf16() {
        for (expression, expected) in [
            (
                "( /* prefix */ './' + ('li' + 'b.cjs') /* suffix */ )",
                "./lib.cjs",
            ),
            ("`./${'lib'}.cjs`", "./lib.cjs"),
            ("`./${`${'li'}b`}.cjs`", "./lib.cjs"),
            (r#"`./\${literal}.cjs`"#, "./${literal}.cjs"),
            (r#"'./\uD83D' + '\uDE00.cjs'"#, "./😀.cjs"),
            (r#"`./${'\u{D83D}'}${'\u{DE00}'}.cjs`"#, "./😀.cjs"),
            (r#"'./\u{00000061}.cjs'"#, "./a.cjs"),
            ("`./a\r\nb\rc.cjs`", "./a\nb\nc.cjs"),
            (r#"`./a\rb.cjs`"#, "./a\rb.cjs"),
            ("`./a\\\r\nb.cjs`", "./ab.cjs"),
            (r#"'./\x61' + '\u0062' + '\u{63}.cjs'"#, "./abc.cjs"),
        ] {
            assert_eq!(
                scan_string_request(expression, SourceLanguage::JavaScript).as_deref(),
                Some(expected),
                "{expression:?}"
            );
        }
        for expression in [r#"'./\uD800.cjs'"#, r#"'./\uDC00' + '\uD800.cjs'"#] {
            assert!(scan_string_request(expression, SourceLanguage::JavaScript).is_none());
        }
    }

    #[test]
    fn exact_string_typescript_wrappers_preserve_runtime_string_values() {
        for expression in [
            "('./value.cjs' as const)",
            "('./value.cjs' satisfies string)",
            "('./value.cjs')!",
            "('./' as string) + ('value.cjs' as const)",
            "`./${('value' as const)}.cjs`",
        ] {
            assert_eq!(
                scan_string_request(expression, SourceLanguage::TypeScript).as_deref(),
                Some("./value.cjs"),
                "{expression}"
            );
        }
    }

    #[test]
    fn exact_string_capture_rejects_coercion_bindings_and_result_side_effects() {
        for expression in [
            "'./' + name",
            "`./${name}.cjs`",
            "'./' + 1",
            "`./${1}.cjs`",
            "flag ? './one.cjs' : unknown",
            "'./one.cjs' || './two.cjs'",
            "(touch(), './value.cjs')",
            "(name = './value.cjs')",
            "('./value.cjs').toString()",
            "String.raw`./value.cjs`",
            "tag`./value.cjs`",
            "['./value.cjs'][0]",
            "`./${{toString() { touch(); return 'value'; }}}.cjs`",
        ] {
            assert!(
                scan_string_request(expression, SourceLanguage::JavaScript).is_none(),
                "runtime behavior must stay unresolved: {expression}"
            );
        }
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "require(('./ignored.cjs', './value.cjs')); require('./' + name);",
        );
        put(
            root.path(),
            "ignored.cjs",
            "throw new Error('not a captured route');",
        );
        put(
            root.path(),
            "value.cjs",
            "throw new Error('not a captured route');",
        );
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved);
        assert_eq!(paths(&captured), ["app.cjs"]);
        assert!(
            captured
                .report()
                .edges
                .iter()
                .all(|edge| edge.state == EdgeState::NonLiteral)
        );
        let pin = captured.report().input_hash.clone();
        assert_eq!(
            registry::PinnedModuleRegistry::new(captured, &pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );
    }

    #[test]
    fn conditional_strings_enumerate_nested_choices_products_and_templates() {
        for (expression, expected) in [
            (
                "flag ? './one.cjs' : './two.cjs'",
                vec!["./one.cjs", "./two.cjs"],
            ),
            (
                "true ? './one.cjs' : (other ? './two.cjs' : './three.cjs')",
                vec!["./one.cjs", "./three.cjs", "./two.cjs"],
            ),
            (
                "'./' + (flag ? 'a' : 'b') + (other ? '.cjs' : '.mjs')",
                vec!["./a.cjs", "./a.mjs", "./b.cjs", "./b.mjs"],
            ),
            (
                "`./${flag ? 'a' : 'b'}${other ? '.cjs' : '.mjs'}`",
                vec!["./a.cjs", "./a.mjs", "./b.cjs", "./b.mjs"],
            ),
            (
                "(touch(), flag) ? './one.cjs' : './two.cjs'",
                vec!["./one.cjs", "./two.cjs"],
            ),
            (
                "'./' + (flag ? '\\uD83D' : '\\uD83D') + '\\uDE00.cjs'",
                vec!["./😀.cjs"],
            ),
            (
                "flag ? './same.cjs' : (other ? './same.cjs' : './same.cjs')",
                vec!["./same.cjs"],
            ),
        ] {
            assert_eq!(
                scan_string_requests(expression, SourceLanguage::JavaScript),
                expected
                    .into_iter()
                    .map(|value| Some(value.to_owned()))
                    .collect::<Vec<_>>(),
                "{expression}"
            );
        }
        assert_eq!(
            scan_string_requests(
                "(flag ? './one.cjs' as const : ('./two.cjs' satisfies string))!",
                SourceLanguage::TypeScript,
            ),
            vec![Some("./one.cjs".into()), Some("./two.cjs".into())]
        );
    }

    #[test]
    fn conditional_strings_never_publish_a_known_subset_of_an_unknown_choice() {
        for expression in [
            "flag ? './one.cjs' : name",
            "flag ? name : './one.cjs'",
            "flag ? './one.cjs' : 1",
            "flag ? './one.cjs' : ('./' + name)",
            "flag ? './one.cjs' : (touch(), './two.cjs')",
            "flag ? './one.cjs' : (name = './two.cjs')",
            "flag ? './one.cjs' : './two.cjs'.toString()",
            "`./${flag ? 'one' : {toString() { return 'two'; }}}.cjs`",
            "flag ? './one.cjs' : '\\uD800'",
        ] {
            assert_eq!(
                scan_string_requests(expression, SourceLanguage::JavaScript),
                vec![None],
                "{expression}"
            );
        }
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "require(flag ? './one.cjs' : name);",
        );
        put(root.path(), "one.cjs", "module.exports = 1;");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_eq!(paths(&graph), ["app.cjs"]);
        assert!(!graph.report().fully_resolved);
        assert_eq!(graph.report().edges.len(), 1);
        assert_eq!(graph.report().edges[0].state, EdgeState::NonLiteral);
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            registry::PinnedModuleRegistry::new(graph, &pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );
    }

    #[test]
    fn conditional_strings_obey_unique_route_copy_work_and_existing_expression_limits() {
        fn choices(values: &[String]) -> String {
            if values.len() == 1 {
                return format!("'{}'", values[0]);
            }
            let middle = values.len() / 2;
            format!(
                "(flag ? {} : {})",
                choices(&values[..middle]),
                choices(&values[middle..])
            )
        }
        let paths = (0..MAX_STRING_ALTERNATIVES)
            .map(|index| format!("./variant-{index:02}.cjs"))
            .collect::<Vec<_>>();
        assert_eq!(
            scan_string_requests(&choices(&paths), SourceLanguage::JavaScript),
            paths.iter().cloned().map(Some).collect::<Vec<_>>()
        );
        let mut too_many = paths.clone();
        too_many.push("./overflow.cjs".into());
        assert_eq!(
            scan_string_requests(&choices(&too_many), SourceLanguage::JavaScript),
            vec![None]
        );
        let duplicates = vec!["./same.cjs".to_owned(); 128];
        assert_eq!(
            scan_string_requests(&choices(&duplicates), SourceLanguage::JavaScript),
            vec![Some("./same.cjs".into())]
        );
        let path_at_limit = "a".repeat(super::super::MAX_PATH);
        let depth_overflow = format!(
            "{}flag ? 'a' : 'b'{}",
            "(".repeat(MAX_STRING_EXPRESSION_DEPTH + 1),
            ")".repeat(MAX_STRING_EXPRESSION_DEPTH + 1)
        );
        let product_overflow = std::iter::repeat_n("(flag ? 'a' : 'b')", 6)
            .collect::<Vec<_>>()
            .join("+");
        let copy_overflow = format!("'{path_at_limit}' + {}", choices(&vec![String::new(); 128]));
        let mut work_overflow = "(flag ? '' : '')".to_owned();
        for _ in 0..11 {
            work_overflow = format!("({work_overflow}+{work_overflow})");
        }
        // Distinct empty-source choices cannot spend unbounded copy work on
        // the same long prefix. Repeated concatenation also has an independent
        // work budget even when every final alternative is identical.
        let copy_overflow = format!("({copy_overflow}){}", "+''".repeat(17));
        for expression in [
            format!("flag ? '{path_at_limit}x' : 'b'"),
            format!(
                "flag ? '{}' : 'b'",
                "é".repeat(super::super::MAX_PATH / 2 + 1)
            ),
            format!(
                "flag ? 'a' : '{}'",
                "\\\n".repeat(MAX_STRING_EXPRESSION_BYTES / 2 + 1)
            ),
            depth_overflow,
            product_overflow,
            copy_overflow,
            work_overflow,
        ] {
            assert_eq!(
                scan_string_requests(&expression, SourceLanguage::JavaScript),
                vec![None],
                "bounded expression with {} bytes",
                expression.len()
            );
        }
        let source = "require(flag ? './one.cjs' : './two.cjs');";
        let mut budget = Budget {
            sites: MAX_SITES - 1,
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
    fn conditional_request_tests_keep_nested_loads_and_loader_mutation_visible() {
        for (source, expected_kind) in [
            (
                "require(flag ? './one.cjs' : './two.cjs');",
                LoadKind::Require,
            ),
            (
                "require.resolve(flag ? './one.cjs' : './two.cjs');",
                LoadKind::Require,
            ),
            (
                "const load = require; load(flag ? './one.cjs' : './two.cjs');",
                LoadKind::Require,
            ),
            (
                "import(flag ? './one.cjs' : './two.cjs');",
                LoadKind::DynamicImport,
            ),
            (
                "import {createRequire} from 'node:module'; const load = createRequire(import.meta.url); load(flag ? './one.cjs' : './two.cjs');",
                LoadKind::Require,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
            let choices = loads
                .iter()
                .filter(|load| load.kind == expected_kind)
                .collect::<Vec<_>>();
            assert_eq!(choices.len(), 2, "{source}: {loads:?}");
            assert_eq!(choices[0].site, choices[1].site);
            assert_eq!(choices[0].specifier.as_deref(), Some("./one.cjs"));
            assert_eq!(choices[1].specifier.as_deref(), Some("./two.cjs"));
        }
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            b"require(require('./guard.cjs') ? './one.cjs' : './two.cjs');",
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed && notices.is_empty());
        assert_eq!(loads.len(), 3);
        assert_eq!(loads[2].specifier.as_deref(), Some("./guard.cjs"));
        for source in [
            "require((require = replacement) ? './one.cjs' : './two.cjs');",
            "require(eval('flag') ? './one.cjs' : './two.cjs');",
        ] {
            let (_, notices, _) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(
                !notices.is_empty(),
                "condition concealed unsafe code: {source}"
            );
        }
        let (loads, _, _) = scan(
            &mut Parser::new(),
            b"require(import(name) ? './one.cjs' : './two.cjs');",
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(
            loads
                .iter()
                .any(|load| load.kind == LoadKind::DynamicImport && load.specifier.is_none())
        );
    }

    #[test]
    fn conditional_package_routes_remain_pinned_during_capsule_replay() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let source = "module.exports = require(flag ? './production.cjs' : './development.cjs');";
        put(root.path(), "app.cjs", "require('conditional-package');");
        put(
            root.path(),
            "node_modules/conditional-package/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/conditional-package/index.cjs",
            source,
        );
        put(
            root.path(),
            "node_modules/conditional-package/production.cjs",
            "module.exports = 1;",
        );
        put(
            root.path(),
            "node_modules/conditional-package/development.cjs",
            "module.exports = 2;",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        assert!(!graph.report().runtime_completeness);
        assert_eq!(graph.report().modules.len(), 4);
        let pin = graph.report().input_hash.clone();
        let capsule = super::capsule::encode(&graph).unwrap();
        put(
            root.path(),
            "node_modules/conditional-package/production.cjs",
            "throw new Error('live drift');",
        );
        put(
            root.path(),
            "node_modules/conditional-package/development.cjs",
            "throw new Error('live drift');",
        );
        put(
            root.path(),
            "node_modules/conditional-package/uncaptured.cjs",
            "module.exports = 3;",
        );
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), graph.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let package = registry
            .lookup(
                Some(registry.entrypoint()),
                "conditional-package",
                RequestStyle::Require,
            )
            .unwrap();
        assert_eq!(package.source(), source);
        for (specifier, expected) in [
            ("./production.cjs", "module.exports = 1;"),
            ("./development.cjs", "module.exports = 2;"),
        ] {
            let module = registry
                .lookup(Some(package.id()), specifier, RequestStyle::Require)
                .unwrap();
            assert_eq!(module.source(), expected);
        }
        for (specifier, style) in [
            ("./uncaptured.cjs", RequestStyle::Require),
            ("./production.cjs", RequestStyle::Import),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(package.id()), specifier, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
    }

    #[test]
    fn exact_string_evaluation_bounds_depth_work_and_final_utf8_bytes() {
        let at_limit = "x".repeat(super::super::MAX_PATH);
        assert_eq!(
            scan_string_request(&format!("'{at_limit}'"), SourceLanguage::JavaScript),
            Some(at_limit.clone())
        );
        for expression in [
            format!("'{at_limit}' + 'x'"),
            format!("'{}'", "é".repeat(super::super::MAX_PATH / 2 + 1)),
            format!(
                "{}'x'{}",
                "(".repeat(MAX_STRING_EXPRESSION_DEPTH + 1),
                ")".repeat(MAX_STRING_EXPRESSION_DEPTH + 1)
            ),
            format!("'{}'", "\\\n".repeat(MAX_STRING_EXPRESSION_BYTES / 2 + 1)),
        ] {
            assert!(scan_string_request(&expression, SourceLanguage::JavaScript).is_none());
        }
        // A balanced tree has shallow recursion and an empty result, but its
        // many operands must still consume the expression work budget.
        let mut many_empty_strings = "''".to_owned();
        for _ in 0..12 {
            many_empty_strings = format!("({many_empty_strings}+{many_empty_strings})");
        }
        assert!(scan_string_request(&many_empty_strings, SourceLanguage::JavaScript).is_none());
        let at_depth = format!(
            "{}'x'{}",
            "(".repeat(MAX_STRING_EXPRESSION_DEPTH),
            ")".repeat(MAX_STRING_EXPRESSION_DEPTH)
        );
        assert_eq!(
            scan_string_request(&at_depth, SourceLanguage::JavaScript).as_deref(),
            Some("x")
        );
    }

    #[test]
    fn computed_loads_and_mutable_loader_aliases_never_look_complete() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import(name); let load; load=require; load('hidden'); const f=eval;",
        );
        let g = graph(root.path());
        assert_eq!(g.report.edges[0].state, EdgeState::NonLiteral);
        assert!(
            g.report
                .diagnostics
                .iter()
                .any(|d| d.code == "INDIRECT_REQUIRE")
        );
        assert!(
            g.report
                .diagnostics
                .iter()
                .any(|d| d.code == "DYNAMIC_CODE_OR_LOADER")
        );
        assert!(!g.report.fully_resolved);
    }

    #[test]
    fn loader_typeof_probes_are_observations_without_lookup_authority() {
        for (language, source) in [
            (SourceLanguage::JavaScript, "typeof require;"),
            (SourceLanguage::JavaScript, "typeof (((require)));"),
            (
                SourceLanguage::JavaScript,
                "typeof (/* before */ require /* after */);",
            ),
            (SourceLanguage::JavaScript, "typeof module.require;"),
            (SourceLanguage::JavaScript, "typeof ((module).require);"),
            (SourceLanguage::TypeScript, "typeof (require as Loader);"),
            (
                SourceLanguage::TypeScript,
                "typeof (require satisfies Loader);",
            ),
            (SourceLanguage::TypeScript, "typeof require!;"),
            (
                SourceLanguage::TypeScript,
                "typeof ((module as Module).require as Loader);",
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(loads.is_empty(), "{source}: {loads:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
        }
    }

    #[test]
    fn commonjs_main_guards_accept_only_entry_identity_comparisons() {
        for (source, language) in [
            ("if(require.main===module){}", SourceLanguage::JavaScript),
            ("if(module!==require.main){}", SourceLanguage::JavaScript),
            ("require['main']===module;", SourceLanguage::JavaScript),
            ("module!==require['ma'+'in'];", SourceLanguage::JavaScript),
            ("((require).main)===((module));", SourceLanguage::JavaScript),
            (
                "Object.prototype[Symbol.toPrimitive]=function(){leaked=this; return 1;}; module=1; require.main===module;",
                SourceLanguage::JavaScript,
            ),
            (
                "const load=require; const next=load; if(next.main===module){} if(module!==load.main){}",
                SourceLanguage::JavaScript,
            ),
            (
                "((require as Loader).main) === (module satisfies Module);",
                SourceLanguage::TypeScript,
            ),
        ] {
            assert!(
                scan_source_requests(source, language).is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn commonjs_main_guards_refuse_object_escape_writes_shadowing_and_created_loaders() {
        for source in [
            "const main=require.main;",
            "save(require.main);",
            "require.main.require('./hidden.cjs');",
            "require.main.filename;",
            "require.main();",
            "require.main=module;",
            "require.main++;",
            "delete require.main;",
            "[require.main]=values;",
            "for(require.main of values){}",
            "require.main===other;",
            "require.main==module;",
            "module!=require.main;",
            "const load=require; load.main==module;",
            "Object.prototype[Symbol.toPrimitive]=function(){leaked=this; return 1;}; module=1; require.main==module;",
            "Object.prototype[Symbol.toPrimitive]=function(){leaked=this; return 1;}; module=1; module!=require.main;",
            "require.main===(module, other);",
            "require.main===(module=other);",
            "require[name]===module;",
            "module.require.main===module;",
            "const load=require; load.main=module;",
            "const load=require; const main=load.main;",
            "const load=require; function nested(load){return load.main===module;}",
            "function nested(require){return require.main===module;}",
            "import {createRequire as make} from 'node:module'; const load=make(import.meta.url); load.main===module;",
            "const {createRequire:make}=require('node:module'); const load=make(__filename); load.main===module;",
            "import {createRequire as require} from 'node:module'; require.main===module;",
        ] {
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(
                notices.iter().any(|notice| matches!(
                    notice.code,
                    "INDIRECT_REQUIRE"
                        | "INDIRECT_REQUIRE_ALIAS"
                        | "INDIRECT_CREATED_REQUIRE"
                        | "INDIRECT_CREATE_REQUIRE"
                )),
                "unproved main observation: {source}: {notices:?}",
            );
        }
    }

    #[test]
    fn commonjs_main_guards_refuse_loose_coercion_before_module_authorization() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('./child.cjs');");
        for (operator, expected, admitted) in [
            ("==", "true object .\n", false),
            ("!=", "false object .\n", false),
            ("===", "false undefined undefined\n", true),
            ("!==", "true undefined undefined\n", true),
        ] {
            let source = format!(
                "let leaked; Object.prototype[Symbol.toPrimitive]=function(){{leaked=this; return 1;}}; \
                 module=1; const compared=require.main{operator}module; \
                 console.log(compared, typeof leaked, leaked && leaked.id);"
            );
            put(root.path(), "child.cjs", &source);
            let reference = std::process::Command::new("node")
                .arg(root.path().join("app.cjs"))
                .current_dir(root.path())
                .env_remove("NODE_OPTIONS")
                .env_remove("NODE_PATH")
                .output()
                .expect("Node is required for the independent entry-module coercion oracle");
            assert!(reference.status.success(), "{operator}: {reference:?}");
            assert!(reference.stderr.is_empty(), "{operator}: {reference:?}");
            assert_eq!(reference.stdout, expected.as_bytes(), "{operator}");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert_eq!(graph.report().fully_resolved, admitted, "{operator}");
            let pin = graph.report().input_hash.clone();
            let registry = registry::PinnedModuleRegistry::new(graph, &pin);
            if admitted {
                assert!(registry.is_ok(), "{operator}");
            } else {
                assert_eq!(
                    registry.err().unwrap().code,
                    "ERR_MODULE_REGISTRY_INCOMPLETE",
                    "{operator}"
                );
            }
        }
    }

    #[test]
    fn commonjs_main_guards_preserve_unresolved_loads_and_bounded_proof_work() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "dep.cjs", "module.exports=42;");
        put(
            root.path(),
            "app.cjs",
            "if(require.main===module){require('./dep.cjs');} else {require(runtimeName);}",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(graph.report().diagnostics.is_empty());
        assert_eq!(graph.report().edges.len(), 2);
        assert_eq!(graph.report().edges[0].state, EdgeState::Resolved);
        assert_eq!(graph.report().edges[1].state, EdgeState::NonLiteral);
        assert!(!graph.report().fully_resolved);
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            registry::PinnedModuleRegistry::new(graph, &pin)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );

        let source = format!(
            "{}require{}.main===module;",
            "(".repeat(MAX_STRING_EXPRESSION_DEPTH + 1),
            ")".repeat(MAX_STRING_EXPRESSION_DEPTH + 1)
        );
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed);
        assert!(loads.is_empty());
        assert!(
            notices
                .iter()
                .any(|notice| notice.code == "INDIRECT_REQUIRE")
        );
    }

    #[test]
    fn commonjs_main_guards_match_node_and_preserve_both_frozen_branches() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let entry_source = r#"
const load=require;
if(require.main===module){console.log('entry', require('./cli.cjs'));}
console.log('package', load('guarded'));
if(module!==load.main){throw new Error('entry identity differs');}
"#;
        let package_source = r#"
const load=require;
if(load.main===module){module.exports=load('./cli.cjs');}
else{module.exports=load('./library.cjs');}
"#;
        put(root.path(), "app.cjs", entry_source);
        put(root.path(), "cli.cjs", "module.exports='cli';");
        put(
            root.path(),
            "node_modules/guarded/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/guarded/index.cjs",
            package_source,
        );
        put(
            root.path(),
            "node_modules/guarded/cli.cjs",
            "throw new Error('package is not the entry');",
        );
        put(
            root.path(),
            "node_modules/guarded/library.cjs",
            "module.exports='library';",
        );
        let reference = std::process::Command::new("node")
            .arg(root.path().join("app.cjs"))
            .current_dir(root.path())
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_PATH")
            .output()
            .expect("Node is required for the independent CommonJS entry oracle");
        assert!(reference.status.success(), "{reference:?}");
        assert!(reference.stderr.is_empty(), "{reference:?}");
        assert_eq!(reference.stdout, b"entry cli\npackage library\n");
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved, "{:?}", captured.report());
        assert!(!captured.report().execution_performed);
        assert_eq!(captured.report().modules.len(), 5);
        assert_eq!(captured.report().edges.len(), 4);
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        for path in [
            "app.cjs",
            "node_modules/guarded/index.cjs",
            "node_modules/guarded/library.cjs",
        ] {
            put(root.path(), path, "throw new Error('live source changed');");
        }
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Require)
            .unwrap();
        assert_eq!(entry.source(), entry_source);
        let package = registry
            .lookup(Some(entry.id()), "guarded", RequestStyle::Require)
            .unwrap();
        assert_eq!(package.source(), package_source);
        for (request, expected) in [
            ("./library.cjs", "module.exports='library';"),
            ("./cli.cjs", "throw new Error('package is not the entry');"),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(package.id()), request, RequestStyle::Require)
                    .unwrap()
                    .source(),
                expected
            );
        }
        for (from, request, style) in [
            (entry.id(), "./library.cjs", RequestStyle::Require),
            (package.id(), "./library.cjs", RequestStyle::Import),
            (package.id(), "./uncaptured.cjs", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(from), request, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
    }

    #[test]
    fn loader_typeof_probes_do_not_hide_bindings_mutation_or_loader_escape() {
        for source in [
            "typeof (require = replacement);",
            "typeof (other, require);",
            "typeof (condition ? require : other);",
            "typeof (() => require);",
            "typeof save(require);",
            "typeof require.call(null, './hidden.cjs');",
            "typeof (module.require = replacement);",
            "typeof (0, module.require);",
            "typeof save(module.require);",
            "function guarded(require) { return typeof require; }",
            "const require = replacement; typeof require;",
            "function require() {} typeof require;",
            "try {} catch (require) { typeof require; }",
            "let load; load = require as Loader; typeof require; load('./hidden.cjs');",
            "const load = typeof require === 'function' ? require : fallback;",
        ] {
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::TypeScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}");
            assert!(
                notices
                    .iter()
                    .any(|notice| notice.code == "INDIRECT_REQUIRE"),
                "a type probe cannot establish loader identity for {source}: {notices:?}"
            );
        }
    }

    #[test]
    fn loader_typeof_probes_preserve_guarded_literal_and_computed_requests() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            r#"
if (typeof require === 'function') { require('./live.cjs'); }
if (typeof require === 'undefined') { require('./other.cjs'); }
const loadedType = typeof require('./live.cjs');
if (typeof module.require === 'function') { module.require('./other.cjs'); }
"#,
        );
        put(root.path(), "live.cjs", "module.exports = 1;");
        put(root.path(), "other.cjs", "module.exports = 2;");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(
            graph.report().fully_resolved,
            "{:?}",
            graph.report().diagnostics
        );
        assert_eq!(graph.report().edges.len(), 4);
        assert!(
            graph
                .report()
                .edges
                .iter()
                .all(|edge| edge.kind == LoadKind::Require && edge.state == EdgeState::Resolved)
        );
        assert_eq!(paths(&graph), ["app.cjs", "live.cjs", "other.cjs"]);

        // A guard is not branch evaluation or permission to infer a name.
        put(
            root.path(),
            "app.cjs",
            "if (typeof require === 'function') require(name);",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!graph.report().fully_resolved);
        assert_eq!(graph.report().edges.len(), 1);
        assert_eq!(graph.report().edges[0].state, EdgeState::NonLiteral);
        put(
            root.path(),
            "app.cjs",
            "if (typeof require === 'undefined') require('./absent.cjs');",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!graph.report().fully_resolved);
        assert_eq!(graph.report().edges[0].state, EdgeState::Unresolved);
    }

    // A UMD-style npm wrapper tests the host loader before using a literal
    // dependency. The wrapper itself is ordinary guest code, never rewritten
    // or evaluated by source capture.
    const UMD_PACKAGE: &str = r#"
(function(factory) {
  if (typeof module === 'object' && typeof module.exports === 'object'
      && typeof (require) === 'function') {
    module.exports = factory(require('./value.cjs'));
  } else {
    throw new Error('CommonJS loader is unavailable');
  }
})(function(value) { return { answer: value + 2 }; });
"#;

    fn put_umd_package(root: &Path) {
        put(
            root,
            "app.cjs",
            "console.log('umd', require('guarded-package').answer);",
        );
        put(
            root,
            "node_modules/guarded-package/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(root, "node_modules/guarded-package/index.cjs", UMD_PACKAGE);
        put(
            root,
            "node_modules/guarded-package/value.cjs",
            "module.exports = 40;",
        );
    }

    #[test]
    fn umd_loader_probes_preserve_exact_pinned_sources_and_capsule_routes() {
        use super::registry::{PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        put_umd_package(root.path());
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(
            graph.report().fully_resolved,
            "{:?}",
            graph.report().diagnostics
        );
        assert!(!graph.report().execution_performed);
        assert_eq!(graph.report().edges.len(), 2);
        assert_eq!(graph.report().modules.len(), 3);
        let pin = graph.report().input_hash.clone();
        let capsule = super::capsule::encode(&graph).unwrap();
        put(
            root.path(),
            "node_modules/guarded-package/value.cjs",
            "module.exports = -1;",
        );
        let restored = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(restored.report(), graph.report());
        let registry = PinnedModuleRegistry::new(restored, &pin).unwrap();
        let package = registry
            .lookup(
                Some(registry.entrypoint()),
                "guarded-package",
                RequestStyle::Require,
            )
            .unwrap();
        assert_eq!(package.source(), UMD_PACKAGE);
        let value = registry
            .lookup(Some(package.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(value.source(), "module.exports = 40;");
        assert_eq!(
            registry
                .lookup(
                    Some(package.id()),
                    "./not-captured.cjs",
                    RequestStyle::Require
                )
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ROUTE"
        );
    }

    #[cfg(feature = "engine")]
    #[test]
    fn umd_loader_probes_execute_frozen_npm_packages_in_both_native_lanes() {
        use super::engine_resolver::CapturedEngineResolver;
        use frankenengine_engine::ast::ParseGoal;
        use frankenengine_engine::baseline_interpreter::LaneChoice;
        use frankenengine_engine::capability::RuntimeCapability;
        use frankenengine_engine::execution_orchestrator::{
            ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
        };
        use frankenengine_engine::module_resolver::{
            CapabilityPolicyHook, ModuleResolver, ResolutionContext,
        };
        use frankenengine_engine::runtime_config::RuntimeConfig;
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        put_umd_package(root.path());
        let reference = std::process::Command::new("node")
            .arg("app.cjs")
            .current_dir(root.path())
            .output()
            .expect("Node is required as the native UMD package test's reference runtime");
        assert!(
            reference.status.success(),
            "{}",
            String::from_utf8_lossy(&reference.stderr)
        );
        assert_eq!(reference.stdout, b"umd 42\n");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let capsule = super::capsule::encode(&graph).unwrap();
        put(
            root.path(),
            "node_modules/guarded-package/index.cjs",
            "throw new Error('live package source must not be opened');",
        );
        put(
            root.path(),
            "node_modules/guarded-package/value.cjs",
            "module.exports = -1;",
        );

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let restored = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
            let resolver = Arc::new(CapturedEngineResolver::new(restored, &pin).ok().unwrap());
            let policy = Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
            ])));
            let context = ResolutionContext::new("umd-trace", "umd-decision", "umd-policy");
            let entry = resolver
                .resolve(&resolver.entry_request(), &context, policy.as_ref())
                .unwrap();
            let installed = resolver.execution_resolver(root.path(), policy).unwrap();
            let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
                OrchestratorConfig {
                    force_lane: Some(lane),
                    parse_goal: ParseGoal::Script,
                    commonjs_entry: true,
                    ..OrchestratorConfig::default()
                },
                RuntimeConfig::default(),
            )
            .unwrap();
            let package = ExtensionPackage {
                extension_id: "captured-umd-package".into(),
                source: "throw new Error('uncaptured source must not execute');".into(),
                source_file: Some(root.path().join("app.cjs").display().to_string()),
                module_root: None,
                capabilities: vec!["module_load".into(), "builtin".into()],
                version: "1.0.0".into(),
                metadata: BTreeMap::new(),
            };
            let result = engine
                .execute_resolved_entry_with_resolver(&package, &entry, installed)
                .expect("a loader type probe must not prevent a frozen UMD package from executing");
            let output = result
                .console_output
                .iter()
                .map(|line| line.message.as_str())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            assert_eq!(output.as_bytes(), reference.stdout, "{lane:?}");
        }
    }

    #[test]
    fn runtime_modules_and_missing_files_remain_distinct_while_other_edges_continue() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import 'node:fs'; import './absent.mjs'; import './ok.mjs';",
        );
        put(root.path(), "ok.mjs", "");
        let g = graph(root.path());
        assert_eq!(
            g.report.edges.iter().map(|e| e.state).collect::<Vec<_>>(),
            [
                EdgeState::RuntimeRequired,
                EdgeState::Unresolved,
                EdgeState::Resolved
            ]
        );
        assert_eq!(paths(&g), ["app.mjs", "ok.mjs"]);
        assert!(!g.report.fully_resolved);
    }

    #[test]
    fn syntax_errors_and_unsupported_formats_preserve_source_without_claiming_analysis() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './broken.mjs'; import './addon.node';",
        );
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
        put(
            root.path(),
            "app.mjs",
            "import './cached.mjs'; import './missing.mjs';",
        );
        put(root.path(), "cached.mjs", "export const captured=1;");
        let mut resolver = Resolver::new(root.path(), &[], SymlinkPolicy::Reject).unwrap();
        resolver.locate("cached.mjs").unwrap();
        resolver.locate("missing.mjs").unwrap();
        put(root.path(), "cached.mjs", "import './never-captured.mjs';");
        put(root.path(), "missing.mjs", "export const late=1;");
        let g = build(resolver, "app.mjs", GraphOptions::default()).unwrap();
        let id = ModuleId {
            path: "cached.mjs".into(),
            url_suffix: String::new(),
        };
        assert_eq!(g.source_bytes(&id).unwrap(), b"export const captured=1;");
        assert_eq!(g.report.edges[1].state, EdgeState::Unresolved);
        assert_eq!(g.report.edges.len(), 2);
    }

    #[test]
    fn graph_hash_is_relocatable_and_binds_transitive_bytes_and_query_suffixes() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        for root in [a.path(), b.path()] {
            put(
                root,
                "app.mjs",
                "import './lib.mjs?one'; import './lib.mjs?two';",
            );
            put(root, "lib.mjs", "export default 1;");
        }
        let first = graph(a.path());
        assert_eq!(first.report.input_hash, graph(b.path()).report.input_hash);
        assert_eq!(first.report.modules.len(), 3);
        put(b.path(), "lib.mjs", "export default 2;");
        assert_ne!(first.report.input_hash, graph(b.path()).report.input_hash);
    }

    #[test]
    fn equivalent_esm_url_spellings_share_registry_identity_across_capsule_replay() {
        let root = tempfile::tempdir().unwrap();
        let raw = "./state.mjs?mode=a b#café";
        let serialized = "./state.mjs?mode=a%20b#caf%C3%A9";
        let different = "./state.mjs?mode=a%20b#caf%c3%a9";
        put(
            root.path(),
            "app.mjs",
            &format!("import {raw:?}; import {serialized:?}; import {different:?};"),
        );
        put(root.path(), "state.mjs", "export const state = {};");
        let captured = graph(root.path());
        assert!(captured.report().fully_resolved);
        assert_eq!(captured.report().modules.len(), 3);
        assert_eq!(captured.report().edges.len(), 3);
        assert_eq!(
            captured.report().edges[0].target,
            captured.report().edges[1].target
        );
        assert_ne!(
            captured.report().edges[0].target,
            captured.report().edges[2].target
        );
        assert_eq!(
            captured.report().edges[0]
                .target
                .as_ref()
                .unwrap()
                .url_suffix,
            "?mode=a%20b#caf%C3%A9"
        );
        let pin = captured.report().input_hash.clone();
        let capsule = capsule::encode(&captured).unwrap();
        put(root.path(), "state.mjs", "throw new Error('source changed');");
        let replayed = capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(captured.report(), replayed.report());
        let registry = registry::PinnedModuleRegistry::new(replayed, &pin).unwrap();
        let first = registry
            .lookup(
                Some(registry.entrypoint()),
                raw,
                registry::RequestStyle::Import,
            )
            .unwrap();
        let alias = registry
            .lookup(
                Some(registry.entrypoint()),
                serialized,
                registry::RequestStyle::Import,
            )
            .unwrap();
        let distinct = registry
            .lookup(
                Some(registry.entrypoint()),
                different,
                registry::RequestStyle::Import,
            )
            .unwrap();
        assert_eq!(first.id(), alias.id());
        assert_ne!(first.id(), distinct.id());
        assert_eq!(first.source(), "export const state = {};" );
        assert_eq!(registry.summary().modules, 3);
        assert_eq!(registry.summary().routes, 3);
    }

    #[test]
    fn contained_workspace_importer_uses_physical_dependency_context() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'workspace';");
        put(
            root.path(),
            "packages/workspace/package.json",
            r#"{"main":"main.cjs"}"#,
        );
        put(
            root.path(),
            "packages/workspace/main.cjs",
            "require('dep');",
        );
        put(
            root.path(),
            "packages/workspace/node_modules/dep/index.js",
            "",
        );
        std::fs::create_dir_all(root.path().join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            "../packages/workspace",
            root.path().join("node_modules/workspace"),
        )
        .unwrap();
        assert!(capture(root.path(), "app.mjs", GraphOptions::default()).is_err());
        let g = capture(
            root.path(),
            "app.mjs",
            GraphOptions {
                symlink_policy: SymlinkPolicy::Contained,
                conditions: None,
            },
        )
        .unwrap();
        assert!(g.report.fully_resolved);
        assert!(paths(&g).contains(&"packages/workspace/node_modules/dep/index.js"));
    }

    #[test]
    fn safety_failures_do_not_return_partial_graphs() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import '../outside.mjs';");
        let e = capture(root.path(), "app.mjs", GraphOptions::default())
            .err()
            .unwrap();
        assert_eq!(e.code, "ERR_MODULE_OUTSIDE_PROJECT");
    }

    #[test]
    fn source_and_site_bounds_refuse_truncated_success() {
        let root = tempfile::tempdir().unwrap();
        let imports = (0..MAX_MODULES)
            .map(|i| format!("import './m{i}.mjs';"))
            .collect::<String>();
        put(root.path(), "app.mjs", &imports);
        for i in 0..MAX_MODULES {
            put(root.path(), &format!("m{i}.mjs"), "");
        }
        assert_eq!(
            capture(root.path(), "app.mjs", GraphOptions::default())
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
        put(
            root.path(),
            "app.mjs",
            &"import './m0.mjs';".repeat(MAX_SITES + 1),
        );
        assert_eq!(
            capture(root.path(), "app.mjs", GraphOptions::default())
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
    }

    #[test]
    fn escaped_js_literals_preserve_utf16_and_refuse_computed_or_legacy_octal() {
        assert_eq!(
            decode_literal(r#"'./\x61\u0062\u{63}.mjs'"#).as_deref(),
            Some("./abc.mjs")
        );
        assert_eq!(
            decode_literal(r#"'./\uD83D\uDE00.mjs'"#).as_deref(),
            Some("./😀.mjs")
        );
        assert!(decode_literal(r#"'./\uD800.mjs'"#).is_none());
        assert!(decode_literal(r#"'./\141.mjs'"#).is_none());
    }

    #[test]
    fn graph_report_does_not_serialize_source_and_snapshot_survives_later_mutation() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "const private_source_marker='secret';",
        );
        let g = graph(root.path());
        put(root.path(), "app.mjs", "changed after capture");
        assert!(
            std::str::from_utf8(g.source_bytes(&g.report.resolved_entrypoint).unwrap())
                .unwrap()
                .contains("private_source_marker")
        );
        assert!(
            !serde_json::to_string(g.report())
                .unwrap()
                .contains("private_source_marker")
        );
        assert!(g.report.fully_resolved);
    }

    fn typed_graph(root: &Path, entry: &str) -> CapturedModuleGraph {
        capture(root, entry, GraphOptions::default()).unwrap()
    }

    #[test]
    fn typescript_mts_cts_and_javascript_switch_grammars_per_captured_module() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "import './a.mts'; import './b.cts'; import './plain.mjs'; const n: number = 1;",
        );
        put(root.path(), "a.mts", "export const n: number = 2;");
        put(
            root.path(),
            "b.cts",
            "const n: number = require('./data.json'); module.exports=n;",
        );
        put(root.path(), "plain.mjs", "export const n = 3;");
        put(root.path(), "data.json", "1");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.modules.len(), 5);
        assert_eq!(
            g.report
                .modules
                .iter()
                .filter(|m| m.source_language == SourceLanguage::TypeScript)
                .count(),
            3
        );
        assert!(!g.report.type_resolution_performed);
    }

    #[test]
    fn whole_type_declarations_never_probe_erased_paths_or_runtime_modules() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "import type {T} from '../outside'; export type {U} from './absent.d.ts'; type S = import('node:fs').Stats;",
        );
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 3);
        assert!(g.report.edges.iter().all(|e| e.state == EdgeState::TypeOnly
            && e.conditions.is_empty()
            && e.target.is_none()
            && !e.deferred_or_conditional));
        assert!(
            g.report
                .probes
                .iter()
                .all(|p| !p.path.contains("absent") && !p.path.contains("outside"))
        );
        assert_eq!(paths(&g), ["app.ts"]);
    }

    #[test]
    fn inline_type_specifiers_preserve_empty_runtime_imports_and_reexports() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "import {type T} from './side.mts'; export {type T} from './side.mts'; import type from './side.mts';",
        );
        put(
            root.path(),
            "side.mts",
            "export type T = string; export default 1;",
        );
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 3);
        assert!(
            g.report
                .edges
                .iter()
                .all(|e| e.state == EdgeState::Resolved)
        );
        assert_eq!(paths(&g), ["app.ts", "side.mts"]);
    }

    #[test]
    fn nested_import_types_are_erased_without_erasing_adjacent_runtime_expressions() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            r#"
type T = typeof import('type-a');
interface Shape { value: import('type-b').Value; }
let p: Promise<typeof import('type-c')> = import('./live.mts');
const v = p as Promise<typeof import('type-d')>;
const ok = v satisfies Promise<typeof import('type-e')>;
type Factory = typeof require;
interface Names { eval: Function; }
"#,
        );
        put(root.path(), "live.mts", "export const value: number = 1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::TypeOnly)
                .count(),
            5
        );
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::Resolved)
                .count(),
            1
        );
        assert_eq!(paths(&g), ["app.ts", "live.mts"]);
    }

    #[test]
    fn ambient_module_imports_have_no_runtime_lookup_authority() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "declare module 'virtual' { import X from '../outside'; export {X}; } declare namespace N { type T = import('types').T; } const live: number = 1;",
        );
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 2);
        assert!(
            g.report
                .edges
                .iter()
                .all(|e| e.state == EdgeState::TypeOnly)
        );
    }

    #[test]
    fn import_equals_uses_require_conditions_and_reports_transform_boundary() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cts",
            "import dep = require('dual'); export = dep;",
        );
        put(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/dual/right.cjs",
            "module.exports=1;",
        );
        let g = typed_graph(root.path(), "app.cts");
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.edges.len(), 1, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges[0].kind, LoadKind::Require);
        assert_eq!(
            g.report.edges[0].target.as_ref().unwrap().path,
            "node_modules/dual/right.cjs"
        );
        assert!(
            g.report
                .diagnostics
                .iter()
                .all(|d| d.code == "TYPESCRIPT_TRANSFORM_REQUIRED")
        );
    }

    #[test]
    fn type_only_import_equals_does_not_request_transform_or_require_a_package() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cts",
            "import type Shape = require('absent'); const x: number = 1;",
        );
        let g = typed_graph(root.path(), "app.cts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 1);
        assert_eq!(g.report.edges[0].state, EdgeState::TypeOnly);
    }

    #[test]
    fn tsx_retains_explicit_edges_but_does_not_invent_implicit_jsx_dependencies() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.tsx",
            "import type {Props} from 'types'; import {X} from './component.ts'; export const view = <X>{import('./deferred.ts')}</X>;",
        );
        put(root.path(), "component.ts", "export const X: any = null;");
        put(root.path(), "deferred.ts", "export default 1;");
        let g = typed_graph(root.path(), "app.tsx");
        assert!(!g.report.fully_resolved);
        assert_eq!(paths(&g), ["app.tsx", "component.ts", "deferred.ts"]);
        assert!(
            g.report
                .diagnostics
                .iter()
                .any(|d| d.code == "UNSUPPORTED_JAVASCRIPT_SURFACE")
        );
        assert!(
            !g.report
                .probes
                .iter()
                .any(|p| p.path.contains("jsx-runtime"))
        );
    }

    #[test]
    fn enum_initializers_capture_runtime_dependencies() {
        let root = tempfile::tempdir().unwrap();
        for source in [
            "enum E { A = require('./value.cjs') }",
            "export enum E { A = require('./value.cjs') }",
            "const enum E { A = require('./value.cjs') }",
            "function value() { enum E { A = require('./value.cjs') } return E.A; }",
        ] {
            put(root.path(), "app.ts", source);
            put(root.path(), "value.cjs", "module.exports=1;");
            let g = typed_graph(root.path(), "app.ts");
            assert!(
                g.report.fully_resolved,
                "{source}: {:?}",
                g.report.diagnostics
            );
            assert_eq!(paths(&g), ["app.ts", "value.cjs"], "{source}");
            assert_eq!(g.report.edges.len(), 1, "{source}");
            assert_eq!(g.report.edges[0].kind, LoadKind::Require);
            assert_eq!(g.report.edges[0].state, EdgeState::Resolved);
            assert_eq!(g.report.edges[0].specifier.as_deref(), Some("./value.cjs"));
            assert!(g.report.edges[0].deferred_or_conditional);
            assert!(!g.report.runtime_completeness);
            assert!(!g.report.execution_performed);
            let pin = g.report.input_hash.clone();
            assert_eq!(
                registry::PinnedModuleRegistry::new(g, &pin)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_FORMAT",
                "capture must not enable a transform-free TypeScript registry"
            );
        }
    }

    #[test]
    fn enum_normalization_helper_captures_keep_routes_but_block_admission() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "value.cjs", "module.exports=1;");
        for source in [
            "const __value=1;\nenum E { A=__value, Loaded=require('./value.cjs') }",
            "const __enum=1;\nenum E { A=__enum, Loaded=require('./value.cjs') }",
            "const __enum_next=1;\nenum E { A=__enum_next, Loaded=require('./value.cjs') }",
            "enum E { __enum=1, Loaded=require('./value.cjs') }",
            "enum E { __enum_next=1, Loaded=require('./value.cjs') }",
            "enum E { __value=1, A=__value, Loaded=require('./value.cjs') }",
            r"const __value=1;
enum E { A=\u005f_value, Loaded=require('./value.cjs') }",
            r"const __enum=1;
enum E { A=__enu\u006d, Loaded=require('./value.cjs') }",
            r"const __enum_next=1;
enum E { A=\u{5f}_enum_next, Loaded=require('./value.cjs') }",
        ] {
            put(root.path(), "app.ts", source);
            let g = typed_graph(root.path(), "app.ts");
            assert!(!g.report.fully_resolved, "{source}");
            assert_eq!(paths(&g), ["app.ts", "value.cjs"], "{source}");
            assert_eq!(g.report.edges.len(), 1, "{source}");
            assert_eq!(g.report.edges[0].state, EdgeState::Resolved);
            assert!(
                g.report.diagnostics.iter().any(|d| {
                    d.code == "TYPESCRIPT_TRANSFORM_REQUIRED"
                        && d.message.contains("normalization helper")
                }),
                "{source}: {:?}",
                g.report.diagnostics
            );
        }
    }

    #[test]
    fn enum_member_names_need_the_engines_exact_binding_contract() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "value.cjs", "module.exports=1;");
        for source in [
            "enum E { 'A'=1, B=A+1, Loaded=require('./value.cjs') }",
            "enum E { \"A\"=1, B=A+1, Loaded=require('./value.cjs') }",
            r"enum E { \u0041=1, B=A+1, Loaded=require('./value.cjs') }",
            r"enum E { \u{41}=1, B=A+1, Loaded=require('./value.cjs') }",
            "enum E { Å=1, B=Å+1, Loaded=require('./value.cjs') }",
        ] {
            put(root.path(), "app.ts", source);
            let g = typed_graph(root.path(), "app.ts");
            assert!(!g.report.fully_resolved, "{source}");
            assert_eq!(paths(&g), ["app.ts", "value.cjs"], "{source}");
            assert_eq!(g.report.edges.len(), 1, "{source}");
            assert_eq!(g.report.edges[0].state, EdgeState::Resolved);
            assert!(
                g.report.diagnostics.iter().any(|d| {
                    d.code == "TYPESCRIPT_TRANSFORM_REQUIRED"
                        && d.message.contains("decoded engine member bindings")
                }),
                "{source}: {:?}",
                g.report.diagnostics
            );
        }
    }

    #[test]
    fn enum_hygiene_guard_ignores_properties_strings_outer_bindings_and_erased_types() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "value.cjs", "module.exports=1;");
        for source in [
            "const __enum=1, __enum_next=2, __value=3;\nenum E { A=require('./value.cjs') }",
            "enum E { A=({__value:1}).__value, B='__enum', C='__enum_next', Loaded=require('./value.cjs') }",
            "enum E { /* __enum __enum_next __value */ A=require('./value.cjs') }",
            "declare enum __enum { __value=1 }\nenum E { A=require('./value.cjs') }",
            "enum E { A=1 as import('type-only').__value, Loaded=require('./value.cjs') }",
            "enum E { A=require('./value.cjs') }\nconst __value=1;",
        ] {
            put(root.path(), "app.ts", source);
            let g = typed_graph(root.path(), "app.ts");
            assert!(
                g.report.fully_resolved,
                "{source}: {:?}",
                g.report.diagnostics
            );
            assert_eq!(paths(&g), ["app.ts", "value.cjs"], "{source}");
            assert_eq!(
                g.report
                    .edges
                    .iter()
                    .filter(|e| e.state == EdgeState::Resolved)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn enum_type_references_are_erased_but_runtime_choices_are_captured() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            r#"
enum Values {
    Selected = require(flag ? './left.cjs' : './right.cjs'),
    Typed = 1 as import('../outside').Count,
}
declare namespace Ambient { const value: typeof import('ambient-only'); }
"#,
        );
        put(root.path(), "left.cjs", "module.exports=1;");
        put(root.path(), "right.cjs", "module.exports=2;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(paths(&g), ["app.ts", "left.cjs", "right.cjs"]);
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::TypeOnly)
                .count(),
            2
        );
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::Resolved)
                .count(),
            2
        );
        assert!(
            g.report
                .probes
                .iter()
                .all(|p| { !p.path.contains("outside") && !p.path.contains("ambient-only") })
        );
    }

    #[test]
    fn enums_do_not_hide_unbounded_loads_or_dynamic_code() {
        let root = tempfile::tempdir().unwrap();
        for source in [
            "enum E { A = require(request) }",
            "enum E { A = import(request) }",
            "enum E { A = eval('require(request)') }",
            "enum E { A = ((load) => load('./hidden.cjs'))(require) }",
            "enum E { A = require('./missing.cjs') }",
        ] {
            put(root.path(), "app.ts", source);
            let g = typed_graph(root.path(), "app.ts");
            assert!(!g.report.fully_resolved, "{source}");
            assert!(
                !g.report.diagnostics.is_empty()
                    || g.report
                        .edges
                        .iter()
                        .any(|e| matches!(e.state, EdgeState::NonLiteral | EdgeState::Unresolved)),
                "unsupported runtime surface lost its evidence: {source}"
            );
        }
    }

    #[test]
    fn unconfigured_typescript_transforms_keep_real_loads_and_block_admission() {
        let root = tempfile::tempdir().unwrap();
        for source in [
            "namespace N { export const x = require('./value.cjs'); }",
            "class C { constructor(public value = require('./value.cjs')) {} }",
            "namespace N { export class C { constructor(public value = require('./value.cjs')) {} } }",
            "module N { export const x = require('./value.cjs'); }",
        ] {
            put(root.path(), "app.ts", source);
            put(root.path(), "value.cjs", "module.exports=1;");
            let g = typed_graph(root.path(), "app.ts");
            assert!(!g.report.fully_resolved, "{source}");
            assert!(
                paths(&g).contains(&"value.cjs"),
                "{source}: {:?}",
                g.report.diagnostics
            );
            assert!(
                g.report
                    .diagnostics
                    .iter()
                    .any(|d| d.code == "TYPESCRIPT_TRANSFORM_REQUIRED")
            );
        }
    }

    #[test]
    fn declaration_files_are_not_accepted_as_runtime_implementations() {
        let root = tempfile::tempdir().unwrap();
        for path in ["types.d.ts", "types.d.mts", "types.d.cts"] {
            put(root.path(), path, "export interface T { value: string }");
            let g = typed_graph(root.path(), path);
            assert!(!g.report.fully_resolved);
            assert_eq!(
                g.report.modules[0].source_language,
                SourceLanguage::Declaration
            );
            assert!(!g.report.modules[0].analyzed);
            assert_eq!(g.report.diagnostics[0].code, "DECLARATION_FILE_NOT_RUNTIME");
        }
    }

    #[test]
    fn typescript_does_not_enable_tsconfig_aliases_or_js_to_ts_substitution() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "import './helper.js'; import './helper'; import '@app/helper';",
        );
        put(root.path(), "helper.ts", "export default 1;");
        put(
            root.path(),
            "tsconfig.json",
            r#"{"compilerOptions":{"paths":{"@app/*":["./*"]}}}"#,
        );
        let g = typed_graph(root.path(), "app.ts");
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.edges.len(), 3);
        assert!(
            g.report
                .edges
                .iter()
                .all(|e| e.state == EdgeState::Unresolved)
        );
        assert_eq!(paths(&g), ["app.ts"]);
        assert!(!g.report.probes.iter().any(|p| p.path == "tsconfig.json"));
    }

    #[test]
    fn erased_references_consume_the_same_global_site_budget() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            &"import type {T} from 'types';".repeat(MAX_SITES + 1),
        );
        assert_eq!(
            capture(root.path(), "app.ts", GraphOptions::default())
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
    }

    #[test]
    fn typescript_syntax_does_not_relax_the_javascript_grammar() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './typed.ts'; import './not-typed.js';",
        );
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
        put(
            root.path(),
            "app.ts",
            "import type {T} from './types.d.ts'; const private_value: number = 1;",
        );
        put(root.path(), "types.d.ts", "export interface T {}");
        let first = typed_graph(root.path(), "app.ts");
        put(
            root.path(),
            "types.d.ts",
            "export interface T {changed: true}",
        );
        assert_eq!(
            first.report.input_hash,
            typed_graph(root.path(), "app.ts").report.input_hash
        );
        put(
            root.path(),
            "app.ts",
            "import type {T} from './different.d.ts';",
        );
        assert_ne!(
            first.report.input_hash,
            typed_graph(root.path(), "app.ts").report.input_hash
        );
        assert!(
            std::str::from_utf8(
                first
                    .source_bytes(&first.report.resolved_entrypoint)
                    .unwrap()
            )
            .unwrap()
            .contains("private_value")
        );
        assert!(
            !serde_json::to_string(first.report())
                .unwrap()
                .contains("private_value")
        );
    }

    #[test]
    fn transparent_typed_loader_calls_preserve_all_explicit_runtime_dependencies() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cts",
            r#"
(require as Loader)('./dep.cjs');
(require satisfies Loader)('./dep.cjs');
require!('./dep.cjs');
(module.require as Loader)('./dep.cjs');
((module as Module).require)('./dep.cjs');
(/* before */ require /* after */)('./dep.cjs');
"#,
        );
        put(root.path(), "dep.cjs", "module.exports=1;");
        let g = typed_graph(root.path(), "app.cts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(g.report.edges.len(), 6);
        assert!(
            g.report
                .edges
                .iter()
                .all(|e| e.kind == LoadKind::Require && e.state == EdgeState::Resolved)
        );
    }

    #[test]
    fn typed_call_operand_and_type_query_have_separate_lookup_authority() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "(require as typeof import('../type-only').load)('./dep.cjs');",
        );
        put(root.path(), "dep.cjs", "module.exports=1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(g.report.fully_resolved, "{:?}", g.report.diagnostics);
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::Resolved)
                .count(),
            1
        );
        assert_eq!(
            g.report
                .edges
                .iter()
                .filter(|e| e.state == EdgeState::TypeOnly)
                .count(),
            1
        );
    }

    #[test]
    fn executable_loader_wrappers_and_mutable_aliases_are_not_treated_as_direct_calls() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.ts",
            "let load; load = require as Loader; load('hidden'); (other, require)('hidden');",
        );
        let g = typed_graph(root.path(), "app.ts");
        assert!(!g.report.fully_resolved);
        assert!(g.report.edges.is_empty());
        assert!(
            g.report
                .diagnostics
                .iter()
                .any(|d| d.code == "INDIRECT_REQUIRE")
        );
    }

    #[test]
    fn angle_assertions_keep_explicit_calls_but_require_non_strip_transform() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.ts", "(<Loader>require)('./dep.cjs');");
        put(root.path(), "dep.cjs", "module.exports=1;");
        let g = typed_graph(root.path(), "app.ts");
        assert!(!g.report.fully_resolved);
        assert_eq!(g.report.edges[0].state, EdgeState::Resolved);
        assert!(
            g.report
                .diagnostics
                .iter()
                .any(|d| d.code == "TYPESCRIPT_TRANSFORM_REQUIRED")
        );
    }

    #[test]
    fn created_require_const_aliases_preserve_factory_and_loader_origins() {
        for (source, language) in [
            (
                "import {createRequire} from 'node:module'; const require=createRequire(import.meta.url); const load=require; load('./dep.cjs'); load.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import {createRequire as require} from 'node:module'; const first=require(import.meta.url), second=first, third=(second); third('./dep.cjs'); third['res'+'olve']('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "import * as mod from 'node:module'; const first=mod.createRequire(import.meta.url); const second=first; function nested(){return second('./dep.cjs');} const later=()=>second.resolve('./dep.cjs'); console.log(typeof arguments);",
                SourceLanguage::JavaScript,
            ),
            (
                "import mod from 'module'; const first: Loader=mod.createRequire(import.meta.url as string); const second: Loader=first!; const third=(second as Loader); third?.('./dep.cjs'); (third.resolve satisfies Resolver)('./dep.cjs');",
                SourceLanguage::TypeScript,
            ),
            (
                "const {createRequire}=require('node:module'); const first=createRequire(__filename), second=first; const third=second; third('./dep.cjs'); third.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
            (
                "const mod=require('module'); const first=mod.createRequire(__filename); const second=(first); if(typeof second==='function') second('./dep.cjs'); second.resolve('./dep.cjs');",
                SourceLanguage::JavaScript,
            ),
        ] {
            let (loads, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                language,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(notices.is_empty(), "{source}: {notices:?}");
            let dependencies: Vec<_> = loads
                .iter()
                .filter(|load| load.specifier.as_deref() == Some("./dep.cjs"))
                .collect();
            assert_eq!(dependencies.len(), 2, "{source}: {loads:?}");
            assert!(
                dependencies
                    .iter()
                    .all(|load| load.kind == LoadKind::Require && !load.type_only)
            );
        }
    }

    #[test]
    fn created_require_aliases_refuse_forward_mutable_and_escaping_bindings() {
        let factory = "import {createRequire as make} from 'node:module';";
        for body in [
            "const load=local; const local=make(import.meta.url); load('./dep.cjs');",
            "const first=second, second=make(import.meta.url); first('./dep.cjs');",
            "const local=make(import.meta.url); const first=second, second=local; first('./dep.cjs');",
            "const local=make(import.meta.url); let load=local; load=other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=(0,local); load('./dep.cjs');",
            "const local=make(import.meta.url); const load=flag?local:other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; load=other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; local=other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; load.resolve=other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; Object.assign(load,{resolve:other}); load('./dep.cjs');",
            "const local=make(import.meta.url); function nested(){const load=local; load('./dep.cjs');}",
            "const local=make(import.meta.url); const load=local; function shadow(load){load('./dep.cjs');}",
            "const local=make(import.meta.url); const load=local; function shadow(local){load('./dep.cjs');}",
            "const local=make(import.meta.url); const load=local; try{}catch(load){load('./dep.cjs');}",
            "const local=make(import.meta.url); const load=local; const {load}=other; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; ({load}=other); load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; const escaped={load}; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; consume(load); load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; export {load}; load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; load.call(null,'./dep.cjs');",
            "const local=make(import.meta.url); const load=local; const resolve=load.resolve; resolve('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; load.resolve('./dep.cjs',{paths:['other']});",
            "const local=make(import.meta.url); const load=local; function shadow(lo\\u0061d){} load('./dep.cjs');",
            "const local=make(import.meta.url); const lo\\u0061d=local; lo\\u0061d('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; eval('load=other'); load('./dep.cjs');",
            "const local=make(import.meta.url); const load=local; import.meta.url='file:///other.mjs'; load('./dep.cjs');",
        ] {
            let source = format!("{factory}{body}");
            let (_, notices, analyzed) = scan(
                &mut Parser::new(),
                source.as_bytes(),
                SourceLanguage::JavaScript,
                &mut Budget::default(),
            )
            .unwrap();
            assert!(analyzed, "{source}: {notices:?}");
            assert!(
                !notices.is_empty(),
                "unproved created-loader alias became complete: {source}"
            );
        }
    }

    #[test]
    fn created_require_aliases_keep_nonliteral_requests_and_binding_limits() {
        let source = "import {createRequire} from 'node:module'; const local=createRequire(import.meta.url); const next=local; next(request); next.resolve(`./${name}.cjs`);";
        let (loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed);
        assert!(notices.is_empty(), "{notices:?}");
        let requests: Vec<_> = loads
            .iter()
            .filter(|load| load.kind == LoadKind::Require)
            .collect();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|load| load.specifier.is_none()));

        let mut source = String::from(
            "import {createRequire} from 'node:module'; const local=createRequire(import.meta.url);",
        );
        for index in 0..MAX_SITES {
            source.push_str(&format!("const load{index}=local;"));
        }
        let failure = scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default(),
        )
        .unwrap_err();
        assert_eq!(failure.code, "ERR_MODULE_GRAPH_LIMIT");
    }

    #[test]
    fn created_require_alias_capsules_keep_importer_routes_and_negative_probes() {
        use super::registry::{ModuleKind, PinnedModuleRegistry, RequestStyle};
        let root = tempfile::tempdir().unwrap();
        let source = "import {createRequire} from 'node:module'; const require=createRequire(import.meta.url); const load=require; load('pkg'); load('./value.cjs'); try{load('optional')}catch(error){}";
        put(root.path(), "app.mjs", source);
        put(root.path(), "value.cjs", "module.exports=42;");
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root.path(),
            "node_modules/pkg/index.cjs",
            "const {createRequire}=require('node:module'); const local=createRequire(__filename); const read=local; module.exports=read('./value.cjs');",
        );
        put(
            root.path(),
            "node_modules/pkg/value.cjs",
            "module.exports=17;",
        );
        let captured = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(captured.report().diagnostics.is_empty());
        assert_eq!(captured.report().edges.len(), 6);
        let pin = captured.report().input_hash.clone();
        let capsule = super::capsule::encode(&captured).unwrap();
        put(
            root.path(),
            "value.cjs",
            "throw new Error('live source changed');",
        );
        put(
            root.path(),
            "node_modules/pkg/value.cjs",
            "throw new Error('live package changed');",
        );
        put(
            root.path(),
            "node_modules/optional/index.js",
            "module.exports='new live dependency';",
        );
        put(root.path(), "uncaptured.cjs", "module.exports=99;");
        let replayed = super::capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
        assert_eq!(replayed.report(), captured.report());
        let registry = PinnedModuleRegistry::new_with_kind_resolver(
            replayed,
            &pin,
            |module, _, _| {
                Ok(if module.format_hint == "commonjs" {
                    ModuleKind::CommonJs
                } else {
                    ModuleKind::EsModule
                })
            },
            |specifier, _| match specifier {
                "module" | "node:module" => Some("node:module"),
                _ => None,
            },
        )
        .unwrap();
        let entry = registry
            .lookup(None, registry.entrypoint(), RequestStyle::Import)
            .unwrap();
        let local = registry
            .lookup(Some(entry.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(local.source(), "module.exports=42;");
        let package = registry
            .lookup(Some(entry.id()), "pkg", RequestStyle::Require)
            .unwrap();
        let nested = registry
            .lookup(Some(package.id()), "./value.cjs", RequestStyle::Require)
            .unwrap();
        assert_eq!(nested.source(), "module.exports=17;");
        assert_ne!(nested.id(), local.id());
        assert_eq!(registry.summary().missing_routes, 1);
        assert_eq!(
            registry
                .lookup(Some(entry.id()), "optional", RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "MODULE_NOT_FOUND"
        );
        for (importer, specifier, style) in [
            (entry.id(), "./uncaptured.cjs", RequestStyle::Require),
            (entry.id(), "./value.cjs", RequestStyle::Import),
            (package.id(), "optional", RequestStyle::Require),
        ] {
            assert_eq!(
                registry
                    .lookup(Some(importer), specifier, style)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
    }
}
