//! Entrypoint-wide capture of static and exact-string JavaScript/TypeScript requests.
//!
//! One resolver owns every source, manifest, link and negative probe for the
//! whole graph. This is a conservative source graph, not execution or proof of
//! all runtime dependencies: literal deferred loads are included even in dead
//! branches; exact string concatenations and templates add no runtime lookup
//! authority. Dynamic/indirect loaders and unsupported syntax stay explicit.
//! TypeScript follows explicit runtime syntax, not tsconfig-dependent emit.
//! Whole-declaration type imports and import types are recorded but never read;
//! inline type specifiers retain their declaration's side-effect dependency.
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
/// Only immutable top-level imports and const declarations participate. Native
/// CommonJS require may also flow through an ordered chain of const aliases.
/// Every other occurrence of their names is checked by the ordinary bounded
/// walk; shadowing, mutation and escape make the graph incomplete instead of
/// lending an unrelated function the captured importer's require authority.
#[derive(Default)]
struct CreateRequireBindings<'source> {
    factories: BTreeMap<&'source str, CreateRequireFactory>,
    commonjs_factories: BTreeSet<&'source str>,
    loaders: BTreeSet<&'source str>,
    commonjs_aliases: BTreeSet<&'source str>,
    allowed_identifiers: BTreeSet<usize>,
    factory_members: BTreeSet<usize>,
    factory_patterns: BTreeSet<usize>,
    filename_origin: bool,
}

impl<'source> CreateRequireBindings<'source> {
    fn discover(root: Node<'_>, source: &'source str) -> Result<Self> {
        let mut bindings = Self::default();
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if statement.kind() == "lexical_declaration" && keyword(statement, "const") {
                bindings.discover_commonjs_factories(statement, source)?;
                continue;
            }
            if statement.kind() != "import_statement" || keyword(statement, "type") {
                continue;
            }
            let from_module = statement
                .child_by_field_name("source")
                .and_then(|node| literal(node, source))
                .is_some_and(|name| matches!(name.as_str(), "module" | "node:module"));
            if !from_module {
                continue;
            }
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
                        bindings.add_factory(
                            part,
                            None,
                            CreateRequireFactory::Namespace,
                            source,
                        )?;
                    } else if part.kind() == "namespace_import" {
                        if let Some(name) = part.named_child(0) {
                            bindings.add_factory(
                                name,
                                None,
                                CreateRequireFactory::Namespace,
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
                            if imported.kind() == "identifier"
                                && imported.utf8_text(source.as_bytes()) == Ok("createRequire")
                            {
                                let local =
                                    specifier.child_by_field_name("alias").unwrap_or(imported);
                                bindings.add_factory(
                                    local,
                                    Some(imported),
                                    CreateRequireFactory::Named,
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
            return Ok(bindings);
        }
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if statement.kind() != "lexical_declaration" || !keyword(statement, "const") {
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
                    .is_ok_and(|name| bindings.commonjs_factories.contains(name));
                let own_origin = arguments.next().is_some_and(|argument| {
                    let argument = runtime_operand(argument);
                    if commonjs {
                        return argument.kind() == "identifier"
                            && argument.utf8_text(source.as_bytes()) == Ok("__filename");
                    }
                    named_member(argument, "url", source)
                        && argument
                            .child_by_field_name("object")
                            .is_some_and(|object| {
                                let object = runtime_operand(object);
                                object.kind() == "meta_property"
                                    && object.utf8_text(source.as_bytes()) == Ok("import.meta")
                            })
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
                bindings.filename_origin |= commonjs;
                bindings.allowed_identifiers.insert(name.id());
                bindings.allowed_identifiers.insert(factory.id());
                bindings
                    .factory_members
                    .insert(runtime_operand(function).id());
            }
        }
        bindings.discover_commonjs_aliases(root, source)?;
        Ok(bindings)
    }

    /// An alias retains exactly this module's require origin. Only earlier
    /// aliases in top-level const initializers may supply a later alias; no
    /// fixed-point inference, nested binding, property read or executable
    /// expression can manufacture another loader. The full scan still rejects
    /// every unproved occurrence of require or any alias, including shadowing.
    fn discover_commonjs_aliases(&mut self, root: Node<'_>, source: &'source str) -> Result<()> {
        // An explicitly imported factory or createRequire result named
        // require is not the CommonJS wrapper binding. Its existing narrower
        // contract remains authoritative, including refusal of aliases.
        if self.factories.contains_key("require") || self.loaders.contains("require") {
            return Ok(());
        }
        let mut statements = root.walk();
        for statement in root.named_children(&mut statements) {
            if statement.kind() != "lexical_declaration" || !keyword(statement, "const") {
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
                if origin != "require" && !self.commonjs_aliases.contains(origin) {
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
                self.commonjs_aliases.insert(spelling);
                self.loaders.insert(spelling);
                self.allowed_identifiers.insert(name.id());
                self.allowed_identifiers.insert(value.id());
            }
        }
        Ok(())
    }

    /// Keep the ordinary require('node:module') edge in the graph. Only a
    /// direct builtin load into a top-level const proves a factory. Defaults,
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
                self.add_commonjs_factory(name, CreateRequireFactory::Namespace, source)?;
            } else if name.kind() == "object_pattern" {
                let mut properties = name.walk();
                for property in name.named_children(&mut properties) {
                    if property.kind() == "shorthand_property_identifier_pattern"
                        && property.utf8_text(source.as_bytes()) == Ok("createRequire")
                    {
                        self.add_commonjs_factory(property, CreateRequireFactory::Named, source)?;
                    } else if property.kind() == "pair_pattern"
                        && property.child_by_field_name("key").is_some_and(|key| {
                            key.utf8_text(source.as_bytes()) == Ok("createRequire")
                                || literal(key, source).as_deref() == Some("createRequire")
                        })
                        && let Some(local) = property.child_by_field_name("value")
                    {
                        self.add_commonjs_factory(local, CreateRequireFactory::Named, source)?;
                        if self.allowed_identifiers.contains(&local.id()) {
                            self.factory_patterns.insert(property.id());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn add_commonjs_factory(
        &mut self,
        local: Node<'_>,
        kind: CreateRequireFactory,
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
            self.commonjs_factories.insert(spelling);
        }
        Ok(())
    }

    fn reserve_binding(&self) -> Result<()> {
        if self.factories.len() + self.loaders.len() >= MAX_SITES {
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
        if spelling.contains('\\') || self.factories.contains_key(spelling) {
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
            {
                return Some(object);
            }
        }
        None
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
    let mut loads = Vec::new();
    let mut notices = Vec::new();
    let mut cursor = tree.walk();
    // One inherited bit per cursor depth, not an ancestor scan at every node.
    // All syntax still consumes the global budget, including erased subtrees.
    let mut type_context = vec![false];
    loop {
        budget.ast_nodes += 1;
        if budget.ast_nodes > MAX_AST_NODES {
            return Err(limit());
        }
        let node = cursor.node();
        let erased = language.is_typescript()
            && (*type_context.last().expect("root context") || erased_region(node));
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
                } else if bindings.allowed_identifiers.contains(&node.id()) {
                    // Exactly the immutable import, const declaration and
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
                } else if bindings.factories.contains_key(spelling) {
                    issue = Some((
                        "INDIRECT_CREATE_REQUIRE",
                        "createRequire factory must initialize a top-level const from this module's unchanged origin",
                    ));
                } else if bindings.loaders.contains(spelling) {
                    if !bindings.direct_loader_use(node, text) && !loader_typeof_probe(node) {
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
        if let Some((kind, argument)) = request {
            budget.site()?;
            loads.push(Load {
                site: SourceSite::of(node),
                kind,
                specifier: literal(argument, text),
                type_only: erased,
            });
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
        }
    }
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
        "enum_declaration" | "internal_module" | "module" | "import_alias" | "decorator"
        | "type_assertion" => true,
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
        let source = format!("require({expression});");
        let (mut loads, notices, analyzed) = scan(
            &mut Parser::new(),
            source.as_bytes(),
            language,
            &mut Budget::default(),
        )
        .unwrap();
        assert!(analyzed, "{expression}: {notices:?}");
        assert!(notices.is_empty(), "{expression}: {notices:?}");
        assert_eq!(loads.len(), 1, "{expression}: {loads:?}");
        loads.pop().unwrap().specifier
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
    fn commonjs_require_aliases_refuse_shadowing_mutation_and_escaped_origins() {
        for body in [
            "load=replacement;",
            "load.resolve=replacement;",
            "Object.assign(load, {resolve:replacement});",
            "const escaped={load};",
            "consume(load);",
            "export {load};",
            "let next=load; next('./dep.cjs');",
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
            "let load=require; load('./dep.cjs');",
            "var load=require; load('./dep.cjs');",
            "const first=second; const second=require; first('./dep.cjs');",
            "const load=(0, require); load('./dep.cjs');",
            "const load=condition ? require : other; load('./dep.cjs');",
            "const load=module.require; load('./dep.cjs');",
            "const {load}=require; load('./dep.cjs');",
            "function nested(){const load=require; load('./dep.cjs');}",
            "import {createRequire as require} from 'node:module'; const load=require; load('./dep.cjs');",
            "import {createRequire} from 'node:module'; const require=createRequire(import.meta.url); const load=require; load('./dep.cjs');",
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
            "let {createRequire:make}=require('node:module'); const local=make(__filename); local('./dep.cjs');",
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
            "let local=make(import.meta.url); local('./dep.cjs');",
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
            "const alias=local;",
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
    fn exact_string_capture_rejects_coercion_bindings_branches_and_side_effects() {
        for expression in [
            "'./' + name",
            "`./${name}.cjs`",
            "'./' + 1",
            "`./${1}.cjs`",
            "true ? './one.cjs' : './two.cjs'",
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
            "import(name); let load=require; load('hidden'); const f=eval;",
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
            "let load = require as Loader; typeof require; load('./hidden.cjs');",
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
    fn nonerasable_typescript_keeps_real_loads_but_requires_transform_analysis() {
        let root = tempfile::tempdir().unwrap();
        for source in [
            "enum E { A = require('./value.cjs') }",
            "namespace N { export const x = require('./value.cjs'); }",
            "class C { constructor(public value = require('./value.cjs')) {} }",
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
            "let load = require as Loader; load('hidden'); (other, require)('hidden');",
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
}
