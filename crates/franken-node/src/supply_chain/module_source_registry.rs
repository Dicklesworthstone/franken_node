//! Pinned, closed-world source delivery for an engine module resolver.
//!
//! Admission consumes a captured (or replayed) graph and an independent graph
//! pin. Lookup thereafter has no filesystem, parser, environment or network
//! dependency. A module may request only the exact importer/style/specifier
//! routes captured for it. This is source delivery, not capability admission:
//! engine consumers must authorize every lookup through ModulePolicyHook.

use super::{
    CapturedModuleGraph, EdgeState, LoadKind, ModuleId, ResolutionError, SourceLanguage, error,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

type Result<T> = std::result::Result<T, ResolutionError>;
const ID_DOMAIN: &[u8] = b"franken-node/sealed-module-id/v1\0";
const BUILTIN_ID_DOMAIN: &[u8] = b"franken-node/sealed-native-builtin/v1\0";
type ImporterRoutes = BTreeMap<RequestStyle, BTreeMap<String, RegisteredTarget>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStyle {
    Import,
    Require,
}

impl RequestStyle {
    fn for_load(kind: LoadKind) -> Self {
        if kind == LoadKind::Require {
            Self::Require
        } else {
            Self::Import
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    EsModule,
    CommonJs,
    /// Engine-owned terminal descriptor; it has no captured source file.
    NativeBuiltin,
}

impl ModuleKind {
    pub fn entry_style(self) -> RequestStyle {
        match self {
            Self::EsModule => RequestStyle::Import,
            Self::CommonJs | Self::NativeBuiltin => RequestStyle::Require,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RegisteredTarget {
    Module { id: String },
    /// A captured CommonJS lookup that deterministically found no module.
    /// This is a terminal failure, never an invitation to probe the live host.
    Missing { error: ResolutionError },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisteredDependency {
    pub specifier: String,
    pub style: RequestStyle,
    pub target: RegisteredTarget,
}

/// Immutable registered source. Debug and serialization intentionally omit
/// source text; engine adapters copy it only after their policy hook succeeds.
pub struct RegisteredModule {
    id: String,
    origin: ModuleId,
    kind: ModuleKind,
    source: Arc<str>,
    source_sha256: String,
    dependencies: Vec<RegisteredDependency>,
}

impl RegisteredModule {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn origin(&self) -> &ModuleId {
        &self.origin
    }
    pub fn kind(&self) -> ModuleKind {
        self.kind
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    pub fn dependencies(&self) -> &[RegisteredDependency] {
        &self.dependencies
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrySummary {
    pub schema_version: &'static str,
    pub graph_input_hash: String,
    pub entrypoint: String,
    pub modules: usize,
    pub routes: usize,
    pub missing_routes: usize,
    pub execution_performed: bool,
    pub policy_admission_performed: bool,
}

/// A borrowed, resolved route. This is data, not a policy permit. Consumers
/// must authorize every yielded route, including routes to an already visited
/// module, before deduplicating module outputs.
pub struct RegisteredRequest<'a> {
    pub referrer: Option<&'a str>,
    pub specifier: &'a str,
    pub style: RequestStyle,
    pub module: &'a RegisteredModule,
}

/// Lazy breadth-first route traversal. Only modules are queued, once each;
/// high fan-in therefore retains O(modules), not O(routes), traversal state.
/// Request strings and sources are borrowed from the immutable registry.
/// Dropping the iterator stops traversal immediately after a policy denial.
pub struct ReachableRequests<'a> {
    registry: &'a PinnedModuleRegistry,
    entry: Option<RegisteredRequest<'a>>,
    pending: VecDeque<&'a RegisteredModule>,
    scheduled: BTreeSet<&'a str>,
    current: Option<(&'a RegisteredModule, usize)>,
    failed: bool,
}

impl<'a> Iterator for ReachableRequests<'a> {
    type Item = Result<RegisteredRequest<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if let Some(entry) = self.entry.take() {
            return Some(Ok(entry));
        }
        loop {
            if self.current.is_none() {
                self.current = self.pending.pop_front().map(|module| (module, 0));
            }
            let (importer, index) = self.current?;
            let Some(dependency) = importer.dependencies.get(index) else {
                self.current = None;
                continue;
            };
            self.current = Some((importer, index + 1));
            if let Err(error) = validate_specifier(&dependency.specifier) {
                self.failed = true;
                return Some(Err(error));
            }
            let target = match &dependency.target {
                RegisteredTarget::Module { id } => id,
                RegisteredTarget::Missing { error } => {
                    // A complete eager walk cannot deliver an absent module.
                    // Runtime require evaluates this route only if reached,
                    // where the engine can expose its catchable missing error.
                    self.failed = true;
                    return Some(Err(error.clone()));
                }
            };
            let Some(module) = self.registry.modules.get(target) else {
                // Admission normally makes this impossible. Do not turn an
                // inconsistent graph into a truncated successful traversal.
                self.failed = true;
                return Some(Err(invalid_graph()));
            };
            if self.scheduled.insert(module.id()) {
                self.pending.push_back(module);
            }
            return Some(Ok(RegisteredRequest {
                referrer: Some(importer.id()),
                specifier: &dependency.specifier,
                style: dependency.style,
                module,
            }));
        }
    }
}

impl std::iter::FusedIterator for ReachableRequests<'_> {}

/// Thread-transferable immutable data, NOT an authorization decision or an
/// evaluation cache. Engine policy must be checked again even on a cache hit.
/// Canonical IDs are opaque and graph-scoped, never host paths to reopen.
pub struct PinnedModuleRegistry {
    summary: RegistrySummary,
    modules: BTreeMap<String, RegisteredModule>,
    // Split the key so BTreeMap's borrowed lookup can use &str directly.
    // A tuple of owned strings allocated on every successful load.
    routes: BTreeMap<String, ImporterRoutes>,
}

impl PinnedModuleRegistry {
    pub fn new(graph: CapturedModuleGraph, independent_graph_pin: &str) -> Result<Self> {
        Self::new_with_kind_resolver(graph, independent_graph_pin, |module, _, _| {
            match (module.source_language, module.format_hint.as_str()) {
                (SourceLanguage::JavaScript, "module") => Ok(ModuleKind::EsModule),
                (SourceLanguage::JavaScript, "commonjs") => Ok(ModuleKind::CommonJs),
                _ => Err(error(
                    "ERR_MODULE_REGISTRY_FORMAT",
                    format!(
                        "module {:?} needs engine format detection or transformation",
                        module.id.path
                    ),
                )),
            }
        }, |_| None)
    }

    /// Engine-owned preparation may assign a runtime kind to captured source.
    /// The ordinary constructor remains transform-free. Crucially, pins and
    /// graph completeness are checked BEFORE the callback sees source bytes.
    /// The callback cannot rewrite identities, routes, source bytes or pins.
    /// A separate engine callback may admit an exact captured CommonJS builtin
    /// requirement as a source-free terminal. It never changes the report or
    /// allows unknown, computed, import-style or uncaptured runtime requests.
    pub(super) fn new_with_kind_resolver<F, B>(
        graph: CapturedModuleGraph,
        independent_graph_pin: &str,
        mut kind_of: F,
        native_builtin: B,
    ) -> Result<Self>
    where
        F: FnMut(&super::SourceModule, &str, &super::SourceGraphReport) -> Result<ModuleKind>,
        B: Fn(&str) -> Option<&'static str>,
    {
        let digest = independent_graph_pin.strip_prefix("sha256:").unwrap_or("");
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(error(
                "ERR_MODULE_REGISTRY_PIN",
                "an independent canonical source-graph pin is required",
            ));
        }
        if independent_graph_pin != graph.report().input_hash {
            return Err(error(
                "ERR_MODULE_REGISTRY_PIN_MISMATCH",
                "captured graph differs from reviewed source graph",
            ));
        }
        let report = graph.report();
        let mut builtin_targets = BTreeMap::<String, (String, &'static str)>::new();
        let mut has_missing_routes = false;
        let incomplete = || error(
            "ERR_MODULE_REGISTRY_INCOMPLETE",
            "source delivery requires a closed, analyzed graph with engine-approved terminal requirements",
        );
        if !report.diagnostics.is_empty() || report.modules.iter().any(|m| !m.analyzed) {
            return Err(incomplete());
        }
        for edge in &report.edges {
            match edge.state {
                EdgeState::Resolved | EdgeState::TypeOnly => {}
                EdgeState::RuntimeRequired
                    if edge.kind == LoadKind::Require
                        && edge.target.is_none()
                        && edge.error.as_ref().is_some_and(|failure|
                            failure.code == "ERR_RUNTIME_MODULE_REQUIRED") =>
                {
                    let request = edge.specifier.as_deref().ok_or_else(incomplete)?;
                    let name = native_builtin(request).ok_or_else(incomplete)?;
                    builtin_targets.insert(
                        request.to_owned(),
                        (native_builtin_id(&report.input_hash, name), name),
                    );
                }
                EdgeState::Unresolved
                    if edge.kind == LoadKind::Require
                        && edge.target.is_none()
                        && edge.specifier.is_some()
                        && edge.error.as_ref().is_some_and(|failure|
                            failure.code == "MODULE_NOT_FOUND") =>
                {
                    // Optional dependencies and require.resolve probes are
                    // ordinary CommonJS control flow. Capture has sealed the
                    // negative probes too; preserve this exact missing result
                    // without pretending it resolves or predicting a catch.
                    has_missing_routes = true;
                }
                _ => return Err(incomplete()),
            }
        }
        // The captured report remains truthful: runtime requirements are not
        // source files and never make its fully_resolved flag true.
        if !report.fully_resolved && builtin_targets.is_empty() && !has_missing_routes {
            return Err(incomplete());
        }
        let identities: BTreeMap<_, _> = report
            .modules
            .iter()
            .map(|m| (m.id.clone(), canonical_id(&report.input_hash, &m.id)))
            .collect();
        let mut modules = BTreeMap::new();
        let mut shared_sources = BTreeMap::<String, Arc<str>>::new();
        for module in &report.modules {
            let bytes = graph.source_bytes(&module.id).ok_or_else(invalid_graph)?;
            let text = std::str::from_utf8(bytes).map_err(|_| invalid_graph())?;
            let kind = kind_of(module, text, report)?;
            let source = if let Some(existing) = shared_sources.get(&module.id.path) {
                if existing.as_ref() != text {
                    return Err(invalid_graph());
                }
                Arc::clone(existing)
            } else {
                let source: Arc<str> = Arc::from(text);
                shared_sources.insert(module.id.path.clone(), Arc::clone(&source));
                source
            };
            let id = identities
                .get(&module.id)
                .ok_or_else(invalid_graph)?
                .clone();
            if modules
                .insert(
                    id.clone(),
                    RegisteredModule {
                        id,
                        origin: module.id.clone(),
                        kind,
                        source,
                        source_sha256: module.content_sha256.clone(),
                        dependencies: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(invalid_graph());
            }
        }
        for (id, name) in builtin_targets.values() {
            modules.entry(id.clone()).or_insert_with(|| RegisteredModule {
                id: id.clone(),
                origin: ModuleId { path: (*name).to_owned(), url_suffix: String::new() },
                kind: ModuleKind::NativeBuiltin,
                source: Arc::from(""),
                source_sha256: hex::encode(Sha256::digest([])),
                dependencies: Vec::new(),
            });
        }
        let mut routes = BTreeMap::<String, ImporterRoutes>::new();
        let mut route_count = 0;
        let mut missing_routes = 0;
        for edge in &report.edges {
            if edge.state == EdgeState::TypeOnly {
                continue;
            }
            let importer = identities.get(&edge.importer).ok_or_else(invalid_graph)?;
            let specifier = edge.specifier.as_ref().ok_or_else(invalid_graph)?;
            let target = match edge.state {
                EdgeState::RuntimeRequired => RegisteredTarget::Module {
                    id: builtin_targets.get(specifier).ok_or_else(invalid_graph)?.0.clone(),
                },
                EdgeState::Unresolved => RegisteredTarget::Missing {
                    error: edge.error.clone().ok_or_else(invalid_graph)?,
                },
                _ => RegisteredTarget::Module {
                    id: identities
                        .get(edge.target.as_ref().ok_or_else(invalid_graph)?)
                        .ok_or_else(invalid_graph)?
                        .clone(),
                },
            };
            let style = RequestStyle::for_load(edge.kind);
            let by_specifier = routes
                .entry(importer.clone())
                .or_default()
                .entry(style)
                .or_default();
            if let Some(previous) = by_specifier.get(specifier) {
                if previous != &target {
                    return Err(invalid_graph());
                }
                continue;
            }
            by_specifier.insert(specifier.clone(), target.clone());
            route_count += 1;
            missing_routes += usize::from(matches!(target, RegisteredTarget::Missing { .. }));
            modules
                .get_mut(importer)
                .ok_or_else(invalid_graph)?
                .dependencies
                .push(RegisteredDependency {
                    specifier: specifier.clone(),
                    style,
                    target,
                });
        }
        let entrypoint = identities
            .get(&report.resolved_entrypoint)
            .ok_or_else(invalid_graph)?
            .clone();
        let summary = RegistrySummary {
            schema_version: "franken-node/sealed-module-registry/v2",
            graph_input_hash: report.input_hash.clone(),
            entrypoint,
            modules: modules.len(),
            routes: route_count,
            missing_routes,
            execution_performed: false,
            policy_admission_performed: false,
        };
        Ok(Self {
            summary,
            modules,
            routes,
        })
    }

    pub fn summary(&self) -> &RegistrySummary {
        &self.summary
    }
    pub fn entrypoint(&self) -> &str {
        &self.summary.entrypoint
    }
    pub fn entry_style(&self) -> RequestStyle {
        self.modules[&self.summary.entrypoint].kind.entry_style()
    }

    /// Immutable module inventory for preparing bounded engine-side caches.
    /// Enumeration, like lookup, confers no policy or execution authority.
    pub fn modules(&self) -> impl ExactSizeIterator<Item = &RegisteredModule> {
        self.modules.values()
    }

    /// Data lookup only. This never confers an execution/capability permit.
    /// With no referrer, only the exact entrypoint ID and its admitted style
    /// are accepted. With a referrer, even a known target's canonical ID cannot
    /// bypass the recorded importer/style/specifier route.
    pub fn lookup(
        &self,
        referrer: Option<&str>,
        specifier: &str,
        style: RequestStyle,
    ) -> Result<&RegisteredModule> {
        validate_specifier(specifier)?;
        let id = match referrer {
            None if specifier == self.entrypoint() && style == self.entry_style() => {
                self.entrypoint()
            }
            None => {
                return Err(error(
                    "ERR_MODULE_REGISTRY_ENTRY",
                    "only the sealed entrypoint may be requested without a referrer",
                ));
            }
            Some(importer) => {
                if !self.modules.contains_key(importer) {
                    return Err(error(
                        "ERR_MODULE_REGISTRY_REFERRER",
                        "referrer does not belong to this sealed graph",
                    ));
                }
                let target = self.routes
                    .get(importer)
                    .and_then(|styles| styles.get(&style))
                    .and_then(|specifiers| specifiers.get(specifier))
                    .ok_or_else(|| {
                        error(
                            "ERR_MODULE_REGISTRY_ROUTE",
                            "module request was not captured for this importer and load style",
                        )
                    })?;
                match target {
                    RegisteredTarget::Module { id } => id.as_str(),
                    RegisteredTarget::Missing { error } => return Err(error.clone()),
                }
            }
        };
        self.modules.get(id).ok_or_else(invalid_graph)
    }

    /// Borrowed breadth-first routes with O(modules) retained traversal state.
    /// Initial request validation happens before the iterator is returned.
    /// Every distinct incoming route is yielded, including cycle back-edges.
    pub fn walk_requests<'a>(
        &'a self,
        referrer: Option<&'a str>,
        specifier: &'a str,
        style: RequestStyle,
    ) -> Result<ReachableRequests<'a>> {
        let module = self.lookup(referrer, specifier, style)?;
        Ok(ReachableRequests {
            registry: self,
            entry: Some(RegisteredRequest {
                referrer,
                specifier,
                style,
                module,
            }),
            pending: VecDeque::from([module]),
            scheduled: BTreeSet::from([module.id()]),
            current: None,
            failed: false,
        })
    }

    /// Deterministic breadth-first requests, not evaluation order. Each route
    /// is included once, even when the target was already reached by another
    /// importer. An engine adapter must authorize those edges BEFORE deduping
    /// its returned module list, so diamond/cycle edges cannot bypass policy.
    /// Consumers that can stop on denial should use `walk_requests` instead
    /// of allocating this complete owned projection.
    pub fn reachable_requests(
        &self,
        referrer: Option<&str>,
        specifier: &str,
        style: RequestStyle,
    ) -> Result<Vec<(Option<String>, String, RequestStyle)>> {
        self.walk_requests(referrer, specifier, style)?
            .map(|request| {
                request.map(|request| {
                    (
                        request.referrer.map(str::to_owned),
                        request.specifier.to_owned(),
                        request.style,
                    )
                })
            })
            .collect()
    }
}

fn validate_specifier(specifier: &str) -> Result<()> {
    if specifier.is_empty() || specifier.len() > 4096 || specifier.chars().any(char::is_control) {
        return Err(error(
            "ERR_MODULE_REGISTRY_REQUEST",
            "invalid module request",
        ));
    }
    Ok(())
}

fn invalid_graph() -> ResolutionError {
    error(
        "ERR_MODULE_REGISTRY_GRAPH",
        "captured source graph has inconsistent module identities or routes",
    )
}

fn native_builtin_id(graph_hash: &str, name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(BUILTIN_ID_DOMAIN);
    for part in [graph_hash, name] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    format!("franken-captured-builtin:{}", hex::encode(digest.finalize()))
}

fn canonical_id(graph_hash: &str, id: &ModuleId) -> String {
    let mut digest = Sha256::new();
    digest.update(ID_DOMAIN);
    for part in [graph_hash, &id.path, &id.url_suffix] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    format!("franken-captured:{}", hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::super::{GraphOptions, capsule, capture};
    use super::*;
    use std::path::Path;

    fn put(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    fn registry(root: &Path, entry: &str) -> PinnedModuleRegistry {
        let graph = capture(root, entry, GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        PinnedModuleRegistry::new(graph, &pin).ok().unwrap()
    }
    fn entry(registry: &PinnedModuleRegistry) -> &RegisteredModule {
        registry
            .lookup(None, registry.entrypoint(), registry.entry_style())
            .ok()
            .unwrap()
    }

    #[test]
    fn independent_pin_is_required_and_mismatch_precedes_graph_admission() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'missing';");
        for pin in ["", "sha256:x", &format!("sha256:{}", "A".repeat(64))] {
            let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
            assert_eq!(
                PinnedModuleRegistry::new(graph, pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_PIN"
            );
        }
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert_eq!(
            PinnedModuleRegistry::new(graph, &format!("sha256:{}", "0".repeat(64)))
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_PIN_MISMATCH"
        );
    }

    #[test]
    fn incomplete_and_runtime_required_graphs_are_not_source_load_authority() {
        for source in [
            "import 'missing';",
            "import 'node:fs';",
            "require(variable);",
            "const x = ;",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_INCOMPLETE"
            );
        }
    }

    #[test]
    fn captured_missing_require_routes_are_terminal_without_invented_modules() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", r#"
            try { module.exports = require('optional-addon'); }
            catch (error) { module.exports = require('./fallback.cjs'); }
            try { require.resolve('optional-addon'); } catch (error) {}
        "#);
        put(root.path(), "fallback.cjs", "module.exports = 42;");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!graph.report().fully_resolved);
        assert!(graph.report().diagnostics.is_empty());
        let pin = graph.report().input_hash.clone();
        let r = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
        assert_eq!(r.summary().graph_input_hash, pin);
        assert_eq!(r.summary().modules, 2);
        assert_eq!(r.summary().routes, 2);
        assert_eq!(r.summary().missing_routes, 1);
        assert_eq!(entry(&r).dependencies().len(), 2);
        assert!(matches!(
            entry(&r).dependencies()[0].target,
            RegisteredTarget::Missing { .. }
        ));
        for _ in 0..2 {
            let missing = r.lookup(Some(r.entrypoint()), "optional-addon", RequestStyle::Require)
                .err().unwrap();
            assert_eq!(missing.code, "MODULE_NOT_FOUND");
        }
        assert_eq!(
            r.lookup(Some(r.entrypoint()), "./fallback.cjs", RequestStyle::Require)
                .ok().unwrap().source(),
            "module.exports = 42;"
        );
        for (specifier, style) in [
            ("optional-addon", RequestStyle::Import),
            ("different-addon", RequestStyle::Require),
            ("././fallback.cjs", RequestStyle::Require),
        ] {
            assert_eq!(
                r.lookup(Some(r.entrypoint()), specifier, style).err().unwrap().code,
                "ERR_MODULE_REGISTRY_ROUTE"
            );
        }
        let fallback = r.lookup(Some(r.entrypoint()), "./fallback.cjs", RequestStyle::Require)
            .ok().unwrap();
        assert_eq!(
            r.lookup(Some(fallback.id()), "optional-addon", RequestStyle::Require)
                .err().unwrap().code,
            "ERR_MODULE_REGISTRY_ROUTE"
        );
        let mut walk = r.walk_requests(None, r.entrypoint(), r.entry_style()).unwrap();
        assert!(walk.next().unwrap().is_ok());
        assert_eq!(walk.next().unwrap().err().unwrap().code, "MODULE_NOT_FOUND");
        assert!(walk.next().is_none());
        assert!(walk.next().is_none());
    }

    #[test]
    fn replayed_missing_require_stays_absent_after_an_install_or_source_change() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('./optional.cjs');");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let graph_pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        put(root.path(), "optional.cjs", "module.exports = 99;");
        put(root.path(), "app.cjs", "require('./new.cjs');");
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert!(!replayed.report().fully_resolved);
        let r = PinnedModuleRegistry::new(replayed, &graph_pin).ok().unwrap();
        assert_eq!(entry(&r).source(), "require('./optional.cjs');");
        assert_eq!(
            r.lookup(Some(r.entrypoint()), "./optional.cjs", RequestStyle::Require)
                .err().unwrap().code,
            "MODULE_NOT_FOUND"
        );
        assert_eq!(
            r.lookup(Some(r.entrypoint()), "./new.cjs", RequestStyle::Require)
                .err().unwrap().code,
            "ERR_MODULE_REGISTRY_ROUTE"
        );
        let current = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_ne!(current.report().input_hash, graph_pin);
    }

    #[test]
    fn only_commonjs_module_not_found_is_an_admissible_negative_route() {
        for source in [
            "import './absent.mjs';",
            "import('./absent.mjs');",
            "require('pkg/private');",
            "require('broken');",
            "require('node:unknown');",
            "require(variable);",
            "require('./optional.cjs'); import './absent.mjs';",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            put(root.path(), "node_modules/pkg/package.json", r#"{"exports":{".":"./index.cjs"}}"#);
            put(root.path(), "node_modules/broken/package.json", "{invalid");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                PinnedModuleRegistry::new(graph, &pin).err()
                    .unwrap_or_else(|| panic!("unexpectedly admitted {source}")).code,
                "ERR_MODULE_REGISTRY_INCOMPLETE",
                "{source}"
            );
        }
    }

    #[test]
    fn formats_requiring_detection_or_transforms_are_not_guessed() {
        for (name, source) in [
            ("app.js", "const x=1;"),
            ("app.ts", "const x: number=1;"),
            ("app.mts", "export const x: number=1;"),
            ("app.json", "{}"),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), name, source);
            let graph = capture(root.path(), name, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_FORMAT",
                "{name}"
            );
        }
    }

    #[test]
    fn explicit_package_type_supplies_the_javascript_module_kind() {
        for (kind, expected) in [
            ("module", ModuleKind::EsModule),
            ("commonjs", ModuleKind::CommonJs),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "package.json",
                &format!(r#"{{"type":"{kind}"}}"#),
            );
            put(root.path(), "app.js", "const x=1;");
            assert_eq!(entry(&registry(root.path(), "app.js")).kind(), expected);
        }
    }

    #[test]
    fn only_exact_entrypoint_and_admitted_entry_style_are_accepted_without_referrer() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.cjs';");
        put(root.path(), "dep.cjs", "module.exports=1;");
        let r = registry(root.path(), "app.mjs");
        assert_eq!(
            r.lookup(None, r.entrypoint(), RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ENTRY"
        );
        let dep = r
            .lookup(Some(r.entrypoint()), "./dep.cjs", RequestStyle::Import)
            .ok()
            .unwrap();
        assert_eq!(
            r.lookup(None, dep.id(), RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ENTRY"
        );
        assert!(r.lookup(None, "app.mjs", RequestStyle::Import).is_err());
    }

    #[test]
    fn canonical_target_and_equivalent_path_spellings_cannot_bypass_a_route() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const x=1;");
        let r = registry(root.path(), "app.mjs");
        let dep = r
            .lookup(Some(r.entrypoint()), "./dep.mjs", RequestStyle::Import)
            .ok()
            .unwrap();
        for request in [dep.id(), "././dep.mjs", "dep.mjs", "./dep.mjs ", "node:fs"] {
            assert_eq!(
                r.lookup(Some(r.entrypoint()), request, RequestStyle::Import)
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_REGISTRY_ROUTE",
                "{request}"
            );
        }
        assert!(
            r.lookup(Some("app.mjs"), "./dep.mjs", RequestStyle::Import)
                .is_err()
        );
        assert!(
            r.lookup(Some(r.entrypoint()), "", RequestStyle::Import)
                .is_err()
        );
    }

    #[test]
    fn import_and_require_routes_keep_their_selected_package_branches() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'pkg'; require('pkg');");
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"exports":{"import":"./i.mjs","require":"./r.cjs"}}"#,
        );
        put(root.path(), "node_modules/pkg/i.mjs", "export const x=1;");
        put(root.path(), "node_modules/pkg/r.cjs", "module.exports=2;");
        let r = registry(root.path(), "app.mjs");
        let i = r
            .lookup(Some(r.entrypoint()), "pkg", RequestStyle::Import)
            .ok()
            .unwrap();
        let c = r
            .lookup(Some(r.entrypoint()), "pkg", RequestStyle::Require)
            .ok()
            .unwrap();
        assert_ne!(i.id(), c.id());
        assert_eq!(i.kind(), ModuleKind::EsModule);
        assert_eq!(c.kind(), ModuleKind::CommonJs);
        assert_eq!(entry(&r).dependencies().len(), 2);
    }

    #[test]
    fn nested_versions_are_selected_by_exact_captured_referrer() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('a'); require('dep');");
        put(
            root.path(),
            "node_modules/a/package.json",
            r#"{"main":"app.cjs"}"#,
        );
        put(root.path(), "node_modules/a/app.cjs", "require('dep');");
        for (path, value) in [
            ("node_modules/dep", "outer"),
            ("node_modules/a/node_modules/dep", "inner"),
        ] {
            put(
                root.path(),
                &format!("{path}/package.json"),
                r#"{"main":"app.cjs"}"#,
            );
            put(
                root.path(),
                &format!("{path}/app.cjs"),
                &format!("module.exports='{value}';"),
            );
        }
        let r = registry(root.path(), "app.cjs");
        let a = r
            .lookup(Some(r.entrypoint()), "a", RequestStyle::Require)
            .ok()
            .unwrap();
        let inner = r
            .lookup(Some(a.id()), "dep", RequestStyle::Require)
            .ok()
            .unwrap();
        let outer = r
            .lookup(Some(r.entrypoint()), "dep", RequestStyle::Require)
            .ok()
            .unwrap();
        assert_ne!(inner.id(), outer.id());
        assert!(inner.source().contains("inner"));
        assert!(outer.source().contains("outer"));
    }

    #[test]
    fn loaded_bytes_never_reopen_mutated_or_unavailable_project_paths() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const secret='original';");
        let r = registry(root.path(), "app.mjs");
        put(root.path(), "dep.mjs", "throw Error('changed');");
        let hidden = root.path().join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::rename(root.path().join("dep.mjs"), hidden.join("dep.mjs")).unwrap();
        let loaded = r
            .lookup(Some(r.entrypoint()), "./dep.mjs", RequestStyle::Import)
            .ok()
            .unwrap();
        assert_eq!(loaded.source(), "export const secret='original';");
        assert!(
            !serde_json::to_string(r.summary())
                .unwrap()
                .contains("original")
        );
    }

    #[test]
    fn replay_produces_identical_registry_without_live_filesystem_authority() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const secret=1;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let live = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
        std::fs::rename(root.path().join("app.mjs"), root.path().join("changed.mjs")).unwrap();
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let restored = PinnedModuleRegistry::new(replay, &pin).ok().unwrap();
        assert_eq!(live.summary(), restored.summary());
        assert_eq!(entry(&live).source(), entry(&restored).source());
    }

    #[test]
    fn graph_scoped_ids_prevent_cross_capture_referrer_reuse() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const x=1;");
        let before = registry(root.path(), "app.mjs");
        put(root.path(), "dep.mjs", "export const x=2;");
        let after = registry(root.path(), "app.mjs");
        assert_ne!(before.entrypoint(), after.entrypoint());
        assert_eq!(
            after
                .lookup(Some(before.entrypoint()), "./dep.mjs", RequestStyle::Import)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_REFERRER"
        );
    }

    #[test]
    fn url_instances_remain_distinct_while_identical_source_storage_is_shared() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './dep.mjs?one'; import './dep.mjs?two';",
        );
        put(root.path(), "dep.mjs", "export const x=1;");
        let r = registry(root.path(), "app.mjs");
        let one = r
            .lookup(Some(r.entrypoint()), "./dep.mjs?one", RequestStyle::Import)
            .ok()
            .unwrap();
        let two = r
            .lookup(Some(r.entrypoint()), "./dep.mjs?two", RequestStyle::Import)
            .ok()
            .unwrap();
        assert_ne!(one.id(), two.id());
        assert!(Arc::ptr_eq(&one.source, &two.source));
        assert_ne!(one.origin().url_suffix, two.origin().url_suffix);
    }

    #[test]
    fn cyclic_and_diamond_edges_are_retained_for_per_edge_authorization() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './a.mjs'; import './b.mjs';",
        );
        put(root.path(), "a.mjs", "import './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';");
        let r = registry(root.path(), "app.mjs");
        let requests = r
            .reachable_requests(None, r.entrypoint(), RequestStyle::Import)
            .unwrap();
        assert_eq!(r.summary().modules, 4);
        assert_eq!(requests.len(), 6);
        assert_eq!(
            requests
                .iter()
                .filter(|(_, s, _)| s == "./shared.mjs")
                .count(),
            2
        );
    }

    #[test]
    fn duplicate_load_sites_do_not_expand_identical_routes() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "require('./d.cjs'); require('./d.cjs');",
        );
        put(root.path(), "d.cjs", "module.exports=1;");
        let r = registry(root.path(), "app.cjs");
        assert_eq!(r.summary().routes, 1);
        assert_eq!(entry(&r).dependencies().len(), 1);
        assert!(
            r.lookup(Some(r.entrypoint()), "./d.cjs", RequestStyle::Import)
                .is_err()
        );
    }

    #[test]
    fn registry_is_send_sync_and_has_no_live_directory_or_rc_dependencies() {
        fn check<T: Send + Sync>() {}
        check::<PinnedModuleRegistry>();
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "module.exports=1;");
        let r = registry(root.path(), "app.cjs");
        assert_eq!(
            std::thread::spawn(move || entry(&r).source().to_owned())
                .join()
                .unwrap(),
            "module.exports=1;"
        );
    }

    #[test]
    fn borrowed_walk_preserves_breadth_first_order_and_resolved_targets() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './a.mjs'; import './b.mjs';",
        );
        put(root.path(), "a.mjs", "import './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';");
        let r = registry(root.path(), "app.mjs");
        let mut walk = r
            .walk_requests(None, r.entrypoint(), r.entry_style())
            .unwrap();
        let mut order = Vec::new();
        for request in walk.by_ref() {
            let request = request.unwrap();
            let looked_up = r
                .lookup(request.referrer, request.specifier, request.style)
                .unwrap();
            assert!(std::ptr::eq(looked_up, request.module));
            order.push((
                request.referrer.map(str::to_owned),
                request.specifier.to_owned(),
                request.style,
            ));
        }
        assert_eq!(
            order,
            r.reachable_requests(None, r.entrypoint(), r.entry_style())
                .unwrap()
        );
        assert_eq!(
            order
                .iter()
                .map(|(_, specifier, _)| specifier.as_str())
                .collect::<Vec<_>>(),
            vec![
                r.entrypoint(),
                "./a.mjs",
                "./b.mjs",
                "./shared.mjs",
                "./shared.mjs",
                "./app.mjs"
            ]
        );
        assert!(walk.next().is_none());
        assert!(walk.next().is_none());
    }

    #[test]
    fn high_fan_in_walk_queues_modules_not_all_incoming_edges() {
        let root = tempfile::tempdir().unwrap();
        let width = 24;
        let leaves = (0..width)
            .map(|i| format!("import './leaf{i}.mjs';"))
            .collect::<String>();
        let roots = (0..width)
            .map(|i| format!("import './parent{i}.mjs';"))
            .collect::<String>();
        put(root.path(), "app.mjs", &roots);
        for i in 0..width {
            put(root.path(), &format!("parent{i}.mjs"), &leaves);
            put(root.path(), &format!("leaf{i}.mjs"), "export const value=1;");
        }
        let r = registry(root.path(), "app.mjs");
        assert_eq!(r.summary().routes, width + width * width);
        assert_eq!(r.modules().len(), 1 + 2 * width);
        let mut walk = r
            .walk_requests(None, r.entrypoint(), r.entry_style())
            .unwrap();
        let mut count = 0;
        while let Some(request) = walk.next() {
            request.unwrap();
            count += 1;
            assert!(walk.pending.len() <= r.summary().modules);
            assert!(walk.scheduled.len() <= r.summary().modules);
        }
        assert_eq!(count, 1 + width + width * width);
    }

    #[test]
    fn borrowed_walk_validates_the_start_and_can_stop_before_expansion() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const value=1;");
        let r = registry(root.path(), "app.mjs");
        assert_eq!(
            r.walk_requests(Some("outside"), "./dep.mjs", RequestStyle::Import)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_REFERRER"
        );
        assert_eq!(
            r.walk_requests(None, r.entrypoint(), RequestStyle::Require)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ENTRY"
        );
        let mut walk = r
            .walk_requests(None, r.entrypoint(), r.entry_style())
            .unwrap();
        assert_eq!(walk.next().unwrap().unwrap().module.id(), r.entrypoint());
        assert_eq!(walk.scheduled.len(), 1);
        assert!(walk.current.is_none());
    }

    #[test]
    fn inconsistent_traversal_fails_once_instead_of_truncating_successfully() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const value=1;");
        let mut r = registry(root.path(), "app.mjs");
        let entry_id = r.entrypoint().to_owned();
        r.modules.get_mut(&entry_id).unwrap().dependencies[0].target =
            RegisteredTarget::Module { id: "missing".into() };
        let mut walk = r
            .walk_requests(None, r.entrypoint(), r.entry_style())
            .unwrap();
        assert!(walk.next().unwrap().is_ok());
        assert_eq!(
            walk.next().unwrap().err().unwrap().code,
            "ERR_MODULE_REGISTRY_GRAPH"
        );
        assert!(walk.next().is_none());
        assert!(walk.next().is_none());
    }

    #[test]
    fn engine_preparation_cannot_run_before_pin_and_closed_graph_admission() {
        use std::cell::Cell;
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mts", "import './missing.mjs';");
        let calls = Cell::new(0);
        for mismatch in [true, false] {
            let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
            let pin = if mismatch {
                format!("sha256:{}", "0".repeat(64))
            } else {
                graph.report().input_hash.clone()
            };
            let result = PinnedModuleRegistry::new_with_kind_resolver(graph, &pin, |_, _, _| {
                calls.set(calls.get() + 1);
                Ok(ModuleKind::EsModule)
            }, |_| None);
            assert_eq!(
                result.err().unwrap().code,
                if mismatch {
                    "ERR_MODULE_REGISTRY_PIN_MISMATCH"
                } else {
                    "ERR_MODULE_REGISTRY_INCOMPLETE"
                }
            );
        }
        assert_eq!(calls.get(), 0);
    }
}
