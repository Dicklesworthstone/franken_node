//! Pinned, closed-world source delivery for an engine module resolver.
//!
//! Admission consumes a captured (or replayed) graph and an independent graph
//! pin. Lookup thereafter has no filesystem, parser, environment or network
//! dependency. A module may request only the exact importer/style/specifier
//! routes captured for it. This is source delivery, not capability admission:
//! engine consumers must authorize every lookup through ModulePolicyHook.

use super::{CapturedModuleGraph, EdgeState, LoadKind, ModuleId, ResolutionError,
    SourceLanguage, error};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Result<T> = std::result::Result<T, ResolutionError>;
const ID_DOMAIN: &[u8] = b"franken-node/sealed-module-id/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStyle { Import, Require }

impl RequestStyle {
    fn for_load(kind: LoadKind) -> Self {
        if kind == LoadKind::Require { Self::Require } else { Self::Import }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind { EsModule, CommonJs }

impl ModuleKind {
    pub fn entry_style(self) -> RequestStyle {
        match self { Self::EsModule => RequestStyle::Import, Self::CommonJs => RequestStyle::Require }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisteredDependency {
    pub specifier: String,
    pub style: RequestStyle,
    pub target: String,
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
    pub fn id(&self) -> &str { &self.id }
    pub fn origin(&self) -> &ModuleId { &self.origin }
    pub fn kind(&self) -> ModuleKind { self.kind }
    pub fn source(&self) -> &str { &self.source }
    pub fn source_sha256(&self) -> &str { &self.source_sha256 }
    pub fn dependencies(&self) -> &[RegisteredDependency] { &self.dependencies }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrySummary {
    pub schema_version: &'static str,
    pub graph_input_hash: String,
    pub entrypoint: String,
    pub modules: usize,
    pub routes: usize,
    pub execution_performed: bool,
    pub policy_admission_performed: bool,
}

/// Thread-transferable immutable data, NOT an authorization decision or an
/// evaluation cache. Engine policy must be checked again even on a cache hit.
/// Canonical IDs are opaque and graph-scoped, never host paths to reopen.
pub struct PinnedModuleRegistry {
    summary: RegistrySummary,
    modules: BTreeMap<String, RegisteredModule>,
    routes: BTreeMap<(String, RequestStyle, String), String>,
}

impl PinnedModuleRegistry {
    pub fn new(graph: CapturedModuleGraph, independent_graph_pin: &str) -> Result<Self> {
        let digest = independent_graph_pin.strip_prefix("sha256:").unwrap_or("");
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(error("ERR_MODULE_REGISTRY_PIN", "an independent canonical source-graph pin is required"));
        }
        if independent_graph_pin != graph.report().input_hash {
            return Err(error("ERR_MODULE_REGISTRY_PIN_MISMATCH", "captured graph differs from reviewed source graph"));
        }
        let report = graph.report();
        if !report.fully_resolved || !report.diagnostics.is_empty()
            || report.modules.iter().any(|m| !m.analyzed)
            || report.edges.iter().any(|e| !matches!(e.state, EdgeState::Resolved | EdgeState::TypeOnly)) {
            return Err(error("ERR_MODULE_REGISTRY_INCOMPLETE", "source delivery requires a closed, analyzed graph"));
        }
        let identities: BTreeMap<_, _> = report.modules.iter().map(|m|
            (m.id.clone(), canonical_id(&report.input_hash, &m.id))).collect();
        let mut modules = BTreeMap::new();
        let mut shared_sources = BTreeMap::<String, Arc<str>>::new();
        for module in &report.modules {
            // Do not invent a TS/JSX transform, JSON-to-JS conversion, addon
            // loader, or syntax-detection result at the engine boundary.
            let kind = match (module.source_language, module.format_hint.as_str()) {
                (SourceLanguage::JavaScript, "module") => ModuleKind::EsModule,
                (SourceLanguage::JavaScript, "commonjs") => ModuleKind::CommonJs,
                _ => return Err(error("ERR_MODULE_REGISTRY_FORMAT",
                    format!("module {:?} needs engine format detection or transformation", module.id.path))),
            };
            let bytes = graph.source_bytes(&module.id).ok_or_else(invalid_graph)?;
            let text = std::str::from_utf8(bytes).map_err(|_| invalid_graph())?;
            let source = if let Some(existing) = shared_sources.get(&module.id.path) {
                if existing.as_ref() != text { return Err(invalid_graph()); }
                Arc::clone(existing)
            } else {
                let source: Arc<str> = Arc::from(text);
                shared_sources.insert(module.id.path.clone(), Arc::clone(&source));
                source
            };
            let id = identities.get(&module.id).ok_or_else(invalid_graph)?.clone();
            if modules.insert(id.clone(), RegisteredModule { id, origin: module.id.clone(),
                kind, source, source_sha256: module.content_sha256.clone(), dependencies: Vec::new() }).is_some() {
                return Err(invalid_graph());
            }
        }
        let mut routes = BTreeMap::new();
        for edge in &report.edges {
            if edge.state == EdgeState::TypeOnly { continue; }
            let importer = identities.get(&edge.importer).ok_or_else(invalid_graph)?;
            let target = identities.get(edge.target.as_ref().ok_or_else(invalid_graph)?).ok_or_else(invalid_graph)?;
            let specifier = edge.specifier.as_ref().ok_or_else(invalid_graph)?;
            let style = RequestStyle::for_load(edge.kind);
            let key = (importer.clone(), style, specifier.clone());
            if let Some(previous) = routes.get(&key) {
                if previous != target { return Err(invalid_graph()); }
                continue;
            }
            routes.insert(key, target.clone());
            modules.get_mut(importer).ok_or_else(invalid_graph)?.dependencies.push(RegisteredDependency {
                specifier: specifier.clone(), style, target: target.clone(),
            });
        }
        let entrypoint = identities.get(&report.resolved_entrypoint).ok_or_else(invalid_graph)?.clone();
        let summary = RegistrySummary {
            schema_version: "franken-node/sealed-module-registry/v1",
            graph_input_hash: report.input_hash.clone(), entrypoint,
            modules: modules.len(), routes: routes.len(),
            execution_performed: false, policy_admission_performed: false,
        };
        Ok(Self { summary, modules, routes })
    }

    pub fn summary(&self) -> &RegistrySummary { &self.summary }
    pub fn entrypoint(&self) -> &str { &self.summary.entrypoint }
    pub fn entry_style(&self) -> RequestStyle {
        self.modules[&self.summary.entrypoint].kind.entry_style()
    }

    /// Data lookup only. This never confers an execution/capability permit.
    /// With no referrer, only the exact entrypoint ID and its admitted style
    /// are accepted. With a referrer, even a known target's canonical ID cannot
    /// bypass the recorded importer/style/specifier route.
    pub fn lookup(&self, referrer: Option<&str>, specifier: &str, style: RequestStyle) -> Result<&RegisteredModule> {
        if specifier.is_empty() || specifier.len() > 4096 || specifier.chars().any(char::is_control) {
            return Err(error("ERR_MODULE_REGISTRY_REQUEST", "invalid module request"));
        }
        let id = match referrer {
            None if specifier == self.entrypoint() && style == self.entry_style() => self.entrypoint(),
            None => return Err(error("ERR_MODULE_REGISTRY_ENTRY", "only the sealed entrypoint may be requested without a referrer")),
            Some(importer) => {
                if !self.modules.contains_key(importer) {
                    return Err(error("ERR_MODULE_REGISTRY_REFERRER", "referrer does not belong to this sealed graph"));
                }
                self.routes.get(&(importer.to_owned(), style, specifier.to_owned())).map(String::as_str)
                    .ok_or_else(|| error("ERR_MODULE_REGISTRY_ROUTE", "module request was not captured for this importer and load style"))?
            }
        };
        self.modules.get(id).ok_or_else(invalid_graph)
    }

    /// Deterministic breadth-first requests, not evaluation order. Each route
    /// is included once, even when the target was already reached by another
    /// importer. An engine adapter must authorize those edges BEFORE deduping
    /// its returned module list, so diamond/cycle edges cannot bypass policy.
    pub fn reachable_requests(&self, referrer: Option<&str>, specifier: &str, style: RequestStyle)
        -> Result<Vec<(Option<String>, String, RequestStyle)>> {
        let mut pending = std::collections::VecDeque::from([(referrer.map(str::to_owned), specifier.to_owned(), style)]);
        let mut expanded = BTreeSet::new();
        let mut requests = Vec::new();
        while let Some((referrer, specifier, style)) = pending.pop_front() {
            let module = self.lookup(referrer.as_deref(), &specifier, style)?;
            requests.push((referrer, specifier, style));
            if expanded.insert(module.id()) {
                for dependency in &module.dependencies {
                    pending.push_back((Some(module.id.clone()), dependency.specifier.clone(), dependency.style));
                }
            }
        }
        Ok(requests)
    }
}

fn invalid_graph() -> ResolutionError {
    error("ERR_MODULE_REGISTRY_GRAPH", "captured source graph has inconsistent module identities or routes")
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
    use super::*;
    use super::super::{GraphOptions, capture, capsule};
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
        registry.lookup(None, registry.entrypoint(), registry.entry_style()).ok().unwrap()
    }

    #[test]
    fn independent_pin_is_required_and_mismatch_precedes_graph_admission() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'missing';");
        for pin in ["", "sha256:x", &format!("sha256:{}", "A".repeat(64))] {
            let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
            assert_eq!(PinnedModuleRegistry::new(graph, pin).err().unwrap().code, "ERR_MODULE_REGISTRY_PIN");
        }
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert_eq!(PinnedModuleRegistry::new(graph, &format!("sha256:{}", "0".repeat(64))).err().unwrap().code,
            "ERR_MODULE_REGISTRY_PIN_MISMATCH");
    }

    #[test]
    fn incomplete_and_runtime_required_graphs_are_not_source_load_authority() {
        for source in ["import 'missing';", "import 'node:fs';", "require(variable);", "const x = ;"] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code, "ERR_MODULE_REGISTRY_INCOMPLETE");
        }
    }

    #[test]
    fn formats_requiring_detection_or_transforms_are_not_guessed() {
        for (name, source) in [("app.js", "const x=1;"), ("app.ts", "const x: number=1;"),
            ("app.mts", "export const x: number=1;"), ("app.json", "{}")]
        {
            let root = tempfile::tempdir().unwrap(); put(root.path(), name, source);
            let graph = capture(root.path(), name, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code, "ERR_MODULE_REGISTRY_FORMAT", "{name}");
        }
    }

    #[test]
    fn explicit_package_type_supplies_the_javascript_module_kind() {
        for (kind, expected) in [("module", ModuleKind::EsModule), ("commonjs", ModuleKind::CommonJs)] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "package.json", &format!(r#"{{"type":"{kind}"}}"#));
            put(root.path(), "app.js", "const x=1;");
            assert_eq!(entry(&registry(root.path(), "app.js")).kind(), expected);
        }
    }

    #[test]
    fn only_exact_entrypoint_and_admitted_entry_style_are_accepted_without_referrer() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.cjs';"); put(root.path(), "dep.cjs", "module.exports=1;");
        let r = registry(root.path(), "app.mjs");
        assert_eq!(r.lookup(None, r.entrypoint(), RequestStyle::Require).err().unwrap().code, "ERR_MODULE_REGISTRY_ENTRY");
        let dep = r.lookup(Some(r.entrypoint()), "./dep.cjs", RequestStyle::Import).ok().unwrap();
        assert_eq!(r.lookup(None, dep.id(), RequestStyle::Require).err().unwrap().code, "ERR_MODULE_REGISTRY_ENTRY");
        assert!(r.lookup(None, "app.mjs", RequestStyle::Import).is_err());
    }

    #[test]
    fn canonical_target_and_equivalent_path_spellings_cannot_bypass_a_route() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';"); put(root.path(), "dep.mjs", "export const x=1;");
        let r = registry(root.path(), "app.mjs");
        let dep = r.lookup(Some(r.entrypoint()), "./dep.mjs", RequestStyle::Import).ok().unwrap();
        for request in [dep.id(), "././dep.mjs", "dep.mjs", "./dep.mjs ", "node:fs"] {
            assert_eq!(r.lookup(Some(r.entrypoint()), request, RequestStyle::Import).err().unwrap().code,
                "ERR_MODULE_REGISTRY_ROUTE", "{request}");
        }
        assert!(r.lookup(Some("app.mjs"), "./dep.mjs", RequestStyle::Import).is_err());
        assert!(r.lookup(Some(r.entrypoint()), "", RequestStyle::Import).is_err());
    }

    #[test]
    fn import_and_require_routes_keep_their_selected_package_branches() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'pkg'; require('pkg');");
        put(root.path(), "node_modules/pkg/package.json", r#"{"exports":{"import":"./i.mjs","require":"./r.cjs"}}"#);
        put(root.path(), "node_modules/pkg/i.mjs", "export const x=1;");
        put(root.path(), "node_modules/pkg/r.cjs", "module.exports=2;");
        let r = registry(root.path(), "app.mjs");
        let i = r.lookup(Some(r.entrypoint()), "pkg", RequestStyle::Import).ok().unwrap();
        let c = r.lookup(Some(r.entrypoint()), "pkg", RequestStyle::Require).ok().unwrap();
        assert_ne!(i.id(), c.id()); assert_eq!(i.kind(), ModuleKind::EsModule); assert_eq!(c.kind(), ModuleKind::CommonJs);
        assert_eq!(entry(&r).dependencies().len(), 2);
    }

    #[test]
    fn nested_versions_are_selected_by_exact_captured_referrer() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('a'); require('dep');");
        put(root.path(), "node_modules/a/package.json", r#"{"main":"app.cjs"}"#);
        put(root.path(), "node_modules/a/app.cjs", "require('dep');");
        for (path, value) in [("node_modules/dep", "outer"), ("node_modules/a/node_modules/dep", "inner")] {
            put(root.path(), &format!("{path}/package.json"), r#"{"main":"app.cjs"}"#);
            put(root.path(), &format!("{path}/app.cjs"), &format!("module.exports='{value}';"));
        }
        let r = registry(root.path(), "app.cjs");
        let a = r.lookup(Some(r.entrypoint()), "a", RequestStyle::Require).ok().unwrap();
        let inner = r.lookup(Some(a.id()), "dep", RequestStyle::Require).ok().unwrap();
        let outer = r.lookup(Some(r.entrypoint()), "dep", RequestStyle::Require).ok().unwrap();
        assert_ne!(inner.id(), outer.id()); assert!(inner.source().contains("inner")); assert!(outer.source().contains("outer"));
    }

    #[test]
    fn loaded_bytes_never_reopen_mutated_or_unavailable_project_paths() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';"); put(root.path(), "dep.mjs", "export const secret='original';");
        let r = registry(root.path(), "app.mjs");
        put(root.path(), "dep.mjs", "throw Error('changed');");
        let hidden = root.path().join("hidden"); std::fs::create_dir(&hidden).unwrap();
        std::fs::rename(root.path().join("dep.mjs"), hidden.join("dep.mjs")).unwrap();
        let loaded = r.lookup(Some(r.entrypoint()), "./dep.mjs", RequestStyle::Import).ok().unwrap();
        assert_eq!(loaded.source(), "export const secret='original';");
        assert!(!serde_json::to_string(r.summary()).unwrap().contains("original"));
    }

    #[test]
    fn replay_produces_identical_registry_without_live_filesystem_authority() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const secret=1;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone(); let encoded = capsule::encode(&graph).unwrap();
        let live = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
        std::fs::rename(root.path().join("app.mjs"), root.path().join("changed.mjs")).unwrap();
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let restored = PinnedModuleRegistry::new(replay, &pin).ok().unwrap();
        assert_eq!(live.summary(), restored.summary()); assert_eq!(entry(&live).source(), entry(&restored).source());
    }

    #[test]
    fn graph_scoped_ids_prevent_cross_capture_referrer_reuse() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';"); put(root.path(), "dep.mjs", "export const x=1;");
        let before = registry(root.path(), "app.mjs");
        put(root.path(), "dep.mjs", "export const x=2;"); let after = registry(root.path(), "app.mjs");
        assert_ne!(before.entrypoint(), after.entrypoint());
        assert_eq!(after.lookup(Some(before.entrypoint()), "./dep.mjs", RequestStyle::Import).err().unwrap().code,
            "ERR_MODULE_REGISTRY_REFERRER");
    }

    #[test]
    fn url_instances_remain_distinct_while_identical_source_storage_is_shared() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs?one'; import './dep.mjs?two';");
        put(root.path(), "dep.mjs", "export const x=1;"); let r = registry(root.path(), "app.mjs");
        let one = r.lookup(Some(r.entrypoint()), "./dep.mjs?one", RequestStyle::Import).ok().unwrap();
        let two = r.lookup(Some(r.entrypoint()), "./dep.mjs?two", RequestStyle::Import).ok().unwrap();
        assert_ne!(one.id(), two.id()); assert!(Arc::ptr_eq(&one.source, &two.source));
        assert_ne!(one.origin().url_suffix, two.origin().url_suffix);
    }

    #[test]
    fn cyclic_and_diamond_edges_are_retained_for_per_edge_authorization() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './a.mjs'; import './b.mjs';");
        put(root.path(), "a.mjs", "import './shared.mjs';"); put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';"); let r = registry(root.path(), "app.mjs");
        let requests = r.reachable_requests(None, r.entrypoint(), RequestStyle::Import).unwrap();
        assert_eq!(r.summary().modules, 4); assert_eq!(requests.len(), 6);
        assert_eq!(requests.iter().filter(|(_, s, _)| s == "./shared.mjs").count(), 2);
    }

    #[test]
    fn duplicate_load_sites_do_not_expand_identical_routes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('./d.cjs'); require('./d.cjs');");
        put(root.path(), "d.cjs", "module.exports=1;"); let r = registry(root.path(), "app.cjs");
        assert_eq!(r.summary().routes, 1); assert_eq!(entry(&r).dependencies().len(), 1);
        assert!(r.lookup(Some(r.entrypoint()), "./d.cjs", RequestStyle::Import).is_err());
    }

    #[test]
    fn registry_is_send_sync_and_has_no_live_directory_or_rc_dependencies() {
        fn check<T: Send + Sync>() {} check::<PinnedModuleRegistry>();
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.cjs", "module.exports=1;");
        let r = registry(root.path(), "app.cjs");
        assert_eq!(std::thread::spawn(move || entry(&r).source().to_owned()).join().unwrap(), "module.exports=1;");
    }
}
