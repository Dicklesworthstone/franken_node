//! FrankenEngine ModuleResolver implementation over a pinned source registry.
//!
//! This implements the real sibling engine trait, not a lookalike interface.
//! Source selection is closed-world; the supplied engine policy runs on every
//! delivered candidate, including cache hits and traversed cycle back-edges.
//! Exact captured requests for engine-supported native builtin objects become
//! source-free terminal descriptors. No builtin fallback, live I/O or evaluation
//! happens here. Source preparation uses the sibling engine front end.

#[path = "module_engine_preparation.rs"]
mod preparation;
pub use preparation::ModulePreparationSummary;
pub use preparation::detect_kind_with_options;
use preparation::{PreparedSources, SourcePreparer};

use super::registry::{
    ModuleKind, PinnedModuleRegistry, RegisteredModule, RegistrySummary, RequestStyle,
};
use super::{CapturedModuleGraph, ResolutionError as CaptureError};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{
    ExecutionModuleResolver, ImportStyle, ModuleDependency, ModulePolicyHook, ModuleProvenance,
    ModuleRecord, ModuleRequest, ModuleResolver, ModuleSourceKind, ModuleSourceLocation, ModuleSyntax,
    NativeBuiltinModule, ResolutionContext, ResolutionError, ResolutionErrorCode, ResolutionEvent,
    ResolutionOutcome, ResolutionResult, ResolvedModule,
};
use frankenengine_engine::parser::ParserOptions;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, OnceLock};

const MAX_CHAIN_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 1024;

/// An embedding resolver, not an evaluator or a policy grant. It can be passed
/// directly as &dyn FrankenEngine ModuleResolver. Syntax detection and source
/// normalization use the engine; linking and evaluation remain engine work.
pub struct CapturedEngineResolver {
    registry: PinnedModuleRegistry,
    chain_source_budget: usize,
    // One small cell per admitted module, not an unbounded request-key cache.
    // Cache content identity only. Authorization and request/event context are
    // always fresh. No duplicate source strings are retained by this cache.
    content_hashes: BTreeMap<String, OnceLock<ContentHash>>,
    prepared_sources: PreparedSources,
    #[cfg(test)]
    hash_computations: std::sync::atomic::AtomicUsize,
}

impl CapturedEngineResolver {
    pub fn new(
        graph: CapturedModuleGraph,
        independent_graph_pin: &str,
    ) -> Result<Self, CaptureError> {
        Self::new_with_parser_options(graph, independent_graph_pin, ParserOptions::default())
    }

    /// Preserve the caller's parser limits during captured source preparation.
    /// Neither these options nor preparation change the graph's load authority.
    pub fn new_with_parser_options(
        graph: CapturedModuleGraph,
        independent_graph_pin: &str,
        parser_options: ParserOptions,
    ) -> Result<Self, CaptureError> {
        let mut preparer = SourcePreparer::with_parser_options(parser_options);
        let registry = PinnedModuleRegistry::new_with_kind_resolver(
            graph,
            independent_graph_pin,
            |module, source, report| preparer.prepare(module, source, report),
            |specifier, _| NativeBuiltinModule::from_specifier(specifier)
                .map(NativeBuiltinModule::canonical_specifier),
        )?;
        let mut resolver = Self::from_registry(registry);
        resolver.prepared_sources = preparer.finish();
        Ok(resolver)
    }

    pub fn from_registry(registry: PinnedModuleRegistry) -> Self {
        let content_hashes = registry
            .modules()
            .map(|module| (module.id().to_owned(), OnceLock::new()))
            .collect();
        Self {
            registry,
            chain_source_budget: MAX_CHAIN_SOURCE_BYTES,
            content_hashes,
            prepared_sources: PreparedSources::default(),
            #[cfg(test)]
            hash_computations: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn summary(&self) -> &RegistrySummary {
        self.registry.summary()
    }

    /// Source-free evidence for files needing engine preparation. Explicit
    /// JavaScript on the unchanged fast path has no preparation report.
    pub fn preparation_reports(&self) -> impl Iterator<Item = &ModulePreparationSummary> {
        self.prepared_sources.summaries()
    }

    pub fn entry_request(&self) -> ModuleRequest {
        ModuleRequest::new(
            self.registry.entrypoint(),
            engine_style(self.registry.entry_style()),
        )
        .with_compatibility_mode(CompatibilityMode::NodeCompat)
    }

    /// Install this immutable registry for native runtime loads. The absolute
    /// root supplies guest-visible origins; constructing metadata opens no files.
    /// Authorization remains a per-request decision, including cache hits.
    pub fn execution_resolver(
        self: &Arc<Self>,
        project_root: &Path,
        policy: Arc<dyn ModulePolicyHook + Send + Sync>,
    ) -> Result<ExecutionModuleResolver, CaptureError> {
        if !project_root.is_absolute() {
            return Err(super::error(
                "ERR_MODULE_ENGINE_SOURCE_LOCATION",
                "native module origins require an absolute project root",
            ));
        }
        let mut locations = BTreeMap::new();
        for module in self.registry.modules() {
            if module.kind() == ModuleKind::NativeBuiltin {
                continue;
            }
            let filename = project_root.join(&module.origin().path);
            let mut url = url::Url::from_file_path(&filename)
                .map_err(|_| {
                    super::error(
                        "ERR_MODULE_ENGINE_SOURCE_LOCATION",
                        "captured module origin cannot be represented as a file URL",
                    )
                })?
                .to_string();
            url.push_str(&module.origin().url_suffix);
            locations.insert(module.id().to_owned(), ModuleSourceLocation { filename, url });
        }
        Ok(ExecutionModuleResolver::new(
            self.registry.entrypoint(),
            Arc::clone(self) as Arc<dyn ModuleResolver + Send + Sync>,
            policy,
        )
        .with_source_locations(locations))
    }

    fn validate_request(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        if request.compatibility_mode != CompatibilityMode::NodeCompat {
            return Err(denied(
                ResolutionErrorCode::UnsupportedSpecifier,
                "captured node-resolution choices cannot be relabelled as native or Bun resolution",
                request,
                context,
                None,
            ));
        }
        if [&context.trace_id, &context.decision_id, &context.policy_id]
            .iter()
            .any(|value| {
                value.is_empty()
                    || value.len() > MAX_CONTEXT_BYTES
                    || value.chars().any(char::is_control)
            })
        {
            return Err(denied(
                ResolutionErrorCode::PolicyDenied,
                "bounded nonempty trace, decision and policy identities are required",
                request,
                context,
                None,
            ));
        }
        Ok(())
    }

    fn lookup<'a>(
        &'a self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<&'a RegisteredModule> {
        self.registry
            .lookup(
                request.referrer.as_deref(),
                &request.specifier,
                source_style(request.style),
            )
            .map_err(|error| registry_error(error, request, context))
    }

    fn record(&self, module: &RegisteredModule) -> ModuleRecord {
        let syntax = match module.kind() {
            ModuleKind::EsModule => ModuleSyntax::EsModule,
            ModuleKind::CommonJs => ModuleSyntax::CommonJs,
            ModuleKind::NativeBuiltin => {
                return NativeBuiltinModule::from_specifier(&module.origin().path)
                    .expect("native terminal was admitted by the engine provider inventory")
                    .record(module.id());
            }
        };
        ModuleRecord {
            id: module.id().to_owned(),
            syntax,
            // The policy receives this candidate record, as required by the
            // engine contract. It is not returned to a caller before approval.
            source: self.prepared_sources.source(module).to_owned(),
            dependencies: module
                .dependencies()
                .iter()
                .map(|d| ModuleDependency::new(&d.specifier, engine_style(d.style)))
                .collect(),
            required_capabilities: BTreeSet::from([RuntimeCapability::ModuleLoad]),
            provenance: ModuleProvenance {
                // Captured installed code is NOT claimed to be authenticated
                // registry content. Workspace means captured project material.
                kind: ModuleSourceKind::Workspace,
                origin: format!(
                    "franken-node-source-graph:{}",
                    self.registry.summary().graph_input_hash
                ),
            },
        }
    }

    fn authorize(
        &self,
        request: &ModuleRequest,
        record: &ModuleRecord,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<()> {
        policy.authorize(request, record, context).map_err(|error| {
            denied(
                // A policy refusal never means a captured file was absent.
                // Hooks may use any resolver error code; normalize the origin
                // here so a misleading ModuleNotFound cannot become a guest
                // catch and optional-dependency fallback in the interpreter.
                ResolutionErrorCode::PolicyDenied,
                &format!("{}: {}", error.code.stable_code(), error.message),
                request,
                context,
                Some(&record.id),
            )
        })
    }

    fn outcome(
        &self,
        request: &ModuleRequest,
        record: ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionOutcome {
        // Every record reaching this private method was constructed from the
        // sealed registry. Its complete canonical form is immutable for this
        // resolver's lifetime; caller-owned returned copies never enter here.
        // Compute only after authorization, outside the policy callback, so
        // denial does not populate the cache and reentrant policies cannot
        // deadlock on an initializing cell. Use the actual engine hash API.
        let compute = || {
            #[cfg(test)]
            self.hash_computations
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            record.canonical_hash()
        };
        let content_hash = match self.content_hashes.get(&record.id) {
            Some(slot) => *slot.get_or_init(compute),
            None => compute(),
        };
        ResolutionOutcome {
            module: ResolvedModule {
                request_specifier: request.specifier.clone(),
                canonical_specifier: record.id.clone(),
                record,
                content_hash,
                probe_sequence: Vec::new(),
            },
            event: event(context, "allow", ""),
        }
    }
}

impl ModuleResolver for CapturedEngineResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome> {
        self.validate_request(request, context)?;
        let module = self.lookup(request, context)?;
        let record = self.record(module);
        self.authorize(request, &record, context, policy)?;
        Ok(self.outcome(request, record, context))
    }

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>> {
        self.validate_request(entry_request, context)?;
        let requests = self
            .registry
            .walk_requests(
                entry_request.referrer.as_deref(),
                &entry_request.specifier,
                source_style(entry_request.style),
            )
            .map_err(|error| registry_error(error, entry_request, context))?;
        let mut outcomes: Vec<ResolutionOutcome> = Vec::new();
        let mut positions = BTreeMap::<String, usize>::new();
        let mut source_bytes = 0_usize;
        for route in requests {
            let route = route.map_err(|error| registry_error(error, entry_request, context))?;
            let mut request = ModuleRequest::new(route.specifier, engine_style(route.style))
                .with_compatibility_mode(CompatibilityMode::NodeCompat);
            request.referrer = route.referrer.map(str::to_owned);
            let module = route.module;
            if let Some(&position) = positions.get(module.id()) {
                // Cached source is not cached authorization. Checking this edge
                // precedes output deduplication, even for a cycle's back-edge.
                self.authorize(&request, &outcomes[position].module.record, context, policy)?;
                continue;
            }
            source_bytes = source_bytes
                .checked_add(self.prepared_sources.source(module).len())
                .ok_or_else(|| {
                    denied(
                        ResolutionErrorCode::UnsupportedSpecifier,
                        "resolved-chain source budget exceeded",
                        &request,
                        context,
                        Some(module.id()),
                    )
                })?;
            if source_bytes > self.chain_source_budget {
                return Err(denied(
                    ResolutionErrorCode::UnsupportedSpecifier,
                    "resolved-chain source budget exceeded",
                    &request,
                    context,
                    Some(module.id()),
                ));
            }
            let record = self.record(module);
            self.authorize(&request, &record, context, policy)?;
            positions.insert(module.id().to_owned(), outcomes.len());
            outcomes.push(self.outcome(&request, record, context));
        }
        // Any error above drops all prepared outputs. This is traversal order,
        // not an ESM instantiation/evaluation order or a linkage certificate.
        Ok(outcomes)
    }
}

fn source_style(style: ImportStyle) -> RequestStyle {
    match style {
        ImportStyle::Import => RequestStyle::Import,
        ImportStyle::Require => RequestStyle::Require,
    }
}
fn engine_style(style: RequestStyle) -> ImportStyle {
    match style {
        RequestStyle::Import => ImportStyle::Import,
        RequestStyle::Require => ImportStyle::Require,
    }
}

fn bounded(value: &str, max: usize) -> String {
    let mut end = value.len().min(max);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn event(context: &ResolutionContext, outcome: &str, code: &str) -> ResolutionEvent {
    ResolutionEvent {
        trace_id: bounded(&context.trace_id, MAX_CONTEXT_BYTES),
        decision_id: bounded(&context.decision_id, MAX_CONTEXT_BYTES),
        policy_id: bounded(&context.policy_id, MAX_CONTEXT_BYTES),
        component: "captured_module_resolver".into(),
        event: "module_resolution".into(),
        outcome: outcome.into(),
        error_code: code.into(),
    }
}

fn denied(
    code: ResolutionErrorCode,
    message: &str,
    request: &ModuleRequest,
    context: &ResolutionContext,
    canonical: Option<&str>,
) -> Box<ResolutionError> {
    let event = event(context, "deny", code.stable_code());
    Box::new(ResolutionError {
        code,
        message: bounded(message, 4096),
        trace_id: event.trace_id.clone(),
        decision_id: event.decision_id.clone(),
        policy_id: event.policy_id.clone(),
        request_specifier: bounded(&request.specifier, 4096),
        canonical_specifier: canonical.map(str::to_owned),
        source_kind: canonical.map(|_| ModuleSourceKind::Workspace),
        probe_sequence: Vec::new(),
        event,
    })
}

fn registry_error(
    error: CaptureError,
    request: &ModuleRequest,
    context: &ResolutionContext,
) -> Box<ResolutionError> {
    let code = match error.code {
        "ERR_MODULE_REGISTRY_REFERRER" => ResolutionErrorCode::InvalidReferrer,
        // Only admitted, captured lookup failures become guest control flow.
        // Keep package-map failures distinct from absence. The engine retains
        // CommonJS throws versus dynamic-import rejections; unknown routes and
        // runtime policy denials never become optional-dependency fallback.
        "MODULE_NOT_FOUND" | "ERR_MODULE_NOT_FOUND" => ResolutionErrorCode::ModuleNotFound,
        "ERR_PACKAGE_PATH_NOT_EXPORTED" => ResolutionErrorCode::PackagePathNotExported,
        "ERR_PACKAGE_IMPORT_NOT_DEFINED" => ResolutionErrorCode::PackageImportNotDefined,
        "ERR_MODULE_REGISTRY_ROUTE" => ResolutionErrorCode::UnsupportedSpecifier,
        "ERR_MODULE_REGISTRY_REQUEST" if request.specifier.is_empty() => {
            ResolutionErrorCode::EmptySpecifier
        }
        _ => ResolutionErrorCode::UnsupportedSpecifier,
    };
    denied(
        code,
        &format!("{}: {}", error.code, error.detail),
        request,
        context,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::super::{GraphOptions, capsule, capture};
    use super::*;
    use frankenengine_engine::module_resolver::{AllowAllPolicy, CapabilityPolicyHook};
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    fn put(root: &Path, path: &str, source: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    fn resolver(root: &Path) -> CapturedEngineResolver {
        let graph = capture(root, "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        CapturedEngineResolver::new(graph, &pin).ok().unwrap()
    }
    fn context() -> ResolutionContext {
        ResolutionContext::new("trace", "decision", "policy")
    }
    fn granted() -> CapabilityPolicyHook {
        CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]))
    }

    #[test]
    fn native_builtin_terminals_keep_original_pin_and_exact_commonjs_routes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs",
            "require('buffer'); require('node:buffer'); require('./side.cjs');");
        put(root.path(), "side.cjs", "require('events');");
        put(root.path(), "node_modules/buffer/index.js", "throw new Error('shadowed builtin');");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert!(!graph.report().fully_resolved);
        assert!(graph.report().diagnostics.is_empty());
        assert_eq!(graph.report().modules.len(), 2);
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        assert_eq!(resolver.summary().graph_input_hash, pin);
        assert_eq!(resolver.summary().modules, 4);
        let policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin,
        ]));
        let entry = resolver.resolve(&resolver.entry_request(), &context(), &policy).unwrap();
        let request = |name: &str, style| ModuleRequest::new(name, style)
            .with_referrer(entry.module.record.id.clone())
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        let bare = resolver.resolve(&request("buffer", ImportStyle::Require), &context(), &policy).unwrap();
        let prefixed = resolver.resolve(&request("node:buffer", ImportStyle::Require), &context(), &policy).unwrap();
        assert_eq!(bare.module.record, prefixed.module.record);
        assert_eq!(bare.module.content_hash, bare.module.record.canonical_hash());
        assert_eq!(
            NativeBuiltinModule::from_record(&bare.module.record),
            Some(NativeBuiltinModule::Buffer)
        );
        assert!(bare.module.record.source.is_empty());
        assert!(bare.module.record.dependencies.is_empty());
        assert_eq!(
            resolver.resolve(&request("buffer", ImportStyle::Import), &context(), &policy)
                .unwrap_err().code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
        assert_eq!(
            resolver.resolve(&request("events", ImportStyle::Require), &context(), &policy)
                .unwrap_err().code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
        assert_eq!(
            resolver.resolve(&request("buffer", ImportStyle::Require), &context(), &granted())
                .unwrap_err().code,
            ResolutionErrorCode::PolicyDenied
        );
        assert_eq!(resolver.resolve_chain(&resolver.entry_request(), &context(), &policy).unwrap().len(), 4);
    }

    #[test]
    fn native_builtin_hash_cache_does_not_retain_a_policy_grant() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('buffer');");
        let resolver = resolver_entry(root.path(), "app.cjs");
        let policy = ChangingPolicy { allowed: Cell::new(true), calls: Cell::new(0) };
        let entry = resolver.resolve(&resolver.entry_request(), &context(), &policy).unwrap();
        let request = ModuleRequest::new("buffer", ImportStyle::Require)
            .with_referrer(entry.module.record.id)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        let first = resolver.resolve(&request, &context(), &policy).unwrap();
        policy.allowed.set(false);
        assert_eq!(
            resolver.resolve(&request, &context(), &policy).unwrap_err().code,
            ResolutionErrorCode::PolicyDenied
        );
        policy.allowed.set(true);
        assert_eq!(
            first.module.record,
            resolver.resolve(&request, &context(), &policy).unwrap().module.record
        );
        assert_eq!(policy.calls.get(), 4);
    }

    #[test]
    fn path_esm_terminals_keep_distinct_facades_and_per_request_policy() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import 'node:path'; import 'path/posix'; import('node:path/win32');",
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert!(!graph.report().fully_resolved);
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        assert_eq!(resolver.summary().graph_input_hash, pin);
        assert_eq!(resolver.summary().modules, 4);
        let policy = ChangingPolicy {
            allowed: Cell::new(true),
            calls: Cell::new(0),
        };
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &policy)
            .unwrap();
        let request = |specifier: &str, style| {
            ModuleRequest::new(specifier, style)
                .with_referrer(entry.module.record.id.clone())
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        let path_request = request("node:path", ImportStyle::Import);
        let path = resolver
            .resolve(&path_request, &context(), &policy)
            .unwrap();
        policy.allowed.set(false);
        assert_eq!(
            resolver
                .resolve(&path_request, &context(), &policy)
                .unwrap_err()
                .code,
            ResolutionErrorCode::PolicyDenied
        );
        policy.allowed.set(true);
        assert_eq!(
            resolver
                .resolve(&path_request, &context(), &policy)
                .unwrap()
                .module
                .record,
            path.module.record
        );
        for (specifier, native) in [
            ("path/posix", NativeBuiltinModule::PathPosix),
            ("node:path/win32", NativeBuiltinModule::PathWin32),
        ] {
            let delivered = resolver
                .resolve(
                    &request(specifier, ImportStyle::Import),
                    &context(),
                    &policy,
                )
                .unwrap();
            assert_eq!(
                NativeBuiltinModule::from_record(&delivered.module.record),
                Some(native)
            );
            assert_ne!(delivered.module.record.id, path.module.record.id);
            assert!(delivered.module.record.source.is_empty());
        }
        for (specifier, style) in [
            ("node:path", ImportStyle::Require),
            ("path", ImportStyle::Import),
            ("node:path/posix", ImportStyle::Import),
        ] {
            assert_eq!(
                resolver
                    .resolve(&request(specifier, style), &context(), &policy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        assert_eq!(policy.calls.get(), 6);
    }

    #[test]
    fn native_builtin_esm_terminals_preserve_pins_and_exact_import_routes() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            r#"
            import 'buffer';
            export { join } from 'node:path';
            import('node:events');
        "#,
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert!(!graph.report().fully_resolved);
        assert!(graph.report().diagnostics.is_empty());
        assert_eq!(graph.report().modules.len(), 1);
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        assert_eq!(resolver.summary().graph_input_hash, pin);
        assert_eq!(resolver.summary().modules, 4);
        let policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ]));
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &policy)
            .unwrap();
        let request = |name: &str, style| {
            ModuleRequest::new(name, style)
                .with_referrer(entry.module.record.id.clone())
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        for (name, native) in [
            ("buffer", NativeBuiltinModule::Buffer),
            ("node:path", NativeBuiltinModule::Path),
            ("node:events", NativeBuiltinModule::Events),
        ] {
            let delivered = resolver
                .resolve(&request(name, ImportStyle::Import), &context(), &policy)
                .unwrap();
            assert_eq!(
                NativeBuiltinModule::from_record(&delivered.module.record),
                Some(native)
            );
            assert_eq!(
                delivered.module.content_hash,
                delivered.module.record.canonical_hash()
            );
            assert!(delivered.module.record.source.is_empty());
            assert!(delivered.module.record.dependencies.is_empty());
        }
        // A supported provider is not authority to invent another route or
        // load style, even when an alias selects the same cached descriptor.
        for (name, style) in [
            ("buffer", ImportStyle::Require),
            ("node:buffer", ImportStyle::Import),
            ("events", ImportStyle::Import),
        ] {
            assert_eq!(
                resolver
                    .resolve(&request(name, style), &context(), &policy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        assert_eq!(
            resolver
                .resolve(
                    &request("buffer", ImportStyle::Import),
                    &context(),
                    &granted()
                )
                .unwrap_err()
                .code,
            ResolutionErrorCode::PolicyDenied
        );
    }

    #[test]
    fn filesystem_builtin_routes_share_descriptors_without_granting_io() {
        for (file, source, style) in [
            (
                "app.cjs",
                "require('fs'); require('node:fs'); require('fs/promises'); require('node:fs/promises');",
                ImportStyle::Require,
            ),
            (
                "app.mjs",
                "import 'fs'; import 'node:fs'; import 'fs/promises'; import('node:fs/promises');",
                ImportStyle::Import,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), file, source);
            put(
                root.path(),
                "node_modules/fs/index.js",
                "throw new Error('shadowed builtin');",
            );
            let graph = capture(root.path(), file, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let encoded = capsule::encode(&graph).unwrap();
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            let resolver = CapturedEngineResolver::new(replayed, &pin).ok().unwrap();
            assert_eq!(resolver.summary().graph_input_hash, pin);
            assert_eq!(resolver.summary().modules, 3);
            let policy = CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
            ]));
            let entry = resolver
                .resolve(&resolver.entry_request(), &context(), &policy)
                .unwrap();
            for (bare, native) in [
                ("fs", NativeBuiltinModule::Fs),
                ("fs/promises", NativeBuiltinModule::FsPromises),
            ] {
                let request = |specifier: &str| {
                    ModuleRequest::new(specifier, style)
                        .with_referrer(entry.module.record.id.clone())
                        .with_compatibility_mode(CompatibilityMode::NodeCompat)
                };
                let resolved = resolver
                    .resolve(&request(bare), &context(), &policy)
                    .unwrap();
                let alias = resolver
                    .resolve(&request(&format!("node:{bare}")), &context(), &policy)
                    .unwrap();
                assert_eq!(resolved.module.record, alias.module.record);
                assert_eq!(
                    NativeBuiltinModule::from_record(&resolved.module.record),
                    Some(native)
                );
                assert_eq!(
                    resolved.module.content_hash,
                    resolved.module.record.canonical_hash()
                );
                assert_eq!(
                    resolved.module.record.required_capabilities,
                    BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin,])
                );
                assert!(resolved.module.record.source.is_empty());
                assert!(resolved.module.record.dependencies.is_empty());
                assert_eq!(
                    resolver
                        .resolve(&request(bare), &context(), &granted())
                        .unwrap_err()
                        .code,
                    ResolutionErrorCode::PolicyDenied
                );
            }
        }
    }

    #[test]
    fn package_import_alias_delivers_fs_provider_without_granting_io() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r##"{"imports":{"#fs":"fs"}}"##);
        put(root.path(), "app.mjs", "import '#fs';");
        let resolver = resolver(root.path());
        let policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ]));
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &policy)
            .unwrap();
        let request = |specifier: &str| {
            ModuleRequest::new(specifier, ImportStyle::Import)
                .with_referrer(entry.module.record.id.clone())
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        let resolved = resolver
            .resolve(&request("#fs"), &context(), &policy)
            .unwrap();
        assert_eq!(
            NativeBuiltinModule::from_record(&resolved.module.record),
            Some(NativeBuiltinModule::Fs)
        );
        assert_eq!(
            resolved.module.content_hash,
            resolved.module.record.canonical_hash()
        );
        assert_eq!(
            resolved.module.record.required_capabilities,
            BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin])
        );
        assert!(resolved.module.record.source.is_empty());
        assert!(resolved.module.record.dependencies.is_empty());
        assert_eq!(
            resolver
                .resolve(&request("#fs"), &context(), &granted())
                .unwrap_err()
                .code,
            ResolutionErrorCode::PolicyDenied
        );
        assert_eq!(
            resolver
                .resolve(&request("fs"), &context(), &policy)
                .unwrap_err()
                .code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
    }

    #[test]
    fn captured_stream_submodules_preserve_descriptors_routes_and_offline_replay() {
        for (entrypoint, style, source) in [
            (
                "app.cjs",
                ImportStyle::Require,
                "require('stream/consumers'); require('node:stream/consumers'); \
                 require('stream/web'); require('node:stream/web');",
            ),
            (
                "app.mjs",
                ImportStyle::Import,
                "import 'stream/consumers'; import 'node:stream/consumers'; \
                 import 'stream/web'; import 'node:stream/web';",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), entrypoint, source);
            let graph = capture(root.path(), entrypoint, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let encoded = capsule::encode(&graph).unwrap();
            let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            put(
                root.path(),
                entrypoint,
                "throw new Error('live source was reopened');",
            );
            let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            let restored = CapturedEngineResolver::new(replay, &pin).ok().unwrap();
            let policy = CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
            ]));
            let before = live
                .resolve_chain(&live.entry_request(), &context(), &policy)
                .unwrap();
            assert_eq!(
                before,
                restored
                    .resolve_chain(&restored.entry_request(), &context(), &policy)
                    .unwrap()
            );
            assert_eq!(live.summary().modules, 3);
            let entry = live
                .resolve(&live.entry_request(), &context(), &policy)
                .unwrap();
            let request = |specifier: &str, request_style| {
                ModuleRequest::new(specifier, request_style)
                    .with_referrer(entry.module.record.id.clone())
                    .with_compatibility_mode(CompatibilityMode::NodeCompat)
            };
            for (bare, native) in [
                ("stream/consumers", NativeBuiltinModule::StreamConsumers),
                ("stream/web", NativeBuiltinModule::StreamWeb),
            ] {
                let delivered = live
                    .resolve(&request(bare, style), &context(), &policy)
                    .unwrap();
                let alias = live
                    .resolve(
                        &request(&format!("node:{bare}"), style),
                        &context(),
                        &policy,
                    )
                    .unwrap();
                assert_eq!(delivered.module.record, alias.module.record);
                assert_eq!(
                    NativeBuiltinModule::from_record(&delivered.module.record),
                    Some(native)
                );
                assert_eq!(
                    delivered.module.content_hash,
                    delivered.module.record.canonical_hash()
                );
                assert!(delivered.module.record.source.is_empty());
                assert!(delivered.module.record.dependencies.is_empty());
                assert_eq!(
                    delivered.module.record.required_capabilities,
                    BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin])
                );
                assert_eq!(
                    live.resolve(&request(bare, style), &context(), &granted())
                        .unwrap_err()
                        .code,
                    ResolutionErrorCode::PolicyDenied
                );
                let other_style = match style {
                    ImportStyle::Import => ImportStyle::Require,
                    ImportStyle::Require => ImportStyle::Import,
                };
                assert_eq!(
                    live.resolve(&request(bare, other_style), &context(), &policy)
                        .unwrap_err()
                        .code,
                    ResolutionErrorCode::UnsupportedSpecifier
                );
            }
            for uncaptured in ["stream", "node:stream/promises", "fs", "node:fs"] {
                assert_eq!(
                    live.resolve(&request(uncaptured, style), &context(), &policy)
                        .unwrap_err()
                        .code,
                    ResolutionErrorCode::UnsupportedSpecifier
                );
            }
        }
    }

    #[test]
    fn unsupported_builtin_providers_and_indirect_loaders_remain_refused() {
        for (file, source) in [
            ("app.cjs", "require('worker_threads');"),
            ("app.cjs", "require('node:unknown');"),
            ("app.cjs", "let name='buffer'; require(name);"),
            ("app.cjs", "require.resolve('buffer', {paths: ['/tmp']});"),
            ("app.cjs", "require('#builtin');"),
            ("app.mjs", "import 'node:worker_threads';"),
            ("app.mjs", "import('node:unknown');"),
            ("app.mjs", "let name='buffer'; import(name);"),
            ("app.mjs", "let name = 'node:path'; import(name);"),
            ("app.mjs", "import '#path';"),
            ("app.mjs", "import '#http';"),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "package.json", r##"{"imports":{"#builtin":"buffer","#path":"node:path","#http":"http"}}"##);
            put(root.path(), file, source);
            let graph = capture(root.path(), file, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_INCOMPLETE",
                "{source}"
            );
        }
    }

    #[test]
    fn builtin_terminal_admission_never_changes_the_generic_registry_contract() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require('buffer');");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );
    }

    #[test]
    fn native_builtin_routes_and_descriptors_survive_closed_capsule_replay() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "require('buffer'); require('node:crypto'); require('zlib');",
        );
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        put(root.path(), "app.cjs", "require('events');");
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert!(!replayed.report().fully_resolved);
        let restored = CapturedEngineResolver::new(replayed, &pin).ok().unwrap();
        let policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin,
        ]));
        assert_eq!(
            live.resolve_chain(&live.entry_request(), &context(), &policy).unwrap(),
            restored.resolve_chain(&restored.entry_request(), &context(), &policy).unwrap()
        );
    }

    #[test]
    fn create_require_routes_keep_native_factory_conditions_and_frozen_origins() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import { value } from './bridge.mjs?revision=1#captured'; export { value };",
        );
        let bridge_source = "import { createRequire } from 'node:module'; \
            const localRequire = createRequire(import.meta.url); \
            export const value = localRequire('dual'); localRequire.resolve('dual');";
        put(root.path(), "bridge.mjs", bridge_source);
        put(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{"require":"./required.cjs","import":"./imported.mjs"}}"#,
        );
        put(
            root.path(),
            "node_modules/dual/required.cjs",
            "module.exports = 42;",
        );
        put(
            root.path(),
            "node_modules/dual/imported.mjs",
            "export default 'wrong branch';",
        );
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        assert!(graph.report().diagnostics.is_empty());
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        put(root.path(), "bridge.mjs", "throw new Error('live bridge');");
        put(
            root.path(),
            "node_modules/dual/required.cjs",
            "throw new Error('live package');",
        );
        put(
            root.path(),
            "node_modules/dual/package.json",
            r#"{"exports":{}}"#,
        );
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
        let policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ]));
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &policy)
            .unwrap();
        let bridge = resolver
            .resolve(
                &ModuleRequest::new("./bridge.mjs?revision=1#captured", ImportStyle::Import)
                    .with_referrer(entry.module.record.id.clone())
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &policy,
            )
            .unwrap();
        assert_eq!(bridge.module.record.source, bridge_source);
        let request = |specifier: &str, style| {
            ModuleRequest::new(specifier, style)
                .with_referrer(bridge.module.record.id.clone())
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        let factory = resolver
            .resolve(
                &request("node:module", ImportStyle::Import),
                &context(),
                &policy,
            )
            .unwrap();
        assert_eq!(
            NativeBuiltinModule::from_record(&factory.module.record),
            Some(NativeBuiltinModule::Module)
        );
        assert!(factory.module.record.source.is_empty());
        let required = resolver
            .resolve(&request("dual", ImportStyle::Require), &context(), &policy)
            .unwrap();
        assert_eq!(required.module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(required.module.record.source, "module.exports = 42;");
        for (name, style) in [
            ("dual", ImportStyle::Import),
            ("module", ImportStyle::Import),
            ("node:module", ImportStyle::Require),
        ] {
            assert_eq!(
                resolver
                    .resolve(&request(name, style), &context(), &policy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        let installed = resolver
            .execution_resolver(root.path(), Arc::new(policy))
            .unwrap();
        let origin = installed.source_location(&bridge.module.record.id).unwrap();
        assert_eq!(origin.filename, root.path().join("bridge.mjs"));
        assert!(origin.url.ends_with("/bridge.mjs?revision=1#captured"));
        let changing = ChangingPolicy {
            allowed: Cell::new(true),
            calls: Cell::new(0),
        };
        resolver
            .resolve(
                &request("dual", ImportStyle::Require),
                &context(),
                &changing,
            )
            .unwrap();
        changing.allowed.set(false);
        assert_eq!(
            resolver
                .resolve(
                    &request("dual", ImportStyle::Require),
                    &context(),
                    &changing
                )
                .unwrap_err()
                .code,
            ResolutionErrorCode::PolicyDenied
        );
        assert_eq!(changing.calls.get(), 2);
    }

    #[test]
    fn real_engine_trait_returns_exact_sources_and_engine_canonical_hashes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const answer=42;");
        let resolver = resolver(root.path());
        let engine: &dyn ModuleResolver = &resolver;
        let out = engine
            .resolve(&resolver.entry_request(), &context(), &granted())
            .unwrap();
        assert_eq!(out.module.record.source, "export const answer=42;");
        assert_eq!(out.module.record.syntax, ModuleSyntax::EsModule);
        assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
        assert_eq!(
            out.module.record.required_capabilities,
            BTreeSet::from([RuntimeCapability::ModuleLoad])
        );
        assert_eq!(out.event.policy_id, "policy");
        assert_eq!(out.event.outcome, "allow");
    }

    #[test]
    fn real_engine_capability_and_specifier_denials_remain_load_bearing() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path());
        let request = r.entry_request();
        let denied = r
            .resolve(
                &request,
                &context(),
                &CapabilityPolicyHook::new(BTreeSet::new()),
            )
            .unwrap_err();
        assert_eq!(denied.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(denied.request_specifier, request.specifier);
        assert_eq!(
            denied.canonical_specifier.as_deref(),
            Some(request.specifier.as_str())
        );
        assert!(
            r.resolve(
                &request,
                &context(),
                &granted().deny_specifier(&request.specifier)
            )
            .is_err()
        );
        assert!(r.resolve(&request, &context(), &granted()).is_ok());
    }

    #[test]
    fn missing_dynamic_imports_remain_distinct_from_unknown_or_denied_routes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import('./optional.mjs'); import('./present.mjs');");
        put(root.path(), "present.mjs", "export const answer = 42;");
        let resolver = resolver(root.path());
        let request = |specifier: &str, style| ModuleRequest::new(specifier, style)
            .with_referrer(resolver.entry_request().specifier)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        for _ in 0..2 {
            let missing = resolver.resolve(
                &request("./optional.mjs", ImportStyle::Import), &context(), &granted(),
            ).unwrap_err();
            assert_eq!(missing.code, ResolutionErrorCode::ModuleNotFound);
            assert!(missing.message.starts_with("ERR_MODULE_NOT_FOUND:"));
        }
        for route in [
            request("./optional.mjs", ImportStyle::Require),
            request("./uncaptured.mjs", ImportStyle::Import),
        ] {
            assert_eq!(
                resolver.resolve(&route, &context(), &granted()).unwrap_err().code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        let present = request("./present.mjs", ImportStyle::Import);
        assert!(resolver.resolve(&present, &context(), &granted()).is_ok());
        assert_eq!(
            resolver.resolve(&present, &context(), &granted().deny_specifier("./present.mjs"))
                .unwrap_err().code,
            ResolutionErrorCode::PolicyDenied
        );
        assert_eq!(
            resolver.resolve_chain(&resolver.entry_request(), &context(), &granted())
                .unwrap_err().code,
            ResolutionErrorCode::ModuleNotFound
        );
    }

    #[test]
    fn captured_package_errors_keep_typed_engine_codes_and_route_boundaries() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "require('pkg/private'); require('#optional'); import('pkg/private'); import('#optional'); require('./present.cjs');",
        );
        put(
            root.path(),
            "package.json",
            r##"{"imports":{"#present":"./present.cjs"}}"##,
        );
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"exports":{".":"./index.cjs"}}"#,
        );
        put(root.path(), "present.cjs", "module.exports = 42;");
        let resolver = resolver_entry(root.path(), "app.cjs");
        let request = |specifier: &str, style| {
            ModuleRequest::new(specifier, style)
                .with_referrer(resolver.entry_request().specifier)
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        for style in [ImportStyle::Require, ImportStyle::Import] {
            for (specifier, expected, node_code) in [
                (
                    "pkg/private",
                    ResolutionErrorCode::PackagePathNotExported,
                    "ERR_PACKAGE_PATH_NOT_EXPORTED",
                ),
                (
                    "#optional",
                    ResolutionErrorCode::PackageImportNotDefined,
                    "ERR_PACKAGE_IMPORT_NOT_DEFINED",
                ),
            ] {
                let error = resolver
                    .resolve(&request(specifier, style), &context(), &granted())
                    .unwrap_err();
                assert_eq!(error.code, expected);
                assert!(error.message.starts_with(node_code));
            }
            assert_eq!(
                resolver
                    .resolve(&request("#uncaptured", style), &context(), &granted())
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        assert_eq!(
            resolver
                .resolve(
                    &request("./present.cjs", ImportStyle::Require),
                    &context(),
                    &granted().deny_specifier("./present.cjs")
                )
                .unwrap_err()
                .code,
            ResolutionErrorCode::PolicyDenied
        );
    }

    struct ChangingPolicy {
        allowed: Cell<bool>,
        calls: Cell<usize>,
    }
    impl ModulePolicyHook for ChangingPolicy {
        fn authorize(
            &self,
            request: &ModuleRequest,
            record: &ModuleRecord,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            self.calls.set(self.calls.get() + 1);
            if self.allowed.get() {
                Ok(())
            } else {
                Err(denied(
                    ResolutionErrorCode::PolicyDenied,
                    "policy revoked",
                    request,
                    context,
                    Some(&record.id),
                ))
            }
        }
    }

    #[test]
    fn cached_sources_never_cache_a_previous_policy_allow() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path());
        let request = r.entry_request();
        let policy = ChangingPolicy {
            allowed: Cell::new(true),
            calls: Cell::new(0),
        };
        let mut first = r.resolve(&request, &context(), &policy).unwrap();
        first.module.record.source = "mutated caller copy".into();
        policy.allowed.set(false);
        assert_eq!(
            r.resolve(&request, &context(), &policy).unwrap_err().code,
            ResolutionErrorCode::PolicyDenied
        );
        policy.allowed.set(true);
        assert_eq!(
            r.resolve(&request, &context(), &policy)
                .unwrap()
                .module
                .record
                .source,
            "export const x=1;"
        );
        assert_eq!(policy.calls.get(), 3);
    }

    #[test]
    fn native_and_bun_mode_requests_cannot_relabel_captured_node_choices() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path());
        for mode in [CompatibilityMode::Native, CompatibilityMode::BunCompat] {
            let request = r.entry_request().with_compatibility_mode(mode);
            assert_eq!(
                r.resolve(&request, &context(), &AllowAllPolicy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
            assert!(
                r.resolve_chain(&request, &context(), &AllowAllPolicy)
                    .is_err()
            );
        }
    }

    #[test]
    fn unknown_referrers_and_uncaptured_routes_fail_even_under_allow_all() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.cjs';");
        put(root.path(), "dep.cjs", "module.exports=1;");
        let r = resolver(root.path());
        let request = ModuleRequest::new("./dep.cjs", ImportStyle::Import)
            .with_compatibility_mode(CompatibilityMode::NodeCompat)
            .with_referrer("app.mjs");
        assert_eq!(
            r.resolve(&request, &context(), &AllowAllPolicy)
                .unwrap_err()
                .code,
            ResolutionErrorCode::InvalidReferrer
        );
        for specifier in ["node:fs", "./unseen.mjs", "././dep.cjs"] {
            let mut request = request.clone();
            request.referrer = Some(r.entry_request().specifier);
            request.specifier = specifier.into();
            assert_eq!(
                r.resolve(&request, &context(), &AllowAllPolicy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
    }

    #[test]
    fn import_require_branches_and_captured_dependency_records_are_engine_native() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import 'p'; require('p');");
        put(
            root.path(),
            "node_modules/p/package.json",
            r#"{"exports":{"import":"./i.mjs","require":"./r.cjs"}}"#,
        );
        put(root.path(), "node_modules/p/i.mjs", "export const x=1;");
        put(root.path(), "node_modules/p/r.cjs", "module.exports=2;");
        let r = resolver(root.path());
        let out = r
            .resolve(&r.entry_request(), &context(), &granted())
            .unwrap();
        assert_eq!(
            out.module.record.dependencies,
            vec![
                ModuleDependency::new("p", ImportStyle::Import),
                ModuleDependency::new("p", ImportStyle::Require)
            ]
        );
        let request = ModuleRequest::new("p", ImportStyle::Require)
            .with_referrer(out.module.record.id)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert_eq!(
            r.resolve(&request, &context(), &granted())
                .unwrap()
                .module
                .record
                .syntax,
            ModuleSyntax::CommonJs
        );
    }

    struct EdgePolicy {
        deny_referrer: Option<String>,
        calls: RefCell<Vec<(Option<String>, String)>>,
    }
    impl ModulePolicyHook for EdgePolicy {
        fn authorize(
            &self,
            request: &ModuleRequest,
            record: &ModuleRecord,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            self.calls
                .borrow_mut()
                .push((request.referrer.clone(), request.specifier.clone()));
            if self.deny_referrer.is_some() && request.referrer == self.deny_referrer {
                return Err(denied(
                    ResolutionErrorCode::PolicyDenied,
                    "this incoming edge is denied",
                    request,
                    context,
                    Some(&record.id),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn resolve_chain_checks_diamond_and_cycle_edges_before_output_deduplication() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './a.mjs'; import './b.mjs';",
        );
        put(root.path(), "a.mjs", "import './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';");
        let r = resolver(root.path());
        let policy = EdgePolicy {
            deny_referrer: None,
            calls: RefCell::new(Vec::new()),
        };
        let outputs = r
            .resolve_chain(&r.entry_request(), &context(), &policy)
            .unwrap();
        assert_eq!(outputs.len(), 4);
        assert_eq!(policy.calls.borrow().len(), 6);
        let b = r
            .registry
            .lookup(
                Some(r.registry.entrypoint()),
                "./b.mjs",
                RequestStyle::Import,
            )
            .ok()
            .unwrap();
        let denied_edge = EdgePolicy {
            deny_referrer: Some(b.id().into()),
            calls: RefCell::new(Vec::new()),
        };
        let error = r
            .resolve_chain(&r.entry_request(), &context(), &denied_edge)
            .unwrap_err();
        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(error.request_specifier, "./shared.mjs");
        assert_eq!(
            denied_edge
                .calls
                .borrow()
                .iter()
                .filter(|(_, s)| s == "./shared.mjs")
                .count(),
            2
        );
    }

    #[test]
    fn chain_cannot_expose_partial_outputs_or_unbounded_duplicate_source_bytes() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './dep.mjs?1'; import './dep.mjs?2';",
        );
        put(root.path(), "dep.mjs", "export const x=1;");
        let mut r = resolver(root.path());
        let first_size = entry_source_size(&r);
        r.chain_source_budget = first_size + "export const x=1;".len();
        let error = r
            .resolve_chain(&r.entry_request(), &context(), &granted())
            .unwrap_err();
        assert!(error.message.contains("source budget"));
        assert!(
            r.resolve(&r.entry_request(), &context(), &granted())
                .is_ok()
        );
    }
    fn entry_source_size(r: &CapturedEngineResolver) -> usize {
        r.registry
            .lookup(None, r.registry.entrypoint(), r.registry.entry_style())
            .ok()
            .unwrap()
            .source()
            .len()
    }

    #[test]
    fn policy_context_is_current_and_oversized_error_evidence_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const secret=1;");
        let r = resolver(root.path());
        let policy = ChangingPolicy {
            allowed: Cell::new(true),
            calls: Cell::new(0),
        };
        let updated = ResolutionContext::new("new-trace", "new-decision", "new-policy");
        assert_eq!(
            r.resolve(&r.entry_request(), &updated, &policy)
                .unwrap()
                .event
                .policy_id,
            "new-policy"
        );
        let bad = ResolutionContext::new("x".repeat(100_000), "d", "p");
        let error = r.resolve(&r.entry_request(), &bad, &policy).unwrap_err();
        assert!(error.trace_id.len() <= MAX_CONTEXT_BYTES);
        assert_eq!(policy.calls.get(), 1);
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
    }

    #[test]
    fn replayed_capsule_is_loadable_with_no_live_project_and_identical_record_identity() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const retained=7;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let before = live
            .resolve(&live.entry_request(), &context(), &granted())
            .unwrap();
        std::fs::rename(root.path().join("app.mjs"), root.path().join("moved.mjs")).unwrap();
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let replay = CapturedEngineResolver::new(replay, &pin).ok().unwrap();
        assert_eq!(
            before,
            replay
                .resolve(&replay.entry_request(), &context(), &granted())
                .unwrap()
        );
    }

    #[test]
    fn engine_resolver_is_shareable_but_does_not_serialize_private_sources() {
        fn assert_shared<T: Send + Sync>() {}
        assert_shared::<CapturedEngineResolver>();
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const private_source=1;");
        let r = std::sync::Arc::new(resolver(root.path()));
        let copy = std::sync::Arc::clone(&r);
        let out = std::thread::spawn(move || {
            copy.resolve(&copy.entry_request(), &context(), &granted())
                .unwrap()
        })
        .join()
        .unwrap();
        assert!(out.module.record.source.contains("private_source"));
        assert!(
            !serde_json::to_string(r.summary())
                .unwrap()
                .contains("private_source")
        );
    }

    #[test]
    fn canonical_hash_is_computed_once_without_caching_policy_or_caller_mutations() {
        use std::sync::atomic::Ordering;
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const answer=42;");
        let r = resolver(root.path());
        let request = r.entry_request();
        let policy = ChangingPolicy {
            allowed: Cell::new(false),
            calls: Cell::new(0),
        };
        assert!(r.resolve(&request, &context(), &policy).is_err());
        assert_eq!(r.hash_computations.load(Ordering::Relaxed), 0);
        policy.allowed.set(true);
        let mut first = r.resolve(&request, &context(), &policy).unwrap();
        let expected_hash = first.module.content_hash;
        first.module.record.source = "changed".into();
        first.module.record.dependencies.clear();
        first.module.record.required_capabilities.clear();
        first.module.record.provenance.origin = "changed".into();
        first.module.record.syntax = ModuleSyntax::CommonJs;
        for i in 0..20 {
            let current = ResolutionContext::new(format!("trace-{i}"), "decision", "policy");
            let out = r.resolve(&request, &current, &policy).unwrap();
            assert_eq!(out.module.content_hash, expected_hash);
            assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
            assert_eq!(out.event.trace_id, format!("trace-{i}"));
        }
        policy.allowed.set(false);
        assert!(r.resolve(&request, &context(), &policy).is_err());
        assert_eq!(policy.calls.get(), 23);
        assert_eq!(r.hash_computations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn concurrent_resolves_share_one_canonical_hash_computation() {
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, Barrier};
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "export const answer=42;");
        let r = Arc::new(resolver(root.path()));
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let r = Arc::clone(&r);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let out = r
                        .resolve(&r.entry_request(), &context(), &granted())
                        .unwrap();
                    assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
                    out.module.content_hash
                })
            })
            .collect();
        let hashes: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert!(hashes.iter().all(|hash| hash == &hashes[0]));
        assert_eq!(r.hash_computations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn streamed_chains_reuse_hashes_but_reauthorize_every_route_on_every_call() {
        use std::sync::atomic::Ordering;
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mjs",
            "import './a.mjs'; import './b.mjs';",
        );
        put(root.path(), "a.mjs", "import './shared.mjs';");
        put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';");
        let r = resolver(root.path());
        let policy = EdgePolicy {
            deny_referrer: None,
            calls: RefCell::new(Vec::new()),
        };
        for _ in 0..3 {
            let out = r
                .resolve_chain(&r.entry_request(), &context(), &policy)
                .unwrap();
            assert_eq!(out.len(), 4);
            for module in out {
                assert_eq!(
                    module.module.content_hash,
                    module.module.record.canonical_hash()
                );
            }
        }
        assert_eq!(policy.calls.borrow().len(), 18);
        assert_eq!(r.hash_computations.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn entry_denial_does_not_prepare_or_hash_the_rest_of_the_graph() {
        use std::sync::atomic::Ordering;
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs';");
        put(root.path(), "dep.mjs", "export const value=1;");
        let r = resolver(root.path());
        let policy = ChangingPolicy {
            allowed: Cell::new(false),
            calls: Cell::new(0),
        };
        assert!(
            r.resolve_chain(&r.entry_request(), &context(), &policy)
                .is_err()
        );
        assert_eq!(policy.calls.get(), 1);
        assert_eq!(r.hash_computations.load(Ordering::Relaxed), 0);
        assert!(r.content_hashes.values().all(|cell| cell.get().is_none()));
    }

    fn resolver_entry(root: &Path, entry: &str) -> CapturedEngineResolver {
        let graph = capture(root, entry, GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        CapturedEngineResolver::new(graph, &pin).ok().unwrap()
    }

    #[test]
    fn unmarked_javascript_uses_engine_commonjs_body_and_module_syntax_detection() {
        for (source, syntax) in [
            ("module.exports=42;", ModuleSyntax::CommonJs),
            ("return;", ModuleSyntax::CommonJs),
            ("export const answer=42;", ModuleSyntax::EsModule),
            ("const module=42;", ModuleSyntax::EsModule),
            ("const exports=42;", ModuleSyntax::EsModule),
            ("const __filename=42;", ModuleSyntax::EsModule),
            ("const __dirname=42;", ModuleSyntax::EsModule),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.js", source);
            let r = resolver_entry(root.path(), "app.js");
            let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
            assert_eq!(out.module.record.syntax, syntax, "{source}");
            assert_eq!(out.module.record.source, source);
            assert_eq!(r.preparation_reports().count(), 1);
        }
    }

    #[test]
    fn installed_unmarked_npm_entry_keeps_its_captured_route_and_detected_format() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "module.exports=require('pkg');");
        put(
            root.path(),
            "node_modules/pkg/package.json",
            r#"{"name":"pkg","main":"index.js"}"#,
        );
        for (source, syntax) in [
            ("module.exports=42;", ModuleSyntax::CommonJs),
            ("export const answer=42;", ModuleSyntax::EsModule),
        ] {
            put(root.path(), "node_modules/pkg/index.js", source);
            let r = resolver_entry(root.path(), "app.cjs");
            let out = r.resolve_chain(&r.entry_request(), &context(), &granted()).unwrap();
            assert_eq!(out.len(), 2);
            assert_eq!(out[1].module.record.syntax, syntax);
            assert_eq!(out[1].module.record.source, source);
            assert_eq!(out[1].module.request_specifier, "pkg");
        }
    }

    #[test]
    fn configured_parser_options_admit_token_heavy_captured_source() {
        let root = tempfile::tempdir().unwrap();
        let source = format!("module.exports=[{}0];", "0,".repeat(40_000));
        put(root.path(), "app.js", &source);
        let graph = || capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        let pin = graph().report().input_hash.clone();
        assert_eq!(
            CapturedEngineResolver::new(graph(), &pin).err().unwrap().code,
            "ERR_MODULE_ENGINE_PARSE_LIMIT"
        );
        let mut options = ParserOptions::default();
        options.budget.max_token_count = 100_000;
        let r = CapturedEngineResolver::new_with_parser_options(graph(), &pin, options)
            .ok()
            .unwrap();
        let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(out.module.record.source, source);
        assert_eq!(out.module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(r.summary().graph_input_hash, pin);
    }

    #[test]
    fn explicit_typescript_formats_use_the_shared_engine_normalizer() {
        use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;
        for (path, source, syntax) in [
            (
                "app.mts",
                "export const answer: number = 42;",
                ModuleSyntax::EsModule,
            ),
            (
                "app.cts",
                "const answer: number = 42; module.exports=answer;",
                ModuleSyntax::CommonJs,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), path, source);
            let r = resolver_entry(root.path(), path);
            let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
            let expected = prepare_source_entry_for_public_entrypoints(
                source,
                path,
                "captured-module-preparation",
                &r.summary().graph_input_hash,
                "franken-node.engine-source-preparation.v1",
            )
            .unwrap();
            assert_eq!(out.module.record.source, expected.prepared_source);
            assert_eq!(out.module.record.syntax, syntax);
            assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
            let report = r.preparation_reports().next().unwrap();
            assert_eq!(report.source_ingestion, expected.source_ingestion);
            assert!(report.normalization_witness.is_some());
            assert_eq!(report.path, path);
        }
    }

    #[test]
    fn typescript_enums_keep_normalization_witnesses_and_module_routes() {
        use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;

        let root = tempfile::tempdir().unwrap();
        let source = r#"
enum State { Ready = require('./seed.cjs'), Next }
enum Label { Ready = 'ready', Done = 'done' }
module.exports = { State, Label, offset: require('./offset.cjs') };
"#;
        put(root.path(), "app.cts", source);
        put(root.path(), "seed.cjs", "module.exports = 40;");
        put(root.path(), "offset.cjs", "module.exports = 1;");
        let graph = capture(root.path(), "app.cts", GraphOptions::default()).unwrap();
        assert!(
            graph.report().fully_resolved,
            "{:?}",
            graph.report().diagnostics
        );
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &granted())
            .unwrap();
        let expected = prepare_source_entry_for_public_entrypoints(
            source,
            "app.cts",
            "captured-module-preparation",
            &pin,
            "franken-node.engine-source-preparation.v1",
        )
        .unwrap();
        assert_eq!(entry.module.record.source, expected.prepared_source);
        assert_eq!(entry.module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(resolver.summary().graph_input_hash, pin);
        assert_eq!(
            entry.module.record.dependencies,
            vec![
                ModuleDependency::new("./seed.cjs", ImportStyle::Require),
                ModuleDependency::new("./offset.cjs", ImportStyle::Require),
            ]
        );
        let prepared = resolver.preparation_reports().next().unwrap();
        assert_eq!(prepared.source_ingestion, expected.source_ingestion);
        assert_eq!(
            prepared.normalization_witness,
            expected.normalization_output.map(|o| o.witness)
        );
        assert!(prepared.normalization_witness.is_some());

        put(
            root.path(),
            "app.cts",
            "throw new Error('live TypeScript was reopened');",
        );
        put(root.path(), "seed.cjs", "module.exports = 0;");
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let restored = CapturedEngineResolver::new(replayed, &pin).ok().unwrap();
        assert_eq!(
            entry,
            restored
                .resolve(&restored.entry_request(), &context(), &granted())
                .unwrap()
        );
        assert_eq!(
            resolver.preparation_reports().collect::<Vec<_>>(),
            restored.preparation_reports().collect::<Vec<_>>()
        );
    }

    #[test]
    fn typescript_enums_cannot_add_or_erase_captured_loads() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cts",
            "enum State { Ready = require('./seed.cjs') }\nmodule.exports=State;\n",
        );
        put(root.path(), "seed.cjs", "module.exports = 42;");
        let graph = capture(root.path(), "app.cts", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        let module = graph
            .report()
            .modules
            .iter()
            .find(|module| module.id.path == "app.cts")
            .unwrap();
        for altered in [
            "enum State { Ready = 42 }\nmodule.exports=State;\n",
            "enum State { Ready = require('./seed.cjs'), Other = require('./uncaptured.cjs') }\nmodule.exports=State;\n",
        ] {
            assert_eq!(
                SourcePreparer::default()
                    .prepare(module, altered, graph.report())
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_ENGINE_DEPENDENCY_DRIFT"
            );
        }
    }

    #[test]
    fn typescript_enum_expansion_obeys_the_callers_parser_budget() {
        let root = tempfile::tempdir().unwrap();
        let source = "export enum State { Ready, Done = 7, Later }\n";
        put(root.path(), "app.mts", source);
        let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        let pin = graph.report().input_hash.clone();
        let mut options = ParserOptions::default();
        options.budget.max_source_bytes = u64::try_from(source.len()).unwrap();
        assert_eq!(
            CapturedEngineResolver::new_with_parser_options(graph, &pin, options)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_ENGINE_PARSE_LIMIT"
        );
    }

    #[test]
    fn unsupported_typescript_transforms_remain_outside_engine_admission() {
        for source in [
            "namespace Values { export const value: number = 42; }\nmodule.exports=Values;\n",
            "namespace Values { export class Box {} }\nmodule.exports=Values;\n",
            "class Value { constructor(public value: number) {} }\nmodule.exports=Value;\n",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cts", source);
            let graph = capture(root.path(), "app.cts", GraphOptions::default()).unwrap();
            assert!(!graph.report().fully_resolved, "{source}");
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_INCOMPLETE",
                "{source}"
            );
        }
    }

    #[test]
    fn normalized_typescript_type_only_imports_do_not_gain_load_authority() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mts",
            "import type { Missing } from './absent.d.ts'; export const answer: number = 42;",
        );
        let r = resolver_entry(root.path(), "app.mts");
        let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
        assert!(out.module.record.dependencies.is_empty());
        assert!(!out.module.record.source.contains("absent.d.ts"));
        let request = ModuleRequest::new("./absent.d.ts", ImportStyle::Import)
            .with_referrer(out.module.record.id)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert_eq!(
            r.resolve(&request, &context(), &granted()).unwrap_err().code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
    }

    #[test]
    fn url_instances_share_preparation_but_keep_distinct_engine_identities() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mts?one'; import './dep.mts?two';");
        put(root.path(), "dep.mts", "export const answer: number = 42;");
        let r = resolver(root.path());
        let out = r.resolve_chain(&r.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(r.preparation_reports().count(), 1);
        assert_eq!(out[1].module.record.source, out[2].module.record.source);
        assert_ne!(out[1].module.content_hash, out[2].module.content_hash);
        assert_ne!(
            out[1].module.canonical_specifier,
            out[2].module.canonical_specifier
        );
    }

    #[test]
    fn engine_preparation_rejects_added_or_removed_runtime_dependency_routes() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mts",
            "import './side.mjs'; export const answer: number=42;",
        );
        put(root.path(), "side.mjs", "export const effect=1;");
        let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
        let module = graph
            .report()
            .modules
            .iter()
            .find(|m| m.id.path == "app.mts")
            .unwrap();
        for transformed_input in [
            "export const answer: number=42;",
            "import './side.mjs'; import './new.mjs'; export const answer: number=42;",
        ] {
            let mut preparer = SourcePreparer::default();
            assert_eq!(
                preparer
                    .prepare(module, transformed_input, graph.report())
                    .err()
                    .unwrap()
                    .code,
                "ERR_MODULE_ENGINE_DEPENDENCY_DRIFT"
            );
        }
    }

    #[test]
    fn typed_capability_obligations_are_not_erased_at_the_module_boundary() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.mts",
            "hostcall<\"network.fetch\">('https://example.invalid');",
        );
        let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_ENGINE_CAPABILITY_METADATA"
        );
    }

    #[test]
    fn prepared_source_replay_never_reopens_the_original_project() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mts", "export const answer: number=42;");
        let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let before = live.resolve(&live.entry_request(), &context(), &granted()).unwrap();
        put(root.path(), "app.mts", "throw new Error('changed');");
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let restored = CapturedEngineResolver::new(replay, &pin).ok().unwrap();
        assert_eq!(
            before,
            restored.resolve(&restored.entry_request(), &context(), &granted()).unwrap()
        );
        assert_eq!(
            live.preparation_reports().collect::<Vec<_>>(),
            restored.preparation_reports().collect::<Vec<_>>()
        );
    }

    #[test]
    fn chain_budget_is_applied_to_delivered_engine_prepared_bytes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mts", "export const answer: number = 42;");
        let mut r = resolver_entry(root.path(), "app.mts");
        let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
        r.chain_source_budget = out.module.record.source.len();
        assert!(r.resolve_chain(&r.entry_request(), &context(), &granted()).is_ok());
        r.chain_source_budget -= 1;
        assert!(r.resolve_chain(&r.entry_request(), &context(), &granted()).is_err());
    }

    #[test]
    fn hashbang_uses_engine_preparation_without_changing_the_graph_pin() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "#!/usr/bin/env node\nmodule.exports=42;");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let r = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(r.summary().graph_input_hash, pin);
        assert_eq!(out.module.record.syntax, ModuleSyntax::CommonJs);
        assert!(!out.module.record.source.contains("#!"));
        assert!(out.module.record.source.ends_with("module.exports=42;"));
        let report = r.preparation_reports().next().unwrap();
        assert!(report.source_ingestion.normalization_applied);
        assert!(report.normalization_witness.is_none());
    }

    #[test]
    fn package_scoped_typescript_uses_engine_normalization_and_detection() {
        use frankenengine_engine::ts_normalization::prepare_source_entry_for_public_entrypoints;
        for (manifest, source, syntax) in [
            (r#"{"type":"module"}"#, "export const answer: number=42;", ModuleSyntax::EsModule),
            (r#"{"type":"commonjs"}"#, "const answer: number=42; module.exports=answer;", ModuleSyntax::CommonJs),
            ("{}", "export const answer: number=42;", ModuleSyntax::EsModule),
            ("{}", "const answer: number=42; module.exports=answer;", ModuleSyntax::CommonJs),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "package.json", manifest);
            put(root.path(), "app.ts", source);
            let r = resolver_entry(root.path(), "app.ts");
            let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
            let expected = prepare_source_entry_for_public_entrypoints(
                source,
                "app.ts",
                "captured-module-preparation",
                &r.summary().graph_input_hash,
                "franken-node.engine-source-preparation.v1",
            ).unwrap();
            assert_eq!(out.module.record.syntax, syntax);
            assert_eq!(out.module.record.source, expected.prepared_source);
            assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
            assert_eq!(r.preparation_reports().count(), 1);
            let prepared = r.preparation_reports().next().unwrap();
            assert_eq!(prepared.source_ingestion, expected.source_ingestion);
            assert!(prepared.normalization_witness.is_some());
        }
    }

    #[test]
    fn explicit_commonjs_typescript_scope_cannot_be_relabelled_as_esm() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r#"{"type":"commonjs"}"#);
        put(root.path(), "app.ts", "export const answer: number=42;");
        let graph = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_ENGINE_PARSE"
        );
    }

    #[test]
    fn typed_url_instances_share_preparation_and_reauthorize_cached_loads() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r#"{"type":"module"}"#);
        put(root.path(), "app.mjs", "import './dep.ts?one'; import './dep.ts?two';");
        put(root.path(), "dep.ts", "export const answer: number=42;");
        let r = resolver(root.path());
        let policy = ChangingPolicy {
            allowed: Cell::new(true),
            calls: Cell::new(0),
        };
        let out = r.resolve_chain(&r.entry_request(), &context(), &policy).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(r.preparation_reports().count(), 1);
        assert_eq!(out[1].module.record.source, out[2].module.record.source);
        assert_ne!(out[1].module.content_hash, out[2].module.content_hash);
        assert_ne!(out[1].module.record.id, out[2].module.record.id);
        let request = ModuleRequest::new("./dep.ts?one", ImportStyle::Import)
            .with_referrer(out[0].module.record.id.clone())
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        policy.allowed.set(false);
        assert_eq!(
            r.resolve(&request, &context(), &policy).unwrap_err().code,
            ResolutionErrorCode::PolicyDenied
        );
        assert_eq!(policy.calls.get(), 4);
    }

    #[test]
    fn typed_package_scope_survives_capsule_replay_after_manifest_mutation() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r#"{"type":"module"}"#);
        put(root.path(), "app.ts", "export const answer: number=42;");
        let graph = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let before = live.resolve(&live.entry_request(), &context(), &granted()).unwrap();
        put(root.path(), "package.json", r#"{"type":"commonjs"}"#);
        put(root.path(), "app.ts", "const answer: number=0; module.exports=answer;");
        let changed = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let changed_pin = changed.report().input_hash.clone();
        assert_ne!(pin, changed_pin);
        let fresh = CapturedEngineResolver::new(changed, &changed_pin).ok().unwrap();
        assert_eq!(
            fresh.resolve(&fresh.entry_request(), &context(), &granted()).unwrap().module.record.syntax,
            ModuleSyntax::CommonJs
        );
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let restored = CapturedEngineResolver::new(replay, &pin).ok().unwrap();
        assert_eq!(
            before,
            restored.resolve(&restored.entry_request(), &context(), &granted()).unwrap()
        );
        assert_eq!(
            live.preparation_reports().collect::<Vec<_>>(),
            restored.preparation_reports().collect::<Vec<_>>()
        );
    }

    #[test]
    fn typed_runtime_routes_cannot_gain_or_lose_dependencies() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r#"{"type":"module"}"#);
        put(root.path(), "app.ts", "import type { Missing } from './absent.d.ts'; import './side.mjs'; export const answer: number=42;");
        put(root.path(), "side.mjs", "export const effect=1;");
        let graph = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let module = graph.report().modules.iter().find(|m| m.id.path == "app.ts").unwrap();
        for altered in [
            "export const answer: number=42;",
            "import './side.mjs'; import './new.mjs'; export const answer: number=42;",
        ] {
            assert_eq!(
                SourcePreparer::default().prepare(module, altered, graph.report()).err().unwrap().code,
                "ERR_MODULE_ENGINE_DEPENDENCY_DRIFT"
            );
        }
        let pin = graph.report().input_hash.clone();
        let r = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let out = r.resolve_chain(&r.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].module.record.dependencies,
            vec![ModuleDependency::new("./side.mjs", ImportStyle::Import)]
        );
        assert!(!out[0].module.record.source.contains("absent.d.ts"));
        let request = ModuleRequest::new("./absent.d.ts", ImportStyle::Import)
            .with_referrer(out[0].module.record.id.clone())
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert_eq!(
            r.resolve(&request, &context(), &granted()).unwrap_err().code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
    }

    #[test]
    fn typed_host_capability_intents_remain_non_erasable() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", r#"{"type":"module"}"#);
        put(root.path(), "app.ts", "hostcall<\"network.fetch\">('https://example.invalid');");
        let graph = capture(root.path(), "app.ts", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_ENGINE_CAPABILITY_METADATA"
        );
    }

    #[test]
    fn syntax_detection_does_not_bypass_indirect_loader_capture_restrictions() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.js", "const require=42;");
        let graph = capture(root.path(), "app.js", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(
            CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_INCOMPLETE"
        );
    }
    fn execute_captured_graph_for_test(
        root: &Path,
        entrypoint: &str,
        lane: frankenengine_engine::baseline_interpreter::LaneChoice,
        after_capture: impl FnOnce(),
    ) -> frankenengine_engine::execution_orchestrator::OrchestratorResult {
        execute_captured_graph_with_policy_for_test(
            root,
            entrypoint,
            lane,
            Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
                RuntimeCapability::Timer,
            ]))),
            after_capture,
        )
        .expect("the actual sibling runtime executes product-captured sources")
    }

    fn execute_captured_graph_with_policy_for_test(
        root: &Path,
        entrypoint: &str,
        lane: frankenengine_engine::baseline_interpreter::LaneChoice,
        policy: Arc<dyn ModulePolicyHook + Send + Sync>,
        after_capture: impl FnOnce(),
    ) -> Result<
        frankenengine_engine::execution_orchestrator::OrchestratorResult,
        frankenengine_engine::execution_orchestrator::OrchestratorError,
    > {
        use frankenengine_engine::ast::ParseGoal;
        use frankenengine_engine::execution_orchestrator::{
            ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
        };

        let graph = capture(root, entrypoint, GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), policy.as_ref())
            .unwrap();
        let installed = resolver.execution_resolver(root, policy).unwrap();
        after_capture();
        let commonjs = entry.module.record.syntax == ModuleSyntax::CommonJs;
        let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig {
                force_lane: Some(lane),
                parse_goal: if commonjs { ParseGoal::Script } else { ParseGoal::Module },
                commonjs_entry: commonjs,
                ..OrchestratorConfig::default()
            },
            frankenengine_engine::runtime_config::RuntimeConfig::default(),
        )
        .unwrap();
        let package = ExtensionPackage {
            extension_id: "captured-product-graph-test".into(),
            source: "throw new Error('uncaptured entry was executed');".into(),
            source_file: Some("/unopened/captured-product-graph-test.js".into()),
            module_root: None,
            capabilities: vec!["module_load".into(), "builtin".into(), "timer".into()],
            version: "1.0.0".into(),
            metadata: BTreeMap::new(),
        };
        engine
            .execute_resolved_entry_with_resolver(&package, &entry, installed)
    }

    fn node_reference_output(root: &Path, entrypoint: &str) -> String {
        let reference = std::process::Command::new("node")
            .arg(root.join(entrypoint))
            .current_dir(root)
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_PATH")
            .output()
            .expect("Node is required for the independent runtime oracle");
        assert!(reference.status.success(), "{reference:?}");
        assert!(reference.stderr.is_empty(), "{reference:?}");
        String::from_utf8(reference.stdout).unwrap()
    }

    #[test]
    fn native_frozen_typescript_enums_keep_package_exports_and_captured_source() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            for (entrypoint, load) in [
                ("app.cjs", "const { Count, Label } = require('enum-kit');"),
                ("app.mjs", "import { Count, Label } from 'enum-kit';"),
            ] {
                let root = tempfile::tempdir().unwrap();
                put(
                    root.path(),
                    entrypoint,
                    &format!(
                        r#"
{load}
console.log(Count.Start, Count.Next, Count.Combined, Count[40], Count[41]);
console.log(Label.Ready, Label.Done, Label[Label.Ready]);
Count.Next = 99;
console.log(Count.Next);
"#
                    ),
                );
                put(
                    root.path(),
                    "node_modules/enum-kit/package.json",
                    r#"{
    "exports": { "import": "./index.mts", "require": "./index.cts" }
}"#,
                );
                put(
                    root.path(),
                    "node_modules/enum-kit/index.cts",
                    r#"
enum Count { Start = require('./seed.cjs'), Next, Combined = Start | Next }
enum Label { Ready = 'ready', Done = 'done' }
module.exports = { Count, Label };
"#,
                );
                put(
                    root.path(),
                    "node_modules/enum-kit/index.mts",
                    r#"
import { seed } from './seed.mjs';
export enum Count { Start = seed, Next, Combined = Start | Next }
export enum Label { Ready = 'ready', Done = 'done' }
"#,
                );
                put(
                    root.path(),
                    "node_modules/enum-kit/seed.cjs",
                    "module.exports = 40;",
                );
                put(
                    root.path(),
                    "node_modules/enum-kit/seed.mjs",
                    "export const seed = 40;",
                );

                let result = execute_captured_graph_for_test(root.path(), entrypoint, lane, || {
                    for path in [
                        entrypoint,
                        "node_modules/enum-kit/index.cts",
                        "node_modules/enum-kit/index.mts",
                        "node_modules/enum-kit/seed.cjs",
                        "node_modules/enum-kit/seed.mjs",
                    ] {
                        put(
                            root.path(),
                            path,
                            "throw new Error('uncaptured source was reopened');",
                        );
                    }
                    put(
                        root.path(),
                        "node_modules/enum-kit/package.json",
                        r#"{
                        "exports": "./uncaptured.cjs"
                    }"#,
                    );
                });
                assert_eq!(
                    result
                        .console_output
                        .iter()
                        .map(|entry| entry.message.as_str())
                        .collect::<Vec<_>>(),
                    ["40 41 41 Start Combined", "ready done undefined", "99"],
                    "{lane:?}: {entrypoint}"
                );
            }
        }
    }

    #[test]
    fn native_typescript_enum_initializers_do_not_bypass_module_policy() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cts",
                "enum Count { Start = require('./seed.cjs') }\nconsole.log(Count.Start);\n",
            );
            put(root.path(), "seed.cjs", "module.exports = 40;");
            let error = execute_captured_graph_with_policy_for_test(
                root.path(),
                "app.cts",
                lane,
                Arc::new(granted().deny_specifier("./seed.cjs")),
                || {},
            )
            .expect_err("normalizing an enum cannot authorize its initializer's module load");
            let message = error.to_string();
            assert!(
                message.contains("closed-world module resolution refused"),
                "{lane:?}: {message}"
            );
            assert!(message.contains("./seed.cjs"), "{lane:?}: {message}");
            assert!(message.contains("policy"), "{lane:?}: {message}");
        }
    }

    #[test]
    fn captured_conditional_requests_authorize_only_captured_choices_and_styles() {
        let root = tempfile::tempdir().unwrap();
        put(
            root.path(),
            "app.cjs",
            "module.exports = function(flag) { \
             return require(flag ? './first.cjs' : './second.cjs'); };",
        );
        for name in ["first", "second", "uncaptured"] {
            put(root.path(), &format!("{name}.cjs"), "module.exports = 42;");
        }
        let resolver = resolver_entry(root.path(), "app.cjs");
        let policy = granted();
        let entry = resolver
            .resolve(&resolver.entry_request(), &context(), &policy)
            .unwrap();
        assert_eq!(entry.module.record.dependencies.len(), 2);
        let request = |specifier: &str, style| {
            ModuleRequest::new(specifier, style)
                .with_referrer(entry.module.record.id.clone())
                .with_compatibility_mode(CompatibilityMode::NodeCompat)
        };
        for specifier in ["./first.cjs", "./second.cjs"] {
            resolver
                .resolve(&request(specifier, ImportStyle::Require), &context(), &policy)
                .unwrap();
            assert_eq!(
                resolver
                    .resolve(&request(specifier, ImportStyle::Import), &context(), &policy)
                    .unwrap_err()
                    .code,
                ResolutionErrorCode::UnsupportedSpecifier
            );
        }
        assert_eq!(
            resolver
                .resolve(
                    &request("./uncaptured.cjs", ImportStyle::Require),
                    &context(),
                    &policy,
                )
                .unwrap_err()
                .code,
            ResolutionErrorCode::UnsupportedSpecifier
        );
    }

    #[test]
    fn captured_conditional_branch_policy_is_checked_when_the_branch_loads() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            for denied in [false, true] {
                let root = tempfile::tempdir().unwrap();
                put(
                    root.path(),
                    "app.cjs",
                    &format!(
                        "function choose(flag) {{ \
                         try {{ return require(flag ? './denied.cjs' : './allowed.cjs'); }} \
                         catch (error) {{ return 'policy refusal became catchable'; }} \
                         }} console.log(choose({denied}));"
                    ),
                );
                put(root.path(), "allowed.cjs", "module.exports = 'allowed';");
                put(root.path(), "denied.cjs", "module.exports = 'forbidden';");
                let policy = granted().deny_specifier("./denied.cjs");
                let result = execute_captured_graph_with_policy_for_test(
                    root.path(),
                    "app.cjs",
                    lane,
                    Arc::new(policy),
                    || {},
                );
                if denied {
                    let error = result.expect_err("captured choices do not grant module authority");
                    let message = error.to_string();
                    assert!(
                        message.contains("closed-world module resolution refused"),
                        "{lane:?}: {message}"
                    );
                    assert!(message.contains("./denied.cjs"), "{lane:?}: {message}");
                    assert!(message.contains("policy"), "{lane:?}: {message}");
                } else {
                    let result = result
                        .expect("an unselected denied alternative does not block execution");
                    assert_eq!(
                        result
                            .console_output
                            .iter()
                            .map(|entry| entry.message.as_str())
                            .collect::<Vec<_>>(),
                        ["allowed"],
                        "{lane:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn captured_conditional_npm_loads_match_node_without_reopening_sources() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                "const choose = require('conditional-kit'); \
                 console.log(choose(true)); console.log(choose(false));",
            );
            put(
                root.path(),
                "node_modules/conditional-kit/package.json",
                r#"{"main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/conditional-kit/index.cjs",
                r#"
module.exports = function(enabled) {
    const selected = require(enabled ? './production.cjs' : './development.cjs');
    const repeated = require(`./${enabled ? 'production' : 'development'}.cjs`);
    const asset = require.resolve('./assets/' + (enabled ? 'first' : 'second') + '.cjs');
    return selected.name + ':' + (selected === repeated) + ':' +
        asset.endsWith(enabled ? 'assets/first.cjs' : 'assets/second.cjs');
};
"#,
            );
            for name in ["production", "development"] {
                put(
                    root.path(),
                    &format!("node_modules/conditional-kit/{name}.cjs"),
                    &format!("module.exports = {{ name: '{name}' }};"),
                );
            }
            for name in ["first", "second"] {
                put(
                    root.path(),
                    &format!("node_modules/conditional-kit/assets/{name}.cjs"),
                    "throw new Error('require.resolve must not evaluate either asset');",
                );
            }
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(reference, "production:true:true\ndevelopment:true:true\n");
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                for path in [
                    "app.cjs",
                    "node_modules/conditional-kit/index.cjs",
                    "node_modules/conditional-kit/production.cjs",
                    "node_modules/conditional-kit/development.cjs",
                ] {
                    put(root.path(), path, "throw new Error('live source reopened');");
                }
                put(
                    root.path(),
                    "node_modules/conditional-kit/package.json",
                    r#"{"main":"uncaptured.cjs"}"#,
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_conditional_created_require_and_import_match_node() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "nested/app.mjs",
                r#"
import { createRequire } from 'node:module';
const local = createRequire(import.meta.url);
function chooseCommonJs(enabled) {
    return local(enabled ? './first.cjs' : './second.cjs');
}
function chooseEsm(enabled) {
    return import(`./${enabled ? 'first' : 'second'}.mjs`);
}
console.log(chooseCommonJs(true), chooseCommonJs(false));
chooseEsm(true).then(function(first) {
    console.log(first.default);
    return chooseEsm(false);
}).then(function(second) {
    console.log(second.default);
});
"#,
            );
            for (name, value) in [("first", 41), ("second", 42)] {
                put(
                    root.path(),
                    &format!("nested/{name}.cjs"),
                    &format!("module.exports = {value};"),
                );
                put(
                    root.path(),
                    &format!("nested/{name}.mjs"),
                    &format!("export default '{name}';"),
                );
                // The createRequire origin must remain the captured nested
                // module, not the root where other modules could exist.
                put(
                    root.path(),
                    &format!("{name}.cjs"),
                    "throw new Error('wrong createRequire origin');",
                );
            }
            let reference = node_reference_output(root.path(), "nested/app.mjs");
            assert_eq!(reference, "41 42\nfirst\nsecond\n");
            let result = execute_captured_graph_for_test(root.path(), "nested/app.mjs", lane, || {
                for path in [
                    "nested/app.mjs",
                    "nested/first.cjs",
                    "nested/second.cjs",
                    "nested/first.mjs",
                    "nested/second.mjs",
                ] {
                    put(
                        root.path(),
                        path,
                        "throw new Error('live conditional source reopened');",
                    );
                }
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_conditional_optional_dependency_stays_missing_after_installation() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const { createRequire } = require('node:module');
const local = createRequire(__filename);
const load = local;
const present = './present.cjs';
const optional = './optional.cjs';
function choose(installed) {
    try { return load(installed ? present : optional); }
    catch (error) { return error.code; }
}
console.log(choose(true), choose(false));
"#,
            );
            put(root.path(), "present.cjs", "module.exports = 42;");
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(reference, "42 MODULE_NOT_FOUND\n");
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                put(
                    root.path(),
                    "optional.cjs",
                    "module.exports = 'uncaptured installation';",
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_package_errors_match_node_after_package_maps_change() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
try { require('pkg/private'); } catch (error) { console.log('require-export', error.name, error.code, error instanceof TypeError); }
try { require.resolve('pkg/private'); } catch (error) { console.log('resolve-export', error.name, error.code, error instanceof TypeError); }
try { require('#optional'); } catch (error) { console.log('require-import', error.name, error.code, error instanceof TypeError); }
try { require.resolve('#optional'); } catch (error) { console.log('resolve-import', error.name, error.code, error instanceof TypeError); }
import('pkg/private').catch(error => console.log('dynamic-export', error.name, error.code, error instanceof TypeError));
import('#optional').catch(error => console.log('dynamic-import', error.name, error.code, error instanceof TypeError));
console.log(require('./fallback.cjs'));
"#,
            );
            put(
                root.path(),
                "package.json",
                r##"{"imports":{"#present":"./fallback.cjs"}}"##,
            );
            put(root.path(), "fallback.cjs", "module.exports = 42;");
            put(
                root.path(),
                "node_modules/pkg/package.json",
                r#"{"exports":{".":"./index.cjs"}}"#,
            );
            put(
                root.path(),
                "node_modules/pkg/private.cjs",
                "throw new Error('must not execute newly exported source');",
            );
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(
                reference,
                concat!(
                    "require-export Error ERR_PACKAGE_PATH_NOT_EXPORTED false\n",
                    "resolve-export Error ERR_PACKAGE_PATH_NOT_EXPORTED false\n",
                    "require-import TypeError ERR_PACKAGE_IMPORT_NOT_DEFINED true\n",
                    "resolve-import TypeError ERR_PACKAGE_IMPORT_NOT_DEFINED true\n",
                    "42\n",
                    "dynamic-export Error ERR_PACKAGE_PATH_NOT_EXPORTED false\n",
                    "dynamic-import TypeError ERR_PACKAGE_IMPORT_NOT_DEFINED true\n",
                )
            );
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                put(
                    root.path(),
                    "package.json",
                    r##"{"imports":{"#optional":"./fallback.cjs"}}"##,
                );
                put(
                    root.path(),
                    "node_modules/pkg/package.json",
                    r#"{"exports":{"./private":"./private.cjs"}}"#,
                );
            });
            assert_eq!(
                result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                reference.lines().collect::<Vec<_>>(),
                "{lane:?}"
            );
        }
    }

    #[test]
    fn captured_constant_request_bindings_match_node_after_live_source_changes() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const name = 'mode-kit';
const load = require;
const choose = load(name);
const path = name + '/production.cjs';
console.log(choose(true), choose(false));
console.log(require.resolve(path).endsWith('/node_modules/mode-kit/production.cjs'));
"#,
            );
            put(
                root.path(),
                "node_modules/mode-kit/package.json",
                r#"{"name":"mode-kit","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/mode-kit/index.cjs",
                r#"
const prefix = './';
const production = prefix + 'production.cjs';
const development = prefix + 'development.cjs';
module.exports = function(flag) {
    return require(flag ? production : development);
};
"#,
            );
            put(
                root.path(),
                "node_modules/mode-kit/production.cjs",
                "module.exports = 42;",
            );
            put(
                root.path(),
                "node_modules/mode-kit/development.cjs",
                "module.exports = 7;",
            );
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(reference, "42 7\ntrue\n");
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                for path in [
                    "app.cjs",
                    "node_modules/mode-kit/index.cjs",
                    "node_modules/mode-kit/production.cjs",
                    "node_modules/mode-kit/development.cjs",
                ] {
                    put(
                        root.path(),
                        path,
                        "throw new Error('live source must not execute');",
                    );
                }
                put(
                    root.path(),
                    "node_modules/mode-kit/package.json",
                    r#"{"main":"missing.cjs"}"#,
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_commonjs_main_guards_keep_entry_identity_across_packages() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const load = require;
console.log(require.main === module, load.main === module);
const kit = require('main-kit');
console.log(kit.main, kit.alias, kit.nonmain);
"#,
            );
            put(
                root.path(),
                "node_modules/main-kit/package.json",
                r#"{"name":"main-kit","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/main-kit/index.cjs",
                r#"
const load = require;
if (require.main === module) { console.log('entry only'); }
else { console.log('loaded as dependency'); }
exports.main = require.main === module;
exports.alias = load.main === module;
exports.nonmain = module !== require.main;
"#,
            );
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(
                reference,
                "true true\nloaded as dependency\nfalse false true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                for path in ["app.cjs", "node_modules/main-kit/index.cjs"] {
                    put(
                        root.path(),
                        path,
                        "throw new Error('uncaptured code must not execute');",
                    );
                }
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_crypto_zlib_packages_match_node_without_live_source_access() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        // These are ordinary module values crossing a package boundary, not
        // source-pattern hostcalls. A captured package must be able to extract
        // methods while preserving the native module's realm-wide identity.
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            for (entrypoint, imports) in [
                (
                    "app.cjs",
                    "const load = require; const next = load; \
                     const crypto = next('crypto'); const zlib = next('node:zlib'); \
                     const createHash = crypto.createHash; const kit = next('archive-kit');",
                ),
                (
                    "app.mjs",
                    "import crypto, { createHash } from 'crypto'; \
                     import zlib from 'node:zlib'; import kit from 'archive-kit';",
                ),
            ] {
                let root = tempfile::tempdir().unwrap();
                put(
                    root.path(),
                    "node_modules/archive-kit/package.json",
                    r#"{"name":"archive-kit","version":"1.0.0","main":"index.cjs"}"#,
                );
                put(
                    root.path(),
                    "node_modules/archive-kit/index.cjs",
                    r#"
const crypto = require('node:crypto');
const zlib = require('zlib');
const hash = crypto.createHash;
const hmac = crypto.createHmac;
const compress = zlib.gzipSync;
const decompress = zlib.gunzipSync;
module.exports = {
    crypto: crypto,
    zlib: zlib,
    digest: function(value) { return hash('sha256').update(value).digest('hex'); },
    authenticate: function(value) { return hmac('sha256', 'key').update(value).digest('hex'); },
    pack: function(value) { return compress(value); },
    unpack: function(value) { return decompress(value).toString('utf8'); }
};
"#,
                );
                let source = format!(
                    r#"{imports}
console.log(crypto === kit.crypto, zlib === kit.zlib, createHash === kit.crypto.createHash);
console.log(kit.digest('abc'));
console.log(kit.authenticate('payload'));
console.log(kit.unpack(kit.pack('frozen npm archive')));
// An independently produced gzip member prevents a paired implementation
// error in compression and decompression from making the roundtrip pass.
console.log(kit.unpack(Buffer.from('1f8b08000000000000034b4c4a0600c241243503000000', 'hex')));
crypto.createHash = function() {{ return 'shared mutation'; }};
console.log(kit.crypto.createHash(), createHash('sha256').update('abc').digest('hex'));
import('node:zlib').then(function(again) {{
    console.log(again.default === zlib, again.gunzipSync === kit.zlib.gunzipSync);
}});
"#
                );
                put(root.path(), entrypoint, &source);
                let reference = node_reference_output(root.path(), entrypoint);
                assert!(reference.starts_with("true true true\n"));
                assert!(reference.contains("\nfrozen npm archive\nabc\n"));
                let result = execute_captured_graph_for_test(root.path(), entrypoint, lane, || {
                    put(
                        root.path(),
                        entrypoint,
                        "throw new Error('live entry must not execute');",
                    );
                    put(
                        root.path(),
                        "node_modules/archive-kit/index.cjs",
                        "throw new Error('live npm package must not execute');",
                    );
                    put(
                        root.path(),
                        "node_modules/archive-kit/package.json",
                        r#"{"main":"missing.cjs"}"#,
                    );
                });
                let actual = result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual,
                    reference.lines().collect::<Vec<_>>(),
                    "{entrypoint} through {lane:?}"
                );
            }
        }
    }

    #[test]
    fn captured_crypto_module_does_not_grant_entropy_authority() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            for (entrypoint, source) in [
                (
                    "app.cjs",
                    "const crypto = require('crypto'); const random = crypto.randomBytes; \
                     random(8); console.log('ENTROPY_MUST_NOT_BE_GRANTED');",
                ),
                (
                    "app.mjs",
                    "import { randomBytes } from 'node:crypto'; \
                     randomBytes(8); console.log('ENTROPY_MUST_NOT_BE_GRANTED');",
                ),
            ] {
                let root = tempfile::tempdir().unwrap();
                put(root.path(), entrypoint, source);
                let result = execute_captured_graph_with_policy_for_test(
                    root.path(),
                    entrypoint,
                    lane,
                    Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
                        RuntimeCapability::ModuleLoad,
                        RuntimeCapability::Builtin,
                    ]))),
                    || {},
                );
                let error = result.expect_err("importing crypto must not grant random_read");
                let detail = error.to_string();
                assert!(
                    detail.contains("random_read"),
                    "{entrypoint} through {lane:?} must retain a typed entropy denial: {detail}"
                );
            }
        }
    }

    #[test]
    fn captured_create_require_factory_forms_execute_through_native_engine() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
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
                    "{factory} const local={origin}; const alias=local, again=alias; \
                     const suffix='.cjs', dependency='./dep'+suffix; \
                     const packageName='du'+'al', asset='./asset'+suffix; \
                     console.log(alias(dependency), again(packageName).answer, \
                         alias(packageName)===again(packageName), again(packageName).resolved); \
                     console.log(again.resolve(asset));"
                );
                put(root.path(), entrypoint, &source);
                put(root.path(), "nested/dep.cjs", "module.exports=42;");
                put(root.path(), "dep.cjs", "throw new Error('wrong origin');");
                put(
                    root.path(),
                    "nested/asset.cjs",
                    "throw new Error('resolve must not evaluate');",
                );
                put(
                    root.path(),
                    "node_modules/dual/package.json",
                    r#"{"exports":{"import":"./imported.mjs","require":"./required.cjs"}}"#,
                );
                put(
                    root.path(),
                    "node_modules/dual/required.cjs",
                    "const {createRequire}=require('node:module'); \
                     const local=createRequire(__filename); const alias=local; \
                     const suffix='.cjs', value='./value'+suffix, asset='./asset'+suffix; \
                     module.exports={answer:alias(value), \
                         resolved:alias.resolve(asset).endsWith('/dual/asset.cjs')};",
                );
                put(
                    root.path(),
                    "node_modules/dual/value.cjs",
                    "module.exports=7;",
                );
                put(
                    root.path(),
                    "node_modules/dual/asset.cjs",
                    "throw new Error('nested resolve must not evaluate');",
                );
                put(
                    root.path(),
                    "nested/value.cjs",
                    "throw new Error('nested alias used entrypoint origin');",
                );
                put(
                    root.path(),
                    "node_modules/dual/imported.mjs",
                    "export default -1;",
                );
                let reference = node_reference_output(root.path(), entrypoint);
                assert_eq!(
                    reference,
                    format!(
                        "42 7 true true\n{}\n",
                        root.path().join("nested/asset.cjs").display()
                    )
                );
                let result = execute_captured_graph_for_test(root.path(), entrypoint, lane, || {
                    put(
                        root.path(),
                        entrypoint,
                        "throw new Error('live entry reopened');",
                    );
                    put(
                        root.path(),
                        "nested/dep.cjs",
                        "throw new Error('live dependency reopened');",
                    );
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
                        "node_modules/dual/value.cjs",
                        "module.exports=-1;",
                    );
                });
                let actual = result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual,
                    reference.lines().collect::<Vec<_>>(),
                    "{lane:?}: {factory}"
                );
            }
        }
    }

    #[test]
    fn native_commonjs_core_objects_execute_across_captured_package_boundaries() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", r#"
                const b=require('buffer');
                const again=require('node:buffer');
                const events=require('events');
                const qs=require('querystring');
                const url=require('url');
                const os=require('os');
                const timers=require('timers');
                const perf=require('perf_hooks');
                const nested=require('fixture');
                console.log(b===again,b.Buffer.from('ok').toString(),nested.same(b));
                const emitter=new events.EventEmitter();
                let total=0;
                emitter.on('value',function(v){total+=v;});
                emitter.emit('value',42);
                console.log(total,qs.stringify({a:42}),new url.URL('https://example.com/a').pathname);
                console.log(os.EOL==='\n',timers.setTimeout===setTimeout,perf.performance===performance);
            "#);
            put(root.path(), "node_modules/fixture/package.json", r#"{"main":"index.cjs"}"#);
            put(root.path(), "node_modules/fixture/index.cjs",
                "module.exports={same:function(value){return require('buffer')===value;}};");
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                put(root.path(), "node_modules/fixture/index.cjs",
                    "throw new Error('uncaptured package was reopened');");
            });
            assert_eq!(
                result.console_output.iter().map(|entry| entry.message.as_str()).collect::<Vec<_>>(),
                vec!["true ok true", "42 a=42 /a", "true true true"]
            );
        }
    }

    #[test]
    fn captured_path_namespaces_preserve_native_identity_and_complete_windows_methods() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const path = require('path/posix');
const child = require('path-user');
const windows = require('node:path/win32');
console.log(child.path === path, windows.posix === path, path.win32 === windows);
console.log(child.make('file.txt'), windows.resolve('C:\\base', '..', 'out'));
path.join = function() { return 'shared mutation'; };
console.log(child.make('ignored'), require('node:path').join('ignored'));
"#,
            );
            put(
                root.path(),
                "node_modules/path-user/package.json",
                r#"{"name":"path-user","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/path-user/index.cjs",
                r#"
const path = require('node:path');
module.exports = { path: path, make: function(value) { return path.join('root', value); } };
"#,
            );
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let captured = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            assert_eq!(captured.summary().modules, 5);
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {
                put(
                    root.path(),
                    "node_modules/path-user/index.cjs",
                    "throw new Error('uncaptured path consumer was reopened');",
                );
            });
            assert_eq!(
                result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                [
                    "true true true",
                    "root/file.txt C:\\out",
                    "shared mutation shared mutation",
                ]
            );
        }
    }

    #[test]
    fn captured_package_import_builtin_aliases_match_node_across_package_scopes() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "package.json",
                r##"{"imports":{"#shared":{"import":"path/posix","default":"events"},"#core/*":"*"}}"##,
            );
            put(
                root.path(),
                "app.mjs",
                r#"
import localPath from '#shared';
import directPath from 'path/posix';
import packagePath, { basename } from 'alias-user';
import { Buffer } from '#core/buffer';
console.log(localPath === directPath, localPath === packagePath, Buffer.from('ok').toString());
console.log(localPath.join('root', 'file.txt'), packagePath.join('root', 'file.txt'));
console.log(basename('C:\\root\\file.txt'));
import('#shared').then(loaded => { console.log(loaded.default === localPath); });
"#,
            );
            put(
                root.path(),
                "node_modules/alias-user/package.json",
                r##"{"exports":"./index.mjs","imports":{"#shared":"path/win32"}}"##,
            );
            put(
                root.path(),
                "node_modules/alias-user/index.mjs",
                "export { default, basename } from '#shared';",
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "true false ok\nroot/file.txt root\\file.txt\nfile.txt\ntrue\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "package.json",
                    r##"{"imports":{"#shared":"events","#core/*":"*"}}"##,
                );
                put(
                    root.path(),
                    "node_modules/alias-user/package.json",
                    r##"{"exports":"./index.mjs","imports":{"#shared":"buffer"}}"##,
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_path_esm_facades_share_commonjs_objects_across_packages() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import path, { join, win32 } from 'node:path';
import * as namespace from 'path';
import windows, { posix, join as windowsJoin } from 'path/win32';
import * as canonical from 'path/posix';
import * as prefixed from 'node:path/posix';
import consumer from 'path-user';
console.log(path === consumer.path, windows === consumer.windows,
    path.win32 === windows, windows.posix === path,
    canonical === prefixed, canonical !== namespace);
console.log(join('root', 'file.txt'), windowsJoin('C:\\root', '..', 'out'));
console.log(win32 === windows, posix === path,
    Object.getPrototypeOf(canonical) === null, Object.isExtensible(canonical));
path.join = function() { return 'shared mutation'; };
console.log(join('one', 'two'), path.join('ignored'), consumer.path.join('ignored'));
import('path').then(function(again) {
    console.log(again === namespace, again.default === path,
        again.join === join, again !== canonical);
});
"#,
            );
            put(
                root.path(),
                "node_modules/path-user/package.json",
                r#"{"name":"path-user","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/path-user/index.cjs",
                "module.exports = { path: require('path'), windows: require('node:path/win32') };",
            );
            let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let captured = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            assert_eq!(captured.summary().modules, 5);
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "node_modules/path-user/index.cjs",
                    "throw new Error('uncaptured path consumer was reopened');",
                );
            });
            assert_eq!(
                result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                [
                    "true true true true true true",
                    "root/file.txt C:\\out",
                    "true true true false",
                    "one/two shared mutation shared mutation",
                    "true true true true",
                ]
            );
        }
    }

    #[test]
    fn native_esm_core_objects_execute_across_captured_npm_package_boundaries() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import buffer, { Buffer } from 'node:buffer';
import * as namespace from 'buffer';
import { encoded, emit, packageBuffer, PackageBuffer, packagePath, join } from 'esm-core-user';
console.log(encoded('ok'), packageBuffer === buffer, PackageBuffer === Buffer);
console.log(emit(42), Object.prototype.toString.call(namespace), namespace.default === buffer);
console.log(join('root', 'file.txt'), packagePath.join === join);
import('node:buffer').then(loaded => {
    console.log(loaded === namespace, loaded.default === packageBuffer, loaded.Buffer === Buffer);
});
"#,
            );
            put(
                root.path(),
                "node_modules/esm-core-user/package.json",
                r#"{"name":"esm-core-user","type":"module","exports":"./index.mjs"}"#,
            );
            put(
                root.path(),
                "node_modules/esm-core-user/index.mjs",
                r#"
import { Buffer } from 'buffer';
import EventEmitter from 'node:events';
export { default as packageBuffer, Buffer as PackageBuffer } from 'node:buffer';
export * from './path-exports.mjs';
export function encoded(text) { return Buffer.from(text).toString('hex'); }
export function emit(value) {
    const emitter = new EventEmitter();
    let result = 0;
    emitter.on('value', function(item) { result = item; });
    emitter.emit('value', value);
    return result;
}
"#,
            );
            put(
                root.path(),
                "node_modules/esm-core-user/path-exports.mjs",
                r#"
export { default as packagePath, join } from 'node:path';
"#,
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "6f6b true true\n42 [object Module] true\nroot/file.txt true\ntrue true true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "node_modules/esm-core-user/index.mjs",
                    "throw new Error('uncaptured ESM package was reopened');",
                );
                put(
                    root.path(),
                    "node_modules/esm-core-user/path-exports.mjs",
                    "throw new Error('uncaptured reexport was reopened');",
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_esm_native_utility_exports_match_node_across_commonjs_packages() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import querystring, { stringify, parse } from 'node:querystring';
import url, { URL, URLSearchParams } from 'url';
import os, { platform, EOL } from 'node:os';
import timers, { setTimeout as schedule, clearTimeout as cancel } from 'timers';
import hooks, { performance as clock } from 'node:perf_hooks';
import common from 'utility-core-user';
console.log(querystring === common.querystring, url === common.url,
    os === common.os, timers === common.timers, hooks === common.hooks);
console.log(stringify({space: 'a b', count: 2}), parse('a=42&b=x%20y').b);
console.log(new URL('https://example.test/a?x=1').pathname, new URLSearchParams('x=a+b').get('x'));
console.log(typeof platform(), EOL === '\n' || EOL === '\r\n', os.platform === platform);
const pending = schedule(function() { throw new Error('cancelled timer ran'); }, 10000);
cancel(pending);
console.log(timers.setTimeout === schedule, cancel === clearTimeout,
    hooks.performance === clock, typeof clock.now(), Number.isFinite(clock.now()));
"#,
            );
            put(
                root.path(),
                "node_modules/utility-core-user/package.json",
                r#"{"name":"utility-core-user","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/utility-core-user/index.cjs",
                r#"
module.exports = {
    querystring: require('querystring'),
    url: require('node:url'),
    os: require('os'),
    timers: require('node:timers'),
    hooks: require('perf_hooks')
};
"#,
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "true true true true true\nspace=a%20b&count=2 x y\n/a a b\nstring true true\ntrue true true number true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "node_modules/utility-core-user/index.cjs",
                    "throw new Error('uncaptured builtin consumer was reopened');",
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_web_stream_consumers_match_node_across_npm_and_frozen_sources() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import consumers, { text, json, buffer, arrayBuffer, blob } from 'node:stream/consumers';
import web, { ReadableStream, WritableStream, TransformStream } from 'stream/web';
import * as namespace from 'node:stream/web';
import common from 'stream-body-user';
console.log(consumers === common.consumers, web === common.web,
    ReadableStream === common.web.ReadableStream, namespace.default === web);
function chunks(values) {
    return new ReadableStream({start(controller) {
        for (const value of values) controller.enqueue(value);
        controller.close();
    }});
}
async function run() {
    console.log(await text(chunks([
        new Uint8Array([0x73, 0x6e, 0x6f, 0x77, 0x20, 0xe2]),
        new Uint8Array([0x98, 0x83])
    ])));
    console.log((await json(chunks(['{"answer":', '42}']))).answer);
    const collected = await buffer(chunks([new Uint8Array([104]), new Uint8Array([105])]));
    const binary = await arrayBuffer(chunks([new Uint8Array([7, 8])]));
    const collectedBlob = await blob(chunks(['body']));
    console.log(common.Buffer.isBuffer(collected), collected.toString(),
        new Uint8Array(binary).join(','), await collectedBlob.text());
    const fromBlob = new common.Blob(['shared']).stream();
    const fromNode = common.Readable.toWeb(common.Readable.from(['node']));
    console.log(fromBlob instanceof ReadableStream, fromNode instanceof ReadableStream,
        await text(fromBlob), await text(fromNode));
    const received = [];
    await chunks(['a', 'b']).pipeThrough(new TransformStream({
        transform(value, controller) { controller.enqueue(value.toUpperCase()); }
    })).pipeTo(new WritableStream({write(value) { received.push(value); }}));
    console.log(received.join(''));
    const dynamic = await import('stream/web');
    console.log(dynamic === namespace, dynamic.ReadableStream === ReadableStream);
}
run();
"#,
            );
            put(
                root.path(),
                "node_modules/stream-body-user/package.json",
                r#"{"name":"stream-body-user","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/stream-body-user/index.cjs",
                r#"
const bytes = require('node:buffer');
module.exports = {
    consumers: require('stream/consumers'),
    web: require('node:stream/web'),
    Buffer: bytes.Buffer,
    Blob: bytes.Blob,
    Readable: require('node:stream').Readable
};
"#,
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "true true true true\nsnow ☃\n42\ntrue hi 7,8 body\ntrue true shared node\nAB\ntrue true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "app.mjs",
                    "throw new Error('live entry was reopened');",
                );
                put(
                    root.path(),
                    "node_modules/stream-body-user/index.cjs",
                    "throw new Error('live npm consumer was reopened');",
                );
                put(
                    root.path(),
                    "node_modules/stream-body-user/package.json",
                    r#"{"exports":{}}"#,
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn cached_stream_factories_reauthorize_denied_alias_imports() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            for name in ["stream/consumers", "stream/web"] {
                let root = tempfile::tempdir().unwrap();
                let alias = format!("node:{name}");
                let source = format!(
                    "const core = require('{name}'); \
                     import('{alias}').then(\
                         function() {{ console.log('cached module bypassed policy'); }}, \
                         function() {{ console.log('policy denial became catchable'); }}\
                     );"
                );
                put(root.path(), "app.cjs", &source);
                let mut policy = CapabilityPolicyHook::new(BTreeSet::from([
                    RuntimeCapability::ModuleLoad,
                    RuntimeCapability::Builtin,
                ]));
                policy.denied_specifiers.insert(alias.clone());
                let error = execute_captured_graph_with_policy_for_test(
                    root.path(),
                    "app.cjs",
                    lane,
                    Arc::new(policy),
                    || {},
                )
                .expect_err("a retained native factory must still authorize every public route");
                let message = error.to_string();
                assert!(
                    message.contains("closed-world module resolution refused"),
                    "{lane:?}: {message}"
                );
                assert!(message.contains(&alias), "{lane:?}: {message}");
                assert!(message.contains("policy"), "{lane:?}: {message}");
            }
        }
    }

    #[test]
    fn captured_mixed_builtin_imports_share_defaults_and_distinct_path_namespaces() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import * as path from 'path';
import * as pathAlias from 'node:path';
import * as posix from 'node:path/posix';
import * as windows from 'path/win32';
import buffer from 'node:buffer';
import events from 'events';
import common from 'mixed-core-user';
console.log(path === pathAlias, path !== posix, path.default === posix.default);
console.log(common.path === path.default, common.posix === posix.default, common.windows === windows.default);
console.log(path.default.win32 === windows.default, windows.default.posix === posix.default);
console.log(common.buffer === buffer, common.events === events, events === events.EventEmitter);
"#,
            );
            put(
                root.path(),
                "node_modules/mixed-core-user/package.json",
                r#"{"name":"mixed-core-user","main":"index.cjs"}"#,
            );
            put(
                root.path(),
                "node_modules/mixed-core-user/index.cjs",
                r#"
module.exports = {
    path: require('node:path'),
    posix: require('path/posix'),
    windows: require('node:path/win32'),
    buffer: require('buffer'),
    events: require('node:events')
};
"#,
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "true true true\ntrue true true\ntrue true\ntrue true true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(
                    root.path(),
                    "node_modules/mixed-core-user/index.cjs",
                    "throw new Error('uncaptured CommonJS package was reopened');",
                );
            });
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_builtin_namespaces_preserve_declared_exports_after_commonjs_mutation() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const path = require('path');
path.captureOnly = 'package extension';
import('node:path').then(namespace => {
    const join = namespace.join;
    console.log(Object.prototype.hasOwnProperty.call(namespace, 'captureOnly'),
        namespace.default === path, namespace.default.captureOnly);
    path.join = function() { return 'changed'; };
    return import('path').then(alias => {
        console.log(alias === namespace, alias.join === join,
            alias.join('a', 'b'), path.join('a', 'b'));
    });
});
"#,
            );
            let reference = node_reference_output(root.path(), "app.cjs");
            assert_eq!(
                reference,
                "false true package extension\ntrue true a/b changed\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.cjs", lane, || {});
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_native_namespaces_match_node_write_and_reflection_semantics() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.mjs",
                r#"
import * as namespace from 'node:buffer';
const original = namespace.Buffer;
const descriptor = Object.getOwnPropertyDescriptor(namespace, 'Buffer');
function failure(action) {
    try { action(); return 'no error'; } catch (error) { return error.name; }
}
console.log(Object.getPrototypeOf(namespace) === null, Object.isExtensible(namespace),
    Object.isSealed(namespace), Object.isFrozen(namespace));
console.log(descriptor.value === original, descriptor.writable,
    descriptor.enumerable, descriptor.configurable);
console.log(Reflect.set(namespace, 'Buffer', original),
    Reflect.set(namespace, 'newExport', 1), namespace.Buffer === original);
console.log(failure(function() { namespace.Buffer = 7; }),
    Reflect.defineProperty(namespace, 'Buffer', {value: original}),
    Reflect.defineProperty(namespace, 'Buffer', {
        value: original, writable: true, enumerable: true, configurable: false
    }), Object.defineProperty(namespace, 'Buffer', {value: original}) === namespace);
console.log(Reflect.defineProperty(namespace, 'Buffer', {value: 7}),
    Reflect.defineProperty(namespace, 'Buffer', {writable: false}),
    Reflect.defineProperty(namespace, 'Buffer', {get: function() { return original; }}),
    Reflect.defineProperty(namespace, 'Buffer', {enumerable: false}),
    Reflect.defineProperty(namespace, 'Buffer', {configurable: true}));
console.log(failure(function() { Object.defineProperty(namespace, 'Buffer', {value: 7}); }),
    Reflect.deleteProperty(namespace, 'Buffer'), Reflect.deleteProperty(namespace, 'missing'));
const receiver = {};
const inherited = Object.create(namespace);
const proxy = new Proxy(namespace, {});
console.log(Reflect.set(namespace, 'Buffer', 7, receiver),
    Reflect.set(namespace, 'missing', 7, receiver), Object.keys(receiver).length);
console.log(Reflect.set(inherited, 'Buffer', 7), Reflect.set(inherited, 'missing', 7),
    inherited.Buffer === original, Object.keys(inherited).length);
Object.defineProperty(inherited, 'Buffer', {value: 7, writable: true});
console.log(Reflect.set(inherited, 'Buffer', 8), inherited.Buffer, namespace.Buffer === original);
console.log(Reflect.set(proxy, 'Buffer', original), Reflect.set({}, 'Buffer', original, proxy),
    Reflect.set({}, 'Buffer', original, namespace));
console.log(Reflect.set(proxy, 'Buffer', 7),
    Reflect.defineProperty(proxy, 'Buffer', {value: original}),
    Reflect.defineProperty(proxy, 'Buffer', {value: 7}),
    Reflect.deleteProperty(proxy, 'Buffer'), Reflect.deleteProperty(proxy, 'missing'));
"#,
            );
            let reference = node_reference_output(root.path(), "app.mjs");
            assert_eq!(
                reference,
                "true false true false\ntrue true true false\nfalse false true\nTypeError true true true\nfalse false false false false\nTypeError false true\ntrue true 2\ntrue true false 2\ntrue 8 true\ntrue true false\nfalse true false false true\n"
            );
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {});
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(actual, reference.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn captured_builtin_cached_default_cannot_bypass_import_policy() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                r#"
const buffer = require('buffer');
console.log(buffer.Buffer.from('cached').toString());
import('node:buffer').then(
    function() { console.log('forbidden alias was loaded'); },
    function() { console.log('policy refusal became a guest exception'); }
);
"#,
            );
            let mut policy = CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
                RuntimeCapability::Timer,
            ]));
            policy.denied_specifiers.insert("node:buffer".into());
            let error = execute_captured_graph_with_policy_for_test(
                root.path(),
                "app.cjs",
                lane,
                Arc::new(policy),
                || {},
            )
            .expect_err("cached native objects never retain an import authorization");
            let message = error.to_string();
            assert!(
                message.contains("closed-world module resolution refused"),
                "{lane:?}: {message}"
            );
            assert!(message.contains("node:buffer"), "{lane:?}: {message}");
            assert!(message.contains("policy"), "{lane:?}: {message}");
        }
    }

    #[test]
    fn native_commonjs_uses_captured_npm_json_sources_and_original_filenames() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path();
            put(root, "app.cjs",
                "const a=require('fixture'); const b=require('fixture'); console.log(a.answer, a===b); console.log(__filename); console.log(__dirname);");
            put(root, "node_modules/fixture/package.json",
                r#"{"exports":[null,"./index.cjs"]}"#);
            put(root, "node_modules/fixture/index.cjs", "module.exports=require('./answer.json');");
            put(root, "node_modules/fixture/answer.json", r#"{"answer":42}"#);
            let result = execute_captured_graph_for_test(root, "app.cjs", lane, || {
                put(root, "app.cjs", "throw new Error('changed entry');");
                put(root, "node_modules/fixture/index.cjs", "throw new Error('changed dependency');");
                put(root, "node_modules/fixture/answer.json", r#"{"answer":99}"#);
            });
            let lines = result.console_output.iter().map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(lines, vec![
                "42 true".to_string(),
                root.join("app.cjs").display().to_string(),
                root.display().to_string(),
            ]);
        }
    }

    #[test]
    fn native_optional_dynamic_import_rejection_matches_node_after_installation_changes() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.mjs", r#"
                console.log('start');
                if (false) import('never-installed');
                import('optional-package').catch(error => {
                    console.log(error.code);
                    return import('./fallback.mjs');
                }).then(fallback => console.log(fallback.answer));
            "#);
            put(root.path(), "fallback.mjs", "export const answer = 42;");
            let reference = std::process::Command::new("node")
                .arg(root.path().join("app.mjs"))
                .current_dir(root.path())
                .env_remove("NODE_OPTIONS")
                .env_remove("NODE_PATH")
                .output().expect("Node is required for the independent runtime oracle");
            assert!(reference.status.success(), "{reference:?}");
            let reference_output = String::from_utf8(reference.stdout).unwrap();
            assert_eq!(reference_output, "start\nERR_MODULE_NOT_FOUND\n42\n");
            let result = execute_captured_graph_for_test(root.path(), "app.mjs", lane, || {
                put(root.path(), "node_modules/optional-package/package.json",
                    r#"{"main":"index.mjs"}"#);
                put(root.path(), "node_modules/optional-package/index.mjs",
                    "throw new Error('uncaptured installation was loaded');");
                put(root.path(), "fallback.mjs", "export const answer = 99;");
            });
            let actual = result.console_output.iter()
                .map(|entry| entry.message.as_str()).collect::<Vec<_>>();
            assert_eq!(actual, reference_output.lines().collect::<Vec<_>>(), "{lane:?}");
        }
    }

    #[test]
    fn native_esm_preserves_captured_query_origins_after_files_change() {
        use frankenengine_engine::baseline_interpreter::LaneChoice;

        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let parent = tempfile::tempdir().unwrap();
            let root = parent.path().join("project with spaces");
            put(&root, "app.mjs",
                "import { answer, origin } from './side.mjs?one#tag'; console.log(answer, origin.url); console.log(import.meta.url);");
            put(&root, "side.mjs", "export const answer=42; export const origin=import.meta;");
            let result = execute_captured_graph_for_test(&root, "app.mjs", lane, || {
                put(&root, "side.mjs", "throw new Error('changed ESM dependency');");
            });
            let lines = result.console_output.iter().map(|entry| entry.message.as_str())
                .collect::<Vec<_>>();
            assert_eq!(lines, vec![
                format!("42 {}?one#tag", url::Url::from_file_path(root.join("side.mjs")).unwrap()),
                url::Url::from_file_path(root.join("app.mjs")).unwrap().to_string(),
            ]);
        }
    }
}
