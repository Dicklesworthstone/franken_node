//! FrankenEngine ModuleResolver implementation over a pinned source registry.
//!
//! This implements the real sibling engine trait, not a lookalike interface.
//! Source selection is closed-world; the supplied engine policy runs on every
//! delivered candidate, including cache hits and traversed cycle back-edges.
//! Exact CommonJS requests for engine-supported native builtin objects become
//! source-free terminal descriptors. No builtin fallback, live I/O or evaluation
//! happens here. Source preparation uses the sibling engine front end.

#[path = "module_engine_preparation.rs"]
mod preparation;
pub use preparation::ModulePreparationSummary;
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
            |specifier| NativeBuiltinModule::from_specifier(specifier)
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
        // Only a captured negative CommonJS lookup is a guest-catchable
        // absence. An unknown route is a closed-world authority violation;
        // it must not be disguised as an optional dependency being absent.
        "MODULE_NOT_FOUND" => ResolutionErrorCode::ModuleNotFound,
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
    fn unsupported_builtin_load_styles_and_indirect_loaders_remain_refused() {
        for (file, source) in [
            ("app.cjs", "require('fs');"),
            ("app.cjs", "require('node:unknown');"),
            ("app.cjs", "const name='buffer'; require(name);"),
            ("app.cjs", "require.resolve('buffer', {paths: ['/tmp']});"),
            ("app.cjs", "require('#builtin');"),
            ("app.mjs", "import 'buffer';"),
            ("app.mjs", "import('node:buffer');"),
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "package.json", r##"{"imports":{"#builtin":"buffer"}}"##);
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
        put(root.path(), "app.cjs", "require('buffer');");
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
        use frankenengine_engine::ast::ParseGoal;
        use frankenengine_engine::execution_orchestrator::{
            ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
        };

        let graph = capture(root, entrypoint, GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        let policy = Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin, RuntimeCapability::Timer,
        ])));
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
            .expect("the actual sibling runtime executes product-captured sources")
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
            assert_eq!(captured.summary().modules, 4);
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

