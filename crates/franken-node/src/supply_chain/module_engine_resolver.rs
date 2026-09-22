//! FrankenEngine ModuleResolver implementation over a pinned source registry.
//!
//! This implements the real sibling engine trait, not a lookalike interface.
//! Source selection is closed-world; the supplied engine policy runs on every
//! resolve and every traversed edge, including cache hits and cycle back-edges.
//! No builtin fallback, live I/O, transformation or evaluation happens here.

use super::{CapturedModuleGraph, ResolutionError as CaptureError};
use super::registry::{ModuleKind, PinnedModuleRegistry, RegisteredModule, RegistrySummary, RequestStyle};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
use frankenengine_engine::module_resolver::{ImportStyle, ModuleDependency, ModulePolicyHook,
    ModuleProvenance, ModuleRecord, ModuleRequest, ModuleResolver, ModuleSourceKind, ModuleSyntax,
    ResolutionContext, ResolutionError, ResolutionErrorCode, ResolutionEvent, ResolutionOutcome,
    ResolutionResult, ResolvedModule};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CHAIN_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 1024;

/// An embedding resolver, not an evaluator or a policy grant. It can be passed
/// directly as &dyn FrankenEngine ModuleResolver. Only explicit JavaScript
/// ESM/CommonJS formats are admitted; normalization and linking stay in engine.
pub struct CapturedEngineResolver {
    registry: PinnedModuleRegistry,
    chain_source_budget: usize,
}

impl CapturedEngineResolver {
    pub fn new(graph: CapturedModuleGraph, independent_graph_pin: &str) -> Result<Self, CaptureError> {
        Ok(Self::from_registry(PinnedModuleRegistry::new(graph, independent_graph_pin)?))
    }

    pub fn from_registry(registry: PinnedModuleRegistry) -> Self {
        Self { registry, chain_source_budget: MAX_CHAIN_SOURCE_BYTES }
    }

    pub fn summary(&self) -> &RegistrySummary { self.registry.summary() }

    pub fn entry_request(&self) -> ModuleRequest {
        ModuleRequest::new(self.registry.entrypoint(), engine_style(self.registry.entry_style()))
            .with_compatibility_mode(CompatibilityMode::NodeCompat)
    }

    fn validate_request(&self, request: &ModuleRequest, context: &ResolutionContext) -> ResolutionResult<()> {
        if request.compatibility_mode != CompatibilityMode::NodeCompat {
            return Err(denied(ResolutionErrorCode::UnsupportedSpecifier,
                "captured node-resolution choices cannot be relabelled as native or Bun resolution", request, context, None));
        }
        if [&context.trace_id, &context.decision_id, &context.policy_id].iter().any(|value|
            value.is_empty() || value.len() > MAX_CONTEXT_BYTES || value.chars().any(char::is_control)) {
            return Err(denied(ResolutionErrorCode::PolicyDenied,
                "bounded nonempty trace, decision and policy identities are required", request, context, None));
        }
        Ok(())
    }

    fn lookup<'a>(&'a self, request: &ModuleRequest, context: &ResolutionContext) -> ResolutionResult<&'a RegisteredModule> {
        self.registry.lookup(request.referrer.as_deref(), &request.specifier, source_style(request.style))
            .map_err(|error| registry_error(error, request, context))
    }

    fn record(&self, module: &RegisteredModule) -> ModuleRecord {
        ModuleRecord {
            id: module.id().to_owned(),
            syntax: match module.kind() { ModuleKind::EsModule => ModuleSyntax::EsModule, ModuleKind::CommonJs => ModuleSyntax::CommonJs },
            // The policy receives this candidate record, as required by the
            // engine contract. It is not returned to a caller before approval.
            source: module.source().to_owned(),
            dependencies: module.dependencies().iter().map(|d|
                ModuleDependency::new(&d.specifier, engine_style(d.style))).collect(),
            required_capabilities: BTreeSet::from([RuntimeCapability::ModuleLoad]),
            provenance: ModuleProvenance {
                // Captured installed code is NOT claimed to be authenticated
                // registry content. Workspace means captured project material.
                kind: ModuleSourceKind::Workspace,
                origin: format!("franken-node-source-graph:{}", self.registry.summary().graph_input_hash),
            },
        }
    }

    fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord, context: &ResolutionContext,
        policy: &dyn ModulePolicyHook) -> ResolutionResult<()> {
        policy.authorize(request, record, context).map_err(|error|
            denied(error.code, &error.message, request, context, Some(&record.id)))
    }

    fn outcome(&self, request: &ModuleRequest, record: ModuleRecord, context: &ResolutionContext) -> ResolutionOutcome {
        let content_hash = record.canonical_hash();
        ResolutionOutcome {
            module: ResolvedModule { request_specifier: request.specifier.clone(),
                canonical_specifier: record.id.clone(), record, content_hash, probe_sequence: Vec::new() },
            event: event(context, "allow", ""),
        }
    }
}

impl ModuleResolver for CapturedEngineResolver {
    fn resolve(&self, request: &ModuleRequest, context: &ResolutionContext,
        policy: &dyn ModulePolicyHook) -> ResolutionResult<ResolutionOutcome> {
        self.validate_request(request, context)?;
        let module = self.lookup(request, context)?;
        let record = self.record(module);
        self.authorize(request, &record, context, policy)?;
        Ok(self.outcome(request, record, context))
    }

    fn resolve_chain(&self, entry_request: &ModuleRequest, context: &ResolutionContext,
        policy: &dyn ModulePolicyHook) -> ResolutionResult<Vec<ResolutionOutcome>> {
        self.validate_request(entry_request, context)?;
        let requests = self.registry.reachable_requests(entry_request.referrer.as_deref(),
            &entry_request.specifier, source_style(entry_request.style))
            .map_err(|error| registry_error(error, entry_request, context))?;
        let mut outcomes: Vec<ResolutionOutcome> = Vec::new();
        let mut positions = BTreeMap::<String, usize>::new();
        let mut source_bytes = 0_usize;
        for (referrer, specifier, style) in requests {
            let mut request = ModuleRequest::new(specifier, engine_style(style))
                .with_compatibility_mode(CompatibilityMode::NodeCompat);
            request.referrer = referrer;
            let module = self.lookup(&request, context)?;
            if let Some(&position) = positions.get(module.id()) {
                // Cached source is not cached authorization. Checking this edge
                // precedes output deduplication, even for a cycle's back-edge.
                self.authorize(&request, &outcomes[position].module.record, context, policy)?;
                continue;
            }
            source_bytes = source_bytes.checked_add(module.source().len()).ok_or_else(||
                denied(ResolutionErrorCode::UnsupportedSpecifier, "resolved-chain source budget exceeded", &request, context, Some(module.id())))?;
            if source_bytes > self.chain_source_budget {
                return Err(denied(ResolutionErrorCode::UnsupportedSpecifier,
                    "resolved-chain source budget exceeded", &request, context, Some(module.id())));
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
    match style { ImportStyle::Import => RequestStyle::Import, ImportStyle::Require => RequestStyle::Require }
}
fn engine_style(style: RequestStyle) -> ImportStyle {
    match style { RequestStyle::Import => ImportStyle::Import, RequestStyle::Require => ImportStyle::Require }
}

fn bounded(value: &str, max: usize) -> String {
    let mut end = value.len().min(max);
    while !value.is_char_boundary(end) { end -= 1; }
    value[..end].to_owned()
}

fn event(context: &ResolutionContext, outcome: &str, code: &str) -> ResolutionEvent {
    ResolutionEvent { trace_id: bounded(&context.trace_id, MAX_CONTEXT_BYTES),
        decision_id: bounded(&context.decision_id, MAX_CONTEXT_BYTES),
        policy_id: bounded(&context.policy_id, MAX_CONTEXT_BYTES),
        component: "captured_module_resolver".into(), event: "module_resolution".into(),
        outcome: outcome.into(), error_code: code.into() }
}

fn denied(code: ResolutionErrorCode, message: &str, request: &ModuleRequest,
    context: &ResolutionContext, canonical: Option<&str>) -> Box<ResolutionError> {
    let event = event(context, "deny", code.stable_code());
    Box::new(ResolutionError { code, message: bounded(message, 4096),
        trace_id: event.trace_id.clone(), decision_id: event.decision_id.clone(), policy_id: event.policy_id.clone(),
        request_specifier: bounded(&request.specifier, 4096), canonical_specifier: canonical.map(str::to_owned),
        source_kind: canonical.map(|_| ModuleSourceKind::Workspace), probe_sequence: Vec::new(), event })
}

fn registry_error(error: CaptureError, request: &ModuleRequest, context: &ResolutionContext) -> Box<ResolutionError> {
    let code = match error.code {
        "ERR_MODULE_REGISTRY_REFERRER" => ResolutionErrorCode::InvalidReferrer,
        "ERR_MODULE_REGISTRY_ROUTE" => ResolutionErrorCode::ModuleNotFound,
        "ERR_MODULE_REGISTRY_REQUEST" if request.specifier.is_empty() => ResolutionErrorCode::EmptySpecifier,
        _ => ResolutionErrorCode::UnsupportedSpecifier,
    };
    denied(code, &format!("{}: {}", error.code, error.detail), request, context, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{GraphOptions, capture, capsule};
    use frankenengine_engine::module_resolver::{AllowAllPolicy, CapabilityPolicyHook};
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    fn put(root: &Path, path: &str, source: &str) {
        let path = root.join(path); std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }
    fn resolver(root: &Path) -> CapturedEngineResolver {
        let graph = capture(root, "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone(); CapturedEngineResolver::new(graph, &pin).ok().unwrap()
    }
    fn context() -> ResolutionContext { ResolutionContext::new("trace", "decision", "policy") }
    fn granted() -> CapabilityPolicyHook { CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad])) }

    #[test]
    fn real_engine_trait_returns_exact_sources_and_engine_canonical_hashes() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const answer=42;");
        let resolver = resolver(root.path()); let engine: &dyn ModuleResolver = &resolver;
        let out = engine.resolve(&resolver.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(out.module.record.source, "export const answer=42;");
        assert_eq!(out.module.record.syntax, ModuleSyntax::EsModule);
        assert_eq!(out.module.content_hash, out.module.record.canonical_hash());
        assert_eq!(out.module.record.required_capabilities, BTreeSet::from([RuntimeCapability::ModuleLoad]));
        assert_eq!(out.event.policy_id, "policy"); assert_eq!(out.event.outcome, "allow");
    }

    #[test]
    fn real_engine_capability_and_specifier_denials_remain_load_bearing() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path()); let request = r.entry_request();
        let denied = r.resolve(&request, &context(), &CapabilityPolicyHook::new(BTreeSet::new())).unwrap_err();
        assert_eq!(denied.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(denied.request_specifier, request.specifier);
        assert_eq!(denied.canonical_specifier.as_deref(), Some(request.specifier.as_str()));
        assert!(r.resolve(&request, &context(), &granted().deny_specifier(&request.specifier)).is_err());
        assert!(r.resolve(&request, &context(), &granted()).is_ok());
    }

    struct ChangingPolicy { allowed: Cell<bool>, calls: Cell<usize> }
    impl ModulePolicyHook for ChangingPolicy {
        fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord, context: &ResolutionContext) -> ResolutionResult<()> {
            self.calls.set(self.calls.get() + 1);
            if self.allowed.get() { Ok(()) } else {
                Err(denied(ResolutionErrorCode::PolicyDenied, "policy revoked", request, context, Some(&record.id)))
            }
        }
    }

    #[test]
    fn cached_sources_never_cache_a_previous_policy_allow() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path()); let request = r.entry_request();
        let policy = ChangingPolicy { allowed: Cell::new(true), calls: Cell::new(0) };
        let mut first = r.resolve(&request, &context(), &policy).unwrap();
        first.module.record.source = "mutated caller copy".into();
        policy.allowed.set(false);
        assert_eq!(r.resolve(&request, &context(), &policy).unwrap_err().code, ResolutionErrorCode::PolicyDenied);
        policy.allowed.set(true);
        assert_eq!(r.resolve(&request, &context(), &policy).unwrap().module.record.source, "export const x=1;");
        assert_eq!(policy.calls.get(), 3);
    }

    #[test]
    fn native_and_bun_mode_requests_cannot_relabel_captured_node_choices() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const x=1;");
        let r = resolver(root.path());
        for mode in [CompatibilityMode::Native, CompatibilityMode::BunCompat] {
            let request = r.entry_request().with_compatibility_mode(mode);
            assert_eq!(r.resolve(&request, &context(), &AllowAllPolicy).unwrap_err().code, ResolutionErrorCode::UnsupportedSpecifier);
            assert!(r.resolve_chain(&request, &context(), &AllowAllPolicy).is_err());
        }
    }

    #[test]
    fn unknown_referrers_and_uncaptured_routes_fail_even_under_allow_all() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.cjs';"); put(root.path(), "dep.cjs", "module.exports=1;");
        let r = resolver(root.path());
        let request = ModuleRequest::new("./dep.cjs", ImportStyle::Import)
            .with_compatibility_mode(CompatibilityMode::NodeCompat).with_referrer("app.mjs");
        assert_eq!(r.resolve(&request, &context(), &AllowAllPolicy).unwrap_err().code, ResolutionErrorCode::InvalidReferrer);
        for specifier in ["node:fs", "./unseen.mjs", "././dep.cjs"] {
            let mut request = request.clone(); request.referrer = Some(r.entry_request().specifier); request.specifier = specifier.into();
            assert_eq!(r.resolve(&request, &context(), &AllowAllPolicy).unwrap_err().code, ResolutionErrorCode::ModuleNotFound);
        }
    }

    #[test]
    fn import_require_branches_and_captured_dependency_records_are_engine_native() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "import 'p'; require('p');");
        put(root.path(), "node_modules/p/package.json", r#"{"exports":{"import":"./i.mjs","require":"./r.cjs"}}"#);
        put(root.path(), "node_modules/p/i.mjs", "export const x=1;"); put(root.path(), "node_modules/p/r.cjs", "module.exports=2;");
        let r = resolver(root.path());
        let out = r.resolve(&r.entry_request(), &context(), &granted()).unwrap();
        assert_eq!(out.module.record.dependencies, vec![ModuleDependency::new("p", ImportStyle::Import), ModuleDependency::new("p", ImportStyle::Require)]);
        let request = ModuleRequest::new("p", ImportStyle::Require).with_referrer(out.module.record.id)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert_eq!(r.resolve(&request, &context(), &granted()).unwrap().module.record.syntax, ModuleSyntax::CommonJs);
    }

    struct EdgePolicy { deny_referrer: Option<String>, calls: RefCell<Vec<(Option<String>, String)>> }
    impl ModulePolicyHook for EdgePolicy {
        fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord, context: &ResolutionContext) -> ResolutionResult<()> {
            self.calls.borrow_mut().push((request.referrer.clone(), request.specifier.clone()));
            if self.deny_referrer.is_some() && request.referrer == self.deny_referrer {
                return Err(denied(ResolutionErrorCode::PolicyDenied, "this incoming edge is denied", request, context, Some(&record.id)));
            }
            Ok(())
        }
    }

    #[test]
    fn resolve_chain_checks_diamond_and_cycle_edges_before_output_deduplication() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './a.mjs'; import './b.mjs';");
        put(root.path(), "a.mjs", "import './shared.mjs';"); put(root.path(), "b.mjs", "import './shared.mjs';");
        put(root.path(), "shared.mjs", "import './app.mjs';"); let r = resolver(root.path());
        let policy = EdgePolicy { deny_referrer: None, calls: RefCell::new(Vec::new()) };
        let outputs = r.resolve_chain(&r.entry_request(), &context(), &policy).unwrap();
        assert_eq!(outputs.len(), 4); assert_eq!(policy.calls.borrow().len(), 6);
        let b = r.registry.lookup(Some(r.registry.entrypoint()), "./b.mjs", RequestStyle::Import).ok().unwrap();
        let denied_edge = EdgePolicy { deny_referrer: Some(b.id().into()), calls: RefCell::new(Vec::new()) };
        let error = r.resolve_chain(&r.entry_request(), &context(), &denied_edge).unwrap_err();
        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(error.request_specifier, "./shared.mjs");
        assert_eq!(denied_edge.calls.borrow().iter().filter(|(_, s)| s == "./shared.mjs").count(), 2);
    }

    #[test]
    fn chain_cannot_expose_partial_outputs_or_unbounded_duplicate_source_bytes() {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.mjs", "import './dep.mjs?1'; import './dep.mjs?2';"); put(root.path(), "dep.mjs", "export const x=1;");
        let mut r = resolver(root.path());
        let first_size = entry_source_size(&r);
        r.chain_source_budget = first_size + "export const x=1;".len();
        let error = r.resolve_chain(&r.entry_request(), &context(), &granted()).unwrap_err();
        assert!(error.message.contains("source budget"));
        assert!(r.resolve(&r.entry_request(), &context(), &granted()).is_ok());
    }
    fn entry_source_size(r: &CapturedEngineResolver) -> usize {
        r.registry.lookup(None, r.registry.entrypoint(), r.registry.entry_style()).ok().unwrap().source().len()
    }

    #[test]
    fn policy_context_is_current_and_oversized_error_evidence_is_bounded() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const secret=1;");
        let r = resolver(root.path()); let policy = ChangingPolicy { allowed: Cell::new(true), calls: Cell::new(0) };
        let updated = ResolutionContext::new("new-trace", "new-decision", "new-policy");
        assert_eq!(r.resolve(&r.entry_request(), &updated, &policy).unwrap().event.policy_id, "new-policy");
        let bad = ResolutionContext::new("x".repeat(100_000), "d", "p");
        let error = r.resolve(&r.entry_request(), &bad, &policy).unwrap_err();
        assert!(error.trace_id.len() <= MAX_CONTEXT_BYTES); assert_eq!(policy.calls.get(), 1);
        assert!(!serde_json::to_string(&error).unwrap().contains("secret"));
    }

    #[test]
    fn replayed_capsule_is_loadable_with_no_live_project_and_identical_record_identity() {
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const retained=7;");
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone(); let encoded = capsule::encode(&graph).unwrap();
        let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let before = live.resolve(&live.entry_request(), &context(), &granted()).unwrap();
        std::fs::rename(root.path().join("app.mjs"), root.path().join("moved.mjs")).unwrap();
        let replay = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        let replay = CapturedEngineResolver::new(replay, &pin).ok().unwrap();
        assert_eq!(before, replay.resolve(&replay.entry_request(), &context(), &granted()).unwrap());
    }

    #[test]
    fn engine_resolver_is_shareable_but_does_not_serialize_private_sources() {
        fn assert_shared<T: Send + Sync>() {} assert_shared::<CapturedEngineResolver>();
        let root = tempfile::tempdir().unwrap(); put(root.path(), "app.mjs", "export const private_source=1;");
        let r = std::sync::Arc::new(resolver(root.path()));
        let copy = std::sync::Arc::clone(&r);
        let out = std::thread::spawn(move || copy.resolve(&copy.entry_request(), &context(), &granted()).unwrap()).join().unwrap();
        assert!(out.module.record.source.contains("private_source"));
        assert!(!serde_json::to_string(r.summary()).unwrap().contains("private_source"));
    }
}