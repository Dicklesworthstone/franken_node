//! Product capture -> sealed registry -> sibling-engine require.resolve.
//! Node's public require.resolve is the reference, not an alternate executor.

use super::*;
use super::registry::{PinnedModuleRegistry, RequestStyle};

fn put(root: &Path, path: &str, source: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, source).unwrap();
}

fn scan_source(source: &str, language: SourceLanguage) -> Scan {
    scan(
        &mut Parser::new(),
        source.as_bytes(),
        language,
        &mut Budget::default(),
    )
    .unwrap()
}

#[test]
fn direct_resolve_spellings_and_typed_wrappers_capture_the_same_require_request() {
    for (language, source) in [
        (SourceLanguage::JavaScript, "require.resolve('./dep.cjs');"),
        (SourceLanguage::JavaScript, "(require.resolve)('./dep.cjs');"),
        (SourceLanguage::JavaScript, "(require).resolve(/* before */ './dep.cjs', /* after */);"),
        (SourceLanguage::JavaScript, "require['resolve']('./dep.cjs');"),
        (SourceLanguage::JavaScript, "require[`resolve`](`./dep.cjs`);"),
        (SourceLanguage::JavaScript, r#"require['res\u006flve']('./dep.cjs');"#),
        (SourceLanguage::TypeScript, "(require.resolve as Resolver)('./dep.cjs');"),
        (SourceLanguage::TypeScript, "(require as Loader).resolve('./dep.cjs');"),
        (SourceLanguage::TypeScript, "require.resolve!('./dep.cjs');"),
        (SourceLanguage::TypeScript, "(require.resolve satisfies Resolver)('./dep.cjs');"),
    ] {
        let (loads, notices, analyzed) = scan_source(source, language);
        assert!(analyzed, "{source}");
        assert!(notices.is_empty(), "{source}: {notices:?}");
        assert_eq!(loads.len(), 1, "{source}");
        assert_eq!(loads[0].kind, LoadKind::Require);
        assert_eq!(loads[0].specifier.as_deref(), Some("./dep.cjs"));
        assert!(!loads[0].type_only);
    }
}

#[test]
fn resolve_options_are_not_silently_resolved_from_the_importer_directory() {
    let root = tempfile::tempdir().unwrap();
    for source in [
        "require.resolve('./dep.cjs', { paths: ['elsewhere'] });",
        "require.resolve('./dep.cjs', {});",
        "require.resolve('./dep.cjs', undefined);",
        "require.resolve('./dep.cjs', ...options);",
    ] {
        put(root.path(), "app.cjs", source);
        // Even an existing first-argument target must not acquire a guessed route.
        put(root.path(), "dep.cjs", "throw new Error('not a default-path request');");
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved, "{source}");
        assert_eq!(captured.report().edges.len(), 1);
        assert_eq!(captured.report().edges[0].state, EdgeState::NonLiteral);
        assert!(captured.report().edges[0].specifier.is_none());
        assert!(captured.report().diagnostics.iter()
            .any(|notice| notice.code == "REQUIRE_RESOLVE_OPTIONS"));
        assert!(!captured.report().probes.iter().any(|probe| probe.path == "dep.cjs"));
    }
    let (loads, notices, _) = scan_source(
        "require.resolve('./dep.cjs', require('./options.cjs'));",
        SourceLanguage::JavaScript,
    );
    assert_eq!(loads.len(), 2);
    assert!(loads[0].specifier.is_none());
    assert_eq!(loads[1].specifier.as_deref(), Some("./options.cjs"));
    assert_eq!(notices[0].code, "REQUIRE_RESOLVE_OPTIONS");
}

#[test]
fn indirect_or_mutated_resolve_members_and_shadowed_loaders_stay_incomplete() {
    for source in [
        "const resolve = require.resolve; resolve('./dep.cjs');",
        "const { resolve } = require; resolve('./dep.cjs');",
        "require[name]('./dep.cjs');",
        "require['res' + 'olve']('./dep.cjs');",
        "require.resolve.call(null, './dep.cjs');",
        "require.resolve.paths('pkg');",
        "(0, require.resolve)('./dep.cjs');",
        "module.require.resolve('./dep.cjs');",
        "function f(require) { return require.resolve('./dep.cjs'); }",
        "require.resolve = replacement; require.resolve('./dep.cjs');",
    ] {
        let (_, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}");
        assert!(notices.iter().any(|notice| notice.code == "INDIRECT_REQUIRE"),
            "must not infer loader identity for {source}: {notices:?}");
    }
    for source in ["require.resolve(name);", "require.resolve();", "require.resolve(...names);"] {
        let (loads, _, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}");
        assert_eq!(loads.len(), 1);
        assert!(loads[0].specifier.is_none());
    }
}

#[test]
fn resolve_routes_preserve_conditions_encapsulation_pins_and_capsule_replay() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", "require.resolve('dual'); require('dual'); require.resolve('./dep.cjs');");
    put(root.path(), "dep.cjs", "module.exports=7;");
    put(root.path(), "node_modules/dual/package.json",
        r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#);
    put(root.path(), "node_modules/dual/right.cjs", "module.exports=42;");
    put(root.path(), "node_modules/dual/wrong.mjs", "export default 0;");
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(captured.report().fully_resolved);
    assert_eq!(captured.report().edges.len(), 3);
    assert_eq!(captured.report().modules.len(), 3);
    assert_eq!(captured.report().edges[0].target, captured.report().edges[1].target);
    assert!(captured.report().edges.iter().all(|edge|
        edge.kind == LoadKind::Require && edge.deferred_or_conditional
        && edge.conditions == ResolutionMode::Require.default_conditions()));
    assert!(!captured.report().probes.iter().any(|probe| probe.path.ends_with("wrong.mjs")));
    let pin = captured.report().input_hash.clone();
    let capsule = capsule::encode(&captured).unwrap();
    put(root.path(), "node_modules/dual/right.cjs", "throw new Error('live bytes');");
    let replayed = capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
    assert_eq!(replayed.report(), captured.report());
    let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
    assert_eq!(registry.summary().routes, 2);
    let target = registry.lookup(Some(registry.entrypoint()), "dual", RequestStyle::Require).unwrap();
    assert_eq!(target.origin().path, "node_modules/dual/right.cjs");
    assert_eq!(target.source(), "module.exports=42;");
    for (specifier, style) in [
        ("dual", RequestStyle::Import),
        ("node_modules/dual/right.cjs", RequestStyle::Require),
        (target.id(), RequestStyle::Require),
        ("./not-captured.cjs", RequestStyle::Require),
    ] {
        assert_eq!(registry.lookup(Some(registry.entrypoint()), specifier, style)
            .err().unwrap().code, "ERR_MODULE_REGISTRY_ROUTE");
    }
    let changed = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert_eq!(PinnedModuleRegistry::new(changed, &pin).err().unwrap().code,
        "ERR_MODULE_REGISTRY_PIN_MISMATCH");
}

#[test]
fn resolve_requests_keep_missing_target_path_safety_and_resource_failures() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", "require.resolve('./missing.cjs');");
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(!captured.report().fully_resolved);
    assert_eq!(captured.report().edges[0].state, EdgeState::Unresolved);
    let pin = captured.report().input_hash.clone();
    assert_eq!(PinnedModuleRegistry::new(captured, &pin).err().unwrap().code,
        "ERR_MODULE_REGISTRY_INCOMPLETE");
    put(root.path(), "app.cjs", "require.resolve('../outside.cjs');");
    assert_eq!(capture(root.path(), "app.cjs", GraphOptions::default()).err().unwrap().code,
        "ERR_MODULE_OUTSIDE_PROJECT");
    let source = "require.resolve('./dep.cjs');".repeat(MAX_SITES + 1);
    assert_eq!(scan(&mut Parser::new(), source.as_bytes(), SourceLanguage::JavaScript,
        &mut Budget::default()).unwrap_err().code, "ERR_MODULE_GRAPH_LIMIT");
}

#[test]
fn resolve_only_capture_does_not_claim_arbitrary_asset_or_dynamic_reload_support() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", "require.resolve('./addon.node');");
    put(root.path(), "addon.node", "not a supported source module");
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(!captured.report().fully_resolved);
    assert!(captured.report().diagnostics.iter().any(|d| d.code == "UNSUPPORTED_MODULE_FORMAT"));
    // Resolve's returned filename is not a new literal/importer route permit.
    let (loads, _, _) = scan_source("require(require.resolve('./dep.cjs'));", SourceLanguage::JavaScript);
    assert_eq!(loads.len(), 2);
    assert!(loads[0].specifier.is_none());
    assert_eq!(loads[1].specifier.as_deref(), Some("./dep.cjs"));
}

#[cfg(feature = "engine")]
mod native {
    use super::*;
    use super::super::engine_resolver::CapturedEngineResolver;
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::LaneChoice;
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
    };
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, ModulePolicyHook, ModuleRecord, ModuleRequest, ModuleResolver,
        ResolutionContext, ResolutionResult,
    };
    use frankenengine_engine::runtime_config::RuntimeConfig;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn policy() -> CapabilityPolicyHook {
        CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin,
        ]))
    }

    fn context() -> ResolutionContext {
        ResolutionContext::new("resolve-trace", "resolve-decision", "resolve-policy")
    }

    fn engine(lane: LaneChoice) -> ExecutionOrchestrator {
        ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig {
                force_lane: Some(lane), parse_goal: ParseGoal::Script, commonjs_entry: true,
                ..OrchestratorConfig::default()
            },
            RuntimeConfig::default(),
        ).unwrap()
    }

    fn package() -> ExtensionPackage {
        ExtensionPackage {
            extension_id: "captured-require-resolve".into(),
            source: "throw new Error('uncaptured entry was executed');".into(),
            source_file: Some("/unopened/resolve-entry.cjs".into()),
            module_root: None,
            capabilities: vec!["module_load".into(), "builtin".into()],
            version: "1.0.0".into(), metadata: BTreeMap::new(),
        }
    }

    const ENTRY: &str = r#"
console.log('resolved', require.resolve('fixture'));
console.log('still-unloaded');
console.log('root', require.resolve('dual'));
const first = require('fixture');
const second = require('fixture');
console.log('same', first === second, first.answer);
console.log('builtin', require.resolve('buffer'), require.resolve('node:buffer'));
"#;
    const FIXTURE: &str = r#"
console.log('package-origin', __filename);
console.log('nested', require.resolve('dual'));
console.log('json', require.resolve('./payload.json'));
module.exports = { answer: 42 };
"#;

    #[test]
    fn native_resolve_uses_frozen_npm_origins_without_evaluation_or_live_files() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("project with spaces");
        put(&root, "app.cjs", ENTRY);
        put(&root, "node_modules/fixture/package.json", r#"{"main":"index.cjs"}"#);
        put(&root, "node_modules/fixture/index.cjs", FIXTURE);
        put(&root, "node_modules/fixture/payload.json", r#"{"answer":42}"#);
        for base in ["node_modules/dual", "node_modules/fixture/node_modules/dual"] {
            put(&root, &format!("{base}/package.json"),
                r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#);
            put(&root, &format!("{base}/right.cjs"), "throw new Error('resolve must not evaluate');");
            put(&root, &format!("{base}/wrong.mjs"), "throw new Error('wrong conditions');");
        }
        let captured = capture(&root, "app.cjs", GraphOptions::default()).unwrap();
        // Builtin terminal requirements remain explicit capture evidence.
        assert!(!captured.report().fully_resolved);
        assert!(captured.report().diagnostics.is_empty());
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        std::fs::rename(root.join("node_modules"), root.join("hidden_packages")).unwrap();
        put(&root, "node_modules/fixture/index.cjs", "throw new Error('live files reopened');");
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            assert_eq!(captured.report(), replayed.report());
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            let policy = Arc::new(policy());
            let entry = resolver.resolve(&resolver.entry_request(), &context(), policy.as_ref()).unwrap();
            let installed = resolver.execution_resolver(&root, policy).unwrap();
            let result = engine(lane).execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect("real sibling engine resolves the product-captured npm graph");
            assert_eq!(result.console_output.iter().map(|line| line.message.clone()).collect::<Vec<_>>(), [
                format!("resolved {}", root.join("node_modules/fixture/index.cjs").display()),
                "still-unloaded".into(),
                format!("root {}", root.join("node_modules/dual/right.cjs").display()),
                format!("package-origin {}", root.join("node_modules/fixture/index.cjs").display()),
                format!("nested {}", root.join("node_modules/fixture/node_modules/dual/right.cjs").display()),
                format!("json {}", root.join("node_modules/fixture/payload.json").display()),
                "same true 42".into(),
                "builtin buffer node:buffer".into(),
            ], "{lane:?}");
        }
    }

    struct RevokeSecondResolve(AtomicUsize);

    impl ModulePolicyHook for RevokeSecondResolve {
        fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord,
            context: &ResolutionContext) -> ResolutionResult<()> {
            let mut policy = policy();
            if request.specifier == "./dep.cjs" && self.0.fetch_add(1, Ordering::SeqCst) > 0 {
                policy.denied_specifiers.insert(request.specifier.clone());
            }
            policy.authorize(request, record, context)
        }
    }

    #[test]
    fn native_resolve_rechecks_policy_after_a_cached_success() {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", "console.log(require.resolve('./dep.cjs')); require.resolve('./dep.cjs'); console.log('must not reach');");
            put(root.path(), "dep.cjs", "throw new Error('must not evaluate');");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            let changing = Arc::new(RevokeSecondResolve(AtomicUsize::new(0)));
            let entry = resolver.resolve(&resolver.entry_request(), &context(), &policy()).unwrap();
            let installed = resolver.execution_resolver(root.path(), changing.clone()).unwrap();
            let mut engine = engine(lane);
            let failure = engine.execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect_err("cached require.resolve cannot bypass revocation");
            assert!(failure.to_string().contains("closed-world module resolution refused"), "{failure}");
            assert_eq!(changing.0.load(Ordering::SeqCst), 2);
            assert_eq!(engine.last_failed_console_output().iter()
                .map(|line| line.message.clone()).collect::<Vec<_>>(),
                [root.path().join("dep.cjs").display().to_string()]);
        }
    }
}
