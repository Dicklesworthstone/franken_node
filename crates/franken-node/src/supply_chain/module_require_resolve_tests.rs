//! Product capture -> sealed registry -> sibling-engine require.resolve.
//! Node's public require.resolve is the reference, not an alternate executor.

use super::registry::{PinnedModuleRegistry, RequestStyle};
use super::*;

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
fn direct_resolve_spellings_and_typed_wrappers_capture_resolution_only_requests() {
    for (language, source) in [
        (SourceLanguage::JavaScript, "require.resolve('./dep.cjs');"),
        (
            SourceLanguage::JavaScript,
            "(require.resolve)('./dep.cjs');",
        ),
        (
            SourceLanguage::JavaScript,
            "(require).resolve(/* before */ './dep.cjs', /* after */);",
        ),
        (
            SourceLanguage::JavaScript,
            "require['resolve']('./dep.cjs');",
        ),
        (
            SourceLanguage::JavaScript,
            "require['res' + 'olve']('./dep.cjs');",
        ),
        (
            SourceLanguage::JavaScript,
            "require[`resolve`](`./dep.cjs`);",
        ),
        (
            SourceLanguage::JavaScript,
            r#"require['res\u006flve']('./dep.cjs');"#,
        ),
        (
            SourceLanguage::TypeScript,
            "(require.resolve as Resolver)('./dep.cjs');",
        ),
        (
            SourceLanguage::TypeScript,
            "(require as Loader).resolve('./dep.cjs');",
        ),
        (SourceLanguage::TypeScript, "require.resolve!('./dep.cjs');"),
        (
            SourceLanguage::TypeScript,
            "(require.resolve satisfies Resolver)('./dep.cjs');",
        ),
    ] {
        let (loads, notices, analyzed) = scan_source(source, language);
        assert!(analyzed, "{source}");
        assert!(notices.is_empty(), "{source}: {notices:?}");
        assert_eq!(loads.len(), 1, "{source}");
        assert_eq!(loads[0].kind, LoadKind::RequireResolve);
        assert_eq!(loads[0].specifier.as_deref(), Some("./dep.cjs"));
        assert!(!loads[0].type_only);
    }
}

#[test]
fn resolve_options_are_not_silently_resolved_from_the_importer_directory() {
    let root = tempfile::tempdir().unwrap();
    for source in [
        "require.resolve('./dep.cjs', { paths: roots });",
        "require.resolve('./dep.cjs', { get paths() { return ['elsewhere']; } });",
        "require.resolve('./dep.cjs', undefined);",
        "require.resolve('./dep.cjs', ...options);",
    ] {
        put(root.path(), "app.cjs", source);
        // Even an existing first-argument target must not acquire a guessed route.
        put(
            root.path(),
            "dep.cjs",
            "throw new Error('not a default-path request');",
        );
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved, "{source}");
        assert_eq!(captured.report().edges.len(), 1);
        assert_eq!(captured.report().edges[0].state, EdgeState::NonLiteral);
        assert!(captured.report().edges[0].specifier.is_none());
        assert!(
            captured
                .report()
                .diagnostics
                .iter()
                .any(|notice| notice.code == "REQUIRE_RESOLVE_OPTIONS")
        );
        assert!(
            !captured
                .report()
                .probes
                .iter()
                .any(|probe| probe.path == "dep.cjs")
        );
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
        "const resolve = require[member]; resolve('./dep.cjs');",
        "const { resolve = fallback } = require; resolve('./dep.cjs');",
        "require[name]('./dep.cjs');",
        "require['res' + name]('./dep.cjs');",
        "require.resolve.call(null, './dep.cjs');",
        "const paths=require.resolve.paths; paths('pkg');",
        "(0, require.resolve)('./dep.cjs');",
        "module.require.resolve('./dep.cjs');",
        "function f(require) { return require.resolve('./dep.cjs'); }",
        "require.resolve = replacement; require.resolve('./dep.cjs');",
    ] {
        let (_, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}");
        assert!(
            notices
                .iter()
                .any(|notice| notice.code == "INDIRECT_REQUIRE"),
            "must not infer loader identity for {source}: {notices:?}"
        );
    }
    for source in [
        "require.resolve(name);",
        "require.resolve();",
        "require.resolve(...names);",
    ] {
        let (loads, _, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}");
        assert_eq!(loads.len(), 1);
        assert!(loads[0].specifier.is_none());
    }
}

#[test]
fn resolve_routes_preserve_conditions_encapsulation_pins_and_capsule_replay() {
    let root = tempfile::tempdir().unwrap();
    put(
        root.path(),
        "app.cjs",
        "require.resolve('dual'); require('dual'); require.resolve('./dep.cjs');",
    );
    put(root.path(), "dep.cjs", "module.exports=7;");
    put(
        root.path(),
        "node_modules/dual/package.json",
        r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#,
    );
    put(
        root.path(),
        "node_modules/dual/right.cjs",
        "module.exports=42;",
    );
    put(
        root.path(),
        "node_modules/dual/wrong.mjs",
        "export default 0;",
    );
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(captured.report().fully_resolved);
    assert_eq!(captured.report().edges.len(), 3);
    assert_eq!(captured.report().modules.len(), 2);
    assert_eq!(captured.report().resolution_targets.len(), 2);
    assert_eq!(
        captured.report().edges[0].target,
        captured.report().edges[1].target
    );
    assert_eq!(
        captured
            .report()
            .edges
            .iter()
            .map(|edge| edge.kind)
            .collect::<Vec<_>>(),
        [
            LoadKind::RequireResolve,
            LoadKind::Require,
            LoadKind::RequireResolve
        ]
    );
    assert!(
        captured
            .report()
            .edges
            .iter()
            .all(|edge| edge.deferred_or_conditional
                && edge.conditions == ResolutionMode::Require.default_conditions())
    );
    assert!(
        !captured
            .report()
            .probes
            .iter()
            .any(|probe| probe.path.ends_with("wrong.mjs"))
    );
    let pin = captured.report().input_hash.clone();
    let capsule = capsule::encode(&captured).unwrap();
    put(
        root.path(),
        "node_modules/dual/right.cjs",
        "throw new Error('live bytes');",
    );
    let replayed = capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
    assert_eq!(replayed.report(), captured.report());
    let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
    assert_eq!(registry.summary().routes, 1);
    assert_eq!(registry.summary().resolution_routes, 2);
    let target = registry
        .lookup(Some(registry.entrypoint()), "dual", RequestStyle::Require)
        .unwrap();
    assert_eq!(target.origin().path, "node_modules/dual/right.cjs");
    assert_eq!(target.source(), "module.exports=42;");
    assert_eq!(
        registry
            .lookup_resolution(Some(registry.entrypoint()), "dual")
            .unwrap()
            .id(),
        target.id()
    );
    let metadata = registry
        .lookup_resolution(Some(registry.entrypoint()), "./dep.cjs")
        .unwrap();
    assert_eq!(metadata.origin().path, "dep.cjs");
    assert!(
        registry
            .lookup(
                Some(registry.entrypoint()),
                "./dep.cjs",
                RequestStyle::Require
            )
            .is_err()
    );
    assert!(
        registry
            .lookup(
                Some(registry.entrypoint()),
                "dual",
                RequestStyle::RequireResolve
            )
            .is_err()
    );
    for (specifier, style) in [
        ("dual", RequestStyle::Import),
        ("node_modules/dual/right.cjs", RequestStyle::Require),
        (target.id(), RequestStyle::Require),
        ("./not-captured.cjs", RequestStyle::Require),
    ] {
        assert_eq!(
            registry
                .lookup(Some(registry.entrypoint()), specifier, style)
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_REGISTRY_ROUTE"
        );
    }
    let changed = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert_eq!(
        PinnedModuleRegistry::new(changed, &pin).err().unwrap().code,
        "ERR_MODULE_REGISTRY_PIN_MISMATCH"
    );
}

#[test]
fn resolve_requests_keep_missing_target_path_safety_and_resource_failures() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", "require.resolve('./missing.cjs');");
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(!captured.report().fully_resolved);
    assert_eq!(captured.report().edges[0].state, EdgeState::Unresolved);
    let pin = captured.report().input_hash.clone();
    let registry = PinnedModuleRegistry::new(captured, &pin).unwrap();
    assert_eq!(registry.summary().missing_routes, 0);
    assert_eq!(registry.summary().missing_resolution_routes, 1);
    assert_eq!(
        registry
            .lookup_resolution(Some(registry.entrypoint()), "./missing.cjs")
            .err()
            .unwrap()
            .code,
        "MODULE_NOT_FOUND"
    );
    assert!(
        registry
            .lookup(
                Some(registry.entrypoint()),
                "./missing.cjs",
                RequestStyle::Require
            )
            .is_err()
    );
    put(root.path(), "app.cjs", "require.resolve('../outside.cjs');");
    assert_eq!(
        capture(root.path(), "app.cjs", GraphOptions::default())
            .err()
            .unwrap()
            .code,
        "ERR_MODULE_OUTSIDE_PROJECT"
    );
    let source = "require.resolve('./dep.cjs');".repeat(MAX_SITES + 1);
    assert_eq!(
        scan(
            &mut Parser::new(),
            source.as_bytes(),
            SourceLanguage::JavaScript,
            &mut Budget::default()
        )
        .unwrap_err()
        .code,
        "ERR_MODULE_GRAPH_LIMIT"
    );
}

#[test]
fn resolve_only_assets_keep_bytes_pinned_without_parsing_or_dependency_traversal() {
    let root = tempfile::tempdir().unwrap();
    let assets: &[(&str, &[u8])] = &[
        ("style.css", b"\xff\0body { color: red; }"),
        ("addon.node", b"\x7fELF\xff\0"),
        ("module.wasm", b"\0asm\xff"),
        ("invalid.json", b"{invalid JSON"),
        ("invalid.cjs", b"function { invalid JavaScript"),
        ("types.d.ts", b"interface Value { answer: number }"),
        (
            "transitive.cjs",
            b"require('../outside.cjs'); require('not-installed');",
        ),
    ];
    let mut source = String::from("const load=require;\n");
    for (name, bytes) in assets {
        std::fs::write(root.path().join(name), bytes).unwrap();
        source.push_str(&format!("load.resolve('./{name}');\n"));
    }
    source.push_str("if (false) { require.resolve('./addon.node'); }\n");
    put(root.path(), "app.cjs", &source);
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(captured.report().fully_resolved, "{:?}", captured.report());
    assert_eq!(captured.report().modules.len(), 1);
    assert_eq!(captured.report().resolution_targets.len(), assets.len());
    assert_eq!(captured.report().edges.len(), assets.len() + 1);
    assert!(
        captured
            .report()
            .edges
            .iter()
            .all(|edge| edge.kind == LoadKind::RequireResolve
                && edge.state == EdgeState::Resolved
                && edge.deferred_or_conditional)
    );
    assert!(
        !captured
            .report()
            .probes
            .iter()
            .any(|probe| probe.path.contains("node_modules") || probe.path.contains("outside.cjs"))
    );
    for target in &captured.report().resolution_targets {
        let original = assets
            .iter()
            .find(|(name, _)| *name == target.id.path)
            .unwrap()
            .1;
        assert_eq!(target.content_bytes, original.len());
        assert_eq!(target.content_sha256, hex::encode(Sha256::digest(original)));
        assert!(captured.source_bytes(&target.id).is_none());
    }
    let pin = captured.report().input_hash.clone();
    let encoded = capsule::encode(&captured).unwrap();
    for (name, _) in assets {
        std::fs::write(root.path().join(name), b"changed after capture").unwrap();
    }
    assert_ne!(
        capture(root.path(), "app.cjs", GraphOptions::default())
            .unwrap()
            .report()
            .input_hash,
        pin
    );
    let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
    assert_eq!(replayed.report(), captured.report());
    assert_eq!(capsule::encode(&replayed).unwrap().bytes(), encoded.bytes());
    let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
    assert_eq!(registry.modules().count(), 1);
    assert_eq!(registry.resolutions().count(), assets.len());
    for (name, _) in assets {
        let request = format!("./{name}");
        let target = registry
            .lookup_resolution(Some(registry.entrypoint()), &request)
            .unwrap();
        assert_eq!(target.origin().path, *name);
        assert!(
            registry
                .lookup(Some(registry.entrypoint()), &request, RequestStyle::Require)
                .is_err()
        );
        assert!(
            registry
                .lookup_resolution(Some(registry.entrypoint()), target.id())
                .is_err()
        );
    }
}

#[test]
fn resolution_only_files_do_not_read_package_format_or_grant_dynamic_loads() {
    let root = tempfile::tempdir().unwrap();
    put(
        root.path(),
        "app.cjs",
        "require.resolve('./nested/asset.js');",
    );
    put(
        root.path(),
        "nested/package.json",
        "{invalid package config",
    );
    put(root.path(), "nested/asset.js", "not JavaScript");
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(captured.report().fully_resolved);
    assert_eq!(captured.report().modules.len(), 1);
    assert_eq!(captured.report().resolution_targets.len(), 1);
    assert!(
        !captured
            .report()
            .probes
            .iter()
            .any(|probe| probe.path == "nested/package.json")
    );

    // Resolve's returned filename is not a new literal/importer route permit.
    let (loads, _, _) = scan_source(
        "require(require.resolve('./dep.cjs'));",
        SourceLanguage::JavaScript,
    );
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[0].kind, LoadKind::Require);
    assert!(loads[0].specifier.is_none());
    assert_eq!(loads[1].kind, LoadKind::RequireResolve);
    assert_eq!(loads[1].specifier.as_deref(), Some("./dep.cjs"));
    put(
        root.path(),
        "app.cjs",
        "require(require.resolve('./nested/asset.js'));",
    );
    let dynamic = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert_eq!(dynamic.report().resolution_targets.len(), 1);
    assert!(
        dynamic
            .report()
            .edges
            .iter()
            .any(|edge| edge.kind == LoadKind::Require && edge.state == EdgeState::NonLiteral)
    );
    let pin = dynamic.report().input_hash.clone();
    assert_eq!(
        PinnedModuleRegistry::new(dynamic, &pin).err().unwrap().code,
        "ERR_MODULE_REGISTRY_INCOMPLETE"
    );
}

#[test]
fn resolution_and_loading_have_independent_order_invariant_source_authority() {
    let root = tempfile::tempdir().unwrap();
    put(
        root.path(),
        "shared.custom",
        "module.exports=require('./leaf.cjs');",
    );
    put(root.path(), "leaf.cjs", "module.exports=42;");
    for source in [
        "require.resolve('./shared.custom'); require('./shared.custom');",
        "require('./shared.custom'); require.resolve('./shared.custom');",
    ] {
        put(root.path(), "app.cjs", source);
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved, "{:?}", captured.report());
        assert_eq!(captured.report().modules.len(), 3);
        assert_eq!(captured.report().resolution_targets.len(), 1);
        let target = &captured.report().resolution_targets[0];
        assert_eq!(target.id.path, "shared.custom");
        assert_eq!(
            captured.source_bytes(&target.id),
            Some(b"module.exports=require('./leaf.cjs');".as_slice())
        );
        assert!(
            captured
                .report()
                .edges
                .iter()
                .any(|edge| edge.importer == target.id
                    && edge.specifier.as_deref() == Some("./leaf.cjs"))
        );
    }
    for source in [
        "require.resolve('./addon.node'); require('./addon.node');",
        "require('./addon.node'); require.resolve('./addon.node');",
    ] {
        put(root.path(), "app.cjs", source);
        std::fs::write(root.path().join("addon.node"), b"\x7fELF\xff").unwrap();
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved);
        assert_eq!(captured.report().resolution_targets.len(), 1);
        assert!(
            captured
                .report()
                .diagnostics
                .iter()
                .any(|notice| notice.code == "UNSUPPORTED_MODULE_FORMAT")
        );
    }
}

#[test]
fn metadata_and_loaded_targets_share_the_existing_module_bound() {
    let root = tempfile::tempdir().unwrap();
    let mut source = String::new();
    for index in 0..MAX_MODULES - 1 {
        let name = format!("target-{index}.cjs");
        put(root.path(), &name, "module.exports=1;");
        source.push_str(&format!("require.resolve('./{name}');\n"));
    }
    source.push_str("require('./target-0.cjs');\n");
    put(root.path(), "app.cjs", &source);
    let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(captured.report().fully_resolved);
    assert_eq!(captured.report().modules.len(), 2);
    assert_eq!(captured.report().resolution_targets.len(), MAX_MODULES - 1);
    put(root.path(), "extra.cjs", "module.exports=2;");
    for extra in ["require('./extra.cjs');", "require.resolve('./extra.cjs');"] {
        put(root.path(), "app.cjs", &format!("{source}{extra}"));
        assert_eq!(
            capture(root.path(), "app.cjs", GraphOptions::default())
                .err()
                .unwrap()
                .code,
            "ERR_MODULE_GRAPH_LIMIT"
        );
    }
}


#[test]
fn commonjs_search_capture_keeps_order_singleton_probes_and_lookup_purpose() {
    let source = r#"
const second = 'two';
require.resolve('pkg', {paths: ['one', second]});
require.resolve('./asset.cjs', {paths: ['one', second]});
require.resolve('pkg', {paths: []});
require.resolve('pkg', {});
require.resolve.paths('pkg');
"#;
    let (loads, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed && notices.is_empty(), "{notices:?}");
    assert_eq!(loads.len(), 6);
    let roots = |load: &Load| load.search_paths.as_ref().map(|roots| {
        roots.iter().map(|root| root.text.clone()).collect::<Vec<_>>()
    });
    assert_eq!(roots(&loads[0]), Some(vec!["one".into(), "two".into()]));
    assert_eq!(roots(&loads[1]), Some(vec!["one".into()]));
    assert_eq!(roots(&loads[2]), Some(vec!["two".into()]));
    assert_eq!(roots(&loads[3]), Some(Vec::new()));
    assert_eq!(roots(&loads[4]), None);
    assert!(loads[5].lookup_paths);
    assert!(loads.iter().all(|load| load.kind == LoadKind::RequireResolve));
}

#[test]
fn commonjs_search_refuses_mutable_ambiguous_or_excessive_option_authority() {
    for source in [
        "const roots=['one']; require.resolve('pkg',{paths:roots});",
        "require.resolve('pkg',{paths:['one',,'two']});",
        "require.resolve('pkg',{paths:[...roots]});",
        "require.resolve('pkg',{paths:['one'],paths:['two']});",
        "require.resolve('pkg',{['paths']:['one']});",
        "require.resolve('pkg',{paths:['one'],extra:true});",
        "function f(__dirname){return require.resolve('pkg',{paths:[__dirname]});}",
        "__dirname='elsewhere'; require.resolve('pkg',{paths:[__dirname]});",
        "arguments[4]='elsewhere'; require.resolve('pkg',{paths:[__dirname]});",
        "require.resolve('pkg',{paths:[__dirname+'suffix']});",
        "import.meta.dirname='elsewhere'; require.resolve('pkg',{paths:[import.meta.dirname]});",
    ] {
        let (_, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed && !notices.is_empty(), "unproved paths admitted: {source}");
    }
    let source = format!(
        "require.resolve('pkg',{{paths:[{}]}});",
        vec!["'root'"; super::super::MAX_COMMONJS_SEARCH_PATHS + 1].join(","),
    );
    assert!(scan_source(&source, SourceLanguage::JavaScript).1
        .iter().any(|notice| notice.code == "REQUIRE_RESOLVE_OPTIONS"));
}

#[test]
fn commonjs_search_routes_are_pinned_relocatable_and_never_load_authority() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", r#"
require.resolve('pkg',{paths:['one','two']});
require.resolve('pkg',{paths:['two','one']});
require.resolve('ancestor',{paths:['one','two']});
require.resolve('./asset.cjs',{paths:['missing','two']});
require.resolve('pkg',{paths:[]});
require.resolve('./asset.cjs',{paths:[]});
require.resolve.paths('pkg');
require.resolve.paths('./asset.cjs');
"#);
    for directory in ["one", "two", ""] {
        let prefix = if directory.is_empty() { String::new() } else { format!("{directory}/") };
        put(root.path(), &format!("{prefix}node_modules/pkg/package.json"),
            r#"{"exports":"./index.cjs"}"#);
        put(root.path(), &format!("{prefix}node_modules/pkg/index.cjs"),
            "throw new Error('metadata must not evaluate');");
    }
    put(root.path(), "node_modules/ancestor/index.js", "first-root ancestor wins");
    put(root.path(), "two/node_modules/ancestor/index.js", "later-root candidate must not win");
    put(root.path(), "two/asset.cjs", "throw new Error('asset must not evaluate');");
    put(root.path(), "asset.cjs", "throw new Error('empty roots must not use default');");
    let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().diagnostics.is_empty());
    assert_eq!(graph.report().modules.len(), 1);
    let pin = graph.report().input_hash.clone();
    let encoded = capsule::encode(&graph).unwrap();
    put(root.path(), "two/asset.cjs", "live mutation");
    put(root.path(), "missing/asset.cjs", "new file after capture");
    let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
    assert_eq!(graph.report(), replayed.report());
    let registry = PinnedModuleRegistry::new(replayed, &pin).ok().unwrap();
    let caller = Some(registry.entrypoint());
    for (paths, expected) in [
        (vec!["one".into(), "two".into()], "one/node_modules/pkg/index.cjs"),
        (vec!["two".into(), "one".into()], "two/node_modules/pkg/index.cjs"),
    ] {
        assert_eq!(registry.lookup_resolution_from_paths(caller, "pkg", &paths)
            .unwrap().origin().path, expected);
    }
    assert_eq!(registry.lookup_resolution_from_paths(caller, "./asset.cjs", &["two".into()])
        .unwrap().origin().path, "two/asset.cjs");
    assert_eq!(registry.lookup_resolution_from_paths(caller, "ancestor", &["one".into(), "two".into()])
        .unwrap().origin().path, "node_modules/ancestor/index.js");
    for (request, paths) in [
        ("pkg", Vec::new()),
        ("./asset.cjs", Vec::new()),
        ("./asset.cjs", vec!["missing".into()]),
    ] {
        assert_eq!(registry.lookup_resolution_from_paths(caller, request, &paths)
            .err().unwrap().code, "MODULE_NOT_FOUND");
    }
    for paths in [vec!["one".into()], vec!["two".into(), "one".into(), "two".into()]] {
        assert_eq!(registry.lookup_resolution_from_paths(caller, "pkg", &paths)
            .err().unwrap().code, "ERR_MODULE_REGISTRY_ROUTE");
    }
    assert_eq!(registry.lookup_resolution(caller, "pkg").err().unwrap().code,
        "ERR_MODULE_REGISTRY_ROUTE");
    assert_eq!(registry.lookup(caller, "pkg", RequestStyle::Require).err().unwrap().code,
        "ERR_MODULE_REGISTRY_ROUTE");
    match registry.lookup_paths(caller, "pkg").unwrap() {
        registry::RegisteredLookupPaths::Directories(paths) => assert_eq!(paths, ["node_modules"]),
        _ => panic!("package lookup directories are not builtin null"),
    }
    match registry.lookup_paths(caller, "./asset.cjs").unwrap() {
        registry::RegisteredLookupPaths::Directories(paths) => assert_eq!(paths, [""]),
        _ => panic!("relative lookup requires the caller directory"),
    }
    assert!(registry.lookup_paths(caller, "uncaptured").is_err());
    assert!(registry.lookup_paths(Some("foreign-referrer"), "pkg").is_err());
}

#[test]
fn commonjs_search_keeps_original_package_imports_and_self_scope_with_empty_roots() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "owner/app.cjs", r#"
require.resolve('#local',{paths:['other']});
require.resolve('owner',{paths:['other']});
require.resolve('#local',{paths:[]});
require.resolve('owner',{paths:[]});
"#);
    put(root.path(), "owner/package.json",
        r##"{"name":"owner","imports":{"#local":"./private.cjs"},"exports":"./self.cjs"}"##);
    put(root.path(), "owner/private.cjs", "private asset");
    put(root.path(), "owner/self.cjs", "self asset");
    put(root.path(), "other/package.json",
        r##"{"name":"owner","imports":{"#local":"./wrong.cjs"},"exports":"./wrong.cjs"}"##);
    put(root.path(), "other/wrong.cjs", "must never select");
    let graph = capture(root.path(), "owner/app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().fully_resolved);
    assert_eq!(graph.report().edges.iter().map(|edge| edge.target.as_ref().unwrap().path.as_str())
        .collect::<Vec<_>>(),
        ["owner/private.cjs", "owner/self.cjs", "owner/private.cjs", "owner/self.cjs"]);
}

#[test]
fn commonjs_search_selected_export_or_main_failure_cannot_fall_through() {
    for manifest in [
        r#"{"exports":"./missing.cjs"}"#,
        r#"{"main":"./missing.cjs"}"#,
        r#"{"exports":{"./other":"./index.cjs"}}"#,
    ] {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", "require.resolve('broken',{paths:['one','two']});");
        put(root.path(), "one/node_modules/broken/package.json", manifest);
        put(root.path(), "two/node_modules/broken/index.js", "alternate must not win");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert_eq!(graph.report().edges[0].state, EdgeState::Unresolved);
        assert!(matches!(graph.report().edges[0].error.as_ref().unwrap().code,
            "MODULE_NOT_FOUND" | "ERR_PACKAGE_PATH_NOT_EXPORTED"));
        assert!(!graph.report().probes.iter()
            .any(|probe| probe.path.starts_with("two/node_modules")));
        let pin = graph.report().input_hash.clone();
        let registry = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
        assert!(registry.lookup_resolution_from_paths(Some(registry.entrypoint()),
            "broken", &["one".into(), "two".into()]).is_err());
    }
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cjs", "require.resolve('./broken',{paths:['one','two']});");
    put(root.path(), "one/broken/package.json", r#"{"main":"./missing.cjs"}"#);
    put(root.path(), "two/broken/index.js", "alternate must not win");
    let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().edges.iter().any(|edge| edge.error.as_ref()
        .is_some_and(|error| error.code == "ERR_REQUIRE_RESOLVE_SEARCH_TERMINAL")));
    let pin = graph.report().input_hash.clone();
    assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
        "ERR_MODULE_REGISTRY_INCOMPLETE");
}

#[test]
fn commonjs_search_roots_cannot_escape_or_enter_operator_state() {
    let root = tempfile::tempdir().unwrap();
    for path in ["../outside", "/outside", ".franken-node", ".git", ".beads"] {
        put(root.path(), "app.cjs", &format!(
            "require.resolve('pkg',{{paths:[{path:?}]}});"
        ));
        let failure = capture(root.path(), "app.cjs", GraphOptions::default()).err().unwrap();
        assert!(matches!(failure.code,
            "ERR_MODULE_OUTSIDE_PROJECT" | "ERR_INVALID_MODULE_SPECIFIER"), "{path}: {failure:?}");
    }
}

#[test]
fn commonjs_lookup_builtin_classification_requires_the_engine_inventory() {
    let root = tempfile::tempdir().unwrap();
    for request in ["fs", "node:fs", "node:franken_missing"] {
        put(root.path(), "app.cjs", &format!("require.resolve.paths({request:?});"));
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_INCOMPLETE");
    }
}

#[test]
fn commonjs_lookup_directories_stop_at_project_root_and_skip_node_modules_parent() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "node_modules/pkg/lib/app.cjs",
        "require.resolve.paths('absent'); require.resolve.paths('.hidden-package'); require.resolve.paths('..');");
    let graph = capture(root.path(), "node_modules/pkg/lib/app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().fully_resolved);
    assert!(graph.report().resolution_targets.is_empty());
    let pin = graph.report().input_hash.clone();
    let registry = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
    for request in ["absent", ".hidden-package"] {
        match registry.lookup_paths(Some(registry.entrypoint()), request).unwrap() {
            registry::RegisteredLookupPaths::Directories(paths) => assert_eq!(paths, [
                "node_modules/pkg/lib/node_modules", "node_modules/pkg/node_modules", "node_modules",
            ]),
            _ => panic!("ordinary package lookup cannot be null"),
        }
    }
    match registry.lookup_paths(Some(registry.entrypoint()), "..").unwrap() {
        registry::RegisteredLookupPaths::Directories(paths) =>
            assert_eq!(paths, ["node_modules/pkg/lib"]),
        _ => panic!("relative lookup cannot be null"),
    }
}

#[test]
fn dirname_requests_capture_exact_purpose_and_importer_without_relative_aliases() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "nested/app.cjs", r#"
const suffix='/dep.cjs';
const load=require;
load(__dirname + suffix);
load.resolve(__dirname + '/asset.txt');
try { require(__dirname + '/missing.cjs'); } catch (error) {}
"#);
    put(root.path(), "nested/dep.cjs", "module.exports=42;");
    put(root.path(), "nested/asset.txt", "this is not JavaScript");
    let graph = capture(root.path(), "nested/app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().diagnostics.is_empty());
    assert_eq!(graph.report().modules.len(), 2);
    assert_eq!(graph.report().resolution_targets.len(), 1);
    assert_eq!(graph.report().edges.len(), 3);
    assert!(graph.report().edges.iter().all(|edge| edge.dirname_request));
    let pin = graph.report().input_hash.clone();
    let registry = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
    let entry = registry.entrypoint();
    let dep = registry.lookup_dirname(Some(entry), "./dep.cjs").unwrap();
    assert_eq!(dep.origin().path, "nested/dep.cjs");
    assert_eq!(registry.lookup_dirname_resolution(Some(entry), "./asset.txt").unwrap().origin().path,
        "nested/asset.txt");
    for request in ["./dep.cjs", "./asset.txt", "./missing.cjs"] {
        assert_eq!(registry.lookup(Some(entry), request, RequestStyle::Require).err().unwrap().code,
            "ERR_MODULE_REGISTRY_ROUTE");
        assert_eq!(registry.lookup_resolution(Some(entry), request).err().unwrap().code,
            "ERR_MODULE_REGISTRY_ROUTE");
    }
    assert_eq!(registry.lookup_dirname(Some(entry), "./asset.txt").err().unwrap().code,
        "ERR_MODULE_REGISTRY_ROUTE");
    assert_eq!(registry.lookup_dirname_resolution(Some(entry), "./dep.cjs").err().unwrap().code,
        "ERR_MODULE_REGISTRY_ROUTE");
    assert_eq!(registry.lookup_dirname(Some(dep.id()), "./dep.cjs").err().unwrap().code,
        "ERR_MODULE_REGISTRY_ROUTE");
    assert_eq!(registry.lookup_dirname(Some(entry), "./missing.cjs").err().unwrap().code,
        "MODULE_NOT_FOUND");
}

#[test]
fn dirname_request_capsules_replay_sources_and_absence_after_source_retirement() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("original");
    put(&root, "nested/app.cjs", "require(__dirname+'/dep.cjs'); try { require.resolve(__dirname+'/missing'); } catch(e) {}");
    put(&root, "nested/dep.cjs", "module.exports=42;");
    let graph = capture(&root, "nested/app.cjs", GraphOptions::default()).unwrap();
    let pin = graph.report().input_hash.clone();
    let capsule = capsule::encode(&graph).unwrap();
    std::fs::rename(&root, parent.path().join("retired")).unwrap();
    put(&root, "nested/dep.cjs", "throw new Error('live replacement');");
    put(&root, "nested/missing", "module.exports='must stay missing';");
    let replayed = capsule::replay(capsule.bytes(), capsule.digest()).unwrap();
    assert_eq!(graph.report(), replayed.report());
    let registry = PinnedModuleRegistry::new(replayed, &pin).ok().unwrap();
    assert_eq!(registry.lookup_dirname(Some(registry.entrypoint()), "./dep.cjs").unwrap().source(),
        "module.exports=42;");
    assert_eq!(registry.lookup_dirname_resolution(Some(registry.entrypoint()), "./missing").err().unwrap().code,
        "MODULE_NOT_FOUND");
}

#[test]
fn dirname_requests_reject_mutation_shadowing_escaped_bindings_and_unknown_suffixes() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "dep.cjs", "module.exports=42;");
    for source in [
        "__dirname='/foreign'; require(__dirname+'/dep.cjs');",
        "function f(__dirname){return require(__dirname+'/dep.cjs');}",
        "{ const __dirname='/foreign'; require(__dirname+'/dep.cjs'); }",
        "const {__dirname}=input; require(__dirname+'/dep.cjs');",
        "arguments[4]='/foreign'; require(__dirname+'/dep.cjs');",
        "const args=arguments; require(__dirname+'/dep.cjs');",
        "eval('change()'); require(__dirname+'/dep.cjs');",
        "__dirn\\u0061me='/foreign'; require(__dirname+'/dep.cjs');",
        "let suffix='/dep.cjs'; require(__dirname+suffix);",
        "require(__dirname+suffix); const suffix='/dep.cjs';",
        "require(__dirname+(flag?'/dep.cjs':unknown));",
        "require(__dirname+('x'+sideEffect()));",
        "require.resolve(__dirname+'/dep.cjs',{paths:['elsewhere']});",
        "require.resolve.paths(__dirname+'/dep.cjs');",
        "import(__dirname+'/dep.cjs');",
    ] {
        let (_, _, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}");
        put(root.path(), "app.cjs", source);
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        // An immutable shadow can still yield an exact ordinary string. That
        // observation is not dirname authority: the absolute-path refusal must
        // survive the complete source-closure admission, not merely scanning.
        assert!(PinnedModuleRegistry::new(graph, &pin).is_err(),
            "unproved dirname request acquired executable authority: {source}");
    }
    for source in [
        "const suffix='/dep.cjs'; require(__dirname+suffix);",
        "require.resolve((__dirname) + '/dep.cjs', {});",
        "(require as Loader)((__dirname as string) + ('/dep.cjs' as string));",
    ] {
        let (loads, notices, analyzed) = scan_source(source, SourceLanguage::TypeScript);
        assert!(analyzed && notices.is_empty(), "{source}: {notices:?}");
        assert!(loads.iter().all(|load| load.dirname_request && load.specifier.as_deref()==Some("./dep.cjs")));
    }
    // A block-local variable with this name can still prove an ordinary
    // relative string. Preserve that pre-existing const-expression support
    // without granting the native dirname route for the same target.
    put(root.path(), "app.cjs", "{ const __dirname='./'; require(__dirname+'dep.cjs'); }");
    let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().fully_resolved);
    assert!(!graph.report().edges[0].dirname_request);
    let pin = graph.report().input_hash.clone();
    let registry = PinnedModuleRegistry::new(graph, &pin).ok().unwrap();
    assert!(registry.lookup(Some(registry.entrypoint()), "./dep.cjs", RequestStyle::Require).is_ok());
    assert!(registry.lookup_dirname(Some(registry.entrypoint()), "./dep.cjs").is_err());
}

#[test]
fn dirname_request_paths_cannot_leave_project_or_traverse_operator_state() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "dep.cjs", "module.exports=42;");
    for suffix in ["/../../outside.cjs", "/../../root/dep.cjs"] {
        put(root.path(), "nested/app.cjs", &format!("require(__dirname+'{suffix}');"));
        assert_eq!(capture(root.path(), "nested/app.cjs", GraphOptions::default()).err().unwrap().code,
            "ERR_MODULE_OUTSIDE_PROJECT");
    }
    for suffix in ["/../.franken-node/../dep.cjs", "/../.git/../dep.cjs", "/../bad\\\\dep.cjs"] {
        put(root.path(), "nested/app.cjs", &format!("require(__dirname+'{suffix}');"));
        let graph = capture(root.path(), "nested/app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert!(PinnedModuleRegistry::new(graph, &pin).is_err(), "{suffix}");
    }
    put(root.path(), "nested/app.cjs", "require(__dirname+'/../dep.cjs');");
    let graph = capture(root.path(), "nested/app.cjs", GraphOptions::default()).unwrap();
    assert!(graph.report().fully_resolved);
    assert_eq!(graph.report().edges[0].target.as_ref().unwrap().path, "dep.cjs");
    // The suffix byte bound is checked before publishing any inferred route.
    let source = format!("require(__dirname+'/{}');", "a".repeat(super::super::MAX_PATH));
    let (loads, _, _) = scan_source(&source, SourceLanguage::JavaScript);
    assert!(loads[0].specifier.is_none());
}

#[cfg(feature = "engine")]
mod native {
    use super::super::engine_resolver::CapturedEngineResolver;
    use super::*;
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::LaneChoice;
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
    };
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, ModuleMetadata, ModulePolicyHook, ModuleRecord, ModuleRequest,
        ModuleResolver, ResolutionContext, ResolutionResult,
    };
    use frankenengine_engine::runtime_config::RuntimeConfig;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn policy() -> CapabilityPolicyHook {
        CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ]))
    }

    fn context() -> ResolutionContext {
        ResolutionContext::new("resolve-trace", "resolve-decision", "resolve-policy")
    }

    fn engine(lane: LaneChoice) -> ExecutionOrchestrator {
        ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig {
                force_lane: Some(lane),
                parse_goal: ParseGoal::Script,
                commonjs_entry: true,
                ..OrchestratorConfig::default()
            },
            RuntimeConfig::default(),
        )
        .unwrap()
    }

    fn package() -> ExtensionPackage {
        ExtensionPackage {
            extension_id: "captured-require-resolve".into(),
            source: "throw new Error('uncaptured entry was executed');".into(),
            source_file: Some("/unopened/resolve-entry.cjs".into()),
            module_root: None,
            capabilities: vec!["module_load".into(), "builtin".into()],
            version: "1.0.0".into(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn native_dirname_requests_match_node_and_replay_under_independent_roots() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("original project");
        put(&root, "app.cjs", r#"
const suffix='/pkg';
const first=require(__dirname+suffix);
const second=require(__dirname+'/pkg/index.cjs');
console.log('same',first===second);
console.log('value',first.value);
console.log('asset',require.resolve(__dirname+'/pkg/data.txt'));
try { require(__dirname+'/optional.cjs'); } catch(error) { console.log('absent',error.code); }
"#);
        put(&root, "pkg/package.json", r#"{"main":"index.cjs"}"#);
        put(&root, "pkg/index.cjs", "module.exports={value:require(__dirname+'/../leaf.cjs')};");
        put(&root, "leaf.cjs", "module.exports=42;");
        put(&root, "pkg/data.txt", "this must never be executed");
        let reference = std::process::Command::new("node").arg("app.cjs")
            .current_dir(&root).output().expect("Node reference for dirname requests");
        assert!(reference.status.success(), "{}", String::from_utf8_lossy(&reference.stderr));
        let expected = format!("same true\nvalue 42\nasset {}\nabsent MODULE_NOT_FOUND\n",
            root.join("pkg/data.txt").display());
        assert_eq!(String::from_utf8(reference.stdout).unwrap(), expected);
        let graph = capture(&root, "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        std::fs::rename(&root, parent.path().join("retired source")).unwrap();
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
        for destination in ["relocated first", "relocated second"] {
            let destination = parent.path().join(destination);
            assert!(!destination.exists());
            let expected = expected.replace(root.to_str().unwrap(), destination.to_str().unwrap());
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let policy = Arc::new(policy());
                let entry = resolver.resolve(&resolver.entry_request(), &context(), policy.as_ref()).unwrap();
                let installed = resolver.execution_resolver(&destination, policy).unwrap();
                let output = engine(lane).execute_resolved_entry_with_resolver(&package(), &entry, installed)
                    .expect("captured dirname requests execute through the native resolver");
                let actual = output.console_output.iter().map(|line| line.message.as_str())
                    .collect::<Vec<_>>().join("\n") + "\n";
                assert_eq!(actual, expected, "{lane:?}");
            }
        }
    }

    #[derive(Default)]
    struct DirnamePolicy {
        seen: std::sync::Mutex<Vec<String>>,
        deny: std::sync::atomic::AtomicBool,
    }

    impl ModulePolicyHook for DirnamePolicy {
        fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord, context: &ResolutionContext)
            -> ResolutionResult<()>
        {
            self.seen.lock().unwrap().push(request.specifier.clone());
            let mut policy = policy();
            if self.deny.load(Ordering::SeqCst) {
                policy.denied_specifiers.insert(request.specifier.clone());
            }
            policy.authorize(request, record, context)
        }

        fn authorize_metadata(&self, request: &ModuleRequest, metadata: &ModuleMetadata, context: &ResolutionContext)
            -> ResolutionResult<()>
        {
            self.seen.lock().unwrap().push(request.specifier.clone());
            let mut policy = policy();
            if self.deny.load(Ordering::SeqCst) {
                policy.denied_specifiers.insert(request.specifier.clone());
            }
            policy.authorize_metadata(request, metadata, context)
        }
    }

    #[test]
    fn dirname_engine_routes_keep_original_requests_purposes_roots_and_cached_policy() {
        use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
        use frankenengine_engine::module_resolver::{ImportStyle, ResolutionErrorCode};

        let root = tempfile::tempdir().unwrap();
        put(root.path(), "nested/app.cjs", "require(__dirname+'/dep.cjs'); require.resolve(__dirname+'/asset.txt');");
        put(root.path(), "nested/dep.cjs", "module.exports=42;");
        put(root.path(), "nested/asset.txt", "metadata only");
        let graph = capture(root.path(), "nested/app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        let policy = Arc::new(DirnamePolicy::default());
        let installed = resolver.execution_resolver(root.path(), policy.clone()).unwrap();
        let request = |path: String| ModuleRequest::new(path, ImportStyle::Require)
            .with_referrer(resolver.entry_request().specifier)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        let load = request(root.path().join("nested/dep.cjs").display().to_string());
        let metadata = request(root.path().join("nested/asset.txt").display().to_string());
        let first = installed.resolve_shared(&load, &context()).unwrap();
        let cached = installed.resolve_shared(&load, &context()).unwrap();
        assert!(Arc::ptr_eq(&first.module.record, &cached.module.record));
        assert_eq!(first.module.request_specifier, load.specifier);
        assert_eq!(installed.resolve_metadata(&metadata, &context()).unwrap().module.request_specifier,
            metadata.specifier);
        assert_eq!(*policy.seen.lock().unwrap(),
            vec![load.specifier.clone(), load.specifier.clone(), metadata.specifier.clone()]);
        for other in [
            "./dep.cjs".into(),
            root.path().join("nested/./dep.cjs").display().to_string(),
            root.path().join("nested/../nested/dep.cjs").display().to_string(),
            root.path().join("nested/.franken-node/../dep.cjs").display().to_string(),
            format!("{}-foreign/nested/dep.cjs", root.path().display()),
        ] {
            assert!(installed.resolve_shared(&request(other), &context()).is_err());
        }
        assert!(installed.resolve_shared(&metadata, &context()).is_err());
        assert!(installed.resolve_metadata(&load, &context()).is_err());
        assert!(installed.resolve_require_metadata_from_paths(&metadata, &["nested".into()], &context()).is_err());
        let mut foreign = load.clone();
        foreign.referrer = Some(first.module.record.id.clone());
        assert!(installed.resolve_shared(&foreign, &context()).is_err());
        foreign = load.clone();
        foreign.style = ImportStyle::Import;
        assert!(installed.resolve_shared(&foreign, &context()).is_err());
        assert!(resolver.resolve(&load, &context(), &self::policy()).is_err());
        policy.deny.store(true, Ordering::SeqCst);
        assert_eq!(installed.resolve_shared(&load, &context()).unwrap_err().code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(installed.resolve_metadata(&metadata, &context()).unwrap_err().code, ResolutionErrorCode::PolicyDenied);
        let relocated = root.path().join("other-root");
        let second_policy = Arc::new(DirnamePolicy::default());
        let second = resolver.execution_resolver(&relocated, second_policy.clone()).unwrap();
        assert!(second.resolve_shared(&load, &context()).is_err());
        let moved = request(relocated.join("nested/dep.cjs").display().to_string());
        let moved_result = second.resolve_shared(&moved, &context()).unwrap();
        assert!(Arc::ptr_eq(&first.module.record, &moved_result.module.record));
        assert_eq!(*second_policy.seen.lock().unwrap(), vec![moved.specifier]);
    }


    #[test]
    fn native_commonjs_search_matches_node_and_replays_under_independent_roots() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("captured project");
        put(&root, "app.cjs", r#"
console.log('one',require.resolve('pkg',{paths:[__dirname+'/one',__dirname+'/two']}));
console.log('two',require.resolve('pkg',{paths:[__dirname+'/two',__dirname+'/one']}));
console.log('literal',require.resolve('pkg',{paths:['two']}));
console.log('ancestor',require.resolve('ancestor',{paths:[__dirname+'/one',__dirname+'/two']}));
console.log('relative',require.resolve('./asset.cjs',{paths:[__dirname+'/absent',__dirname+'/two']}));
console.log('relative-dir',require.resolve.paths('./asset.cjs')[0]===__dirname);
console.log('builtins',require.resolve.paths('fs')===null,require.resolve.paths('node:fs')===null);
console.log('package-dir',require.resolve.paths('pkg')[0]===__dirname+'/node_modules');
console.log('reserved-dir',require.resolve.paths('node:franken_missing')[0]===__dirname+'/node_modules');
try { require.resolve('pkg',{paths:[]}); } catch(e) { console.log('empty-package',e.code); }
try { require.resolve('./asset.cjs',{paths:[]}); } catch(e) { console.log('empty-relative',e.code); }
try { require.resolve('node:franken_missing',{paths:[]}); } catch(e) { console.log('reserved',e.code); }
try { require.resolve('broken',{paths:[__dirname+'/one',__dirname+'/two']}); } catch(e) { console.log('terminal-main',e.code); }
const {createRequire}=require('node:module');
const local=createRequire(__filename);
const lookup=local.resolve;
console.log('alias',lookup('pkg',{paths:[__dirname+'/two']}));
console.log('alias-dir',lookup.paths('./asset.cjs')[0]===__dirname);
"#);
        for directory in ["one", "two"] {
            put(&root, &format!("{directory}/node_modules/pkg/package.json"),
                r#"{"exports":"./index.cjs"}"#);
            put(&root, &format!("{directory}/node_modules/pkg/index.cjs"),
                "throw new Error('resolved asset evaluated');");
        }
        put(&root, "node_modules/ancestor/index.js", "first-root ancestor wins");
        put(&root, "two/node_modules/ancestor/index.js", "later-root candidate must not win");
        put(&root, "two/asset.cjs", "throw new Error('resolved asset evaluated');");
        put(&root, "one/node_modules/broken/package.json", r#"{"main":"./missing.cjs"}"#);
        put(&root, "two/node_modules/broken/index.js", "throw new Error('terminal bypass');");
        let reference = std::process::Command::new("node")
            .arg("app.cjs").current_dir(&root).output().expect("Node reference executable");
        assert!(reference.status.success(), "{}", String::from_utf8_lossy(&reference.stderr));
        let expected = String::from_utf8(reference.stdout).unwrap();
        assert!(expected.contains("relative-dir true\nbuiltins true true\n"));
        assert!(expected.contains("empty-package MODULE_NOT_FOUND\nempty-relative MODULE_NOT_FOUND\n"));
        assert!(expected.contains("reserved MODULE_NOT_FOUND\n"));
        assert!(expected.contains("terminal-main MODULE_NOT_FOUND\n"));
        let graph = capture(&root, "app.cjs", GraphOptions::default()).unwrap();
        assert!(graph.report().diagnostics.is_empty(), "{:?}", graph.report().diagnostics);
        let pin = graph.report().input_hash.clone();
        let encoded = capsule::encode(&graph).unwrap();
        std::fs::rename(&root, parent.path().join("retired input")).unwrap();
        let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
        assert_eq!(graph.report(), replayed.report());
        let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
        // The same immutable resolver must support two independently relocated
        // roots; neither destination exists and no source may be reopened.
        for destination in ["relocated one", "relocated two"] {
            let destination = parent.path().join(destination);
            assert!(!destination.exists());
            let expected = expected.replace(root.to_str().unwrap(), destination.to_str().unwrap());
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let policy = Arc::new(policy());
                let entry = resolver.resolve(&resolver.entry_request(), &context(), policy.as_ref())
                    .unwrap();
                let installed = resolver.execution_resolver(&destination, policy).unwrap();
                let output = engine(lane)
                    .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                    .expect("captured CommonJS search executes through the real engine hooks");
                let output = output.console_output.iter().map(|line| line.message.as_str())
                    .collect::<Vec<_>>().join("\n") + "\n";
                assert_eq!(output, expected, "{lane:?}");
            }
        }
    }

    #[test]
    fn native_create_require_search_uses_read_only_esm_dirname_origin() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("esm");
        put(&root, "app.mjs", r#"
import {createRequire} from 'node:module';
const load=createRequire(import.meta.url);
const lookup=load.resolve;
console.log('resolved',lookup('pkg',{paths:[import.meta.dirname+'/plugins']}));
console.log('directory',lookup.paths('./asset')[0]===import.meta.dirname);
"#);
        put(&root, "plugins/node_modules/pkg/index.js", "throw new Error('metadata evaluated');");
        let graph = capture(&root, "app.mjs", GraphOptions::default()).unwrap();
        assert!(graph.report().diagnostics.is_empty(), "{:?}", graph.report().diagnostics);
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        let destination = parent.path().join("unopened relocation");
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
                OrchestratorConfig {
                    force_lane: Some(lane),
                    parse_goal: ParseGoal::Module,
                    commonjs_entry: false,
                    ..OrchestratorConfig::default()
                },
                RuntimeConfig::default(),
            ).unwrap();
            let policy = Arc::new(policy());
            let entry = resolver.resolve(&resolver.entry_request(), &context(), policy.as_ref()).unwrap();
            let installed = resolver.execution_resolver(&destination, policy).unwrap();
            let result = engine.execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect("current-module createRequire and lexical import.meta.dirname retain their origins");
            assert_eq!(result.console_output.iter().map(|line| line.message.clone()).collect::<Vec<_>>(),
                [format!("resolved {}", destination.join("plugins/node_modules/pkg/index.js").display()),
                 "directory true".into()], "{lane:?}");
        }
    }

    #[test]
    fn native_commonjs_search_policy_denial_is_fresh_and_not_a_search_miss() {
        for source in [
            "console.log(require.resolve('./dep.cjs',{paths:[__dirname]})); try {require.resolve('./dep.cjs',{paths:[__dirname]});} catch(e) {console.log('bypass');}",
            "console.log(require.resolve.paths('./dep.cjs')[0]); try {require.resolve.paths('./dep.cjs');} catch(e) {console.log('bypass');}",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            put(root.path(), "dep.cjs", "throw new Error('metadata must not evaluate');");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let changing = Arc::new(RevokeSecondResolve(AtomicUsize::new(0)));
                let entry = resolver.resolve(&resolver.entry_request(), &context(), &policy()).unwrap();
                let installed = resolver.execution_resolver(root.path(), changing.clone()).unwrap();
                let mut engine = engine(lane);
                let failure = engine.execute_resolved_entry_with_resolver(&package(), &entry, installed)
                    .expect_err("metadata policy denial cannot select another root or be caught");
                assert!(failure.to_string().contains("closed-world module resolution refused"),
                    "{lane:?}: {failure}");
                assert_eq!(changing.0.load(Ordering::SeqCst), 2);
                assert_eq!(engine.last_failed_console_output().len(), 1);
                assert!(!engine.last_failed_console_output().iter().any(|line| line.message == "bypass"));
            }
        }
    }

    #[test]
    fn commonjs_search_engine_hooks_reject_uncaptured_purposes_roots_and_referrers() {
        use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
        use frankenengine_engine::module_resolver::{ImportStyle, ResolutionErrorCode};

        let root = tempfile::tempdir().unwrap();
        put(root.path(), "app.cjs", r#"
require.resolve('pkg',{paths:['one','two']});
require.resolve.paths('pkg');
require.resolve.paths('node:fs');
require.resolve('node:buffer');
"#);
        put(root.path(), "one/node_modules/pkg/index.js", "metadata only");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        let request = ModuleRequest::new("pkg", ImportStyle::Require)
            .with_referrer(resolver.entry_request().specifier)
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        let roots = vec!["one".into(), "two".into()];
        resolver.resolve_require_metadata_from_paths(&request, &roots, &context(), &policy()).unwrap();
        assert!(resolver.resolve_metadata(&request, &context(), &policy()).is_err());
        assert!(resolver.resolve(&request, &context(), &policy()).is_err());
        for paths in [vec![], vec!["two".into(), "one".into()], vec!["../outside".into()]] {
            assert!(resolver.resolve_require_metadata_from_paths(&request, &paths, &context(), &policy()).is_err());
        }
        let mut foreign = request.clone();
        foreign.referrer = Some("foreign".into());
        assert!(resolver.resolve_require_metadata_from_paths(&foreign, &roots, &context(), &policy()).is_err());
        assert!(resolver.require_lookup_paths(&foreign, &context(), &policy()).is_err());
        let mut denied = policy();
        denied.denied_specifiers.insert("pkg".into());
        assert_eq!(resolver.resolve_require_metadata_from_paths(&request, &roots, &context(), &denied)
            .unwrap_err().code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(resolver.require_lookup_paths(&request, &context(), &denied)
            .unwrap_err().code, ResolutionErrorCode::PolicyDenied);
        let mut builtin = request.clone();
        builtin.specifier = "node:fs".into();
        assert_eq!(resolver.require_lookup_paths(&builtin, &context(), &policy()).unwrap(), None);
        assert!(resolver.resolve_metadata(&builtin, &context(), &policy()).is_err());
        builtin.specifier = "node:buffer".into();
        resolver.resolve_metadata(&builtin, &context(), &policy()).unwrap();
        assert!(resolver.require_lookup_paths(&builtin, &context(), &policy()).is_err());
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
        put(
            &root,
            "node_modules/fixture/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(&root, "node_modules/fixture/index.cjs", FIXTURE);
        put(
            &root,
            "node_modules/fixture/payload.json",
            r#"{"answer":42}"#,
        );
        for base in [
            "node_modules/dual",
            "node_modules/fixture/node_modules/dual",
        ] {
            put(
                &root,
                &format!("{base}/package.json"),
                r#"{"exports":{"import":"./wrong.mjs","require":"./right.cjs"}}"#,
            );
            put(
                &root,
                &format!("{base}/right.cjs"),
                "throw new Error('resolve must not evaluate');",
            );
            put(
                &root,
                &format!("{base}/wrong.mjs"),
                "throw new Error('wrong conditions');",
            );
        }
        let captured = capture(&root, "app.cjs", GraphOptions::default()).unwrap();
        // Builtin terminal requirements remain explicit capture evidence.
        assert!(!captured.report().fully_resolved);
        assert!(captured.report().diagnostics.is_empty());
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        std::fs::rename(root.join("node_modules"), root.join("hidden_packages")).unwrap();
        put(
            &root,
            "node_modules/fixture/index.cjs",
            "throw new Error('live files reopened');",
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            assert_eq!(captured.report(), replayed.report());
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            let policy = Arc::new(policy());
            let entry = resolver
                .resolve(&resolver.entry_request(), &context(), policy.as_ref())
                .unwrap();
            let installed = resolver.execution_resolver(&root, policy).unwrap();
            let result = engine(lane)
                .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect("real sibling engine resolves the product-captured npm graph");
            assert_eq!(
                result
                    .console_output
                    .iter()
                    .map(|line| line.message.clone())
                    .collect::<Vec<_>>(),
                [
                    format!(
                        "resolved {}",
                        root.join("node_modules/fixture/index.cjs").display()
                    ),
                    "still-unloaded".into(),
                    format!(
                        "root {}",
                        root.join("node_modules/dual/right.cjs").display()
                    ),
                    format!(
                        "package-origin {}",
                        root.join("node_modules/fixture/index.cjs").display()
                    ),
                    format!(
                        "nested {}",
                        root.join("node_modules/fixture/node_modules/dual/right.cjs")
                            .display()
                    ),
                    format!(
                        "json {}",
                        root.join("node_modules/fixture/payload.json").display()
                    ),
                    "same true 42".into(),
                    "builtin buffer node:buffer".into(),
                ],
                "{lane:?}"
            );
        }
    }

    #[test]
    fn native_optional_package_fallbacks_match_node_and_keep_captured_absence() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        put(
            root,
            "app.cjs",
            r#"
const fixture = require('fallback-fixture');
console.log('value', fixture.value, fixture.lookup, fixture.resolved);
if (false) { require('unused-missing'); }
console.log('done');
"#,
        );
        put(
            root,
            "node_modules/fallback-fixture/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root,
            "node_modules/fallback-fixture/index.cjs",
            r#"
let value;
let lookup;
let resolved;
try { value = require('optional-addon'); }
catch (error) {
    if (error.code !== 'MODULE_NOT_FOUND') { throw error; }
    lookup = error.code;
    value = require('./fallback.cjs');
}
try { require.resolve('optional-addon'); }
catch (error) { resolved = error.code; }
module.exports = { value: value, lookup: lookup, resolved: resolved };
"#,
        );
        put(
            root,
            "node_modules/fallback-fixture/fallback.cjs",
            "module.exports = 42;",
        );
        let reference = std::process::Command::new("node")
            .arg("app.cjs")
            .current_dir(root)
            .output()
            .expect("Node supplies the optional-package reference result");
        assert!(
            reference.status.success(),
            "{}",
            String::from_utf8_lossy(&reference.stderr)
        );
        assert_eq!(
            reference.stdout,
            b"value 42 MODULE_NOT_FOUND MODULE_NOT_FOUND\ndone\n"
        );
        let captured = capture(root, "app.cjs", GraphOptions::default()).unwrap();
        assert!(!captured.report().fully_resolved);
        assert!(captured.report().diagnostics.is_empty());
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        // Neither a later install nor a changed fallback can alter a replay.
        put(
            root,
            "node_modules/optional-addon/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root,
            "node_modules/optional-addon/index.cjs",
            "module.exports = 999;",
        );
        put(
            root,
            "node_modules/fallback-fixture/fallback.cjs",
            "throw new Error('live fallback reopened');",
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            assert_eq!(replayed.report(), captured.report());
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            assert_eq!(resolver.summary().missing_routes, 2);
            assert_eq!(resolver.summary().missing_resolution_routes, 1);
            let policy = Arc::new(policy());
            let entry = resolver
                .resolve(&resolver.entry_request(), &context(), policy.as_ref())
                .unwrap();
            let installed = resolver.execution_resolver(root, policy).unwrap();
            let result = engine(lane)
                .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect("optional package lookup is ordinary CommonJS control flow");
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
    fn native_lexical_const_npm_requests_match_node_after_source_replacement() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        put(
            root,
            "app.cjs",
            r#"
const fixture = require('scoped-fixture');
console.log('values', fixture.load(true), fixture.load(false));
console.log('resolved', fixture.lookup());
console.log('optional', fixture.optional());
"#,
        );
        put(
            root,
            "node_modules/scoped-fixture/package.json",
            r#"{"main":"index.cjs"}"#,
        );
        put(
            root,
            "node_modules/scoped-fixture/index.cjs",
            r#"
const prefix = './';
function load(flag) {
    const leaf = flag ? 'one' : 'two';
    const target = prefix + leaf + '.cjs';
    return require(target);
}
function lookup() {
    const selected = './one.cjs';
    return require.resolve(selected);
}
function optional() {
    const absent = 'optional-addon';
    try { return require(absent); }
    catch (error) { return error.code; }
}
module.exports = { load: load, lookup: lookup, optional: optional };
"#,
        );
        put(
            root,
            "node_modules/scoped-fixture/one.cjs",
            "module.exports = 41;",
        );
        put(
            root,
            "node_modules/scoped-fixture/two.cjs",
            "module.exports = 42;",
        );
        let reference = std::process::Command::new("node")
            .arg("app.cjs")
            .current_dir(root)
            .output()
            .expect("Node supplies the scoped-package reference result");
        assert!(
            reference.status.success(),
            "{}",
            String::from_utf8_lossy(&reference.stderr)
        );
        let expected = format!(
            "values 41 42\nresolved {}\noptional MODULE_NOT_FOUND\n",
            root.join("node_modules/scoped-fixture/one.cjs").display(),
        );
        assert_eq!(reference.stdout, expected.as_bytes());
        let captured = capture(root, "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().diagnostics.is_empty());
        assert_eq!(captured.report().modules.len(), 4);
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        std::fs::rename(root.join("node_modules"), root.join("original_packages")).unwrap();
        put(
            root,
            "node_modules/scoped-fixture/index.cjs",
            "throw new Error('live package reopened');",
        );
        put(
            root,
            "node_modules/optional-addon/index.js",
            "module.exports = 999;",
        );
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            assert_eq!(replayed.report(), captured.report());
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            assert_eq!(resolver.summary().missing_routes, 1);
            let policy = Arc::new(policy());
            let entry = resolver
                .resolve(&resolver.entry_request(), &context(), policy.as_ref())
                .unwrap();
            let installed = resolver.execution_resolver(root, policy).unwrap();
            let result = engine(lane)
                .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect("lexical immutable requests retain the captured npm package origin");
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
    fn native_uncaught_missing_require_and_resolve_still_fail_execution() {
        for source in [
            "require('missing-package');",
            "require.resolve('missing-package');",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = captured.report().input_hash.clone();
            let encoded = capsule::encode(&captured).unwrap();
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let graph = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
                let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
                let policy = Arc::new(policy());
                let entry = resolver
                    .resolve(&resolver.entry_request(), &context(), policy.as_ref())
                    .unwrap();
                let installed = resolver.execution_resolver(root.path(), policy).unwrap();
                let failure = engine(lane)
                    .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                    .expect_err(
                        "admitting a known absence does not turn an uncaught load into success",
                    );
                assert!(
                    failure
                        .to_string()
                        .contains("Cannot find module 'missing-package'"),
                    "{lane:?}: {failure}"
                );
            }
        }
    }

    struct RevokeSecondResolve(AtomicUsize);

    struct MissingCodePolicy;

    impl ModulePolicyHook for MissingCodePolicy {
        fn authorize_metadata(
            &self,
            request: &ModuleRequest,
            metadata: &ModuleMetadata,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            let mut policy = policy();
            if request.specifier == "./dep.cjs" {
                policy.denied_specifiers.insert(request.specifier.clone());
                let mut denial = policy
                    .authorize_metadata(request, metadata, context)
                    .unwrap_err();
                denial.code =
                    frankenengine_engine::module_resolver::ResolutionErrorCode::ModuleNotFound;
                return Err(denial);
            }
            policy.authorize_metadata(request, metadata, context)
        }

        fn authorize(
            &self,
            request: &ModuleRequest,
            record: &ModuleRecord,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            let mut policy = policy();
            if request.specifier == "./dep.cjs" {
                policy.denied_specifiers.insert(request.specifier.clone());
                let mut denial = policy.authorize(request, record, context).unwrap_err();
                denial.code =
                    frankenengine_engine::module_resolver::ResolutionErrorCode::ModuleNotFound;
                return Err(denial);
            }
            policy.authorize(request, record, context)
        }
    }

    #[test]
    fn native_policy_denial_cannot_masquerade_as_an_optional_dependency_miss() {
        for source in [
            "try { require('./dep.cjs'); } catch (error) { console.log('policy bypass'); }",
            "try { require.resolve('./dep.cjs'); } catch (error) { console.log('policy bypass'); }",
        ] {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", source);
            put(root.path(), "dep.cjs", "module.exports=42;");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            let request = ModuleRequest::new(
                "./dep.cjs",
                frankenengine_engine::module_resolver::ImportStyle::Require,
            )
            .with_referrer(resolver.entry_request().specifier)
            .with_compatibility_mode(
                frankenengine_engine::module_compatibility_matrix::CompatibilityMode::NodeCompat,
            );
            let denial = if source.contains("require.resolve") {
                resolver
                    .resolve_metadata(&request, &context(), &MissingCodePolicy)
                    .unwrap_err()
            } else {
                resolver
                    .resolve(&request, &context(), &MissingCodePolicy)
                    .unwrap_err()
            };
            assert_eq!(
                denial.code,
                frankenengine_engine::module_resolver::ResolutionErrorCode::PolicyDenied
            );
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let entry = resolver
                    .resolve(&resolver.entry_request(), &context(), &policy())
                    .unwrap();
                let installed = resolver
                    .execution_resolver(root.path(), Arc::new(MissingCodePolicy))
                    .unwrap();
                let mut engine = engine(lane);
                let failure = engine
                    .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                    .expect_err("policy refusal remains outside guest exception handling");
                assert!(
                    failure
                        .to_string()
                        .contains("closed-world module resolution refused"),
                    "{lane:?}: {failure}"
                );
                assert!(engine.last_failed_console_output().is_empty());
            }
        }
    }

    impl ModulePolicyHook for RevokeSecondResolve {
        fn authorize(
            &self,
            request: &ModuleRequest,
            record: &ModuleRecord,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            policy().authorize(request, record, context)
        }

        fn authorize_metadata(
            &self,
            request: &ModuleRequest,
            metadata: &ModuleMetadata,
            context: &ResolutionContext,
        ) -> ResolutionResult<()> {
            let mut policy = policy();
            if request.specifier == "./dep.cjs" && self.0.fetch_add(1, Ordering::SeqCst) > 0 {
                policy.denied_specifiers.insert(request.specifier.clone());
            }
            policy.authorize_metadata(request, metadata, context)
        }
    }

    #[test]
    fn native_resolve_rechecks_policy_after_a_cached_success() {
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let root = tempfile::tempdir().unwrap();
            put(
                root.path(),
                "app.cjs",
                "console.log(require.resolve('./dep.cjs')); require.resolve('./dep.cjs'); console.log('must not reach');",
            );
            put(
                root.path(),
                "dep.cjs",
                "throw new Error('must not evaluate');",
            );
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            let changing = Arc::new(RevokeSecondResolve(AtomicUsize::new(0)));
            let entry = resolver
                .resolve(&resolver.entry_request(), &context(), &policy())
                .unwrap();
            let installed = resolver
                .execution_resolver(root.path(), changing.clone())
                .unwrap();
            let mut engine = engine(lane);
            let failure = engine
                .execute_resolved_entry_with_resolver(&package(), &entry, installed)
                .expect_err("cached require.resolve cannot bypass revocation");
            assert!(
                failure
                    .to_string()
                    .contains("closed-world module resolution refused"),
                "{failure}"
            );
            assert_eq!(changing.0.load(Ordering::SeqCst), 2);
            assert_eq!(
                engine
                    .last_failed_console_output()
                    .iter()
                    .map(|line| line.message.clone())
                    .collect::<Vec<_>>(),
                [root.path().join("dep.cjs").display().to_string()]
            );
        }
    }
}
