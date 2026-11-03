//! Bound metadata resolvers must retain their importer and never acquire load authority.

use super::*;
use super::registry::{PinnedModuleRegistry, RequestStyle};

fn scan_source(source: &str, language: SourceLanguage) -> Scan {
    scan(
        &mut Parser::new(),
        source.as_bytes(),
        language,
        &mut Budget::default(),
    )
    .unwrap()
}

fn put(root: &Path, path: &str, source: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, source).unwrap();
}

#[test]
fn extracted_resolvers_capture_exact_origins_and_alias_chains() {
    for (source, language, expected) in [
        (
            "const lookup=require.resolve; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const lookup=require['res'+'olve']; const next=lookup; next('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const {resolve}=require; resolve('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const {'resolve':lookup}=require; const next=lookup; next('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const load=require; const lookup=load.resolve; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const load=require, next=load, lookup=next.resolve; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "import {createRequire as make} from 'node:module'; const load=make(import.meta.url); const next=load; const {resolve:lookup}=next; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const {createRequire:make}=require('node:module'); const load=make(__filename); const lookup=load.resolve; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "import {createRequire as make} from 'node:module'; const load=make(import.meta.url), lookup=load.resolve; lookup('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::RequireResolve,
        ),
        (
            "const locate=import.meta.resolve; const next=locate; next('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::ImportMetaResolve,
        ),
        (
            "const {resolve:locate}=import.meta; locate('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::ImportMetaResolve,
        ),
        (
            "const {resolve}=import.meta; resolve('./asset');",
            SourceLanguage::JavaScript,
            LoadKind::ImportMetaResolve,
        ),
        (
            "const lookup=(require.resolve as Resolver); const next=(lookup satisfies Resolver); next('./asset');",
            SourceLanguage::TypeScript,
            LoadKind::RequireResolve,
        ),
        (
            "const locate=(import.meta['resolve'] as Resolver); locate!('./asset');",
            SourceLanguage::TypeScript,
            LoadKind::ImportMetaResolve,
        ),
    ] {
        let (loads, notices, analyzed) = scan_source(source, language);
        assert!(analyzed, "{source}");
        assert!(notices.is_empty(), "{source}: {notices:?}");
        let requests: Vec<_> = loads.iter()
            .filter(|load| load.specifier.as_deref() == Some("./asset"))
            .collect();
        assert_eq!(requests.len(), 1, "{source}: {loads:?}");
        assert_eq!(requests[0].kind, expected, "{source}");
        assert!(!requests[0].type_only);
    }
}

#[test]
fn extracted_resolvers_keep_load_and_metadata_purposes_distinct() {
    let source = "const load=require; const lookup=load.resolve; const locate=import.meta.resolve; typeof lookup; typeof locate; lookup('pkg'); locate('pkg'); load('pkg');";
    let (loads, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed);
    assert!(notices.is_empty(), "{notices:?}");
    assert_eq!(
        loads.iter().map(|load| load.kind).collect::<Vec<_>>(),
        [LoadKind::RequireResolve, LoadKind::ImportMetaResolve, LoadKind::Require],
    );
    assert!(loads.iter().all(|load| load.specifier.as_deref() == Some("pkg")));
}

#[test]
fn extracted_resolvers_require_immutable_unshadowed_non_escaping_bindings() {
    for origin in ["require.resolve", "import.meta.resolve"] {
        for body in [
            "lookup=other;",
            "lookup+=other;",
            "lookup++;",
            "({lookup}=other);",
            "for(lookup of values){}",
            "for(lookup in values){}",
            "const escaped={lookup};",
            "consume(lookup);",
            "export {lookup};",
            "function escape(){return lookup;}",
            "function shadow(lookup){lookup('./outside');}",
            "const shadow=(lookup)=>lookup('./outside');",
            "{const lookup=other; lookup('./outside');}",
            "try{}catch(lookup){lookup('./outside');}",
            "const {lookup}=other;",
            "var lookup;",
            "lookup.call(null,'./asset');",
            "lookup.apply(null,['./asset']);",
            "lookup.bind(null)('./asset');",
            "lookup.resolve('./asset');",
            "new lookup('./asset');",
            "lookup[key]('./asset');",
            "lo\\u006fkup=other;",
            "function shadow(lo\\u006fkup){}",
            "eval('lookup=other');",
        ] {
            let source = format!("const lookup={origin}; {body} lookup('./asset');");
            let (_, notices, analyzed) = scan_source(&source, SourceLanguage::JavaScript);
            assert!(analyzed, "{source}: {notices:?}");
            assert!(!notices.is_empty(), "unproved alias became complete: {source}");
        }
    }
}

#[test]
fn extracted_resolvers_reject_unproved_origins_and_forward_initialization() {
    for source in [
        "lookup('./asset'); const lookup=require.resolve;",
        "const first=lookup; const lookup=require.resolve; first('./asset');",
        "const lookup=load.resolve; const load=require; lookup('./asset');",
        "const lookup=load.resolve, load=require; lookup('./asset');",
        "const {resolve:lookup}=load; const load=require; lookup('./asset');",
        "import {createRequire} from 'node:module'; const lookup=load.resolve; const load=createRequire(import.meta.url); lookup('./asset');",
        "const lookup=next; const next=require.resolve; lookup('./asset');",
        "const lookup=(0,require.resolve); lookup('./asset');",
        "const lookup=flag?require.resolve:other; lookup('./asset');",
        "const lookup=require[member]; lookup('./asset');",
        "const lookup=import.meta[member]; lookup('./asset');",
        "const {resolve:lookup=fallback}=require; lookup('./asset');",
        "const {resolve:lookup,...rest}=require; lookup('./asset');",
        "const {resolve:lookup,main}=require; lookup('./asset');",
        "const {['resolve']:lookup}=require; lookup('./asset');",
        "const {resolve:lookup=fallback}=import.meta; lookup('./asset');",
        "const {resolve:lookup,url}=import.meta; lookup('./asset');",
        "function nested(){const lookup=require.resolve; lookup('./asset');}",
        "export const lookup=import.meta.resolve; lookup('./asset');",
        "const lookup=require.resolve; require.resolve=other; lookup('./asset');",
        "const lookup=require.resolve; Object.assign(require,{resolve:other}); lookup('./asset');",
        "const lookup=import.meta.resolve; import.meta.resolve=other; lookup('./asset');",
        "const lookup=import.meta.resolve; Object.assign(import.meta,{resolve:other}); lookup('./asset');",
        "const lookup=import.meta.resolve; const origin=import.meta; lookup('./asset');",
    ] {
        let (_, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
        assert!(analyzed, "{source}: {notices:?}");
        assert!(!notices.is_empty(), "unproved origin became complete: {source}");
    }
}

#[test]
fn extracted_resolvers_with_mutable_syntax_need_the_initialization_prelude() {
    for declaration in ["var", "let"] {
        for origin in ["require.resolve", "import.meta.resolve"] {
            let source = format!(
                "{declaration} lookup={origin}; {declaration} next=lookup; if(typeof next==='function') next('./asset');"
            );
            let (loads, notices, analyzed) = scan_source(&source, SourceLanguage::JavaScript);
            assert!(analyzed);
            assert!(notices.is_empty(), "{source}: {notices:?}");
            assert_eq!(loads.len(), 1);
            for source in [
                format!("invoke(); {declaration} lookup={origin}; function invoke(){{lookup('./asset');}}"),
                format!("const unknown=invoke(); {declaration} lookup={origin}; function invoke(){{lookup('./asset');}}"),
                format!("{declaration} lookup={origin}, unknown=invoke(); function invoke(){{lookup('./asset');}}"),
                format!("lookup('./asset'); {declaration} lookup={origin};"),
            ] {
                let (_, notices, analyzed) = scan_source(&source, SourceLanguage::JavaScript);
                assert!(analyzed, "{source}: {notices:?}");
                assert!(notices.iter().any(|notice|
                    notice.code == "UNPROVED_LOADER_INITIALIZATION"), "{source}: {notices:?}");
            }
        }
    }
}

#[test]
fn commonjs_resolver_extraction_rejects_wrapper_argument_mutation() {
    for origin in ["require.resolve", "require['resolve']"] {
        for body in [
            "arguments[1]=other;",
            "arguments[1].resolve=other;",
            "mutate(arguments);",
            "(()=>{arguments[1]=other;})();",
            "({[arguments[1]=other](){}});",
            "class Example {[arguments[1]=other](){}}",
        ] {
            let source = format!("{body} const lookup={origin}; lookup('./asset');");
            let (_, notices, analyzed) = scan_source(&source, SourceLanguage::JavaScript);
            assert!(analyzed, "{source}");
            assert!(notices.iter().any(|notice| notice.code == "MUTABLE_REQUIRE_ORIGIN"),
                "{source}: {notices:?}");
        }
    }
    let source = "const lookup=require.resolve; function ownArguments(){return arguments[0];} lookup('./asset');";
    let (_, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed);
    assert!(notices.is_empty(), "{notices:?}");
}

#[test]
fn resolver_aliases_preserve_options_refusals_and_nested_argument_loads() {
    let source = "const lookup=require.resolve; lookup('./asset',require('./options.cjs'));";
    let (loads, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed);
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[0].kind, LoadKind::RequireResolve);
    assert!(loads[0].specifier.is_none());
    assert_eq!(loads[1].kind, LoadKind::Require);
    assert_eq!(loads[1].specifier.as_deref(), Some("./options.cjs"));
    assert!(notices.iter().any(|notice| notice.code == "REQUIRE_RESOLVE_OPTIONS"));

    let source = "const locate=import.meta.resolve; locate('./missing',import('./options.mjs'));";
    let (loads, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed);
    assert!(notices.is_empty(), "{notices:?}");
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[0].kind, LoadKind::ImportMetaResolve);
    assert_eq!(loads[0].specifier.as_deref(), Some("./missing"));
    assert_eq!(loads[1].kind, LoadKind::DynamicImport);
    assert_eq!(loads[1].specifier.as_deref(), Some("./options.mjs"));
}

#[test]
fn resolver_aliases_reuse_finite_request_proofs_and_shared_binding_limits() {
    let source = "const lookup=require.resolve; const locate=import.meta.resolve; const target=flag?'./one':'./two'; lookup(target); locate(target); lookup(runtimeName);";
    let (loads, notices, analyzed) = scan_source(source, SourceLanguage::JavaScript);
    assert!(analyzed);
    assert!(notices.is_empty(), "{notices:?}");
    assert_eq!(loads.iter().map(|load| (load.kind, load.specifier.as_deref())).collect::<Vec<_>>(),
        [
            (LoadKind::RequireResolve, Some("./one")),
            (LoadKind::RequireResolve, Some("./two")),
            (LoadKind::ImportMetaResolve, Some("./one")),
            (LoadKind::ImportMetaResolve, Some("./two")),
            (LoadKind::RequireResolve, None),
        ]);

    let mut source = String::from("const load=require;");
    for index in 0..MAX_SITES {
        source.push_str(&format!("const lookup{index}=load.resolve;"));
    }
    let failure = scan(
        &mut Parser::new(),
        source.as_bytes(),
        SourceLanguage::JavaScript,
        &mut Budget::default(),
    ).unwrap_err();
    assert_eq!(failure.code, "ERR_MODULE_GRAPH_LIMIT");
}

#[test]
fn resolver_alias_capsules_keep_purpose_and_importer_authority_after_relocation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("project");
    put(&root, "app.mjs", "import './child/paths.mjs'; import './child/paths.cjs';");
    put(&root, "child/paths.mjs",
        "const locate=import.meta.resolve; const next=locate; next('dual'); next('./missing.json?x#y');");
    put(&root, "child/paths.cjs",
        "const {resolve:lookup}=require; const next=lookup; next('dual'); next('./asset.bin');");
    put(&root, "node_modules/dual/package.json",
        r#"{"exports":{"import":"./import.bin","require":"./require.bin"}}"#);
    put(&root, "node_modules/dual/import.bin", "unparsed import bytes");
    put(&root, "node_modules/dual/require.bin", "unparsed require bytes");
    put(&root, "child/asset.bin", "unparsed local bytes");
    let graph = capture(&root, "app.mjs", GraphOptions::default()).unwrap();
    assert!(graph.report().fully_resolved, "{:?}", graph.report().diagnostics);
    assert_eq!(graph.report().modules.len(), 3);
    assert_eq!(graph.report().resolution_targets.len(), 2);
    let pin = graph.report().input_hash.clone();
    let encoded = capsule::encode(&graph).unwrap();
    std::fs::rename(&root, temporary.path().join("original")).unwrap();
    put(&root, "app.mjs", "throw Error('ambient replacement');");
    let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
    assert_eq!(replayed.report(), graph.report());
    let registry = PinnedModuleRegistry::new(replayed, &pin).unwrap();
    let esm = registry.modules().find(|module| module.origin().path == "child/paths.mjs").unwrap();
    let cjs = registry.modules().find(|module| module.origin().path == "child/paths.cjs").unwrap();
    assert_eq!(registry.lookup_url_resolution(Some(esm.id()), "dual").unwrap().target(),
        &ResolutionUrl::File { id: ModuleId {
            path: "node_modules/dual/import.bin".into(),
            url_suffix: String::new(),
        } });
    assert_eq!(registry.lookup_resolution(Some(cjs.id()), "dual").unwrap().origin().path,
        "node_modules/dual/require.bin");
    assert_eq!(registry.lookup_resolution(Some(cjs.id()), "./asset.bin").unwrap().origin().path,
        "child/asset.bin");
    assert!(registry.lookup_resolution(Some(esm.id()), "dual").is_err());
    assert!(registry.lookup_url_resolution(Some(cjs.id()), "dual").is_err());
    assert!(registry.lookup_resolution(Some(registry.entrypoint()), "dual").is_err());
    assert!(registry.lookup_url_resolution(Some(registry.entrypoint()), "dual").is_err());
    for importer in [esm.id(), cjs.id()] {
        for style in [RequestStyle::Require, RequestStyle::Import] {
            assert!(registry.lookup(Some(importer), "dual", style).is_err());
        }
    }
}
