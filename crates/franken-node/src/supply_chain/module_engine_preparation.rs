//! Engine-owned preparation of captured source, with no new load authority.
//!
//! Ordinary explicitly typed JavaScript keeps the zero-transform path. Source
//! requiring syntax detection, hashbang handling or TypeScript normalization
//! goes through the actual FrankenEngine front end exactly once per physical
//! source. Original graph pins and routes remain authoritative.
//! JSON dependencies reached through require or attributed static imports retain their original
//! text and use the engine's native JSON syntax. They never enter JavaScript
//! normalization or source-format detection. Static attributes remain part of
//! every dependency route; dynamic JSON options require a separate contract.

use super::super::{
    Budget, EdgeState, ImportAttributes, LoadKind, ModuleId, SourceGraphReport, SourceLanguage, SourceModule, error, scan,
};
use super::{CaptureError, ModuleKind, RegisteredModule, RequestStyle};
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParseErrorCode, ParserOptions};
use frankenengine_engine::ts_normalization::{
    SourceIngestionSummary, SourceMapEntry, TsNormalizationWitness,
    prepare_source_entry_for_public_entrypoints,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Result<T> = std::result::Result<T, CaptureError>;
type Routes = BTreeSet<(String, RequestStyle, ImportAttributes)>;
const MAX_PREPARED_SOURCE_BYTES: usize = 32 * 1024 * 1024;

/// Source-free engine preparation evidence. A report identifies an original
/// physical source; its URL instances still have separate graph-scoped IDs.
/// Preparation does not mean that execution or policy admission succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModulePreparationSummary {
    pub path: String,
    pub kind: ModuleKind,
    pub prepared_source_bytes: usize,
    pub source_ingestion: SourceIngestionSummary,
    pub normalization_witness: Option<TsNormalizationWitness>,
    pub source_map: Vec<SourceMapEntry>,
}

struct PreparedModule {
    // Unchanged source is borrowed from the registry, not retained twice.
    source: Option<Arc<str>>,
    summary: ModulePreparationSummary,
    language: SourceLanguage,
    format_hint: String,
    original_sha256: String,
    routes: Routes,
}

/// Only immutable Send+Sync data survives admission. The parser, construction
/// budgets and temporary route indexes are dropped by SourcePreparer::finish.
#[derive(Default)]
pub(super) struct PreparedSources {
    modules: BTreeMap<String, PreparedModule>,
}

impl PreparedSources {
    pub(super) fn source<'a>(&'a self, module: &'a RegisteredModule) -> &'a str {
        self.modules
            .get(&module.origin().path)
            .and_then(|prepared| prepared.source.as_deref())
            .unwrap_or_else(|| module.source())
    }

    pub(super) fn summaries(&self) -> impl Iterator<Item = &ModulePreparationSummary> {
        self.modules.values().map(|module| &module.summary)
    }
}

pub(super) struct SourcePreparer {
    prepared: PreparedSources,
    expected: Option<ExpectedRoutes>,
    parser: tree_sitter::Parser,
    parser_options: ParserOptions,
    scan_budget: Budget,
    retained_bytes: usize,
}

impl Default for SourcePreparer {
    fn default() -> Self {
        Self::with_parser_options(ParserOptions::default())
    }
}

impl SourcePreparer {
    pub(super) fn with_parser_options(parser_options: ParserOptions) -> Self {
        Self {
            prepared: PreparedSources::default(),
            expected: None,
            parser: tree_sitter::Parser::new(),
            parser_options,
            scan_budget: Budget::default(),
            retained_bytes: 0,
        }
    }

    pub(super) fn finish(self) -> PreparedSources {
        self.prepared
    }

    /// Called only after independent pin and closed-graph admission.
    pub(super) fn prepare(
        &mut self,
        module: &SourceModule,
        source: &str,
        report: &SourceGraphReport,
    ) -> Result<ModuleKind> {
        let explicit = captured_kind(module)?;
        let has_hashbang = source
            .strip_prefix('\u{feff}')
            .unwrap_or(source)
            .starts_with("#!");
        if module.source_language == SourceLanguage::JavaScript
            && !has_hashbang
            && let Some(kind) = explicit
        {
            return Ok(kind);
        }

        if self.expected.is_none() {
            self.expected = Some(expected_routes(report)?);
        }
        let index = self
            .expected
            .as_ref()
            .ok_or_else(invalid_preparation)?;
        let expected = index.modules.get(&module.id).ok_or_else(invalid_preparation)?;
        if module.source_language == SourceLanguage::Json {
            if !index.json_admitted.contains(&module.id) || !expected.is_empty() {
                return Err(error(
                    "ERR_MODULE_ENGINE_JSON_IMPORT",
                    "captured JSON requires require() or static imports with type=json; entrypoints, untyped imports and dynamic JSON are not admitted",
                ));
            }
            // The graph has already validated and pinned the original JSON.
            // Its value belongs to the engine's intrinsic JSON loader, not to
            // JavaScript source normalization or the guest-visible JSON object.
            // Retain no transformed copy and invent no JS-ingestion report.
            return Ok(ModuleKind::Json);
        }
        if let Some(prepared) = self.prepared.modules.get(&module.id.path) {
            if prepared.language != module.source_language
                || prepared.format_hint != module.format_hint
                || prepared.original_sha256 != module.content_sha256
                || &prepared.routes != expected
            {
                return Err(invalid_preparation());
            }
            return Ok(prepared.summary.kind);
        }

        let prepared = prepare_source_entry_for_public_entrypoints(
            source,
            &module.id.path,
            "captured-module-preparation",
            &report.input_hash,
            "franken-node.engine-source-preparation.v1",
        )
        .map_err(|_| {
            error(
                "ERR_MODULE_ENGINE_NORMALIZATION",
                "the engine could not normalize captured source",
            )
        })?;
        if prepared.source_ingestion.ts_capability_intent_count != 0 {
            // ModuleRecord has no slot for a TS capability-intent witness.
            // Never erase hostcall annotations while dropping their authority
            // obligations. A future ingestion contract can transport them.
            return Err(error(
                "ERR_MODULE_ENGINE_CAPABILITY_METADATA",
                "typed capability intents require an engine ingestion witness contract",
            ));
        }
        if module.source_language == SourceLanguage::JavaScript
            && prepared.source_ingestion.source_language
                != frankenengine_engine::ts_normalization::SourceLanguage::JavaScript
        {
            // The public engine API also accepts an inferred TS/hostcall DSL.
            // A Node-mode .js capture must not silently switch languages just
            // because an engine heuristic recognizes type-like source text.
            return Err(error(
                "ERR_MODULE_ENGINE_SOURCE_LANGUAGE",
                "JavaScript source cannot be implicitly reclassified as TypeScript",
            ));
        }
        let normalized = prepared.prepared_source;
        if normalized.len() > MAX_PREPARED_SOURCE_BYTES {
            return Err(preparation_limit());
        }
        let kind = detect_kind_with_options(&normalized, explicit, &self.parser_options)?;
        let routes = if normalized == source {
            expected.clone()
        } else {
            // Reuse the production graph scanner without a Resolver or any
            // filesystem authority. A transform cannot add a dependency or
            // erase a runtime side-effect dependency from a reviewed graph.
            let (loads, notices, analyzed) = scan(
                &mut self.parser,
                normalized.as_bytes(),
                SourceLanguage::JavaScript,
                &mut self.scan_budget,
            )?;
            if !analyzed || !notices.is_empty() {
                return Err(error(
                    "ERR_MODULE_ENGINE_DEPENDENCY_DRIFT",
                    "prepared source no longer has a closed analyzable dependency surface",
                ));
            }
            let mut routes = Routes::new();
            for load in loads {
                if load.type_only {
                    return Err(invalid_preparation());
                }
                let specifier = load.specifier.ok_or_else(invalid_preparation)?;
                routes.insert((specifier, request_style(load.kind), load.import_attributes));
            }
            routes
        };
        if &routes != expected {
            return Err(error(
                "ERR_MODULE_ENGINE_DEPENDENCY_DRIFT",
                "engine normalization changed the captured runtime dependency routes",
            ));
        }
        let source = if normalized == source {
            None
        } else {
            self.retained_bytes = self
                .retained_bytes
                .checked_add(normalized.len())
                .filter(|bytes| *bytes <= MAX_PREPARED_SOURCE_BYTES)
                .ok_or_else(preparation_limit)?;
            Some(Arc::from(normalized.as_str()))
        };
        let (normalization_witness, source_map) = prepared
            .normalization_output
            .map(|output| (Some(output.witness), output.source_map))
            .unwrap_or_default();
        self.prepared.modules.insert(
            module.id.path.clone(),
            PreparedModule {
                source,
                summary: ModulePreparationSummary {
                    path: module.id.path.clone(),
                    kind,
                    prepared_source_bytes: normalized.len(),
                    source_ingestion: prepared.source_ingestion,
                    normalization_witness,
                    source_map,
                },
                language: module.source_language,
                format_hint: module.format_hint.clone(),
                original_sha256: module.content_sha256.clone(),
                routes,
            },
        );
        Ok(kind)
    }
}

/// Format selection uses only captured metadata and physical source identity.
/// In particular, .ts inherits its captured package scope, while .mts/.cts are
/// explicit. An absent or legacy unknown hint is not evidence of an unmarked
/// package: only the resolver's typescript_unspecified observation permits
/// syntax detection. JSON additionally requires graph-wide attributed-route
/// admission above. JSX, declarations and addons need other contracts.
fn captured_kind(module: &SourceModule) -> Result<Option<ModuleKind>> {
    match (module.source_language, module.format_hint.as_str()) {
        (SourceLanguage::JavaScript, "module") => Ok(Some(ModuleKind::EsModule)),
        (SourceLanguage::JavaScript, "commonjs") => Ok(Some(ModuleKind::CommonJs)),
        (SourceLanguage::JavaScript, "javascript_unspecified") => Ok(None),
        (SourceLanguage::Json, "json") if module.id.path.ends_with(".json") => {
            Ok(Some(ModuleKind::Json))
        }
        (SourceLanguage::TypeScript, _) if module.id.path.ends_with(".mts") => {
            Ok(Some(ModuleKind::EsModule))
        }
        (SourceLanguage::TypeScript, _) if module.id.path.ends_with(".cts") => {
            Ok(Some(ModuleKind::CommonJs))
        }
        (SourceLanguage::TypeScript, "module") if module.id.path.ends_with(".ts") => {
            Ok(Some(ModuleKind::EsModule))
        }
        (SourceLanguage::TypeScript, "commonjs") if module.id.path.ends_with(".ts") => {
            Ok(Some(ModuleKind::CommonJs))
        }
        (SourceLanguage::TypeScript, "typescript_unspecified")
            if module.id.path.ends_with(".ts") =>
        {
            Ok(None)
        }
        _ => Err(error(
            "ERR_MODULE_REGISTRY_FORMAT",
            "engine preparation requires a captured JavaScript, TypeScript or JSON module format",
        )),
    }
}

struct ExpectedRoutes {
    modules: BTreeMap<ModuleId, Routes>,
    json_admitted: BTreeSet<ModuleId>,
}

fn expected_routes(report: &SourceGraphReport) -> Result<ExpectedRoutes> {
    let mut routes: BTreeMap<_, _> = report
        .modules
        .iter()
        .map(|module| (module.id.clone(), Routes::new()))
        .collect();
    // Index incoming JSON modes together with outgoing routes once, rather
    // than rescanning all edges for every data file or alias. Never collapse
    // require and import based on a shared physical path or content hash.
    let mut json_admitted: BTreeSet<_> = report.modules.iter()
        .filter(|module| module.source_language == SourceLanguage::Json
            && module.id != report.resolved_entrypoint)
        .map(|module| module.id.clone())
        .collect();
    let mut required = BTreeSet::new();
    for edge in &report.edges {
        if edge.state == EdgeState::TypeOnly {
            continue;
        }
        let importer = routes
            .get_mut(&edge.importer)
            .ok_or_else(invalid_preparation)?;
        let specifier = edge.specifier.as_ref().ok_or_else(invalid_preparation)?;
        importer.insert((specifier.clone(), request_style(edge.kind), edge.import_attributes.clone()));
        if matches!(edge.kind, LoadKind::RequireResolve | LoadKind::ImportMetaResolve) {
            continue;
        }
        if let Some(target) = &edge.target {
            let admitted = (edge.kind == LoadKind::Require && edge.import_attributes.is_empty())
                || (matches!(edge.kind, LoadKind::StaticImport | LoadKind::Reexport)
                    && edge.import_attributes.len() == 1
                    && edge.import_attributes.get("type").map(String::as_str) == Some("json"));
            if admitted {
                required.insert(target.clone());
            } else {
                json_admitted.remove(target);
            }
        }
    }
    json_admitted.retain(|id| required.contains(id));
    Ok(ExpectedRoutes { modules: routes, json_admitted })
}

fn request_style(kind: LoadKind) -> RequestStyle {
    match kind {
        LoadKind::Require => RequestStyle::Require,
        LoadKind::RequireResolve => RequestStyle::RequireResolve,
        LoadKind::ImportMetaResolve => RequestStyle::ImportMetaResolve,
        LoadKind::StaticImport | LoadKind::Reexport | LoadKind::DynamicImport => RequestStyle::Import,
    }
}

/// Node's syntax detection asks whether source parses as a CommonJS function
/// body, not as a Script (which would wrongly reject top-level return). The
/// standard wrapper parameters also expose lexical redeclaration conflicts.
/// Only detection uses this wrapper; delivered source is never wrapped here.
/// All grammar and early-error decisions belong to the actual engine parser.
#[cfg(test)]
fn detect_kind(source: &str, explicit: Option<ModuleKind>) -> Result<ModuleKind> {
    detect_kind_with_options(source, explicit, &ParserOptions::default())
}

/// Share the captured-module parser's bounded format detection with native
/// entrypoint execution. Callers retain the original source for ingestion.
pub fn detect_kind_with_options(
    source: &str,
    explicit: Option<ModuleKind>,
    options: &ParserOptions,
) -> Result<ModuleKind> {
    if matches!(explicit, Some(ModuleKind::Json | ModuleKind::NativeBuiltin)) {
        return Err(error(
            "ERR_MODULE_REGISTRY_FORMAT",
            "native JSON and builtin descriptors cannot enter JavaScript format detection",
        ));
    }
    let parser = CanonicalEs2020Parser;
    if explicit != Some(ModuleKind::EsModule) {
        let wrapper = format!(
            "(function(exports, require, module, __filename, __dirname) {{\n{source}\n}});"
        );
        // ParserInput accepts owned String and &str, not &String. Moving the
        // temporary wrapper also avoids another full source-buffer copy.
        match parser.parse_with_options(wrapper, ParseGoal::Script, options) {
            Ok(_) => return Ok(ModuleKind::CommonJs),
            Err(failure)
                if matches!(
                    failure.code,
                    ParseErrorCode::InvalidGoal
                        | ParseErrorCode::InvalidSyntax
                        | ParseErrorCode::UnsupportedSyntax
                        | ParseErrorCode::StrictModeWithStatement
                        | ParseErrorCode::AwaitOutsideAsync
                ) => {}
            // Resource/input failure is not evidence of ESM syntax. In
            // particular, a source may fit a module budget while its CommonJS
            // wrapper does not. Retrying would silently select another format.
            Err(failure) => return Err(parser_failure(failure.code)),
        }
    }
    if explicit != Some(ModuleKind::CommonJs) {
        return parser
            .parse_with_options(source, ParseGoal::Module, options)
            .map(|_| ModuleKind::EsModule)
            .map_err(|failure| parser_failure(failure.code));
    }
    Err(parser_failure(ParseErrorCode::InvalidGoal))
}

fn parser_failure(code: ParseErrorCode) -> CaptureError {
    if matches!(code, ParseErrorCode::SourceTooLarge | ParseErrorCode::BudgetExceeded) {
        return error(
            "ERR_MODULE_ENGINE_PARSE_LIMIT",
            "engine source-format detection exceeded its parser budget",
        );
    }
    error(
        "ERR_MODULE_ENGINE_PARSE",
        "captured source is not accepted by the engine in its selected module format",
    )
}

fn invalid_preparation() -> CaptureError {
    error(
        "ERR_MODULE_ENGINE_PREPARATION",
        "captured source preparation is inconsistent with the sealed graph",
    )
}

fn preparation_limit() -> CaptureError {
    error(
        "ERR_MODULE_ENGINE_PREPARATION_LIMIT",
        "engine-prepared source exceeds the retained-source budget",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::parser::ParserBudget;

    fn source_budget(bytes: usize) -> ParserOptions {
        ParserOptions {
            budget: ParserBudget {
                max_source_bytes: u64::try_from(bytes).unwrap(),
                ..ParserBudget::default()
            },
            ..ParserOptions::default()
        }
    }

    fn source_module(path: &str, language: SourceLanguage, format: &str) -> SourceModule {
        SourceModule {
            id: ModuleId {
                path: path.into(),
                url_suffix: String::new(),
            },
            content_sha256: String::new(),
            content_bytes: 0,
            format_hint: format.into(),
            source_language: language,
            analyzed: true,
        }
    }

    #[test]
    fn captured_typescript_scope_selects_the_engine_parse_goal() {
        for (path, format, expected) in [
            ("app.ts", "module", Some(ModuleKind::EsModule)),
            ("app.ts", "commonjs", Some(ModuleKind::CommonJs)),
            ("app.ts", "typescript_unspecified", None),
            ("app.mts", "module", Some(ModuleKind::EsModule)),
            ("app.cts", "commonjs", Some(ModuleKind::CommonJs)),
        ] {
            let module = source_module(path, SourceLanguage::TypeScript, format);
            assert_eq!(captured_kind(&module).unwrap(), expected);
        }
    }

    #[test]
    fn unknown_scope_and_non_runtime_languages_cannot_enter_ts_preparation() {
        for (path, language, format) in [
            ("app.ts", SourceLanguage::TypeScript, "unknown"),
            ("app.ts", SourceLanguage::TypeScript, "javascript_unspecified"),
            ("app.tsx", SourceLanguage::Tsx, "module"),
            ("app.d.ts", SourceLanguage::Declaration, "module"),
            ("app.json", SourceLanguage::Json, "module"),
        ] {
            let module = source_module(path, language, format);
            assert_eq!(
                captured_kind(&module).unwrap_err().code,
                "ERR_MODULE_REGISTRY_FORMAT"
            );
        }
    }

    #[test]
    fn wrapper_budget_failure_cannot_relabel_commonjs_as_a_module() {
        let source = "const value=42;";
        let options = source_budget(source.len());
        // Establish that the tempting fallback would succeed. The wrapper
        // exceeds this exact source budget, which is not a syntax decision.
        assert!(
            CanonicalEs2020Parser
                .parse_with_options(source, ParseGoal::Module, &options)
                .is_ok()
        );
        for explicit in [None, Some(ModuleKind::CommonJs)] {
            assert_eq!(
                detect_kind_with_options(source, explicit, &options)
                    .unwrap_err()
                    .code,
                "ERR_MODULE_ENGINE_PARSE_LIMIT"
            );
        }
        assert_eq!(
            detect_kind_with_options(source, Some(ModuleKind::EsModule), &options).unwrap(),
            ModuleKind::EsModule
        );
    }

    #[test]
    fn explicit_module_budget_failure_is_distinct_and_source_free() {
        let source = "export const private_name=42;";
        let failure = detect_kind_with_options(
            source,
            Some(ModuleKind::EsModule),
            &source_budget(source.len() - 1),
        )
        .unwrap_err();
        assert_eq!(failure.code, "ERR_MODULE_ENGINE_PARSE_LIMIT");
        assert!(!failure.detail.contains("private_name"));
    }

    #[test]
    fn syntax_fallback_preserves_explicit_commonjs_boundaries() {
        let source = "export const answer=42;";
        assert_eq!(detect_kind(source, None).unwrap(), ModuleKind::EsModule);
        assert_eq!(
            detect_kind(source, Some(ModuleKind::CommonJs))
                .unwrap_err()
                .code,
            "ERR_MODULE_ENGINE_PARSE"
        );
        assert_eq!(
            detect_kind("return 42;", None).unwrap(),
            ModuleKind::CommonJs
        );
    }

    #[test]
    fn native_json_preserves_captured_text_without_reconstructing_values_or_code() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture};
        use frankenengine_engine::capability::RuntimeCapability;
        use frankenengine_engine::module_resolver::{
            CapabilityPolicyHook, ModuleResolver, ModuleSyntax, ResolutionContext,
        };

        let root = tempfile::tempdir().unwrap();
        put_json_fixture(root.path(), "app.cjs", "require('./data.json');");
        let policy = CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]));
        for text in [
            "null", "false", "-0", "9007199254740993",
            r#"{"same":1,"same":2,"__proto__":{"value":7}}"#,
            r#"{"text":"\"); require('unseen'); //","type":"const x: number = 1"}"#,
            r#"["line\nfeed","slash\\","\u0000","\ud83d\ude00"]"#,
            "{\"unicode\":\"é\u{2028}\u{2029}😀\"}",
            "\u{feff}{\"answer\":42}",
        ] {
            put_json_fixture(root.path(), "data.json", text);
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(graph.report().fully_resolved);
            let pin = graph.report().input_hash.clone();
            let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            let outcomes = resolver.resolve_chain(&resolver.entry_request(),
                &ResolutionContext::new("trace", "decision", "policy"), &policy).unwrap();
            assert_eq!(outcomes.len(), 2);
            let record = &outcomes[1].module.record;
            assert_eq!(record.syntax, ModuleSyntax::Json);
            // The engine receives the original JSON, including duplicate keys,
            // numeric spelling and escapes, without a generated JavaScript wrapper.
            assert_eq!(record.source, text);
            assert!(record.dependencies.is_empty());
            assert_eq!(outcomes[1].module.content_hash, record.canonical_hash());
            assert_eq!(resolver.preparation_reports().count(), 0);
        }
    }

    #[test]
    fn native_data_kinds_cannot_enter_javascript_format_detection() {
        for kind in [ModuleKind::Json, ModuleKind::NativeBuiltin] {
            let failure = detect_kind_with_options("{}", Some(kind), &source_budget(0)).unwrap_err();
            assert_eq!(failure.code, "ERR_MODULE_REGISTRY_FORMAT");
        }
    }

    fn put_json_fixture(root: &std::path::Path, path: &str, text: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn require_json_dependency_uses_engine_record_and_preserves_the_original_pin() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture};
        use frankenengine_engine::capability::RuntimeCapability;
        use frankenengine_engine::module_resolver::{CapabilityPolicyHook, ModuleResolver, ModuleSyntax, ResolutionContext};
        use sha2::{Digest, Sha256};

        let root = tempfile::tempdir().unwrap();
        put_json_fixture(root.path(), "app.cjs", "module.exports=require('./data.json');");
        let json = r#"{"answer":42}"#;
        put_json_fixture(root.path(), "data.json", json);
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved);
        let pin = graph.report().input_hash.clone();
        let original_hash = hex::encode(Sha256::digest(json.as_bytes()));
        assert_eq!(graph.report().modules.iter()
            .find(|module| module.id.path == "data.json").unwrap().content_sha256, original_hash);
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let policy = CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]));
        let outcomes = resolver.resolve_chain(&resolver.entry_request(),
            &ResolutionContext::new("trace", "decision", "policy"), &policy).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[1].module.record.syntax, ModuleSyntax::Json);
        assert_eq!(outcomes[1].module.record.source, json);
        assert_eq!(hex::encode(Sha256::digest(outcomes[1].module.record.source.as_bytes())),
            original_hash);
        assert!(outcomes[1].module.record.dependencies.is_empty());
        assert_eq!(outcomes[1].module.content_hash, outcomes[1].module.record.canonical_hash());
        assert_eq!(resolver.summary().graph_input_hash, pin);
        assert_eq!(resolver.preparation_reports().count(), 0);
        assert!(!resolver.summary().execution_performed);
        assert!(!resolver.summary().policy_admission_performed);
    }

    #[test]
    fn untyped_json_imports_or_entrypoints_cannot_borrow_an_admitted_route() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture};

        for source in [
            "import value from './data.json';",
            "import('./data.json');",
            "export { default } from './data.json';",
            "require('./data.json'); import('./data.json');",
            "import('./data.json'); require('./data.json');",
            "require('./data.json'); import('./data.json?other');",
            "import value from './data.json' with {type:'json'}; import './data.json';",
            "import value from './data.json' with {type:'json'}; export {default} from './data.json';",
            "import value from './data.json' with {type:'json'}; import('./data.json');",
            "import value from './data.json' with {type:'text'};",
            "import value from './data.json' with {type:'json', extra:'unsupported'};",
        ] {
            let root = tempfile::tempdir().unwrap();
            put_json_fixture(root.path(), "app.mjs", source);
            put_json_fixture(root.path(), "data.json", "{}");
            let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
            assert!(graph.report().fully_resolved, "{source}");
            let pin = graph.report().input_hash.clone();
            assert_eq!(CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_ENGINE_JSON_IMPORT", "{source}");
        }
        let root = tempfile::tempdir().unwrap();
        put_json_fixture(root.path(), "data.json", "{}");
        let graph = capture(root.path(), "data.json", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_ENGINE_JSON_IMPORT");
    }

    #[test]
    fn static_json_routes_survive_typescript_normalization_with_exact_attributes() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture};
        use frankenengine_engine::capability::RuntimeCapability;
        use frankenengine_engine::module_resolver::{CapabilityPolicyHook, ModuleResolver,
            ModuleSyntax, ResolutionContext};

        let root = tempfile::tempdir().unwrap();
        put_json_fixture(root.path(), "app.mts", r#"
import data from './data.json' with {type:'json'};
export {default as forwarded} from './data.json' with {'type':'json'};
const answer: number=data.answer;
export {answer};
"#);
        let json = "\u{feff}{\"answer\":42}";
        put_json_fixture(root.path(), "data.json", json);
        let graph = capture(root.path(), "app.mts", GraphOptions::default()).unwrap();
        assert!(graph.report().fully_resolved, "{:?}", graph.report());
        let pin = graph.report().input_hash.clone();
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let policy = CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]));
        let records = resolver.resolve_chain(&resolver.entry_request(),
            &ResolutionContext::new("trace", "decision", "policy"), &policy).unwrap();
        assert_eq!(records.len(), 2);
        let entry = &records[0].module.record;
        assert_eq!(entry.syntax, ModuleSyntax::EsModule);
        assert!(!entry.source.contains(": number"));
        assert!(entry.source.contains("with {type:'json'}"));
        assert!(entry.source.contains("with {'type':'json'}"));
        assert!(entry.dependencies.iter().all(|dependency|
            dependency.import_attributes.get("type") == Some("json")
                && dependency.import_attributes.len() == 1));
        assert_eq!(entry.dependencies.len(), 1);
        assert_eq!(records[1].module.record.syntax, ModuleSyntax::Json);
        assert_eq!(records[1].module.record.source, json);
        assert_eq!(resolver.summary().graph_input_hash, pin);
        let reports = resolver.preparation_reports().collect::<Vec<_>>();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].path, "app.mts");
        assert!(reports[0].normalization_witness.is_some());
    }

    #[test]
    fn invalid_json_and_transform_free_registry_keep_their_existing_barriers() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture, registry::PinnedModuleRegistry};

        let root = tempfile::tempdir().unwrap();
        put_json_fixture(root.path(), "app.cjs", "require('./data.json');");
        for json in ["{} trailing", "{\"a\":1,}", "// comment\n{}"] {
            put_json_fixture(root.path(), "data.json", json);
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(!graph.report().fully_resolved);
            let pin = graph.report().input_hash.clone();
            assert_eq!(CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_INCOMPLETE");
        }
        put_json_fixture(root.path(), "data.json", "{}");
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        assert_eq!(PinnedModuleRegistry::new(graph, &pin).err().unwrap().code,
            "ERR_MODULE_REGISTRY_FORMAT");
    }

    mod json_graph {
        use super::{put_json_fixture as put, *};
        use super::super::super::CapturedEngineResolver;
        use super::super::super::super::{GraphOptions, capture, capsule};
        use frankenengine_engine::capability::RuntimeCapability;
        use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
        use frankenengine_engine::module_resolver::{
            CapabilityPolicyHook, ImportStyle, ModulePolicyHook, ModuleRecord, ModuleRequest,
            ModuleResolver, ModuleSyntax, ResolutionContext, ResolutionErrorCode, ResolutionResult,
        };
        use std::cell::Cell;

        fn granted() -> CapabilityPolicyHook {
            CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]))
        }
        fn context() -> ResolutionContext {
            ResolutionContext::new("trace", "decision", "policy")
        }
        fn resolver(root: &std::path::Path, entry: &str) -> CapturedEngineResolver {
            let graph = capture(root, entry, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            CapturedEngineResolver::new(graph, &pin).ok().unwrap()
        }

        #[test]
        fn npm_json_extension_index_main_and_manifest_routes_are_engine_loadable() {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "package.json", r#"{"type":"commonjs"}"#);
            put(root.path(), "app.cjs", "require('./value'); require('./data-dir'); require('data-package'); require('./package.json');");
            put(root.path(), "value.json", r#"{"source":"extension"}"#);
            put(root.path(), "data-dir/index.json", r#"{"source":"index"}"#);
            put(root.path(), "node_modules/data-package/package.json", r#"{"main":"value.json"}"#);
            put(root.path(), "node_modules/data-package/value.json", r#"{"source":"package"}"#);
            let resolver = resolver(root.path(), "app.cjs");
            for (request, expected) in [
                ("./value", r#"{"source":"extension"}"#),
                ("./data-dir", r#"{"source":"index"}"#),
                ("data-package", r#"{"source":"package"}"#),
                ("./package.json", r#"{"type":"commonjs"}"#),
            ] {
                let request = ModuleRequest::new(request, ImportStyle::Require)
                    .with_referrer(resolver.entry_request().specifier)
                    .with_compatibility_mode(CompatibilityMode::NodeCompat);
                let outcome = resolver.resolve(&request, &context(), &granted()).unwrap();
                assert_eq!(outcome.module.record.source, expected);
                assert_eq!(outcome.module.record.syntax, ModuleSyntax::Json);
                assert_eq!(outcome.module.content_hash, outcome.module.record.canonical_hash());
            }
            assert_eq!(resolver.preparation_reports().count(), 0);
        }

        struct ChangingPolicy { allow: Cell<bool>, calls: Cell<usize> }
        impl ModulePolicyHook for ChangingPolicy {
            fn authorize(&self, request: &ModuleRequest, record: &ModuleRecord,
                context: &ResolutionContext) -> ResolutionResult<()> {
                self.calls.set(self.calls.get() + 1);
                let capabilities = if self.allow.get() {
                    BTreeSet::from([RuntimeCapability::ModuleLoad])
                } else { BTreeSet::new() };
                CapabilityPolicyHook::new(capabilities).authorize(request, record, context)
            }
        }

        #[test]
        fn shared_json_in_a_cycle_retains_original_data_and_rechecks_each_load() {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", "require('./dep.cjs'); require('./value.json'); require('./value');");
            put(root.path(), "dep.cjs", "require('./app.cjs'); module.exports=require('./value.json');");
            put(root.path(), "value.json", r#"{"private_label":42}"#);
            let resolver = resolver(root.path(), "app.cjs");
            let policy = ChangingPolicy { allow: Cell::new(true), calls: Cell::new(0) };
            let outputs = resolver.resolve_chain(&resolver.entry_request(), &context(), &policy).unwrap();
            assert_eq!(outputs.len(), 3);
            assert_eq!(policy.calls.get(), 6); // Entry plus five captured incoming routes.
            assert_eq!(resolver.preparation_reports().count(), 0);
            let request = ModuleRequest::new("./value.json", ImportStyle::Require)
                .with_referrer(resolver.entry_request().specifier)
                .with_compatibility_mode(CompatibilityMode::NodeCompat);
            let mut before = resolver.resolve(&request, &context(), &policy).unwrap();
            let expected_hash = before.module.content_hash;
            before.module.record.source = "caller mutation".into();
            policy.allow.set(false);
            assert_eq!(resolver.resolve(&request, &context(), &policy).unwrap_err().code,
                ResolutionErrorCode::PolicyDenied);
            policy.allow.set(true);
            let now = ResolutionContext::new("new-trace", "new-decision", "new-policy");
            let after = resolver.resolve(&request, &now, &policy).unwrap();
            assert_eq!(after.module.content_hash, expected_hash);
            assert_eq!(after.module.record.source, r#"{"private_label":42}"#);
            assert_eq!(after.module.record.syntax, ModuleSyntax::Json);
            assert_eq!(after.event.trace_id, "new-trace");
            assert_eq!(policy.calls.get(), 9);
            assert_eq!(resolver.preparation_reports().count(), 0);
            // Knowing the data module's ID is not authority for another route.
            let invented = ModuleRequest::new("./not-captured.json", ImportStyle::Require)
                .with_referrer(resolver.entry_request().specifier)
                .with_compatibility_mode(CompatibilityMode::NodeCompat);
            let preparations_before = resolver.preparation_reports().cloned().collect::<Vec<_>>();
            let failure = resolver.resolve(&invented, &now, &policy).unwrap_err();
            assert_eq!(failure.code, ResolutionErrorCode::UnsupportedSpecifier);
            assert!(failure.message.starts_with("ERR_MODULE_REGISTRY_ROUTE:"));
            assert_eq!(policy.calls.get(), 9);
            assert_eq!(
                resolver.preparation_reports().cloned().collect::<Vec<_>>(),
                preparations_before
            );
        }

        #[test]
        fn contained_json_aliases_and_capsule_replay_preserve_physical_identity() {
            use super::super::super::super::super::SymlinkPolicy;
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", "require('./alias.json'); require('./value.json');");
            put(root.path(), "value.json", r#"{"original":true}"#);
            std::os::unix::fs::symlink("value.json", root.path().join("alias.json")).unwrap();
            let graph = capture(root.path(), "app.cjs", GraphOptions {
                symlink_policy: SymlinkPolicy::Contained, ..GraphOptions::default()
            }).unwrap();
            assert_eq!(graph.report().modules.len(), 2);
            let pin = graph.report().input_hash.clone();
            let encoded = capsule::encode(&graph).unwrap();
            let live = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            let before = live.resolve_chain(&live.entry_request(), &context(), &granted()).unwrap();
            assert_eq!(before.len(), 2);
            assert_eq!(before[1].module.record.syntax, ModuleSyntax::Json);
            assert_eq!(before[1].module.record.source, r#"{"original":true}"#);
            assert_eq!(live.preparation_reports().count(), 0);
            put(root.path(), "value.json", r#"{"replacement":true}"#);
            std::fs::rename(root.path().join("app.cjs"), root.path().join("moved.cjs")).unwrap();
            let graph = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            let restored = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            assert_eq!(before, restored.resolve_chain(&restored.entry_request(), &context(), &granted()).unwrap());
            assert_eq!(live.preparation_reports().collect::<Vec<_>>(), restored.preparation_reports().collect::<Vec<_>>());
            assert_eq!(before, live.resolve_chain(&live.entry_request(), &context(), &granted()).unwrap());
        }

        #[test]
        fn native_json_does_not_consume_javascript_preparation_budget() {
            let root = tempfile::tempdir().unwrap();
            put(root.path(), "app.cjs", "require('./a.json'); require('./b.json');");
            put(root.path(), "a.json", "{}");
            put(root.path(), "b.json", "[]");
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let a = graph.report().modules.iter().find(|module| module.id.path == "a.json").unwrap();
            let b = graph.report().modules.iter().find(|module| module.id.path == "b.json").unwrap();
            let mut preparer = SourcePreparer::with_parser_options(source_budget(0));
            preparer.retained_bytes = MAX_PREPARED_SOURCE_BYTES;
            assert_eq!(preparer.prepare(a, "{}", graph.report()).unwrap(), ModuleKind::Json);
            assert_eq!(preparer.prepare(a, "{}", graph.report()).unwrap(), ModuleKind::Json);
            assert_eq!(preparer.prepare(b, "[]", graph.report()).unwrap(), ModuleKind::Json);
            assert!(preparer.prepared.modules.is_empty());
            assert_eq!(preparer.retained_bytes, MAX_PREPARED_SOURCE_BYTES);
            assert_eq!(preparer.finish().summaries().count(), 0);
        }

        #[test]
        fn chain_budget_counts_original_json_bytes_exactly() {
            let root = tempfile::tempdir().unwrap();
            let app = "require('./value.json');";
            let json = r#"{"escaped":"\"\\"}"#;
            put(root.path(), "app.cjs", app);
            put(root.path(), "value.json", json);
            let mut resolver = resolver(root.path(), "app.cjs");
            let outputs = resolver.resolve_chain(&resolver.entry_request(), &context(), &granted()).unwrap();
            let delivered: usize = outputs.iter().map(|outcome| outcome.module.record.source.len()).sum();
            assert_eq!(delivered, app.len() + json.len());
            resolver.chain_source_budget = delivered - 1;
            let failure = resolver.resolve_chain(&resolver.entry_request(), &context(), &granted()).unwrap_err();
            assert!(failure.message.contains("source budget"));
            resolver.chain_source_budget = delivered;
            assert_eq!(outputs, resolver.resolve_chain(&resolver.entry_request(), &context(), &granted()).unwrap());
        }

        #[test]
        fn typed_commonjs_can_require_json_without_gaining_type_only_loads() {
            for entry in ["app.cts", "app.ts"] {
                let root = tempfile::tempdir().unwrap();
                put(root.path(), "package.json", r#"{"type":"commonjs"}"#);
                put(root.path(), entry,
                    "import type { Missing } from './absent.d.ts'; const data=require('./value.json'); const answer: number=data.answer; module.exports=answer;");
                put(root.path(), "value.json", r#"{"answer":42}"#);
                let resolver = resolver(root.path(), entry);
                let outputs = resolver.resolve_chain(&resolver.entry_request(), &context(), &granted()).unwrap();
                assert_eq!(outputs.len(), 2);
                assert_eq!(outputs[0].module.record.syntax, ModuleSyntax::CommonJs);
                assert_eq!(outputs[1].module.record.syntax, ModuleSyntax::Json);
                assert_eq!(outputs[1].module.record.source, r#"{"answer":42}"#);
                assert!(!outputs[0].module.record.source.contains("absent.d.ts"));
                assert!(!outputs[0].module.record.source.contains(": number"));
                assert_eq!(outputs[0].module.record.dependencies.len(), 1);
                assert_eq!(outputs[0].module.record.dependencies[0].specifier, "./value.json");
                assert_eq!(resolver.preparation_reports().count(), 1);
            }
        }
    }
}
