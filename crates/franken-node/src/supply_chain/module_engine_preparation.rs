//! Engine-owned preparation of captured source, with no new load authority.
//!
//! Ordinary explicitly typed JavaScript keeps the zero-transform path. Source
//! requiring syntax detection, hashbang handling or TypeScript normalization
//! goes through the actual FrankenEngine front end exactly once per physical
//! source. Original graph pins and routes remain authoritative.
//! JSON dependencies reached exclusively through require are delivered as a
//! quoted JSON.parse adapter, so value construction belongs to the engine,
//! not serde's numeric/object representation. ESM JSON needs import-attribute
//! and shared-namespace contracts which this captured graph does not carry.

use super::super::{
    Budget, EdgeState, LoadKind, ModuleId, SourceGraphReport, SourceLanguage, SourceModule, error, scan,
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
use std::io::{self, Write};
use std::sync::Arc;

type Result<T> = std::result::Result<T, CaptureError>;
type Routes = BTreeSet<(String, RequestStyle)>;
const MAX_PREPARED_SOURCE_BYTES: usize = 32 * 1024 * 1024;

/// Source-free engine preparation evidence. A report identifies an original
/// physical source; its URL instances still have separate graph-scoped IDs.
/// Preparation does not mean that execution or policy admission succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModulePreparationSummary {
    pub path: String,
    pub kind: ModuleKind,
    pub prepared_source_bytes: usize,
    /// For JSON, ingestion hashes describe the generated JavaScript adapter.
    /// This separate pin identifies the original JSON bytes in the graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_source_sha256: Option<String>,
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
    scan_budget: Budget,
    retained_bytes: usize,
}

impl Default for SourcePreparer {
    fn default() -> Self {
        Self {
            prepared: PreparedSources::default(),
            expected: None,
            parser: tree_sitter::Parser::new(),
            scan_budget: Budget::default(),
            retained_bytes: 0,
        }
    }
}

impl SourcePreparer {
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
        if module.source_language == SourceLanguage::JavaScript && !has_hashbang {
            if let Some(kind) = explicit {
                return Ok(kind);
            }
        }

        if self.expected.is_none() {
            self.expected = Some(expected_routes(report)?);
        }
        let index = self
            .expected
            .as_ref()
            .ok_or_else(invalid_preparation)?;
        let expected = index.modules.get(&module.id).ok_or_else(invalid_preparation)?;
        let json = module.source_language == SourceLanguage::Json;
        if json && (!index.json_require_only.contains(&module.id) || !expected.is_empty()) {
            return Err(error(
                "ERR_MODULE_ENGINE_JSON_IMPORT",
                "captured JSON requires exclusively CommonJS incoming routes; JSON entrypoints and ESM attributes need a separate engine contract",
            ));
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

        // A JSON value is NOT emitted as an object literal: that would change
        // __proto__, duplicate-member behavior and number semantics. Serialize
        // only the original text into one inert string literal. The graph's
        // existing JSON syntax admission and original source pin stay intact.
        let json_adapter = if json {
            Some(json_commonjs_source(
                source,
                MAX_PREPARED_SOURCE_BYTES.saturating_sub(self.retained_bytes),
            )?)
        } else {
            None
        };
        let input = json_adapter.as_deref().unwrap_or(source);
        let prepared = prepare_source_entry_for_public_entrypoints(
            input,
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
        if matches!(module.source_language, SourceLanguage::JavaScript | SourceLanguage::Json)
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
        if json && normalized != input {
            return Err(error(
                "ERR_MODULE_ENGINE_JSON_PREPARATION",
                "engine preparation must preserve the generated JSON adapter exactly",
            ));
        }
        if normalized.len() > MAX_PREPARED_SOURCE_BYTES {
            return Err(preparation_limit());
        }
        let kind = detect_kind(&normalized, explicit)?;
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
                routes.insert((specifier, request_style(load.kind)));
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
                    json_source_sha256: json.then(|| module.content_sha256.clone()),
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
/// syntax detection. JSON additionally requires graph-wide require-only
/// admission above. JSX, declarations and addons need other contracts.
fn captured_kind(module: &SourceModule) -> Result<Option<ModuleKind>> {
    match (module.source_language, module.format_hint.as_str()) {
        (SourceLanguage::JavaScript, "module") => Ok(Some(ModuleKind::EsModule)),
        (SourceLanguage::JavaScript, "commonjs") => Ok(Some(ModuleKind::CommonJs)),
        (SourceLanguage::JavaScript, "javascript_unspecified") => Ok(None),
        (SourceLanguage::Json, "json") if module.id.path.ends_with(".json") => {
            Ok(Some(ModuleKind::CommonJs))
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
    json_require_only: BTreeSet<ModuleId>,
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
    let mut json_require_only: BTreeSet<_> = report.modules.iter()
        .filter(|module| module.source_language == SourceLanguage::Json
            && module.id != report.resolved_entrypoint
            && module.id.url_suffix.is_empty())
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
        importer.insert((specifier.clone(), request_style(edge.kind)));
        if let Some(target) = &edge.target {
            if edge.kind == LoadKind::Require {
                required.insert(target.clone());
            } else {
                json_require_only.remove(target);
            }
        }
    }
    json_require_only.retain(|id| required.contains(id));
    Ok(ExpectedRoutes { modules: routes, json_require_only })
}

/// Encoding goes straight into one bounded buffer. Do not first allocate an
/// unbounded escaped copy and check its size afterwards. Errors never include
/// private JSON text, and the caller drops partial output on every failure.
fn json_commonjs_source(source: &str, limit: usize) -> Result<String> {
    struct BoundedSource {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for BoundedSource {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let end = self.bytes.len().checked_add(bytes.len())
                .filter(|end| *end <= self.limit)
                .ok_or_else(|| io::Error::other("JSON adapter byte limit"))?;
            self.bytes.try_reserve(end - self.bytes.len())
                .map_err(|_| io::Error::other("JSON adapter allocation failed"))?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let mut output = BoundedSource { bytes: Vec::new(), limit };
    output.write_all(b"module.exports = JSON.parse(").map_err(|_| preparation_limit())?;
    // Same text-to-JSON.parse value boundary as the sibling engine's native
    // CommonJS JSON loader. No host JSON Value enters the delivered module.
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    serde_json::to_writer(&mut output, text).map_err(|_| preparation_limit())?;
    output.write_all(b");\n").map_err(|_| preparation_limit())?;
    String::from_utf8(output.bytes).map_err(|_| invalid_preparation())
}

fn request_style(kind: LoadKind) -> RequestStyle {
    if kind == LoadKind::Require {
        RequestStyle::Require
    } else {
        RequestStyle::Import
    }
}

/// Node's syntax detection asks whether source parses as a CommonJS function
/// body, not as a Script (which would wrongly reject top-level return). The
/// standard wrapper parameters also expose lexical redeclaration conflicts.
/// Only detection uses this wrapper; delivered source is never wrapped here.
/// All grammar and early-error decisions belong to the actual engine parser.
fn detect_kind(source: &str, explicit: Option<ModuleKind>) -> Result<ModuleKind> {
    detect_kind_with_options(source, explicit, &ParserOptions::default())
}

fn detect_kind_with_options(
    source: &str,
    explicit: Option<ModuleKind>,
    options: &ParserOptions,
) -> Result<ModuleKind> {
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
    fn json_adapter_preserves_text_instead_of_reconstructing_values_or_code() {
        for text in [
            "null", "false", "-0", "9007199254740993",
            r#"{"same":1,"same":2,"__proto__":{"value":7}}"#,
            r#"{"text":"\"); require('unseen'); //","type":"const x: number = 1"}"#,
            r#"["line\nfeed","slash\\","\u0000","\ud83d\ude00"]"#,
            "{\"unicode\":\"é\u{2028}\u{2029}😀\"}",
        ] {
            let adapter = json_commonjs_source(text, MAX_PREPARED_SOURCE_BYTES).unwrap();
            let literal = adapter.strip_prefix("module.exports = JSON.parse(").unwrap()
                .strip_suffix(");\n").unwrap();
            // Parse only the outer string, not the original JSON value. Exact
            // equality detects duplicate-key, numeric and escape rewriting.
            assert_eq!(serde_json::from_str::<String>(literal).unwrap(), text);
            assert_eq!(detect_kind(&adapter, Some(ModuleKind::CommonJs)).unwrap(), ModuleKind::CommonJs);
            let mut parser = tree_sitter::Parser::new();
            let (loads, notices, analyzed) = scan(
                &mut parser, adapter.as_bytes(), SourceLanguage::JavaScript, &mut Budget::default(),
            ).unwrap();
            assert!(analyzed && loads.is_empty() && notices.is_empty());
            let engine = prepare_source_entry_for_public_entrypoints(
                &adapter, "data.json", "test", "decision", "policy",
            ).unwrap();
            assert_eq!(engine.prepared_source, adapter);
            assert_eq!(engine.source_ingestion.ts_capability_intent_count, 0);
            assert_eq!(engine.source_ingestion.source_language,
                frankenengine_engine::ts_normalization::SourceLanguage::JavaScript);
        }
    }

    #[test]
    fn json_adapter_budget_includes_escaping_and_never_returns_partial_source() {
        let source = r#"{"private":"\"\\\n"}"#;
        let full = json_commonjs_source(source, MAX_PREPARED_SOURCE_BYTES).unwrap();
        assert!(full.len() > source.len());
        assert_eq!(json_commonjs_source(source, full.len()).unwrap(), full);
        for limit in [0, 1, source.len(), full.len() - 1] {
            let failure = json_commonjs_source(source, limit).unwrap_err();
            assert_eq!(failure.code, "ERR_MODULE_ENGINE_PREPARATION_LIMIT");
            assert!(!failure.detail.contains("private"));
        }
        // The live graph currently applies its existing JSON admission rules;
        // adapter BOM handling also agrees with the native JSON loader.
        assert_eq!(json_commonjs_source("\u{feff}null", full.len()).unwrap(),
            "module.exports = JSON.parse(\"null\");\n");
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
        let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
        let policy = CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]));
        let outcomes = resolver.resolve_chain(&resolver.entry_request(),
            &ResolutionContext::new("trace", "decision", "policy"), &policy).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[1].module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(outcomes[1].module.record.source,
            "module.exports = JSON.parse(\"{\\\"answer\\\":42}\");\n");
        assert!(outcomes[1].module.record.dependencies.is_empty());
        assert_eq!(outcomes[1].module.content_hash, outcomes[1].module.record.canonical_hash());
        assert_eq!(resolver.summary().graph_input_hash, pin);
        let summaries: Vec<_> = resolver.preparation_reports().collect();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].path, "data.json");
        assert_eq!(summaries[0].json_source_sha256.as_deref(), Some(original_hash.as_str()));
        assert!(summaries[0].normalization_witness.is_none());
        assert!(summaries[0].source_map.is_empty());
        assert!(!resolver.summary().execution_performed);
        assert!(!resolver.summary().policy_admission_performed);
    }

    #[test]
    fn json_esm_routes_or_entrypoints_cannot_borrow_commonjs_admission() {
        use super::super::CapturedEngineResolver;
        use super::super::super::{GraphOptions, capture};

        for source in [
            "import value from './data.json';",
            "import('./data.json');",
            "export { default } from './data.json';",
            "require('./data.json'); import('./data.json');",
            "import('./data.json'); require('./data.json');",
            "require('./data.json'); import('./data.json?other');",
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
}
