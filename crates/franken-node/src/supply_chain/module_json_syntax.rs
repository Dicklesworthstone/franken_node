//! Validate JSON syntax without imposing Rust value semantics on guest data.
//!
//! The engine constructs values. In particular, numeric overflow, negative
//! zero, duplicate keys and escaped UTF-16 code units are not capture-time
//! conversions. IgnoredAny checks grammar without building a Value tree, but
//! its iterative path needs an explicit depth bound matching prior admission.

const MAX_JSON_DEPTH: usize = 127;

pub(super) fn valid(bytes: &[u8]) -> bool {
    // Ignore exactly one leading BOM for syntax checking, not in the captured
    // bytes or identity. JSON module preparation performs the same removal.
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in text.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return false;
                }
            }
            b']' | b'}' => {
                let Some(previous) = depth.checked_sub(1) else {
                    return false;
                };
                depth = previous;
            }
            _ => {}
        }
    }
    if quoted || depth != 0 {
        return false;
    }
    // This also checks matching delimiters, escapes, separators and EOF.
    // Do not deserialize Value here: that rejects otherwise valid JS JSON.
    serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_json_grammar_without_constructing_host_values() {
        for source in [
            "null", "true", "false", "-0", "1e400", "-1e400", "1e-4000",
            "9007199254740993", "{\"a\":1,\"a\":2}",
            "{\"__proto__\":{\"polluted\":true}}",
            r#""\ud800""#, r#""\udfff""#, r#""\ud83d\ude00""#,
            "\u{feff}{\"answer\":42}", "[{},[],\"[{}]\"]",
            "{\"x\":\"quote: \\\" brackets: [ ]\"}",
        ] {
            assert!(valid(source.as_bytes()), "rejected fixture {source:?}");
        }
    }

    #[test]
    fn malformed_grammar_trailing_input_and_non_utf8_stay_rejected() {
        for source in [
            "", " ", "[1,]", "{\"a\":1,}", "{a:1}", "01", "+1", "1.",
            "1e", "1e+", "NaN", "Infinity", "null false", "{}[]", "/*x*/0",
            "\u{feff}\u{feff}{}", " \u{feff}{}", "\"unterminated", "[}",
            "\"literal\nnewline\"", r#""\uZZZZ""#, r#""\x00""#,
        ] {
            assert!(!valid(source.as_bytes()), "accepted fixture {source:?}");
        }
        assert!(!valid(b"\"\xff\""));
    }

    #[test]
    fn iterative_validation_keeps_the_previous_nesting_limit() {
        for (open, close) in [("[", "]"), ("{\"x\":", "}")] {
            let boundary = format!("{}0{}", open.repeat(MAX_JSON_DEPTH), close.repeat(MAX_JSON_DEPTH));
            assert!(valid(boundary.as_bytes()));
            assert!(!valid(format!("{open}{boundary}{close}").as_bytes()));
        }
        let quoted = format!("\"{}\"", "[".repeat(MAX_JSON_DEPTH * 2));
        assert!(valid(quoted.as_bytes()));
        assert!(valid(br#"{"escaped":"\\\"[{}]"}"#));
    }
}

#[cfg(all(test, feature = "engine"))]
mod engine_tests {
    use super::super::engine_resolver::CapturedEngineResolver;
    use super::super::{GraphOptions, SourceLanguage, capsule, capture};
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::LaneChoice;
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
    };
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, ModuleResolver, ResolutionContext,
    };
    use frankenengine_engine::runtime_config::RuntimeConfig;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    fn policy() -> CapabilityPolicyHook {
        CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ]))
    }

    fn context() -> ResolutionContext {
        ResolutionContext::new("json-trace", "json-decision", "json-policy")
    }

    #[test]
    fn json_reaches_engine_preparation_with_original_bytes_and_pins() {
        for payload in [
            "\u{feff}{\"answer\":42}",
            "{\"large\":1e400,\"small\":1e-4000,\"negativeZero\":-0}",
            r#"{"text":"\ud800","__proto__":{"safe":true},"x":1,"x":2}"#,
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("app.cjs"), "module.exports = require('./data.json');").unwrap();
            std::fs::write(root.path().join("data.json"), payload).unwrap();
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(graph.report().fully_resolved);
            let json = graph.report().modules.iter()
                .find(|m| m.source_language == SourceLanguage::Json).unwrap();
            assert_eq!(graph.source_bytes(&json.id).unwrap(), payload.as_bytes());
            let original_pin = json.content_sha256.clone();
            let pin = graph.report().input_hash.clone();
            let resolver = CapturedEngineResolver::new(graph, &pin).ok().unwrap();
            let outcomes = resolver.resolve_chain(&resolver.entry_request(), &context(), &policy()).unwrap();
            assert_eq!(outcomes.len(), 2);
            let delivered = outcomes.iter()
                .find(|o| o.module.record.source.starts_with("module.exports = JSON.parse(")).unwrap();
            let text = payload.strip_prefix('\u{feff}').unwrap_or(payload);
            let expected = format!("module.exports = JSON.parse({});\n", serde_json::to_string(text).unwrap());
            assert_eq!(delivered.module.record.source, expected);
            let summary = resolver.preparation_reports().find(|s| s.path == "data.json").unwrap();
            assert_eq!(summary.json_source_sha256.as_deref(), Some(original_pin.as_str()));
        }
    }

    #[test]
    fn invalid_json_never_enters_the_pinned_engine_registry() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.cjs"), "require('./data.json');").unwrap();
        for payload in ["{\"a\":1,}", "{}[]", "\u{feff}\u{feff}{}"] {
            std::fs::write(root.path().join("data.json"), payload).unwrap();
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            assert!(!graph.report().fully_resolved);
            assert!(graph.report().diagnostics.iter().any(|d| d.code == "INVALID_JSON_MODULE"));
            let pin = graph.report().input_hash.clone();
            assert_eq!(
                CapturedEngineResolver::new(graph, &pin).err().unwrap().code,
                "ERR_MODULE_REGISTRY_INCOMPLETE"
            );
        }
    }

    #[test]
    fn native_npm_json_execution_uses_replayed_bytes_and_engine_value_semantics() {
        let root = tempfile::tempdir().unwrap();
        let package_dir = root.path().join("node_modules/fixture");
        std::fs::create_dir_all(&package_dir).unwrap();
        std::fs::write(package_dir.join("package.json"), r#"{"main":"index.cjs"}"#).unwrap();
        std::fs::write(package_dir.join("index.cjs"), "module.exports = require('./data.json');").unwrap();
        let payload = concat!(
            "\u{feff}",
            r#"{"large":1e400,"small":1e-4000,"negativeZero":-0,"text":"\ud800","__proto__":{"safe":true},"x":1,"x":2}"#
        );
        std::fs::write(package_dir.join("data.json"), payload).unwrap();
        std::fs::write(root.path().join("app.cjs"), r#"
const value = require('fixture');
const again = require('fixture');
console.log(value.large === Infinity, value.small === 0,
  1 / value.negativeZero === -Infinity, value.text.charCodeAt(0) === 55296,
  Object.prototype.hasOwnProperty.call(value, '__proto__'),
  value.__proto__.safe, value.x, value === again);
"#).unwrap();
        let captured = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        assert!(captured.report().fully_resolved);
        let pin = captured.report().input_hash.clone();
        let encoded = capsule::encode(&captured).unwrap();
        // Execution must not reopen either package code or JSON after capture.
        std::fs::write(package_dir.join("index.cjs"), "throw new Error('live code reopened');").unwrap();
        std::fs::write(package_dir.join("data.json"), "{\"x\":99}").unwrap();
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let replayed = capsule::replay(encoded.bytes(), encoded.digest()).unwrap();
            assert_eq!(replayed.report(), captured.report());
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            let policy = Arc::new(policy());
            let entry = resolver.resolve(&resolver.entry_request(), &context(), policy.as_ref()).unwrap();
            let installed = resolver.execution_resolver(root.path(), policy).unwrap();
            let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
                OrchestratorConfig {
                    force_lane: Some(lane),
                    parse_goal: ParseGoal::Script,
                    commonjs_entry: true,
                    ..OrchestratorConfig::default()
                },
                RuntimeConfig::default(),
            ).unwrap();
            let package = ExtensionPackage {
                extension_id: "captured-json-semantics".into(),
                source: "throw new Error('uncaptured entry executed');".into(),
                source_file: Some("/unopened/captured-json-test.cjs".into()),
                module_root: None,
                capabilities: vec!["module_load".into(), "builtin".into()],
                version: "1.0.0".into(),
                metadata: BTreeMap::new(),
            };
            let result = engine.execute_resolved_entry_with_resolver(&package, &entry, installed)
                .expect("sibling engine executes the replayed npm JSON graph");
            assert_eq!(
                result.console_output.iter().map(|line| line.message.as_str()).collect::<Vec<_>>(),
                ["true true true true true true 2 true"],
                "{lane:?}"
            );
        }
    }
}
