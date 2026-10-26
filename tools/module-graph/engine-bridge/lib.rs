//! Compile the exact product bridge against the actual sibling engine crate.
#![forbid(unsafe_code)]

use franken_module_graph_schema as schema_versions;
#[path = "../../../crates/franken-node/src/supply_chain/module_resolution_graph.rs"]
pub mod module_resolution_graph;

// Keep the product namespace used by the shared dependency workspace selector.
#[cfg(target_os = "linux")]
mod supply_chain {
    pub(crate) use crate::module_resolution_graph;
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../../crates/franken-node/src/migration/dependency_admission.rs"]
pub(crate) mod dependency_admission;
#[cfg(target_os = "linux")]
mod migration {
    pub(crate) use crate::dependency_admission;
}

use std::io::{self, Read};
use std::path::Path;

// Same focused-host bounded read as the module-graph command. All resolution,
// capsule reconstruction, registry admission and engine adapter code is loaded
// unmodified from the product modules; no engine contracts are mocked.
pub fn bounded_read_to_string(path: &Path, limit: u64) -> io::Result<String> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata is nonregular or exceeds its byte limit"));
    }
    let mut text = String::new();
    file.take(limit.saturating_add(1)).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "metadata exceeds its byte limit"));
    }
    Ok(text)
}

#[cfg(test)]
mod native_builtin_execution {
    use super::module_resolution_graph::file_resolution::source_graph::{
        GraphOptions, capsule, capture, engine_resolver::CapturedEngineResolver,
    };
    use frankenengine_engine::{
        ast::ParseGoal,
        baseline_interpreter::LaneChoice,
        capability::RuntimeCapability,
        execution_orchestrator::{ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig},
        module_resolver::{CapabilityPolicyHook, ModuleResolver, ResolutionContext},
        runtime_config::RuntimeConfig,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    fn execute(
        resolver: Arc<CapturedEngineResolver>,
        root: &std::path::Path,
        commonjs: bool,
    ) -> Vec<String> {
        let policy = Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Builtin,
        ])));
        let entry = resolver
            .resolve(
                &resolver.entry_request(),
                &ResolutionContext::new("capture-test", "capture-decision", "capture-policy"),
                policy.as_ref(),
            )
            .expect("admitted captured entry");
        let installed = resolver
            .execution_resolver(root, policy)
            .expect("runtime resolver");
        let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig {
                commonjs_entry: commonjs,
                parse_goal: if commonjs {
                    ParseGoal::Script
                } else {
                    ParseGoal::Module
                },
                force_lane: Some(LaneChoice::QuickJs),
                ..OrchestratorConfig::default()
            },
            RuntimeConfig::default(),
        )
        .expect("real sibling engine");
        let package = ExtensionPackage {
            extension_id: "captured-native-builtins".into(),
            source: entry.module.record.source.clone(),
            source_file: None,
            module_root: None,
            capabilities: vec!["module_load".into(), "builtin".into()],
            version: "1.0.0".into(),
            metadata: BTreeMap::new(),
        };
        engine
            .execute_resolved_entry_with_resolver(&package, &entry, installed)
            .expect("captured npm modules execute through the real engine")
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect()
    }

    #[test]
    fn frozen_npm_package_uses_canonical_builtin_factories_after_source_changes() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("node_modules/format-kit");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"format-kit","main":"index.cjs"}"#,
        )
        .unwrap();
        std::fs::write(
            package.join("index.cjs"),
            r#"
const util = require('node:util');
const assert = require('node:assert/strict');
const StringDecoder = require('string_decoder').StringDecoder;
module.exports = {
    util: util,
    describe: function(value) {
        assert.equal(value, 42);
        const decoder = new StringDecoder('utf8');
        const head = decoder.write(Buffer.from([226, 130]));
        return util.format('%s=%d:%s', 'answer', value, head + decoder.end(Buffer.from([172])));
    }
};
"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("app.cjs"),
            r#"
const kit = require('format-kit');
const util = require('util');
console.log(kit.describe(42));
console.log(kit.util === util, require('util/types') === util.types);
console.log(require('assert').strict === require('assert/strict'));
"#,
        )
        .unwrap();
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let sealed = capsule::encode(&graph).unwrap();
        // A later live-file mutation cannot change replayed application code.
        std::fs::write(
            package.join("index.cjs"),
            "throw new Error('live source must not run');",
        )
        .unwrap();
        std::fs::write(
            root.path().join("app.cjs"),
            "throw new Error('live entry must not run');",
        )
        .unwrap();
        let replayed = capsule::replay(sealed.bytes(), sealed.digest()).unwrap();
        let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
        assert_eq!(
            execute(resolver, root.path(), true),
            ["answer=42:€", "true true", "true"]
        );
    }

    #[test]
    fn frozen_create_require_executes_the_creating_packages_commonjs_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("packages/bridge/node_modules/where");
        let outer = root.path().join("node_modules/where");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&outer).unwrap();
        std::fs::write(
            nested.join("package.json"),
            r#"{"name":"where","main":"index.cjs"}"#,
        )
        .unwrap();
        std::fs::write(nested.join("index.cjs"), "module.exports = {value: 42};").unwrap();
        std::fs::write(outer.join("index.js"), "module.exports = {value: 9000};").unwrap();
        let bridge = root.path().join("packages/bridge/bridge.mjs");
        std::fs::write(
            &bridge,
            r#"
import {createRequire as makeRequire} from 'node:module';
const localRequire = makeRequire(import.meta.url);
export function readFromBridge() {
    return localRequire('where').value + ':' + localRequire.resolve('where').endsWith('/packages/bridge/node_modules/where/index.cjs');
}
"#,
        )
        .unwrap();
        let app = root.path().join("app.mjs");
        std::fs::write(
            &app,
            "import {readFromBridge} from './packages/bridge/bridge.mjs?revision=1#captured'; console.log(readFromBridge());",
        )
        .unwrap();
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let sealed = capsule::encode(&graph).unwrap();
        for path in [
            &app,
            &bridge,
            &nested.join("index.cjs"),
            &outer.join("index.js"),
        ] {
            std::fs::write(path, "throw new Error('live code must not run');").unwrap();
        }
        std::fs::write(nested.join("package.json"), r#"{"main":"missing.cjs"}"#).unwrap();
        let replayed = capsule::replay(sealed.bytes(), sealed.digest()).unwrap();
        let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
        assert_eq!(execute(resolver, root.path(), false), ["42:true"]);
    }

    #[test]
    fn frozen_esm_gets_callable_assert_and_named_util_decoder_exports() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("app.mjs"),
            r#"
import assert, {strictEqual} from 'node:assert';
import strict from 'assert/strict';
import util, {format, MIMEType} from 'util';
import * as utilNamespace from 'util';
import types, {isMap} from 'node:util/types';
import {StringDecoder} from 'node:string_decoder';
strictEqual(strict, assert.strict);
assert(types === util.types);
strictEqual(Reflect.set(utilNamespace, 'format', null), false);
strictEqual(Reflect.defineProperty(utilNamespace, 'format', {value: null}), false);
strictEqual(utilNamespace.format, format);
console.log(format('%s:%d', 'esm', 7), isMap(new Map()), typeof StringDecoder);
console.log(new MIMEType('Text/Plain').essence);
"#,
        )
        .unwrap();
        let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        assert_eq!(
            execute(resolver, root.path(), false),
            ["esm:7 true function", "text/plain"]
        );
    }
}
