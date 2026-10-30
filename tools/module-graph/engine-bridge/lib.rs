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
        execute_with_capabilities(
            resolver,
            root,
            commonjs,
            LaneChoice::QuickJs,
            &[RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin],
        )
        .expect("captured npm modules execute through the real engine")
    }

    fn execute_with_capabilities(
        resolver: Arc<CapturedEngineResolver>,
        root: &std::path::Path,
        commonjs: bool,
        lane: LaneChoice,
        capabilities: &[RuntimeCapability],
    ) -> Result<Vec<String>, String> {
        let policy = Arc::new(CapabilityPolicyHook::new(
            capabilities.iter().copied().collect::<BTreeSet<_>>(),
        ));
        let entry = resolver
            .resolve(
                &resolver.entry_request(),
                &ResolutionContext::new("capture-test", "capture-decision", "capture-policy"),
                policy.as_ref(),
            )
            .map_err(|error| error.to_string())?;
        let installed = resolver
            .execution_resolver(root, policy)
            .map_err(|error| error.to_string())?;
        let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig {
                commonjs_entry: commonjs,
                parse_goal: if commonjs {
                    ParseGoal::Script
                } else {
                    ParseGoal::Module
                },
                force_lane: Some(lane),
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
            capabilities: capabilities.iter().map(ToString::to_string).collect(),
            version: "1.0.0".into(),
            metadata: BTreeMap::new(),
        };
        let result = engine
            .execute_resolved_entry_with_resolver(&package, &entry, installed)
            .map_err(|error| format!("{error}; console={:?}", engine.last_failed_console_output()))?;
        Ok(result
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect())
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

    #[test]
    fn frozen_readline_diagnostics_share_factories_after_live_sources_change() {
        for commonjs in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let package = root.path().join("node_modules/line-consumer");
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join("package.json"),
                r#"{"name":"line-consumer","main":"index.cjs"}"#).unwrap();
            std::fs::write(package.join("index.cjs"), r#"
module.exports = {
    readline: require('node:readline'),
    promises: require('node:readline/promises'),
    diagnostics: require('node:diagnostics_channel')
};
"#).unwrap();
            let prefix = if commonjs { r#"
const readline = require('readline');
const promises = require('readline/promises');
const diagnostics = require('diagnostics_channel');
const events = require('events');
const child = require('line-consumer');
"# } else { r#"
import readline from 'readline';
import promises from 'readline/promises';
import diagnostics from 'diagnostics_channel';
import events from 'events';
import child from 'line-consumer';
"# };
            let body = r#"
console.log(readline === child.readline, diagnostics === child.diagnostics,
    promises === readline.promises, promises === child.promises);
const input = new events.EventEmitter();
input.resume = function () {};
input.pause = function () {};
const reader = child.readline.createInterface({input: input, terminal: false});
const seen = [];
diagnostics.subscribe('lines', function (line) { seen.push(line); });
reader.on('line', function (line) { child.diagnostics.channel('lines').publish(line); });
input.emit('data', Buffer.from([226, 130]));
input.emit('data', Buffer.from([172, 10]));
input.emit('data', 'tail');
input.emit('end');
console.log(reader instanceof events.EventEmitter, seen.join('|'), reader.closed);
console.log(diagnostics.channel('lines').hasSubscribers,
    typeof readline.cursorTo, typeof promises.Readline);
"#;
            let entrypoint = if commonjs { "app.cjs" } else { "app.mjs" };
            let app = root.path().join(entrypoint);
            std::fs::write(&app, format!("{prefix}\n{body}")).unwrap();
            let graph = capture(root.path(), entrypoint, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let sealed = capsule::encode(&graph).unwrap();
            for path in [&app, &package.join("index.cjs")] {
                std::fs::write(path, "throw new Error('live source must not execute');").unwrap();
            }
            std::fs::write(package.join("package.json"), r#"{"main":"missing.cjs"}"#).unwrap();
            let replayed = capsule::replay(sealed.bytes(), sealed.digest()).unwrap();
            let resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                assert_eq!(execute_with_capabilities(
                    resolver.clone(), root.path(), commonjs, lane,
                    &[RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin, RuntimeCapability::Timer],
                ).unwrap(), [
                    "true true true true", "true €|tail true", "true function function",
                ]);
            }
        }
    }

    #[test]
    fn conditional_array_fallback_matches_node_in_live_and_frozen_execution() {
        let root = tempfile::tempdir().unwrap();
        for (name, contents) in [
            ("package.json", r##"{"name":"self","exports":{"node":[{"browser":"./wrong.cjs"}],"default":"./self.cjs"},"imports":{"#local":{"node":[[{"browser":"./wrong.cjs"}],{}],"default":"./local.cjs"},"#external":"fallback"}}"##),
            ("self.cjs", "module.exports = 'self';"),
            ("local.cjs", "module.exports = 'local';"),
            ("node_modules/fallback/package.json", r#"{"exports":{"node":[[{"browser":"./wrong.cjs"}],{}],"default":{"require":"./value.cjs","import":"./value.mjs"}}}"#),
            ("node_modules/fallback/value.cjs", "module.exports = 'require';"),
            ("node_modules/fallback/value.mjs", "export default 'import';"),
            ("node_modules/empty/package.json", r#"{"exports":{"node":[],"default":"./wrong.cjs"}}"#),
            ("node_modules/excluded/package.json", r#"{"exports":{"node":["../invalid.cjs",null,{}],"default":"./wrong.cjs"}}"#),
            ("node_modules/empty/wrong.cjs", "throw new Error('empty array fell through');"),
            ("node_modules/excluded/wrong.cjs", "throw new Error('null fell through');"),
            ("app.cjs", r#"
console.log(require('fallback'), require('self'), require('#local'), require('#external'));
try { require('empty'); } catch (error) { console.log(error.code); }
try { require('excluded'); } catch (error) { console.log(error.code); }
import('fallback').then(value => console.log(value.default));
"#),
            ("app.mjs", r#"
import value from 'fallback';
import self from 'self';
import local from '#local';
import external from '#external';
console.log(value, self, local, external);
import('empty').then(() => console.log('wrong fallback'), error => console.log(error.code));
"#),
        ] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        for commonjs in [true, false] {
            let entrypoint = if commonjs { "app.cjs" } else { "app.mjs" };
            let node = std::process::Command::new("node")
                .arg(entrypoint)
                .current_dir(root.path())
                .env_remove("NODE_OPTIONS")
                .output()
                .expect("Node is required for the package-resolution oracle");
            assert!(node.status.success(), "{}", String::from_utf8_lossy(&node.stderr));
            let expected: Vec<_> = String::from_utf8(node.stdout).unwrap()
                .lines().map(str::to_owned).collect();
            let exact = if commonjs {
                vec!["require self local require", "ERR_PACKAGE_PATH_NOT_EXPORTED",
                    "ERR_PACKAGE_PATH_NOT_EXPORTED", "import"]
            } else {
                vec!["import self local import", "ERR_PACKAGE_PATH_NOT_EXPORTED"]
            };
            assert_eq!(expected, exact, "the oracle must perform the useful work and refusals");
            let graph = capture(root.path(), entrypoint, GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let sealed = capsule::encode(&graph).unwrap();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
                let capabilities = [RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin];
                let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
                    OrchestratorConfig {
                        commonjs_entry: commonjs,
                        parse_goal: if commonjs { ParseGoal::Script } else { ParseGoal::Module },
                        force_lane: Some(lane),
                        ..OrchestratorConfig::default()
                    },
                    RuntimeConfig::default(),
                ).unwrap();
                let result = engine.execute(&ExtensionPackage {
                    extension_id: "conditional-array-fallback".into(),
                    source: std::fs::read_to_string(root.path().join(entrypoint)).unwrap(),
                    source_file: Some(root.path().join(entrypoint).display().to_string()),
                    module_root: Some(root.path().display().to_string()),
                    capabilities: capabilities.iter().map(ToString::to_string).collect(),
                    version: "1.0.0".into(),
                    metadata: BTreeMap::new(),
                }).unwrap_or_else(|error| panic!("live {entrypoint} {lane:?}: {error}"));
                assert_eq!(result.console_output.iter().map(|line| line.message.clone())
                    .collect::<Vec<_>>(), expected, "live {entrypoint} {lane:?}");
                assert_eq!(execute_with_capabilities(resolver.clone(), root.path(), commonjs,
                    lane, &capabilities).unwrap(), expected, "frozen {entrypoint} {lane:?}");
            }
            // Replay redoes selection from the capsule's original manifest
            // bytes and negative routes, not from the live package directory.
            let replayed = capsule::replay(sealed.bytes(), sealed.digest()).unwrap();
            let replay_resolver = Arc::new(CapturedEngineResolver::new(replayed, &pin).ok().unwrap());
            assert_eq!(execute(replay_resolver, root.path(), commonjs), expected);
        }
    }

    #[test]
    fn frozen_readline_diagnostics_retain_missing_capability_refusals() {
        for name in ["readline", "readline/promises", "diagnostics_channel"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("app.cjs"),
                format!("require('{name}'); console.log('unreachable');")).unwrap();
            let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            for missing in [RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin, RuntimeCapability::Timer] {
                let grants: Vec<_> = [RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin, RuntimeCapability::Timer]
                    .into_iter().filter(|capability| *capability != missing).collect();
                let error = execute_with_capabilities(
                    resolver.clone(), root.path(), true, LaneChoice::QuickJs, &grants,
                ).expect_err("native factories do not widen the captured execution's authority");
                assert!(error.contains(&missing.to_string()), "{name} / {missing}: {error}");
                assert!(!error.contains("unreachable"), "{error}");
            }
        }
    }

    #[test]
    fn frozen_diagnostics_callbacks_do_not_gain_host_write_authority() {
        let root = tempfile::tempdir().unwrap();
        let forbidden = root.path().join("forbidden.txt");
        let filename = serde_json::to_string(&forbidden.display().to_string()).unwrap();
        std::fs::write(
            root.path().join("app.cjs"),
            format!(
                r#"
const diagnostics = require('diagnostics_channel');
const fs = require('fs');
diagnostics.subscribe('attempt', function () {{
    console.log('callback entered');
    fs.writeFileSync({filename}, 'wrong');
}});
diagnostics.channel('attempt').publish(42);
console.log('unreachable');
"#
            ),
        )
        .unwrap();
        let graph = capture(root.path(), "app.cjs", GraphOptions::default()).unwrap();
        let pin = graph.report().input_hash.clone();
        let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let error = execute_with_capabilities(
                resolver.clone(),
                root.path(),
                true,
                lane,
                &[
                    RuntimeCapability::ModuleLoad,
                    RuntimeCapability::Builtin,
                    RuntimeCapability::Timer,
                ],
            )
            .expect_err("a subscriber callback keeps the guest's original authority");
            assert!(error.contains("capability denied: fs:write"), "{lane:?}: {error}");
            assert!(error.contains("callback entered"), "{lane:?}: {error}");
            assert!(!error.contains("unreachable"), "{lane:?}: {error}");
            assert!(!forbidden.exists());
        }
    }

    #[test]
    fn frozen_diagnostics_esm_refuses_guest_or_snapshot_getters() {
        for mutation in [
            "Object.defineProperty(dc.Channel.prototype, 'hasSubscribers', {get: function hasSubscribers() { console.log('guest getter ran'); return true; }});",
            "const get = Object.getOwnPropertyDescriptor(dc.Channel.prototype, 'hasSubscribers').get; Object.defineProperty(dc, 'channel', {get: get});",
        ] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("mutator.cjs"),
                format!("const dc=require('diagnostics_channel'); {mutation}")).unwrap();
            std::fs::write(root.path().join("app.mjs"),
                "import './mutator.cjs'; import {channel} from 'node:diagnostics_channel'; console.log('unreachable');").unwrap();
            let graph = capture(root.path(), "app.mjs", GraphOptions::default()).unwrap();
            let pin = graph.report().input_hash.clone();
            let resolver = Arc::new(CapturedEngineResolver::new(graph, &pin).ok().unwrap());
            let error = execute_with_capabilities(
                resolver, root.path(), false, LaneChoice::QuickJs,
                &[RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin, RuntimeCapability::Timer],
            ).expect_err("namespace publication cannot execute an unaudited getter");
            assert!(error.contains("bounded-import contract"), "{mutation}: {error}");
            assert!(!error.contains("guest getter ran") && !error.contains("unreachable"), "{error}");
        }
    }
}
