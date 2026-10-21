//! Bound Bun catalogs for captured project/workspace declarations.
//!
//! Spec: https://bun.com/docs/pm/catalogs. Catalogs are root-owned range
//! indirection, not another installer, a registry lookup or an override grant.
//! The lock and manifest must agree before an indexed resolver is constructed.
//! Raw manifest/lock bytes stay fingerprinted by Capture. Only the private
//! project declaration projection is expanded, after raw workspace binding.

use super::super::{
    Capture, MAX_METADATA_BYTES, MAX_PACKAGES, SECTIONS, alias, bounded_text, graph, name,
    time_remaining, workspaces,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::time::Instant;

const MAX_CATALOGS: usize = 128;
const MAX_CATALOG_NAME_BYTES: usize = 128;

type Definitions = BTreeMap<String, BTreeMap<String, String>>;

/// Constructed only after independently parsed root/lock definitions match.
/// The private parent module exposes this to admission, not to guest code.
pub(in super::super) struct Catalogs {
    definitions: Definitions,
}

#[derive(Default)]
struct Budget {
    entries: usize,
    bytes: usize,
}

impl Budget {
    fn account(&mut self, bytes: usize, deadline: Instant) -> Result<()> {
        time_remaining(deadline)?;
        self.entries = self.entries.checked_add(1).context("Bun catalog count overflow")?;
        self.bytes = self.bytes.checked_add(bytes).context("Bun catalog byte count overflow")?;
        ensure!(self.entries <= MAX_PACKAGES && self.bytes <= MAX_METADATA_BYTES,
            "Bun catalog expansion exceeds its shared entry/byte budget");
        Ok(())
    }
}

fn catalog_name(value: &str) -> Result<&str> {
    ensure!(value.len() <= MAX_CATALOG_NAME_BYTES && !value.chars().any(char::is_control),
        "invalid or oversized Bun catalog name");
    let name = value.trim();
    Ok(if name == "default" { "" } else { name })
}

pub(super) fn request_text(value: &Value) -> Result<&str> {
    if let Some(text) = value.as_str().filter(|text| text.starts_with("catalog:")) {
        ensure!(text.len() <= 4096, "Bun catalog reference exceeds its text bound");
        catalog_name(&text["catalog:".len()..])?;
        Ok(text)
    } else {
        bounded_text(value, "Bun dependency request")
    }
}

fn add_catalog(
    definitions: &mut Definitions,
    label: &str,
    value: &Value,
    budget: &mut Budget,
    deadline: Instant,
) -> Result<()> {
    let label = catalog_name(label)?;
    let entries = value.as_object().context("Bun catalog must be a dependency map")?;
    for (package, request) in entries {
        name(package)?;
        let request = bounded_text(request, "Bun catalog request")?;
        let (_, requirement) = alias(package, Some(request))?;
        // A mismatch against this fixed witness still means a valid range.
        // An opaque request, recursion, or unversioned alias does not. The
        // actual installed version is checked later by the same checker.
        let review = graph::version_review(requirement, Some("0.0.0"));
        ensure!(review.is_none_or(|(code, _)| code == "dependency_version_mismatch"),
            "Bun catalog entries require supported registry ranges or versioned npm aliases");
        budget.account(label.len() + package.len() + request.len(), deadline)?;
        if !definitions.contains_key(label) {
            ensure!(definitions.len() < MAX_CATALOGS, "Bun catalog namespace limit exceeded");
        }
        let catalog = definitions.entry(label.to_owned()).or_default();
        ensure!(!catalog.contains_key(package),
            "duplicate Bun catalog dependency after default/name normalization");
        catalog.insert(package.clone(), request.to_owned());
    }
    time_remaining(deadline)
}

fn collect_fields(
    object: &Map<String, Value>,
    definitions: &mut Definitions,
    budget: &mut Budget,
    deadline: Instant,
) -> Result<()> {
    if let Some(value) = object.get("catalog") {
        add_catalog(definitions, "", value, budget, deadline)?;
    }
    if let Some(value) = object.get("catalogs") {
        let catalogs = value.as_object().context("Bun catalogs must be a map of dependency maps")?;
        ensure!(catalogs.len() <= MAX_CATALOGS, "Bun catalog namespace limit exceeded");
        for (label, value) in catalogs {
            time_remaining(deadline)?;
            add_catalog(definitions, label, value, budget, deadline)?;
        }
    }
    Ok(())
}

/// Bun's object form is a selector list plus root catalog definitions. Do
/// not silently discard unimplemented layout controls such as selfContained
/// or nohoist. npm callers never enter this Bun-only projection.
pub(super) fn workspace_selectors(manifest: &Map<String, Value>) -> Result<Option<&Vec<Value>>> {
    match manifest.get("workspaces") {
        None => Ok(None),
        Some(Value::Array(selectors)) => Ok(Some(selectors)),
        Some(Value::Object(options)) => {
            ensure!(options.keys().all(|key| ["packages", "catalog", "catalogs"].contains(&key.as_str())),
                "unsupported Bun workspace object field; layout controls require separate review");
            options.get("packages").and_then(Value::as_array).map(Some)
                .context("Bun workspace object requires a packages selector array")
        }
        _ => anyhow::bail!("Bun workspaces must be an array or a supported workspace object"),
    }
}

impl Catalogs {
    pub(in super::super) fn bind(
        manifest: &Map<String, Value>,
        lock: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Self> {
        time_remaining(deadline)?;
        let mut declared = Definitions::new();
        let mut recorded = Definitions::new();
        let mut budget = Budget::default();
        workspace_selectors(manifest)?;
        collect_fields(manifest, &mut declared, &mut budget, deadline)?;
        if let Some(Value::Object(options)) = manifest.get("workspaces") {
            // One definition budget across BOTH root placements. Duplicate
            // keys after namespace normalization remain errors, not overrides.
            collect_fields(options, &mut declared, &mut budget, deadline)?;
        }
        collect_fields(lock, &mut recorded, &mut Budget::default(), deadline)?;
        ensure!(declared == recorded,
            "Bun catalog definitions differ between captured package.json and bun.lock");
        Ok(Self { definitions: declared })
    }

    pub(in super::super) fn has_entries(&self) -> bool {
        !self.definitions.is_empty()
    }

    /// Adapt the already-bound root's workspace syntax to the existing
    /// descriptor-relative selector. Do not use lockfile workspace paths as
    /// selectors, and do not alter any on-disk manifest or fingerprint.
    pub(in super::super) fn capture_workspaces(
        &self,
        capture: &mut Capture,
        mut root: Value,
    ) -> Result<BTreeMap<String, Value>> {
        time_remaining(capture.deadline)?;
        let object = root.as_object_mut().context("Bun root manifest must be an object")?;
        workspace_selectors(object)?;
        if let Some(Value::Object(options)) = object.get_mut("workspaces") {
            // Move rather than clone a potentially large selector vector.
            // The common selector retains its own count/path/glob budgets.
            let selectors = options.remove("packages").context("Bun workspace selectors missing")?;
            object.insert("workspaces".into(), selectors);
        }
        workspaces::capture(capture, root)
    }

    fn resolve<'a>(&'a self, package: &str, request: &str) -> Result<Option<&'a str>> {
        let Some(label) = request.strip_prefix("catalog:") else { return Ok(None); };
        let label = catalog_name(label)?;
        self.definitions.get(label).and_then(|entries| entries.get(package))
            .map(|request| Some(request.as_str()))
            .context("Bun catalog reference has no pinned dependency in the selected catalog")
    }

    /// Expand owned project metadata only AFTER matching the raw captured
    /// workspace declarations to the lock. Installed registry manifests never
    /// enter this method. No filesystem input or caller's lock is rewritten.
    pub(in super::super) fn expand(
        &self,
        projects: &mut BTreeMap<String, Value>,
        deadline: Instant,
    ) -> Result<()> {
        let mut budget = Budget::default();
        for (directory, manifest) in projects {
            time_remaining(deadline)?;
            let manifest = manifest.as_object_mut().context("Bun project manifest must be an object")?;
            if !directory.is_empty() {
                for field in ["catalog", "catalogs"] {
                    ensure!(manifest.get(field).is_none_or(|value|
                        value.as_object().is_some_and(Map::is_empty)),
                        "Bun catalogs are root-owned; workspace-local catalog definitions require review");
                }
            }
            for field in SECTIONS {
                let Some(value) = manifest.get_mut(*field) else { continue; };
                let entries = value.as_object_mut().context("Bun dependency section must be an object")?;
                // Validate even losing/optional declarations. Missing catalogs
                // cannot disappear behind optional absence or dev precedence.
                for (package, value) in entries {
                    name(package)?;
                    let request = request_text(value)?;
                    let resolved = self.resolve(package, request)?;
                    budget.account(resolved.map_or(0, str::len), deadline)?;
                    if let Some(resolved) = resolved { *value = Value::String(resolved.to_owned()); }
                }
            }
        }
        time_remaining(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{inspect, inspect_for_execution};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(15) }
    fn bind(manifest: Value, lock: Value) -> Result<Catalogs> {
        Catalogs::bind(manifest.as_object().unwrap(), lock.as_object().unwrap(), deadline())
    }
    fn put(root: &Path, path: &str, value: &Value) {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn fixture(manifest: &Value, root_record: &Value, packages: Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let mut lock = json!({"lockfileVersion":2,"configVersion":0,
            "workspaces":{"":root_record},"packages":packages});
        for field in ["catalog", "catalogs"] {
            if let Some(value) = manifest.get(field) { lock[field] = value.clone(); }
        }
        put(root.path(), "package.json", manifest);
        put(root.path(), "bun.lock", &lock);
        root
    }
    fn ordinary(request: &str) -> tempfile::TempDir {
        let manifest = json!({"catalog":{"a":"^1"},"dependencies":{"a":request}});
        fixture(&manifest, &json!({"dependencies":{"a":request}}),
            json!({"a":["a@1.2.3","",{},""]}))
    }
    fn install(root: &Path, manifest: Value) {
        put(root, "node_modules/a/package.json", &manifest);
        fs::write(root.join("node_modules/a/index.js"),
            "throw Error('catalog inspection must not execute source');").unwrap();
    }

    #[test]
    fn default_named_and_default_alias_catalogs_share_one_bound_index() {
        let definitions = json!({"catalog":{"a":"^1"},
            "catalogs":{"default":{"b":"~2.0"},"testing":{"a":"npm:@scope/real@^3"}}});
        let context = bind(definitions.clone(), definitions).unwrap();
        for request in ["catalog:", "catalog:default", "catalog:   "] {
            assert_eq!(context.resolve("a", request).unwrap(), Some("^1"));
        }
        assert_eq!(context.resolve("b", "catalog:default").unwrap(), Some("~2.0"));
        assert_eq!(context.resolve("a", "catalog:testing").unwrap(), Some("npm:@scope/real@^3"));
        assert_eq!(context.resolve("a", "^8").unwrap(), None);
        assert!(context.resolve("absent", "catalog:").is_err());
        assert!(context.resolve("a", "catalog:missing").is_err());
        assert!(context.resolve("a", "catalog:TESTING").is_err());
    }

    #[test]
    fn stale_ambiguous_recursive_and_opaque_definitions_are_refused() {
        assert!(bind(json!({"catalog":{"a":"^1"}}), json!({"catalog":{"a":"^2"}})).is_err());
        for definitions in [
            json!({"catalog":null}), json!({"catalogs":{"testing":"^1"}}),
            json!({"catalog":{"a":"1"},"catalogs":{"default":{"a":"1"}}}),
            json!({"catalogs":{"testing":{"a":"1"}," testing ":{"a":"1"}}}),
            json!({"catalog":{"a":"catalog:loop"}}),
            json!({"catalog":{"a":"workspace:*"}}),
            json!({"catalog":{"a":"latest"}}),
            json!({"catalog":{"a":"npm:other"}}),
            json!({"catalog":{"a":"https://example.invalid/a.tgz"}}),
            json!({"catalog":{"a":""}}),
        ] {
            assert!(bind(definitions.clone(), definitions).is_err());
        }
        let empty = bind(json!({"catalog":{},"catalogs":{"default":{}}}), json!({})).unwrap();
        assert!(!empty.has_entries());
    }

    #[test]
    fn catalog_admission_keeps_raw_inputs_and_requires_the_actual_installation() {
        for request in ["catalog:", "catalog:default", "catalog:   "] {
            let root = ordinary(request);
            let raw_manifest = fs::read(root.path().join("package.json")).unwrap();
            let raw_lock = fs::read(root.path().join("bun.lock")).unwrap();
            let metadata = inspect(root.path(), deadline()).unwrap();
            assert!(!metadata.requires_review(), "{metadata:?}");
            assert!(!metadata.installation_checked);
            assert!(inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
            install(root.path(), json!({"name":"a","version":"1.2.3"}));
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(!report.requires_review(), "{report:?}");
            assert!(report.installation_checked);
            assert!(report.scope.contains("catalog"));
            for (path, bytes) in [("package.json", &raw_manifest), ("bun.lock", &raw_lock)] {
                let input = report.inputs.iter().find(|input| input.path == path).unwrap();
                assert_eq!(input.sha256, hex::encode(Sha256::digest(bytes)));
                assert_eq!(fs::read(root.path().join(path)).unwrap(), *bytes);
            }
            assert_eq!(report, inspect_for_execution(root.path(), deadline()).unwrap());
            install(root.path(), json!({"name":"a","version":"1.9.0"}));
            assert!(inspect_for_execution(root.path(), deadline()).unwrap().findings.iter()
                .any(|finding| finding.code == "installed_identity_mismatch"));
        }
    }

    #[test]
    fn catalog_ranges_and_aliases_do_not_bypass_version_or_native_review() {
        for (effective, identity, code) in [
            ("^2", "a@1.2.3", "dependency_version_mismatch"),
            ("npm:sharp@^1", "sharp@1.2.3", "native_addon"),
            ("npm:other@^1", "a@1.2.3", "unresolved_declaration"),
        ] {
            let root = fixture(&json!({"catalog":{"a":effective},"dependencies":{"a":"catalog:"}}),
                &json!({"dependencies":{"a":"catalog:"}}), json!({"a":[identity,"",{},""]}));
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(report.findings.iter().any(|finding| finding.code == code), "{report:?}");
            assert!(!report.installation_checked);
        }
        let root = fixture(&json!({"catalogs":{"testing":{"a":"npm:@scope/real@^1"}},
            "devDependencies":{"a":"catalog:testing"}}),
            &json!({"devDependencies":{"a":"catalog:testing"}}),
            json!({"a":["@scope/real@1.2.3","",{},""]}));
        install(root.path(), json!({"name":"@scope/real","version":"1.2.3"}));
        assert!(!inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
    }

    #[test]
    fn missing_catalogs_cannot_hide_in_optional_losing_or_published_edges() {
        for record in [
            json!({"optionalDependencies":{"a":"catalog:missing"}}),
            json!({"dependencies":{"a":"catalog:missing"},"devDependencies":{"a":"1"}}),
        ] {
            let root = fixture(&record, &record, json!({}));
            assert!(inspect(root.path(), deadline()).is_err());
        }
        let manifest = json!({"catalog":{"a":"1"},"dependencies":{"outer":"1"}});
        let root = fixture(&manifest, &json!({"dependencies":{"outer":"1"}}), json!({
            "outer":["outer@1.0.0","",{"optionalDependencies":{"a":"catalog:"}},""]}));
        assert!(inspect(root.path(), deadline()).is_err());
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", &json!({"catalog":{"a":"1"},"dependencies":{"a":"catalog:"}}));
        put(root.path(), "package-lock.json", &json!({"lockfileVersion":3,"packages":{
            "node_modules/a":{"version":"1.0.0"}}}));
        let report = inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.code == "unverifiable_dependency_version"));
    }

    #[test]
    fn expansion_validates_all_sections_and_does_not_retain_a_global_cache() {
        let context = bind(json!({"catalog":{"a":"1"}}), json!({"catalog":{"a":"1"}})).unwrap();
        let mut projects = BTreeMap::new();
        for (index, section) in SECTIONS.iter().enumerate() {
            projects.insert(format!("packages/{index}"), json!({(*section):{"a":"catalog:"}}));
        }
        context.expand(&mut projects, deadline()).unwrap();
        for manifest in projects.values() {
            for section in SECTIONS {
                if let Some(entries) = manifest.get(*section) { assert_eq!(entries["a"], "1"); }
            }
        }
        let new = bind(json!({"catalog":{"a":"2"}}), json!({"catalog":{"a":"2"}})).unwrap();
        assert_eq!(context.resolve("a", "catalog:").unwrap(), Some("1"));
        assert_eq!(new.resolve("a", "catalog:").unwrap(), Some("2"));
        let mut local = BTreeMap::from([("packages/a".into(), json!({"catalog":{"a":"9"}}))]);
        assert!(context.expand(&mut local, deadline()).is_err());
    }

    #[test]
    fn catalog_deadline_namespace_and_aggregate_expansion_budgets_fail_closed() {
        assert!(Catalogs::bind(&Map::new(), &Map::new(), Instant::now()).is_err());
        let mut budget = Budget { entries: MAX_PACKAGES, bytes: 0 };
        assert!(budget.account(0, deadline()).is_err());
        let mut budget = Budget { entries: 0, bytes: MAX_METADATA_BYTES };
        assert!(budget.account(1, deadline()).is_err());
        let catalogs: Map<String, Value> = (0..MAX_CATALOGS + 1)
            .map(|index| (format!("c{index}"), json!({"a":"1"}))).collect();
        let value = json!({"catalogs":catalogs});
        assert!(bind(value.clone(), value).is_err());
    }

    fn workspace_fixture(isolated: bool) -> (tempfile::TempDir, Value, Value) {
        let manifest = json!({"name":"root",
            "workspaces":{"packages":["packages/*"],"catalog":{"a":"^1"},
                "catalogs":{"tooling":{"tool":"npm:@tools/real@~2.0"}}},
            "dependencies":{"@demo/app":"workspace:*"}});
        let member = json!({"name":"@demo/app","version":"1.0.0",
            "dependencies":{"a":"catalog:"},"devDependencies":{"tool":"catalog:tooling"}});
        let lock = json!({"lockfileVersion":2,"configVersion":0,
            "catalog":{"a":"^1"},"catalogs":{"tooling":{"tool":"npm:@tools/real@~2.0"}},
            "workspaces":{"":{"name":"root","dependencies":{"@demo/app":"workspace:*"}},
                "packages/app":member},
            "packages":{"@demo/app":["@demo/app@workspace:packages/app"],
                "a":["a@1.2.3","",{},""],"tool":["@tools/real@2.0.1","",{},""]}});
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", &manifest);
        put(root.path(), "bun.lock", &lock);
        put(root.path(), "packages/app/package.json", &member);
        fs::write(root.path().join("packages/app/index.js"), "throw Error('not executed');").unwrap();
        fs::create_dir_all(root.path().join("node_modules/@demo")).unwrap();
        std::os::unix::fs::symlink("../../packages/app", root.path().join("node_modules/@demo/app")).unwrap();
        for (slot, package, version) in [("a", "a", "1.2.3"), ("tool", "@tools/real", "2.0.1")] {
            let location = if isolated {
                format!("node_modules/.bun/{slot}@{version}/node_modules/{slot}")
            } else { format!("node_modules/{slot}") };
            put(root.path(), &format!("{location}/package.json"), &json!({"name":package,"version":version}));
            fs::write(root.path().join(&location).join("index.js"), "throw Error('not executed');").unwrap();
            if isolated {
                std::os::unix::fs::symlink(format!(".bun/{slot}@{version}/node_modules/{slot}"),
                    root.path().join("node_modules").join(slot)).unwrap();
            }
        }
        (root, manifest, lock)
    }

    #[test]
    fn object_workspace_catalogs_reach_hoisted_and_isolated_staged_admission() {
        for isolated in [false, true] {
            let (root, manifest, lock) = workspace_fixture(isolated);
            let raw_member = fs::read(root.path().join("packages/app/package.json")).unwrap();
            let report = inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(!report.requires_review(), "isolated={isolated}: {report:?}");
            assert!(report.installation_checked);
            assert_eq!(report.packages_scanned, 3);
            // Hoisted: one workspace link and two registry directories.
            // Isolated: those registry positions are aliases, with two
            // additional physical store positions; no manifest is reread
            // through either alias.
            assert_eq!(report.installed_packages_scanned, if isolated { 5 } else { 3 });
            assert_eq!(report.manifests_scanned, 4);
            for (slot, version) in [("a", "1.2.3"), ("tool", "2.0.1")] {
                let position = format!("node_modules/{slot}");
                let manifest_path = if isolated {
                    let target = format!(".bun/{slot}@{version}/node_modules/{slot}");
                    let link = report.inputs.iter().find(|input| input.path == position).unwrap();
                    assert_eq!(link.bytes, target.len());
                    assert_eq!(link.sha256, hex::encode(Sha256::digest(target.as_bytes())));
                    assert!(!report.inputs.iter().any(|input| input.path == format!("{position}/package.json")));
                    format!("node_modules/{target}/package.json")
                } else { format!("{position}/package.json") };
                let input = report.inputs.iter().find(|input| input.path == manifest_path).unwrap();
                let bytes = fs::read(root.path().join(&manifest_path)).unwrap();
                assert_eq!(input.sha256, hex::encode(Sha256::digest(&bytes)));
            }
            assert!(report.scope.contains("catalog"));
            for (path, raw) in [("package.json", serde_json::to_vec(&manifest).unwrap()),
                ("bun.lock", serde_json::to_vec(&lock).unwrap()), ("packages/app/package.json", raw_member)] {
                let input = report.inputs.iter().find(|input| input.path == path).unwrap();
                assert_eq!(input.sha256, hex::encode(Sha256::digest(&raw)));
                assert_eq!(fs::read(root.path().join(path)).unwrap(), raw);
            }
            assert_eq!(report, inspect_for_execution(root.path(), deadline()).unwrap());
        }
    }

    #[test]
    fn workspace_catalog_indirection_never_erases_raw_binding_or_lifecycle_findings() {
        for mode in ["equivalent-reference", "lifecycle", "local-catalog"] {
            let (root, _, lock) = workspace_fixture(false);
            let mut member = lock["workspaces"]["packages/app"].clone();
            match mode {
                // Both expand to ^1, but the source and lock did not agree.
                "equivalent-reference" => member["dependencies"]["a"] = "catalog:default".into(),
                "lifecycle" => member["scripts"] = json!({"prepare":"touch catalog-must-not-run"}),
                _ => member["catalog"] = json!({"a":"^9"}),
            }
            put(root.path(), "packages/app/package.json", &member);
            let result = inspect_for_execution(root.path(), deadline());
            if mode == "local-catalog" {
                assert!(result.is_err());
            } else {
                let report = result.unwrap();
                let code = if mode == "lifecycle" { "install_script" } else { "workspace_review" };
                assert!(report.findings.iter().any(|finding| finding.code == code), "{report:?}");
                assert!(!report.installation_checked);
            }
            assert!(!root.path().join("catalog-must-not-run").exists());
            assert!(!root.path().join("packages/app/catalog-must-not-run").exists());
        }
    }

    #[test]
    fn embedded_and_top_level_catalogs_share_binding_and_duplicate_detection() {
        let root = json!({"catalog":{"a":"1"},"workspaces":{"packages":[],
            "catalogs":{"testing":{"tool":"2"}}}});
        let recorded = json!({"catalog":{"a":"1"},"catalogs":{"testing":{"tool":"2"}}});
        let catalogs = bind(root.clone(), recorded.clone()).unwrap();
        assert_eq!(catalogs.resolve("a", "catalog:").unwrap(), Some("1"));
        assert_eq!(catalogs.resolve("tool", "catalog:testing").unwrap(), Some("2"));
        let mut duplicate = root.clone();
        duplicate["workspaces"]["catalog"] = json!({"a":"1"});
        assert!(bind(duplicate, recorded.clone()).is_err());
        let mut stale = root;
        stale["workspaces"]["catalogs"]["testing"]["tool"] = "3".into();
        assert!(bind(stale, recorded).is_err());
    }

    #[test]
    fn object_workspace_selectors_cannot_grant_lock_only_or_unknown_layout_authority() {
        for options in [json!({"packages":"packages/*"}), json!({"catalog":{}}),
            json!({"packages":[],"selfContained":true}),
            json!({"packages":[],"nohoist":["**"]}), json!({"packages":[],"unknown":false})] {
            assert!(bind(json!({"workspaces":options}), json!({})).is_err());
        }
        let (root, mut manifest, _) = workspace_fixture(false);
        manifest["workspaces"]["packages"] = json!([]);
        put(root.path(), "package.json", &manifest);
        assert!(inspect_for_execution(root.path(), deadline()).is_err());
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", &json!({"workspaces":{"packages":[]}}));
        put(root.path(), "package-lock.json", &json!({"lockfileVersion":3,"packages":{}}));
        assert!(inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn catalog_workspace_still_checks_native_payloads_and_exact_private_routes() {
        let (root, _, mut lock) = workspace_fixture(false);
        // A compatible hoist cannot replace the pinned private installation.
        lock["packages"]["@demo/app/a"] = json!(["a@1.2.3","",{},""]);
        put(root.path(), "bun.lock", &lock);
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding|
            finding.code == "installed_dependency_route_mismatch"
                && finding.source == "packages/app/package.json#dependencies"), "{report:?}");
        let (root, _, _) = workspace_fixture(true);
        fs::write(root.path().join("node_modules/.bun/a@1.2.3/node_modules/a/native.node"), b"not executable").unwrap();
        let report = inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.code == "native_payload"), "{report:?}");
    }
}
