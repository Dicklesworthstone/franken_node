//! Bun text-lock admission for captured, hoisted registry/workspace packages.
//!
//! The v1/v2 package tuples and slash-separated installation keys are decoded
//! into the existing internal installation graph. This is not an npm lockfile
//! export, a Bun installer, or an assertion that a mutable installation matches.
//! The original bun.lock bytes remain the evidence input, and checked execution
//! still inspects every installed manifest/edge/native/lifecycle marker.
//! Workspace tuples grant nothing by themselves: the common admission path
//! independently selects and binds real manifests before inspecting link text.
//!
//! References: bun.com/docs/pm/lockfile and Bun's
//! test/cli/install/lockfile-version-2.test.ts at
//! 281698ac9380110414b293017531b39466014ad3. No Bun implementation is copied.

use super::{MAX_DEPTH, MAX_LOCK_BYTES, MAX_METADATA_BYTES, MAX_PACKAGES, SECTIONS,
    bounded_text, graph, name, parse_unique, relative, time_remaining};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

#[path = "dependency_bun_catalogs.rs"]
mod catalogs;
pub(super) use catalogs::Catalogs;

const MAX_WORKSPACES: usize = 1024;

fn checkpoint(index: usize, next: &mut usize, deadline: Instant) -> Result<()> {
    if index >= *next {
        time_remaining(deadline)?;
        *next = index + 4096;
    }
    Ok(())
}

/// Strip only JSONC comments/trailing commas, preserving byte offsets and
/// string contents. Unique keys, JSON grammar and resource limits are still
/// enforced by the same parser as npm. Never use this for package.json.
pub(super) fn parse(bytes: &[u8], deadline: Instant) -> Result<Value> {
    time_remaining(deadline)?;
    ensure!(bytes.len() <= MAX_LOCK_BYTES, "Bun lockfile byte limit exceeded");
    std::str::from_utf8(bytes).context("Bun lockfile must be UTF-8")?;
    let mut text = bytes.to_vec();
    if text.starts_with(&[0xef, 0xbb, 0xbf]) { text[..3].fill(b' '); }
    let mut index = 0;
    let mut next = 0;
    while index < text.len() {
        checkpoint(index, &mut next, deadline)?;
        match text[index] {
            b'"' => { index = string_end(&text, index, &mut next, deadline)?; }
            0xe2 if unicode_line_separator(&text, index) => {
                // JSONC uses JavaScript comment terminators. Preserve the
                // newline boundary instead of letting // hide the next key.
                text[index..index + 3].fill(b' ');
                text[index] = b'\n';
                index += 3;
            }
            b'/' if text.get(index + 1) == Some(&b'/') => {
                while index < text.len() && !matches!(text[index], b'\r' | b'\n')
                    && !unicode_line_separator(&text, index)
                {
                    checkpoint(index, &mut next, deadline)?;
                    text[index] = b' ';
                    index += 1;
                }
            }
            b'/' if text.get(index + 1) == Some(&b'*') => {
                text[index..index + 2].fill(b' ');
                index += 2;
                loop {
                    checkpoint(index, &mut next, deadline)?;
                    ensure!(index < text.len(), "unterminated Bun lockfile comment");
                    if text[index] == b'*' && text.get(index + 1) == Some(&b'/') {
                        text[index..index + 2].fill(b' ');
                        index += 2;
                        break;
                    }
                    if !matches!(text[index], b'\r' | b'\n') { text[index] = b' '; }
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }
    index = 0;
    next = 0;
    let mut previous = None;
    while index < text.len() {
        checkpoint(index, &mut next, deadline)?;
        let byte = text[index];
        if byte == b'"' {
            index = string_end(&text, index, &mut next, deadline)?;
            previous = Some(b'"');
            continue;
        }
        if byte == b',' {
            let mut after = index + 1;
            while after < text.len() && json_space(text[after]) {
                checkpoint(after, &mut next, deadline)?;
                after += 1;
            }
            // Empty elements and repeated commas are invalid JSONC too. Do
            // not turn [,], {"x":,}, or [1,,] into valid empty/value forms.
            if matches!(text.get(after), Some(b']' | b'}'))
                && previous.is_some_and(|b| !matches!(b, b'[' | b'{' | b':' | b','))
            {
                text[index] = b' ';
                index += 1;
                continue;
            }
        }
        if !json_space(byte) { previous = Some(byte); }
        index += 1;
    }
    time_remaining(deadline)?;
    parse_unique(&text, deadline)
}

fn json_space(byte: u8) -> bool { matches!(byte, b' ' | b'\t' | b'\r' | b'\n') }

fn unicode_line_separator(text: &[u8], index: usize) -> bool {
    text.get(index..index + 3)
        .is_some_and(|bytes| bytes == b"\xe2\x80\xa8" || bytes == b"\xe2\x80\xa9")
}

fn string_end(text: &[u8], start: usize, next: &mut usize, deadline: Instant) -> Result<usize> {
    let mut index = start + 1;
    while index < text.len() {
        checkpoint(index, next, deadline)?;
        match text[index] {
            b'"' => return Ok(index + 1),
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    bail!("unterminated Bun lockfile string")
}

fn no_resolution_controls(object: &Map<String, Value>) -> Result<()> {
    for field in ["overrides", "resolutions", "patchedDependencies"] {
        if let Some(value) = object.get(field) {
            ensure!(value.as_object().is_some_and(Map::is_empty),
                "Bun {field} needs explicit resolution/patch review before checked execution");
        }
    }
    if let Some(value) = object.get("trustedDependencies") {
        ensure!(value.as_array().is_some_and(Vec::is_empty),
            "Bun trustedDependencies needs explicit lifecycle review before checked execution");
    }
    Ok(())
}

fn declarations(record: &mut Map<String, Value>, root: bool, deadline: Instant) -> Result<()> {
    for key in record.keys() {
        ensure!(SECTIONS.contains(&key.as_str())
            || ["name", "version", "optionalPeers", "bin", "os", "cpu", "hasInstallScript"].contains(&key.as_str()),
            "unsupported Bun package metadata field: {key}");
    }
    for field in SECTIONS {
        if let Some(value) = record.get(*field) {
            let entries = value.as_object().context("Bun dependency section must be an object")?;
            ensure!(root || *field != "devDependencies" || entries.is_empty(),
                "installed Bun package cannot contribute development dependencies");
            for (package, requirement) in entries {
                time_remaining(deadline)?;
                name(package)?;
                let request = catalogs::request_text(requirement)?;
                ensure!(root || !request.starts_with("catalog:"),
                    "published Bun package cannot inherit a project's catalog definitions");
            }
        }
    }
    if let Some(value) = record.remove("optionalPeers") {
        let peers = value.as_array().context("Bun optionalPeers must be an array")?;
        let mut metadata = Map::new();
        for peer in peers {
            time_remaining(deadline)?;
            let peer = name(bounded_text(peer, "Bun optional peer")?)?;
            ensure!(record.get("peerDependencies").and_then(Value::as_object)
                .is_some_and(|entries| entries.contains_key(peer)), "Bun optional peer has no declaration");
            ensure!(metadata.insert(peer.into(), json!({"optional":true})).is_none(),
                "duplicate Bun optional peer");
        }
        if !metadata.is_empty() { record.insert("peerDependenciesMeta".into(), Value::Object(metadata)); }
    }
    for field in ["os", "cpu"] {
        if let Some(value) = record.get(field) {
            if let Some(entries) = value.as_array() {
                for entry in entries {
                    time_remaining(deadline)?;
                    bounded_text(entry, "Bun platform selector")?;
                }
            } else { bounded_text(value, "Bun platform selector")?; }
        }
    }
    if let Some(value) = record.get("bin") {
        if let Some(entries) = value.as_object() {
            for (command, target) in entries {
                time_remaining(deadline)?;
                name(command)?;
                bounded_text(target, "Bun bin target")?;
            }
        } else { bounded_text(value, "Bun bin target")?; }
    }
    super::flag(record, "hasInstallScript")?;
    Ok(())
}

/// Each slash separates an installed package except the slash inside a scoped
/// name. No URL, version suffix, dot segment, store identifier or host path is
/// accepted as an installation key. Scoped parents stay whole at every level.
fn installation_path(key: &str) -> Result<String> {
    relative(key)?;
    let mut parts = key.split('/');
    let mut path = String::new();
    let mut depth = 0;
    while let Some(first) = parts.next() {
        depth += 1;
        ensure!(depth <= MAX_DEPTH, "Bun installation nesting exceeds limit");
        let package = if first.starts_with('@') {
            format!("{first}/{}", parts.next().context("incomplete Bun package scope")?)
        } else { first.to_owned() };
        name(&package)?;
        ensure!(!package.starts_with('.') && package != "node_modules",
            "reserved Bun installation component");
        if !path.is_empty() { path.push('/'); }
        path.push_str("node_modules/");
        path.push_str(&package);
        ensure!(path.len() <= 4096, "Bun installation path exceeds limit");
    }
    relative(&path)?;
    Ok(path)
}

fn tuple_record(tuple: Value, deadline: Instant) -> Result<Value> {
    let Value::Array(mut tuple) = tuple else { bail!("Bun package must be a tuple"); };
    ensure!(tuple.len() == 4, "only Bun registry package tuples are admitted; file/Git/workspace/tarball forms need review");
    let integrity = tuple.pop().context("Bun package integrity missing")?;
    let metadata = tuple.pop().context("Bun package metadata missing")?;
    let resolved = tuple.pop().context("Bun package resolution missing")?;
    let identity = tuple.pop().context("Bun package identity missing")?;
    let identity = bounded_text(&identity, "Bun package identity")?;
    let (package, version) = identity.rsplit_once('@').context("Bun package identity has no version")?;
    name(package)?;
    ensure!(graph::version_review(Some(version), Some(version)).is_none(),
        "Bun package identity must contain a concrete registry version");
    for value in [&resolved, &integrity] {
        let text = value.as_str().context("Bun resolution/integrity must be a string")?;
        ensure!(text.len() <= 4096 && !text.chars().any(char::is_control),
            "invalid Bun resolution/integrity text");
    }
    let Value::Object(mut metadata) = metadata else { bail!("Bun package metadata must be an object"); };
    // Tuple identity is authoritative; conflicting redundant fields cannot
    // overwrite it during conversion. The original bytes remain pinned.
    ensure!(!metadata.contains_key("name") && !metadata.contains_key("version"),
        "Bun tuple metadata duplicates package identity");
    declarations(&mut metadata, false, deadline)?;
    metadata.insert("name".into(), package.into());
    metadata.insert("version".into(), version.into());
    metadata.insert("resolved".into(), resolved);
    metadata.insert("integrity".into(), integrity);
    Ok(Value::Object(metadata))
}

/// Internal projection only: reuse the SAME graph/version/installed checks as
/// npm, but keep the source filename and original-byte hash as Bun evidence.
/// Workspace links are projected only to explicitly named source directories.
/// Their identities and declarations are subsequently bound to real captured
/// manifests by workspaces::bind_links. Isolated stores are NOT inferred from
/// configVersion: execution admission still checks the actual hoisted layout.
pub(super) fn project_lock(lock: Value, manifest: &Value, deadline: Instant) -> Result<(Value, Catalogs)> {
    time_remaining(deadline)?;
    let Value::Object(mut document) = lock else { bail!("Bun lockfile must be an object"); };
    for key in document.keys() {
        ensure!(["lockfileVersion", "configVersion", "workspaces", "packages", "trustedDependencies",
            "overrides", "resolutions", "patchedDependencies", "catalog", "catalogs"].contains(&key.as_str()),
            "unsupported Bun lockfile field: {key}");
    }
    ensure!(matches!(document.get("lockfileVersion").and_then(Value::as_u64), Some(1 | 2)),
        "unsupported Bun text lockfileVersion; expected 1 or 2");
    if let Some(value) = document.get("configVersion") {
        ensure!(matches!(value.as_u64(), Some(0 | 1)), "unsupported Bun configVersion");
    }
    no_resolution_controls(&document)?;
    let manifest = manifest.as_object().context("Bun project manifest must be an object")?;
    no_resolution_controls(manifest)?;
    let catalogs = Catalogs::bind(manifest, &document, deadline)?;
    let selectors = manifest.get("workspaces").map(|value|
        value.as_array().context("Bun workspaces must be an array of captured selectors")
    ).transpose()?;
    let workspaces = document.remove("workspaces").context("Bun workspaces missing")?;
    let Value::Object(mut workspaces) = workspaces else { bail!("Bun workspaces must be an object"); };
    ensure!(workspaces.len() <= MAX_WORKSPACES && workspaces.contains_key(""),
        "Bun workspaces must include the root and fit the manifest bound");
    ensure!(workspaces.len() == 1 || selectors.is_some_and(|values| !values.is_empty()),
        "Bun lock declares workspaces not selected by the project manifest");
    let root = workspaces.remove("").context("Bun root workspace missing")?;
    let Value::Object(mut root) = root else { bail!("Bun root workspace must be an object"); };
    declarations(&mut root, true, deadline)?;
    let empty = Map::new();
    for field in SECTIONS.iter().copied().chain(["peerDependenciesMeta"]) {
        let actual = match manifest.get(field) { None => Some(&empty), Some(value) => value.as_object() };
        let recorded = match root.get(field) { None => Some(&empty), Some(value) => value.as_object() };
        ensure!(actual.is_some() && actual == recorded,
            "Bun root {field} differs from captured package.json; stale lock requires review");
    }
    let entries = document.remove("packages").context("Bun packages missing")?;
    let Value::Object(entries) = entries else { bail!("Bun packages must be an object"); };
    ensure!(entries.len() <= MAX_PACKAGES, "Bun package count exceeds limit");
    let mut names = BTreeSet::new();
    if let Some(value) = manifest.get("name") {
        names.insert(name(bounded_text(value, "Bun root name")?)?.to_owned());
    }
    let mut packages = Map::new();
    packages.insert(String::new(), Value::Object(root));
    let mut retained = serde_json::to_vec(&packages)?.len();
    let mut workspace_names = BTreeMap::new();
    for (directory, record) in workspaces {
        time_remaining(deadline)?;
        workspace_directory(&directory)?;
        let Value::Object(mut record) = record else { bail!("Bun workspace must be an object"); };
        declarations(&mut record, true, deadline)?;
        let package = name(bounded_text(record.get("name").context("Bun workspace name missing")?,
            "Bun workspace name")?)?.to_owned();
        let version = bounded_text(record.get("version").context("Bun workspace version missing")?,
            "Bun workspace version")?;
        ensure!(graph::version_review(Some(version), Some(version)).is_none(),
            "Bun workspace needs a concrete captured version, not an invented default");
        ensure!(names.insert(package.clone()), "duplicate Bun workspace/root package name");
        workspace_names.insert(package, directory.clone());
        let record = Value::Object(record);
        account_record(&directory, &record, &mut retained)?;
        ensure!(packages.insert(directory, record).is_none(), "duplicate Bun workspace directory");
    }
    let mut virtual_records = Map::new();
    let mut workspace_links = BTreeMap::new();
    for (key, tuple) in entries {
        time_remaining(deadline)?;
        let path = installation_path(&key)?;
        let record = if let Some(tuple) = tuple.as_array().filter(|tuple| tuple.len() == 1) {
            let identity = bounded_text(&tuple[0], "Bun workspace tuple")?;
            let (package, target) = identity.split_once("@workspace:")
                .context("only explicit workspace tuples may omit registry metadata")?;
            name(package)?;
            workspace_directory(target)?;
            ensure!(key == package && workspace_names.get(package).is_some_and(|path| path == target),
                "Bun workspace link must be the canonical root name and its recorded workspace target");
            workspace_links.insert(path.clone(), target.to_owned());
            json!({"link":true,"resolved":target})
        } else { tuple_record(tuple, deadline)? };
        account_record(&path, &record, &mut retained)?;
        ensure!(virtual_records.insert(path, record).is_none(), "duplicate Bun installation identity");
    }
    // A nested key cannot create an unrecorded parent installation. This also
    // refuses isolated-store spellings rather than treating them as hoists.
    for path in virtual_records.keys() {
        let mut current = path.as_str();
        while let Some((parent, _)) = current.rsplit_once("/node_modules/") {
            time_remaining(deadline)?;
            ensure!(virtual_records.contains_key(parent), "Bun nested package has no recorded parent");
            current = parent;
        }
    }
    ensure!(workspace_links.len() == workspace_names.len(),
        "Bun workspace is missing its canonical root installation link");
    for (path, record) in virtual_records {
        time_remaining(deadline)?;
        // Node resolves from a workspace's physical directory, not from the
        // lexical node_modules symlink. Preserve private versions there. This
        // is one indexed lookup per record, never a scan of all workspaces.
        let physical = if let Some((root_link, rest)) = path.split_once("/node_modules/") {
            workspace_links.get(root_link).map(|target| format!("{target}/node_modules/{rest}"))
        } else { None };
        let physical = physical.unwrap_or_else(|| path.clone());
        retained = retained.checked_add(physical.len().saturating_sub(path.len()))
            .context("Bun graph path byte count overflow")?;
        ensure!(retained <= MAX_METADATA_BYTES, "Bun projected graph exceeds byte limit");
        relative(&physical)?;
        ensure!(physical.split('/').count() <= MAX_DEPTH,
            "Bun physical installation exceeds path depth bound");
        ensure!(packages.len() <= MAX_PACKAGES, "Bun projected package count exceeds limit");
        ensure!(packages.insert(physical, record).is_none(), "Bun projected installation paths collide");
    }
    time_remaining(deadline)?;
    Ok((json!({"lockfileVersion":3,"packages":packages}), catalogs))
}

fn workspace_directory(directory: &str) -> Result<()> {
    relative(directory)?;
    ensure!(directory.split('/').count() <= MAX_DEPTH && directory.split('/').all(|part|
        !["node_modules", ".bun", ".git", ".beads", ".franken-node", ".franken-rewrite", ".migrate-backup"].contains(&part)),
        "Bun workspace target must be an ordinary project source directory");
    Ok(())
}

fn account_record(path: &str, record: &Value, retained: &mut usize) -> Result<()> {
    let size = serde_json::to_vec(record)?.len();
    *retained = retained.checked_add(size).and_then(|n| n.checked_add(path.len() + 16))
        .context("Bun graph byte count overflow")?;
    ensure!(*retained <= MAX_METADATA_BYTES, "Bun projected graph exceeds byte limit");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;
    use sha2::{Digest, Sha256};

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(10) }
    fn lock(root: Value, packages: Value) -> Value {
        json!({"lockfileVersion":2,"configVersion":1,"workspaces":{"":root},"packages":packages})
    }
    fn tuple(name: &str, metadata: Value) -> Value { json!([name,"",metadata,""]) }
    fn fixture(manifest: &Value, lock: &Value) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("package.json"), serde_json::to_vec(manifest).unwrap()).unwrap();
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(lock).unwrap()).unwrap();
        root
    }
    fn installed(root: &std::path::Path, path: &str, manifest: Value) {
        fs::create_dir_all(root.join(path)).unwrap();
        fs::write(root.join(path).join("package.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(root.join(path).join("index.js"), "throw Error('inspection must never evaluate me');").unwrap();
    }

    #[test]
    fn jsonc_preserves_strings_comments_unicode_and_original_key_validation() {
        let input = br#"{ // comment
          "url": "https://registry.example/a//b/*literal*/", /* block */
          "escaped": "quote: \" slash: \\", "array": [1,2,],
        }"#;
        let parsed = parse(input, deadline()).unwrap();
        assert_eq!(parsed["url"], "https://registry.example/a//b/*literal*/");
        assert_eq!(parsed["escaped"], "quote: \" slash: \\");
        assert_eq!(parsed["array"], json!([1,2]));
        assert!(parse("{\"π\":1,}".as_bytes(), deadline()).is_ok());
        assert!(parse(b"\xef\xbb\xbf{\"a\":1,}", deadline()).is_ok());
        for separator in ['\u{2028}', '\u{2029}'] {
            let source = format!("{{\"a\":1,// comment{separator}\"b\":2}} ");
            assert_eq!(parse(source.as_bytes(), deadline()).unwrap(), json!({"a":1,"b":2}));
            let duplicate = format!("{{\"a\":1,// comment{separator}\"a\":2\n}}");
            assert!(parse(duplicate.as_bytes(), deadline()).is_err());
            let literal = format!("{{\"a\":\"{separator}\"}}");
            assert_eq!(parse(literal.as_bytes(), deadline()).unwrap()["a"], separator.to_string());
        }
        for input in [r#"{"a":1,"\u0061":2,}"#, "[, ]", "[1,,]", r#"{"a":,}"#,
            "/*", "{}{}", "[1, /* missing", "{\"a\":\"unterminated}"] {
            assert!(parse(input.as_bytes(), deadline()).is_err(), "{input}");
        }
        assert!(parse(b"{}", Instant::now()).is_err());
        assert!(parse(b"//\xff\n{}", deadline()).is_err());
        assert!(parse(&vec![b' '; MAX_LOCK_BYTES + 1], deadline()).is_err());
    }

    #[test]
    fn scoped_and_nested_installation_keys_have_exact_hoisted_locations() {
        for (key, expected) in [
            ("a", "node_modules/a"),
            ("@scope/a", "node_modules/@scope/a"),
            ("a/@scope/b/c", "node_modules/a/node_modules/@scope/b/node_modules/c"),
            ("@a/x/@b/y", "node_modules/@a/x/node_modules/@b/y"),
        ] { assert_eq!(installation_path(key).unwrap(), expected); }
        for key in ["", "/a", "a//b", "a/../b", "a/./b", "@scope", "a/@scope", "a@1.0.0", ".bun/a", "node_modules/a", "a\\b"] {
            assert!(installation_path(key).is_err(), "{key}");
        }
    }

    #[test]
    fn both_supported_versions_reach_the_live_metadata_gate_and_pin_original_bytes() {
        let manifest = json!({"dependencies":{"ordinary":"^1"}});
        for version in [1,2] {
            let mut document = lock(manifest.clone(), json!({"ordinary":tuple("ordinary@1.2.3", json!({}))}));
            document["lockfileVersion"] = version.into();
            let root = fixture(&manifest, &document);
            let compact = serde_json::to_string(&document).unwrap();
            let raw = format!("// actual Bun input\n{},\n}}", &compact[..compact.len() - 1]);
            fs::write(root.path().join("bun.lock"), &raw).unwrap();
            let report = super::super::inspect(root.path(), deadline()).unwrap();
            assert!(!report.requires_review(), "{report:?}");
            assert_eq!(report.packages_scanned, 1);
            assert!(!report.installation_checked);
            assert!(report.scope.contains("Bun"));
            let input = report.inputs.iter().find(|input| input.path == "bun.lock").unwrap();
            assert_eq!(input.sha256, hex::encode(Sha256::digest(raw.as_bytes())));
            assert_eq!(input.bytes, raw.len());
            assert!(!root.path().join("node_modules").exists());
            assert_eq!(report, super::super::inspect(root.path(), deadline()).unwrap());
        }
    }

    #[test]
    fn actual_staged_installation_remains_mandatory_and_code_is_never_executed() {
        let manifest = json!({"dependencies":{"ordinary":"1"}});
        let root = fixture(&manifest, &lock(manifest.clone(), json!({"ordinary":tuple("ordinary@1.2.3", json!({}))})));
        assert!(super::super::inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
        installed(root.path(), "node_modules/ordinary", json!({"name":"ordinary","version":"1.2.3"}));
        let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.installation_checked);
        assert_eq!(report.installed_packages_scanned, 1);
        assert!(!report.requires_review(), "{report:?}");
        assert!(report.scope.contains("Bun"));
        installed(root.path(), "node_modules/ordinary", json!({"name":"ordinary","version":"1.2.4"}));
        assert!(super::super::inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
    }

    #[test]
    fn aliases_nested_versions_and_transitive_requirements_use_the_shared_graph() {
        let manifest = json!({"dependencies":{"parent":"1","alias":"npm:@scope/actual@2","dep":"2"}});
        let document = lock(manifest.clone(), json!({
            "parent":tuple("parent@1.0.0",json!({"dependencies":{"dep":"1"}})),
            "parent/dep":tuple("dep@1.1.0",json!({})),
            "dep":tuple("dep@2.0.0",json!({})),
            "alias":tuple("@scope/actual@2.0.0",json!({}))
        }));
        let root = fixture(&manifest, &document);
        let report = super::super::inspect(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        assert_eq!(report.packages_scanned, 4);
        let mut stale = document;
        stale["packages"]["parent/dep"][0] = "dep@2.0.0".into();
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&stale).unwrap()).unwrap();
        let report = super::super::inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|f| f.code == "dependency_version_mismatch"
            && f.source.starts_with("bun.lock#node_modules/parent#")));
    }

    #[test]
    fn optional_peers_are_translated_without_exempting_wrong_present_versions() {
        let manifest = json!({"dependencies":{"parent":"1"}});
        let mut document = lock(manifest.clone(), json!({"parent":tuple("parent@1.0.0",json!({
            "peerDependencies":{"peer":"^2"},"optionalPeers":["peer"],"optionalDependencies":{"absent":"1"}
        }))}));
        let root = fixture(&manifest, &document);
        assert!(!super::super::inspect(root.path(), deadline()).unwrap().requires_review());
        document["packages"]["peer"] = tuple("peer@1.0.0",json!({}));
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(super::super::inspect(root.path(), deadline()).unwrap().requires_review());
        assert!(tuple_record(tuple("p@1.0.0",json!({"optionalPeers":["missing"]})),deadline()).is_err());
    }

    #[test]
    fn lifecycle_and_native_markers_are_not_lost_in_bun_conversion() {
        let manifest = json!({"dependencies":{"ordinary":"1"}});
        let root = fixture(&manifest, &lock(manifest.clone(), json!({"ordinary":tuple("ordinary@1.0.0",json!({}))})));
        installed(root.path(), "node_modules/ordinary", json!({"name":"ordinary","version":"1.0.0","scripts":{"postinstall":"touch forbidden"}}));
        let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|f| f.code == "install_script"));
        assert!(!root.path().join("forbidden").exists());
        fs::write(root.path().join("node_modules/ordinary/binding.gyp"), "{}").unwrap();
        assert!(super::super::inspect_for_execution(root.path(), deadline()).unwrap().requires_review());
    }

    #[test]
    fn stale_roots_unsupported_protocols_and_unknown_semantics_fail_closed() {
        let root = json!({"dependencies":{"a":"1"}});
        let good = lock(root.clone(), json!({"a":tuple("a@1.0.0",json!({}))}));
        assert!(project_lock(good.clone(), &json!({"dependencies":{"a":"2"}}), deadline()).is_err());
        for version in [0,3,999] {
            let mut changed = good.clone(); changed["lockfileVersion"] = version.into();
            assert!(project_lock(changed, &root, deadline()).is_err());
        }
        for field in ["overrides","resolutions","patchedDependencies","catalog","catalogs"] {
            let mut changed = good.clone(); changed[field] = json!({"a":"2"});
            assert!(project_lock(changed, &root, deadline()).is_err(), "{field}");
        }
        let mut changed = good.clone(); changed["trustedDependencies"] = json!(["a"]);
        assert!(project_lock(changed, &root, deadline()).is_err());
        let mut changed = good.clone(); changed["workspaces"]["packages/a"] = json!({"name":"a"});
        assert!(project_lock(changed, &root, deadline()).is_err());
        for descriptor in [json!(["a@file:../outside",{}]), json!(["a@workspace:packages/a"]),
            tuple("a@https://example.invalid/a.tgz",json!({})),tuple("a@1.0.0",json!({"unknownLoadRule":true}))] {
            assert!(tuple_record(descriptor,deadline()).is_err());
        }
        assert!(project_lock(lock(json!({}),json!({"missing/child":tuple("child@1.0.0",json!({}))})),&json!({}),deadline()).is_err());
    }

    #[test]
    fn npm_and_bun_authorities_cannot_be_mixed_or_jsonc_enabled_for_npm() {
        let document = lock(json!({}), json!({}));
        let root = fixture(&json!({}), &document);
        fs::write(root.path().join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{}}"#).unwrap();
        assert!(super::super::inspect(root.path(), deadline()).is_err());
        assert!(parse_unique(br#"{"lockfileVersion":3,"packages":{},}"#, deadline()).is_err());
        let root = fixture(&json!({}), &document);
        fs::write(root.path().join("package.json"), "{/* not Bun */}").unwrap();
        assert!(super::super::inspect(root.path(), deadline()).is_err());
    }

    #[test]
    fn bun_metadata_links_and_isolated_install_links_are_not_followed() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("lock"), serde_json::to_vec(&lock(json!({}),json!({}))).unwrap()).unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("package.json"), "{}").unwrap();
        symlink(outside.path().join("lock"),root.path().join("bun.lock")).unwrap();
        assert!(super::super::inspect(root.path(),deadline()).is_err());
        let manifest = json!({"dependencies":{"ordinary":"1"}});
        let root = fixture(&manifest,&lock(manifest.clone(),json!({"ordinary":tuple("ordinary@1.0.0",json!({}))})));
        fs::create_dir(root.path().join("node_modules")).unwrap();
        symlink(outside.path(),root.path().join("node_modules/ordinary")).unwrap();
        assert!(super::super::inspect_for_execution(root.path(),deadline()).unwrap().requires_review());
    }

    fn workspace_fixture() -> (tempfile::TempDir, Value, Value) {
        let manifest = json!({"workspaces":["packages/*"],
            "dependencies":{"@demo/app":"^1","private":"^1"}});
        let member = json!({"name":"@demo/app","version":"1.0.0",
            "dependencies":{"private":"^1","hoisted":"^2"}});
        let mut document = lock(json!({"dependencies":{"@demo/app":"^1","private":"^1"}}), json!({
            "@demo/app":["@demo/app@workspace:packages/app"],
            "@demo/app/private":tuple("private@1.1.0",json!({"dependencies":{"@nested/value":"^3"}})),
            "@demo/app/private/@nested/value":tuple("@nested/value@3.1.0",json!({})),
            "private":tuple("private@1.0.0",json!({})),
            "hoisted":tuple("hoisted@2.0.0",json!({}))
        }));
        document["configVersion"] = 0.into();
        document["workspaces"]["packages/app"] = member.clone();
        let root = fixture(&manifest, &document);
        installed(root.path(), "packages/app", member);
        installed(root.path(), "packages/app/node_modules/private",
            json!({"name":"private","version":"1.1.0","dependencies":{"@nested/value":"^3"}}));
        installed(root.path(), "packages/app/node_modules/private/node_modules/@nested/value",
            json!({"name":"@nested/value","version":"3.1.0"}));
        installed(root.path(), "node_modules/private", json!({"name":"private","version":"1.0.0"}));
        installed(root.path(), "node_modules/hoisted", json!({"name":"hoisted","version":"2.0.0"}));
        fs::create_dir_all(root.path().join("node_modules/@demo")).unwrap();
        std::os::unix::fs::symlink("../../packages/app", root.path().join("node_modules/@demo/app")).unwrap();
        (root, manifest, document)
    }

    #[test]
    fn hoisted_workspaces_bind_real_manifests_and_physical_private_dependencies() {
        let (root, manifest, document) = workspace_fixture();
        let (projected, _) = project_lock(document, &manifest, deadline()).unwrap();
        assert_eq!(projected["packages"]["node_modules/@demo/app"]["resolved"], "packages/app");
        assert_eq!(projected["packages"]["packages/app/node_modules/private"]["version"], "1.1.0");
        assert!(projected["packages"].get("node_modules/@demo/app/node_modules/private").is_none());
        let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        assert!(report.installation_checked);
        assert_eq!(report.packages_scanned, 5);
        assert_eq!(report.installed_packages_scanned, 5);
        for input in &report.inputs {
            assert_eq!(input.sha256, hex::encode(Sha256::digest(fs::read(root.path().join(&input.path)).unwrap())));
        }
        assert!(report.inputs.iter().any(|input| input.path == "packages/app/package.json"));
        assert_eq!(report, super::super::inspect_for_execution(root.path(), deadline()).unwrap());
    }

    #[test]
    fn absent_private_workspace_copy_cannot_use_a_compatible_hoisted_copy() {
        let (root, _, _) = workspace_fixture();
        fs::rename(root.path().join("packages/app/node_modules/private"),
            root.path().join("packages/app/retained-private")).unwrap();
        let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding|
            finding.code == "installed_dependency_route_mismatch"
                && finding.source == "packages/app/package.json#dependencies"
                && finding.installed_as == "private"
                && finding.package_path.as_deref() == Some("packages/app/node_modules/private")),
            "{report:?}");
    }

    #[test]
    fn stale_workspace_identity_edges_and_lifecycle_fail_before_runtime_admission() {
        for changed in [
            json!({"name":"@demo/app","version":"2.0.0","dependencies":{"private":"^1","hoisted":"^2"}}),
            json!({"name":"@demo/app","version":"1.0.0","dependencies":{"private":"^1","hoisted":"^2","hidden":"1"}}),
            json!({"name":"@demo/app","version":"1.0.0","dependencies":{"private":"^1","hoisted":"^2"},
                "scripts":{"prepare":"touch forbidden-workspace-effect"}}),
        ] {
            let (root, _, _) = workspace_fixture();
            installed(root.path(), "packages/app", changed);
            let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
            assert!(report.requires_review(), "{report:?}");
            assert!(!report.installation_checked);
            assert!(!root.path().join("forbidden-workspace-effect").exists());
        }
    }

    #[test]
    fn workspace_tuples_cannot_invent_identity_targets_or_nested_links() {
        let (_, manifest, document) = workspace_fixture();
        for descriptor in [
            json!(["@demo/app@workspace:../outside"]),
            json!(["@demo/app@workspace:node_modules/other"]),
            json!(["@demo/app@workspace:packages/absent"]),
            json!(["other@workspace:packages/app"]),
            json!(["@demo/app@file:packages/app"]),
        ] {
            let mut changed = document.clone();
            changed["packages"]["@demo/app"] = descriptor;
            assert!(project_lock(changed, &manifest, deadline()).is_err());
        }
        let mut missing = document.clone();
        missing["packages"].as_object_mut().unwrap().remove("@demo/app");
        assert!(project_lock(missing, &manifest, deadline()).is_err());
        let mut nested = document.clone();
        nested["packages"]["private/@demo/app"] = json!(["@demo/app@workspace:packages/app"]);
        assert!(project_lock(nested, &manifest, deadline()).is_err());
        let mut duplicate = document;
        duplicate["workspaces"]["packages/other"] = duplicate["workspaces"]["packages/app"].clone();
        assert!(project_lock(duplicate, &manifest, deadline()).is_err());
    }

    #[test]
    fn lock_only_workspace_cannot_clear_unselected_link_review() {
        let (root, mut manifest, mut document) = workspace_fixture();
        manifest["workspaces"] = json!(["packages/app"]);
        let extra = json!({"name":"extra","version":"1.0.0"});
        document["workspaces"]["packages/extra"] = extra.clone();
        document["packages"]["extra"] = json!(["extra@workspace:packages/extra"]);
        fs::write(root.path().join("package.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(root.path().join("bun.lock"), serde_json::to_vec(&document).unwrap()).unwrap();
        installed(root.path(), "packages/extra", extra);
        let report = super::super::inspect(root.path(), deadline()).unwrap();
        assert!(report.findings.iter().any(|finding| finding.code == "local_link"
            && finding.package_path.as_deref() == Some("node_modules/extra")), "{report:?}");
        assert!(!report.inputs.iter().any(|input| input.path == "packages/extra/package.json"));
    }

    #[test]
    fn hoisted_workspace_cycles_use_bounded_shared_graph_checks() {
        let manifest = json!({"workspaces":["packages/*"]});
        let a = json!({"name":"a","version":"1.0.0","dependencies":{"b":"^1"}});
        let b = json!({"name":"b","version":"1.1.0","dependencies":{"a":"^1"}});
        let document = json!({"lockfileVersion":2,"configVersion":0,
            "workspaces":{"":{},"packages/a":a,"packages/b":b},
            "packages":{"a":["a@workspace:packages/a"],"b":["b@workspace:packages/b"]}});
        let root = fixture(&manifest, &document);
        installed(root.path(), "packages/a", document["workspaces"]["packages/a"].clone());
        installed(root.path(), "packages/b", document["workspaces"]["packages/b"].clone());
        fs::create_dir(root.path().join("node_modules")).unwrap();
        for name in ["a", "b"] {
            std::os::unix::fs::symlink(format!("../packages/{name}"),
                root.path().join("node_modules").join(name)).unwrap();
        }
        let report = super::super::inspect_for_execution(root.path(), deadline()).unwrap();
        assert!(!report.requires_review(), "{report:?}");
        assert!(report.installation_checked);
        assert_eq!(report.packages_scanned, 2);
    }
}
