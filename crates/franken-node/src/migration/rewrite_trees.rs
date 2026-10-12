//! Exact, bounded images for create-only directory-tree installation (Linux).
//!
//! A tree is one absent root plus a complete inventory of regular descendants.
//! Staging never touches a live project. The transaction layer must publish its
//! durable journal before renaming the staged root with NOREPLACE. This module
//! never follows links, invokes project code, removes files, or grants approval.

use anyhow::{Context, Result, ensure};
use rustix::fs::{Dir, Mode, OFlags, mkdirat, openat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

const SCHEMA: &str = "franken-node/rewrite-tree-image/v1";
pub const MAX_ENTRIES: usize = 1_000;
pub const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_TREE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;

/// A descendant of the new root. None denotes a directory, not an empty file.
/// Every parent is explicit, and modes are part of the approved image.
pub struct Entry<'a> {
    pub path: &'a str,
    pub contents: Option<&'a [u8]>,
    pub mode: u32,
}

/// One project-relative root that does not yet exist. Descendants are relative
/// to that root. The caller owns source inspection, validation and installation.
pub struct CreateTree<'a> {
    pub path: &'a str,
    pub mode: u32,
    pub entries: &'a [Entry<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub files: usize,
    /// Includes the new root itself.
    pub directories: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ImageData {
    Directory,
    File { bytes: usize, sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageEntry {
    path: String,
    mode: u32,
    data: ImageData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    schema_version: String,
    mode: u32,
    entries: Vec<ImageEntry>,
}

fn relative(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    ensure!(!path.is_empty() && path.len() <= 4096 && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && parsed.components().all(|part| matches!(part, Component::Normal(_)))
        && parsed.components().map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>().join("/") == path
        && !parsed.components().any(|part| part.as_os_str() == ".git"),
        "tree image requires canonical, non-reserved relative paths");
    Ok(())
}

fn permissions(mode: u32, directory: bool) -> Result<()> {
    let required = if directory { 0o500 } else { 0o400 };
    ensure!(mode <= 0o777 && mode & required == required,
        "tree entries require ordinary owner-readable permissions and searchable directories");
    Ok(())
}

impl Image {
    fn validate(&self) -> Result<Summary> {
        ensure!(self.schema_version == SCHEMA && self.entries.len() < MAX_ENTRIES,
            "unsupported or oversized tree image inventory");
        permissions(self.mode, true)?;
        let mut summary = Summary { files: 0, directories: 1, bytes: 0 };
        let mut directories = BTreeSet::from([String::new()]);
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            relative(&entry.path)?;
            ensure!(previous.is_none_or(|path| path < entry.path.as_str()),
                "tree image paths must be unique and canonically ordered");
            previous = Some(&entry.path);
            let parent = Path::new(&entry.path).parent().unwrap_or_else(|| Path::new(""));
            ensure!(directories.contains(parent.to_str().context("non-UTF-8 tree parent")?),
                "tree image omits a parent directory or places children beneath a file");
            permissions(entry.mode, matches!(&entry.data, ImageData::Directory))?;
            match &entry.data {
                ImageData::Directory => {
                    directories.insert(entry.path.clone());
                    summary.directories += 1;
                }
                ImageData::File { bytes, sha256 } => {
                    ensure!(*bytes <= MAX_FILE_BYTES && sha256.len() == 64
                        && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                        "invalid tree file size or SHA-256");
                    summary.bytes = summary.bytes.checked_add(*bytes).context("tree byte overflow")?;
                    ensure!(summary.bytes <= MAX_TREE_BYTES, "tree image exceeds byte budget");
                    summary.files += 1;
                }
            }
        }
        Ok(summary)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_INDEX_BYTES, "tree index exceeds metadata budget");
        let image: Self = serde_json::from_slice(bytes).context("invalid tree image index")?;
        image.validate()?;
        ensure!(serde_json::to_vec(&image)? == bytes, "tree index is not canonical");
        Ok(image)
    }
}

/// Canonical content/mode identity. Source bytes are hashed, never embedded in
/// the index or Debug output. Empty files remain distinct from directories.
pub fn encode(tree: &CreateTree<'_>) -> Result<(Vec<u8>, Summary)> {
    relative(tree.path)?;
    ensure!(tree.entries.len() < MAX_ENTRIES, "tree image exceeds entry budget");
    let mut image = Image { schema_version: SCHEMA.into(), mode: tree.mode, entries: Vec::new() };
    let mut total = 0_usize;
    for entry in tree.entries {
        relative(&format!("{}/{}", tree.path, entry.path))?;
        let data = match entry.contents {
            None => ImageData::Directory,
            Some(bytes) => {
                total = total.checked_add(bytes.len()).context("tree byte overflow")?;
                ensure!(bytes.len() <= MAX_FILE_BYTES && total <= MAX_TREE_BYTES,
                    "tree image exceeds byte budget");
                ImageData::File { bytes: bytes.len(), sha256: hex::encode(Sha256::digest(bytes)) }
            }
        };
        image.entries.push(ImageEntry { path: entry.path.into(), mode: entry.mode, data });
    }
    image.entries.sort_by(|a, b| a.path.cmp(&b.path));
    let summary = image.validate()?;
    let encoded = serde_json::to_vec(&image)?;
    ensure!(encoded.len() <= MAX_INDEX_BYTES, "tree index exceeds metadata budget");
    Ok((encoded, summary))
}

/// Re-derive the counts committed by an enclosing journal; never trust counts
/// supplied separately from the canonical index.
pub fn summarize(index: &[u8]) -> Result<Summary> {
    Image::decode(index)?.validate()
}

/// The enclosing journal must bind this mode as well as descendant counts.
pub fn root_mode(index: &[u8]) -> Result<u32> {
    Ok(Image::decode(index)?.mode)
}

fn directory(parent: &File, name: &OsStr) -> Result<File> {
    Ok(File::from(openat(parent, name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty())?))
}

fn parent<'a>(directories: &'a BTreeMap<String, File>, path: &str) -> Result<(&'a File, OsString)> {
    let path = Path::new(path);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let fd = directories.get(parent.to_str().context("non-UTF-8 tree parent")?)
        .context("missing held tree parent")?;
    Ok((fd, path.file_name().context("missing tree leaf")?.to_owned()))
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.len() == b.len() && a.mode() == b.mode()
        && a.mtime() == b.mtime() && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime() && a.ctime_nsec() == b.ctime_nsec()
}

/// Build a private, durable tree in a transaction-owned directory. Never reuse
/// a pre-existing staging name. A preparation failure retains recovery material
/// privately and cannot publish a partial tree into the live project.
pub fn stage(parent_fd: &File, leaf: &OsStr, tree: &CreateTree<'_>, index: &[u8]) -> Result<()> {
    ensure!(!leaf.as_bytes().contains(&b'/') && !leaf.as_bytes().contains(&0)
        && Path::new(leaf).components().count() == 1
        && matches!(Path::new(leaf).components().next(), Some(Component::Normal(_))),
        "tree staging name must be one normal component");
    let (actual, _) = encode(tree)?;
    ensure!(actual == index, "tree source differs from its prepared index");
    let image = Image::decode(index)?;
    let source: BTreeMap<_, _> = tree.entries.iter().map(|entry| (entry.path, entry.contents)).collect();
    mkdirat(parent_fd, leaf, Mode::from_raw_mode(0o700))?;
    let root = directory(parent_fd, leaf)?;
    root.set_permissions(Permissions::from_mode(0o700))?;
    let mut directories = BTreeMap::from([(String::new(), root)]);
    for entry in &image.entries {
        let (fd, name) = parent(&directories, &entry.path)?;
        match &entry.data {
            ImageData::Directory => {
                mkdirat(fd, &name, Mode::from_raw_mode(0o700))?;
                let child = directory(fd, &name)?;
                child.set_permissions(Permissions::from_mode(0o700))?;
                directories.insert(entry.path.clone(), child);
            }
            ImageData::File { .. } => {
                let bytes = source.get(entry.path.as_str()).and_then(|value| *value)
                    .context("tree file source missing")?;
                let mut file = File::from(openat(fd, &name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600))?);
                file.write_all(bytes)?;
                file.set_permissions(Permissions::from_mode(entry.mode))?;
                file.sync_all().context("tree file durability barrier")?;
            }
        }
    }
    // Descendants become durable before parents. Assign final directory modes
    // last, so a reviewed read-only directory can still be prepared safely.
    for entry in image.entries.iter().rev() {
        if matches!(&entry.data, ImageData::Directory) {
            let fd = &directories[&entry.path];
            fd.set_permissions(Permissions::from_mode(entry.mode))?;
            fd.sync_all().context("tree directory durability barrier")?;
        }
    }
    directories[""].set_permissions(Permissions::from_mode(image.mode))?;
    directories[""].sync_all().context("tree root durability barrier")?;
    parent_fd.sync_all().context("tree staging parent durability barrier")?;
    Ok(())
}

/// Verify the complete root, including absence of unrecorded descendants. This
/// is a local identity check, not authentication of an untrusted index. Held
/// NOFOLLOW descriptors prevent ordinary symlink redirection. The enclosing
/// writer lock coordinates cooperators; arbitrary editors are not sandboxed.
pub fn verify(parent_fd: &File, leaf: &OsStr, index: &[u8]) -> Result<Option<Metadata>> {
    let image = Image::decode(index)?;
    ensure!(!leaf.as_bytes().contains(&b'/') && !leaf.as_bytes().contains(&0)
        && Path::new(leaf).components().count() == 1
        && matches!(Path::new(leaf).components().next(), Some(Component::Normal(_))),
        "tree verification name must be one normal component");
    let root = match directory(parent_fd, leaf) {
        Ok(root) => root,
        Err(error) if error.downcast_ref::<rustix::io::Errno>() == Some(&rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("open tree root without following links"),
    };
    let before = root.metadata()?;
    ensure!(before.mode() & 0o7777 == image.mode, "tree root permissions changed");
    let mut directories = BTreeMap::from([(String::new(), root)]);
    let mut observed = BTreeMap::from([(String::new(), before.clone())]);
    let mut expected: BTreeMap<String, BTreeSet<OsString>> = BTreeMap::from([(String::new(), BTreeSet::new())]);
    for entry in &image.entries {
        let path = Path::new(&entry.path);
        let parent_path = path.parent().unwrap_or_else(|| Path::new(""));
        expected.entry(parent_path.to_str().context("non-UTF-8 tree parent")?.into())
            .or_default().insert(path.file_name().context("missing tree filename")?.to_owned());
        let (fd, name) = parent(&directories, &entry.path)?;
        match &entry.data {
            ImageData::Directory => {
                let child = directory(fd, &name)?;
                let metadata = child.metadata()?;
                ensure!(metadata.dev() == before.dev() && metadata.mode() & 0o7777 == entry.mode,
                    "tree directory device or permissions changed");
                observed.insert(entry.path.clone(), metadata);
                directories.insert(entry.path.clone(), child);
                expected.entry(entry.path.clone()).or_default();
            }
            ImageData::File { bytes, sha256 } => {
                let mut file = File::from(openat(fd, &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty())?);
                let metadata = file.metadata()?;
                ensure!(metadata.is_file() && metadata.nlink() == 1 && metadata.dev() == before.dev()
                    && metadata.len() == *bytes as u64 && metadata.mode() & 0o7777 == entry.mode,
                    "tree file type, aliasing, length or permissions changed");
                let mut hasher = Sha256::new();
                let mut consumed = 0_usize;
                let mut buffer = [0_u8; 65536];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 { break; }
                    consumed = consumed.checked_add(count).context("tree file read overflow")?;
                    ensure!(consumed <= *bytes, "tree file grew during verification");
                    hasher.update(&buffer[..count]);
                }
                ensure!(consumed == *bytes && hex::encode(hasher.finalize()) == *sha256
                    && same_version(&metadata, &file.metadata()?), "tree file contents changed");
                let reopened = File::from(openat(fd, &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty())?);
                ensure!(same_version(&metadata, &reopened.metadata()?), "tree file path changed during verification");
            }
        }
    }
    let mut entries_seen = 0_usize;
    for (path, fd) in &directories {
        let mut names = BTreeSet::new();
        for entry in Dir::read_from(fd)? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." { continue; }
            entries_seen += 1;
            ensure!(entries_seen < MAX_ENTRIES, "tree directory inventory exceeds budget");
            ensure!(names.insert(OsString::from_vec(bytes.to_vec())), "tree directory entry repeated");
        }
        ensure!(names == expected[path], "tree contains missing or unrecorded descendants");
        ensure!(same_version(&observed[path], &fd.metadata()?), "tree directory changed during verification");
    }
    ensure!(same_version(&before, &directory(parent_fd, leaf)?.metadata()?), "tree root changed during verification");
    Ok(Some(before))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn entries() -> [Entry<'static>; 4] {
        [Entry { path: "nested/empty", contents: Some(b""), mode: 0o400 },
         Entry { path: "nested", contents: None, mode: 0o500 },
         Entry { path: "app.js", contents: Some(b"console.log(42);"), mode: 0o755 },
         Entry { path: "unused", contents: None, mode: 0o700 }]
    }

    #[test]
    fn nested_images_preserve_empty_directories_binary_bytes_and_exact_modes() {
        let temp = tempfile::tempdir().unwrap();
        let parent = File::open(temp.path()).unwrap();
        let entries = entries();
        let tree = CreateTree { path: "src", mode: 0o750, entries: &entries };
        let (index, summary) = encode(&tree).unwrap();
        assert_eq!(summary, Summary { files: 2, directories: 3, bytes: 16 });
        assert_eq!(summarize(&index).unwrap(), summary);
        assert!(verify(&parent, OsStr::new("staged"), &index).unwrap().is_none());
        stage(&parent, OsStr::new("staged"), &tree, &index).unwrap();
        assert!(verify(&parent, OsStr::new("staged"), &index).unwrap().is_some());
        assert_eq!(fs::metadata(temp.path().join("staged/nested")).unwrap().mode() & 0o777, 0o500);
        assert_eq!(fs::read(temp.path().join("staged/nested/empty")).unwrap(), b"");
        assert!(stage(&parent, OsStr::new("staged"), &tree, &index).is_err());
        let binary = [Entry { path: "bytes", contents: Some(&[0, 255, 128, 0]), mode: 0o640 }];
        let tree = CreateTree { path: "binary", mode: 0o700, entries: &binary };
        let (index, _) = encode(&tree).unwrap();
        stage(&parent, OsStr::new("binary"), &tree, &index).unwrap();
        assert!(verify(&parent, OsStr::new("binary"), &index).unwrap().is_some());
    }

    #[test]
    fn index_is_order_independent_but_modes_kinds_and_bytes_are_bound() {
        let mut entries = entries();
        let before = encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).unwrap().0;
        entries.reverse();
        assert_eq!(encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).unwrap().0, before);
        entries[0].mode = 0o755;
        assert_ne!(encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).unwrap().0, before);
        for bytes in [b"[]".as_slice(), b"null", b"{}", b"{} {}"] { assert!(summarize(bytes).is_err()); }
        let mut padded = before.clone(); padded.push(b' ');
        assert!(summarize(&padded).is_err());
    }

    #[test]
    fn incomplete_conflicting_escaped_and_aliased_paths_are_rejected_before_staging() {
        for path in ["", "../x", "/x", "a//x", "a/./x", "a/../x", "a\\x", ".git/config", "a\nx", "missing/file"] {
            let entries = [Entry { path, contents: Some(b"x"), mode: 0o600 }];
            assert!(encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).is_err(), "{path}");
        }
        let entries = [Entry { path: "a", contents: Some(b"x"), mode: 0o600 },
            Entry { path: "a/b", contents: Some(b"x"), mode: 0o600 }];
        assert!(encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).is_err());
        let entries = [Entry { path: "a", contents: None, mode: 0o700 }, Entry { path: "a", contents: Some(b""), mode: 0o600 }];
        assert!(encode(&CreateTree { path: "src", mode: 0o755, entries: &entries }).is_err());
        for mode in [0, 0o400, 0o4644, 0o1777] {
            assert!(encode(&CreateTree { path: "src", mode: 0o755, entries: &[] }).is_ok());
            assert!(encode(&CreateTree { path: "src", mode, entries: &[] }).is_err());
        }
    }

    #[test]
    fn later_files_mode_changes_symlinks_and_hardlinks_fail_complete_verification() {
        for mutation in 0..6 {
            let temp = tempfile::tempdir().unwrap();
            let parent = File::open(temp.path()).unwrap();
            let entries = [Entry { path: "file", contents: Some(b"original"), mode: 0o600 }];
            let tree = CreateTree { path: "src", mode: 0o700, entries: &entries };
            let (index, _) = encode(&tree).unwrap();
            stage(&parent, OsStr::new("src"), &tree, &index).unwrap();
            match mutation {
                0 => fs::write(temp.path().join("src/later-work"), b"keep me").unwrap(),
                1 => fs::write(temp.path().join("src/file"), b"modified").unwrap(),
                2 => fs::set_permissions(temp.path().join("src/file"), Permissions::from_mode(0o640)).unwrap(),
                3 => { fs::rename(temp.path().join("src/file"), temp.path().join("saved")).unwrap();
                    symlink("../saved", temp.path().join("src/file")).unwrap(); },
                4 => fs::hard_link(temp.path().join("src/file"), temp.path().join("alias")).unwrap(),
                _ => fs::create_dir(temp.path().join("src/new-dir")).unwrap(),
            }
            assert!(verify(&parent, OsStr::new("src"), &index).is_err(), "{mutation}");
            assert!(temp.path().join("src").is_dir());
        }
    }

    #[test]
    fn verification_and_staging_cannot_traverse_root_links_or_relative_parent_components() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = File::open(temp.path()).unwrap();
        let tree = CreateTree { path: "src", mode: 0o700, entries: &[] };
        let (index, _) = encode(&tree).unwrap();
        symlink(outside.path(), temp.path().join("src")).unwrap();
        assert!(verify(&parent, OsStr::new("src"), &index).is_err());
        assert!(stage(&parent, OsStr::new("src"), &tree, &index).is_err());
        for path in ["../escape", "a/b", "a/", ".", "..", "/tmp/escape"] {
            assert!(verify(&parent, OsStr::new(path), &index).is_err());
            assert!(stage(&parent, OsStr::new(path), &tree, &index).is_err());
        }
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn new_empty_root_is_a_real_tree_and_bounds_never_silently_drop_entries() {
        let tree = CreateTree { path: "empty", mode: 0o700, entries: &[] };
        let (index, summary) = encode(&tree).unwrap();
        assert_eq!(summary, Summary { files: 0, directories: 1, bytes: 0 });
        let temp = tempfile::tempdir().unwrap();
        let parent = File::open(temp.path()).unwrap();
        stage(&parent, OsStr::new("empty"), &tree, &index).unwrap();
        assert!(verify(&parent, OsStr::new("empty"), &index).unwrap().is_some());
        let many: Vec<_> = (0..MAX_ENTRIES).map(|_| Entry { path: "x", contents: None, mode: 0o700 }).collect();
        assert!(encode(&CreateTree { path: "large", mode: 0o700, entries: &many }).is_err());
        let large = vec![0; MAX_FILE_BYTES + 1];
        let entries = [Entry { path: "large", contents: Some(&large), mode: 0o600 }];
        assert!(encode(&CreateTree { path: "large", mode: 0o700, entries: &entries }).is_err());
        assert!(summarize(&vec![b' '; MAX_INDEX_BYTES + 1]).is_err());
    }
}
