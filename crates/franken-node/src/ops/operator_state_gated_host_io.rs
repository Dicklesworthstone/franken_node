//! Keep product credentials and operator control state outside guest filesystem
//! authority, even when the guest holds fs_read and fs_write.
//!
//! This is a product policy around the engine's filesystem mechanism. Install it
//! outside the effect WAL: a refusal must never become an admitted host effect.
//! Default state names, explicitly selected operator files, both operands of
//! transfers, directory descendants, and descriptor admission are checked.
//! Guest filesystem calls through this provider are serialized so one cannot
//! change an alias while another is being authorized. The engine still owns
//! descriptor-relative confinement and actual I/O. This does not establish an
//! atomic policy boundary against a separate host process changing the tree
//! between policy inspection and the engine operation. This boundary covers
//! HostIo requests; signed subprocess filesystem access has separate authority.

use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoControl, HostIoError,
    HostIoExceptionProvenance, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 256;
const MAX_SYMLINKS: usize = 40;
const MAX_INSPECTED_ENTRIES: usize = 16_384;
const MAX_INSPECTION_TIME: Duration = Duration::from_secs(2);
const MAX_DESCRIPTORS: usize = 4096;

fn denied(detail: &str) -> HostIoError {
    HostIoError::Denied {
        reason: format!("operator_state: {detail}"),
    }
}

fn reserved_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.eq_ignore_ascii_case(".franken-node") || name.eq_ignore_ascii_case("franken_node.toml")
    })
}

fn reserved_path(path: &Path) -> bool {
    path.components()
        .any(|part| matches!(part, Component::Normal(name) if reserved_name(name)))
}

/// Resolve existing operator-selected ancestors even when the selected file
/// has not been created yet. Remembering only the lexical spelling would miss
/// a future file reached through a preexisting directory symlink.
fn protected_destination(path: &Path) -> io::Result<PathBuf> {
    let mut ancestor = path;
    let mut absent = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for name in absent.into_iter().rev() {
                    resolved.push(name);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::symlink_metadata(ancestor) {
                    // A dangling symlink has an unproven destination; do not
                    // silently preserve its unresolved spelling as authority.
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "operator-protected path has an unresolved existing ancestor",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                let name = ancestor.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid operator-protected path",
                    )
                })?;
                absent.push(name.to_owned());
                ancestor = ancestor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid operator-protected root",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug, Default)]
struct GuestFiles {
    descriptors: BTreeSet<u64>,
}

/// Wrap a fresh, exclusively owned filesystem provider. Explicit protected
/// paths are absolute host paths selected by the operator, never guest input.
/// Regular files with multiple hard links fail closed: a pathname cannot prove
/// that another link is not an operator credential or control-state record.
#[derive(Debug)]
pub struct OperatorStateGatedHostIo<P> {
    inner: P,
    root: PathBuf,
    root_identity: fs::Metadata,
    protected_paths: Vec<PathBuf>,
    files: Mutex<GuestFiles>,
}

impl<P: HostIoProvider> OperatorStateGatedHostIo<P> {
    pub fn new(inner: P, root: &Path, protected_paths: &[PathBuf]) -> io::Result<Self> {
        // The operator namespace stays reserved even when its symlink points
        // at an otherwise ordinary directory outside that lexical namespace.
        if reserved_path(root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "guest filesystem root cannot be operator state",
            ));
        }
        let root = root.canonicalize()?;
        let root_identity = fs::metadata(&root)?;
        if !root_identity.is_dir() || reserved_path(&root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "guest filesystem root cannot be operator state",
            ));
        }
        let mut protected = Vec::with_capacity(protected_paths.len());
        for path in protected_paths {
            if !path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "operator-protected paths must be absolute",
                ));
            }
            if path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "operator-protected paths must be normalized",
                ));
            }
            let canonical = protected_destination(path)?;
            if root.starts_with(path) || root.starts_with(&canonical) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "guest filesystem root is inside protected operator state",
                ));
            }
            protected.push(path.clone());
            protected.push(canonical);
        }
        protected.sort();
        protected.dedup();
        Ok(Self {
            inner,
            root,
            root_identity,
            protected_paths: protected,
            files: Mutex::new(GuestFiles::default()),
        })
    }

    fn check_root(&self) -> Result<(), HostIoError> {
        let current = fs::symlink_metadata(&self.root)
            .map_err(|_| denied("guest filesystem root is no longer available"))?;
        if !current.is_dir() || current.file_type().is_symlink() {
            return Err(denied("guest filesystem root changed after admission"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != self.root_identity.dev()
                || current.ino() != self.root_identity.ino()
            {
                return Err(denied("guest filesystem root changed after admission"));
            }
        }
        #[cfg(not(unix))]
        let _ = &self.root_identity;
        Ok(())
    }

    fn check_operator_path(&self, path: &Path) -> Result<(), HostIoError> {
        if reserved_path(path)
            || self
                .protected_paths
                .iter()
                .any(|protected| path.starts_with(protected))
        {
            return Err(denied("guest access to operator state is forbidden"));
        }
        Ok(())
    }

    fn check_mutated_ancestor(&self, path: &Path) -> Result<(), HostIoError> {
        if self
            .protected_paths
            .iter()
            .any(|protected| protected.starts_with(path))
        {
            return Err(denied(
                "guest cannot mutate an ancestor of selected operator state",
            ));
        }
        Ok(())
    }

    fn components(raw: &str) -> Result<VecDeque<OsString>, HostIoError> {
        if raw.is_empty() || raw.len() > MAX_PATH_BYTES || raw.contains(['\0', '\\']) {
            return Err(denied("invalid or oversized guest filesystem path"));
        }
        let mut parts = VecDeque::new();
        for part in Path::new(raw).components() {
            match part {
                Component::Normal(name) => {
                    if reserved_name(name) {
                        return Err(denied("guest access to operator state is forbidden"));
                    }
                    parts.push_back(name.to_owned());
                }
                // The engine interprets a leading slash relative to its root.
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(denied("guest filesystem path escapes its authority"));
                }
            }
        }
        if parts.len() > MAX_PATH_COMPONENTS {
            return Err(denied("guest filesystem path exceeds inspection bounds"));
        }
        Ok(parts)
    }

    /// Follow the same root-relative, contained-link spelling as the engine,
    /// including dangling targets and intermediate link components. A missing
    /// ordinary target is delegated so the mechanism retains its ENOENT rules.
    fn inspect_path(&self, raw: &str) -> Result<(PathBuf, Option<fs::Metadata>), HostIoError> {
        let mut pending = Self::components(raw)?;
        let mut resolved = self.root.clone();
        let mut links = 0;
        let mut visited = 0;
        while let Some(part) = pending.pop_front() {
            visited += 1;
            if visited > MAX_PATH_COMPONENTS {
                return Err(denied("guest filesystem path exceeds inspection bounds"));
            }
            if part == OsStr::new("..") {
                if resolved == self.root || !resolved.pop() {
                    return Err(denied("symlink target escapes guest filesystem authority"));
                }
                continue;
            }
            let candidate = resolved.join(&part);
            self.check_operator_path(&candidate)?;
            let metadata = match fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                    ) =>
                {
                    // All remaining spellings still need the policy check,
                    // including explicitly protected files that do not exist yet.
                    resolved = candidate;
                    for part in pending {
                        match part.as_os_str() {
                            name if name == OsStr::new("..") => {
                                if resolved == self.root || !resolved.pop() {
                                    return Err(denied("symlink target escapes guest authority"));
                                }
                            }
                            name => {
                                resolved.push(name);
                                self.check_operator_path(&resolved)?;
                            }
                        }
                    }
                    return Ok((resolved, None));
                }
                Err(_) => return Err(denied("cannot inspect guest filesystem authority")),
            };
            if metadata.file_type().is_symlink() {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(denied("symlink inspection bound exceeded"));
                }
                let target = fs::read_link(&candidate)
                    .map_err(|_| denied("cannot inspect guest filesystem alias"))?;
                let relative = if target.is_absolute() {
                    resolved = self.root.clone();
                    target
                        .strip_prefix(&self.root)
                        .map_err(|_| denied("symlink target escapes guest filesystem authority"))?
                } else {
                    target.as_path()
                };
                let mut next = VecDeque::new();
                for component in relative.components() {
                    match component {
                        Component::Normal(name) => {
                            if reserved_name(name) {
                                return Err(denied("filesystem alias reaches operator state"));
                            }
                            next.push_back(name.to_owned());
                        }
                        Component::ParentDir => next.push_back(OsString::from("..")),
                        Component::CurDir => {}
                        Component::RootDir | Component::Prefix(_) => {
                            return Err(denied("invalid filesystem alias target"));
                        }
                    }
                }
                if next.len().saturating_add(pending.len()) > MAX_PATH_COMPONENTS {
                    return Err(denied("filesystem alias exceeds inspection bounds"));
                }
                next.append(&mut pending);
                pending = next;
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.is_file() && metadata.nlink() > 1 {
                    return Err(denied(
                        "multiply linked files have unproven operator-state isolation",
                    ));
                }
            }
            resolved = candidate;
            if pending.is_empty() {
                return Ok((resolved, Some(metadata)));
            }
        }
        self.check_operator_path(&resolved)?;
        let metadata = fs::metadata(&resolved)
            .map_err(|_| denied("cannot inspect guest filesystem authority"))?;
        Ok((resolved, Some(metadata)))
    }

    fn inspect_descendants(&self, path: &Path) -> Result<(), HostIoError> {
        let started = Instant::now();
        let mut pending = vec![path.to_path_buf()];
        let mut inspected = 0;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)
                .map_err(|_| denied("cannot prove directory mutation excludes operator state"))?
            {
                inspected += 1;
                if inspected > MAX_INSPECTED_ENTRIES || started.elapsed() > MAX_INSPECTION_TIME {
                    return Err(denied(
                        "directory mutation exceeds operator-state inspection bounds",
                    ));
                }
                let entry =
                    entry.map_err(|_| denied("cannot inspect directory mutation descendants"))?;
                self.check_operator_path(&entry.path())?;
                // Never traverse a link during a recursive namespace check.
                // Moving/removing the link does not move/remove its referent.
                let kind = entry
                    .file_type()
                    .map_err(|_| denied("cannot inspect directory mutation descendants"))?;
                if kind.is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        Ok(())
    }

    fn inspect_mutation(&self, raw: &str, descendants: bool) -> Result<(), HostIoError> {
        // Check the requested namespace before following aliases, then the
        // destination even when it is absent. Otherwise a guest could install
        // or replace a parent symlink before the operator creates its file.
        let mut spelled = self.root.clone();
        for part in Self::components(raw)? {
            spelled.push(part);
        }
        self.check_mutated_ancestor(&spelled)?;
        let (path, metadata) = self.inspect_path(raw)?;
        self.check_mutated_ancestor(&path)?;
        if descendants && metadata.is_some_and(|metadata| metadata.is_dir()) {
            if path == self.root {
                return Err(denied(
                    "guest cannot mutate its operator-owned filesystem root",
                ));
            }
            self.inspect_descendants(&path)?;
        }
        Ok(())
    }

    fn descriptor(arguments: &[String]) -> Result<u64, HostIoError> {
        arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("fd="))
            .and_then(|fd| fd.parse().ok())
            .ok_or_else(|| HostIoError::Fs {
                code: "EBADF".into(),
                detail: "bad file descriptor argument".into(),
            })
    }

    fn check_request(
        &self,
        request: &HostIoRequest,
        files: &GuestFiles,
    ) -> Result<(), HostIoError> {
        self.check_root()?;
        match request {
            HostIoRequest::FsRead { path } => self.inspect_path(path).map(|_| ()),
            HostIoRequest::FsWrite { path, .. } => self.inspect_mutation(path, false),
            HostIoRequest::FsMeta {
                operation,
                path,
                arguments,
                ..
            } => {
                use FsOperation as Op;
                match operation {
                    Op::ReadFd
                    | Op::WriteFd
                    | Op::Fsync
                    | Op::CloseFd
                    | Op::Fstat
                    | Op::Ftruncate
                    | Op::Fdatasync
                    | Op::Fchmod
                    | Op::Futimes => {
                        let fd = Self::descriptor(arguments)?;
                        if !files.descriptors.contains(&fd) {
                            return Err(HostIoError::Fs {
                                code: "EBADF".into(),
                                detail: "descriptor was not admitted through the operator-state boundary".into(),
                            });
                        }
                        Ok(())
                    }
                    Op::Rename | Op::CopyFile | Op::Symlink => {
                        let destination = arguments.first().ok_or_else(|| HostIoError::Fs {
                            code: "EINVAL".into(),
                            detail: "filesystem transfer requires a destination".into(),
                        })?;
                        if *operation == Op::Rename {
                            self.inspect_mutation(path, true)?;
                        } else {
                            self.inspect_path(path)?;
                        }
                        self.inspect_mutation(destination, *operation == Op::Rename)?;
                        if *operation == Op::Symlink {
                            // A relative stored target is interpreted from the link's
                            // parent, not the sandbox root. Check that spelling too.
                            let mut relative = PathBuf::new();
                            let parts = Self::components(destination)?;
                            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                                relative.push(part);
                            }
                            relative.push(path);
                            self.inspect_path(
                                relative
                                    .to_str()
                                    .ok_or_else(|| denied("invalid alias spelling"))?,
                            )?;
                        }
                        Ok(())
                    }
                    Op::Open => {
                        if files.descriptors.len() >= MAX_DESCRIPTORS {
                            return Err(denied("guest descriptor admission bound exceeded"));
                        }
                        self.inspect_mutation(path, false)
                    }
                    Op::Remove | Op::RemoveDir | Op::Chmod => self.inspect_mutation(path, true),
                    Op::Read
                    | Op::Exists
                    | Op::ReadDir
                    | Op::Stat
                    | Op::Lstat
                    | Op::ReadLink
                    | Op::Access
                    | Op::Realpath => self.inspect_path(path).map(|_| ()),
                    Op::Write
                    | Op::Append
                    | Op::Mkdir
                    | Op::Unlink
                    | Op::Truncate
                    | Op::Utimes
                    | Op::Mkdtemp => self.inspect_mutation(path, false),
                }
            }
            _ => Ok(()),
        }
    }

    fn dispatch(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        perform: impl FnOnce() -> HostIoOutcome,
    ) -> HostIoOutcome {
        let capability = request.required_capability();
        if !granted.contains(&capability) {
            return Err(HostIoError::CapabilityMissing { capability });
        }
        if !matches!(
            request,
            HostIoRequest::FsRead { .. }
                | HostIoRequest::FsWrite { .. }
                | HostIoRequest::FsMeta { .. }
        ) {
            return perform();
        }
        let mut files = self
            .files
            .lock()
            .map_err(|_| denied("filesystem policy state is unavailable"))?;
        self.check_request(request, &files)?;
        let outcome = perform();
        if let HostIoRequest::FsMeta {
            operation,
            arguments,
            ..
        } = request
        {
            match (operation, &outcome) {
                (
                    FsOperation::Open,
                    Ok(HostIoResponse::FsMeta {
                        result: FsMetaResult::Unsigned(fd),
                    }),
                ) => {
                    files.descriptors.insert(*fd);
                }
                (FsOperation::CloseFd, Ok(_)) => {
                    files.descriptors.remove(&Self::descriptor(arguments)?);
                }
                _ => {}
            }
        }
        outcome
    }
}

impl<P: HostIoProvider> HostIoProvider for OperatorStateGatedHostIo<P> {
    fn name(&self) -> &str {
        "operator-state-gated-host-io"
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.inner.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.dispatch(request, granted, || self.inner.perform(request, granted))
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        if control.checkpoint().is_err() {
            return Err(denied(
                "supervisor control refused filesystem policy inspection",
            ));
        }
        self.dispatch(request, granted, || {
            self.inner.perform_controlled(request, granted, control)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_extension_host::host_io::SandboxedHostIo;
    #[cfg(unix)]
    use frankenengine_extension_host::host_io::UnrestrictedHostIoControl;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GRANTS: &[HostIoCapability] = &[HostIoCapability::FsRead, HostIoCapability::FsWrite];

    #[derive(Debug)]
    struct Observed {
        inner: SandboxedHostIo,
        calls: Arc<AtomicUsize>,
        controlled: Arc<AtomicUsize>,
    }

    impl HostIoProvider for Observed {
        fn name(&self) -> &str {
            "observed-real-provider"
        }

        fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
            self.inner.filesystem_exception_provenance()
        }

        fn perform(&self, request: &HostIoRequest, grants: &[HostIoCapability]) -> HostIoOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.perform(request, grants)
        }

        fn perform_controlled(
            &self,
            request: &HostIoRequest,
            grants: &[HostIoCapability],
            control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.controlled.fetch_add(1, Ordering::SeqCst);
            self.inner.perform_controlled(request, grants, control)
        }
    }

    fn observed(
        root: &Path,
        protected: &[PathBuf],
    ) -> (OperatorStateGatedHostIo<Observed>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Observed {
            inner: SandboxedHostIo::with_root(root).unwrap(),
            calls: calls.clone(),
            controlled: Arc::new(AtomicUsize::new(0)),
        };
        (
            OperatorStateGatedHostIo::new(provider, root, protected).unwrap(),
            calls,
        )
    }

    fn read(path: &str) -> HostIoRequest {
        HostIoRequest::FsRead { path: path.into() }
    }

    fn write(path: &str) -> HostIoRequest {
        HostIoRequest::FsWrite {
            path: path.into(),
            data: b"changed".to_vec(),
        }
    }

    fn meta(operation: FsOperation, path: &str, arguments: &[&str]) -> HostIoRequest {
        HostIoRequest::FsMeta {
            operation,
            path: path.into(),
            arguments: arguments.iter().map(|a| (*a).into()).collect(),
            data: b"changed".to_vec(),
        }
    }

    fn assert_refused<P: HostIoProvider>(
        gate: &OperatorStateGatedHostIo<P>,
        request: &HostIoRequest,
    ) {
        assert!(
            matches!(
                gate.perform(request, GRANTS),
                Err(HostIoError::Denied { reason }) if reason.starts_with("operator_state:")
            ),
            "{request:?}",
        );
    }

    #[test]
    fn operator_credentials_and_control_state_never_reach_the_provider() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".franken-node/keys")).unwrap();
        fs::write(
            root.path().join(".franken-node/keys/signing.key"),
            b"private key",
        )
        .unwrap();
        fs::write(
            root.path().join("franken_node.toml"),
            b"registry_signing_key = 'private'",
        )
        .unwrap();
        let (gate, calls) = observed(root.path(), &[]);
        for path in [
            ".franken-node/keys/signing.key",
            "/.franken-node/keys/signing.key",
            "./.franken-node//keys/signing.key",
            "franken_node.toml",
            ".FRANKEN-NODE/key",
            "FRANKEN_NODE.TOML",
        ] {
            assert_refused(&gate, &read(path));
            assert_refused(&gate, &write(path));
            for operation in [
                FsOperation::Stat,
                FsOperation::Exists,
                FsOperation::ReadDir,
                FsOperation::Open,
                FsOperation::Unlink,
                FsOperation::Remove,
                FsOperation::Chmod,
            ] {
                assert_refused(
                    &gate,
                    &meta(operation, path, &["flags=w", "recursive=true", "mode=0"]),
                );
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "denials must precede WAL admission and the real provider",
        );
        assert_eq!(
            fs::read(root.path().join(".franken-node/keys/signing.key")).unwrap(),
            b"private key",
        );
        assert_eq!(
            fs::read(root.path().join("franken_node.toml")).unwrap(),
            b"registry_signing_key = 'private'",
        );
    }

    #[test]
    fn both_transfer_operands_and_mutated_ancestors_are_protected() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("nested/.franken-node/safe-mode")).unwrap();
        fs::write(
            root.path()
                .join("nested/.franken-node/safe-mode/state.json"),
            b"held",
        )
        .unwrap();
        fs::write(root.path().join("ordinary.txt"), b"ordinary").unwrap();
        let (gate, calls) = observed(root.path(), &[]);
        for operation in [
            FsOperation::CopyFile,
            FsOperation::Rename,
            FsOperation::Symlink,
        ] {
            assert_refused(
                &gate,
                &meta(operation, "ordinary.txt", &["nested/.franken-node/new"]),
            );
            assert_refused(
                &gate,
                &meta(
                    operation,
                    "nested/.franken-node/safe-mode/state.json",
                    &["ordinary.txt"],
                ),
            );
        }
        assert_refused(&gate, &meta(FsOperation::Rename, "nested", &["renamed"]));
        assert_refused(
            &gate,
            &meta(FsOperation::Rename, "ordinary.txt", &["nested"]),
        );
        assert_refused(
            &gate,
            &meta(FsOperation::Remove, "nested", &["recursive=true"]),
        );
        assert_refused(&gate, &meta(FsOperation::Chmod, "nested", &["mode=0"]));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read(
                root.path()
                    .join("nested/.franken-node/safe-mode/state.json")
            )
            .unwrap(),
            b"held",
        );
    }

    #[test]
    fn explicit_operator_files_include_absent_names_and_parent_mutations() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("ops")).unwrap();
        fs::write(root.path().join("ops/selected.conf"), b"private config").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let protected = [
            root_path.join("ops/selected.conf"),
            root_path.join("later/key"),
        ];
        let (gate, calls) = observed(root.path(), &protected);
        for path in ["ops/selected.conf", "later/key"] {
            assert_refused(&gate, &read(path));
            assert_refused(&gate, &write(path));
        }
        assert_refused(&gate, &meta(FsOperation::Rename, "ops", &["renamed"]));
        assert_refused(
            &gate,
            &meta(FsOperation::Remove, "ops", &["recursive=true"]),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(unix)]
    #[test]
    fn absent_selected_files_reserve_ancestor_names_before_creation() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("waiting")).unwrap();
        fs::create_dir(root.path().join("ordinary")).unwrap();
        fs::write(root.path().join("ordinary/source"), b"application").unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let protected = [
            root_path.join("waiting/keys/token"),
            root_path.join("uncreated/token"),
        ];
        let (gate, calls) = observed(root.path(), &protected);
        for path in ["waiting", "/waiting//keys/.", "uncreated"] {
            assert_refused(&gate, &write(path));
            for operation in [
                FsOperation::Mkdir,
                FsOperation::Open,
                FsOperation::Unlink,
                FsOperation::Remove,
                FsOperation::Chmod,
                FsOperation::Utimes,
            ] {
                assert_refused(
                    &gate,
                    &meta(operation, path, &["recursive=true", "flags=w", "mode=0"]),
                );
            }
            assert_refused(&gate, &meta(FsOperation::Rename, path, &["moved"]));
            assert_refused(&gate, &meta(FsOperation::Rename, "ordinary", &[path]));
            assert_refused(
                &gate,
                &meta(FsOperation::CopyFile, "ordinary/source", &[path]),
            );
            assert_refused(&gate, &meta(FsOperation::Symlink, "ordinary", &[path]));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(root.path().join("waiting").is_dir());
        assert!(!root.path().join("waiting/keys").exists());
        assert!(!root.path().join("uncreated").exists());

        // A reserved descendant does not turn its entire parent into a secret
        // namespace: ordinary reads and sibling writes retain engine behavior.
        assert!(gate.perform(&write("waiting/user-data"), GRANTS).is_ok());
        assert!(
            gate.perform(&meta(FsOperation::ReadDir, "waiting", &[]), GRANTS)
                .is_ok(),
        );
        assert!(matches!(
            gate.perform(&read("waiting/missing-sibling"), GRANTS),
            Err(HostIoError::Fs { code, .. }) if code == "ENOENT",
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[cfg(unix)]
    #[test]
    fn absent_selected_files_retain_existing_parent_symlink_destinations() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("private")).unwrap();
        symlink("private", root.path().join("selected-location")).unwrap();
        symlink("private", root.path().join("public-alias")).unwrap();
        let protected = [root
            .path()
            .canonicalize()
            .unwrap()
            .join("selected-location/future.key")];
        let (gate, calls) = observed(root.path(), &protected);

        for path in [
            "selected-location/future.key",
            "private/future.key",
            "public-alias/future.key",
        ] {
            assert_refused(&gate, &read(path));
            assert_refused(&gate, &write(path));
        }
        for parent in ["selected-location", "private", "public-alias"] {
            assert_refused(&gate, &meta(FsOperation::Rename, parent, &["moved"]));
            assert_refused(&gate, &meta(FsOperation::Unlink, parent, &[]));
        }
        // The trusted operator creates the file after provider construction.
        // Both its selected spelling and the resolved destination remain private.
        fs::write(root.path().join("private/future.key"), b"operator secret").unwrap();
        for path in [
            "selected-location/future.key",
            "private/future.key",
            "public-alias/future.key",
        ] {
            assert_refused(&gate, &read(path));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(gate.perform(&write("private/user-data"), GRANTS).is_ok());
        assert!(gate.perform(&write("private-extra"), GRANTS).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_selected_operator_aliases_refuse_admission() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        symlink("missing-parent", root.path().join("selected-location")).unwrap();
        let protected = [root
            .path()
            .canonicalize()
            .unwrap()
            .join("selected-location/future.key")];
        let error = OperatorStateGatedHostIo::new(
            SandboxedHostIo::with_root(root.path()).unwrap(),
            root.path(),
            &protected,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_files_virtual_absolute_paths_and_descriptors_keep_real_behavior() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".franken-node-public")).unwrap();
        fs::write(
            root.path().join(".franken-node-public/data.txt"),
            b"ordinary",
        )
        .unwrap();
        let (gate, calls) = observed(root.path(), &[]);
        assert_eq!(
            gate.filesystem_exception_provenance(),
            HostIoExceptionProvenance::ProviderInternal,
        );
        assert_eq!(
            gate.perform(&read("/.franken-node-public/data.txt"), GRANTS)
                .unwrap(),
            HostIoResponse::FsRead {
                bytes: b"ordinary".to_vec()
            },
        );
        assert!(
            gate.perform(&write("franken_node.toml.example"), GRANTS)
                .is_ok()
        );
        let opened = gate
            .perform(
                &meta(
                    FsOperation::Open,
                    ".franken-node-public/data.txt",
                    &["flags=r"],
                ),
                GRANTS,
            )
            .unwrap();
        let HostIoResponse::FsMeta {
            result: FsMetaResult::Unsigned(fd),
        } = opened
        else {
            panic!("missing real descriptor")
        };
        let fd = format!("fd={fd}");
        assert!(matches!(
            gate.perform(
                &meta(FsOperation::ReadFd, "", &[&fd, "length=8"]),
                GRANTS,
            ),
            Ok(HostIoResponse::FsMeta {
                result: FsMetaResult::Bytes(bytes),
            }) if bytes == b"ordinary",
        ));
        assert!(
            gate.perform(&meta(FsOperation::CloseFd, "", &[&fd]), GRANTS)
                .is_ok(),
        );
        assert!(matches!(
            gate.perform(
                &meta(FsOperation::ReadFd, "", &[&fd, "length=8"]),
                GRANTS,
            ),
            Err(HostIoError::Fs { code, .. }) if code == "EBADF",
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[cfg(unix)]
    #[test]
    fn unguarded_descriptors_cannot_import_operator_authority() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("franken_node.toml"), b"private config").unwrap();
        let inner = SandboxedHostIo::with_root(root.path()).unwrap();
        let opened = inner
            .perform(
                &meta(FsOperation::Open, "franken_node.toml", &["flags=r"]),
                GRANTS,
            )
            .unwrap();
        let HostIoResponse::FsMeta {
            result: FsMetaResult::Unsigned(fd),
        } = opened
        else {
            panic!("missing real descriptor")
        };
        let gate = OperatorStateGatedHostIo::new(inner, root.path(), &[]).unwrap();
        assert!(matches!(
            gate.perform(
                &meta(
                    FsOperation::ReadFd,
                    "ordinary",
                    &[&format!("fd={fd}"), "length=20"],
                ),
                GRANTS,
            ),
            Err(HostIoError::Fs { code, .. }) if code == "EBADF",
        ));
    }

    #[cfg(unix)]
    #[test]
    fn capability_and_control_refusals_precede_filesystem_inspection() {
        #[derive(Debug)]
        struct Stopped;
        impl HostIoControl for Stopped {
            fn checkpoint(&self) -> Result<(), HostIoError> {
                Err(HostIoError::Denied {
                    reason: "stop".into(),
                })
            }
        }
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("ordinary"), b"ok").unwrap();
        let (gate, calls) = observed(root.path(), &[]);
        assert!(matches!(
            gate.perform(&read(".franken-node/secret"), &[]),
            Err(HostIoError::CapabilityMissing { .. }),
        ));
        assert!(
            gate.perform_controlled(&read("ordinary"), GRANTS, Arc::new(Stopped))
                .is_err(),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            gate.perform_controlled(
                &read("ordinary"),
                GRANTS,
                Arc::new(UnrestrictedHostIoControl),
            )
            .is_ok(),
        );
        assert_eq!(gate.inner.controlled.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_aliases_and_destination_relative_symlinks_cannot_reach_state() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".franken-node/keys")).unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::write(
            root.path().join(".franken-node/keys/token.json"),
            b"private token",
        )
        .unwrap();
        fs::write(root.path().join("ordinary"), b"ok").unwrap();
        symlink(
            ".franken-node/keys/token.json",
            root.path().join("alias.json"),
        )
        .unwrap();
        symlink("../.franken-node/keys", root.path().join("nested/hidden")).unwrap();
        symlink("ordinary", root.path().join("safe-alias")).unwrap();
        let (gate, calls) = observed(root.path(), &[]);
        assert_refused(&gate, &read("alias.json"));
        assert_refused(&gate, &read("nested/hidden/token.json"));
        assert_refused(
            &gate,
            &meta(
                FsOperation::Symlink,
                "hidden/token.json",
                &["nested/new-alias"],
            ),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            gate.perform(&read("safe-alias"), GRANTS).unwrap(),
            HostIoResponse::FsRead {
                bytes: b"ok".to_vec()
            },
        );
    }

    #[cfg(unix)]
    #[test]
    fn operator_state_root_aliases_are_refused_before_canonicalization() {
        use std::os::unix::fs::symlink;
        let parent = tempfile::tempdir().unwrap();
        let ordinary = parent.path().join("ordinary");
        fs::create_dir_all(ordinary.join("app")).unwrap();
        let alias = parent.path().join(".franken-node");
        symlink(&ordinary, &alias).unwrap();
        for root in [alias.clone(), alias.join("app")] {
            let error = OperatorStateGatedHostIo::new(
                SandboxedHostIo::with_root(&root).unwrap(),
                &root,
                &[],
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }

    #[cfg(unix)]
    #[test]
    fn real_directory_opens_never_admit_descriptor_mutation_authority() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("parent/.franken-node")).unwrap();
        fs::write(
            root.path().join("parent/.franken-node/private"),
            b"private state",
        )
        .unwrap();
        let root_mode = fs::metadata(root.path()).unwrap().permissions().mode();
        let parent_mode = fs::metadata(root.path().join("parent"))
            .unwrap()
            .permissions()
            .mode();
        let (gate, calls) = observed(root.path(), &[]);
        for path in [".", "parent"] {
            assert!(matches!(
                gate.perform(&meta(FsOperation::Open, path, &["flags=r"]), GRANTS),
                Err(HostIoError::Fs { code, .. }) if code == "EISDIR",
            ));
        }
        assert!(gate.files.lock().unwrap().descriptors.is_empty());
        for operation in [
            FsOperation::Fchmod,
            FsOperation::Futimes,
            FsOperation::Ftruncate,
            FsOperation::WriteFd,
        ] {
            assert!(matches!(
                gate.perform(
                    &meta(
                        operation,
                        "",
                        &["fd=3", "mode=0", "length=0", "atime=0", "mtime=0"],
                    ),
                    GRANTS,
                ),
                Err(HostIoError::Fs { code, .. }) if code == "EBADF",
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode(),
            root_mode,
        );
        assert_eq!(
            fs::metadata(root.path().join("parent"))
                .unwrap()
                .permissions()
                .mode(),
            parent_mode,
        );
        assert_eq!(
            fs::read(root.path().join("parent/.franken-node/private")).unwrap(),
            b"private state",
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_control_files_and_root_relocation_fail_closed() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("project");
        fs::create_dir_all(root.join(".franken-node")).unwrap();
        fs::write(root.join(".franken-node/private"), b"private token").unwrap();
        fs::hard_link(root.join(".franken-node/private"), root.join("public-name")).unwrap();
        let (gate, calls) = observed(&root, &[]);
        assert_refused(&gate, &read("public-name"));
        assert_refused(&gate, &write("public-name"));
        assert!(
            OperatorStateGatedHostIo::new(
                SandboxedHostIo::with_root(root.join(".franken-node")).unwrap(),
                &root.join(".franken-node"),
                &[],
            )
            .is_err(),
        );
        fs::rename(&root, parent.path().join("retained-project")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("ordinary"), b"replacement").unwrap();
        assert_refused(&gate, &read("ordinary"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
