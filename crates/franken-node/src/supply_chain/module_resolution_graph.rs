//! Canonical npm/Bun-style module-resolution graph construction.
//!
//! This module intentionally models project metadata and lockfile facts, not
//! full Node/Bun runtime resolution semantics. Runtime parity remains the job
//! of the lockstep oracle; this graph gives admission and receipt layers stable
//! bytes for package manifests, workspace edges, dependency ranges, conditional
//! exports/imports, and npm/Bun lockfile pins. Bun text-lock normalization uses
//! the same bounded parser and workspace/catalog binding as checked migration.
//!
//! Installed dependency lookup is importer-relative and bounded to the project:
//! the closest recorded `node_modules` entry wins. It is not a semver solver,
//! exports evaluator, installation verifier, or substitute for the live loader.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[path = "module_file_resolution.rs"]
pub mod file_resolution;
#[path = "package_target_resolution.rs"]
pub mod package_targets;

#[path = "module_dependency_topology.rs"]
pub mod dependency_topology;

/// CommonJS LOAD_AS_FILE and LOAD_INDEX probe these suffixes in this order.
/// Callers retain their own containment, capture and resource-limit checks.
pub(crate) const COMMONJS_FILE_EXTENSIONS: [&str; 3] = [".js", ".json", ".node"];

#[derive(Debug, Clone, Copy)]
pub(crate) enum CommonJsDirectoryStep<'a> {
    MainFile(&'a str),
    MainIndex(&'a str),
    PackageIndex,
}

/// Node's directory lookup order, shared by live entrypoint selection and
/// captured module resolution. A main value is a literal path: whitespace is
/// meaningful, while an empty string falls back to the package index.
pub(crate) fn commonjs_directory_steps(
    main: Option<&str>,
) -> impl Iterator<Item = CommonJsDirectoryStep<'_>> {
    let main = main.filter(|main| !main.is_empty());
    [
        main.map(CommonJsDirectoryStep::MainFile),
        main.map(CommonJsDirectoryStep::MainIndex),
        Some(CommonJsDirectoryStep::PackageIndex),
    ]
    .into_iter()
    .flatten()
}

/// Workspace negation and wildcard character units differ between npm and Bun.
/// The selected lock authority chooses the dialect; selectors never do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSelectionMode {
    Npm,
    Bun,
}

/// Shared npm/Bun workspace selection for trust topology and checked migration.
/// Callers retain their own manifest admission, count limits and missing-match
/// policy. One descriptor-relative walk carries all selector states, so overlap
/// never reopens a manifest or multiplies directory enumeration.
#[cfg(unix)]
pub(crate) mod workspace_selection {
    use super::{
        ModuleResolutionGraphError, ModuleResolutionGraphResult, WorkspaceSelectionMode,
        enforce_len,
    };
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, statat};
    use std::collections::BTreeMap;
    use std::fs::{File, Metadata};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::Instant;

    const MAX_PATH_BYTES: usize = 4096;
    const MAX_DEPTH: usize = 64;
    const EXCLUDED: &[&str] = &[
        "node_modules",
        ".git",
        ".beads",
        ".migrate-backup",
        ".franken-node",
        ".franken-rewrite",
    ];

    pub(crate) struct Limits {
        pub mode: WorkspaceSelectionMode,
        pub patterns: usize,
        /// Includes the already captured root manifest.
        pub manifests: usize,
        pub directories: usize,
        pub entries: usize,
        pub depth: usize,
        pub require_matches: bool,
    }

    fn invalid(detail: impl Into<String>) -> ModuleResolutionGraphError {
        ModuleResolutionGraphError::InvalidMetadata {
            detail: detail.into(),
        }
    }

    fn io_error(
        path: impl Into<PathBuf>,
        source: impl Into<std::io::Error>,
    ) -> ModuleResolutionGraphError {
        ModuleResolutionGraphError::Io {
            path: path.into(),
            source: source.into(),
        }
    }

    fn check_deadline(deadline: Option<Instant>) -> ModuleResolutionGraphResult<()> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(invalid("workspace inventory deadline exceeded"));
        }
        Ok(())
    }

    fn relative(path: &str) -> bool {
        !path.is_empty()
            && path.len() <= MAX_PATH_BYTES
            && path.split('/').count() <= MAX_DEPTH
            && !path.contains(['\\', ':'])
            && !path.chars().any(char::is_control)
            && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
    }

    /// Compile component syntax once, before opening any workspace directory.
    /// Classes deliberately accept ASCII literals/ranges only. Malformed,
    /// nested and POSIX classes remain explicit errors, never literal fallbacks
    /// that could silently omit a workspace from dependency admission.
    enum ComponentToken {
        Literal(u32),
        One,
        Star,
        Class {
            negated: bool,
            ranges: Vec<(u8, u8)>,
        },
    }

    struct ComponentPattern {
        tokens: Vec<ComponentToken>,
        mode: WorkspaceSelectionMode,
        explicit_dot: bool,
        literal: bool,
    }

    impl ComponentPattern {
        fn parse(source: &str, mode: WorkspaceSelectionMode) -> Option<Self> {
            let mut characters = source.chars().peekable();
            let mut tokens = Vec::new();
            let mut literal = true;
            while let Some(character) = characters.next() {
                match character {
                    '*' => {
                        literal = false;
                        tokens.push(ComponentToken::Star);
                    }
                    '?' => {
                        literal = false;
                        tokens.push(ComponentToken::One);
                    }
                    '[' => {
                        literal = false;
                        let negated = matches!(characters.peek(), Some('!' | '^'));
                        if negated {
                            characters.next();
                        }
                        let mut members = Vec::new();
                        loop {
                            match characters.next()? {
                                ']' => break,
                                member
                                    if member.is_ascii_graphic()
                                        && !matches!(
                                            member,
                                            '[' | '/' | '\\' | ':' | '{' | '}' | '(' | ')' | '|'
                                        ) =>
                                {
                                    members.push(member as u8);
                                }
                                _ => return None,
                            }
                        }
                        if members.is_empty() {
                            return None;
                        }
                        let mut ranges = Vec::new();
                        let mut index = 0;
                        while index < members.len() {
                            let first = members[index];
                            if index + 2 < members.len() && members[index + 1] == b'-' {
                                let last = members[index + 2];
                                if first > last || first == b'-' || last == b'-' {
                                    return None;
                                }
                                ranges.push((first, last));
                                index += 3;
                            } else {
                                // A dash is literal only at a class boundary;
                                // chained or incomplete ranges are ambiguous.
                                if first == b'-' && index != 0 && index + 1 != members.len() {
                                    return None;
                                }
                                ranges.push((first, first));
                                index += 1;
                            }
                        }
                        tokens.push(ComponentToken::Class { negated, ranges });
                    }
                    '!' | ']' | '{' | '}' | '(' | ')' | '|' => return None,
                    _ => match mode {
                        WorkspaceSelectionMode::Npm => {
                            let mut encoded = [0_u16; 2];
                            for unit in character.encode_utf16(&mut encoded) {
                                tokens.push(ComponentToken::Literal(u32::from(*unit)));
                            }
                        }
                        WorkspaceSelectionMode::Bun => {
                            tokens.push(ComponentToken::Literal(u32::from(character)));
                        }
                    },
                }
            }
            Some(Self {
                tokens,
                mode,
                explicit_dot: source.starts_with('.'),
                literal,
            })
        }

        fn matches(&self, text: &str, dot: bool) -> bool {
            if (!dot && text.starts_with('.') && !self.explicit_dot) || text.contains('/') {
                return false;
            }
            let mut input = match self.mode {
                WorkspaceSelectionMode::Npm => ComponentUnits::Npm(text.encode_utf16()),
                WorkspaceSelectionMode::Bun => ComponentUnits::Bun(text.chars()),
            }
            .peekable();
            // npm's shipped minimatch consumes UTF-16 units, while Bun uses
            // Unicode scalars. Keep both the literals and wildcard cursor in
            // the selected dialect, including when retrying after a star.
            // Iterators are cheap to clone; matching allocates no text buffer
            // and never constructs a recursive backtracking tree.
            let mut token_index = 0;
            let mut star = None;
            let mut retry = input.clone();
            while let Some(&character) = input.peek() {
                let matches = match self.tokens.get(token_index) {
                    Some(ComponentToken::Literal(value)) => *value == character,
                    Some(ComponentToken::One) => true,
                    Some(ComponentToken::Class { negated, ranges }) => {
                        let contained = ranges.iter().any(|(first, last)| {
                            (u32::from(*first)..=u32::from(*last)).contains(&character)
                        });
                        contained != *negated
                    }
                    _ => false,
                };
                if matches {
                    token_index += 1;
                    input.next();
                } else if matches!(self.tokens.get(token_index), Some(ComponentToken::Star)) {
                    star = Some(token_index);
                    token_index += 1;
                    retry = input.clone();
                } else if let Some(index) = star {
                    if retry.next().is_none() {
                        return false;
                    }
                    input = retry.clone();
                    token_index = index + 1;
                } else {
                    return false;
                }
            }
            while matches!(self.tokens.get(token_index), Some(ComponentToken::Star)) {
                token_index += 1;
            }
            token_index == self.tokens.len()
        }
    }

    #[derive(Clone)]
    enum ComponentUnits<'a> {
        Npm(std::str::EncodeUtf16<'a>),
        Bun(std::str::Chars<'a>),
    }

    impl Iterator for ComponentUnits<'_> {
        type Item = u32;

        fn next(&mut self) -> Option<Self::Item> {
            match self {
                Self::Npm(units) => units.next().map(u32::from),
                Self::Bun(characters) => characters.next().map(u32::from),
            }
        }
    }

    struct Pattern {
        parts: Vec<String>,
        components: Vec<ComponentPattern>,
        negative: bool,
        literal: bool,
        trailing_slash: bool,
    }

    impl Pattern {
        fn parse(raw: &str, mode: WorkspaceSelectionMode) -> ModuleResolutionGraphResult<Self> {
            let body = raw.strip_prefix('!').unwrap_or(raw);
            let normalized = body.strip_prefix("./").unwrap_or(body);
            let normalized = normalized.strip_suffix('/').unwrap_or(normalized);
            if raw.trim() != raw
                || body.trim() != body
                || raw.len() > MAX_PATH_BYTES
                || !relative(normalized)
                || normalized
                    .split('/')
                    .any(|part| EXCLUDED.contains(&part) || (part.contains("**") && part != "**"))
            {
                return Err(ModuleResolutionGraphError::InvalidWorkspacePattern {
                    pattern: raw.to_owned(),
                });
            }
            let components = normalized
                .split('/')
                .map(|component| ComponentPattern::parse(component, mode))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| ModuleResolutionGraphError::InvalidWorkspacePattern {
                    pattern: raw.to_owned(),
                })?;
            let literal = components.iter().all(|component| component.literal);
            Ok(Self {
                parts: normalized.split('/').map(str::to_owned).collect(),
                components,
                negative: raw.starts_with('!'),
                literal,
                trailing_slash: body.ends_with('/'),
            })
        }

        /// npm applies surviving exclusions to authored selector strings,
        /// and a later positive selector can cancel an earlier exclusion.
        /// Match those strings as text, without expanding the candidate's
        /// glob syntax. Directory matching below uses the same automaton.
        fn matches_selector(&self, selector: &str) -> bool {
            let selector = selector.strip_prefix("./").unwrap_or(selector);
            let trailing_slash = selector.ends_with('/');
            if self.trailing_slash && !trailing_slash {
                return false;
            }
            let selector = selector.strip_suffix('/').unwrap_or(selector);
            let mut state = self.start();
            let trailing_globstar = self.parts.last().is_some_and(|part| part == "**");
            let mut consumed_trailing_globstar = false;
            for component in selector.split('/') {
                consumed_trailing_globstar =
                    trailing_globstar && state[self.parts.len() - 1] && !component.starts_with('.');
                state = self.step(&state, component);
            }
            // minimatch requires a path component after the slash in `a/**`.
            // An authored `a/` supplies an empty final component; plain `a`
            // does not. Filesystem directory matching already has that slash.
            state.last() == Some(&true)
                && (!trailing_globstar || trailing_slash || consumed_trailing_globstar)
        }

        fn covers_descendants(&self, state: &[bool]) -> bool {
            self.parts.last().is_some_and(|part| part == "**") && state[self.parts.len() - 1]
        }

        fn closure(&self, state: &mut [bool]) {
            for (index, part) in self.parts.iter().enumerate() {
                if state[index] && part == "**" {
                    state[index + 1] = true;
                }
            }
        }

        fn start(&self) -> Vec<bool> {
            let mut state = vec![false; self.parts.len() + 1];
            state[0] = true;
            self.closure(&mut state);
            state
        }

        fn step(&self, state: &[bool], component: &str) -> Vec<bool> {
            self.step_with_dot(state, component, false)
        }

        fn step_with_dot(&self, state: &[bool], component: &str, dot: bool) -> Vec<bool> {
            let mut next = vec![false; state.len()];
            for (index, part) in self.parts.iter().enumerate() {
                if !state[index] {
                    continue;
                }
                if part == "**" {
                    if dot || !component.starts_with('.') {
                        next[index] = true;
                    }
                } else if self.components[index].matches(component, dot) {
                    next[index + 1] = true;
                }
            }
            self.closure(&mut next);
            next
        }
    }

    /// Brace alternatives share one walk with every other selector. Expansion
    /// is bounded before filesystem access, including branches that match no
    /// directory. Keep the authored selector index: one successful alternative
    /// satisfies that selector, while overlapping alternatives capture once.
    fn compile_patterns(
        selectors: &[String],
        limit: usize,
        deadline: Option<Instant>,
        mode: WorkspaceSelectionMode,
    ) -> ModuleResolutionGraphResult<Vec<(usize, Pattern)>> {
        enforce_len("workspace patterns", selectors.len(), limit)?;
        let mut compiled = Vec::new();
        for (selector, raw) in selectors.iter().enumerate() {
            let invalid_pattern = || ModuleResolutionGraphError::InvalidWorkspacePattern {
                pattern: raw.clone(),
            };
            if raw.trim() != raw || raw.len() > MAX_PATH_BYTES {
                return Err(invalid_pattern());
            }
            // Brace expansion precedes component parsing. Do not let it
            // reinterpret a forbidden class as several valid alternatives.
            let mut in_class = false;
            for character in raw.chars() {
                match character {
                    '[' if in_class => return Err(invalid_pattern()),
                    '[' => in_class = true,
                    ']' => in_class = false,
                    '{' | '}' if in_class => return Err(invalid_pattern()),
                    _ => {}
                }
            }
            let mut pending = vec![raw.clone()];
            while let Some(pattern) = pending.pop() {
                check_deadline(deadline)?;
                let Some(start) = pattern.find('{') else {
                    enforce_len("expanded workspace patterns", compiled.len() + 1, limit)?;
                    let mut parsed = Pattern::parse(&pattern, mode)?;
                    if parsed.negative != raw.starts_with('!') {
                        return Err(invalid_pattern());
                    }
                    // A brace-expanded literal is still a glob in Bun. Only
                    // an authored ordinary directory can override negation.
                    parsed.literal &= !raw.contains('{');
                    compiled.push((selector, parsed));
                    continue;
                };
                if pattern[..start].contains('}') {
                    return Err(invalid_pattern());
                }
                let mut depth = 0;
                let mut separators = Vec::new();
                let mut end = None;
                for (offset, character) in pattern[start..].char_indices() {
                    match character {
                        '{' => {
                            depth += 1;
                            enforce_len("workspace brace depth", depth, MAX_DEPTH)?;
                        }
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(start + offset);
                                break;
                            }
                        }
                        ',' if depth == 1 => separators.push(start + offset),
                        _ => {}
                    }
                }
                let end = end.ok_or_else(invalid_pattern)?;
                // Only explicit alternative lists are supported. Numeric
                // ranges, literal/unbalanced braces and unknown dialects stay
                // errors instead of being interpreted as a partial selector.
                if separators.is_empty() {
                    return Err(invalid_pattern());
                }
                separators.push(end);
                enforce_len(
                    "expanded workspace patterns",
                    compiled.len() + pending.len() + separators.len(),
                    limit,
                )?;
                let mut begin = start + 1;
                for stop in separators {
                    let expanded = format!(
                        "{}{}{}",
                        &pattern[..start],
                        &pattern[begin..stop],
                        &pattern[end + 1..]
                    );
                    // Each expansion removes delimiters; this still checks
                    // bounds explicitly before retaining or parsing a branch.
                    enforce_len("workspace pattern bytes", expanded.len(), MAX_PATH_BYTES)?;
                    pending.push(expanded);
                    begin = stop + 1;
                }
            }
        }
        Ok(compiled)
    }

    fn apply_mode(
        patterns: &mut Vec<(usize, Pattern)>,
        selectors: &[String],
        mode: WorkspaceSelectionMode,
    ) {
        if mode != WorkspaceSelectionMode::Npm {
            return;
        }
        let mut negatives = Vec::new();
        for (current, selector) in selectors.iter().enumerate() {
            if selector.starts_with('!') {
                negatives.push(current);
            } else {
                let mut index = 0;
                while index < negatives.len() {
                    if patterns.iter().any(|(owner, pattern)| {
                        *owner == negatives[index] && pattern.matches_selector(selector)
                    }) {
                        negatives.remove(index);
                    }
                    // npm's indexed splice loop advances even after removal.
                    // Preserve its handling of adjacent matching exclusions.
                    index += 1;
                }
            }
        }
        // Filter positives only after all cancellations. A later positive can
        // restore an earlier broad selector by cancelling its exclusion.
        let active = selectors
            .iter()
            .enumerate()
            .map(|(index, selector)| {
                if selector.starts_with('!') {
                    negatives.contains(&index)
                } else {
                    !patterns.iter().any(|(owner, pattern)| {
                        negatives.contains(owner) && pattern.matches_selector(selector)
                    })
                }
            })
            .collect::<Vec<_>>();
        // Validate and charge every expansion before discarding any selector.
        // Negation cannot hide malformed syntax or evade an expansion bound.
        patterns.retain(|(selector, _)| active[*selector]);
    }

    fn selected(
        patterns: &[(usize, Pattern)],
        states: &[Vec<bool>],
        mode: WorkspaceSelectionMode,
    ) -> bool {
        let mut included = false;
        let mut excluded = false;
        let mut literal = false;
        for ((_, pattern), state) in patterns.iter().zip(states) {
            if state.last() != Some(&true) {
                continue;
            }
            if pattern.negative {
                excluded = true;
            } else {
                included = true;
                literal |= pattern.literal;
            }
        }
        included && (!excluded || (mode == WorkspaceSelectionMode::Bun && literal))
    }

    fn descend(patterns: &[(usize, Pattern)], states: &[Vec<bool>]) -> bool {
        patterns.iter().zip(states).any(|((_, pattern), state)| {
            !pattern.negative && state[..state.len() - 1].iter().any(|active| *active)
        })
    }

    fn excluded_subtree(
        patterns: &[(usize, Pattern)],
        states: &[Vec<bool>],
        mode: WorkspaceSelectionMode,
    ) -> bool {
        let excluded = patterns
            .iter()
            .zip(states)
            .any(|((_, pattern), state)| pattern.negative && pattern.covers_descendants(state));
        excluded
            && !(mode == WorkspaceSelectionMode::Bun
                && patterns.iter().zip(states).any(|((_, pattern), state)| {
                    !pattern.negative && pattern.literal && state.iter().any(|active| *active)
                }))
    }

    fn mark_excluded(
        patterns: &[(usize, Pattern)],
        states: &[Vec<bool>],
        matched: &mut [bool],
        subtree: bool,
    ) {
        for ((selector, pattern), state) in patterns.iter().zip(states) {
            if !pattern.negative
                && if subtree {
                    state.iter().any(|active| *active)
                } else {
                    state.last() == Some(&true)
                }
            {
                // Explicitly excluded directories require no manifest read.
                // Only surviving positive selectors demand an actual match.
                matched[*selector] = true;
            }
        }
    }

    #[cfg(test)]
    fn component_matches(pattern: &str, text: &str) -> bool {
        ComponentPattern::parse(pattern, WorkspaceSelectionMode::Npm)
            .is_some_and(|pattern| pattern.matches(text, false))
    }

    pub(crate) fn open_root(project: &Path) -> ModuleResolutionGraphResult<File> {
        let root = if project.is_absolute() {
            project.to_path_buf()
        } else {
            project
                .canonicalize()
                .map_err(|error| io_error(project, error))?
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory =
            File::from(open("/", flags, Mode::empty()).map_err(|error| io_error(&root, error))?);
        for part in root.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    directory = File::from(
                        openat(&directory, name, flags, Mode::empty())
                            .map_err(|error| io_error(&root, error))?,
                    );
                }
                _ => {
                    return Err(invalid(
                        "workspace authority must not contain parent traversal",
                    ));
                }
            }
        }
        Ok(directory)
    }

    pub(crate) fn open_directory(root: &File, path: &str) -> ModuleResolutionGraphResult<File> {
        let mut current = root.try_clone().map_err(|error| io_error(path, error))?;
        if !path.is_empty() {
            if !relative(path) || path.split('/').any(|part| EXCLUDED.contains(&part)) {
                return Err(invalid(
                    "workspace directory must be bounded, project-relative and outside reserved state",
                ));
            }
            for component in path.split('/') {
                current = File::from(
                    openat(
                        &current,
                        component,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|error| io_error(path, error))?,
                );
            }
        }
        Ok(current)
    }

    fn identity(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }

    /// Visit every selected directory once while its descriptor is held.
    /// The callback owns manifest capture and returns whether one existed;
    /// source bytes and semantic policy never move into the glob matcher.
    pub(crate) fn walk<E: From<ModuleResolutionGraphError>>(
        root: &File,
        selectors: &[String],
        limits: Limits,
        deadline: Option<Instant>,
        mut visit_manifest: impl FnMut(&str, &File) -> Result<bool, E>,
    ) -> Result<(), E> {
        check_deadline(deadline)?;
        let mut patterns = compile_patterns(selectors, limits.patterns, deadline, limits.mode)?;
        apply_mode(&mut patterns, selectors, limits.mode);
        if patterns.is_empty() {
            return Ok(());
        }
        enforce_len("package manifests", 1, limits.manifests)?;
        enforce_len("workspace directories", 1, limits.directories)?;
        let mut matched = vec![true; selectors.len()];
        for (selector, pattern) in &patterns {
            if !pattern.negative {
                matched[*selector] = false;
            }
        }
        let initial: Vec<_> = patterns
            .iter()
            .map(|(_, pattern)| pattern.start())
            .collect();
        let mut pending = vec![(String::new(), initial, 0_usize)];
        let (mut entries, mut directories, mut manifests) = (0_usize, 1_usize, 1_usize);
        while let Some((path, states, depth)) = pending.pop() {
            check_deadline(deadline)?;
            if excluded_subtree(&patterns, &states, limits.mode) {
                mark_excluded(&patterns, &states, &mut matched, true);
                continue;
            }
            let fd = open_directory(root, &path)?;
            let before = fd.metadata().map_err(|error| io_error(&path, error))?;
            let include = selected(&patterns, &states, limits.mode);
            if !path.is_empty() && include && visit_manifest(&path, &fd)? {
                manifests = manifests.saturating_add(1);
                enforce_len("package manifests", manifests, limits.manifests)?;
                for ((selector, pattern), state) in patterns.iter().zip(&states) {
                    if !pattern.negative {
                        matched[*selector] |= state.last() == Some(&true);
                    }
                }
            } else if !include {
                mark_excluded(&patterns, &states, &mut matched, false);
            }
            if !descend(&patterns, &states) {
                let after = fd.metadata().map_err(|error| io_error(&path, error))?;
                if identity(&before) != identity(&after) {
                    return Err(invalid("workspace directory changed during enumeration").into());
                }
                continue;
            }
            let mut children = BTreeMap::new();
            for entry in Dir::read_from(&fd).map_err(|error| io_error(&path, error))? {
                check_deadline(deadline)?;
                let entry = entry.map_err(|error| io_error(&path, error))?;
                let bytes = entry.file_name().to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                entries = entries.saturating_add(1);
                enforce_len("workspace directory entries", entries, limits.entries)?;
                let component = entry
                    .file_name()
                    .to_str()
                    .map_err(|_| invalid("workspace directory entry must be UTF-8"))?;
                if EXCLUDED.contains(&component) {
                    continue;
                }
                let next: Vec<_> = patterns
                    .iter()
                    .zip(&states)
                    .map(|((_, pattern), state)| {
                        // npm glob ignores include dot directories, even
                        // though its authored-selector minimatch does not.
                        pattern.step_with_dot(
                            state,
                            component,
                            limits.mode == WorkspaceSelectionMode::Npm && pattern.negative,
                        )
                    })
                    .collect();
                if !patterns.iter().zip(&next).any(|((_, pattern), state)| {
                    !pattern.negative && state.iter().any(|active| *active)
                }) {
                    continue;
                }
                let prune = excluded_subtree(&patterns, &next, limits.mode);
                if prune || (!selected(&patterns, &next, limits.mode) && !descend(&patterns, &next))
                {
                    mark_excluded(&patterns, &next, &mut matched, prune);
                    continue;
                }
                let stat = statat(&fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| io_error(&path, error))?;
                let kind = FileType::from_raw_mode(stat.st_mode);
                if kind == FileType::Symlink {
                    return Err(invalid(
                        "workspace selector may traverse a symlink; inventory refused",
                    )
                    .into());
                }
                if kind != FileType::Directory {
                    continue;
                }
                enforce_len(
                    "workspace traversal depth",
                    depth.saturating_add(1),
                    limits.depth,
                )?;
                directories = directories.saturating_add(1);
                enforce_len("workspace directories", directories, limits.directories)?;
                let child = if path.is_empty() {
                    component.into()
                } else {
                    format!("{path}/{component}")
                };
                if !relative(&child) {
                    return Err(invalid(
                        "workspace directory must be bounded and project-relative",
                    )
                    .into());
                }
                if children.insert(child, next).is_some() {
                    return Err(invalid("workspace directory changed during enumeration").into());
                }
            }
            let after = fd.metadata().map_err(|error| io_error(&path, error))?;
            if identity(&before) != identity(&after) {
                return Err(invalid("workspace directory changed during enumeration").into());
            }
            pending.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|(path, state)| (path, state, depth + 1)),
            );
        }
        if limits.require_matches && matched.iter().any(|seen| !seen) {
            return Err(invalid(
                "workspace selector matched no package manifests; incomplete inventory refused",
            )
            .into());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn limits() -> Limits {
            Limits {
                mode: WorkspaceSelectionMode::Npm,
                patterns: 8,
                manifests: 8,
                directories: 32,
                entries: 128,
                depth: 8,
                require_matches: true,
            }
        }

        #[test]
        fn star_matcher_handles_utf8_suffixes_and_does_not_match_path_separators() {
            assert!(component_matches("π*-app", "π工具-app"));
            assert!(component_matches("a*b*c", "axbybc"));
            assert!(!component_matches("a*b*c", "axbybd"));
            assert!(!component_matches("*", ".hidden"));
            assert!(component_matches(".hidden*", ".hidden-name"));
            let pattern = Pattern::parse("packages/*", WorkspaceSelectionMode::Npm).unwrap();
            let s = pattern.step(&pattern.start(), "packages");
            let s = pattern.step(&s, "a");
            assert_eq!(s.last(), Some(&true));
            assert!(!pattern.step(&s, "b").iter().any(|active| *active));
        }

        #[test]
        fn component_globs_match_single_units_lists_ranges_and_negation() {
            for (pattern, text, expected) in [
                ("pkg-?", "pkg-a", true),
                ("pkg-?", "pkg-ab", false),
                ("pkg-?", "pkg-", false),
                ("pkg-[ac]", "pkg-a", true),
                ("pkg-[ac]", "pkg-b", false),
                ("pkg-[a-c][0-9]", "pkg-b2", true),
                ("pkg-[a-c][0-9]", "pkg-d2", false),
                ("pkg-[!a-c]", "pkg-z", true),
                ("pkg-[^a-c]", "pkg-b", false),
                ("pkg-[-a]", "pkg--", true),
                ("pkg-[a-]", "pkg--", true),
                ("pkg-[*?]", "pkg-?", true),
                ("pkg-[a,b]", "pkg-,", true),
                ("*a?[0-9]", "aaabx7", false),
                ("*a?[0-9]", "aaab7", true),
                ("*", "one/two", false),
                ("[.]hidden", ".hidden", false),
                (".[a-z]*", ".hidden", true),
                ("π*-?", "π工具-x", true),
            ] {
                for mode in [WorkspaceSelectionMode::Npm, WorkspaceSelectionMode::Bun] {
                    let compiled = ComponentPattern::parse(pattern, mode).unwrap();
                    assert_eq!(
                        compiled.matches(text, false),
                        expected,
                        "{mode:?}: {pattern} {text}"
                    );
                }
            }
        }

        #[test]
        fn workspace_glob_unicode_units_follow_the_selected_package_manager() {
            // npm's shipped minimatch (10.x) uses non-u regular expressions
            // for this syntax; Bun's native glob consumes Unicode scalars.
            for (pattern, text, npm, bun) in [
                ("?", "é", true, true),
                ("?", "😀", false, true),
                ("??", "😀", true, false),
                ("😀", "😀", true, true),
                ("?[a-z]", "😀a", false, true),
                ("[!a]", "😀", false, true),
                ("[!a][!a]", "😀", true, false),
                ("*?x", "😀x", true, true),
                ("*😀?", "prefix😀é", true, true),
            ] {
                for (mode, expected) in [
                    (WorkspaceSelectionMode::Npm, npm),
                    (WorkspaceSelectionMode::Bun, bun),
                ] {
                    assert_eq!(
                        ComponentPattern::parse(pattern, mode)
                            .unwrap()
                            .matches(text, false),
                        expected,
                        "{mode:?}: {pattern} {text}",
                    );
                }
            }
        }

        #[test]
        fn workspace_component_globs_capture_exact_manifests_in_both_dialects() {
            let root = tempfile::tempdir().unwrap();
            for path in [
                "packages/pkg-a0",
                "packages/pkg-a4",
                "packages/pkg-b2",
                "packages/pkg-z3",
                "packages/.hidden",
                "apps/app-x",
                "apps/app-7",
            ] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
                std::fs::write(root.path().join(path).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            let selectors = [
                "packages/pkg-[ab]?".into(),
                "!packages/pkg-?[34]".into(),
                "apps/app-[!0-9]".into(),
            ];
            for mode in [WorkspaceSelectionMode::Npm, WorkspaceSelectionMode::Bun] {
                let mut found = Vec::new();
                walk::<ModuleResolutionGraphError>(
                    &held,
                    &selectors,
                    Limits { mode, ..limits() },
                    None,
                    |path, _| {
                        found.push(path.to_owned());
                        Ok(true)
                    },
                )
                .unwrap();
                assert_eq!(found, ["apps/app-x", "packages/pkg-a0", "packages/pkg-b2"]);
            }

            // A wildcard spelling must not acquire Bun's special authority
            // for an explicitly named directory and undo an exclusion.
            for selector in ["packages/pkg-a?", "packages/pkg-[a]0"] {
                let mut found = Vec::new();
                walk::<ModuleResolutionGraphError>(
                    &held,
                    &[selector.into(), "!packages/pkg-a*".into()],
                    Limits {
                        mode: WorkspaceSelectionMode::Bun,
                        ..limits()
                    },
                    None,
                    |path, _| {
                        found.push(path.to_owned());
                        Ok(true)
                    },
                )
                .unwrap();
                assert!(found.is_empty(), "{selector}");
            }
        }

        #[test]
        fn malformed_component_globs_fail_before_any_workspace_is_captured() {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("packages/a")).unwrap();
            let held = open_root(root.path()).unwrap();
            for bad in [
                "packages/[",
                "packages/[]",
                "packages/[!]",
                "packages/[^]",
                "packages/[z-a]",
                "packages/[a-b-c]",
                "packages/[[:digit:]]",
                "packages/[a/b]",
                "packages/[é]",
                "packages/[a{b,c}]",
                "packages/[{a,b}]",
                "packages/{pkg-[a,b],other}",
                "packages/a]",
                "packages/!(a)",
                "packages/{a,[z-a]}",
                "!packages/[z-a]",
            ] {
                for mode in [WorkspaceSelectionMode::Npm, WorkspaceSelectionMode::Bun] {
                    assert!(
                        walk::<ModuleResolutionGraphError>(
                            &held,
                            &["packages/a".into(), bad.into()],
                            Limits { mode, ..limits() },
                            None,
                            |_, _| panic!("malformed selector admitted its supported prefix"),
                        )
                        .is_err(),
                        "{mode:?}: {bad}",
                    );
                }
            }
            let oversized = format!("packages/[{}]", "a".repeat(MAX_PATH_BYTES));
            assert!(compile_patterns(&[oversized], 8, None, WorkspaceSelectionMode::Npm).is_err());
        }

        #[test]
        fn component_globs_keep_symlink_containment_and_negated_subtree_pruning() {
            use std::os::unix::fs::symlink;
            let root = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("packages/pkg-a1")).unwrap();
            symlink(outside.path(), root.path().join("packages/pkg-b1")).unwrap();
            let held = open_root(root.path()).unwrap();
            for mode in [WorkspaceSelectionMode::Npm, WorkspaceSelectionMode::Bun] {
                assert!(
                    walk::<ModuleResolutionGraphError>(
                        &held,
                        &["packages/pkg-??".into()],
                        Limits { mode, ..limits() },
                        None,
                        |_, _| Ok(true),
                    )
                    .is_err()
                );
                let mut found = Vec::new();
                walk::<ModuleResolutionGraphError>(
                    &held,
                    &["packages/pkg-??".into(), "!packages/pkg-b[0-9]/**".into()],
                    Limits { mode, ..limits() },
                    None,
                    |path, _| {
                        found.push(path.to_owned());
                        Ok(true)
                    },
                )
                .unwrap();
                assert_eq!(found, ["packages/pkg-a1"]);
            }
        }

        #[test]
        fn npm_exclusions_follow_reference_order_and_never_invent_an_included_universe() {
            // Expected sets observed with npm 11.19.1's map-workspaces API.
            // The candidate walker never executes npm or any package code.
            let root = tempfile::tempdir().unwrap();
            for path in [
                "packages/keep",
                "packages/legacy",
                "packages/legacy/sub",
                "packages/.hidden",
                "packages/.hidden/sub",
                "apps/web",
            ] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
                std::fs::write(root.path().join(path).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            for (selectors, expected) in [
                (
                    vec!["packages/*", "!packages/legacy"],
                    vec!["packages/keep"],
                ),
                (
                    vec!["!packages/legacy", "packages/*"],
                    vec!["packages/keep"],
                ),
                (vec!["packages/legacy", "!packages/legacy"], vec![]),
                (
                    vec!["!packages/legacy", "packages/legacy"],
                    vec!["packages/legacy"],
                ),
                (
                    vec!["packages/**", "!packages/legacy/**"],
                    vec!["packages/keep"],
                ),
                (
                    vec!["packages/**", "!packages/legacy"],
                    vec!["packages/keep", "packages/legacy/sub"],
                ),
                (
                    vec!["!packages/**", "packages/*"],
                    vec!["packages/keep", "packages/legacy"],
                ),
                (vec!["packages/*", "!packages/**"], vec![]),
                (
                    vec!["packages/*", "!packages/*", "packages/*"],
                    vec!["packages/keep", "packages/legacy"],
                ),
                (
                    vec!["packages/*", "!packages/**", "packages/keep"],
                    vec!["packages/keep", "packages/legacy"],
                ),
                (vec!["!packages/**", "!packages/*", "packages/keep"], vec![]),
                (
                    vec![
                        "packages/*",
                        "!packages/keep",
                        "!packages/keep",
                        "packages/keep",
                    ],
                    vec!["packages/legacy"],
                ),
                (
                    vec![
                        "packages/**",
                        "!packages/**",
                        "!packages/keep",
                        "packages/keep",
                    ],
                    vec!["packages/legacy", "packages/legacy/sub"],
                ),
                (
                    vec!["!packages/**", "!apps/**", "!packages/*", "packages/keep"],
                    vec!["packages/keep"],
                ),
                (vec!["!packages/legacy/**", "packages/legacy"], vec![]),
                (
                    vec!["!packages/legacy/**", "packages/legacy/"],
                    vec!["packages/legacy"],
                ),
                (
                    vec!["packages/**", "!packages/legacy/**", "packages/legacy/sub"],
                    vec!["packages/keep", "packages/legacy", "packages/legacy/sub"],
                ),
                (vec!["!packages/legacy/", "packages/legacy"], vec![]),
                (vec!["!packages/legacy"], vec![]),
                (
                    vec!["{apps,packages}/*", "!packages/legacy"],
                    vec!["apps/web", "packages/keep"],
                ),
                (
                    vec!["packages/*", "!missing/*"],
                    vec!["packages/keep", "packages/legacy"],
                ),
                (vec!["packages/.hidden", "!packages/*"], vec![]),
                (vec!["packages/.hidden/sub", "!packages/**/sub"], vec![]),
                (
                    vec!["packages/.hidden", "!packages/*", "packages/.hidden"],
                    vec![],
                ),
            ] {
                let selectors = selectors.into_iter().map(str::to_owned).collect::<Vec<_>>();
                let mut found = Vec::new();
                walk::<ModuleResolutionGraphError>(&held, &selectors, limits(), None, |path, _| {
                    let exists = root.path().join(path).join("package.json").is_file();
                    if exists {
                        found.push(path.to_owned());
                    }
                    Ok(exists)
                })
                .unwrap_or_else(|error| panic!("{selectors:?}: {error}"));
                assert_eq!(found, expected, "{selectors:?}");
            }
        }

        #[test]
        fn bun_negation_preserves_authored_literal_directories_but_not_brace_alternatives() {
            // Bun's documented workspace contract keeps ordinary path entries
            // regardless of exclusion order; brace alternatives remain globs.
            let root = tempfile::tempdir().unwrap();
            for path in ["packages/keep", "packages/legacy", "packages/legacy/sub"] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
                std::fs::write(root.path().join(path).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            for (selectors, expected) in [
                (
                    vec!["packages/*", "!packages/legacy"],
                    vec!["packages/keep"],
                ),
                (
                    vec!["packages/legacy", "!packages/legacy"],
                    vec!["packages/legacy"],
                ),
                (
                    vec!["!packages/legacy", "packages/legacy"],
                    vec!["packages/legacy"],
                ),
                (
                    vec!["packages/**", "!packages/legacy/**", "packages/legacy/sub"],
                    vec!["packages/keep", "packages/legacy/sub"],
                ),
                (
                    vec!["packages/{keep,legacy}", "!packages/legacy"],
                    vec!["packages/keep"],
                ),
                (vec!["!packages/**", "packages/*"], vec![]),
            ] {
                let selectors = selectors.into_iter().map(str::to_owned).collect::<Vec<_>>();
                let mut found = Vec::new();
                let policy = Limits {
                    mode: WorkspaceSelectionMode::Bun,
                    ..limits()
                };
                walk::<ModuleResolutionGraphError>(&held, &selectors, policy, None, |path, _| {
                    let exists = root.path().join(path).join("package.json").is_file();
                    if exists {
                        found.push(path.to_owned());
                    }
                    Ok(exists)
                })
                .unwrap_or_else(|error| panic!("{selectors:?}: {error}"));
                assert_eq!(found, expected, "{selectors:?}");
            }
        }

        #[test]
        fn excluded_subtrees_are_not_opened_and_do_not_hide_surviving_validation_failures() {
            use std::os::unix::fs::symlink;
            let root = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("packages/keep")).unwrap();
            std::fs::write(root.path().join("packages/keep/package.json"), "{}").unwrap();
            symlink(outside.path(), root.path().join("packages/excluded")).unwrap();
            let held = open_root(root.path()).unwrap();
            let selectors = ["packages/**".into(), "!packages/excluded/**".into()];
            let mut found = Vec::new();
            walk::<ModuleResolutionGraphError>(
                &held,
                &selectors,
                Limits {
                    directories: 3,
                    ..limits()
                },
                None,
                |path, _| {
                    assert!(!path.contains("excluded"));
                    let exists = root.path().join(path).join("package.json").is_file();
                    if exists {
                        found.push(path.to_owned());
                    }
                    Ok(exists)
                },
            )
            .unwrap();
            assert_eq!(found, ["packages/keep"]);
            for selectors in [
                vec!["packages/**", "!packages/excluded"],
                vec!["missing/*", "!packages/excluded/**"],
                vec!["packages/*", "!packages/{keep,../outside}"],
                vec!["packages/*", "!!packages/excluded"],
                vec!["{packages/keep,!packages/excluded}"],
            ] {
                let selectors = selectors.into_iter().map(str::to_owned).collect::<Vec<_>>();
                assert!(
                    walk::<ModuleResolutionGraphError>(
                        &held,
                        &selectors,
                        limits(),
                        None,
                        |_, _| Ok(true)
                    )
                    .is_err(),
                    "{selectors:?}"
                );
            }
        }

        #[test]
        fn brace_lists_expand_nested_utf8_empty_and_cross_directory_alternatives() {
            // Literal expansion sets also observed with npm 11.9.0's
            // minimatch.braceExpand; no filesystem or package code executes.
            for (source, expected) in [
                (
                    "packages/{core,{cli,工具}}",
                    vec!["packages/cli", "packages/core", "packages/工具"],
                ),
                ("{apps,packages}/*", vec!["apps/*", "packages/*"]),
                (
                    "packages/{,group/}core",
                    vec!["packages/core", "packages/group/core"],
                ),
                (
                    "./{apps,packages}/{a,b}/",
                    vec!["apps/a", "apps/b", "packages/a", "packages/b"],
                ),
            ] {
                let patterns =
                    compile_patterns(&[source.into()], 8, None, WorkspaceSelectionMode::Npm)
                        .unwrap();
                let mut actual = patterns
                    .iter()
                    .map(|(selector, pattern)| {
                        assert_eq!(*selector, 0);
                        pattern.parts.join("/")
                    })
                    .collect::<Vec<_>>();
                actual.sort();
                assert_eq!(actual, expected, "{source}");
            }
        }

        #[test]
        fn brace_alternatives_walk_once_and_match_the_authored_selector() {
            let root = tempfile::tempdir().unwrap();
            for path in [
                "apps/web",
                "packages/core",
                "packages/cli",
                "packages/group/工具",
            ] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
                std::fs::write(root.path().join(path).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            let selectors = [
                "apps/{web,missing}".into(),
                "packages/{core,{cli,group/*}}".into(),
                "packages/{core,core}".into(),
            ];
            let mut visits = Vec::new();
            walk::<ModuleResolutionGraphError>(&held, &selectors, limits(), None, |path, _| {
                visits.push(path.to_owned());
                Ok(root.path().join(path).join("package.json").is_file())
            })
            .unwrap();
            assert_eq!(
                visits,
                [
                    "apps/web",
                    "packages/cli",
                    "packages/core",
                    "packages/group/工具"
                ]
            );
            let error = walk::<ModuleResolutionGraphError>(
                &held,
                &["packages/{absent,missing}".into()],
                limits(),
                None,
                |_, _| panic!("absent alternatives must not visit a manifest"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("matched no package manifests"));
        }

        #[test]
        fn every_brace_branch_is_validated_before_a_manifest_is_opened() {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("packages/a")).unwrap();
            let held = open_root(root.path()).unwrap();
            for pattern in [
                "packages/{a,../outside}",
                "{packages/a,/outside}",
                "packages/{a,node_modules/private}",
                "packages/{a,.git/private}",
                "packages/{a,part-{1..3}}",
                "packages/{a,b[}",
                "packages/{a,{b}}",
                "packages/{a,{b,c}",
                "packages/{a,b}}",
                "packages/{}",
            ] {
                let result = walk::<ModuleResolutionGraphError>(
                    &held,
                    &[pattern.into()],
                    limits(),
                    None,
                    |_, _| panic!("invalid branch applied a supported prefix: {pattern}"),
                );
                assert!(result.is_err(), "{pattern}");
            }
        }

        #[test]
        fn brace_expansion_has_aggregate_nontruncating_pattern_and_depth_bounds() {
            let root = tempfile::tempdir().unwrap();
            let held = open_root(root.path()).unwrap();
            for selectors in [
                vec!["packages/{a,b,c}/{x,y,z}".into()],
                vec!["packages/{a,b,c,d}".into(), "apps/{a,b,c,d,e}".into()],
            ] {
                let failure = walk::<ModuleResolutionGraphError>(
                    &held,
                    &selectors,
                    limits(),
                    None,
                    |_, _| panic!("expansion limit must precede filesystem selection"),
                )
                .unwrap_err();
                assert!(
                    matches!(
                        failure,
                        ModuleResolutionGraphError::BoundExceeded {
                            bound: "expanded workspace patterns",
                            limit: 8
                        }
                    ),
                    "{failure}"
                );
            }
            let pattern = format!(
                "packages/{}a{}",
                "{x,".repeat(MAX_DEPTH + 1),
                "}".repeat(MAX_DEPTH + 1)
            );
            assert!(matches!(
                compile_patterns(&[pattern], 128, None, WorkspaceSelectionMode::Npm),
                Err(ModuleResolutionGraphError::BoundExceeded {
                    bound: "workspace brace depth",
                    ..
                })
            ));
            assert!(
                compile_patterns(
                    &["packages/{a,b}".into()],
                    8,
                    Some(Instant::now()),
                    WorkspaceSelectionMode::Npm,
                )
                .is_err()
            );
        }

        #[test]
        fn overlapping_selection_preserves_caller_bounds_and_never_returns_partial_success() {
            let root = tempfile::tempdir().unwrap();
            for directory in ["packages/a", "packages/b"] {
                std::fs::create_dir_all(root.path().join(directory)).unwrap();
                std::fs::write(root.path().join(directory).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            let selectors = ["packages/*".to_owned(), "packages/**".to_owned()];
            let present = |path: &str| root.path().join(path).join("package.json").is_file();
            let mut visits = Vec::new();
            walk::<ModuleResolutionGraphError>(&held, &selectors, limits(), None, |path, _| {
                visits.push(path.to_owned());
                Ok(present(path))
            })
            .unwrap();
            assert_eq!(visits, ["packages", "packages/a", "packages/b"]);

            for (limited, expected_bound) in [
                (
                    Limits {
                        patterns: 1,
                        ..limits()
                    },
                    "workspace patterns",
                ),
                (
                    Limits {
                        manifests: 2,
                        ..limits()
                    },
                    "package manifests",
                ),
                (
                    Limits {
                        directories: 2,
                        ..limits()
                    },
                    "workspace directories",
                ),
                (
                    Limits {
                        entries: 1,
                        ..limits()
                    },
                    "workspace directory entries",
                ),
                (
                    Limits {
                        depth: 1,
                        ..limits()
                    },
                    "workspace traversal depth",
                ),
            ] {
                let failure = walk::<ModuleResolutionGraphError>(
                    &held,
                    &selectors,
                    limited,
                    None,
                    |path, _| Ok(present(path)),
                )
                .unwrap_err();
                assert!(
                    matches!(failure, ModuleResolutionGraphError::BoundExceeded { bound, .. }
                    if bound == expected_bound),
                    "{failure}"
                );
            }
            let failure = walk::<ModuleResolutionGraphError>(
                &held,
                &selectors,
                limits(),
                Some(Instant::now()),
                |_, _| panic!("expired inventory must not capture a manifest"),
            )
            .unwrap_err();
            assert!(failure.to_string().contains("deadline exceeded"));
        }

        #[test]
        fn manifest_budget_counts_packages_instead_of_selected_directories() {
            let root = tempfile::tempdir().unwrap();
            for directory in ["packages/a", "packages/b", "packages/z-unpackaged"] {
                std::fs::create_dir_all(root.path().join(directory)).unwrap();
            }
            for directory in ["", "packages/a", "packages/b"] {
                std::fs::write(root.path().join(directory).join("package.json"), "{}").unwrap();
            }
            let held = open_root(root.path()).unwrap();
            let selectors = ["packages/**".to_owned()];
            let exact_budget = Limits {
                manifests: 3,
                ..limits()
            };
            let mut visits = Vec::new();
            walk::<ModuleResolutionGraphError>(&held, &selectors, exact_budget, None, |path, _| {
                visits.push(path.to_owned());
                Ok(root.path().join(path).join("package.json").is_file())
            })
            .unwrap();
            assert_eq!(
                visits,
                [
                    "packages",
                    "packages/a",
                    "packages/b",
                    "packages/z-unpackaged"
                ]
            );

            std::fs::write(root.path().join("packages/z-unpackaged/package.json"), "{}").unwrap();
            let failure = walk::<ModuleResolutionGraphError>(
                &held,
                &selectors,
                Limits {
                    manifests: 3,
                    ..limits()
                },
                None,
                |path, _| Ok(root.path().join(path).join("package.json").is_file()),
            )
            .unwrap_err();
            assert!(
                matches!(
                    failure,
                    ModuleResolutionGraphError::BoundExceeded {
                        bound: "package manifests",
                        limit: 3,
                    }
                ),
                "{failure}"
            );
        }

        #[test]
        fn terminal_directory_mutation_during_manifest_capture_is_refused() {
            for selector in ["packages/a", "packages/*"] {
                let root = tempfile::tempdir().unwrap();
                std::fs::create_dir_all(root.path().join("packages/a")).unwrap();
                let held = open_root(root.path()).unwrap();
                let failure = walk::<ModuleResolutionGraphError>(
                    &held,
                    &[selector.to_owned()],
                    limits(),
                    None,
                    |path, _| {
                        std::fs::write(root.path().join(path).join("new-entry"), "changed")
                            .unwrap();
                        Ok(true)
                    },
                )
                .unwrap_err();
                assert!(
                    failure.to_string().contains("changed during enumeration"),
                    "{failure}"
                );
            }
        }
    }
}

const MAX_PACKAGE_JSON_BYTES: u64 = 512 * 1024;
const MAX_CAPTURED_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_PACKAGE_MANIFESTS: usize = 256;
const MAX_WORKSPACE_PATTERNS: usize = 128;
const MAX_DEPENDENCY_EDGES: usize = 16_384;
const MAX_LOCKFILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOCKFILE_PACKAGES: usize = 16_384;
const MAX_LOCKFILE_DEPENDENCY_EDGES: usize = 65_536;
const MAX_CONDITIONAL_TARGETS: usize = 4_096;
const MODULE_RESOLUTION_GRAPH_HASH_DOMAIN: &[u8] =
    b"franken-node/module-resolution-graph/canonical-hash/v1:";

pub const MODULE_RESOLUTION_GRAPH_SCHEMA: &str = crate::schema_versions::MODULE_RESOLUTION_GRAPH;

#[derive(Debug)]
pub enum ModuleResolutionGraphError {
    MissingRootManifest {
        path: PathBuf,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    InvalidWorkspacePattern {
        pattern: String,
    },
    InvalidMetadata {
        detail: String,
    },
    BoundExceeded {
        bound: &'static str,
        limit: usize,
    },
}

impl fmt::Display for ModuleResolutionGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRootManifest { path } => {
                write!(
                    formatter,
                    "package manifest not found at {}",
                    path.display()
                )
            }
            Self::Io { path, source } => {
                write!(formatter, "failed reading {}: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(
                    formatter,
                    "failed parsing JSON from {}: {source}",
                    path.display()
                )
            }
            Self::InvalidWorkspacePattern { pattern } => {
                write!(formatter, "unsupported workspace pattern `{pattern}`")
            }
            Self::InvalidMetadata { detail } => {
                write!(formatter, "invalid package metadata: {detail}")
            }
            Self::BoundExceeded { bound, limit } => {
                write!(formatter, "{bound} exceeds deterministic bound of {limit}")
            }
        }
    }
}

impl std::error::Error for ModuleResolutionGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::MissingRootManifest { .. }
            | Self::InvalidWorkspacePattern { .. }
            | Self::InvalidMetadata { .. }
            | Self::BoundExceeded { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResolutionGraph {
    pub schema_version: String,
    pub project_root: String,
    pub root_package_id: String,
    /// Present when exclusions or character globs depend on the workspace
    /// dialect. The canonical payload prevents cross-manager hash reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_selection_mode: Option<WorkspaceSelectionMode>,
    pub packages: Vec<PackageNode>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub lockfile_pins: Vec<LockfilePin>,
    pub canonical_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageNode {
    pub package_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub relative_manifest_path: String,
    pub workspace: bool,
    pub workspace_patterns: Vec<String>,
    pub exports: Vec<ConditionalResolutionEntry>,
    pub imports: Vec<ConditionalResolutionEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Production,
    Development,
    Peer,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from_package_id: String,
    pub dependency_name: String,
    pub requested_range: String,
    pub dependency_kind: DependencyKind,
    pub target_package_id: Option<String>,
    pub lockfile_package_path: Option<String>,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalResolutionEntry {
    pub specifier: String,
    pub targets: Vec<ConditionalTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionalTarget {
    pub condition: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfilePin {
    pub package_path: String,
    pub package_name: String,
    pub version: Option<String>,
    pub resolved: Option<String>,
    pub integrity: Option<String>,
    pub dependencies: Vec<LockfileDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileDependency {
    pub name: String,
    pub requested_range: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ModuleResolutionGraphPayload {
    schema_version: String,
    project_root: String,
    root_package_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace_selection_mode: Option<WorkspaceSelectionMode>,
    packages: Vec<PackageNode>,
    dependency_edges: Vec<DependencyEdge>,
    lockfile_pins: Vec<LockfilePin>,
}

#[derive(Debug, Clone)]
struct ParsedManifest {
    relative_manifest_path: String,
    package: PackageNode,
    dependencies: Vec<DependencySpec>,
}

struct CapturedLockfile {
    path: PathBuf,
    raw: String,
    bun: bool,
}

#[derive(Default)]
struct CapturedManifests {
    values: BTreeMap<String, Value>,
    bytes: usize,
}

#[derive(Debug, Clone)]
struct DependencySpec {
    name: String,
    requested_range: String,
    kind: DependencyKind,
    optional: bool,
}

pub type ModuleResolutionGraphResult<T> = Result<T, ModuleResolutionGraphError>;

/// Read one bounded metadata file through the selected project authority.
/// The Unix path walks retained directory descriptors without following links;
/// a FIFO or device is refused before reading. Callers receive the captured
/// bytes rather than reopening a path after validating its contents.
pub fn read_project_metadata(
    project_root: &Path,
    relative_path: &Path,
    limit: u64,
) -> ModuleResolutionGraphResult<String> {
    use std::path::Component;
    let components: Vec<_> = relative_path.components().collect();
    if components.is_empty()
        || components.len() > 64
        || components
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return invalid_metadata("metadata path must be bounded and project-relative");
    }
    let path = project_root.join(relative_path);
    let read = || -> std::io::Result<String> {
        // An absolute root has already selected an authority. Do not
        // canonicalize it again: a replacement symlink must be refused,
        // not followed into a different project. Relative callers select
        // their authority once from the current working directory.
        let root = if project_root.is_absolute() {
            project_root.to_path_buf()
        } else {
            project_root.canonicalize()?
        };
        if root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "metadata authority must not contain parent traversal",
            ));
        }
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags, open, openat};
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut directory = std::fs::File::from(open("/", flags, Mode::empty())?);
            for part in root.components() {
                if let Component::Normal(name) = part {
                    directory =
                        std::fs::File::from(openat(&directory, name, flags, Mode::empty())?);
                }
            }
            for part in &components[..components.len() - 1] {
                directory = std::fs::File::from(openat(
                    &directory,
                    part.as_os_str(),
                    flags,
                    Mode::empty(),
                )?);
            }
            std::fs::File::from(openat(
                &directory,
                components.last().expect("nonempty path").as_os_str(),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?)
        };
        #[cfg(not(unix))]
        let file = {
            let mut checked = std::path::PathBuf::new();
            for part in root.components().chain(components.iter().copied()) {
                checked.push(part.as_os_str());
                if std::fs::symlink_metadata(&checked)?.is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "metadata symlinks are not allowed",
                    ));
                }
            }
            std::fs::File::open(checked)?
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata must be a regular file within its byte bound",
            ));
        }
        let mut raw = String::new();
        (&file)
            .take(limit.saturating_add(1))
            .read_to_string(&mut raw)?;
        if raw.len() as u64 > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata exceeded its byte bound while reading",
            ));
        }
        let after = file.metadata()?;
        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt;
            metadata.dev() != after.dev()
                || metadata.ino() != after.ino()
                || metadata.len() != after.len()
                || metadata.mtime() != after.mtime()
                || metadata.mtime_nsec() != after.mtime_nsec()
                || metadata.ctime() != after.ctime()
                || metadata.ctime_nsec() != after.ctime_nsec()
        };
        #[cfg(not(unix))]
        let changed = metadata.len() != after.len() || metadata.modified()? != after.modified()?;
        if changed || !after.is_file() || after.len() != raw.len() as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata changed while reading",
            ));
        }
        Ok(raw)
    };
    read().map_err(|source| ModuleResolutionGraphError::Io { path, source })
}

pub fn build_canonical_module_resolution_graph(
    project_root: impl AsRef<Path>,
) -> ModuleResolutionGraphResult<ModuleResolutionGraph> {
    build_graph_parts(project_root.as_ref()).map(|(graph, _)| graph)
}

// Both public views consume this one parse. In particular, topology must not
// read a second lockfile after binding itself to the first graph's hash.
fn build_graph_parts(
    project_root: &Path,
) -> ModuleResolutionGraphResult<(ModuleResolutionGraph, LockfileDetails)> {
    let root_manifest_path = project_root.join("package.json");
    if std::fs::symlink_metadata(&root_manifest_path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(ModuleResolutionGraphError::MissingRootManifest {
            path: root_manifest_path,
        });
    }

    let captured_lockfile = capture_package_lock(project_root)?;
    let bun = captured_lockfile.as_ref().is_some_and(|lock| lock.bun);
    // Capture each manifest once. File-directory dependencies, Bun and root
    // overrides use these same values for authority binding, never a second
    // filesystem read that could select different package declarations.
    let mut captured_manifests = Some(CapturedManifests::default());
    let root_manifest = parse_manifest(
        project_root,
        &root_manifest_path,
        false,
        captured_manifests.as_mut(),
    )?;
    #[cfg(not(target_os = "linux"))]
    let root_overrides = captured_manifests
        .as_ref()
        .and_then(|captured| captured.values.get(""))
        .and_then(|root| root.get("overrides"))
        .is_some_and(|rules| !rules.as_object().is_some_and(serde_json::Map::is_empty));
    #[cfg(not(target_os = "linux"))]
    if root_overrides {
        return invalid_metadata(
            "root override trust admission requires the native Linux metadata parser",
        );
    }
    let selection_mode = if bun {
        WorkspaceSelectionMode::Bun
    } else {
        WorkspaceSelectionMode::Npm
    };
    let workspace_selection_mode = root_manifest
        .package
        .workspace_patterns
        .iter()
        .any(|pattern| pattern.starts_with('!') || pattern.contains(['?', '[']))
        .then_some(selection_mode);
    let workspace_manifest_paths = collect_workspace_manifest_paths(
        project_root,
        &root_manifest.package.workspace_patterns,
        selection_mode,
    )?;

    let mut manifests = Vec::new();
    manifests.push(root_manifest);
    for manifest_path in workspace_manifest_paths {
        manifests.push(parse_manifest(
            project_root,
            &manifest_path,
            true,
            captured_manifests.as_mut(),
        )?);
        enforce_len("package manifests", manifests.len(), MAX_PACKAGE_MANIFESTS)?;
    }

    let Lockfile {
        pins: lockfile_pins,
        details,
    } = read_package_lock(captured_lockfile, captured_manifests.as_mut())?;
    let file_links = if !bun {
        capture_npm_file_manifests(
            project_root,
            &mut manifests,
            captured_manifests.as_mut().expect("root manifests are retained"),
            &lockfile_pins,
            &details,
        )?
    } else {
        BTreeSet::new()
    };
    if let Some(captured) = captured_manifests.filter(|_| bun) {
        for manifest in &mut manifests {
            let directory = manifest_directory(&manifest.relative_manifest_path);
            let value = captured.values.get(directory).ok_or_else(|| {
                ModuleResolutionGraphError::InvalidMetadata {
                    detail: "Bun normalization lost a captured manifest".into(),
                }
            })?;
            manifest.dependencies = effective_dependencies(value, true)?;
        }
    }

    manifests.sort_by(|left, right| {
        left.relative_manifest_path
            .cmp(&right.relative_manifest_path)
    });

    let packages = manifests
        .iter()
        .map(|manifest| manifest.package.clone())
        .collect::<Vec<_>>();
    let root_package_id = packages
        .iter()
        .find(|package| package.relative_manifest_path == "package.json")
        .map(|package| package.package_id.clone())
        .unwrap_or_default();
    let mut workspace_by_name = BTreeMap::new();
    let mut workspace_by_path = BTreeMap::new();
    for package in &packages {
        if package.workspace
            && let Some(name) = &package.name
            && workspace_by_name
                .insert(name.clone(), package.package_id.clone())
                .is_some()
        {
            return invalid_metadata(format!("duplicate workspace package name {name:?}"));
        }
        if package.relative_manifest_path != "package.json" {
            workspace_by_path.insert(manifest_directory(&package.relative_manifest_path), package);
        }
    }

    for (path, target) in &details.links {
        let Some(package) = workspace_by_path.get(target.as_str()) else {
            return invalid_metadata(format!(
                "lockfile link {path:?} targets an uncaptured workspace or file dependency {target:?}"
            ));
        };
        if !package.workspace && !file_links.contains(path) {
            return invalid_metadata("local directory link has no independently captured file: declaration");
        }
    }
    let lockfile_by_path = lockfile_pins
        .iter()
        .map(|pin| (pin.package_path.as_str(), pin))
        .collect::<BTreeMap<_, _>>();

    let mut dependency_edges = Vec::new();
    for manifest in &manifests {
        for dependency in &manifest.dependencies {
            let selected = nearest_lockfile_pin(
                manifest_directory(&manifest.relative_manifest_path),
                &dependency.name,
                &lockfile_by_path,
            );
            // A matching name alone is NOT evidence of an installed workspace.
            // Explicit workspace: requests express workspace intent; ordinary
            // version ranges bind only through a captured lockfile link.
            let target_package_id = if let Some(pin) = selected {
                details
                    .links
                    .get(&pin.package_path)
                    .and_then(|target| workspace_by_path.get(target.as_str()))
                    .map(|package| package.package_id.clone())
            } else if dependency.requested_range.starts_with("workspace:") {
                workspace_by_name.get(&dependency.name).cloned()
            } else {
                None
            };
            dependency_edges.push(DependencyEdge {
                from_package_id: manifest.package.package_id.clone(),
                dependency_name: dependency.name.clone(),
                requested_range: dependency.requested_range.clone(),
                dependency_kind: dependency.kind,
                target_package_id,
                lockfile_package_path: selected.map(|pin| pin.package_path.clone()),
                optional: dependency.optional,
            });
            enforce_len(
                "dependency edges",
                dependency_edges.len(),
                MAX_DEPENDENCY_EDGES,
            )?;
        }
    }
    dependency_edges.sort_by(|left, right| {
        (
            &left.from_package_id,
            &left.dependency_kind,
            &left.dependency_name,
        )
            .cmp(&(
                &right.from_package_id,
                &right.dependency_kind,
                &right.dependency_name,
            ))
    });

    let payload = ModuleResolutionGraphPayload {
        schema_version: MODULE_RESOLUTION_GRAPH_SCHEMA.to_string(),
        project_root: ".".to_string(),
        root_package_id,
        workspace_selection_mode,
        packages,
        dependency_edges,
        lockfile_pins,
    };
    let bytes = serialize_payload(&payload)?;
    let canonical_hash = canonical_hash(&bytes);

    Ok((
        ModuleResolutionGraph {
            schema_version: payload.schema_version,
            project_root: payload.project_root,
            root_package_id: payload.root_package_id,
            workspace_selection_mode: payload.workspace_selection_mode,
            packages: payload.packages,
            dependency_edges: payload.dependency_edges,
            lockfile_pins: payload.lockfile_pins,
            canonical_hash,
        },
        details,
    ))
}

pub fn canonical_module_resolution_graph_bytes(
    graph: &ModuleResolutionGraph,
) -> ModuleResolutionGraphResult<Vec<u8>> {
    serialize_payload(&ModuleResolutionGraphPayload {
        schema_version: graph.schema_version.clone(),
        project_root: graph.project_root.clone(),
        root_package_id: graph.root_package_id.clone(),
        workspace_selection_mode: graph.workspace_selection_mode,
        packages: graph.packages.clone(),
        dependency_edges: graph.dependency_edges.clone(),
        lockfile_pins: graph.lockfile_pins.clone(),
    })
}

pub fn recompute_module_resolution_graph_hash(
    graph: &ModuleResolutionGraph,
) -> ModuleResolutionGraphResult<String> {
    canonical_module_resolution_graph_bytes(graph).map(|bytes| canonical_hash(&bytes))
}

fn parse_manifest(
    project_root: &Path,
    manifest_path: &Path,
    workspace: bool,
    mut captured: Option<&mut CapturedManifests>,
) -> ModuleResolutionGraphResult<ParsedManifest> {
    let relative_path = manifest_path.strip_prefix(project_root).map_err(|_| {
        ModuleResolutionGraphError::InvalidMetadata {
            detail: "package manifest escaped its project root".into(),
        }
    })?;
    refuse_unsupported_dependency_authorities(
        project_root,
        relative_path.parent().unwrap_or(Path::new("")),
    )?;
    let raw = read_project_metadata(project_root, relative_path, MAX_PACKAGE_JSON_BYTES)?;
    if let Some(captured) = captured.as_mut() {
        captured.bytes = captured.bytes.saturating_add(raw.len());
        enforce_len(
            "captured manifest bytes",
            captured.bytes,
            MAX_CAPTURED_MANIFEST_BYTES,
        )?;
    }
    let text = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let value: Value = match captured.as_ref() {
        #[cfg(target_os = "linux")]
        Some(_) => crate::migration::dependency_admission::parse_unique(
            text.as_bytes(),
            std::time::Instant::now() + std::time::Duration::from_secs(15),
        )
        .map_err(|error| ModuleResolutionGraphError::InvalidMetadata {
            detail: format!("{}: {error:#}", manifest_path.display()),
        })?,
        _ => serde_json::from_str(text).map_err(|source| ModuleResolutionGraphError::Json {
            path: manifest_path.to_path_buf(),
            source,
        })?,
    };

    if !value.is_object() {
        return invalid_metadata("package manifest must contain an object");
    }

    let relative_manifest_path = relative_display(project_root, manifest_path);
    let manifest_dir = manifest_path.parent().unwrap_or(project_root);
    let relative_package_dir = relative_display(project_root, manifest_dir);
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(ToString::to_string);
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.trim().is_empty())
        .map(ToString::to_string);
    let package_id = package_id(name.as_deref(), version.as_deref(), &relative_package_dir);
    let workspace_patterns = if workspace {
        Vec::new()
    } else {
        workspace_patterns(&value)?
    };

    let dependencies = effective_dependencies(&value, true)?;

    let manifest = ParsedManifest {
        relative_manifest_path: relative_manifest_path.clone(),
        package: PackageNode {
            package_id,
            name,
            version,
            relative_manifest_path,
            workspace,
            workspace_patterns,
            exports: conditional_entries(value.get("exports"), true)?,
            imports: conditional_entries(value.get("imports"), false)?,
        },
        dependencies,
    };
    if let Some(captured) = captured {
        captured.values.insert(
            manifest_directory(&manifest.relative_manifest_path).to_owned(),
            value,
        );
    }
    Ok(manifest)
}

fn effective_dependencies(
    value: &Value,
    development: bool,
) -> ModuleResolutionGraphResult<Vec<DependencySpec>> {
    let mut dependencies = Vec::new();
    collect_dependencies(
        value,
        "dependencies",
        DependencyKind::Production,
        false,
        &mut dependencies,
    )?;
    if development {
        collect_dependencies(
            value,
            "devDependencies",
            DependencyKind::Development,
            false,
            &mut dependencies,
        )?;
    }
    collect_dependencies(
        value,
        "peerDependencies",
        DependencyKind::Peer,
        false,
        &mut dependencies,
    )?;
    collect_dependencies(
        value,
        "optionalDependencies",
        DependencyKind::Optional,
        true,
        &mut dependencies,
    )?;
    // npm optionalDependencies override same-name production requirements.
    // Installed development requirements are not part of the consumer graph.
    let optional: BTreeSet<_> = dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::Optional)
        .map(|dependency| dependency.name.clone())
        .collect();
    dependencies.retain(|dependency| {
        dependency.kind != DependencyKind::Production || !optional.contains(&dependency.name)
    });
    if let Some(meta) = value.get("peerDependenciesMeta") {
        let meta = meta
            .as_object()
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "peerDependenciesMeta must be an object".into(),
            })?;
        for (name, attributes) in meta {
            validate_package_name(name)?;
            if !attributes.is_object() {
                return invalid_metadata("peer dependency metadata must be an object");
            }
            let optional = match attributes.get("optional") {
                Some(Value::Bool(value)) => *value,
                None => false,
                Some(_) => return invalid_metadata("peer dependency optional must be a boolean"),
            };
            for dependency in dependencies.iter_mut().filter(|dependency| {
                dependency.kind == DependencyKind::Peer && dependency.name == *name
            }) {
                dependency.optional = optional;
            }
        }
    }
    dependencies.sort_by(|left, right| {
        (&left.kind, &left.name, &left.requested_range).cmp(&(
            &right.kind,
            &right.name,
            &right.requested_range,
        ))
    });

    Ok(dependencies)
}

fn collect_dependencies(
    manifest: &Value,
    field: &'static str,
    kind: DependencyKind,
    optional: bool,
    dependencies: &mut Vec<DependencySpec>,
) -> ModuleResolutionGraphResult<()> {
    let Some(value) = manifest.get(field) else {
        return Ok(());
    };
    let entries = value
        .as_object()
        .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
            detail: format!("manifest {field} must be an object"),
        })?;
    for (name, range) in entries {
        validate_package_name(name)?;
        let requested_range =
            range
                .as_str()
                .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                    detail: format!("{field} range for {name:?} must be a string"),
                })?;
        dependencies.push(DependencySpec {
            name: name.clone(),
            requested_range: requested_range.to_string(),
            kind,
            optional,
        });
        enforce_len("dependency edges", dependencies.len(), MAX_DEPENDENCY_EDGES)?;
    }
    Ok(())
}

fn workspace_patterns(manifest: &Value) -> ModuleResolutionGraphResult<Vec<String>> {
    let Some(workspaces) = manifest.get("workspaces") else {
        return Ok(Vec::new());
    };
    let items = match workspaces {
        Value::Array(items) => items,
        Value::Object(object) => object
            .get("packages")
            .and_then(Value::as_array)
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "workspace object requires a packages selector array".into(),
            })?,
        _ => return invalid_metadata("workspaces must be a selector array or a packages object"),
    };
    let mut patterns = Vec::new();
    for item in items {
        let pattern = item
            .as_str()
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "workspace selector must be a string".into(),
            })?;
        patterns.push(pattern.to_owned());
    }
    // npm negation can remove earlier positives or be cancelled by later
    // positives. Preserve that authored order, including repeated selectors.
    // Ordinary selector sets retain their existing canonical representation.
    if !patterns.iter().any(|pattern| pattern.starts_with('!')) {
        patterns.sort();
        patterns.dedup();
    }
    enforce_len("workspace patterns", patterns.len(), MAX_WORKSPACE_PATTERNS)?;
    Ok(patterns)
}

#[cfg(unix)]
fn collect_workspace_manifest_paths(
    project_root: &Path,
    patterns: &[String],
    mode: WorkspaceSelectionMode,
) -> ModuleResolutionGraphResult<Vec<PathBuf>> {
    use rustix::fs::{AtFlags, FileType, statat};

    if patterns.is_empty() {
        return Ok(Vec::new());
    }
    let root = workspace_selection::open_root(project_root)?;
    let mut manifests = Vec::new();
    workspace_selection::walk::<ModuleResolutionGraphError>(
        &root,
        patterns,
        workspace_selection::Limits {
            mode,
            patterns: MAX_WORKSPACE_PATTERNS,
            manifests: MAX_PACKAGE_MANIFESTS,
            directories: 4096,
            entries: 50_000,
            depth: 64,
            // A metadata topology may be partial. Checked migration retains
            // its stricter requirement that every selector match a manifest.
            require_matches: false,
        },
        None,
        |directory, fd| {
            let path = project_root.join(directory).join("package.json");
            match statat(fd, "package.json", AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(error) => Err(ModuleResolutionGraphError::Io {
                    path,
                    source: error.into(),
                }),
                Ok(metadata)
                    if FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile =>
                {
                    manifests.push(path);
                    Ok(true)
                }
                Ok(_) => invalid_metadata(
                    "workspace package.json must be a regular file, not a symlink or device",
                ),
            }
        },
    )?;
    manifests.sort();
    Ok(manifests)
}

// Preserve the existing portable selection path where the descriptor-relative
// reader and checked-migration capture are not available.
#[cfg(not(unix))]
fn collect_workspace_manifest_paths(
    project_root: &Path,
    patterns: &[String],
    _mode: WorkspaceSelectionMode,
) -> ModuleResolutionGraphResult<Vec<PathBuf>> {
    let mut manifests = BTreeSet::new();
    for pattern in patterns {
        for manifest in expand_workspace_pattern(project_root, pattern)? {
            manifests.insert(manifest);
            enforce_len(
                "package manifests",
                manifests.len().saturating_add(1),
                MAX_PACKAGE_MANIFESTS,
            )?;
        }
    }
    Ok(manifests.into_iter().collect())
}

#[cfg(not(unix))]
fn expand_workspace_pattern(
    project_root: &Path,
    pattern: &str,
) -> ModuleResolutionGraphResult<Vec<PathBuf>> {
    if pattern.trim().is_empty()
        || pattern.contains("..")
        || pattern.starts_with('/')
        || pattern.starts_with('!')
    {
        return Err(ModuleResolutionGraphError::InvalidWorkspacePattern {
            pattern: pattern.to_string(),
        });
    }
    if !pattern.contains('*') {
        let manifest = project_root.join(pattern).join("package.json");
        return Ok(manifest.exists().then_some(manifest).into_iter().collect());
    }
    if pattern.matches('*').count() != 1 || !pattern.ends_with("/*") {
        return Err(ModuleResolutionGraphError::InvalidWorkspacePattern {
            pattern: pattern.to_string(),
        });
    }

    let base = project_root.join(pattern.trim_end_matches("/*"));
    if !base.is_dir() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(&base).map_err(|source| ModuleResolutionGraphError::Io {
        path: base.clone(),
        source,
    })? {
        let entry = entry.map_err(|source| ModuleResolutionGraphError::Io {
            path: base.clone(),
            source,
        })?;
        let path = entry.path();
        if path.is_dir() {
            let manifest = path.join("package.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    Ok(manifests)
}

fn conditional_entries(
    field: Option<&Value>,
    exports_field: bool,
) -> ModuleResolutionGraphResult<Vec<ConditionalResolutionEntry>> {
    let Some(field) = field else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    match field {
        Value::String(_) => {
            entries.push(ConditionalResolutionEntry {
                specifier: ".".to_string(),
                targets: flatten_targets(field)?,
            });
        }
        Value::Object(object) if exports_field && object.keys().any(|key| key.starts_with('.')) => {
            for (specifier, value) in object {
                entries.push(ConditionalResolutionEntry {
                    specifier: specifier.clone(),
                    targets: flatten_targets(value)?,
                });
            }
        }
        Value::Object(object) if !exports_field => {
            for (specifier, value) in object {
                entries.push(ConditionalResolutionEntry {
                    specifier: specifier.clone(),
                    targets: flatten_targets(value)?,
                });
            }
        }
        Value::Object(_) => {
            entries.push(ConditionalResolutionEntry {
                specifier: ".".to_string(),
                targets: flatten_targets(field)?,
            });
        }
        _ => {}
    }

    entries.sort_by(|left, right| left.specifier.cmp(&right.specifier));
    enforce_len(
        "conditional resolution entries",
        entries.len(),
        MAX_CONDITIONAL_TARGETS,
    )?;
    Ok(entries)
}

fn flatten_targets(value: &Value) -> ModuleResolutionGraphResult<Vec<ConditionalTarget>> {
    let mut targets = Vec::new();
    flatten_targets_inner(value, &mut Vec::new(), &mut targets)?;
    targets.sort_by(|left, right| {
        (&left.condition, &left.target).cmp(&(&right.condition, &right.target))
    });
    Ok(targets)
}

fn flatten_targets_inner(
    value: &Value,
    conditions: &mut Vec<String>,
    targets: &mut Vec<ConditionalTarget>,
) -> ModuleResolutionGraphResult<()> {
    match value {
        Value::String(target) => {
            targets.push(ConditionalTarget {
                condition: if conditions.is_empty() {
                    "default".to_string()
                } else {
                    conditions.join(".")
                },
                target: target.clone(),
            });
            enforce_len(
                "conditional targets",
                targets.len(),
                MAX_CONDITIONAL_TARGETS,
            )?;
        }
        Value::Object(object) => {
            for (condition, nested) in object {
                conditions.push(condition.clone());
                flatten_targets_inner(nested, conditions, targets)?;
                conditions.pop();
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                conditions.push(format!("array_{index}"));
                flatten_targets_inner(nested, conditions, targets)?;
                conditions.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

#[derive(Default)]
struct Lockfile {
    pins: Vec<LockfilePin>,
    details: LockfileDetails,
}

#[derive(Default)]
struct LockfileDetails {
    lockfile_source: Option<dependency_topology::CapturedLockfileSource>,
    links: BTreeMap<String, String>,
    local_records: BTreeMap<String, Value>,
    requirements: BTreeMap<String, Vec<DependencySpec>>,
    dependency_kinds_complete: bool,
    edges: usize,
    #[cfg(target_os = "linux")]
    overrides: Option<crate::migration::dependency_admission::CapturedRootOverrides>,
}

impl LockfileDetails {
    fn record(
        &mut self,
        path: &str,
        requirements: Vec<DependencySpec>,
    ) -> ModuleResolutionGraphResult<()> {
        self.edges = self.edges.saturating_add(requirements.len());
        enforce_len(
            "lockfile dependency edges",
            self.edges,
            MAX_LOCKFILE_DEPENDENCY_EDGES,
        )?;
        self.requirements.insert(path.to_owned(), requirements);
        Ok(())
    }
}

fn invalid_metadata<T>(detail: impl Into<String>) -> ModuleResolutionGraphResult<T> {
    Err(ModuleResolutionGraphError::InvalidMetadata {
        detail: detail.into(),
    })
}

fn manifest_directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(directory, _)| directory)
}

/// npm <=11 directory requests are relative to the declaring package. Admit
/// only project-contained paths, not tarballs, URL encodings or global links.
/// Both checked migration and trust topology use this exact interpretation.
/// Contract: docs.npmjs.com/cli/v11/commands/npm-install/#description
pub(crate) fn npm_file_dependency_target(
    consumer: &str,
    request: &str,
) -> ModuleResolutionGraphResult<Option<String>> {
    let Some(path) = request.strip_prefix("file:") else {
        return Ok(None);
    };
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with(['/', '~'])
        || path.contains(['\\', ':', '%', '?', '#'])
        || path.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || [".tgz", ".tar", ".tar.gz"].iter().any(|suffix| path.ends_with(*suffix))
    {
        return invalid_metadata("file: dependency must name a bounded project-local directory");
    }
    let mut parts: Vec<_> = consumer.split('/').filter(|part| !part.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return invalid_metadata("file: dependency escapes its project root");
                }
            }
            "" | ".git" | ".franken-node" | "node_modules" => {
                return invalid_metadata("file: dependency targets a reserved or ambiguous directory");
            }
            _ => parts.push(part),
        }
        enforce_len("file dependency path components", parts.len(), 64)?;
    }
    if parts.is_empty() {
        return invalid_metadata("file: dependency cannot target the project root");
    }
    let target = parts.join("/");
    enforce_len("file dependency path bytes", target.len(), 4096)?;
    validate_lock_path(&target)?;
    Ok(Some(target))
}

/// A lock's local-package descriptor cannot supply the manifest it purports
/// to pin. Compare it with separately captured bytes, including runtime peers
/// and optionality. Local development dependencies are not installed edges.
pub(crate) fn npm_file_manifest_matches(manifest: &Value, recorded: &Value) -> bool {
    let Some(name) = manifest.get("name").and_then(Value::as_str) else {
        return false;
    };
    let Some(version) = manifest.get("version").and_then(Value::as_str) else {
        return false;
    };
    if validate_package_name(name).is_err()
        || version.is_empty()
        || version.len() > 256
        || version.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || recorded.get("version").and_then(Value::as_str) != Some(version)
        || recorded.get("name").is_some_and(|value| value.as_str() != Some(name))
        || recorded.get("link").is_some_and(|value| value.as_bool() != Some(false))
    {
        return false;
    }
    let empty = serde_json::Map::new();
    ["dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"]
        .into_iter()
        .all(|field| {
            let left = manifest.get(field).map_or(Some(&empty), Value::as_object);
            let right = recorded.get(field).map_or(Some(&empty), Value::as_object);
            left.is_some() && left == right
        })
}

fn capture_npm_file_manifests(
    project_root: &Path,
    manifests: &mut Vec<ParsedManifest>,
    captured: &mut CapturedManifests,
    pins: &[LockfilePin],
    details: &LockfileDetails,
) -> ModuleResolutionGraphResult<BTreeSet<String>> {
    let by_path = pins.iter().map(|pin| (pin.package_path.as_str(), pin)).collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut visited = 0;
    let mut edges = 0;
    let mut bound = BTreeSet::new();
    while visited < manifests.len() {
        if std::time::Instant::now() >= deadline {
            return invalid_metadata("file dependency capture deadline exceeded");
        }
        let manifest = &manifests[visited];
        let consumer = manifest_directory(&manifest.relative_manifest_path).to_owned();
        // The ordinary graph retains all kinds; file discovery follows npm's
        // winning declaration so a superseded optional edge grants no access.
        let mut selected = BTreeMap::new();
        for kind in [DependencyKind::Peer, DependencyKind::Production,
            DependencyKind::Optional, DependencyKind::Development] {
            for edge in manifest.dependencies.iter().filter(|edge| edge.kind == kind) {
                selected.insert(edge.name.clone(), edge.clone());
            }
        }
        visited += 1;
        for edge in selected.into_values() {
            edges += 1;
            enforce_len("file dependency edges", edges, MAX_DEPENDENCY_EDGES)?;
            let Some(target) = npm_file_dependency_target(&consumer, &edge.requested_range)? else {
                continue;
            };
            if captured.values[""].get("overrides").is_some_and(|rules| {
                !rules.as_object().is_some_and(serde_json::Map::is_empty)
            }) {
                return invalid_metadata("file: dependencies with root overrides require explicit review");
            }
            let Some(pin) = nearest_lockfile_pin(&consumer, &edge.name, &by_path) else {
                if edge.optional {
                    continue;
                }
                return invalid_metadata("file: dependency has no nearest locked installation");
            };
            if details.links.get(&pin.package_path) != Some(&target) {
                return invalid_metadata("file: request differs from its nearest locked link target");
            }
            let record = details.local_records.get(&target).ok_or_else(|| {
                ModuleResolutionGraphError::InvalidMetadata {
                    detail: "file: link has no captured local lock descriptor".into(),
                }
            })?;
            if !captured.values.contains_key(&target) {
                enforce_len("package manifests", manifests.len() + 1, MAX_PACKAGE_MANIFESTS)?;
                let mut local = parse_manifest(
                    project_root,
                    &project_root.join(&target).join("package.json"),
                    true,
                    Some(&mut *captured),
                )?;
                let value = &captured.values[&target];
                if value.get("workspaces").is_some() {
                    return invalid_metadata("file: dependency cannot introduce another workspace authority");
                }
                local.package.workspace = false;
                local.dependencies = effective_dependencies(value, false)?;
                manifests.push(local);
            }
            let value = &captured.values[&target];
            if value.get("name").and_then(Value::as_str) != Some(edge.name.as_str())
                || !npm_file_manifest_matches(value, record)
            {
                return invalid_metadata("file: dependency name, version or runtime declarations differ from its captured lock descriptor");
            }
            bound.insert(pin.package_path.clone());
            for name in ["package-lock.json", "npm-shrinkwrap.json", "bun.lock"] {
                let path = Path::new(&target).join(name);
                match read_project_metadata(project_root, &path, 0) {
                    Err(ModuleResolutionGraphError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return invalid_metadata("file: dependency has an independent lock authority"),
                }
            }
        }
    }
    Ok(bound)
}

pub(crate) fn validate_package_name(name: &str) -> ModuleResolutionGraphResult<()> {
    let components: Vec<_> = name.split('/').collect();
    let scoped = name.starts_with('@');
    let valid = name.len() <= 214
        && components.len() == if scoped { 2 } else { 1 }
        && components.iter().enumerate().all(|(index, part)| {
            let part: &str = if scoped && index == 0 {
                &part[1..]
            } else {
                part
            };
            !part.is_empty()
                && part != "."
                && part != ".."
                && part != "node_modules"
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte))
        });
    if !valid {
        return invalid_metadata(format!("unsupported or unsafe dependency name {name:?}"));
    }
    Ok(())
}

fn validate_lock_path(path: &str) -> ModuleResolutionGraphResult<()> {
    if path.len() > 4096
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || (!path.is_empty()
            && path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return invalid_metadata(format!(
            "lockfile location must be canonical and project-relative: {path:?}"
        ));
    }
    Ok(())
}

fn nearest_lockfile_pin<'a>(
    importer: &str,
    dependency: &str,
    pins: &BTreeMap<&str, &'a LockfilePin>,
) -> Option<&'a LockfilePin> {
    let mut directory = importer;
    loop {
        // Node does not probe node_modules/node_modules while ascending.
        if directory.rsplit('/').next() != Some("node_modules") {
            let candidate = if directory.is_empty() {
                format!("node_modules/{dependency}")
            } else {
                format!("{directory}/node_modules/{dependency}")
            };
            if let Some(pin) = pins.get(candidate.as_str()) {
                return Some(*pin);
            }
        }
        if directory.is_empty() {
            return None;
        }
        directory = directory.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

fn optional_string(package: &Value, field: &str) -> ModuleResolutionGraphResult<Option<String>> {
    match package.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => invalid_metadata(format!("lockfile {field} must be a string")),
    }
}

/// Unsupported lock/workspace and loader authorities cannot disappear into an
/// otherwise clean npm/Bun dependency inventory. Keep migration and runtime
/// topology on the same explicitly refused set.
pub(crate) const UNSUPPORTED_DEPENDENCY_AUTHORITY_FILES: &[&str] = &[
    "bun.lockb",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    ".pnp.cjs",
    ".pnp.js",
    ".pnp.data.json",
    ".pnp.loader.mjs",
];

fn refuse_unsupported_dependency_authorities(
    project_root: &Path,
    directory: &Path,
) -> ModuleResolutionGraphResult<()> {
    for name in UNSUPPORTED_DEPENDENCY_AUTHORITY_FILES {
        let path = directory.join(name);
        // A zero-byte probe rejects every present entry without decoding an
        // unsupported format. The shared reader also refuses links, devices,
        // directories and FIFOs before reading; only absence may proceed.
        match read_project_metadata(project_root, &path, 0) {
            Err(ModuleResolutionGraphError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return invalid_metadata(format!(
                    "unsupported dependency authority {}; select a reviewed npm or Bun text-lock project before trust admission",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn capture_package_lock(
    project_root: &Path,
) -> ModuleResolutionGraphResult<Option<CapturedLockfile>> {
    // A binary lock cannot silently turn a Bun project into a manifest-only
    // trust inventory. Probe with a zero byte budget: no binary is allocated
    // or decoded, and links/devices remain refused by the shared reader.
    match read_project_metadata(project_root, Path::new("bun.lockb"), 0) {
        Err(ModuleResolutionGraphError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return invalid_metadata(
                "binary bun.lockb cannot supply dependency trust; select a reviewed bun.lock text lockfile",
            );
        }
    }
    // npm's published lockfile contract gives shrinkwrap precedence. A
    // malformed or unreadable preferred file must not fall back to another
    // dependency tree that omits a revoked transitive package.
    let mut captured = None;
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        match read_project_metadata(project_root, Path::new(name), MAX_LOCKFILE_BYTES) {
            Ok(raw) => {
                captured = Some(CapturedLockfile {
                    path: project_root.join(name),
                    raw,
                    bun: false,
                });
                break;
            }
            Err(ModuleResolutionGraphError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    match read_project_metadata(project_root, Path::new("bun.lock"), MAX_LOCKFILE_BYTES) {
        Ok(raw) => {
            if captured.is_some() {
                return invalid_metadata(
                    "Bun and npm lockfiles are both present; select one dependency authority before trust admission",
                );
            }
            captured = Some(CapturedLockfile {
                path: project_root.join("bun.lock"),
                raw,
                bun: true,
            });
        }
        Err(ModuleResolutionGraphError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(captured)
}

fn read_package_lock(
    captured: Option<CapturedLockfile>,
    captured_manifests: Option<&mut CapturedManifests>,
) -> ModuleResolutionGraphResult<Lockfile> {
    #[cfg(target_os = "linux")]
    let mut captured_manifests = captured_manifests;
    let Some(CapturedLockfile {
        path: lockfile_path,
        raw,
        bun,
    }) = captured
    else {
        let lockfile = Lockfile::default();
        #[cfg(target_os = "linux")]
        let mut lockfile = lockfile;
        #[cfg(target_os = "linux")]
        if let Some(manifests) = captured_manifests {
            lockfile.details.overrides =
                crate::migration::dependency_admission::capture_topology_overrides(
                    &manifests.values,
                    None,
                    false,
                    std::time::Instant::now() + std::time::Duration::from_secs(15),
                )
                .map_err(|error| ModuleResolutionGraphError::InvalidMetadata {
                    detail: format!("captured root override authority: {error:#}"),
                })?;
        }
        return Ok(lockfile);
    };
    let value: Value = if bun {
        #[cfg(target_os = "linux")]
        {
            let captured_manifests = captured_manifests.as_deref_mut().ok_or_else(|| {
                ModuleResolutionGraphError::InvalidMetadata {
                    detail: "Bun lockfile requires captured project manifests".into(),
                }
            })?;
            crate::migration::dependency_admission::project_bun_lock_for_topology(
                raw.as_bytes(),
                &mut captured_manifests.values,
                std::time::Instant::now() + std::time::Duration::from_secs(15),
            )
            .map_err(|error| ModuleResolutionGraphError::InvalidMetadata {
                detail: format!("{}: {error:#}", lockfile_path.display()),
            })?
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = captured_manifests;
            return invalid_metadata(
                "Bun text-lock trust admission requires the native Linux metadata parser",
            );
        }
    } else {
        match captured_manifests.as_ref() {
            #[cfg(target_os = "linux")]
            Some(_) => crate::migration::dependency_admission::parse_unique(
                raw.as_bytes(),
                std::time::Instant::now() + std::time::Duration::from_secs(15),
            )
            .map_err(|error| ModuleResolutionGraphError::InvalidMetadata {
                detail: format!("{}: {error:#}", lockfile_path.display()),
            })?,
            _ => serde_json::from_str(&raw).map_err(|source| ModuleResolutionGraphError::Json {
                path: lockfile_path.clone(),
                source,
            })?,
        }
    };

    if !value.is_object() {
        return invalid_metadata("npm lockfile must contain an object");
    }
    if let Some(version) = value.get("lockfileVersion")
        && !matches!(version.as_u64(), Some(1..=3))
    {
        return invalid_metadata("unsupported lockfileVersion; supported versions are 1, 2 and 3");
    }
    let supported_shape = value.get("packages").is_some_and(Value::is_object)
        || value.get("dependencies").is_some_and(Value::is_object)
        || (value.get("lockfileVersion").and_then(Value::as_u64) == Some(1)
            && value.get("packages").is_none()
            && value.get("dependencies").is_none());
    if !supported_shape {
        return invalid_metadata(
            "unsupported lockfile dependency shape: expected a packages or dependencies object, or an empty version 1 lockfile",
        );
    }
    let mut lockfile = Lockfile::default();
    lockfile.details.lockfile_source = Some(dependency_topology::CapturedLockfileSource {
        path: lockfile_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "captured lockfile name is not UTF-8".into(),
            })?
            .to_owned(),
        sha256: format!("sha256:{}", hex::encode(Sha256::digest(raw.as_bytes()))),
    });
    #[cfg(target_os = "linux")]
    if let Some(manifests) = captured_manifests {
        lockfile.details.overrides =
            crate::migration::dependency_admission::capture_topology_overrides(
                &manifests.values,
                Some(&value),
                bun,
                std::time::Instant::now() + std::time::Duration::from_secs(15),
            )
            .map_err(|error| ModuleResolutionGraphError::InvalidMetadata {
                detail: format!("captured root override authority: {error:#}"),
            })?;
    }
    if let Some(packages_value) = value.get("packages") {
        lockfile.details.dependency_kinds_complete = true;
        let packages = packages_value.as_object().ok_or_else(|| {
            ModuleResolutionGraphError::InvalidMetadata {
                detail: "lockfile packages must be an object".into(),
            }
        })?;
        enforce_len(
            "lockfile package records",
            packages.len(),
            MAX_LOCKFILE_PACKAGES + 1,
        )?;
        for (package_path, package) in packages {
            validate_lock_path(package_path)?;
            if !package.is_object() {
                return invalid_metadata(format!(
                    "lockfile record {package_path:?} must be an object"
                ));
            }
            if package_path.is_empty() {
                continue;
            }
            let Some(package_name) = package_name_from_lock_path(package_path) else {
                if package_path.split('/').any(|part| part == "node_modules") {
                    return invalid_metadata(format!(
                        "invalid installed package location {package_path:?}"
                    ));
                }
                if matches!(value.get("lockfileVersion").and_then(Value::as_u64), Some(2 | 3)) {
                    lockfile
                        .details
                        .local_records
                        .insert(package_path.clone(), package.clone());
                }
                continue;
            };
            validate_package_name(&package_name)?;
            let package_name = optional_string(package, "name")?.unwrap_or(package_name);
            validate_package_name(&package_name)?;
            let resolved = optional_string(package, "resolved")?;
            match package.get("link") {
                Some(Value::Bool(true)) => {
                    let target = resolved.as_ref().ok_or_else(|| {
                        ModuleResolutionGraphError::InvalidMetadata {
                            detail: format!("lockfile link {package_path:?} has no target"),
                        }
                    })?;
                    validate_lock_path(target)?;
                    lockfile
                        .details
                        .links
                        .insert(package_path.clone(), target.clone());
                }
                None | Some(Value::Bool(false)) => {}
                Some(_) => return invalid_metadata("lockfile link must be a boolean"),
            }
            lockfile
                .details
                .record(package_path, effective_dependencies(package, false)?)?;
            lockfile.pins.push(LockfilePin {
                package_path: package_path.clone(),
                package_name,
                version: optional_string(package, "version")?,
                // Bun's tuple placeholders mean unavailable metadata, not
                // an empty artifact identity that a trust card can match.
                resolved: resolved.filter(|value| !bun || !value.is_empty()),
                integrity: optional_string(package, "integrity")?
                    .filter(|value| !bun || !value.is_empty()),
                dependencies: lockfile_dependencies(package.get("dependencies"))?,
            });
            enforce_len(
                "lockfile packages",
                lockfile.pins.len(),
                MAX_LOCKFILE_PACKAGES,
            )?;
        }
    } else if value
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .is_some_and(|version| version >= 2)
    {
        return invalid_metadata("modern lockfile is missing its authoritative packages object");
    } else {
        // npm v1 records an installation hierarchy, not a global version map.
        // A modern packages map wins over its redundant legacy dependencies.
        read_legacy_packages(value.get("dependencies"), "", 0, &mut lockfile)?;
    }
    lockfile
        .pins
        .sort_by(|left, right| left.package_path.cmp(&right.package_path));
    Ok(lockfile)
}

fn read_legacy_packages(
    dependencies: Option<&Value>,
    parent: &str,
    depth: usize,
    lockfile: &mut Lockfile,
) -> ModuleResolutionGraphResult<()> {
    enforce_len("legacy lockfile nesting", depth, 64)?;
    let Some(dependencies) = dependencies else {
        return Ok(());
    };
    let entries =
        dependencies
            .as_object()
            .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                detail: "legacy lockfile dependencies must be an object".into(),
            })?;
    for (name, package) in entries {
        validate_package_name(name)?;
        if !package.is_object() {
            return invalid_metadata("legacy package record must be an object");
        }
        let path = if parent.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{parent}/node_modules/{name}")
        };
        validate_lock_path(&path)?;
        let requirements = lockfile_dependencies(package.get("requires"))?;
        lockfile.details.record(
            &path,
            requirements
                .iter()
                .map(|dependency| DependencySpec {
                    name: dependency.name.clone(),
                    requested_range: dependency.requested_range.clone(),
                    kind: DependencyKind::Production,
                    optional: false,
                })
                .collect(),
        )?;
        lockfile.pins.push(LockfilePin {
            package_path: path.clone(),
            package_name: name.clone(),
            version: optional_string(package, "version")?,
            resolved: optional_string(package, "resolved")?,
            integrity: optional_string(package, "integrity")?,
            dependencies: requirements,
        });
        enforce_len(
            "lockfile packages",
            lockfile.pins.len(),
            MAX_LOCKFILE_PACKAGES,
        )?;
        read_legacy_packages(package.get("dependencies"), &path, depth + 1, lockfile)?;
    }
    Ok(())
}

fn lockfile_dependencies(
    value: Option<&Value>,
) -> ModuleResolutionGraphResult<Vec<LockfileDependency>> {
    let mut dependencies = Vec::new();
    if let Some(value) = value {
        let object =
            value
                .as_object()
                .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                    detail: "lockfile dependency requirements must be an object".into(),
                })?;
        for (name, range) in object {
            validate_package_name(name)?;
            let requested_range =
                range
                    .as_str()
                    .ok_or_else(|| ModuleResolutionGraphError::InvalidMetadata {
                        detail: format!(
                            "lockfile dependency requirement for {name:?} must be a string"
                        ),
                    })?;
            dependencies.push(LockfileDependency {
                name: name.clone(),
                requested_range: requested_range.to_string(),
            });
            enforce_len(
                "lockfile dependencies",
                dependencies.len(),
                MAX_DEPENDENCY_EDGES,
            )?;
        }
    }
    dependencies.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(dependencies)
}

fn package_name_from_lock_path(package_path: &str) -> Option<String> {
    let parts: Vec<_> = package_path.split('/').collect();
    let offset = parts.iter().rposition(|part| *part == "node_modules")?;
    let suffix = &parts[offset + 1..];
    match suffix {
        [scope, name] if scope.starts_with('@') => Some(format!("{scope}/{name}")),
        [name] if !name.starts_with('@') && !name.is_empty() => Some((*name).to_owned()),
        _ => None,
    }
}

fn package_id(name: Option<&str>, version: Option<&str>, relative_package_dir: &str) -> String {
    let stable_path = if relative_package_dir.is_empty() {
        "."
    } else {
        relative_package_dir
    };
    match (name, version) {
        (Some(name), Some(version)) => format!("npm:{name}@{version}#{stable_path}"),
        (Some(name), None) => format!("npm:{name}@unknown#{stable_path}"),
        (None, Some(version)) => format!("manifest:{stable_path}@{version}"),
        (None, None) => format!("manifest:{stable_path}"),
    }
}

fn serialize_payload(
    payload: &ModuleResolutionGraphPayload,
) -> ModuleResolutionGraphResult<Vec<u8>> {
    serde_json::to_vec(payload).map_err(|source| ModuleResolutionGraphError::Json {
        path: PathBuf::from("<module-resolution-graph>"),
        source,
    })
}

fn canonical_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MODULE_RESOLUTION_GRAPH_HASH_DOMAIN);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn enforce_len(
    bound: &'static str,
    actual: usize,
    limit: usize,
) -> ModuleResolutionGraphResult<()> {
    if actual > limit {
        return Err(ModuleResolutionGraphError::BoundExceeded { bound, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn canonical_graph_captures_workspaces_lockfile_and_conditions() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("packages/app")).expect("app dir");
        std::fs::create_dir_all(root.join("packages/lib")).expect("lib dir");
        std::fs::write(
            root.join("package.json"),
            r##"{
                "name": "root-app",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {"left-pad": "^1.3.0"},
                "devDependencies": {"@scope/tool": "~2.0.0"},
                "exports": {
                    ".": {"import": "./esm/index.js", "require": "./cjs/index.cjs"},
                    "./feature": {"node": {"import": "./esm/feature.js"}}
                },
                "imports": {"#internal": {"default": "./src/internal.js"}}
            }"##,
        )
        .expect("root package");
        std::fs::write(
            root.join("packages/app/package.json"),
            r#"{"name":"@acme/app","version":"0.1.0","dependencies":{"@acme/lib":"workspace:*"}}"#,
        )
        .expect("app package");
        std::fs::write(
            root.join("packages/lib/package.json"),
            r#"{"name":"@acme/lib","version":"0.1.0","peerDependencies":{"react":"^18.2.0"}}"#,
        )
        .expect("lib package");
        std::fs::write(
            root.join("package-lock.json"),
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root-app", "version": "1.0.0"},
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                        "integrity": "sha512-left",
                        "dependencies": {"repeat-string": "^1.6.1"}
                    },
                    "node_modules/@scope/tool": {
                        "version": "2.0.1",
                        "integrity": "sha512-tool"
                    },
                    "node_modules/repeat-string": {"version": "1.6.1"}
                }
            }"#,
        )
        .expect("lockfile");

        let graph = build_canonical_module_resolution_graph(root).expect("graph");

        assert_eq!(graph.schema_version, MODULE_RESOLUTION_GRAPH_SCHEMA);
        assert_eq!(graph.workspace_selection_mode, None);
        let serialized = serde_json::to_value(&graph).expect("serialize graph");
        assert!(serialized.get("workspace_selection_mode").is_none());
        assert_eq!(
            serde_json::from_value::<ModuleResolutionGraph>(serialized).expect("legacy graph"),
            graph
        );
        assert_eq!(graph.packages.len(), 3);
        assert_eq!(graph.lockfile_pins.len(), 3);
        assert!(graph.dependency_edges.iter().any(|edge| {
            edge.dependency_name == "@acme/lib"
                && edge
                    .target_package_id
                    .as_deref()
                    .is_some_and(|id| id.contains("@acme/lib"))
        }));
        assert!(
            graph
                .dependency_edges
                .iter()
                .any(|edge| edge.dependency_name == "left-pad"
                    && edge.lockfile_package_path.as_deref() == Some("node_modules/left-pad"))
        );

        let root_package = graph
            .packages
            .iter()
            .find(|package| package.name.as_deref() == Some("root-app"))
            .expect("root package node");
        let export_targets = root_package
            .exports
            .iter()
            .find(|entry| entry.specifier == ".")
            .expect("root export")
            .targets
            .iter()
            .map(|target| (target.condition.as_str(), target.target.as_str()))
            .collect::<BTreeSet<_>>();
        assert!(export_targets.contains(&("import", "./esm/index.js")));
        assert!(export_targets.contains(&("require", "./cjs/index.cjs")));

        let bytes = canonical_module_resolution_graph_bytes(&graph).expect("canonical bytes");
        assert!(
            serde_json::from_slice::<Value>(&bytes)
                .expect("canonical payload")
                .get("workspace_selection_mode")
                .is_none()
        );
        let hash = recompute_module_resolution_graph_hash(&graph).expect("hash");
        assert_eq!(graph.canonical_hash, hash);
        assert!(
            String::from_utf8(bytes)
                .expect("json")
                .contains("\"dependency_edges\"")
        );
    }

    #[test]
    fn graph_is_deterministic_for_repeated_builds() {
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"deterministic","version":"1.0.0","dependencies":{"b":"2","a":"1"}}"#,
        )
        .expect("package");

        let first = build_canonical_module_resolution_graph(root).expect("first");
        let second = build_canonical_module_resolution_graph(root).expect("second");

        assert_eq!(first, second);
        assert_eq!(
            canonical_module_resolution_graph_bytes(&first).expect("first bytes"),
            canonical_module_resolution_graph_bytes(&second).expect("second bytes")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn nested_workspace_selectors_share_migration_inventory_without_duplicate_packages() {
        use std::time::{Duration, Instant};

        let tmp = tempdir().expect("tempdir");
        let root = tmp.path();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"root","workspaces":["./packages/**/tool-*/","packages/team/plugins/*","packages/@scope/*","packages/tool-root"]}"#,
        )
        .unwrap();
        let selected = [
            ("packages/tool-root", "root-tool"),
            ("packages/team/tool-nested", "nested-tool"),
            ("packages/team/plugins/tool-plugin", "plugin-tool"),
            ("packages/@scope/工具", "unicode-tool"),
        ];
        for (directory, name) in selected {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            std::fs::write(
                root.join(directory).join("package.json"),
                serde_json::to_vec(&serde_json::json!({
                    "name": name,
                    "dependencies": {"shared": "^1"}
                }))
                .unwrap(),
            )
            .unwrap();
        }
        for directory in [
            "packages/.hidden/tool-private",
            "packages/node_modules/tool-installed",
            "packages/.git/tool-state",
        ] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            std::fs::write(root.join(directory).join("package.json"), "not-json").unwrap();
        }

        let graph = build_canonical_module_resolution_graph(root).expect("nested workspace graph");
        let expected = std::iter::once("package.json".to_owned())
            .chain(
                selected
                    .iter()
                    .map(|(path, _)| format!("{path}/package.json")),
            )
            .collect::<BTreeSet<_>>();
        let actual = graph
            .packages
            .iter()
            .map(|package| package.relative_manifest_path.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(graph.packages.len(), selected.len() + 1);
        assert_eq!(graph.dependency_edges.len(), selected.len());

        let admission = crate::migration::dependency_admission::inspect(
            root,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("same selected workspace manifests in checked migration");
        assert_eq!(admission.manifests_scanned, graph.packages.len());
        assert_eq!(
            admission
                .inputs
                .iter()
                .map(|input| input.path.clone())
                .collect::<BTreeSet<_>>(),
            expected,
        );
        assert_eq!(
            graph,
            build_canonical_module_resolution_graph(root).unwrap()
        );
    }

    #[test]
    fn metadata_reads_accept_exact_bound_and_bom_but_refuse_overflow_and_parent_paths() {
        let tmp = tempdir().expect("tempdir");
        let raw = "\u{feff}{\"dependencies\":{\"package\":\"1\"}}";
        std::fs::write(tmp.path().join("package.json"), raw).unwrap();
        assert_eq!(
            read_project_metadata(tmp.path(), Path::new("package.json"), raw.len() as u64).unwrap(),
            raw
        );
        assert!(
            read_project_metadata(tmp.path(), Path::new("package.json"), raw.len() as u64 - 1)
                .is_err()
        );
        assert!(read_project_metadata(tmp.path(), Path::new("../package.json"), 1024).is_err());
        let graph = build_canonical_module_resolution_graph(tmp.path()).unwrap();
        assert_eq!(graph.dependency_edges.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn metadata_reads_refuse_symlinks_fifos_and_replaced_project_authorities() {
        use std::os::unix::fs::symlink;
        let tmp = tempdir().expect("tempdir");
        let root = tmp.path().join("project");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("package.json"), "{}").unwrap();
        symlink(outside.join("package.json"), root.join("linked.json")).unwrap();
        symlink(&outside, root.join("linked-dir")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.join("fifo.json"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        for path in ["linked.json", "linked-dir/package.json", "fifo.json"] {
            assert!(
                read_project_metadata(&root, Path::new(path), 1024).is_err(),
                "{path}"
            );
        }
        let authority = root.canonicalize().unwrap();
        std::fs::rename(&root, tmp.path().join("original-project")).unwrap();
        symlink(&outside, &root).unwrap();
        assert!(read_project_metadata(&authority, Path::new("package.json"), 1024).is_err());
    }

    #[test]
    fn missing_manifest_fails_closed() {
        let tmp = tempdir().expect("tempdir");
        let error = build_canonical_module_resolution_graph(tmp.path())
            .expect_err("missing manifest must fail");

        assert!(matches!(
            error,
            ModuleResolutionGraphError::MissingRootManifest { .. }
        ));
    }

    #[test]
    fn unsupported_workspace_pattern_fails_closed() {
        let tmp = tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"bad-workspace","version":"1.0.0","workspaces":["../*"]}"#,
        )
        .expect("package");

        let error = build_canonical_module_resolution_graph(tmp.path())
            .expect_err("workspace escape must fail");

        assert!(matches!(
            error,
            ModuleResolutionGraphError::InvalidWorkspacePattern { .. }
        ));
    }
}
