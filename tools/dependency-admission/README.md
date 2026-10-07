# Native dependency admission

The Linux `franken-node migrate rewrite --apply --verify` path inspects npm
metadata from its private captured project before planning a new rewrite or
starting a validation runtime. This is the native Rust product path, not the
Python scanner. Both pair and three-runtime checked apply use the same gate.

The inspector reads `package.json` and either `package-lock.json` or
`npm-shrinkwrap.json`. npm lockfile versions 1, 2 and 3 are supported. Recorded
installation locations and versions stay separate, including nested packages,
aliases, development packages and optional dependencies. Both lock filenames
present, invalid JSON, duplicate JSON members, unsupported schemas, unsafe
metadata paths and resource-limit exhaustion fail with `ERROR`, never a clean
inventory. Symlinked/nonregular metadata is not followed.

## Workspace admission

A root `workspaces` array selects captured manifests with literal path
components, component `*` wildcards and standalone `**`. One leading `./` and
one trailing slash are accepted. Wildcards do not implicitly enter dot
folders. Overlapping selectors read each manifest once. Unsupported pattern
dialects, selectors matching no manifests, duplicate workspace/root names,
nested workspace configurations and selected symlinks fail explicitly.
Installed packages and reserved runtime/backup/state directories are excluded.
Traversal is bounded by 64 selectors, depth 64, 4,096 directories, 50,000
entries and 1,024 manifests including the root. Metadata and declaration budgets
are shared across the entire inspection, not reset for each workspace.

Every selected workspace must have a canonical root `node_modules/<name>` link
in a modern npm lockfile. The recorded target, name, version, dependency maps
and peer metadata must match its actual captured manifest before the link's
review finding can be cleared. Workspace-private and hoisted dependency
locations are checked nearest-first; a wrong nearer identity cannot be rescued
by a matching root identity. Alias, URL, Git and file requests do not authorize
substitution with a same-named workspace. Other local links remain review items.
Legacy lockfiles can be inventoried but cannot establish workspace link binding.

Known native-addon/build dependencies, recorded or captured install/prepare
lifecycle scripts, `binding.gyp`/`gypfile` markers, incomplete identities,
unresolved declarations and inconsistent workspace metadata produce
`REJECTED`. Independent workspace lockfiles also require separate project
assessment; they are fingerprinted but never mixed with the root's authority.
A clean lockfile projection cannot hide a newly added workspace dependency or
lifecycle script. These findings precede new candidate execution, so a passing
test suite cannot outweigh them.

Checked JSON retains schema `franken-node/checked-rewrite/v1` and optional
`dependency_admission`, with exact metadata SHA-256 fingerprints, package and
manifest counts, scope, and structured findings. Human output reports each
finding's code, source, package and location. The inspector returns metadata
observations, not installed-content authentication, semver satisfaction, or
runtime compatibility proof. No package manager, registry or lifecycle script
is invoked by the inspector. Existing runtime comparison and source-drift
checks remain necessary after a clean metadata assessment.

Opening the existing rewrite transaction can recover an earlier interrupted
installation before these checks. Rejection prevents NEW execution/installation;
it does not suppress required recovery or claim that no local state was touched.

## Focused execution

```sh
cargo test --manifest-path tools/dependency-admission/Cargo.toml
```

This standalone manifest compiles the actual product inspector and workspace
selector source and their unit tests without unrelated sibling workspaces. It
does not compile the whole product binary. Integration regressions live in
`verified_rewrite.rs`; the existing `verified-rewrite.yml` lane compiles that
actual source and exercises the shared checked-apply orchestration. A configured
workflow is not evidence of a successful run: inspect the job result before
claiming these tests passed.
