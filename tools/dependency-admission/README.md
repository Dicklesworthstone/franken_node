# Native dependency admission

The Linux `franken-node migrate rewrite --apply --verify` path inspects dependency
metadata from its private captured project before planning a new rewrite or
starting a validation runtime. This is the native Rust product path, not the
Python scanner. Both pair and three-runtime checked apply use the same gate.

The inspector reads `package.json` and either `package-lock.json`,
`npm-shrinkwrap.json`, or the supported `bun.lock` subset below. npm lockfile
versions 1, 2 and 3 are supported. Recorded installation locations and versions
stay separate, including nested packages, aliases, development packages and
optional dependencies. Conflicting lock authorities, invalid JSON, duplicate
JSON members, unsupported schemas, unsafe metadata paths and resource-limit
exhaustion fail with `ERROR`, never a clean inventory. Symlinked/nonregular
metadata is not followed. A root or selected workspace `bun.lockb` is explicitly
refused, including empty, linked and nonregular inputs; it is never silently
ignored as though the project had no dependency authority.

## Bun text-lock admission

Bun text-lock versions 1 and 2 can supply the logical graph for registry packages
and independently captured workspaces. Hoisted installations and the bounded
project-local isolated layout below use the same admitted graph. JSONC comments
and trailing commas are accepted only in named `bun.lock` inputs; `package.json`
and npm locks remain strict JSON. Duplicate keys (including escaped spellings),
array holes, malformed comments, unknown versions and unsupported metadata are
refused. The original `bun.lock` bytes, not a stripped or reconstructed document,
are fingerprinted in `inputs`.

The decoder preserves scoped names, aliases, nested installation positions,
production/optional/peer declarations and optional-peer metadata. Its internal
projection feeds the existing native range checker, nearest-installation
resolver and transitive graph gate. It never writes a generated npm lockfile or
invokes Bun/npm. A clean metadata result still cannot authorize execution:
checked migration inspects the actual staged installation, verifies exact
manifest identities and required routes, and checks lifecycle/native markers.
Missing packages, stale installed manifests and arbitrary package links remain
review barriers. Guest sources are not evaluated by the inspector.

A canonical `name@workspace:relative/path` tuple can describe the root link for
that named workspace. Its source descriptor must contain a concrete version;
missing versions are not invented. The common workspace gate then independently
selects and reads the real manifest and binds the name, version and dependency
maps. Lockfile-only workspaces cannot clear link review. Private dependency keys
below a workspace are projected to its physical source directory, not to the
lexical root symlink. Scoped/nested packages retain distinct locations and
versions. Projection uses indexed workspace lookup, bounded paths and an
aggregate retained-byte limit; it does not scan every workspace for each edge.

Bun project manifests may use `workspace:*`, `workspace:^`, `workspace:~`, or an
explicit supported range such as `workspace:^1.2`. These requests require the
nearest recorded installation to be a manifest-bound workspace link, never a
registry namesake or an unselected local link. Shorthands select the captured
local version, including a prerelease; explicit ranges must satisfy that
version. Empty suffixes, path/alias protocols and unverifiable forms require
review. Original declarations remain unchanged and fingerprinted. This Bun-only
admission rule does not enable `workspace:` under an npm lockfile, and does not
relax the installed physical-link, lifecycle, native-payload or route checks.

This is not a full Bun installer/solver or proof of Bun runtime parity. Binary
`bun.lockb`, version 0 text locks, arbitrary file/Git/link/direct-tarball tuple
forms, root/lockfile catalogs, overrides, patches and nonempty trusted-dependency
declarations in those inputs remain outside the supported contract.
`configVersion` does not prove a physical layout: only an inspected matching
installation can pass execution admission. An unsupported text lock fails
explicitly rather than becoming an empty successful graph. When Bun and npm
locks coexist, select one authority before checked execution. Resolution URLs
and integrity strings are retained metadata, not verified archive SRI or
publisher authentication. Installed-content authentication and runtime
comparison remain separate claims.

## Project-local isolated installation

For a selected supported `bun.lock`, an ordinary `node_modules/.bun` directory
activates physical-layout binding. Registry installation links must select
ordinary packages inside this project-local store. Store labels are not trusted
as package names or versions: actual captured manifests must match the exact
logical lock pins. Registry aliases, scoped packages, store fallback links,
nested versions and cycles retain their physical module-resolution contexts.
Selected workspaces continue to resolve from their real source directories.
A missing optional installation may remain absent; a present wrong installation
cannot acquire an optionality exemption.

The mapper resolves each declared edge from its physical consumer and binds the
result to the nearest selected logical pin. Two logical dependency contexts may
share one physical package only when their captured records agree; conflicting
pins cannot collapse into one store entry. Store fallback/public aliases can
expose an already-bound identity but cannot introduce an unbound package.
Unreferenced store payloads and unknown aliases require review rather than being
silently ignored. A physically nearer invalid slot cannot fall through to a
more convenient outer copy. Private peer placement is still checked.

The full installed-tree inspector then runs unchanged manifest, exact-version,
dependency-declaration, lifecycle and native-payload checks on ordinary package
contents. It never reads a package manifest through an installation symlink.
Verified registry aliases reuse the inspected physical identity, not cloned
source manifests. Graph admission checks outgoing declarations once per physical
consumer while retaining all alias positions for incoming dependency lookups.
Canonical identity consistency is checked before deduplication; equal names and
versions in different physical peer contexts are not merged. The existing edge
limit is unchanged and no timing speedup is claimed.

All link text is bounded and interpreted without following filesystem symlinks;
directory identities and original link text are rechecked before success. Link
positions in `inputs` fingerprint the exact UTF-8 link text, not the target file
or an archive. File positions continue to fingerprint original file bytes.
The isolated `scope` explicitly identifies this distinction. Registry alias and
scheduled-context fan-out have aggregate identity/path budgets, and the existing
metadata, directory, entry, depth and findings limits remain fail-closed.

Global-store symlinks, chained links, absolute/escaping links, linked installation
containers and unverified payload links are not supported. An npm project does
not gain Bun layout authority by creating a `.bun` directory. This is installed
layout admission for the supported lock subset, not sandboxing, verification of
archive integrity, proof that an installer generated the tree, or certification
that the runtime executes its packages correctly.

## Workspace admission

For npm and supported Bun projects, a root `workspaces` array selects captured
manifests with literal path components, component `*` wildcards and standalone
`**`. One leading `./` and one trailing slash are accepted. Wildcards do not
implicitly enter dot folders. Overlapping selectors read each manifest once.
Unsupported pattern dialects, selectors matching no manifests, duplicate
workspace/root names, nested workspace configurations and selected symlinks
fail explicitly. Installed packages and reserved runtime/backup/state
directories are excluded. Traversal is bounded by 64 selectors, depth 64,
4,096 directories, 50,000 entries and 1,024 manifests including the root.
Metadata and declaration budgets are shared across the entire inspection.

Every selected workspace must have a canonical root `node_modules/<name>` link
in a modern npm lockfile or supported Bun projection. The recorded target,
name, version, dependency maps and peer metadata must match its actual captured
manifest before the link's review finding can be cleared. Workspace-private and
hoisted dependency locations are checked nearest-first. A wrong nearer identity
cannot be rescued by a matching root identity; a missing private installation
cannot silently fall through to a compatible but differently located hoisted
copy. Alias, URL, Git and file requests do not authorize substitution with a
same-named workspace. Other local links remain review items. Legacy npm locks
can be inventoried but cannot establish workspace link binding.

Known native-addon/build dependencies, recorded or captured install/prepare
lifecycle scripts, `binding.gyp`/`gypfile` markers, incomplete identities,
unresolved declarations and inconsistent workspace metadata produce `REJECTED`.
Independent npm or Bun text locks in selected workspaces are fingerprinted but
never mixed with the root's authority; they require separate project assessment.
A clean lockfile projection cannot hide a newly added workspace dependency or
lifecycle script. These findings precede new candidate execution, so a passing
test suite cannot outweigh them.

Checked JSON retains schema `franken-node/checked-rewrite/v1` and optional
`dependency_admission`, with exact metadata SHA-256 fingerprints, package and
manifest counts, scope, and structured findings. Human output reports each
finding's code, source, package and location. Supported registry ranges must
satisfy the recorded version; opaque forms require review. No package manager,
registry or lifecycle script is invoked by the inspector. Existing runtime
comparison and source-drift checks remain necessary after clean admission.

Opening the existing rewrite transaction can recover an earlier interrupted
installation before these checks. Rejection prevents NEW execution/installation;
it does not suppress required recovery or claim that no local state was touched.

## Focused execution

```sh
cargo test --manifest-path tools/dependency-admission/Cargo.toml
```

This standalone manifest compiles the actual product inspector, Bun decoder,
workspace selector, isolated-layout mapper and installed-tree checks and their
unit tests without unrelated sibling workspaces. It does not compile the whole
product binary. Integration regressions live in `verified_rewrite.rs`; the
existing `verified-rewrite.yml` lane compiles that actual source and exercises
the shared checked-apply orchestration. A configured workflow is not evidence
of a successful run: inspect the job result before claiming these tests passed.
