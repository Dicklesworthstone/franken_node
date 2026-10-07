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

Known native-addon/build dependencies, recorded install lifecycle scripts,
incomplete package identities and declarations without matching recorded
identities produce `REJECTED`. Workspace declarations and local links currently
require explicit review; this native path does not yet reproduce the Python
scanner's workspace expansion. These findings cannot be outweighed by a passing
test suite because the new candidate has not been executed yet.

Checked JSON retains schema `franken-node/checked-rewrite/v1` and adds optional
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

This standalone manifest compiles the actual product inspector source and its
unit tests without the unrelated sibling workspaces. It does not compile the
whole product binary. Integration regressions live in `verified_rewrite.rs`;
the existing `verified-rewrite.yml` lane compiles that actual source and exercises
the shared checked-apply orchestration. A configured workflow is not evidence of
a successful run: inspect the job result before claiming these tests passed.
