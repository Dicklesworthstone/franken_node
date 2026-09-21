# Native package graph inspection

`franken-module-graph` runs the product's actual Rust module-graph builder without
linking the optional sibling execution engine. It reads root/workspace manifests
and npm `package-lock.json`, emits deterministic graph evidence, and supports
importer-specific dependency queries and independently pinned hash checks. It
never installs dependencies or executes project JavaScript or lifecycle scripts.

```sh
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project \
  --importer packages/app/package.json --dependency '@scope/tool' --require-resolved
cargo run --manifest-path tools/module-graph/Cargo.toml -- /path/to/project \
  --expected-hash 'sha256:<64-lowercase-hex-digits>'
```

Exit 0 means inspection succeeded and any requested checks passed; 1 means a
hash mismatch or a required-but-unresolved edge; 2 means invalid input or an I/O
error. Errors and reports are JSON. `--dependency` selects that manifest's
explicitly declared edges across dependency kinds. Without a dependency query,
the complete graph is exported. `--importer` defaults to `package.json` and must
exactly match a captured project-relative manifest path.

## Resolution contract

Each importer walks recorded `node_modules` locations from its own directory to
the project root. A root dependency cannot accidentally select a sibling's nested
version. Scoped names and installation aliases retain their installation path;
modern lockfiles can separately identify the alias target's real package name.
No location above the project, global package directory, or `NODE_PATH` is used.

Modern npm v2/v3 `packages` maps are authoritative; redundant legacy records are
not merged into them. npm v1's nested `dependencies` hierarchy is converted to
explicit installation paths, with `requires` retained separately from nested
installation records. Unknown lockfile versions and malformed locations, records,
requirements, or link metadata fail rather than silently producing an empty
successful graph. These are npm lockfile formats, not pnpm/yarn/Bun lock parsers.

An ordinary dependency range does not imply a same-named local workspace. A
recorded workspace link binds through its exact captured target directory.
Explicit `workspace:` requests can record workspace intent even without an
installed link; a null `lockfile_package_path` makes that distinction visible.
Duplicate workspace names and links to uncaptured workspaces fail closed.

## What the evidence does not establish

This is **lockfile-metadata inspection**, not a semver solver, installer, trust
verifier, or proof that live `node_modules` matches the lock. The selected version
is the nearest *recorded* installation, not an inferred preferred version. A
workspace intent is not proof of an installed link. `--require-resolved` checks
for pins or explicit workspace intent, not execution readiness. Conditional
exports evaluation, actual module-file loading and native runtime parity remain
outside this command. A graph hash is content identity, not authentication;
`--expected-hash` must come from an independently trusted source. No receipt or
security approval is fabricated, and `franken-node run` is unchanged.

## Executed tests

```sh
cargo test --manifest-path tools/module-graph/Cargo.toml \
  --bin franken-module-graph --test cli
```

The graph builder's own unit tests run alongside executable CLI regressions.
Node must be available for the resolver oracle: it compares real
`createRequire(...).resolve(...)` choices against the Rust graph for nested,
hoisted, scoped and alias installations. Fixture modules throw if evaluated, so
resolver comparison does not silently substitute successful program execution.
The schema registry is compiled from production source as a non-test dependency;
its full-workspace tests are not claimed by this focused command.
