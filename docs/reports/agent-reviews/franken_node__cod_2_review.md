# franken_node__cod_2 Review

Scope:
- Command run: `git log 9707c9e1..HEAD --oneline --no-merges -- crates/franken-node/src/migration crates/franken-node/src/repair crates/franken-node/tests/migrate_*`
- Explicit commits reviewed: `b030fb8e`, `ee9c2958`, `8971091b`, `93a1690d`, `7fd20577`
- Note: `7fd20577` is outside the path-filtered migration/repair log, but was reviewed because it was explicitly assigned.

Summary:
- Critical: 0
- High: 1
- Medium: 0
- Low: 0
- High-severity bead created: `bd-q3hen`

## High

### `7fd20577` adds a non-self-contained production dependency
- Location: `crates/franken-node/Cargo.toml:37`
- Bead: `bd-q3hen`
- Issue: `frankentui` is added as a non-optional production dependency using absolute path `/dp/frankentui/crates/ftui`, and the commit does not include the resulting `Cargo.lock` update.
- Impact: clean checkouts are no longer self-contained. Builds fail on machines without that exact `/dp` path, and locked/release-style builds fail from the committed lock state.
- Reproduction:
  - From a clean checkout at/after `7fd20577` without `/dp/frankentui`, run `rch exec -- cargo check -p frankenengine-node`.
  - From the committed lock state, run `rch exec -- cargo check -p frankenengine-node --locked`; Cargo must update `Cargo.lock` for the new dependency graph.
- Expected fix: use a workspace/relative dependency or feature-gate the TUI bridge, and commit the matching `Cargo.lock` update.

## No Defects Found

- `b030fb8e` migrate audit golden: no real defect found.
- `ee9c2958` migrate validate snapshot: no real defect found.
- `8971091b` migrate validate `--format`: no real defect found.
- `93a1690d` migration throughput bench: no real defect found.

## Verification Note

- Attempted targeted verification with `rch exec -- cargo test -p frankenengine-node --test migrate_validate_goldens -- --nocapture`.
- Verification is currently blocked by unrelated dirty-worktree compile error at `crates/franken-node/src/control_plane/fleet_transport.rs:10`: `expected identifier, found #`.
