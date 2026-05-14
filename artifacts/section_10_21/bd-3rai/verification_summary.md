# bd-3rai - Signed lineage graph builder

## Verdict

`PASS`

This replaces the stale placeholder artifact that claimed a generic
`crates/franken-node/src/bpet/` module. The real implementation now lives in
`crates/franken-node/src/security/lineage_tracker.rs`, with executable coverage
registered as the `signed_lineage_graph_builder` integration test target.

## Implementation

`SignedLineageGraphBuilder` builds a deterministic signed supply-chain lineage
artifact from:

- `SignedLineageVersion`
- `SignedLineageMaintainer`
- `SignedLineageDependency`
- `SignedLineagePipelineTransition`

The emitted graph includes typed nodes and these explicit edges:

- `maintains:<role>` from maintainer identity to release version
- `depends_on` from release version to dependency digest
- `pipeline_transition` across ordered build/release stages
- `produces_version` from final pipeline transition back to the release version

Before signing, the builder validates that signer identity, version data,
maintainer data, dependency data, and pipeline data are all present. Canonical
payload bytes are SHA-256 digested, then signed with HMAC-SHA256 using the
configured signer material.

## Static Evidence

- Builder and typed artifact model: `lineage_tracker.rs:530-823`
- Fail-closed validation: `lineage_tracker.rs:796-895`
- Inline tests: `lineage_tracker.rs:2394-2486`
- Cargo test target registration: `crates/franken-node/Cargo.toml:184-186`
- Executable integration tests: `tests/security/signed_lineage_graph_builder.rs`
- Test names:
  - `signed_lineage_graph_builder_links_all_supply_chain_domains`
  - `signed_lineage_graph_builder_is_deterministic_for_unordered_inputs`
  - `signed_lineage_graph_builder_rejects_missing_dependency_links`
  - `signed_lineage_graph_signature_changes_when_dependency_digest_changes`

## RCH Proof

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/franken_node-snowybeaver-bd3rai-integration-target cargo test -p frankenengine-node --test signed_lineage_graph_builder --no-default-features -- --nocapture
```

Result: RCH job `29840908367167944` on worker `vmi1167313` completed with
exit code 0 at `2026-05-14T10:36:09.474627Z`.

```text
running 4 tests
test signed_lineage_graph_builder_is_deterministic_for_unordered_inputs ... ok
test signed_lineage_graph_builder_rejects_missing_dependency_links ... ok
test signed_lineage_graph_signature_changes_when_dependency_digest_changes ... ok
test signed_lineage_graph_builder_links_all_supply_chain_domains ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```
