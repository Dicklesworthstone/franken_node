# Pinned sibling source builds

Cargo loads sibling path dependencies, including development dependencies during
workspace resolution. An engine-only checkout is not a complete build input.
The shared `scripts/bootstrap_source.sh` stages `franken_engine`, `frankentui`,
`fastapi_rust`, and `sqlmodel_rust` beside a clean, committed `franken_node`
checkout. It needs Git, Bash, and SHA-256 support, not Python, sudo, `/dp` links,
or Cargo source patches.

```bash
bash scripts/bootstrap_source.sh --workspace "$PWD" \
  --engine-ref "$REVIEWED_ENGINE_COMMIT" \
  --receipt /private/build-inputs.tsv
cargo build --release --locked -p frankenengine-node --bin franken-node
bash scripts/bootstrap_source.sh --workspace "$PWD" \
  --engine-ref "$REVIEWED_ENGINE_COMMIT" --verify-only \
  --receipt /private/build-inputs-after.tsv
cmp /private/build-inputs.tsv /private/build-inputs-after.tsv
```

The receipt parent must already exist outside all input repositories, and the
receipt must be new. The caller selects the engine revision. Supporting revisions
come from that node checkout's `packaging/source-siblings.tsv`; they never fall
back to a current branch. For a new engine checkout a branch or tag may be selected
explicitly; the receipt records its resolved commit. Use that commit for subsequent
offline verification. Reproduction also requires the original node commit.

Existing sibling checkouts are reused only when clean, standalone, and already at
the exact selected commit. Dirty repositories, linked roots or manifest parents,
missing manifests, malformed/incomplete locks, and conflicting receipts are refused.
Nothing resets or removes existing source. An interrupted new fetch can leave an
incomplete checkout that must be inspected rather than silently replaced on retry.
`--verify-only` never fetches or moves a branch.

## Installation

`install.sh --method source --node-ref COMMIT --engine-ref COMMIT` uses the selected
node checkout's bootstrap and supporting-source lock, stamps the actual node/engine
commits into the build environment, and builds with `--locked`. It verifies the
same inputs after compilation before entering the existing staged binary health
check and atomic installation. Cargo errors and source changes preserve the old
installed binary. Historical node revisions without the bootstrap contract are
rejected instead of receiving invented floating dependencies.

The source receipt is printed unless `--quiet` is selected; the installer does not
persist it beyond its temporary workspace. Save the installer output when source
provenance is needed. Release and offline-binary installation retain their existing
archive/checksum/signature boundaries.

## Release integration and limits

The release certification job and all four platform builds use the same bootstrap,
engine pin, supporting-source lock, and committed Cargo lockfile. Each verifies its
source receipt after building, before generated campaign outputs modify the source
workspace. Per-platform receipts must byte-match the certification receipt before
signing. The receipt files have checksum sidecars and are included in the existing
Sigstore signing loop. Missing binaries, checksums, receipts, or mismatched source
sets stop publication. Existing compatibility and close-condition gates remain
mandatory; this does not waive their thresholds or alter the release engine pin.

The pinned supporting revisions are source selections, not a claim that the current
source set has passed compilation or release qualification. A stale Cargo lockfile,
API mismatch, or other build failure must be resolved and tested explicitly; do not
remove `--locked` or introduce development-source patches to manufacture success.

Receipts name Git revisions and the supporting-lock digest. They do not capture
ignored/untracked-ignored build inputs, global Git/Cargo configuration, toolchain
and linker images, downloaded registry contents, or host state. Clean-tree checks
are not filesystem locks against a concurrent hostile process. They establish the
observed source selection, not bit-for-bit cross-platform reproducibility or a
standalone release certificate.

## Tests

```bash
python3 -m unittest discover -s tests -p test_source_bootstrap.py -v
python3 -m unittest discover -s tests -p test_release_source_binding.py -v
```

Checkout tests use actual Git repositories and redirect their network URLs to local
remotes. Installer tests substitute only the compiler boundary and explicitly do
not prove Rust compilation. Release-binding tests execute the actual pre-signing
workflow block with real checksum files; they do not sign or publish a release.
