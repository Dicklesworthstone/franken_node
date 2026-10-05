# Captured output expectations for migration validation

Runtime agreement is not an independent correctness oracle: two successful
processes can emit the same wrong output, or both forget to create a required
artifact. Projects can now supply golden stdout, stderr and generated-file
fixtures in `.franken-node/migration-tests.json`.

```json
{
  "schema_version": "franken-node/migration-tests/v1",
  "tests": ["scripts/check.cjs"],
  "expectations": {
    "scripts/check.cjs": {
      "stdout": "fixtures/check.stdout",
      "stderr": "fixtures/empty.bin",
      "files": {
        "out/result.json": "fixtures/result.json"
      }
    }
  }
}
```

For example, `scripts/check.cjs` could contain:

```javascript
const fs = require('node:fs');
fs.mkdirSync('out', { recursive: true });
fs.writeFileSync('out/result.json', '{"answer":42}\n');
process.stdout.write('migration-ready\n');
```

Create `fixtures/check.stdout` containing `migration-ready` followed by a single
LF, `fixtures/result.json` containing `{"answer":42}` followed by a single LF,
and a zero-byte `fixtures/empty.bin`. Run the normal execution-backed migration
validator, or the standalone operator:

```sh
cargo +stable run --manifest-path tools/migration-validator/Cargo.toml -- \
  ./project --native-bin /absolute/path/to/franken-node --execute
```

Use trusted projects only. Execution still has the ambient/external authority
described by the migration validator; these assertions do not create an OS
sandbox. The standalone operator also needs its normal reference Node runtime.

## Contract

All paths are canonical project-root-relative paths, including generated-file
targets when a test has a custom `execution.cwd`. Expected files must be regular
captured inputs, not symlinks or dependencies, backups or reserved metadata.
Generated targets may be absent from the input capture and created by the test.
They must exist as regular files after execution; symlink leaves and symlinked
parent components are refused. Directory descriptors are pinned before guest
execution and generated outputs are opened component-by-component relative to
that pinned root, without following symlinks. FIFO outputs are opened
nonblocking and rejected before reading.

Every expected fixture is limited to 1 MiB. At most 64 generated-file assertions
are accepted per test; the existing 64 KiB manifest and total capture limits
also apply. Output-file reads use the existing per-leg deadline and compare
bounded chunks against captured bytes. File-version changes during comparison
fail closed. This is a post-execution assertion, not an atomic filesystem
snapshot or a check of every transient/external effect.

Comparisons are byte-exact. No UTF-8 decoding, newline conversion, whitespace
trimming, JSON normalization, wildcard expansion or shell evaluation occurs.
An empty fixture asserts an empty output; omission means that stream is not
independently asserted. An explicit expectations object must assert at least
one stream or generated file. Null values, unknown fields and duplicate keys
are rejected rather than silently disabling an assertion.

The original and candidate must have the same assertion declarations **and the
same captured expected bytes**. Checked rewrites, paired validation, product
validation and capsule replay use the shared test-inventory/execution path.
Neither a candidate editing its golden fixture nor a guest overwriting a staged
fixture can redefine the oracle. Captured bytes, not the mutable source tree or
the guest's staged copy, provide the expected values.

An assertion failure is reported through the existing execution-error path:
`ERROR` in the paired suite, never `PASS`. Diagnostics identify the stream or
file target without embedding expected or actual content. A matching assertion
does not change a nonzero exit into success, suppress a runtime divergence or
certify a release. Existing manifests without expectations retain their prior
comparison-only behavior. File assertions do not require
`--compare-filesystem`; that separate option still checks broader persistent
workspace deltas.

## Focused regression tests

The existing native migration workflow compiles the real modules through the
standalone operator. These filters select the added assertions:

```sh
cargo +stable test --manifest-path tools/migration-validator/Cargo.toml \
  expectation_tests -- --nocapture --test-threads=2
```

The Node/Node tests deliberately exercise Rust orchestration rather than claim
independent runtime implementations or native Franken compatibility.
