# bd-25nl Verification Summary

## Outcome
Implemented the fail-closed root bootstrap gate and supporting spec/tests.

## Delivered
- `crates/franken-node/src/control_plane/root_pointer.rs`
  - Added detached root auth record support (`root_pointer.auth.json`) at publish time.
  - Added `RootAuthConfig`, `VerifiedRoot`, and `BootstrapError` contract.
  - Added `bootstrap_root(...)` verification gate with fail-closed checks for:
    - root presence
    - root parse validity
    - auth record parse validity
    - format version match
    - epoch validity window
    - root hash integrity
    - epoch consistency
    - MAC verification
- `tests/security/root_bootstrap_fail_closed.rs`
  - Added normative security tests for all required reject paths + success path.
- `docs/specs/root_bootstrap_auth.md`
  - Added bootstrap auth/version/epoch verification contract and error semantics.
- `artifacts/10.14/root_bootstrap_validation_report.json`
  - Machine-readable implementation/validation report.

## Validation Commands
- `rch doctor` -> pass.
- `rch exec -- cargo test -p frankenengine-node root_pointer` -> blocked by remote path dependency resolution (`franken_engine` missing in worker workspace layout).
- `rch exec -- cargo test --manifest-path franken_node/Cargo.toml -p frankenengine-node root_pointer` -> blocked by pre-existing unrelated compile error in `crates/franken-node/src/tools/repro_bundle_export.rs:590`.
- `rustfmt --edition 2024 ...` on touched files -> pass.

## Current Gate Status
Implementation complete for `bd-25nl`; full cargo gate remains blocked by unrelated/global workspace issues outside the bead scope.
