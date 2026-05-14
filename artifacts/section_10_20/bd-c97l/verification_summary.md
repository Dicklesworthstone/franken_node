# bd-c97l.1 — DGIS topological context risk surface artifacts

## Verdict: PASS

bd-c97l previously had generic evidence for topological context integration.
bd-c97l.1 replaces that thin artifact set with concrete trust-card style risk
surface code, a focused integration target, and a machine-readable risk UI
snapshot.

## Implementation

- `crates/franken-node/src/security/dgis/risk_surface_integration.rs` builds
  versioned DGIS risk surfaces for trust-card context, adversary posterior
  updates, and extension risk UI overlays.
- `tests/integration/dgis_trust_card_integration.rs` verifies blast radius,
  add/update/remove dependency deltas, posterior attribution, deterministic
  replay, and fail-closed non-finite metric handling.
- `artifacts/10.20/dgis_risk_ui_snapshot.json` records the measured critical
  risk sample used by the integration test.
- `crates/franken-node/Cargo.toml` registers the focused
  `dgis_trust_card_integration` target.

## Verification

- `rustfmt --edition 2024 --check --config skip_children=true crates/franken-node/src/security/dgis/risk_surface_integration.rs tests/integration/dgis_trust_card_integration.rs`
- `python3 -m json.tool artifacts/10.20/dgis_risk_ui_snapshot.json`
- `RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,CARGO_INCREMENTAL,CARGO_BUILD_JOBS CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/franken_node-snowybeaver-bdc97l-target rch exec -- cargo test -p frankenengine-node --test dgis_trust_card_integration --no-default-features -- --nocapture` — PASS on `vmi1152480` (4 passed, 0 failed)
