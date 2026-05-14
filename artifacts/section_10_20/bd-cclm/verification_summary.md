# bd-cclm.1 — DGIS adversarial validation suite concrete artifacts

## Verdict: PASS

bd-cclm previously had generic evidence that did not name concrete
adversarial fixtures. bd-cclm.1 replaces that thin artifact set with explicit
test, playbook, and result files.

## Implementation

- `tests/security/dgis_adversarial_suite.rs` covers graph poisoning, edge
  obfuscation, fake-low-risk pivots, delayed activation, and deterministic
  replay.
- `docs/security/dgis_attack_playbook.md` documents the stable failure classes
  and operator remediation hints.
- `artifacts/10.20/dgis_adversarial_results.json` records the measured
  infected-node bounds and termination outcomes for each campaign.
- `crates/franken-node/Cargo.toml` registers the focused
  `dgis_adversarial_suite` test target.

## Verification

- `rustfmt --edition 2024 --check --config skip_children=true tests/security/dgis_adversarial_suite.rs`
- `python3 -m json.tool artifacts/10.20/dgis_adversarial_results.json`
- `rch exec -- cargo test -p frankenengine-node --test dgis_adversarial_suite --no-default-features -- --nocapture` on `vmi1152480`: 5 passed, 0 failed.
