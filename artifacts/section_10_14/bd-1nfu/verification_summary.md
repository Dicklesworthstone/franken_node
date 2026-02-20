# bd-1nfu Verification Summary

## Require RemoteCap for network-bound trust/control operations

- **Section:** 10.14
- **Status:** PARTIAL_WITH_EXTERNAL_BLOCKERS
- **Agent:** CyanFinch (codex-cli, gpt-5-codex)
- **Date:** 2026-02-20

## Delivered

- `crates/franken-node/src/security/remote_cap.rs`
- `crates/franken-node/src/security/mod.rs` (module export)
- `crates/franken-node/src/security/network_guard.rs` (centralized gate enforcement in egress path)
- `tests/security/remote_cap_enforcement.rs`
- `tests/conformance/network_guard_policy.rs` (updated for enforced RemoteCap path)
- `docs/specs/remote_cap_contract.md`
- `artifacts/10.14/remote_cap_denials.json`
- `artifacts/section_10_14/bd-1nfu/verification_evidence.json`

## Implemented Behaviors

- Provider-only token issuance with explicit operator authorization requirement.
- Signed RemoteCap payload (scope + issuer + expiry + single-use semantics).
- Centralized gate checks for missing/expired/invalid/out-of-scope/replayed/revoked tokens.
- Structured audit events for issue/consume/deny/revoke/local-only mode.
- Network guard integration requiring RemoteCap gate check before policy evaluation.
- Local-only operation path remains functional without remote capabilities.

## Targeted Validation (via `rch exec`)

1. `cargo test --manifest-path franken_node/Cargo.toml remote_cap -- --nocapture`
: **PASS** (9 tests passed; 0 failed).

## Blockers Observed

1. `cargo check --manifest-path franken_node/Cargo.toml --all-targets`
: **BLOCKED outside bead scope** — compile failure in `crates/franken-node/src/observability/evidence_ledger.rs` (missing fields in `EvidenceEntry` initializer, E0063).
2. `cargo clippy --manifest-path franken_node/Cargo.toml --all-targets -- -D warnings`
: **BLOCKED outside bead scope** — large pre-existing lint debt across unrelated modules.
3. `cargo fmt --manifest-path franken_node/Cargo.toml --check`
: **BLOCKED outside bead scope** — unrelated formatting drift in existing observability/policy modules.
4. `rch` sync stability
: recurring rsync permission failure on `/data/projects/remote_compilation_helper/perf.data`, causing local fallback.
5. CLI dispatch wiring for `franken-node remotecap issue ...`
: deferred this pass to avoid active `main.rs` reservation overlap with JadeFalcon.

## Notes

This pass implements the core RemoteCap primitive + enforcement checkpoint and keeps all changes scoped away from actively contested files. The remaining delta to full acceptance is command-surface wiring in `main.rs` once reservation overlap is clear.
