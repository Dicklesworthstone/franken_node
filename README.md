# franken_node

<div align="center">
  <img src="docs/assets/franken_node_illustration.webp" alt="franken_node - trust-native JavaScript and TypeScript runtime platform">
</div>

<div align="center">

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Security](https://img.shields.io/badge/security-trust--native-1f6feb)
![Compatibility](https://img.shields.io/badge/compatibility-node%20%2B%20bun-5b3cc4)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Rust](https://img.shields.io/badge/rust-2024-orange)

</div>

`franken_node` is a trust-native JavaScript/TypeScript runtime platform for extension-heavy systems; it pairs Node/Bun migration speed with deterministic security controls and replayable operations.

```bash
# Build from source
cargo build --release -p frankenengine-node
```

## TL;DR

### The Problem
Node/Bun make rapid extension development easy, but production security and incident handling are mostly stitched together with external tools and policy glue.

### The Solution
`franken_node` makes trust, migration, compatibility, and incident replay first-class runtime behavior. You keep JS/TS velocity and gain deterministic control surfaces for risk-heavy extension ecosystems.

### Why Use franken_node?

| Capability | What You Get |
|---|---|
| Compatibility oracle | Continuous lockstep checks across Node, Bun, and franken_node with divergence receipts |
| Migration autopilot | Audit -> rewrite -> validate -> rollout pipeline with confidence scoring |
| Trust cards | Per-extension provenance, behavior risk, revocation state, and policy posture |
| Revocation-first execution | Risky actions gate on fresh trust state instead of best-effort checks |
| Deterministic incident replay | High-severity incidents replay from signed bundles with counterfactual simulation |
| Fleet quarantine controls | Fast containment and release workflows with convergence telemetry |
| Verifier toolkit | Independent validation for security and benchmark claims |

## Quick Example

```bash
# 1) Build from source
cargo build --release -p frankenengine-node

# 2) Initialize policy and workspace metadata
franken-node init --profile balanced

# 3) Audit a Node/Bun codebase
franken-node migrate audit ./my-app --format json --out migration-audit.json

# 4) Apply recommended rewrites with rollback artifact generation
franken-node migrate rewrite ./my-app --apply --emit-rollback ./rollback-plan.json

# 5) Validate behavior in lockstep against Node and Bun
franken-node verify lockstep ./my-app --runtimes node,bun,franken-node

# 6) Inspect extension trust state
franken-node trust card npm:@example/plugin

# 7) Run with strict policy controls
franken-node run ./my-app --policy strict

# 8) Export and replay a high-severity incident bundle
franken-node incident bundle --id INC-2026-0007 --evidence-path ./incidents/INC-2026-0007/evidence.v1.json --verify
franken-node incident replay --bundle ./INC-2026-0007.fnbundle --trusted-public-key ./keys/replay-trust-anchor.pub
franken-node incident counterfactual --bundle ./INC-2026-0007.fnbundle --trusted-public-key ./keys/replay-trust-anchor.pub --policy strict
```

## Charter

See the [Product Charter](docs/PRODUCT_CHARTER.md) for scope boundaries, governance model, and decision rules. The charter defines what franken_node is, what it is not, and how direction changes are authorized.

## Design Philosophy

1. Compatibility is a wedge, not the destination.  
   The platform chases practical migration outcomes first, then pushes beyond baseline runtimes with trust-native behavior.
2. Security controls must be operational, not decorative.  
   Policy gates, revocation checks, and quarantine paths are runtime defaults with measurable behavior.
3. Claims require evidence.  
   Benchmark, resilience, and security statements map to reproducible artifacts and verifier workflows.
4. Determinism drives incident quality.  
   Replay and forensics depend on stable event ordering, stable schemas, and explicit control contracts.
5. Performance work must preserve semantics.  
   Optimization is accepted only with conformance evidence and bounded tail-latency impact.

## Comparison

| Area | franken_node | Node.js | Bun |
|---|---|---|---|
| Extension trust cards | Built-in | External tooling | External tooling |
| Revocation-aware execution gates | Built-in | Not native | Not native |
| Deterministic incident replay bundles | Built-in | Not native | Not native |
| Compatibility divergence receipts | Built-in | N/A | N/A |
| Migration autopilot pipeline | Built-in | External scripts | External scripts |
| Fleet quarantine control plane | Built-in | External platform | External platform |
| Verifier SDK for public claims | Built-in | Not native | Not native |

## Installation

Important: this repository is not a standalone Rust workspace. `crates/franken-node/Cargo.toml`
consumes sibling engine crates from `../franken_engine` per the engine split contract, so
local source builds require both repositories checked out side-by-side.

### Option 1: One-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.sh | bash
```

Homebrew is not currently published for `franken-node`; the public
`Dicklesworthstone/homebrew-tap` repository does not yet ship a `franken-node`
formula. Use the installer above or build from source instead.

### Option 2: Build from source (split repo layout required)

```bash
git clone https://github.com/Dicklesworthstone/franken_engine.git
git clone https://github.com/Dicklesworthstone/franken_node.git
cd franken_node
cargo build --release -p frankenengine-node
./target/release/franken-node --version
```

Expected local layout:

```text
<parent>/
  franken_engine/
  franken_node/
```

## Quick Start

1. Create a default config:
```bash
franken-node init --profile balanced
```
2. Audit your existing project:
```bash
franken-node migrate audit ./my-app --out migration-audit.json
```
3. Validate compatibility before rollout:
```bash
franken-node verify lockstep ./my-app --runtimes node,bun,franken-node
```
4. Seed trust cards from your dependency graph:
```bash
franken-node trust scan ./my-app
```
5. Run in policy-governed mode:
```bash
franken-node run ./my-app --policy strict
```
6. Check trust state and incidents:
```bash
franken-node trust list --risk high
franken-node incident list --severity high
```

## Command Reference

| Command | Purpose | Example |
|---|---|---|
| `franken-node init` | Bootstrap config, policy profile, and workspace metadata | `franken-node init --profile strict --scan` |
| `franken-node run` | Run app under policy-governed runtime controls | `franken-node run ./my-app --policy balanced` |
| `franken-node migrate audit` | Inventory migration risk and emit findings | `franken-node migrate audit ./my-app --format json` |
| `franken-node migrate rewrite` | Apply migration transforms with rollback artifacts | `franken-node migrate rewrite ./my-app --apply` |
| `franken-node migrate validate` | Validate transformed project with conformance checks | `franken-node migrate validate ./my-app` |
| `franken-node verify lockstep` | Compare behavior across runtimes | `franken-node verify lockstep ./my-app --runtimes node,bun,franken-node` |
| `franken-node trust card` | Show trust profile for one extension | `franken-node trust card npm:@example/plugin` |
| `franken-node trust list` | List extensions by risk/status filters | `franken-node trust list --risk high --revoked false` |
| `franken-node trust scan` | Populate baseline trust cards from package.json dependencies | `franken-node trust scan ./my-app --deep --audit` |
| `franken-node trust sync` | Refresh trust-card cache and npm vulnerability state from OSV | `franken-node trust sync --force` |
| `franken-node trust revoke` | Revoke artifact or publisher trust | `franken-node trust revoke npm:@example/plugin@2.4.1` |
| `franken-node trust quarantine` | Quarantine a suspicious artifact fleet-wide | `franken-node trust quarantine --artifact sha256:...` |
| `franken-node fleet status` | Show policy and quarantine state across nodes | `franken-node fleet status --zone prod-us-east` |
| `franken-node fleet describe` | Describe one fleet node with zone context and incident state | `franken-node fleet describe node-17 --zone prod-us-east` |
| `franken-node fleet release` | Lift quarantine/revocation controls with receipts | `franken-node fleet release --incident INC-2026-0007` |
| `franken-node ops health-check` | Inspect process and runtime health signals | `franken-node ops health-check --json` |
| `franken-node ops rotate-key` | Validate replacement signing-key material as a non-remediating preview; it exits non-zero and does not update signer config or evidence ledger | `franken-node ops rotate-key --new-key ./keys/candidate.ed25519 --json` |
| `franken-node incident bundle` | Export deterministic incident bundle from authoritative evidence | `franken-node incident bundle --id INC-2026-0007 --evidence-path ./incidents/INC-2026-0007/evidence.v1.json --verify` |
| `franken-node incident replay` | Replay incident timeline locally | `franken-node incident replay --bundle ./INC-2026-0007.fnbundle --trusted-public-key ./keys/replay-trust-anchor.pub` |
| `franken-node incident counterfactual` | Simulate alternative policy actions | `franken-node incident counterfactual --bundle ./INC-2026-0007.fnbundle --trusted-public-key ./keys/replay-trust-anchor.pub --policy strict` |
| `franken-node registry publish` | Publish signed extension artifact | `franken-node registry publish ./dist/plugin.fnext --signing-key ./keys/publisher.ed25519` |
| `franken-node registry search` | Query extension registry with trust filters | `franken-node registry search auth --min-assurance 3` |
| `franken-node bench run` | Run benchmark suite and emit signed report | `franken-node bench run --scenario secure-extension-heavy` |
| `franken-node doctor` | Diagnose environment and policy setup (optionally with live policy activation telemetry) | `franken-node doctor --verbose --policy-activation-input ./fixtures/policy_activation/doctor_policy_activation_pass.json` |

`franken-node incident bundle` reads authoritative evidence from `--evidence-path`
or from
`<project-root>/.franken-node/state/incidents/<incident-id-slug>/evidence.v1.json`.
Deterministic fixture timelines remain test-only.

`franken-node incident replay` and `franken-node incident counterfactual` fail
closed unless you provide `--trusted-public-key <path>` or `--key-dir <dir>`;
the CLI intentionally accepts no built-in trust roots for bundle verification.

`franken-node registry publish` fails closed unless you provide `--signing-key <path>` with an Ed25519 private key file (raw 32-byte key, hex, base64, or supported JSON wrapper).

## Configuration

Example `franken_node.toml`:

```toml
# Runtime profile: strict | balanced | legacy-risky
profile = "balanced"

[compatibility]
# API compatibility mode for migration and runtime dispatch
mode = "balanced"
# Divergence receipts are always recorded in production profiles
emit_divergence_receipts = true
# TTL for signed compatibility receipts
default_receipt_ttl_secs = 3600

[migration]
# Enable automatic rewrite suggestions
autofix = true
# Require lockstep validation before rollout stage transition
require_lockstep_validation = true

[trust]
# Revocation freshness requirements by action class
risky_requires_fresh_revocation = true
dangerous_requires_fresh_revocation = true
# Quarantine defaults
quarantine_on_high_risk = true

[replay]
# Persist high-severity replay artifacts
persist_high_severity = true
# Deterministic bundle export format version
bundle_version = "v1"
# Maximum permitted replay capsule freshness window
max_replay_capsule_freshness_secs = 3600

[registry]
# Enforce signature and provenance gates
require_signatures = true
require_provenance = true
minimum_assurance_level = 3

[fleet]
# Optional override for the persisted fleet transport state root
state_dir = ".franken-node/state/fleet"
# Fleet convergence timeout for quarantine/release operations
convergence_timeout_seconds = 120

[observability]
# Stable metrics namespace for automation
namespace = "franken_node"
emit_structured_audit_events = true

[remote]
# Default TTL for remote idempotency entries
idempotency_ttl_secs = 604800

[security]
# Maximum degraded-mode duration before suspension
max_degraded_duration_secs = 3600

[security.network_policy]
# Network egress policy enforcement mode
mode = "enforced"

[engine]
# Optional path override for the franken_engine binary
# binary_path = "/usr/local/bin/franken-engine"

[runtime]
# Preferred runtime: auto | node | bun | franken-engine
preferred = "auto"
# Global max in-flight network-bound operations
remote_max_in_flight = 50
# Retry hint when bulkhead saturated
bulkhead_retry_after_ms = 50

[runtime.lanes.cancel]
max_concurrent = 12
priority_weight = 100
queue_limit = 24
enqueue_timeout_ms = 25
overflow_policy = "reject"

[runtime.lanes.realtime]
max_concurrent = 24
priority_weight = 60
queue_limit = 48
enqueue_timeout_ms = 75
overflow_policy = "enqueue-with-timeout"

[thresholds]
# Algorithmic/statistical thresholds (all optional with safe defaults)
max_failure_rate = 0.05
min_quality_score = 0.8
max_variance_pct = 5.0
regression_threshold_pct = 10.0
```

## Architecture

```text
                 +--------------------------------------+
                 |              franken_node            |
                 | compatibility + migration + trust UX |
                 +-------------------+------------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
         +---------v---------+               +---------v---------+
         |   asupersync      |               |    frankentui     |
         | control semantics |               | operator surfaces |
         +---------+---------+               +-------------------+
                   |
   +---------------+-------------------+
   |                                   |
+--v----------------+      +-----------v-----------+
|  franken_engine   |      |      fastapi_rust     |
| runtime internals |      | control-plane API     |
+--+----------------+      +-----------+-----------+
   |                                   |
   +---------------+-------------------+
                   |
            +------v-------+
            | frankensqlite|
            | audit/replay |
            +--------------+
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `lockstep validation failed` | Behavior delta across runtimes | Run `franken-node verify lockstep --emit-fixtures` and inspect generated divergence fixtures |
| `revocation frontier stale` | Local trust state is older than policy requirement or vulnerability refresh has not been re-run since the last registry change | Run `franken-node trust sync --force`; the command refreshes npm cards against OSV, preserves stale data if the network fails, and emits warnings for packages that could not be refreshed |
| `artifact rejected: missing attestation` | Registry policy requires provenance proofs | Rebuild artifact with provenance metadata and re-sign before publish |
| `quarantine not converged` | One or more nodes did not apply control action in time | Run `franken-node fleet status --verbose`, then `franken-node fleet reconcile` |
| `incident replay nondeterministic` | Missing, corrupted, or stale incident evidence / bundle components | Re-export with `franken-node incident bundle --id INC-2026-0007 --verify --evidence-path ./incidents/INC-2026-0007/evidence.v1.json` or ensure `<project-root>/.franken-node/state/incidents/<incident-id-slug>/evidence.v1.json` exists |

## Limitations

- Legacy mode can run insecure compatibility behaviors if explicitly enabled by policy.
- Strict trust profiles can block extensions that have weak provenance metadata.
- Migration rewrites target high-value patterns first; niche framework macros may need manual edits.
- Fleet-wide controls depend on healthy control-plane connectivity and correct clock discipline.
- Single-node mode stores fleet state locally; multi-node coordination requires external transport configuration.
- Counterfactual simulations depend on available telemetry completeness for the incident window.
- Runtime execution delegates to Node/Bun; franken_engine integration is still evolving.

## FAQ

### Is this a drop-in replacement for Node or Bun?
For many high-value workloads, yes. For edge compatibility cases, use lockstep validation and divergence receipts before production rollout.

### Does franken_node require a full rewrite of existing projects?
No. The migration autopilot is designed to audit and transform incrementally, then validate each rollout step.

### Can I run franken_node without centralized fleet control?
Yes. Local mode works for single-node usage. Fleet features activate when control-plane services are configured.

### What does deterministic replay include?
Replay bundles include timeline events, policy decisions, trust artifacts, and references needed to reproduce high-severity incidents.

### How does this help with supply-chain risk?
The platform combines signed artifacts, provenance checks, revocation freshness gates, trust cards, and quarantine controls as runtime defaults.

### Do I have to use strict mode?
No. Use `balanced` for most teams, `strict` for high-assurance environments, and `legacy-risky` only for constrained migration windows.

## About Contributions

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT. See `LICENSE`.
