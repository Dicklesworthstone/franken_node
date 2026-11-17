# FrankenNode - Architecture Overview

*For engineers new to the franken_node codebase*

## Executive Summary

**FrankenNode** is the product layer over sibling `franken_engine`: migration, trust, fleet quarantine/control-plane coordination, replay, and verifier surfaces around a native JS/TS runtime. It is **not** a drop-in Node.js/Bun replacement (committed L1 corpus artifact is currently `69.82%` (`391/560`) in `artifacts/compat/corpus_pass.json`, with `78.93%` (`442/560`) under `balanced` in `CLAIM-001`; `child_process` and strict ambient capabilities remain gated). The system implements a 3-kernel architecture for separation of concerns between execution, correctness control, and product surfaces.

**Key Stats:**
- **Language:** Rust 2024 Edition (`nightly-2026-09-21` pinned in `rust-toolchain.toml`, required by `fsqlite-pager` `core_intrinsics`)
- **Architecture:** 3-kernel design (franken_engine + asupersync + franken_node)
- **Test Coverage:** 500+ integration tests, 70+ conformance harnesses, fuzz testing
- **Package:** `frankenengine-node` (binary: `franken-node`)

## 3-Kernel Architecture

FrankenNode is built on a tri-kernel design that separates concerns across three cooperating repositories:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  franken_engine │    │   asupersync    │    │  franken_node   │
│  (Execution)    │    │ (Correctness)   │    │   (Product)     │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Runtime core  │    │ • Cancellation  │    │ • User surfaces │
│ • JS execution  │    │ • Replay/audit  │    │ • Policy engine │
│ • Extension     │    │ • Deterministic │    │ • Migration aid │
│   sandbox       │    │   execution     │    │ • Trust/supply  │
│ • Native JS/TS  │    │ • Evidence      │    │   chain control │
│   (no V8/QJS)   │    │   ledger        │    │ • File fleet log│
└─────────────────┘    └─────────────────┘    └─────────────────┘
       │                         │                         │
       └─────────────────────────┼─────────────────────────┘
                                 │
                    Shared facades & adapters
                    (CLI fleet is file JSONL;
                    live_control_plane=false)
```

### Kernel Responsibilities

| Kernel | Plane | Owns |
|--------|-------|------|
| **franken_engine** | Execution | Runtime internals, extension host sandbox, low-level execution primitives |
| **asupersync** | Correctness Control | Cancellation protocol, deterministic replay, evidence contracts, epoch transitions |
| **franken_node** | Product | User/operator surfaces, policy orchestration, evidence consumption/publication |

**Cross-kernel interfaces are strictly controlled** - no kernel may import another's `*_internal` modules.

## Major Product Domains

FrankenNode organizes functionality into distinct product planes:

### 🔄 Migration Domain (`migration/`)
**Purpose:** Automated discovery, risk analysis, and migration from Node.js/Bun  
**Key Components:**
- API scanner for Node.js compatibility analysis
- Risk scoring engine for migration planning  
- Automated rewrite suggestions
- Rollout guidance and compatibility reports

**Entry Points:**
- `src/migration/mod.rs` - Migration orchestration
- CLI: `franken-node migrate audit <path>`

### 🔐 Trust & Supply Chain Domain (`supply_chain/`, `security/`)
**Purpose:** Supply chain security, trust cards, policy enforcement  
**Key Components:**
- Trust card generator and verification
- Supply chain attestation and manifest validation
- Policy engine for trust decisions
- Quarantine and revocation management

**Entry Points:**
- `src/supply_chain/mod.rs` - Supply chain analysis
- `src/security/` - Security policy enforcement
- CLI: `franken-node trust`, `franken-node verify`

### 🚁 Fleet Control Domain (`api/fleet_quarantine.rs`, `control_plane/`)
**Purpose:** Fleet quarantine/release control plane: a local durable store by default, or a live HTTP coordinator shared by every node  
**Key Components:**
- Durable quarantine/release/reconcile records and node heartbeats
- Signed decision receipts
- Zone labels on fleet records
- Local convergence (`live_control_plane=false`) or multi-node convergence through `fleet serve` (`live_control_plane=true`)

**Entry Points:**
- `src/api/fleet_quarantine.rs:FleetControlManager` 
- `src/control_plane/fleet_transport.rs` (durable store), `fleet_http_server.rs` (coordinator), `fleet_transport_http.rs` (client)
- CLI: `franken-node fleet serve`, `franken-node fleet status`, `franken-node fleet release`, `franken-node fleet agent`

### 📊 Replay & Incidents Domain (`replay/`, `observability/`)
**Purpose:** Deterministic replay, incident analysis, evidence capture  
**Key Components:**
- Replay bundle generation and validation
- Evidence ledger for audit trails
- Incident bundle integrity verification
- Counterfactual re-evaluation of the recorded decision trace (not live re-execution)

**Entry Points:**
- `src/replay/mod.rs` - Replay orchestration
- `src/observability/evidence_ledger.rs` - Evidence capture
- CLI: `franken-node incident replay`, `franken-node incident bundle` (recorded bundles, not live re-execution)

### ⚙️ Runtime & Control Plane Domain (`runtime/`, `control_plane/`)
**Purpose:** Runtime execution control, lane scheduling, engine dispatch  
**Key Components:**
- Engine dispatcher for franken_engine coordination
- Lane router for workload distribution
- Telemetry bridge for audit capture
- Runtime profile management

**Entry Points:**
- `src/runtime/mod.rs` - Runtime coordination
- `src/ops/engine_dispatcher.rs` - Engine integration
- CLI: `franken-node run` (policy-governed). `runtime lane` / `runtime epoch` are local snapshots / integer compare, not a live node.

### 🌐 Remote Execution Domain (`remote/`)
**Purpose:** Scope-bound Ed25519 capability tokens for network-bound operations  
**Key Components:**
- Token issue / inspect / revoke
- `remotecap use` / `verify` authorize a scoped operation (dry-run; does not perform the HTTP request)
- Audience binding and optional single-use
- Remote transport abstractions in-library (CLI is token lifecycle, not a live federated executor)

**Entry Points:**
- `src/remote/mod.rs` - Remote capability coordination
- CLI: `franken-node remotecap`

### ✅ Verifier & Evidence Domain (`vef/`, `verifier_economy/`, `sdk/verifier/`)
**Purpose:** External verification, proof generation, verifier economy  
**Key Components:**
- Verifier SDK for external tooling
- Proof verification and generation
- Verifier economy and staking
- Evidence schema validation

**Entry Points:**
- `src/vef/mod.rs` - Verifier framework
- `sdk/verifier/src/lib.rs` - External verifier SDK
- CLI: `franken-node verify` (proof-related commands are under verify subcommands)

### 📈 Observability & Operations Domain (`observability/`, `ops/`)
**Purpose:** Evidence ledger plus local ops snapshots (not a live daemon)  
**Key Components:**
- Evidence ledger for audit compliance
- `ops health-check` / `metrics` from local files and this CLI process
- `ops validation-readiness` / `validation-closeout` inspect `--input`/`--receipt` snapshots (`live_broker=false`)
- Witness and attestation collection

**Entry Points:**
- `src/observability/mod.rs` - Observability framework
- `src/ops/` - Operational utilities
- CLI: `franken-node doctor`, `franken-node ops`

## Key Entry Surfaces

### Primary Entry Points

| File | Purpose | Key Exports |
|------|---------|-------------|
| **`src/main.rs`** | Binary entry point, CLI argument parsing | Main function, command dispatch, configuration loading |
| **`src/lib.rs`** | Library entry point for external consumers | `ActionableError`, utility functions, common types |
| **`src/cli.rs`** | CLI command definitions and argument validation | `Cli` struct, subcommand definitions, argument parsing |
| **`src/config.rs`** | Configuration management and validation | `Config` struct, environment/file precedence, validation |
| **`sdk/verifier/src/lib.rs`** | External verifier SDK | Capsule replay, bundle verification, deterministic schema |

### Configuration Precedence
1. **Command line arguments** (highest priority)
2. **Environment variables** (prefixed with `FRANKEN_NODE_`)
3. **Configuration file** (`franken_node.toml`)
4. **Built-in defaults** (lowest priority)

### CLI Command Structure
```bash
franken-node <SUBCOMMAND> [OPTIONS]

Core Commands:
  run              Execute JavaScript with franken_engine
  deploy           Signed releases, activation pointer, crash-loop rollback to a verified known-good release
  migrate          Migration analysis and tooling (`--emit-rollback` is unsigned JSON)
  trust            Trust and supply chain operations
  fleet            Fleet quarantine control plane (local store, or a live `fleet serve` coordinator)
  ops              Local ops snapshots (not a live daemon)
    health-check   Compiled git SHA plus local ledger/receipt files
  verify           Compatibility/release verification (Node is spec when included)
  incident         Recorded incident bundles (replay is not live re-execution)
  remotecap        Ed25519 capability tokens (`use` is dry-run)
  doctor           Diagnostic and health checking
```

## Feature Flags

FrankenNode uses granular feature flags for compile-time optimization and optional functionality:

### Core Features
- **`engine`** - franken_engine integration (default: enabled)
- **`http-client`** - HTTP client functionality (default: enabled)
- **`external-commands`** - External process execution (default: enabled)
- **`fleet-control-plane-server`** - Live HTTP fleet coordinator over durable fleet state; enables `franken-node fleet serve` (default: enabled)
- **`asupersync-transport`** - `Cx`-checkpointed `asupersync` control-lane transport for `franken-node fleet agent` with receipted degraded fallback (default: enabled)

### Product Surface Features
- **`extended-surfaces`** - Legacy umbrella for `control-plane`, `policy-engine`, `remote-ops`, `admin-tools`, `verifier-tools`, and `advanced-features`
- **`control-plane`** - API middleware and file-transport fleet/quarantine log (not a live multi-node plane)
- **`policy-engine`** - Security policies, guardrail monitors, hardening
- **`remote-ops`** - Remote capability tokens and distributed coordination primitives (CLI `remotecap use` is dry-run)
- **`admin-tools`** - Enterprise governance, migration tools
- **`verifier-tools`** - Verifier-specific tooling and SDK
- **`advanced-features`** - Claims, conformance, encoding, extensions, federation, performance, and repair surfaces

### Development Features
- **`test-support`** - Test utilities and extended testing surfaces; composes `control-plane` and `admin-tools`
- **`loom-models`** - Library-level `#[cfg(loom)]` model helpers for explicit Loom test invocations; not enabled by default or by `test-support`

### Optional Dependencies
- **`compression`** - GZIP/deflate support via flate2
- **`cbor-serialization`** - CBOR encoding support via ciborium
- **`blake3`** - BLAKE3 hashing (performance optimization)
- **`profiling`** - Per-hot-path latency histograms via hdrhistogram; opt-in and compiled out of default builds

## Data Flow

### High-Level Execution Flow
```
CLI Input → Config Resolution → Feature Gate Check → Domain Router → Engine Dispatch
    ↓
Evidence Capture ← Telemetry Bridge ← franken_engine Execution ← asupersync Control
    ↓
Result Processing → Decision Receipt → Audit Log → User Response
```

### Trust Decision Flow
```
Supply Chain Input → Trust Card Validation → Policy Engine → Decision Receipt
                                                    ↓
                                     File-transport fleet quarantine (if needed) → Evidence Ledger
```

## External Dependencies

### Critical Dependencies
| Dependency | Purpose | Risk Level |
|------------|---------|------------|
| **ed25519-dalek** | Digital signatures, cryptographic verification | High |
| **serde/serde_json** | Serialization for configs, receipts, evidence | High |
| **chrono** | Timestamp handling, audit trails | Medium |
| **sha2/hmac** | Cryptographic hashing and MACs | High |
| **tokio** | Dev-dependency (`sync`/`time` features) for tests; not the CLI async runtime | Medium |

### External Kernels
| Kernel | Repository | Integration |
|--------|------------|-------------|
| **franken_engine** | sibling `../franken_engine/` | Default `run` uses the embedded engine; `--engine-bin` is an optional process path |
| **asupersync** | Published `0.6.2` | Default-enabled (`fleet-control-plane-server` + `asupersync-transport`) `Cx`-checkpointed control-lane runtime for `fleet serve` and `fleet agent` |

### Substrate Dependencies
| Substrate | Repository | Purpose |
|-----------|------------|---------|
| **frankentui** | `../frankentui/` (`packaging/source-siblings.tsv`) | Elm/Bubbletea `Model`/`Cmd`/`ProgramSimulator`/`BufferDiff` interactive operator console (`ops operator-console`) plus bordered `Frame` widget screens (`doctor --screen`, `fleet status --screen`) |
| **frankensqlite (`fsqlite`)** | Published `0.1.19` | Live WAL-backed durable SQLite store across product stores (telemetry/audit adapter, trust-card registry, deployment store, fleet transport, native session inventory) |
| **fastapi_rust** | `../fastapi_rust/` (`packaging/source-siblings.tsv`) | Default-enabled (`fleet-control-plane-server`) live HTTP fleet coordinator (`franken-node fleet serve`) on `asupersync` |
| **sqlmodel_rust** | `../sqlmodel_rust/` (`packaging/source-siblings.tsv`) | Production typed schema/DDL boundary (`sqlmodel-core` + `sqlmodel-schema`) for `DurableFrankensqliteAdapter`, the 21 canonical domain models, `ops storage-schema-audit`, and `doctor` live SQLite drift checks |

## High-Impact Control, Obligation & Persistence Boundary Matrix

Every high-impact mutating or authority-bearing CLI/API flow binds explicit capability contexts (`Cx`), bounded regions/supervisors, cancellation/drain rules, linear obligations, remote transport gates, control epochs, and signed/durable evidence:

| High-Impact Path | Consuming Implementation | `Cx` / Capability Scope | Region & Cancellation / Drain | Obligation / Linear Permit | Remote / Transport Boundary | Epoch / Barrier Semantics | Durable Evidence & Typed Store | Immutable Constraints & Open Boundaries |
|------------------|--------------------------|-------------------------|-------------------------------|----------------------------|-----------------------------|---------------------------|-------------------------------|-----------------------------------------|
| **`registry publish` / admission** | `main.rs` (`handle_registry_publish`), `extensions::artifact_contract`, `supply_chain::provenance_gate` | Publisher Ed25519 identity + attenuated `MacaroonCapabilityEnvelope` | Bounded synchronous admission; aborts atomically before store commit on verification error | Publisher signature + SLSA/Sigstore provenance check before registry write | Local capsule + optional `RemoteCap` registry sync | `ControlEpoch` stamped in admission receipt | `trust-card-registry.v1.db` (`fsqlite` + `sqlmodel` schema) + `evidence-ledger.db` | Never admits unsigned/unpinned bytes; `capability_artifact.rs` is never an execution-authority gate |
| **`trust revoke` / `trust quarantine` / `trust release`** | `main.rs` (`handle_trust_revoke`, `handle_trust_quarantine`, `handle_trust_release`), `supply_chain::trust_card` | Operator identity + signing key (`receipt-signing.key`) | Fail-closed atomic SQLite transaction; stale revocation overrides require `DegradedModeAuditLog` | Signed revocation/quarantine receipt committed prior to status flip | Publishes fleet action to `DurableFleetTransport` (`fleet-state.db`) or `fleet serve` HTTP coordinator | Monotonic `quarantine_version` + `ControlEpoch` | `trust-card-registry.v1.db` + `fleet-state.db` + hash-chained `evidence-ledger.db` | Local `trust release` never clears active fleet holds or revocations |
| **`fleet serve` / `fleet agent` / `fleet quarantine` / `fleet release`** | `control_plane::fleet_http_server`, `control_plane::fleet_transport_durable`, `main.rs` (`run_fleet_agent`) | `asupersync::Cx` (`cx.checkpoint()`) + enrolled node Ed25519 keys / bearer auth | `asupersync` runtime listener + `Cx`-checkpointed agent poll/heartbeat loop with bounded drain | Separate `persisted-action`, `applied-policy`, and `session-quiescent` obligations | `fastapi_rust` TCP/HTTP listener (`/v1` + `/v2/fleet/epoch-barrier`) + `AsupersyncFleetTransport` (or receipted `--fallback-file-transport`) | `ControlEpoch` + `EpochTransitionBarrier` + 80-byte atomic `SeqlockControlPage` | `fleet-state.db` (`fsqlite` WAL, `sqlmodel`-audited) + `AuditLog` fallback receipts | `fleet_quiescence_certified == false` on single-node, unauthenticated, shared-bearer, or non-barrier checkpoints; multi-host partition proof tracked in `.31` |
| **`migrate audit` / `migrate rewrite` / `migrate validate`** | `migration::verified_rewrite`, `migration::rewrite_transaction`, `migration::validation_suite` | Profile-governed (`strict`/`balanced`/`legacy-risky`) `ContainmentGate` | Group-commit `RewriteTransaction` (`v6`) journal + `smoke_supervisor` child timeout/kill | `GuestExecutionPermit` required before validation child spawn; rollback plan digest bound before file mutation | Local workspace + lockstep `node`/`bun`/`franken-node` subprocess oracle | Lockstep report SHA-256 bound to candidate tree | `.franken-node/migration/` journal + Ed25519 `artifacts/migration/throughput_delta.json` | Crash-recovery isomorphism & adversarial bypass proofs tracked in producer-distinct `.35` / `.37` |
| **`migrate rollout`** | `migration::rollout`, `migration::rollout_store_signing`, `main.rs` (`sync_rollout_deployment`, `sync_rollout_fleet`) | Operator + `RolloutTransitionSigningContext` Ed25519 key | `shadow -> canary -> ramp -> default` state machine; `--cancel` triggers immediate rollback | Lockstep SHA-256 + rollback plan + Ed25519 transition signature required per promotion | Syncs `DeploymentStore` AND `DurableFleetTransport` (`Release` on `default`, `Quarantine` on rollback/cancel) | Monotonic stage transitions + fleet `quarantine_version` | Persisted rollout state JSON + `DeploymentStore` + `fleet-state.db` | Quantifies holdout cohort + Wilson 95% confidence interval separately from wall-clock velocity |
| **`deploy register` / `deploy activate` / `deploy supervise`** | `ops::deployment_store`, `main.rs` (`run_deploy_supervise`), `EProcessHealthMonitor` | `ContainmentGate` `GuestExecutionPermit` over full `dependency_ids` on candidate AND rollback target | Persistent crash-only microreboot loop with authenticated child panic pipe + anytime-valid Ville e-process canary monitor | Signed release/activation record + sustained post-rollback health obligation | Local supervisor pipe + `native-sessions.db` MVCC WAL | Generation/epoch-stamped activation records | `DeploymentStore` + `native-sessions.db` (`fsqlite` WAL, `sqlmodel`-audited) | Revoked dependencies or active release safe-mode block both candidate activation and rollback selection |
| **`run` / `incident bundle` / `incident replay`** | `ops::engine_dispatcher`, `ops::native_replay`, `sdk/verifier` | Profile `ContainmentGate` `GuestExecutionPermit` + per-effect hostcall capability checks | Bounded execution orchestrator + replay deadline guard | Host-effect hash chain + module-source closure digest (`graph_hash`) | Embedded `frankenengine-engine` + offline `frankenengine-verifier-sdk` | Policy/epoch snapshot bound in `native_replay` (`guest_execution` vs `guest_execution_and_policy`) | `.franken-node/state/incidents/` + `native-sessions.db` + `evidence-ledger.db` | `EffectKind::Spawn` child outcomes remain indeterminate without engine receipt; SDK `incident_module_capsule` keeps `graph_hash_recomputed: false` until full closure recompute (`.7` / `.24` / `bd-f5b04.11`) |

## Test Infrastructure

### Test Organization
| Test Type | Count | Location | Purpose |
|-----------|-------|----------|---------|
| **Unit Tests** | Embedded | `src/**/*.rs` | Module-level validation |
| **Integration Tests** | 500+ | `tests/*.rs` | End-to-end scenarios |
| **Conformance Harnesses** | 70+ | `tests/*_conformance.rs` | Protocol/spec compliance |
| **Metamorphic Tests** | 20+ | `tests/*_metamorphic.rs` | Property-based validation |
| **Golden Tests** | 15+ | `tests/golden/*.rs` | Output stability verification |
| **Fuzz Harnesses** | 10+ | `fuzz/fuzz_targets/*.rs` | Crash detection, round-trip validation |
| **Benchmarks** | 5+ | `benches/*.rs` | Performance regression detection |

### Cross-Substrate Conformance
| Component | Location | Purpose |
|-----------|----------|---------|
| **Conformance Vectors v1** | `artifacts/conformance_vectors/v1/` | Version-pinned canonical test vectors with machine-readable index |
| **Test Strategies** | `src/test_strategies/` | Unified proptest generators for consistent fuzz/PBT input distributions |
| **Vector Consumer Tests** | `tests/*_vector_consumer_conformance.rs` | Validates compatibility with published vectors |

### Test Features
- **Mock-free E2E testing** - Real file-based persistence instead of mocks
- **Real runtime testing** - Tests against actual franken_engine when available
- **Adversarial testing** - Security-focused attack simulation
- **Regression coverage** - Historical bug prevention
- **Cross-substrate conformance vectors** - Versioned canonical test vectors in `artifacts/conformance_vectors/v1/`
- **Unified test strategies** - Centralized proptest generators in `src/test_strategies/` for consistent input distributions

## Development Workflow

### Building
Cargo-heavy work in this repo goes through `rch exec --` (do not wrap
`rch exec -- env ... sh -c 'cargo ...'`).

```bash
# Standard build (limited features)
rch exec -- cargo build

# Full-featured build
rch exec -- cargo build --features extended-surfaces

# Test build with all surfaces
rch exec -- cargo build --features test-support
```

### Testing
```bash
# Core tests
rch exec -- cargo test

# Full test suite with all features
rch exec -- cargo test --features extended-surfaces

# Specific conformance tests (one TESTNAME; integration binaries that
# declare required-features = ["test-support"] need --features test-support)
rch exec -- cargo test -p frankenengine-node --test fleet_decision_contract_harness --features engine,test-support

# Fuzz testing
cd fuzz && cargo fuzz run fuzz_config_toml_parse
```

### Key Development Files
- **`AGENTS.md`** - Agent collaboration guidelines
- **`docs/architecture/`** - Detailed technical architecture docs
- **`.beads/`** - Issue tracking and project management
- **`artifacts/golden/`** - Golden test reference outputs

## Getting Started for New Engineers

1. **Read the foundation docs:**
   - This document (architecture overview)
   - `AGENTS.md` (development workflow)
   - `docs/architecture/blueprint.md` (detailed technical blueprint)

2. **Build and explore:**
   ```bash
   rch exec -- cargo build -p frankenengine-node
   rch exec -- cargo test -p frankenengine-node --test cli_subcommand_goldens --features engine,test-support
   franken-node doctor --json
   ```
   `cli_subcommand_goldens` declares `required-features = ["test-support"]` and
   fails in seconds without that feature. `doctor` diagnoses the environment;
   it is not a live control-plane probe.

3. **Understand the domains:**
   - Pick a domain that interests you (Migration, Trust, Fleet, etc.)
   - Read the domain's `mod.rs` file
   - Run related tests to see the domain in action

4. **Key concepts to understand:**
   - **3-kernel separation** - Never violate cross-kernel boundaries
   - **Feature flags** - Most functionality is behind compile-time gates  
   - **Evidence-first design** - All operations generate audit evidence
   - **Security hardening** - Constant-time operations, saturating arithmetic
   - **Mock-free testing** - Real persistence and real runtime integration

5. **Development patterns:**
   - Use `push_bounded()` for all Vec operations in structs
   - Use `saturating_add()`/`saturating_sub()` for arithmetic
   - Use `ct_eq()` for sensitive comparisons
   - Generate golden tests for output stability
   - Write conformance harnesses for protocols
   - Use `test_strategies::*` for proptest/fuzz generators to ensure consistent input distributions

## Notes & Gotchas

- **Kernel boundaries are enforced** - Cross-kernel calls only through stable facades
- **Feature flags control compilation** - Many tests require specific features enabled
- **Evidence logging is mandatory** - All decisions must generate audit evidence  
- **Security patterns are required** - Follow hardening patterns for all security-sensitive code
- **No `unsafe` code allowed** - `#![forbid(unsafe_code)]` is enforced
- **Real integration preferred** - Mock-free testing with actual file systems and processes

---

*This overview provides the essential architecture knowledge for effective contribution to franken_node. For deeper technical details, see `docs/architecture/` and domain-specific `mod.rs` files.*
