# FrankenNode - Architecture Overview

*For engineers new to the franken_node codebase*

## Executive Summary

**FrankenNode** is the product layer over sibling `franken_engine`: migration, trust, fleet file-transport, replay, and verifier surfaces around a native JS/TS runtime. It is **not** a drop-in Node.js/Bun replacement (L1 corpus currently 86.43%; `child_process` native-eval aborts remain fail). The system implements a 3-kernel architecture for separation of concerns between execution, correctness control, and product surfaces.

**Key Stats:**
- **Language:** Rust 2024 Edition (this checkout does not pin a `rust-toolchain.toml`; use a compatible stable toolchain unless a task proves otherwise)
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
**Purpose:** Local file-transport fleet/quarantine log (not a live multi-node control plane)  
**Key Components:**
- File-backed quarantine/release/reconcile records
- Signed decision receipts
- Zone labels on local log records
- File-transport convergence (`live_control_plane=false`)

**Entry Points:**
- `src/api/fleet_quarantine.rs:FleetControlManager` 
- `src/control_plane/` - epoch/fork/MMR primitives (not a live fleet daemon)
- CLI: `franken-node fleet status`, `franken-node fleet release`, `franken-node fleet agent` (file JSONL, not a live heartbeat)

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
  migrate          Migration analysis and tooling (`--emit-rollback` is unsigned JSON)
  trust            Trust and supply chain operations
  fleet            Local file-transport fleet/quarantine log (not a live control plane)
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
- **`asupersync-transport`** - Direct asupersync integration

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
| **asupersync** | Optional feature | Direct crate dependency |

### Substrate Dependencies
| Substrate | Repository | Purpose |
|-----------|------------|---------|
| **frankentui** | `../../../dp/frankentui/` | Buffer echo of preformatted doctor/fleet lines |
| **frankensqlite** | Dev-dependency (published 0.1.19) | In-memory adapter / conformance model, not the live durable store |
| **fastapi_rust** | Dev-dependency | In-process catalog; does not bind a socket |

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
