# FrankenNode - Architecture Overview

*For engineers new to the franken_node codebase*

## Executive Summary

**FrankenNode** is a trust-native JavaScript runtime replacement for Node.js/Bun, designed around supply chain security, migration assistance, and verifiable execution. The system implements a 3-kernel architecture for separation of concerns between execution, correctness control, and product surfaces.

**Key Stats:**
- **Language:** Rust 2024 Edition (nightly toolchain)
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
│ • QuickJS/V8    │    │ • Evidence      │    │   chain control │
│   lanes         │    │   ledger        │    │ • Fleet ops     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
       │                         │                         │
       └─────────────────────────┼─────────────────────────┘
                                 │
                    Shared control plane via
                    stable facades & adapters
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
- CLI: `franken-node migrate analyze <path>`

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
**Purpose:** Enterprise fleet management and quarantine operations  
**Key Components:**
- Fleet-wide quarantine orchestration
- Decision receipt generation
- Zone-based fleet control
- Convergence state management

**Entry Points:**
- `src/api/fleet_quarantine.rs:FleetControlManager` 
- `src/control_plane/` - Control plane services
- CLI: `franken-node fleet quarantine`, `franken-node fleet release`

### 📊 Replay & Incidents Domain (`replay/`, `observability/`)
**Purpose:** Deterministic replay, incident analysis, evidence capture  
**Key Components:**
- Replay bundle generation and validation
- Evidence ledger for audit trails
- Incident bundle integrity verification
- Time-travel debugging capabilities

**Entry Points:**
- `src/replay/mod.rs` - Replay orchestration
- `src/observability/evidence_ledger.rs` - Evidence capture
- CLI: `franken-node replay`, `franken-node incident`

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
- CLI: `franken-node run`, `franken-node runtime`

### 🌐 Remote Execution Domain (`remote/`)
**Purpose:** Distributed execution, remote capabilities, federated operations  
**Key Components:**
- Remote capability management
- Distributed computation registry
- Federation protocol implementation
- Remote transport abstractions

**Entry Points:**
- `src/remote/mod.rs` - Remote execution coordination
- CLI: `franken-node remote`

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
- CLI: `franken-node verify`, `franken-node proof`

### 📈 Observability & Operations Domain (`observability/`, `ops/`)
**Purpose:** Monitoring, telemetry, operational tooling  
**Key Components:**
- Evidence ledger for audit compliance
- Telemetry bridge for metrics collection
- Operational tooling for fleet management
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
3. **Configuration file** (`franken-node.toml`)
4. **Built-in defaults** (lowest priority)

### CLI Command Structure
```bash
franken-node <SUBCOMMAND> [OPTIONS]

Core Commands:
  run              Execute JavaScript with franken_engine
  migrate          Migration analysis and tooling
  trust            Trust and supply chain operations
  fleet            Fleet management and quarantine
    describe       Fleet status and configuration inspection
  ops              Runtime operations and health inspection
    health-check   Process/runtime health signals
  verify           Verification and proof operations
  replay           Replay and incident analysis
  remote           Remote execution capabilities
  doctor           Diagnostic and health checking
```

## Feature Flags

FrankenNode uses granular feature flags for compile-time optimization and optional functionality:

### Core Features
- **`engine`** - franken_engine integration (default: enabled)
- **`http-client`** - HTTP client functionality (default: enabled)
- **`external-commands`** - External process execution (default: enabled)

### Product Surface Features
- **`extended-surfaces`** - All product surfaces (legacy umbrella feature)
- **`control-plane`** - API middleware, fleet operations, control plane
- **`policy-engine`** - Security policies, guardrail monitors, hardening
- **`remote-ops`** - Remote operations, distributed coordination
- **`admin-tools`** - Enterprise governance, migration tools
- **`verifier-tools`** - Verifier-specific tooling and SDK
- **`advanced-features`** - Claims, conformance, encoding, extensions

### Development Features
- **`test-support`** - Test utilities and extended testing surfaces
- **`asupersync-transport`** - Direct asupersync integration

### Optional Dependencies
- **`compression`** - GZIP/deflate support via flate2
- **`cbor-serialization`** - CBOR encoding support
- **`blake3`** - BLAKE3 hashing (performance optimization)

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
                                     Fleet Quarantine (if needed) → Evidence Ledger
```

## External Dependencies

### Critical Dependencies
| Dependency | Purpose | Risk Level |
|------------|---------|------------|
| **ed25519-dalek** | Digital signatures, cryptographic verification | High |
| **serde/serde_json** | Serialization for configs, receipts, evidence | High |
| **chrono** | Timestamp handling, audit trails | Medium |
| **sha2/hmac** | Cryptographic hashing and MACs | High |
| **tokio** | Async runtime for I/O operations | Medium |

### External Kernels
| Kernel | Repository | Integration |
|--------|------------|-------------|
| **franken_engine** | `../../../franken_engine/` | Process boundary via engine dispatcher |
| **asupersync** | Optional feature | Direct crate dependency |

### Substrate Dependencies
| Substrate | Repository | Purpose |
|-----------|------------|---------|
| **frankentui** | `../../../dp/frankentui/` | Terminal UI components |
| **frankensqlite** | Test dependency | SQLite persistence substrate |
| **fastapi_rust** | Test dependency | HTTP service substrate |

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
```bash
# Standard build (limited features)
cargo build

# Full-featured build
cargo build --features extended-surfaces

# Test build with all surfaces
cargo build --features test-support
```

### Testing
```bash
# Core tests
cargo test

# Full test suite with all features
cargo test --features extended-surfaces

# Specific conformance tests
cargo test --test fleet_decision_contract_harness

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
   cargo build --features test-support
   cargo test --test cli_subcommand_goldens
   ./target/debug/franken-node doctor
   ```

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