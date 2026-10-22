# Reality Check and Bridge Plan: franken_node

## Current assessment — 2026-10-21

### Execution TODO — started 2026-10-21 after the assessment

Consumer: the operator explicitly requested a detailed TODO while implementing the bridge. This checklist tracks execution and retires into the canonical Beads when guarded tracker writes work again. It gives no capability credit by itself.

- [x] Recheck HEAD, dirty paths, required disk admission, and guarded Beads claiming. Tree initially clean; disk still critical; `.12` claim refused by database-family authority.
- [x] R1: reproduce the initial reference failures, inspect Node contracts, and preserve all expected outputs and case identities.
- [x] R1: exercise pinned Node 22.14.0 and available Node 24.20.0/26.8.1; retain version-specific failures. Full qualification remains open below.
- [x] R1: await the asynchronous closed-directory rejection and use a synchronous closed-descriptor probe where required; retain cleanup assertions.
- [x] R1: replace the hand-built diagnostic store with the required AsyncLocalStorage instance.
- [x] R1: capture the pre-aborted sink's actual stream error and await close before observing resource cleanup; retain Node 24's internal Web-stream failures as non-pass.
- [x] R1: await `writer.closed` in the sink-error bridge program. Exact original error identity and all original cleanup/file assertions pass on Node 22/24/26 and Bun.
- [x] Make the existing project collection runnable: add 34 missing categories in seven manifests, add `--corpus-dir`, reject duplicate IDs/invalid/oversized collections, retain all cases after a failure, and make the existing reference test execute every manifest.
- [x] R4: repair the explicitly synthetic triad fixture's missing file mutation; retain the intentional file-mismatch negative. This supplies orchestration proof only.
- [x] Execute the complete 153-case triad on real published v0.2.0, Node 26.8.1 and Bun 1.4.0, retaining binary hashes, versions, corpus digest, streams, files and watchdog receipts. This is release evidence, not current-source evidence.
- [x] Execute focused Python suites; classify native skips, remaining reference-version differences and denied host signal cleanup explicitly.
- [x] R2 instructions: publish the actual inline override/features, nonzero discovery check and module execution command in both replay documents. Parser tests and preflight pass; Rust discovery/execution remain unverified.
- [x] Correct user-facing release/source-bootstrap/architecture/feature instructions from current release metadata and code. Existing source-bootstrap tests pass 27/27; this is onboarding maintenance, not runtime capability credit.
- [x] Review changes from a fresh verification pass against the original expectations, re-execute the real full collection, compile touched Python sources, inspect UBS warnings, and pass `git diff --check`. Publication is recorded by the implementation commit and final operator response, not a pre-checked push claim.
- [ ] R1/R1T: independently qualify all 153 frozen expectations and execute the current source candidate. Node 22 has unsupported/crashing Web-file-stream cases, Node 24 has Blob and pre-abort differences, Node 26 has Blob/dotenv differences, and Bun disagrees on 14 cases. No golden or threshold was changed to force agreement.
- [x] R0: restore safe Beads write admission through the owning engine checkpoint and reviewed in-place schema migration, reconcile the canonical JSONL, claim `.12`, record evidence and sync. The original framed WAL and complete family remain preserved; no JSONL-based DB rebuild or manual row edit was used. Details below.
- [ ] R2T/R3/R3T/R5: current-engine compilation, native project/replay verification, module replay and installed-asset qualification. Local build admission remains critical. On 2026-10-22 the operator explicitly allowed strictly remote RCH builds despite that check; normal worker/toolchain/source admission still applies, with no local Cargo or deletion authorized.
- [ ] Existing later owners: current per-profile >=95% corpus, >=3x durable migration, live substrate/advanced-surface integration, performance, independent replication and production adoption. These remain open until their own positive acceptance evidence exists.

### Offline npm and native-build execution — 2026-10-22

- [x] Recheck live work, priorities and disk: 6.86% free / 274 GB; local builds remain prohibited. Obtain the explicit operator exception **"Allow strictly remote RCH builds"** before attempting remote Rust verification. Preserve all peer work and delete nothing.
- [x] Inspect module replay wiring: the frozen source capsule and closed-world engine resolver already exist, but captures omit the capsule and replay deliberately removes ModuleLoad. `bd-f5b04.10` still requires authenticated capture/restore and source-bound native tests; do not merely remove either refusal.
- [x] Download the official npm archives for `is-number@7.0.0`, `isarray@2.0.5`, `escape-string-regexp@4.0.0` as data, verify registry SHA-512 integrity and SHA-1 archive checksums, and retain each original runtime source, manifest and MIT license. No package manager or install script ran.
- [x] Add three offline package projects with API drivers, exact version/URL/integrity lockfiles, and all nine original upstream files **byte-identical** to those verified archives. Frozen expectations cover numeric/coercion boundaries, array/prototype shapes, Unicode regex use, empty strings and precise type errors. This is an initial bounded npm band, not representative top-N coverage.
- [x] Wire integrity/reference tests into the existing CI job. Local Node executes every new driver and matches all frozen observations; identity tests pin all nine upstream hashes independently of fixture contents. Actual GitHub job execution is unverified.
- [x] Connect the five newly committed promised-stream source cases by adding only their mandatory categories. All five match Node, including file cleanup observations. Their IDs, code and expectations are unchanged. The complete loader now admits **161 cases / 24 manifests**; all pre-existing expectations remain intact.
- [x] Execute the genuine npm triad with published **v0.2.0 / Node 26.8.1 / Bun 1.4.0** under strict, balanced and legacy-risky: **3/3 PASS in each profile**, all nine native and eighteen reference legs observed. No adapter, profile change, golden regeneration or skip was used. This is published-release package evidence, not current-source or ecosystem-wide qualification.
- [x] Resolve the clean-source compiler admission conflict with an explicit compiler file. RCH clean-overlay ignores ambient/command toolchain selection when no project file exists, then refuses the missing identity. The initial **1.99.0** pin admitted normal worker selection; RCH rules remain unchanged. The actual stable compile subsequently failed as recorded below, so the current pin is **nightly-2026-09-21**, present locally and on the selected worker with clippy/rustfmt.
- [x] Finish strict-remote Python qualification on `ovh-b`: **50/50 PASS, zero skips**, 63.5 seconds; the full 48-test runner plus two genuine npm integrity/reference tests. All five worker-reported runner/test/fixture hashes match local bytes. The first pinned request was cooperatively cancelled before admission; an unpinned attempt refused unsafe/live source destinations before reaching `hz3`. That worker then failed 1/50 and 3/50 in separate runs while read-only inspection found the test process in disk I/O wait and full I/O PSI about 49%. Preserve those losses; do not attribute their exact causes beyond observed evidence. Added diagnostic seed/positive-report assertions and bounded an independent diagnostic `node --version` call at five seconds; no production deadline or assertion was relaxed.
- [x] Execute the stable remote compiler baseline on exact committed source roots: node `20c6c7f5a`, engine `3fb3f39ca`, frankentui `bb8c49f10`, fastapi `08f7251c9`, sqlmodel `7f432ff69`, plus the explicit toolchain-file overlay. **FAIL, exit 101:** published `fsqlite-pager 0.4.1` enables `feature(core_intrinsics)` on x86_64 and Rust 1.99 stable rejects it with E0554. Concurrent engine working-tree edits were excluded. Earlier option/toolchain/source-binding refusals and this real compiler failure are not passes. No `RUSTC_BOOTSTRAP` workaround is permitted.
- [x] Review every generated Cargo-lock delta, manually apply it, and prove byte identity with the retained remote lock: SHA-256 `a3c81830228d427fc60b82c173edbbbac03a1f4a85b719e9f2d8c72c6498b309`. Align `packaging/source-siblings.tsv` with the three supporting commits above. The 27 real-checkout source-bootstrap tests pass; they do not compile Rust.
- [x] Execute the source recipe with **nightly-2026-09-21** and **--locked** on `vmi1152480`, five explicit source roots. The compiler passes the stable-only failure and reaches the product, then **FAILS exit 101 with five E0004 errors**: missing `EnvRead` cases in the ledger and SSRF decorator. This is a real baseline loss, not a source-build pass. RCH retired the isolated worker tree after completion, so a subsequent read-only lock-hash request found no file; no post-run hash is claimed.
- [ ] Recheck the current candidate with `--locked --all-targets`, then clippy, fmt and discovered native tests. The original 17-overlay check failed as recorded below. A new strict-remote all-target check uses merged node `681842777`, the same five overlays as the active native test, and engine `10b88fb2c`; it is awaiting normal admission. Prepared fixes add a distinct `env_read` receipt (stable tag 8) to product and independent SDK, preserve absent/empty commitments and Secret lineage, and pass environment operations through the existing controlled provider. No profile grant changed.
- [ ] `bd-f5b04.10`: qualify the prepared v3 capture containing the existing frozen source capsule, canonical pins and original prepared entry binding. Replay restores the closed-world resolver with original capabilities; captures without a capsule still disable module loads. Historical v2 execution is refused explicitly. SDK metadata inspection remains distinct from validating/executing a capsule.
- [ ] `bd-f5b04.10`: execute the new nested CommonJS positive after source files move, with missing/altered source, wrong-pin and oversized-payload negatives.
- [x] `bd-f5b04.10`: replace the prepared ESM test's unsupported `fs` setup. Existing frozen execution still refuses `require('fs')`. The test now uses an explicitly allowlisted real environment read, replays completed/exception outcomes from another operator directory after moving the entire original project and changing the replay host's environment, compares the exact journal and rejects an authenticated wrong capsule pin. Execution remains pending; this does not qualify frozen filesystem-writing applications.
- [x] `bd-f5b04.10`: move capsule/source preparation validation into the existing 64 MiB replay worker before evaluation. The new source parser no longer runs on the caller's smaller stack; envelope/canonical-byte validation remains before spawning. Native execution remains pending.
- [ ] Execute environment-read capture/replay through the actual CLI, proving absent/empty/present commitments differ, private names/values stay out of effect receipts, unread variables stay out of capture, and a changed replay-host environment is ignored. Execute the standalone SDK and SSRF delegation regressions as well.
- [ ] Obtain the separate exact-source/trust-anchor verification in `bd-f5b04.11`. Code, pins, a metadata test and self-review cannot close that independent acceptance task.
- [x] Execute the standalone SDK suite on `hz4`, exact SDK overlay fingerprint `9795b1dfae17ea92e3077cd60dd4702816f3fbb0706b0cb3443e3b7829dcee07`: Cargo exits 0, 341 unit tests pass plus the integration suites; 26 doctests pass and **11 doctests remain ignored**. The first SDK compile found a missing `EnvRead => 8` arm in the independent round-trip encoder; added that explicit arm without changing old tags or goldens. Source-init and capacity refusals before the successful retry are not test passes. Metadata inspection still does not execute the native capsule.
- [x] Finish the 17-overlay all-target attempt: **FAIL exit 101**, older engine `3fb3f39ca` lacks `NativeBuiltinModule::PathPosix`. A concurrent writer committed the prototype as `741378b29` and merged the separate captured-ESM update at `681842777`; all 17 running input hashes remained identical. Preserve both commits. This publication is not qualification of the prototype.
- [ ] Qualify merged node `681842777` with the captured-ESM update's explicit engine `10b88fb2c70041ae7a0036a83b4c8e2cfead29f9`; their Cargo manifests have no dependency changes from the old engine baseline. The strictly remote targeted native CommonJS capture/replay test is building on `vmi1152480` with five explicit source overlays. Current fixes move source validation to the large replay stack, replace the unsupported filesystem test with a recorded environment read, and retain separate environment/file source labels through later verbatim byte flows. No native positive is claimed yet.
- [x] Add the distinct environment-source commitment assertion to the actual CLI environment regression. The inline ledger regression also checks an environment-derived write and unrelated clean output. Both still require nonzero native execution; the disabled default inline harness supplies no credit.
- [x] Correct the CommonJS test setup to reuse the actual config produced by `init`. The helper previously received `Config::default()` and synthesized fresh registry/API credentials after init. It now loads the genuine init TOML, preserving the positive output, offline replay and all seven negatives. Execution of the corrected test is pending.
- [x] Correct the CommonJS tamper probes: serializing the mutated `serde_json::Value` sorted struct fields and could reject every candidate at the generic canonical-byte guard. Unique, exact JSON-fragment replacements now preserve original field order, recompute the envelope digest, and require each specific source/capsule/origin/budget error. Both direct and authenticated CLI pin probes now use a well-formed, incorrect 64-hex digest; the CLI probe also requires the capsule-validation diagnostic. The original seven mutations and canonical-byte guard remain intact. These new assertions are not executed yet.
- [x] Before changing local test inputs during compilation, preserve all five source files outside the checkout and compare SHA-256 against **both** isolated remote trees. Every file matches, and both commands report `RCH_BUILD_SOURCE=681842777aaae014453366bec83f311cc0e7b2a1-overlay-a2089eeeab604784c45c8b5e8619b09da8921338a5cf1a06816c533b8fe2f95d`. Those running results belong only to that preserved candidate; they cannot qualify the subsequent test corrections or formatting. Source snapshots are retained at `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-replay-frozen-1919.lj4EmsSt/`.
- [ ] Run the corrected CommonJS and signed ESM/environment CLI tests, then recheck the final source with all targets, clippy and formatting. Do not substitute the earlier frozen run for these final-source checks.
- [x] Preserve the native-build infrastructure loss: `vmi1152480` reached `frankenengine-core` and failed creating a compiler temp directory with **ENOSPC**. The local wrapper exits 1; no native test executed. RCH initially retained unconfirmed ownership after SSH 255. Its supported `jobs recover` then confirmed that remote execution had ended without a completion receipt and classified it failed, but could not persist source cancellation because that worker was still full. Do not clear locks, restart shared daemons, delete files or pretend recovery completed. A corrected-test request to that worker separately refused draining/unreachable admission (103).
- [ ] Execute corrected replay integration on `hz4`: live read-only inspection reports **103 GiB disk free / 239 GiB available RAM**; normal RCH admission remains required. The request selects both actual Cargo integration targets with the `replay` filter, `--no-fail-fast` and one test thread, preserving the new CJS/ESM/environment checks and existing replay regressions. This is a new corrected source candidate, not an automatic replay of the unconfirmed old job. The final-source formatting request separately failed source initialization on `hz3` (73 / Killed), then exited 103 without a formatting verdict; the earlier actual 82-file failure remains the only completed full formatting result.
- [x] Reduce only debug-symbol storage for the corrected native test recipe: cooperatively cancel the still-queued original request, observe terminal exit **130**, then submit the same tests with explicit `--config profile.test.debug=1`. [Cargo documents this as limited debug information](https://doc.rust-lang.org/cargo/reference/profiles.html#debug), distinct from `debug-assertions`, overflow checks and optimization; those test defaults remain unchanged. This is a build-resource choice, not a performance result, relaxed assertion or release qualification. The replacement request is awaiting normal `hz4` admission.
- [x] Reconcile the existing README and environment/engine-stop replay contracts with the implemented v3 envelope and capsule/no-capsule split. Remove stale claims that v2 payloads remain accepted; state that frozen multi-file native qualification is pending, SDK metadata inspection is not capsule execution, and the three tiny npm release successes do not qualify current source or the wider ecosystem. No new documentation system or capability credit is introduced.
- [ ] Satisfy the existing no-contract-no-merge gate with truthful evidence, without modifying the gate or reusing unrelated example measurements. The exact gate on the current changed-file list exits **1**, `CONTRACT_NO_MERGE_MISSING`: there is no change-summary companion. Its existing schema requires benchmark, numerical coverage/loss/confidence, and tested rollback evidence; these are not established by the current native candidate. Keep this separate from the SDK pass and do not fabricate fields, use an override label or silently call the merge gate green.
- [ ] Finish corrected native admission: the first limited-debug `hz4` request timed out in the normal queue (103), with zero test execution. Read-only diagnosis reports all workers at capacity. Submit one replacement with the documented `RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800`, unchanged capacity/pressure checks, `profile.test.debug=1` and `profile.test.incremental=false` to avoid accumulating incremental build cache. Preserve assertions, overflow checks, optimization and both replay integration targets. No worker configuration, daemon restart or local Cargo fallback is authorized or used.
- [x] Preserve the subsequent admission results: even the documented 1800-second client wait returned daemon `queue_timeout` after approximately 300 seconds, exit 103. A normal `hz3` replacement remained queued and was cooperatively cancelled before start, with terminal exit 130, after source review found invalid CLI test configuration types. Neither request executed tests.
- [x] Correct both new CLI fixtures to use the actual `BTreeSet<String>` environment allowlist via `.insert()`, rather than assigning a `Vec`. This is a source-review finding, not a claimed observed compiler diagnostic. Capture final five-file hashes in `corrected-rust-inputs-1950.sha256` and submit the corrected native request on `hz3`.
- [ ] Finish the replacement all-target check on `vmi1153651` against those corrected inputs. The outdated check was cooperatively stopped: its cancellation RPC timed out, the remote compiler's terminal **143** was observed, and its automatic retry correctly refused changed local inputs with `RCH-E413`, ending the wrapper at **103**. The preserved old overlay and its partial dependency checking do not qualify the final source. No cancellation/retry/refusal is a compiler pass.
- [ ] Finish static triage without suppressions. UBS static-only scan over 16 full Rust files exits 1: **54 critical / 6,951 warning / 3,346 info** matches. Its text report includes intentional test panics, dummy secrets, public PID/key comparisons and controlled executable selection; displayed samples do not establish every match is benign. JSONL exports counts only, and the attempted SARIF export reports no SARIF inputs and an empty `runs` array; neither is a clean scan. Full text is retained. Cargo phases are explicitly not evaluated by this scan and remain in RCH.
- [x] Obtain complete critical-match locations from the unchanged UBS analyzer, with report detail increased only: 16 files, **54 critical / 6,951 warning / 3,342 info**, no analyzer errors. Inspect all 54 critical locations: 16 test failure guards; 17 public key/status/PID/UID comparisons; eight dummy fixture values, source labels or token-location constants; seven explicitly selected command paths with separate arguments; four fixed outbound HTTP header classifications; two fixed `/bin/sh -c 'exit 0'` tests. No new defect was identified in those matches. The first diagnostic incorrectly supplied a newline-separated file list and is invalid; the corrected NUL-separated run reports all 16 files. UBS still exits 1, the thousands of warnings are not collectively certified, no suppression was added, and this static inspection does not replace remote compiler/native verification.
- [x] Preserve another concurrent publication: `52b25fcb3` committed only the distinct environment-label helper while the frozen native build was running. Its worktree bytes are unchanged, so the build still tests its original `681842777` plus explicit overlays; the new commit itself supplies no execution evidence. Import canonical Beads after observing the update.
- [ ] Correct new formatting after the frozen compiler/SDK runs complete. The exact remote `cargo fmt --check` failed with 1,902 hunks across 82 files, including untouched migration/config/registry sources; the complete 1.7 MB log is retained. The accidentally broader `--all` check was cooperatively cancelled (exit 143); its cancellation RPC timed out but its own wrapper's terminal exit was observed. A first exact-check retry refused critical worker pressure (exit 103); the admitted `vmi1152480` check produced the actual formatting failure. No check was called a pass or weakened.
- [x] Verify every original 153-case manifest against the pre-work Git source and the stream additions as category-only. UBS exits 0 over both changed Python tests, zero critical / 11 warnings; warnings are expected fixture JSON parse failures in assertions, with no suppression. Workflow YAML and new job shell syntax parse; the Beads graph has zero cycles. Publication is recorded in Git and the final response.
- [x] Re-execute the entire 161-case Node 26.8.1 reference collection: **159 match / two retained stdout disagreements**, Blob iterable snapshot and dotenv prototype behavior. The 10-test reference suite exits 1 with those two subtest failures; no original golden was edited. This is not a green whole-collection qualification or a native score.
- [x] Reconcile the interrupted 19:56 native/check invocations through supported RCH recovery: both remote commands ended **143**, terminal acknowledgements confirmed; neither reached a compiler/test verdict. The earlier ENOSPC job is also now acknowledged as failed. No process ownership or lock was cleared manually.
- [x] Preserve concurrent publication `ebbf4234ecc15a0a10907b9e7a0560ffeb38e96b`: its eight authored worktree paths match the frozen inputs, and its publication adds no native qualification. Save the index outside the checkout before reconciling only those matching reserved paths. Canonical Beads were imported after observing the update.
- [x] Retain the final 16-file static-only UBS result: **exit 1; 54 critical / 6,959 warning / 3,348 info**. The critical count is unchanged; the complete warning population is not certified. Exact remote formatting also remains **exit 1** across the workspace. Manually correct only newly authored formatting blocks; preserve unrelated differences and both complete logs.
- [ ] Finish native replay integration on `vmi1153651` and the admitted inline discovery build on `hz4`. The pinned all-target retry timed out before admission (103); a normal-selection replacement checks the latest `final-source-inputs-2052.sha256` candidate. Native/inline runs still use the preceding frozen inputs, and clippy uses the pre-format inputs: retain those identities and recheck after any subsequent changes. Final manual dispatcher formatting and the inline test's misleading v2 description were corrected; the latter now explicitly asserts optional module capture is absent in the current v3 shape. Then execute discovered inline replay/SSRF/ledger regressions with nonzero counts, and measure the current native package band. No native pass, independent acceptance or Beads closure is established yet.
- [x] Finish the first all-target clippy attempt: **exit 101**, three `collapsible_if` errors in the SDK capture validator. Manually collapse those exact predicates using short-circuit let chains; preserve all exit-code, trace and zero-effect-event checks. No lint suppression or validation rule changed.
- [ ] Qualify the six-overlay candidate, now including `sdk/verifier/src/incident_native_capture.rs`: rerun all-target clippy on `vmi1152480` and the full standalone SDK suite on `hz4`, then final formatting/static checks. Older native/inline/all-target requests retain their earlier bytes and cannot qualify these later edits.
- [x] Qualify the current SDK after all three predicate fixes and manual formatting: strict RCH on `vmi1227854`, base `ed244303afe527702d0f85a054923ef2a80da76b` plus three overlays, source fingerprint `5cac51280927f112bd6a0e29c23f4d27b97e5139118b43b96d4793c72d5591f8`. **Cargo exits 0: 341 unit + 59 integration + 26 doctests pass; 11 doctests ignored.** Zero-test helper targets add no proof. The slow signature-timing regression passes; no threshold changed. All three local input hashes still match the submitted snapshot. The earlier `hz4` source initialization failed (Killed/73 then103); a replacement waited on clippy's source lock, and supported cancellation remains unacknowledged. Its retained lease/locks were not cleared. The passing invocation uses a distinct newer source namespace and is not a replay of that unresolved request.
- [ ] Finish broad product clippy/checking, discovered inline/native execution and final static/format triage. Current SDK all-target clippy passes as recorded below. The latest full formatting check still exits 1 (1,857 hunks); the new static-only UBS wrapper invocation is stalled before producing a result, not passed. Native `.10` and independent `.11` remain open.
- [x] Finish current SDK all-target clippy with `-D warnings`: the first dedicated attempt failed on seven test-code lints (five single-range slices and two needless one-element clones). Replace them with `std::slice::from_ref`, preserving every exact range, duplicate-event negative and assertion. The four-overlay candidate fingerprint `9570db884e22cf650c8e4bd97ad41124aea66c24f92dad9a00b82e32fe1ab94d` passes clippy (**exit 0**) and all **42 affected incident-bundle unit tests** (**exit 0; zero failures/ignores; 299 unrelated tests filtered**). All four submitted hashes still match local files. Production predicates are unchanged from the full SDK pass above; no lint allowance, range expansion or test deletion was used.
- [x] Recover complete static evidence through the unchanged installed Rust analyzer: verify all **350 Python helper source hashes** against the installed UBS wrapper pins, generate its normal built-in AST rules, and scan all **17 full Rust files** without category skips or test exclusion. The first setup failed in the checksum parser and produced no scan; retain it. The corrected run completes with **exit 1**, 54 critical / 7,215 warning / 3,387 info counts, 10,648 finding records, all 17 files retained by prefilter and no analyzer errors. All 17 source hashes remain unchanged during analysis. After path normalization, all 54 critical rule/file/exact-source-text matches are identical to the earlier inspected set. This is direct static-analyzer evidence; the separately stalled UBS wrapper remains incomplete, warnings are not collectively certified, and Cargo phases are not evaluated. The final full formatting check remains exit 1; a new one-line SDK test assertion wrap was corrected without changing its tokens or assertions.
- [x] Preserve the final all-target check's real infrastructure loss: `hz3` reaches engine metadata and then fails **101 / ENOSPC**, including an I/O error while publishing its shell status. No product compiler verdict or test execution is credited. Normal read-only worker probes find the still-running native/clippy workers have available storage; one mistaken-address probe was refused by host-key checking and was corrected from RCH's live inventory. No files, locks or worker thresholds were changed.
- [ ] Complete the seven-overlay all-target retry on `vmi1149989` through normal admission, retaining node `681842777`, engine `10b88fb2c` and all supporting pins. Disable only dev/test incremental cache generation to reduce storage use; targets, compiler diagnostics, assertions, overflow checks and optimization remain unchanged. This final recipe includes the SDK test-helper fixes. Live inspection before submission reports 53 GiB free / 39 GiB available RAM on that worker; capacity and pressure admission still apply.
- [x] Preserve broad clippy's configured-deadline loss: after dependency/engine checking, the six-overlay invocation ends **137 at 3600 seconds**, without a final product verdict. No deadline loss is treated as a lint pass. Submit the current seven-overlay candidate to the same normally admitted worker/cache with the original deadline and `-D warnings` unchanged; include the already qualified SDK test-helper fixes.
- [x] Reconcile the formerly source-lock-waiting SDK request through supported recovery. Once broad clippy releases its lock, the SDK request correctly refuses changed local inputs with `RCH-E413` before executing tests; its wrapper exits 103. Recovery reports a terminal acknowledgement and recorded exit 1 for the final attempted worker. No test is credited and no lease/lock is cleared manually. The separately passing SDK candidates above are unaffected.
- [ ] After native/inline qualification, replace the pre-existing vacuous unsigned `>= 0` test assertions reported by the enabled-inline compiler in `testing/lab_runtime.rs`, `testing/virtual_transport.rs` and `testing/mod.rs` with each fixture's intended exact/monotonic/count invariant, then execute those named tests. Inspect the unused-state warning in `runtime/anti_entropy.rs` for missing assertions rather than hiding it. These warnings arise outside the selected replay tests and contribute no replay proof; preserve the current frozen compiler inputs while they run.
- [x] Finish enabled inline replay discovery on `hz4`: **exit 0, 31 tests / zero benchmarks**, and the nonzero-discovery consumer passes with count 31. Compilation took 84m15s; listing executes no tests. Retain the discovery candidate (`681842777` plus its original five overlays), rather than crediting subsequent SDK/formatting changes. The retained 1,877,992,232-byte test binary hashes to `6e45f928bfbd77f439d63b1335dc46be354c2df4bbd7f3aad179f04639360363`.
- [ ] Execute that exact retained binary through a normally admitted `rch exec --job` on `hz4`, checking its SHA-256 before executing the 31 replay tests. The installed CLI rejects `--job` combined with clean-overlay/source-baseline options; both rejected commands executed no test. The replacement uses the immutable compiled artifact hash and explicitly reports its original compiled-source identity. This cannot qualify later source changes; rerun the expanded current candidate afterward.
- [x] Finish the warm-cache seven-overlay broad clippy attempt: **exit 101 with 14 errors**. Manually repair the five simple predicates/ownership/sort findings in their authoritative files; preserve stable pattern precedence. Audit the migration dead-code findings against the standalone operator and existing public rollback inspection: expose/document the existing Linux transaction module so callers can name its already-public request type, preserving all transaction implementations and caller approval duties. Box only the oversized replay-success and OSV-updated enum payloads; update owned OSV callers. Group the unchanged private quarantine source/audit/risk inputs as signed-update provenance, retain lazy replay refusal, and collapse the directory-main predicate without changing order. No lint allowances, golden changes or test removals.
- [ ] Verify all those fixes with the expanded **15-overlay** all-target clippy recipe on its warm `vmi1152480` cache, pinned to the same compiler, node baseline and four sibling revisions. Then execute current inline replay, migration, npm-range, package-map and OSV/quarantine regressions, and the current native CLI tests. Earlier seven-overlay check/native runs keep their own source identities and do not qualify these eight additional files.
- [x] Expand unchanged direct UBS analysis to all **24 affected Rust files**, reverify all 350 helper hashes, retain normal built-in AST rules and every category/test, and verify all input hashes remain stable. The analyzer completes with **exit 1: 55 critical / 9,417 warning / 4,596 info**, not a clean scan. Exact rule/path/source comparison retains all previous 54 critical matches and adds one in the newly scanned `config.rs`: `spawn-token` inside a `#[cfg(test)]` child-process configuration fixture with deliberately dummy signature bytes. Inspect that context; no new defect is identified in the added match. Warnings remain unqualified, the stalled outer UBS wrapper remains incomplete, and this static scan supplies no native/Cargo proof.
- [x] Finish the expanded formatting check through RCH: **exit 1, 1,860 hunks**, retaining all broad existing differences. Manually correct its three newly authored layout findings (one literal ownership expression and both replay preparation matches), with no token/behavior changes. Both 15-overlay clippy requests expire in the normal queue (**103**, no lint execution); keep those losses and submit the formatted **18-overlay** candidate with normal capacity/pressure admission and the documented per-command priority setting.
- [x] Strengthen three pre-existing inline tests flagged by the enabled build, with manual test-only changes: compare actual empty/populated anti-entropy state digests against domain-separated expected preimages; require successful complete fault-free 1 MB delivery with exact identity/payload/ticks/counters, preserving the original two-second deadline; require all nine role fixtures to build/send/roundtrip and account for both messages as delivered or dropped, retaining original fault settings and legal drop outcomes. Remove swallowed errors and vacuous unsigned nonnegative checks; preserve domain-separator negatives. These source edits remain unexecuted and earn no runtime acceptance until the enabled current harness runs them.
- [ ] Execute the unchanged Unicode-label lab test before correcting its contradictory expectation: timer labels and raw event payloads deliberately preserve valid UTF-8 including NUL, while the old test accepts those labels and forbids NUL in raw payloads. Adjacent coverage explicitly requires hostile labels preserved. Obtain the source-bound baseline failure, then assert exact labels, monotonic/bounded ticks and JSON escaping/roundtrip without changing production or hiding failed operations. No lab code has been changed yet.

Npm source archives, registry metadata and raw real-executable observations are retained locally under `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-npm-specimens-20261022-ci9g4pcu/`. The npm corpus digest is `sha256:595ad0457ae8bce87af37d810423badb8d8318799d75c5bde6f3eb06aa4a974b`. The original published candidate remains SHA-256 `cd938fd67c8f506a0a49fd7347b8c736ff4a74035eaca47dcbab345eb5a06438`.

Qualified Python/source hashes: runner `5f07ebbb1d8ff1bbbf778d3cfb1fea318d8c4198cffa46c5386337632a8ebb7e`; runner tests `35b0040b0780e45f592e1d6c01c914294f60e4cc942be7133ab8a0a6e3f89c00`; corpus tests `829b981018c12965cd351b33ebf4ffcbde7111f75fe205c61b75576e8c534626`; npm manifest `431cbf87e41a705976324b75cbc7ac7237f973d494e48cc23f1238b81e1d2d25`; stream manifest `7f95e9f11bca5fdd5b7017a129d31be2e40cecc26a3a435ae5c286a921843502`.

### Reference reproducibility execution — 2026-10-22

This implements another bounded part of `bd-reality-20260923-26n9r.12`; it does not establish engine-source binding or improve native compatibility.

- [x] Recheck the live work graph, current source and disk admission. Only the generated migration marker was initially dirty; `sbh` still returned critical at 6.99% free. No Cargo invocation was started.
- [x] Record the actual candidate/Node/Bun `--version` output through bounded watchdog probes, with retained streams/receipts, UTC start/end, host/load/Python details and watchdog SHA-256. Failed, empty, invalid-UTF-8, incomplete and over-budget probes prevent project execution and PASS.
- [x] Implement optional `--baseline-report` reference hash/version pins. Changed references stop before fixtures; `--reference-change` requires an explicit nonempty reason and retains old/new identities. Neither a reason nor a previous verdict can approve a failed probe or case mismatch. Preserve the baseline bytes.
- [x] Detect binary changes after version probing and after the campaign. Keep `candidate_source_binding=not_established_by_this_runner`; a version string or adjacent source checkout is insufficient proof.
- [x] Preserve all original fixture IDs/expectations and denominators. Isolate probe artifacts under `.runtime-versions` so valid case names cannot collide with metadata.
- [x] Connect the project-runner regression suite to the existing watchdog CI workflow and its relevant path triggers. The job explicitly labels synthetic candidate/Bun adapters as orchestration evidence; actual GitHub job execution is unverified.
- [x] Exercise real published v0.2.0 / Node 26.8.1 / Bun 1.4.0: selected CommonJS and ESM cases pass, the selected buffer-validation failure remains FAIL. Node 24.20.0 replacement without a reason executes zero project cases; with a reason it executes all three and retains the same native failure. Full/selected counts remain 153/3 and the frozen corpus digest is unchanged.
- [x] Complete final Linux qualification: **48/48 PASS, zero skips**, Python 3.14.4 / Node 25.2.1 on `ovh-b`. Worker-emitted script/watchdog/test hashes exactly match local bytes. UBS exits 0, scans both touched Python files, and reports zero critical / 13 warnings; descriptor cleanup and bounded/validated JSON inputs were inspected, with no suppression. Workflow YAML and new job shell syntax parse; the live Beads graph has zero cycles. Publication is recorded by Git history and the final response.
- [ ] Remaining `.12` acceptance stays open: current-source native execution, full reference qualification, engine revision binding, default-profile score publication and scheduled native freshness. No task closure is supported by this tooling work alone.

Real-executable evidence is retained locally at `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-project-provenance-20261022-in3jcvx5/`. It is published-release evidence, not current-source capability evidence or independent certification. The final-code reruns retain a mixed native result and a refused reference change; the earlier explicit-change run demonstrates that accepting reference drift does not approve the native failure.

The final executed runner SHA-256 is `5f07ebbb1d8ff1bbbf778d3cfb1fea318d8c4198cffa46c5386337632a8ebb7e`; its test file is `2fcf49ba99c8371e8da4fed618f29bd20f3ed3e5351507a074e4cb98e53ed820`. A concurrent writer committed the preceding 47-test implementation as `bbfafb039` while this work was still running. Its four index entries remained byte-identical to the pre-work base, making the new commit appear staged for reversal; the index was preserved outside the checkout before reconciling only the root agent's reserved paths. The separately published `f44c95ad5` changes native Path integration tests/resolution; those Rust changes carry no native acceptance claim here.

### Follow-through execution — 2026-10-21

This pass resolves the earlier Beads and supported-host Python verification blockers. It does not resolve the required local Rust-build disk admission.

- [x] Recheck clean source, disk and guarded recovery. Disk remains critical: 6.44% free initially and 6.32% at final verification.
- [x] Diagnose actual RCH admission: generic jobs requested four cores; `RCH_BUILD_SLOTS=1` admits the small Python jobs. A conflicting source alias on `vmi1152480` was refused; normal RCH retry selected `ovh-b`. No worker configuration, priority, capacity or pressure threshold was changed.
- [x] Execute all 51 watchdog tests on Linux through strict RCH: **51/51 PASS, zero skips**, including TERM-resistant descendants, deadlines, quotas, cancellation, evidence-storage failures and stdin handling.
- [x] Execute the full project-runner suite on the same supported worker: **36/36 PASS, zero skips**. Python 3.14.4 and real Node 25.2.1 were reported by the worker. Its SHA-256 values for both scripts and both test files exactly match local committed `fa8464175` bytes. The candidate/Bun adapters in this suite remain explicitly synthetic; this proves orchestration, not native JS compatibility.
- [x] Cooperatively cancel only the redundant worker-pinned queued request through `rch jobs cancel`; observe its wrapper finish with exit 130 before admission. No peer job was cancelled or wrapper killed.
- [x] Use existing Python 3.14 with `cryptography 46.0.6`; install nothing. Honesty manifest **9/9 PASS including Ed25519**, ordinary claims census **7/7 PASS**, migration verifier tests **17/17 PASS**.
- [x] Re-execute signed migration verification: **FAIL, 20/22 checks**. Signature and deterministic recomputation pass; retained ratio is **1.2353x < 3x**, and `crates/franken-node/tests/fixtures/migrate/rewrite_shell_commonjs/package.json` no longer matches its frozen digest. Preserve both failures; no threshold, fixture or signed artifact was changed.
- [x] Preserve 12 original Beads family/canonical files outside the checkout, verify live hashes remain stable, and rehearse recovery on copies. The one committed WAL frame already matches its main-file page; owning-engine checkpoint returns `0|0|0`, integrity `ok`, 4,348 rows, and unchanged complete SQL-dump SHA-256 `b68d52d3956675ca20d62af957dc8413b3a30b6c37d7325d58ea785ab44cbba5`.
- [x] Rehearse reviewed schema **17 -> 19** in place, followed by ordinary import-only and exact-ID additive reconciliation. All 4,380 canonical issues match; existing comments, labels and dependencies survive. This is a recovery rehearsal, not an alternate store used to deliver project work.
- [x] Apply the same owning-engine checkpoint to the live family while holding `.write.lock`. The original main DB SHA-256 and canonical JSONL SHA-256 remain byte-identical after checkpoint. Apply the reviewed live migration token, retain its automatic backup and attestations, and pass post-migration integrity.
- [x] Import canonical JSONL: **32 created / 12 updated / 4,336 skipped**. Read-only exact-ID reconciliation then reports **no_changes / 4,380 equal**, 6,273 labels, 3,817 dependencies and 1,340 comments before new work notes. No manual SQL row change, JSONL rebuild, forced sync or committed-WAL discard was used. The engine's normal migration maintenance retires empty derived sidecars after checkpoint.
- [x] Verify real guarded writes: claim `bd-reality-20260923-26n9r.12` for BlueSpire, record compatibility/recovery/migration evidence, and flush through normal `br sync --flush-only` with strict policy and no errors.
- [x] Materialize uncovered positive work rather than duplicate broad owners: **`bd-f5b04.10`** captures authenticated module sources; dependent **`bd-f5b04.11`** independently verifies offline multi-file replay. **`bd-tenx3.6`** tracks actual production adoption, born blocked on qualified installation and real external operator evidence. Original owners remain open; no item was closed.
- [x] Extend the existing Beads ignore rules for journal/WAL/FEC/certificate/recovery scratch. Preserve the already-tracked per-machine migration marker as a local runtime change; exclude it from publication.
- [x] Recheck every original issue against the preserved pre-state, verify canonical/base equality, enforce the recovery ignore patterns, and pass `git diff --check`. Doctor now reports zero errors; recovery artifacts and three pre-existing blocked-status warnings remain visible. No source tests, goldens or thresholds changed in this pass. Publication is recorded by Git history and the final operator response.
- [ ] Current native compilation and the feature tasks above remain open. There are now 4,383 canonical issues, including the three newly tracked gaps; 54 are unfinished, and zero were closed in this pass. Do not use task counts as a capability score.

Recovery evidence is retained locally at `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-node-recovery-rehearsal-20261021-x0v8av6x/`: preserved original files under `frozen/`, checkpoint/migration rehearsals, live checkpoint receipt, hash-bound live plan/apply receipts and before-work reconciliation. This is self-verified operational recovery, not an independent product certificate. Normal br 0.7.6 export removes **211 obsolete machine-local `source_repo_path` fields** from portable JSONL; all original IDs, other untouched task fields, comments and relations were checked against the preserved pre-state. The portable `source_repo` fields are unchanged. No issue content was silently narrowed to force reconciliation.

UBS was invoked on all four publishable changed paths and exited 3: Markdown/JSONL/ignore files contain no supported scanner language, so zero files were scanned. This is not a scanner pass; no no-scan override was used. Validation here is the actual database integrity/reconciliation, JSONL semantic comparison, ignore checks and clean diff. The generated local migration timestamp remains uncommitted.

### Implementation and re-execution — 2026-10-21

The runner can now execute all **153 cases in 22 project manifests** with one `--corpus-dir` invocation. Previously the default command selected only the 42-case `corpus.json`, and 34 cases in seven other manifests were rejected for missing mandatory category metadata. Directory mode retains original case IDs and exact expectations, rejects an invalid member or duplicate ID before execution, retains a canonical combined corpus, and continues after individual failures. Tests include a positive two-manifest execution and a planted candidate mismatch that keeps the overall result failed while the following case still executes. Default single-manifest behavior and the historical compatibility-score denominator are unchanged.

Five fixture programs were corrected: diagnostic channel binding now uses AsyncLocalStorage; two directory probes now observe the actual closed-read operation; the pre-aborted sink waits for its actual error and close; and the Web sink bridge waits for terminal error propagation. **Every original `expected` object and all 153 IDs are unchanged**, verified against the committed pre-state. Six delegated manifests were independently checked to differ only by category additions; the root agent re-executed the checks rather than accepting agent agreement as proof.

The final real triad run used balanced policy, isolated per-runtime workspaces and isolated release XDG state. It retained all 153 results and exited 1: **11 PASS / 128 FAIL / 14 INCONCLUSIVE**, with no ERROR, cancellation or missing case. All three legs actually executed. This qualifies neither current `main` nor the historical 560-case headline. The published candidate was `franken-node 0.2.0`, binary SHA-256 `cd938fd67c8f506a0a49fd7347b8c736ff4a74035eaca47dcbab345eb5a06438`. The combined corpus digest was `sha256:9463c147651d184338913c90083eaeb05d4dbeec4d1e09d27b42b8688e308814`. Final evidence is outside the checkout at `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-node-execute-20261021-8xqtdo7w/release-v0.2.0-projects-final/`; its `report.json`, retained corpus and each runtime's `execution/` receipts/streams are the primary evidence. These temporary files are not durable release qualification artifacts.

Reference identity matters: Node 26.8.1 matched 151/153 frozen cases; `blob-iterable-part-snapshots` produced `67,67,68` instead of `65,66,68`, and Node's newer dotenv result used a null prototype and retained `__proto__`. Both original goldens were reproduced unchanged on official, checksum-verified Node 22.14.0. Node 24.20.0 reproduced the Blob difference and two internal pre-aborted Web-stream `closeCache.reject` failures. Bun 1.4.0 disagreed with Node on 14 cases; its installed Cellar directory is labelled 1.3.8, so the observed executable version, not the directory name, is recorded. No one reference version is qualified for the whole collection. The repaired sink bridge matched its original streams/status/files on all four real reference binaries.

| Post-change check | Observed result | Boundary |
|---|---|---|
| Pipeline/reference suite, Node 26.8.1 | 45 tests: 30 pass, 15 native tests skipped | All reference assertions pass; skipped native execution earns no credit. |
| Whole-collection reference test, Node 26.8.1 | 153 cases executed; 151 match, two retained version mismatches; suite exits 1 | Expands actual coverage to every manifest without regenerating goldens. |
| Project runner suite | 36 tests: 34 pass, two fail | Timeout/quota cleanup still hits denied `os.killpg` on this host; isolation fix and new collection/Unicode-digest tests pass. No expected failure was weakened. |
| Stream bridge suite, Node 26.8.1 | 3 tests: two pass, one native test skipped | Exact terminal error and file assertions pass. |
| Inline gate parser and preflight | 20 tests pass; preflight passes | Parser negatives reject zero tests. No Rust test discovery or execution ran. |
| Source-bootstrap suite | 27 tests pass | Local Git-fixture materialization/preservation behavior, not current-source compilation. |
| UBS on three touched Python files | Exit 0; zero critical, eight warnings | Descriptor lifetime and JSON parsing warnings were inspected; no blanket suppression, tolerance or no-scan override was added. Public digest comparison now uses `compare_digest`; wrong and Unicode pins still refuse before execution. |

Current-source Rust/native verification remains blocked: the latest `sbh check --need 20G` returned critical at 6.52% free, and a required-remote Python job failed every worker's preflight with exit 103. Guarded Beads claiming was retried and again refused with `SYNC_CONFLICT` because WAL-index recovery admission is unavailable. No issue was marked claimed, completed or closed through a bypass. The 51 unfinished canonical records remain unfinished.

The final self-review found no changed golden, relaxed assertion, new skip, hidden case drop or unsupported closure. The synthetic isolation adapter remains explicitly orchestration-only. This is self-verification; no independent verifier reviewed the complete implementation, and no current-native capability completion is claimed. The requested TODO/report is process tracking and earns no runtime capability credit.

This section supersedes the dated assessments below. Historical measurements are retained as history, not silently promoted to current results.

**Verdict:** substantial native runtime and trust infrastructure exists, and the source has advanced materially since the September assessment. The charter is not fulfilled. More fundamentally, there is no current, source-bound body of executed evidence that establishes how close it is. The installed-release experience, current source, and retained KPI artifacts describe three different states.

### Scope and evidence boundaries

- Read the complete root `AGENTS.md` (914 lines) and `README.md` (3,986 lines). Read the local ancestor guidance at `/Users/jemanuel/AGENTS.md` and `/Users/jemanuel/projects/AGENTS.md`. The required `/data/projects/AGENTS.md` does not resolve on this machine; no claim is made to have read that missing file.
- Inspected the charter, canonical plan sections, engine split, close-condition contract, claims registry, parity tracker, replay/environment/failure contracts, migration capture contract, current manifests, source bootstrap, release workflow, source modules, test wiring, and canonical issue inventory. There are 1,194 Markdown files: this is coverage of the vision domains and their authoritative implementation paths, not a claim to have read every auxiliary specification or every function.
- Source snapshot: node `5884ef52598fb27a74693efd2c0b7b8a179e9c0c`; sibling engine `6aae84f7451a43ebfa12ae1845de175f25ceeb80`. The engine is a live path dependency; those two hashes identify the inspected pair, not a successfully compiled pair.
- `sbh check --need 20G` returned exit 1, `status=critical`. No new Cargo build/check/clippy/test was started, and no local fallback was used. Fresh current-source compilation, native e2e, SDK tests, and performance remain unverified.
- Live release facts came from GitHub's release API. Downloaded only the Apple Silicon `v0.2.0` asset into a new temporary evidence directory, verified its published SHA-256, inspected the archive member, and ran that executable in an isolated workspace with its own `XDG_STATE_HOME`. No installation or existing operator state was changed.
- Evidence directory: `/var/folders/vt/n2xyn_s51b97_j3yh2qbqcnc0000gn/T/franken-node-reality-20261021-uxhdiqo7`. It contains gate stdout/stderr, downloaded release/checksum, isolated application state, release probe outputs, runner/watchdog test logs, and the bv snapshot. It is local evidence, not a published certification bundle. Private keys generated by `init` stay there and must not be published with a future evidence export.

### Charter scoreboard

| Promise | Evidence found or executed now | Assessment |
|---|---|---|
| At least 95% targeted compatibility | Re-ran the gate over `artifacts/13/compatibility_corpus_results.json`: **391/560 = 69.82%**, 169 failures; 11 families below 80%; core/high-value/edge floors all fail. The measurement is dated **2026-08-26**. | **UNMET in retained evidence; current rate unknown.** Do not describe 69.82% as a fresh measurement of October source. |
| Representative package/project compatibility | Current tree has **153 cases in 22 multi-file project manifests** under `fixtures/compatibility/projects/`, including package boundaries, streams, byte validation, MIME and filesystem composition. They are absent from the retained 560-case score. | **PARTIAL, with substantial new implementation work.** Reference qualification and current native execution are still required. |
| At least 3x migration throughput/confidence | Signed summary retains **1.24x**, CI95 **[0.9690x, 1.3511x]**. This is the September durable-rewrite measurement against scripted baseline codemods. Fresh verifier execution stopped on missing Python `cryptography`. | **UNMET historically; fresh cryptographic verification unavailable here.** The measurement is also a proxy for time-to-production and confidence. |
| At least 10x compromise reduction | Static gate passes **27/27** checks. The later `artifacts/adversarial/compromise_reduction_v2.json` is schema 2.1.0, dated Sep 29, and records **20 baseline / 20 native attempts, 20 / 0 compromises**, with typed outcomes and execution controls. The separate summary uses 20/2 and a 10x ratio. | **Bounded retained campaign evidence exists.** This is stronger than the old invalid campaign. It is not a fresh campaign or an independent production security result. |
| 100% high-severity replay artifact availability; full-fidelity time travel | Authenticated run/source/bundle code and native transcript replay exist. Local coverage explicitly cannot prove history after inventory deletion/rollback; interrupted runs remain uncertified; guest replay still refuses runtime module loading. | **PARTIAL / full population unproven.** Recorded-trace verification, guest execution, certified failure prefixes, and full application replay are different claims. |
| Friction-minimized install to safe workload | Published `v0.2.0` initializes and executes CommonJS and TypeScript here. It lacks newer replay/fleet CLI paths, and its safe-mode state did not stop a subsequent run. | **PARTIAL.** An available release is not qualification of the current README workflow. |
| Production adoption of at least three impossible-by-default capabilities | `artifacts/adoption/ibd_production_use.json` reports **0 production operators**, `pending`. Its gate passes because that pending state is honest. | **UNMET.** A passing honesty check does not mean adoption happened. |
| At least two independent replications | Replication gate fails, **20/24 checks**, **0 independently passing replications**. The retained report includes `example.org` evidence endpoints. | **UNMET.** Placeholder records do not establish external reproduction. |

The default close-condition gate exits 1 (**FAIL / L1 RED**). Consistency mode exits 0 because an honest RED is allowed to merge. Neither result is a fresh source-bound release certificate. Strict release-mode verification additionally requires an actual release-run URL, freshness limit, exact source pair and signed composite receipt; no such fresh campaign was supplied or manufactured in this audit.

### What the published executable actually did

GitHub Latest is **v0.2.0**, published **2026-10-04T14:27:49Z**, target commit `577591cf9a17ca65a6084242722b6feb28470797`. The inspected main is 233 commits ahead of that tag. GitHub supplies Linux x86_64, macOS arm64 and Windows x86_64 archives plus checksum files. Availability and names are verified; Windows/Linux installation and behavior were not tested here. The macOS archive SHA-256 is `a82a4d02adb91c53c5b77a6303e7a899b849aa859531e23b4d2231f23627eca5` and matched the published checksum. This checksum check is not an independent signer/provenance attestation.

| Isolated v0.2.0 probe | Observed outcome |
|---|---|
| `--version` | `franken-node 0.2.0`, exit 0. |
| `init --profile balanced --out-dir . --json` | Creates real config, keys and state; exit 0. |
| `run hello.js --policy balanced --json` | Native execution succeeds; prints the guest's hello output in the report. |
| CommonJS entry requiring a local module | Prints `42`, exit 0. |
| TypeScript entry with a `number` annotation | Prints `42`, exit 0. |
| Guest prints, then throws | Exit 1; JSON retains `before-throw` and the actual exception under `run-failure-effect-evidence/v2`. |
| `doctor --json` | Exit 0, `warn`; 9 pass / 3 warn / 0 fail. This is diagnostic behavior, not release readiness. |
| `verify transparency-log ... --public-key ... --json` | After the first two successful runs, verifies two entries and signatures, exit 0. This older verifier output does not establish the newer predecessor-authentication/checkpoint contract. |
| `run ... --capture-replay --json` | Exit 1: flag is unknown in this release. No guest was executed by this invocation. |
| `fleet serve --help` | Exit 2: `serve` is unknown in this release. |
| `safe-mode enter ... --json`, then `run hello.js --json` in the same directory | Enter reports active persisted state, exit 0. **The subsequent run also exits 0 and succeeds.** This is an installed v0.2.0 limitation; current source contains later admission/supervision checks. |
| Balanced guest attempts `fs.writeFileSync` | Exit 1, typed `capability denied: fs:write`; target file is absent. This probe produced no stored incident (`incident list` count 0). Do not represent it as a completed run-to-incident-to-replay demonstration. |

The source is not merely an external Node wrapper: these native executions and typed failures are real. Equally, executing hello or verifying an old signed ledger cannot stand in for the complete operator narrative.

### Current source: implementation and integration map

| Vision domain | Current code evidence | Status and remaining obligation | Existing owner |
|---|---|---|---|
| Native JS/TS execution and package loading | `ops/engine_dispatcher.rs`, engine dependency, project compatibility fixtures | **PARTIAL**. Current curated modules and first-class builtin work go well beyond September's six-package probe. Re-run representative pinned real packages; do not repeat the obsolete claim that no npm package can run. | `bd-f5b04`, `bd-reality-20260923-26n9r.4`, `.6`, `.12` |
| Resource budgets and invocation settings | Current dispatcher/config and replay settings | **CODE PRESENT; fresh execution unverified**. Do not repeat old 100k-instruction/console-truncation findings as current bugs. Prove caps and failure settings on the exact source pair. | `.5`, `bd-fkdzv` |
| Dependency trust admission | Shared dependency capture, trust store, dispatcher admission/rechecks | **CODE PRESENT** for reachable metadata and signed-state rechecks. Installed source authentication and undeclared dynamic code attribution remain distinct gaps. | `.1` history, `.13`, `bd-f5b04` |
| Trust cards, observations and reputation graph | `supply_chain/trust_card_registry_store.rs`, `trust_graph.rs`; `trust observe` dispatch and collector contract | **PARTIAL product integration**. Cards, graph and signed collector observations are real; native effect ledgers do not yet provide per-dependency trajectory attribution. | `.14`, `.15` |
| Revocation frontier | HMAC-authenticated frontier in the live store, profile admission | **CODE PRESENT**. Fresh `trust sync`/stale/adversarial-store/TOCTOU e2e proof is still required here. Balanced warns where strict refuses; broad fail-closed prose must preserve that distinction. | `.1` history, `.15` |
| Host I/O and process isolation | Dispatcher capability/SSRF/process paths and source tests | **PARTIAL**. Released fs-write refusal verified; Linux signed Bubblewrap spawning and its full corpus are not validated on this Mac. | `bd-91tpy`, `bd-at11s`, `bd-zyp0c` |
| Safe mode and live containment | `engine_dispatcher.rs:137`, `:3414`, `:6250`, `:9440`; scope and crash tests | **CODE PRESENT**, materially newer than release. Source has 250ms control polling and admission checks. Installed v0.2.0 failure remains a release qualification gap, not proof the current source lacks checks. | `.11`, `.16`, `bd-34d5` |
| Run-to-incident evidence | `main.rs:11291`, `:11544`, `:22421`; signed run/source bindings | **CODE PRESENT**, substantial progress over September. Fresh denial/exception/timeout/corruption e2e is needed; no new binary was built. | `.8` |
| Guest replay and certified failures | `ops/native_replay.rs`, typed engine-stop and environment contracts | **PARTIAL**. Public capture/re-execution paths and inline tests exist. Module loading is explicitly disabled (`native_replay.rs:21`); interrupted/uncertified execution is not replay-certified. | `.8`, `bd-f5b04`; proposed R3/R3T below |
| Counterfactuals | Production versus synthetic executor paths in `main.rs` | **PARTIAL**. Production re-decides recorded host effects; after divergence the path is assumed. It does not execute an alternate application path or certify identical original policy decisions. | `.8`, `.14` |
| Independent SDK / long-term verification | `sdk/verifier`, CLI LTV calls and trust-anchor checks | **CODE PRESENT**. Current SDK is broader and more precise than the old broken-bundle assessment; no fresh standalone compile or consumer test ran here. | `.7`, `bd-whxp` |
| Live fleet API | `main.rs:27745`; `control_plane/fleet_http_server.rs:539`; default feature in Cargo | **CODE PRESENT**. A real fastapi_rust listener on asupersync exists, with authentication and durable store. The old claim that fastapi is dev-only is false now. No current binary/socket campaign ran here. | `bd-tenx3.1`, `.14` |
| Fleet convergence versus quiescence | HTTP/file transports and native live-control path | **PARTIAL**. Polling, persisted application, effective policy revisions and session stopping have different completion semantics; an action acknowledgement is not all-session quiescence. | `bd-f5b04`, `bd-tenx3.1` |
| Migration | Rewrite transactions, rollback/cohort/store modules; rollout evidence checks | **PARTIAL**. Durable transformations and lockstep-gated stages are real. State-machine promotion does not by itself demonstrate production traffic rollout, global rollback or 3x time-to-production. | `bd-tenx3.3`, `.16`, `bd-v0lgc` |
| Durable storage / mandatory substrates | Published `fsqlite` is a normal dependency used by trust/fleet/evidence; live fastapi/asupersync server | **PARTIAL charter adoption**, not empty adapters. TUI presentation and typed-schema integration still need a precise production-path census; there are no signed waivers in `docs/governance/waiver_registry.json`. | `bd-tenx3.1` |
| VEF / ATC / DGIS / advanced primitives | Concrete domain modules plus feature gates and the README's reachability table | **PARTIAL / library-only in many cases**. Do not turn library models into claims of a live proof broker, ZK backend or federated deployment. `vef/proof_generator.rs` explicitly describes future ZK backends. No fresh reachability percentage was computed. | `.14`, `bd-f5b04` |
| Startup/tail performance and security overhead | Criterion/perf artifacts, source spans and budgets | **UNPROVEN against current incumbents here**. No fresh same-invocation Node/Bun/native benchmark or p99/security-overhead experiment ran. | `.10` |
| Source reproducibility and packaging | `scripts/bootstrap_source.sh`, `packaging/source-siblings.tsv`, `install.sh:446`; pinned release workflow inputs | **PARTIAL**, improved significantly. Bootstrap handles frankentui/fastapi/sqlmodel siblings and records source inputs. The README's two-checkout build layout is incomplete for the present Cargo graph. A path dependency alone pins nothing. | `.11`, `.12`, `bd-tenx3.4` |
| Public claims and doc consistency | Root README, claims registry, honesty census and executable gates | **PARTIAL**. README still says v0.1.0 is the only release, describes fastapi as dev-only in its diagram, and has old no-camouflage/no-crash-caller language alongside newer implementations. Later sections also correctly explain many boundaries. Fix from source/release evidence, not by reducing the charter. | `.15`, `.16`, `bd-tenx3` |

### Assessment-time verification results (before implementation above)

| Check | Result | What it proves |
|---|---|---|
| Default oracle close gate | **FAIL** | Retained L1 is RED; historical alias L2/linkage GREEN does not make the conjunction pass. |
| Consistency-mode oracle gate | **PASS** | The retained RED is honestly represented, not that the product is shippable. |
| Compatibility corpus pass gate | **FAIL**, 43/50 checks | Threshold, family/band floors and IFC-refusal census remain failed in the historical artifact. |
| Compromise-reduction gate | **PASS**, 27/27 | Retained report/source/evidence contracts satisfy this verifier; no new attack campaign ran. |
| Replication gate | **FAIL**, 20/24 | Zero independent passing reproductions satisfy the gate. |
| Adoption gate | **PASS**, 74/74 | Honest pending zero-user state and contract checks are accepted. |
| Honesty manifest check | **PASS**, 9 ok / 0 drift | Census counts are within tolerance. Live integration census 4,382 versus signed 3,756; inline 23,247 versus 21,621; validators 440 versus 437. Counts are not executed tests. Python explicitly skipped signature verification without `cryptography`. |
| Migration gate | **ENVIRONMENT ERROR** | Missing `cryptography`; no current signed-summary verification verdict was obtained. |
| Compatibility-gate unit tests | **PASS**, 51 tests | Python verifier behavior, not native compatibility. |
| Compromise-gate unit tests | **PASS**, 11 tests | Python verifier behavior, not a fresh compromise campaign. |
| Project pipeline tests, Node 26.8.1 | **FAIL**, 45 tests / 4 failures / 15 skipped | Reference fixture expectations disagree; all 15 actual-native tests skip without `FRANKEN_NODE_BIN`. |
| Same suite, Node 24.20.0 | **FAIL**, 45 tests / 4 failures / 15 skipped | Failure set is version-sensitive. A green fixture schema check is insufficient. |
| Project runner tests | **FAIL**, 32 tests / 3 failures | Timeout/quota paths encounter denied process-group signalling here; the third failure is the synthetic candidate fixture's missing expected file mutation. These are harness findings, not current native VM failures. |
| Runtime watchdog tests | **FAIL**, 51 tests / 4 failures / 6 errors / 2 skipped | Process cleanup/transport cases do not qualify on this execution surface. A direct normal invocation completed, while a timeout raised `PermissionError` at `os.killpg`; supported-host cleanup must be qualified without weakening containment. |
| Oracle tests via `unittest discover` | **0 tests** | This file uses pytest-style functions and pytest is absent. This invocation supplies no test proof. |
| Fresh Rust check/clippy/tests/fmt | **NOT RUN** | Required disk admission was critical. No product code was changed. |
| Report validation | **`git diff --check` PASS; UBS not applicable** | UBS exited 3 because this Markdown-only change contains no supported scanner language. No scanner ran and no no-scan override was used. |

The new environment replay docs list `cargo test ... native_environment_` and related filters. The definitions are inline in `ops/native_replay.rs`, while `lib.rs:2` excludes inline library tests unless `franken_node_inline_tests` is supplied. Their documented commands therefore do not, by themselves, establish execution of those named tests. Discovery and nonzero executed counts must be part of the proof. The dedicated inline workflow has the override, but its full lane is manual; a cheap preflight is not the full run.

GitHub's latest returned 100 workflow runs span Oct 7–8: **8 success / 75 failure / 17 cancelled**, all push events. This is an API sample, not a recomputed all-history success rate or proof of the Oct 21 source. No workflows were triggered or changed in this audit.

### Would finishing the existing work graph close the vision?

The canonical JSONL contains **4,380 issues: 4,329 closed, 26 open, 21 in progress, 4 blocked**. That is **51 unfinished records**, not a readiness score. `br --no-db dep cycles --json` reports no active cycles. Installed `bv 0.12.0` reports 4,266 issues and the same 51 unfinished records; its reduced population corresponds to the 114 closed records with issue types outside its four reported types. Treat its rankings as advisory, not as a replacement for the full JSONL census.

**No: completing the existing issue text mechanically is insufficient.** The broad owners cover most vision domains, but evidence must be earned on exact source/release pairs; incomplete proof cannot become completion by satisfying a static validator. Production adoption and independent replication also require real external outcomes. In particular:

1. `bd-28sz` plus `.12` must measure current native/package semantics and the actual intended profile, retaining Node/Bun disagreements. Advancing engine code without regenerating qualified evidence does not close this.
2. `.9`, `bd-rjc2m.21`, `bd-o776s` and `bd-z7bt` need executed named tests and supported-host cleanup proof, not only registrations, keyword scans, compile success or zero-test filters.
3. `.8` covers authentic incident production broadly, but no specific open task located in the inspected graph defines loaded-module source capture/replay closure. That is a concrete acceptance gap for full-fidelity application replay.
4. `.11`, `bd-34d5`, and `bd-tenx3.4` need installed-asset behavior. A Windows archive now exists; that fact neither proves Windows behavior nor closes the safe-workload path.
5. `bd-whxp` must obtain real independently verifiable replications. The closed adoption-instrumentation task created an honest pending metric; a concrete operational task to earn production adoption is still needed.
6. `bd-tenx3.1` must be revised around the current live fleet/storage integrations before execution; its older dev-only claims are stale. Finishing an obsolete description is not a useful definition of done.

### Bridge plan and proposed issue payloads

The following payloads were prepared during the assessment. After write recovery, the uncovered module-capture feature and its separate verification became **`bd-f5b04.10` / `bd-f5b04.11`**, and actual production adoption became **`bd-tenx3.6`**. R1/R1T/R4 continue under `.12`; R2/R2T, R5 and R7 remain with their existing owners. R0 is recorded as recovered in the parent reality thread. Do not duplicate those owners with new umbrella epics. No parent or capability is closable merely by editing this report or a golden.

**R0 — Restore canonical Beads write admission without losing the WAL (P1, operational prerequisite).** `br` can read JSONL, but attempted `br --no-db create` refused because database-family pending-merge authority could not be inspected. `br doctor` found DB 4,348 versus JSONL 4,380, with 32 records present only in JSONL. The documented `br doctor migrate-schema recover --json` also refused before opening because the WAL contains possibly committed, uncheckpointed frames. It explicitly forbids deleting/replacing the WAL or rebuilding this DB from JSONL. Preserve the entire family and current export; use an owning-engine, supported checkpoint/recovery path under exclusive authority, then reconcile all 4,380 records and comments/dependencies. Acceptance: verified retained pre-state, no lost WAL rows, exact JSONL ID/content reconciliation, successful guarded `br` mutation and explicit sync, no active cycles. No direct SQLite edits or alternate-store bypass.

**R1 — Qualify the expanded project references (P1; attach to `.12`).** Background: 153 current multi-file cases are not represented in August's score, and the 45-test pipeline suite has four reference failures on each of Node 24.20.0 and 26.8.1, with differing membership. Inspect `diagnostics-callback-package-store-scope`, `callback-dir-esm-shared-cursor`, `callback-dir-parse-failure-cleanup`, `web-preaborted-esm-sink-aborts-file`, and `web-preaborted-duplex-cleans-both-resources`. Define supported pinned real Node/Bun versions in the runner contract; bind their identities and hashes to results; diagnose application cleanup/event ownership separately from reference regressions. Repair faulty fixture programs only with independent expected-behavior evidence. Preserve case identities, denominators, raw failures and non-pass reference disagreements. Then connect qualified project evidence to per-profile compatibility reporting, with balanced as the default headline. Files: `scripts/project_compat_runner.py`, the named corpus manifests, `tests/test_project_compat_stream_pipeline.py`, and the parent compatibility producer/gate. Acceptance: no unexplained reference/golden mismatch is scored native PASS; complete streams/status/files and all selected cases are retained.

**R1T — Prove project/reference qualification on exact binaries (P1; depends R1).** Execute the full selected reference matrix and real native candidate on the exact node/engine revisions, using separate fresh workspaces for every leg. Cover Node/Bun disagreement, wrong goldens, file mutations, callback close/error ordering, aborts, expected nonzero exits, timeout, quota, setup failure and continuation after a failed case. Require executed native counts greater than zero and report skips explicitly. Retain manifests, binary hashes/versions, source closure, watchdog receipts, full streams and file hashes. A Node wrapper cannot serve as an independent Bun leg. Acceptance: independently reviewed reference expectations, current native verdicts for all selected cases, no hidden truncation, and gate failure on every deliberately broken evidence case.

**R2 — Make named replay tests discoverable and commands truthful (P1; attach to `bd-rjc2m.21` / `.9`).** Background: environment/failure replay is security-sensitive implementation, but the documented filters omit the library inline override. Inspect `lib.rs:2`, `ops/native_replay.rs`, replay docs, the dedicated inline workflow and `scripts/check_inline_lib_tests.py`. Choose a supported dedicated inline invocation or a genuine existing integration target; document its full features/RUSTFLAGS and RCH environment forwarding. Do not remove the global test gate casually or duplicate production modules into shims. Make the evidence record identify the named tests actually executed, exact source pair and failures. Acceptance: each published replay command discovers and executes its promised tests; zero matches cannot pass as completion.

**R2T — Verify test discovery and rejection of empty proof (P1; depends R2).** First list the environment, malformed-capture, debug-redaction, native replay and typed-stop tests with the actual dedicated configuration. Execute them remotely after disk/source admission. Verify the evidence consumer rejects zero selected tests, missing overrides, missing features, wrong source revisions and skipped-only runs. Unit proof must cover missing/empty/Unicode environment values, order/exhaustion/suffix mismatch, Secret-flow and authority restrictions, actual typed stops and forged stop text. Keep completed/failure/interrupted proof classes distinct. Acceptance: nonzero named executed counts, complete logs and source-bound results, plus negative evidence demonstrating the proof gate refuses emptiness.

**R3 — Capture the module-source closure for native guest replay (P1, engine-first feature; attach to `.8` / `bd-f5b04`).** Current replay explicitly refuses runtime module loading although real applications load modules. Add bounded capture at the authoritative engine loader for every actually loaded source and required resolution metadata, including package identity, CJS/ESM mode and relevant package.json/exports conditions. Product code must authenticate and bind this closure into its signed run/source/bundle without pretending old signatures covered new fields. Re-execution must resolve only captured modules, perform no live module reads, and retain the original capability/IFC and global effect ordering. Preserve existing capture size/count/depth limits or introduce an explicitly reviewed bounded schema; reject overflow, missing closure, contradictory identity, unknown module requests and unsupported historical captures. Do not grant ambient source/network authority to make replay succeed. Acceptance: authenticated offline multi-file replay under unchanged comparison scopes, with no live source fallback and no inflation of original-policy equivalence.

**R3T — Independently verify offline multi-file replay (P1; depends R3).** Use real CJS and ESM project captures, nested/conditional package resolution, JSON modules, cyclic loads, denied dependencies and a certified guest exception. After capture, alter or remove access to the original workspace using an isolated test arrangement; replay must still use captured bytes and repeat no filesystem/network/process effects. Tamper one module, resolution record, package identity, signature, effect order or transcript suffix and require refusal. Exercise capture overflow and absent historical fields. The consuming verifier must use independently supplied trust anchors. Acceptance: exact guest outputs/terminal state and supported witness comparisons, source closure authentication, negative-case refusals, and explicit unknowns for interrupted or incomplete recordings.

**R4 — Repair the triad-isolation harness fixture (P2; attach to `.12`).** `tests/test_project_compat_runner.py:85` intentionally creates a synthetic native adapter that prints values without executing JS. `test_three_runtime_workspaces_are_mutation_isolated` nevertheless expects `other-runtime.txt` from all three legs. The synthetic candidate never writes it, so the test fails even when its report says PASS. Give this explicit test double the required fixture mutation behavior or test the runner's isolation with correctly instrumented distinct adapters. Keep it labelled orchestration evidence; do not call it native JS/Bun execution. Acceptance: the existing exact file-isolation assertion passes, and intentional reference/candidate workspace leakage still fails. This is a harness-only task, not compatibility credit.

**R5 — Qualify the installed release against its promised workflow (P1, verification task; attach to `bd-34d5` / `.11`).** Freshly install the actual next candidate archives in clean supported Linux/macOS/Windows environments, retaining binary/source-pair provenance and independent integrity verification. Exercise first native safe workload, local/package modules, a denied write, exception output, safe-mode active-scope admission, live fleet listener/agent flow where supported, and supported run-capture/bundle/replay/SDK consumption. Explicitly test that safe-mode entry blocks a subsequent run: published v0.2.0 did not do so in this audit. Probe CLI availability before presenting newer source-only workflows as installed features. Preserve Linux-only process-spawn boundaries. Acceptance: all advertised installed paths succeed or refuse as specified on exact produced assets; current close-condition conjunction and fresh signed evidence pass; release docs identify the version each workflow needs. A checksum, version string or asset name alone cannot close this task.

**R6 — Earn production adoption rather than completing its instrument (P1, operational outcome; attach to `bd-tenx3`, coordinate with `bd-whxp`).** Preserve the zero/pending adoption artifact until real independent operators exercise the required capabilities. The existing artifact requires three operators and three capabilities per operator; retain that published contract unless the owner deliberately changes it. Define a bounded pilot record including deployed binary/source provenance, operator-controlled identity, actual signed decision/capture/fleet artifacts, verification under independently obtained anchors, conflicts/disclosures, and reproducible acceptance outcomes. No outreach or external message is authorized merely by writing this task. Acceptance: actual operator evidence satisfies the adoption contract; two independent replications separately satisfy `bd-whxp`; synthetic fixtures, example.org links and producer assertions cannot supply either outcome. R5 qualification precedes claims of a production-ready pilot.

**R7 — Refresh claims from a versioned evidence matrix (P2; attach to `.15` / `.16`).** Revise the existing README/claims/architecture documentation in place after R5 and source-path review. Correct v0.1-only release prose; distinguish v0.2 installed behavior from newer fleet/capture/safe-mode source; remove obsolete dev-only fastapi and no-crash-caller descriptions; preserve the nuanced current limits on profile warnings, counterfactual paths, metadata-only dependency identity, module replay and inventory completeness. Update manual source-build instructions to materialize the full pinned sibling set through the existing bootstrap. Acceptance: every externally visible workflow has a supported version, authoritative code path and appropriate executed proof; examples pass on that installed version, and remaining targets stay pending/RED. Do not change charter targets to make the table green.

Dependency order: **R0 permits canonical issue mutations. R1 -> R1T; R2 -> R2T; engine module capture -> R3 -> R3T; qualified current binaries and core proof -> R5 -> production-readiness/adoption claims in R6; R7 reconciles the resulting evidence.** R4 is an independent harness repair. Existing compatibility, migration, performance, substrate and replication owners remain necessary; this is not a replacement work graph.

### Ambition and refinement review

Three ambition passes changed the bridge from a list of local fixes into proof of complete user workflows: (1) exact source-to-installed-consumer closure across all required siblings; (2) authenticated application replay with module closure and explicit interruption limits; (3) independent pilot/replication outcomes and uncertainty-aware KPI interpretation. They preserve the charter's targets.

Five refinement passes checked: domain/owner coverage; unsupported proof-class upgrades; named executed tests and independent references; dependency order and duplication with existing owners; and preservation of signatures, history, case denominators and peer work. The resulting plan keeps the newly observed negative evidence, separates harness and product failures, and requires the appropriate companion proof tasks. It does not declare a passing test campaign or a finished product.

### Beads execution boundary and handoff

The skill's frozen creation template says: “Remember to ONLY use the `br` tool to create and modify the beads and add the dependencies.” Both attempted guarded creations failed before creating a record. The documented recovery attempt then refused the frame-bearing WAL; the final explicit `br --no-db sync --flush-only --json` also refused pending database-family authority. **No issue was created, edited, reopened or closed; no dependency was added; the Beads creation/refinement/updated-graph validation stages remain blocked.** The proposed payloads above preserve the work for `br` once the existing database family can be admitted safely.

No WAL/database file was deleted, replaced or rebuilt from JSONL. Existing source, artifacts, issue states and historical evidence were retained. No product code, gate, golden or release was changed. Current-source runtime proof remains gated by disk admission and an exact supported source/build environment. The next useful work is to restore safe tracker authority, execute the named core validation lanes, and obtain a current per-profile ecosystem measurement—not to create another count-based completion claim.

---

## Historical assessments (retained)

**Reality check date:** 2026-08-20
**Follow-up (2026-08-21):** scoreboard bound to corpus 86.43% RED; `run` e2e written; installer/CLI/revocation/10x-equal-attempts honesty landed. 95% corpus still open (`bd-28sz`: 76 remaining). Need 48 more passes (532/560). Do **not** recategorize `child_process` deny as pass. Residual mix: `child_process` 30 native-eval aborts (exit 1, 0 stdout); `crypto` 13 / `stream` 12 / `zlib` 3 / `tls` 5 / `cluster` 2 mostly franken-engine crash (exit 1); `events::0022` is franken_engine missing arrow lexical-`this` (29 vs 30 bytes: `arrow-this:true` vs node/bun `false`); `net::0005`/`net::0024` are **node vs bun reference disagreement** (franken matches node). Orchestrator cadence locked at **4 minutes**. Spawn note: signed Bubblewrap + aliases were already in the 2026-08-20 measurement (`e22e89fc4` ancestor of `cbc7a7bfb`). The 30 distinct stderr digests are the CLI wrapper plus **fixture filename** (`Engine execution failed… fix_command=…/<case>.js`), not 30 policy texts. Length bands ≈ 181/198/208 + filename. Guest JS never ran `console.log`. Product already grants `process_spawn` when admission is present (`resolve_capabilities_for_execution`) and maps spawnSync failures to a result object — so the measured abort is **before** that object is returned (HostCall `?` on `process_spawn`, capability/IFC/attempt, or facade holes: `stdin` is `Undefined`, `pid` hardcoded 1). PATH skip-insecure is landed; it does not recategorize deny as pass. Next honest engine cut: do not `?` `dispatch_process_spawn_hostcall` out of the eval (`baseline_interpreter.rs:41072-41073`); route HostProcess like builtins so spawnSync can return `{error}` and execSync `try/catch` can catch.
**Git HEAD:** `f74fa63b7` (`v0.1.0-709-gf74fa63b7`)
**Shipped GitHub release:** `v0.1.0` (2026-05-29) — **709 commits behind HEAD**
**PATH binary probed:** `/home/ubuntu/.local/bin/franken-node` (26 MB, BuildID `a3d9be2d`, dated 2026-06-08)
**Beads at check:** 4317 issues in `.beads/issues.jsonl` — 4269 closed / 13 open / 9 in_progress / 5 blocked (~98.8% closed)
**Method:** README + AGENTS.md + PRODUCT_CHARTER + PLAN_TO_CREATE_FRANKEN_NODE + CLAIMS_REGISTRY as the measuring stick; `crates/franken-node/src/**`, live CLI, oracle artifacts, and remaining beads as ground truth.

This document is the single in-place artifact for this reality check. Later ambition/refinement rounds revise this file; they do not spawn sibling plan docs.

---

## Executive answer

franken_node is a **real, large, fail-closed product-layer codebase** sitting on sibling `franken_engine`. It is **not** delivering the charter’s category-creation floor.

What exists today is an **evidence-producing operator shell**: trust cards, revocation gates, signed receipts, incident bundle integrity, local fleet state machines, a verifier SDK, a tree-sitter migration pipeline, and a native `run` path that *can* execute JS through franken_engine when the engine feature is present. That is substantial software.

What the README and charter use to claim a new runtime category is **not closed**:

| Charter floor | Reality on 2026-08-20 |
|---|---|
| ≥95% targeted compatibility corpus | Close-condition receipt: **2.5% (14/560)**. `artifacts/compat/corpus_pass.json` still `pending` with `observed_pct: null`. Bead `bd-28sz` is still **open**. |
| ≥3× migration throughput/confidence | Pipeline exists. The checked-in “3.15×” report is a **constructed 10-project cohort from 2026-02-21**, not a live measured gate. `CLAIM-002` is **pending**. Bead `bd-3agp` was **closed**. |
| ≥10× host-compromise reduction | Adversarial harness + `artifacts/13/compromise_reduction_report.json` exist; bead `bd-3cpa` is still **open**. Not an independently audited production campaign. |
| 100% deterministic replay for high-severity incidents | **Conformance-level integrity replay of recorded traces is real.** Live JS re-execution is explicitly *not* what `incident replay` does (README Limitations). |
| ≥3 impossible-by-default capabilities adopted by production users | **Zero production users** (AGENTS.md: early development, no users). Bead `bd-2hrg` was **closed with reason `done`**. |
| Dual-oracle close condition all GREEN | **Contradictory artifacts.** `close_condition_receipt.json` L1=**RED** (2.5%). `l1_product_verdict.json` L1=**GREEN** from a 3-effect proof-carrying chain, not the corpus. L2/release_policy GREEN files were **backfilled 2026-05-21** by a previous reality-check. |
| Install → first safe JS workload | `init` works. `doctor` runs. The probed PATH binary **refused `run ./app.js`** with `trust-native runtime unavailable` unless `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK=1`. Bead `bd-34d5` is still **open**. |

**Bead-completion illusion:** closing the remaining 27 open/in_progress/blocked beads would move the *tracked* charter gates if they are implemented honestly. It would **not** close the vision. Several load-bearing charter beads are already closed (`bd-2hrg`, `bd-1ps`, `bd-2tua`, `bd-26ux`, `bd-3agp`, `bd-1oyt`) while the corresponding product reality is still a model, a pending claim, or a contradictory artifact.

---

## Source documents (the promise)

| Document | Role |
|---|---|
| `README.md` (3330 lines) | Public operator promise: trust-native JS/TS runtime, installer, CLI, primitives, honesty manifest |
| `docs/PRODUCT_CHARTER.md` | Scope, 10 IBD capabilities, success metrics, substrate non-negotiables |
| `docs/plans/PLAN_TO_CREATE_FRANKEN_NODE.md` | Canonical ambition plan (22 tracks) |
| `docs/ROADMAP.md` | Supporting summary; engine-heavy; Phase 0 “in progress” |
| `docs/CLAIMS_REGISTRY.md` | Explicit pending vs verified claims (backfilled 2026-05-20) |
| `docs/honesty_manifest.json` | Census of test/fuzz/validator *counts*, not charter KPIs |
| `AGENTS.md` | Workspace/layout/process; confirms no-users, default features, rch, beads |

README Limitations (L3126–3170) is more honest than the Comparison table. The gap analysis treats **both** as part of the promise, and flags where they disagree.

---

## Architecture (what the code actually is)

```
CLI (crates/franken-node/src/main.rs, ~29k lines, #[cfg(not(test))])
  → Config::resolve (CLI > env > profile TOML > defaults)
  → domain modules in crates/franken-node/src/**
  → optional native franken_engine session (ops::engine_dispatcher)
  → signed receipts / trust-card JSON / replay bundles / run receipts
  → JSON or frankentui::Buffer-wrapped human text
```

**Workspace:** `crates/franken-node` (product), `crates/franken-security-macros`, `sdk/verifier`.

**Default features:** `engine` + `http-client` + `external-commands` only. Library modules `api`, `claims`, `federation`, `registry`, `verifier_economy`, `migration` (lib), `extensions` are feature-gated. The **binary still lists the whole CLI tree**; it `#[path]`-includes a subset of `api`/`policy`/`security` so default `franken-node` is usable without `--features extended-surfaces`.

**Core types:** `Config`/`Profile`, `TrustCard`, `Receipt`/`SignedReceipt`, `ControlEpoch`, `RemoteCap`, `ReplayBundle`, `EffectReceipt`, connector FSM.

**Substrate honesty vs charter §4:**

| Substrate (charter: mandatory) | Code reality |
|---|---|
| `franken_engine` | **Real, default-on** path deps. Native `run` uses `ExecutionOrchestrator`. |
| `asupersync` Cx-first control | **Optional** `asupersync-transport`. Default fleet transport is **file JSONL**. Product `run` is sync threads/processes. |
| `frankensqlite` for durable state | **In-memory adapter model** (`storage/frankensqlite_adapter.rs:1-6`). Live state is JSON/JSONL under `.franken-node/state/`. `fsqlite` is a **dev-dependency**. Beads `bd-2tua`/`bd-26ux` **closed**. |
| `frankentui` as console substrate | **Cosmetic:** copy already-rendered lines into `frankentui::Buffer` and read them back (`main.rs` `render_operator_surface_with_frankentui`). Not an interactive TUI. |
| `fastapi_rust` for HTTP control plane | **Dev-only.** `api/service.rs` is an in-process catalog; **does not bind a socket**. |

---

## Vision checklist

Status key: `WORKING` / `PARTIAL` / `STUB` / `UNPROVEN` / `NOT_STARTED` / `REGRESSED` / `WRONG_APPROACH`. Bead coverage is against **currently open/in_progress/blocked** beads, not historically closed ones.

| # | Goal | Source | Priority | Status | Bead coverage | Evidence |
|---|------|--------|----------|--------|---------------|----------|
| V1 | Trust-native JS/TS runtime that executes guest JS under policy | README TL;DR, Limitations L3153 | Core | PARTIAL | `bd-f5b04` (TNR epic, open) | Current source: `EngineDispatcher::dispatch_run` native path. PATH `v0.1.0` binary: `run ./app.js` failed closed (`trust-native runtime unavailable`). Host-effect runtime-of-record still incomplete. |
| V2 | Revocation-first execution before risky actions | README L109, CLAIM-006 | Core | PARTIAL | none remaining (impl exists) | Real modules `revocation_freshness` **and** `revocation_freshness_gate` with **two incompatible SafetyTier models**. |
| V3 | Per-extension trust cards (provenance, camouflage, revocation) | README L128, IBD-06 | Core | WORKING | none remaining | `supply_chain::trust_card`; live `init` wrote `trust-card-registry.v1.json`; CLAIM-005 verified. JSON files, not SQLite. |
| V4 | Deterministic incident replay + counterfactual | README L114–116, IBD-04 | Core | PARTIAL | none remaining for integrity; TNR for live re-exec | Integrity replay is load-bearing. Counterfactual default executor is **synthetic**. README admits this. |
| V5 | Migration autopilot audit→rewrite→validate→rollout | README L117, IBD-02 | Core | PARTIAL | no open 3× gate (`bd-3agp` closed) | Real CLI + tree-sitter. Not autonomous fleet rollout. 3× number is a constructed cohort. |
| V6 | Lockstep compatibility oracle ≥95% targeted corpus | Charter §5, IBD-07, `bd-28sz` | Core | UNPROVEN / far from target | `bd-28sz`, `bd-2djfa`, corpus residuals | Close-condition 2.5%. corpus_pass.json pending. Lockstep harness needs `strace` + Node/Bun. |
| V7 | Fleet quarantine with bounded convergence | README L136, IBD-05 | Important | PARTIAL | none remaining | Real SM + signed receipts over **local file transport**. Not a live multi-node HTTP/asupersync mesh unless opted in. |
| V8 | Signed extension registry (Ed25519 + provenance) | README L137, CLAIM-009 | Important | WORKING (local) | none remaining | Local FS registry. Not a public ecosystem registry. |
| V9 | Remote capability tokens | README L138 | Important | WORKING (local) | none remaining | Real Ed25519 tokens; local revoke set, not a remote cap service. |
| V10 | Verifier SDK independent of producer | README L139, IBD-10 | Core | PARTIAL | none remaining | Real crate; verifies artifacts, not guest JS / ZK. Honesty signer is harness key; `generated_at` is Unix epoch. |
| V11 | Operator doctor + workspace pressure | README L139 | Important | WORKING | none remaining | Live doctor after `init`: 9 pass / 1 warn / 1 fail (workspace pressure CRITICAL + RCH unavailable). |
| V12 | VEF / ATC / DGIS / BPET as production differentiators | README primitives table | Important | PARTIAL | residuals under TNR/compat | Real in-process models. ATC `atc/mod.rs` is a name fingerprint; VEF uses SHA-256 attestation backends (“future ZK”). |
| V13 | SSRF/egress policy as runtime default | README Network Egress | Important | WORKING on native `run` | `bd-y4t2i` crypto/egress residuals | Load-bearing `ssrf_gated_host_io` on engine host I/O. |
| V14 | Child-process spawn impossible-by-default + Bubblewrap | README Runtime Profiles | Important | PARTIAL | `bd-91tpy`, `bd-at11s` | Real signed opt-in. Linux-only. PATH binary process-spawn-readiness exists. |
| V15 | No `unsafe` | README L141 | Core | WORKING | honesty manifest | `#![forbid(unsafe_code)]`; honesty `unsafe_blocks=0`. |
| V16 | ≥3× migration velocity vs baseline | Charter §5, CLAIM-002 | Core | MEASURED 2.30×, PENDING | `bd-reality-20260820-w0fc6.2` (live gate landed) | Live signed gate (`artifacts/migration/throughput_delta.json`, target-release, 2026-08-22): pooled median 2.30x, CI95 [1.90x, 3.30x] — below 3x. Constructed `bd-3agp` cohort rejected by the gate. |
| V17 | ≥10× compromise reduction | Charter §5, CLAIM-003 | Core | UNPROVEN | `bd-3cpa` open | Report exists; gate bead still open. Not production-campaign evidence. |
| V18 | ≥2 independent replications | Charter / `bd-whxp` | Important | NOT_STARTED | `bd-whxp` open | Still ready-work. |
| V19 | Friction-minimized install → first safe production | Charter §5, `bd-34d5` | Core | PARTIAL | `bd-34d5` open | Installer exists. Homebrew unpublished (README honest). Shipped binary 709 commits stale. Live `run` failed without engine/fallback. |
| V20 | Dual-oracle close GREEN (L1 ∧ L2 ∧ release policy) | Charter §7, README Close-Condition | Core | WRONG_APPROACH (artifact theater) | `bd-1oyt` closed; `bd-3c2ie` exists as test drift | Conflicting GREEN/RED artifacts. L1 GREEN is not the corpus. |
| V21 | asupersync Cx-first for high-impact async | Charter §4 | Important | STUB/optional | no remaining bead | Optional feature; default file transport. |
| V22 | frankensqlite as the durable store | Charter §4 | Important | STUB | **NO open bead** (`bd-2tua`/`bd-26ux` closed `done`) | Adapter header says not the live store. |
| V23 | fastapi_rust live HTTP control plane | Charter §4 | Nice-to-have vs README fleet | NOT_STARTED | no remaining bead | In-process catalog only. |
| V24 | frankentui as operator surface | Charter §4 | Nice-to-have | STUB | `bd-e16uf` clippy blocker only | Buffer round-trip. |
| V25 | Public installer + current release | README Installation | Core | PARTIAL / REGRESSED vs HEAD | **NO open bead** | `v0.1.0` is Latest; HEAD is +709. PATH binary lacks `ltv`. Absolute `--out-dir` rejected. |
| V26 | CLI command surface matches README and does real work | README Command Reference | Important | PARTIAL | **NO open bead for honesty** | No `todo!()`. README now labels `verify module` as crate-src (not guest JS), `runtime lane/epoch` as ephemeral, `proofs workers restart` as request-unless-`--execute`, `ops health-check` as persisted session files. Remaining thin: live HTTP fleet (`activated:false` on file transport) and substrate stubs (frankensqlite/fastapi/frankentui). |
| V27 | Effective test coverage (not raw count) | README Testing, honesty manifest | Important | PARTIAL | `bd-rjc2m.21` in_progress; `bd-o776s` | ~3.8k default cargo tests. ~21k inline tests compiled **out** of default `cargo test`. |
| V28 | ≥3 IBD capabilities in production use | Charter §5 | Core | NOT_STARTED | **NO open bead** (`bd-2hrg` closed `done`) | No users. |

**Vision delivery (strict):** **3 of 28** fully `WORKING` (V3 trust cards, V11 doctor, V15 no-unsafe). Several more are `WORKING` at *local-library* fidelity but not at the charter’s production meaning.

---

## Live software probes (this session)

### PATH binary (`franken-node 0.1.0`, June 8 2026)

1. `franken-node --help` — full command tree **except `ltv`** (present in current `cli.rs`, absent from this binary).
2. `franken-node doctor --json` in empty cwd — fail-closed: `trust.registry_signing_key must be configured`.
3. `franken-node init --profile balanced --json --out-dir ws` (relative) — **success**. Wrote `franken_node.toml`, state dirs, synthesized registry signing key + API key, created `trust-card-registry.v1.json`.
4. `franken-node doctor --json` in that workspace — `overall_status=fail` (workspace pressure CRITICAL; RCH unavailable; bench summary missing). Config resolve **passed**.
5. `franken-node run ./app.js --policy balanced --json` with `console.log(...)` — preflight skipped (no package.json), then:
   ```
   Error: trust-native runtime unavailable: auto-mode fallback to node/bun requires
   explicit reduced-guarantee opt-in via FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK=1
   ```
   **No JS executed.**
6. `franken-node ltv --help` — `unrecognized subcommand`.
7. Absolute `--out-dir /tmp/...` — rejected (`Absolute paths not allowed for user content`).

### Source vs shipped

- GitHub Latest release = `v0.1.0` (2026-05-29).
- `git rev-list --count v0.1.0..HEAD` = **709**.
- One-line installer therefore cannot deliver current `run`/LTV/`--compat-preflight` behavior.

---

## Artifact theater (must not be treated as GREEN)

| Artifact | What it says | What’s wrong |
|---|---|---|
| `artifacts/oracle/l1_product_verdict.json` | L1 **GREEN**, 1538 tests passed (2026-07-12) | Evidence is 3 proof-carrying host effects (`fs.read`/`fs.write`/`http.request`), **not** the compatibility corpus. |
| `artifacts/oracle/close_condition_receipt.json` | L1 **RED**, 14/560 = 2.5% (2026-07-12) | This is the honest corpus number. Contradicts the GREEN file above. |
| `artifacts/oracle/l2_engine_verdict.json` | GREEN, 266 tests | Notes: created 2026-05-21 as README alias; timestamp `2026-05-21T00:00:00Z`. |
| `artifacts/oracle/release_policy_verdict.json` | GREEN | Notes: **“Backfilled 2026-05-21 from the reality-check bridge plan.”** |
| `artifacts/compat/corpus_pass.json` | `verdict: pending`, `observed_pct: null` | Still the May 21 backfill. Charter metric has no signed observed rate. |
| `artifacts/13/migration_velocity_report.json` | 3.15× on 10 archetypes | Constructed cohort timestamps in Feb 2026; CLAIM-002 still pending. |
| `docs/honesty_manifest.json` | Counts match README ±tolerance | Does **not** attest 95%/3×/10×. `generated_at` is `1970-01-01`. Signer is harness key. |

Previous reality-check (2026-05-20/21) made the gap *visible* in CLAIMS_REGISTRY and then **backfilled GREEN-looking oracle files**. That is the failure mode this skill exists to catch.

---

## Remaining beads vs vision (would completing them close it?)

**Currently incomplete (open / in_progress / blocked): 27.** Ready set includes the actual charter KPIs that were *not* false-closed:

| Bead | Tracks |
|---|---|
| `bd-28sz` | ≥95% compat |
| `bd-3cpa` | ≥10× compromise |
| `bd-whxp` | ≥2 independent replications |
| `bd-34d5` | install → first safe production |
| `bd-f5b04` | TNR runtime-of-record |
| `bd-2djfa` | lockstep executable + release-gated |
| `bd-y4t2i`, `bd-at11s`, `bd-zyp0c`, `bd-m8vaa.1`, `bd-387cw`, `bd-sul35` | corpus family residuals |
| `bd-rjc2m*` | verification scaffolding / inline tests / e2e |
| `bd-gc0ze`, `bd-famte`, `bd-pnmnu` | RCH/clippy/fmt farm health |

**If those 27 were implemented honestly:** V6, V17, V18, V19, V1 (TNR), V27 (inline tests) would get *a chance* to close. Compat residuals would raise the 2.5% floor; they would not magically hit 95% unless `bd-28sz` is treated as a hard release gate rather than another closed-with-artifact event.

**Would not close even if all 27 finish:**

| Gap | Why remaining beads don’t cover it |
|---|---|
| V16 3× migration | `bd-3agp` already closed |
| V20 dual-oracle contradiction | `bd-1oyt` closed; GREEN files are backfills |
| V22 frankensqlite live store | `bd-2tua`/`bd-26ux` closed `done` while adapter is in-memory |
| V21 asupersync default | optional feature, no remaining bead |
| V23 fastapi HTTP | not started; no remaining bead |
| V25 current release / installer freshness | no remaining bead |
| V26 CLI honesty (thin commands) | no remaining bead |
| V28 production IBD adoption | `bd-2hrg` closed `done`; no users |
| Dual revocation-tier models | no remaining bead |

**False-closed load-bearing beads (close_reason `done` or equivalent):** `bd-2hrg`, `bd-1ps`, `bd-2tua`, `bd-26ux`. `bd-3agp` has a longer close_reason citing artifacts that CLAIMS_REGISTRY still calls pending.

---

## CLI honesty (default binary, current source)

Every README family is in clap and dispatched. Zero `todo!()` / `unimplemented!()` in `src/`. The lie is **kind of work**, not missing handlers.

| Family | Verdict |
|---|---|
| `init`, `run` (engine), `doctor*`, `migrate*`, `trust*`, `remotecap`, `fleet` (file transport), `incident*`, `ltv*` (HEAD), `registry*`, `bench run`, `debug explain/evidence/trace` | Real local implementations + e2e in various feature sets |
| `verify lockstep`, `verify release`, `verify corpus` | Real |
| `verify module` | Looks up **this crate’s** `src/` module ids. Not JS module conformance |
| `verify compatibility` | Profile name parse **auto-PASS** |
| `runtime lane status/assign` | Fresh in-memory scheduler; discarded |
| `runtime epoch` | Two `u64` compare; not `ControlEpoch` |
| `proofs workers restart` | Emits `dispatch_restart_to_deployment_supervisor`; restarts nothing |
| `proofs queue status` | Snapshot/receipt report, not a live queue |
| `ops health-check` | New empty `SessionManager` → `active_session_count=0`; `pass` depends on compile-time git sha + ledger file |
| `trust scan --json` | Flag accepted, ignored |

Fleet/proofs/control-plane commands are **local-file or snapshot tools**. Implemented, not distributed SaaS.

---

## Gap report (actionable)

### Critical (vision undeliverable without these)

**G1 — Compatibility corpus far below 95% (V6)**
- Promise: Charter §5; README lockstep story.
- Reality: 2.5% in close-condition receipt; corpus_pass pending.
- Beads: `bd-28sz`, `bd-2djfa`, family residuals. **Partially covered.**
- Close condition: a **new** signed `artifacts/compat/corpus_pass.json` with `observed_pct >= 95` from a lockstep run that actually executed Bun + franken-engine (Node opt-in when real), plus release gate that fails closed on RED. Must **overwrite** the contradictory L1 GREEN file or stop treating it as the close-condition input.

**G2 — `run` is not a working “first JS workload” on the shipped path (V1, V19)**
- Promise: Quick Example step 7; Charter install-to-safe-workload.
- Reality: PATH binary cannot execute `app.js` without degraded fallback. TNR epic still open.
- Beads: `bd-f5b04`, `bd-34d5` cover product work; **no bead covers installer/release freshness**.
- Close condition: `franken-node run` on a machine that followed README install executes a fixture JS file through franken_engine, prints stdout, writes a run receipt, exit 0 — without `FRANKEN_NODE_ALLOW_DEGRADED_RUNTIME_FALLBACK`.

**G3 — Dual-oracle artifacts disagree; GREEN files are not the corpus (V20)**
- Promise: README Close-Condition; `doctor close-condition`.
- Reality: RED 2.5% vs GREEN 3-effect chain vs May 21 backfills.
- Beads: **NO_BEAD** (gate bead closed).
- Close condition: one conjunctive receipt; L1 **must** be the corpus metric; any GREEN L1 without `observed_pct` is a gate failure.

**G4 — Category metrics 3× / 10× / production IBD (V16, V17, V28)**
- 3×: closed bead + constructed cohort + pending claim.
- 10×: open bead + harness artifacts; not an external replication.
- Production IBD: closed `done`, zero users.
- Close condition: live measured gates with Wilson intervals (honesty manifest already has the interval helper) and fail-closed CI. No constructed archetypes.

### Major

**G5 — frankensqlite not the live store (V22)** — false-closed `bd-2tua`/`bd-26ux`. Trust/fleet/evidence still JSON.

**G6 — asupersync not the control substrate (V21)** — charter non-negotiable, optional feature.

**G7 — CLI / README mismatches (V26)** — thin commands listed as first-class operator tools.

**G8 — Dual revocation freshness models (V2)** — two enums, two clocks (seconds vs epochs).

**G9 — Default cargo test hides ~21k inline tests (V27)** — `bd-rjc2m.21` already tracks this.

**G10 — Release channel stale (V25)** — installer → v0.1.0; HEAD +709; no `ltv` on PATH binary.

### Minor / polish

**G11 — frankentui Buffer round-trip.** **G12 — fastapi not a server.** **G13 — Homebrew unpublished (README already honest).** **G14 — ATC module is a fingerprint.** **G15 — VEF is hash attestation, not ZK.**

---

## Bridge plan (close every gap)

Priority is **vision impact**, not ease.

### Gap #1: Compatibility floor — PARTIAL → WORKING

**Current:** 2.5% corpus; pending artifact; lockstep needs strace; L1 GREEN file is the wrong metric.
**Target:** Targeted high-value Node/Bun bands ≥95% on the lockstep oracle; `corpus_pass.json` has a real `observed_pct`; close-condition L1 reads that file only.
**Success criteria:**
- [ ] `franken-node verify lockstep` (or `ops compat-corpus-run`) produces a signed corpus result consumed by `scripts/check_compatibility_corpus_pass_gate.py`
- [ ] `artifacts/compat/corpus_pass.json` `verdict` is GREEN or honestly RED with `observed_pct` set
- [ ] `l1_product_verdict.json` cannot be GREEN while corpus < 95%
- [ ] Residual family beads (`bd-y4t2i` etc.) are either closed with passing families or explicitly excluded from the “targeted” denominator with a published exclusion list
**Depends on:** `bd-2djfa`, engine corpus work, `bd-28sz`.
**Would existing beads close it?** Partially. Need a new bead to **kill L1 artifact contradiction** (Gap #3).
**Complexity:** XL

### Gap #2: Install → `run` JS — PARTIAL → WORKING

**Current:** `init`/`doctor` work. Shipped `run` does not execute JS. TNR incomplete vs Node host APIs.
**Target:** README Quick Example steps 1–7 work on a clean Linux box from the installer **or** the README must stop implying that.
**Success criteria:**
- [ ] Hermetic e2e: install or `cargo build --release -p frankenengine-node`, `init --scan`, `run` fixture `console.log`, assert stdout + receipt
- [ ] Fail closed if engine missing; **no** silent Node fallback
- [ ] New release (or documented “source-only until v0.2”) so installer ≠ 709-commit-old binary
**Depends on:** `bd-f5b04`, `bd-34d5`, new release-freshness bead.
**Would existing beads close it?** Partially (TNR + install path). Not the stale release.
**Complexity:** XL

### Gap #3: Dual-oracle truth — WRONG_APPROACH → WORKING

**Current:** Three files, two L1 answers.
**Target:** Single definition: L1 = targeted corpus pass rate; L2 = engine-split + verifier independence; release policy = both consumed fail-closed.
**Success criteria:**
- [ ] Regenerating close-condition fails if L1 GREEN file and corpus_pass disagree
- [ ] May 21 backfill notes cannot satisfy `doctor close-condition` happy path
- [ ] `doctor_close_condition_e2e` expected GREEN only on a fixture that includes corpus ≥95% **and** proof-carrying effects (see `bd-3c2ie` drift)
**Would existing beads close it?** No.
**Complexity:** M

### Gap #4: 3× migration as a live gate — UNPROVEN → WORKING or honest pending

**Current:** Closed bead + constructed 3.15× JSON.
**Target:** Either (a) a real before/after study on N real repos with signed timing/confidence, or (b) CLAIMS_REGISTRY + README stop implying the number is earned.
**Success criteria:**
- [ ] `artifacts/migration/throughput_delta.json` emitted by a runner that times `migrate audit/rewrite/validate` vs a documented manual baseline on checked-in fixtures
- [ ] Gate fails if ratio < 3.0 **or** if inputs are the Feb 2026 archetype list
- [ ] Reopen/replace `bd-3agp` rather than cite it
**Would existing beads close it?** No.
**Complexity:** L

### Gap #5: 10× compromise — UNPROVEN → WORKING

**Current:** Harness + reports; `bd-3cpa` still open. Good.
**Target:** Keep `bd-3cpa` honest: ratio computed from a replayable campaign; Wilson lower bound; fail if baseline runtime unavailable (`fail_closed_baseline_unavailable` already in v2 artifact).
**Success criteria:** listed on `bd-3cpa`. Do not close on constructed 20/2 arithmetic alone.
**Would existing beads close it?** Yes, if not false-closed.
**Complexity:** L

### Gap #6: Live frankensqlite — STUB → WORKING

**Current:** In-memory model; JSON trust/fleet/evidence.
**Target:** Trust-card registry, fleet action log, and evidence-ledger spill go through `fsqlite` with crash-safe WAL (Tier 1), with a documented migration from JSON.
**Success criteria:**
- [ ] Adapter header no longer says “not the live store”
- [ ] `franken-node init` creates an fsqlite file; `trust scan` persists there
- [ ] Kill -9 mid-write leaves previous consistent snapshot (existing TempFileGuard semantics must hold on the DB)
- [ ] Conformance tests use the real engine, not only the model
**Would existing beads close it?** No (false-closed).
**Complexity:** XL

### Gap #7: CLI honesty pass — PARTIAL → WORKING

Fix or relabel: `verify module`, `verify compatibility`, `runtime lane/epoch`, `proofs workers restart`, `ops health-check` session count, `trust scan --json`.
**Success criteria:** each command’s `--help` and README row match the actual work; e2e asserts JSON fields that would have caught auto-PASS and ignored `--json`.
**Would existing beads close it?** No.
**Complexity:** M

### Gap #8: Unify revocation freshness — PARTIAL → WORKING

One `SafetyTier`, one clock, one gate on the `run` path and capability issuance.
**Would existing beads close it?** No.
**Complexity:** M

### Gap #9: Release freshness — PARTIAL → WORKING

Cut a release from current `main` **or** README installer section must say “prebuilt is historical; build from source.” Prefer a real release: checksums, cosign if claimed, `verify release` e2e against that dir.
**Would existing beads close it?** No.
**Complexity:** L (process) + M (docs/CI)

### Gap #10: asupersync / fastapi / frankentui substrate doctrine

Charter says mandatory. Code says optional/model/cosmetic.
**Target (ambitious, in-charter):** default fleet transport on `asupersync-transport` with file transport as explicit degraded fallback; fastapi binds a real control-plane socket behind `control-plane`; frankentui owns interactive doctor/fleet status, not a Buffer echo.
If the owner wants to de-scope, that is **off-charter unless the owner says so**. This plan does not de-scope.
**Would existing beads close it?** No.
**Complexity:** XL

### Gap #11: Inline tests + verification scaffolding

Already `bd-rjc2m*`. Execute, don’t replace.

---

## Ambition constraints (do not “simplify” the charter)

- Compatibility remains a **wedge**, not the destination. Hitting 95% without TNR host-effect receipts is still off-charter.
- 3× and 10× must be **measured with uncertainty** (Wilson interval already in verifier SDK). Point ratios of 3.15 and 10.0 with constructed denominators are not claims.
- Dual-oracle is conjunctive. Partial GREEN is a failed close, not a vibe.
- Substrate doctrine (asupersync, frankensqlite, frankentui, fastapi_rust) is not optional documentation. Either implement or the owner must amend the charter.
- Do not add compatibility shims. Do not wrap Node and call it franken-node `run`.

### Measurement design (charter KPIs)

Use the honesty-manifest pattern for **KPI** claims, not just test counts:

1. **Census** of the raw runs (per-case lockstep verdicts, per-repo migration timings, per-vector compromise outcomes).
2. **Signed manifest** binding recomputed ratio, README number, tolerance, evidence digest.
3. **Independent verify** via `frankenengine-verifier-sdk` with a non-harness trust anchor for anything published as a headline.

For 95% lockstep: Wilson lower bound of pass rate at 95% confidence must itself be ≥95% **or** the README must quote the interval, not a point. (95/100 is not enough; ~88.8% lower bound — the README already explains this.)

For 3× migration: ratio of medians on a frozen fixture set, plus a holdout repo not used to tune rewrites.

For 10× compromise: baseline must be **real Node or Bun** with the same payload; `franken_compromised=0` with `franken_attempts < baseline_attempts` is an apples-to-oranges trap already visible in v2 (`20` vs `10` attempts).

---

## Verification plan (after bridge work)

- [ ] V1: `run` fixture JS via engine, no degraded fallback
- [ ] V3: `trust scan` + `trust list --json` on a real package.json
- [ ] V4: `incident bundle --verify` + `incident replay` + counterfactual labeled executor
- [ ] V5: migrate audit/rewrite/validate on a fixture app with rollback
- [ ] V6: corpus_pass observed_pct ≥95 or honest RED
- [ ] V7: fleet quarantine/release/reconcile on file transport **and** documented multi-node path
- [ ] V10: `cargo test -p frankenengine-verifier-sdk` + honesty recompute
- [ ] V15: forbid(unsafe) still holds
- [ ] V16–V18: KPI manifests verify
- [ ] V20: close-condition conjunctive and consistent
- [ ] V22: fsqlite file survives kill -9
- [ ] V25: installer binary `--version` matches a tag within N commits of `main`
- [ ] V26: CLI honesty e2e
- [ ] V27: inline lane green or default `cargo test` runs them

---

## Dependency graph (new beads + existing)

```
existing: bd-2djfa ─┐
existing: residuals─┼─► bd-28sz (95%) ─┐
                    ┘                  │
G3 dual-oracle truth ──────────────────┼─► dual-oracle GREEN
existing: bd-f5b04 (TNR) ─┐            │
G2/G10 run+release ───────┴─► bd-34d5 ─┤
existing: bd-3cpa (10×) ───────────────┤
G4 3× live gate ───────────────────────┤
G6 frankensqlite live ─────────────────┤
G7 CLI honesty ────────────────────────┤
G8 revocation unify ───────────────────┘
existing: bd-rjc2m* (proof the proofs work)
```

Existing beads are **not** duplicated. New beads exist only for NO_BEAD / false-closed vision gaps.

**Created 2026-08-20 (epic `bd-reality-20260820-w0fc6`):**

| ID | Gap | Vision |
|---|---|---|
| `bd-reality-20260820-w0fc6.1` | G3 dual-oracle contradiction | V20 |
| `bd-reality-20260820-w0fc6.2` | G4 live 3× migration gate (`bd-3agp` false-closed) | V16 |
| `bd-reality-20260820-w0fc6.3` | G6 live frankensqlite (`bd-2tua`/`bd-26ux` false-closed) | V22 |
| `bd-reality-20260820-w0fc6.4` | G10 release/installer 709 commits stale | V25 |
| `bd-reality-20260820-w0fc6.5` | G7 CLI honesty | V26 |
| `bd-reality-20260820-w0fc6.6` | G8 unify revocation freshness models | V2 |
| `bd-reality-20260820-w0fc6.7` | G2 prove `run` executes JS without degraded fallback | V1 |
| `bd-reality-20260820-w0fc6.8` | IBD production-adoption KPI (`bd-2hrg` false-closed) | V28 |
| `bd-reality-20260820-w0fc6.9` | Charter substrates: asupersync / fastapi HTTP / frankentui (not Buffer echo) | V21, V23, V24 |

---

## What this reality check is not

It is not a claim that the last 4,269 closed beads were wasted. The product layer is dense, fail-closed, and unusually serious about receipts. It *is* a claim that **bead percentage is not vision percentage**, that **May 21 GREEN backfills are not close conditions**, and that **a 2.5% corpus with a GREEN L1 file is the central honesty failure**.

---

## Refresh 2026-08-23 (second full reality check — delta pass)

**Method:** same measuring stick (README + charter + CLAIMS_REGISTRY), fresh live probes only; no re-litigation of closed work without evidence. HEAD `v0.1.0-799-g457580b58` (branch `main`). Beads: 15 open / 10 in_progress / 5 blocked / 4,302 closed. Honesty manifest recomputed this session: **9 ok, 0 drifted** (`scripts/check_claims_manifest.py --check-honesty`; integration census 3,756→live 4,009; inline census 21,621→live 21,868; fuzz targets 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Velocity (bv): 22 closed last 7d, avg 1.27 days to close.

### What moved since the 2026-08-20 check (verified this session)

| Aug-20 gap | State today | Evidence |
|---|---|---|
| G3 dual-oracle contradiction (V20) | **CLOSED** (`w0fc6.1`). L1 is now bound to the measured corpus and honestly RED | `artifacts/oracle/l1_product_verdict.json` verdict=RED; `artifacts/compat/corpus_pass.json` verdict=RED, `observed_pct=86.43`, timestamp 2026-08-20T17:40Z |
| G4 constructed 3.15× cohort (V16) | **CLOSED as a live signed gate** (`w0fc6.2`). KPI itself still **unmet** | `artifacts/migration/throughput_delta.json`: pooled median 2.30×, bootstrap CI95 [1.90×, 3.30×], holdout 1.90×; CLAIM-002 pending (measured below 3.0×) |
| G6 frankensqlite in-memory model (V22) | **CLOSED** (`w0fc6.3`). Tier-1 WAL store live (trust-card registry authority switch + evidence-ledger durability) | close_reason cites `trust_card_registry_store.rs`, `trust_card.rs:1271-1427`; README State Layout now lists `trust-card-registry.v1.db` |
| G7 CLI honesty (V26) | **CLOSED** (`w0fc6.5`) | `verify compatibility` no longer auto-PASSes profile names; e2e regression anchors named in close_reason |
| G8 dual revocation models (V2) | **CLOSED** (`w0fc6.6`) | product SafetyTier canonical for run/remotecap; control-plane EpochFreshnessTier separated |
| G2 `run` cannot execute JS (V1) | **CLOSED at fixture level** (`w0fc6.7`) | `default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback`; host-effect runtime-of-record remains TNR (`bd-f5b04`) |
| IBD adoption false-close (V28) | **CLOSED as honest-pending KPI** (`w0fc6.8`) | `artifacts/adoption/ibd_production_use.json`: production_operator_count=0, verdict pending |
| Release staleness (V25) | Documented honestly (`w0fc6.4`); **not fixed** — Latest is still v0.1.0, now **799 commits** behind HEAD (was 709 on Aug-20) | `git describe` → `v0.1.0-799-g457580b58`; PATH binary still Jun-8 v0.1.0 |

Strict WORKING count moves **3/28 → ~7/28**: V3, V11, V15 (unchanged) + V20 (mechanism honest, verdict RED until corpus ≥95%), V22 (fsqlite store live), V26 (CLI honesty restored), V1 (fixture-level run proven from source; full host-effect TNR still open).

### Current corpus residual mix (76 failures; 484/560 = 86.43%; need 532/560 for 95%)

child_process 30 · crypto 13 · stream 12 · fs 6 · tls 5 · zlib 3 · net 3 · events 2 · cluster 2
(`artifacts/13/compatibility_corpus_results.json.failing_tests_tracking`).

Family bead coverage: child_process `bd-at11s`, crypto `bd-y4t2i`, stream `bd-m8vaa.1`, tls `bd-387cw`, net `bd-sul35` (37/40; incl. node-vs-bun reference disagreement 0005/0024 where franken matches node), cluster `bd-zyp0c`. **fs / zlib / events had zero dedicated beads anywhere (product or engine)** → created this session (see bead table below). zlib engine breadth exists as franken_engine `bd-znj5l` (Brotli) but no product-side residual tracking; events::0022 (arrow lexical-`this`) falls only under the broad franken_engine BRIDGE-14.11 umbrella.

### New regressions / risks found this session

1. **`bd-c6qum` (open, P1): 18 `fleet_cli_e2e` failures at HEAD** after the durable-transport switch (tests seed via `FileFleetTransport` while CLI now uses `DurableFleetTransport`). Active fix in flight by another agent (layers 2b–2d landed Aug 22–23; snapshot files modified in working tree).
2. **P0 inline-test hole persists:** `[lib] test=false` keeps ~21.9k inline tests out of default `cargo test` (`bd-rjc2m.21`, P0 in_progress). The dedicated lane now compiles but has runtime behavior-drift failures (`bd-o776s`).
3. Verification-scaffolding API-drift epic `bd-rjc2m` (~68 targets) with `.38`/`.39` G2G restore items in_progress and children `.7` (conformance cluster), `.17` (cargo-deny license) blocked.
4. RCH/farm health drags on validation: `bd-gc0ze` (stale fastapi-http dependency sync blocks validation), `bd-famte`/`bd-pnmnu` (clippy/fmt blockers).

### Beads created by this refresh (Phase 3a)

| ID | Gap | Vision |
|---|---|---|
| `bd-reality-20260823-fs-residual-yxlxu` | fs corpus residuals 6 (0021/0022/0023/0044/0045 engine crashes; 0030 output mismatch) | V6 |
| `bd-reality-20260823-zlib-residual-l6ev2` | zlib corpus residuals 3 (0004/0009/0016 engine crashes; cross-ref engine `bd-znj5l`) | V6 |
| `bd-reality-20260823-events-residual-uopqy` | events corpus residuals 2 (0017 engine crash; 0022 arrow lexical-`this` output mismatch) | V6 |

All three block `bd-28sz` (the ≥95% gate). No other NO_BEAD vision gaps found this pass: every other open gap maps to an existing bead (see tables above).

### Refinement notes (plan-space pass over this refresh)

* Do **not** reopen closed `w0fc6.*` items without new evidence; their close_reasons carry file:line + commit citations that checked out against the tree today.
* The release-freshness decision stands as documented-honesty (`README.md:286-294` warns Latest lags main). If the owner wants a real channel fix, cut v0.2.0 after `bd-c6qum` clears and corpus ≥95% — do not cut earlier just to shrink the number.
* `net::0005`/`net::0024` are reference-leg disagreement (franken matches Node); resolution is spec adjudication inside `bd-sul35`, not engine work.
* Keep the orchestrator cadence (4 min) and do not recategorize `child_process` native-eval aborts as pass — both reaffirmed by the Aug-21 follow-up and unchanged today.

### Live binary probes (2026-08-23/24, fresh release build)

Build: `cargo build --release -p frankenengine-node` → `/data/tmp/cargo-target/release/franken-node` (`CARGO_TARGET_DIR` is set workspace-wide; there is no in-repo `target/`). Binary `--version` → `franken-node 0.1.0`.

| Probe | Result |
|---|---|
| `init --profile balanced --json --out-dir .` | exit 0; state dirs + keys bootstrapped |
| `run ./hello.js --policy balanced` (auto) | **exit 1, fails closed**: resolves external `node`, refuses it ("cannot enforce franken-node's capability contract"). Correct refusal — but auto does **not** discover a sibling-built engine |
| same + `FRANKEN_NODE_ENGINE_BINARY_PATH=<target>/frankenctl` | **exit 0**, stdout `hello-from-engine`, run receipt written (`runtime=franken_engine exit_code=0 violations=0`) |
| `run … --runtime franken-engine` without engine bin configured | fail-closed: "requested runtime was not found; fix --engine-bin / FRANKEN_NODE_ENGINE_BINARY_PATH / [engine].binary_path" |
| `doctor close-condition --json` | **bug filed** `bd-9zrqh`: unconditional signing-key demand; its own fix_command then fails with "failed generating close-condition receipt" and empty stderr |

Interpretation: `w0fc6.7`'s closure is accurate for its tested scope (harness provisions the engine authority); the clean-room operator path still requires an explicit engine-binary handoff that README's "First safe workload (current source)" does not mention. That gap belongs to open `bd-34d5` (install → first safe production), not a reopen.

## Refresh 2026-08-29 (third full reality check — delta pass)

**Method:** same measuring stick (README + AGENTS.md + PRODUCT_CHARTER + CLAIMS_REGISTRY + the Aug-20/23 sections of this file), fresh live probes only; no re-litigation of closed work without new evidence. HEAD `v0.1.0-860-g77a8d48cc` (2026-08-28). Beads: 4,342 issues — 14 open / 11 in_progress / 4 blocked (~99.3% closed). Honesty manifest recomputed this session: **9 ok, 0 drifted** (integration census 3,756→live 4,014; inline 21,621→21,871; fuzz 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Release drift grew again: Latest `v0.1.0` is now **860 commits** behind HEAD (709 at Aug-20, 799 at Aug-23).

### Headline: the compatibility corpus REGRESSED 86.43% → 69.82%

`artifacts/13/compatibility_corpus_results.json`, regenerated 2026-08-24 (f50be1135) and 2026-08-26 (10ae1ddcd), now measures **391/560 = 69.82%** (bands: core 74.41%, high-value 62.40%, edge 82.14% — all below their 99/95/90 floors). The Aug-20/23 measurements recorded 484/560 = 86.43% with a 76-failure mix containing **no IFC failure class at all**. The current artifact has 169 failures; **97 of them share one new signature**: the franken-engine leg refuses at the lowering stage with `unauthorized flow detected at op N: TopSecret -> Internal` (information-flow-control / taint enforcement). Class census: engine_crash 120 (97 = IFC refusals), native_eval_abort 30 (child_process, unchanged), output_mismatch 18, reference_disagree 1. IFC refusals span ≥12 families (buffer 14, url 8, querystring 7, os ~5, cluster ~5, crypto ~12, events ~13, fs ~13, stream ~8, http ~3, timers 1, tls ~1, zlib ~5). Same-corpus-hash anchor: v0.1.0 scores 68.21% — the regression puts main ~1.6 points above the May baseline, erasing ~6 weeks of measured compatibility progress. Suspected cause: default-on IFC enforcement landed engine-side between the two measurement windows. This is the charter's central collision (security hardening vs the ≥95% floor); per the Aug-21 reaffirmation these failures must NOT be recategorized — benign flows must declassify correctly, malicious flows must still refuse.

**Beads created this pass (all three block `bd-28sz`):**

| ID | Gap | Vision |
|---|---|---|
| `bd-kx70h` (P0, bug) | IFC lowering-refusal regression: 97 corpus cases; triage incl. measurement-protocol hygiene; engine-first fix per split contract + CI class tripwire | V6 |
| `bd-bwa93` (P2, task) | Failure-ownership sweep: os/http non-IFC residuals (4 known) + durable "every corpus failure has an owner" invariant | V6 |
| `bd-klpse` (P2, bug) | `artifacts/compat/corpus_pass.json` (86.43 @ Aug-20) + CLAIMS_REGISTRY CLAIM-001 stale vs 69.82 measured; `check_compatibility_corpus_pass_gate.py` never reads `corpus_pass.json` — zero drift detection | V6/V20 |

### What else moved since 2026-08-23 (verified this session)

| Aug-23 item | State today | Evidence |
|---|---|---|
| fleet_cli_e2e 18 failures (`bd-c6qum`) | CLOSED; close-reason quality high | 50/50 green at HEAD d9c0973b4, serial + -j4, verified 10+ runs |
| doctor close-condition keyless bug (`bd-9zrqh`) | CLOSED | 22fbc4f7b; `close_condition.rs:709-746` + `main.rs:6685-6731`; regression test named |
| 10× compromise gate (`bd-3cpa`) | CLOSED as gate implementation; CLAIM-003 correctly still pending | c3dddc6f1: bench targets registered, gate 27/27 PASS; v2 artifact uses raw bun/node baselines (20 attempts each) with `fail_closed_baseline_unavailable=true`; registry retains "do not treat 20.0× as verified" — gate-vs-claim separation coherent, no reopen |
| Inline-test hole (`bd-rjc2m.21`, P0) | Still open; dedicated lane now compiles but has runtime behavior-drift failures (`bd-o776s`) | V27 remains PARTIAL: ~21.9k inline tests still not effectively executed anywhere |
| Migration 3× (`bd-v0lgc`) | Still open | live gate measured 2.30× (CI95 [1.90×, 3.30×]) vs ≥3.0× charter floor |
| CLI honesty (`w0fc6.5`) | **Re-verified HOLDS** by a fresh static audit this session | zero `todo!`/`unimplemented!`/`TODO` in src; `verify compatibility` profile targets fail closed (`main.rs:28186-28203`); proofs restart paper-labeled with `ERR_PROOF_RESTART_NO_EXECUTOR` (`ops/proof_pipeline.rs:486-497`, `main.rs:8775-8782`); counterfactual `--model production` bails (`main.rs:20008-20015`); `trust sync` performs a real OSV POST with offline warnings; all six spot-checked primitives 1,289–6,977 lines, REAL |
| Release channel (`w0fc6.4`, documented honesty) | Drift worsened 799 → 860 commits; correctly still blocked on corpus ≥95% per the Aug-23 decision | `git describe` |

### Vision checklist deltas (Aug-20 numbering)

- **V6 (compat ≥95%): REGRESSED** — 86.43% → 69.82%. Honest RED everywhere: `l1_product_verdict.json` RED, close-condition receipt `failing_dimensions=[L1_product_oracle]`, `corpus_pass.json` RED-but-stale (bd-klpse).
- V1 (`run` executes JS): fixture-level proof stands (`w0fc6.7`); this session re-ran the named e2e via rch — result recorded below. Clean-room operator path still owned by `bd-34d5`.
- V20 (dual-oracle truth): mechanism still honest; summary-artifact staleness is the one new crack (bd-klpse).
- V27 (effective coverage): unchanged PARTIAL; the P0 remains the single largest coverage hole in the repo.
- Strict WORKING count: **~7/28, unchanged** (V3, V11, V15, V20-mechanism, V22, V26, V1-fixture-level). The corpus regression blocks any further climb until the IFC class is resolved.

### Run-proof re-verification (2026-08-29 session)

**Live operator probe PASS (new positive delta vs 2026-08-23).** Using the shared debug binary built 2026-08-29 03:28 (`/data/tmp/cargo-target/debug/franken-node`, newer than HEAD 77a8d48cc) in a clean `/tmp` workspace with the standard sibling `franken_engine` checkout:

1. `franken-node init --profile balanced --json --out-dir .` → `franken-node/init-cli/v1`, exit 0.
2. `franken-node run ./hello.js --policy balanced` (auto runtime) → **exit 0, stdout `hello-from-engine`, `runtime=franken_engine exit_code=0 violations=0 auto_quarantined=0`**, signed run receipt written under `.franken-node/state/execution-receipts/2026-08-29/…`. **No `FRANKEN_NODE_ENGINE_BINARY_PATH` and no degraded-fallback env were needed** — auto mode discovered the sibling engine, which FAILED on the identical probe 2026-08-23. The clean-room gap that `bd-34d5` tracks has narrowed to release-channel freshness (debug/source builds auto-discover; the shipped v0.1.0 installer artifact still cannot).
3. `doctor close-condition` keyless in that workspace → no signing-key demand (bd-9zrqh fix live); fails with a precise missing-artifact path (`artifacts/section/10.N/gate_verdict/bd-1neb_section_gate.json`) plus a fix_command naming the checkout requirement.
4. `verify compatibility balanced` → **fail closed**, `status=fail exit_code=1`, contract_version 3.0.0, message: profile is not a compatibility claim (w0fc6.5 behavior confirmed live).

The named regression e2e (`default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback`) was re-launched this session via `rch` and produced **no verdict**: the remote build was SIGKILLed (`exit=137`, rch "likely resource exhaustion") on worker hz4 after a 60-minute cold compile, with no higher-capacity worker available — an infrastructure failure, not a product regression. V1 fixture-level evidence for this refresh therefore rests on the live probe above (newer-than-HEAD binary, full operator path, auto-discovered engine) plus the standing `w0fc6.7` proof; the named test should be re-run once a warm target or a larger worker is available.

### Refinement notes (Phase 5 pass, this session)

- `bd-kx70h` amended after review: triage must first confirm the Aug-20 run's measurement protocol (policy_mode, reference runtime, corpus hash) before attributing the drop to engine code; only the code-delta component is engine work. Same-corpus-hash v0.1.0 anchor suggests protocol comparability, but verify from the Aug-20 run record.
- Generalization candidate noted, deliberately not bead-ed yet: the IFC tripwire (bd-kx70h task 3) could become a generic failure-class-census tripwire (any class-census shift beyond a registered floor fails CI). Decide when the IFC tripwire lands.
- Known-and-accepted (again): `docs/TODO_ULTRA_DETAILED.md` sections 1–5 are stale (QuickJS-evaluator TODOs contradict the no-bindings rule; ROADMAP "Phase 0 In Progress" is wrong). Flagged Aug-20; still not worth a bead against the P0 — a 10-minute truth pass is warranted once the corpus is green.
- Cross-repo bead references: `failing_tests_tracking.investigation_bead_id` `bd-8qvy6` lives in the franken_engine bead store, not this one — intentional, but triagers must look there.
- Beads-store transient corruption during this session's concurrent creation: auto-export hit `database disk image is malformed` plus a JSONL write-lock timeout; the first bd-kx70h write was lost and re-created. Store now verifies clean: 4,342/4,342 coverage, dirty 0 (pre-repair snapshot in `.beads/recovery_20260829_realitycheck/`).

### Work-session addendum (2026-08-30, gap-closure pass)

- **IFC regression is PARTIALLY healed at HEAD.** Probing formerly-failing fixtures through the exact corpus franken-leg command (`run --console-only --policy legacy-risky --runtime franken-engine --engine-bin <self>`): buffer/0005, fs/0021, url/0003, zlib/0004 now PASS; **events/0017 and querystring/0002 still refuse** with `unauthorized flow detected at op N: TopSecret -> Internal (reason=no_lattice_or_declassification_path)` — confirmed live, residual class is real and owned by `bd-kx70h`/`bd-bwa93`. Both residual fixtures share the shape `require(<builtin>)` + method calls.
- **Reproduction gap (measurement provenance):** `ops compat-corpus-run --require-node-reference` with real node v22.2.0 + bun 1.4.0 (same corpus hash `compat-corpus-v2-7b86e9d2…`) on this host measured **60.36% (338/560)**; dyad (bun-only) 60.0% — the committed 69.82% (Aug-26) does NOT reproduce. The artifact pins no host, engine build, node/bun versions, or fixture-tree revision, so cross-host reproduction is unverifiable. Probe evidence: `artifacts/13/compatibility_corpus_results.repro-probe-20260830.json` (untracked by the gate; canonical artifact unchanged). Until provenance is pinned (bd-kx70h), treat single-run corpus deltas of ~±10 points as measurement uncertainty, not engineering signal.
- **bd-klpse delivered:** `scripts/check_compatibility_corpus_pass_gate.py` now fail-closes on `SUMMARY_OBSERVED_PCT_MISSING/_MISMATCH`, `SUMMARY_STALE_VS_RESULTS`, `SUMMARY_TIMESTAMP_UNPARSEABLE`, `SUMMARY_GREEN_BELOW_FLOOR`, `SUMMARY_VERDICT_INCONSISTENT` (self-test 6/6 incl. stale/mismatch/GREEN-below-floor vectors). `artifacts/compat/corpus_pass.json` synced to the measured 69.82 (honest RED, Aug-26 provenance); CLAIMS_REGISTRY CLAIM-001 synced with the reproduction caveat. Gate already wired into CI (`.github/workflows/dist.yml`) and imported by `scripts/check_oracle_close_condition.py` (which re-derives L1 from the results artifact, unaffected).

## Refresh 2026-09-22 (fourth full reality check — delta pass)

**Method:** same measuring stick (README + AGENTS.md + PRODUCT_CHARTER + CLAIMS_REGISTRY + prior sections of this file), fresh live probes and verification runs. HEAD `v0.1.0-1114-g08447a0aa` (branch `main`). Beads: 4,349 total issues — 4,314 closed (99.20%), 12 in_progress, 19 open, 4 blocked (35 active/non-closed). Honesty manifest recomputed this session: **9 ok, 0 drifted** (`scripts/check_claims_manifest.py --check-honesty`; integration census 3,756→live 4,106; inline census 21,621→live 22,421; fuzz targets 146/146; validators 437→438; `unsafe_blocks=0`; Ed25519 harness-key signature ok). Release drift reached **1,114 commits** past `v0.1.0`.

### What moved since 2026-08-29 (past 254 commits)

1. **Captured Migration Execution & Failure Reducer Landed:** Pinned manifest-selected test execution (`docs/MIGRATION_CAPTURED_EXECUTION.md`, `scripts/migration_validation_runner.py`), pipe transport binding, and execution-backed line reduction (`scripts/minimize_migration_failure.py`, 58/58 unit tests passing).
2. **Supervised Invocation Watchdog:** External process execution supervision with fail-closed timeout evidence and bounded binary stdin/stdout streaming (`test_runtime_invoke_watchdog.py`).
3. **Supply-Chain Dependency Graph Capture:** Entrypoint-wide JavaScript/TypeScript source dependency graphs, package-map target selection (`package.json` `exports`/`imports`), contained package symlink resolution, and TypeScript erasure verification without loading erased types.
4. **Closed-World Offline Replay:** Pinned closed-world module source registry and private source capsules for replay exclusively from captured observations.

### Standing Vision Gaps (Status at 2026-09-22)

- **V6 (Targeted Compatibility Floor ≥95%): REGRESSED at 69.82%.** Canonical artifact records 391/560 (69.82%); 97 cases fail on engine IFC lowering refusals (`bd-kx70h`, P0). Cross-host reproduction measured 60.36%. Dual-oracle close condition is honestly RED (FAIL).
- **V16 (Migration Velocity ≥3×): UNMET at 2.30×.** Live signed gate (`artifacts/migration/throughput_delta.json`) measures pooled median 2.30× (CI95 [1.90×, 3.30×]), holdout 1.90× (`bd-v0lgc`).
- **V25 (Release Distribution Freshness): REGRESSED.** Latest tag `v0.1.0` is 1,114 commits behind HEAD. Promised Windows x86_64 prebuilt is not built in CI (`bd-tenx3.4`).
- **V27 (Inline Test Hole): PARTIAL.** ~22,421 inline tests remain disabled from default `cargo test` (`[lib] test=false`, `bd-rjc2m.21`, P0); dedicated inline lane compiles but has behavior drift (`bd-o776s`).
- **Charter Substrates (Charter §4): PARTIAL.** `asupersync` remains opt-in, `fastapi_rust` is an in-process catalog, `frankentui` is a Buffer copy-echo (`bd-tenx3.1`).
- **V28 (Production IBD Adoption): NOT_STARTED.** 0 production operators (`artifacts/adoption/ibd_production_use.json`).

## Same-day verification pass (2026-09-22, independent delta pass)

**Method:** fresh-eyes audit layered on the refresh above, same measuring stick; four parallel read-only code investigations (CLI surface, run/engine path, test reality, stub scan) plus live probes (honesty manifest recompute, beads DB read-only, oracle artifacts, corpus census, git-history forensics). Every headline number in the refresh above was **independently re-verified and confirmed**: honesty manifest 9 ok / 0 drifted live; corpus 391/560 = 69.82% with failure census 120 engine_crash (~97 IFC `TopSecret -> Internal`) / 30 native_eval_abort / 18 output_mismatch / 1 reference_disagree; L1 RED, L2 + release-policy GREEN-by-backfill; release drift 1,114 commits; 35 active beads; ~7/28 strict WORKING.

### New findings (all bead-ed or fixed this pass)

1. **bd-kx70h task-1 forensics COMPLETE — the 86.43 → 69.82 comparison is confounded.** Git history of `artifacts/13/compatibility_corpus_results.json`: the Aug-20 run (f74fa63b7, 86.43%) used reference legs **node v20.19.4 + bun 1.3.14**; the Aug-24/26 runs (f50be1135, 10ae1ddcd, 69.82%) used **node v22.2.0 + bun 1.4.0**. Corpus hash, policy mode, topology, and product runtime id are identical; only the reference legs changed. Scope limit: the confound can only affect output_mismatch (18) + reference_disagree (1) classes — the 97 IFC refusals + 30 native_eval_abort cases (≥150/169) are franken-leg intrinsic and stand regardless. Combined with the 2026-08-30 same-protocol repro at 60.36%, provenance pinning in the artifact is mandatory before any delta is treated as signal. Recorded as a bead comment on `bd-kx70h`.
2. **`api/service.rs` fabricated-claims fix landed (bd-svc-honesty-v4yy9).** `http_server::dispatch_http_request` hardcoded `"live_control_plane": true` on `/v1/fleet/status` and returned a canned empty `/v1/trust/cards` 200. Fixed: fleet status now reports the fleet-CLI contract vocabulary (`transport=file live_control_plane=false activated_source=file_transport_not_live`); trust cards now load the real durable registry (`TrustCardRegistry::load_authoritative_state`, `TrustedFile`) relative to the workspace and fail closed with a typed `urn:franken-node:error:trust-registry-unavailable` 503 when absent — never a fabricated list. Three inline tests pin the markers (`http_server_fleet_status_reports_file_transport_not_live`, `http_server_trust_cards_fail_closed_without_registry`, `http_server_trust_cards_read_real_registry_store`).
3. **README/CLI drift fixed (bd-readme-cli-drift-4l0ex).** Command Reference rows added for `migrate rollback`, `migrate rollout` (both real at `cli.rs:652/658`, handlers `main.rs:30944/31025`), and `doctor process-spawn-readiness` — CLI is now 72/72 documented. The "run by a default `cargo test`" claim corrected in three places: flagship CLI e2e need `--features test-support`, most `bd_*` conformance families `--features advanced-features`, so a default-feature run executes only the ungated subset; counts updated to the live census (~4,100 registered / ~22k inline).
4. **`docs/TODO_ULTRA_DETAILED.md` sections 1–5 banner added** (the 10-minute truth pass flagged since Aug-20): marked as historical pre-engine-split notes; QuickJS/V8 items contradict the charter no-bindings rule; delivered §5 items (CLI, structured logging, release pipeline) called out as stale-unchecked.
5. **`fuzz/regression/` thinness bead-ed (bd-fuzz-regression-corpus-f28ac):** 5 crash inputs vs 146 registered targets; the "regression case forever" claim is thin — corpus workflow + CI rot-check + seed campaign tracked there.

### Infrastructure notes this pass

- The named `default_run_executes_fixture_js_through_embedded_engine_without_degraded_fallback` re-run and a fresh binary build were **RCH-blocked** (queue 0/16 slots; one worker failed with missing `rustc`; local fallback refused by policy). V1 evidence therefore still rests on the 2026-08-29 live probe + the standing `w0fc6.7` proof; re-run when the farm drains.
- A second verification attempt (canonical inline lane for the `api/service.rs` honesty tests, `bd-svc-honesty-v4yy9`) also failed **before reaching this crate**: the sibling `franken_engine` lib itself did not compile (concurrent `fetch_update` → `try_update` API migration in flight engine-side) and the worker additionally SIGKILLed rustc (OOM) on the debug lib compile. The service.rs changes are fmt-clean but their three new inline tests are **written, not yet executed**; the bead carries the exact lane command to run once the engine tree compiles again.
- `br` was mid schema-migration (v17→v19) by a concurrent agent during part of this pass; beads were read directly from SQLite read-only and mutated only after the migration settled.


## Refresh 2026-09-23 (fifth full reality check — first LIVE-BINARY pass)

**Method.** Earlier passes mostly read code and artifacts, and the Sep-22 pass could not build a binary because RCH was blocked. This pass **built a fresh release binary** and ran it:
- **Builds:**
  - release build via `rch exec` (fell back to local), 19 min;
  - franken_node HEAD `8b8b45311` (`v0.1.0-1136`);
  - franken_engine `0dce0e734`, 2026-09-23;
  - a scratch crate that depends *only* on `sdk/verifier`.
- **Probes run against the binary:**
  - 20 realistic programs, 8 real npm packages (installed with bun), and ~30 language/runtime micro-probes, all compared against node v22.2.0;
  - the adversarial payloads;
  - the incident pipeline into the SDK;
  - hyperfine timings against node and bun;
  - a fresh full compatibility-corpus triad run.
- **Parallel read-only audits (7):**
  - plan-vision extraction;
  - trust-gate wiring;
  - incident/replay/SDK provenance;
  - the host-API surface;
  - CI/release reality (gh API);
  - a bead-compliance audit of closures since Aug-19;
  - a module-reachability census.
- **Artifact handling:** all probe artifacts live in the session scratchpad. **No committed artifact was regenerated.**

Beads: 4,352 total, 4,319 closed (99.2%).

### Executive answer

franken_node is a large, carefully fail-closed **trust/verification control plane** attached to a **native JS runtime that today can execute only single-file, self-contained, small programs**. Specifically:
- no module loading;
- a 100k-instruction budget on the default profile;
- a frozen clock;
- several silent miscompiles.

The strongest claims made since Aug-29 do not survive running the software:
- the ≥3× migration pass traded away crash durability;
- the ≥10× compromise campaign never executed franken-node;
- the revocation freshness gate is dead on every default install;
- the independent SDK cannot read the CLI's incident bundles;
- CI has never produced a green `cargo test` of the crate.

One real positive: **compatibility on the corpus recovered to 87.32%** (from 69.82% in the stale committed artifact). The containment primitives (fs write, SSRF, eval, sandbox escape) genuinely block when a payload actually runs.

### Live probes (release binary; `FRANKEN_NODE_ENGINE_BINARY_PATH` set, because default auto mode fails — see G-C below)

**Runtime surface.** Of 20 realistic programs under balanced `--console-only`, 3 matched node cleanly, 2 more exited 0 with divergent output, and 15 failed.

| Probe | node | franken-node |
|---|---|---|
| `console.log("hello")` | ok | ok (strict: exit **92**, verdict `Sandbox`) |
| `require("./lib/math")` | `rel:5` | `ambient authority violation: access to 'require' requires effect 'fs.read'` |
| lodash / ms+semver / dayjs / uuid / commander / express (node_modules) | all ok | **0/8**, same ambient-authority violation |
| `const EventEmitter=require("events"); new EventEmitter()` | ok | refused (only the destructured `{EventEmitter}` pattern works) |
| `.mjs` importing `./lib/esm_math.mjs` + `fs` | ok | `unauthorized flow … TopSecret -> Internal` |
| `run dirapp` (package.json main) | — | `Failed to read application source … Is a directory` |
| `(async()=>{ await null; … })()` | ok | `type error: expected function, got string` |
| `[...generator()]` | `1+2` | `expected iterable, got object` |
| `class A{#x=1; get x(){return this.#x}}` | `class:1` | **`class:this.#x`** (silent wrong answer, exit 0) |
| `for(i<20000) s+=i` (balanced) | ok | `instruction budget exhausted: 100000/100000` (legacy-risky: 50k iterations ok, 100k fail) |
| `Date.now()` | real time | `1767225600000` every run |
| 1,500 × `console.log` | 1,500 lines | last 1,000 only (first 500 silently dropped) |
| `console.log("before"); throw …` | prints `before` | stdout empty |
| `console.log({a:1},[1,2,3])` | `{ a: 1 } [ 1, 2, 3 ]` | `[object Object] 1,2,3` |
| `const s="password"; console.log(s.length)` | `8` | IFC refusal `Secret -> Internal` |
| `process.env.HOME` / `process.exit(3)` (legacy-risky) | ok | ambient-authority violation (every profile) |
| strict: `JSON.stringify` / `path.join` | ok | `capability denied: builtin:JsonStringify` / `builtin:PathJoin` |
| `TextEncoder`, `structuredClone`, `globalThis` | defined | `undefined` ×3 |
| fetch `169.254.169.254` metadata | blocked | blocked (strict `capability denied: net:request`; balanced SSRF) ✓ |

**Security gates.**
- **Revocation freshness (G-A).** Aging the `.db` registry 400 days still passes `--policy strict`. Adding a 400-day-old legacy `.json` makes the same run block (`RF_STALE_FRONTIER … age 34560000s > max 300s`). The gate reads the mtime of a file `init` never writes (`main.rs:294`, `:18566`).
- **Adversarial payloads run directly.**
  - `fs.writeFileSync`: denied under strict/balanced, **PWNED under legacy-risky**.
  - metadata SSRF: blocked.
  - `/etc/passwd`: refused under all profiles.
  - `eval`: denied under all profiles.
  - The containment is real.
- **The ≥10× bench's franken leg reproduced exactly** (`run --policy strict --json .`): "cannot launch external runtime node", or with the engine configured "Is a directory". **It never executes guest code** (G-D).

**Incident pipeline.**
- A **hand-authored** `evidence.v1.json` produced a signed bundle.
- `incident replay` → `matched=true`.
- `incident counterfactual --policy strict` → executor `synthetic`, `changed_decisions=1, severity_delta=-47`.
- The scratch crate using only `frankenengine-verifier-sdk` → `bundle::deserialize`/`verify`/`validate_bundle` all fail: `missing field artifact_path`. **The SDK cannot read CLI bundles** (G-E).

**First run (G-C).**
- A fresh build's default `run hello.js` fails. Auto mode finds no sidecar `franken-engine`/`frankenctl` binary, falls back to node, and refuses node. Yet the sidecar is never executed; it is a pure presence gate.
- `trust scan --deep --audit` needs `FRANKEN_NODE_REMOTECAP_KEY` **and** a `remotecap issue` token in `FRANKEN_NODE_TRUST_SCAN_REMOTECAP_TOKEN`, neither documented.
- `incident bundle` needs a hand-generated fleet signing key.
- `doctor` detects none of these, and exits 0 while reporting `overall_status: fail`.

**Performance (never measured before).** hyperfine, same host (load average ≈ 50):
- `run hello.js`: **164.3 ms ± 6.0**.
- node: 36.7 ms ± 1.9, so franken-node is **4.5× slower**.
- bun: 188 ms (this host's bun is anomalous).
- The ~130 ms fixed per-run overhead dominates: a 50k-iteration loop costs the same as hello.
- HC-003 ("within 10% of Node") is "verified" by `scripts/check_latency_gates.py`, which only greps spec keywords.

**Compatibility corpus (fresh, scratch).**
- `ops compat-corpus-run --require-node-reference`: node v22.2.0 + bun 1.4.2 + engine `0dce0e734`, `legacy-risky`, 9m42s.
- **489/560 = 87.32%** (committed artifact: 69.82% @ 2026-08-26).
- Remaining failures:

| Family | Failures | Cause |
|---|---|---|
| child_process | 30 | Bubblewrap containment-unit abort |
| crypto | 14 | 13 IFC `Secret -> Internal` |
| stream | 21 | 12 IFC `TopSecret`, 3 output mismatch, rest type errors / `require` |
| cluster | 2 | |
| fs | 2 | |
| http | 1 | |
| net | 1 | |

- IFC refusals: 97 → 26.
- Bands: core 88.98 (floor 99), high-value 84.0 (95), edge 94.64 (90).
- **+43 passes are needed for 95%.** child_process (30) + crypto IFC (13) is exactly that minimum.
- Caveat: the corpus is 540 single-file micro-probes averaging 8.8 lines, with **zero** module/package usage, measured under `legacy-risky`. It **cannot detect** any of the ecosystem failures above.

### Audits (agents; each finding spot-verified by hand where marked ✓)

- **G-B ✓ Migration ≥3× bought with durability.** `rewrite_transaction.rs` `sync_all` count went 7 (35881aa36) → 1 (608f2088d) → 0 (318ac9360), while the ratio went 0.45× → 2.50× → 5.67×. 608f2088d's message describes `touched_dirs` batching that **does not exist** (`rg touched_dirs` → 0). The header still promises a durable journal. bd-v0lgc closed on it. CLAIMS_REGISTRY CLAIM-002 still says 2.30× pending; the section-13 artifacts say 5.56/5.67×.
- **G-D ✓ ≥10× campaign invalid.** All 20 franken cases in `compromise_reduction_v2.json`: `exit_code:1, blocked:false, contained:false, typed_errors:[]`.
- **G-F ✓ CI.**
  - Last 7 days: 1,924 runs on main, 14.3% success, **82% failure**. No run has ever compiled and tested the crate successfully, and none runs `franken-node run`.
  - 10 PR-only gates (claims-manifest, mutants, inline-lib-tests, no-self-compare, verification-target-compile, …) have **never run**: the repo has **0 PRs**.
  - `connector-conformance.yml` has had invalid YAML since Feb (0/3,468). README Quick Example Smoke: 0/1,340.
  - `dist.yml` never succeeded; the v0.1.0 assets were hand-uploaded. `install.sh --method source` never clones frankentui.
- **G-G Reachability.**
  - About **42.7%** of 360,816 non-test product lines is reachable from the default binary (module-level upper bound); 35.2% is compiled-but-unreachable; 22.1% is opt-in only.
  - Unreachable: DGIS, BPET, VEF (except evidence_capsule), `replay::time_travel_engine` (referenced by nothing), and `control_plane::{audience_token, fork_detection, control_epoch, epoch_transition_barrier, divergence_gate, key_role_separation}`.
  - Also unreachable: `security::copilot_engine` (IBD-8) and `tools::reputation_graph_apis` (IBD-9).
  - bd-137 compat-gate APIs are implemented **three times**.
- **G-H README scenario is fiction on CLI paths.**
  - No typosquat or publisher-age computation anywhere.
  - Camouflage/GradualCreep is reached only from tests.
  - `migrate audit` never runs `trust scan`.
  - No CLI path writes the evidence ledger; `run` receipts are hash-only.
  - The per-profile camouflage threshold is a constant.
  - Safe-mode crash-loop auto-entry has no callers.
  - SSRF `monitor` blocks like `block`, and the FAQ's `mode = enforced|report-only` key does not exist (silently ignored).
- **G-I Bead compliance** (load-bearing closures since Aug-19): 3 FALSE-CLOSED (w0fc6.9, bd-3cpa, tenx3.3) and 4 OVER-CLAIMED (w0fc6.7, tenx3.4, tenx3.5, v0lgc; v0lgc is effectively false-closed per G-B); the rest (w0fc6.1/.2/.3/.4/.5/.6/.8, bd-klpse, bd-9zrqh, readme-cli-drift) VERIFIED statically.
  - tenx3.3 rollout: `lockstep_verified = true` hard-coded (`migration/rollout.rs:415`); confidence never computed; the "signature" is a SHA-256 digest.
- **G-J Unmapped plan goals** (never assessed by V1–V28):
  - performance budgets and HC-003;
  - benign false-positive rate;
  - engine pinning (a bare path dependency, which contradicts charter §2 rule 4; README:2506 claims "pinned");
  - L2 as a differential oracle (today a GREEN backfill; engine Test262 is 3 precomputed vectors);
  - IBD-8/IBD-9;
  - isolation tiers;
  - confidence half of 3×;
  - per-band floors;
  - convergence latency.

### Vision checklist deltas (Aug-20 numbering + new items)

| # | Goal | 2026-09-22 | **2026-09-23 (live)** |
|---|---|---|---|
| V1 | `run` executes guest JS | WORKING (fixture) | **PARTIAL.** Single-file only; 0/8 npm; 100k budget; default auto fails on a fresh build |
| V2 | Revocation-first execution | "unified" (w0fc6.6) | **REGRESSED.** Gate dead on default installs; fails open |
| V3 | Trust cards | WORKING | **PARTIAL.** Cards seeded; deep/audit fails by default; all `medium`; re-scan never refreshes |
| V4 | Replay + counterfactual | PARTIAL | **INTEGRITY-ONLY.** Certifies hand-authored evidence; counterfactual synthetic; no run→incident capture |
| V6 | ≥95% corpus | REGRESSED 69.82% | **RED 87.32%** (fresh, legacy-risky, single-file corpus) |
| V10 | Verifier SDK independent | PARTIAL | **BROKEN for bundles.** Cannot parse CLI `.fnbundle`; unkeyed "signature" |
| V11 | Doctor | WORKING | **PARTIAL.** Misses every first-run blocker; exit 0 on fail |
| V16 | ≥3× migration | UNMET 2.30× | **WRONG_APPROACH.** "Pass" via fsync removal; proxy metric |
| V17 | ≥10× compromise | UNPROVEN | **INVALID MEASUREMENT.** Franken leg never executes |
| V25 | Release freshness | REGRESSED | **REGRESSED.** 1,136 commits; `--method source` broken; dist never green |
| V27 | Effective coverage | PARTIAL | **NOT PROVEN.** No green CI `cargo test` ever; 10 gates never ran |
| V29 | Performance vs Node / budgets | *unassessed* | **FAIL.** 4.5× node on hello; HC-003 keyword gate |
| V30 | Module loading / ecosystem | *unassessed* | **NOT_STARTED** on the run path |
| V31 | Language correctness | *unassessed* | **FAIL.** Silent miscompile + async/generator failures; no Test262 |
| V32 | Primitives reachable from product | *unassessed* | **~43%** reachable; flagship primitives are islands |
| V33 | Engine pinning + corpus provenance | *unassessed* | **ABSENT** |
| V34 | Evidence ledger written by decisions | *unassessed* | **ABSENT** on CLI paths |

**Strict WORKING count:** V15 (no unsafe) still holds. V13 (SSRF on the native path) and the containment primitives are verified live. V1, V3 and V11 are downgraded from the Sep-22 count, and V2 has regressed. The honest summary: the *verification/trust machinery* is broad and often real, but the *runtime it is supposed to govern* cannot yet run the ecosystem the charter targets.

### Answers to the reality-check questions

1. **What works today.**
   - Single-file programs using a pattern-matched subset of 16 builtins, with real SSRF, capability, sandbox and eval containment and signed host-effect ledgers.
   - `init`, `migrate audit`, plain `trust scan`, `incident bundle`/`replay` as integrity tools, and `doctor`.
   - A recovered 87% single-file micro-corpus.
2. **What does not work.**
   - Module loading and npm packages; non-trivial compute (instruction budget); a real clock; several ES2015+ features.
   - The strict profile for ordinary code.
   - Revocation freshness on default installs.
   - CLI→SDK bundle verification; run→incident capture.
   - Deep trust intelligence (typosquat, publisher age, camouflage); the evidence ledger.
   - CI.
   - The fresh-build first run.
3. **What is blocking.**
   - The engine execution model: `require` is a compile-time recognizer, there is a deterministic-lane budget, and IFC is fail-high with no declassification. These are engine-first changes under the split contract.
   - A measurement culture that closes KPI beads on artifacts that were never executed end to end: fsync removal, a directory passed to `run`, keyword gates, PR-only gates.
   - Zero functioning CI to catch either problem.
4. **Would the open/in-progress beads close the gap?** **No.**
   - bd-28sz/bd-kx70h/family residuals can plausibly reach 95% **on this corpus**, which cannot see the module-loading, language or limits failures.
   - bd-f5b04 (TNR) does not name module loading, execution limits or language correctness.
   - bd-34d5 does not name the sidecar presence gate or the undocumented trust-scan env.
   - No open bead covered the freshness-gate regression, the fsync durability trade, the invalid 10× campaign, the SDK/CLI format split, run→incident capture, CI trigger reality, performance, reachability, or engine pinning.
5. **Vision goals with no bead before this pass:** all of V29–V34 plus G-A/G-B/G-D/G-E/G-F/G-H/G-I. They are now covered by the new epic below.

### Beads created (Phase 3a) — epic `bd-reality-20260923-26n9r` (P0)

| ID | P | Gap |
|---|---|---|
| `.1` | P0 bug | Revocation freshness gate dead/fail-open on default installs; needs a real signed revocation frontier (not file mtime) |
| `.2` | P0 bug | Restore rewrite-transaction durability (7→0 fsyncs); barrier-count test; honest re-measure; reconcile CLAIM-002 |
| `.3` | P1 bug | ≥10× campaign never executes the franken leg; positive controls, typed outcomes, Wilson bounds |
| `.4` | P0 feature | Module loading on `run`: CJS/ESM resolution, node_modules, `run <dir>`, missing builtins (engine-first) |
| `.5` | P1 feature | Execution-limits contract: instruction budget, virtual clock, console truncation, lost output, strict semantics, `process` |
| `.6` | P1 bug | Language correctness (private fields, async IIFE, generator spread, inspect formatting, globals) + executed Test262 |
| `.7` | P1 bug | SDK cannot parse CLI bundles; unkeyed SDK "signature"; CLI→SDK round-trip test |
| `.8` | P1 feature | Product run→incident capture; stop certifying hand-authored evidence; coverage metric for "100% replay" |
| `.9` | P1 bug | CI: PR-only gates never run, sibling checkout broken, invalid YAML, one honest canary job, dynamic badges |
| `.10` | P2 task | Performance vs node, measured (replace HC-003 keyword gate); cut ~130 ms fixed overhead |
| `.11` | P1 bug | First-run blockers: sidecar presence gate, undocumented trust-scan env/token, bundle key, doctor gaps |
| `.12` | P1 task | Corpus v3 (ecosystem + language + per-profile) + provenance + engine revision pinning |
| `.13` | P1 task | IFC benign false-positive rate + declassification surface |
| `.14` | P2 task | Library islands: disposition (wire/gate/retire), dedupe bd-137, reachability gate |
| `.15` | P2 feature | Make the README scenario real: typosquat, publisher age, camouflage on real data, evidence ledger writes |
| `.16` | P1 task | False-closed/over-claimed follow-ups: tenx3.3, tenx3.4, tenx3.5, w0fc6.7, w0fc6.9, closer-gate hardening |
| `.17` | P2 docs | README/CLAIMS_REGISTRY truth pass for all of the above |

Related links point to bd-f5b04, bd-28sz, bd-kx70h, bd-34d5, bd-tenx3.1/.2/.3/.4/.5, bd-v0lgc, bd-3cpa, bd-rjc2m.21 and w0fc6.6/.7/.9, so existing owners see the new evidence. Blocking edges: `.15`←`.11`, `.8`←`.7`. `br dep cycles` is clean. Evidence comments were added to bd-kx70h (fresh 87.32% breakdown), bd-v0lgc and bd-3cpa.

### Recommended order (bridge plan, highest vision impact first)

1. `.1` and `.2`: correctness and security regressions. Small, surgical, and they stop the bleeding.
2. `.9` (CI) and `.11` (first run): without them no other claim can be checked by anyone but an agent with a warm target dir.
3. `.4` → `.5` → `.6`: turn the engine into something that runs npm code. This is the product.
4. `.12` + `.13`: make the compatibility metric able to see (3), then chase 95% on a corpus that means something.
5. `.7` → `.8`: make the verifier/incident story true end to end.
6. `.3`, `.10`: re-measure the 10× and performance claims honestly.
7. `.14`, `.15`, `.16`, `.17`: wire or retire the islands, make the README scenario real, clean up the false closes, align the docs.

### Probe reproduction

- **Build:** `rch exec -- env CARGO_TARGET_DIR=<scratch>/target CARGO_PROFILE_RELEASE_DEBUG=0 cargo build --release -p frankenengine-node --bin franken-node`.
- **Probe workspace:** `init --profile balanced --out-dir .` in a scratch dir with `bun install` of lodash@4.17.21, ms@2.1.3, semver@7.6.3, minimist@1.2.8, dayjs@1.11.13, uuid@9.0.1, commander@12.1.0, express@4.21.2.
- **Run each probe with:** `FRANKEN_NODE_ENGINE_BINARY_PATH=<binary> franken-node run <file> --policy balanced --console-only`, and compare with `node <file>`.
- **Corpus:** `ops compat-corpus-run --corpus-root <copy of crates/franken-node/tests/fixtures/compat_corpus> --out <scratch>/results.json --require-node-reference`.
- **Probe programs:** the one-liners in the tables above are complete. The beads `.4`/`.5`/`.6`/`.11` specify the checked-in probe scripts that will make these runs permanent.

## Refresh 2026-09-27 (sixth full reality check — live-binary delta pass)

**Method.** Same measuring stick: README (3,542 lines) and AGENTS.md read in full, plus the charter, the plan (§3, §9, §11-16) and every earlier section of this file. Everything below was either run against a release binary or re-read from the code:
- **Binaries.**
  - `build13` is node `ac8deece2` plus engine `fcb7b3877`.
  - `build14` is node `a5a1721fa` plus engine `27c5bd165`, the current main of both repos.
- **Comparisons.** Every probe was run against node v22.2.0, with bun 1.4 as the lockstep second leg.
- **Corpus.** Each profile was run with the new and the incumbent binary back to back in one invocation.
- **CI.** Measured from the GitHub API.
- **Closure audit.** An independent audit checked every bead closed since 09-23 in both repos, and I re-verified its load-bearing findings by hand before acting on them.
- **Artifacts.** No committed artifact was regenerated; probe artifacts live in the session scratchpad.

**Beads:** 4,374 total. The active set grew because three closes were reopened and two gaps were filed (below).

### Executive answer

The runtime crossed the line from "runs only self-contained single files" to **"runs real CommonJS programs, resolves installed npm packages, and fails honestly"** in four days.
- **What landed:**
  - `require('./lib/x')`;
  - Node's `node_modules` resolution: `exports` conditions in author order, patterns, `main`, JSON modules, and core-module precedence;
  - output kept when a program throws;
  - a 5M-iteration loop under the default profile;
  - a working first run from a fresh build under all three profiles;
  - `strict` hello exiting 0;
  - hello-world overhead 1.79× node, down from 4.5×.
- **Closed or narrowed as landed:** the incident pipeline runs end to end from a real `run` (auto capture → signed bundle → replay `matched=true` → verification in the SDK via `ltv attest`), and the revocation gate blocks under strict on a default install.

**What has not moved is the charter's headline:**
- No real npm package runs yet: 0/6. Each now fails one layer deeper, on four named gaps.
- The compatibility corpus is flat at 70.71 / 78.93 / 86.61% (strict / balanced / legacy-risky). It cannot see the ecosystem failures anyway (.12).
- CI is 28% green.
- The only release is 1,218 commits stale.

The closure audit also found that 4 of 8 recent closes had shipped less than they promised. Three were reopened.

### Live probes (release binaries; no engine env, no degraded fallback)

| Probe | 2026-09-23 | **2026-09-27** |
|---|---|---|
| Fresh dir: `init` + `run hello.js` (no `FRANKEN_NODE_ENGINE_BINARY_PATH`) | failed (sidecar presence gate) | **exit 0** under strict, balanced, legacy-risky; doctor `warn`, 0 failing checks |
| `strict` hello | exit 92 (Sandbox) | **exit 0** |
| `require("./lib/math")` | ambient-authority refusal | **works** (engine b2f96f751, node be768f452) |
| `require('pkg')` from `node_modules` | refused | **resolves** (engine fcb7b3877): main, `exports` require-condition, subpaths, `*` patterns, `null` exclusion, scoped, JSON, hoisted walk-up, core precedence |
| 6 real npm packages (lodash, ms+semver, dayjs, uuid, commander, minimist) | 0/8 (no module loading) | **0/6**, each past resolution: lodash parse budget (bd-fkdzv); minimist/dayjs/commander parser bugs (**fixed** engine 27c5bd165 — see npm re-probe below); semver IFC keyword false positive on the key `tokens` (.13); uuid `require('crypto')` as an object (engine bd-305gi) |
| Language probe (10 snippets) | 5/10 (09-23), 7/10 (09-24) | **8/10**. Still silently wrong: private field (`this.#x`) and std globals. Root cause of the first: **the parser drops every class field**, public and static included (`class A { y = 2 }` → `undefined`) |
| Execution limits (.5 acceptance, 7 probes) | 0/7 | **2/7**: 5e6-iteration loop ✓, throw-after-log ✓. Still failing: frozen `Date.now()`, first 500 of 1,500 lines dropped silently, a timer throw exits 0, `process.exit`/`argv`/`env` refused at lowering |
| `console.log({a:1},[1,2,3])` | `[object Object] 1,2,3` | `{ a: 1 } [ 1, 2, 3 ]` ✓ (engine a56eeac63) |
| hyperfine `run hello.js` vs `node` (same invocation, load ≈178/64 cores) | 4.5× slower (164 vs 37 ms) | **1.79× ± 0.30** (91.8 ± 14.3 vs 51.2 ± 2.9 ms) |
| SSRF egress → incident | hand-authored evidence only | **auto-captured** `INC-RUN-*`; `incident bundle --verify` ok; `incident replay` `matched=true`; `incident counterfactual` executor `synthetic` (documented); **`ltv attest` verifies the CLI bundle through the SDK** |
| Revocation freshness, default install, no frontier | gate dead (read a never-written `.json` mtime) | **strict blocks** ("no revocation frontier has been recorded"), balanced warns and runs |
| `trust scan` typosquats (`lodahs`, `expres`) | no typosquat logic | **raised to high** ("possible typosquat of popular package `lodash`") |
| `verify lockstep . --runtimes bun,franken-node` (CJS program) | — | **Pass**, 0 divergences; report records both runtime versions as `unknown` (provenance gap) |
| `migrate audit` (probe project) | works | works: 33 files, 5 findings (skips `node_modules`) |

**Compatibility corpus** (560 cases, `--require-node-reference`, build13 vs build12 back to back per profile, host load ≈170):

| Profile | Pass | Core (floor 99) | High-value (95) | Edge (90) | vs incumbent |
|---|---|---|---|---|---|
| strict | 396 (70.71%) | 71.26% | 68.80% | 76.79% | identical pass set |
| balanced | 442 (78.93%) | 79.53% | 77.20% | 83.93% | identical pass set |
| legacy-risky | 485 (86.61%) | 88.98% | 84.40% | 85.71% | identical pass set |

The four days of runtime work above (CJS entries, `node_modules`, kept output on throw) **moved the corpus by zero cases on every profile**, because its 540 single-file micro-probes exercise none of it. That is .12's point, now measured.

Balanced failures (118) by cause:
- guest file writes denied by the profile's policy: 46 (owner decision bd-bpmb2, not a defect);
- `child_process` Bubblewrap abort: 30;
- IFC refusals: **27 = 4.82% benign false positives** (14 `TopSecret`, 13 `Secret`);
- core module needed as a runtime object: 5;
- `process` access: 4;
- type errors: 3;
- output mismatch: 3.

### New defects found by this pass

1. **`--console-only` stderr polluted by the incident notice** (verified live): a run that tripped capture printed `incident captured: …` on stderr, breaking the byte-exact console contract the lockstep/corpus franken leg relies on. **Fixed** in this session (see Work-session addendum).
2. **The effect ledger records ordinary I/O errors as policy denials** (verified live): a caught `ENOENT` read is receipted `policy_outcome: denied`, counted in `denied_count`, auto-captured as a High "runtime-security-control" incident, and fed to the sentinel. `PolicyOutcome` has only `Allowed`/`Denied`. **NO_BEAD → bd-bwn5a** (P1).
3. **Parser token budget blocks real modules**: required modules parse under `ParserOptions::default()` (64K tokens) regardless of profile; the per-profile token caps (32K/64K/128K) bind long before the documented source-byte caps (256 KB / 1 MB / 2 MB). lodash = 121,230 tokens. **NO_BEAD → bd-fkdzv** (P1, blocks .4).
4. **Class fields silently dropped** (parser `split_class_members` skips `;`-terminated members; no AST field node). Silent wrong answers for any ES2022 class field. Recorded as the root cause on .6 (engine-first).
5. **Two parser defects** blocking minimist/dayjs/commander: `=` inside a regex literal parsed as an assignment; a line starting with `||`/`?`/`:`/`,` split into its own statement. **Fixed** engine 27c5bd165 with unit tests.
6. **`incident list` cannot see captured-but-unbundled incidents** (scans `*.fnbundle` only): a deliverable of the reopened .8.
7. **Engine test suite is red at main** (~18 tests, pre-existing and not owned): baseline_interpreter_integration 5, bd_8y64t 2, path shadow 1, memory_budget_adversarial 4 (16 KiB budget overrun by 4-67 bytes), and 6 parser-contract tests that still pin lenient top-level `await` / mismatched-quote behaviour and the old `ParseErrorCode` count after another agent made the parser stricter. The **engine beads DB has been wedged** ("recovery in progress") since 2026-09-25 00:06 with no live `br` process, so none of these (nor the engine-side items above) can be filed engine-side; texts are queued in the session scratchpad and `br doctor --repair` (JSONL rebuild, backups kept) needs an owner decision.

### Closure audit (every close since 2026-09-23, both repos: 7 node + 1 engine)

| Close | Verdict | Action |
|---|---|---|
| bd-vxw97 (lane router reload) | VERIFIED | — |
| bd-svc-honesty-v4yy9 (service.rs catalog) | VERIFIED | — |
| .2 (rewrite durability) | VERIFIED (7→0 fsyncs restored as ordered `durable_sync`; honest re-measure 1.24×) | — |
| .1 (revocation freshness) | THIN: behaviour real (verified live) but the acceptance probe script, the CLI-level A/B/C tests, the signed frontier record, the single resolver and the `DR-TRUST-FRESHNESS` check are all missing | **Reopened** |
| .7 (SDK reads CLI bundles) | THIN: headline fixed (verified live via `ltv attest`) but the unkeyed digest is still *named* a signature in SDK code (`bundle.rs:137,2464,2545`), the second bundle format was neither removed nor versioned, and the README example is not compiled | **Reopened** |
| .8 (run → incident capture) | FALSE-CLOSED on scope: 3/5 deliverables absent (`incident capture --from-run` + hand-edit refusal, `incident list` over the store, `ops incident-coverage`), package unsigned and unreferenced from the receipt, acceptance unmet by the close_reason's own admission; plus the two regressions above | **Reopened** (now blocked by bd-bwn5a) |
| .17 (README truth pass) | THIN (minor): README:76-77 absolute "every decision is a signed receipt" | Fixed in this session |
| engine bd-9vouw.6 | THIN (minor): default budget left at 100k without an evidence-based decision | Queued (engine DB wedged) |

### Vision checklist deltas (Aug-20 numbering + V29-V34)

| # | Goal | 2026-09-23 | **2026-09-27** |
|---|---|---|---|
| V1 | `run` executes guest JS | PARTIAL: single-file only | **PARTIAL, much wider**: CJS programs + local `require` + `node_modules` resolution + ESM entries by package type; fresh first run works; real npm packages 0/6 on four named gaps |
| V2 | Revocation-first execution | REGRESSED (gate dead) | **WORKING behaviour, PROOF GAP** (strict blocks live; acceptance tests missing → .1 reopened) |
| V3 | Trust cards | PARTIAL | **PARTIAL+**: typosquat + registry signals live on `trust scan`; camouflage still library-only |
| V4 | Replay + counterfactual | INTEGRITY-ONLY | **INTEGRITY, now from real runs**: auto-capture → bundle → replay → SDK; counterfactual still synthetic; capture over-fires on I/O errors (bd-bwn5a) |
| V6 | ≥95% corpus | RED 87.32% (legacy, scratch) | **RED, flat**: strict 70.71 / balanced 78.93 / legacy-risky 86.61; no band meets its floor; zero cases moved by four days of runtime work, blind to the ecosystem (.12) |
| V10 | Verifier SDK independent | BROKEN for bundles | **WORKING for CLI bundles** (verified live); honesty naming open (.7 reopened) |
| V11 | Doctor | PARTIAL | **PARTIAL+**: fresh workspace reports `warn`, 0 failures |
| V16 | ≥3× migration | WRONG_APPROACH | **UNMET, honestly measured**: durability restored, 1.24× (bd-v0lgc) |
| V17 | ≥10× compromise | INVALID | unchanged (.3 open) |
| V25 | Release freshness | 1,136 commits | **1,218 commits** behind `v0.1.0` |
| V27 | Effective coverage / CI | 14.3% green | **28.2% green** (256/908, 09-21..27); 9 workflows never green in the window |
| V29 | Performance vs node | 4.5× | **1.79× ± 0.30** on hello (loaded host) |
| V30 | Module loading / ecosystem | NOT_STARTED | **PARTIAL**: resolution done, npm execution blocked (bd-fkdzv, .13, bd-305gi); the re-probe with the 27c5bd165 parser fixes is recorded in the addendum below |
| V31 | Language correctness | FAIL | **FAIL, narrower**: 8/10 probes; class fields dropped (silent); no Test262 |
| V32 | Primitives reachable | ~43% | unchanged (.14) |
| V33 | Engine pinning + provenance | ABSENT | **PARTIAL**: corpus results carry `run_provenance`; engine is still a bare path dependency; lockstep report records runtime versions as `unknown` |
| V34 | Evidence ledger written by decisions | ABSENT on CLI | **WORKING** for `run` (incl. preflight refusals), `trust revoke/quarantine/release`, `fleet release`; `verify transparency-log` checks it |

**Strict WORKING count:** V10, V15, V34 join V13; V2 behaves but lacks its proof. The runtime (V1/V30/V31) is the axis that moved most, and it is still the one that decides the charter.

### Answers to the reality-check questions

1. **What works today:** everything in the probe table marked ✓/works: governed execution of CommonJS programs with local modules and real module resolution, with containment (SSRF, capability, eval, sandbox) and signed host-effect ledgers; the incident pipeline from a real run to SDK verification; revocation gating; typosquat-aware trust cards; lockstep on small programs; `migrate audit`; a fresh first run.
2. **What does not work:** any real npm package (four gaps, one fixed today); ES2022 class fields; a real clock; >1,000 console lines; `process.exit/argv/env`; timer-throw exit codes; CI (72% red, 9 never-green workflows); a current release; the 3×/10× KPIs; benign-code IFC false positives on keyword literals and property names (.13).
3. **What is blocking:** (a) the engine execution model's remaining gaps (parse budget, class fields, builtins as runtime objects, IFC keyword labels), all engine-first under the split contract, while (b) the engine's own issue tracker is wedged and ~18 engine tests are red and unowned, so engine work cannot be tracked or gated where it lives.
4. **Would the open/in-progress beads close the gap?** Closer than on 09-23 but **no**: the npm path now has concrete blockers with owners (bd-fkdzv, .13, bd-305gi, .6), but no bead makes the npm probe a *measured, gated* metric (the corpus still cannot see it; .12), and the engine-side items cannot be filed until the engine tracker is repaired.
5. **Vision goals with no bead before this pass:** the ledger denial/failure conflation (bd-bwn5a) and the parse-budget contract (bd-fkdzv); both filed.

### Bridge plan (next, highest vision impact first)

1. **Owner decisions** (unblock everything else): repair the engine beads DB (`br doctor --repair`); decide .13's keyword-label question (it blocks semver today and 4.64% of the corpus); decide bd-fkdzv's parse-budget policy.
2. **npm execution** (.4 via bd-fkdzv, then .6 class fields fail-closed → implemented, then bd-305gi builtins): re-run the 6-package probe after each; check the probe in as an e2e with node-identical assertions so progress is a number.
3. **Honesty of evidence** (bd-bwn5a, then .8's remaining deliverables): a denial must mean a policy refusal.
4. **.5 remainder**: real clock (with deterministic mode kept for replay), console overflow reported (not silent), timer-throw exit code, `process` surface.
5. **CI** (.9): make the 9 never-green workflows start/pass or retire them with owner sign-off.
6. **Corpus v3** (.12): add module/package cases so the headline metric can see (1)-(4).
7. Reopened .1/.7 acceptance items; release freshness (V25) once corpus and CI are credible.

### Work-session addendum (2026-09-27, this pass)

- **Engine 27c5bd165** (landed, main + master): the parser skips regex literals when scanning for a top-level `=`, and a line that starts with an operator continues the previous statement. Unit tests `merge_logical_lines_continues_lines_that_start_with_an_operator`, `parse_script_accepts_leading_operator_continuations`, `regex_literals_containing_equals_are_not_assignments`; lib `parser::` 1490/1490 via rch.
- **`--console-only` purity**: `run` no longer prints the incident-capture notice on the guest's stderr in console-only mode (`main.rs`, capture notice gated on `!console_only`); regression test `console_only_run_keeps_incident_capture_notice_out_of_guest_streams`.
- **README:76-77** no longer claims every decision is in the evidence ledger; it names the decisions that are.
- **Beads**: reopened .1, .7, .8 (evidence on each); filed bd-bwn5a and bd-fkdzv (both P1; `.8` and `.4` blocked by them); evidence comments on .5, .6, .9, .10, .11, .13. `br dep cycles` clean.
- **npm re-probe with the parser fixes**: needs a release binary containing 27c5bd165. build14 compiled remotely but rch lost the artifact (completion "unconfirmed", `rch jobs recover` refused on an artifact-policy error), so a rebuild is queued; the result is appended below when it lands.

### Addendum 2026-09-27 evening: npm re-probe and new live findings

**npm re-probe on build15** (node a5a1721fa + engine b57e6a660, which includes 27c5bd165). Each probe ran in the same directory as Node v22 and was compared byte-for-byte:

| Package | balanced | legacy-risky | First wall |
|---|---|---|---|
| minimist | FAIL | **MATCHES Node** | balanced: `register 256 out of bounds` (engine bd-9vouw.23) |
| lodash | FAIL | FAIL | module token budget 121,230 > 65,536 (the engine now honors the configured budget, 719f6d422; the default is still 64K, bd-fkdzv) |
| dayjs | FAIL | FAIL | parser: an `=` inside a `?:` branch was taken as the statement's assignment operator (root cause found; fix on the engine parser branch) |
| semver | FAIL | FAIL | IFC keyword label Secret → Internal at lowering (.13 / engine bd-9vouw.19) |
| commander | FAIL | FAIL | IFC import ceiling: the eleven `require()`s at the top of `lib/command.js` raise the whole-program label to TopSecret, 171 denied flows (engine bd-j8f7q; no keywords are involved) |
| uuid | FAIL | FAIL | no runtime module for `crypto` (bd-305gi) |

Result: balanced 0/6, legacy-risky 1/6 (was 0/6 and 0/6). IFC over-labelling is now the largest blocker class: 2 of 6 packages, through two different mechanisms.
- **Keyword heuristic** (.13 / engine bd-9vouw.19): semver's only trigger is the object-literal key `tokens:` at index.js:84, and the same heuristic hits 27 of 560 corpus cases.
- **Import ceiling** (engine bd-j8f7q): hits commander.

**Console output was silently truncated and unbounded in bytes** (live, build13):
- 1,500 `console.log` lines print only lines 500–1499, exit 0, with no warning, in every profile (a 1,000-entry ring that evicted the oldest entries).
- 300 × 1 MiB lines reach 1.48 GB RSS, then die as "Engine crashed with panic … bug in the engine" on the 24 MiB native-session frame.
- Engine fix in verification (branch `console-budget-fail-closed`): overflow is a typed `ConsoleBudgetExceeded` failure that JS cannot catch; the head of the output is kept; the entry caps become 100k/1M; a new 8 MiB byte budget fits node's 10 MiB guest-output bound.

**Async failures exited 0** (engine bd-xzemw, now in progress):
- A throw inside a `setTimeout`/`setImmediate` callback was printed to the host's stderr and dropped.
- An unhandled rejection (`Promise.reject(e)`, or a throwing async function that nobody awaits) was ignored.
- The fix makes both end the run like Node's uncaught exception. Rejections are tracked incrementally, without a per-tick store walk, and rejections observed by combinators or adoption are marked handled.

**Class fields** (engine bd-9vouw.64): on branch `class-fields-fail-closed`, still in verification, the parser refuses them with `UnsupportedSyntax` instead of silently dropping them. This is refusal-only, so the bead stays open for the implementation.

### Addendum 2026-09-27 late: landed and verified on a live release binary (build16)

Landed:
- franken_engine fb07b73f2 (console budget), 6a1955fc0 (class-field refusal; `=` inside `?:` branches), c1d0b05f5 (`process.exit` / `exitCode` / argv), 083aac714 (timer throws and unhandled rejections), 719f6d422 (module parse budget).
- franken_node a4ec6df57 (`run app.js -- args`, exit-status mapping, e2e tests) and 9b415077a (ledger: TLS trust refusals stay denials; failed spawns are `failed`).
- Beads closed: engine bd-xzemw, bd-my9hk.

Live checks on build16 (node 732e4f65a + engine f80cee567), `--console-only`:

| Program | Result |
|---|---|
| 1,500 × `console.log` | all 1,500 lines, exit 0 (was: lines 500..1499, exit 0) |
| 9 × 1 MiB lines | 8 lines kept, exit 1, `console output budget exceeded: 9 entries / 9437184 bytes, limits …` (was: 1.48 GB RSS, "Engine crashed with panic") |
| throw in `setTimeout` | `before`, exit 1, `uncaught exception: Error: timer boom` (was: exit 0) |
| `Promise.reject(e)` unhandled | `before`, exit 1, `uncaught exception: Error: …` (was: exit 0, later timers ran) |
| `process.exit(3)` / `process.exitCode = 7` | exit 3 / exit 7 (was: refused at lowering) |
| `run app.js -- alpha beta` (legacy-risky) | `process.argv.slice(2)` = `alpha,beta`; balanced still refuses `process.argv` (bd-y30zw, owner question on .5) |
| `class A { y = 2 }` | refused: `class fields and private names are not supported yet` (was: `undefined`, exit 0) |

npm re-probe on build16: balanced 0/6, legacy-risky 1/6 (minimist). lodash now parses, and its next wall is a runtime `expected function, got string`, probably an `Expression::Raw` fallback. dayjs now parses, and its next wall is `globalThis` refused at lowering (BRIDGE-15.13). The other walls are unchanged: semver (keyword IFC), commander (import ceiling), uuid (`crypto` module).
