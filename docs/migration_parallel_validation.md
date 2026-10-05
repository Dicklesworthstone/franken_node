# Bounded parallel migration validation

Three-runtime project validation can overlap independent test cases while
retaining Node, Bun and native observations for every selected test. This is
an explicit captured-project permission, not a default scheduling change or a
claim of test independence, runtime compatibility, or a measured speedup.

## Opt in before capturing and reviewing inputs

Set `max_concurrent_tests` in `.franken-node/migration-tests.json`:

```json
{
  "schema_version": "franken-node/migration-tests/v1",
  "tests": ["checks/a.cjs", "checks/b.cjs", "checks/c.cjs"],
  "max_concurrent_tests": 3
}
```

The value must be an integer from 1 through 4. Omission means 1, including
heuristically discovered suites with no manifest. Null, zero, negative,
fractional, duplicate and excessive values are errors, not requests to select
an automatic machine-dependent default. Existing tests, execution settings,
stdin fixtures and output expectations retain their normal validation.

Only grant concurrency when separate tests may safely overlap. Fresh private
workspaces isolate their captured files, not ambient network services, absolute
paths, shared databases, ports, child processes or other external effects.
Leave the value at 1 for tests requiring global ordering or exclusive external
resources. The value is a concurrency ceiling, not a guarantee that every
worker is active or that the tests constitute independent statistical samples.

Original and candidate must have the same effective concurrency permission.
Changing that permission changes the captured input identity; review both input
hashes again before an attested original-to-candidate run. An explicit 1 and an
omitted value describe the same serial execution policy. Neither a candidate
nor an environment variable can silently increase the grant. A later mutable
manifest edit cannot change the already approved immutable capture.

## Execution and evidence

The product oracle schedules bounded batches of complete cases. Each case
still executes Node, then Bun, then native, once each, in separate newly staged
workspaces. Cases borrow the same immutable input snapshots and captured
environment. All legs retain the original total deadline, per-leg timeout,
output budget, process cleanup, exact stream comparison, optional filesystem
delta comparison and declared golden-output assertions. There is no fresh
full timeout for a newly started batch.

Workers are scoped and all successfully started workers are joined, including
when another worker cannot start, returns an infrastructure error, or panics.
An infrastructure failure stops later batches and makes the suite incomplete;
completed peer observations remain in the report. A missing case is skipped,
not a fabricated passing result. A measured failing or timed-out case keeps
its existing classification and does not silently remove later cases.

Report rows and diagnostics remain in captured inventory order, independent
of worker completion order. Reference disagreement remains INCONCLUSIVE,
native divergence remains FAIL, and incomplete execution remains ERROR. All
runtime identities are rechecked after execution. Parallelism does not weaken
signature verification, cohort confidence, source-recovery checks or the
requirement that all three runtime observations support admission.

Live product comparison, checked three-runtime candidates, attestation and
product-capsule replay already share this executor. The captured manifest also
travels with exported capsules. The scheduling implementation is included in
the existing replay implementation hash, so changed scheduler semantics do
not silently qualify as replay under an older implementation.

## Resource and performance limits

There are at most four active case workers per suite invocation, with one
supervised runtime leg per case at a time. This is not an operating-system
limit on guest-created descendants or on multiple concurrent operator
invocations. Each case still stages its own runtime workspaces and retains
bounded stream observations, so parallel execution increases peak memory,
file-descriptor and disk use. Batches intentionally wait for their slowest
case before starting the next batch; no unbounded task queue is introduced.

Measure serial and parallel execution on the same real project and runtime
binaries before choosing a concurrency ceiling. CPU-bound or disk-bound suites
can slow down. No 3x migration-quality or throughput claim follows from this
feature or from test fixtures. Keep the existing measured KPI gate unchanged.

## Verification

The existing native migration validation workflow runs the exact production
modules through the standalone suite crate. New tests exercise a bounded
cross-worker handshake (which serial dispatch cannot satisfy), inventory
ordering, exact-once dispatch, captured permissions, worker errors and panics,
concurrent timeout handling, binary pipe input, working directories, immutable
fixtures and generated-file assertions. Tests that deliberately use Node in
all runtime roles validate orchestration only, never independent runtime
compatibility or release certification.
