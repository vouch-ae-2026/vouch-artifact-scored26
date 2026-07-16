# Build and test

Run the repository-level commands from the artifact root when possible. They
copy this source tree to an operating-system temporary directory, prepare the
closed review toolchain there, run the checks, and delete the copy. No package
download or network access is required.

The pinned release environment is Linux/amd64 with Node 22.14.0, npm 10.9.2,
Rust 1.85.1, and Git. Host runs are development validation; the distributed
empirical and provenance records come from the completed pinned Linux lifecycle.

## Inventory, C0 identity, and anonymity

The following read-only commands may be run directly under `source/`:

```sh
node tools/check-source-projection.mjs
node tools/check-source-negative.mjs
node tools/check-synthetic-checkout.mjs
```

The projection check verifies the exact manifest, all 2,367 C0 files against
the bundled C0 tree, F→B→C0 topology and generic commit metadata, the pinned
review-toolchain package trees, the canonical TypeScript chunk manifest and
ordered reconstruction hash, the per-file size limit, file modes, absence of
`.git` metadata and remotes, and first-party identity/secret/path boundaries.
The TypeScript parts are at most 7 MiB, each below 4open's 8 MB file limit.
The negative lane proves representative leaks, changed parts, and no-replace
publication races are rejected. The checkout lane creates two clean detached
C0 checkouts from the bundle and removes their temporary local bundle remotes
before use.

For manual bundle inspection:

```sh
git bundle verify synthetic-history/vouch-scored26.bundle
git bundle list-heads synthetic-history/vouch-scored26.bundle
```

The expected head is
`3e910c9ff87cc01d3bc241d63297218b44e75ede HEAD`. The repository-level checker
also requires these bundle bytes to match `release/vouch-scored26.bundle` in
the D-bound archive manifest. The surrounding projection remains a review
view, not a signed release object.

## Portable artifact checks

From the repository root:

```sh
npm run check
```

The command verifies the final repository inventory, release chain, source
manifest, D-bound archive transport, and exact bundle reconciliation, then runs
the portable source lanes in an isolated temporary copy. The source setup creates exactly nine temporary
`node_modules` links to the inventoried TypeScript 5.8.2 declarations and Ajv
closure. It performs no install.

The equivalent source-level commands inside an operating-system temporary copy
are:

```sh
node tools/prepare-review-toolchain.mjs
npm run check:artifact
npm run check:consumer
node tools/check-fixture-results.mjs
node tools/check-fixture-results-negative.mjs
node tools/check-replay-manifest-portable.mjs
```

## Full offline source lane

From the repository root:

```sh
npm run check:source-full
```

The wrapper uses the exact bundled C0 in a detached checkout, links only the
verified temporary review toolchain, and runs the Vouch generate/verify/replay
example, Bridge and adversarial checks, Rust format/lint/tests, and the complete
165-fixture conformance runner. Before linking, it verifies the ordered
TypeScript parts, fsyncs a same-directory temporary reconstruction, and
publishes it without replacing an existing path. Generated `target/`,
`packages/vouch-consumer/dist/`, and temporary `node_modules/` are kept out
of the distributed source and removed with the temporary checkout.

Workload and mutation result validators are included in the source lane. Their
clean generators and the full D→Q→R→P→S implementation are also public. A
reviewer can rerun phase 1 from the distributed D-bound archive without the
release key; regenerating the signed D and R objects requires an independently
chosen key and produces a distinct release identity.
