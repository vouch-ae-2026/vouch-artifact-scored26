# Vouch SCORED26 review source

This directory publishes the complete tracked tree of the sanitized synthetic
Vouch source commit
`3e910c9ff87cc01d3bc241d63297218b44e75ede` (C0). All 2,367 C0 files are
present byte-for-byte with their executable modes preserved. The directory has
no `.git` metadata, repository remote, private key, credential, or local
developer path.

The adjacent projection layer adds only review documentation, manifest and
checking tools, the integrity-pinned JavaScript/TypeScript review toolchain, and
`synthetic-history/vouch-scored26.bundle`. These additions do not replace or
rewrite any C0 path.

## Synthetic lineage

The bundle contains exactly this generic, three-commit SHA-1 history:

- F: `c90f97ddd6b1d662791a76fe4663b90e79c443ec` — the nine frozen
  workload inputs;
- B: `ef7ef9bb4b56382ef5d413408a5f93a6898498c2` — the sanitized Vouch
  dependency closure and generators;
- C0: `3e910c9ff87cc01d3bc241d63297218b44e75ede` — the B-bound
  differential, Meaning Environment, Vouch-loop, workload, mutation, and
  fixture results.

All commits use the placeholder identity
`Artifact Maintainer <artifact@example.invalid>`, fixed UTC timestamps, and
no remote.

This bundle is byte-identical to `release/vouch-scored26.bundle` inside the
assembled release archive bound by descriptor D. The repository-level checker
verifies that identity against the archive's release manifest and D's archive
digest. This authenticates the exact bundle as an archive member; it does not
turn the projection-only files around it into signed release objects.

## Published implementation

The source is not a report-only shell. It includes:

- `interp/`: both checked evaluator paths, canonicalization, observation,
  invocation-bound tokens, Native issue/verify, workload and mutation runners,
  and Rust tests;
- `vouch/`: canonical artifact JSON, DSSE, policy, replay, issuance, and
  release-boundary code;
- `packages/vouch-consumer/`: structural verification, evidence and decision
  capabilities, promotion, compile-time negatives, runtime forgery tests, and
  the intentionally vulnerable negative control;
- `artifact/`: both contracts, the 213-condition ledger, 165-fixture
  registry and results, workload and twelve-mutant inputs/results, release
  lifecycle implementation, scanners, schemas, and pinned image description;
- `differential/`, `meaning-graph/`, `meaning-env/`,
  `examples/vouch-loop/`, and `adversarial/`: executable corpora, expected
  records, the public generate/verify/replay example, and negative controls;
- the Bridge contract, schemas, verifier path, example, and checks;
- the complete offline Rust vendor closure and the lock-pinned TypeScript/Ajv
  review toolchain.

The byte-exact C0 `package.json` retains npm's `"private": true` safeguard to
prevent accidental registry publication. That package-manager flag does not
mean the implementation is withheld: the files listed above are present in
this public review tree and may be built and tested under `RIGHTS.md`.

One projection-only TypeScript payload is 9,065,569 bytes in its upstream
form. It is transported as deterministic parts of at most 7 MiB, each below
4open's 8 MB file limit. The canonical chunk manifest records the original
path, size and SHA-256 plus the ordered part sizes and SHA-256 values. Review
setup verifies every part and the concatenated identity, then publishes the
reassembled original with a fail-closed no-replace operation only inside the
temporary copy.

The small `content/`, `cli/`, `public/`, `src/`, and `wasm/` surfaces
are included only where the C0 Vouch closure uses them as public Vouch
documentation, executable conformance fixtures, the offline Bridge verifier,
or version-drift guards. The broader Lispex product site, UI implementation,
governance and coordination records, unrelated research tracks, original Git
history, and remotes are not included.

## Evidence boundary

The committed differential, Meaning Environment, Vouch-loop, workload, and
mutation records bind B because they are B-generated inputs to C0. A fresh
release lifecycle builds C0 and issues its release receipts at C0. Those two
identities serve different roles and must not be conflated.

`SOURCE-MANIFEST.json` inventories every distributed source-layer file,
distinguishes the 2,367 byte-exact C0 paths from projection additions and
third-party packages, and records the bundle and chunk-transport boundaries.
It is a review manifest, not a D/Q/R/P/S object.

The normative contract is
`artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md`, SHA-256
`ecc294798be49f5843bd84e0ebad5d94a930f2b09f51db4852e42d2789addddc`.
All 213 conditions are built and fixture-backed; the committed fixture report
contains 165/165 matches with zero skips.

See `RUN.md` for the offline checks and `RIGHTS.md` for the evaluation
permission.
