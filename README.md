# Vouch SCORED26 Artifact

This repository is the anonymous review artifact for Vouch authenticated
Native evidence. It contains the complete sanitized implementation used by the
release, the generated evaluation records, the signed release chain, and an
offline-capable verification projection.

The publication verdict is the terminal report
`release/chain/publication-report.json` (S). This tree represents a conforming
release only when S has `status=pass`, `chain_verified=pass`,
`paper_claims_matched=true`, and `claim_language_scan=pass`, and the root
checker verifies those fields and their D→Q→R→P bindings. A missing,
changed, or failing S is not partial conformance.

Start with:

```sh
npm run check
```

No install is required. See [RUN.md](RUN.md) for the full source lane, archive
reassembly, and a pinned Linux phase-1 rerun.

On Rust 1.85.1, `npm run check:source-full` currently exits on the pre-existing `clippy::format_collect` warning at `vouch/src/io_boundary/mod.rs:703`; the synthetic fixture projection and its checks are unaffected.

## What is included

- `source/` publishes the 2,367 tracked paths from sanitized synthetic source
  commit C0 `3e910c9ff87cc01d3bc241d63297218b44e75ede`: 2,366 are byte-for-byte,
  and one scanner negative-fixture path is a hash-pinned synthetic-value
  overlay. Executable modes are preserved. The source manifest inventories
  3,155 files after review-only support files and pinned toolchain packages
  are added.
- `release/chain/` contains the public key and trust policy, signed descriptor
  D, phase-1 report Q, signed observation R, publication index P, and terminal
  report S.
- `release/results/` contains the fixture, workload, mutation, performance,
  exact-reproduction, condition-map, and D-bound release-manifest records.
- `release/archive-chunks/` transports the exact release archive bound by D.
- `release/audit/` records lifecycle, anonymity, secret-scan, source-boundary,
  and exact-bundle reconciliation facts.
- `machine-record/` contains the publication-check PDF, while
  `ARTIFACT-MANIFEST.json` inventories the distributed repository bytes and
  modes.

The implementation is not a report-only subset. It includes both evaluator
paths; canonical artifact JSON; Native issuance, DSSE verification, replay and
promotion; the TypeScript consumer capability boundary and forgery negatives;
the Bridge path; release-lifecycle code; schemas and contracts; all Rust and
TypeScript tests; the differential and Meaning Environment corpora; the public
Vouch loop; adversarial cases; the frozen workload; the twelve-mutant
campaign; the fixture machinery; and the offline Rust and JavaScript/TypeScript
dependency closure.

The normative contract is
`source/artifact/contract/NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md`, SHA-256
`ecc294798be49f5843bd84e0ebad5d94a930f2b09f51db4852e42d2789addddc`.
The ledger records 213/213 conditions built, and the fixture report records
165/165 matches with zero skips. The frozen workload has 1,536 candidates,
240 selected cases (192 development and 48 held out), and the mutation
registry has twelve single-site mutants with twelve activation witnesses.

## Source and authentication boundary

The distributed `source/` directory is a review projection, not a claim that
the wider Lispex product repository is part of this artifact. The broader site
and UI, governance and coordination records, unrelated research tracks,
original Git history, remotes, credentials, local paths, and private release
key are excluded. Small Lispex-named paths remain only when the Vouch closure
uses them as executable semantic fixtures, public Vouch documentation, the
offline Bridge verifier, or version-drift guards.

`source/synthetic-history/vouch-scored26.bundle` carries exactly three generic
SHA-1 commits:

- F `c90f97ddd6b1d662791a76fe4663b90e79c443ec`;
- B `ef7ef9bb4b56382ef5d413408a5f93a6898498c2`;
- C0 `3e910c9ff87cc01d3bc241d63297218b44e75ede`.

They use only `Artifact Maintainer <artifact@example.invalid>`, fixed UTC
timestamps, and no remote. The exact bundle bytes are byte-identical to
`release/vouch-scored26.bundle` inside the D-bound archive, and the archive's
release manifest names that member. Thus D authenticates the archive and,
through that manifest, the exact bundle and its F→B→C0 tree.

That statement does **not** authenticate or make archive-equivalent the whole
`source/` projection. `README.md`, `RUN.md`, `RIGHTS.md`,
`SOURCE-MANIFEST.json`, `tools/`, the split review toolchain, and the adjacent
synthetic bundle are projection-layer review files. The source and root
manifests make this boundary checkable; they are not additional D/Q/R/P/S
objects.

## Archive transport

The D-bound `vouch-scored26-artifact.tar.zst` is transported as 59 ordered
parts. Parts 0–57 are 7,340,032 bytes each; part 58 is 3,706,440 bytes. The
concatenated archive is 429,428,296 bytes with SHA-256
`49e9e1fd9e669b2da168d8763f4c61f88b95944f566a3e44232f3a8c443740ad`.
`release/archive-chunks/archive-chunks.json` records every part's size and
digest. The root checker verifies all parts, the concatenated identity, and
equality with D's `archive_sha256` before treating the archive or its bundle as
authenticated.

The unchunked archive is deliberately not duplicated in the repository. It can
be verified or reconstructed with the dependency-free commands in RUN.md.

## Package metadata and rights

Both npm package files use `"private": true` as a package-manager safeguard
against accidental registry publication. It does not mean the implementation
is unavailable or withheld: the complete Vouch source closure described above
is present in this public tree. The root checker's Apache-2.0 scope and the
first-party evaluation permission for `source/` are stated in
[LICENSE-SCOPE.md](LICENSE-SCOPE.md) and `source/RIGHTS.md`.

## Claim limits

The receipt establishes observed agreement over its explicit checked surface;
it is not a proof of semantic equivalence. The two evaluator paths are
same-origin and share substrate. Consumer policy remains the trust root, and
the artifact does not establish input truth, policy fairness, signer honesty
after key compromise, freshness, a transparency log, a trusted timestamp, or
deployment attestation. Host runs are useful validation, but the release's
empirical and provenance claims are the generated pinned-Linux records bound
through D→Q→R→P and accepted by S. The recorded Linux/amd64 run used Lima
virtualization and Rosetta translation on an Apple host; it is not an
independent bare-metal reproduction.
