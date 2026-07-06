# Generated Disjointness v0 Record

Status: W1.2 generated disjointness for P1-P3.

This record adds a deterministic generated candidate set for native/Bridge
artifact-class disjointness:

```text
manifests/generated-disjointness.v0.json
```

The generator starts from one valid native differential receipt and one valid
Bridge report, then constructs top-level field/tag combinations across native,
Bridge, both-tag, wrong-tag, and no-tag modes. Each candidate is submitted to
both verifier entrypoints.

## Properties

- P1: no generated candidate is accepted by both native and Bridge verifiers
- P2: a valid `vouch.bridge-report/v0` is accepted as Bridge evidence and
  rejected by the native verifier
- P3: a valid `csk.differential-receipt/v0` is accepted as native evidence and
  rejected by the Bridge verifier

## Machine Check

```sh
npm run check:generated-disjointness
```

The check regenerates the candidate set, runs both verifier entrypoints for every
candidate, and compares the committed manifest with the regenerated result.

## Negative Check

`check:generated-disjointness` mutates temporary in-memory copies and requires
failure for:

- P1 set to false
- P2 set to false
- P3 set to false
- nonzero dual-accept summary
- generated candidate count shrink
- boundary overclaim that removes `exhaustive-artifact-grammar-fuzzing` from
  excludes

## Boundary

This slice opens one claim:

> The native and Bridge verifier entrypoints satisfy generated P1-P3
> artifact-class disjointness over the deterministic W1.2 candidate set.

It does not claim exhaustive artifact grammar fuzzing, semantic equivalence,
independent witnessing, or receipt authenticity.
