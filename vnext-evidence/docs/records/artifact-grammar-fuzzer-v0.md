# Artifact Grammar Fuzzer v0 Record

Status: W1.3 deterministic artifact grammar fuzzer.

This record adds a resident grammar candidate set across Vouch artifact classes:

```text
manifests/artifact-grammar-fuzzer.v0.json
```

The generator starts from one valid native differential receipt, one valid
Bridge report, one valid Bridge context manifest, and generated verify/replay
reports. It then applies deterministic malformed variants across:

- native receipt grammar
- Bridge report grammar
- Bridge context manifest grammar
- verify report grammar
- replay report grammar
- malformed native/Bridge hybrids

## Machine Check

```sh
npm run check:artifact-grammar-fuzzer
```

The check regenerates the candidate set, runs the relevant verifier or local
contract entrypoint for every case, and compares the committed manifest with the
regenerated result.

## Negative Check

`check:artifact-grammar-fuzzer` mutates temporary in-memory copies and requires
failure for:

- wrong fuzzer manifest tag
- nonzero unexpected accept count
- missing required artifact class coverage
- positive case marked as rejected
- negative case with erased expected failure
- boundary overclaim that removes `exhaustive-artifact-grammar-coverage` from
  excludes

## Boundary

This slice opens one claim:

> The deterministic W1.3 artifact grammar candidate set keeps positive cases
> accepted and malformed native, Bridge, context, verify/replay, and hybrid
> cases fail-closed with recorded failure classes.

It does not claim exhaustive artifact grammar coverage, randomized fuzzing,
semantic equivalence, independent witnessing, or receipt authenticity.
