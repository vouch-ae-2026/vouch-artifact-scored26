# Mutation Generator v0 Record

Status: W1.4 deterministic mutation generator with W3.4 native canonical
acceptance.

This record adds a property-mapped mutation generator:

```text
manifests/mutation-generator.v0.json
```

The generator covers the W1.4 claim-hardening properties:

- P4 canonical idempotence for Bridge read-side canonical acceptance
- P5 binding soundness for supplied source, target, linked artifact, and context
  bytes
- P6 boundary exactness for native and Bridge boundary weakening
- P7 diagnostic precision for active cases

It also records native receipt canonical-byte mutations as active caught cases.
Native compact JSON, CRLF JSON, and duplicate-key submissions fail the native
reader with `non-canonical-artifact-json`. The implementation does not claim a
dedicated `duplicate-key` diagnostic; duplicate-key cases are caught through the
round-trip canonical byte check.

## Machine Check

```sh
npm run check:mutation-generator
```

The check regenerates the deterministic mutation set and verifies that active
mutations fail with their expected diagnostic class.

## Negative Check

`check:mutation-generator` mutates temporary in-memory copies and requires
failure for:

- P7 set to false
- active case downgraded to the wrong failure class
- active case marked as accepted
- native canonical cases weakened from caught to accepted
- boundary overclaim that removes `duplicate-key-diagnostic-claim` from excludes

## Boundary

This slice opens one claim:

> The deterministic W1.4 mutation set enforces P4-P7 diagnostic precision for
> active Bridge/context/native boundary cases, including native receipt
> canonical-byte mutations.

It does not claim exhaustive mutation generation, randomized fuzzing, a separate
duplicate-key diagnostic, semantic equivalence, or receipt authenticity.
