# JSON Logic Shallow Oracle v0 Record

Status: W1.5 JSON Logic shallow transcription-fidelity oracle harness.

This record adds the first M2-style offline evaluation harness:

```text
manifests/jsonlogic-shallow-oracle.v0.json
```

The harness compares two existing JSON Logic-shaped decision gallery rules
against declared JSON Logic rule objects and declared input/output maps. It runs
the same generated input through:

- the Lispex CSK Profile transcription, using `diff-receipt`
- a local JSON Logic operations subset evaluator for the documented operators
  used by the two rules

The comparison is a transcription-fidelity oracle. It is not an independent
verifier, a full JSON Logic implementation, or a policy-correctness claim.

## Corpus

- `jsonlogic-pie-ready`: 64 deterministic boundary-style inputs
- `jsonlogic-required-fields`: 4 boolean required-field inputs

All 68 cases pin the input datum hash under `csk/profile-input-hash/v0` and
compare the Lispex transcript against the declared upstream output map.

## Machine Check

```sh
npm run check:jsonlogic-shallow-oracle
```

The check regenerates the ledger, requires all cases to agree, and requires the
partiality audit to cover every transcribed rule.

## Negative Check

`check:jsonlogic-shallow-oracle` mutates temporary in-memory copies and requires
failure for:

- a case marked as `disagree`
- removed partiality audit coverage
- nonzero fault-derived not-comparable count
- output-map drift
- boundary overclaim that removes `external-independent-verification` from
  excludes

## Boundary

This slice opens one claim:

> The W1.5 JSON Logic shallow harness compares 68 generated cases through a
> declared input/output map and records zero transcription disagreements with a
> partiality audit.

It does not claim independent verification, full JSON Logic language coverage,
policy correctness, upstream engine completeness, semantic equivalence, or
receipt authenticity.
