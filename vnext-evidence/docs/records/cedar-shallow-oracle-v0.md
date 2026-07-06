# Cedar Shallow Oracle v0 Record

Status: W2.1 Cedar shallow transcription-fidelity oracle harness.

This record adds the second M2-style offline evaluation harness:

```text
manifests/cedar-shallow-oracle.v0.json
```

The harness compares two shallow Cedar-shaped authorization policies against
Lispex CSK Profile transcriptions. It runs the same generated request data
through:

- the Lispex CSK Profile transcription, using `diff-receipt`
- a local evaluator for the two documented Cedar-style policy patterns used by
  this fixture set

The comparison is a transcription-fidelity oracle. It is not an independent
verifier, a Cedar engine, Cedar Analysis, a full Cedar implementation, or a
policy-correctness claim.

## Corpus

- `cedar-specific-photo`: 32 deterministic request inputs
- `cedar-owner-or-public-photo`: 32 deterministic request inputs

All 64 cases pin the input datum hash under `csk/profile-input-hash/v0` and
compare the Lispex transcript against the declared upstream output map.

## Machine Check

```sh
npm run check:cedar-shallow-oracle
```

The check regenerates the ledger, requires all cases to agree, and requires the
partiality audit to cover every transcribed rule.

## Negative Check

`check:cedar-shallow-oracle` mutates temporary in-memory copies and requires
failure for:

- a case marked as `disagree`
- removed partiality audit coverage
- nonzero fault-derived not-comparable count
- output-map drift
- oracle-strength overclaim
- boundary overclaim that removes `external-independent-verification` from
  excludes

## Boundary

This slice opens one claim:

> The W2.1 Cedar shallow harness compares 64 generated request cases through a
> declared input/output map and records zero transcription disagreements with a
> partiality audit.

It does not claim independent verification, full Cedar language coverage, Cedar
Analysis symbolic guarantees, policy correctness, upstream engine completeness,
semantic equivalence, or receipt authenticity.
