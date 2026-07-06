# OpenFisca Core Deep Oracle v0 Record

Status: W2.2 OpenFisca Core deep transcription-fidelity oracle harness.

This record adds the first executable upstream harness for the M2 program:

```text
manifests/openfisca-core-deep-oracle.v0.json
```

The harness compares one OpenFisca Core tax-benefit style formula against its
Lispex CSK Profile transcription. It runs the same generated person inputs
through:

- OpenFisca Core 44.7.0, installed into a repo-local cache when absent
- the Lispex CSK Profile transcription, using `diff-receipt`

The comparison is a transcription-fidelity oracle. It is not an independent
verifier, a legal benefit model, a full OpenFisca language coverage claim, a
PolicyEngine runtime coverage claim, or a policy-correctness claim.

## Corpus

- `openfisca-core-benefit-taper`: 544 deterministic person inputs
- period fixed to `2026`
- parameters pinned by `vouch/openfisca-parameter-data-hash/v0`
- application-level invalid inputs represented as deterministic
  `(decision invalid-input bad-input)` decisions

All cases pin the input datum hash under `csk/profile-input-hash/v0` and compare
the Lispex transcript against the declared upstream output map.

## Machine Check

```sh
npm run check:openfisca-core-deep-oracle
```

The check regenerates the ledger, requires all cases to agree, requires a
nonzero invalid-input class, and requires the partiality audit to cover every
transcribed rule.

## Negative Check

`check:openfisca-core-deep-oracle` mutates temporary in-memory copies and
requires failure for:

- a case marked as `disagree`
- removed partiality audit coverage
- nonzero fault-derived not-comparable count
- removed parameter data hashes
- oracle-strength drift
- boundary overclaim that removes `policy-correctness` from excludes
- invalid-input class removal

## Boundary

This slice opens one claim:

> The W2.2/W2.5 OpenFisca Core harness compares 544 generated person cases through a
> declared input/output map and records zero transcription disagreements against
> an executable OpenFisca Core upstream.

It does not claim independent verification, legal benefit correctness, full
OpenFisca language coverage, full PolicyEngine runtime coverage, semantic
equivalence, runtime external fetch, float semantics, or receipt authenticity.
