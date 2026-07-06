# Seeded Divergence v0 Record

Status: W1.1 seeded-divergence drill.

This record replaces the earlier synthetic-only disagree coverage with an
executable seeded fixture:

```text
detection/seeded-divergence/cases/seeded-branch.lspx
detection/seeded-divergence/expected/seeded-branch.disagree.json
manifests/seeded-divergence.v0.json
```

The source first generates a normal `agree` differential receipt through the
Rust receipt-generation path. The drill then applies one deterministic,
test-only fault injection to the Meaning Environment transcript, recomputes the
Meaning Environment transcript hash, and records:

```text
comparison.status = disagree
comparison.reason = transcript-bytes-differ
comparison.first_divergence = { index: 0, reference: "1", meaning_env: "2" }
```

The resulting artifact is not a natural engine divergence and is not part of the
ordinary differential corpus. It is a seeded drill that proves the public verifier
accepts a self-consistent `disagree` receipt and rejects broken divergence
metadata.

## Machine Check

```sh
npm run check:seeded-divergence
```

The check regenerates the baseline receipt, reapplies the deterministic
injection, verifies the committed disagree receipt with `lispex verify --source`,
and compares the manifest against the committed artifact bytes.

## Negative Check

`check:seeded-divergence` mutates temporary copies and requires failure for:

- incorrect `first_divergence`
- incorrect disagree reason
- corrupted Meaning Environment transcript hash
- corrupted manifest artifact hash
- boundary overclaim that removes `natural-engine-divergence` from excludes

## Boundary

This slice opens one claim:

> The public verifier exercises the `disagree` branch over a seeded,
> self-consistent differential receipt and recomputes `first_divergence` from the
> recorded reference and Meaning Environment transcripts.

It does not claim a naturally observed engine divergence, semantic equivalence,
independent witnessing, production decision behavior, or source-corpus
observation.
