# Transcription Complexity Metrics v0 Record

Status: W2.7 M2 static transcription complexity metrics.

This record adds static source metrics for the current M2 transcription corpus:

```text
manifests/transcription-complexity-metrics.v0.json
```

The manifest counts authored source surfaces only. It records rule case counts,
Lispex and upstream non-empty LOC, input leaf counts, `if` count, max list depth,
band identifiers, lookup tokens, arithmetic and comparison tokens, and
invalid-input classes.

## Machine Check

```sh
npm run check:transcription-complexity-metrics
```

The check requires every M2 rule to have pinned Lispex source bytes, nonzero
source metrics, correct total case accounting, and recorded invalid-input
classes.

## Boundary

These are static accounting metrics. They do not prove semantic complexity,
maintainability, policy correctness, semantic equivalence, full upstream
language coverage, independent verification, or receipt authenticity.
