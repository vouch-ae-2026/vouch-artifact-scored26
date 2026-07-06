# Vouch vNext Evidence Addendum

This directory is an additive evidence addendum for the anonymous Vouch artifact.
It preserves the original artifact surface and adds only vNext evidence records,
schemas, fixtures, and a local consistency check.

The original bundle remains the evidence object for the submitted artifact path.
This addendum does not replace any original receipt, contract, expected hash, or
checker file. It supplies additional records for transcription fidelity, zero
profile growth, deterministic disjointness checks, mutation checks, and seeded
divergence.

What this addendum can show:

- 676 mapped transcription cases agree with their declared oracle outputs.
- The profile growth review recommends zero profile admissions.
- Deterministic generated disjointness cases produce zero dual accepts.
- Artifact grammar and mutation gates fail closed on their active cases.
- A seeded divergence fixture records `comparison.status = disagree` and a first
  divergence.

What this addendum does not show:

- policy correctness
- semantic equivalence
- independent verification
- receipt authenticity
- issuer binding
- generation honesty
- exhaustive randomized fuzzing

Run `node vnext-evidence/scripts/check-vnext-evidence.mjs` from the bundle root
to check the addendum.
