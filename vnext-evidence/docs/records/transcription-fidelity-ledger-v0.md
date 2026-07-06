# Transcription Fidelity Ledger v0 Record

Status: W2.3 M2 transcription-fidelity ledger.

This record adds the aggregate M2 ledger:

```text
manifests/transcription-fidelity-ledger.v0.json
```

The ledger reads the current oracle manifests for JSON Logic shallow, Cedar
shallow, and OpenFisca Core deep transcription harnesses. It records their
source manifest hashes, per-rule axes, per-case outcome axes, and summary
metrics without re-running the upstream engines.

## Machine Check

```sh
npm run check:transcription-fidelity-ledger
```

The check requires:

- every source manifest to remain hash-pinned
- every case to carry an input hash and valid outcome axis
- zero unresolved disagreements in the current corpus
- zero fault-derived not-comparable cases
- at least one executable-engine rule axis
- at least one invalid-input case axis

## Boundary

The ledger is an accounting artifact. It attests that the M2 oracle manifests
are pinned and that their rule/case axes are aggregated consistently.

It does not claim independent verification, semantic equivalence, policy
correctness, legal policy status, full upstream language coverage, regulatory
approval, or receipt authenticity.
