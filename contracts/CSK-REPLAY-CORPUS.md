# Replay Corpus Contract

Status: v1.3.6 contract for `lispex replay` corpora.

This document defines the small directory shape consumed by `lispex replay`.
It is intentionally narrower than a project repository. A replay corpus is a
baseline set of committed receipts plus a manifest that says which cases belong
to the set.

## 1. Directory Shape

```text
<corpus>/
  manifest.json
  expected/
    <case>.json
  cases/
    <case>.lspx      optional, used by examples and authors
  inputs/
    <case>.datum     optional, used by examples and authors
```

`manifest.json` and `expected/*.json` are required. `cases/` and `inputs/` are
not read by `lispex replay` in v1.3.6, but public examples SHOULD include them so
the same directory can demonstrate generation, verification, and replay.

## 2. Manifest

The manifest is deterministic JSON with this required shape:

```json
{
  "decision_gallery": "csk.profile-decision-gallery/v0",
  "status": "<human status string>",
  "policy": {
    "claim": "<bounded claim string>"
  },
  "cases": [
    {
      "stem": "<case>",
      "expected_transcript": ["<canonical datum text>"]
    }
  ]
}
```

`stem` binds a case to `expected/<stem>.json`. If `cases/<stem>.lspx` and
`inputs/<stem>.datum` exist, they are the authoring source and pinned input for
generating a fresh candidate receipt. `expected_transcript` is the transcript
that the baseline receipt must carry in `reference.transcript`.

Manifest entries MAY include `anchor` and `money_policy` objects. Those fields
are documentation and lint inputs. They are not replay comparison surfaces.

## 3. Replay Modes

`lispex replay <corpus> --against <version>` checks the baseline receipts in
`expected/` against a version string. Each receipt must have
`engine.version == <version>`, `comparison.status == "agree"`,
`input.status == "bound"`, and `reference.transcript` equal to the manifest
entry's `expected_transcript`.

`lispex replay <corpus> --against <receipts-dir>` compares the baseline receipts
in `<corpus>/expected` with candidate receipts in `<receipts-dir>`. Candidate
receipts must pass the same artifact precondition checks as baseline receipts.
Replay reports a byte change when a reference transcript, meaning-environment
transcript, comparison status, or input hash changes.

The command emits `csk.replay-report/v0` JSON to stdout. Exit code `0` means no
behavioral change was found. Exit code `1` means changed behavior or failed
preconditions. Exit code `2` means usage or I/O failure.

## 4. Public Example

`examples/vouch-loop` is the minimal public corpus. It contains one rule, one
input datum, one committed baseline receipt, and a README with the native
generation command:

```sh
lispex diff-receipt --input examples/vouch-loop/inputs/refund-window.datum examples/vouch-loop/cases/refund-window.lspx > examples/vouch-loop/receipts/current/refund-window.json
```

That fresh receipt can be checked with `lispex verify` and compared with:

```sh
lispex replay examples/vouch-loop --against examples/vouch-loop/receipts/current
```

## 5. Boundary

A replay corpus compares recorded receipts. It does not prove that a receipt was
generated honestly, that input data is authentic, that a decision was applied,
when it was applied, or that a deployed system used the same rule. Those are
authenticity, provenance, timestamping, deployment, and review concerns outside
the replay corpus contract.

Boundary excludes use the same names as replay reports where they overlap:
`generation-honesty`, `receipt-authenticity`, `input-provenance`,
`non-repudiation`, and `external-independent-verification`.
