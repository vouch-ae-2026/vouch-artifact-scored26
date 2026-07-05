# CSK Verify And Replay Contract v0

> Status: v1.2.16-compatible contract for npm CLI verify/replay artifacts.
> This document specifies offline checks over existing CSK differential receipt
> artifacts. It does not define a receipt generator, does not execute Lispex
> source, and does not authenticate receipt origin.

## 1. Purpose

`lispex verify` and `lispex replay` make the v1.2 decision artifacts usable
outside the native Rust CLI.

Replay corpus directory shape is specified in `CSK-REPLAY-CORPUS.md`. This
document owns the command and report artifacts. The corpus contract owns
`manifest.json`, `expected/*.json`, and the public example corpus shape.

The commands are intentionally boring. They read deterministic JSON artifacts,
recompute only hashes whose preimage bytes are embedded in the receipt, compare
receipt sets, and emit deterministic JSON reports that state whether the
artifacts are internally consistent with the public v0 contracts.

For the full Lispex language, the Rust reference interpreter remains the
operational authority. The npm verify/replay path is not a second evaluator.

## 2. Commands

The npm CLI exposes:

```text
lispex verify <receipt.json>
lispex verify --source <file.lspx> <receipt.json>
lispex replay <corpus> --against <version-or-receipts-dir>
```

Exit codes are pinned:

- verify `0`: the artifact check passed and stdout contains a
  `csk.verify-report/v0` report.
- verify `1`: the artifact was readable, but failed a contract, hash, boundary,
  or policy check; stdout still contains a `csk.verify-report/v0` report.
- replay `0`: no behavioral change was found and stdout contains a
  `csk.replay-report/v0` report.
- replay `1`: a behavioral change or replay precondition failure was found and
  stdout still contains a `csk.replay-report/v0` report.
- `2`: usage, I/O, or JSON parse failure.

stdout is reserved for the JSON report. Human-readable summaries, when printed,
go to stderr.

`lispex verify` accepts only `csk.differential-receipt/v0` receipts in v1.2.13.
It does not accept `lispex.receipt/v0` because that older receipt does not embed
enough payload bytes for an offline npm checker to recompute its key hashes.

## 3. Verify Scope

`lispex verify` emits exactly one `csk.verify-report/v0` JSON object to stdout
when it exits `0` or `1`. The report includes:

- `verify_report: "csk.verify-report/v0"`
- `verifier` with checker name, version, required `commit`, and
  `authorship_boundary: "same-origin-public-spec-checker"`
- `inputs` with target receipt path, detected tag, and optional supplied source
  path
- `checks.recomputed`
- `checks.recorded_only`
- `summary` with `status`, `exit_code`, and `failure_count`
- `boundary`
- `diagnostics`

The verify-report hash domain is:

```text
csk/verify-report-hash/v0
```

The verify-report hash preimage is frozen by `CSK-SPEC-FREEZE.md` as:

```text
csk/verify-report-hash/v0\0<verify-report-json-bytes>
```

The report hash is defined only for committed artifacts that satisfy
`csk.artifact-json/v0`. Ad-hoc local CLI output that embeds local paths or other
non-neutral metadata is not a hash-preimage target. The report does not embed
its own hash in v0.

The verifier recomputes these checks:

- Meaning Environment transcript hash:
  `csk/meaning-env-transcript-hash/v0\0<transcript-bytes>`, where transcript
  bytes are every embedded transcript entry followed by LF.
- Reference transcript hash:
  `lispex/runtime-hash/v0\0<stdout-bytes>`, but only when the embedded transcript
  entries reconstruct the recorded byte length exactly.
- Profile input hash:
  `csk/profile-input-hash/v0\0<input-datum-canonical-bytes>`, using the embedded
  canonical datum string bytes exactly as written.
- Source hash, only when the caller supplies `--source <file.lspx>`.

The reference transcript reconstructibility gate is load-bearing. The Rust
receipt stores raw stdout byte length but embeds transcript entries after
splitting on LF terminators. Rejoining each entry plus LF is sound only when the
rejoined byte length equals `reference.transcript_byte_len`. If an `agree`
receipt cannot pass that equality check, the verifier fails it with
`reference-hash-not-recomputable`.

The verifier treats these fields as recorded-only unless the caller supplied the
missing preimage bytes:

- `source.hash` without `--source`
- `canonical.hash`
- `graph.hash`

Recorded-only still means structurally checked: the hash object must carry the
pinned domain, `sha-256`, and lowercase hex.

## 4. Receipt Consistency

The verifier checks:

- receipt tag `csk.differential-receipt/v0`
- engine name `lispex-rust-reference`
- canonical format `lispex.core.canonical/v0`
- `engine.commit` with `{ "vcs": "git", "hex": <40-hex>, "dirty": false }`,
  interpreted as the receipt producer's release build identity for native
  v1.3.2+ artifacts
- required top-level fields
- hash object shape and domain strings
- `comparison.status` coherence:
  - `agree`: both transcript producers are `ok`, transcript arrays match, and
    `first_divergence` is `null`
  - `disagree`: both transcript producers are `ok`, transcript arrays differ,
    and `first_divergence` names the first differing index
  - `not-comparable`: reason is one of the six pinned reasons, agrees with the
    stage-failure precedence, `fault_class` matches the primary blocker, and
    `blockers[0]` is the primary blocker
- exact boundary lists

The pinned `not-comparable` primary reason order is:

1. `read-error`
2. `normalize-error`
3. `lowering-fault`
4. `input-error`
5. `reference-runtime-error`
6. `meaning-env-fault`

## 5. Replay Scope

`lispex replay` emits exactly one `csk.replay-report/v0` JSON object to stdout
when it exits `0` or `1`. The report includes:

- `replay_report: "csk.replay-report/v0"`
- `verifier` with checker name, version, required `commit`, and
  `authorship_boundary: "same-origin-public-spec-checker"`
- `mode: "rule-change"`
- `corpus` with id, tag, case count, and `manifest_hash`
- `against` with kind, value, and optional source hash
- `cases`
- `summary`
- `boundary`
- `diagnostics`

The replay-report hash domain is:

```text
csk/replay-report-hash/v0
```

The replay-report hash preimage is frozen by `CSK-SPEC-FREEZE.md` as:

```text
csk/replay-report-hash/v0\0<replay-report-json-bytes>
```

The report hash is defined only for committed artifacts that satisfy
`csk.artifact-json/v0`. Ad-hoc local CLI output that embeds local paths or other
non-neutral metadata is not a hash-preimage target. The report does not embed
its own hash in v0.

The decision-gallery manifest hash domain is:

```text
csk/decision-gallery-manifest-hash/v0
```

Its preimage is frozen by `CSK-SPEC-FREEZE.md` as:

```text
csk/decision-gallery-manifest-hash/v0\0<decision-gallery-manifest-json-bytes>
```

Each replay case record has a required byte-comparison layer:

- `case_id`
- `input_hash`
- `old.source_hash`
- `old.transcript_hash`
- `old.status`
- `old.fault_class`
- `new.source_hash`
- `new.transcript_hash`
- `new.status`
- `new.fault_class`
- `changed`

It also carries optional decision projection with `decision`. The required byte
layer above is the only comparison surface guaranteed by replay-report v0, and
the case-level `changed` flag is computed from that byte layer. The decision
layer is a convenience projection over transcript text.

Replay compares rule changes by reconstructing the differential pipeline per
case from existing receipt artifacts. The `old.status` and `new.status` fields
are differential `comparison.status` values. When a side is `agree`, its
`transcript_hash` uses the `lispex/runtime-hash/v0` domain over the reference
transcript bytes, and that transcript is also the lowered-subset agreement
surface for that side.

Projection is attempted for a side only when that side has
`comparison.status = "agree"`, `reference.status = "ok"`,
`meaning_env.status = "ok"`, transcript length `1`, and the single transcript
entry is a canonical `csk.decision-datum/v0` datum:

```text
(decision allow)
(decision deny <reason-symbol>)
(decision amount <exact-integer-cents> <reason-symbol>)
(decision invalid-input <reason-symbol>)
```

`<reason-symbol>` is a canonical symbol token. `<exact-integer-cents>` is an
exact integer rendered as decimal text. The JSON projection must encode amount
fields as canonical integer strings, for example `"amount_cents": "9950"` or
`"amount_delta_cents": "-50"` if a future report adds a delta. JSON numbers are
forbidden for projected money fields.

When projection succeeds or fails in a reportable way, `decision` has:

- `old`: side projection object or `null` when the old side is absent
- `new`: side projection object or `null` when the new side is absent
- `decision_changed`: JSON comparison of the two projected decision values when
  both sides projected, otherwise `null`

A projected side has:

- `status: "projected"`
- `datum`: the transcript datum text
- `value.decision_datum: "csk.decision-datum/v0"`
- `value.kind: "allow" | "deny" | "amount" | "invalid-input"`
- optional `value.reason`
- optional `value.amount_cents` as a string for `amount`

A non-projected side has `status: "not_projected"` and one closed reason:

- `not-attempted-case-not-agree`
- `not-attempted-runtime-or-meaning-fault`
- `not-projectable-empty-transcript`
- `not-projectable-multiple-transcript-datums`
- `not-projectable-non-canonical-datum`
- `not-projectable-unknown-decision-shape`
- `not-projectable-invalid-reason`
- `not-projectable-amount-not-exact-integer`

If both sides are absent, `decision` is `null`. `(decision invalid-input
<reason-symbol>)` is a normal decision output convention; it is distinct from a
profile input parse/hash/domain failure or runtime/meaning fault, which remains
represented by receipt status, `fault_class`, and blockers and is not projected.
Replay-report v0 has one report-level `verifier` object for rule-change replay.
Old/new engine-upgrade fields are absent in v0, not present as `null`.

`lispex replay <corpus> --against <version-or-receipts-dir>` accepts a decision
gallery directory containing:

```text
manifest.json
cases/*.lspx
inputs/*.datum
expected/*.json
```

The manifest tag must be `csk.profile-decision-gallery/v0`.

Before replay comparison, every baseline receipt in `expected/*.json` must pass
`lispex verify`'s core checks.

Version mode is selected when `--against` is a semver-like string such as
`1.2.14` or `v1.2.14`. Version mode checks:

- every receipt engine version equals the requested version
- every receipt has `comparison.status = "agree"`
- every receipt has `input.status = "bound"`
- every reference transcript matches the manifest `expected_transcript`

Receipt-directory mode is selected when `--against` is an existing directory.
The directory must contain candidate receipt JSON files keyed by the same stems
as the corpus baseline. Candidate receipts must pass the same verify core.

Receipt-directory replay classifies as behavioral:

- added or removed receipt stems
- reference transcript byte changes
- Meaning Environment transcript byte changes
- `comparison.status` changes
- profile input hash changes

If only recorded metadata changes, replay exits `0` and reports that no
behavioral differences were found. If any behavioral difference is found, replay
exits `1` and names the affected stems.

## 6. Authorship And Independence Boundary

The npm verify/replay path is a same-origin JavaScript artifact checker.

It does not execute the Lispex Rust reference interpreter, does not link the
Rust crate or WebAssembly module for verify/replay, and does not parse or
evaluate Lispex source. Its checks are over already-emitted JSON receipt and
gallery artifacts.

That makes the path implementation-blind with respect to the Rust evaluator's
runtime execution, but it is not external independent verification. The checker
lives in the same repository and authorial loop as the Rust implementation and
the public contracts. Public claims must therefore say same-origin JS checker or
offline artifact checker, not spec-blind third-party reimplementation,
independently verified, or externally validated.

The future cold-review drill may add outside reproducibility evidence, but a
drill result is a separate artifact and must not be implied by this contract.

## 7. Public Boundary

Verify/replay establishes artifact self-consistency only.

The commands do not attest:

- receipt authenticity
- generation honesty
- semantic equivalence
- substrate independence
- external independent verification
- spec-blind third-party reimplementation
- input provenance
- Topaz reporting
- full Core Semantic Kernel coverage
- target code generation

The receipt boundary lists must remain exact. v1.2.16 attests only:

- `source-bytes`
- `profile-input-hash-binding`
- `canonical-core-v0-bytes`
- `meaning-graph-v0-hash-binding`
- `reference-transcript-bytes`
- `meaning-env-transcript-bytes`
- `lowered-subset-transcript-agreement`

v1.2.16 explicitly excludes:

- `semantic-equivalence`
- `independent-witness`
- `external-independent-verification`
- `spec-blind-third-party-reimplementation`
- `substrate-independence`
- `error-agreement`
- `input-provenance`
- `topaz-reporting`
- `full-cskernel-coverage`
- `target-code-generation`
- `private-implementation-detail`

## 8. Non-Goals

v1.2.13 does not:

- add a wasm export
- shell out to Cargo from the npm CLI
- parse Lispex or canonical datum syntax in JavaScript
- generate or regenerate differential receipts
- compare artifacts against an external system
- change Rust evaluation behavior

The native Rust CLI remains the receipt generation authority.

## 9. Changelog

- v1.2.13 amended close: verify/replay stdout is a JSON artifact contract, not a
  human UX string contract.
- v1.2.13 amended close: report hash domains
  `csk/verify-report-hash/v0` and `csk/replay-report-hash/v0` are reserved only;
  preimage definitions wait for v1.2.16.
- v1.2.13 amended close: differential receipt comparison adds `fault_class` and
  `blockers`, and primary order is read, normalize, lowering, input, reference,
  meaning-env. This is documented schema evolution, not silent relabeling.
- v1.2.13 amended close: expected-artifact comparison masks
  `engine.commit.hex` while requiring 40-hex shape and `dirty:false`.
- v1.2.14: replay-report fills the optional decision projection when a case
  transcript contains exactly one conforming gallery decision datum. The
  required byte layer remains the normative replay comparison surface.
- v1.2.16: verify-report and replay-report hash preimages are frozen as
  `<domain>\0<report-json-bytes>`, and this contract discloses the same-origin
  JavaScript checker boundary.

## 10. Slice Close

v1.2.13 closes only when:

- `lispex verify` passes the decision gallery and differential receipt corpus
- tampered receipt fixtures fail with stable reason strings
- `lispex verify` emits `csk.verify-report/v0` JSON to stdout
- `lispex replay` emits `csk.replay-report/v0` JSON to stdout
- `lispex replay profile-gallery/decision-gallery --against <current-version>`
  passes after generated goldens carry that version
- replay receipt-directory mode rejects a synthetic behavioral change and
  accepts a metadata-only change
- `npm run check:verify-replay` is in the root `npm run check` chain
- public boundary checks cover this document and the new CLI text
- version surfaces move to `1.2.13` only after the slice is otherwise closed
