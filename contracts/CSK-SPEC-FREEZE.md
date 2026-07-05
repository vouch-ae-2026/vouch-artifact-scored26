# CSK Spec Freeze Contract v0

> Status: v1.2.16 freeze contract.
> This document freezes shared byte rules, report and receipt hash preimages,
> artifact neutrality rules, and the authored-vector/generated-golden split for
> the Lispex CSK Profile evidence path. It does not add source semantics,
> builtins, or proof claims.

## 1. Purpose

v1.2.16 is the byte-contract freeze before release-audit and public v1.3
promotion work. The freeze exists so cold-review bundles and future release
checks can compare artifacts by bytes rather than by prose interpretation.

The Rust reference interpreter remains the operational authority for the full
Lispex language. The frozen contracts describe the checked CSK Profile artifact
surface only.

The freeze contract tag is:

```text
csk.spec-freeze/v0
```

## 2. Deterministic JSON Byte Profile

The shared artifact JSON profile tag is:

```text
csk.artifact-json/v0
```

All committed CSK v0 JSON artifacts that participate in receipts, reports,
ledgers, manifests, cold-review bundles, or generated goldens use this shared
byte profile unless their owning contract narrows it further:

- UTF-8 bytes, no byte order mark.
- LF line endings only.
- Two-space indentation.
- Exactly one trailing LF.
- No trailing whitespace.
- Object field order is the order specified by the owning contract, schema, or
  generating writer. Field order is part of the artifact bytes and is not
  sorted unless the owning contract explicitly says so.
- Unknown fields are illegal in frozen artifacts.
- Optional fields are omitted, not emitted as `null`, unless the owning contract
  gives `null` a meaning value. Existing meaning values include
  `first_divergence`, `fault_class`, and other explicitly nullable status
  fields.
- Strings are JSON strings; exact numbers, rationals, datums, money amounts,
  and decision amounts that need canonical numeric identity are carried as
  canonical text, not JSON numbers, when their owning contract says so.
- JSON numbers are allowed only for structural bounded integers such as indexes,
  counts, exit codes, byte lengths, and step counts.
- Unicode text is not normalized, folded, or re-escaped beyond the JSON writer's
  deterministic escaping rules.

String escaping is pinned by the cross-writer fixture under
`artifact-json/fixtures/cross-writer-strings.json` and `npm run
check:artifact-json`. Rust `serde_json` and JavaScript `JSON.stringify` must
emit the same bytes for:

| Value class                     | Required behavior                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `"`                             | escape as `\"`                                                                    |
| `\`                             | escape as `\\`                                                                    |
| control characters below U+0020 | escape with JSON control escapes or lowercase `\u00xx` as produced by the fixture |
| non-ASCII scalar values         | emit deterministic UTF-8 text, not writer-dependent alternate spellings           |
| U+2028 and U+2029               | preserve the fixture's cross-writer byte spelling                                 |

Committed artifacts and reports used as evidence must be path-neutral and
host-neutral. They must not embed absolute paths, current working directories,
home/temp directory names, wall-clock timestamps, elapsed timing fields,
hostnames, user names, or platform-specific path separators.
Repository-relative paths use `/`.

`drill-result.json` artifacts are the deliberate exception: they may record
reviewer environment and start/end time fields, but they are not report or
receipt hash preimages.

## 3. Frozen Hash Preimages

Every hash below uses SHA-256 and the preimage:

```text
<domain>\0<payload-bytes>
```

where `\0` is byte `0x00`. Displayed digests are lowercase 64-character
hexadecimal strings.

Domain inventory:

| Domain                                  | Status   | Payload bytes                                                                | Owning contract               |
| --------------------------------------- | -------- | ---------------------------------------------------------------------------- | ----------------------------- |
| `lispex/source-hash/v0`                 | active   | raw source bytes                                                             | `CSK-RECEIPT.md`              |
| `lispex/core-hash/v0`                   | active   | Canonical Core v0 program bytes                                              | `CSK-CANONICAL-CORE.md`       |
| `lispex/runtime-hash/v0`                | active   | reference stdout transcript bytes                                            | `CSK-RECEIPT.md`              |
| `lispex/engine-version/v0`              | reserved | none in v0                                                                   | `CSK-CANONICAL-CORE.md`       |
| `csk/profile-input-hash/v0`             | active   | canonical input datum bytes                                                  | `CSK-PROFILE.md`              |
| `csk/meaning-graph-hash/v0`             | active   | deterministic Meaning Graph JSON bytes                                       | `CSK-MEANING-LOWERING.md`     |
| `csk/meaning-env-transcript-hash/v0`    | active   | Meaning Environment transcript bytes                                         | `CSK-DIFFERENTIAL-RECEIPT.md` |
| `csk/meaning-env-report-hash/v0`        | active   | `csk.artifact-json/v0` `csk.meaning-env-report/v0` JSON bytes                | `CSK-MEANING-ENVIRONMENT.md`  |
| `csk/differential-receipt-hash/v0`      | active   | `csk.artifact-json/v0` `csk.differential-receipt/v0` JSON bytes              | `CSK-DIFFERENTIAL-RECEIPT.md` |
| `csk/verify-report-hash/v0`             | active   | `csk.artifact-json/v0` `csk.verify-report/v0` JSON bytes                     | `CSK-VERIFY-REPLAY.md`        |
| `csk/replay-report-hash/v0`             | active   | `csk.artifact-json/v0` `csk.replay-report/v0` JSON bytes                     | `CSK-VERIFY-REPLAY.md`        |
| `csk/decision-gallery-manifest-hash/v0` | active   | `csk.artifact-json/v0` `csk.profile-decision-gallery/v0` manifest JSON bytes | `CSK-VERIFY-REPLAY.md`        |
| `csk/oracle-source-hash/v0`             | active   | oracle fixture source bytes                                                  | `CSK-SCHEME-ORACLE.md`        |
| `csk/oracle-program-hash/v0`            | active   | generated Scheme program bytes                                               | `CSK-SCHEME-ORACLE.md`        |
| `vouch/external-source-hash/v0`         | active   | external source bytes                                                        | `VOUCH-BRIDGE.md`             |
| `vouch/external-target-hash/v0`         | active   | external target bytes                                                        | `VOUCH-BRIDGE.md`             |
| `vouch/linked-artifact-hash/v0`         | active   | linked proof or gate artifact bytes                                          | `VOUCH-BRIDGE.md`             |
| `vouch/bridge-report-hash/v0`           | active   | `csk.artifact-json/v0` `vouch.bridge-report/v0` JSON bytes                   | `VOUCH-BRIDGE.md`             |
| `vouch/bridge-verify-report-hash/v0`    | active   | `csk.artifact-json/v0` `vouch.bridge-verify-report/v0` JSON bytes            | `VOUCH-BRIDGE.md`             |

Any future hash domain must be added to this inventory in the same slice that
introduces it.

No report or receipt may embed a `self_hash` field. The hash of a report or
receipt, when a future bundle records it, is stored outside the report: either
as a sibling `.sha256` file or in a bundle manifest. It covers the exact artifact
bytes including the commit hex.

Layer A is repository golden comparison. It may mask `engine.commit.hex` or
`verifier.commit.hex` while still requiring 40-hex shape and `dirty:false`,
because otherwise a commit that records regenerated goldens would invalidate
itself. Layer A is a diff/check operation, not a report-hash operation.

Layer B is release and cold-review bundle comparison. It uses a clean release
commit and exact artifact bytes with no commit masking. Expected hashes live
outside reports and receipts, and a bundle is bound to one fixed commit.

## 4. Artifact Field Order

Field order is frozen by the owning contract for each artifact:

- Canonical Core bytes: `CSK-CANONICAL-CORE.md`.
- Meaning Graph JSON: `CSK-MEANING-GRAPH.md` and `CSK-MEANING-LOWERING.md`.
- Meaning Environment reports: `CSK-MEANING-ENVIRONMENT.md`.
- Differential receipts: `CSK-DIFFERENTIAL-RECEIPT.md`.
- Verify/replay reports: `CSK-VERIFY-REPLAY.md`.
- Scheme oracle manifest and ledger: `CSK-SCHEME-ORACLE.md`.
- Claims registry: `schemas/csk.claims.schema.v0.json`.
- Cold-review bundle and drill result: `docs/CSK-COLD-REVIEWER-DRILL.md` and
  the matching schemas under `schemas/`.

Changing field order in any frozen artifact is a byte change. A compatible patch
may clarify prose, add generated cases, or add non-normative examples, but it may
not silently alter v0 artifact bytes.

## 5. Authored Vectors And Generated Goldens

The authoritative vector split is recorded in:

```text
semantic-vectors/manifest.json
```

Authored vectors are spec-status inputs. Changing them requires an ADR or an
explicit roadmap slice note before the generated artifacts are regenerated.

Generated goldens are implementation outputs. They may be rewritten only by
their owning generator/check command, and close gates must include a clean HEAD
regeneration pass whose diff is zero.

No generated golden may become the sole source of truth for a semantic decision.
When an implementation mismatch appears, it is a design input, not permission to
silently edit the authored vector or relabel the Rust path as correct.

## 6. Public Boundary

v1.2.16 attests only:

- deterministic JSON byte-profile rules for v0 artifacts
- cross-writer JSON escaping compatibility between Rust and JavaScript
- report and receipt hash preimage definitions
- path-neutral and host-neutral artifact requirements
- authored-vector/generated-golden separation
- same-origin verifier boundary disclosure through `CSK-VERIFY-REPLAY.md`

v1.2.16 explicitly excludes:

- semantic-equivalence proofs
- formal verification
- external independent verification
- spec-blind third-party reimplementation
- whole-language coverage
- target-code generation
- regulatory or non-repudiation claims
- private implementation detail

## 7. Slice Close

v1.2.16 closes only when:

- this contract is covered by `npm run check:spec-freeze`
- artifact JSON escaping is covered by `npm run check:artifact-json`
- committed artifact neutrality is covered by `npm run check:path-neutral-json`
- claims registry validation is covered by `npm run check:public-claims`
- verify/replay and differential contracts reference the frozen report/receipt
  preimages instead of deferring them
- the cold-review drill protocol is committed but not executed
- generated artifacts affected by version or byte-profile changes are
  regenerated once
- a clean HEAD regeneration gate reports diff zero
- version surfaces move to `1.2.16`
