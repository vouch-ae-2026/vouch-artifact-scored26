# Lispex Vouch Bridge Contract v0

> Status: v1.3.11 contract for external-engine evidence reports.
> This document is the public contract for `vouch.bridge-report/v0`,
> `vouch.bridge-context-manifest/v0`, and the `lispex verify-bridge` checker.
> It defines the Bridge artifact class, byte acceptance rule, hash domains,
> context checks, and boundary declarations. It does not make Lispex the runtime
> for external engines, and it does not make Vouch a correctness oracle for
> generated target code.

## 1. Purpose

Lispex Vouch started with one checked Lispex rule, one pinned input, one native
differential receipt, offline verify, and replay. The Bridge extends the same
evidence discipline to external engines that already have their own gates.

The first Bridge profile is conversion evidence. An external conversion engine
may run its own pipeline, produce its own proof or gate report, and then emit a
Vouch Bridge report that binds:

- source bytes
- target bytes
- engine identity
- declared route and capability ids
- declared gate results
- linked proof-artifact hashes
- an explicit attests/excludes boundary

The public checker validates the Bridge report shape, canonical bytes, declared
boundary, and optional consumer-supplied byte/context bindings. It does not run
the external engine, inspect private implementation details, judge whether the
target code is correct, or prove whole-language semantic equivalence.

## 2. Naming and Artifact Class

The implementation-family pattern is `{language or engine} Vouch`. Lispex Vouch
is the first and reference implementation. A Bridge report is not called
`CSK Vouch`, and Vouch itself is not marked as a trademark.

External engines SHOULD use their own namespace for private proof artifacts. The
public Bridge artifact uses this tag:

```text
vouch.bridge-report/v0
```

The npm checker emits this report tag:

```text
vouch.bridge-verify-report/v0
```

A Bridge report is a separate artifact class from a native differential receipt
(`csk.differential-receipt/v0`). It is accepted by a separate verifier
entrypoint and has a different required field set. Bridge evidence is accepted
only as external evidence; it is not promoted into native transcript agreement.

## 3. Command and Exit Codes

The npm CLI exposes:

```text
lispex verify-bridge <report.json>
lispex verify-bridge --source <source-file> --target <target-file> <report.json>
lispex verify-bridge --linked <artifact-id>=<artifact-file> <report.json>
lispex verify-bridge --expect-context <manifest.json> <report.json>
```

The options can be combined.

Exit codes are pinned:

- `0`: the Bridge report passed structure, boundary, and requested byte/context
  checks.
- `1`: the Bridge report was readable, but failed a schema, hash, boundary,
  canonical-byte, or context check. stdout still contains a
  `vouch.bridge-verify-report/v0` report.
- `2`: usage, I/O, or JSON parse failure.

stdout is reserved for JSON. Human-readable summaries go to stderr.

The optional `--source`, `--target`, `--linked`, and `--expect-context` inputs
are consumer-side checks. They do not make the consumer a trust authority. They
answer only whether the report is bound to the bytes and subject context the
consumer intended to inspect.

## 4. Hash Domains

All Bridge hashes use SHA-256 over:

```text
<domain>\0<payload-bytes>
```

| Domain                               | Status | Payload bytes                                              |
| ------------------------------------ | ------ | ---------------------------------------------------------- |
| `vouch/external-source-hash/v0`      | active | external source bytes                                      |
| `vouch/external-target-hash/v0`      | active | external target bytes                                      |
| `vouch/linked-artifact-hash/v0`      | active | linked proof or gate artifact bytes                        |
| `vouch/bridge-report-hash/v0`        | active | `csk.artifact-json/v0` `vouch.bridge-report/v0` JSON bytes |
| `vouch/bridge-verify-report-hash/v0` | active | `csk.artifact-json/v0` Bridge verify report JSON bytes     |

Bridge report hashes are stored outside the report in release, review, or
artifact-evaluation manifests. A Bridge report MUST NOT embed `self_hash`.

## 5. Read-Side Byte Acceptance

Bridge verification reads artifacts in this order:

1. Read raw bytes.
2. Parse JSON only to obtain a candidate value.
3. Re-serialize that candidate value with the `csk.artifact-json/v0` writer for
   `vouch.bridge-report/v0`.
4. Byte-compare the canonical bytes with the submitted raw bytes.
5. If they differ, fail before semantic interpretation with
   `non-canonical-artifact-json`.
6. Only after canonical byte acceptance, run recursive closed-world schema
   checks and semantic checks.

Compact JSON, CRLF line endings, duplicate keys that collapse through the
JavaScript parser, key-order variants, and whitespace variants are not accepted
as Bridge artifacts. The current implementation does not expose raw JSON tokens,
so it does not claim a separate `duplicate-key` failure class. Duplicate-key
cases fail as `non-canonical-artifact-json` in this implementation.

This read-side canonical acceptance is a Bridge artifact-class rule. It does not
claim read-side canonical enforcement for all artifact classes.

## 6. Recursive Closed-World Schema

Canonical bytes alone are not enough. A canonical report could still carry a
trust-smuggling field such as `engine.extra` or
`subject.route.semantic_proof`. Therefore every schema-defined object layer is
closed after canonical byte acceptance.

The closed object layers are:

- root
- `profile`
- `engine`
- `engine.commit`
- `subject`
- `subject.source`
- `subject.source.hash`
- `subject.target`
- `subject.target.hash`
- `subject.route`
- each `checks[]`
- each `checks[].artifact_hash`
- each `linked_artifacts[]`
- each `linked_artifacts[].hash`
- `summary`
- `boundary`
- each `diagnostics[]`

Unknown fields fail with `unknown-field:<path>` or
`unknown-top-level-field:<field>`. Examples include:

- `engine.extra` -> `unknown-field:engine.extra`
- `subject.route.semantic_proof` ->
  `unknown-field:subject.route.semantic_proof`
- `subject.route.verified_by` -> `unknown-field:subject.route.verified_by`
- `subject.route.generated_at` -> `unknown-field:subject.route.generated_at`
- `subject.route.hostname` -> `unknown-field:subject.route.hostname`

Closed-world checks run only after canonical byte acceptance. A non-canonical
artifact must not receive trusted field-path diagnostics.

## 7. Bridge Report Shape

Top-level fields are ordered:

1. `bridge_report`
2. `profile`
3. `engine`
4. `subject`
5. `checks`
6. `linked_artifacts`
7. `summary`
8. `boundary`
9. `diagnostics`

These fields are required and no other top-level fields are allowed.

`profile` is:

```json
{ "kind": "conversion-evidence", "version": "v0" }
```

`engine` carries the external engine identity:

```json
{
  "name": "external-engine",
  "version": "1.3.11",
  "commit": { "vcs": "git", "hex": "<40-hex>", "dirty": false }
}
```

The name above is an example of an external engine identity. It does not mean
Lispex runs that engine.

`subject.kind` is:

```text
source-to-target-conversion
```

`subject.source` and `subject.target` each carry:

- `language`
- repository-relative `path`
- `byte_len`
- `hash`

The source hash domain is `vouch/external-source-hash/v0`. The target hash
domain is `vouch/external-target-hash/v0`.

`subject.route` carries:

- `id`
- `checked_profile`
- `capability_ids`

`checks` is an ordered list of declared external-engine gates. Each check has:

- `id`
- `stage`
- `status`: `pass`, `fail`, or `not-run`
- `artifact_hash`: `null` or a `vouch/linked-artifact-hash/v0` hash object

`linked_artifacts` lists external proof or gate artifacts. Each item has:

- `id`
- `kind`
- `path`
- `disclosure`: `hash-only` or `public-bytes`
- `hash`

`summary.status` is `pass` only when every declared check is `pass`.

The machine-readable schema is:

```text
schemas/vouch.bridge-report.schema.v0.json
```

## 8. Context Manifest

A consumer may provide a context manifest to check that the report is attached
to the expected profile, subject, route, checked profile, and capability list.
The manifest tag is:

```text
vouch.bridge-context-manifest/v0
```

The machine-readable schema is:

```text
schemas/vouch.bridge-context-manifest.schema.v0.json
```

The context manifest is an intent declaration by the consumer. It is not a
trusted authority and does not assert that the subject is correct. It only checks
that the report is the one the consumer intended to inspect.

The context manifest fields are:

- `bridge_context_manifest`
- `profile.kind`
- `profile.version`
- `subject.kind`
- `subject.case_id`
- `subject.route.id`
- `subject.route.checked_profile`
- `subject.route.capability_ids`

Context failures are closed and field-specific:

- `context-manifest-not-object`
- `context-manifest-tag-mismatch`
- `context-profile-mismatch`
- `context-subject-kind-mismatch`
- `context-case-id-mismatch`
- `context-route-id-mismatch`
- `context-checked-profile-mismatch`
- `context-capability-ids-mismatch`

## 9. Boundary

Every v0 Bridge report carries exactly these attests:

```text
external-engine-evidence-shape
source-target-byte-binding
declared-gate-results
linked-artifact-hash-binding
boundary-disclosure
```

Every v0 Bridge report carries exactly these excludes:

```text
target-code-correctness
semantic-equivalence
external-engine-execution
private-engine-disclosure
production-enforcement
receipt-authenticity
generation-honesty
issuer-binding
timestamping
non-repudiation
external-independent-verification
full-cskernel-coverage
```

The Bridge is intentionally strong about evidence shape and intentionally narrow
about correctness. It gives an external engine a public evidence surface without
forcing that engine to disclose its private implementation.

## 10. Verify Report

`lispex verify-bridge` emits `vouch.bridge-verify-report/v0` on stdout for exit
codes `0` and `1`.

The report records:

- verifier version and commit
- target report path and tag
- optional source, target, linked artifact, and context inputs
- recomputed checks
- recorded-only checks
- summary status, exit code, and failure count
- the checker boundary
- diagnostics

The verify report is itself an artifact. Its hash domain is:

```text
vouch/bridge-verify-report-hash/v0
```

The checker boundary attests public artifact checking. It does not attest
external-engine execution, target-code correctness, issuer binding, timestamping,
non-repudiation, generation honesty, or independent external verification.

## 11. Diagnostic Vocabulary

The implementation uses closed diagnostic strings for the checked conditions.
The main Bridge diagnostics include:

- `non-canonical-artifact-json`
- `bridge-report-not-object`
- `unknown-top-level-field:<field>`
- `unknown-field:<path>`
- `missing-<field>`
- `tag-mismatch`
- `profile-kind-mismatch`
- `profile-version-mismatch`
- `engine-name-missing`
- `engine-version-missing`
- `engine-commit-missing`
- `engine-commit-vcs`
- `engine-commit-hex`
- `engine-commit-dirty`
- `subject-kind-mismatch`
- `subject-case-id-missing`
- `route-id-missing`
- `route-checked-profile-missing`
- `route-capability-ids`
- `source-missing`
- `source-language-missing`
- `source-path-not-neutral`
- `source-hash-domain`
- `source-hash-mismatch`
- `source-byte-len-mismatch`
- `source-file-unreadable`
- `target-missing`
- `target-language-missing`
- `target-path-not-neutral`
- `target-hash-domain`
- `target-hash-mismatch`
- `target-byte-len-mismatch`
- `target-file-unreadable`
- `checks-not-array`
- `check-not-object`
- `check-id-missing`
- `duplicate-check:<id>`
- `check-status-invalid:<id>`
- `check-stage-missing:<id>`
- `check-<id>-artifact-hash-domain`
- `linked-artifacts-not-array`
- `linked-artifact-not-object`
- `linked-artifact-id-missing`
- `linked-artifact-kind-missing`
- `linked-artifact-<id>-path-not-neutral`
- `linked-artifact-disclosure-invalid:<id>`
- `linked-artifact-<id>-hash-domain`
- `linked-artifact-unexpected:<id>`
- `linked-artifact-file-unreadable:<id>`
- `linked-artifact-hash-mismatch`
- `summary-status-invalid`
- `summary-check-count-mismatch`
- `summary-failed-checks-mismatch`
- `summary-not-run-checks-mismatch`
- `summary-should-fail`
- `summary-should-pass`
- `boundary-attests-mismatch`
- `boundary-excludes-mismatch`
- `diagnostics-not-array`

The context manifest diagnostics are listed in section 8.

## 12. Artifact-Class Separation

Bridge reports and native differential receipts are disjoint artifact classes:

- native receipt tag: `csk.differential-receipt/v0`
- Bridge report tag: `vouch.bridge-report/v0`
- native verifier: `lispex verify`
- Bridge verifier: `lispex verify-bridge`

A valid Bridge report is not native evidence. A valid native differential
receipt is not a Bridge report. Changing a tag or adding native-looking fields
does not promote external evidence into native transcript agreement.

The adversarial evidence fixtures record this property with
`promoted_to_native: "no"` across the A.1-A.12 laundering-adversarial cases.

## 13. External Product Alignment

External Product remains a separate commercial product and runs on External Engine. The
Bridge gives that engine a public target for evidence output: conversion results
can be accompanied by Vouch-shaped reports whose bytes and boundaries are
checkable with the Lispex npm CLI.

The allowed strong positioning is:

```text
External Engine performs the commercial conversion. Lispex Vouch supplies the public
evidence shape and checker boundary for the conversion evidence that the engine
emits.
```

The forbidden positioning is:

```text
Lispex runs External Product.
Lispex Vouch proves target-code correctness.
Vouch verifies all 30-language conversion.
```

## 14. Example

`examples/vouch-bridge` contains a TypeScript to Python conversion evidence
fixture:

```text
node cli/bin/lispex.js verify-bridge \
  --source examples/vouch-bridge/source/checkout-discount.ts \
  --target examples/vouch-bridge/target/checkout_discount.py \
  --linked external-gate-proof=examples/vouch-bridge/linked/external-gate-proof.json \
  --expect-context examples/vouch-bridge/context/checkout-discount.context.json \
  examples/vouch-bridge/reports/checkout-discount.bridge.json
```

The example is a public Bridge-shape fixture. It is not a claim that the private
External Product repository has already emitted this exact artifact.
