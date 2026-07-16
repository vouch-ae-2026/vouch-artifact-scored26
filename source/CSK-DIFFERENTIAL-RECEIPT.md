# CSK Differential Receipt Contract v0

> Status: v1.2.16 compatible expansion of the v1.2.8 implementation contract.
> This artifact records lowered-subset transcript agreement between the reference
> interpreter and the Meaning Environment, optionally over one pinned checked profile
> host input datum. It is not a semantic equivalence proof and not an independent
> witness.

## 1. Purpose

The differential receipt records one source input, one optional checked profile host
input datum, the reference interpreter transcript for that pair, the Meaning
Graph v0 lowering when available, the Meaning Environment transcript when
available, and the byte-level comparison between the two transcript payloads.

For the full Lispex language, the reference interpreter remains the operational
authority. For the lowered checked profile subset, a disagreement is an
investigation event; no path may be silently re-labeled correct by regenerating
goldens.

## 2. Tags And Domains

- Receipt tag: `csk.differential-receipt/v0`.
- Source hash domain: `lispex/source-hash/v0`.
- Canonical Core hash domain: `lispex/core-hash/v0`.
- Reference transcript hash domain: `lispex/runtime-hash/v0`.
- Meaning Graph hash domain: `csk/meaning-graph-hash/v0`.
- Meaning Environment transcript hash domain:
  `csk/meaning-env-transcript-hash/v0`.
- checked profile input hash domain: `csk/profile-input-hash/v0`.
- Differential receipt hash domain:
  `csk/differential-receipt-hash/v0`.

The Meaning Environment transcript hash preimage is
`csk/meaning-env-transcript-hash/v0\0<transcript-bytes>`, where
`transcript-bytes` is each transcript entry followed by LF.

The profile input hash preimage is
`csk/profile-input-hash/v0\0<input-datum-canonical-bytes>`, where
`input-datum-canonical-bytes` is the Canonical Core v0 datum writer output for
the supplied input value.

The differential receipt hash preimage is defined from v1.2.16 onward only for
committed artifacts that satisfy `csk.artifact-json/v0` as specified by
`CSK-SPEC-FREEZE.md`. Its preimage is
`csk/differential-receipt-hash/v0\0<differential-receipt-json-bytes>`. Ad-hoc local
CLI output that embeds local paths or other non-neutral metadata is not a
hash-preimage target. The receipt does not embed its own hash in v0. Repository
golden comparisons may mask `engine.commit.hex`, but an exact cold-review bundle
hash covers the full receipt bytes for the fixed bundle commit.

From W3.4, the npm native receipt consumer also treats canonical receipt bytes
as part of the read-side artifact boundary. `lispex verify` and receipt-directory
`lispex replay` reject non-canonical `csk.differential-receipt/v0` JSON bytes
with `non-canonical-artifact-json` before semantic receipt interpretation. This
does not introduce `artifact-json/v1`, does not unify all Rust/JavaScript writer
ordering contracts, and does not claim a dedicated `duplicate-key` diagnostic.

## 3. Command

The native Rust CLI exposes:

```text
lispex diff-receipt <file.lspx|->
lispex diff-receipt --input <datum-file> <file.lspx|->
```

The command emits a deterministic JSON receipt to stdout.

Exit codes are pinned:

- `0`: comparison status is `agree`.
- `1`: comparison status is `not-comparable` or `disagree`; a receipt is still
  written to stdout.
- `2`: usage, I/O, or UTF-8 failure; no receipt is written.

`--input` reads exactly one datum from a file path. `-` is not accepted as the
input datum path, so source stdin and input data cannot compete for the same
stream. Unreadable input files are usage/I/O failures and write no receipt.
Input datum parse, cardinality, canonicalization, or profile-domain failures
write a receipt whose comparison reason is `input-error` unless an earlier
source pipeline stage fails first.

From v1.3.4, the native Rust CLI is the public receipt-generation path for
`csk.differential-receipt/v0`. The npm CLI and wasm playground do not expose
`diff-receipt`; they remain artifact consumer and snippet-running surfaces.

## 4. Scope

The agreement surface is the source-reachable lowered subset: literals,
references, direct block bindings, direct block sequencing, `if`, lowered `cond`,
short-circuit `and`/`or`, parallel `let`, fixed-arity `lambda` closures,
top-level recursive `define`, quasiquote-driven `cons`, `append`, and
`list->vector` intrinsics, and the v1.2.14 checked profile builtin set.

Plain source calls to profile builtin names such as `(cons 1 2)`, `(+ 1 2)`, and
`(eqv? 1 1)` lower as intrinsic references in the checked profile. Source
definitions that bind profile builtin names or the host-input name
`input` are outside the agreement surface and fault during lowering as
`profile-escape`.

The v1.2.14 agreement surface includes `assoc`/`member` (`equal?`),
`assv`/`memv` (`eqv?`), `number?`/`boolean?`/`symbol?`, `min`/`max`/`abs`,
`quotient`/`remainder`/`floor`/`ceiling`/`round`/`truncate`, and the profile-only
`any?`/`all?` traversal predicates. `min`/`max` require at least one argument.
`any?`/`all?` require predicate callbacks to return strict booleans, even though
language-level `if` uses normal truthiness. `assq`/`memq` are excluded because
`eq?` is not part of the checked profile.

`letrec`, variadic `lambda`, mutation, multiple values, guard/dynamic control,
and inexact profile arithmetic are not agreement claims in v1.2.14.

The v1.2.12 agreement surface admits one host input datum bound as the profile
name `input`. Source code may reference `input` but must not bind, define, or
shadow it. The host input is not injected into source, Canonical Core, or Meaning
Graph bytes; it is bound directly into the reference interpreter global
environment and the Meaning Environment root frame. Therefore the same source
program keeps the same source, canonical, and graph hashes across different
input data, while the receipt records a different profile input hash.

The comparison observes rendered transcript bytes only. It does not observe
object identity, sharing, mutation, continuation behavior, host I/O, or error
agreement.

## 5. Comparison

The reference transcript payload is the exact stdout bytes produced by the
reference interpreter's normal top-level auto-print path.

The Meaning Environment transcript payload is the `transcript` array from the
Meaning Environment report, joined as each entry followed by LF. In the bounded
receipt-fuel slice, `diff-receipt` obtains the Meaning Environment receipt
fields through the receipt projection path and uses a command-specific bounded
step limit for that comparison. The `meaning_env.steps.limit` field records the
actual receipt-comparison limit; this does not change the `eval-graph` default
report limit and does not make unbounded TCO or resource-limit claims.

Comparison status is:

- `agree`: both paths ran successfully and transcript bytes are identical.
- `disagree`: both paths ran successfully and transcript bytes differ.
- `not-comparable`: one of the prerequisite stages failed.

The pinned `not-comparable` primary reason order is:

1. `read-error`
2. `normalize-error`
3. `lowering-fault`
4. `input-error`
5. `reference-runtime-error`
6. `meaning-env-fault`

The receipt may record successful artifacts from later paths when they are
reachable. If more than one prerequisite fails, `comparison.reason` is
`comparison.blockers[0].reason`; the rest of `comparison.blockers` records the
additional failures in the same fixed order. This is a schema evolution of the
comparison object, not permission to silently re-label historical agreement.

## 6. Shared Substrate Disclosure

The two paths share the Rust reader, normalizer, Core AST, `Value` representation,
numeric tower, canonical datum writer, graph JSON writer, graph hasher, and one
binary/process.

The two paths do not share evaluation engines: the reference path uses the
interpreter trampoline and primitive table, while the Meaning Environment path
uses the graph node evaluator, its own lexical frame/cell environment, closure
application, and fresh intrinsic implementations.

Agreement can be produced by a bug in shared components. The receipt therefore
attests lowered-subset transcript agreement inside the shared Rust reference
substrate only.

## 7. Receipt JSON

The receipt top-level fields are:

- `differential_receipt`
- `engine`
- `source`
- `input`
- `canonical`
- `graph`
- `reference`
- `meaning_env`
- `comparison`
- `diagnostics`
- `boundary`

The `engine` object carries `name`, `version`, `canonical_format`, and required
`commit` metadata:

```json
{ "vcs": "git", "hex": "<40-hex-full-oid>", "dirty": false }
```

Public corpus and gallery expected artifacts require `dirty:false`. The exact
`hex` value is required at runtime but is masked by expected-artifact comparison
checks, because otherwise every artifact commit would invalidate every golden.
From v1.3.2, release-built native receipt producers populate this object from the
build commit identity. They must not read the user's current working-directory
git status at receipt-generation time. `LISPEX_ARTIFACT_COMMIT_HEX` and
`LISPEX_ARTIFACT_COMMIT_DIRTY` remain internal repository overrides for
regenerating version-bearing goldens.

The `comparison` object carries `status`, `reason`, `fault_class`, `substrate`,
`first_divergence`, and `blockers`. The substrate string is
`shared-rust-reference`.

For `agree`, `first_divergence` is `null`. For `disagree`, it records the first
index where the embedded transcript arrays differ. `disagree` is unit-tested but
not represented by a source corpus fixture in v0. For both `agree` and
`disagree`, `fault_class` is `null` and `blockers` is empty.

For `not-comparable`, `fault_class` classifies the primary blocker. Lowering
fault classes use `lowering-*`; Meaning Environment fault classes use
`meaning-*`; read, normalize, input, and reference runtime errors use their
reason string as the fault class.

The `input` object is one of:

- `{ "status": "absent" }`
- a bound input object with `status`, `path`, `name`, `datum`, `byte_len`, and
  hash object using `csk/profile-input-hash/v0`
- an error object with `status`, `path`, and `message`

## 8. Corpus

The v0 corpus lives under `differential/`:

- `differential/cases/*.lspx`: source inputs.
- `differential/graphs/*.json`: graph bytes for cases that lower.
- `differential/expected/*.json`: differential receipt goldens.

The corpus includes agreement cases for literals, defines, references, rebinding,
nested begins, quasiquote cons, quasiquote append, quasiquote vector, `if`,
`case`, `cond`, short-circuit `and`/`or`, exact profile arithmetic, exact
integer/rounding operations, string comparison, list operations, assoc/member
lookup, fixed-arity lambdas, closure capture, top-level recursive define,
traversal HOFs, `any?`/`all?`, and list/string/number/boolean/symbol predicates.
It also includes
not-comparable cases for read errors, normalize errors, lowering faults, empty
programs, plain user calls that have no Meaning Environment binding,
profile-escape faults, and inexact profile arithmetic. The main differential
corpus records `input.status = "absent"`; the input-bound decision corpus lives
under `profile-gallery/decision-gallery`.

## 9. Public Boundary

v1.2.16 attests only:

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
- `substrate-independence`
- `error-agreement`
- `input-provenance`
- `external-backend-reporting`
- `full-cskernel-coverage`
- `target-code-generation`
- `private-implementation-detail`
- `receipt-authenticity`
- `generation-honesty`
- `issuer-binding`
- `timestamping`
- `non-repudiation`

Do not call the Meaning Environment report a receipt. Do not describe the
differential receipt as independent.

## 10. Versioning

v1.2.13 amended v1.2.12 by adding required `engine.commit`, `fault_class`, and
`blockers`, and by reordering `not-comparable` primary selection to follow the
source pipeline before host input failures.

v1.2.14 widens the checked profile builtin surface for gallery ergonomics and
adds corpus cases for lookup, rounding/integer conversion, and profile-only
`any?`/`all?`. Version surfaces move only after the slice is closed.

v1.2.16 freezes the differential receipt hash preimage and keeps the repository
golden `engine.commit.hex` mask separate from exact cold-review bundle hashes.

v1.3.10 adds authenticity non-goals to native differential receipt excludes:
`receipt-authenticity`, `generation-honesty`, `issuer-binding`, `timestamping`,
and `non-repudiation`. This is an explicit non-goal expansion, not a reduction
of what the receipt attests.
