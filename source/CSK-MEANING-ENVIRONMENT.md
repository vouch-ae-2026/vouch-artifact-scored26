# CSK Meaning Environment Contract v0

> Status: v1.2.16 compatible expansion of the v1.2.7 implementation contract.
> This document specifies the bounded evaluator for canonical Meaning Graph v0
> JSON bytes. It does not claim source-language semantic equivalence.

## 1. Purpose

The Meaning Environment v0 is the deterministic evaluation context for a
Meaning Graph v0 artifact. It exists to make the graph executable
without routing back through the Lispex source interpreter.

For the full Lispex language, the Rust reference interpreter remains the
operational authority. For the checked profile subset, the Meaning
Environment is an internal second path used to compare lowered-subset
transcripts. The reset v1.3 roadmap widens that checked subset before freezing
public semantic vectors.

## 2. Tags And Reserved Domains

- Report tag: `csk.meaning-env-report/v0`.
- Report hash domain: `csk/meaning-env-report-hash/v0`.
- Input graph binding uses the existing graph hash preimage:
  `csk/meaning-graph-hash/v0\0<meaning-graph-json-bytes>`.

The report hash preimage is defined from v1.2.16 onward only for committed
artifacts that satisfy `csk.artifact-json/v0` as specified by
`CSK-SPEC-FREEZE.md`. Its preimage is
`csk/meaning-env-report-hash/v0\0<meaning-env-report-json-bytes>`. Ad-hoc local
CLI output that embeds local paths or other non-neutral metadata is not a
hash-preimage target. The report does not embed its own hash in v0.

v1.2.13 adds required git commit metadata to the report engine object. Expected
artifact comparison masks the exact commit hex but requires a 40-hex full object
id and `dirty:false`.

## 3. Command

The native Rust CLI exposes the evaluator as:

```text
lispex eval-graph <graph.json|->
lispex eval-graph --steps N <graph.json|->
lispex eval-graph --input <datum-file> <graph.json|->
```

The command consumes canonical Meaning Graph v0 JSON bytes, not Lispex source.
The intended source pipeline is:

```text
lispex lower program.lspx | lispex eval-graph -
```

`--steps N` and `--input <datum-file>` are order-insensitive options. `--input`
reads exactly one checked profile input datum from a file path and binds it as the
user name `input` in the root frame before graph evaluation. Input datum usage,
I/O, UTF-8, parse, cardinality, or profile-domain failures are CLI input
failures and write no report.

Exit codes are pinned:

- `0`: evaluation succeeded and a report was written to stdout.
- `1`: Meaning Law validation failed, or evaluation produced a structured fault;
  a report was still written to stdout.
- `2`: usage, I/O, UTF-8, or JSON parse failure; no report is written.

The npm CLI and wasm playground do not expose `eval-graph` in v1.2.12.

## 4. Intake Boundary

Input bytes must be valid UTF-8 JSON. JSON parse failures are input failures, not
Meaning Environment reports.

After JSON parsing, the Rust implementation validates Meaning Law v0 before
execution. The Rust validator uses the same public rule ids as
`scripts/check-meaning-graph-contract.mjs`, including `top-level-fields`,
`graph-tag`, `roots-non-empty`, `index-in-range`, `node-kind`, `fields`,
`block-body-non-empty`, `bind-position`, `intrinsic-name`, `anchor-positive`,
`datum-text`, `reachability`, `bind-name-space`, `lambda-formals`,
`let-bindings`, `name`, and `child-order`.

Law-invalid graphs are never executed. The report status is `law-error`, and the
`law_errors` array carries rule ids and messages.

Law-valid input must also be canonical Meaning Graph JSON writer bytes.
Whitespace-only or key-order variants are reported as a `non-canonical-graph`
evaluation fault. This keeps graph hashes bound to one byte representation.

Meaning Environment v0 also requires tree-shaped graph use. A law-valid graph
that reuses a node from two parents, repeats a child index, or repeats a root
faults as `shared-node` before evaluation. This restriction is deliberate:
v0 lowering emits fresh nodes per occurrence, and v0 does not define
shared binding identity.

Literal nodes use a strict Canonical Core v0 datum parser. A datum is accepted
only when it reads to a data value and writes back to exactly the same bytes via
the canonical datum writer.

## 5. Environment Components

The v0 Meaning Environment has these components:

- Bindings: a lexical frame chain with mutable cells. Keys are separated by name
  space: user names and hygienic temp indices cannot collide.
- Dynamic context: none in v0.
- Host inputs: optional in v1.2.12. When supplied through `--input`, exactly one
  immutable checked profile datum is bound as `user:input` in the root frame. Full
  Lispex `read`/`input` I/O remains outside v1.2.
- Step/fault limits: present. The default step limit is `65536`; the CLI may
  override it with `--steps N`. Native differential receipt generation may use a
  separately pinned receipt-comparison limit; the report still records the
  actual limit used in `steps.limit`.

Each cell contains either one Meaning Environment value or an uninitialized
sentinel. A direct `block.body` `bind` is prebound before the block body runs,
then assigned when its value node completes. This is the v1.2.11 support for
top-level recursive `define`; reading a prebound but not-yet-assigned cell faults
as `uninitialized-ref`.

The input binding is a host binding, not a source or graph node. It does not
change Meaning Graph bytes or graph hashes.

`lambda` captures the current environment handle. Applying a closure creates a
child frame and binds fixed formals to argument values. `let` evaluates
initializers in the outer environment, then evaluates its body in a child frame
containing the parallel bindings.

## 6. Evaluation Semantics

Roots are evaluated in order against the same environment. The final result is
the value sequence produced by the final root.

Node semantics are pinned:

- `lit`: parse the node's `datum` as strict Canonical Core v0 datum text and
  produce one datum value.
- `ref`: intrinsic refs produce an intrinsic value. User/temp refs look up the
  lexical environment, fault `unbound-ref` when absent, or fault
  `uninitialized-ref` when the cell exists but has not been assigned.
- `call`: evaluate the operator first, then arguments left to right. The operator
  must produce exactly one callable value, either an intrinsic or a closure, or
  the call faults `non-callable`. Each argument must produce exactly one value.
  Ordinary intrinsics then enforce their own datum domains.
- `if`: evaluate `test`; if it produces exactly one datum, only `#f` is false.
  Evaluate exactly one of `then` or `else` and produce that branch's values.
- `lambda`: produce one closure value capturing the current environment.
- `let`: evaluate initializer values in the outer environment, bind them in a
  child frame, then evaluate the body in that child frame.
- `block`: evaluate body items left to right and produce the final item values.
- `bind`: evaluate its value, assign or create a local cell, and produce zero
  values.

The evaluator implements fresh intrinsic semantics for the closed checked profile
intrinsic set:

```text
cons append list->vector
+ - * /
= < > <= >=
equal? eqv? not
string=? string<?
null? pair?
car cdr list length
list? string? number? boolean? symbol?
assoc assv member memv
min max abs quotient remainder floor ceiling round truncate
map filter reduce fold-left fold-right apply values call-with-values any? all?
```

It does not call the reference interpreter's trampoline or primitive table. It
may share the public `Value` data type, number types, canonical datum
writer/parser, and graph hash utilities.

Intrinsic arity errors fault as `arity`. Intrinsic type/domain errors fault as
`intrinsic-domain`. Division by zero faults as `division-by-zero`. Arithmetic
and numeric comparison intrinsics accept exact integers and exact rationals only;
inexact reals/floats are outside the checked profile and fault
`intrinsic-domain`. `quotient` and `remainder` require exact integer arguments.
`floor`, `ceiling`, `round`, and `truncate` accept exact profile numbers and
return exact integers; `round` uses the R7RS ties-to-even rule. `quotient` and
`remainder` are the R7RS truncate-toward-zero quotient family, which differs
from `floor` for negative values. `min` and `max` accept one or more arguments;
zero arguments fault as `arity`.

`eqv?` is exactness-sensitive on numbers; `-0.0` and `0.0` are distinct when
such values are reachable outside the checked profile; strings, pairs, vectors,
bytevectors, procedures, continuations, and error objects use identity when such
values are reachable. `equal?` is structural for datum aggregates reachable
through the graph subset. `assoc` and `member` use `equal?`; `assv` and `memv`
use `eqv?`. `assq` and `memq` are not checked profile intrinsics.

`map`, `filter`, `reduce`, `fold-left`, `fold-right`, `apply`, and
`call-with-values` accept callable values and proper-list operands where their
surface procedures require them. Their callbacks are applied through the same
graph evaluator and step accounting as ordinary calls. `reduce` and `fold-left`
call `(f acc elem)` left-to-right. `fold-right` calls `(f elem acc)`
right-to-left. `apply` requires at least a callable and a final proper list, then
calls the callable with any middle arguments followed by the final list's
elements. `values` returns its already evaluated arguments as the result value
sequence; zero arguments produce zero values. `call-with-values` requires a
producer and consumer, calls the producer with zero arguments, and calls the
consumer with the producer's full value sequence.
`any?` and `all?` are profile-only intrinsics with arity `(pred list)`;
they require a proper list, evaluate list elements left to right, short-circuit,
and return strict `#t` or `#f`. Empty lists return `#f` for `any?` and `#t` for
`all?`. Unlike language-level `if`, where only `#f` is false, their predicate
callback must return `#t` or `#f`; any other datum faults as `intrinsic-domain`.

Trace events are emitted only when a node evaluation completes. Each event
carries `step`, `node`, `kind`, and `values`. Datum values are rendered as
canonical datum text. Intrinsic values are rendered as `#<intrinsic:NAME>`;
closure values are rendered as `#<closure>`. These opaque tokens may appear in
traces, but not as final source transcript claims for the checked corpus.

The report `transcript` is the public comparison surface for v1.2.8+. For a root
block, each direct body item that produces non-zero values contributes those
rendered values in order. For a non-block root, the root result contributes its
non-zero values. `bind` contributes nothing.

## 7. Report JSON

A report is deterministic JSON with these top-level fields in order:

- `meaning_env_report`
- `engine`
- `graph`
- optional `input`, present only when an input datum was supplied
- `status`
- `law_errors`
- `trace`
- `transcript`
- `result`
- `fault`
- `steps`
- `boundary`

The `engine` object records `name`, `version`, and required `commit` metadata:

```json
{ "vcs": "git", "hex": "<40-hex-full-oid>", "dirty": false }
```

The `graph` object records `byte_len` and a hash object with domain
`csk/meaning-graph-hash/v0`, algorithm `sha-256`, and lowercase hex digest.

When present, the `input` object records `status`, `name`, canonical `datum`,
`byte_len`, and a hash object using `csk/profile-input-hash/v0`.

`status` is one of `ok`, `law-error`, or `fault`.

For `ok`, `result` is an object with `values`. For `law-error` and `fault`,
`result` is `null`. Evaluation faults carry `kind`, `message`, and when
available `node` and `anchor`.

The boundary block names exactly what the report attests and excludes.

## 8. Public Boundary

v1.2.14 attests only:

- `meaning-law-v0-validation-rust`
- `bounded-deterministic-v0-subset-evaluation`
- `lexical-closure-v0-evaluation`
- `higher-order-traversal-v0-evaluation`
- `gallery-ergonomics-intrinsics-v0`
- `profile-input-binding-when-supplied`
- `transcript-bytes`
- `graph-hash-binding`

v1.2.14 explicitly excludes:

- `semantic-equivalence`
- `differential-receipt`
- `independent-witness`
- `external-backend-reporting`
- `lispex-source-lowering`
- `target-code-generation`
- `full-cskernel-coverage`
- `private-implementation-detail`

Do not call the Meaning Environment report a receipt. It binds to graph bytes,
but it does not attest source bytes or prove interpreter agreement.

## 9. Versioning

v1.2.14 closes only when the Rust evaluator, native CLI, targeted profile input
tests, public claim boundary checks, mini-gallery checks, decision-gallery
checks, differential corpus, verify/replay checks, and this contract check pass
together. Version surfaces move from `1.2.13` to `1.2.14` only after the slice is
closed.

Later slices add verify/replay UX and external oracle material. An external backend is
deferred until after v1.3 unless a fresh strategy decision changes the roadmap.
