# NATIVE-IMPLEMENTATION-CONDITIONS-v8.5.1.md

## 1. Purpose, conformance rule, and provenance

This document is the single normative implementation contract for every empirical and security claim in the paper. It covers the Native subsystem and the Bridge subsystem as one contract with one condition namespace.

The paper PDF is a Layer-4 derived publication artifact under C-ID. It renders the deterministic identity values from the signed external descriptor and the post-run values from the signed reproduction observation R that the external publication record names, after the publication-check command verifies R, and it is regenerated from the implementation built against this contract. A current draft PDF that predates the implementation is expected to fail the C-FINAL-03 claim-language scan, and that failure is a property of the stale draft rather than a defect in this contract.

A release conforms only when every applicable condition passes in a clean checkout. A failed, skipped, manually waived, or unmeasured condition makes the linked paper claim unsupported. Generated identity values are release-derived cryptographic outputs. They MUST NOT contain placeholders, abbreviated hashes, uncommitted paths, or mutable branch names.

The words MUST, MUST NOT, REQUIRED, and EXACT are normative as described by RFC 2119.

This document supersedes `NATIVE-IMPLEMENTATION-CONDITIONS.md`, `SCHEMA-ADDENDUM.md`, `CONTRACT-RECONCILIATION.md`, and `CHECKED-PROFILE-v0.md`. Those files remain repository history and are non-normative. Version 5 resolved the round-4 review conflicts. Version 7 resolves the round-6 release-lifecycle conflicts (the descriptor, the clean-run report, the signed observation, and the publication record now have a strict one-way generation order and hash graph), plus the handled-failure directory publish, the TypeScript generic error types, the fixture scope gate split, and the primitive-operand classification. Version 6 resolved the round-5 single-implementable-contract conflicts: it removes the invocation nonce from the receipt, unifies issue-native on one output directory, splits the release descriptor from its post-run reproduction observation to break a hash and time cycle, unifies the Bridge canonical error, completes and splits the verification error types, realigns the final report to the new workload and mutation units, and pins the workload numeric domain. Version 8 resolves the round-7 executable-release-lifecycle conflicts while leaving the authenticated-native security boundary and the static D/Q/R/P hash graph unchanged. It splits the release lifecycle into three commands, phase 1 `scored26:reproduce` producing only the phase-1 generated result files, from which the trusted outer clean-room driver constructs the clean-run report Q at an external path, phase 2 `scored26:finalize-observation` constructing and signing the observation R and the publication record P, and phase 3 `scored26:publication-check` verifying the full chain, rendering the paper, and emitting a terminal publication report S that carries the paper-claim result formerly in Q, so the first release run has the real order D, Q, R, P, paper, S with no semantic cycle. It measures the clean-run time with a trusted outer driver, binds the observation envelope to its JSON bytes exactly as the descriptor is bound and fixes the R signer key to the descriptor key, requires the finalizer to construct R with cross-field consistency checks and no caller-supplied payload, unifies one split fixture-summary schema across C-FIX-02, C-FIX-08, Q, and R, adds threshold spacing so every workload interval has a non-boundary interior and the fixed candidate counts hold, corrects the P binding-direction sentence and states P as a non-authoritative convenience index, and adds five release-lifecycle fixtures. Version 8.1 is a consistency patch on the round-8 review and adds no new security mechanism, because the authenticated-native boundary and the D/Q/R/P/paper/S generation DAG both passed again. It removes the literal conformance contradiction in which the inner `scored26:reproduce` command was required both to emit the clean-run report Q and not to construct it, by naming three commands and three gates: the inner runner emits only the phase-1 result files, the trusted outer driver constructs Q and is the phase-1 gate, and the phase-3 publication-check is the release final gate that emits the terminal report S. It closes a cross-release mix-up in which an honest finalizer handed the descriptor of one release and the clean-run report of another could sign a single valid observation, by requiring `Q.release_descriptor_sha256 == SHA256(D)` in both the finalizer and the publication-check and adding the L06 fixture. It makes the observation a checkable derivation of the owner reports rather than an asserted summary, fixes the performance report to an exact path and closed schema, gives the finalizer an exact command, key-handle, output, atomicity, and error contract, pins the workload selection and split hash preimages, gives the release-lifecycle fixtures unique identifiers L01 through L06, adds the observation minimum version to the trust policy, and anchors the clean-run report to the clean-room root with an atomic publish. Version 8.2 is a consistency patch on the round-8.1 review and again adds no new security mechanism, because the authenticated-native boundary, the D/Q/R/P/paper/S lifecycle, and the resolution of the previous round's two blockers all passed again. It closes the release layer's byte lifetime and error model. The finalizer and the publication-check now read every input path exactly once into a private immutable buffer and every check, derivation, construction, render, and report consumes only those buffers, so an owner report cannot satisfy one check and then be replaced before another hashes it, and the paper cannot be rendered from a file the signed observation did not authenticate. The exact-reproduction comparison rows become checkable facts: the trusted outer driver hashes the regenerated files itself, each row's expected digest must equal the descriptor's, and its matched flag must equal the equality of its two digests, so a row cannot claim a match its own digests contradict. The finalizer error model gains the canonical, resource, and schema input failures it could not previously express, a third publication carve-out for a usage error raised before a usable output directory exists, and a zero-key-access assertion narrowed to pre-key refusals. The publication-check gains an exact command, an output path, an atomic publication, an exit table, and a terminal report that can carry a null digest it never read. The interior-selection preimage's undefined candidate bytes are unified with the defined input bytes, the workload and mutation detail members are closed, and fixtures L07 through L12 are added.

Version 8.3 is the round-8.2 focused revision. It makes the trusted outer clean-room driver the sole author of the external exact-reproduction comparison artifact, binds Q to the full bytes of all five phase-1 reports and carries those bindings across R, fixes workload invalid-candidate byte determinism, requires phase 3 to re-authenticate D before the R and P chain, corrects and extends the release-lifecycle fixture registry, and authenticates the paper-source entry state before rendering.

Version 8.4 is the round-8.3 focused revision. It closes bootstrap object lifetime over the policy, descriptor, descriptor envelope, and archive, binds release-key identity by three-way equality, replays the terminal qd and rd derivations in phase 3, and makes the phase-1 matched gate refuse a passing Q on any reproduction mismatch. The subsequent round-8.3 gate fixes remove the bootstrap staging-path reopen by requiring digest verification and extraction through one retained archive descriptor, extend L14 across both the archive argument path and any would-be staging path, and reconcile L18 with Q's pass-only schema by giving the no-Q matched-gate refusal one named outer-driver exit code and null report fields.

Version 8.5 is the round-8.4 focused revision. It requires a private pathless archive byte snapshot that closes the same-inode content TOCTOU between hashing and extraction, and it hardens the finalizer by binding the loaded private key to D.key_id and self-verifying the new R envelope before atomic publication.

Version 8.5.1 is the round-8.5 minor revision. It admits post-key publication I/O failure as a second post-key refusal class, narrows the snapshot handoff wording, and strengthens finalizer self-verification to the full C-DSSE-09 verifier.

## 2. Paper claim index

| Claim | Paper claim |
|---|---|
| P1 | An unsigned native-shaped receipt can establish structural consistency but never authenticated native origin. |
| P2 | Authenticated native evidence is the exact canonical `csk.differential-receipt/v0` payload signed in a DSSE envelope by a consumer-authorized Ed25519 issuer. |
| P3 | `issue-native` reads source and input once, executes the native pipeline, constructs the receipt itself, applies the signability gate, self-checks the result, and never accepts a caller-supplied receipt. |
| P4 | `verify-native` binds authentication to a consumer trust policy and trusted source, input, profile, and engine context in a fixed order. Decision promotion is a separate operation. |
| P5 | Native, Bridge, policy, manifest, envelope, descriptor, and report readers use one normative `csk.artifact-json/v0` writer and reject noncanonical bytes before semantic interpretation. |
| P6 | A strict tagged union provides structural separation but accepts a self-consistent unsigned native forgery. |
| P7 | Native authentication, native decision promotion, and Bridge verification mint distinct opaque capabilities with compile-time and runtime separation. |
| P8 | The vulnerable consumer displays a valid Bridge report as `Verified`, while the repaired consumer displays only `External evidence checked`. |
| P9 | Every fixture declared by the generated fixture manifest produces its recorded expected result. |
| P10 | The signed replay manifest detects deletion, reordering, substitution, and expected-count changes relative to the frozen supplied corpus. |
| P11 | The deterministic workload generator records its candidate population, selection, and split from the frozen workload specification. |
| P12 | Replay records decision distributions, transitions, partition results, profile escapes, comparison outcomes, and coverage under the pinned protocol. |
| P13 | The mutation campaign records build, activation, detection, common-mode, pipeline-failure, and survivor outcomes for every registered mutant. |
| P14 | Mutant results are structural experimental evidence and are never authenticated with the release key. |
| P15 | The publication identity and signed external release descriptor pin the immutable sources, release artifacts, engine, key identifier, toolchains, dependencies, and clean-room sequence. |
| P16 | Size, latency, memory, and clean-run measurements use the pinned protocol and report the observations produced by that protocol. |
| P17 | Private-key absence, consumer authorization, residual replay, signer-compromise, and dishonest-consumer limitations are literal. |
| P18 | All public welfare-shaped inputs are synthetic and the release scan rejects likely personal data. |
| P19 | The selected workload report records profile extensions, profile escapes, comparison availability, and decision-label exercise without treating any predetermined numeric result as a conformance requirement. |

No exact empirical outcome is a conformance requirement unless the outcome defines protocol structure rather than a measurement. Generated reports MUST record the observed numeric outcomes. The paper MUST derive empirical statements from those generated reports.

## 3. Covered evaluation subset, shared substrate, and independence boundary

### A-1 Covered evaluation subset

The Meaning Environment path and the reference path MUST be compared over the higher-order functional subset defined by `csk.checked-profile/v0`. Lambdas are first-class values. The subset MUST NOT be described as first-order.

The covered Core forms are exactly this closed set:

```text
covered immutable literal
lexical variable reference
fixed-arity lambda
application
if
nonempty begin
parallel let
nonrecursive top-level define
and
or
restricted cond
```

The covered source primitives are exactly this closed set:

```text
+ - * / = < <= > >= cons car cdr null? pair? list
decision-approve
decision-deny
decision-review
decision-invalid-input
```

The decision constructors are nullary. All other primitive arities, coercions, evaluation order, and typed language faults MUST match the frozen interpreter conformance fixtures.

The covered literal values are exactly booleans, exact integers, reduced exact rationals, finite binary64 reals, strings, the empty list, and quoted symbols introduced through the restricted symbol-literal syntax required by P-7. General `quote` and `quasiquote` are not covered.

`and` and `or` MUST lower with left-to-right short-circuit semantics. They MUST NOT appear as graph operations. Covered `cond` MUST normalize to nested `if` forms as required by P-7. It MUST NOT appear as a graph operation.

A syntactic form for which no checked-profile source grammar production exists MUST cause `issue-native` to return `native-lowering-failed` without invoking either evaluator and without writing an artifact. The closed examples are listed by P-10.

A construct with a covered syntactic shape that violates a checked-profile restriction MUST terminate as `profile-escape`. This includes an empty `begin`, duplicate bindings, binding or shadowing `input`, recursive top-level definitions, and an observable procedure result.

Procedures remain valid intermediate and bound values. After each top-level form is evaluated, the value-event encoder MUST examine its observable result. If the result is a procedure, the encoder MUST emit no fabricated value encoding and issuance MUST terminate with `profile-escape`.

Decision values are valid only as final root values. A decision value observed before the final root MUST terminate with `profile-escape`.

### A-2 Shared substrate and independence boundary

The two paths share a disclosed substrate and are not numerically independent.

The Meaning Environment path MUST reuse the interpreter public numeric and value types for arithmetic, comparison, value representation, and canonical value rendering. It MUST NOT call the interpreter evaluator for control flow, environment handling, application, or operator dispatch.

The differential independence boundary is confined to lowering, graph structure and traversal, evaluation order, environment handling, operator dispatch, and path-local transcript serialization. Lowering, graph-evaluator, source-evaluator, and path-serialization mutants may produce disagreement. Shared numeric, reader, and normalizer mutants may produce common-mode outcomes.

Neither path may use an unbounded evaluator. The exact budgets are:

```text
MEANING_ENV_STEP_BUDGET = 1000000
MEANING_ENV_DEPTH_BUDGET = 1024
REFERENCE_STEP_BUDGET = 1000000
REFERENCE_DEPTH_BUDGET = 1024
```

One step MUST be charged for entry into each evaluated Core form and for each primitive invocation. Depth is the number of simultaneously active evaluator frames including the current frame. The initial top-level evaluator frame has depth one.

Meaning Environment exhaustion MUST use language-fault code `meaning-env-budget-exhausted`. Reference exhaustion MUST use language-fault code `reference-budget-exhausted`. Exhaustion MUST NOT panic or silently truncate a transcript. A budget fault prevents decision promotion under A-16.

## 4. Canonical artifact JSON

### C-JSON-01 Supported data model

`csk.artifact-json/v0` MUST accept only JSON null, Boolean values, Unicode strings, arrays, objects, and signed integers in the inclusive range `-9007199254740991` through `9007199254740991`. Exact rationals MUST use their schema-defined string representation. Floating-point JSON numbers and negative zero MUST be rejected.

Every schema member described as `uint` MUST be a JSON integer in the inclusive range `0` through `9007199254740991`.

Backs P5.

### C-JSON-02 UTF-8 rule

All artifact JSON MUST use strict UTF-8 without a byte-order mark. Invalid sequences, overlong encodings, lone surrogates, and trailing non-JSON bytes MUST fail as `non-canonical-artifact-json`.

Backs P5 and P9.

### C-JSON-03 Object ordering

Object member names MUST be ordered by their unsigned UTF-8 byte sequences. No object may contain duplicate member names. The rule applies recursively and does not depend on schema field order.

Backs P5.

### C-JSON-04 Layout

The writer MUST use two ASCII spaces per nesting level. A nonempty object or array MUST place each member or item on its own line. A colon MUST be followed by one ASCII space. Commas MUST be followed by LF. Empty objects and arrays MUST be written as `{}` and `[]`. The complete document MUST end with exactly one LF.

Backs P5.

### C-JSON-05 String escaping

The writer MUST escape quotation mark and reverse solidus as `\"` and `\\`. It MUST use `\b`, `\t`, `\n`, `\f`, and `\r` for their five control characters. Other code points from U+0000 through U+001F MUST use lowercase four-digit `\u00xx` escapes. All other valid scalar values MUST be emitted as UTF-8 without optional escaping.

Backs P5.

### C-JSON-06 Integer formatting

Integers MUST use base-10 ASCII with no leading plus, no unnecessary leading zero, and no exponent. Zero MUST be `0`.

Backs P5.

### C-JSON-07 One writer across implementations

Rust production and JavaScript verification MUST each implement the preceding writer. `artifact/tests/cross-writer-goldens.json` MUST cover every artifact class and all string, integer, empty collection, and nesting cases. Every golden MUST have byte-identical Rust and JavaScript output.

Backs P5.

### C-JSON-08 Read-side byte gate

Each reader MUST perform these operations before reading semantic fields:

1. Enforce the raw byte limit.
2. Decode strict UTF-8.
3. Parse exactly one JSON value.
4. Enforce structural resource limits.
5. Serialize with `csk.artifact-json/v0`.
6. Compare the serialized bytes with the submitted bytes.

A mismatch MUST return `non-canonical-artifact-json`. No repaired serialization may replace the submitted evidence.

Backs P5 and P9.

### C-JSON-09 Covered classes (amended v8.3)

The byte gate MUST apply to this closed set:

- DSSE envelopes
- Native receipt payloads
- Bridge reports
- Native trust policies
- Native public-key records
- Release descriptors
- Reproduction observations of type `csk.reproduction-observation/v0`
- Release publication records of type `csk.release-publication/v0`
- Release manifests such as `artifact/release-manifest.json`
- Replay corpus manifests
- Workload space, candidate, selection, split, and holdout manifests
- Fixture manifests
- Clean-run reports of type `vouch.scored26-reproduction/v0`
- Exact-reproduction comparison artifacts of type `vouch.scored26-reproduction-comparisons/v0` at `<clean-room-root>/external/exact-reproduction-comparisons.json`
- Native, structural, Bridge, replay, issue, workload, mutation, performance, fixture, reproduction, finalize, and publication reports

Backs P5 and P10.

## 5. Canonical value encoding

### A-4 Canonical value encoding (amended v4)

Canonical observable values have exactly these closed shapes.

```text
integer
  { "t": "int", "v": <canonical base-10 integer string> }

rational
  {
    "t": "rat",
    "n": <canonical integer string>,
    "d": <positive canonical integer string>
  }

real
  { "t": "real", "v": <interpreter shortest round-trip rendering> }

boolean
  { "t": "bool", "v": true | false }

nil
  { "t": "nil" }

pair or list
  {
    "t": "list",
    "items": [<canonical value>, ...],
    "improper_tail": <canonical value or null>
  }

symbol
  { "t": "sym", "v": <symbol name> }

string
  { "t": "str", "v": <string> }

void
  { "t": "void" }

decision
  {
    "t": "decision",
    "v": "approve" | "deny" | "review" | "invalid-input"
  }
```

The `decision.v` enum is closed and exhaustive.

A canonical integer string has an optional leading minus sign and no leading zero except the string `0`. The spelling `-0` is forbidden. A rational denominator MUST be positive. Its numerator and denominator MUST be in lowest terms.

Real rendering MUST reuse the interpreter numeric formatter so both paths produce identical bytes. NaN, positive infinity, and negative infinity are outside the profile.

Any value kind outside the closed table MUST terminate as `profile-escape`. A procedure observable result MUST be detected after evaluation and MUST NOT receive a fabricated encoding. Mutable cells and records are not encodable.

A successful top-level `define` MUST emit `{ "t": "void" }`.

The application decision schema is exactly the four `decision` values. Boolean values are not application decisions. Decision values are opaque. No primitive may inspect, compare, decompose, convert, serialize as source data, or otherwise operate on a decision value.

A decision value may occur only as the complete canonical value of the final top-level root required by A-3. A violation that is observable in the serialized receipt is a structural rejection: a decision at an earlier top-level root, or a decision nested inside a list, a pair, an `items` member, an `improper_tail` member, or another recorded canonical value. A decision consumed as a primitive operand is a dynamic value-flow property that is not observable in the serialized receipt. It is a `profile-escape` at issuance that yields no signable receipt, enforced by the checked-profile evaluator, and it is not a standalone structural-verifier check.

The workload labels `approve`, `deny`, `review`, and `invalid-input` map one-to-one to the corresponding `decision.v` values.

## 6. Checked profile v0

### P-1 Raw input file (amended v3)

The input file MUST be canonical UTF-8 JSON produced by `csk.artifact-json/v0`. It MUST have no byte-order mark or leading whitespace. It MUST end with exactly one LF as required by C-JSON-04.

The top-level object has exactly this closed shape:

```text
{
  "input": "csk.checked-input/v0",
  "value": <checked host value>
}
```

Unknown members, duplicate members, missing members, and noncanonical JSON are forbidden.

The raw input bytes MUST be read exactly once into an immutable buffer. The final LF is part of that buffer. Receipt field `input.sha256` MUST hash the entire buffer as required by A-7. Receipt field `input.byte_length` MUST equal the length of that same buffer.

Parsing MUST NOT change the hash preimage. The parsed `value` member MUST be independently converted to a Lispex value under P-3. Both evaluators consume that value through the reserved top-level binding `input`.

### P-2 Checked host-value grammar

A checked host value is exactly one member of this closed grammar:

```text
boolean
  JSON true or false

integer
  a JSON integer in the inclusive range
  -9007199254740991 through 9007199254740991

string
  a JSON string

list
  a JSON array of checked host values

rational
  {
    "$rat": {
      "n": <canonical integer string>,
      "d": <positive canonical integer string>
    }
  }

binary64 real
  {
    "$real": <interpreter canonical finite binary64 string>
  }

symbol
  {
    "$sym": <valid Lispex symbol-name string>
  }
```

The empty JSON array is the empty Lispex list.

A canonical integer string has an optional leading minus sign, has no leading zero except `0`, and is not `-0`.

A rational denominator MUST be greater than zero. Numerator and denominator MUST be coprime. Zero MUST be encoded with denominator `1`.

A `$real` value MUST be finite and use the interpreter exact shortest round-trip rendering. NaN and infinities are forbidden.

A `$sym` name MUST satisfy the frozen Lispex identifier grammar. It MUST NOT be `input`. It MUST NOT be a covered primitive name when used as input data.

JSON `null` is not a checked host value.

Records are outside version 0. An object is valid only when it has exactly one `$rat`, `$real`, or `$sym` tag and the exact nested schema above. Arbitrary JSON objects and maps are forbidden.

### P-3 Host-to-Lispex mapping

The mapping is total over P-2:

```text
JSON Boolean
  Lispex Boolean

JSON integer
  exact Lispex integer

JSON string
  immutable Lispex string

JSON array
  proper immutable Lispex list whose elements are recursively mapped
  in array order

{"$rat":{"n":N,"d":D}}
  reduced exact Lispex rational N/D

{"$real":R}
  finite binary64 Lispex real represented by R

{"$sym":S}
  immutable quoted Lispex symbol S
```

No host record, object, null, mutable value, procedure, port, bytevector, or cyclic structure can enter through the checked input.

The implementation MUST canonicalize the mapped Lispex value with the shared canonical value writer. It MUST compute `input.canonical_value_sha256` from those bytes as required by A-7.

The parsed canonical Lispex value and the immutable raw input buffer MUST be retained for the lifetime of evaluation. Native verification MUST retain private defensive copies as required by A-16.

### P-4 Malformed and invalid input (amended v3)

The input error classes are exactly:

```text
native-input-parse-failed
  The bytes are not valid UTF-8 JSON, contain a byte-order mark, contain
  trailing data after the required LF, or cannot be parsed as exactly one
  JSON value.

native-input-profile-invalid
  The bytes parse as JSON but are noncanonical, the top-level object has a
  missing, duplicate, unknown, or mistyped member, or value does not match
  the closed host grammar in P-2.
```

A host-grammar violation MUST occur before evaluation. Neither evaluator may run after either error.

Application-level invalidity is not a host-grammar violation. A valid host list with the wrong arity, a wrong element type, or an out-of-range integer category code MUST enter evaluation. The checked program MUST return `decision-invalid-input`.

### P-5 Reserved `input` binding

Before the first top-level form is evaluated, each path MUST create one immutable top-level binding:

```text
input = <Lispex value produced by P-3>
```

The binding MUST exist for the entire evaluation unit and be identical for every top-level form. It MUST NOT be reassigned, removed, redefined, captured under a different value, or shadowed.

The name `input` is forbidden as:

```text
a lambda parameter
a let binding
a top-level define name
a primitive alias
any binding introduced by lowering
```

A source occurrence of `input` is a lexical variable reference to the reserved binding.

Every scored workload unit MUST contain a reachable evaluation path that reads `input` and makes the final observable decision depend on its value. The workload manifest MUST identify at least one pair of valid application inputs for each decision-producing source unit that changes the final decision. A source unit whose final result is invariant under all declared workload inputs is not a decision-distribution fixture.

### P-6 Covered source forms (amended v3)

The covered source forms and primitives are the closed sets required by A-1.

Lambdas are first-class values. Procedures may be passed, returned internally, stored in lexical bindings, and invoked. A procedure cannot be a top-level observable result.

Primitive values are provided by the initial environment. They MUST NOT be redefined at top level.

Duplicate lambda parameter names, duplicate names in one `let`, and duplicate top-level definitions are forbidden. Lexical shadowing of names other than `input` is allowed.

An empty `begin` is forbidden.

Decision constructors are nullary. A decision value is permitted only as the observable value of the final top-level form. No decision value may be consumed as an operand.

### P-7 `quote`, symbols, and `cond`

General `quote`, `quasiquote`, `unquote`, and `unquote-splicing` are outside the profile.

The only quoted values introduced by the input profile are symbols represented by the `$sym` host tag. Source symbol literals may use only the restricted symbol-literal token accepted by the checked-profile parser. That token MUST lower directly to a symbol literal node. It is not general `quote`.

Covered `cond` has exactly this grammar:

```text
(cond
  (<test> <result>)
  ...
  (else <result>))
```

It MUST contain at least one tested clause and exactly one final `else` clause. Each clause MUST have exactly one result expression. `=>` clauses and clauses with multiple result expressions are outside the profile.

Lowering MUST use this right-associated transformation:

```text
(cond
  (t0 r0)
  (t1 r1)
  (else re))

(if t0 r0 (if t1 r1 re))
```

Tests MUST retain left-to-right short-circuit behavior. No `cond` node or operation may appear in the graph.

### P-8 Top-level definitions and recursion

A top-level `define` is nonrecursive.

For this form:

```text
(define name expression)
```

`expression` MUST be evaluated in the environment that existed before `name` was bound. On success, `name` becomes available to later top-level forms and the observable value is void.

A definition expression MUST NOT contain a free reference to its own name. Mutually recursive groups, forward references intended to create recursion, internal recursive definitions, named `let`, and `letrec` are outside the profile.

A recursive use with an otherwise covered `define` shape MUST terminate as `profile-escape`. `letrec` and other uncovered recursion syntax MUST terminate as `native-lowering-failed`.

### P-9 Observable results and decisions (amended v3)

After each top-level form evaluates successfully, its observable result MUST be encoded under A-4.

If an observable result is a procedure or another unsupported value kind, the encoder MUST emit no substitute representation and issuance MUST terminate as `profile-escape`.

A decision-producing unit MUST have at least one top-level form. Its final top-level observable result MUST be exactly one of:

```text
{ "t": "decision", "v": "approve" }
{ "t": "decision", "v": "deny" }
{ "t": "decision", "v": "review" }
{ "t": "decision", "v": "invalid-input" }
```

Only that final decision value can be promoted as an application decision. A Boolean final value is not a decision and MUST be refused by issuance and promotion.

### P-10 Unsupported-construct classification (amended v3)

The source-profile error classes are exactly:

```text
native-lowering-failed
  The source contains syntax for which the checked-profile grammar has no
  production and which cannot enter the covered Core graph.

profile-escape
  The source has a covered syntactic shape but violates a profile restriction,
  or evaluation produces an observable value outside the canonical value
  schema or at a forbidden position.
```

The closed examples of `native-lowering-failed` are:

```text
set!
letrec
variadic lambda
values
continuations
dynamic-wind
guard
mutable vectors
bytevectors
ports
general quote
quasiquote
unsupported cond clause syntax
```

The closed examples of `profile-escape` are:

```text
binding or shadowing input
duplicate binding names
empty begin
recursive use of a covered top-level define
observable procedure result
decision value before the final root
nonfinite real produced as an observable value
```

A syntactically uncovered form MUST be classified before either evaluator runs. A dynamic profile escape MUST be detected when it becomes known and MUST NOT receive a fabricated encoding.

A non-decision final canonical value is not a source-profile error when evaluation and encoding otherwise succeed. It MUST reach the signability gate and be refused as `native-result-not-signable` with reason `final-value-not-decision`.

### P-11 Application input schema

For the scored workload, `value` MUST be a positional list. The workload specification MUST define the exact arity, the required element type at every position, the integer category code assigned to every categorical value, and every permitted numeric range.

Category codes MUST be JSON integers. Strings and symbols MUST NOT represent categories.

The application schema is identified as `csk.checked-input/v0`. Its arity, position table, category-code table, and numeric ranges form a closed workload schema. A conforming workload implementation MUST reject unlisted category codes at the application layer by returning `decision-invalid-input`.

Wrong arity, wrong element type within a valid host list, and out-of-range category code are application-level invalidities. They MUST remain valid host input and MUST evaluate to:

```text
{ "t": "decision", "v": "invalid-input" }
```

## 7. Transcript schema and completeness

### A-3 Transcript schema and completeness (amended v4)

A transcript is an ordered observable trace with exactly this closed shape.

```text
{
  "transcript": "csk.transcript/v0",
  "events": [<event>, ...],
  "terminal": <terminal>
}
```

An event has exactly one of these closed shapes.

```text
{
  "kind": "output",
  "form_index": <uint>,
  "bytes_b64": <RFC 4648 standard padded base64>
}

{
  "kind": "value",
  "form_index": <uint>,
  "value": <canonical value required by A-4>
}
```

Version 0 has no covered output primitive. A version 0 transcript MUST contain no output event. The output event variant is reserved and cannot be emitted by `csk.checked-profile/v0`.

A terminal has exactly one of these closed shapes.

```text
{
  "kind": "completed"
}

{
  "kind": "language-fault",
  "code": <language-fault-code>,
  "form_index": <uint>
}

{
  "kind": "infrastructure-failure",
  "code": <infrastructure-failure-code>,
  "phase": "reference-evaluation" | "meaning-evaluation",
  "next_form_index": <uint>
}
```

The `phase` enum is closed and exhaustive.

The language-fault code enum is closed and exhaustive.

```text
arity-mismatch
type-error
division-by-zero
numeric-domain-error
reference-budget-exhausted
meaning-env-budget-exhausted
```

The infrastructure-failure code enum is closed and exhaustive.

```text
native-reference-execution-failed
native-meaning-execution-failed
```

`native-reference-execution-failed` MUST have phase `reference-evaluation`. `native-meaning-execution-failed` MUST have phase `meaning-evaluation`.

A completed terminal and a language-fault terminal are comparable language terminals. An infrastructure-failure terminal is not a comparable language terminal.

The native pipeline order is exactly the following sequence.

```text
parse
normalize
lower to graph
reference evaluation
meaning evaluation
comparison
```

A failure before the graph exists is a pipeline error. It MUST produce no differential receipt. A failure during either evaluation occurs after the full graph exists and MUST produce a receipt with an infrastructure-failure terminal for the failing side.

`form_index` is zero-based. The graph MUST have at least one root. A zero-root graph is a structural rejection.

If the graph has `n` roots and the terminal is completed, the transcript MUST contain exactly `n` value events. Their indices MUST be exactly `0` through `n - 1` in order.

If the terminal is a language fault at index `k`, then `0 <= k < n`. Value events MUST exist exactly for indices `0` through `k - 1`. No value event may exist for index `k` or any later index.

If the terminal is an infrastructure failure with `next_form_index = k`, then `0 <= k <= n`. Value events MUST exist exactly for indices `0` through `k - 1`. No value event may exist for index `k` or any later index.

After a language fault or infrastructure failure, no later top-level form may be evaluated.

A decision canonical value may occur only in the value event whose `form_index` equals `n - 1`. It MUST be the complete value of that event. No decision value may occur in an earlier top-level event, inside a list or pair, or nested inside another canonical value, and these observable restrictions apply recursively and are a structural rejection. Consumption of a decision value as a primitive operand is a dynamic value-flow property that the no-replay structural verifier cannot observe. It is a `profile-escape` at issuance enforced by the checked-profile evaluator under A-4, not a structural-verifier check.

A transcript with a missing event, an additional event, a duplicate event, an out-of-order event, an invalid index, an event forbidden by its terminal, or any other malformed event sequence is structurally invalid. An incomplete transcript is a structural rejection. A violation of the decision placement rule is a structural rejection.

`canonical_transcript_bytes` is the `csk.artifact-json/v0` serialization of the complete transcript object.

For comparison, a comparable transcript is its event sequence followed by one terminal sentinel. `first_divergence_index` is the zero-based index of the first unequal element. If one event array is a strict prefix of the other, the first unmatched element is the divergence. If all events agree and the terminal sentinels differ, the terminal sentinel has index `events.length`.

Comparison status is a closed enum.

```text
agree
disagree
not-comparable
```

`agree` applies only when both terminals are comparable language terminals and the complete canonical transcript bytes are byte-identical.

`disagree` applies only when both terminals are comparable language terminals and the complete canonical transcript bytes differ.

`not-comparable` applies if and only if either terminal is an infrastructure failure.

For `agree`, `first_divergence_index` MUST be null. For `disagree`, it MUST be the actual first divergence. For `not-comparable`, it MUST be null.

For `not-comparable`, `comparison_unavailable_at` MUST equal the smallest `next_form_index` among the failing side or sides. For `agree` and `disagree`, `comparison_unavailable_at` MUST be null.

Internally inconsistent comparison fields are a structural rejection. Final values that differ while `comparison.status` is `agree` are a structural rejection.

Verifiers MUST compare the recorded transcript objects and their canonical bytes. Comparing only hashes is forbidden.

### A-19 Decision before final root fixture

The adversarial fixture `decision-before-final-root` contains a structurally well-formed receipt with a decision value at an intermediate root and a valid decision value at the final root. Structural validation MUST reject the receipt.

## 8. Graph schema and canonical forest

### A-5 Graph schema and canonical forest (amended v3)

A graph has exactly this closed shape:

```text
{
  "graph": "csk.graph/v0",
  "roots": [<uint>, ...],
  "nodes": [<node>, ...]
}
```

The root array MUST contain at least one identifier.

Nodes have exactly these closed operation-specific shapes:

```text
lit
  { "id": <uint>, "op": "lit", "value": <covered source literal> }

var
  { "id": <uint>, "op": "var", "name": <string> }

lambda
  {
    "id": <uint>,
    "op": "lambda",
    "params": [<string>, ...],
    "body": <uint>
  }

app
  {
    "id": <uint>,
    "op": "app",
    "operator": <uint>,
    "arguments": [<uint>, ...]
  }

if
  {
    "id": <uint>,
    "op": "if",
    "test": <uint>,
    "consequent": <uint>,
    "alternate": <uint>
  }

begin
  { "id": <uint>, "op": "begin", "forms": [<uint>, ...] }

let
  {
    "id": <uint>,
    "op": "let",
    "names": [<string>, ...],
    "initializers": [<uint>, ...],
    "body": <uint>
  }

define
  {
    "id": <uint>,
    "op": "define",
    "name": <string>,
    "value": <uint>
  }

prim
  { "id": <uint>, "op": "prim", "name": <covered primitive name> }
```

`roots` MUST contain exactly one identifier per top-level form in source order. Every child and root identifier MUST refer to an existing node. Node identifiers MUST equal their array indices.

Node sharing is forbidden. The graph is a tree forest with one fresh node for every source occurrence. Every nonroot node MUST have exactly one incoming child edge. Every root MUST have no incoming edge. A root identifier MUST occur exactly once in `roots`.

The graph MUST be acyclic. Every node MUST be reachable from exactly one root.

Canonical identifier assignment MUST use a preorder forest traversal. Roots are visited in source order. At each node, the node receives the next zero-based identifier before its children are visited. Child fields are visited in the written order below. Array-valued child fields are visited in array order.

```text
lambda
  body

app
  operator, then arguments

if
  test, consequent, alternate

begin
  forms

let
  initializers, then body

define
  value
```

A graph MUST satisfy all of these rules:

1. `let.names.length` MUST equal `let.initializers.length`.
2. A lambda parameter list MUST contain no duplicate name.
3. A `let` name list MUST contain no duplicate name.
4. Duplicate top-level `define` names are forbidden.
5. The reserved name `input` MUST NOT be bound.
6. Primitive names MUST NOT be redefined.
7. Other lexical shadowing is allowed.
8. An empty `begin` is forbidden.
9. A `lit` node may carry only a source literal covered by A-1.
10. `{ "t": "void" }` is not a source literal permitted in a `lit` node.
11. A `prim` name MUST belong to the exact primitive allow-list in A-1.
12. `and`, `or`, and `cond` MUST NOT appear as graph operations or primitive names.
13. A `define` node may appear only as a root.
14. A `var` node MUST be bound.
15. No root may reference a top-level name defined by a later root.
16. Every free variable occurrence MUST resolve to `input`, an allowed primitive, a lexical binding in scope, or a prior top-level definition.
17. A top-level definition value MUST NOT contain a free reference to its own name.

Parallel `let` initializers MUST evaluate left to right in the outer environment. Application MUST evaluate its operator first and its arguments left to right. Multiple lambda-body forms MUST be represented by one nonempty `begin` node.

The Meaning Environment report has exactly this closed shape:

```text
{
  "meaning_env": "csk.meaning-env-report/v0",
  "graph_sha256": <lowercase hex64>,
  "transcript_sha256": <lowercase hex64>,
  "node_count": <uint>,
  "terminal": <transcript terminal>,
  "transcript": <csk.transcript/v0 object>
}
```

The Meaning Environment report is an internal receipt-construction input. It is not independently authenticated.

## 9. Differential receipt schema

### A-6 Differential receipt schema (amended v4)

A `csk.differential-receipt/v0` object has exactly these twelve top-level members.

```text
differential_receipt
engine
execution
source
input
canonical
graph
reference
meaning_env
comparison
diagnostics
boundary
```

Their closed schemas are shown below.

```text
differential_receipt
  "csk.differential-receipt/v0"

engine {
  "executable_sha256": <"sha256:" plus lowercase hex64>,
  "target_triple": <string>
}

execution {
  "invocation": "native-checked",
  "context_digest": <lowercase hex64>,
  "profile": "csk.checked-profile/v0",
  "lispex_version": <string>,
  "build_commit": <lowercase hex40>,
  "build_variant": "release" | "mutant",
  "mutant_id": <string or null>,
  "target_triple": <string>,
  "executable_sha256": <"sha256:" plus lowercase hex64>
}

source {
  "sha256": <lowercase hex64>,
  "byte_length": <uint>
}

input {
  "sha256": <lowercase hex64>,
  "byte_length": <uint>,
  "canonical_value_sha256": <lowercase hex64>
}

canonical {
  "normalized_sha256": <lowercase hex64>,
  "normalized_bytes_b64": <RFC 4648 standard padded base64>
}

graph {
  "graph_sha256": <lowercase hex64>,
  "node_count": <uint>,
  "value": <csk.graph/v0 object>
}

reference {
  "transcript_sha256": <lowercase hex64>,
  "terminal": <transcript terminal>,
  "transcript": <csk.transcript/v0 object>
}

meaning_env {
  "meaning_env": "csk.meaning-env-report/v0",
  "graph_sha256": <lowercase hex64>,
  "transcript_sha256": <lowercase hex64>,
  "node_count": <uint>,
  "terminal": <transcript terminal>,
  "transcript": <csk.transcript/v0 object>
}

comparison {
  "status": "agree" | "disagree" | "not-comparable",
  "first_divergence_index": <uint or null>,
  "comparison_unavailable_at": <uint or null>
}

diagnostics [
  {
    "code": <string>,
    "message": <string>
  },
  ...
]

boundary {
  "statement_sha256": <lowercase hex64>
}
```

All enums in this schema are closed and exhaustive.

`execution.context_digest` binds the invocation to the frozen normalized source bytes, the input canonical value digest, the profile identifier, and the engine executable digest as required by A-7. It is signed receipt content and is deterministic, so it does not defeat exact-payload reproduction. The per-invocation nonce is not signed receipt content. It exists only inside the module-private evaluator tokens of C-ISSUE-05 and binds the two transcripts to one live invocation. It does not independently prove freshness.

`execution.build_variant` records the build variant that produced the receipt. A version 0 release-signed receipt MUST have `execution.build_variant` equal to `release` and `execution.mutant_id` equal to null. A receipt produced by a mutant build MUST have `execution.build_variant` equal to `mutant`. The signability gate MUST read both fields from the sealed verified snapshot.

The decoded `normalized_bytes_b64` bytes are the sole receipt-carried preimage of `canonical.normalized_sha256`. `graph.value` is the sole receipt-carried preimage of `graph.graph_sha256`. Each recorded transcript object is the sole receipt-carried preimage of its transcript hash.

Source, input, mapped input value, and executable bytes are absent from the receipt. Their digests are checked against external context where required.

Structural verification MUST parse the decoded normalized program bytes, lower them deterministically under the recorded profile, serialize the resulting graph with `csk.artifact-json/v0`, and require byte identity with the canonical serialization of `graph.value`.

The graph MUST have at least one root. A zero-root graph is a structural rejection. A malformed graph or malformed event sequence is a structural rejection.

When external input is supplied, structural verification MUST parse the exact external bytes, apply P-2 and P-3, serialize the mapped canonical Lispex value, recompute its digest, and require equality with `input.canonical_value_sha256`.

Both transcripts MUST satisfy the completeness and event-sequence rules in A-3. An incomplete transcript is a structural rejection.

For `agree`, both terminals MUST be comparable language terminals, complete canonical transcript bytes MUST be identical, `first_divergence_index` MUST be null, and `comparison_unavailable_at` MUST be null.

For `disagree`, both terminals MUST be comparable language terminals, complete canonical transcript bytes MUST differ, `first_divergence_index` MUST be the actual first divergence, and `comparison_unavailable_at` MUST be null.

For `not-comparable`, at least one terminal MUST be an infrastructure failure, `first_divergence_index` MUST be null, and `comparison_unavailable_at` MUST equal the smallest `next_form_index` of the failing side or sides.

Comparison fields that do not satisfy these rules are internally inconsistent and cause structural rejection. Final values that differ while `comparison.status` is `agree` cause structural rejection.

The standalone no-replay structural verifier checks only what is observable in the transcript top-level value events. A decision value at any top-level root other than the final root causes structural rejection. A decision value nested inside a list, a pair, or another canonical value within a recorded top-level value causes structural rejection. Whether a decision value was consumed as an intermediate primitive operand is a dynamic value-flow property. The no-replay structural verifier MUST NOT attempt to decide it and MUST NOT structurally reject on it. The checked-profile evaluator enforces the no-operand-consumption rule of A-4 at issuance, and the module-private evaluator tokens of C-ISSUE-05 bind that enforcement to the signed receipt, so verify-structure does not re-derive it.

Zero-root graphs, incomplete transcripts, internally inconsistent comparison fields, differing final values under `agree`, malformed graphs, and malformed event sequences are structural failures. They MUST NOT be represented as signability reasons.

A release-signed receipt MUST have an empty `diagnostics` array. An unsigned internal incident receipt may contain stable diagnostic codes. Diagnostics MUST NOT contain secrets, host paths, key information, or implementation-defined panic text.

The frozen boundary statement is the UTF-8 content between `BEGIN` and `END`. The delimiter lines and their line endings are excluded. The statement has no byte-order mark or trailing line ending.

```text
BEGIN
This receipt records structural consistency only. It is not authentication, an independent witness, or evidence of freshness. Deterministic gates may veto a result. Only a human operator gives final approval.
END
```

Object member order MUST follow `csk.artifact-json/v0`. Array order is significant.

The signer authenticates a claim that it executed the bound source and input. Structural verification independently checks deterministic derivations and internal consistency. Structural verification does not replay execution.

## 10. Digest representations

### A-7 Digest representations (amended v4)

Receipt-internal content-block hashing uses the following construction.

```text
H(label, content) =
  SHA256(UTF8(label) || 0x1F || content)
```

The resulting encoding is exactly 64 lowercase hexadecimal characters without a prefix.

The mappings are shown below.

```text
source.sha256
  H("csk.v0.source", exact source bytes)

input.sha256
  H("csk.v0.input", exact raw checked-input file bytes)

input.canonical_value_sha256
  H("csk.v0.input-canonical-value", canonical mapped Lispex value bytes)

canonical.normalized_sha256
  H("csk.v0.canonical", normalized program bytes)

graph.graph_sha256
meaning_env.graph_sha256
  H("csk.v0.graph", canonical graph bytes)

reference.transcript_sha256
  H("csk.v0.reference", canonical reference transcript bytes)

meaning_env.transcript_sha256
  H("csk.v0.meaning_env", canonical Meaning Environment transcript bytes)

boundary.statement_sha256
  H("csk.v0.boundary", frozen boundary statement bytes)
```

`execution.context_digest` uses the following closed context object.

```text
{
  "normalized_bytes_b64": <RFC 4648 standard padded base64 of the exact frozen normalized source bytes>,
  "input_canonical_value_sha256": <lowercase hex64>,
  "profile": "csk.checked-profile/v0",
  "engine_executable_sha256": <"sha256:" plus lowercase hex64>
}
```

Its member order MUST follow `csk.artifact-json/v0`. Its digest is computed as follows.

```text
execution.context_digest =
  H(
    "csk.v0.execution-context",
    csk.artifact-json/v0 bytes of the closed context object
  )
```

The context object values MUST equal `canonical.normalized_bytes_b64`, `input.canonical_value_sha256`, `execution.profile`, and `engine.executable_sha256`. Structural verification MUST recompute `execution.context_digest` and require equality with the recorded value.

The input file final LF required by P-1 MUST be included in the preimages for `input.sha256` and `input.byte_length`. It is not part of the mapped Lispex value preimage.

Executable identity uses an ordinary file digest.

```text
executable_file_sha256 =
  "sha256:" + lowercase_hex(
    SHA256(exact executable file bytes)
  )
```

No domain-separation label may be applied to executable bytes. The identical `sha256:<64hex>` value MUST appear in the following fields and records.

```text
engine.executable_sha256
execution.executable_sha256
the trust policy allowed_engine_sha256 entry
the release manifest executable entry
the external release descriptor
```

The publication identity MUST pin the digest of the external release descriptor. It MUST NOT duplicate the engine digest.

Repeated fields MUST be byte-identical. Version 0 has no comparison-block digest.

Structural verification MUST recompute every receipt-carried preimage digest. Source and input raw-byte digests MUST be recomputed when their external bytes are supplied. The mapped input digest MUST be re-derived from external input whenever external input is supplied.

The executable digest is an authenticated signer claim until consumer policy authorizes it. It is not a hardware-backed measurement.

## 11. DSSE and Ed25519

### C-DSSE-01 Envelope schema

A DSSE envelope MUST have exactly these top-level members.

```json
{
  "payloadType": "...",
  "payload": "...",
  "signatures": [
    {
      "keyid": "...",
      "sig": "..."
    }
  ]
}
```

The envelope MUST contain exactly one signature. Unknown members are forbidden at every level.

### C-DSSE-02 Payload type

The only payload type accepted by `verify-native` is:

```text
application/vnd.csk.differential-receipt.v0+json
```

No alias, case variant, parameter, suffix variation, or other version may be accepted as version 0.

### C-DSSE-03 Base64

`payload` and `sig` MUST use RFC 4648 standard base64 with `=` padding and no whitespace. Decoding followed by standard re-encoding MUST reproduce the submitted string exactly.

### C-DSSE-04 Signature input

The signature input MUST be the DSSE pre-authentication encoding:

```text
"DSSEv1" SP decimal_length(payloadType) SP payloadType
SP decimal_length(payload_bytes) SP payload_bytes
```

Lengths MUST be unsigned decimal byte lengths without a leading zero.

### C-DSSE-05 Signature algorithm

The signature MUST be Ed25519 over the DSSE pre-authentication bytes. Public keys MUST be raw 32-byte Ed25519 keys. Signature values MUST be exactly 64 bytes before base64 encoding.

Ed25519ph, Ed25519ctx, ECDSA, RSA, and algorithm negotiation are forbidden for version 0.

### C-DSSE-06 Exact payload bytes

The decoded payload of a native envelope MUST be exactly the canonical receipt bytes written to `payload.json` in the issue-native output directory. The signer MUST NOT parse and reserialize the payload after structural self-verification.

### C-DSSE-07 Manifest payload type

The signed replay corpus manifest MUST use:

```text
application/vnd.csk.replay-corpus-manifest.v0+json
```

Replay verification MUST apply the same DSSE framing, signature algorithm, key lookup, base64, and canonical payload rules.

### C-DSSE-08 Release descriptor payload type (amended v4)

The signed external release descriptor MUST use:

```text
application/vnd.csk.release-descriptor.v0+json
```

Release descriptor verification MUST apply the same DSSE framing, signature algorithm, key lookup, base64, and canonical payload rules. The decoded payload MUST be canonical `csk.artifact-json/v0` bytes for the closed schema required by C-ID-06.

### C-DSSE-09 Reproduction observation payload type (amended v8)

The signed reproduction observation R of C-ID-10 MUST use:

```text
application/vnd.csk.reproduction-observation.v0+json
```

Observation verification MUST apply the same DSSE framing, signature algorithm, out-of-band policy key lookup, base64, and canonical payload rules as the descriptor. The order is policy canonical gate and schema, observation envelope canonical gate and closed schema, keyid lookup and key selection in the consumer trust policy, selected-key payload-type authorization for this observation type, signature verification, then observation payload canonical gate and closed schema. The decoded payload MUST be canonical `csk.artifact-json/v0` bytes for the closed schema required by C-ID-10.

The observation envelope MUST satisfy the same exact-byte binding the descriptor satisfies. The base64 decode of `reproduction-observation.dsse.json` `payload` MUST be byte-identical to the exact canonical `reproduction-observation.json` bytes. A verifier MUST decode the envelope payload, require byte equality with the standalone `reproduction-observation.json`, and only then hash and render R, so the verified R and the rendered R are the same bytes.

The observation is signed under the release key. The observation envelope `signatures[0].keyid` MUST equal the descriptor `key_id` of C-ID-06, so R and D are signed by the same release key. A policy that authorizes the observation payload type for a key other than the descriptor `key_id` MUST NOT be used to accept R. A clean-room or publication verifier that verifies R MUST select the key only from the out-of-band consumer trust policy, never from a descriptor-adjacent field, and MUST additionally require the selected key to equal the descriptor `key_id`.

The descriptor signing key and release trust policy are release-layer artifacts inside or alongside the descriptor set. They MUST NOT be embedded in the source commit or release executable. The release executable MUST NOT embed its own digest. It MAY embed the source commit identifier as build provenance under C-ID-02, because the source commit is fixed before the build and embedding it does not introduce the executable digest into the committed tree.

Bootstrap verification MUST use the trusted verifier and out-of-band consumer trust policy required by C-REP-04. Archive-supplied code MUST NOT act as the bootstrap verifier.

## 12. Key handling and distribution

### C-KEY-01 Release key creation

The release Ed25519 private key MUST be generated from an operating-system cryptographic random source outside the repository and outside the distributed archive.

### C-KEY-02 Key handle

`issue-native --key-handle` MUST accept an opaque URI string. The artifact release implementation MUST support:

```text
pkcs8-file:///absolute/path
```

The URI MUST identify a PKCS#8 Ed25519 private key. Relative paths, inline keys, environment variables containing raw key bytes, and standard input are forbidden.

### C-KEY-03 No arbitrary signing interface (amended v8)

The public CLI MUST NOT expose a command that signs caller-supplied receipt or payload bytes.

`issue-native` MUST construct its payload from the source and input supplied to that invocation. The release-only corpus signer MUST construct its manifest from the corpus directory, rule files, and frozen manifests. The release descriptor signer MUST construct its payload from verified release outputs and build metadata. The reproduction-observation finalizer MUST construct the observation R from the authenticated descriptor, the exact clean-run report bytes, and the owner reports as required by C-ID-10. No release-only signer, including the observation finalizer, may accept a caller-supplied payload.

### C-KEY-04 Private-key absence

The archive, reachable Git objects, npm cache, Cargo vendor tree, logs, fixtures, crash files, and generated reports MUST contain no release private-key seed, expanded private key, PKCS#8 private key, or recoverable key material.

`artifact/scripts/scan-release-secrets` MUST pass.

### C-KEY-05 Public-key record

`artifact/trust/native-release-public-key.json` MUST contain exactly:

```json
{
  "native_public_key": "csk.native-public-key/v0",
  "key_id": "sha256:<64 lowercase hex digits>",
  "algorithm": "ed25519",
  "public_key": "<standard padded base64 of 32 raw bytes>"
}
```

It MUST pass the canonical byte gate.

### C-KEY-06 Distribution is not authorization

No verifier may discover or authorize a key by reading an envelope, receipt, public-key record, release manifest, release descriptor, or sibling file. The key MUST already appear in the consumer-supplied trust policy.

### C-KEY-07 Pre-signability key isolation

Before C-ISSUE-04 step 13, `issue-native` MAY validate only the syntax of the opaque key-handle URI string.

Before that step, it MUST NOT:

- read filesystem metadata for the handle
- canonicalize or resolve a path from the handle
- open a key file
- contact or query an HSM
- contact or query a KMS
- invoke a key-provider operation
- request credentials or key-provider authentication

URI syntax validation MUST operate only on the caller-supplied string.

### C-KEY-08 Counting key-provider audit (amended v8.5.1)

Every issuance refusal occurring before C-ISSUE-04 step 13, and every finalization refusal of C-ID-10 occurring before that finalizer resolves its key handle, MUST be tested with a counting key provider. The provider MUST record exactly zero metadata, resolution, open, query, authentication, load, and signing operations. Only refusals occurring BEFORE key-handle resolution are subject to the zero-key-access assertion. Post-key `key-loading-or-signing-failure` refusals and post-key `input-output-failure` refusals occurring while writing, flushing, or atomically publishing the already-constructed success set are outside that assertion and MUST NOT be asserted to have zero key accesses.

The aggregate audit MUST record exactly zero key accesses across all refused issuance fixtures and all PRE-KEY refused finalization fixtures, including L06 and L16. Post-key `key-loading-or-signing-failure` and post-key publication `input-output-failure` refusals are outside this aggregate.

## 13. Consumer trust policy

### C-POLICY-01 Exact schema (amended v8.1)

The reproduction trust policy MUST have this closed shape:

```json
{
  "trust_policy": "csk.native-trust-policy/v0",
  "minimum_versions": {
    "native_receipt": 0,
    "release_descriptor": 0,
    "replay_corpus_manifest": 0,
    "reproduction_observation": 0
  },
  "keys": [
    {
      "key_id": "sha256:<64 lowercase hex digits>",
      "algorithm": "ed25519",
      "public_key": "<standard padded base64>",
      "allowed_payload_types": [
        "application/vnd.csk.differential-receipt.v0+json",
        "application/vnd.csk.release-descriptor.v0+json",
        "application/vnd.csk.reproduction-observation.v0+json",
        "application/vnd.csk.replay-corpus-manifest.v0+json"
      ],
      "allowed_profiles": [
        "csk.checked-profile/v0"
      ],
      "allowed_engine_sha256": [
        "sha256:<64 lowercase hex digits>"
      ]
    }
  ]
}
```

The displayed member order is illustrative. Canonical output MUST follow `csk.artifact-json/v0`.

`allowed_profiles` is a field of each individual key entry. It is not a policy-wide authorization list.

### C-POLICY-02 Closed policy

Unknown fields, duplicate key identifiers, duplicate public keys, duplicate list entries, empty authorization lists, malformed digests, malformed profile identifiers, and unsupported algorithms MUST fail as `native-trust-policy-invalid`.

Each enum and field set in C-POLICY-01 is closed.

### C-POLICY-03 Key consistency

For every key entry, the computed domain-separated identifier MUST equal `key_id`. A mismatch MUST fail as `native-trust-policy-invalid`.

The identifier MUST be:

```text
"sha256:" + lowercase_hex(
  SHA256(
    UTF8("csk/native-key-id/v0") ||
    0x00 ||
    raw_32_byte_ed25519_public_key
  )
)
```

### C-POLICY-04 Minimum version

A supported payload version below the configured minimum MUST fail as `native-schema-version-below-policy`. An unknown version MUST fail as `unsupported-native-version` and MUST NOT be interpreted as an older version.

### C-POLICY-05 Exact engine authorization

Engine authorization MUST compare the lowercase `sha256:` digest as an exact string after syntax validation. Prefix, suffix, abbreviated, case-folded, and build-commit-only matches are forbidden.

Engine authorization MUST use only the `allowed_engine_sha256` field of the single key entry selected by the envelope `keyid`.

### C-POLICY-06 Profile identifier syntax (amended v4)

The CLI profile identifier MUST match this ASCII grammar:

```text
^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*/v(?:0|[1-9][0-9]*)$
```

A malformed identifier MUST be rejected as a usage error before semantic verification.

The verifier MUST first select exactly one key entry by the envelope `keyid`. It MUST then compare the expected profile identifier with that selected key entry's `allowed_profiles`.

Profile authorization MUST never use the union, intersection, or any other aggregation of `allowed_profiles` across multiple key entries.

A syntactically valid expected profile that is absent from the selected key entry's `allowed_profiles` MUST fail as `native-profile-disallowed`.

Only after the selected key authorizes the expected profile may the verifier compare the expected profile with the authenticated receipt profile. A difference MUST fail as `native-profile-mismatch`.

## 14. Release identity and external release descriptor

### C-ID-01 Generated identity file (amended v4)

`generated/artifact-identity.tex` MUST exist in the committed paper source tree and MUST define exactly this command:

```tex
\newcommand{\ArtifactFreezeCommit}{<full immutable ancestor commit>}
```

The committed file MUST NOT contain the source commit identifier, release descriptor digest, archive digest, engine digest, release key identifier, runtime, build environment, toolchain metadata, result digest, or equivalent resolved release field.

`ArtifactFreezeCommit` MUST be a full object identifier accepted by `git rev-parse --verify`. An abbreviated identifier or mutable branch name is forbidden. It MUST identify an ancestor of the final source commit.

The committed source tree MUST NOT contain its own commit hash. It also MUST NOT contain the descriptor hash, archive hash, or engine hash.

### C-ID-02 Identity derivation (amended v4)

`generated/artifact-identity.tex` MUST be generated by `artifact/scripts/generate-artifact-identity` before the final source commit and MUST never be edited manually.

The generator MUST fail if:

- the worktree or index is dirty
- the freeze commit identifier is malformed
- the freeze commit is not an ancestor of the current generation commit
- the generated file contains a field forbidden by C-ID-01
- the generated result differs from its committed version

The final source commit identifier MUST be derived only after the source tree is committed. It MUST NOT appear in the committed source tree. It MUST be recorded in the external descriptor required by C-ID-06 and in the external publication material required by C-ID-09. It MAY also appear as build provenance in the release executable and in the receipts that executable issues, because the source commit is fixed before the build and embedding it does not introduce any release digest into the committed tree.

The paper PDF MUST be regenerated after descriptor and publication-record creation. A PDF containing resolved release identity MUST NOT be committed into the source commit or included in the release archive.

### C-ID-03 Archive digest (amended v4)

The external `release-descriptor.json` MUST record the ordinary SHA-256 digest over the exact distributed `vouch-scored26-artifact.tar.zst` bytes.

The same digest MUST appear in `vouch-scored26-artifact.tar.zst.sha256`, which MUST remain outside the archive. The adjacent checksum is an internal consistency copy. It is not an independent authenticator and MUST NOT authorize archive extraction.

The archive digest MUST NOT appear in the committed identity file or anywhere else in the source commit.

### C-ID-04 Engine digest (amended v4)

The engine digest MUST be:

```text
"sha256:" + lowercase_hex(
  SHA256(exact release executable file bytes)
)
```

No domain-separation label may be applied.

The identical value MUST appear in:

```text
engine.executable_sha256 in every authenticated receipt
execution.executable_sha256 in every authenticated receipt
the release-layer trust policy allowed_engine_sha256 entry
the release-layer manifest executable entry
release-descriptor.json
```

The executable MUST be the exact release executable that issued every authenticated workload receipt.

The engine allow-list MUST be generated at the release layer. The release trust policy and engine allow-list MUST be inside or alongside the external descriptor set. Neither artifact may be committed into the source commit. The executable MUST NOT embed a policy, manifest, or other value that introduces its own executable digest into the executable. Embedding the source commit identifier as build provenance under C-ID-02 is permitted because it does not introduce the executable digest.

### C-ID-05 Key identifier (amended v4)

The release key identifier MUST equal:

```text
"sha256:" + lowercase_hex(
  SHA256(
    UTF8("csk/native-key-id/v0") ||
    0x00 ||
    raw_32_byte_ed25519_public_key
  )
)
```

The raw public key MUST match the release-layer public key authorized by the out-of-band consumer trust policy. The identical key identifier MUST appear in `release-descriptor.json`.

The key identifier and release public key MUST NOT appear in `generated/artifact-identity.tex`.

### C-ID-06 External release descriptor (amended v4)

`release-descriptor.json` MUST be external to the distributed archive and MUST contain exactly this closed schema:

```text
{
  "release_descriptor": "csk.release-descriptor/v0",
  "artifact_commit": <full immutable commit>,
  "artifact_freeze_commit": <full immutable ancestor commit>,
  "archive_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "engine_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "key_id": <"sha256:" plus 64 lowercase hex digits>,
  "exact_reproduction_results": [
    {
      "path": <normalized relative path>,
      "sha256": <"sha256:" plus 64 lowercase hex digits>
    }
  ],
  "target_triple": <string>,
  "toolchains": {
    "rustc": <exact version string>,
    "cargo": <exact version string>,
    "node": <exact version string>,
    "npm": <exact version string>,
    "typescript": <exact version string>,
    "glibc": <exact version string>,
    "dependency_version_manifest_digests": [
      {
        "path": <normalized relative path>,
        "sha256": <"sha256:" plus 64 lowercase hex digits>
      }
    ]
  },
  "build_image_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "build_parameters": {
    "linker": <exact linker identity and version>,
    "os_image_reference": <immutable image reference>,
    "build_path_policy": <exact build path policy string>,
    "source_date_epoch": <uint>,
    "locale": <exact locale string>,
    "build_id_policy": <exact build-id policy string>
  },
  "build_environment": {
    "rustflags": "",
    "cargo_encoded_rustflags": ""
  }
}
```

Unknown members are forbidden at every level. Every `uint` MUST be in the inclusive range `0` through `9007199254740991`.

Each `exact_reproduction_results` entry MUST bind one deterministic pre-descriptor result whose bytes are fixed by the pinned build. Non-deterministic and re-measured observations MUST NOT appear in the descriptor. They belong to the reproduction observation of C-ID-10. Each dependency version manifest entry MUST bind one manifest that fixes dependency versions. Both arrays MUST be nonempty and sorted by `path` in UTF-8 byte order. Duplicate paths are forbidden.

A normalized relative path MUST use `/` separators. It MUST NOT be empty, absolute, contain an empty segment, contain `.` or `..` as a segment, or contain a NUL byte.

The descriptor MUST be canonical `csk.artifact-json/v0`. The descriptor is deterministic. It MUST NOT contain `clean_run_runtime_seconds` or any post-run measurement. Those live in the clean-run report Q of C-FINAL-01 and the reproduction observation R of C-ID-10, which point at the descriptor one way, so no descriptor field ever binds a post-run observation.

Exact-payload clean-room reproduction is defined relative to the pinned `build_image_sha256`, toolchain values, dependency version manifest digests, and deterministic build parameters. A reproduction under different pins is not an exact-payload reproduction.

### C-ID-07 Signed release descriptor (amended v4)

`release-descriptor.dsse.json` MUST be a canonical DSSE envelope whose decoded payload is byte-identical to `release-descriptor.json`.

The envelope MUST use the payload type required by C-DSSE-08 and MUST be signed by the release key. The out-of-band consumer trust policy MUST explicitly authorize the selected key for that payload type.

Clean-room reproduction MUST verify the stored signature before archive extraction as required by C-REP-04. It MUST NOT regenerate the release signature.

### C-ID-08 Descriptor consistency (amended v8.4)

The release descriptor MUST satisfy all of these conditions:

```text
artifact_commit identifies source commit C0
artifact_freeze_commit == ArtifactFreezeCommit in C0
artifact_freeze_commit is an ancestor of artifact_commit
key_id == descriptor-envelope.signatures[0].keyid == the selected policy key.key_id
engine_sha256 == the release executable file digest
archive_sha256 == the distributed archive file digest
target_triple == the release executable target triple
every exact_reproduction_results entry == the digest of its named result
every dependency manifest digest == the digest of its named manifest
build_image_sha256 == the immutable build container digest
embedded CSK_BUILD_COMMIT == receipt.execution.build_commit
receipt.execution.build_commit == artifact_commit
artifact_commit == the contents of release/COMMIT
```

The descriptor signature authenticates the release claim. Structural comparison with locally rebuilt artifacts does not reproduce the release signature.

The source commit MUST NOT be changed to insert any resolved descriptor value. A changed source tree is a different source commit and requires a new release archive and descriptor.

### C-ID-09 Four-layer release identity (amended v8.3)

Release identity MUST use exactly these four layers:

```text
Layer 1   source commit C0
Layer 2   release archive A built from C0
Layer 3A  signed deterministic external descriptor D
Layer 3B  clean-run report Q emitted by the clean-room run
Layer 3C  signed post-run reproduction observation R
Layer 4   external publication record P
```

Layer 1 MUST contain no self commit hash, descriptor hash, archive hash, or engine hash.

Layer 2 MUST be built from Layer 1. It MUST NOT contain a resolved publication record or a resolved paper PDF.

Layer 3A, the descriptor D, MUST bind the full source commit identifier, `sha256(A)`, the engine digest, the deterministic exact-reproduction result digests, toolchain pins, build container digest, deterministic build parameters, and release metadata required by C-ID-06. D MUST NOT bind any post-run observation. Layer 3B, the clean-run report Q of C-REP-10, is constructed by the trusted outer clean-room driver of C-REP-04 at the end of the clean-room run and carries `sha256(D)` plus the exact full-file digests of all five phase-1 reports. Layer 3C, the reproduction observation R of C-ID-10, is emitted afterward by an external finalizer and carries `sha256(D)` and `sha256(Q)`. D MUST NOT carry `sha256(Q)` or `sha256(R)`, Q MUST NOT carry `sha256(R)`, so the whole graph is one way and D can be built before the clean-room run.

Layer 4 MUST remain outside Layer 1 and Layer 2. Its `release_descriptor_sha256` MUST be the ordinary SHA-256 over the exact canonical `release-descriptor.json` bytes, and its `reproduction_observation_sha256` MUST be the ordinary SHA-256 over the exact canonical `reproduction-observation.json` payload bytes, never over the DSSE envelope bytes. The publication record MUST contain exactly:

```text
{
  "publication_record": "csk.release-publication/v0",
  "release_descriptor_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "reproduction_observation_sha256": <"sha256:" plus 64 lowercase hex digits>
}
```

Unknown members are forbidden. The publication record MUST be canonical `csk.artifact-json/v0`. The binding direction is exactly: D does not bind R; R binds D and Q; P binds D and R. So the one-way generation order is D, then Q, then R, then P.

P is a non-authoritative convenience index, not a cryptographic trust root. The signed reproduction observation R is the authority for the post-run values, and the signed descriptor D is the authority for the deterministic release identity. P is unsigned canonical JSON whose only role is to name, by ordinary SHA-256, which D and which R a given publication uses. The paper build MUST trust the signed R that P names after verifying R under C-DSSE-09, and MUST NOT treat P itself as an authenticator. If a future release wants P to be authoritative, it MUST either sign P as its own DSSE envelope or pin the P digest in an out-of-band publication root such as the paper metadata or a transparency log; the current design does neither and P stays a convenience index.

### C-ID-10 Post-run reproduction observation (amended v8.5.1)

`reproduction-observation.json` MUST be external to the archive and to the descriptor, and MUST contain exactly this closed schema:

```text
{
  "reproduction_observation": "csk.reproduction-observation/v0",
  "release_descriptor_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "clean_run_report_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "clean_run_runtime_seconds": <uint>,
  "performance_observations": [
    { "metric": <one of the four C-PERF-05 metric literals>, "statistic": "median" | "p95" | "maximum", "unit": <the unit literal C-PERF-05 registers for that metric>, "value": <uint> }
  ],
  "reproduced_result_comparisons": [
    { "path": <normalized relative path>, "matched": <boolean> }
  ],
  "verify_only_observational_results": [
    { "path": <normalized relative path>, "sha256": <"sha256:" plus 64 lowercase hex digits> }
  ],
  "fixture_results": {
    "built": { "expected": <uint>, "matched": <uint>, "mismatched": <uint>, "skipped": <uint> },
    "design_target": { "listed": <uint>, "implemented": <uint>, "matched": <uint>, "not_implemented": <uint> }
  },
  "workload_summary_sha256": <"sha256:" plus 64 lowercase hex digits>,
  "mutation_summary_sha256": <"sha256:" plus 64 lowercase hex digits>
}
```

Unknown members are forbidden. R MUST be canonical `csk.artifact-json/v0`. R MUST be produced only after the clean-room run by the external finalizer command `npm run scored26:finalize-observation`, release lifecycle phase 2, which takes the authenticated D and the exact Q as inputs and emits the signed R and the publication record P. R MUST carry `release_descriptor_sha256` equal to `sha256(D)` and `clean_run_report_sha256` equal to `sha256(Q)`, where Q is the clean-run report of C-REP-10. R MUST NOT carry `sha256(P)`, so its references to D and Q are one way. Every array MUST be sorted by `path`, or by `metric` and then `statistic`, in UTF-8 byte order, with no duplicate `path` and no duplicate `(metric, statistic)` pair. The performance array carries one entry per metric-and-statistic pair, so `metric` alone is not unique in it. `clean_run_runtime_seconds` MUST equal the value recorded in Q and is not remeasured here. Each `performance_observations` entry MUST carry an explicit `unit`.

R MUST be signed as its own DSSE envelope `reproduction-observation.dsse.json` with the payload type of C-DSSE-09 under the release key, whose `keyid` equals the descriptor `key_id` of C-ID-06. The base64 decode of the envelope payload MUST be byte-identical to the exact canonical `reproduction-observation.json` bytes, exactly as C-DSSE-09 requires. No specific runtime, performance, or observational value is a conformance requirement. The exact-reproduction result digests are compared byte-identically under C-REP-06. The observational values here are recorded, not reproduced.

The reproduction-observation finalizer MUST construct R itself from the authenticated descriptor D, the exact clean-run report Q bytes, the owner fixture report, the owner workload report, the owner mutation report, the owner performance report, and the exact reproduction-comparison results. It MUST NOT accept caller-supplied R payload bytes. This extends the no-arbitrary-signing rule of C-KEY-03 to the release observation, so no interface signs a caller-provided observation.

Before it opens the release key handle, the finalizer MUST verify every check below and MUST refuse to sign if any fails. The release-binding check `rb-q-descriptor` comes first, because it is the one that prevents an honest finalizer from combining the deterministic identity of one release with the post-run observations of another. The other two release-binding checks read the R the finalizer itself constructs, so they run after that construction, in the evaluation order fixed below:

Each check carries a stable identifier in the left column. Those identifiers are the closed
`failed_check` enum of the finalize report below, so a refusal names exactly one of them.

```text
release binding
  rb-q-descriptor      Q.release_descriptor_sha256     == SHA256(exact release-descriptor.json bytes)
  rb-r-descriptor      R.release_descriptor_sha256     == Q.release_descriptor_sha256
  rb-r-cleanrun        R.clean_run_report_sha256       == SHA256(exact clean-run-report.json bytes)

Q is a faithful derivation of the owner reports
  qd-fixture-bytes     Q.fixture_report_sha256         == SHA256(exact artifact/results/fixture-results.json bytes)
  qd-fixture           Q.fixture_results               == derive(exact artifact/results/fixture-results.json bytes)
  qd-workload-bytes    Q.workload_report_sha256        == SHA256(exact artifact/workload/workload-results.json bytes)
  qd-workload          Q.workload                      == derive(exact artifact/workload/workload-results.json bytes)
  qd-mutation-bytes    Q.mutation_report_sha256        == SHA256(exact artifact/mutation/mutation-results.json bytes)
  qd-mutation          Q.mutation                      == derive(exact artifact/mutation/mutation-results.json bytes)
  qd-performance       Q.performance_report_sha256     == SHA256(exact artifact/performance/performance-results.json bytes)
  qd-comparisons       Q.exact_reproduction_comparisons_sha256
                                                       == SHA256(exact <clean-room-root>/external/exact-reproduction-comparisons.json bytes)
  qd-comparison-expected
                       every <clean-room-root>/external/exact-reproduction-comparisons.json row's expected_sha256
                                                       == the sha256 D records for that row's path
  qd-comparison-matched
                       every <clean-room-root>/external/exact-reproduction-comparisons.json row's matched
                                                       == (that row's expected_sha256 == its observed_sha256)

R is a faithful re-serialization of Q and the owner reports
  rd-runtime           R.clean_run_runtime_seconds     == Q.clean_run_runtime_seconds
  rd-fixture           R.fixture_results               == Q.fixture_results
  rd-performance       R.performance_observations      == derive(exact artifact/performance/performance-results.json bytes)
  rd-workload-digest   R.workload_summary_sha256       == SHA256(exact artifact/workload/workload-results.json bytes)
  rd-mutation-digest   R.mutation_summary_sha256       == SHA256(exact artifact/mutation/mutation-results.json bytes)
  rd-comparisons       R.reproduced_result_comparisons == derive(exact <clean-room-root>/external/exact-reproduction-comparisons.json bytes)
  rd-comparison-paths  R.reproduced_result_comparisons paths == exactly the D.exact_reproduction_results paths
  rd-comparisons-matched
                       every R.reproduced_result_comparisons entry has matched == true
  rd-observational-set R.verify_only_observational_results == the exact closed observational file set
                                                             with each entry's sha256 equal to both that file's bytes
                                                             and its corresponding Q owner-report digest
```

Every `derive` above is a total function of exactly the named file's bytes, defined by the condition that owns that file: C-FIX-02 for the fixture summary, C-WL-24 for the workload summary, C-MUT-08 for the mutation summary, C-PERF-05 for the performance observations, and C-REP-04 for the exact-reproduction comparisons. The finalizer runs outside the clean room, so it can only check what phase 1 recorded: the exact-reproduction comparisons are an outer-driver artifact whose digest Q pins, which is why the finalizer takes them as an input rather than recomputing them. The release-binding set closes a cross-release mix-up. Without `Q.release_descriptor_sha256 == SHA256(D)` a finalizer handed the descriptor of one release and the clean-run report of another could sign a single valid R whose deterministic identity and post-run observations come from different releases, and every downstream hash check would still pass. `matched == true` for every reproduced result is required because a conforming release reproduces every deterministic artifact byte for byte; a `false` entry is a reproduction failure, not a recordable observation, and MUST NOT be signed as a conforming release. The `derive` function for each report is the canonical, deterministic summary derivation defined by the condition that owns that report, and it takes the exact file bytes as its only input, so a buffer mix-up or a wrong report selection by an honest finalizer is caught before any key access. The five Q digest checks bind the exact bytes of the fixture, workload, mutation, performance, and comparison reports, not merely their summaries. For each owner report, the finalizer computes its full-file digest and every derivation from the same entry buffer.

The observational file set of `verify_only_observational_results` is exactly the release-layer observational artifacts that are recorded but not reproduced byte for byte, at exactly the paths their owner conditions require: `artifact/workload/workload-results.json` of C-WL-01, `artifact/mutation/mutation-results.json` of C-MUT-01, `artifact/results/fixture-results.json` of C-FIX-02, and `artifact/performance/performance-results.json` of C-PERF-05. These are the same files the paper reads its workload, mutation, fixture, and performance values from, so no empirical value is ever read from a copy outside the digest-verified set. Each entry's `sha256` MUST be the ordinary SHA-256 of that file's exact bytes. No other path may appear and none may be omitted.

The `rd-observational-set` equality to Q is exact under this fixed mapping:

```text
artifact/results/fixture-results.json        -> Q.fixture_report_sha256
artifact/workload/workload-results.json      -> Q.workload_report_sha256
artifact/mutation/mutation-results.json      -> Q.mutation_report_sha256
artifact/performance/performance-results.json -> Q.performance_report_sha256
```

For every row, `R.verify_only_observational_results[i].sha256` MUST equal the mapped Q digest byte for byte as well as SHA-256 of that report's immutable entry buffer. A summary-equivalent replacement therefore fails before key access.

The finalizer is a release-key signer, so it MUST have an exact interface with the same rigor as `issue-native`. The phase-2 command is:

```text
npm run scored26:finalize-observation -- \
  --descriptor <path to release-descriptor.json> \
  --descriptor-envelope <path to release-descriptor.dsse.json> \
  --trust-policy <path to the out-of-band consumer trust policy> \
  --clean-run-report <path to the external clean-run-report.json> \
  --fixture-report <path to artifact/results/fixture-results.json> \
  --workload-report <path to artifact/workload/workload-results.json> \
  --mutation-report <path to artifact/mutation/mutation-results.json> \
  --performance-report <path to artifact/performance/performance-results.json> \
  --reproduction-comparisons <clean-room-root>/external/exact-reproduction-comparisons.json \
  --key-handle <opaque key-handle URI> \
  --out-dir <path>
```

At command entry, before any validation, the finalizer MUST open and read each input path EXACTLY ONCE into a private immutable byte buffer, exactly as `issue-native` reads its raw input under P-1. Canonical validation, schema validation, digest computation, every `derive`, the construction of R, the construction of P, and the generation of the finalize report MUST consume ONLY those buffers. Reopening any input path after entry is FORBIDDEN, and no check may re-read a path it has already hashed. The rule MUST be observable: the fixture harness supplies a counting file provider that records exactly one open and one read per declared input path for the whole run, and fixture L08 asserts it. Without this rule the checks below are individually satisfiable against different contents of the same path: a workload report could satisfy `qd-workload` and then be replaced before `rd-workload-digest` hashes it, so the signed R would authenticate bytes the clean-run report never derived from.

The exact sequence MUST be: authenticate D through its envelope and the out-of-band trust policy exactly as C-REP-04 does, including the three-way equality `D.key_id == descriptor-envelope.signatures[0].keyid == selected policy key.key_id` in the authenticated payload step immediately following descriptor signature verification; canonical-gate every input BUFFER and validate it against the schema its owner condition defines, which for the fixture, workload, mutation, and performance reports means the closed summary member and the report tag that condition fixes, with additional members permitted and ignored; run `rb-q-descriptor` and every Q-derivation check above; construct R itself from those authenticated inputs; run `rb-r-descriptor`, `rb-r-cleanrun`, and every R-derivation check above against the constructed R; and only then resolve the key handle. From the loaded private key the finalizer MUST derive the public key and compute its csk native key ID, and MUST require `loaded_key_id == D.key_id`. It MUST sign the exact canonical R JSON bytes and construct the new R envelope. The finalizer MUST invoke the complete C-DSSE-09 verifier on the newly constructed envelope and the exact in-memory R bytes before publication. Only after every loaded-key and self-verification requirement succeeds may the finalizer construct the success publication set and atomic-publish it. A loaded-key identifier mismatch, signing failure, or new-envelope self-verification failure is the existing `key-loading-or-signing-failure`, exits 4, has `failed_check`, `input_artifact`, and `underlying_error` null, publishes no R, R envelope, or P, and introduces no new error class.

A failure of the descriptor three-way equality is `descriptor-authentication-failed`, exits 1, has `failed_check` null, and occurs before any key-handle access. The key handle is an opaque URI supplied by the caller and is resolved exactly once, after every check has passed. Until every release-binding, Q-derivation, and R-derivation check above has passed, syntactic validation of the key-handle URI is the only permitted key-handle operation. The finalizer MUST obey the pre-signability key-isolation prohibitions of C-KEY-07 with issuance key resolution read as finalizer key-handle resolution: no key-file metadata read, no path canonicalization, no key-file open, no HSM or KMS query, no other key-provider operation, and no credential request. The counting key-provider audit of C-FIX-03 MUST record exactly zero key accesses for every finalization refusal that occurs BEFORE key-handle resolution, including L06 and L16. A refusal after key-handle resolution may be exactly `key-loading-or-signing-failure` or `input-output-failure` occurring while writing, flushing, or atomically publishing the already-constructed success set. Only refusals occurring BEFORE key-handle resolution are subject to the zero-key-access assertion. Post-key key-loading-or-signing failures AND post-key publication I/O failures are outside that assertion.

On success the finalizer MUST publish exactly these files into `--out-dir`, written to a staging directory and published by a single rename on the same filesystem:

```text
reproduction-observation.json
reproduction-observation.dsse.json
release-publication.json
finalize-report.json
```

On refusal it MUST publish only `finalize-report.json`, by the same staging-and-rename discipline, and MUST NOT write a partial observation, envelope, or publication record. An `--out-dir` that already exists is a usage error, raised before any check and before any key operation, so a finalization can never overwrite a previous one. A staging directory that is not on the same filesystem as `--out-dir` is an input or output failure, raised before signing, because the single-rename publication would otherwise be unachievable and undiagnosed.

An `input-output-failure` occurring after key-handle resolution while writing, flushing, or atomically publishing the already-constructed success set MUST exit 3, MUST leave no final `--out-dir`, and MUST leave no partially published R, envelope, or P. It reuses the existing `input-output-failure` class and the existing publication carve-out and introduces no new error class. Key access is permitted and the counting key provider MUST record it as nonzero. If the same I/O reason prevents publication of `finalize-report.json`, the finalizer MUST report on standard error only.

`finalize-report.json` MUST be canonical `csk.artifact-json/v0` and MUST carry exactly this closed schema, so a refusal is machine-readable rather than prose:

```text
{
  "finalize_report": "vouch.scored26-finalize-report/v0",
  "status": "finalized" | "refused",
  "primary_error": <null when finalized, else one of the closed error classes below>,
  "failed_check": <the exact check identifier when primary_error is release-binding-mismatch, clean-run-derivation-mismatch, or observation-derivation-mismatch; null otherwise>,
  "input_artifact": <the failing input when primary_error is finalizer-input-invalid; null otherwise>,
  "underlying_error": <the input fault when primary_error is finalizer-input-invalid; null otherwise>
}
```

`primary_error` is closed and exhaustive:

```text
descriptor-authentication-failed
finalizer-input-invalid
release-binding-mismatch
clean-run-derivation-mismatch
observation-derivation-mismatch
usage-error
input-output-failure
key-loading-or-signing-failure
```

`finalizer-input-invalid` covers every failure of an input buffer that occurs BEFORE any release-binding or derivation check can run, because such a failure has no `failed_check` identifier. It carries two further closed members:

```text
input_artifact =
  descriptor | descriptor-envelope | trust-policy
  | clean-run-report | fixture-report | workload-report | mutation-report
  | performance-report | reproduction-comparisons
  | observation | observation-envelope | publication-record

underlying_error =
  artifact-resource-limit | non-canonical-artifact-json | schema-invalid
```

This one closed enum names every input of BOTH release commands, and each command emits only the values it actually reads. `observation`, `observation-envelope`, and `publication-record` are publication-check inputs, so the finalizer never emits them. The publication-check reuses this same closed enum for its own `publication-input-invalid` and for its `input-output-failure`.

`descriptor-authentication-failed` TAKES PRECEDENCE over `finalizer-input-invalid` for the descriptor, the descriptor envelope, and the trust policy: any canonical, resource, schema, key-selection, or signature failure inside the C-REP-04 authentication sequence is reported as `descriptor-authentication-failed` with `input_artifact` and `underlying_error` null. The finalizer therefore never emits `descriptor`, `descriptor-envelope`, or `trust-policy` in `input_artifact`, and `finalizer-input-invalid` applies only to the six non-authentication input buffers.

`artifact-resource-limit` and `non-canonical-artifact-json` are the same codes the common JSON and resource conditions require, so the finalizer does not invent a second vocabulary for the same faults. `input_artifact` and `underlying_error` are `null` unless `primary_error` is `finalizer-input-invalid`.

`failed_check` is the exact identifier of the first check that failed, drawn from the closed enum of the check identifiers in the release-binding, Q-derivation, and R-derivation blocks above, exactly one identifier per check line. The finalizer MUST report the FIRST failing check in this evaluation order, which is the order the sequence above runs them and not merely the order they are written:

```text
rb-q-descriptor
then the Q-derivation block in written order
then rb-r-descriptor, then rb-r-cleanrun
then the R-derivation block in written order
```

So a refusal is deterministic and a fixture can record a single expected value. The block a check belongs to fixes its `primary_error`: an `rb-` check yields `release-binding-mismatch`, a `qd-` check yields `clean-run-derivation-mismatch`, and an `rd-` check yields `observation-derivation-mismatch`. `qd-comparison-expected` and `qd-comparison-matched` are what stop a comparison row that claims `matched` true while its two digests differ; without them such a row is schema-valid and every other check passes, so a reproduction failure could be signed as a conforming release. The finalizer runs outside the clean room and cannot re-hash a reproduced file, so it checks the row against D and against itself; the trusted outer driver is what binds `observed_sha256` to the actual bytes. A refusal whose `primary_error` is `descriptor-authentication-failed`, `usage-error`, `input-output-failure`, or `key-loading-or-signing-failure` does not fail one of those checks, so its `failed_check` is `null`.

The finalizer MUST use this closed exit-code table, mirroring C-ISSUE-10:

| Exit | Meaning |
|---:|---|
| 0 | Observation, envelope, publication record, and report published successfully |
| 1 | Descriptor-authentication, input-validity, release-binding, Q-derivation, or R-derivation refusal |
| 2 | Usage error, including a pre-existing `--out-dir` |
| 3 | Input or output failure, including a cross-filesystem staging directory |
| 4 | Key loading or signing failure |

Exit 0 means signed and published. No refusal exit may be confused with success. Every refusal exit MUST be accompanied by a `finalize-report.json` whose `status` is `refused`, with exactly three carve-outs, mirroring the atomicity carve-out of C-ISSUE-09:

```text
1  a usage error raised because --out-dir already exists
2  an input or output failure that prevents the single-rename publication
3  a usage error raised BEFORE exactly one syntactically valid and usable --out-dir
   has been obtained, which includes a missing, empty, repeated, or malformed
   --out-dir and any unknown option encountered before --out-dir is parsed
```

In those three cases the finalizer MUST write no file at any final path and MUST report the error on standard error, because publishing a report would overwrite a previous finalization, require the very rename that failed, or have no output directory to publish into at all. Every OTHER usage error, raised after exactly one usable `--out-dir` has been obtained, MUST publish a report-only staging directory by the same single rename. Every fixture-manifest row for a finalizer refusal, including L06, records its expected exit code, expected `primary_error`, expected `failed_check`, expected `input_artifact`, and expected `underlying_error` from these closed sets.

### C-REP-10 Clean-run report (amended v8.3)

The clean-run report Q is defined by C-FINAL-01 and constructed by the trusted outer clean-room driver of C-REP-04 after the `npm run scored26:reproduce` run, written atomically to the external path `<clean-room-root>/external/clean-run-report.json` outside the worktree. It MUST carry `release_descriptor_sha256` equal to `sha256(D)`, the fixture, workload, mutation, and performance results, the full-file digests of the fixture, workload, mutation, performance, and external exact-reproduction comparison reports, and `clean_run_runtime_seconds` measured directly during the run by the outer driver. For each owner report, the outer driver MUST compute the summary derivation, full-file digest, and Q construction from the same read-once immutable buffer. Q MUST NOT carry `sha256(R)`, `sha256(P)`, or `paper_claims_matched`. The strict one-way generation order is D first in phase 0, then the phase 1 clean-room run produces the owner reports and the outer driver produces the comparison and Q, then the phase 2 finalizer emits the signed R that binds `sha256(D)` and `sha256(Q)` and the publication record P that binds `sha256(D)` and `sha256(R)`, then the phase 3 publication-check verifies the chain, renders the paper, and emits the terminal report S. No object binds an object created after it.

The paper PDF is a Layer-4 derived publication artifact. It MUST render the resolved deterministic identity values from the authenticated descriptor D and the post-run values from the signed reproduction observation R that the publication record P names, after the publication-check command of C-REP-08 verifies R and the full chain. P is a convenience index and is not itself the authority for any rendered value. The paper MUST be regenerated after Layer 3 and Layer 4 exist. It MUST never be committed into C0 or inserted into A with resolved release identity.

## 15. Mutant build seam and metadata

### A-8 Mutant build seam (amended v3)

The twelve mutants are compile-time single-site variants selected by `SCORED_MUTANT`. Both participating build scripts MUST read the variable at build time and MUST NOT read it at runtime.

An empty or absent value MUST build the unmutated release. A nonempty value MUST be exactly one identifier from `M01` through `M12`, activate exactly one registered site, and be recorded in build metadata.

The class mapping is closed:

```text
Lowering
  M01
  M02

Graph evaluator
  M03
  M04

Source evaluator
  M05
  M06

Shared numeric
  M07
  M08

Path serialization
  M09
  M10

Shared reader and normalizer
  M11
  M12
```

The path mapping and transformations are:

```text
M09
  Meaning Environment graph-side path serialization.
  Replace the final graph-side value event value with a different canonical
  value of the same schema.

M10
  Reference-side canonical-value mutation.
  Before calling the shared canonical writer, replace a string value containing
  U+000A with the same string where each U+000A is replaced by U+005C followed
  by U+006E.
```

M10 MUST mutate only the reference-side canonical value. It MUST then call the unchanged shared canonical writer. It MUST produce a schema-valid receipt with a genuine value disagreement.

Comparison code, canonical writers, verifiers, workload files, and test expectations MUST remain byte-identical across mutant and unmutated builds.

M07, M08, M11, and M12 affect the shared substrate. They are common-mode outcomes when both paths change identically and comparison remains `agree`.

`issue-native` MUST refuse every mutant build under C-ISSUE-12. Mutation experiments MUST use the internal non-signing mutation runner.

### A-9 Build metadata and refusal ordering (amended v3)

Both build scripts MUST independently:

- read `SCORED_MUTANT`
- emit `cargo:rerun-if-env-changed=SCORED_MUTANT`
- accept only an empty value or one identifier from `M01` through `M12`
- expose the selected identifier through compile-time configuration
- reject every other value as a build error

The release build MUST export these compile-time constants:

```text
CSK_LISPEX_VERSION
CSK_BUILD_COMMIT
CSK_TARGET_TRIPLE
CSK_SCORED_MUTANT
```

`CSK_BUILD_COMMIT` MUST be the lowercase 40-hex output of `git rev-parse --verify HEAD`. A non-detached symbolic state, dirty worktree, dirty index, or malformed commit value MUST make a release build fail.

Executable identity MUST be computed from one open file handle to the exact running executable. It MUST NOT come from caller input. The value MUST be copied unchanged into both receipt executable fields.

Mutant status is checked by the signability gate at C-ISSUE-04 step 11 and by the engine, invocation, and mutant self-check at step 12. No key-handle access may occur before step 13.

### A-18 Mutant configuration guard

The Rust build MUST expose each selected mutation as a `scored_mutant` configuration value.

A compile-time assertion MUST count active `scored_mutant` values and enforce:

```text
CSK_SCORED_MUTANT is empty
  active scored_mutant count == 0

CSK_SCORED_MUTANT is M01 through M12
  active scored_mutant count == 1
  active scored_mutant value == CSK_SCORED_MUTANT
```

Any mismatch MUST terminate compilation with `compile_error!`.

A release build MUST require `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` to be absent or empty. The checked values MUST be recorded as empty strings in the release descriptor.

A cfg-injection fixture MUST build with:

```text
RUSTFLAGS=--cfg scored_mutant
```

The fixture MUST fail to compile. A build that accepts an unregistered, unpaired, duplicated, or environment-injected mutant configuration is nonconforming.

## 16. `issue-native` interface

### C-ISSUE-01 Command form (amended v4)

The exact release interface is:

```text
lispex issue-native
  --source <path>
  --input <path>
  --profile <profile-id>
  --key-handle <uri>
  --out-dir <path>
```

Every argument is required exactly once. Positional arguments are forbidden. No other output option is accepted. An `--envelope-out`, `--payload-out`, or `--report-out` option MUST produce a usage error with exit code 2.

Successful issuance publishes a directory containing exactly `payload.json`, `envelope.dsse.json`, and `issue-report.json`. A handled failure publishes a directory containing exactly `issue-report.json`. Both are published by the single atomic directory rename of C-ISSUE-09.

If `--out-dir` already exists, issuance MUST fail with a usage error before any signing and MUST NOT overwrite it. If the staging directory and `--out-dir` are on different filesystems, issuance MUST fail as `artifact-io-error` before signing, because the single-rename publication is then impossible. A crash before the rename leaves no `--out-dir`, so recovery is a clean retry.

The profile identifier MUST pass C-POLICY-06 syntax. The only profile supported for issuance in version 0 is:

```text
csk.checked-profile/v0
```

### C-ISSUE-02 Forbidden inputs

`issue-native` MUST reject `--receipt`, `--payload`, `--decision`, `--transcript`, caller-supplied engine metadata, duplicate options, and unknown options as usage errors.

Caller-supplied evaluator tokens and caller-supplied transcript objects are forbidden.

### C-ISSUE-03 Immutable reads (amended v4)

Source and input MUST each be opened and read exactly once.

At API entry, the implementation MUST make private defensive copies of the source and input byte buffers. Hashing, parsing, normalization, evaluation, derivation checking, receipt construction, and output generation MUST consume those same private buffers.

Reopening either path or consulting a caller buffer after the defensive copy is forbidden.

The issuer MUST create a fresh invocation nonce for each invocation. It MUST compute one context digest from the frozen normalized source bytes, the canonical input value digest, the profile identifier, and the running engine executable digest.

The invocation nonce and context digest MUST remain bound to the private invocation state until issuance terminates.

### C-ISSUE-04 Execution sequence (amended v4)

The command MUST perform these steps in order:

1. CLI syntax and resource checks.
2. Immutable source and input reads.
3. Source parsing and checked-input host parsing.
4. Checked-profile validation and deterministic normalization.
5. Deterministic lowering to the complete canonical graph.
6. Reference evaluation and creation of one live `ReferenceTraceToken`.
7. Meaning Environment evaluation and creation of one live `MeaningTraceToken`.
8. Token-bound transcript comparison and receipt construction.
9. Canonical payload serialization.
10. Structural self-verification and token-binding self-verification under A-11.
11. Release signability gate under C-ISSUE-12.
12. Engine, invocation, build environment, and mutant self-check.
13. Key-handle resolution and open.
14. DSSE signing.
15. Atomic output publication under C-ISSUE-09.

Failures before step 5 completes are pipeline errors and MUST produce no differential receipt.

An infrastructure failure during step 6 or step 7 MUST be represented by the applicable infrastructure terminal required by A-3. The full graph and resulting receipt MUST proceed to comparison and structural self-verification. Because an infrastructure-failure terminal makes the comparison `not-comparable`, the signability gate MUST refuse issuance with reason `comparison-not-agree`, which precedes `terminal-not-completed` in the closed reason order of C-ISSUE-12. The infrastructure-failure codes `native-reference-execution-failed` and `native-meaning-execution-failed` are transcript terminal codes, not issue-report primary errors.

Every refusal at or before step 12 MUST occur before key-handle resolution, key-provider opening, or key-provider query.

### C-ISSUE-05 Receipt construction (amended v4)

The command MUST create a receipt with exactly these required top-level fields:

```text
differential_receipt
engine
execution
source
input
canonical
graph
reference
meaning_env
comparison
diagnostics
boundary
```

The exact tag MUST be:

```text
csk.differential-receipt/v0
```

The receipt builder MUST accept exactly one live `ReferenceTraceToken` and exactly one live `MeaningTraceToken`.

Each evaluator returns exactly one module-private token with this logical shape:

```text
ReferenceTraceToken {
  invocation_nonce
  context_digest
  normalized_sha256
  input_canonical_value_sha256
  profile
  budgets
  transcript
}

MeaningTraceToken {
  invocation_nonce
  context_digest
  graph_sha256
  input_canonical_value_sha256
  profile
  budgets
  transcript
}
```

These token types MUST be unforgeable outside their defining evaluator module. Their transcript fields MUST NOT be independently accepted by the receipt builder.

The builder MUST reject caller-supplied transcript objects, forged tokens, consumed tokens, and tokens created by a prior invocation.

The two tokens MUST have identical `invocation_nonce`, `context_digest`, `input_canonical_value_sha256`, `profile`, and `budgets` fields. Those fields MUST also equal the current invocation state.

The source, graph, input, and transcripts inserted into the receipt MUST come from the current invocation and the two accepted live tokens.

### C-ISSUE-06 Execution block (amended v4)

The receipt `execution` object MUST include:

```text
invocation = native-checked
context_digest
profile = csk.checked-profile/v0
lispex_version
build_commit
target_triple
executable_sha256
build_variant = release | mutant
mutant_id = string | null
```

The `build_variant` enum is closed and exhaustive.

A release build MUST have `build_variant` equal to `release` and `mutant_id` equal to null.

A mutant build MUST have `build_variant` equal to `mutant` and a nonempty `mutant_id`.

The executable digest, build commit, target triple, Lispex version, build variant, and mutant identifier MUST be obtained from the running build and MUST NOT be caller-controlled.

The context digest MUST bind the frozen source normalized bytes, `input.canonical_value_sha256`, the profile identifier, and `executable_sha256` using the contract-defined domain-separated digest encoding.

### C-ISSUE-07 Self-verification (amended v4)

The canonical payload MUST pass the same schema, digest, derivation, graph, transcript, comparison, input mapping, boundary, and cross-field checks used by `verify-structure`.

Self-verification MUST use the private immutable source and input buffers already held by issuance.

It MUST decode and parse `canonical.normalized_bytes_b64`, lower the normalized program deterministically, serialize the resulting graph with `csk.artifact-json/v0`, and require byte identity with the canonical bytes of `graph.value`.

It MUST reparse the external input buffer, derive the canonical mapped Lispex value, compute its digest, and require equality with `input.canonical_value_sha256`.

The issuer-side self-check MUST additionally receive the two live evaluator tokens and the private current invocation state. It MUST verify that both tokens have the same invocation nonce and context digest as each other and as the current invocation.

It MUST verify the token-specific normalized source digest, graph digest, input canonical value digest, profile, budgets, and transcript against the receipt and current invocation.

A prior-invocation token, mismatched token pair, caller-supplied transcript, or transcript not carried by the accepted token MUST fail as `native-self-verification-failed`.

Failure MUST produce `native-self-verification-failed`. No payload or envelope may be published and no key access may occur.

Structural self-verification checks deterministic derivations, token binding, and internal consistency. It MUST NOT replay either evaluation path.

A verifier of an already signed receipt MUST NOT re-execute either evaluator and MUST NOT require module-private evaluator tokens.

### C-ISSUE-08 Mutant refusal (amended v4)

A receipt whose sealed `execution.build_variant` is `mutant` MUST fail the signability gate as:

```text
native-result-not-signable
reason = mutant-build
```

A nonnull `execution.mutant_id` in a release receipt is a structural inconsistency.

The refusal MUST occur before key-handle resolution or access. The obsolete error class `mutant-build-not-signable` MUST NOT be emitted.

A compile-time mutant refusal MAY provide an additional issuer-side guard. It MUST NOT replace the sealed receipt check.

### C-ISSUE-09 Atomic outputs (amended v4)

The issuer publishes into a single output directory named by `--out-dir`. Cross-directory and cross-filesystem publication is not defined and MUST NOT be attempted, because three independent renames cannot be one atomic operation.

On successful issuance, the canonical payload, the DSSE envelope, and the success report MUST be written into one temporary staging directory on the same filesystem as the output directory. When all three files are complete and flushed, the staging directory MUST be published by a single atomic directory rename to the output directory. This makes the three files simultaneously observable and recoverable.

A handled failure MUST publish only the failure report. It MUST publish no payload and no envelope. It MUST use the same staging model as success: the failure report is written into a temporary staging directory on the same filesystem as the output directory, containing exactly `issue-report.json`, and the staging directory is published by a single atomic directory rename to the output directory. A file rename into a nonexistent output directory is forbidden, so success and handled failure share one atomic commit model.

If an I/O failure prevents publication of the required report, the implementation MUST guarantee that none of the payload, envelope, or report final paths exists.

No observable final state may contain a payload without its envelope and success report or an envelope without its payload and success report.

### C-ISSUE-10 Exit codes

`issue-native` MUST use this closed exit-code table:

| Exit | Meaning |
|---:|---|
| 0 | Payload, envelope, and report issued successfully |
| 1 | Checked input, execution, lowering, self-check, or signability failure |
| 2 | Usage error |
| 3 | Input or output failure |
| 4 | Key loading or signing failure |

### C-ISSUE-11 Error classes (amended v4)

The issue report status and primary error vocabulary is closed:

```text
issued-native
artifact-resource-limit
native-input-parse-failed
native-input-profile-invalid
profile-escape
native-lowering-failed
native-self-verification-failed
native-result-not-signable
native-key-load-failed
native-signing-failed
artifact-io-error
usage-error
```

Every success or handled-failure report MUST carry these fields:

```text
native_issue_report = csk.native-issue-report/v0
status
primary_error
reason
```

A successful report MUST have:

```text
status = issued-native
primary_error = null
reason = null
```

A handled failure other than a signability refusal MUST have:

```text
status = <applicable failure status>
primary_error = <applicable closed primary error>
reason = null
```

A signability refusal MUST have:

```text
status = native-result-not-signable
primary_error = native-result-not-signable
reason = <closed reason from C-ISSUE-12>
```

A handled failure MUST obey the report-only publication rule in C-ISSUE-09.

### C-ISSUE-12 Structural and release signability gates (amended v4)

Structural validation and release signability are separate gates.

Structural validation MUST reject each of these conditions before release signability is evaluated:

```text
zero-root graph
incomplete transcript
comparison fields internally inconsistent
final values differ while comparison status says agree
malformed graph or event sequence
```

These conditions MUST produce `native-self-verification-failed`. They MUST NOT produce a public signability reason.

The release signability gate MUST pass only when all of these conditions hold:

1. `comparison.status` is `agree`.
2. Both terminals have `kind` equal to `completed`.
3. The final agreed value is exactly one decision value allowed by A-4.
4. `diagnostics` is empty.
5. `execution.build_variant` is `release` and `execution.mutant_id` is null.

Boolean values are not decision values.

Every signability failure MUST use the single error class `native-result-not-signable`. The reason enum is closed and exhaustive:

```text
comparison-not-agree
terminal-not-completed
final-value-not-decision
diagnostics-present
mutant-build
```

When multiple reasons apply, the reason MUST be the first applicable value in the displayed order.

The public signability reason vocabulary MUST NOT contain `empty-decision-unit`, `transcript-incomplete`, or `final-values-differ`.

### C-ISSUE-13 Zero-access refusal and transcript-swap fixture (amended v4)

Every refusal at or before C-ISSUE-04 step 12 MUST occur before key-handle resolution, key-provider opening, or key-provider query.

The counting key-provider fixture required by C-KEY-08 MUST observe exactly zero key accesses for:

- comparison disagreement
- a completed comparison with a typed language fault
- a not-comparable comparison
- a completed agreement with a non-decision final value
- a completed agreement with zero graph roots
- an incomplete transcript
- nonempty diagnostics
- a mutant build
- input parsing failure
- input profile failure
- structural self-verification failure
- evaluator token-binding failure

The completed agreement with zero graph roots MUST be rejected structurally as `native-self-verification-failed`.

The incomplete transcript MUST be rejected structurally as `native-self-verification-failed`.

A final-value difference recorded with comparison status `agree` MUST be rejected structurally as `native-self-verification-failed`.

The same-root-count transcript-swap fixture MUST construct source, graph, and input evidence from invocation A and two transcripts from invocation B. Both invocations MUST have equal root counts. The constructed receipt MUST otherwise have a valid schema and a final decision.

The fixture MUST fail receipt construction or issuer-side self-verification because its evaluator tokens do not bind to invocation A. It MUST publish no payload and no envelope. If the failure is handled, it MUST publish only the failure report required by C-ISSUE-09.

### C-ISSUE-14 Checked input errors

Input bytes that cannot be parsed as one strict UTF-8 JSON value MUST fail as `native-input-parse-failed`.

Parseable bytes that violate canonical artifact JSON, the closed checked-input host schema, or the allowed host-value grammar MUST fail as `native-input-profile-invalid`.

Application-level invalidity inside a valid checked-input list MUST remain evaluation data. It MUST NOT produce either input error. The checked program MUST return the `invalid-input` decision.

The exact input file bytes MUST end with one LF. That LF MUST be included in the `input.sha256` and `input.byte_length` preimages.

## 17. `verify-structure` interface

### C-VS-01 Command form (amended v4)

The exact CLI is:

```text
lispex verify-structure
  --receipt <path>
  --input <path>
  --report-out <path>
  [--source <path>]
  [--profile <profile-id>]
```

`--receipt`, `--input`, and `--report-out` are required exactly once. Source and profile context are optional.

The mandatory input is required for the deterministic input-mapping recheck in A-11.

### C-VS-02 Scope (amended v4)

The command MUST check:

- canonical receipt bytes
- exact receipt version
- the complete closed receipt schema
- domain-separated hashes
- normalized-program derivation
- deterministic graph derivation
- graph canonicality
- checked-input parsing and mapping
- transcript consistency and completeness
- comparison consistency
- cross-field consistency
- boundary contents
- the deterministic context_digest carried by the receipt, not any token or nonce

It MUST reject:

- a zero-root graph
- an incomplete transcript
- internally inconsistent comparison fields
- different final values recorded with comparison status `agree`
- a malformed graph or event sequence

It MUST NOT require an envelope, signature, key, trust policy, or live evaluator token. It MUST NOT authenticate executable identity, build provenance, signer origin, freshness, or the provenance of serialized transcript bytes.

### C-VS-03 Success status

Success MUST emit:

```text
verify_report = csk.verify-report/v0
status = structurally-consistent
```

The strings `native`, `authenticated-native`, `trusted-native`, and `verified-native` MUST NOT occur in any success field or user-facing success message.

### C-VS-04 Exit codes

`verify-structure` MUST use this closed exit-code table:

| Exit | Meaning |
|---:|---|
| 0 | Structurally consistent |
| 1 | Structural rejection |
| 2 | Usage error |
| 3 | Input or output failure |

### C-VS-05 External context (amended v4)

The input path MUST be opened and read exactly once. Its immutable bytes MUST be used for its raw digest, byte length, checked-input parse, host-to-Lispex mapping, and canonical mapped-value digest.

When source is supplied, it MUST be opened and read exactly once. Its immutable bytes MUST be used for its digest, byte length, parsing, and normalization.

A supplied profile mismatch MUST fail as `native-profile-mismatch`. A source mismatch MUST fail as `native-source-mismatch`. A raw input digest or length mismatch MUST fail as `native-input-mismatch`.

A successful contextual check remains only `structurally-consistent`.

### A-11 `verify-structure` recomputation (amended v4)

`verify-structure` MUST perform these checks in order and fail at the first failure:

1. Apply the consolidated raw-byte and post-parse resource limits required by C-LIM-01.
2. Reserialize the parsed receipt with `csk.artifact-json/v0` and require byte identity with the submitted receipt.
3. Require the exact tag `csk.differential-receipt/v0`.
4. Validate the complete closed receipt schema, including every nested graph, transcript, terminal, canonical value, node, digest representation, safe integer, comparison status, context digest, build variant, and mutant identifier.
5. Recompute graph, reference transcript, Meaning Environment transcript, normalized-program, and boundary hashes from their receipt-carried preimages.
6. Require every repeated hash, count, target, executable identity, execution-context field, and terminal field to match.
7. Decode `canonical.normalized_bytes_b64`, parse the normalized program, and deterministically lower it to a fresh graph.
8. Serialize the fresh graph with `csk.artifact-json/v0` and require byte identity with the serialization of `graph.value`.
9. Read the external input once and require its raw digest and byte length to equal the receipt input fields.
10. Parse the external input under the checked-input host schema and rederive the canonical mapped Lispex value.
11. Serialize the mapped value canonically, compute its required domain-separated digest, and require equality with `input.canonical_value_sha256`.
12. When source is supplied, read it once, recompute its digest and byte length, normalize it, and require normalized byte identity with the decoded `canonical.normalized_bytes_b64`.
13. Validate graph completeness and canonicality under A-5.
14. Require at least one graph root and validate transcript completeness against the graph root count under A-3.
15. Freshly compare both transcripts and require every recorded comparison field to match.
16. Reject different final canonical values when the recorded comparison status is `agree`.
17. Enforce every cross-field condition in A-14 and every external-preimage condition in A-15.
18. Enforce the release diagnostics and build-variant rules when the receipt is identified as release-signed by its verification caller.

The graph validation in step 13 MUST enforce fresh nodes per source occurrence, roots-only definitions, no primitive or `input` redefinition, no unbound variable node, no later-root forward reference, lexical scope validity, acyclicity, reachability, and canonical node order.

Step 14 MUST reject a zero-root graph and every incomplete transcript as structural failures.

Steps 15 and 16 MUST reject internally inconsistent comparison fields and final-value disagreement recorded as `agree`. These failures are structural failures and are not signability reasons.

The boundary digest MUST be checked exactly once in step 5.

Success MUST emit `structurally-consistent`. The command MUST NOT replay reference evaluation or Meaning Environment evaluation.

The `issue-native` self-check MUST run the same algorithm with the private source and input buffers already held by issuance. It MUST additionally receive exactly two live evaluator tokens and the private current invocation state.

The issuer-side self-check MUST require the two tokens to bind to the same invocation nonce and context digest as each other and as the current invocation. The receipt does not carry the invocation nonce, so no receipt field is compared against it. The receipt context_digest MUST equal the token context_digest. It MUST verify their source or graph digest, input canonical value digest, profile, budgets, and transcripts.

The issuer-side self-check MUST reject a prior-invocation token, a caller-supplied transcript, and any token or transcript mismatch as `native-self-verification-failed`.

A standalone `verify-structure` invocation MUST NOT claim to reconstruct or authenticate module-private evaluator tokens. Its structural result does not authenticate transcript execution provenance.

## 18. `verify-native` interface

### C-VN-01 Command form (amended v4)

The exact CLI is:

```text
lispex verify-native
  --envelope <path>
  --trust-policy <path>
  --source <path>
  --input <path>
  --profile <profile-id>
  --report-out <path>
```

Every argument is required exactly once. Positional arguments, duplicate options, and unknown options are forbidden.

The profile identifier MUST pass the syntax rule in C-POLICY-06 before semantic verification.

The command MUST write exactly one canonical report on every handled verification result. An authenticated result MUST use the authenticated evidence variant in C-VN-03. A verification rejection MUST use the rejection variant in C-VN-03.

### C-VN-02 Exit codes (amended v4)

`verify-native` MUST use this closed exit-code table:

| Exit | Meaning |
|---:|---|
| 0 | Evidence authentication succeeded and decision promotion is eligible |
| 1 | Verification rejection with a report |
| 2 | Usage error |
| 3 | Input or output failure |
| 10 | Evidence authentication succeeded and decision promotion is ineligible |

Exit 0 MUST NOT be used for authenticated evidence that fails any promotion condition in A-16.

An authenticated receipt with `comparison_status` equal to `disagree` or `not-comparable` MUST use exit 10.

An authentication failure MUST use exit 1 when its rejection report is written successfully. It MUST NOT use exit 10.

### C-VN-03 Native verification report tagged union (amended v4)

The native verification report MUST be a closed and exhaustive tagged union with the common tag:

```text
native_verify_report = csk.native-verify-report/v0
```

The authenticated evidence variant MUST contain:

```text
authentication_status = authenticated
comparison_status = agree | disagree | not-comparable
decision_promotion = eligible | ineligible
primary_error = null
envelope_sha256
payload_sha256
key_id
profile
engine_sha256
source_sha256
input_sha256
input_canonical_value_sha256
```

The authenticated `comparison_status` enum is closed and exhaustive.

`comparison_status` MUST equal the authenticated receipt comparison status.

`decision_promotion` MUST be `eligible` only when promotion under A-16 would succeed for the live evidence capability. Otherwise it MUST be `ineligible`.

`not-comparable` is reserved for an authenticated receipt whose evaluator infrastructure failed. It MUST NOT describe a failure to authenticate evidence.

The rejection variant MUST contain:

```text
authentication_status = rejected
comparison_status = null
decision_promotion = not-evaluated
primary_error = <closed error code>
```

A rejection report MUST NOT contain authenticated evidence fields whose values require trust in the rejected payload.

A verification that fails envelope authentication, key authorization, signature verification, payload validation, structural validation, profile authorization, engine authorization, source matching, or input matching MUST use the rejection variant.

A rejection report MUST NOT use `comparison_status = not-comparable`, `decision_promotion = ineligible`, or `authentication_status = authenticated`.

The report variants and every enum in this condition are closed and exhaustive.

### C-VN-04 Report is not a capability (amended v4)

No API may deserialize `csk.native-verify-report/v0` into `AuthenticatedNativeEvidence` or `AuthenticatedNativeDecision`.

A serialized report is never a capability and can never be promoted. Passing a report object, report bytes, a plain object, or a Proxy for promotion MUST fail as `wrong-evidence-capability`.

This rule applies to both variants of the report tagged union.

### C-VN-05 Immutable expected context (amended v4)

Expected source and input MUST each be read exactly once.

At API entry, the implementation MUST make private defensive copies of the envelope, trust policy, source, and input byte buffers. Verification, hashing, parsing, derivation checks, report generation, and capability construction MUST use only those private copies.

Path reopening and later consultation of caller-owned buffers are forbidden.

The parsed trust policy and expected context MUST be copied into closed immutable internal values before authorization begins.

### C-VN-06 Fixed verification order (amended v4)

CLI profile syntax validation MUST occur before semantic verification. A malformed profile identifier MUST produce a usage error with exit code 2.

After CLI validation, the verifier MUST use exactly this primary-failure order:

```text
1  resource limit
2  policy canonical gate and schema
3  submitted-bytes canonical JSON gate
4  raw-artifact and no-attestation classification
5  DSSE envelope closed-schema validation
6  payload type and base64 checks
7  keyid lookup and key selection
8  expected profile is a member of the selected key allowed_profiles, else native-profile-disallowed
9  selected-key payload-type authorization
10 signature verification
11 payload canonical gate, schema, and internal consistency
12 receipt profile equals expected profile, else native-profile-mismatch
13 engine, source, and input context checks
```

Step 1 MUST apply the applicable consolidated limits required by C-LIM-01 before deeper parsing or cryptographic work.

Step 2 MUST validate canonical policy bytes, the complete closed trust-policy schema, key identifiers, key uniqueness, list uniqueness, minimum versions, profiles, algorithms, and digest syntax. Failure MUST use the applicable policy error.

Step 3 MUST validate that the submitted bytes are canonical JSON under C-JSON without applying any DSSE envelope schema. This generic canonical gate MUST precede raw-artifact classification so that a canonical raw artifact reaches step 4 rather than failing a DSSE schema it was never meant to satisfy.

Step 4 MUST classify a canonical raw `csk.differential-receipt/v0` receipt and a canonical raw `vouch.bridge-report/v0` report as missing an attestation, failing as `missing-native-attestation`. It MUST not consume payload fields as authenticated data. Only submitted bytes that are not a raw artifact continue to step 5.

Step 5 MUST validate the complete closed DSSE envelope schema. Failure MUST be `native-envelope-schema`.

Step 6 MUST validate the payload type and all base64 syntax and round-trip requirements. An unsupported or unrecognized payload type MUST fail as `native-payload-type`. A base64 syntax or round-trip failure MUST fail as `native-base64-invalid`.

Step 7 MUST look up the envelope `keyid` and select exactly one matching key entry. A missing key MUST fail as `untrusted-native-key`.

Step 8 MUST compare the expected profile only with the `allowed_profiles` field of the selected key entry. It MUST NOT compare against a union, intersection, or aggregation of other key entries.

Step 9 MUST authorize the payload type only under the selected key entry. A payload type absent from the selected key `allowed_payload_types` MUST fail as `native-payload-type-disallowed`.

Step 10 MUST complete signature verification before payload parsing or receipt-field consumption. Failure MUST be `native-signature-invalid`.

Step 11 MUST apply the payload canonical gate, read only the version discriminator needed for version handling, enforce the policy version floor, validate the complete closed receipt schema, and perform every receipt-carried digest, normalized-program, deterministic graph, transcript, comparison, boundary, and cross-field recomputation required by A-11.

Step 11 MUST reject a zero-root graph, an incomplete transcript, internally inconsistent comparison fields, final-value disagreement recorded as `agree`, and every malformed graph or event sequence as structural inconsistency.

Step 11 MUST NOT replay either evaluator. It MUST NOT attempt to reconstruct module-private evaluator tokens.

Step 12 MUST compare the authenticated receipt profile with the expected profile already authorized for the selected key.

Step 13 MUST check the authenticated engine before source and input context. Source checks MUST precede input parsing and input mapping checks.

All input checks in step 13 MUST use the same private expected input buffer. They MUST reparse the checked input, derive its canonical mapped Lispex value, verify `input.canonical_value_sha256`, and verify the raw input digest and byte length.

The first failure in this order MUST become `primary_error` in the rejection report.

C-CAP-13 lists the exact single public `NativeVerificationErrorCode` that each of these thirteen steps produces.

### C-VN-07 Raw payload rejection

When `--envelope` contains a canonical `csk.differential-receipt/v0` object rather than a DSSE envelope, the primary error MUST be `missing-native-attestation`.

The report MUST use the rejection variant in C-VN-03.

### C-VN-08 Raw Bridge rejection

When `--envelope` contains a canonical `vouch.bridge-report/v0` object, the primary error MUST be `missing-native-attestation`.

The report MUST use the rejection variant in C-VN-03.

### C-VN-09 Signature-before-payload semantics

After envelope structure, key selection, expected-profile authorization, and selected-key payload authorization succeed, signature verification MUST occur before payload parsing or receipt-field consumption.

A signed-byte mutation that also breaks schema, derivation, or hash consistency MUST report `native-signature-invalid`.

The rejection report MUST have `authentication_status` equal to `rejected`, `comparison_status` equal to null, and `decision_promotion` equal to `not-evaluated`.

### C-VN-10 Engine-before-context order

The allowed-engine check MUST occur before source and input comparisons.

A fixture with both a disallowed engine and wrong source bytes MUST report `native-engine-disallowed`.

### C-VN-11 Multi-key profile confusion fixture

The trust policy fixture MUST contain at least two distinct valid key entries.

Key A MUST authorize only `csk.profile-x/v0`. Key B MUST authorize only `csk.profile-y/v0`.

The envelope MUST identify key B. Its receipt MUST claim `csk.profile-x/v0`. Its signature under key B MUST be valid. The CLI expected profile MUST be `csk.profile-x/v0`.

Verification MUST reject at C-VN-06 step 8 with:

```text
authentication_status = rejected
comparison_status = null
decision_promotion = not-evaluated
primary_error = native-profile-disallowed
```

The verifier MUST NOT authorize `csk.profile-x/v0` because key A allows it. It MUST evaluate profile authorization only against key B.

### C-VN-12 Unauthenticated rejection report fixture

The fixture MUST contain an envelope with an invalid signature and no earlier failure under C-VN-06.

Verification MUST emit:

```text
native_verify_report = csk.native-verify-report/v0
authentication_status = rejected
comparison_status = null
decision_promotion = not-evaluated
primary_error = native-signature-invalid
```

The report MUST NOT use `not-comparable`. The command MUST exit with code 1 after successfully writing the rejection report.

### A-12 `verify-native` ordering and result (amended v4)

`verify-native` MUST NOT re-execute the reference evaluator or Meaning Environment evaluator.

Successful verification MUST mint an in-process `AuthenticatedNativeEvidence`. It MUST NOT directly mint `AuthenticatedNativeDecision`.

Evidence authentication succeeds only after:

1. The envelope authenticates under the supplied trust policy.
2. The expected profile is authorized by the single key selected by the envelope `keyid`.
3. Payload authorization and signature validation succeed under that selected key.
4. The receipt is canonical and internally structurally consistent.
5. The receipt profile equals the already authorized expected profile.
6. Engine, source, and input checks succeed in the order required by C-VN-06.
7. The normalized program deterministically lowers to graph bytes identical to the authenticated graph.
8. The external input deterministically maps to the value digest recorded in `input.canonical_value_sha256`.
9. The implementation has retained only private defensive context copies and the private immutable verified snapshot required by A-16.

The resulting evidence MAY contain an agreeing, disagreeing, comparable language-fault, or not-comparable receipt.

The CLI MUST evaluate promotion eligibility from the live evidence capability. It MUST NOT convert a serialized report into a capability.

Eligible authenticated evidence MUST produce exit 0 and the authenticated report variant with `decision_promotion` equal to `eligible`.

Ineligible authenticated evidence MUST produce exit 10 and the authenticated report variant with `decision_promotion` equal to `ineligible`.

Rejected evidence MUST produce exit 1 when its rejection report is written and MUST use the rejection report variant.

A serialized native verification report remains non-capability evidence and MUST NOT be deserialized into either native capability type.

Profile failure precedence is exact:

```text
malformed expected profile identifier
  usage error

syntactically valid expected profile absent from selected key allowed_profiles
  native-profile-disallowed

selected key authorizes expected profile but authenticated receipt profile differs
  native-profile-mismatch
```

## 19. Two-tier consumer capabilities

### C-CAP-01 Opaque classes (amended v4)

The supported TypeScript package MUST export these opaque classes:

```ts
AuthenticatedNativeEvidence
AuthenticatedNativeDecision
CheckedBridgeEvidence
```

Each class MUST declare a distinct private unique-symbol brand. Each class MUST have its own closure-owned `WeakSet` membership set and snapshot store.

Each exported constructor MUST require the exact unexported secret token owned by its class. Construction without that token MUST fail. Only the corresponding verifier or promotion factory may invoke the constructor and insert the resulting object into its membership set.

Branding symbols, secret tokens, membership sets, and snapshot storage MUST NOT be exported.

Backs P7.

### C-CAP-02 Separate verification and promotion functions (amended v4)

The package MUST export exactly these native operations:

```ts
verifyNativeEvidence(
  envelope: Uint8Array,
  trustPolicyBytes: Uint8Array,
  expected: NativeExpectedContext
): Result<AuthenticatedNativeEvidence, VerificationError<NativeVerificationErrorCode>>

promoteNativeDecision(
  evidence: AuthenticatedNativeEvidence
): Result<AuthenticatedNativeDecision, PromotionError>
```

The package MUST also export:

```ts
verifyBridgeEvidence(
  report: Uint8Array,
  expected: BridgeExpectedContext
): Result<CheckedBridgeEvidence, VerificationError<BridgeVerificationErrorCode>>
```

`verifyBridgeEvidence` MUST apply the closed Bridge report schema, expected-context schema, verification order, limits, minting preconditions, and error precedence required by C-BR-01 through C-BR-07.

Native authentication and native decision promotion MUST remain separate operations.

The repaired package MUST NOT export `verifyAny`, a common `Verified` type, a shared `{ ok: true }` evidence object, or any operation that promotes a serialized report.

### C-CAP-13 Native input and error types

`verifyNativeEvidence` MUST take the trust policy as raw bytes so that the canonical byte gate of C-VN-06 step 2 can be applied. A parsed policy object MUST NOT be accepted, because its original canonicality cannot then be verified. `NativeExpectedContext` is a closed immutable value:

```ts
type NativeExpectedContext = Readonly<{
  profile: string
  source: Uint8Array
  input: Uint8Array
}>
```

`VerificationError` is generic over its code set. Native and Bridge verification carry different closed code sets:

```ts
type VerificationError<C extends string> = { code: C }
```

`NativeVerificationErrorCode` is closed and exhaustive and is exactly the native primary-error set that the thirteen verify-native steps of C-VN-06 through C-VN-10 can produce:

```ts
type NativeVerificationErrorCode =
  | "artifact-resource-limit"
  | "non-canonical-artifact-json"
  | "native-trust-policy-invalid"
  | "missing-native-attestation"
  | "native-envelope-schema"
  | "native-payload-type"
  | "native-base64-invalid"
  | "untrusted-native-key"
  | "native-profile-disallowed"
  | "native-payload-type-disallowed"
  | "native-signature-invalid"
  | "unsupported-native-version"
  | "native-schema-version-below-policy"
  | "native-receipt-schema"
  | "native-receipt-inconsistent"
  | "native-profile-mismatch"
  | "native-engine-disallowed"
  | "native-source-mismatch"
  | "native-input-mismatch"
  | "native-input-parse-failed"
  | "native-input-profile-invalid"
```

`BridgeVerificationErrorCode` is closed and exhaustive and is exactly the Bridge error set of C-BR-07:

```ts
type BridgeVerificationErrorCode =
  | "artifact-resource-limit"
  | "non-canonical-artifact-json"
  | "bridge-report-schema"
  | "unsupported-bridge-version"
  | "bridge-profile-mismatch"
  | "bridge-engine-mismatch"
  | "bridge-source-mismatch"
  | "bridge-input-mismatch"
  | "bridge-input-canonical-value-mismatch"
```

`verifyNativeEvidence` returns `VerificationError<NativeVerificationErrorCode>` and `verifyBridgeEvidence` returns `VerificationError<BridgeVerificationErrorCode>`. Each verify-native step of C-VN-06 produces exactly one public code per invocation, which is the first applicable code in that step's ordered subchecks: step 1 `artifact-resource-limit`, step 2 `native-trust-policy-invalid` or `non-canonical-artifact-json`, step 3 `non-canonical-artifact-json`, step 4 `missing-native-attestation`, step 5 `native-envelope-schema`, step 6 `native-payload-type` or `native-base64-invalid`, step 7 `untrusted-native-key`, step 8 `native-profile-disallowed`, step 9 `native-payload-type-disallowed`, step 10 `native-signature-invalid`, step 11 `non-canonical-artifact-json` or `unsupported-native-version` or `native-schema-version-below-policy` or `native-receipt-schema` or `native-receipt-inconsistent`, step 12 `native-profile-mismatch`, step 13 `native-engine-disallowed` or `native-source-mismatch` or `native-input-mismatch` or `native-input-parse-failed` or `native-input-profile-invalid`.

Backs P7.

Backs P7 and P8.

### C-CAP-03 Runtime brands (amended v4)

Each capability class MUST use its own closure-owned `WeakSet`. A capability operation MUST check membership in the exact set for the required class.

A plain object, `Proxy`, structured clone, separately constructed imitation, deserialized object, or capability minted by another package instance MUST fail membership as `wrong-evidence-capability`.

Cross-realm rejection is scoped to the authority-generation origin. A separately constructed object from another realm MUST fail. A single live capability object that is passed through another realm without cloning MUST retain its identity and membership.

Successful native verification MUST add only the newly minted `AuthenticatedNativeEvidence` instance to its membership set. Successful promotion MUST add only the newly minted `AuthenticatedNativeDecision` instance to its membership set. Successful Bridge verification MUST add only the newly minted `CheckedBridgeEvidence` instance to its membership set.

Backs P7.

### C-CAP-04 Sealed retained evidence (amended v4)

The native package MUST maintain a closure-owned:

```ts
WeakMap<object, VerifiedNativeSnapshot>
```

Only a live member of the `AuthenticatedNativeEvidence` membership set may be a key.

`VerifiedNativeSnapshot` MUST be a deep-immutable closed internal value with exactly these fields:

```text
canonical_payload_bytes
receipt
source_sha256
input_sha256
input_canonical_value_sha256
profile
engine_sha256
key_id
build_variant
mutant_id
```

`canonical_payload_bytes` MUST be a private immutable byte sequence containing the exact authenticated canonical payload bytes.

`receipt` MUST be the exact closed immutable `csk.differential-receipt/v0` value parsed during verification. It MUST include the comparison state, terminal states, final canonical values, diagnostics, execution metadata, `build_variant`, and `mutant_id` used by promotion.

The snapshot constructor MUST move the parse result into private ownership or deep copy it. No nested array or object in the snapshot may alias a caller value or a public projection. The implementation MUST recursively deep freeze the entire snapshot or use an immutable internal representation with equivalent guarantees.

Typed arrays MUST never be exposed on a public field. No capability may expose a raw mutable envelope, payload, source, input, graph, transcript, or snapshot field.

At native verification entry, the implementation MUST make private defensive copies of every caller-supplied envelope, source, and input byte buffer. Hashing, parsing, context comparison, snapshot construction, and later promotion MUST use only those private copies.

The implementation MUST read each trust-policy and expected-context member exactly once at API entry. It MUST copy the resulting values into exact closed immutable internal values before canonical checks, authorization, context comparison, or snapshot construction. Later verification steps MUST use only the entry copies.

Mutation of caller buffers, trust-policy objects, expected-context objects, getters, proxies, or public receipt projections after entry MUST NOT change verification or promotion behavior.

`AuthenticatedNativeDecision` MUST retain a deep-immutable decision payload derived only from the sealed snapshot. It MUST NOT retain source or input paths for later reading.

Backs P4, P7, and P17.

### C-CAP-05 Renderer signatures (amended v4)

The native renderer MUST accept only `AuthenticatedNativeDecision`. The Bridge renderer MUST accept only `CheckedBridgeEvidence` and MUST apply the Bridge renderer boundary required by C-BR-08.

The native renderer MUST reject `AuthenticatedNativeEvidence` at compile time when statically typed and as `wrong-evidence-capability` at runtime.

Backs P7.

### C-CAP-06 Exact visible strings (amended v4)

The native decision renderer MUST display exactly:

```text
Authenticated native decision
```

The Bridge renderer MUST display exactly:

```text
External evidence checked
```

The repaired consumer MUST NOT display the unqualified string `Verified`.

Backs P7 and P8.

### C-CAP-07 Vulnerable demonstration

`artifact/consumer-demo/vulnerable` MUST intentionally reduce successful native and Bridge checker reports to `{ ok: true }`. Supplying fixture `B01` MUST display exactly `Verified`.

This vulnerable helper MUST NOT be exported by the supported consumer package.

Backs P8.

### C-CAP-08 TypeScript Bridge negative fixture

Compiling the fixture that passes `CheckedBridgeEvidence` to `renderNativeDecision` MUST fail with a TypeScript argument-type error. The test MUST fail if compilation succeeds.

Backs P7 and P8.

### C-CAP-09 JavaScript Bridge negative fixture

The untyped fixture MUST invoke `renderNativeDecision` with a real `CheckedBridgeEvidence` object. It MUST throw a typed error whose class is `wrong-evidence-capability`.

Backs P7 and P8.

### C-CAP-10 Dishonest consumer limitation

The package documentation and paper boundary file MUST state that an application can ignore the package or draw a false interface. No test or claim may say that capabilities constrain a deliberately dishonest application.

Backs P17.

### C-CAP-11 Constructor runtime forgery

The constructor runtime-forgery fixture MUST attempt all of these operations for every exported capability class:

```text
new on the exported class
Reflect.construct
Object.create on the exported prototype
construction through a subclass
prototype replacement before construction
prototype replacement after construction
```

No resulting object may enter any capability membership set. Every attempt to use such an object as evidence MUST fail with `wrong-evidence-capability`.

A forged object MUST NOT acquire authority through a copied private-looking field, copied symbol, prototype match, `instanceof` result, or TypeScript cast.

### C-CAP-12 Policy and context getter TOCTOU

There are two separate TOCTOU fixtures, because the trust policy is passed as bytes and only the expected context is a JavaScript object.

The policy-bytes TOCTOU fixture MUST mutate the caller-owned trust-policy `Uint8Array` after the entry defensive copy. The parsed policy exists only inside the verifier, built once from the entry copy, so the mutation MUST NOT change the selected key, the authorized profile, the authorized engine, the verification outcome, or the retained snapshot.

The expected-context TOCTOU fixture MUST supply a `NativeExpectedContext` whose `profile`, `source`, or `input` is a getter or `Proxy` member returning a different value on successive reads. Verification MUST read each member exactly once at entry as required by C-CAP-04, and a later getter result MUST NOT change the expected context, the verification outcome, or the retained snapshot.

### C-CAP-14 Capability-level verification report

Any verification report exposed by the capability package MUST be exactly one member of this tagged union:

```ts
type CapabilityVerificationReport =
  | {
      authentication_status: "authenticated"
      comparison_status: "agree" | "disagree" | "not-comparable"
      decision_promotion: "eligible" | "ineligible"
    }
  | {
      authentication_status: "rejected"
      comparison_status: null
      decision_promotion: "not-evaluated"
      primary_error: NativeVerificationErrorCode
    }
```

The union is closed and exhaustive. Unknown members are forbidden.

`not-comparable` is reserved for authenticated evidence whose evaluator infrastructure failed. Authentication failure MUST produce the rejection member. It MUST NOT produce `not-comparable`.

A capability-level report is a public projection. It is never a capability and MUST NOT alias the sealed snapshot.

### A-16 Two-tier native capability and decision promotion (amended v4)

`verifyNativeEvidence` MUST mint `AuthenticatedNativeEvidence` only after all of these conditions hold:

1. The envelope authenticates under the immutable entry copy of the supplied trust policy.
2. Payload authorization and signature validation succeed.
3. The receipt is canonical and internally structurally consistent.
4. Profile, engine, source, and input checks succeed in their required order.
5. The immutable private source and input copies match the receipt context.
6. The deep-immutable snapshot required by C-CAP-04 has been stored.

Structural validation before minting MUST reject a zero-root graph, incomplete transcript, internally inconsistent comparison fields, differing final values when comparison status is `agree`, and any malformed graph or event sequence.

Authenticated evidence may describe an agreeing receipt, a disagreeing receipt, a comparable language fault, or a not-comparable receipt. Authentication alone does not establish decision eligibility.

`promoteNativeDecision` MUST first verify membership in the `AuthenticatedNativeEvidence` membership set. It MUST then obtain the snapshot from the closure-owned `WeakMap`. It MUST read only that snapshot. It MUST NOT read public fields, caller buffers, serialized reports, caller paths, mutable projections, getters, proxies, or compile-time build constants as substitutes for snapshot fields.

Promotion MUST succeed only when all of these conditions hold:

1. `comparison.status` is `agree`.
2. Both terminals have kind `completed`.
3. The final agreed value is exactly one of the four decision values defined by the canonical value grammar.
4. `diagnostics` is empty.
5. The sealed snapshot `build_variant` is `release`.

The four eligible final values are the closed set:

```json
{"t":"decision","v":"approve"}
{"t":"decision","v":"deny"}
{"t":"decision","v":"review"}
{"t":"decision","v":"invalid-input"}
```

A Boolean or any other canonical value is not an application decision.

`PromotionError` MUST be the following closed union:

```ts
type PromotionError =
  | {
      code: "wrong-evidence-capability"
    }
  | {
      code: "native-decision-promotion-ineligible"
      reason:
        | "comparison-not-agree"
        | "terminal-not-completed"
        | "final-value-not-decision"
        | "diagnostics-present"
        | "mutant-build"
    }
```

The promotion reason enum is closed and exhaustive. Its members are exactly the five members shown and in the shown order.

Promotion MUST report the first applicable reason in this order:

```text
comparison-not-agree
terminal-not-completed
final-value-not-decision
diagnostics-present
mutant-build
```

The `mutant-build` check MUST read `build_variant` from the sealed snapshot. A compile-time mutant guard is an additional issuer-side control and MUST NOT replace the snapshot check.

A signed disagree receipt, agreeing comparable language-fault receipt, or not-comparable receipt MAY remain authenticated evidence for incident analysis. It MUST NOT produce `AuthenticatedNativeDecision`.

A serialized `csk.native-verify-report/v0` report is never a capability. It MUST NOT be deserialized, reconstructed, cast, or otherwise converted into either native capability.

### A-17 Native decision renderer boundary (amended v4)

The native decision renderer accepts only a live in-memory `AuthenticatedNativeDecision`. It MUST NOT accept:

```text
a differential receipt
a DSSE envelope
an AuthenticatedNativeEvidence
a serialized verification report
an unsigned mutation-runner result
a transcript
a fixture expectation
```

Version 0 has no explicit `decision` member in the differential receipt. Promotion derives the decision from the final agreed canonical decision value in the sealed snapshot.

A fixture MAY restate the expected decision and rendered result for comparison. It MUST NOT supply, replace, or override the receipt value.

## 20. Bridge subsystem

### C-BR-01 Bridge report schema

A `vouch.bridge-report/v0` object has exactly these nine top-level members:

```text
bridge_report
profile
engine_sha256
source_sha256
input_sha256
input_canonical_value_sha256
comparison_status
decision
diagnostics
```

The exact closed schema is:

```text
{
  "bridge_report": "vouch.bridge-report/v0",
  "profile": <profile identifier>,
  "engine_sha256": <"sha256:" plus lowercase hex64>,
  "source_sha256": <lowercase hex64>,
  "input_sha256": <lowercase hex64>,
  "input_canonical_value_sha256": <lowercase hex64>,
  "comparison_status": "agree" | "disagree" | "not-comparable",
  "decision":
    "approve" | "deny" | "review" | "invalid-input" | null,
  "diagnostics": [
    {
      "code": <string>,
      "message": <string>
    },
    ...
  ]
}
```

The `comparison_status` enum and the non-null `decision` enum are closed and exhaustive. Unknown members are forbidden at every object level.

`decision` MUST be non-null only when `comparison_status` is `agree`. A non-null `decision` MUST be one of the four application decisions defined by A-4. For `disagree` and `not-comparable`, `decision` MUST be null.

`profile` MUST satisfy the profile identifier syntax in C-POLICY-06. `engine_sha256` MUST be the string `sha256:` followed by exactly 64 lowercase hexadecimal characters. `source_sha256`, `input_sha256`, and `input_canonical_value_sha256` MUST each be exactly 64 lowercase hexadecimal characters.

Diagnostics MUST contain no secrets, host paths, key information, or implementation-defined panic text.

A Bridge report is checked external evidence. Canonicality, schema validity, and context equality do not authenticate its producer and do not establish freshness.

A report that passes verification is reported with the status string defined by C-BR-10, which is exactly `checked-external`.

Backs P7 and P8.

### C-BR-02 Command form

The exact CLI is:

```text
lispex verify-bridge
  --report <path>
  --profile <profile-id>
  --engine-sha256 <digest>
  --source <path>
  --input <path>
  --input-canonical-value-sha256 <digest>
  --report-out <path>
```

Every argument is required exactly once. Positional arguments, duplicate options, and unknown options are forbidden.

The profile identifier MUST pass the syntax rule in C-POLICY-06. Digest arguments MUST satisfy the corresponding digest syntax in C-BR-01. A malformed option value MUST produce a usage error before semantic verification.

The command MUST read the `--report`, `--source`, and `--input` paths exactly once each. It MUST make private byte copies at entry and MUST derive their byte digests only from those copies.

The command MUST write exactly one canonical report on every handled verification result as required by C-BR-10. Exit codes are defined by C-BR-09. Handled input or output failures are governed by C-BR-11.

The build status of this command is stated in C-BR-12.

### C-BR-03 Bridge expected context

`BridgeExpectedContext` has exactly this closed TypeScript shape:

```ts
type BridgeExpectedContext = Readonly<{
  profile: string
  engineSha256: `sha256:${string}`
  source: Uint8Array
  input: Uint8Array
  inputCanonicalValueSha256: string
}>
```

Unknown members are forbidden.

At API entry, `verifyBridgeEvidence` MUST read every property exactly once. It MUST copy `source` and `input` into private byte buffers. It MUST validate and copy every string into a closed immutable internal context value.

A getter, Proxy, caller mutation, or later buffer mutation MUST NOT alter verification or the resulting capability.

`engineSha256` MUST match `sha256:` followed by exactly 64 lowercase hexadecimal characters. `inputCanonicalValueSha256` MUST contain exactly 64 lowercase hexadecimal characters. `profile` MUST satisfy C-POLICY-06.

### C-BR-04 Fixed verification order

After API argument validation or CLI syntax validation, Bridge verification MUST use this exact primary-failure order:

```text
1  artifact-resource-limit
2  non-canonical-artifact-json
3  unsupported-bridge-version
4  bridge-report-schema
5  bridge-profile-mismatch
6  bridge-engine-mismatch
7  bridge-source-mismatch
8  bridge-input-mismatch
9  bridge-input-canonical-value-mismatch
```

Step 1 MUST apply C-BR-05 and the applicable C-LIM conditions.

Step 2 MUST require byte identity with the `csk.artifact-json/v0` serialization of the parsed value. A mismatch MUST fail as `non-canonical-artifact-json`.

Step 3 may inspect only the `bridge_report` discriminator. A discriminator of the form `vouch.bridge-report/v<N>` whose version `<N>` is a nonnegative integer other than `0` MUST produce `unsupported-bridge-version`. A missing discriminator or any other value MUST continue to step 4.

Step 4 MUST validate the complete closed schema and all cross-field rules in C-BR-01. A report whose discriminator is absent, is not equal to `vouch.bridge-report/v0`, omits a required member, carries an unknown member, or violates a cross-field rule MUST fail as `bridge-report-schema`.

Steps 5 through 9 MUST use only the immutable entry copy required by C-BR-03.

Step 5 MUST compare the report `profile` with the expected profile. A difference MUST fail as `bridge-profile-mismatch`.

Step 6 MUST compare the report `engine_sha256` with the expected engine digest. A difference MUST fail as `bridge-engine-mismatch`.

Step 7 MUST compare the report `source_sha256` with the SHA-256 digest of the private source copy. A difference MUST fail as `bridge-source-mismatch`.

Step 8 MUST compare the report `input_sha256` with the SHA-256 digest of the private input copy. A difference MUST fail as `bridge-input-mismatch`.

Step 9 MUST compare the report `input_canonical_value_sha256` with the expected canonical input value digest. A difference MUST fail as `bridge-input-canonical-value-mismatch`. Bridge verification MUST NOT derive a canonical input value unless a profile-specific caller performs that derivation before constructing `BridgeExpectedContext`.

When more than one condition fails, the first applicable error in this order MUST be the primary error.

### C-BR-05 Bridge report limits

The raw Bridge report MUST satisfy all applicable consolidated resource limits, including C-LIM-10 and C-LIM-11.

The raw report length MUST NOT exceed 16,777,216 bytes. A report of 16,777,217 bytes MUST fail with `artifact-resource-limit` before UTF-8 decoding, canonical parsing, schema inspection, or context comparison.

Bridge verification MUST use a bounded parser. It MUST NOT allocate a string, array, object, or diagnostic collection beyond the applicable C-LIM bound.

Source and input context copies MUST satisfy C-LIM-07.

### C-BR-06 Checked Bridge evidence minting

`verifyBridgeEvidence` declared by C-CAP-02 MUST mint `CheckedBridgeEvidence` only after all of these conditions hold:

1. The report satisfies every applicable resource limit.
2. The report bytes are canonical.
3. The report has version `vouch.bridge-report/v0`.
4. The complete report satisfies C-BR-01.
5. Profile, engine, source, input, and canonical input value context checks succeed in the order required by C-BR-04.
6. The implementation has stored a deep-immutable private snapshot.
7. The newly created capability has been inserted into the `CheckedBridgeEvidence` membership set required by C-CAP-01 and C-CAP-03.

The private snapshot has exactly this closed internal schema:

```text
canonical report byte copy
parsed Bridge report
profile identifier
engine digest
source digest
input digest
input canonical value digest
```

Construction MUST move the parse result into private ownership or deep-copy it. No nested array or object may alias a caller value or public projection. Typed arrays MUST NOT be exposed through a public field. The snapshot MUST use recursive deep freezing or an immutable internal representation.

The minted capability MUST carry the runtime status `checked-external`. That status is the value reported by C-BR-10 and displayed by C-BR-08.

Only the verifier factory may construct and register a `CheckedBridgeEvidence` instance. A separately constructed imitation, structured clone, deserialized object, capability from another package instance, or prototype forgery MUST fail as `wrong-evidence-capability`.

### C-BR-07 Bridge error precedence

`VerificationError` for Bridge verification is the following closed and exhaustive code set:

```text
artifact-resource-limit
non-canonical-artifact-json
unsupported-bridge-version
bridge-report-schema
bridge-profile-mismatch
bridge-engine-mismatch
bridge-source-mismatch
bridge-input-mismatch
bridge-input-canonical-value-mismatch
```

A handled Bridge verification failure MUST return exactly one primary code. It MUST use the precedence in C-BR-04.

A failure MUST mint no `CheckedBridgeEvidence`. A serialized success report or failure report is not a capability and MUST NOT be converted into `CheckedBridgeEvidence`.

### C-BR-08 Bridge renderer boundary

The Bridge renderer MUST accept only a live `CheckedBridgeEvidence` minted under C-BR-06.

It MUST reject all of these inputs as `wrong-evidence-capability`:

```text
a vouch.bridge-report/v0 object
canonical Bridge report bytes
a serialized verification report
an AuthenticatedNativeEvidence
an AuthenticatedNativeDecision
a plain object
a Proxy
a structured clone
a deserialized object
a capability minted by another package instance
```

The renderer MUST obtain its data only from the private immutable snapshot associated with the capability. It MUST NOT read public fields, caller buffers, caller paths, or serialized projections.

The exact visible string remains the value required by C-CAP-06:

```text
External evidence checked
```

The renderer MUST NOT describe Bridge evidence as authenticated, trusted, fresh, or independently witnessed.

### C-BR-09 Exit codes

`verify-bridge` MUST use this closed exit-code table:

| Exit | Meaning |
|---:|---|
| 0 | Bridge report checked and checked-external evidence minted |
| 1 | Bridge verification rejection with a report |
| 2 | Usage error |
| 3 | Input or output failure |

Exit 0 MUST be used only when a `CheckedBridgeEvidence` capability is minted under C-BR-06 and the checked report variant in C-BR-10 is written successfully.

A handled verification failure under C-BR-04 MUST use exit 1 when its rejection report is written successfully. It MUST use the checked report variant only on exit 0.

A malformed argument value under C-BR-02 MUST use exit 2 before semantic verification.

An input or output failure MUST use exit 3 as required by C-BR-11.

There is no promotion exit code. Bridge verification never promotes a decision and never uses exit 10.

### C-BR-10 Bridge verification report tagged union

`verify-bridge` MUST write exactly one canonical report to `--report-out` on every handled verification result. The report MUST be canonical `csk.artifact-json/v0` and MUST pass the byte gate in C-JSON-08.

The report MUST be a closed and exhaustive tagged union with the common tag:

```text
bridge_verify_report = vouch.bridge-verify-report/v0
```

The checked variant MUST contain exactly:

```text
bridge_verify_report = vouch.bridge-verify-report/v0
status = checked-external
primary_error = null
profile
engine_sha256
source_sha256
input_sha256
input_canonical_value_sha256
comparison_status = agree | disagree | not-comparable
decision = approve | deny | review | invalid-input | null
```

The `status`, `comparison_status`, and non-null `decision` enums are closed and exhaustive.

`status` MUST be exactly `checked-external` on the checked variant. This is the same runtime status carried by the minted `CheckedBridgeEvidence` capability required by C-BR-06 and rendered by C-BR-08. The context members MUST equal the expected context that was checked equal under C-BR-04. `comparison_status` and `decision` MUST equal the corresponding members of the verified report.

The rejection variant MUST contain exactly:

```text
bridge_verify_report = vouch.bridge-verify-report/v0
status = rejected
primary_error = <closed Bridge error code from C-BR-07>
```

`primary_error` MUST be exactly one member of the closed set in C-BR-07. A rejection report MUST NOT contain context members whose values would require trusting the rejected report.

The checked variant MUST NOT be described as authenticated, trusted, fresh, or independently witnessed. A serialized report of either variant is never a capability. It MUST NOT be converted into `CheckedBridgeEvidence` as required by C-BR-06 and C-BR-07.

Both variants and every enum in this condition are closed and exhaustive.

Backs P7 and P8.

### C-BR-11 Handled input or output failure

`verify-bridge` MUST open and read the `--report`, `--source`, and `--input` paths exactly once each as required by C-BR-02.

A failure to read any required input path and a failure to write the report to `--report-out` MUST be a handled input or output failure. The command MUST exit 3.

The command MUST write the report to `--report-out` atomically. A pre-existing `--report-out` path MUST be treated as an input or output failure. A partial report MUST never be observable at `--report-out`.

An input or output failure MUST NOT be reported as a Bridge verification error from the closed set in C-BR-07. It MUST NOT mint `CheckedBridgeEvidence`.

### C-BR-12 Bridge implementation scope and conformance boundary

The reproduction crypto core built for this release implements and passes conformance for the following Bridge behavior only. The shared canonical byte gate in C-JSON-08 applied to a `vouch.bridge-report/v0` report. The `bridge_report` discriminator check that rejects a report whose discriminator is absent or not equal to `vouch.bridge-report/v0` as `bridge-report-schema`. The minting of a distinct `CheckedBridgeEvidence` capability whose runtime status is `checked-external` and whose compile-time and runtime separation from the native capabilities is required by C-CAP-01 and C-CAP-03. The `missing-native-attestation` classification when a raw `vouch.bridge-report/v0` report is submitted to `verify-native` as required by C-VN-08.

The following Bridge behavior is specified by this contract as a design target and is not yet built into the conformance-passing core. It MUST NOT be reported as conformant until it is implemented and exercised by the B fixtures in C-BR. The complete nine-field schema validation and cross-field rules in C-BR-01. The fixed context-comparison verification order and its mismatch error codes in C-BR-04. The `verify-bridge` CLI in C-BR-02 with the exit codes in C-BR-09, the report tagged union in C-BR-10, and the input or output rule in C-BR-11. The `verifyBridgeEvidence` context-checking export and the `BridgeExpectedContext` shape in C-CAP-02 and C-BR-03.

The Bridge report schema and its context-comparison verification are a design target on the same footing as the differential native execution engine required by C-ISSUE-04 through C-ISSUE-07. Neither is part of the crypto-primitive conformance figure. That figure covers only the canonical writer and byte gate, the DSSE envelope with Ed25519 signing and verification, the consumer trust policy, the native receipt schema and native verification order, and the capability separation. The current library entry point performs the byte gate and the discriminator check and reports `non-canonical-artifact-json`, `artifact-resource-limit`, and `bridge-report-schema` from that scope. It reports `non-canonical-artifact-json` for a Bridge canonical mismatch from that scope. It does not yet compute the context-mismatch codes in C-BR-04.

A release MUST NOT claim that the built core validates the nine-field Bridge report schema or performs Bridge context comparison until fixtures B01 and B04 through B12 pass against the built implementation.

Backs P7 and P8.

## 21. Internal mutation runner

### A-13 Internal mutation runner (amended v3)

Mutation experiments MUST NOT invoke `issue-native`.

The release MUST contain an internal non-signing mutation runner that accepts immutable source and input buffers. It MUST execute checked-profile validation, parsing, normalization, lowering, both evaluators, comparison, receipt construction, canonical serialization, and structural self-verification.

The runner MUST use the production budgets, canonical writers, receipt schemas, evaluators, lowering implementation, comparison implementation, and deterministic derivation checks. It MUST NOT apply the release signability gate because disagreement and fault receipts are experiment outputs.

The runner MUST have no key-handle parameter, key-provider dependency, signing path, or release-key access. It MUST NOT be installed as a release CLI.

M01 through M06, M09, and M10 MUST have activation cases that produce genuine path disagreement.

M09 MUST replace the final Meaning Environment graph-side value event with a different canonical value of the same schema. It MUST NOT remove an event or violate transcript completeness.

M10 MUST be applied to the reference side before the shared canonical writer is called. It MUST replace a string value containing U+000A with the same string where each U+000A is replaced by U+005C followed by U+006E. The resulting receipt MUST remain schema-valid and MUST contain a genuine canonical-value disagreement.

M07, M08, M11, and M12 MUST have activation cases where both paths change identically and `comparison.status` remains `agree`.

An experiment outcome MUST NOT be established solely by an executable digest, diagnostic, panic, build failure, schema failure, completeness failure, or release issuer refusal.

Unsigned disagree, comparable language-fault, and not-comparable receipts produced by the runner are incident-analysis artifacts. They are not authenticated evidence or native decisions.

## 22. Cross-field and external-preimage consistency

### A-14 Cross-field consistency (amended v3)

Structural consistency requires all of these equalities:

```text
engine.target_triple == execution.target_triple

engine.executable_sha256 == execution.executable_sha256

graph.node_count == graph.value.nodes.length

meaning_env.node_count == graph.node_count

meaning_env.graph_sha256 == graph.graph_sha256

reference.terminal == reference.transcript.terminal

meaning_env.terminal == meaning_env.transcript.terminal
```

Structural consistency also requires:

1. Every receipt `uint` is in the inclusive range `0` through `2^53−1`.
2. Every repeated digest uses its required representation and domain mapping.
3. Every graph identifier satisfies the canonical graph rules.
4. Every node is reachable and the graph is acyclic.
5. The graph has at least one root.
6. Every transcript index identifies an existing root.
7. A completed transcript contains exactly one value event per root.
8. A comparable language-fault transcript contains values only for the completed prefix before its fault index.
9. An infrastructure-failure transcript contains values only for indices below `next_form_index`.
10. A version 0 transcript contains no output event.
11. `comparison.status` and `comparison.first_divergence_index` equal a fresh comparison of the two recorded transcripts.
12. `comparison.status` is `not-comparable` if and only if at least one terminal has kind `infrastructure-failure`.
13. For `not-comparable`, `first_divergence_index` is `null`.
14. For `not-comparable`, `comparison_unavailable_at` equals the smallest `next_form_index` among the failing side or sides.
15. For `agree` or `disagree`, `comparison_unavailable_at` is `null`.
16. A release-signed receipt has an empty `diagnostics` array.
17. `input.canonical_value_sha256` has the required digest representation.
18. The deterministic derivation checks below succeed.

The structural verifier MUST decode `canonical.normalized_bytes_b64`, parse the normalized program, and deterministically lower it again. The canonical bytes of the newly produced graph MUST be byte-identical to the canonical bytes of `graph.value`.

When external input bytes are available, the structural verifier MUST parse those bytes again, apply the checked host-to-Lispex mapping, canonically encode the mapped value, and recompute its digest. The result MUST equal `input.canonical_value_sha256`.

The `issue-native` structural self-verification always has the immutable external source and input buffers. It MUST perform both deterministic derivation checks before the signability gate.

A source and graph combination that does not reproduce byte-identical graph bytes MUST fail structural verification. An input whose mapped canonical value does not reproduce `input.canonical_value_sha256` MUST fail structural verification.

### A-15 External-preimage consistency (amended v3)

Canonical normalized program bytes, graph bytes, transcript bytes, and boundary bytes are receipt-carried preimages. Structural verification MUST recompute their digests from those carried preimages.

The receipt-carried normalized program bytes MUST also reproduce the graph as required by A-14. Digest equality without deterministic graph reproduction is insufficient.

Source, raw input, and executable bytes are not receipt members. External source and input bytes are checked only at their assigned verification steps. Supplying external context MUST NOT permit a later check to determine an earlier primary error.

When source bytes are supplied, the verifier MUST read them once, recompute the source digest and byte length, normalize from the same immutable buffer, and require the normalized bytes to equal the decoded receipt bytes.

When input bytes are supplied, the verifier MUST read them once, recompute the raw input digest and byte length including the required final LF, parse the same immutable bytes, derive the canonical mapped Lispex value, and require its digest to equal `input.canonical_value_sha256`.

The executable digest is calculated during issuance from one open executable handle. During native verification it is an authenticated signer claim until the engine-policy step compares it with external trust context. It is not a hardware-backed measurement.

Structural verification independently checks deterministic derivations and internal consistency. It does not replay either evaluator and does not establish that execution occurred.

The authenticated claim remains that the signer claims to have executed the bound source and input. Deterministic structural checks do not convert that claim into an independent witness.

## 23. Fixture manifest

Every fixture declared by the conformance registries MUST appear exactly once in `artifact/fixtures/fixture-manifest.json`.

Every manifest row MUST record:

```text
fixture identifier
scope
input paths
command or API operation
expected exit code
expected primary error
expected secondary reason
expected failed check
expected input artifact
expected underlying error
expected status
expected display
paper claim identifiers
```

`scope` is the `built` or `design-target` value C-FIX-08 requires. `expected failed check` is the C-ID-10 finalizer check identifier a finalizer-refusal row expects or the C-REP-08 phase-3 check identifier a publication-check row expects, and is `null` when the applicable closed report schema requires no identified check. `expected input artifact` is the C-ID-10 and C-REP-08 `input_artifact` member that a `finalizer-input-invalid` row, a `publication-input-invalid` row, or a publication-check `input-output-failure` row expects, and is `null` for every other row. `expected underlying error` is the `underlying_error` member that a `finalizer-input-invalid` or `publication-input-invalid` row expects, and is `null` for every other row.

A field that does not apply MUST be `null`. Fixture identifiers form one global unique namespace.

### Native authentication and context fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| N01 | Valid release envelope, reproduction policy, correct source, input, and profile. Exit 0 with `authentication_status = authenticated`, `decision_promotion = eligible`, and `comparison_status = agree`. Promotion succeeds. | P2, P4, P7 |
| N02 | Canonical self-consistent unsigned receipt. `verify-structure` exits 0 with `structurally-consistent`. `verify-native` exits 1 with `missing-native-attestation`. | P1, P6 |
| N03 | One payload byte changed after signing. Exit 1 with `native-signature-invalid`. | P2 |
| N04 | Final canonical decision value changed after signing. Exit 1 with `native-signature-invalid`. | P2 |
| N05 | Source hash changed after signing. Exit 1 with `native-signature-invalid`. | P2 |
| N06 | Input hash changed after signing. Exit 1 with `native-signature-invalid`. | P2 |
| N07 | Canonical Bridge payload signed under the native payload type by a dedicated fixture key whose policy the harness loads for that fixture directory as an operational rule. Exit 1 with `native-receipt-schema`. | P2, P4 |
| N08 | Valid native receipt signed by an attacker key absent from policy. Exit 1 with `untrusted-native-key`. | P2, P4 |
| N09 | Authorized `keyid` paired with an attacker signature. Exit 1 with `native-signature-invalid`. | P2 |
| N10 | Valid signature and receipt with an executable digest absent from policy. Exit 1 with `native-engine-disallowed`. | P4 |
| N11 | Valid envelope checked against wrong source bytes. Exit 1 with `native-source-mismatch`. | P4 |
| N12 | Valid envelope checked against wrong input bytes. Exit 1 with `native-input-mismatch`. | P4 |
| N13 | Valid envelope checked against a syntactically valid and policy-authorized expected profile that differs from the receipt profile. Exit 1 with `native-profile-mismatch`. | P4 |
| N14 | Signed disagree receipt. Exit 10 with `authentication_status = authenticated`, `decision_promotion = ineligible`, and `comparison_status = disagree`. Promotion fails with reason `comparison-not-agree`. | P2, P7 |
| N15 | Signed agreeing comparable language-fault receipt. Exit 10 with `authentication_status = authenticated`, `decision_promotion = ineligible`, and `comparison_status = agree`. Promotion fails with reason `terminal-not-completed`. | P2, P7 |
| N16 | Signed not-comparable receipt. Exit 10 with `authentication_status = authenticated`, `decision_promotion = ineligible`, and `comparison_status = not-comparable`. Promotion fails with reason `comparison-not-agree`. | P2, P7 |
| N17 | Signed completed agreement whose final value is not a decision. Authentication succeeds but promotion is ineligible. Promotion fails with reason `final-value-not-decision`. | P2, P7 |
| N18 | Signed zero-root completed agreement submitted to `verify-native` is rejected as `native-receipt-inconsistent`, and `verify-structure` rejects it likewise, so no AuthenticatedNativeEvidence snapshot is ever minted. The issuer-side self-check name `native-self-verification-failed` is not used on the external verification path. A promotion-path invariant test MUST confirm that no such snapshot reaches promotion and that no decision is minted. | P1, P7 |
| N19 | A serialized successful native verification report passed to promotion fails as `wrong-evidence-capability`. | P7 |
| N20 | A valid envelope checked with a syntactically valid profile that policy does not authorize and whose value also differs from the receipt profile. Exit 1 with `native-profile-disallowed`. | P4 |

### Canonical-byte fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| J01 | Compact DSSE envelope. `non-canonical-artifact-json`. | P5 |
| J02 | DSSE envelope with CRLF. `non-canonical-artifact-json`. | P5 |
| J03 | Reordered DSSE envelope members. `non-canonical-artifact-json`. | P5 |
| J04 | DSSE envelope with trailing whitespace. `non-canonical-artifact-json`. | P5 |
| J05 | DSSE envelope with a UTF-8 byte-order mark. `non-canonical-artifact-json`. | P5 |
| J06 | DSSE envelope using optional Unicode escaping. `non-canonical-artifact-json`. | P5 |
| J07 | DSSE envelope with duplicate top-level members carrying different values. `non-canonical-artifact-json`. | P5 |
| J08 | DSSE envelope with duplicate top-level members carrying identical values. `non-canonical-artifact-json`. | P5 |
| J09 | Validly signed compact receipt payload. `non-canonical-artifact-json` after signature verification. | P2, P5 |
| J10 | Validly signed receipt payload with CRLF. `non-canonical-artifact-json`. | P5 |
| J11 | Validly signed receipt payload with reordered members. `non-canonical-artifact-json`. | P5 |
| J12 | Validly signed receipt payload with trailing whitespace. `non-canonical-artifact-json`. | P5 |
| J13 | Validly signed receipt payload using alternate string escaping. `non-canonical-artifact-json`. | P5 |
| J14 | Validly signed receipt payload with duplicate top-level members. `non-canonical-artifact-json`. | P5 |
| J15 | Validly signed receipt payload with duplicate nested members carrying identical values. `non-canonical-artifact-json`. | P5 |

The valid signatures in J09 through J15 MUST be precomputed by a dedicated fixture key. That key MUST not be the release key. Its policy authorizes payload types and key identifiers only, and the harness loads it for its named fixture directory as an operational rule under C-FIX-04.

### Schema, version, resource, and derivation fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| P01 | Canonical, validly signed, schema-invalid receipt. Canonical verification passes before `native-receipt-schema`. | P4, P5 |
| P02 | Canonical, validly signed unknown receipt version. `unsupported-native-version`. | P4 |
| P03 | Unknown DSSE payload type. `native-payload-type`. | P4 |
| P04 | Envelope of 16 MiB plus one byte. `artifact-resource-limit` with subject `envelope-bytes`. | P4 |
| P05 | Raw structural payload of 16 MiB plus one byte. `artifact-resource-limit` with subject `payload-bytes`. | P5 |
| P06 | Parsed depth 129. `artifact-resource-limit` with subject `json-depth`. | P5 |
| P07 | One array with 10,001 members. `artifact-resource-limit` with subject `array-members`. | P5 |
| P08 | One string with 1 MiB plus one UTF-8 byte. `artifact-resource-limit` with subject `string-bytes`. | P5 |
| P09 | Parsed value with 100,001 nodes while all other limits remain within bounds. `artifact-resource-limit` with subject `json-nodes`. | P5 |
| P10 | Receipt normalized program bytes paired with graph bytes from another source. Structural verification fails as `native-receipt-inconsistent`. Issuance self-verification fails before key access. | P1, P3 |
| P11 | External input bytes map to a canonical value digest different from `input.canonical_value_sha256`. Structural verification fails as `native-receipt-inconsistent`. | P1, P4 |

### Bridge and bound-context fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| B01 | Valid `vouch.bridge-report/v0` report whose `profile`, `engine_sha256`, `source_sha256`, `input_sha256`, and `input_canonical_value_sha256` match the expected context. `verify-bridge` exits 0 and writes the checked report variant with `status` equal to `checked-external`. | P7, P8 |
| B02 | Raw `vouch.bridge-report/v0` report submitted to `verify-native`. `missing-native-attestation`. | P4 |
| B03 | Native DSSE envelope submitted to `verify-bridge`. The submitted bytes carry no `bridge_report` discriminator. `bridge-report-schema`. | P7 |
| B04 | Bridge report of 16,777,217 bytes. `artifact-resource-limit`. | P7 |
| B05 | Bridge report with noncanonical bytes such as reordered members. `non-canonical-artifact-json`. | P5, P7 |
| B06 | Report whose `bridge_report` value is `vouch.bridge-report/v1`. `unsupported-bridge-version`. | P7 |
| B07 | Report whose `bridge_report` value is `vouch.bridge-report/v0` but which omits a required member, carries an unknown member, or sets a non-null `decision` while `comparison_status` is not `agree`. `bridge-report-schema`. | P7 |
| B08 | Report whose `profile` differs from the expected profile. `bridge-profile-mismatch`. | P7 |
| B09 | Report whose `engine_sha256` differs from the expected engine digest. `bridge-engine-mismatch`. | P7 |
| B10 | Report whose `source_sha256` differs from the SHA-256 digest of the expected source bytes. `bridge-source-mismatch`. | P7 |
| B11 | Report whose `input_sha256` differs from the SHA-256 digest of the expected input bytes. `bridge-input-mismatch`. | P7 |
| B12 | Report whose `input_canonical_value_sha256` differs from the expected canonical input value digest. `bridge-input-canonical-value-mismatch`. | P7 |

### Replay-manifest fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| R01 | Exact signed manifest, ordered corpus, rules, selection, and split. Manifest verification passes. | P10 |
| R02 | One corpus case deleted. `replay-corpus-member-missing`. | P10 |
| R03 | Two corpus cases reordered. `replay-corpus-order-mismatch`. | P10 |
| R04 | Canonical substitute manifest signed by an attacker key. `untrusted-native-key`. | P10 |
| R05 | Manifest expected count changed after signing. `native-signature-invalid`. | P10 |

### Consumer and capability fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| U01 | Strict `oneOf` validates B01 only in its Bridge branch and rejects it in its native branch. | P6 |
| U02 | Strict `oneOf` accepts N02 in its native-shaped branch without authenticating origin. | P1, P6 |
| U03 | Vulnerable Boolean consumer receives B01 and displays exactly `Verified`. | P8 |
| U04 | Repaired consumer receives B01 and displays exactly `External evidence checked`. | P7, P8 |
| U05 | TypeScript passes `CheckedBridgeEvidence` to `renderNativeDecision`. Compilation fails. | P7, P8 |
| U06 | Untyped JavaScript passes `CheckedBridgeEvidence` to `renderNativeDecision`. Runtime fails as `wrong-evidence-capability`. | P7, P8 |
| U07 | A plain-object forgery of `AuthenticatedNativeEvidence` passed to promotion fails as `wrong-evidence-capability`. | P7 |
| U08 | A `Proxy` forgery of `AuthenticatedNativeEvidence` passed to promotion fails as `wrong-evidence-capability`. | P7 |
| U09 | A structured clone of real `AuthenticatedNativeEvidence` passed to promotion fails as `wrong-evidence-capability`. | P7 |
| U10 | A separately constructed cross-realm imitation of `AuthenticatedNativeEvidence`, or a capability transferred through structured clone, passed to promotion fails as `wrong-evidence-capability`. | P7 |
| U11 | TypeScript passes real `AuthenticatedNativeEvidence` to `renderNativeDecision`. Compilation fails. | P7 |
| U12 | Untyped JavaScript passes real `AuthenticatedNativeEvidence` to `renderNativeDecision`. Runtime fails as `wrong-evidence-capability`. | P7 |
| U13 | The same live `AuthenticatedNativeEvidence` capability object passed through another realm without cloning retains membership and promotes normally. | P7 |

### Immutable-memory fixtures

| ID | Condition and expected result | Backs |
|---|---|---|
| T01 | Verify N01, modify both source and input paths, then render the promoted decision. It still displays `Authenticated native decision` and retains the originally verified digests. | P4, P7, P17 |
| T02 | Verify N01, mutate the caller envelope, source, and input buffers and mutate every exposed receipt projection, then promote. Promotion produces the same deep-frozen decision and digests as before mutation. | P4, P7, P17 |

### Issuance signability and input fixtures

| ID | Condition and expected result |
|---|---|
| I01 | Disagree comparison. Issuance fails as `native-result-not-signable` with reason `comparison-not-agree` and zero key accesses. |
| I02 | One or both terminals are not completed. Issuance fails as `native-result-not-signable` with reason `terminal-not-completed` and zero key accesses. |
| I03 | Zero graph roots. The receipt is rejected by structural self-verification as `native-self-verification-failed` before the signability gate, with zero key accesses. Zero roots is a structural rejection under C-ISSUE-13, not a signability reason. |
| I04 | Completed agreement with a non-decision final value. Issuance fails as `native-result-not-signable` with reason `final-value-not-decision` and zero key accesses. |
| I05 | Final values differ. The receipt is rejected by structural self-verification as `native-self-verification-failed` before the signability gate, with zero key accesses. A final-value difference is a structural rejection under C-ISSUE-13, not a signability reason. |
| I06 | One or both transcripts are incomplete. The receipt is rejected by structural self-verification as `native-self-verification-failed` before the signability gate, with zero key accesses. An incomplete transcript is a structural rejection under C-ISSUE-13, not a signability reason. |
| I07 | Diagnostics is nonempty. Issuance fails as `native-result-not-signable` with reason `diagnostics-present` and zero key accesses. |
| I08 | Build metadata identifies a mutant. Issuance fails as `native-result-not-signable` with reason `mutant-build` and zero key accesses. |
| I09 | Input bytes are not parseable as one strict UTF-8 JSON value. Issuance fails as `native-input-parse-failed` before evaluation and key access. |
| I10 | Input bytes parse as JSON but violate the host input profile. Issuance fails as `native-input-profile-invalid` before evaluation and key access. |
| I11 | A valid host input list has application-level wrong arity, wrong element type, or an out-of-range category code. Evaluation returns the canonical `invalid-input` decision. It does not fail input-profile validation. |
| I12 | A checked input file without exactly one final LF is rejected as `native-input-profile-invalid`. |
| I13 | A checked input file with exactly one final LF hashes and records a byte length that include that LF. |

### Mutant build guard fixture

| ID | Condition and expected result |
|---|---|
| G01 | Build with `RUSTFLAGS=--cfg scored_mutant` and no identical `CSK_SCORED_MUTANT` selection. Compilation fails through `compile_error!`. |
| G02 | Build with mismatched active `scored_mutant` cfg values and `CSK_SCORED_MUTANT`. Compilation fails through `compile_error!`. |
| G03 | Build with more than one active `scored_mutant` cfg value. Compilation fails through `compile_error!`. |

### C-FIX-01 Generated manifest count rule (amended v3)

The fixture manifest MUST be generated from the complete fixture registries. Its `expected` count MUST equal the number of generated unique rows. No numeric fixture count is a conformance constant.

Generation MUST fail if an identifier is absent, duplicated, manually added outside a registry, or omitted from the generated manifest.

The aggregate runner MUST fail if a manifest row is skipped, marked expected-failure without observing its exact expected failure, or produces a result different from any recorded expected field.

### C-FIX-02 Generated fixture report (amended v8)

`artifact/results/fixture-results.json` MUST contain one result for every generated manifest row and exactly this closed `fixture_results` summary shape, which is the single owner fixture summary schema reused verbatim by C-FIX-08, the clean-run report Q of C-FINAL-01, and the reproduction observation R of C-ID-10:

```json
{
  "built": {
    "expected": <uint>,
    "matched": <uint>,
    "mismatched": <uint>,
    "skipped": <uint>
  },
  "design_target": {
    "listed": <uint>,
    "implemented": <uint>,
    "matched": <uint>,
    "not_implemented": <uint>
  }
}
```

The `built` object counts the `built`-scope rows of C-FIX-08 and the `design_target` object counts the `design-target`-scope rows. Every count is a `<uint>` and is not quoted. A passing report MUST satisfy, over the `built` object:

```text
built.matched == built.expected
built.mismatched == 0
built.skipped == 0
```

Design-target rows are recorded in the `design_target` object with their observed results but do not affect the pass condition, as required by C-FIX-08. The report MUST derive every count from the generated manifest and observed results. It MUST NOT contain a hard-coded expected fixture count. The report MUST be canonical `csk.artifact-json/v0` and MUST carry the tag `"fixture_report": "vouch.scored26-fixture/v0"`. `derive(exact artifact/results/fixture-results.json bytes)` for `Q.fixture_results` is the report's `fixture_results` object taken verbatim, and the report MAY carry additional members that `derive` never reads.

### C-FIX-03 Counting key-provider audit (amended v8.5.1)

Every refused issuance fixture and every refused finalization fixture MUST use the counting key-provider fixture.

The provider MUST count all filesystem metadata reads, path canonicalization attempts, key-file opens, HSM queries, KMS queries, and other key-handle resolution operations.

Each refused issuance and each PRE-KEY refused finalization MUST record exactly zero key accesses. The aggregate audit MUST also record exactly zero key accesses across all refused issuances and all pre-key refused finalizations. The finalization refusals in scope are L06, L07, L11A, L11B, L13, L16, and every other refusal of the C-ID-10 finalizer that occurs before key-handle resolution. Post-key `key-loading-or-signing-failure` and post-key publication `input-output-failure` refusals are out of scope because the handle was legitimately resolved after every check passed. L21 MUST record nonzero key access.

Before the signability gate passes, syntactic validation of the opaque key-handle URI is the only permitted key-handle operation.

### C-FIX-04 Fixture-key isolation (amended v4)

Every fixture requiring a valid signature over a receipt that release issuance would refuse MUST use a dedicated fixture key.

A fixture key MUST NOT be the release key. Fixture-key material MUST NOT be accepted by the reproduction release policy. The trust policy schema has no directory scope field. The phrase directory authorization is an operational rule of the fixture harness and not a cryptographic policy field. It means only that the fixture harness loads that fixture policy file when running that fixture directory. A fixture key trust policy authorizes payload types and key identifiers exactly like any other trust policy, with no directory-scoped authority.

### C-FIX-05 Capability refusal completeness

Every capability-forgery fixture MUST assert all of these outcomes:

1. No `AuthenticatedNativeDecision` is minted.
2. No native renderer output is produced.
3. The exact error is `wrong-evidence-capability`.
4. No public field or serialized representation is used as authority.
5. The original live capability remains unaffected.

### C-FIX-06 Memory TOCTOU audit

The immutable-memory fixtures MUST mutate caller-owned buffers after verification and before promotion. They MUST also mutate any public receipt or metadata projection.

The promoted result, promotion eligibility, decision value, source digest, input digest, input canonical value digest, profile identifier, engine digest, and key identifier MUST remain identical to the values derived at verification time.

### C-FIX-07 Round-4 adversarial fixtures (amended v8.5.1)

The generated fixture manifest MUST include every fixture below, each defined in its owner condition and referenced here by identifier. The fixture count stays generated under C-FIX-01 and is not a fixed number.

```text
C-VN-11    multi-key profile confusion
C-ISSUE-13 same-root-count transcript swap
C-CAP-11   constructor runtime forgery
C-CAP-12   policy and context getter TOCTOU
C-VN-12    unauthenticated rejection report
C-REP-09   bootstrap substitution
A-19       decision before final root
```

The failure-report atomicity fixture required by C-ISSUE-09 and the local rebuild payload reproduction fixture required by C-REP-06 MUST also appear in the generated manifest. An issuance fixture in which a checked program consumes a decision value as a primitive operand at the final root MUST also appear, expecting a `profile-escape` at issuance and no signable receipt as required by A-4, distinct from the structural decision-before-final-root fixture A-19.

The release lifecycle fixtures below MUST also appear in the generated manifest. Each carries its own unique fixture identifier in the single global identifier namespace of C-FIX-01, so the duplicate-identifier gate stays satisfiable, and each names the condition that owns its behavior:

```text
L01  observation-json-payload-mismatch     owner C-DSSE-09
     the DSSE decoded payload is not byte-identical to reproduction-observation.json
     -> reject before hashing or rendering R

L02  observation-wrong-release-key         owner C-DSSE-09
     the observation is signed by a policy-authorized key whose keyid != descriptor key_id
     -> reject at key selection

L03  cross-release-publication-chain       owner C-ID-09
     a publication record P from one release is combined with the R and Q of another
     -> reject at the C-REP-08 chain check

L04  premature-phase1-rp-access            owner C-REP-05
     the phase-1 clean-room run attempts to read or verify R or P before Q exists
     -> reject, phase 1 has no R or P access

L05  empty-workload-interior               owner C-WL-05
     a threshold set leaves an interval with an empty interior pool
     -> reject at threshold extraction

L06  cross-release-descriptor-report-mix   owner C-ID-10
     the finalizer is handed the descriptor D of one release and the clean-run report
     Q of another, both authentic, under the same authorized release key, and is asked
     to finalize a single R binding both
     -> reject before any key access, at Q.release_descriptor_sha256 == SHA256(D)
```

```text
L07  comparison-row-false-match             owner C-ID-10
      a comparison row whose expected_sha256 differs from its observed_sha256 while
      matched is true
      -> exit 1, status refused, primary_error clean-run-derivation-mismatch,
         failed_check qd-comparison-matched, input_artifact null, underlying_error null,
         before any key access

L08  finalizer-input-swapped-after-entry   owner C-ID-10
     every input file is overwritten with different but valid bytes after command entry
     and before the R-derivation checks run
     -> exit 0, primary_error null, failed_check null, status finalized; the signed R,
        the publication record P, and every derivation MUST equal the values computed
        from the bytes read at entry and MUST NOT reflect the replacement bytes

L09  publication-report-swapped-after-entry owner C-REP-08
      every owner report and tracked paper-source file is overwritten with different but
      valid bytes after command entry and before the paper is rendered
      -> exit 0, primary_error null, status pass; every empirical value in the rendered
         paper and in S and every rendered paper-source byte MUST equal the entry buffers
         and provenance snapshot and MUST NOT reflect the replacement bytes

L10  missing-out-dir-usage-failure          owner C-ID-10
     the finalizer is invoked with no usable --out-dir
     -> exit 2, usage-error, no file written at any final path, error on stderr only

L11A noncanonical-owner-report              owner C-ID-10
      the workload report is valid JSON but is not canonical csk.artifact-json/v0
      -> exit 1, status refused, primary_error finalizer-input-invalid,
         failed_check null, input_artifact workload-report,
         underlying_error non-canonical-artifact-json,
         before any release-binding or derivation check and before key access

L11B overlimit-owner-report                 owner C-ID-10
      the workload report exceeds the registered raw artifact byte limit
      -> exit 1, status refused, primary_error finalizer-input-invalid,
         failed_check null, input_artifact workload-report,
         underlying_error artifact-resource-limit,
         before any release-binding or derivation check and before key access

L12  publication-input-missing              owner C-REP-08
      the clean-run report input is missing
      -> exit 3, S published with status fail, release_descriptor_sha256 and every other
         successfully read digest populated, clean_run_report_sha256 null,
         primary_error input-output-failure, failed_check null, input_artifact clean-run-report,
         underlying_error null, chain_verified not-run, paper_claims_matched null,
         claim_language_scan not-run

L13  same-summary-different-details-after-q owner C-ID-10
      phase 1 produces workload report A and Q is published from A; afterward A is
      replaced by a valid workload report B with the identical derived workload summary
      but different detail members before the finalizer starts
      -> exit 1, status refused, primary_error clean-run-derivation-mismatch,
         failed_check qd-workload-bytes, input_artifact null, underlying_error null,
         before key access

L14  archive-use-after-check-path-swaps       owner C-REP-04
     archive A passes authenticated D.archive_sha256; after the digest check and before
     extraction, the archive argument path is replaced with archive B and an attacker also
     creates or replaces the predictable path at which a content-addressed staging copy
     would have existed
     -> exit 0, status pass, every error field null; the driver opens no staging path,
        extraction reads only through the digest-verified private pathless snapshot of A,
        B is never extracted, and no archive-supplied code from B runs

L15  bootstrap-descriptor-swap                owner C-REP-04
     D_A authenticates archive A; after authentication the D argument path is replaced
     with D_B before extraction and Q construction
     -> exit 0, status pass, every error field null; extraction, the inner runner, the
        comparison artifact, and Q remain bound only to the frozen authenticated D_A bytes

L16  descriptor-payload-keyid-mismatch        owner C-ID-10
     policy-authorized key A signs D while D.key_id names distinct policy-authorized key B
     -> exit 1, status refused, primary_error descriptor-authentication-failed,
        failed_check null, input_artifact null, underlying_error null, before key access;
        the bootstrap and publication-check variants of the same mismatch are likewise
        rejected by their C-REP-04 and p3-descriptor-authentication classes

L17  signed-observation-semantic-mismatch     owner C-REP-08
     R has a valid release-key signature and correct D and Q hashes but carries a
     clean_run_runtime_seconds value inconsistent with Q
     -> exit 1, S status fail, primary_error chain-verification-failed,
        failed_check p3-rd-runtime, input_artifact null, underlying_error null,
        chain_verified fail, paper_claims_matched null, claim_language_scan not-run

L18  phase-1-comparison-mismatch              owner C-REP-04/C-FINAL-01
     a phase-1 comparison row has matched == false
     -> expected exit code PHASE_1_COMPARISON_MISMATCH (1), expected primary error null,
        expected failed check null, expected input artifact null, expected underlying error
        null, expected status null, and no Q is published; rd-comparisons-matched is not
        needed to make phase 1 fail

L19  archive-inode-content-swap               owner C-REP-04
     the verifier opens normal archive A's inode by retained descriptor; after A's digest check
     and before extraction, the attacker overwrites the same inode in place (pwrite/truncate/mmap)
     with malicious B through a pre-existing writable descriptor
     => B is not extracted, B's archive-supplied code does not run, extraction consumes only the
        digest-verified immutable snapshot of A
     -> expected exit code 0, expected primary error null, expected failed check null,
        expected secondary reason null, expected input artifact null, expected underlying error
        null, expected status pass, expected display null, paper claim identifiers P9 and P15;
        any snapshot-integrity failure uses the existing bootstrap archive-integrity failure class

L20  wrong-finalizer-private-key-handle       owner C-ID-10
     D identifies key A, but --key-handle is key B's private key
     => exit 4, no R, no R envelope, no P published
     -> expected primary error key-loading-or-signing-failure, expected secondary reason null,
        expected failed check null, expected input artifact null, expected underlying error null,
        expected status refused, expected display null, paper claim identifiers P9, P15, and P17

L21  post-key-publication-io-failure           owner C-ID-10
     after all checks and the key/envelope self-verification succeed, inject a failure into the
     staging write, the fsync, or the final rename
     => exit 3; input-output-failure; no final output directory; no partial final publication of
        R / envelope / P; NOT subject to the zero-key-access assertion (key access is nonzero)
     -> expected secondary reason null, expected failed check null, expected input artifact null,
        expected underlying error null, expected status null, expected display null,
        paper claim identifiers P9, P15, and P17
```

L01 through L10, L11A, L11B, and L12 through L21 carry `scope` `built` under C-FIX-08. They exercise the release-layer commands, not the not-yet-built differential engine or the Bridge context path, so they are not part of the `design-target` subset. L06 is the fixture for the cross-release mix-up an honest finalizer could otherwise sign. It MUST fail on the release-binding check `rb-q-descriptor`, before the key handle is resolved, and the counting key-provider audit of C-FIX-03 MUST record zero key accesses for it. L07 through L21 close the byte-lifetime, comparison-truth, report-binding, error-model, bootstrap-object-lifetime and byte-snapshot, release-key-identity, terminal-derivation, phase-1 gate, finalizer exact-signer, and post-key publication-I/O gaps of the release layer. The finalizer refusals L06, L07, L11A, L11B, L13, and L16 are pre-key refusals and are in scope for the C-FIX-03 zero-access audit. L20 and L21 are post-key refusals and are outside that audit because key-handle resolution has already occurred; L21 MUST record nonzero key access. L10 is a pre-key usage refusal for which no usable output directory exists and likewise performs no key access. L08, L09, L14, L15, and L19 are positive-outcome fixtures that assert the read-once immutable-object rules hold. L12 and L17 exercise the publication-check, which resolves no finalizer key handle and is therefore outside that audit. L18 exercises the outer-driver phase-1 gate and publishes no passing Q. No fixture in this list may be omitted, and the manifest report MUST record that every identifier through L21 is present exactly once.

### C-FIX-08 Fixture scope and the partial-implementation conformance gate (amended v8.1)

Every generated manifest row MUST carry a `scope` of exactly `built` or `design-target`.

The `design-target` subset is exactly the fixtures whose behavior C-BR-12 and the differential native execution engine of C-ISSUE-04 through C-ISSUE-07 mark as specified but not yet built. It includes the Bridge context path fixtures B01 context checking, B06, B07, B08, B09, B10, B11, and B12, and every fixture that exercises the not-yet-built differential engine. B02, B03, B04, B05, and the Bridge capability-separation fixtures stay `built`, because C-BR-12 keeps the byte gate, the `artifact-resource-limit` and `non-canonical-artifact-json` codes, and the discriminator check in the built scope, which is exactly what B04 and B05 exercise.

There are exactly two FIXTURE gates, and each condition names exactly one of them. Neither is the release final gate; the release final gate is the phase-3 publication-check of C-REP-08. The partial-implementation fixture gate is `npm run scored26:core-conformance`. It runs every row whose scope is currently `built`, which includes the built crypto rows, the built native rows, the built Bridge rows B02, B03, B04, B05, and the Bridge capability-separation fixtures, and it MUST pass for the current partial implementation. The full fixture gate is the phase-1 `npm run scored26:reproduce`. It is named by C-REP-05 and C-FINAL-01 and is valid only for a final release in which every design target has already moved to `built` scope, so it simply runs every row, the workload, the differential engine, all mutants, and the full Bridge context path. Passing it means phase 1 passed, not that the release passed.

C-FIX-01 generation fails on a duplicated or missing identifier in any scope. The aggregate-runner requirement that no row is skipped and every result matches applies to `built`-scope rows in whichever gate is running. Every `built`-scope row MUST match its expected result and none may be skipped. A `design-target` row is generated, listed, and recorded in the `design_target` object, but it is not required to pass in the current partial-implementation release and MUST NOT be reported as conformant.

The fixture summary MUST be the single owner `fixture_results` object defined in C-FIX-02, with a `built` object of `expected`, `matched`, `mismatched`, and `skipped` and a `design_target` object of `listed`, `implemented`, `matched`, and `not_implemented`. When a design target is implemented it moves to `built` scope, and the phase-1 full fixture gate then requires it to pass. This is how the mandatory-pass rule and the designed-not-built scope hold at once.

## 24. Consolidated resource limits

### C-LIM-01 Resource limit scope and error

The limits in this family are mandatory for every Native and Bridge parser, verifier, issuer, structural checker, fixture runner, and reproduction command that consumes the covered value.

Exceeding any limit MUST produce `artifact-resource-limit` unless a more specific condition explicitly requires termination as `profile-escape` during live language evaluation.

Resource preflight MUST precede canonical validation, schema validation, cryptographic verification, context comparison, graph derivation, and evaluator execution.

Implementations MAY reject earlier while incrementally counting toward a limit. They MUST NOT accept a value whose final count exceeds a limit.

### C-LIM-02 Raw artifact byte limit

A raw JSON artifact MUST contain no more than 16,777,216 bytes.

The count is the exact number of octets read from the artifact before byte-order mark handling, UTF-8 decoding, newline normalization, or parsing. No transformation may reduce the counted length.

An artifact containing exactly 16,777,216 bytes is within this limit. An artifact containing 16,777,217 bytes MUST fail with `artifact-resource-limit`.

The implementation MUST enforce the limit while reading. It MUST stop after observing byte 16,777,217 and MUST NOT buffer the remainder.

### C-LIM-03 JSON nesting depth limit

JSON container nesting depth MUST NOT exceed 128.

The root value begins at depth zero. Entering an array or object increases the depth by one. Leaving that container restores the previous depth. Scalars do not increase depth.

A scalar root has depth zero. An empty root array or object reaches depth one. A value reached through 128 simultaneously open arrays or objects is within the limit. Opening the 129th container MUST fail with `artifact-resource-limit`.

Depth counting MUST operate on JSON tokens before construction of the complete object model.

### C-LIM-04 JSON object member limit

A single JSON object MUST contain no more than 10,000 member occurrences.

The count begins at zero when an object opens. Each syntactic name and value pair increments that object's count by one. Counts are independent for nested objects.

Duplicate names still count as separate member occurrences. A duplicate-name rejection does not erase an occurrence already counted.

An object with 10,000 member occurrences is within the limit. Observation of the 10,001st member occurrence MUST fail with `artifact-resource-limit`.

### C-LIM-05 JSON string byte limit

Every JSON string token, including every object member name, MUST decode to no more than 1,048,576 UTF-8 bytes.

The parser MUST decode JSON escapes and Unicode surrogate pairs into Unicode scalar values. It MUST then count the bytes produced by strict UTF-8 encoding of those scalar values. Quote characters and escape spelling bytes are not part of this count.

A decoded string of exactly 1,048,576 UTF-8 bytes is within the limit. A decoded string of 1,048,577 UTF-8 bytes MUST fail with `artifact-resource-limit`.

Invalid Unicode escape structure remains a canonical or parse failure. It MUST NOT be replaced before counting.

### C-LIM-06 Graph node limit

A graph MUST contain no more than 100,000 node records.

The count is the number of elements in the canonical node collection of the `csk.graph/v0` value. Every declared node record counts exactly once regardless of reachability, root membership, shared incoming edges, or repeated references.

The verifier MUST compare this count with every recorded `node_count` field. A mismatch is structural inconsistency. A count greater than the limit is `artifact-resource-limit`.

A graph containing exactly 100,000 node records is within the limit. Observation of the 100,001st node record MUST fail with `artifact-resource-limit`.

Traversal through graph edges MUST NOT increment the node count. Implementations MUST NOT count a shared node once per incoming edge.

### C-LIM-07 Source and input byte limits

Source bytes MUST contain no more than 1,048,576 bytes.

Input bytes MUST contain no more than 1,048,576 bytes.

Each count is the exact number of octets in the private entry copy before UTF-8 decoding, newline normalization, parsing, canonical mapping, or hashing.

A source or input containing exactly 1,048,576 bytes is within its limit. A source or input containing 1,048,577 bytes MUST fail with `artifact-resource-limit`.

Path metadata, terminating zero bytes added by an implementation, and transport framing are not part of the count. Every octet present in the supplied file or byte buffer is part of the count.

### C-LIM-08 Rational digit limits

A canonical rational numerator magnitude MUST contain no more than 4,096 decimal digits.

A canonical rational denominator MUST contain no more than 4,096 decimal digits.

For the numerator, an optional leading minus sign does not count as a digit. For both components, the count is the number of ASCII decimal digits after canonical integer syntax validation and before greatest-common-divisor reduction.

Canonical rational input MUST already be in lowest terms under A-4. Reduction MUST NOT be used to bring an over-limit component within the limit.

A component containing exactly 4,096 digits is within the limit. A component containing 4,097 digits MUST fail with `artifact-resource-limit` during artifact verification or parsing. Live evaluation that attempts to construct an out-of-profile rational MUST terminate as `profile-escape` when required by the checked profile.

### C-LIM-09 Bounded counting algorithm

Resource preflight MUST use these counters:

```text
raw_byte_count
current_container_depth
member_count_for_each_open_object
decoded_utf8_byte_count_for_current_string
member_count_for_each_open_array
total_json_node_count
graph_node_record_count
source_byte_count
input_byte_count
rational_numerator_digit_count
rational_denominator_digit_count
integer_digit_count
```

Raw artifact, source, and input counters MUST be monotonic octet counters.

Container depth MUST increment before accepting an opening array or object token and decrement after accepting its matching closing token.

Each object member counter MUST increment when its member name and separating colon establish a syntactic member occurrence. The counter MUST remain associated with that open object until the object closes.

The string counter MUST be reset for each string token and increment by the strict UTF-8 width of each decoded Unicode scalar value.

The graph counter MUST increment once for each element encountered in the canonical node collection.

Rational digit counters MUST inspect the canonical decimal component strings. They MUST exclude the numerator sign and include every decimal digit.

A counter MUST use checked arithmetic. Counter overflow MUST produce `artifact-resource-limit`.

### C-LIM-10 JSON array member limit

A single JSON array MUST contain no more than 10,000 member elements.

The count begins at zero when an array opens. Each element increments that array's count by one. Counts are independent for nested arrays.

An array with 10,000 elements is within the limit. Observation of the 10,001st element MUST fail with `artifact-resource-limit` with subject `array-members`.

### C-LIM-11 Total JSON node limit

A parsed JSON value MUST contain no more than 100,000 total nodes. A node is any JSON object, array, string, number, boolean, or null occurrence, counted once at the point it is parsed.

The total node counter is monotonic across the whole parse of one artifact and is independent of the per-container object and array member limits.

A value with 100,000 total nodes is within the limit. Observation of the 100,001st node MUST fail with `artifact-resource-limit` with subject `json-nodes`. This bounds object allocation from many small scalars inside the raw byte limit.

### C-LIM-12 Canonical integer digit limit

A canonical integer value string, in `{ "t": "int", "v": <string> }` and in every canonical integer position, MUST contain no more than 4,096 decimal digits.

An optional leading minus sign does not count as a digit. The count is the number of ASCII decimal digits after canonical integer syntax validation. This limit is separate from the C-LIM-05 string limit and from the C-LIM-08 rational component limits.

An integer value string with exactly 4,096 digits is within the limit. An integer value string with 4,097 digits MUST fail with `artifact-resource-limit`.

### C-LIM-13 Allocation and precedence requirements

A parser MUST enforce C-LIM-02, C-LIM-03, C-LIM-04, C-LIM-05, C-LIM-10, and C-LIM-11 while tokenizing. The canonical integer parser and evaluator MUST enforce C-LIM-12. The rational parser and evaluator MUST enforce C-LIM-08. A parser MUST NOT first construct an unbounded syntax tree.

Graph parsing and deterministic lowering MUST enforce C-LIM-06 before allocating storage for a 100,001st node record.

Source and input readers MUST enforce C-LIM-07 before parsing or evaluation.

The canonical integer parser and evaluator MUST enforce C-LIM-12, and the rational parser and evaluator MUST enforce C-LIM-08, before allocating or operating on an over-limit arbitrary-precision value.

When an otherwise malformed artifact crosses a countable resource boundary first, `artifact-resource-limit` has precedence. When malformed syntax prevents the bounded tokenizer from identifying the relevant structure before any limit is exceeded, the applicable parse, canonical, or schema error retains precedence.

## 25. Strict tagged-union baseline

### C-UNION-01 Schema version

The baseline MUST use JSON Schema Draft 2020-12 with one closed native receipt subschema and one closed Bridge report subschema under `oneOf`. `unevaluatedProperties` MUST be `false`.

Backs P6.

### C-UNION-02 Honest baseline behavior

The baseline MUST report structural branch membership only. Its output MUST NOT use `authenticated`, `trusted`, or issuer-origin language.

Backs P1 and P6.

### C-UNION-03 Required observations

B01 MUST validate only as Bridge. N02 MUST validate only as native-shaped. N02 MUST still fail `verify-native` as `missing-native-attestation`.

Backs P1, P6, and P9.

## 26. Replay corpus manifest

### C-RM-01 Manifest shape

The signed manifest payload MUST have tag `csk.replay-corpus-manifest/v0` and bind all of the following:

- ordered case identifiers
- canonical input hashes
- baseline rule hash
- changed rule hash
- expected case count
- workload-space hash
- workload-selection hash
- workload-split hash
- holdout-plan hash
- checked profile
- artifact schema versions

Backs P10 and P15.

### C-RM-02 Ordered comparison

Replay MUST compare case count, identifier order, and input hash at each position before executing any case.

Backs P10.

### C-RM-03 Rule binding

The baseline and changed rule bytes MUST each be read once and hashed under their published rule-hash domain. A mismatch MUST stop replay before execution.

Backs P10 and P12.

### C-RM-04 Signature

The manifest MUST be signed by the release key under the manifest payload type. The reproduction trust policy MUST explicitly authorize that payload type.

Backs P10 and P17.

### C-RM-05 Complete supplied corpus wording

Generated reports and documentation MUST describe the result as complete over the supplied corpus. They MUST NOT contain an unqualified corpus-completeness claim.

Backs P10.

## 27. Deterministic workload

### C-WL-01 Required files

The release MUST contain:

```text
artifact/workload/workload-space.json
artifact/workload/workload-candidates.json
artifact/workload/workload-selection.json
artifact/workload/workload-split.json
artifact/workload/holdout-plan.json
artifact/workload/workload-results.json
artifact/workload/workload-metrics.csv
generated/workload-results.tex
```

Backs P11, P12, and P15.

### C-WL-02 Categorical strata (amended v3)

The workload application value MUST be a positional `csk.checked-input/v0` list with this exact shape:

```text
[
  <period_code>,
  <household_code>,
  <dependents_code>,
  <residency_code>,
  <amount>
]
```

The list arity MUST be exactly five.

The category-code mappings are closed and exhaustive:

```text
period_code
  2025 = 2025
  2026 = 2026

household_code
  0 = single
  1 = couple
  2 = single-parent
  3 = multi-adult

dependents_code
  0 = none
  1 = one
  2 = two-plus

residency_code
  0 = resident
  1 = temporary
```

Every category code and `amount` MUST be an integer. Strings and symbols MUST NOT represent categories.

The admitted numeric domain of `amount` is the closed integer interval from `AMOUNT_MIN` to `AMOUNT_MAX`, where `AMOUNT_MIN = 0` and `AMOUNT_MAX = 1000000`. Every extracted threshold MUST satisfy `AMOUNT_MIN + 1 <= threshold <= AMOUNT_MAX - 1`. The six sorted thresholds partition the domain into seven intervals that are half-open on the upper side, numbered `1` through `7` exactly as C-WL-05 numbers them, so interval `i` for `i` in `1..7` is `[lower_i, upper_i)` with `lower_1 = AMOUNT_MIN`, `upper_7 = AMOUNT_MAX + 1`, and each interior boundary equal to a threshold. An `amount` equal to `AMOUNT_MAX` lies in interval `7`.

The workload space MUST use the Cartesian product:

```text
period       = 2025 | 2026
household    = single | couple | single-parent | multi-adult
dependents   = none | one | two-plus
residency    = resident | temporary
```

This produces exactly 48 strata in lexicographic order. The strata MUST be named `S01` through `S48`.

Backs P11.

### C-WL-03 Threshold extraction

The generator MUST extract numeric decision thresholds from both frozen rule parameter tables. The union MUST contain exactly six applicable thresholds per stratum. Thresholds MUST be sorted numerically and recorded with source file, JSON path, rule version, and value.

Backs P11.

### C-WL-04 Boundary candidates

For every stratum and every one of its six thresholds `t`, the generator MUST emit valid cases at `t - 1`, `t`, and `t + 1`. This produces 18 boundary candidates per stratum and 864 overall.

Backs P11.

### C-WL-05 Interior candidates (amended v8.2)

The admitted numeric domain for `amount` is the closed integer interval bounded by these named constants:

```text
AMOUNT_MIN = 0
AMOUNT_MAX = 1000000
```

Every extracted threshold MUST be at least `AMOUNT_MIN + 1` and at most `AMOUNT_MAX - 1`, so that the `t - 1`, `t`, and `t + 1` boundary candidates required by C-WL-04 stay inside the admitted domain.

The threshold set MUST additionally satisfy a spacing rule so that every one of the seven intervals contains at least one non-boundary interior value:

```text
t1 >= AMOUNT_MIN + 2
t(i+1) - t(i) >= 4   for every i in 1..5
t6 <= AMOUNT_MAX - 2
```

The generator MUST validate this spacing rule when it extracts the thresholds and MUST fail with a configuration error if any interval would have an empty interior pool. Because the admitted domain uses `AMOUNT_MIN = 0` and `AMOUNT_MAX = 1000000`, a wide compliant set exists, so this is a validation gate, not a change to the fixed candidate counts.

The six sorted thresholds `t1 < t2 < t3 < t4 < t5 < t6` divide the admitted numeric domain into seven intervals. Each threshold is the lower inclusive endpoint of the interval it opens and is not a member of the interval below it:

```text
interval 1  AMOUNT_MIN inclusive to t1 exclusive
interval 2  t1 inclusive to t2 exclusive
interval 3  t2 inclusive to t3 exclusive
interval 4  t3 inclusive to t4 exclusive
interval 5  t4 inclusive to t5 exclusive
interval 6  t5 inclusive to t6 exclusive
interval 7  t6 inclusive to AMOUNT_MAX inclusive
```

The generator MUST select one interior value per interval using the lowest hash under:

```text
SHA256(
  UTF8("vouch/workload-interior/v0") ||
  0x00 ||
  UTF8(stratum_id) ||
  0x00 ||
  UTF8(interval_id) ||
  0x00 ||
  canonical_input_bytes
)
```

In this preimage, `interval_id` is the decimal ASCII string of the 1-based interval number, exactly one of `1`, `2`, `3`, `4`, `5`, `6`, or `7`, matching the interval numbering of C-WL-02, and `stratum_id` is the canonical stratum identifier defined by C-WL-02. `canonical_input_bytes` is the exact complete bytes of the candidate's canonical `csk.checked-input/v0` file, including its single final LF, identical to the `canonical_input_bytes` of C-WL-08 and C-WL-11 for that candidate; the earlier name `canonical_candidate_bytes` is retired because it was never defined and three readings of it would select three different interior corpora. No other spelling of `interval_id` or of the candidate bytes is permitted, so the interior-selection hash is reproducible.

The candidate pool for interval `i` is exactly the integers in `[lower_i, upper_i)` under the interval definition of this condition, excluding every extracted threshold and every boundary value `t - 1`, `t`, and `t + 1` used by C-WL-04, so interior and boundary candidates never coincide. Digest comparison for the lowest interior hash is unsigned lexicographic over the raw 32 SHA-256 bytes, exactly as in C-WL-08 and C-WL-11, because a signed-byte order would yield a different interior corpus. The spacing rule above guarantees this pool is non-empty for every interval, so the generator selects exactly one interior value per interval, producing exactly seven interior candidates per stratum and exactly 336 interior candidates overall, matching C-WL-07, C-WL-08, C-WL-10, and C-WL-12. A threshold set that would leave any interval with an empty interior pool is rejected at threshold extraction and never reaches selection.

Backs P11.

### C-WL-06 Invalid candidates (amended v8.3)

Each stratum MUST produce exactly seven application-level invalid candidates. C-WL-05 fixes `AMOUNT_MIN = 0`, so the invalid base amount is frozen without changing the existing corpus quantities:

```text
INVALID_BASE_AMOUNT = 0
invalid_base_input = [period_code, household_code, dependents_code, residency_code, INVALID_BASE_AMOUNT]
```

The seven candidates are exactly these index-level transformations of `invalid_base_input`, using zero-based indices and no other change:

1. I1 removes index 3, producing arity four
2. I2 appends the integer `0`, producing arity six
3. I3 replaces index 0 with the canonical rational `1/2`
4. I4 replaces index 1 with the canonical rational `1/2`
5. I5 replaces index 2 with the integer `3`
6. I6 replaces index 3 with the integer `2`
7. I7 replaces index 4 with the integer `-1`

Each candidate MUST remain a valid checked host list under P-2. No candidate in this class may use malformed JSON, an unexpected top-level JSON field, a disallowed checked host value form, a string category, or a symbol category.

Each candidate MUST pass host input parsing and checked host-value validation. Evaluation MUST return:

```json
{
  "t": "decision",
  "v": "invalid-input"
}
```

This produces 336 invalid candidates overall.

Backs P11 and P19.

### C-WL-07 Candidate count

The candidate manifest MUST contain exactly:

```text
864 boundary valid
336 interior valid
336 application invalid
1536 total
```

Backs P11.

### C-WL-08 Selection hash (amended v8.1)

Each candidate MUST receive:

```text
SHA256(
  UTF8("vouch/workload-selection/v0") ||
  0x00 ||
  UTF8(stratum_id) ||
  0x00 ||
  UTF8(candidate_class) ||
  0x00 ||
  canonical_input_bytes
)
```

Every element of this preimage is exact, so two conforming implementations select the identical corpus:

```text
stratum_id
  the canonical stratum identifier defined by C-WL-02

candidate_class
  exactly one of the three literals "boundary", "interior", "invalid",
  lowercase ASCII, with no other spelling permitted

canonical_input_bytes
  the exact complete bytes of the candidate's canonical
  csk.checked-input/v0 file, including its single final LF,
  not the bytes of any member of it
```

Within each stratum, selection MUST take the lowest three boundary hashes, the lowest one interior hash, and the lowest one invalid hash. Digest comparison is unsigned lexicographic over the raw 32 SHA-256 bytes.

Backs P11.

### C-WL-09 No manual selection

The selection script MUST assert that every selected identifier follows the hash-ranking rule. No allowlist, denylist, manual inclusion, manual exclusion, or postselection replacement is permitted.

Backs P11.

### C-WL-10 Selected quantities

Selection MUST produce exactly:

```text
144 boundary valid
48 interior valid
48 application invalid
240 total
```

Backs P11.

### C-WL-11 Split hash (amended v8.1)

For each selected case, compute:

```text
SHA256(
  UTF8("vouch/workload-split/v0") ||
  0x00 ||
  workload_selection_sha256_bytes ||
  UTF8(stratum_id) ||
  0x00 ||
  canonical_input_bytes
)
```

Every element of this preimage is exact:

```text
workload_selection_sha256_bytes
  the RAW 32-byte SHA-256 output of that case's C-WL-08 selection hash,
  not lowercase hex, not a "sha256:" prefixed string

stratum_id
  the canonical stratum identifier defined by C-WL-02

canonical_input_bytes
  the exact complete bytes of the case's canonical csk.checked-input/v0
  file, including its single final LF, identical to the bytes used in
  the C-WL-08 preimage
```

The selected case with the lowest split hash in each stratum MUST be held out, comparing unsigned lexicographically over the raw 32 digest bytes. The remaining four MUST be development cases.

Backs P11.

### C-WL-12 Partition quantities

The exact split MUST be:

| Partition | Boundary | Interior | Invalid | Total |
|---|---:|---:|---:|---:|
| Development | 115 | 39 | 38 | 192 |
| Held out | 29 | 9 | 10 | 48 |
| Total | 144 | 48 | 48 | 240 |

Backs P11.

### C-WL-13 Stable case identifiers

Development cases sorted by split hash MUST be named `D001` through `D192`. Held-out cases sorted by split hash MUST be named `H001` through `H048`.

Backs P11 and P13.

### C-WL-14 Freeze commit

`ArtifactFreezeCommit` MUST contain the rule files, parameter tables, workload-space manifest, candidates, selection, split, and holdout plan. It MUST NOT contain held-out result files. The release descriptor `artifact_commit` MUST descend from `ArtifactFreezeCommit` without modifying any frozen file. The final source commit is recorded only in the external descriptor and publication material under C-ID-02.

Backs P11, P12, and P15.

### C-WL-15 Held-out prediction plan (amended v3)

Before held-out execution, `holdout-plan.json` MUST record the predicted affected strata selected by the frozen prediction protocol.

Held-out execution MUST record every observed flip and its stratum in `workload-results.json`. The generated report MUST compare the recorded predictions with the recorded observations.

No particular affected stratum or held-out flip count is a conformance requirement.

Backs P12.

### C-WL-23 Case outcome algebra (new v4)

Every selected workload case has one baseline execution and one changed execution. Each execution MUST resolve to exactly one member of this closed and exhaustive execution outcome algebra:

```text
CaseOutcome =
    Decision(approve | deny | review | invalid-input)
  | ProfileEscape
  | NotComparable
  | PipelineFailure
```

A `Decision` outcome occurs when the case yields a release-eligible receipt whose final agreed value is one of the four decision values required by P-9. `ProfileEscape`, `NotComparable`, and `PipelineFailure` are the exceptional outcomes. Boolean final values are not decisions and MUST NOT be recorded as `Decision`.

The workload report MUST record these counts:

```text
selected_case_count
decision_pair_count
exception_count_by_kind
excluded_from_matrix_count
```

An execution outcome is defined for each `(case_id, rule_version)`. A pair outcome is defined for each `case_id` and is a decision pair only when both executions of that case resolve to `Decision`. `decision_pair_count` is the number of cases whose baseline execution and changed execution both resolve to `Decision`. `exception_count_by_kind` counts executions, not cases, so one case may contribute an exceptional execution on one side and a `Decision` execution on the other. `excluded_from_matrix_count` is `selected_case_count` minus `decision_pair_count`. `exception_count_by_kind` records a separate count for `ProfileEscape`, `NotComparable`, and `PipelineFailure`, under the exact member names fixed by C-WL-24. Any nonzero exceptional count MUST remain visible and MUST NOT be rewritten or suppressed. No particular count is a conformance requirement.

Backs P12 and P19.

### C-WL-24 Workload result report (amended v8.2)

`artifact/workload/workload-results.json` is the owner report for every workload number the paper states. It MUST be canonical `csk.artifact-json/v0` and MUST have this shape, whose `workload_summary` member is exactly the closed object shown, so that `derive` in C-ID-10 is a total function of its exact bytes:

```text
{
  "workload_report": "vouch.scored26-workload/v0",
  "workload_summary": {
    "candidates": <uint>,
    "selected_case_count": <uint>,
    "decision_pair_count": <uint>,
    "excluded_from_matrix_count": <uint>,
    "development": <uint>,
    "held_out": <uint>,
    "decision_flips": <uint>,
    "held_out_flips": <uint>,
    "exception_count_by_kind": {
      "profile_escape_executions": <uint>,
      "not_comparable_executions": <uint>,
      "pipeline_failure_executions": <uint>
    },
    "decision_distribution_baseline": <closed four-label count object>,
    "decision_distribution_changed": <closed four-label count object>,
    "transition_matrix": <closed 4 by 4 count matrix>
  }
}
```

The report MUST additionally carry these required sibling members, which hold the records the other workload conditions require and which `derive` never reads:

```text
"held_out_flip_records": [
  { "case_id": <held-out case identifier>, "stratum_id": <canonical stratum identifier>,
    "baseline": <one of "approve","deny","review","invalid-input">,
    "changed":  <one of "approve","deny","review","invalid-input"> }
],
"development_flips": <uint>,
"coverage": {
  "covered":   [ <stable identifier> ],
  "uncovered": [ <stable identifier> ]
},
"smoke_suite": {
  "cases":  <uint>,
  "passed": <uint>,
  "failed": <uint>
}
```

`held_out_flip_records` satisfies C-WL-15, `development_flips` with the summary's `held_out_flips` satisfies C-WL-19, `coverage` satisfies C-WL-21, and `smoke_suite` satisfies C-WL-22. `held_out_flip_records` MUST be sorted by `case_id` in UTF-8 byte order with no duplicate `case_id`, and both `coverage` arrays MUST be sorted in UTF-8 byte order with no duplicate identifier, so any table or appendix the paper draws from them is deterministic. A record appears only when `baseline` differs from `changed`.

`derive` reads only `workload_summary`, so it stays a total function while the report remains the single owner file for every workload number the paper states. The member names are exactly those of the `workload` object in the clean-run report Q of C-FINAL-01, and `derive(exact artifact/workload/workload-results.json bytes)` for `Q.workload` is the `workload_summary` object taken verbatim. `profile_escape_executions`, `not_comparable_executions`, and `pipeline_failure_executions` are the exact recorded member names for the `ProfileEscape`, `NotComparable`, and `PipelineFailure` execution kinds of C-WL-23; no other spelling is permitted. `candidates` is the candidate total of C-WL-07, and `development` and `held_out` are the partition totals of C-WL-12, recorded here so that the workload report alone is a sufficient preimage for the workload half of Q. The decision-distribution objects and the transition matrix satisfy C-WL-16 and C-WL-18. No particular count is a conformance requirement.

Backs P11, P12, and P19.

### C-WL-16 Baseline distribution (amended v4)

The baseline result report MUST record counts for this closed and exhaustive decision-label enum:

```text
approve
deny
review
invalid-input
```

Each label MUST map one-to-one to the canonical receipt decision value with the identical `v` member. The counts MUST be derived from the generated baseline receipts of cases whose baseline outcome is `Decision`. Their sum MUST equal the number of baseline `Decision` outcomes and MUST NOT include exceptional cases recorded under C-WL-23.

No particular distribution is a conformance requirement.

Backs P12.

### C-WL-17 Changed distribution (amended v4)

The changed result report MUST record counts for the closed decision-label enum in C-WL-16.

Each count MUST be derived from the generated changed-rule receipts of cases whose changed outcome is `Decision`. Their sum MUST equal the number of changed `Decision` outcomes and MUST NOT include exceptional cases recorded under C-WL-23.

No particular distribution is a conformance requirement.

Backs P12.

### C-WL-18 Transition matrix (amended v4)

The workload report MUST contain a 4 by 4 baseline-to-changed transition matrix.

Rows and columns MUST use this closed order:

```text
approve
deny
review
invalid-input
```

The matrix admits only decision pairs. A selected case contributes to exactly one cell when and only when both its baseline receipt and its changed receipt resolve to `Decision` under C-WL-23. A case with any exceptional outcome on either side is excluded from the matrix and counted in `excluded_from_matrix_count`. The number of cases contributing to the matrix MUST equal `decision_pair_count`.

Each cell MUST contain the generated count whose baseline receipt has the row decision value and whose changed receipt has the column decision value. The sum of off-diagonal cells MUST equal the recorded decision-flip count.

No particular cell value or flip count is a conformance requirement.

Backs P12.

### C-WL-19 Partition flips (amended v3)

The workload report MUST record decision-flip counts separately for the development and held-out partitions. Their sum MUST equal the off-diagonal total required by C-WL-18.

No particular partition count is a conformance requirement.

Backs P12.

### C-WL-20 Execution outcomes (amended v4)

Across both rule versions and all selected cases, the generated report MUST record the `CaseOutcome` tally required by C-WL-23, which covers profile escapes, not-comparable receipts, pipeline failures, and the decision labels exercised.

Every successful decision-producing execution MUST end in exactly one of the four decision values required by P-9. Boolean final values MUST NOT be counted as decisions.

No particular recorded outcome count is a conformance requirement. Any nonzero exceptional count MUST remain visible and MUST NOT be rewritten or suppressed.

Backs P12 and P19.

### C-WL-21 Coverage (amended v3)

Coverage instrumentation MUST record:

```text
source branches covered
source branches total
graph nodes covered
graph nodes total
```

A branch or node counts as covered only when its stable instrumentation identifier is observed in at least one selected baseline or changed execution.

The generated report MUST list the covered and uncovered stable identifiers. No particular coverage count or percentage is a conformance requirement.

Backs P12 and P19.

### C-WL-22 Smoke suite (amended v3)

The retained 12-case smoke suite MUST record its observed decision flips. Its report, documentation, and generated tables MUST identify it as a smoke suite and MUST NOT use it as the principal workload result.

No particular smoke-suite flip count is a conformance requirement.

Backs P12.

## 28. Mutation study

### C-MUT-01 Required files

The release MUST contain:

```text
artifact/mutation/mutation-manifest.json
artifact/mutation/mutation-results.json
artifact/mutation/mutation-results.csv
generated/mutation-results.tex
```

Backs P13 and P15.

### C-MUT-02 Single-site rule

Each mutant build MUST enable exactly one mutation identifier. Its patch MUST change one registered semantic site. Comparison code, canonical writers, verifiers, workload files, and test expectations MUST remain byte-identical to the unmutated release.

Backs P13.

### C-MUT-03 Manifest fields (amended v3)

Every mutant row MUST record:

```text
mutant_id
class
source_file
source_location
component
one_line_transformation
activation_case_ids
baseline_binary_sha256
mutated_binary_sha256
development_case_outcomes
heldout_case_outcomes
```

`development_case_outcomes` and `heldout_case_outcomes` are each a closed count object with the members `disagreement_cases`, `common_mode_cases`, `pipeline_failure_cases`, `infrastructure_failure_cases`, and `survivor_cases`, because one mutant can produce a different outcome on each activation case. A single per-mutant outcome label is not recorded.

Each mutated binary digest MUST differ from the baseline digest and from every other mutant digest.

The activation and outcome fields MUST contain generated observations. They MUST NOT contain prescribed empirical results.

Backs P13 and P15.

### C-MUT-04 Activation definition

A mutant is activated only when at least one transcript or projected semantic result differs from the unmutated build on the same input. A changed build digest alone is not activation.

Backs P13.

### C-MUT-05 Detection definition

A differential detection requires at least one activated case whose receipt has `comparison.status = "disagree"`. Diagnostic count, process failure, build failure, and receipt-schema failure do not count as differential detection.

Backs P13.

### C-MUT-06 Other outcome definitions (amended v3)

A pipeline failure is an activated case that cannot produce a differential receipt because failure occurred before the graph existed.

An evaluation infrastructure failure produces a receipt with `comparison.status = "not-comparable"` as required by A-3. It is not a pipeline failure and does not count as differential detection.

A common-mode miss changes both paths identically and retains `comparison.status = "agree"`.

A survivor is activated but has no disagreement, pipeline failure, evaluation infrastructure failure, or recognized common-mode change.

These outcome categories are closed and exhaustive for an activated mutant.

Backs P13.

### C-MUT-07 Mutant registry (amended v3)

The registry is closed and contains exactly these twelve single-site mutants:

| ID | Class | Path | Mutation |
|---|---|---|---|
| M01 | Lowering | Meaning Environment | Lower `and` using `or` |
| M02 | Lowering | Meaning Environment | Reverse subtraction arguments during lowering |
| M03 | Graph evaluator | Meaning Environment | Swap true and false graph successors of `if` |
| M04 | Graph evaluator | Meaning Environment | Treat graph `<=` as `<` |
| M05 | Source evaluator | Reference | Swap source evaluator branches of `if` |
| M06 | Source evaluator | Reference | Reverse source evaluator subtraction operands |
| M07 | Shared numeric | Shared | Treat shared inclusive comparison as strict on equality |
| M08 | Shared numeric | Shared | Normalize a negative rational with the wrong sign |
| M09 | Path serialization | Meaning Environment | Replace the final graph-side value event value with a different canonical value of the same schema |
| M10 | Path serialization | Reference | Replace U+000A in a string value with U+005C followed by U+006E before the shared canonical writer is called |
| M11 | Shared reader and normalizer | Shared | Reverse subtraction operands in the shared normalizer |
| M12 | Shared reader and normalizer | Shared | Decode `#f` as `#t` in the shared reader |

M09 MUST preserve transcript completeness and receipt schema validity.

M10 MUST be a canonical-value mutation applied on the reference side before calling the unchanged shared canonical writer. The input value MUST contain U+000A. The replacement MUST produce a string containing the two code points U+005C and U+006E at that position. The resulting receipt MUST remain schema-valid and MUST contain a genuine value disagreement.

The mutation study is split into two suites that MUST NOT be conflated.

The conformance activation suite is a set of per-operator unit witnesses. Each witness proves only that its operator changes the intended code. M01 through M06, M09, and M10 each have a unit witness that produces a genuine path disagreement. M07, M08, M11, and M12 each have a unit witness where both paths change identically and comparison remains `agree`. These unit witnesses are correctness checks on the mutation operators. They MUST NOT be counted as empirical detection results and MUST be reported separately from the evaluation suite of C-MUT-08.

The frozen-workload mutation evaluation runs only the frozen development and held-out workload of C-WL. It observes and records the outcome of each activated mutant on each workload case. No per-mutant global outcome is prescribed and no aggregate detection result is required. One mutant MAY be a disagreement on one case, a common-mode change on another, and an infrastructure failure on a third. The report MUST record case-level outcome counts rather than a single per-mutant verdict.

All activation identifiers and outcomes MUST be recorded from execution. No named activation case or aggregate result is prescribed.

Backs P13.

### C-MUT-08 Aggregate results (amended v8.2)

The aggregate report MUST contain one row for each closed class and one total row:

```text
Lowering
Graph evaluator
Source evaluator
Shared numeric
Path serialization
Shared reader and normalizer
Total
```

Each row MUST record two separate tallies that MUST NOT be summed together, because one mutant can produce different outcomes on different cases.

Mutant-level counts, one per mutant:

```text
seeded
built
activated_any
detected_any
```

Case-level counts, summed over activation cases:

```text
disagreement_cases
common_mode_cases
pipeline_failure_cases
infrastructure_failure_cases
survivor_cases
```

The values MUST be computed from generated mutant results. The total seeded count MUST equal the registry size. Case-level counts MUST NOT be divided by the mutant-level seeded count.

`artifact/mutation/mutation-results.json` is the owner report for every mutation number the paper states. It MUST be canonical `csk.artifact-json/v0` and MUST have this shape, whose `mutation_summary` member is exactly the closed object shown, so that `derive` in C-ID-10 is a total function of its exact bytes:

```text
{
  "mutation_report": "vouch.scored26-mutation/v0",
  "mutation_summary": {
    "mutant_level": {
      "seeded": <uint>,
      "built": <uint>,
      "activated_any": <uint>,
      "detected_any": <uint>,
      "detection_rate": <one-decimal percentage string>
    },
    "case_level": {
      "disagreement_cases": <uint>,
      "common_mode_cases": <uint>,
      "pipeline_failure_cases": <uint>,
      "infrastructure_failure_cases": <uint>,
      "survivor_cases": <uint>
    }
  },
  "rows": [
    { "class": <one of the seven closed row labels above>, "mutant_level": <the four mutant-level counts>, "case_level": <the five case-level counts> }
  ],
  "partitions": {
    "development": {
      "activated": <uint>, "detected": <uint>, "pipeline_failures": <uint>,
      "infrastructure_failures": <uint>, "common_mode": <uint>, "survivors": <uint>
    },
    "held_out": {
      "activated": <uint>, "detected": <uint>, "pipeline_failures": <uint>,
      "infrastructure_failures": <uint>, "common_mode": <uint>, "survivors": <uint>
    },
    "mutants_without_held_out_activation": [ <mutant identifier> ]
  }
}
```

The `rows` and `partitions` members hold the records C-MUT-08 and C-MUT-09 require and which `derive` never reads. `partitions` carries exactly the six counts C-MUT-09 names, under those exact member names, for each partition, and `mutants_without_held_out_activation` MUST be sorted in UTF-8 byte order with no duplicate identifier, so any table or appendix the paper draws from them is deterministic. `derive` reads only `mutation_summary`, so it stays a total function while the report remains the single owner file for every mutation number the paper states.

The member names are exactly those of the `mutation` object in the clean-run report Q of C-FINAL-01, and `derive(exact artifact/mutation/mutation-results.json bytes)` for `Q.mutation` is the `mutation_summary` object taken verbatim. The report MUST record `detection_rate` as the decimal string of `100 * detected_any / seeded`, rounded half-up to exactly one fractional digit, and as `"0.0"` when `seeded` is zero. It is a percentage, not a ratio, and it is the exact value copied into `Q.mutation.mutant_level.detection_rate`, so the derivation is total and unambiguous.

No particular detected count, miss count, or detection rate is a conformance requirement.

Backs P13.

### C-MUT-09 Partition results (amended v3)

The mutation report MUST record activation, detection, pipeline-failure, infrastructure-failure, common-mode, and survivor counts separately for the development and held-out partitions.

It MUST identify every mutant without held-out activation. No particular held-out activation or detection result is a conformance requirement.

Backs P13.

### C-MUT-10 No release authentication

Mutation mode MUST disable release-key access. Mutant receipts MUST be stored as unsigned canonical payloads with experiment metadata. No mutant DSSE envelope may verify under the release key identified by the descriptor `key_id`.

Backs P14 and P17.

## 29. Performance measurements

### C-PERF-01 Runtime environment

The external release descriptor MUST pin at least:

```text
Rust                 1.85.1
Cargo                1.85.1
target               x86_64-unknown-linux-gnu
Node.js              22.14.0
npm                  10.9.2
TypeScript           5.8.2
ed25519-dalek        2.1.1
sha2                 0.10.8
base64               0.22.1
serde                1.0.219
serde_json           1.0.140
Ajv                  8.17.1
glibc                2.39
```

Every transitive dependency MUST be pinned by committed lockfiles and the vendored or offline dependency store.

Backs P15 and P16.

### C-PERF-02 Measurement protocol

Performance collection MUST use five complete warm-up runs followed by 30 measured runs. No warm-up observation may enter reported statistics.

Backs P16.

### C-PERF-03 Percentiles

Median and p95 MUST use the nearest-rank method over sorted observations. Maximum MUST be the largest observed value. Timing MUST use a monotonic clock.

Backs P16.

### C-PERF-04 Receipt-size population (amended v4)

Envelope size MUST be measured over every successfully issued release envelope, one baseline receipt and one changed receipt per selected case whose outcome on that side is `Decision` under C-WL-23. The population size `n` is the observed issued-envelope count, not a fixed number. A case with an exceptional outcome on a side issues no envelope for that side, so no fixed 480 count is required. The report MUST list `n` and the exact identifiers of every case excluded from a side.

Backs P16.

### C-PERF-05 Recorded measurements (amended v8.1)

The performance report MUST be written to exactly this path and MUST be canonical `csk.artifact-json/v0`, so that `Q.performance_report_sha256` and `R.performance_observations` have one exact preimage and one exact derivation:

```text
artifact/performance/performance-results.json
```

It MUST have this shape, whose `measurements` member is exactly the closed array shown, and the report MAY carry additional members that `derive` never reads:

```text
{
  "performance_report": "vouch.scored26-performance/v0",
  "measurements": [
    {
      "metric": <one of the four metric literals below>,
      "unit": <the unit literal registered for that metric below>,
      "statistic": <one of "median", "p95", "maximum">,
      "value": <uint>,
      "population": <uint>,
      "excluded_ids": [ { "case": <case identifier>, "side": "baseline" | "changed" } ]
    }
  ]
}
```

The metric and unit literals are closed and exhaustive:

```text
envelope_bytes                    unit "byte"
native_verification_latency       unit "microsecond"
selected_corpus_replay_latency    unit "microsecond"
peak_resident_memory              unit "byte"
```

The array MUST contain exactly one entry for each metric-and-statistic pair, twelve entries in all, sorted by `metric` then `statistic` in UTF-8 byte order. `population` is the count of observations the statistic was computed over and `excluded_ids` is the exact set of excluded `(case, side)` pairs, sorted by `case` and then `side` in UTF-8 byte order, which is what C-PERF-04 means by the identifiers of every case excluded from a side, so `derive(exact performance-results.json bytes)` is a total function. Every value MUST be derived from the observations collected under C-PERF-02 through C-PERF-04.

`R.performance_observations` is derived from this report by taking, for each entry, its `metric`, `statistic`, `unit`, and `value`, preserving the report's order. It therefore carries the same twelve entries, and `statistic` is what makes each entry uniquely keyed. No particular size, latency, or memory value is a conformance requirement.

Backs P16.

### C-PERF-06 Clean-run time (amended v8.1)

The clean-run report Q MUST record the wall-clock time for the exact clean-room sequence required by C-REP-04, in the field `clean_run_runtime_seconds`.

The time MUST be measured by the trusted outer clean-room driver of C-REP-04 using a single monotonic timer, because the inner `npm run scored26:reproduce` process starts only after archive verification, checkout, offline dependency installation, and the release build, and so cannot measure those earlier phases itself. The time MUST exclude archive download time. It MUST include exactly the phase-1 work: archive verification, bundle checkout, offline dependency installation, release build, fixtures, workload execution, mutation execution, and release scans. It MUST NOT include the LaTeX regeneration or the paper-claim comparison, which are phase 3; it MUST NOT include the finalizer's C-ID-10 derivation checks, which are phase 2; and it MUST NOT include the outer driver's construction of Q, which the mandatory driver order of C-REP-04 places after the timer stops.

`clean_run_runtime_seconds` is first recorded in Q and copied unchanged into the C-ID-10 reproduction observation R. It is never an exact-byte reproduction target. The deterministic release descriptor MUST NOT bind it. No particular duration is a conformance requirement.

Backs P15 and P16.

## 30. Reproducibility and clean-room execution

### C-REP-01 Required repository pins (amended v4)

The source commit MUST contain:

```text
rust-toolchain.toml
Cargo.lock
.cargo/config.toml
vendor/
package.json
package-lock.json
.nvmrc
artifact/vendor-manifest.json
artifact/runtime-versions.json
```

The release layer MUST additionally provide the closed descriptor, build container digest, toolchain pins, dependency version manifest digests, and deterministic build parameters required by C-ID-06.

The source commit MUST NOT contain its own commit identifier, the descriptor digest, the archive digest, or the engine digest.

Backs P15.

### C-REP-02 Offline Rust build (amended v4)

`.cargo/config.toml` MUST replace crates.io with the committed `vendor/` directory. `cargo build --frozen --offline --release` MUST complete without network access and without changing `Cargo.lock`.

`RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` MUST be absent or empty for a release build. Their observed empty or absent states MUST be recorded in the external release descriptor.

The Rust build MUST run in the container identified by `build_image_sha256` and under the deterministic build parameters required by C-ID-06.

Backs P15.

### C-REP-03 Offline npm installation (amended v4)

The archive MUST contain `vendor/npm-cache`. The command:

```text
npm ci --offline --cache ../vendor/npm-cache
```

MUST complete without network access and without changing `package-lock.json`.

The Node, npm, TypeScript, dependency manifest, build container, locale, and build path pins required by C-ID-06 MUST govern the installation and build.

Backs P15.

### C-REP-04 Exact clean-room sequence (amended v8.5.1)

The trusted bootstrap inputs MUST be exactly:

```text
a trusted bootstrap verifier
an out-of-band consumer trust policy
external release-descriptor.json
external release-descriptor.dsse.json
```

The archive and its adjacent checksum are untrusted inputs until authenticated through the descriptor.

At bootstrap entry, before any validation, the trusted outer driver MUST open and read the out-of-band consumer trust policy, `release-descriptor.json`, and `release-descriptor.dsse.json` each EXACTLY ONCE into separate private immutable byte buffers. Every policy check, descriptor check, digest lookup, inner-runner input, comparison construction, and Q construction MUST consume only the authenticated values parsed from those entry buffers. Reopening any of those three paths after entry is FORBIDDEN. In particular, the inner runner, the construction of `exact-reproduction-comparisons.json`, and the construction of Q consume only the authenticated D snapshot and never a reopened D path.

At the same entry boundary, the driver MUST open the archive path EXACTLY ONCE and MUST reject it unless that open obtains a regular, non-symlink file. The driver MUST retain that source descriptor only to perform one sequential source read into a private pathless snapshot. The snapshot MUST be a `memfd`, an `O_TMPFILE`, or a temporary file in a verifier-only trusted directory that is unpredictably named and unlinked immediately on creation. The snapshot descriptor MUST NOT be exposed to archive-supplied code, an external caller, or any component outside the trusted bootstrap extraction boundary. After successful digest verification it MAY be transferred or duplicated only to the trusted extractor.

The archive snapshot is a read-once immutable object in the same sense as the policy, D, and envelope entry buffers. During the source archive's single read, the driver MUST feed every chunk to SHA-256 AND write that same chunk in full to the snapshot descriptor, retrying or failing on short writes so that only the complete byte sequence can become the snapshot. After the source reaches EOF, the driver MUST flush and rewind the snapshot and, where the platform provides them, apply write, grow, and shrink seals before making the digest decision. No validation, digest lookup, extraction, or later bootstrap operation may consume archive bytes from the source descriptor or from any path. If the computed digest does not equal authenticated `D.archive_sha256`, the driver MUST discard the snapshot and extraction is FORBIDDEN. If it equals, every later archive-byte consumer MUST use ONLY the snapshot's retained descriptor. The source descriptor MUST never be rewound or used for extraction.

The private snapshot is the one immutable archive-byte object from chunk capture through digest decision and extraction. Advisory locks and mtime, ctime, or size rechecks are insufficient. A concurrent rename, replacement, symlink substitution, truncate, `pwrite`, or `mmap` write against the archive argument path or the source inode cannot change the bytes extracted from the completed private snapshot. Bootstrap policy, descriptor, or envelope authentication failures remain bootstrap verification failures. Archive file-type, source-descriptor, snapshot creation, snapshot write, flush, rewind, seal, read, digest, or extraction-integrity failures remain archive integrity failures; no additional bootstrap error class is introduced.

Before executing any archive-supplied code, the bootstrap verifier MUST perform exactly this order:

```text
1  consumer trust policy canonical gate and closed schema
2  descriptor DSSE envelope canonical gate and closed schema
3  descriptor keyid lookup and key selection in the consumer trust policy
4  selected-key payload-type authorization for the descriptor payload type
5  descriptor DSSE signature verification under the selected key
6  descriptor payload canonical gate and closed schema, require the decoded envelope
   payload bytes to equal the standalone release-descriptor.json bytes, then require
   D.key_id == descriptor-envelope.signatures[0].keyid == selected policy key.key_id
7  read the retained source archive descriptor once, feeding every chunk to SHA-256 and
   writing that same chunk in full into the private pathless snapshot; flush and rewind the
   snapshot, apply write/grow/shrink seals where available, and verify that sha256 equals
   the authenticated descriptor archive_sha256
8  only then extract through the retained SNAPSHOT descriptor, never the source descriptor
   and never any path
9  run npm and cargo inside a sandbox
```

The descriptor signing key is never taken from a descriptor-adjacent field. It is selected only from the out-of-band consumer trust policy, exactly as native verification selects a key under C-VN-06.

Failure at any step before step 8 MUST stop processing before archive extraction. A failure of the three-way key identity equality in step 6 is a bootstrap verification failure. No archive path may be read as executable code before step 8. Neither the archive argument path nor any snapshot or staging path may be opened or reopened at or after step 7, and the source descriptor MUST NOT supply extraction bytes.

After step 7 succeeds, the remaining clean-room sequence MUST begin by extracting the retained object and be equivalent to:

```sh
# S is the retained private pathless snapshot descriptor, digest-verified and at byte zero.
tar --zstd -xf - <&S
cd vouch-scored26-artifact
git clone release/vouch-scored26.bundle work
cd work
git checkout --detach "$(cat ../release/COMMIT)"
npm ci --offline --cache ../vendor/npm-cache
cargo build --frozen --offline --release
npm run scored26:reproduce
```

`S` denotes the retained descriptor of the private pathless snapshot, not the descriptor returned by the archive's single entry open. The redirection supplies digest-verified snapshot bytes, not bytes from the source descriptor and not bytes from a filesystem path. A library equivalent MUST likewise consume only the retained snapshot descriptor or its stream. No verifier or extractor operation may resolve or reopen a filesystem pathname for the snapshot.

The sandbox network MUST be disabled before `npm ci` and remain disabled through completion. The sandbox MUST use the build image and deterministic build parameters authenticated through C-ID-06.

The adjacent `vouch-scored26-artifact.tar.zst.sha256` file MAY be checked after descriptor authentication as an internal consistency value. It MUST NOT gate extraction and MUST NOT be treated as an independent authenticator.

`npm run scored26:reproduce` executes archive-supplied code. It MUST NOT be described or used as the bootstrap verifier.

The whole sequence above is driven by a trusted outer clean-room driver that is not archive-supplied code. Because the inner `npm run scored26:reproduce` process starts only after archive verification, extraction, checkout, `npm ci`, and `cargo build`, it cannot measure those earlier phases, so the trusted outer driver owns the single monotonic timer for the full clean-run time of C-PERF-06. The outer driver order MUST be:

```text
start monotonic timer
consume the entry policy, D, and D-envelope buffers, authenticate D, enforce the three-way key identity equality, and select its key from the out-of-band policy
read the retained source archive descriptor once while hashing each chunk and writing that same chunk in full to the private pathless snapshot
flush and rewind the snapshot, apply write/grow/shrink seals where available, and authenticate its captured bytes against the authenticated D snapshot's archive_sha256
extract only through the retained snapshot descriptor, never the source descriptor or any filesystem path
checkout the pinned commit
npm ci offline
cargo build offline release
invoke the inner reproduction runner npm run scored26:reproduce
stop monotonic timer
read each emitted owner report and each regenerated exact-reproduction result exactly once into private immutable buffers
hash each regenerated exact-reproduction result buffer itself
construct exact-reproduction-comparisons.json in a private immutable buffer
fail the phase-1 gate if any constructed comparison row has matched == false; publish no passing Q
compute the full-file digests of all five phase-1 reports and derive each owner-report Q summary from its corresponding read-once immutable buffer
publish the comparison buffer outside the worktree at <clean-room-root>/external/exact-reproduction-comparisons.json
construct and publish Q from those same buffers and digests outside the worktree at <clean-room-root>/external/clean-run-report.json
```

The timer stops immediately after the inner runner exits, after its final worktree-clean check. Comparison construction, the explicit all-rows-matched phase-1 gate, phase-1 output hashing and summary derivation, and Q construction happen AFTER the timer stops and are not part of `clean_run_runtime_seconds`; the timed window is the clean-room execution through the inner runner, while the external comparison and Q are trusted post-run packaging. If any comparison row has `matched == false`, the trusted outer driver MUST fail at that gate and MUST NOT publish Q. The fixed exit code for that failure is defined only by C-FINAL-01. The later finalizer check `rd-comparisons-matched` remains defence in depth. The outer driver MUST NOT reopen an owner-report path or a regenerated-result path after capturing its buffer. For each owner report, its summary, full-file digest, and Q member MUST be computed from the same immutable buffer. The canonical comparison bytes are likewise retained as one immutable buffer from construction through digest computation and publication.

The outer driver is the ONLY author of `<clean-room-root>/external/exact-reproduction-comparisons.json`. The inner runner never writes, stages, or supplies asserted comparison rows. The comparison file MUST be canonical `csk.artifact-json/v0`, sorted by `path` in UTF-8 byte order, and have this closed schema, whose `path` set equals the `exact_reproduction_results` path set of authenticated D:

```text
{
  "exact_reproduction_comparisons": "vouch.scored26-reproduction-comparisons/v0",
  "comparisons": [
    {
      "path": <normalized relative path>,
      "expected_sha256": <"sha256:" plus 64 lowercase hex digits>,
      "observed_sha256": <"sha256:" plus 64 lowercase hex digits>,
      "matched": <boolean>
    }
  ]
}
```

Each row is a checkable fact and MUST satisfy exactly:

```text
c.expected_sha256 == the sha256 D.exact_reproduction_results records for c.path
c.observed_sha256 == the ordinary SHA-256 of the immutable regenerated-file buffer for c.path
c.matched         == (c.expected_sha256 == c.observed_sha256)
```

`derive(exact <clean-room-root>/external/exact-reproduction-comparisons.json bytes)` for `R.reproduced_result_comparisons` takes each entry's `path` and `matched` in file order. The outer driver MUST NOT copy a comparison digest or matched value asserted by archive-supplied code.

The `<clean-room-root>` is the directory in which the archive file and its adjacent checksum sit and in which `tar` is run. It is the parent of the extracted `vouch-scored26-artifact/` directory and therefore the grandparent of the `work` checkout, and it is NOT resolved relative to the inner runner's working directory, which is `work`. Resolving `external/` relative to the checkout would place external reports inside the worktree and break the worktree-clean check. The outer driver MUST write both the comparison file and Q to staging files in that same `external/` directory and publish each by a single rename on the same filesystem, so neither is observed partially written. Neither publication mutates the checkout, so the worktree-clean step of C-REP-05, its last step, remains true. The driver does not construct, read, or verify R, P, or the paper; those are release lifecycle phases 2 and 3.

Backs P15 and P16.

### C-REP-05 Reproduction contents (amended v8.3)

This condition defines the phase-1 inner runner `npm run scored26:reproduce`. It is the full fixture gate of C-FIX-08 and it is NOT the release final gate; the release final gate is the phase-3 publication-check of C-REP-08. The current partial implementation is gated by `npm run scored26:core-conformance` over built-scope rows only, as required by C-FIX-08.

After C-REP-04 authenticates and extracts the archive, `npm run scored26:reproduce` MUST:

1. verify the internal path manifest
2. verify internal consistency with the authenticated external release descriptor
3. verify toolchain, dependency, target, build container, and deterministic build parameter pins
4. build the Rust and JavaScript implementations
5. regenerate canonical unsigned native payload bytes from the pinned source and input corpus
6. require byte equality between regenerated canonical payloads and stored decoded payloads
7. verify every stored release signature of the deterministic artifacts, which are the receipts, the replay manifests, and the descriptor, without regenerating it, and never the reproduction observation, which does not exist in phase 1
8. verify the signed replay manifest
9. run every built-scope and, for a final release, every design-target fixture declared by the generated fixture manifest, per the scope rule of C-FIX-08
10. require every fixture result in the applicable scope to match its manifest expectation
11. run the strict-union baseline
12. run the vulnerable and repaired consumers
13. generate and execute the selected workload
14. build and run all twelve mutants
15. collect measurements under C-PERF-02 through C-PERF-05 and emit the regenerated deterministic artifacts plus the fixture, workload, mutation, and performance owner reports at their owner-condition paths
16. scan for private keys and personal data
17. fail if the worktree changes

`npm run scored26:reproduce` is release lifecycle phase 1, the clean-room run. It runs the full experiment and emits only regenerated artifacts and owner reports. It MUST NOT write, stage, or author `exact-reproduction-comparisons.json` at any path. It MUST NOT read, render, or verify the reproduction observation R, the publication record P, or the final paper, and it MUST NOT compare paper claims. Regenerating the LaTeX inputs, comparing paper empirical claims, and verifying the stored observation signature are release lifecycle phase 3 and belong to the publication-check command of C-REP-08, not to this phase. Removing them from phase 1 is what breaks the former Q-to-observation generation cycle.

The external comparison artifact of C-REP-04 is what makes the byte-for-byte reproduction of C-REP-06 a recorded, digest-pinned fact rather than a transient check, so the phase-2 finalizer can verify it instead of asserting it. The trusted clean-room driver of C-REP-04, not this inner runner, measures the wall-clock time, constructs that comparison artifact, and constructs the clean-run report Q of C-FINAL-01 at fixed external paths from read-once immutable buffers, so both land outside the worktree and `worktree_clean` stays satisfiable.

The runner MUST use the generated fixture manifest count. It MUST NOT contain a separately maintained fixed fixture count.

The runner verifies internal consistency after extraction. It is not the authority that permits extraction.

Backs P1 through P19.

### C-REP-06 Release signature reproduction boundary (amended v8)

The clean-room command MUST reproduce exact canonical payload bytes for the deterministic artifacts, which are the receipts and the replay manifests, and MUST verify their stored release signatures. The external release descriptor is deterministic and MUST be regenerated to byte equality along with the other deterministic artifacts. Its `exact_reproduction_results` entries MUST each equal the digest of their reproduced result. The non-deterministic values are the clean-run runtime, the performance measurements, and the re-measured observational digests. `clean_run_runtime_seconds` is first recorded in the clean-run report Q of C-FINAL-01 and is copied unchanged into the C-ID-10 reproduction observation R. It is never an exact-byte reproduction target, and neither are the performance measurements or observational digests. The clean-room run of phase 1 MUST verify the stored descriptor signature for the deterministic artifacts. It MUST NOT verify a reproduction observation, because R does not exist during the first clean-room run; R is created afterward in phase 2, and its signature is verified in phase 3 by the publication-check command of C-REP-08. This is what removes the former requirement that Q depend on a stored observation signature.

Exact-payload reproduction MUST use the authenticated `build_image_sha256`, toolchain pins, dependency version manifest digests, and deterministic build parameters required by C-ID-06.

The clean-room command MUST NOT regenerate release signatures. An ephemeral key may be used to exercise `issue-native`. Every ephemeral envelope MUST be discarded and MUST not verify under the release policy.

Backs P2, P3, P15, and P17.

### C-REP-07 File manifest (amended v4)

`artifact/release-manifest.json` MUST list every distributed archive path with:

```text
path
byte_length
sha256
generating_command
artifact_class
expected_result
```

Paths MUST be sorted by UTF-8 byte order. The manifest MUST not list itself, the external descriptor, the descriptor envelope, the external publication record, or the adjacent archive checksum.

The release manifest is a release-layer artifact. It MUST NOT be embedded in the release executable. Its executable entry MUST carry the same engine digest as C-ID-04.

Backs P15.

### C-REP-08 Paper extraction check (amended v8.4)

This is the publication-check command, release lifecycle phase 3. It runs only after phase 1 has produced Q and phase 2 has produced the signed R and the publication record P. It MUST build the paper as a Layer-4 derived publication artifact and extract its text. Its exact interface is:

```text
npm run scored26:publication-check -- \
  --descriptor <path to release-descriptor.json> \
  --descriptor-envelope <path to release-descriptor.dsse.json> \
  --trust-policy <path to the out-of-band consumer trust policy> \
  --clean-run-report <path to the external clean-run-report.json> \
  --observation <path to reproduction-observation.json> \
  --observation-envelope <path to reproduction-observation.dsse.json> \
  --publication-record <path to release-publication.json> \
  --fixture-report <path to artifact/results/fixture-results.json> \
  --workload-report <path to artifact/workload/workload-results.json> \
  --mutation-report <path to artifact/mutation/mutation-results.json> \
  --performance-report <path to artifact/performance/performance-results.json> \
  --reproduction-comparisons <clean-room-root>/external/exact-reproduction-comparisons.json \
  --paper-source-root <path to the fixed paper-source checkout> \
  --out-dir <path>
```

At command entry, before any verification, it MUST open and read each file input path EXACTLY ONCE into a private immutable byte buffer, exactly as the finalizer does. It MUST also capture the fixed `--paper-source-root` entry state exactly once into a private immutable provenance snapshot: HEAD, the HEAD git-tree manifest, index state, worktree state, and a sorted tracked-worktree manifest, with each manifest containing each tracked path, git mode, and ordinary SHA-256 content digest. Every tracked paper-source file used to compute the worktree manifest or render the paper MUST be opened and read exactly once into the snapshot, and rendering MUST consume those captured buffers. The snapshot records either the captured value or the capture failure for each checkable component, so a missing, unreadable, or malformed paper-source root is deferred to the corresponding provenance check and is never ambiguously reported as a render failure or as a file-input `input-output-failure`. Hash verification, DSSE verification, empirical-value extraction, LaTeX generation, the paper-claim comparison, and the generation of S MUST consume ONLY the entry buffers and the provenance snapshot. Reopening any file input or paper-source path after entry is FORBIDDEN. The rule MUST be observable: the fixture harness supplies a counting file provider that records exactly one open and one read per declared file input and tracked paper-source path for the whole run, and fixture L09 asserts it. The LaTeX generator and the claim comparator MUST be given the verified frozen parsed values, or a sealed staging tree materialized from the buffers, and MUST NOT be given input paths. Without this rule an owner report or paper source could pass its check and then be replaced before rendering, so the signed release would authenticate one set of bytes while the paper printed another.

It MUST publish `publication-report.json`, which is S, into `--out-dir`, written to a staging directory and published by a single rename on the same filesystem, and it MUST use this closed exit-code table:

| Exit | Meaning |
|---:|---|
| 0 | The chain verified, the paper rendered, the claims matched, and the language scan passed |
| 1 | A chain, paper-source provenance, render, claim, claim-language, or input-validity failure, with S published |
| 2 | Usage error |
| 3 | Input or output failure |

The three carve-outs of C-ID-10 apply unchanged: a pre-existing `--out-dir`, an input or output failure that prevents the single rename, and a usage error raised before exactly one usable `--out-dir` is obtained MUST write no file at any final path and MUST report on standard error.

Before rendering any clean-run runtime or post-run observation, the command MUST verify the full identity chain over the authenticated descriptor D of C-ID-06, the clean-run report Q, the signed reproduction observation R of C-ID-10, its envelope, and the publication record P of C-ID-09:

```text
p3-descriptor-authentication: FIRST authenticate D from the frozen entry buffers by exactly
  C-REP-04 steps 1 through 6: policy canonical gate and closed schema; descriptor-envelope
  canonical gate and closed schema; policy keyid lookup and key selection; selected-key
  descriptor payload-type authorization; descriptor signature verification; descriptor
  payload canonical gate and closed schema; and decoded envelope payload bytes equal the
  standalone D buffer; then require D.key_id == descriptor-envelope.signatures[0].keyid
  == selected policy key.key_id
verify R under C-DSSE-09, selecting the key from the out-of-band policy and requiring keyid == D.key_id
base64_decode(reproduction-observation.dsse.json.payload) == exact reproduction-observation.json bytes
P.release_descriptor_sha256       == SHA256(exact release-descriptor.json bytes)
P.reproduction_observation_sha256 == SHA256(exact reproduction-observation.json bytes)
R.release_descriptor_sha256       == SHA256(exact release-descriptor.json bytes)
R.clean_run_report_sha256         == SHA256(exact clean-run-report.json bytes)
Q.release_descriptor_sha256       == SHA256(exact release-descriptor.json bytes)
R.release_descriptor_sha256       == Q.release_descriptor_sha256
Q.fixture_report_sha256           == SHA256(exact artifact/results/fixture-results.json bytes)
Q.workload_report_sha256          == SHA256(exact artifact/workload/workload-results.json bytes)
Q.mutation_report_sha256          == SHA256(exact artifact/mutation/mutation-results.json bytes)
R.workload_summary_sha256         == SHA256(exact artifact/workload/workload-results.json bytes)
R.mutation_summary_sha256         == SHA256(exact artifact/mutation/mutation-results.json bytes)
Q.performance_report_sha256       == SHA256(exact artifact/performance/performance-results.json bytes)
Q.exact_reproduction_comparisons_sha256
                                  == SHA256(exact <clean-room-root>/external/exact-reproduction-comparisons.json bytes)
every external exact-reproduction-comparisons.json row's expected_sha256 == the sha256 D records for that row's path
every external exact-reproduction-comparisons.json row's matched == (that row's expected_sha256 == its observed_sha256)
every R.verify_only_observational_results entry sha256 == both that file's exact bytes and its corresponding Q owner-report digest
every R.reproduced_result_comparisons entry has matched == true
```

After `p3-descriptor-authentication` and every existing chain check above passes, phase 3 MUST replay the finalizer's terminal Q- and R-derivation semantics from the frozen entry buffers in this fixed order:

```text
p3-qd-fixture-summary
  Q.fixture_results == derive(exact frozen artifact/results/fixture-results.json buffer)
p3-qd-workload-summary
  Q.workload == derive(exact frozen artifact/workload/workload-results.json buffer)
p3-qd-mutation-summary
  Q.mutation == derive(exact frozen artifact/mutation/mutation-results.json buffer)
p3-rd-runtime
  R.clean_run_runtime_seconds == Q.clean_run_runtime_seconds
p3-rd-fixture
  R.fixture_results == Q.fixture_results
p3-rd-performance
  R.performance_observations == derive(exact frozen artifact/performance/performance-results.json buffer)
p3-rd-comparisons
  R.reproduced_result_comparisons == derive(exact frozen exact-reproduction-comparisons.json buffer)
p3-rd-comparison-paths
  R.reproduced_result_comparisons paths == exactly D.exact_reproduction_results paths
p3-rd-observational-set
  R.verify_only_observational_results == the exact closed observational file set, with each
  sha256 equal to both its frozen owner-report buffer and the corresponding Q digest under
  the fixed rd-observational-set mapping in C-ID-10
```

Each identifier in this replay block is owned by C-REP-08, occupies the displayed fixed evaluation-order slot, and is a member of S's closed `failed_check` enum. The first replay failure is `chain-verification-failed`, exits 1, records that identifier in S, sets `chain_verified` to `fail`, and occurs before paper-source provenance or rendering. Phase 3 already holds every required frozen buffer, so this replay introduces no new trust assumption, file open, path read, or other I/O.

`p3-descriptor-authentication` is the first phase-3 verification check and owns a fixed first position. It MUST finish before any R or P verification runs. A mismatch in its three-way key identity equality is part of that check. Its failure is `chain-verification-failed`, exits 1, and records `failed_check` `p3-descriptor-authentication`; it does not introduce a descriptor-specific phase-3 error class. The remaining existing chain checks run in their written order, followed by the replay block in its written order. The `Q.release_descriptor_sha256 == SHA256(D)` check is what stops a publication whose deterministic identity and post-run observations come from different releases; without it the other hash checks are individually satisfiable across a cross-release mix. Re-verifying the owner-report digests and replaying their derivations here means the paper values are read only from files whose bytes both Q and signed R authenticate.

After the full D/Q/R/P chain passes and before any render begins, the command MUST verify the frozen paper-source entry snapshot in this fixed order:

```text
p3-paper-head           snapshot HEAD == D.artifact_commit
p3-paper-index-clean    snapshot index is clean relative to HEAD
p3-paper-worktree-clean snapshot worktree is clean relative to the index, including no untracked paper-source input
p3-paper-manifest-c0    snapshot tracked-worktree path, mode, and content-digest manifest == the captured HEAD git-tree manifest; p3-paper-head establishes that tree is C0, where C0 is D.artifact_commit
```

These four checks are owned by C-REP-08. A capture failure fails the check for the component that could not be captured. The first failure in written order yields `paper-source-provenance-failed`, exits 1, and records that exact identifier in S `failed_check`. The source manifest comparison uses only the entry snapshot and the immutable C0 tree named by authenticated D. A provenance failure is not a render failure: `chain_verified` remains `pass`, `paper_claims_matched` is `null`, and `claim_language_scan` is `not-run` because rendering never began.

Only after every chain and paper-source provenance check passes may the command regenerate the LaTeX inputs, render the paper, and compare paper claims. These three steps moved here from phase 1, and each empirical value MUST be read from the private immutable buffer of the owner report whose digest was just verified, never from a path and never from an unverified copy. Paper-source bytes MUST come only from the verified entry snapshot. The resolved paper PDF MUST remain outside the source commit and release archive.

The command MUST verify that the paper contains the resolved full source commit, freeze commit, release key identifier, publication-pinned release descriptor digest, archive digest, engine digest, and every empirical value that the paper states.

Each empirical value MUST match the generated workload, mutation, performance, fixture, or reproduction report that owns it. No unmeasured empirical number, unresolved command, placeholder, abbreviated hash, or mutable branch name may remain.

The paper MUST NOT require a predetermined workload outcome, mutation outcome, coverage result, fixture count, latency, memory value, or clean-run duration.

The command MUST emit a terminal publication report S with this closed schema, which carries the paper-claim result that used to live in Q:

```text
{
  "publication_report": "vouch.scored26-publication/v0",
  "status": "pass" | "fail",
  "release_descriptor_sha256": <"sha256:" plus lowercase hex64, or null when that buffer was never read>,
  "clean_run_report_sha256": <"sha256:" plus lowercase hex64, or null when that buffer was never read>,
  "reproduction_observation_sha256": <"sha256:" plus lowercase hex64, or null when that buffer was never read>,
  "chain_verified": "pass" | "fail" | "not-run",
  "paper_claims_matched": <boolean, or null when the paper was not rendered>,
  "claim_language_scan": "pass" | "fail" | "not-run",
  "primary_error": <null when status is pass, else one of the closed classes below>,
  "failed_check": <one of p3-descriptor-authentication, p3-qd-fixture-summary, p3-qd-workload-summary, p3-qd-mutation-summary, p3-rd-runtime, p3-rd-fixture, p3-rd-performance, p3-rd-comparisons, p3-rd-comparison-paths, p3-rd-observational-set, p3-paper-head, p3-paper-index-clean, p3-paper-worktree-clean, or p3-paper-manifest-c0 when that identified check failed; null otherwise>,
  "input_artifact": <the failing input when primary_error is publication-input-invalid or input-output-failure; null otherwise>,
  "underlying_error": <the input fault when primary_error is publication-input-invalid; null otherwise>
}
```

`primary_error` is closed and exhaustive:

```text
chain-verification-failed
paper-source-provenance-failed
paper-render-failed
paper-claim-mismatch
claim-language-scan-failed
publication-input-invalid
input-output-failure
usage-error
```

`publication-input-invalid` carries the same closed `input_artifact` and `underlying_error` members as the finalizer's `finalizer-input-invalid`, over the same closed enum, so a non-canonical, over-limit, or schema-invalid non-descriptor input is reported with the same vocabulary. The publication-check has NO `descriptor-authentication-failed` class. Once the descriptor, descriptor-envelope, and trust-policy buffers have been read successfully, every canonical, resource, schema, key-selection, payload-authorization, signature, payload-canonicality, or decoded-payload equality failure within `p3-descriptor-authentication` is `chain-verification-failed`, with `failed_check` `p3-descriptor-authentication`. A failure to read one of those three paths remains `input-output-failure` because authentication never ran and names the artifact in `input_artifact`. Each of the command's twelve file inputs is therefore reportable, and the paper-source root has the separate honest provenance class above. A digest member is `null` exactly when its buffer was never successfully read, which is the only state in which the command cannot compute it; `status` is then `fail` and `primary_error` names the command error. Every digest the command DID read MUST be reported, so S never hides what it saw.

The command-error classes are raised at entry, before any verification, except for the publication-time input or output failure of carve-out 2, and they take precedence over every other class, in this order: `usage-error`, then `publication-input-invalid`, then `input-output-failure`. Validation of the three D-authentication buffers is deliberately part of `p3-descriptor-authentication`, not the entry input-validity block. The remaining classes apply only when their check actually RAN and failed, and among those the first applicable value in the displayed order is reported. So a missing input is `input-output-failure`, never `chain-verification-failed`, because the chain check never ran.

When the command stops before chain verification runs, which is every usage error, every `publication-input-invalid`, and every `input-output-failure` raised at entry, `chain_verified` MUST be `not-run`. A failure of `p3-descriptor-authentication`, any later existing D/Q/R/P chain check, or any phase-3 derivation-replay check makes `chain_verified` `fail`. A paper-source provenance or later failure occurs only after the chain passes, so `chain_verified` is `pass`. When the command stops before the paper is rendered, which is every command error, every chain-verification failure, and every paper-source provenance failure, `paper_claims_matched` MUST be `null` and `claim_language_scan` MUST be `not-run`. A `paper-render-failed` outcome also carries those two values because no completed render exists. `failed_check` is non-null only for the fourteen identifiers declared in its closed schema and is null for every other outcome. S therefore never asserts that a check failed when that check was never run.

S MUST be canonical `csk.artifact-json/v0` and MUST be emitted on every outcome except the three carve-outs above, in which no final path may be written at all, so a failing release is machine-readable rather than silent. The publication-check COMMAND exits 0 only when the chain verification, the paper render, the paper-claim comparison, and the C-FINAL-03 claim-language scan all pass, in which case S carries `status` `pass`. Otherwise the command exits nonzero and S carries `status` `fail` and names its `primary_error`. S is the only place `paper_claims_matched` and `claim_language_scan` are recorded.

Backs P11, P12, P13, P15, and P16.

### C-REP-09 Bootstrap substitution

The bootstrap substitution fixture MUST replace the release archive and its adjacent checksum with a mutually consistent substituted pair.

The external authenticated descriptor and out-of-band consumer trust policy MUST remain unchanged.

The trusted bootstrap verifier MUST reject the substituted inputs at C-REP-04 step 2 or step 7. Rejection at step 2 is permitted when the attack also substitutes or corrupts descriptor material, which fails the descriptor DSSE envelope gate. Rejection at step 7, the archive digest check, is required when the original authenticated descriptor remains intact.

The fixture MUST prove that no archive extraction, package installation, build command, archive script, or other archive-supplied code executes before rejection.

## 31. Synthetic-data and release-scan conditions

### C-DATA-01 Synthetic inputs

Every public welfare-shaped input MUST be generated by the deterministic workload generator or the named smoke-fixture generator. No public input may originate from a person, case file, production log, or administrative dataset.

Backs P18.

### C-DATA-02 Personal-data scan

`artifact/scripts/scan-public-data` MUST inspect source files, Git objects in the release bundle, generated JSON, logs, archives, and npm output. It MUST reject likely email addresses outside the anonymous paper metadata, telephone numbers, national identifiers, payment-card patterns, street-address patterns, and unapproved proper-name fields.

Backs P18.

### C-DATA-03 Low-entropy disclosure statement

The artifact documentation MUST state that unsalted public hashes do not protect low-entropy real-world records and that the public inputs are synthetic.

Backs P18.

## 32. Final acceptance gate

### C-FINAL-01 Phase-1 clean-run report Q (amended v8.4)

This condition defines the phase-1 clean-run report Q and the phase-1 gate. It is NOT the release final gate. The release final gate is the phase-3 publication-check of C-REP-08, which emits the terminal publication report S.

The three release commands and the three gates are exactly:

```text
npm run scored26:reproduce
  the inner experiment runner
  emits only the phase-1 generated result files
  exits 0 only when every phase-1 check it can make passes
  it does NOT construct Q, and it never reads R, P, or the paper

the trusted outer clean-room driver
  runs the whole C-REP-04 sequence, including the inner runner
  measures the clean-run time, solely constructs the external comparison artifact, and constructs Q
  this is the phase-1 clean-run gate: it exits nonzero when the inner runner
  failed or when Q cannot be constructed from the emitted result files

npm run scored26:publication-check
  the phase-3 command of C-REP-08
  verifies the full D, Q, R, envelope, P chain, renders the paper, compares
  paper claims, and emits the terminal report S
  this is the release final gate, and its exit code is the release verdict
```

An optional trusted orchestrator `npm run scored26:release` MAY run the three phases in order and exit according to S. It MUST NOT collapse the phases or let phase 1 read R, P, or the paper.

The inner runner cannot know a phase-2 or phase-3 outcome when it exits, so no condition may require its exit code to depend on the signed observation, the publication record, or the paper. A phase-1 exit code 0 means only that phase 1 passed.

The trusted outer driver's phase-1 gate has this explicit final sequence before Q publication:

```text
construct every comparison row from authenticated D and the regenerated-result buffers
require every row's matched member to equal its two-digest equality
require every comparison row to have matched == true
only then publish the comparison artifact and a passing Q
```

If any row has `matched == false`, the phase-1 gate MUST publish no Q and MUST exit with the fixed code `PHASE_1_COMPARISON_MISMATCH = 1`. This sentence is the sole normative source of that named exit code. This check is jointly owned by C-REP-04 and C-FINAL-01. The finalizer's `rd-comparisons-matched` remains a defence-in-depth phase-2 check and does not replace phase 1 ownership.

Q MUST be a canonical report with this closed schema:

```text
{
  "reproduction_report": "vouch.scored26-reproduction/v0",
  "status": "pass",
  "fixture_results": {
    "built": {
      "expected": <uint>,
      "matched": <uint>,
      "mismatched": <uint>,
      "skipped": <uint>
    },
    "design_target": {
      "listed": <uint>,
      "implemented": <uint>,
      "matched": <uint>,
      "not_implemented": <uint>
    }
  },
  "workload": {
    "candidates": <uint>,
    "selected_case_count": <uint>,
    "decision_pair_count": <uint>,
    "excluded_from_matrix_count": <uint>,
    "development": <uint>,
    "held_out": <uint>,
    "decision_flips": <uint>,
    "held_out_flips": <uint>,
    "exception_count_by_kind": {
      "profile_escape_executions": <uint>,
      "not_comparable_executions": <uint>,
      "pipeline_failure_executions": <uint>
    },
    "decision_distribution_baseline": <closed four-label count object>,
    "decision_distribution_changed": <closed four-label count object>,
    "transition_matrix": <closed 4 by 4 count matrix>
  },
  "mutation": {
    "mutant_level": {
      "seeded": <uint>,
      "built": <uint>,
      "activated_any": <uint>,
      "detected_any": <uint>,
      "detection_rate": <one-decimal percentage string>
    },
    "case_level": {
      "disagreement_cases": <uint>,
      "common_mode_cases": <uint>,
      "pipeline_failure_cases": <uint>,
      "infrastructure_failure_cases": <uint>,
      "survivor_cases": <uint>
    }
  },
  "clean_run_runtime_seconds": <uint>,
  "fixture_report_sha256": <"sha256:" plus lowercase hex64>,
  "workload_report_sha256": <"sha256:" plus lowercase hex64>,
  "mutation_report_sha256": <"sha256:" plus lowercase hex64>,
  "performance_report_sha256": <"sha256:" plus lowercase hex64>,
  "exact_reproduction_comparisons_sha256": <"sha256:" plus lowercase hex64>,
  "release_descriptor_sha256": <"sha256:" plus lowercase hex64>,
  "release_private_key_present": false,
  "public_data_scan": "pass",
  "worktree_clean": true
}
```

The decision-distribution objects MUST contain exactly:

```text
approve
deny
review
invalid-input
```

The transition matrix MUST satisfy C-WL-18. This report is the clean-run report Q of C-REP-10. It is constructed by the trusted outer clean-room driver of C-REP-04 after the phase 1 inner run and after the timer stops, written atomically to the fixed external path `<clean-room-root>/external/clean-run-report.json` outside the worktree, and its digest is an ordinary SHA-256 over the exact canonical Q bytes including the final line feed. `fixture_report_sha256`, `workload_report_sha256`, `mutation_report_sha256`, `performance_report_sha256`, and `exact_reproduction_comparisons_sha256` are ordinary SHA-256 digests of the exact canonical full-file bytes of their five named reports. For each owner report, the driver MUST compute its digest from a read-once immutable buffer, MUST derive its Q summary member from that same buffer where this schema defines one (the fixture, workload, and mutation reports; the performance report and the comparison artifact contribute digests only), and MUST construct Q from those same values without reopening a path. The comparison digest is computed from the one immutable canonical buffer the outer driver constructed and published at `<clean-room-root>/external/exact-reproduction-comparisons.json`. Q carries `release_descriptor_sha256`, which is `sha256(D)`. It MUST NOT carry `sha256(R)` or `sha256(P)`, and it MUST NOT carry `paper_claims_matched`, because the reproduction observation R, the publication record P, and the paper are all created after this report. `clean_run_runtime_seconds` is measured directly by the outer driver during the timed window and recorded here, then copied unchanged into R. The paper-claim comparison and the observation-signature verification are release lifecycle phase 3 and are recorded in the terminal publication report S of C-REP-08, so the phase 1 command no longer depends on R, P, or the paper, and the former report-to-observation generation cycle is gone. Numeric empirical fields MUST contain generated observations. No specific empirical value is required except deterministic design quantities fixed by the workload and mutant registries.

Backs P1 through P19.

### C-FINAL-02 No partial conformance (amended v8.4)

The release final gate is the phase-3 publication-check of C-REP-08, whose terminal report S carries the release verdict. A release MUST fail that final gate when any built-scope generated result, digest, error class, visible string, toolchain pin, command outcome, schema rule, signature, deterministic derivation, manifest expectation, or paper value violates this contract. Phase 3 MUST itself re-evaluate every deterministic qd and rd derivation named by the C-REP-08 replay block from its frozen buffers, so every such derivation violation fails the terminal gate even when R has a valid release-key signature. Checks that phase 1 can make fail phase 1; checks that depend on the signed observation R, the publication record P, or the paper fail phase 3. Design-target rows under C-FIX-08 are not part of the current gate and MUST NOT be reported as conformant.

An empirical result MUST NOT fail solely because it differs from a planned or previously recorded numeric outcome. It MUST fail when the generated report is internally inconsistent, incomplete, suppressed, manually substituted, or inconsistent with a public claim.

The runner MUST NOT update expected files automatically during verification.

Backs P1 through P19.

### C-FINAL-03 Claim-language scan (amended v8.1)

This scan runs in the phase-3 publication-check of C-REP-08, because it reads the rendered paper. Its result is recorded in the terminal report S. The public paper and artifact documentation MUST fail the release final gate if they:

- describe unsigned schema acceptance as native origin
- describe structural consistency as authentication
- claim policy correctness or semantic equivalence
- claim independent witnessing
- claim freshness
- claim that capabilities constrain dishonest applications
- state an unqualified completeness claim over the input domain
- use a finite zero-promotion observation as the security argument
- state an empirical number that is absent from the generated reports
- state an empirical number that differs from its generated report
- present a planned workload, mutation, coverage, fixture, latency, memory, or reproduction outcome as already measured

Backs P1, P2, P6, P13, P17, and P19.
