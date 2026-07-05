# CSK Profile Contract v0

> Status: v1.2.14-compatible design contract for the Lispex Vouch patch train.
> This document defines the checked source profile boundary and the gallery
> ergonomics surface used before external Scheme oracles and spec freeze.

## 1. Purpose

The CSK Profile is the Lispex source subset that may participate in Lispex
Vouch decision artifacts. Full Lispex remains larger than this profile, and the
Rust reference interpreter remains the operational authority for the full
language.

The profile exists to answer a narrower product question: can a deterministic
rule, evaluated over a pinned input datum, leave a portable artifact that can be
re-checked without trusting a private service?

## 2. Checked Profile Boundary

The initial profile contract is intentionally smaller than full Lispex.

Initial profile forms:

- `quote`
- `if`
- lowered `cond`
- lowered `case`
- short-circuit `and` and `or`
- `begin`
- `define`
- fixed-arity `lambda` and closures
- parallel `let`
- top-level recursive `define`

Outside the profile until a later slice explicitly changes the contract:

- `letrec`
- variadic `lambda`
- mutation
- macros
- continuations
- `dynamic-wind`
- unconstrained I/O
- vectors beyond literal data
- chars
- floats
- the full numeric tower

An out-of-profile source construct must produce a profile escape diagnostic or
lowering fault. It must not be silently approximated.

## 3. Profile Builtin Binding

Profile builtin names are closed and versioned. A source reference to a profile
builtin lowers to an intrinsic reference in Meaning Graph, not to a user binding.

In the checked profile, source code must not bind, define, or shadow a profile
builtin name. Such a binder is a profile escape fault. This is stricter than
full Lispex and is deliberate: profile receipts need a closed builtin surface
whose semantics can be checked from public contracts.

The v1.2.14 profile builtin set is:

```text
+ - * /
= < > <= >=
equal? eqv? not
string=? string<?
null? pair? list? string? number? boolean? symbol?
car cdr cons list append length
assoc assv member memv
min max abs quotient remainder floor ceiling round truncate
map filter reduce fold-left fold-right any? all?
```

Profile numeric data includes exact integers and exact rationals. It excludes
inexact reals/floats until their deterministic byte and runtime story is pinned.
The `/` builtin therefore returns an exact integer or exact rational for exact
arguments and faults deterministically on division by zero. Any operation that
would require an inexact result is outside the checked profile.

`min` and `max` accept one or more arguments; zero arguments are an `arity`
fault. The basic arithmetic builtins keep their full Lispex variadic arity where
already defined. `quotient` and `remainder` require exact integer arguments and
use the R7RS truncate-toward-zero quotient family; this differs from `floor` for
negative refund or adjustment amounts. `floor`, `ceiling`, `round`, and
`truncate` accept exact profile numbers and return exact integers. `round`
follows the R7RS ties-to-even rule; money rules should spell out `floor`,
`ceiling`, `truncate`, or `round-half-even` when their business convention hits a
rational-to-cent boundary.

`assoc` and `member` use `equal?` and are fixed to their two-argument profile
shape. `assv` and `memv` use `eqv?` and are also fixed to two arguments.
`assq` and `memq` remain outside the checked profile because `eq?` on numbers
and characters is implementation-dependent across Scheme systems.

Traversal builtins `map`, `filter`, `reduce`, `fold-left`, and `fold-right` are
inside v1.2.11 because the Meaning Environment now supports evaluator re-entry
through fixed-arity closures with step-limit accounting. `fold` without a suffix
is not a profile builtin name.

`any?` and `all?` are CSK Profile extensions, not R7RS claims. Both take exactly
`(pred list)`, require a proper list, evaluate list elements left to right with
short-circuiting, and return strict `#t` or `#f` rather than forwarding the
predicate's original truthy value. Empty lists return `#f` for `any?` and `#t`
for `all?`. Unlike language-level `if`, where only `#f` is false, these two
builtins require the predicate callback to return `#t` or `#f`; any other value
is an `intrinsic-domain` fault.

v1.2.10 added a closed-form 4-rule eligibility mini-gallery under
`profile-gallery/eligibility-mini`. v1.2.12 keeps that mini-gallery as a
historical closed-form corpus and ports its four rules into the input-bound
decision gallery under `profile-gallery/decision-gallery`.

## 4. Pinned Host Input

The checked profile has one host input datum.

- The host supplies it through a profile command such as `--input`.
- The datum is immutable for the duration of evaluation.
- The datum is bound to the distinguished profile name `input`.
- Profile source must not bind, define, or shadow `input`.
- Full Lispex does not reserve `input`; this restriction is profile-only.
- The checked input datum domain admits booleans, exact integers, exact
  rationals, symbols, strings, `()`, and proper or dotted pairs/lists containing
  admitted values.
- The checked input datum domain rejects inexact reals/floats, characters,
  vectors, bytevectors, and execution-only values.
- An input datum parse, cardinality, canonicalization, or profile-domain failure
  is a deterministic `input-error` differential receipt event. Usage failures
  and unreadable input files exit with code 2 and write no receipt.

The canonical input bytes use the same datum byte discipline as Canonical Core
literal data. The reserved input hash domain is:

```text
csk/profile-input-hash/v0
```

The hash preimage is:

```text
csk/profile-input-hash/v0\0<input-datum-canonical-bytes>
```

Decision receipts record this input binding before they make any claim about a
rule evaluation. The input is not injected into source, Canonical Core, or
Meaning Graph bytes; it is bound through the host API in both the reference
interpreter and Meaning Environment. A gallery without pinned input is not a
decision gallery; it is only a closed-form program corpus.

The v1.2.14 input-bound gallery has 10 agree receipts under:

```text
profile-gallery/decision-gallery/cases/*.lspx
profile-gallery/decision-gallery/inputs/*.datum
profile-gallery/decision-gallery/expected/*.json
profile-gallery/decision-gallery/manifest.json
```

The gallery is guarded by `npm run check:decision-gallery`. External anchors in
the manifest are only style re-expressions; they are not implementation or
format-parity claims about OpenFisca, Cedar, JSON Logic, or any other system.

Gallery cases use a single printed decision datum as their public transcript
convention:

```text
(decision allow)
(decision deny <reason-symbol>)
(decision amount <exact-integer-cents> <reason-symbol>)
(decision invalid-input <reason-symbol>)
```

`<reason-symbol>` is a symbol token. `<exact-integer-cents>` is an exact integer
count of cents, not a decimal float. JSON projections of amount decisions must
encode money as canonical integer strings such as `"amount_cents": "9950"`; JSON
numbers are forbidden to avoid JavaScript precision loss. Rule authors should
represent money as integer cents throughout profile code. Amount cases in the
gallery manifest must declare:

```json
{
  "unit": "cent",
  "amount_encoding": "exact-integer-cents",
  "rounding": "none|floor|ceiling|truncate|round-half-even",
  "rounding_required_at": "rational-to-cent-boundary",
  "note": "<reason>"
}
```

Dates should prefer an `epoch-day` integer when arithmetic or ordering is
needed; `YYYYMMDD` integers are acceptable only for display-like comparisons
that do not need calendar arithmetic.

`lispex replay` may project this convention into its optional `decision` layer
only when a receipt transcript contains exactly one conforming decision datum.
Malformed decision text, multiple datum outputs, or non-decision outputs leave
the projection `null`; they do not change the underlying byte transcript
comparison.

## 5. Decision Artifact Boundary

A profile decision artifact may attest:

- source bytes and source hash
- canonical profile input bytes and input hash
- engine name and version
- checked profile boundary
- deterministic transcript bytes
- structured diagnostics and faults
- linked Meaning Graph and Meaning Environment artifacts when available

It must not claim:

- whole-language Lispex coverage
- full CSK coverage
- correctness of the policy itself
- semantic equivalence between implementations
- regulatory or audit fitness
- independence claims unless an implementation-blind check path exists
- Topaz independence or external witnessing

Receipts attest what was evaluated and which public boundaries were checked.
They do not decide whether the business rule is morally, legally, or
commercially correct.

## 6. Slice Order

The profile work now gates the v1.3 train:

1. v1.2.9: profile contract, builtin binding, host input pinning, public
   positioning.
2. v1.2.10: control and arithmetic mini-gallery.
3. v1.2.11: closures, fixed-arity functions, traversal builtins.
4. v1.2.12: host-input execution path and externally anchored full gallery.
5. v1.2.13: verify/replay JSON report artifacts.
6. v1.2.14: gallery ergonomics builtins, decision output convention, and
   integer-cents/date idioms.
7. v1.2.15+: external oracles, spec freeze, and release gates.
8. v1.3.9: welfare replay evaluation, profile expansion 0, and recursive
   idiom capture.

This file is the public place for source-profile decisions. Graph schema,
lowering bytes, evaluator reports, and receipts remain in their own contracts.

## 7. Welfare Replay Idioms

v1.3.9 adds `profile-gallery/welfare-replay` as an evaluation corpus for
welfare-style rule replay. It intentionally adds no profile forms, no profile
builtins, and no new runtime semantics.

The corpus records three profile idioms that rule authors should prefer before
requesting profile expansion:

- recursive bracket accumulation for marginal rates and tapers
- recursive dependent bonus accumulation for household additions
- nested `assoc` lookup through `lookup-path` for table-shaped policy data

Malformed policy tables close as `(decision invalid-input bad-table)`, not as
out-of-scope behavior. This keeps the fail-closed boundary deterministic when
real rule data is malformed.

See `docs/CSK-WELFARE-REPLAY-EVALUATION.md` for the corpus layout, replay
result, and the profile expansion decision.
