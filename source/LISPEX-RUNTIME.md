# Lispex v1.2 — Reference Runtime Semantics (Executable Profile)

> **Status: reference build profile (2026-06-28).** The companion
> surface/normalization specification is outside this source projection. This
> document is the semantic reference for the interpreter's executable profile;
> product planning and approval history have been omitted from this projected
> copy.
>
> **Implementation plan:** built in **Rust now** (a reference interpreter + wasm playground), engineered so
> a later **external backend** port is a transliteration (every choice below avoids host-specific control flow and
> maps onto a recursive enum + arbitrary-precision integer + `while`-loop trampoline). Determinism is
> the product identity, so **every R7RS-unspecified point is pinned here.**
>
> **Differential-validation note:** New interpreter backends must implement
> these pins and demonstrate their fit by byte-level agreement checks plus
> native differential receipts, not by weakening the profile.
>
> **Lispex Vouch note (v1.3 track):** Lispex is not documented as the whole Core Semantic Kernel public language yet.
> The public v1.3 direction is to make Lispex Vouch the checked source/profile boundary for a
> subset that can replay realistic rule corpora across engine versions and emit portable receipts. Public
> product-specific integration terms do not belong in this runtime contract.

## 0. Pinned semantic decisions

1. **`case` uses `eqv?`** (not `equal?`). The executable profile normalizes `case` with `eqv?`
   (R7RS-correct). `LISPEX.md` §6.4 and the concept docs now state `eqv?` (doc fix applied 2026-06-29; the
   obsolete `W320` "case compare" notice is retired).
2. **`=` is numeric-only** (not deep-list compare); **`==`/`!=` are structural** — `equal?` is the structural
   comparator and `==`/`!=` are aliases of `equal?` / its negation. → doc fix: `content/**/reference/operators.mdx` (rewrite `(= (list 1 2)(list 1 2)) ⇒ #t` to `equal?`), and the conformance corpus carries an exception until patched.
3. **"Unspecified" results are ZERO VALUES**, not a printable sentinel. `set!`, `define`, and false-branch
   `when`/`unless` yield zero values (extends the spec's own `when/unless → (values)` convention).

Additional doc fixes surfaced (apply to `LISPEX.md`/MDX during R2): `first-project.mdx` `str-concat` → `string-append`; migrate `list-first`/`list-rest` → `first`/`rest` (kept as deprecated aliases meanwhile); reconcile §6.4 `case` text to `eqv?` and quote its datum arms; **add named `let` to the grammar (§14)** (it appears in §15.1 examples but is absent from the BNF); fix the `\xHH;` "one-byte" wording to "Unicode scalar"; tighten the numeric-literal regex (no ambiguous/leading-zero reals) per §2 here.

## 1. Architecture (load-bearing; backend-portable)

- The evaluator **returns an explicit signal, never host control flow**:
  `Eval<Outcome> = Ok(Outcome) | Error(RuntimeError) | Escape { tag, Outcome }`, propagated by `?`-style
  threading. **No `panic`/unwind, no exceptions.** This is the only model that ports to the planned backend (whose faults
  are uncatchable → a port must thread `Result`/trampoline). Errors, escape-continuations, and a future
  `guard-call` all reuse this one signal.
- `Outcome = One(Value) | Many(Vec<Value>)` (`Many` covers 0 and ≥2 values). Multiple values are an
  _evaluation outcome_, never a storable `Value`. (Design note: type the signal as `Eval<Outcome>`, since
  escapes/errors can carry zero or many values.)
- **Value** is a recursive sum type (maps to a future external backend recursive enum):
  `Bool, Int(BigInt), Rational(BigRational), Real(f64), Char(scalar), Sym(interned), Str,
Nil, Pair(car/cdr), Vector(mutable cell), Bytevector, Closure, Primitive, Cont`.
  - Invariant: a rational whose denominator is 1 is **demoted to `Int`**; `Rational` always has q>1, lowest
    terms, sign on the numerator.
  - Aggregates are reference-shared (boxed cell → external backend 1-slot box). **In v1.2 only `Vector` is mutable**
    (`vector-set!`) and only variable cells via `set!`; `Str`/`Pair`/`Bytevector` ship NO mutators in v1.2
    (immutable values; `set-car!`/`set-cdr!`/`string-set!` are v2). `quote`d data is immutable.
- **Every binding is a mutable cell** (assignment conversion). Environment = chain of frames; frame = name →
  boxed cell. Variable read = find cell in the lexical chain and load; closures capture the frame, so they
  share cells; `set!` mutates the cell. Uninitialized `letrec` cells hold an **`Uninitialized` sentinel that
  is not representable as a user value**.

## 2. Numeric tower — FULL exact

Exact integer = `BigInt` (arbitrary precision); exact rational = `BigRational`; inexact real = `f64`. No
complex, no inexact-rational, no fixnum/flonum tiering.

- **Contagion (for `+` `-` `*` `/` only):** `exact ⊕ exact → exact`; if any operand is inexact, coerce all
  operands to `f64` and run in IEEE-754 → inexact. **This whole-operand coercion is ONLY for `+ - * /`.** The
  comparison operators (`= < > <= >=`) and `min`/`max` instead **compare EXACTLY** (a non-selected exact
  operand need NOT be f64-representable — so `(min 0.0 <huge-exact>) → 0.0`, never `E314`) and apply contagion
  only to the _result's_ inexactness (R7RS). `modulo`/`quotient`/`remainder` are **integer-domain**: compute the
  exact integer result, then make it inexact iff an operand was inexact (`(modulo <huge-exact> 3.0) → 1.0`, not
  `E314` — the bounded `modulo`/`remainder` results always coerce finitely; an unbounded `quotient` result can
  still overflow → `E314`).
- `(/ 1 3) → 1/3`; `(/ 10 5) → 2`; `(/ 1.0 3) → 0.3333333333333333` (inexact).
- **★ Finite-`Real` invariant (v1.2 has no inf/NaN).** `Real(f64)` is ALWAYS finite. **Every f64 producer**
  checks `is_finite` and raises on a non-finite result — not just arithmetic, but also a reader literal
  (`1e9999` → `E314`), `string->number`, the `inexact` proc, exact→f64 contagion coercion, and
  `(inexact <huge bigint/rational>)`. `(/ x 0)` and `(/ x 0.0)` → `E313`; any other non-finite f64 → `E314`.
  (Underflow to subnormal or to `0.0`/`-0.0` is fine — those are finite.) Because no producer can yield
  inf/NaN, there are no `+inf.0`/`+nan.0` literals or values and no NaN canonicalization. `-0.0` _does_ exist
  (finite) and is distinct from `0.0` under `eqv?`/`eq?` (equal numerically under `=`).
- `modulo` = sign-of-divisor; `quotient` = truncated (toward-zero) division; `remainder` = sign-of-dividend
  (contrast `modulo`) — each integer-domain, exactly 2 args, zero divisor → `E313`, satisfying
  `n = d·(quotient n d) + (remainder n d)`.
- The R7RS division family layers on these: `floor-quotient` = `⌊n/d⌋` (toward −∞, contrast `quotient`);
  `floor-remainder` ≡ `modulo`; `truncate-quotient` ≡ `quotient`; `truncate-remainder` ≡ `remainder`;
  `floor/` and `truncate/` each return TWO values (the quotient and remainder together).
- Comparisons (`= < > <= >=`) are variadic chains, ≥2 args, pairwise; **mixed exact/inexact compared
  EXACTLY** (convert each `f64` to its exact dyadic rational, compare exactly — no double-rounding).
- Literals decimal-only, exact token grammar pinned: integer `-?(0|[1-9][0-9]*)` (no leading zeros, no
  radix/exactness prefixes like `#x #e` → `E100`); rational `<int>/[1-9][0-9]*` (denominator ≥1, reader
  reduces to lowest terms, sign→numerator); real `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?` **with at
  least one of `.`-fraction or exponent present** (a bare `-?(0|[1-9][0-9]*)` is an integer, not a real;
  require a digit on both sides of `.`). `42/7 → 7` (exact); `19.99` inexact. Ambiguous/leading-zero tokens
  are `E100`.
- Two crossing procs: `inexact` (exact→nearest f64, round-to-nearest-even) and `exact` (f64→its **true**
  dyadic rational; `(exact 0.5) → 1/2`). Aliases `exact->inexact`/`inexact->exact`.
- **★ Float formatting is a pinned, self-implemented algorithm** (must-fix): canonical `number->string`
  / `display` / `write` for `f64` = **shortest round-trip, POSITIONAL only (never scientific), force a
  trailing `.0`**, `-0.0` preserved (`3.0 → "3.0"`, `1.0/3.0 → "0.3333333333333333"`,
  `1e30 → "1000000000000000000000000000000.0"`). The Rust impl and the future external backend port implement the SAME
  algorithm verified by a golden float-vector (do NOT rely on either language's default float printing — this
  is the same parity concern as the corresponding external implementation). Exact int = decimal; exact rational = `p/q` lowest
  terms, q>1, sign on numerator.
- **Transcendentals excluded from v1.2** (`sqrt/sin/cos/tan/exp/log`; the general/transcendental `expt` with a
  non-integer/float exponent) — platform libm is nondeterministic. An `expt` with an **exact-integer exponent** IS
  supported (deterministic exact/rational arithmetic); so is **`exact-integer-sqrt`** (pure integer arithmetic, NOT the
  excluded transcendental `sqrt`). v1.2 numeric procs = `+ - * / modulo quotient remainder floor-quotient floor-remainder truncate-quotient truncate-remainder floor/ truncate/ abs square min max floor ceiling round truncate gcd lcm expt exact-integer-sqrt` (rounding: one real → integer-valued, SAME exactness, `round` half-to-EVEN; the floor-/truncate- family layers on modulo/quotient/remainder — `floor-quotient`=⌊n/d⌋, `floor-remainder`≡modulo, `truncate-quotient`≡quotient, `truncate-remainder`≡remainder, `floor/`/`truncate/` return two values; `gcd`/`lcm` variadic integer, always non-negative, (gcd)=0/(lcm)=1; `expt` exact-integer exponent only — contagion follows the base, exp 0 → 1, negative exp → reciprocal, exact 0^negative → E313; a base of magnitude 0 or 1 is representable for ANY exponent, while any other base raised to an `|exponent|` beyond the machine-integer bound (an astronomically large power) reports the overflow fault E314; `square` = z·z exactness-preserving; `exact-integer-sqrt` returns two values s,r = floor-sqrt + remainder for an exact non-negative integer, negative → E312), the 5 comparisons, `exact`/`inexact`,
  and exact predicates (`zero? positive? negative? even? odd? number? integer? exact-integer? rational? real? complex? exact? inexact?` — in v1.2 `real?`≡`rational?`≡`complex?`≡`number?` since the tower is finite reals with no complex/inf/NaN, and `exact-integer?` is #t only for an exact `Int`).

## 3. Evaluation order — strict left-to-right

Application = **operator first, then operands L→R**, then arity check, then enter. `let` inits L→R in the
enclosing env (parallel binding); `let*` chained; `letrec` in the env where all names are visible; `begin`
and body sequences L→R (non-final values discarded); `and`/`or` L→R short-circuit.

## 4. Tail calls — GUARANTEED proper TCO

Implemented as an explicit-control eval loop / trampoline (CEK-style; a tail application replaces the current
frame). **Self- and mutual-recursion both get TCO.** Tail positions: `lambda`/`let`/`let*`/`letrec`/`begin`
last body expr; both `if` branches; each `cond`/`case` clause's last expr (via if-expansion); the last operand
of `and`/`or`; `when`/`unless` taken-branch last expr; `do`'s recursive self-call and result last expr.
**Critical:** rely on `LISPEX.md` §6.5/6.6 single-operand `and`/`or` expansion and §6.8 `do→letrec`-loop so
the last operand/recur lands in `if`-branch (tail) position — do NOT wrap the last operand in a `let`-temp.
TCO goldens (must exist): self, mutual, and through `if/begin/and/or/cond/case/do/call-with-values/apply`.

## 5. Multiple values

`values → Outcome`; `call-with-values producer consumer` applies producer to 0 args, captures all values,
applies consumer (arity must match incl. dotted rest, else `E302`). A **single-value context** (call operand,
`if` test, `let`/`letrec`/`set!`/`define` RHS, **and each operand position — including the operands of
`values` itself**) receiving **0 or ≥2** values → `E320`; exactly 1 unwraps. (So `(values (values 1 2) 3)`
→ `E320`: an inner `values` used where one value is expected.)
**Discard contexts** (non-final body/`begin` exprs), the `call-with-values` producer continuation, and the
REPL continuation accept any arity.

## 6. Equality

`eq?` ≡ `eqv?` on atoms (numbers/chars/bools/syms/`()`), pointer identity on aggregates. `eqv?`:
exactness-sensitive (`(eqv? 2 2.0) → #f`, `(eqv? 1/2 1/2) → #t`); aggregates by identity. `equal?`: deep
structural (pair/vector/bytevector/string), atoms via `eqv?` (`(equal? 2 2.0) → #f`), procedures by identity,
**cycle-safe** (visited-set, must terminate). `case` comparator = `eqv?` (§0.1). `=` numeric-only; `==`/`!=` = structural `equal?` (§0.2).
(No NaN/inf in v1.2, §2; `-0.0` is a normal finite value — `(eqv? 0.0 -0.0) → #f`, `(= 0.0 -0.0) → #t`.)

## 7. Core forms

Truthiness: **only `#f` is false** (`()`,`0`,`0.0`,`""`, vectors all truthy). `if` is 3-arm (else mandatory by
grammar). Closures = `(formals, body, captured-frame)`, lexical capture by frame. `set!` of unbound → `E303`;
`set!`/`define` yield zero values. `letrec` = allocate-then-assign; **reading** an uninitialized cell during
init → `E321`. (`set!` TO a not-yet-initialized letrec cell is allowed — it just stores into the location, R7RS-style; only a _read_ of the uninitialized sentinel faults.) Top-level duplicate `define` **reassigns the existing global cell** (so early-captured holders and
late lookups agree; document closure visibility). `quote` = immutable literal. **`quasiquote`/`unquote`/
`unquote-splicing` are fully expanded at NORMALIZE time** (per `LISPEX.md` §10) into `quote` + constructor
calls, so the runtime core implements only `quote`. Dotted/variadic formals `(x y . rest)` collect a fresh
proper list. Reserved words (`LISPEX.md` §4) are unshadowable → `E110`. **Named `let`**
`(let name ((v init)…) body)` is a derived form ⇒ `(letrec ((name (lambda (v…) body))) (name init…))`
(the canonical loop idiom in `LISPEX.md` §15.1; hygienic per §7.1). A bare `unquote`/`unquote-splicing`
**outside** a `quasiquote` is a **static error** (E1xx), never a runtime form.

### 7.1 ★ Hygiene (must-fix)

Derived-form normalization (`cond`/`case`/`and`/`or`/`when`/`unless`/`do`/`quasiquote`/`let*`/named-`let`)
must expand to **hidden intrinsics + fresh internal identifiers**, never to user-shadowable surface names
(`append`, `list`, `not`, `eqv?`, `vector->list`, `cons`, …) and never to user-collidable temp names. In
particular `unless` must NOT expand through the user-shadowable `not`: expand `(unless t b…)` as
`(if t (values) (begin b…))` (and `when` as `(if t (begin b…) (values))`), or via a hidden intrinsic-not. A
program that binds `list`/`append`/`not` must not change the meaning of any desugared form. Temp variables
introduced by expansion use a reserved namespace that cannot appear in source.

## 8. Error model

`RuntimeError { code, message, irritants, span }`. Codes namespace **E3xx = runtime** (E1xx static, W2xx/W3xx
warnings unchanged); message format `CODE file:line:col message` (`LISPEX.md` §13 style); deterministic
templates; irritants rendered via `write`; span = the enclosing call site; **first error aborts**; no stack
traces (frame identity isn't deterministic). Cases:

| Code | Case                      | Code | Case                                          |
| ---- | ------------------------- | ---- | --------------------------------------------- |
| E300 | unbound variable          | E313 | division by zero                              |
| E301 | apply non-procedure       | E314 | inexact result not finite (overflow)          |
| E302 | arity mismatch            | E320 | multiple-values misuse                        |
| E303 | `set!` on unbound         | E321 | unassigned `letrec` var read                  |
| E310 | pair expected (car/cdr/…) | E330 | user `(error …)`                              |
| E311 | index out of range        | E340 | escape continuation no longer active          |
| E312 | wrong type to primitive   | E331 | object raised, uncaught (`raise`)             |
| E330 | user `(error …)`          | E332 | handler returned from a non-continuable raise |

**Catching (v1.2)** — the procedural exception system over the SAME `Eval::Error` signal (no new
control mechanism): `(raise obj)` (non-continuable → `E331` uncaught), `(raise-continuable obj)` (the
current handler runs IN PLACE and its value returns into the call), `(with-exception-handler handler
thunk)` (a handler stack, base-length/truncate discipline; a handler returning from a non-continuable
raise → `E332`), the **`guard`** surface form `(guard (var clause…) body…)` (a fixed Core node — NOT a
user macro — that catches a catchable fault at its frame, binds `var`, runs cond-style clauses, and
reraises the original fault when none match and there is no `else`), and the error objects
`error-object?` / `error-object-message` / `error-object-irritants` (also made by `error`). A caught
intrinsic fault is synthesized as an error object. The `RecursionLimit` resource bound stays OUTSIDE
`E3xx` and is **never** catchable. `guard` clauses reuse `cond`'s machinery exactly (no `=>`).

## 9. call/cc + dynamic-wind — escape-only v1.2

`call/cc` = **one-shot upward (escape-only, non-reentrant)** continuation via `Eval::Escape` (NOT host
unwinding → backend-portable). `(call/cc proc)` mints a fresh tag, calls `proc` with escape `k`; the FIRST
`(k v…)` atomically consumes `k` before producing `Eval::Escape{tag,[v…]}` that unwinds to the owning frame,
which returns `(values v…)`. Any later invocation → `E340`, including a second invocation from a pending
`dynamic-wind` `after` while the owner frame is still live; invoking after the frame returns is also `E340`.
The deterministic E340 message is `escape continuation is no longer active`. `dynamic-wind before thunk after`:
`before → thunk → after`; on escape/error through the frame, pending `after` thunks run (innermost-first) then
the signal continues; `before` never re-runs. **Precedence:** if an `after` thunk itself raises/escapes while
a signal is already in flight, the newer signal **replaces** the in-flight one; `before`/`after` run in
discard context (their values dropped); nested winds run `after`s innermost-first on unwind. **Full multi-shot
call/cc + dynamic-wind re-entry/rewind are v2** (the top scope cut).

## 10. Stdlib (v1.2 minimum) + canonicalization

**Rule:** R7RS names are canonical; the docs' friendly names become **real aliases** so every published
snippet runs as-written; third spellings/never-used names are dropped; deprecated aliases emit a W3xx style
warning. Set (in-scope unless marked): arithmetic `+ - * / modulo quotient remainder floor-quotient floor-remainder truncate-quotient truncate-remainder floor/ truncate/` (`%` = deprecated alias of `modulo`, W330; floor-/truncate- = floored/truncated division, `floor/`/`truncate/` return two values),
`abs square min max floor ceiling round truncate gcd lcm expt exact-integer-sqrt` (rounding → integer-valued same-exactness, `round` half-to-even; `gcd`/`lcm` variadic non-negative; `expt` exact-integer exponent only, general expt excluded; `square` = z·z; `exact-integer-sqrt` = floor int sqrt + remainder, two values, exact non-negative integer); comparisons `= < > <= >=` (numeric), equality `eq? eqv? equal?` (`==`=alias of `equal?`, `!=` =
`(not (equal? …))`); boolean `not boolean=?` (`and`/`or` are **special forms**, not procedures; `boolean=?` = ≥2 booleans, #t iff all equal); pairs/lists `cons car
cdr` (`first`/`rest` = aliases; `list-first`/`list-rest` = deprecated aliases), `null?` (`empty?` = alias),
`pair? list? length append reverse list make-list list-ref list-tail list-copy caar cadr cdar cddr` (`nth` = alias; `make-list` = `(make-list k [fill])`, a fresh list of k copies of fill (default the exact `0`, pinned like `make-vector`; non-int k → E312, negative/huge → E311); `list-tail` = the shared k-th cdr, out-of-range k → E311; `list-copy` = a shallow spine copy, total/lenient on non-lists; the `c…r` accessor family `caar`..`cddddr` is present — the four 2-deep are `(scheme base)`, the 3-/4-deep are the `(scheme cxr)` extension, each faulting E310 on a non-pair at any step), `map filter reduce fold-left fold-right apply for-each` (`fold-left` = R6RS alias of `reduce`; `fold-right` = right fold, `(f elem acc)`; `apply` tail-applies a proc to spread args + a final proper list; `for-each` = `map` run for effect, unspecified result), list-search `member memv memq assoc assv assq` (member/assoc by `equal?`, the `v`/`q` spellings by `eqv?` — eq?≡eqv? in v1.2, §6); strings `string-append
make-string string-length substring string-copy string-ref string->list string->vector list->string string->symbol symbol->string string->number number->string string=? string<? string>? string<=? string>=? string-ci=? string-ci<? string-ci>? string-ci<=? string-ci>=? string-map string-for-each string-upcase string-downcase string-foldcase` (`make-string` = k copies of a char, default fill `#\space` (pinned); `string-ci…?` are case-insensitive — fold each operand via full lowercase (ASCII-exact); `string-foldcase` = that same fold (a functional twin of `string-downcase` in v1.2; exact Unicode folding deferred); `string-upcase`/`string-downcase` apply the Unicode FULL case mapping (result may change length, e.g. "ß"→"SS"; char-upcase/downcase use simple mapping); `string-copy` = `substring` with an optional `[start end]`, fresh string; `string-ref` uses a character index, not a byte offset; string comparisons lexicographic by Unicode scalar; `string-map`/`string-for-each` are SINGLE-string HOFs — `string-map`'s proc must return a character (else E312) in a single-value context, `string-for-each` runs for effect → zero values; `number->string`/`string->number` take an optional radix 2/8/10/16 (default 10 = the full grammar/formatter; a non-decimal radix is exact-integer-only — `number->string` requires an exact integer, `string->number` parses a signed integer in that base else #f, and an in-string radix prefix like `#x` is not honored in v1.2))
(drop `str-concat`); chars `char? char->integer integer->char char=? char<? char>? char<=? char>=? char-ci=? char-ci<? char-ci>? char-ci<=? char-ci>=? char-alphabetic? char-numeric? char-whitespace? char-upper-case? char-lower-case? char-upcase char-downcase char-foldcase` (compare by Unicode scalar order; `char-ci…?` are case-insensitive — they fold each operand via an approximation (≈ simple lowercase, ASCII-exact; diverges from true Unicode case-folding for a few chars like `µ`/`ſ`/final-sigma `ς`, a v2 refinement); `char-foldcase` = that same fold; `char-upcase`/`char-downcase` apply the Unicode SIMPLE single-char case mapping — a char whose FULL mapping would expand, e.g. `ß`, is returned unchanged, contrasting `string-upcase`/`string-downcase` (full); exact Unicode folding deferred; the classification predicates require a char (non-char → E312) and use the Unicode property — `char-alphabetic?`/`char-whitespace?`/`char-upper-case?`/`char-lower-case?` are full-Unicode, while `char-numeric?` is v1.2 ASCII decimal digits `#\0`..`#\9` only, full Unicode `Nd` deferred to v2); vectors `make-vector vector vector-ref
vector-set! vector-length vector->list vector->string list->vector vector-copy vector-map vector-for-each` (`string->vector`/`vector->string` convert between a string and a fresh char vector, each with an optional `[start end]` sub-range — `string->vector`'s vector is mutable, `vector->string` requires every in-range element to be a character (else E312); `vector-copy` = a fresh MUTABLE vector with an optional `[start end]` sub-range, `0 ≤ start ≤ end ≤ len`; reads but never mutates its input, so copying an immutable vector yields a mutable one; the R7RS `vector-copy!` mutator stays v2; `vector-map`/`vector-for-each` are SINGLE-vector HOFs like `map`/`for-each` — `vector-map` collects `(proc elem)` into a fresh vector in a single-value context, `vector-for-each` runs for effect → zero values; both snapshot the elements before applying, so the proc may safely mutate the same vector); bytevectors `bytevector? make-bytevector bytevector bytevector-length bytevector-u8-ref` (immutable in v1.2; `bytevector-u8-set!` deferred to v2); symbols `symbol? symbol->string string->symbol symbol=?` (`symbol=?` = ≥2 symbols, #t iff all equal by name);
predicates `number? integer? string? symbol? char? boolean? procedure? vector? bytevector? null? pair? list?` (+ the exact
numeric predicates from §2). **Deferred to v2:**
bytevector mutation (`bytevector-u8-set!`), `bytevector-copy`/`bytevector-append`, utf8 codecs, EXACT Unicode case folding (the `char-foldcase`/`string-foldcase`/`char-ci…?`/`string-ci…?` family ships an ASCII-exact lowercase approximation; exact folding is v2), `read`/`input`, transcendentals. Mutators present in v1.2: **only `set!` (variables) and `vector-set!`**; `Str`/`Pair`/`Bytevector` are immutable
in v1.2 (`string-set!`/`set-car!`/`set-cdr!` deferred to v2). `quote`d data is immutable → mutating it is
`E312`. `write` and `equal?` on cyclic aggregates must terminate (visited-set, deterministic notation).

## 11. I/O + REPL

`display` (human; strings unquoted, char as glyph) and `write` (re-readable; strings quoted/escaped, char as
`#\…`) both return zero values; `newline` emits `\n`; `println` = `(begin (display x) (newline))` (kept).
`read`/`input` deferred (determinism). **REPL/corpus auto-print** = after each top-level expression, print its
value via `write`, one value per line; **zero values prints nothing**; multiple values one per line. **Batch
mode**: no auto-print. **List rendering = R7RS `(1 2 3)`** (not `(list 1 2 3)`); the corpus reconciles the
docs' `(list …)` notation via the evaluate-the-annotation comparison (§13).

## 12. Reader pins

UTF-8 source; line `;` + nestable block `#| |#` comments; the optional `;! lispex` header pragma is recorded as
metadata only.
**Symbols case-sensitive; no Unicode normalization** (compare by raw scalar sequence). Numeric tokens per §2
(decimal only; `p/q`; reals). String/char escapes `\" \\ \n \t \r \xHH;` where `\xHH;` is a variable-length hex
**Unicode scalar value** (1+ hex digits, value ≤ max scalar — NOT a fixed 2-digit byte; `LISPEX.md`'s
"2-digit/one-byte" wording is reconciled to scalar here; reject surrogates/out-of-range → `E150`). Bytevector elements 0–255 (out of range → static error). Dotted
lists, `' ` `` ` `` `,` `,@` shorthands.

## 13. Conformance corpus

Three families: **(A)** evaluation goldens (doc blocks with `;; Result:` / `; ⇒` / `;; ⇒`); **(B)** diagnostic
negatives (`LISPEX.md` + `error-handling.mdx` static E1xx/W3xx, plus new runtime E3xx negatives:
`(car (list))→E310`, `(/ 1 0)→E313`, `(foo)→E300`, `(5 1)→E301`, …); **(C)** authored normalization pairs
for derived-form transformer behavior. Extract **en only** as canonical +
a drift guard asserting ko/ru code fences are **translation-invariant** — equal to en after stripping line/block
comments and the `;; Result:`/`;; ⇒` markers and collapsing whitespace runs (translators localise comments,
markers, and alignment; the executable code must not diverge). Real divergences (translated string literals, an
en-only `(and 1 . 2)` example, a ko/ru-only `'apple` block, the incomplete ru syntax page) are explicitly
pinned. Accept ` ```lispex ` and ` ```clojure ` fences.
Snippets run unmodified (the interpreter binds every documented alias). **★ Comparison (must-fix
guard):** the expected annotation is a **restricted expectation language** — literals, quoted data, vectors,
bytevectors, `(values …)`, and error codes only — compared by value; **plus** a canonical `write` string
compare. Do NOT allow arbitrary procedure evaluation in the expectation (it would mask bugs where program and
expectation share a broken procedure).

v1.2.4 exports the canonical English doc/corpus subset plus authored TCO/control goldens as
`conformance/lispex.conformance.manifest.v0.json`, specified by `CSK-CONFORMANCE-MANIFEST.md`.
The manifest is input for a future conformance checker; it does not ship that checker or
claim Meaning Graph lowering.

v1.2.7 adds a native-only `lispex eval-graph` command specified by
`CSK-MEANING-ENVIRONMENT.md`. It evaluates canonical Meaning Graph v0 JSON bytes with a
bounded Meaning Environment report. This is a second internal reference path for the lowered
subset, not a replacement for the interpreter and not a claim that both paths capture the
whole same meaning.

v1.2.8 adds a native-only `lispex diff-receipt` command specified by
`CSK-DIFFERENTIAL-RECEIPT.md`. It records transcript agreement for the lowered subset inside
the shared Rust reference substrate; it is not evidence from another implementation.
Native receipt generation may use a separately pinned step limit for the
Meaning Environment comparison while `eval-graph` keeps its default report
limit; receipt JSON records the actual limit used, and this is not a tail-call
implementation claim.

## 14. Legacy Reader Metadata

Older source files may contain reader metadata beyond the version marker. The
runtime records that metadata for diagnostics and regression tests, but v1.3
does not expose a compatibility mode or promise alternate expansion behavior.
The checked Core Semantic Kernel Profile has one public normalization path, and `case` uses
the hidden `eqv?` intrinsic in that path.

## 15. v1.2 scope

**In:** reader + deterministic normalization (hygienic), the 13 core forms, full exact int/rational + f64,
guaranteed TCO, multiple values, escape-only `call/cc` + cleanup `dynamic-wind`, `(error)`, the §10 stdlib +
friendly aliases, `display`/`write`/`newline`/`println`, the three-family conformance corpus, the wasm
playground.
**Added in v1.2:** the recoverable error-handling system — `raise` / `raise-continuable` /
`with-exception-handler` / `guard` + error objects (§8).
**Out (v2):** full multi-shot `call/cc` + `dynamic-wind` re-entry (top cut),
`read`/`input`, transcendentals, bytevector mutation + copy/append + utf8 codecs,
EXACT Unicode case folding only (the `char-foldcase`/`string-foldcase`/`char-ci…?`/`string-ci…?` family ships with an ASCII-exact lowercase approximation).

**wasm32 recursion profile (R8).** Native targets reach the logical `CALL_DEPTH_LIMIT = 10_000` for non-tail
recursion by growing the host stack on demand (`stacker`, see `eval::Interp::eval`). On `wasm32` there is no
real stack to grow, so the build instead **pins a smaller, fixed `CALL_DEPTH_LIMIT = 512`** (`cfg(target_arch
= "wasm32")`) set EMPIRICALLY below the wasm stack-overflow depth, and drops the `stacker` dependency (it is a
no-op there and pulls a host-only C toolchain wasm doesn't need). The number is measured, not estimated: the
original `2_000` sat _above_ the overflow depth and trapped instead of faulting (caught by `wasm/verify.mjs`).
The trap depth is shape-dependent — `dynamic-wind`/`call/cc`/`call-with-values`/HOF wrappers push uncounted host
frames around each counted `eval`, so they overflow at a much lower counted depth than plain non-tail recursion;
`512` is pinned under the worst measured wrapper case, and `wasm/verify.mjs` probes those shapes (each in a fresh
process) to keep the margin honest. A deep non-tail recursion therefore returns the same clean
`recursion-limit file:line:col …` diagnostic the native build gives — **never** a wasm trap / blank crash. The
bound value is a host-resource ceiling, not part of the language contract; determinism holds **within each
build profile** (every wasm run faults at the same depth). The `lispex-wasm` cdylib (`wasm/`) wraps the library
in a `run_lispex(src) -> { output, diagnostics, ok }` export that mirrors `bin/lispex.rs::run` (capturing
stdout/diagnostics) and drives the browser playground.

## 16. Implementation order

R1 Rust scaffold + reader/lexer · R2 hygienic normalizer (surface → Core AST) · R3 evaluator core
(`Eval<Outcome>`, cells, closures, TCO trampoline, core forms) · R4 numeric tower + pinned formatter ·
R5 stdlib + aliases · R6 error model + escape `call/cc` + `dynamic-wind` · R7 conformance corpus + harness ·
R8 wasm playground. Every choice above is engineered so a later **external backend**
implementability probe can transliterate the interpreter shape and consume Lispex receipts
without changing the language contract.
