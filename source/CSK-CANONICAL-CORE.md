# Lispex Canonical Core Contract v0

> Status: v1.2.2 contract slice.
> This document specifies the byte-level Canonical Core format and hash domains
> for later receipt work. It does not change runtime semantics and does not by
> itself compute receipts.

## 1. Scope And Non-Goals

Canonical Core v0 is the deterministic byte representation of Lispex **normalized
Core**, after reader and normalizer success.

Included:

- The ordered top-level list of normalized `CoreExpr` nodes.
- Each `CoreKind` variant and its child order.
- `Ident::User`, `Ident::Temp`, and `Intrinsic` identity.
- Literal datum structure as represented by `Value::write_repr`.

Excluded:

- Source text, comments, whitespace, file paths, and spans.
- Runtime values, stdout, diagnostics, traces, timing, or host environment.
- Meaning Graph, Meaning Environment, Receipt CLI, external backend witness data, or any
  target-language code generation.

This is a syntactic-normalization contract. It must not be described as a
semantic proof or as full Core Semantic Kernel coverage.

## 2. Domain Tags

The canonical format tag is:

```text
lispex.core.canonical/v0
```

The hash domain separation strings are:

```text
lispex/core-hash/v0
lispex/source-hash/v0
lispex/runtime-hash/v0
lispex/engine-version/v0
```

Only `lispex/core-hash/v0` is specified in this document. The source/runtime
domains are specified by `CSK-RECEIPT.md`; `lispex/engine-version/v0` remains
reserved so future engine-version hashes cannot collide with the Core hash
domain.

## 3. Canonical Program Bytes

Canonical program bytes are UTF-8 bytes formed as:

```text
lispex.core.canonical/v0\n
<core-expr-0>\n
<core-expr-1>\n
...
<core-expr-n>\n
```

Rules:

- The format tag is ASCII exactly as written.
- `\n` is byte `0x0a`.
- There is exactly one trailing newline after the tag and after every top-level
  Core expression.
- An empty program is valid and serializes to only the tag line plus its newline.
- No byte order mark, CRLF, indentation, extra spaces, or comments are emitted.

## 4. Core Expression Grammar

The grammar below is byte grammar, not reader grammar. Terminals are ASCII unless
the literal writer emits UTF-8 content.

```text
core-expr   = var
            / quote
            / if
            / lambda
            / app
            / begin
            / set
            / define
            / let
            / letrec
            / values
            / intrinsic
            / guard

var         = ident
quote       = "(quote " datum ")"
if          = "(if " core-expr " " core-expr " " core-expr ")"
lambda      = "(lambda " formals " " core-expr ")"
app         = "(" core-expr *( " " core-expr ) ")"
begin       = "(begin" 1*( " " core-expr ) ")"
set         = "(set! " ident " " core-expr ")"
define      = "(define " ident " " core-expr ")"
let         = "(let (" binding-list ") " core-expr ")"
letrec      = "(letrec (" binding-list ") " core-expr ")"
values      = "(values" *( " " core-expr ) ")"
intrinsic   = "#<intrinsic:" intrinsic-name ">"
guard       = "(guard (" ident *( " (" core-expr " " core-expr ")" )
              [ " (else " core-expr ")" ] ") " core-expr ")"

binding-list = [ binding *( " " binding ) ]
binding      = "(" ident " " core-expr ")"
formals      = "()"
             / "(" ident *( " " ident ) ")"
             / "(" [ ident *( " " ident ) " " ] ". " ident ")"
```

`begin` has one or more children because empty source bodies normalize to
`(values)`, not to empty begin.

## 5. Identifier And Intrinsic Encoding

`Ident::User(name)` emits the interned source name bytes exactly as Unicode UTF-8,
with no case folding and no Unicode normalization.

`Ident::Temp(n)` emits:

```text
#:t<n>
```

where `<n>` is the base-10 ASCII representation of the deterministic normalizer
temp counter, with no leading zeros except the value `0`.

`Intrinsic` emits one of:

```text
#<intrinsic:cons>
#<intrinsic:append>
#<intrinsic:list->vector>
#<intrinsic:eqv?>
```

Temp identifiers and intrinsic forms are byte-level Core tokens. Source programs
cannot introduce them through the reader.

## 6. Literal Encoding

`datum` is the `Value::write_repr` representation for literal data. Canonical Core
v0 inherits these pinned v1.2 writer rules:

- Booleans: `#t` or `#f`.
- Exact integers: base-10 ASCII, optional leading `-`, no leading `+`, no leading
  zeros except `0`.
- Exact rationals: `<numerator>/<denominator>`, reduced to lowest terms, sign on
  numerator, denominator greater than `1`.
- Inexact finite reals: `format_real` positional decimal form: never exponent
  notation, integral values end in `.0`, and `-0.0` is preserved.
- Characters: `#\space`, `#\newline`, `#\tab`, `#\return`, `#\null` for
  those five scalar values; `#\x<hex>` with lowercase hex digits and no leading
  zeros for every other scalar value below `0x20` and for `0x7f`; otherwise
  `#\` followed by the character glyph as UTF-8.
- Strings: double-quoted; `"` `\` newline tab carriage-return escaped as
  `\"` `\\` `\n` `\t` `\r`; all other scalar values, including other valid
  control scalars such as NUL, are emitted as UTF-8 bytes.
- Symbols: interned name bytes exactly as UTF-8, with no normalization.
- Empty list: `()`.
- Pairs and proper/dotted lists: `(<datum> ...)` or `(<datum> ... . <datum>)`.
- Vectors: `#(<datum> ...)`. The mutable flag is excluded.
- Bytevectors: `#u8(<byte> ...)` with decimal bytes `0` through `255`.

Execution-only values (`Closure`, `Primitive`, `Cont`, `ErrorObject`) are not
valid literal payloads in normalized Core quote nodes for source-derived
Canonical Core v0. Cyclic aggregates are also unreachable from source-derived
literals because the reader has no datum labels. If a future serializer
encounters execution-only values or the writer's vector cycle marker case
(`#(...)`), it must report an internal serialization fault instead of emitting
procedure-like placeholders or ambiguous cycle markers.

## 7. Determinism Rules

Canonical Core v0 is deterministic if and only if:

- A program is one `normalize_program` invocation over the reader's full
  top-level datum sequence after module flattening.
- Reader and normalizer inputs are the same logical source bytes. The v1.2
  reader does not strip a byte order mark and does not normalize newlines; the
  v1.2.3 source hash preimage must be defined over raw source bytes.
- Normalization succeeds without diagnostics.
- The normalizer's temp counter starts at zero for each program and increments in
  the existing deterministic traversal order.
- Top-level Core expressions keep normalized program order.
- Child vectors keep AST order; maps/sets must not influence output ordering.
- All emitted text is encoded as UTF-8.
- The literal writer uses the pinned v1.2 `Value::write_repr` and `format_real`
  rules.

The contract is `same normalized Core -> same canonical bytes`. It is not
`same source text -> same bytes` until the reader and normalizer version are also
held fixed by a receipt.

Byte injectivity also relies on these normalizer invariants, which are part of
the v0 contract obligations:

- Syntactic keywords such as `quote`, `if`, `lambda`, `begin`, `set!`, `define`,
  `let`, `letrec`, and `guard` cannot appear as a `var` or binder; violating
  source forms fail normalization with E110.
- `values` in operator position always normalizes to the dedicated `values`
  node; a source `(values ...)` form cannot become an `app` node.
- A guard clause whose printed test would be the bare identifier `else` cannot
  exist as an ordinary test clause. A leading `else` clause is the trailing
  `else` arm, and later `else` clauses are normalization errors.

## 8. Hash Construction

The v0 Core hash algorithm is SHA-256 over:

```text
lispex/core-hash/v0\0<canonical-program-bytes>
```

where `\0` is byte `0x00`. The displayed digest is lowercase hexadecimal, 64
ASCII characters, with no prefix.

The domain separator is part of the hashed bytes but not part of Canonical Core
serialization. This keeps the same canonical bytes reusable while making hashes
non-colliding across source/runtime/core domains.

## 9. Versioning And Stability

This contract is `v0`. Any incompatible change to grammar, literal encoding,
domain strings, or hash construction must mint a new tag such as
`lispex.core.canonical/v1` and `lispex/core-hash/v1`.

Patch releases in the v1.2.x train may clarify this document without changing
the v0 bytes. A byte-changing edit is not a clarification.

## 10. Relationship To `CoreExpr::sexpr`

`CoreExpr::sexpr` is the existing span-free Rust debug/test printer. Its output
resembles the expression grammar above and is useful as a preview, but this
document is the public contract.

For v1.2.2:

- `CoreExpr::sexpr` delegates to the canonical writer but is not itself the
  public serializer contract.
- No runtime path, CLI output, or receipt depends on this contract yet.
- v1.2.3 uses the dedicated canonical writer for receipt hashes.

That separation prevents a debug-printer refactor from silently changing public
hashes.
