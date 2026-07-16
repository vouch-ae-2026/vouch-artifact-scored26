# CSK Meaning Graph Contract v0

> Status: v1.2.14 compatible expansion of the v1.2.5 contract slice.
> This document specifies the public graph schema used by the checked profile
> subset. It does not by itself define source lowering or execution semantics.
> For the full Lispex language, the Rust reference interpreter remains the
> operational authority.

## 1. Scope And Non-Goals

Meaning Graph v0 is a structural contract for a future Lispex checked profile
lowering path. It is deliberately smaller than Lispex Core and covers only:

- literals
- references
- calls
- conditionals
- fixed-arity lambdas
- parallel lets
- blocks
- bindings
- source anchors

Known v0 exclusions: `set!`, `guard`, `letrec`, variadic lambdas,
mutation, continuations, host input as a graph node, and full Core Semantic Kernel coverage
are outside this schema as of v1.2.14. The schema admits closure and `let`
shape; the Meaning Environment contract defines the bounded lexical execution
semantics. The v1.2.12+ host input is bound externally as `user:input`, so it does
not add a Meaning Graph node kind.

This slice specifies graph shape and the minimal Meaning Law v0 needed to reject
malformed graph artifacts. It does not implement Core-to-Meaning-Graph lowering,
Meaning Environment execution, semantic equivalence, independent witnessing,
external backend reporting, target-code generation, full Core Semantic Kernel coverage, or any private
implementation detail.

## 2. Tags And Reserved Domains

The graph tag is:

```text
csk.meaning-graph/v0
```

The graph hash domain is:

```text
csk/meaning-graph-hash/v0
```

The graph hash preimage is specified by `CSK-MEANING-LOWERING.md` as
`csk/meaning-graph-hash/v0\0<meaning-graph-json-bytes>`.

The graph hash domain is used only with the lowering contract's deterministic
graph JSON bytes. A later breaking change to graph bytes or hash preimages must
mint a new graph contract tag.

## 3. Container And Serialization

A Meaning Graph v0 artifact is a JSON object:

```json
{
  "meaning_graph": "csk.meaning-graph/v0",
  "nodes": [],
  "roots": []
}
```

Rules:

- `nodes` is an array. Node references are 0-based integer indexes into this
  array.
- `roots` is a non-empty array of node indexes. Root order is meaningful.
- JSON is UTF-8, two-space pretty-printed, and ends with exactly one trailing
  newline in fixtures.
- Object keys use the order shown in this document and in the fixtures.
- Artifacts must not include absolute paths, timestamps, host names, or
  platform-specific newlines.

## 4. Nodes

Every node is a JSON object with a `kind` string and optional `anchor`.
Unknown node kinds and unknown fields are illegal.

### 4.1 `lit`

```json
{
  "kind": "lit",
  "datum": "1",
  "anchor": { "file": "example.lspx", "line": 1, "col": 1 }
}
```

`datum` is Canonical Core v0 datum text as specified by
`CSK-CANONICAL-CORE.md` literal encoding. It is text, not a JSON number, so exact
integers, rationals, finite reals including `-0.0`, characters, strings,
symbols, lists, vectors, and bytevectors keep their canonical byte form.
Execution-only values and cyclic aggregate markers are illegal.

### 4.2 `ref`

```json
{
  "kind": "ref",
  "name": { "space": "user", "text": "x" }
}
```

`name` is one of:

```json
{ "space": "user", "text": "x" }
{ "space": "temp", "index": 0 }
{ "space": "intrinsic", "name": "cons" }
```

User names are UTF-8 text with no Unicode normalization or case folding. Temp
names use a non-negative decimal index. Intrinsic names are the closed set:

```text
cons
append
list->vector
eqv?
+ - * /
= < > <= >=
equal? assoc assv member memv not
string=? string<?
null? pair?
car cdr list length
list? string? number? boolean? symbol?
min max abs quotient remainder floor ceiling round truncate
map filter reduce fold-left fold-right apply values call-with-values any? all?
```

`assq` and `memq` are deliberately absent from this closed set because the CSK
Profile does not admit `eq?`-based lookup intrinsics.

A `ref` is name-level only. Binding visibility and closure capture are defined
by the Meaning Environment, not by this graph node alone.

### 4.3 `call`

```json
{
  "kind": "call",
  "op": 1,
  "args": [0]
}
```

`op` is the operator node index. `args` is an ordered array of argument node
indexes.

### 4.4 `if`

```json
{
  "kind": "if",
  "test": 0,
  "then": 1,
  "else": 2
}
```

`test`, `then`, and `else` are node indexes. The node records conditional
control shape only; truthiness and short-circuit execution behavior are defined
by the Meaning Environment contract, not by the graph schema alone.

### 4.5 `lambda`

```json
{
  "kind": "lambda",
  "formals": [{ "space": "user", "text": "x" }],
  "body": 0
}
```

`formals` is an ordered array of non-intrinsic name objects. It represents fixed
arity only; dotted or variadic source lambdas are outside the v1.2.11 lowering
profile. Formal names must be unique within the lambda.

### 4.6 `let`

```json
{
  "kind": "let",
  "bindings": [
    {
      "name": { "space": "user", "text": "x" },
      "value": 0
    }
  ],
  "body": 1
}
```

`let` is parallel binding shape. Binding names are non-intrinsic name objects and
must be unique within the `let`. Initializer values are child nodes evaluated in
the outer environment by the Meaning Environment.

### 4.7 `block`

```json
{
  "kind": "block",
  "body": [0, 1]
}
```

`body` is a non-empty ordered array of node indexes.

### 4.8 `bind`

```json
{
  "kind": "bind",
  "name": { "space": "user", "text": "x" },
  "value": 0
}
```

`bind` connects a name object to a value node. A bind node is legal only as a
direct item of a `block.body`. It cannot be a root, a call operator, a call
argument, another bind value, or a direct child through any other edge. v0 does
not define mutation. Visibility, prebinding, and evaluation order are defined by
the Meaning Environment.

### 4.9 Source Anchors

```json
{
  "file": "examples/simple.lspx",
  "line": 43,
  "col": 1
}
```

`anchor` is optional. When present, `line` and `col` are 1-based positive
integers. `file` is optional and must be a repository-relative forward-slash
path when present. Anchors are provenance metadata only; they do not claim that
any source program has already been lowered to this graph.

## 5. Meaning Law v0

A graph satisfies Meaning Law v0 only if all rules below hold:

- `meaning_graph` equals `csk.meaning-graph/v0`.
- The only top-level fields are `meaning_graph`, `nodes`, and `roots`.
- `nodes` is an array and `roots` is a non-empty array.
- Every root is an integer index in range.
- Every node has a legal closed `kind`.
- Every node has exactly the fields allowed for its kind plus optional
  `anchor`.
- Every node edge is an integer index in range.
- Every child index is lower than the parent node index. This topological order
  makes cycles structurally illegal.
- Every node is reachable from at least one root.
- `block.body` is non-empty.
- `bind` nodes are referenced only as direct `block.body` items and are never
  roots.
- `lit.datum` is Canonical Core v0 datum text and does not encode
  execution-only values or cycle markers.
- `ref.name` and `bind.name` use a legal name object. `bind.name.space` cannot
  be `intrinsic`.
- `lambda.formals` is an array of unique non-intrinsic name objects.
- `let.bindings` is an array of objects with unique non-intrinsic `name` fields
  and `value` child indexes.
- `anchor.line` and `anchor.col`, when present, are positive integers.

## 6. Fixtures

`meaning-graph/fixtures/valid/*.json` contains hand-authored valid graphs.
`meaning-graph/fixtures/invalid/*.json` contains wrappers with
`expected_error` and `graph` fields. Invalid fixtures must fail for the expected
Meaning Law rule.

Fixtures are hand-authored. They must not be generated from the current Rust
interpreter or from a hidden lowering implementation.

The fixture checker uses a narrow syntactic guard for `lit.datum`
fixtures. It does not replace the full Canonical Core datum parser that a later
lowering slice must use before emitting graph artifacts.

## 7. Boundary

Meaning Graph v0 attests only:

- public graph shape
- minimal graph legality rules
- fixed-arity closure graph shape
- parallel-let graph shape
- source-anchor metadata shape
- reserved graph tag and hash domain

Meaning Graph v0 excludes:

- `core-to-graph-lowering`
- `meaning-environment-execution`
- `semantic-equivalence`
- `independent-witness`
- `external-backend-reporting`
- `target-code-generation`
- `full-cskernel-coverage`
- `private-implementation-detail`

## 8. Versioning

The schema tag remains `/v0` while compatible clarifications and non-normative
metadata are added. A breaking schema change must mint a new tag.
