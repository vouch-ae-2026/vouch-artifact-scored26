# Lispex Core To CSK Meaning Graph Lowering Contract v0

> Status: v1.2.14 compatible expansion of the v1.2.6 contract slice.
> This document specifies deterministic one-way lowering from the Lispex CSK
> Profile Core subset into Meaning Graph v0. It does not define semantic
> equivalence, a differential receipt, or an independent witness.

## 1. Scope And Non-Goals

`lispex lower [FILE|-]` reads Lispex source, normalizes it with the Rust
reference interpreter, and emits Meaning Graph v0 JSON only when every normalized
Core expression is inside the v0 lowering subset.

Included Core forms:

- `Quote`
- `Var`
- `Intrinsic`
- `App`
- `If`
- `Begin`
- `Define`
- fixed-arity `Lambda`
- parallel `Let`, including normalizer-generated temp-only `Let` used by
  derived forms such as `or` and `case`

Excluded Core forms fault the whole lowering:

- variadic `Lambda`
- `Set`
- `Letrec`
- `Values`
- `Guard`

This is a structural transform only. It does not implement a Meaning Environment
evaluator, graph execution semantics, semantic equivalence, graph-to-Core
inversion, Topaz witnessing, target-code generation, full Core Semantic Kernel coverage, or
private implementation detail.

## 2. Command

```text
lispex lower <file.lspx>
lispex lower -
cat file.lspx | lispex lower -
```

Exit codes:

- `0`: graph JSON emitted to stdout.
- `1`: reader, normalizer, or lowering fault; no graph JSON is emitted.
- `2`: usage, I/O, or UTF-8 failure; no graph JSON is emitted.

The npm/WebAssembly CLI does not claim `lower` support in v1.2.12.

## 3. Graph Container

Every successful program lowers to one synthetic program block root:

```json
{
  "meaning_graph": "csk.meaning-graph/v0",
  "nodes": [],
  "roots": [0]
}
```

An empty program is a lowering fault. The synthetic program block has no source
anchor. All source-derived nodes carry `anchor.line` and `anchor.col`; `anchor.file`
is intentionally omitted so file and stdin lowering have identical graph bytes.

## 4. Node Emission

Node references are 0-based indexes into `nodes`. Lowering emits nodes by
left-to-right post-order depth-first traversal: children are emitted before the
parent that references them. Every occurrence emits a fresh node; v0 lowering
does not intern, share, or deduplicate nodes.

This order makes every edge reference a lower node index and therefore satisfies
Meaning Law v0 child-order without a separate graph rewrite.

## 5. Core Mapping

| Core form | Meaning Graph v0 node |
| --- | --- |
| `Quote(value)` | `lit` with `datum` from Canonical Core v0 datum text |
| `Var(Ident::User)` for a CSK Profile builtin | `ref` with `{ "space": "intrinsic", "name": ... }` |
| `Var(Ident::User)` otherwise | `ref` with `{ "space": "user", "text": ... }` |
| `Var(Ident::Temp)` | `ref` with `{ "space": "temp", "index": ... }` |
| `Intrinsic` | `ref` with `{ "space": "intrinsic", "name": ... }` |
| `App { op, args }` | `call` with lowered `op` and ordered `args` |
| `If(test, then, else)` | `if` with lowered `test`, `then`, and `else` |
| fixed-arity `Lambda { formals, body }` | `lambda` with ordered non-intrinsic `formals` and lowered `body` |
| `Begin(exprs)` | `block` with lowered `body`, non-empty |
| `Define { name, value }` | `bind` with lowered `value` |
| `Let { bindings, body }` | `let` with parallel binding initializers and lowered `body` |

`Define` is legal only as a direct program block body item or direct `Begin`
block body item. Function define syntax normalizes to `Define` whose value is a
fixed-arity `Lambda`, so fixed-arity function definitions lower in v1.2.12.

The CSK Profile reserves its builtin names and the host-input name `input`. A
source `define`, lambda formal, or `let` binding for any of those names faults
as `profile-escape` instead of becoming a graph binding. A source reference to
`input` remains a user reference; v1.2.12 binds it through the host environment,
not through source or graph injection.

The reserved builtin set follows `CSK-PROFILE.md` v1.2.14. `assoc`/`member`
lower to `equal?`-based profile intrinsics, `assv`/`memv` lower to `eqv?`-based
profile intrinsics, and `assq`/`memq` stay outside the checked profile because
`eq?` is not part of the CSK Profile comparison surface.

`Let` lowers as a graph `let` node for both user-authored parallel `let` and
normalizer-generated temp-only `let`. `Letrec` stays outside v1.2.12; recursive
programs are admitted through top-level recursive `define` backed by block
prebinding in the Meaning Environment.

Variadic or dotted lambdas fault as `profile-escape`. The profile accepts only
fixed-arity lambdas until a later slice explicitly widens the public boundary.

`Quote` reuses the Canonical Core v0 literal writer. Execution-only values and
cyclic aggregate markers fault instead of becoming graph data.

## 6. Graph Hash

The Meaning Graph hash domain is:

```text
csk/meaning-graph-hash/v0
```

The v0 graph hash algorithm is SHA-256 over:

```text
csk/meaning-graph-hash/v0\0<meaning-graph-json-bytes>
```

where `\0` is byte `0x00` and `<meaning-graph-json-bytes>` is the deterministic
UTF-8 JSON emitted by this contract.

The graph hash is recorded by `lispex diff-receipt` when lowering succeeds.
The older `lispex receipt` command still does not attest Meaning Graph lowering.

## 7. Goldens And Faults

`meaning-graph/lowering/cases/*.lspx` and
`meaning-graph/lowering/expected/*.json` are hand-authored goldens. The Rust
lowering implementation must match the expected JSON bytes exactly, and the
expected JSON must independently satisfy Meaning Law v0.

`meaning-graph/lowering/faults.json` lists source programs that must fail
lowering, including unsupported Core forms and the empty program. Faults are
structured by lowering fault kind and source line/column, including
`profile-escape` for reserved CSK Profile binders.

Goldens must not be generated by dumping the current lowering implementation.

## 8. Boundary

Core-to-Meaning-Graph Lowering v0 attests only:

- deterministic one-way lowering for the listed Core subset
- Meaning Graph v0 JSON bytes for successful cases
- lowering fault kind and source anchor for unsupported cases
- reserved graph hash preimage

Core-to-Meaning-Graph Lowering v0 excludes:

- `meaning-environment-execution`
- `graph-execution-semantics`
- `semantic-equivalence`
- `graph-to-core-inversion`
- `differential-receipt`
- `independent-witness`
- `topaz-reporting`
- `target-code-generation`
- `full-cskernel-coverage`
- `private-implementation-detail`

## 9. Versioning

The lowering contract remains `/v0` while compatible clarifications and
additional subset goldens are added. A breaking change to graph bytes, lowering
coverage, node emission order, or hash preimage must mint a new lowering
contract tag.
