# Lispex Receipt Contract v0

> Status: v1.2.3 contract slice.
> This document specifies the native Rust `lispex receipt` output. It does not
> claim Meaning Graph lowering, independent witnessing, or semantic proof.

## 1. Scope And Non-Goals

`lispex receipt [FILE|-]` reads source bytes, parses and normalizes them with the
Rust reference interpreter, evaluates the program when possible, and writes one
JSON receipt to stdout.

The receipt attests only:

- Source bytes as read by the Rust CLI.
- Canonical Core v0 bytes when reader and normalizer succeed.
- Runtime stdout transcript bytes when evaluation succeeds.
- Diagnostics and engine metadata produced by this reference interpreter.

The receipt excludes semantic equivalence, Meaning Graph lowering, Meaning
Environment execution, external backend witnessing, target-language generation, timing, host
identity, and any patent/private-track implementation detail.

## 2. Command And Exit Codes

```text
lispex receipt <file.lspx>
lispex receipt -
cat file.lspx | lispex receipt
```

Exit codes:

- `0`: receipt emitted and runtime status is `ok`.
- `1`: receipt emitted with reader, normalizer, or runtime diagnostics.
- `2`: usage, I/O, or UTF-8 failure; no receipt is emitted.

Program stdout is captured into the receipt runtime transcript. The only stdout
bytes written by the command are the receipt JSON plus its trailing newline.

## 3. Hash Domains And Preimages

Every hash uses SHA-256, lower-case hexadecimal, and the preimage shape:

```text
<domain>\0<payload-bytes>
```

Domains:

- Source hash: `lispex/source-hash/v0`
- Canonical Core hash: `lispex/core-hash/v0`
- Runtime stdout transcript hash: `lispex/runtime-hash/v0`

Source hash payload is the raw file/stdin byte sequence. The CLI does not remove
a byte order mark and does not normalize newlines. Source bytes must be valid
UTF-8 to continue past source hashing; invalid UTF-8 is exit code `2` with no
receipt.

Canonical Core hash payload is the Canonical Core v0 program bytes specified in
`CSK-CANONICAL-CORE.md`.

Runtime hash payload is the exact stdout transcript that successful `lispex run`
would produce: side-effect output followed by auto-printed values in the same
per-top-level-form order. Diagnostics and warnings are not part of the runtime
hash payload.

`lispex/engine-version/v0` remains reserved. Receipt v0 reports engine metadata
as plain JSON fields, not as a fourth hash. v1.2.13 adds required git commit
metadata to the engine object so local artifacts can identify the implementation
revision that emitted them. From v1.3.2, native Rust release binaries record the
release build commit, not the user's current working-directory git state.
Repository golden-generation overrides may still set `LISPEX_ARTIFACT_COMMIT_*`
explicitly.

The receipt JSON bytes are not a hash preimage. Field order and pretty-printing
may change without changing the three hash values.

This native `lispex.receipt/v0` artifact is distinct from the committed CSK
Profile report/receipt family frozen in `CSK-SPEC-FREEZE.md`. v1.2.16 defines
`csk.artifact-json/v0` report/receipt preimages for committed
`csk.meaning-env-report/v0`, `csk.differential-receipt/v0`,
`csk.verify-report/v0`, and `csk.replay-report/v0` artifacts only. Ad-hoc native
receipt JSON remains outside that report self-hash family.

## 4. JSON Schema

The v0 receipt has this shape:

```json
{
  "receipt": "lispex.receipt/v0",
  "engine": {
    "name": "lispex-rust-reference",
    "version": "1.2.x",
    "canonical_format": "lispex.core.canonical/v0",
    "commit": {
      "vcs": "git",
      "hex": "<40-hex-full-oid>",
      "dirty": false
    }
  },
  "source": {
    "path": "program.lspx",
    "byte_len": 12,
    "hash": {
      "domain": "lispex/source-hash/v0",
      "algo": "sha-256",
      "hex": "..."
    }
  },
  "canonical": {
    "status": "ok",
    "byte_len": 42,
    "hash": {
      "domain": "lispex/core-hash/v0",
      "algo": "sha-256",
      "hex": "..."
    }
  },
  "runtime": {
    "status": "ok",
    "transcript_byte_len": 3,
    "hash": {
      "domain": "lispex/runtime-hash/v0",
      "algo": "sha-256",
      "hex": "..."
    }
  },
  "diagnostics": [],
  "boundary": {
    "attests": ["source-bytes", "canonical-core-v0-bytes", "stdout-transcript"],
    "excludes": [
      "semantic-equivalence",
      "meaning-graph-lowering",
      "independent-witness"
    ]
  }
}
```

Stage status values:

- `canonical.status`: `ok`, `read-error`, `normalize-error`.
- `runtime.status`: `ok`, `error`, `not-run`.

When a stage does not produce bytes, its hash and byte length fields are omitted.

Diagnostic entries use:

```json
{
  "severity": "error",
  "code": "E100",
  "file": "program.lspx",
  "line": 1,
  "col": 1,
  "message": "..."
}
```

Warnings use severity `warning`. Runtime errors use their `E3xx` or
`recursion-limit` code. Reader and normalizer diagnostics use `E1xx` codes.

## 5. Native First

v1.2.3 closes on the native Rust CLI. The npm/WebAssembly CLI shares the version
surface but does not claim `receipt` support unless a later slice explicitly
adds it.
