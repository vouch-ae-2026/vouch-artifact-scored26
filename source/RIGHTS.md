# Source review rights

The first-party files in this directory, including the synthetic history
bundle, are supplied for artifact evaluation, security review, and
reproducibility inspection. For those files, the copyright holders grant each
recipient a limited, non-exclusive permission to download and reproduce them
locally, inspect their history, compile and execute them, and make the
modifications reasonably necessary to perform peer review or artifact
evaluation.

This permission does not allow redistribution of source, binaries, bundles, or
modified copies; commercial or production use; sublicensing; or use unrelated
to peer review or artifact evaluation. No general-purpose open-source license
is granted, and all other rights are reserved. First-party package metadata
therefore remains `UNLICENSED`.

The `vendor/` tree consists of pinned third-party Rust dependencies. Each
vendored package retains its own notices and license terms. Nothing here
narrows or expands those terms.

The packages under `review-toolchain/` are unmodified upstream npm package
trees except that one TypeScript payload is split into byte-exact transport
parts for the hosting file-size limit and reconstructed only in a temporary
review copy. The parts remain TypeScript material under Apache-2.0. TypeScript
5.8.2 uses Apache-2.0; `@types/node`, `undici-types`, Ajv,
`fast-deep-equal`, `json-schema-traverse`, and `require-from-string` use
MIT; `fast-uri` uses BSD-3-Clause. Their exact license files are included
inside their package directories and govern those files.

The source manifest records a rights classification for every distributed
file. Inclusion in this review artifact does not transfer ownership or grant
rights by implication or estoppel.
