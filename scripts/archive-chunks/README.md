# Vouch release-archive chunk tools

These dependency-free Node.js tools publish and verify a D-bound release archive
as deterministic 7 MiB chunks. Every nonfinal chunk is exactly 7,340,032 bytes;
the final chunk contains between one byte and 7 MiB.

```sh
npm run archive:chunk -- \
  --archive /path/to/vouch-scored26-artifact.tar.zst \
  --output-dir release/archive-chunks
npm run check:archive-chunks
npm run archive:reassemble -- \
  --reassemble /path/to/new-release.tar.zst
npm run check:archive-chunks:self-test
```

The input archive name is fixed as `vouch-scored26-artifact.tar.zst`; all other
file and directory basenames are restricted to a portable printable-ASCII token
alphabet. The chunker requires a new output directory and publishes the entire directory
through a same-parent atomic rename after syncing all files and the staging
directory. The verifier rejects non-canonical manifests, extra schema fields,
non-contiguous entries, wrong sizes or hashes, missing files, and symlinks. Its
optional reassembly similarly requires a new destination and only publishes it
after both per-chunk and streaming concatenated verification succeeds. Manifest
decoding rejects malformed UTF-8 and a UTF-8 BOM before schema validation.

The root artifact checker invokes the same streaming verifier and requires the
concatenated archive digest to equal signed descriptor D's `archive_sha256`.
The unchunked archive is an assembly input, not a distributed repository file.
