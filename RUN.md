# Running the Vouch SCORED26 artifact

Treat an extracted artifact as untrusted input. Use a disposable VM or
container without credentials, signing keys, SSH material, cloud variables,
repository tokens, or a valuable home directory. The supplied checkers scrub
their subprocess environments, but a host run is not an operating-system
network sandbox.

## Requirements

- Node.js 22.x and npm 10.x;
- Git with SHA-1 bundle support;
- a case-sensitive filesystem;
- Rust 1.85.1 for `check:source-full`;
- Docker with a local `linux/amd64` image whose image ID equals D's
  `build_image_sha256`, for the pinned phase-1 rerun.

Do not run `npm install`, `npm ci`, or another package installation at the
repository root or directly under `source/`. The root package has no
third-party runtime dependencies. Source checks copy the tree to an operating
system temporary directory, verify and reconstruct the split TypeScript file
there, and create only the nine local links needed for the pinned TypeScript
5.8.2 declarations and Ajv closure.

## 1. Verify the published tree

From the repository root:

```sh
npm run check
```

This verifies the repository manifest; D and R signatures; D→Q→R→P and
S derivations; the passing S fields; generated owner reports; archive chunks
and their equality to D; the D-bound release manifest; exact bundle
reconciliation; source inventory and synthetic history; anonymity and secret
reports; portable source checks; and root tamper negatives.

A successful run ends with:

```text
Vouch artifact verification passed
Vouch artifact tamper negatives passed
```

Any nonzero exit or missing success marker invalidates the check. The command
does not modify the distributed tree and performs no network access or package
download.

## 2. Run the full source lane

After the root check:

```sh
npm run check:source-full
```

The wrapper creates a temporary detached C0 checkout from the distributed
bundle, verifies the F→B→C0 topology and exact C0 bytes, prepares the closed
review toolchain, and runs the artifact, consumer, public-claim, Bridge,
adversarial, Vouch-loop, portable replay, Rust format/lint/test, and full
165-fixture conformance lanes. Temporary `target/`, `node_modules/`, generated
consumer output, and the checkout are removed afterward.

The three projection checks may also be run directly:

```sh
node source/tools/check-source-projection.mjs
node source/tools/check-source-negative.mjs
node source/tools/check-synthetic-checkout.mjs
```

For manual bundle inspection:

```sh
git bundle verify source/synthetic-history/vouch-scored26.bundle
git bundle list-heads source/synthetic-history/vouch-scored26.bundle
```

The listed head must be
`3e910c9ff87cc01d3bc241d63297218b44e75ede HEAD`.

## 3. Verify or reassemble the D-bound archive

Verify all 59 parts without writing the unchunked archive:

```sh
npm run check:archive-chunks
```

To reconstruct it, choose a parent directory that already exists and a final
file path that does not:

```sh
npm run archive:reassemble -- \
  --reassemble <new-output-path>/vouch-scored26-artifact.tar.zst
```

The tool validates canonical manifest JSON, contiguous indexes, regular-file
types, every part's byte count and SHA-256, and the concatenated identity
before publishing the output with no replacement. The expected reconstructed
identity is:

```text
bytes   429428296
sha256  49e9e1fd9e669b2da168d8763f4c61f88b95944f566a3e44232f3a8c443740ad
```

`npm run check` additionally requires that identity to equal the authenticated
descriptor D's `archive_sha256`. Do not extract or execute an archive that
fails either check.

The chunk transport's own positive and negative controls are available as:

```sh
npm run check:archive-chunks:self-test
```

## 4. Rerun release phase 1 on pinned Linux

Phase 1 re-executes the clean-room experiment from the authenticated archive.
It needs no release private key and does not create new release signatures.
The pinned image must already be available locally; obtaining or building that
image is outside the network-disabled run, and its local image ID must exactly
equal `release/chain/release-descriptor.json` field
`build_image_sha256`. Replace every angle-bracket placeholder below with an
absolute path or the named value from D; do not type the brackets literally.

First create a clean C0 checkout and trusted bootstrap. Both destination paths
below must not already exist:

```sh
git clone \
  <artifact-root>/source/synthetic-history/vouch-scored26.bundle \
  <c0-checkout>
git -C <c0-checkout> checkout --detach \
  3e910c9ff87cc01d3bc241d63297218b44e75ede

(
  cd <c0-checkout>
  cargo build --frozen --offline --release \
    -p scored26-release-anchor --bin scored26-archive-snapshot
  npm run scored26:prepare-bootstrap -- \
    --out-dir <trusted-bootstrap> \
    --snapshot-helper target/release/scored26-archive-snapshot
)
```

Create a fresh phase-1 directory. Reassemble the archive into it, then copy the
three public bootstrap objects without renaming them:

```sh
mkdir <phase1-root>
(
  cd <artifact-root>
  npm run archive:reassemble -- \
    --reassemble <phase1-root>/vouch-scored26-artifact.tar.zst
)
cp <artifact-root>/release/chain/trust-policy.json <phase1-root>/
cp <artifact-root>/release/chain/release-descriptor.json <phase1-root>/
cp <artifact-root>/release/chain/release-descriptor.dsse.json <phase1-root>/
```

Read the four authenticated runtime values from D and supply them exactly in
the following command. `<pinned-image-reference>` must resolve to the local
image whose ID equals `<D.build_image_sha256>`.

```sh
docker run --rm --platform=linux/amd64 --network=none \
  -e SCORED26_NETWORK_DISABLED=1 \
  --mount type=bind,source=<phase1-root>,target=/opt/vouch-scored26/clean-room \
  --mount type=bind,source=<trusted-bootstrap>,target=/opt/vouch-scored26/trusted-bootstrap,readonly \
  <pinned-image-reference> \
  node /opt/vouch-scored26/trusted-bootstrap/cleanroom-release.mjs \
    --clean-room-root /opt/vouch-scored26/clean-room \
    --archive /opt/vouch-scored26/clean-room/vouch-scored26-artifact.tar.zst \
    --snapshot-helper /opt/vouch-scored26/trusted-bootstrap/scored26-archive-snapshot \
    --trust-policy /opt/vouch-scored26/clean-room/trust-policy.json \
    --descriptor /opt/vouch-scored26/clean-room/release-descriptor.json \
    --descriptor-envelope /opt/vouch-scored26/clean-room/release-descriptor.dsse.json \
    --build-image-sha256 <D.build_image_sha256> \
    --os-image-reference <D.build_parameters.os_image_reference> \
    --linker '<D.build_parameters.linker>' \
    --npm /usr/local/bin/npm \
    --time /usr/bin/time
```

The container has only loopback networking. Its `npm ci` uses the archive-local
cache inside the authenticated archive with `--offline`; Cargo uses the
vendored closure with `--frozen --offline`.

A passing run prints:

```text
SCORED26 phase-1 clean-room gate passed
```

It writes regenerated artifacts under `<phase1-root>/phase1-results/` and
publishes these two outer-driver records:

```text
<phase1-root>/external/exact-reproduction-comparisons.json
<phase1-root>/external/clean-run-report.json
```

Every deterministic comparison must match before Q is published. Phase 1 also
regenerates fixture, workload, mutation, and performance owner reports, checks
the source worktree and public-data boundary, and records that the release key
was absent. It deliberately does not read or create R, P, the paper, or S; a
passing Q is therefore not a replacement for the distributed terminal
`S=pass` verdict. Regenerating signed D or R requires a separately chosen
private key and produces a different release identity.

The retained phase-1 log also preserves npm deprecation and security notices
emitted while replaying the pinned monorepo lockfile, including notices for
Next.js 14.2.4, older `glob` releases, and ESLint 8.57.1. This lifecycle is not
a dependency-vulnerability audit, and the notices do not by themselves show
whether those packages are used or reachable on the Vouch execution path.

## Expected scope and limitations

Portable host checks verify implementation and record consistency; only the
pinned, network-disabled Linux path reproduces the release environment. The
artifact checks observed evaluator agreement on the declared surface, not a
formal equivalence theorem. They do not validate real-world input truth,
policy fairness, freshness, external transparency, trusted time, deployment
state, or security after compromise of an authorized signing key.
