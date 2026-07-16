# Path-neutral lifecycle command record

This record is generated from the retained lifecycle logs and canonical
structured objects. Angle-bracket names deliberately replace host paths. No
release-key path or private-key bytes are included. D and R are signed; Q, P,
and S are canonical digest/derivation-checked reports.

## Fixed identities

- Release source C0: `3e910c9ff87cc01d3bc241d63297218b44e75ede`
- Workload freeze F: `c90f97ddd6b1d662791a76fe4663b90e79c443ec`
- Contract SHA-256: `ecc294798be49f5843bd84e0ebad5d94a930f2b09f51db4852e42d2789addddc`
- Image: `scored26-release@sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e`
- Base: `ubuntu@sha256:6015f66923d7afbc53558d7ccffd325d43b4e249f41a6e93eef074c9505d2233`
- Platform: `linux/amd64`
- Preliminary `npm ci --offline` network: `none`
- Assembly network: enabled for lockfile/cache population before D
- Phase 1/2/3 and final-scan network: `none`
- Release key ID: `sha256:dfad0e0c05811e9c83c5733eaf2e5009a9bf11c8877278400116d66d774bd982`

## Assembly: archive A and signed descriptor D

`docker run --platform=linux/amd64 --mount <CLEAN_ROOM> --mount <RELEASE_KEY_FILE:read-only> scored26-release@sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e npm run scored26:assemble-release -- <pinned arguments>`

- Network is enabled only at this assembly boundary so the locked dependency
  cache can be populated before D is emitted.
- Marker: `SCORED26 release assembled`
- Exit: `0`, established by the retained marker under the wrapper's
  `set -euo pipefail` boundary.
- A: `sha256:49e9e1fd9e669b2da168d8763f4c61f88b95944f566a3e44232f3a8c443740ad`
- D payload: `sha256:daca8fa97901d6396abd7e64c27cbd692929a23b70de82cc16f0d158220fd5ae`
- D envelope: `sha256:8803773addc832543b66c99a6ab7a16ef3e6fea3f0dcce70e697d3a87102b99c`

## Exact review-bundle reconciliation

The required distributed review bundle was compared byte-for-byte with
`release/vouch-scored26.bundle` safely extracted from archive A. The archive's
canonical `artifact/release-manifest.json` row agrees with the same byte count
and digest.

- Review bundle: `sha256:18f40298fcf9e4d919fc9e5e0a1ac6b29c47b081daeaa402da017b3940a7f26a`, `7778554` bytes
- Release manifest: `sha256:2397c200d4cac10e4b5d1e1d5261fb7c99a6340fb80a363592ae5ce36a2544fb`
- Reconciliation: `sha256:3f38a57cfb1b36d432de73f8f253235aafb27fab8fdc1a955fa4d275a17f2279`, status `pass`
- Boundary: `release_archive_equivalent=true` and
  `release_chain_authenticated=true` apply only to the exact distributed
  review bundle bytes, not to the whole source projection.

## Phase 1: key-absent pinned clean room

`docker run --platform=linux/amd64 --network=none --mount <PHASE1_CLEAN_ROOM> --mount <TRUSTED_BOOTSTRAP:read-only> scored26-release@sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e node <TRUSTED_BOOTSTRAP>/cleanroom-release.mjs <pinned arguments>`

- Marker: `SCORED26 phase-1 clean-room gate passed`
- Exit: `0`, established by the retained marker under `pipefail`.
- Runtime: `5122` seconds
- Q: `sha256:f0414f051e062f7b98a32f44b04ff526da79a61a6af00f2d95b62b024cc9ec2c`
- Exact comparisons: `sha256:634bb491aa90a02c69533e099bcdf759fa825991b30cbb294fc64aea7387128b`
- Fixture/workload/mutation/performance reports: `sha256:f6dc99af7c81ce6f0b8a8a580dba8e5c73b9f2fc9f597ac49676ee5dd07f55f7`, `sha256:60aaa12d73d36f3183b5bac04e447d70aece9da2a9cc4c5841548fb84047b0fb`, `sha256:4b8604da8b97fc6550f52005c88166a65592e8cc7b97def0338c908597e75fd4`, `sha256:3c4c5bc8e487341acd998657fee61a1653675c4bd1fb58816252e00c2656e6ec`

## Phase 2: signed observation R and publication index P

`docker run --platform=linux/amd64 --network=none --mount <RELEASE_ROOT> --mount <SOURCE_ROOT:read-only> --mount <RELEASE_KEY_FILE:read-only> scored26-release@sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e npm --prefix <SOURCE_ROOT> run scored26:finalize-observation -- <D/Q/report inputs>`

- Marker: `SCORED26 reproduction observation finalized`
- Exit: `0`, established by the retained marker under `pipefail`.
- R payload: `sha256:ff36863387b2d865a817d699e8d7ba73ceeb42dc4c3e78818293f01727fd7e81`
- R envelope: `sha256:4f2ccc76556fd88b836497c57b9439fcbf7e56517f44076d0a776db3275c90a5`
- P: `sha256:9855f8f3d67c64c87931f4347cbaebe31cf904a7586d962092ea5a42644f4a22`

## Phase 3: machine PDF and terminal report S

`docker run --platform=linux/amd64 --network=none --mount <RELEASE_ROOT> --mount <SOURCE_ROOT:read-only> scored26-release@sha256:c40e87e9fbdf67f18850020696984308eda72bd8e9f89acc2b69c46bc550108e npm --prefix <SOURCE_ROOT> run scored26:publication-check -- <D/Q/R/P/report inputs>`

- Marker: `SCORED26 publication check passed (S=pass)`
- Exit: `0`, established by the retained marker under `pipefail`.
- S: `sha256:1922ac844a1dd0a90dc1664cacb5d315f3f27181a3e8aed6c7f0a99fa50a9149`
- Machine PDF: `sha256:cabff13cf9c34a3d96dfda4944d30ac681960eab007ee11267f09ca90200d556`
- S fields: `status=pass`, `chain_verified=pass`, `claim_language_scan=pass`, `paper_claims_matched=true`

## Final scans

All scans run in the pinned image with `--network=none`. The actual-key scan
mounts `<RELEASE_KEY_FILE>` read-only and scans the re-extracted release,
bundle bytes, and reachable Git objects. The generic marker scan and public-data
scan receive no key mount. See `release/audit/lifecycle-audit.json` and the
sanitized scan logs for the recorded verdicts.
