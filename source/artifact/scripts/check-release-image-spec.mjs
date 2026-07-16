import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  parseBuildImageRecord,
  verifyBuildImagePins,
} from './release-layer-lib.mjs';

const root = resolve(import.meta.dirname, '../..');
const dockerfile = readFileSync(
  resolve(root, 'artifact/release/Dockerfile.scored26'),
  'utf8'
);
const runtime = JSON.parse(
  readFileSync(resolve(root, 'artifact/runtime-versions.json'), 'utf8')
);
const imageRecordBytes = readFileSync(
  resolve(root, 'artifact/release/build-image.json')
);
const imageRecord = parseBuildImageRecord(imageRecordBytes);
const expectedImages = [
  'rust@sha256:9f841bbe9e7d8e37ceb96ed907265a3a0df7f44e3737d0b100e7907a679acb36',
  'node@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b',
  'ubuntu@sha256:6015f66923d7afbc53558d7ccffd325d43b4e249f41a6e93eef074c9505d2233',
];
for (const image of expectedImages) assert.match(dockerfile, new RegExp(image));
assert.equal(imageRecord.build_image, 'vouch.scored26-build-image/v0');
assert.match(imageRecord.build_image_sha256, /^sha256:[0-9a-f]{64}$/);
assert.equal(imageRecord.platform, 'linux/amd64');
assert.equal(
  imageRecord.dockerfile_path,
  'artifact/release/Dockerfile.scored26'
);
for (const image of expectedImages) {
  assert.equal(
    Object.values(imageRecord).includes(image),
    true,
    `build-image record omits ${image}`
  );
}
for (const value of Object.values(runtime.toolchains)) {
  assert.equal(
    dockerfile.includes(value),
    true,
    `release image omits toolchain assertion ${value}`
  );
}
verifyBuildImagePins(
  imageRecord,
  imageRecord.build_image_sha256,
  imageRecord.os_base_image
);
assert.throws(
  () =>
    verifyBuildImagePins(
      imageRecord,
      `sha256:${'0'.repeat(64)}`,
      imageRecord.os_base_image
    ),
  /release image options differ/
);
assert.throws(
  () =>
    verifyBuildImagePins(
      imageRecord,
      imageRecord.build_image_sha256,
      `ubuntu@sha256:${'0'.repeat(64)}`
    ),
  /release image options differ/
);
assert.throws(
  () =>
    parseBuildImageRecord(
      writeArtifactJson({ ...imageRecord, unexpected_field: true })
    ),
  /build-image-record: closed schema mismatch/
);
assert.match(dockerfile, /--device=lima-vm\.io\/rosetta=cached/);
assert.match(dockerfile, /texlive-latex-recommended/);
assert.match(dockerfile, /poppler-utils/);
console.log(
  'SCORED26 release image spec passed (digest-pinned bases, exact toolchains, paper tools)'
);
