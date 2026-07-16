import assert from 'node:assert/strict';

import {
  ArtifactJsonError,
  canonicalArtifactJson,
  parseArtifactJson,
  writeArtifactJson,
} from './artifact-json.mjs';
import {
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE,
  authenticateDescriptor,
  parseReleaseDescriptor,
} from './release-schema.mjs';
import { buildReleaseTestFixture } from './release-test-fixtures.mjs';

const fixture = buildReleaseTestFixture();
assert.deepEqual(
  JSON.parse(
    JSON.stringify(parseReleaseDescriptor(fixture.buffers.descriptor))
  ),
  fixture.descriptor
);
assert.equal(
  authenticateDescriptor({
    policyBytes: fixture.buffers.trustPolicy,
    descriptorBytes: fixture.buffers.descriptor,
    envelopeBytes: fixture.buffers.descriptorEnvelope,
  }).descriptor.key_id,
  fixture.releaseKey.keyId
);
assert.equal(
  RELEASE_DESCRIPTOR_PAYLOAD_TYPE.includes('release-descriptor'),
  true
);

const canonical = writeArtifactJson({ a: ['😀', 1, true, null], z: 'é' });
assert.equal(
  writeArtifactJson(canonicalArtifactJson(canonical)).equals(canonical),
  true
);
expectCode(Buffer.from('{"a":1,"a":2}\n'), 'non-canonical-artifact-json');
expectCode(Buffer.from('[1,]\n'), 'non-canonical-artifact-json');
expectCode(Buffer.alloc(16_777_217, 0x20), 'artifact-resource-limit');

const deep = Buffer.from(`${'['.repeat(129)}0${']'.repeat(129)}\n`);
expectCode(deep, 'artifact-resource-limit');

const tooManyArrayMembers = Buffer.from(
  `[\n${Array.from({ length: 10_001 }, () => '  0').join(',\n')}\n]\n`
);
expectCode(tooManyArrayMembers, 'artifact-resource-limit');

const tooManyObjectMembers = Buffer.from(
  `{\n${Array.from(
    { length: 10_001 },
    (_, index) => `  "k${String(index).padStart(5, '0')}": 0`
  ).join(',\n')}\n}\n`
);
expectCode(tooManyObjectMembers, 'artifact-resource-limit');

const tooLongString = writeArtifactJson('x'.repeat(1_048_577));
expectCode(tooLongString, 'artifact-resource-limit');

const nodeHeavy = writeArtifactJson(
  Array.from({ length: 101 }, () => Array.from({ length: 990 }, () => 0))
);
expectCode(nodeHeavy, 'artifact-resource-limit');

const memberNameHeavy = writeArtifactJson(
  Object.fromEntries(
    Array.from({ length: 10_000 }, (_, index) => [
      `key-${String(index).padStart(5, '0')}`,
      Array.from({ length: 9 }, () => index),
    ])
  )
);
expectCode(memberNameHeavy, 'artifact-resource-limit');

console.log(
  'SCORED26 release schema passed (canonical bytes, descriptor auth, bounded token limits)'
);

function expectCode(bytes, code) {
  assert.throws(
    () => parseArtifactJson(bytes),
    (error) => error instanceof ArtifactJsonError && error.code === code
  );
}
