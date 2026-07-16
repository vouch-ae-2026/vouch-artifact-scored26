import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(scriptDir, '..');
const registry = JSON.parse(
  await readFile(
    path.join(artifactDir, 'fixtures', 'fixture-registry.json'),
    'utf8'
  )
);
const conditionMap = JSON.parse(
  await readFile(
    path.join(artifactDir, 'contract', 'condition-map.json'),
    'utf8'
  )
);
const contractText = await readFile(
  path.join(
    artifactDir,
    'contract',
    'NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md'
  ),
  'utf8'
);
const crossWriterGoldens = JSON.parse(
  await readFile(
    path.join(artifactDir, 'tests', 'cross-writer-goldens.json'),
    'utf8'
  )
);
const implementationFixtureIds = [
  'S25-METER-01',
  'S2-VALUE-01',
  'S2-INPUT-01',
  'S2-PROFILE-01',
  'S2-GRAPH-01',
  'S2-TRANSCRIPT-01',
  'S2-DETERMINISM-01',
  'S2-RESOURCE-01',
  'S3-STRUCTURE-01',
  'S3-CLI-01',
  'S4-EVALUATORS-01',
  'S4-TOKENS-01',
  'S4-MUTATION-CFG-01',
  'S5-NATIVE-VERIFY-01',
  'S5-CLI-01',
  'S5-CAPABILITY-01',
  'S5-BRIDGE-BYTE-01',
  'S5-VULNERABLE-01',
  'S6-ISSUE-01',
  'S6-KEY-AUDIT-01',
  'S6-ATOMIC-PUBLISH-01',
  'S6-CLI-01',
  'S6-PKCS8-01',
  'S7-BRIDGE-API-01',
  'S7-BRIDGE-CLI-01',
  'S7-FIXTURE-GATE-01',
  'S8-WORKLOAD-FREEZE-01',
  'S8-REPLAY-01',
  'S8-WORKLOAD-RESULT-01',
  'S8-APPLICATION-SCHEMA-01',
  'S9-MUTATION-MECHANISM-01',
  'S9-MUTATION-RESULT-01',
  'S10-RELEASE-SCHEMA-01',
  'S10-FINALIZER-01',
  'S10-PUBLICATION-01',
  'S10-SUPPLY-01',
  'S10-CLEANROOM-01',
  'S10-CONDITION-LEDGER-01',
];

if (!Array.isArray(registry.fixtures) || registry.fixtures.length === 0) {
  throw new Error('fixture registry has no fixture rows');
}
const registryIds = registry.fixtures.map((row, index) => {
  if (
    !row ||
    typeof row.fixture_id !== 'string' ||
    row.fixture_id.length === 0
  ) {
    throw new Error(`fixture registry row ${index} is missing fixture_id`);
  }
  return row.fixture_id;
});
const uniqueRegistryIds = new Set(registryIds);
if (uniqueRegistryIds.size !== registryIds.length) {
  const duplicate = registryIds.find(
    (id, index) => registryIds.indexOf(id) !== index
  );
  throw new Error(`duplicate fixture id: ${duplicate}`);
}

const fixtureSection = contractText.slice(
  contractText.indexOf('## 23. Fixture manifest'),
  contractText.indexOf('### C-FIX-01')
);
const expectedIds = [
  ...[...fixtureSection.matchAll(/^\| ([A-Z][A-Z0-9-]+) \|/gm)]
    .map((match) => match[1])
    .filter((id) => id !== 'ID'),
  'C-VN-11',
  'C-ISSUE-13',
  'C-CAP-11',
  'C-CAP-12',
  'C-VN-12',
  'C-REP-09',
  'A-19',
  'C-ISSUE-09',
  'C-REP-06',
  'A-4',
  ...[
    ...contractText.matchAll(
      /^L(11[AB]|0[1-9]|1[0-9]|2[01])\s+(?!through\b)/gm
    ),
  ].map((match) => `L${match[1]}`),
  crossWriterGoldens.fixture_id,
  ...implementationFixtureIds,
];
const uniqueExpectedIds = new Set(expectedIds);
if (uniqueExpectedIds.size !== expectedIds.length) {
  throw new Error('frozen contract derives duplicate fixture identifiers');
}
for (const expectedId of uniqueExpectedIds) {
  if (!uniqueRegistryIds.has(expectedId)) {
    throw new Error(
      `fixture registry is missing contract fixture id ${expectedId}`
    );
  }
}
for (const registryId of uniqueRegistryIds) {
  if (!uniqueExpectedIds.has(registryId)) {
    throw new Error(
      `fixture registry contains unknown fixture id ${registryId}`
    );
  }
}

if (
  !Array.isArray(conditionMap.conditions) ||
  conditionMap.conditions.length === 0
) {
  throw new Error('condition map has no condition rows');
}
for (const [index, row] of conditionMap.conditions.entries()) {
  if (!row || typeof row.condition_id !== 'string') {
    throw new Error(`condition map row ${index} is missing condition_id`);
  }
  if (!Array.isArray(row.test_or_fixture_ids)) {
    throw new Error(`${row.condition_id} has no test_or_fixture_ids array`);
  }
  if (row.scope === 'built' && row.test_or_fixture_ids.length === 0) {
    throw new Error(`${row.condition_id} is built but has no fixture evidence`);
  }
  const rowIds = new Set();
  for (const fixtureId of row.test_or_fixture_ids) {
    if (typeof fixtureId !== 'string' || fixtureId.length === 0) {
      throw new Error(`${row.condition_id} contains a missing fixture id`);
    }
    if (rowIds.has(fixtureId)) {
      throw new Error(
        `${row.condition_id} references duplicate fixture id ${fixtureId}`
      );
    }
    if (!uniqueRegistryIds.has(fixtureId)) {
      throw new Error(
        `${row.condition_id} references absent fixture id ${fixtureId}`
      );
    }
    rowIds.add(fixtureId);
  }
}

console.log(
  `fixture ids valid: ${registryIds.length} registry rows, ${conditionMap.conditions.length} condition rows`
);
