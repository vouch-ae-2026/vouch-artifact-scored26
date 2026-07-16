import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(scriptDir, '..');
const contractPath = path.join(
  artifactDir,
  'contract',
  'NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md'
);
const contractBytes = await readFile(contractPath);
const contractText = contractBytes.toString('utf8');
const contractHash = createHash('sha256').update(contractBytes).digest('hex');
const crossWriterGoldens = JSON.parse(
  await readFile(
    path.join(artifactDir, 'tests', 'cross-writer-goldens.json'),
    'utf8'
  )
);
const fixtureSection = contractText.slice(
  contractText.indexOf('## 23. Fixture manifest'),
  contractText.indexOf('### C-FIX-01')
);

const tableIds = [...fixtureSection.matchAll(/^\| ([A-Z][A-Z0-9-]+) \|/gm)]
  .map((match) => match[1])
  .filter((id) => id !== 'ID');
const referencedConditionIds = [
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
];
const lifecycleIds = [
  ...contractText.matchAll(/^L(11[AB]|0[1-9]|1[0-9]|2[01])\s+(?!through\b)/gm),
].map((match) => `L${match[1]}`);
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
const fixtureIds = [
  ...tableIds,
  ...referencedConditionIds,
  ...lifecycleIds,
  crossWriterGoldens.fixture_id,
  ...implementationFixtureIds,
];

const seen = new Set();
for (const fixtureId of fixtureIds) {
  if (seen.has(fixtureId)) {
    throw new Error(`duplicate fixture id derived from contract: ${fixtureId}`);
  }
  seen.add(fixtureId);
}

const registry = {
  fixture_registry: 'vouch.scored26-fixture-registry/v0',
  contract_sha256: contractHash,
  fixtures: fixtureIds.map((fixtureId) => ({ fixture_id: fixtureId })),
};
const outputPath = path.join(artifactDir, 'fixtures', 'fixture-registry.json');
await writeFile(outputPath, `${JSON.stringify(registry, null, 2)}\n`, 'utf8');
console.log(
  `wrote ${fixtureIds.length} fixture ids to ${path.relative(process.cwd(), outputPath)}`
);
