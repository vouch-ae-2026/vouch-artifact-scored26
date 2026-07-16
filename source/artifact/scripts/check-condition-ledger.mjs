import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(scriptDir, '..');
const contractDir = path.join(artifactDir, 'contract');
const activeContractPath = path.join(
  contractDir,
  'NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md'
);
const historicalContractPath = path.join(
  contractDir,
  'NATIVE-IMPLEMENTATION-CONDITIONS-v8.5.1.md'
);

const [
  activeBytes,
  expectedActiveHash,
  historicalBytes,
  expectedHistoricalHash,
  conditionMapBytes,
  registryBytes,
] = await Promise.all([
  readFile(activeContractPath),
  readFile(path.join(contractDir, 'SHA256'), 'utf8'),
  readFile(historicalContractPath),
  readFile(path.join(contractDir, 'SHA256-v8.5.1'), 'utf8'),
  readFile(path.join(contractDir, 'condition-map.json')),
  readFile(path.join(artifactDir, 'fixtures', 'fixture-registry.json')),
]);

verifyDigest(activeBytes, expectedActiveHash.trim(), 'active contract');
verifyDigest(
  historicalBytes,
  expectedHistoricalHash.trim(),
  'historical v8.5.1 contract'
);

const contractIds = [
  ...activeBytes
    .toString('utf8')
    .matchAll(/^### ((?:A|P)-\d+|C-[A-Z]+-\d+)\b/gm),
].map((match) => match[1]);
requireUnique(contractIds, 'contract condition');
if (contractIds.length !== 213) {
  throw new Error(`expected 213 contract conditions, got ${contractIds.length}`);
}

const conditionMap = JSON.parse(conditionMapBytes.toString('utf8'));
const registry = JSON.parse(registryBytes.toString('utf8'));
validateLedger(conditionMap, registry, contractIds, expectedActiveHash.trim());

expectRejected('duplicate condition', (map) => {
  map.conditions.push(structuredClone(map.conditions[0]));
});
expectRejected('missing condition', (map) => {
  map.conditions.pop();
});
expectRejected('not-built condition', (map) => {
  map.conditions.find((row) => row.condition_id === 'P-4').implementation_status =
    'not-started';
});
expectRejected('fixtureless condition', (map) => {
  map.conditions.find((row) => row.condition_id === 'P-11').test_or_fixture_ids =
    [];
});
expectRejected('unknown fixture', (map) => {
  map.conditions[0].test_or_fixture_ids = ['UNKNOWN-FIXTURE'];
});

console.log(
  `condition ledger complete: ${conditionMap.conditions.length}/${contractIds.length} built, uniquely mapped, fixture-backed`
);

function verifyDigest(bytes, expected, subject) {
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) {
    throw new Error(`${subject} SHA-256 mismatch: expected ${expected}, got ${actual}`);
  }
}

function validateLedger(map, fixtureRegistry, expectedIds, expectedHash) {
  if (map.contract_sha256 !== expectedHash) {
    throw new Error('condition map does not bind the active contract digest');
  }
  if (fixtureRegistry.contract_sha256 !== expectedHash) {
    throw new Error('fixture registry does not bind the active contract digest');
  }
  if (!Array.isArray(map.conditions)) {
    throw new Error('condition map has no conditions array');
  }
  const mapIds = map.conditions.map((row) => row.condition_id);
  requireUnique(mapIds, 'condition-map');
  if (
    mapIds.length !== expectedIds.length ||
    mapIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw new Error(
      'condition map is not an exact ordered projection of the contract'
    );
  }

  const fixtureIds = fixtureRegistry.fixtures.map((row) => row.fixture_id);
  requireUnique(fixtureIds, 'fixture-registry');
  const fixtureSet = new Set(fixtureIds);
  for (const row of map.conditions) {
    if (row.scope !== 'built') {
      throw new Error(`${row.condition_id}: release condition is not built-scope`);
    }
    if (row.implementation_status !== 'built') {
      throw new Error(`${row.condition_id}: implementation status is not built`);
    }
    if (
      !Array.isArray(row.test_or_fixture_ids) ||
      row.test_or_fixture_ids.length === 0
    ) {
      throw new Error(`${row.condition_id}: no fixture evidence`);
    }
    requireUnique(row.test_or_fixture_ids, `${row.condition_id} fixture`);
    for (const fixtureId of row.test_or_fixture_ids) {
      if (!fixtureSet.has(fixtureId)) {
        throw new Error(`${row.condition_id}: unknown fixture ${fixtureId}`);
      }
    }
  }
}

function expectRejected(subject, mutate) {
  const candidate = structuredClone(conditionMap);
  mutate(candidate);
  try {
    validateLedger(candidate, registry, contractIds, expectedActiveHash.trim());
  } catch {
    return;
  }
  throw new Error(`negative control was accepted: ${subject}`);
}

function requireUnique(values, subject) {
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`${subject} contains an invalid identifier`);
    }
    if (seen.has(value)) {
      throw new Error(`${subject} contains duplicate identifier ${value}`);
    }
    seen.add(value);
  }
}
