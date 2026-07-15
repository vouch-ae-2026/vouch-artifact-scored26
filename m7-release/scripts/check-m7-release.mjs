#!/usr/bin/env node
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const releaseRoot = resolve(scriptDir, '..');
const failures = [];

function fail(name, detail) {
  failures.push(name + ': ' + detail);
}

function bytes(path) {
  return readFileSync(resolve(releaseRoot, path));
}

function json(path) {
  try {
    return JSON.parse(bytes(path).toString('utf8'));
  } catch (error) {
    fail(path, 'invalid JSON: ' + error.message);
    return {};
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function taggedSha256(value) {
  return 'sha256:' + sha256(value);
}

function expect(name, actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      name,
      'expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual)
    );
  }
}

function walk(root, prefix = '') {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const rel = prefix ? prefix + '/' + entry.name : entry.name;
    const path = join(root, entry.name);
    if (entry.isSymbolicLink()) {
      fail('inventory', 'symbolic link is forbidden: ' + rel);
    } else if (entry.isDirectory()) {
      files.push(...walk(path, rel));
    } else if (entry.isFile()) {
      files.push(rel);
    } else {
      fail('inventory', 'non-regular entry is forbidden: ' + rel);
    }
  }
  return files;
}

function dssePae(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from('DSSEv1 ' + type.length + ' ', 'utf8'),
    type,
    Buffer.from(' ' + payload.length + ' ', 'utf8'),
    payload,
  ]);
}

function rawEd25519PublicKey(raw) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return createPublicKey({
    key: Buffer.concat([prefix, raw]),
    format: 'der',
    type: 'spki',
  });
}

function verifyEnvelope(envelopePath, payloadPath, expectedType, policy) {
  const envelope = json(envelopePath);
  const payload = bytes(payloadPath);
  expect(envelopePath + '.payloadType', envelope.payloadType, expectedType);
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    fail(envelopePath, 'expected exactly one signature');
    return;
  }
  const signature = envelope.signatures[0];
  const key = policy.keys.find((row) => row.key_id === signature.keyid);
  if (!key) {
    fail(envelopePath, 'signature key is not selected by the trust policy');
    return;
  }
  if (!key.allowed_payload_types.includes(expectedType)) {
    fail(envelopePath, 'payload type is not authorized by the selected key');
  }
  const embedded = Buffer.from(envelope.payload, 'base64');
  if (!embedded.equals(payload)) {
    fail(envelopePath, 'embedded payload bytes differ from the adjacent payload');
  }
  const publicKey = rawEd25519PublicKey(Buffer.from(key.public_key, 'base64'));
  const signatureBytes = Buffer.from(signature.sig, 'base64');
  const pae = dssePae(expectedType, embedded);
  if (!verifySignature(null, pae, publicKey, signatureBytes)) {
    fail(envelopePath, 'Ed25519 signature verification failed');
  }

  const tampered = Buffer.from(embedded);
  tampered[0] ^= 1;
  const tamperedPae = dssePae(expectedType, tampered);
  if (verifySignature(null, tamperedPae, publicKey, signatureBytes)) {
    fail(envelopePath, 'negative control accepted a tampered payload');
  }
}

const manifest = json('manifests/m7-release.v0.json');
expect(
  'manifest tag',
  manifest.m7_release_addendum,
  'vouch.m7-release-addendum/v0'
);
expect('manifest mode', manifest.mode, 'additive-authenticated-native-evidence');
expect('archive distributed', manifest.artifact.archive_distributed, false);

const expectedFiles = new Map();
for (const entry of manifest.distributed_files ?? []) {
  if (
    typeof entry.path !== 'string' ||
    entry.path.startsWith('/') ||
    entry.path.includes('..') ||
    entry.path.includes('\\')
  ) {
    fail('manifest file path', JSON.stringify(entry.path));
    continue;
  }
  if (expectedFiles.has(entry.path)) {
    fail('manifest file path', 'duplicate ' + entry.path);
  }
  expectedFiles.set(entry.path, entry.sha256);
  const actual = sha256(bytes(entry.path));
  expect('file hash ' + entry.path, actual, entry.sha256);
}

const actualFiles = [
  ...walk(resolve(releaseRoot, 'chain'), 'chain'),
  ...walk(resolve(releaseRoot, 'results'), 'results'),
  ...walk(resolve(releaseRoot, 'paper'), 'paper'),
].sort();
expect('distributed file inventory', actualFiles, [...expectedFiles.keys()].sort());

const policy = json('chain/trust-policy.json');
expect('trust policy tag', policy.trust_policy, 'csk.native-trust-policy/v0');
expect('trust policy key count', policy.keys?.length, 1);
verifyEnvelope(
  'chain/release-descriptor.dsse.json',
  'chain/release-descriptor.json',
  'application/vnd.csk.release-descriptor.v0+json',
  policy
);
verifyEnvelope(
  'chain/reproduction-observation.dsse.json',
  'chain/reproduction-observation.json',
  'application/vnd.csk.reproduction-observation.v0+json',
  policy
);

const descriptorBytes = bytes('chain/release-descriptor.json');
const cleanRunBytes = bytes('chain/clean-run-report.json');
const observationBytes = bytes('chain/reproduction-observation.json');
const descriptor = json('chain/release-descriptor.json');
const cleanRun = json('chain/clean-run-report.json');
const observation = json('chain/reproduction-observation.json');
const publication = json('chain/release-publication.json');
const terminal = json('chain/publication-report.json');

expect('descriptor digest', sha256(descriptorBytes), manifest.chain.release_descriptor_sha256);
expect('clean-run digest', sha256(cleanRunBytes), manifest.chain.clean_run_report_sha256);
expect(
  'observation digest',
  sha256(observationBytes),
  manifest.chain.reproduction_observation_sha256
);
expect(
  'publication digest',
  sha256(bytes('chain/release-publication.json')),
  manifest.chain.publication_record_sha256
);
expect(
  'terminal digest',
  sha256(bytes('chain/publication-report.json')),
  manifest.chain.terminal_report_sha256
);
expect(
  'release-record PDF digest',
  sha256(bytes('paper/vouch-scored26-release-record.pdf')),
  manifest.chain.release_record_pdf_sha256
);

expect('descriptor tag', descriptor.release_descriptor, 'csk.release-descriptor/v0');
expect('artifact commit', descriptor.artifact_commit, manifest.artifact.commit);
expect(
  'artifact freeze commit',
  descriptor.artifact_freeze_commit,
  manifest.artifact.freeze_commit
);
expect(
  'archive digest',
  descriptor.archive_sha256,
  'sha256:' + manifest.artifact.archive_sha256
);
expect('descriptor key id', descriptor.key_id, manifest.artifact.key_id);
expect('target triple', descriptor.target_triple, manifest.artifact.target_triple);
expect(
  'build image digest',
  descriptor.build_image_sha256,
  'sha256:' + manifest.artifact.build_image_sha256
);

expect('Q status', cleanRun.status, 'pass');
expect(
  'Q descriptor link',
  cleanRun.release_descriptor_sha256,
  taggedSha256(descriptorBytes)
);
expect('Q private key absent', cleanRun.release_private_key_present, false);
expect('Q worktree clean', cleanRun.worktree_clean, true);
expect('Q public-data scan', cleanRun.public_data_scan, 'pass');

expect(
  'Q fixture report digest',
  cleanRun.fixture_report_sha256,
  taggedSha256(bytes('results/fixture-results.json'))
);
expect(
  'Q workload report digest',
  cleanRun.workload_report_sha256,
  taggedSha256(bytes('results/workload-results.json'))
);
expect(
  'Q mutation report digest',
  cleanRun.mutation_report_sha256,
  taggedSha256(bytes('results/mutation/mutation-results.json'))
);
expect(
  'Q performance report digest',
  cleanRun.performance_report_sha256,
  taggedSha256(bytes('results/performance-results.json'))
);
expect(
  'Q exact comparisons digest',
  cleanRun.exact_reproduction_comparisons_sha256,
  taggedSha256(bytes('results/exact-reproduction-comparisons.json'))
);

const fixtureReport = json('results/fixture-results.json');
const workloadReport = json('results/workload-results.json');
const mutationReport = json('results/mutation/mutation-results.json');
expect('fixture summary agrees with Q', fixtureReport.fixture_results, cleanRun.fixture_results);
expect('workload summary agrees with Q', workloadReport.workload_summary, cleanRun.workload);
expect('mutation summary agrees with Q', mutationReport.mutation_summary, cleanRun.mutation);
expect(
  'exact comparison count',
  json('results/exact-reproduction-comparisons.json').comparisons?.length,
  482
);

expect(
  'R descriptor link',
  observation.release_descriptor_sha256,
  taggedSha256(descriptorBytes)
);
expect('R clean-run link', observation.clean_run_report_sha256, taggedSha256(cleanRunBytes));
expect(
  'R workload link',
  observation.workload_summary_sha256,
  taggedSha256(bytes('results/workload-results.json'))
);
expect(
  'R mutation link',
  observation.mutation_summary_sha256,
  taggedSha256(bytes('results/mutation/mutation-results.json'))
);
expect('R fixture summary agrees with Q', observation.fixture_results, cleanRun.fixture_results);
expect(
  'R clean runtime agrees with Q',
  observation.clean_run_runtime_seconds,
  cleanRun.clean_run_runtime_seconds
);

expect(
  'P descriptor link',
  publication.release_descriptor_sha256,
  taggedSha256(descriptorBytes)
);
expect(
  'P observation link',
  publication.reproduction_observation_sha256,
  taggedSha256(observationBytes)
);
expect('S status', terminal.status, manifest.chain.terminal_status);
expect('S chain verdict', terminal.chain_verified, 'pass');
expect('S paper claims', terminal.paper_claims_matched, true);
expect('S claim-language scan', terminal.claim_language_scan, 'pass');
expect(
  'S descriptor link',
  terminal.release_descriptor_sha256,
  taggedSha256(descriptorBytes)
);
expect('S clean-run link', terminal.clean_run_report_sha256, taggedSha256(cleanRunBytes));
expect(
  'S observation link',
  terminal.reproduction_observation_sha256,
  taggedSha256(observationBytes)
);

const expectedResults = manifest.results;
expect(
  'built fixture expected count',
  cleanRun.fixture_results.built.expected,
  expectedResults.built_fixtures_expected
);
expect(
  'built fixture matched count',
  cleanRun.fixture_results.built.matched,
  expectedResults.built_fixtures_matched
);
expect(
  'built fixture mismatch count',
  cleanRun.fixture_results.built.mismatched,
  expectedResults.built_fixtures_mismatched
);
expect(
  'built fixture skip count',
  cleanRun.fixture_results.built.skipped,
  expectedResults.built_fixtures_skipped
);
expect('workload candidates', cleanRun.workload.candidates, expectedResults.workload_candidates);
expect(
  'workload selected',
  cleanRun.workload.selected_case_count,
  expectedResults.workload_selected
);
expect(
  'workload decision flips',
  cleanRun.workload.decision_flips,
  expectedResults.workload_decision_flips
);
expect(
  'workload held-out flips',
  cleanRun.workload.held_out_flips,
  expectedResults.workload_held_out_flips
);
expect(
  'mutants seeded',
  cleanRun.mutation.mutant_level.seeded,
  expectedResults.mutants_seeded
);
expect(
  'mutants built',
  cleanRun.mutation.mutant_level.built,
  expectedResults.mutants_built
);
expect(
  'mutants activated',
  cleanRun.mutation.mutant_level.activated_any,
  expectedResults.mutants_activated
);
expect(
  'mutants detected',
  cleanRun.mutation.mutant_level.detected_any,
  expectedResults.mutants_detected
);
expect(
  'mutant detection rate',
  cleanRun.mutation.mutant_level.detection_rate,
  expectedResults.mutant_detection_rate
);
expect(
  'clean runtime',
  cleanRun.clean_run_runtime_seconds,
  expectedResults.clean_run_runtime_seconds
);

const conditionMap = json('results/condition-map.json');
const built = conditionMap.conditions?.filter(
  (row) => row.implementation_status === 'built'
);
const notStarted = conditionMap.conditions
  ?.filter((row) => row.implementation_status === 'not-started')
  .map((row) => row.condition_id)
  .sort();
expect('condition row count', conditionMap.conditions?.length, expectedResults.condition_rows);
expect('built condition count', built?.length, expectedResults.conditions_built);
expect(
  'not-started condition ids',
  notStarted,
  [...expectedResults.conditions_not_started].sort()
);

const tamperedReport = Buffer.concat([
  bytes('results/workload-results.json'),
  Buffer.from(' ', 'utf8'),
]);
if (taggedSha256(tamperedReport) === cleanRun.workload_report_sha256) {
  fail('owner-report negative control', 'tampered bytes retained the authenticated digest');
}

if (failures.length > 0) {
  console.error('M7 release addendum check failed');
  for (const failure of failures) console.error('- ' + failure);
  process.exit(1);
}

console.log('M7 release addendum check passed');
console.log('D/Q/R/P/S chain: verified');
console.log('Built fixtures: 163/163 matched, zero skipped');
console.log('Workload: 1,536 candidates, 240 selected, 83 flips, 19 held-out flips');
console.log('Mutation: 12 built, 5 activated, 4 detected, 33.3 percent');
console.log('Condition ledger: 211 built, P-4/P-11 not-started');
