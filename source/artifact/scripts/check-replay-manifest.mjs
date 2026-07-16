import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  buildReplayManifest,
  replaceEnvelopePayload,
  signReplayManifest,
} from './replay-manifest-lib.mjs';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

function fail(message) {
  console.error(`SCORED26 replay-manifest check failed: ${message}`);
  process.exit(1);
}

const build = spawnSync(
  'cargo',
  [
    'build',
    '--release',
    '--quiet',
    '--manifest-path',
    'vouch/Cargo.toml',
    '--bin',
    'scored26-replay-verify',
  ],
  { cwd: repoRoot, encoding: 'utf8' }
);
if (build.status !== 0)
  fail(`verifier build failed\n${build.stdout}\n${build.stderr}`);

const generated = buildReplayManifest(repoRoot);
const honestPair = generateKeyPairSync('ed25519');
const honestDer = honestPair.privateKey.export({
  format: 'der',
  type: 'pkcs8',
});
const honest = signReplayManifest(generated.payloadBytes, honestDer);
const attackerPair = generateKeyPairSync('ed25519');
const attackerDer = attackerPair.privateKey.export({
  format: 'der',
  type: 'pkcs8',
});
const attacker = signReplayManifest(generated.payloadBytes, attackerDer);
const root = mkdtempSync(join(tmpdir(), 'lispex-stage8-replay-'));
const verifier = join(repoRoot, 'target/release/scored26-replay-verify');

try {
  const paths = {
    envelope: join(root, 'manifest.dsse.json'),
    policy: join(root, 'trust-policy.json'),
    baselineRule: join(root, 'baseline.lspx'),
    changedRule: join(root, 'changed.lspx'),
    workloadSpace: join(root, 'workload-space.json'),
    workloadSelection: join(root, 'workload-selection.json'),
    workloadSplit: join(root, 'workload-split.json'),
    holdoutPlan: join(root, 'holdout-plan.json'),
    corpus: join(root, 'corpus.json'),
  };
  const restore = () => {
    writeFileSync(paths.envelope, honest.envelopeBytes);
    writeFileSync(paths.policy, honest.policyBytes);
    writeFileSync(paths.baselineRule, generated.files.baselineRule);
    writeFileSync(paths.changedRule, generated.files.changedRule);
    writeFileSync(paths.workloadSpace, generated.files.workloadSpace);
    writeFileSync(paths.workloadSelection, generated.files.workloadSelection);
    writeFileSync(paths.workloadSplit, generated.files.workloadSplit);
    writeFileSync(paths.holdoutPlan, generated.files.holdoutPlan);
    writeFileSync(paths.corpus, generated.corpusBytes);
  };
  const run = () =>
    spawnSync(
      verifier,
      [
        '--envelope',
        paths.envelope,
        '--trust-policy',
        paths.policy,
        '--baseline-rule',
        paths.baselineRule,
        '--changed-rule',
        paths.changedRule,
        '--workload-space',
        paths.workloadSpace,
        '--workload-selection',
        paths.workloadSelection,
        '--workload-split',
        paths.workloadSplit,
        '--holdout-plan',
        paths.holdoutPlan,
        '--corpus',
        paths.corpus,
      ],
      { cwd: repoRoot, encoding: 'utf8' }
    );
  const expect = (label, expectedStatus, mutate = () => {}) => {
    restore();
    mutate(paths);
    const result = run();
    if (expectedStatus === 'verified') {
      if (
        result.status !== 0 ||
        !result.stdout.includes('"status": "verified"')
      ) {
        fail(
          `${label}: honest verification failed\n${result.stdout}\n${result.stderr}`
        );
      }
      return;
    }
    if (result.status !== 1 || !result.stderr.includes(expectedStatus)) {
      fail(
        `${label}: expected ${expectedStatus}, status=${result.status}\n` +
          `${result.stdout}\n${result.stderr}`
      );
    }
  };

  expect('R01', 'verified');
  expect('R02', 'replay-corpus-member-missing', () => {
    const corpus = structuredClone(generated.corpus);
    corpus.cases.pop();
    writeFileSync(paths.corpus, writeArtifactJson(corpus));
  });
  expect('R03', 'replay-corpus-order-mismatch', () => {
    const corpus = structuredClone(generated.corpus);
    [corpus.cases[0], corpus.cases[1]] = [corpus.cases[1], corpus.cases[0]];
    writeFileSync(paths.corpus, writeArtifactJson(corpus));
  });
  expect('R04', 'untrusted-native-key', () => {
    writeFileSync(paths.envelope, attacker.envelopeBytes);
  });
  expect('R05', 'native-signature-invalid', () => {
    const payload = structuredClone(generated.payload);
    payload.expected_case_count += 1;
    writeFileSync(
      paths.envelope,
      replaceEnvelopePayload(honest.envelope, writeArtifactJson(payload))
    );
  });
  expect('payload authorization', 'native-payload-type-disallowed', () => {
    const policy = structuredClone(honest.policy);
    policy.keys[0].allowed_payload_types =
      policy.keys[0].allowed_payload_types.filter(
        (value) => !value.includes('replay-corpus-manifest')
      );
    writeFileSync(paths.policy, writeArtifactJson(policy));
  });
  expect('profile authorization', 'native-profile-disallowed', () => {
    const policy = structuredClone(honest.policy);
    policy.keys[0].allowed_profiles = ['csk.other-profile/v0'];
    writeFileSync(paths.policy, writeArtifactJson(policy));
  });
  expect('input substitute', 'replay-corpus-input-mismatch', () => {
    const corpus = structuredClone(generated.corpus);
    corpus.cases[0].input = corpus.cases[1].input;
    writeFileSync(paths.corpus, writeArtifactJson(corpus));
  });
  expect('rule substitute', 'replay-rule-mismatch', () => {
    writeFileSync(
      paths.baselineRule,
      Buffer.concat([generated.files.baselineRule, Buffer.from('\n')])
    );
  });
  expect('artifact substitute', 'replay-artifact-mismatch', () => {
    writeFileSync(
      paths.holdoutPlan,
      Buffer.concat([
        generated.files.holdoutPlan.subarray(0, -1),
        Buffer.from(' \n'),
      ])
    );
  });
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log(
  'SCORED26 replay-manifest check passed ' +
    '(R01-R05 plus policy/rule/input/artifact negatives)'
);
