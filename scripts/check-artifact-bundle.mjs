import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(root, 'cli', 'bin', 'lispex.js');

function fail(message) {
  console.error(message);
  process.exit(1);
}

function run(args, expected) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== expected) {
    fail(args.join(' ') + ' exited ' + result.status + ', expected ' + expected + '\n' + result.stdout + '\n' + result.stderr);
  }
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    fail(args.join(' ') + ' did not emit JSON: ' + error.message);
  }
}

function expectDiag(report, code, label) {
  if (!report.diagnostics?.some((entry) => entry.code === code)) {
    fail(label + ' missing diagnostic ' + code);
  }
}

function hashWithDomain(domain, bytes) {
  return createHash('sha256').update(Buffer.from(domain + '\0', 'utf8')).update(bytes).digest('hex');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

const bridgeReport = 'examples/vouch-bridge/reports/checkout-discount.bridge.json';
const source = 'examples/vouch-bridge/source/checkout-discount.ts';
const target = 'examples/vouch-bridge/target/checkout_discount.py';
const linked = 'examples/vouch-bridge/linked/external-gate-proof.json';
const context = 'examples/vouch-bridge/context/checkout-discount.context.json';

const positive = run([
  'verify-bridge',
  '--source', source,
  '--target', target,
  '--linked', 'external-gate-proof=' + linked,
  '--expect-context', context,
  bridgeReport,
], 0);
if (positive.bridge_verify_report !== 'vouch.bridge-verify-report/v0') {
  fail('verify-bridge did not emit vouch.bridge-verify-report/v0');
}

const contextManifest = JSON.parse(readFileSync(join(root, 'adversarial/context-mismatch/manifest.json'), 'utf8'));
for (const row of contextManifest.rows) {
  const report = run(['verify-bridge', '--expect-context', row.path, bridgeReport], 1);
  expectDiag(report, row.expected_failure, row.id);
}

const replay = run(['replay', 'examples/welfare', '--against', 'examples/welfare/changed-expected'], 1);
if (replay.replay_report !== 'csk.replay-report/v0') fail('replay report tag mismatch');
if (replay.summary?.decision_changed !== 6 || replay.summary?.total !== 12) {
  fail('welfare replay summary mismatch');
}

for (const dir of ['examples/welfare/expected', 'examples/welfare/changed-expected']) {
  for (const file of readdirSync(join(root, dir)).filter((entry) => entry.endsWith('.json')).sort()) {
    const receipt = join(dir, file);
    const report = run(['verify', receipt], 0);
    if (report.verify_report !== 'csk.verify-report/v0') fail('verify report tag mismatch for ' + receipt);
  }
}

const fixtures = JSON.parse(readFileSync(join(root, 'adversarial/vouch-evidence-laundering/fixtures.json'), 'utf8'));
for (const row of fixtures.rows) {
  const args = row.gate === 'bridge-verify' ? ['verify-bridge', row.path] : ['verify', row.path];
  const expected = row.expected_failure === 'none' ? 0 : 1;
  const report = run(args, expected);
  if (row.expected_failure !== 'none') expectDiag(report, row.expected_failure, row.id);
  const native = run(['verify', row.path], row.id === 'A.4' ? 1 : 1);
  if (native.summary?.status === 'pass') fail(row.id + ' promoted to native');
}

const results = JSON.parse(readFileSync(join(root, 'adversarial/vouch-evidence-laundering/results.json'), 'utf8'));
if (results.summary?.group_a_total !== 12 || results.summary?.group_a_promoted_to_native !== 0) {
  fail('adversarial results summary mismatch');
}

const hashes = JSON.parse(readFileSync(join(root, 'hashes/expected-hashes.json'), 'utf8'));
for (const entry of hashes.entries) {
  const bytes = readFileSync(join(root, entry.path));
  const actual = entry.domain === 'sha256/raw-bytes' ? sha256(bytes) : hashWithDomain(entry.domain, bytes);
  if (actual !== entry.sha256) fail('hash mismatch for ' + entry.path);
}

console.log('anonymous Vouch artifact bundle checks passed');
