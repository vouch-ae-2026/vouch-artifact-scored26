import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const exampleRoot = 'examples/vouch-loop';
const stem = 'refund-window';
const rulePath = `${exampleRoot}/cases/${stem}.lspx`;
const inputPath = `${exampleRoot}/inputs/${stem}.datum`;
const expectedDir = `${exampleRoot}/expected`;
const version = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'))
  .version;

function fail(message) {
  console.error(`vouch loop example check failed: ${message}`);
  process.exit(1);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 120000,
    ...options,
  });
  if (result.status !== 0) {
    fail(
      `${command} ${args.join(' ')} exited ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
    );
  }
  return result.stdout;
}

function artifactEnv() {
  const head = run('git', ['rev-parse', 'HEAD']).trim();
  if (!/^[0-9a-f]{40}$/.test(head)) fail('cannot determine git HEAD');
  return {
    ...process.env,
    LISPEX_ARTIFACT_COMMIT_HEX: head,
    LISPEX_ARTIFACT_COMMIT_DIRTY: 'false',
  };
}

function readJson(bytes, label) {
  try {
    return JSON.parse(bytes);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function generateReceipt(outputPath) {
  const stdout = run(
    'cargo',
    [
      'run',
      '--manifest-path',
      'interp/Cargo.toml',
      '--quiet',
      '--',
      'diff-receipt',
      '--input',
      inputPath,
      rulePath,
    ],
    { env: artifactEnv() }
  );
  writeFileSync(outputPath, stdout);
  const receipt = readJson(stdout, 'generated receipt');
  if (receipt.differential_receipt !== 'csk.differential-receipt/v0') {
    fail('generated receipt tag mismatch');
  }
  if (receipt.engine?.version !== version) {
    fail(`generated receipt version ${receipt.engine?.version} != ${version}`);
  }
  if (receipt.comparison?.status !== 'agree') {
    fail(`generated receipt comparison ${receipt.comparison?.status} != agree`);
  }
}

function verifyReceipt(receiptPath) {
  const stdout = run(process.execPath, [
    'cli/bin/lispex.js',
    'verify',
    '--source',
    rulePath,
    receiptPath,
  ]);
  const report = readJson(stdout, 'verify report');
  if (report.verify_report !== 'csk.verify-report/v0') {
    fail('verify report tag mismatch');
  }
  if (report.summary?.status !== 'pass') {
    fail(`verify summary ${report.summary?.status} != pass`);
  }
}

function replayCandidate(candidateDir) {
  const stdout = run(process.execPath, [
    'cli/bin/lispex.js',
    'replay',
    exampleRoot,
    '--against',
    candidateDir,
  ]);
  const report = readJson(stdout, 'replay report');
  if (report.replay_report !== 'csk.replay-report/v0') {
    fail('replay report tag mismatch');
  }
  if (report.summary?.status !== 'unchanged') {
    fail(`replay summary ${report.summary?.status} != unchanged`);
  }
}

function replayVersion() {
  const stdout = run(process.execPath, [
    'cli/bin/lispex.js',
    'replay',
    exampleRoot,
    '--against',
    version,
  ]);
  const report = readJson(stdout, 'version replay report');
  if (report.summary?.status !== 'unchanged') {
    fail(`version replay summary ${report.summary?.status} != unchanged`);
  }
}

const tmp = mkdtempSync(join(tmpdir(), 'lispex-vouch-loop-'));
try {
  const currentDir = join(tmp, 'current');
  mkdirSync(currentDir, { recursive: true });
  const generated = join(currentDir, `${stem}.json`);
  generateReceipt(generated);
  verifyReceipt(generated);
  replayCandidate(currentDir);
  replayVersion();
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log('vouch loop example check passed (generate, verify, replay)');
