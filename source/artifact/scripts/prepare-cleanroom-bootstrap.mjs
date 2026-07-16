import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import { parseCanonical, sha256Id } from './release-schema.mjs';

const options = parseArgs(process.argv.slice(2));
const sourceRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const output = resolve(options.get('--out-dir'));
const snapshotHelper = resolve(options.get('--snapshot-helper'));
const staging = `${output}.staging-${process.pid}`;
if (existsSync(output) || existsSync(staging)) {
  throw new Error('trusted bootstrap output already exists');
}
const helperStat = lstatSync(snapshotHelper);
if (!helperStat.isFile() || helperStat.isSymbolicLink()) {
  throw new Error('--snapshot-helper must be a regular non-symlink file');
}
const commit = command('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: sourceRoot,
}).stdout.trim();
if (
  command('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    cwd: sourceRoot,
  }).stdout !== ''
) {
  throw new Error(
    'trusted bootstrap source must be a clean committed checkout'
  );
}
const sourcePaths = [
  'artifact-json.mjs',
  'cleanroom-driver-lib.mjs',
  'cleanroom-release.mjs',
  'release-schema.mjs',
];

try {
  mkdirSync(staging, { recursive: false, mode: 0o700 });
  const rows = [];
  for (const name of sourcePaths) {
    const source = join(sourceRoot, 'artifact/scripts', name);
    const destination = join(staging, name);
    copyFileSync(source, destination);
    chmodSync(destination, name === 'cleanroom-release.mjs' ? 0o755 : 0o644);
    rows.push({
      path: name,
      sha256: sha256Id(readFileSync(destination)),
    });
  }
  const helperName = 'scored26-archive-snapshot';
  const helperDestination = join(staging, helperName);
  copyFileSync(snapshotHelper, helperDestination);
  chmodSync(helperDestination, 0o755);
  rows.push({
    path: helperName,
    sha256: sha256Id(readFileSync(helperDestination)),
  });
  rows.sort((left, right) =>
    Buffer.from(left.path).compare(Buffer.from(right.path))
  );
  const manifest = writeArtifactJson({
    trusted_bootstrap: 'vouch.scored26-trusted-bootstrap/v0',
    artifact_commit: commit,
    files: rows,
  });
  const manifestPath = join(staging, 'trusted-bootstrap-manifest.json');
  parseCanonical(manifest, 'trusted-bootstrap-manifest');
  writeFileSync(manifestPath, manifest, { mode: 0o644 });
  renameSync(staging, output);
  console.log(
    `SCORED26 trusted bootstrap prepared (${commit.slice(0, 12)}, ${rows.length} pinned files)`
  );
} catch (error) {
  rmSync(staging, { recursive: true, force: true });
  throw error;
}

function parseArgs(raw) {
  const required = new Set(['--out-dir', '--snapshot-helper']);
  if (raw.length !== 4)
    throw new Error('expected --out-dir and --snapshot-helper');
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index];
    const value = raw[index + 1];
    if (!required.has(name) || values.has(name) || !value) {
      throw new Error(`invalid or repeated option ${name}`);
    }
    values.set(name, value);
  }
  return values;
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    ...options,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${program} failed (status ${result.status})\n${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`
    );
  }
  return result;
}
