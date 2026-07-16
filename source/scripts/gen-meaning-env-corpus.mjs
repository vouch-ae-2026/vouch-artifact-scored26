import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const casesDir = join(repoRoot, 'meaning-env', 'cases');
const expectedDir = join(repoRoot, 'meaning-env', 'expected');
const write = process.argv.includes('--write');

function fail(message) {
  console.error(`[gen-meaning-env-corpus] ${message}`);
  process.exit(1);
}

function gitOutput(args) {
  const result = spawnSync('git', args, { cwd: repoRoot, encoding: 'utf8' });
  if (result.status !== 0) return null;
  return result.stdout.trim() || null;
}

function artifactEnv() {
  const hex = gitOutput(['rev-parse', 'HEAD']);
  if (!/^[0-9a-f]{40}$/.test(hex ?? '')) {
    fail('cannot determine git HEAD for artifact commit metadata');
  }
  return {
    ...process.env,
    LISPEX_ARTIFACT_COMMIT_HEX: hex,
    LISPEX_ARTIFACT_COMMIT_DIRTY: 'false',
  };
}

const genEnv = write ? artifactEnv() : process.env;

function withPreservedExpectedCommit(bytes, expectedPath) {
  if (!existsSync(expectedPath)) return bytes;
  let next;
  let previous;
  try {
    next = JSON.parse(bytes.toString('utf8'));
    previous = JSON.parse(readFileSync(expectedPath, 'utf8'));
  } catch (error) {
    fail(`cannot preserve engine.commit.hex for ${expectedPath}: ${error.message}`);
  }
  const previousHex = previous?.engine?.commit?.hex;
  if (!/^[0-9a-f]{40}$/.test(previousHex ?? '')) {
    fail(`${expectedPath} does not carry a reusable engine.commit.hex`);
  }
  if (next?.engine?.commit) {
    next.engine.commit.hex = previousHex;
  }
  return Buffer.from(`${JSON.stringify(next, null, 2)}\n`, 'utf8');
}

function maskCommitHex(value) {
  const commit = value?.engine?.commit;
  if (!commit || commit.vcs !== 'git' || !/^[0-9a-f]{40}$/.test(commit.hex) || commit.dirty !== false) {
    fail('artifact engine.commit must carry git 40-hex and dirty:false');
  }
  commit.hex = '<masked-commit>';
  return value;
}

function sameArtifact(leftBytes, rightBytes) {
  let left;
  let right;
  try {
    left = maskCommitHex(JSON.parse(leftBytes.toString('utf8')));
    right = maskCommitHex(JSON.parse(rightBytes.toString('utf8')));
  } catch (error) {
    fail(`artifact JSON parse failed: ${error.message}`);
  }
  return JSON.stringify(left) === JSON.stringify(right);
}

function runLispex(args) {
  return spawnSync(
    'cargo',
    ['run', '--manifest-path', 'interp/Cargo.toml', '--quiet', '--', ...args],
    {
      cwd: repoRoot,
      encoding: null,
      env: genEnv,
    }
  );
}

let count = 0;

for (const entry of readdirSync(casesDir).filter((name) => name.endsWith('.json')).sort()) {
  const stem = basename(entry, '.json');
  const graphRel = `meaning-env/cases/${entry}`;
  const out = runLispex(['eval-graph', graphRel]);
  if (out.status !== 0) {
    fail(`${graphRel} eval-graph exited ${out.status}: ${out.stderr.toString()}`);
  }
  const expectedPath = join(expectedDir, `${stem}.json`);
  if (write) {
    writeFileSync(expectedPath, withPreservedExpectedCommit(out.stdout, expectedPath));
  } else {
    const expected = readFileSync(expectedPath);
    if (!sameArtifact(out.stdout, expected)) {
      fail(`${graphRel} report drifted from meaning-env/expected/${stem}.json`);
    }
  }
  count += 1;
}

console.log(`[gen-meaning-env-corpus] ${write ? 'wrote' : 'checked'} ${count} reports`);
