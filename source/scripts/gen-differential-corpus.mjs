import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = join(fileURLToPath(new URL('..', import.meta.url)));
const casesDir = join(repoRoot, 'differential', 'cases');
const expectedDir = join(repoRoot, 'differential', 'expected');
const graphsDir = join(repoRoot, 'differential', 'graphs');
const write = process.argv.includes('--write');

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

function runLispex(args) {
  const result = spawnSync(
    'cargo',
    ['run', '--manifest-path', 'interp/Cargo.toml', '--quiet', '--', ...args],
    {
      cwd: repoRoot,
      encoding: null,
      env: genEnv,
    }
  );
  return result;
}

function fail(message) {
  console.error(`[gen-differential-corpus] ${message}`);
  process.exit(1);
}

let expectedCount = 0;
let graphCount = 0;

for (const entry of readdirSync(casesDir).filter((name) => name.endsWith('.lspx')).sort()) {
  const stem = basename(entry, '.lspx');
  const sourceRel = `differential/cases/${entry}`;

  const receipt = runLispex(['diff-receipt', sourceRel]);
  if (![0, 1].includes(receipt.status)) {
    fail(`${sourceRel} diff-receipt exited ${receipt.status}: ${receipt.stderr.toString()}`);
  }
  if (write) {
    const expectedPath = join(expectedDir, `${stem}.json`);
    writeFileSync(expectedPath, withPreservedExpectedCommit(receipt.stdout, expectedPath));
  }
  expectedCount += 1;

  const graph = runLispex(['lower', sourceRel]);
  const graphPath = join(graphsDir, `${stem}.json`);
  if (graph.status === 0) {
    if (write) {
      writeFileSync(graphPath, graph.stdout);
    }
    graphCount += 1;
  } else if (write) {
    rmSync(graphPath, { force: true });
  }
}

console.log(
  `[gen-differential-corpus] ${write ? 'wrote' : 'checked generation for'} ${expectedCount} receipts and ${graphCount} graphs`
);
