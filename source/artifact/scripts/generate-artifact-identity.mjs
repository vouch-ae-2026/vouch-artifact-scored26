import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));
const outputPath = fileURLToPath(
  new URL('../../generated/artifact-identity.tex', import.meta.url)
);
const args = process.argv.slice(2);
const write = args.includes('--write');
const freezeIndex = args.indexOf('--freeze');
const allowed = new Set(['--write', '--freeze']);
for (let index = 0; index < args.length; index += 1) {
  if (!allowed.has(args[index]) && index !== freezeIndex + 1) {
    fail(`unknown argument ${args[index]}`);
  }
}
if (freezeIndex >= 0 && args[freezeIndex + 1] === undefined) {
  fail('--freeze requires a full commit');
}

const status = git(['status', '--porcelain=v1', '--untracked-files=all']);
if (status.length !== 0) fail('worktree or index is dirty');
const head = git(['rev-parse', '--verify', 'HEAD']).trim();
let freeze = freezeIndex >= 0 ? args[freezeIndex + 1] : null;
let actual = null;
try {
  actual = readFileSync(outputPath, 'utf8');
  const match =
    /^\\newcommand\{\\ArtifactFreezeCommit\}\{([0-9a-f]{40})\}\n$/.exec(actual);
  if (freeze === null && match) freeze = match[1];
} catch (error) {
  if (!write) fail(`cannot read generated identity: ${error.message}`);
}
if (!/^[0-9a-f]{40}$/.test(freeze ?? '')) {
  fail('freeze commit is not full lowercase 40-hex');
}
git(['rev-parse', '--verify', `${freeze}^{commit}`]);
git(['merge-base', '--is-ancestor', freeze, head]);
const expected = `\\newcommand{\\ArtifactFreezeCommit}{${freeze}}\n`;
if (
  /Artifact(?:Source|Release|Archive|Engine)|sha256:|runtime|toolchain/i.test(
    expected
  )
) {
  fail('generated identity contains a forbidden resolved release field');
}
if (write) {
  writeFileSync(outputPath, expected, 'utf8');
  console.log(`wrote generated/artifact-identity.tex at ${head.slice(0, 12)}`);
} else if (actual !== expected) {
  fail('generated identity differs from the committed file');
} else {
  console.log(
    `artifact identity valid at ${head.slice(0, 12)} (freeze ${freeze.slice(0, 12)})`
  );
}

function git(commandArgs) {
  const result = spawnSync('git', commandArgs, {
    cwd: repoRoot,
    encoding: 'utf8',
  });
  if (result.error || result.status !== 0) {
    fail(`git ${commandArgs.join(' ')} failed`);
  }
  return result.stdout;
}

function fail(message) {
  console.error(`artifact identity generation failed: ${message}`);
  process.exit(1);
}
