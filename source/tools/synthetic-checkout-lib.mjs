import { spawnSync } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  BASE_COMMIT,
  buildManifest,
  canonicalJson,
  FREEZE_COMMIT,
  scanProjection,
  sha256,
  SOURCE_COMMIT,
  SOURCE_SANITIZED_OVERLAYS,
  SOURCE_TRACKED_FILE_COUNT,
  SOURCE_TREE,
  SYNTHETIC_BUNDLE_PATH,
} from './source-projection-lib.mjs';

const EXPECTED_HISTORY = [
  {
    commit: FREEZE_COMMIT,
    parent: '',
    epoch: '946684800',
    subject: 'Freeze Vouch evaluation inputs',
  },
  {
    commit: BASE_COMMIT,
    parent: FREEZE_COMMIT,
    epoch: '946771200',
    subject: 'Add anonymous Vouch release source',
  },
  {
    commit: SOURCE_COMMIT,
    parent: BASE_COMMIT,
    epoch: '946857600',
    subject: 'Record B-bound Vouch evaluation outputs',
  },
];
const SYNTHETIC_AUTHOR_NAME = 'Artifact Maintainer';
const SYNTHETIC_AUTHOR_EMAIL = 'artifact@example.invalid';
const SANITIZED_OVERLAYS_BY_PATH = new Map(
  SOURCE_SANITIZED_OVERLAYS.map((overlay) => [overlay.path, overlay])
);

export function assertProjectionReady(root) {
  const manifestPath = join(root, 'SOURCE-MANIFEST.json');
  const expected = canonicalJson(buildManifest(root));
  const actual = readFileSync(manifestPath);
  if (!actual.equals(expected)) {
    throw new Error(
      'SOURCE-MANIFEST.json is stale; run node tools/build-source-manifest.mjs --write'
    );
  }
  const issues = scanProjection(root);
  if (issues.length > 0) throw new Error(issues.join('\n'));
}

export function verifySyntheticHistoryBundle(
  sourceRoot,
  { keepCheckout = false } = {}
) {
  const bundle = join(sourceRoot, ...SYNTHETIC_BUNDLE_PATH.split('/'));
  const bundleStat = lstatSync(bundle);
  if (!bundleStat.isFile() || bundleStat.isSymbolicLink()) {
    throw new Error(`${SYNTHETIC_BUNDLE_PATH}: regular bundle file required`);
  }
  const heads = command(sourceRoot, 'git', [
    'bundle',
    'list-heads',
    bundle,
  ]);
  if (heads !== `${SOURCE_COMMIT} HEAD`) {
    throw new Error(`synthetic bundle head mismatch: ${heads}`);
  }

  const container = mkdtempSync(join(tmpdir(), 'vouch-bundle-audit-'));
  const checkout = join(container, 'checkout');
  try {
    command(container, 'git', [
      'clone',
      '--quiet',
      '--no-checkout',
      bundle,
      checkout,
    ]);
    command(checkout, 'git', ['remote', 'remove', 'origin']);
    command(checkout, 'git', ['checkout', '--quiet', '--detach', SOURCE_COMMIT]);

    const commits = command(checkout, 'git', [
      'rev-list',
      '--reverse',
      '--topo-order',
      '--all',
    ]).split('\n');
    if (
      commits.length !== EXPECTED_HISTORY.length ||
      commits.some((commit, index) => commit !== EXPECTED_HISTORY[index].commit)
    ) {
      throw new Error(`synthetic bundle commit set mismatch: ${commits.join(', ')}`);
    }
    for (const expected of EXPECTED_HISTORY) {
      const actual = command(checkout, 'git', [
        'show',
        '-s',
        '--format=%H%n%P%n%an%n%ae%n%at%n%cn%n%ce%n%ct%n%s',
        expected.commit,
      ]).split('\n');
      const wanted = [
        expected.commit,
        expected.parent,
        SYNTHETIC_AUTHOR_NAME,
        SYNTHETIC_AUTHOR_EMAIL,
        expected.epoch,
        SYNTHETIC_AUTHOR_NAME,
        SYNTHETIC_AUTHOR_EMAIL,
        expected.epoch,
        expected.subject,
      ];
      if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
        throw new Error(
          `synthetic commit metadata mismatch at ${expected.commit}: ${actual.join(' | ')}`
        );
      }
    }
    const tree = command(checkout, 'git', ['rev-parse', `${SOURCE_COMMIT}^{tree}`]);
    if (tree !== SOURCE_TREE) {
      throw new Error(`synthetic C0 tree mismatch: ${tree} != ${SOURCE_TREE}`);
    }

    const listing = commandBuffer(checkout, 'git', [
      'ls-tree',
      '-rz',
      '--full-tree',
      SOURCE_COMMIT,
    ]);
    const rows = listing
      .subarray(0, listing.length - (listing.at(-1) === 0 ? 1 : 0))
      .toString('utf8')
      .split('\0')
      .filter(Boolean)
      .map((line) => {
        const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(line);
        if (match === null) {
          throw new Error(`synthetic C0 contains unsupported tree row: ${line}`);
        }
        return { mode: match[1], object: match[2], path: match[3] };
      });
    if (rows.length !== SOURCE_TRACKED_FILE_COUNT) {
      throw new Error(
        `synthetic C0 file count ${rows.length} != ${SOURCE_TRACKED_FILE_COUNT}`
      );
    }
    const batch = catFileBatch(checkout, rows.map((row) => row.object));
    rows.forEach((row, index) => {
      const projected = join(sourceRoot, ...row.path.split('/'));
      const stat = lstatSync(projected);
      if (!stat.isFile() || stat.isSymbolicLink()) {
        throw new Error(`${row.path}: C0 projection requires a regular file`);
      }
      const expectedMode = row.mode === '100755' ? 0o755 : 0o644;
      if ((stat.mode & 0o777) !== expectedMode) {
        throw new Error(`${row.path}: projected mode differs from C0`);
      }
      const projectedBytes = readFileSync(projected);
      const overlay = SANITIZED_OVERLAYS_BY_PATH.get(row.path);
      if (overlay !== undefined) {
        if (sha256(batch[index]) !== overlay.source_sha256) {
          throw new Error(`${row.path}: sanitized overlay source bytes differ from C0 pin`);
        }
        if (sha256(projectedBytes) !== overlay.projected_sha256) {
          throw new Error(`${row.path}: sanitized overlay projected bytes differ from pin`);
        }
      } else if (!projectedBytes.equals(batch[index])) {
        throw new Error(`${row.path}: projected bytes differ from C0`);
      }
    });
    for (const overlay of SOURCE_SANITIZED_OVERLAYS) {
      if (!rows.some((row) => row.path === overlay.path)) {
        throw new Error(`${overlay.path}: sanitized overlay path is absent from C0`);
      }
    }
    const verified = {
      bundle,
      checkout,
      commits,
      container,
      paths: new Set(rows.map((row) => row.path)),
      sourceTree: tree,
    };
    if (!keepCheckout) {
      rmSync(container, { recursive: true, force: true });
      return { ...verified, checkout: null, container: null };
    }
    return verified;
  } catch (error) {
    rmSync(container, { recursive: true, force: true });
    throw error;
  }
}

export function createSyntheticCheckout(sourceRoot) {
  assertProjectionReady(sourceRoot);
  const verified = verifySyntheticHistoryBundle(sourceRoot, {
    keepCheckout: true,
  });
  const checkout = verified.checkout;
  const container = verified.container;
  if (gitStatus(checkout, ['symbolic-ref', '-q', 'HEAD']).status === 0) {
    removeSyntheticCheckout({ checkout, container });
    throw new Error('synthetic checkout is not detached');
  }
  if (git(checkout, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    removeSyntheticCheckout({ checkout, container });
    throw new Error('synthetic checkout is dirty immediately after creation');
  }
  if (git(checkout, ['remote']) !== '') {
    removeSyntheticCheckout({ checkout, container });
    throw new Error('synthetic checkout retained a remote');
  }
  return { checkout, commit: SOURCE_COMMIT, container };
}

export function removeSyntheticCheckout(result) {
  rmSync(result.container, { recursive: true, force: true });
  if (existsSync(result.container)) {
    throw new Error(`synthetic checkout cleanup failed: ${result.container}`);
  }
}

export function assertSyntheticCheckoutClean(checkout) {
  if (gitStatus(checkout, ['symbolic-ref', '-q', 'HEAD']).status === 0) {
    throw new Error('synthetic checkout is no longer detached');
  }
  const status = git(checkout, [
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
  ]);
  if (status !== '') throw new Error(`synthetic checkout became dirty: ${status}`);
}

export function ignoreSyntheticTopLevelPath(checkout, name) {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error(`invalid synthetic ignore path: ${name}`);
  }
  appendFileSync(join(checkout, '.git', 'info', 'exclude'), `\n/${name}\n`);
  const ignored = gitStatus(checkout, ['check-ignore', '--quiet', '--', name]);
  if (ignored.error) throw ignored.error;
  if (ignored.status !== 0) {
    throw new Error(`synthetic temporary path is not ignored: ${name}`);
  }
}

export function runInCheckout(checkout, program, args, { env = {} } = {}) {
  for (const forbidden of [
    'GITHUB_SHA',
    'LISPEX_BUILD_COMMIT_HEX',
    'LISPEX_BUILD_COMMIT_DIRTY',
  ]) {
    if (Object.hasOwn(env, forbidden)) {
      throw new Error(`review command may not override ${forbidden}`);
    }
  }
  const result = spawnSync(program, args, {
    cwd: checkout,
    env: { ...cleanBuildEnvironment(), ...env },
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${program} ${args.join(' ')} failed with status ${result.status}`);
  }
}

function catFileBatch(checkout, objects) {
  const output = commandBuffer(
    checkout,
    'git',
    ['cat-file', '--batch'],
    Buffer.from(`${objects.join('\n')}\n`, 'ascii')
  );
  const blobs = [];
  let offset = 0;
  for (const object of objects) {
    const newline = output.indexOf(0x0a, offset);
    if (newline === -1) throw new Error('truncated Git batch header');
    const header = output.subarray(offset, newline).toString('ascii');
    const match = /^([0-9a-f]{40}) blob ([0-9]+)$/u.exec(header);
    if (match === null || match[1] !== object) {
      throw new Error(`malformed Git batch header: ${header}`);
    }
    const length = Number(match[2]);
    const start = newline + 1;
    const end = start + length;
    if (end >= output.length || output[end] !== 0x0a) {
      throw new Error('truncated Git batch blob');
    }
    blobs.push(output.subarray(start, end));
    offset = end + 1;
  }
  if (offset !== output.length) throw new Error('extra Git batch output');
  return blobs;
}

function command(cwd, program, args) {
  return commandBuffer(cwd, program, args).toString('utf8').trim();
}

function commandBuffer(cwd, program, args, input = undefined) {
  const result = spawnSync(program, args, {
    cwd,
    encoding: 'buffer',
    input,
    maxBuffer: 1024 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${program} ${args.join(' ')} failed (${result.status}): ${result.stderr
        .toString('utf8')
        .trim()}`
    );
  }
  return result.stdout;
}

function git(cwd, args) {
  const result = gitStatus(cwd, args);
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(' ')} failed (${result.status}): ${result.stderr.trim()}`
    );
  }
  return result.stdout.trim();
}

function gitStatus(cwd, args) {
  return spawnSync('git', args, {
    cwd,
    env: process.env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function cleanBuildEnvironment() {
  const env = { ...process.env };
  for (const name of [
    'GITHUB_SHA',
    'LISPEX_BUILD_COMMIT_HEX',
    'LISPEX_BUILD_COMMIT_DIRTY',
  ]) {
    delete env[name];
  }
  env.CARGO_NET_OFFLINE = 'true';
  return env;
}
