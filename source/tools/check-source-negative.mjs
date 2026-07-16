import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  projectionRoot,
  reviewToolchainChunkIssues,
  scanProjection,
  TYPESCRIPT_CHUNK_MANIFEST_PATH,
  TYPESCRIPT_REASSEMBLED_PATH,
  TYPESCRIPT_CHUNK_SPEC,
  transientReviewToolchainIssues,
  vendoredReviewToolchainIssues,
} from './source-projection-lib.mjs';
import {
  prepareReviewToolchain,
  reassembleTypeScript,
} from './review-toolchain-lib.mjs';

const root = mkdtempSync(join(tmpdir(), 'vouch-source-negative-'));
try {
  writeFileSync(
    join(root, 'contact.txt'),
    ['reviewer', 'nonplaceholder.invalid'].join('@')
  );
  writeFileSync(
    join(root, 'local-path.txt'),
    ['', 'Users', 'review-account', 'workspace'].join('/')
  );
  mkdirSync(join(root, '.git'));
  writeFileSync(join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
  writeFileSync(
    join(root, 'repository.txt'),
    ['https://github.com', 'review-owner', 'private-repository'].join('/')
  );
  writeFileSync(
    join(root, 'key-material.txt'),
    [['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' '), 'not-a-real-key'].join(
      '\n'
    )
  );
  writeFileSync(
    join(root, 'credential.txt'),
    ['gh', 'p_', 'A'.repeat(40)].join('')
  );
  writeFileSync(join(root, 'release.key'), 'not-a-real-key\n');
  writeFileSync(
    join(root, `${'GO'}${'AL'}.md`),
    'non-product coordination record\n'
  );
  writeFileSync(
    join(root, 'process.txt'),
    [`${'ag'}${'ent'}`, 'review', 'workflow'].join(' ')
  );
  mkdirSync(join(root, 'content', 'en', 'docs', 'classic'), {
    recursive: true,
  });
  writeFileSync(
    join(root, 'content', 'en', 'docs', 'classic', 'unlisted.mdx'),
    'not an allowlisted executable conformance fixture\n'
  );
  const issues = scanProjection(root);
  for (const expected of [
    'non-placeholder email address',
    'user-home absolute path',
    'Git metadata is forbidden',
    'repository account URL',
    'private-key PEM marker',
    'credential-shaped token',
    'key-material filename outside vendor',
    'excluded non-product record',
    'excluded non-product subtree',
    'excluded non-product process prose',
  ]) {
    if (!issues.some((issue) => issue.includes(expected))) {
      throw new Error(`negative control was accepted: ${expected}`);
    }
  }

  const scannerControl = join(root, 'scanner-control');
  const scannerFixturePath = ['', 'Users', 'cskernel2', 'project'].join('/');
  const releaseSupplyScanner = join(
    scannerControl,
    'artifact',
    'scripts',
    'check-release-supply.mjs'
  );
  mkdirSync(join(releaseSupplyScanner, '..'), { recursive: true });
  writeFileSync(releaseSupplyScanner, `${scannerFixturePath}\n`);
  if (
    scanProjection(scannerControl).some((issue) =>
      issue.includes('user-home absolute path')
    )
  ) {
    throw new Error('release-supply scanner fixture was misclassified as a local path');
  }
  writeFileSync(
    join(scannerControl, 'artifact', 'scripts', 'not-a-scanner.mjs'),
    `${scannerFixturePath}\n`
  );
  if (
    !scanProjection(scannerControl).some((issue) =>
      issue.includes('user-home absolute path')
    )
  ) {
    throw new Error('negative control was accepted: scanner-path exemption widened');
  }

  mkdirSync(join(root, 'review-toolchain', 'typescript'), { recursive: true });
  writeFileSync(
    join(root, 'review-toolchain', 'typescript', 'package.json'),
    '{"name":"typescript","version":"5.8.2"}\n'
  );
  if (
    !vendoredReviewToolchainIssues(root).some((issue) =>
      issue.includes('tree SHA-256')
    )
  ) {
    throw new Error('negative control was accepted: incomplete compiler package');
  }

  const wrongCaseLicenseRoot = join(
    root,
    'review-toolchain',
    'require-from-string'
  );
  mkdirSync(wrongCaseLicenseRoot, { recursive: true });
  writeFileSync(join(wrongCaseLicenseRoot, 'LICENSE'), 'wrong-case path\n');
  if (
    !vendoredReviewToolchainIssues(root).some((issue) =>
      issue.includes('exact-case license path is missing')
    )
  ) {
    throw new Error('negative control was accepted: wrong-case license path');
  }

  mkdirSync(join(root, 'node_modules', '.bin'), { recursive: true });
  writeFileSync(join(root, 'node_modules', 'unexpected.txt'), 'not allowed\n');
  if (
    !transientReviewToolchainIssues(root).some((issue) =>
      issue.includes('unexpected temporary toolchain entry')
    )
  ) {
    throw new Error('negative control was accepted: extra node_modules entry');
  }

  const distributed = projectionRoot(import.meta.url);
  const chunkRoot = join(root, 'chunk-control');
  for (const path of [
    TYPESCRIPT_CHUNK_MANIFEST_PATH,
    ...TYPESCRIPT_CHUNK_SPEC.parts.map((part) => part.path),
  ]) {
    const destination = join(chunkRoot, ...path.split('/'));
    mkdirSync(join(destination, '..'), { recursive: true });
    copyFileSync(join(distributed, ...path.split('/')), destination);
  }
  if (reviewToolchainChunkIssues(chunkRoot).length !== 0) {
    throw new Error('valid TypeScript chunk control failed');
  }
  const changedPart = join(
    chunkRoot,
    ...TYPESCRIPT_CHUNK_SPEC.parts[0].path.split('/')
  );
  const changedBytes = readFileSync(changedPart);
  changedBytes[0] ^= 0x01;
  writeFileSync(changedPart, changedBytes);
  if (
    !reviewToolchainChunkIssues(chunkRoot).some((issue) =>
      issue.includes('chunk bytes or SHA-256 mismatch')
    )
  ) {
    throw new Error('negative control was accepted: changed TypeScript chunk');
  }
  copyFileSync(
    join(distributed, ...TYPESCRIPT_CHUNK_SPEC.parts[0].path.split('/')),
    changedPart
  );

  const reconstructed = join(
    chunkRoot,
    ...TYPESCRIPT_REASSEMBLED_PATH.split('/')
  );
  mkdirSync(join(reconstructed, '..'), { recursive: true });
  const sentinel = Buffer.from('must-not-be-overwritten\n');
  writeFileSync(reconstructed, sentinel);
  try {
    reassembleTypeScript(chunkRoot);
    throw new Error(
      'negative control was accepted: preexisting reconstruction overwrite'
    );
  } catch (error) {
    if (
      error.message ===
      'negative control was accepted: preexisting reconstruction overwrite'
    ) {
      throw error;
    }
    if (!readFileSync(reconstructed).equals(sentinel)) {
      throw new Error('failed reconstruction changed a preexisting target');
    }
  }
  rmSync(reconstructed);
  const raceSentinel = Buffer.from('race-target-must-not-be-overwritten\n');
  try {
    reassembleTypeScript(chunkRoot, {
      beforePublish: ({ target }) => writeFileSync(target, raceSentinel),
    });
    throw new Error('negative control was accepted: race target overwrite');
  } catch (error) {
    if (error.message === 'negative control was accepted: race target overwrite') {
      throw error;
    }
    if (!readFileSync(reconstructed).equals(raceSentinel)) {
      throw new Error('no-replace publication changed a race target');
    }
  }
  rmSync(reconstructed);
  writeFileSync(
    reconstructed,
    Buffer.concat(
      TYPESCRIPT_CHUNK_SPEC.parts.map((part) =>
        readFileSync(join(chunkRoot, ...part.path.split('/')))
      )
    )
  );
  const reused = reassembleTypeScript(chunkRoot);
  if (reused.created || reused.path !== reconstructed) {
    throw new Error('exact preexisting reconstruction was not reused');
  }

  try {
    prepareReviewToolchain('/');
    throw new Error('negative control was accepted: non-temporary setup');
  } catch (error) {
    if (error.message === 'negative control was accepted: non-temporary setup') {
      throw error;
    }
    if (!error.message.includes('refuses to mutate a non-temporary projection')) {
      throw new Error(`unexpected non-temporary setup failure: ${error.message}`);
    }
  }

  console.log(
    'source projection boundary controls passed (negative and exemption-scope checks)'
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
