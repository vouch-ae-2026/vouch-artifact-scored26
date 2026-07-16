import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';

import {
  buildManifest,
  canonicalJson,
  isTemporaryProjectionRoot,
  reviewToolchainChunkIssues,
  scanProjection,
  sha256,
  TYPESCRIPT_CHUNK_SPEC,
  TYPESCRIPT_REASSEMBLED_PATH,
  transientReviewToolchainIssues,
} from './source-projection-lib.mjs';

export function prepareReviewToolchain(root) {
  if (!isTemporaryProjectionRoot(root)) {
    throw new Error(
      'prepare:review-toolchain refuses to mutate a non-temporary projection; copy the source tree below the OS temporary directory first'
    );
  }

  assertInventoriedProjection(root);
  const reconstruction = reassembleTypeScript(root);
  const nodeModules = join(root, 'node_modules');
  const existingIssues = transientReviewToolchainIssues(root);
  if (existingIssues.length === 0 && existsSync(nodeModules)) {
    return {
      created: false,
      compiler: join(nodeModules, '.bin', 'tsc'),
      reconstructed: reconstruction.created,
    };
  }
  if (existingIssues.length > 0) {
    throw new Error(existingIssues.join('\n'));
  }

  let created = false;
  try {
    mkdirSync(nodeModules, { mode: 0o755 });
    created = true;
    mkdirSync(join(nodeModules, '.bin'), { mode: 0o755 });
    symlinkSync(
      '../../review-toolchain/typescript/bin/tsc',
      join(nodeModules, '.bin', 'tsc')
    );
    symlinkSync('../review-toolchain/typescript', join(nodeModules, 'typescript'));
    mkdirSync(join(nodeModules, '@types'), { mode: 0o755 });
    symlinkSync(
      '../../review-toolchain/types-node',
      join(nodeModules, '@types', 'node')
    );
    symlinkSync(
      '../review-toolchain/undici-types',
      join(nodeModules, 'undici-types')
    );
    for (const name of [
      'ajv',
      'fast-deep-equal',
      'fast-uri',
      'json-schema-traverse',
      'require-from-string',
    ]) {
      symlinkSync(`../review-toolchain/${name}`, join(nodeModules, name));
    }

    const preparedIssues = transientReviewToolchainIssues(root);
    if (preparedIssues.length > 0) throw new Error(preparedIssues.join('\n'));
    assertInventoriedProjection(root);
    return {
      created: true,
      compiler: join(nodeModules, '.bin', 'tsc'),
      reconstructed: reconstruction.created,
    };
  } catch (error) {
    if (created) rmSync(nodeModules, { recursive: true, force: true });
    if (reconstruction.created) {
      rmSync(reconstruction.path, { force: true });
    }
    throw error;
  }
}

export function reassembleTypeScript(root, { beforePublish = null } = {}) {
  const issues = reviewToolchainChunkIssues(root);
  if (issues.length > 0) throw new Error(issues.join('\n'));
  const target = join(root, ...TYPESCRIPT_REASSEMBLED_PATH.split('/'));
  if (existsSync(target)) {
    const bytes = readFileSync(target);
    if (
      bytes.length !== TYPESCRIPT_CHUNK_SPEC.original.bytes ||
      sha256(bytes) !== TYPESCRIPT_CHUNK_SPEC.original.sha256
    ) {
      throw new Error(
        `${TYPESCRIPT_REASSEMBLED_PATH}: existing reconstruction differs from the pinned compiler`
      );
    }
    return { created: false, path: target };
  }

  const temporary = `${target}.reassembling-${process.pid}`;
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    for (const part of TYPESCRIPT_CHUNK_SPEC.parts) {
      const bytes = readFileSync(join(root, ...part.path.split('/')));
      let offset = 0;
      while (offset < bytes.length) {
        offset += writeSync(
          descriptor,
          bytes,
          offset,
          bytes.length - offset
        );
      }
    }
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    const assembled = readFileSync(temporary);
    if (
      assembled.length !== TYPESCRIPT_CHUNK_SPEC.original.bytes ||
      sha256(assembled) !== TYPESCRIPT_CHUNK_SPEC.original.sha256
    ) {
      throw new Error('atomic TypeScript reconstruction identity mismatch');
    }
    chmodSync(temporary, 0o644);
    if (beforePublish !== null) beforePublish({ target, temporary });
    linkSync(temporary, target);
    unlinkSync(temporary);
    return { created: true, path: target };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    rmSync(temporary, { force: true });
    throw error;
  }
}

export function assertInventoriedProjection(root) {
  const expected = canonicalJson(buildManifest(root));
  const actual = readFileSync(join(root, 'SOURCE-MANIFEST.json'));
  if (!actual.equals(expected)) {
    throw new Error('SOURCE-MANIFEST.json is stale; refuse review-toolchain setup');
  }
  const issues = scanProjection(root);
  if (issues.length > 0) throw new Error(issues.join('\n'));
}
