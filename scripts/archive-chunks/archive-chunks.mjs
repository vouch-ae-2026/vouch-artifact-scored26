#!/usr/bin/env node

// SPDX-License-Identifier: Apache-2.0

import { constants as fsConstants, realpathSync } from 'node:fs';
import fs from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ARCHIVE_CHUNK_MANIFEST,
  ARCHIVE_CHUNK_SIZE_BYTES,
  ARCHIVE_CHUNK_TAG,
  ARCHIVE_FILENAME,
  IO_BUFFER_BYTES,
  MAX_CHUNK_COUNT,
  canonicalJson,
  chunkPathFor,
  fsyncDirectory,
  invariant,
  lstatIfExists,
  openRegularNoFollow,
  parseStrictFlags,
  portableBasename,
  requireAbsent,
  requireDirectoryNoSymlink,
  writeAll,
} from './archive-chunk-lib.mjs';

async function acquirePublishLock(parentDirectory, outputBasename) {
  const lockPath = path.join(parentDirectory, `.${outputBasename}.publish.lock`);
  let handle;
  try {
    handle = await fs.open(
      lockPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new Error(`publish lock already exists: ${lockPath}`);
    }
    throw error;
  }
  try {
    await writeAll(handle, Buffer.from(`${process.pid}\n`, 'utf8'));
    await handle.sync();
    return { handle, lockPath };
  } catch (error) {
    try {
      await handle.close();
    } finally {
      await fs.unlink(lockPath).catch(() => {});
    }
    throw error;
  }
}

async function releasePublishLock(lock, parentDirectory) {
  if (!lock) {
    return;
  }
  try {
    await lock.handle.close();
  } finally {
    try {
      await fs.unlink(lock.lockPath);
    } finally {
      await fsyncDirectory(parentDirectory);
    }
  }
}

export async function chunkArchive({ archivePath, outputDirectory }) {
  invariant(typeof archivePath === 'string' && archivePath.length > 0, 'archivePath is required');
  invariant(typeof outputDirectory === 'string' && outputDirectory.length > 0, 'outputDirectory is required');

  const absoluteArchive = path.resolve(archivePath);
  const absoluteOutput = path.resolve(outputDirectory);
  const outputParent = path.dirname(absoluteOutput);
  const outputBasename = path.basename(absoluteOutput);
  portableBasename(outputBasename, 'output directory basename');
  await requireDirectoryNoSymlink(outputParent, 'output parent directory');
  await requireAbsent(absoluteOutput, 'output directory');

  const archiveFilename = portableBasename(path.basename(absoluteArchive), 'archive filename');
  invariant(archiveFilename === ARCHIVE_FILENAME, `archive filename must equal ${ARCHIVE_FILENAME}`);
  const openedArchive = await openRegularNoFollow(absoluteArchive, 'archive');
  let lock = null;
  let stagingDirectory = null;
  let published = false;
  try {
    invariant(Number.isSafeInteger(openedArchive.stat.size), 'archive size is not a safe integer');
    invariant(openedArchive.stat.size > 0, 'archive must contain at least one byte');
    const chunkCount = Math.ceil(openedArchive.stat.size / ARCHIVE_CHUNK_SIZE_BYTES);
    invariant(chunkCount <= MAX_CHUNK_COUNT, `archive would require more than ${MAX_CHUNK_COUNT} chunks`);

    lock = await acquirePublishLock(outputParent, outputBasename);
    await requireAbsent(absoluteOutput, 'output directory');
    stagingDirectory = path.join(outputParent, `.${outputBasename}.staging-${randomUUID()}`);
    await fs.mkdir(stagingDirectory, { mode: 0o700 });

    const archiveHash = createHash('sha256');
    const chunks = [];
    const buffer = Buffer.allocUnsafe(IO_BUFFER_BYTES);
    let archiveOffset = 0;

    for (let index = 0; index < chunkCount; index += 1) {
      const relativeChunkPath = chunkPathFor(archiveFilename, index);
      const stagedChunkPath = path.join(stagingDirectory, relativeChunkPath);
      const expectedBytes = Math.min(ARCHIVE_CHUNK_SIZE_BYTES, openedArchive.stat.size - archiveOffset);
      const chunkHash = createHash('sha256');
      const chunkHandle = await fs.open(
        stagedChunkPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
        0o600,
      );
      let chunkOffset = 0;
      try {
        while (chunkOffset < expectedBytes) {
          const wanted = Math.min(buffer.length, expectedBytes - chunkOffset);
          const result = await openedArchive.handle.read(buffer, 0, wanted, archiveOffset);
          invariant(result.bytesRead > 0, `archive ended unexpectedly at byte ${archiveOffset}`);
          const bytes = buffer.subarray(0, result.bytesRead);
          await writeAll(chunkHandle, bytes);
          chunkHash.update(bytes);
          archiveHash.update(bytes);
          archiveOffset += result.bytesRead;
          chunkOffset += result.bytesRead;
        }
        await chunkHandle.chmod(0o644);
        await chunkHandle.sync();
      } finally {
        await chunkHandle.close();
      }
      chunks.push({
        bytes: expectedBytes,
        index,
        path: relativeChunkPath,
        sha256: chunkHash.digest('hex'),
      });
    }

    invariant(archiveOffset === openedArchive.stat.size, 'chunked byte count does not equal archive size');
    const afterArchive = await openedArchive.handle.stat();
    invariant(
      afterArchive.size === openedArchive.stat.size &&
        afterArchive.dev === openedArchive.stat.dev &&
        afterArchive.ino === openedArchive.stat.ino &&
        afterArchive.mtimeMs === openedArchive.stat.mtimeMs &&
        afterArchive.ctimeMs === openedArchive.stat.ctimeMs,
      'archive changed while it was being chunked',
    );
    const eofProbe = Buffer.allocUnsafe(1);
    const eof = await openedArchive.handle.read(eofProbe, 0, 1, archiveOffset);
    invariant(eof.bytesRead === 0, 'archive grew while it was being chunked');

    const manifest = {
      archive: {
        bytes: openedArchive.stat.size,
        filename: archiveFilename,
        sha256: archiveHash.digest('hex'),
      },
      chunk_size_bytes: ARCHIVE_CHUNK_SIZE_BYTES,
      chunks,
      tag: ARCHIVE_CHUNK_TAG,
    };
    const manifestPath = path.join(stagingDirectory, ARCHIVE_CHUNK_MANIFEST);
    const manifestHandle = await fs.open(
      manifestPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    try {
      await writeAll(manifestHandle, Buffer.from(`${canonicalJson(manifest)}\n`, 'utf8'));
      await manifestHandle.chmod(0o644);
      await manifestHandle.sync();
    } finally {
      await manifestHandle.close();
    }

    await fs.chmod(stagingDirectory, 0o755);
    await fsyncDirectory(stagingDirectory);
    await requireAbsent(absoluteOutput, 'output directory');
    await fs.rename(stagingDirectory, absoluteOutput);
    published = true;
    stagingDirectory = null;
    await fsyncDirectory(outputParent);

    return {
      archive: manifest.archive,
      chunk_count: chunks.length,
      manifest: path.join(absoluteOutput, ARCHIVE_CHUNK_MANIFEST),
      output_directory: absoluteOutput,
      status: 'chunked',
    };
  } finally {
    try {
      await openedArchive.handle.close();
    } finally {
      try {
        if (!published && stagingDirectory !== null && (await lstatIfExists(stagingDirectory)) !== null) {
          await fs.rm(stagingDirectory, { force: true, recursive: true });
        }
      } finally {
        await releasePublishLock(lock, outputParent);
      }
    }
  }
}

function usage() {
  return [
    'Usage:',
    `  node archive-chunks.mjs --archive <path>/${ARCHIVE_FILENAME} --output-dir <new-directory>`,
    '',
    `The output directory must not exist. Chunks are exactly ${ARCHIVE_CHUNK_SIZE_BYTES} bytes`,
    'except for the final non-empty chunk. The directory is published atomically.',
  ].join('\n');
}

async function main() {
  const values = parseStrictFlags(process.argv.slice(2), {
    '--archive': 'archivePath',
    '--output-dir': 'outputDirectory',
  });
  if (values.help) {
    console.log(usage());
    return;
  }
  invariant(values.archivePath, '--archive is required');
  invariant(values.outputDirectory, '--output-dir is required');
  const result = await chunkArchive(values);
  console.log(canonicalJson(result));
}

const invokedDirectly =
  process.argv[1] && realpathSync(path.resolve(process.argv[1])) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(`archive-chunks: ${error.message}`);
    process.exitCode = 1;
  });
}
