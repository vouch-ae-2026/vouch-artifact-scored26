#!/usr/bin/env node

// SPDX-License-Identifier: Apache-2.0

import { constants as fsConstants, realpathSync } from 'node:fs';
import fs from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ARCHIVE_CHUNK_SIZE_BYTES,
  IO_BUFFER_BYTES,
  canonicalJson,
  fsyncDirectory,
  invariant,
  lstatIfExists,
  openRegularNoFollow,
  parseCanonicalManifest,
  parseStrictFlags,
  portableBasename,
  requireAbsent,
  requireDirectoryNoSymlink,
  writeAll,
} from './archive-chunk-lib.mjs';

async function beginAtomicReassembly(destinationPath) {
  const destination = path.resolve(destinationPath);
  const parent = path.dirname(destination);
  const basename = portableBasename(path.basename(destination), 'reassembly destination basename');
  await requireDirectoryNoSymlink(parent, 'reassembly destination parent');
  await requireAbsent(destination, 'reassembly destination');

  const lockPath = path.join(parent, `.${basename}.reassemble.lock`);
  let lockHandle;
  try {
    lockHandle = await fs.open(
      lockPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
  } catch (error) {
    if (error?.code === 'EEXIST') {
      throw new Error(`reassembly lock already exists: ${lockPath}`);
    }
    throw error;
  }

  let stagingPath = null;
  let outputHandle = null;
  try {
    await writeAll(lockHandle, Buffer.from(`${process.pid}\n`, 'utf8'));
    await lockHandle.sync();
    await requireAbsent(destination, 'reassembly destination');
    stagingPath = path.join(parent, `.${basename}.staging-${randomUUID()}`);
    outputHandle = await fs.open(
      stagingPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
  } catch (error) {
    try {
      await lockHandle.close();
    } finally {
      await fs.unlink(lockPath).catch(() => {});
    }
    throw error;
  }

  let committed = false;
  return {
    destination,
    outputHandle,
    async commit() {
      await outputHandle.chmod(0o644);
      await outputHandle.sync();
      await outputHandle.close();
      outputHandle = null;
      await requireAbsent(destination, 'reassembly destination');
      await fs.rename(stagingPath, destination);
      stagingPath = null;
      await fsyncDirectory(parent);
      committed = true;
    },
    async finish() {
      if (outputHandle !== null) {
        await outputHandle.close().catch(() => {});
      }
      if (!committed && stagingPath !== null && (await lstatIfExists(stagingPath)) !== null) {
        await fs.unlink(stagingPath).catch(() => {});
      }
      await lockHandle.close().catch(() => {});
      await fs.unlink(lockPath).catch(() => {});
      await fsyncDirectory(parent);
    },
  };
}

export async function verifyArchiveChunks({ manifestPath, reassemblePath = null }) {
  invariant(typeof manifestPath === 'string' && manifestPath.length > 0, 'manifestPath is required');
  invariant(
    reassemblePath === null || (typeof reassemblePath === 'string' && reassemblePath.length > 0),
    'reassemblePath must be null or a non-empty string',
  );
  const parsed = await parseCanonicalManifest(manifestPath);
  let reassembly = null;
  try {
    if (reassemblePath !== null) {
      reassembly = await beginAtomicReassembly(reassemblePath);
    }

    const concatenatedHash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(IO_BUFFER_BYTES);
    let totalBytes = 0;

    for (const chunk of parsed.manifest.chunks) {
      const chunkPath = path.join(parsed.manifestDirectory, chunk.path);
      const opened = await openRegularNoFollow(chunkPath, `chunk ${chunk.index}`);
      try {
        invariant(opened.stat.size === chunk.bytes, `chunk ${chunk.index} size does not match manifest`);
        if (chunk.index < parsed.manifest.chunks.length - 1) {
          invariant(opened.stat.size === ARCHIVE_CHUNK_SIZE_BYTES, `nonfinal chunk ${chunk.index} is not exactly 7 MiB`);
        } else {
          invariant(
            opened.stat.size >= 1 && opened.stat.size <= ARCHIVE_CHUNK_SIZE_BYTES,
            `final chunk ${chunk.index} is not between 1 byte and 7 MiB`,
          );
        }

        const chunkHash = createHash('sha256');
        let chunkOffset = 0;
        while (chunkOffset < chunk.bytes) {
          const wanted = Math.min(buffer.length, chunk.bytes - chunkOffset);
          const result = await opened.handle.read(buffer, 0, wanted, chunkOffset);
          invariant(result.bytesRead > 0, `chunk ${chunk.index} ended unexpectedly at byte ${chunkOffset}`);
          const bytes = buffer.subarray(0, result.bytesRead);
          chunkHash.update(bytes);
          concatenatedHash.update(bytes);
          if (reassembly !== null) {
            await writeAll(reassembly.outputHandle, bytes);
          }
          chunkOffset += result.bytesRead;
          totalBytes += result.bytesRead;
        }
        const eofProbe = Buffer.allocUnsafe(1);
        const eof = await opened.handle.read(eofProbe, 0, 1, chunk.bytes);
        invariant(eof.bytesRead === 0, `chunk ${chunk.index} contains bytes beyond its declared size`);
        const after = await opened.handle.stat();
        invariant(
          after.size === opened.stat.size &&
            after.dev === opened.stat.dev &&
            after.ino === opened.stat.ino &&
            after.mtimeMs === opened.stat.mtimeMs &&
            after.ctimeMs === opened.stat.ctimeMs,
          `chunk ${chunk.index} changed while it was verified`,
        );
        invariant(chunkHash.digest('hex') === chunk.sha256, `chunk ${chunk.index} SHA-256 mismatch`);
      } finally {
        await opened.handle.close();
      }
    }

    invariant(totalBytes === parsed.manifest.archive.bytes, 'concatenated byte count does not match archive manifest');
    invariant(
      concatenatedHash.digest('hex') === parsed.manifest.archive.sha256,
      'concatenated archive SHA-256 mismatch',
    );

    if (reassembly !== null) {
      const staged = await reassembly.outputHandle.stat();
      invariant(staged.isFile() && staged.size === totalBytes, 'staged reassembly size does not match verified bytes');
      await reassembly.commit();
    }
    return {
      archive: parsed.manifest.archive,
      chunk_count: parsed.manifest.chunks.length,
      manifest: parsed.absoluteManifest,
      reassembled: reassembly?.destination ?? null,
      status: 'verified',
    };
  } finally {
    if (reassembly !== null) {
      await reassembly.finish();
    }
  }
}

function usage() {
  return [
    'Usage:',
    '  node verify-archive-chunks.mjs --manifest <archive-chunks.json> [--reassemble <new-file>]',
    '',
    'The optional reassembly destination must not exist. It is staged, fsynced, and',
    'published atomically only after every chunk and the concatenated archive verify.',
  ].join('\n');
}

async function main() {
  const values = parseStrictFlags(process.argv.slice(2), {
    '--manifest': 'manifestPath',
    '--reassemble': 'reassemblePath',
  });
  if (values.help) {
    console.log(usage());
    return;
  }
  invariant(values.manifestPath, '--manifest is required');
  const result = await verifyArchiveChunks(values);
  console.log(canonicalJson(result));
}

const invokedDirectly =
  process.argv[1] && realpathSync(path.resolve(process.argv[1])) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error) => {
    console.error(`verify-archive-chunks: ${error.message}`);
    process.exitCode = 1;
  });
}
