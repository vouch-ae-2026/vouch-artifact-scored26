#!/usr/bin/env node

// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

import { chunkArchive } from './archive-chunks.mjs';
import { verifyArchiveChunks } from './verify-archive-chunks.mjs';
import {
  ARCHIVE_CHUNK_MANIFEST,
  ARCHIVE_CHUNK_SIZE_BYTES,
  ARCHIVE_CHUNK_TAG,
  ARCHIVE_FILENAME,
  canonicalJson,
  invariant,
  writeAll,
} from './archive-chunk-lib.mjs';

const results = [];

function pass(name, detail = '') {
  results.push({ detail, name, status: 'pass' });
  console.log(`PASS ${name}${detail ? `: ${detail}` : ''}`);
}

async function expectReject(name, operation, expectedPattern = null) {
  try {
    await operation();
  } catch (error) {
    if (expectedPattern !== null) {
      invariant(expectedPattern.test(error.message), `${name} failed with unexpected error: ${error.message}`);
    }
    pass(name, error.message);
    return;
  }
  throw new Error(`${name} unexpectedly succeeded`);
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  const handle = await fs.open(filePath, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let position = 0;
  try {
    while (true) {
      const result = await handle.read(buffer, 0, buffer.length, position);
      if (result.bytesRead === 0) {
        break;
      }
      hash.update(buffer.subarray(0, result.bytesRead));
      position += result.bytesRead;
    }
  } finally {
    await handle.close();
  }
  return hash.digest('hex');
}

async function writeDeterministicArchive(filePath) {
  const handle = await fs.open(filePath, 'wx', 0o600);
  const block = Buffer.allocUnsafe(1024 * 1024);
  for (let index = 0; index < block.length; index += 1) {
    block[index] = (index * 131 + 17) & 0xff;
  }
  let remaining = ARCHIVE_CHUNK_SIZE_BYTES + 12_345;
  try {
    while (remaining > 0) {
      const count = Math.min(block.length, remaining);
      await writeAll(handle, block, 0, count);
      remaining -= count;
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function main() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'vouch-archive-chunk-self-test-'));
  const archive = path.join(root, ARCHIVE_FILENAME);
  const chunks = path.join(root, 'chunks');
  const chunksAgain = path.join(root, 'chunks-again');
  const manifestPath = path.join(chunks, ARCHIVE_CHUNK_MANIFEST);
  const reassembled = path.join(root, 'release.reassembled.tar.zst');
  let keep = process.env.KEEP_SELF_TEST === '1';
  try {
    await writeDeterministicArchive(archive);
    await chunkArchive({ archivePath: archive, outputDirectory: chunks });
    pass('chunk archive');

    const verification = await verifyArchiveChunks({ manifestPath });
    invariant(verification.chunk_count === 2, 'expected the sample to produce exactly two chunks');
    pass('verify valid chunks');

    await verifyArchiveChunks({ manifestPath, reassemblePath: reassembled });
    invariant((await sha256File(archive)) === (await sha256File(reassembled)), 'reassembled archive digest differs');
    pass('reassemble valid chunks');

    await chunkArchive({ archivePath: archive, outputDirectory: chunksAgain });
    const firstManifest = await fs.readFile(manifestPath);
    const secondManifest = await fs.readFile(path.join(chunksAgain, ARCHIVE_CHUNK_MANIFEST));
    invariant(firstManifest.equals(secondManifest), 'identical archives produced different manifests');
    pass('deterministic manifest');
    await fs.rm(chunksAgain, { force: true, recursive: true });

    await expectReject(
      'reject preexisting output directory',
      () => chunkArchive({ archivePath: archive, outputDirectory: chunks }),
      /already exists/,
    );

    const wrongArchive = path.join(root, 'wrong-name.tar.zst');
    await fs.link(archive, wrongArchive);
    await expectReject(
      'reject unexpected archive filename',
      () => chunkArchive({ archivePath: wrongArchive, outputDirectory: path.join(root, 'wrong-name-chunks') }),
      /archive filename must equal/,
    );
    await fs.unlink(wrongArchive);

    await expectReject(
      'reject nonportable output basename',
      () => chunkArchive({ archivePath: archive, outputDirectory: path.join(root, 'bad output') }),
      /portable printable ASCII/,
    );

    const symlinkOutput = path.join(root, 'symlink-output');
    await fs.symlink(path.basename(chunks), symlinkOutput);
    await expectReject(
      'reject symlink output directory',
      () => chunkArchive({ archivePath: archive, outputDirectory: symlinkOutput }),
      /already exists/,
    );
    await fs.unlink(symlinkOutput);

    const existingDestination = path.join(root, 'existing-destination.tar.zst');
    const sentinel = Buffer.from('do-not-overwrite\n', 'utf8');
    await fs.writeFile(existingDestination, sentinel, { flag: 'wx' });
    await expectReject(
      'reject preexisting reassembly destination',
      () => verifyArchiveChunks({ manifestPath, reassemblePath: existingDestination }),
      /already exists/,
    );
    invariant((await fs.readFile(existingDestination)).equals(sentinel), 'preexisting destination was modified');

    const symlinkDestination = path.join(root, 'symlink-destination.tar.zst');
    await fs.symlink(path.basename(existingDestination), symlinkDestination);
    await expectReject(
      'reject symlink reassembly destination',
      () => verifyArchiveChunks({ manifestPath, reassemblePath: symlinkDestination }),
      /already exists/,
    );
    await fs.unlink(symlinkDestination);

    const manifestRaw = await fs.readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestRaw);
    const firstChunk = path.join(chunks, manifest.chunks[0].path);
    const lastChunk = path.join(chunks, manifest.chunks.at(-1).path);

    const corruptHandle = await fs.open(firstChunk, 'r+');
    const originalByte = Buffer.allocUnsafe(1);
    try {
      await corruptHandle.read(originalByte, 0, 1, 0);
      await corruptHandle.write(Buffer.from([originalByte[0] ^ 0xff]), 0, 1, 0);
      await corruptHandle.sync();
    } finally {
      await corruptHandle.close();
    }
    const corruptDestination = path.join(root, 'corrupt-reassembly.tar.zst');
    await expectReject(
      'reject corrupt chunk without publishing reassembly',
      () => verifyArchiveChunks({ manifestPath, reassemblePath: corruptDestination }),
      /SHA-256 mismatch/,
    );
    await fs.access(corruptDestination).then(
      () => {
        throw new Error('corrupt verification published a reassembly destination');
      },
      (error) => invariant(error.code === 'ENOENT', `unexpected corrupt destination access error: ${error.message}`),
    );
    const leakedCorruptPaths = (await fs.readdir(root)).filter(
      (entry) => entry.includes('corrupt-reassembly') && (entry.includes('.staging-') || entry.endsWith('.lock')),
    );
    invariant(leakedCorruptPaths.length === 0, `corrupt verification leaked staging paths: ${leakedCorruptPaths.join(', ')}`);
    const restoreCorrupt = await fs.open(firstChunk, 'r+');
    try {
      await restoreCorrupt.write(originalByte, 0, 1, 0);
      await restoreCorrupt.sync();
    } finally {
      await restoreCorrupt.close();
    }

    const missingBackup = `${lastChunk}.missing`;
    await fs.rename(lastChunk, missingBackup);
    await expectReject('reject missing chunk', () => verifyArchiveChunks({ manifestPath }), /ENOENT/);
    await fs.rename(missingBackup, lastChunk);

    const reordered = structuredClone(manifest);
    [reordered.chunks[0], reordered.chunks[1]] = [reordered.chunks[1], reordered.chunks[0]];
    await fs.writeFile(manifestPath, `${canonicalJson(reordered)}\n`, { flag: 'w' });
    await expectReject('reject reordered manifest entries', () => verifyArchiveChunks({ manifestPath }), /index must equal 0/);
    await fs.writeFile(manifestPath, manifestRaw, { flag: 'w' });

    const extraSchemaField = structuredClone(manifest);
    extraSchemaField.unexpected = true;
    await fs.writeFile(manifestPath, `${canonicalJson(extraSchemaField)}\n`, { flag: 'w' });
    await expectReject('reject extra manifest schema field', () => verifyArchiveChunks({ manifestPath }), /keys must be exactly/);
    await fs.writeFile(manifestPath, manifestRaw, { flag: 'w' });

    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'w' });
    await expectReject('reject noncanonical manifest JSON', () => verifyArchiveChunks({ manifestPath }), /not canonical/);
    await fs.writeFile(manifestPath, manifestRaw, { flag: 'w' });

    const invalidUtf8 = Buffer.from(manifestRaw, 'utf8');
    const tagOffset = invalidUtf8.indexOf(Buffer.from(ARCHIVE_CHUNK_TAG, 'utf8'));
    invariant(tagOffset >= 0, 'failed to locate tag for invalid UTF-8 test');
    invalidUtf8[tagOffset] = 0xff;
    await fs.writeFile(manifestPath, invalidUtf8, { flag: 'w' });
    await expectReject('reject invalid UTF-8 manifest', () => verifyArchiveChunks({ manifestPath }), /not valid UTF-8/);
    await fs.writeFile(manifestPath, manifestRaw, { flag: 'w' });

    const firstStat = await fs.stat(firstChunk);
    const oversizeHandle = await fs.open(firstChunk, 'a');
    try {
      await writeAll(oversizeHandle, Buffer.from([0]));
      await oversizeHandle.sync();
    } finally {
      await oversizeHandle.close();
    }
    await expectReject('reject oversize nonfinal chunk', () => verifyArchiveChunks({ manifestPath }), /size does not match/);
    await fs.truncate(firstChunk, firstStat.size);

    const symlinkBackup = `${firstChunk}.regular`;
    await fs.rename(firstChunk, symlinkBackup);
    await fs.symlink(path.basename(symlinkBackup), firstChunk);
    await expectReject('reject symlink chunk', () => verifyArchiveChunks({ manifestPath }), /must not be a symlink/);
    await fs.unlink(firstChunk);
    await fs.rename(symlinkBackup, firstChunk);

    await verifyArchiveChunks({ manifestPath });
    pass('verify restored baseline');

    console.log(canonicalJson({ results, status: 'self-test-pass', test_root: keep ? root : null }));
  } catch (error) {
    keep = true;
    console.error(`SELF-TEST FAILED; retained ${root}`);
    throw error;
  } finally {
    if (!keep) {
      await fs.rm(root, { force: true, recursive: true });
    }
  }
}

main().catch((error) => {
  console.error(`self-test: ${error.stack ?? error.message}`);
  process.exitCode = 1;
});
