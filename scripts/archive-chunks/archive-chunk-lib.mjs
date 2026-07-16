// SPDX-License-Identifier: Apache-2.0

import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { TextDecoder } from 'node:util';

export const ARCHIVE_CHUNK_TAG = 'vouch.scored26-archive-chunks/v1';
export const ARCHIVE_CHUNK_SIZE_BYTES = 7_340_032;
export const ARCHIVE_CHUNK_MANIFEST = 'archive-chunks.json';
export const ARCHIVE_FILENAME = 'vouch-scored26-artifact.tar.zst';
export const IO_BUFFER_BYTES = 1024 * 1024;
export const MAX_CHUNK_COUNT = 1_000_000;

export function invariant(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (isPlainObject(value)) {
    const output = {};
    for (const key of Object.keys(value).sort()) {
      output[key] = canonicalValue(value[key]);
    }
    return output;
  }
  invariant(
    value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value)),
    'canonical JSON input contains a non-JSON value',
  );
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function portableBasename(value, label) {
  invariant(typeof value === 'string' && value.length > 0, `${label} must be a non-empty string`);
  invariant(value !== '.' && value !== '..', `${label} must not be ${JSON.stringify(value)}`);
  invariant(path.posix.basename(value) === value, `${label} must be a basename`);
  invariant(path.win32.basename(value) === value, `${label} must be a portable basename`);
  invariant(!value.includes('\0'), `${label} must not contain NUL`);
  invariant(
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value),
    `${label} must use only portable printable ASCII letters, digits, dot, underscore, or hyphen`,
  );
  return value;
}

export function chunkPathFor(archiveFilename, index) {
  invariant(Number.isSafeInteger(index) && index >= 0 && index < MAX_CHUNK_COUNT, 'chunk index is out of range');
  return `${archiveFilename}.part-${String(index).padStart(6, '0')}`;
}

export async function lstatIfExists(targetPath) {
  try {
    return await fs.lstat(targetPath);
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

export async function requireAbsent(targetPath, label) {
  const stat = await lstatIfExists(targetPath);
  invariant(stat === null, `${label} already exists: ${targetPath}`);
}

export async function requireDirectoryNoSymlink(directoryPath, label) {
  const stat = await fs.lstat(directoryPath);
  invariant(!stat.isSymbolicLink(), `${label} must not be a symlink: ${directoryPath}`);
  invariant(stat.isDirectory(), `${label} is not a directory: ${directoryPath}`);
  return stat;
}

export async function requireRegularNoSymlink(filePath, label) {
  const stat = await fs.lstat(filePath);
  invariant(!stat.isSymbolicLink(), `${label} must not be a symlink: ${filePath}`);
  invariant(stat.isFile(), `${label} is not a regular file: ${filePath}`);
  return stat;
}

export async function openRegularNoFollow(filePath, label) {
  const before = await requireRegularNoSymlink(filePath, label);
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await fs.open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const after = await handle.stat();
    invariant(after.isFile(), `${label} is not a regular file: ${filePath}`);
    invariant(
      before.dev === after.dev && before.ino === after.ino,
      `${label} changed while it was being opened: ${filePath}`,
    );
    return { handle, stat: after };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

export async function fsyncDirectory(directoryPath) {
  const handle = await fs.open(directoryPath, fsConstants.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function writeAll(handle, buffer, offset = 0, length = buffer.length, position = null) {
  let written = 0;
  while (written < length) {
    const result = await handle.write(
      buffer,
      offset + written,
      length - written,
      position === null ? null : position + written,
    );
    invariant(result.bytesWritten > 0, 'short write made no progress');
    written += result.bytesWritten;
  }
}

export async function readExactly(handle, buffer, length, position) {
  let read = 0;
  while (read < length) {
    const result = await handle.read(buffer, read, length - read, position + read);
    invariant(result.bytesRead > 0, `unexpected end of file at byte ${position + read}`);
    read += result.bytesRead;
  }
}

export function assertExactKeys(object, expected, label) {
  invariant(isPlainObject(object), `${label} must be an object`);
  const actual = Object.keys(object).sort();
  const wanted = [...expected].sort();
  invariant(
    actual.length === wanted.length && actual.every((key, index) => key === wanted[index]),
    `${label} keys must be exactly ${wanted.join(', ')}`,
  );
}

export function assertSafePositiveInteger(value, label) {
  invariant(Number.isSafeInteger(value) && value > 0, `${label} must be a positive safe integer`);
}

export function assertSha256(value, label) {
  invariant(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), `${label} must be a lowercase SHA-256 hex digest`);
}

export async function parseCanonicalManifest(manifestPath) {
  const absoluteManifest = path.resolve(manifestPath);
  const manifestDirectory = path.dirname(absoluteManifest);
  await requireDirectoryNoSymlink(manifestDirectory, 'manifest directory');
  const { handle, stat } = await openRegularNoFollow(absoluteManifest, 'manifest');
  let bytes;
  try {
    bytes = await handle.readFile();
    const after = await handle.stat();
    invariant(after.size === stat.size, 'manifest size changed while it was read');
  } finally {
    await handle.close();
  }
  let raw;
  try {
    // Keeping a UTF-8 BOM in the decoded string makes the canonical-byte check
    // below reject it instead of silently discarding it.
    raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error('manifest is not valid UTF-8');
  }
  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (error) {
    throw new Error(`manifest is not valid JSON: ${error.message}`);
  }
  invariant(raw === `${canonicalJson(manifest)}\n`, 'manifest is not canonical sorted-key JSON with one trailing LF');
  validateManifest(manifest);
  return { absoluteManifest, manifestDirectory, manifest, raw };
}

export function validateManifest(manifest) {
  assertExactKeys(manifest, ['archive', 'chunk_size_bytes', 'chunks', 'tag'], 'manifest');
  invariant(manifest.tag === ARCHIVE_CHUNK_TAG, `manifest.tag must equal ${ARCHIVE_CHUNK_TAG}`);
  invariant(
    manifest.chunk_size_bytes === ARCHIVE_CHUNK_SIZE_BYTES,
    `manifest.chunk_size_bytes must equal ${ARCHIVE_CHUNK_SIZE_BYTES}`,
  );

  assertExactKeys(manifest.archive, ['bytes', 'filename', 'sha256'], 'manifest.archive');
  portableBasename(manifest.archive.filename, 'manifest.archive.filename');
  invariant(
    manifest.archive.filename === ARCHIVE_FILENAME,
    `manifest.archive.filename must equal ${ARCHIVE_FILENAME}`,
  );
  assertSafePositiveInteger(manifest.archive.bytes, 'manifest.archive.bytes');
  assertSha256(manifest.archive.sha256, 'manifest.archive.sha256');

  invariant(Array.isArray(manifest.chunks), 'manifest.chunks must be an array');
  const expectedCount = Math.ceil(manifest.archive.bytes / ARCHIVE_CHUNK_SIZE_BYTES);
  invariant(expectedCount > 0 && expectedCount <= MAX_CHUNK_COUNT, 'archive requires an unsupported number of chunks');
  invariant(manifest.chunks.length === expectedCount, `manifest.chunks must contain exactly ${expectedCount} entries`);

  let totalBytes = 0;
  for (let index = 0; index < manifest.chunks.length; index += 1) {
    const chunk = manifest.chunks[index];
    const label = `manifest.chunks[${index}]`;
    assertExactKeys(chunk, ['bytes', 'index', 'path', 'sha256'], label);
    invariant(chunk.index === index, `${label}.index must equal ${index}`);
    invariant(chunk.path === chunkPathFor(manifest.archive.filename, index), `${label}.path is not contiguous or canonical`);
    assertSha256(chunk.sha256, `${label}.sha256`);
    const expectedBytes = Math.min(
      ARCHIVE_CHUNK_SIZE_BYTES,
      manifest.archive.bytes - index * ARCHIVE_CHUNK_SIZE_BYTES,
    );
    assertSafePositiveInteger(chunk.bytes, `${label}.bytes`);
    invariant(chunk.bytes === expectedBytes, `${label}.bytes must equal ${expectedBytes}`);
    if (index < manifest.chunks.length - 1) {
      invariant(chunk.bytes === ARCHIVE_CHUNK_SIZE_BYTES, `${label} is nonfinal and must be exactly 7 MiB`);
    } else {
      invariant(
        chunk.bytes >= 1 && chunk.bytes <= ARCHIVE_CHUNK_SIZE_BYTES,
        `${label} is final and must be between 1 byte and 7 MiB`,
      );
    }
    totalBytes += chunk.bytes;
  }
  invariant(totalBytes === manifest.archive.bytes, 'sum of chunk bytes does not equal archive bytes');
  return manifest;
}

export function parseStrictFlags(argv, specification) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') {
      values.help = true;
      continue;
    }
    invariant(Object.hasOwn(specification, argument), `unknown argument: ${argument}`);
    invariant(!Object.hasOwn(values, specification[argument]), `duplicate argument: ${argument}`);
    invariant(index + 1 < argv.length, `missing value for ${argument}`);
    const value = argv[index + 1];
    invariant(!value.startsWith('--'), `missing value for ${argument}`);
    values[specification[argument]] = value;
    index += 1;
  }
  return values;
}
