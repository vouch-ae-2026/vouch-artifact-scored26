import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

export function capturePaperSourceSnapshot(root) {
  const snapshot = {
    head: null,
    indexClean: false,
    worktreeClean: false,
    treeManifest: null,
    worktreeManifest: null,
    files: new Map(),
    modes: new Map(),
    readCounts: new Map(),
    captureErrors: [],
  };
  try {
    snapshot.head = git(root, ['rev-parse', '--verify', 'HEAD'])
      .toString('utf8')
      .trim();
  } catch (error) {
    snapshot.captureErrors.push(`head:${error.message}`);
    return Object.freeze(snapshot);
  }

  let treeEntries;
  let indexEntries;
  try {
    treeEntries = parseTree(
      git(root, ['ls-tree', '-rz', '--full-tree', snapshot.head])
    );
  } catch (error) {
    snapshot.captureErrors.push(`tree:${error.message}`);
    return Object.freeze(snapshot);
  }
  try {
    indexEntries = parseIndex(git(root, ['ls-files', '-s', '-z']));
  } catch (error) {
    snapshot.captureErrors.push(`index:${error.message}`);
    return Object.freeze(snapshot);
  }
  snapshot.indexClean =
    entryIdentity(treeEntries) === entryIdentity(indexEntries);

  try {
    const status = git(root, [
      'status',
      '--porcelain=v1',
      '--untracked-files=all',
      '--ignore-submodules=none',
    ]);
    snapshot.worktreeClean = status.length === 0;
  } catch (error) {
    snapshot.captureErrors.push(`worktree-status:${error.message}`);
  }

  let treeBytes;
  try {
    treeBytes = readBlobs(
      root,
      treeEntries.map((entry) => entry.oid)
    );
  } catch (error) {
    snapshot.captureErrors.push(`tree-blobs:${error.message}`);
    return Object.freeze(snapshot);
  }
  snapshot.treeManifest = treeEntries.map((entry, index) => ({
    path: entry.path,
    mode: entry.mode,
    sha256: ordinarySha256(treeBytes[index]),
  }));

  const worktreeManifest = [];
  for (const entry of indexEntries) {
    const count = snapshot.readCounts.get(entry.path) ?? 0;
    if (count !== 0) {
      snapshot.captureErrors.push(`tracked-path-reopened:${entry.path}`);
      snapshot.worktreeClean = false;
      continue;
    }
    snapshot.readCounts.set(entry.path, 1);
    try {
      const bytes = readFileSync(join(root, entry.path));
      snapshot.files.set(entry.path, Buffer.from(bytes));
      snapshot.modes.set(entry.path, entry.mode);
      worktreeManifest.push({
        path: entry.path,
        mode: entry.mode,
        sha256: ordinarySha256(bytes),
      });
    } catch (error) {
      snapshot.captureErrors.push(
        `tracked-path:${entry.path}:${error.message}`
      );
      snapshot.worktreeClean = false;
    }
  }
  snapshot.worktreeManifest = worktreeManifest;
  return Object.freeze(snapshot);
}

function parseTree(bytes) {
  return splitNull(bytes).map((record) => {
    const match = /^(\d{6}) (blob|commit) ([0-9a-f]{40})\t([\s\S]+)$/.exec(
      record
    );
    if (!match || match[2] !== 'blob')
      throw new Error('unsupported tree entry');
    return { mode: match[1], oid: match[3], path: match[4] };
  });
}

function parseIndex(bytes) {
  return splitNull(bytes).map((record) => {
    const match = /^(\d{6}) ([0-9a-f]{40}) ([0-3])\t([\s\S]+)$/.exec(record);
    if (!match || match[3] !== '0') throw new Error('unmerged index entry');
    return { mode: match[1], oid: match[2], path: match[4] };
  });
}

function splitNull(bytes) {
  const text = bytes.toString('utf8');
  if (text.length === 0) return [];
  if (!text.endsWith('\0')) throw new Error('unterminated NUL record');
  return text.slice(0, -1).split('\0');
}

function entryIdentity(entries) {
  return entries
    .map(({ mode, oid, path }) => `${mode} ${oid}\t${path}`)
    .join('\0');
}

function readBlobs(root, objectIds) {
  if (objectIds.length === 0) return [];
  const input = Buffer.from(`${objectIds.join('\n')}\n`, 'ascii');
  const output = git(root, ['cat-file', '--batch'], input, 1024 * 1024 * 1024);
  const blobs = [];
  let offset = 0;
  for (const expected of objectIds) {
    const newline = output.indexOf(0x0a, offset);
    if (newline < 0) throw new Error('truncated cat-file header');
    const header = output.subarray(offset, newline).toString('ascii');
    const match = /^([0-9a-f]{40}) blob ([0-9]+)$/.exec(header);
    if (!match || match[1] !== expected)
      throw new Error('cat-file identity mismatch');
    const length = Number(match[2]);
    if (!Number.isSafeInteger(length) || length < 0)
      throw new Error('cat-file length');
    const start = newline + 1;
    const end = start + length;
    if (end >= output.length || output[end] !== 0x0a)
      throw new Error('truncated cat-file body');
    blobs.push(Buffer.from(output.subarray(start, end)));
    offset = end + 1;
  }
  if (offset !== output.length) throw new Error('trailing cat-file output');
  return blobs;
}

function git(root, args, input = undefined, maxBuffer = 256 * 1024 * 1024) {
  const result = spawnSync('git', args, {
    cwd: root,
    input,
    encoding: 'buffer',
    maxBuffer,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${args.join(' ')} exited ${result.status}: ${result.stderr?.toString('utf8') ?? result.error?.message}`
    );
  }
  return result.stdout;
}

function ordinarySha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
