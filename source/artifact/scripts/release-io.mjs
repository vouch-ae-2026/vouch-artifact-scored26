import { randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { ARTIFACT_JSON_LIMITS, ArtifactJsonError } from './artifact-json.mjs';

export class ReleaseIoError extends Error {
  constructor(code, inputArtifact = null) {
    super(code);
    this.name = 'ReleaseIoError';
    this.code = code;
    this.inputArtifact = inputArtifact;
  }
}

export class ReadOnceFileProvider {
  #counts = new Map();

  read(path, inputArtifact, maximumBytes = ARTIFACT_JSON_LIMITS.rawBytes) {
    const previous = this.#counts.get(path) ?? 0;
    if (previous !== 0)
      throw new ReleaseIoError('read-once-violation', inputArtifact);
    this.#counts.set(path, previous + 1);
    let descriptor;
    try {
      descriptor = openSync(path, 'r');
    } catch {
      throw new ReleaseIoError('input-output-failure', inputArtifact);
    }
    try {
      const chunks = [];
      let observed = 0;
      for (;;) {
        const capacity = Math.min(64 * 1024, maximumBytes + 1 - observed);
        if (capacity <= 0)
          throw new ArtifactJsonError(
            'artifact-resource-limit',
            'artifact-bytes'
          );
        const chunk = Buffer.allocUnsafe(capacity);
        const count = readSync(descriptor, chunk, 0, capacity, null);
        if (count === 0) break;
        observed += count;
        chunks.push(chunk.subarray(0, count));
        if (observed > maximumBytes) {
          throw new ArtifactJsonError(
            'artifact-resource-limit',
            'artifact-bytes'
          );
        }
      }
      return Buffer.concat(chunks, observed);
    } catch (error) {
      if (error instanceof ArtifactJsonError) throw error;
      throw new ReleaseIoError('input-output-failure', inputArtifact);
    } finally {
      closeSync(descriptor);
    }
  }

  count(path) {
    return this.#counts.get(path) ?? 0;
  }

  totalReads() {
    return [...this.#counts.values()].reduce((sum, value) => sum + value, 0);
  }
}

export class MemoryReadOnceFileProvider {
  #files = new Map();
  #counts = new Map();

  set(path, bytes) {
    this.#files.set(path, Buffer.from(bytes));
  }

  read(path, inputArtifact, maximumBytes = ARTIFACT_JSON_LIMITS.rawBytes) {
    const previous = this.#counts.get(path) ?? 0;
    if (previous !== 0)
      throw new ReleaseIoError('read-once-violation', inputArtifact);
    this.#counts.set(path, previous + 1);
    const bytes = this.#files.get(path);
    if (bytes === undefined)
      throw new ReleaseIoError('input-output-failure', inputArtifact);
    if (bytes.length > maximumBytes) {
      throw new ArtifactJsonError('artifact-resource-limit', 'artifact-bytes');
    }
    return Buffer.from(bytes);
  }

  replace(path, bytes) {
    if (!this.#files.has(path))
      throw new ReleaseIoError('input-output-failure');
    this.#files.set(path, Buffer.from(bytes));
  }

  count(path) {
    return this.#counts.get(path) ?? 0;
  }

  totalReads() {
    return [...this.#counts.values()].reduce((sum, value) => sum + value, 0);
  }
}

export class AtomicDirectoryPublisher {
  publish(output, files) {
    if (existsSync(output)) throw new ReleaseIoError('output-exists');
    const parent = dirname(output);
    const name = basename(output);
    if (name.length === 0 || name === '.' || name === '..') {
      throw new ReleaseIoError('invalid-output-name');
    }
    const staging = join(
      parent,
      `.${name}.staging-${process.pid}-${randomBytes(12).toString('hex')}`
    );
    let renamed = false;
    try {
      mkdirSync(staging, { mode: 0o700 });
      for (const [fileName, bytes] of [...files.entries()].sort(
        ([left], [right]) =>
          Buffer.compare(Buffer.from(left), Buffer.from(right))
      )) {
        if (!/^[a-z0-9][a-z0-9.-]*$/.test(fileName)) {
          throw new ReleaseIoError('invalid-output-name');
        }
        const path = join(staging, fileName);
        const descriptor = openSync(path, 'wx', 0o600);
        try {
          let offset = 0;
          while (offset < bytes.length) {
            const written = writeSync(
              descriptor,
              bytes,
              offset,
              bytes.length - offset,
              null
            );
            if (written <= 0) throw new ReleaseIoError('short-write');
            offset += written;
          }
          fsyncSync(descriptor);
        } finally {
          closeSync(descriptor);
        }
      }
      const directoryDescriptor = openSync(staging, 'r');
      try {
        fsyncSync(directoryDescriptor);
      } finally {
        closeSync(directoryDescriptor);
      }
      renameSync(staging, output);
      renamed = true;
    } catch (error) {
      if (error instanceof ReleaseIoError) throw error;
      throw new ReleaseIoError('input-output-failure');
    } finally {
      if (!renamed) rmSync(staging, { recursive: true, force: true });
    }
  }
}

export class MemoryAtomicDirectoryPublisher {
  #directories = new Map();
  #fault = null;
  #renames = 0;

  setFault(fault) {
    this.#fault = fault;
  }

  publish(output, files) {
    if (this.#directories.has(output))
      throw new ReleaseIoError('output-exists');
    if (this.#fault !== null) throw new ReleaseIoError(this.#fault);
    const captured = new Map();
    for (const [name, bytes] of files) captured.set(name, Buffer.from(bytes));
    this.#directories.set(output, captured);
    this.#renames += 1;
  }

  directory(output) {
    const value = this.#directories.get(output);
    if (value === undefined) return null;
    return new Map(
      [...value].map(([name, bytes]) => [name, Buffer.from(bytes)])
    );
  }

  renameCount() {
    return this.#renames;
  }
}
