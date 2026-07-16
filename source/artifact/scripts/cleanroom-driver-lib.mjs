import { randomUUID } from 'node:crypto';
import {
  closeSync,
  constants,
  cpSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';

import { writeArtifactJson } from './artifact-json.mjs';
import {
  parseCleanRunReport,
  parseFixtureReport,
  parseMutationReport,
  parsePerformanceReport,
  parseWorkloadReport,
  sha256Id,
} from './release-schema.mjs';

export const PHASE_1_COMPARISON_MISMATCH = 1;
export const ENVIRONMENT_BUFFER_CHUNK_BYTES = 24 * 1024;
const MAX_ENVIRONMENT_BUFFER_CHUNKS = 16;

export function copyPrivateNpmCache(source, destination) {
  if (existsSync(destination)) {
    throw new Error('private npm cache destination already exists');
  }
  requireRegularDirectoryTree(source);
  try {
    cpSync(source, destination, {
      recursive: true,
      errorOnExist: true,
      force: false,
    });
  } catch (error) {
    rmSync(destination, { recursive: true, force: true });
    throw error;
  }
  return destination;
}

export function selectFreshPhaseOneOutputRoot(
  cleanRoomRoot,
  exists = existsSync
) {
  const outputRoot = join(cleanRoomRoot, 'phase1-results');
  if (exists(outputRoot)) {
    throw new Error('phase-1 output directory already exists');
  }
  return outputRoot;
}

export function encodeEnvironmentBuffer(name, bytes) {
  requireEnvironmentBufferName(name);
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    throw new Error(`${name}: nonempty buffer is required`);
  }
  const encoded = bytes.toString('base64');
  const chunks = [];
  for (
    let offset = 0;
    offset < encoded.length;
    offset += ENVIRONMENT_BUFFER_CHUNK_BYTES
  ) {
    chunks.push(encoded.slice(offset, offset + ENVIRONMENT_BUFFER_CHUNK_BYTES));
  }
  if (chunks.length > MAX_ENVIRONMENT_BUFFER_CHUNKS) {
    throw new Error(`${name}: environment buffer exceeds the chunk budget`);
  }
  const environment = { [`${name}_CHUNK_COUNT`]: String(chunks.length) };
  for (const [index, chunk] of chunks.entries()) {
    environment[environmentChunkName(name, index)] = chunk;
  }
  return Object.freeze(environment);
}

export function consumeEnvironmentBuffer(environment, name) {
  requireEnvironmentBufferName(name);
  if (environment === null || typeof environment !== 'object') {
    throw new Error(`${name}: environment object is required`);
  }
  if (Object.hasOwn(environment, name)) {
    throw new Error(`${name}: unchunked environment buffer is forbidden`);
  }
  const countName = `${name}_CHUNK_COUNT`;
  const countText = environment[countName];
  if (!/^[1-9][0-9]*$/.test(countText ?? '')) {
    throw new Error(`${name}: invalid environment chunk count`);
  }
  const count = Number(countText);
  if (!Number.isSafeInteger(count) || count > MAX_ENVIRONMENT_BUFFER_CHUNKS) {
    throw new Error(`${name}: invalid environment chunk count`);
  }
  const expectedNames = new Set([countName]);
  const chunks = [];
  for (let index = 0; index < count; index += 1) {
    const chunkName = environmentChunkName(name, index);
    expectedNames.add(chunkName);
    const chunk = environment[chunkName];
    if (
      typeof chunk !== 'string' ||
      chunk.length === 0 ||
      chunk.length > ENVIRONMENT_BUFFER_CHUNK_BYTES ||
      (index + 1 < count &&
        chunk.length !== ENVIRONMENT_BUFFER_CHUNK_BYTES)
    ) {
      throw new Error(`${name}: invalid environment chunk ${index}`);
    }
    chunks.push(chunk);
  }
  for (const key of Object.keys(environment)) {
    if (
      key.startsWith(`${name}_CHUNK_`) &&
      !expectedNames.has(key)
    ) {
      throw new Error(`${name}: unexpected environment chunk`);
    }
  }
  const encoded = chunks.join('');
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length === 0 || bytes.toString('base64') !== encoded) {
    throw new Error(`${name}: environment chunks are not canonical base64`);
  }
  for (const key of expectedNames) delete environment[key];
  return bytes;
}

/**
 * Capture all bootstrap paths at one entry boundary. Input descriptors are
 * opened before any read or validation. Policy, D, and D-envelope are then
 * each read once; the untrusted archive remains an open descriptor and is
 * never read by JavaScript.
 */
export function captureBootstrapEntry(paths, io = new NodeBootstrapIo()) {
  const opened = [];
  let archive = null;
  try {
    const trustPolicy = io.openInput(paths.trustPolicy);
    opened.push(trustPolicy);
    const descriptor = io.openInput(paths.descriptor);
    opened.push(descriptor);
    const descriptorEnvelope = io.openInput(paths.descriptorEnvelope);
    opened.push(descriptorEnvelope);
    archive = io.openArchive(paths.archive);
    opened.push(archive);

    const buffers = Object.freeze({
      trustPolicy: Buffer.from(io.read(trustPolicy)),
      descriptor: Buffer.from(io.read(descriptor)),
      descriptorEnvelope: Buffer.from(io.read(descriptorEnvelope)),
    });
    if (!io.isRegular(archive)) {
      throw new Error('archive argument is not a regular non-symlink file');
    }
    for (const handle of [trustPolicy, descriptor, descriptorEnvelope]) {
      io.close(handle);
      opened.splice(opened.indexOf(handle), 1);
    }
    return Object.freeze({
      buffers,
      archive,
      closeArchive() {
        if (archive !== null) {
          io.close(archive);
          archive = null;
        }
      },
    });
  } catch (error) {
    for (const handle of opened.reverse()) {
      try {
        io.close(handle);
      } catch {}
    }
    archive = null;
    throw error;
  }
}

export class NodeBootstrapIo {
  openInput(path) {
    return openSync(path, constants.O_RDONLY | noFollow() | closeOnExec());
  }

  openArchive(path) {
    return openSync(path, constants.O_RDONLY | noFollow() | closeOnExec());
  }

  read(descriptor) {
    return readFileSync(descriptor);
  }

  isRegular(descriptor) {
    return fstatSync(descriptor).isFile();
  }

  close(descriptor) {
    closeSync(descriptor);
  }
}

export function readRegularFileOnce(path) {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | noFollow() | closeOnExec()
  );
  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new Error(`${path}: expected a regular non-symlink file`);
    }
    return Buffer.from(readFileSync(descriptor));
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Construct the comparison artifact and passing Q only from immutable buffers.
 * A single mismatch returns the contract's fixed exit code and no Q bytes.
 */
export function constructPhaseOneGate({
  descriptor,
  descriptorBytes,
  ownerBuffers,
  reproducedResultBuffers,
  cleanRunRuntimeSeconds,
}) {
  requireUint(cleanRunRuntimeSeconds, 'clean-run runtime');
  const fixtureReport = parseFixtureReport(ownerBuffers.fixtureReport);
  const workloadReport = parseWorkloadReport(ownerBuffers.workloadReport);
  const mutationReport = parseMutationReport(ownerBuffers.mutationReport);
  parsePerformanceReport(ownerBuffers.performanceReport);

  const expectedRows = descriptor.exact_reproduction_results;
  if (
    !(reproducedResultBuffers instanceof Map) ||
    reproducedResultBuffers.size !== expectedRows.length
  ) {
    throw new Error('regenerated exact-result path set differs from D');
  }
  const comparisons = expectedRows.map((expected) => {
    const bytes = reproducedResultBuffers.get(expected.path);
    if (!Buffer.isBuffer(bytes)) {
      throw new Error(`${expected.path}: regenerated exact result is absent`);
    }
    const observed = sha256Id(bytes);
    return {
      path: expected.path,
      expected_sha256: expected.sha256,
      observed_sha256: observed,
      matched: expected.sha256 === observed,
    };
  });
  for (const path of reproducedResultBuffers.keys()) {
    if (!expectedRows.some((row) => row.path === path)) {
      throw new Error(`${path}: unexpected regenerated exact result`);
    }
  }
  const comparisonBytes = writeArtifactJson({
    exact_reproduction_comparisons:
      'vouch.scored26-reproduction-comparisons/v0',
    comparisons,
  });
  if (comparisons.some((row) => !row.matched)) {
    return Object.freeze({
      exitCode: PHASE_1_COMPARISON_MISMATCH,
      comparisonBytes,
      qBytes: null,
      q: null,
    });
  }

  const q = {
    reproduction_report: 'vouch.scored26-reproduction/v0',
    status: 'pass',
    fixture_results: fixtureReport.fixture_results,
    workload: workloadReport.workload_summary,
    mutation: mutationReport.mutation_summary,
    clean_run_runtime_seconds: cleanRunRuntimeSeconds,
    fixture_report_sha256: sha256Id(ownerBuffers.fixtureReport),
    workload_report_sha256: sha256Id(ownerBuffers.workloadReport),
    mutation_report_sha256: sha256Id(ownerBuffers.mutationReport),
    performance_report_sha256: sha256Id(ownerBuffers.performanceReport),
    exact_reproduction_comparisons_sha256: sha256Id(comparisonBytes),
    release_descriptor_sha256: sha256Id(descriptorBytes),
    release_private_key_present: false,
    public_data_scan: 'pass',
    worktree_clean: true,
  };
  const qBytes = writeArtifactJson(q);
  parseCleanRunReport(qBytes);
  return Object.freeze({ exitCode: 0, comparisonBytes, qBytes, q });
}

export function atomicPublish(path, bytes) {
  if (!Buffer.isBuffer(bytes)) throw new Error(`${path}: bytes are required`);
  if (existsSync(path)) throw new Error(`${path}: refusing to replace output`);
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o755 });
  const staging = `${path}.staging-${process.pid}-${randomUUID()}`;
  let file = null;
  try {
    file = openSync(
      staging,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | closeOnExec(),
      0o644
    );
    writeFileSync(file, bytes);
    fsyncSync(file);
    closeSync(file);
    file = null;
    renameSync(staging, path);
    const parent = openSync(directory, constants.O_RDONLY | closeOnExec());
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  } catch (error) {
    if (file !== null) closeSync(file);
    rmSync(staging, { force: true });
    throw error;
  }
}

function requireUint(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} is not a uint`);
  }
}

function requireEnvironmentBufferName(name) {
  if (!/^[A-Z][A-Z0-9_]*$/.test(name)) {
    throw new Error('invalid environment buffer name');
  }
}

function environmentChunkName(name, index) {
  return `${name}_CHUNK_${String(index).padStart(2, '0')}`;
}

function requireRegularDirectoryTree(root) {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('npm cache source is not a regular directory');
  }
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error('npm cache source contains a symlink');
      }
      if (entry.isDirectory()) visit(path);
      else if (!entry.isFile()) {
        throw new Error('npm cache source contains a non-regular entry');
      }
    }
  };
  visit(root);
}

function noFollow() {
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    throw new Error('O_NOFOLLOW is unavailable on this platform');
  }
  return constants.O_NOFOLLOW;
}

function closeOnExec() {
  return Number.isInteger(constants.O_CLOEXEC) ? constants.O_CLOEXEC : 0;
}
