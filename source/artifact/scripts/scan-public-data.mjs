import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import {
  publicDataArchivePathPolicy,
  regularFiles,
  regularFilesAfterPhaseOneCheckout,
} from './release-layer-lib.mjs';

const options = parseArgs(process.argv.slice(2));
const suppliedRoot = resolve(options.get('--root'));
const root = realpathSync(suppliedRoot);
const bundle = realpathSync(options.get('--bundle'));
const files = options.has('--phase1-checkout')
  ? regularFilesAfterPhaseOneCheckout(
      suppliedRoot,
      options.get('--phase1-checkout')
    )
  : regularFiles(suppliedRoot);
const generatedJson = [];
for (const path of files) {
  const pathBytes = Buffer.from(path, 'utf8');
  scanKnownIdentityBytes(pathBytes, `archive-path:${path}`);
  scanText(pathBytes, `archive-path:${path}`, { cards: false });
  const policy = publicDataArchivePathPolicy(path);
  const bytes = readFileSync(join(root, ...path.split('/')));
  scanKnownIdentityBytes(bytes, `archive:${path}`);
  if (!policy.scanText && !policy.collectGeneratedJson) continue;
  if (policy.scanText && !thirdPartyDependencyPath(path)) {
    scanText(bytes, `archive:${path}`, { cards: cardScanPath(path) });
  }
  if (policy.collectGeneratedJson) {
    generatedJson.push([path, bytes]);
  }
}

const scratch = mkdtempSync(join(tmpdir(), 'scored26-public-data-scan-'));
try {
  const bare = join(scratch, 'repo.git');
  command('git', ['clone', '--quiet', '--bare', bundle, bare]);
  const identities = command(
    'git',
    ['log', '--all', '--format=%an%n%ae%n%cn%n%ce'],
    {
      cwd: bare,
    }
  ).stdout;
  validateCommitIdentities(identities);
  const messages = command('git', ['log', '--all', '--format=%B%x00'], {
    cwd: bare,
  }).stdout;
  const messageBytes = Buffer.from(messages, 'utf8');
  scanKnownIdentityBytes(messageBytes, 'reachable-commit-messages');
  scanText(messageBytes, 'reachable-commit-messages', { cards: false });
  scanReachableBlobs(bare);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
for (const [path, bytes] of generatedJson) scanSensitiveFields(path, bytes);
console.log('SCORED26 public-data scan passed (synthetic public inputs only)');

function scanText(bytes, label, { cards = true } = {}) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return;
  }
  for (const match of text.matchAll(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu
  )) {
    const email = match[0].toLowerCase();
    if (
      email.endsWith('@example.com') ||
      email.endsWith('@example.org') ||
      email.endsWith('@example.invalid')
    ) {
      continue;
    }
    throw new Error(`${label}: unapproved email-shaped value ${email}`);
  }
  for (const match of text.matchAll(
    /\b(?:phone|telephone|mobile|contact(?:[ _-]?number)?|tel)\b["']?\s*[:=]\s*["']?(\+?\d(?:[ .()_-]?\d){6,14})/giu
  )) {
    const digits = match[1].replace(/\D/g, '');
    if (digits.length >= 7 && digits.length <= 15) {
      throw new Error(`${label}: telephone-shaped value`);
    }
  }
  for (const match of text.matchAll(
    /\b(?:national[ _-]?id|social[ _-]?security|ssn|resident[ _-]?registration|passport(?:[ _-]?number)?|tax[ _-]?id)\b["']?\s*[:=]\s*["']?([A-Z0-9](?:[ _-]?[A-Z0-9]){5,19})/giu
  )) {
    const compact = match[1].replace(/[^A-Z0-9]/giu, '');
    if (compact.length >= 6 && compact.length <= 20) {
      throw new Error(`${label}: national-identifier-shaped value`);
    }
  }
  for (const match of text.matchAll(
    /\b\d{1,6}\s+[A-Z][A-Z.'-]*(?:\s+[A-Z][A-Z.'-]*){0,5}\s+(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr)\b/giu
  )) {
    if (match[0]) throw new Error(`${label}: street-address-shaped value`);
  }
  for (const match of text.matchAll(
    /\b(?:author|committer|full[ _-]?name|person[ _-]?name)\b["']?\s*[:=]\s*["']?([A-Z][\p{L}'-]+(?:\s+[A-Z][\p{L}'-]+){1,3})/gu
  )) {
    const candidate = match[1].toLowerCase();
    if (
      ![
        'artifact maintainer',
        'anonymous author',
        'anonymous authors',
      ].includes(candidate)
    ) {
      throw new Error(`${label}: unapproved proper-name-shaped value`);
    }
  }
  if (cards) {
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    const candidates = json === undefined ? [text] : jsonStrings(json);
    for (const candidate of candidates) {
      for (const match of candidate.matchAll(
        /(?:card|credit|debit|payment|\bpan\b)[^\n\d]{0,32}((?:\d[ -]?){13,19})/giu
      )) {
        const digits = match[1].replace(/\D/g, '');
        if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) {
          throw new Error(`${label}: payment-card-shaped value`);
        }
      }
    }
  }
}

function knownIdentityTokens() {
  return [
    [
      'first-party domain',
      [119, 119, 119, 46, 108, 105, 115, 112, 101, 120, 46, 99, 111, 109],
      'hostname',
    ],
    [
      'first-party domain',
      [108, 105, 115, 112, 101, 120, 46, 99, 111, 109],
      'hostname',
    ],
    [
      'organization domain',
      [
        115, 116, 117, 100, 105, 111, 104, 97, 122, 101, 46, 99, 111, 46, 107,
        114,
      ],
      'hostname',
    ],
    ['source-account handle', [99, 108, 97, 118, 101, 102], 'handle'],
    [
      'publishing-account handle',
      [103, 114, 101, 121, 102, 105, 108, 101],
      'handle',
    ],
    [
      'local user path',
      [47, 117, 115, 101, 114, 115, 47, 99, 115, 107, 101, 114, 110, 101, 108],
      'path',
    ],
    [
      'local user path',
      [47, 104, 111, 109, 101, 47, 99, 115, 107, 101, 114, 110, 101, 108],
      'path',
    ],
    [
      'external product identifier',
      [108, 101, 110, 97, 32, 99, 111, 100, 101],
      'word',
    ],
    [
      'external product identifier',
      [108, 101, 110, 97, 32, 101, 110, 103, 105, 110, 101],
      'word',
    ],
    [
      'external product identifier',
      [108, 101, 110, 97, 45, 101, 110, 103, 105, 110, 101],
      'word',
    ],
    [
      'external product identifier',
      [108, 101, 110, 97, 45, 103, 97, 116, 101, 45, 112, 114, 111, 111, 102],
      'word',
    ],
    ['external backend identifier', [116, 111, 112, 97, 122], 'word'],
  ];
}

function scanKnownIdentityBytes(bytes, label) {
  const normalized = bytes.toString('latin1').toLowerCase();
  for (const [kind, codePoints, boundary] of knownIdentityTokens()) {
    const token = String.fromCodePoint(...codePoints);
    if (containsBoundedToken(normalized, token, boundary)) {
      throw new Error(`${label}: forbidden ${kind}`);
    }
  }
}

function containsBoundedToken(text, token, boundary) {
  let offset = 0;
  while (offset <= text.length - token.length) {
    const index = text.indexOf(token, offset);
    if (index === -1) return false;
    const before = index === 0 ? '' : text[index - 1];
    const afterIndex = index + token.length;
    const after = afterIndex === text.length ? '' : text[afterIndex];
    let beforeOk;
    let afterOk;
    if (boundary === 'path') {
      beforeOk = true;
      afterOk = after === '' || after === '/' || after === '\\';
    } else if (boundary === 'hostname') {
      beforeOk = before === '' || before === '.' || !/[a-z0-9_-]/.test(before);
      afterOk = after === '' || !/[a-z0-9_-]/.test(after);
    } else if (boundary === 'handle') {
      beforeOk = before === '' || !/[a-z0-9_]/.test(before);
      afterOk = after === '' || !/[a-z0-9_]/.test(after);
    } else {
      beforeOk = before === '' || !/[a-z0-9._-]/.test(before);
      afterOk = after === '' || !/[a-z0-9._-]/.test(after);
    }
    if (beforeOk && afterOk) return true;
    offset = index + 1;
  }
  return false;
}

function validateCommitIdentities(text) {
  const fields = text.trim().split('\n');
  if (fields.length === 0 || fields.length % 4 !== 0) {
    throw new Error('reachable-commit-identities: malformed identity stream');
  }
  for (let index = 0; index < fields.length; index += 4) {
    const [authorName, authorEmail, committerName, committerEmail] =
      fields.slice(index, index + 4);
    if (
      authorName !== 'Artifact Maintainer' ||
      committerName !== 'Artifact Maintainer' ||
      authorEmail !== 'artifact@example.invalid' ||
      committerEmail !== 'artifact@example.invalid'
    ) {
      throw new Error(
        'reachable-commit-identities: non-anonymous commit identity'
      );
    }
  }
}

function jsonStrings(value) {
  const strings = [];
  const visit = (node) => {
    if (typeof node === 'string') strings.push(node);
    else if (Array.isArray(node)) node.forEach(visit);
    else if (node !== null && typeof node === 'object') {
      Object.values(node).forEach(visit);
    }
  };
  visit(value);
  return strings;
}

function scanReachableBlobs(bare) {
  const listing = command('git', ['rev-list', '--objects', '--all'], {
    cwd: bare,
  }).stdout;
  const pathsByObject = new Map();
  for (const line of listing.trim().split('\n')) {
    const separator = line.indexOf(' ');
    if (separator === -1) continue;
    const object = line.slice(0, separator);
    const path = line.slice(separator + 1);
    const pathBytes = Buffer.from(path, 'utf8');
    scanKnownIdentityBytes(pathBytes, `reachable-git-path:${path}`);
    scanText(pathBytes, `reachable-git-path:${path}`, { cards: false });
    const paths = pathsByObject.get(object) ?? [];
    paths.push(path);
    pathsByObject.set(object, paths);
  }
  const objects = [...pathsByObject.keys()];
  const batch = command('git', ['cat-file', '--batch'], {
    cwd: bare,
    encoding: 'buffer',
    input: Buffer.from(`${objects.join('\n')}\n`),
    maxBuffer: 1024 * 1024 * 1024,
  }).stdout;
  let offset = 0;
  for (const object of objects) {
    const newline = batch.indexOf(0x0a, offset);
    if (newline === -1) throw new Error('truncated Git batch header');
    const header = batch.subarray(offset, newline).toString('ascii');
    const match = /^([0-9a-f]{40}) ([a-z]+) ([0-9]+)$/.exec(header);
    if (!match || match[1] !== object) {
      throw new Error('malformed Git batch object header');
    }
    const length = Number(match[3]);
    const start = newline + 1;
    const end = start + length;
    if (end >= batch.length || batch[end] !== 0x0a) {
      throw new Error('truncated Git batch object');
    }
    if (match[2] === 'blob') {
      const paths = pathsByObject.get(object);
      const bytes = batch.subarray(start, end);
      const label = `reachable-git-blob:${paths.join(',')}`;
      scanKnownIdentityBytes(bytes, label);
      if (paths.some((path) => !thirdPartyDependencyPath(path))) {
        scanText(bytes, label, { cards: paths.some(cardScanPath) });
      }
    }
    offset = end + 1;
  }
  if (offset !== batch.length) throw new Error('extra Git batch output');
}

function thirdPartyDependencyPath(path) {
  return (
    path.startsWith('vendor/') ||
    path.startsWith('node_modules/') ||
    ['Cargo.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'].includes(
      path
    )
  );
}

function cardScanPath(path) {
  return (
    /\.(?:csv|md|mdx|tsv|txt|ya?ml)$/i.test(path) &&
    !(
      path.endsWith('.log') ||
      path.startsWith('artifact/mutation/') ||
      path.startsWith('artifact/results/') ||
      path.startsWith('artifact/workload/') ||
      path.startsWith('release/receipts/') ||
      path === 'release/replay-corpus.json' ||
      path === 'release/workload-execution.json'
    )
  );
}

function scanSensitiveFields(path, bytes) {
  let value;
  try {
    value = JSON.parse(bytes);
  } catch {
    return;
  }
  const forbidden = new Set([
    'address',
    'address_line1',
    'author_name',
    'committer_name',
    'email',
    'first_name',
    'full_name',
    'last_name',
    'mobile',
    'national_id',
    'passport_number',
    'person_name',
    'phone',
    'postal_address',
    'resident_registration_number',
    'ssn',
    'street_address',
    'tax_id',
    'telephone',
  ]);
  const visit = (node) => {
    if (Array.isArray(node)) return node.forEach(visit);
    if (node === null || typeof node !== 'object') return;
    for (const [name, child] of Object.entries(node)) {
      if (forbidden.has(name)) {
        throw new Error(`${path}: forbidden personal-data field ${name}`);
      }
      visit(child);
    }
  };
  visit(value);
}

function luhn(value) {
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = Number(value[index]);
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}

function parseArgs(raw) {
  if (
    ![4, 6].includes(raw.length) ||
    raw[0] !== '--root' ||
    !raw[1] ||
    raw[2] !== '--bundle' ||
    !raw[3] ||
    (raw.length === 6 && (raw[4] !== '--phase1-checkout' || !raw[5]))
  ) {
    throw new Error(
      'usage: scan-public-data --root <path> --bundle <path> [--phase1-checkout <path>]'
    );
  }
  const options = new Map([
    [raw[0], raw[1]],
    [raw[2], raw[3]],
  ]);
  if (raw.length === 6) options.set(raw[4], raw[5]);
  return options;
}

function command(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd,
    encoding: options.encoding ?? 'utf8',
    input: options.input,
    maxBuffer: options.maxBuffer ?? 128 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${program} failed during public-data scan`);
  }
  return result;
}
