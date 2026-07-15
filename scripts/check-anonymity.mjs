#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const failures = [];

const forbiddenIdentity = [
  ['Matt', 'Park'].join(' '),
  ['id', 'matt.kr'].join('@'),
  ['matt', 'studiohaze.co.kr'].join('@'),
  ['STUDIO', 'HAZE'].join(' '),
  ['Studio', 'Haze'].join(' '),
  ['clave', 'f'].join(''),
  ['grey', 'file'].join(''),
  ['vouch-ae', '2026'].join('-'),
  ['/Users', 'cskernel'].join('/'),
  ['D:', 'Projects'].join('\\'),
];

const allowedAbsoluteHits = new Map([
  [
    'adversarial/vouch-evidence-laundering/fixtures/a9.json',
    new Set(['/tmp/checkout-discount.ts']),
  ],
]);

const emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu;
const absolutePatterns = [
  /\/Users\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._/-]+)?/g,
  /\/home\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._/-]+)?/g,
  /[A-Za-z]:\\[A-Za-z0-9._\\/-]+/g,
];
const secretPatterns = [
  /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE\s+KEY-----/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /gh[pousr]_[A-Za-z0-9]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
];

function walk(path) {
  const files = [];
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const child = join(path, entry.name);
    if (entry.isSymbolicLink()) {
      failures.push('symbolic link is forbidden: ' + relative(root, child));
    } else if (entry.isDirectory()) {
      files.push(...walk(child));
    } else if (entry.isFile()) {
      files.push(child);
    } else {
      failures.push('non-regular entry is forbidden: ' + relative(root, child));
    }
  }
  return files;
}

function allowedEmail(value) {
  const lower = value.toLowerCase();
  return (
    lower.endsWith('@example.com') ||
    lower.endsWith('@example.org') ||
    lower.endsWith('@example.invalid') ||
    lower.endsWith('@lispex.dev') ||
    lower.endsWith('@topaz.dev') ||
    lower.endsWith('@topaz.ooo') ||
    lower.endsWith('@users.noreply.github.com') ||
    lower === 'noreply@github.com'
  );
}

function scan(label, value, options = {}) {
  const text = Buffer.isBuffer(value) ? value.toString('latin1') : String(value);
  const diagnostics = [];
  for (const needle of forbiddenIdentity) {
    if (text.includes(needle)) diagnostics.push('identity ' + JSON.stringify(needle));
  }
  for (const match of text.matchAll(emailPattern)) {
    if (!allowedEmail(match[0])) {
      diagnostics.push('unapproved email ' + JSON.stringify(match[0].toLowerCase()));
    }
  }
  if (options.absolutePaths !== false) {
    for (const pattern of absolutePatterns) {
      for (const match of text.matchAll(pattern)) {
        const allowed = allowedAbsoluteHits.get(label);
        if (!allowed?.has(match[0])) {
          diagnostics.push('absolute path ' + JSON.stringify(match[0]));
        }
      }
    }
  }
  for (const pattern of secretPatterns) {
    for (const match of text.matchAll(pattern)) {
      diagnostics.push('secret marker ' + JSON.stringify(match[0].slice(0, 24)));
    }
  }
  return diagnostics;
}

for (const file of walk(root)) {
  const label = relative(root, file).replaceAll('\\', '/');
  if (label === '.DS_Store' || label.endsWith('/.DS_Store')) {
    failures.push('macOS metadata file is forbidden: ' + label);
    continue;
  }
  for (const diagnostic of scan(label, readFileSync(file))) {
    failures.push(label + ': ' + diagnostic);
  }
}

const gitCheck = spawnSync(
  'git',
  ['log', '--all', '-p', '--no-ext-diff', '--no-textconv', '--format=fuller'],
  {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  }
);
if (gitCheck.status === 0) {
  for (const diagnostic of scan('reachable-git-history', gitCheck.stdout, {
    absolutePaths: false,
  })) {
    failures.push('reachable-git-history: ' + diagnostic);
  }
} else if (existsSync(join(root, '.git'))) {
  failures.push('reachable Git history scan failed');
}

const identityNegative = scan(
  'negative-identity',
  [['Matt', 'Park'].join(' ')].join('')
);
if (!identityNegative.some((row) => row.startsWith('identity '))) {
  failures.push('negative control failed to reject an identity string');
}
const keyNegative = scan(
  'negative-key',
  [['-----BEGIN', 'PRIVATE KEY-----'].join(' ')].join('')
);
if (!keyNegative.some((row) => row.startsWith('secret marker '))) {
  failures.push('negative control failed to reject a private-key marker');
}
const tokenNegative = scan(
  'negative-token',
  'ghp_' + 'a'.repeat(40)
);
if (!tokenNegative.some((row) => row.startsWith('secret marker '))) {
  failures.push('negative control failed to reject a token marker');
}

if (failures.length > 0) {
  console.error('anonymous bundle identity/secret check failed');
  for (const failure of failures) console.error('- ' + failure);
  process.exit(1);
}

console.log('anonymous bundle identity/secret check passed');
console.log('working tree and reachable anonymous Git history: zero identity/secret hits');
