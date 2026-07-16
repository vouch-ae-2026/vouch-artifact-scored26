import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  regularFiles,
  regularFilesAfterPhaseOneCheckout,
} from './release-layer-lib.mjs';

const options = parseArgs(process.argv.slice(2));
const root = resolve(options.get('--root'));
const files = options.has('--phase1-checkout')
  ? regularFilesAfterPhaseOneCheckout(root, options.get('--phase1-checkout'))
  : regularFiles(root);
const markers = [
  Buffer.from('-----BEGIN PRIVATE KEY-----'),
  Buffer.from('-----BEGIN ENCRYPTED PRIVATE KEY-----'),
  Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----'),
  Buffer.from('-----BEGIN RSA PRIVATE KEY-----'),
  Buffer.from('-----BEGIN EC PRIVATE KEY-----'),
  Buffer.from('302e020100300506032b657004220420', 'hex'),
];

for (const path of files) {
  if (path.startsWith('vendor/npm-cache/') || path.endsWith('.bundle'))
    continue;
  const bytes = readFileSync(`${root}/${path}`);
  if (markers.some((marker) => bytes.indexOf(marker) !== -1)) {
    throw new Error(`${path}: private-key marker detected`);
  }
}
console.log('SCORED26 generic private-key marker scan passed');

function parseArgs(raw) {
  if (
    ![2, 4].includes(raw.length) ||
    raw[0] !== '--root' ||
    !raw[1] ||
    (raw.length === 4 && (raw[2] !== '--phase1-checkout' || !raw[3]))
  ) {
    throw new Error(
      'usage: scan-private-key-markers --root <path> [--phase1-checkout <path>]'
    );
  }
  const options = new Map([[raw[0], raw[1]]]);
  if (raw.length === 4) options.set(raw[2], raw[3]);
  return options;
}
