// Single source of truth (for the site) for the current native-binary release.
// Bump RELEASE_VERSION in lockstep with the uploaded blob version on every release.
// Binaries live in a Vercel Blob store and are served behind a clean
// artifact.invalid/lispex/dl/<version>/<asset> path (the /dl rewrite in next.config.js ->
// LISPEX_BLOB_ORIGIN). CI (.github/workflows/release.yml) builds them; they are
// uploaded to the blob under lispex/<version>/ alongside lispex/latest.json.

// Full semver — keys the blob path and the download URLs (/dl/<RELEASE_VERSION>/…).
// Bump in lockstep with the uploaded binaries on every release.
export const RELEASE_VERSION = 'v1.4.0';

// The user-facing version (major.minor only). Derived from the semver, so
// there is ONE source of truth — v1.2.0 → v1.2. This is what docs and the downloads
// page display; URLs still use the full RELEASE_VERSION.
export const DISPLAY_VERSION = RELEASE_VERSION.replace(
  /^(v\d+\.\d+)\.\d+$/,
  '$1'
);

export const RELEASE_BASE = `https://artifact.invalid/lispex/dl/${RELEASE_VERSION}`;

export type ReleaseAsset = {
  os: 'Linux' | 'macOS' | 'Windows';
  arch: string;
  /** asset file name under lispex/<RELEASE_VERSION>/ in the Blob store */
  file: string;
  /** human label for the downloads table */
  label: string;
};

export const RELEASE_ASSETS: ReleaseAsset[] = [
  {
    os: 'Linux',
    arch: 'x86_64',
    file: 'lispex-linux-x86_64',
    label: 'Linux · x86_64',
  },
  {
    os: 'Linux',
    arch: 'aarch64',
    file: 'lispex-linux-aarch64',
    label: 'Linux · aarch64',
  },
  {
    os: 'macOS',
    arch: 'aarch64',
    file: 'lispex-macos-aarch64',
    label: 'macOS · Apple silicon',
  },
  {
    os: 'macOS',
    arch: 'x86_64',
    file: 'lispex-macos-x86_64',
    label: 'macOS · Intel',
  },
  {
    os: 'Windows',
    arch: 'x86_64',
    file: 'lispex-windows-x86_64.exe',
    label: 'Windows · x86_64',
  },
];

export function assetUrl(file: string): string {
  return `${RELEASE_BASE}/${file}`;
}
