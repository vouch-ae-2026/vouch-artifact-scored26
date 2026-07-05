#!/usr/bin/env node
'use strict';

// Lispex CLI — a thin local host wrapper around the SAME WebAssembly reference
// interpreter the browser playground uses. It implements NO evaluation itself:
// it loads the wasm-pack (--target nodejs) glue and calls `run_lispex`, so a
// program produces identical output locally and in the browser by construction.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const HELP = `lispex — run Lispex (.lspx) with the reference interpreter (WebAssembly)

Usage:
  lispex run <file.lspx>     Evaluate a file and print its output
  lispex <file.lspx>         Shorthand for "run"
  cat file.lspx | lispex     Evaluate source piped on stdin
  lispex verify <receipt>    Check a CSK differential receipt artifact and emit JSON
  lispex verify-bridge <report>
                             Check a Vouch Bridge report artifact and emit JSON
  lispex verify-bridge --expect-context <manifest.json> <report>
                             Check Bridge subject/profile/route against consumer intent
  lispex replay <corpus> --against <version-or-receipts-dir>
                             Emit a JSON replay report for a version pin or receipt set
  lispex --version            Print the version
  lispex --help               Show this help

Exit code: 0 on success, 1 on evaluation/artifact mismatch, 2 on usage or I/O.

A local wrapper around the SAME WebAssembly reference interpreter the browser
playground (https://www.lispex.com) runs — identical core, identical results.

The verify/replay commands are offline artifact-consistency checks. They do not
re-run the interpreter, generate receipts, authenticate receipt origin, or attest
semantic equivalence. verify-bridge checks external-engine Vouch Bridge reports;
it does not run the external engine or judge target-code correctness.`;

const DIFF_TAG = 'csk.differential-receipt/v0';
const BRIDGE_TAG = 'vouch.bridge-report/v0';
const BRIDGE_CONTEXT_TAG = 'vouch.bridge-context-manifest/v0';
const BRIDGE_VERIFY_REPORT_TAG = 'vouch.bridge-verify-report/v0';
const VERIFY_REPORT_TAG = 'csk.verify-report/v0';
const REPLAY_REPORT_TAG = 'csk.replay-report/v0';
const GALLERY_TAG = 'csk.profile-decision-gallery/v0';
const SOURCE_DOMAIN = 'lispex/source-hash/v0';
const CORE_DOMAIN = 'lispex/core-hash/v0';
const RUNTIME_DOMAIN = 'lispex/runtime-hash/v0';
const GRAPH_DOMAIN = 'csk/meaning-graph-hash/v0';
const ME_TRANSCRIPT_DOMAIN = 'csk/meaning-env-transcript-hash/v0';
const PROFILE_INPUT_DOMAIN = 'csk/profile-input-hash/v0';
const DECISION_GALLERY_MANIFEST_DOMAIN =
  'csk/decision-gallery-manifest-hash/v0';
const BRIDGE_EXTERNAL_SOURCE_DOMAIN = 'vouch/external-source-hash/v0';
const BRIDGE_EXTERNAL_TARGET_DOMAIN = 'vouch/external-target-hash/v0';
const BRIDGE_LINKED_ARTIFACT_DOMAIN = 'vouch/linked-artifact-hash/v0';
const SUBSTRATE = 'shared-rust-reference';

const PINNED_ATTESTS = [
  'source-bytes',
  'profile-input-hash-binding',
  'canonical-core-v0-bytes',
  'meaning-graph-v0-hash-binding',
  'reference-transcript-bytes',
  'meaning-env-transcript-bytes',
  'lowered-subset-transcript-agreement',
];

const PINNED_EXCLUDES = [
  'semantic-equivalence',
  'independent-witness',
  'substrate-independence',
  'error-agreement',
  'input-provenance',
  'topaz-reporting',
  'full-cskernel-coverage',
  'target-code-generation',
  'private-implementation-detail',
  'receipt-authenticity',
  'generation-honesty',
  'issuer-binding',
  'timestamping',
  'non-repudiation',
];

const NOT_COMPARABLE_REASONS = [
  'read-error',
  'normalize-error',
  'lowering-fault',
  'input-error',
  'reference-runtime-error',
  'meaning-env-fault',
];

const DIFF_RECEIPT_TOP_LEVEL_FIELDS = [
  'boundary',
  'canonical',
  'comparison',
  'diagnostics',
  'differential_receipt',
  'engine',
  'graph',
  'input',
  'meaning_env',
  'reference',
  'source',
];

const BRIDGE_TOP_LEVEL_FIELDS = [
  'bridge_report',
  'profile',
  'engine',
  'subject',
  'checks',
  'linked_artifacts',
  'summary',
  'boundary',
  'diagnostics',
];

const BRIDGE_ATTESTS = [
  'external-engine-evidence-shape',
  'source-target-byte-binding',
  'declared-gate-results',
  'linked-artifact-hash-binding',
  'boundary-disclosure',
];

const BRIDGE_EXCLUDES = [
  'target-code-correctness',
  'semantic-equivalence',
  'external-engine-execution',
  'private-engine-disclosure',
  'production-enforcement',
  'receipt-authenticity',
  'generation-honesty',
  'issuer-binding',
  'timestamping',
  'non-repudiation',
  'external-independent-verification',
  'full-cskernel-coverage',
];

function version() {
  try {
    return require('../package.json').version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function gitOutput(args) {
  const result = childProcess.spawnSync('git', args, {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  if (result.status !== 0) return null;
  return result.stdout.trim();
}

function validGitHex(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function artifactCommit() {
  const envHex = validGitHex(process.env.LISPEX_ARTIFACT_COMMIT_HEX)
    ? process.env.LISPEX_ARTIFACT_COMMIT_HEX
    : null;
  const hex =
    envHex ||
    (validGitHex(gitOutput(['rev-parse', 'HEAD']))
      ? gitOutput(['rev-parse', 'HEAD'])
      : '0000000000000000000000000000000000000000');
  let dirty;
  if (process.env.LISPEX_ARTIFACT_COMMIT_DIRTY === 'false') dirty = false;
  else if (process.env.LISPEX_ARTIFACT_COMMIT_DIRTY === 'true') dirty = true;
  else dirty = (gitOutput(['status', '--porcelain']) ?? 'dirty') !== '';
  return { vcs: 'git', hex, dirty };
}

function reportVerifier() {
  return {
    name: 'lispex-npm-artifact-checker',
    version: version(),
    commit: artifactCommit(),
    authorship_boundary: 'same-origin-public-spec-checker',
  };
}

function neutralPath(value) {
  const absolute = path.resolve(process.cwd(), value);
  const relativePath = path.relative(process.cwd(), absolute);
  if (
    relativePath &&
    !relativePath.startsWith('..') &&
    !path.isAbsolute(relativePath)
  ) {
    return relativePath.split(path.sep).join('/');
  }
  return path.basename(absolute);
}

function hashObject(domain, bytes) {
  return {
    algo: 'sha-256',
    domain,
    hex: hashWithDomain(domain, bytes),
  };
}

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function exactJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function orderedObject(value, orderedKeys) {
  if (!isObject(value)) return value;
  const next = {};
  for (const key of orderedKeys) {
    if (Object.prototype.hasOwnProperty.call(value, key))
      next[key] = value[key];
  }
  for (const key of Object.keys(value)) {
    if (!orderedKeys.includes(key)) next[key] = value[key];
  }
  return next;
}

function bridgeHashObject(value) {
  return orderedObject(value, ['algo', 'domain', 'hex']);
}

function canonicalBridgeValue(value) {
  if (Array.isArray(value)) return value.map(canonicalBridgeValue);
  if (!isObject(value)) return value;
  const top = orderedObject(value, BRIDGE_TOP_LEVEL_FIELDS);
  const next = {};
  for (const [key, entry] of Object.entries(top)) {
    if (key === 'profile') {
      next[key] = orderedObject(entry, ['kind', 'version']);
    } else if (key === 'engine') {
      const engine = orderedObject(entry, ['name', 'version', 'commit']);
      if (isObject(engine.commit)) {
        engine.commit = orderedObject(engine.commit, ['vcs', 'hex', 'dirty']);
      }
      next[key] = engine;
    } else if (key === 'subject') {
      const subject = orderedObject(entry, [
        'kind',
        'case_id',
        'source',
        'target',
        'route',
      ]);
      for (const side of ['source', 'target']) {
        if (isObject(subject[side])) {
          subject[side] = orderedObject(subject[side], [
            'language',
            'path',
            'byte_len',
            'hash',
          ]);
          if (isObject(subject[side].hash)) {
            subject[side].hash = bridgeHashObject(subject[side].hash);
          }
        }
      }
      if (isObject(subject.route)) {
        subject.route = orderedObject(subject.route, [
          'id',
          'checked_profile',
          'capability_ids',
        ]);
      }
      next[key] = subject;
    } else if (key === 'checks' && Array.isArray(entry)) {
      next[key] = entry.map((check) => {
        const ordered = orderedObject(check, [
          'id',
          'stage',
          'status',
          'artifact_hash',
        ]);
        if (isObject(ordered.artifact_hash)) {
          ordered.artifact_hash = bridgeHashObject(ordered.artifact_hash);
        }
        return ordered;
      });
    } else if (key === 'linked_artifacts' && Array.isArray(entry)) {
      next[key] = entry.map((artifact) => {
        const ordered = orderedObject(artifact, [
          'id',
          'kind',
          'path',
          'disclosure',
          'hash',
        ]);
        if (isObject(ordered.hash))
          ordered.hash = bridgeHashObject(ordered.hash);
        return ordered;
      });
    } else if (key === 'summary') {
      next[key] = orderedObject(entry, [
        'status',
        'check_count',
        'failed_checks',
        'not_run_checks',
      ]);
    } else if (key === 'boundary') {
      next[key] = orderedObject(entry, ['attests', 'excludes']);
    } else if (key === 'diagnostics' && Array.isArray(entry)) {
      next[key] = entry.map((diagnostic) =>
        orderedObject(diagnostic, ['code', 'message'])
      );
    } else {
      next[key] = canonicalBridgeValue(entry);
    }
  }
  return next;
}

function canonicalReceiptValue(value) {
  if (!isObject(value)) return value;
  return orderedObject(value, DIFF_RECEIPT_TOP_LEVEL_FIELDS);
}

function canonicalArtifactJson(value, kind) {
  if (kind === 'bridge') return exactJson(canonicalBridgeValue(value));
  if (kind === 'native') return exactJson(canonicalReceiptValue(value));
  return exactJson(value);
}

function inferredArtifactKind(value, fallbackKind) {
  if (!isObject(value)) return fallbackKind;
  const hasBridgeTag = value.bridge_report === BRIDGE_TAG;
  const hasNativeTag = value.differential_receipt === DIFF_TAG;
  if (hasBridgeTag && !hasNativeTag) return 'bridge';
  if (hasNativeTag && !hasBridgeTag) return 'native';
  return fallbackKind;
}

// A user-facing failure: a message + exit code, surfaced by the top-level catch.
class CliError {
  constructor(message, code) {
    this.message = message;
    this.code = code;
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stable(value) {
  return JSON.stringify(value);
}

function sameJson(left, right) {
  return stable(left) === stable(right);
}

function hashWithDomain(domain, bytes) {
  return crypto
    .createHash('sha256')
    .update(domain, 'utf8')
    .update(Buffer.from([0]))
    .update(bytes)
    .digest('hex');
}

function transcriptBytes(entries) {
  return Buffer.from(entries.map((entry) => `${entry}\n`).join(''), 'utf8');
}

function readJsonFile(file, command) {
  let text;
  try {
    text = fs.readFileSync(path.resolve(process.cwd(), file), 'utf8');
  } catch {
    throw new CliError(`${command}: cannot read file: ${file}`, 2);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new CliError(
      `${command}: invalid JSON in ${file}: ${error.message}`,
      2
    );
  }
}

function readJsonArtifactFile(file, command, kind) {
  let text;
  try {
    text = fs.readFileSync(path.resolve(process.cwd(), file), 'utf8');
  } catch {
    throw new CliError(`${command}: cannot read file: ${file}`, 2);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new CliError(
      `${command}: invalid JSON in ${file}: ${error.message}`,
      2
    );
  }
  const canonical = canonicalArtifactJson(
    value,
    inferredArtifactKind(value, kind)
  );
  return {
    value,
    text,
    canonical,
    canonicalFailures:
      text === canonical ? [] : ['non-canonical-artifact-json'],
  };
}

function expect(condition, failures, reason) {
  if (!condition) failures.push(reason);
}

function expectHashObject(obj, domain, failures, label) {
  expect(isObject(obj), failures, `${label}-hash-missing`);
  if (!isObject(obj)) return false;
  expect(obj.algo === 'sha-256', failures, `${label}-hash-algo`);
  expect(obj.domain === domain, failures, `${label}-hash-domain`);
  expect(
    typeof obj.hex === 'string' && /^[0-9a-f]{64}$/.test(obj.hex),
    failures,
    `${label}-hash-hex`
  );
  return (
    obj.algo === 'sha-256' &&
    obj.domain === domain &&
    typeof obj.hex === 'string'
  );
}

function expectStageHash(stage, domain, failures, label) {
  expect(isObject(stage), failures, `${label}-stage-missing`);
  if (!isObject(stage)) return;
  expect(
    Number.isInteger(stage.byte_len) && stage.byte_len >= 0,
    failures,
    `${label}-byte-len`
  );
  expectHashObject(stage.hash, domain, failures, label);
}

function stageTranscript(stage, failures, label) {
  expect(isObject(stage), failures, `${label}-stage-missing`);
  if (!isObject(stage)) return null;
  expect(
    Array.isArray(stage.transcript),
    failures,
    `${label}-transcript-array`
  );
  expect(
    Number.isInteger(stage.transcript_byte_len) &&
      stage.transcript_byte_len >= 0,
    failures,
    `${label}-transcript-byte-len`
  );
  if (!Array.isArray(stage.transcript)) return null;
  for (const entry of stage.transcript) {
    expect(typeof entry === 'string', failures, `${label}-transcript-entry`);
  }
  return stage.transcript.every((entry) => typeof entry === 'string')
    ? stage.transcript
    : null;
}

function firstDivergence(reference, meaningEnv) {
  const len = Math.max(reference.length, meaningEnv.length);
  for (let index = 0; index < len; index += 1) {
    const left = index < reference.length ? reference[index] : null;
    const right = index < meaningEnv.length ? meaningEnv[index] : null;
    if (left !== right) {
      return { index, reference: left, meaning_env: right };
    }
  }
  return null;
}

function expectedNotComparableReason(receipt) {
  if (receipt.canonical?.status === 'read-error') return 'read-error';
  if (receipt.canonical?.status === 'normalize-error') return 'normalize-error';
  if (receipt.graph?.status === 'fault') return 'lowering-fault';
  if (receipt.input?.status === 'error') return 'input-error';
  if (receipt.reference?.status === 'error') return 'reference-runtime-error';
  if (['fault', 'law-error'].includes(receipt.meaning_env?.status)) {
    return 'meaning-env-fault';
  }
  return null;
}

function expectedFaultClass(receipt, reason) {
  if (reason === 'lowering-fault') {
    return `lowering-${receipt.graph?.kind || 'fault'}`;
  }
  if (reason === 'meaning-env-fault') {
    if (receipt.meaning_env?.status === 'law-error') return 'meaning-law-error';
    return `meaning-${receipt.meaning_env?.fault?.kind || 'fault'}`;
  }
  return reason;
}

function verifyReceipt(receipt, options = {}) {
  const failures = [];
  const recomputed = [];
  const recordedOnly = [];

  if (!isObject(receipt)) {
    failures.push('receipt-not-object');
    return { ok: false, failures, recomputed, recordedOnly };
  }
  for (const field of Object.keys(receipt)) {
    if (!DIFF_RECEIPT_TOP_LEVEL_FIELDS.includes(field)) {
      failures.push(`unknown-top-level-field:${field}`);
    }
  }
  expect(receipt.differential_receipt === DIFF_TAG, failures, 'tag-mismatch');
  for (const field of DIFF_RECEIPT_TOP_LEVEL_FIELDS.filter(
    (field) => field !== 'differential_receipt'
  )) {
    expect(
      Object.prototype.hasOwnProperty.call(receipt, field),
      failures,
      `missing-${field}`
    );
  }

  expect(
    receipt.engine?.name === 'lispex-rust-reference',
    failures,
    'engine-name-mismatch'
  );
  expect(
    receipt.engine?.canonical_format === 'lispex.core.canonical/v0',
    failures,
    'engine-canonical-format-mismatch'
  );
  expect(isObject(receipt.engine?.commit), failures, 'engine-commit-missing');
  if (isObject(receipt.engine?.commit)) {
    expect(receipt.engine.commit.vcs === 'git', failures, 'engine-commit-vcs');
    expect(
      validGitHex(receipt.engine.commit.hex),
      failures,
      'engine-commit-hex'
    );
    expect(
      receipt.engine.commit.dirty === false,
      failures,
      'engine-commit-dirty'
    );
  }
  expect(Array.isArray(receipt.diagnostics), failures, 'diagnostics-not-array');

  expect(
    sameJson(receipt.boundary?.attests, PINNED_ATTESTS),
    failures,
    'boundary-attests-mismatch'
  );
  expect(
    sameJson(receipt.boundary?.excludes, PINNED_EXCLUDES),
    failures,
    'boundary-excludes-mismatch'
  );

  expectStageHash(receipt.source, SOURCE_DOMAIN, failures, 'source');
  if (options.sourcePath) {
    let sourceBytes;
    try {
      sourceBytes = fs.readFileSync(
        path.resolve(process.cwd(), options.sourcePath)
      );
    } catch {
      failures.push('source-file-unreadable');
      sourceBytes = null;
    }
    if (sourceBytes) {
      expect(
        receipt.source.byte_len === sourceBytes.length,
        failures,
        'source-byte-len-mismatch'
      );
      expect(
        receipt.source.hash?.hex === hashWithDomain(SOURCE_DOMAIN, sourceBytes),
        failures,
        'source-hash-mismatch'
      );
      recomputed.push('source');
    }
  } else {
    recordedOnly.push('source');
  }

  if (receipt.canonical?.status === 'ok') {
    expectStageHash(receipt.canonical, CORE_DOMAIN, failures, 'canonical');
    recordedOnly.push('canonical');
  } else {
    expect(
      typeof receipt.canonical?.status === 'string',
      failures,
      'canonical-status-missing'
    );
  }

  if (receipt.graph?.status === 'ok') {
    expectStageHash(receipt.graph, GRAPH_DOMAIN, failures, 'graph');
    recordedOnly.push('graph');
  } else {
    expect(
      typeof receipt.graph?.status === 'string',
      failures,
      'graph-status-missing'
    );
  }

  if (receipt.input?.status === 'bound') {
    expect(receipt.input.name === 'input', failures, 'input-name-mismatch');
    expect(
      typeof receipt.input.datum === 'string',
      failures,
      'input-datum-missing'
    );
    if (typeof receipt.input.datum === 'string') {
      const inputBytes = Buffer.from(receipt.input.datum, 'utf8');
      expect(
        receipt.input.byte_len === inputBytes.length,
        failures,
        'input-byte-len-mismatch'
      );
      expectHashObject(
        receipt.input.hash,
        PROFILE_INPUT_DOMAIN,
        failures,
        'input'
      );
      expect(
        receipt.input.hash?.hex ===
          hashWithDomain(PROFILE_INPUT_DOMAIN, inputBytes),
        failures,
        'input-hash-mismatch'
      );
      recomputed.push('profile-input');
    }
  } else {
    expect(
      ['absent', 'error'].includes(receipt.input?.status),
      failures,
      'input-status-invalid'
    );
  }

  if (['ok', 'fault', 'law-error'].includes(receipt.meaning_env?.status)) {
    const entries = stageTranscript(
      receipt.meaning_env,
      failures,
      'meaning-env'
    );
    if (entries) {
      const bytes = transcriptBytes(entries);
      expect(
        receipt.meaning_env.transcript_byte_len === bytes.length,
        failures,
        'meaning-env-transcript-byte-len-mismatch'
      );
      expectHashObject(
        receipt.meaning_env.hash,
        ME_TRANSCRIPT_DOMAIN,
        failures,
        'meaning-env'
      );
      expect(
        receipt.meaning_env.hash?.hex ===
          hashWithDomain(ME_TRANSCRIPT_DOMAIN, bytes),
        failures,
        'meaning-env-hash-mismatch'
      );
      recomputed.push('meaning-env-transcript');
    }
  } else {
    expect(
      ['not-run', undefined].includes(receipt.meaning_env?.status),
      failures,
      'meaning-env-status-invalid'
    );
  }

  if (receipt.reference?.status === 'ok') {
    const entries = stageTranscript(receipt.reference, failures, 'reference');
    expectHashObject(
      receipt.reference.hash,
      RUNTIME_DOMAIN,
      failures,
      'reference'
    );
    if (entries) {
      const bytes = transcriptBytes(entries);
      if (receipt.reference.transcript_byte_len === bytes.length) {
        expect(
          receipt.reference.hash?.hex === hashWithDomain(RUNTIME_DOMAIN, bytes),
          failures,
          'reference-hash-mismatch'
        );
        recomputed.push('reference-transcript');
      } else {
        recordedOnly.push('reference-transcript');
        if (receipt.comparison?.status === 'agree') {
          failures.push('reference-hash-not-recomputable');
        }
      }
    }
  } else if (receipt.reference?.status === 'error') {
    const entries = stageTranscript(receipt.reference, failures, 'reference');
    expect(
      receipt.reference.hash === null,
      failures,
      'reference-error-hash-not-null'
    );
    if (entries) {
      const bytes = transcriptBytes(entries);
      expect(
        receipt.reference.transcript_byte_len === bytes.length,
        failures,
        'reference-error-byte-len-mismatch'
      );
    }
  } else {
    expect(
      receipt.reference?.status === 'not-run',
      failures,
      'reference-status-invalid'
    );
  }

  const comparison = receipt.comparison;
  expect(isObject(comparison), failures, 'comparison-missing');
  if (isObject(comparison)) {
    expect(
      comparison.substrate === SUBSTRATE,
      failures,
      'comparison-substrate-mismatch'
    );
    const refEntries =
      Array.isArray(receipt.reference?.transcript) &&
      receipt.reference.transcript.every((entry) => typeof entry === 'string')
        ? receipt.reference.transcript
        : [];
    const meEntries =
      Array.isArray(receipt.meaning_env?.transcript) &&
      receipt.meaning_env.transcript.every((entry) => typeof entry === 'string')
        ? receipt.meaning_env.transcript
        : [];
    if (comparison.status === 'agree') {
      expect(
        receipt.reference?.status === 'ok',
        failures,
        'agree-reference-not-ok'
      );
      expect(
        receipt.meaning_env?.status === 'ok',
        failures,
        'agree-meaning-env-not-ok'
      );
      expect(
        sameJson(refEntries, meEntries),
        failures,
        'agree-transcript-mismatch'
      );
      expect(
        comparison.reason === 'transcript-bytes-equal',
        failures,
        'agree-reason-mismatch'
      );
      expect(
        comparison.first_divergence === null,
        failures,
        'agree-first-divergence-not-null'
      );
      expect(comparison.fault_class === null, failures, 'agree-fault-class');
      expect(
        Array.isArray(comparison.blockers) && comparison.blockers.length === 0,
        failures,
        'agree-blockers'
      );
    } else if (comparison.status === 'disagree') {
      expect(
        receipt.reference?.status === 'ok',
        failures,
        'disagree-reference-not-ok'
      );
      expect(
        receipt.meaning_env?.status === 'ok',
        failures,
        'disagree-meaning-env-not-ok'
      );
      expect(
        !sameJson(refEntries, meEntries),
        failures,
        'disagree-transcript-not-different'
      );
      expect(
        comparison.reason === 'transcript-bytes-differ',
        failures,
        'disagree-reason-mismatch'
      );
      expect(
        sameJson(
          comparison.first_divergence,
          firstDivergence(refEntries, meEntries)
        ),
        failures,
        'disagree-first-divergence-mismatch'
      );
      expect(comparison.fault_class === null, failures, 'disagree-fault-class');
      expect(
        Array.isArray(comparison.blockers) && comparison.blockers.length === 0,
        failures,
        'disagree-blockers'
      );
    } else if (comparison.status === 'not-comparable') {
      expect(
        comparison.first_divergence === null,
        failures,
        'not-comparable-divergence'
      );
      expect(
        NOT_COMPARABLE_REASONS.includes(comparison.reason),
        failures,
        'not-comparable-reason-invalid'
      );
      const expectedReason = expectedNotComparableReason(receipt);
      if (expectedReason) {
        expect(
          comparison.reason === expectedReason,
          failures,
          'not-comparable-reason-mismatch'
        );
        expect(
          comparison.fault_class ===
            expectedFaultClass(receipt, expectedReason),
          failures,
          'not-comparable-fault-class-mismatch'
        );
      }
      expect(
        Array.isArray(comparison.blockers) && comparison.blockers.length > 0,
        failures,
        'not-comparable-blockers'
      );
      if (
        Array.isArray(comparison.blockers) &&
        comparison.blockers.length > 0
      ) {
        expect(
          comparison.blockers[0]?.reason === comparison.reason,
          failures,
          'not-comparable-primary-blocker'
        );
        expect(
          comparison.blockers[0]?.fault_class === comparison.fault_class,
          failures,
          'not-comparable-primary-fault-class'
        );
        for (const blocker of comparison.blockers) {
          expect(isObject(blocker), failures, 'not-comparable-blocker-object');
          expect(
            NOT_COMPARABLE_REASONS.includes(blocker.reason),
            failures,
            'not-comparable-blocker-reason'
          );
          expect(
            typeof blocker.fault_class === 'string' &&
              blocker.fault_class.length > 0,
            failures,
            'not-comparable-blocker-fault-class'
          );
        }
      }
    } else {
      failures.push('comparison-status-invalid');
    }
  }

  return {
    ok: failures.length === 0,
    failures,
    recomputed: [...new Set(recomputed)],
    recordedOnly: [...new Set(recordedOnly)],
  };
}

function parseVerifyArgs(args) {
  let sourcePath = null;
  let receiptPath = null;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--source') {
      sourcePath = args[index + 1];
      if (!sourcePath)
        throw new CliError('lispex verify: --source requires a file', 2);
      index += 1;
    } else if (!arg.startsWith('-') && !receiptPath) {
      receiptPath = arg;
    } else {
      throw new CliError(`lispex verify: unexpected argument ${arg}`, 2);
    }
  }
  if (!receiptPath) throw new CliError('lispex verify: missing <receipt>', 2);
  return { receiptPath, sourcePath };
}

function verifyCommand(args) {
  const { receiptPath, sourcePath } = parseVerifyArgs(args);
  const receipt = readJsonFile(receiptPath, 'lispex verify');
  const core = verifyReceipt(receipt, { sourcePath });
  const exitCode = core.ok ? 0 : 1;
  const report = {
    verify_report: VERIFY_REPORT_TAG,
    verifier: reportVerifier(),
    inputs: {
      target: {
        path: neutralPath(receiptPath),
        tag: receipt?.differential_receipt ?? null,
      },
      source: sourcePath ? { path: neutralPath(sourcePath) } : null,
    },
    checks: {
      recomputed: core.recomputed,
      recorded_only: core.recordedOnly,
    },
    summary: {
      status: core.ok ? 'pass' : 'fail',
      exit_code: exitCode,
      failure_count: core.failures.length,
    },
    boundary: {
      attests: [
        'offline-artifact-self-consistency',
        'same-origin-js-check-path',
      ],
      excludes: [
        'external-independent-verification',
        'spec-blind-third-party-reimplementation',
        'receipt-authenticity',
        'generation-honesty',
        'issuer-binding',
        'timestamping',
        'non-repudiation',
        'semantic-equivalence',
        'substrate-independence',
        'input-provenance',
        'full-cskernel-coverage',
      ],
    },
    diagnostics: core.failures.map((failure) => ({ code: failure })),
  };
  writeJson(report);
  if (!core.ok) {
    process.stderr.write('receipt is not artifact-consistent\n');
    for (const failure of core.failures) process.stderr.write(`- ${failure}\n`);
  } else {
    process.stderr.write('receipt is artifact-consistent\n');
  }
  return exitCode;
}

function parseVerifyBridgeArgs(args) {
  let sourcePath = null;
  let targetPath = null;
  let contextPath = null;
  let reportPath = null;
  const linkedPaths = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--source') {
      sourcePath = args[index + 1];
      if (!sourcePath)
        throw new CliError('lispex verify-bridge: --source requires a file', 2);
      index += 1;
    } else if (arg === '--target') {
      targetPath = args[index + 1];
      if (!targetPath)
        throw new CliError('lispex verify-bridge: --target requires a file', 2);
      index += 1;
    } else if (arg === '--linked') {
      const value = args[index + 1];
      if (!value)
        throw new CliError(
          'lispex verify-bridge: --linked requires <id>=<file>',
          2
        );
      const equals = value.indexOf('=');
      if (equals <= 0 || equals === value.length - 1) {
        throw new CliError(
          'lispex verify-bridge: --linked requires <id>=<file>',
          2
        );
      }
      linkedPaths.set(value.slice(0, equals), value.slice(equals + 1));
      index += 1;
    } else if (arg === '--expect-context') {
      contextPath = args[index + 1];
      if (!contextPath)
        throw new CliError(
          'lispex verify-bridge: --expect-context requires a file',
          2
        );
      index += 1;
    } else if (!arg.startsWith('-') && !reportPath) {
      reportPath = arg;
    } else {
      throw new CliError(`lispex verify-bridge: unexpected argument ${arg}`, 2);
    }
  }
  if (!reportPath)
    throw new CliError('lispex verify-bridge: missing <report>', 2);
  return { reportPath, sourcePath, targetPath, contextPath, linkedPaths };
}

function expectString(value, failures, reason) {
  expect(typeof value === 'string' && value.length > 0, failures, reason);
}

function expectPathNeutral(value, failures, reason) {
  if (typeof value !== 'string') {
    failures.push(reason);
    return;
  }
  if (
    path.isAbsolute(value) ||
    /^[A-Za-z]:[\\/]/.test(value) ||
    value.includes('\\') ||
    value.includes('..')
  ) {
    failures.push(reason);
  }
}

function expectAllowedKeys(value, allowed, failures, pathLabel) {
  if (!isObject(value)) return;
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      failures.push(`unknown-field:${pathLabel}.${key}`);
  }
}

function expectHashObjectClosed(value, failures, pathLabel) {
  expectAllowedKeys(value, ['algo', 'domain', 'hex'], failures, pathLabel);
}

function checkBridgeClosedWorld(report, failures) {
  for (const field of Object.keys(report)) {
    if (!BRIDGE_TOP_LEVEL_FIELDS.includes(field)) {
      failures.push(`unknown-top-level-field:${field}`);
    }
  }
  expectAllowedKeys(report.profile, ['kind', 'version'], failures, 'profile');
  expectAllowedKeys(
    report.engine,
    ['name', 'version', 'commit'],
    failures,
    'engine'
  );
  if (isObject(report.engine?.commit)) {
    expectAllowedKeys(
      report.engine.commit,
      ['vcs', 'hex', 'dirty'],
      failures,
      'engine.commit'
    );
  }
  expectAllowedKeys(
    report.subject,
    ['kind', 'case_id', 'source', 'target', 'route'],
    failures,
    'subject'
  );
  for (const side of ['source', 'target']) {
    if (isObject(report.subject?.[side])) {
      expectAllowedKeys(
        report.subject[side],
        ['language', 'path', 'byte_len', 'hash'],
        failures,
        `subject.${side}`
      );
      expectHashObjectClosed(
        report.subject[side].hash,
        failures,
        `subject.${side}.hash`
      );
    }
  }
  if (isObject(report.subject?.route)) {
    expectAllowedKeys(
      report.subject.route,
      ['id', 'checked_profile', 'capability_ids'],
      failures,
      'subject.route'
    );
  }
  if (Array.isArray(report.checks)) {
    report.checks.forEach((check, index) => {
      expectAllowedKeys(
        check,
        ['id', 'stage', 'status', 'artifact_hash'],
        failures,
        `checks[${index}]`
      );
      if (isObject(check?.artifact_hash)) {
        expectHashObjectClosed(
          check.artifact_hash,
          failures,
          `checks[${index}].artifact_hash`
        );
      }
    });
  }
  if (Array.isArray(report.linked_artifacts)) {
    report.linked_artifacts.forEach((artifact, index) => {
      expectAllowedKeys(
        artifact,
        ['id', 'kind', 'path', 'disclosure', 'hash'],
        failures,
        `linked_artifacts[${index}]`
      );
      expectHashObjectClosed(
        artifact?.hash,
        failures,
        `linked_artifacts[${index}].hash`
      );
    });
  }
  expectAllowedKeys(
    report.summary,
    ['status', 'check_count', 'failed_checks', 'not_run_checks'],
    failures,
    'summary'
  );
  expectAllowedKeys(
    report.boundary,
    ['attests', 'excludes'],
    failures,
    'boundary'
  );
  if (Array.isArray(report.diagnostics)) {
    report.diagnostics.forEach((diagnostic, index) => {
      expectAllowedKeys(
        diagnostic,
        ['code', 'message'],
        failures,
        `diagnostics[${index}]`
      );
    });
  }
}

function checkBridgeContext(report, context, failures) {
  if (!context) return;
  if (!isObject(context)) {
    failures.push('context-manifest-not-object');
    return;
  }
  expectAllowedKeys(
    context,
    ['bridge_context_manifest', 'profile', 'subject'],
    failures,
    'context'
  );
  expectAllowedKeys(
    context.profile,
    ['kind', 'version'],
    failures,
    'context.profile'
  );
  expectAllowedKeys(
    context.subject,
    ['kind', 'case_id', 'route'],
    failures,
    'context.subject'
  );
  expectAllowedKeys(
    context.subject?.route,
    ['id', 'checked_profile', 'capability_ids'],
    failures,
    'context.subject.route'
  );
  expect(
    context.bridge_context_manifest === BRIDGE_CONTEXT_TAG,
    failures,
    'context-manifest-tag-mismatch'
  );
  if (!sameJson(context.profile, report.profile)) {
    failures.push('context-profile-mismatch');
  }
  if (context.subject?.kind !== report.subject?.kind) {
    failures.push('context-subject-kind-mismatch');
  }
  if (context.subject?.case_id !== report.subject?.case_id) {
    failures.push('context-case-id-mismatch');
  }
  if (context.subject?.route?.id !== report.subject?.route?.id) {
    failures.push('context-route-id-mismatch');
  }
  if (
    context.subject?.route?.checked_profile !==
    report.subject?.route?.checked_profile
  ) {
    failures.push('context-checked-profile-mismatch');
  }
  if (
    !sameJson(
      context.subject?.route?.capability_ids,
      report.subject?.route?.capability_ids
    )
  ) {
    failures.push('context-capability-ids-mismatch');
  }
}

function verifyBridgeReport(report, options = {}) {
  const failures = [];
  const recomputed = [];
  const recordedOnly = [];

  if (!isObject(report)) {
    failures.push('bridge-report-not-object');
    return { ok: false, failures, recomputed, recordedOnly };
  }

  checkBridgeClosedWorld(report, failures);
  for (const field of BRIDGE_TOP_LEVEL_FIELDS) {
    expect(
      Object.prototype.hasOwnProperty.call(report, field),
      failures,
      `missing-${field}`
    );
  }

  expect(report.bridge_report === BRIDGE_TAG, failures, 'tag-mismatch');
  expect(
    report.profile?.kind === 'conversion-evidence',
    failures,
    'profile-kind-mismatch'
  );
  expect(
    report.profile?.version === 'v0',
    failures,
    'profile-version-mismatch'
  );

  expectString(report.engine?.name, failures, 'engine-name-missing');
  expectString(report.engine?.version, failures, 'engine-version-missing');
  expect(isObject(report.engine?.commit), failures, 'engine-commit-missing');
  if (isObject(report.engine?.commit)) {
    expect(report.engine.commit.vcs === 'git', failures, 'engine-commit-vcs');
    expect(
      validGitHex(report.engine.commit.hex),
      failures,
      'engine-commit-hex'
    );
    expect(
      report.engine.commit.dirty === false,
      failures,
      'engine-commit-dirty'
    );
  }

  expect(
    report.subject?.kind === 'source-to-target-conversion',
    failures,
    'subject-kind-mismatch'
  );
  expectString(report.subject?.case_id, failures, 'subject-case-id-missing');
  expectString(report.subject?.route?.id, failures, 'route-id-missing');
  expectString(
    report.subject?.route?.checked_profile,
    failures,
    'route-checked-profile-missing'
  );
  expect(
    Array.isArray(report.subject?.route?.capability_ids),
    failures,
    'route-capability-ids'
  );

  for (const side of [
    ['source', BRIDGE_EXTERNAL_SOURCE_DOMAIN, options.sourcePath],
    ['target', BRIDGE_EXTERNAL_TARGET_DOMAIN, options.targetPath],
  ]) {
    const [key, domain, suppliedPath] = side;
    const stage = report.subject?.[key];
    expect(isObject(stage), failures, `${key}-missing`);
    if (!isObject(stage)) continue;
    expectString(stage.language, failures, `${key}-language-missing`);
    expectPathNeutral(stage.path, failures, `${key}-path-not-neutral`);
    expectStageHash(stage, domain, failures, key);
    if (suppliedPath) {
      let bytes;
      try {
        bytes = fs.readFileSync(path.resolve(process.cwd(), suppliedPath));
      } catch {
        failures.push(`${key}-file-unreadable`);
        bytes = null;
      }
      if (bytes) {
        expect(
          stage.byte_len === bytes.length,
          failures,
          `${key}-byte-len-mismatch`
        );
        expect(
          stage.hash?.hex === hashWithDomain(domain, bytes),
          failures,
          `${key}-hash-mismatch`
        );
        recomputed.push(key);
      }
    } else {
      recordedOnly.push(key);
    }
  }

  const linkedById = new Map();

  expect(Array.isArray(report.checks), failures, 'checks-not-array');
  if (Array.isArray(report.checks)) {
    const checkIds = new Set();
    for (const check of report.checks) {
      expect(isObject(check), failures, 'check-not-object');
      if (!isObject(check)) continue;
      expectString(check.id, failures, 'check-id-missing');
      if (checkIds.has(check.id)) failures.push(`duplicate-check:${check.id}`);
      checkIds.add(check.id);
      expect(
        ['pass', 'fail', 'not-run'].includes(check.status),
        failures,
        `check-status-invalid:${check.id}`
      );
      expectString(check.stage, failures, `check-stage-missing:${check.id}`);
      if (check.artifact_hash !== null) {
        expectHashObject(
          check.artifact_hash,
          BRIDGE_LINKED_ARTIFACT_DOMAIN,
          failures,
          `check-${check.id}-artifact`
        );
      }
    }
  }

  expect(
    Array.isArray(report.linked_artifacts),
    failures,
    'linked-artifacts-not-array'
  );
  if (Array.isArray(report.linked_artifacts)) {
    for (const artifact of report.linked_artifacts) {
      expect(isObject(artifact), failures, 'linked-artifact-not-object');
      if (!isObject(artifact)) continue;
      expectString(artifact.id, failures, 'linked-artifact-id-missing');
      if (typeof artifact.id === 'string')
        linkedById.set(artifact.id, artifact);
      expectString(artifact.kind, failures, 'linked-artifact-kind-missing');
      expectPathNeutral(
        artifact.path,
        failures,
        `linked-artifact-${artifact.id}-path-not-neutral`
      );
      expect(
        ['hash-only', 'public-bytes'].includes(artifact.disclosure),
        failures,
        `linked-artifact-disclosure-invalid:${artifact.id}`
      );
      expectHashObject(
        artifact.hash,
        BRIDGE_LINKED_ARTIFACT_DOMAIN,
        failures,
        `linked-artifact-${artifact.id}`
      );
    }
  }

  if (options.linkedPaths instanceof Map && options.linkedPaths.size > 0) {
    for (const [id, suppliedPath] of options.linkedPaths.entries()) {
      const artifact = linkedById.get(id);
      if (!artifact) {
        failures.push(`linked-artifact-unexpected:${id}`);
        continue;
      }
      let bytes;
      try {
        bytes = fs.readFileSync(path.resolve(process.cwd(), suppliedPath));
      } catch {
        failures.push(`linked-artifact-file-unreadable:${id}`);
        bytes = null;
      }
      if (bytes) {
        expect(
          artifact.hash?.hex ===
            hashWithDomain(BRIDGE_LINKED_ARTIFACT_DOMAIN, bytes),
          failures,
          'linked-artifact-hash-mismatch'
        );
        recomputed.push(`linked_artifact:${id}`);
      }
    }
  }

  const failedChecks = Array.isArray(report.checks)
    ? report.checks.filter((check) => check?.status === 'fail').length
    : 0;
  const notRunChecks = Array.isArray(report.checks)
    ? report.checks.filter((check) => check?.status === 'not-run').length
    : 0;
  expect(
    ['pass', 'fail'].includes(report.summary?.status),
    failures,
    'summary-status-invalid'
  );
  expect(
    report.summary?.check_count === (report.checks?.length ?? 0),
    failures,
    'summary-check-count-mismatch'
  );
  expect(
    report.summary?.failed_checks === failedChecks,
    failures,
    'summary-failed-checks-mismatch'
  );
  expect(
    report.summary?.not_run_checks === notRunChecks,
    failures,
    'summary-not-run-checks-mismatch'
  );
  if (failedChecks > 0 || notRunChecks > 0) {
    expect(report.summary?.status === 'fail', failures, 'summary-should-fail');
  } else {
    expect(report.summary?.status === 'pass', failures, 'summary-should-pass');
  }

  expect(
    sameJson(report.boundary?.attests, BRIDGE_ATTESTS),
    failures,
    'boundary-attests-mismatch'
  );
  expect(
    sameJson(report.boundary?.excludes, BRIDGE_EXCLUDES),
    failures,
    'boundary-excludes-mismatch'
  );
  expect(Array.isArray(report.diagnostics), failures, 'diagnostics-not-array');
  checkBridgeContext(report, options.context, failures);

  const structurallyOk = failures.length === 0;
  return {
    ok: structurallyOk && report.summary?.status === 'pass',
    failures,
    recomputed: [...new Set(recomputed)],
    recordedOnly: [...new Set(recordedOnly)],
  };
}

function verifyBridgeCommand(args) {
  const { reportPath, sourcePath, targetPath, contextPath, linkedPaths } =
    parseVerifyBridgeArgs(args);
  const artifact = readJsonArtifactFile(
    reportPath,
    'lispex verify-bridge',
    'bridge'
  );
  let context = null;
  if (contextPath) {
    context = readJsonFile(
      contextPath,
      'lispex verify-bridge --expect-context'
    );
  }
  const core =
    artifact.canonicalFailures.length > 0
      ? {
          ok: false,
          failures: artifact.canonicalFailures,
          recomputed: [],
          recordedOnly: [],
        }
      : verifyBridgeReport(artifact.value, {
          sourcePath,
          targetPath,
          linkedPaths,
          context,
        });
  const exitCode = core.ok ? 0 : 1;
  const report = {
    bridge_verify_report: BRIDGE_VERIFY_REPORT_TAG,
    verifier: reportVerifier(),
    inputs: {
      target: {
        path: neutralPath(reportPath),
        tag:
          artifact.canonicalFailures.length === 0
            ? (artifact.value?.bridge_report ?? null)
            : null,
      },
      source: sourcePath ? { path: neutralPath(sourcePath) } : null,
      target_code: targetPath ? { path: neutralPath(targetPath) } : null,
      context: contextPath ? { path: neutralPath(contextPath) } : null,
      linked_artifacts:
        linkedPaths.size > 0
          ? [...linkedPaths.entries()].map(([id, linkedPath]) => ({
              id,
              path: neutralPath(linkedPath),
            }))
          : [],
    },
    checks: {
      recomputed: core.recomputed,
      recorded_only: core.recordedOnly,
    },
    summary: {
      status: core.ok ? 'pass' : 'fail',
      exit_code: exitCode,
      failure_count: core.failures.length,
    },
    boundary: {
      attests: [
        'external-engine-evidence-shape',
        'source-target-byte-binding',
        'same-origin-js-check-path',
      ],
      excludes: [
        'target-code-correctness',
        'semantic-equivalence',
        'external-engine-execution',
        'private-engine-disclosure',
        'production-enforcement',
        'receipt-authenticity',
        'generation-honesty',
        'issuer-binding',
        'timestamping',
        'non-repudiation',
        'external-independent-verification',
        'full-cskernel-coverage',
      ],
    },
    diagnostics: core.failures.map((failure) => ({ code: failure })),
  };
  writeJson(report);
  if (!core.ok) {
    process.stderr.write('bridge report is not artifact-consistent\n');
    for (const failure of core.failures) process.stderr.write(`- ${failure}\n`);
  } else {
    process.stderr.write('bridge report is artifact-consistent\n');
  }
  return exitCode;
}

function semverLike(value) {
  return /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value);
}

function normalizedVersion(value) {
  return value.replace(/^v/, '');
}

function parseReplayArgs(args) {
  if (!args[0]) throw new CliError('lispex replay: missing <corpus>', 2);
  const corpusPath = args[0];
  let against = null;
  for (let index = 1; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--against') {
      against = args[index + 1];
      if (!against)
        throw new CliError('lispex replay: --against requires a value', 2);
      index += 1;
    } else {
      throw new CliError(`lispex replay: unexpected argument ${arg}`, 2);
    }
  }
  if (!against)
    throw new CliError(
      'lispex replay: missing --against <version-or-receipts-dir>',
      2
    );
  return { corpusPath, against };
}

function listJsonFiles(dir, command) {
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch {
    throw new CliError(`${command}: cannot read directory: ${dir}`, 2);
  }
  return entries.filter((entry) => entry.endsWith('.json')).sort();
}

function stemOf(file) {
  return path.basename(file, '.json');
}

function readReceiptDir(dir, command) {
  const receipts = new Map();
  for (const entry of listJsonFiles(dir, command)) {
    receipts.set(stemOf(entry), readJsonFile(path.join(dir, entry), command));
  }
  return receipts;
}

function readDecisionCorpus(corpusPath) {
  const abs = path.resolve(process.cwd(), corpusPath);
  const manifestPath = path.join(abs, 'manifest.json');
  let manifestBytes;
  let manifest;
  try {
    manifestBytes = fs.readFileSync(manifestPath);
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    throw new CliError(
      `lispex replay: cannot read manifest.json: ${error.message}`,
      2
    );
  }
  if (manifest.decision_gallery !== GALLERY_TAG) {
    throw new CliError('lispex replay: unsupported corpus manifest', 2);
  }
  if (!Array.isArray(manifest.cases)) {
    throw new CliError('lispex replay: manifest cases must be an array', 2);
  }
  const expectedDir = path.join(abs, 'expected');
  const receipts = readReceiptDir(expectedDir, 'lispex replay');
  const stems = manifest.cases.map((entry) => entry && entry.stem);
  if (!stems.every((stem) => typeof stem === 'string')) {
    throw new CliError('lispex replay: manifest cases need string stems', 2);
  }
  return {
    abs,
    id: neutralPath(abs),
    manifest,
    manifestHash: hashObject(DECISION_GALLERY_MANIFEST_DOMAIN, manifestBytes),
    expectedDir,
    receipts,
    stems,
  };
}

function verifyPrecondition(receipts, label) {
  const failures = [];
  for (const [stem, receipt] of receipts) {
    const report = verifyReceipt(receipt);
    if (!report.ok) {
      failures.push(`${label}/${stem}: ${report.failures.join(', ')}`);
    }
  }
  return failures;
}

function transcriptPayload(stage) {
  if (!Array.isArray(stage?.transcript)) return null;
  return transcriptBytes(stage.transcript).toString('utf8');
}

function compareStemSets(left, right) {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  const added = [...rightSet].filter((stem) => !leftSet.has(stem)).sort();
  const removed = [...leftSet].filter((stem) => !rightSet.has(stem)).sort();
  return { added, removed };
}

function artifactHash(stage) {
  return isObject(stage?.hash) ? stage.hash : null;
}

const DECISION_REASON_RE =
  '[A-Za-z_+\\-*/<>=!?$%&~^:.][A-Za-z0-9_+\\-*/<>=!?$%&~^:.]*';

function notProjected(reason) {
  return { status: 'not_projected', reason };
}

function parseDecisionDatum(text) {
  if (typeof text !== 'string' || text.trim() !== text || /\s{2,}/.test(text)) {
    return notProjected('not-projectable-non-canonical-datum');
  }
  if (text === '(decision allow)') {
    return {
      status: 'projected',
      value: { decision_datum: 'csk.decision-datum/v0', kind: 'allow' },
    };
  }
  const reason = DECISION_REASON_RE;
  const deny = text.match(new RegExp(`^\\(decision deny (${reason})\\)$`));
  if (deny) {
    return {
      status: 'projected',
      value: {
        decision_datum: 'csk.decision-datum/v0',
        kind: 'deny',
        reason: deny[1],
      },
    };
  }
  const amountShape = text.match(/^\(decision amount ([^\s()]+) ([^\s()]+)\)$/);
  if (amountShape) {
    if (!/^-?[0-9]+$/.test(amountShape[1])) {
      return notProjected('not-projectable-amount-not-exact-integer');
    }
    if (!new RegExp(`^${reason}$`).test(amountShape[2])) {
      return notProjected('not-projectable-invalid-reason');
    }
    return {
      status: 'projected',
      value: {
        decision_datum: 'csk.decision-datum/v0',
        kind: 'amount',
        amount_cents: amountShape[1],
        reason: amountShape[2],
      },
    };
  }
  const invalid = text.match(
    new RegExp(`^\\(decision invalid-input (${reason})\\)$`)
  );
  if (invalid) {
    return {
      status: 'projected',
      value: {
        decision_datum: 'csk.decision-datum/v0',
        kind: 'invalid-input',
        reason: invalid[1],
      },
    };
  }
  if (/^\(decision (deny|invalid-input) /.test(text)) {
    return notProjected('not-projectable-invalid-reason');
  }
  return notProjected('not-projectable-unknown-decision-shape');
}

function projectDecisionSide(receipt) {
  if (!receipt) return null;
  if (receipt.comparison?.status !== 'agree') {
    if (
      receipt.reference?.status !== 'ok' ||
      receipt.meaning_env?.status !== 'ok'
    ) {
      return notProjected('not-attempted-runtime-or-meaning-fault');
    }
    return notProjected('not-attempted-case-not-agree');
  }
  const transcript = receipt.reference?.transcript;
  if (!Array.isArray(transcript) || transcript.length === 0) {
    return notProjected('not-projectable-empty-transcript');
  }
  if (transcript.length !== 1) {
    return notProjected('not-projectable-multiple-transcript-datums');
  }
  const parsed = parseDecisionDatum(transcript[0]);
  if (parsed.status !== 'projected') return parsed;
  return {
    status: 'projected',
    datum: transcript[0],
    value: parsed.value,
  };
}

function projectedValue(side) {
  return side?.status === 'projected' ? side.value : null;
}

function decisionProjection(oldReceipt, newReceipt) {
  const old = projectDecisionSide(oldReceipt);
  const newSide = projectDecisionSide(newReceipt);
  if (!old && !newSide) return null;
  const oldValue = projectedValue(old);
  const newValue = projectedValue(newSide);
  return {
    old,
    new: newSide,
    decision_changed:
      oldValue && newValue ? !sameJson(oldValue, newValue) : null,
  };
}

function caseLayer(stem, oldReceipt, newReceipt) {
  const oldLayer = oldReceipt
    ? {
        source_hash: artifactHash(oldReceipt.source),
        transcript_hash: artifactHash(oldReceipt.reference),
        status: oldReceipt.comparison?.status ?? null,
        fault_class: oldReceipt.comparison?.fault_class ?? null,
      }
    : null;
  const newLayer = newReceipt
    ? {
        source_hash: artifactHash(newReceipt.source),
        transcript_hash: artifactHash(newReceipt.reference),
        status: newReceipt.comparison?.status ?? null,
        fault_class: newReceipt.comparison?.fault_class ?? null,
      }
    : null;
  return {
    case_id: stem,
    input_hash:
      artifactHash(newReceipt?.input) ?? artifactHash(oldReceipt?.input),
    old: oldLayer,
    new: newLayer,
    changed: !sameJson(oldLayer, newLayer),
    decision: decisionProjection(oldReceipt, newReceipt),
  };
}

function summarizeReplay(status, exitCode, cases) {
  let byteChanged = 0;
  let decisionChanged = 0;
  let notProjectable = 0;
  let faults = 0;
  for (const record of cases) {
    if (record.changed) byteChanged += 1;
    const decision = record.decision;
    if (decision?.decision_changed === true) decisionChanged += 1;
    for (const side of [decision?.old, decision?.new]) {
      if (side?.status === 'not_projected') notProjectable += 1;
    }
    if (
      record.old?.status === 'not-comparable' ||
      record.new?.status === 'not-comparable'
    ) {
      faults += 1;
    }
  }
  return {
    status,
    exit_code: exitCode,
    total: cases.length,
    byte_changed: byteChanged,
    decision_changed: decisionChanged,
    not_projectable: notProjectable,
    faults,
  };
}

function replayReport({
  corpus,
  against,
  mode,
  status,
  exitCode,
  cases,
  diagnostics,
}) {
  return {
    replay_report: REPLAY_REPORT_TAG,
    verifier: reportVerifier(),
    mode: 'rule-change',
    corpus: {
      id: corpus.id,
      tag: corpus.manifest.decision_gallery ?? null,
      cases: corpus.manifest.cases.length,
      manifest_hash: corpus.manifestHash,
    },
    against: {
      kind: mode,
      value: against,
      source_hash: null,
    },
    cases,
    summary: summarizeReplay(status, exitCode, cases),
    boundary: {
      attests: [
        'offline-artifact-self-consistency',
        'same-origin-js-check-path',
        'rule-change-replay-byte-comparison',
      ],
      excludes: [
        'external-independent-verification',
        'spec-blind-third-party-reimplementation',
        'receipt-authenticity',
        'generation-honesty',
        'issuer-binding',
        'timestamping',
        'semantic-equivalence',
        'input-provenance',
        'non-repudiation',
        'full-cskernel-coverage',
      ],
    },
    diagnostics: diagnostics.map((diagnostic) =>
      typeof diagnostic === 'string' ? { code: diagnostic } : diagnostic
    ),
  };
}

function replayVersion(corpus, versionValue) {
  const target = normalizedVersion(versionValue);
  const failures = [];
  const cases = [];
  for (const entry of corpus.manifest.cases) {
    const receipt = corpus.receipts.get(entry.stem);
    if (!receipt) {
      failures.push(`${entry.stem}: missing expected receipt`);
      cases.push(caseLayer(entry.stem, null, null));
      continue;
    }
    cases.push(caseLayer(entry.stem, receipt, receipt));
    if (receipt.engine?.version !== target) {
      failures.push(
        `${entry.stem}: engine-version ${receipt.engine?.version} != ${target}`
      );
    }
    if (receipt.comparison?.status !== 'agree') {
      failures.push(`${entry.stem}: comparison is not agree`);
    }
    if (receipt.input?.status !== 'bound') {
      failures.push(`${entry.stem}: input is not bound`);
    }
    if (
      !sameJson(receipt.reference?.transcript, entry.expected_transcript ?? [])
    ) {
      failures.push(
        `${entry.stem}: reference transcript differs from manifest`
      );
    }
  }
  const exitCode = failures.length > 0 ? 1 : 0;
  if (failures.length > 0) {
    process.stderr.write(`replay did not match version ${target}\n`);
    for (const failure of failures) process.stderr.write(`- ${failure}\n`);
  } else {
    process.stderr.write(`replay artifact-consistent against ${target}\n`);
    process.stderr.write(
      `${corpus.manifest.cases.length} decision receipts matched the manifest\n`
    );
  }
  writeJson(
    replayReport({
      corpus,
      against: versionValue,
      mode: 'version',
      status: failures.length > 0 ? 'changed' : 'unchanged',
      exitCode,
      cases,
      diagnostics: failures,
    })
  );
  return exitCode;
}

function replayRuleset(corpus, candidateDir, reportAgainst = candidateDir) {
  const candidate = readReceiptDir(candidateDir, 'lispex replay');
  const preconditionFailures = verifyPrecondition(candidate, 'candidate');
  if (preconditionFailures.length > 0) {
    process.stderr.write('candidate-precondition-failed\n');
    for (const failure of preconditionFailures)
      process.stderr.write(`- ${failure}\n`);
    writeJson(
      replayReport({
        corpus,
        against: reportAgainst,
        mode: 'receipt-directory',
        status: 'failed-precondition',
        exitCode: 1,
        cases: [],
        diagnostics: preconditionFailures,
      })
    );
    return 1;
  }

  const candidateStems = [...candidate.keys()].sort();
  const baselineStems = [...corpus.receipts.keys()].sort();
  const setDiff = compareStemSets(baselineStems, candidateStems);
  const behavioral = [];
  const metadata = [];
  const cases = [];
  for (const stem of setDiff.added) behavioral.push(`${stem}: added`);
  for (const stem of setDiff.removed) behavioral.push(`${stem}: removed`);
  for (const stem of setDiff.added)
    cases.push(caseLayer(stem, null, candidate.get(stem)));
  for (const stem of setDiff.removed)
    cases.push(caseLayer(stem, corpus.receipts.get(stem), null));

  for (const stem of baselineStems.filter((name) => candidate.has(name))) {
    const baseline = corpus.receipts.get(stem);
    const next = candidate.get(stem);
    const diffs = [];
    if (
      transcriptPayload(baseline.reference) !==
      transcriptPayload(next.reference)
    ) {
      diffs.push('reference-transcript');
    }
    if (
      transcriptPayload(baseline.meaning_env) !==
      transcriptPayload(next.meaning_env)
    ) {
      diffs.push('meaning-env-transcript');
    }
    if (baseline.comparison?.status !== next.comparison?.status) {
      diffs.push('comparison-status');
    }
    if (!sameJson(baseline.input?.hash ?? null, next.input?.hash ?? null)) {
      diffs.push('input-hash');
    }
    const record = caseLayer(stem, baseline, next);
    if (diffs.length > 0) {
      behavioral.push(`${stem}: ${diffs.join(', ')}`);
      record.changed = true;
    } else if (!sameJson(baseline, next)) {
      metadata.push(stem);
      record.changed = false;
    }
    cases.push(record);
  }

  if (behavioral.length > 0) {
    process.stderr.write('replay found behavioral differences\n');
    for (const diff of behavioral) process.stderr.write(`- ${diff}\n`);
    writeJson(
      replayReport({
        corpus,
        against: reportAgainst,
        mode: 'receipt-directory',
        status: 'changed',
        exitCode: 1,
        cases,
        diagnostics: behavioral,
      })
    );
    return 1;
  }
  process.stderr.write(
    'replay artifact-consistent; no behavioral differences\n'
  );
  if (metadata.length > 0) {
    process.stderr.write(
      `${metadata.length} receipt(s) changed only in recorded metadata\n`
    );
  }
  writeJson(
    replayReport({
      corpus,
      against: reportAgainst,
      mode: 'receipt-directory',
      status: 'unchanged',
      exitCode: 0,
      cases,
      diagnostics: metadata.map((stem) => `${stem}: metadata-only`),
    })
  );
  return 0;
}

function replayCommand(args) {
  const { corpusPath, against } = parseReplayArgs(args);
  const corpus = readDecisionCorpus(corpusPath);
  const manifestSet = new Set(corpus.stems);
  const receiptSet = new Set(corpus.receipts.keys());
  const setDiff = compareStemSets([...manifestSet], [...receiptSet]);
  if (setDiff.added.length > 0 || setDiff.removed.length > 0) {
    process.stderr.write('baseline-precondition-failed\n');
    for (const stem of setDiff.added)
      process.stderr.write(`- unexpected receipt: ${stem}\n`);
    for (const stem of setDiff.removed)
      process.stderr.write(`- missing receipt: ${stem}\n`);
    writeJson(
      replayReport({
        corpus,
        against,
        mode: semverLike(against) ? 'version' : 'receipt-directory',
        status: 'failed-precondition',
        exitCode: 1,
        cases: [],
        diagnostics: [
          ...setDiff.added.map((stem) => `unexpected receipt: ${stem}`),
          ...setDiff.removed.map((stem) => `missing receipt: ${stem}`),
        ],
      })
    );
    return 1;
  }
  const preconditionFailures = verifyPrecondition(corpus.receipts, 'baseline');
  if (preconditionFailures.length > 0) {
    process.stderr.write('baseline-precondition-failed\n');
    for (const failure of preconditionFailures)
      process.stderr.write(`- ${failure}\n`);
    writeJson(
      replayReport({
        corpus,
        against,
        mode: semverLike(against) ? 'version' : 'receipt-directory',
        status: 'failed-precondition',
        exitCode: 1,
        cases: [],
        diagnostics: preconditionFailures,
      })
    );
    return 1;
  }

  if (semverLike(against)) return replayVersion(corpus, against);
  const abs = path.resolve(process.cwd(), against);
  try {
    if (fs.statSync(abs).isDirectory())
      return replayRuleset(corpus, abs, against);
  } catch {
    // Fall through to usage error below.
  }
  throw new CliError(
    'lispex replay: --against must be a semver or receipt directory',
    2
  );
}

function run() {
  const args = process.argv.slice(2);

  if (args[0] === '--version' || args[0] === '-v') {
    process.stdout.write(version() + '\n');
    return 0;
  }
  if (args[0] === '--help' || args[0] === '-h') {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (args[0] === 'verify') return verifyCommand(args.slice(1));
  if (args[0] === 'verify-bridge') return verifyBridgeCommand(args.slice(1));
  if (args[0] === 'replay') return replayCommand(args.slice(1));

  // Resolve the source: a file argument, or source piped on stdin.
  let file = null;
  if (args[0] === 'run') {
    if (!args[1]) throw new CliError('lispex run: missing <file.lspx>', 2);
    file = args[1];
  } else if (args[0] && !args[0].startsWith('-')) {
    file = args[0];
  } else if (args[0]) {
    throw new CliError(
      'lispex: unknown option ' + args[0] + ' (try --help)',
      2
    );
  }

  let src;
  if (file) {
    const abs = path.resolve(process.cwd(), file);
    try {
      src = fs.readFileSync(abs, 'utf8');
    } catch {
      throw new CliError('lispex: cannot read file: ' + file, 2);
    }
  } else if (!process.stdin.isTTY) {
    src = fs.readFileSync(0, 'utf8'); // stdin
  } else {
    process.stdout.write(HELP + '\n');
    return 0;
  }

  // Load the wasm reference interpreter lazily so --version/--help skip init.
  const { run_lispex } = require('../pkg/lispex_wasm.js');
  const res = run_lispex(src);

  if (res.output) process.stdout.write(res.output);
  if (res.diagnostics) process.stderr.write(res.diagnostics);
  return res.ok ? 0 : 1;
}

// Set `process.exitCode` and let Node drain/close handles itself, rather than
// forcing `process.exit()` — the latter can trip a libuv handle-teardown
// assertion on Windows when stdin was a pipe.
try {
  process.exitCode = run();
} catch (e) {
  if (e instanceof CliError) {
    process.stderr.write(e.message + '\n');
    process.exitCode = e.code;
  } else {
    process.stderr.write(
      'internal error: ' + (e && e.message ? e.message : String(e)) + '\n'
    );
    process.exitCode = 1;
  }
}
