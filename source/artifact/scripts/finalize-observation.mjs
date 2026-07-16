#!/usr/bin/env node

import { existsSync } from 'node:fs';

import { ArtifactJsonError } from './artifact-json.mjs';
import {
  Pkcs8FileKeyProvider,
  finalizeObservation,
  keyHandleSyntaxValid,
  publishFinalizerRefusal,
} from './release-finalizer-lib.mjs';
import {
  AtomicDirectoryPublisher,
  ReadOnceFileProvider,
} from './release-io.mjs';
import { parseReleaseArguments } from './release-cli.mjs';

const OPTION_TO_MEMBER = Object.freeze({
  '--descriptor': ['descriptor', 'descriptor'],
  '--descriptor-envelope': ['descriptorEnvelope', 'descriptor-envelope'],
  '--trust-policy': ['trustPolicy', 'trust-policy'],
  '--clean-run-report': ['cleanRunReport', 'clean-run-report'],
  '--fixture-report': ['fixtureReport', 'fixture-report'],
  '--workload-report': ['workloadReport', 'workload-report'],
  '--mutation-report': ['mutationReport', 'mutation-report'],
  '--performance-report': ['performanceReport', 'performance-report'],
  '--reproduction-comparisons': ['comparisons', 'reproduction-comparisons'],
});
const REQUIRED = Object.freeze([
  ...Object.keys(OPTION_TO_MEMBER),
  '--key-handle',
  '--out-dir',
]);

let parsed = parseReleaseArguments(process.argv.slice(2), REQUIRED);
if (parsed.ok && !keyHandleSyntaxValid(parsed.values['--key-handle'])) {
  parsed = Object.freeze({
    ...parsed,
    ok: false,
    error: 'malformed --key-handle',
    reportOutDir: parsed.values['--out-dir'],
  });
}
if (!parsed.ok) {
  const publisher = new AtomicDirectoryPublisher();
  if (parsed.reportOutDir === null || existsSync(parsed.reportOutDir)) {
    console.error(`usage-error: ${parsed.error}`);
    process.exitCode = 2;
  } else {
    const outcome = publishFinalizerRefusal({
      publisher,
      output: parsed.reportOutDir,
      exitCode: 2,
      primaryError: 'usage-error',
    });
    if (outcome.stderrOnly) console.error('usage-error');
    process.exitCode = outcome.exitCode;
  }
} else if (existsSync(parsed.values['--out-dir'])) {
  console.error('usage-error: --out-dir already exists');
  process.exitCode = 2;
} else {
  const publisher = new AtomicDirectoryPublisher();
  const files = new ReadOnceFileProvider();
  const buffers = {};
  const entryFailures = [];
  for (const [option, [member, inputArtifact]] of Object.entries(
    OPTION_TO_MEMBER
  )) {
    try {
      buffers[member] = files.read(parsed.values[option], inputArtifact);
    } catch (error) {
      entryFailures.push({
        error,
        inputArtifact,
        authentication:
          member === 'descriptor' ||
          member === 'descriptorEnvelope' ||
          member === 'trustPolicy',
      });
    }
  }
  let outcome;
  const entryFailure = entryFailures[0] ?? null;
  if (entryFailure !== null) {
    if (entryFailure.error instanceof ArtifactJsonError) {
      outcome = publishFinalizerRefusal({
        publisher,
        output: parsed.values['--out-dir'],
        exitCode: 1,
        primaryError: entryFailure.authentication
          ? 'descriptor-authentication-failed'
          : 'finalizer-input-invalid',
        inputArtifact: entryFailure.authentication
          ? null
          : entryFailure.inputArtifact,
        underlyingError: entryFailure.authentication
          ? null
          : entryFailure.error.code,
      });
    } else {
      outcome = publishFinalizerRefusal({
        publisher,
        output: parsed.values['--out-dir'],
        exitCode: 3,
        primaryError: 'input-output-failure',
      });
    }
  } else {
    outcome = finalizeObservation({
      buffers,
      keyHandle: parsed.values['--key-handle'],
      keyProvider: new Pkcs8FileKeyProvider(),
      publisher,
      output: parsed.values['--out-dir'],
    });
  }
  if (outcome.stderrOnly || outcome.exitCode !== 0) {
    console.error(outcome.report.primary_error ?? 'finalization-failed');
  } else {
    console.log('SCORED26 reproduction observation finalized');
  }
  process.exitCode = outcome.exitCode;
}
