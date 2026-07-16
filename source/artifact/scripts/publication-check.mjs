#!/usr/bin/env node

import { existsSync } from 'node:fs';

import { ArtifactJsonError } from './artifact-json.mjs';
import { capturePaperSourceSnapshot } from './paper-source-snapshot.mjs';
import { renderPublicationPaper } from './paper-release.mjs';
import {
  publicationCheck,
  publishPublicationFailure,
} from './release-publication-lib.mjs';
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
  '--observation': ['observation', 'observation'],
  '--observation-envelope': ['observationEnvelope', 'observation-envelope'],
  '--publication-record': ['publicationRecord', 'publication-record'],
  '--fixture-report': ['fixtureReport', 'fixture-report'],
  '--workload-report': ['workloadReport', 'workload-report'],
  '--mutation-report': ['mutationReport', 'mutation-report'],
  '--performance-report': ['performanceReport', 'performance-report'],
  '--reproduction-comparisons': ['comparisons', 'reproduction-comparisons'],
});
const REQUIRED = Object.freeze([
  ...Object.keys(OPTION_TO_MEMBER),
  '--paper-source-root',
  '--out-dir',
]);

const parsed = parseReleaseArguments(process.argv.slice(2), REQUIRED);
if (!parsed.ok) {
  const publisher = new AtomicDirectoryPublisher();
  if (parsed.reportOutDir === null || existsSync(parsed.reportOutDir)) {
    console.error(`usage-error: ${parsed.error}`);
    process.exitCode = 2;
  } else {
    const outcome = publishPublicationFailure({
      publisher,
      output: parsed.reportOutDir,
      buffers: {},
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
  const failures = [];
  for (const [option, [member, inputArtifact]] of Object.entries(
    OPTION_TO_MEMBER
  )) {
    try {
      buffers[member] = files.read(parsed.values[option], inputArtifact);
    } catch (error) {
      failures.push({ member, inputArtifact, error });
    }
  }
  const paperSnapshot = capturePaperSourceSnapshot(
    parsed.values['--paper-source-root']
  );
  let outcome;
  const invalid = failures.find(
    (failure) =>
      failure.error instanceof ArtifactJsonError &&
      !['descriptor', 'descriptorEnvelope', 'trustPolicy'].includes(
        failure.member
      )
  );
  const descriptorInvalid = failures.find(
    (failure) =>
      failure.error instanceof ArtifactJsonError &&
      ['descriptor', 'descriptorEnvelope', 'trustPolicy'].includes(
        failure.member
      )
  );
  const inputOutput = failures.find(
    (failure) => !(failure.error instanceof ArtifactJsonError)
  );
  if (invalid !== undefined) {
    outcome = publishPublicationFailure({
      publisher,
      output: parsed.values['--out-dir'],
      buffers,
      exitCode: 1,
      primaryError: 'publication-input-invalid',
      inputArtifact: invalid.inputArtifact,
      underlyingError: invalid.error.code,
    });
  } else if (inputOutput !== undefined) {
    outcome = publishPublicationFailure({
      publisher,
      output: parsed.values['--out-dir'],
      buffers,
      exitCode: 3,
      primaryError: 'input-output-failure',
      inputArtifact: inputOutput.inputArtifact,
    });
  } else if (descriptorInvalid !== undefined) {
    outcome = publishPublicationFailure({
      publisher,
      output: parsed.values['--out-dir'],
      buffers,
      exitCode: 1,
      primaryError: 'chain-verification-failed',
      failedCheck: 'p3-descriptor-authentication',
      chainVerified: 'fail',
    });
  } else {
    outcome = publicationCheck({
      buffers,
      paperSnapshot,
      renderer: renderPublicationPaper,
      publisher,
      output: parsed.values['--out-dir'],
    });
  }
  if (outcome.exitCode === 0) {
    console.log('SCORED26 publication check passed (S=pass)');
  } else {
    console.error(outcome.report.primary_error ?? 'publication-check-failed');
  }
  process.exitCode = outcome.exitCode;
}
