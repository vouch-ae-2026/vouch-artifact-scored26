import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';

import { sha256Id } from './release-schema.mjs';

const PAPER_PATH = 'artifact/paper/vouch-scored26-release.tex';

export function renderPublicationPaper(context) {
  const temporaryRoot = mkdtempSync(join(tmpdir(), 'scored26-publication-'));
  try {
    materializeSnapshot(context.paperSnapshot, temporaryRoot);
    const identityBytes = Buffer.from(buildIdentityTex(context), 'utf8');
    const resultsBytes = Buffer.from(buildResultsTex(context), 'utf8');
    writeDerived(
      temporaryRoot,
      'generated/artifact-identity.tex',
      identityBytes
    );
    writeDerived(temporaryRoot, 'generated/release-results.tex', resultsBytes);

    const paperRoot = join(temporaryRoot, dirname(PAPER_PATH));
    const buildRoot = join(temporaryRoot, 'publication-build');
    mkdirSync(buildRoot);
    command(
      'latexmk',
      [
        '-pdf',
        '-interaction=nonstopmode',
        '-halt-on-error',
        '-file-line-error',
        `-outdir=${buildRoot}`,
        join(temporaryRoot, PAPER_PATH),
      ],
      {
        cwd: paperRoot,
        env: {
          ...process.env,
          SOURCE_DATE_EPOCH: String(
            context.descriptor.build_parameters.source_date_epoch
          ),
          TZ: 'UTC',
          LC_ALL: context.descriptor.build_parameters.locale,
          LANG: context.descriptor.build_parameters.locale,
        },
      }
    );
    const pdfPath = join(buildRoot, 'vouch-scored26-release.pdf');
    const pdfBytes = readFileSync(pdfPath);
    const extractedText = command('pdftotext', ['-layout', pdfPath, '-'], {
      cwd: buildRoot,
    }).stdout;
    return Object.freeze({
      pdfBytes,
      extractedText,
      claimsMatched: claimsMatch(context, extractedText),
      claimLanguageScan: claimLanguageScan(extractedText),
      identityTexSha256: sha256Id(identityBytes),
      resultsTexSha256: sha256Id(resultsBytes),
    });
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function materializeSnapshot(snapshot, root) {
  if (!(snapshot?.files instanceof Map) || !(snapshot?.modes instanceof Map)) {
    throw new Error('paper snapshot has no captured files');
  }
  for (const [path, bytes] of snapshot.files) {
    safeRelativePath(path);
    const destination = join(root, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, bytes, { flag: 'wx' });
    if (snapshot.modes.get(path) === '100755') chmodSync(destination, 0o755);
  }
}

function writeDerived(root, path, bytes) {
  safeRelativePath(path);
  const destination = join(root, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, bytes);
}

function buildIdentityTex({ descriptor, observation, publicationRecord }) {
  return [
    '% Generated only after the authenticated D/Q/R/P chain is available.',
    texCommand('ArtifactFreezeCommit', descriptor.artifact_freeze_commit),
    texCommand('ArtifactSourceCommit', descriptor.artifact_commit),
    texCommand('ArtifactReleaseKeyId', descriptor.key_id),
    texCommand(
      'ArtifactReleaseDescriptorDigest',
      publicationRecord.release_descriptor_sha256
    ),
    texCommand('ArtifactArchiveDigest', descriptor.archive_sha256),
    texCommand('ArtifactEngineDigest', descriptor.engine_sha256),
    texCommand('ArtifactTargetTriple', descriptor.target_triple),
    texCommand(
      'ArtifactObservationDigest',
      publicationRecord.reproduction_observation_sha256
    ),
    texCommand(
      'ArtifactCleanRunSeconds',
      String(observation.clean_run_runtime_seconds)
    ),
    '',
  ].join('\n');
}

function buildResultsTex({
  cleanRunReport,
  observation,
  fixtureReport,
  workloadReport,
  mutationReport,
  performanceReport,
  comparisons,
}) {
  const fixture = fixtureReport.fixture_results;
  const workload = workloadReport.workload_summary;
  const mutation = mutationReport.mutation_summary;
  const lines = [
    '% Derived from digest-verified owner-report entry buffers.',
    texCommand('ArtifactFixtureBuiltExpected', String(fixture.built.expected)),
    texCommand('ArtifactFixtureBuiltMatched', String(fixture.built.matched)),
    texCommand(
      'ArtifactFixtureBuiltMismatched',
      String(fixture.built.mismatched)
    ),
    texCommand('ArtifactFixtureBuiltSkipped', String(fixture.built.skipped)),
    texCommand(
      'ArtifactFixtureDesignTargets',
      String(fixture.design_target.listed)
    ),
    texCommand('ArtifactWorkloadCandidates', String(workload.candidates)),
    texCommand(
      'ArtifactWorkloadSelected',
      String(workload.selected_case_count)
    ),
    texCommand(
      'ArtifactWorkloadDecisionPairs',
      String(workload.decision_pair_count)
    ),
    texCommand(
      'ArtifactWorkloadDecisionFlips',
      String(workload.decision_flips)
    ),
    texCommand('ArtifactWorkloadHeldOutFlips', String(workload.held_out_flips)),
    texCommand('ArtifactMutationSeeded', String(mutation.mutant_level.seeded)),
    texCommand('ArtifactMutationBuilt', String(mutation.mutant_level.built)),
    texCommand(
      'ArtifactMutationActivated',
      String(mutation.mutant_level.activated_any)
    ),
    texCommand(
      'ArtifactMutationDetected',
      String(mutation.mutant_level.detected_any)
    ),
    texCommand('ArtifactMutationRate', mutation.mutant_level.detection_rate),
    texCommand(
      'ArtifactComparisonCount',
      String(comparisons.comparisons.length)
    ),
    texCommand(
      'ArtifactCleanRuntime',
      String(cleanRunReport.clean_run_runtime_seconds)
    ),
    texCommand(
      'ArtifactObservationalFileCount',
      String(observation.verify_only_observational_results.length)
    ),
    '\\newcommand{\\ArtifactPerformanceRows}{%',
  ];
  for (const row of performanceReport.measurements) {
    lines.push(
      `  \\texttt{${texEscape(row.metric)}} & ${texEscape(row.statistic)} & ${row.value} & \\texttt{${texEscape(row.unit)}} & ${row.population} \\\\%`
    );
  }
  lines.push('}', '');
  return lines.join('\n');
}

function claimsMatch(context, extractedText) {
  const compact = extractedText.replace(/\s+/g, '');
  const required = [
    context.descriptor.artifact_commit,
    context.descriptor.artifact_freeze_commit,
    context.descriptor.key_id,
    context.publicationRecord.release_descriptor_sha256,
    context.descriptor.archive_sha256,
    context.descriptor.engine_sha256,
    context.publicationRecord.reproduction_observation_sha256,
    String(context.cleanRunReport.clean_run_runtime_seconds),
    String(context.fixtureReport.fixture_results.built.expected),
    String(context.fixtureReport.fixture_results.built.matched),
    String(context.workloadReport.workload_summary.selected_case_count),
    String(context.mutationReport.mutation_summary.mutant_level.seeded),
    ...context.performanceReport.measurements.map((row) => String(row.value)),
  ];
  return required.every((value) => compact.includes(value.replace(/\s+/g, '')));
}

function claimLanguageScan(extractedText) {
  const text = extractedText.toLowerCase().replace(/\s+/g, ' ');
  const forbidden = [
    /proves? semantic equivalence/,
    /guarantees? freshness/,
    /capabilities constrain dishonest/,
    /complete for all possible inputs/,
    /zero promotions? proves?/,
    /structural consistency authenticates/,
    /schema acceptance proves? native origin/,
  ];
  return forbidden.some((pattern) => pattern.test(text)) ? 'fail' : 'pass';
}

function texCommand(name, value) {
  return `\\newcommand{\\${name}}{\\detokenize{${value}}}`;
}

function texEscape(value) {
  return String(value)
    .replaceAll('\\', '\\textbackslash{}')
    .replaceAll('_', '\\_')
    .replaceAll('%', '\\%')
    .replaceAll('&', '\\&')
    .replaceAll('#', '\\#');
}

function safeRelativePath(path) {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.startsWith('/') ||
    path.includes('\\') ||
    path.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`unsafe snapshot path ${path}`);
  }
}

function command(program, args, { cwd, env = process.env }) {
  const result = spawnSync(program, args, {
    cwd,
    env,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${program} exited ${result.status}: ${result.stderr ?? ''}${result.stdout ?? ''}${result.error?.message ?? ''}`
    );
  }
  return result;
}
