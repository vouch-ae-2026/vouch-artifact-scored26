import { hrtime } from 'node:process';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { writeArtifactJson } from './artifact-json.mjs';
import { releasePerformanceReceiptPopulation } from './release-layer-lib.mjs';
import { parseCanonical } from './release-schema.mjs';

const options = parseArgs(process.argv.slice(2));
const sourceRoot = resolve(options.get('--source-root'));
const releaseRoot = resolve(options.get('--release-root'));
const outputRoot = resolve(options.get('--output-root'));
const executable = resolve(options.get('--executable'));
const keyHandle = options.get('--ephemeral-key-handle');
const timeExecutable = resolve(options.get('--time'));
const performancePath = join(
  outputRoot,
  'artifact/performance/performance-results.json'
);
const scratch = join(outputRoot, '.performance-scratch');
if (process.platform !== 'linux' || process.arch !== 'x64') {
  throw new Error('release performance must run on x86_64 Linux');
}
rmSync(scratch, { recursive: true, force: true });
mkdirSync(scratch, { recursive: true, mode: 0o700 });

try {
  const policy = readFileSync(join(releaseRoot, 'release/trust-policy.json'));
  const execution = parseCanonical(
    readFileSync(join(releaseRoot, 'release/workload-execution.json')),
    'release-workload-execution'
  );
  const split = parseCanonical(
    readFileSync(join(sourceRoot, 'artifact/workload/workload-split.json')),
    'workload-split'
  );
  const splitById = new Map(split.cases.map((row) => [row.case_id, row]));
  const sources = {
    baseline: readFileSync(
      join(sourceRoot, 'artifact/workload/rules/baseline.lspx')
    ),
    changed: readFileSync(
      join(sourceRoot, 'artifact/workload/rules/changed.lspx')
    ),
  };
  const { verifyNativeEvidence } = await import(
    pathToFileURL(join(sourceRoot, 'packages/vouch-consumer/dist/index.js'))
  );
  const population = releasePerformanceReceiptPopulation(execution);
  const receipts = population.coordinates.map(({ caseId, side }) => ({
    caseId,
    side,
    source: sources[side],
    input: writeArtifactJson(splitById.get(caseId).input),
    envelope: readFileSync(
      join(releaseRoot, 'release/receipts', caseId, side, 'envelope.dsse.json')
    ),
  }));
  const excluded = population.excluded;

  // Five complete verification warmups. No warmup duration enters the sample.
  for (let run = 0; run < 5; run += 1) {
    verifyPopulation(receipts, policy, verifyNativeEvidence, null);
  }
  const verificationMicros = [];
  for (let run = 0; run < 30; run += 1) {
    verifyPopulation(
      receipts,
      policy,
      verifyNativeEvidence,
      verificationMicros
    );
  }

  const replayMicros = [];
  const peakResidentBytes = [];
  for (let run = 0; run < 35; run += 1) {
    const root = join(scratch, `run-${String(run).padStart(2, '0')}`);
    const receiptRoot = join(root, 'receipts');
    const executionReport = join(root, 'execution.json');
    const timeReport = join(root, 'time.txt');
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const started = hrtime.bigint();
    const result = spawnSync(
      timeExecutable,
      [
        '-v',
        '-o',
        timeReport,
        executable,
        ...workloadArguments({
          sourceRoot,
          releaseRoot,
          keyHandle,
          receiptRoot,
          executionReport,
        }),
      ],
      {
        cwd: sourceRoot,
        encoding: 'utf8',
        env: cleanEnvironment(),
        maxBuffer: 32 * 1024 * 1024,
        timeout: 15 * 60 * 1000,
      }
    );
    const ended = hrtime.bigint();
    if (result.error || result.status !== 0) {
      throw new Error(
        `performance replay ${run} failed\n${result.stdout}${result.stderr}${result.error?.message ?? ''}`
      );
    }
    const timeText = readFileSync(timeReport, 'utf8');
    const kib = /Maximum resident set size \(kbytes\): (\d+)/.exec(
      timeText
    )?.[1];
    if (!kib) throw new Error(`performance replay ${run}: missing peak RSS`);
    if (run >= 5) {
      replayMicros.push(microseconds(ended - started));
      peakResidentBytes.push(Number(kib) * 1024);
    }
    rmSync(root, { recursive: true, force: true });
  }

  const metrics = [
    metricRows(
      'envelope_bytes',
      'byte',
      receipts.map((entry) => entry.envelope.length),
      excluded
    ),
    metricRows(
      'native_verification_latency',
      'microsecond',
      verificationMicros,
      excluded
    ),
    metricRows('peak_resident_memory', 'byte', peakResidentBytes, []),
    metricRows(
      'selected_corpus_replay_latency',
      'microsecond',
      replayMicros,
      []
    ),
  ].flat();
  const report = {
    measurement_protocol: {
      measured_runs: 30,
      monotonic_clock: 'process.hrtime.bigint',
      percentile_method: 'nearest-rank',
      warmup_runs: 5,
    },
    measurements: metrics,
    performance_report: 'vouch.scored26-performance/v0',
  };
  mkdirSync(dirname(performancePath), { recursive: true });
  writeFileSync(performancePath, writeArtifactJson(report));
  console.log(
    `SCORED26 performance report generated (${receipts.length} envelopes, 5 warmups + 30 measured runs)`
  );
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

function verifyPopulation(receipts, policy, verify, observations) {
  for (const receipt of receipts) {
    const started = observations === null ? 0n : hrtime.bigint();
    const result = verify(receipt.envelope, policy, {
      profile: 'csk.checked-profile/v1',
      source: receipt.source,
      input: receipt.input,
    });
    if (!result.ok) {
      throw new Error(
        `${receipt.caseId}/${receipt.side}: performance verification rejected ${result.error.code}`
      );
    }
    if (observations !== null) {
      observations.push(microseconds(hrtime.bigint() - started));
    }
  }
}

function metricRows(metric, unit, values, excludedIds) {
  if (
    values.length === 0 ||
    values.some((value) => !Number.isSafeInteger(value))
  ) {
    throw new Error(`${metric}: empty or unsafe observation population`);
  }
  const sorted = [...values].sort((left, right) => left - right);
  return [
    ['maximum', sorted.at(-1)],
    ['median', nearestRank(sorted, 50)],
    ['p95', nearestRank(sorted, 95)],
  ].map(([statistic, value]) => ({
    excluded_ids: excludedIds,
    metric,
    population: values.length,
    statistic,
    unit,
    value,
  }));
}

function nearestRank(sorted, percentile) {
  const rank = Math.ceil((percentile / 100) * sorted.length);
  return sorted[Math.max(0, rank - 1)];
}

function microseconds(nanoseconds) {
  const value = Number((nanoseconds + 999n) / 1000n);
  if (!Number.isSafeInteger(value)) throw new Error('timing exceeds safe uint');
  return value;
}

function workloadArguments({
  sourceRoot: source,
  releaseRoot: release,
  keyHandle: key,
  receiptRoot,
  executionReport,
}) {
  return [
    '--envelope',
    join(release, 'release/replay-manifest.dsse.json'),
    '--trust-policy',
    join(release, 'release/trust-policy.json'),
    '--baseline-rule',
    join(source, 'artifact/workload/rules/baseline.lspx'),
    '--changed-rule',
    join(source, 'artifact/workload/rules/changed.lspx'),
    '--workload-space',
    join(source, 'artifact/workload/workload-space.json'),
    '--workload-selection',
    join(source, 'artifact/workload/workload-selection.json'),
    '--workload-split',
    join(source, 'artifact/workload/workload-split.json'),
    '--holdout-plan',
    join(source, 'artifact/workload/holdout-plan.json'),
    '--corpus',
    join(release, 'release/replay-corpus.json'),
    '--key-handle',
    key,
    '--receipt-root',
    receiptRoot,
    '--execution-report',
    executionReport,
  ];
}

function cleanEnvironment() {
  const env = {
    ...process.env,
    CARGO_TERM_COLOR: 'never',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    SOURCE_DATE_EPOCH: '0',
  };
  for (const name of [
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'SCORED_MUTANT',
    'LISPEX_BUILD_COMMIT_HEX',
    'LISPEX_BUILD_COMMIT_DIRTY',
    'GITHUB_SHA',
  ]) {
    delete env[name];
  }
  return env;
}

function parseArgs(raw) {
  const required = new Set([
    '--source-root',
    '--release-root',
    '--output-root',
    '--executable',
    '--ephemeral-key-handle',
    '--time',
  ]);
  if (raw.length % 2 !== 0) throw new Error('every option requires a value');
  const values = new Map();
  for (let index = 0; index < raw.length; index += 2) {
    if (
      !required.has(raw[index]) ||
      values.has(raw[index]) ||
      !raw[index + 1]
    ) {
      throw new Error(`invalid option ${raw[index]}`);
    }
    values.set(raw[index], raw[index + 1]);
  }
  for (const name of required) {
    if (!values.has(name)) throw new Error(`${name} is required`);
  }
  return values;
}
