import { parseArtifactJson } from '../artifact/scripts/artifact-json.mjs';

export function assertFixtureResultsBytes(reportBytes, manifestBytes) {
  let report;
  let manifest;
  try {
    report = parseArtifactJson(reportBytes, { canonical: true }).value;
  } catch (error) {
    throw new Error(`fixture results are not canonical artifact JSON: ${error.message}`);
  }
  try {
    manifest = parseArtifactJson(manifestBytes, { canonical: true }).value;
  } catch (error) {
    throw new Error(`fixture manifest is not canonical artifact JSON: ${error.message}`);
  }
  const issues = fixtureResultIssues(report, manifest);
  if (issues.length > 0) throw new Error(issues.join('\n'));
  return {
    built: report.fixture_results.built.expected,
    report,
  };
}

export function fixtureResultIssues(report, manifest) {
  const issues = [];
  exactKeys(report, ['fixture_report', 'fixture_results', 'results'], 'report', issues);
  if (report?.fixture_report !== 'vouch.scored26-fixture/v0') {
    issues.push('report: fixture-report-tag');
  }
  exactKeys(
    report?.fixture_results,
    ['built', 'design_target'],
    'fixture_results',
    issues
  );
  exactKeys(
    report?.fixture_results?.built,
    ['expected', 'matched', 'mismatched', 'skipped'],
    'fixture_results.built',
    issues
  );
  exactKeys(
    report?.fixture_results?.design_target,
    ['implemented', 'listed', 'matched', 'not_implemented'],
    'fixture_results.design_target',
    issues
  );

  const manifestRows = Array.isArray(manifest?.fixtures) ? manifest.fixtures : [];
  if (!Array.isArray(manifest?.fixtures)) issues.push('manifest: fixtures-not-array');
  const rows = Array.isArray(report?.results) ? report.results : [];
  if (!Array.isArray(report?.results)) issues.push('report: results-not-array');
  if (rows.length !== manifestRows.length) {
    issues.push(`report: result-count ${rows.length} != ${manifestRows.length}`);
  }

  const seen = new Set();
  rows.forEach((row, index) => {
    exactKeys(
      row,
      ['fixture_id', 'scope', 'implemented', 'matched', 'operation'],
      `results[${index}]`,
      issues
    );
    if (typeof row?.fixture_id !== 'string') {
      issues.push(`results[${index}]: fixture-id-not-string`);
    } else if (seen.has(row.fixture_id)) {
      issues.push(`results[${index}]: duplicate-fixture-id ${row.fixture_id}`);
    } else {
      seen.add(row.fixture_id);
    }
    if (typeof row?.implemented !== 'boolean' || typeof row?.matched !== 'boolean') {
      issues.push(`results[${index}]: outcome-not-boolean`);
    }
    const expected = manifestRows[index];
    if (!expected) return;
    for (const [name, actual, wanted] of [
      ['fixture_id', row.fixture_id, expected.fixture_id],
      ['scope', row.scope, expected.scope],
      ['operation', row.operation, expected.command_or_api_operation],
    ]) {
      if (actual !== wanted) {
        issues.push(`results[${index}]: ${name} ${actual} != ${wanted}`);
      }
    }
    if (expected.scope === 'built' && row.implemented !== true) {
      issues.push(`results[${index}]: built-row-not-implemented`);
    }
    if (expected.scope === 'built' && row.matched !== true) {
      issues.push(`results[${index}]: built-row-not-matched`);
    }
  });

  const built = rows.filter((row) => row?.scope === 'built');
  const design = rows.filter((row) => row?.scope === 'design-target');
  const derived = {
    built: {
      expected: built.length,
      matched: built.filter((row) => row.matched === true).length,
      mismatched: built.filter((row) => row.matched !== true).length,
      skipped: 0,
    },
    design_target: {
      listed: design.length,
      implemented: design.filter((row) => row.implemented === true).length,
      matched: design.filter((row) => row.matched === true).length,
      not_implemented: design.filter((row) => row.implemented !== true).length,
    },
  };
  compareSummary(report?.fixture_results?.built, derived.built, 'built', issues);
  compareSummary(
    report?.fixture_results?.design_target,
    derived.design_target,
    'design_target',
    issues
  );
  if (derived.built.expected !== manifestRows.filter((row) => row.scope === 'built').length) {
    issues.push('report: built-scope-count-does-not-match-manifest');
  }
  return issues;
}

function exactKeys(value, expected, label, issues) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    issues.push(`${label}: object-required`);
    return;
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    issues.push(`${label}: closed-schema ${actual.join(',')} != ${wanted.join(',')}`);
  }
}

function compareSummary(actual, expected, label, issues) {
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return;
  for (const [name, value] of Object.entries(expected)) {
    if (!Number.isSafeInteger(actual[name]) || actual[name] < 0) {
      issues.push(`fixture_results.${label}.${name}: nonnegative-integer-required`);
    } else if (actual[name] !== value) {
      issues.push(
        `fixture_results.${label}.${name}: ${actual[name]} != derived ${value}`
      );
    }
  }
}

function compareUtf8(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}
