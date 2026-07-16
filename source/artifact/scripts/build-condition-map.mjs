import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactDir = path.resolve(scriptDir, '..');
const contractPath = path.join(
  artifactDir,
  'contract',
  'NATIVE-IMPLEMENTATION-CONDITIONS-v8.6.0.md'
);
const outputPath = path.join(artifactDir, 'contract', 'condition-map.json');
const expectedHash = (
  await readFile(path.join(artifactDir, 'contract', 'SHA256'), 'utf8')
).trim();
const contractBytes = await readFile(contractPath);
const actualHash = createHash('sha256').update(contractBytes).digest('hex');

if (actualHash !== expectedHash) {
  throw new Error(
    `contract SHA-256 mismatch: expected ${expectedHash}, got ${actualHash}`
  );
}

const conditionPattern = /^### ((?:A|P)-\d+|C-[A-Z]+-\d+)\b/gm;
const conditionIds = [
  ...contractBytes.toString('utf8').matchAll(conditionPattern),
].map((match) => match[1]);

if (new Set(conditionIds).size !== conditionIds.length) {
  throw new Error('duplicate condition identifier in frozen contract');
}

const designTargets = new Set([]);

const linuxPrefixes = ['C-ID-', 'C-PERF-', 'C-REP-', 'C-FINAL-'];

const builtConditions = new Set([
  'A-1',
  'A-2',
  'C-JSON-01',
  'C-JSON-02',
  'C-JSON-03',
  'C-JSON-04',
  'C-JSON-05',
  'C-JSON-06',
  'C-JSON-07',
  'C-JSON-08',
  'C-JSON-09',
  'C-DSSE-01',
  'C-DSSE-02',
  'C-DSSE-03',
  'C-DSSE-04',
  'C-DSSE-05',
  'C-LIM-02',
  'C-LIM-03',
  'C-LIM-04',
  'C-LIM-05',
  'C-LIM-01',
  'C-LIM-06',
  'C-LIM-08',
  'C-LIM-09',
  'C-LIM-10',
  'C-LIM-11',
  'C-LIM-12',
  'C-LIM-13',
  'A-4',
  'P-1',
  'P-2',
  'P-3',
  'P-4',
  'P-5',
  'P-6',
  'P-7',
  'P-8',
  'P-9',
  'P-10',
  'P-11',
  'A-19',
  'A-5',
  'C-LIM-07',
  'A-3',
  'A-6',
  'A-7',
  'A-11',
  'A-14',
  'A-15',
  'C-VS-01',
  'C-VS-02',
  'C-VS-03',
  'C-VS-04',
  'C-VS-05',
  'C-DSSE-06',
  'C-DSSE-07',
  'C-DSSE-08',
  'C-DSSE-09',
  'C-POLICY-01',
  'C-POLICY-02',
  'C-POLICY-03',
  'C-POLICY-04',
  'C-POLICY-05',
  'C-POLICY-06',
  'C-VN-01',
  'C-VN-02',
  'C-VN-03',
  'C-VN-04',
  'C-VN-05',
  'C-VN-06',
  'C-VN-07',
  'C-VN-08',
  'C-VN-09',
  'C-VN-10',
  'C-VN-11',
  'C-VN-12',
  'A-12',
  'C-CAP-01',
  'C-CAP-02',
  'C-CAP-13',
  'C-CAP-03',
  'C-CAP-04',
  'C-CAP-05',
  'C-CAP-06',
  'C-CAP-07',
  'C-CAP-08',
  'C-CAP-09',
  'C-CAP-10',
  'C-CAP-11',
  'C-CAP-12',
  'C-CAP-14',
  'A-16',
  'A-17',
  'C-BR-05',
  'C-BR-01',
  'C-BR-02',
  'C-BR-03',
  'C-BR-04',
  'C-BR-06',
  'C-BR-07',
  'C-BR-08',
  'C-BR-09',
  'C-BR-10',
  'C-BR-11',
  'C-BR-12',
  'C-FIX-01',
  'C-FIX-02',
  'C-FIX-03',
  'C-FIX-04',
  'C-FIX-05',
  'C-FIX-06',
  'C-FIX-08',
  'C-KEY-02',
  'C-KEY-01',
  'C-KEY-03',
  'C-KEY-05',
  'C-KEY-06',
  'C-KEY-07',
  'C-KEY-08',
  'A-9',
  'A-18',
  'C-ISSUE-01',
  'C-ISSUE-02',
  'C-ISSUE-03',
  'C-ISSUE-04',
  'C-ISSUE-05',
  'C-ISSUE-06',
  'C-ISSUE-07',
  'C-ISSUE-08',
  'C-ISSUE-09',
  'C-ISSUE-10',
  'C-ISSUE-11',
  'C-ISSUE-12',
  'C-ISSUE-13',
  'C-ISSUE-14',
  'C-RM-01',
  'C-RM-02',
  'C-RM-03',
  'C-RM-04',
  'C-RM-05',
  'C-UNION-01',
  'C-UNION-02',
  'C-UNION-03',
  'C-WL-01',
  'C-WL-02',
  'C-WL-03',
  'C-WL-04',
  'C-WL-05',
  'C-WL-06',
  'C-WL-07',
  'C-WL-08',
  'C-WL-09',
  'C-WL-10',
  'C-WL-11',
  'C-WL-12',
  'C-WL-13',
  'C-WL-14',
  'C-WL-15',
  'C-WL-16',
  'C-WL-17',
  'C-WL-18',
  'C-WL-19',
  'C-WL-20',
  'C-WL-21',
  'C-WL-22',
  'C-WL-23',
  'C-WL-24',
  'A-8',
  'A-13',
  'C-MUT-01',
  'C-MUT-02',
  'C-MUT-03',
  'C-MUT-04',
  'C-MUT-05',
  'C-MUT-06',
  'C-MUT-07',
  'C-MUT-08',
  'C-MUT-09',
  'C-MUT-10',
  'C-DATA-01',
  'C-DATA-03',
  'C-KEY-04',
  'C-ID-01',
  'C-ID-02',
  'C-ID-03',
  'C-ID-04',
  'C-ID-05',
  'C-ID-06',
  'C-ID-07',
  'C-ID-08',
  'C-ID-09',
  'C-ID-10',
  'C-REP-01',
  'C-REP-02',
  'C-REP-03',
  'C-REP-04',
  'C-REP-05',
  'C-REP-06',
  'C-REP-07',
  'C-REP-08',
  'C-REP-09',
  'C-REP-10',
  'C-FIX-07',
  'C-PERF-01',
  'C-PERF-02',
  'C-PERF-03',
  'C-PERF-04',
  'C-PERF-05',
  'C-PERF-06',
  'C-DATA-02',
  'C-FINAL-01',
  'C-FINAL-02',
  'C-FINAL-03',
]);

const fixturesByCondition = new Map([
  ['A-1', ['S4-EVALUATORS-01']],
  ['A-2', ['S25-METER-01', 'S4-EVALUATORS-01']],
  ['C-JSON-07', ['S1-CROSS-WRITER-01']],
  ['A-4', ['S2-VALUE-01']],
  ['P-1', ['S2-INPUT-01']],
  ['P-2', ['S2-INPUT-01']],
  ['P-3', ['S2-INPUT-01']],
  ['P-4', ['S8-APPLICATION-SCHEMA-01', 'S10-CONDITION-LEDGER-01']],
  ['P-5', ['S2-PROFILE-01']],
  ['P-6', ['S2-PROFILE-01']],
  ['P-7', ['S2-PROFILE-01']],
  ['P-8', ['S2-PROFILE-01']],
  ['P-9', ['S4-EVALUATORS-01']],
  ['P-10', ['S2-PROFILE-01', 'S4-EVALUATORS-01']],
  ['P-11', ['S8-APPLICATION-SCHEMA-01', 'S10-CONDITION-LEDGER-01']],
  ['C-JSON-01', ['S1-CROSS-WRITER-01']],
  ['C-JSON-02', ['J05', 'S1-CROSS-WRITER-01']],
  ['C-JSON-03', ['J03', 'J07', 'J08', 'S1-CROSS-WRITER-01']],
  ['C-JSON-04', ['J01', 'J02', 'J04', 'S1-CROSS-WRITER-01']],
  ['C-JSON-05', ['J06', 'S1-CROSS-WRITER-01']],
  ['C-JSON-06', ['S1-CROSS-WRITER-01']],
  ['C-JSON-08', ['J01', 'J02', 'J03', 'J04', 'J05', 'J06', 'J07', 'J08']],
  ['C-DSSE-01', ['N01', 'N07']],
  ['C-DSSE-02', ['N01', 'P03']],
  ['C-DSSE-03', ['N01', 'S5-NATIVE-VERIFY-01']],
  ['C-DSSE-04', ['N01', 'N03']],
  ['C-DSSE-05', ['N01', 'N03']],
  ['C-LIM-02', ['P04', 'P05']],
  ['C-LIM-03', ['P06']],
  ['C-LIM-04', ['S2-RESOURCE-01']],
  ['C-LIM-05', ['P08']],
  ['C-LIM-10', ['P07']],
  ['C-LIM-11', ['P09']],
  ['A-19', ['S2-TRANSCRIPT-01']],
  ['A-5', ['S2-GRAPH-01', 'S2-DETERMINISM-01']],
  ['C-LIM-07', ['S2-RESOURCE-01']],
  ['A-3', ['S3-STRUCTURE-01']],
  ['A-6', ['S3-STRUCTURE-01']],
  ['A-7', ['S3-STRUCTURE-01']],
  ['A-11', ['S3-STRUCTURE-01', 'S3-CLI-01']],
  ['A-14', ['S3-STRUCTURE-01']],
  ['A-15', ['S3-STRUCTURE-01']],
  ['C-VS-01', ['S3-CLI-01']],
  ['C-VS-02', ['S3-STRUCTURE-01']],
  ['C-VS-03', ['S3-CLI-01']],
  ['C-VS-04', ['S3-CLI-01']],
  ['C-VS-05', ['S3-STRUCTURE-01', 'S3-CLI-01']],
  ['C-DSSE-06', ['N01', 'N03']],
  ['C-DSSE-07', ['R01', 'S8-REPLAY-01']],
  ['C-DSSE-08', ['S10-RELEASE-SCHEMA-01']],
  ['C-DSSE-09', ['L01', 'L02', 'S10-PUBLICATION-01']],
  ['C-JSON-09', ['S10-RELEASE-SCHEMA-01']],
  ['C-POLICY-01', ['S5-NATIVE-VERIFY-01']],
  ['C-POLICY-02', ['S5-NATIVE-VERIFY-01']],
  ['C-POLICY-03', ['S5-NATIVE-VERIFY-01']],
  ['C-POLICY-04', ['P02']],
  ['C-POLICY-05', ['N10']],
  ['C-POLICY-06', ['N20']],
  ['C-VN-01', ['S5-CLI-01']],
  ['C-VN-02', ['N01', 'N14', 'N16', 'S5-CLI-01']],
  ['C-VN-03', ['N01', 'N03', 'N14']],
  ['C-VN-04', ['N19']],
  ['C-VN-05', ['T02']],
  ['C-VN-06', ['S5-NATIVE-VERIFY-01']],
  ['C-VN-07', ['N02']],
  ['C-VN-08', ['B02']],
  ['C-VN-09', ['N03', 'J09']],
  ['C-VN-10', ['N10']],
  ['C-VN-11', ['C-VN-11']],
  ['C-VN-12', ['C-VN-12']],
  ['A-12', ['N01', 'N14', 'N15', 'N16', 'S5-NATIVE-VERIFY-01']],
  ['C-CAP-01', ['S5-CAPABILITY-01']],
  ['C-CAP-02', ['S7-BRIDGE-API-01']],
  ['C-CAP-13', ['S5-CAPABILITY-01']],
  ['C-CAP-03', ['U06', 'U07', 'U08', 'U09', 'U10', 'U13']],
  ['C-CAP-04', ['T02']],
  ['C-CAP-05', ['U05', 'U11']],
  ['C-CAP-06', ['U04', 'T01']],
  ['C-CAP-07', ['U03', 'S5-VULNERABLE-01']],
  ['C-CAP-08', ['U05']],
  ['C-CAP-09', ['U06']],
  ['C-CAP-10', ['S5-CAPABILITY-01']],
  ['C-CAP-11', ['C-CAP-11']],
  ['C-CAP-12', ['C-CAP-12']],
  ['C-CAP-14', ['S5-CAPABILITY-01']],
  ['A-16', ['N01', 'N14', 'N15', 'N16', 'N17', 'N18', 'N19']],
  ['A-17', ['U05', 'U06', 'U11', 'U12', 'T01']],
  ['C-BR-05', ['B04']],
  ['C-BR-01', ['B01', 'B07', 'S7-BRIDGE-API-01']],
  ['C-BR-02', ['B01', 'S7-BRIDGE-CLI-01']],
  ['C-BR-03', ['S7-BRIDGE-API-01']],
  ['C-BR-04', ['B06', 'B07', 'B08', 'B09', 'B10', 'B11', 'B12']],
  ['C-BR-06', ['B01', 'S7-BRIDGE-API-01']],
  ['C-BR-07', ['B04', 'B05', 'B06', 'B07', 'B08', 'B09', 'B10', 'B11', 'B12']],
  ['C-BR-08', ['U04', 'U06']],
  ['C-BR-09', ['B01', 'S7-BRIDGE-CLI-01']],
  ['C-BR-10', ['B01', 'S7-BRIDGE-CLI-01']],
  ['C-BR-11', ['S7-BRIDGE-CLI-01']],
  [
    'C-BR-12',
    [
      'B01',
      'B02',
      'B03',
      'B04',
      'B05',
      'B06',
      'B07',
      'B08',
      'B09',
      'B10',
      'B11',
      'B12',
      'S5-BRIDGE-BYTE-01',
      'S7-BRIDGE-API-01',
      'S7-BRIDGE-CLI-01',
    ],
  ],
  ['C-FIX-01', ['S7-FIXTURE-GATE-01']],
  ['C-FIX-02', ['S7-FIXTURE-GATE-01']],
  ['C-FIX-03', ['S6-KEY-AUDIT-01']],
  ['C-FIX-04', ['S5-NATIVE-VERIFY-01', 'S6-KEY-AUDIT-01']],
  ['C-FIX-05', ['S5-CAPABILITY-01']],
  ['C-FIX-06', ['T01', 'T02', 'C-CAP-12']],
  ['C-FIX-08', ['S7-FIXTURE-GATE-01']],
  ['C-LIM-01', ['P04', 'P05', 'P06', 'P07', 'P08', 'P09']],
  ['C-LIM-06', ['P09', 'S2-GRAPH-01']],
  ['C-LIM-08', ['S2-RESOURCE-01']],
  ['C-LIM-09', ['P04', 'P05', 'P06', 'P07', 'P08', 'P09']],
  ['C-LIM-12', ['S2-RESOURCE-01', 'S3-STRUCTURE-01']],
  ['C-LIM-13', ['P04', 'P05', 'P06', 'P07', 'P08', 'P09', 'S2-RESOURCE-01']],
  ['C-KEY-01', ['S10-SUPPLY-01']],
  ['C-KEY-02', ['S6-PKCS8-01']],
  ['C-KEY-03', ['S6-CLI-01']],
  ['C-KEY-06', ['S5-NATIVE-VERIFY-01', 'S6-ISSUE-01']],
  ['C-KEY-07', ['S6-KEY-AUDIT-01']],
  ['C-KEY-08', ['S6-KEY-AUDIT-01']],
  ['C-KEY-05', ['S10-SUPPLY-01']],
  ['A-9', ['S4-MUTATION-CFG-01', 'S6-ISSUE-01']],
  ['A-18', ['S4-MUTATION-CFG-01']],
  ['C-ISSUE-01', ['S6-CLI-01']],
  ['C-ISSUE-02', ['S6-CLI-01']],
  ['C-ISSUE-03', ['S6-ISSUE-01']],
  ['C-ISSUE-04', ['S6-ISSUE-01']],
  ['C-ISSUE-05', ['S4-TOKENS-01', 'S6-ISSUE-01']],
  ['C-ISSUE-06', ['S6-ISSUE-01']],
  ['C-ISSUE-07', ['C-ISSUE-13', 'S6-ISSUE-01']],
  ['C-ISSUE-08', ['S6-KEY-AUDIT-01']],
  ['C-ISSUE-09', ['C-ISSUE-09', 'S6-ATOMIC-PUBLISH-01']],
  ['C-ISSUE-10', ['S6-CLI-01', 'S6-ATOMIC-PUBLISH-01']],
  ['C-ISSUE-11', ['S6-CLI-01', 'S6-ISSUE-01']],
  ['C-ISSUE-12', ['S6-KEY-AUDIT-01']],
  ['C-ISSUE-13', ['C-ISSUE-13', 'S6-KEY-AUDIT-01']],
  ['C-ISSUE-14', ['S6-CLI-01', 'S6-KEY-AUDIT-01']],
  ['C-RM-01', ['R01', 'S8-REPLAY-01']],
  ['C-RM-02', ['R01', 'R02', 'R03', 'S8-REPLAY-01']],
  ['C-RM-03', ['R01', 'S8-REPLAY-01']],
  ['C-RM-04', ['R01', 'R04', 'R05', 'S8-REPLAY-01']],
  ['C-RM-05', ['S8-WORKLOAD-RESULT-01']],
  ['C-UNION-01', ['U01', 'U02']],
  ['C-UNION-02', ['U01', 'U02']],
  ['C-UNION-03', ['N02', 'U01', 'U02']],
  ['C-WL-01', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-02', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-03', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-04', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-05', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-06', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-07', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-08', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-09', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-10', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-11', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-12', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-13', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-14', ['S8-WORKLOAD-FREEZE-01']],
  ['C-WL-15', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-16', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-17', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-18', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-19', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-20', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-21', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-22', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-23', ['S8-WORKLOAD-RESULT-01']],
  ['C-WL-24', ['S8-WORKLOAD-RESULT-01']],
  ['A-8', ['S9-MUTATION-MECHANISM-01']],
  ['A-13', ['S9-MUTATION-MECHANISM-01']],
  ['C-MUT-01', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-02', ['S9-MUTATION-MECHANISM-01']],
  ['C-MUT-03', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-04', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-05', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-06', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-07', ['S9-MUTATION-MECHANISM-01']],
  ['C-MUT-08', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-09', ['S9-MUTATION-RESULT-01']],
  ['C-MUT-10', ['S9-MUTATION-MECHANISM-01', 'S9-MUTATION-RESULT-01']],
  ['C-DATA-01', ['S8-WORKLOAD-FREEZE-01']],
  ['C-DATA-03', ['S10-SUPPLY-01']],
  ['C-KEY-04', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-ID-01', ['S10-RELEASE-SCHEMA-01', 'S10-SUPPLY-01']],
  ['C-ID-02', ['S10-SUPPLY-01']],
  ['C-ID-03', ['S10-SUPPLY-01']],
  ['C-ID-04', ['S10-SUPPLY-01']],
  ['C-ID-05', ['S10-SUPPLY-01']],
  ['C-ID-06', ['S10-RELEASE-SCHEMA-01', 'S10-SUPPLY-01']],
  ['C-ID-07', ['S10-RELEASE-SCHEMA-01', 'S10-CLEANROOM-01']],
  ['C-ID-08', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-ID-09', ['L03', 'S10-PUBLICATION-01']],
  [
    'C-ID-10',
    [
      'L06',
      'L07',
      'L08',
      'L10',
      'L11A',
      'L11B',
      'L13',
      'L16',
      'L20',
      'L21',
      'S10-FINALIZER-01',
    ],
  ],
  ['C-REP-01', ['S10-SUPPLY-01']],
  ['C-REP-02', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-REP-03', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-REP-04', ['L14', 'L15', 'L18', 'L19', 'C-REP-09', 'S10-CLEANROOM-01']],
  ['C-REP-05', ['L04', 'S10-CLEANROOM-01']],
  ['C-REP-06', ['C-REP-06', 'S10-CLEANROOM-01']],
  ['C-REP-07', ['S10-SUPPLY-01']],
  [
    'C-REP-08',
    ['L01', 'L02', 'L03', 'L09', 'L12', 'L17', 'S10-PUBLICATION-01'],
  ],
  ['C-REP-09', ['C-REP-09', 'S10-CLEANROOM-01']],
  ['C-REP-10', ['L18', 'S10-CLEANROOM-01']],
  [
    'C-FIX-07',
    [
      'C-VN-11',
      'C-ISSUE-13',
      'C-CAP-11',
      'C-CAP-12',
      'C-VN-12',
      'C-REP-09',
      'A-19',
      'C-ISSUE-09',
      'C-REP-06',
      'A-4',
      'L01',
      'L02',
      'L03',
      'L04',
      'L05',
      'L06',
      'L07',
      'L08',
      'L09',
      'L10',
      'L11A',
      'L11B',
      'L12',
      'L13',
      'L14',
      'L15',
      'L16',
      'L17',
      'L18',
      'L19',
      'L20',
      'L21',
      'S10-CLEANROOM-01',
    ],
  ],
  ['C-PERF-01', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-PERF-02', ['S10-CLEANROOM-01']],
  ['C-PERF-03', ['S10-CLEANROOM-01']],
  ['C-PERF-04', ['S10-CLEANROOM-01']],
  ['C-PERF-05', ['S10-CLEANROOM-01']],
  ['C-PERF-06', ['S10-CLEANROOM-01']],
  ['C-DATA-02', ['S10-SUPPLY-01', 'S10-CLEANROOM-01']],
  ['C-FINAL-01', ['L18', 'S10-CLEANROOM-01']],
  ['C-FINAL-02', ['S10-PUBLICATION-01', 'S10-CLEANROOM-01']],
  ['C-FINAL-03', ['S10-PUBLICATION-01']],
]);

function ownership(conditionId) {
  if (conditionId.startsWith('C-JSON-') || conditionId.startsWith('C-LIM-')) {
    return ['vouch::artifact_json', 'artifact JSON byte gate'];
  }
  if (conditionId.startsWith('C-DSSE-')) {
    return ['vouch::dsse', 'DSSE encode and verify primitives'];
  }
  if (conditionId.startsWith('C-POLICY-')) {
    return ['vouch::policy', 'native trust-policy parser and verifier'];
  }
  if (conditionId.startsWith('C-KEY-')) {
    return ['vouch::io_boundary', 'key and file provider boundaries'];
  }
  if (conditionId.startsWith('C-ID-') || conditionId.startsWith('C-REP-')) {
    return ['vouch::release', 'release lifecycle API'];
  }
  if (conditionId.startsWith('C-ISSUE-')) {
    return ['lispex::vouch_native::issue', 'issue-native contract lane'];
  }
  if (conditionId.startsWith('C-VS-') || conditionId === 'A-11') {
    return [
      'lispex::vouch_native::structural_verify',
      'verify-structure contract lane',
    ];
  }
  if (conditionId.startsWith('C-VN-') || conditionId === 'A-12') {
    return ['lispex::vouch_native::verify', 'verify-native contract lane'];
  }
  if (conditionId.startsWith('C-CAP-')) {
    return ['packages/vouch-consumer', 'consumer capability API'];
  }
  if (conditionId.startsWith('C-BR-')) {
    return ['packages/vouch-consumer::bridge', 'Bridge verification API'];
  }
  if (conditionId.startsWith('C-FIX-')) {
    return ['artifact::fixtures', 'fixture registry and conformance runner'];
  }
  if (conditionId.startsWith('C-RM-')) {
    return ['vouch::release', 'replay-manifest verification API'];
  }
  if (conditionId.startsWith('C-WL-')) {
    return ['artifact::workload', 'workload generator and replay runner'];
  }
  if (conditionId.startsWith('C-MUT-')) {
    return ['artifact::mutation', 'mutation registry and campaign runner'];
  }
  if (conditionId.startsWith('C-PERF-')) {
    return ['artifact::performance', 'performance measurement runner'];
  }
  if (conditionId.startsWith('C-DATA-')) {
    return ['artifact::scripts', 'public-data generation and scan commands'];
  }
  if (
    conditionId.startsWith('C-FINAL-') ||
    conditionId.startsWith('C-UNION-')
  ) {
    return ['artifact::release', 'release acceptance gate'];
  }
  if (['A-8', 'A-9', 'A-18'].includes(conditionId)) {
    return [
      'lispex::vouch_native::test_support',
      'compile-time mutation configuration',
    ];
  }
  if (conditionId === 'A-3') {
    return ['lispex::vouch_native::transcript', 'contract transcript types'];
  }
  if (conditionId === 'A-4') {
    return [
      'lispex::vouch_native::canonical_value',
      'canonical contract value encoder',
    ];
  }
  if (conditionId === 'A-5') {
    return ['lispex::vouch_native::graph', 'contract graph type and validator'];
  }
  if (['A-6', 'A-7', 'A-14', 'A-15', 'A-19'].includes(conditionId)) {
    return [
      'lispex::vouch_native::receipt',
      'contract receipt model and consistency checks',
    ];
  }
  if (['A-1', 'A-2', 'A-13'].includes(conditionId)) {
    return [
      'lispex::vouch_native::checked_profile',
      'checked-profile execution lane',
    ];
  }
  if (['A-16', 'A-17'].includes(conditionId)) {
    return [
      'packages/vouch-consumer',
      'native evidence promotion and rendering API',
    ];
  }
  if (conditionId.startsWith('P-')) {
    const ownerModule = ['P-1', 'P-2', 'P-3', 'P-4', 'P-11'].includes(
      conditionId
    )
      ? 'lispex::vouch_native::checked_input'
      : 'lispex::vouch_native::checked_profile';
    return [ownerModule, 'checked input/profile contract lane'];
  }
  throw new Error(`no ownership mapping for ${conditionId}`);
}

const rows = conditionIds.map((conditionId) => {
  const [ownerModule, publicInterface] = ownership(conditionId);
  return {
    condition_id: conditionId,
    owner_module: ownerModule,
    public_interface: publicInterface,
    test_or_fixture_ids: fixturesByCondition.get(conditionId) ?? [],
    scope: designTargets.has(conditionId) ? 'design-target' : 'built',
    platform: linuxPrefixes.some((prefix) => conditionId.startsWith(prefix))
      ? 'linux'
      : 'portable',
    implementation_status: builtConditions.has(conditionId)
      ? 'built'
      : 'not-started',
  };
});

const document = {
  condition_map: 'vouch.scored26-condition-map/v0',
  contract_sha256: expectedHash,
  conditions: rows,
};

await writeFile(outputPath, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
console.log(
  `wrote ${rows.length} condition rows to ${path.relative(process.cwd(), outputPath)}`
);
