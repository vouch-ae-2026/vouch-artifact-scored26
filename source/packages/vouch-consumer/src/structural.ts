import { createHash } from 'node:crypto';

import {
  ArtifactJsonError,
  bytesEqual,
  canonicalGate,
  exactObject,
  type JsonValue,
  writeArtifactJson,
} from './artifact-json.js';
import {
  graphFromNormalized,
  normalizeCheckedSource,
  readerSymbol,
} from './core.js';

const BOUNDARY_STATEMENT =
  'This receipt records structural consistency only. It is not authentication, an independent witness, or evidence of freshness. Deterministic gates may veto a result. Only a human operator gives final approval.';
const PROFILE = 'csk.checked-profile/v1';
const encoder = new TextEncoder();

export class StructuralFault extends Error {
  constructor(
    readonly resource = false,
    readonly schema = false
  ) {
    super(resource ? 'resource' : schema ? 'schema' : 'inconsistent');
  }
}

export type CheckedReceipt = Readonly<Record<string, JsonValue>>;

export function verifyReceiptIntrinsic(value: JsonValue): CheckedReceipt {
  const receipt = object(value, [
    'differential_receipt',
    'engine',
    'execution',
    'source',
    'input',
    'canonical',
    'graph',
    'reference',
    'meaning_env',
    'comparison',
    'diagnostics',
    'boundary',
  ]);
  equal(string(receipt.differential_receipt), 'csk.differential-receipt/v0');

  const engine = object(receipt.engine, ['executable_sha256', 'target_triple']);
  executableDigest(engine.executable_sha256);
  string(engine.target_triple);

  const execution = object(receipt.execution, [
    'invocation',
    'context_digest',
    'profile',
    'lispex_version',
    'build_commit',
    'build_variant',
    'mutant_id',
    'target_triple',
    'executable_sha256',
  ]);
  equal(string(execution.invocation), 'native-checked');
  equal(string(execution.profile), PROFILE);
  hex64(execution.context_digest);
  string(execution.lispex_version);
  hex(execution.build_commit, 40);
  const buildVariant = enumString(execution.build_variant, [
    'release',
    'mutant',
  ] as const);
  const mutantId = nullableString(execution.mutant_id);
  if (
    (buildVariant === 'release' && mutantId !== null) ||
    (buildVariant === 'mutant' && !mutantId)
  )
    inconsistent();
  string(execution.target_triple);
  executableDigest(execution.executable_sha256);
  consistentEqual(engine.target_triple, execution.target_triple);
  consistentEqual(engine.executable_sha256, execution.executable_sha256);

  const source = byteIdentity(receipt.source);
  const input = object(receipt.input, [
    'sha256',
    'byte_length',
    'canonical_value_sha256',
  ]);
  hex64(input.sha256);
  uint(input.byte_length);
  hex64(input.canonical_value_sha256);

  const canonical = object(receipt.canonical, [
    'normalized_sha256',
    'normalized_bytes_b64',
  ]);
  hex64(canonical.normalized_sha256);
  const normalized = decodeBase64(string(canonical.normalized_bytes_b64));
  if (normalized.byteLength > 1_048_576) throw new StructuralFault(true);
  consistentEqual(
    canonical.normalized_sha256,
    domainHash('csk.v0.canonical', normalized)
  );

  const graphContainer = object(receipt.graph, [
    'graph_sha256',
    'node_count',
    'value',
  ]);
  hex64(graphContainer.graph_sha256);
  const nodeCount = uint(graphContainer.node_count);
  if (nodeCount > 100_000) throw new StructuralFault(true);
  const graph = object(graphContainer.value, ['graph', 'roots', 'nodes']);
  equal(string(graph.graph), 'csk.graph/v0');
  const roots = array(graph.roots);
  const nodes = array(graph.nodes);
  if (nodes.length > 100_000) throw new StructuralFault(true);
  if (roots.length === 0 || nodeCount !== nodes.length) inconsistent();
  roots.forEach(uint);
  let reproducedGraph: JsonValue;
  try {
    reproducedGraph = graphFromNormalized(normalized);
  } catch (error) {
    if (error instanceof RangeError) throw new StructuralFault(true);
    inconsistent();
  }
  if (!bytesEqual(writeArtifactJson(graph), writeArtifactJson(reproducedGraph)))
    inconsistent();
  consistentEqual(
    graphContainer.graph_sha256,
    domainHash('csk.v0.graph', writeArtifactJson(graph))
  );

  const reference = traceReport(
    receipt.reference,
    'csk.v0.reference',
    roots.length
  );
  const meaning = object(receipt.meaning_env, [
    'meaning_env',
    'graph_sha256',
    'transcript_sha256',
    'node_count',
    'terminal',
    'transcript',
  ]);
  equal(string(meaning.meaning_env), 'csk.meaning-env-report/v0');
  hex64(meaning.graph_sha256);
  hex64(meaning.transcript_sha256);
  consistentEqual(uint(meaning.node_count), nodeCount);
  consistentEqual(meaning.graph_sha256, graphContainer.graph_sha256);
  const meaningTranscript = transcript(meaning.transcript, roots.length);
  const meaningTerminal = terminal(meaning.terminal);
  if (!jsonEqual(meaningTerminal, meaningTranscript.terminal)) inconsistent();
  consistentEqual(
    meaning.transcript_sha256,
    domainHash('csk.v0.meaning_env', writeArtifactJson(meaning.transcript))
  );

  const comparison = object(receipt.comparison, [
    'status',
    'first_divergence_index',
    'comparison_unavailable_at',
  ]);
  enumString(comparison.status, [
    'agree',
    'disagree',
    'not-comparable',
  ] as const);
  nullableUint(comparison.first_divergence_index);
  nullableUint(comparison.comparison_unavailable_at);
  const fresh = compareTranscripts(
    reference.transcriptObject,
    meaningTranscript
  );
  if (!jsonEqual(comparison, fresh)) inconsistent();

  const diagnostics = array(receipt.diagnostics);
  for (const diagnostic of diagnostics) {
    const item = object(diagnostic, ['code', 'message']);
    string(item.code);
    string(item.message);
  }
  const boundary = object(receipt.boundary, ['statement_sha256']);
  hex64(boundary.statement_sha256);
  consistentEqual(
    boundary.statement_sha256,
    domainHash('csk.v0.boundary', encoder.encode(BOUNDARY_STATEMENT))
  );

  const context: JsonValue = {
    normalized_bytes_b64: encodeBase64(normalized),
    input_canonical_value_sha256: string(input.canonical_value_sha256),
    profile: PROFILE,
    engine_executable_sha256: string(execution.executable_sha256),
  };
  consistentEqual(
    execution.context_digest,
    domainHash('csk.v0.execution-context', writeArtifactJson(context))
  );
  void source;
  return receipt;
}

export function verifyExpectedSource(
  receipt: CheckedReceipt,
  sourceBytes: Uint8Array
): void {
  const source = object(receipt.source!, ['sha256', 'byte_length']);
  if (
    uint(source.byte_length) !== sourceBytes.byteLength ||
    source.sha256 !== domainHash('csk.v0.source', sourceBytes)
  ) {
    throw new ContextFault('source');
  }
  let normalized: Uint8Array;
  try {
    normalized = normalizeCheckedSource(sourceBytes);
  } catch (error) {
    if (error instanceof RangeError) throw new StructuralFault(true);
    throw new ContextFault('source');
  }
  const canonical = object(receipt.canonical!, [
    'normalized_sha256',
    'normalized_bytes_b64',
  ]);
  let expected: Uint8Array;
  try {
    expected = decodeBase64(string(canonical.normalized_bytes_b64));
  } catch {
    throw new ContextFault('source');
  }
  if (!bytesEqual(normalized, expected)) throw new ContextFault('source');
}

export class ContextFault extends Error {
  constructor(
    readonly kind:
      'source' | 'input-raw' | 'input-parse' | 'input-profile' | 'input-value'
  ) {
    super(kind);
  }
}

export function verifyExpectedInput(
  receipt: CheckedReceipt,
  inputBytes: Uint8Array
): void {
  const input = object(receipt.input!, [
    'sha256',
    'byte_length',
    'canonical_value_sha256',
  ]);
  if (
    uint(input.byte_length) !== inputBytes.byteLength ||
    input.sha256 !== domainHash('csk.v0.input', inputBytes)
  ) {
    throw new ContextFault('input-raw');
  }
  let gate: JsonValue;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(inputBytes);
    if (!text.endsWith('\n') || text.endsWith('\n\n')) throw new Error();
    JSON.parse(text);
  } catch {
    throw new ContextFault('input-parse');
  }
  try {
    gate = canonicalGate(inputBytes).value;
  } catch (error) {
    if (error instanceof ArtifactJsonError && error.kind === 'resource') {
      throw new StructuralFault(true);
    }
    throw new ContextFault('input-profile');
  }
  const host = exactObject(gate, ['input', 'value']);
  if (!host || host.input !== 'csk.checked-input/v1')
    throw new ContextFault('input-profile');
  let mapped: JsonValue;
  try {
    mapped = mapInput(host.value!);
  } catch (error) {
    if (error instanceof StructuralFault && error.resource) throw error;
    throw new ContextFault('input-profile');
  }
  const digest = domainHash(
    'csk.v0.input-canonical-value',
    writeArtifactJson(mapped)
  );
  if (digest !== input.canonical_value_sha256)
    throw new ContextFault('input-value');
}

function mapInput(value: JsonValue): JsonValue {
  if (typeof value === 'boolean') return { t: 'bool', v: value };
  if (typeof value === 'number') return { t: 'int', v: String(value) };
  if (typeof value === 'string') return { t: 'str', v: value };
  if (Array.isArray(value))
    return { t: 'list', items: value.map(mapInput), improper_tail: null };
  const tagged = value && typeof value === 'object' ? value : undefined;
  if (!tagged || Object.keys(tagged).length !== 1) fault();
  if ('$rat' in tagged) {
    const rat = object(tagged.$rat!, ['n', 'd']);
    const n = canonicalInteger(rat.n, true);
    const d = canonicalInteger(rat.d, false);
    if (digits(n) > 4096 || digits(d) > 4096) throw new StructuralFault(true);
    const numerator = BigInt(n);
    const denominator = BigInt(d);
    if (
      denominator <= 1n ||
      numerator === 0n ||
      gcd(numerator, denominator) !== 1n
    )
      fault();
    return { t: 'rat', n, d };
  }
  if ('$real' in tagged) {
    const real = string(tagged.$real!);
    if (!Number.isFinite(Number(real)) || !canonicalReal(real)) fault();
    return { t: 'real', v: real };
  }
  if ('$sym' in tagged) {
    const symbol = string(tagged.$sym!);
    if (!readerSymbol(symbol) || symbol === 'input' || PRIMITIVES.has(symbol))
      fault();
    return { t: 'sym', v: symbol };
  }
  fault();
}

const PRIMITIVES = new Set([
  '+',
  '-',
  '*',
  '/',
  '=',
  '<',
  '<=',
  '>',
  '>=',
  'cons',
  'car',
  'cdr',
  'null?',
  'pair?',
  'list',
  'exact-integer?',
  'decision-approve',
  'decision-deny',
  'decision-review',
  'decision-invalid-input',
]);

function traceReport(
  value: JsonValue,
  domain: string,
  roots: number
): { transcriptObject: TranscriptShape } {
  const report = object(value, ['transcript_sha256', 'terminal', 'transcript']);
  hex64(report.transcript_sha256);
  const parsed = transcript(report.transcript, roots);
  const repeated = terminal(report.terminal);
  if (!jsonEqual(repeated, parsed.terminal)) inconsistent();
  consistentEqual(
    report.transcript_sha256,
    domainHash(domain, writeArtifactJson(report.transcript))
  );
  return { transcriptObject: parsed };
}

type TranscriptShape = {
  value: Record<string, JsonValue>;
  events: Record<string, JsonValue>[];
  terminal: Record<string, JsonValue>;
};

function transcript(
  value: JsonValue,
  roots: number | undefined
): TranscriptShape {
  const transcriptObject = object(value, ['transcript', 'events', 'terminal']);
  equal(string(transcriptObject.transcript), 'csk.transcript/v0');
  const events = array(transcriptObject.events).map((event) => {
    const raw = asObject(event);
    const kind = string(raw.kind!);
    if (kind === 'output') {
      const item = object(event, ['kind', 'form_index', 'bytes_b64']);
      uint(item.form_index);
      decodeBase64(string(item.bytes_b64));
      return item;
    }
    if (kind === 'value') {
      const item = object(event, ['kind', 'form_index', 'value']);
      uint(item.form_index);
      canonicalValue(item.value);
      return item;
    }
    fault();
  });
  const parsedTerminal = terminal(transcriptObject.terminal);
  if (roots !== undefined) validateTranscript(events, parsedTerminal, roots);
  return { value: transcriptObject, events, terminal: parsedTerminal };
}

function terminal(value: JsonValue): Record<string, JsonValue> {
  const raw = asObject(value);
  switch (string(raw.kind!)) {
    case 'completed':
      return object(value, ['kind']);
    case 'language-fault': {
      const result = object(value, ['kind', 'code', 'form_index']);
      enumString(result.code, [
        'arity-mismatch',
        'type-error',
        'division-by-zero',
        'numeric-domain-error',
        'reference-budget-exhausted',
        'meaning-env-budget-exhausted',
      ] as const);
      uint(result.form_index);
      return result;
    }
    case 'infrastructure-failure': {
      const result = object(value, [
        'kind',
        'code',
        'phase',
        'next_form_index',
      ]);
      const code = enumString(result.code, [
        'native-reference-execution-failed',
        'native-meaning-execution-failed',
      ] as const);
      const phase = enumString(result.phase, [
        'reference-evaluation',
        'meaning-evaluation',
      ] as const);
      if (
        code.startsWith('native-reference') !==
        (phase === 'reference-evaluation')
      )
        fault();
      uint(result.next_form_index);
      return result;
    }
    default:
      fault();
  }
}

function validateTranscript(
  events: Record<string, JsonValue>[],
  terminalValue: Record<string, JsonValue>,
  roots: number
): void {
  if (roots === 0 || events.some((event) => event.kind === 'output'))
    inconsistent();
  let expected: number;
  if (terminalValue.kind === 'completed') expected = roots;
  else if (terminalValue.kind === 'language-fault') {
    expected = uint(terminalValue.form_index!);
    if (expected >= roots) inconsistent();
  } else {
    expected = uint(terminalValue.next_form_index!);
    if (expected > roots) inconsistent();
  }
  if (events.length !== expected) inconsistent();
  events.forEach((event, index) => {
    if (uint(event.form_index!) !== index || event.kind !== 'value')
      inconsistent();
    const value = event.value!;
    if (
      containsDecision(value) &&
      (!(asObject(value).t === 'decision') || index + 1 !== roots)
    )
      inconsistent();
  });
}

function compareTranscripts(
  left: TranscriptShape,
  right: TranscriptShape
): Record<string, JsonValue> {
  const indexes = [
    infrastructureIndex(left.terminal),
    infrastructureIndex(right.terminal),
  ].filter((value): value is number => value !== undefined);
  if (indexes.length)
    return {
      status: 'not-comparable',
      first_divergence_index: null,
      comparison_unavailable_at: Math.min(...indexes),
    };
  if (
    bytesEqual(writeArtifactJson(left.value), writeArtifactJson(right.value))
  ) {
    return {
      status: 'agree',
      first_divergence_index: null,
      comparison_unavailable_at: null,
    };
  }
  const shared = Math.min(left.events.length, right.events.length);
  let divergence = shared;
  for (let index = 0; index < shared; index += 1) {
    if (!jsonEqual(left.events[index], right.events[index])) {
      divergence = index;
      break;
    }
  }
  if (divergence === shared && left.events.length === right.events.length)
    divergence = left.events.length;
  return {
    status: 'disagree',
    first_divergence_index: divergence,
    comparison_unavailable_at: null,
  };
}

function infrastructureIndex(
  value: Record<string, JsonValue>
): number | undefined {
  return value.kind === 'infrastructure-failure'
    ? uint(value.next_form_index!)
    : undefined;
}

function canonicalValue(value: JsonValue): void {
  const raw = asObject(value);
  const tag = string(raw.t!);
  switch (tag) {
    case 'int': {
      const item = object(value, ['t', 'v']);
      const text = canonicalInteger(item.v, true);
      if (digits(text) > 4096) throw new StructuralFault(true);
      return;
    }
    case 'rat': {
      const item = object(value, ['t', 'n', 'd']);
      const n = canonicalInteger(item.n, true);
      const d = canonicalInteger(item.d, false);
      if (digits(n) > 4096 || digits(d) > 4096) throw new StructuralFault(true);
      const numerator = BigInt(n);
      const denominator = BigInt(d);
      if (
        denominator <= 0n ||
        gcd(numerator, denominator) !== 1n ||
        (numerator === 0n && denominator !== 1n)
      )
        fault();
      return;
    }
    case 'real': {
      const item = object(value, ['t', 'v']);
      if (!canonicalReal(string(item.v))) fault();
      return;
    }
    case 'bool': {
      const item = object(value, ['t', 'v']);
      if (typeof item.v !== 'boolean') fault();
      return;
    }
    case 'nil':
      object(value, ['t']);
      return;
    case 'list': {
      const item = object(value, ['t', 'items', 'improper_tail']);
      array(item.items).forEach(canonicalValue);
      if (item.improper_tail !== null) canonicalValue(item.improper_tail!);
      return;
    }
    case 'sym':
    case 'str': {
      const item = object(value, ['t', 'v']);
      string(item.v);
      return;
    }
    case 'void':
      object(value, ['t']);
      return;
    case 'decision': {
      const item = object(value, ['t', 'v']);
      enumString(item.v, [
        'approve',
        'deny',
        'review',
        'invalid-input',
      ] as const);
      return;
    }
    default:
      fault();
  }
}

function containsDecision(value: JsonValue): boolean {
  const raw = asObject(value);
  if (raw.t === 'decision') return true;
  if (raw.t !== 'list') return false;
  return (
    array(raw.items!).some(containsDecision) ||
    (raw.improper_tail !== null && containsDecision(raw.improper_tail!))
  );
}

function byteIdentity(value: JsonValue): Record<string, JsonValue> {
  const result = object(value, ['sha256', 'byte_length']);
  hex64(result.sha256);
  uint(result.byte_length);
  return result;
}

export function domainHash(label: string, bytes: Uint8Array): string {
  return createHash('sha256')
    .update(label, 'utf8')
    .update(Uint8Array.of(0x1f))
    .update(bytes)
    .digest('hex');
}

export function ordinaryHash(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function decodeBase64(value: string): Uint8Array {
  if (
    value.length % 4 !== 0 ||
    /\s/.test(value) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value
    )
  )
    fault();
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fault();
  return Uint8Array.from(bytes);
}

export function encodeBase64(value: Uint8Array): string {
  return Buffer.from(value).toString('base64');
}

function object(
  value: JsonValue,
  fields: readonly string[]
): Record<string, JsonValue> {
  const result = exactObject(value, fields);
  if (!result) fault();
  return result;
}
function asObject(value: JsonValue): Record<string, JsonValue> {
  if (!value || Array.isArray(value) || typeof value !== 'object') fault();
  return value;
}
function array(value: JsonValue): JsonValue[] {
  if (!Array.isArray(value)) fault();
  return value;
}
function string(value: JsonValue): string {
  if (typeof value !== 'string') fault();
  return value;
}
function uint(value: JsonValue): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    fault();
  return value;
}
function nullableUint(value: JsonValue): number | null {
  return value === null ? null : uint(value);
}
function nullableString(value: JsonValue): string | null {
  return value === null ? null : string(value);
}
function enumString<T extends string>(
  value: JsonValue,
  choices: readonly T[]
): T {
  const text = string(value);
  if (!choices.includes(text as T)) fault();
  return text as T;
}
function executableDigest(value: JsonValue): string {
  const text = string(value);
  if (!/^sha256:[0-9a-f]{64}$/.test(text)) fault();
  return text;
}
function hex64(value: JsonValue): string {
  return hex(value, 64);
}
function hex(value: JsonValue, length: number): string {
  const text = string(value);
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(text)) fault();
  return text;
}
function equal(left: unknown, right: unknown): void {
  if (left !== right) fault();
}
function consistentEqual(left: unknown, right: unknown): void {
  if (left !== right) inconsistent();
}
function jsonEqual(left: unknown, right: unknown): boolean {
  try {
    return bytesEqual(
      writeArtifactJson(left as JsonValue),
      writeArtifactJson(right as JsonValue)
    );
  } catch {
    return false;
  }
}
function fault(): never {
  throw new StructuralFault(false, true);
}
function inconsistent(): never {
  throw new StructuralFault(false, false);
}
function digits(value: string): number {
  return value.startsWith('-') ? value.length - 1 : value.length;
}
function canonicalInteger(value: JsonValue, negative: boolean): string {
  const text = string(value);
  const pattern = negative
    ? /^(?:0|-[1-9][0-9]*|[1-9][0-9]*)$/
    : /^(?:0|[1-9][0-9]*)$/;
  if (!pattern.test(text)) fault();
  return text;
}
function canonicalReal(value: string): boolean {
  const number = Number(value);
  return Number.isFinite(number) && formatReal(number) === value;
}
function formatReal(value: number): string {
  const negative = value < 0 || Object.is(value, -0);
  const raw = Math.abs(value).toString().toLowerCase();
  const [mantissa, exponentText] = raw.split('e');
  const exponent = exponentText === undefined ? 0 : Number(exponentText);
  const [integer, fraction = ''] = mantissa!.split('.');
  const all = `${integer}${fraction}`;
  const leading = all.search(/[1-9]/);
  if (leading < 0) return negative ? '-0.0' : '0.0';
  const significant = all.slice(leading).replace(/0+$/, '');
  const leadingExponent = exponent - fraction.length + all.length - 1 - leading;
  const point = leadingExponent + 1;
  let result: string;
  if (point <= 0) result = `0.${'0'.repeat(-point)}${significant}`;
  else if (point >= significant.length)
    result = `${significant}${'0'.repeat(point - significant.length)}.0`;
  else result = `${significant.slice(0, point)}.${significant.slice(point)}`;
  return negative ? `-${result}` : result;
}
function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}
