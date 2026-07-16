const MIN_SAFE_INTEGER = -9_007_199_254_740_991;
const MAX_SAFE_INTEGER = 9_007_199_254_740_991;

export const ARTIFACT_JSON_LIMITS = Object.freeze({
  rawBytes: 16_777_216,
  depth: 128,
  objectMembers: 10_000,
  arrayMembers: 10_000,
  stringBytes: 1_048_576,
  totalNodes: 100_000,
});

export class ArtifactJsonError extends Error {
  constructor(code, subject = null) {
    super(subject === null ? code : `${code}: ${subject}`);
    this.name = 'ArtifactJsonError';
    this.code = code;
    this.subject = subject;
  }
}

/**
 * Bounded token-level parsing for csk.artifact-json/v0.
 *
 * This deliberately does not use JSON.parse: duplicate member occurrences and
 * count-limit precedence must be observed before an object model exists.
 */
export function parseArtifactJson(bytes, { canonical = true } = {}) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  if (bytes.length > ARTIFACT_JSON_LIMITS.rawBytes) {
    throw resourceLimit('artifact-bytes');
  }
  if (bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))) {
    throw nonCanonical();
  }
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw nonCanonical();
  }
  const parser = new BoundedParser(source);
  parser.skipWhitespace();
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) throw nonCanonical();
  if (canonical && !writeArtifactJson(value).equals(bytes)) {
    throw nonCanonical();
  }
  return Object.freeze({
    value,
    counts: Object.freeze({
      raw_byte_count: bytes.length,
      maximum_container_depth: parser.maximumDepth,
      total_json_node_count: parser.totalNodes,
    }),
  });
}

export function canonicalArtifactJson(bytes) {
  return parseArtifactJson(bytes, { canonical: true }).value;
}

export function writeArtifactJson(value) {
  const chunks = [];
  writeValue(value, 0, chunks);
  chunks.push('\n');
  return Buffer.from(chunks.join(''), 'utf8');
}

function writeValue(value, depth, chunks) {
  if (value === null) {
    chunks.push('null');
    return;
  }
  if (typeof value === 'boolean') {
    chunks.push(value ? 'true' : 'false');
    return;
  }
  if (typeof value === 'number') {
    if (
      !Number.isSafeInteger(value) ||
      Object.is(value, -0) ||
      value < MIN_SAFE_INTEGER ||
      value > MAX_SAFE_INTEGER
    ) {
      throw new TypeError(
        'csk.artifact-json/v0 accepts only signed safe integers'
      );
    }
    chunks.push(String(value));
    return;
  }
  if (typeof value === 'string') {
    writeString(value, chunks);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      chunks.push('[]');
      return;
    }
    chunks.push('[\n');
    value.forEach((item, index) => {
      chunks.push('  '.repeat(depth + 1));
      writeValue(item, depth + 1, chunks);
      chunks.push(index + 1 === value.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), ']');
    return;
  }
  if (
    typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  ) {
    const names = Object.keys(value).sort(compareUtf8);
    if (names.length === 0) {
      chunks.push('{}');
      return;
    }
    chunks.push('{\n');
    names.forEach((name, index) => {
      chunks.push('  '.repeat(depth + 1));
      writeString(name, chunks);
      chunks.push(': ');
      writeValue(value[name], depth + 1, chunks);
      chunks.push(index + 1 === names.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), '}');
    return;
  }
  throw new TypeError('value is outside csk.artifact-json/v0');
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function writeString(value, chunks) {
  chunks.push('"');
  for (const scalar of value) {
    const code = scalar.codePointAt(0);
    if (code >= 0xd800 && code <= 0xdfff) {
      throw new TypeError(
        'csk.artifact-json/v0 strings contain Unicode scalars only'
      );
    }
    switch (code) {
      case 0x22:
        chunks.push('\\"');
        break;
      case 0x5c:
        chunks.push('\\\\');
        break;
      case 0x08:
        chunks.push('\\b');
        break;
      case 0x09:
        chunks.push('\\t');
        break;
      case 0x0a:
        chunks.push('\\n');
        break;
      case 0x0c:
        chunks.push('\\f');
        break;
      case 0x0d:
        chunks.push('\\r');
        break;
      default:
        if (code <= 0x1f) {
          chunks.push(`\\u${code.toString(16).padStart(4, '0')}`);
        } else {
          chunks.push(scalar);
        }
    }
  }
  chunks.push('"');
}

class BoundedParser {
  constructor(source) {
    this.source = source;
    this.offset = 0;
    this.depth = 0;
    this.maximumDepth = 0;
    this.totalNodes = 0;
  }

  atEnd() {
    return this.offset === this.source.length;
  }

  peek() {
    return this.source[this.offset];
  }

  skipWhitespace() {
    while (/^[\u0009\u000a\u000d\u0020]$/.test(this.peek() ?? '')) {
      this.offset += 1;
    }
  }

  parseValue() {
    this.countNode();
    const token = this.peek();
    if (token === 'n') return this.literal('null', null);
    if (token === 'f') return this.literal('false', false);
    if (token === 't') return this.literal('true', true);
    if (token === '"') return this.parseString();
    if (token === '[') return this.parseArray();
    if (token === '{') return this.parseObject();
    if (token === '-' || (token >= '0' && token <= '9')) {
      return this.parseInteger();
    }
    throw nonCanonical();
  }

  literal(spelling, value) {
    if (
      this.source.slice(this.offset, this.offset + spelling.length) !== spelling
    ) {
      throw nonCanonical();
    }
    this.offset += spelling.length;
    return value;
  }

  enterContainer() {
    this.depth = checkedIncrement(this.depth, 'json-depth');
    if (this.depth > ARTIFACT_JSON_LIMITS.depth) {
      throw resourceLimit('json-depth');
    }
    this.maximumDepth = Math.max(this.maximumDepth, this.depth);
  }

  parseArray() {
    this.enterContainer();
    this.offset += 1;
    this.skipWhitespace();
    const values = [];
    if (this.consume(']')) {
      this.depth -= 1;
      return values;
    }
    let members = 0;
    for (;;) {
      members = checkedIncrement(members, 'array-members');
      if (members > ARTIFACT_JSON_LIMITS.arrayMembers) {
        throw resourceLimit('array-members');
      }
      values.push(this.parseValue());
      this.skipWhitespace();
      if (this.consume(']')) {
        this.depth -= 1;
        return values;
      }
      if (!this.consume(',')) throw nonCanonical();
      this.skipWhitespace();
    }
  }

  parseObject() {
    this.enterContainer();
    this.offset += 1;
    this.skipWhitespace();
    const value = Object.create(null);
    if (this.consume('}')) {
      this.depth -= 1;
      return value;
    }
    const names = new Set();
    let members = 0;
    for (;;) {
      if (this.peek() !== '"') throw nonCanonical();
      this.countNode();
      const name = this.parseString();
      this.skipWhitespace();
      if (!this.consume(':')) throw nonCanonical();
      members = checkedIncrement(members, 'object-members');
      if (members > ARTIFACT_JSON_LIMITS.objectMembers) {
        throw resourceLimit('object-members');
      }
      if (names.has(name)) throw nonCanonical();
      names.add(name);
      this.skipWhitespace();
      Object.defineProperty(value, name, {
        value: this.parseValue(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      this.skipWhitespace();
      if (this.consume('}')) {
        this.depth -= 1;
        return value;
      }
      if (!this.consume(',')) throw nonCanonical();
      this.skipWhitespace();
    }
  }

  parseInteger() {
    const start = this.offset;
    this.consume('-');
    if (this.consume('0')) {
      if (isDigit(this.peek())) throw nonCanonical();
    } else {
      if (!isNonzeroDigit(this.peek())) throw nonCanonical();
      while (isDigit(this.peek())) this.offset += 1;
    }
    if (['.', 'e', 'E', '+'].includes(this.peek())) throw nonCanonical();
    const spelling = this.source.slice(start, this.offset);
    if (spelling === '-0') throw nonCanonical();
    const value = Number(spelling);
    if (
      !Number.isSafeInteger(value) ||
      value < MIN_SAFE_INTEGER ||
      value > MAX_SAFE_INTEGER
    ) {
      throw nonCanonical();
    }
    return value;
  }

  parseString() {
    if (!this.consume('"')) throw nonCanonical();
    const scalars = [];
    let decodedBytes = 0;
    while (!this.atEnd()) {
      const code = this.source.codePointAt(this.offset);
      if (code === 0x22) {
        this.offset += 1;
        return scalars.join('');
      }
      let scalar;
      if (code === 0x5c) {
        this.offset += 1;
        scalar = this.parseEscape();
      } else {
        if (code <= 0x1f || (code >= 0xd800 && code <= 0xdfff)) {
          throw nonCanonical();
        }
        scalar = String.fromCodePoint(code);
        this.offset += scalar.length;
      }
      decodedBytes = checkedAdd(
        decodedBytes,
        Buffer.byteLength(scalar, 'utf8'),
        'string-bytes'
      );
      if (decodedBytes > ARTIFACT_JSON_LIMITS.stringBytes) {
        throw resourceLimit('string-bytes');
      }
      scalars.push(scalar);
    }
    throw nonCanonical();
  }

  parseEscape() {
    const escape = this.source[this.offset++];
    const simple = Object.freeze({
      '"': '"',
      '\\': '\\',
      '/': '/',
      b: '\b',
      f: '\f',
      n: '\n',
      r: '\r',
      t: '\t',
    });
    if (Object.hasOwn(simple, escape)) return simple[escape];
    if (escape !== 'u') throw nonCanonical();
    const first = this.hexCodeUnit();
    if (first >= 0xd800 && first <= 0xdbff) {
      if (this.source.slice(this.offset, this.offset + 2) !== '\\u') {
        throw nonCanonical();
      }
      this.offset += 2;
      const second = this.hexCodeUnit();
      if (second < 0xdc00 || second > 0xdfff) throw nonCanonical();
      return String.fromCodePoint(
        0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
      );
    }
    if (first >= 0xdc00 && first <= 0xdfff) throw nonCanonical();
    return String.fromCodePoint(first);
  }

  hexCodeUnit() {
    const spelling = this.source.slice(this.offset, this.offset + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(spelling)) throw nonCanonical();
    this.offset += 4;
    return Number.parseInt(spelling, 16);
  }

  consume(token) {
    if (this.source[this.offset] !== token) return false;
    this.offset += 1;
    return true;
  }

  countNode() {
    this.totalNodes = checkedIncrement(this.totalNodes, 'json-nodes');
    if (this.totalNodes > ARTIFACT_JSON_LIMITS.totalNodes) {
      throw resourceLimit('json-nodes');
    }
  }
}

function checkedIncrement(value, subject) {
  return checkedAdd(value, 1, subject);
}

function checkedAdd(left, right, subject) {
  const value = left + right;
  if (!Number.isSafeInteger(value)) throw resourceLimit(subject);
  return value;
}

function isDigit(value) {
  return value >= '0' && value <= '9';
}

function isNonzeroDigit(value) {
  return value >= '1' && value <= '9';
}

function nonCanonical() {
  return new ArtifactJsonError('non-canonical-artifact-json');
}

function resourceLimit(subject) {
  return new ArtifactJsonError('artifact-resource-limit', subject);
}
