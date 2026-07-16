export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export class ArtifactJsonError extends Error {
  constructor(readonly kind: 'resource' | 'canonical') {
    super(kind);
  }
}

const MAX_RAW_BYTES = 16_777_216;
const MAX_DEPTH = 128;
const MAX_MEMBERS = 10_000;
const MAX_NODES = 100_000;
const MAX_STRING_BYTES = 1_048_576;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function canonicalGate(bytes: Uint8Array): {
  value: JsonValue;
  bytes: Uint8Array;
} {
  if (bytes.byteLength > MAX_RAW_BYTES) throw new ArtifactJsonError('resource');
  if (
    bytes.byteLength >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    throw new ArtifactJsonError('canonical');
  }
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new ArtifactJsonError('canonical');
  }
  const parser = new BoundedJsonParser(text);
  const value = parser.parse();
  const canonical = writeArtifactJson(value);
  if (!bytesEqual(bytes, canonical)) throw new ArtifactJsonError('canonical');
  return { value, bytes: canonical };
}

export function writeArtifactJson(value: JsonValue): Uint8Array {
  const chunks: string[] = [];
  writeValue(value, 0, chunks);
  chunks.push('\n');
  return encoder.encode(chunks.join(''));
}

function writeValue(value: JsonValue, depth: number, chunks: string[]): void {
  if (value === null) return void chunks.push('null');
  if (typeof value === 'boolean')
    return void chunks.push(value ? 'true' : 'false');
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new ArtifactJsonError('canonical');
    }
    return void chunks.push(String(value));
  }
  if (typeof value === 'string') return writeString(value, chunks);
  if (Array.isArray(value)) {
    if (value.length === 0) return void chunks.push('[]');
    chunks.push('[\n');
    value.forEach((item, index) => {
      chunks.push('  '.repeat(depth + 1));
      writeValue(item, depth + 1, chunks);
      chunks.push(index + 1 === value.length ? '\n' : ',\n');
    });
    chunks.push('  '.repeat(depth), ']');
    return;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ArtifactJsonError('canonical');
  }
  const names = Object.keys(value).sort(compareUtf8);
  if (names.length === 0) return void chunks.push('{}');
  chunks.push('{\n');
  names.forEach((name, index) => {
    chunks.push('  '.repeat(depth + 1));
    writeString(name, chunks);
    chunks.push(': ');
    writeValue(value[name]!, depth + 1, chunks);
    chunks.push(index + 1 === names.length ? '\n' : ',\n');
  });
  chunks.push('  '.repeat(depth), '}');
}

function writeString(value: string, chunks: string[]): void {
  chunks.push('"');
  for (const scalar of value) {
    const code = scalar.codePointAt(0)!;
    if (code >= 0xd800 && code <= 0xdfff)
      throw new ArtifactJsonError('canonical');
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
        chunks.push(
          code <= 0x1f ? `\\u${code.toString(16).padStart(4, '0')}` : scalar
        );
    }
  }
  chunks.push('"');
}

function compareUtf8(left: string, right: string): number {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let i = 0; i < left.byteLength; i += 1)
    difference |= left[i]! ^ right[i]!;
  return difference === 0;
}

class BoundedJsonParser {
  private index = 0;
  private nodes = 0;

  constructor(private readonly text: string) {}

  parse(): JsonValue {
    this.whitespace();
    const value = this.value(0);
    this.whitespace();
    if (this.index !== this.text.length)
      throw new ArtifactJsonError('canonical');
    return value;
  }

  private node(): void {
    this.nodes += 1;
    if (this.nodes > MAX_NODES) throw new ArtifactJsonError('resource');
  }

  private value(depth: number): JsonValue {
    this.node();
    const char = this.text[this.index];
    if (char === '{') return this.object(depth + 1);
    if (char === '[') return this.array(depth + 1);
    if (char === '"') return this.string();
    if (this.text.startsWith('true', this.index)) {
      this.index += 4;
      return true;
    }
    if (this.text.startsWith('false', this.index)) {
      this.index += 5;
      return false;
    }
    if (this.text.startsWith('null', this.index)) {
      this.index += 4;
      return null;
    }
    return this.number();
  }

  private object(depth: number): { [key: string]: JsonValue } {
    if (depth > MAX_DEPTH) throw new ArtifactJsonError('resource');
    this.index += 1;
    const object: { [key: string]: JsonValue } = {};
    const names = new Set<string>();
    this.whitespace();
    if (this.take('}')) return object;
    let count = 0;
    while (true) {
      count += 1;
      if (count > MAX_MEMBERS) throw new ArtifactJsonError('resource');
      if (this.text[this.index] !== '"')
        throw new ArtifactJsonError('canonical');
      this.node();
      const name = this.string();
      if (names.has(name)) throw new ArtifactJsonError('canonical');
      names.add(name);
      this.whitespace();
      this.expect(':');
      this.whitespace();
      Object.defineProperty(object, name, {
        configurable: true,
        enumerable: true,
        value: this.value(depth),
        writable: true,
      });
      this.whitespace();
      if (this.take('}')) return object;
      this.expect(',');
      this.whitespace();
    }
  }

  private array(depth: number): JsonValue[] {
    if (depth > MAX_DEPTH) throw new ArtifactJsonError('resource');
    this.index += 1;
    const array: JsonValue[] = [];
    this.whitespace();
    if (this.take(']')) return array;
    while (true) {
      if (array.length >= MAX_MEMBERS) throw new ArtifactJsonError('resource');
      array.push(this.value(depth));
      this.whitespace();
      if (this.take(']')) return array;
      this.expect(',');
      this.whitespace();
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    let closed = false;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        closed = true;
        break;
      }
      if (code <= 0x1f) throw new ArtifactJsonError('canonical');
      if (code === 0x5c) {
        this.index += 1;
        const escape = this.text[this.index];
        if (escape === 'u') {
          const hex = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex))
            throw new ArtifactJsonError('canonical');
          this.index += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape)) {
          throw new ArtifactJsonError('canonical');
        }
      }
      this.index += 1;
    }
    if (!closed) throw new ArtifactJsonError('canonical');
    let value: string;
    try {
      value = JSON.parse(this.text.slice(start, this.index)) as string;
    } catch {
      throw new ArtifactJsonError('canonical');
    }
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff))
          throw new ArtifactJsonError('canonical');
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        throw new ArtifactJsonError('canonical');
      }
    }
    if (encoder.encode(value).byteLength > MAX_STRING_BYTES) {
      throw new ArtifactJsonError('resource');
    }
    return value;
  }

  private number(): number {
    const rest = this.text.slice(this.index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      rest
    );
    if (!match) throw new ArtifactJsonError('canonical');
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new ArtifactJsonError('canonical');
    }
    return value;
  }

  private expect(character: string): void {
    if (!this.take(character)) throw new ArtifactJsonError('canonical');
  }

  private take(character: string): boolean {
    if (this.text[this.index] !== character) return false;
    this.index += 1;
    return true;
  }

  private whitespace(): void {
    while (/\s/.test(this.text[this.index] ?? '')) {
      const character = this.text[this.index];
      if (
        character !== ' ' &&
        character !== '\n' &&
        character !== '\r' &&
        character !== '\t'
      ) {
        throw new ArtifactJsonError('canonical');
      }
      this.index += 1;
    }
  }
}

export function exactObject(
  value: JsonValue,
  fields: readonly string[]
): Record<string, JsonValue> | undefined {
  if (value === null || Array.isArray(value) || typeof value !== 'object')
    return undefined;
  const names = Object.keys(value);
  if (
    names.length !== fields.length ||
    fields.some((field) => !names.includes(field))
  ) {
    return undefined;
  }
  return value;
}
