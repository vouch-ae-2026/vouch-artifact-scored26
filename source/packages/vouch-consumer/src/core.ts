import type { JsonValue } from './artifact-json.js';

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

type Datum = Readonly<{ atom: string }> | readonly Datum[];
type Core =
  | { k: 'quote'; text: string; value: JsonValue }
  | { k: 'var'; name: string }
  | { k: 'if'; test: Core; consequent: Core; alternate: Core }
  | { k: 'lambda'; params: string[]; body: Core }
  | { k: 'app'; operator: Core; arguments: Core[] }
  | { k: 'begin'; forms: Core[] }
  | { k: 'let'; names: string[]; initializers: Core[]; body: Core }
  | { k: 'define'; name: string; value: Core };

type GraphNode = Record<string, JsonValue>;

export function normalizeCheckedSource(source: Uint8Array): Uint8Array {
  const text = decodeStrict(source);
  const lowerer = new SurfaceLowerer();
  const core = parseDatums(text).map((datum) => lowerer.lower(datum));
  validateCore(core);
  return new TextEncoder().encode(
    `lispex.core.canonical/v0\n${core.map(renderCore).join('\n')}\n`
  );
}

export function graphFromNormalized(normalized: Uint8Array): JsonValue {
  const text = decodeStrict(normalized);
  const prefix = 'lispex.core.canonical/v0\n';
  if (!text.startsWith(prefix) || !text.endsWith('\n'))
    throw new Error('normalized');
  const body = text.slice(prefix.length);
  const core = parseDatums(body).map(parseNormalizedCore);
  if (core.length === 0) throw new Error('normalized');
  validateCore(core);
  const reproduced = `${prefix}${core.map(renderCore).join('\n')}\n`;
  if (reproduced !== text) throw new Error('normalized');
  const nodes: GraphNode[] = [];
  const roots: number[] = [];
  const topLevel = new Set<string>();
  for (const form of core) {
    roots.push(lowerGraph(form, nodes, true, topLevel));
    if (form.k === 'define') topLevel.add(form.name);
  }
  return { graph: 'csk.graph/v0', roots, nodes };
}

function decodeStrict(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error('utf8');
  }
}

class SurfaceLowerer {
  private nextTemp = 0;

  lower(datum: Datum): Core {
    if (!Array.isArray(datum)) {
      const atom = (datum as { atom: string }).atom;
      if (isLiteral(atom)) return literalCore(atom);
      if (atom.startsWith('$sym:')) {
        const name = atom.slice(5);
        if (!identifier(name) || name === 'input' || PRIMITIVES.has(name))
          throw new Error('symbol');
        return { k: 'quote', text: name, value: { t: 'sym', v: name } };
      }
      if (!identifier(atom)) throw new Error('identifier');
      return { k: 'var', name: atom };
    }
    const list = datum as readonly Datum[];
    if (list.length === 0)
      return { k: 'quote', text: '()', value: { t: 'nil' } };
    const head = atomText(list[0]);
    if (
      [
        'set!',
        'letrec',
        'let*',
        'quote',
        'quasiquote',
        'unquote',
        'unquote-splicing',
        'values',
        'call-with-values',
        'call/cc',
        'dynamic-wind',
        'guard',
        'case',
        'when',
        'unless',
        'do',
        'module',
        'export',
        'import',
        'define-syntax',
        'syntax-rules',
        'define-library',
        'vector',
        'make-vector',
        'vector-set!',
        'bytevector',
        'make-bytevector',
        'display',
        'write',
        'newline',
        'println',
      ].includes(head ?? '')
    ) {
      throw new Error('uncovered');
    }
    switch (head) {
      case 'if':
        if (list.length !== 4) throw new Error('if');
        return {
          k: 'if',
          test: this.lower(list[1]!),
          consequent: this.lower(list[2]!),
          alternate: this.lower(list[3]!),
        };
      case 'lambda': {
        if (list.length < 3) throw new Error('lambda');
        const params = binderList(list[1]!);
        return { k: 'lambda', params, body: this.body(list.slice(2)) };
      }
      case 'begin':
        if (list.length < 2) throw new Error('begin');
        return {
          k: 'begin',
          forms: list.slice(1).map((item) => this.lower(item)),
        };
      case 'define': {
        if (list.length !== 3) throw new Error('define');
        return {
          k: 'define',
          name: binder(list[1]!),
          value: this.lower(list[2]!),
        };
      }
      case 'let': {
        if (list.length < 3 || !Array.isArray(list[1])) throw new Error('let');
        const names: string[] = [];
        const initializers: Core[] = [];
        for (const raw of list[1] as readonly Datum[]) {
          if (!Array.isArray(raw) || raw.length !== 2) throw new Error('let');
          names.push(binder(raw[0]!));
          initializers.push(this.lower(raw[1]!));
        }
        return {
          k: 'let',
          names,
          initializers,
          body: this.body(list.slice(2)),
        };
      }
      case 'and':
        return this.and(list.slice(1));
      case 'or':
        return this.or(list.slice(1));
      case 'cond':
        return this.cond(list.slice(1));
      default:
        return {
          k: 'app',
          operator: this.lower(list[0]!),
          arguments: list.slice(1).map((item) => this.lower(item)),
        };
    }
  }

  private body(forms: readonly Datum[]): Core {
    if (forms.length === 0) throw new Error('body');
    const lowered = forms.map((form) => this.lower(form));
    return lowered.length === 1 ? lowered[0]! : { k: 'begin', forms: lowered };
  }

  private and(forms: readonly Datum[]): Core {
    if (forms.length === 0) return literalCore('#t');
    if (forms.length === 1) return this.lower(forms[0]!);
    return {
      k: 'if',
      test: this.lower(forms[0]!),
      consequent: this.and(forms.slice(1)),
      alternate: literalCore('#f'),
    };
  }

  private or(forms: readonly Datum[]): Core {
    if (forms.length === 0) return literalCore('#f');
    if (forms.length === 1) return this.lower(forms[0]!);
    const name = `#:t${this.nextTemp++}`;
    return {
      k: 'let',
      names: [name],
      initializers: [this.lower(forms[0]!)],
      body: {
        k: 'if',
        test: { k: 'var', name },
        consequent: { k: 'var', name },
        alternate: this.or(forms.slice(1)),
      },
    };
  }

  private cond(clauses: readonly Datum[]): Core {
    if (clauses.length < 2) throw new Error('cond');
    const parsed = clauses.map((clause) => {
      if (!Array.isArray(clause) || clause.length !== 2)
        throw new Error('cond');
      return clause as unknown as readonly [Datum, Datum];
    });
    if (atomText(parsed.at(-1)![0]) !== 'else') throw new Error('cond');
    if (parsed.slice(0, -1).some((clause) => atomText(clause[0]) === 'else'))
      throw new Error('cond');
    let result = this.lower(parsed.at(-1)![1]);
    for (let index = parsed.length - 2; index >= 0; index -= 1) {
      result = {
        k: 'if',
        test: this.lower(parsed[index]![0]),
        consequent: this.lower(parsed[index]![1]),
        alternate: result,
      };
    }
    return result;
  }
}

function parseNormalizedCore(datum: Datum): Core {
  if (!Array.isArray(datum)) {
    const name = atomText(datum);
    if (!name || !identifier(name, true)) throw new Error('core var');
    return { k: 'var', name };
  }
  const list = datum as readonly Datum[];
  if (list.length === 0) throw new Error('core empty');
  const head = atomText(list[0]);
  switch (head) {
    case 'quote':
      if (list.length !== 2) throw new Error('quote');
      return quotedDatum(list[1]!);
    case 'if':
      if (list.length !== 4) throw new Error('if');
      return {
        k: 'if',
        test: parseNormalizedCore(list[1]!),
        consequent: parseNormalizedCore(list[2]!),
        alternate: parseNormalizedCore(list[3]!),
      };
    case 'lambda':
      if (list.length !== 3) throw new Error('lambda');
      return {
        k: 'lambda',
        params: binderList(list[1]!, true),
        body: parseNormalizedCore(list[2]!),
      };
    case 'begin':
      if (list.length < 2) throw new Error('begin');
      return { k: 'begin', forms: list.slice(1).map(parseNormalizedCore) };
    case 'define':
      if (list.length !== 3) throw new Error('define');
      return {
        k: 'define',
        name: binder(list[1]!, true),
        value: parseNormalizedCore(list[2]!),
      };
    case 'let': {
      if (list.length !== 3 || !Array.isArray(list[1])) throw new Error('let');
      const names: string[] = [];
      const initializers: Core[] = [];
      for (const raw of list[1] as readonly Datum[]) {
        if (!Array.isArray(raw) || raw.length !== 2) throw new Error('let');
        names.push(binder(raw[0]!, true));
        initializers.push(parseNormalizedCore(raw[1]!));
      }
      return {
        k: 'let',
        names,
        initializers,
        body: parseNormalizedCore(list[2]!),
      };
    }
    default:
      return {
        k: 'app',
        operator: parseNormalizedCore(list[0]!),
        arguments: list.slice(1).map(parseNormalizedCore),
      };
  }
}

function quotedDatum(datum: Datum): Core {
  if (Array.isArray(datum)) {
    if (datum.length !== 0) throw new Error('literal list');
    return { k: 'quote', text: '()', value: { t: 'nil' } };
  }
  const atom = (datum as { atom: string }).atom;
  if (!isLiteral(atom)) {
    if (!identifier(atom)) throw new Error('literal symbol');
    return { k: 'quote', text: atom, value: { t: 'sym', v: atom } };
  }
  return literalCore(atom);
}

function literalCore(atom: string): Core {
  if (['#t', '#true', '#f', '#false'].includes(atom)) {
    const value = atom === '#t' || atom === '#true';
    return {
      k: 'quote',
      text: value ? '#t' : '#f',
      value: { t: 'bool', v: value },
    };
  }
  if (atom.startsWith('"')) {
    const value = decodeSchemeString(atom);
    return {
      k: 'quote',
      text: renderSchemeString(value),
      value: { t: 'str', v: value },
    };
  }
  if (/^-?(?:0|[1-9][0-9]*)$/.test(atom)) {
    if (atom.replace(/^-/, '').length > 4096) throw new RangeError('integer');
    return { k: 'quote', text: atom, value: { t: 'int', v: atom } };
  }
  const rational = /^(-?(?:0|[1-9][0-9]*))\/([1-9][0-9]*)$/.exec(atom);
  if (rational) {
    if (
      rational[1]!.replace(/^-/, '').length > 4096 ||
      rational[2]!.length > 4096
    )
      throw new RangeError('rational');
    const numerator = BigInt(rational[1]!);
    const denominator = BigInt(rational[2]!);
    const divisor = gcd(numerator, denominator);
    const n = numerator / divisor;
    const d = denominator / divisor;
    if (d === 1n) {
      const text = n.toString();
      return { k: 'quote', text, value: { t: 'int', v: text } };
    }
    return {
      k: 'quote',
      text: `${n}/${d}`,
      value: { t: 'rat', n: n.toString(), d: d.toString() },
    };
  }
  if (/^-?(?:[0-9]+\.[0-9]+|[0-9]+(?:e[+-]?[0-9]+))$/i.test(atom)) {
    const text = formatReal(Number(atom));
    if (!Number.isFinite(Number(atom))) throw new Error('real');
    return { k: 'quote', text, value: { t: 'real', v: text } };
  }
  throw new Error('literal');
}

function isLiteral(atom: string): boolean {
  return (
    ['#t', '#true', '#f', '#false'].includes(atom) ||
    atom.startsWith('"') ||
    /^-?(?:0|[1-9][0-9]*)(?:\/[1-9][0-9]*|\.[0-9]+|[eE][+-]?[0-9]+)?$/.test(
      atom
    )
  );
}

function renderCore(core: Core): string {
  switch (core.k) {
    case 'quote':
      return `(quote ${core.text})`;
    case 'var':
      return core.name;
    case 'if':
      return `(if ${renderCore(core.test)} ${renderCore(core.consequent)} ${renderCore(core.alternate)})`;
    case 'lambda':
      return `(lambda (${core.params.join(' ')}) ${renderCore(core.body)})`;
    case 'app':
      return `(${[renderCore(core.operator), ...core.arguments.map(renderCore)].join(' ')})`;
    case 'begin':
      return `(begin ${core.forms.map(renderCore).join(' ')})`;
    case 'let':
      return `(let (${core.names.map((name, index) => `(${name} ${renderCore(core.initializers[index]!)})`).join(' ')}) ${renderCore(core.body)})`;
    case 'define':
      return `(define ${core.name} ${renderCore(core.value)})`;
  }
}

function validateCore(core: readonly Core[]): void {
  if (core.length === 0) throw new Error('empty program');
  const top = new Set([...PRIMITIVES, 'input']);
  const definitions = new Set<string>();
  for (const form of core) {
    if (form.k === 'define') {
      if (
        form.name === 'input' ||
        PRIMITIVES.has(form.name) ||
        definitions.has(form.name)
      )
        throw new Error('define');
      validateExpression(form.value, top);
      definitions.add(form.name);
      top.add(form.name);
    } else {
      validateExpression(form, top);
    }
  }
}

function validateExpression(core: Core, scope: ReadonlySet<string>): void {
  switch (core.k) {
    case 'quote':
      return;
    case 'var':
      if (!scope.has(core.name)) throw new Error('unbound');
      return;
    case 'define':
      throw new Error('nested define');
    case 'lambda': {
      uniqueBinders(core.params);
      const child = new Set([...scope, ...core.params]);
      validateExpression(core.body, child);
      return;
    }
    case 'let': {
      uniqueBinders(core.names);
      core.initializers.forEach((item) => validateExpression(item, scope));
      validateExpression(core.body, new Set([...scope, ...core.names]));
      return;
    }
    case 'if':
      validateExpression(core.test, scope);
      validateExpression(core.consequent, scope);
      validateExpression(core.alternate, scope);
      return;
    case 'app':
      validateExpression(core.operator, scope);
      core.arguments.forEach((item) => validateExpression(item, scope));
      return;
    case 'begin':
      if (core.forms.length === 0) throw new Error('begin');
      core.forms.forEach((item) => validateExpression(item, scope));
      return;
  }
}

function uniqueBinders(names: readonly string[]): void {
  if (
    new Set(names).size !== names.length ||
    names.some((name) => name === 'input')
  )
    throw new Error('binder');
}

function lowerGraph(
  core: Core,
  nodes: GraphNode[],
  root: boolean,
  lexical: ReadonlySet<string>
): number {
  if (nodes.length >= 100_000) throw new RangeError('graph');
  const id = nodes.length;
  nodes.push({});
  let node: GraphNode;
  switch (core.k) {
    case 'quote':
      node = { id, op: 'lit', value: core.value };
      break;
    case 'var':
      node =
        PRIMITIVES.has(core.name) && !lexical.has(core.name)
          ? { id, op: 'prim', name: core.name }
          : { id, op: 'var', name: core.name };
      break;
    case 'lambda': {
      const child = new Set(lexical);
      core.params.forEach((name) => child.add(name));
      node = {
        id,
        op: 'lambda',
        params: core.params,
        body: lowerGraph(core.body, nodes, false, child),
      };
      break;
    }
    case 'app':
      node = {
        id,
        op: 'app',
        operator: lowerGraph(core.operator, nodes, false, lexical),
        arguments: core.arguments.map((item) =>
          lowerGraph(item, nodes, false, lexical)
        ),
      };
      break;
    case 'if':
      node = {
        id,
        op: 'if',
        test: lowerGraph(core.test, nodes, false, lexical),
        consequent: lowerGraph(core.consequent, nodes, false, lexical),
        alternate: lowerGraph(core.alternate, nodes, false, lexical),
      };
      break;
    case 'begin':
      node = {
        id,
        op: 'begin',
        forms: core.forms.map((item) =>
          lowerGraph(item, nodes, false, lexical)
        ),
      };
      break;
    case 'let': {
      const child = new Set(lexical);
      core.names.forEach((name) => child.add(name));
      node = {
        id,
        op: 'let',
        names: core.names,
        initializers: core.initializers.map((item) =>
          lowerGraph(item, nodes, false, lexical)
        ),
        body: lowerGraph(core.body, nodes, false, child),
      };
      break;
    }
    case 'define':
      if (!root) throw new Error('nested define');
      node = {
        id,
        op: 'define',
        name: core.name,
        value: lowerGraph(core.value, nodes, false, lexical),
      };
      break;
  }
  nodes[id] = node;
  return id;
}

function binder(value: Datum, temporary = false): string {
  const text = atomText(value);
  if (!text || !identifier(text, temporary)) throw new Error('binder');
  return text;
}

function binderList(value: Datum, temporary = false): string[] {
  if (!Array.isArray(value)) throw new Error('binders');
  return value.map((item) => binder(item, temporary));
}

function atomText(value: Datum): string | undefined {
  return Array.isArray(value) ? undefined : (value as { atom: string }).atom;
}

function identifier(value: string, temporary = false): boolean {
  if (temporary) {
    if (/^#:t(?:0|[1-9][0-9]*)$/.test(value)) return true;
    if (value.startsWith('#:')) return false;
  } else if (value.startsWith('#')) {
    return false;
  }
  return readerSymbol(value);
}

export function readerSymbol(value: string): boolean {
  if (value.length === 0 || value === '.' || value.startsWith('#'))
    return false;
  if (/[\s()[\]{}";'`,]/.test(value)) return false;
  const beginsNumber = /^[0-9]/.test(value) || /^-[0-9]/.test(value);
  return !beginsNumber && !isLiteral(value);
}

function parseDatums(text: string): Datum[] {
  const tokens = tokenize(text);
  let index = 0;
  const read = (): Datum => {
    const token = tokens[index++];
    if (token === undefined) throw new Error('eof');
    if (token === '(') {
      const values: Datum[] = [];
      while (tokens[index] !== ')') {
        if (index >= tokens.length) throw new Error('paren');
        values.push(read());
      }
      index += 1;
      return values;
    }
    if (token === ')') throw new Error('paren');
    return { atom: token };
  };
  const values: Datum[] = [];
  while (index < tokens.length) values.push(read());
  return values;
}

function tokenize(text: string): string[] {
  const tokens: string[] = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index]!;
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === ';') {
      while (index < text.length && text[index] !== '\n') index += 1;
      continue;
    }
    if (char === '#' && text[index + 1] === '|') {
      index += 2;
      let depth = 1;
      while (index < text.length && depth > 0) {
        if (text[index] === '#' && text[index + 1] === '|') {
          depth += 1;
          index += 2;
        } else if (text[index] === '|' && text[index + 1] === '#') {
          depth -= 1;
          index += 2;
        } else index += 1;
      }
      if (depth !== 0) throw new Error('block comment');
      continue;
    }
    if (char === '(' || char === ')') {
      tokens.push(char);
      index += 1;
      continue;
    }
    if (char === "'" || char === '`' || char === ',')
      throw new Error('reader sugar');
    if (char === '"') {
      const start = index++;
      let escaped = false;
      while (index < text.length) {
        const current = text[index++]!;
        if (escaped) escaped = false;
        else if (current === '\\') escaped = true;
        else if (current === '"') break;
      }
      const token = text.slice(start, index);
      if (!token.endsWith('"')) throw new Error('string');
      decodeSchemeString(token);
      tokens.push(token);
      continue;
    }
    const start = index;
    while (index < text.length && !/[\s();]/.test(text[index]!)) index += 1;
    if (start === index) throw new Error('token');
    tokens.push(text.slice(start, index));
  }
  return tokens;
}

function decodeSchemeString(token: string): string {
  let output = '';
  for (let index = 1; index < token.length - 1; index += 1) {
    const char = token[index]!;
    if (char !== '\\') {
      output += char;
      continue;
    }
    const escape = token[++index];
    const mapped: Record<string, string> = {
      n: '\n',
      r: '\r',
      t: '\t',
      '"': '"',
      '\\': '\\',
    };
    if (escape === 'x' || escape === 'X') {
      let hex = '';
      while (index + 1 < token.length - 1 && token[index + 1] !== ';')
        hex += token[++index]!;
      if (token[index + 1] !== ';' || !/^[0-9a-fA-F]+$/.test(hex))
        throw new Error('escape');
      index += 1;
      const scalar = Number.parseInt(hex, 16);
      if (scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff))
        throw new Error('escape');
      output += String.fromCodePoint(scalar);
    } else {
      if (escape === undefined || mapped[escape] === undefined)
        throw new Error('escape');
      output += mapped[escape];
    }
  }
  return output;
}

function renderSchemeString(value: string): string {
  let output = '"';
  for (const scalar of value) {
    if (scalar === '"') output += '\\"';
    else if (scalar === '\\') output += '\\\\';
    else if (scalar === '\n') output += '\\n';
    else if (scalar === '\t') output += '\\t';
    else if (scalar === '\r') output += '\\r';
    else output += scalar;
  }
  return `${output}"`;
}

function gcd(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
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
