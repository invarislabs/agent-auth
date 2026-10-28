/**
 * Strict JSON parsing and canonical serialization.
 *
 * `JSON.parse` can't be used for anything that gets verified: it turns `1.0`
 * into the integer 1 and silently loses precision above 2^53, so a verifier
 * built on it would accept payloads the protocol forbids (floats are never
 * allowed in signed data). This parser keeps every number's lexical type:
 *
 * - integers that fit in a double exactly -> `number`
 * - larger integers -> `bigint`
 * - anything with a fraction or exponent -> `JsonFloat`
 *
 * Canonical JSON (protocol §1.4) matches the Python reference byte for byte:
 * keys sorted by Unicode code point, no whitespace, UTF-8, non-ASCII emitted
 * as-is, floats and lone surrogates rejected.
 */

export class JsonFloat {
  constructor(readonly text: string) {}
}

export type JsonValue = null | boolean | number | bigint | string | JsonFloat | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

const MAX_DEPTH = 512;

export class JsonParseError extends Error {}

export interface ParseOptions {
  /** Refuse objects with a repeated key (otherwise the last one wins, as in Python's json module). */
  rejectDuplicateKeys?: boolean;
}

export function parseJson(text: string, opts: ParseOptions = {}): JsonValue {
  let i = 0;
  const n = text.length;

  const fail = (msg: string): never => {
    throw new JsonParseError(`${msg} at position ${i}`);
  };
  const ws = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = (): string => {
    // text[i] === '"'
    i++;
    let out = "";
    let start = i;
    while (true) {
      if (i >= n) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) fail("control character in string");
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default:
            fail("bad escape");
        }
        start = i;
        continue;
      }
      i++;
    }
  };

  const NUM = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
  const parseNumber = (): number | bigint | JsonFloat => {
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) return fail("bad number");
    i = NUM.lastIndex;
    const lit = m[0];
    if (m[1] !== undefined || m[2] !== undefined) return new JsonFloat(lit);
    const big = BigInt(lit);
    return big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(lit) : big;
  };

  const parseValue = (depth: number): JsonValue => {
    if (depth > MAX_DEPTH) fail("nested too deeply");
    ws();
    if (i >= n) fail("unexpected end of input");
    const c = text[i];
    if (c === "{") {
      i++;
      const obj: JsonObject = Object.create(null);
      ws();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      while (true) {
        ws();
        if (text[i] !== '"') fail("expected string key");
        const k = parseString();
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        if (opts.rejectDuplicateKeys && Object.prototype.hasOwnProperty.call(obj, k)) fail(`duplicate key ${JSON.stringify(k)}`);
        obj[k] = parseValue(depth + 1); // duplicate keys: last one wins (as in Python's json module)
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const arr: JsonValue[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return arr;
      }
      while (true) {
        arr.push(parseValue(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return arr;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return parseString();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return parseNumber();
    return fail("unexpected character");
  };

  const v = parseValue(0);
  ws();
  if (i !== n) fail("trailing data");
  return v;
}

export class CanonicalizationError extends Error {}

function hasLoneSurrogate(s: string): boolean {
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(k + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return true;
      k++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Compare strings by Unicode code point (Python's ordering), not UTF-16 code unit. */
export function compareCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  while (true) {
    const x = ia.next();
    const y = ib.next();
    if (x.done) return y.done ? 0 : -1;
    if (y.done) return 1;
    const cx = x.value.codePointAt(0)!;
    const cy = y.value.codePointAt(0)!;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
}

function encodeString(s: string): string {
  if (hasLoneSurrogate(s)) throw new CanonicalizationError("strings in signed payloads must be valid Unicode");
  // For well-formed strings JSON.stringify escapes exactly what Python's json.dumps(ensure_ascii=False) does.
  return JSON.stringify(s);
}

function serialize(v: unknown): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return encodeString(v);
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new CanonicalizationError("floats are not allowed in signed payloads");
    if (!Number.isSafeInteger(v)) throw new CanonicalizationError("integer outside the safe range; pass a bigint");
    return String(v);
  }
  if (v instanceof JsonFloat) throw new CanonicalizationError("floats are not allowed in signed payloads");
  if (Array.isArray(v)) return "[" + v.map(serialize).join(",") + "]";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort(compareCodePoints);
    return "{" + keys.map((k) => encodeString(k) + ":" + serialize(o[k])).join(",") + "}";
  }
  throw new CanonicalizationError(`cannot canonicalize ${typeof v}`);
}

export function canonicalJson(v: unknown): Uint8Array {
  return new TextEncoder().encode(serialize(v));
}

// --- small type guards over parsed JSON ------------------------------------ //

export function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof JsonFloat);
}

/** A JSON integer (never a boolean, never a float). Large integers come back as bigint. */
export function isInt(v: unknown): v is number | bigint {
  return (typeof v === "number" && Number.isInteger(v)) || typeof v === "bigint";
}

export function intInRange(v: unknown, lo: number, hi: number): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi;
}
