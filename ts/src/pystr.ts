/**
 * The few Python string semantics the verifier depends on, reproduced exactly so
 * both implementations accept the same inputs. (JavaScript's `\s` and `trim()`
 * differ from Python's `str.isspace()` and `str.strip()`: JavaScript treats
 * U+FEFF as whitespace and U+001C-U+001F and U+0085 as not.)
 */

const SPACE_CLASS = "\\t\\n\\v\\f\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const SPACE = new RegExp(`^[${SPACE_CLASS}]$`, "u");
const LEADING = new RegExp(`^[${SPACE_CLASS}]+`, "u");
const TRAILING = new RegExp(`[${SPACE_CLASS}]+$`, "u");

/** Python `c.isspace()` for a single code point. */
export const isSpace = (c: string): boolean => SPACE.test(c);

/** Python `s.strip()`. */
export const strip = (s: string): string => s.replace(LEADING, "").replace(TRAILING, "");

/** The regex character class body for Python's `\s` (for building patterns). */
export const SPACE_RE_CLASS = SPACE_CLASS;

/** C0 controls, DEL and C1 controls. */
export function isControl(c: string): boolean {
  const o = c.codePointAt(0)!;
  return o < 0x20 || (o >= 0x7f && o <= 0x9f);
}

/** Python `len(s)`: code points, not UTF-16 code units. */
export function codePointLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** ASCII-only lower-casing (the protocol never case-folds anything else). */
export const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
