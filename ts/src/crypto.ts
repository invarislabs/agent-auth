/**
 * Encodings and cryptographic primitives (protocol §1): base58btc, multibase,
 * Ed25519 multikeys, SHA-256 multihash digests, strict base64url, and
 * signature verification via WebCrypto (Node 20+, browsers, Deno, workers).
 */

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX = new Map([...B58].map((c, i) => [c, i] as const));
const ED25519_PUB = [0xed, 0x01];
const SHA256_MULTIHASH = [0x12, 0x20];

export const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

const enc = new TextEncoder();
export const utf8 = (s: string): Uint8Array => enc.encode(s);

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto (globalThis.crypto.subtle) is required; use Node 20+ or a modern runtime");
  return c.subtle;
}

export function b58encode(data: Uint8Array): string {
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  let pad = 0;
  while (pad < data.length && data[pad] === 0) pad++;
  return "1".repeat(pad) + out;
}

export function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const v = B58_INDEX.get(c);
    if (v === undefined) throw new Error(`invalid base58 character ${JSON.stringify(c)}`);
    n = n * 58n + BigInt(v);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let pad = 0;
  while (pad < s.length && s[pad] === "1") pad++;
  return Uint8Array.from([...new Array(pad).fill(0), ...body]);
}

export function multibaseDecode(s: string): Uint8Array {
  if (typeof s !== "string" || !s.startsWith("z")) throw new Error("only base58btc multibase ('z') is supported");
  return b58decode(s.slice(1));
}

export const multibaseEncode = (data: Uint8Array): string => "z" + b58encode(data);

// --- base64 / base64url ---------------------------------------------------- //

export function b64encode(data: Uint8Array): string {
  let bin = "";
  for (const b of data) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export const b64u = (data: Uint8Array): string => b64encode(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * Strict, canonical base64url (no padding, no stray characters, zero unused bits).
 * Only the one encoding `b64u` produces is accepted, so a signature has exactly one spelling.
 */
export function b64uDecode(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new Error("not canonical unpadded base64url");
  }
  const std = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const out = b64decode(std);
  if (b64u(out) !== s) throw new Error("not canonical unpadded base64url");
  return out;
}

// --- keys, digests, signatures --------------------------------------------- //

export function publicKeyToMultikey(raw: Uint8Array): string {
  if (raw.length !== 32) throw new Error("Ed25519 public keys are 32 bytes");
  return multibaseEncode(Uint8Array.from([...ED25519_PUB, ...raw]));
}

export function multikeyToPublicKey(multikey: unknown): Uint8Array {
  if (typeof multikey !== "string" || multikey.length > 64) throw new Error("not an Ed25519 multikey");
  const data = multibaseDecode(multikey);
  if (data.length !== 34 || data[0] !== ED25519_PUB[0] || data[1] !== ED25519_PUB[1]) {
    throw new Error("not an Ed25519 multikey");
  }
  return data.slice(2);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));
}

/** Self-describing SHA-256 digest: multibase(multihash(sha256(data))). */
export async function digest(data: Uint8Array): Promise<string> {
  return multibaseEncode(Uint8Array.from([...SHA256_MULTIHASH, ...(await sha256(data))]));
}

/** Is `value` a well-formed `digest()` string? */
export function isDigest(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("z") || value.length > 64) return false;
  try {
    const raw = multibaseDecode(value);
    return raw.length === 34 && raw[0] === SHA256_MULTIHASH[0] && raw[1] === SHA256_MULTIHASH[1];
  } catch {
    return false;
  }
}

/** Pre-rotation commitment: the digest of the next key's multikey string. */
export const keyCommitment = (multikey: string): Promise<string> => digest(utf8(multikey));

const keyCache = new Map<string, Promise<CryptoKey>>();

function importKey(multikey: string): Promise<CryptoKey> {
  let k = keyCache.get(multikey);
  if (!k) {
    k = subtle().importKey("raw", multikeyToPublicKey(multikey) as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    k.catch(() => keyCache.delete(multikey));
    if (keyCache.size > 10_000) keyCache.clear();
    keyCache.set(multikey, k);
  }
  return k;
}

/** Verify an Ed25519 signature. Never throws: anything malformed is simply invalid. */
export async function verify(multikey: unknown, message: Uint8Array, signatureB64u: unknown): Promise<boolean> {
  try {
    if (typeof multikey !== "string" || typeof signatureB64u !== "string") return false;
    const sig = b64uDecode(signatureB64u);
    if (sig.length !== 64) return false;
    return await subtle().verify({ name: "Ed25519" }, await importKey(multikey), sig as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}
