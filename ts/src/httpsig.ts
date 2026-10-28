/**
 * AgentSig request authentication (protocol §3): strict header parsing, the
 * signing string, and a verifier with audience binding, a timestamp window and
 * replay protection. A port of `agentauth.httpsig`, check for check.
 */

import { digest, utf8, verify } from "./crypto.js";
import { AuthError } from "./errors.js";
import { isAgentDid } from "./identity.js";
import { SPACE_RE_CLASS, asciiLower } from "./pystr.js";

export const SCHEME = "AgentSig";
export const DEFAULT_MAX_SKEW = 120;
export const MAX_HEADER_BYTES = 4096;
export const REQUIRED_PARAMS = ["did", "kid", "aud", "ts", "nonce", "sig"] as const;

const PARAM_RE = new RegExp(`[${SPACE_RE_CLASS}]*([A-Za-z0-9_]+)="([^"]*)"[${SPACE_RE_CLASS}]*(?:,|$)`, "uy");
const TS_RE = /^[0-9]{1,15}$/;
const NONCE_RE = /^[A-Za-z0-9_\-.~+/=]{16,128}$/;
const KID_RE = /^([^\n]+)#key-(0|[1-9][0-9]{0,8})$/u; // Python's "." excludes only "\n"
const AUD_RE = /^[\x21\x23-\x2b\x2d-\x7e]{1,255}$/;

export type AgentSigParams = Record<(typeof REQUIRED_PARAMS)[number], string> & Record<string, string>;

/** Python's `str.upper()` and JavaScript's `toUpperCase()` agree on everything an HTTP method can contain. */
export async function signingString(
  method: string, audience: string, path: string, ts: string, nonce: string, body: Uint8Array, grants = "",
): Promise<Uint8Array> {
  return utf8(
    [
      "agentauth-request/1",
      method.toUpperCase(),
      audience.toLowerCase(),
      path,
      ts,
      nonce,
      await digest(body),
      await digest(utf8(grants)),
    ].join("\n"),
  );
}

/** Strictly parse an AgentSig header. Duplicate or malformed parameters are rejected. */
export function parseAuthorization(header: unknown): AgentSigParams {
  if (typeof header !== "string" || !header.startsWith(SCHEME + " ")) {
    throw new AuthError(`missing or non-${SCHEME} Authorization header`);
  }
  if (utf8Length(header) > MAX_HEADER_BYTES) throw new AuthError("Authorization header too large");
  const rest = header.slice(SCHEME.length + 1);
  const params: Record<string, string> = Object.create(null);
  let pos = 0;
  while (pos < rest.length) {
    PARAM_RE.lastIndex = pos;
    const m = PARAM_RE.exec(rest);
    if (!m || PARAM_RE.lastIndex === pos) throw new AuthError("malformed Authorization header");
    const k = m[1]!;
    if (k in params) throw new AuthError(`duplicate Authorization parameter '${k}'`);
    params[k] = m[2]!;
    pos = PARAM_RE.lastIndex;
  }
  const missing = REQUIRED_PARAMS.filter((p) => !(p in params));
  if (missing.length) throw new AuthError(`Authorization header missing: ${missing.sort().join(", ")}`);
  return params as AgentSigParams;
}

/** UTF-8 length, counting a lone surrogate as 3 bytes (Python's "surrogatepass"). */
function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

export function kidSeq(kid: unknown): number {
  const m = typeof kid === "string" ? KID_RE.exec(kid) : null;
  return m ? Number(m[2]) : -1;
}

export function kidDid(kid: string): string | null {
  const m = KID_RE.exec(kid);
  return m ? m[1]! : null;
}

// --- replay protection ------------------------------------------------------ //

/**
 * Must be atomic across every process verifying requests for the same audiences:
 * true the first time (did, nonce) is seen within the window, false afterwards.
 * Throw when unsure; the request is then refused with 503.
 */
export interface ReplayCache {
  readonly ttl?: number;
  checkAndStore(did: string, nonce: string): boolean | Promise<boolean>;
}

/** In-memory, single-process replay cache. Use a shared store (e.g. Redis SET NX EX) with several replicas. */
export class MemoryNonceCache implements ReplayCache {
  private seen = new Map<string, number>(); // insertion order = expiry order (one shared TTL)
  private perDid = new Map<string, number>();

  constructor(
    readonly ttl: number,
    private readonly maxEntries = 1_000_000,
    private readonly maxPerDid = 100_000,
    private readonly clock: () => number = () => Date.now() / 1000,
  ) {}

  private prune(now: number): void {
    for (const [k, exp] of this.seen) {
      if (exp > now) break;
      this.seen.delete(k);
      const did = k.slice(0, k.indexOf("\n"));
      const left = (this.perDid.get(did) ?? 1) - 1;
      if (left) this.perDid.set(did, left);
      else this.perDid.delete(did);
    }
  }

  checkAndStore(did: string, nonce: string): boolean {
    const now = this.clock();
    this.prune(now);
    const key = `${did}\n${nonce}`;
    if (this.seen.has(key)) return false;
    if (this.seen.size >= this.maxEntries) throw new Error("replay cache is full");
    if ((this.perDid.get(did) ?? 0) >= this.maxPerDid) throw new Error("too many requests from this agent inside the replay window");
    this.seen.set(key, now + this.ttl);
    this.perDid.set(did, (this.perDid.get(did) ?? 0) + 1);
    return true;
  }
}

// --- verification ------------------------------------------------------------ //

/** did -> [current multikey, current key id], or null if unknown or deactivated. */
export interface KeyResolver {
  (did: string): Promise<readonly [string, string] | null> | readonly [string, string] | null;
  /** Optional: drop any cached entry (called once when a request claims a newer key). */
  invalidate?: (did: string) => void;
}

export async function resolveOrFail<E extends Error>(
  resolve: KeyResolver, did: string, makeError: (msg: string, status: number) => E, errorType: new (...a: never[]) => E,
): Promise<readonly [string, string] | null> {
  try {
    return await resolve(did);
  } catch (e) {
    if (e instanceof errorType) throw e;
    throw makeError(`could not resolve ${did}: ${(e as Error)?.message ?? String(e)}`, 503);
  }
}

export interface VerifiedAgent {
  did: string;
  kid: string;
  key: string;
  audience: string;
}

export interface RequestVerifierOptions {
  audiences: Iterable<string>;
  maxSkew?: number;
  nonceCache?: ReplayCache;
  /** Require the signed audience to equal the Host header the request arrived with. */
  bindHost?: boolean;
  /** Seconds since the epoch; defaults to the system clock. */
  clock?: () => number;
}

export interface RequestToVerify {
  authorization: string | null | undefined;
  method: string;
  /** The raw request target (path + query), exactly as sent, percent-encoding intact. */
  path: string;
  body?: Uint8Array;
  /** The AgentGrant header value, or "" when absent. */
  grants?: string;
  host?: string | null;
}

export class RequestVerifier {
  readonly audiences: Set<string>;
  readonly maxSkew: number;
  readonly minNonceTtl: number;
  readonly nonces: ReplayCache;
  readonly bindHost: boolean;
  private readonly clock: () => number;

  constructor(private readonly resolveKey: KeyResolver, opts: RequestVerifierOptions) {
    this.audiences = new Set([...opts.audiences].map((a) => a.toLowerCase()));
    if (!this.audiences.size) throw new Error("RequestVerifier needs at least one audience");
    this.maxSkew = opts.maxSkew ?? DEFAULT_MAX_SKEW;
    if (!(this.maxSkew > 0 && this.maxSkew <= 3600)) throw new Error("maxSkew must be between 1 and 3600 seconds");
    this.minNonceTtl = 2 * this.maxSkew + 1;
    this.clock = opts.clock ?? (() => Date.now() / 1000);
    this.nonces = opts.nonceCache ?? new MemoryNonceCache(this.minNonceTtl, undefined, undefined, this.clock);
    if (typeof this.nonces.ttl === "number" && this.nonces.ttl < this.minNonceTtl) {
      throw new Error(`replay cache ttl (${this.nonces.ttl}s) is shorter than the replay window (${this.minNonceTtl}s)`);
    }
    this.bindHost = opts.bindHost ?? false;
  }

  async verify(req: RequestToVerify): Promise<VerifiedAgent> {
    const p = parseAuthorization(req.authorization);
    if (!AUD_RE.test(p.aud) || !this.audiences.has(asciiLower(p.aud))) {
      throw new AuthError(`request was signed for a different audience (${p.aud.slice(0, 100)})`);
    }
    if (this.bindHost && (req.host == null || asciiLower(req.host) !== asciiLower(p.aud))) {
      throw new AuthError("request was signed for a different host than the one it was sent to");
    }
    if (!TS_RE.test(p.ts)) throw new AuthError("ts must be an integer number of seconds");
    if (Math.abs(this.clock() - Number(p.ts)) > this.maxSkew) throw new AuthError("request timestamp outside allowed window");
    if (!NONCE_RE.test(p.nonce)) throw new AuthError("nonce must be 16-128 URL-safe characters");
    if (!isAgentDid(p.did)) throw new AuthError("did is not a did:agent identifier");
    if (kidDid(p.kid) !== p.did) throw new AuthError("kid must be '<did>#key-<n>'");

    const fail = (msg: string, status: number) => new AuthError(msg, status);
    let resolved = await resolveOrFail(this.resolveKey, p.did, fail, AuthError);
    if (resolved === null) throw new AuthError("unknown or deactivated agent");
    if (p.kid !== resolved[1] && kidSeq(p.kid) > kidSeq(resolved[1]) && this.resolveKey.invalidate) {
      // The caller claims a newer key than the cache holds: it probably just rotated.
      this.resolveKey.invalidate(p.did);
      resolved = await resolveOrFail(this.resolveKey, p.did, fail, AuthError);
      if (resolved === null) throw new AuthError("unknown or deactivated agent");
    }
    const [key, kid] = resolved;
    if (p.kid !== kid) throw new AuthError("signed with a key that is not the agent's current key");

    const msg = await signingString(req.method, p.aud, req.path, p.ts, p.nonce, req.body ?? new Uint8Array(), req.grants ?? "");
    if (!(await verify(key, msg, p.sig))) throw new AuthError("bad request signature");
    // Only burn the nonce once the signature checks out, so garbage can't fill the cache.
    let fresh: boolean;
    try {
      fresh = await this.nonces.checkAndStore(p.did, p.nonce);
    } catch {
      throw new AuthError("replay protection unavailable", 503);
    }
    if (!fresh) throw new AuthError("replayed request (nonce already used)");
    return { did: p.did, kid, key, audience: asciiLower(p.aud) };
  }
}
