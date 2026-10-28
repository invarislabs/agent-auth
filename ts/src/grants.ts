/**
 * AgentGrant delegation chains (protocol §4) and revocations (§6): decoding with
 * a canonical-payload requirement, structural checks, attenuation, limits
 * narrowing, signatures against each issuer's current key, the relying party's
 * root policy and revocation status. A port of `agentauth.grants`.
 */

import { b64uDecode, MAX_SAFE_INT, verify } from "./crypto.js";
import { GrantError, LimitError } from "./errors.js";
import { kidSeq, resolveOrFail, type KeyResolver } from "./httpsig.js";
import { isAgentDid, shapeOk } from "./identity.js";
import { CanonicalizationError, canonicalJson, isObject, parseJson, type JsonObject } from "./json.js";
import { Limits } from "./limits.js";
import { asciiLower, codePointLength, strip } from "./pystr.js";

export const VERSION = "agentauth-grant/1";
export const REVOCATION_VERSION = "agentauth-revocation/1";
export const HEADER = "AgentGrant";
export const MAX_TTL = 24 * 60 * 60;
export const MAX_CHAIN = 8;
export const CLOCK_SKEW = 60;
export const MAX_HEADER_BYTES = 32 * 1024;
export const MAX_SCOPES = 64;
export const MAX_AUDIENCES = 32;
export const MAX_GRANT_DEPTH = 8;

const GRANT_FIELDS = ["v", "id", "iss", "kid", "sub", "scope", "aud", "nbf", "exp", "depth", "parent"];
const OPTIONAL_GRANT_FIELDS = ["limits"];
const REVOCATION_FIELDS = ["v", "grant", "iss", "ts"];
const ID_RE = /^[A-Za-z0-9_\-.:]{1,128}$/;
const AUD_RE = /^[\x21\x23-\x2b\x2d-\x7e]{1,255}$/;
const SCOPE_CHARS_RE = /^[\x21-\x7e]{1,128}$/;

const decoder = new TextDecoder("utf-8", { fatal: true });
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isPlainInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const byCodeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0); // == code point order for ASCII

// --- scopes and audiences ---------------------------------------------------- //

function validScope(s: unknown): s is string {
  if (typeof s !== "string" || !SCOPE_CHARS_RE.test(s)) return false;
  return s === "*" || (!s.slice(0, -1).includes("*") && (!s.endsWith("*") || s.endsWith(".*")));
}

/** Does `parent` include everything `child` allows? */
export function scopeCovers(parent: string, child: string): boolean {
  if (parent === "*" || parent === child) return true;
  if (parent.endsWith(".*")) {
    const prefix = parent.slice(0, -1); // keep the trailing dot
    return child.startsWith(prefix) && child !== prefix;
  }
  return false;
}

export const scopesCover = (parents: Iterable<string>, children: Iterable<string>): boolean => {
  const ps = [...parents];
  return [...children].every((c) => ps.some((p) => scopeCovers(p, c)));
};

const validAudience = (a: unknown): a is string => typeof a === "string" && AUD_RE.test(a);

export function audienceCovers(parents: Iterable<string>, children: Iterable<string>): boolean {
  const ps = new Set([...parents].map(asciiLower));
  return ps.has("*") || [...children].every((c) => ps.has(asciiLower(c)));
}

// --- grants ------------------------------------------------------------------- //

export class Grant {
  constructor(readonly body: JsonObject, readonly sig: string) {}

  get id(): string { return this.body["id"] as string; }
  get iss(): string { return this.body["iss"] as string; }
  get sub(): string { return this.body["sub"] as string; }
  get scopes(): string[] { return this.body["scope"] as string[]; }
  get aud(): string[] { return this.body["aud"] as string[]; }
  get nbf(): number { return this.body["nbf"] as number; }
  get exp(): number { return this.body["exp"] as number; }
  get depth(): number { return this.body["depth"] as number; }
  get parent(): string | null { return this.body["parent"] as string | null; }
  get limits(): Limits { return Limits.fromDict(this.body["limits"]); }

  /**
   * Parse one link. The payload must be exactly canonicalJson(body): no duplicate
   * keys, no floats, no alternative encodings different parsers could read differently.
   */
  static decode(token: string): Grant {
    const parts = strip(token).split(".");
    if (parts.length !== 2) throw new GrantError("malformed grant", 400);
    const [b, s] = parts as [string, string];
    let raw: Uint8Array;
    let body: unknown;
    try {
      raw = b64uDecode(b);
      body = parseJson(decoder.decode(raw), { rejectDuplicateKeys: true });
    } catch {
      throw new GrantError("malformed grant", 400);
    }
    if (!isObject(body) || !shapeOk(body, MAX_GRANT_DEPTH)) throw new GrantError("malformed grant", 400);
    let canonical: Uint8Array;
    try {
      canonical = canonicalJson(body);
    } catch {
      throw new GrantError("malformed grant: not canonical JSON (floats are not allowed)", 400);
    }
    if (!bytesEqual(canonical, raw)) throw new GrantError("malformed grant: payload is not canonical JSON", 400);
    return new Grant(body, s);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class GrantChain {
  constructor(readonly links: Grant[]) {}
  get root(): Grant { return this.links[0]!; }
  get leaf(): Grant { return this.links[this.links.length - 1]!; }

  static decode(header: string | null | undefined): GrantChain {
    const h = header ?? "";
    if (h && codePointLength(h) > MAX_HEADER_BYTES) throw new GrantError(`${HEADER} header larger than ${MAX_HEADER_BYTES} bytes`, 400);
    const parts = h.split(",").filter((p) => strip(p));
    if (!parts.length) throw new GrantError("no grant presented", 401);
    if (parts.length > MAX_CHAIN) throw new GrantError(`delegation chain longer than ${MAX_CHAIN}`);
    return new GrantChain(parts.map((p) => Grant.decode(p)));
  }
}

/** Structural validation of one grant body. Unknown fields are rejected (fail closed). */
export function checkGrantBody(b: JsonObject, i = 0): void {
  if (b["v"] !== VERSION) throw new GrantError(`link ${i}: unsupported grant version`);
  const keys = Object.keys(b);
  const unknown = keys.filter((k) => !GRANT_FIELDS.includes(k) && !OPTIONAL_GRANT_FIELDS.includes(k));
  if (!GRANT_FIELDS.every((f) => has(b, f)) || unknown.length) {
    throw new GrantError(`link ${i}: missing or unknown fields` + (unknown.length ? ` (${unknown.sort().join(", ")})` : ""));
  }
  for (const k of ["id", "iss", "kid", "sub"]) if (typeof b[k] !== "string") throw new GrantError(`link ${i}: missing or bad field '${k}'`);
  for (const k of ["scope", "aud"]) if (!Array.isArray(b[k])) throw new GrantError(`link ${i}: missing or bad field '${k}'`);
  for (const k of ["nbf", "exp", "depth"]) if (!isPlainInt(b[k])) throw new GrantError(`link ${i}: missing or bad field '${k}'`);
  const id = b["id"] as string, iss = b["iss"] as string, kid = b["kid"] as string, sub = b["sub"] as string;
  const scope = b["scope"] as unknown[], aud = b["aud"] as unknown[];
  if (!ID_RE.test(id)) throw new GrantError(`link ${i}: bad grant id`);
  if (!isAgentDid(iss) || !isAgentDid(sub)) throw new GrantError(`link ${i}: iss and sub must be did:agent identifiers`);
  if (!kid.startsWith(iss + "#key-") || kidSeq(kid) < 0) throw new GrantError(`link ${i}: kid does not belong to the issuer`);
  if (!scope.length || scope.length > MAX_SCOPES || !scope.every(validScope)) throw new GrantError(`link ${i}: invalid scope`);
  if (!aud.length || aud.length > MAX_AUDIENCES || !aud.every(validAudience)) throw new GrantError(`link ${i}: invalid audience`);
  const wantAud = [...new Set((aud as string[]).map(asciiLower))].sort(byCodeUnit);
  const wantScope = [...new Set(scope as string[])].sort(byCodeUnit);
  if (!arraysEqual(aud as string[], wantAud) || !arraysEqual(scope as string[], wantScope)) {
    throw new GrantError(`link ${i}: aud must be lower-case, and aud and scope sorted without duplicates`);
  }
  const nbf = b["nbf"] as number, exp = b["exp"] as number, depth = b["depth"] as number;
  if (!(nbf >= 0 && nbf <= MAX_SAFE_INT && exp >= 0 && exp <= MAX_SAFE_INT)) throw new GrantError(`link ${i}: nbf/exp out of range`);
  if (!(depth >= 0 && depth <= MAX_SAFE_INT)) throw new GrantError(`link ${i}: depth out of range`);
  const parent = b["parent"];
  if (parent !== null && !(typeof parent === "string" && ID_RE.test(parent))) throw new GrantError(`link ${i}: bad parent id`);
  if (has(b, "limits") && !isObject(b["limits"])) throw new GrantError(`link ${i}: limits must be an object`);
}

const arraysEqual = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

// --- verification ---------------------------------------------------------------- //

/** (principal DID, audience) -> scopes that principal may grant here, or null if untrusted. */
export type RootPolicy = (did: string, audience: string) => Iterable<string> | null | undefined | Promise<Iterable<string> | null | undefined>;
/** [[issuer, grant id], ...] -> the pairs that are revoked. */
export type RevocationCheck = (pairs: Array<[string, string]>) => Iterable<[string, string]> | Promise<Iterable<[string, string]>>;

export const trustPrincipals = (policy: Record<string, string[]>): RootPolicy => (did) =>
  Object.prototype.hasOwnProperty.call(policy, did) ? policy[did] : null;

export interface AuthorizedAgent {
  did: string;
  /** The root issuer (human or organisation) the authority traces back to. */
  principal: string;
  /** Effective scopes: the leaf grant's. */
  scopes: string[];
  chain: GrantChain;
  /** DIDs from principal to agent, e.g. [human, agent, sub-agent]. */
  via: string[];
  grantIds: string[];
  /** The leaf grant's limits object as issued (already includes everything inherited), or null. */
  limits: JsonObject | null;
  /** Every link's parsed limits, root to leaf. A service must enforce all of them. */
  linkLimits: Array<{ iss: string; id: string; limits: Limits; exp: number }>;
  allows(scope: string): boolean;
}

export interface GrantVerifierOptions {
  rootPolicy: RootPolicy;
  /** Omit only if you accept that revoked grants stay valid until they expire. */
  revoked?: RevocationCheck;
  maxChain?: number;
}

export class GrantVerifier {
  private readonly rootPolicy: RootPolicy;
  private readonly revoked: RevocationCheck;
  private readonly maxChain: number;

  constructor(private readonly resolveKey: KeyResolver, opts: GrantVerifierOptions) {
    if (!opts.revoked) console.warn("agentauth: GrantVerifier without a revocation check accepts revoked grants");
    this.rootPolicy = opts.rootPolicy;
    this.revoked = opts.revoked ?? (() => []);
    this.maxChain = Math.min(opts.maxChain ?? MAX_CHAIN, MAX_CHAIN);
  }

  private async issuerKey(did: string, kid: string): Promise<string> {
    const fail = (msg: string, status: number) => new GrantError(msg.replace("could not resolve", "could not resolve grant issuer"), status);
    let found = await resolveOrFail(this.resolveKey, did, fail, GrantError);
    if (found && kidSeq(kid) > kidSeq(found[1]) && this.resolveKey.invalidate) {
      this.resolveKey.invalidate(did);
      found = await resolveOrFail(this.resolveKey, did, fail, GrantError);
    }
    if (found === null) throw new GrantError(`grant issuer ${did} is unknown or deactivated`);
    const [key, currentKid] = found;
    if (kid !== currentKid) throw new GrantError(`grant was signed with a key ${did} no longer uses; re-issue it`);
    return key;
  }

  async verify(header: string | null | undefined, { requester, audience, now }: { requester: string; audience: string; now?: number }): Promise<AuthorizedAgent> {
    const chain = GrantChain.decode(header);
    if (chain.links.length > this.maxChain) throw new GrantError(`delegation chain longer than ${this.maxChain}`);
    const t = Math.trunc(now ?? Date.now() / 1000);
    const aud = asciiLower(audience);

    let prev: Grant | null = null;
    let prevLimits = new Limits();
    const linkLimits: AuthorizedAgent["linkLimits"] = [];
    const seen = new Set<string>();
    for (const [i, g] of chain.links.entries()) {
      const b = g.body;
      checkGrantBody(b, i);
      const pairKey = `${g.iss}\n${g.id}`;
      if (seen.has(pairKey)) throw new GrantError(`link ${i}: grant appears twice in the chain`);
      seen.add(pairKey);
      if (g.iss === g.sub) throw new GrantError(`link ${i}: a grant cannot be issued to its own issuer`);
      if (!(g.nbf - CLOCK_SKEW <= t && t < g.exp + CLOCK_SKEW) || !(g.exp - g.nbf > 0 && g.exp - g.nbf <= MAX_TTL)) {
        throw new GrantError(`link ${i}: grant expired or not yet valid`);
      }
      if (!audienceCovers(g.aud, [aud])) throw new GrantError(`link ${i}: grant is not valid for audience ${aud}`);
      let lim: Limits;
      try {
        lim = g.limits;
      } catch (e) {
        if (e instanceof LimitError) throw new GrantError(`link ${i}: ${e.message}`);
        throw e;
      }
      if (lim.stateful && g.aud.includes("*")) throw new GrantError(`link ${i}: budget, rate and use limits can't apply to audience '*'`);

      if (prev === null) {
        if (g.parent !== null) throw new GrantError("chain is missing its root grant");
      } else {
        if (g.parent !== prev.id || g.iss !== prev.sub) throw new GrantError(`link ${i}: does not chain to its parent`);
        if (prev.depth < 1 || g.depth > prev.depth - 1) throw new GrantError(`link ${i}: delegation depth exceeded`);
        if (!scopesCover(prev.scopes, g.scopes) || !audienceCovers(prev.aud, g.aud)) throw new GrantError(`link ${i}: widens its parent's authority`);
        if (g.nbf < prev.nbf || g.exp > prev.exp) throw new GrantError(`link ${i}: outlives its parent`);
        const why = prevLimits.narrowingViolation(lim);
        if (why) throw new GrantError(`link ${i}: loosens its parent's limits (${why})`);
      }

      const key = await this.issuerKey(g.iss, b["kid"] as string);
      let msg: Uint8Array;
      try {
        msg = canonicalJson(b);
      } catch (e) {
        if (e instanceof CanonicalizationError) throw new GrantError(`link ${i}: grant is not canonicalizable`);
        throw e;
      }
      if (!(await verify(key, msg, g.sig))) throw new GrantError(`link ${i}: bad signature`);
      prev = g;
      prevLimits = lim;
      linkLimits.push({ iss: g.iss, id: g.id, limits: lim, exp: g.exp + CLOCK_SKEW });
    }

    if (chain.leaf.sub !== requester) throw new GrantError("grant was issued to a different agent");

    let allowed: Iterable<string> | null | undefined;
    try {
      allowed = await this.rootPolicy(chain.root.iss, aud);
    } catch {
      throw new GrantError("root policy unavailable", 503);
    }
    if (allowed == null) throw new GrantError("root issuer is not a principal this service trusts");
    if (!scopesCover(allowed, chain.root.scopes)) throw new GrantError("root grant exceeds what its principal may authorize here");

    let revoked: Array<[string, string]>;
    try {
      revoked = [...(await this.revoked(chain.links.map((g) => [g.iss, g.id] as [string, string])))];
    } catch {
      throw new GrantError("revocation status unavailable", 503);
    }
    if (revoked.length) throw new GrantError("a grant in the chain has been revoked");

    const scopes = chain.leaf.scopes;
    return {
      did: requester,
      principal: chain.root.iss,
      scopes,
      chain,
      via: [chain.root.iss, ...chain.links.map((g) => g.sub)],
      grantIds: chain.links.map((g) => g.id),
      limits: (chain.leaf.body["limits"] as JsonObject | undefined) ?? null,
      linkLimits,
      allows: (s: string) => scopes.some((p) => scopeCovers(p, s)),
    };
  }
}

/**
 * Stateless per-call checks against every link (resources, per-call spend).
 * Stateful limits (totals, rates, uses) need a ledger shared by every replica of
 * the service: check `link.limits.stateful` and charge them atomically yourself.
 */
export function checkCall(authz: AuthorizedAgent, call: { resource?: string | null; amount?: number; unit?: string | null }): void {
  const amount = call.amount ?? 0;
  if (!Number.isInteger(amount) || amount < 0 || amount > MAX_SAFE_INT) throw new GrantError("amount must be a non-negative integer", 400);
  try {
    for (const l of authz.linkLimits) l.limits.checkCall({ ...call, amount });
  } catch (e) {
    if (e instanceof LimitError) throw new GrantError(e.message, e.status);
    throw e;
  }
}

// --- revocations ----------------------------------------------------------------- //

/** Structural checks on a revocation (no signature check). Returns its body. */
export function parseRevocation(event: unknown): JsonObject {
  const body = isObject(event) ? event["body"] : undefined;
  const bad = () => new GrantError("malformed revocation", 400);
  if (!isObject(body) || body["v"] !== REVOCATION_VERSION) throw bad();
  const keys = Object.keys(body);
  if (keys.length !== REVOCATION_FIELDS.length || !REVOCATION_FIELDS.every((f) => has(body, f))) throw bad();
  const ev = event as JsonObject;
  if (Object.keys(ev).some((k) => k !== "body" && k !== "sig") || typeof ev["sig"] !== "string") throw bad();
  if (typeof body["grant"] !== "string" || !ID_RE.test(body["grant"]) || !isAgentDid(body["iss"])) throw bad();
  const ts = body["ts"];
  if (!isPlainInt(ts) || ts < 0 || ts > MAX_SAFE_INT) throw bad();
  return body;
}

/** Check a revocation's structure and that `issuerKey` signed it. */
export async function verifyRevocation(event: unknown, issuerKey: string): Promise<JsonObject> {
  const body = parseRevocation(event);
  let msg: Uint8Array;
  try {
    msg = canonicalJson(body);
  } catch {
    throw new GrantError("malformed revocation", 400);
  }
  if (!(await verify(issuerKey, msg, (event as JsonObject)["sig"]))) throw new GrantError("bad revocation signature", 400);
  return body;
}

