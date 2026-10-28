/**
 * Talking to an AgentAuth registry without trusting it.
 *
 * The registry is a witness, not an authority: everything here replays the key
 * event log it serves and checks it locally, binds controller signatures to the
 * controller's own verified log, and pins what it has seen so a registry that
 * later rolls a log back or forks it is detected (EquivocationError).
 */

import { AgentAuthError, EquivocationError, GrantError } from "./errors.js";
import { eventDigest, isAgentDid, keyId, verifyLog, type ControllerKeyCheck, type IdentityState } from "./identity.js";
import { isObject, parseJson, type JsonObject } from "./json.js";
import { parseRevocation } from "./grants.js";
import { canonicalJson } from "./json.js";
import { verify } from "./crypto.js";

export type Fetch = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; redirect?: "error" | "follow" | "manual"; signal?: AbortSignal }) => Promise<{ status: number; text(): Promise<string> }>;

export class RegistryError extends AgentAuthError {
  constructor(status: number, message: string) {
    super(message, status);
  }
}

/** Remembers, per DID, the digests of every event seen, so a log must always extend what came before. */
export class KelPins {
  private pins = new Map<string, string[]>();
  constructor(private readonly maxDids = 100_000) {}

  async check(did: string, events: JsonObject[]): Promise<void> {
    const digests = await Promise.all(events.map((e) => eventDigest(e)));
    const pinned = this.pins.get(did);
    if (pinned) {
      if (digests.length < pinned.length) throw new EquivocationError(did, `log rolled back from ${pinned.length} to ${digests.length} events`);
      for (let i = 0; i < pinned.length; i++) {
        if (digests[i] !== pinned[i]) throw new EquivocationError(did, `log forked at event ${i}`);
      }
    }
    this.pins.delete(did);
    this.pins.set(did, digests);
    while (this.pins.size > this.maxDids) this.pins.delete(this.pins.keys().next().value as string);
  }
}

export interface RegistryClientOptions {
  fetch?: Fetch;
  pins?: KelPins;
  timeoutMs?: number;
}

export class RegistryClient {
  readonly baseUrl: string;
  private readonly fetch: Fetch;
  readonly pins: KelPins;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, opts: RegistryClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    const f = opts.fetch ?? (globalThis.fetch as unknown as Fetch | undefined);
    if (!f) throw new Error("no fetch implementation available; pass one in options.fetch");
    this.fetch = f;
    this.pins = opts.pins ?? new KelPins();
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  private async request(path: string, init: { method?: string; body?: string } = {}): Promise<unknown> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await this.fetch(this.baseUrl + path, {
        method: init.method ?? "GET",
        headers: init.body ? { "content-type": "application/json" } : {},
        body: init.body,
        redirect: "error", // never follow a registry somewhere else
        signal: ctrl.signal,
      });
      const text = await r.text();
      if (r.status === 404) return null;
      if (r.status >= 400) throw new RegistryError(r.status >= 500 ? 503 : r.status, `registry answered ${r.status}`);
      return parseJson(text);
    } finally {
      clearTimeout(timer);
    }
  }

  /** The raw key event log (null if the registry doesn't know the DID). */
  async log(did: string): Promise<JsonObject[] | null> {
    if (!isAgentDid(did)) throw new RegistryError(400, "not a did:agent identifier");
    const res = await this.request(`/v1/identities/${did}/log`);
    if (res === null) return null;
    if (!isObject(res) || res["did"] !== did || !Array.isArray(res["events"]) || !res["events"].every(isObject)) {
      throw new RegistryError(503, "registry returned a malformed log");
    }
    return res["events"] as JsonObject[];
  }

  /** Every key `did` has ever held, from its verified log (empty if unknown). */
  async controllerKeys(did: string, depth = 0): Promise<Set<string>> {
    const events = await this.log(did);
    if (!events) return new Set();
    const st = await verifyLog(events, this.boundCheck(depth + 1));
    return new Set(st.history.map(([, k]) => k));
  }

  /** A controller check that accepts a key only if it appears in the controller's own verified log. */
  boundCheck(depth = 0): ControllerKeyCheck {
    const cache = new Map<string, Promise<Set<string>>>();
    return async (did, key) => {
      if (depth > 4) return false; // controller chains this deep aren't verified
      let p = cache.get(did);
      if (!p) {
        p = this.controllerKeys(did, depth);
        cache.set(did, p);
      }
      return (await p).has(key);
    };
  }

  /** Replay and verify the log (controller-bound), check it against the pins, and return the state. */
  async verifiedState(did: string): Promise<IdentityState | null> {
    const events = await this.log(did);
    if (!events) return null;
    const st = await verifyLog(events, this.boundCheck());
    if (st.did !== did) throw new RegistryError(503, "registry served the log of a different DID");
    await this.pins.check(did, events);
    return st;
  }

  /** [[issuer, grant id], ...] -> the registry's claims, each with the issuer-signed revocation. */
  async revocationProofs(pairs: Array<[string, string]>): Promise<Map<string, JsonObject>> {
    const res = await this.request("/v1/revocations/check", { method: "POST", body: JSON.stringify({ grants: pairs }) });
    const out = new Map<string, JsonObject>();
    if (!isObject(res) || !Array.isArray(res["revoked"])) throw new RegistryError(503, "registry returned a malformed answer");
    const proofs = Array.isArray(res["proofs"]) ? res["proofs"] : [];
    res["revoked"].forEach((p, i) => {
      if (Array.isArray(p) && p.length === 2 && typeof p[0] === "string" && typeof p[1] === "string") {
        out.set(`${p[0]}\n${p[1]}`, (proofs[i] ?? null) as JsonObject);
      }
    });
    return out;
  }
}

/** A KeyResolver (for RequestVerifier and GrantVerifier) backed by verified registry logs, with a TTL cache. */
export function registryKeyResolver(registry: RegistryClient, { ttlSeconds = 30, minRefreshSeconds = 1 } = {}) {
  const cache = new Map<string, { at: number; value: readonly [string, string] | null }>();
  const forced = new Map<string, number>();
  const now = () => Date.now() / 1000;
  const resolver = async (did: string): Promise<readonly [string, string] | null> => {
    const hit = cache.get(did);
    if (hit && now() - hit.at < ttlSeconds) return hit.value;
    const st = await registry.verifiedState(did);
    const value = st && st.active && st.key ? ([st.key, keyId(st)] as const) : null;
    cache.set(did, { at: now(), value });
    if (cache.size > 100_000) cache.delete(cache.keys().next().value as string);
    return value;
  };
  resolver.invalidate = (did: string) => {
    const last = forced.get(did) ?? 0;
    if (now() - last < minRefreshSeconds) return; // rate-limit forced refreshes
    forced.set(did, now());
    cache.delete(did);
  };
  return resolver;
}

/**
 * A RevocationCheck backed by the registry. Each claimed revocation must come with
 * a revocation signed by one of the issuer's keys (from its verified log); a claim
 * without a valid proof is treated as revoked (`onUnproven: "deny"`, fail closed)
 * or ignored (`"ignore"`).
 */
export function registryRevocationChecker(registry: RegistryClient, { onUnproven = "deny" as "deny" | "ignore" } = {}) {
  return async (pairs: Array<[string, string]>): Promise<Array<[string, string]>> => {
    let claims: Map<string, JsonObject>;
    try {
      claims = await registry.revocationProofs(pairs);
    } catch (e) {
      throw new GrantError(`revocation status unavailable: ${(e as Error).message}`, 503);
    }
    const out: Array<[string, string]> = [];
    for (const [iss, gid] of pairs) {
      if (!claims.has(`${iss}\n${gid}`)) continue;
      const proof = claims.get(`${iss}\n${gid}`);
      let ok = false;
      try {
        const body = parseRevocation(proof);
        if (body["iss"] === iss && body["grant"] === gid) {
          const st = await registry.verifiedState(iss);
          const msg = canonicalJson(body);
          for (const [, k] of st?.history ?? []) if (await verify(k, msg, (proof as JsonObject)["sig"])) ok = true;
        }
      } catch {
        ok = false;
      }
      if (ok || onUnproven === "deny") out.push([iss, gid]);
    }
    return out;
  };
}
