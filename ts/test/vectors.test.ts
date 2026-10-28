/**
 * Runs the shared cross-implementation test vectors (../test-vectors, generated
 * from the Python reference) against this implementation. The Python suite runs
 * the same files (tests/test_vectors.py), so passing both means the two accept
 * and reject exactly the same inputs.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  audienceCovers, b58decode, b58encode, canonicalJson, digest, GrantError, GrantVerifier, InvalidEvent, keyCommitment,
  keyId, Limits, LimitError, parseJson, patternCovers, patternMatches, publicKeyToMultikey, RequestVerifier, scopeCovers,
  signingString, trustPrincipals, verify, verifyLog, verifyRevocation, AuthError, type JsonObject,
} from "../src/index.js";

const ROOT = new URL("../../../test-vectors/", import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;

function load(name: string): Any {
  const data = parseJson(readFileSync(new URL(name, ROOT), "utf8")) as Any;
  assert.equal(data.format, "agentauth-test-vectors/1");
  return data;
}

const b64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "base64"));
const text = (u: Uint8Array) => new TextDecoder().decode(u);
/** The strict parser builds null-prototype objects; compare plain copies. */
const plain = (x: unknown): unknown => JSON.parse(JSON.stringify(x));
const show = (x: unknown): string => JSON.stringify(x, (_k, v) => (typeof v === "bigint" ? `${v}n` : v));

async function rejects(p: Promise<unknown>, type: Function, status?: number): Promise<void> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof type, `expected ${type.name}, got ${(e as Error)?.constructor?.name}: ${(e as Error)?.message}`);
    if (status !== undefined) assert.equal((e as Any).status, status, (e as Error).message);
    return;
  }
  assert.fail(`expected ${type.name}`);
}

describe("primitives", () => {
  const P = load("primitives.json");
  it("base58btc", () => {
    for (const c of P.base58btc) {
      assert.equal(b58encode(b64(c.bytes_b64)), c.encoded);
      assert.deepEqual(b58decode(c.encoded), b64(c.bytes_b64));
    }
  });
  it("multikey, digest, key commitment", async () => {
    for (const c of P.multikey) assert.equal(publicKeyToMultikey(b64(c.public_key_b64)), c.multikey);
    for (const c of P.digest) assert.equal(await digest(b64(c.input_b64)), c.digest);
    for (const c of P.key_commitment) assert.equal(await keyCommitment(c.multikey), c.commitment);
  });
  it("canonical JSON", () => {
    for (const c of P.canonical_json) assert.equal(text(canonicalJson(parseJson(c.json))), c.canonical, c.json);
    for (const c of P.canonical_json_invalid) assert.throws(() => canonicalJson(parseJson(c.json)), c.reason);
  });
  it("signatures", async () => {
    for (const c of P.signatures) assert.equal(await verify(c.multikey, b64(c.message_b64), c.signature), c.valid, c.reason);
  });
});

describe("key event logs", () => {
  const K = load("kel.json");
  for (const c of K.cases) {
    it(c.name, async () => {
      if (!c.valid) return rejects(verifyLog(c.log), InvalidEvent);
      const st = await verifyLog(c.log);
      const w = c.state;
      assert.deepEqual(
        [st.did, st.seq, st.active, st.key, st.next, st.controller, st.lastDigest, st.active ? keyId(st) : null],
        [w.did, w.seq, w.active, w.key, w.next, w.controller, w.last_digest, w.kid],
      );
      if ("valid_with_controller_binding" in c) {
        const ctrl = await verifyLog(K.cases.find((x: Any) => x.name === c.controller_log).log);
        const keys = new Map([[ctrl.did, new Set(ctrl.history.map(([, k]) => k))]]);
        const bound = (d: string, k: string) => keys.get(d)?.has(k) ?? false;
        if (c.valid_with_controller_binding) await verifyLog(c.log, bound);
        else await rejects(verifyLog(c.log, bound), InvalidEvent);
      }
    });
  }
});

describe("signed requests", () => {
  const R = load("requests.json");
  it("signing string", async () => {
    for (const c of R.signing_string) {
      const got = await signingString(c.method, c.audience, c.path, c.ts, c.nonce, b64(c.body_b64), c.grants);
      assert.equal(text(got), c.signing_string);
    }
  });
  for (const c of R.cases) {
    it(c.name, async () => {
      const seen = new Set<string>();
      const nonces = { ttl: 10_000, checkAndStore: (d: string, n: string) => !seen.has(d + n) && !!seen.add(d + n) };
      const keys = R.keys;
      const v = new RequestVerifier((d) => (d in keys ? [keys[d].key, keys[d].kid] : null), {
        audiences: R.audiences, maxSkew: R.max_skew, nonceCache: nonces, clock: () => c.now,
      });
      const got = [];
      for (let i = 0; i < c.repeat; i++) {
        try {
          const a = await v.verify({ authorization: c.authorization, method: c.method, path: c.path, body: b64(c.body_b64), grants: c.grants });
          got.push({ valid: true, did: a.did, kid: a.kid });
        } catch (e) {
          if (!(e instanceof AuthError)) throw e;
          got.push({ valid: false, status: e.status });
        }
      }
      assert.deepEqual(got, plain(c.expect));
    });
  }
});

describe("grant chains", () => {
  const G = load("grants.json");
  for (const c of G.cases) {
    it(c.name, async () => {
      const keys = G.keys;
      const revoked = new Set(c.revoked.map((r: string[]) => r.join("\n")));
      const gv = new GrantVerifier((d) => (d in keys ? [keys[d].key, keys[d].kid] : null), {
        rootPolicy: trustPrincipals(G.root_policy),
        revoked: (pairs) => pairs.filter((p) => revoked.has(p.join("\n"))),
      });
      const run = () => gv.verify(c.header, { requester: c.requester, audience: c.audience, now: c.now });
      if (!c.expect.valid) return rejects(run(), GrantError, c.expect.status);
      const a = await run();
      const w = c.expect;
      assert.deepEqual([a.principal, a.via, a.scopes, a.grantIds], plain([w.principal, w.via, w.scopes, w.grant_ids]));
      assert.equal(text(canonicalJson(a.limits)), text(canonicalJson(w.leaf_limits)));
    });
  }
  it("scope and audience algebra", () => {
    for (const c of G.scope_covers) assert.equal(scopeCovers(c.parent, c.child), c.covers, show(c));
    for (const c of G.audience_covers) assert.equal(audienceCovers(c.parents, c.children), c.covers, show(c));
  });
});

describe("limits", () => {
  const L = load("limits.json");
  it("narrowing", () => {
    for (const c of L.narrowing) {
      const got = Limits.fromDict(c.parent).narrowingViolation(Limits.fromDict(c.child)) !== null;
      assert.equal(got, c.violation, show(c));
    }
  });
  it("invalid limits", () => {
    for (const c of L.invalid) assert.throws(() => Limits.fromDict(c.limits), LimitError, show(c));
  });
  it("per-call checks", () => {
    for (const c of L.check_call) {
      let got: object;
      try {
        Limits.fromDict(c.limits).checkCall({ resource: c.resource, amount: c.amount, unit: c.unit });
        got = { valid: true };
      } catch (e) {
        if (!(e instanceof LimitError)) throw e;
        got = { valid: false, status: e.status };
      }
      assert.deepEqual(got, plain(c.expect), show(c));
    }
  });
  it("patterns", () => {
    for (const c of L.pattern_matches) assert.equal(patternMatches(c.pattern, c.resource), c.matches);
    for (const c of L.pattern_covers) assert.equal(patternCovers(c.parent, c.child), c.covers);
  });
});

describe("revocations", () => {
  for (const c of load("revocations.json").cases) {
    it(c.name, async () => {
      if (c.valid) await verifyRevocation(c.event as JsonObject, c.issuer_key);
      else await rejects(verifyRevocation(c.event, c.issuer_key), GrantError);
    });
  }
});
