/** The registry client against a fake registry: controller binding, pins, revocation proofs, strict JSON. */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
  EquivocationError, InvalidEvent, JsonFloat, parseJson, RegistryClient, registryKeyResolver, registryRevocationChecker,
  type Fetch,
} from "../src/index.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const ROOT = new URL("../../../test-vectors/", import.meta.url);
const kel = parseJson(readFileSync(new URL("kel.json", ROOT), "utf8")) as Any;
const revs = parseJson(readFileSync(new URL("revocations.json", ROOT), "utf8")) as Any;
const kcase = (name: string) => kel.cases.find((c: Any) => c.name === name);

function fakeRegistry(logs: Map<string, unknown[]>, revoked: Record<string, unknown> = {}): Fetch {
  return async (url, init) => {
    const u = new URL(url);
    const m = /^\/v1\/identities\/([^/]+)\/log$/.exec(u.pathname);
    if (m && logs.has(m[1]!)) return { status: 200, text: async () => JSON.stringify({ did: m[1], events: logs.get(m[1]!) }) };
    if (u.pathname === "/v1/revocations/check") {
      const pairs = JSON.parse(init!.body!).grants as string[][];
      const hit = pairs.filter((p) => p.join("\n") in revoked);
      return { status: 200, text: async () => JSON.stringify({ revoked: hit, proofs: hit.map((p) => revoked[p.join("\n")]) }) };
    }
    return { status: 404, text: async () => "{}" };
  };
}

const didOf = (log: Any[]) => log[0].body.did as string;

describe("registry client", () => {
  it("accepts a controller deactivation only when the key is in the controller's own log", async () => {
    const ctrl = kcase("controller_log").log;
    const good = kcase("controller_deactivation").log;
    const forged = kcase("controller_deactivation_unbound_key").log;
    const reg = (log: Any[]) => new RegistryClient("https://reg.example", {
      fetch: fakeRegistry(new Map([[didOf(ctrl), ctrl], [didOf(log), log]])),
    });
    const st = await reg(good).verifiedState(didOf(good));
    assert.equal(st?.active, false);
    await assert.rejects(reg(forged).verifiedState(didOf(forged)), InvalidEvent);
  });

  it("detects a rolled-back or forked log", async () => {
    const full = kcase("two_rotations").log;
    const logs = new Map([[didOf(full), full]]);
    const reg = new RegistryClient("https://reg.example", { fetch: fakeRegistry(logs) });
    assert.equal((await reg.verifiedState(didOf(full)))?.seq, 2);
    logs.set(didOf(full), full.slice(0, 2));
    await assert.rejects(reg.verifiedState(didOf(full)), EquivocationError);
  });

  it("resolves current keys and unknown DIDs", async () => {
    const log = kcase("two_rotations").log;
    const reg = new RegistryClient("https://reg.example", { fetch: fakeRegistry(new Map([[didOf(log), log]])) });
    const resolve = registryKeyResolver(reg);
    assert.deepEqual(await resolve(didOf(log)), [log[2].body.key, `${didOf(log)}#key-2`]);
    assert.equal(await resolve("did:agent:" + "1".repeat(45)), null);
  });

  it("only counts revocation claims backed by an issuer signature (or denies, by default)", async () => {
    const valid = revs.cases.find((c: Any) => c.name === "valid");
    const iss = valid.event.body.iss as string;
    const gid = valid.event.body.grant as string;
    const pair = `${iss}\n${gid}`;
    const reg = (proof: unknown) => new RegistryClient("https://reg.example", {
      fetch: fakeRegistry(new Map([[iss, revs.issuer_log]]), { [pair]: proof }),
    });
    assert.deepEqual(await registryRevocationChecker(reg(valid.event))([[iss, gid]]), [[iss, gid]]);
    assert.deepEqual(await registryRevocationChecker(reg(revs.forged_proof), { onUnproven: "ignore" })([[iss, gid]]), []);
    assert.deepEqual(await registryRevocationChecker(reg(revs.forged_proof))([[iss, gid]]), [[iss, gid]]);
    assert.deepEqual(await registryRevocationChecker(reg(valid.event))([[iss, "other-grant"]]), []);
  });
});

describe("strict JSON", () => {
  it("keeps number types and refuses duplicate keys when asked", () => {
    const v = parseJson('{"a":1,"b":1.0,"c":9007199254740993}') as Any;
    assert.equal(v.a, 1);
    assert.ok(v.b instanceof JsonFloat);
    assert.equal(v.c, 9007199254740993n);
    assert.throws(() => parseJson('{"a":1,"a":2}', { rejectDuplicateKeys: true }));
    assert.throws(() => parseJson("[1,]"));
    assert.throws(() => parseJson('{"a":NaN}'));
    assert.throws(() => parseJson("[".repeat(600) + "]".repeat(600)));
  });
});
